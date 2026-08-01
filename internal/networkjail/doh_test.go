package networkjail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func publicV6() netip.Addr {
	return netip.AddrFrom16([16]byte{
		0x26, 0x06, 0x47, 0x00,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0x11, 0x11,
	})
}

func validDoHRuntimeConfig() DoHRuntimeConfig {
	return DoHRuntimeConfig{
		RequestTimeout:      5 * time.Second,
		TLSHandshakeTimeout: 3 * time.Second,
		ConnectionLifetime:  30 * time.Second,
		IdleTimeout:         10 * time.Second,
		MaxResponseBytes:    4 << 10,
		MaxRecords:          16,
		MinTTL:              1,
		MaxTTL:              3600,
	}
}

func TestPermitSequencerIsSharedAcrossDoHEndpoints(t *testing.T) {
	sequencer := NewPermitSequencer()
	client := &fakePermitClient{}
	first, err := sequencer.request(
		context.Background(),
		client,
		DialPermitRequest{SlotID: 3, JobGeneration: 7, Class: DialClassDoH},
	)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	second, err := sequencer.request(
		context.Background(),
		client,
		DialPermitRequest{SlotID: 3, JobGeneration: 7, Class: DialClassDoH},
	)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if first.number != 1 || second.number != 2 ||
		len(client.requests) != 2 ||
		client.requests[0].Sequence != 1 ||
		client.requests[1].Sequence != 2 {
		t.Fatalf("permits=(%d,%d) requests=%#v", first.number, second.number, client.requests)
	}
}

func TestPermitSequencerBurnsFailedSubmission(t *testing.T) {
	sequencer := NewPermitSequencer()
	client := &fakePermitClient{err: errors.New("synthetic permit failure")}
	request := DialPermitRequest{
		SlotID:        3,
		JobGeneration: 7,
		Class:         DialClassDoH,
	}
	if _, err := sequencer.request(context.Background(), client, request); err == nil {
		t.Fatal("failed permit submission returned nil error")
	}
	client.err = nil
	permit, err := sequencer.request(context.Background(), client, request)
	if err != nil {
		t.Fatalf("second permit submission: %v", err)
	}
	if permit.number != 2 || len(client.requests) != 2 ||
		client.requests[0].Sequence != 1 ||
		client.requests[1].Sequence != 2 {
		t.Fatalf("permit=%d requests=%#v", permit.number, client.requests)
	}
}

func TestPermitSequencerOverflowDoesNotMutateOrSubmit(t *testing.T) {
	sequencer := NewPermitSequencer()
	sequencer.sequence = PermitSequence(math.MaxUint64)
	client := &fakePermitClient{}
	request := DialPermitRequest{
		SlotID:        3,
		JobGeneration: 7,
		Class:         DialClassDoH,
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := sequencer.request(
			context.Background(),
			client,
			request,
		); !errors.Is(err, ErrPermitSequence) {
			t.Fatalf("overflow attempt %d error = %v", attempt, err)
		}
	}
	if sequencer.sequence != PermitSequence(math.MaxUint64) ||
		len(client.requests) != 0 {
		t.Fatalf("sequence=%d requests=%#v", sequencer.sequence, client.requests)
	}
}

func TestPermitSequencerRejectsUninitializedGate(t *testing.T) {
	if _, err := (&PermitSequencer{}).request(
		context.Background(),
		&fakePermitClient{},
		DialPermitRequest{},
	); !errors.Is(err, ErrPermitSequence) {
		t.Fatalf("uninitialized request error = %v", err)
	}
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, err := NewDoHResolverWithSequencer(
		graph,
		0,
		x509.NewCertPool(),
		&fakeLiteralDialer{},
		&fakePermitClient{},
		3,
		7,
		validDoHRuntimeConfig(),
		&PermitSequencer{},
	); err == nil {
		t.Fatal("NewDoHResolverWithSequencer accepted an uninitialized sequencer")
	}
}

func TestDoHPermitSequencerSerializesSubmissionAndSkipsCanceledWaiters(
	t *testing.T,
) {
	permits := &blockingPermitClient{
		firstEntered:  make(chan struct{}),
		secondEntered: make(chan struct{}),
		releaseFirst:  make(chan struct{}),
	}
	connector := &dohConnector{
		endpoint: DoHEndpoint{
			ServerName: "resolver.example",
			Bootstrap:  []netip.Addr{publicV4(8, 8, 8, 8)},
			Path:       "/dns-query",
		},
		roots:      x509.NewCertPool(),
		literals:   &fakeLiteralDialer{},
		permits:    permits,
		slot:       3,
		generation: 7,
		config:     validDoHRuntimeConfig(),
		sequencer:  NewPermitSequencer(),
	}

	firstDone := make(chan error, 1)
	go func() {
		_, dialErr := connector.DialTLSContext(
			context.Background(),
			"tcp",
			"resolver.example:443",
		)
		firstDone <- dialErr
	}()
	select {
	case <-permits.firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first permit request did not enter")
	}

	secondContext, cancelSecond := context.WithCancel(context.Background())
	cancelSecond()
	secondDone := make(chan error, 1)
	go func() {
		_, dialErr := connector.DialTLSContext(
			secondContext,
			"tcp",
			"resolver.example:443",
		)
		secondDone <- dialErr
	}()
	select {
	case dialErr := <-secondDone:
		if dialErr == nil {
			t.Fatal("canceled second DialTLSContext returned nil error")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled second DialTLSContext did not return")
	}
	secondSubmitted := false
	select {
	case <-permits.secondEntered:
		secondSubmitted = true
	default:
	}

	close(permits.releaseFirst)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first DialTLSContext did not return after release")
	}
	_, _ = connector.DialTLSContext(
		context.Background(),
		"tcp",
		"resolver.example:443",
	)

	permits.mu.Lock()
	requests := append([]DialPermitRequest(nil), permits.requests...)
	permits.mu.Unlock()
	if secondSubmitted {
		t.Fatal("canceled queued caller submitted sequence 2 before sequence 1 completed")
	}
	if len(requests) != 2 ||
		requests[0].Sequence != 1 ||
		requests[1].Sequence != 2 {
		t.Fatalf("permit requests = %#v, want sequences 1 and 2", requests)
	}
}

func TestDNSMessageValidationBindsIDQuestionTypeTTLAndEOF(t *testing.T) {
	const id = 17
	query, question, err := buildDNSQuery("example.com", dnsmessage.TypeA, id)
	if err != nil || len(query) == 0 {
		t.Fatalf("buildDNSQuery = bytes:%d err:%v", len(query), err)
	}
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 id,
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: publicV4(8, 8, 8, 8).As4()},
			},
		},
	}
	packed, err := response.Pack()
	if err != nil {
		t.Fatalf("response.Pack: %v", err)
	}
	answers, err := parseDNSResponse(
		packed,
		id,
		question,
		validDoHRuntimeConfig(),
	)
	if err != nil || len(answers) != 1 || answers[0] != publicV4(8, 8, 8, 8) {
		t.Fatalf("parseDNSResponse = %v err:%v", answers, err)
	}

	tests := []struct {
		name   string
		mutate func(dnsmessage.Message) dnsmessage.Message
		trail  bool
	}{
		{"wrong id", func(value dnsmessage.Message) dnsmessage.Message {
			value.ID++
			return value
		}, false},
		{"not response", func(value dnsmessage.Message) dnsmessage.Message {
			value.Response = false
			return value
		}, false},
		{"truncated", func(value dnsmessage.Message) dnsmessage.Message {
			value.Truncated = true
			return value
		}, false},
		{"rcode", func(value dnsmessage.Message) dnsmessage.Message {
			value.RCode = dnsmessage.RCodeRefused
			return value
		}, false},
		{"wrong question", func(value dnsmessage.Message) dnsmessage.Message {
			value.Questions[0].Type = dnsmessage.TypeAAAA
			return value
		}, false},
		{"ttl zero", func(value dnsmessage.Message) dnsmessage.Message {
			value.Answers[0].Header.TTL = 0
			return value
		}, false},
		{"wrong answer type", func(value dnsmessage.Message) dnsmessage.Message {
			value.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: publicV6().As16()}
			return value
		}, false},
		{"authority section", func(value dnsmessage.Message) dnsmessage.Message {
			value.Authorities = []dnsmessage.Resource{value.Answers[0]}
			return value
		}, false},
		{"trailing bytes", func(value dnsmessage.Message) dnsmessage.Message {
			return value
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := tc.mutate(response)
			raw, err := candidate.Pack()
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			if tc.trail {
				raw = append(raw, 0)
			}
			if _, err := parseDNSResponse(
				raw,
				id,
				question,
				validDoHRuntimeConfig(),
			); err == nil {
				t.Fatal("parseDNSResponse accepted invalid response")
			}
		})
	}
}

func TestDNSMessageValidationAcceptsBoundedCNAMEChain(t *testing.T) {
	const id = 23
	_, question, err := buildDNSQuery("example.com", dnsmessage.TypeA, id)
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	target, err := dnsmessage.NewName("target.example.com.")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  target,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: publicV4(8, 8, 8, 8).As4()},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.CNAMEResource{CNAME: target},
			},
		},
	}
	raw, err := response.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	answers, err := parseDNSResponse(raw, id, question, validDoHRuntimeConfig())
	if err != nil {
		t.Fatalf("parseDNSResponse: %v", err)
	}
	if len(answers) != 1 || answers[0] != publicV4(8, 8, 8, 8) {
		t.Fatalf("answers = %v", answers)
	}
}

type mappedLiteralDialer struct {
	mu      sync.Mutex
	target  string
	calls   []DialRequest
	network net.Dialer
}

func (dialer *mappedLiteralDialer) DialLiteral(
	ctx context.Context,
	address netip.Addr,
	port uint16,
) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.calls = append(
		dialer.calls,
		DialRequest{Host: address.String(), Port: port},
	)
	dialer.mu.Unlock()
	return dialer.network.DialContext(ctx, "tcp", dialer.target)
}

func (dialer *mappedLiteralDialer) callCount() int {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return len(dialer.calls)
}

func TestDoHResolverUsesOnePermittedLockedPersistentConnection(t *testing.T) {
	var requestCount int
	var requestMu sync.Mutex
	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			requestMu.Lock()
			requestCount++
			requestMu.Unlock()
			if request.Method != http.MethodPost ||
				request.URL.Path != "/dns-query" ||
				request.Header.Get("Content-Type") != "application/dns-message" {
				http.Error(writer, "bad request", http.StatusBadRequest)
				return
			}
			raw, err := io.ReadAll(io.LimitReader(request.Body, 4097))
			if err != nil {
				http.Error(writer, "read failed", http.StatusBadRequest)
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(raw); err != nil || len(query.Questions) != 1 {
				http.Error(writer, "query failed", http.StatusBadRequest)
				return
			}
			question := query.Questions[0]
			response := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 query.ID,
					Response:           true,
					RecursionAvailable: true,
				},
				Questions: []dnsmessage.Question{question},
			}
			header := dnsmessage.ResourceHeader{
				Name:  question.Name,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			}
			switch question.Type {
			case dnsmessage.TypeA:
				response.Answers = []dnsmessage.Resource{{
					Header: header,
					Body:   &dnsmessage.AResource{A: publicV4(8, 8, 8, 8).As4()},
				}}
			case dnsmessage.TypeAAAA:
				response.Answers = []dnsmessage.Resource{{
					Header: header,
					Body:   &dnsmessage.AAAAResource{AAAA: publicV6().As16()},
				}}
			default:
				http.Error(writer, "type failed", http.StatusBadRequest)
				return
			}
			packed, err := response.Pack()
			if err != nil {
				http.Error(writer, "pack failed", http.StatusInternalServerError)
				return
			}
			writer.Header().Set("Content-Type", "application/dns-message")
			_, _ = writer.Write(packed)
		},
	))
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	if len(server.Certificate().DNSNames) == 0 {
		t.Fatal("test server certificate has no DNS name")
	}
	serverName := server.Certificate().DNSNames[0]
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	manifest := validPolicyManifest()
	manifest.DoHBootstrap = []DoHEndpoint{{
		ServerName: serverName,
		Bootstrap:  []netip.Addr{publicV4(8, 8, 8, 8)},
		Path:       "/dns-query",
	}}
	graph, _, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	literals := &mappedLiteralDialer{target: server.Listener.Addr().String()}
	permits := &fakePermitClient{}
	resolver, err := NewDoHResolver(
		graph,
		0,
		roots,
		literals,
		permits,
		3,
		7,
		validDoHRuntimeConfig(),
	)
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	t.Cleanup(resolver.Close)

	for iteration := 0; iteration < 2; iteration++ {
		answers, err := resolver.Resolve(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("Resolve iteration %d: %v", iteration, err)
		}
		if len(answers) != 2 ||
			answers[0] != publicV4(8, 8, 8, 8) ||
			answers[1] != publicV6() {
			t.Fatalf("answers iteration %d = %v", iteration, answers)
		}
	}
	if literals.callCount() != 1 || len(permits.requests) != 1 {
		t.Fatalf("persistent connection dials=%d permits=%d, want 1/1",
			literals.callCount(), len(permits.requests))
	}
	if permits.requests[0].Class != DialClassDoH ||
		permits.requests[0].Sequence != 1 {
		t.Fatalf("DoH permit request = %#v", permits.requests[0])
	}
	requestMu.Lock()
	gotRequests := requestCount
	requestMu.Unlock()
	if gotRequests != 4 {
		t.Fatalf("DoH requests = %d, want 4", gotRequests)
	}
}

func TestDoHResolverRejectsWrongTLSNameAndUntrustedRoot(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Error("HTTP handler reached despite TLS rejection")
		},
	))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	literals := &mappedLiteralDialer{target: server.Listener.Addr().String()}

	for _, tc := range []struct {
		name       string
		serverName string
		roots      *x509.CertPool
	}{
		{"wrong name", "not-certified.invalid", roots},
		{"untrusted", server.Certificate().DNSNames[0], x509.NewCertPool()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := validPolicyManifest()
			manifest.DoHBootstrap = []DoHEndpoint{{
				ServerName: tc.serverName,
				Bootstrap:  []netip.Addr{publicV4(8, 8, 8, 8)},
				Path:       "/dns-query",
			}}
			graph, _, err := Compile(manifest)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			permits := &fakePermitClient{}
			resolver, err := NewDoHResolver(
				graph,
				0,
				tc.roots,
				literals,
				permits,
				3,
				7,
				validDoHRuntimeConfig(),
			)
			if err != nil {
				t.Fatalf("NewDoHResolver: %v", err)
			}
			defer resolver.Close()
			if _, err := resolver.Resolve(context.Background(), "example.com"); err == nil {
				t.Fatal("Resolve TLS rejection = nil error")
			}
			if len(permits.requests) != 1 {
				t.Fatalf("TLS rejection permits = %d, want 1 attempted connection", len(permits.requests))
			}
		})
	}
}

func TestDoHResolverRejectsExpiredCertificate(t *testing.T) {
	server, root := newExpiredDoHTestServer(t, "expired.example")
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	manifest := validPolicyManifest()
	manifest.DoHBootstrap = []DoHEndpoint{{
		ServerName: "expired.example",
		Bootstrap:  []netip.Addr{publicV4(8, 8, 8, 8)},
		Path:       "/dns-query",
	}}
	graph, _, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	permits := &fakePermitClient{}
	resolver, err := NewDoHResolver(
		graph,
		0,
		roots,
		&mappedLiteralDialer{target: server.Listener.Addr().String()},
		permits,
		3,
		7,
		validDoHRuntimeConfig(),
	)
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	defer resolver.Close()
	if _, err := resolver.Resolve(context.Background(), "example.com"); err == nil {
		t.Fatal("Resolve expired certificate = nil error")
	}
	if len(permits.requests) != 1 {
		t.Fatalf("expired-certificate permits = %d, want 1", len(permits.requests))
	}
}

func TestDoHResolverBoundsResponseBeforeDNSParsing(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/dns-message")
			_, _ = writer.Write(bytes.Repeat([]byte{1}, 1025))
		},
	))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	manifest := validPolicyManifest()
	manifest.DoHBootstrap = []DoHEndpoint{{
		ServerName: server.Certificate().DNSNames[0],
		Bootstrap:  []netip.Addr{publicV4(8, 8, 8, 8)},
		Path:       "/dns-query",
	}}
	graph, _, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	config := validDoHRuntimeConfig()
	config.MaxResponseBytes = 1024
	resolver, err := NewDoHResolver(
		graph,
		0,
		roots,
		&mappedLiteralDialer{target: server.Listener.Addr().String()},
		&fakePermitClient{},
		3,
		7,
		config,
	)
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	defer resolver.Close()
	if _, err := resolver.Resolve(context.Background(), "example.com"); err == nil {
		t.Fatal("Resolve oversized response = nil error")
	}
}

var _ LiteralDialer = (*mappedLiteralDialer)(nil)

func newExpiredDoHTestServer(
	t *testing.T,
	serverName string,
) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	_, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey root: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Portable GHAR test root"},
		NotBefore:             now.Add(-72 * time.Hour),
		NotAfter:              now.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		rootKey.Public(),
		rootKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate root: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate root: %v", err)
	}
	_, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey leaf: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-72 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		root,
		leafKey.Public(),
		rootKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Error("HTTP handler reached with expired certificate")
		},
	))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER, rootDER},
			PrivateKey:  leafKey,
			Leaf:        leaf,
		}},
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	return server, root
}
