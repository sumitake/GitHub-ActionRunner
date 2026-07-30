package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestExchangeHTTPSUsesExactLoopbackConnectAndTLSBindings(t *testing.T) {
	t.Parallel()

	body := []byte("portable-ghar-task11-response\n")
	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet ||
				request.URL.RequestURI() != "/probe" ||
				request.Host != "example.com" ||
				request.Header.Get("Connection") != "close" {
				t.Errorf("unexpected HTTPS request: %+v", request)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/octet-stream")
			_, _ = writer.Write(body)
		},
	))
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	relay := newTestConnectRelay(t, server.Listener.Addr().String())
	defer relay.Close()
	sentinel := sentinelForTLSTest(server.Certificate(), body)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := exchangeHTTPSVia(
		ctx,
		sentinel,
		httpsExchangeRuntime{
			relayAddress: relay.Address(),
			roots:        roots,
			dialContext:  testHTTPSDialContext,
		},
	)
	if err != nil || got != sentinel.ResponseBodyDigest {
		t.Fatalf("exchangeHTTPSVia() = %q, %v", got, err)
	}
	relay.Wait(t)
	const wantConnect = "CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com:443\r\n\r\n"
	if relay.Request() != wantConnect {
		t.Fatalf("CONNECT request = %q, want %q", relay.Request(), wantConnect)
	}
}

func TestExchangeHTTPSRejectsTLSBodyAndStatusSubstitution(t *testing.T) {
	t.Parallel()

	tests := map[string]func(
		*task11synthetic.Sentinel,
		*httptest.Server,
	){
		"SPKI": func(
			sentinel *task11synthetic.Sentinel,
			_ *httptest.Server,
		) {
			sentinel.SPKIDigest = listenerTestDigestA
		},
		"certificate": func(
			sentinel *task11synthetic.Sentinel,
			_ *httptest.Server,
		) {
			sentinel.CertificateDigest = listenerTestDigestA
		},
		"body": func(
			sentinel *task11synthetic.Sentinel,
			_ *httptest.Server,
		) {
			sentinel.ResponseBodyDigest = listenerTestDigestA
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			body := []byte("portable-ghar-task11-response\n")
			server := httptest.NewUnstartedServer(http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					_, _ = writer.Write(body)
				},
			))
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			relay := newTestConnectRelay(t, server.Listener.Addr().String())
			defer relay.Close()
			sentinel := sentinelForTLSTest(server.Certificate(), body)
			mutate(&sentinel, server)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()
			if _, err := exchangeHTTPSVia(
				ctx,
				sentinel,
				httpsExchangeRuntime{
					relayAddress: relay.Address(),
					roots:        roots,
					dialContext:  testHTTPSDialContext,
				},
			); err == nil {
				t.Fatal("exchangeHTTPSVia accepted substituted evidence")
			}
			relay.WaitAfterRejectedExchange(t)
		})
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "/other", http.StatusFound)
		},
	))
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	relay := newTestConnectRelay(t, server.Listener.Addr().String())
	defer relay.Close()
	sentinel := sentinelForTLSTest(server.Certificate(), []byte("unused"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := exchangeHTTPSVia(
		ctx,
		sentinel,
		httpsExchangeRuntime{
			relayAddress: relay.Address(),
			roots:        roots,
			dialContext:  testHTTPSDialContext,
		},
	); err == nil {
		t.Fatal("exchangeHTTPSVia followed or accepted redirect")
	}
	relay.WaitAfterRejectedExchange(t)
}

func TestExchangeHTTPSRequiresFutureDeadlineBeforeDial(t *testing.T) {
	t.Parallel()

	input, _ := listenerInputForTest(
		t,
		task11synthetic.ScenarioOneJob,
	)
	dialCalls := 0
	runtime := httpsExchangeRuntime{
		relayAddress: "unused",
		roots:        x509.NewCertPool(),
		dialContext: func(
			context.Context,
			string,
			string,
		) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("injected dial failure")
		},
	}
	expired, cancelExpired := context.WithDeadline(
		context.Background(),
		time.Now().Add(-time.Second),
	)
	defer cancelExpired()
	for name, ctx := range map[string]context.Context{
		"nil":              nil,
		"missing deadline": context.Background(),
		"expired deadline": expired,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := exchangeHTTPSVia(
				ctx,
				input.Sentinel,
				runtime,
			); !errors.Is(err, errHTTPSExchange) {
				t.Fatalf("exchangeHTTPSVia error = %v", err)
			}
		})
	}
	if dialCalls != 0 {
		t.Fatalf("dial calls without future deadline = %d", dialCalls)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := exchangeHTTPSVia(
		ctx,
		input.Sentinel,
		runtime,
	); !errors.Is(err, errHTTPSExchange) {
		t.Fatalf("exchangeHTTPSVia future-deadline error = %v", err)
	}
	if dialCalls != 1 {
		t.Fatalf("dial calls with future deadline = %d, want 1", dialCalls)
	}
}

func TestExchangeHTTPSBoundsStalledDialConnectAndTLS(t *testing.T) {
	input, _ := listenerInputForTest(
		t,
		task11synthetic.ScenarioOneJob,
	)
	tests := map[string]func() (
		func(context.Context, string, string) (net.Conn, error),
		<-chan struct{},
	){
		"dial": func() (
			func(context.Context, string, string) (net.Conn, error),
			<-chan struct{},
		) {
			done := make(chan struct{})
			return func(
				ctx context.Context,
				_ string,
				_ string,
			) (net.Conn, error) {
				defer close(done)
				<-ctx.Done()
				return nil, ctx.Err()
			}, done
		},
		"CONNECT": func() (
			func(context.Context, string, string) (net.Conn, error),
			<-chan struct{},
		) {
			return newPipeHTTPSDial(func(connection net.Conn) {
				_, _ = readHTTPHead(connection)
				_, _ = io.Copy(io.Discard, connection)
			})
		},
		"TLS": func() (
			func(context.Context, string, string) (net.Conn, error),
			<-chan struct{},
		) {
			return newPipeHTTPSDial(func(connection net.Conn) {
				_, _ = readHTTPHead(connection)
				_, _ = io.WriteString(
					connection,
					"HTTP/1.1 200 Connection Established\r\n\r\n",
				)
				_, _ = io.Copy(io.Discard, connection)
			})
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			dialContext, done := setup()
			ctx, cancel := context.WithTimeout(
				context.Background(),
				100*time.Millisecond,
			)
			defer cancel()
			start := time.Now()
			if _, err := exchangeHTTPSVia(
				ctx,
				input.Sentinel,
				httpsExchangeRuntime{
					relayAddress: "unused",
					roots:        x509.NewCertPool(),
					dialContext:  dialContext,
				},
			); !errors.Is(err, errHTTPSExchange) {
				t.Fatalf("exchangeHTTPSVia error = %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("stalled %s exchange took %s", name, elapsed)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("stalled %s helper did not stop", name)
			}
		})
	}
}

func TestExchangeHTTPSBoundsStalledHeadersAndBody(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"headers": func(
			_ http.ResponseWriter,
			request *http.Request,
		) {
			<-request.Context().Done()
		},
		"body": func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			writer.Header().Set("Content-Length", "1")
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			<-request.Context().Done()
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(handler)
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			relay := newTestConnectRelay(
				t,
				server.Listener.Addr().String(),
			)
			defer relay.Close()
			sentinel := sentinelForTLSTest(
				server.Certificate(),
				[]byte("x"),
			)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				100*time.Millisecond,
			)
			defer cancel()
			start := time.Now()
			if _, err := exchangeHTTPSVia(
				ctx,
				sentinel,
				httpsExchangeRuntime{
					relayAddress: relay.Address(),
					roots:        roots,
					dialContext:  testHTTPSDialContext,
				},
			); !errors.Is(err, errHTTPSExchange) {
				t.Fatalf("exchangeHTTPSVia error = %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("stalled %s exchange took %s", name, elapsed)
			}
			relay.WaitAfterRejectedExchange(t)
		})
	}
}

func TestExchangeHTTPSEnforcesDecodedBodyLimit(t *testing.T) {
	for _, size := range []int{
		int(task11synthetic.MaximumWireBytes),
		int(task11synthetic.MaximumWireBytes) + 1,
	} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			body := bytes.Repeat([]byte{'x'}, size)
			server := httptest.NewUnstartedServer(http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set(
						"Content-Length",
						strconv.Itoa(len(body)),
					)
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write(body)
				},
			))
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			relay := newTestConnectRelay(
				t,
				server.Listener.Addr().String(),
			)
			defer relay.Close()
			sentinel := sentinelForTLSTest(server.Certificate(), body)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()
			got, err := exchangeHTTPSVia(
				ctx,
				sentinel,
				httpsExchangeRuntime{
					relayAddress: relay.Address(),
					roots:        roots,
					dialContext:  testHTTPSDialContext,
				},
			)
			if size == int(task11synthetic.MaximumWireBytes) {
				if err != nil || got != sentinel.ResponseBodyDigest {
					t.Fatalf("exchangeHTTPSVia() = %q, %v", got, err)
				}
				relay.Wait(t)
				return
			}
			if !errors.Is(err, errHTTPSExchange) || got != "" {
				t.Fatalf("oversize exchange = %q, %v", got, err)
			}
			relay.WaitAfterRejectedExchange(t)
		})
	}
}

func TestExchangeHTTPSRejectsNoncanonicalHTTPResponses(t *testing.T) {
	body := []byte("ok")
	tests := map[string][]byte{
		"HTTP 1.0": []byte(
			"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
		),
		"missing content length": []byte(
			"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok",
		),
		"content encoding": []byte(
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" +
				"Content-Encoding: gzip\r\n\r\nok",
		),
		"declared trailer": []byte(
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" +
				"Trailer: X-Test\r\n\r\n2\r\nok\r\n0\r\n" +
				"X-Test: present\r\n\r\n",
		),
		"partial framing": []byte(
			"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok",
		),
		"informational response": []byte(
			"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		),
		"oversize headers": []byte(
			"HTTP/1.1 200 OK\r\nX-Pad: " +
				strings.Repeat("a", 33<<10) +
				"\r\nContent-Length: 2\r\n\r\nok",
		),
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			server := newRawTLSTestServer(t, response)
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			relay := newTestConnectRelay(t, server.Address())
			defer relay.Close()
			sentinel := sentinelForTLSTest(server.Certificate(), body)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()
			if got, err := exchangeHTTPSVia(
				ctx,
				sentinel,
				httpsExchangeRuntime{
					relayAddress: relay.Address(),
					roots:        roots,
					dialContext:  testHTTPSDialContext,
				},
			); !errors.Is(err, errHTTPSExchange) || got != "" {
				t.Fatalf("exchangeHTTPSVia() = %q, %v", got, err)
			}
			relay.WaitAfterRejectedExchange(t)
			server.Wait(t)
		})
	}
}

func sentinelForTLSTest(
	certificate *x509.Certificate,
	body []byte,
) task11synthetic.Sentinel {
	certificateSum := sha256.Sum256(certificate.Raw)
	spkiSum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	bodySum := sha256.Sum256(body)
	return task11synthetic.Sentinel{
		URL:                  "https://example.com/probe",
		Host:                 "example.com",
		Port:                 443,
		HostIdentityDigest:   listenerTestDigestC,
		SPKIDigest:           hex.EncodeToString(spkiSum[:]),
		CertificateDigest:    hex.EncodeToString(certificateSum[:]),
		PolicyEntryDigest:    listenerTestDigestF,
		PolicyEvidenceDigest: listenerTestDigestA,
		ResponseBodyDigest:   hex.EncodeToString(bodySum[:]),
	}
}

func testHTTPSDialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func newPipeHTTPSDial(
	handler func(net.Conn),
) (
	func(context.Context, string, string) (net.Conn, error),
	<-chan struct{},
) {
	done := make(chan struct{})
	return func(
		context.Context,
		string,
		string,
	) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer close(done)
			defer server.Close()
			handler(server)
		}()
		return client, nil
	}, done
}

func readHTTPHead(connection net.Conn) (string, error) {
	reader := bufio.NewReaderSize(connection, 16<<10)
	var document strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		document.WriteString(line)
		if strings.HasSuffix(document.String(), "\r\n\r\n") {
			return document.String(), nil
		}
		if document.Len() > 16<<10 {
			return "", errors.New("HTTP head too large")
		}
	}
}

type rawTLSTestServer struct {
	listener    net.Listener
	certificate *x509.Certificate
	response    []byte
	done        chan struct{}

	mu  sync.Mutex
	err error
}

func newRawTLSTestServer(
	t *testing.T,
	response []byte,
) *rawTLSTestServer {
	t.Helper()
	template := httptest.NewUnstartedServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {},
	))
	template.StartTLS()
	tlsConfig := template.TLS.Clone()
	certificate := template.Certificate()
	template.Close()
	tlsConfig.NextProtos = []string{"http/1.1"}

	listener, err := net.Listen(
		"tcp4",
		net.JoinHostPort(net.IPv4(127, 0, 0, 1).String(), "0"),
	)
	if err != nil {
		t.Fatalf("listen raw TLS server: %v", err)
	}
	server := &rawTLSTestServer{
		listener:    tls.NewListener(listener, tlsConfig),
		certificate: certificate,
		response:    bytes.Clone(response),
		done:        make(chan struct{}),
	}
	go server.serve()
	return server
}

func (s *rawTLSTestServer) Address() string {
	return s.listener.Addr().String()
}

func (s *rawTLSTestServer) Certificate() *x509.Certificate {
	return s.certificate
}

func (s *rawTLSTestServer) Wait(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal("raw TLS server did not finish")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		t.Fatalf("raw TLS server error: %v", s.err)
	}
}

func (s *rawTLSTestServer) Close() {
	_ = s.listener.Close()
	select {
	case <-s.done:
	default:
	}
}

func (s *rawTLSTestServer) serve() {
	defer close(s.done)
	connection, err := s.listener.Accept()
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			s.setError(err)
		}
		return
	}
	defer connection.Close()
	_ = s.listener.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := readHTTPHead(connection); err != nil {
		s.setError(err)
		return
	}
	_ = writeExact(connection, s.response)
}

func (s *rawTLSTestServer) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

type testConnectRelay struct {
	listener net.Listener
	target   string

	mu      sync.Mutex
	request string
	err     error
	done    chan struct{}
}

func newTestConnectRelay(t *testing.T, target string) *testConnectRelay {
	t.Helper()
	listener, err := net.Listen(
		"tcp4",
		net.JoinHostPort(net.IPv4(127, 0, 0, 1).String(), "0"),
	)
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	relay := &testConnectRelay{
		listener: listener,
		target:   target,
		done:     make(chan struct{}),
	}
	go relay.serve()
	return relay
}

func (r *testConnectRelay) Address() string {
	return r.listener.Addr().String()
}

func (r *testConnectRelay) Request() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.request
}

func (r *testConnectRelay) Wait(t *testing.T) {
	r.wait(t)
}

func (r *testConnectRelay) WaitAfterRejectedExchange(t *testing.T) {
	r.wait(t)
}

func (r *testConnectRelay) wait(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil &&
		!(r.request != "" && isBenignRelayTerminalError(r.err)) {
		t.Fatalf("relay error: %v", r.err)
	}
}

func isBenignRelayTerminalError(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "closed network connection")
}

func (r *testConnectRelay) Close() {
	_ = r.listener.Close()
	select {
	case <-r.done:
	default:
	}
}

func (r *testConnectRelay) serve() {
	defer close(r.done)
	client, err := r.listener.Accept()
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			r.setError(err)
		}
		return
	}
	defer client.Close()
	_ = r.listener.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(client, 16<<10)
	var request strings.Builder
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			r.setError(readErr)
			return
		}
		request.WriteString(line)
		if strings.HasSuffix(request.String(), "\r\n\r\n") {
			break
		}
		if request.Len() > 16<<10 {
			r.setError(errors.New("CONNECT request too large"))
			return
		}
	}
	r.mu.Lock()
	r.request = request.String()
	r.mu.Unlock()
	target, err := net.DialTimeout("tcp", r.target, 5*time.Second)
	if err != nil {
		r.setError(err)
		return
	}
	defer target.Close()
	if _, err := io.WriteString(
		client,
		"HTTP/1.1 200 Connection Established\r\n\r\n",
	); err != nil {
		r.setError(err)
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})
	copyDone := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(target, reader)
		copyDone <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(client, target)
		copyDone <- copyErr
	}()
	firstErr := <-copyDone
	_ = client.Close()
	_ = target.Close()
	secondErr := <-copyDone
	for _, copyErr := range []error{firstErr, secondErr} {
		if copyErr != nil && !isBenignRelayTerminalError(copyErr) {
			r.setError(copyErr)
			return
		}
	}
}

func (r *testConnectRelay) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
}
