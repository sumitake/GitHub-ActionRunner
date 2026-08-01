package networkjail

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	mu      sync.Mutex
	answers []netip.Addr
	err     error
	calls   []string
	trace   *[]string
}

func (resolver *fakeResolver) Resolve(
	_ context.Context,
	name string,
) ([]netip.Addr, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls = append(resolver.calls, name)
	if resolver.trace != nil {
		*resolver.trace = append(*resolver.trace, "resolve")
	}
	return append([]netip.Addr(nil), resolver.answers...), resolver.err
}

type fakeLiteralDialer struct {
	mu       sync.Mutex
	failures map[netip.Addr]error
	calls    []DialRequest
	trace    *[]string
}

func (dialer *fakeLiteralDialer) DialLiteral(
	_ context.Context,
	address netip.Addr,
	port uint16,
) (net.Conn, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	dialer.calls = append(dialer.calls, DialRequest{Host: address.String(), Port: port})
	if dialer.trace != nil {
		*dialer.trace = append(*dialer.trace, "dial:"+address.String())
	}
	if err := dialer.failures[address]; err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

type fakePermitClient struct {
	mu       sync.Mutex
	requests []DialPermitRequest
	err      error
	trace    *[]string
}

type blockingPermitClient struct {
	mu            sync.Mutex
	requests      []DialPermitRequest
	firstEntered  chan struct{}
	secondEntered chan struct{}
	releaseFirst  chan struct{}
}

func (client *blockingPermitClient) Request(
	_ context.Context,
	request DialPermitRequest,
) (Permit, error) {
	client.mu.Lock()
	client.requests = append(client.requests, request)
	call := len(client.requests)
	client.mu.Unlock()
	switch call {
	case 1:
		close(client.firstEntered)
		<-client.releaseFirst
	case 2:
		close(client.secondEntered)
	}
	return Permit{
		slot:   request.SlotID,
		class:  request.Class,
		number: uint64(request.Sequence),
	}, nil
}

func (client *fakePermitClient) Request(
	_ context.Context,
	request DialPermitRequest,
) (Permit, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.requests = append(client.requests, request)
	if client.trace != nil {
		*client.trace = append(*client.trace, "permit")
	}
	if client.err != nil {
		return Permit{}, client.err
	}
	return Permit{
		slot:   request.SlotID,
		class:  request.Class,
		number: uint64(request.Sequence),
	}, nil
}

func TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	first := publicV4(8, 8, 4, 4)
	second := publicV4(8, 8, 8, 8)
	var trace []string
	resolver := &fakeResolver{
		answers: []netip.Addr{second, first},
		trace:   &trace,
	}
	literals := &fakeLiteralDialer{
		failures: map[netip.Addr]error{first: errors.New("synthetic refusal")},
		trace:    &trace,
	}
	permits := &fakePermitClient{trace: &trace}
	dialer, err := NewBrokerDialer(graph, 3, 7, resolver, literals, permits)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	frame, err := EncodeDialRequest(DialRequest{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("EncodeDialRequest: %v", err)
	}

	connection, err := dialer.DialFrame(context.Background(), frame)
	if err != nil {
		t.Fatalf("DialFrame: %v", err)
	}
	_ = connection.Close()
	wantTrace := []string{
		"resolve",
		"permit",
		"dial:" + first.String(),
		"permit",
		"dial:" + second.String(),
	}
	if strings.Join(trace, ",") != strings.Join(wantTrace, ",") {
		t.Fatalf("trace = %v, want %v", trace, wantTrace)
	}
	if len(permits.requests) != 2 ||
		permits.requests[0].Class != DialClassJob ||
		permits.requests[0].Sequence != 1 ||
		permits.requests[1].Sequence != 2 {
		t.Fatalf("permit requests = %#v", permits.requests)
	}
}

func TestBrokerDialerRejectsWholeMixedRRSetBeforePermit(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	resolver := &fakeResolver{
		answers: []netip.Addr{publicV4(8, 8, 8, 8), deniedDocumentationV4()},
	}
	literals := &fakeLiteralDialer{}
	permits := &fakePermitClient{}
	dialer, err := NewBrokerDialer(graph, 3, 7, resolver, literals, permits)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	frame, _ := EncodeDialRequest(DialRequest{Host: "example.com", Port: 443})
	if _, err := dialer.DialFrame(context.Background(), frame); err == nil {
		t.Fatal("DialFrame mixed RRset = nil error")
	}
	if len(permits.requests) != 0 || len(literals.calls) != 0 {
		t.Fatalf("mixed RRset crossed permit/dial boundary: permits=%d dials=%d",
			len(permits.requests), len(literals.calls))
	}
}

func TestBrokerDialerLiteralSkipsResolverAndRequiresPermit(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	literal := publicV4(8, 8, 8, 8)
	resolver := &fakeResolver{}
	literals := &fakeLiteralDialer{}
	permits := &fakePermitClient{}
	dialer, err := NewBrokerDialer(graph, 3, 7, resolver, literals, permits)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	frame, _ := EncodeDialRequest(DialRequest{Host: literal.String(), Port: 443})
	connection, err := dialer.DialFrame(context.Background(), frame)
	if err != nil {
		t.Fatalf("DialFrame literal: %v", err)
	}
	_ = connection.Close()
	if len(resolver.calls) != 0 || len(permits.requests) != 1 ||
		len(literals.calls) != 1 || literals.calls[0].Host != literal.String() {
		t.Fatalf("literal path resolver=%v permits=%#v dials=%#v",
			resolver.calls, permits.requests, literals.calls)
	}
}

func TestBrokerDialerPermitFailurePreventsKernelDial(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	literal := publicV4(8, 8, 8, 8)
	literals := &fakeLiteralDialer{}
	permits := &fakePermitClient{err: ErrPermitBudgetExhausted}
	dialer, err := NewBrokerDialer(
		graph,
		3,
		7,
		&fakeResolver{},
		literals,
		permits,
	)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	frame, _ := EncodeDialRequest(DialRequest{Host: literal.String(), Port: 443})
	if _, err := dialer.DialFrame(context.Background(), frame); err == nil {
		t.Fatal("DialFrame permit failure = nil error")
	}
	if len(literals.calls) != 0 {
		t.Fatalf("kernel dials after permit failure = %d, want 0", len(literals.calls))
	}
}

func TestBrokerDialerSerializesPermitSequenceAllocationAndSubmission(
	t *testing.T,
) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	literal := publicV4(8, 8, 8, 8)
	permits := &blockingPermitClient{
		firstEntered:  make(chan struct{}),
		secondEntered: make(chan struct{}),
		releaseFirst:  make(chan struct{}),
	}
	dialer, err := NewBrokerDialer(
		graph,
		3,
		7,
		&fakeResolver{},
		&fakeLiteralDialer{},
		permits,
	)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	frame, err := EncodeDialRequest(DialRequest{
		Host: literal.String(),
		Port: 443,
	})
	if err != nil {
		t.Fatalf("EncodeDialRequest: %v", err)
	}

	firstDone := make(chan error, 1)
	go func() {
		connection, dialErr := dialer.DialFrame(context.Background(), frame)
		if connection != nil {
			_ = connection.Close()
		}
		firstDone <- dialErr
	}()
	<-permits.firstEntered

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		connection, dialErr := dialer.DialFrame(context.Background(), frame)
		if connection != nil {
			_ = connection.Close()
		}
		secondDone <- dialErr
	}()
	<-secondStarted
	select {
	case <-permits.secondEntered:
		close(permits.releaseFirst)
		t.Fatal("second permit request entered before sequence 1 completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(permits.releaseFirst)

	for index, done := range []<-chan error{firstDone, secondDone} {
		select {
		case dialErr := <-done:
			if dialErr != nil {
				t.Fatalf("DialFrame[%d] error = %v", index, dialErr)
			}
		case <-time.After(time.Second):
			t.Fatalf("DialFrame[%d] did not complete", index)
		}
	}
	permits.mu.Lock()
	defer permits.mu.Unlock()
	if len(permits.requests) != 2 ||
		permits.requests[0].Sequence != 1 ||
		permits.requests[1].Sequence != 2 {
		t.Fatalf("permit requests = %#v", permits.requests)
	}
}

func TestBrokerDialerErrorsDoNotDiscloseDestination(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	literal := publicV4(8, 8, 8, 8)
	literals := &fakeLiteralDialer{
		failures: map[netip.Addr]error{literal: errors.New("synthetic secret detail")},
	}
	dialer, err := NewBrokerDialer(
		graph,
		3,
		7,
		&fakeResolver{},
		literals,
		&fakePermitClient{},
	)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	frame, _ := EncodeDialRequest(DialRequest{Host: literal.String(), Port: 443})
	_, err = dialer.DialFrame(context.Background(), frame)
	if err == nil {
		t.Fatal("DialFrame failed dial = nil error")
	}
	for _, forbidden := range []string{literal.String(), "synthetic", "secret"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("DialFrame error %q disclosed %q", err, forbidden)
		}
	}
}

func TestLiteralNetDialerUsesExactAddressFamilyAndBoundedContext(t *testing.T) {
	var network, endpoint string
	var hadDeadline bool
	dialer, err := newLiteralNetDialer(
		2*time.Second,
		func(ctx context.Context, gotNetwork, gotEndpoint string) (net.Conn, error) {
			network, endpoint = gotNetwork, gotEndpoint
			_, hadDeadline = ctx.Deadline()
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	)
	if err != nil {
		t.Fatalf("newLiteralNetDialer: %v", err)
	}
	connection, err := dialer.DialLiteral(
		context.Background(),
		publicV4(8, 8, 8, 8),
		443,
	)
	if err != nil {
		t.Fatalf("DialLiteral: %v", err)
	}
	_ = connection.Close()
	if network != "tcp4" || endpoint != "8.8.8.8:443" || !hadDeadline {
		t.Fatalf("dial network=%q endpoint=%q deadline=%v", network, endpoint, hadDeadline)
	}
	if _, err := dialer.DialLiteral(
		context.Background(),
		netip.Addr{},
		443,
	); err == nil {
		t.Fatal("DialLiteral invalid address = nil error")
	}
}

var _ Resolver = (*fakeResolver)(nil)
var _ LiteralDialer = (*fakeLiteralDialer)(nil)
var _ DialPermitClient = (*fakePermitClient)(nil)
