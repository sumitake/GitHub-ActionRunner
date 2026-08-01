package networkjail

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type serverLiteralDialer struct {
	mu         sync.Mutex
	connection net.Conn
	calls      []DialRequest
}

type deadlinePermitClient struct {
	entered chan time.Time
}

func (client *deadlinePermitClient) Request(
	ctx context.Context,
	_ DialPermitRequest,
) (Permit, error) {
	deadline, found := ctx.Deadline()
	if !found {
		deadline = time.Time{}
	}
	client.entered <- deadline
	<-ctx.Done()
	return Permit{}, ctx.Err()
}

func (dialer *serverLiteralDialer) DialLiteral(
	_ context.Context,
	address netip.Addr,
	port uint16,
) (net.Conn, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	dialer.calls = append(
		dialer.calls,
		DialRequest{Host: address.String(), Port: port},
	)
	connection := dialer.connection
	dialer.connection = nil
	return connection, nil
}

func TestBrokerControlServerOwnsUpstreamAndRelaysAfterPermit(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	upstreamClient, upstreamServer := net.Pipe()
	t.Cleanup(func() {
		_ = upstreamClient.Close()
		_ = upstreamServer.Close()
	})
	resolver := &fakeResolver{answers: []netip.Addr{publicV4(8, 8, 4, 4)}}
	literals := &serverLiteralDialer{connection: upstreamClient}
	permits := &fakePermitClient{}
	dialer, err := NewBrokerDialer(graph, 7, 11, resolver, literals, permits)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	server, err := NewBrokerControlServer(dialer, BrokerControlConfig{
		HandshakeTimeout: time.Second,
		RelayTimeout:     time.Second,
		MaxClients:       1,
	})
	if err != nil {
		t.Fatalf("NewBrokerControlServer: %v", err)
	}
	controlClient, controlServer := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- server.handleControl(context.Background(), controlServer)
	}()
	frame, err := EncodeDialRequest(DialRequest{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("EncodeDialRequest: %v", err)
	}
	if err := writeDialRequestFrame(controlClient, frame); err != nil {
		t.Fatalf("writeDialRequestFrame: %v", err)
	}
	allowed, err := readDialStatus(controlClient)
	if err != nil || !allowed {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if _, err := controlClient.Write([]byte("ping")); err != nil {
		t.Fatalf("control write: %v", err)
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(upstreamServer, request); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(request) != "ping" {
		t.Fatalf("upstream request=%q", request)
	}
	if _, err := upstreamServer.Write([]byte("pong")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(controlClient, response); err != nil {
		t.Fatalf("control read: %v", err)
	}
	if string(response) != "pong" {
		t.Fatalf("control response=%q", response)
	}
	_ = controlClient.Close()
	_ = upstreamServer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleControl: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handleControl did not stop")
	}
	if len(permits.requests) != 1 || len(literals.calls) != 1 {
		t.Fatalf("permits=%d dials=%d", len(permits.requests), len(literals.calls))
	}
}

func TestBrokerControlServerRejectsInvalidFrameWithoutDial(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dialer, err := NewBrokerDialer(
		graph,
		7,
		11,
		&fakeResolver{},
		&fakeLiteralDialer{},
		&fakePermitClient{},
	)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	server, err := NewBrokerControlServer(dialer, BrokerControlConfig{
		HandshakeTimeout: time.Second,
		RelayTimeout:     time.Second,
		MaxClients:       1,
	})
	if err != nil {
		t.Fatalf("NewBrokerControlServer: %v", err)
	}
	controlClient, controlServer := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.handleControl(context.Background(), controlServer) }()
	_, _ = controlClient.Write([]byte("not-a-frame"))
	_ = controlClient.Close()
	if err := <-done; err == nil {
		t.Fatal("invalid control frame was accepted")
	}
}

func TestBrokerControlServerPropagatesHandshakeDeadlineToPermit(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	permits := &deadlinePermitClient{entered: make(chan time.Time, 1)}
	literals := &fakeLiteralDialer{}
	dialer, err := NewBrokerDialer(
		graph,
		7,
		11,
		&fakeResolver{},
		literals,
		permits,
	)
	if err != nil {
		t.Fatalf("NewBrokerDialer: %v", err)
	}
	const handshakeTimeout = 100 * time.Millisecond
	server, err := NewBrokerControlServer(dialer, BrokerControlConfig{
		HandshakeTimeout: handshakeTimeout,
		RelayTimeout:     time.Second,
		MaxClients:       1,
	})
	if err != nil {
		t.Fatalf("NewBrokerControlServer: %v", err)
	}
	controlClient, controlServer := net.Pipe()
	defer controlClient.Close()
	defer controlServer.Close()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- server.handleControl(parent, controlServer) }()
	frame, err := EncodeDialRequest(DialRequest{
		Host: publicV4(8, 8, 8, 8).String(),
		Port: 443,
	})
	if err != nil {
		t.Fatalf("EncodeDialRequest: %v", err)
	}
	if err := writeDialRequestFrame(controlClient, frame); err != nil {
		t.Fatalf("writeDialRequestFrame: %v", err)
	}
	select {
	case deadline := <-permits.entered:
		if deadline.IsZero() || deadline.Before(started) ||
			deadline.After(started.Add(2*handshakeTimeout)) {
			t.Fatalf("permit deadline=%s started=%s", deadline, started)
		}
	case <-time.After(time.Second):
		t.Fatal("permit request did not enter")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired handshake returned nil error")
		}
	case <-time.After(500 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("handshake deadline did not cancel permit submission")
	}
	literals.mu.Lock()
	literalCalls := len(literals.calls)
	literals.mu.Unlock()
	if literalCalls != 0 {
		t.Fatalf("literal dials after permit deadline=%d", literalCalls)
	}
}
