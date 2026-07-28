package networkjail

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type pipeControlConnector struct {
	server func(net.Conn)
}

func (connector pipeControlConnector) Connect(context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	go connector.server(server)
	return client, nil
}

func TestBrokerParserRelaysOnlyAfterCanonicalHTTPConnectApproval(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	connector := pipeControlConnector{server: func(connection net.Conn) {
		defer connection.Close()
		frame, err := readDialRequestFrame(connection)
		if err != nil {
			t.Errorf("readDialRequestFrame: %v", err)
			return
		}
		request, err := DecodeDialRequest(frame, graph)
		if err != nil || request.Host != "example.com" || request.Port != 443 {
			t.Errorf("request=%+v err=%v", request, err)
			return
		}
		if err := writeDialStatus(connection, true); err != nil {
			t.Errorf("writeDialStatus: %v", err)
			return
		}
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(connection, buffer); err != nil {
			t.Errorf("relay read: %v", err)
			return
		}
		_, _ = connection.Write(bytes.ToUpper(buffer))
	}}
	parser, err := NewBrokerParser(graph, connector, ParserRuntimeConfig{
		HandshakeTimeout: time.Second,
		RelayTimeout:     time.Second,
		MaxClients:       1,
	})
	if err != nil {
		t.Fatalf("NewBrokerParser: %v", err)
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- parser.handleClient(context.Background(), server) }()
	request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response := make([]byte, len(httpConnectOK))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(response) != httpConnectOK {
		t.Fatalf("response=%q", response)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(client, echo); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(echo) != "PING" {
		t.Fatalf("echo=%q", echo)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleClient: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handleClient did not stop")
	}
}

func TestBrokerParserRejectsPipelinedHTTPBytesBeforeControlDial(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	controlCalled := false
	parser, err := NewBrokerParser(
		graph,
		pipeControlConnector{server: func(connection net.Conn) {
			controlCalled = true
			_ = connection.Close()
		}},
		ParserRuntimeConfig{
			HandshakeTimeout: time.Second,
			RelayTimeout:     time.Second,
			MaxClients:       1,
		},
	)
	if err != nil {
		t.Fatalf("NewBrokerParser: %v", err)
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- parser.handleClient(context.Background(), server) }()
	_, _ = io.WriteString(
		client,
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nextra",
	)
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("pipelined request was accepted")
	}
	if controlCalled {
		t.Fatal("pipelined request reached dialer control")
	}
}

func TestBrokerParserSOCKSHandshakeIsSequentialAndBounded(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	connector := pipeControlConnector{server: func(connection net.Conn) {
		defer connection.Close()
		frame, err := readDialRequestFrame(connection)
		if err != nil {
			t.Errorf("readDialRequestFrame: %v", err)
			return
		}
		request, err := DecodeDialRequest(frame, graph)
		if err != nil || request.Host != "example.com" || request.Port != 443 {
			t.Errorf("request=%+v err=%v", request, err)
			return
		}
		_ = writeDialStatus(connection, true)
		_, _ = io.Copy(io.Discard, connection)
	}}
	parser, err := NewBrokerParser(graph, connector, ParserRuntimeConfig{
		HandshakeTimeout: time.Second,
		RelayTimeout:     time.Second,
		MaxClients:       1,
	})
	if err != nil {
		t.Fatalf("NewBrokerParser: %v", err)
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- parser.handleClient(context.Background(), server) }()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(client, greeting); err != nil ||
		!bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("greeting=%v err=%v", greeting, err)
	}
	host := []byte("example.com")
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	request = append(request, 1, 187)
	if _, err := client.Write(request); err != nil {
		t.Fatalf("request write: %v", err)
	}
	response := make([]byte, len(socksConnectOK))
	if _, err := io.ReadFull(client, response); err != nil ||
		!bytes.Equal(response, socksConnectOK) {
		t.Fatalf("response=%v err=%v", response, err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatalf("handleClient: %v", err)
	}
}
