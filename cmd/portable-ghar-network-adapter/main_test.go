package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
)

func TestRunBindPeerAcceptsOnlyCanonicalBoundedFrame(t *testing.T) {
	binding := testBinding()
	document, err := relaycontract.Encode(binding)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var received relaycontract.Binding
	runtime := adapterRuntime{
		ioTimeout: time.Second,
		bindPeer: func(_ context.Context, candidate relaycontract.Binding) error {
			received = candidate
			return nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"bind-peer"}, bytes.NewReader(document), &stdout, &stderr, runtime); code != 0 {
		t.Fatalf("bind-peer code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if received != binding || stdout.String() != "OK\n" || stderr.Len() != 0 {
		t.Fatalf("received=%+v stdout=%q stderr=%q", received, stdout.String(), stderr.String())
	}

	for name, payload := range map[string][]byte{
		"empty":        nil,
		"trailing":     append(append([]byte{}, document...), 'x'),
		"noncanonical": []byte(strings.Replace(string(document), `{"version":1`, "{\n\"version\":1", 1)),
		"oversized":    bytes.Repeat([]byte("x"), relaycontract.MaxBindingBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			called := false
			runtime.bindPeer = func(context.Context, relaycontract.Binding) error {
				called = true
				return nil
			}
			if code := run([]string{"bind-peer"}, bytes.NewReader(payload), &stdout, &stderr, runtime); code != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if called || stdout.Len() != 0 || stderr.String() != "portable-ghar-network-adapter: unavailable\n" {
				t.Fatalf("called=%v stdout=%q stderr=%q", called, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunNetNSIDIsInputFreeAndCanonical(t *testing.T) {
	runtime := adapterRuntime{
		ioTimeout: time.Second,
		namespace: func() ([]byte, error) {
			return []byte("{\"version\":1,\"device\":7,\"inode\":8}\n"), nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"netns-id"}, nil, &stdout, &stderr, runtime); code != 0 {
		t.Fatalf("netns-id code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "{\"version\":1,\"device\":7,\"inode\":8}\n" || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"netns-id"}, strings.NewReader("x"), &stdout, &stderr, runtime); code != 1 {
		t.Fatalf("netns-id with input code=%d", code)
	}
}

func TestRunHoldDelegatesToClosedRuntime(t *testing.T) {
	called := false
	runtime := adapterRuntime{
		ioTimeout: time.Second,
		hold: func() error {
			called = true
			return errors.New("fixture terminal")
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hold"}, nil, &stdout, &stderr, runtime); code != 1 {
		t.Fatalf("hold code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !called {
		t.Fatal("hold runtime was not invoked")
	}
}

func TestRequireEmptyInput(t *testing.T) {
	if requireEmptyInput(nil) != nil || requireEmptyInput(bytes.NewReader(nil)) != nil {
		t.Fatal("empty input rejected")
	}
	if err := requireEmptyInput(strings.NewReader("x")); err == nil {
		t.Fatal("nonempty input accepted")
	}
	if err := requireEmptyInput(errorReader{}); err == nil {
		t.Fatal("input error accepted")
	}
}

func TestReadBindingConnectionRequiresApprovedControlPeer(t *testing.T) {
	binding := testBinding()
	document, err := relaycontract.Encode(binding)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	temporary, err := os.MkdirTemp("/private/tmp", "pghar-control-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(temporary) })
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: filepath.Join(temporary, "control.sock"), Net: "unix"},
	)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()

	dial := func() *net.UnixConn {
		t.Helper()
		client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
		if err != nil {
			t.Fatalf("DialUnix: %v", err)
		}
		go func() {
			defer client.Close()
			_, _ = client.Write(document)
			_ = client.CloseWrite()
		}()
		connection, err := listener.AcceptUnix()
		if err != nil {
			t.Fatalf("AcceptUnix: %v", err)
		}
		return connection
	}

	rejected := dial()
	called := false
	if _, err := readBindingConnection(
		rejected,
		time.Second,
		func(*net.UnixConn) error {
			called = true
			return errors.New("fixture peer rejected")
		},
	); err == nil {
		t.Fatal("readBindingConnection accepted a rejected control peer")
	}
	_ = rejected.Close()
	if !called {
		t.Fatal("readBindingConnection skipped control peer verification")
	}

	accepted := dial()
	loaded, err := readBindingConnection(
		accepted,
		time.Second,
		func(*net.UnixConn) error { return nil },
	)
	_ = accepted.Close()
	if err != nil {
		t.Fatalf("readBindingConnection: %v", err)
	}
	if loaded != binding {
		t.Fatalf("loaded=%+v want=%+v", loaded, binding)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func testBinding() relaycontract.Binding {
	return relaycontract.Binding{
		Version:          1,
		BrokerGeneration: 17,
		Directory: relaycontract.Directory{
			Device: 101, Inode: 102, UID: 65532, GID: 65532, Mode: 0o700,
		},
		Socket: relaycontract.Socket{
			Name:   relaycontract.HTTPSProxySocket,
			Device: 101, Inode: 103, UID: 65532, GID: 65532, Mode: 0o600,
		},
		Peer: relaycontract.Process{PID: 7001, StartTime: 7002},
	}
}
