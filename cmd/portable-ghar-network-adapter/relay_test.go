package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
	"golang.org/x/sys/unix"
)

func TestVerifyBrokerObjectsRejectsAliasAndSameUIDSocketReplacement(t *testing.T) {
	fixture := newBrokerSocketFixture(t)
	if _, err := verifyBrokerObjects(fixture.directory, fixture.binding); err != nil {
		t.Fatalf("verifyBrokerObjects: %v", err)
	}

	alias := fixture.directory + "-alias"
	if err := os.Symlink(fixture.directory, alias); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	if _, err := verifyBrokerObjects(alias, fixture.binding); err == nil {
		t.Fatal("verifyBrokerObjects accepted a directory alias")
	}

	if err := fixture.listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Remove(fixture.socketPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: fixture.socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("replacement ListenUnix: %v", err)
	}
	defer replacement.Close()
	if err := os.Chmod(fixture.socketPath, 0o600); err != nil {
		t.Fatalf("replacement Chmod: %v", err)
	}
	if _, err := verifyBrokerObjects(fixture.directory, fixture.binding); err == nil {
		t.Fatal("verifyBrokerObjects accepted same-UID socket replacement")
	}
}

func TestRelayOneCopiesOpaqueBytesAndPropagatesHalfClose(t *testing.T) {
	fixture := newBrokerSocketFixture(t)
	defer fixture.listener.Close()
	brokerDone := make(chan error, 1)
	go func() {
		connection, err := fixture.listener.AcceptUnix()
		if err != nil {
			brokerDone <- err
			return
		}
		defer connection.Close()
		request, err := io.ReadAll(connection)
		if err != nil {
			brokerDone <- err
			return
		}
		if string(request) != "opaque CONNECT bytes" {
			brokerDone <- errUnexpectedPayload
			return
		}
		_, err = connection.Write([]byte("opaque response"))
		brokerDone <- err
	}()

	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer tcpListener.Close()
	clientRaw, err := net.DialTCP("tcp4", nil, tcpListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer clientRaw.Close()
	serverSide, err := tcpListener.AcceptTCP()
	if err != nil {
		t.Fatalf("AcceptTCP: %v", err)
	}
	machine := relayMachine{
		brokerDirectory: fixture.directory,
		binding:         fixture.binding,
		ioTimeout:       2 * time.Second,
		verifyPeer:      func(*net.UnixConn, relaycontract.Binding) error { return nil },
	}
	relayDone := make(chan error, 1)
	go func() { relayDone <- machine.relayOne(context.Background(), serverSide) }()

	if _, err := clientRaw.Write([]byte("opaque CONNECT bytes")); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if err := clientRaw.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	response, err := io.ReadAll(clientRaw)
	if err != nil || string(response) != "opaque response" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	if err := <-brokerDone; err != nil {
		t.Fatalf("broker: %v", err)
	}
	if err := <-relayDone; err != nil {
		t.Fatalf("relayOne: %v", err)
	}
}

func TestRelayEndpointTableIsClosed(t *testing.T) {
	valid := []relayEndpoint{{LoopbackAddress: "127.0.0.1:18080", SocketName: relaycontract.HTTPSProxySocket}}
	if err := validateRelayEndpoints(valid); err != nil {
		t.Fatalf("validateRelayEndpoints: %v", err)
	}
	tests := [][]relayEndpoint{
		nil,
		{{LoopbackAddress: "0.0.0.0:18080", SocketName: relaycontract.HTTPSProxySocket}},
		{{LoopbackAddress: "127.0.0.1:0", SocketName: relaycontract.HTTPSProxySocket}},
		{{LoopbackAddress: "127.0.0.1:18080", SocketName: "../escape"}},
		{
			{LoopbackAddress: "127.0.0.1:18080", SocketName: relaycontract.HTTPSProxySocket},
			{LoopbackAddress: "127.0.0.1:18080", SocketName: relaycontract.HTTPSProxySocket},
		},
	}
	for _, endpoints := range tests {
		if err := validateRelayEndpoints(endpoints); err == nil {
			t.Fatalf("validateRelayEndpoints accepted %+v", endpoints)
		}
	}
}

func TestRelayServerRejectsClientFloodAtExactCap(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entered := make(chan int32, 2)
	release := make(chan struct{}, 2)
	var calls atomic.Int32
	var active atomic.Int32
	var peak atomic.Int32
	handler := func(ctx context.Context, connection *net.TCPConn) error {
		defer connection.Close()
		call := calls.Add(1)
		now := active.Add(1)
		defer active.Add(-1)
		for {
			previous := peak.Load()
			if now <= previous || peak.CompareAndSwap(previous, now) {
				break
			}
		}
		entered <- call
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveRelayListenersWith(
			ctx,
			[]*net.TCPListener{listener},
			1,
			handler,
		)
	}()

	first := dialTCPFixture(t, listener)
	defer first.Close()
	if call := <-entered; call != 1 {
		t.Fatalf("first call=%d", call)
	}

	second, dialErr := net.DialTCP(
		"tcp4",
		nil,
		listener.Addr().(*net.TCPAddr),
	)
	if dialErr != nil && !isConnectionReset(dialErr) {
		t.Fatalf("over-cap DialTCP: %v", dialErr)
	}
	if second != nil {
		defer second.Close()
		if err := second.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("second SetDeadline: %v", err)
		}
		if _, err := second.Write([]byte("over-cap")); err == nil {
			var probe [1]byte
			if count, readErr := second.Read(probe[:]); count != 0 || readErr == nil {
				t.Fatalf("over-cap client remained open: count=%d err=%v", count, readErr)
			}
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("over-cap client reached handler: calls=%d", calls.Load())
	}

	release <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("first relay did not release its permit")
	}

	third := dialTCPFixture(t, listener)
	defer third.Close()
	select {
	case call := <-entered:
		if call != 2 {
			t.Fatalf("third call=%d", call)
		}
	case <-time.After(time.Second):
		t.Fatal("released permit did not admit the next client")
	}
	release <- struct{}{}
	cancel()
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("canceled relay server returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("relay server did not stop after cancellation")
	}
	if peak.Load() != 1 {
		t.Fatalf("peak active relays=%d want=1", peak.Load())
	}
}

func TestRelayDuplexBoundsSlowClient(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()

	start := time.Now()
	err := relayDuplex(left, right, 25*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("relayDuplex accepted an indefinitely idle client")
	}
	if elapsed > time.Second {
		t.Fatalf("relayDuplex exceeded slow-client bound: %s", elapsed)
	}
}

func dialTCPFixture(t *testing.T, listener *net.TCPListener) *net.TCPConn {
	t.Helper()
	connection, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	return connection
}

type brokerSocketFixture struct {
	directory  string
	socketPath string
	listener   *net.UnixListener
	binding    relaycontract.Binding
}

func newBrokerSocketFixture(t *testing.T) brokerSocketFixture {
	t.Helper()
	temporary, err := os.MkdirTemp(shortTestTempRoot(), "pghar-adapter-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(temporary) })
	root, err := filepath.EvalSymlinks(temporary)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod root: %v", err)
	}
	socketPath := filepath.Join(root, relaycontract.HTTPSProxySocket)
	oldMask := unix.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	unix.Umask(oldMask)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		t.Fatalf("Chmod socket: %v", err)
	}
	var directoryStat, socketStat unix.Stat_t
	if unix.Lstat(root, &directoryStat) != nil || unix.Lstat(socketPath, &socketStat) != nil {
		listener.Close()
		t.Fatal("Lstat fixture failed")
	}
	binding := relaycontract.Binding{
		Version:          1,
		BrokerGeneration: 17,
		Directory: relaycontract.Directory{
			Device: uint64(directoryStat.Dev),
			Inode:  directoryStat.Ino,
			UID:    directoryStat.Uid,
			GID:    directoryStat.Gid,
			Mode:   uint32(directoryStat.Mode) & 0o777,
		},
		Socket: relaycontract.Socket{
			Name:   relaycontract.HTTPSProxySocket,
			Device: uint64(socketStat.Dev),
			Inode:  socketStat.Ino,
			UID:    socketStat.Uid,
			GID:    socketStat.Gid,
			Mode:   uint32(socketStat.Mode) & 0o777,
		},
		Peer: relaycontract.Process{PID: 7001, StartTime: 7002},
	}
	return brokerSocketFixture{directory: root, socketPath: socketPath, listener: listener, binding: binding}
}

var errUnexpectedPayload = &relayTestError{"unexpected payload"}

type relayTestError struct{ message string }

func (e *relayTestError) Error() string { return e.message }
