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
	guard, socketPath, err := openBrokerGuard(
		fixture.directory,
		fixture.binding,
	)
	if err != nil {
		t.Fatalf("openBrokerGuard: %v", err)
	}
	if socketPath != fixture.socketPath {
		t.Fatalf("socket path = %q, want %q", socketPath, fixture.socketPath)
	}

	alias := fixture.directory + "-alias"
	if err := os.Symlink(fixture.directory, alias); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	if _, _, err := openBrokerGuard(alias, fixture.binding); err == nil {
		t.Fatal("openBrokerGuard accepted a directory alias")
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
	if err := guard.Verify(); err == nil {
		t.Fatal("retained broker guard accepted same-UID socket replacement")
	}
}

func TestRelayOneCopiesOpaqueBytesAndPropagatesHalfClose(t *testing.T) {
	fixture := newBrokerSocketFixture(t)
	defer fixture.listener.Close()
	brokerGuard, brokerSocketPath, err := openBrokerGuard(
		fixture.directory,
		fixture.binding,
	)
	if err != nil {
		t.Fatalf("openBrokerGuard: %v", err)
	}
	defer brokerGuard.Close()
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
		brokerGuard:      brokerGuard,
		brokerSocketPath: brokerSocketPath,
		binding:          fixture.binding,
		ioTimeout:        2 * time.Second,
		verifyPeer:       func(*net.UnixConn, relaycontract.Binding) error { return nil },
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

func TestRelayDuplexKeepsOneWayProgressAlive(t *testing.T) {
	left, leftPeer := newTCPConnectionPair(t)
	right, rightPeer := newTCPConnectionPair(t)
	const timeout = 400 * time.Millisecond
	for _, peer := range []*net.TCPConn{leftPeer, rightPeer} {
		if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	}

	done := make(chan error, 1)
	go func() { done <- relayDuplex(left, right, timeout) }()
	started := time.Now()
	for index := byte(0); index < 6; index++ {
		if _, err := leftPeer.Write([]byte{index}); err != nil {
			t.Fatalf("one-way Write[%d]: %v", index, err)
		}
		var received [1]byte
		if _, err := io.ReadFull(rightPeer, received[:]); err != nil {
			t.Fatalf("one-way Read[%d]: %v", index, err)
		}
		if received[0] != index {
			t.Fatalf("one-way byte[%d]=%d", index, received[0])
		}
		if index < 5 {
			time.Sleep(timeout / 4)
		}
	}
	if elapsed := time.Since(started); elapsed <= timeout {
		t.Fatalf("one-way transfer elapsed=%s, want >%s", elapsed, timeout)
	}
	if err := leftPeer.CloseWrite(); err != nil {
		t.Fatalf("left CloseWrite: %v", err)
	}
	var eof [1]byte
	if count, err := rightPeer.Read(eof[:]); count != 0 || err != io.EOF {
		t.Fatalf("right EOF count=%d err=%v", count, err)
	}
	if err := rightPeer.CloseWrite(); err != nil {
		t.Fatalf("right CloseWrite: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relayDuplex: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relayDuplex did not finish after both half-closes")
	}
}

func TestRelayDuplexBoundsBlockedDestination(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()

	done := make(chan error, 1)
	go func() { done <- relayDuplex(left, right, 50*time.Millisecond) }()
	writeDone := make(chan error, 1)
	go func() {
		_, err := leftPeer.Write(make([]byte, relayBufferBytes))
		writeDone <- err
	}()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("source write did not reach the relay")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("relayDuplex accepted a permanently blocked destination")
		}
	case <-time.After(time.Second):
		t.Fatal("relayDuplex did not bound a blocked destination")
	}
}

func newTCPConnectionPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP(
		"tcp4",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
	)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	peer, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatalf("DialTCP: %v", err)
	}
	relay, err := listener.AcceptTCP()
	_ = listener.Close()
	if err != nil {
		_ = peer.Close()
		t.Fatalf("AcceptTCP: %v", err)
	}
	t.Cleanup(func() {
		_ = relay.Close()
		_ = peer.Close()
	})
	return relay, peer
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
