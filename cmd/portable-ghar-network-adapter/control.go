package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
	"github.com/sumitake/portable-ghar/internal/unixsocketguard"
	"golang.org/x/sys/unix"
)

type adapterConfig struct {
	controlDirectory string
	controlSocket    string
	brokerDirectory  string
	endpoints        []relayEndpoint
	maxConnections   int
	ioTimeout        time.Duration
	verifyControl    controlPeerVerifier
	verifyPeer       peerVerifier
}

type controlPeerVerifier func(*net.UnixConn) error

func holdAdapter(config adapterConfig) (result error) {
	if !canonicalAbsolute(config.controlDirectory) ||
		!canonicalAbsolute(config.controlSocket) ||
		!canonicalAbsolute(config.brokerDirectory) ||
		filepath.Dir(config.controlSocket) != config.controlDirectory ||
		config.maxConnections <= 0 || config.ioTimeout <= 0 ||
		config.verifyControl == nil || config.verifyPeer == nil ||
		validateRelayEndpoints(config.endpoints) != nil {
		return errors.New("network-adapter: runtime configuration invalid")
	}
	if err := verifyPrivateDirectory(config.controlDirectory); err != nil {
		return err
	}
	if err := verifyBrokerDirectoryBaseline(config.brokerDirectory); err != nil {
		return err
	}
	control, controlGuard, err := listenControlSocket(config.controlSocket)
	if err != nil {
		return err
	}
	controlOpen := true
	defer func() {
		if controlOpen {
			result = errors.Join(
				result,
				closeOwnedControlSocket(control, controlGuard),
			)
		}
	}()

	connection, err := control.AcceptUnix()
	if err != nil {
		return errors.New("network-adapter: control accept failed")
	}
	binding, err := readBindingConnection(connection, config.ioTimeout, config.verifyControl)
	if err != nil {
		connection.Close()
		return err
	}
	brokerGuard, brokerSocketPath, err := openBrokerGuard(
		config.brokerDirectory,
		binding,
	)
	if err != nil {
		connection.Close()
		return err
	}
	brokerGuardOpen := true
	defer func() {
		if brokerGuardOpen {
			if closeErr := brokerGuard.Close(); closeErr != nil {
				result = errors.Join(
					result,
					errors.New("network-adapter: broker guard close failed"),
				)
			}
		}
	}()
	machine := relayMachine{
		brokerGuard:      brokerGuard,
		brokerSocketPath: brokerSocketPath,
		binding:          binding,
		ioTimeout:        config.ioTimeout,
		verifyPeer:       config.verifyPeer,
	}
	listeners, err := openRelayListeners(config.endpoints)
	if err != nil {
		connection.Close()
		return err
	}
	defer closeRelayListeners(listeners)
	if err := connection.SetWriteDeadline(time.Now().Add(config.ioTimeout)); err != nil {
		connection.Close()
		return errors.New("network-adapter: control deadline failed")
	}
	if written, err := connection.Write([]byte("OK\n")); err != nil || written != 3 {
		connection.Close()
		return errors.New("network-adapter: control response failed")
	}
	if err := connection.Close(); err != nil {
		return errors.New("network-adapter: control close failed")
	}
	if err := closeOwnedControlSocket(control, controlGuard); err != nil {
		return err
	}
	controlOpen = false
	serveErr := serveRelayListeners(
		context.Background(),
		listeners,
		machine,
		config.maxConnections,
	)
	if err := brokerGuard.Close(); err != nil {
		serveErr = errors.Join(
			serveErr,
			errors.New("network-adapter: broker guard close failed"),
		)
	}
	brokerGuardOpen = false
	return serveErr
}

func forwardBinding(
	ctx context.Context,
	socketPath string,
	binding relaycontract.Binding,
	timeout time.Duration,
) error {
	if ctx == nil || !canonicalAbsolute(socketPath) || timeout <= 0 {
		return errors.New("network-adapter: bind forward inputs invalid")
	}
	document, err := relaycontract.Encode(binding)
	if err != nil {
		return err
	}
	defer zero(document)
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return errors.New("network-adapter: bind forward connect failed")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		raw.Close()
		return errors.New("network-adapter: bind forward transport invalid")
	}
	defer connection.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancel()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("network-adapter: bind forward deadline failed")
	}
	if written, err := connection.Write(document); err != nil || written != len(document) {
		return errors.New("network-adapter: bind forward write failed")
	}
	if err := connection.CloseWrite(); err != nil {
		return errors.New("network-adapter: bind forward close-write failed")
	}
	response, err := io.ReadAll(io.LimitReader(connection, 4))
	if err != nil || !bytes.Equal(response, []byte("OK\n")) {
		return errors.New("network-adapter: bind forward response invalid")
	}
	return nil
}

func readBindingConnection(
	connection *net.UnixConn,
	timeout time.Duration,
	verifyControl controlPeerVerifier,
) (relaycontract.Binding, error) {
	if connection == nil || timeout <= 0 || verifyControl == nil {
		return relaycontract.Binding{}, errors.New("network-adapter: control connection invalid")
	}
	if err := verifyControl(connection); err != nil {
		return relaycontract.Binding{}, errors.New("network-adapter: control peer invalid")
	}
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return relaycontract.Binding{}, errors.New("network-adapter: control deadline failed")
	}
	return relaycontract.Load(connection)
}

func verifyPrivateDirectory(directory string) error {
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("network-adapter: private directory indirect")
	}
	var stat unix.Stat_t
	if unix.Lstat(directory, &stat) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(stat.Mode)&0o777 != 0o700 ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New("network-adapter: private directory identity invalid")
	}
	return nil
}

func verifyBrokerDirectoryBaseline(directory string) error {
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("network-adapter: broker directory indirect")
	}
	var stat unix.Stat_t
	if unix.Lstat(directory, &stat) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(stat.Mode)&0o777 != 0o700 ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New("network-adapter: broker directory identity invalid")
	}
	return nil
}

func listenControlSocket(
	path string,
) (*net.UnixListener, *unixsocketguard.OwnedGuard, error) {
	var existing unix.Stat_t
	if err := unix.Lstat(path, &existing); err == nil || !errors.Is(err, unix.ENOENT) {
		return nil, nil, errors.New("network-adapter: control socket exists")
	}
	oldMask := unix.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(oldMask)
	if err != nil {
		return nil, nil, errors.New("network-adapter: control listen failed")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, nil, errors.New("network-adapter: control chmod failed")
	}
	root := filepath.Dir(path)
	name := filepath.Base(path)
	snapshot, err := unixsocketguard.Observe(root, name)
	if err != nil ||
		snapshot.Directory.UID != uint32(os.Geteuid()) ||
		snapshot.Socket.UID != uint32(os.Geteuid()) {
		listener.SetUnlinkOnClose(false)
		_ = listener.Close()
		return nil, nil, errors.New("network-adapter: control identity invalid")
	}
	guard, err := unixsocketguard.OpenOwned(root, snapshot)
	if err != nil {
		current, observeErr := unixsocketguard.Observe(root, name)
		if observeErr != nil || current != snapshot {
			listener.SetUnlinkOnClose(false)
		}
		_ = listener.Close()
		return nil, nil, errors.New("network-adapter: control identity invalid")
	}
	listener.SetUnlinkOnClose(false)
	return listener, guard, nil
}

func closeOwnedControlSocket(
	listener *net.UnixListener,
	guard *unixsocketguard.OwnedGuard,
) error {
	if listener == nil || guard == nil || guard.Verify() != nil {
		return errors.New("network-adapter: control socket replacement detected")
	}
	if err := listener.Close(); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		return errors.New("network-adapter: control listener close failed")
	}
	if guard.Verify() != nil || guard.Remove() != nil {
		return errors.New("network-adapter: control socket replacement detected")
	}
	if guard.Close() != nil {
		return errors.New("network-adapter: control guard close failed")
	}
	return nil
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
