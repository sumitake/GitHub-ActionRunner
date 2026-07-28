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
	"time"

	"golang.org/x/sys/unix"
)

const maxGateResponseBytes = 512

type gateSocketIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
}

func listenGateSocket(path string) (*net.UnixListener, gateSocketIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, gateSocketIdentity{}, errors.New("runner-gate: socket path invalid")
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, gateSocketIdentity{}, errors.New("runner-gate: socket parent indirect")
	}
	var parentStat unix.Stat_t
	if unix.Lstat(parent, &parentStat) != nil || uint32(parentStat.Mode)&unix.S_IFMT != unix.S_IFDIR || uint32(parentStat.Mode)&0o777 != 0o700 || parentStat.Uid != uint32(os.Geteuid()) {
		return nil, gateSocketIdentity{}, errors.New("runner-gate: socket parent identity invalid")
	}
	var existing unix.Stat_t
	if err := unix.Lstat(path, &existing); err == nil || !errors.Is(err, unix.ENOENT) {
		return nil, gateSocketIdentity{}, errors.New("runner-gate: socket path already exists")
	}

	oldMask := unix.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(oldMask)
	if err != nil {
		return nil, gateSocketIdentity{}, errors.New("runner-gate: socket listen failed")
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return nil, gateSocketIdentity{}, errors.New("runner-gate: socket chmod failed")
	}
	var socketStat unix.Stat_t
	if unix.Lstat(path, &socketStat) != nil || uint32(socketStat.Mode)&unix.S_IFMT != unix.S_IFSOCK || uint32(socketStat.Mode)&0o777 != 0o600 || socketStat.Uid != uint32(os.Geteuid()) {
		listener.Close()
		_ = os.Remove(path)
		return nil, gateSocketIdentity{}, errors.New("runner-gate: socket identity invalid")
	}
	return listener, gateSocketIdentity{
		device: uint64(socketStat.Dev),
		inode:  socketStat.Ino,
		uid:    socketStat.Uid,
		gid:    socketStat.Gid,
	}, nil
}

func serveGateListener(listener *net.UnixListener, identity gateSocketIdentity, machine *gateMachine, ioTimeout time.Duration) error {
	if listener == nil || machine == nil || ioTimeout <= 0 {
		return errors.New("runner-gate: server inputs invalid")
	}
	path := listener.Addr().String()
	defer listener.Close()
	defer removeOwnedGateSocket(path, identity)

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			machine.phase = phaseFailed
			return errors.New("runner-gate: accept failed")
		}
		response, action, err := serveGateConnection(connection, machine, ioTimeout)
		if err == nil {
			_ = connection.SetWriteDeadline(time.Now().Add(ioTimeout))
			written, writeErr := connection.Write(response)
			if writeErr != nil || written != len(response) {
				err = errors.New("runner-gate: response write failed")
			}
		}
		closeErr := connection.Close()
		if err != nil || closeErr != nil {
			machine.phase = phaseFailed
			return errors.New("runner-gate: connection terminal failure")
		}
		if action != nil {
			if err := listener.Close(); err != nil {
				machine.phase = phaseFailed
				return errors.New("runner-gate: listener close failed")
			}
			if err := removeOwnedGateSocket(path, identity); err != nil {
				machine.phase = phaseFailed
				return err
			}
			return action()
		}
	}
}

func serveGateConnection(connection *net.UnixConn, machine *gateMachine, ioTimeout time.Duration) ([]byte, func() error, error) {
	if err := connection.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, nil, errors.New("runner-gate: deadline failed")
	}
	var opcode [1]byte
	if _, err := io.ReadFull(connection, opcode[:]); err != nil {
		return nil, nil, errors.New("runner-gate: opcode read failed")
	}
	operation := gateOperation(opcode[0])
	limit, ok := gatePayloadLimit(operation)
	if !ok {
		return nil, nil, errors.New("runner-gate: opcode invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(connection, int64(limit)+1))
	if err != nil || len(payload) > limit {
		zero(payload)
		return nil, nil, errors.New("runner-gate: payload invalid")
	}
	defer zero(payload)
	return machine.apply(operation, payload)
}

func forwardGate(ctx context.Context, socketPath string, operation gateOperation, stdin io.Reader, stdout io.Writer, ioTimeout time.Duration) error {
	if ctx == nil || stdout == nil || ioTimeout <= 0 {
		return errors.New("runner-gate: forward inputs invalid")
	}
	limit, ok := gatePayloadLimit(operation)
	if !ok {
		return errors.New("runner-gate: forward operation invalid")
	}
	var payload []byte
	if stdin != nil {
		var err error
		payload, err = io.ReadAll(io.LimitReader(stdin, int64(limit)+1))
		if err != nil || len(payload) > limit {
			zero(payload)
			return errors.New("runner-gate: forward payload invalid")
		}
	}
	defer zero(payload)

	dialer := net.Dialer{}
	rawConnection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return errors.New("runner-gate: forward connect failed")
	}
	connection, ok := rawConnection.(*net.UnixConn)
	if !ok {
		rawConnection.Close()
		return errors.New("runner-gate: forward transport invalid")
	}
	defer connection.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancel()
	deadline := time.Now().Add(ioTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("runner-gate: forward deadline failed")
	}
	frame := append([]byte{byte(operation)}, payload...)
	written, err := connection.Write(frame)
	zero(frame)
	if err != nil || written != 1+len(payload) {
		return errors.New("runner-gate: forward write failed")
	}
	if err := connection.CloseWrite(); err != nil {
		return errors.New("runner-gate: forward close-write failed")
	}
	response, err := io.ReadAll(io.LimitReader(connection, maxGateResponseBytes+1))
	if err != nil || len(response) == 0 || len(response) > maxGateResponseBytes {
		return errors.New("runner-gate: forward response invalid")
	}
	if operation == opNetNSID {
		if !validNamespaceResponse(response) {
			return errors.New("runner-gate: forward namespace response invalid")
		}
	} else if !bytes.Equal(response, []byte("OK\n")) {
		return errors.New("runner-gate: forward acknowledgement invalid")
	}
	written, err = stdout.Write(response)
	if err != nil || written != len(response) {
		return errors.New("runner-gate: forward output failed")
	}
	return nil
}

func gatePayloadLimit(operation gateOperation) (int, bool) {
	switch operation {
	case opHydrateSeeds:
		return 16 << 10, true
	case opNetNSID:
		return 0, true
	case opArm:
		return 44, true
	case opRelease:
		return 47 + maxJITLength, true
	default:
		return 0, false
	}
}

func removeOwnedGateSocket(path string, identity gateSocketIdentity) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil || uint64(stat.Dev) != identity.device || stat.Ino != identity.inode || stat.Uid != identity.uid || stat.Gid != identity.gid || uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("runner-gate: socket replacement detected")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("runner-gate: socket removal failed")
	}
	return nil
}
