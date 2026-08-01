//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
	"golang.org/x/sys/unix"
)

func verifyUnixPeer(connection *net.UnixConn, binding relaycontract.Binding) error {
	want := binding.Peer
	if connection == nil || relaycontract.Validate(binding) != nil {
		return errors.New("network-adapter: peer proof invalid")
	}
	before, err := unixPeerCredentials(connection)
	if err != nil || before.Pid <= 0 || uint32(before.Pid) != want.PID ||
		before.Uid != binding.Socket.UID || before.Gid != binding.Socket.GID {
		return errors.New("network-adapter: peer credentials differ")
	}
	start, err := linuxProcessStartTime(want.PID)
	if err != nil || start != want.StartTime {
		return errors.New("network-adapter: peer process identity differs")
	}
	after, err := unixPeerCredentials(connection)
	if err != nil || *after != *before {
		return errors.New("network-adapter: peer credentials changed")
	}
	return nil
}

func verifyControlPeer(connection *net.UnixConn) error {
	if connection == nil {
		return errors.New("network-adapter: control peer unavailable")
	}
	credentials, err := unixPeerCredentials(connection)
	if err != nil || credentials.Uid != uint32(os.Geteuid()) ||
		credentials.Gid != uint32(os.Getegid()) {
		return errors.New("network-adapter: control peer credentials differ")
	}
	return nil
}

func unixPeerCredentials(connection *net.UnixConn) (*unix.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return credentials, socketErr
}

func linuxProcessStartTime(pid uint32) (uint64, error) {
	path := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat"
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > 4096 ||
		bytes.ContainsAny(data, "\r\n") {
		return 0, errors.New("network-adapter: peer stat invalid")
	}
	closeParen := bytes.LastIndexByte(data, ')')
	openParen := bytes.Index(data, []byte(" ("))
	if openParen <= 0 || closeParen <= openParen+1 || closeParen+2 >= len(data) ||
		string(data[:openParen]) != strconv.FormatUint(uint64(pid), 10) ||
		data[closeParen+1] != ' ' {
		return 0, errors.New("network-adapter: peer stat shape invalid")
	}
	fields := strings.Fields(string(data[closeParen+2:]))
	if len(fields) < 20 {
		return 0, errors.New("network-adapter: peer stat fields invalid")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 || strconv.FormatUint(start, 10) != fields[19] {
		return 0, errors.New("network-adapter: peer start time invalid")
	}
	return start, nil
}
