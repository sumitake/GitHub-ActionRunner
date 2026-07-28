//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

func brokerPlatformSupported() bool { return true }

func observeProcessIdentity(
	pid int,
) (hostruntime.ProcessIdentity, uint32, error) {
	if pid <= 0 {
		return hostruntime.ProcessIdentity{}, 0,
			errors.New("broker-dialer: process identity invalid")
	}
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return hostruntime.ProcessIdentity{}, 0,
			errors.New("broker-dialer: process identity unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil ||
		len(data) == 0 || len(data) > 4096 ||
		bytes.ContainsAny(data, "\r\n") {
		zero(data)
		return hostruntime.ProcessIdentity{}, 0,
			errors.New("broker-dialer: process identity invalid")
	}
	closeParen := bytes.LastIndexByte(data, ')')
	openParen := bytes.Index(data, []byte(" ("))
	if openParen <= 0 || closeParen <= openParen+1 ||
		closeParen+2 >= len(data) ||
		string(data[:openParen]) != strconv.Itoa(pid) ||
		data[closeParen+1] != ' ' {
		zero(data)
		return hostruntime.ProcessIdentity{}, 0,
			errors.New("broker-dialer: process stat invalid")
	}
	fields := strings.Fields(string(data[closeParen+2:]))
	zero(data)
	if len(fields) < 20 {
		return hostruntime.ProcessIdentity{}, 0,
			errors.New("broker-dialer: process stat incomplete")
	}
	ppid, ppidErr := strconv.ParseUint(fields[1], 10, 32)
	start, startErr := strconv.ParseUint(fields[19], 10, 64)
	if ppidErr != nil || startErr != nil || start == 0 ||
		strconv.FormatUint(ppid, 10) != fields[1] ||
		strconv.FormatUint(start, 10) != fields[19] {
		return hostruntime.ProcessIdentity{}, 0,
			errors.New("broker-dialer: process identity fields invalid")
	}
	return hostruntime.ProcessIdentity{
		PID:       uint32(pid),
		StartTime: start,
	}, uint32(ppid), nil
}

func observeAuthorityPeer(
	path string,
	expected hostruntime.AuthorityBinding,
) error {
	beforeDirectory, beforeSocket, err := observeAuthorityObjects(path)
	if err != nil ||
		beforeDirectory != expected.Directory ||
		beforeSocket != expected.Socket {
		return errors.New("broker-dialer: authority objects changed")
	}
	connection, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		return errors.New("broker-dialer: authority peer unavailable")
	}
	defer connection.Close()
	before, err := unixCredentials(connection)
	if err != nil || before.Pid <= 0 ||
		uint32(before.Pid) != expected.Peer.PID ||
		before.Uid != expected.Socket.UID ||
		before.Gid != expected.Socket.GID {
		return errors.New("broker-dialer: authority peer invalid")
	}
	identity, _, err := observeProcessIdentity(int(before.Pid))
	if err != nil || identity != expected.Peer {
		return errors.New("broker-dialer: authority process changed")
	}
	after, err := unixCredentials(connection)
	if err != nil || *after != *before {
		return errors.New("broker-dialer: authority credentials changed")
	}
	afterDirectory, afterSocket, err := observeAuthorityObjects(path)
	if err != nil ||
		afterDirectory != beforeDirectory ||
		afterSocket != beforeSocket {
		return errors.New("broker-dialer: authority objects changed")
	}
	return nil
}

func unixCredentials(connection *net.UnixConn) (*unix.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	}); err != nil {
		return nil, err
	}
	return credential, socketErr
}

func observeAuthorityObjects(
	socketPath string,
) (
	hostruntime.DirectoryIdentity,
	hostruntime.SocketIdentity,
	error,
) {
	directory := filepath.Dir(socketPath)
	document, err := inspectAuthorityFilesystemAt(directory, socketPath)
	if err != nil {
		return hostruntime.DirectoryIdentity{},
			hostruntime.SocketIdentity{}, err
	}
	var wire authorityFilesystemDocument
	if err := json.Unmarshal(document, &wire); err != nil {
		zero(document)
		return hostruntime.DirectoryIdentity{},
			hostruntime.SocketIdentity{},
			errors.New("broker-dialer: authority identity invalid")
	}
	canonical, err := json.Marshal(wire)
	canonical = append(canonical, '\n')
	if err != nil || !bytes.Equal(canonical, document) {
		zero(document)
		zero(canonical)
		return hostruntime.DirectoryIdentity{},
			hostruntime.SocketIdentity{},
			errors.New("broker-dialer: authority identity noncanonical")
	}
	zero(document)
	zero(canonical)
	return wire.Directory, wire.Socket, nil
}

func observeFDIdentity(file *os.File) (uint64, uint64, error) {
	if file == nil {
		return 0, 0, errors.New("broker-dialer: descriptor invalid")
	}
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		stat.Dev == 0 || stat.Ino == 0 {
		return 0, 0, errors.New("broker-dialer: descriptor identity invalid")
	}
	return uint64(stat.Dev), stat.Ino, nil
}

func observeProcessFDIdentity(pid int, fd int) (uint64, uint64, error) {
	if pid <= 0 || fd < 0 {
		return 0, 0, errors.New("broker-dialer: process descriptor invalid")
	}
	var stat unix.Stat_t
	if unix.Stat(
		"/proc/"+strconv.Itoa(pid)+"/fd/"+strconv.Itoa(fd),
		&stat,
	) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		stat.Dev == 0 || stat.Ino == 0 {
		return 0, 0, errors.New("broker-dialer: process descriptor unavailable")
	}
	return uint64(stat.Dev), stat.Ino, nil
}
