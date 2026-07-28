//go:build linux

package networkjail

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func observeUnixPermitPeer(connection *net.UnixConn) (PermitPeer, error) {
	if connection == nil {
		return PermitPeer{}, ErrPermitPeerInvalid
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return PermitPeer{}, ErrPermitPeerInvalid
	}
	var (
		credential *unix.Ucred
		controlErr error
	)
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	}); err != nil || controlErr != nil || credential == nil ||
		credential.Pid <= 0 {
		return PermitPeer{}, ErrPermitPeerInvalid
	}
	startTime, err := linuxProcessStartTime(int(credential.Pid))
	if err != nil {
		return PermitPeer{}, ErrPermitPeerInvalid
	}
	return newPermitPeer(
		int(credential.Pid),
		credential.Uid,
		startTime,
	), nil
}

func linuxProcessStartTime(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, errors.New("networkjail: process identity unavailable")
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return 0, errors.New("networkjail: process identity unavailable")
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 || closing+2 >= len(data) {
		return 0, errors.New("networkjail: process identity unavailable")
	}
	fields := strings.Fields(string(data[closing+2:]))
	if len(fields) <= 19 {
		return 0, errors.New("networkjail: process identity unavailable")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return 0, errors.New("networkjail: process identity unavailable")
	}
	return startTime, nil
}
