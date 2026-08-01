//go:build darwin

package networkjail

import (
	"math"
	"net"
	"os"

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
		pid        int
		controlErr error
	)
	if err := raw.Control(func(fd uintptr) {
		pid, controlErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERPID,
		)
	}); err != nil || controlErr != nil || pid <= 0 {
		return PermitPeer{}, ErrPermitPeerInvalid
	}
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || process == nil ||
		process.Proc.P_starttime.Sec <= 0 ||
		process.Proc.P_starttime.Usec < 0 ||
		uint64(process.Proc.P_starttime.Sec) >
			(math.MaxUint64-uint64(process.Proc.P_starttime.Usec))/1_000_000 {
		return PermitPeer{}, ErrPermitPeerInvalid
	}
	startTime := uint64(process.Proc.P_starttime.Sec)*1_000_000 +
		uint64(process.Proc.P_starttime.Usec)
	return newPermitPeer(pid, uint32(os.Getuid()), startTime), nil
}
