//go:build darwin

package networkjail

import (
	"errors"
	"math"
	"os"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

func readAuthorityPathIdentity(
	path string,
	socket bool,
) (hostruntime.DirectoryIdentity, hostruntime.SocketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return hostruntime.DirectoryIdentity{}, hostruntime.SocketIdentity{},
			errors.New("networkjail: authority identity unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return hostruntime.DirectoryIdentity{}, hostruntime.SocketIdentity{},
			errors.New("networkjail: authority identity unavailable")
	}
	if socket {
		if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
			return hostruntime.DirectoryIdentity{}, hostruntime.SocketIdentity{},
				errors.New("networkjail: authority socket identity invalid")
		}
		return hostruntime.DirectoryIdentity{}, hostruntime.SocketIdentity{
			Name:   "dial-authority.sock",
			Device: uint64(stat.Dev),
			Inode:  stat.Ino,
			UID:    stat.Uid,
			GID:    stat.Gid,
			Mode:   uint32(info.Mode().Perm()),
		}, nil
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return hostruntime.DirectoryIdentity{}, hostruntime.SocketIdentity{},
			errors.New("networkjail: authority directory identity invalid")
	}
	return hostruntime.DirectoryIdentity{
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		UID:    stat.Uid,
		GID:    stat.Gid,
		Mode:   uint32(info.Mode().Perm()),
	}, hostruntime.SocketIdentity{}, nil
}

func currentAuthorityProcessIdentity() (hostruntime.ProcessIdentity, error) {
	pid := os.Getpid()
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || process == nil || pid <= 0 ||
		process.Proc.P_starttime.Sec <= 0 ||
		process.Proc.P_starttime.Usec < 0 ||
		uint64(process.Proc.P_starttime.Sec) >
			(math.MaxUint64-uint64(process.Proc.P_starttime.Usec))/1_000_000 {
		return hostruntime.ProcessIdentity{},
			errors.New("networkjail: authority process identity unavailable")
	}
	return hostruntime.ProcessIdentity{
		PID: uint32(pid),
		StartTime: uint64(process.Proc.P_starttime.Sec)*1_000_000 +
			uint64(process.Proc.P_starttime.Usec),
	}, nil
}
