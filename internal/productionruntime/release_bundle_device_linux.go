//go:build linux

package productionruntime

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func releaseIdentityFields(
	info os.FileInfo,
) (releaseFileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return releaseFileIdentity{}, false
	}
	return releaseFileIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
	}, true
}

func releaseDeviceNumbers(device uint64) (uint32, uint32, bool) {
	major := unix.Major(device)
	return major, unix.Minor(device), major != 0
}
