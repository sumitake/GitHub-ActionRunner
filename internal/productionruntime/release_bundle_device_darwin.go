//go:build darwin

package productionruntime

import (
	"os"
	"syscall"
)

func releaseIdentityFields(
	info os.FileInfo,
) (releaseFileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return releaseFileIdentity{}, false
	}
	return releaseFileIdentity{
		device: uint64(uint32(stat.Dev)),
		inode:  stat.Ino,
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
	}, true
}

func releaseDeviceNumbers(device uint64) (uint32, uint32, bool) {
	major := uint32(device >> 24)
	minor := uint32(device & 0x00ffffff)
	return major, minor, major != 0
}
