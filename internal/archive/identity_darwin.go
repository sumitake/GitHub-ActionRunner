//go:build darwin

package archive

import "golang.org/x/sys/unix"

func identityFromStat(stat *unix.Stat_t) fileIdentity {
	return fileIdentity{
		device:    uint64(stat.Dev),
		inode:     stat.Ino,
		nlink:     uint64(stat.Nlink),
		uid:       stat.Uid,
		gid:       stat.Gid,
		size:      stat.Size,
		mode:      uint32(stat.Mode),
		mtimeSec:  stat.Mtim.Sec,
		mtimeNsec: stat.Mtim.Nsec,
		ctimeSec:  stat.Ctim.Sec,
		ctimeNsec: stat.Ctim.Nsec,
		blocks:    stat.Blocks,
	}
}
