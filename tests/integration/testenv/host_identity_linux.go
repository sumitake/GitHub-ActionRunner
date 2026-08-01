//go:build integration && linux

package testenv

import "golang.org/x/sys/unix"

type unixExecutionHostStatSource struct{}

func (unixExecutionHostStatSource) Lstat(
	path string,
) (executionHostFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return executionHostFileIdentity{}, ErrExecutionHostIdentity
	}
	return executionHostFileIdentity{
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
		Mode:   uint32(stat.Mode),
		NLink:  uint64(stat.Nlink),
	}, nil
}
