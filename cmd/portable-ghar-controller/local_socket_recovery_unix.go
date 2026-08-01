//go:build linux || darwin

package main

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func recoverOwnedLocalSockets(paths []string, expectedUID uint32) error {
	if len(paths) != 2 ||
		!canonicalAbsolutePath(paths[0]) ||
		!canonicalAbsolutePath(paths[1]) ||
		paths[0] == paths[1] {
		return errLocalProtocol
	}
	parent := filepath.Dir(paths[0])
	if filepath.Dir(paths[1]) != parent {
		return errLocalProtocol
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errLocalProtocol
	}
	directoryFD, err := unix.Open(
		parent,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return errLocalProtocol
	}
	defer unix.Close(directoryFD)
	var directoryStat unix.Stat_t
	if unix.Fstat(directoryFD, &directoryStat) != nil ||
		uint32(directoryStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(directoryStat.Mode)&0o777 != 0o700 ||
		directoryStat.Uid != expectedUID {
		return errLocalProtocol
	}

	names := []string{filepath.Base(paths[0]), filepath.Base(paths[1])}
	present := make([]bool, len(names))
	for index, name := range names {
		if name == "." || name == ".." || filepath.Base(name) != name {
			return errLocalProtocol
		}
		var socketStat unix.Stat_t
		err := unix.Fstatat(
			directoryFD,
			name,
			&socketStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil ||
			uint32(socketStat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
			uint32(socketStat.Mode)&0o777 != 0o600 ||
			socketStat.Uid != expectedUID ||
			socketStat.Gid != directoryStat.Gid ||
			socketStat.Nlink != 1 {
			return errLocalProtocol
		}
		present[index] = true
	}

	mutated := false
	for index, name := range names {
		if !present[index] {
			continue
		}
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
			return errLocalProtocol
		}
		mutated = true
	}
	if mutated && unix.Fsync(directoryFD) != nil {
		return errLocalProtocol
	}
	for _, name := range names {
		var stat unix.Stat_t
		err := unix.Fstatat(
			directoryFD,
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if !errors.Is(err, unix.ENOENT) {
			return errLocalProtocol
		}
	}
	return nil
}
