//go:build linux

package unixsocketguard

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type linuxGuard struct {
	root        string
	directoryFD int
	socketFD    int
}

func observePlatform(root, name string) (Snapshot, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return Snapshot{}, ErrUnavailable
	}
	var directoryStat unix.Stat_t
	if err := unix.Lstat(root, &directoryStat); err != nil {
		return Snapshot{}, ErrUnavailable
	}
	directory, err := linuxDirectoryIdentity(directoryStat)
	if err != nil {
		return Snapshot{}, err
	}
	var socketStat unix.Stat_t
	if err := unix.Lstat(filepath.Join(root, name), &socketStat); err != nil {
		return Snapshot{}, ErrUnavailable
	}
	socket, err := linuxSocketIdentity(name, socketStat, true)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Directory: directory, Socket: socket}, nil
}

func openPlatformGuard(root string, snapshot Snapshot) (platformGuard, error) {
	directoryFD, err := unix.Open(
		root,
		unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	guard := &linuxGuard{
		root:        root,
		directoryFD: directoryFD,
		socketFD:    -1,
	}
	socketFD, err := unix.Openat(
		directoryFD,
		snapshot.Socket.Name,
		unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		_ = guard.close()
		return nil, ErrUnavailable
	}
	guard.socketFD = socketFD
	if err := guard.verify(snapshot); err != nil {
		_ = guard.close()
		return nil, err
	}
	return guard, nil
}

func (guard *linuxGuard) verify(snapshot Snapshot) error {
	if guard == nil || guard.directoryFD < 0 || guard.socketFD < 0 {
		return ErrUnavailable
	}
	current, err := observePlatform(guard.root, snapshot.Socket.Name)
	if err != nil || current != snapshot {
		return ErrUnavailable
	}
	var directoryStat unix.Stat_t
	if err := unix.Fstat(guard.directoryFD, &directoryStat); err != nil {
		return ErrUnavailable
	}
	directory, err := linuxDirectoryIdentity(directoryStat)
	if err != nil || directory != snapshot.Directory {
		return ErrUnavailable
	}
	var pinnedSocketStat unix.Stat_t
	if err := unix.Fstat(guard.socketFD, &pinnedSocketStat); err != nil {
		return ErrUnavailable
	}
	pinnedSocket, err := linuxSocketIdentity(
		snapshot.Socket.Name,
		pinnedSocketStat,
		true,
	)
	if err != nil || pinnedSocket != snapshot.Socket {
		return ErrUnavailable
	}
	var entryStat unix.Stat_t
	if err := unix.Fstatat(
		guard.directoryFD,
		snapshot.Socket.Name,
		&entryStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return ErrUnavailable
	}
	entry, err := linuxSocketIdentity(snapshot.Socket.Name, entryStat, true)
	if err != nil || entry != snapshot.Socket {
		return ErrUnavailable
	}
	return nil
}

func (guard *linuxGuard) unlink(name string) error {
	if guard == nil || guard.directoryFD < 0 {
		return ErrUnavailable
	}
	if err := unix.Unlinkat(guard.directoryFD, name, 0); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (guard *linuxGuard) verifyRemoved(snapshot Snapshot) error {
	if guard == nil || guard.directoryFD < 0 || guard.socketFD < 0 {
		return ErrUnavailable
	}
	var entryStat unix.Stat_t
	err := unix.Fstatat(
		guard.directoryFD,
		snapshot.Socket.Name,
		&entryStat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if !errors.Is(err, unix.ENOENT) {
		return ErrUnavailable
	}
	var pinnedSocketStat unix.Stat_t
	if err := unix.Fstat(guard.socketFD, &pinnedSocketStat); err != nil {
		return ErrUnavailable
	}
	pinnedSocket, err := linuxSocketIdentity(
		snapshot.Socket.Name,
		pinnedSocketStat,
		false,
	)
	if err != nil || pinnedSocket != snapshot.Socket ||
		pinnedSocketStat.Nlink != 0 {
		return ErrUnavailable
	}
	return nil
}

func (guard *linuxGuard) close() error {
	if guard == nil {
		return nil
	}
	var result error
	if guard.socketFD >= 0 {
		if err := unix.Close(guard.socketFD); err != nil {
			result = errors.Join(result, ErrUnavailable)
		}
		guard.socketFD = -1
	}
	if guard.directoryFD >= 0 {
		if err := unix.Close(guard.directoryFD); err != nil {
			result = errors.Join(result, ErrUnavailable)
		}
		guard.directoryFD = -1
	}
	return result
}

func linuxDirectoryIdentity(stat unix.Stat_t) (DirectoryIdentity, error) {
	if uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(stat.Mode)&0o777 != 0o700 ||
		stat.Dev == 0 ||
		stat.Ino == 0 {
		return DirectoryIdentity{}, ErrUnavailable
	}
	return DirectoryIdentity{
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		UID:    stat.Uid,
		GID:    stat.Gid,
		Mode:   uint32(stat.Mode) & 0o777,
	}, nil
}

func linuxSocketIdentity(
	name string,
	stat unix.Stat_t,
	requireLinked bool,
) (SocketIdentity, error) {
	if uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(stat.Mode)&0o777 != 0o600 ||
		stat.Dev == 0 ||
		stat.Ino == 0 ||
		(requireLinked && stat.Nlink != 1) {
		return SocketIdentity{}, ErrUnavailable
	}
	return SocketIdentity{
		Name:   name,
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		UID:    stat.Uid,
		GID:    stat.Gid,
		Mode:   uint32(stat.Mode) & 0o777,
	}, nil
}
