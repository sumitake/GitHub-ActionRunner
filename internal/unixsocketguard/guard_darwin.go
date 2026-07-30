//go:build darwin

package unixsocketguard

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type darwinSocketFingerprint struct {
	socket    SocketIdentity
	changeSec int64
	changeNS  int64
	birthSec  int64
	birthNS   int64
}

type darwinGuard struct {
	root        string
	directoryFD int
	fingerprint darwinSocketFingerprint
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
	directory, err := darwinDirectoryIdentity(directoryStat)
	if err != nil {
		return Snapshot{}, err
	}
	var socketStat unix.Stat_t
	if err := unix.Lstat(filepath.Join(root, name), &socketStat); err != nil {
		return Snapshot{}, ErrUnavailable
	}
	fingerprint, err := darwinSocketFingerprintFromStat(name, socketStat)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Directory: directory,
		Socket:    fingerprint.socket,
	}, nil
}

func openPlatformGuard(root string, snapshot Snapshot) (platformGuard, error) {
	directoryFD, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	fingerprint, err := darwinSocketAtFingerprint(
		directoryFD,
		snapshot.Socket.Name,
	)
	if err != nil || fingerprint.socket != snapshot.Socket {
		_ = unix.Close(directoryFD)
		return nil, ErrUnavailable
	}
	guard := &darwinGuard{
		root:        root,
		directoryFD: directoryFD,
		fingerprint: fingerprint,
	}
	if err := guard.verify(snapshot); err != nil {
		_ = guard.close()
		return nil, err
	}
	return guard, nil
}

func (guard *darwinGuard) verify(snapshot Snapshot) error {
	if guard == nil || guard.directoryFD < 0 {
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
	directory, err := darwinDirectoryIdentity(directoryStat)
	if err != nil || directory != snapshot.Directory {
		return ErrUnavailable
	}
	fingerprint, err := darwinSocketAtFingerprint(
		guard.directoryFD,
		snapshot.Socket.Name,
	)
	if err != nil || fingerprint != guard.fingerprint {
		return ErrUnavailable
	}
	return nil
}

func (guard *darwinGuard) unlink(name string) error {
	if guard == nil || guard.directoryFD < 0 {
		return ErrUnavailable
	}
	if err := unix.Unlinkat(guard.directoryFD, name, 0); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (guard *darwinGuard) verifyRemoved(snapshot Snapshot) error {
	if guard == nil || guard.directoryFD < 0 {
		return ErrUnavailable
	}
	var stat unix.Stat_t
	err := unix.Fstatat(
		guard.directoryFD,
		snapshot.Socket.Name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if !errors.Is(err, unix.ENOENT) {
		return ErrUnavailable
	}
	return nil
}

func (guard *darwinGuard) close() error {
	if guard == nil || guard.directoryFD < 0 {
		return nil
	}
	err := unix.Close(guard.directoryFD)
	guard.directoryFD = -1
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func darwinDirectoryIdentity(stat unix.Stat_t) (DirectoryIdentity, error) {
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

func darwinSocketAtFingerprint(
	directoryFD int,
	name string,
) (darwinSocketFingerprint, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		directoryFD,
		name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return darwinSocketFingerprint{}, ErrUnavailable
	}
	return darwinSocketFingerprintFromStat(name, stat)
}

func darwinSocketFingerprintFromStat(
	name string,
	stat unix.Stat_t,
) (darwinSocketFingerprint, error) {
	if uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(stat.Mode)&0o777 != 0o600 ||
		stat.Dev == 0 ||
		stat.Ino == 0 ||
		stat.Nlink != 1 {
		return darwinSocketFingerprint{}, ErrUnavailable
	}
	return darwinSocketFingerprint{
		socket: SocketIdentity{
			Name:   name,
			Device: uint64(stat.Dev),
			Inode:  stat.Ino,
			UID:    stat.Uid,
			GID:    stat.Gid,
			Mode:   uint32(stat.Mode) & 0o777,
		},
		changeSec: stat.Ctim.Sec,
		changeNS:  stat.Ctim.Nsec,
		birthSec:  stat.Btim.Sec,
		birthNS:   stat.Btim.Nsec,
	}, nil
}
