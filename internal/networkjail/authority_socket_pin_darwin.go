//go:build darwin

package networkjail

import (
	"errors"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

const authoritySocketLiteral = "dial-authority.sock"

type authoritySocketFingerprint struct {
	socket    hostruntime.SocketIdentity
	changeSec int64
	changeNS  int64
	birthSec  int64
	birthNS   int64
}

type authoritySocketPin struct {
	directoryPath string
	directoryFD   int
	directory     hostruntime.DirectoryIdentity
	fingerprint   authoritySocketFingerprint
}

func openAuthoritySocketPin(
	directoryPath string,
	directory hostruntime.DirectoryIdentity,
	socket hostruntime.SocketIdentity,
) (*authoritySocketPin, error) {
	directoryFD, err := unix.Open(
		directoryPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrPermitAuthorityUnavailable
	}
	fingerprint, err := darwinAuthoritySocketAtFingerprint(directoryFD)
	if err != nil || fingerprint.socket != socket {
		_ = unix.Close(directoryFD)
		return nil, ErrPermitAuthorityUnavailable
	}
	pin := &authoritySocketPin{
		directoryPath: directoryPath,
		directoryFD:   directoryFD,
		directory:     directory,
		fingerprint:   fingerprint,
	}
	if err := pin.verify(); err != nil {
		_ = pin.close()
		return nil, err
	}
	return pin, nil
}

func (pin *authoritySocketPin) verify() error {
	if pin == nil || pin.directoryFD < 0 {
		return ErrPermitAuthorityUnavailable
	}
	pathDirectory, _, err := readAuthorityPathIdentity(
		pin.directoryPath,
		false,
	)
	if err != nil || pathDirectory != pin.directory {
		return ErrPermitAuthorityUnavailable
	}
	directory, err := darwinAuthorityDirectoryFDIdentity(pin.directoryFD)
	if err != nil || directory != pin.directory {
		return ErrPermitAuthorityUnavailable
	}
	fingerprint, err := darwinAuthoritySocketAtFingerprint(pin.directoryFD)
	if err != nil || fingerprint != pin.fingerprint {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func (pin *authoritySocketPin) remove() error {
	if err := pin.verify(); err != nil {
		return err
	}
	if err := unix.Unlinkat(
		pin.directoryFD,
		authoritySocketLiteral,
		0,
	); err != nil {
		return ErrPermitAuthorityUnavailable
	}
	var stat unix.Stat_t
	err := unix.Fstatat(
		pin.directoryFD,
		authoritySocketLiteral,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if !errors.Is(err, unix.ENOENT) {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func (pin *authoritySocketPin) close() error {
	if pin == nil || pin.directoryFD < 0 {
		return nil
	}
	err := unix.Close(pin.directoryFD)
	pin.directoryFD = -1
	if err != nil {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func darwinAuthorityDirectoryFDIdentity(
	fd int,
) (hostruntime.DirectoryIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(stat.Mode)&0o777 != 0o700 ||
		stat.Dev == 0 ||
		stat.Ino == 0 {
		return hostruntime.DirectoryIdentity{}, ErrPermitAuthorityUnavailable
	}
	return hostruntime.DirectoryIdentity{
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		UID:    stat.Uid,
		GID:    stat.Gid,
		Mode:   uint32(stat.Mode) & 0o777,
	}, nil
}

func darwinAuthoritySocketAtFingerprint(
	directoryFD int,
) (authoritySocketFingerprint, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		directoryFD,
		authoritySocketLiteral,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(stat.Mode)&0o777 != 0o600 ||
		stat.Dev == 0 ||
		stat.Ino == 0 {
		return authoritySocketFingerprint{}, ErrPermitAuthorityUnavailable
	}
	return authoritySocketFingerprint{
		socket: hostruntime.SocketIdentity{
			Name:   authoritySocketLiteral,
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
