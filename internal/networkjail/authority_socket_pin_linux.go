//go:build linux

package networkjail

import (
	"errors"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

const authoritySocketLiteral = "dial-authority.sock"

type authoritySocketPin struct {
	directoryPath string
	directoryFD   int
	socketFD      int
	directory     hostruntime.DirectoryIdentity
	socket        hostruntime.SocketIdentity
}

func openAuthoritySocketPin(
	directoryPath string,
	directory hostruntime.DirectoryIdentity,
	socket hostruntime.SocketIdentity,
) (*authoritySocketPin, error) {
	directoryFD, err := unix.Open(
		directoryPath,
		unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrPermitAuthorityUnavailable
	}
	pin := &authoritySocketPin{
		directoryPath: directoryPath,
		directoryFD:   directoryFD,
		socketFD:      -1,
		directory:     directory,
		socket:        socket,
	}
	socketFD, err := unix.Openat(
		directoryFD,
		authoritySocketLiteral,
		unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		_ = pin.close()
		return nil, ErrPermitAuthorityUnavailable
	}
	pin.socketFD = socketFD
	if err := pin.verify(); err != nil {
		_ = pin.close()
		return nil, err
	}
	return pin, nil
}

func (pin *authoritySocketPin) verify() error {
	if pin == nil || pin.directoryFD < 0 || pin.socketFD < 0 {
		return ErrPermitAuthorityUnavailable
	}
	pathDirectory, _, err := readAuthorityPathIdentity(
		pin.directoryPath,
		false,
	)
	if err != nil || pathDirectory != pin.directory {
		return ErrPermitAuthorityUnavailable
	}
	directory, err := linuxAuthorityDirectoryFDIdentity(pin.directoryFD)
	if err != nil || directory != pin.directory {
		return ErrPermitAuthorityUnavailable
	}
	socket, err := linuxAuthoritySocketFDIdentity(pin.socketFD)
	if err != nil || socket != pin.socket {
		return ErrPermitAuthorityUnavailable
	}
	entry, err := linuxAuthoritySocketAtIdentity(pin.directoryFD)
	if err != nil || entry != pin.socket {
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
	if pin == nil {
		return nil
	}
	var result error
	if pin.socketFD >= 0 {
		if err := unix.Close(pin.socketFD); err != nil {
			result = errors.Join(result, ErrPermitAuthorityUnavailable)
		}
		pin.socketFD = -1
	}
	if pin.directoryFD >= 0 {
		if err := unix.Close(pin.directoryFD); err != nil {
			result = errors.Join(result, ErrPermitAuthorityUnavailable)
		}
		pin.directoryFD = -1
	}
	return result
}

func linuxAuthorityDirectoryFDIdentity(
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

func linuxAuthoritySocketFDIdentity(
	fd int,
) (hostruntime.SocketIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return hostruntime.SocketIdentity{}, ErrPermitAuthorityUnavailable
	}
	return linuxAuthoritySocketStatIdentity(stat)
}

func linuxAuthoritySocketAtIdentity(
	directoryFD int,
) (hostruntime.SocketIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		directoryFD,
		authoritySocketLiteral,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return hostruntime.SocketIdentity{}, ErrPermitAuthorityUnavailable
	}
	return linuxAuthoritySocketStatIdentity(stat)
}

func linuxAuthoritySocketStatIdentity(
	stat unix.Stat_t,
) (hostruntime.SocketIdentity, error) {
	if uint32(stat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(stat.Mode)&0o777 != 0o600 ||
		stat.Dev == 0 ||
		stat.Ino == 0 {
		return hostruntime.SocketIdentity{}, ErrPermitAuthorityUnavailable
	}
	return hostruntime.SocketIdentity{
		Name:   authoritySocketLiteral,
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		UID:    stat.Uid,
		GID:    stat.Gid,
		Mode:   uint32(stat.Mode) & 0o777,
	}, nil
}
