package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

const (
	brokerAuthorityDirectory = "/run/portable-ghar/authority"
	brokerAuthoritySocket    = "/run/portable-ghar/authority/dial-authority.sock"
)

type authorityFilesystemDocument struct {
	Version   uint8                         `json:"version"`
	Directory hostruntime.DirectoryIdentity `json:"directory"`
	Socket    hostruntime.SocketIdentity    `json:"socket"`
}

func inspectAuthorityFilesystem() ([]byte, error) {
	return inspectAuthorityFilesystemAt(
		brokerAuthorityDirectory,
		brokerAuthoritySocket,
	)
}

func inspectAuthorityFilesystemAt(directory, socket string) ([]byte, error) {
	if !filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory ||
		socket != filepath.Join(directory, "dial-authority.sock") {
		return nil, errors.New("broker-dialer: authority path invalid")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, errors.New("broker-dialer: authority directory indirect")
	}
	var directoryStat unix.Stat_t
	if unix.Lstat(directory, &directoryStat) != nil ||
		uint32(directoryStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(directoryStat.Mode)&0o777 != 0o700 ||
		directoryStat.Uid != uint32(os.Geteuid()) ||
		directoryStat.Gid != uint32(os.Getegid()) ||
		directoryStat.Nlink == 0 {
		return nil, errors.New("broker-dialer: authority directory invalid")
	}
	var socketStat unix.Stat_t
	if unix.Lstat(socket, &socketStat) != nil ||
		uint32(socketStat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(socketStat.Mode)&0o777 != 0o600 ||
		socketStat.Dev != directoryStat.Dev ||
		socketStat.Uid != directoryStat.Uid ||
		socketStat.Gid != directoryStat.Gid ||
		socketStat.Nlink != 1 {
		return nil, errors.New("broker-dialer: authority socket invalid")
	}
	document, err := json.Marshal(authorityFilesystemDocument{
		Version: 1,
		Directory: hostruntime.DirectoryIdentity{
			Device: uint64(directoryStat.Dev),
			Inode:  directoryStat.Ino,
			UID:    directoryStat.Uid,
			GID:    directoryStat.Gid,
			Mode:   uint32(directoryStat.Mode) & 0o777,
		},
		Socket: hostruntime.SocketIdentity{
			Name:   "dial-authority.sock",
			Device: uint64(socketStat.Dev),
			Inode:  socketStat.Ino,
			UID:    socketStat.Uid,
			GID:    socketStat.Gid,
			Mode:   uint32(socketStat.Mode) & 0o777,
		},
	})
	if err != nil || len(document)+1 > maxBrokerCommandResponse {
		zero(document)
		return nil, errors.New("broker-dialer: authority identity unavailable")
	}
	return append(document, '\n'), nil
}
