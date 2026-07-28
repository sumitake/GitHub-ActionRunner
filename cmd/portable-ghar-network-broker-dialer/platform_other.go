//go:build !linux

package main

import (
	"errors"
	"os"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func brokerPlatformSupported() bool { return false }

func observeProcessIdentity(
	int,
) (hostruntime.ProcessIdentity, uint32, error) {
	return hostruntime.ProcessIdentity{}, 0,
		errors.New("broker-dialer: process identity unavailable")
}

func observeAuthorityPeer(
	string,
	hostruntime.AuthorityBinding,
) error {
	return errors.New("broker-dialer: authority peer unavailable")
}

func observeAuthorityObjects(
	string,
) (
	hostruntime.DirectoryIdentity,
	hostruntime.SocketIdentity,
	error,
) {
	return hostruntime.DirectoryIdentity{},
		hostruntime.SocketIdentity{},
		errors.New("broker-dialer: authority identity unavailable")
}

func observeFDIdentity(*os.File) (uint64, uint64, error) {
	return 0, 0, errors.New("broker-dialer: descriptor identity unavailable")
}

func observeProcessFDIdentity(int, int) (uint64, uint64, error) {
	return 0, 0, errors.New("broker-dialer: process descriptor unavailable")
}
