//go:build !linux

package main

import (
	"errors"
	"net"

	"github.com/sumitake/portable-ghar/internal/relaycontract"
)

func verifyUnixPeer(*net.UnixConn, relaycontract.Binding) error {
	return errors.New("network-adapter: peer instance proof unavailable")
}

func verifyControlPeer(*net.UnixConn) error {
	return errors.New("network-adapter: control peer proof unavailable")
}
