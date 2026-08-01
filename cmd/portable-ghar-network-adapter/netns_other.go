//go:build !linux

package main

import "errors"

func currentNetworkNamespace() ([]byte, error) {
	return nil, errors.New("network-adapter: namespace proof unavailable")
}
