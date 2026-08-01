//go:build !linux

package main

import "errors"

func currentNetworkNamespace() ([]byte, error) {
	return nil, errors.New("runner-gate: network namespace unsupported")
}
