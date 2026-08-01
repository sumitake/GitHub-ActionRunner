//go:build !linux

package main

import "errors"

func installParserSandbox() (sandboxProof, error) {
	return sandboxProof{}, errors.New("broker-parser: linux seccomp unavailable")
}
