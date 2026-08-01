//go:build !linux

package main

import (
	"errors"
	"os"
)

func execListenerProcess(*os.File, string, []string, []string) error {
	return errors.New("runner-gate: listener execution unsupported")
}
