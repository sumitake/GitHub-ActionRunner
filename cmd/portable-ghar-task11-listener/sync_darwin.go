//go:build darwin

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

func syncDirectoryFD(fd int) error {
	err := unix.Fsync(fd)
	if errors.Is(err, unix.EINVAL) {
		return nil
	}
	return err
}
