//go:build linux

package main

import "golang.org/x/sys/unix"

func syncDirectoryFD(fd int) error {
	return unix.Fsync(fd)
}
