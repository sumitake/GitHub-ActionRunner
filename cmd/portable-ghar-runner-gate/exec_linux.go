//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func execListenerProcess(file *os.File, path string, argv, env []string) error {
	if err := validateListenerExecBoundary(file, path, argv, env); err != nil {
		return err
	}
	fd := uint(file.Fd())
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, 0); err != nil {
		return errors.New("runner-gate: listener descriptor flags invalid")
	}
	if fd > 3 {
		if err := unix.CloseRange(3, fd-1, 0); err != nil {
			return errors.New("runner-gate: inherited descriptor close failed")
		}
	}
	if fd < ^uint(0) {
		if err := unix.CloseRange(fd+1, ^uint(0), 0); err != nil {
			return errors.New("runner-gate: inherited descriptor close failed")
		}
	}
	if err := unix.Exec(path, argv, env); err != nil {
		_, _, _ = unix.RawSyscall(unix.SYS_EXIT_GROUP, 127, 0, 0)
		for {
		}
	}
	return nil
}
