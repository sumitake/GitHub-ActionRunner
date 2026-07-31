//go:build darwin || linux

package hostruntime

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func proveBrokerRootEmpty(path string) error {
	fd, identity, err := openLifecycleAbsoluteDirectory(path)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("hostruntime: broker root descriptor unavailable")
	}
	entries, readErr := directory.ReadDir(1)
	closeErr := directory.Close()
	if len(entries) != 0 ||
		(readErr != nil && !errors.Is(readErr, io.EOF)) ||
		closeErr != nil {
		return errors.New("hostruntime: broker root not empty")
	}

	currentFD, current, err := openLifecycleAbsoluteDirectory(path)
	if err == nil {
		err = unix.Close(currentFD)
	}
	if err != nil || !samePinnedDirectoryIdentity(identity, current) {
		return errors.New("hostruntime: broker root identity changed")
	}
	return nil
}
