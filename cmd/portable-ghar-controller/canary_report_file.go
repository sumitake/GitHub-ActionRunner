package main

import (
	"bytes"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// replaceCanaryReport uses the existing private-directory and pinned-file
// contract, checks the original D2 bytes immediately before replacement, then
// atomically replaces that same report and syncs its parent. The operator runs
// one journaled sealing step; the acquisition loop never writes this file.
func replaceCanaryReport(path string, pending, completed []byte, expectedUID uint32) error {
	if len(completed) == 0 || len(completed) > maxConformanceReportBytes {
		return errCommandUnavailable
	}
	directory := filepath.Dir(path)
	parentFD, err := openProductionPrivateDirectory(directory, expectedUID)
	if err != nil {
		return errCommandUnavailable
	}
	parent := os.NewFile(uintptr(parentFD), "canary-state")
	if parent == nil {
		_ = unix.Close(parentFD)
		return errCommandUnavailable
	}
	defer parent.Close()
	temporary, err := os.CreateTemp(directory, ".conformance-report-*")
	if err != nil {
		return errCommandUnavailable
	}
	temporaryPath := temporary.Name()
	defer func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }()
	if temporary.Chmod(0600) != nil {
		return errCommandUnavailable
	}
	if _, err := temporary.Write(completed); err != nil {
		return errCommandUnavailable
	}
	if temporary.Sync() != nil || temporary.Close() != nil {
		return errCommandUnavailable
	}
	current, err := readPinnedOwnedFile(path, 0600, maxConformanceReportBytes, expectedUID)
	if err != nil || !bytes.Equal(current, pending) {
		return errCommandUnavailable
	}
	if os.Rename(temporaryPath, path) != nil || parent.Sync() != nil {
		return errCommandUnavailable
	}
	return nil
}
