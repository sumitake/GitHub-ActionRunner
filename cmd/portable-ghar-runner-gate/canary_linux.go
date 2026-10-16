//go:build linux

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sumitake/portable-ghar/internal/canary"
	"golang.org/x/sys/unix"
)

func defaultCanaryProbe() (canary.Probe, error) {
	return readCanarySocket(defaultGateDirectory, uint32(os.Geteuid()), time.Second)
}

func validCanarySocketStat(stat unix.Stat_t, expectedUID uint32) bool {
	return uint32(stat.Mode)&unix.S_IFMT == unix.S_IFSOCK && uint32(stat.Mode)&0777 == 0600 && stat.Uid == expectedUID && stat.Nlink == 1 && stat.Ino != 0
}

// The final workflow step owns this socket and stays alive until it is read.
// The controller runs this fixed command under the lifecycle's same-key lock,
// persisting its result before a Completed event can reclaim the tmpfs.
func readCanarySocket(directory string, expectedUID uint32, timeout time.Duration) (canary.Probe, error) {
	rootFD, _, err := openRuntimeRunnerRoot(directory)
	if err != nil {
		return canary.Probe{}, canary.ErrEvidence
	}
	defer unix.Close(rootFD)
	var stat unix.Stat_t
	err = unix.Fstatat(rootFD, canaryReportSocketName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return canary.Probe{Version: 1, Pending: true}, nil
	}
	if err != nil || !validCanarySocketStat(stat, expectedUID) || timeout <= 0 {
		return canary.Probe{}, canary.ErrEvidence
	}
	connection, err := net.DialTimeout("unix", filepath.Join(directory, canaryReportSocketName), timeout)
	if err != nil {
		return canary.Probe{}, canary.ErrEvidence
	}
	defer connection.Close()
	if connection.SetDeadline(time.Now().Add(timeout)) != nil {
		return canary.Probe{}, canary.ErrEvidence
	}
	document, err := io.ReadAll(io.LimitReader(connection, canary.MaxWorkflowBytes+1))
	if err != nil {
		return canary.Probe{}, canary.ErrEvidence
	}
	workflow, err := canary.ParseWorkflow(document)
	if err != nil {
		return canary.Probe{}, err
	}
	return canary.Probe{Version: 1, Workflow: &workflow}, nil
}
