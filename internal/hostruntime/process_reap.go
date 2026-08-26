package hostruntime

import (
	"errors"
	"syscall"
	"time"
)

const defaultOwnedProcessReapTimeout = 2 * time.Second

var killOwnedProcessGroup = func(pid int) error {
	if pid <= 0 {
		return errors.New("hostruntime: invalid process group")
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}

// SignalOwnedProcessGroup sends SIGKILL to the owned process group.
func SignalOwnedProcessGroup(pid int) error {
	return killOwnedProcessGroup(pid)
}

// ReplaceOwnedProcessGroupKiller installs a test seam for process-group
// termination. Production callers must not use it.
func ReplaceOwnedProcessGroupKiller(next func(int) error) func(int) error {
	previous := killOwnedProcessGroup
	if next != nil {
		killOwnedProcessGroup = next
	}
	return previous
}

func ownedProcessReapTimeout(override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	if defaultOwnedProcessReapTimeout > 0 {
		return defaultOwnedProcessReapTimeout
	}
	return 2 * time.Second
}

// FinishOwnedProcess signals the owned process group and waits for Wait to
// return until bound. reaped is false when the wait bound expires; callers
// must treat that as terminal cleanup failure, never success.
func FinishOwnedProcess(
	pid int,
	waited <-chan error,
	bound time.Duration,
) (waitErr error, reaped bool) {
	_ = SignalOwnedProcessGroup(pid)
	timer := time.NewTimer(ownedProcessReapTimeout(bound))
	defer timer.Stop()
	select {
	case err := <-waited:
		return err, true
	case <-timer.C:
		return errors.New("hostruntime: command cleanup failed"), false
	}
}
