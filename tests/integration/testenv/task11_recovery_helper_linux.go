//go:build integration && linux

package testenv

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

const (
	task11RecoveryHelperEnv        = "PGHAR_TASK11_RECOVERY_HELPER"
	task11RecoveryHelperController = "controller"
	task11RecoveryHelperObserver   = "observer"
	task11RecoveryHelperPoll       = "noncancellable-poll"
	task11RecoveryReadyFD          = uintptr(3)
)

func init() {
	role := os.Getenv(task11RecoveryHelperEnv)
	if role == "" {
		return
	}
	switch role {
	case task11RecoveryHelperController,
		task11RecoveryHelperObserver:
	case task11RecoveryHelperPoll:
		signal.Ignore(unix.SIGTERM)
	default:
		os.Exit(97)
	}
	ready := os.NewFile(task11RecoveryReadyFD, "task11-recovery-ready")
	if ready == nil {
		os.Exit(98)
	}
	if _, err := ready.Write([]byte{1}); err != nil {
		_ = ready.Close()
		os.Exit(99)
	}
	if err := ready.Close(); err != nil {
		os.Exit(100)
	}
	for {
		_ = unix.Pause()
	}
}
