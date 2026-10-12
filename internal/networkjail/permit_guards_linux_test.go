//go:build linux

package networkjail

import (
	"context"
	"os"
	"testing"
)

// The validator compares /proc against the start time read at accept, so
// both readers must agree on the same live process.
func TestObservePermitPeerProcessMatchesAcceptTimeIdentity(t *testing.T) {
	pid := os.Getpid()
	accepted, err := linuxProcessStartTime(pid)
	if err != nil {
		t.Fatalf("linuxProcessStartTime: %v", err)
	}
	observed, err := ObservePermitPeerProcess(context.Background(), pid)
	if err != nil {
		t.Fatalf("ObservePermitPeerProcess: %v", err)
	}
	if observed.StartTime != accepted || observed.UID != uint32(os.Getuid()) {
		t.Fatalf("observed %+v, want start time %d and uid %d", observed, accepted, os.Getuid())
	}
}
