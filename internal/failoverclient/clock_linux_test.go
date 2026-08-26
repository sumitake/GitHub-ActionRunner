//go:build linux

package failoverclient

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestLinuxAuthorityClockAbsoluteWaitAndDomain(t *testing.T) {
	clock, err := NewProductionAuthorityClock()
	if err != nil || !clock.Capable() {
		t.Fatalf("NewProductionAuthorityClock = (%v, %v)", clock, err)
	}
	now, err := clock.Now()
	if err != nil {
		t.Fatalf("Now: %v", err)
	}
	if now.Location() != linuxBoottimeLocation {
		t.Fatalf("Now location = %p, want %p", now.Location(), linuxBoottimeLocation)
	}
	if err := clock.WaitUntil(context.Background(), time.Now().UTC().Add(time.Millisecond)); !errors.Is(err, ErrAuthorityClock) {
		t.Fatalf("wall deadline error = %v", err)
	}

	deadline := now.Add(5 * time.Millisecond)
	if err := clock.WaitUntil(context.Background(), deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("absolute wait error = %v", err)
	}
	after, err := clock.Now()
	if err != nil || after.Before(deadline) {
		t.Fatalf("absolute wait returned early: after=%v deadline=%v err=%v", after, deadline, err)
	}
}

func TestLinuxAuthorityClockCancellationIsBoundedAndLeakFree(t *testing.T) {
	clock, err := NewProductionAuthorityClock()
	if err != nil {
		t.Fatalf("NewProductionAuthorityClock: %v", err)
	}
	before := countOpenFDs(t)
	for range 32 {
		now, nowErr := clock.Now()
		if nowErr != nil {
			t.Fatalf("Now: %v", nowErr)
		}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(time.Millisecond, cancel)
		started := time.Now()
		err := clock.WaitUntil(ctx, now.Add(time.Hour))
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled wait error = %v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("canceled wait took %v", elapsed)
		}
	}
	after := countOpenFDs(t)
	if after > before {
		t.Fatalf("open FDs grew from %d to %d", before, after)
	}
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd): %v", err)
	}
	return len(entries)
}
