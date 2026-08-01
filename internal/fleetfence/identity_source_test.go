package fleetfence

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSystemIdentitySourceBindsCurrentProcessStably(t *testing.T) {
	t.Parallel()

	source := NewSystemIdentitySource()
	if source == nil {
		t.Fatal("NewSystemIdentitySource returned nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, err := source.Current(ctx, os.Getpid())
	if err != nil {
		t.Skipf("live process identity unavailable in current sandbox: %v", err)
	}
	second, err := source.Current(ctx, os.Getpid())
	if err != nil {
		t.Fatalf("Current second: %v", err)
	}
	if first.BootID == "" || first.ProcessStartID == "" || first != second ||
		!validScalar(first.BootID) || !validScalar(first.ProcessStartID) {
		t.Fatalf("unstable or invalid identity: first=%+v second=%+v", first, second)
	}
}

func TestSystemIdentitySourceRejectsInvalidOrCancelledLookup(t *testing.T) {
	t.Parallel()

	source := NewSystemIdentitySource()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Current(ctx, os.Getpid()); err == nil {
		t.Fatal("cancelled lookup succeeded")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := source.Current(ctx, 0); err == nil {
		t.Fatal("zero PID lookup succeeded")
	}
}
