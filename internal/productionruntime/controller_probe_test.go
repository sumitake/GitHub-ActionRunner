package productionruntime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestSystemDisabledControllerProbeCancellationDoesNotBlockWhenChildIgnoresKill(
	t *testing.T,
) {
	previousKill := hostruntime.ReplaceOwnedProcessGroupKiller(
		func(int) error { return nil },
	)
	t.Cleanup(func() {
		hostruntime.ReplaceOwnedProcessGroupKiller(previousKill)
	})

	root := t.TempDir()
	helper := filepath.Join(root, "probe-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0o500); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	privatePath := filepath.Join(root, "private")
	if err := os.Mkdir(privatePath, 0o700); err != nil {
		t.Fatalf("mkdir private: %v", err)
	}

	probe, err := NewSystemDisabledControllerProbe(helper, privatePath)
	if err != nil {
		t.Fatalf("NewSystemDisabledControllerProbe: %v", err)
	}
	probe.reapTimeout = 40 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, runErr := probe.run(ctx, "probe")
		done <- runErr
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("probe returned success after a hung child")
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("controller probe blocked after kill deadline")
	}
}

func TestSystemDisabledControllerProbeStillOwnsProcessGroupOnCancel(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "probe-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0o500); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	privatePath := filepath.Join(root, "private")
	if err := os.Mkdir(privatePath, 0o700); err != nil {
		t.Fatalf("mkdir private: %v", err)
	}
	probe, err := NewSystemDisabledControllerProbe(helper, privatePath)
	if err != nil {
		t.Fatalf("NewSystemDisabledControllerProbe: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, runErr := probe.run(ctx, "probe")
		done <- runErr
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled probe returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled probe did not return after process-group kill")
	}
}
