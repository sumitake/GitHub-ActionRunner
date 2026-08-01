//go:build linux

package networkjail

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadLinuxBootIDIsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(
		path,
		[]byte("00112233-4455-6677-8899-aabbccddeeff\n"),
		0o600,
	); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	boot, err := readLinuxBootID(path)
	if err != nil {
		t.Fatalf("readLinuxBootID: %v", err)
	}
	if got := boot.String(); got != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("boot ID = %q", got)
	}
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatalf("WriteFile malformed: %v", err)
	}
	if _, err := readLinuxBootID(path); err == nil {
		t.Fatal("readLinuxBootID malformed = nil error")
	}
}

func TestSystemMonotonicClockObservationsDoNotRegress(t *testing.T) {
	clock, err := NewSystemMonotonicClock()
	if err != nil {
		t.Fatalf("NewSystemMonotonicClock: %v", err)
	}
	first, err := clock.Observe(context.Background())
	if err != nil {
		t.Fatalf("first Observe: %v", err)
	}
	second, err := clock.Observe(context.Background())
	if err != nil {
		t.Fatalf("second Observe: %v", err)
	}
	if first.BootID != second.BootID ||
		second.MonotonicNanos < first.MonotonicNanos {
		t.Fatalf("observations regressed: first=%#v second=%#v", first, second)
	}
}
