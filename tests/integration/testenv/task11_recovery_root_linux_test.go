//go:build integration && linux

package testenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTask11RecoveryRootRemovesOnlyExactKnownState(t *testing.T) {
	t.Parallel()

	root, cycle := newTask11RecoveryRootForTest(
		t,
		strings.Repeat("e", 64),
	)
	databasePath, fencePath, err := root.prepareRecoveryState()
	if err != nil {
		t.Fatalf("prepare recovery state: %v", err)
	}
	for _, path := range []string{
		databasePath,
		databasePath + "-wal",
		databasePath + "-shm",
		filepath.Join(fencePath, "fleet.json"),
		filepath.Join(fencePath, "fleet.lock"),
	} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	if err := os.Mkdir(filepath.Join(fencePath, "holders"), 0o700); err != nil {
		t.Fatalf("mkdir holders: %v", err)
	}

	if err := root.removeRecoveryState(); err != nil {
		t.Fatalf("remove recovery state: %v", err)
	}
	if _, err := os.Lstat(cycle.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery root remains: %v", err)
	}
}

func TestTask11RecoveryRootPreservesUnexpectedContent(t *testing.T) {
	t.Parallel()

	root, cycle := newTask11RecoveryRootForTest(
		t,
		strings.Repeat("f", 64),
	)
	databasePath, _, err := root.prepareRecoveryState()
	if err != nil {
		t.Fatalf("prepare recovery state: %v", err)
	}
	if err := os.WriteFile(databasePath, []byte("known"), 0o600); err != nil {
		t.Fatalf("write known state: %v", err)
	}
	unexpected := filepath.Join(cycle.Root, "operator-owned")
	if err := os.WriteFile(unexpected, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("write unexpected state: %v", err)
	}

	if err := root.removeRecoveryState(); !errors.Is(
		err,
		ErrFixtureUnexpectedObject,
	) {
		t.Fatalf("remove recovery state error = %v", err)
	}
	for _, path := range []string{databasePath, unexpected, cycle.Root} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("preserved path %s: %v", path, err)
		}
	}
}

func newTask11RecoveryRootForTest(
	t *testing.T,
	runDigest string,
) (*linuxTask11SyntheticCycleRoot, task11SyntheticCycleIdentity) {
	t.Helper()

	primaryRoot := t.TempDir()
	if err := os.Chmod(primaryRoot, 0o700); err != nil {
		t.Fatalf("chmod primary root: %v", err)
	}
	primary := FixtureBinding{
		Root:                         primaryRoot,
		ExecutionOwnerUID:            uint32(os.Geteuid()),
		ExecutionOwnerIdentityDigest: strings.Repeat("a", 64),
	}
	cycle, err := deriveTask11RecoveryCycleIdentity(primary, runDigest)
	if err != nil {
		t.Fatalf("derive recovery identity: %v", err)
	}
	root, binding, err := createLinuxTask11SyntheticCycleRoot(primary, cycle)
	if err != nil {
		t.Fatalf("create recovery root: %v", err)
	}
	if binding.Root != cycle.Root {
		t.Fatalf("binding root = %q, want %q", binding.Root, cycle.Root)
	}
	t.Cleanup(func() {
		_ = root.close()
	})
	return root, cycle
}
