//go:build integration && linux

package testenv

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestTask11SyntheticCycleRootPreparesAndRemovesExactBrokerDirectories(
	t *testing.T,
) {
	t.Parallel()

	primaryRoot := t.TempDir()
	if err := os.Chmod(primaryRoot, 0o700); err != nil {
		t.Fatalf("chmod primary root: %v", err)
	}
	cycle, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		strings.Repeat("a", 64),
		task11SyntheticCycleRequest{
			Kind: task11CycleCleanupControllerRestart,
		},
	)
	if err != nil {
		t.Fatalf("derive cycle identity: %v", err)
	}
	root, _, err := createLinuxTask11SyntheticCycleRoot(
		FixtureBinding{
			Root:                         primaryRoot,
			ExecutionOwnerUID:            uint32(os.Geteuid()),
			ExecutionOwnerIdentityDigest: strings.Repeat("b", 64),
		},
		cycle,
	)
	if err != nil {
		t.Fatalf("create cycle root: %v", err)
	}
	t.Cleanup(func() {
		_ = root.close()
	})

	if err := root.prepareBrokerDirectories(); err != nil {
		t.Fatalf("prepare broker directories: %v", err)
	}
	names, err := root.snapshotEntries()
	if err != nil {
		t.Fatalf("snapshot entries: %v", err)
	}
	sort.Strings(names)
	if strings.Join(names, "\x00") != "authority\x00relay" {
		t.Fatalf("entries = %q", names)
	}
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(cycle.Root, name))
		if err != nil {
			t.Fatalf("lstat %s: %v", name, err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %v", name, info.Mode())
		}
	}

	if err := root.removeEmpty(); err != nil {
		t.Fatalf("remove empty: %v", err)
	}
	if _, err := os.Lstat(cycle.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cycle root remains: %v", err)
	}
}

func TestTask11SyntheticCycleRootRejectsUnexpectedBrokerDirectoryContent(
	t *testing.T,
) {
	t.Parallel()

	primaryRoot := t.TempDir()
	if err := os.Chmod(primaryRoot, 0o700); err != nil {
		t.Fatalf("chmod primary root: %v", err)
	}
	cycle, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		strings.Repeat("c", 64),
		task11SyntheticCycleRequest{
			Kind: task11CycleCleanupControllerRestart,
		},
	)
	if err != nil {
		t.Fatalf("derive cycle identity: %v", err)
	}
	root, _, err := createLinuxTask11SyntheticCycleRoot(
		FixtureBinding{
			Root:                         primaryRoot,
			ExecutionOwnerUID:            uint32(os.Geteuid()),
			ExecutionOwnerIdentityDigest: strings.Repeat("d", 64),
		},
		cycle,
	)
	if err != nil {
		t.Fatalf("create cycle root: %v", err)
	}
	t.Cleanup(func() {
		_ = root.close()
	})
	if err := root.prepareBrokerDirectories(); err != nil {
		t.Fatalf("prepare broker directories: %v", err)
	}
	unexpected := filepath.Join(cycle.Root, "relay", "unexpected")
	if err := os.WriteFile(unexpected, []byte("tripwire"), 0o600); err != nil {
		t.Fatalf("write unexpected object: %v", err)
	}

	if err := root.removeEmpty(); !errors.Is(
		err,
		ErrFixtureUnexpectedObject,
	) {
		t.Fatalf("remove empty error = %v", err)
	}
	if _, err := os.Lstat(unexpected); err != nil {
		t.Fatalf("unexpected object was removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cycle.Root, "authority")); err != nil {
		t.Fatalf("sibling directory was removed: %v", err)
	}
	if _, err := os.Lstat(cycle.Root); err != nil {
		t.Fatalf("cycle root was removed: %v", err)
	}
}
