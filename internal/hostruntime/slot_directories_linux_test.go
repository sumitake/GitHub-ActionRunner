//go:build linux

package hostruntime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

var testSlotIdentity = "pghar-slot-" + strings.Repeat("0a", 16)

// slotTestUser chowns to an unprivileged user when the test runs as root,
// and to the current user otherwise, so the test runs in both settings.
func slotTestUser() (uint32, uint32) {
	if os.Geteuid() == 0 {
		return 1000, 1000
	}
	return uint32(os.Getuid()), uint32(os.Getgid())
}

func newSlotBrokerRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "broker")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	return root
}

func requireSlotDirectory(t *testing.T, path string, uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("%s: dir=%v mode=%v owner=%d:%d, want 0700 %d:%d",
			path, info.IsDir(), info.Mode().Perm(), stat.Uid, stat.Gid, uid, gid)
	}
}

func TestCreateSlotDirectoriesCreatesEmptyBrokerOwnedDirectories(t *testing.T) {
	uid, gid := slotTestUser()
	root := newSlotBrokerRoot(t)
	slot := testSlotIdentity
	if err := CreateSlotDirectories(root, slot, uid, gid); err != nil {
		t.Fatalf("CreateSlotDirectories: %v", err)
	}
	requireSlotDirectory(t, filepath.Join(root, slot), uint32(os.Geteuid()), uint32(os.Getegid()))
	for _, name := range []string{"relay", "authority"} {
		requireSlotDirectory(t, filepath.Join(root, slot, name), uid, gid)
	}

	// A leftover from an unfinished cleanup is never reused.
	if err := CreateSlotDirectories(root, slot, uid, gid); err == nil {
		t.Fatal("second CreateSlotDirectories succeeded over existing directories")
	}

	// Cleanup removes relay and authority but keeps the slot directory.
	for _, name := range []string{"relay", "authority"} {
		if err := os.Remove(filepath.Join(root, slot, name)); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	}
	if err := CreateSlotDirectories(root, slot, uid, gid); err != nil {
		t.Fatalf("CreateSlotDirectories after cleanup: %v", err)
	}
}

func TestCreateSlotDirectoriesRemovesWhatItCreatedOnFailure(t *testing.T) {
	uid, gid := slotTestUser()
	root := newSlotBrokerRoot(t)
	slot := testSlotIdentity
	if err := os.MkdirAll(filepath.Join(root, slot, "authority"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, slot), 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := CreateSlotDirectories(root, slot, uid, gid); err == nil {
		t.Fatal("CreateSlotDirectories succeeded with a leftover authority directory")
	}
	if _, err := os.Lstat(filepath.Join(root, slot, "relay")); !os.IsNotExist(err) {
		t.Fatalf("relay left behind after failure: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, slot, "authority")); err != nil {
		t.Fatalf("pre-existing authority directory was removed: %v", err)
	}
}

func TestCreateSlotDirectoriesFailsClosed(t *testing.T) {
	uid, gid := slotTestUser()
	slot := testSlotIdentity
	tests := map[string]func(t *testing.T) (string, string, uint32){
		"root broker user": func(t *testing.T) (string, string, uint32) {
			return newSlotBrokerRoot(t), slot, 0
		},
		"path in slot name": func(t *testing.T) (string, string, uint32) {
			return newSlotBrokerRoot(t), "../escape", uid
		},
		"broker root too open": func(t *testing.T) (string, string, uint32) {
			root := newSlotBrokerRoot(t)
			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			return root, slot, uid
		},
		"broker root is a symlink": func(t *testing.T) (string, string, uint32) {
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(newSlotBrokerRoot(t), link); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			return link, slot, uid
		},
		"slot is a symlink": func(t *testing.T) (string, string, uint32) {
			root := newSlotBrokerRoot(t)
			if err := os.Symlink(t.TempDir(), filepath.Join(root, slot)); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			return root, slot, uid
		},
		"slot too open": func(t *testing.T) (string, string, uint32) {
			root := newSlotBrokerRoot(t)
			if err := os.Mkdir(filepath.Join(root, slot), 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			if err := os.Chmod(filepath.Join(root, slot), 0o755); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			return root, slot, uid
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			root, slotName, brokerUID := setup(t)
			if err := CreateSlotDirectories(root, slotName, brokerUID, gid); err == nil {
				t.Fatal("CreateSlotDirectories succeeded")
			}
		})
	}
}
