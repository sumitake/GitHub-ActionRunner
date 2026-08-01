//go:build linux || darwin

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverOwnedLocalSocketsRemovesOnlyValidatedFixedSockets(
	t *testing.T,
) {
	root, paths, listeners := staleLocalSocketFixture(t)
	if err := recoverOwnedLocalSockets(
		paths,
		uint32(os.Geteuid()),
	); err != nil {
		t.Fatalf("recoverOwnedLocalSockets() error = %v", err)
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered socket %q error = %v", path, err)
		}
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("recovery removed private parent: %v", err)
	}
}

func TestControllerSocketRecoveryRequiresLiveOwnershipProof(t *testing.T) {
	_, paths, listeners := staleLocalSocketFixture(t)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	ownership := &testOwnershipLease{}
	ownership.SetValidateError(errors.New("fixture ownership lost"))
	process := &disabledControllerProcess{
		ownership:        ownership,
		adminSocketPath:  paths[0],
		healthSocketPath: paths[1],
		expectedUID:      uint32(os.Geteuid()),
	}
	if err := process.recoverServerSockets(); !errors.Is(
		err,
		errLocalProtocol,
	) {
		t.Fatalf("recoverServerSockets(no ownership) error = %v", err)
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unowned recovery mutated %q: %v", path, err)
		}
	}
	ownership.SetValidateError(nil)
	if err := process.recoverServerSockets(); err != nil {
		t.Fatalf("recoverServerSockets(owned) error = %v", err)
	}
}

func TestRecoverOwnedLocalSocketsRejectsWholeSetBeforeMutation(
	t *testing.T,
) {
	_, paths, listeners := staleLocalSocketFixture(t)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	if err := os.Remove(paths[1]); err != nil {
		t.Fatalf("remove second socket = %v", err)
	}
	if err := os.WriteFile(paths[1], []byte("invalid"), 0o600); err != nil {
		t.Fatalf("write invalid second entry = %v", err)
	}

	if err := recoverOwnedLocalSockets(
		paths,
		uint32(os.Geteuid()),
	); !errors.Is(err, errLocalProtocol) {
		t.Fatalf("recoverOwnedLocalSockets(invalid set) error = %v", err)
	}
	first, err := os.Lstat(paths[0])
	if err != nil || first.Mode()&os.ModeSocket == 0 {
		t.Fatalf("first socket mutated before rejection: (%v, %v)", first, err)
	}
	second, err := os.Lstat(paths[1])
	if err != nil || !second.Mode().IsRegular() {
		t.Fatalf("invalid second entry mutated: (%v, %v)", second, err)
	}
}

func staleLocalSocketFixture(
	t *testing.T,
) (string, []string, []*net.UnixListener) {
	t.Helper()
	root, err := os.MkdirTemp(shortTestTempRoot(), "pgh-stale-sockets-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod root = %v", err)
	}
	paths := []string{
		filepath.Join(root, "admin.sock"),
		filepath.Join(root, "health.sock"),
	}
	listeners := make([]*net.UnixListener, 0, len(paths))
	for _, path := range paths {
		listener, err := net.ListenUnix(
			"unix",
			&net.UnixAddr{Name: path, Net: "unix"},
		)
		if err != nil {
			t.Fatalf("ListenUnix(%q) error = %v", path, err)
		}
		listener.SetUnlinkOnClose(false)
		if err := os.Chmod(path, 0o600); err != nil {
			_ = listener.Close()
			t.Fatalf("chmod socket %q = %v", path, err)
		}
		listeners = append(listeners, listener)
	}
	return root, paths, listeners
}
