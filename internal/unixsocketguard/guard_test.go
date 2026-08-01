//go:build linux || darwin

package unixsocketguard

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOwnedGuardPinsOriginalAndRejectsReplacement(t *testing.T) {
	root, path, listener, snapshot := newGuardFixture(t)
	guard, err := OpenOwned(root, snapshot)
	if err != nil {
		t.Fatalf("OpenOwned() error = %v", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove original socket = %v", err)
	}
	replacement, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("listen replacement = %v", err)
	}
	defer replacement.Close()
	replacement.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod replacement = %v", err)
	}

	if err := guard.Verify(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Verify(replacement) error = %v", err)
	}
	if err := guard.Remove(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Remove(replacement) error = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("replacement removed = %v", err)
	}
	if err := guard.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Close(quarantined) error = %v", err)
	}
}

func TestOwnedGuardRemoveIsOneShotAfterNameReappears(t *testing.T) {
	root, path, listener, snapshot := newGuardFixture(t)
	guard, err := OpenOwned(root, snapshot)
	if err != nil {
		t.Fatalf("OpenOwned() error = %v", err)
	}
	defer listener.Close()

	hookCalls := 0
	var replacement *net.UnixListener
	guard.afterUnlinkForTest = func() {
		hookCalls++
		var listenErr error
		replacement, listenErr = net.ListenUnix(
			"unix",
			&net.UnixAddr{Name: path, Net: "unix"},
		)
		if listenErr != nil {
			t.Fatalf("listen post-unlink replacement = %v", listenErr)
		}
		replacement.SetUnlinkOnClose(false)
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			t.Fatalf("chmod post-unlink replacement = %v", chmodErr)
		}
	}
	defer func() {
		if replacement != nil {
			_ = replacement.Close()
		}
		_ = os.Remove(path)
	}()

	if err := guard.Remove(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Remove(post-unlink replacement) error = %v", err)
	}
	if err := guard.Remove(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second Remove(post-unlink replacement) error = %v", err)
	}
	if hookCalls != 1 {
		t.Fatalf("unlink hook calls = %d, want 1", hookCalls)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("post-unlink replacement removed = %v", err)
	}
}

func TestOwnedGuardRemoveSuccessProvesAbsence(t *testing.T) {
	root, path, listener, snapshot := newGuardFixture(t)
	guard, err := OpenOwned(root, snapshot)
	if err != nil {
		t.Fatalf("OpenOwned() error = %v", err)
	}
	defer listener.Close()

	if err := guard.Remove(); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed path error = %v, want not-exist", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestReadOnlyGuardHasNoRemovalAuthority(t *testing.T) {
	root, path, listener, snapshot := newGuardFixture(t)
	guard, err := OpenReadOnly(root, snapshot)
	if err != nil {
		t.Fatalf("OpenReadOnly() error = %v", err)
	}
	defer listener.Close()
	if err := guard.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("read-only guard removed socket = %v", err)
	}
}

func TestGuardCloseFailureRemainsTerminal(t *testing.T) {
	pin := &failingCloseGuard{}
	guard := &Guard{
		snapshot: Snapshot{
			Directory: DirectoryIdentity{
				Device: 1,
				Inode:  2,
				Mode:   0o700,
			},
			Socket: SocketIdentity{
				Name:   "endpoint.sock",
				Device: 1,
				Inode:  3,
				Mode:   0o600,
			},
		},
		pin: pin,
	}
	if err := guard.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Close(first) error = %v", err)
	}
	if err := guard.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Close(second) error = %v", err)
	}
	if pin.closeCalls != 1 {
		t.Fatalf("platform close calls = %d, want 1", pin.closeCalls)
	}
}

func TestObserveRejectsTraversalName(t *testing.T) {
	root, _, listener, _ := newGuardFixture(t)
	defer listener.Close()
	if _, err := Observe(root, "../escape.sock"); !errors.Is(
		err,
		ErrUnavailable,
	) {
		t.Fatalf("Observe(traversal) error = %v", err)
	}
}

func newGuardFixture(
	t *testing.T,
) (string, string, *net.UnixListener, Snapshot) {
	t.Helper()
	tempRoot := "/tmp"
	if runtime.GOOS == "darwin" {
		tempRoot = "/private/tmp"
	}
	root, err := os.MkdirTemp(tempRoot, "pgh-socket-guard-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod root = %v", err)
	}
	path := filepath.Join(root, "endpoint.sock")
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatalf("ListenUnix() error = %v", err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		t.Fatalf("chmod socket = %v", err)
	}
	snapshot, err := Observe(root, "endpoint.sock")
	if err != nil {
		_ = listener.Close()
		t.Fatalf("Observe() error = %v", err)
	}
	return root, path, listener, snapshot
}

type failingCloseGuard struct {
	closeCalls int
}

func (*failingCloseGuard) verify(Snapshot) error {
	return nil
}

func (*failingCloseGuard) unlink(string) error {
	return nil
}

func (*failingCloseGuard) verifyRemoved(Snapshot) error {
	return nil
}

func (guard *failingCloseGuard) close() error {
	guard.closeCalls++
	return errors.New("fixture close failure")
}
