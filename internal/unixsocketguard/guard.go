//go:build linux || darwin

// Package unixsocketguard pins a private Unix-socket pathname for the
// lifetime of an endpoint. It deliberately separates read-only verification
// from one-shot owned removal.
package unixsocketguard

import (
	"errors"
	"path/filepath"
	"sync"
)

var ErrUnavailable = errors.New("unixsocketguard: unavailable")

type DirectoryIdentity struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   uint32
}

type SocketIdentity struct {
	Name   string
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   uint32
}

type Snapshot struct {
	Directory DirectoryIdentity
	Socket    SocketIdentity
}

type platformGuard interface {
	verify(Snapshot) error
	unlink(string) error
	verifyRemoved(Snapshot) error
	close() error
}

type Guard struct {
	mu          sync.Mutex
	snapshot    Snapshot
	pin         platformGuard
	closed      bool
	quarantined bool
}

type OwnedGuard struct {
	*Guard
	removeAttempted    bool
	removed            bool
	afterUnlinkForTest func()
}

func Observe(root, name string) (Snapshot, error) {
	if !validRootAndName(root, name) {
		return Snapshot{}, ErrUnavailable
	}
	snapshot, err := observePlatform(root, name)
	if err != nil || !validSnapshot(snapshot) {
		return Snapshot{}, ErrUnavailable
	}
	return snapshot, nil
}

func OpenReadOnly(root string, snapshot Snapshot) (*Guard, error) {
	if !validRootAndName(root, snapshot.Socket.Name) ||
		!validSnapshot(snapshot) {
		return nil, ErrUnavailable
	}
	pin, err := openPlatformGuard(root, snapshot)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Guard{snapshot: snapshot, pin: pin}, nil
}

func OpenOwned(root string, snapshot Snapshot) (*OwnedGuard, error) {
	guard, err := OpenReadOnly(root, snapshot)
	if err != nil {
		return nil, err
	}
	return &OwnedGuard{Guard: guard}, nil
}

func (guard *Guard) Verify() error {
	if guard == nil {
		return ErrUnavailable
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.verifyLocked()
}

func (guard *Guard) verifyLocked() error {
	if guard.closed || guard.quarantined || guard.pin == nil {
		return ErrUnavailable
	}
	if err := guard.pin.verify(guard.snapshot); err != nil {
		guard.quarantined = true
		return ErrUnavailable
	}
	return nil
}

func (guard *Guard) Close() error {
	if guard == nil {
		return ErrUnavailable
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.quarantined {
		return ErrUnavailable
	}
	if guard.closed {
		return nil
	}
	guard.closed = true
	if guard.pin == nil || guard.pin.close() != nil {
		guard.quarantined = true
		return ErrUnavailable
	}
	guard.pin = nil
	return nil
}

func (guard *OwnedGuard) Remove() error {
	if guard == nil || guard.Guard == nil {
		return ErrUnavailable
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.removeAttempted {
		if guard.removed {
			return nil
		}
		return ErrUnavailable
	}
	guard.removeAttempted = true
	if err := guard.verifyLocked(); err != nil {
		return err
	}
	if err := guard.pin.unlink(guard.snapshot.Socket.Name); err != nil {
		guard.quarantined = true
		return ErrUnavailable
	}
	if guard.afterUnlinkForTest != nil {
		guard.afterUnlinkForTest()
	}
	if err := guard.pin.verifyRemoved(guard.snapshot); err != nil {
		guard.quarantined = true
		return ErrUnavailable
	}
	guard.removed = true
	return nil
}

func validRootAndName(root, name string) bool {
	return filepath.IsAbs(root) &&
		filepath.Clean(root) == root &&
		name != "" &&
		name != "." &&
		name != ".." &&
		filepath.Base(name) == name
}

func validSnapshot(snapshot Snapshot) bool {
	return snapshot.Directory.Device != 0 &&
		snapshot.Directory.Inode != 0 &&
		snapshot.Directory.Mode == 0o700 &&
		snapshot.Socket.Name != "" &&
		snapshot.Socket.Device == snapshot.Directory.Device &&
		snapshot.Socket.Inode != 0 &&
		snapshot.Socket.UID == snapshot.Directory.UID &&
		snapshot.Socket.GID == snapshot.Directory.GID &&
		snapshot.Socket.Mode == 0o600
}
