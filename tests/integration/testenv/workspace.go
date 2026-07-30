package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

type fixtureWorkspaceOperations interface {
	Prepare(uint32, uint32) error
	StateDatabasePath() (string, error)
	Remove() error
	Close() error
}

type fixtureWorkspaceState uint8

const (
	fixtureWorkspaceReady fixtureWorkspaceState = iota + 1
	fixtureWorkspaceCleanupReachable
	fixtureWorkspacePrepared
	fixtureWorkspaceRemoved
)

type fixtureWorkspace struct {
	mu         sync.Mutex
	state      fixtureWorkspaceState
	operations fixtureWorkspaceOperations
	handle     cleanupHandle
}

func compositionCleanupHandle(
	kind CleanupKind,
	domain string,
	runDigest string,
) (cleanupHandle, error) {
	if !validCleanupKind(kind) || domain == "" ||
		!isLowerHex(runDigest, sha256.Size*2) {
		return cleanupHandle{}, ErrFixtureStart
	}
	raw, err := hex.DecodeString(runDigest)
	if err != nil || len(raw) != sha256.Size {
		return cleanupHandle{}, ErrFixtureStart
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{byte(kind)})
	_, _ = hash.Write(raw)
	id := hex.EncodeToString(hash.Sum(nil))
	if !isLowerHex(id, sha256.Size*2) {
		return cleanupHandle{}, ErrFixtureStart
	}
	return cleanupHandle{kind: kind, id: id}, nil
}

func newFixtureWorkspace(
	operations fixtureWorkspaceOperations,
	handle cleanupHandle,
) (*fixtureWorkspace, error) {
	if operations == nil ||
		handle.kind != CleanupTestProcess ||
		!isLowerHex(handle.id, sha256.Size*2) {
		return nil, ErrFixtureStart
	}
	return &fixtureWorkspace{
		state:      fixtureWorkspaceReady,
		operations: operations,
		handle:     handle,
	}, nil
}

func (w *fixtureWorkspace) Acquire(
	ctx context.Context,
	brokerUser string,
	record func(cleanupHandle) error,
) error {
	uid, gid, ok := parseStaticNumericUser(brokerUser)
	if w == nil || ctx == nil || ctx.Err() != nil ||
		record == nil || !ok || uid == 0 {
		return ErrFixtureStart
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != fixtureWorkspaceReady ||
		w.operations == nil {
		return ErrFixtureStart
	}
	if err := record(w.handle); err != nil {
		_ = w.operations.Close()
		w.state = fixtureWorkspaceRemoved
		return ErrFixtureStart
	}
	w.state = fixtureWorkspaceCleanupReachable
	if err := w.operations.Prepare(uint32(uid), uint32(gid)); err != nil {
		return ErrFixtureStart
	}
	w.state = fixtureWorkspacePrepared
	return nil
}

func (w *fixtureWorkspace) StateDatabasePath() (string, error) {
	if w == nil {
		return "", ErrFixtureStart
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != fixtureWorkspacePrepared ||
		w.operations == nil {
		return "", ErrFixtureStart
	}
	path, err := w.operations.StateDatabasePath()
	if err != nil || !validAbsolutePath(path) {
		return "", ErrFixtureStart
	}
	return path, nil
}

func (w *fixtureWorkspace) Remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if w == nil || ctx == nil || ctx.Err() != nil ||
		handle != w.handle {
		return ErrFixtureCleanup
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state == fixtureWorkspaceRemoved {
		return nil
	}
	if (w.state != fixtureWorkspaceCleanupReachable &&
		w.state != fixtureWorkspacePrepared) ||
		w.operations == nil {
		return ErrFixtureCleanup
	}
	removeErr := w.operations.Remove()
	closeErr := w.operations.Close()
	w.state = fixtureWorkspaceRemoved
	if removeErr != nil {
		if removeErr == ErrFixtureUnexpectedObject {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	if closeErr != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (w *fixtureWorkspace) CloseUnstarted() error {
	if w == nil {
		return ErrFixtureCleanup
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch w.state {
	case fixtureWorkspaceReady:
		if w.operations == nil {
			return ErrFixtureCleanup
		}
		err := w.operations.Close()
		w.state = fixtureWorkspaceRemoved
		if err != nil {
			return ErrFixtureCleanup
		}
		return nil
	case fixtureWorkspaceRemoved:
		return nil
	default:
		// Once the workspace handle is cleanup-reachable, the fixture cleanup
		// state machine is its sole destructive authority.
		return nil
	}
}
