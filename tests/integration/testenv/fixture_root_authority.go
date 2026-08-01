package testenv

import (
	"context"
	"errors"
	"sync"
)

var ErrFixtureRootInUse = errors.New("testenv: fixture root in use")

type fixtureRootLeaseOperations interface {
	Lock() error
	ObserveEmpty() (fixtureRootObservation, error)
	Remove() error
	SyncParent() error
	ProveAbsent() error
	Close() error
}

type fixtureRootAuthorityState uint8

const (
	fixtureRootAuthorityReady fixtureRootAuthorityState = iota + 1
	fixtureRootAuthorityHeld
	fixtureRootAuthorityClosed
)

// lockedFixtureRootAuthority owns the stable fixture-root inode from the
// first-effect boundary through exact root removal. It never discovers or
// recursively removes children.
type lockedFixtureRootAuthority struct {
	mu          sync.Mutex
	state       fixtureRootAuthorityState
	operations  fixtureRootLeaseOperations
	binding     FixtureBinding
	observation fixtureRootObservation
	handle      cleanupHandle
	closeOnce   sync.Once
	closeErr    error
}

func newLockedFixtureRootAuthority(
	operations fixtureRootLeaseOperations,
) (*lockedFixtureRootAuthority, error) {
	if operations == nil {
		return nil, ErrFixtureStart
	}
	return &lockedFixtureRootAuthority{
		state:      fixtureRootAuthorityReady,
		operations: operations,
	}, nil
}

func (a *lockedFixtureRootAuthority) Acquire(
	ctx context.Context,
	binding FixtureBinding,
) (cleanupHandle, error) {
	if a == nil || ctx == nil {
		return cleanupHandle{}, ErrFixtureStart
	}
	if err := ctx.Err(); err != nil {
		return cleanupHandle{}, ErrFixtureStart
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != fixtureRootAuthorityReady ||
		a.operations == nil ||
		!validAbsolutePath(binding.Root) ||
		binding.ParentDevice == 0 ||
		binding.ParentInode == 0 ||
		!isLowerHex(binding.RequiredEmptyDigest, 64) {
		return cleanupHandle{}, ErrFixtureStart
	}
	if err := a.operations.Lock(); err != nil {
		_ = a.closeLocked()
		if errors.Is(err, ErrFixtureRootInUse) {
			return cleanupHandle{}, ErrFixtureRootInUse
		}
		return cleanupHandle{}, ErrFixtureStart
	}
	observation, err := a.operations.ObserveEmpty()
	if err != nil || !fixtureRootObservationMatches(binding, observation) {
		_ = a.closeLocked()
		return cleanupHandle{}, ErrFixtureStart
	}
	digest, err := computeFixtureEmptyDigest(observation)
	if err != nil || digest != binding.RequiredEmptyDigest {
		_ = a.closeLocked()
		return cleanupHandle{}, ErrFixtureStart
	}
	a.state = fixtureRootAuthorityHeld
	a.binding = binding
	a.observation = observation
	a.handle = cleanupHandle{
		kind: CleanupFixtureRoot,
		id:   digest,
	}
	return a.handle, nil
}

func (a *lockedFixtureRootAuthority) RemoveRoot(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if a == nil || ctx == nil {
		return ErrFixtureCleanup
	}
	if err := ctx.Err(); err != nil {
		return ErrFixtureCleanup
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != fixtureRootAuthorityHeld ||
		handle != a.handle ||
		a.operations == nil {
		return ErrFixtureCleanup
	}
	observation, err := a.operations.ObserveEmpty()
	if err != nil {
		_ = a.closeLocked()
		if errors.Is(err, ErrFixtureUnexpectedObject) {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	if observation != a.observation ||
		!fixtureRootObservationMatches(a.binding, observation) {
		_ = a.closeLocked()
		return ErrFixtureCleanup
	}
	digest, err := computeFixtureEmptyDigest(observation)
	if err != nil || digest != handle.id {
		_ = a.closeLocked()
		return ErrFixtureCleanup
	}
	if err := a.operations.Remove(); err != nil {
		_ = a.closeLocked()
		return ErrFixtureCleanup
	}
	if err := a.operations.SyncParent(); err != nil {
		_ = a.closeLocked()
		return ErrFixtureCleanup
	}
	if err := a.operations.ProveAbsent(); err != nil {
		_ = a.closeLocked()
		return ErrFixtureCleanup
	}
	if err := a.closeLocked(); err != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (a *lockedFixtureRootAuthority) Close() error {
	if a == nil {
		return ErrFixtureCleanup
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closeLocked(); err != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (a *lockedFixtureRootAuthority) closeLocked() error {
	a.closeOnce.Do(func() {
		if a.operations != nil {
			a.closeErr = a.operations.Close()
		}
		a.state = fixtureRootAuthorityClosed
	})
	return a.closeErr
}

func fixtureRootObservationMatches(
	binding FixtureBinding,
	observation fixtureRootObservation,
) bool {
	return observation.SchemaVersion == 1 &&
		observation.ParentDevice == binding.ParentDevice &&
		observation.ParentInode == binding.ParentInode &&
		observation.ParentOwnerUID == binding.ExecutionOwnerUID &&
		observation.ParentMode&0o022 == 0 &&
		observation.RootDevice == binding.ParentDevice &&
		observation.OwnerUID == binding.ExecutionOwnerUID &&
		observation.Mode == 0o700
}
