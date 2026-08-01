package testenv

import (
	"context"
	"sync"
)

type task11RecoveryDriver interface {
	RunRecovery(context.Context) (SyntheticRecoveryProof, error)
	owns(cleanupHandle) bool
	remove(context.Context, cleanupHandle) error
	recordedRemoved(cleanupHandle) bool
}

type task11RecoveryRuntime struct {
	prepared task11PreparedRuntimeSource
	driver   task11RecoveryDriver

	mu      sync.Mutex
	started bool
	failed  bool
	ready   bool
	proof   SyntheticRecoveryProof
}

func newTask11RecoveryRuntime(
	prepared task11PreparedRuntimeSource,
	driver task11RecoveryDriver,
) (*task11RecoveryRuntime, error) {
	if prepared == nil || driver == nil {
		return nil, ErrFixtureStart
	}
	return &task11RecoveryRuntime{
		prepared: prepared,
		driver:   driver,
	}, nil
}

func (r *task11RecoveryRuntime) RecoveryObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (SyntheticRecoveryProof, error) {
	if r == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		r.prepared == nil ||
		r.driver == nil ||
		!validFixtureRuntimeObservation(prepared) {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if _, err := r.prepared.SnapshotPreparedEvidence(
		ctx,
		prepared,
	); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	r.mu.Lock()
	if r.started || r.failed || r.ready {
		r.mu.Unlock()
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	r.started = true
	r.mu.Unlock()

	proof, err := r.driver.RunRecovery(ctx)
	if err != nil || ValidateSyntheticRecovery(proof) != nil {
		r.mu.Lock()
		r.failed = true
		r.mu.Unlock()
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	r.mu.Lock()
	if r.failed || r.ready {
		r.failed = true
		r.mu.Unlock()
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	r.proof = cloneSyntheticRecoveryProof(proof)
	r.ready = true
	r.mu.Unlock()
	return cloneSyntheticRecoveryProof(proof), nil
}

func (r *task11RecoveryRuntime) owns(handle cleanupHandle) bool {
	return r != nil && r.driver != nil && r.driver.owns(handle)
}

func (r *task11RecoveryRuntime) remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if r == nil || r.driver == nil {
		return ErrFixtureCleanup
	}
	return r.driver.remove(ctx, handle)
}

func (r *task11RecoveryRuntime) recordedRemoved(
	handle cleanupHandle,
) bool {
	return r != nil &&
		r.driver != nil &&
		r.driver.recordedRemoved(handle)
}

var _ recoveryRuntime = (*task11RecoveryRuntime)(nil)
