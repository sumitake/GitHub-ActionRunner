package testenv

import (
	"context"
	"errors"
	"testing"
)

type fakeTask11RecoveryDriver struct {
	proof       SyntheticRecoveryProof
	err         error
	calls       int
	removed     bool
	removeCalls int
	handle      cleanupHandle
}

func (d *fakeTask11RecoveryDriver) RunRecovery(
	ctx context.Context,
) (SyntheticRecoveryProof, error) {
	if ctx == nil || ctx.Err() != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	d.calls++
	return cloneSyntheticRecoveryProof(d.proof), d.err
}

func (d *fakeTask11RecoveryDriver) owns(handle cleanupHandle) bool {
	return handle == d.handle
}

func (d *fakeTask11RecoveryDriver) remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if ctx == nil || ctx.Err() != nil || !d.owns(handle) {
		return ErrFixtureCleanup
	}
	d.removeCalls++
	d.removed = true
	return nil
}

func (d *fakeTask11RecoveryDriver) recordedRemoved(
	handle cleanupHandle,
) bool {
	return d.owns(handle) && d.removed
}

func TestTask11RecoveryRuntimeRunsOnceAgainstPreparedEvidence(t *testing.T) {
	preparedSource, prepared := validTask11SyntheticPreparedSource()
	handle := cleanupHandle{
		kind: CleanupHelper,
		id:   "0000000000000000000000000000000000000000000000000000000000000001",
	}
	driver := &fakeTask11RecoveryDriver{
		proof:  validSyntheticRecoveryProof(),
		handle: handle,
	}
	runtime, err := newTask11RecoveryRuntime(preparedSource, driver)
	if err != nil {
		t.Fatalf("newTask11RecoveryRuntime: %v", err)
	}
	proof, err := runtime.RecoveryObservation(
		context.Background(),
		prepared,
	)
	if err != nil || ValidateSyntheticRecovery(proof) != nil {
		t.Fatalf("RecoveryObservation = %+v, %v", proof, err)
	}
	if driver.calls != 1 {
		t.Fatalf("driver calls = %d, want 1", driver.calls)
	}
	if _, err := runtime.RecoveryObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("second observation error = %v", err)
	}
	if !runtime.owns(handle) {
		t.Fatal("runtime does not own driver handle")
	}
	if err := runtime.remove(context.Background(), handle); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !runtime.recordedRemoved(handle) {
		t.Fatal("removed driver handle was not recorded")
	}
}

func TestTask11RecoveryRuntimeFailsClosedOnInvalidProof(t *testing.T) {
	preparedSource, prepared := validTask11SyntheticPreparedSource()
	driver := &fakeTask11RecoveryDriver{
		proof: validSyntheticRecoveryProof(),
	}
	driver.proof.ListenerReleaseCalls = 1
	runtime, err := newTask11RecoveryRuntime(preparedSource, driver)
	if err != nil {
		t.Fatalf("newTask11RecoveryRuntime: %v", err)
	}
	if _, err := runtime.RecoveryObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("invalid proof error = %v", err)
	}
}
