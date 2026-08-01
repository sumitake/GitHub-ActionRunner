//go:build darwin || linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLifecycleEngineExecuteRejectsClosedLeaseBeforeEffects(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	effects := newTestLifecycleEffects(t, binding)
	var acquired *LifecycleLease
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 57, 0, 0, time.UTC),
		),
		leaseAcquire: func(
			ctx context.Context,
			pollInterval time.Duration,
		) (lifecycleOperationLease, error) {
			lease, err := store.Acquire(ctx, pollInterval)
			if err != nil {
				return nil, err
			}
			acquired = lease
			if err := unix.Close(lease.fd); err != nil {
				return nil, err
			}
			lease.fd = -1
			return lease, nil
		},
	}
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 57, 0, 0, time.UTC),
	)

	result, err := engine.Execute(context.Background(), request)
	if !errors.Is(err, ErrLifecycleExecution) ||
		result.Status != HostActionFailed ||
		result.ErrorClass != LifecycleErrorIntegrity ||
		len(effects.countsCopy()) != 0 ||
		acquired == nil ||
		!acquired.closed {
		t.Fatalf(
			"Execute() = %#v, error=%v, effects=%#v, lease=%#v",
			result,
			err,
			effects.countsCopy(),
			acquired,
		)
	}
}

func TestLifecycleEngineRecoverRejectsReplacedLockBeforeEffects(t *testing.T) {
	t.Parallel()

	root := makeLifecycleRoot(t)
	store, err := OpenLifecycleStore(root, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("LifecycleStore.Close() error = %v", err)
		}
	})
	binding := goldenUpgradeBinding(t)
	effects := newTestLifecycleEffects(t, binding)
	var acquired *LifecycleLease
	engine := LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      allowTestStorage{},
		Compensation: &testCompensationAuthority{},
		PollInterval: time.Millisecond,
		Now: monotonicTestClock(
			time.Date(2026, 7, 29, 12, 58, 0, 0, time.UTC),
		),
		leaseAcquire: func(
			ctx context.Context,
			pollInterval time.Duration,
		) (lifecycleOperationLease, error) {
			lease, err := store.Acquire(ctx, pollInterval)
			if err != nil {
				return nil, err
			}
			acquired = lease
			lockPath := filepath.Join(root, lifecycleLockName)
			if err := os.Remove(lockPath); err != nil {
				return nil, err
			}
			if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
				return nil, err
			}
			return lease, nil
		},
	}
	request := lifecycleTestRequest(
		t,
		binding,
		time.Date(2026, 7, 29, 12, 58, 0, 0, time.UTC),
	)

	result, err := engine.Recover(context.Background(), request)
	if !errors.Is(err, ErrLifecycleExecution) ||
		result.Status != HostActionFailed ||
		result.ErrorClass != LifecycleErrorIntegrity ||
		len(effects.countsCopy()) != 0 ||
		acquired == nil ||
		!acquired.closed {
		t.Fatalf(
			"Recover() = %#v, error=%v, effects=%#v, lease=%#v",
			result,
			err,
			effects.countsCopy(),
			acquired,
		)
	}
	names, listErr := store.ListCanonicalNames(LifecycleJournals)
	if listErr == nil || len(names) != 0 {
		t.Fatalf(
			"journal names = %v, error=%v; replaced lock must fail closed",
			names,
			listErr,
		)
	}
}
