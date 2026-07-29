package watchdog

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunCycleRestartsOnlyDisabledAtSameFence(t *testing.T) {
	t.Parallel()

	lifecycle := &fakeLifecycle{}
	supervisor := &fakeSupervisor{
		observation: Observation{
			FenceGeneration: 19,
			ActiveFleet:     FleetPortable,
			Process:         ProcessAbsent,
		},
	}
	watchdog := Watchdog{
		Lifecycle:    lifecycle,
		Supervisor:   supervisor,
		Storage:      allowStorage{},
		PollInterval: time.Millisecond,
	}
	result, err := watchdog.RunCycle(context.Background())
	if err != nil ||
		result.Status != StatusOK ||
		result.Reason != ReasonRestarted ||
		supervisor.starts != 1 ||
		supervisor.stops != 0 ||
		supervisor.proofs != 1 {
		t.Fatalf(
			"RunCycle() = %#v, error=%v, supervisor=%#v",
			result,
			err,
			supervisor,
		)
	}
}

func TestRunCycleRefusesToCrossNonterminalLifecycleState(t *testing.T) {
	t.Parallel()

	lifecycle := &fakeLifecycle{owned: true}
	supervisor := &fakeSupervisor{
		observation: Observation{
			FenceGeneration: 19,
			ActiveFleet:     FleetPortable,
			Process:         ProcessAbsent,
		},
	}
	watchdog := Watchdog{
		Lifecycle:    lifecycle,
		Supervisor:   supervisor,
		Storage:      allowStorage{},
		PollInterval: time.Millisecond,
	}
	result, err := watchdog.RunCycle(context.Background())
	if !errors.Is(err, ErrLifecycleOwned) ||
		result.Status != StatusRecoverable ||
		result.Reason != ReasonLifecycleOwned ||
		supervisor.starts != 0 ||
		supervisor.stops != 0 {
		t.Fatalf(
			"RunCycle() = %#v, error=%v, supervisor=%#v",
			result,
			err,
			supervisor,
		)
	}
}

func TestRunCycleStopsUnexpectedProcessWhenFenceIsNone(t *testing.T) {
	t.Parallel()

	lifecycle := &fakeLifecycle{}
	supervisor := &fakeSupervisor{
		observation: Observation{
			FenceGeneration: 20,
			ActiveFleet:     FleetNone,
			Process:         ProcessRunning,
			ProcessIdentity: strings.Repeat("a", 64),
		},
	}
	watchdog := Watchdog{
		Lifecycle:    lifecycle,
		Supervisor:   supervisor,
		Storage:      allowStorage{},
		PollInterval: time.Millisecond,
	}
	result, err := watchdog.RunCycle(context.Background())
	if err != nil ||
		result.Status != StatusOK ||
		result.Reason != ReasonStoppedAtNone ||
		supervisor.stops != 1 ||
		supervisor.starts != 0 {
		t.Fatalf(
			"RunCycle() = %#v, error=%v, supervisor=%#v",
			result,
			err,
			supervisor,
		)
	}
}

func TestRunCycleFailsClosedOnProofOrStorageDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		storage StorageEnvelope
		mutate  func(*fakeSupervisor)
		reason  Reason
	}{
		{
			name:    "storage stop",
			storage: denyStorage{},
			reason:  ReasonStorageStop,
		},
		{
			name:    "listener remains",
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.activeListeners = 1
			},
			reason: ReasonProofFailed,
		},
		{
			name:    "identity substituted",
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.proofIdentity = strings.Repeat("f", 64)
			},
			reason: ReasonProofFailed,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lifecycle := &fakeLifecycle{}
			supervisor := &fakeSupervisor{
				observation: Observation{
					FenceGeneration: 21,
					ActiveFleet:     FleetPortable,
					Process:         ProcessRunning,
					ProcessIdentity: strings.Repeat("b", 64),
				},
			}
			if test.mutate != nil {
				test.mutate(supervisor)
			}
			watchdog := Watchdog{
				Lifecycle:    lifecycle,
				Supervisor:   supervisor,
				Storage:      test.storage,
				PollInterval: time.Millisecond,
			}
			result, err := watchdog.RunCycle(context.Background())
			if err == nil ||
				result.Status != StatusRecoverable ||
				result.Reason != test.reason ||
				supervisor.starts != 0 {
				t.Fatalf(
					"RunCycle() = %#v, error=%v, supervisor=%#v",
					result,
					err,
					supervisor,
				)
			}
		})
	}
}

type fakeSupervisor struct {
	mu              sync.Mutex
	observation     Observation
	starts          int
	stops           int
	proofs          int
	activeListeners uint64
	proofIdentity   string
}

func (supervisor *fakeSupervisor) Inspect(
	context.Context,
) (Observation, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.observation, nil
}

func (supervisor *fakeSupervisor) SafeStop(
	_ context.Context,
	observation Observation,
) error {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if observation != supervisor.observation {
		return ErrSupervisionFailed
	}
	supervisor.stops++
	supervisor.observation.Process = ProcessAbsent
	supervisor.observation.ProcessIdentity = ""
	return nil
}

func (supervisor *fakeSupervisor) StartDisabled(
	_ context.Context,
	observation Observation,
) (Observation, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if observation != supervisor.observation ||
		observation.Process != ProcessAbsent {
		return Observation{}, ErrSupervisionFailed
	}
	supervisor.starts++
	supervisor.observation.Process = ProcessRunning
	supervisor.observation.ProcessIdentity = strings.Repeat("c", 64)
	return supervisor.observation, nil
}

func (supervisor *fakeSupervisor) ProveDisabled(
	_ context.Context,
	observation Observation,
) (DisabledProof, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	supervisor.proofs++
	identity := observation.ProcessIdentity
	if supervisor.proofIdentity != "" {
		identity = supervisor.proofIdentity
	}
	return DisabledProof{
		FenceGeneration:      observation.FenceGeneration,
		ActiveFleet:          observation.ActiveFleet,
		ProcessIdentity:      identity,
		PolicyDisabled:       true,
		PendingAcquisitions:  0,
		ActiveListeners:      supervisor.activeListeners,
		ManagedProcesses:     1,
		AcquisitionProcesses: 0,
	}, nil
}

type allowStorage struct{}

func (allowStorage) Revalidate(context.Context) error { return nil }

type denyStorage struct{}

func (denyStorage) Revalidate(context.Context) error {
	return errors.New("stop")
}

type fakeLifecycle struct {
	owned      bool
	acquireErr error
	ownedErr   error
}

func (lifecycle *fakeLifecycle) Acquire(
	context.Context,
	time.Duration,
) (LifecycleLease, error) {
	if lifecycle.acquireErr != nil {
		return nil, lifecycle.acquireErr
	}
	return &fakeLifecycleLease{
		owned: lifecycle.owned,
		err:   lifecycle.ownedErr,
	}, nil
}

type fakeLifecycleLease struct {
	owned bool
	err   error
}

func (*fakeLifecycleLease) Validate() error { return nil }

func (lease *fakeLifecycleLease) Owned() (bool, error) {
	return lease.owned, lease.err
}

func (*fakeLifecycleLease) Close() error { return nil }
