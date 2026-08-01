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
		status  Status
		reason  Reason
	}{
		{
			name:    "storage stop",
			storage: denyStorage{},
			status:  StatusRecoverable,
			reason:  ReasonStorageStop,
		},
		{
			name:    "listener remains",
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.activeListeners = 1
			},
			status: StatusFailed,
			reason: ReasonProofFailed,
		},
		{
			name:    "identity substituted",
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.proofIdentity = strings.Repeat("f", 64)
			},
			status: StatusFailed,
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
				result.Status != test.status ||
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

func TestRunCycleRejectsZeroFenceGeneration(t *testing.T) {
	t.Parallel()

	supervisor := &fakeSupervisor{
		observation: Observation{
			ActiveFleet: FleetPortable,
			Process:     ProcessAbsent,
		},
	}
	result, err := (Watchdog{
		Lifecycle:    &fakeLifecycle{},
		Supervisor:   supervisor,
		Storage:      allowStorage{},
		PollInterval: time.Millisecond,
	}).RunCycle(context.Background())
	if !errors.Is(err, ErrSupervisionFailed) ||
		result.Status != StatusFailed ||
		result.Reason != ReasonInspectFailed ||
		supervisor.starts != 0 ||
		supervisor.stops != 0 ||
		supervisor.proofs != 0 {
		t.Fatalf(
			"RunCycle() = %#v, error=%v, supervisor=%#v",
			result,
			err,
			supervisor,
		)
	}
}

func TestRunCycleStopsAndProvesAbsentAfterFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		observation Observation
		storage     StorageEnvelope
		mutate      func(*fakeSupervisor)
		wantStatus  Status
		wantReason  Reason
		wantStarts  int
	}{
		{
			name: "running proof failure",
			observation: Observation{
				FenceGeneration: 31,
				ActiveFleet:     FleetPortable,
				Process:         ProcessRunning,
				ProcessIdentity: strings.Repeat("a", 64),
			},
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.activeListeners = 1
			},
			wantStatus: StatusFailed,
			wantReason: ReasonProofFailed,
		},
		{
			name: "storage failure",
			observation: Observation{
				FenceGeneration: 32,
				ActiveFleet:     FleetPortable,
				Process:         ProcessRunning,
				ProcessIdentity: strings.Repeat("b", 64),
			},
			storage:    denyStorage{},
			wantStatus: StatusRecoverable,
			wantReason: ReasonStorageStop,
		},
		{
			name: "new process proof failure",
			observation: Observation{
				FenceGeneration: 33,
				ActiveFleet:     FleetPortable,
				Process:         ProcessAbsent,
			},
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.activeListeners = 1
			},
			wantStatus: StatusFailed,
			wantReason: ReasonProofFailed,
			wantStarts: 1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			events := []string{}
			lifecycle := &fakeLifecycle{events: &events}
			supervisor := &fakeSupervisor{
				observation: test.observation,
				events:      &events,
			}
			if test.mutate != nil {
				test.mutate(supervisor)
			}
			result, err := (Watchdog{
				Lifecycle:    lifecycle,
				Supervisor:   supervisor,
				Storage:      test.storage,
				PollInterval: time.Millisecond,
			}).RunCycle(context.Background())
			if !errors.Is(err, ErrSupervisionFailed) ||
				result.Status != test.wantStatus ||
				result.Reason != test.wantReason ||
				supervisor.starts != test.wantStarts ||
				supervisor.stops != 1 ||
				supervisor.observation.Process != ProcessAbsent ||
				supervisor.observation.ProcessIdentity != "" ||
				lifecycle.lastLease == nil ||
				lifecycle.lastLease.closeCount != 1 {
				t.Fatalf(
					"RunCycle() = %#v, error=%v, supervisor=%#v, lease=%#v",
					result,
					err,
					supervisor,
					lifecycle.lastLease,
				)
			}
			stopIndex := indexOfEvent(events, "stop")
			proofIndex := lastIndexOfEvent(events, "inspect")
			closeIndex := indexOfEvent(events, "close")
			if stopIndex < 0 ||
				proofIndex < 0 ||
				closeIndex < 0 ||
				stopIndex >= proofIndex ||
				proofIndex >= closeIndex {
				t.Fatalf("call order = %v", events)
			}
		})
	}
}

func TestRunCycleFailsWhenPostStopAbsenceCannotBeProved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*fakeSupervisor)
	}{
		{
			name: "inspect error",
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.inspectErrAt = 2
				supervisor.inspectErr = errors.New("inspect failed")
			},
		},
		{
			name: "foreign identity remains",
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.afterStop = &Observation{
					FenceGeneration: 34,
					ActiveFleet:     FleetPortable,
					Process:         ProcessRunning,
					ProcessIdentity: strings.Repeat("f", 64),
				}
			},
		},
		{
			name: "fence drift",
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.afterStop = &Observation{
					FenceGeneration: 35,
					ActiveFleet:     FleetPortable,
					Process:         ProcessAbsent,
				}
			},
		},
		{
			name: "fleet drift",
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.afterStop = &Observation{
					FenceGeneration: 34,
					ActiveFleet:     FleetLegacy,
					Process:         ProcessAbsent,
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			supervisor := &fakeSupervisor{
				observation: Observation{
					FenceGeneration: 34,
					ActiveFleet:     FleetPortable,
					Process:         ProcessRunning,
					ProcessIdentity: strings.Repeat("d", 64),
				},
				activeListeners: 1,
			}
			test.mutate(supervisor)
			result, err := (Watchdog{
				Lifecycle:    &fakeLifecycle{},
				Supervisor:   supervisor,
				Storage:      allowStorage{},
				PollInterval: time.Millisecond,
			}).RunCycle(context.Background())
			if !errors.Is(err, ErrSupervisionFailed) ||
				result.Status != StatusFailed ||
				result.Reason != ReasonProofFailed ||
				supervisor.stops != 1 ||
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

func TestRunCycleUnhealthyStopFailureIsFailed(t *testing.T) {
	t.Parallel()

	stopErr := errors.New("stop failed")
	supervisor := &fakeSupervisor{
		observation: Observation{
			FenceGeneration: 35,
			ActiveFleet:     FleetPortable,
			Process:         ProcessUnhealthy,
			ProcessIdentity: strings.Repeat("e", 64),
		},
		stopErr: stopErr,
	}
	result, err := (Watchdog{
		Lifecycle:    &fakeLifecycle{},
		Supervisor:   supervisor,
		Storage:      allowStorage{},
		PollInterval: time.Millisecond,
	}).RunCycle(context.Background())
	if !errors.Is(err, ErrSupervisionFailed) ||
		!errors.Is(err, stopErr) ||
		result.Status != StatusFailed ||
		result.Reason != ReasonStopFailed ||
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

func TestRunCycleLeaseCloseFailureCannotReturnSuccess(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("lease close failed")
	lifecycle := &fakeLifecycle{closeErr: closeErr}
	result, err := (Watchdog{
		Lifecycle: lifecycle,
		Supervisor: &fakeSupervisor{
			observation: Observation{
				FenceGeneration: 36,
				ActiveFleet:     FleetNone,
				Process:         ProcessAbsent,
			},
		},
		Storage:      allowStorage{},
		PollInterval: time.Millisecond,
	}).RunCycle(context.Background())
	if !errors.Is(err, ErrSupervisionFailed) ||
		!errors.Is(err, closeErr) ||
		result.Status != StatusFailed ||
		result.Reason != Reason("lifecycle-close-failed") ||
		lifecycle.lastLease == nil ||
		lifecycle.lastLease.closeCount != 1 {
		t.Fatalf(
			"RunCycle() = %#v, error=%v, lease=%#v",
			result,
			err,
			lifecycle.lastLease,
		)
	}
}

func TestRunCycleLeaseCloseFailurePreservesPrimaryResult(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("lease close failed")
	lifecycle := &fakeLifecycle{
		owned:    true,
		closeErr: closeErr,
	}
	result, err := (Watchdog{
		Lifecycle: lifecycle,
		Supervisor: &fakeSupervisor{
			observation: Observation{
				FenceGeneration: 37,
				ActiveFleet:     FleetPortable,
				Process:         ProcessAbsent,
			},
		},
		Storage:      allowStorage{},
		PollInterval: time.Millisecond,
	}).RunCycle(context.Background())
	if !errors.Is(err, ErrLifecycleOwned) ||
		!errors.Is(err, closeErr) ||
		result.Status != StatusRecoverable ||
		result.Reason != ReasonLifecycleOwned ||
		lifecycle.lastLease == nil ||
		lifecycle.lastLease.closeCount != 1 {
		t.Fatalf(
			"RunCycle() = %#v, error=%v, lease=%#v",
			result,
			err,
			lifecycle.lastLease,
		)
	}
}

func TestRunCycleRevalidatesLeaseImmediatelyBeforeEveryMutation(t *testing.T) {
	t.Parallel()

	validationErr := errors.New("lease identity replaced")
	tests := []struct {
		name          string
		observation   Observation
		storage       StorageEnvelope
		mutate        func(*fakeSupervisor)
		validateErrAt int
		wantStarts    int
		wantStops     int
		wantProofs    int
	}{
		{
			name: "storage-stop path",
			observation: Observation{
				FenceGeneration: 41,
				ActiveFleet:     FleetPortable,
				Process:         ProcessRunning,
				ProcessIdentity: strings.Repeat("a", 64),
			},
			storage:       denyStorage{},
			validateErrAt: 2,
		},
		{
			name: "none-fleet stop path",
			observation: Observation{
				FenceGeneration: 42,
				ActiveFleet:     FleetNone,
				Process:         ProcessRunning,
				ProcessIdentity: strings.Repeat("b", 64),
			},
			storage:       allowStorage{},
			validateErrAt: 2,
		},
		{
			name: "running proof cleanup path",
			observation: Observation{
				FenceGeneration: 43,
				ActiveFleet:     FleetPortable,
				Process:         ProcessRunning,
				ProcessIdentity: strings.Repeat("c", 64),
			},
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.activeListeners = 1
			},
			validateErrAt: 2,
			wantProofs:    1,
		},
		{
			name: "unhealthy stop path",
			observation: Observation{
				FenceGeneration: 44,
				ActiveFleet:     FleetPortable,
				Process:         ProcessUnhealthy,
				ProcessIdentity: strings.Repeat("d", 64),
			},
			storage:       allowStorage{},
			validateErrAt: 2,
		},
		{
			name: "restart after unhealthy stop",
			observation: Observation{
				FenceGeneration: 45,
				ActiveFleet:     FleetPortable,
				Process:         ProcessUnhealthy,
				ProcessIdentity: strings.Repeat("e", 64),
			},
			storage:       allowStorage{},
			validateErrAt: 3,
			wantStops:     1,
		},
		{
			name: "start path",
			observation: Observation{
				FenceGeneration: 46,
				ActiveFleet:     FleetPortable,
				Process:         ProcessAbsent,
			},
			storage:       allowStorage{},
			validateErrAt: 2,
		},
		{
			name: "post-start proof cleanup path",
			observation: Observation{
				FenceGeneration: 47,
				ActiveFleet:     FleetPortable,
				Process:         ProcessAbsent,
			},
			storage: allowStorage{},
			mutate: func(supervisor *fakeSupervisor) {
				supervisor.activeListeners = 1
			},
			validateErrAt: 3,
			wantStarts:    1,
			wantProofs:    1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lifecycle := &fakeLifecycle{
				validateErrAt: test.validateErrAt,
				validateErr:   validationErr,
			}
			supervisor := &fakeSupervisor{observation: test.observation}
			if test.mutate != nil {
				test.mutate(supervisor)
			}
			result, err := (Watchdog{
				Lifecycle:    lifecycle,
				Supervisor:   supervisor,
				Storage:      test.storage,
				PollInterval: time.Millisecond,
			}).RunCycle(context.Background())
			if !errors.Is(err, ErrSupervisionFailed) ||
				result.Status != StatusFailed ||
				result.Reason != ReasonInspectFailed ||
				supervisor.starts != test.wantStarts ||
				supervisor.stops != test.wantStops ||
				supervisor.proofs != test.wantProofs ||
				lifecycle.lastLease == nil ||
				lifecycle.lastLease.validateCount != test.validateErrAt ||
				lifecycle.lastLease.closeCount != 1 {
				t.Fatalf(
					"RunCycle()=%#v error=%v supervisor=%#v lease=%#v",
					result,
					err,
					supervisor,
					lifecycle.lastLease,
				)
			}
		})
	}
}

func indexOfEvent(events []string, wanted string) int {
	for index, event := range events {
		if event == wanted {
			return index
		}
	}
	return -1
}

func lastIndexOfEvent(events []string, wanted string) int {
	found := -1
	for index, event := range events {
		if event == wanted {
			found = index
		}
	}
	return found
}

type fakeSupervisor struct {
	mu              sync.Mutex
	observation     Observation
	starts          int
	stops           int
	proofs          int
	activeListeners uint64
	proofIdentity   string
	inspectCount    int
	inspectErrAt    int
	inspectErr      error
	afterStop       *Observation
	events          *[]string
	stopErr         error
}

func (supervisor *fakeSupervisor) Inspect(
	context.Context,
) (Observation, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	supervisor.inspectCount++
	supervisor.recordEvent("inspect")
	if supervisor.inspectErrAt == supervisor.inspectCount {
		return Observation{}, supervisor.inspectErr
	}
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
	supervisor.recordEvent("stop")
	supervisor.stops++
	if supervisor.stopErr != nil {
		return supervisor.stopErr
	}
	if supervisor.afterStop != nil {
		supervisor.observation = *supervisor.afterStop
		return nil
	}
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
	supervisor.recordEvent("start")
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
	supervisor.recordEvent("prove")
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

func (supervisor *fakeSupervisor) recordEvent(event string) {
	if supervisor.events != nil {
		*supervisor.events = append(*supervisor.events, event)
	}
}

type allowStorage struct{}

func (allowStorage) Revalidate(context.Context) error { return nil }

type denyStorage struct{}

func (denyStorage) Revalidate(context.Context) error {
	return errors.New("stop")
}

type fakeLifecycle struct {
	owned         bool
	acquireErr    error
	ownedErr      error
	closeErr      error
	validateErrAt int
	validateErr   error
	events        *[]string
	lastLease     *fakeLifecycleLease
}

func (lifecycle *fakeLifecycle) Acquire(
	context.Context,
	time.Duration,
) (LifecycleLease, error) {
	if lifecycle.events != nil {
		*lifecycle.events = append(*lifecycle.events, "acquire")
	}
	if lifecycle.acquireErr != nil {
		return nil, lifecycle.acquireErr
	}
	lifecycle.lastLease = &fakeLifecycleLease{
		owned:         lifecycle.owned,
		err:           lifecycle.ownedErr,
		closeErr:      lifecycle.closeErr,
		validateErrAt: lifecycle.validateErrAt,
		validateErr:   lifecycle.validateErr,
		events:        lifecycle.events,
	}
	return lifecycle.lastLease, nil
}

type fakeLifecycleLease struct {
	owned         bool
	err           error
	closeErr      error
	closeCount    int
	validateErrAt int
	validateErr   error
	validateCount int
	events        *[]string
}

func (lease *fakeLifecycleLease) Validate() error {
	lease.recordEvent("validate")
	lease.validateCount++
	if lease.validateCount == lease.validateErrAt {
		return lease.validateErr
	}
	return nil
}

func (lease *fakeLifecycleLease) Owned() (bool, error) {
	lease.recordEvent("owned")
	return lease.owned, lease.err
}

func (lease *fakeLifecycleLease) Close() error {
	lease.closeCount++
	lease.recordEvent("close")
	return lease.closeErr
}

func (lease *fakeLifecycleLease) recordEvent(event string) {
	if lease.events != nil {
		*lease.events = append(*lease.events, event)
	}
}
