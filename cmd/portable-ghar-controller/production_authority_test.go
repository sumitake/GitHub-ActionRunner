package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type productionAuthorityStateFixture struct {
	mu             sync.Mutex
	policy         controller.AcquisitionPolicy
	recoverable    []controller.RecoverableAssignment
	summary        controller.OperationalSummary
	advanced       []controller.AssignmentKey
	markedEpoch    uint64
	markedAt       time.Time
	marked         []controller.AssignmentKey
	beginCycles    []string
	completeCycles []controller.CycleReceipt
	abortCycles    []string
	advanceErr     error
	listErr        error
	summaryErr     error
	markErr        error
}

func (fixture *productionAuthorityStateFixture) Snapshot(
	context.Context,
) (controller.AcquisitionPolicy, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return cloneObserverDesired(fixture.policy), nil
}

func (fixture *productionAuthorityStateFixture) MarkPreRunningRevoked(
	_ context.Context,
	epoch uint64,
	at time.Time,
) ([]controller.AssignmentKey, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.markedEpoch = epoch
	fixture.markedAt = at
	return append([]controller.AssignmentKey(nil), fixture.marked...), fixture.markErr
}

func (fixture *productionAuthorityStateFixture) OperationalSummary(
	context.Context,
	time.Time,
) (controller.OperationalSummary, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.summary, fixture.summaryErr
}

func (fixture *productionAuthorityStateFixture) Advance(
	_ context.Context,
	key controller.AssignmentKey,
	next controller.State,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if next != controller.StateDestroyed {
		return errors.New("unexpected state")
	}
	fixture.advanced = append(fixture.advanced, key)
	return fixture.advanceErr
}

func (fixture *productionAuthorityStateFixture) BeginCycle(
	_ context.Context,
	id string,
	_ time.Time,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.beginCycles = append(fixture.beginCycles, id)
	return nil
}

func (fixture *productionAuthorityStateFixture) ListRecoverable(
	context.Context,
) ([]controller.RecoverableAssignment, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append(
		[]controller.RecoverableAssignment(nil),
		fixture.recoverable...,
	), fixture.listErr
}

func (fixture *productionAuthorityStateFixture) CompleteCycle(
	_ context.Context,
	receipt controller.CycleReceipt,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.completeCycles = append(fixture.completeCycles, receipt)
	return nil
}

func (fixture *productionAuthorityStateFixture) AbortCycle(
	_ context.Context,
	id string,
	_ time.Time,
	_ controller.ReasonCode,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.abortCycles = append(fixture.abortCycles, id)
	return nil
}

type productionRecoveryFixture struct {
	mu         sync.Mutex
	specs      []hostruntime.RecoverySpec
	removals   int
	inspectErr error
	removeErr  error
}

func (fixture *productionRecoveryFixture) InspectManaged(
	_ context.Context,
	spec hostruntime.RecoverySpec,
) (hostruntime.ManagedSnapshot, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.specs = append(fixture.specs, spec)
	return hostruntime.ManagedSnapshot{}, fixture.inspectErr
}

func (fixture *productionRecoveryFixture) RemoveManaged(
	context.Context,
	hostruntime.ManagedSnapshot,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.removals++
	return fixture.removeErr
}

type productionQuiescenceFixture struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (fixture *productionQuiescenceFixture) ProveManagedQuiescence(
	context.Context,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.calls++
	return fixture.err
}

func productionRecoverable(
	state controller.State,
) controller.RecoverableAssignment {
	key := controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 41,
	}
	slot := controller.RunnerSlot{}
	if state != controller.StateReceived {
		slot = controller.RunnerSlot{
			OpaqueName:         controller.OpaqueSlotName(key),
			CapacitySlotID:     1,
			AdapterContainerID: strings.Repeat("a", 64),
		}
	}
	switch state {
	case controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified:
		slot.BrokerContainerID = strings.Repeat("b", 64)
	case controller.StateRunnerHeld, controller.StateReleaseArmed:
		slot.BrokerContainerID = strings.Repeat("b", 64)
		slot.RunnerContainerID = strings.Repeat("c", 64)
	}
	return controller.RecoverableAssignment{
		Key:       key,
		State:     state,
		Slot:      slot,
		UpdatedAt: time.Date(2026, 7, 30, 1, 0, 0, 0, time.UTC),
	}
}

func TestProductionCleanupWorkerReclaimsExactPreReleaseSlot(t *testing.T) {
	t.Parallel()

	state := &productionAuthorityStateFixture{}
	recovery := &productionRecoveryFixture{}
	root := "/var/lib/portable-ghar/broker"
	worker, err := newProductionCleanupWorker(
		state,
		recovery,
		strings.Repeat("d", 64),
		17,
		root,
	)
	if err != nil {
		t.Fatalf("newProductionCleanupWorker: %v", err)
	}
	assignment := productionRecoverable(controller.StateRunnerHeld)
	if err := worker.ReconcileAssignment(
		context.Background(),
		assignment,
	); err != nil {
		t.Fatalf("ReconcileAssignment: %v", err)
	}
	if len(recovery.specs) != 1 || recovery.removals != 1 {
		t.Fatalf(
			"recovery calls = specs:%d removals:%d, want 1/1",
			len(recovery.specs),
			recovery.removals,
		)
	}
	spec := recovery.specs[0]
	suffix := strings.TrimPrefix(
		assignment.Slot.OpaqueName,
		"pghar-slot-",
	)
	want := hostruntime.RecoverySpec{
		SlotIdentity:      assignment.Slot.OpaqueName,
		BuildID:           strings.Repeat("d", 64),
		FleetGeneration:   17,
		AdapterName:       "pghar-adapter-" + suffix,
		BrokerName:        "pghar-broker-" + suffix,
		RunnerName:        "pghar-runner-" + suffix,
		ExpectedAdapterID: assignment.Slot.AdapterContainerID,
		ExpectedBrokerID:  assignment.Slot.BrokerContainerID,
		ExpectedRunnerID:  assignment.Slot.RunnerContainerID,
		RelayParent: filepath.Join(
			root,
			assignment.Slot.OpaqueName,
			"relay",
		),
		AuthorityParent: filepath.Join(
			root,
			assignment.Slot.OpaqueName,
			"authority",
		),
	}
	if spec != want {
		t.Fatalf("recovery spec = %+v, want %+v", spec, want)
	}
	if len(state.advanced) != 1 || state.advanced[0] != assignment.Key {
		t.Fatalf("advanced = %+v, want exact assignment", state.advanced)
	}
}

func TestProductionCleanupWorkerTerminalizesEmptyReceivedAssignment(t *testing.T) {
	t.Parallel()

	state := &productionAuthorityStateFixture{}
	recovery := &productionRecoveryFixture{}
	worker, err := newProductionCleanupWorker(
		state,
		recovery,
		strings.Repeat("d", 64),
		17,
		"/var/lib/portable-ghar/broker",
	)
	if err != nil {
		t.Fatalf("newProductionCleanupWorker: %v", err)
	}
	assignment := productionRecoverable(controller.StateReceived)
	if err := worker.ReconcileAssignment(context.Background(), assignment); err != nil {
		t.Fatalf("ReconcileAssignment: %v", err)
	}
	if len(recovery.specs) != 0 || recovery.removals != 0 ||
		len(state.advanced) != 1 {
		t.Fatalf(
			"calls = specs:%d removals:%d advanced:%d, want 0/0/1",
			len(recovery.specs),
			recovery.removals,
			len(state.advanced),
		)
	}
}

func TestProductionCleanupWorkerRejectsUnsafeStateBeforeRuntimeMutation(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*controller.RecoverableAssignment){
		"released": func(value *controller.RecoverableAssignment) {
			value.State = controller.StateListenerReleased
			value.Released = true
		},
		"ambiguous": func(value *controller.RecoverableAssignment) {
			value.Ambiguous = true
			value.AmbiguousReason = "unknown"
		},
		"wrong slot": func(value *controller.RecoverableAssignment) {
			value.Slot.OpaqueName = "pghar-slot-" + strings.Repeat("f", 32)
		},
		"missing adapter": func(value *controller.RecoverableAssignment) {
			value.Slot.AdapterContainerID = ""
		},
		"unexpected upstream": func(value *controller.RecoverableAssignment) {
			value.Slot.UpstreamRunnerID = 9
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := &productionAuthorityStateFixture{}
			recovery := &productionRecoveryFixture{}
			worker, err := newProductionCleanupWorker(
				state,
				recovery,
				strings.Repeat("d", 64),
				17,
				"/var/lib/portable-ghar/broker",
			)
			if err != nil {
				t.Fatalf("newProductionCleanupWorker: %v", err)
			}
			assignment := productionRecoverable(controller.StateRunnerHeld)
			mutate(&assignment)
			if err := worker.ReconcileAssignment(
				context.Background(),
				assignment,
			); err == nil {
				t.Fatal("ReconcileAssignment accepted unsafe state")
			}
			if len(recovery.specs) != 0 ||
				recovery.removals != 0 ||
				len(state.advanced) != 0 {
				t.Fatal("unsafe state crossed a mutation boundary")
			}
		})
	}
}

func TestProductionCleanupWorkerDoesNotAdvanceWithoutRemovalProof(t *testing.T) {
	t.Parallel()

	for name, configure := range map[string]func(*productionRecoveryFixture){
		"inspect": func(fixture *productionRecoveryFixture) {
			fixture.inspectErr = errors.New("inspect failed")
		},
		"remove": func(fixture *productionRecoveryFixture) {
			fixture.removeErr = errors.New("remove failed")
		},
	} {
		configure := configure
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := &productionAuthorityStateFixture{}
			recovery := &productionRecoveryFixture{}
			configure(recovery)
			worker, err := newProductionCleanupWorker(
				state,
				recovery,
				strings.Repeat("d", 64),
				17,
				"/var/lib/portable-ghar/broker",
			)
			if err != nil {
				t.Fatalf("newProductionCleanupWorker: %v", err)
			}
			if err := worker.ReconcileAssignment(
				context.Background(),
				productionRecoverable(controller.StateRunnerHeld),
			); err == nil {
				t.Fatal("ReconcileAssignment accepted unproven cleanup")
			}
			if len(state.advanced) != 0 {
				t.Fatal("assignment advanced without cleanup proof")
			}
		})
	}
}

func TestProductionLocalAuthorityReconcilesRevokesAndProvesZero(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 30, 2, 0, 0, 0, time.UTC)
	assignment := productionRecoverable(controller.StateReceived)
	state := &productionAuthorityStateFixture{
		policy: controller.AcquisitionPolicy{
			Mode:                     controller.AcquisitionDisabled,
			RepositoryPolicyRevision: 1,
			RepositoryPolicies: []controller.RepositoryPolicySummary{{
				Alias:          "repo-a",
				MaxConcurrency: 1,
				Eligibility:    "active",
			}},
			Epoch: 8,
		},
		recoverable: []controller.RecoverableAssignment{assignment},
		marked:      []controller.AssignmentKey{assignment.Key},
	}
	recovery := &productionRecoveryFixture{}
	quiescence := &productionQuiescenceFixture{}
	authority, err := newProductionLocalAuthority(
		productionLocalAuthorityConfig{
			State:       state,
			Recovery:    recovery,
			Quiescence:  quiescence,
			BuildID:     strings.Repeat("d", 64),
			Generation:  17,
			BrokerRoot:  "/var/lib/portable-ghar/broker",
			Timeout:     time.Second,
			Now:         func() time.Time { return now },
			NextCycleID: func() string { return "cycle-1" },
		},
	)
	if err != nil {
		t.Fatalf("newProductionLocalAuthority: %v", err)
	}

	if err := authority.ColdReconcile(context.Background()); err != nil {
		t.Fatalf("ColdReconcile: %v", err)
	}
	if err := authority.RevokePreRunning(context.Background()); err != nil {
		t.Fatalf("RevokePreRunning: %v", err)
	}
	if state.markedEpoch != 9 || !state.markedAt.Equal(now) {
		t.Fatalf(
			"revocation = epoch:%d at:%s, want 9/%s",
			state.markedEpoch,
			state.markedAt,
			now,
		)
	}
	state.mu.Lock()
	state.recoverable = nil
	state.mu.Unlock()
	observation, err := authority.Observe(context.Background())
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !observation.Zero() ||
		observation.Sequence != 1 ||
		!observation.ObservedAt.Equal(now) {
		t.Fatalf("observation = %+v, want complete zero", observation)
	}
	if quiescence.calls != 1 {
		t.Fatalf("quiescence calls = %d, want 1", quiescence.calls)
	}
}

func TestProductionLocalAuthorityObserveFailsClosed(t *testing.T) {
	t.Parallel()

	tests := map[string]func(
		*productionAuthorityStateFixture,
		*productionQuiescenceFixture,
	){
		"recoverable": func(
			state *productionAuthorityStateFixture,
			_ *productionQuiescenceFixture,
		) {
			state.recoverable = []controller.RecoverableAssignment{
				productionRecoverable(controller.StateReceived),
			}
		},
		"running": func(
			state *productionAuthorityStateFixture,
			_ *productionQuiescenceFixture,
		) {
			state.summary.RunningJobs = 1
		},
		"runtime": func(
			_ *productionAuthorityStateFixture,
			quiescence *productionQuiescenceFixture,
		) {
			quiescence.err = errors.New("runtime not empty")
		},
	}
	for name, configure := range tests {
		configure := configure
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := &productionAuthorityStateFixture{
				policy: controller.AcquisitionPolicy{Epoch: 1},
			}
			quiescence := &productionQuiescenceFixture{}
			configure(state, quiescence)
			authority, err := newProductionLocalAuthority(
				productionLocalAuthorityConfig{
					State:       state,
					Recovery:    &productionRecoveryFixture{},
					Quiescence:  quiescence,
					BuildID:     strings.Repeat("d", 64),
					Generation:  17,
					BrokerRoot:  "/var/lib/portable-ghar/broker",
					Timeout:     time.Second,
					Now:         time.Now,
					NextCycleID: func() string { return "cycle-1" },
				},
			)
			if err != nil {
				t.Fatalf("newProductionLocalAuthority: %v", err)
			}
			if observation, err := authority.Observe(
				context.Background(),
			); err == nil || observation != (localObservation{}) {
				t.Fatalf(
					"Observe = (%+v, %v), want closed failure",
					observation,
					err,
				)
			}
		})
	}
}
