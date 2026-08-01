package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/health"
)

type reconcileServiceFixture struct {
	service    *Service
	state      *fakeDurableState
	broker     *fakeAdmissionBroker
	reconciler *fakeCycleReconciler
	publisher  *fakeHealthPublisher
	terminator *fakeTerminator
	now        time.Time
}

func newReconcileServiceFixture(t *testing.T) reconcileServiceFixture {
	t.Helper()
	now := time.Date(2026, 7, 28, 19, 0, 0, 0, time.UTC)
	state := &fakeDurableState{
		summary: OperationalSummary{
			AssignedJobs:                2,
			RunningJobs:                 1,
			OldestLiveAssignmentAge:     3 * time.Minute,
			UnassignedReleasedListeners: 0,
			LatestTerminalAt:            now.Add(-5 * time.Minute),
		},
	}
	broker := &fakeAdmissionBroker{
		capacitySummary: CapacitySummary{ConfiguredCapacity: 4},
	}
	publisher := &fakeHealthPublisher{}
	service, terminator := startPressureServiceWithTerminator(
		t,
		now,
		state,
		broker,
		testHistoryPressureThresholds(),
		publisher,
		&fakeEventSink{},
	)
	current := service.Policy()
	broker.mu.Lock()
	broker.capacitySummary = CapacitySummary{
		Epoch:              current.Epoch,
		ConfiguredCapacity: 4,
		EffectiveCapacity:  current.MaxCapacity,
		Occupied:           1,
		Available:          current.MaxCapacity - 1,
		Queued:             3,
	}
	broker.mu.Unlock()
	reconciler := &fakeCycleReconciler{
		receipt: CycleReceipt{
			CycleID:         "cycle-task8-1",
			CompletedAt:     now.Add(-time.Second),
			AssignmentCount: 2,
			OldestAge:       3 * time.Minute,
		},
	}
	service.reconciler = reconciler
	return reconcileServiceFixture{
		service:    service,
		state:      state,
		broker:     broker,
		reconciler: reconciler,
		publisher:  publisher,
		terminator: terminator,
		now:        now,
	}
}

func TestServiceReconcileOnceFinalizesStableOrderThenPublishesHeartbeat(t *testing.T) {
	t.Parallel()

	fixture := newReconcileServiceFixture(t)
	first := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 10}
	second := AssignmentKey{RepositoryAlias: "repo-b", RunnerRequestID: 2}
	fixture.state.terminalFinalizations = []TerminalFinalization{
		{Key: second, MessageID: 92, At: fixture.now.Add(-2 * time.Minute)},
		{Key: first, MessageID: 91, At: fixture.now.Add(-time.Minute)},
	}

	receipt, err := fixture.service.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if receipt != fixture.reconciler.receipt {
		t.Fatalf("receipt = %+v, want %+v", receipt, fixture.reconciler.receipt)
	}
	fixture.state.mu.Lock()
	compacted := append([]AssignmentKey(nil), fixture.state.compacted...)
	fixture.state.mu.Unlock()
	if !reflect.DeepEqual(compacted, []AssignmentKey{first, second}) {
		t.Fatalf("compaction order = %+v", compacted)
	}
	snapshots := fixture.publisher.Snapshots()
	if len(snapshots) != 1 {
		t.Fatalf("heartbeat count = %d, want 1", len(snapshots))
	}
	policy := fixture.service.Policy()
	digest, err := AcquisitionPolicyDigest(policy)
	if err != nil {
		t.Fatalf("AcquisitionPolicyDigest: %v", err)
	}
	want := health.Snapshot{
		ObservedAt:               fixture.now,
		FleetAlias:               testFleetAlias,
		AcquisitionMode:          health.AcquisitionEnabled,
		PolicyEpoch:              policy.Epoch,
		PolicyDigest:             hex.EncodeToString(digest[:]),
		RepositoryPolicyRevision: policy.RepositoryPolicyRevision,
		Capacity: health.CapacitySummary{
			Configured: 4,
			Effective:  policy.MaxCapacity,
			Occupied:   1,
			Available:  policy.MaxCapacity - 1,
			Queued:     3,
		},
		AssignedJobs:                2,
		RunningJobs:                 1,
		OldestLiveAssignmentAge:     3 * time.Minute,
		UnassignedReleasedListeners: 0,
		LastTerminalAt:              fixture.now.Add(-time.Minute),
		HostProfileID:               testHostProfileID,
		Degraded:                    true,
		BuildID:                     testBuildID,
	}
	if !reflect.DeepEqual(snapshots[0], want) {
		t.Fatalf("heartbeat = %+v, want %+v", snapshots[0], want)
	}
}

func TestServiceReconcileOnceFailureReturnsNoReceiptOrHeartbeat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject func(*reconcileServiceFixture)
	}{
		{
			name: "lifecycle cycle",
			inject: func(fixture *reconcileServiceFixture) {
				fixture.reconciler.err = errors.New("injected lifecycle failure")
			},
		},
		{
			name: "terminal list",
			inject: func(fixture *reconcileServiceFixture) {
				fixture.state.terminalFinalizationErr = errors.New("injected terminal read failure")
			},
		},
		{
			name: "terminal finalizer",
			inject: func(fixture *reconcileServiceFixture) {
				fixture.state.terminalFinalizations = []TerminalFinalization{{
					Key:       AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 1},
					MessageID: 10,
					At:        fixture.now.Add(-time.Second),
				}}
				fixture.state.compactErr = errors.New("injected compaction failure")
			},
		},
		{
			name: "summary",
			inject: func(fixture *reconcileServiceFixture) {
				fixture.state.summaryErr = errors.New("injected summary failure")
			},
		},
		{
			name: "capacity identity",
			inject: func(fixture *reconcileServiceFixture) {
				fixture.broker.mu.Lock()
				fixture.broker.capacitySummary.Epoch++
				fixture.broker.mu.Unlock()
			},
		},
		{
			name: "publish",
			inject: func(fixture *reconcileServiceFixture) {
				fixture.publisher.err = errors.New("injected publish failure")
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReconcileServiceFixture(t)
			test.inject(&fixture)
			receipt, err := fixture.service.ReconcileOnce(context.Background())
			if !errors.Is(err, ErrReconciliation) {
				t.Fatalf("ReconcileOnce = (%+v, %v), want ErrReconciliation", receipt, err)
			}
			if receipt != (CycleReceipt{}) {
				t.Fatalf("failure receipt = %+v", receipt)
			}
			if snapshots := fixture.publisher.Snapshots(); len(snapshots) != 0 {
				t.Fatalf("failure published heartbeat %+v", snapshots)
			}
		})
	}
}

func TestServiceReconcileOnceJITFatalPersistsFatalBeforeTermination(t *testing.T) {
	t.Parallel()

	fixture := newReconcileServiceFixture(t)
	fixture.reconciler.err = errors.Join(ErrReconciliation, ErrJITFatal)
	receipt, err := fixture.service.ReconcileOnce(context.Background())
	if !errors.Is(err, ErrPollFatal) {
		t.Fatalf("ReconcileOnce = (%+v, %v), want ErrPollFatal", receipt, err)
	}
	if receipt != (CycleReceipt{}) {
		t.Fatalf("fatal receipt = %+v", receipt)
	}
	if fixture.service.Ready() {
		t.Fatal("service remained ready after fatal JIT reconciliation")
	}
	if fixture.service.Policy().Mode != AcquisitionFatal ||
		fixture.terminator.Count() != 1 ||
		fixture.terminator.LastReason() != ReasonAcquisitionJoin {
		t.Fatalf(
			"fatal state = policy %+v terminator (%d,%d)",
			fixture.service.Policy(),
			fixture.terminator.Count(),
			fixture.terminator.LastReason(),
		)
	}
	if len(fixture.publisher.Snapshots()) != 0 {
		t.Fatal("fatal reconciliation published a heartbeat")
	}
}
