package controller

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/health"
	"github.com/sumitake/portable-ghar/internal/observability"
)

const (
	testFleetAlias    = "portable-fleet"
	testHostProfileID = "qts-capless-root"
	testBuildID       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func testDesiredPolicy() AcquisitionPolicy {
	return AcquisitionPolicy{
		Mode:                     AcquisitionEnabled,
		EligibleScaleSets:        []string{"portable-ghar"},
		MaxCapacity:              2,
		RepositoryPolicyRevision: 4,
		RepositoryPolicies: []RepositoryPolicySummary{{
			Alias:          "repo-a",
			MaxConcurrency: 2,
			Eligibility:    "active",
		}},
		Epoch: 7,
	}
}

func testHistoryPressureThresholds() HistoryPressureThresholds {
	return HistoryPressureThresholds{
		WarningHistoryRows:        100,
		StopHistoryRows:           200,
		WarningHistoryBytes:       1_000,
		StopHistoryBytes:          2_000,
		WarningNetworkLedgerRows:  100,
		StopNetworkLedgerRows:     200,
		WarningNetworkLedgerBytes: 1_000,
		StopNetworkLedgerBytes:    2_000,
		WarningMaxCapacity:        1,
	}
}

func testRecoverable(
	requestID int64,
	state State,
	phase AdmissionPhase,
	slotID uint32,
) RecoverableAssignment {
	at := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: requestID,
		JobID:           "opaque-job",
		RepositoryName:  "owner/repository",
		OwnerName:       "owner",
		RequestLabels:   []string{"self-hosted", "portable-ghar"},
		QueueTime:       at,
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: requestID}
	admission := AdmissionReference{
		Key:   key,
		Phase: phase,
	}
	slot := RunnerSlot{}
	if phase != AdmissionQueued {
		admission.SlotID = slotID
		admission.FullCharge = ResourceProjection{MemoryBytes: 3, DurableStateBytes: 2}
		admission.LedgerCharge = ResourceProjection{DurableStateBytes: 2}
		admission.LedgerCreatedAt = at
		admission.LedgerEverUsed = phase == AdmissionActive
	}
	if phase == AdmissionActive {
		slot.CapacitySlotID = slotID
		slot.OpaqueName = "opaque-slot"
	}
	return RecoverableAssignment{
		Key:       key,
		State:     state,
		Offer:     offer,
		Admission: admission,
		Slot:      slot,
		UpdatedAt: at,
	}
}

func TestHistoryStartupRestoresExactProjectionBeforeReady(t *testing.T) {
	trace := &callTrace{}
	state := &fakeDurableState{
		trace: trace,
		recoverable: []RecoverableAssignment{
			testRecoverable(1001, StateReceived, AdmissionQueued, 0),
			testRecoverable(1002, StateCapacityReserved, AdmissionActive, 2),
		},
		uncertain: []UncertainMessageReceipt{{
			RepositoryAlias: "repo-a",
			MessageID:       501,
			Digest:          MessageDigest{1, 2, 3},
			StartedAt:       time.Date(2026, 7, 28, 14, 0, 0, 0, time.UTC),
		}},
	}
	broker := &fakeAdmissionBroker{trace: trace}
	transitions := newFakeTransitioner(trace, testDesiredPolicy())
	terminator := &fakeTerminator{}
	service, err := NewService(ServiceConfig{
		State:                 state,
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            terminator,
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !service.Ready() {
		t.Fatal("service is not ready after successful exact restore")
	}
	if service.UncertainAckCount() != 1 {
		t.Fatalf("UncertainAckCount = %d, want 1", service.UncertainAckCount())
	}
	if terminator.Count() != 0 {
		t.Fatalf("terminator called %d times on successful startup", terminator.Count())
	}

	gotTransitions := transitions.Transitions()
	if len(gotTransitions) != 1 {
		t.Fatalf("transitions = %+v, want startup zero only", gotTransitions)
	}
	if gotTransitions[0].Mode != AcquisitionDisabled ||
		gotTransitions[0].MaxCapacity != 0 ||
		len(gotTransitions[0].EligibleScaleSets) != 0 {
		t.Fatalf("first transition = %+v, want disabled/zero", gotTransitions[0])
	}
	if service.Policy().Epoch != 8 || service.Policy().Mode != AcquisitionDisabled {
		t.Fatalf("ready policy = %+v, want disabled epoch 8", service.Policy())
	}

	restored := broker.Restored()
	if len(restored) != 2 {
		t.Fatalf("restored refs = %+v", restored)
	}
	for i, ref := range restored {
		if ref.Offer.RunnerRequestID != ref.Key.RunnerRequestID ||
			ref.Offer.RepositoryName != "owner/repository" {
			t.Fatalf("restored[%d] lost durable offer: %+v", i, ref)
		}
	}
	if restored[1].Phase != AdmissionActive ||
		restored[1].SlotID != 2 ||
		restored[1].FullCharge != (ResourceProjection{MemoryBytes: 3, DurableStateBytes: 2}) {
		t.Fatalf("active restore = %+v", restored[1])
	}
	if got := trace.Snapshot(); !reflect.DeepEqual(got, []string{
		"transition:disabled",
		"broker:apply:disabled",
		"state:list-recoverable",
		"broker:restore",
		"state:list-uncertain",
	}) {
		t.Fatalf("startup order = %v", got)
	}
}

func TestHistoryStartupCanRetryWhenZeroEpochWasNotPersisted(t *testing.T) {
	transitions := newFakeTransitioner(nil, testDesiredPolicy())
	transitions.errAt = 1
	transitions.err = errors.New("injected pre-zero persistence failure")
	terminator := &fakeTerminator{}
	service, err := NewService(ServiceConfig{
		State:                 &fakeDurableState{},
		Broker:                &fakeAdmissionBroker{},
		Transitions:           transitions,
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            terminator,
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
		Now:                   time.Now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if err := service.Start(context.Background()); !errors.Is(err, ErrStartupRestore) {
		t.Fatalf("first Start err = %v, want ErrStartupRestore", err)
	}
	if service.Ready() {
		t.Fatal("service became ready without a persisted zero epoch")
	}
	if terminator.Count() != 0 {
		t.Fatalf("pre-zero failure called after-persist terminator %d times", terminator.Count())
	}

	transitions.mu.Lock()
	transitions.errAt = 0
	transitions.mu.Unlock()
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("retry Start after pre-zero failure: %v", err)
	}
	if !service.Ready() {
		t.Fatal("service did not become ready after successful zero-and-restore retry")
	}
}

func TestHistoryStartupRejectsMissingProjectionAndTerminatesAfterFatalPersist(t *testing.T) {
	trace := &callTrace{}
	bad := testRecoverable(1101, StateReceived, AdmissionQueued, 0)
	bad.Admission = AdmissionReference{}
	state := &fakeDurableState{
		trace:       trace,
		recoverable: []RecoverableAssignment{bad},
	}
	broker := &fakeAdmissionBroker{trace: trace}
	transitions := newFakeTransitioner(trace, testDesiredPolicy())
	terminator := &fakeTerminator{}
	service, err := NewService(ServiceConfig{
		State:                 state,
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            terminator,
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
		Now:                   time.Now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	err = service.Start(context.Background())
	if !errors.Is(err, ErrStartupRestore) {
		t.Fatalf("Start err = %v, want ErrStartupRestore", err)
	}
	if service.Ready() {
		t.Fatal("service became ready after invalid projection")
	}
	if terminator.Count() != 1 || terminator.LastReason() != ReasonRestoreInvalid {
		t.Fatalf("terminator = (%d, %v), want one restore-invalid call", terminator.Count(), terminator.LastReason())
	}
	if len(broker.Restored()) != 0 {
		t.Fatalf("invalid projection reached broker restore: %+v", broker.Restored())
	}
	gotTransitions := transitions.Transitions()
	if len(gotTransitions) != 2 ||
		gotTransitions[0].Mode != AcquisitionDisabled ||
		gotTransitions[1].Mode != AcquisitionFatal ||
		gotTransitions[1].MaxCapacity != 0 {
		t.Fatalf("failure transitions = %+v, want disabled then fatal/zero", gotTransitions)
	}
}

func TestHistoryStartupTransitionMutexQueuesExplicitEnableUntilRestoreCompletes(t *testing.T) {
	trace := &callTrace{}
	restoreEntered := make(chan struct{})
	restoreRelease := make(chan struct{})
	state := &fakeDurableState{
		trace:       trace,
		recoverable: []RecoverableAssignment{testRecoverable(1201, StateReceived, AdmissionQueued, 0)},
	}
	broker := &fakeAdmissionBroker{
		trace:          trace,
		restoreEntered: restoreEntered,
		restoreRelease: restoreRelease,
	}
	transitions := newFakeTransitioner(trace, testDesiredPolicy())
	service, err := NewService(ServiceConfig{
		State:                 state,
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            &fakeTerminator{},
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
		Now:                   time.Now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	startResult := make(chan error, 1)
	go func() { startResult <- service.Start(context.Background()) }()
	<-restoreEntered

	transitionResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		next := testDesiredPolicy()
		next.Epoch = 8
		_, err := service.Transition(ctx, 8, next)
		transitionResult <- err
	}()
	select {
	case err := <-transitionResult:
		t.Fatalf("Transition escaped startup mutex early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if len(transitions.Transitions()) != 1 {
		t.Fatalf("transition count during blocked restore = %d, want only zero transition", len(transitions.Transitions()))
	}

	close(restoreRelease)
	if err := <-startResult; err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := <-transitionResult; err != nil {
		t.Fatalf("Transition: %v", err)
	}
	gotTransitions := transitions.Transitions()
	if len(gotTransitions) != 2 ||
		gotTransitions[1].Mode != AcquisitionEnabled ||
		gotTransitions[1].MaxCapacity != 2 {
		t.Fatalf("queued transition order = %+v", gotTransitions)
	}
	if got := broker.PressureCalls(); len(got) != 0 {
		t.Fatalf("explicit transition used legacy pressure path: %v", got)
	}
}

func TestHistoryKeySequencerSerializesAndReturnsToBaseline(t *testing.T) {
	sequencer := newKeySequencer()
	for i := int64(1); i <= 1024; i++ {
		release := sequencer.Acquire([]AssignmentKey{
			{RepositoryAlias: "repo-a", RunnerRequestID: i},
			{RepositoryAlias: "repo-a", RunnerRequestID: i},
		})
		release()
	}
	if got := sequencer.Size(); got != 0 {
		t.Fatalf("sequencer retained %d entries after 1024 identities", got)
	}

	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 2001}
	firstRelease := sequencer.Acquire([]AssignmentKey{key})
	secondEntered := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		release := sequencer.Acquire([]AssignmentKey{key})
		close(secondEntered)
		release()
		close(secondDone)
	}()
	select {
	case <-secondEntered:
		t.Fatal("same-key operation entered before first release")
	case <-time.After(25 * time.Millisecond):
	}
	firstRelease()
	<-secondEntered
	<-secondDone
	if got := sequencer.Size(); got != 0 {
		t.Fatalf("sequencer retained %d entries after concurrent release", got)
	}
}

func TestHistoryPressureCountsCompleteHistoryUncertaintyAndIndependentNetworkBudget(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	state := &fakeDurableState{
		uncertain: []UncertainMessageReceipt{{
			RepositoryAlias: "repo-a",
			MessageID:       501,
			Digest:          MessageDigest{1},
			StartedAt:       now.Add(-time.Minute),
		}},
		usage: HistoryUsage{
			LiveRows:                  1,
			LiveLogicalBytes:          10,
			ProtectedTerminalRows:     2,
			ProtectedTerminalBytes:    20,
			MessageReceiptRows:        3,
			MessageReceiptBytes:       30,
			TombstoneRows:             4,
			TombstoneLogicalBytes:     40,
			NetworkLedgerRows:         6,
			NetworkLedgerLogicalBytes: 60,
			InflightAssignments:       7,
			ReservedRows:              5,
			ReservedLogicalBytes:      50,
			OldestRetainedAt:          now.Add(-2 * time.Hour),
		},
	}
	publisher := &fakeHealthPublisher{}
	sink := &fakeEventSink{}
	service := startPressureService(
		t,
		now,
		state,
		&fakeAdmissionBroker{},
		testHistoryPressureThresholds(),
		publisher,
		sink,
	)

	snapshot, err := service.EvaluateHistoryPressure(context.Background())
	if err != nil {
		t.Fatalf("EvaluateHistoryPressure: %v", err)
	}
	if snapshot.Pressure != health.PressureNormal ||
		snapshot.HistoryRows != 15 ||
		snapshot.HistoryLogicalBytes != 150 ||
		snapshot.NetworkLedgerRows != 6 ||
		snapshot.NetworkLedgerLogicalBytes != 60 ||
		snapshot.InflightWork != 7 ||
		snapshot.UncertainAcknowledgements != 1 ||
		snapshot.OldestRetainedAge != 2*time.Hour ||
		snapshot.EffectiveCapacity != 2 {
		t.Fatalf("snapshot = %+v, want complete aggregate budgets", snapshot)
	}
	if got := publisher.Snapshots(); len(got) != 0 {
		t.Fatalf("history evaluation published Worker heartbeat: %+v", got)
	}
	events := sink.Events()
	if len(events) != 1 ||
		events[0].Reasons != observability.PressureReasonNone ||
		events[0].Snapshot != snapshot {
		t.Fatalf("events = %+v, want one exact normal evaluation", events)
	}
}

func TestHistoryPressureWarningLowersThroughEpochBarrier(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	thresholds := testHistoryPressureThresholds()
	thresholds.WarningHistoryRows = 10
	thresholds.StopHistoryRows = 20
	state := &fakeDurableState{usage: HistoryUsage{LiveRows: 10}}
	broker := &fakeAdmissionBroker{}
	publisher := &fakeHealthPublisher{}
	sink := &fakeEventSink{}
	service := startPressureService(t, now, state, broker, thresholds, publisher, sink)

	snapshot, err := service.EvaluateHistoryPressure(context.Background())
	if err != nil {
		t.Fatalf("EvaluateHistoryPressure: %v", err)
	}
	if snapshot.Pressure != health.PressureWarning ||
		snapshot.EffectiveCapacity != 1 ||
		service.Policy().MaxCapacity != 1 ||
		service.Policy().Epoch != 10 {
		t.Fatalf("warning result = snapshot %+v policy %+v", snapshot, service.Policy())
	}
	if got := broker.PressureCalls(); len(got) != 0 {
		t.Fatalf("history pressure used legacy broker pressure path: %v", got)
	}
	events := sink.Events()
	if len(events) != 1 ||
		events[0].Reasons != observability.PressureReasonHistoryRows {
		t.Fatalf("warning events = %+v", events)
	}
}

func TestHistoryPressureStopZerosCapacityAndAllowsActiveDrain(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	thresholds := testHistoryPressureThresholds()
	state := &fakeDurableState{
		usage: HistoryUsage{
			NetworkLedgerLogicalBytes: thresholds.StopNetworkLedgerBytes,
			InflightAssignments:       2,
		},
	}
	broker := &fakeAdmissionBroker{}
	publisher := &fakeHealthPublisher{}
	sink := &fakeEventSink{}
	service, terminator := startPressureServiceWithTerminator(
		t,
		now,
		state,
		broker,
		thresholds,
		publisher,
		sink,
	)

	snapshot, err := service.EvaluateHistoryPressure(context.Background())
	if err != nil {
		t.Fatalf("EvaluateHistoryPressure: %v", err)
	}
	policy := service.Policy()
	if snapshot.Pressure != health.PressureStop ||
		snapshot.EffectiveCapacity != 0 ||
		policy.Mode != AcquisitionDisabled ||
		policy.MaxCapacity != 0 ||
		snapshot.InflightWork != 2 {
		t.Fatalf("stop result = snapshot %+v policy %+v", snapshot, policy)
	}
	if got := broker.PressureCalls(); len(got) != 0 {
		t.Fatalf("history stop used legacy broker pressure path: %v", got)
	}
	if terminator.Count() != 0 {
		t.Fatalf("safe stop terminated active drain: %d calls", terminator.Count())
	}
	events := sink.Events()
	if len(events) != 1 ||
		events[0].Reasons != observability.PressureReasonNetworkLedgerBytes {
		t.Fatalf("stop events = %+v", events)
	}
}

func TestHistoryPressureNeverImplicitlyIncreasesCapacity(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	thresholds := testHistoryPressureThresholds()
	thresholds.WarningHistoryRows = 10
	thresholds.StopHistoryRows = 20
	thresholds.WarningMaxCapacity = 2
	state := &fakeDurableState{usage: HistoryUsage{LiveRows: 10}}
	broker := &fakeAdmissionBroker{}
	service := startPressureService(
		t,
		now,
		state,
		broker,
		thresholds,
		&fakeHealthPublisher{},
		&fakeEventSink{},
	)
	if err := service.ApplyPressure(context.Background(), 1); err != nil {
		t.Fatalf("ApplyPressure: %v", err)
	}

	snapshot, err := service.EvaluateHistoryPressure(context.Background())
	if err != nil {
		t.Fatalf("EvaluateHistoryPressure: %v", err)
	}
	if snapshot.Pressure != health.PressureWarning ||
		snapshot.EffectiveCapacity != 1 ||
		service.Policy().MaxCapacity != 1 {
		t.Fatalf("warning increased prior pressure: snapshot %+v policy %+v", snapshot, service.Policy())
	}
	if got := broker.PressureCalls(); len(got) != 0 {
		t.Fatalf("history pressure used legacy broker pressure path: %v", got)
	}
}

func TestHistoryPressureArithmeticOverflowFailsClosedToStop(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	state := &fakeDurableState{usage: HistoryUsage{
		LiveRows:     math.MaxUint64,
		ReservedRows: 1,
	}}
	broker := &fakeAdmissionBroker{}
	sink := &fakeEventSink{}
	service := startPressureService(
		t,
		now,
		state,
		broker,
		testHistoryPressureThresholds(),
		&fakeHealthPublisher{},
		sink,
	)

	snapshot, err := service.EvaluateHistoryPressure(context.Background())
	if err != nil {
		t.Fatalf("EvaluateHistoryPressure: %v", err)
	}
	if snapshot.Pressure != health.PressureStop ||
		snapshot.HistoryRows != math.MaxUint64 ||
		service.Policy().MaxCapacity != 0 {
		t.Fatalf("overflow result = snapshot %+v policy %+v", snapshot, service.Policy())
	}
	events := sink.Events()
	if len(events) != 1 ||
		events[0].Reasons&observability.PressureReasonArithmeticOverflow == 0 {
		t.Fatalf("overflow events = %+v", events)
	}
}

func TestHistoryPressureUsageReadFailureSafeStopsBeforeReturning(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	state := &fakeDurableState{usageErr: errors.New("injected aggregate read failure")}
	broker := &fakeAdmissionBroker{}
	publisher := &fakeHealthPublisher{}
	sink := &fakeEventSink{}
	service, terminator := startPressureServiceWithTerminator(
		t,
		now,
		state,
		broker,
		testHistoryPressureThresholds(),
		publisher,
		sink,
	)

	if _, err := service.EvaluateHistoryPressure(context.Background()); !errors.Is(err, ErrHistoryPressure) {
		t.Fatalf("EvaluateHistoryPressure err = %v, want ErrHistoryPressure", err)
	}
	if policy := service.Policy(); policy.Mode != AcquisitionDisabled || policy.MaxCapacity != 0 {
		t.Fatalf("usage failure policy = %+v, want disabled/zero", policy)
	}
	if got := broker.PressureCalls(); len(got) != 0 {
		t.Fatalf("usage failure used legacy broker pressure path: %v", got)
	}
	if len(publisher.Snapshots()) != 0 || len(sink.Events()) != 0 {
		t.Fatalf("unmeasured usage published snapshot/event: %+v %+v", publisher.Snapshots(), sink.Events())
	}
	if terminator.Count() != 0 {
		t.Fatalf("measurement safe stop terminated active work: %d calls", terminator.Count())
	}
}

func TestHistoryPressureThresholdsHaveNoConstructorDefaults(t *testing.T) {
	_, err := NewService(ServiceConfig{
		State:                 &fakeDurableState{},
		Broker:                &fakeAdmissionBroker{},
		Transitions:           newFakeTransitioner(nil, testDesiredPolicy()),
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            &fakeTerminator{},
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		Now:                   time.Now,
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
	})
	if !errors.Is(err, ErrServiceNotReady) {
		t.Fatalf("NewService(zero thresholds) err = %v, want ErrServiceNotReady", err)
	}
}

func TestPressureBrokerFailureDoesNotClaimAfterPersistTerminationWhenFatalPersistFails(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 15, 0, 0, time.UTC)
	transitions := newFakeTransitioner(nil, testDesiredPolicy())
	transitions.errAt = 4 // startup zero, restore, pressure, then failed fatal.
	transitions.err = errors.New("injected fatal persistence failure")
	broker := &fakeAdmissionBroker{
		applyErr:   errors.New("injected broker policy failure"),
		applyErrAt: 3,
	}
	terminator := &fakeTerminator{}
	service, err := NewService(ServiceConfig{
		State:                 &fakeDurableState{},
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            terminator,
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		Now:                   func() time.Time { return now },
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	enableServiceForTest(t, service)

	err = service.ApplyPressure(context.Background(), 1)
	if !errors.Is(err, ErrPressureTransition) {
		t.Fatalf("ApplyPressure err = %v, want ErrPressureTransition", err)
	}
	if terminator.Count() != 0 {
		t.Fatalf("terminator called %d times without persisted fatal/zero state", terminator.Count())
	}
	if service.Ready() {
		t.Fatal("service remained ready after broker/persistence divergence")
	}
}

func TestPollPersistAckOrdersEveryDurableBoundaryBeforeAck(t *testing.T) {
	now := time.Date(2026, 7, 28, 17, 0, 0, 0, time.UTC)
	trace := &callTrace{}
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3001,
		JobID:           "job-guid-3001",
		RepositoryName:  "owner/repository",
		OwnerName:       "owner",
		RequestLabels:   []string{"self-hosted", "portable-ghar"},
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3001}
	queued := AdmissionReference{Key: key, Offer: offer, Phase: AdmissionQueued}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{queued},
	}
	events := &fakeEventRecorder{trace: trace}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{
			MessageID: 601,
			Offers:    []githubscale.Offer{offer},
		},
	}
	service, terminator := startPollService(t, now, trace, state, broker, events)
	trace.Reset()

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if got := service.LastMessageID("repo-a"); got != 601 {
		t.Fatalf("LastMessageID = %d, want 601", got)
	}
	if session.AckCount() != 1 || session.LastPollCapacity() != 1 {
		t.Fatalf("session ack/capacity = (%d, %d)", session.AckCount(), session.LastPollCapacity())
	}
	if terminator.Count() != 0 {
		t.Fatalf("terminator called %d times", terminator.Count())
	}
	assertTraceOrder(t, trace.Snapshot(),
		"broker:lease",
		"session:poll",
		"state:receipt",
		"events:record",
		"state:offer",
		"broker:check",
		"state:begin-acquisition",
		"session:acquire",
		"state:complete-acquisition",
		"broker:demand",
		"broker:ensure",
		"state:persist:queued",
		"state:begin-ack",
		"session:ack",
		"state:confirm-ack",
	)
}

func TestPollPersistAckHeadroomRefusalClearsQueuedProjectionWithoutAck(t *testing.T) {
	now := time.Date(2026, 7, 28, 17, 30, 0, 0, time.UTC)
	trace := &callTrace{}
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3101,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureErr: ErrAdmissionHeadroom,
	}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{MessageID: 602, Offers: []githubscale.Offer{offer}},
	}
	service, terminator := startPollService(t, now, trace, state, broker, &fakeEventRecorder{trace: trace})
	trace.Reset()

	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrAdmissionHeadroom) {
		t.Fatalf("PollOnce err = %v, want ErrAdmissionHeadroom", err)
	}
	if session.AckCount() != 0 {
		t.Fatalf("Ack called %d times after headroom refusal", session.AckCount())
	}
	if terminator.Count() != 0 {
		t.Fatalf("normal headroom refusal called terminator %d times", terminator.Count())
	}
	assertTraceOrder(t, trace.Snapshot(),
		"state:complete-acquisition",
		"broker:demand",
		"broker:ensure",
		"state:clear-admission",
	)
	if service.LastMessageID("repo-a") != 0 {
		t.Fatal("headroom refusal advanced message cursor")
	}
}

func TestPollPersistAckUnknownBrokerBatchErrorKeepsProjectionAndEntersFatalState(t *testing.T) {
	now := time.Date(2026, 7, 28, 17, 45, 0, 0, time.UTC)
	trace := &callTrace{}
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3151,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureErr: ErrAdmissionUnavailable,
	}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{MessageID: 6021, Offers: []githubscale.Offer{offer}},
	}
	service, terminator := startPollService(t, now, trace, state, broker, &fakeEventRecorder{trace: trace})
	trace.Reset()

	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrPollFatal) {
		t.Fatalf("PollOnce err = %v, want ErrPollFatal", err)
	}
	if session.AckCount() != 0 {
		t.Fatalf("Ack called %d times after uncertain broker batch failure", session.AckCount())
	}
	if service.Ready() {
		t.Fatal("service remained ready after uncertain broker batch failure")
	}
	if terminator.Count() != 1 || terminator.LastReason() != ReasonProjectionPersist {
		t.Fatalf(
			"terminator = (%d, %v), want one projection-persist call",
			terminator.Count(),
			terminator.LastReason(),
		)
	}
	for _, call := range trace.Snapshot() {
		if call == "state:clear-admission" {
			t.Fatal("uncertain broker batch failure cleared the durable recovery projection")
		}
	}
	if got := service.Policy(); got.Mode != AcquisitionFatal || got.MaxCapacity != 0 {
		t.Fatalf("fatal policy = %+v, want fatal/zero", got)
	}
	if service.LastMessageID("repo-a") != 0 {
		t.Fatal("uncertain broker batch failure advanced message cursor")
	}
}

func TestPollPersistAckPostBrokerProjectionFailurePersistsFatalAndNeverAcks(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	trace := &callTrace{}
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3201,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3201}
	state := &fakeDurableState{
		trace:        trace,
		persistErrAt: 1,
		persistErr:   errors.New("injected exact projection write failure"),
	}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{
			Key:             key,
			Offer:           offer,
			Phase:           AdmissionReserved,
			SlotID:          1,
			FullCharge:      ResourceProjection{MemoryBytes: 3},
			LedgerCharge:    ResourceProjection{},
			LedgerCreatedAt: now,
		}},
	}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{MessageID: 603, Offers: []githubscale.Offer{offer}},
	}
	service, terminator := startPollService(t, now, trace, state, broker, &fakeEventRecorder{trace: trace})
	trace.Reset()

	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrPollFatal) {
		t.Fatalf("PollOnce err = %v, want ErrPollFatal", err)
	}
	if session.AckCount() != 0 {
		t.Fatalf("Ack called %d times after exact projection failure", session.AckCount())
	}
	if service.Ready() {
		t.Fatal("service remained ready after post-broker durable divergence")
	}
	if terminator.Count() != 1 || terminator.LastReason() != ReasonProjectionPersist {
		t.Fatalf("terminator = (%d, %v), want projection-persist", terminator.Count(), terminator.LastReason())
	}
	if got := service.Policy(); got.Mode != AcquisitionFatal || got.MaxCapacity != 0 {
		t.Fatalf("fatal policy = %+v", got)
	}
}

func TestPollPersistAckExactRedeliveryReopensOnlyTheSameUncertainReceipt(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 30, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3301,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3301}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{Key: key, Offer: offer, Phase: AdmissionQueued}},
	}
	session := &fakeSession{
		batch:     githubscale.Batch{MessageID: 604, Offers: []githubscale.Offer{offer}},
		ackErrors: []error{errors.New("injected ack transport failure"), nil},
	}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("first PollOnce err = %v, want ErrAckUncertain", err)
	}
	if service.LastMessageID("repo-a") != 0 || service.UncertainAckCount() != 1 {
		t.Fatalf("after failed Ack cursor/uncertain = (%d, %d)",
			service.LastMessageID("repo-a"), service.UncertainAckCount())
	}
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("redelivery PollOnce: %v", err)
	}
	if state.ObserveCalls() != 1 {
		t.Fatalf("ObserveRedelivery calls = %d, want 1", state.ObserveCalls())
	}
	if service.LastMessageID("repo-a") != 604 || service.UncertainAckCount() != 0 {
		t.Fatalf("after exact redelivery cursor/uncertain = (%d, %d)",
			service.LastMessageID("repo-a"), service.UncertainAckCount())
	}
	if session.AckCount() != 2 {
		t.Fatalf("Ack calls = %d, want 2 authorized attempts", session.AckCount())
	}
}

func TestPollPersistAckNewMessageDoesNotResolveOlderUncertainReceipt(t *testing.T) {
	now := time.Date(2026, 7, 28, 19, 0, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3401,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3401}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{Key: key, Offer: offer, Phase: AdmissionQueued}},
	}
	session := &fakeSession{
		batch:     githubscale.Batch{MessageID: 605, Offers: []githubscale.Offer{offer}},
		ackErrors: []error{errors.New("injected first ack failure"), nil},
	}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("first PollOnce err = %v", err)
	}

	session.SetBatch(githubscale.Batch{MessageID: 606, Offers: []githubscale.Offer{offer}})
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("new-message PollOnce: %v", err)
	}
	if state.ObserveCalls() != 0 {
		t.Fatalf("new message invoked ObserveRedelivery %d times", state.ObserveCalls())
	}
	if service.LastMessageID("repo-a") != 606 || service.UncertainAckCount() != 1 {
		t.Fatalf("new-message cursor/uncertain = (%d, %d), want (606, 1)",
			service.LastMessageID("repo-a"), service.UncertainAckCount())
	}
}

func TestPollPersistAckConfirmationFailureKeepsProtectedUncertainty(t *testing.T) {
	now := time.Date(2026, 7, 28, 19, 30, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3501,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3501}
	state := &fakeDurableState{confirmErr: errors.New("injected confirmation storage failure")}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{Key: key, Offer: offer, Phase: AdmissionQueued}},
	}
	session := &fakeSession{batch: githubscale.Batch{MessageID: 607, Offers: []githubscale.Offer{offer}}}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("PollOnce err = %v, want ErrAckUncertain", err)
	}
	if session.AckCount() != 1 || service.LastMessageID("repo-a") != 0 ||
		service.UncertainAckCount() != 1 {
		t.Fatalf("confirmation failure ack/cursor/uncertain = (%d, %d, %d)",
			session.AckCount(), service.LastMessageID("repo-a"), service.UncertainAckCount())
	}
}

func TestPollAckCancellationReleasesEpochCriticalBeforeTransitionReturns(t *testing.T) {
	now := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3601,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3601}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{Key: key, Offer: offer, Phase: AdmissionQueued}},
	}
	ackEntered := make(chan struct{})
	session := &fakeSession{
		batch:          githubscale.Batch{MessageID: 608, Offers: []githubscale.Offer{offer}},
		ackWaitContext: true,
		ackEntered:     ackEntered,
	}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	service.ackTimeout = 30 * time.Millisecond

	pollResult := make(chan error, 1)
	started := time.Now()
	go func() {
		pollResult <- service.PollOnce(
			context.Background(),
			githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
			session,
		)
	}()
	<-ackEntered
	pressureResult := make(chan error, 1)
	go func() { pressureResult <- service.ApplyPressure(context.Background(), 1) }()
	if err := <-pollResult; !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("PollOnce err = %v, want ErrAckUncertain", err)
	}
	if err := <-pressureResult; err != nil {
		t.Fatalf("ApplyPressure after Ack timeout: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Ack cancellation/join took %v, want bounded below 250ms", elapsed)
	}
	if service.UncertainAckCount() != 1 {
		t.Fatalf("Ack timeout uncertain count = %d, want 1", service.UncertainAckCount())
	}
	if policy := service.Policy(); policy.MaxCapacity != 1 || policy.Epoch != 10 {
		t.Fatalf("post-cancel transition policy = %+v", policy)
	}
}

func TestReplayHostedRoutingUsesStableAssignmentOnlyEffectIdentity(t *testing.T) {
	now := time.Date(2026, 7, 28, 20, 30, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3701,
		RepositoryName:  "owner/repository",
	}}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
	}
	session := &fakeSession{batch: githubscale.Batch{MessageID: 609, Offers: []githubscale.Offer{offer}}}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	service.replay = &fakeReplayVerifier{result: ReplayNotCurrent}
	hosted := &recordingHostedRouter{
		proof: HostedReadinessProof{
			RepositoryAlias:   "repo-a",
			PolicyEpoch:       service.Policy().Epoch,
			ObservedAt:        now,
			ExpiresAt:         now.Add(time.Minute),
			AvailableCapacity: 1,
		},
		resultIdentity: "opaque-hosted-proof",
	}
	service.hosted = hosted

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("first hosted PollOnce: %v", err)
	}
	if hosted.RouteCalls() != 1 || session.AckCount() != 1 {
		t.Fatalf("first hosted route/ack calls = (%d, %d)", hosted.RouteCalls(), session.AckCount())
	}
	firstKey := hosted.LastIdempotencyKey()
	if firstKey == "" {
		t.Fatal("hosted route received empty idempotency key")
	}

	if err := service.ApplyPressure(context.Background(), 1); err != nil {
		t.Fatalf("ApplyPressure: %v", err)
	}
	session.SetBatch(githubscale.Batch{MessageID: 610, Offers: []githubscale.Offer{offer}})
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("later-message hosted PollOnce: %v", err)
	}
	if hosted.RouteCalls() != 1 {
		t.Fatalf("completed hosted effect rerouted externally %d times", hosted.RouteCalls())
	}
	if got := state.LastHostedIdempotencyKey(); got != firstKey {
		t.Fatalf("hosted idempotency key changed across message/policy epoch: %q -> %q", firstKey, got)
	}
	if broker.EnsureCalls() != 0 {
		t.Fatalf("hosted-only offer entered local broker %d times", broker.EnsureCalls())
	}
	if session.AckCount() != 2 {
		t.Fatalf("hosted messages acked %d times, want 2 after durable proof reuse", session.AckCount())
	}
}

func TestReplayHostedReadinessFailureLeavesMessageUnacknowledged(t *testing.T) {
	now := time.Date(2026, 7, 28, 21, 0, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3801,
		RepositoryName:  "owner/repository",
	}}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
	}
	session := &fakeSession{batch: githubscale.Batch{MessageID: 611, Offers: []githubscale.Offer{offer}}}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	service.replay = &fakeReplayVerifier{result: ReplayUnknown}
	hosted := &recordingHostedRouter{
		proof: HostedReadinessProof{
			RepositoryAlias:   "repo-a",
			PolicyEpoch:       service.Policy().Epoch,
			ObservedAt:        now.Add(-time.Hour),
			ExpiresAt:         now.Add(-time.Second),
			AvailableCapacity: 1,
		},
	}
	service.hosted = hosted

	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrHostedUnavailable) {
		t.Fatalf("PollOnce err = %v, want ErrHostedUnavailable", err)
	}
	if session.AckCount() != 0 || hosted.RouteCalls() != 0 {
		t.Fatalf("stale readiness ack/route calls = (%d, %d)", session.AckCount(), hosted.RouteCalls())
	}
	if state.HostedBeginCalls() != 0 {
		t.Fatalf("stale readiness journaled %d hosted intents", state.HostedBeginCalls())
	}
}

func TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged(t *testing.T) {
	now := time.Date(2026, 7, 28, 21, 15, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 3851,
		RepositoryName:  "owner/repository",
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3851}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
	}
	session := &fakeSession{batch: githubscale.Batch{MessageID: 612, Offers: []githubscale.Offer{offer}}}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	service.replay = &fakeReplayVerifier{result: ReplayNotCurrent}
	hosted := &recordingHostedRouter{
		proof: HostedReadinessProof{
			RepositoryAlias:   "repo-a",
			PolicyEpoch:       service.Policy().Epoch,
			ObservedAt:        now,
			ExpiresAt:         now.Add(time.Minute),
			AvailableCapacity: 1,
		},
		routeErr: errors.New("injected explicit hosted rejection"),
	}
	service.hosted = hosted

	for attempt := 0; attempt < 2; attempt++ {
		err := service.PollOnce(
			context.Background(),
			githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
			session,
		)
		if !errors.Is(err, ErrHostedUnavailable) {
			t.Fatalf("PollOnce[%d] err = %v, want ErrHostedUnavailable", attempt, err)
		}
	}
	if session.AckCount() != 0 {
		t.Fatalf("explicit hosted failure acknowledged %d messages", session.AckCount())
	}
	if hosted.RouteCalls() != 1 {
		t.Fatalf("durably failed hosted effect routed %d times, want 1", hosted.RouteCalls())
	}
	effect, err := state.LookupHostedEffect(
		context.Background(),
		key,
		hostedIdempotencyKey(key),
	)
	if err != nil {
		t.Fatalf("LookupHostedEffect: %v", err)
	}
	if effect.State != HostedEffectFailed ||
		effect.Failure != HostedFailureRouteRejected {
		t.Fatalf("failed hosted effect = %+v", effect)
	}
}

func TestReplayHostedEmptyOwnershipProofIsDurableFailure(t *testing.T) {
	now := time.Date(2026, 7, 28, 21, 20, 0, 0, time.UTC)
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3871}
	state := &fakeDurableState{}
	service, _ := startPollService(
		t,
		now,
		nil,
		state,
		&fakeAdmissionBroker{},
		&fakeEventRecorder{},
	)
	service.hosted = &recordingHostedRouter{proof: HostedReadinessProof{
		RepositoryAlias:   "repo-a",
		PolicyEpoch:       service.Policy().Epoch,
		ObservedAt:        now,
		ExpiresAt:         now.Add(time.Minute),
		AvailableCapacity: 1,
	}}

	err := service.routeHostedLocked(
		context.Background(),
		service.Policy(),
		OfferRecord{Key: key, State: StateReceived},
		613,
		HostedReasonReplayUnknown,
	)
	if !errors.Is(err, ErrHostedUnavailable) {
		t.Fatalf("routeHostedLocked err = %v, want ErrHostedUnavailable", err)
	}
	effect, lookupErr := state.LookupHostedEffect(
		context.Background(),
		key,
		hostedIdempotencyKey(key),
	)
	if lookupErr != nil {
		t.Fatalf("LookupHostedEffect: %v", lookupErr)
	}
	if effect.State != HostedEffectFailed ||
		effect.Failure != HostedFailureRouteRejected {
		t.Fatalf("empty-proof hosted effect = %+v", effect)
	}
}

func TestHistoryAdmitOncePersistsExactActiveProjectionAndStableOpaqueName(t *testing.T) {
	now := time.Date(2026, 7, 28, 21, 30, 0, 0, time.UTC)
	trace := &callTrace{}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3901}
	projection := AdmissionReference{
		Key:             key,
		Phase:           AdmissionActive,
		SlotID:          2,
		FullCharge:      ResourceProjection{MemoryBytes: 3, DurableStateBytes: 2},
		LedgerCharge:    ResourceProjection{DurableStateBytes: 2},
		LedgerCreatedAt: now,
		LedgerEverUsed:  true,
	}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		admitDecisions: []AdmissionDecision{{
			Key:        key,
			Projection: projection,
		}},
	}
	service, terminator := startPollService(t, now, trace, state, broker, &fakeEventRecorder{})
	trace.Reset()

	decisions, err := service.AdmitOnce(context.Background())
	if err != nil {
		t.Fatalf("AdmitOnce: %v", err)
	}
	if !reflect.DeepEqual(decisions, broker.admitDecisions) {
		t.Fatalf("AdmitOnce decisions = %+v, want %+v", decisions, broker.admitDecisions)
	}
	reservations := state.Reservations()
	if len(reservations) != 1 ||
		reservations[0].key != key ||
		!reflect.DeepEqual(reservations[0].projection, projection) ||
		reservations[0].opaqueName == "" ||
		reservations[0].opaqueName != opaqueSlotName(key) {
		t.Fatalf("durable reservations = %+v", reservations)
	}
	if terminator.Count() != 0 {
		t.Fatalf("successful admission called terminator %d times", terminator.Count())
	}
	assertTraceOrder(t, trace.Snapshot(), "broker:admit", "state:reserve-active")
}

func TestHistoryAdmitOncePostBrokerFailurePersistsFatal(t *testing.T) {
	now := time.Date(2026, 7, 28, 22, 0, 0, 0, time.UTC)
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 4001}
	state := &fakeDurableState{reserveErr: errors.New("injected active transaction failure")}
	broker := &fakeAdmissionBroker{
		admitDecisions: []AdmissionDecision{{
			Key: key,
			Projection: AdmissionReference{
				Key:             key,
				Phase:           AdmissionActive,
				SlotID:          1,
				LedgerCreatedAt: now,
				LedgerEverUsed:  true,
			},
		}},
	}
	service, terminator := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})

	if _, err := service.AdmitOnce(context.Background()); !errors.Is(err, ErrPollFatal) {
		t.Fatalf("AdmitOnce err = %v, want ErrPollFatal", err)
	}
	if service.Ready() {
		t.Fatal("service remained ready after post-broker active transaction failure")
	}
	if terminator.Count() != 1 || terminator.LastReason() != ReasonActivePersist {
		t.Fatalf("terminator = (%d, %v), want active-persist", terminator.Count(), terminator.LastReason())
	}
}

func TestHistoryAdmitOnceBrokerErrorIsFatalBecauseMutationMayBePartial(t *testing.T) {
	now := time.Date(2026, 7, 28, 21, 45, 0, 0, time.UTC)
	broker := &fakeAdmissionBroker{admitErr: errors.New("injected partial broker admit failure")}
	service, terminator := startPollService(
		t,
		now,
		nil,
		&fakeDurableState{},
		broker,
		&fakeEventRecorder{},
	)

	if _, err := service.AdmitOnce(context.Background()); !errors.Is(err, ErrPollFatal) {
		t.Fatalf("AdmitOnce err = %v, want ErrPollFatal", err)
	}
	if service.Ready() {
		t.Fatal("service remained ready after potentially partial broker admission")
	}
	if terminator.Count() != 1 || terminator.LastReason() != ReasonActivePersist {
		t.Fatalf("terminator = (%d, %v), want one active-persist call", terminator.Count(), terminator.LastReason())
	}
}

func TestHistoryFinalizeTerminalUsesReleaseRetireAbsenceClearBindCompactOrder(t *testing.T) {
	now := time.Date(2026, 7, 28, 22, 30, 0, 0, time.UTC)
	trace := &callTrace{}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 4101}
	ref := AdmissionReference{
		Key:             key,
		Phase:           AdmissionActive,
		SlotID:          1,
		LedgerCreatedAt: now.Add(-time.Hour),
		LedgerEverUsed:  true,
	}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace:            trace,
		reference:        ref,
		referencePresent: true,
		live:             true,
	}
	service, _ := startPollService(t, now, trace, state, broker, &fakeEventRecorder{})
	trace.Reset()

	if err := service.FinalizeTerminal(context.Background(), key, 701, now); err != nil {
		t.Fatalf("FinalizeTerminal: %v", err)
	}
	assertTraceOrder(t, trace.Snapshot(),
		"broker:reference",
		"broker:release",
		"broker:retire",
		"broker:has-live",
		"state:clear-terminal-runtime",
		"state:clear-admission",
		"state:bind-terminal",
		"state:compact-terminal",
	)
	if broker.HasLiveReference(key) {
		t.Fatal("terminal finalization left a live broker reference")
	}
}

func TestHistoryFinalizeTerminalRejectsMismatchedBrokerReference(t *testing.T) {
	now := time.Date(2026, 7, 28, 22, 15, 0, 0, time.UTC)
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 4051}
	broker := &fakeAdmissionBroker{
		reference: AdmissionReference{
			Key:   AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 9999},
			Phase: AdmissionActive,
		},
		referencePresent: true,
		live:             true,
	}
	service, _ := startPollService(
		t,
		now,
		nil,
		&fakeDurableState{},
		broker,
		&fakeEventRecorder{},
	)

	if err := service.FinalizeTerminal(context.Background(), key, 702, now); !errors.Is(err, ErrTerminalFinalize) {
		t.Fatalf("FinalizeTerminal err = %v, want ErrTerminalFinalize", err)
	}
	if !broker.HasLiveReference(key) {
		t.Fatal("mismatched broker reference was mutated")
	}
}

func startPollService(
	t *testing.T,
	now time.Time,
	trace *callTrace,
	state *fakeDurableState,
	broker *fakeAdmissionBroker,
	events *fakeEventRecorder,
) (*Service, *fakeTerminator) {
	t.Helper()
	transitions := newFakeTransitioner(trace, testDesiredPolicy())
	terminator := &fakeTerminator{}
	service, err := NewService(ServiceConfig{
		State:                 state,
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            terminator,
		Events:                events,
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		Now:                   func() time.Time { return now },
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	enableServiceForTest(t, service)
	return service, terminator
}

func startPressureService(
	t *testing.T,
	now time.Time,
	state *fakeDurableState,
	broker *fakeAdmissionBroker,
	thresholds HistoryPressureThresholds,
	publisher *fakeHealthPublisher,
	sink *fakeEventSink,
) *Service {
	t.Helper()
	service, _ := startPressureServiceWithTerminator(
		t,
		now,
		state,
		broker,
		thresholds,
		publisher,
		sink,
	)
	return service
}

func startPressureServiceWithTerminator(
	t *testing.T,
	now time.Time,
	state *fakeDurableState,
	broker *fakeAdmissionBroker,
	thresholds HistoryPressureThresholds,
	publisher *fakeHealthPublisher,
	sink *fakeEventSink,
) (*Service, *fakeTerminator) {
	t.Helper()
	transitions := newFakeTransitioner(nil, testDesiredPolicy())
	terminator := &fakeTerminator{}
	service, err := NewService(ServiceConfig{
		State:                 state,
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               &fakeAcquisitionRevoker{},
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            terminator,
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       thresholds,
		HealthPublisher:       publisher,
		EventSink:             sink,
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		Degraded:              true,
		EnabledPolicyTemplate: testDesiredPolicy(),
		Now:                   func() time.Time { return now },
		AckTimeout:            time.Second,
		OperationTimeout:      time.Second,
		PollCycleTimeout:      5 * time.Second,
		ReconciliationTimeout: time.Second,
		PollCadence:           time.Millisecond,
		ReconciliationCadence: time.Millisecond,
		DrainPollCadence:      time.Millisecond,
		ShutdownTimeout:       time.Second,
		SessionCloseTimeout:   time.Second,
		TransitionJoinTimeout: time.Second,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	enableServiceForTest(t, service)
	return service, terminator
}

func enableServiceForTest(t *testing.T, service *Service) AcquisitionPolicy {
	t.Helper()
	current := service.Policy()
	next := testDesiredPolicy()
	next.Epoch = current.Epoch
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	persisted, err := service.Transition(ctx, current.Epoch, next)
	if err != nil {
		t.Fatalf("enable service: %v", err)
	}
	return persisted
}

func assertTraceOrder(t *testing.T, trace []string, expected ...string) {
	t.Helper()
	cursor := 0
	for _, call := range trace {
		if cursor < len(expected) && call == expected[cursor] {
			cursor++
		}
	}
	if cursor != len(expected) {
		t.Fatalf("trace %v did not contain ordered subsequence %v (matched %d)", trace, expected, cursor)
	}
}

type callTrace struct {
	mu    sync.Mutex
	calls []string
}

func (t *callTrace) Add(call string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls = append(t.calls, call)
}

func (t *callTrace) Snapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.calls...)
}

func (t *callTrace) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls = nil
}

type fakeTransitioner struct {
	mu          sync.Mutex
	trace       *callTrace
	current     AcquisitionPolicy
	transitions []AcquisitionPolicy
	attempts    int
	errAt       int
	err         error
}

func newFakeTransitioner(trace *callTrace, current AcquisitionPolicy) *fakeTransitioner {
	return &fakeTransitioner{trace: trace, current: cloneAcquisitionPolicy(current)}
}

func (f *fakeTransitioner) Snapshot(context.Context) (AcquisitionPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneAcquisitionPolicy(f.current), nil
}

func (f *fakeTransitioner) Transition(
	_ context.Context,
	expectedEpoch uint64,
	next AcquisitionPolicy,
) (AcquisitionPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if expectedEpoch != f.current.Epoch {
		return AcquisitionPolicy{}, errors.New("fake transition epoch mismatch")
	}
	f.attempts++
	if f.attempts == f.errAt {
		return AcquisitionPolicy{}, f.err
	}
	next = cloneAcquisitionPolicy(next)
	next.Epoch = expectedEpoch + 1
	f.current = next
	f.transitions = append(f.transitions, cloneAcquisitionPolicy(next))
	if f.trace != nil {
		f.trace.Add("transition:" + string(next.Mode))
	}
	return cloneAcquisitionPolicy(next), nil
}

func (f *fakeTransitioner) Transitions() []AcquisitionPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]AcquisitionPolicy, len(f.transitions))
	for i := range f.transitions {
		out[i] = cloneAcquisitionPolicy(f.transitions[i])
	}
	return out
}

type fakeTerminator struct {
	mu      sync.Mutex
	reasons []ReasonCode
}

type fakeAcquisitionRevoker struct {
	mu     sync.Mutex
	trace  *callTrace
	epochs []uint64
	keys   [][]AssignmentKey
	err    error
}

func (f *fakeAcquisitionRevoker) RevokePreRunning(
	_ context.Context,
	epoch uint64,
	keys []AssignmentKey,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.trace != nil {
		f.trace.Add("lifecycle:revoke")
	}
	f.epochs = append(f.epochs, epoch)
	f.keys = append(f.keys, append([]AssignmentKey(nil), keys...))
	return f.err
}

type fakeRunningCanceler struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeRunningCanceler) CancelRunning(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeRunningCanceler) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeTerminator) TerminateAfterPersist(reason ReasonCode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reasons = append(f.reasons, reason)
}

func (f *fakeTerminator) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reasons)
}

func (f *fakeTerminator) LastReason() ReasonCode {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reasons) == 0 {
		return 0
	}
	return f.reasons[len(f.reasons)-1]
}

type fakeDurableState struct {
	mu                      sync.Mutex
	trace                   *callTrace
	recoverable             []RecoverableAssignment
	terminalFinalizations   []TerminalFinalization
	terminalFinalizationErr error
	compacted               []AssignmentKey
	compactErr              error
	uncertain               []UncertainMessageReceipt
	persistCalls            int
	persistErrAt            int
	persistErr              error
	messageErr              error
	offerErr                error
	confirmErr              error
	receipts                map[int]MessageReceiptRecord
	observeCalls            int
	effects                 map[string]HostedEffectRecord
	hostedBegins            int
	lastHostedKey           string
	reserveErr              error
	reservations            []fakeReservation
	clearTerminalRuntimeErr error
	clearedTerminalRuntime  []AssignmentKey
	clearAdmissionErr       error
	clearedAdmissions       []AssignmentKey
	usage                   HistoryUsage
	usageErr                error
	promoteErr              error
	promoteCalls            int
	revokeErr               error
	revoked                 []AssignmentKey
	summary                 OperationalSummary
	summaryErr              error
	acquisitionBatches      map[int]AcquisitionBatchRecord
	acquisitionMembers      map[int][]AssignmentKey
	acquisitionOutcomes     map[AssignmentKey]AssignmentAcquisitionRecord
	acquisitionBeginErr     error
	acquisitionAbortErr     error
	acquisitionCompleteErr  error
	acquisitionAmbiguousErr error
}

type fakeReservation struct {
	key        AssignmentKey
	projection AdmissionReference
	opaqueName string
}

func (f *fakeDurableState) RecordMessageReceipt(
	_ context.Context,
	envelope MessageEnvelope,
	_ time.Time,
) (MessageReceiptRecord, error) {
	if f.trace != nil {
		f.trace.Add("state:receipt")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.messageErr != nil {
		return MessageReceiptRecord{}, f.messageErr
	}
	if f.receipts == nil {
		f.receipts = make(map[int]MessageReceiptRecord)
	}
	if record, ok := f.receipts[envelope.MessageID]; ok {
		record.Inserted = false
		return record, nil
	}
	record := MessageReceiptRecord{
		Digest:   MessageDigest{byte(envelope.MessageID), 9},
		State:    MessageAckPersisted,
		Inserted: true,
	}
	f.receipts[envelope.MessageID] = record
	return record, nil
}
func (f *fakeDurableState) RecordOffer(
	_ context.Context,
	alias string,
	offer githubscale.Offer,
	evidence OfferEvidence,
) (OfferRecord, error) {
	if f.trace != nil {
		f.trace.Add("state:offer")
	}
	if f.offerErr != nil {
		return OfferRecord{}, f.offerErr
	}
	key := AssignmentKey{
		RepositoryAlias: alias,
		RunnerRequestID: offer.RunnerRequestID,
	}
	f.mu.Lock()
	if f.acquisitionOutcomes == nil {
		f.acquisitionOutcomes = make(map[AssignmentKey]AssignmentAcquisitionRecord)
	}
	if _, exists := f.acquisitionOutcomes[key]; !exists {
		f.acquisitionOutcomes[key] = AssignmentAcquisitionRecord{
			Key:     key,
			Outcome: AssignmentOffered,
		}
	}
	f.mu.Unlock()
	_ = evidence
	return OfferRecord{
		Key:         key,
		Disposition: OfferInserted,
		State:       StateReceived,
	}, nil
}
func (f *fakeDurableState) BeginAcquisition(
	_ context.Context,
	alias string,
	messageID int,
	keys []AssignmentKey,
	at time.Time,
) (AcquisitionBatchRecord, error) {
	if f.trace != nil {
		f.trace.Add("state:begin-acquisition")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquisitionBeginErr != nil {
		return AcquisitionBatchRecord{}, f.acquisitionBeginErr
	}
	if f.acquisitionBatches == nil {
		f.acquisitionBatches = make(map[int]AcquisitionBatchRecord)
		f.acquisitionMembers = make(map[int][]AssignmentKey)
	}
	if existing, ok := f.acquisitionBatches[messageID]; ok {
		existing.CallAuthorized = false
		existing.Inserted = false
		return existing, nil
	}
	record := AcquisitionBatchRecord{
		RepositoryAlias: alias,
		MessageID:       messageID,
		Status:          AcquisitionBatchBegun,
		RequestedCount:  len(keys),
		BegunAt:         at,
		UpdatedAt:       at,
		Inserted:        true,
		CallAuthorized:  true,
	}
	f.acquisitionBatches[messageID] = record
	f.acquisitionMembers[messageID] = append([]AssignmentKey(nil), keys...)
	for _, key := range keys {
		f.acquisitionOutcomes[key] = AssignmentAcquisitionRecord{
			Key:     key,
			Outcome: AssignmentRequested,
		}
	}
	return record, nil
}
func (f *fakeDurableState) AbortAcquisitionBeforeCall(
	_ context.Context,
	alias string,
	messageID int,
	at time.Time,
) (AcquisitionBatchRecord, error) {
	if f.trace != nil {
		f.trace.Add("state:abort-acquisition")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquisitionAbortErr != nil {
		return AcquisitionBatchRecord{}, f.acquisitionAbortErr
	}
	record := f.acquisitionBatches[messageID]
	record.RepositoryAlias = alias
	record.MessageID = messageID
	record.Status = AcquisitionBatchNotAttempted
	record.UpdatedAt = at
	f.acquisitionBatches[messageID] = record
	for _, key := range f.acquisitionMembers[messageID] {
		f.acquisitionOutcomes[key] = AssignmentAcquisitionRecord{
			Key:     key,
			Outcome: AssignmentOffered,
		}
	}
	return record, nil
}
func (f *fakeDurableState) CompleteAcquisition(
	_ context.Context,
	alias string,
	messageID int,
	acquired []AssignmentKey,
	at time.Time,
) (AcquisitionBatchRecord, error) {
	if f.trace != nil {
		f.trace.Add("state:complete-acquisition")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquisitionCompleteErr != nil {
		return AcquisitionBatchRecord{}, f.acquisitionCompleteErr
	}
	record := f.acquisitionBatches[messageID]
	record.RepositoryAlias = alias
	record.MessageID = messageID
	record.Status = AcquisitionBatchCompleted
	record.AcquiredCount = len(acquired)
	record.UpdatedAt = at
	f.acquisitionBatches[messageID] = record
	acquiredSet := make(map[AssignmentKey]struct{}, len(acquired))
	for _, key := range acquired {
		acquiredSet[key] = struct{}{}
	}
	for _, key := range f.acquisitionMembers[messageID] {
		outcome := AssignmentRejected
		if _, ok := acquiredSet[key]; ok {
			outcome = AssignmentAcquired
		}
		f.acquisitionOutcomes[key] = AssignmentAcquisitionRecord{
			Key:     key,
			Outcome: outcome,
		}
	}
	return record, nil
}
func (f *fakeDurableState) MarkAcquisitionAmbiguous(
	_ context.Context,
	alias string,
	messageID int,
	at time.Time,
) (AcquisitionBatchRecord, error) {
	if f.trace != nil {
		f.trace.Add("state:ambiguous-acquisition")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquisitionAmbiguousErr != nil {
		return AcquisitionBatchRecord{}, f.acquisitionAmbiguousErr
	}
	record := f.acquisitionBatches[messageID]
	record.RepositoryAlias = alias
	record.MessageID = messageID
	record.Status = AcquisitionBatchAmbiguous
	record.UpdatedAt = at
	f.acquisitionBatches[messageID] = record
	return record, nil
}
func (f *fakeDurableState) PromoteBegunAcquisitions(context.Context, time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.promoteCalls++
	return 0, f.promoteErr
}
func (f *fakeDurableState) AcquisitionBatch(
	_ context.Context,
	_ string,
	messageID int,
) (AcquisitionBatchRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if record, ok := f.acquisitionBatches[messageID]; ok {
		return record, nil
	}
	return AcquisitionBatchRecord{}, nil
}
func (f *fakeDurableState) AcquisitionAssignment(
	_ context.Context,
	key AssignmentKey,
) (AssignmentAcquisitionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if record, ok := f.acquisitionOutcomes[key]; ok {
		return record, nil
	}
	return AssignmentAcquisitionRecord{Key: key, Outcome: AssignmentAcquired}, nil
}
func (f *fakeDurableState) MarkPreRunningRevoked(
	context.Context,
	uint64,
	time.Time,
) ([]AssignmentKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]AssignmentKey(nil), f.revoked...), f.revokeErr
}
func (f *fakeDurableState) PersistAdmission(_ context.Context, _ AssignmentKey, ref AdmissionReference) error {
	f.mu.Lock()
	f.persistCalls++
	call := f.persistCalls
	errAt := f.persistErrAt
	err := f.persistErr
	f.mu.Unlock()
	if f.trace != nil {
		f.trace.Add("state:persist:" + admissionPhaseName(ref.Phase))
	}
	if call == errAt {
		return err
	}
	return nil
}
func (f *fakeDurableState) ReserveActive(
	_ context.Context,
	key AssignmentKey,
	projection AdmissionReference,
	opaqueName string,
) error {
	if f.trace != nil {
		f.trace.Add("state:reserve-active")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reserveErr != nil {
		return f.reserveErr
	}
	f.reservations = append(f.reservations, fakeReservation{
		key:        key,
		projection: projection,
		opaqueName: opaqueName,
	})
	return nil
}
func (f *fakeDurableState) ClearAdmission(
	_ context.Context,
	key AssignmentKey,
) error {
	if f.trace != nil {
		f.trace.Add("state:clear-admission")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clearAdmissionErr != nil {
		return f.clearAdmissionErr
	}
	f.clearedAdmissions = append(f.clearedAdmissions, key)
	return nil
}
func (f *fakeDurableState) ClearTerminalRuntime(
	_ context.Context,
	key AssignmentKey,
) error {
	if f.trace != nil {
		f.trace.Add("state:clear-terminal-runtime")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clearTerminalRuntimeErr != nil {
		return f.clearTerminalRuntimeErr
	}
	f.clearedTerminalRuntime = append(f.clearedTerminalRuntime, key)
	return nil
}
func (f *fakeDurableState) LookupHostedEffect(
	_ context.Context,
	_ AssignmentKey,
	key string,
) (HostedEffectRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastHostedKey = key
	if record, ok := f.effects[key]; ok {
		return record, nil
	}
	return HostedEffectRecord{State: HostedEffectAbsent}, nil
}
func (f *fakeDurableState) BeginHostedEffect(
	_ context.Context,
	_ AssignmentKey,
	key string,
) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.effects == nil {
		f.effects = make(map[string]HostedEffectRecord)
	}
	f.lastHostedKey = key
	if _, exists := f.effects[key]; exists {
		return false, nil
	}
	f.effects[key] = HostedEffectRecord{State: HostedEffectPending}
	f.hostedBegins++
	return true, nil
}
func (f *fakeDurableState) CompleteHostedEffect(
	_ context.Context,
	key string,
	proof string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.effects == nil {
		f.effects = make(map[string]HostedEffectRecord)
	}
	f.lastHostedKey = key
	f.effects[key] = HostedEffectRecord{
		State:          HostedEffectCompleted,
		ResultIdentity: proof,
	}
	return nil
}
func (f *fakeDurableState) FailHostedEffect(
	_ context.Context,
	key string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.effects == nil {
		f.effects = make(map[string]HostedEffectRecord)
	}
	f.lastHostedKey = key
	f.effects[key] = HostedEffectRecord{
		State:   HostedEffectFailed,
		Failure: HostedFailureRouteRejected,
	}
	return nil
}
func (f *fakeDurableState) BeginAck(_ context.Context, _ string, messageID int, _ time.Time) error {
	if f.trace != nil {
		f.trace.Add("state:begin-ack")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	record := f.receipts[messageID]
	if record.State != MessageAckPersisted && record.State != MessageAckRedeliveryProven {
		return ErrAckUncertain
	}
	record.State = MessageAckStarted
	f.receipts[messageID] = record
	return nil
}
func (f *fakeDurableState) ConfirmAck(_ context.Context, _ string, messageID int, _ time.Time) error {
	if f.trace != nil {
		f.trace.Add("state:confirm-ack")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.confirmErr != nil {
		return f.confirmErr
	}
	record := f.receipts[messageID]
	record.State = MessageAckConfirmed
	f.receipts[messageID] = record
	return nil
}
func (f *fakeDurableState) ObserveRedelivery(
	_ context.Context,
	_ string,
	messageID int,
	digest MessageDigest,
	_ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record := f.receipts[messageID]
	if record.Digest != digest {
		return errors.New("fake redelivery digest mismatch")
	}
	record.State = MessageAckRedeliveryProven
	f.receipts[messageID] = record
	f.observeCalls++
	return nil
}
func (f *fakeDurableState) ListUncertainAcks(context.Context) ([]UncertainMessageReceipt, error) {
	if f.trace != nil {
		f.trace.Add("state:list-uncertain")
	}
	return append([]UncertainMessageReceipt(nil), f.uncertain...), nil
}
func (f *fakeDurableState) BindTerminalMessage(context.Context, AssignmentKey, int) error {
	if f.trace != nil {
		f.trace.Add("state:bind-terminal")
	}
	return nil
}
func (f *fakeDurableState) Advance(context.Context, AssignmentKey, State) error {
	return nil
}
func (f *fakeDurableState) ListRecoverable(context.Context) ([]RecoverableAssignment, error) {
	if f.trace != nil {
		f.trace.Add("state:list-recoverable")
	}
	return append([]RecoverableAssignment(nil), f.recoverable...), nil
}
func (f *fakeDurableState) ListTerminalFinalizations(context.Context) ([]TerminalFinalization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]TerminalFinalization(nil), f.terminalFinalizations...),
		f.terminalFinalizationErr
}
func (f *fakeDurableState) CompactTerminal(
	_ context.Context,
	key AssignmentKey,
	_ time.Time,
) error {
	if f.trace != nil {
		f.trace.Add("state:compact-terminal")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compacted = append(f.compacted, key)
	return f.compactErr
}
func (f *fakeDurableState) HistoryUsage(context.Context) (HistoryUsage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.usage, f.usageErr
}
func (f *fakeDurableState) OperationalSummary(
	context.Context,
	time.Time,
) (OperationalSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.summary, f.summaryErr
}
func (f *fakeDurableState) ObserveCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.observeCalls
}
func (f *fakeDurableState) HostedBeginCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hostedBegins
}
func (f *fakeDurableState) LastHostedIdempotencyKey() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastHostedKey
}
func (f *fakeDurableState) Reservations() []fakeReservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeReservation(nil), f.reservations...)
}

type fakeAdmissionBroker struct {
	mu               sync.Mutex
	trace            *callTrace
	restored         []AdmissionReference
	restoreEntered   chan struct{}
	restoreRelease   chan struct{}
	pressure         []int
	pressureErr      error
	lease            PollLease
	ensureRefs       []AdmissionReference
	ensureErr        error
	checkErr         error
	ensureCalls      int
	admitDecisions   []AdmissionDecision
	admitErr         error
	reference        AdmissionReference
	referencePresent bool
	live             bool
	appliedPolicies  []AcquisitionPolicy
	applyErr         error
	applyErrAt       int
	applyCalls       int
	capacitySummary  CapacitySummary
	demandCalls      []fakeDemandCall
	demandErr        error
}

type fakeCycleReconciler struct {
	mu      sync.Mutex
	receipt CycleReceipt
	err     error
	calls   int
}

func (f *fakeCycleReconciler) Once(context.Context) (CycleReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.receipt, f.err
}

func (f *fakeCycleReconciler) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeDemandCall struct {
	repositoryAlias string
	epoch           uint64
	total           int
}

func (f *fakeAdmissionBroker) ApplyAcquisitionPolicy(policy AcquisitionPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyCalls++
	f.appliedPolicies = append(f.appliedPolicies, cloneAcquisitionPolicy(policy))
	if f.trace != nil {
		f.trace.Add("broker:apply:" + string(policy.Mode))
	}
	f.capacitySummary.Epoch = policy.Epoch
	f.capacitySummary.EffectiveCapacity = policy.MaxCapacity
	available := policy.MaxCapacity - f.capacitySummary.Occupied
	if available < 0 {
		available = 0
	}
	f.capacitySummary.Available = available
	if f.lease.RepositoryAlias != "" {
		f.lease.Epoch = policy.Epoch
	}
	if f.applyErrAt != 0 && f.applyCalls != f.applyErrAt {
		return nil
	}
	return f.applyErr
}
func (f *fakeAdmissionBroker) SetDemand(
	repositoryAlias string,
	epoch uint64,
	total int,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.demandCalls = append(f.demandCalls, fakeDemandCall{
		repositoryAlias: repositoryAlias,
		epoch:           epoch,
		total:           total,
	})
	if f.trace != nil {
		f.trace.Add("broker:demand")
	}
	return f.demandErr
}
func (f *fakeAdmissionBroker) CapacitySummary() CapacitySummary {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.capacitySummary
}
func (f *fakeAdmissionBroker) CheckOffer(string, githubscale.Offer) error {
	if f.trace != nil {
		f.trace.Add("broker:check")
	}
	return f.checkErr
}
func (f *fakeAdmissionBroker) LeasePoll(string, time.Time) (PollLease, error) {
	if f.trace != nil {
		f.trace.Add("broker:lease")
	}
	return f.lease, nil
}
func (f *fakeAdmissionBroker) EnsureQueuedBatch(
	epoch uint64,
	_ string,
	_ []githubscale.Offer,
) ([]AdmissionReference, error) {
	f.mu.Lock()
	f.ensureCalls++
	currentEpoch := f.capacitySummary.Epoch
	f.mu.Unlock()
	if f.trace != nil {
		f.trace.Add("broker:ensure")
	}
	if epoch != currentEpoch {
		return nil, ErrAdmissionConflict
	}
	return append([]AdmissionReference(nil), f.ensureRefs...), f.ensureErr
}
func (f *fakeAdmissionBroker) Restore(refs []AdmissionReference) error {
	f.mu.Lock()
	f.restored = append([]AdmissionReference(nil), refs...)
	if f.trace != nil {
		f.trace.Add("broker:restore")
	}
	entered := f.restoreEntered
	release := f.restoreRelease
	f.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return nil
}
func (f *fakeAdmissionBroker) Admit(epoch uint64, _ time.Time) ([]AdmissionDecision, error) {
	if f.trace != nil {
		f.trace.Add("broker:admit")
	}
	f.mu.Lock()
	currentEpoch := f.capacitySummary.Epoch
	f.mu.Unlock()
	if epoch != currentEpoch {
		return nil, ErrAdmissionConflict
	}
	return append([]AdmissionDecision(nil), f.admitDecisions...), f.admitErr
}
func (f *fakeAdmissionBroker) Reference(AssignmentKey) (AdmissionReference, bool, error) {
	if f.trace != nil {
		f.trace.Add("broker:reference")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reference, f.referencePresent, nil
}
func (f *fakeAdmissionBroker) SetPressure(max int) (previous, current int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pressure = append(f.pressure, max)
	return 2, max, f.pressureErr
}
func (f *fakeAdmissionBroker) Release(AssignmentKey) error {
	if f.trace != nil {
		f.trace.Add("broker:release")
	}
	return nil
}
func (f *fakeAdmissionBroker) Retire(AssignmentKey) error {
	if f.trace != nil {
		f.trace.Add("broker:retire")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live = false
	f.referencePresent = false
	return nil
}
func (f *fakeAdmissionBroker) HasLiveReference(AssignmentKey) bool {
	if f.trace != nil {
		f.trace.Add("broker:has-live")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live
}
func (f *fakeAdmissionBroker) Restored() []AdmissionReference {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]AdmissionReference(nil), f.restored...)
}
func (f *fakeAdmissionBroker) PressureCalls() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.pressure...)
}

func (f *fakeAdmissionBroker) DemandCalls() []fakeDemandCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeDemandCall(nil), f.demandCalls...)
}
func (f *fakeAdmissionBroker) EnsureCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ensureCalls
}

func admissionPhaseName(phase AdmissionPhase) string {
	switch phase {
	case AdmissionQueued:
		return "queued"
	case AdmissionReserved:
		return "reserved"
	case AdmissionActive:
		return "active"
	default:
		return "invalid"
	}
}

type fakeEventRecorder struct {
	mu    sync.Mutex
	trace *callTrace
	err   error
	calls int
}

type fakeHealthPublisher struct {
	mu        sync.Mutex
	snapshots []health.Snapshot
	err       error
}

func (f *fakeHealthPublisher) Publish(_ context.Context, snapshot health.Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.snapshots = append(f.snapshots, snapshot)
	return nil
}

func (f *fakeHealthPublisher) Snapshots() []health.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]health.Snapshot(nil), f.snapshots...)
}

type fakeEventSink struct {
	mu     sync.Mutex
	events []observability.Event
	err    error
}

func (f *fakeEventSink) Emit(_ context.Context, event observability.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

func (f *fakeEventSink) Events() []observability.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]observability.Event(nil), f.events...)
}

func (f *fakeEventRecorder) RecordBatch(context.Context, MessageEnvelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.trace != nil {
		f.trace.Add("events:record")
	}
	return f.err
}

func (f *fakeEventRecorder) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeReplayVerifier struct {
	result ReplayVerification
	err    error
}

func (f *fakeReplayVerifier) VerifyCurrentOffer(
	context.Context,
	githubscale.Fleet,
	githubscale.Offer,
) (ReplayVerification, error) {
	return f.result, f.err
}

type fakeHostedRouter struct{}

func (*fakeHostedRouter) Readiness(
	context.Context,
	string,
	uint64,
) (HostedReadinessProof, error) {
	return HostedReadinessProof{}, errors.New("unexpected hosted readiness call")
}

func (*fakeHostedRouter) RouteHosted(
	context.Context,
	AssignmentKey,
	string,
	HostedReason,
) (string, error) {
	return "", errors.New("unexpected hosted route call")
}

type fakeSession struct {
	mu                sync.Mutex
	trace             *callTrace
	batch             githubscale.Batch
	pollErr           error
	ackErr            error
	ackErrors         []error
	ackWaitContext    bool
	ackEntered        chan struct{}
	ackCalls          int
	lastPollCapacity  int
	acquiredIDs       []int64
	acquireErr        error
	acquireRequests   [][]int64
	statisticsMissing bool
}

var _ githubscale.Session = (*fakeSession)(nil)

func (*fakeSession) Compatibility() githubscale.ScaleSetCompatibilityReport {
	return githubscale.ScaleSetCompatibilityReport{
		SingleNameLabel: true,
		DisableUpdate:   true,
	}
}

func (f *fakeSession) Poll(_ context.Context, _ int, maxCapacity int) (githubscale.Batch, error) {
	f.mu.Lock()
	f.lastPollCapacity = maxCapacity
	batch := f.batch
	if !batch.Empty && !f.statisticsMissing {
		batch.StatisticsPresent = true
	}
	f.mu.Unlock()
	if f.trace != nil {
		f.trace.Add("session:poll")
	}
	return batch, f.pollErr
}

func (f *fakeSession) Ack(ctx context.Context, _ int) error {
	f.mu.Lock()
	index := f.ackCalls
	f.ackCalls++
	var err error
	if index < len(f.ackErrors) {
		err = f.ackErrors[index]
	} else {
		err = f.ackErr
	}
	wait := f.ackWaitContext
	entered := f.ackEntered
	f.mu.Unlock()
	if f.trace != nil {
		f.trace.Add("session:ack")
	}
	if entered != nil {
		close(entered)
	}
	if wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (f *fakeSession) Acquire(_ context.Context, requestIDs []int64) ([]int64, error) {
	f.mu.Lock()
	f.acquireRequests = append(
		f.acquireRequests,
		append([]int64(nil), requestIDs...),
	)
	acquired := f.acquiredIDs
	if acquired == nil {
		acquired = requestIDs
	}
	err := f.acquireErr
	f.mu.Unlock()
	if f.trace != nil {
		f.trace.Add("session:acquire")
	}
	return append([]int64(nil), acquired...), err
}
func (*fakeSession) GenerateJIT(context.Context, githubscale.JITRequest) (githubscale.JITConfig, error) {
	return githubscale.JITConfig{}, errors.New("unexpected GenerateJIT")
}
func (*fakeSession) GetRunnerByName(context.Context, string) (githubscale.RunnerRef, bool, error) {
	return githubscale.RunnerRef{}, false, errors.New("unexpected GetRunnerByName")
}
func (*fakeSession) GetRunner(context.Context, int64) (githubscale.RunnerRef, bool, error) {
	return githubscale.RunnerRef{}, false, errors.New("unexpected GetRunner")
}
func (*fakeSession) RemoveRunner(context.Context, int64) error {
	return errors.New("unexpected RemoveRunner")
}
func (*fakeSession) Close(context.Context) error { return nil }

func (f *fakeSession) AckCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ackCalls
}

func (f *fakeSession) LastPollCapacity() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastPollCapacity
}

func (f *fakeSession) SetBatch(batch githubscale.Batch) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batch = batch
}

func (f *fakeSession) AcquireRequests() [][]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]int64, len(f.acquireRequests))
	for i := range f.acquireRequests {
		out[i] = append([]int64(nil), f.acquireRequests[i]...)
	}
	return out
}

type recordingHostedRouter struct {
	mu             sync.Mutex
	proof          HostedReadinessProof
	readinessErr   error
	routeErr       error
	resultIdentity string
	routeCalls     int
	lastKey        string
	lastReason     HostedReason
}

func (r *recordingHostedRouter) Readiness(
	context.Context,
	string,
	uint64,
) (HostedReadinessProof, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.proof, r.readinessErr
}

func (r *recordingHostedRouter) RouteHosted(
	_ context.Context,
	_ AssignmentKey,
	key string,
	reason HostedReason,
) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routeCalls++
	r.lastKey = key
	r.lastReason = reason
	return r.resultIdentity, r.routeErr
}

func (r *recordingHostedRouter) RouteCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routeCalls
}

func (r *recordingHostedRouter) LastIdempotencyKey() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastKey
}
