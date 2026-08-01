package controller

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

type task8TransitionFixture struct {
	service     *Service
	state       *fakeDurableState
	broker      *fakeAdmissionBroker
	transitions *fakeTransitioner
	revoker     *fakeAcquisitionRevoker
	terminator  *fakeTerminator
}

type expiringTransitioner struct {
	mu                 sync.Mutex
	current            AcquisitionPolicy
	freshSnapshotProof bool
}

func (t *expiringTransitioner) Snapshot(ctx context.Context) (AcquisitionPolicy, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return AcquisitionPolicy{}, err
	}
	t.freshSnapshotProof = true
	return cloneAcquisitionPolicy(t.current), nil
}

func (t *expiringTransitioner) Transition(
	ctx context.Context,
	_ uint64,
	_ AcquisitionPolicy,
) (AcquisitionPolicy, error) {
	<-ctx.Done()
	return AcquisitionPolicy{}, ctx.Err()
}

func newTask8TransitionFixture(
	t *testing.T,
	joinTimeout time.Duration,
) task8TransitionFixture {
	t.Helper()
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{}
	transitions := newFakeTransitioner(nil, testDesiredPolicy())
	revoker := &fakeAcquisitionRevoker{}
	terminator := &fakeTerminator{}
	service, err := NewService(ServiceConfig{
		State:                 state,
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               revoker,
		RunningCanceler:       &fakeRunningCanceler{},
		Terminator:            terminator,
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		Conformance:           testPassingAcquisitionConformance(),
		HostCapacity:          testNormalHostCapacityProvider{},
		HostCapacityMaxAge:    48 * time.Hour,
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            &fakeCycleReconciler{},
		FleetAlias:            testFleetAlias,
		HostProfileID:         testHostProfileID,
		BuildID:               testBuildID,
		FleetGeneration:       testFleetGeneration,
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
		TransitionJoinTimeout: joinTimeout,
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
	return task8TransitionFixture{
		service:     service,
		state:       state,
		broker:      broker,
		transitions: transitions,
		revoker:     revoker,
		terminator:  terminator,
	}
}

func TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen(t *testing.T) {
	t.Parallel()

	fixture := newTask8TransitionFixture(t, time.Second)
	operationCtx, operationCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer operationCancel()
	operation, err := fixture.service.barrierSnapshot().beginOperation(
		operationCtx,
		"poll",
		"repo-a",
		"portable-ghar",
	)
	if err != nil {
		t.Fatalf("beginOperation: %v", err)
	}
	revokedKey := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 91}
	fixture.state.mu.Lock()
	fixture.state.revoked = []AssignmentKey{revokedKey}
	fixture.state.mu.Unlock()

	current := fixture.service.Policy()
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := fixture.service.Transition(ctx, current.Epoch, next)
		result <- err
	}()

	select {
	case <-operation.Context().Done():
		if !errors.Is(context.Cause(operation.Context()), ErrAcquisitionEpochSuperseded) {
			t.Fatalf("operation cause = %v", context.Cause(operation.Context()))
		}
	case <-time.After(time.Second):
		t.Fatal("transition did not cancel old operation")
	}
	select {
	case err := <-result:
		t.Fatalf("Transition returned before old operation closed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("operation.Close: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if policy := fixture.service.Policy(); policy.Mode != AcquisitionCanaryOnly ||
		policy.Epoch != current.Epoch+1 {
		t.Fatalf("policy = %+v, want canary epoch %d", policy, current.Epoch+1)
	}
	fixture.revoker.mu.Lock()
	lastEpoch := fixture.revoker.epochs[len(fixture.revoker.epochs)-1]
	lastKeys := fixture.revoker.keys[len(fixture.revoker.keys)-1]
	fixture.revoker.mu.Unlock()
	if lastEpoch != current.Epoch+1 ||
		len(lastKeys) != 1 ||
		lastKeys[0] != revokedKey {
		t.Fatalf("revocation = epoch %d keys %+v", lastEpoch, lastKeys)
	}
	if fixture.terminator.Count() != 0 {
		t.Fatalf("terminator called on successful transition: %d", fixture.terminator.Count())
	}
}

func TestServiceTransitionRetiresRevokedBrokerReferenceBeforeOpeningEpoch(
	t *testing.T,
) {
	t.Parallel()

	fixture := newTask8TransitionFixture(t, time.Second)
	trace := &callTrace{}
	fixture.state.trace = trace
	fixture.broker.trace = trace
	fixture.revoker.trace = trace
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 93}
	fixture.state.mu.Lock()
	fixture.state.revoked = []AssignmentKey{key}
	fixture.state.mu.Unlock()
	fixture.broker.mu.Lock()
	fixture.broker.reference = AdmissionReference{
		Key:   key,
		Phase: AdmissionActive,
	}
	fixture.broker.referencePresent = true
	fixture.broker.live = true
	fixture.broker.mu.Unlock()

	current := fixture.service.Policy()
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := fixture.service.Transition(
		ctx,
		current.Epoch,
		next,
	); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if fixture.broker.HasLiveReference(key) {
		t.Fatal("transition left revoked broker reference live")
	}
	fixture.state.mu.Lock()
	cleared := append([]AssignmentKey(nil), fixture.state.clearedAdmissions...)
	fixture.state.mu.Unlock()
	if len(cleared) != 1 || cleared[0] != key {
		t.Fatalf("cleared admissions = %+v, want [%+v]", cleared, key)
	}
	assertTraceOrder(
		t,
		trace.Snapshot(),
		"lifecycle:revoke",
		"broker:release",
		"broker:retire",
		"broker:has-live",
		"state:clear-admission",
	)
}

func TestServiceTransitionFailedCASReopensUnchangedEpoch(t *testing.T) {
	t.Parallel()

	fixture := newTask8TransitionFixture(t, time.Second)
	fixture.transitions.mu.Lock()
	fixture.transitions.errAt = fixture.transitions.attempts + 1
	fixture.transitions.err = errors.New("injected unchanged CAS failure")
	fixture.transitions.mu.Unlock()

	current := fixture.service.Policy()
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := fixture.service.Transition(ctx, current.Epoch, next); !errors.Is(
		err,
		ErrAcquisitionTransition,
	) {
		t.Fatalf("Transition = %v, want ErrAcquisitionTransition", err)
	}
	if !fixture.service.Ready() || !equalAcquisitionPolicy(fixture.service.Policy(), current) {
		t.Fatalf("failed CAS changed service: ready=%v policy=%+v", fixture.service.Ready(), fixture.service.Policy())
	}
	operationCtx, operationCancel := context.WithTimeout(context.Background(), time.Second)
	defer operationCancel()
	operation, err := fixture.service.barrierSnapshot().beginOperation(
		operationCtx,
		"poll",
		"repo-a",
		"portable-ghar",
	)
	if err != nil {
		t.Fatalf("reopened epoch rejected operation: %v", err)
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("operation.Close: %v", err)
	}
	if fixture.terminator.Count() != 0 {
		t.Fatalf("terminator called after unchanged CAS: %d", fixture.terminator.Count())
	}
}

func TestServiceTransitionProvesFailedCASWithFreshBoundedContext(t *testing.T) {
	t.Parallel()

	fixture := newTask8TransitionFixture(t, time.Second)
	current := fixture.service.Policy()
	proof := &expiringTransitioner{current: current}
	fixture.service.transitions = proof
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := fixture.service.Transition(ctx, current.Epoch, next); !errors.Is(
		err,
		ErrAcquisitionTransition,
	) {
		t.Fatalf("Transition = %v, want ErrAcquisitionTransition", err)
	}
	proof.mu.Lock()
	freshSnapshotProof := proof.freshSnapshotProof
	proof.mu.Unlock()
	if !freshSnapshotProof {
		t.Fatal("failed CAS did not use a fresh context for unchanged-state proof")
	}
	if !fixture.service.Ready() ||
		!equalAcquisitionPolicy(fixture.service.Policy(), current) {
		t.Fatalf(
			"failed CAS changed service: ready=%v policy=%+v",
			fixture.service.Ready(),
			fixture.service.Policy(),
		)
	}
}

func TestValidatePersistedAcquisitionTransitionRejectsEpochOverflow(t *testing.T) {
	t.Parallel()

	request := testDesiredPolicy()
	request.Epoch = math.MaxUint64
	persisted := cloneAcquisitionPolicy(request)
	persisted.Epoch = 0
	if _, err := validatePersistedAcquisitionTransition(
		math.MaxUint64,
		request,
		persisted,
	); !errors.Is(err, ErrAcquisitionEpochMismatch) {
		t.Fatalf("overflow validation = %v, want ErrAcquisitionEpochMismatch", err)
	}
}

func TestServiceDisabledTransitionRequiresListenerQuiescence(t *testing.T) {
	t.Parallel()

	fixture := newTask8TransitionFixture(t, time.Second)
	fixture.state.mu.Lock()
	fixture.state.summary.UnassignedReleasedListeners = 1
	fixture.state.mu.Unlock()

	current := fixture.service.Policy()
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionDisabled
	next.MaxCapacity = 0
	next.EligibleScaleSets = nil
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := fixture.service.Transition(ctx, current.Epoch, next); !errors.Is(
		err,
		ErrAcquisitionTransition,
	) {
		t.Fatalf("Transition = %v, want ErrAcquisitionTransition", err)
	}
	if fixture.service.Ready() {
		t.Fatal("service remained ready without listener quiescence")
	}
	if policy := fixture.service.Policy(); policy.Mode != AcquisitionFatal ||
		policy.MaxCapacity != 0 ||
		policy.Epoch != current.Epoch+2 {
		t.Fatalf("fatal policy = %+v", policy)
	}
	if fixture.terminator.Count() != 1 ||
		fixture.terminator.LastReason() != ReasonAcquisitionQuiescence {
		t.Fatalf("terminator = (%d,%v)", fixture.terminator.Count(), fixture.terminator.LastReason())
	}
}

func TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination(t *testing.T) {
	t.Parallel()

	fixture := newTask8TransitionFixture(t, 25*time.Millisecond)
	operationCtx, operationCancel := context.WithTimeout(context.Background(), time.Second)
	defer operationCancel()
	operation, err := fixture.service.barrierSnapshot().beginOperation(
		operationCtx,
		"poll",
		"repo-a",
		"portable-ghar",
	)
	if err != nil {
		t.Fatalf("beginOperation: %v", err)
	}
	current := fixture.service.Policy()
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := fixture.service.Transition(ctx, current.Epoch, next); !errors.Is(
		err,
		ErrAcquisitionTransition,
	) {
		t.Fatalf("Transition = %v, want ErrAcquisitionTransition", err)
	}
	if fixture.terminator.Count() != 1 ||
		fixture.terminator.LastReason() != ReasonAcquisitionJoin {
		t.Fatalf("terminator = (%d,%v)", fixture.terminator.Count(), fixture.terminator.LastReason())
	}
	if policy := fixture.service.Policy(); policy.Mode != AcquisitionFatal {
		t.Fatalf("policy = %+v, want fatal", policy)
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("operation.Close after termination: %v", err)
	}
}
