package controller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

type runtimeSession struct {
	*fakeSession

	pollOnce        sync.Once
	pollEntered     chan struct{}
	pollWaitContext bool

	closeMu    sync.Mutex
	closeCalls int
	closeErr   error
}

func (s *runtimeSession) Poll(
	ctx context.Context,
	_ int,
	maxCapacity int,
) (githubscale.Batch, error) {
	s.fakeSession.mu.Lock()
	s.fakeSession.lastPollCapacity = maxCapacity
	s.fakeSession.mu.Unlock()
	if s.pollEntered != nil {
		s.pollOnce.Do(func() { close(s.pollEntered) })
	}
	if s.pollWaitContext {
		<-ctx.Done()
		return githubscale.Batch{}, ctx.Err()
	}
	return githubscale.Batch{Empty: true}, nil
}

func (s *runtimeSession) Close(context.Context) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.closeCalls++
	return s.closeErr
}

func (s *runtimeSession) CloseCalls() int {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeCalls
}

type runtimeServiceFixture struct {
	service     *Service
	state       *fakeDurableState
	broker      *fakeAdmissionBroker
	transitions *fakeTransitioner
	revoker     *fakeAcquisitionRevoker
	canceler    *fakeRunningCanceler
	terminator  *fakeTerminator
	session     *runtimeSession
	now         time.Time
}

type blockingRuntimeReconciler struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingRuntimeReconciler) Once(context.Context) (CycleReceipt, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return CycleReceipt{}, context.Canceled
}

func newRuntimeServiceFixture(
	t *testing.T,
	session *runtimeSession,
	restoreEntered chan struct{},
	restoreRelease chan struct{},
) runtimeServiceFixture {
	t.Helper()
	now := time.Date(2026, 7, 28, 23, 30, 0, 0, time.UTC)
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		restoreEntered: restoreEntered,
		restoreRelease: restoreRelease,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			PollCapacity:    0,
			ExpiresAt:       now.Add(time.Hour),
		},
		capacitySummary: CapacitySummary{ConfiguredCapacity: 2},
	}
	transitions := newFakeTransitioner(nil, testDesiredPolicy())
	revoker := &fakeAcquisitionRevoker{}
	canceler := &fakeRunningCanceler{}
	terminator := &fakeTerminator{}
	reconciler := &fakeCycleReconciler{receipt: CycleReceipt{
		CycleID:     "runtime-cycle",
		CompletedAt: now.Add(-time.Second),
	}}
	config := ServiceConfig{
		State:                 state,
		Broker:                broker,
		Transitions:           transitions,
		Revoker:               revoker,
		RunningCanceler:       canceler,
		Terminator:            terminator,
		Events:                &fakeEventRecorder{},
		Replay:                &fakeReplayVerifier{result: ReplayCurrent},
		Hosted:                &fakeHostedRouter{},
		FleetGuards:           canonicalFleetGuardProviderStub{},
		Permits:               canonicalPermitProviderStub{},
		HistoryPressure:       testHistoryPressureThresholds(),
		HealthPublisher:       &fakeHealthPublisher{},
		EventSink:             &fakeEventSink{},
		Reconciler:            reconciler,
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
		TransitionJoinTimeout: 250 * time.Millisecond,
		DurableFinishTimeout:  time.Second,
		ReplayEvidenceMaxAge:  time.Hour,
	}
	if session != nil {
		config.PollTargets = []PollTarget{{
			Fleet: githubscale.Fleet{
				RepositoryAlias: "repo-a",
				ScaleSetName:    "portable-ghar",
			},
			Session: session,
		}}
	}
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	return runtimeServiceFixture{
		service:     service,
		state:       state,
		broker:      broker,
		transitions: transitions,
		revoker:     revoker,
		canceler:    canceler,
		terminator:  terminator,
		session:     session,
		now:         now,
	}
}

func TestServiceStartRetiresMarkedBrokerReferencesBeforeReady(t *testing.T) {
	t.Parallel()

	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	trace := &callTrace{}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 7051}
	fixture.state.trace = trace
	fixture.state.mu.Lock()
	fixture.state.revoked = []AssignmentKey{key}
	fixture.state.mu.Unlock()
	fixture.broker.trace = trace
	fixture.broker.mu.Lock()
	fixture.broker.reference = AdmissionReference{
		Key:   key,
		Phase: AdmissionQueued,
	}
	fixture.broker.referencePresent = true
	fixture.broker.live = true
	fixture.broker.mu.Unlock()
	fixture.revoker.trace = trace

	if err := fixture.service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !fixture.service.Ready() || fixture.broker.HasLiveReference(key) {
		t.Fatalf(
			"startup readiness/live reference = (%v,%v), want (true,false)",
			fixture.service.Ready(),
			fixture.broker.HasLiveReference(key),
		)
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
		"broker:retire",
		"broker:has-live",
		"state:clear-admission",
	)
}

func TestRuntimeRunCompletesRecoveryBeforePollAndDisablesBeforeClose(
	t *testing.T,
) {
	restoreEntered := make(chan struct{})
	restoreRelease := make(chan struct{})
	session := &runtimeSession{
		fakeSession:     &fakeSession{},
		pollEntered:     make(chan struct{}),
		pollWaitContext: true,
	}
	fixture := newRuntimeServiceFixture(
		t,
		session,
		restoreEntered,
		restoreRelease,
	)
	runCtx, cancelRun := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- fixture.service.Run(runCtx) }()

	select {
	case <-restoreEntered:
	case <-time.After(time.Second):
		t.Fatal("startup did not enter durable restore")
	}
	select {
	case <-session.pollEntered:
		t.Fatal("poll began before cold recovery completed")
	case <-time.After(20 * time.Millisecond):
	}

	close(restoreRelease)
	select {
	case <-session.pollEntered:
	case <-time.After(time.Second):
		t.Fatal("poll did not start after cold recovery")
	}
	cancelRun()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not complete bounded shutdown")
	}

	transitions := fixture.transitions.Transitions()
	if len(transitions) != 2 ||
		transitions[0].Mode != AcquisitionDisabled ||
		transitions[1].Mode != AcquisitionDisabled ||
		transitions[1].Epoch != transitions[0].Epoch+1 {
		t.Fatalf("runtime transitions = %+v, want newer disabled shutdown epoch", transitions)
	}
	if fixture.state.promoteCalls != 1 {
		t.Fatalf("begun promotion calls = %d, want 1", fixture.state.promoteCalls)
	}
	if session.CloseCalls() != 1 {
		t.Fatalf("session close calls = %d, want 1", session.CloseCalls())
	}
	if fixture.terminator.Count() != 0 {
		t.Fatalf("graceful runtime invoked terminator %d times", fixture.terminator.Count())
	}
}

func TestRuntimeSetAcquisitionUsesExactExpectedModeAndClosedStatus(
	t *testing.T,
) {
	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	if err := fixture.service.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	enableServiceForTest(t, fixture.service)

	status, err := fixture.service.SetAcquisition(
		context.Background(),
		AcquisitionChange{
			Set:              AcquisitionCanaryOnly,
			Expected:         AcquisitionEnabled,
			EligibleScaleSet: "portable-ghar",
		},
	)
	if err != nil {
		t.Fatalf("SetAcquisition(canary) = %v", err)
	}
	if status.Mode != AcquisitionCanaryOnly ||
		status.Capacity != 1 ||
		status.Epoch != fixture.service.Policy().Epoch {
		t.Fatalf("canary status = %+v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Marshal(status) = %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal(status) = %v", err)
	}
	if got := sortedStringKeys(fields); !reflect.DeepEqual(
		got,
		[]string{"capacity", "digest", "epoch", "mode"},
	) {
		t.Fatalf("PolicyStatus keys = %v", got)
	}
	if _, err := fixture.service.SetAcquisition(
		context.Background(),
		AcquisitionChange{
			Set:      AcquisitionDisabled,
			Expected: AcquisitionEnabled,
		},
	); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("stale expected mode error = %v, want ErrAdminConflict", err)
	}
	if _, err := fixture.service.SetAcquisition(
		context.Background(),
		AcquisitionChange{
			Set:              AcquisitionEnabled,
			Expected:         AcquisitionCanaryOnly,
			EligibleScaleSet: "portable-ghar",
		},
	); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabled eligible override error = %v, want ErrAdminConflict", err)
	}
}

func TestRuntimeDrainWaitAndCancelUseDistinctRunningPolicy(t *testing.T) {
	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	if err := fixture.service.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	enableServiceForTest(t, fixture.service)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := fixture.service.Drain(ctx, DrainWait); err != nil {
		t.Fatalf("Drain(wait) = %v", err)
	}
	if fixture.canceler.Calls() != 0 {
		t.Fatalf("Drain(wait) cancel calls = %d, want 0", fixture.canceler.Calls())
	}
	enableServiceForTest(t, fixture.service)
	if err := fixture.service.Drain(ctx, DrainCancel); err != nil {
		t.Fatalf("Drain(cancel) = %v", err)
	}
	if fixture.canceler.Calls() != 1 {
		t.Fatalf("Drain(cancel) cancel calls = %d, want 1", fixture.canceler.Calls())
	}
	if fixture.service.Policy().Mode != AcquisitionDisabled {
		t.Fatalf("drained policy = %+v", fixture.service.Policy())
	}
}

func TestRuntimeUnjoinableCentralLoopPersistsFatalBeforeTermination(
	t *testing.T,
) {
	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	reconciler := &blockingRuntimeReconciler{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	fixture.service.reconciler = reconciler
	fixture.service.shutdownTimeout = 25 * time.Millisecond

	runCtx, cancelRun := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- fixture.service.Run(runCtx) }()

	select {
	case <-reconciler.entered:
	case <-time.After(time.Second):
		t.Fatal("central loop did not enter reconciliation")
	}
	cancelRun()

	select {
	case err := <-result:
		if !errors.Is(err, ErrPollFatal) ||
			!errors.Is(err, ErrRuntimeShutdown) {
			t.Fatalf(
				"Run() = %v, want ErrPollFatal and ErrRuntimeShutdown",
				err,
			)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() hung on an unjoinable central loop")
	}
	if fixture.service.Ready() {
		t.Fatal("runtime remained ready after unjoinable-loop fatal")
	}
	if policy := fixture.service.Policy(); policy.Mode != AcquisitionFatal {
		t.Fatalf("policy = %+v, want fatal", policy)
	}
	if fixture.terminator.Count() != 1 ||
		fixture.terminator.LastReason() != ReasonAcquisitionJoin {
		t.Fatalf(
			"terminator = (%d,%d), want one ReasonAcquisitionJoin",
			fixture.terminator.Count(),
			fixture.terminator.LastReason(),
		)
	}
	close(reconciler.release)
}

func sortedStringKeys(input map[string]any) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
