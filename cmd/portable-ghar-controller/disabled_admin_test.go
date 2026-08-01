package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

func TestDisabledAdminInitializesBeforeProbeReadiness(t *testing.T) {
	fixture := newDisabledAdminFixture(t)
	if _, err := fixture.service.Probe(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("pre-initialize Probe() error = %v", err)
	}
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	status, err := fixture.service.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if status.Mode != controller.AcquisitionDisabled ||
		status.Epoch != 5 ||
		status.Capacity != 0 ||
		len(status.Digest) != 64 {
		t.Fatalf("Probe() = %#v", status)
	}
	if fixture.authority.ColdCalls() != 1 {
		t.Fatalf(
			"ColdReconcile calls = %d, want 1",
			fixture.authority.ColdCalls(),
		)
	}
	if fixture.socketProofCalls != 2 {
		t.Fatalf(
			"socket proof calls = %d, want startup+probe 2",
			fixture.socketProofCalls,
		)
	}
}

func TestDisabledAdminPrepareProvesAuthorityBeforeSocketActivation(
	t *testing.T,
) {
	fixture := newDisabledAdminFixture(t)
	fixture.SetSocketProofError(errors.New("sockets not created"))
	if err := fixture.service.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if _, err := fixture.service.Probe(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Probe() before Activate error = %v", err)
	}
	fixture.SetSocketProofError(nil)
	if err := fixture.service.Activate(context.Background()); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	status, err := fixture.service.Probe(context.Background())
	if err != nil ||
		status.Mode != controller.AcquisitionDisabled ||
		status.Epoch != 5 ||
		status.Capacity != 0 {
		t.Fatalf("Probe() after Activate = (%#v, %v)", status, err)
	}
}

func TestDisabledAdminRejectsIncompleteStartupProjection(t *testing.T) {
	fixture := newDisabledAdminFixture(t)
	observation := fixture.authority.Observation()
	observation.Runners = 1
	fixture.authority.SetObservation(observation)
	if err := fixture.service.Initialize(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Initialize() error = %v", err)
	}
	if _, err := fixture.service.Probe(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Probe() after failed startup error = %v", err)
	}
}

func TestDisabledAdminAllowsOnlyExactDisabledToDisabledCAS(t *testing.T) {
	fixture := newDisabledAdminFixture(t)
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	before := fixture.transitions.TransitionCount()
	if _, err := fixture.service.SetAcquisition(
		context.Background(),
		controller.AcquisitionChange{
			Set:              controller.AcquisitionCanaryOnly,
			Expected:         controller.AcquisitionDisabled,
			EligibleScaleSet: "scale-a",
		},
	); !errors.Is(err, controller.ErrRuntimeUnavailable) {
		t.Fatalf("SetAcquisition(nonzero) error = %v", err)
	}
	if fixture.transitions.TransitionCount() != before {
		t.Fatal("nonzero SetAcquisition mutated policy")
	}
	if _, err := fixture.service.SetAcquisition(
		context.Background(),
		controller.AcquisitionChange{
			Set:      controller.AcquisitionDisabled,
			Expected: controller.AcquisitionEnabled,
		},
	); !errors.Is(err, controller.ErrAdminConflict) {
		t.Fatalf("SetAcquisition(expected mismatch) error = %v", err)
	}
	if fixture.transitions.TransitionCount() != before {
		t.Fatal("expected-mode conflict mutated policy")
	}
	status, err := fixture.service.SetAcquisition(
		context.Background(),
		controller.AcquisitionChange{
			Set:      controller.AcquisitionDisabled,
			Expected: controller.AcquisitionDisabled,
		},
	)
	if err != nil {
		t.Fatalf("SetAcquisition(disabled) error = %v", err)
	}
	if status.Epoch != 6 ||
		status.Mode != controller.AcquisitionDisabled ||
		status.Capacity != 0 ||
		fixture.transitions.TransitionCount() != before+1 {
		t.Fatalf(
			"SetAcquisition(disabled) = %#v transitions=%d",
			status,
			fixture.transitions.TransitionCount(),
		)
	}
}

func TestDisabledAdminProofDriftClearsReadiness(t *testing.T) {
	fixture := newDisabledAdminFixture(t)
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	fixture.ownership.SetValidateError(errors.New("lost ownership"))
	if _, err := fixture.service.Probe(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("drift Probe() error = %v", err)
	}
	fixture.ownership.SetValidateError(nil)
	if _, err := fixture.service.Probe(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Probe() re-armed after sticky drift: %v", err)
	}
}

func TestDisabledAdminHandleLocalNeverConvertsFailureToSuccess(t *testing.T) {
	fixture := newDisabledAdminFixture(t)
	response := fixture.service.HandleLocal(
		context.Background(),
		localRequest{
			SchemaVersion: localProtocolSchemaVersion,
			Method:        localMethodProbe,
		},
	)
	if response.Status != localStatusUnavailable ||
		response.Reason != localReasonNotReady ||
		response.Policy != nil {
		t.Fatalf("pre-ready response = %#v", response)
	}
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	response = fixture.service.HandleLocal(
		context.Background(),
		localRequest{
			SchemaVersion: localProtocolSchemaVersion,
			Method:        localMethodProbe,
		},
	)
	if response.Status != localStatusOK ||
		response.Reason != localReasonNone ||
		response.Policy == nil ||
		!validLowerDigest(response.Policy.Digest) {
		t.Fatalf("ready response = %#v", response)
	}
}

func TestDisabledAdminHealthIsPromptlyNotReadyDuringLongEffect(
	t *testing.T,
) {
	fixture := newDisabledAdminFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.authority.SetReconcile(func(
		context.Context,
	) (controller.CycleReceipt, error) {
		close(entered)
		<-release
		return fixture.authority.Receipt(), nil
	})
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := fixture.service.ReconcileOnce(context.Background())
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("ReconcileOnce() did not enter authority")
	}
	started := time.Now()
	if err := fixture.service.Health(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Health() during reconcile error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("Health() waited behind long effect: %s", elapsed)
	}
	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("ReconcileOnce() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReconcileOnce() did not finish")
	}
	if err := fixture.service.Health(context.Background()); err != nil {
		t.Fatalf("Health() after reconcile error = %v", err)
	}
}

func TestDisabledAdminShutdownCancelsLongEffectBeforeGateJoin(
	t *testing.T,
) {
	fixture := newDisabledAdminFixture(t)
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	fixture.authority.SetDrain(func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	drainCtx, cancelDrain := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelDrain()
	drainResult := make(chan error, 1)
	go func() {
		drainResult <- fixture.service.Drain(
			drainCtx,
			controller.DrainWait,
		)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Drain() did not enter authority")
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancelShutdown()
	if err := fixture.service.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("Shutdown() did not cancel long authority effect")
	}
	select {
	case err := <-drainResult:
		if !errors.Is(err, controller.ErrRuntimeUnavailable) {
			t.Fatalf("Drain() after shutdown error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Drain() did not join after shutdown")
	}
	if err := fixture.service.Health(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Health() after shutdown error = %v", err)
	}
	if fixture.authority.RevokeCalls() != 1 {
		t.Fatalf(
			"RevokePreRunning calls = %d, want 1",
			fixture.authority.RevokeCalls(),
		)
	}
}

func TestDisabledAdminShutdownClassifiesCancellationIgnoringEffect(
	t *testing.T,
) {
	fixture := newDisabledAdminFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.authority.SetDrain(func(context.Context) error {
		close(entered)
		<-release
		return nil
	})
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	drainCtx, cancelDrain := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelDrain()
	drainResult := make(chan error, 1)
	go func() {
		drainResult <- fixture.service.Drain(
			drainCtx,
			controller.DrainWait,
		)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Drain() did not enter ignoring authority")
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(),
		30*time.Millisecond,
	)
	defer cancelShutdown()
	started := time.Now()
	if err := fixture.service.Shutdown(shutdownCtx); !errors.Is(
		err,
		errShutdownEffectStuck,
	) || !errors.Is(err, controller.ErrRuntimeShutdown) {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("Shutdown() exceeded bounded stuck classification: %s", elapsed)
	}
	if fixture.ownership.CountClosed() != 0 {
		t.Fatal("stuck shutdown closed ownership under live effect")
	}
	if err := fixture.service.Health(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Health() after stuck shutdown error = %v", err)
	}
	close(release)
	select {
	case err := <-drainResult:
		if !errors.Is(err, controller.ErrRuntimeUnavailable) {
			t.Fatalf("late Drain() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late Drain() did not release effect gate")
	}
}

func TestDisabledAdminBeginShutdownReturnsBeforeIgnoringEffectJoins(
	t *testing.T,
) {
	fixture := newDisabledAdminFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.authority.SetDrain(func(context.Context) error {
		close(entered)
		<-release
		return nil
	})
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	drainResult := make(chan error, 1)
	go func() {
		drainCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		drainResult <- fixture.service.Drain(
			drainCtx,
			controller.DrainWait,
		)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Drain() did not enter ignoring authority")
	}

	started := time.Now()
	if err := fixture.service.BeginShutdown(); err != nil {
		t.Fatalf("BeginShutdown() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("BeginShutdown() waited for live effect: %s", elapsed)
	}
	if err := fixture.service.Health(context.Background()); !errors.Is(
		err,
		controller.ErrRuntimeUnavailable,
	) {
		t.Fatalf("Health() after BeginShutdown error = %v", err)
	}

	finishCtx, cancelFinish := context.WithTimeout(
		context.Background(),
		30*time.Millisecond,
	)
	defer cancelFinish()
	if err := fixture.service.FinishShutdown(finishCtx); !errors.Is(
		err,
		errShutdownEffectStuck,
	) {
		t.Fatalf("FinishShutdown() error = %v", err)
	}
	close(release)
	select {
	case err := <-drainResult:
		if !errors.Is(err, controller.ErrRuntimeUnavailable) {
			t.Fatalf("late Drain() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late Drain() did not release effect gate")
	}
}

func TestDisabledAdminFinishShutdownJoinsHandlersBeforeAuthorityCleanup(
	t *testing.T,
) {
	fixture := newDisabledAdminFixture(t)
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if err := fixture.service.BeginShutdown(); err != nil {
		t.Fatalf("BeginShutdown() error = %v", err)
	}
	joinEntered := make(chan struct{})
	joinRelease := make(chan struct{})
	finishResult := make(chan error, 1)
	go func() {
		finishCtx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		finishResult <- fixture.service.FinishShutdownWithJoin(
			finishCtx,
			func(context.Context) error {
				close(joinEntered)
				<-joinRelease
				return nil
			},
		)
	}()
	select {
	case <-joinEntered:
	case <-time.After(time.Second):
		t.Fatal("shutdown handler join did not begin")
	}
	if calls := fixture.authority.RevokeCalls(); calls != 0 {
		t.Fatalf(
			"RevokePreRunning calls before handler join = %d, want 0",
			calls,
		)
	}
	close(joinRelease)
	select {
	case err := <-finishResult:
		if err != nil {
			t.Fatalf("FinishShutdownWithJoin() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FinishShutdownWithJoin() did not finish")
	}
	if calls := fixture.authority.RevokeCalls(); calls != 1 {
		t.Fatalf(
			"RevokePreRunning calls after handler join = %d, want 1",
			calls,
		)
	}
}

func TestDisabledAdminFinishShutdownProvesTerminalStateAfterSocketsClose(
	t *testing.T,
) {
	fixture := newDisabledAdminFixture(t)
	if err := fixture.service.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if err := fixture.service.BeginShutdown(); err != nil {
		t.Fatalf("BeginShutdown() error = %v", err)
	}
	fixture.SetSocketProofError(errors.New("sockets intentionally retired"))
	finishCtx, cancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancel()
	if err := fixture.service.FinishShutdown(finishCtx); err != nil {
		t.Fatalf("FinishShutdown() after socket close error = %v", err)
	}
	if calls := fixture.authority.RevokeCalls(); calls != 1 {
		t.Fatalf("RevokePreRunning calls = %d, want 1", calls)
	}
}

type disabledAdminFixture struct {
	service          *disabledAdminService
	transitions      *observerTransitionFixture
	authority        *completeAuthorityFixture
	fleet            *fleetAuthorityFixture
	ownership        *testOwnershipLease
	socketProofMu    sync.Mutex
	socketProofErr   error
	socketProofCalls int
}

func newDisabledAdminFixture(t *testing.T) *disabledAdminFixture {
	t.Helper()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	transitions := &observerTransitionFixture{
		policy: controller.AcquisitionPolicy{
			Mode:                     controller.AcquisitionEnabled,
			EligibleScaleSets:        []string{"scale-a"},
			MaxCapacity:              1,
			RepositoryPolicyRevision: 7,
			RepositoryPolicies:       disabledObserverPolicy().RepositoryPolicies,
			Epoch:                    4,
		},
	}
	authority := &completeAuthorityFixture{
		observation: localObservation{
			Sequence:   1,
			ObservedAt: now.Add(-time.Second),
			Complete:   true,
		},
		receipt: controller.CycleReceipt{
			CycleID:         "cycle-1",
			CompletedAt:     now,
			AssignmentCount: 0,
			OldestAge:       0,
		},
	}
	fleet := &fleetAuthorityFixture{
		proof: fleetAuthorityProof{
			Sequence:       1,
			ObservedAt:     now.Add(-time.Second),
			Fleet:          fleetfence.FleetPortable,
			Generation:     17,
			SelfGuardToken: "self-guard",
		},
	}
	ownership := &testOwnershipLease{}
	fixture := &disabledAdminFixture{
		transitions: transitions,
		authority:   authority,
		fleet:       fleet,
		ownership:   ownership,
	}
	external := newUnavailableExternalGraph()
	service, err := newDisabledAdminService(disabledAdminConfig{
		Transitions:        transitions,
		Authority:          authority,
		Broker:             mustZeroDemandBroker(t, 4),
		Fleet:              fleet,
		External:           &external,
		Ownership:          ownership,
		Desired:            disabledObserverPolicy(),
		ExpectedFleet:      fleetfence.FleetPortable,
		ExpectedGeneration: 17,
		ObservationMaxAge:  2 * time.Second,
		Now:                func() time.Time { return now },
		SocketProof: func() error {
			fixture.socketProofMu.Lock()
			defer fixture.socketProofMu.Unlock()
			fixture.socketProofCalls++
			return fixture.socketProofErr
		},
	})
	if err != nil {
		t.Fatalf("newDisabledAdminService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

func (fixture *disabledAdminFixture) SetSocketProofError(err error) {
	fixture.socketProofMu.Lock()
	defer fixture.socketProofMu.Unlock()
	fixture.socketProofErr = err
}

func mustZeroDemandBroker(
	t *testing.T,
	epoch uint64,
) *zeroDemandBroker {
	t.Helper()
	broker, err := newZeroDemandBroker(epoch)
	if err != nil {
		t.Fatalf("newZeroDemandBroker() error = %v", err)
	}
	return broker
}

type completeAuthorityFixture struct {
	mu          sync.Mutex
	observation localObservation
	receipt     controller.CycleReceipt
	coldCalls   int
	revokeCalls int
	reconcile   func(context.Context) (controller.CycleReceipt, error)
	drain       func(context.Context) error
}

func (fixture *completeAuthorityFixture) ColdReconcile(
	context.Context,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.coldCalls++
	return nil
}

func (fixture *completeAuthorityFixture) ReconcileOnce(
	ctx context.Context,
) (controller.CycleReceipt, error) {
	fixture.mu.Lock()
	reconcile := fixture.reconcile
	receipt := fixture.receipt
	fixture.mu.Unlock()
	if reconcile != nil {
		return reconcile(ctx)
	}
	return receipt, nil
}

func (fixture *completeAuthorityFixture) DrainWait(ctx context.Context) error {
	fixture.mu.Lock()
	drain := fixture.drain
	fixture.mu.Unlock()
	if drain != nil {
		return drain(ctx)
	}
	return nil
}

func (fixture *completeAuthorityFixture) RevokePreRunning(
	context.Context,
) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.revokeCalls++
	return nil
}

func (fixture *completeAuthorityFixture) Observe(
	context.Context,
) (localObservation, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.observation, nil
}

func (fixture *completeAuthorityFixture) Observation() localObservation {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.observation
}

func (fixture *completeAuthorityFixture) SetObservation(
	observation localObservation,
) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.observation = observation
}

func (fixture *completeAuthorityFixture) ColdCalls() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.coldCalls
}

func (fixture *completeAuthorityFixture) Receipt() controller.CycleReceipt {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.receipt
}

func (fixture *completeAuthorityFixture) SetReconcile(
	reconcile func(context.Context) (controller.CycleReceipt, error),
) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.reconcile = reconcile
}

func (fixture *completeAuthorityFixture) SetDrain(
	drain func(context.Context) error,
) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.drain = drain
}

func (fixture *completeAuthorityFixture) RevokeCalls() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.revokeCalls
}

type fleetAuthorityFixture struct {
	mu    sync.Mutex
	proof fleetAuthorityProof
}

func (fixture *fleetAuthorityFixture) Observe(
	context.Context,
) (fleetAuthorityProof, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.proof, nil
}
