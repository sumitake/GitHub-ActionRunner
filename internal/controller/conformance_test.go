package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

const testFleetGeneration = uint64(7)

type recordingAcquisitionConformance struct {
	mu    sync.Mutex
	err   error
	calls []conformance.AcquisitionConformanceRequest
}

func (g *recordingAcquisitionConformance) Verify(
	ctx context.Context,
	request conformance.AcquisitionConformanceRequest,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, request)
	return g.err
}

func (g *recordingAcquisitionConformance) SetError(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.err = err
}

func (g *recordingAcquisitionConformance) Calls() []conformance.AcquisitionConformanceRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]conformance.AcquisitionConformanceRequest(nil), g.calls...)
}

func testPassingAcquisitionConformance() conformance.AcquisitionConformance {
	return &recordingAcquisitionConformance{}
}

func TestAcquisitionConformanceBlocksEnableBeforePersistence(t *testing.T) {
	t.Parallel()

	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	if err := fixture.service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	gate := &recordingAcquisitionConformance{
		err: conformance.ErrAcquisitionConformanceUnavailable,
	}
	fixture.service.conformance = gate
	before := len(fixture.transitions.Transitions())

	_, err := fixture.service.SetAcquisition(
		context.Background(),
		AcquisitionChange{
			Set:              AcquisitionCanaryOnly,
			Expected:         AcquisitionDisabled,
			EligibleScaleSet: "portable-ghar",
		},
	)
	if !errors.Is(err, ErrAcquisitionConformance) {
		t.Fatalf("SetAcquisition = %v, want conformance failure", err)
	}
	if got := len(fixture.transitions.Transitions()); got != before {
		t.Fatalf("transition count = %d, want unchanged %d", got, before)
	}
	if policy := fixture.service.Policy(); policy.Mode != AcquisitionDisabled {
		t.Fatalf("policy = %+v, want disabled", policy)
	}
	if fixture.terminator.Count() != 0 {
		t.Fatalf("terminator calls = %d, want zero", fixture.terminator.Count())
	}
	calls := gate.Calls()
	if len(calls) != 1 ||
		calls[0].BuildID != testBuildID ||
		calls[0].HostProfileID != testHostProfileID ||
		calls[0].FleetGeneration != testFleetGeneration ||
		calls[0].Mode != conformance.AcquisitionCanaryOnly {
		t.Fatalf("gate calls = %+v", calls)
	}
}

func TestAcquisitionConformanceFailureDuringStartupCleansThenPersistsFatal(
	t *testing.T,
) {
	t.Parallel()

	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	fixture.service.conformance = &recordingAcquisitionConformance{
		err: conformance.ErrAcquisitionConformanceUnavailable,
	}

	if err := fixture.service.Start(context.Background()); !errors.Is(
		err,
		ErrStartupRestore,
	) || !errors.Is(err, ErrAcquisitionConformance) {
		t.Fatalf("Start = %v, want startup/conformance failure", err)
	}
	transitions := fixture.transitions.Transitions()
	if len(transitions) != 2 ||
		transitions[0].Mode != AcquisitionDisabled ||
		transitions[1].Mode != AcquisitionFatal {
		t.Fatalf("startup transitions = %+v, want disabled then fatal", transitions)
	}
	if fixture.service.Ready() {
		t.Fatal("service became ready after missing active conformance")
	}
	if fixture.terminator.Count() != 1 ||
		fixture.terminator.LastReason() != ReasonRestoreInvalid {
		t.Fatalf(
			"terminator = (%d,%v), want one restore-invalid",
			fixture.terminator.Count(),
			fixture.terminator.LastReason(),
		)
	}
	fixture.revoker.mu.Lock()
	revokeCalls := len(fixture.revoker.epochs)
	fixture.revoker.mu.Unlock()
	if revokeCalls != 1 {
		t.Fatalf("startup revoke calls = %d, want one before fatal", revokeCalls)
	}
}

func TestAcquisitionConformanceLossBeforeJITRevokesAndCreatesNoListener(
	t *testing.T,
) {
	t.Parallel()

	service, request, session, _, _ := newTask8JITFixture(t)
	gate := &recordingAcquisitionConformance{
		err: conformance.ErrAcquisitionConformanceUnavailable,
	}
	service.conformance = gate
	revoker := service.revoker.(*fakeAcquisitionRevoker)
	revoker.mu.Lock()
	beforeRevokes := len(revoker.epochs)
	revoker.mu.Unlock()

	if _, err := service.GenerateJITAuthorized(
		context.Background(),
		request,
	); !errors.Is(err, ErrAcquisitionConformance) {
		t.Fatalf("GenerateJITAuthorized = %v, want conformance failure", err)
	}
	if got := session.Calls(); len(got) != 0 {
		t.Fatalf("JIT provider calls = %+v, want none", got)
	}
	if service.Ready() || service.Policy().Mode != AcquisitionFatal {
		t.Fatalf(
			"service ready/policy = %t/%+v, want false/fatal",
			service.Ready(),
			service.Policy(),
		)
	}
	revoker.mu.Lock()
	afterRevokes := len(revoker.epochs)
	revoker.mu.Unlock()
	if afterRevokes != beforeRevokes+1 {
		t.Fatalf(
			"revokes = %d -> %d, want one cleanup revoke",
			beforeRevokes,
			afterRevokes,
		)
	}
}

func TestUnavailableConformanceStillAllowsDisabledStartup(t *testing.T) {
	t.Parallel()

	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	fixture.transitions.mu.Lock()
	disabled := cloneAcquisitionPolicy(fixture.transitions.current)
	disabled.Mode = AcquisitionDisabled
	disabled.MaxCapacity = 0
	disabled.EligibleScaleSets = nil
	fixture.transitions.current = disabled
	fixture.transitions.mu.Unlock()
	fixture.service.conformance = conformance.NewUnavailableAcquisitionGate()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := fixture.service.Start(ctx); err != nil {
		t.Fatalf("Start(disabled): %v", err)
	}
	if !fixture.service.Ready() ||
		fixture.service.Policy().Mode != AcquisitionDisabled {
		t.Fatalf(
			"disabled startup = ready %t policy %+v",
			fixture.service.Ready(),
			fixture.service.Policy(),
		)
	}
}
