package controller

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

type testNormalHostCapacityProvider struct{}

func (testNormalHostCapacityProvider) Evaluate(context.Context) (HostCapacityReport, error) {
	return HostCapacityReport{
		State:             HostCapacityNormal,
		EffectiveCapacity: 2,
		EvidenceDigest:    strings.Repeat("a", 64),
		ObservedAt:        time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}, nil
}

type scriptedHostCapacityProvider struct {
	mu      sync.Mutex
	reports []HostCapacityReport
	errs    []error
	calls   int
}

func (p *scriptedHostCapacityProvider) Evaluate(context.Context) (HostCapacityReport, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	index := p.calls
	p.calls++
	if index < len(p.errs) && p.errs[index] != nil {
		return HostCapacityReport{}, p.errs[index]
	}
	if index >= len(p.reports) {
		return HostCapacityReport{}, errors.New("unexpected host-capacity call")
	}
	return p.reports[index], nil
}

func (p *scriptedHostCapacityProvider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func hostCapacityReport(
	state HostCapacityState,
	capacity int,
	now time.Time,
) HostCapacityReport {
	return HostCapacityReport{
		State:             state,
		EffectiveCapacity: capacity,
		EvidenceDigest:    strings.Repeat("b", 64),
		ObservedAt:        now,
	}
}

func TestHostCapacityWarningLowersAndNormalNeverRaises(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	service := startPressureService(
		t,
		now,
		&fakeDurableState{},
		&fakeAdmissionBroker{},
		testHistoryPressureThresholds(),
		&fakeHealthPublisher{},
		&fakeEventSink{},
	)
	provider := &scriptedHostCapacityProvider{reports: []HostCapacityReport{
		hostCapacityReport(HostCapacityWarning, 1, now),
		hostCapacityReport(HostCapacityNormal, 2, now),
	}}
	service.hostCapacity = provider
	service.hostCapacityMaxAge = time.Minute

	report, err := service.EvaluateHostPressure(context.Background())
	if err != nil {
		t.Fatalf("warning evaluation: %v", err)
	}
	if report.State != HostCapacityWarning ||
		service.Policy().MaxCapacity != 1 {
		t.Fatalf("warning report=%+v policy=%+v", report, service.Policy())
	}
	report, err = service.EvaluateHostPressure(context.Background())
	if err != nil {
		t.Fatalf("normal evaluation: %v", err)
	}
	if report.State != HostCapacityNormal ||
		service.Policy().MaxCapacity != 1 {
		t.Fatalf("normal auto-raised: report=%+v policy=%+v", report, service.Policy())
	}
}

func TestHostCapacityInvalidOrStopPersistsZeroBeforeFailure(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		report   HostCapacityReport
		provider error
	}{
		{
			name:     "provider error",
			provider: errors.New("measurement unavailable"),
		},
		{
			name:   "stop",
			report: hostCapacityReport(HostCapacityStop, 0, now),
		},
		{
			name:   "stale",
			report: hostCapacityReport(HostCapacityNormal, 2, now.Add(-2*time.Minute)),
		},
		{
			name: "uppercase digest",
			report: HostCapacityReport{
				State:             HostCapacityNormal,
				EffectiveCapacity: 2,
				EvidenceDigest:    strings.Repeat("A", 64),
				ObservedAt:        now,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			service := startPressureService(
				t,
				now,
				&fakeDurableState{},
				&fakeAdmissionBroker{},
				testHistoryPressureThresholds(),
				&fakeHealthPublisher{},
				&fakeEventSink{},
			)
			provider := &scriptedHostCapacityProvider{
				reports: []HostCapacityReport{test.report},
				errs:    []error{test.provider},
			}
			service.hostCapacity = provider
			service.hostCapacityMaxAge = time.Minute
			if _, err := service.EvaluateHostPressure(context.Background()); !errors.Is(err, ErrHostPressure) {
				t.Fatalf("EvaluateHostPressure err=%v", err)
			}
			if policy := service.Policy(); policy.Mode != AcquisitionDisabled ||
				policy.MaxCapacity != 0 {
				t.Fatalf("failure returned before zero persisted: %+v", policy)
			}
		})
	}
}

func TestPublicCyclesEvaluateHostPressureBeforeEffects(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	injected := errors.New("host evidence unavailable")

	t.Run("poll", func(t *testing.T) {
		trace := &callTrace{}
		broker := &fakeAdmissionBroker{
			trace: trace,
			lease: PollLease{
				RepositoryAlias: "repo-a",
				Epoch:           9,
				PollCapacity:    0,
			},
		}
		service, _ := startPollService(
			t,
			now,
			trace,
			&fakeDurableState{trace: trace},
			broker,
			&fakeEventRecorder{trace: trace},
		)
		provider := &scriptedHostCapacityProvider{errs: []error{injected}}
		service.hostCapacity = provider
		service.hostCapacityMaxAge = time.Minute
		fleet := githubscale.Fleet{
			RepositoryAlias: "repo-a",
			ScaleSetName:    "portable-ghar",
		}
		if err := service.PollOnce(
			context.Background(),
			fleet,
			&fakeSession{},
		); !errors.Is(err, ErrHostPressure) {
			t.Fatalf("PollOnce err=%v", err)
		}
		for _, call := range trace.Snapshot() {
			if call == "broker:lease" {
				t.Fatal("poll acquired broker lease before host pressure")
			}
		}
	})

	t.Run("admit", func(t *testing.T) {
		broker := &fakeAdmissionBroker{}
		service := startPressureService(
			t,
			now,
			&fakeDurableState{},
			broker,
			testHistoryPressureThresholds(),
			&fakeHealthPublisher{},
			&fakeEventSink{},
		)
		service.hostCapacity = &scriptedHostCapacityProvider{errs: []error{injected}}
		service.hostCapacityMaxAge = time.Minute
		if _, err := service.AdmitOnce(context.Background()); !errors.Is(err, ErrHostPressure) {
			t.Fatalf("AdmitOnce err=%v", err)
		}
		if broker.EnsureCalls() != 0 {
			t.Fatal("admission mutated broker after host-pressure failure")
		}
	})

	t.Run("reconcile", func(t *testing.T) {
		reconciler := &fakeCycleReconciler{}
		publisher := &fakeHealthPublisher{}
		service := startPressureService(
			t,
			now,
			&fakeDurableState{},
			&fakeAdmissionBroker{},
			testHistoryPressureThresholds(),
			publisher,
			&fakeEventSink{},
		)
		service.reconciler = reconciler
		service.hostCapacity = &scriptedHostCapacityProvider{errs: []error{injected}}
		service.hostCapacityMaxAge = time.Minute
		if _, err := service.ReconcileOnce(context.Background()); !errors.Is(err, ErrHostPressure) {
			t.Fatalf("ReconcileOnce err=%v", err)
		}
		if reconciler.Calls() != 0 || len(publisher.Snapshots()) != 0 {
			t.Fatalf("reconciliation effects occurred: calls=%d snapshots=%d", reconciler.Calls(), len(publisher.Snapshots()))
		}
	})
}

func TestCentralLoopEvaluatesHostPressureOncePerCombinedCycle(t *testing.T) {
	t.Parallel()

	fixture := newRuntimeServiceFixture(t, nil, nil, nil)
	if err := fixture.service.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	provider := &scriptedHostCapacityProvider{
		reports: []HostCapacityReport{
			hostCapacityReport(HostCapacityNormal, 2, fixture.now),
		},
		errs: []error{
			nil,
			errors.New("stop after one combined cycle"),
		},
	}
	fixture.service.hostCapacity = provider
	fixture.service.hostCapacityMaxAge = time.Minute

	if err := fixture.service.runCentralLoop(context.Background()); !errors.Is(err, ErrHostPressure) {
		t.Fatalf("runCentralLoop err=%v", err)
	}
	if provider.Calls() != 2 {
		t.Fatalf("host-capacity calls = %d, want one per cycle", provider.Calls())
	}
	if fixture.service.reconciler.(*fakeCycleReconciler).Calls() != 1 {
		t.Fatalf(
			"reconciler calls = %d, want one completed combined cycle",
			fixture.service.reconciler.(*fakeCycleReconciler).Calls(),
		)
	}
}
