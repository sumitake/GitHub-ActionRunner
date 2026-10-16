package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type canaryObserverFixture struct {
	t                                                    *testing.T
	fixture                                              lifecycleFixture
	calls                                                []string
	beforeErr, authorizedErr, completedErr, reclaimedErr error
}

func (o *canaryObserverFixture) BeforeJIT(_ context.Context, key controller.AssignmentKey, compatibility githubscale.ScaleSetCompatibilityReport) error {
	o.calls = append(o.calls, "jit-intent")
	if key != o.fixture.assignment.Key || compatibility != o.fixture.session.compatibility || o.fixture.session.generateCalls != 0 {
		o.t.Fatal("intent did not precede governed JIT or use live compatibility")
	}
	return o.beforeErr
}
func (o *canaryObserverFixture) AuthorizedJIT(_ context.Context, key controller.AssignmentKey, binding controller.AcquisitionPermitBinding) error {
	o.calls = append(o.calls, "governed-jit")
	if key != o.fixture.assignment.Key || binding != o.fixture.jit.permit.Binding() || o.fixture.session.generateCalls != 1 || o.fixture.jails.releaseCalls != 0 {
		o.t.Fatal("JIT evidence was not recorded between authorization and release")
	}
	return o.authorizedErr
}
func (o *canaryObserverFixture) Collect(_ context.Context, key controller.AssignmentKey, recovery hostruntime.RecoverySpec) error {
	o.calls = append(o.calls, "collect")
	locks := &o.fixture.service.(*service).locks
	locks.mu.Lock()
	entry := locks.entries[key]
	locks.mu.Unlock()
	if entry == nil {
		return errors.New("collection has no lifecycle lock")
	}
	if entry.mu.TryLock() {
		entry.mu.Unlock()
		return errors.New("collection did not hold lifecycle lock")
	}
	if key != o.fixture.assignment.Key || recovery.ExpectedRunnerID != o.fixture.state.record.Slot.RunnerContainerID || o.fixture.state.record.State != controller.StateJobRunning || o.fixture.jails.destroyLive != 0 {
		return errors.New("collection outside live job boundary")
	}
	return nil
}
func (o *canaryObserverFixture) Completed(_ context.Context, key controller.AssignmentKey, result string) error {
	o.calls = append(o.calls, "completed")
	if key != o.fixture.assignment.Key || result != "success" || o.fixture.state.record.State != controller.StateJobFinished || o.fixture.jails.destroyLive != 0 {
		o.t.Fatal("result was not captured after upstream identity checkpoint and before cleanup")
	}
	return o.completedErr
}
func (o *canaryObserverFixture) Reclaimed(_ context.Context, key controller.AssignmentKey) error {
	o.calls = append(o.calls, "reclaimed")
	if key != o.fixture.assignment.Key || len(o.fixture.session.runners) != 0 || o.fixture.recovery.removeCalls == 0 || o.fixture.state.record.State != controller.StateJobFinished {
		o.t.Fatal("cleanup was recorded before upstream/runtime absence")
	}
	return o.reclaimedErr
}

func installCanaryObserver(t *testing.T, f lifecycleFixture) *canaryObserverFixture {
	t.Helper()
	f.session.compatibility = githubscale.ScaleSetCompatibilityReport{DisableUpdate: true, SingleNameLabel: true}
	observer := &canaryObserverFixture{t: t, fixture: f}
	f.service.(*service).canary = observer
	return observer
}

func TestCanaryObserverRecordsOnlyExistingLifecycleBoundaries(t *testing.T) {
	f := newLifecycleFixture(t)
	observer := installCanaryObserver(t, f)
	releaseAndCompleteCanary(t, f)
	if err := f.service.Destroy(context.Background(), f.assignment.Key, controller.ReasonLifecycleJobFinished); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observer.calls, []string{"jit-intent", "governed-jit", "completed", "reclaimed"}) || f.state.record.State != controller.StateDestroyed {
		t.Fatal("incomplete or misordered evidence", observer.calls)
	}
}

func TestCanaryObserverReleaseFailureDoesNotLeakAnUnreleasedJIT(t *testing.T) {
	for _, phase := range []string{"before", "authorized"} {
		t.Run(phase, func(t *testing.T) {
			f := newLifecycleFixture(t)
			o := installCanaryObserver(t, f)
			if phase == "before" {
				o.beforeErr = errors.New("injected")
			} else {
				o.authorizedErr = errors.New("injected")
			}
			if _, err := f.service.Prepare(context.Background(), f.assignment); err != nil {
				t.Fatal(err)
			}
			if err := f.service.Release(context.Background(), f.assignment.Key); !errors.Is(err, ErrReleaseFailed) {
				t.Fatalf("release error: %v", err)
			}
			if f.jails.releaseCalls != 0 || len(f.session.runners) != 0 {
				t.Fatal("observation failure released listener or leaked upstream runner")
			}
			if phase == "before" && f.session.generateCalls != 0 {
				t.Fatal("failed intent reached JIT")
			}
			if phase == "authorized" && (f.session.generateCalls != 1 || len(f.session.removeCalls) != 1) {
				t.Fatal("generated runner was not removed")
			}
		})
	}
}

func TestCanaryObserverCompletedFailureStillLeavesCleanupPossible(t *testing.T) {
	f := newLifecycleFixture(t)
	o := installCanaryObserver(t, f)
	o.completedErr = errors.New("injected")
	ctx := context.Background()
	if _, err := f.service.Prepare(ctx, f.assignment); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Release(ctx, f.assignment.Key); err != nil {
		t.Fatal(err)
	}
	runner := f.session.runners[f.assignment.Slot.OpaqueName]
	job := f.assignment.Offer.JobRef
	job.FinishTime = time.Now().Add(-time.Second)
	event, err := githubscale.NewCompletedEvent(githubscale.CompletedEvent{JobRef: job, Result: "success", RunnerID: runner.ID, RunnerName: runner.Name})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.Observe(ctx, event); err == nil {
		t.Fatal("missing evidence failure ignored")
	}
	if f.state.record.State != controller.StateJobFinished {
		t.Fatal("upstream completion was lost")
	}
	if err := f.service.Destroy(ctx, f.assignment.Key, controller.ReasonLifecycleJobFinished); err != nil {
		t.Fatal(err)
	}
	if f.state.record.State != controller.StateDestroyed {
		t.Fatal("evidence failure blocked cleanup")
	}
}

func TestCanaryObserverCleanupWriteCanRetryWithoutRepeatingJIT(t *testing.T) {
	f := newLifecycleFixture(t)
	o := installCanaryObserver(t, f)
	releaseAndCompleteCanary(t, f)
	o.reclaimedErr = errors.New("injected")
	if err := f.service.Destroy(context.Background(), f.assignment.Key, controller.ReasonLifecycleJobFinished); err == nil || f.state.record.State != controller.StateJobFinished {
		t.Fatal("missing cleanup evidence was acknowledged")
	}
	o.reclaimedErr = nil
	if err := f.service.Destroy(context.Background(), f.assignment.Key, controller.ReasonLifecycleJobFinished); err != nil {
		t.Fatal(err)
	}
	if f.state.record.State != controller.StateDestroyed || f.session.generateCalls != 1 {
		t.Fatal("cleanup retry repeated acquisition")
	}
}

func TestCanaryObserverCompositionRequiresOneNonNilObserver(t *testing.T) {
	f := newLifecycleFixture(t)
	o := installCanaryObserver(t, f)
	for _, observers := range [][]CanaryObserver{{nil}, {o, o}} {
		if _, err := NewService(f.state, f.sessions, f.jit, f.service.(*service).builder, f.jails, f.recovery, time.Now, observers...); !errors.Is(err, ErrLifecycle) {
			t.Fatal("invalid observer composition accepted")
		}
	}
	runtime, err := NewService(f.state, f.sessions, f.jit, f.service.(*service).builder, f.jails, f.recovery, time.Now, o)
	if err != nil || runtime.(*service).canary != o {
		t.Fatal("observer was not installed")
	}
}

func TestCanaryObserverCollectsThroughExistingRunningReconciliation(t *testing.T) {
	f := newLifecycleFixture(t)
	o := installCanaryObserver(t, f)
	ctx := context.Background()
	if _, err := f.service.Prepare(ctx, f.assignment); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Release(ctx, f.assignment.Key); err != nil {
		t.Fatal(err)
	}
	runner := f.session.runners[f.assignment.Slot.OpaqueName]
	job := f.assignment.Offer.JobRef
	job.RunnerAssignTime = time.Now().Add(-time.Second)
	started, err := githubscale.NewStartedEvent(githubscale.StartedEvent{JobRef: job, RunnerID: runner.ID, RunnerName: runner.Name})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.Observe(ctx, started); err != nil {
		t.Fatal(err)
	}
	// The fixture deliberately has no issued live managed snapshot. Collection is
	// non-authorizing; the existing runtime verification still fails afterward.
	if err := f.service.ReconcileAssignment(ctx, projectedRecovery(f.state.record)); !errors.Is(err, ErrReleaseAmbiguous) {
		t.Fatalf("existing live-graph guard changed: %v", err)
	}
	if !reflect.DeepEqual(o.calls, []string{"jit-intent", "governed-jit", "collect"}) {
		t.Fatal("running reconciliation did not collect job result", o.calls)
	}
}
