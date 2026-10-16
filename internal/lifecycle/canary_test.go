package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func releaseAndCompleteCanary(t *testing.T, f lifecycleFixture) githubscale.RunnerRef {
	t.Helper()
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
	completed, err := githubscale.NewCompletedEvent(githubscale.CompletedEvent{JobRef: job, Result: "success", RunnerID: runner.ID, RunnerName: runner.Name})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.Observe(ctx, completed); err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestCleanupProvesKnownUpstreamIDAbsentEvenWhenNameIsAbsent(t *testing.T) {
	f := newLifecycleFixture(t)
	runner := releaseAndCompleteCanary(t, f)
	delete(f.session.runners, runner.Name)
	f.session.runners["other-name"] = githubscale.RunnerRef{ID: runner.ID, Name: "other-name"}
	if err := f.service.Destroy(context.Background(), f.assignment.Key, controller.ReasonLifecycleJobFinished); !errors.Is(err, ErrCleanupUnproven) {
		t.Fatalf("upstream ID remained: %v", err)
	}
	if f.jails.destroyLive != 0 || f.state.record.State == controller.StateDestroyed {
		t.Fatal("unproven upstream absence was marked reclaimed")
	}
}
