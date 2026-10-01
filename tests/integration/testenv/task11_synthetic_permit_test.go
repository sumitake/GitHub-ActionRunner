package testenv

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/failoverclient"
)

// task11SyntheticPermitClock holds the authority clock still and parks the
// deadline waiter until its context ends, so an active permit stays live for
// the duration of a test. The failoverclient fake returns from WaitUntil at
// once, which would drop every permit before it could be used.
type task11SyntheticPermitClock struct {
	now      time.Time
	disabled bool
}

func (c *task11SyntheticPermitClock) Capable() bool { return !c.disabled }

func (c *task11SyntheticPermitClock) Now() (time.Time, error) {
	return c.now, nil
}

func (*task11SyntheticPermitClock) WaitUntil(
	ctx context.Context,
	_ time.Time,
) error {
	<-ctx.Done()
	return ctx.Err()
}

func task11SyntheticPermitCycle(ordinal uint64) task11SyntheticCycleIdentity {
	return task11SyntheticCycleIdentity{
		Request: task11SyntheticCycleRequest{
			Kind:    task11CycleOneJob,
			Ordinal: ordinal,
		},
		RunDigest: strings.Repeat("c", 64),
	}
}

func TestTask11SyntheticReleasePermitIsAcceptedByReleaseContract(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &task11SyntheticPermitClock{now: now}
	permit, err := acquireTask11SyntheticReleasePermit(
		context.Background(),
		clock,
		task11SyntheticPermitCycle(1),
		"portable-ghar-conformance",
		strings.Repeat("a", 64),
		now,
		now.Add(time.Minute),
		5*time.Second,
	)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(func() { _ = permit.Close() })

	binding := permit.Binding()
	if _, err := controller.AcquisitionPermitBindingDigest(binding); err != nil {
		t.Fatalf("binding digest: %v", err)
	}
	if binding.RepositoryAlias != "portable-ghar-conformance" ||
		binding.OperationKind != "jit" ||
		binding.PolicyMode != controller.AcquisitionCanaryOnly {
		t.Fatalf("unexpected binding: %+v", binding)
	}
	if err := permit.ValidateBinding(context.Background(), binding); err != nil {
		t.Fatalf("validate binding: %v", err)
	}
	if permit.Context() == nil || permit.Context().Err() != nil {
		t.Fatal("permit context is not live")
	}
	if err := permit.Revalidate(); err != nil {
		t.Fatalf("revalidate: %v", err)
	}
	if err := permit.Admit(); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := permit.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestTask11SyntheticReleasePermitBindsCycleIdentity(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	acquire := func(ordinal uint64) controller.AcquisitionPermitBinding {
		permit, err := acquireTask11SyntheticReleasePermit(
			context.Background(),
			&task11SyntheticPermitClock{now: now},
			task11SyntheticPermitCycle(ordinal),
			"portable-ghar-conformance",
			strings.Repeat("a", 64),
			now,
			now.Add(time.Minute),
			5*time.Second,
		)
		if err != nil {
			t.Fatalf("acquire %d: %v", ordinal, err)
		}
		t.Cleanup(func() { _ = permit.Close() })
		return permit.Binding()
	}
	first, second := acquire(1), acquire(2)
	if first.OperationID == second.OperationID ||
		first.SessionID == second.SessionID {
		t.Fatalf("cycles share permit identity: %+v %+v", first, second)
	}
}

func TestTask11SyntheticReleasePermitRejectsUnusableAuthority(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	valid := strings.Repeat("a", 64)
	incapable := &task11SyntheticPermitClock{now: now, disabled: true}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name   string
		ctx    context.Context
		clock  failoverclient.AuthorityClock
		alias  string
		digest string
		after  time.Time
		tail   time.Duration
	}{
		{"nil clock", context.Background(), nil, "alias", valid, now.Add(time.Minute), time.Second},
		{"incapable clock", context.Background(), incapable, "alias", valid, now.Add(time.Minute), time.Second},
		{"empty alias", context.Background(), &task11SyntheticPermitClock{now: now}, "", valid, now.Add(time.Minute), time.Second},
		{"short digest", context.Background(), &task11SyntheticPermitClock{now: now}, "alias", "abc", now.Add(time.Minute), time.Second},
		{"expired authorization", context.Background(), &task11SyntheticPermitClock{now: now}, "alias", valid, now, time.Second},
		{"no slack before tail", context.Background(), &task11SyntheticPermitClock{now: now}, "alias", valid, now.Add(time.Second), time.Second},
		{"zero tail", context.Background(), &task11SyntheticPermitClock{now: now}, "alias", valid, now.Add(time.Minute), 0},
		{"canceled context", canceled, &task11SyntheticPermitClock{now: now}, "alias", valid, now.Add(time.Minute), time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			permit, err := acquireTask11SyntheticReleasePermit(
				test.ctx,
				test.clock,
				task11SyntheticPermitCycle(1),
				test.alias,
				test.digest,
				now,
				test.after,
				test.tail,
			)
			if permit != nil {
				_ = permit.Close()
				t.Fatal("permit issued for unusable authority")
			}
			if !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("error = %v, want ErrFixtureStart", err)
			}
		})
	}
}
