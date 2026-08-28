package failoverclient

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFakeAuthorityClockWaitUntilExactDeadline(t *testing.T) {
	deadline := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	clock := NewFakeAuthorityClock(deadline)

	if err := clock.WaitUntil(context.Background(), deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitUntil exact deadline error = %v", err)
	}
	got, err := clock.Now()
	if err != nil || !got.Equal(deadline) {
		t.Fatalf("Now after exact wait = (%v, %v)", got, err)
	}
}

func TestFakeAuthorityClockWaitUntilPreCanceled(t *testing.T) {
	clock := NewFakeAuthorityClock(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := clock.WaitUntil(ctx, clock.now.Add(time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitUntil canceled error = %v", err)
	}
}
