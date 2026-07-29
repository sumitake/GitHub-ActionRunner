package controller

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquisitionBarrierRejectsRegistrationUntilOpened(t *testing.T) {
	t.Parallel()

	policy := testDesiredPolicy()
	barrier, err := newAcquisitionBarrier(policy, false)
	if err != nil {
		t.Fatalf("newAcquisitionBarrier: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := barrier.beginOperation(ctx, "poll", "repo-a", "portable-ghar"); !errors.Is(
		err,
		ErrAcquisitionTransitioning,
	) {
		t.Fatalf("beginOperation(closed) = %v, want ErrAcquisitionTransitioning", err)
	}
	if err := barrier.open(policy.Epoch); err != nil {
		t.Fatalf("open: %v", err)
	}
	operation, err := barrier.beginOperation(ctx, "poll", "repo-a", "portable-ghar")
	if err != nil {
		t.Fatalf("beginOperation(open): %v", err)
	}
	if operation.ID() == "" ||
		operation.Epoch() != policy.Epoch ||
		operation.Policy().Epoch != policy.Epoch ||
		operation.Policy().EligibleScaleSets[0] != "portable-ghar" {
		t.Fatalf("operation binding = id=%q epoch=%d policy=%+v", operation.ID(), operation.Epoch(), operation.Policy())
	}
	policy.EligibleScaleSets[0] = "mutated"
	if operation.Policy().EligibleScaleSets[0] != "portable-ghar" {
		t.Fatal("operation policy aliases caller memory")
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := operation.Close(); !errors.Is(err, ErrAcquisitionOperationClosed) {
		t.Fatalf("second Close = %v, want ErrAcquisitionOperationClosed", err)
	}
}

func TestAcquisitionBarrierFailedTransitionReopensSameEpoch(t *testing.T) {
	t.Parallel()

	policy := testDesiredPolicy()
	barrier, err := newAcquisitionBarrier(policy, true)
	if err != nil {
		t.Fatalf("newAcquisitionBarrier: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	operation, err := barrier.beginOperation(ctx, "poll", "repo-a", "portable-ghar")
	if err != nil {
		t.Fatalf("beginOperation: %v", err)
	}
	closed, err := barrier.closeGate(policy.Epoch)
	if err != nil {
		t.Fatalf("closeGate: %v", err)
	}
	if _, err := barrier.beginOperation(ctx, "acquire", "repo-a", "portable-ghar"); !errors.Is(
		err,
		ErrAcquisitionTransitioning,
	) {
		t.Fatalf("beginOperation(transitioning) = %v, want ErrAcquisitionTransitioning", err)
	}
	if err := barrier.reopen(closed); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	select {
	case <-operation.Context().Done():
		t.Fatalf("failed transition cancelled old operation: %v", context.Cause(operation.Context()))
	default:
	}
	other, err := barrier.beginOperation(ctx, "acquire", "repo-a", "portable-ghar")
	if err != nil {
		t.Fatalf("beginOperation(reopened): %v", err)
	}
	if other.Epoch() != operation.Epoch() {
		t.Fatalf("reopened epoch = %d, want %d", other.Epoch(), operation.Epoch())
	}
	if err := other.Close(); err != nil {
		t.Fatalf("other.Close: %v", err)
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("operation.Close: %v", err)
	}
}

func TestAcquisitionBarrierPublicationCancelsAndJoinsOldEpoch(t *testing.T) {
	t.Parallel()

	policy := testDesiredPolicy()
	barrier, err := newAcquisitionBarrier(policy, true)
	if err != nil {
		t.Fatalf("newAcquisitionBarrier: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	operation, err := barrier.beginOperation(ctx, "poll", "repo-a", "portable-ghar")
	if err != nil {
		t.Fatalf("beginOperation: %v", err)
	}
	critical, err := barrier.beginCritical(ctx, "repo-a", 41)
	if err != nil {
		t.Fatalf("beginCritical: %v", err)
	}
	if _, err := barrier.beginCritical(ctx, "repo-a", 41); !errors.Is(
		err,
		ErrAcquisitionCriticalBusy,
	) {
		t.Fatalf("duplicate beginCritical = %v, want ErrAcquisitionCriticalBusy", err)
	}

	closed, err := barrier.closeGate(policy.Epoch)
	if err != nil {
		t.Fatalf("closeGate: %v", err)
	}
	next := policy
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	next.Epoch++
	old, err := barrier.publish(closed, next)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if old != closed {
		t.Fatal("publish returned a different old epoch")
	}
	for name, operationContext := range map[string]context.Context{
		"operation": operation.Context(),
		"critical":  critical.Context(),
	} {
		select {
		case <-operationContext.Done():
			if !errors.Is(context.Cause(operationContext), ErrAcquisitionEpochSuperseded) {
				t.Fatalf("%s cause = %v, want ErrAcquisitionEpochSuperseded", name, context.Cause(operationContext))
			}
		case <-time.After(time.Second):
			t.Fatalf("%s context was not cancelled", name)
		}
	}
	if _, err := barrier.beginOperation(ctx, "jit", "repo-a", "portable-ghar"); !errors.Is(
		err,
		ErrAcquisitionTransitioning,
	) {
		t.Fatalf("new epoch operation before open = %v, want ErrAcquisitionTransitioning", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- barrier.waitEpoch(ctx, old)
	}()
	select {
	case err := <-waitDone:
		t.Fatalf("waitEpoch returned before releases: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := operation.Close(); err != nil {
		t.Fatalf("operation.Close: %v", err)
	}
	select {
	case err := <-waitDone:
		t.Fatalf("waitEpoch returned with critical still live: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := critical.Close(); err != nil {
		t.Fatalf("critical.Close: %v", err)
	}
	if err := <-waitDone; err != nil {
		t.Fatalf("waitEpoch: %v", err)
	}
	operations, criticals := barrier.epochCounts(old)
	if operations != 0 || criticals != 0 {
		t.Fatalf("old epoch counts = (%d,%d), want zero", operations, criticals)
	}
	if err := barrier.open(next.Epoch); err != nil {
		t.Fatalf("open(next): %v", err)
	}
	current, err := barrier.beginOperation(ctx, "jit", "repo-a", "portable-ghar")
	if err != nil {
		t.Fatalf("beginOperation(next): %v", err)
	}
	if current.Epoch() != next.Epoch {
		t.Fatalf("current epoch = %d, want %d", current.Epoch(), next.Epoch)
	}
	if err := current.Close(); err != nil {
		t.Fatalf("current.Close: %v", err)
	}
}

func TestAcquisitionBarrierRequiresBoundedContextAndExactEpoch(t *testing.T) {
	t.Parallel()

	policy := testDesiredPolicy()
	barrier, err := newAcquisitionBarrier(policy, true)
	if err != nil {
		t.Fatalf("newAcquisitionBarrier: %v", err)
	}
	if _, err := barrier.beginOperation(
		context.Background(),
		"poll",
		"repo-a",
		"portable-ghar",
	); !errors.Is(err, ErrAcquisitionDeadlineRequired) {
		t.Fatalf("beginOperation(unbounded) = %v, want ErrAcquisitionDeadlineRequired", err)
	}
	if _, err := barrier.beginCritical(
		context.Background(),
		"repo-a",
		1,
	); !errors.Is(err, ErrAcquisitionDeadlineRequired) {
		t.Fatalf("beginCritical(unbounded) = %v, want ErrAcquisitionDeadlineRequired", err)
	}
	if _, err := barrier.closeGate(policy.Epoch + 1); !errors.Is(
		err,
		ErrAcquisitionEpochMismatch,
	) {
		t.Fatalf("closeGate(stale) = %v, want ErrAcquisitionEpochMismatch", err)
	}
}
