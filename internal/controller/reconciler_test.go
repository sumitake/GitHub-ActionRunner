package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeReconcileState struct {
	assignments []RecoverableAssignment
	begun       []string
	completed   []CycleReceipt
	aborted     []string
	err         error
}

func (f *fakeReconcileState) BeginCycle(
	_ context.Context,
	cycleID string,
	_ time.Time,
) error {
	if f.err != nil {
		return f.err
	}
	f.begun = append(f.begun, cycleID)
	return nil
}

func (f *fakeReconcileState) ListRecoverable(
	context.Context,
) ([]RecoverableAssignment, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]RecoverableAssignment(nil), f.assignments...), nil
}

func (f *fakeReconcileState) CompleteCycle(
	_ context.Context,
	receipt CycleReceipt,
) error {
	if f.err != nil {
		return f.err
	}
	f.completed = append(f.completed, receipt)
	return nil
}

func (f *fakeReconcileState) AbortCycle(
	_ context.Context,
	cycleID string,
	_ time.Time,
	reason ReasonCode,
) error {
	if reason != ReasonLifecycleReconcile {
		return errors.New("unexpected abort reason")
	}
	f.aborted = append(f.aborted, cycleID)
	return nil
}

type fakeAssignmentReconciler struct {
	keys  []AssignmentKey
	fail  AssignmentKey
	cause error
}

func (f *fakeAssignmentReconciler) ReconcileAssignment(
	_ context.Context,
	assignment RecoverableAssignment,
) error {
	f.keys = append(f.keys, assignment.Key)
	if assignment.Key == f.fail {
		return f.cause
	}
	return nil
}

func TestReconcilerOnceSortsAssignmentsAndCompletesAfterAllSucceed(t *testing.T) {
	started := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	completed := started.Add(4 * time.Second)
	times := []time.Time{started, completed}
	clock := func() time.Time {
		value := times[0]
		times = times[1:]
		return value
	}
	assignments := []RecoverableAssignment{
		{
			Key:       AssignmentKey{RepositoryAlias: "zeta", RunnerRequestID: 2, Attempt: 1},
			UpdatedAt: started.Add(-3 * time.Minute),
		},
		{
			Key:       AssignmentKey{RepositoryAlias: "alpha", RunnerRequestID: 8},
			UpdatedAt: started.Add(-5 * time.Minute),
		},
		{
			Key:       AssignmentKey{RepositoryAlias: "alpha", RunnerRequestID: 7, Attempt: 2},
			UpdatedAt: started.Add(-time.Minute),
		},
	}
	state := &fakeReconcileState{assignments: assignments}
	worker := &fakeAssignmentReconciler{}
	reconciler, err := NewReconciler(state, worker, clock, func() string { return "cycle-17" })
	if err != nil {
		t.Fatalf("NewReconciler() = %v", err)
	}

	receipt, err := reconciler.Once(context.Background())
	if err != nil {
		t.Fatalf("Once() = %v", err)
	}
	wantOrder := []AssignmentKey{
		assignments[2].Key,
		assignments[1].Key,
		assignments[0].Key,
	}
	if !reflect.DeepEqual(worker.keys, wantOrder) {
		t.Fatalf("reconcile order = %+v, want %+v", worker.keys, wantOrder)
	}
	wantReceipt := CycleReceipt{
		CycleID:         "cycle-17",
		CompletedAt:     completed,
		AssignmentCount: 3,
		OldestAge:       5 * time.Minute,
	}
	if receipt != wantReceipt {
		t.Fatalf("receipt = %+v, want %+v", receipt, wantReceipt)
	}
	if !reflect.DeepEqual(state.begun, []string{"cycle-17"}) ||
		!reflect.DeepEqual(state.completed, []CycleReceipt{wantReceipt}) ||
		len(state.aborted) != 0 {
		t.Fatalf("cycle persistence = begun=%v completed=%+v aborted=%v", state.begun, state.completed, state.aborted)
	}
}

func TestReconcilerOnceAbortsWithoutSuccessReceiptOnAssignmentFailure(t *testing.T) {
	started := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	completed := started.Add(time.Second)
	times := []time.Time{started, completed}
	key := AssignmentKey{RepositoryAlias: "alpha", RunnerRequestID: 7}
	state := &fakeReconcileState{assignments: []RecoverableAssignment{{
		Key:       key,
		UpdatedAt: started.Add(-time.Minute),
	}}}
	worker := &fakeAssignmentReconciler{fail: key, cause: errors.New("cleanup unavailable")}
	reconciler, err := NewReconciler(
		state,
		worker,
		func() time.Time {
			value := times[0]
			times = times[1:]
			return value
		},
		func() string { return "cycle-fail" },
	)
	if err != nil {
		t.Fatalf("NewReconciler() = %v", err)
	}

	receipt, err := reconciler.Once(context.Background())
	if err == nil {
		t.Fatal("Once() = nil error, want assignment failure")
	}
	if receipt != (CycleReceipt{}) {
		t.Fatalf("failed receipt = %+v, want zero", receipt)
	}
	if len(state.completed) != 0 || !reflect.DeepEqual(state.aborted, []string{"cycle-fail"}) {
		t.Fatalf("failed persistence = completed=%+v aborted=%v", state.completed, state.aborted)
	}
}

func TestReconcilerOnceRejectsFutureAssignmentTimestamp(t *testing.T) {
	started := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	completed := started.Add(time.Second)
	times := []time.Time{started, completed}
	state := &fakeReconcileState{assignments: []RecoverableAssignment{{
		Key:       AssignmentKey{RepositoryAlias: "alpha", RunnerRequestID: 7},
		UpdatedAt: started.Add(time.Second),
	}}}
	worker := &fakeAssignmentReconciler{}
	reconciler, err := NewReconciler(
		state,
		worker,
		func() time.Time {
			value := times[0]
			times = times[1:]
			return value
		},
		func() string { return "cycle-future" },
	)
	if err != nil {
		t.Fatalf("NewReconciler() = %v", err)
	}

	if _, err := reconciler.Once(context.Background()); err == nil {
		t.Fatal("Once(future timestamp) = nil, want error")
	}
	if len(worker.keys) != 0 || len(state.completed) != 0 ||
		!reflect.DeepEqual(state.aborted, []string{"cycle-future"}) {
		t.Fatalf("future timestamp effects = worker=%v completed=%v aborted=%v",
			worker.keys, state.completed, state.aborted)
	}
}
