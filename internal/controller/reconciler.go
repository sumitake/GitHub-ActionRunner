package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

var ErrReconciliation = errors.New("controller: reconciliation failed")

// ReconcileState is the controller-owned durable cycle boundary. The state
// adapter maps these calls to the bounded SQLite cycle journal.
type ReconcileState interface {
	BeginCycle(context.Context, string, time.Time) error
	ListRecoverable(context.Context) ([]RecoverableAssignment, error)
	CompleteCycle(context.Context, CycleReceipt) error
	AbortCycle(context.Context, string, time.Time, ReasonCode) error
}

// AssignmentReconciler performs the state-aware, same-key-exclusive recovery
// for one durable assignment.
type AssignmentReconciler interface {
	ReconcileAssignment(context.Context, RecoverableAssignment) error
}

// Reconciler executes one bounded reconciliation cycle.
type Reconciler interface {
	Once(context.Context) (CycleReceipt, error)
}

type reconciler struct {
	state  ReconcileState
	worker AssignmentReconciler
	now    func() time.Time
	nextID func() string
}

func NewReconciler(
	state ReconcileState,
	worker AssignmentReconciler,
	now func() time.Time,
	nextID func() string,
) (Reconciler, error) {
	if state == nil || worker == nil || now == nil || nextID == nil {
		return nil, fmt.Errorf("%w: dependencies required", ErrReconciliation)
	}
	return &reconciler{
		state:  state,
		worker: worker,
		now:    now,
		nextID: nextID,
	}, nil
}

func (r *reconciler) Once(ctx context.Context) (CycleReceipt, error) {
	if err := ctx.Err(); err != nil {
		return CycleReceipt{}, fmt.Errorf("%w: context: %w", ErrReconciliation, err)
	}
	cycleID := r.nextID()
	startedAt := r.now()
	if cycleID == "" || startedAt.IsZero() {
		return CycleReceipt{}, fmt.Errorf("%w: invalid cycle identity", ErrReconciliation)
	}
	if err := r.state.BeginCycle(ctx, cycleID, startedAt); err != nil {
		return CycleReceipt{}, fmt.Errorf("%w: begin cycle: %w", ErrReconciliation, err)
	}

	assignments, err := r.state.ListRecoverable(ctx)
	if err != nil {
		return CycleReceipt{}, r.abort(ctx, cycleID, fmt.Errorf("list recoverable: %w", err))
	}
	assignments = append([]RecoverableAssignment(nil), assignments...)
	for _, assignment := range assignments {
		if !validRecoverableForCycle(assignment, startedAt) {
			return CycleReceipt{}, r.abort(
				ctx,
				cycleID,
				fmt.Errorf("invalid recoverable assignment %+v", assignment.Key),
			)
		}
	}
	sort.SliceStable(assignments, func(i, j int) bool {
		left, right := assignments[i].Key, assignments[j].Key
		if left.RepositoryAlias != right.RepositoryAlias {
			return left.RepositoryAlias < right.RepositoryAlias
		}
		if left.RunnerRequestID != right.RunnerRequestID {
			return left.RunnerRequestID < right.RunnerRequestID
		}
		return left.Attempt < right.Attempt
	})

	var oldestAge time.Duration
	for _, assignment := range assignments {
		age := startedAt.Sub(assignment.UpdatedAt)
		if age > oldestAge {
			oldestAge = age
		}
		if err := r.worker.ReconcileAssignment(ctx, assignment); err != nil {
			return CycleReceipt{}, r.abort(
				ctx,
				cycleID,
				fmt.Errorf("assignment %+v: %w", assignment.Key, err),
			)
		}
	}
	completedAt := r.now()
	if completedAt.IsZero() || completedAt.Before(startedAt) {
		return CycleReceipt{}, r.abort(ctx, cycleID, errors.New("completion time precedes cycle start"))
	}
	receipt := CycleReceipt{
		CycleID:         cycleID,
		CompletedAt:     completedAt,
		AssignmentCount: len(assignments),
		OldestAge:       oldestAge,
	}
	if err := r.state.CompleteCycle(ctx, receipt); err != nil {
		// A failed completion write may have committed before returning. Do not
		// overwrite that ambiguity with an abort; the next BeginCycle closes a
		// genuinely incomplete predecessor.
		return CycleReceipt{}, fmt.Errorf("%w: complete cycle: %w", ErrReconciliation, err)
	}
	return receipt, nil
}

func validRecoverableForCycle(assignment RecoverableAssignment, startedAt time.Time) bool {
	return assignment.Key.RepositoryAlias != "" &&
		assignment.Key.RunnerRequestID > 0 &&
		!assignment.UpdatedAt.IsZero() &&
		!assignment.UpdatedAt.After(startedAt)
}

func (r *reconciler) abort(ctx context.Context, cycleID string, cause error) error {
	completedAt := r.now()
	abortErr := r.state.AbortCycle(
		ctx,
		cycleID,
		completedAt,
		ReasonLifecycleReconcile,
	)
	if abortErr != nil {
		return errors.Join(
			fmt.Errorf("%w: %w", ErrReconciliation, cause),
			fmt.Errorf("%w: abort cycle: %w", ErrReconciliation, abortErr),
		)
	}
	return fmt.Errorf("%w: %w", ErrReconciliation, cause)
}
