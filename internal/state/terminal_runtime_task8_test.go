package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestClearTerminalRuntimeRequiresDestroyedCompleteAssignmentAndIsIdempotent(
	t *testing.T,
) {
	t.Parallel()

	store := newHistoryStore(t)
	ctx := context.Background()
	queuedAt := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 8801, 18801, queuedAt)
	receipt, err := store.RecordOffer(
		ctx,
		offer,
		currentPollEvidence(881, queuedAt, queuedAt.Add(time.Second)),
	)
	if err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	recordMessageReceiptForOffers(
		t,
		store,
		offer.RepositoryAlias,
		881,
		queuedAt.Add(30*time.Second),
		offer,
	)
	if err := store.BeginMessageAck(
		ctx,
		offer.RepositoryAlias,
		881,
		queuedAt.Add(time.Minute),
	); err != nil {
		t.Fatalf("BeginMessageAck() = %v", err)
	}
	if err := store.ConfirmMessageAck(
		ctx,
		offer.RepositoryAlias,
		881,
		queuedAt.Add(2*time.Minute),
	); err != nil {
		t.Fatalf("ConfirmMessageAck() = %v", err)
	}
	if err := store.Reserve(
		ctx,
		receipt.Key,
		"task8-terminal-runtime-slot",
		nextCapacitySlotID(t),
	); err != nil {
		t.Fatalf("Reserve() = %v", err)
	}

	if err := store.ClearTerminalRuntime(ctx, receipt.Key); !errors.Is(
		err,
		ErrIdentityConflict,
	) {
		t.Fatalf(
			"ClearTerminalRuntime(pre-terminal) error = %v, want ErrIdentityConflict",
			err,
		)
	}
	assertTerminalRuntimeRowCounts(t, store, receipt.Key, 1, 1)

	advanceTo(t, ctx, store, receipt.Key, controller.StateJobFinished)
	const incompleteKey = "task8-terminal-runtime-incomplete"
	began, err := store.BeginEffect(
		ctx,
		receipt.Key,
		incompleteKey,
		"terminal-cleanup-proof",
	)
	if err != nil || !began {
		t.Fatalf("BeginEffect(incomplete) = (%t, %v), want (true, nil)", began, err)
	}
	if err := store.Advance(ctx, receipt.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(DESTROYED) = %v", err)
	}

	if err := store.ClearTerminalRuntime(ctx, receipt.Key); !errors.Is(
		err,
		ErrIdentityConflict,
	) {
		t.Fatalf(
			"ClearTerminalRuntime(incomplete effect) error = %v, want ErrIdentityConflict",
			err,
		)
	}
	assertTerminalRuntimeRowCounts(t, store, receipt.Key, 1, 1)

	if err := store.CompleteEffect(
		ctx,
		incompleteKey,
		EffectResult{},
	); err != nil {
		t.Fatalf("CompleteEffect() = %v", err)
	}
	if err := store.ClearTerminalRuntime(ctx, receipt.Key); err != nil {
		t.Fatalf("ClearTerminalRuntime() = %v", err)
	}
	assertTerminalRuntimeRowCounts(t, store, receipt.Key, 0, 0)
	if err := store.ClearTerminalRuntime(ctx, receipt.Key); err != nil {
		t.Fatalf("ClearTerminalRuntime(replay) = %v", err)
	}

	if err := store.BindTerminalMessage(ctx, receipt.Key, 881); err != nil {
		t.Fatalf("BindTerminalMessage() = %v", err)
	}
	terminalAt := terminalCheckpoint(t, store, receipt.Key)
	if err := store.CompactTerminal(
		ctx,
		receipt.Key,
		testHistoryLimits(),
		terminalAt.Add(time.Minute),
	); err != nil {
		t.Fatalf("CompactTerminal() = %v", err)
	}
	if err := store.ClearTerminalRuntime(ctx, receipt.Key); err != nil {
		t.Fatalf("ClearTerminalRuntime(compacted replay) = %v", err)
	}
}

func assertTerminalRuntimeRowCounts(
	t *testing.T,
	store *SQLiteStore,
	key controller.AssignmentKey,
	wantReservations int,
	wantSlots int,
) {
	t.Helper()
	var (
		reservations int
		slots        int
	)
	if err := store.DB().QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM reservations r
			 JOIN assignments a ON a.id = r.assignment_id
			 WHERE a.repository_alias = ? AND a.runner_request_id = ? AND a.attempt = ?),
			(SELECT COUNT(*) FROM runner_slots rs
			 JOIN assignments a ON a.id = rs.assignment_id
			 WHERE a.repository_alias = ? AND a.runner_request_id = ? AND a.attempt = ?)
	`,
		key.RepositoryAlias,
		key.RunnerRequestID,
		key.Attempt,
		key.RepositoryAlias,
		key.RunnerRequestID,
		key.Attempt,
	).Scan(&reservations, &slots); err != nil {
		t.Fatalf("read terminal runtime counts: %v", err)
	}
	if reservations != wantReservations || slots != wantSlots {
		t.Fatalf(
			"terminal runtime rows = reservations:%d slots:%d, want %d/%d",
			reservations,
			slots,
			wantReservations,
			wantSlots,
		)
	}
}
