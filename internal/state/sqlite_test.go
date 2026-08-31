package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

// --- test helpers -----------------------------------------------------

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.db")
	s, err := OpenWithHistoryLimits(path, testHistoryLimits())
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits(%q) = %v, want nil", path, err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close() = %v, want nil", err)
		}
	})
	return s
}

func beginTestListenerRelease(
	t *testing.T,
	ctx context.Context,
	s *SQLiteStore,
	key controller.AssignmentKey,
	label string,
) string {
	t.Helper()
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"test-listener-release-v1\x00%s\x00%d\x00%d\x00%s",
		key.RepositoryAlias,
		key.RunnerRequestID,
		key.Attempt,
		label,
	)))
	began, err := s.BeginListenerReleaseEffect(ctx, key, digest)
	if err != nil || !began {
		t.Fatalf("BeginListenerReleaseEffect(%s) = (%v, %v), want (true, nil)", label, began, err)
	}
	return hex.EncodeToString(digest[:])
}

func recordTestOffer(
	t *testing.T,
	ctx context.Context,
	s *SQLiteStore,
	offer OfferIdentity,
) controller.AssignmentKey {
	t.Helper()
	receipt, err := s.RecordOffer(ctx, offer, OfferEvidence{
		Kind:       EvidenceSelectiveReadback,
		ObservedAt: time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("RecordOffer() = %v, want nil", err)
	}
	return receipt.Key
}

var slotCounter atomic.Uint32

func nextCapacitySlotID(t *testing.T) uint32 {
	t.Helper()
	return slotCounter.Add(1)
}

// checkpointStep is one entry of the happy-path walk used by advanceTo.
type checkpointStep struct {
	state  controller.State
	kind   string
	column IdentityColumn
}

var checkpointSteps = []checkpointStep{
	{controller.StateAdapterCreated, "adapter-create", IdentityAdapterContainer},
	{controller.StateAdapterVerified, "adapter-verify", IdentityNone},
	{controller.StateBrokerHeld, "broker-hold", IdentityBrokerContainer},
	{controller.StateBrokerPolicyApplied, "broker-policy-apply", IdentityPolicySocketDigest},
	{controller.StateDialAuthorityReady, "dial-authority-ready", IdentityNone},
	{controller.StateBrokerReleased, "broker-release", IdentityNone},
	{controller.StateEgressVerified, "egress-verify", IdentityNone},
	{controller.StateRunnerHeld, "runner-hold", IdentityRunnerContainer},
	{controller.StateReleaseArmed, "release-arm", IdentityNone},
	{controller.StateListenerReleased, "listener-release", IdentityNone},
	{controller.StateJobRunning, "job-start", IdentityNone},
	{controller.StateJobFinished, "job-finish", IdentityNone},
}

// seedAssignment creates a fresh offer and reserves it, returning the
// resulting key. The assignment is left at StateCapacityReserved.
func seedAssignment(t *testing.T, ctx context.Context, s *SQLiteStore, repositoryAlias string, runnerRequestID int64) controller.AssignmentKey {
	t.Helper()
	key := recordTestOffer(t, ctx, s, OfferIdentity{
		RepositoryAlias: repositoryAlias,
		RunnerRequestID: runnerRequestID,
		WorkflowJobID:   1000 + runnerRequestID,
	})

	opaqueName := fmt.Sprintf("slot-%s-%d", repositoryAlias, runnerRequestID)
	if err := s.Reserve(ctx, key, opaqueName, nextCapacitySlotID(t)); err != nil {
		t.Fatalf("Reserve() = %v, want nil", err)
	}
	return key
}

// advanceTo walks key forward from CAPACITY_RESERVED to target (inclusive)
// through checkpointSteps, performing BeginEffect/CompleteEffect/Advance
// for each intermediate state in exact external-effect order.
func advanceTo(t *testing.T, ctx context.Context, s *SQLiteStore, key controller.AssignmentKey, target controller.State) {
	t.Helper()
	for _, step := range checkpointSteps {
		idemKey := fmt.Sprintf("%s|%d|%d|%s", key.RepositoryAlias, key.RunnerRequestID, key.Attempt, step.kind)
		began, err := s.BeginEffect(ctx, key, idemKey, step.kind)
		if err != nil {
			t.Fatalf("BeginEffect(%s) = %v, want nil", step.kind, err)
		}
		if !began {
			t.Fatalf("BeginEffect(%s) began = false on first call, want true", step.kind)
		}

		identity := ""
		if step.column != IdentityNone {
			identity = fmt.Sprintf("%s-%s-%d", step.kind, key.RepositoryAlias, key.RunnerRequestID)
		}
		if err := s.CompleteEffect(ctx, idemKey, EffectResult{ResultIdentity: identity, Column: step.column}); err != nil {
			t.Fatalf("CompleteEffect(%s) = %v, want nil", step.kind, err)
		}

		if err := s.Advance(ctx, key, step.state); err != nil {
			t.Fatalf("Advance(%s) = %v, want nil", step.state, err)
		}

		if step.state == target {
			return
		}
	}
	t.Fatalf("advanceTo: target state %s not reached by checkpointSteps", target)
}

func findRecoverable(t *testing.T, list []RecoverableAssignment, key controller.AssignmentKey) (RecoverableAssignment, bool) {
	t.Helper()
	for _, ra := range list {
		if ra.Key == key {
			return ra, true
		}
	}
	return RecoverableAssignment{}, false
}

// --- pragma / schema tests ---------------------------------------------

func TestSQLiteOpenAppliesRequiredPragmas(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	var journalMode string
	if err := s.DB().QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want %q", journalMode, "wal")
	}

	var foreignKeys int
	if err := s.DB().QueryRowContext(ctx, "PRAGMA foreign_keys;").Scan(&foreignKeys); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	var synchronous int
	if err := s.DB().QueryRowContext(ctx, "PRAGMA synchronous;").Scan(&synchronous); err != nil {
		t.Fatalf("PRAGMA synchronous: %v", err)
	}
	if synchronous != 3 { // FULL
		t.Errorf("synchronous = %d, want 3 (FULL)", synchronous)
	}

	var busyTimeout int
	if err := s.DB().QueryRowContext(ctx, "PRAGMA busy_timeout;").Scan(&busyTimeout); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}
}

// TestSQLiteDSNUsesImmediateTransactionLock asserts the store's DSN opts
// every non-read-only transaction into BEGIN IMMEDIATE (see Open's doc):
// the readback pragma tests above cover the other four pragmas, but none of
// them exercises _txlock, which only affects transaction-open behavior, not
// a queryable PRAGMA. Checking the DSN string directly is the cheap,
// positive confirmation that immediate-mode locking is actually requested.
func TestSQLiteDSNUsesImmediateTransactionLock(t *testing.T) {
	dsn := dsnForPath("controller.db")
	if !strings.Contains(dsn, "_txlock=immediate") {
		t.Errorf("dsnForPath() = %q, want it to contain _txlock=immediate", dsn)
	}
}

func TestSQLiteForeignKeysEnforced(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.DB().ExecContext(ctx,
		`INSERT INTO effects (assignment_id, idempotency_key, kind, began_at) VALUES (?, ?, ?, ?)`,
		999999, "orphan-effect", "adapter-create", time.Now().UTC().Format(time.RFC3339Nano))
	if err == nil {
		t.Fatal("insert effects row with nonexistent assignment_id succeeded, want foreign key violation")
	}
}

func TestSQLiteExactTableSet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	rows, err := s.DB().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()

	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		got[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	want := []string{"assignments", "runner_slots", "reservations", "effects", "acquisition_state", "network_ledgers", "reconcile_cycles"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("table %q missing from schema", w)
		}
	}
}

// --- happy path ----------------------------------------------------------

func TestSQLiteHappyPathAdjacentTransitionsInExternalEffectOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 1)
	advanceTo(t, ctx, s, key, controller.StateJobFinished)

	if err := s.Advance(ctx, key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(JOB_FINISHED->DESTROYED) = %v, want nil", err)
	}

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	if _, ok := findRecoverable(t, list, key); ok {
		t.Fatal("ListRecoverable() includes a DESTROYED assignment, want excluded")
	}
}

func TestSQLitePersistsCheckpointIdentities(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 2)
	advanceTo(t, ctx, s, key, controller.StateRunnerHeld)

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	ra, ok := findRecoverable(t, list, key)
	if !ok {
		t.Fatal("ListRecoverable() missing seeded assignment")
	}

	if ra.Slot.AdapterContainerID != "adapter-create-owner/repository-2" {
		t.Errorf("Slot.AdapterContainerID = %q, want the adapter-create identity", ra.Slot.AdapterContainerID)
	}
	if ra.Slot.BrokerContainerID != "broker-hold-owner/repository-2" {
		t.Errorf("Slot.BrokerContainerID = %q, want the broker-hold identity", ra.Slot.BrokerContainerID)
	}
	if ra.Slot.RunnerContainerID != "runner-hold-owner/repository-2" {
		t.Errorf("Slot.RunnerContainerID = %q, want the runner-hold identity", ra.Slot.RunnerContainerID)
	}
	if ra.Slot.CapacitySlotID == 0 {
		t.Error("Slot.CapacitySlotID = 0, want the stable reserved capacity-slot id")
	}
	if ra.Slot.OpaqueName == "" {
		t.Error("Slot.OpaqueName is empty, want the stable slot name from Reserve")
	}
}

// --- idempotent replay -----------------------------------------------------

func TestSQLiteIdempotentEffectReplay(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 3)

	idemKey := "owner/repository|3|0|adapter-create"
	began1, err := s.BeginEffect(ctx, key, idemKey, "adapter-create")
	if err != nil || !began1 {
		t.Fatalf("BeginEffect() first call = (%v, %v), want (true, nil)", began1, err)
	}
	began2, err := s.BeginEffect(ctx, key, idemKey, "adapter-create")
	if err != nil {
		t.Fatalf("BeginEffect() replay = %v, want nil error", err)
	}
	if began2 {
		t.Error("BeginEffect() replay began = true, want false (already recorded)")
	}

	var count int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM effects WHERE idempotency_key = ?`, idemKey).Scan(&count); err != nil {
		t.Fatalf("count effects rows: %v", err)
	}
	if count != 1 {
		t.Errorf("effects rows for idempotency key = %d, want 1", count)
	}

	result := EffectResult{ResultIdentity: "adapter-container-abc", Column: IdentityAdapterContainer}
	if err := s.CompleteEffect(ctx, idemKey, result); err != nil {
		t.Fatalf("CompleteEffect() first call = %v, want nil", err)
	}

	var firstCompletedAt string
	if err := s.DB().QueryRowContext(ctx, `SELECT completed_at FROM effects WHERE idempotency_key = ?`, idemKey).Scan(&firstCompletedAt); err != nil {
		t.Fatalf("read completed_at after first CompleteEffect: %v", err)
	}
	if firstCompletedAt == "" {
		t.Fatal("completed_at is empty after first CompleteEffect, want a timestamp")
	}

	time.Sleep(2 * time.Millisecond) // ensure now() would differ if completed_at were wrongly rewritten
	if err := s.CompleteEffect(ctx, idemKey, result); err != nil {
		t.Fatalf("CompleteEffect() replay = %v, want nil (idempotent)", err)
	}

	var secondCompletedAt string
	if err := s.DB().QueryRowContext(ctx, `SELECT completed_at FROM effects WHERE idempotency_key = ?`, idemKey).Scan(&secondCompletedAt); err != nil {
		t.Fatalf("read completed_at after replayed CompleteEffect: %v", err)
	}
	if secondCompletedAt != firstCompletedAt {
		t.Errorf("completed_at after replay = %q, want unchanged %q (idempotent replay must not rewrite the completion timestamp)", secondCompletedAt, firstCompletedAt)
	}

	if err := s.Advance(ctx, key, controller.StateAdapterCreated); err != nil {
		t.Fatalf("Advance() first call = %v, want nil", err)
	}
	if err := s.Advance(ctx, key, controller.StateAdapterCreated); err != nil {
		t.Fatalf("Advance() replay = %v, want nil (idempotent no-op)", err)
	}
}

func TestSQLiteListenerReleaseEffectRequiresExactBindingDigest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := seedAssignment(t, ctx, s, "owner/repository", 32)
	var bindingDigest [sha256.Size]byte
	bindingDigest[0] = 1
	bindingDigest[sha256.Size-1] = 2

	if began, err := s.BeginEffect(
		ctx,
		key,
		"unbound-listener-release",
		LifecycleEffectListenerRelease,
	); began || !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("generic listener release = (%t, %v), want bound-only rejection", began, err)
	}
	if began, err := s.BeginListenerReleaseEffect(ctx, key, bindingDigest); err != nil || !began {
		t.Fatalf("BeginListenerReleaseEffect(first) = (%t, %v), want (true, nil)", began, err)
	}
	if began, err := s.BeginListenerReleaseEffect(ctx, key, bindingDigest); err != nil || began {
		t.Fatalf("BeginListenerReleaseEffect(replay) = (%t, %v), want (false, nil)", began, err)
	}
	different := bindingDigest
	different[1] = 3
	if began, err := s.BeginListenerReleaseEffect(ctx, key, different); began ||
		!errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("changed listener binding = (%t, %v), want identity conflict", began, err)
	}

	var idempotencyKey, kind string
	if err := s.DB().QueryRowContext(ctx, `
		SELECT idempotency_key, kind
		FROM effects
		WHERE assignment_id = (
			SELECT id FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		)
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(
		&idempotencyKey,
		&kind,
	); err != nil {
		t.Fatalf("read listener binding: %v", err)
	}
	if want := hex.EncodeToString(bindingDigest[:]); idempotencyKey != want ||
		kind != LifecycleEffectListenerRelease {
		t.Fatalf("persisted listener binding = (%q, %q), want (%q, %q)",
			idempotencyKey, kind, want, LifecycleEffectListenerRelease)
	}
}

func TestSQLiteRaceBeginListenerReleaseSingleBoundRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := seedAssignment(t, ctx, s, "owner/repository", 33)
	var bindingDigest [sha256.Size]byte
	bindingDigest[0] = 4

	const workers = 8
	var wg sync.WaitGroup
	began := make([]bool, workers)
	errs := make([]error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(index int) {
			defer wg.Done()
			began[index], errs[index] = s.BeginListenerReleaseEffect(
				ctx,
				key,
				bindingDigest,
			)
		}(i)
	}
	wg.Wait()

	trueCount := 0
	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("worker %d: BeginListenerReleaseEffect = %v", i, errs[i])
		}
		if began[i] {
			trueCount++
		}
	}
	if trueCount != 1 {
		t.Fatalf("listener begins = %d, want one", trueCount)
	}
	var count int
	if err := s.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM effects
		WHERE assignment_id = (
			SELECT id FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		) AND kind = ?
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt,
		LifecycleEffectListenerRelease).Scan(&count); err != nil {
		t.Fatalf("count listener effects: %v", err)
	}
	if count != 1 {
		t.Fatalf("listener effect rows = %d, want one", count)
	}
}

func TestSQLiteCompleteEffectRejectsZeroRowConditionalUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := seedAssignment(t, ctx, s, "owner/repository", 31)
	const idempotencyKey = "owner/repository|31|0|adapter-create"
	if began, err := s.BeginEffect(ctx, key, idempotencyKey, "adapter-create"); err != nil || !began {
		t.Fatalf("BeginEffect() = (%v, %v), want (true, nil)", began, err)
	}
	if _, err := s.DB().ExecContext(ctx, `
		CREATE TRIGGER ignore_test_effect_completion
		BEFORE UPDATE OF completed_at ON effects
		WHEN OLD.idempotency_key = 'owner/repository|31|0|adapter-create'
		BEGIN
			SELECT RAISE(IGNORE);
		END
	`); err != nil {
		t.Fatalf("create zero-row update fixture: %v", err)
	}

	result := EffectResult{
		ResultIdentity: "adapter-container-31",
		Column:         IdentityAdapterContainer,
	}
	if err := s.CompleteEffect(ctx, idempotencyKey, result); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("CompleteEffect(zero-row update) err = %v, want ErrIdentityConflict", err)
	}

	var completedAt, adapterContainer sql.NullString
	if err := s.DB().QueryRowContext(ctx, `
		SELECT e.completed_at, rs.adapter_container_id
		FROM effects e
		JOIN runner_slots rs ON rs.assignment_id = e.assignment_id
		WHERE e.idempotency_key = ?
	`, idempotencyKey).Scan(&completedAt, &adapterContainer); err != nil {
		t.Fatalf("read zero-row completion state: %v", err)
	}
	if completedAt.Valid || adapterContainer.Valid {
		t.Fatalf(
			"zero-row effect update diverged effect/slot state: completed=%v slot=%v",
			completedAt,
			adapterContainer,
		)
	}
}

func TestSQLiteRaceBeginEffectSingleRowPerKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 4)
	idemKey := "owner/repository|4|0|adapter-create"

	const workers = 8
	var wg sync.WaitGroup
	began := make([]bool, workers)
	errs := make([]error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			began[i], errs[i] = s.BeginEffect(ctx, key, idemKey, "adapter-create")
		}(i)
	}
	wg.Wait()

	trueCount := 0
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d: BeginEffect() = %v, want nil", i, errs[i])
		}
		if began[i] {
			trueCount++
		}
	}
	if trueCount != 1 {
		t.Errorf("workers reporting began=true = %d, want exactly 1", trueCount)
	}

	var count int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM effects WHERE idempotency_key = ?`, idemKey).Scan(&count); err != nil {
		t.Fatalf("count effects rows: %v", err)
	}
	if count != 1 {
		t.Errorf("effects rows for idempotency key = %d, want 1", count)
	}
}

// --- pre-release failure -> DESTROYED --------------------------------------

func TestSQLitePreReleaseFailureDestroysAssignment(t *testing.T) {
	preReleaseStates := []controller.State{
		controller.StateCapacityReserved,
		controller.StateAdapterCreated,
		controller.StateAdapterVerified,
		controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified,
		controller.StateRunnerHeld,
		controller.StateReleaseArmed,
	}

	for i, target := range preReleaseStates {
		t.Run(string(target), func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()

			key := seedAssignment(t, ctx, s, "owner/repository", int64(100+i))
			if target != controller.StateCapacityReserved {
				advanceTo(t, ctx, s, key, target)
			}

			if err := s.Advance(ctx, key, controller.StateDestroyed); err != nil {
				t.Fatalf("Advance(%s->DESTROYED) = %v, want nil", target, err)
			}

			list, err := s.ListRecoverable(ctx)
			if err != nil {
				t.Fatalf("ListRecoverable() = %v, want nil", err)
			}
			if _, ok := findRecoverable(t, list, key); ok {
				t.Error("ListRecoverable() includes a DESTROYED assignment, want excluded")
			}
		})
	}
}

// --- reject skipped/reversed ------------------------------------------------

func TestSQLiteRejectsSkippedAndReversedStates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 5)

	if err := s.Advance(ctx, key, controller.StateAdapterVerified); err == nil {
		t.Fatal("Advance(CAPACITY_RESERVED->ADAPTER_VERIFIED) = nil, want error (skipped state)")
	}
	if err := s.Advance(ctx, key, controller.StateReceived); err == nil {
		t.Fatal("Advance(CAPACITY_RESERVED->RECEIVED) = nil, want error (reversed state)")
	}

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	ra, ok := findRecoverable(t, list, key)
	if !ok {
		t.Fatal("ListRecoverable() missing assignment")
	}
	if ra.State != controller.StateCapacityReserved {
		t.Errorf("State after rejected transitions = %s, want unchanged CAPACITY_RESERVED", ra.State)
	}
}

// --- post-release ambiguity -------------------------------------------------

func TestSQLitePostReleaseAmbiguityNoDuplicateRelease(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 6)
	advanceTo(t, ctx, s, key, controller.StateListenerReleased)

	if err := s.MarkAmbiguous(ctx, key, "listener-release-timeout"); err != nil {
		t.Fatalf("MarkAmbiguous() = %v, want nil", err)
	}
	// Idempotent replay of MarkAmbiguous must not create a second record.
	if err := s.MarkAmbiguous(ctx, key, "listener-release-timeout"); err != nil {
		t.Fatalf("MarkAmbiguous() replay = %v, want nil", err)
	}

	if err := s.Advance(ctx, key, controller.StateDestroyed); err == nil {
		t.Fatal("Advance(LISTENER_RELEASED->DESTROYED) = nil, want error (no blind post-release destroy)")
	}

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	ra, ok := findRecoverable(t, list, key)
	if !ok {
		t.Fatal("ListRecoverable() missing assignment")
	}
	if ra.State != controller.StateListenerReleased {
		t.Errorf("State after rejected post-release destroy = %s, want unchanged LISTENER_RELEASED", ra.State)
	}
	if !ra.Ambiguous {
		t.Error("Ambiguous = false, want true")
	}
	if ra.AmbiguousReason != "listener-release-timeout" {
		t.Errorf("AmbiguousReason = %q, want %q", ra.AmbiguousReason, "listener-release-timeout")
	}
}

// --- store self-enforces the released invariant (Fix 1) --------------------
//
// Advance no longer accepts a caller-supplied released argument; it derives
// the invariant itself from the row's persisted current state via
// controller.HasReleasedListener. These tests prove the store rejects a
// post-release skip-to-DESTROYED exactly as if a caller had (correctly)
// passed released=true under the old API, still accepts the legal
// post-release and pre-release paths, and that the persisted
// assignments.released column tracks the LISTENER_RELEASED boundary
// precisely.

func TestSQLiteAdvanceRejectsSkipToDestroyedAfterRelease(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 16)
	advanceTo(t, ctx, s, key, controller.StateJobRunning)

	if err := s.Advance(ctx, key, controller.StateDestroyed); err == nil {
		t.Fatal("Advance(JOB_RUNNING->DESTROYED) = nil, want error (post-release skip of JOB_FINISHED, regardless of caller expectation)")
	}

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	ra, ok := findRecoverable(t, list, key)
	if !ok {
		t.Fatal("ListRecoverable() missing assignment")
	}
	if ra.State != controller.StateJobRunning {
		t.Errorf("State after rejected skip-to-DESTROYED = %s, want unchanged JOB_RUNNING", ra.State)
	}
}

func TestSQLiteAdvanceFullPostReleasePathAccepted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 17)
	advanceTo(t, ctx, s, key, controller.StateJobFinished)

	if err := s.Advance(ctx, key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(JOB_FINISHED->DESTROYED) = %v, want nil (full post-release path JOB_RUNNING->JOB_FINISHED->DESTROYED)", err)
	}

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	if _, ok := findRecoverable(t, list, key); ok {
		t.Fatal("ListRecoverable() includes a DESTROYED assignment, want excluded")
	}
}

func TestSQLiteAdvancePreReleaseTeardownAccepted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 18)
	advanceTo(t, ctx, s, key, controller.StateBrokerHeld)

	if err := s.Advance(ctx, key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(BROKER_HELD->DESTROYED) = %v, want nil (pre-release teardown still accepted)", err)
	}

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	if _, ok := findRecoverable(t, list, key); ok {
		t.Fatal("ListRecoverable() includes a DESTROYED assignment, want excluded")
	}
}

func TestSQLiteReleasedColumnMatchesListenerReleaseBoundary(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 19)

	readReleased := func() bool {
		t.Helper()
		var releasedInt int
		if err := s.DB().QueryRowContext(ctx,
			`SELECT released FROM assignments WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?`,
			key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(&releasedInt); err != nil {
			t.Fatalf("read released column: %v", err)
		}
		return releasedInt != 0
	}

	if got, want := readReleased(), controller.HasReleasedListener(controller.StateCapacityReserved); got != want {
		t.Errorf("released column at CAPACITY_RESERVED = %v, want %v", got, want)
	}

	for _, step := range checkpointSteps {
		idemKey := fmt.Sprintf("%s|%d|%d|%s", key.RepositoryAlias, key.RunnerRequestID, key.Attempt, step.kind)
		if _, err := s.BeginEffect(ctx, key, idemKey, step.kind); err != nil {
			t.Fatalf("BeginEffect(%s) = %v, want nil", step.kind, err)
		}
		identity := ""
		if step.column != IdentityNone {
			identity = fmt.Sprintf("%s-%s-%d", step.kind, key.RepositoryAlias, key.RunnerRequestID)
		}
		if err := s.CompleteEffect(ctx, idemKey, EffectResult{ResultIdentity: identity, Column: step.column}); err != nil {
			t.Fatalf("CompleteEffect(%s) = %v, want nil", step.kind, err)
		}
		if err := s.Advance(ctx, key, step.state); err != nil {
			t.Fatalf("Advance(%s) = %v, want nil", step.state, err)
		}

		want := controller.HasReleasedListener(step.state)
		if got := readReleased(); got != want {
			t.Errorf("released column after advancing to %s = %v, want %v (iff state is at/after LISTENER_RELEASED)", step.state, got, want)
		}
	}
}

// --- unique offer / runner-slot keys ---------------------------------------

func TestSQLiteRecordOfferIsUniqueAndIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	offer := OfferIdentity{RepositoryAlias: "owner/repository", RunnerRequestID: 7, WorkflowJobID: 1007}
	key1 := recordTestOffer(t, ctx, s, offer)
	key2 := recordTestOffer(t, ctx, s, offer)
	if key1 != key2 {
		t.Errorf("RecordOffer() replay key = %+v, want unchanged %+v", key2, key1)
	}

	var count int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM assignments WHERE repository_alias = ? AND runner_request_id = ?`,
		offer.RepositoryAlias, offer.RunnerRequestID).Scan(&count); err != nil {
		t.Fatalf("count assignments rows: %v", err)
	}
	if count != 1 {
		t.Errorf("assignments rows for offer = %d, want 1", count)
	}
}

func TestSQLiteReserveRejectsDuplicateCapacitySlot(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	sharedSlotID := nextCapacitySlotID(t)

	keyA := recordTestOffer(t, ctx, s, OfferIdentity{
		RepositoryAlias: "owner/repository",
		RunnerRequestID: 8,
		WorkflowJobID:   1008,
	})
	if err := s.Reserve(ctx, keyA, "slot-a", sharedSlotID); err != nil {
		t.Fatalf("Reserve(A) = %v, want nil", err)
	}

	keyB := recordTestOffer(t, ctx, s, OfferIdentity{
		RepositoryAlias: "owner/repository",
		RunnerRequestID: 9,
		WorkflowJobID:   1009,
	})
	if err := s.Reserve(ctx, keyB, "slot-b", sharedSlotID); err == nil {
		t.Fatal("Reserve(B) with duplicate capacity slot id = nil, want error")
	}

	// No partial write: B's assignment must remain at RECEIVED and have no
	// runner_slots row.
	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	ra, ok := findRecoverable(t, list, keyB)
	if !ok {
		t.Fatal("ListRecoverable() missing assignment B")
	}
	if ra.State != controller.StateReceived {
		t.Errorf("assignment B state = %s, want unchanged RECEIVED (transaction rolled back)", ra.State)
	}

	var slotCount int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM runner_slots WHERE opaque_name = ?`, "slot-b").Scan(&slotCount); err != nil {
		t.Fatalf("count runner_slots rows: %v", err)
	}
	if slotCount != 0 {
		t.Errorf("runner_slots rows for rejected reservation = %d, want 0 (no partial write)", slotCount)
	}
}

func TestSQLiteReserveRejectsDuplicateOpaqueName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	keyA := recordTestOffer(t, ctx, s, OfferIdentity{
		RepositoryAlias: "owner/repository",
		RunnerRequestID: 10,
		WorkflowJobID:   1010,
	})
	if err := s.Reserve(ctx, keyA, "shared-opaque-name", nextCapacitySlotID(t)); err != nil {
		t.Fatalf("Reserve(A) = %v, want nil", err)
	}

	keyB := recordTestOffer(t, ctx, s, OfferIdentity{
		RepositoryAlias: "owner/repository",
		RunnerRequestID: 11,
		WorkflowJobID:   1011,
	})
	if err := s.Reserve(ctx, keyB, "shared-opaque-name", nextCapacitySlotID(t)); err == nil {
		t.Fatal("Reserve(B) with duplicate opaque name = nil, want error")
	}
}

func TestSQLiteBindRunnerRecordsUpstreamBindingUniquely(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	keyA := seedAssignment(t, ctx, s, "owner/repository", 12)
	keyB := seedAssignment(t, ctx, s, "owner/repository", 13)
	const observedRequestID = int64(912)

	if err := s.BindRunner(ctx, keyA, 555, observedRequestID, "runner-container-a"); err != nil {
		t.Fatalf("BindRunner(A) = %v, want nil", err)
	}
	if err := s.BindRunner(ctx, keyA, 555, observedRequestID, "runner-container-a"); err != nil {
		t.Fatalf("BindRunner(A replay) = %v, want nil", err)
	}
	if err := s.BindRunner(ctx, keyA, 555, observedRequestID+1, "runner-container-a"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BindRunner(A conflicting request) = %v, want ErrIdentityConflict", err)
	}
	if err := s.BindRunner(ctx, keyB, 555, observedRequestID+2, "runner-container-b"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BindRunner(B) with duplicate upstream runner id = %v, want ErrIdentityConflict", err)
	}

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	ra, ok := findRecoverable(t, list, keyA)
	if !ok {
		t.Fatal("ListRecoverable() missing assignment A")
	}
	if ra.Slot.UpstreamRunnerID != 555 {
		t.Errorf("Slot.UpstreamRunnerID = %d, want 555", ra.Slot.UpstreamRunnerID)
	}
	if ra.Slot.BoundRequestID != observedRequestID {
		t.Errorf("Slot.BoundRequestID = %d, want observed request %d", ra.Slot.BoundRequestID, observedRequestID)
	}
}

func TestSQLiteAdvancePreReleaseDestroyedRejectsBegunListenerRelease(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	safeKey := seedAssignment(t, ctx, s, "owner/repository", 120)
	advanceTo(t, ctx, s, safeKey, controller.StateReleaseArmed)
	if err := s.AdvancePreReleaseDestroyed(ctx, safeKey); err != nil {
		t.Fatalf("AdvancePreReleaseDestroyed(no listener effect) = %v, want nil", err)
	}

	ambiguousKey := seedAssignment(t, ctx, s, "owner/repository", 121)
	advanceTo(t, ctx, s, ambiguousKey, controller.StateReleaseArmed)
	beginTestListenerRelease(t, ctx, s, ambiguousKey, "ambiguous-121")
	if err := s.AdvancePreReleaseDestroyed(ctx, ambiguousKey); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("AdvancePreReleaseDestroyed(begun listener effect) = %v, want ErrIdentityConflict", err)
	}
	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v", err)
	}
	got, ok := findRecoverable(t, list, ambiguousKey)
	if !ok || got.State != controller.StateReleaseArmed {
		t.Fatalf("ambiguous assignment = (%+v, %v), want RELEASE_ARMED and retained", got, ok)
	}
}

func TestSQLiteApplyRunnerObservationAtomicallyResolvesAmbiguousRelease(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := seedAssignment(t, ctx, s, "owner/repository", 122)
	advanceTo(t, ctx, s, key, controller.StateReleaseArmed)

	beginTestListenerRelease(t, ctx, s, key, "observed-122")
	if err := s.MarkAmbiguous(ctx, key, "listener-release-checkpoint"); err != nil {
		t.Fatalf("MarkAmbiguous() = %v", err)
	}
	before, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	if !ok || before.Slot.RunnerContainerID == "" {
		t.Fatalf("runner slot before observation = (%+v, %v), want persisted runner container", before, ok)
	}
	observation := RunnerObservation{
		UpstreamRunnerID:  6122,
		BoundRequestID:    7122,
		RunnerContainerID: before.Slot.RunnerContainerID,
		ObservedAt:        time.Now().Add(-time.Second),
	}
	if err := s.ApplyRunnerObservation(ctx, key, observation); err != nil {
		t.Fatalf("ApplyRunnerObservation(started) = %v", err)
	}
	if err := s.ApplyRunnerObservation(ctx, key, observation); err != nil {
		t.Fatalf("ApplyRunnerObservation(replay) = %v", err)
	}
	after, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	if !ok {
		t.Fatal("observed assignment missing")
	}
	if after.State != controller.StateJobRunning || !after.Released {
		t.Fatalf("observed state/released = (%s,%v), want (JOB_RUNNING,true)", after.State, after.Released)
	}
	if after.Ambiguous || after.AmbiguousReason != "" {
		t.Fatalf("ambiguity after exact observation = (%v,%q), want cleared", after.Ambiguous, after.AmbiguousReason)
	}
	if after.Slot.UpstreamRunnerID != observation.UpstreamRunnerID ||
		after.Slot.BoundRequestID != observation.BoundRequestID ||
		after.Slot.RunnerContainerID != observation.RunnerContainerID {
		t.Fatalf("observed binding = %+v, want exact tuple %+v", after.Slot, observation)
	}
	if after.UpdatedAt.Before(before.UpdatedAt) {
		t.Fatalf(
			"ApplyRunnerObservation moved durable time backward: before=%s after=%s event=%s",
			before.UpdatedAt,
			after.UpdatedAt,
			observation.ObservedAt,
		)
	}
	if !after.UpdatedAt.After(observation.ObservedAt) {
		t.Fatalf(
			"ApplyRunnerObservation persisted upstream event time instead of local observation time: after=%s event=%s",
			after.UpdatedAt,
			observation.ObservedAt,
		)
	}

	conflict := observation
	conflict.BoundRequestID++
	if err := s.ApplyRunnerObservation(ctx, key, conflict); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ApplyRunnerObservation(conflict) = %v, want ErrIdentityConflict", err)
	}
}

func TestSQLiteApplyRunnerObservationSerializesWithPreRunningRevocation(t *testing.T) {
	observationFor := func(
		t *testing.T,
		ctx context.Context,
		s *SQLiteStore,
		key controller.AssignmentKey,
	) RunnerObservation {
		t.Helper()
		record, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
		if !ok || record.Slot.RunnerContainerID == "" {
			t.Fatalf("release-armed assignment = (%+v, %v), want persisted runner container", record, ok)
		}
		return RunnerObservation{
			UpstreamRunnerID:  6200 + key.RunnerRequestID,
			BoundRequestID:    7200 + key.RunnerRequestID,
			RunnerContainerID: record.Slot.RunnerContainerID,
			ObservedAt:        time.Now().Add(-time.Second),
		}
	}

	t.Run("revocation commits first", func(t *testing.T) {
		s := newTestStore(t)
		ctx := context.Background()
		key := seedAssignment(t, ctx, s, "owner/repository", 127)
		advanceTo(t, ctx, s, key, controller.StateReleaseArmed)
		beginTestListenerRelease(t, ctx, s, key, "revoke-first")
		observation := observationFor(t, ctx, s, key)

		marked, err := s.MarkPreRunningRevoked(ctx, 9, time.Now().Add(-time.Second))
		if err != nil {
			t.Fatalf("MarkPreRunningRevoked() = %v", err)
		}
		if len(marked) != 1 || marked[0] != key {
			t.Fatalf("MarkPreRunningRevoked() = %+v, want [%+v]", marked, key)
		}
		if err := s.ApplyRunnerObservation(ctx, key, observation); !errors.Is(err, ErrIdentityConflict) {
			t.Fatalf("ApplyRunnerObservation(revoked) = %v, want ErrIdentityConflict", err)
		}

		record, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
		if !ok || record.State != controller.StateReleaseArmed {
			t.Fatalf("revoked assignment = (%+v, %v), want RELEASE_ARMED and retained", record, ok)
		}
		if record.Slot.UpstreamRunnerID != 0 || record.Slot.BoundRequestID != 0 {
			t.Fatalf("revoked runner binding = %+v, want no upstream binding", record.Slot)
		}
	})

	t.Run("runner admission commits first", func(t *testing.T) {
		s := newTestStore(t)
		ctx := context.Background()
		key := seedAssignment(t, ctx, s, "owner/repository", 128)
		advanceTo(t, ctx, s, key, controller.StateReleaseArmed)
		beginTestListenerRelease(t, ctx, s, key, "admit-first")
		observation := observationFor(t, ctx, s, key)

		if err := s.ApplyRunnerObservation(ctx, key, observation); err != nil {
			t.Fatalf("ApplyRunnerObservation(started) = %v", err)
		}
		marked, err := s.MarkPreRunningRevoked(ctx, 9, time.Now().Add(-time.Second))
		if err != nil {
			t.Fatalf("MarkPreRunningRevoked() = %v", err)
		}
		if len(marked) != 0 {
			t.Fatalf("MarkPreRunningRevoked() = %+v, want running assignment preserved", marked)
		}

		observation.Finished = true
		if err := s.ApplyRunnerObservation(ctx, key, observation); err != nil {
			t.Fatalf("ApplyRunnerObservation(completed) = %v", err)
		}
		record, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
		if !ok || record.State != controller.StateJobFinished {
			t.Fatalf("completed assignment = (%+v, %v), want JOB_FINISHED", record, ok)
		}
	})
}

func TestSQLiteResolvePostReleaseRequiresEffectAndPersistsEvidence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := seedAssignment(t, ctx, s, "owner/repository", 123)
	advanceTo(t, ctx, s, key, controller.StateReleaseArmed)

	evidence := sha256.Sum256([]byte("closed-two-sided-readback"))
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseDestroyed,
		evidence,
		time.Now().Add(-time.Second),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ResolvePostRelease(no listener effect) = %v, want ErrIdentityConflict", err)
	}
	beginTestListenerRelease(t, ctx, s, key, "resolve-123")
	if err := s.MarkAmbiguous(ctx, key, "release-outcome-unknown"); err != nil {
		t.Fatalf("MarkAmbiguous() = %v", err)
	}
	marked, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	if !ok {
		t.Fatal("ambiguous release assignment missing")
	}
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseDestroyed,
		evidence,
		marked.UpdatedAt,
	); err != nil {
		t.Fatalf("ResolvePostRelease(destroyed) = %v", err)
	}
	if _, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key); ok {
		t.Fatal("resolved DESTROYED assignment remains recoverable")
	}
	record, err := s.LookupAssignmentEffect(ctx, key, LifecycleEffectPostReleaseResolution)
	if err != nil {
		t.Fatalf("LookupAssignmentEffect(resolution) = %v", err)
	}
	if record.State != EffectCompleted || record.ResultIdentity != fmt.Sprintf("%x", evidence) {
		t.Fatalf("resolution effect = %+v, want completed digest %x", record, evidence)
	}
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseDestroyed,
		[sha256.Size]byte{},
		time.Now().Add(-time.Second),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ResolvePostRelease(zero digest) = %v, want ErrIdentityConflict", err)
	}
}

func TestSQLiteResolvePostReleaseAllowsForwardEvidenceSupersession(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := seedAssignment(t, ctx, s, "owner/repository", 127)
	advanceTo(t, ctx, s, key, controller.StateReleaseArmed)
	beginTestListenerRelease(t, ctx, s, key, "progress-127")

	liveEvidence := sha256.Sum256([]byte("release-armed-both-live"))
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseListenerReleased,
		liveEvidence,
		time.Now(),
	); err != nil {
		t.Fatalf("ResolvePostRelease(listener released) = %v", err)
	}
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseListenerReleased,
		liveEvidence,
		time.Now(),
	); err != nil {
		t.Fatalf("ResolvePostRelease(listener exact replay) = %v", err)
	}
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseListenerReleased,
		sha256.Sum256([]byte("same-state-conflicting-evidence")),
		time.Now(),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf(
			"ResolvePostRelease(listener conflicting replay) = %v, want ErrIdentityConflict",
			err,
		)
	}
	destroyedEvidence := sha256.Sum256([]byte("listener-released-both-absent"))
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseDestroyed,
		destroyedEvidence,
		time.Now(),
	); err != nil {
		t.Fatalf("ResolvePostRelease(destroyed progression) = %v", err)
	}
	if _, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key); ok {
		t.Fatal("forward-resolved DESTROYED assignment remains recoverable")
	}
	record, err := s.LookupAssignmentEffect(
		ctx,
		key,
		LifecycleEffectPostReleaseResolution,
	)
	if err != nil {
		t.Fatalf("LookupAssignmentEffect(resolution) = %v", err)
	}
	if record.State != EffectCompleted ||
		record.ResultIdentity != fmt.Sprintf("%x", destroyedEvidence) {
		t.Fatalf(
			"superseded resolution effect = %+v, want final digest %x",
			record,
			destroyedEvidence,
		)
	}
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseDestroyed,
		destroyedEvidence,
		time.Now(),
	); err != nil {
		t.Fatalf("ResolvePostRelease(destroyed exact replay) = %v", err)
	}
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseDestroyed,
		sha256.Sum256([]byte("destroyed-conflicting-evidence")),
		time.Now(),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf(
			"ResolvePostRelease(destroyed conflicting replay) = %v, want ErrIdentityConflict",
			err,
		)
	}
}

func TestValidResolutionDigestRequiresCanonicalSHA256Hex(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: strings.Repeat("a", sha256.Size*2), want: true},
		{value: strings.Repeat("A", sha256.Size*2), want: false},
		{value: strings.Repeat("g", sha256.Size*2), want: false},
		{value: strings.Repeat("0", sha256.Size*2-1), want: false},
		{value: "", want: false},
	}
	for _, test := range tests {
		if got := validResolutionDigest(test.value); got != test.want {
			t.Errorf(
				"validResolutionDigest(%q) = %v, want %v",
				test.value,
				got,
				test.want,
			)
		}
	}
}

func TestSQLitePostReleaseEvidenceRejectsFailedListenerEffect(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := seedAssignment(t, ctx, s, "owner/repository", 124)
	advanceTo(t, ctx, s, key, controller.StateReleaseArmed)

	idempotencyKey := beginTestListenerRelease(t, ctx, s, key, "failed-124")
	if err := s.CompleteEffect(ctx, idempotencyKey, EffectResult{
		Column:     IdentityNone,
		ReasonCode: "listener-release-failed",
	}); err != nil {
		t.Fatalf("CompleteEffect(failed listener release) = %v", err)
	}
	record, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	if !ok {
		t.Fatal("release-armed assignment missing")
	}
	observation := RunnerObservation{
		UpstreamRunnerID:  6124,
		BoundRequestID:    7124,
		RunnerContainerID: record.Slot.RunnerContainerID,
		ObservedAt:        time.Now().Add(-time.Second),
	}
	if err := s.ApplyRunnerObservation(
		ctx,
		key,
		observation,
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ApplyRunnerObservation(failed release effect) = %v, want ErrIdentityConflict", err)
	}
	if err := s.ResolvePostRelease(
		ctx,
		key,
		controller.PostReleaseDestroyed,
		sha256.Sum256([]byte("failed-release-is-not-evidence")),
		time.Now().Add(-time.Second),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ResolvePostRelease(failed release effect) = %v, want ErrIdentityConflict", err)
	}
}

func TestSQLitePostReleaseResolutionRejectsBackwardTimeAndNewTerminalEvidence(t *testing.T) {
	t.Run("backward durable time", func(t *testing.T) {
		s := newTestStore(t)
		ctx := context.Background()
		key := seedAssignment(t, ctx, s, "owner/repository", 125)
		advanceTo(t, ctx, s, key, controller.StateReleaseArmed)
		beginTestListenerRelease(t, ctx, s, key, "pending-125")
		record, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
		if !ok {
			t.Fatal("release-armed assignment missing")
		}
		if err := s.ResolvePostRelease(
			ctx,
			key,
			controller.PostReleaseDestroyed,
			sha256.Sum256([]byte("backward-resolution")),
			record.UpdatedAt.Add(-time.Second),
		); !errors.Is(err, ErrIdentityConflict) {
			t.Fatalf("ResolvePostRelease(backward time) = %v, want ErrIdentityConflict", err)
		}
	})

	t.Run("new evidence after normal job finish", func(t *testing.T) {
		s := newTestStore(t)
		ctx := context.Background()
		key := seedAssignment(t, ctx, s, "owner/repository", 126)
		advanceTo(t, ctx, s, key, controller.StateReleaseArmed)
		beginTestListenerRelease(t, ctx, s, key, "observed-126")
		record, ok := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
		if !ok {
			t.Fatal("release-armed assignment missing")
		}
		if err := s.ApplyRunnerObservation(ctx, key, RunnerObservation{
			UpstreamRunnerID:  6126,
			BoundRequestID:    7126,
			RunnerContainerID: record.Slot.RunnerContainerID,
			Finished:          true,
			ObservedAt:        time.Now().Add(-time.Second),
		}); err != nil {
			t.Fatalf("ApplyRunnerObservation(completed) = %v", err)
		}
		if err := s.ResolvePostRelease(
			ctx,
			key,
			controller.PostReleaseJobFinished,
			sha256.Sum256([]byte("invented-after-normal-finish")),
			time.Now(),
		); !errors.Is(err, ErrIdentityConflict) {
			t.Fatalf("ResolvePostRelease(new terminal evidence) = %v, want ErrIdentityConflict", err)
		}
	})
}

func TestSQLiteReconcileCyclesRemainBoundedAcrossCrashAndCompletion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	started := time.Now().Add(-10 * time.Second).UTC()

	if err := s.BeginReconcileCycle(ctx, "cycle-1", started); err != nil {
		t.Fatalf("BeginReconcileCycle(cycle-1) = %v", err)
	}
	if err := s.BeginReconcileCycle(ctx, "cycle-2", started.Add(time.Second)); err != nil {
		t.Fatalf("BeginReconcileCycle(cycle-2) = %v", err)
	}
	assertCycleRowCount(t, ctx, s, 2)

	receipt := controller.CycleReceipt{
		CycleID:         "cycle-2",
		CompletedAt:     started.Add(2 * time.Second),
		AssignmentCount: 4,
		OldestAge:       31 * time.Second,
	}
	if err := s.CompleteReconcileCycle(ctx, receipt); err != nil {
		t.Fatalf("CompleteReconcileCycle(cycle-2) = %v", err)
	}
	assertCycleRowCount(t, ctx, s, 1)

	var (
		completedAt string
		count       int
		oldest      int64
		note        string
	)
	if err := s.DB().QueryRowContext(ctx, `
		SELECT completed_at, assignment_count, oldest_age_seconds, note
		FROM reconcile_cycles WHERE cycle_id = ?
	`, receipt.CycleID).Scan(&completedAt, &count, &oldest, &note); err != nil {
		t.Fatalf("read completed cycle: %v", err)
	}
	if completedAt != formatTime(receipt.CompletedAt) ||
		count != receipt.AssignmentCount ||
		oldest != int64(receipt.OldestAge/time.Second) ||
		note != "completed" {
		t.Fatalf("completed cycle = (%q,%d,%d,%q), want (%q,%d,%d,%q)",
			completedAt, count, oldest, note,
			formatTime(receipt.CompletedAt), receipt.AssignmentCount, int64(receipt.OldestAge/time.Second), "completed")
	}

	if err := s.BeginReconcileCycle(ctx, "cycle-3", started.Add(3*time.Second)); err != nil {
		t.Fatalf("BeginReconcileCycle(cycle-3) = %v", err)
	}
	if err := s.AbortReconcileCycle(ctx, "cycle-3", started.Add(4*time.Second), "assignment-failed"); err != nil {
		t.Fatalf("AbortReconcileCycle(cycle-3) = %v", err)
	}
	assertCycleRowCount(t, ctx, s, 1)
}

func TestSQLiteReconcileCycleValidationFailsClosed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	started := time.Now().Add(-time.Minute).UTC()
	if err := s.BeginReconcileCycle(ctx, "cycle-valid", started); err != nil {
		t.Fatalf("BeginReconcileCycle(valid) = %v", err)
	}
	if err := s.BeginReconcileCycle(ctx, "cycle-valid", started); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BeginReconcileCycle(duplicate) = %v, want ErrIdentityConflict", err)
	}
	if err := s.BeginReconcileCycle(ctx, "cycle-future", time.Now().Add(time.Hour)); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BeginReconcileCycle(future) = %v, want ErrIdentityConflict", err)
	}
	if err := s.CompleteReconcileCycle(ctx, controller.CycleReceipt{
		CycleID:         "cycle-valid",
		CompletedAt:     started.Add(time.Second),
		AssignmentCount: -1,
	}); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("CompleteReconcileCycle(negative count) = %v, want ErrIdentityConflict", err)
	}
	if err := s.AbortReconcileCycle(ctx, "cycle-valid", started.Add(-time.Second), "failed"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("AbortReconcileCycle(backward time) = %v, want ErrIdentityConflict", err)
	}
}

func TestSQLiteBeginReconcileCycleRejectsMultipleIncompleteRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	started := time.Now().Add(-time.Minute).UTC()
	for index, cycleID := range []string{"corrupt-incomplete-a", "corrupt-incomplete-b"} {
		if _, err := s.DB().ExecContext(ctx, `
			INSERT INTO reconcile_cycles (cycle_id, started_at)
			VALUES (?, ?)
		`, cycleID, formatTime(started.Add(time.Duration(index)*time.Second))); err != nil {
			t.Fatalf("insert incomplete cycle %q: %v", cycleID, err)
		}
	}

	if err := s.BeginReconcileCycle(
		ctx,
		"must-not-mask-corruption",
		started.Add(2*time.Second),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BeginReconcileCycle(multiple incomplete) = %v, want ErrIdentityConflict", err)
	}

	var incomplete int
	if err := s.DB().QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM reconcile_cycles WHERE completed_at IS NULL`,
	).Scan(&incomplete); err != nil {
		t.Fatalf("count incomplete cycles: %v", err)
	}
	if incomplete != 2 {
		t.Fatalf("incomplete cycle count = %d, want original corrupt rows preserved", incomplete)
	}
}

func mustListRecoverable(t *testing.T, ctx context.Context, s *SQLiteStore) []RecoverableAssignment {
	t.Helper()
	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v", err)
	}
	return list
}

func assertCycleRowCount(t *testing.T, ctx context.Context, s *SQLiteStore, want int) {
	t.Helper()
	var got int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM reconcile_cycles`).Scan(&got); err != nil {
		t.Fatalf("count reconcile cycles: %v", err)
	}
	if got != want {
		t.Fatalf("reconcile cycle row count = %d, want %d", got, want)
	}
}

// --- orphan held-broker reconciliation --------------------------------------

func TestSQLiteOrphanHeldBrokerReconciliation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 14)
	advanceTo(t, ctx, s, key, controller.StateBrokerHeld)
	// Simulate a crash here: no further progress, broker never released.

	list, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable() = %v, want nil", err)
	}
	ra, ok := findRecoverable(t, list, key)
	if !ok {
		t.Fatal("ListRecoverable() missing orphaned BROKER_HELD assignment")
	}
	if ra.State != controller.StateBrokerHeld {
		t.Errorf("State = %s, want BROKER_HELD", ra.State)
	}
	if ra.Slot.BrokerContainerID == "" {
		t.Error("Slot.BrokerContainerID is empty, want the held broker's container id for reconciliation")
	}
}

// --- restart from every checkpoint ------------------------------------------

func TestSQLiteRestartFromEveryCheckpoint(t *testing.T) {
	checkpoints := append([]controller.State{controller.StateCapacityReserved}, statesOf(checkpointSteps)...)

	for i, target := range checkpoints {
		t.Run(string(target), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "controller.db")
			ctx := context.Background()

			s1, err := OpenWithHistoryLimits(path, testHistoryLimits())
			if err != nil {
				t.Fatalf("OpenWithHistoryLimits() = %v, want nil", err)
			}

			key := seedAssignment(t, ctx, s1, "owner/repository", int64(200+i))
			if target != controller.StateCapacityReserved {
				advanceTo(t, ctx, s1, key, target)
			}
			if err := s1.Close(); err != nil {
				t.Fatalf("Close() = %v, want nil", err)
			}

			// Simulate a controller restart: reopen the same file.
			s2, err := OpenWithHistoryLimits(path, testHistoryLimits())
			if err != nil {
				t.Fatalf("OpenWithHistoryLimits() (restart) = %v, want nil", err)
			}
			defer func() {
				if err := s2.Close(); err != nil {
					t.Errorf("Close() (restart) = %v, want nil", err)
				}
			}()

			list, err := s2.ListRecoverable(ctx)
			if err != nil {
				t.Fatalf("ListRecoverable() (restart) = %v, want nil", err)
			}
			ra, ok := findRecoverable(t, list, key)
			if !ok {
				t.Fatalf("ListRecoverable() (restart) missing assignment at checkpoint %s", target)
			}
			if ra.State != target {
				t.Errorf("State after restart = %s, want %s", ra.State, target)
			}
		})
	}
}

func statesOf(steps []checkpointStep) []controller.State {
	states := make([]controller.State, len(steps))
	for i, step := range steps {
		states[i] = step.state
	}
	return states
}

// --- acquisition policy CAS -------------------------------------------------

func TestSQLiteAcquisitionPolicyDefaultAndCompareAndSet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	initial, err := s.AcquisitionPolicy(ctx)
	if err != nil {
		t.Fatalf("AcquisitionPolicy() = %v, want nil", err)
	}
	if initial.Mode != controller.AcquisitionDisabled {
		t.Errorf("initial Mode = %q, want %q", initial.Mode, controller.AcquisitionDisabled)
	}
	if initial.Epoch != 0 {
		t.Errorf("initial Epoch = %d, want 0", initial.Epoch)
	}

	next := controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionCanaryOnly,
		EligibleScaleSets:        []string{"example-fleet"},
		MaxCapacity:              3,
		RepositoryPolicyRevision: 1,
		RepositoryPolicies: []controller.RepositoryPolicySummary{
			{Alias: "owner/repository", MaxConcurrency: 2, Eligibility: "active"},
		},
	}

	updated, err := s.CompareAndSetAcquisition(ctx, initial.Epoch, next)
	if err != nil {
		t.Fatalf("CompareAndSetAcquisition() = %v, want nil", err)
	}
	if updated.Epoch != initial.Epoch+1 {
		t.Errorf("updated Epoch = %d, want %d", updated.Epoch, initial.Epoch+1)
	}
	if updated.Mode != controller.AcquisitionCanaryOnly {
		t.Errorf("updated Mode = %q, want %q", updated.Mode, controller.AcquisitionCanaryOnly)
	}
	if len(updated.EligibleScaleSets) != 1 || updated.EligibleScaleSets[0] != "example-fleet" {
		t.Errorf("updated EligibleScaleSets = %v, want [example-fleet]", updated.EligibleScaleSets)
	}

	// Stale epoch must be rejected and must not change stored state.
	staleAttempt := next
	staleAttempt.Mode = controller.AcquisitionEnabled
	_, err = s.CompareAndSetAcquisition(ctx, initial.Epoch, staleAttempt)
	if err == nil {
		t.Fatal("CompareAndSetAcquisition() with stale epoch = nil, want error")
	}

	current, err := s.AcquisitionPolicy(ctx)
	if err != nil {
		t.Fatalf("AcquisitionPolicy() = %v, want nil", err)
	}
	if current.Mode != controller.AcquisitionCanaryOnly {
		t.Errorf("Mode after rejected stale CAS = %q, want unchanged %q", current.Mode, controller.AcquisitionCanaryOnly)
	}
	if current.Epoch != updated.Epoch {
		t.Errorf("Epoch after rejected stale CAS = %d, want unchanged %d", current.Epoch, updated.Epoch)
	}

	// Correct epoch succeeds.
	second, err := s.CompareAndSetAcquisition(ctx, updated.Epoch, staleAttempt)
	if err != nil {
		t.Fatalf("CompareAndSetAcquisition() with correct epoch = %v, want nil", err)
	}
	if second.Epoch != updated.Epoch+1 {
		t.Errorf("second Epoch = %d, want %d", second.Epoch, updated.Epoch+1)
	}
}

// --- network_ledgers retention -----------------------------------------

func TestSQLiteNetworkLedgerOutlivesAssignment(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	key := seedAssignment(t, ctx, s, "owner/repository", 15)

	var assignmentID int64
	if err := s.DB().QueryRowContext(ctx,
		`SELECT id FROM assignments WHERE repository_alias = ? AND runner_request_id = ?`,
		key.RepositoryAlias, key.RunnerRequestID).Scan(&assignmentID); err != nil {
		t.Fatalf("look up assignment id: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO network_ledgers (ledger_key, assignment_id, state_digest, updated_at) VALUES (?, ?, ?, ?)`,
		"ledger-owner/repository-15", assignmentID, "digest-abc", now); err != nil {
		t.Fatalf("insert network_ledgers row: %v", err)
	}

	// Tear down the assignment directly, simulating post-DESTROYED cleanup.
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM assignments WHERE id = ?`, assignmentID); err != nil {
		t.Fatalf("delete assignment: %v", err)
	}

	var ledgerAssignmentID sql.NullInt64
	if err := s.DB().QueryRowContext(ctx,
		`SELECT assignment_id FROM network_ledgers WHERE ledger_key = ?`,
		"ledger-owner/repository-15").Scan(&ledgerAssignmentID); err != nil {
		t.Fatalf("network_ledgers row was deleted along with its assignment, want it to outlive: %v", err)
	}
	if ledgerAssignmentID.Valid {
		t.Errorf("network_ledgers.assignment_id = %d after assignment delete, want NULL (not cascaded)", ledgerAssignmentID.Int64)
	}
}

// --- reject secret-bearing columns --------------------------------------

// TestStoreAPISurfaceRejectsSecretTypes structurally proves no Store method
// parameter or return type is, or contains as a direct field,
// *redaction.Secret. This is a compile-time property of the interface
// (Store's method signatures are fixed source text), so a reflective walk
// over the interface's method set is a faithful proof rather than a
// runtime-only check.
func TestStoreAPISurfaceRejectsSecretTypes(t *testing.T) {
	secretPtrType := reflect.TypeOf(&redaction.Secret{})
	storeType := reflect.TypeOf((*Store)(nil)).Elem()

	// unwrap strips pointer/slice wrapping so both *redaction.Secret and
	// []*redaction.Secret (or a struct field of either shape) are caught.
	unwrap := func(t reflect.Type) reflect.Type {
		for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		return t
	}

	isSecretShaped := func(t reflect.Type) bool {
		return t == secretPtrType || unwrap(t) == secretPtrType.Elem()
	}

	checkType := func(t reflect.Type, where string) {
		if isSecretShaped(t) {
			t2 := t // avoid shadowing lint noise
			_ = t2
			panic(fmt.Sprintf("%s is shaped like redaction.Secret", where))
		}
		if s := unwrap(t); s.Kind() == reflect.Struct {
			for i := 0; i < s.NumField(); i++ {
				field := s.Field(i)
				if isSecretShaped(field.Type) {
					panic(fmt.Sprintf("%s has field %q shaped like redaction.Secret", where, field.Name))
				}
			}
		}
	}

	for i := 0; i < storeType.NumMethod(); i++ {
		m := storeType.Method(i)
		for p := 0; p < m.Type.NumIn(); p++ {
			where := fmt.Sprintf("Store.%s parameter %d (%s)", m.Name, p, m.Type.In(p))
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Error(r)
					}
				}()
				checkType(m.Type.In(p), where)
			}()
		}
		for r := 0; r < m.Type.NumOut(); r++ {
			where := fmt.Sprintf("Store.%s return %d (%s)", m.Name, r, m.Type.Out(r))
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						t.Error(rec)
					}
				}()
				checkType(m.Type.Out(r), where)
			}()
		}
	}
}
