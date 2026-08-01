package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestAcquisitionJournalAbortReopenAndEmptyCompletion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	at := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	keys := seedAcquisitionOffers(t, store, "repo-a", 801, at, 8101, 8102)

	batch, err := store.BeginAcquisition(ctx, "repo-a", 801, reverseKeys(keys), at)
	if err != nil {
		t.Fatalf("BeginAcquisition: %v", err)
	}
	if batch.State != AcquisitionBatchBegun || batch.RequestedCount != 2 ||
		!batch.Inserted || !batch.CallAuthorized {
		t.Fatalf("begun batch = %+v", batch)
	}
	begunReplay, err := store.BeginAcquisition(
		ctx,
		"repo-a",
		801,
		keys,
		at.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("BeginAcquisition(begun replay): %v", err)
	}
	if begunReplay.Inserted || begunReplay.CallAuthorized ||
		begunReplay.State != AcquisitionBatchBegun {
		t.Fatalf("begun replay = %+v", begunReplay)
	}
	assertAcquisitionOutcomes(t, store, keys, AcquisitionOutcomeRequested)
	usage, err := store.HistoryUsage(ctx, testHistoryLimits())
	if err != nil {
		t.Fatalf("HistoryUsage(acquisition): %v", err)
	}
	wantBytes, err := acquisitionLogicalBytes("repo-a")
	if err != nil {
		t.Fatalf("acquisitionLogicalBytes: %v", err)
	}
	if usage.AcquisitionRows != 1 || usage.AcquisitionLogicalBytes != wantBytes {
		t.Fatalf(
			"acquisition usage = %d rows/%d bytes, want 1/%d",
			usage.AcquisitionRows,
			usage.AcquisitionLogicalBytes,
			wantBytes,
		)
	}

	aborted, err := store.AbortAcquisitionBeforeCall(
		ctx,
		"repo-a",
		801,
		at.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("AbortAcquisitionBeforeCall: %v", err)
	}
	if aborted.State != AcquisitionBatchNotAttempted {
		t.Fatalf("aborted state = %q, want not_attempted", aborted.State)
	}
	assertAcquisitionOutcomes(t, store, keys, AcquisitionOutcomeOffered)
	if _, err := store.BeginAcquisition(
		ctx,
		"repo-a",
		801,
		keys[:1],
		at.Add(2*time.Second),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BeginAcquisition(mismatched reopen) = %v, want ErrIdentityConflict", err)
	}
	assertAcquisitionOutcomes(t, store, keys, AcquisitionOutcomeOffered)

	reopened, err := store.BeginAcquisition(
		ctx,
		"repo-a",
		801,
		keys,
		at.Add(2*time.Second),
	)
	if err != nil {
		t.Fatalf("BeginAcquisition(reopen): %v", err)
	}
	if reopened.State != AcquisitionBatchBegun || reopened.Inserted ||
		!reopened.CallAuthorized {
		t.Fatalf("reopened batch = %+v", reopened)
	}

	completed, err := store.CompleteAcquisition(
		ctx,
		"repo-a",
		801,
		nil,
		at.Add(3*time.Second),
	)
	if err != nil {
		t.Fatalf("CompleteAcquisition(empty): %v", err)
	}
	if completed.State != AcquisitionBatchCompleted ||
		completed.RequestedCount != 2 ||
		completed.AcquiredCount != 0 ||
		completed.ResultDigest == ([32]byte{}) {
		t.Fatalf("completed batch = %+v", completed)
	}
	assertAcquisitionOutcomes(t, store, keys, AcquisitionOutcomeRejected)

	replay, err := store.CompleteAcquisition(
		ctx,
		"repo-a",
		801,
		nil,
		at.Add(4*time.Second),
	)
	if err != nil {
		t.Fatalf("CompleteAcquisition(empty replay): %v", err)
	}
	if replay.ResultDigest != completed.ResultDigest {
		t.Fatalf("replay digest = %x, want %x", replay.ResultDigest, completed.ResultDigest)
	}
	if _, err := store.CompleteAcquisition(
		ctx,
		"repo-a",
		801,
		keys[:1],
		at.Add(5*time.Second),
	); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("conflicting completed replay = %v, want ErrIdentityConflict", err)
	}
}

func TestOperationalSummaryIsAggregateAndClosed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	at := time.Date(2026, 7, 29, 5, 0, 0, 0, time.UTC)
	keys := seedAcquisitionOffers(
		t,
		store,
		"repo-a",
		807,
		at,
		8701,
		8702,
		8703,
		8704,
	)
	for index, state := range []controller.State{
		controller.StateListenerReleased,
		controller.StateListenerReleased,
		controller.StateJobRunning,
		controller.StateDestroyed,
	} {
		updated := at
		if state == controller.StateDestroyed {
			updated = at.Add(30 * time.Minute)
		}
		if _, err := store.DB().ExecContext(ctx, `
			UPDATE assignments SET state = ?, updated_at = ?
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, string(state), formatTime(updated), keys[index].RepositoryAlias,
			keys[index].RunnerRequestID, keys[index].Attempt,
		); err != nil {
			t.Fatalf("seed summary state %d: %v", index, err)
		}
	}
	for index, key := range []controller.AssignmentKey{keys[1], keys[2]} {
		if _, err := store.DB().ExecContext(ctx, `
			INSERT INTO runner_slots (
				assignment_id, opaque_name, capacity_slot_id,
				upstream_runner_id, created_at, updated_at
			)
			SELECT id, ?, ?, ?, ?, ?
			FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, fmt.Sprintf("summary-slot-%d", index), 100+index, 9000+index,
			formatTime(at), formatTime(at), key.RepositoryAlias,
			key.RunnerRequestID, key.Attempt,
		); err != nil {
			t.Fatalf("seed summary runner slot %d: %v", index, err)
		}
	}
	tombstoneAt := at.Add(45 * time.Minute)
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO history_tombstones (
			repository_alias, runner_request_id, attempt,
			offer_digest, offer_payload_digest, source_message_id,
			terminal_at, retain_until, logical_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "repo-z", 9999, 0, make([]byte, sha256.Size), make([]byte, sha256.Size),
		nil, formatTime(tombstoneAt), formatTime(tombstoneAt.Add(time.Hour)), 1,
	); err != nil {
		t.Fatalf("seed summary tombstone: %v", err)
	}

	summary, err := store.OperationalSummary(ctx, at.Add(time.Hour))
	if err != nil {
		t.Fatalf("OperationalSummary: %v", err)
	}
	if summary.AssignedJobs != 2 ||
		summary.RunningJobs != 1 ||
		summary.OldestLiveAssignmentAge != time.Hour ||
		summary.UnassignedReleasedListeners != 1 ||
		!summary.LatestTerminalAt.Equal(tombstoneAt) {
		t.Fatalf("OperationalSummary = %+v", summary)
	}
}

func TestTerminalFinalizationsPreferBoundReceiptAndRemainStable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	at := time.Date(2026, 7, 29, 6, 0, 0, 0, time.UTC)
	keys := seedAcquisitionOffers(t, store, "repo-a", 901, at, 9802, 9801)
	for index, key := range keys {
		if _, err := store.DB().ExecContext(ctx, `
			UPDATE assignments SET state = ?, updated_at = ?
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, string(controller.StateDestroyed), formatTime(at.Add(time.Duration(index+1)*time.Minute)),
			key.RepositoryAlias, key.RunnerRequestID, key.Attempt,
		); err != nil {
			t.Fatalf("seed destroyed assignment %d: %v", index, err)
		}
	}
	if _, err := store.RecordMessageReceipt(
		ctx,
		taskDEnvelope("repo-a", 902),
		at.Add(3*time.Minute),
	); err != nil {
		t.Fatalf("RecordMessageReceipt(terminal): %v", err)
	}
	if err := store.BindTerminalMessage(ctx, keys[0], 902); err != nil {
		t.Fatalf("BindTerminalMessage(DESTROYED): %v", err)
	}

	finalizations, err := store.ListTerminalFinalizations(ctx)
	if err != nil {
		t.Fatalf("ListTerminalFinalizations: %v", err)
	}
	want := []TerminalFinalization{
		{
			Key:       keys[1],
			MessageID: 901,
			At:        at.Add(2 * time.Minute),
		},
		{
			Key:       keys[0],
			MessageID: 902,
			At:        at.Add(time.Minute),
		},
	}
	if !reflect.DeepEqual(finalizations, want) {
		t.Fatalf("finalizations = %+v, want %+v", finalizations, want)
	}
}

func TestBindTerminalMessageAcceptsJobFinishedBeforeDestroy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	at := time.Date(2026, 7, 29, 7, 0, 0, 0, time.UTC)
	key := seedAssignment(t, ctx, store, "repo-a", 9901)
	advanceTo(t, ctx, store, key, controller.StateJobFinished)
	if _, err := store.RecordMessageReceipt(
		ctx,
		taskDEnvelope("repo-a", 903),
		at,
	); err != nil {
		t.Fatalf("RecordMessageReceipt: %v", err)
	}
	if err := store.BindTerminalMessage(ctx, key, 903); err != nil {
		t.Fatalf("BindTerminalMessage(JOB_FINISHED): %v", err)
	}
	if err := store.Advance(ctx, key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(DESTROYED): %v", err)
	}
	finalizations, err := store.ListTerminalFinalizations(ctx)
	if err != nil {
		t.Fatalf("ListTerminalFinalizations: %v", err)
	}
	if len(finalizations) != 1 || finalizations[0].Key != key ||
		finalizations[0].MessageID != 903 {
		t.Fatalf("finalizations = %+v", finalizations)
	}
}

func TestAcquisitionSchemaMigratesV2AndRollsBackEveryWrite(t *testing.T) {
	ctx := context.Background()
	seedV2 := func(t *testing.T, path string) *sql.DB {
		t.Helper()
		db := seedHistorySchemaV1(t, path)
		if _, err := db.Exec(schemaV2); err != nil {
			t.Fatalf("create schema v2: %v", err)
		}
		if _, err := db.Exec(`
			UPDATE assignments SET admission_phase = 2
			WHERE repository_alias = 'repo-v1' AND runner_request_id = 703
		`); err != nil {
			t.Fatalf("seed v2 acquired projection: %v", err)
		}
		if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
			t.Fatalf("set v2 user_version: %v", err)
		}
		return db
	}

	success := seedV2(t, filepath.Join(t.TempDir(), "success-v2.db"))
	var steps int
	if err := migrateV2ToV3WithHook(ctx, success, func(_ int, _ string) error {
		steps++
		return nil
	}); err != nil {
		t.Fatalf("migrateV2ToV3WithHook(success): %v", err)
	}
	if steps == 0 {
		t.Fatal("v2 migration executed zero injectable writes")
	}
	var version int
	var outcome string
	if err := success.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("read v3 user_version: %v", err)
	}
	if err := success.QueryRow(`
		SELECT acquisition_outcome FROM assignments
		WHERE repository_alias = 'repo-v1' AND runner_request_id = 703
	`).Scan(&outcome); err != nil {
		t.Fatalf("read migrated acquisition outcome: %v", err)
	}
	if version != currentSchemaVersion || outcome != string(AcquisitionOutcomeAcquired) {
		t.Fatalf("migrated version/outcome = %d/%q", version, outcome)
	}

	injected := errors.New("injected v2 migration failure")
	for failAt := 1; failAt <= steps; failAt++ {
		t.Run(fmt.Sprintf("rollback-before-write-%03d", failAt), func(t *testing.T) {
			db := seedV2(t, filepath.Join(t.TempDir(), "rollback-v2.db"))
			before := databaseSnapshot(t, db)
			err := migrateV2ToV3WithHook(ctx, db, func(step int, _ string) error {
				if step == failAt {
					return injected
				}
				return nil
			})
			if !errors.Is(err, injected) {
				t.Fatalf("migration error = %v, want injected", err)
			}
			if after := databaseSnapshot(t, db); after != before {
				t.Fatalf("v2 database changed after failure before write %d", failAt)
			}
		})
	}
}

func TestAcquisitionReadOnlyRejectsOldAndFutureSchemas(t *testing.T) {
	for name, version := range map[string]int{
		"old":    2,
		"future": currentSchemaVersion + 1,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".db")
			db, err := sql.Open("sqlite", dsnForPath(path))
			if err != nil {
				t.Fatalf("open seed database: %v", err)
			}
			if _, err := db.Exec(`PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
				_ = db.Close()
				t.Fatalf("set auto_vacuum: %v", err)
			}
			if _, err := db.Exec(schemaV1); err != nil {
				_ = db.Close()
				t.Fatalf("create v1 schema: %v", err)
			}
			if _, err := db.Exec(schemaV2); err != nil {
				_ = db.Close()
				t.Fatalf("create v2 schema: %v", err)
			}
			if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, version)); err != nil {
				_ = db.Close()
				t.Fatalf("set user_version: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatalf("close seed database: %v", err)
			}
			if _, err := OpenReadOnlyWithHistoryLimits(
				path,
				testHistoryLimits(),
			); !errors.Is(err, ErrOfflineMigration) {
				t.Fatalf("OpenReadOnlyWithHistoryLimits = %v, want ErrOfflineMigration", err)
			}
		})
	}
}

func TestAcquisitionJournalSubsetAndInvalidResultAreAtomic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	at := time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC)
	keys := seedAcquisitionOffers(t, store, "repo-a", 802, at, 8201, 8202, 8203)
	if _, err := store.BeginAcquisition(ctx, "repo-a", 802, keys, at); err != nil {
		t.Fatalf("BeginAcquisition: %v", err)
	}

	foreign := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 9999}
	for name, acquired := range map[string][]controller.AssignmentKey{
		"duplicate": {keys[0], keys[0]},
		"foreign":   {keys[0], foreign},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.CompleteAcquisition(
				ctx,
				"repo-a",
				802,
				acquired,
				at.Add(time.Second),
			); !errors.Is(err, ErrIdentityConflict) {
				t.Fatalf("CompleteAcquisition = %v, want ErrIdentityConflict", err)
			}
			batch, err := store.AcquisitionBatch(ctx, "repo-a", 802)
			if err != nil {
				t.Fatalf("AcquisitionBatch: %v", err)
			}
			if batch.State != AcquisitionBatchBegun {
				t.Fatalf("state after invalid result = %q, want begun", batch.State)
			}
			assertAcquisitionOutcomes(t, store, keys, AcquisitionOutcomeRequested)
		})
	}

	completed, err := store.CompleteAcquisition(
		ctx,
		"repo-a",
		802,
		[]controller.AssignmentKey{keys[2], keys[0]},
		at.Add(2*time.Second),
	)
	if err != nil {
		t.Fatalf("CompleteAcquisition(valid subset): %v", err)
	}
	if completed.AcquiredCount != 2 {
		t.Fatalf("AcquiredCount = %d, want 2", completed.AcquiredCount)
	}
	assertAcquisitionOutcome(t, store, keys[0], AcquisitionOutcomeAcquired)
	assertAcquisitionOutcome(t, store, keys[1], AcquisitionOutcomeRejected)
	assertAcquisitionOutcome(t, store, keys[2], AcquisitionOutcomeAcquired)
}

func TestAcquisitionJournalPromotesOnlySurvivingBegun(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	at := time.Date(2026, 7, 29, 3, 0, 0, 0, time.UTC)
	begunKeys := seedAcquisitionOffers(t, store, "repo-a", 803, at, 8301)
	abortedKeys := seedAcquisitionOffers(t, store, "repo-a", 804, at, 8401)
	completedKeys := seedAcquisitionOffers(t, store, "repo-a", 805, at, 8501)

	if _, err := store.BeginAcquisition(ctx, "repo-a", 803, begunKeys, at); err != nil {
		t.Fatalf("begin surviving: %v", err)
	}
	if _, err := store.BeginAcquisition(ctx, "repo-a", 804, abortedKeys, at); err != nil {
		t.Fatalf("begin aborted: %v", err)
	}
	if _, err := store.AbortAcquisitionBeforeCall(ctx, "repo-a", 804, at.Add(time.Second)); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if _, err := store.BeginAcquisition(ctx, "repo-a", 805, completedKeys, at); err != nil {
		t.Fatalf("begin completed: %v", err)
	}
	if _, err := store.CompleteAcquisition(
		ctx,
		"repo-a",
		805,
		completedKeys,
		at.Add(time.Second),
	); err != nil {
		t.Fatalf("complete: %v", err)
	}

	count, err := store.PromoteBegunAcquisitions(ctx, at.Add(2*time.Second))
	if err != nil {
		t.Fatalf("PromoteBegunAcquisitions: %v", err)
	}
	if count != 1 {
		t.Fatalf("promoted count = %d, want 1", count)
	}
	for messageID, want := range map[int]AcquisitionBatchState{
		803: AcquisitionBatchAmbiguous,
		804: AcquisitionBatchNotAttempted,
		805: AcquisitionBatchCompleted,
	} {
		batch, err := store.AcquisitionBatch(ctx, "repo-a", messageID)
		if err != nil {
			t.Fatalf("AcquisitionBatch(%d): %v", messageID, err)
		}
		if batch.State != want {
			t.Fatalf("batch %d state = %q, want %q", messageID, batch.State, want)
		}
	}
	assertAcquisitionOutcome(t, store, begunKeys[0], AcquisitionOutcomeRequested)
	assertAcquisitionOutcome(t, store, abortedKeys[0], AcquisitionOutcomeOffered)
	assertAcquisitionOutcome(t, store, completedKeys[0], AcquisitionOutcomeAcquired)
}

func TestMarkPreRunningRevokedPreservesRunningAndTerminal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	at := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	keys := seedAcquisitionOffers(t, store, "repo-a", 806, at, 8601, 8602, 8603)
	if _, err := store.DB().ExecContext(ctx, `
		UPDATE assignments
		SET state = CASE runner_request_id
			WHEN 8601 THEN ?
			WHEN 8602 THEN ?
			WHEN 8603 THEN ?
		END
		WHERE repository_alias = 'repo-a' AND runner_request_id IN (8601, 8602, 8603)
	`, string(controller.StateListenerReleased), string(controller.StateJobRunning), string(controller.StateDestroyed)); err != nil {
		t.Fatalf("seed states: %v", err)
	}

	marked, err := store.MarkPreRunningRevoked(ctx, 9, at.Add(time.Second))
	if err != nil {
		t.Fatalf("MarkPreRunningRevoked: %v", err)
	}
	if len(marked) != 1 || marked[0] != keys[0] {
		t.Fatalf("marked = %+v, want [%+v]", marked, keys[0])
	}
	for index, want := range []uint64{9, 0, 0} {
		record, err := store.AcquisitionAssignment(ctx, keys[index])
		if err != nil {
			t.Fatalf("AcquisitionAssignment(%d): %v", index, err)
		}
		if record.RevokedEpoch != want {
			t.Fatalf("key %d revoked epoch = %d, want %d", index, record.RevokedEpoch, want)
		}
	}
}

func seedAcquisitionOffers(
	t *testing.T,
	store *SQLiteStore,
	repositoryAlias string,
	messageID int,
	at time.Time,
	requestIDs ...int64,
) []controller.AssignmentKey {
	t.Helper()
	offers := make([]OfferIdentity, len(requestIDs))
	for i, requestID := range requestIDs {
		offers[i] = historyOffer(repositoryAlias, requestID, requestID+10000, at)
	}
	recordMessageReceiptForOffers(t, store, repositoryAlias, messageID, at, offers...)
	keys := make([]controller.AssignmentKey, 0, len(offers))
	for _, offer := range offers {
		receipt, err := store.RecordOffer(
			context.Background(),
			offer,
			currentPollEvidence(messageID, at, at),
		)
		if err != nil {
			t.Fatalf("RecordOffer(%d): %v", offer.RunnerRequestID, err)
		}
		keys = append(keys, receipt.Key)
	}
	return keys
}

func reverseKeys(keys []controller.AssignmentKey) []controller.AssignmentKey {
	out := append([]controller.AssignmentKey(nil), keys...)
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	return out
}

func assertAcquisitionOutcomes(
	t *testing.T,
	store *SQLiteStore,
	keys []controller.AssignmentKey,
	want AcquisitionOutcome,
) {
	t.Helper()
	for _, key := range keys {
		assertAcquisitionOutcome(t, store, key, want)
	}
}

func assertAcquisitionOutcome(
	t *testing.T,
	store *SQLiteStore,
	key controller.AssignmentKey,
	want AcquisitionOutcome,
) {
	t.Helper()
	record, err := store.AcquisitionAssignment(context.Background(), key)
	if err != nil {
		t.Fatalf("AcquisitionAssignment(%+v): %v", key, err)
	}
	if record.Outcome != want {
		t.Fatalf("AcquisitionAssignment(%+v) outcome = %q, want %q", key, record.Outcome, want)
	}
}
