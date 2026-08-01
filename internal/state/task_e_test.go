package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func rowCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("row count: %v", err)
	}
	return count
}

func insertTombstone(
	t *testing.T,
	db *sql.DB,
	runnerRequestID int64,
	terminalAt time.Time,
	retainUntil time.Time,
) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO history_tombstones (
			repository_alias, runner_request_id, attempt,
			offer_digest, offer_payload_digest, terminal_at,
			retain_until, logical_bytes
		) VALUES ('repo-maintenance', ?, 0, zeroblob(32), zeroblob(32), ?, ?, 160)
	`, runnerRequestID, formatTime(terminalAt), formatTime(retainUntil)); err != nil {
		t.Fatalf("insert tombstone %d: %v", runnerRequestID, err)
	}
}

func insertMessageReceipt(
	t *testing.T,
	db *sql.DB,
	messageID int,
	ackState string,
	retainUntil time.Time,
) {
	t.Helper()
	retain := any(nil)
	if !retainUntil.IsZero() {
		retain = formatTime(retainUntil)
	}
	if _, err := db.Exec(`
		INSERT INTO message_receipts (
			repository_alias, message_id, payload_digest, persisted_at,
			ack_state, ack_started_at, ack_confirmed_at, retain_until,
			logical_bytes
		) VALUES ('repo-maintenance', ?, zeroblob(32), ?, ?, ?, ?, ?, 160)
	`, messageID, formatTime(retainUntil.Add(-time.Hour)), ackState,
		formatTime(retainUntil.Add(-30*time.Minute)),
		formatTime(retainUntil.Add(-15*time.Minute)),
		retain,
	); err != nil {
		t.Fatalf("insert message receipt %d: %v", messageID, err)
	}
}

func TestCollectHistoryCompactsEligibleTerminalGraphsOnly(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)

	_, eligible := compactableOffer(t, s, 700, 201, base)
	eligibleTerminalAt := terminalCheckpoint(t, s, eligible.Key)
	var eligibleID int64
	if err := s.DB().QueryRow(`
		SELECT id FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, eligible.Key.RepositoryAlias, eligible.Key.RunnerRequestID, eligible.Key.Attempt).Scan(&eligibleID); err != nil {
		t.Fatalf("read eligible assignment id: %v", err)
	}
	if _, err := s.DB().Exec(`
		INSERT INTO network_ledgers (
			ledger_key, assignment_id, state_digest, updated_at,
			retained_until, logical_bytes
		) VALUES ('collect-attached-ledger', ?, 'opaque', ?, ?, 64)
	`, eligibleID, formatTime(base), formatTime(eligibleTerminalAt.Add(48*time.Hour))); err != nil {
		t.Fatalf("insert attached ledger: %v", err)
	}

	uncertainOffer := historyOffer("repo-a", 701, 1701, base.Add(time.Minute))
	uncertain, err := s.RecordOffer(
		ctx,
		uncertainOffer,
		currentPollEvidence(202, uncertainOffer.QueueTime, uncertainOffer.QueueTime),
	)
	if err != nil {
		t.Fatalf("RecordOffer(uncertain): %v", err)
	}
	recordMessageReceiptForOffers(t, s, "repo-a", 202, base.Add(90*time.Second), uncertainOffer)
	if err := s.BeginMessageAck(ctx, "repo-a", 202, base.Add(2*time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck(uncertain): %v", err)
	}
	terminalMessage(t, s, uncertain.Key, 202)
	if err := s.Advance(ctx, uncertain.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(uncertain): %v", err)
	}

	usage, err := s.CollectHistory(
		ctx,
		testHistoryLimits(),
		eligibleTerminalAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if usage.Maintenance.CompactedTerminalGraphs != 1 {
		t.Fatalf("CompactedTerminalGraphs = %d, want 1", usage.Maintenance.CompactedTerminalGraphs)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM assignments WHERE runner_request_id = 700`,
	); got != 0 {
		t.Fatalf("eligible assignment count = %d, want 0", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id = 700`,
	); got != 1 {
		t.Fatalf("eligible tombstone count = %d, want 1", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM assignments WHERE runner_request_id = 701`,
	); got != 1 {
		t.Fatalf("uncertain assignment count = %d, want 1", got)
	}
	var detached sql.NullInt64
	if err := s.DB().QueryRow(`
		SELECT assignment_id FROM network_ledgers
		WHERE ledger_key = 'collect-attached-ledger'
	`).Scan(&detached); err != nil {
		t.Fatalf("read detached ledger: %v", err)
	}
	if detached.Valid {
		t.Fatalf("eligible ledger remains attached to %d", detached.Int64)
	}
}

func TestCollectHistoryOldestTerminalIsNotStarvedByFutureLowerIDs(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 28, 9, 30, 0, 0, time.UTC)
	limits := testHistoryLimits()
	limits.MaxHistoryRows = 2
	limits.GCBatchRows = 1

	var receipts []OfferReceipt
	for i := 0; i < 3; i++ {
		_, receipt := compactableOffer(
			t,
			s,
			int64(710+i),
			211+i,
			base.Add(time.Duration(i)*time.Minute),
		)
		receipts = append(receipts, receipt)
	}
	for i, receipt := range receipts {
		checkpoint := base.Add(time.Duration(i+1) * time.Hour)
		if i == len(receipts)-1 {
			checkpoint = base.Add(-time.Hour)
		}
		if _, err := s.DB().Exec(`
			UPDATE assignments SET updated_at = ?
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, formatTime(checkpoint), receipt.Key.RepositoryAlias,
			receipt.Key.RunnerRequestID, receipt.Key.Attempt); err != nil {
			t.Fatalf("set terminal checkpoint %d: %v", i, err)
		}
	}

	compacted, err := s.compactEligibleTerminalGraphs(ctx, limits, base)
	if err != nil {
		t.Fatalf("compactEligibleTerminalGraphs: %v", err)
	}
	if compacted != 1 {
		t.Fatalf("compacted terminal graphs = %d, want 1", compacted)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM assignments WHERE runner_request_id = 712`,
	); got != 0 {
		t.Fatalf("oldest higher-id assignment count = %d, want 0", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM assignments WHERE runner_request_id IN (710, 711)`,
	); got != 2 {
		t.Fatalf("future lower-id assignments = %d, want 2", got)
	}
}

func TestCollectHistoryRequiresDurableAdmissionProjectionClearedBeforeCompaction(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 702, 1702, base)
	receipt, err := s.RecordOffer(
		ctx,
		offer,
		currentPollEvidence(203, base, base.Add(time.Second)),
	)
	if err != nil {
		t.Fatalf("RecordOffer: %v", err)
	}
	if err := s.PersistAdmissionProjection(
		ctx,
		receipt.Key,
		AdmissionProjection{Valid: true, Phase: AdmissionQueued},
	); err != nil {
		t.Fatalf("PersistAdmissionProjection(queued): %v", err)
	}
	recordMessageReceiptForOffers(t, s, offer.RepositoryAlias, 203, base.Add(30*time.Second), offer)
	if err := s.BeginMessageAck(ctx, offer.RepositoryAlias, 203, base.Add(time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck: %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, offer.RepositoryAlias, 203, base.Add(2*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck: %v", err)
	}
	terminalMessage(t, s, receipt.Key, 203)
	if err := s.Advance(ctx, receipt.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(RECEIVED->DESTROYED): %v", err)
	}
	terminalAt := terminalCheckpoint(t, s, receipt.Key)

	usage, err := s.CollectHistory(ctx, testHistoryLimits(), terminalAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("CollectHistory(with queued projection): %v", err)
	}
	if usage.Maintenance.CompactedTerminalGraphs != 0 {
		t.Fatalf(
			"CompactedTerminalGraphs = %d, want 0 while admission is durable",
			usage.Maintenance.CompactedTerminalGraphs,
		)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM assignments WHERE runner_request_id = 702`,
	); got != 1 {
		t.Fatalf("assignment count with queued projection = %d, want 1", got)
	}
	if err := s.ClearAdmissionProjection(ctx, receipt.Key); err != nil {
		t.Fatalf("ClearAdmissionProjection: %v", err)
	}
	usage, err = s.CollectHistory(ctx, testHistoryLimits(), terminalAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("CollectHistory(after clear): %v", err)
	}
	if usage.Maintenance.CompactedTerminalGraphs != 1 {
		t.Fatalf(
			"CompactedTerminalGraphs after clear = %d, want 1",
			usage.Maintenance.CompactedTerminalGraphs,
		)
	}
}

func TestCollectHistoryDeletesExpiredHistoryOldestFirstWithinBatch(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	limits.GCBatchRows = 2
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		insertTombstone(
			t,
			s.DB(),
			int64(800+i),
			now.Add(-72*time.Hour),
			now.Add(time.Duration(-3+i)*time.Hour),
		)
	}
	insertTombstone(t, s.DB(), 899, now.Add(-time.Hour), now.Add(time.Hour))

	usage, err := s.CollectHistory(ctx, limits, now)
	if err != nil {
		t.Fatalf("CollectHistory(first): %v", err)
	}
	if usage.Maintenance.DeletedTombstones != 2 ||
		usage.Maintenance.DeletedMessageReceipts != 0 {
		t.Fatalf("first maintenance = %+v, want two tombstones", usage.Maintenance)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id IN (800, 801)`,
	); got != 0 {
		t.Fatalf("oldest expired tombstones remaining = %d, want 0", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id IN (802, 899)`,
	); got != 2 {
		t.Fatalf("newer/protected tombstones remaining = %d, want 2", got)
	}

	usage, err = s.CollectHistory(ctx, limits, now)
	if err != nil {
		t.Fatalf("CollectHistory(second): %v", err)
	}
	if usage.Maintenance.DeletedTombstones != 1 {
		t.Fatalf("second DeletedTombstones = %d, want 1", usage.Maintenance.DeletedTombstones)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id = 899`,
	); got != 1 {
		t.Fatalf("protected tombstone count = %d, want 1", got)
	}
}

func TestCollectHistoryExpiredHistoryIsNotStarvedByProtectedLowerIDs(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	limits.MaxHistoryRows = 2
	limits.GCBatchRows = 1
	now := time.Date(2026, 7, 28, 12, 30, 0, 0, time.UTC)

	insertTombstone(t, s.DB(), 850, now.Add(-time.Hour), now.Add(time.Hour))
	insertTombstone(t, s.DB(), 851, now.Add(-time.Hour), now.Add(2*time.Hour))
	insertTombstone(t, s.DB(), 852, now.Add(-2*time.Hour), now.Add(-time.Hour))

	receipts, tombstones, err := s.deleteExpiredHistory(ctx, limits, now)
	if err != nil {
		t.Fatalf("deleteExpiredHistory: %v", err)
	}
	if receipts != 0 || tombstones != 1 {
		t.Fatalf(
			"history deletion = receipts %d tombstones %d, want 0/1",
			receipts,
			tombstones,
		)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id = 852`,
	); got != 0 {
		t.Fatalf("expired higher-id tombstone count = %d, want 0", got)
	}
}

func TestCollectHistoryProtectsUncertainReceiptsAndRollsBackInterruptedBatch(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	limits.GCBatchRows = 4
	now := time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC)
	insertMessageReceipt(t, s.DB(), 301, "ack_confirmed", now.Add(-2*time.Hour))
	insertMessageReceipt(t, s.DB(), 302, "ack_started", now.Add(-time.Hour))
	if _, err := s.DB().Exec(`
		CREATE TRIGGER fail_receipt_collection
		BEFORE DELETE ON message_receipts
		BEGIN
			SELECT RAISE(ABORT, 'injected collection failure');
		END
	`); err != nil {
		t.Fatalf("create receipt delete trigger: %v", err)
	}

	if _, err := s.CollectHistory(ctx, limits, now); err == nil {
		t.Fatal("CollectHistory(interrupted batch) = nil, want error")
	}
	if got := rowCount(t, s.DB(), `SELECT COUNT(*) FROM message_receipts`); got != 2 {
		t.Fatalf("receipt count after rollback = %d, want 2", got)
	}
	if _, err := s.DB().Exec(`DROP TRIGGER fail_receipt_collection`); err != nil {
		t.Fatalf("drop receipt delete trigger: %v", err)
	}

	usage, err := s.CollectHistory(ctx, limits, now)
	if err != nil {
		t.Fatalf("CollectHistory(retry): %v", err)
	}
	if usage.Maintenance.DeletedMessageReceipts != 1 {
		t.Fatalf("DeletedMessageReceipts = %d, want 1", usage.Maintenance.DeletedMessageReceipts)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM message_receipts WHERE message_id = 301`,
	); got != 0 {
		t.Fatalf("confirmed expired receipt count = %d, want 0", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM message_receipts WHERE message_id = 302 AND ack_state = 'ack_started'`,
	); got != 1 {
		t.Fatalf("uncertain receipt count = %d, want 1", got)
	}
}

func TestCollectHistoryDeletesOnlyExpiredDetachedNetworkLedgers(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	limits.NetworkGCBatchRows = 1
	now := time.Date(2026, 7, 28, 14, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 900, 1900, now.Add(-time.Hour))
	receipt, err := s.RecordOffer(
		ctx,
		offer,
		currentPollEvidence(401, offer.QueueTime, offer.QueueTime),
	)
	if err != nil {
		t.Fatalf("RecordOffer: %v", err)
	}
	var assignmentID int64
	if err := s.DB().QueryRow(`
		SELECT id FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
		t.Fatalf("read assignment id: %v", err)
	}
	for _, ledger := range []struct {
		key        string
		assignment any
		retain     time.Time
	}{
		{"detached-oldest", nil, now.Add(-2 * time.Hour)},
		{"detached-newer", nil, now.Add(-time.Hour)},
		{"detached-future", nil, now.Add(time.Hour)},
		{"attached-expired", assignmentID, now.Add(-3 * time.Hour)},
	} {
		if _, err := s.DB().Exec(`
			INSERT INTO network_ledgers (
				ledger_key, assignment_id, state_digest, updated_at,
				retained_until, logical_bytes
			) VALUES (?, ?, 'opaque', ?, ?, 64)
		`, ledger.key, ledger.assignment, formatTime(now.Add(-4*time.Hour)), formatTime(ledger.retain)); err != nil {
			t.Fatalf("insert ledger %s: %v", ledger.key, err)
		}
	}

	usage, err := s.CollectHistory(ctx, limits, now)
	if err != nil {
		t.Fatalf("CollectHistory(first): %v", err)
	}
	if usage.Maintenance.DeletedNetworkLedgers != 1 {
		t.Fatalf("DeletedNetworkLedgers = %d, want 1", usage.Maintenance.DeletedNetworkLedgers)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM network_ledgers WHERE ledger_key = 'detached-oldest'`,
	); got != 0 {
		t.Fatalf("oldest detached ledger count = %d, want 0", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM network_ledgers WHERE ledger_key IN ('detached-newer', 'detached-future', 'attached-expired')`,
	); got != 3 {
		t.Fatalf("newer/protected/attached ledgers count = %d, want 3", got)
	}

	if _, err := s.CollectHistory(ctx, limits, now); err != nil {
		t.Fatalf("CollectHistory(second): %v", err)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM network_ledgers WHERE ledger_key IN ('detached-future', 'attached-expired')`,
	); got != 2 {
		t.Fatalf("future/attached ledgers count = %d, want 2", got)
	}
}

func TestCollectHistoryExpiredLedgerIsNotStarvedByProtectedLowerIDs(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	limits.MaxNetworkLedgerRows = 2
	limits.NetworkGCBatchRows = 1
	now := time.Date(2026, 7, 28, 14, 15, 0, 0, time.UTC)

	for _, ledger := range []struct {
		key    string
		retain time.Time
	}{
		{"protected-low-id-1", now.Add(time.Hour)},
		{"protected-low-id-2", now.Add(2 * time.Hour)},
		{"expired-high-id", now.Add(-time.Hour)},
	} {
		if _, err := s.DB().Exec(`
			INSERT INTO network_ledgers (
				ledger_key, assignment_id, state_digest, updated_at,
				retained_until, logical_bytes
			) VALUES (?, NULL, 'opaque', ?, ?, 64)
		`, ledger.key, formatTime(now.Add(-2*time.Hour)), formatTime(ledger.retain)); err != nil {
			t.Fatalf("insert ledger %s: %v", ledger.key, err)
		}
	}

	deleted, err := s.deleteExpiredNetworkLedgers(ctx, limits, now)
	if err != nil {
		t.Fatalf("deleteExpiredNetworkLedgers: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("network deletion = %d, want 1", deleted)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM network_ledgers WHERE ledger_key = 'expired-high-id'`,
	); got != 0 {
		t.Fatalf("expired higher-id ledger count = %d, want 0", got)
	}
}

func TestCollectHistoryUsesParsedTimeFloorsNotLexicalTimestampOrder(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	now := time.Date(2026, 7, 28, 14, 30, 0, 0, time.UTC)
	insertTombstone(t, s.DB(), 920, now.Add(-time.Hour), now.Add(-time.Nanosecond))
	insertTombstone(t, s.DB(), 921, now.Add(-time.Hour), now.Add(time.Nanosecond))
	for _, ledger := range []struct {
		key    string
		retain time.Time
	}{
		{"nanosecond-expired", now.Add(-time.Nanosecond)},
		{"nanosecond-protected", now.Add(time.Nanosecond)},
	} {
		if _, err := s.DB().Exec(`
			INSERT INTO network_ledgers (
				ledger_key, assignment_id, state_digest, updated_at,
				retained_until, logical_bytes
			) VALUES (?, NULL, 'opaque', ?, ?, 64)
		`, ledger.key, formatTime(now.Add(-time.Hour)), formatTime(ledger.retain)); err != nil {
			t.Fatalf("insert ledger %s: %v", ledger.key, err)
		}
	}

	if _, err := s.CollectHistory(ctx, limits, now); err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id = 920`,
	); got != 0 {
		t.Fatalf("expired nanosecond tombstone count = %d, want 0", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id = 921`,
	); got != 1 {
		t.Fatalf("protected nanosecond tombstone count = %d, want 1", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM network_ledgers WHERE ledger_key = 'nanosecond-expired'`,
	); got != 0 {
		t.Fatalf("expired nanosecond ledger count = %d, want 0", got)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM network_ledgers WHERE ledger_key = 'nanosecond-protected'`,
	); got != 1 {
		t.Fatalf("protected nanosecond ledger count = %d, want 1", got)
	}
}

func TestPersistedTimeEncodingPreservesSubsecondRetentionOrder(t *testing.T) {
	s := newHistoryStore(t)
	terminalAt := time.Date(2026, 7, 28, 14, 45, 0, 0, time.UTC)
	retainUntil := terminalAt.Add(time.Nanosecond)

	if !(formatTime(terminalAt) < formatTime(retainUntil)) {
		t.Fatalf(
			"persisted timestamp order = %q >= %q",
			formatTime(terminalAt),
			formatTime(retainUntil),
		)
	}
	insertTombstone(t, s.DB(), 930, terminalAt, retainUntil)
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id = 930`,
	); got != 1 {
		t.Fatalf("subsecond-retained tombstone count = %d, want 1", got)
	}
}

func TestHistoryMaintenanceQueriesHaveDedicatedOrderingIndexes(t *testing.T) {
	s := newHistoryStore(t)
	indexNames := []string{
		"assignments_history_oldest",
		"assignments_terminal_collection",
		"history_tombstones_history_oldest",
		"message_receipts_history_oldest",
		"network_ledgers_history_oldest",
		"network_ledgers_retention",
	}
	for _, name := range indexNames {
		if got := rowCount(t, s.DB(), `
			SELECT COUNT(*) FROM sqlite_master
			WHERE type = 'index' AND name = ?
		`, name); got != 1 {
			t.Fatalf("maintenance index %q count = %d, want 1", name, got)
		}
	}
}

func TestMaintenanceCandidateScansAreBoundedByConfiguredCaps(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 14, 50, 0, 0, time.UTC)
	limits := testHistoryLimits()
	limits.MaxHistoryRows = 2
	limits.GCBatchRows = 1
	limits.MaxNetworkLedgerRows = 2
	limits.NetworkGCBatchRows = 1

	insertTombstone(t, s.DB(), 940, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	insertTombstone(t, s.DB(), 941, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := s.DB().Exec(`
		INSERT INTO history_tombstones (
			repository_alias, runner_request_id, attempt,
			offer_digest, offer_payload_digest, terminal_at,
			retain_until, logical_bytes
		) VALUES ('repo-maintenance', 942, 0, zeroblob(32), zeroblob(32), '!', 'not-a-time', 160)
	`); err != nil {
		t.Fatalf("insert out-of-envelope tombstone: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.DB().Exec(`
			INSERT INTO network_ledgers (
				ledger_key, assignment_id, state_digest, updated_at,
				retained_until, logical_bytes
			) VALUES (?, NULL, 'opaque', ?, ?, 64)
		`, fmt.Sprintf("bounded-ledger-%d", i), formatTime(now.Add(-3*time.Hour)),
			formatTime(now.Add(time.Duration(-2+i)*time.Hour))); err != nil {
			t.Fatalf("insert bounded ledger %d: %v", i, err)
		}
	}
	if _, err := s.DB().Exec(`
		INSERT INTO network_ledgers (
			ledger_key, assignment_id, state_digest, updated_at,
			retained_until, logical_bytes
		) VALUES ('out-of-envelope-ledger', NULL, 'opaque', ?, 'not-a-time', 64)
	`, formatTime(now)); err != nil {
		t.Fatalf("insert out-of-envelope ledger: %v", err)
	}

	receipts, tombstones, err := s.deleteExpiredHistory(ctx, limits, now)
	if err != nil {
		t.Fatalf("deleteExpiredHistory: %v", err)
	}
	if receipts != 0 || tombstones != 1 {
		t.Fatalf("history deletion = receipts %d tombstones %d, want 0/1", receipts, tombstones)
	}
	deletedLedgers, err := s.deleteExpiredNetworkLedgers(ctx, limits, now)
	if err != nil {
		t.Fatalf("deleteExpiredNetworkLedgers: %v", err)
	}
	if deletedLedgers != 1 {
		t.Fatalf("network deletion = %d, want 1", deletedLedgers)
	}
}

func TestReadOnlyHistoryStoreRequiresExistingCurrentSchemaAndRejectsWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	limits := testHistoryLimits()
	writable, err := OpenWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	maintainedAt := time.Date(2026, 7, 28, 14, 55, 0, 0, time.UTC)
	if _, err := writable.CollectHistory(
		context.Background(),
		limits,
		maintainedAt,
	); err != nil {
		_ = writable.Close()
		t.Fatalf("CollectHistory: %v", err)
	}
	if err := writable.Close(); err != nil {
		t.Fatalf("close writable store: %v", err)
	}

	readOnly, err := OpenReadOnlyWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenReadOnlyWithHistoryLimits: %v", err)
	}
	usage, err := readOnly.HistoryUsage(context.Background(), limits)
	if err != nil {
		_ = readOnly.Close()
		t.Fatalf("HistoryUsage(read-only): %v", err)
	}
	if !usage.Maintenance.ObservedAt.Equal(maintainedAt) {
		_ = readOnly.Close()
		t.Fatalf(
			"read-only maintenance time = %s, want %s",
			usage.Maintenance.ObservedAt,
			maintainedAt,
		)
	}
	if _, err := readOnly.DB().Exec(`DELETE FROM history_maintenance`); err == nil {
		_ = readOnly.Close()
		t.Fatal("read-only store accepted a write")
	}
	if err := readOnly.Close(); err != nil {
		t.Fatalf("close read-only store: %v", err)
	}

	missingPath := filepath.Join(t.TempDir(), "missing.db")
	if _, err := OpenReadOnlyWithHistoryLimits(missingPath, limits); !errors.Is(err, ErrOfflineMigration) {
		t.Fatalf("read-only missing database error = %v, want ErrOfflineMigration", err)
	}
	if _, err := os.Stat(missingPath); !os.IsNotExist(err) {
		t.Fatalf("missing database stat error = %v, want not-exist", err)
	}
}

func TestCollectHistoryReportsAggregatePhysicalAndCheckpointResult(t *testing.T) {
	s := newHistoryStore(t)
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	usage, err := s.CollectHistory(context.Background(), testHistoryLimits(), now)
	if err != nil {
		t.Fatalf("CollectHistory: %v", err)
	}
	if usage.ActivePageBytes == 0 {
		t.Fatal("ActivePageBytes = 0, want positive aggregate")
	}
	if !usage.Maintenance.ObservedAt.Equal(now) {
		t.Fatalf("maintenance observed_at = %s, want %s", usage.Maintenance.ObservedAt, now)
	}
	if usage.Maintenance.VacuumedPages > testHistoryLimits().VacuumBatchPages {
		t.Fatalf(
			"VacuumedPages = %d, exceeds configured batch %d",
			usage.Maintenance.VacuumedPages,
			testHistoryLimits().VacuumBatchPages,
		)
	}
}

func TestCollectHistoryBusyCheckpointIsObservableAndNonfatal(t *testing.T) {
	s := newHistoryStore(t)
	now := time.Date(2026, 7, 28, 15, 30, 0, 0, time.UTC)
	usage, err := s.collectHistory(
		context.Background(),
		testHistoryLimits(),
		now,
		func(context.Context) (bool, uint64, uint64, error) {
			return true, 9, 3, nil
		},
	)
	if err != nil {
		t.Fatalf("collectHistory(busy checkpoint): %v", err)
	}
	if !usage.Maintenance.CheckpointBusy ||
		usage.Maintenance.CheckpointLogPages != 9 ||
		usage.Maintenance.CheckpointedPages != 3 {
		t.Fatalf("busy checkpoint result = %+v", usage.Maintenance)
	}
}

func TestFailedMaintenanceKeepsPriorCompletedCycleMarker(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	first := time.Date(2026, 7, 28, 15, 40, 0, 0, time.UTC)
	if _, err := s.CollectHistory(ctx, limits, first); err != nil {
		t.Fatalf("CollectHistory(first): %v", err)
	}
	insertTombstone(t, s.DB(), 980, first.Add(-2*time.Hour), first.Add(-time.Hour))

	injected := errors.New("injected checkpoint failure")
	if _, err := s.collectHistory(
		ctx,
		limits,
		first.Add(time.Minute),
		func(context.Context) (bool, uint64, uint64, error) {
			return false, 0, 0, injected
		},
	); !errors.Is(err, injected) {
		t.Fatalf("collectHistory(failed cycle) error = %v, want injected", err)
	}
	if got := rowCount(t, s.DB(),
		`SELECT COUNT(*) FROM history_tombstones WHERE runner_request_id = 980`,
	); got != 0 {
		t.Fatalf("expired tombstone after partial cycle = %d, want 0", got)
	}
	usage, err := s.HistoryUsage(ctx, limits)
	if err != nil {
		t.Fatalf("HistoryUsage: %v", err)
	}
	if !usage.Maintenance.ObservedAt.Equal(first) {
		t.Fatalf(
			"last completed maintenance = %s, want %s",
			usage.Maintenance.ObservedAt,
			first,
		)
	}
}

func TestBoundedHistorySoak(t *testing.T) {
	path := fmt.Sprintf("%s/controller.db", t.TempDir())
	limits := testHistoryLimits()
	limits.MinRetention = time.Minute
	limits.MaxHistoryRows = 32
	limits.MaxHistoryLogicalBytes = 1 << 20
	limits.MaxNetworkLedgerRows = 8
	limits.MaxNetworkLedgerLogicalBytes = 1 << 16
	limits.GCBatchRows = 8
	limits.NetworkGCBatchRows = 4
	s, err := OpenWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	base := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	var warmActive, warmWAL uint64
	for i := 0; i < int(limits.MaxHistoryRows)*3; i++ {
		cycleAt := base.Add(time.Duration(i) * 2 * time.Minute)
		messageID := 500 + i
		offer := historyOffer("repo-soak", int64(1000+i), int64(2000+i), cycleAt)
		record, err := s.RecordOffer(
			ctx,
			offer,
			currentPollEvidence(messageID, cycleAt, cycleAt),
		)
		if err != nil {
			t.Fatalf("cycle %d RecordOffer: %v", i, err)
		}
		recordMessageReceiptForOffers(t, s, "repo-soak", messageID, cycleAt.Add(10*time.Second), offer)
		if err := s.BeginMessageAck(ctx, "repo-soak", messageID, cycleAt.Add(20*time.Second)); err != nil {
			t.Fatalf("cycle %d BeginMessageAck: %v", i, err)
		}
		if err := s.ConfirmMessageAck(ctx, "repo-soak", messageID, cycleAt.Add(30*time.Second)); err != nil {
			t.Fatalf("cycle %d ConfirmMessageAck: %v", i, err)
		}
		terminalMessage(t, s, record.Key, messageID)
		if err := s.Advance(ctx, record.Key, controller.StateDestroyed); err != nil {
			t.Fatalf("cycle %d Advance: %v", i, err)
		}
		if _, err := s.DB().Exec(`
			UPDATE assignments SET updated_at = ?
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, formatTime(cycleAt), record.Key.RepositoryAlias, record.Key.RunnerRequestID, record.Key.Attempt); err != nil {
			t.Fatalf("cycle %d set deterministic terminal checkpoint: %v", i, err)
		}
		var assignmentID int64
		if err := s.DB().QueryRow(`
			SELECT id FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, record.Key.RepositoryAlias, record.Key.RunnerRequestID, record.Key.Attempt).Scan(&assignmentID); err != nil {
			t.Fatalf("cycle %d assignment id: %v", i, err)
		}
		if _, err := s.DB().Exec(`
			INSERT INTO network_ledgers (
				ledger_key, assignment_id, state_digest, updated_at,
				retained_until, logical_bytes
			) VALUES (?, ?, 'opaque', ?, ?, 64)
		`, fmt.Sprintf("soak-ledger-%d", i), assignmentID, formatTime(cycleAt),
			formatTime(cycleAt.Add(3*time.Minute))); err != nil {
			t.Fatalf("cycle %d insert ledger: %v", i, err)
		}

		usage, err := s.CollectHistory(ctx, limits, cycleAt.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("cycle %d CollectHistory: %v", i, err)
		}
		historyRows, rowOverflow := addHistoryBytes(
			usage.LiveRows,
			usage.ProtectedTerminalRows,
			usage.MessageReceiptRows,
			usage.TombstoneRows,
			usage.ReservedRows,
		)
		historyBytes, byteOverflow := addHistoryBytes(
			usage.LiveLogicalBytes,
			usage.ProtectedTerminalBytes,
			usage.MessageReceiptBytes,
			usage.TombstoneLogicalBytes,
			usage.ReservedLogicalBytes,
		)
		if rowOverflow != nil || byteOverflow != nil ||
			historyRows > limits.MaxHistoryRows ||
			historyBytes > limits.MaxHistoryLogicalBytes ||
			usage.NetworkLedgerRows > limits.MaxNetworkLedgerRows ||
			usage.NetworkLedgerLogicalBytes > limits.MaxNetworkLedgerLogicalBytes {
			t.Fatalf("cycle %d usage escaped bounds: %+v", i, usage)
		}
		if got := rowCount(t, s.DB(), `SELECT COUNT(*) FROM assignments`); got != 0 {
			t.Fatalf("cycle %d assignments = %d, want 0", i, got)
		}
		if usage.NetworkLedgerRows > 2 {
			t.Fatalf("cycle %d network ledger rows = %d, want <= 2", i, usage.NetworkLedgerRows)
		}
		if i == int(limits.MaxHistoryRows) {
			warmActive, warmWAL = usage.ActivePageBytes, usage.WALBytes
		}
		if i > int(limits.MaxHistoryRows) {
			const testOnlyGrowthSlack = uint64(1 << 20)
			if usage.ActivePageBytes > warmActive+testOnlyGrowthSlack ||
				usage.WALBytes > warmWAL+testOnlyGrowthSlack {
				t.Fatalf(
					"cycle %d storage did not reach a bounded steady state: active=%d/%d wal=%d/%d",
					i,
					usage.ActivePageBytes,
					warmActive,
					usage.WALBytes,
					warmWAL,
				)
			}
		}
	}
}
