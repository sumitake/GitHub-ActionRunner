package state

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func testHistoryLimits() HistoryLimits {
	return HistoryLimits{
		MinRetention:                 24 * time.Hour,
		MaxHistoryRows:               256,
		MaxHistoryLogicalBytes:       1 << 20,
		MaxNetworkLedgerRows:         64,
		MaxNetworkLedgerLogicalBytes: 1 << 18,
		InflightReserveRows:          8,
		InflightReserveLogicalBytes:  1 << 14,
		GCBatchRows:                  16,
		NetworkGCBatchRows:           8,
		VacuumBatchPages:             4,
		MaintenanceCadence:           time.Minute,
	}
}

func newHistoryStore(t *testing.T) *SQLiteStore {
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

func historyOffer(repositoryAlias string, requestID, workflowJobID int64, queuedAt time.Time) OfferIdentity {
	return OfferIdentity{
		RepositoryAlias:    repositoryAlias,
		RunnerRequestID:    requestID,
		WorkflowJobID:      workflowJobID,
		JobID:              fmt.Sprintf("job-%d", workflowJobID),
		RepositoryName:     "owner/repository",
		OwnerName:          "owner",
		JobWorkflowRef:     "owner/repository/.github/workflows/test.yml@refs/heads/main",
		JobDisplayName:     "bounded history test",
		WorkflowRunID:      workflowJobID + 1000,
		EventName:          "push",
		RequestLabels:      []string{"self-hosted", "portable-ghar"},
		QueueTime:          queuedAt.UTC(),
		ScaleSetAssignTime: time.Time{},
		RunnerAssignTime:   time.Time{},
		FinishTime:         time.Time{},
		AcquireJobURL:      "https://example.invalid/acquire",
	}
}

func currentPollEvidence(messageID int, queuedAt, observedAt time.Time) OfferEvidence {
	return OfferEvidence{
		Kind:       EvidenceCurrentPoll,
		MessageID:  messageID,
		QueueTime:  queuedAt.UTC(),
		ObservedAt: observedAt.UTC(),
	}
}

func messageEnvelopeForOffers(
	repositoryAlias string,
	messageID int,
	offers ...OfferIdentity,
) controller.MessageEnvelope {
	envelope := controller.MessageEnvelope{
		RepositoryAlias: repositoryAlias,
		MessageID:       messageID,
	}
	for _, offer := range offers {
		envelope.Offers = append(envelope.Offers, controller.MessageOffer{
			Job: controller.MessageJobRef{
				RunnerRequestID:    offer.RunnerRequestID,
				JobID:              offer.JobID,
				RepositoryName:     offer.RepositoryName,
				OwnerName:          offer.OwnerName,
				JobWorkflowRef:     offer.JobWorkflowRef,
				JobDisplayName:     offer.JobDisplayName,
				WorkflowRunID:      offer.WorkflowRunID,
				EventName:          offer.EventName,
				RequestLabels:      append([]string(nil), offer.RequestLabels...),
				QueueTime:          offer.QueueTime,
				ScaleSetAssignTime: offer.ScaleSetAssignTime,
				RunnerAssignTime:   offer.RunnerAssignTime,
				FinishTime:         offer.FinishTime,
			},
			AcquireJobURL: offer.AcquireJobURL,
		})
	}
	return envelope
}

func recordMessageReceiptForOffers(
	t *testing.T,
	s *SQLiteStore,
	repositoryAlias string,
	messageID int,
	at time.Time,
	offers ...OfferIdentity,
) MessageReceipt {
	t.Helper()
	receipt, err := s.RecordMessageReceipt(
		context.Background(),
		messageEnvelopeForOffers(repositoryAlias, messageID, offers...),
		at,
	)
	if err != nil {
		t.Fatalf("RecordMessageReceipt() = %v", err)
	}
	return receipt
}

func terminalMessage(t *testing.T, s *SQLiteStore, key controller.AssignmentKey, messageID int) {
	t.Helper()
	if _, err := s.DB().Exec(
		`UPDATE assignments SET terminal_message_id = ? WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?`,
		messageID, key.RepositoryAlias, key.RunnerRequestID, key.Attempt,
	); err != nil {
		t.Fatalf("bind terminal message: %v", err)
	}
}

func assignmentCheckpoint(t *testing.T, s *SQLiteStore, key controller.AssignmentKey) time.Time {
	t.Helper()
	var checkpointText string
	if err := s.DB().QueryRow(`
		SELECT updated_at FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(&checkpointText); err != nil {
		t.Fatalf("read assignment checkpoint time: %v", err)
	}
	checkpoint, err := time.Parse(time.RFC3339Nano, checkpointText)
	if err != nil {
		t.Fatalf("parse assignment checkpoint time: %v", err)
	}
	return checkpoint
}

func terminalCheckpoint(t *testing.T, s *SQLiteStore, key controller.AssignmentKey) time.Time {
	t.Helper()
	return assignmentCheckpoint(t, s, key)
}

func compactableOffer(
	t *testing.T,
	s *SQLiteStore,
	requestID int64,
	messageID int,
	queuedAt time.Time,
) (OfferIdentity, OfferReceipt) {
	t.Helper()
	ctx := context.Background()
	offer := historyOffer("repo-a", requestID, requestID+1000, queuedAt)
	receipt, err := s.RecordOffer(ctx, offer, currentPollEvidence(messageID, queuedAt, queuedAt.Add(time.Second)))
	if err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	recordMessageReceiptForOffers(t, s, offer.RepositoryAlias, messageID, queuedAt.Add(30*time.Second), offer)
	if err := s.BeginMessageAck(ctx, offer.RepositoryAlias, messageID, queuedAt.Add(time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck() = %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, offer.RepositoryAlias, messageID, queuedAt.Add(2*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck() = %v", err)
	}
	terminalMessage(t, s, receipt.Key, messageID)
	if err := s.Advance(ctx, receipt.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(RECEIVED->DESTROYED) = %v", err)
	}
	return offer, receipt
}

func TestHistoryTypes(t *testing.T) {
	if OfferInserted == OfferActiveReplay || OfferActiveReplay == OfferTerminalReplay {
		t.Fatal("OfferDisposition constants are not distinct")
	}
	if EvidenceCurrentPoll == EvidenceSelectiveReadback {
		t.Fatal("OfferEvidenceKind constants are not distinct")
	}
	if !errors.Is(fmt.Errorf("wrapped: %w", ErrIdentityConflict), ErrIdentityConflict) {
		t.Fatal("ErrIdentityConflict does not support errors.Is")
	}

	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	for _, method := range []string{
		"RecordOffer",
		"BeginMessageAck",
		"ConfirmMessageAck",
		"ObserveMessageRedelivery",
		"CompactTerminal",
		"HistoryUsage",
		"CollectHistory",
	} {
		if _, ok := storeType.MethodByName(method); !ok {
			t.Errorf("Store.%s is missing", method)
		}
	}
	if _, ok := storeType.MethodByName("UpsertOffer"); ok {
		t.Fatal("Store.UpsertOffer compatibility path remains exposed")
	}
}

func TestHistorySchema(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()

	var version int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("PRAGMA user_version: %v", err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("user_version = %d, want %d", version, currentSchemaVersion)
	}

	var autoVacuum int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		t.Fatalf("PRAGMA auto_vacuum: %v", err)
	}
	if autoVacuum != sqliteAutoVacuumIncremental {
		t.Fatalf("auto_vacuum = %d, want %d (INCREMENTAL)", autoVacuum, sqliteAutoVacuumIncremental)
	}

	for _, table := range []string{"message_receipts", "history_tombstones"} {
		var count int
		if err := s.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
		).Scan(&count); err != nil {
			t.Fatalf("query table %q: %v", table, err)
		}
		if count != 1 {
			t.Errorf("table %q count = %d, want 1", table, count)
		}
	}

	requiredAssignmentColumns := map[string]bool{
		"offer_digest": false, "offer_payload_digest": false,
		"queue_time": false, "source_message_id": false,
		"terminal_message_id": false, "request_labels": false,
		"admission_phase": false, "admission_slot_id": false,
		"full_memory_bytes": false, "ledger_memory_bytes": false,
		"ledger_created_at": false, "ledger_ever_used": false,
		"history_logical_bytes": false,
	}
	rows, err := s.DB().QueryContext(ctx, `PRAGMA table_info(assignments)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info(assignments): %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("scan assignment column: %v", err)
		}
		if _, required := requiredAssignmentColumns[name]; required {
			requiredAssignmentColumns[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("assignment columns: %v", err)
	}
	for column, found := range requiredAssignmentColumns {
		if !found {
			t.Errorf("assignments.%s is missing", column)
		}
	}

	queuedAt := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 101, 1001, queuedAt)
	if _, err := s.RecordOffer(ctx, offer, currentPollEvidence(77, queuedAt, queuedAt.Add(time.Second))); err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE assignments SET offer_digest = x'01' WHERE repository_alias = ? AND runner_request_id = ?`,
		offer.RepositoryAlias, offer.RunnerRequestID,
	); err == nil {
		t.Fatal("one-byte offer_digest update succeeded, want CHECK failure")
	}

	nowText := queuedAt.Format(time.RFC3339Nano)
	if _, err := s.DB().ExecContext(ctx, `
		INSERT INTO message_receipts
			(repository_alias, message_id, payload_digest, persisted_at, ack_state, logical_bytes)
		VALUES (?, ?, zeroblob(32), ?, 'invalid', 1)
	`, "repo-a", 88, nowText); err == nil {
		t.Fatal("invalid message_receipts.ack_state insert succeeded")
	}
	if _, err := s.DB().ExecContext(ctx, `
		INSERT INTO history_tombstones
			(repository_alias, runner_request_id, attempt, offer_digest, offer_payload_digest, terminal_at, retain_until, logical_bytes)
		VALUES (?, ?, 0, zeroblob(32), zeroblob(32), ?, ?, 1)
	`, "repo-a", 999, queuedAt.Add(time.Hour).Format(time.RFC3339Nano), nowText); err == nil {
		t.Fatal("history_tombstones retain_until before terminal_at insert succeeded")
	}
}

func TestHistorySchemaRefusesFutureVersionBeforeWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	db, err := sql.Open("sqlite", dsnForPath(path))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
		t.Fatalf("set auto_vacuum: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE sentinel (value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create sentinel: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sentinel (value) VALUES ('unchanged')`); err != nil {
		t.Fatalf("insert sentinel: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, currentSchemaVersion+1)); err != nil {
		t.Fatalf("set future user_version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed database: %v", err)
	}

	if _, err := Open(path); !errors.Is(err, ErrOfflineMigration) {
		t.Fatalf("Open(future schema) error = %v, want ErrOfflineMigration", err)
	}

	verify, err := sql.Open("sqlite", dsnForPath(path))
	if err != nil {
		t.Fatalf("reopen seed database: %v", err)
	}
	defer verify.Close()
	var value string
	if err := verify.QueryRow(`SELECT value FROM sentinel`).Scan(&value); err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	if value != "unchanged" {
		t.Errorf("sentinel = %q, want unchanged", value)
	}
	var version int
	if err := verify.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("read future user_version: %v", err)
	}
	if version != currentSchemaVersion+1 {
		t.Errorf("user_version after rejected open = %d, want %d", version, currentSchemaVersion+1)
	}
}

func TestHistorySchemaRefusesExistingNonIncrementalDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE legacy (value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	if _, err := Open(path); !errors.Is(err, ErrOfflineMigration) {
		t.Fatalf("Open(non-incremental legacy schema) error = %v, want ErrOfflineMigration", err)
	}
}

func seedHistorySchemaV0(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dsnForPath(path))
	if err != nil {
		t.Fatalf("sql.Open(%q): %v", path, err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close legacy database: %v", err)
		}
	})
	if _, err := db.Exec(`PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
		t.Fatalf("set legacy auto_vacuum: %v", err)
	}
	if _, err := db.Exec(schemaV0); err != nil {
		t.Fatalf("create schema v0: %v", err)
	}
	if _, err := db.Exec(seedAcquisitionState, string(controller.AcquisitionDisabled)); err != nil {
		t.Fatalf("seed legacy acquisition state: %v", err)
	}
	now := time.Date(2026, 7, 28, 11, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	res, err := db.Exec(`
		INSERT INTO assignments (
			repository_alias, runner_request_id, attempt, workflow_job_id,
			state, released, release_generation, created_at, updated_at
		) VALUES (?, ?, 0, ?, ?, 0, 0, ?, ?)
	`, "repo-legacy", 91, 991, string(controller.StateCapacityReserved), now, now)
	if err != nil {
		t.Fatalf("insert legacy assignment: %v", err)
	}
	assignmentID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("legacy assignment id: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO runner_slots (
			assignment_id, opaque_name, capacity_slot_id, created_at, updated_at
		) VALUES (?, 'slot-legacy', 17, ?, ?)
	`, assignmentID, now, now); err != nil {
		t.Fatalf("insert legacy runner slot: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO reservations (assignment_id, capacity_slot_id, reserved_at)
		VALUES (?, 17, ?)
	`, assignmentID, now); err != nil {
		t.Fatalf("insert legacy reservation: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO effects (
			assignment_id, idempotency_key, kind, began_at, completed_at,
			result_identity
		) VALUES (?, 'legacy-effect', 'create', ?, ?, 'opaque-result')
	`, assignmentID, now, now); err != nil {
		t.Fatalf("insert legacy effect: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO network_ledgers (
			ledger_key, assignment_id, state_digest, updated_at, retained_until
		) VALUES ('legacy-ledger', ?, 'opaque-state', ?, ?)
	`, assignmentID, now, now); err != nil {
		t.Fatalf("insert legacy network ledger: %v", err)
	}
	if _, err := db.Exec(`PRAGMA user_version=0`); err != nil {
		t.Fatalf("set legacy user_version: %v", err)
	}
	return db
}

func databaseSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out bytes.Buffer
	var version, autoVacuum int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("snapshot user_version: %v", err)
	}
	if err := db.QueryRow(`PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		t.Fatalf("snapshot auto_vacuum: %v", err)
	}
	fmt.Fprintf(&out, "user_version=%d\nauto_vacuum=%d\n", version, autoVacuum)

	schemaRows, err := db.Query(`
		SELECT type, name, tbl_name, COALESCE(sql, '')
		FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%'
		ORDER BY type, name
	`)
	if err != nil {
		t.Fatalf("snapshot schema: %v", err)
	}
	var tables []string
	for schemaRows.Next() {
		var objectType, name, tableName, definition string
		if err := schemaRows.Scan(&objectType, &name, &tableName, &definition); err != nil {
			_ = schemaRows.Close()
			t.Fatalf("snapshot schema row: %v", err)
		}
		fmt.Fprintf(&out, "schema|%s|%s|%s|%s\n", objectType, name, tableName, definition)
		if objectType == "table" {
			tables = append(tables, name)
		}
	}
	if err := schemaRows.Err(); err != nil {
		_ = schemaRows.Close()
		t.Fatalf("snapshot schema rows: %v", err)
	}
	if err := schemaRows.Close(); err != nil {
		t.Fatalf("close snapshot schema rows: %v", err)
	}

	for _, table := range tables {
		columnRows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%q)`, table))
		if err != nil {
			t.Fatalf("snapshot %s columns: %v", table, err)
		}
		var columns []string
		for columnRows.Next() {
			var cid, notNull, primaryKey int
			var name, columnType string
			var defaultValue any
			if err := columnRows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = columnRows.Close()
				t.Fatalf("snapshot %s column: %v", table, err)
			}
			columns = append(columns, name)
		}
		if err := columnRows.Err(); err != nil {
			_ = columnRows.Close()
			t.Fatalf("snapshot %s columns: %v", table, err)
		}
		if err := columnRows.Close(); err != nil {
			t.Fatalf("close snapshot %s columns: %v", table, err)
		}
		selectColumns := make([]string, len(columns))
		for i, column := range columns {
			selectColumns[i] = fmt.Sprintf("quote(%q)", column)
		}
		dataRows, err := db.Query(fmt.Sprintf(
			`SELECT %s FROM %q ORDER BY rowid`,
			strings.Join(selectColumns, ", "), table,
		))
		if err != nil {
			t.Fatalf("snapshot %s data: %v", table, err)
		}
		for dataRows.Next() {
			values := make([]string, len(columns))
			destinations := make([]any, len(columns))
			for i := range values {
				destinations[i] = &values[i]
			}
			if err := dataRows.Scan(destinations...); err != nil {
				_ = dataRows.Close()
				t.Fatalf("snapshot %s data row: %v", table, err)
			}
			fmt.Fprintf(&out, "data|%s|%s\n", table, strings.Join(values, "|"))
		}
		if err := dataRows.Err(); err != nil {
			_ = dataRows.Close()
			t.Fatalf("snapshot %s data rows: %v", table, err)
		}
		if err := dataRows.Close(); err != nil {
			t.Fatalf("close snapshot %s data rows: %v", table, err)
		}
	}
	return out.String()
}

func databaseSchemaSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out bytes.Buffer
	rows, err := db.Query(`
		SELECT type, name, tbl_name, COALESCE(sql, '')
		FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%'
		ORDER BY type, name
	`)
	if err != nil {
		t.Fatalf("schema snapshot: %v", err)
	}
	for rows.Next() {
		var objectType, name, tableName, definition string
		if err := rows.Scan(&objectType, &name, &tableName, &definition); err != nil {
			_ = rows.Close()
			t.Fatalf("schema snapshot row: %v", err)
		}
		fmt.Fprintf(&out, "%s|%s|%s|%s\n",
			objectType, name, tableName, strings.Join(strings.Fields(definition), " "))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatalf("schema snapshot rows: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close schema snapshot rows: %v", err)
	}
	return out.String()
}

func TestHistorySchemaMigratesV0AndRollsBackEveryWrite(t *testing.T) {
	ctx := context.Background()
	successPath := filepath.Join(t.TempDir(), "success.db")
	successDB := seedHistorySchemaV0(t, successPath)
	var migrationSteps int
	if err := migrateV0ToV1WithHook(ctx, successDB, func(_ int, _ string) error {
		migrationSteps++
		return nil
	}); err != nil {
		t.Fatalf("migrateV0ToV1WithHook(success) = %v", err)
	}
	if migrationSteps == 0 {
		t.Fatal("migration executed zero injectable write steps")
	}

	var version int
	if err := successDB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("read migrated user_version: %v", err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("migrated user_version = %d, want %d", version, currentSchemaVersion)
	}
	legacyIdentity := OfferIdentity{
		RepositoryAlias: "repo-legacy",
		RunnerRequestID: 91,
		WorkflowJobID:   991,
	}
	wantIdentity := CanonicalOfferDigest(legacyIdentity)
	wantPayload := CanonicalOfferPayloadDigest(legacyIdentity)
	var gotIdentity, gotPayload []byte
	var logicalBytes int64
	if err := successDB.QueryRow(`
		SELECT offer_digest, offer_payload_digest, history_logical_bytes
		FROM assignments
		WHERE repository_alias = 'repo-legacy' AND runner_request_id = 91
	`).Scan(&gotIdentity, &gotPayload, &logicalBytes); err != nil {
		t.Fatalf("read migrated offer: %v", err)
	}
	if !bytes.Equal(gotIdentity, wantIdentity[:]) || !bytes.Equal(gotPayload, wantPayload[:]) || logicalBytes <= 0 {
		t.Fatalf("migrated offer = identity %x payload %x bytes %d", gotIdentity, gotPayload, logicalBytes)
	}
	for _, table := range []string{"runner_slots", "reservations", "effects", "network_ledgers"} {
		var count int
		if err := successDB.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %q`, table)).Scan(&count); err != nil {
			t.Fatalf("count migrated %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("migrated %s rows = %d, want 1", table, count)
		}
	}
	var foreignKeyFailures int
	if err := successDB.QueryRow(`SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&foreignKeyFailures); err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	if foreignKeyFailures != 0 {
		t.Fatalf("foreign_key_check failures = %d, want 0", foreignKeyFailures)
	}

	injected := errors.New("injected migration failure")
	for failAt := 1; failAt <= migrationSteps; failAt++ {
		t.Run(fmt.Sprintf("rollback-before-write-%03d", failAt), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rollback.db")
			db := seedHistorySchemaV0(t, path)
			before := databaseSnapshot(t, db)
			err := migrateV0ToV1WithHook(ctx, db, func(step int, _ string) error {
				if step == failAt {
					return injected
				}
				return nil
			})
			if !errors.Is(err, injected) {
				t.Fatalf("migration error = %v, want injected failure at write %d", err, failAt)
			}
			after := databaseSnapshot(t, db)
			if after != before {
				t.Fatalf("database changed after failure before write %d\n--- before ---\n%s\n--- after ---\n%s", failAt, before, after)
			}
		})
	}
}

func TestHistorySchemaBootstrapRollsBackEveryWrite(t *testing.T) {
	ctx := context.Background()
	openEmpty := func(t *testing.T) *sql.DB {
		t.Helper()
		path := filepath.Join(t.TempDir(), "bootstrap.db")
		db, err := sql.Open("sqlite", dsnForPath(path))
		if err != nil {
			t.Fatalf("sql.Open(%q): %v", path, err)
		}
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Errorf("close bootstrap database: %v", err)
			}
		})
		return db
	}

	successDB := openEmpty(t)
	var migrationSteps int
	if err := bootstrapV1WithHook(ctx, successDB, func(_ int, _ string) error {
		migrationSteps++
		return nil
	}); err != nil {
		t.Fatalf("bootstrapV1WithHook(success) = %v", err)
	}
	if migrationSteps == 0 {
		t.Fatal("bootstrap executed zero injectable write steps")
	}

	injected := errors.New("injected bootstrap failure")
	for failAt := 1; failAt <= migrationSteps; failAt++ {
		t.Run(fmt.Sprintf("rollback-before-write-%03d", failAt), func(t *testing.T) {
			db := openEmpty(t)
			before := databaseSnapshot(t, db)
			err := bootstrapV1WithHook(ctx, db, func(step int, _ string) error {
				if step == failAt {
					return injected
				}
				return nil
			})
			if !errors.Is(err, injected) {
				t.Fatalf("bootstrap error = %v, want injected failure at write %d", err, failAt)
			}
			after := databaseSnapshot(t, db)
			if after != before {
				t.Fatalf("database changed after bootstrap failure before write %d\n--- before ---\n%s\n--- after ---\n%s", failAt, before, after)
			}
		})
	}
}

func TestHistorySchemaUpgradeMatchesBootstrap(t *testing.T) {
	ctx := context.Background()
	freshPath := filepath.Join(t.TempDir(), "fresh.db")
	fresh, err := OpenWithHistoryLimits(freshPath, testHistoryLimits())
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits(fresh) = %v", err)
	}
	defer fresh.Close()

	upgradedPath := filepath.Join(t.TempDir(), "upgraded.db")
	upgraded := seedHistorySchemaV0(t, upgradedPath)
	if err := migrateV0ToV1WithHook(ctx, upgraded, nil); err != nil {
		t.Fatalf("migrateV0ToV1WithHook(upgraded) = %v", err)
	}

	freshSchema := databaseSchemaSnapshot(t, fresh.DB())
	upgradedSchema := databaseSchemaSnapshot(t, upgraded)
	if upgradedSchema != freshSchema {
		t.Fatalf("upgraded schema differs from bootstrap\n--- bootstrap ---\n%s\n--- upgraded ---\n%s", freshSchema, upgradedSchema)
	}
}

func TestCanonicalOfferDigest(t *testing.T) {
	offer := OfferIdentity{
		RepositoryAlias: "répo/测试",
		RunnerRequestID: 42,
		WorkflowJobID:   99,
	}
	got := CanonicalOfferDigest(offer)
	want, err := hex.DecodeString("7c3bb3c153920499854fbb5b8178c271c3a90313fde3313cef8d8ec0c3fad411")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("CanonicalOfferDigest() = %x, want %x", got, want)
	}

	changedJob := offer
	changedJob.WorkflowJobID++
	if CanonicalOfferDigest(changedJob) == got {
		t.Fatal("workflow-job mismatch did not change canonical digest")
	}
	changedAlias := offer
	changedAlias.RepositoryAlias += "\x00suffix"
	if CanonicalOfferDigest(changedAlias) == got {
		t.Fatal("length-prefixed alias mismatch did not change canonical digest")
	}
	if got == sha256.Sum256([]byte("portable-ghar.offer.v1"+offer.RepositoryAlias)) {
		t.Fatal("digest unexpectedly matches delimiter-free encoding")
	}

	full := historyOffer("répo/测试", 42, 99, time.Date(2026, 7, 28, 1, 2, 3, 4, time.UTC))
	identityDigest := CanonicalOfferDigest(full)
	payloadDigest := CanonicalOfferPayloadDigest(full)
	changedPayload := full
	changedPayload.RequestLabels = append([]string(nil), full.RequestLabels...)
	changedPayload.RequestLabels[0] = "different"
	if CanonicalOfferDigest(changedPayload) != identityDigest {
		t.Fatal("display-payload change altered the fixed identity digest")
	}
	if CanonicalOfferPayloadDigest(changedPayload) == payloadDigest {
		t.Fatal("display-payload change did not alter the full payload digest")
	}
}

func TestRecordOfferReplayConflictAndEvidence(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	queuedAt := time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC)
	evidence := currentPollEvidence(100, queuedAt, queuedAt.Add(time.Second))
	offer := historyOffer("repo-a", 200, 1200, queuedAt)

	inserted, err := s.RecordOffer(ctx, offer, evidence)
	if err != nil {
		t.Fatalf("RecordOffer(insert) = %v", err)
	}
	if inserted.Disposition != OfferInserted || inserted.State != controller.StateReceived {
		t.Fatalf("insert receipt = %+v, want inserted/RECEIVED", inserted)
	}
	if inserted.Key != (controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 200, Attempt: 0}) {
		t.Fatalf("insert key = %+v", inserted.Key)
	}

	checkpointBeforeActiveReplay := assignmentCheckpoint(t, s, inserted.Key)
	activeEvidence := currentPollEvidence(100, queuedAt, queuedAt.Add(10*time.Minute))
	active, err := s.RecordOffer(ctx, offer, activeEvidence)
	if err != nil {
		t.Fatalf("RecordOffer(active replay) = %v", err)
	}
	if active.Disposition != OfferActiveReplay {
		t.Fatalf("active replay disposition = %v, want %v", active.Disposition, OfferActiveReplay)
	}
	if checkpointAfterActiveReplay := assignmentCheckpoint(t, s, inserted.Key); !checkpointAfterActiveReplay.Equal(checkpointBeforeActiveReplay) {
		t.Fatalf(
			"active replay changed assignment checkpoint from %s to %s",
			checkpointBeforeActiveReplay,
			checkpointAfterActiveReplay,
		)
	}

	conflict := offer
	conflict.WorkflowJobID++
	if _, err := s.RecordOffer(ctx, conflict, evidence); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("RecordOffer(conflict) error = %v, want ErrIdentityConflict", err)
	}
	payloadConflict := offer
	payloadConflict.RequestLabels = append([]string(nil), offer.RequestLabels...)
	payloadConflict.RequestLabels[1] = "changed-label"
	if _, err := s.RecordOffer(ctx, payloadConflict, evidence); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("RecordOffer(payload conflict) error = %v, want ErrIdentityConflict", err)
	}

	if err := s.Advance(ctx, inserted.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(RECEIVED->DESTROYED) = %v", err)
	}
	terminalAtBeforeReplay := terminalCheckpoint(t, s, inserted.Key)
	terminal, err := s.RecordOffer(ctx, offer, evidence)
	if err != nil {
		t.Fatalf("RecordOffer(terminal replay) = %v", err)
	}
	if terminal.Disposition != OfferTerminalReplay {
		t.Fatalf("terminal replay disposition = %v, want %v", terminal.Disposition, OfferTerminalReplay)
	}
	if terminalAtAfterReplay := terminalCheckpoint(t, s, inserted.Key); !terminalAtAfterReplay.Equal(terminalAtBeforeReplay) {
		t.Fatalf(
			"terminal replay changed terminal checkpoint from %s to %s",
			terminalAtBeforeReplay,
			terminalAtAfterReplay,
		)
	}

	newOffer := historyOffer("repo-a", 201, 1201, queuedAt)
	if _, err := s.RecordOffer(ctx, newOffer, OfferEvidence{}); !errors.Is(err, ErrReplayEvidence) {
		t.Fatalf("RecordOffer(missing evidence) error = %v, want ErrReplayEvidence", err)
	}
}

func TestRecordOfferFailsClosedWithoutConfiguredBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer s.Close()
	queuedAt := time.Date(2026, 7, 28, 14, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 300, 1300, queuedAt)
	if _, err := s.RecordOffer(context.Background(), offer, currentPollEvidence(101, queuedAt, queuedAt)); !errors.Is(err, ErrHistoryBudget) {
		t.Fatalf("RecordOffer(unconfigured budget) error = %v, want ErrHistoryBudget", err)
	}
}

func TestRecordOfferReservesWorstCaseHistoryHeadroom(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	limits := testHistoryLimits()
	limits.MaxHistoryRows = 3
	limits.InflightReserveRows = 2
	limits.MaxHistoryLogicalBytes = 1 << 20
	limits.InflightReserveLogicalBytes = 4096
	s, err := OpenWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits() = %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	now := time.Date(2026, 7, 28, 14, 15, 0, 0, time.UTC)
	first := historyOffer("repo-a", 320, 1320, now)
	if _, err := s.RecordOffer(ctx, first, currentPollEvidence(102, now, now)); err != nil {
		t.Fatalf("RecordOffer(first) = %v", err)
	}
	second := historyOffer("repo-a", 321, 1321, now.Add(time.Second))
	if _, err := s.RecordOffer(ctx, second, currentPollEvidence(103, second.QueueTime, second.QueueTime)); !errors.Is(err, ErrHistoryBudget) {
		t.Fatalf("RecordOffer(over budget) error = %v, want ErrHistoryBudget", err)
	}
	replay, err := s.RecordOffer(ctx, first, currentPollEvidence(102, now, now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("RecordOffer(existing replay under pressure) = %v", err)
	}
	if replay.Disposition != OfferActiveReplay {
		t.Fatalf("replay disposition = %v, want %v", replay.Disposition, OfferActiveReplay)
	}

	usage, err := s.HistoryUsage(ctx, limits)
	if err != nil {
		t.Fatalf("HistoryUsage() = %v", err)
	}
	if usage.LiveRows != 1 || usage.InflightAssignments != 1 ||
		usage.ReservedRows != limits.InflightReserveRows ||
		usage.ReservedLogicalBytes != limits.InflightReserveLogicalBytes {
		t.Fatalf("HistoryUsage() = %+v, want one live assignment and one full reserve", usage)
	}
}

func TestHistoryUsageCountsFullAssignmentGraphs(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	limits := testHistoryLimits()
	now := time.Date(2026, 7, 28, 14, 45, 0, 0, time.UTC)
	liveOffer := historyOffer("repo-a", 330, 1330, now)
	liveReceipt, err := s.RecordOffer(ctx, liveOffer, currentPollEvidence(106, now, now))
	if err != nil {
		t.Fatalf("RecordOffer(live) = %v", err)
	}
	terminalOffer := historyOffer("repo-a", 331, 1331, now.Add(time.Second))
	terminalReceipt, err := s.RecordOffer(
		ctx,
		terminalOffer,
		currentPollEvidence(107, terminalOffer.QueueTime, terminalOffer.QueueTime),
	)
	if err != nil {
		t.Fatalf("RecordOffer(terminal) = %v", err)
	}
	recordMessageReceiptForOffers(t, s, "repo-a", 107, now.Add(30*time.Second), terminalOffer)
	if err := s.BeginMessageAck(ctx, "repo-a", 107, now.Add(time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck() = %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, "repo-a", 107, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck() = %v", err)
	}
	terminalMessage(t, s, terminalReceipt.Key, 107)
	if err := s.Advance(ctx, terminalReceipt.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(terminal) = %v", err)
	}

	var liveID, terminalID int64
	if err := s.DB().QueryRow(`
		SELECT id FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, liveReceipt.Key.RepositoryAlias, liveReceipt.Key.RunnerRequestID, liveReceipt.Key.Attempt).Scan(&liveID); err != nil {
		t.Fatalf("read live assignment id: %v", err)
	}
	if err := s.DB().QueryRow(`
		SELECT id FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, terminalReceipt.Key.RepositoryAlias, terminalReceipt.Key.RunnerRequestID, terminalReceipt.Key.Attempt).Scan(&terminalID); err != nil {
		t.Fatalf("read terminal assignment id: %v", err)
	}
	nowText := now.Format(time.RFC3339Nano)
	if _, err := s.DB().Exec(`
		INSERT INTO runner_slots (
			assignment_id, opaque_name, capacity_slot_id, created_at, updated_at
		) VALUES (?, 'usage-slot', 31, ?, ?)
	`, liveID, nowText, nowText); err != nil {
		t.Fatalf("insert usage runner slot: %v", err)
	}
	if _, err := s.DB().Exec(`
		INSERT INTO reservations (assignment_id, capacity_slot_id, reserved_at)
		VALUES (?, 31, ?)
	`, liveID, nowText); err != nil {
		t.Fatalf("insert usage reservation: %v", err)
	}
	for _, effect := range []struct {
		assignmentID int64
		key          string
	}{
		{assignmentID: liveID, key: "usage-live-effect"},
		{assignmentID: terminalID, key: "usage-terminal-effect"},
	} {
		if _, err := s.DB().Exec(`
			INSERT INTO effects (
				assignment_id, idempotency_key, kind, began_at, completed_at
			) VALUES (?, ?, 'usage', ?, ?)
		`, effect.assignmentID, effect.key, nowText, nowText); err != nil {
			t.Fatalf("insert %s: %v", effect.key, err)
		}
	}
	if _, err := s.DB().Exec(`
		INSERT INTO history_tombstones (
			repository_alias, runner_request_id, attempt,
			offer_digest, offer_payload_digest, terminal_at,
			retain_until, logical_bytes
		) VALUES ('repo-a', 999, 0, zeroblob(32), zeroblob(32), ?, ?, 200)
	`, nowText, now.Add(limits.MinRetention).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert usage tombstone: %v", err)
	}
	if _, err := s.DB().Exec(`
		INSERT INTO network_ledgers (
			ledger_key, assignment_id, state_digest, updated_at,
			retained_until, logical_bytes
		) VALUES ('usage-ledger', NULL, 'opaque', ?, ?, 64)
	`, nowText, now.Add(limits.MinRetention).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert usage network ledger: %v", err)
	}

	liveOfferBytes, err := offerLogicalBytesV1(liveOffer)
	if err != nil {
		t.Fatalf("offerLogicalBytesV1(live) = %v", err)
	}
	terminalOfferBytes, err := offerLogicalBytesV1(terminalOffer)
	if err != nil {
		t.Fatalf("offerLogicalBytesV1(terminal) = %v", err)
	}
	receiptBytes, err := receiptLogicalBytes("repo-a")
	if err != nil {
		t.Fatalf("receiptLogicalBytes() = %v", err)
	}
	usage, err := s.HistoryUsage(ctx, limits)
	if err != nil {
		t.Fatalf("HistoryUsage() = %v", err)
	}
	if usage.LiveRows != 4 || usage.LiveLogicalBytes != liveOfferBytes+128+96+160 {
		t.Errorf("live usage = %d rows/%d bytes, want 4/%d",
			usage.LiveRows, usage.LiveLogicalBytes, liveOfferBytes+128+96+160)
	}
	if usage.ProtectedTerminalRows != 2 ||
		usage.ProtectedTerminalBytes != terminalOfferBytes+160 {
		t.Errorf("terminal usage = %d rows/%d bytes, want 2/%d",
			usage.ProtectedTerminalRows,
			usage.ProtectedTerminalBytes,
			terminalOfferBytes+160,
		)
	}
	if usage.MessageReceiptRows != 1 || usage.MessageReceiptBytes != receiptBytes {
		t.Errorf("receipt usage = %d rows/%d bytes, want 1/%d",
			usage.MessageReceiptRows, usage.MessageReceiptBytes, receiptBytes)
	}
	if usage.TombstoneRows != 1 || usage.TombstoneLogicalBytes != 200 {
		t.Errorf("tombstone usage = %d rows/%d bytes, want 1/200",
			usage.TombstoneRows, usage.TombstoneLogicalBytes)
	}
	if usage.NetworkLedgerRows != 1 || usage.NetworkLedgerLogicalBytes != 64 {
		t.Errorf("network usage = %d rows/%d bytes, want 1/64",
			usage.NetworkLedgerRows, usage.NetworkLedgerLogicalBytes)
	}
	if usage.InflightAssignments != 1 ||
		usage.ReservedRows != limits.InflightReserveRows ||
		usage.ReservedLogicalBytes != limits.InflightReserveLogicalBytes {
		t.Errorf("inflight usage = %+v, want one assignment reserve", usage)
	}
	if !usage.OldestRetainedAt.Equal(now) {
		t.Errorf("OldestRetainedAt = %s, want %s", usage.OldestRetainedAt, now)
	}
}

func TestHistoryRecoverableAdmissionProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	limits := testHistoryLimits()
	s, err := OpenWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits() = %v", err)
	}
	now := time.Date(2026, 7, 28, 14, 30, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 350, 1350, now)
	receipt, err := s.RecordOffer(context.Background(), offer, currentPollEvidence(105, now, now))
	if err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	projection := AdmissionProjection{
		Valid:  true,
		Phase:  AdmissionReserved,
		SlotID: 9,
		FullCharge: ResourceProjection{
			MilliCPU: 1000, MemoryBytes: 2048, PIDs: 16, FileDescriptors: 32,
			TmpfsBytes: 4096, ScratchBytes: 8192, SocketStateBytes: 128,
			DurableStateBytes: 256, Inodes: 64,
		},
		LedgerCharge: ResourceProjection{
			SocketStateBytes: 128, DurableStateBytes: 256, Inodes: 64,
		},
		LedgerCreatedAt: now.Add(time.Second),
		LedgerEverUsed:  true,
	}
	if err := s.PersistAdmissionProjection(context.Background(), receipt.Key, projection); err != nil {
		t.Fatalf("PersistAdmissionProjection() = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	reopened, err := OpenWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits(reopen) = %v", err)
	}
	defer reopened.Close()
	list, err := reopened.ListRecoverable(context.Background())
	if err != nil {
		t.Fatalf("ListRecoverable() = %v", err)
	}
	got, ok := findRecoverable(t, list, receipt.Key)
	if !ok {
		t.Fatal("ListRecoverable() missing recorded offer")
	}
	if !reflect.DeepEqual(got.Offer, offer) {
		t.Errorf("recovered offer = %#v, want %#v", got.Offer, offer)
	}
	if !reflect.DeepEqual(got.Admission, projection) {
		t.Errorf("recovered admission projection = %#v, want %#v", got.Admission, projection)
	}

	invalid := projection
	invalid.LedgerCharge.MemoryBytes = projection.FullCharge.MemoryBytes + 1
	if err := reopened.PersistAdmissionProjection(context.Background(), receipt.Key, invalid); err == nil {
		t.Fatal("PersistAdmissionProjection(ledger > full) = nil, want error")
	}
	list, err = reopened.ListRecoverable(context.Background())
	if err != nil {
		t.Fatalf("ListRecoverable(after rejected projection) = %v", err)
	}
	got, ok = findRecoverable(t, list, receipt.Key)
	if !ok || !reflect.DeepEqual(got.Admission, projection) {
		t.Fatalf("projection changed after rejected update: %#v", got.Admission)
	}

	queued := AdmissionProjection{Valid: true, Phase: AdmissionQueued}
	if err := reopened.PersistAdmissionProjection(context.Background(), receipt.Key, queued); err != nil {
		t.Fatalf("PersistAdmissionProjection(queued) = %v", err)
	}
	list, err = reopened.ListRecoverable(context.Background())
	if err != nil {
		t.Fatalf("ListRecoverable(after queued projection) = %v", err)
	}
	got, ok = findRecoverable(t, list, receipt.Key)
	if !ok || !reflect.DeepEqual(got.Admission, queued) {
		t.Fatalf("queued projection = %#v, want %#v", got.Admission, queued)
	}
}

func TestHistoryRecoverableAdmissionProjectionRejectsPartialCorruption(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 14, 40, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 351, 1351, now)
	receipt, err := s.RecordOffer(ctx, offer, currentPollEvidence(108, now, now))
	if err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	if _, err := s.DB().Exec(`
		UPDATE assignments
		SET admission_phase = ?
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, AdmissionReserved,
		receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt); err != nil {
		t.Fatalf("corrupt admission projection: %v", err)
	}
	if _, err := s.ListRecoverable(ctx); err == nil {
		t.Fatal("ListRecoverable(partial admission projection) = nil error, want fail-closed error")
	}
}

func TestMessageAckLifecycle(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	var offers []OfferIdentity
	for i := int64(0); i < 2; i++ {
		offer := historyOffer("repo-a", 400+i, 1400+i, now.Add(time.Duration(i)*time.Second))
		if _, err := s.RecordOffer(ctx, offer, currentPollEvidence(111, offer.QueueTime, now.Add(time.Minute))); err != nil {
			t.Fatalf("RecordOffer(%d) = %v", i, err)
		}
		offers = append(offers, offer)
	}
	recordMessageReceiptForOffers(t, s, "repo-a", 111, now.Add(90*time.Second), offers...)

	if err := s.BeginMessageAck(ctx, "repo-a", 111, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck() = %v", err)
	}
	if err := s.BeginMessageAck(ctx, "repo-a", 111, now.Add(3*time.Minute)); !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("BeginMessageAck(uncertain replay) error = %v, want ErrAckUncertain", err)
	}

	var payloadDigest []byte
	var ackState string
	if err := s.DB().QueryRowContext(ctx, `
		SELECT payload_digest, ack_state FROM message_receipts
		WHERE repository_alias = ? AND message_id = ?
	`, "repo-a", 111).Scan(&payloadDigest, &ackState); err != nil {
		t.Fatalf("read message receipt: %v", err)
	}
	if len(payloadDigest) != sha256.Size || ackState != "ack_started" {
		t.Fatalf("receipt = digest[%d], state %q; want digest[32], ack_started", len(payloadDigest), ackState)
	}

	var wrong [sha256.Size]byte
	copy(wrong[:], payloadDigest)
	wrong[0] ^= 0xff
	if err := s.ObserveMessageRedelivery(ctx, "repo-a", 111, wrong, now.Add(4*time.Minute)); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ObserveMessageRedelivery(wrong digest) error = %v, want ErrIdentityConflict", err)
	}

	var exact [sha256.Size]byte
	copy(exact[:], payloadDigest)
	if err := s.ObserveMessageRedelivery(ctx, "repo-a", 111, exact, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("ObserveMessageRedelivery(exact) = %v", err)
	}
	if err := s.BeginMessageAck(ctx, "repo-a", 111, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck(after exact redelivery) = %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, "repo-a", 111, now.Add(6*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck() = %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, "repo-a", 111, now.Add(7*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck(idempotent replay) = %v", err)
	}
	if err := s.BeginMessageAck(ctx, "repo-a", 111, now.Add(8*time.Minute)); !errors.Is(err, ErrAckConfirmed) {
		t.Fatalf("BeginMessageAck(already confirmed) error = %v, want ErrAckConfirmed", err)
	}
}

func TestMessageAckCrashRecovery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	limits := testHistoryLimits()
	open := func(t *testing.T) *SQLiteStore {
		t.Helper()
		s, err := OpenWithHistoryLimits(path, limits)
		if err != nil {
			t.Fatalf("OpenWithHistoryLimits() = %v", err)
		}
		return s
	}
	now := time.Date(2026, 7, 28, 15, 30, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 450, 1450, now)

	s := open(t)
	if _, err := s.RecordOffer(ctx, offer, currentPollEvidence(115, now, now)); err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	recordMessageReceiptForOffers(t, s, "repo-a", 115, now.Add(30*time.Second), offer)
	if err := s.Close(); err != nil {
		t.Fatalf("Close(before BeginMessageAck) = %v", err)
	}

	s = open(t)
	if err := s.BeginMessageAck(ctx, "repo-a", 115, now.Add(time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck(after pre-begin crash) = %v", err)
	}
	var digestBytes []byte
	if err := s.DB().QueryRow(`
		SELECT payload_digest FROM message_receipts
		WHERE repository_alias = 'repo-a' AND message_id = 115
	`).Scan(&digestBytes); err != nil {
		t.Fatalf("read persisted receipt digest: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close(after durable Ack start) = %v", err)
	}

	s = open(t)
	if err := s.BeginMessageAck(ctx, "repo-a", 115, now.Add(2*time.Minute)); !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("BeginMessageAck(after ack-start crash) error = %v, want ErrAckUncertain", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	if err := s.ObserveMessageRedelivery(ctx, "repo-a", 115, digest, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("ObserveMessageRedelivery() = %v", err)
	}
	if err := s.BeginMessageAck(ctx, "repo-a", 115, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck(after redelivery) = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close(after simulated upstream success) = %v", err)
	}

	s = open(t)
	defer s.Close()
	if err := s.BeginMessageAck(ctx, "repo-a", 115, now.Add(5*time.Minute)); !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("BeginMessageAck(after success-before-confirm crash) error = %v, want ErrAckUncertain", err)
	}
	if err := s.ObserveMessageRedelivery(ctx, "repo-a", 115, digest, now.Add(6*time.Minute)); err != nil {
		t.Fatalf("ObserveMessageRedelivery(second) = %v", err)
	}
	if err := s.BeginMessageAck(ctx, "repo-a", 115, now.Add(7*time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck(second retry) = %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, "repo-a", 115, now.Add(8*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck() = %v", err)
	}
}

func TestCompactTerminalIsAtomicAndTombstoneReplaySafe(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 500, 1500, now)
	receipt, err := s.RecordOffer(ctx, offer, currentPollEvidence(121, now, now.Add(time.Second)))
	if err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	recordMessageReceiptForOffers(t, s, "repo-a", 121, now.Add(30*time.Second), offer)
	if err := s.BeginMessageAck(ctx, "repo-a", 121, now.Add(time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck() = %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, "repo-a", 121, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck() = %v", err)
	}
	terminalMessage(t, s, receipt.Key, 121)
	if err := s.Advance(ctx, receipt.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(RECEIVED->DESTROYED) = %v", err)
	}
	terminalAt := terminalCheckpoint(t, s, receipt.Key)

	var assignmentID int64
	if err := s.DB().QueryRowContext(ctx, `
		SELECT id FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
		t.Fatalf("read assignment id: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, `
		INSERT INTO network_ledgers
			(ledger_key, assignment_id, state_digest, updated_at, retained_until, logical_bytes)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "ledger-500", assignmentID, "opaque-digest", now.Format(time.RFC3339Nano),
		terminalAt.Add(48*time.Hour).Format(time.RFC3339Nano), 64); err != nil {
		t.Fatalf("insert retained network ledger: %v", err)
	}

	if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); err != nil {
		t.Fatalf("CompactTerminal() = %v", err)
	}

	var assignmentCount, tombstoneCount int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assignments WHERE repository_alias = ? AND runner_request_id = ?`,
		receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID,
	).Scan(&assignmentCount); err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM history_tombstones WHERE repository_alias = ? AND runner_request_id = ?`,
		receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID,
	).Scan(&tombstoneCount); err != nil {
		t.Fatalf("count tombstones: %v", err)
	}
	if assignmentCount != 0 || tombstoneCount != 1 {
		t.Fatalf("post-compact counts assignments=%d tombstones=%d, want 0/1", assignmentCount, tombstoneCount)
	}

	var detached sql.NullInt64
	if err := s.DB().QueryRowContext(ctx,
		`SELECT assignment_id FROM network_ledgers WHERE ledger_key = 'ledger-500'`,
	).Scan(&detached); err != nil {
		t.Fatalf("read retained network ledger: %v", err)
	}
	if detached.Valid {
		t.Fatalf("retained network ledger assignment_id = %d, want NULL", detached.Int64)
	}

	replay, err := s.RecordOffer(ctx, offer, currentPollEvidence(122, now, now.Add(4*time.Minute)))
	if err != nil {
		t.Fatalf("RecordOffer(tombstone replay) = %v", err)
	}
	if replay.Disposition != OfferTerminalReplay {
		t.Fatalf("tombstone replay disposition = %v, want %v", replay.Disposition, OfferTerminalReplay)
	}
	conflict := offer
	conflict.JobDisplayName = "changed after compaction"
	if _, err := s.RecordOffer(ctx, conflict, currentPollEvidence(122, now, now.Add(4*time.Minute))); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("RecordOffer(tombstone conflict) error = %v, want ErrIdentityConflict", err)
	}
}

func TestCompactTerminalRejectsUnconfirmedAckAndLiveDurableState(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 17, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 600, 1600, now)
	receipt, err := s.RecordOffer(ctx, offer, currentPollEvidence(131, now, now))
	if err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	recordMessageReceiptForOffers(t, s, "repo-a", 131, now.Add(30*time.Second), offer)
	terminalMessage(t, s, receipt.Key, 131)
	if err := s.Advance(ctx, receipt.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(RECEIVED->DESTROYED) = %v", err)
	}
	terminalAt := terminalCheckpoint(t, s, receipt.Key)
	if err := s.BeginMessageAck(ctx, "repo-a", 131, now.Add(time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck() = %v", err)
	}
	if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); !errors.Is(err, ErrAckUncertain) {
		t.Fatalf("CompactTerminal(unconfirmed ack) error = %v, want ErrAckUncertain", err)
	}
}

func TestCompactTerminalRejectsEveryLivePrecondition(t *testing.T) {
	ctx := context.Background()
	baseTime := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)

	t.Run("nonterminal assignment", func(t *testing.T) {
		s := newHistoryStore(t)
		offer := historyOffer("repo-a", 610, 1610, baseTime)
		receipt, err := s.RecordOffer(ctx, offer, currentPollEvidence(141, baseTime, baseTime))
		if err != nil {
			t.Fatalf("RecordOffer() = %v", err)
		}
		recordMessageReceiptForOffers(t, s, "repo-a", 141, baseTime.Add(30*time.Second), offer)
		if err := s.BeginMessageAck(ctx, "repo-a", 141, baseTime.Add(time.Minute)); err != nil {
			t.Fatalf("BeginMessageAck() = %v", err)
		}
		if err := s.ConfirmMessageAck(ctx, "repo-a", 141, baseTime.Add(2*time.Minute)); err != nil {
			t.Fatalf("ConfirmMessageAck() = %v", err)
		}
		terminalMessage(t, s, receipt.Key, 141)
		if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), baseTime.Add(3*time.Minute)); err == nil {
			t.Fatal("CompactTerminal(nonterminal) = nil, want error")
		}
	})

	t.Run("incomplete effect", func(t *testing.T) {
		s := newHistoryStore(t)
		_, receipt := compactableOffer(t, s, 611, 142, baseTime)
		terminalAt := terminalCheckpoint(t, s, receipt.Key)
		var assignmentID int64
		if err := s.DB().QueryRow(`
			SELECT id FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
			t.Fatalf("read assignment id: %v", err)
		}
		if _, err := s.DB().Exec(`
			INSERT INTO effects (assignment_id, idempotency_key, kind, began_at)
			VALUES (?, 'incomplete-effect', 'destroy', ?)
		`, assignmentID, baseTime.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert incomplete effect: %v", err)
		}
		if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); err == nil {
			t.Fatal("CompactTerminal(incomplete effect) = nil, want error")
		}
	})

	t.Run("reservation", func(t *testing.T) {
		s := newHistoryStore(t)
		_, receipt := compactableOffer(t, s, 612, 143, baseTime)
		terminalAt := terminalCheckpoint(t, s, receipt.Key)
		var assignmentID int64
		if err := s.DB().QueryRow(`
			SELECT id FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
			t.Fatalf("read assignment id: %v", err)
		}
		if _, err := s.DB().Exec(`
			INSERT INTO reservations (assignment_id, capacity_slot_id, reserved_at)
			VALUES (?, 22, ?)
		`, assignmentID, baseTime.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert reservation: %v", err)
		}
		if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); err == nil {
			t.Fatal("CompactTerminal(reservation) = nil, want error")
		}
	})

	t.Run("runner slot", func(t *testing.T) {
		s := newHistoryStore(t)
		_, receipt := compactableOffer(t, s, 613, 144, baseTime)
		terminalAt := terminalCheckpoint(t, s, receipt.Key)
		var assignmentID int64
		if err := s.DB().QueryRow(`
			SELECT id FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
			t.Fatalf("read assignment id: %v", err)
		}
		if _, err := s.DB().Exec(`
			INSERT INTO runner_slots (
				assignment_id, opaque_name, capacity_slot_id, created_at, updated_at
			) VALUES (?, 'still-live-slot', 23, ?, ?)
		`, assignmentID, baseTime.Format(time.RFC3339Nano), baseTime.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert runner slot: %v", err)
		}
		if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); err == nil {
			t.Fatal("CompactTerminal(runner slot) = nil, want error")
		}
	})

	t.Run("persisted admission slot", func(t *testing.T) {
		s := newHistoryStore(t)
		_, receipt := compactableOffer(t, s, 614, 145, baseTime)
		terminalAt := terminalCheckpoint(t, s, receipt.Key)
		if _, err := s.DB().Exec(`
			UPDATE assignments
			SET admission_phase = ?, admission_slot_id = ?,
				full_milli_cpu = 1, full_memory_bytes = 1, full_pids = 1,
				full_file_descriptors = 1, full_tmpfs_bytes = 1,
				full_scratch_bytes = 1, full_socket_state_bytes = 1,
				full_durable_state_bytes = 1, full_inodes = 1,
				ledger_milli_cpu = 0, ledger_memory_bytes = 0, ledger_pids = 0,
				ledger_file_descriptors = 0, ledger_tmpfs_bytes = 0,
				ledger_scratch_bytes = 0, ledger_socket_state_bytes = 0,
				ledger_durable_state_bytes = 0, ledger_inodes = 0,
				ledger_created_at = ?, ledger_ever_used = 0
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, AdmissionReserved, 24, baseTime.Format(time.RFC3339Nano),
			receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt); err != nil {
			t.Fatalf("persist live admission projection: %v", err)
		}
		if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); err == nil {
			t.Fatal("CompactTerminal(persisted admission slot) = nil, want error")
		}
	})

	for _, tc := range []struct {
		name          string
		retainedUntil any
	}{
		{name: "unretained network ledger", retainedUntil: nil},
		{name: "malformed network ledger retention", retainedUntil: "not-a-timestamp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newHistoryStore(t)
			_, receipt := compactableOffer(t, s, 615, 146, baseTime)
			terminalAt := terminalCheckpoint(t, s, receipt.Key)
			var assignmentID int64
			if err := s.DB().QueryRow(`
				SELECT id FROM assignments
				WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
			`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
				t.Fatalf("read assignment id: %v", err)
			}
			if _, err := s.DB().Exec(`
				INSERT INTO network_ledgers (
					ledger_key, assignment_id, state_digest, updated_at,
					retained_until, logical_bytes
				) VALUES ('not-independently-retained', ?, 'opaque', ?, ?, 64)
			`, assignmentID, baseTime.Format(time.RFC3339Nano), tc.retainedUntil); err != nil {
				t.Fatalf("insert network ledger: %v", err)
			}
			if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); err == nil {
				t.Fatalf("CompactTerminal(%s) = nil, want error", tc.name)
			}
		})
	}

	t.Run("conflicting tombstone", func(t *testing.T) {
		s := newHistoryStore(t)
		_, receipt := compactableOffer(t, s, 616, 147, baseTime)
		terminalAt := terminalCheckpoint(t, s, receipt.Key)
		retainUntil := terminalAt.Add(testHistoryLimits().MinRetention)
		if _, err := s.DB().Exec(`
			INSERT INTO history_tombstones (
				repository_alias, runner_request_id, attempt,
				offer_digest, offer_payload_digest, terminal_at,
				retain_until, logical_bytes
			) VALUES (?, ?, ?, ?, zeroblob(32), ?, ?, 128)
		`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt,
			bytes.Repeat([]byte{0xff}, sha256.Size),
			terminalAt.Format(time.RFC3339Nano), retainUntil.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert conflicting tombstone: %v", err)
		}
		if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); !errors.Is(err, ErrIdentityConflict) {
			t.Fatalf("CompactTerminal(conflicting tombstone) error = %v, want ErrIdentityConflict", err)
		}
	})
}

func TestCompactTerminalPreservesIndependentLedgerTail(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	baseTime := time.Date(2026, 7, 28, 18, 30, 0, 0, time.UTC)
	_, receipt := compactableOffer(t, s, 618, 149, baseTime)
	terminalAt := terminalCheckpoint(t, s, receipt.Key)
	var assignmentID int64
	if err := s.DB().QueryRow(`
		SELECT id FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
		t.Fatalf("read assignment id: %v", err)
	}
	retainedUntil := time.Unix(0, 0).UTC().Format(time.RFC3339Nano)
	if _, err := s.DB().Exec(`
		INSERT INTO network_ledgers (
			ledger_key, assignment_id, state_digest, updated_at,
			retained_until, logical_bytes
		) VALUES ('independent-expired-tail', ?, 'opaque', ?, ?, 64)
	`, assignmentID, baseTime.Format(time.RFC3339Nano), retainedUntil); err != nil {
		t.Fatalf("insert independently retained ledger: %v", err)
	}

	if err := s.CompactTerminal(
		ctx,
		receipt.Key,
		testHistoryLimits(),
		terminalAt.Add(time.Minute),
	); err != nil {
		t.Fatalf("CompactTerminal(independent ledger tail) = %v", err)
	}

	var detached sql.NullInt64
	var retainedUntilAfter string
	if err := s.DB().QueryRow(`
		SELECT assignment_id, retained_until
		FROM network_ledgers
		WHERE ledger_key = 'independent-expired-tail'
	`).Scan(&detached, &retainedUntilAfter); err != nil {
		t.Fatalf("read detached independent ledger: %v", err)
	}
	if detached.Valid {
		t.Fatalf("independent ledger assignment_id = %d, want NULL", detached.Int64)
	}
	if retainedUntilAfter != retainedUntil {
		t.Fatalf("independent ledger retained_until = %q, want %q", retainedUntilAfter, retainedUntil)
	}
}

func TestCompactTerminalRollsBackAfterTombstoneInsert(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	limits := testHistoryLimits()
	s, err := OpenWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits() = %v", err)
	}
	baseTime := time.Date(2026, 7, 28, 19, 0, 0, 0, time.UTC)
	_, receipt := compactableOffer(t, s, 620, 151, baseTime)
	terminalAt := terminalCheckpoint(t, s, receipt.Key)
	var assignmentID int64
	if err := s.DB().QueryRow(`
		SELECT id FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentID); err != nil {
		t.Fatalf("read assignment id: %v", err)
	}
	if _, err := s.DB().Exec(`
		INSERT INTO network_ledgers (
			ledger_key, assignment_id, state_digest, updated_at,
			retained_until, logical_bytes
		) VALUES ('rollback-ledger', ?, 'opaque', ?, ?, 64)
	`, assignmentID, baseTime.Format(time.RFC3339Nano),
		terminalAt.Add(48*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert retained ledger: %v", err)
	}
	if _, err := s.DB().Exec(`
		CREATE TRIGGER fail_assignment_delete
		BEFORE DELETE ON assignments
		BEGIN
			SELECT RAISE(ABORT, 'injected delete failure');
		END
	`); err != nil {
		t.Fatalf("create delete-failure trigger: %v", err)
	}

	if err := s.CompactTerminal(ctx, receipt.Key, limits, terminalAt.Add(time.Minute)); err == nil {
		t.Fatal("CompactTerminal(injected delete failure) = nil, want error")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	reopened, err := OpenWithHistoryLimits(path, limits)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits(reopen) = %v", err)
	}
	defer reopened.Close()
	var assignmentCount, tombstoneCount int
	if err := reopened.DB().QueryRow(`
		SELECT COUNT(*) FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignmentCount); err != nil {
		t.Fatalf("count assignment after rollback: %v", err)
	}
	if err := reopened.DB().QueryRow(`
		SELECT COUNT(*) FROM history_tombstones
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&tombstoneCount); err != nil {
		t.Fatalf("count tombstone after rollback: %v", err)
	}
	var ledgerAssignment sql.NullInt64
	if err := reopened.DB().QueryRow(`
		SELECT assignment_id FROM network_ledgers WHERE ledger_key = 'rollback-ledger'
	`).Scan(&ledgerAssignment); err != nil {
		t.Fatalf("read ledger after rollback: %v", err)
	}
	if assignmentCount != 1 || tombstoneCount != 0 ||
		!ledgerAssignment.Valid || ledgerAssignment.Int64 != assignmentID {
		t.Fatalf(
			"rollback state assignment=%d tombstone=%d ledger_assignment=%+v, want 1/0/%d",
			assignmentCount, tombstoneCount, ledgerAssignment, assignmentID,
		)
	}
}

func TestCompactTerminalRejectsTimeBeforeTerminalCheckpoint(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 19, 30, 0, 0, time.UTC)
	_, receipt := compactableOffer(t, s, 625, 156, now)
	var terminalAtText string
	if err := s.DB().QueryRow(`
		SELECT updated_at FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&terminalAtText); err != nil {
		t.Fatalf("read terminal checkpoint time: %v", err)
	}
	terminalAt, err := time.Parse(time.RFC3339Nano, terminalAtText)
	if err != nil {
		t.Fatalf("parse terminal checkpoint time: %v", err)
	}
	if err := s.CompactTerminal(
		ctx,
		receipt.Key,
		testHistoryLimits(),
		terminalAt.Add(-time.Nanosecond),
	); err == nil {
		t.Fatal("CompactTerminal(time before terminal checkpoint) = nil, want error")
	}
	var assignments, tombstones int
	if err := s.DB().QueryRow(`
		SELECT COUNT(*) FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&assignments); err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if err := s.DB().QueryRow(`
		SELECT COUNT(*) FROM history_tombstones
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, receipt.Key.RepositoryAlias, receipt.Key.RunnerRequestID, receipt.Key.Attempt).Scan(&tombstones); err != nil {
		t.Fatalf("count tombstones: %v", err)
	}
	if assignments != 1 || tombstones != 0 {
		t.Fatalf("rejected compaction left assignments=%d tombstones=%d, want 1/0", assignments, tombstones)
	}
}

func TestRecordOfferTombstoneReplayUnderNewMessageCanAck(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	offer, receipt := compactableOffer(t, s, 630, 161, now)
	terminalAt := terminalCheckpoint(t, s, receipt.Key)
	if err := s.CompactTerminal(ctx, receipt.Key, testHistoryLimits(), terminalAt.Add(time.Minute)); err != nil {
		t.Fatalf("CompactTerminal() = %v", err)
	}

	replay, err := s.RecordOffer(ctx, offer, currentPollEvidence(162, now, now.Add(4*time.Minute)))
	if err != nil {
		t.Fatalf("RecordOffer(tombstone under new message) = %v", err)
	}
	if replay.Disposition != OfferTerminalReplay {
		t.Fatalf("replay disposition = %v, want %v", replay.Disposition, OfferTerminalReplay)
	}
	recordMessageReceiptForOffers(t, s, offer.RepositoryAlias, 162, now.Add(4*time.Minute), offer)
	if err := s.BeginMessageAck(ctx, offer.RepositoryAlias, 162, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("BeginMessageAck(new message) = %v", err)
	}
	if err := s.ConfirmMessageAck(ctx, offer.RepositoryAlias, 162, now.Add(6*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck(new message) = %v", err)
	}
}

func TestRecordOfferMessageAckCompactTerminalConcurrentStress(t *testing.T) {
	s := newHistoryStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 21, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 640, 1640, now)
	evidence := currentPollEvidence(171, now, now)

	const callers = 16
	type recordResult struct {
		receipt OfferReceipt
		err     error
	}
	recordResults := make(chan recordResult, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			receipt, err := s.RecordOffer(ctx, offer, evidence)
			recordResults <- recordResult{receipt: receipt, err: err}
		}()
	}
	wg.Wait()
	close(recordResults)
	inserted, active := 0, 0
	var key controller.AssignmentKey
	for result := range recordResults {
		if result.err != nil {
			t.Fatalf("concurrent RecordOffer() = %v", result.err)
		}
		key = result.receipt.Key
		switch result.receipt.Disposition {
		case OfferInserted:
			inserted++
		case OfferActiveReplay:
			active++
		default:
			t.Fatalf("concurrent disposition = %v", result.receipt.Disposition)
		}
	}
	if inserted != 1 || active != callers-1 {
		t.Fatalf("concurrent results inserted=%d active=%d, want 1/%d", inserted, active, callers-1)
	}
	recordMessageReceiptForOffers(t, s, "repo-a", 171, now.Add(30*time.Second), offer)

	ackErrors := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ackErrors <- s.BeginMessageAck(ctx, "repo-a", 171, now.Add(time.Minute))
		}()
	}
	wg.Wait()
	close(ackErrors)
	ackStarted, ackUncertain := 0, 0
	for err := range ackErrors {
		switch {
		case err == nil:
			ackStarted++
		case errors.Is(err, ErrAckUncertain):
			ackUncertain++
		default:
			t.Fatalf("concurrent BeginMessageAck() = %v", err)
		}
	}
	if ackStarted != 1 || ackUncertain != callers-1 {
		t.Fatalf("concurrent Ack results started=%d uncertain=%d, want 1/%d", ackStarted, ackUncertain, callers-1)
	}
	if err := s.ConfirmMessageAck(ctx, "repo-a", 171, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("ConfirmMessageAck() = %v", err)
	}
	terminalMessage(t, s, key, 171)
	if err := s.Advance(ctx, key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(DESTROYED) = %v", err)
	}
	terminalAt := terminalCheckpoint(t, s, key)

	start := make(chan struct{})
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(compact bool) {
			defer wg.Done()
			<-start
			if compact {
				errs <- s.CompactTerminal(ctx, key, testHistoryLimits(), terminalAt.Add(time.Minute))
				return
			}
			replay, err := s.RecordOffer(ctx, offer, currentPollEvidence(172, now, now.Add(3*time.Minute)))
			if err == nil && replay.Disposition != OfferTerminalReplay {
				err = fmt.Errorf("terminal replay disposition = %v", replay.Disposition)
			}
			errs <- err
		}(i%2 == 0)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent terminal replay/compaction = %v", err)
		}
	}

	var assignments, tombstones int
	if err := s.DB().QueryRow(`
		SELECT COUNT(*) FROM assignments
		WHERE repository_alias = 'repo-a' AND runner_request_id = 640
	`).Scan(&assignments); err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if err := s.DB().QueryRow(`
		SELECT COUNT(*) FROM history_tombstones
		WHERE repository_alias = 'repo-a' AND runner_request_id = 640
	`).Scan(&tombstones); err != nil {
		t.Fatalf("count tombstones: %v", err)
	}
	if assignments != 0 || tombstones != 1 {
		t.Fatalf("terminal graph assignments=%d tombstones=%d, want 0/1", assignments, tombstones)
	}
}
