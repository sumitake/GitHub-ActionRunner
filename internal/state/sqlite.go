package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver.

	"github.com/sumitake/portable-ghar/internal/controller"
)

// ErrAcquisitionEpochMismatch is returned by CompareAndSetAcquisition when
// expectedEpoch does not match the currently stored acquisition_epoch. The
// caller should re-read AcquisitionPolicy and retry against the current
// epoch rather than assume its transition applied.
var ErrAcquisitionEpochMismatch = errors.New("state: acquisition epoch mismatch")

// SQLiteStore is the crash-safe Store implementation backed by a modernc
// (pure-Go, cgo-free) SQLite database. The zero value is not usable;
// construct one with Open.
type SQLiteStore struct {
	db            *sql.DB
	historyLimits *HistoryLimits
}

var _ Store = (*SQLiteStore)(nil)

// Open opens (creating if necessary) the SQLite database at path, applies
// migrations, and returns a ready-to-use *SQLiteStore.
//
// The DSN applies this store's fixed pragma set to every connection the
// pool opens: WAL journaling, enforced foreign keys, a 5-second busy
// timeout, and full (fsync-on-commit) synchronous durability -- the
// crash-safety contract this package promises depends on synchronous
// never being relaxed to NORMAL, even though NORMAL is faster under WAL.
// _txlock=immediate makes every non-read-only transaction this store opens
// via *sql.DB.BeginTx issue "BEGIN IMMEDIATE" (a write-intent lock taken up
// front), not just the ones the plan calls out by name (reservations):
// with the pool capped at one connection below, every mutating Store
// method is already fully serialized, so applying immediate-mode
// universally costs nothing and removes a class of "which methods
// remembered to ask for the write lock" bugs.
//
// The pool is capped at one open connection. SQLite allows only one
// writer at a time regardless of pool size; capping the Go-level pool at
// one avoids SQLITE_BUSY contention between pooled connections racing for
// the same file lock, and makes this store's own concurrency (goroutines
// calling Store methods concurrently) safe by serializing through
// database/sql's own connection-checkout synchronization -- without
// weakening any durability pragma to get there.
// dsnForPath builds the fixed-pragma SQLite DSN Open uses for path. It is
// split out from Open so the DSN's fixed pragma/txlock set (in particular
// _txlock=immediate, see Open's doc) can be asserted directly by a test
// without going through a real database connection.
func dsnForPath(path string) string {
	return fmt.Sprintf(
		"file:%s?_pragma=auto_vacuum(2)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(3)&_txlock=immediate",
		path,
	)
}

func Open(path string) (*SQLiteStore, error) {
	return openStore(path, nil)
}

// OpenWithHistoryLimits opens the store with explicit durable-history bounds.
// It is the only constructor that authorizes RecordOffer to insert a new
// identity; Open remains a compatibility path whose history admission fails
// closed because production limits have no defaults.
func OpenWithHistoryLimits(path string, limits HistoryLimits) (*SQLiteStore, error) {
	if err := validateRecordLimits(limits); err != nil {
		return nil, fmt.Errorf("state: invalid history limits: %w", err)
	}
	return openStore(path, &limits)
}

func openStore(path string, historyLimits *HistoryLimits) (*SQLiteStore, error) {
	dsn := dsnForPath(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("state: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &SQLiteStore{db: db, historyLimits: historyLimits}, nil
}

// Close closes the underlying database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB. It exists for schema-level tests and
// for later tasks that need direct access to tables Task 2 establishes but
// does not yet wrap in a Store method (network_ledgers' token/clock state
// is Task 6's; reconcile_cycles' CycleReceipt is a later reconciler task's
// -- see internal/controller's package doc for the matching scope note).
// It must never be used to bypass Store's reject-secret-columns rule.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// queryRower is satisfied by both *sql.DB and *sql.Tx, letting helpers
// like readAcquisitionPolicy run either standalone or inside a
// transaction.
type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// lookupAssignmentTx resolves key to its row id and current persisted
// state.
func lookupAssignmentTx(ctx context.Context, tx *sql.Tx, key controller.AssignmentKey) (id int64, current controller.State, err error) {
	var stateStr string
	err = tx.QueryRowContext(ctx,
		`SELECT id, state FROM assignments WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?`,
		key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(&id, &stateStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", fmt.Errorf("state: assignment %+v not found", key)
		}
		return 0, "", fmt.Errorf("state: look up assignment %+v: %w", key, err)
	}
	return id, controller.State(stateStr), nil
}

func persistOffer(
	ctx context.Context,
	q execer,
	offer OfferIdentity,
	sourceMessageID any,
	ts string,
) ([sha256.Size]byte, [sha256.Size]byte, uint64, error) {
	digest := CanonicalOfferDigest(offer)
	payloadDigest := CanonicalOfferPayloadDigest(offer)
	logicalBytes, err := offerLogicalBytesV1(offer)
	if err != nil {
		return [sha256.Size]byte{}, [sha256.Size]byte{}, 0, fmt.Errorf("state: size offer: %w", err)
	}
	labelsJSON, err := json.Marshal(offer.RequestLabels)
	if err != nil {
		return [sha256.Size]byte{}, [sha256.Size]byte{}, 0, fmt.Errorf("state: encode offer labels: %w", err)
	}
	if _, err := q.ExecContext(ctx, `
		INSERT INTO assignments (
			repository_alias, runner_request_id, attempt, workflow_job_id,
			offer_digest, offer_payload_digest, source_message_id,
			job_id, repository_name, owner_name, job_workflow_ref,
			job_display_name, workflow_run_id, event_name, request_labels,
			queue_time, scale_set_assign_time, runner_assign_time, finish_time,
			acquire_job_url, history_logical_bytes,
			state, created_at, updated_at
		)
		VALUES (
			?, ?, 0, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?
		)
		ON CONFLICT (repository_alias, runner_request_id, attempt) DO NOTHING
		`,
		offer.RepositoryAlias, offer.RunnerRequestID, offer.WorkflowJobID,
		digest[:], payloadDigest[:], sourceMessageID,
		offer.JobID, offer.RepositoryName, offer.OwnerName, offer.JobWorkflowRef,
		offer.JobDisplayName, offer.WorkflowRunID, offer.EventName, string(labelsJSON),
		formatTime(offer.QueueTime), formatTime(offer.ScaleSetAssignTime),
		formatTime(offer.RunnerAssignTime), formatTime(offer.FinishTime),
		offer.AcquireJobURL, logicalBytes,
		string(controller.StateReceived), ts, ts,
	); err != nil {
		return [sha256.Size]byte{}, [sha256.Size]byte{}, 0, err
	}
	return digest, payloadDigest, logicalBytes, nil
}

// UpsertOffer implements Store's temporary compatibility path.
func (s *SQLiteStore) UpsertOffer(ctx context.Context, offer OfferIdentity) (controller.AssignmentKey, error) {
	digest, payloadDigest, _, err := persistOffer(ctx, s.db, offer, nil, now())
	if err != nil {
		return controller.AssignmentKey{}, fmt.Errorf("state: upsert offer: %w", err)
	}

	var existing, existingPayload []byte
	if err := s.db.QueryRowContext(ctx, `
			SELECT offer_digest, offer_payload_digest FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = 0
		`, offer.RepositoryAlias, offer.RunnerRequestID).Scan(&existing, &existingPayload); err != nil {
		return controller.AssignmentKey{}, fmt.Errorf("state: read upserted offer: %w", err)
	}
	if len(existing) != sha256.Size || !bytes.Equal(existing, digest[:]) ||
		len(existingPayload) != sha256.Size || !bytes.Equal(existingPayload, payloadDigest[:]) {
		return controller.AssignmentKey{}, fmt.Errorf("%w: %s/%d", ErrIdentityConflict, offer.RepositoryAlias, offer.RunnerRequestID)
	}

	return controller.AssignmentKey{
		RepositoryAlias: offer.RepositoryAlias,
		RunnerRequestID: offer.RunnerRequestID,
		Attempt:         0,
	}, nil
}

type historyBudgetTotals struct {
	rows                uint64
	logicalBytes        uint64
	inflightAssignments uint64
}

func historyBudgetTotalsTx(ctx context.Context, tx *sql.Tx) (historyBudgetTotals, error) {
	var (
		rowsInt, bytesInt, inflightInt int64
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM assignments) +
			(SELECT COUNT(*) FROM runner_slots) +
			(SELECT COUNT(*) FROM reservations) +
			(SELECT COUNT(*) FROM effects) +
			(SELECT COUNT(*) FROM message_receipts) +
			(SELECT COUNT(*) FROM history_tombstones),
			COALESCE((SELECT SUM(history_logical_bytes) FROM assignments), 0) +
			COALESCE((SELECT SUM(logical_bytes) FROM message_receipts), 0) +
			COALESCE((SELECT SUM(logical_bytes) FROM history_tombstones), 0) +
			((SELECT COUNT(*) FROM runner_slots) * ?) +
			((SELECT COUNT(*) FROM reservations) * ?) +
			((SELECT COUNT(*) FROM effects) * ?),
			(SELECT COUNT(*) FROM assignments WHERE state != ?)
	`,
		historyRunnerSlotFixedBytes,
		historyReservationFixedBytes,
		historyEffectFixedBytes,
		string(controller.StateDestroyed),
	).Scan(&rowsInt, &bytesInt, &inflightInt); err != nil {
		return historyBudgetTotals{}, fmt.Errorf("state: calculate history budget: %w", err)
	}
	if rowsInt < 0 || bytesInt < 0 || inflightInt < 0 {
		return historyBudgetTotals{}, ErrHistoryBudget
	}
	return historyBudgetTotals{
		rows:                uint64(rowsInt),
		logicalBytes:        uint64(bytesInt),
		inflightAssignments: uint64(inflightInt),
	}, nil
}

func ensureOfferHeadroom(
	ctx context.Context,
	tx *sql.Tx,
	limits HistoryLimits,
	offerLogicalBytes uint64,
) error {
	if err := validateRecordLimits(limits); err != nil {
		return err
	}
	if offerLogicalBytes > limits.InflightReserveLogicalBytes {
		return ErrHistoryBudget
	}
	current, err := historyBudgetTotalsTx(ctx, tx)
	if err != nil {
		return err
	}
	reservedRows, err := multiplyHistoryBytes(current.inflightAssignments, limits.InflightReserveRows)
	if err != nil {
		return err
	}
	reservedBytes, err := multiplyHistoryBytes(current.inflightAssignments, limits.InflightReserveLogicalBytes)
	if err != nil {
		return err
	}
	effectiveRows, err := addHistoryBytes(current.rows, reservedRows, 1, limits.InflightReserveRows)
	if err != nil || effectiveRows > limits.MaxHistoryRows {
		return ErrHistoryBudget
	}
	effectiveBytes, err := addHistoryBytes(
		current.logicalBytes,
		reservedBytes,
		offerLogicalBytes,
		limits.InflightReserveLogicalBytes,
	)
	if err != nil || effectiveBytes > limits.MaxHistoryLogicalBytes {
		return ErrHistoryBudget
	}
	return nil
}

// RecordOffer implements Store.
func (s *SQLiteStore) RecordOffer(
	ctx context.Context,
	offer OfferIdentity,
	evidence OfferEvidence,
) (OfferReceipt, error) {
	key := controller.AssignmentKey{
		RepositoryAlias: offer.RepositoryAlias,
		RunnerRequestID: offer.RunnerRequestID,
		Attempt:         0,
	}
	digest := CanonicalOfferDigest(offer)
	payloadDigest := CanonicalOfferPayloadDigest(offer)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OfferReceipt{}, fmt.Errorf("state: record offer: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var tombstoneDigest, tombstonePayloadDigest []byte
	err = tx.QueryRowContext(ctx, `
			SELECT offer_digest, offer_payload_digest FROM history_tombstones
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = 0
		`, offer.RepositoryAlias, offer.RunnerRequestID).Scan(&tombstoneDigest, &tombstonePayloadDigest)
	switch {
	case err == nil:
		if len(tombstoneDigest) != sha256.Size || !bytes.Equal(tombstoneDigest, digest[:]) ||
			len(tombstonePayloadDigest) != sha256.Size || !bytes.Equal(tombstonePayloadDigest, payloadDigest[:]) {
			return OfferReceipt{}, fmt.Errorf("%w: %s/%d", ErrIdentityConflict, offer.RepositoryAlias, offer.RunnerRequestID)
		}
		if evidence.MessageID > 0 && validateOfferEvidence(offer, evidence) == nil {
			if _, err := tx.ExecContext(ctx, `
				UPDATE history_tombstones
				SET source_message_id = ?
				WHERE repository_alias = ? AND runner_request_id = ? AND attempt = 0
			`, evidence.MessageID, offer.RepositoryAlias, offer.RunnerRequestID); err != nil {
				return OfferReceipt{}, fmt.Errorf("state: record offer: update tombstone replay evidence: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return OfferReceipt{}, fmt.Errorf("state: record offer: commit tombstone replay evidence: %w", err)
			}
		}
		return OfferReceipt{Key: key, Disposition: OfferTerminalReplay, State: controller.StateDestroyed}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return OfferReceipt{}, fmt.Errorf("state: record offer: read tombstone: %w", err)
	}

	var (
		assignmentID        int64
		storedDigest        []byte
		storedPayloadDigest []byte
		stateText           string
	)
	err = tx.QueryRowContext(ctx, `
			SELECT id, offer_digest, offer_payload_digest, state FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = 0
		`, offer.RepositoryAlias, offer.RunnerRequestID).Scan(
		&assignmentID, &storedDigest, &storedPayloadDigest, &stateText,
	)
	switch {
	case err == nil:
		if len(storedDigest) != sha256.Size || !bytes.Equal(storedDigest, digest[:]) ||
			len(storedPayloadDigest) != sha256.Size || !bytes.Equal(storedPayloadDigest, payloadDigest[:]) {
			return OfferReceipt{}, fmt.Errorf("%w: %s/%d", ErrIdentityConflict, offer.RepositoryAlias, offer.RunnerRequestID)
		}
		if evidence.MessageID > 0 && validateOfferEvidence(offer, evidence) == nil {
			// Re-observation can bind a newer queue message, but it is not an
			// assignment-state transition and must not move the state checkpoint.
			if _, err := tx.ExecContext(ctx,
				`UPDATE assignments SET source_message_id = ? WHERE id = ?`,
				evidence.MessageID, assignmentID,
			); err != nil {
				return OfferReceipt{}, fmt.Errorf("state: record offer: update replay evidence: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return OfferReceipt{}, fmt.Errorf("state: record offer: commit replay evidence: %w", err)
			}
		}
		disposition := OfferActiveReplay
		if controller.State(stateText) == controller.StateDestroyed {
			disposition = OfferTerminalReplay
		}
		return OfferReceipt{Key: key, Disposition: disposition, State: controller.State(stateText)}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return OfferReceipt{}, fmt.Errorf("state: record offer: read assignment: %w", err)
	}

	if err := validateOfferEvidence(offer, evidence); err != nil {
		return OfferReceipt{}, err
	}
	if s.historyLimits == nil {
		return OfferReceipt{}, ErrHistoryBudget
	}
	logicalBytes, err := offerLogicalBytesV1(offer)
	if err != nil {
		return OfferReceipt{}, err
	}
	if err := ensureOfferHeadroom(ctx, tx, *s.historyLimits, logicalBytes); err != nil {
		return OfferReceipt{}, err
	}
	sourceMessageID := any(nil)
	if evidence.MessageID > 0 {
		sourceMessageID = evidence.MessageID
	}
	if _, _, _, err := persistOffer(ctx, tx, offer, sourceMessageID, formatTime(evidence.ObservedAt)); err != nil {
		return OfferReceipt{}, fmt.Errorf("state: record offer: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return OfferReceipt{}, fmt.Errorf("state: record offer: commit: %w", err)
	}
	return OfferReceipt{Key: key, Disposition: OfferInserted, State: controller.StateReceived}, nil
}

func validResourceProjection(value ResourceProjection) bool {
	return value.MilliCPU >= 0 &&
		value.MemoryBytes >= 0 &&
		value.PIDs >= 0 &&
		value.FileDescriptors >= 0 &&
		value.TmpfsBytes >= 0 &&
		value.ScratchBytes >= 0 &&
		value.SocketStateBytes >= 0 &&
		value.DurableStateBytes >= 0 &&
		value.Inodes >= 0
}

func resourceProjectionContains(full, part ResourceProjection) bool {
	return part.MilliCPU <= full.MilliCPU &&
		part.MemoryBytes <= full.MemoryBytes &&
		part.PIDs <= full.PIDs &&
		part.FileDescriptors <= full.FileDescriptors &&
		part.TmpfsBytes <= full.TmpfsBytes &&
		part.ScratchBytes <= full.ScratchBytes &&
		part.SocketStateBytes <= full.SocketStateBytes &&
		part.DurableStateBytes <= full.DurableStateBytes &&
		part.Inodes <= full.Inodes
}

func zeroResourceProjection(value ResourceProjection) bool {
	return value == (ResourceProjection{})
}

func validateAdmissionProjection(projection AdmissionProjection) error {
	if !projection.Valid ||
		!validResourceProjection(projection.FullCharge) ||
		!validResourceProjection(projection.LedgerCharge) ||
		!resourceProjectionContains(projection.FullCharge, projection.LedgerCharge) {
		return fmt.Errorf("state: invalid admission projection")
	}
	switch projection.Phase {
	case AdmissionQueued:
		if projection.SlotID != 0 ||
			!zeroResourceProjection(projection.FullCharge) ||
			!zeroResourceProjection(projection.LedgerCharge) ||
			!projection.LedgerCreatedAt.IsZero() ||
			projection.LedgerEverUsed {
			return fmt.Errorf("state: queued admission projection carries slot state")
		}
	case AdmissionReserved, AdmissionActive:
		if projection.SlotID == 0 || projection.LedgerCreatedAt.IsZero() {
			return fmt.Errorf("state: occupied admission projection lacks stable slot identity")
		}
	default:
		return fmt.Errorf("state: invalid admission phase %d", projection.Phase)
	}
	return nil
}

// PersistAdmissionProjection implements Store.
func (s *SQLiteStore) PersistAdmissionProjection(
	ctx context.Context,
	key controller.AssignmentKey,
	projection AdmissionProjection,
) error {
	if err := validateAdmissionProjection(projection); err != nil {
		return err
	}
	slotID := any(projection.SlotID)
	ledgerCreatedAt := any(formatTime(projection.LedgerCreatedAt))
	if projection.Phase == AdmissionQueued {
		slotID = nil
		ledgerCreatedAt = nil
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE assignments SET
			admission_phase = ?, admission_slot_id = ?,
			full_milli_cpu = ?, full_memory_bytes = ?, full_pids = ?,
			full_file_descriptors = ?, full_tmpfs_bytes = ?, full_scratch_bytes = ?,
			full_socket_state_bytes = ?, full_durable_state_bytes = ?, full_inodes = ?,
			ledger_milli_cpu = ?, ledger_memory_bytes = ?, ledger_pids = ?,
			ledger_file_descriptors = ?, ledger_tmpfs_bytes = ?, ledger_scratch_bytes = ?,
			ledger_socket_state_bytes = ?, ledger_durable_state_bytes = ?, ledger_inodes = ?,
			ledger_created_at = ?, ledger_ever_used = ?, updated_at = ?
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ? AND state != ?
	`,
		projection.Phase, slotID,
		projection.FullCharge.MilliCPU, projection.FullCharge.MemoryBytes, projection.FullCharge.PIDs,
		projection.FullCharge.FileDescriptors, projection.FullCharge.TmpfsBytes, projection.FullCharge.ScratchBytes,
		projection.FullCharge.SocketStateBytes, projection.FullCharge.DurableStateBytes, projection.FullCharge.Inodes,
		projection.LedgerCharge.MilliCPU, projection.LedgerCharge.MemoryBytes, projection.LedgerCharge.PIDs,
		projection.LedgerCharge.FileDescriptors, projection.LedgerCharge.TmpfsBytes, projection.LedgerCharge.ScratchBytes,
		projection.LedgerCharge.SocketStateBytes, projection.LedgerCharge.DurableStateBytes, projection.LedgerCharge.Inodes,
		ledgerCreatedAt, boolToInt(projection.LedgerEverUsed), now(),
		key.RepositoryAlias, key.RunnerRequestID, key.Attempt, string(controller.StateDestroyed),
	)
	if err != nil {
		return fmt.Errorf("state: persist admission projection: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("state: persist admission projection: rows affected: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("state: persist admission projection: assignment %+v unavailable", key)
	}
	return nil
}

func messageDigestTx(
	ctx context.Context,
	tx *sql.Tx,
	repositoryAlias string,
	messageID int,
) ([sha256.Size]byte, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT offer_payload_digest, runner_request_id, attempt
		FROM assignments
		WHERE repository_alias = ? AND source_message_id = ?
		UNION ALL
		SELECT offer_payload_digest, runner_request_id, attempt
		FROM history_tombstones
		WHERE repository_alias = ? AND source_message_id = ?
		ORDER BY runner_request_id, attempt
	`, repositoryAlias, messageID, repositoryAlias, messageID)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("state: read message offers: %w", err)
	}
	defer rows.Close()
	var digests [][]byte
	for rows.Next() {
		var digest []byte
		var runnerRequestID, attempt int64
		if err := rows.Scan(&digest, &runnerRequestID, &attempt); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("state: scan message offer: %w", err)
		}
		if len(digest) != sha256.Size {
			return [sha256.Size]byte{}, ErrIdentityConflict
		}
		digests = append(digests, append([]byte(nil), digest...))
	}
	if err := rows.Err(); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("state: read message offers: %w", err)
	}
	if len(digests) == 0 {
		return [sha256.Size]byte{}, ErrReplayEvidence
	}
	return canonicalMessageDigest(repositoryAlias, messageID, digests), nil
}

func ensureReceiptHeadroom(ctx context.Context, tx *sql.Tx, limits HistoryLimits, logicalBytes uint64) error {
	current, err := historyBudgetTotalsTx(ctx, tx)
	if err != nil {
		return err
	}
	reservedRows, err := multiplyHistoryBytes(current.inflightAssignments, limits.InflightReserveRows)
	if err != nil {
		return err
	}
	reservedBytes, err := multiplyHistoryBytes(current.inflightAssignments, limits.InflightReserveLogicalBytes)
	if err != nil {
		return err
	}
	rows, err := addHistoryBytes(current.rows, reservedRows, 1)
	if err != nil || rows > limits.MaxHistoryRows {
		return ErrHistoryBudget
	}
	logical, err := addHistoryBytes(current.logicalBytes, reservedBytes, logicalBytes)
	if err != nil || logical > limits.MaxHistoryLogicalBytes {
		return ErrHistoryBudget
	}
	return nil
}

// BeginMessageAck implements Store.
func (s *SQLiteStore) BeginMessageAck(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	startedAt time.Time,
) error {
	if repositoryAlias == "" || messageID <= 0 || startedAt.IsZero() {
		return ErrReplayEvidence
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin message ack: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		digest   []byte
		ackState string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT payload_digest, ack_state FROM message_receipts
		WHERE repository_alias = ? AND message_id = ?
	`, repositoryAlias, messageID).Scan(&digest, &ackState)
	if errors.Is(err, sql.ErrNoRows) {
		if s.historyLimits == nil {
			return ErrHistoryBudget
		}
		messageDigest, err := messageDigestTx(ctx, tx, repositoryAlias, messageID)
		if err != nil {
			return err
		}
		logicalBytes, err := receiptLogicalBytes(repositoryAlias)
		if err != nil {
			return err
		}
		if err := ensureReceiptHeadroom(ctx, tx, *s.historyLimits, logicalBytes); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO message_receipts (
				repository_alias, message_id, payload_digest, persisted_at,
				ack_state, logical_bytes
			) VALUES (?, ?, ?, ?, 'persisted', ?)
		`, repositoryAlias, messageID, messageDigest[:], formatTime(startedAt), logicalBytes); err != nil {
			return fmt.Errorf("state: begin message ack: persist receipt: %w", err)
		}
		digest = messageDigest[:]
		ackState = "persisted"
	} else if err != nil {
		return fmt.Errorf("state: begin message ack: read receipt: %w", err)
	}
	if len(digest) != sha256.Size {
		return ErrIdentityConflict
	}

	switch ackState {
	case "ack_confirmed":
		return ErrAckConfirmed
	case "ack_started":
		return ErrAckUncertain
	case "persisted", "redelivery_proven":
	default:
		return ErrAckUncertain
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE message_receipts
		SET ack_state = 'ack_started', ack_started_at = ?
		WHERE repository_alias = ? AND message_id = ?
	`, formatTime(startedAt), repositoryAlias, messageID); err != nil {
		return fmt.Errorf("state: begin message ack: transition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: begin message ack: commit: %w", err)
	}
	return nil
}

// ConfirmMessageAck implements Store.
func (s *SQLiteStore) ConfirmMessageAck(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	confirmedAt time.Time,
) error {
	if repositoryAlias == "" || messageID <= 0 || confirmedAt.IsZero() {
		return ErrReplayEvidence
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: confirm message ack: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var ackState string
	if err := tx.QueryRowContext(ctx, `
		SELECT ack_state FROM message_receipts
		WHERE repository_alias = ? AND message_id = ?
	`, repositoryAlias, messageID).Scan(&ackState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAckUncertain
		}
		return fmt.Errorf("state: confirm message ack: read receipt: %w", err)
	}
	if ackState == "ack_confirmed" {
		return nil
	}
	if ackState != "ack_started" {
		return ErrAckUncertain
	}
	retainUntil := confirmedAt
	if s.historyLimits != nil {
		retainUntil = confirmedAt.Add(s.historyLimits.MinRetention)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE message_receipts
		SET ack_state = 'ack_confirmed', ack_confirmed_at = ?, retain_until = ?
		WHERE repository_alias = ? AND message_id = ?
	`, formatTime(confirmedAt), formatTime(retainUntil), repositoryAlias, messageID); err != nil {
		return fmt.Errorf("state: confirm message ack: transition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: confirm message ack: commit: %w", err)
	}
	return nil
}

// ObserveMessageRedelivery implements Store.
func (s *SQLiteStore) ObserveMessageRedelivery(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	payloadDigest [sha256.Size]byte,
	observedAt time.Time,
) error {
	if repositoryAlias == "" || messageID <= 0 || observedAt.IsZero() {
		return ErrReplayEvidence
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: observe message redelivery: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		storedDigest []byte
		ackState     string
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT payload_digest, ack_state FROM message_receipts
		WHERE repository_alias = ? AND message_id = ?
	`, repositoryAlias, messageID).Scan(&storedDigest, &ackState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrReplayEvidence
		}
		return fmt.Errorf("state: observe message redelivery: read receipt: %w", err)
	}
	if len(storedDigest) != sha256.Size || !bytes.Equal(storedDigest, payloadDigest[:]) {
		return ErrIdentityConflict
	}
	if ackState == "persisted" || ackState == "redelivery_proven" {
		return nil
	}
	if ackState != "ack_started" && ackState != "ack_confirmed" {
		return ErrAckUncertain
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE message_receipts
		SET ack_state = 'redelivery_proven', redelivered_at = ?,
		    ack_started_at = NULL, ack_confirmed_at = NULL, retain_until = NULL
		WHERE repository_alias = ? AND message_id = ?
	`, formatTime(observedAt), repositoryAlias, messageID); err != nil {
		return fmt.Errorf("state: observe message redelivery: transition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: observe message redelivery: commit: %w", err)
	}
	return nil
}

// CompactTerminal implements Store.
func (s *SQLiteStore) CompactTerminal(
	ctx context.Context,
	key controller.AssignmentKey,
	limits HistoryLimits,
	at time.Time,
) error {
	if limits.MinRetention <= 0 || at.IsZero() {
		return ErrHistoryBudget
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: compact terminal: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		assignmentID       int64
		stateText          string
		offerDigest        []byte
		offerPayloadDigest []byte
		updatedAtText      string
		terminalMessage    sql.NullInt64
		sourceMessage      sql.NullInt64
		admissionPhase     sql.NullInt64
		admissionSlotID    sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT
			id, state, offer_digest, offer_payload_digest, updated_at,
			terminal_message_id, source_message_id, admission_phase,
			admission_slot_id
		FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(
		&assignmentID,
		&stateText,
		&offerDigest,
		&offerPayloadDigest,
		&updatedAtText,
		&terminalMessage,
		&sourceMessage,
		&admissionPhase,
		&admissionSlotID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		var tombstoneDigest []byte
		tombstoneErr := tx.QueryRowContext(ctx, `
			SELECT offer_digest FROM history_tombstones
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(&tombstoneDigest)
		if tombstoneErr == nil && len(tombstoneDigest) == sha256.Size {
			return nil
		}
		if tombstoneErr != nil && !errors.Is(tombstoneErr, sql.ErrNoRows) {
			return fmt.Errorf("state: compact terminal: read tombstone: %w", tombstoneErr)
		}
		return fmt.Errorf("state: compact terminal: assignment %+v not found", key)
	}
	if err != nil {
		return fmt.Errorf("state: compact terminal: read assignment: %w", err)
	}
	if controller.State(stateText) != controller.StateDestroyed {
		return fmt.Errorf("state: compact terminal: assignment is %s, want DESTROYED", stateText)
	}
	if len(offerDigest) != sha256.Size || len(offerPayloadDigest) != sha256.Size {
		return ErrIdentityConflict
	}
	if !terminalMessage.Valid || terminalMessage.Int64 <= 0 {
		return ErrAckUncertain
	}

	var ackState string
	if err := tx.QueryRowContext(ctx, `
		SELECT ack_state FROM message_receipts
		WHERE repository_alias = ? AND message_id = ?
	`, key.RepositoryAlias, terminalMessage.Int64).Scan(&ackState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAckUncertain
		}
		return fmt.Errorf("state: compact terminal: read terminal receipt: %w", err)
	}
	if ackState != "ack_confirmed" {
		return ErrAckUncertain
	}

	var incompleteEffects, reservations, slots int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM effects WHERE assignment_id = ? AND completed_at IS NULL`,
		assignmentID,
	).Scan(&incompleteEffects); err != nil {
		return fmt.Errorf("state: compact terminal: inspect effects: %w", err)
	}
	if incompleteEffects != 0 {
		return fmt.Errorf("state: compact terminal: %d effects incomplete", incompleteEffects)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM reservations WHERE assignment_id = ?`,
		assignmentID,
	).Scan(&reservations); err != nil {
		return fmt.Errorf("state: compact terminal: inspect reservations: %w", err)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM runner_slots WHERE assignment_id = ?`,
		assignmentID,
	).Scan(&slots); err != nil {
		return fmt.Errorf("state: compact terminal: inspect runner slots: %w", err)
	}
	if reservations != 0 || slots != 0 {
		return fmt.Errorf("state: compact terminal: live durable slot state remains")
	}
	if admissionSlotID.Valid ||
		(admissionPhase.Valid && AdmissionPhase(admissionPhase.Int64) != AdmissionQueued) {
		return fmt.Errorf("state: compact terminal: live admission projection remains")
	}

	terminalAt, err := time.Parse(time.RFC3339Nano, updatedAtText)
	if err != nil {
		return fmt.Errorf("state: compact terminal: parse terminal timestamp: %w", err)
	}
	if at.Before(terminalAt) {
		return fmt.Errorf("state: compact terminal: compaction time precedes terminal checkpoint")
	}
	retainUntil := terminalAt.Add(limits.MinRetention)
	ledgerRows, err := tx.QueryContext(ctx, `
		SELECT retained_until FROM network_ledgers
		WHERE assignment_id = ?
	`, assignmentID)
	if err != nil {
		return fmt.Errorf("state: compact terminal: inspect network ledgers: %w", err)
	}
	for ledgerRows.Next() {
		var retainedUntil sql.NullString
		if err := ledgerRows.Scan(&retainedUntil); err != nil {
			_ = ledgerRows.Close()
			return fmt.Errorf("state: compact terminal: scan network ledger retention: %w", err)
		}
		if !retainedUntil.Valid || retainedUntil.String == "" {
			_ = ledgerRows.Close()
			return fmt.Errorf("state: compact terminal: attached network ledger lacks independent retention")
		}
		// The network ledger owns its retention tail. Compaction only proves that
		// the tail is durable and parseable before detaching the assignment graph;
		// it must not extend or couple that tail to history retention.
		if _, err := time.Parse(time.RFC3339Nano, retainedUntil.String); err != nil {
			_ = ledgerRows.Close()
			return fmt.Errorf("state: compact terminal: parse network ledger retention: %w", err)
		}
	}
	if err := ledgerRows.Err(); err != nil {
		_ = ledgerRows.Close()
		return fmt.Errorf("state: compact terminal: inspect network ledger retention: %w", err)
	}
	if err := ledgerRows.Close(); err != nil {
		return fmt.Errorf("state: compact terminal: close network ledger retention: %w", err)
	}

	logicalBytes, err := tombstoneLogicalBytes(key.RepositoryAlias)
	if err != nil {
		return err
	}

	var existingDigest, existingPayloadDigest []byte
	tombstoneErr := tx.QueryRowContext(ctx, `
		SELECT offer_digest, offer_payload_digest FROM history_tombstones
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(&existingDigest, &existingPayloadDigest)
	if tombstoneErr == nil {
		if len(existingDigest) != sha256.Size || !bytes.Equal(existingDigest, offerDigest) ||
			len(existingPayloadDigest) != sha256.Size || !bytes.Equal(existingPayloadDigest, offerPayloadDigest) {
			return ErrIdentityConflict
		}
	} else if !errors.Is(tombstoneErr, sql.ErrNoRows) {
		return fmt.Errorf("state: compact terminal: read existing tombstone: %w", tombstoneErr)
	} else if _, err := tx.ExecContext(ctx, `
		INSERT INTO history_tombstones (
			repository_alias, runner_request_id, attempt, offer_digest, offer_payload_digest,
			source_message_id, terminal_at, retain_until, logical_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt, offerDigest, offerPayloadDigest,
		sourceMessage, formatTime(terminalAt), formatTime(retainUntil), logicalBytes); err != nil {
		return fmt.Errorf("state: compact terminal: insert tombstone: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE network_ledgers SET assignment_id = NULL WHERE assignment_id = ?`,
		assignmentID,
	); err != nil {
		return fmt.Errorf("state: compact terminal: detach network ledgers: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM assignments WHERE id = ?`, assignmentID); err != nil {
		return fmt.Errorf("state: compact terminal: delete assignment graph: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: compact terminal: commit: %w", err)
	}
	return nil
}

func scanUsagePair(
	ctx context.Context,
	q queryRower,
	query string,
	args ...any,
) (uint64, uint64, error) {
	var rows, logicalBytes int64
	if err := q.QueryRowContext(ctx, query, args...).Scan(&rows, &logicalBytes); err != nil {
		return 0, 0, err
	}
	if rows < 0 || logicalBytes < 0 {
		return 0, 0, ErrHistoryBudget
	}
	return uint64(rows), uint64(logicalBytes), nil
}

func assignmentGraphUsage(
	ctx context.Context,
	q queryRower,
	terminal bool,
) (uint64, uint64, error) {
	predicate := "!="
	if terminal {
		predicate = "="
	}
	query := fmt.Sprintf(`
		WITH selected AS (
			SELECT id, history_logical_bytes
			FROM assignments
			WHERE state %s ?
		)
		SELECT
			(SELECT COUNT(*) FROM selected) +
			(SELECT COUNT(*) FROM runner_slots
				WHERE assignment_id IN (SELECT id FROM selected)) +
			(SELECT COUNT(*) FROM reservations
				WHERE assignment_id IN (SELECT id FROM selected)) +
			(SELECT COUNT(*) FROM effects
				WHERE assignment_id IN (SELECT id FROM selected)),
			COALESCE((SELECT SUM(history_logical_bytes) FROM selected), 0) +
			((SELECT COUNT(*) FROM runner_slots
				WHERE assignment_id IN (SELECT id FROM selected)) * ?) +
			((SELECT COUNT(*) FROM reservations
				WHERE assignment_id IN (SELECT id FROM selected)) * ?) +
			((SELECT COUNT(*) FROM effects
				WHERE assignment_id IN (SELECT id FROM selected)) * ?)
	`, predicate)
	return scanUsagePair(
		ctx,
		q,
		query,
		string(controller.StateDestroyed),
		historyRunnerSlotFixedBytes,
		historyReservationFixedBytes,
		historyEffectFixedBytes,
	)
}

func historyUsageWithQuery(ctx context.Context, q queryRower, limits HistoryLimits) (HistoryUsage, error) {
	var usage HistoryUsage
	var err error
	usage.LiveRows, usage.LiveLogicalBytes, err = assignmentGraphUsage(ctx, q, false)
	if err != nil {
		return HistoryUsage{}, fmt.Errorf("state: history usage live: %w", err)
	}
	usage.ProtectedTerminalRows, usage.ProtectedTerminalBytes, err = assignmentGraphUsage(ctx, q, true)
	if err != nil {
		return HistoryUsage{}, fmt.Errorf("state: history usage terminal: %w", err)
	}
	usage.MessageReceiptRows, usage.MessageReceiptBytes, err = scanUsagePair(ctx, q, `
		SELECT COUNT(*), COALESCE(SUM(logical_bytes), 0) FROM message_receipts
	`)
	if err != nil {
		return HistoryUsage{}, fmt.Errorf("state: history usage receipts: %w", err)
	}
	usage.TombstoneRows, usage.TombstoneLogicalBytes, err = scanUsagePair(ctx, q, `
		SELECT COUNT(*), COALESCE(SUM(logical_bytes), 0) FROM history_tombstones
	`)
	if err != nil {
		return HistoryUsage{}, fmt.Errorf("state: history usage tombstones: %w", err)
	}
	usage.NetworkLedgerRows, usage.NetworkLedgerLogicalBytes, err = scanUsagePair(ctx, q, `
		SELECT COUNT(*), COALESCE(SUM(logical_bytes), 0) FROM network_ledgers
	`)
	if err != nil {
		return HistoryUsage{}, fmt.Errorf("state: history usage network ledgers: %w", err)
	}
	var inflight int64
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assignments WHERE state != ?`,
		string(controller.StateDestroyed),
	).Scan(&inflight); err != nil {
		return HistoryUsage{}, fmt.Errorf("state: history usage inflight assignments: %w", err)
	}
	if inflight < 0 {
		return HistoryUsage{}, ErrHistoryBudget
	}
	usage.InflightAssignments = uint64(inflight)
	usage.ReservedRows, err = multiplyHistoryBytes(usage.InflightAssignments, limits.InflightReserveRows)
	if err != nil {
		return HistoryUsage{}, err
	}
	usage.ReservedLogicalBytes, err = multiplyHistoryBytes(
		usage.InflightAssignments,
		limits.InflightReserveLogicalBytes,
	)
	if err != nil {
		return HistoryUsage{}, err
	}

	var oldest sql.NullString
	if err := q.QueryRowContext(ctx, `
		SELECT MIN(retained_at) FROM (
			SELECT created_at AS retained_at FROM assignments
			UNION ALL
			SELECT persisted_at AS retained_at FROM message_receipts
			UNION ALL
			SELECT terminal_at AS retained_at FROM history_tombstones
			UNION ALL
			SELECT updated_at AS retained_at FROM network_ledgers
		)
		WHERE retained_at != ''
	`).Scan(&oldest); err != nil {
		return HistoryUsage{}, fmt.Errorf("state: history usage oldest retained: %w", err)
	}
	if oldest.Valid {
		usage.OldestRetainedAt, err = time.Parse(time.RFC3339Nano, oldest.String)
		if err != nil {
			return HistoryUsage{}, fmt.Errorf("state: history usage parse oldest retained: %w", err)
		}
	}
	return usage, nil
}

// HistoryUsage implements Store.
func (s *SQLiteStore) HistoryUsage(ctx context.Context, limits HistoryLimits) (HistoryUsage, error) {
	return historyUsageWithQuery(ctx, s.db, limits)
}

// CollectHistory implements the bounded no-deletion baseline. Task E adds
// batched expiry deletion, checkpoint, and incremental-vacuum work.
func (s *SQLiteStore) CollectHistory(
	ctx context.Context,
	limits HistoryLimits,
	_ time.Time,
) (HistoryUsage, error) {
	return s.HistoryUsage(ctx, limits)
}

// Reserve implements Store.
func (s *SQLiteStore) Reserve(ctx context.Context, key controller.AssignmentKey, opaqueName string, capacitySlotID uint32) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: reserve: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	assignmentID, current, err := lookupAssignmentTx(ctx, tx, key)
	if err != nil {
		return err
	}

	if current == controller.StateCapacityReserved {
		// Idempotent replay: the reservation (and its runner-slot row)
		// already exist; re-inserting would violate their UNIQUE
		// constraints, so there is nothing further to do.
		return nil
	}

	if err := controller.Transition(current, controller.StateCapacityReserved, false); err != nil {
		return fmt.Errorf("state: reserve: %w", err)
	}

	ts := now()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO reservations (assignment_id, capacity_slot_id, reserved_at) VALUES (?, ?, ?)`,
		assignmentID, capacitySlotID, ts); err != nil {
		return fmt.Errorf("state: reserve: insert reservation: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO runner_slots (assignment_id, opaque_name, capacity_slot_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		assignmentID, opaqueName, capacitySlotID, ts, ts); err != nil {
		return fmt.Errorf("state: reserve: insert runner slot: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE assignments SET state = ?, released = 0, updated_at = ? WHERE id = ?`,
		string(controller.StateCapacityReserved), ts, assignmentID); err != nil {
		return fmt.Errorf("state: reserve: advance state: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: reserve: commit: %w", err)
	}
	return nil
}

// BeginEffect implements Store.
func (s *SQLiteStore) BeginEffect(ctx context.Context, key controller.AssignmentKey, idempotencyKey, kind string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("state: begin effect: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	assignmentID, _, err := lookupAssignmentTx(ctx, tx, key)
	if err != nil {
		return false, err
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO effects (assignment_id, idempotency_key, kind, began_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (idempotency_key) DO NOTHING
	`, assignmentID, idempotencyKey, kind, now())
	if err != nil {
		return false, fmt.Errorf("state: begin effect: insert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("state: begin effect: rows affected: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("state: begin effect: commit: %w", err)
	}
	return n == 1, nil
}

// identityColumnName maps an IdentityColumn to its fixed runner_slots
// column name. The switch is exhaustive over a small closed enum defined
// in this package, never over caller-supplied text, so building SQL with
// the result is not an injection risk.
func identityColumnName(c IdentityColumn) (string, error) {
	switch c {
	case IdentityAdapterContainer:
		return "adapter_container_id", nil
	case IdentityBrokerContainer:
		return "broker_container_id", nil
	case IdentityRunnerContainer:
		return "runner_container_id", nil
	case IdentityPolicySocketDigest:
		return "policy_socket_digest", nil
	default:
		return "", fmt.Errorf("state: unknown identity column %d", c)
	}
}

// CompleteEffect implements Store.
func (s *SQLiteStore) CompleteEffect(ctx context.Context, idempotencyKey string, result EffectResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: complete effect: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var assignmentID int64
	if err := tx.QueryRowContext(ctx, `SELECT assignment_id FROM effects WHERE idempotency_key = ?`, idempotencyKey).Scan(&assignmentID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("state: complete effect: no effect begun for idempotency key %q", idempotencyKey)
		}
		return fmt.Errorf("state: complete effect: look up effect: %w", err)
	}

	ts := now()
	// completed_at only ever gets its first-completion value: COALESCE
	// keeps an idempotent replay (same idempotencyKey completed again,
	// e.g. after a crash-and-retry) from rewriting the timestamp on every
	// call, so it stays a stable "when did this effect actually finish"
	// fact rather than drifting to the most recent replay's clock.
	if _, err := tx.ExecContext(ctx,
		`UPDATE effects SET completed_at = COALESCE(completed_at, ?), result_identity = ?, reason_code = ? WHERE idempotency_key = ?`,
		ts, result.ResultIdentity, result.ReasonCode, idempotencyKey); err != nil {
		return fmt.Errorf("state: complete effect: update: %w", err)
	}

	if result.Column != IdentityNone {
		column, err := identityColumnName(result.Column)
		if err != nil {
			return fmt.Errorf("state: complete effect: %w", err)
		}
		stmt := fmt.Sprintf(`UPDATE runner_slots SET %s = ?, updated_at = ? WHERE assignment_id = ?`, column)
		if _, err := tx.ExecContext(ctx, stmt, result.ResultIdentity, ts, assignmentID); err != nil {
			return fmt.Errorf("state: complete effect: persist identity: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: complete effect: commit: %w", err)
	}
	return nil
}

// Advance implements Store.
//
// released is deliberately not a parameter: the store derives it itself
// from the row's persisted current state via controller.HasReleasedListener,
// rather than trusting a caller-supplied flag. A caller passing
// released=false while the assignment is actually already at/after
// LISTENER_RELEASED would let controller.Transition's pre-release "any
// state -> DESTROYED" shortcut fire when it must not -- exactly the
// post-release blind-destroy case Transition's doc says must instead route
// through MarkAmbiguous. Self-deriving the invariant from persisted state
// makes that caller mistake structurally impossible.
func (s *SQLiteStore) Advance(ctx context.Context, key controller.AssignmentKey, next controller.State) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: advance: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	assignmentID, current, err := lookupAssignmentTx(ctx, tx, key)
	if err != nil {
		return err
	}

	wasReleased := controller.HasReleasedListener(current)

	if err := controller.Transition(current, next, wasReleased); err != nil {
		return fmt.Errorf("state: advance: %w", err)
	}

	if current == next {
		// Idempotent replay: state already reflects this checkpoint.
		return nil
	}

	releaseGenBump := 0
	if next == controller.StateListenerReleased {
		releaseGenBump = 1
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE assignments SET state = ?, released = ?, release_generation = release_generation + ?, updated_at = ? WHERE id = ?`,
		string(next), boolToInt(controller.HasReleasedListener(next)), releaseGenBump, now(), assignmentID); err != nil {
		return fmt.Errorf("state: advance: update: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: advance: commit: %w", err)
	}
	return nil
}

// MarkAmbiguous implements Store.
func (s *SQLiteStore) MarkAmbiguous(ctx context.Context, key controller.AssignmentKey, reasonCode string) error {
	ts := now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE assignments SET ambiguous_reason = ?, ambiguous_at = ?, updated_at = ?
		 WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?`,
		reasonCode, ts, ts, key.RepositoryAlias, key.RunnerRequestID, key.Attempt)
	if err != nil {
		return fmt.Errorf("state: mark ambiguous: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("state: mark ambiguous: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("state: mark ambiguous: assignment %+v not found", key)
	}
	return nil
}

// BindRunner implements Store.
func (s *SQLiteStore) BindRunner(ctx context.Context, key controller.AssignmentKey, upstreamRunnerID int64, runnerContainerID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: bind runner: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	assignmentID, _, err := lookupAssignmentTx(ctx, tx, key)
	if err != nil {
		return err
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE runner_slots SET upstream_runner_id = ?, bound_request_id = ?, runner_container_id = ?, updated_at = ? WHERE assignment_id = ?`,
		upstreamRunnerID, key.RunnerRequestID, runnerContainerID, now(), assignmentID)
	if err != nil {
		return fmt.Errorf("state: bind runner: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("state: bind runner: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("state: bind runner: no runner slot reserved for assignment %+v", key)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: bind runner: commit: %w", err)
	}
	return nil
}

// ListRecoverable implements Store.
func (s *SQLiteStore) ListRecoverable(ctx context.Context) ([]RecoverableAssignment, error) {
	rows, err := s.db.QueryContext(ctx, `
			SELECT a.repository_alias, a.runner_request_id, a.attempt, a.state, a.released,
			       a.ambiguous_reason, a.updated_at,
			       a.workflow_job_id, a.job_id, a.repository_name, a.owner_name,
			       a.job_workflow_ref, a.job_display_name, a.workflow_run_id,
			       a.event_name, a.request_labels, a.queue_time,
			       a.scale_set_assign_time, a.runner_assign_time, a.finish_time,
			       a.acquire_job_url,
			       a.admission_phase, a.admission_slot_id,
			       a.full_milli_cpu, a.full_memory_bytes, a.full_pids,
			       a.full_file_descriptors, a.full_tmpfs_bytes, a.full_scratch_bytes,
			       a.full_socket_state_bytes, a.full_durable_state_bytes, a.full_inodes,
			       a.ledger_milli_cpu, a.ledger_memory_bytes, a.ledger_pids,
			       a.ledger_file_descriptors, a.ledger_tmpfs_bytes, a.ledger_scratch_bytes,
			       a.ledger_socket_state_bytes, a.ledger_durable_state_bytes, a.ledger_inodes,
			       a.ledger_created_at, a.ledger_ever_used,
			       rs.opaque_name, rs.capacity_slot_id, rs.upstream_runner_id, rs.bound_request_id,
			       rs.runner_container_id, rs.adapter_container_id, rs.broker_container_id
			FROM assignments a
		LEFT JOIN runner_slots rs ON rs.assignment_id = a.id
		WHERE a.state != ?
		ORDER BY a.id
	`, string(controller.StateDestroyed))
	if err != nil {
		return nil, fmt.Errorf("state: list recoverable: query: %w", err)
	}
	defer rows.Close()

	var out []RecoverableAssignment
	for rows.Next() {
		var (
			repositoryAlias         string
			runnerRequestID         int64
			attempt                 int64
			stateStr                string
			releasedInt             int
			ambiguousReason         sql.NullString
			updatedAtStr            string
			workflowJobID           int64
			jobID                   string
			repositoryName          string
			ownerName               string
			jobWorkflowRef          string
			jobDisplayName          string
			workflowRunID           int64
			eventName               string
			requestLabelsJSON       string
			queueTimeText           string
			scaleSetTimeText        string
			runnerTimeText          string
			finishTimeText          string
			acquireJobURL           string
			admissionPhase          sql.NullInt64
			admissionSlotID         sql.NullInt64
			fullMilliCPU            sql.NullInt64
			fullMemoryBytes         sql.NullInt64
			fullPIDs                sql.NullInt64
			fullFileDescriptors     sql.NullInt64
			fullTmpfsBytes          sql.NullInt64
			fullScratchBytes        sql.NullInt64
			fullSocketStateBytes    sql.NullInt64
			fullDurableStateBytes   sql.NullInt64
			fullInodes              sql.NullInt64
			ledgerMilliCPU          sql.NullInt64
			ledgerMemoryBytes       sql.NullInt64
			ledgerPIDs              sql.NullInt64
			ledgerFileDescriptors   sql.NullInt64
			ledgerTmpfsBytes        sql.NullInt64
			ledgerScratchBytes      sql.NullInt64
			ledgerSocketStateBytes  sql.NullInt64
			ledgerDurableStateBytes sql.NullInt64
			ledgerInodes            sql.NullInt64
			ledgerCreatedAtText     sql.NullString
			ledgerEverUsed          sql.NullInt64
			opaqueName              sql.NullString
			capacitySlotID          sql.NullInt64
			upstreamRunnerID        sql.NullInt64
			boundRequestID          sql.NullInt64
			runnerContainer         sql.NullString
			adapterContainer        sql.NullString
			brokerContainer         sql.NullString
		)
		if err := rows.Scan(
			&repositoryAlias, &runnerRequestID, &attempt, &stateStr, &releasedInt,
			&ambiguousReason, &updatedAtStr,
			&workflowJobID, &jobID, &repositoryName, &ownerName,
			&jobWorkflowRef, &jobDisplayName, &workflowRunID,
			&eventName, &requestLabelsJSON, &queueTimeText,
			&scaleSetTimeText, &runnerTimeText, &finishTimeText,
			&acquireJobURL,
			&admissionPhase, &admissionSlotID,
			&fullMilliCPU, &fullMemoryBytes, &fullPIDs,
			&fullFileDescriptors, &fullTmpfsBytes, &fullScratchBytes,
			&fullSocketStateBytes, &fullDurableStateBytes, &fullInodes,
			&ledgerMilliCPU, &ledgerMemoryBytes, &ledgerPIDs,
			&ledgerFileDescriptors, &ledgerTmpfsBytes, &ledgerScratchBytes,
			&ledgerSocketStateBytes, &ledgerDurableStateBytes, &ledgerInodes,
			&ledgerCreatedAtText, &ledgerEverUsed,
			&opaqueName, &capacitySlotID, &upstreamRunnerID, &boundRequestID,
			&runnerContainer, &adapterContainer, &brokerContainer,
		); err != nil {
			return nil, fmt.Errorf("state: list recoverable: scan: %w", err)
		}

		updatedAt, err := time.Parse(time.RFC3339Nano, updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("state: list recoverable: parse updated_at: %w", err)
		}
		queueTime, err := parseOptionalTime(queueTimeText)
		if err != nil {
			return nil, fmt.Errorf("state: list recoverable: parse queue_time: %w", err)
		}
		scaleSetTime, err := parseOptionalTime(scaleSetTimeText)
		if err != nil {
			return nil, fmt.Errorf("state: list recoverable: parse scale_set_assign_time: %w", err)
		}
		runnerTime, err := parseOptionalTime(runnerTimeText)
		if err != nil {
			return nil, fmt.Errorf("state: list recoverable: parse runner_assign_time: %w", err)
		}
		finishTime, err := parseOptionalTime(finishTimeText)
		if err != nil {
			return nil, fmt.Errorf("state: list recoverable: parse finish_time: %w", err)
		}
		var requestLabels []string
		if err := json.Unmarshal([]byte(requestLabelsJSON), &requestLabels); err != nil {
			return nil, fmt.Errorf("state: list recoverable: decode request_labels: %w", err)
		}
		var ledgerCreatedAt time.Time
		if ledgerCreatedAtText.Valid {
			ledgerCreatedAt, err = parseOptionalTime(ledgerCreatedAtText.String)
			if err != nil {
				return nil, fmt.Errorf("state: list recoverable: parse ledger_created_at: %w", err)
			}
		}
		projectionScalars := []sql.NullInt64{
			fullMilliCPU,
			fullMemoryBytes,
			fullPIDs,
			fullFileDescriptors,
			fullTmpfsBytes,
			fullScratchBytes,
			fullSocketStateBytes,
			fullDurableStateBytes,
			fullInodes,
			ledgerMilliCPU,
			ledgerMemoryBytes,
			ledgerPIDs,
			ledgerFileDescriptors,
			ledgerTmpfsBytes,
			ledgerScratchBytes,
			ledgerSocketStateBytes,
			ledgerDurableStateBytes,
			ledgerInodes,
		}
		if !admissionPhase.Valid {
			if admissionSlotID.Valid || ledgerCreatedAtText.Valid || ledgerEverUsed.Valid {
				return nil, fmt.Errorf("state: list recoverable: orphaned admission projection metadata")
			}
			for _, scalar := range projectionScalars {
				if scalar.Valid {
					return nil, fmt.Errorf("state: list recoverable: orphaned admission projection charge")
				}
			}
		} else {
			for _, scalar := range projectionScalars {
				if !scalar.Valid {
					return nil, fmt.Errorf("state: list recoverable: incomplete admission projection charge")
				}
			}
			if !ledgerEverUsed.Valid {
				return nil, fmt.Errorf("state: list recoverable: incomplete admission ledger state")
			}
			switch AdmissionPhase(admissionPhase.Int64) {
			case AdmissionQueued:
				if admissionSlotID.Valid || ledgerCreatedAtText.Valid {
					return nil, fmt.Errorf("state: list recoverable: queued admission carries slot metadata")
				}
			case AdmissionReserved, AdmissionActive:
				if !admissionSlotID.Valid || !ledgerCreatedAtText.Valid {
					return nil, fmt.Errorf("state: list recoverable: occupied admission lacks slot metadata")
				}
			default:
				return nil, fmt.Errorf("state: list recoverable: invalid admission phase %d", admissionPhase.Int64)
			}
		}
		projection := AdmissionProjection{}
		if admissionPhase.Valid {
			projection = AdmissionProjection{
				Valid:  true,
				Phase:  AdmissionPhase(admissionPhase.Int64),
				SlotID: uint32(admissionSlotID.Int64),
				FullCharge: ResourceProjection{
					MilliCPU:          fullMilliCPU.Int64,
					MemoryBytes:       fullMemoryBytes.Int64,
					PIDs:              fullPIDs.Int64,
					FileDescriptors:   fullFileDescriptors.Int64,
					TmpfsBytes:        fullTmpfsBytes.Int64,
					ScratchBytes:      fullScratchBytes.Int64,
					SocketStateBytes:  fullSocketStateBytes.Int64,
					DurableStateBytes: fullDurableStateBytes.Int64,
					Inodes:            fullInodes.Int64,
				},
				LedgerCharge: ResourceProjection{
					MilliCPU:          ledgerMilliCPU.Int64,
					MemoryBytes:       ledgerMemoryBytes.Int64,
					PIDs:              ledgerPIDs.Int64,
					FileDescriptors:   ledgerFileDescriptors.Int64,
					TmpfsBytes:        ledgerTmpfsBytes.Int64,
					ScratchBytes:      ledgerScratchBytes.Int64,
					SocketStateBytes:  ledgerSocketStateBytes.Int64,
					DurableStateBytes: ledgerDurableStateBytes.Int64,
					Inodes:            ledgerInodes.Int64,
				},
				LedgerCreatedAt: ledgerCreatedAt,
				LedgerEverUsed:  ledgerEverUsed.Int64 != 0,
			}
			if err := validateAdmissionProjection(projection); err != nil {
				return nil, fmt.Errorf("state: list recoverable: %w", err)
			}
		}

		out = append(out, RecoverableAssignment{
			Key: controller.AssignmentKey{
				RepositoryAlias: repositoryAlias,
				RunnerRequestID: runnerRequestID,
				Attempt:         uint32(attempt),
			},
			State: controller.State(stateStr),
			Offer: OfferIdentity{
				RepositoryAlias:    repositoryAlias,
				RunnerRequestID:    runnerRequestID,
				WorkflowJobID:      workflowJobID,
				JobID:              jobID,
				RepositoryName:     repositoryName,
				OwnerName:          ownerName,
				JobWorkflowRef:     jobWorkflowRef,
				JobDisplayName:     jobDisplayName,
				WorkflowRunID:      workflowRunID,
				EventName:          eventName,
				RequestLabels:      requestLabels,
				QueueTime:          queueTime,
				ScaleSetAssignTime: scaleSetTime,
				RunnerAssignTime:   runnerTime,
				FinishTime:         finishTime,
				AcquireJobURL:      acquireJobURL,
			},
			Admission:       projection,
			Released:        releasedInt != 0,
			Ambiguous:       ambiguousReason.Valid && ambiguousReason.String != "",
			AmbiguousReason: ambiguousReason.String,
			Slot: controller.RunnerSlot{
				OpaqueName:         opaqueName.String,
				UpstreamRunnerID:   upstreamRunnerID.Int64,
				BoundRequestID:     boundRequestID.Int64,
				RunnerContainerID:  runnerContainer.String,
				AdapterContainerID: adapterContainer.String,
				BrokerContainerID:  brokerContainer.String,
				CapacitySlotID:     uint32(capacitySlotID.Int64),
			},
			UpdatedAt: updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: list recoverable: rows: %w", err)
	}
	return out, nil
}

// readAcquisitionPolicy reads the singleton acquisition_state row through
// q, which may be either the store's *sql.DB or an in-flight *sql.Tx.
func readAcquisitionPolicy(ctx context.Context, q queryRower) (controller.AcquisitionPolicy, error) {
	var (
		mode         string
		eligibleJSON string
		maxCapacity  int
		revision     int64
		policiesJSON string
		epoch        int64
	)
	err := q.QueryRowContext(ctx, `
		SELECT mode, eligible_scale_sets, max_capacity, repository_policy_revision, repository_policies, acquisition_epoch
		FROM acquisition_state WHERE id = 1
	`).Scan(&mode, &eligibleJSON, &maxCapacity, &revision, &policiesJSON, &epoch)
	if err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: read acquisition policy: %w", err)
	}

	var eligible []string
	if err := json.Unmarshal([]byte(eligibleJSON), &eligible); err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: read acquisition policy: decode eligible scale sets: %w", err)
	}
	var policies []controller.RepositoryPolicySummary
	if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: read acquisition policy: decode repository policies: %w", err)
	}

	return controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionMode(mode),
		EligibleScaleSets:        eligible,
		MaxCapacity:              maxCapacity,
		RepositoryPolicyRevision: uint64(revision),
		RepositoryPolicies:       policies,
		Epoch:                    uint64(epoch),
	}, nil
}

// AcquisitionPolicy implements Store.
func (s *SQLiteStore) AcquisitionPolicy(ctx context.Context) (controller.AcquisitionPolicy, error) {
	return readAcquisitionPolicy(ctx, s.db)
}

// CompareAndSetAcquisition implements Store.
func (s *SQLiteStore) CompareAndSetAcquisition(ctx context.Context, expectedEpoch uint64, next controller.AcquisitionPolicy) (controller.AcquisitionPolicy, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: compare-and-set acquisition: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentEpoch int64
	if err := tx.QueryRowContext(ctx, `SELECT acquisition_epoch FROM acquisition_state WHERE id = 1`).Scan(&currentEpoch); err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: compare-and-set acquisition: read epoch: %w", err)
	}

	if uint64(currentEpoch) != expectedEpoch {
		current, err := readAcquisitionPolicy(ctx, tx)
		if err != nil {
			return controller.AcquisitionPolicy{}, err
		}
		return current, fmt.Errorf("%w: expected %d, current %d", ErrAcquisitionEpochMismatch, expectedEpoch, currentEpoch)
	}

	eligibleJSON, err := json.Marshal(next.EligibleScaleSets)
	if err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: compare-and-set acquisition: encode eligible scale sets: %w", err)
	}
	policiesJSON, err := json.Marshal(next.RepositoryPolicies)
	if err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: compare-and-set acquisition: encode repository policies: %w", err)
	}

	newEpoch := expectedEpoch + 1
	if _, err := tx.ExecContext(ctx, `
		UPDATE acquisition_state
		SET mode = ?, eligible_scale_sets = ?, max_capacity = ?, repository_policy_revision = ?, repository_policies = ?, acquisition_epoch = ?
		WHERE id = 1
	`, string(next.Mode), string(eligibleJSON), next.MaxCapacity, next.RepositoryPolicyRevision, string(policiesJSON), newEpoch); err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: compare-and-set acquisition: update: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return controller.AcquisitionPolicy{}, fmt.Errorf("state: compare-and-set acquisition: commit: %w", err)
	}

	result := next
	result.Epoch = newEpoch
	return result, nil
}
