package state

import (
	"context"
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
	db *sql.DB
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
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(3)&_txlock=immediate",
		path,
	)
}

func Open(path string) (*SQLiteStore, error) {
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

	return &SQLiteStore{db: db}, nil
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

// UpsertOffer implements Store.
func (s *SQLiteStore) UpsertOffer(ctx context.Context, offer OfferIdentity) (controller.AssignmentKey, error) {
	ts := now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO assignments (repository_alias, runner_request_id, attempt, workflow_job_id, state, created_at, updated_at)
		VALUES (?, ?, 0, ?, ?, ?, ?)
		ON CONFLICT (repository_alias, runner_request_id, attempt) DO NOTHING
	`, offer.RepositoryAlias, offer.RunnerRequestID, offer.WorkflowJobID, string(controller.StateReceived), ts, ts)
	if err != nil {
		return controller.AssignmentKey{}, fmt.Errorf("state: upsert offer: %w", err)
	}

	return controller.AssignmentKey{
		RepositoryAlias: offer.RepositoryAlias,
		RunnerRequestID: offer.RunnerRequestID,
		Attempt:         0,
	}, nil
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
			repositoryAlias  string
			runnerRequestID  int64
			attempt          int64
			stateStr         string
			releasedInt      int
			ambiguousReason  sql.NullString
			updatedAtStr     string
			opaqueName       sql.NullString
			capacitySlotID   sql.NullInt64
			upstreamRunnerID sql.NullInt64
			boundRequestID   sql.NullInt64
			runnerContainer  sql.NullString
			adapterContainer sql.NullString
			brokerContainer  sql.NullString
		)
		if err := rows.Scan(
			&repositoryAlias, &runnerRequestID, &attempt, &stateStr, &releasedInt,
			&ambiguousReason, &updatedAtStr,
			&opaqueName, &capacitySlotID, &upstreamRunnerID, &boundRequestID,
			&runnerContainer, &adapterContainer, &brokerContainer,
		); err != nil {
			return nil, fmt.Errorf("state: list recoverable: scan: %w", err)
		}

		updatedAt, err := time.Parse(time.RFC3339Nano, updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("state: list recoverable: parse updated_at: %w", err)
		}

		out = append(out, RecoverableAssignment{
			Key: controller.AssignmentKey{
				RepositoryAlias: repositoryAlias,
				RunnerRequestID: runnerRequestID,
				Attempt:         uint32(attempt),
			},
			State:           controller.State(stateStr),
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
