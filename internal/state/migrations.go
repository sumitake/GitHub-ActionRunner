package state

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

const (
	currentSchemaVersion        = 3
	sqliteAutoVacuumNone        = 0
	sqliteAutoVacuumFull        = 1
	sqliteAutoVacuumIncremental = 2
)

// schemaV1 is the complete bootstrap schema. New databases select incremental
// auto-vacuum before this table set is created. Existing version-zero
// databases can migrate in place only when they were already created in that
// mode; otherwise Open returns ErrOfflineMigration and performs no schema
// write.
const schemaV1 = `
CREATE TABLE IF NOT EXISTS assignments (
	id                    INTEGER PRIMARY KEY AUTOINCREMENT,
	repository_alias      TEXT    NOT NULL,
	runner_request_id     INTEGER NOT NULL,
	attempt               INTEGER NOT NULL DEFAULT 0,
	workflow_job_id       INTEGER NOT NULL,
	offer_digest          BLOB    NOT NULL CHECK (length(offer_digest) = 32),
	offer_payload_digest  BLOB    NOT NULL CHECK (length(offer_payload_digest) = 32),
	source_message_id     INTEGER,
	terminal_message_id   INTEGER,
	job_id                TEXT    NOT NULL,
	repository_name       TEXT    NOT NULL,
	owner_name            TEXT    NOT NULL,
	job_workflow_ref      TEXT    NOT NULL,
	job_display_name      TEXT    NOT NULL,
	workflow_run_id       INTEGER NOT NULL,
	event_name            TEXT    NOT NULL,
	request_labels        TEXT    NOT NULL,
	queue_time            TEXT    NOT NULL,
	scale_set_assign_time TEXT    NOT NULL,
	runner_assign_time    TEXT    NOT NULL,
	finish_time           TEXT    NOT NULL,
	acquire_job_url       TEXT    NOT NULL,
	admission_phase       INTEGER CHECK (admission_phase IS NULL OR admission_phase IN (1, 2, 3)),
	admission_slot_id     INTEGER CHECK (admission_slot_id IS NULL OR admission_slot_id BETWEEN 1 AND 4294967295),
	full_milli_cpu          INTEGER,
	full_memory_bytes       INTEGER,
	full_pids               INTEGER,
	full_file_descriptors   INTEGER,
	full_tmpfs_bytes        INTEGER,
	full_scratch_bytes      INTEGER,
	full_socket_state_bytes INTEGER,
	full_durable_state_bytes INTEGER,
	full_inodes              INTEGER,
	ledger_milli_cpu          INTEGER,
	ledger_memory_bytes       INTEGER,
	ledger_pids               INTEGER,
	ledger_file_descriptors   INTEGER,
	ledger_tmpfs_bytes        INTEGER,
	ledger_scratch_bytes      INTEGER,
	ledger_socket_state_bytes INTEGER,
	ledger_durable_state_bytes INTEGER,
	ledger_inodes              INTEGER,
	ledger_created_at       TEXT,
	ledger_ever_used        INTEGER CHECK (ledger_ever_used IS NULL OR ledger_ever_used IN (0, 1)),
	history_logical_bytes   INTEGER NOT NULL CHECK (history_logical_bytes > 0),
	state                 TEXT    NOT NULL,
	released              INTEGER NOT NULL DEFAULT 0,
	release_generation    INTEGER NOT NULL DEFAULT 0,
	ambiguous_reason      TEXT,
	ambiguous_at          TEXT,
	created_at            TEXT    NOT NULL,
	updated_at            TEXT    NOT NULL,
	UNIQUE (repository_alias, runner_request_id, attempt)
);

CREATE INDEX IF NOT EXISTS assignments_source_message
	ON assignments (repository_alias, source_message_id);
CREATE INDEX IF NOT EXISTS assignments_terminal_message
	ON assignments (repository_alias, terminal_message_id);

CREATE TABLE IF NOT EXISTS runner_slots (
	id                    INTEGER PRIMARY KEY AUTOINCREMENT,
	assignment_id         INTEGER NOT NULL UNIQUE REFERENCES assignments (id) ON DELETE CASCADE,
	opaque_name           TEXT    NOT NULL UNIQUE,
	capacity_slot_id      INTEGER NOT NULL UNIQUE,
	upstream_runner_id    INTEGER,
	bound_request_id      INTEGER,
	runner_container_id   TEXT,
	adapter_container_id  TEXT,
	broker_container_id   TEXT,
	policy_socket_digest  TEXT,
	created_at            TEXT    NOT NULL,
	updated_at            TEXT    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS runner_slots_upstream_runner_id_unique
	ON runner_slots (upstream_runner_id)
	WHERE upstream_runner_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS reservations (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	assignment_id     INTEGER NOT NULL UNIQUE REFERENCES assignments (id) ON DELETE CASCADE,
	capacity_slot_id  INTEGER NOT NULL UNIQUE,
	reserved_at       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS effects (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	assignment_id    INTEGER NOT NULL REFERENCES assignments (id) ON DELETE CASCADE,
	idempotency_key  TEXT    NOT NULL UNIQUE,
	kind             TEXT    NOT NULL,
	began_at         TEXT    NOT NULL,
	completed_at     TEXT,
	result_identity  TEXT,
	reason_code      TEXT
);

CREATE TABLE IF NOT EXISTS acquisition_state (
	id                          INTEGER PRIMARY KEY CHECK (id = 1),
	mode                        TEXT    NOT NULL,
	eligible_scale_sets         TEXT    NOT NULL,
	max_capacity                INTEGER NOT NULL,
	repository_policy_revision  INTEGER NOT NULL,
	repository_policies         TEXT    NOT NULL,
	acquisition_epoch           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS network_ledgers (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	ledger_key     TEXT NOT NULL UNIQUE,
	assignment_id  INTEGER REFERENCES assignments (id) ON DELETE SET NULL,
	state_digest   TEXT,
	updated_at     TEXT NOT NULL,
	retained_until TEXT,
	logical_bytes  INTEGER NOT NULL DEFAULT 1 CHECK (logical_bytes > 0)
);

CREATE TABLE IF NOT EXISTS reconcile_cycles (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	cycle_id            TEXT    NOT NULL UNIQUE,
	started_at          TEXT    NOT NULL,
	completed_at        TEXT,
	assignment_count    INTEGER,
	oldest_age_seconds  INTEGER,
	note                TEXT
);

CREATE TABLE IF NOT EXISTS message_receipts (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	repository_alias   TEXT    NOT NULL,
	message_id         INTEGER NOT NULL,
	payload_digest     BLOB    NOT NULL CHECK (length(payload_digest) = 32),
	persisted_at       TEXT    NOT NULL,
	ack_state          TEXT    NOT NULL CHECK (ack_state IN ('persisted', 'ack_started', 'redelivery_proven', 'ack_confirmed')),
	ack_started_at     TEXT,
	ack_confirmed_at   TEXT,
	redelivered_at     TEXT,
	retain_until       TEXT,
	logical_bytes      INTEGER NOT NULL CHECK (logical_bytes > 0),
	UNIQUE (repository_alias, message_id)
);

CREATE INDEX IF NOT EXISTS message_receipts_retention
	ON message_receipts (retain_until, id);

CREATE TABLE IF NOT EXISTS history_tombstones (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	repository_alias   TEXT    NOT NULL,
	runner_request_id  INTEGER NOT NULL,
	attempt            INTEGER NOT NULL,
	offer_digest       BLOB    NOT NULL CHECK (length(offer_digest) = 32),
	offer_payload_digest BLOB  NOT NULL CHECK (length(offer_payload_digest) = 32),
	source_message_id  INTEGER,
	terminal_at        TEXT    NOT NULL,
	retain_until       TEXT    NOT NULL,
	logical_bytes      INTEGER NOT NULL CHECK (logical_bytes > 0),
	CHECK (retain_until >= terminal_at),
	UNIQUE (repository_alias, runner_request_id, attempt)
);

CREATE INDEX IF NOT EXISTS history_tombstones_retention
	ON history_tombstones (retain_until, id);
CREATE INDEX IF NOT EXISTS history_tombstones_source_message
	ON history_tombstones (repository_alias, source_message_id);
`

// schemaV2 adds one bounded aggregate singleton for the last successfully
// completed maintenance cycle plus the ordering indexes used by bounded
// oldest-first reporting and collection. The singleton contains no repository,
// offer, runner, message, or other workload identity and lets status remain a
// read-only operation. The v1-to-v2 transaction also rewrites every timestamp
// used by these indexes into the fixed-width UTC key they require.
const schemaV2 = `
CREATE TABLE IF NOT EXISTS history_maintenance (
	id                         INTEGER PRIMARY KEY CHECK (id = 1),
	observed_at                TEXT    NOT NULL,
	compacted_terminal_graphs  INTEGER NOT NULL CHECK (compacted_terminal_graphs >= 0),
	deleted_message_receipts   INTEGER NOT NULL CHECK (deleted_message_receipts >= 0),
	deleted_tombstones         INTEGER NOT NULL CHECK (deleted_tombstones >= 0),
	deleted_network_ledgers    INTEGER NOT NULL CHECK (deleted_network_ledgers >= 0),
	checkpoint_busy            INTEGER NOT NULL CHECK (checkpoint_busy IN (0, 1)),
	checkpoint_log_pages       INTEGER NOT NULL CHECK (checkpoint_log_pages >= 0),
	checkpointed_pages         INTEGER NOT NULL CHECK (checkpointed_pages >= 0),
	vacuumed_pages             INTEGER NOT NULL CHECK (vacuumed_pages >= 0)
);

CREATE INDEX IF NOT EXISTS assignments_history_oldest
	ON assignments (created_at);
CREATE INDEX IF NOT EXISTS assignments_terminal_collection
	ON assignments (state, updated_at, id);
CREATE INDEX IF NOT EXISTS message_receipts_history_oldest
	ON message_receipts (persisted_at);
CREATE INDEX IF NOT EXISTS history_tombstones_history_oldest
	ON history_tombstones (terminal_at);
CREATE INDEX IF NOT EXISTS network_ledgers_history_oldest
	ON network_ledgers (updated_at);
CREATE INDEX IF NOT EXISTS network_ledgers_retention
	ON network_ledgers (retained_until, id)
	WHERE assignment_id IS NULL AND retained_until IS NOT NULL;
`

// schemaV3 adds the durable acquisition batch journal and the assignment-side
// acquisition/revocation classifications used by Task 8. The batch row is
// receipt-owned: once every linked assignment graph and its receipt satisfy
// retention, deleting that receipt atomically removes the batch through the
// foreign key. Existing queued assignments remain offered, while an existing
// reserved/active admission projection proves that acquisition already
// succeeded and is migrated to acquired.
const schemaV3 = `
ALTER TABLE assignments
	ADD COLUMN acquisition_outcome TEXT NOT NULL DEFAULT 'offered'
	CHECK (acquisition_outcome IN ('offered', 'requested', 'acquired', 'rejected'));
ALTER TABLE assignments
	ADD COLUMN pre_running_revoked_epoch INTEGER
	CHECK (pre_running_revoked_epoch IS NULL OR pre_running_revoked_epoch > 0);

CREATE TABLE message_acquisitions (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	repository_alias   TEXT    NOT NULL,
	message_id         INTEGER NOT NULL,
	request_digest     BLOB    NOT NULL CHECK (length(request_digest) = 32),
	result_digest      BLOB    CHECK (result_digest IS NULL OR length(result_digest) = 32),
	state              TEXT    NOT NULL CHECK (state IN ('begun', 'not_attempted', 'completed', 'ambiguous')),
	requested_count    INTEGER NOT NULL CHECK (requested_count > 0),
	acquired_count     INTEGER CHECK (
		acquired_count IS NULL OR
		(acquired_count >= 0 AND acquired_count <= requested_count)
	),
	begun_at           TEXT    NOT NULL,
	updated_at         TEXT    NOT NULL,
	logical_bytes      INTEGER NOT NULL CHECK (logical_bytes > 0),
	UNIQUE (repository_alias, message_id),
	FOREIGN KEY (repository_alias, message_id)
		REFERENCES message_receipts (repository_alias, message_id)
		ON DELETE CASCADE,
	CHECK (
		(state = 'completed' AND result_digest IS NOT NULL AND acquired_count IS NOT NULL) OR
		(state != 'completed' AND result_digest IS NULL AND acquired_count IS NULL)
	)
);

CREATE INDEX message_acquisitions_state_updated
	ON message_acquisitions (state, updated_at, id);
CREATE INDEX assignments_acquisition_source
	ON assignments (repository_alias, source_message_id, acquisition_outcome, id);
CREATE INDEX assignments_pre_running_revoked
	ON assignments (pre_running_revoked_epoch, state, id)
	WHERE pre_running_revoked_epoch IS NOT NULL;

UPDATE assignments
SET acquisition_outcome = CASE
	WHEN admission_phase IN (2, 3) THEN 'acquired'
	ELSE 'offered'
END;
`

// schemaV0 is the exact pre-history schema. Keeping the source shape beside
// its migration makes the compatibility contract executable in tests instead
// of reconstructing an approximate legacy database.
const schemaV0 = `
CREATE TABLE IF NOT EXISTS assignments (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	repository_alias    TEXT    NOT NULL,
	runner_request_id   INTEGER NOT NULL,
	attempt             INTEGER NOT NULL DEFAULT 0,
	workflow_job_id     INTEGER NOT NULL,
	state               TEXT    NOT NULL,
	released            INTEGER NOT NULL DEFAULT 0,
	release_generation  INTEGER NOT NULL DEFAULT 0,
	ambiguous_reason    TEXT,
	ambiguous_at        TEXT,
	created_at          TEXT    NOT NULL,
	updated_at          TEXT    NOT NULL,
	UNIQUE (repository_alias, runner_request_id, attempt)
);

CREATE TABLE IF NOT EXISTS runner_slots (
	id                    INTEGER PRIMARY KEY AUTOINCREMENT,
	assignment_id         INTEGER NOT NULL UNIQUE REFERENCES assignments (id) ON DELETE CASCADE,
	opaque_name           TEXT    NOT NULL UNIQUE,
	capacity_slot_id      INTEGER NOT NULL UNIQUE,
	upstream_runner_id    INTEGER,
	bound_request_id      INTEGER,
	runner_container_id   TEXT,
	adapter_container_id  TEXT,
	broker_container_id   TEXT,
	policy_socket_digest  TEXT,
	created_at            TEXT    NOT NULL,
	updated_at            TEXT    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS runner_slots_upstream_runner_id_unique
	ON runner_slots (upstream_runner_id)
	WHERE upstream_runner_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS reservations (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	assignment_id     INTEGER NOT NULL UNIQUE REFERENCES assignments (id) ON DELETE CASCADE,
	capacity_slot_id  INTEGER NOT NULL UNIQUE,
	reserved_at       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS effects (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	assignment_id    INTEGER NOT NULL REFERENCES assignments (id) ON DELETE CASCADE,
	idempotency_key  TEXT    NOT NULL UNIQUE,
	kind             TEXT    NOT NULL,
	began_at         TEXT    NOT NULL,
	completed_at     TEXT,
	result_identity  TEXT,
	reason_code      TEXT
);

CREATE TABLE IF NOT EXISTS acquisition_state (
	id                          INTEGER PRIMARY KEY CHECK (id = 1),
	mode                        TEXT    NOT NULL,
	eligible_scale_sets         TEXT    NOT NULL,
	max_capacity                INTEGER NOT NULL,
	repository_policy_revision  INTEGER NOT NULL,
	repository_policies         TEXT    NOT NULL,
	acquisition_epoch           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS network_ledgers (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	ledger_key     TEXT NOT NULL UNIQUE,
	assignment_id  INTEGER REFERENCES assignments (id) ON DELETE SET NULL,
	state_digest   TEXT,
	updated_at     TEXT NOT NULL,
	retained_until TEXT
);

CREATE TABLE IF NOT EXISTS reconcile_cycles (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	cycle_id            TEXT    NOT NULL UNIQUE,
	started_at          TEXT    NOT NULL,
	completed_at        TEXT,
	assignment_count    INTEGER,
	oldest_age_seconds  INTEGER,
	note                TEXT
);
`

const seedAcquisitionState = `
INSERT OR IGNORE INTO acquisition_state
	(id, mode, eligible_scale_sets, max_capacity, repository_policy_revision, repository_policies, acquisition_epoch)
VALUES
	(1, ?, '[]', 0, 0, '[]', 0);
`

type migrationStepper struct {
	ctx         context.Context
	tx          *sql.Tx
	beforeWrite func(step int, label string) error
	step        int
}

func (m *migrationStepper) exec(label, statement string, args ...any) error {
	m.step++
	if m.beforeWrite != nil {
		if err := m.beforeWrite(m.step, label); err != nil {
			return err
		}
	}
	_, err := m.tx.ExecContext(m.ctx, statement, args...)
	return err
}

func (m *migrationStepper) execSchema(labelPrefix, schema string) error {
	statementNumber := 0
	for _, raw := range strings.Split(schema, ";") {
		statement := strings.TrimSpace(raw)
		if statement == "" {
			continue
		}
		statementNumber++
		if err := m.exec(
			fmt.Sprintf("%s-%d", labelPrefix, statementNumber),
			statement,
		); err != nil {
			return err
		}
	}
	return nil
}

func canonicalMigrationTimestamp(raw string) (string, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || parsed.IsZero() {
		return "", ErrOfflineMigration
	}
	return formatTime(parsed), nil
}

func normalizeOptionalMigrationTimestamp(
	steps *migrationStepper,
	table string,
	column string,
) error {
	var (
		started bool
		lastID  int64
	)
	for {
		var (
			id  int64
			raw string
		)
		query := fmt.Sprintf(
			`SELECT id, %q
			 FROM %q
			 WHERE %q IS NOT NULL
			 ORDER BY id
			 LIMIT 1`,
			column,
			table,
			column,
		)
		var args []any
		if started {
			query = fmt.Sprintf(
				`SELECT id, %q
				 FROM %q
				 WHERE %q IS NOT NULL AND id > ?
				 ORDER BY id
				 LIMIT 1`,
				column,
				table,
				column,
			)
			args = []any{lastID}
		}
		err := steps.tx.QueryRowContext(
			steps.ctx,
			query,
			args...,
		).Scan(&id, &raw)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if started && id <= lastID {
			return ErrOfflineMigration
		}
		started = true
		lastID = id
		canonical, err := canonicalMigrationTimestamp(raw)
		if err != nil {
			return err
		}
		if canonical == raw {
			continue
		}
		if err := steps.exec(
			fmt.Sprintf("normalize-%s-%s-%d", table, column, id),
			fmt.Sprintf(`UPDATE %q SET %q = ? WHERE id = ?`, table, column),
			canonical,
			id,
		); err != nil {
			return err
		}
	}
}

func normalizeTombstoneMigrationTimestamps(steps *migrationStepper) error {
	var (
		started bool
		lastID  int64
	)
	for {
		var (
			id          int64
			rawTerminal string
			rawRetain   string
		)
		query := `SELECT id, terminal_at, retain_until
			FROM history_tombstones
			ORDER BY id
			LIMIT 1`
		var args []any
		if started {
			query = `SELECT id, terminal_at, retain_until
				FROM history_tombstones
				WHERE id > ?
				ORDER BY id
				LIMIT 1`
			args = []any{lastID}
		}
		err := steps.tx.QueryRowContext(
			steps.ctx,
			query,
			args...,
		).Scan(&id, &rawTerminal, &rawRetain)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if started && id <= lastID {
			return ErrOfflineMigration
		}
		started = true
		lastID = id
		terminalAt, err := time.Parse(time.RFC3339Nano, rawTerminal)
		if err != nil || terminalAt.IsZero() {
			return ErrOfflineMigration
		}
		retainAt, err := time.Parse(time.RFC3339Nano, rawRetain)
		if err != nil || retainAt.IsZero() || retainAt.Before(terminalAt) {
			return ErrOfflineMigration
		}
		canonicalTerminal := formatTime(terminalAt)
		canonicalRetain := formatTime(retainAt)
		if canonicalTerminal == rawTerminal && canonicalRetain == rawRetain {
			continue
		}
		if err := steps.exec(
			fmt.Sprintf("normalize-history-tombstones-%d", id),
			`UPDATE history_tombstones
			 SET terminal_at = ?, retain_until = ? WHERE id = ?`,
			canonicalTerminal,
			canonicalRetain,
			id,
		); err != nil {
			return err
		}
	}
}

func normalizeHistoryMigrationTimestamps(steps *migrationStepper) error {
	for _, timestamp := range []struct {
		table  string
		column string
	}{
		{"assignments", "created_at"},
		{"assignments", "updated_at"},
		{"message_receipts", "persisted_at"},
		{"message_receipts", "retain_until"},
	} {
		if err := normalizeOptionalMigrationTimestamp(
			steps,
			timestamp.table,
			timestamp.column,
		); err != nil {
			return err
		}
	}
	if err := normalizeTombstoneMigrationTimestamps(steps); err != nil {
		return err
	}
	for _, column := range []string{"updated_at", "retained_until"} {
		if err := normalizeOptionalMigrationTimestamp(
			steps,
			"network_ledgers",
			column,
		); err != nil {
			return err
		}
	}
	return nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	var version, autoVacuum, tableCount int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("state: read schema version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("%w: database schema %d is newer than supported %d", ErrOfflineMigration, version, currentSchemaVersion)
	}
	if err := db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		return fmt.Errorf("state: read auto_vacuum: %w", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`,
	).Scan(&tableCount); err != nil {
		return fmt.Errorf("state: inspect schema: %w", err)
	}

	if version == currentSchemaVersion {
		if autoVacuum != sqliteAutoVacuumIncremental {
			return fmt.Errorf("%w: schema %d auto_vacuum=%d, want INCREMENTAL", ErrOfflineMigration, version, autoVacuum)
		}
		return nil
	}

	if tableCount == 0 {
		if version != 0 {
			return fmt.Errorf(
				"%w: empty database reports schema version %d",
				ErrOfflineMigration,
				version,
			)
		}
		if _, err := db.ExecContext(ctx, `PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
			return fmt.Errorf("state: enable incremental auto_vacuum: %w", err)
		}
		if err := db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
			return fmt.Errorf("state: verify auto_vacuum: %w", err)
		}
		if autoVacuum != sqliteAutoVacuumIncremental {
			return fmt.Errorf("%w: fresh database auto_vacuum=%d", ErrOfflineMigration, autoVacuum)
		}
		return bootstrapCurrent(ctx, db)
	}

	if autoVacuum != sqliteAutoVacuumIncremental {
		return fmt.Errorf("%w: existing schema auto_vacuum=%d", ErrOfflineMigration, autoVacuum)
	}
	switch version {
	case 0:
		return migrateV0ToCurrent(ctx, db)
	case 1:
		return migrateV1ToV2(ctx, db)
	case 2:
		return migrateV2ToV3(ctx, db)
	default:
		return fmt.Errorf("%w: unsupported schema version %d", ErrOfflineMigration, version)
	}
}

func bootstrapCurrent(ctx context.Context, db *sql.DB) error {
	return bootstrapCurrentWithHook(ctx, db, nil)
}

func bootstrapCurrentWithHook(
	ctx context.Context,
	db *sql.DB,
	beforeWrite func(step int, label string) error,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin bootstrap migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	steps := migrationStepper{ctx: ctx, tx: tx, beforeWrite: beforeWrite}
	if err := steps.execSchema("bootstrap-schema", schemaV1); err != nil {
		return fmt.Errorf("state: apply schema v1: %w", err)
	}
	if err := steps.execSchema("bootstrap-schema-v2", schemaV2); err != nil {
		return fmt.Errorf("state: apply schema v2: %w", err)
	}
	if err := steps.execSchema("bootstrap-schema-v3", schemaV3); err != nil {
		return fmt.Errorf("state: apply schema v3: %w", err)
	}
	if err := steps.exec("bootstrap-seed-acquisition", seedAcquisitionState, string(controller.AcquisitionDisabled)); err != nil {
		return fmt.Errorf("state: seed acquisition state: %w", err)
	}
	if err := steps.exec("bootstrap-set-user-version", fmt.Sprintf(`PRAGMA user_version=%d`, currentSchemaVersion)); err != nil {
		return fmt.Errorf("state: set schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit bootstrap migration: %w", err)
	}
	return nil
}

func migrateV0ToCurrent(ctx context.Context, db *sql.DB) error {
	return migrateV0ToCurrentWithHook(ctx, db, nil)
}

func migrateV0ToCurrentWithHook(
	ctx context.Context,
	db *sql.DB,
	beforeWrite func(step int, label string) error,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin v0 migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	rows, err := tx.QueryContext(ctx, `
		SELECT
			id, repository_alias, runner_request_id, attempt, workflow_job_id,
			state, released, release_generation, ambiguous_reason, ambiguous_at,
			created_at, updated_at
		FROM assignments ORDER BY id
	`)
	if err != nil {
		return fmt.Errorf("state: read legacy offers: %w", err)
	}
	type legacyAssignment struct {
		id                int64
		identity          OfferIdentity
		attempt           int64
		state             string
		released          int
		releaseGeneration int64
		ambiguousReason   sql.NullString
		ambiguousAt       sql.NullString
		createdAt         string
		updatedAt         string
	}
	var assignments []legacyAssignment
	for rows.Next() {
		var item legacyAssignment
		if err := rows.Scan(
			&item.id,
			&item.identity.RepositoryAlias,
			&item.identity.RunnerRequestID,
			&item.attempt,
			&item.identity.WorkflowJobID,
			&item.state,
			&item.released,
			&item.releaseGeneration,
			&item.ambiguousReason,
			&item.ambiguousAt,
			&item.createdAt,
			&item.updatedAt,
		); err != nil {
			_ = rows.Close()
			return fmt.Errorf("state: scan legacy offer: %w", err)
		}
		assignments = append(assignments, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("state: scan legacy offers: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("state: close legacy offer rows: %w", err)
	}

	steps := migrationStepper{ctx: ctx, tx: tx, beforeWrite: beforeWrite}
	for _, rename := range []struct {
		label     string
		statement string
	}{
		{"drop-v0-runner-slot-index", `DROP INDEX runner_slots_upstream_runner_id_unique`},
		{"rename-v0-runner-slots", `ALTER TABLE runner_slots RENAME TO migration_v0_runner_slots`},
		{"rename-v0-reservations", `ALTER TABLE reservations RENAME TO migration_v0_reservations`},
		{"rename-v0-effects", `ALTER TABLE effects RENAME TO migration_v0_effects`},
		{"rename-v0-network-ledgers", `ALTER TABLE network_ledgers RENAME TO migration_v0_network_ledgers`},
		{"rename-v0-assignments", `ALTER TABLE assignments RENAME TO migration_v0_assignments`},
	} {
		if err := steps.exec(rename.label, rename.statement); err != nil {
			return fmt.Errorf("state: rebuild v0 schema at %s: %w", rename.label, err)
		}
	}

	if err := steps.execSchema("create-v1-schema", schemaV1); err != nil {
		return fmt.Errorf("state: create v1 tables and indexes: %w", err)
	}
	if err := steps.execSchema("create-v2-schema", schemaV2); err != nil {
		return fmt.Errorf("state: create v2 tables: %w", err)
	}

	for _, item := range assignments {
		digest := CanonicalOfferDigest(item.identity)
		payloadDigest := CanonicalOfferPayloadDigest(item.identity)
		logicalBytes, err := offerLogicalBytesV1(item.identity)
		if err != nil {
			return fmt.Errorf("state: size legacy offer: %w", err)
		}
		if err := steps.exec(
			fmt.Sprintf("copy-v0-assignment-%d", item.id),
			`INSERT INTO assignments (
				id, repository_alias, runner_request_id, attempt, workflow_job_id,
				offer_digest, offer_payload_digest,
				job_id, repository_name, owner_name, job_workflow_ref,
				job_display_name, workflow_run_id, event_name, request_labels,
				queue_time, scale_set_assign_time, runner_assign_time, finish_time,
				acquire_job_url, history_logical_bytes,
				state, released, release_generation, ambiguous_reason, ambiguous_at,
				created_at, updated_at
			) VALUES (
				?, ?, ?, ?, ?, ?, ?,
				'', '', '', '', '', 0, '', '[]',
				'', '', '', '', '', ?,
				?, ?, ?, ?, ?, ?, ?
			)`,
			item.id,
			item.identity.RepositoryAlias,
			item.identity.RunnerRequestID,
			item.attempt,
			item.identity.WorkflowJobID,
			digest[:],
			payloadDigest[:],
			logicalBytes,
			item.state,
			item.released,
			item.releaseGeneration,
			item.ambiguousReason,
			item.ambiguousAt,
			item.createdAt,
			item.updatedAt,
		); err != nil {
			return fmt.Errorf("state: copy legacy offer %d: %w", item.id, err)
		}
	}

	for _, copyStep := range []struct {
		label     string
		statement string
	}{
		{
			"copy-v0-runner-slots",
			`INSERT INTO runner_slots (
				id, assignment_id, opaque_name, capacity_slot_id,
				upstream_runner_id, bound_request_id, runner_container_id,
				adapter_container_id, broker_container_id, policy_socket_digest,
				created_at, updated_at
			)
			SELECT
				id, assignment_id, opaque_name, capacity_slot_id,
				upstream_runner_id, bound_request_id, runner_container_id,
				adapter_container_id, broker_container_id, policy_socket_digest,
				created_at, updated_at
			FROM migration_v0_runner_slots`,
		},
		{
			"copy-v0-reservations",
			`INSERT INTO reservations (id, assignment_id, capacity_slot_id, reserved_at)
			SELECT id, assignment_id, capacity_slot_id, reserved_at
			FROM migration_v0_reservations`,
		},
		{
			"copy-v0-effects",
			`INSERT INTO effects (
				id, assignment_id, idempotency_key, kind, began_at,
				completed_at, result_identity, reason_code
			)
			SELECT
				id, assignment_id, idempotency_key, kind, began_at,
				completed_at, result_identity, reason_code
			FROM migration_v0_effects`,
		},
		{
			"copy-v0-network-ledgers",
			`INSERT INTO network_ledgers (
				id, ledger_key, assignment_id, state_digest,
				updated_at, retained_until, logical_bytes
			)
			SELECT
				id, ledger_key, assignment_id, state_digest,
				updated_at, retained_until, 1
			FROM migration_v0_network_ledgers`,
		},
	} {
		if err := steps.exec(copyStep.label, copyStep.statement); err != nil {
			return fmt.Errorf("state: %s: %w", copyStep.label, err)
		}
	}

	if err := normalizeHistoryMigrationTimestamps(&steps); err != nil {
		return fmt.Errorf("state: normalize v0 history timestamps: %w", err)
	}
	if err := steps.execSchema("create-v3-schema", schemaV3); err != nil {
		return fmt.Errorf("state: create v3 tables: %w", err)
	}

	for _, drop := range []struct {
		label     string
		statement string
	}{
		{"drop-v0-runner-slots", `DROP TABLE migration_v0_runner_slots`},
		{"drop-v0-reservations", `DROP TABLE migration_v0_reservations`},
		{"drop-v0-effects", `DROP TABLE migration_v0_effects`},
		{"drop-v0-network-ledgers", `DROP TABLE migration_v0_network_ledgers`},
		{"drop-v0-assignments", `DROP TABLE migration_v0_assignments`},
	} {
		if err := steps.exec(drop.label, drop.statement); err != nil {
			return fmt.Errorf("state: %s: %w", drop.label, err)
		}
	}

	if err := steps.exec("seed-acquisition-state", seedAcquisitionState, string(controller.AcquisitionDisabled)); err != nil {
		return fmt.Errorf("state: seed acquisition state: %w", err)
	}
	if err := steps.exec("set-user-version", fmt.Sprintf(`PRAGMA user_version=%d`, currentSchemaVersion)); err != nil {
		return fmt.Errorf("state: set schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit v0 migration: %w", err)
	}
	return nil
}

func migrateV1ToV2(ctx context.Context, db *sql.DB) error {
	return migrateV1ToV2WithHook(ctx, db, nil)
}

func migrateV1ToV2WithHook(
	ctx context.Context,
	db *sql.DB,
	beforeWrite func(step int, label string) error,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin v1 migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	steps := migrationStepper{ctx: ctx, tx: tx, beforeWrite: beforeWrite}
	if err := steps.execSchema("create-v2-schema", schemaV2); err != nil {
		return fmt.Errorf("state: create v2 tables: %w", err)
	}
	if err := normalizeHistoryMigrationTimestamps(&steps); err != nil {
		return fmt.Errorf("state: normalize v1 history timestamps: %w", err)
	}
	if err := steps.execSchema("create-v3-schema", schemaV3); err != nil {
		return fmt.Errorf("state: create v3 tables: %w", err)
	}
	if err := steps.exec(
		"set-v2-user-version",
		fmt.Sprintf(`PRAGMA user_version=%d`, currentSchemaVersion),
	); err != nil {
		return fmt.Errorf("state: set v2 schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit v1 migration: %w", err)
	}
	return nil
}

func migrateV2ToV3(ctx context.Context, db *sql.DB) error {
	return migrateV2ToV3WithHook(ctx, db, nil)
}

func migrateV2ToV3WithHook(
	ctx context.Context,
	db *sql.DB,
	beforeWrite func(step int, label string) error,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin v2 migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	steps := migrationStepper{ctx: ctx, tx: tx, beforeWrite: beforeWrite}
	if err := steps.execSchema("create-v3-schema", schemaV3); err != nil {
		return fmt.Errorf("state: create v3 tables: %w", err)
	}
	if err := steps.exec(
		"set-v3-user-version",
		fmt.Sprintf(`PRAGMA user_version=%d`, currentSchemaVersion),
	); err != nil {
		return fmt.Errorf("state: set v3 schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit v2 migration: %w", err)
	}
	return nil
}
