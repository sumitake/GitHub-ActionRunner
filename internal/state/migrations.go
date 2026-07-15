package state

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sumitake/portable-ghar/internal/controller"
)

// schema is the store's fixed table set. It is applied once, inside a
// single transaction, by migrate.
//
// Design notes that matter for the crash-safety/idempotency contract this
// package promises:
//
//   - assignments is keyed by (repository_alias, runner_request_id,
//     attempt) -- the natural uniqueness boundary for an acquisition offer
//     (see controller.AssignmentKey's doc). released and
//     release_generation together record whether, and how many times,
//     this assignment has crossed the StateListenerReleased boundary;
//     release_generation increments exactly once per crossing so a
//     reconciler can detect (rather than blindly repeat) a release.
//   - runner_slots is 1:1 with assignments (one slot per assignment for
//     Task 2's scope) and carries every identity RunnerSlot names:
//     opaque_name and capacity_slot_id are written once, at Reserve time,
//     and never change; the container identities and policy/socket digest
//     are written as each checkpoint's effect completes.
//     upstream_runner_id is unique among rows where it is set (a partial
//     unique index, since most rows have it NULL until BindRunner runs),
//     matching "an offer is never itself a binding."
//   - reservations exists as the durable proof that the CAPACITY_RESERVED
//     step took the BEGIN IMMEDIATE write-intent lock before writing;
//     capacity_slot_id is UNIQUE here too so two assignments can never
//     share a reservation.
//   - effects is the idempotency journal: idempotency_key is UNIQUE, so a
//     replayed BeginEffect for the same key can never create a second row
//     (see BeginEffect's INSERT OR IGNORE ... changes()-based detection in
//     sqlite.go).
//   - acquisition_state is a singleton (id fixed to 1 by a CHECK
//     constraint) seeded once at migration time so AcquisitionPolicy never
//     has to special-case a missing row.
//   - network_ledgers intentionally has NO cascading foreign key: its
//     assignment_id reference uses ON DELETE SET NULL, so deleting (or
//     never having) an assignment row never deletes a ledger row. The
//     ledger is the controller's single-writer token/clock state and must
//     outlive the assignment for at least the retention window T --
//     retained_until records that window; GC of ledger rows past
//     retained_until is a later task's job, not this schema's.
//   - reconcile_cycles exists to satisfy the plan's exact table-set
//     requirement for later tasks (the reconciler's CycleReceipt, which
//     Task 2 deliberately does not define -- see internal/controller's
//     package doc). No Store method in Task 2 writes to it.
const schema = `
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

// seedAcquisitionState is the default singleton row: acquisition disabled,
// no eligible scale sets, zero capacity, epoch zero. CompareAndSetAcquisition
// callers pass expectedEpoch=0 to make their first transition.
const seedAcquisitionState = `
INSERT OR IGNORE INTO acquisition_state
	(id, mode, eligible_scale_sets, max_capacity, repository_policy_revision, repository_policies, acquisition_epoch)
VALUES
	(1, ?, '[]', 0, 0, '[]', 0);
`

// migrate applies schema and seeds the acquisition_state singleton, inside
// one transaction, so a crash mid-migration never leaves a partially
// created schema.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op if already committed

	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("state: apply schema: %w", err)
	}
	if _, err := tx.ExecContext(ctx, seedAcquisitionState, string(controller.AcquisitionDisabled)); err != nil {
		return fmt.Errorf("state: seed acquisition_state: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit migration: %w", err)
	}
	return nil
}
