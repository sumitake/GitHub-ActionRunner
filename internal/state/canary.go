package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/sumitake/portable-ghar/internal/canary"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func readCanaryEvidence(ctx context.Context, q queryRower) (canary.Record, error) {
	var document string
	if err := q.QueryRowContext(ctx, `SELECT document FROM canary_evidence WHERE id = 1`).Scan(&document); err != nil {
		return canary.Record{}, err
	}
	return canary.ParseRecord([]byte(document))
}

// CanaryEvidence reads the journal without issuing live probes or changing
// acquisition authority. Read-only store handles support this method.
func (s *SQLiteStore) CanaryEvidence(ctx context.Context) (canary.Record, error) {
	return readCanaryEvidence(ctx, s.db)
}

// InitCanaryEvidence reserves one record's maximum size before acquisition.
// Restarting the same report preserves observations. A fresh report replaces
// only this bounded proof journal; it does not consume or grant authority.
func (s *SQLiteStore) InitCanaryEvidence(ctx context.Context, seed canary.Record) error {
	expected := canary.Record{Version: 1, ReportDigest: seed.ReportDigest, BindingDigest: seed.BindingDigest, FleetGeneration: seed.FleetGeneration}
	document, err := json.Marshal(seed)
	if err != nil || !reflect.DeepEqual(seed, expected) {
		return canary.ErrEvidence
	}
	if _, err := canary.ParseRecord(document); err != nil {
		return err
	}
	if s.historyLimits == nil {
		return ErrHistoryBudget
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := readCanaryEvidence(ctx, tx)
	if err == nil {
		if current.ReportDigest != seed.ReportDigest {
			if err := writeCanaryEvidence(ctx, tx, seed); err != nil {
				return err
			}
			return tx.Commit()
		}
		if current.BindingDigest != seed.BindingDigest || current.FleetGeneration != seed.FleetGeneration {
			return canary.ErrEvidence
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := ensureReceiptHeadroom(ctx, tx, *s.historyLimits, canary.MaxRecordBytes); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO canary_evidence (id,document) VALUES (1,?)`, string(document)); err != nil {
		return err
	}
	return tx.Commit()
}

func canaryAssignmentDigest(key controller.AssignmentKey) string {
	document, _ := json.Marshal(key)
	digest := sha256.Sum256(append([]byte("portable-ghar.canary-assignment.v1\x00"), document...))
	return hex.EncodeToString(digest[:])
}

func writeCanaryEvidence(ctx context.Context, tx *sql.Tx, record canary.Record) error {
	document, err := json.Marshal(record)
	if err != nil {
		return canary.ErrEvidence
	}
	if _, err := canary.ParseRecord(document); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE canary_evidence SET document = ? WHERE id = 1`, string(document))
	return err
}

func (s *SQLiteStore) updateCanaryEvidence(ctx context.Context, reportDigest string, key controller.AssignmentKey, update func(*sql.Tx, *canary.Record) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := updateCanaryEvidenceTx(ctx, tx, reportDigest, key, update); err != nil {
		return err
	}
	return tx.Commit()
}

func updateCanaryEvidenceTx(ctx context.Context, tx *sql.Tx, reportDigest string, key controller.AssignmentKey, update func(*sql.Tx, *canary.Record) error) error {
	record, err := readCanaryEvidence(ctx, tx)
	if err != nil {
		return err
	}
	if record.ReportDigest != reportDigest {
		return canary.ErrEvidence
	}
	if record.AssignmentDigest != "" && record.AssignmentDigest != canaryAssignmentDigest(key) {
		// Observation of another assignment invalidates proof without consuming or
		// changing any acquisition authority. Keep the first assignment's evidence.
		record.Invalid = true
	} else if err := update(tx, &record); err != nil {
		return err
	}
	return writeCanaryEvidence(ctx, tx, record)
}

// BeginCanaryJIT records an attempt before calling the governed JIT authorizer.
// A failed/ambiguous attempt therefore cannot disappear from a later proof.
func (s *SQLiteStore) BeginCanaryJIT(ctx context.Context, reportDigest string, key controller.AssignmentKey, compatibility githubscale.ScaleSetCompatibilityReport) error {
	return s.updateCanaryEvidence(ctx, reportDigest, key, func(tx *sql.Tx, r *canary.Record) error {
		var outcome, checkpoint, batchState string
		var revoked sql.NullInt64
		var result []byte
		var runID int64
		if err := tx.QueryRowContext(ctx, `SELECT a.acquisition_outcome,a.state,a.pre_running_revoked_epoch,m.state,m.result_digest,a.workflow_run_id
   FROM assignments a JOIN message_acquisitions m ON a.repository_alias=m.repository_alias AND a.source_message_id=m.message_id
   WHERE a.repository_alias=? AND a.runner_request_id=? AND a.attempt=?`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(&outcome, &checkpoint, &revoked, &batchState, &result, &runID); err != nil {
			return err
		}
		if outcome != string(AcquisitionOutcomeAcquired) || checkpoint != string(controller.StateReleaseArmed) || revoked.Valid || batchState != string(AcquisitionBatchCompleted) || runID <= 0 {
			return canary.ErrEvidence
		}
		r.AssignmentDigest = canaryAssignmentDigest(key)
		r.AcquisitionDigest = hex.EncodeToString(result)
		r.WorkflowRunID = uint64(runID)
		if r.JITCount < 2 {
			r.JITCount++
		}
		if r.JITCount != 1 {
			r.Invalid = true
		}
		r.DisableUpdate = compatibility.DisableUpdate
		r.SingleNameLabel = compatibility.SingleNameLabel
		return nil
	})
}

func (s *SQLiteStore) BindCanaryJITPermit(ctx context.Context, reportDigest string, key controller.AssignmentKey, binding controller.AcquisitionPermitBinding) error {
	digest, err := controller.AcquisitionPermitBindingDigest(binding)
	if err != nil {
		return err
	}
	return s.updateCanaryEvidence(ctx, reportDigest, key, func(_ *sql.Tx, r *canary.Record) error {
		if r.AssignmentDigest == "" || r.JITCount != 1 || r.PermitDigest != "" || binding.FenceGeneration != r.FleetGeneration || binding.RepositoryAlias != key.RepositoryAlias || binding.OperationKind != "jit" || binding.PolicyMode != controller.AcquisitionCanaryOnly {
			r.Invalid = true
			return nil
		}
		r.PermitDigest = hex.EncodeToString(digest[:])
		r.PolicyDigest = binding.PolicyDigest
		r.CanaryCapacityOne = true
		return nil
	})
}

// CanaryWorkflowRecorded is a read-only observation check used to avoid
// rereading a frame already made durable. Other assignments still run normally.
func (s *SQLiteStore) CanaryWorkflowRecorded(ctx context.Context, reportDigest string, key controller.AssignmentKey) (bool, error) {
	r, err := s.CanaryEvidence(ctx)
	if err != nil {
		return false, err
	}
	if r.ReportDigest != reportDigest {
		return false, canary.ErrEvidence
	}
	return r.AssignmentDigest == canaryAssignmentDigest(key) && r.Workflow.Version == 1, nil
}

// RecordCanaryWorkflow captures the fixed socket frame under the lifecycle's
// same-key lock while the final job step is still alive. No host file is mounted.
func (s *SQLiteStore) RecordCanaryWorkflow(ctx context.Context, reportDigest string, key controller.AssignmentKey, workflow canary.Workflow) error {
	return s.updateCanaryEvidence(ctx, reportDigest, key, func(tx *sql.Tx, r *canary.Record) error {
		id, checkpoint, err := lookupAssignmentTx(ctx, tx, key)
		if err != nil {
			return err
		}
		if checkpoint != controller.StateJobRunning {
			return canary.ErrEvidence
		}
		var binding string
		if err := tx.QueryRowContext(ctx, `SELECT idempotency_key FROM effects WHERE assignment_id=? AND kind=? AND completed_at IS NOT NULL`, id, LifecycleEffectListenerRelease).Scan(&binding); err != nil {
			return err
		}
		if r.PermitDigest == "" || binding != r.PermitDigest {
			r.Invalid = true
		}
		r.ListenerReleased = true
		document, err := json.Marshal(workflow)
		if err != nil {
			return canary.ErrEvidence
		}
		parsed, err := canary.ParseWorkflow(document)
		if err != nil || parsed.ReportDigest != r.ReportDigest || parsed.WorkflowRunID != r.WorkflowRunID {
			r.Invalid = true
			return nil
		}
		if r.Workflow.Version != 0 && !reflect.DeepEqual(r.Workflow, parsed) {
			r.Invalid = true
			return nil
		}
		r.Workflow = parsed
		return nil
	})
}

// CompleteCanaryJob records only the identity-checked, durable upstream result.
// An absent workflow frame invalidates proof without preventing ordinary cleanup.
func (s *SQLiteStore) CompleteCanaryJob(ctx context.Context, reportDigest string, key controller.AssignmentKey, result string) error {
	return s.updateCanaryEvidence(ctx, reportDigest, key, func(tx *sql.Tx, r *canary.Record) error {
		return completeCanaryJobTx(ctx, tx, key, r, result)
	})
}

func applyCanaryCompletionTx(ctx context.Context, tx *sql.Tx, key controller.AssignmentKey, completion CanaryCompletion) error {
	return updateCanaryEvidenceTx(ctx, tx, completion.ReportDigest, key, func(tx *sql.Tx, r *canary.Record) error {
		return completeCanaryJobTx(ctx, tx, key, r, completion.Result)
	})
}

func completeCanaryJobTx(ctx context.Context, tx *sql.Tx, key controller.AssignmentKey, r *canary.Record, result string) error {
	_, checkpoint, err := lookupAssignmentTx(ctx, tx, key)
	if err != nil {
		return err
	}
	if checkpoint != controller.StateJobFinished {
		return canary.ErrEvidence
	}
	switch result {
	case "success", "failure", "canceled", "skipped":
	default:
		result = "unknown"
	}
	if r.JobCount != 0 {
		if r.JobResult != result {
			r.Invalid = true
		}
		return nil
	}
	r.JobCount = 1
	r.JobResult = result
	if r.Workflow.Version != 1 {
		r.Invalid = true
	}
	return nil
}

// MarkCanaryCleanup is called only after the lifecycle's upstream and managed
// runtime absence proofs succeed. Durable capacity/slot retirement is separate.
func (s *SQLiteStore) MarkCanaryCleanup(ctx context.Context, reportDigest string, key controller.AssignmentKey) error {
	return s.updateCanaryEvidence(ctx, reportDigest, key, func(tx *sql.Tx, r *canary.Record) error {
		_, checkpoint, err := lookupAssignmentTx(ctx, tx, key)
		if err != nil {
			return err
		}
		if checkpoint != controller.StateJobFinished {
			return canary.ErrEvidence
		}
		r.UpstreamAbsent = true
		r.RuntimeAbsent = true
		return nil
	})
}

// finalizeCanaryEvidence runs inside the terminal compaction transaction after
// its complete absence/ack preconditions. Evidence survives cascade deletion.
func finalizeCanaryEvidence(ctx context.Context, tx *sql.Tx, key controller.AssignmentKey) error {
	record, err := readCanaryEvidence(ctx, tx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.AssignmentDigest != canaryAssignmentDigest(key) {
		return nil
	}
	record.Finalized = record.UpstreamAbsent && record.RuntimeAbsent
	return writeCanaryEvidence(ctx, tx, record)
}

// CanarySealSnapshot reads one consistent durable snapshot. Sealing requires
// disabled acquisition and no live assignment, capacity, slot, or admission
// projection. Retained terminal history and independent network ledgers remain
// ordinary history; no authority is consumed or written by this operation.
func (s *SQLiteStore) CanarySealSnapshot(ctx context.Context) (canary.Record, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return canary.Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	policy, err := readAcquisitionPolicy(ctx, tx)
	if err != nil {
		return canary.Record{}, err
	}
	if policy.Mode != controller.AcquisitionDisabled {
		return canary.Record{}, canary.ErrEvidence
	}
	var live int64
	if err := tx.QueryRowContext(ctx, `SELECT
  (SELECT COUNT(*) FROM assignments WHERE state != ?) +
  (SELECT COUNT(*) FROM runner_slots) +
  (SELECT COUNT(*) FROM reservations) +
  (SELECT COUNT(*) FROM assignments WHERE admission_phase IS NOT NULL OR admission_slot_id IS NOT NULL)
 `, string(controller.StateDestroyed)).Scan(&live); err != nil {
		return canary.Record{}, err
	}
	if live != 0 {
		return canary.Record{}, canary.ErrEvidence
	}
	return readCanaryEvidence(ctx, tx)
}
