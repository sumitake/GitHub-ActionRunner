package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

const (
	acquisitionRequestDigestDomain = "portable-ghar.acquisition-request.v1"
	acquisitionResultDigestDomain  = "portable-ghar.acquisition-result.v1"
	maxAcquisitionAssignments      = 1024
)

// AcquisitionBatchState is the closed durable state of one message-scoped
// acquisition effect.
type AcquisitionBatchState string

const (
	AcquisitionBatchBegun        AcquisitionBatchState = "begun"
	AcquisitionBatchNotAttempted AcquisitionBatchState = "not_attempted"
	AcquisitionBatchCompleted    AcquisitionBatchState = "completed"
	AcquisitionBatchAmbiguous    AcquisitionBatchState = "ambiguous"
)

// AcquisitionOutcome is the closed assignment-side projection of acquisition.
type AcquisitionOutcome string

const (
	AcquisitionOutcomeOffered   AcquisitionOutcome = "offered"
	AcquisitionOutcomeRequested AcquisitionOutcome = "requested"
	AcquisitionOutcomeAcquired  AcquisitionOutcome = "acquired"
	AcquisitionOutcomeRejected  AcquisitionOutcome = "rejected"
)

// AcquisitionBatchRecord is the bounded, secret-free durable journal view.
// CallAuthorized is true only for the transaction that newly crosses from no
// effect/not_attempted to begun. A replay of an already-begun batch never
// authorizes a second network call.
type AcquisitionBatchRecord struct {
	RepositoryAlias string
	MessageID       int
	RequestDigest   [sha256.Size]byte
	ResultDigest    [sha256.Size]byte
	State           AcquisitionBatchState
	RequestedCount  int
	AcquiredCount   int
	BegunAt         time.Time
	UpdatedAt       time.Time
	Inserted        bool
	CallAuthorized  bool
}

// AcquisitionAssignmentRecord is the bounded acquisition/revocation view of
// one assignment.
type AcquisitionAssignmentRecord struct {
	Key          controller.AssignmentKey
	Outcome      AcquisitionOutcome
	RevokedEpoch uint64
}

func canonicalAcquisitionKeys(
	repositoryAlias string,
	messageID int,
	keys []controller.AssignmentKey,
	allowEmpty bool,
) ([]controller.AssignmentKey, [sha256.Size]byte, error) {
	if repositoryAlias == "" || messageID <= 0 ||
		(!allowEmpty && len(keys) == 0) ||
		len(keys) > maxAcquisitionAssignments {
		return nil, [sha256.Size]byte{}, ErrIdentityConflict
	}
	out := append([]controller.AssignmentKey(nil), keys...)
	for _, key := range out {
		if key.RepositoryAlias != repositoryAlias ||
			key.RunnerRequestID <= 0 ||
			key.Attempt != 0 {
			return nil, [sha256.Size]byte{}, ErrIdentityConflict
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RepositoryAlias != out[j].RepositoryAlias {
			return out[i].RepositoryAlias < out[j].RepositoryAlias
		}
		if out[i].RunnerRequestID != out[j].RunnerRequestID {
			return out[i].RunnerRequestID < out[j].RunnerRequestID
		}
		return out[i].Attempt < out[j].Attempt
	})
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, [sha256.Size]byte{}, ErrIdentityConflict
		}
	}

	h := sha256.New()
	_, _ = h.Write([]byte(acquisitionRequestDigestDomain))
	writeLengthPrefixed(h, []byte(repositoryAlias))
	writeInt64(h, int64(messageID))
	writeUint64(h, uint64(len(out)))
	for _, key := range out {
		writeLengthPrefixed(h, []byte(key.RepositoryAlias))
		writeInt64(h, key.RunnerRequestID)
		writeUint64(h, uint64(key.Attempt))
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return out, digest, nil
}

func canonicalAcquisitionResultDigest(
	requestDigest [sha256.Size]byte,
	acquired []controller.AssignmentKey,
) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(acquisitionResultDigestDomain))
	_, _ = h.Write(requestDigest[:])
	writeUint64(h, uint64(len(acquired)))
	for _, key := range acquired {
		writeLengthPrefixed(h, []byte(key.RepositoryAlias))
		writeInt64(h, key.RunnerRequestID)
		writeUint64(h, uint64(key.Attempt))
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func acquisitionBatchState(value string) (AcquisitionBatchState, error) {
	switch AcquisitionBatchState(value) {
	case AcquisitionBatchBegun,
		AcquisitionBatchNotAttempted,
		AcquisitionBatchCompleted,
		AcquisitionBatchAmbiguous:
		return AcquisitionBatchState(value), nil
	default:
		return "", ErrIdentityConflict
	}
}

func acquisitionOutcome(value string) (AcquisitionOutcome, error) {
	switch AcquisitionOutcome(value) {
	case AcquisitionOutcomeOffered,
		AcquisitionOutcomeRequested,
		AcquisitionOutcomeAcquired,
		AcquisitionOutcomeRejected:
		return AcquisitionOutcome(value), nil
	default:
		return "", ErrIdentityConflict
	}
}

func readAcquisitionBatch(
	ctx context.Context,
	q queryRower,
	repositoryAlias string,
	messageID int,
) (AcquisitionBatchRecord, error) {
	var (
		requestDigest []byte
		resultDigest  []byte
		stateText     string
		requested     int64
		acquired      sql.NullInt64
		begunText     string
		updatedText   string
	)
	if err := q.QueryRowContext(ctx, `
		SELECT request_digest, result_digest, state, requested_count,
			acquired_count, begun_at, updated_at
		FROM message_acquisitions
		WHERE repository_alias = ? AND message_id = ?
	`, repositoryAlias, messageID).Scan(
		&requestDigest,
		&resultDigest,
		&stateText,
		&requested,
		&acquired,
		&begunText,
		&updatedText,
	); err != nil {
		return AcquisitionBatchRecord{}, err
	}
	if len(requestDigest) != sha256.Size ||
		(len(resultDigest) != 0 && len(resultDigest) != sha256.Size) ||
		requested <= 0 ||
		requested > maxAcquisitionAssignments ||
		acquired.Int64 < 0 ||
		acquired.Int64 > requested {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	state, err := acquisitionBatchState(stateText)
	if err != nil {
		return AcquisitionBatchRecord{}, err
	}
	begunAt, err := time.Parse(time.RFC3339Nano, begunText)
	if err != nil || begunAt.IsZero() {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, updatedText)
	if err != nil || updatedAt.IsZero() || updatedAt.Before(begunAt) {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	record := AcquisitionBatchRecord{
		RepositoryAlias: repositoryAlias,
		MessageID:       messageID,
		State:           state,
		RequestedCount:  int(requested),
		BegunAt:         begunAt,
		UpdatedAt:       updatedAt,
	}
	copy(record.RequestDigest[:], requestDigest)
	if len(resultDigest) == sha256.Size {
		copy(record.ResultDigest[:], resultDigest)
	}
	if acquired.Valid {
		record.AcquiredCount = int(acquired.Int64)
	}
	return record, nil
}

func validateAcquisitionAssignments(
	ctx context.Context,
	tx *sql.Tx,
	repositoryAlias string,
	messageID int,
	keys []controller.AssignmentKey,
	want AcquisitionOutcome,
) error {
	for _, key := range keys {
		var (
			stateText string
			outcome   string
			source    sql.NullInt64
			revokedAt sql.NullInt64
		)
		if err := tx.QueryRowContext(ctx, `
			SELECT state, acquisition_outcome, source_message_id,
				pre_running_revoked_epoch
			FROM assignments
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
		`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(
			&stateText,
			&outcome,
			&source,
			&revokedAt,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrIdentityConflict
			}
			return err
		}
		storedOutcome, err := acquisitionOutcome(outcome)
		if err != nil {
			return err
		}
		if controller.State(stateText) != controller.StateReceived ||
			storedOutcome != want ||
			!source.Valid ||
			source.Int64 != int64(messageID) ||
			revokedAt.Valid {
			return ErrIdentityConflict
		}
	}
	return nil
}

func updateAcquisitionKeys(
	ctx context.Context,
	tx *sql.Tx,
	keys []controller.AssignmentKey,
	from AcquisitionOutcome,
	to AcquisitionOutcome,
	updatedAt time.Time,
) error {
	for _, key := range keys {
		result, err := tx.ExecContext(ctx, `
			UPDATE assignments
			SET acquisition_outcome = ?, updated_at = ?
			WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
				AND acquisition_outcome = ?
		`, string(to), formatTime(updatedAt),
			key.RepositoryAlias, key.RunnerRequestID, key.Attempt, string(from),
		)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return ErrIdentityConflict
		}
	}
	return nil
}

// BeginAcquisition implements Store.
func (s *SQLiteStore) BeginAcquisition(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	keys []controller.AssignmentKey,
	begunAt time.Time,
) (AcquisitionBatchRecord, error) {
	if begunAt.IsZero() {
		return AcquisitionBatchRecord{}, ErrReplayEvidence
	}
	canonicalKeys, requestDigest, err := canonicalAcquisitionKeys(
		repositoryAlias,
		messageID,
		keys,
		false,
	)
	if err != nil {
		return AcquisitionBatchRecord{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: begin acquisition: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := readAcquisitionBatch(ctx, tx, repositoryAlias, messageID)
	switch {
	case err == nil:
		if existing.RequestDigest != requestDigest {
			return AcquisitionBatchRecord{}, ErrIdentityConflict
		}
		switch existing.State {
		case AcquisitionBatchNotAttempted:
			if begunAt.Before(existing.UpdatedAt) {
				return AcquisitionBatchRecord{}, ErrIdentityConflict
			}
			if err := validateAcquisitionAssignments(
				ctx, tx, repositoryAlias, messageID, canonicalKeys, AcquisitionOutcomeOffered,
			); err != nil {
				return AcquisitionBatchRecord{}, err
			}
			if err := updateAcquisitionKeys(
				ctx, tx, canonicalKeys, AcquisitionOutcomeOffered,
				AcquisitionOutcomeRequested, begunAt,
			); err != nil {
				return AcquisitionBatchRecord{}, err
			}
			result, err := tx.ExecContext(ctx, `
				UPDATE message_acquisitions
				SET state = 'begun', updated_at = ?
				WHERE repository_alias = ? AND message_id = ?
					AND state = 'not_attempted'
			`, formatTime(begunAt), repositoryAlias, messageID)
			if err != nil {
				return AcquisitionBatchRecord{}, fmt.Errorf("state: reopen acquisition: %w", err)
			}
			affected, err := result.RowsAffected()
			if err != nil || affected != 1 {
				return AcquisitionBatchRecord{}, ErrIdentityConflict
			}
			if err := tx.Commit(); err != nil {
				return AcquisitionBatchRecord{}, fmt.Errorf("state: reopen acquisition: commit: %w", err)
			}
			existing.State = AcquisitionBatchBegun
			existing.UpdatedAt = begunAt.UTC()
			existing.CallAuthorized = true
			return existing, nil
		case AcquisitionBatchBegun,
			AcquisitionBatchCompleted,
			AcquisitionBatchAmbiguous:
			return existing, nil
		default:
			return AcquisitionBatchRecord{}, ErrIdentityConflict
		}
	case !errors.Is(err, sql.ErrNoRows):
		return AcquisitionBatchRecord{}, fmt.Errorf("state: begin acquisition: read: %w", err)
	}

	if s.historyLimits == nil {
		return AcquisitionBatchRecord{}, ErrHistoryBudget
	}
	var receiptCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM message_receipts
		WHERE repository_alias = ? AND message_id = ?
	`, repositoryAlias, messageID).Scan(&receiptCount); err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: begin acquisition: receipt: %w", err)
	}
	if receiptCount != 1 {
		return AcquisitionBatchRecord{}, ErrReplayEvidence
	}
	if err := validateAcquisitionAssignments(
		ctx, tx, repositoryAlias, messageID, canonicalKeys, AcquisitionOutcomeOffered,
	); err != nil {
		return AcquisitionBatchRecord{}, err
	}
	logicalBytes, err := acquisitionLogicalBytes(repositoryAlias)
	if err != nil {
		return AcquisitionBatchRecord{}, err
	}
	if err := ensureReceiptHeadroom(ctx, tx, *s.historyLimits, logicalBytes); err != nil {
		return AcquisitionBatchRecord{}, err
	}
	if err := updateAcquisitionKeys(
		ctx, tx, canonicalKeys, AcquisitionOutcomeOffered,
		AcquisitionOutcomeRequested, begunAt,
	); err != nil {
		return AcquisitionBatchRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO message_acquisitions (
			repository_alias, message_id, request_digest, state,
			requested_count, begun_at, updated_at, logical_bytes
		) VALUES (?, ?, ?, 'begun', ?, ?, ?, ?)
	`, repositoryAlias, messageID, requestDigest[:], len(canonicalKeys),
		formatTime(begunAt), formatTime(begunAt), logicalBytes,
	); err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: begin acquisition: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: begin acquisition: commit: %w", err)
	}
	return AcquisitionBatchRecord{
		RepositoryAlias: repositoryAlias,
		MessageID:       messageID,
		RequestDigest:   requestDigest,
		State:           AcquisitionBatchBegun,
		RequestedCount:  len(canonicalKeys),
		BegunAt:         begunAt.UTC(),
		UpdatedAt:       begunAt.UTC(),
		Inserted:        true,
		CallAuthorized:  true,
	}, nil
}

// AbortAcquisitionBeforeCall implements Store.
func (s *SQLiteStore) AbortAcquisitionBeforeCall(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	abortedAt time.Time,
) (AcquisitionBatchRecord, error) {
	if repositoryAlias == "" || messageID <= 0 || abortedAt.IsZero() {
		return AcquisitionBatchRecord{}, ErrReplayEvidence
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: abort acquisition: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	record, err := readAcquisitionBatch(ctx, tx, repositoryAlias, messageID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AcquisitionBatchRecord{}, ErrReplayEvidence
		}
		return AcquisitionBatchRecord{}, err
	}
	if record.State == AcquisitionBatchNotAttempted {
		return record, nil
	}
	if record.State != AcquisitionBatchBegun {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	if abortedAt.Before(record.UpdatedAt) {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE assignments
		SET acquisition_outcome = 'offered', updated_at = ?
		WHERE repository_alias = ? AND source_message_id = ?
			AND acquisition_outcome = 'requested'
	`, formatTime(abortedAt), repositoryAlias, messageID)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: abort acquisition: assignments: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != int64(record.RequestedCount) {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE message_acquisitions
		SET state = 'not_attempted', updated_at = ?
		WHERE repository_alias = ? AND message_id = ? AND state = 'begun'
	`, formatTime(abortedAt), repositoryAlias, messageID)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: abort acquisition: journal: %w", err)
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	if err := tx.Commit(); err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: abort acquisition: commit: %w", err)
	}
	record.State = AcquisitionBatchNotAttempted
	record.UpdatedAt = abortedAt.UTC()
	return record, nil
}

func requestedAcquisitionKeys(
	ctx context.Context,
	tx *sql.Tx,
	repositoryAlias string,
	messageID int,
) ([]controller.AssignmentKey, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT repository_alias, runner_request_id, attempt
		FROM assignments
		WHERE repository_alias = ? AND source_message_id = ?
			AND acquisition_outcome = 'requested'
		ORDER BY repository_alias, runner_request_id, attempt
	`, repositoryAlias, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []controller.AssignmentKey
	for rows.Next() {
		var key controller.AssignmentKey
		var attempt int64
		if err := rows.Scan(&key.RepositoryAlias, &key.RunnerRequestID, &attempt); err != nil {
			return nil, err
		}
		if attempt < 0 || attempt > int64(^uint32(0)) {
			return nil, ErrIdentityConflict
		}
		key.Attempt = uint32(attempt)
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// CompleteAcquisition implements Store.
func (s *SQLiteStore) CompleteAcquisition(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	acquired []controller.AssignmentKey,
	completedAt time.Time,
) (AcquisitionBatchRecord, error) {
	if completedAt.IsZero() {
		return AcquisitionBatchRecord{}, ErrReplayEvidence
	}
	canonicalAcquired, _, err := canonicalAcquisitionKeys(
		repositoryAlias,
		messageID,
		acquired,
		true,
	)
	if err != nil {
		return AcquisitionBatchRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: complete acquisition: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	record, err := readAcquisitionBatch(ctx, tx, repositoryAlias, messageID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AcquisitionBatchRecord{}, ErrReplayEvidence
		}
		return AcquisitionBatchRecord{}, err
	}
	resultDigest := canonicalAcquisitionResultDigest(record.RequestDigest, canonicalAcquired)
	if record.State == AcquisitionBatchCompleted {
		if record.ResultDigest != resultDigest {
			return AcquisitionBatchRecord{}, ErrIdentityConflict
		}
		return record, nil
	}
	if record.State != AcquisitionBatchBegun {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	if completedAt.Before(record.UpdatedAt) {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	requested, err := requestedAcquisitionKeys(ctx, tx, repositoryAlias, messageID)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: complete acquisition: requested: %w", err)
	}
	if len(requested) != record.RequestedCount {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	requestedSet := make(map[controller.AssignmentKey]struct{}, len(requested))
	for _, key := range requested {
		requestedSet[key] = struct{}{}
	}
	for _, key := range canonicalAcquired {
		if _, ok := requestedSet[key]; !ok {
			return AcquisitionBatchRecord{}, ErrIdentityConflict
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE assignments
		SET acquisition_outcome = 'rejected', updated_at = ?
		WHERE repository_alias = ? AND source_message_id = ?
			AND acquisition_outcome = 'requested'
	`, formatTime(completedAt), repositoryAlias, messageID)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: complete acquisition: reject set: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != int64(record.RequestedCount) {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	if err := updateAcquisitionKeys(
		ctx, tx, canonicalAcquired, AcquisitionOutcomeRejected,
		AcquisitionOutcomeAcquired, completedAt,
	); err != nil {
		return AcquisitionBatchRecord{}, err
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE message_acquisitions
		SET state = 'completed', result_digest = ?, acquired_count = ?, updated_at = ?
		WHERE repository_alias = ? AND message_id = ? AND state = 'begun'
	`, resultDigest[:], len(canonicalAcquired), formatTime(completedAt),
		repositoryAlias, messageID)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: complete acquisition: journal: %w", err)
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	if err := tx.Commit(); err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: complete acquisition: commit: %w", err)
	}
	record.State = AcquisitionBatchCompleted
	record.ResultDigest = resultDigest
	record.AcquiredCount = len(canonicalAcquired)
	record.UpdatedAt = completedAt.UTC()
	return record, nil
}

// MarkAcquisitionAmbiguous implements Store.
func (s *SQLiteStore) MarkAcquisitionAmbiguous(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	observedAt time.Time,
) (AcquisitionBatchRecord, error) {
	if repositoryAlias == "" || messageID <= 0 || observedAt.IsZero() {
		return AcquisitionBatchRecord{}, ErrReplayEvidence
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: mark acquisition ambiguous: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	record, err := readAcquisitionBatch(ctx, tx, repositoryAlias, messageID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AcquisitionBatchRecord{}, ErrReplayEvidence
		}
		return AcquisitionBatchRecord{}, err
	}
	if record.State == AcquisitionBatchAmbiguous {
		return record, nil
	}
	if record.State != AcquisitionBatchBegun {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	if observedAt.Before(record.UpdatedAt) {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE message_acquisitions
		SET state = 'ambiguous', updated_at = ?
		WHERE repository_alias = ? AND message_id = ? AND state = 'begun'
	`, formatTime(observedAt), repositoryAlias, messageID)
	if err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: mark acquisition ambiguous: update: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return AcquisitionBatchRecord{}, ErrIdentityConflict
	}
	if err := tx.Commit(); err != nil {
		return AcquisitionBatchRecord{}, fmt.Errorf("state: mark acquisition ambiguous: commit: %w", err)
	}
	record.State = AcquisitionBatchAmbiguous
	record.UpdatedAt = observedAt.UTC()
	return record, nil
}

// PromoteBegunAcquisitions implements Store.
func (s *SQLiteStore) PromoteBegunAcquisitions(
	ctx context.Context,
	observedAt time.Time,
) (int, error) {
	if observedAt.IsZero() {
		return 0, ErrReplayEvidence
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("state: promote begun acquisitions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var future int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM message_acquisitions
		WHERE state = 'begun' AND begun_at > ?
	`, formatTime(observedAt)).Scan(&future); err != nil {
		return 0, fmt.Errorf("state: promote begun acquisitions: time check: %w", err)
	}
	if future != 0 {
		return 0, ErrIdentityConflict
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE message_acquisitions
		SET state = 'ambiguous', updated_at = ?
		WHERE state = 'begun'
	`, formatTime(observedAt))
	if err != nil {
		return 0, fmt.Errorf("state: promote begun acquisitions: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("state: promote begun acquisitions: rows: %w", err)
	}
	if affected < 0 || affected > int64(^uint(0)>>1) {
		return 0, ErrIdentityConflict
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("state: promote begun acquisitions: commit: %w", err)
	}
	return int(affected), nil
}

// AcquisitionBatch implements Store.
func (s *SQLiteStore) AcquisitionBatch(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
) (AcquisitionBatchRecord, error) {
	if repositoryAlias == "" || messageID <= 0 {
		return AcquisitionBatchRecord{}, ErrReplayEvidence
	}
	record, err := readAcquisitionBatch(ctx, s.db, repositoryAlias, messageID)
	if errors.Is(err, sql.ErrNoRows) {
		return AcquisitionBatchRecord{}, ErrReplayEvidence
	}
	return record, err
}

// AcquisitionAssignment implements Store.
func (s *SQLiteStore) AcquisitionAssignment(
	ctx context.Context,
	key controller.AssignmentKey,
) (AcquisitionAssignmentRecord, error) {
	if key.RepositoryAlias == "" || key.RunnerRequestID <= 0 {
		return AcquisitionAssignmentRecord{}, ErrReplayEvidence
	}
	var outcomeText string
	var revoked sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT acquisition_outcome, pre_running_revoked_epoch
		FROM assignments
		WHERE repository_alias = ? AND runner_request_id = ? AND attempt = ?
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(
		&outcomeText,
		&revoked,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AcquisitionAssignmentRecord{}, ErrReplayEvidence
		}
		return AcquisitionAssignmentRecord{}, err
	}
	outcome, err := acquisitionOutcome(outcomeText)
	if err != nil {
		return AcquisitionAssignmentRecord{}, err
	}
	if revoked.Int64 < 0 {
		return AcquisitionAssignmentRecord{}, ErrIdentityConflict
	}
	return AcquisitionAssignmentRecord{
		Key:          key,
		Outcome:      outcome,
		RevokedEpoch: uint64(revoked.Int64),
	}, nil
}

// MarkPreRunningRevoked implements Store.
func (s *SQLiteStore) MarkPreRunningRevoked(
	ctx context.Context,
	newEpoch uint64,
	observedAt time.Time,
) ([]controller.AssignmentKey, error) {
	if newEpoch == 0 || newEpoch > uint64(^uint64(0)>>1) || observedAt.IsZero() {
		return nil, ErrIdentityConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("state: mark pre-running revoked: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var newer int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM assignments
		WHERE pre_running_revoked_epoch > ?
	`, int64(newEpoch)).Scan(&newer); err != nil {
		return nil, fmt.Errorf("state: mark pre-running revoked: monotonic check: %w", err)
	}
	if newer != 0 {
		return nil, ErrIdentityConflict
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT repository_alias, runner_request_id, attempt
		FROM assignments
		WHERE state NOT IN (?, ?, ?)
			AND (
				pre_running_revoked_epoch IS NULL OR
				pre_running_revoked_epoch < ?
			)
		ORDER BY repository_alias, runner_request_id, attempt
	`, string(controller.StateJobRunning), string(controller.StateJobFinished),
		string(controller.StateDestroyed), int64(newEpoch),
	)
	if err != nil {
		return nil, fmt.Errorf("state: mark pre-running revoked: read: %w", err)
	}
	var keys []controller.AssignmentKey
	for rows.Next() {
		var key controller.AssignmentKey
		var attempt int64
		if err := rows.Scan(&key.RepositoryAlias, &key.RunnerRequestID, &attempt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if attempt < 0 || attempt > int64(^uint32(0)) {
			_ = rows.Close()
			return nil, ErrIdentityConflict
		}
		key.Attempt = uint32(attempt)
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(keys) != 0 {
		result, err := tx.ExecContext(ctx, `
			UPDATE assignments
			SET pre_running_revoked_epoch = ?, updated_at = ?
			WHERE state NOT IN (?, ?, ?)
				AND (
					pre_running_revoked_epoch IS NULL OR
					pre_running_revoked_epoch < ?
				)
		`, int64(newEpoch), formatTime(observedAt),
			string(controller.StateJobRunning), string(controller.StateJobFinished),
			string(controller.StateDestroyed), int64(newEpoch),
		)
		if err != nil {
			return nil, fmt.Errorf("state: mark pre-running revoked: update: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != int64(len(keys)) {
			return nil, ErrIdentityConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("state: mark pre-running revoked: commit: %w", err)
	}
	return keys, nil
}

// OperationalSummary implements Store.
func (s *SQLiteStore) OperationalSummary(
	ctx context.Context,
	observedAt time.Time,
) (OperationalSummary, error) {
	if observedAt.IsZero() {
		return OperationalSummary{}, ErrReplayEvidence
	}
	var (
		assigned       int64
		running        int64
		oldestLive     sql.NullString
		unassigned     int64
		latestTerminal sql.NullString
	)
	if err := s.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE
				WHEN assignments.state != ?
					AND runner_slots.upstream_runner_id IS NOT NULL
				THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE
				WHEN assignments.state = ? THEN 1 ELSE 0 END), 0),
			MIN(CASE
				WHEN assignments.state != ? THEN assignments.created_at
				ELSE NULL END),
			COALESCE(SUM(CASE
				WHEN assignments.state = ?
					AND runner_slots.upstream_runner_id IS NULL
				THEN 1 ELSE 0 END), 0),
			(
				SELECT MAX(terminal_at)
				FROM (
					SELECT updated_at AS terminal_at
					FROM assignments
					WHERE state = ?
					UNION ALL
					SELECT terminal_at
					FROM history_tombstones
				)
			)
		FROM assignments
		LEFT JOIN runner_slots ON runner_slots.assignment_id = assignments.id
	`,
		string(controller.StateDestroyed),
		string(controller.StateJobRunning),
		string(controller.StateDestroyed),
		string(controller.StateListenerReleased),
		string(controller.StateDestroyed),
	).Scan(
		&assigned,
		&running,
		&oldestLive,
		&unassigned,
		&latestTerminal,
	); err != nil {
		return OperationalSummary{}, fmt.Errorf("state: operational summary: %w", err)
	}
	if assigned < 0 || running < 0 || unassigned < 0 {
		return OperationalSummary{}, ErrIdentityConflict
	}
	summary := OperationalSummary{
		AssignedJobs:                uint64(assigned),
		RunningJobs:                 uint64(running),
		UnassignedReleasedListeners: uint64(unassigned),
	}
	if oldestLive.Valid {
		oldest, err := time.Parse(time.RFC3339Nano, oldestLive.String)
		if err != nil || oldest.IsZero() || observedAt.Before(oldest) {
			return OperationalSummary{}, ErrIdentityConflict
		}
		summary.OldestLiveAssignmentAge = observedAt.Sub(oldest)
	}
	if latestTerminal.Valid {
		latest, err := time.Parse(time.RFC3339Nano, latestTerminal.String)
		if err != nil || latest.IsZero() || latest.After(observedAt) {
			return OperationalSummary{}, ErrIdentityConflict
		}
		summary.LatestTerminalAt = latest
	}
	return summary, nil
}
