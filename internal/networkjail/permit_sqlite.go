package networkjail

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/state"
)

const (
	permitLedgerEncodingPrefix = "v1:"
	permitLedgerBinaryBytes    = 165
	permitLedgerTimeLayout     = "2006-01-02T15:04:05.000000000Z"
)

type sqlitePermitStore struct {
	controller *state.SQLiteStore
}

func newSQLitePermitStore(
	controller *state.SQLiteStore,
) (*sqlitePermitStore, error) {
	if controller == nil || controller.DB() == nil {
		return nil, ErrPermitAuthorityUnavailable
	}
	return &sqlitePermitStore{controller: controller}, nil
}

// NewSQLitePermitAuthority constructs the production durability boundary over
// the controller's already-open canonical SQLite store. It does not open a
// second database or create a second writer.
func NewSQLitePermitAuthority(
	graph DecisionGraph,
	clock MonotonicClock,
	controller *state.SQLiteStore,
	peers PermitPeerValidator,
	references LedgerReferenceGuard,
	rebase EmptyConntrackValidator,
	blockSize uint64,
) (*PermitAuthority, error) {
	store, err := newSQLitePermitStore(controller)
	if err != nil {
		return nil, err
	}
	return newPermitAuthority(
		graph,
		clock,
		store,
		peers,
		references,
		rebase,
		blockSize,
	)
}

func (store *sqlitePermitStore) load(
	ctx context.Context,
	slot CapacitySlotID,
) (permitLedger, bool, error) {
	var encoded string
	err := store.controller.DB().QueryRowContext(
		ctx,
		`SELECT state_digest FROM network_ledgers WHERE ledger_key = ?`,
		permitLedgerKey(slot),
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return permitLedger{}, false, nil
	}
	if err != nil {
		return permitLedger{}, false, ErrPermitAuthorityUnavailable
	}
	ledger, err := decodePermitLedger(encoded)
	if err != nil || ledger.SlotID != slot {
		return permitLedger{}, false, ErrPermitAuthorityUnavailable
	}
	return ledger, true, nil
}

func (store *sqlitePermitStore) compareAndSwap(
	ctx context.Context,
	slot CapacitySlotID,
	expectedRevision uint64,
	next permitLedger,
) error {
	if next.SlotID != slot || next.Revision == 0 {
		return ErrPermitAuthorityUnavailable
	}
	if err := validatePermitLedger(next, slot); err != nil {
		return err
	}
	encoded := encodePermitLedger(next)
	if encoded == "" {
		return ErrPermitAuthorityUnavailable
	}
	updatedAt := time.Now().UTC().Format(permitLedgerTimeLayout)

	transaction, err := store.controller.DB().BeginTx(ctx, nil)
	if err != nil {
		return ErrPermitAuthorityUnavailable
	}
	defer func() { _ = transaction.Rollback() }()

	var currentEncoded string
	err = transaction.QueryRowContext(
		ctx,
		`SELECT state_digest FROM network_ledgers WHERE ledger_key = ?`,
		permitLedgerKey(slot),
	).Scan(&currentEncoded)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expectedRevision != 0 {
			return ErrPermitLedgerConflict
		}
		_, err = transaction.ExecContext(ctx, `
			INSERT INTO network_ledgers (
				ledger_key, assignment_id, state_digest, updated_at,
				retained_until, logical_bytes
			) VALUES (?, NULL, ?, ?, NULL, ?)
		`, permitLedgerKey(slot), encoded, updatedAt, len(encoded))
		if err != nil {
			return ErrPermitLedgerConflict
		}
	case err != nil:
		return ErrPermitAuthorityUnavailable
	default:
		current, decodeErr := decodePermitLedger(currentEncoded)
		if decodeErr != nil || current.SlotID != slot {
			return ErrPermitAuthorityUnavailable
		}
		if current.Revision != expectedRevision {
			return ErrPermitLedgerConflict
		}
		result, updateErr := transaction.ExecContext(ctx, `
			UPDATE network_ledgers
			SET state_digest = ?, updated_at = ?,
			    retained_until = NULL, logical_bytes = ?
			WHERE ledger_key = ? AND state_digest = ?
		`, encoded, updatedAt, len(encoded), permitLedgerKey(slot), currentEncoded)
		if updateErr != nil {
			return ErrPermitAuthorityUnavailable
		}
		affected, affectedErr := result.RowsAffected()
		if affectedErr != nil || affected != 1 {
			return ErrPermitLedgerConflict
		}
	}
	if err := transaction.Commit(); err != nil {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func (store *sqlitePermitStore) delete(
	ctx context.Context,
	slot CapacitySlotID,
	expectedRevision uint64,
) error {
	transaction, err := store.controller.DB().BeginTx(ctx, nil)
	if err != nil {
		return ErrPermitAuthorityUnavailable
	}
	defer func() { _ = transaction.Rollback() }()

	var encoded string
	err = transaction.QueryRowContext(
		ctx,
		`SELECT state_digest FROM network_ledgers WHERE ledger_key = ?`,
		permitLedgerKey(slot),
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPermitLedgerConflict
	}
	if err != nil {
		return ErrPermitAuthorityUnavailable
	}
	current, err := decodePermitLedger(encoded)
	if err != nil || current.SlotID != slot {
		return ErrPermitAuthorityUnavailable
	}
	if current.Revision != expectedRevision {
		return ErrPermitLedgerConflict
	}
	result, err := transaction.ExecContext(
		ctx,
		`DELETE FROM network_ledgers WHERE ledger_key = ? AND state_digest = ?`,
		permitLedgerKey(slot),
		encoded,
	)
	if err != nil {
		return ErrPermitAuthorityUnavailable
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return ErrPermitLedgerConflict
	}
	if err := transaction.Commit(); err != nil {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func permitLedgerKey(slot CapacitySlotID) string {
	return "capacity-slot-v1:" + strconv.FormatUint(uint64(slot), 10)
}

func encodePermitLedger(ledger permitLedger) string {
	raw := make([]byte, permitLedgerBinaryBytes)
	raw[0] = ledger.Version
	binary.BigEndian.PutUint32(raw[1:5], uint32(ledger.SlotID))
	copy(raw[5:21], ledger.BootID[:])
	copy(raw[21:37], ledger.LastRebaseBootID[:])
	binary.BigEndian.PutUint64(raw[37:45], ledger.Revision)
	binary.BigEndian.PutUint64(raw[45:53], uint64(ledger.ActiveJobGeneration))
	binary.BigEndian.PutUint64(raw[53:61], ledger.LastMonotonicNanos)
	binary.BigEndian.PutUint64(raw[61:69], ledger.RetainedUntilNanos)
	putPermitClass(raw[69:117], ledger.Job)
	putPermitClass(raw[117:165], ledger.DoH)
	return permitLedgerEncodingPrefix + hex.EncodeToString(raw)
}

func decodePermitLedger(encoded string) (permitLedger, error) {
	if !strings.HasPrefix(encoded, permitLedgerEncodingPrefix) ||
		encoded != strings.ToLower(encoded) ||
		len(encoded) != len(permitLedgerEncodingPrefix)+2*permitLedgerBinaryBytes {
		return permitLedger{}, ErrPermitAuthorityUnavailable
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(encoded, permitLedgerEncodingPrefix))
	if err != nil || len(raw) != permitLedgerBinaryBytes {
		return permitLedger{}, ErrPermitAuthorityUnavailable
	}
	var ledger permitLedger
	ledger.Version = raw[0]
	ledger.SlotID = CapacitySlotID(binary.BigEndian.Uint32(raw[1:5]))
	copy(ledger.BootID[:], raw[5:21])
	copy(ledger.LastRebaseBootID[:], raw[21:37])
	ledger.Revision = binary.BigEndian.Uint64(raw[37:45])
	ledger.ActiveJobGeneration = JobGeneration(binary.BigEndian.Uint64(raw[45:53]))
	ledger.LastMonotonicNanos = binary.BigEndian.Uint64(raw[53:61])
	ledger.RetainedUntilNanos = binary.BigEndian.Uint64(raw[61:69])
	ledger.Job = getPermitClass(raw[69:117])
	ledger.DoH = getPermitClass(raw[117:165])
	if err := validatePermitLedger(ledger, ledger.SlotID); err != nil ||
		encodePermitLedger(ledger) != encoded {
		return permitLedger{}, ErrPermitAuthorityUnavailable
	}
	return ledger, nil
}

func putPermitClass(target []byte, class permitClassLedger) {
	binary.BigEndian.PutUint64(target[0:8], class.TokenUnits)
	binary.BigEndian.PutUint64(target[8:16], class.LastRefillNanos)
	binary.BigEndian.PutUint64(target[16:24], class.ReservedHighWater)
	binary.BigEndian.PutUint64(target[24:32], class.IssuedHighWater)
	binary.BigEndian.PutUint64(target[32:40], uint64(class.ReservedSequence))
	binary.BigEndian.PutUint64(target[40:48], uint64(class.IssuedSequence))
}

func getPermitClass(source []byte) permitClassLedger {
	return permitClassLedger{
		TokenUnits:        binary.BigEndian.Uint64(source[0:8]),
		LastRefillNanos:   binary.BigEndian.Uint64(source[8:16]),
		ReservedHighWater: binary.BigEndian.Uint64(source[16:24]),
		IssuedHighWater:   binary.BigEndian.Uint64(source[24:32]),
		ReservedSequence:  PermitSequence(binary.BigEndian.Uint64(source[32:40])),
		IssuedSequence:    PermitSequence(binary.BigEndian.Uint64(source[40:48])),
	}
}

var _ permitStore = (*sqlitePermitStore)(nil)
