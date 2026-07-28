package networkjail

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sumitake/portable-ghar/internal/state"
)

func TestSQLitePermitStoreCanonicalCASAndDelete(t *testing.T) {
	controllerStore, err := state.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := controllerStore.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	store, err := newSQLitePermitStore(controllerStore)
	if err != nil {
		t.Fatalf("newSQLitePermitStore: %v", err)
	}
	ledger := permitLedger{
		Version:             permitLedgerVersion,
		SlotID:              19,
		BootID:              testBootID(1),
		Revision:            1,
		ActiveJobGeneration: 3,
		LastMonotonicNanos:  100,
		Job: permitClassLedger{
			TokenUnits:        2 * nanosPerSecond,
			LastRefillNanos:   100,
			ReservedHighWater: 2,
			IssuedHighWater:   1,
			ReservedSequence:  2,
			IssuedSequence:    1,
		},
		DoH: permitClassLedger{
			TokenUnits:      nanosPerSecond,
			LastRefillNanos: 100,
		},
	}
	if err := store.compareAndSwap(context.Background(), 19, 0, ledger); err != nil {
		t.Fatalf("initial compareAndSwap: %v", err)
	}
	loaded, found, err := store.load(context.Background(), 19)
	if err != nil || !found {
		t.Fatalf("load = found:%v err:%v", found, err)
	}
	if loaded != ledger {
		t.Fatalf("loaded ledger = %#v, want %#v", loaded, ledger)
	}

	var encoded string
	var logicalBytes uint64
	var retainedUntil sql.NullString
	if err := controllerStore.DB().QueryRow(`
		SELECT state_digest, logical_bytes, retained_until
		FROM network_ledgers
		WHERE ledger_key = ?
	`, permitLedgerKey(19)).Scan(&encoded, &logicalBytes, &retainedUntil); err != nil {
		t.Fatalf("read persisted ledger: %v", err)
	}
	if logicalBytes != uint64(len(encoded)) {
		t.Fatalf("logical_bytes = %d, want exact encoded length %d", logicalBytes, len(encoded))
	}
	if retainedUntil.Valid {
		t.Fatalf("retained_until = %q, want NULL until monotonic GC authorizes deletion", retainedUntil.String)
	}
	if encoded != encodePermitLedger(ledger) {
		t.Fatal("persisted ledger is not the canonical encoding")
	}

	stale := ledger
	stale.Revision = 2
	if err := store.compareAndSwap(context.Background(), 19, 0, stale); !errors.Is(err, ErrPermitLedgerConflict) {
		t.Fatalf("stale compareAndSwap = %v, want ErrPermitLedgerConflict", err)
	}
	if err := store.delete(context.Background(), 19, 2); !errors.Is(err, ErrPermitLedgerConflict) {
		t.Fatalf("stale delete = %v, want ErrPermitLedgerConflict", err)
	}
	if err := store.delete(context.Background(), 19, 1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, err := store.load(context.Background(), 19); err != nil || found {
		t.Fatalf("load after delete = found:%v err:%v, want absent", found, err)
	}
}

func TestSQLitePermitStoreRejectsCorruptState(t *testing.T) {
	controllerStore, err := state.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = controllerStore.Close() })
	store, err := newSQLitePermitStore(controllerStore)
	if err != nil {
		t.Fatalf("newSQLitePermitStore: %v", err)
	}
	if _, err := controllerStore.DB().Exec(`
		INSERT INTO network_ledgers (
			ledger_key, state_digest, updated_at, logical_bytes
		) VALUES (?, 'not-canonical', '2026-07-28T00:00:00.000000000Z', 13)
	`, permitLedgerKey(23)); err != nil {
		t.Fatalf("insert corrupt ledger: %v", err)
	}
	if _, _, err := store.load(context.Background(), 23); err == nil {
		t.Fatal("load corrupt ledger = nil error")
	}
}

func TestSQLitePermitAuthorityCrashRecoveryBurnsBlock(t *testing.T) {
	controllerStore, err := state.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = controllerStore.Close() })
	sqliteStore, err := newSQLitePermitStore(controllerStore)
	if err != nil {
		t.Fatalf("newSQLitePermitStore: %v", err)
	}
	fixture := newPermitFixture(t, 3)
	fixture.store = nil
	fixture.authority, err = newPermitAuthority(
		fixture.authority.graph,
		fixture.clock,
		sqliteStore,
		acceptingPermitGuard{},
		fixture.references,
		fixture.validator,
		3,
	)
	if err != nil {
		t.Fatalf("newPermitAuthority: %v", err)
	}
	fixture.activate(7)
	if _, err := fixture.consume(7, DialClassJob, 1); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	fixture.clock.advance(nanosPerSecond)
	restarted, err := newPermitAuthority(
		fixture.authority.graph,
		fixture.clock,
		sqliteStore,
		acceptingPermitGuard{},
		fixture.references,
		fixture.validator,
		3,
	)
	if err != nil {
		t.Fatalf("restart newPermitAuthority: %v", err)
	}
	fixture.authority = restarted
	permit, err := fixture.consume(7, DialClassJob, 4)
	if err != nil {
		t.Fatalf("post-crash Consume: %v", err)
	}
	if permit.number != 4 {
		t.Fatalf("post-crash permit = %d, want 4", permit.number)
	}
}
