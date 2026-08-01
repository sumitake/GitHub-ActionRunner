//go:build darwin || linux

package hostruntime

import (
	"testing"
	"time"
)

func TestInspectLifecycleOwnershipDistinguishesActiveAndTerminalState(
	t *testing.T,
) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	store := openTestLifecycleStore(t)
	journal := goldenUpgradeJournal(t, OperationPhasePrepared)
	journalDocument, _, err := MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	if err := store.CreateCanonical(
		LifecycleJournals,
		lifecycleJournalName(binding.OperationID),
		journalDocument,
		maxLifecycleJournalBytes,
	); err != nil {
		t.Fatalf("CreateCanonical(journal) error = %v", err)
	}
	reservation := goldenStorageReservation(
		t,
		binding,
		time.Date(2026, 7, 29, 17, 0, 0, 0, time.UTC),
	)
	reservationDocument, _, err := MarshalStorageReservation(reservation)
	if err != nil {
		t.Fatalf("MarshalStorageReservation() error = %v", err)
	}
	if err := store.CreateCanonical(
		LifecycleReservations,
		lifecycleReservationName(binding.OperationID),
		reservationDocument,
		maxLifecycleReservationBytes,
	); err != nil {
		t.Fatalf("CreateCanonical(reservation) error = %v", err)
	}

	snapshot, err := InspectLifecycleOwnership(store)
	if err != nil ||
		!snapshot.Owned() ||
		len(snapshot.NonterminalOperations) != 1 ||
		len(snapshot.ActiveReservations) != 1 ||
		snapshot.NonterminalOperations[0] != binding.OperationID ||
		snapshot.ActiveReservations[0] != binding.OperationID {
		t.Fatalf("InspectLifecycleOwnership() = %#v, error = %v", snapshot, err)
	}

	terminal := journal
	terminal.Phase = OperationPhaseComplete
	terminal.UpdatedAt = terminal.UpdatedAt.Add(time.Second)
	terminalDocument, _, err := MarshalOperationJournal(terminal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal(terminal) error = %v", err)
	}
	if err := store.ReplaceCanonical(
		LifecycleJournals,
		lifecycleJournalName(binding.OperationID),
		journalDocument,
		terminalDocument,
		maxLifecycleJournalBytes,
	); err != nil {
		t.Fatalf("ReplaceCanonical(journal) error = %v", err)
	}
	proof := "7e7dec46d2a2d338fde78f06d6d9ac8165cc544fed1f3f1443589905af48dde6"
	committed := reservation
	committed.State = ReservationStateCommitted
	committed.CommittedTargetProofDigest = &proof
	committed.UpdatedAt = committed.UpdatedAt.Add(time.Second)
	committedDocument, _, err := MarshalStorageReservation(committed)
	if err != nil {
		t.Fatalf("MarshalStorageReservation(committed) error = %v", err)
	}
	if err := store.ReplaceCanonical(
		LifecycleReservations,
		lifecycleReservationName(binding.OperationID),
		reservationDocument,
		committedDocument,
		maxLifecycleReservationBytes,
	); err != nil {
		t.Fatalf("ReplaceCanonical(reservation) error = %v", err)
	}

	snapshot, err = InspectLifecycleOwnership(store)
	if err != nil || snapshot.Owned() {
		t.Fatalf("terminal snapshot = %#v, error = %v", snapshot, err)
	}
}

func TestInspectLifecycleOwnershipRejectsUnknownInventoryEntry(t *testing.T) {
	t.Parallel()

	store := openTestLifecycleStore(t)
	if err := store.CreateCanonical(
		LifecycleJournals,
		"unknown.json",
		[]byte(`{"unknown":true}`),
		1024,
	); err != nil {
		t.Fatalf("CreateCanonical() error = %v", err)
	}
	if _, err := InspectLifecycleOwnership(store); err == nil {
		t.Fatal("InspectLifecycleOwnership() error = nil")
	}
}
