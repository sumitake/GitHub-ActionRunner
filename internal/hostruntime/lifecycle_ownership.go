package hostruntime

import (
	"errors"
	"sort"
	"strings"
)

var ErrLifecycleOwned = errors.New(
	"hostruntime: lifecycle operation owns target",
)

type LifecycleOwnershipSnapshot struct {
	NonterminalOperations []string
	ActiveReservations    []string
}

func (snapshot LifecycleOwnershipSnapshot) Owned() bool {
	return len(snapshot.NonterminalOperations) != 0 ||
		len(snapshot.ActiveReservations) != 0
}

// InspectLifecycleOwnership fail-closes over the complete pinned journal and
// reservation inventories. Callers must hold the stable lifecycle lease while
// using the returned point-in-time snapshot.
func InspectLifecycleOwnership(
	store *LifecycleStore,
) (LifecycleOwnershipSnapshot, error) {
	if store == nil {
		return LifecycleOwnershipSnapshot{}, ErrLifecycleIntegrity
	}
	journalNames, err := store.ListCanonicalNames(LifecycleJournals)
	if err != nil {
		return LifecycleOwnershipSnapshot{}, err
	}
	reservationNames, err := store.ListCanonicalNames(LifecycleReservations)
	if err != nil {
		return LifecycleOwnershipSnapshot{}, err
	}
	snapshot := LifecycleOwnershipSnapshot{
		NonterminalOperations: make([]string, 0),
		ActiveReservations:    make([]string, 0),
	}
	for _, name := range journalNames {
		operationID, ok := lifecycleDocumentOperationID(
			name,
			".journal.json",
		)
		if !ok {
			return LifecycleOwnershipSnapshot{}, ErrLifecycleIntegrity
		}
		document, err := store.ReadCanonical(
			LifecycleJournals,
			name,
			maxLifecycleJournalBytes,
		)
		if err != nil {
			return LifecycleOwnershipSnapshot{}, err
		}
		journal, _, err := ParseOperationJournal(
			document,
			maxLifecycleJournalBytes,
		)
		if err != nil || journal.OperationID != operationID {
			return LifecycleOwnershipSnapshot{}, ErrLifecycleIntegrity
		}
		if !terminalOperationJournal(journal) {
			snapshot.NonterminalOperations = append(
				snapshot.NonterminalOperations,
				operationID,
			)
		}
	}
	for _, name := range reservationNames {
		operationID, ok := lifecycleDocumentOperationID(
			name,
			".reservation.json",
		)
		if !ok {
			return LifecycleOwnershipSnapshot{}, ErrLifecycleIntegrity
		}
		document, err := store.ReadCanonical(
			LifecycleReservations,
			name,
			maxLifecycleReservationBytes,
		)
		if err != nil {
			return LifecycleOwnershipSnapshot{}, err
		}
		reservation, _, err := ParseStorageReservation(
			document,
			maxLifecycleReservationBytes,
		)
		if err != nil || reservation.OperationID != operationID {
			return LifecycleOwnershipSnapshot{}, ErrLifecycleIntegrity
		}
		if reservation.State == ReservationStateActive {
			snapshot.ActiveReservations = append(
				snapshot.ActiveReservations,
				operationID,
			)
		}
	}
	sort.Strings(snapshot.NonterminalOperations)
	sort.Strings(snapshot.ActiveReservations)
	if duplicateSorted(snapshot.NonterminalOperations) ||
		duplicateSorted(snapshot.ActiveReservations) {
		return LifecycleOwnershipSnapshot{}, ErrLifecycleIntegrity
	}
	return snapshot, nil
}

func terminalOperationJournal(journal OperationJournal) bool {
	if journal.CompensationPath == nil {
		return journal.Phase == OperationPhaseComplete
	}
	sequence, ok := compensationPhaseSequences[*journal.CompensationPath]
	return ok && len(sequence) != 0 &&
		journal.Phase == sequence[len(sequence)-1]
}

func lifecycleDocumentOperationID(
	name string,
	suffix string,
) (string, bool) {
	if !strings.HasSuffix(name, suffix) {
		return "", false
	}
	operationID := strings.TrimSuffix(name, suffix)
	return operationID, isLowerHex64(operationID)
}

func duplicateSorted(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}
