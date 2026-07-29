package hostruntime

import "errors"

const lifecycleLockName = "lifecycle.lock"

var (
	ErrLifecycleIntegrity     = errors.New("hostruntime: lifecycle integrity failure")
	ErrLifecycleStateAbsent   = errors.New("hostruntime: lifecycle state absent")
	ErrLifecycleStateExists   = errors.New("hostruntime: lifecycle state exists")
	ErrLifecycleStateConflict = errors.New("hostruntime: lifecycle state conflict")
	ErrLifecycleStoreClosed   = errors.New("hostruntime: lifecycle store closed")
)

type LifecycleDirectory string

const (
	LifecycleJournals     LifecycleDirectory = "journals"
	LifecycleReceipts     LifecycleDirectory = "receipts"
	LifecycleReservations LifecycleDirectory = "reservations"
)

// LifecycleStoreLayout binds the stable lifecycle lock and each evidence
// class to the exact private-overlay roots. The paths are intentionally
// separate: journals, receipts, and reservations must never silently fall
// back to children of StateRoot.
type LifecycleStoreLayout struct {
	LockRoot        string
	JournalRoot     string
	ReceiptRoot     string
	ReservationRoot string
}

func LifecycleStoreLayoutFromPrivateOverlay(
	overlay PrivateOverlay,
) (LifecycleStoreLayout, error) {
	if err := validatePrivateOverlay(overlay); err != nil {
		return LifecycleStoreLayout{}, ErrLifecycleIntegrity
	}
	layout := LifecycleStoreLayout{
		LockRoot:        overlay.Paths.StateRoot,
		JournalRoot:     overlay.Paths.JournalRoot,
		ReceiptRoot:     overlay.Paths.ReceiptRoot,
		ReservationRoot: overlay.Paths.ReservationRoot,
	}
	if !validLifecycleStoreLayout(layout) {
		return LifecycleStoreLayout{}, ErrLifecycleIntegrity
	}
	return layout, nil
}

func validLifecycleDirectory(directory LifecycleDirectory) bool {
	return directory == LifecycleJournals ||
		directory == LifecycleReceipts ||
		directory == LifecycleReservations
}

func validLifecycleStoreLayout(layout LifecycleStoreLayout) bool {
	paths := []string{
		layout.LockRoot,
		layout.JournalRoot,
		layout.ReceiptRoot,
		layout.ReservationRoot,
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "/" || !validCanonicalAbsolutePath(path) {
			return false
		}
		if _, exists := seen[path]; exists {
			return false
		}
		seen[path] = struct{}{}
	}
	return true
}

func lifecycleLayoutPath(
	layout LifecycleStoreLayout,
	directory LifecycleDirectory,
) (string, bool) {
	switch directory {
	case LifecycleJournals:
		return layout.JournalRoot, true
	case LifecycleReceipts:
		return layout.ReceiptRoot, true
	case LifecycleReservations:
		return layout.ReservationRoot, true
	default:
		return "", false
	}
}
