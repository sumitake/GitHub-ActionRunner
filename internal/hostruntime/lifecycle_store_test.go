//go:build darwin || linux

package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecycleStoreCreateReplaceRemoveRoundTrip(t *testing.T) {
	t.Parallel()

	root := makeLifecycleRoot(t)
	store, err := OpenLifecycleStore(root, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	defer store.Close()

	first := []byte(`{"state":"applying"}`)
	second := []byte(`{"state":"applied"}`)
	if err := store.CreateCanonical(
		LifecycleReceipts,
		"effect.json",
		first,
		1024,
	); err != nil {
		t.Fatalf("CreateCanonical() error = %v", err)
	}
	if err := store.ReplaceCanonical(
		LifecycleReceipts,
		"effect.json",
		first,
		second,
		1024,
	); err != nil {
		t.Fatalf("ReplaceCanonical() error = %v", err)
	}
	got, err := store.ReadCanonical(
		LifecycleReceipts,
		"effect.json",
		1024,
	)
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("ReadCanonical() = %q, %v", got, err)
	}
	if err := store.RemoveCanonical(
		LifecycleReceipts,
		"effect.json",
		second,
		1024,
	); err != nil {
		t.Fatalf("RemoveCanonical() error = %v", err)
	}
	if _, err := store.ReadCanonical(
		LifecycleReceipts,
		"effect.json",
		1024,
	); !errors.Is(err, ErrLifecycleStateAbsent) {
		t.Fatalf("ReadCanonical() error = %v", err)
	}
}

func TestLifecycleStoreLayoutUsesExplicitPrivateRoots(t *testing.T) {
	t.Parallel()

	parent := canonicalTestDirectory(t)
	layout := LifecycleStoreLayout{
		LockRoot:        makePrivateLifecycleDirectory(t, parent, "state"),
		JournalRoot:     makePrivateLifecycleDirectory(t, parent, "journal"),
		ReceiptRoot:     makePrivateLifecycleDirectory(t, parent, "receipt"),
		ReservationRoot: makePrivateLifecycleDirectory(t, parent, "reservation"),
	}
	store, err := OpenLifecycleStoreLayout(layout, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStoreLayout() error = %v", err)
	}
	defer store.Close()

	document := []byte(`{"state":"prepared"}`)
	if err := store.CreateCanonical(
		LifecycleJournals,
		"operation.json",
		document,
		1024,
	); err != nil {
		t.Fatalf("CreateCanonical() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(layout.JournalRoot, "operation.json")); err != nil {
		t.Fatalf("journal not written to explicit root: %v", err)
	}
	for _, path := range []string{
		filepath.Join(layout.LockRoot, string(LifecycleJournals), "operation.json"),
		filepath.Join(layout.ReceiptRoot, "operation.json"),
		filepath.Join(layout.ReservationRoot, "operation.json"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected lifecycle document at %q: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(layout.LockRoot, lifecycleLockName)); err != nil {
		t.Fatalf("stable lock missing from explicit lock root: %v", err)
	}
}

func TestLifecycleStoreLayoutRejectsDirectoryPathReplacement(t *testing.T) {
	t.Parallel()

	parent := canonicalTestDirectory(t)
	layout := LifecycleStoreLayout{
		LockRoot:        makePrivateLifecycleDirectory(t, parent, "state"),
		JournalRoot:     makePrivateLifecycleDirectory(t, parent, "journal"),
		ReceiptRoot:     makePrivateLifecycleDirectory(t, parent, "receipt"),
		ReservationRoot: makePrivateLifecycleDirectory(t, parent, "reservation"),
	}
	store, err := OpenLifecycleStoreLayout(layout, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStoreLayout() error = %v", err)
	}
	defer store.Close()

	original := layout.ReceiptRoot + "-original"
	if err := os.Rename(layout.ReceiptRoot, original); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.Mkdir(layout.ReceiptRoot, 0o700); err != nil {
		t.Fatalf("replacement Mkdir() error = %v", err)
	}
	if _, err := store.ReadCanonical(
		LifecycleReceipts,
		"missing.json",
		1024,
	); !errors.Is(err, ErrLifecycleIntegrity) {
		t.Fatalf("ReadCanonical() error = %v", err)
	}
}

func TestLifecycleStoreLayoutFromPrivateOverlay(t *testing.T) {
	t.Parallel()

	overlay := goldenPrivateOverlay()
	layout, err := LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("LifecycleStoreLayoutFromPrivateOverlay() error = %v", err)
	}
	if layout.LockRoot != overlay.Paths.StateRoot ||
		layout.JournalRoot != overlay.Paths.JournalRoot ||
		layout.ReceiptRoot != overlay.Paths.ReceiptRoot ||
		layout.ReservationRoot != overlay.Paths.ReservationRoot {
		t.Fatalf("layout = %#v", layout)
	}
}

func TestLifecycleStoreRejectsDuplicateAndCASMismatch(t *testing.T) {
	t.Parallel()

	store, err := OpenLifecycleStore(makeLifecycleRoot(t), true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	defer store.Close()
	document := []byte(`{"v":1}`)
	if err := store.CreateCanonical(
		LifecycleJournals,
		"operation.json",
		document,
		1024,
	); err != nil {
		t.Fatalf("CreateCanonical() error = %v", err)
	}
	if err := store.CreateCanonical(
		LifecycleJournals,
		"operation.json",
		document,
		1024,
	); !errors.Is(err, ErrLifecycleStateExists) {
		t.Fatalf("duplicate CreateCanonical() error = %v", err)
	}
	if err := store.ReplaceCanonical(
		LifecycleJournals,
		"operation.json",
		[]byte(`{"v":0}`),
		[]byte(`{"v":2}`),
		1024,
	); !errors.Is(err, ErrLifecycleStateConflict) {
		t.Fatalf("ReplaceCanonical() error = %v", err)
	}
	if err := store.RemoveCanonical(
		LifecycleJournals,
		"operation.json",
		[]byte(`{"v":0}`),
		1024,
	); !errors.Is(err, ErrLifecycleStateConflict) {
		t.Fatalf("RemoveCanonical() error = %v", err)
	}
}

func TestLifecycleStoreRejectsRootPathReplacement(t *testing.T) {
	t.Parallel()

	parent := canonicalTestDirectory(t)
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	store, err := OpenLifecycleStore(root, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	defer store.Close()
	original := filepath.Join(parent, "original")
	if err := os.Rename(root, original); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("replacement Mkdir() error = %v", err)
	}
	if _, err := store.ReadCanonical(
		LifecycleJournals,
		"missing.json",
		1024,
	); !errors.Is(err, ErrLifecycleIntegrity) {
		t.Fatalf("ReadCanonical() error = %v", err)
	}
}

func TestLifecycleStoreRejectsLockRecreation(t *testing.T) {
	t.Parallel()

	root := makeLifecycleRoot(t)
	store, err := OpenLifecycleStore(root, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	defer store.Close()
	lockPath := filepath.Join(root, lifecycleLockName)
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := store.Acquire(ctx, 10*time.Millisecond); !errors.Is(
		err,
		ErrLifecycleIntegrity,
	) {
		t.Fatalf("Acquire() error = %v", err)
	}
}

func TestLifecycleStoreLockIsExclusiveAndBounded(t *testing.T) {
	t.Parallel()

	root := makeLifecycleRoot(t)
	first, err := OpenLifecycleStore(root, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore(first) error = %v", err)
	}
	defer first.Close()
	second, err := OpenLifecycleStore(root, false)
	if err != nil {
		t.Fatalf("OpenLifecycleStore(second) error = %v", err)
	}
	defer second.Close()

	lease, err := first.Acquire(context.Background(), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Acquire(first) error = %v", err)
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	if _, err := second.Acquire(ctx, 10*time.Millisecond); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("Acquire(second) error = %v", err)
	}
}

func TestLifecycleStoreRejectsSymlinkHardlinkAndUnsafeNames(t *testing.T) {
	t.Parallel()

	root := makeLifecycleRoot(t)
	store, err := OpenLifecycleStore(root, true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	defer store.Close()
	journalRoot := filepath.Join(root, string(LifecycleJournals))
	target := filepath.Join(journalRoot, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Link(target, filepath.Join(journalRoot, "hard.json")); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	if _, err := store.ReadCanonical(
		LifecycleJournals,
		"target.json",
		1024,
	); !errors.Is(err, ErrLifecycleIntegrity) {
		t.Fatalf("hardlink ReadCanonical() error = %v", err)
	}
	if err := os.Symlink(
		target,
		filepath.Join(journalRoot, "link.json"),
	); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := store.ReadCanonical(
		LifecycleJournals,
		"link.json",
		1024,
	); !errors.Is(err, ErrLifecycleIntegrity) {
		t.Fatalf("symlink ReadCanonical() error = %v", err)
	}
	for _, name := range []string{"", ".", "..", "../x", "x/y", ".tmp-evil"} {
		if err := store.CreateCanonical(
			LifecycleJournals,
			name,
			[]byte("{}"),
			1024,
		); !errors.Is(err, ErrLifecycleIntegrity) {
			t.Fatalf("CreateCanonical(%q) error = %v", name, err)
		}
	}
}

func TestLifecycleStoreRejectsOversizeAndEmptyDocuments(t *testing.T) {
	t.Parallel()

	store, err := OpenLifecycleStore(makeLifecycleRoot(t), true)
	if err != nil {
		t.Fatalf("OpenLifecycleStore() error = %v", err)
	}
	defer store.Close()
	for _, document := range [][]byte{nil, {}, []byte("12345")} {
		if err := store.CreateCanonical(
			LifecycleReservations,
			"reservation.json",
			document,
			4,
		); !errors.Is(err, ErrLifecycleIntegrity) {
			t.Fatalf("CreateCanonical(%q) error = %v", document, err)
		}
	}
}

func makeLifecycleRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(canonicalTestDirectory(t), "lifecycle")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	return root
}

func canonicalTestDirectory(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	return path
}

func makePrivateLifecycleDirectory(
	t *testing.T,
	parent string,
	name string,
) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", path, err)
	}
	return path
}
