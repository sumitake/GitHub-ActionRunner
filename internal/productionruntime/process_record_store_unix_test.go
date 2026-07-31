//go:build darwin || linux

package productionruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessRecordStoreExactCreateReadRemove(t *testing.T) {
	t.Parallel()

	root := processRecordTestRoot(t)
	store, err := OpenProcessRecordStore(root)
	if err != nil {
		t.Fatalf("OpenProcessRecordStore() error = %v", err)
	}
	defer store.Close()

	if _, _, present, err := store.Read(
		context.Background(),
	); err != nil || present {
		t.Fatalf("initial Read() = present %t, %v", present, err)
	}

	record := validProcessRecordFixture()
	identity, err := store.Create(context.Background(), record)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	info, err := os.Lstat(filepath.Join(root, processRecordName))
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("process record mode = %v", info.Mode())
	}

	got, gotIdentity, present, err := store.Read(context.Background())
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !present || got != record || gotIdentity != identity {
		t.Fatalf("Read() = %#v, %q, %t", got, gotIdentity, present)
	}
	if _, err := store.Create(
		context.Background(),
		record,
	); !errors.Is(err, ErrProcessRecordStore) {
		t.Fatalf("duplicate Create() error = %v", err)
	}

	if err := store.Remove(
		context.Background(),
		stringMutation(identity),
	); !errors.Is(err, ErrProcessRecordStore) {
		t.Fatalf("wrong Remove() error = %v", err)
	}
	if _, _, present, err := store.Read(
		context.Background(),
	); err != nil || !present {
		t.Fatalf("record not retained after wrong remove: %t, %v", present, err)
	}

	if err := store.Remove(context.Background(), identity); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, _, present, err := store.Read(
		context.Background(),
	); err != nil || present {
		t.Fatalf("final Read() = present %t, %v", present, err)
	}
}

func TestProcessRecordStoreRejectsUnsafeRecordShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		stage func(string) error
	}{
		{
			"symlink",
			func(path string) error {
				return os.Symlink("/dev/null", path)
			},
		},
		{
			"directory",
			func(path string) error {
				return os.Mkdir(path, 0o700)
			},
		},
		{
			"wrong-mode",
			func(path string) error {
				return os.WriteFile(path, []byte("{}"), 0o644)
			},
		},
		{
			"noncanonical",
			func(path string) error {
				return os.WriteFile(path, []byte("{}"), 0o600)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := processRecordTestRoot(t)
			store, err := OpenProcessRecordStore(root)
			if err != nil {
				t.Fatalf("OpenProcessRecordStore() error = %v", err)
			}
			defer store.Close()
			if err := test.stage(
				filepath.Join(root, processRecordName),
			); err != nil {
				t.Fatalf("stage error = %v", err)
			}
			if _, _, _, err := store.Read(
				context.Background(),
			); !errors.Is(err, ErrProcessRecordStore) {
				t.Fatalf("Read() error = %v", err)
			}
		})
	}
}

func TestProcessRecordStoreRejectsReboundRoot(t *testing.T) {
	t.Parallel()

	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	root := filepath.Join(parent, "state")
	original := filepath.Join(parent, "state-original")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	store, err := OpenProcessRecordStore(root)
	if err != nil {
		t.Fatalf("OpenProcessRecordStore() error = %v", err)
	}
	defer store.Close()
	if err := os.Rename(root, original); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("replacement Mkdir() error = %v", err)
	}

	if _, _, _, err := store.Read(
		context.Background(),
	); !errors.Is(err, ErrProcessRecordStore) {
		t.Fatalf("Read() error = %v", err)
	}
	if _, err := store.Create(
		context.Background(),
		validProcessRecordFixture(),
	); !errors.Is(err, ErrProcessRecordStore) {
		t.Fatalf("Create() error = %v", err)
	}
}

func TestProcessRecordStoreRejectsCancelledAndClosedOperations(t *testing.T) {
	t.Parallel()

	root := processRecordTestRoot(t)
	store, err := OpenProcessRecordStore(root)
	if err != nil {
		t.Fatalf("OpenProcessRecordStore() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := store.Read(
		ctx,
	); !errors.Is(err, ErrProcessRecordStore) {
		t.Fatalf("cancelled Read() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, _, _, err := store.Read(
		context.Background(),
	); !errors.Is(err, ErrProcessRecordStore) {
		t.Fatalf("closed Read() error = %v", err)
	}
}

func stringMutation(value string) string {
	if value[0] == '0' {
		return "1" + value[1:]
	}
	return "0" + value[1:]
}

func processRecordTestRoot(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	root := filepath.Join(parent, "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	return root
}
