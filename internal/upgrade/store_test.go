package upgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFileJournalStoreCreateReplaceAndRestart(t *testing.T) {
	t.Parallel()

	root := privateJournalRoot(t)
	store, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        true,
		MaxDocumentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("OpenFileJournalStore() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lease, err := store.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if _, err := lease.Read(); !errors.Is(err, ErrJournalAbsent) {
		t.Fatalf("initial Read() error = %v, want ErrJournalAbsent", err)
	}
	first := []byte(`{"generation":1}`)
	if err := lease.Create(first); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	readback, err := lease.Read()
	if err != nil || string(readback) != string(first) {
		t.Fatalf("Read() = %s/%v, want %s", readback, err, first)
	}
	second := []byte(`{"generation":2}`)
	if err := lease.Replace([]byte(`{"wrong":true}`), second); !errors.Is(
		err,
		ErrJournalConflict,
	) {
		t.Fatalf("wrong Replace() error = %v, want ErrJournalConflict", err)
	}
	if err := lease.Replace(first, second); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("lease Close() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store Close() error = %v", err)
	}

	reopened, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        false,
		MaxDocumentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer reopened.Close()
	lease, err = reopened.Acquire(ctx)
	if err != nil {
		t.Fatalf("reopened Acquire() error = %v", err)
	}
	defer lease.Close()
	readback, err = lease.Read()
	if err != nil || string(readback) != string(second) {
		t.Fatalf("reopened Read() = %s/%v, want %s", readback, err, second)
	}
}

func TestFileJournalStoreCreateInstallCrashRestartsReadable(t *testing.T) {
	t.Parallel()

	root := privateJournalRoot(t)
	store, lease := openJournalTestLease(t, root)
	document := []byte(`{"generation":1}`)
	store.fault = func(point string) error {
		if point == "create-after-install" {
			return errors.New("simulated process termination")
		}
		return nil
	}
	if err := lease.Create(document); !errors.Is(err, ErrJournalIntegrity) {
		t.Fatalf(
			"Create() error = %v, want ErrJournalIntegrity",
			err,
		)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("lease Close() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store Close() error = %v", err)
	}

	restarted, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		MaxDocumentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("restart OpenFileJournalStore() error = %v", err)
	}
	defer restarted.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	restartedLease, err := restarted.Acquire(ctx)
	if err != nil {
		t.Fatalf("restart Acquire() error = %v", err)
	}
	defer restartedLease.Close()
	readback, err := restartedLease.Read()
	if err != nil || !bytes.Equal(readback, document) {
		t.Fatalf(
			"restart Read() = %s/%v, want %s",
			readback,
			err,
			document,
		)
	}
	assertNoJournalTemps(t, root)
}

func TestFileJournalStoreRequiresDeadlineAndExcludesWriters(t *testing.T) {
	t.Parallel()

	root := privateJournalRoot(t)
	first, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        true,
		MaxDocumentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("first open error = %v", err)
	}
	defer first.Close()
	second, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        false,
		MaxDocumentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("second open error = %v", err)
	}
	defer second.Close()

	if _, err := first.Acquire(context.Background()); !errors.Is(
		err,
		ErrJournalDeadlineRequired,
	) {
		t.Fatalf("Acquire(no deadline) error = %v, want ErrJournalDeadlineRequired", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lease, err := first.Acquire(ctx)
	if err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	defer lease.Close()
	blockedCtx, blockedCancel := context.WithTimeout(
		context.Background(),
		50*time.Millisecond,
	)
	defer blockedCancel()
	if _, err := second.Acquire(blockedCtx); !errors.Is(
		err,
		ErrJournalLeaseUnavailable,
	) {
		t.Fatalf("second Acquire() error = %v, want ErrJournalLeaseUnavailable", err)
	}
}

func TestFileJournalStoreRejectsUnsafeObjects(t *testing.T) {
	t.Parallel()

	t.Run("root mode", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatalf("Chmod() error = %v", err)
		}
		if _, err := OpenFileJournalStore(StoreConfig{
			Root:             root,
			Bootstrap:        true,
			MaxDocumentBytes: 1 << 20,
		}); !errors.Is(err, ErrJournalIntegrity) {
			t.Fatalf("open error = %v, want ErrJournalIntegrity", err)
		}
	})

	t.Run("journal symlink", func(t *testing.T) {
		t.Parallel()
		root := privateJournalRoot(t)
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if err := os.Symlink(target, filepath.Join(root, journalFileName)); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
		store, err := OpenFileJournalStore(StoreConfig{
			Root:             root,
			Bootstrap:        true,
			MaxDocumentBytes: 1 << 20,
		})
		if err != nil {
			t.Fatalf("open error = %v", err)
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		lease, err := store.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire() error = %v", err)
		}
		defer lease.Close()
		if _, err := lease.Read(); !errors.Is(err, ErrJournalIntegrity) {
			t.Fatalf("Read() error = %v, want ErrJournalIntegrity", err)
		}
	})
}

func TestFileJournalStoreBootstrapAndDocumentBounds(t *testing.T) {
	t.Parallel()

	root := privateJournalRoot(t)
	if _, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        false,
		MaxDocumentBytes: 32,
	}); !errors.Is(err, ErrJournalIntegrity) {
		t.Fatalf(
			"open without lock error = %v, want ErrJournalIntegrity",
			err,
		)
	}
	store, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        true,
		MaxDocumentBytes: 32,
	})
	if err != nil {
		t.Fatalf("bootstrap error = %v", err)
	}
	defer store.Close()
	lockInfo, err := os.Lstat(filepath.Join(root, journalLockName))
	if err != nil {
		t.Fatalf("Lstat(lock) error = %v", err)
	}
	if !lockInfo.Mode().IsRegular() ||
		lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode/type = %s", lockInfo.Mode())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := store.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer lease.Close()
	if err := lease.Create(nil); !errors.Is(err, ErrJournalIntegrity) {
		t.Fatalf("Create(nil) error = %v, want ErrJournalIntegrity", err)
	}
	if err := lease.Create(bytes.Repeat([]byte("x"), 33)); !errors.Is(
		err,
		ErrJournalIntegrity,
	) {
		t.Fatalf("Create(oversize) error = %v, want ErrJournalIntegrity", err)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenFileJournalStore(StoreConfig{
		Root:             missing,
		Bootstrap:        true,
		MaxDocumentBytes: 32,
	}); !errors.Is(err, ErrJournalIntegrity) {
		t.Fatalf("missing root error = %v, want ErrJournalIntegrity", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing root was created: %v", err)
	}
}

func TestFileJournalStoreRejectsUnsafeLockObjects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(root, "target")
				if err := os.WriteFile(
					target,
					[]byte("lock"),
					0o600,
				); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				if err := os.Symlink(
					target,
					filepath.Join(root, journalLockName),
				); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			},
		},
		{
			name: "hard link",
			setup: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(root, "target")
				if err := os.WriteFile(
					target,
					[]byte("lock"),
					0o600,
				); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				if err := os.Link(
					target,
					filepath.Join(root, journalLockName),
				); err != nil {
					t.Fatalf("Link() error = %v", err)
				}
			},
		},
		{
			name: "mode",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(root, journalLockName),
					[]byte("lock"),
					0o644,
				); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Mkdir(
					filepath.Join(root, journalLockName),
					0o600,
				); err != nil {
					t.Fatalf("Mkdir() error = %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := privateJournalRoot(t)
			test.setup(t, root)
			if _, err := OpenFileJournalStore(StoreConfig{
				Root:             root,
				Bootstrap:        true,
				MaxDocumentBytes: 1 << 20,
			}); !errors.Is(err, ErrJournalIntegrity) {
				t.Fatalf(
					"open error = %v, want ErrJournalIntegrity",
					err,
				)
			}
		})
	}
}

func TestFileJournalStoreRejectsUnsafeJournalObjects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{
			name: "hard link",
			setup: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(root, "target")
				if err := os.WriteFile(
					target,
					[]byte(`{}`),
					0o600,
				); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				if err := os.Link(
					target,
					filepath.Join(root, journalFileName),
				); err != nil {
					t.Fatalf("Link() error = %v", err)
				}
			},
		},
		{
			name: "mode",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(root, journalFileName),
					[]byte(`{}`),
					0o644,
				); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Mkdir(
					filepath.Join(root, journalFileName),
					0o700,
				); err != nil {
					t.Fatalf("Mkdir() error = %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := privateJournalRoot(t)
			store, err := OpenFileJournalStore(StoreConfig{
				Root:             root,
				Bootstrap:        true,
				MaxDocumentBytes: 1 << 20,
			})
			if err != nil {
				t.Fatalf("open error = %v", err)
			}
			defer store.Close()
			test.setup(t, root)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Second,
			)
			defer cancel()
			lease, err := store.Acquire(ctx)
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			defer lease.Close()
			if _, err := lease.Read(); !errors.Is(
				err,
				ErrJournalIntegrity,
			) {
				t.Fatalf(
					"Read() error = %v, want ErrJournalIntegrity",
					err,
				)
			}
		})
	}
}

func TestFileJournalStoreRejectsRootAndLockReplacement(t *testing.T) {
	t.Parallel()

	t.Run("root replacement", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		root := filepath.Join(parent, "journal")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("Mkdir(root) error = %v", err)
		}
		store, err := OpenFileJournalStore(StoreConfig{
			Root:             root,
			Bootstrap:        true,
			MaxDocumentBytes: 1 << 20,
		})
		if err != nil {
			t.Fatalf("open error = %v", err)
		}
		defer store.Close()
		if err := os.Rename(
			root,
			filepath.Join(parent, "old"),
		); err != nil {
			t.Fatalf("Rename(root) error = %v", err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("Mkdir(replacement) error = %v", err)
		}
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		if _, err := store.Acquire(ctx); !errors.Is(
			err,
			ErrJournalIntegrity,
		) {
			t.Fatalf(
				"Acquire() error = %v, want ErrJournalIntegrity",
				err,
			)
		}
	})

	t.Run("lock replacement", func(t *testing.T) {
		t.Parallel()
		root := privateJournalRoot(t)
		store, err := OpenFileJournalStore(StoreConfig{
			Root:             root,
			Bootstrap:        true,
			MaxDocumentBytes: 1 << 20,
		})
		if err != nil {
			t.Fatalf("open error = %v", err)
		}
		defer store.Close()
		if store.lockPinFD < 0 {
			t.Fatal("store did not retain a lock inode pin")
		}
		pinnedIdentity, err := journalFstatPrivate(
			store.lockPinFD,
			unix.S_IFREG,
			0o600,
			true,
		)
		if err != nil || pinnedIdentity != store.lockIdentity {
			t.Fatalf(
				"lock pin = %+v/%v, want %+v",
				pinnedIdentity,
				err,
				store.lockIdentity,
			)
		}
		lock := filepath.Join(root, journalLockName)
		if err := os.Remove(lock); err != nil {
			t.Fatalf("Remove(lock) error = %v", err)
		}
		if err := os.WriteFile(lock, []byte("replacement"), 0o600); err != nil {
			t.Fatalf("WriteFile(lock) error = %v", err)
		}
		replacementFD, replacementIdentity, err := openJournalLock(
			store.rootFD,
			false,
		)
		if err != nil {
			t.Fatalf("open replacement lock: %v", err)
		}
		if err := unix.Close(replacementFD); err != nil {
			t.Fatalf("close replacement lock: %v", err)
		}
		if replacementIdentity == store.lockIdentity {
			t.Fatalf(
				"replacement reused pinned lock identity: %+v",
				replacementIdentity,
			)
		}
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		if _, err := store.Acquire(ctx); !errors.Is(
			err,
			ErrJournalIntegrity,
		) {
			t.Fatalf(
				"Acquire() error = %v, want ErrJournalIntegrity",
				err,
			)
		}
	})
}

func TestDuplicateJournalAcquireFDsStopsAndCleansUpOnFailure(t *testing.T) {
	t.Run("root duplicate failure never attempts pin duplicate", func(t *testing.T) {
		calls := 0
		duplicate := func(int) (int, error) {
			calls++
			return -1, ErrJournalStoreClosed
		}
		rootFD, pinFD, err := duplicateJournalAcquireFDs(
			101,
			102,
			duplicate,
		)
		if !errors.Is(err, ErrJournalStoreClosed) ||
			rootFD != -1 ||
			pinFD != -1 ||
			calls != 1 {
			t.Fatalf(
				"duplicate result = %d/%d/%v calls=%d",
				rootFD,
				pinFD,
				err,
				calls,
			)
		}
	})

	t.Run("pin duplicate failure closes root duplicate", func(t *testing.T) {
		pipe := make([]int, 2)
		if err := unix.Pipe(pipe); err != nil {
			t.Fatalf("Pipe: %v", err)
		}
		defer unix.Close(pipe[0])
		defer unix.Close(pipe[1])
		rootDuplicate := -1
		calls := 0
		duplicate := func(fd int) (int, error) {
			calls++
			if calls == 1 {
				var err error
				rootDuplicate, err = unix.Dup(fd)
				return rootDuplicate, err
			}
			return -1, ErrJournalStoreClosed
		}
		rootFD, pinFD, err := duplicateJournalAcquireFDs(
			pipe[0],
			pipe[1],
			duplicate,
		)
		if !errors.Is(err, ErrJournalStoreClosed) ||
			rootFD != -1 ||
			pinFD != -1 ||
			calls != 2 {
			t.Fatalf(
				"duplicate result = %d/%d/%v calls=%d",
				rootFD,
				pinFD,
				err,
				calls,
			)
		}
		if closeErr := unix.Close(rootDuplicate); !errors.Is(
			closeErr,
			unix.EBADF,
		) {
			t.Fatalf(
				"root duplicate remained open: close error = %v",
				closeErr,
			)
		}
	})
}

func TestReleaseProspectiveJournalLockUnlocksThenClosesExactlyOnce(
	t *testing.T,
) {
	var calls []string
	err := releaseProspectiveJournalLock(
		41,
		func(fd int) error {
			if fd != 41 {
				t.Fatalf("unlock fd = %d, want 41", fd)
			}
			calls = append(calls, "unlock")
			return errors.New("fixture unlock failure")
		},
		func(fd int) error {
			if fd != 41 {
				t.Fatalf("close fd = %d, want 41", fd)
			}
			calls = append(calls, "close")
			return errors.New("fixture close failure")
		},
	)
	if !errors.Is(err, ErrJournalIntegrity) {
		t.Fatalf("releaseProspectiveJournalLock() error = %v", err)
	}
	if got, want := strings.Join(calls, ","), "unlock,close"; got != want {
		t.Fatalf("cleanup calls = %q, want %q", got, want)
	}
}

func TestFileJournalStoreExactCASAndClosedState(t *testing.T) {
	t.Parallel()

	root := privateJournalRoot(t)
	store, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        true,
		MaxDocumentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("open error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := store.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	first := []byte(`{"generation":1}`)
	if err := lease.Create(first); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := lease.Create(first); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("duplicate Create() error = %v, want ErrJournalConflict", err)
	}
	if err := os.WriteFile(
		filepath.Join(root, journalFileName),
		[]byte(`{"external":true}`),
		0o600,
	); err != nil {
		t.Fatalf("external WriteFile() error = %v", err)
	}
	if err := lease.Replace(
		first,
		[]byte(`{"generation":2}`),
	); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("stale Replace() error = %v, want ErrJournalConflict", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("lease Close() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store Close() error = %v", err)
	}
	if _, err := store.Acquire(ctx); !errors.Is(
		err,
		ErrJournalStoreClosed,
	) {
		t.Fatalf(
			"Acquire(closed) error = %v, want ErrJournalStoreClosed",
			err,
		)
	}
}

func TestFileJournalStoreCleansOwnedTempOnInjectedFailure(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{
		"write",
		"file-fsync",
		"create-install",
	} {
		operation := operation
		t.Run("create-"+operation, func(t *testing.T) {
			t.Parallel()
			root := privateJournalRoot(t)
			store, lease := openJournalTestLease(t, root)
			defer store.Close()
			defer lease.Close()
			store.fault = func(point string) error {
				if point == operation {
					return errors.New("injected")
				}
				return nil
			}
			if err := lease.Create(
				[]byte(`{"generation":1}`),
			); !errors.Is(err, ErrJournalIntegrity) {
				t.Fatalf(
					"Create() error = %v, want ErrJournalIntegrity",
					err,
				)
			}
			assertNoJournalTemps(t, root)
		})
	}

	for _, operation := range []string{
		"write",
		"file-fsync",
		"replace-install",
	} {
		operation := operation
		t.Run("replace-"+operation, func(t *testing.T) {
			t.Parallel()
			root := privateJournalRoot(t)
			store, lease := openJournalTestLease(t, root)
			defer store.Close()
			defer lease.Close()
			first := []byte(`{"generation":1}`)
			if err := lease.Create(first); err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			store.fault = func(point string) error {
				if point == operation {
					return errors.New("injected")
				}
				return nil
			}
			if err := lease.Replace(
				first,
				[]byte(`{"generation":2}`),
			); !errors.Is(err, ErrJournalIntegrity) {
				t.Fatalf(
					"Replace() error = %v, want ErrJournalIntegrity",
					err,
				)
			}
			assertNoJournalTemps(t, root)
			readback, err := lease.Read()
			if err != nil || !bytes.Equal(readback, first) {
				t.Fatalf(
					"Read() = %s/%v, want unchanged %s",
					readback,
					err,
					first,
				)
			}
		})
	}
}

func openJournalTestLease(
	t *testing.T,
	root string,
) (*FileJournalStore, JournalLease) {
	t.Helper()
	store, err := OpenFileJournalStore(StoreConfig{
		Root:             root,
		Bootstrap:        true,
		MaxDocumentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("OpenFileJournalStore() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	lease, err := store.Acquire(ctx)
	if err != nil {
		_ = store.Close()
		t.Fatalf("Acquire() error = %v", err)
	}
	return store, lease
}

func assertNoJournalTemps(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".runner-upgrade.tmp-") {
			t.Fatalf("owned temp remains: %s", entry.Name())
		}
	}
}

func privateJournalRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	return root
}
