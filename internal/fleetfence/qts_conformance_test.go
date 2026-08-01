package fleetfence

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const (
	qtsConformanceAuthorization = "TASK9-QTS-FS-CONFORMANCE-AUTHORIZED"
	qtsConformanceRootEnv       = "PORTABLE_GHAR_TASK9_QTS_FS_ROOT"
	qtsConformanceAuthEnv       = "PORTABLE_GHAR_TASK9_QTS_FS_AUTHORIZATION"
	qtsConformanceProfileEnv    = "PORTABLE_GHAR_TASK9_QTS_FS_PROFILE"
	qtsConformanceDigestEnv     = "PORTABLE_GHAR_TASK9_QTS_FS_PROFILE_DIGEST"
	qtsConformanceHelperEnv     = "PORTABLE_GHAR_TASK9_QTS_FS_CRASH_HELPER"
)

// TestTASK9QTSFSConformance is the named target residual harness. It is
// intentionally dormant unless a later private manifest supplies an empty,
// dedicated QTS test root plus exact operator authorization and qualified
// profile evidence.
func TestTASK9QTSFSConformance(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TASK9-QTS-FS-CONFORMANCE requires the selected Linux/QTS target")
	}
	parent := os.Getenv(qtsConformanceRootEnv)
	if parent == "" {
		t.Skip("TASK9-QTS-FS-CONFORMANCE root not supplied")
	}
	if os.Getenv(qtsConformanceAuthEnv) != qtsConformanceAuthorization {
		t.Fatal("TASK9-QTS-FS-CONFORMANCE operator authorization missing")
	}
	profile := os.Getenv(qtsConformanceProfileEnv)
	if profile != string("strict-linux") &&
		profile != string("qts-capless-root") {
		t.Fatal("TASK9-QTS-FS-CONFORMANCE profile is not qualified")
	}
	if !isLowerHex64(os.Getenv(qtsConformanceDigestEnv)) {
		t.Fatal("TASK9-QTS-FS-CONFORMANCE profile digest is invalid")
	}
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent ||
		filepath.Base(parent) != "portable-ghar-task9-qts-fs-conformance" {
		t.Fatal("TASK9-QTS-FS-CONFORMANCE root is not a dedicated canonical path")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("TASK9-QTS-FS-CONFORMANCE refuses a missing or nonempty root")
	}
	root := filepath.Join(parent, "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create dedicated state root: %v", err)
	}
	store, err := OpenStore(StoreConfig{
		Root:             root,
		Identity:         NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open target store: %v", err)
	}
	defer store.Close()

	active := FleetPortable
	header := qtsHandoff(t, store, FleetNone, active, 0)
	for iteration := 0; iteration < 1000; iteration++ {
		first := qtsAcquire(t, store, active, header.Generation, "qts-first-"+strconv.Itoa(iteration))
		second := qtsAcquire(t, store, active, header.Generation, "qts-second-"+strconv.Itoa(iteration))
		next := FleetLegacy
		if active == FleetLegacy {
			next = FleetPortable
		}
		blocked, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
		request := HandoffRequest{
			From:               active,
			To:                 next,
			ExpectedGeneration: header.Generation,
			OperationID: HandoffOperationID(
				header.Generation,
				active,
				next,
			),
		}
		if _, err := store.Handoff(blocked, request); !errors.Is(err, context.DeadlineExceeded) {
			cancel()
			t.Fatalf("iteration %d: shared guards did not block handoff: %v", iteration, err)
		}
		cancel()
		if err := first.Close(); err != nil {
			t.Fatalf("iteration %d: first close: %v", iteration, err)
		}
		if err := second.Close(); err != nil {
			t.Fatalf("iteration %d: second close: %v", iteration, err)
		}

		qtsCrashAcquire(t, root, active, header.Generation, iteration)
		snapshot := qtsInspect(t, store)
		if len(snapshot.Holders) != 1 {
			t.Fatalf("iteration %d: crash holder count = %d", iteration, len(snapshot.Holders))
		}
		beforeDevice, beforeInode := qtsLockIdentity(t, root)
		header = qtsHandoff(t, store, active, next, header.Generation)
		afterDevice, afterInode := qtsLockIdentity(t, root)
		if beforeDevice != afterDevice || beforeInode != afterInode {
			t.Fatalf("iteration %d: stable lock identity changed", iteration)
		}
		snapshot = qtsInspect(t, store)
		if snapshot.Header != header || len(snapshot.Holders) != 0 {
			t.Fatalf("iteration %d: handoff readback = %+v", iteration, snapshot)
		}
		active = next

		if iteration%100 == 99 {
			renamed := root + ".renamed"
			if err := os.Rename(root, renamed); err != nil {
				t.Fatalf("iteration %d: rename root: %v", iteration, err)
			}
			if snapshot := qtsInspect(t, store); snapshot.Header != header {
				t.Fatalf("iteration %d: retained descriptor drift", iteration)
			}
			if err := os.Rename(renamed, root); err != nil {
				t.Fatalf("iteration %d: restore root name: %v", iteration, err)
			}
		}
	}
}

func TestTASK9QTSFSCrashHelper(t *testing.T) {
	if os.Getenv(qtsConformanceHelperEnv) != "1" {
		t.Skip("crash helper")
	}
	root := os.Getenv(qtsConformanceRootEnv)
	generation, err := strconv.ParseUint(os.Getenv("PORTABLE_GHAR_TASK9_QTS_FS_GENERATION"), 10, 64)
	if err != nil || generation == 0 {
		os.Exit(91)
	}
	fleet := Fleet(os.Getenv("PORTABLE_GHAR_TASK9_QTS_FS_FLEET"))
	owner := os.Getenv("PORTABLE_GHAR_TASK9_QTS_FS_OWNER")
	store, err := OpenStore(StoreConfig{
		Root:             root,
		Identity:         NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		os.Exit(92)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = store.Acquire(ctx, AcquireRequest{
		Fleet:      fleet,
		Generation: generation,
		OwnerID:    owner,
		PID:        os.Getpid(),
	})
	cancel()
	if err != nil {
		os.Exit(93)
	}
	// Deliberately bypass every defer and Guard.Close. Kernel process exit must
	// release flock while the stale canonical holder remains for EX retirement.
	os.Exit(0)
}

func qtsAcquire(
	t *testing.T,
	store *Store,
	fleet Fleet,
	generation uint64,
	owner string,
) Guard {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	guard, err := store.Acquire(ctx, AcquireRequest{
		Fleet:      fleet,
		Generation: generation,
		OwnerID:    owner,
		PID:        os.Getpid(),
	})
	if err != nil {
		t.Fatalf("target acquire: %v", err)
	}
	return guard
}

func qtsHandoff(
	t *testing.T,
	store *Store,
	from Fleet,
	to Fleet,
	generation uint64,
) Header {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	header, err := store.Handoff(ctx, HandoffRequest{
		From:               from,
		To:                 to,
		ExpectedGeneration: generation,
		OperationID:        HandoffOperationID(generation, from, to),
	})
	if err != nil {
		t.Fatalf("target handoff: %v", err)
	}
	return header
}

func qtsInspect(t *testing.T, store *Store) Snapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := store.Inspect(ctx)
	if err != nil {
		t.Fatalf("target inspect: %v", err)
	}
	return snapshot
}

func qtsCrashAcquire(
	t *testing.T,
	root string,
	fleet Fleet,
	generation uint64,
	iteration int,
) {
	t.Helper()
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestTASK9QTSFSCrashHelper$",
	)
	command.Env = append(
		os.Environ(),
		qtsConformanceHelperEnv+"=1",
		qtsConformanceRootEnv+"="+root,
		"PORTABLE_GHAR_TASK9_QTS_FS_GENERATION="+strconv.FormatUint(generation, 10),
		"PORTABLE_GHAR_TASK9_QTS_FS_FLEET="+string(fleet),
		"PORTABLE_GHAR_TASK9_QTS_FS_OWNER=qts-crash-"+strconv.Itoa(iteration),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("iteration %d: crash helper: %v: %q", iteration, err, output)
	}
}

func qtsLockIdentity(t *testing.T, root string) (uint64, uint64) {
	t.Helper()
	info, err := os.Lstat(filepath.Join(root, lockName))
	if err != nil {
		t.Fatalf("stat stable lock: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stable lock identity unavailable")
	}
	return uint64(stat.Dev), uint64(stat.Ino)
}
