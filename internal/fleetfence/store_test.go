package fleetfence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type identityStub struct {
	mu      sync.Mutex
	bootID  string
	startID map[int]string
	err     error
}

func (s *identityStub) Current(
	_ context.Context,
	pid int,
) (ProcessIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return ProcessIdentity{}, s.err
	}
	return ProcessIdentity{
		BootID:         s.bootID,
		ProcessStartID: s.startID[pid],
	}, nil
}

func testContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 2*time.Second)
}

func newTestStore(t *testing.T) (*Store, string, *identityStub) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "fleet")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	identity := &identityStub{
		bootID:  "boot-a",
		startID: map[int]string{os.Getpid(): "start-a"},
	}
	store, err := OpenStore(StoreConfig{
		Root:             root,
		Identity:         identity,
		Now:              func() time.Time { return time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC) },
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store close: %v", err)
		}
	})
	return store, root, identity
}

func bootstrap(
	t *testing.T,
	store *Store,
	to Fleet,
) Header {
	t.Helper()
	request := HandoffRequest{
		From:               FleetNone,
		To:                 to,
		ExpectedGeneration: 0,
	}
	request.OperationID = HandoffOperationID(
		request.ExpectedGeneration,
		request.From,
		request.To,
	)
	ctx, cancel := testContext(t)
	defer cancel()
	header, err := store.Handoff(ctx, request)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return header
}

func acquire(
	t *testing.T,
	store *Store,
	fleet Fleet,
	generation uint64,
	owner string,
) Guard {
	t.Helper()
	ctx, cancel := testContext(t)
	defer cancel()
	guard, err := store.Acquire(ctx, AcquireRequest{
		Fleet:      fleet,
		Generation: generation,
		OwnerID:    owner,
		PID:        os.Getpid(),
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	return guard
}

func TestBootstrapAcquireInspectAndReadOnlySnapshot(t *testing.T) {
	store, root, _ := newTestStore(t)

	ctx, cancel := testContext(t)
	optional, present, err := store.InspectOptional(ctx)
	if err != nil || present ||
		optional.Header != (Header{}) ||
		optional.Holders != nil {
		t.Fatalf(
			"InspectOptional() = (%+v, %t, %v), want zero, false, nil",
			optional,
			present,
			err,
		)
	}
	if _, err := store.Inspect(ctx); err == nil {
		t.Fatal("Inspect created or accepted missing bootstrap state")
	}
	cancel()
	if _, err := os.Stat(filepath.Join(root, "fleet.lock")); !os.IsNotExist(err) {
		t.Fatalf("read-only inspect created lock: %v", err)
	}

	header := bootstrap(t, store, FleetPortable)
	if header.Generation != 1 || header.ActiveFleet != FleetPortable ||
		header.RootDevice == 0 || header.RootInode == 0 ||
		header.LockDevice == 0 || header.LockInode == 0 ||
		header.HolderDevice == 0 || header.HolderInode == 0 {
		t.Fatalf("header = %+v", header)
	}
	beforeHeader, err := os.ReadFile(filepath.Join(root, "fleet.json"))
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	guard := acquire(t, store, FleetPortable, 1, "controller-a")
	snapshotCtx, snapshotCancel := testContext(t)
	snapshot, err := store.Inspect(snapshotCtx)
	snapshotCancel()
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if snapshot.Header != guard.Header() || len(snapshot.Holders) != 1 ||
		snapshot.Holders[0].OwnerID != "controller-a" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	afterHeader, err := os.ReadFile(filepath.Join(root, "fleet.json"))
	if err != nil {
		t.Fatalf("reread header: %v", err)
	}
	if string(beforeHeader) != string(afterHeader) {
		t.Fatal("Inspect mutated header bytes")
	}
	optionalCtx, optionalCancel := testContext(t)
	optional, present, err = store.InspectOptional(optionalCtx)
	optionalCancel()
	if err != nil || !present ||
		optional.Header != snapshot.Header ||
		len(optional.Holders) != 1 ||
		optional.Holders[0] != snapshot.Holders[0] {
		t.Fatalf(
			"InspectOptional() = (%+v, %t, %v), want present snapshot",
			optional,
			present,
			err,
		)
	}
	if err := guard.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("guard close: %v", err)
	}
}

func TestInspectOptionalRejectsPartialBootstrapState(t *testing.T) {
	tests := []struct {
		name string
		path string
		mode os.FileMode
	}{
		{name: "lock only", path: lockName, mode: 0o600},
		{name: "holders only", path: holderDirName, mode: 0o700 | os.ModeDir},
		{name: "header only", path: headerName, mode: 0o600},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			store, root, _ := newTestStore(t)
			path := filepath.Join(root, test.path)
			var err error
			if test.mode.IsDir() {
				err = os.Mkdir(path, test.mode.Perm())
			} else {
				err = os.WriteFile(path, []byte("{}"), test.mode.Perm())
			}
			if err != nil {
				t.Fatalf("create partial state: %v", err)
			}
			ctx, cancel := testContext(t)
			defer cancel()
			if _, _, err := store.InspectOptional(ctx); err == nil {
				t.Fatal("InspectOptional() accepted partial bootstrap state")
			}
		})
	}
}

func TestSharedGuardsBlockExclusiveHandoffUntilEveryClose(t *testing.T) {
	store, _, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	first := acquire(t, store, FleetPortable, 1, "controller-a")
	second := acquire(t, store, FleetPortable, 1, "controller-b")

	request := HandoffRequest{
		From:               FleetPortable,
		To:                 FleetLegacy,
		ExpectedGeneration: 1,
	}
	request.OperationID = HandoffOperationID(1, FleetPortable, FleetLegacy)
	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer blockedCancel()
	if _, err := store.Handoff(blockedCtx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handoff while shared guards live = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	ctx, cancel := testContext(t)
	defer cancel()
	header, err := store.Handoff(ctx, request)
	if err != nil {
		t.Fatalf("handoff after close: %v", err)
	}
	if header.Generation != 2 || header.ActiveFleet != FleetLegacy {
		t.Fatalf("header = %+v", header)
	}
}

func TestAcquireRejectsWrongGenerationFleetAndDuplicateIdentity(t *testing.T) {
	store, _, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	ctx, cancel := testContext(t)
	if _, err := store.Acquire(ctx, AcquireRequest{
		Fleet:      FleetLegacy,
		Generation: 1,
		OwnerID:    "wrong-fleet",
		PID:        os.Getpid(),
	}); err == nil {
		t.Fatal("wrong fleet acquired")
	}
	cancel()
	ctx, cancel = testContext(t)
	if _, err := store.Acquire(ctx, AcquireRequest{
		Fleet:      FleetPortable,
		Generation: 2,
		OwnerID:    "wrong-generation",
		PID:        os.Getpid(),
	}); err == nil {
		t.Fatal("wrong generation acquired")
	}
	cancel()

	guard := acquire(t, store, FleetPortable, 1, "duplicate")
	ctx, cancel = testContext(t)
	if _, err := store.Acquire(ctx, AcquireRequest{
		Fleet:      FleetPortable,
		Generation: 1,
		OwnerID:    "duplicate",
		PID:        os.Getpid(),
	}); err == nil {
		t.Fatal("duplicate exact holder identity acquired")
	}
	cancel()
	if err := guard.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestRenewFailsClosedOnProcessIdentityReuse(t *testing.T) {
	store, _, identity := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	guard := acquire(t, store, FleetPortable, 1, "controller")
	identity.mu.Lock()
	identity.startID[os.Getpid()] = "start-reused"
	identity.mu.Unlock()
	if err := guard.Renew(context.Background()); err == nil {
		t.Fatal("renew accepted changed process identity")
	}
	select {
	case err := <-guard.Failure():
		if err == nil {
			t.Fatal("failure channel returned nil")
		}
	default:
		t.Fatal("renew failure was not published")
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("close after renewal failure: %v", err)
	}
}

func TestRenewRejectsReplayOfAnOlderSameIdentityHolder(t *testing.T) {
	store, root, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	guard := acquire(t, store, FleetPortable, 1, "replay-holder")
	holderDirectory := filepath.Join(root, holderDirName)
	entries, err := os.ReadDir(holderDirectory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("holder entries: %v %v", entries, err)
	}
	holderPath := filepath.Join(holderDirectory, entries[0].Name())
	older, err := os.ReadFile(holderPath)
	if err != nil {
		t.Fatalf("read older holder: %v", err)
	}
	ctx, cancel := testContext(t)
	if err := guard.Renew(ctx); err != nil {
		cancel()
		t.Fatalf("first renew: %v", err)
	}
	cancel()
	newer, err := os.ReadFile(holderPath)
	if err != nil {
		t.Fatalf("read newer holder: %v", err)
	}
	if string(older) == string(newer) {
		t.Fatal("renewal did not advance canonical holder")
	}
	if err := os.WriteFile(holderPath, older, 0o600); err != nil {
		t.Fatalf("replay older holder: %v", err)
	}
	ctx, cancel = testContext(t)
	if err := guard.Renew(ctx); err == nil {
		cancel()
		t.Fatal("older same-identity holder replay was accepted")
	}
	cancel()
	if err := guard.Close(); err == nil {
		t.Fatal("close hid replayed holder state")
	}
}

func TestHandoffIsIdempotentOnlyForExactOperation(t *testing.T) {
	store, _, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	request := HandoffRequest{
		From:               FleetPortable,
		To:                 FleetLegacy,
		ExpectedGeneration: 1,
	}
	request.OperationID = HandoffOperationID(1, FleetPortable, FleetLegacy)
	ctx, cancel := testContext(t)
	first, err := store.Handoff(ctx, request)
	cancel()
	if err != nil {
		t.Fatalf("first handoff: %v", err)
	}
	ctx, cancel = testContext(t)
	second, err := store.Handoff(ctx, request)
	cancel()
	if err != nil || first != second {
		t.Fatalf("idempotent retry first=%+v second=%+v err=%v", first, second, err)
	}
	request.OperationID = strings.Repeat("f", 64)
	ctx, cancel = testContext(t)
	if _, err := store.Handoff(ctx, request); err == nil {
		t.Fatal("stale handoff with different operation accepted")
	}
	cancel()
}

func TestRetainedDescriptorsAndSealedLockRejectPathReplacement(t *testing.T) {
	store, root, identity := newTestStore(t)
	bootstrap(t, store, FleetPortable)

	oldRoot := root + ".old"
	if err := os.Rename(root, oldRoot); err != nil {
		t.Fatalf("rename root: %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("replace root: %v", err)
	}
	ctx, cancel := testContext(t)
	if _, err := store.Inspect(ctx); err != nil {
		t.Fatalf("open store lost retained root: %v", err)
	}
	cancel()
	fresh, err := OpenStore(StoreConfig{
		Root:             root,
		Identity:         identity,
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open replacement root: %v", err)
	}
	defer fresh.Close()
	ctx, cancel = testContext(t)
	if _, err := fresh.Inspect(ctx); err == nil {
		t.Fatal("fresh store accepted replacement root")
	}
	cancel()

	holderPath := filepath.Join(oldRoot, holderDirName)
	oldHolderPath := holderPath + ".old"
	if err := os.Rename(holderPath, oldHolderPath); err != nil {
		t.Fatalf("rename holders: %v", err)
	}
	if err := os.Mkdir(holderPath, 0o700); err != nil {
		t.Fatalf("replace holders: %v", err)
	}
	ctx, cancel = testContext(t)
	if _, err := store.Inspect(ctx); err != nil {
		t.Fatalf("open store lost retained holder directory: %v", err)
	}
	cancel()
	holderReplacement, err := OpenStore(StoreConfig{
		Root:             oldRoot,
		Identity:         identity,
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open holder replacement root: %v", err)
	}
	ctx, cancel = testContext(t)
	if _, err := holderReplacement.Inspect(ctx); err == nil {
		t.Fatal("fresh store accepted replacement holder directory")
	}
	cancel()
	if err := holderReplacement.Close(); err != nil {
		t.Fatalf("close holder replacement store: %v", err)
	}

	lockPath := filepath.Join(oldRoot, "fleet.lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("unlink lock: %v", err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("replace lock: %v", err)
	}
	reopened, err := OpenStore(StoreConfig{
		Root:             oldRoot,
		Identity:         identity,
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open old root: %v", err)
	}
	defer reopened.Close()
	ctx, cancel = testContext(t)
	if _, err := reopened.Inspect(ctx); err == nil {
		t.Fatal("replacement lock inode accepted")
	}
	cancel()
}

func TestPrivateTypesModesLinksAndDeadlineAreRequired(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "fleet")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	identity := &identityStub{
		bootID:  "boot-a",
		startID: map[int]string{os.Getpid(): "start-a"},
	}
	config := StoreConfig{
		Root:             root,
		Identity:         identity,
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	}
	if _, err := OpenStore(config); err == nil {
		t.Fatal("world-readable root accepted")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	store, err := OpenStore(config)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()
	if _, err := store.Handoff(context.Background(), HandoffRequest{}); !errors.Is(err, ErrDeadlineRequired) {
		t.Fatalf("missing deadline err=%v", err)
	}
	bootstrap(t, store, FleetPortable)
	headerPath := filepath.Join(root, headerName)
	if err := os.Link(headerPath, headerPath+".link"); err != nil {
		t.Fatalf("hard link header: %v", err)
	}
	ctx, cancel := testContext(t)
	if _, err := store.Inspect(ctx); err == nil {
		t.Fatal("multiply-linked header accepted")
	}
	cancel()
}

func TestCrashReleasedGuardRecordIsRetiredUnderExclusiveHandoff(t *testing.T) {
	store, _, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	guard := acquire(t, store, FleetPortable, 1, "crashed").(*heldGuard)
	if err := unlockAndClose(guard.lockFD); err != nil {
		t.Fatalf("simulate crash unlock: %v", err)
	}
	guard.lockFD = -1

	request := HandoffRequest{
		From:               FleetPortable,
		To:                 FleetLegacy,
		ExpectedGeneration: 1,
	}
	request.OperationID = HandoffOperationID(1, FleetPortable, FleetLegacy)
	ctx, cancel := testContext(t)
	header, err := store.Handoff(ctx, request)
	cancel()
	if err != nil {
		t.Fatalf("handoff after simulated crash: %v", err)
	}
	if header.Generation != 2 || header.ActiveFleet != FleetLegacy {
		t.Fatalf("header = %+v", header)
	}
	ctx, cancel = testContext(t)
	snapshot, err := store.Inspect(ctx)
	cancel()
	if err != nil || len(snapshot.Holders) != 0 {
		t.Fatalf("stale holder remained: snapshot=%+v err=%v", snapshot, err)
	}
}

func TestBoundedRaceIterationsNeverObserveTwoFleets(t *testing.T) {
	for iteration := 0; iteration < 10; iteration++ {
		store, _, _ := newTestStore(t)
		header := bootstrap(t, store, FleetPortable)
		for cycle := 0; cycle < 4; cycle++ {
			guard := acquire(
				t,
				store,
				header.ActiveFleet,
				header.Generation,
				"runner-"+time.Now().UTC().Format("150405.000000000"),
			)
			if guard.Header().ActiveFleet != header.ActiveFleet {
				t.Fatalf("cycle %d guard/header fleet mismatch", cycle)
			}
			if err := guard.Close(); err != nil {
				t.Fatalf("cycle %d close: %v", cycle, err)
			}
			next := FleetLegacy
			if header.ActiveFleet == FleetLegacy {
				next = FleetPortable
			}
			request := HandoffRequest{
				From:               header.ActiveFleet,
				To:                 next,
				ExpectedGeneration: header.Generation,
			}
			request.OperationID = HandoffOperationID(
				request.ExpectedGeneration,
				request.From,
				request.To,
			)
			ctx, cancel := testContext(t)
			var err error
			header, err = store.Handoff(ctx, request)
			cancel()
			if err != nil {
				t.Fatalf("cycle %d handoff: %v", cycle, err)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatalf("iteration %d close: %v", iteration, err)
		}
	}
}

func TestStateRejectsNoncanonicalUnknownAndTrailingData(t *testing.T) {
	store, root, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	headerPath := filepath.Join(root, "fleet.json")
	original, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	tests := [][]byte{
		append(append([]byte(nil), original...), '\n'),
		[]byte(`{"version":1,"unknown":true}` + "\n"),
		[]byte(" {}\n"),
	}
	for index, content := range tests {
		if err := os.WriteFile(headerPath, content, 0o600); err != nil {
			t.Fatalf("write tamper %d: %v", index, err)
		}
		ctx, cancel := testContext(t)
		if _, err := store.Inspect(ctx); err == nil {
			t.Fatalf("tamper %d accepted", index)
		}
		cancel()
	}
}
