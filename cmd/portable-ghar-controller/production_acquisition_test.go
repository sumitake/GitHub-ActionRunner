package main

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/admission"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

type fakeRecoverableLister struct {
	assignments []state.RecoverableAssignment
	err         error
}

func (lister fakeRecoverableLister) ListRecoverable(context.Context) ([]state.RecoverableAssignment, error) {
	return lister.assignments, lister.err
}

type fakeLedgerReleaser struct {
	slots      []networkjail.CapacitySlotID
	referenced map[networkjail.CapacitySlotID]bool
	err        error
}

func (releaser *fakeLedgerReleaser) DeactivateUnreferenced(
	_ context.Context,
	slot networkjail.CapacitySlotID,
) error {
	releaser.slots = append(releaser.slots, slot)
	if releaser.referenced[slot] {
		return networkjail.ErrLedgerReferenced
	}
	return releaser.err
}

func TestClearUnreferencedSlotsReleasesOnlyWhatNoAssignmentReferences(t *testing.T) {
	key := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 7}
	lister := fakeRecoverableLister{assignments: []state.RecoverableAssignment{{Key: key}}}
	ledgers := &fakeLedgerReleaser{referenced: map[networkjail.CapacitySlotID]bool{2: true}}
	var removedRoot string
	var keep map[string]bool
	remove := func(root string, referenced map[string]bool) error {
		removedRoot, keep = root, referenced
		return nil
	}
	if err := clearUnreferencedSlots(
		context.Background(), lister, ledgers, "/srv/brokers", 3, remove,
	); err != nil {
		t.Fatalf("clearUnreferencedSlots: %v", err)
	}
	if len(ledgers.slots) != 3 || ledgers.slots[0] != 1 || ledgers.slots[2] != 3 {
		t.Fatalf("ledger slots = %v, want 1..3", ledgers.slots)
	}
	if removedRoot != "/srv/brokers" || len(keep) != 1 || !keep[controller.OpaqueSlotName(key)] {
		t.Fatalf("directory sweep = %q %v, want the referenced slot kept", removedRoot, keep)
	}
}

func TestClearUnreferencedSlotsFailsClosed(t *testing.T) {
	remove := func(string, map[string]bool) error { return nil }
	listFailure := errors.New("list failed")
	if err := clearUnreferencedSlots(
		context.Background(), fakeRecoverableLister{err: listFailure},
		&fakeLedgerReleaser{}, "/srv/brokers", 1, remove,
	); !errors.Is(err, listFailure) {
		t.Fatalf("list failure = %v", err)
	}
	ledgerFailure := errors.New("ledger failed")
	removed := false
	if err := clearUnreferencedSlots(
		context.Background(), fakeRecoverableLister{},
		&fakeLedgerReleaser{err: ledgerFailure}, "/srv/brokers", 1,
		func(string, map[string]bool) error { removed = true; return nil },
	); !errors.Is(err, ledgerFailure) || removed {
		t.Fatalf("ledger failure = %v, removed %v", err, removed)
	}
	directoryFailure := errors.New("slot not empty")
	if err := clearUnreferencedSlots(
		context.Background(), fakeRecoverableLister{}, &fakeLedgerReleaser{}, "/srv/brokers", 1,
		func(string, map[string]bool) error { return directoryFailure },
	); !errors.Is(err, directoryFailure) {
		t.Fatalf("directory failure = %v", err)
	}
	for _, capacity := range []uint64{0, math.MaxUint32 + 1} {
		if err := clearUnreferencedSlots(
			context.Background(), fakeRecoverableLister{}, &fakeLedgerReleaser{},
			"/srv/brokers", capacity, remove,
		); err == nil {
			t.Fatalf("capacity %d accepted", capacity)
		}
	}
}

type fakePolicyStore struct {
	current     controller.AcquisitionPolicy
	transitions []controller.AcquisitionPolicy
}

func (store *fakePolicyStore) Snapshot(context.Context) (controller.AcquisitionPolicy, error) {
	return store.current, nil
}

func (store *fakePolicyStore) Transition(
	_ context.Context,
	expected uint64,
	next controller.AcquisitionPolicy,
) (controller.AcquisitionPolicy, error) {
	if expected != store.current.Epoch {
		return store.current, controller.ErrAcquisitionEpochMismatch
	}
	store.transitions = append(store.transitions, next)
	next.Epoch = expected + 1
	store.current = next
	return next, nil
}

func TestDurablePolicyEpochSeedsANewDatabaseWithTheDisabledPolicy(t *testing.T) {
	overlay := admittingOverlay(t)
	fresh := &fakePolicyStore{}
	epoch, err := durablePolicyEpoch(context.Background(), fresh, overlay)
	if err != nil || epoch != 1 || len(fresh.transitions) != 1 ||
		fresh.transitions[0].Mode != controller.AcquisitionDisabled {
		t.Fatalf("fresh database = epoch %d, %v, transitions %+v", epoch, err, fresh.transitions)
	}
	// The broker built at that epoch accepts the next one, which the
	// service's startup records.
	config, err := productionAdmissionConfig(overlay, epoch, time.Now)
	if err != nil {
		t.Fatalf("productionAdmissionConfig: %v", err)
	}
	broker, err := admission.NewBroker(config)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	adapter, err := admission.NewControllerAdapter(
		broker, broker.(admission.LiveHistory), config.Repositories, config.TransientMode,
	)
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}
	startup := fresh.transitions[0]
	startup.Epoch = epoch + 1
	if err := adapter.ApplyAcquisitionPolicy(startup); err != nil {
		t.Fatalf("broker rejected the startup epoch: %v", err)
	}

	existing := &fakePolicyStore{current: controller.AcquisitionPolicy{Epoch: 9}}
	if epoch, err := durablePolicyEpoch(context.Background(), existing, overlay); err != nil ||
		epoch != 9 || len(existing.transitions) != 0 {
		t.Fatalf("existing database = epoch %d, %v, transitions %d", epoch, err, len(existing.transitions))
	}
	exhausted := &fakePolicyStore{current: controller.AcquisitionPolicy{Epoch: math.MaxUint64}}
	if _, err := durablePolicyEpoch(context.Background(), exhausted, overlay); err == nil {
		t.Fatal("durablePolicyEpoch accepted an exhausted epoch")
	}
}

func TestJailUserIDTakesANonRootUID(t *testing.T) {
	if uid, err := jailUserID("10001:10001"); err != nil || uid != 10001 {
		t.Fatalf("jailUserID = %d, %v", uid, err)
	}
	for _, user := range []string{"0:0", "10001", ":10001", "-1:0", "4294967296:0", "abc:0", ""} {
		if _, err := jailUserID(user); err == nil {
			t.Errorf("jailUserID(%q) accepted", user)
		}
	}
}

func TestProductionServiceTimingsComeFromTheOverlay(t *testing.T) {
	overlay := templateOverlay(t)
	timings, err := parseProductionServiceTimings(overlay.Controller)
	if err != nil {
		t.Fatalf("parseProductionServiceTimings: %v", err)
	}
	if timings.ack <= 0 || timings.pollCadence <= 0 || timings.hostCapacityMaxAge <= 0 {
		t.Fatalf("timings = %+v", timings)
	}
	overlay.Controller.DrainPollCadence = "often"
	if _, err := parseProductionServiceTimings(overlay.Controller); err == nil {
		t.Fatal("parseProductionServiceTimings accepted a malformed duration")
	}
}

func TestControllerCLIRunAcquisitionUsesItsOwnOpenerAndRunsLock(t *testing.T) {
	var opened []string
	deps := testCommandDeps()
	deps.OpenController = func(
		context.Context, string, string, controllerOwnershipLease,
	) (controllerProcess, error) {
		opened = append(opened, "run")
		return nil, errCommandUnavailable
	}
	var lockPath string
	deps.AcquireOwnership = func(path string) (controllerOwnershipLease, error) {
		lockPath = path
		return &testOwnershipLease{}, nil
	}
	deps.OpenAcquisitionController = func(
		_ context.Context, config string, database string, _ controllerOwnershipLease,
	) (controllerProcess, error) {
		opened = append(opened, "run-acquisition:"+config+":"+database)
		return nil, startupStep("open fence store", nil)
	}
	var stdout, stderr bytes.Buffer
	exit := runWithDependencies(
		context.Background(),
		[]string{"run-acquisition", "--config", "/etc/o.json", "--database", "/var/s.db"},
		&stdout,
		&stderr,
		deps,
	)
	if exit != 1 || len(opened) != 1 || opened[0] != "run-acquisition:/etc/o.json:/var/s.db" ||
		lockPath != "/var/s.db.owner.lock" ||
		!strings.Contains(stderr.String(), "run-acquisition unavailable") ||
		!strings.Contains(stderr.String(), "open fence store") {
		t.Fatalf("exit %d, opened %v, lock %q, stderr %q", exit, opened, lockPath, stderr.String())
	}
	deps.OpenAcquisitionController = nil
	stderr.Reset()
	if exit := runWithDependencies(
		context.Background(), []string{"run-acquisition"}, &stdout, &stderr, deps,
	); exit != 2 {
		t.Fatalf("missing opener exit = %d, want usage", exit)
	}
}

type countingSession struct {
	githubscale.Session
	closes   int
	failures int
}

func (session *countingSession) Close(context.Context) error {
	session.closes++
	if session.failures > 0 {
		session.failures--
		return errors.New("close timed out")
	}
	return nil
}

func TestCloseOnceSessionRetriesAFailedClose(t *testing.T) {
	inner := &countingSession{failures: 1}
	session := &closeOnceSession{Session: inner}
	if err := session.Close(context.Background()); err == nil {
		t.Fatal("first Close hid the upstream failure")
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close after success: %v", err)
	}
	if inner.closes != 2 {
		t.Fatalf("upstream closes = %d, want 2", inner.closes)
	}
}

func TestCloseOnceSessionSendsOnlyTheFirstClose(t *testing.T) {
	inner := &countingSession{}
	session := &closeOnceSession{Session: inner}
	for range 3 {
		if err := session.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	if inner.closes != 1 {
		t.Fatalf("upstream closes = %d, want 1", inner.closes)
	}
}

func TestControllerCLIRunAcquisitionSignalDuringOpenIsACleanStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lease := &testOwnershipLease{}
	deps := testCommandDeps()
	deps.AcquireOwnership = func(string) (controllerOwnershipLease, error) { return lease, nil }
	deps.OpenAcquisitionController = func(
		context.Context, string, string, controllerOwnershipLease,
	) (controllerProcess, error) {
		cancel()
		return nil, startupStep("open GitHub sessions", context.Canceled)
	}
	var stdout, stderr bytes.Buffer
	exit := runWithDependencies(
		ctx,
		[]string{"run-acquisition", "--config", "/etc/o.json", "--database", "/var/s.db"},
		&stdout,
		&stderr,
		deps,
	)
	if exit != 0 || stderr.Len() != 0 || lease.CountClosed() != 1 {
		t.Fatalf("exit %d, stderr %q, lease closes %d", exit, stderr.String(), lease.CountClosed())
	}
}

func TestControllerCLIRunAcquisitionSignalWithFailedCleanupIsAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	deps := testCommandDeps()
	deps.OpenAcquisitionController = func(
		context.Context, string, string, controllerOwnershipLease,
	) (controllerProcess, error) {
		cancel()
		return nil, errors.Join(context.Canceled, errStartupCleanup, errors.New("session close failed"))
	}
	var stdout, stderr bytes.Buffer
	exit := runWithDependencies(
		ctx,
		[]string{"run-acquisition", "--config", "/etc/o.json", "--database", "/var/s.db"},
		&stdout,
		&stderr,
		deps,
	)
	if exit != 1 || !strings.Contains(stderr.String(), "startup cleanup failed") {
		t.Fatalf("exit %d, stderr %q; want the cleanup failure reported", exit, stderr.String())
	}
}

type failingCloseSession struct{ githubscale.Session }

func (failingCloseSession) Close(context.Context) error { return errors.New("close timed out") }

func TestClosePollTargetsMarksAFailedClose(t *testing.T) {
	targets := []controller.PollTarget{{Session: failingCloseSession{}}}
	if err := closePollTargets(context.Background(), targets); !errors.Is(err, errSessionCleanup) {
		t.Fatalf("closePollTargets = %v, want errSessionCleanup", err)
	}
	if err := closePollTargets(context.Background(), nil); err != nil {
		t.Fatalf("closePollTargets(no targets) = %v", err)
	}
}

func TestControllerCLIRunAcquisitionSignalWithOpenSessionIsAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	deps := testCommandDeps()
	deps.OpenAcquisitionController = func(
		context.Context, string, string, controllerOwnershipLease,
	) (controllerProcess, error) {
		cancel()
		// A partial open whose own cleanup failed, as openGitHubPollTargets
		// reports it.
		return nil, errors.Join(context.Canceled, errSessionCleanup)
	}
	var stdout, stderr bytes.Buffer
	if exit := runWithDependencies(
		ctx,
		[]string{"run-acquisition", "--config", "/etc/o.json", "--database", "/var/s.db"},
		&stdout,
		&stderr,
		deps,
	); exit != 1 {
		t.Fatalf("exit %d, stderr %q; want the open session reported", exit, stderr.String())
	}
}

func TestLeaseOverrunExitLogsAndExitsOnce(t *testing.T) {
	var logs bytes.Buffer
	var codes []int
	overrun := &leaseOverrunExit{logs: &logs, exit: func(code int) { codes = append(codes, code) }}
	binding := controller.AcquisitionPermitBinding{OperationKind: "acquire", OperationID: "op-1"}
	overrun.Fire(binding)
	overrun.Fire(binding)
	if len(codes) != 1 || codes[0] == 0 {
		t.Fatalf("exit codes = %v; want one non-zero exit", codes)
	}
	if got := logs.String(); !strings.Contains(got, "acquire operation op-1 outlived its lease budget") ||
		strings.Count(got, "\n") != 1 {
		t.Fatalf("logs = %q", got)
	}
}

func TestProductionResourcesFailMarksACleanupFailure(t *testing.T) {
	primary := errors.New("open failed")
	clean := &productionControllerResources{}
	clean.Add(&testCloser{})
	if err := clean.Fail(primary); err != primary {
		t.Fatalf("Fail with clean cleanup = %v, want the primary error alone", err)
	}
	dirty := &productionControllerResources{}
	dirty.Add(failingCloser{})
	err := dirty.Fail(primary)
	if !errors.Is(err, primary) || !errors.Is(err, errStartupCleanup) {
		t.Fatalf("Fail with failed cleanup = %v, want primary and errStartupCleanup", err)
	}
}

type failingCloser struct{}

func (failingCloser) Close() error { return errors.New("close failed") }

// blockedWriter never completes a write until released, like a stderr pipe
// nobody drains.
type blockedWriter struct{ release chan struct{} }

func (writer blockedWriter) Write(p []byte) (int, error) {
	<-writer.release
	return len(p), nil
}

func TestLeaseOverrunExitDoesNotWaitOnABlockedLog(t *testing.T) {
	writer := blockedWriter{release: make(chan struct{})}
	t.Cleanup(func() { close(writer.release) })
	exited := make(chan int, 1)
	overrun := &leaseOverrunExit{logs: writer, exit: func(code int) { exited <- code }}
	go overrun.Fire(controller.AcquisitionPermitBinding{OperationKind: "acquire", OperationID: "op-1"})
	select {
	case code := <-exited:
		if code == 0 {
			t.Fatal("overrun exited with status 0")
		}
	case <-time.After(10 * leaseOverrunLogWait):
		t.Fatal("overrun exit waited on a blocked log writer")
	}
}
