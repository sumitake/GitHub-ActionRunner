package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

type testCloser struct {
	mu     sync.Mutex
	closed int
	close  func()
}

func (c *testCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	if c.close != nil {
		c.close()
	}
	return nil
}

func (c *testCloser) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type testOwnershipLease struct {
	mu            sync.Mutex
	closed        int
	validateCalls int
	validateErr   error
	close         func()
}

func (lease *testOwnershipLease) Validate() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.validateCalls++
	return lease.validateErr
}

func (lease *testOwnershipLease) Close() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.closed++
	if lease.close != nil {
		lease.close()
	}
	return nil
}

func (lease *testOwnershipLease) Counts() (int, int) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.validateCalls, lease.closed
}

func (lease *testOwnershipLease) CountClosed() int {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.closed
}

func (lease *testOwnershipLease) SetValidateError(err error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.validateErr = err
}

type testOwnershipPool struct {
	mu   sync.Mutex
	held bool
}

func (p *testOwnershipPool) Acquire(
	string,
) (controllerOwnershipLease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		return nil, errors.New("ownership held")
	}
	p.held = true
	return &testOwnershipLease{close: func() {
		p.mu.Lock()
		p.held = false
		p.mu.Unlock()
	}}, nil
}

type testControllerProcess struct {
	runEntered     chan struct{}
	wait           bool
	closeCalls     int
	ownership      controllerOwnershipLease
	closeOwnership bool
}

func (p *testControllerProcess) Run(ctx context.Context) error {
	if p.runEntered != nil {
		close(p.runEntered)
	}
	if p.wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (p *testControllerProcess) Close() error {
	p.closeCalls++
	if p.closeOwnership && p.ownership != nil {
		return p.ownership.Close()
	}
	return nil
}

type testLiveAdmin struct {
	probeStatus    controller.PolicyStatus
	reconcileCalls int
	drainCalls     []controller.DrainPolicy
	changes        []controller.AcquisitionChange
}

func (a *testLiveAdmin) Probe(context.Context) (controller.PolicyStatus, error) {
	return a.probeStatus, nil
}

func (a *testLiveAdmin) ReconcileOnce(
	context.Context,
) (controller.CycleReceipt, error) {
	a.reconcileCalls++
	return controller.CycleReceipt{}, nil
}

func (a *testLiveAdmin) Drain(
	_ context.Context,
	policy controller.DrainPolicy,
) error {
	a.drainCalls = append(a.drainCalls, policy)
	return nil
}

func (a *testLiveAdmin) SetAcquisition(
	_ context.Context,
	change controller.AcquisitionChange,
) (controller.PolicyStatus, error) {
	a.changes = append(a.changes, change)
	return controller.PolicyStatus{
		Mode:   change.Set,
		Epoch:  11,
		Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Capacity: map[controller.AcquisitionMode]int{
			controller.AcquisitionDisabled:   0,
			controller.AcquisitionCanaryOnly: 1,
			controller.AcquisitionEnabled:    4,
		}[change.Set],
	}, nil
}

func testCommandDeps() commandDependencies {
	return commandDependencies{
		Clock:  time.Now,
		IsRoot: func() bool { return true },
		AcquireOwnership: func(string) (controllerOwnershipLease, error) {
			return &testOwnershipLease{}, nil
		},
		OpenController: func(
			context.Context,
			string,
			string,
			controllerOwnershipLease,
		) (controllerProcess, error) {
			return &testControllerProcess{}, nil
		},
		DialAdmin: func(context.Context) (controller.LiveAdmin, io.Closer, error) {
			return &testLiveAdmin{}, &testCloser{}, nil
		},
		AdminTimeout:      time.Second,
		DrainTimeout:      time.Second,
		StatusReadTimeout: time.Second,
	}
}

func TestControllerCLIExactParserRejectsUnknownDuplicateMissingAndTrailing(
	t *testing.T,
) {
	tests := [][]string{
		{"--json", "--json"},
		{"--unknown"},
		{"trailing"},
		{"--config"},
		{"--json=true"},
		{"--config="},
	}
	allowed := map[string]bool{"json": false, "config": true}
	for _, args := range tests {
		if _, err := parseExactFlags(args, allowed); err == nil {
			t.Errorf("parseExactFlags(%v) = nil error", args)
		}
	}
	got, err := parseExactFlags(
		[]string{"--json", "--config=runtime.json"},
		allowed,
	)
	if err != nil || got["json"] != "true" || got["config"] != "runtime.json" {
		t.Fatalf("parseExactFlags(valid) = (%v, %v)", got, err)
	}
}

func TestControllerCLIRunRequiresRootAndExclusiveOwnership(t *testing.T) {
	pool := &testOwnershipPool{}
	process := &testControllerProcess{
		runEntered: make(chan struct{}),
		wait:       true,
	}
	openCalls := 0
	deps := testCommandDeps()
	deps.AcquireOwnership = pool.Acquire
	deps.OpenController = func(
		_ context.Context,
		_ string,
		_ string,
		ownership controllerOwnershipLease,
	) (controllerProcess, error) {
		openCalls++
		process.ownership = ownership
		process.closeOwnership = true
		return process, nil
	}
	deps.IsRoot = func() bool { return false }
	var stdout, stderr bytes.Buffer
	if exit := runWithDependencies(
		context.Background(),
		[]string{"run", "--config", "runtime.json", "--database", "state.db"},
		&stdout,
		&stderr,
		deps,
	); exit != 1 || openCalls != 0 {
		t.Fatalf("non-root run = exit %d opens %d", exit, openCalls)
	}

	deps.IsRoot = func() bool { return true }
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan int, 1)
	go func() {
		var firstOut, firstErr bytes.Buffer
		firstResult <- runWithDependencies(
			firstCtx,
			[]string{"run", "--config", "runtime.json", "--database", "state.db"},
			&firstOut,
			&firstErr,
			deps,
		)
	}()
	select {
	case <-process.runEntered:
	case <-time.After(time.Second):
		t.Fatal("first run did not enter controller")
	}
	stdout.Reset()
	stderr.Reset()
	if exit := runWithDependencies(
		context.Background(),
		[]string{"run", "--config", "runtime.json", "--database", "state.db"},
		&stdout,
		&stderr,
		deps,
	); exit != 1 {
		t.Fatalf("second run exit = %d, want 1", exit)
	}
	if openCalls != 1 {
		t.Fatalf("second run reached controller factory: calls=%d", openCalls)
	}
	cancelFirst()
	select {
	case <-firstResult:
	case <-time.After(time.Second):
		t.Fatal("first run did not release ownership")
	}
	if process.closeCalls != 1 {
		t.Fatalf("controller close calls = %d, want 1", process.closeCalls)
	}
}

func TestControllerCLIRunTransfersExactOwnershipLeaseToProcess(
	t *testing.T,
) {
	lease := &testOwnershipLease{}
	process := &testControllerProcess{closeOwnership: true}
	deps := testCommandDeps()
	deps.AcquireOwnership = func(string) (controllerOwnershipLease, error) {
		return lease, nil
	}
	deps.OpenController = func(
		_ context.Context,
		_ string,
		_ string,
		got controllerOwnershipLease,
	) (controllerProcess, error) {
		if got != lease {
			t.Fatal("OpenController did not receive exact ownership lease")
		}
		process.ownership = got
		return process, nil
	}
	var stdout, stderr bytes.Buffer
	if exit := runWithDependencies(
		context.Background(),
		[]string{"run", "--config", "runtime.json", "--database", "state.db"},
		&stdout,
		&stderr,
		deps,
	); exit != 0 {
		t.Fatalf("run exit = %d, stderr = %q", exit, stderr.String())
	}
	validateCalls, closeCalls := lease.Counts()
	if validateCalls != 1 {
		t.Fatalf("ownership validation calls = %d, want 1", validateCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("ownership close calls = %d, want process-owned 1", closeCalls)
	}
	if process.closeCalls != 1 {
		t.Fatalf("process close calls = %d, want 1", process.closeCalls)
	}
}

func TestControllerCLIRunClosesUntransferredOwnershipLease(
	t *testing.T,
) {
	t.Run("validation failure", func(t *testing.T) {
		lease := &testOwnershipLease{validateErr: errors.New("invalid lease")}
		openCalls := 0
		deps := testCommandDeps()
		deps.AcquireOwnership = func(string) (controllerOwnershipLease, error) {
			return lease, nil
		}
		deps.OpenController = func(
			context.Context,
			string,
			string,
			controllerOwnershipLease,
		) (controllerProcess, error) {
			openCalls++
			return &testControllerProcess{}, nil
		}
		var stdout, stderr bytes.Buffer
		if exit := runWithDependencies(
			context.Background(),
			[]string{"run", "--config", "runtime.json", "--database", "state.db"},
			&stdout,
			&stderr,
			deps,
		); exit != 1 {
			t.Fatalf("run exit = %d, want 1", exit)
		}
		validateCalls, closeCalls := lease.Counts()
		if validateCalls != 1 || closeCalls != 1 || openCalls != 0 {
			t.Fatalf(
				"validation=%d close=%d open=%d, want 1/1/0",
				validateCalls,
				closeCalls,
				openCalls,
			)
		}
	})

	t.Run("construction failure", func(t *testing.T) {
		lease := &testOwnershipLease{}
		deps := testCommandDeps()
		deps.AcquireOwnership = func(string) (controllerOwnershipLease, error) {
			return lease, nil
		}
		deps.OpenController = func(
			context.Context,
			string,
			string,
			controllerOwnershipLease,
		) (controllerProcess, error) {
			return nil, errors.New("open failed")
		}
		var stdout, stderr bytes.Buffer
		if exit := runWithDependencies(
			context.Background(),
			[]string{"run", "--config", "runtime.json", "--database", "state.db"},
			&stdout,
			&stderr,
			deps,
		); exit != 1 {
			t.Fatalf("run exit = %d, want 1", exit)
		}
		validateCalls, closeCalls := lease.Counts()
		if validateCalls != 1 || closeCalls != 1 {
			t.Fatalf(
				"validation=%d close=%d, want 1/1",
				validateCalls,
				closeCalls,
			)
		}
	})
}

func TestFileOwnershipLeasePinsLockedPathIdentity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "controller.owner.lock")
	lease, err := acquireFileOwnership(path)
	if err != nil {
		t.Fatalf("acquireFileOwnership() error = %v", err)
	}
	if err := lease.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if duplicate, err := acquireFileOwnership(path); err == nil {
		_ = duplicate.Close()
		t.Fatal("second acquireFileOwnership() succeeded")
	}

	oldPath := filepath.Join(root, "controller.owner.old")
	if err := os.Rename(path, oldPath); err != nil {
		t.Fatalf("rename locked path: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := lease.Validate(); err == nil {
		t.Fatal("Validate() accepted replacement path identity")
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	replacement, err := acquireFileOwnership(path)
	if err != nil {
		t.Fatalf("acquire replacement ownership: %v", err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatalf("close replacement ownership: %v", err)
	}
}

func TestFileOwnershipLeaseRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.lock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(root, "controller.owner.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if lease, err := acquireFileOwnership(link); err == nil {
		_ = lease.Close()
		t.Fatal("acquireFileOwnership() accepted symlink")
	}
}

func TestControllerCLIAdminCommandsNeverFallbackWhenLivePortUnavailable(
	t *testing.T,
) {
	deps := testCommandDeps()
	dialCalls := 0
	deps.DialAdmin = func(
		context.Context,
	) (controller.LiveAdmin, io.Closer, error) {
		dialCalls++
		return nil, nil, errors.New("live admin unavailable")
	}
	commands := [][]string{
		{"probe"},
		{"reconcile", "--once"},
		{"drain", "--policy=wait"},
		{
			"acquisition",
			"--set=disabled",
			"--expected=enabled",
			"--json",
		},
	}
	for _, args := range commands {
		var stdout, stderr bytes.Buffer
		if exit := runWithDependencies(
			context.Background(),
			args,
			&stdout,
			&stderr,
			deps,
		); exit != 1 {
			t.Fatalf("%v exit = %d, want 1", args, exit)
		}
		if stdout.Len() != 0 {
			t.Fatalf("%v wrote success output %q", args, stdout.String())
		}
	}
	if dialCalls != len(commands) {
		t.Fatalf("admin dial calls = %d, want %d", dialCalls, len(commands))
	}
}

func TestControllerCLILiveAdminDispatchAndClosedAcquisitionOutput(t *testing.T) {
	admin := &testLiveAdmin{
		probeStatus: controller.PolicyStatus{
			Mode:     controller.AcquisitionDisabled,
			Epoch:    9,
			Digest:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Capacity: 0,
		},
	}
	closer := &testCloser{}
	deps := testCommandDeps()
	deps.IsRoot = func() bool { return false }
	deps.DialAdmin = func(
		context.Context,
	) (controller.LiveAdmin, io.Closer, error) {
		return admin, closer, nil
	}
	var stdout, stderr bytes.Buffer
	if exit := runWithDependencies(
		context.Background(),
		[]string{"probe"},
		&stdout,
		&stderr,
		deps,
	); exit != 0 {
		t.Fatalf("probe exit=%d stderr=%q", exit, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"mode":"disabled"`)) {
		t.Fatalf("probe output = %q", stdout.String())
	}
	deps.IsRoot = func() bool { return true }
	for _, command := range [][]string{
		{"reconcile", "--once"},
		{"drain", "--policy=cancel"},
	} {
		stdout.Reset()
		stderr.Reset()
		if exit := runWithDependencies(
			context.Background(),
			command,
			&stdout,
			&stderr,
			deps,
		); exit != 0 {
			t.Fatalf("%v exit=%d stderr=%q", command, exit, stderr.String())
		}
	}
	stdout.Reset()
	stderr.Reset()
	if exit := runWithDependencies(
		context.Background(),
		[]string{
			"acquisition",
			"--set=canary-only",
			"--expected=disabled",
			"--eligible-scale-set",
			"portable-ghar",
			"--json",
		},
		&stdout,
		&stderr,
		deps,
	); exit != 0 {
		t.Fatalf("acquisition exit=%d stderr=%q", exit, stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte("portable-ghar")) ||
		!bytes.Contains(stdout.Bytes(), []byte(`"capacity":1`)) {
		t.Fatalf("acquisition output leaked eligibility or omitted capacity: %q", stdout.String())
	}
	if admin.reconcileCalls != 1 ||
		len(admin.drainCalls) != 1 ||
		admin.drainCalls[0] != controller.DrainCancel ||
		len(admin.changes) != 1 {
		t.Fatalf(
			"admin calls reconcile=%d drain=%v changes=%+v",
			admin.reconcileCalls,
			admin.drainCalls,
			admin.changes,
		)
	}
	if closer.Count() != 4 {
		t.Fatalf("admin transport closes = %d, want 4", closer.Count())
	}
}

func TestControllerCLIAcquisitionRejectsCanaryFlagShapeBeforeDial(t *testing.T) {
	deps := testCommandDeps()
	dialCalls := 0
	deps.DialAdmin = func(
		context.Context,
	) (controller.LiveAdmin, io.Closer, error) {
		dialCalls++
		return &testLiveAdmin{}, &testCloser{}, nil
	}
	commands := [][]string{
		{
			"acquisition",
			"--set=canary-only",
			"--expected=disabled",
			"--json",
		},
		{
			"acquisition",
			"--set=enabled",
			"--expected=disabled",
			"--eligible-scale-set=portable-ghar",
			"--json",
		},
		{
			"acquisition",
			"--set=fatal",
			"--expected=disabled",
			"--json",
		},
	}
	for _, args := range commands {
		var stdout, stderr bytes.Buffer
		if exit := runWithDependencies(
			context.Background(),
			args,
			&stdout,
			&stderr,
			deps,
		); exit != 2 {
			t.Fatalf("%v exit = %d, want 2", args, exit)
		}
	}
	if dialCalls != 0 {
		t.Fatalf("invalid acquisition commands dialed admin %d times", dialCalls)
	}
}
