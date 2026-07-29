package main

import (
	"bytes"
	"context"
	"errors"
	"io"
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

type testOwnershipPool struct {
	mu   sync.Mutex
	held bool
}

func (p *testOwnershipPool) Acquire(string) (io.Closer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		return nil, errors.New("ownership held")
	}
	p.held = true
	return &testCloser{close: func() {
		p.mu.Lock()
		p.held = false
		p.mu.Unlock()
	}}, nil
}

type testControllerProcess struct {
	runEntered chan struct{}
	wait       bool
	closeCalls int
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
		Clock:            time.Now,
		IsRoot:           func() bool { return true },
		AcquireOwnership: func(string) (io.Closer, error) { return &testCloser{}, nil },
		OpenController:   func(context.Context, string, string) (controllerProcess, error) { return &testControllerProcess{}, nil },
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
		context.Context,
		string,
		string,
	) (controllerProcess, error) {
		openCalls++
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
