package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

// fakeAcquisitionService stands in for controller.Service: Run marks it
// ready once released, and returns runErr when its context ends.
type fakeAcquisitionService struct {
	testLiveAdmin
	ready   atomic.Bool
	release chan struct{}
	entered chan struct{}
	runErr  error
	sets    atomic.Int32
}

func (service *fakeAcquisitionService) SetAcquisition(
	ctx context.Context,
	change controller.AcquisitionChange,
) (controller.PolicyStatus, error) {
	service.sets.Add(1)
	return service.testLiveAdmin.SetAcquisition(ctx, change)
}

func newFakeAcquisitionService() *fakeAcquisitionService {
	return &fakeAcquisitionService{
		release: make(chan struct{}),
		entered: make(chan struct{}),
	}
}

func (service *fakeAcquisitionService) Run(ctx context.Context) error {
	close(service.entered)
	select {
	case <-service.release:
		service.ready.Store(true)
	case <-ctx.Done():
	}
	<-ctx.Done()
	service.ready.Store(false)
	return service.runErr
}

func (service *fakeAcquisitionService) Ready() bool { return service.ready.Load() }

type acquisitionProcessFixture struct {
	process    *acquisitionControllerProcess
	service    *fakeAcquisitionService
	fenceLost  chan struct{}
	sessions   *sessionCloseCounter
	resources  *testCloser
	ownership  *testOwnershipLease
	adminPath  string
	healthPath string
}

func newAcquisitionProcessFixture(t *testing.T) *acquisitionProcessFixture {
	t.Helper()
	root, err := os.MkdirTemp(shortTestTempRoot(), "pgh-acquire-")
	if err != nil {
		t.Fatalf("make process root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove process root: %v", err)
		}
	})
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod process root: %v", err)
	}
	fixture := &acquisitionProcessFixture{
		process:    &acquisitionControllerProcess{},
		service:    newFakeAcquisitionService(),
		fenceLost:  make(chan struct{}),
		sessions:   &sessionCloseCounter{},
		resources:  &testCloser{},
		ownership:  &testOwnershipLease{},
		adminPath:  filepath.Join(root, "admin.sock"),
		healthPath: filepath.Join(root, "health.sock"),
	}
	if err := fixture.process.init(acquisitionProcessConfig{
		Service:          fixture.service,
		FenceLost:        fixture.fenceLost,
		CloseSessions:    fixture.sessions.Close,
		Resources:        fixture.resources,
		Ownership:        fixture.ownership,
		AdminSocketPath:  fixture.adminPath,
		HealthSocketPath: fixture.healthPath,
		ExpectedUID:      uint32(os.Geteuid()),
		AdmissionLimit:   2,
		OperationTimeout: time.Second,
		OwnershipCheck:   5 * time.Millisecond,
		DrainTimeout:     time.Second,
		ShutdownTimeout:  time.Second,
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	return fixture
}

func (fixture *acquisitionProcessFixture) start(t *testing.T) <-chan error {
	t.Helper()
	return fixture.startWith(t, context.Background())
}

func (fixture *acquisitionProcessFixture) startWith(t *testing.T, ctx context.Context) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- fixture.process.Run(ctx) }()
	waitForLocalSocket(t, fixture.adminPath)
	waitForLocalSocket(t, fixture.healthPath)
	return result
}

func waitForRun(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
		return nil
	}
}

func healthStatus(t *testing.T, path string) localStatus {
	t.Helper()
	request, err := marshalLocalRequest(localRequest{
		SchemaVersion:    localProtocolSchemaVersion,
		Method:           localMethodHealth,
		DeadlineUnixNano: time.Now().Add(time.Second).UnixNano(),
	})
	if err != nil {
		t.Fatalf("marshal health request: %v", err)
	}
	response, err := parseLocalResponse(localMethodHealth, rawLocalExchange(t, path, request))
	if err != nil {
		t.Fatalf("parse health response: %v", err)
	}
	return response.Status
}

func TestAcquisitionProcessServesSocketsAndStopsCleanlyOnSignal(t *testing.T) {
	fixture := newAcquisitionProcessFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := fixture.startWith(t, ctx)

	// Health follows the service: unavailable until startup recovery ends.
	if status := healthStatus(t, fixture.healthPath); status != localStatusUnavailable {
		t.Fatalf("health before ready = %q, want unavailable", status)
	}
	close(fixture.service.release)
	deadline := time.Now().Add(time.Second)
	for healthStatus(t, fixture.healthPath) != localStatusOK {
		if time.Now().After(deadline) {
			t.Fatal("health never reported ready")
		}
		time.Sleep(time.Millisecond)
	}
	admin, err := newLocalAdminClient(fixture.adminPath, uint32(os.Geteuid()), time.Second)
	if err != nil {
		t.Fatalf("newLocalAdminClient: %v", err)
	}
	if _, err := admin.SetAcquisition(context.Background(), controller.AcquisitionChange{
		Set:      controller.AcquisitionDisabled,
		Expected: controller.AcquisitionDisabled,
	}); err != nil || fixture.service.sets.Load() != 1 {
		t.Fatalf("SetAcquisition = %v, service saw %d changes", err, fixture.service.sets.Load())
	}

	cancel()
	if err := waitForRun(t, result); err != nil {
		t.Fatalf("Run after signal = %v, want nil", err)
	}
	for _, path := range []string{fixture.adminPath, fixture.healthPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket %s after Run: %v", path, err)
		}
	}
	if err := fixture.process.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := fixture.process.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if fixture.resources.Count() != 1 || fixture.ownership.CountClosed() != 1 {
		t.Fatalf("closed resources %d, ownership %d; want 1 each",
			fixture.resources.Count(), fixture.ownership.CountClosed())
	}
}

func TestAcquisitionProcessExitsWithAnErrorUnlessSignaled(t *testing.T) {
	tests := map[string]struct {
		stop func(*acquisitionProcessFixture)
		want error
	}{
		"persisted fatal state": {
			stop: func(fixture *acquisitionProcessFixture) {
				terminator := &processTerminator{
					stderr: &bytes.Buffer{},
					cancel: func() { fixture.process.stop(errAcquisitionFatal) },
				}
				terminator.TerminateAfterPersist(controller.ReasonCode(3))
			},
			want: errAcquisitionFatal,
		},
		"lost fence guard": {
			stop: func(fixture *acquisitionProcessFixture) { close(fixture.fenceLost) },
			want: errAcquisitionFenceLost,
		},
		"lost ownership lock": {
			stop: func(fixture *acquisitionProcessFixture) {
				fixture.ownership.SetValidateError(errors.New("lock replaced"))
			},
			want: errAcquisitionOwnership,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newAcquisitionProcessFixture(t)
			result := fixture.start(t)
			<-fixture.service.entered
			test.stop(fixture)
			if err := waitForRun(t, result); !errors.Is(err, test.want) {
				t.Fatalf("Run = %v, want %v", err, test.want)
			}
			if err := fixture.process.Close(); err != nil {
				t.Fatalf("Close after a stopped run: %v", err)
			}
		})
	}
}

func TestAcquisitionProcessReturnsTheServiceError(t *testing.T) {
	fixture := newAcquisitionProcessFixture(t)
	fixture.service.runErr = controller.ErrStartupRestore
	ctx, cancel := context.WithCancel(context.Background())
	result := fixture.startWith(t, ctx)
	cancel()
	if err := waitForRun(t, result); !errors.Is(err, controller.ErrStartupRestore) {
		t.Fatalf("Run = %v, want the service error", err)
	}
}

func TestAcquisitionProcessKeepsResourcesUntilRunHasClosedItsServers(t *testing.T) {
	fixture := newAcquisitionProcessFixture(t)
	if err := fixture.process.Close(); !errors.Is(err, controller.ErrRuntimeShutdown) {
		t.Fatalf("Close before Run = %v, want ErrRuntimeShutdown", err)
	}
	if fixture.resources.Count() != 0 || fixture.ownership.CountClosed() != 0 {
		t.Fatal("Close before Run released resources")
	}
}

func TestAcquisitionProcessInitRejectsAnIncompleteConfig(t *testing.T) {
	valid := acquisitionProcessConfig{
		Service:          newFakeAcquisitionService(),
		CloseSessions:    func() error { return nil },
		Resources:        &testCloser{},
		Ownership:        &testOwnershipLease{},
		AdminSocketPath:  "/run/a.sock",
		HealthSocketPath: "/run/h.sock",
		AdmissionLimit:   1,
		OperationTimeout: time.Second,
		OwnershipCheck:   time.Second,
		DrainTimeout:     time.Second,
		ShutdownTimeout:  time.Second,
	}
	if err := (&acquisitionControllerProcess{}).init(valid); err != nil {
		t.Fatalf("init(valid) = %v", err)
	}
	tests := map[string]func(*acquisitionProcessConfig){
		"no service":         func(config *acquisitionProcessConfig) { config.Service = nil },
		"no session closer":  func(config *acquisitionProcessConfig) { config.CloseSessions = nil },
		"no resources":       func(config *acquisitionProcessConfig) { config.Resources = nil },
		"no ownership":       func(config *acquisitionProcessConfig) { config.Ownership = nil },
		"one socket path":    func(config *acquisitionProcessConfig) { config.HealthSocketPath = config.AdminSocketPath },
		"no admission":       func(config *acquisitionProcessConfig) { config.AdmissionLimit = 0 },
		"no shutdown time":   func(config *acquisitionProcessConfig) { config.ShutdownTimeout = 0 },
		"no ownership check": func(config *acquisitionProcessConfig) { config.OwnershipCheck = 0 },
	}
	for name, mutate := range tests {
		config := valid
		mutate(&config)
		if err := (&acquisitionControllerProcess{}).init(config); err == nil {
			t.Errorf("%s: init accepted the config", name)
		}
	}
}

type sessionCloseCounter struct{ calls atomic.Int32 }

func (counter *sessionCloseCounter) Close() error {
	counter.calls.Add(1)
	return nil
}

func TestAcquisitionProcessClosesSessionsOnEveryPath(t *testing.T) {
	t.Run("after the service returns", func(t *testing.T) {
		fixture := newAcquisitionProcessFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		result := fixture.startWith(t, ctx)
		cancel()
		if err := waitForRun(t, result); err != nil {
			t.Fatalf("Run = %v", err)
		}
		if got := fixture.sessions.calls.Load(); got != 1 {
			t.Fatalf("session closes = %d, want 1", got)
		}
	})
	t.Run("when stopped before it started", func(t *testing.T) {
		fixture := newAcquisitionProcessFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := fixture.process.Run(ctx); err != nil {
			t.Fatalf("Run after a pre-start signal = %v, want a clean stop", err)
		}
		if got := fixture.sessions.calls.Load(); got != 1 {
			t.Fatalf("session closes = %d, want 1", got)
		}
		if err := fixture.process.Close(); err != nil {
			t.Fatalf("Close after an unstarted run: %v", err)
		}
		if fixture.resources.Count() != 1 || fixture.ownership.CountClosed() != 1 {
			t.Fatal("Close after an unstarted run did not release resources")
		}
	})
}
