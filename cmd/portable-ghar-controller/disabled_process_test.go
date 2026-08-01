package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

func TestDisabledControllerProcessServesClosedAdminAndHealthSockets(
	t *testing.T,
) {
	fixture := newDisabledProcessFixture(t, time.Second)
	process := fixture.process
	adminPath := fixture.adminPath
	healthPath := fixture.healthPath

	runCtx, cancelRun := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() {
		runResult <- process.Run(runCtx)
	}()
	waitForLocalSocket(t, adminPath)
	waitForLocalSocket(t, healthPath)
	admin, err := newLocalAdminClient(
		adminPath,
		uint32(os.Geteuid()),
		time.Second,
	)
	if err != nil {
		t.Fatalf("newLocalAdminClient() error = %v", err)
	}
	waitForAdminReady(t, admin)
	healthRequest, err := marshalLocalRequest(localRequest{
		SchemaVersion:    localProtocolSchemaVersion,
		Method:           localMethodHealth,
		DeadlineUnixNano: time.Now().Add(time.Second).UnixNano(),
	})
	if err != nil {
		t.Fatalf("marshal health request: %v", err)
	}
	healthResponseDocument := rawLocalExchange(
		t,
		healthPath,
		healthRequest,
	)
	healthResponse, err := parseLocalResponse(
		localMethodHealth,
		healthResponseDocument,
	)
	if err != nil ||
		healthResponse.Status != localStatusOK ||
		healthResponse.Reason != localReasonNone {
		t.Fatalf(
			"health response = (%#v, %v)",
			healthResponse,
			err,
		)
	}

	cancelRun()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not stop")
	}
	if _, err := os.Lstat(adminPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("admin socket after Run = %v", err)
	}
	if _, err := os.Lstat(healthPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("health socket after Run = %v", err)
	}
	if err := process.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if fixture.store.Count() != 1 ||
		fixture.ownership.CountClosed() != 1 {
		t.Fatalf(
			"close counts store=%d ownership=%d",
			fixture.store.Count(),
			fixture.ownership.CountClosed(),
		)
	}
}

func TestDisabledControllerProcessProvesFleetBeforeCreatingSockets(
	t *testing.T,
) {
	fixture, config := newDisabledProcessConfigFixture(t, time.Second)
	socketsObserved := false
	config.Admin.Fleet = fleetAuthorityFunc(func(
		context.Context,
	) (fleetAuthorityProof, error) {
		if _, err := os.Lstat(fixture.adminPath); err == nil {
			socketsObserved = true
		}
		if _, err := os.Lstat(fixture.healthPath); err == nil {
			socketsObserved = true
		}
		return fleetAuthorityProof{}, errDisabledFleetAuthority
	})
	process, err := newDisabledControllerProcess(config)
	if err != nil {
		t.Fatalf("newDisabledControllerProcess() error = %v", err)
	}
	runErr := process.Run(context.Background())
	if !errors.Is(runErr, controller.ErrRuntimeUnavailable) {
		t.Fatalf("Run() error = %v", runErr)
	}
	if socketsObserved {
		t.Fatal("fleet proof observed local sockets before authority prepared")
	}
	if _, err := os.Lstat(fixture.adminPath); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("admin socket after failed prepare = %v", err)
	}
	if _, err := os.Lstat(fixture.healthPath); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("health socket after failed prepare = %v", err)
	}
}

func TestDisabledControllerProcessStopsAdmissionBeforeBoundedEffectJoin(
	t *testing.T,
) {
	fixture := newDisabledProcessFixture(t, 60*time.Millisecond)
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.authority.SetDrain(func(context.Context) error {
		close(entered)
		<-release
		return nil
	})
	runCtx, cancelRun := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() {
		runResult <- fixture.process.Run(runCtx)
	}()
	waitForLocalSocket(t, fixture.adminPath)
	admin, err := newLocalAdminClient(
		fixture.adminPath,
		uint32(os.Geteuid()),
		time.Second,
	)
	if err != nil {
		t.Fatalf("newLocalAdminClient() error = %v", err)
	}
	waitForAdminReady(t, admin)
	drainResult := make(chan error, 1)
	go func() {
		drainCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		drainResult <- admin.Drain(drainCtx, controller.DrainWait)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Drain() did not enter cancellation-ignoring authority")
	}

	cancelRun()
	waitForLocalDialFailure(t, fixture.adminPath)
	select {
	case err := <-runResult:
		if !errors.Is(err, errShutdownEffectStuck) {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() exceeded bounded shutdown")
	}
	if err := fixture.process.Close(); !errors.Is(
		err,
		controller.ErrRuntimeShutdown,
	) {
		t.Fatalf("Close() with live effect error = %v", err)
	}
	if fixture.store.Count() != 0 ||
		fixture.ownership.CountClosed() != 0 {
		t.Fatalf(
			"live-effect close counts store=%d ownership=%d",
			fixture.store.Count(),
			fixture.ownership.CountClosed(),
		)
	}

	close(release)
	select {
	case err := <-drainResult:
		if !errors.Is(err, controller.ErrRuntimeUnavailable) {
			t.Fatalf("late Drain() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late Drain() did not finish")
	}
	waitForLocalSocketRemoval(t, fixture.adminPath)
	waitForLocalSocketRemoval(t, fixture.healthPath)
}

type disabledProcessFixture struct {
	process    *disabledControllerProcess
	authority  *completeAuthorityFixture
	ownership  *testOwnershipLease
	store      *testCloser
	adminPath  string
	healthPath string
}

type fleetAuthorityFunc func(
	context.Context,
) (fleetAuthorityProof, error)

func (function fleetAuthorityFunc) Observe(
	ctx context.Context,
) (fleetAuthorityProof, error) {
	return function(ctx)
}

func newDisabledProcessFixture(
	t *testing.T,
	shutdownTimeout time.Duration,
) *disabledProcessFixture {
	t.Helper()
	fixture, config := newDisabledProcessConfigFixture(
		t,
		shutdownTimeout,
	)
	process, err := newDisabledControllerProcess(config)
	if err != nil {
		t.Fatalf("newDisabledControllerProcess() error = %v", err)
	}
	fixture.process = process
	return fixture
}

func newDisabledProcessConfigFixture(
	t *testing.T,
	shutdownTimeout time.Duration,
) (*disabledProcessFixture, disabledControllerProcessConfig) {
	t.Helper()
	root, err := os.MkdirTemp(shortTestTempRoot(), "pgh-process-")
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
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	transitions := &observerTransitionFixture{
		policy: controller.AcquisitionPolicy{
			Mode:                     controller.AcquisitionEnabled,
			EligibleScaleSets:        []string{"scale-a"},
			MaxCapacity:              1,
			RepositoryPolicyRevision: 7,
			RepositoryPolicies:       disabledObserverPolicy().RepositoryPolicies,
			Epoch:                    4,
		},
	}
	authority := &completeAuthorityFixture{
		observation: localObservation{
			Sequence:   1,
			ObservedAt: now.Add(-time.Second),
			Complete:   true,
		},
		receipt: controller.CycleReceipt{
			CycleID:     "cycle-process",
			CompletedAt: now,
		},
	}
	fleet := &fleetAuthorityFixture{
		proof: fleetAuthorityProof{
			Sequence:       1,
			ObservedAt:     now.Add(-time.Second),
			Fleet:          fleetfence.FleetPortable,
			Generation:     17,
			SelfGuardToken: "process-self-guard",
		},
	}
	ownership := &testOwnershipLease{}
	store := &testCloser{}
	external := newUnavailableExternalGraph()
	adminPath := filepath.Join(root, "admin.sock")
	healthPath := filepath.Join(root, "health.sock")
	config := disabledControllerProcessConfig{
		Admin: disabledAdminConfig{
			Transitions:        transitions,
			Authority:          authority,
			Broker:             mustZeroDemandBroker(t, 4),
			Fleet:              fleet,
			External:           &external,
			Ownership:          ownership,
			Desired:            disabledObserverPolicy(),
			ExpectedFleet:      fleetfence.FleetPortable,
			ExpectedGeneration: 17,
			ObservationMaxAge:  2 * time.Second,
			Now:                func() time.Time { return now },
		},
		StoreCloser:           store,
		AdminSocketPath:       adminPath,
		HealthSocketPath:      healthPath,
		ExpectedUID:           uint32(os.Geteuid()),
		AdmissionLimit:        2,
		IOTimeout:             100 * time.Millisecond,
		OperationTimeout:      time.Second,
		DrainTimeout:          time.Second,
		ReconciliationCadence: time.Hour,
		ShutdownTimeout:       shutdownTimeout,
	}
	return &disabledProcessFixture{
		authority:  authority,
		ownership:  ownership,
		store:      store,
		adminPath:  adminPath,
		healthPath: healthPath,
	}, config
}

func waitForLocalSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("socket %s did not appear", path)
}

func waitForAdminReady(t *testing.T, admin *localAdminClient) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		status, err := admin.Probe(probeCtx)
		cancel()
		if err == nil &&
			status.Mode == controller.AcquisitionDisabled &&
			status.Epoch == 5 &&
			status.Capacity == 0 &&
			len(status.Digest) == 64 &&
			strings.ToLower(status.Digest) == status.Digest {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("admin socket did not become ready")
}

func waitForLocalDialFailure(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout(
			"unix",
			path,
			10*time.Millisecond,
		)
		if err != nil {
			return
		}
		_ = connection.Close()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("socket %s continued accepting", path)
}

func waitForLocalSocketRemoval(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("socket %s was not removed", path)
}
