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

	"github.com/sumitake/portable-ghar/internal/controller"
)

type transitionStub struct {
	mu     sync.Mutex
	policy controller.AcquisitionPolicy
	calls  int
}

func (s *transitionStub) Snapshot(context.Context) (controller.AcquisitionPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy, nil
}

func (s *transitionStub) Transition(
	_ context.Context,
	expected uint64,
	next controller.AcquisitionPolicy,
) (controller.AcquisitionPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.policy.Epoch {
		return controller.AcquisitionPolicy{}, errors.New("epoch conflict")
	}
	next.Epoch = expected + 1
	s.policy = next
	s.calls++
	return next, nil
}

func TestControllerAdapterAcquiresOnlyCurrentPortableGeneration(t *testing.T) {
	store, _, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	adapter, err := NewControllerAdapter(ControllerAdapterConfig{
		Store:           store,
		Generation:      1,
		OwnerID:         "portable-controller",
		PID:             os.Getpid(),
		RenewalInterval: time.Second,
		RenewalTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}
	ctx, cancel := testContext(t)
	guard, err := adapter.AcquirePortable(ctx)
	cancel()
	if err != nil {
		t.Fatalf("AcquirePortable: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("guard close: %v", err)
	}

	stale, err := NewControllerAdapter(ControllerAdapterConfig{
		Store:           store,
		Generation:      2,
		OwnerID:         "stale-controller",
		PID:             os.Getpid(),
		RenewalInterval: time.Second,
		RenewalTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("stale adapter: %v", err)
	}
	ctx, cancel = testContext(t)
	if _, err := stale.AcquirePortable(ctx); err == nil {
		t.Fatal("stale generation acquired")
	}
	cancel()

	request := HandoffRequest{
		From:               FleetPortable,
		To:                 FleetLegacy,
		ExpectedGeneration: 1,
	}
	request.OperationID = HandoffOperationID(1, FleetPortable, FleetLegacy)
	ctx, cancel = testContext(t)
	if _, err := store.Handoff(ctx, request); err != nil {
		t.Fatalf("legacy handoff: %v", err)
	}
	cancel()
	legacy, err := NewControllerAdapter(ControllerAdapterConfig{
		Store:           store,
		Generation:      2,
		OwnerID:         "legacy-controller",
		PID:             os.Getpid(),
		RenewalInterval: time.Second,
		RenewalTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("legacy adapter: %v", err)
	}
	ctx, cancel = testContext(t)
	if _, err := legacy.AcquirePortable(ctx); err == nil {
		t.Fatal("legacy-owned generation acquired portable guard")
	}
	cancel()
}

func TestControllerAdapterRenewalFailureMakesCloseFail(t *testing.T) {
	store, _, identity := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	adapter, err := NewControllerAdapter(ControllerAdapterConfig{
		Store:           store,
		Generation:      1,
		OwnerID:         "portable-controller",
		PID:             os.Getpid(),
		RenewalInterval: time.Millisecond,
		RenewalTimeout:  10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}
	ctx, cancel := testContext(t)
	guard, err := adapter.AcquirePortable(ctx)
	cancel()
	if err != nil {
		t.Fatalf("AcquirePortable: %v", err)
	}
	identity.mu.Lock()
	identity.startID[os.Getpid()] = "reused-start"
	identity.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	if err := guard.Close(); err == nil {
		t.Fatal("renewal failure was hidden by close")
	}
}

func TestOpenControllerRuntimeBuildsOnlyTheFenceAuthority(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "fleet")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	identity := &identityStub{
		bootID:  "boot-a",
		startID: map[int]string{os.Getpid(): "start-a"},
	}
	runtime, err := openControllerRuntime(
		ControllerRuntimeConfig{
			StateDir:         root,
			Generation:       1,
			OwnerID:          "portable-controller",
			PID:              os.Getpid(),
			Now:              time.Now,
			LockPollInterval: time.Millisecond,
			RenewalInterval:  time.Second,
			RenewalTimeout:   time.Second,
		},
		identity,
	)
	if err != nil {
		t.Fatalf("openControllerRuntime: %v", err)
	}
	defer runtime.Close()
	header := bootstrap(t, runtime.store, FleetPortable)
	if header.Generation != 1 {
		t.Fatalf("bootstrap header = %+v", header)
	}
	var provider controller.FleetGuardProvider = runtime.Provider()
	ctx, cancel := testContext(t)
	guard, err := provider.AcquirePortable(ctx)
	cancel()
	if err != nil {
		t.Fatalf("AcquirePortable: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("guard close: %v", err)
	}
}

func TestOpenControllerRuntimeRejectsIncompleteComposition(t *testing.T) {
	t.Parallel()

	if _, err := openControllerRuntime(
		ControllerRuntimeConfig{},
		&identityStub{},
	); err == nil {
		t.Fatal("incomplete composition accepted")
	}
}

func TestNormalizeLegacyObserverPublishesNewZeroEpoch(t *testing.T) {
	store, _, _ := newTestStore(t)
	header := bootstrap(t, store, FleetLegacy)
	transitions := &transitionStub{policy: controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionEnabled,
		EligibleScaleSets:        []string{"portable-ghar"},
		MaxCapacity:              2,
		RepositoryPolicyRevision: 4,
		RepositoryPolicies: []controller.RepositoryPolicySummary{{
			Alias:          "repo-a",
			MaxConcurrency: 2,
			Eligibility:    "active",
		}},
		Epoch: 7,
	}}
	ctx, cancel := testContext(t)
	proof, err := NormalizeLegacyObserver(ctx, store, transitions)
	cancel()
	if err != nil {
		t.Fatalf("NormalizeLegacyObserver: %v", err)
	}
	if proof.FleetGeneration != header.Generation ||
		proof.PolicyEpoch != 8 ||
		!strings.EqualFold(proof.PolicyDigest, strings.ToLower(proof.PolicyDigest)) ||
		len(proof.PolicyDigest) != 64 {
		t.Fatalf("proof = %+v", proof)
	}
	policy, err := transitions.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if policy.Mode != controller.AcquisitionDisabled ||
		policy.MaxCapacity != 0 ||
		len(policy.EligibleScaleSets) != 0 ||
		transitions.calls != 1 {
		t.Fatalf("policy=%+v calls=%d", policy, transitions.calls)
	}
}

func TestNormalizeLegacyObserverRejectsPortableOwnershipWithoutTransition(t *testing.T) {
	store, _, _ := newTestStore(t)
	bootstrap(t, store, FleetPortable)
	transitions := &transitionStub{policy: controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionDisabled,
		MaxCapacity:              0,
		RepositoryPolicyRevision: 1,
		Epoch:                    4,
	}}
	ctx, cancel := testContext(t)
	if _, err := NormalizeLegacyObserver(ctx, store, transitions); err == nil {
		t.Fatal("portable-owned observer normalization accepted")
	}
	cancel()
	if transitions.calls != 0 {
		t.Fatal("portable-owned host policy was mutated")
	}
}
