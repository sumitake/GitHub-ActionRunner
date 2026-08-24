//go:build chaos

package chaos_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

type chaosFenceIdentity struct{}

func (chaosFenceIdentity) Current(
	_ context.Context,
	pid int,
) (fleetfence.ProcessIdentity, error) {
	if pid <= 0 {
		return fleetfence.ProcessIdentity{}, errors.New("chaos: invalid pid")
	}
	return fleetfence.ProcessIdentity{
		BootID:         "chaos-boot",
		ProcessStartID: fmt.Sprintf("chaos-start-%d", pid),
	}, nil
}

type chaosAcquisitionTransitions struct {
	mu     sync.Mutex
	policy controller.AcquisitionPolicy
}

func (transitions *chaosAcquisitionTransitions) Snapshot(
	context.Context,
) (controller.AcquisitionPolicy, error) {
	transitions.mu.Lock()
	defer transitions.mu.Unlock()
	return transitions.policy, nil
}

func (transitions *chaosAcquisitionTransitions) Transition(
	_ context.Context,
	expected uint64,
	next controller.AcquisitionPolicy,
) (controller.AcquisitionPolicy, error) {
	transitions.mu.Lock()
	defer transitions.mu.Unlock()
	if transitions.policy.Epoch != expected {
		return controller.AcquisitionPolicy{}, errors.New("chaos: epoch conflict")
	}
	next.Epoch = expected + 1
	canonical, err := controller.CanonicalizeAcquisitionPolicy(next)
	if err != nil {
		return controller.AcquisitionPolicy{}, err
	}
	transitions.policy = canonical
	return canonical, nil
}

func TestFleetFenceRaceAndObserverRecovery(t *testing.T) {
	_ = requireChaosHost(t)

	root := filepath.Join(t.TempDir(), "fleet")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("chaos: create fence root: %v", err)
	}
	var ticks atomic.Uint64
	store, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:     root,
		Identity: chaosFenceIdentity{},
		Now: func() time.Time {
			return time.Unix(1_800_000_000, int64(ticks.Add(1))).UTC()
		},
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("chaos: open fence store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("chaos: close fence store: %v", err)
		}
	}()

	portable := handoffFence(
		t,
		store,
		fleetfence.FleetNone,
		fleetfence.FleetPortable,
		0,
	)
	if portable.Generation != 1 ||
		portable.ActiveFleet != fleetfence.FleetPortable {
		t.Fatalf("chaos: portable bootstrap = %+v", portable)
	}
	guard := acquireFence(
		t,
		store,
		fleetfence.FleetPortable,
		portable.Generation,
		"portable-controller",
	)

	type handoffResult struct {
		header fleetfence.Header
		err    error
	}
	handoffDone := make(chan handoffResult, 1)
	handoffCtx, handoffCancel := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer handoffCancel()
	go func() {
		request := fleetfence.HandoffRequest{
			From:               fleetfence.FleetPortable,
			To:                 fleetfence.FleetLegacy,
			ExpectedGeneration: portable.Generation,
		}
		request.OperationID = fleetfence.HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		)
		header, handoffErr := store.Handoff(handoffCtx, request)
		handoffDone <- handoffResult{header: header, err: handoffErr}
	}()
	select {
	case result := <-handoffDone:
		t.Fatalf("chaos: handoff crossed live portable guard: %+v", result)
	case <-time.After(25 * time.Millisecond):
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("chaos: close portable guard: %v", err)
	}
	var legacy handoffResult
	select {
	case legacy = <-handoffDone:
	case <-time.After(2 * time.Second):
		t.Fatal("chaos: handoff did not resume after portable guard closed")
	}
	if legacy.err != nil ||
		legacy.header.Generation != 2 ||
		legacy.header.ActiveFleet != fleetfence.FleetLegacy {
		t.Fatalf("chaos: legacy handoff = %+v", legacy)
	}

	staleCtx, staleCancel := context.WithTimeout(
		context.Background(),
		250*time.Millisecond,
	)
	_, staleErr := store.Acquire(staleCtx, fleetfence.AcquireRequest{
		Fleet:      fleetfence.FleetPortable,
		Generation: portable.Generation,
		OwnerID:    "stale-portable",
		PID:        os.Getpid(),
	})
	staleCancel()
	if !errors.Is(staleErr, fleetfence.ErrAuthorityConflict) {
		t.Fatalf("chaos: stale portable acquire = %v", staleErr)
	}

	replay := handoffFence(
		t,
		store,
		fleetfence.FleetPortable,
		fleetfence.FleetLegacy,
		portable.Generation,
	)
	if replay != legacy.header {
		t.Fatalf("chaos: handoff replay = %+v, want %+v", replay, legacy.header)
	}

	transitions := &chaosAcquisitionTransitions{
		policy: controller.AcquisitionPolicy{
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
		},
	}
	normalizeCtx, normalizeCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	proof, err := fleetfence.NormalizeLegacyObserver(
		normalizeCtx,
		store,
		transitions,
	)
	normalizeCancel()
	if err != nil ||
		proof.FleetGeneration != legacy.header.Generation ||
		proof.PolicyEpoch != 8 {
		t.Fatalf("chaos: observer normalization = %+v, error=%v", proof, err)
	}
	normalized, err := transitions.Snapshot(context.Background())
	if err != nil ||
		normalized.Mode != controller.AcquisitionDisabled ||
		normalized.MaxCapacity != 0 ||
		len(normalized.EligibleScaleSets) != 0 {
		t.Fatalf("chaos: normalized policy = %+v, error=%v", normalized, err)
	}

	nextPortable := handoffFence(
		t,
		store,
		fleetfence.FleetLegacy,
		fleetfence.FleetPortable,
		legacy.header.Generation,
	)
	if nextPortable.Generation != 3 ||
		nextPortable.ActiveFleet != fleetfence.FleetPortable {
		t.Fatalf("chaos: next portable handoff = %+v", nextPortable)
	}
	staleWatchdog := fleetfence.HandoffRequest{
		From:               fleetfence.FleetLegacy,
		To:                 fleetfence.FleetNone,
		ExpectedGeneration: legacy.header.Generation,
	}
	staleWatchdog.OperationID = fleetfence.HandoffOperationID(
		staleWatchdog.ExpectedGeneration,
		staleWatchdog.From,
		staleWatchdog.To,
	)
	staleWatchdogCtx, staleWatchdogCancel := context.WithTimeout(
		context.Background(),
		250*time.Millisecond,
	)
	_, err = store.Handoff(staleWatchdogCtx, staleWatchdog)
	staleWatchdogCancel()
	if !errors.Is(err, fleetfence.ErrAuthorityConflict) {
		t.Fatalf("chaos: stale watchdog handoff = %v", err)
	}
	inspectCtx, inspectCancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	snapshot, err := store.Inspect(inspectCtx)
	inspectCancel()
	if err != nil ||
		snapshot.Header.Generation != nextPortable.Generation ||
		snapshot.Header.ActiveFleet != fleetfence.FleetPortable ||
		len(snapshot.Holders) != 0 {
		t.Fatalf("chaos: final fence snapshot = %+v, error=%v", snapshot, err)
	}
}

func handoffFence(
	t *testing.T,
	store *fleetfence.Store,
	from fleetfence.Fleet,
	to fleetfence.Fleet,
	expected uint64,
) fleetfence.Header {
	t.Helper()
	request := fleetfence.HandoffRequest{
		From:               from,
		To:                 to,
		ExpectedGeneration: expected,
	}
	request.OperationID = fleetfence.HandoffOperationID(expected, from, to)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	header, err := store.Handoff(ctx, request)
	if err != nil {
		t.Fatalf("chaos: handoff %s -> %s: %v", from, to, err)
	}
	return header
}

func acquireFence(
	t *testing.T,
	store *fleetfence.Store,
	fleet fleetfence.Fleet,
	generation uint64,
	owner string,
) fleetfence.Guard {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	guard, err := store.Acquire(ctx, fleetfence.AcquireRequest{
		Fleet:      fleet,
		Generation: generation,
		OwnerID:    owner,
		PID:        os.Getpid(),
	})
	if err != nil {
		t.Fatalf("chaos: acquire %s generation %d: %v", fleet, generation, err)
	}
	return guard
}
