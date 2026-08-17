package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/failoverclient"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

func TestProductionExternalGraphDerivesPermitsFromCachedLease(t *testing.T) {
	t.Parallel()

	clock := failoverclient.NewFakeAuthorityClock(
		time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
	)
	graph, err := newProductionExternalGraph(productionExternalGraphConfig{
		Holder:          failoverclient.HolderPortable,
		Fence:           7,
		Clock:           clock,
		CallDuration:    2 * time.Second,
		TerminationTail: time.Second,
	})
	if err != nil {
		t.Fatalf("newProductionExternalGraph: %v", err)
	}
	request := controller.AcquisitionPermitRequest{
		OperationID:     "op-1",
		RepositoryAlias: "repo-a",
		ScaleSetName:    "canary-set",
		PolicyDigest:    strings.Repeat("a", 64),
		OperationKind:   "poll",
		PolicyEpoch:     9,
	}
	if _, err := graph.Acquire(context.Background(), request); err == nil {
		t.Fatal("empty cache authorized")
	}

	canary := "canary-set"
	lease := failoverclient.AcquisitionLeaseV1{
		ProtocolVersion:          1,
		FleetID:                  "example-fleet",
		Holder:                   failoverclient.HolderPortable,
		ServerEpoch:              2,
		SessionID:                strings.Repeat("b", 64),
		LeaseGeneration:          3,
		Mode:                     failoverclient.LeaseCanaryOnly,
		PolicyDigest:             strings.Repeat("a", 64),
		RepositoryPolicyRevision: 4,
		LocalPolicyEpoch:         9,
		MaxCapacity:              1,
		CanaryScaleSet:           &canary,
		DurationMs:               8000,
		Expiry:                   "2026-01-01T00:00:08.000Z",
	}
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		t.Fatalf("AdmissionAuthorityKey: %v", err)
	}
	if err := graph.InstallLease(failoverclient.CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      4,
		Fence:         7,
		LocalDeadline: time.Date(2026, 1, 1, 0, 0, 7, 0, time.UTC),
		SendAnchor:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("InstallLease: %v", err)
	}
	guard, err := graph.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire installed lease: %v", err)
	}
	if guard == nil {
		t.Fatal("Acquire returned nil guard")
	}
	if graph.PollTargets() != nil {
		t.Fatal("lease graph exposed poll targets")
	}
}

func TestProductionExternalGraphHolderFollowsFence(t *testing.T) {
	t.Parallel()

	graph, err := newProductionExternalGraph(productionExternalGraphConfig{
		Fleet: fleetfence.FleetLegacy,
		Fence: 3,
		Clock: failoverclient.NewFakeAuthorityClock(time.Now()),
	})
	if err != nil {
		t.Fatalf("newProductionExternalGraph: %v", err)
	}
	if graph.Holder() != failoverclient.HolderLegacy {
		t.Fatalf("holder = %q, want legacy", graph.Holder())
	}
}

type staticHeartbeatPopulator struct {
	body   []byte
	fence  uint64
	anchor time.Time
	margin time.Duration
}

func (populator staticHeartbeatPopulator) Populate(
	_ context.Context,
	cache *failoverclient.LeaseCache,
) error {
	return failoverclient.InstallHeartbeatLease(
		cache,
		populator.body,
		populator.fence,
		populator.anchor,
		populator.margin,
	)
}

func TestProductionExternalGraphPopulateInstallsHeartbeatLease(t *testing.T) {
	t.Parallel()

	clock := failoverclient.NewFakeAuthorityClock(
		time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
	)
	body := []byte(`{"lease":{"archivedDisabledAliases":[],"canaryScaleSet":null,"durationMs":8000,"expiry":"2026-01-01T00:00:08.000Z","fleetId":"example-fleet","holder":"portable","leaseGeneration":3,"localPolicyEpoch":9,"maxCapacity":2,"mode":"enabled","policyDigest":"` + strings.Repeat("a", 64) + `","protocolVersion":1,"repositoryPolicyRevision":4,"serverEpoch":2,"sessionId":"` + strings.Repeat("b", 64) + `"},"sequence":4}`)
	graph, err := newProductionExternalGraph(productionExternalGraphConfig{
		Holder:          failoverclient.HolderPortable,
		Fence:           7,
		Clock:           clock,
		CallDuration:    2 * time.Second,
		TerminationTail: time.Second,
		Populator: staticHeartbeatPopulator{
			body:   body,
			fence:  7,
			anchor: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			margin: time.Second,
		},
	})
	if err != nil {
		t.Fatalf("newProductionExternalGraph: %v", err)
	}
	if err := graph.Populate(context.Background()); err != nil {
		t.Fatalf("Populate: %v", err)
	}
	if _, err := graph.Acquire(context.Background(), controller.AcquisitionPermitRequest{
		RepositoryAlias: "repo-a",
		PolicyDigest:    strings.Repeat("a", 64),
		PolicyEpoch:     9,
	}); err != nil {
		t.Fatalf("Acquire after populate: %v", err)
	}
}
