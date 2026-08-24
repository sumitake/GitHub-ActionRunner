package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/health"
)

func TestLocalObservationRequiresFreshCompleteProjection(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	valid := localObservation{
		Sequence:   4,
		ObservedAt: now.Add(-time.Second),
		Complete:   true,
	}
	if err := valid.Validate(now, 2*time.Second); err != nil {
		t.Fatalf("Validate(valid) error = %v", err)
	}
	if !valid.Zero() {
		t.Fatal("Zero(valid) = false")
	}
	nonzero := valid
	nonzero.Helpers = 1
	if err := nonzero.Validate(now, 2*time.Second); err != nil {
		t.Fatalf("Validate(nonzero) error = %v", err)
	}
	if nonzero.Zero() {
		t.Fatal("Zero(nonzero) = true")
	}

	invalid := []localObservation{
		{},
		func() localObservation {
			value := valid
			value.Sequence = 0
			return value
		}(),
		func() localObservation {
			value := valid
			value.Complete = false
			return value
		}(),
		func() localObservation {
			value := valid
			value.ObservedAt = now.Add(time.Nanosecond)
			return value
		}(),
		func() localObservation {
			value := valid
			value.ObservedAt = now.Add(-3 * time.Second)
			return value
		}(),
	}
	for _, observation := range invalid {
		if err := observation.Validate(now, 2*time.Second); err == nil {
			t.Errorf("Validate(%#v) accepted incomplete/stale observation", observation)
		}
	}
}

func TestFleetAuthorityProofSeparatesSelfGuardFromWorkload(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	portable := fleetAuthorityProof{
		Sequence:       8,
		ObservedAt:     now.Add(-time.Second),
		Fleet:          fleetfence.FleetPortable,
		Generation:     17,
		SelfGuardToken: "guard-token",
	}
	if err := portable.Validate(
		now,
		2*time.Second,
		fleetfence.FleetPortable,
		17,
	); err != nil {
		t.Fatalf("portable Validate() error = %v", err)
	}
	legacy := fleetAuthorityProof{
		Sequence:   9,
		ObservedAt: now.Add(-time.Second),
		Fleet:      fleetfence.FleetLegacy,
		Generation: 17,
		LegacyProof: &fleetfence.LegacyObserverProof{
			FleetGeneration: 17,
			PolicyEpoch:     6,
			PolicyDigest:    repeatedDigest("d"),
		},
	}
	if err := legacy.Validate(
		now,
		2*time.Second,
		fleetfence.FleetLegacy,
		17,
	); err != nil {
		t.Fatalf("legacy Validate() error = %v", err)
	}
	invalid := []fleetAuthorityProof{
		{},
		func() fleetAuthorityProof {
			value := portable
			value.SelfGuardToken = ""
			return value
		}(),
		func() fleetAuthorityProof {
			value := portable
			value.LegacyProof = legacy.LegacyProof
			return value
		}(),
		func() fleetAuthorityProof {
			value := legacy
			value.SelfGuardToken = "portable"
			return value
		}(),
		func() fleetAuthorityProof {
			value := legacy
			value.LegacyProof = nil
			return value
		}(),
	}
	for _, proof := range invalid {
		if err := proof.Validate(
			now,
			2*time.Second,
			proof.Fleet,
			17,
		); err == nil {
			t.Errorf("Validate(%#v) accepted invalid fleet proof", proof)
		}
	}
}

func TestZeroDemandBrokerCapacityIsEpochBoundAndZero(t *testing.T) {
	broker, err := newZeroDemandBroker(12)
	if err != nil {
		t.Fatalf("newZeroDemandBroker() error = %v", err)
	}
	summary := broker.CapacitySummary()
	if err := validateZeroCapacitySummary(summary, 12); err != nil {
		t.Fatalf("validateZeroCapacitySummary() error = %v", err)
	}
	if err := broker.ApplyAcquisitionPolicy(controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionCanaryOnly,
		EligibleScaleSets:        []string{"scale-a"},
		MaxCapacity:              1,
		RepositoryPolicyRevision: 1,
		RepositoryPolicies: []controller.RepositoryPolicySummary{{
			Alias:          "repo-a",
			MaxConcurrency: 1,
			Eligibility:    "active",
		}},
		Epoch: 13,
	}); !errors.Is(err, errDisabledExternalUnavailable) {
		t.Fatalf("ApplyAcquisitionPolicy(nonzero) error = %v", err)
	}
}

func TestUnavailableExternalGraphNeverProvidesExternalAuthority(t *testing.T) {
	graph := newUnavailableExternalGraph()
	ctx := context.Background()
	if _, err := graph.Acquire(
		ctx,
		controller.AcquisitionPermitRequest{},
	); !errors.Is(err, errDisabledExternalUnavailable) {
		t.Fatalf("Acquire() error = %v", err)
	}
	if err := graph.Invalidate(ctx); !errors.Is(err, errDisabledExternalUnavailable) {
		t.Fatalf("Invalidate() error = %v", err)
	}
	if _, err := graph.VerifyCurrentOffer(
		ctx,
		githubscale.Fleet{},
		githubscale.Offer{},
	); !errors.Is(err, errDisabledExternalUnavailable) {
		t.Fatalf("VerifyCurrentOffer() error = %v", err)
	}
	if _, err := graph.Readiness(
		ctx,
		"repo-a",
		1,
	); !errors.Is(err, errDisabledExternalUnavailable) {
		t.Fatalf("Readiness() error = %v", err)
	}
	if _, err := graph.RouteHosted(
		ctx,
		controller.AssignmentKey{},
		"operation",
		controller.HostedReasonReplayUnknown,
	); !errors.Is(err, errDisabledExternalUnavailable) {
		t.Fatalf("RouteHosted() error = %v", err)
	}
	if err := graph.Publish(
		ctx,
		health.Snapshot{},
	); !errors.Is(err, errDisabledExternalUnavailable) {
		t.Fatalf("Publish() error = %v", err)
	}
	if targets := graph.PollTargets(); targets != nil {
		t.Fatalf("PollTargets() = %#v, want nil", targets)
	}
}

func repeatedDigest(character string) string {
	value := ""
	for len(value) < 64 {
		value += character
	}
	return value
}
