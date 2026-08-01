package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

type fleetInspectorFixture struct {
	snapshot fleetfence.Snapshot
	err      error
}

func (fixture *fleetInspectorFixture) Inspect(
	context.Context,
) (fleetfence.Snapshot, error) {
	return fixture.snapshot, fixture.err
}

func TestProductionFleetAuthorityProvesExactPortableHolder(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 30, 3, 0, 0, 0, time.UTC)
	holder := fleetfence.HolderIdentity{
		Generation:     17,
		Fleet:          fleetfence.FleetPortable,
		OwnerID:        "portable-controller",
		PID:            4242,
		BootID:         "boot-1",
		ProcessStartID: "process-1",
	}
	failure := make(chan error, 1)
	authority, err := newProductionFleetAuthority(
		productionFleetAuthorityConfig{
			Inspector: &fleetInspectorFixture{snapshot: fleetfence.Snapshot{
				Header: fleetfence.Header{
					ActiveFleet: fleetfence.FleetPortable,
					Generation:  17,
				},
				Holders: []fleetfence.HolderIdentity{holder},
			}},
			Transitions:  &observerTransitionFixture{},
			Fleet:        fleetfence.FleetPortable,
			Generation:   17,
			OwnerID:      holder.OwnerID,
			PID:          holder.PID,
			GuardFailure: failure,
			Timeout:      time.Second,
			Now:          func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatalf("newProductionFleetAuthority: %v", err)
	}
	proof, err := authority.Observe(context.Background())
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if proof.Sequence != 1 ||
		!proof.ObservedAt.Equal(now) ||
		proof.Fleet != fleetfence.FleetPortable ||
		proof.Generation != 17 ||
		!validLowerDigest(proof.SelfGuardToken) ||
		proof.LegacyProof != nil {
		t.Fatalf("proof = %+v", proof)
	}
}

func TestProductionFleetAuthorityProvesExactLegacyZeroPolicy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 30, 3, 0, 0, 0, time.UTC)
	transitions := &observerTransitionFixture{policy: controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionDisabled,
		RepositoryPolicyRevision: 1,
		RepositoryPolicies: []controller.RepositoryPolicySummary{{
			Alias:          "repo-a",
			MaxConcurrency: 1,
			Eligibility:    "active",
		}},
		Epoch: 9,
	}}
	authority, err := newProductionFleetAuthority(
		productionFleetAuthorityConfig{
			Inspector: &fleetInspectorFixture{snapshot: fleetfence.Snapshot{
				Header: fleetfence.Header{
					ActiveFleet: fleetfence.FleetLegacy,
					Generation:  17,
				},
			}},
			Transitions: transitions,
			Fleet:       fleetfence.FleetLegacy,
			Generation:  17,
			Timeout:     time.Second,
			Now:         func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatalf("newProductionFleetAuthority: %v", err)
	}
	proof, err := authority.Observe(context.Background())
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if proof.Sequence != 1 ||
		proof.Fleet != fleetfence.FleetLegacy ||
		proof.SelfGuardToken != "" ||
		proof.LegacyProof == nil ||
		proof.LegacyProof.FleetGeneration != 17 ||
		proof.LegacyProof.PolicyEpoch != 9 ||
		!validLowerDigest(proof.LegacyProof.PolicyDigest) {
		t.Fatalf("proof = %+v", proof)
	}
}

func TestProductionFleetAuthorityRejectsDriftAndGuardFailure(t *testing.T) {
	t.Parallel()

	holder := fleetfence.HolderIdentity{
		Generation:     17,
		Fleet:          fleetfence.FleetPortable,
		OwnerID:        "portable-controller",
		PID:            4242,
		BootID:         "boot-1",
		ProcessStartID: "process-1",
	}
	tests := map[string]func(
		*fleetInspectorFixture,
		*observerTransitionFixture,
		chan error,
	){
		"wrong generation": func(
			inspector *fleetInspectorFixture,
			_ *observerTransitionFixture,
			_ chan error,
		) {
			inspector.snapshot.Header.Generation = 18
		},
		"extra holder": func(
			inspector *fleetInspectorFixture,
			_ *observerTransitionFixture,
			_ chan error,
		) {
			inspector.snapshot.Holders = append(
				inspector.snapshot.Holders,
				holder,
			)
		},
		"holder drift": func(
			inspector *fleetInspectorFixture,
			_ *observerTransitionFixture,
			_ chan error,
		) {
			inspector.snapshot.Holders[0].OwnerID = "other"
		},
		"guard failed": func(
			_ *fleetInspectorFixture,
			_ *observerTransitionFixture,
			failure chan error,
		) {
			failure <- errors.New("renewal failed")
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inspector := &fleetInspectorFixture{
				snapshot: fleetfence.Snapshot{
					Header: fleetfence.Header{
						ActiveFleet: fleetfence.FleetPortable,
						Generation:  17,
					},
					Holders: []fleetfence.HolderIdentity{holder},
				},
			}
			transitions := &observerTransitionFixture{}
			failure := make(chan error, 1)
			mutate(inspector, transitions, failure)
			authority, err := newProductionFleetAuthority(
				productionFleetAuthorityConfig{
					Inspector:    inspector,
					Transitions:  transitions,
					Fleet:        fleetfence.FleetPortable,
					Generation:   17,
					OwnerID:      holder.OwnerID,
					PID:          holder.PID,
					GuardFailure: failure,
					Timeout:      time.Second,
					Now:          time.Now,
				},
			)
			if err != nil {
				t.Fatalf("newProductionFleetAuthority: %v", err)
			}
			if proof, err := authority.Observe(
				context.Background(),
			); err == nil || proof != (fleetAuthorityProof{}) {
				t.Fatalf("Observe = (%+v, %v), want failure", proof, err)
			}
		})
	}
}

func TestProductionFleetAuthorityRejectsLegacyHoldersOrNonzeroPolicy(
	t *testing.T,
) {
	t.Parallel()

	for name, configure := range map[string]func(
		*fleetInspectorFixture,
		*observerTransitionFixture,
	){
		"holder": func(
			inspector *fleetInspectorFixture,
			_ *observerTransitionFixture,
		) {
			inspector.snapshot.Holders = []fleetfence.HolderIdentity{{
				Generation:     17,
				Fleet:          fleetfence.FleetLegacy,
				OwnerID:        "legacy",
				PID:            1,
				BootID:         "boot",
				ProcessStartID: "process",
			}}
		},
		"enabled": func(
			_ *fleetInspectorFixture,
			transitions *observerTransitionFixture,
		) {
			transitions.policy.Mode = controller.AcquisitionEnabled
			transitions.policy.MaxCapacity = 1
			transitions.policy.EligibleScaleSets = []string{"scale-set"}
		},
	} {
		configure := configure
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inspector := &fleetInspectorFixture{
				snapshot: fleetfence.Snapshot{
					Header: fleetfence.Header{
						ActiveFleet: fleetfence.FleetLegacy,
						Generation:  17,
					},
				},
			}
			transitions := &observerTransitionFixture{
				policy: controller.AcquisitionPolicy{
					Mode:                     controller.AcquisitionDisabled,
					RepositoryPolicyRevision: 1,
					RepositoryPolicies: []controller.RepositoryPolicySummary{{
						Alias:          "repo-a",
						MaxConcurrency: 1,
						Eligibility:    "active",
					}},
					Epoch: 9,
				},
			}
			configure(inspector, transitions)
			authority, err := newProductionFleetAuthority(
				productionFleetAuthorityConfig{
					Inspector:   inspector,
					Transitions: transitions,
					Fleet:       fleetfence.FleetLegacy,
					Generation:  17,
					Timeout:     time.Second,
					Now:         time.Now,
				},
			)
			if err != nil {
				t.Fatalf("newProductionFleetAuthority: %v", err)
			}
			if _, err := authority.Observe(context.Background()); err == nil {
				t.Fatal("Observe accepted unsafe legacy authority")
			}
		})
	}
}
