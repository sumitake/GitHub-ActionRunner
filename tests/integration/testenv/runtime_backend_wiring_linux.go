//go:build integration && linux

package testenv

import (
	"crypto/sha256"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

func newOrchestratedFixtureRuntime(
	composition fixtureRuntimeComposition,
) (*orchestratedFixtureRuntime, error) {
	if composition.Engine == nil ||
		composition.Store == nil ||
		composition.Store.DB() == nil ||
		composition.Orchestrator == nil ||
		composition.UsageAudit == nil ||
		composition.ProbeMembership.Digest() == "" ||
		composition.FloodAttempts == 0 ||
		composition.Request.Key.RepositoryAlias == "" {
		return nil, ErrFixtureStart
	}
	return &orchestratedFixtureRuntime{composition: composition}, nil
}

func (r *orchestratedFixtureRuntime) bindTask11LossPrevention(
	prevention *task11LossPreventionRuntime,
	attempt *task11RealLossAttemptSource,
) error {
	if r == nil || prevention == nil || attempt == nil {
		return ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prepareAttempted ||
		r.lossPrevention != nil ||
		r.lossAttempt != nil {
		return ErrFixtureStart
	}
	r.lossPrevention = prevention
	r.lossAttempt = attempt
	return nil
}

func newTask11RealLossAttemptSource(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
	seccomp hostruntime.SeccompBinding,
	graph networkjail.DecisionGraph,
	policy hostruntime.PolicyArtifact,
	probes probeMembershipSeal,
	primaryPlan compositionPlan,
	store *state.SQLiteStore,
	clock networkjail.MonotonicClock,
	peerObserver permitPeerProcessObserver,
	record func(cleanupHandle) error,
	now func() time.Time,
) (*task11RealLossAttemptSource, error) {
	if !isLowerHex(input.Authorization.RunID, sha256.Size*2) ||
		graph.Digest() == (networkjail.Digest{}) ||
		!policy.Valid() ||
		probes.Digest() == "" ||
		primaryPlan.Identity.CapacitySlotID == 0 ||
		primaryPlan.Identity.JobGeneration == 0 ||
		store == nil ||
		store.DB() == nil ||
		clock == nil ||
		peerObserver == nil ||
		record == nil ||
		now == nil {
		return nil, ErrFixtureStart
	}
	return &task11RealLossAttemptSource{
		input:        input,
		overlay:      overlay,
		static:       static,
		seccomp:      seccomp,
		graph:        graph,
		policy:       policy,
		probes:       probes,
		primaryPlan:  primaryPlan,
		store:        store,
		clock:        clock,
		peerObserver: peerObserver,
		record:       record,
		now:          now,
	}, nil
}
