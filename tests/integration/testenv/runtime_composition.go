package testenv

import (
	"bytes"
	"context"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

type fixtureRuntimeComposition struct {
	Engine           *recordingEngine
	Store            *state.SQLiteStore
	Journal          *networkjail.StateLifecycleJournal
	Authority        *networkjail.PermitAuthority
	UsageAudit       permitUsageAuditSource
	AuthorityManager *networkjail.UnixAuthorityManager
	Orchestrator     *networkjail.Orchestrator
	OneShotRecorder  *task11OneShotRecorder
	OneShotLeases    *task11OneShotLeaseAuthority
	ClosedSurface    *closedCommandSurface
	MatrixBinding    matrixEvidenceBinding
	RunnerUser       string
	MaximumEvidence  uint64
	ProbeMembership  probeMembershipSeal
	Request          networkjail.PreparedSetupRequest
	FloodAttempts    uint32
}

func newFixtureRuntimeComposition(
	ctx context.Context,
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
	seccomp hostruntime.SeccompBinding,
	graph networkjail.DecisionGraph,
	policy hostruntime.PolicyArtifact,
	probes probeMembershipSeal,
	plan compositionPlan,
	store *state.SQLiteStore,
	clock networkjail.MonotonicClock,
	peerObserver permitPeerProcessObserver,
	record func(cleanupHandle) error,
) (fixtureRuntimeComposition, error) {
	if ctx == nil || ctx.Err() != nil ||
		store == nil || store.DB() == nil ||
		clock == nil || peerObserver == nil || record == nil ||
		graph.Digest().String() == "" ||
		probes.Digest() == "" ||
		static.PolicyGraphDigest != graph.Digest().String() ||
		overlay.Policy.CompiledGraphDigest != graph.Digest().String() ||
		overlay.Commands.DockerBinary == "" ||
		overlay.Paths.BrokerRoot == "" ||
		overlay.Paths.SeccompRoot == "" ||
		overlay.Docker.BrokerNetworkID == "" ||
		plan.CommandRunner == nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	expectedPolicy, err := networkjail.CompilePolicyArtifact(graph)
	if err != nil || !policy.Valid() ||
		expectedPolicy.Digest() != policy.Digest() {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	expectedRuntimePolicy := expectedPolicy.RuntimePolicy()
	actualRuntimePolicy := policy.RuntimePolicy()
	policyMatch := bytes.Equal(
		expectedRuntimePolicy,
		actualRuntimePolicy,
	)
	zeroCompositionBytes(expectedRuntimePolicy)
	zeroCompositionBytes(actualRuntimePolicy)
	if !policyMatch {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	specs, err := runtimeSpecCompositionFrom(
		input,
		overlay,
		static,
		seccomp,
		plan,
		hostruntime.AdapterHandle{},
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	closedSurface, err := newClosedCommandSurface(
		closedCommandConfig{
			DockerPath:   overlay.Commands.DockerBinary,
			FixtureRoot:  input.Fixture.Root,
			MaximumBytes: input.Limits.MaximumEvidenceBytes,
		},
		plan.CommandRunner,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	matrixBinding := matrixEvidenceBinding{
		RunID:           input.Authorization.RunID,
		BuildID:         input.Runtime.BuildID,
		FleetGeneration: input.Runtime.FleetGeneration,
		ProfileID:       input.Target.ProfileID,
		SlotIdentity:    plan.Identity.SlotIdentity,
		GraphDigest:     graph.Digest().String(),
	}
	if !validMatrixEvidenceBinding(matrixBinding) {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	oneShots, err := newTask11OneShotRecorder(
		plan.CommandRunner,
		task11OneShotRecorderBinding{
			DockerPath: overlay.Commands.DockerBinary,
			BrokerName: specs.Broker.Name,
			Helper: task11OneShotCommandBinding{
				Image:           specs.Broker.HelperImage,
				BuildID:         specs.Broker.BuildID,
				FleetGeneration: specs.Broker.FleetGeneration,
				SlotIdentity:    specs.Broker.SlotIdentity,
				User:            "0:0",
				SeccompPath:     specs.Broker.Seccomp.Path,
				Limits:          specs.Broker.HelperLimits,
			},
			Verifier: task11OneShotCommandBinding{
				Image:           specs.Verifier.Image,
				BuildID:         specs.Verifier.BuildID,
				FleetGeneration: specs.Verifier.FleetGeneration,
				SlotIdentity:    specs.Verifier.SlotIdentity,
				User:            specs.Verifier.User,
				SeccompPath:     specs.Verifier.Seccomp.Path,
				Limits:          specs.Verifier.Limits,
			},
		},
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	oneShotLeases, err := newTask11OneShotLeaseAuthority(
		overlay.Commands.DockerBinary,
		input.Limits.DockerLogMaximumBytes,
		plan.CommandRunner,
		record,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	baseEngine, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    overlay.Commands.DockerBinary,
			BrokerRoot:    overlay.Paths.BrokerRoot,
			SeccompRoot:   overlay.Paths.SeccompRoot,
			BrokerNetwork: overlay.Docker.BrokerNetworkID,
		},
		oneShots,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	engine, err := newRecordingEngine(
		baseEngine,
		record,
		recordingRuntimeBinding{
			RunID:           input.Authorization.RunID,
			BuildID:         specs.Adapter.BuildID,
			FleetGeneration: specs.Adapter.FleetGeneration,
			SlotIdentity:    specs.Adapter.SlotIdentity,
			CapacitySlotID:  plan.Identity.CapacitySlotID,
			JobGeneration:   plan.Identity.JobGeneration,
		},
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	peerGuard, err := newCompositionPermitPeerGuard(
		plan,
		specs.Broker.User,
		peerObserver,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	referenceGuard, err := newCompositionLedgerReferenceGuard(
		store,
		plan,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	referenced, err := referenceGuard.HasLedgerReferences(
		ctx,
		networkjail.CapacitySlotID(plan.Identity.CapacitySlotID),
	)
	if err != nil || !referenced {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	authority, err := networkjail.NewSQLitePermitAuthority(
		graph,
		clock,
		store,
		peerGuard,
		referenceGuard,
		rejectCompositionRebase{},
		plan.Authority.ReservationBlockSize,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	authorityManager, err := networkjail.NewUnixAuthorityManager(
		authority,
		plan.Authority.MaximumClients,
		plan.Authority.Timeout,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	journal, err := networkjail.NewStateLifecycleJournal(store)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	orchestrator, err := networkjail.NewOrchestrator(
		engine,
		journal,
		authorityManager,
	)
	if err != nil {
		return fixtureRuntimeComposition{}, ErrFixtureStart
	}
	return fixtureRuntimeComposition{
		Engine:    engine,
		Store:     store,
		Journal:   journal,
		Authority: authority,
		UsageAudit: permitAuthorityUsageAuditSource{
			authority: authority,
		},
		AuthorityManager: authorityManager,
		Orchestrator:     orchestrator,
		OneShotRecorder:  oneShots,
		OneShotLeases:    oneShotLeases,
		ClosedSurface:    closedSurface,
		MatrixBinding:    matrixBinding,
		RunnerUser:       static.RunnerUser,
		MaximumEvidence:  input.Limits.MaximumEvidenceBytes,
		ProbeMembership:  probes,
		FloodAttempts:    input.LoopbackFloodAttempts,
		Request: networkjail.PreparedSetupRequest{
			Key:               plan.AssignmentKey,
			Adapter:           specs.Adapter,
			Broker:            specs.Broker,
			Runner:            specs.Runner,
			Verifier:          specs.Verifier,
			Graph:             graph,
			Policy:            policy,
			ConntrackInput:    plan.ConntrackInput,
			MaxRunnerCapacity: plan.MaxRunnerCapacity,
			SeedIDs:           make([]string, 0),
		},
	}, nil
}

func zeroCompositionBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
