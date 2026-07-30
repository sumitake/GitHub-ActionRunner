//go:build integration && linux

package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/redaction"
	"github.com/sumitake/portable-ghar/internal/state"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

const task11SyntheticNonceDomain = "portable-ghar.task11.synthetic-nonce.v1\x00"

var errTask11SyntheticPreListener = errors.New(
	"testenv: task11 synthetic pre-listener tripwire",
)

type task11SyntheticPreListenerEngine struct {
	hostruntime.Engine
	driver *linuxTask11SyntheticDriver
	state  *linuxTask11SyntheticCycleState

	mu       sync.Mutex
	adapter  hostruntime.AdapterHandle
	broker   hostruntime.BrokerHandle
	runner   hostruntime.RunnerHandle
	observer *task11SyntheticCleanupObserver
	fired    bool
}

type linuxTask11SyntheticCycleState struct {
	driver *linuxTask11SyntheticDriver
	cycle  task11SyntheticCycleIdentity

	mu          sync.Mutex
	handles     []cleanupHandle
	removed     map[cleanupHandle]bool
	rootHandle  cleanupHandle
	root        *linuxTask11SyntheticCycleRoot
	composition *fixtureRuntimeComposition
	recovery    *hostruntime.DockerCLI
	held        networkjail.HeldJail
	heldReady   bool
	live        networkjail.LiveJail
	liveReady   bool
	cleanupDone bool
	cleanupErr  error
}

type linuxTask11SyntheticDriver struct {
	input        ConformanceInput
	overlay      hostruntime.PrivateOverlay
	static       staticPreflightResult
	seccomp      hostruntime.SeccompBinding
	graph        networkjail.DecisionGraph
	policy       hostruntime.PolicyArtifact
	probes       probeMembershipSeal
	store        *state.SQLiteStore
	clock        networkjail.MonotonicClock
	peerObserver permitPeerProcessObserver
	record       func(cleanupHandle) error
	now          func() time.Time
	cgroup       task11synthetic.CgroupVersion
	command      hostruntime.CommandRunner

	mu     sync.Mutex
	owners map[cleanupHandle]*linuxTask11SyntheticCycleState
}

func newLinuxTask11SyntheticDriver(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
	seccomp hostruntime.SeccompBinding,
	graph networkjail.DecisionGraph,
	policy hostruntime.PolicyArtifact,
	probes probeMembershipSeal,
	store *state.SQLiteStore,
	clock networkjail.MonotonicClock,
	peerObserver permitPeerProcessObserver,
	record func(cleanupHandle) error,
	now func() time.Time,
) (*linuxTask11SyntheticDriver, error) {
	cgroup, err := task11CycleCgroupVersion(
		static.DockerInfo.CgroupVersion,
	)
	command, commandErr := commandRunnerFromConformanceLimits(input.Limits)
	if err != nil ||
		commandErr != nil ||
		store == nil ||
		store.DB() == nil ||
		clock == nil ||
		peerObserver == nil ||
		record == nil ||
		now == nil ||
		graph.Digest().String() == "" ||
		!policy.Valid() ||
		probes.Digest() == "" ||
		!validImmutableImageReference(
			input.Images.SyntheticListener.Reference,
			input.Images.SyntheticListener.Digest,
		) ||
		durationMilliseconds(
			input.Limits.ObservationCadenceMilliseconds,
		) <= 0 ||
		durationMilliseconds(
			input.Limits.CleanupSLOMilliseconds,
		) <= 0 ||
		durationMilliseconds(
			input.Limits.CleanupTimeoutMilliseconds,
		) <= 0 {
		return nil, ErrFixtureStart
	}
	return &linuxTask11SyntheticDriver{
		input:        input,
		overlay:      overlay,
		static:       static,
		seccomp:      seccomp,
		graph:        graph,
		policy:       policy,
		probes:       probes,
		store:        store,
		clock:        clock,
		peerObserver: peerObserver,
		record:       record,
		now:          now,
		cgroup:       cgroup,
		command:      command,
		owners:       make(map[cleanupHandle]*linuxTask11SyntheticCycleState),
	}, nil
}

func (d *linuxTask11SyntheticDriver) RunSyntheticCycle(
	ctx context.Context,
	request task11SyntheticCycleRequest,
) (task11SyntheticCycleResult, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	switch request.Kind {
	case task11CycleOneJob,
		task11CycleCleanupSuccess,
		task11CycleCleanupListenerCrash,
		task11CycleCleanupUpgradeInterruption,
		task11CycleReclamation:
		return d.runListenerCycle(ctx, request)
	case task11CycleCleanupCancellation:
		return d.runCancellationCycle(ctx, request)
	case task11CycleCleanupPreListenerFailure:
		return d.runPreListenerFailureCycle(ctx, request)
	case task11CycleCleanupControllerRestart:
		return d.runControllerRestartCycle(ctx, request)
	default:
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
}

func (d *linuxTask11SyntheticDriver) runControllerRestartCycle(
	ctx context.Context,
	request task11SyntheticCycleRequest,
) (task11SyntheticCycleResult, error) {
	parent, err := deriveTask11SyntheticCycleIdentity(
		d.input.Fixture.Root,
		d.input.Authorization.RunID,
		request,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	builder, err := newTask11SyntheticRestartAggregateBuilder(parent)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	for index, stage := range task11synthetic.RestartSetupStages() {
		checkpoint, err := task11SyntheticRestartCheckpointAt(
			stage,
			uint64(index),
		)
		if err != nil {
			builder.fail()
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		child, err := deriveTask11SyntheticRestartStageIdentity(
			d.input.Fixture.Root,
			d.input.Authorization.RunID,
			parent,
			stage,
			uint64(index),
		)
		if err != nil {
			builder.fail()
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		evidence, err := d.runControllerRestartStage(
			ctx,
			child,
			checkpoint,
		)
		if err != nil {
			builder.fail()
			return task11SyntheticCycleResult{}, err
		}
		if err := builder.appendSuccess(evidence); err != nil {
			builder.fail()
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
	}
	aggregate, err := builder.seal()
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	return task11SyntheticCycleResult{
		Kind:    request.Kind,
		Ordinal: request.Ordinal,
		Cleanup: aggregate.proof,
		Restart: &aggregate,
	}, nil
}

func (d *linuxTask11SyntheticDriver) runControllerRestartStage(
	ctx context.Context,
	cycle task11SyntheticCycleIdentity,
	checkpoint task11SyntheticRestartCheckpoint,
) (
	evidence task11SyntheticRestartChildEvidence,
	resultErr error,
) {
	cycleState, _, plan, offer, offerEvidence, err := d.prepareCycle(
		ctx,
		cycle,
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, err
	}
	defer func() {
		recovered := recover()
		if resultErr != nil || recovered != nil {
			cleanupCtx, cancel := context.WithTimeout(
				context.Background(),
				durationMilliseconds(
					d.input.Limits.CleanupTimeoutMilliseconds,
				),
			)
			defer cancel()
			cleanupFailed := false
			if cycleState.composition != nil &&
				cycleState.composition.AuthorityManager != nil {
				if err := cycleState.composition.AuthorityManager.
					ShutdownIntegrationAuthority(
						cleanupCtx,
						networkjail.CapacitySlotID(
							cycle.Composition.CapacitySlotID,
						),
						networkjail.JobGeneration(
							cycle.Composition.JobGeneration,
						),
						cycleState.composition.Request.Broker.
							AuthorityParent,
					); err != nil {
					cleanupFailed = true
				}
			}
			if err := cycleState.cleanup(cleanupCtx); err != nil {
				cleanupFailed = true
			}
			if cleanupFailed {
				resultErr = ErrFixtureCleanup
			}
		}
		if recovered != nil {
			panic(recovered)
		}
	}()

	journal, err := newTask11SyntheticRestartJournal(
		cycleState.composition.Journal,
		d.store,
		plan.AssignmentKey,
		checkpoint,
		d.policy.Digest(),
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	orchestrator, err := networkjail.NewOrchestrator(
		cycleState.composition.Engine,
		journal,
		cycleState.composition.AuthorityManager,
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	if !task11SyntheticRestartPrepareCrashes(
		orchestrator,
		ctx,
		cycleState.composition.Request,
		task11SyntheticRestartSentinel{
			stage:            checkpoint.ProtocolStage,
			declarationIndex: checkpoint.DeclarationIndex,
		},
	) || !journal.didFire() {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}

	rows, err := d.store.ListRecoverable(ctx)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	identities, err := checkpoint.recoveredIdentities(
		cycle,
		plan,
		offer,
		rows,
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	effect, err := d.store.LookupAssignmentEffect(
		ctx,
		plan.AssignmentKey,
		checkpoint.JournalStage.String(),
	)
	if err != nil ||
		!checkpoint.effectMatches(
			effect,
			identities,
			d.policy.Digest(),
		) {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	recovery, expected, err := task11SyntheticRecoveryBinding(
		d.input,
		cycle,
		identities,
	)
	if err != nil || expected != checkpoint.Expected {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	snapshot, err := cycleState.recovery.InspectManaged(ctx, recovery)
	if err != nil ||
		snapshot.Identities() != identities ||
		snapshot.Observation() != checkpoint.Expected {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	observer, err := d.armObserverFromSnapshot(
		ctx,
		cycleState,
		recovery,
		expected,
		snapshot,
		checkpoint.AuthorityExpected,
		checkpoint.RelaySocketExpected,
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	revision, authorityErr := cycleState.composition.Authority.ActiveRevision(
		ctx,
		networkjail.CapacitySlotID(cycle.Composition.CapacitySlotID),
		networkjail.JobGeneration(cycle.Composition.JobGeneration),
	)
	if checkpoint.AuthorityExpected {
		if authorityErr != nil || revision == 0 {
			return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
		}
	} else if revision != 0 ||
		!errors.Is(authorityErr, networkjail.ErrPermitAssignment) {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	listenerEffect, err := d.store.LookupAssignmentEffect(
		ctx,
		plan.AssignmentKey,
		networkjail.StageListenerRelease.String(),
	)
	if err != nil ||
		listenerEffect != (state.EffectRecord{
			State: state.EffectAbsent,
		}) ||
		observer.SealNoListenerOutcome(
			ctx,
			task11SyntheticNoListenerOutcome{
				Reason: task11NoListenerControllerRestart,
			},
		) != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}

	cleanupCtx, cancel := context.WithTimeout(
		context.Background(),
		durationMilliseconds(
			d.input.Limits.CleanupTimeoutMilliseconds,
		),
	)
	defer cancel()
	if err := cycleState.composition.AuthorityManager.
		ShutdownIntegrationAuthority(
			cleanupCtx,
			networkjail.CapacitySlotID(
				cycle.Composition.CapacitySlotID,
			),
			networkjail.JobGeneration(
				cycle.Composition.JobGeneration,
			),
			recovery.AuthorityParent,
		); err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureCleanup
	}
	if err := cycleState.recovery.RemoveManaged(
		cleanupCtx,
		snapshot,
	); err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureCleanup
	}
	proved, err := observer.proveEvidence(cleanupCtx)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureCleanup
	}
	if err := cycleState.markRecoveredRemoved(
		proved,
		identities,
	); err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureCleanup
	}
	if err := d.store.AdvancePreReleaseDestroyed(
		cleanupCtx,
		plan.AssignmentKey,
	); err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	remaining, err := d.store.ListRecoverable(cleanupCtx)
	if err != nil || len(remaining) != 0 {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	receipt, err := d.store.RecordOffer(
		cleanupCtx,
		offer,
		offerEvidence,
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	listenerEffect, err = d.store.LookupAssignmentEffect(
		cleanupCtx,
		plan.AssignmentKey,
		networkjail.StageListenerRelease.String(),
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	completion, err := newTask11SyntheticRestartSuccessCompletion(
		cycle,
		receipt,
		listenerEffect,
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureStart
	}
	handles, err := cycleState.handlesSnapshot()
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureCleanup
	}
	removal, err := newTask11SyntheticCycleRemovalSnapshot(
		cycle,
		handles,
		d.recordedRemoved,
	)
	if err != nil {
		return task11SyntheticRestartChildEvidence{}, ErrFixtureCleanup
	}
	return task11SyntheticRestartChildEvidence{
		stage:            checkpoint.ProtocolStage,
		declarationIndex: checkpoint.DeclarationIndex,
		cycle:            cycle,
		cleanup:          proved,
		completion:       completion,
		removal:          removal,
	}, nil
}

func task11SyntheticRestartPrepareCrashes(
	orchestrator *networkjail.Orchestrator,
	ctx context.Context,
	request networkjail.PreparedSetupRequest,
	expected task11SyntheticRestartSentinel,
) (crashed bool) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		sentinel, ok := recovered.(task11SyntheticRestartSentinel)
		if !ok || sentinel != expected {
			panic(recovered)
		}
		crashed = true
	}()
	if orchestrator == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	if _, err := orchestrator.Prepare(ctx, request); err != nil {
		return false
	}
	return false
}

func task11CycleCgroupVersion(
	value string,
) (task11synthetic.CgroupVersion, error) {
	switch value {
	case "1":
		return task11synthetic.CgroupV1, nil
	case "2":
		return task11synthetic.CgroupV2, nil
	default:
		return "", ErrFixtureStart
	}
}

func (checkpoint task11SyntheticRestartCheckpoint) effectMatches(
	effect state.EffectRecord,
	identities hostruntime.RecoveredIdentities,
	policyDigest string,
) bool {
	expected, err := checkpoint.expectedJournalResult(
		identities,
		policyDigest,
	)
	return err == nil &&
		effect.State == state.EffectCompleted &&
		effect.ResultIdentity == expected.Identity &&
		effect.ReasonCode == ""
}

func (d *linuxTask11SyntheticDriver) runPreListenerFailureCycle(
	ctx context.Context,
	request task11SyntheticCycleRequest,
) (result task11SyntheticCycleResult, resultErr error) {
	cycle, err := deriveTask11SyntheticCycleIdentity(
		d.input.Fixture.Root,
		d.input.Authorization.RunID,
		request,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	cycleState, _, plan, offer, evidence, err := d.prepareCycle(
		ctx,
		cycle,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, err
	}
	defer func() {
		if resultErr != nil {
			cleanupCtx, cancel := context.WithTimeout(
				context.Background(),
				durationMilliseconds(
					d.input.Limits.CleanupTimeoutMilliseconds,
				),
			)
			defer cancel()
			if cleanupErr := cycleState.cleanup(cleanupCtx); cleanupErr != nil {
				resultErr = ErrFixtureCleanup
			}
		}
	}()
	wrapper := &task11SyntheticPreListenerEngine{
		Engine: cycleState.composition.Engine,
		driver: d,
		state:  cycleState,
	}
	orchestrator, err := networkjail.NewOrchestrator(
		wrapper,
		cycleState.composition.Journal,
		cycleState.composition.AuthorityManager,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	_, prepareErr := orchestrator.Prepare(
		ctx,
		cycleState.composition.Request,
	)
	if !errors.Is(prepareErr, networkjail.ErrSetupFailed) {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	observer, ok := wrapper.completedObserver()
	if !ok {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	cleanupCtx, cancel := context.WithTimeout(
		context.Background(),
		durationMilliseconds(
			d.input.Limits.CleanupTimeoutMilliseconds,
		),
	)
	defer cancel()
	proved, err := observer.proveEvidence(cleanupCtx)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureCleanup
	}
	if err := d.requireTerminalReplay(
		cleanupCtx,
		plan,
		offer,
		evidence,
		state.EffectAbsent,
	); err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	if err := cycleState.markRemoved(); err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureCleanup
	}
	return task11SyntheticCycleResult{
		Kind:    request.Kind,
		Ordinal: request.Ordinal,
		Cleanup: proved.proof,
	}, nil
}

func (d *linuxTask11SyntheticDriver) RunSeedIsolation(
	ctx context.Context,
) (task11SeedIsolationResult, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	first, err := deriveTask11SyntheticProtocolCycleIdentity(
		d.input.Fixture.Root,
		d.input.Authorization.RunID,
		task11synthetic.CycleSeedFirst,
		0,
	)
	if err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	firstStream, firstCleanup, err := d.executeListenerCycle(ctx, first)
	if err != nil {
		return task11SeedIsolationResult{}, err
	}
	second, err := deriveTask11SyntheticProtocolCycleIdentity(
		d.input.Fixture.Root,
		d.input.Authorization.RunID,
		task11synthetic.CycleSeedSecond,
		0,
	)
	if err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	secondStream, secondCleanup, err := d.executeListenerCycle(ctx, second)
	if err != nil {
		return task11SeedIsolationResult{}, err
	}
	return task11SyntheticSeedIsolationResultFromStreams(
		d.input.Fixture.Root,
		d.input.Authorization.RunID,
		first,
		firstStream,
		firstCleanup.proof,
		second,
		secondStream,
		secondCleanup.proof,
	)
}

func (d *linuxTask11SyntheticDriver) runListenerCycle(
	ctx context.Context,
	request task11SyntheticCycleRequest,
) (task11SyntheticCycleResult, error) {
	cycle, err := deriveTask11SyntheticCycleIdentity(
		d.input.Fixture.Root,
		d.input.Authorization.RunID,
		request,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	stream, proved, err := d.executeListenerCycle(ctx, cycle)
	if err != nil {
		return task11SyntheticCycleResult{}, err
	}
	result, err := task11SyntheticCycleResultFromStream(
		cycle,
		stream,
		proved.proof,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	return result, nil
}

func (d *linuxTask11SyntheticDriver) executeListenerCycle(
	ctx context.Context,
	cycle task11SyntheticCycleIdentity,
) (
	stream task11synthetic.Stream,
	proved task11SyntheticProvedCleanup,
	resultErr error,
) {
	cycleState, cycleInput, plan, offer, evidence, err :=
		d.prepareCycle(ctx, cycle)
	if err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			err
	}
	defer func() {
		if resultErr != nil {
			cleanupCtx, cancel := context.WithTimeout(
				context.Background(),
				durationMilliseconds(
					d.input.Limits.CleanupTimeoutMilliseconds,
				),
			)
			defer cancel()
			if cleanupErr := cycleState.cleanup(cleanupCtx); cleanupErr != nil {
				resultErr = ErrFixtureCleanup
			}
		}
	}()

	held, err := cycleState.composition.Orchestrator.Prepare(
		ctx,
		cycleState.composition.Request,
	)
	if err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	cycleState.setHeld(held)
	scenario, listener, ok := task11SyntheticScenario(
		cycle.ProtocolKind,
	)
	if !ok || !listener {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	nonce, err := task11SyntheticCycleNonce(cycle, scenario)
	if err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	_, streamBinding, document, err := task11SyntheticListenerInput(
		cycleInput,
		cycle,
		scenario,
		nonce,
		d.cgroup,
		d.input.Limits.MaximumCommandInputBytes,
	)
	if err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	attach, err := startTask11SyntheticAttach(
		d.overlay.Commands.DockerBinary,
		held.RunnerID(),
		d.input.Limits.MaximumEvidenceBytes,
	)
	if err != nil {
		zeroLeaseBytes(document)
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	defer func() {
		if resultErr != nil {
			_ = attach.terminate()
		}
	}()
	observer, err := d.armFullObserver(ctx, cycleState, held)
	if err != nil {
		zeroLeaseBytes(document)
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	jit := redaction.SecretFromBytes(document)
	document = nil
	live, err := cycleState.composition.Orchestrator.Release(
		ctx,
		held,
		jit,
	)
	if err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	cycleState.setLive(live)
	stream, err = attach.waitAndInspect(
		ctx,
		plan.CommandRunner,
		streamBinding,
	)
	if err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	exitCode := attach.result().ExitCode
	if err := observer.SealListenerOutcome(
		ctx,
		task11SyntheticListenerOutcome{
			RunnerID: held.RunnerID(),
			ExitCode: exitCode,
			Stream:   stream,
		},
	); err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	normalExit := exitCode == task11synthetic.NormalExitStatus
	if normalExit {
		if err := d.store.Advance(
			ctx,
			plan.AssignmentKey,
			controller.StateJobRunning,
		); err != nil {
			return task11synthetic.Stream{},
				task11SyntheticProvedCleanup{},
				ErrFixtureStart
		}
		if err := d.store.Advance(
			ctx,
			plan.AssignmentKey,
			controller.StateJobFinished,
		); err != nil {
			return task11synthetic.Stream{},
				task11SyntheticProvedCleanup{},
				ErrFixtureStart
		}
	}

	cleanupCtx, cancel := context.WithTimeout(
		context.Background(),
		durationMilliseconds(
			d.input.Limits.CleanupTimeoutMilliseconds,
		),
	)
	defer cancel()
	if err := cycleState.composition.Orchestrator.DestroyLive(
		cleanupCtx,
		live,
	); err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureCleanup
	}
	proved, err = observer.proveEvidence(cleanupCtx)
	if err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureCleanup
	}
	if normalExit {
		if err := d.store.Advance(
			cleanupCtx,
			plan.AssignmentKey,
			controller.StateDestroyed,
		); err != nil {
			return task11synthetic.Stream{},
				task11SyntheticProvedCleanup{},
				ErrFixtureStart
		}
	} else {
		resolution, err := decodeTask11SyntheticDigest(
			proved.proof.ObservationDigest,
		)
		if err != nil {
			return task11synthetic.Stream{},
				task11SyntheticProvedCleanup{},
				ErrFixtureStart
		}
		if err := d.store.ResolvePostRelease(
			cleanupCtx,
			plan.AssignmentKey,
			controller.PostReleaseDestroyed,
			resolution,
			d.now().UTC(),
		); err != nil {
			return task11synthetic.Stream{},
				task11SyntheticProvedCleanup{},
				ErrFixtureStart
		}
	}
	if err := d.requireTerminalReplay(
		cleanupCtx,
		plan,
		offer,
		evidence,
		state.EffectCompleted,
	); err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureStart
	}
	if err := cycleState.markRemoved(); err != nil {
		return task11synthetic.Stream{},
			task11SyntheticProvedCleanup{},
			ErrFixtureCleanup
	}
	return stream, proved, nil
}

func (d *linuxTask11SyntheticDriver) runCancellationCycle(
	ctx context.Context,
	request task11SyntheticCycleRequest,
) (result task11SyntheticCycleResult, resultErr error) {
	cycle, err := deriveTask11SyntheticCycleIdentity(
		d.input.Fixture.Root,
		d.input.Authorization.RunID,
		request,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	caseCtx, cancelCase := context.WithCancel(ctx)
	defer cancelCase()
	cycleState, _, plan, offer, evidence, err := d.prepareCycle(
		caseCtx,
		cycle,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, err
	}
	defer func() {
		if resultErr != nil {
			cleanupCtx, cancel := context.WithTimeout(
				context.Background(),
				durationMilliseconds(
					d.input.Limits.CleanupTimeoutMilliseconds,
				),
			)
			defer cancel()
			if cleanupErr := cycleState.cleanup(cleanupCtx); cleanupErr != nil {
				resultErr = ErrFixtureCleanup
			}
		}
	}()
	held, err := cycleState.composition.Orchestrator.Prepare(
		caseCtx,
		cycleState.composition.Request,
	)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	cycleState.setHeld(held)
	observer, err := d.armFullObserver(caseCtx, cycleState, held)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	releaseEffect, err := d.store.LookupAssignmentEffect(
		caseCtx,
		plan.AssignmentKey,
		networkjail.StageListenerRelease.String(),
	)
	if err != nil || releaseEffect.State != state.EffectAbsent {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	cancelCase()
	cleanupCtx, cancel := context.WithTimeout(
		context.Background(),
		durationMilliseconds(
			d.input.Limits.CleanupTimeoutMilliseconds,
		),
	)
	defer cancel()
	if err := observer.SealNoListenerOutcome(
		cleanupCtx,
		task11SyntheticNoListenerOutcome{
			Reason: task11NoListenerCancellation,
		},
	); err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	if err := cycleState.composition.Orchestrator.DestroyHeld(
		cleanupCtx,
		held,
	); err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureCleanup
	}
	proved, err := observer.proveEvidence(cleanupCtx)
	if err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureCleanup
	}
	if err := d.store.AdvancePreReleaseDestroyed(
		cleanupCtx,
		plan.AssignmentKey,
	); err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	if err := d.requireTerminalReplay(
		cleanupCtx,
		plan,
		offer,
		evidence,
		state.EffectAbsent,
	); err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	if err := cycleState.markRemoved(); err != nil {
		return task11SyntheticCycleResult{}, ErrFixtureCleanup
	}
	return task11SyntheticCycleResult{
		Kind:    request.Kind,
		Ordinal: request.Ordinal,
		Cleanup: proved.proof,
	}, nil
}

func (d *linuxTask11SyntheticDriver) prepareCycle(
	ctx context.Context,
	cycle task11SyntheticCycleIdentity,
) (
	*linuxTask11SyntheticCycleState,
	ConformanceInput,
	compositionPlan,
	state.OfferIdentity,
	state.OfferEvidence,
	error,
) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	rootHandle, err := task11CycleRootHandle(cycle)
	if err != nil {
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	cycleState := &linuxTask11SyntheticCycleState{
		driver:     d,
		cycle:      cycle,
		rootHandle: rootHandle,
		removed:    make(map[cleanupHandle]bool),
	}
	if err := cycleState.recordHandle(rootHandle); err != nil {
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	root, binding, err := createLinuxTask11SyntheticCycleRoot(
		d.input.Fixture,
		cycle,
	)
	if err != nil {
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	cycleState.root = root
	if err := root.prepareBrokerDirectories(); err != nil {
		_ = cycleState.cleanup(context.Background())
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, err
	}
	cycleInput, cycleOverlay, plan, seedIDs, err :=
		task11SyntheticCycleCompositionInputs(
			d.input,
			d.overlay,
			binding,
			cycle,
		)
	if err != nil {
		_ = cycleState.cleanup(context.Background())
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	cycleNow := d.now().UTC()
	offer, evidence, err := compositionOfferFrom(plan, cycleNow)
	if err != nil ||
		seedCompositionAssignment(
			ctx,
			d.store,
			plan,
			cycleNow,
		) != nil {
		_ = cycleState.cleanup(context.Background())
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	composition, err := newFixtureRuntimeComposition(
		ctx,
		cycleInput,
		cycleOverlay,
		d.static,
		d.seccomp,
		d.graph,
		d.policy,
		d.probes,
		plan,
		d.store,
		d.clock,
		d.peerObserver,
		cycleState.recordHandle,
	)
	if err != nil {
		_ = cycleState.cleanup(context.Background())
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	composition.Request.Runner.Image =
		d.input.Images.SyntheticListener.Reference
	composition.Request.SeedIDs = append([]string(nil), seedIDs...)
	recovery, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    cycleOverlay.Commands.DockerBinary,
			BrokerRoot:    cycleOverlay.Paths.BrokerRoot,
			SeccompRoot:   cycleOverlay.Paths.SeccompRoot,
			BrokerNetwork: cycleOverlay.Docker.BrokerNetworkID,
		},
		plan.CommandRunner,
	)
	if err != nil {
		_ = cycleState.cleanup(context.Background())
		return nil, ConformanceInput{}, compositionPlan{},
			state.OfferIdentity{}, state.OfferEvidence{}, ErrFixtureStart
	}
	cycleState.composition = &composition
	cycleState.recovery = recovery
	return cycleState, cycleInput, plan, offer, evidence, nil
}

func (d *linuxTask11SyntheticDriver) armFullObserver(
	ctx context.Context,
	cycleState *linuxTask11SyntheticCycleState,
	held networkjail.HeldJail,
) (*task11SyntheticCleanupObserver, error) {
	return d.armObserverFromIdentities(
		ctx,
		cycleState,
		hostruntime.RecoveredIdentities{
			AdapterID: held.AdapterID(),
			BrokerID:  held.BrokerID(),
			RunnerID:  held.RunnerID(),
		},
		true,
		true,
	)
}

func (d *linuxTask11SyntheticDriver) armObserverFromIdentities(
	ctx context.Context,
	cycleState *linuxTask11SyntheticCycleState,
	identities hostruntime.RecoveredIdentities,
	authorityExpected bool,
	relayExpected bool,
) (*task11SyntheticCleanupObserver, error) {
	if d == nil || cycleState == nil ||
		cycleState.composition == nil ||
		cycleState.recovery == nil {
		return nil, ErrFixtureStart
	}
	recovery, expected, err := task11SyntheticRecoveryBinding(
		d.input,
		cycleState.cycle,
		identities,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	snapshot, err := cycleState.recovery.InspectManaged(ctx, recovery)
	if err != nil ||
		snapshot.Observation() != expected ||
		snapshot.Identities() != identities {
		return nil, ErrFixtureStart
	}
	return d.armObserverFromSnapshot(
		ctx,
		cycleState,
		recovery,
		expected,
		snapshot,
		authorityExpected,
		relayExpected,
	)
}

func (d *linuxTask11SyntheticDriver) armObserverFromSnapshot(
	ctx context.Context,
	cycleState *linuxTask11SyntheticCycleState,
	recovery hostruntime.RecoverySpec,
	expected hostruntime.ManagedObservation,
	snapshot hostruntime.ManagedSnapshot,
	authorityExpected bool,
	relayExpected bool,
) (*task11SyntheticCleanupObserver, error) {
	if d == nil || cycleState == nil ||
		cycleState.composition == nil ||
		cycleState.recovery == nil ||
		ctx == nil ||
		ctx.Err() != nil {
		return nil, ErrFixtureStart
	}
	identities := snapshot.Identities()
	derivedRecovery, derivedExpected, err := task11SyntheticRecoveryBinding(
		d.input,
		cycleState.cycle,
		identities,
	)
	if err != nil ||
		derivedRecovery != recovery ||
		derivedExpected != expected ||
		snapshot.Observation() != expected {
		return nil, ErrFixtureStart
	}
	probe, err := newLinuxTask11SyntheticCleanupProbe(
		d.overlay.Commands.DockerBinary,
		d.command,
		cycleState.recovery,
		cycleState.root,
		cycleState.composition.AuthorityManager,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	observer, err := newTask11SyntheticCleanupObserver(
		task11SyntheticCleanupObserverBinding{
			PrimaryRoot:      d.input.Fixture.Root,
			PrimaryRunDigest: d.input.Authorization.RunID,
			Cycle:            cycleState.cycle,
			Recovery:         recovery,
			Expected:         expected,

			CapacitySlotID: cycleState.cycle.Composition.CapacitySlotID,
			JobGeneration:  cycleState.cycle.Composition.JobGeneration,
			CgroupVersion:  d.cgroup,
			MaximumProcesses: d.input.Limits.
				MaximumProcesses,
			MaximumFileDescriptors: d.input.Limits.
				MaximumFileDescriptors,
			Cadence: durationMilliseconds(
				d.input.Limits.ObservationCadenceMilliseconds,
			),
			Deadline: durationMilliseconds(
				d.input.Limits.CleanupSLOMilliseconds,
			),
			PayloadVersionCount: 1,
			AuthorityExpected:   authorityExpected,
			RelaySocketExpected: relayExpected,
		},
		probe,
	)
	if err != nil ||
		observer.ArmStructural(ctx, snapshot) != nil {
		return nil, ErrFixtureStart
	}
	return observer, nil
}

func (e *task11SyntheticPreListenerEngine) CreateNetworkAdapter(
	ctx context.Context,
	spec hostruntime.AdapterSpec,
) (hostruntime.AdapterHandle, error) {
	if e == nil || e.Engine == nil || e.driver == nil ||
		ctx == nil || ctx.Err() != nil {
		return hostruntime.AdapterHandle{}, ErrFixtureStart
	}
	e.mu.Lock()
	if e.adapter.ID() != "" || e.fired {
		e.mu.Unlock()
		return hostruntime.AdapterHandle{}, ErrFixtureStart
	}
	e.mu.Unlock()
	handle, err := e.Engine.CreateNetworkAdapter(ctx, spec)
	if err != nil {
		return hostruntime.AdapterHandle{}, err
	}
	e.mu.Lock()
	if e.adapter.ID() != "" || e.fired {
		e.mu.Unlock()
		cleanupCtx, cancel := e.cleanupContext(ctx)
		defer cancel()
		if e.Engine.RemoveNetworkAdapter(cleanupCtx, handle) != nil {
			return hostruntime.AdapterHandle{}, ErrFixtureCleanup
		}
		return hostruntime.AdapterHandle{}, ErrFixtureStart
	}
	e.adapter = handle
	e.mu.Unlock()
	return handle, nil
}

func (e *task11SyntheticPreListenerEngine) CreateNetworkBrokerHeld(
	ctx context.Context,
	spec hostruntime.BrokerSpec,
) (hostruntime.BrokerHandle, error) {
	if e == nil || e.Engine == nil || e.driver == nil ||
		ctx == nil || ctx.Err() != nil {
		return hostruntime.BrokerHandle{}, ErrFixtureStart
	}
	e.mu.Lock()
	if e.adapter.ID() == "" || e.broker.ID() != "" || e.fired {
		e.mu.Unlock()
		return hostruntime.BrokerHandle{}, ErrFixtureStart
	}
	e.mu.Unlock()
	handle, err := e.Engine.CreateNetworkBrokerHeld(ctx, spec)
	if err != nil {
		return hostruntime.BrokerHandle{}, err
	}
	e.mu.Lock()
	if e.adapter.ID() == "" || e.broker.ID() != "" || e.fired {
		e.mu.Unlock()
		cleanupCtx, cancel := e.cleanupContext(ctx)
		defer cancel()
		if e.Engine.RemoveNetworkBroker(cleanupCtx, handle) != nil {
			return hostruntime.BrokerHandle{}, ErrFixtureCleanup
		}
		return hostruntime.BrokerHandle{}, ErrFixtureStart
	}
	e.broker = handle
	e.mu.Unlock()
	return handle, nil
}

func (e *task11SyntheticPreListenerEngine) CreateRunner(
	ctx context.Context,
	spec hostruntime.RunnerSpec,
) (hostruntime.RunnerHandle, error) {
	if e == nil || e.Engine == nil || e.driver == nil ||
		ctx == nil || ctx.Err() != nil {
		return hostruntime.RunnerHandle{}, ErrFixtureStart
	}
	e.mu.Lock()
	if e.adapter.ID() == "" ||
		e.broker.ID() == "" ||
		e.runner.ID() != "" ||
		e.fired {
		e.mu.Unlock()
		return hostruntime.RunnerHandle{}, ErrFixtureStart
	}
	e.mu.Unlock()
	handle, err := e.Engine.CreateRunner(ctx, spec)
	if err != nil {
		return hostruntime.RunnerHandle{}, err
	}
	e.mu.Lock()
	if e.adapter.ID() == "" ||
		e.broker.ID() == "" ||
		e.runner.ID() != "" ||
		e.fired {
		e.mu.Unlock()
		cleanupCtx, cancel := e.cleanupContext(ctx)
		defer cancel()
		if e.Engine.RemoveRunner(cleanupCtx, handle) != nil {
			return hostruntime.RunnerHandle{}, ErrFixtureCleanup
		}
		return hostruntime.RunnerHandle{}, ErrFixtureStart
	}
	e.runner = handle
	e.mu.Unlock()
	return handle, nil
}

func (e *task11SyntheticPreListenerEngine) cleanupContext(
	parent context.Context,
) (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.WithoutCancel(parent),
		durationMilliseconds(
			e.driver.input.Limits.CleanupTimeoutMilliseconds,
		),
	)
}

func (e *task11SyntheticPreListenerEngine) AuthorizeRelease(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
	preArm hostruntime.NetworkNamespaceProof,
	final hostruntime.NetworkNamespaceProof,
) (hostruntime.ReleaseAuthorization, error) {
	if e == nil || e.Engine == nil || e.driver == nil || e.state == nil {
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	e.mu.Lock()
	if e.fired ||
		e.observer != nil ||
		e.adapter.ID() == "" ||
		e.broker.ID() == "" ||
		e.runner.ID() == "" ||
		e.runner.ID() != handle.ID() {
		e.mu.Unlock()
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	e.fired = true
	identities := hostruntime.RecoveredIdentities{
		AdapterID: e.adapter.ID(),
		BrokerID:  e.broker.ID(),
		RunnerID:  e.runner.ID(),
	}
	e.mu.Unlock()
	observer, err := e.driver.armObserverFromIdentities(
		ctx,
		e.state,
		identities,
		true,
		true,
	)
	if err != nil {
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	if err := observer.SealNoListenerOutcome(
		ctx,
		task11SyntheticNoListenerOutcome{
			Reason: task11NoListenerPreListenerFailure,
		},
	); err != nil {
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.observer != nil {
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	e.observer = observer
	return hostruntime.ReleaseAuthorization{},
		errTask11SyntheticPreListener
}

func (e *task11SyntheticPreListenerEngine) completedObserver() (
	*task11SyntheticCleanupObserver,
	bool,
) {
	if e == nil {
		return nil, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.observer, e.fired && e.observer != nil
}

func (d *linuxTask11SyntheticDriver) requireTerminalReplay(
	ctx context.Context,
	plan compositionPlan,
	offer state.OfferIdentity,
	evidence state.OfferEvidence,
	expectedListener state.EffectState,
) error {
	receipt, err := d.store.RecordOffer(ctx, offer, evidence)
	if err != nil ||
		receipt.Key != plan.AssignmentKey ||
		receipt.Disposition != state.OfferTerminalReplay ||
		receipt.State != controller.StateDestroyed {
		return ErrFixtureStart
	}
	listener, err := d.store.LookupAssignmentEffect(
		ctx,
		plan.AssignmentKey,
		networkjail.StageListenerRelease.String(),
	)
	if err != nil ||
		listener.State != expectedListener ||
		listener.ResultIdentity != "" ||
		listener.ReasonCode != "" {
		return ErrFixtureStart
	}
	return nil
}

func task11SyntheticCycleNonce(
	cycle task11SyntheticCycleIdentity,
	scenario task11synthetic.Scenario,
) (string, error) {
	return recordingCanonicalDigest(
		task11SyntheticNonceDomain,
		struct {
			SchemaVersion uint32                   `json:"schema_version"`
			Cycle         task11SyntheticCycleKind `json:"cycle"`
			Ordinal       uint64                   `json:"ordinal"`
			RunDigest     string                   `json:"run_digest"`
			Scenario      task11synthetic.Scenario `json:"scenario"`
		}{
			SchemaVersion: 1,
			Cycle:         cycle.Request.Kind,
			Ordinal:       cycle.Request.Ordinal,
			RunDigest:     cycle.RunDigest,
			Scenario:      scenario,
		},
	)
}

func decodeTask11SyntheticDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return result, ErrFixtureStart
	}
	copy(result[:], decoded)
	return result, nil
}

func (s *linuxTask11SyntheticCycleState) recordHandle(
	handle cleanupHandle,
) error {
	if s == nil || s.driver == nil ||
		!validCleanupKind(handle.kind) ||
		!isLowerHex(handle.id, 64) {
		return ErrFixtureStart
	}
	d := s.driver
	d.mu.Lock()
	if _, exists := d.owners[handle]; exists {
		d.mu.Unlock()
		return ErrFixtureStart
	}
	d.mu.Unlock()
	if err := d.record(handle); err != nil {
		return ErrFixtureStart
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.owners[handle]; exists {
		return ErrFixtureStart
	}
	d.owners[handle] = s
	s.mu.Lock()
	s.handles = append(s.handles, handle)
	s.mu.Unlock()
	return nil
}

func (s *linuxTask11SyntheticCycleState) setHeld(
	held networkjail.HeldJail,
) {
	s.mu.Lock()
	s.held = held
	s.heldReady = true
	s.mu.Unlock()
}

func (s *linuxTask11SyntheticCycleState) setLive(
	live networkjail.LiveJail,
) {
	s.mu.Lock()
	s.live = live
	s.liveReady = true
	s.mu.Unlock()
}

func (s *linuxTask11SyntheticCycleState) cleanup(
	ctx context.Context,
) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrFixtureCleanup
	}
	s.mu.Lock()
	if s.cleanupDone {
		err := s.cleanupErr
		s.mu.Unlock()
		return err
	}
	s.cleanupDone = true
	composition := s.composition
	root := s.root
	held := s.held
	heldReady := s.heldReady
	live := s.live
	liveReady := s.liveReady
	handles := append([]cleanupHandle(nil), s.handles...)
	s.mu.Unlock()

	var cleanupErr error
	if composition != nil {
		switch {
		case liveReady:
			cleanupErr = composition.Orchestrator.DestroyLive(ctx, live)
		case heldReady:
			cleanupErr = composition.Orchestrator.DestroyHeld(ctx, held)
		default:
			for index := len(handles) - 1; index >= 0; index-- {
				handle := handles[index]
				var err error
				switch handle.kind {
				case CleanupAdapter, CleanupBroker, CleanupRunner:
					err = composition.Engine.RemoveRecorded(ctx, handle)
				case CleanupVerifier:
					err = composition.OneShotLeases.Remove(ctx, handle)
				}
				if err != nil && cleanupErr == nil {
					cleanupErr = err
				}
			}
		}
	}
	if root != nil {
		if err := root.removeEmpty(); err != nil && cleanupErr == nil {
			cleanupErr = err
		}
	} else if _, err := os.Lstat(s.cycle.Root); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		if cleanupErr == nil {
			cleanupErr = ErrFixtureCleanup
		}
	}
	if cleanupErr == nil {
		cleanupErr = s.markRemoved()
	}
	if cleanupErr != nil {
		cleanupErr = ErrFixtureCleanup
	}
	s.mu.Lock()
	s.cleanupErr = cleanupErr
	s.mu.Unlock()
	return cleanupErr
}

func (s *linuxTask11SyntheticCycleState) markRemoved() error {
	if s == nil {
		return ErrFixtureCleanup
	}
	s.mu.Lock()
	handles := append([]cleanupHandle(nil), s.handles...)
	composition := s.composition
	rootHandle := s.rootHandle
	s.mu.Unlock()
	if len(handles) == 0 {
		return ErrFixtureCleanup
	}
	for _, handle := range handles {
		var absent bool
		switch {
		case handle == rootHandle:
			_, err := os.Lstat(s.cycle.Root)
			absent = errors.Is(err, os.ErrNotExist)
		case handle.kind == CleanupVerifier:
			absent = composition != nil &&
				composition.OneShotLeases.RecordedRemoved(handle)
		case handle.kind == CleanupAdapter ||
			handle.kind == CleanupBroker ||
			handle.kind == CleanupRunner:
			absent = composition != nil &&
				composition.Engine.RecordedRemoved(handle)
		}
		if !absent {
			return ErrFixtureCleanup
		}
	}
	s.mu.Lock()
	for _, handle := range handles {
		s.removed[handle] = true
	}
	s.cleanupDone = true
	s.cleanupErr = nil
	s.mu.Unlock()
	return nil
}

func (s *linuxTask11SyntheticCycleState) markRecoveredRemoved(
	proved task11SyntheticProvedCleanup,
	identities hostruntime.RecoveredIdentities,
) error {
	if s == nil {
		return ErrFixtureCleanup
	}
	s.mu.Lock()
	composition := s.composition
	cycle := s.cycle
	s.mu.Unlock()
	if composition == nil ||
		composition.Engine == nil ||
		proved.binding.Cycle != cycle ||
		proved.binding.Recovery.ExpectedAdapterID != identities.AdapterID ||
		proved.binding.Recovery.ExpectedBrokerID != identities.BrokerID ||
		proved.binding.Recovery.ExpectedRunnerID != identities.RunnerID ||
		!validTask11SyntheticProvedCleanup(proved, proved.binding) {
		return ErrFixtureCleanup
	}
	if err := composition.Engine.markRecoveredRemoved(
		identities,
	); err != nil {
		return ErrFixtureCleanup
	}
	return s.markRemoved()
}

func (s *linuxTask11SyntheticCycleState) handlesSnapshot() (
	[]cleanupHandle,
	error,
) {
	if s == nil {
		return nil, ErrFixtureCleanup
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.handles) == 0 {
		return nil, ErrFixtureCleanup
	}
	return append([]cleanupHandle(nil), s.handles...), nil
}

func (d *linuxTask11SyntheticDriver) owns(handle cleanupHandle) bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.owners[handle] != nil
}

func (d *linuxTask11SyntheticDriver) remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if d == nil {
		return ErrFixtureCleanup
	}
	d.mu.Lock()
	owner := d.owners[handle]
	d.mu.Unlock()
	if owner == nil || owner.cleanup(ctx) != nil ||
		!owner.removedHandle(handle) {
		return ErrFixtureCleanup
	}
	return nil
}

func (d *linuxTask11SyntheticDriver) recordedRemoved(
	handle cleanupHandle,
) bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	owner := d.owners[handle]
	d.mu.Unlock()
	return owner != nil && owner.removedHandle(handle)
}

func (s *linuxTask11SyntheticCycleState) removedHandle(
	handle cleanupHandle,
) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removed[handle]
}

var (
	_ task11SyntheticLifecycleDriver = (*linuxTask11SyntheticDriver)(nil)
	_ task11SyntheticCleanupOwner    = (*linuxTask11SyntheticDriver)(nil)
)
