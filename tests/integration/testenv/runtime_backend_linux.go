//go:build integration && linux

package testenv

import (
	"context"
	"time"

	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

func (r *orchestratedFixtureRuntime) bindTask11Recovery(
	recovery *task11RecoveryRuntime,
) error {
	if r == nil ||
		recovery == nil ||
		recovery.prepared != r {
		return ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prepareAttempted || r.task11Recovery != nil {
		return ErrFixtureStart
	}
	r.task11Recovery = recovery
	return nil
}

func newLinuxFixtureRuntimeBackend(
	input ConformanceInput,
	preflight linuxStaticPreflight,
	root *lockedFixtureRootAuthority,
) (*fixtureRuntimeBackend, error) {
	if root == nil ||
		preflight.Result.AdapterBrokerUser == "" ||
		preflight.Graph.Digest().String() == "" ||
		!preflight.Policy.Valid() {
		return nil, ErrFixtureStart
	}
	plan, err := compositionPlanFrom(input, preflight.Overlay)
	if err != nil {
		return nil, ErrFixtureStart
	}
	workspaceOperations, err := newLinuxFixtureWorkspaceOperations(
		input.Fixture,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	workspaceHandle, err := compositionCleanupHandle(
		CleanupTestProcess,
		"portable-ghar.task11.workspace.v1\x00",
		input.Authorization.RunID,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	workspace, err := newFixtureWorkspace(
		workspaceOperations,
		workspaceHandle,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	clock, err := networkjail.NewSystemMonotonicClock()
	if err != nil {
		return nil, ErrFixtureStart
	}
	peerObserver := newLinuxPermitPeerProcessObserver()
	return newFixtureRuntimeBackend(
		input,
		plan,
		preflight.Result.AdapterBrokerUser,
		workspace,
		root,
		state.OpenWithHistoryLimits,
		func(
			ctx context.Context,
			store *state.SQLiteStore,
			record func(cleanupHandle) error,
		) (fixtureRuntimeGraph, error) {
			composition, compositionErr :=
				newFixtureRuntimeComposition(
					ctx,
					input,
					preflight.Overlay,
					preflight.Result,
					preflight.Seccomp,
					preflight.Graph,
					preflight.Policy,
					preflight.Probes,
					plan,
					store,
					clock,
					peerObserver,
					record,
				)
			if compositionErr != nil {
				return nil, ErrFixtureStart
			}
			runtimeGraph, runtimeErr :=
				newOrchestratedFixtureRuntime(composition)
			if runtimeErr != nil {
				return nil, ErrFixtureStart
			}
			lossAttempt, lossErr :=
				newTask11RealLossAttemptSource(
					input,
					preflight.Overlay,
					preflight.Result,
					preflight.Seccomp,
					preflight.Graph,
					preflight.Policy,
					preflight.Probes,
					plan,
					store,
					clock,
					peerObserver,
					record,
					time.Now,
				)
			if lossErr != nil {
				return nil, ErrFixtureStart
			}
			lossPrevention, lossErr :=
				newTask11LossPreventionRuntime(
					task11LossPreventionBinding{
						PrimaryRunDigest: input.Authorization.RunID,
						PrimaryCapacitySlotID: networkjail.CapacitySlotID(
							plan.Identity.CapacitySlotID,
						),
						PrimaryJobGeneration: networkjail.JobGeneration(
							plan.Identity.JobGeneration,
						),
						MissingFact: task11MissingBrokerAuditEvidence,
					},
					runtimeGraph,
					lossAttempt,
				)
			if lossErr != nil ||
				runtimeGraph.bindTask11LossPrevention(
					lossPrevention,
					lossAttempt,
				) != nil ||
				runtimeGraph.bindTask11CasesThreeToSix() != nil {
				return nil, ErrFixtureStart
			}
			workflow, workflowErr :=
				newTask11WorkflowToolRuntime(
					runtimeGraph,
					preflight.Overlay.Commands.DockerBinary,
					input.Limits.MaximumEvidenceBytes,
					plan.CommandRunner,
					record,
					input.WorkflowTools,
					preflight.Result.WorkflowToolUsers,
					plan.RuntimeLimits.WorkflowToolProbe,
					preflight.Seccomp,
				)
			if workflowErr != nil ||
				runtimeGraph.bindTask11WorkflowTool(
					workflow,
				) != nil {
				return nil, ErrFixtureStart
			}
			syntheticDriver, syntheticErr :=
				newLinuxTask11SyntheticDriver(
					input,
					preflight.Overlay,
					preflight.Result,
					preflight.Seccomp,
					preflight.Graph,
					preflight.Policy,
					preflight.Probes,
					store,
					clock,
					peerObserver,
					record,
					time.Now,
				)
			if syntheticErr != nil {
				return nil, ErrFixtureStart
			}
			synthetic, syntheticErr :=
				newTask11SyntheticLifecycleRuntime(
					input.Limits.ReclamationSampleCount,
					runtimeGraph,
					syntheticDriver,
				)
			if syntheticErr != nil ||
				runtimeGraph.bindTask11SyntheticLifecycle(
					synthetic,
				) != nil {
				return nil, ErrFixtureStart
			}
			recoveryDriver, recoveryErr :=
				newLinuxTask11RecoveryDriver(
					input,
					preflight.Overlay,
					plan,
				)
			if recoveryErr != nil {
				return nil, ErrFixtureStart
			}
			recovery, recoveryErr := newTask11RecoveryRuntime(
				runtimeGraph,
				recoveryDriver,
			)
			if recoveryErr != nil ||
				runtimeGraph.bindTask11Recovery(recovery) != nil {
				return nil, ErrFixtureStart
			}
			// Registration is deliberately the last fallible construction
			// step. Once the cleanup handle is published, the fully bound
			// runtime is returned without another failure window.
			if recoveryDriver.register(record) != nil {
				return nil, ErrFixtureStart
			}
			return runtimeGraph, nil
		},
		time.Now,
	)
}
