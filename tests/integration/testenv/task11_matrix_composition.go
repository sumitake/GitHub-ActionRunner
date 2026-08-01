package testenv

import (
	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type task11MatrixRuntimes struct {
	Namespace   namespaceEvidenceRuntime
	Broker      brokerCaseRuntime
	MountSecret mountSecretRuntime
	Sandbox     sandboxRuntime
	Runner      runnerPayloadRuntime
	OneJob      syntheticOneJobRuntime
	Cleanup     cleanupMatrixRuntime
	Reclamation reclamationRuntime
	Workflow    workflowToolProbeRuntime
	Seed        seedIsolationRuntime
	Recovery    recoveryRuntime
}

type task11MatrixComposition struct {
	Cases     *matrixCaseExecutor
	Finalizer *dynamicTargetFinalizer
	Source    *compositeMatrixObservationSource
	Ledger    *preparedRuntimeEvidenceLedger
}

func newTask11MatrixComposition(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
	graph networkjail.DecisionGraph,
	plan compositionPlan,
	runtimes task11MatrixRuntimes,
) (*task11MatrixComposition, error) {
	graphDigest := graph.Digest().String()
	expectedIdentity, identityErr := deriveCompositionIdentity(
		input.Authorization.RunID,
	)
	if identityErr != nil ||
		plan.Identity != expectedIdentity ||
		!isLowerHex(input.Runtime.BuildID, 64) ||
		input.Runtime.BuildID != static.ManifestBuildID ||
		input.Runtime.FleetGeneration == 0 ||
		input.LoopbackFloodAttempts == 0 ||
		!isLowerHex(graphDigest, 64) ||
		input.Runtime.PolicyDigest != graphDigest ||
		static.PolicyGraphDigest != graphDigest {
		return nil, ErrFixtureStart
	}
	ledger, err := newPreparedRuntimeEvidenceLedger(
		input.LoopbackFloodAttempts,
		runtimes.Namespace,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	hostProfile, err := newHostProfileMatrixSource(
		input,
		overlay,
		static,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	executionIdentity, err := newExecutionIdentityMatrixSource(
		input.Target,
		static.HostFacts.HostIdentityDigest,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	namespace, err := newNamespaceBaselineMatrixSourceFromLedger(ledger)
	if err != nil {
		return nil, ErrFixtureStart
	}
	broker, err := newBrokerEgressMatrixSource(ledger, runtimes.Broker)
	if err != nil {
		return nil, ErrFixtureStart
	}
	mountSecret, err := newMountSecretMatrixSource(
		ledger,
		runtimes.MountSecret,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	sandbox, err := newSandboxMatrixSource(ledger, runtimes.Sandbox)
	if err != nil {
		return nil, ErrFixtureStart
	}
	runner, err := newRunnerPayloadMatrixSource(ledger, runtimes.Runner)
	if err != nil {
		return nil, ErrFixtureStart
	}
	oneJob, err := newSyntheticOneJobMatrixSource(
		ledger,
		runtimes.OneJob,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	cleanup, err := newCleanupMatrixSource(ledger, runtimes.Cleanup)
	if err != nil {
		return nil, ErrFixtureStart
	}
	reclamation, err := newReclamationMatrixSource(
		ledger,
		input.Baselines,
		input.Limits.ReclamationSampleCount,
		runtimes.Reclamation,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	workflow, err := newWorkflowToolMatrixSource(
		ledger,
		input.WorkflowTools,
		static.WorkflowToolUsers,
		plan.RuntimeLimits.WorkflowToolProbe,
		hostruntime.SeccompBinding{
			Path:   input.Runtime.SeccompPath,
			SHA256: input.Runtime.SeccompDigest,
		},
		runtimes.Workflow,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	seed, err := newSeedIsolationMatrixSource(ledger, runtimes.Seed)
	if err != nil {
		return nil, ErrFixtureStart
	}
	recovery, err := newRecoveryMatrixSource(ledger, runtimes.Recovery)
	if err != nil {
		return nil, ErrFixtureStart
	}
	routes := make(
		map[ObservationID]matrixObservationSource,
		len(preCanaryObservationRequirements()),
	)
	for _, requirement := range preCanaryObservationRequirements() {
		var source matrixObservationSource
		switch requirement.Case {
		case conformance.CaseHostProfile:
			if requirement.ID == "host-execution-identity" {
				source = executionIdentity
			} else {
				source = hostProfile
			}
		case conformance.CaseNamespaceBaseline:
			source = namespace
		case conformance.CaseBrokerEgress:
			source = broker
		case conformance.CaseMountAndSecretIsolation:
			source = mountSecret
		case conformance.CaseSandbox:
			source = sandbox
		case conformance.CaseRunnerPayload:
			source = runner
		case conformance.CaseSyntheticOneJob:
			source = oneJob
		case conformance.CaseCleanupMatrix:
			source = cleanup
		case conformance.CaseReclamationSeries:
			source = reclamation
		case conformance.CaseProxyToolCompatibility:
			source = workflow
		case conformance.CaseSeedIsolation:
			source = seed
		case conformance.CaseWatchdogRecovery,
			conformance.CaseLegacyFenceRecovery,
			conformance.CaseNoncancellableShutdown:
			source = recovery
		}
		if source == nil {
			return nil, ErrFixtureStart
		}
		routes[requirement.ID] = source
	}
	composite, err := newCompositeMatrixObservationSource(
		matrixEvidenceBinding{
			RunID:           input.Authorization.RunID,
			BuildID:         input.Runtime.BuildID,
			FleetGeneration: input.Runtime.FleetGeneration,
			ProfileID:       input.Target.ProfileID,
			SlotIdentity:    plan.Identity.SlotIdentity,
			GraphDigest:     graphDigest,
		},
		ledger,
		routes,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	cases, err := newMatrixCaseExecutor(composite)
	if err != nil {
		return nil, ErrFixtureStart
	}
	finalizer, err := newDynamicTargetFinalizer(
		input,
		overlay,
		static,
		graph,
		composite,
		composite,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	return &task11MatrixComposition{
		Cases:     cases,
		Finalizer: finalizer,
		Source:    composite,
		Ledger:    ledger,
	}, nil
}
