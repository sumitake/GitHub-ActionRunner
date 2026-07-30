package testenv

import (
	"context"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func TestTask11MatrixCompositionRoutesEveryPreCanaryCaseAndFinalizes(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, graph, plan, runtimes :=
		validTask11MatrixCompositionInputs(t)
	composition, err := newTask11MatrixComposition(
		input,
		overlay,
		static,
		graph,
		plan,
		runtimes,
	)
	if err != nil {
		t.Fatalf("newTask11MatrixComposition: %v", err)
	}
	for _, id := range []conformance.ActualHostCaseID{
		conformance.ActualHostProfile,
		conformance.ActualNamespaceBaseline,
		conformance.ActualBrokerEgress,
		conformance.ActualMountAndSecretIsolation,
		conformance.ActualRunnerSandbox,
		conformance.ActualRunnerPayload,
	} {
		if _, err := composition.Cases.RunActualHost(
			context.Background(),
			id,
		); err != nil {
			t.Fatalf("RunActualHost(%d): %v", id, err)
		}
	}
	for _, id := range []conformance.SyntheticCaseID{
		conformance.SyntheticOneJob,
		conformance.SyntheticCleanupMatrix,
		conformance.SyntheticReclamationSeries,
	} {
		if _, err := composition.Cases.RunSynthetic(
			context.Background(),
			id,
		); err != nil {
			t.Fatalf("RunSynthetic(%d): %v", id, err)
		}
	}
	if _, err := composition.Cases.RunActualHost(
		context.Background(),
		conformance.ActualProxyToolCompatibility,
	); err != nil {
		t.Fatalf("RunActualHost(proxy tools): %v", err)
	}
	for _, id := range []conformance.SyntheticCaseID{
		conformance.SyntheticSeedIsolation,
		conformance.SyntheticWatchdogRecovery,
		conformance.SyntheticLegacyFenceRecovery,
		conformance.SyntheticNoncancellableShutdown,
	} {
		if _, err := composition.Cases.RunSynthetic(
			context.Background(),
			id,
		); err != nil {
			t.Fatalf("RunSynthetic(%d): %v", id, err)
		}
	}
	completed := conformance.RequiredCases()
	completed = completed[:len(completed)-1]
	target, err := composition.Finalizer.Finalize(
		context.Background(),
		completed,
	)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !isLowerHex(target.ProfileEvidenceDigest, 64) ||
		!isLowerHex(target.NetworkEvidenceDigest, 64) {
		t.Fatalf("target = %+v", target)
	}
	if _, _, frozen := composition.Ledger.snapshotAfterCase14(); !frozen {
		t.Fatal("shared ledger did not freeze through Case 14")
	}
}

func TestTask11MatrixCompositionRejectsMissingRuntimeOrPolicyDrift(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, graph, plan, runtimes :=
		validTask11MatrixCompositionInputs(t)
	missing := runtimes
	missing.Recovery = nil
	if _, err := newTask11MatrixComposition(
		input,
		overlay,
		static,
		graph,
		plan,
		missing,
	); err != ErrFixtureStart {
		t.Fatalf("missing recovery runtime error = %v", err)
	}

	drifted := input
	drifted.Runtime.PolicyDigest = inputDigestD
	if _, err := newTask11MatrixComposition(
		drifted,
		overlay,
		static,
		graph,
		plan,
		runtimes,
	); err != ErrFixtureStart {
		t.Fatalf("policy drift error = %v", err)
	}
}

func validTask11MatrixCompositionInputs(
	t *testing.T,
) (
	ConformanceInput,
	hostruntime.PrivateOverlay,
	staticPreflightResult,
	networkjail.DecisionGraph,
	compositionPlan,
	task11MatrixRuntimes,
) {
	t.Helper()

	input, overlay, static, graph, _ := validTargetFinalizerInputs(t)
	graphDigest := graph.Digest().String()
	input.Authorization.RunID = inputDigestA
	input.Runtime.BuildID = inputDigestB
	input.Runtime.FleetGeneration = 7
	input.Runtime.PolicyDigest = graphDigest
	input.Target.ControlHostIdentityDigest = inputDigestC
	input.Target.IdentitySeparationRequired = true
	input.LoopbackFloodAttempts = 64
	static.ManifestBuildID = input.Runtime.BuildID
	static.PolicyGraphDigest = graphDigest
	static.HostFacts.ControlHostIdentityDigest =
		input.Target.ControlHostIdentityDigest

	identity, err := deriveCompositionIdentity(input.Authorization.RunID)
	if err != nil {
		t.Fatalf("deriveCompositionIdentity: %v", err)
	}
	bindings, users, workflowLimits, seccomp :=
		validWorkflowToolSourceInputs(t)
	input.WorkflowTools = bindings
	input.Runtime.SeccompPath = seccomp.Path
	input.Runtime.SeccompDigest = seccomp.SHA256
	static.WorkflowToolUsers = users
	baselines, sampleCount, reclamation := validReclamationInputs()
	input.Baselines = baselines
	input.Limits.ReclamationSampleCount = sampleCount
	plan := compositionPlan{
		Identity: identity,
		RuntimeLimits: runtimeLimitComposition{
			WorkflowToolProbe: workflowLimits,
		},
	}
	namespace := validNamespaceEvidenceRuntime()
	namespace.observation.PolicyDigest = graphDigest
	namespace.observation.NetworkEgressReport.PolicyDigest = graphDigest
	namespace.observation.ProbeReport.PolicyDigest = graphDigest
	if namespace.observation.ProbeReport.PolicyDigest != graphDigest {
		t.Fatal("namespace policy setup failed")
	}
	return input, overlay, static, graph, plan, task11MatrixRuntimes{
		Namespace:   namespace,
		Broker:      validBrokerCaseRuntime(),
		MountSecret: validMountSecretRuntime(),
		Sandbox:     validSandboxRuntime(),
		Runner:      validRunnerPayloadRuntime(),
		OneJob:      validSyntheticOneJobRuntime(),
		Cleanup:     validCleanupMatrixRuntime(),
		Reclamation: reclamation,
		Workflow:    newFakeWorkflowToolRuntime(),
		Seed: &fakeSeedIsolationRuntime{
			proof: validSeedIsolationProof(),
		},
		Recovery: &fakeRecoveryRuntime{
			proof: validSyntheticRecoveryProof(),
		},
	}
}
