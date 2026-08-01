package hostruntime

import (
	"context"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type passingConformanceProfile struct {
	binding conformance.Binding
	github  conformance.ActualGitHubResult
	cleanup conformance.CleanupEvidence
}

func newPassingConformanceProfile(
	t *testing.T,
	actualGitHub bool,
) *passingConformanceProfile {
	t.Helper()
	binding, err := conformance.NewBinding(conformance.BindingInput{
		SchemaVersion:                 1,
		BuildID:                       repeatHex("a"),
		SourceCommit:                  "1111111111111111111111111111111111111111",
		RuntimeManifestDigest:         repeatHex("b"),
		PrivateOverlayDigest:          repeatHex("c"),
		ConformanceInputDigest:        repeatHex("d"),
		AuthorizationDigest:           repeatHex("a"),
		RunID:                         repeatHex("b"),
		ProfileID:                     "strict-linux",
		FleetGeneration:               23,
		ExpectedProfileEvidenceDigest: repeatHex("c"),
		ExpectedNetworkEvidenceDigest: repeatHex("d"),
		PlanDigest:                    repeatHex("a"),
	})
	if err != nil {
		t.Fatalf("NewBinding: %v", err)
	}
	plain := conformance.ObservationInput{
		AssertionCount:    2,
		ObservationDigest: repeatHex("b"),
	}
	cleanup, err := conformance.SealCleanup(
		conformance.CleanupObservation(plain),
	)
	if err != nil {
		t.Fatalf("SealCleanup: %v", err)
	}
	github := conformance.PendingActualGitHubTransport()
	if actualGitHub {
		github, err = conformance.SealActualGitHubTransport(
			conformance.ActualGitHubObservation(plain),
		)
		if err != nil {
			t.Fatalf("SealActualGitHubTransport: %v", err)
		}
	}
	return &passingConformanceProfile{
		binding: binding,
		github:  github,
		cleanup: cleanup,
	}
}

func (p *passingConformanceProfile) Binding() (conformance.Binding, error) {
	return p.binding, nil
}

func (*passingConformanceProfile) RunActualHost(
	_ context.Context,
	id conformance.ActualHostCaseID,
) (conformance.ActualHostResult, error) {
	input := conformance.ObservationInput{
		AssertionCount:    2,
		ObservationDigest: repeatHex("b"),
	}
	switch id {
	case conformance.ActualHostProfile:
		return conformance.SealHostProfile(
			conformance.HostProfileObservation(input),
		)
	case conformance.ActualNamespaceBaseline:
		return conformance.SealNamespaceBaseline(
			conformance.NamespaceObservation(input),
		)
	case conformance.ActualBrokerEgress:
		return conformance.SealBrokerEgress(
			conformance.BrokerEgressObservation(input),
		)
	case conformance.ActualMountAndSecretIsolation:
		return conformance.SealMountAndSecretIsolation(
			conformance.MountSecretObservation(input),
		)
	case conformance.ActualRunnerSandbox:
		return conformance.SealRunnerSandbox(
			conformance.RunnerSandboxObservation(input),
		)
	case conformance.ActualRunnerPayload:
		return conformance.SealRunnerPayload(
			conformance.RunnerPayloadObservation(input),
		)
	case conformance.ActualProxyToolCompatibility:
		return conformance.SealProxyToolCompatibility(
			conformance.ProxyToolObservation(input),
		)
	default:
		return conformance.ActualHostResult{}, conformance.ErrInvariant
	}
}

func (*passingConformanceProfile) RunSynthetic(
	_ context.Context,
	id conformance.SyntheticCaseID,
) (conformance.SyntheticResult, error) {
	input := conformance.ObservationInput{
		AssertionCount:    2,
		ObservationDigest: repeatHex("b"),
	}
	switch id {
	case conformance.SyntheticOneJob:
		return conformance.SealSyntheticOneJob(
			conformance.SyntheticJobObservation(input),
		)
	case conformance.SyntheticCleanupMatrix:
		return conformance.SealCleanupMatrix(
			conformance.CleanupMatrixObservation(input),
		)
	case conformance.SyntheticReclamationSeries:
		return conformance.SealReclamationSeries(
			conformance.ReclamationObservation{
				AssertionCount:    2,
				ObservationDigest: repeatHex("b"),
				Measurements: []conformance.MeasurementInput{{
					Name:  "sample_count",
					Value: 3,
					Unit:  "count",
				}},
			},
		)
	case conformance.SyntheticSeedIsolation:
		return conformance.SealSeedIsolation(
			conformance.SeedObservation(input),
		)
	case conformance.SyntheticWatchdogRecovery:
		return conformance.SealWatchdogRecovery(
			conformance.WatchdogObservation(input),
		)
	case conformance.SyntheticLegacyFenceRecovery:
		return conformance.SealLegacyFenceRecovery(
			conformance.LegacyFenceObservation(input),
		)
	case conformance.SyntheticNoncancellableShutdown:
		return conformance.SealNoncancellableShutdown(
			conformance.ShutdownObservation(input),
		)
	default:
		return conformance.SyntheticResult{}, conformance.ErrInvariant
	}
}

func (p *passingConformanceProfile) RunActualGitHub(
	context.Context,
) (conformance.ActualGitHubResult, error) {
	return p.github, nil
}

func (*passingConformanceProfile) FinalizeTarget(
	context.Context,
) (conformance.TargetObservation, error) {
	return conformance.SealTargetObservation(
		conformance.TargetObservationInput{
			ProfileEvidenceDigest: repeatHex("c"),
			NetworkEvidenceDigest: repeatHex("d"),
		},
	)
}

func (p *passingConformanceProfile) Cleanup(
	context.Context,
) (conformance.CleanupEvidence, error) {
	return p.cleanup, nil
}

func (*passingConformanceProfile) ActualHostTimeout(
	conformance.ActualHostCaseID,
) time.Duration {
	return time.Second
}

func (*passingConformanceProfile) SyntheticTimeout(
	conformance.SyntheticCaseID,
) time.Duration {
	return time.Second
}

func (*passingConformanceProfile) ActualGitHubTimeout() time.Duration {
	return time.Second
}

func (*passingConformanceProfile) CleanupTimeout() time.Duration {
	return time.Second
}

func TestDeploymentEligibilityRequiresMatchingSourceAndTargetProofs(t *testing.T) {
	report := conformance.Run(
		context.Background(),
		newPassingConformanceProfile(t, true),
	)
	reportBinding := report.Binding()
	binding := EvidenceBinding{
		BuildID:    reportBinding.BuildID(),
		Profile:    reportBinding.ProfileID(),
		Generation: reportBinding.FleetGeneration(),
	}
	source, err := recordSourceVerification(binding, repeatHex("b"))
	if err != nil {
		t.Fatalf("recordSourceVerification: %v", err)
	}
	target, err := NewTargetConformanceFromReport(report)
	if err != nil {
		t.Fatalf("NewTargetConformanceFromReport: %v", err)
	}

	eligible, err := NewDeploymentEligibility(source, target)
	if err != nil {
		t.Fatalf("NewDeploymentEligibility: %v", err)
	}
	if eligible.Binding() != binding {
		t.Fatalf("eligible binding = %+v, want %+v", eligible.Binding(), binding)
	}
}

func TestDeploymentEligibilityRejectsMissingOrMismatchedTarget(t *testing.T) {
	report := conformance.Run(
		context.Background(),
		newPassingConformanceProfile(t, true),
	)
	reportBinding := report.Binding()
	binding := EvidenceBinding{
		BuildID:    reportBinding.BuildID(),
		Profile:    reportBinding.ProfileID(),
		Generation: reportBinding.FleetGeneration(),
	}
	source, err := recordSourceVerification(binding, repeatHex("b"))
	if err != nil {
		t.Fatalf("recordSourceVerification: %v", err)
	}

	if _, err := NewDeploymentEligibility(source, TargetConformance{}); err == nil {
		t.Fatal("source-only proof constructed DeploymentEligibility")
	}

	target, err := NewTargetConformanceFromReport(report)
	if err != nil {
		t.Fatalf("NewTargetConformanceFromReport: %v", err)
	}
	target.binding.Generation++
	if _, err := NewDeploymentEligibility(source, target); err == nil {
		t.Fatal("mismatched evidence generations constructed DeploymentEligibility")
	}
}

func TestTargetConformanceRejectsPendingOrMissingFullReport(t *testing.T) {
	t.Parallel()

	pending := conformance.Run(
		context.Background(),
		newPassingConformanceProfile(t, false),
	)
	if _, err := NewTargetConformanceFromReport(pending); err == nil {
		t.Fatal("pending report constructed TargetConformance")
	}
	if _, err := NewTargetConformanceFromReport(conformance.Report{}); err == nil {
		t.Fatal("zero report constructed TargetConformance")
	}
}

func repeatHex(char string) string {
	result := ""
	for range 64 {
		result += char
	}
	return result
}
