package testenv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

const (
	reportDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	reportDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	reportDigestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	reportDigestD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	reportDigestE = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	reportCommit  = "1111111111111111111111111111111111111111"
)

func TestValidateConformanceTerminalReportAcceptsPendingSourceShape(
	t *testing.T,
) {
	t.Parallel()

	report := conformance.Run(
		context.Background(),
		newReportShapeProfile(t, false),
	)
	if err := ValidateConformanceTerminalReport(report); err != nil {
		t.Fatalf("ValidateConformanceTerminalReport: %v", err)
	}
}

func TestValidateConformanceTerminalReportAcceptsAuthenticAllPassShape(
	t *testing.T,
) {
	t.Parallel()

	report := conformance.Run(
		context.Background(),
		newReportShapeProfile(t, true),
	)
	if err := ValidateConformanceTerminalReport(report); err != nil {
		t.Fatalf("ValidateConformanceTerminalReport: %v", err)
	}
}

func TestValidateConformanceTerminalReportRejectsOtherTerminalShapes(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*reportShapeProfile)
	}{
		{
			name: "earlier-case-failure",
			mutate: func(profile *reportShapeProfile) {
				profile.actualFailure = conformance.ActualBrokerEgress
			},
		},
		{
			name: "target-mismatch",
			mutate: func(profile *reportShapeProfile) {
				profile.profileDigest = reportDigestE
			},
		},
		{
			name: "cleanup-failure",
			mutate: func(profile *reportShapeProfile) {
				profile.cleanupErr = errors.New("closed cleanup failure")
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			profile := newReportShapeProfile(t, false)
			testCase.mutate(profile)
			report := conformance.Run(context.Background(), profile)
			if err := ValidateConformanceTerminalReport(report); !errors.Is(
				err,
				ErrConformanceTerminalReport,
			) {
				t.Fatalf("error = %v, want terminal report rejection", err)
			}
		})
	}
}

type reportShapeProfile struct {
	t             *testing.T
	binding       conformance.Binding
	actualGitHub  bool
	actualFailure conformance.ActualHostCaseID
	profileDigest string
	networkDigest string
	cleanupErr    error
}

func newReportShapeProfile(
	t *testing.T,
	actualGitHub bool,
) *reportShapeProfile {
	t.Helper()

	binding, err := conformance.NewBinding(conformance.BindingInput{
		SchemaVersion:                 1,
		BuildID:                       reportDigestA,
		SourceCommit:                  reportCommit,
		RuntimeManifestDigest:         reportDigestB,
		PrivateOverlayDigest:          reportDigestC,
		ConformanceInputDigest:        reportDigestD,
		AuthorizationDigest:           reportDigestA,
		RunID:                         reportDigestB,
		ProfileID:                     "qts-capless-root",
		FleetGeneration:               7,
		ExpectedProfileEvidenceDigest: reportDigestC,
		ExpectedNetworkEvidenceDigest: reportDigestD,
		PlanDigest:                    reportDigestA,
	})
	if err != nil {
		t.Fatalf("NewBinding: %v", err)
	}
	return &reportShapeProfile{
		t:             t,
		binding:       binding,
		actualGitHub:  actualGitHub,
		profileDigest: reportDigestC,
		networkDigest: reportDigestD,
	}
}

func (p *reportShapeProfile) Binding() (conformance.Binding, error) {
	return p.binding, nil
}

func (p *reportShapeProfile) RunActualHost(
	_ context.Context,
	id conformance.ActualHostCaseID,
) (conformance.ActualHostResult, error) {
	if id == p.actualFailure {
		return conformance.ActualHostResult{}, conformance.ErrInvariant
	}
	observation := conformance.ObservationInput{
		AssertionCount:    2,
		ObservationDigest: reportDigestB,
	}
	var (
		result conformance.ActualHostResult
		err    error
	)
	switch id {
	case conformance.ActualHostProfile:
		result, err = conformance.SealHostProfile(
			conformance.HostProfileObservation(observation),
		)
	case conformance.ActualNamespaceBaseline:
		result, err = conformance.SealNamespaceBaseline(
			conformance.NamespaceObservation(observation),
		)
	case conformance.ActualBrokerEgress:
		result, err = conformance.SealBrokerEgress(
			conformance.BrokerEgressObservation(observation),
		)
	case conformance.ActualMountAndSecretIsolation:
		result, err = conformance.SealMountAndSecretIsolation(
			conformance.MountSecretObservation(observation),
		)
	case conformance.ActualRunnerSandbox:
		result, err = conformance.SealRunnerSandbox(
			conformance.RunnerSandboxObservation(observation),
		)
	case conformance.ActualRunnerPayload:
		result, err = conformance.SealRunnerPayload(
			conformance.RunnerPayloadObservation(observation),
		)
	case conformance.ActualProxyToolCompatibility:
		result, err = conformance.SealProxyToolCompatibility(
			conformance.ProxyToolObservation(observation),
		)
	default:
		return conformance.ActualHostResult{}, conformance.ErrInvariant
	}
	if err != nil {
		p.t.Fatalf("seal actual host %d: %v", id, err)
	}
	return result, nil
}

func (p *reportShapeProfile) RunSynthetic(
	_ context.Context,
	id conformance.SyntheticCaseID,
) (conformance.SyntheticResult, error) {
	observation := conformance.ObservationInput{
		AssertionCount:    2,
		ObservationDigest: reportDigestB,
	}
	var (
		result conformance.SyntheticResult
		err    error
	)
	switch id {
	case conformance.SyntheticOneJob:
		result, err = conformance.SealSyntheticOneJob(
			conformance.SyntheticJobObservation(observation),
		)
	case conformance.SyntheticCleanupMatrix:
		result, err = conformance.SealCleanupMatrix(
			conformance.CleanupMatrixObservation(observation),
		)
	case conformance.SyntheticReclamationSeries:
		result, err = conformance.SealReclamationSeries(
			conformance.ReclamationObservation{
				AssertionCount:    2,
				ObservationDigest: reportDigestB,
				Measurements: []conformance.MeasurementInput{{
					Name:  "sample_count",
					Value: 3,
					Unit:  "count",
				}},
			},
		)
	case conformance.SyntheticSeedIsolation:
		result, err = conformance.SealSeedIsolation(
			conformance.SeedObservation(observation),
		)
	case conformance.SyntheticWatchdogRecovery:
		result, err = conformance.SealWatchdogRecovery(
			conformance.WatchdogObservation(observation),
		)
	case conformance.SyntheticLegacyFenceRecovery:
		result, err = conformance.SealLegacyFenceRecovery(
			conformance.LegacyFenceObservation(observation),
		)
	case conformance.SyntheticNoncancellableShutdown:
		result, err = conformance.SealNoncancellableShutdown(
			conformance.ShutdownObservation(observation),
		)
	default:
		return conformance.SyntheticResult{}, conformance.ErrInvariant
	}
	if err != nil {
		p.t.Fatalf("seal synthetic %d: %v", id, err)
	}
	return result, nil
}

func (p *reportShapeProfile) RunActualGitHub(
	context.Context,
) (conformance.ActualGitHubResult, error) {
	if !p.actualGitHub {
		return conformance.PendingActualGitHubTransport(), nil
	}
	result, err := conformance.SealActualGitHubTransport(
		conformance.ActualGitHubObservation{
			AssertionCount:    2,
			ObservationDigest: reportDigestB,
		},
	)
	if err != nil {
		p.t.Fatalf("SealActualGitHubTransport: %v", err)
	}
	return result, nil
}

func (p *reportShapeProfile) FinalizeTarget(
	context.Context,
) (conformance.TargetObservation, error) {
	result, err := conformance.SealTargetObservation(
		conformance.TargetObservationInput{
			ProfileEvidenceDigest: p.profileDigest,
			NetworkEvidenceDigest: p.networkDigest,
		},
	)
	if err != nil {
		p.t.Fatalf("SealTargetObservation: %v", err)
	}
	return result, nil
}

func (p *reportShapeProfile) Cleanup(
	context.Context,
) (conformance.CleanupEvidence, error) {
	if p.cleanupErr != nil {
		return conformance.CleanupEvidence{}, p.cleanupErr
	}
	result, err := conformance.SealCleanup(
		conformance.CleanupObservation{
			AssertionCount:    2,
			ObservationDigest: reportDigestB,
		},
	)
	if err != nil {
		p.t.Fatalf("SealCleanup: %v", err)
	}
	return result, nil
}

func (*reportShapeProfile) ActualHostTimeout(
	conformance.ActualHostCaseID,
) time.Duration {
	return time.Second
}

func (*reportShapeProfile) SyntheticTimeout(
	conformance.SyntheticCaseID,
) time.Duration {
	return time.Second
}

func (*reportShapeProfile) ActualGitHubTimeout() time.Duration {
	return time.Second
}

func (*reportShapeProfile) CleanupTimeout() time.Duration {
	return time.Second
}
