package conformance_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

const (
	publicDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	publicDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	publicDigestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	publicDigestD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	publicCommit  = "1111111111111111111111111111111111111111"
)

func TestPublicEvidenceTypesExposeNoCompositeAuthority(t *testing.T) {
	t.Parallel()

	values := []any{
		conformance.Binding{},
		conformance.Measurement{},
		conformance.CaseEvidence{},
		conformance.CleanupEvidence{},
		conformance.Report{},
		conformance.ActualHostResult{},
		conformance.SyntheticResult{},
		conformance.ActualGitHubResult{},
		conformance.TargetObservation{},
	}
	for _, value := range values {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			if typ.Field(index).IsExported() {
				t.Fatalf("%s exposes exported field %q", typ, typ.Field(index).Name)
			}
		}
	}
}

func TestZeroOpaqueValuesAreNotValidEvidence(t *testing.T) {
	t.Parallel()

	if _, err := conformance.MarshalReport(conformance.Report{}); err == nil {
		t.Fatal("zero Report marshaled as valid evidence")
	}
	if (conformance.Report{}).Status() == conformance.StatusPassed {
		t.Fatal("zero Report is passing")
	}
}

func TestFullReportKeepsActualGitHubPendingAgainstAllSourceEvidence(
	t *testing.T,
) {
	t.Parallel()

	profile := newPublicProfile(t, false)
	report := conformance.Run(context.Background(), profile)
	if report.Status() != conformance.StatusPending ||
		report.Failure() != conformance.FailureActualProofPending {
		t.Fatalf(
			"status = %q/%q, want pending/actual proof pending",
			report.Status(),
			report.Failure(),
		)
	}
	if report.ObservedProfileEvidenceDigest() != publicDigestC ||
		report.ObservedNetworkEvidenceDigest() != publicDigestD {
		t.Fatal("pending report omitted independently observed target evidence")
	}
	cases := report.Cases()
	if len(cases) != len(conformance.RequiredCases()) {
		t.Fatalf("case count = %d", len(cases))
	}
	for index := 0; index < len(cases)-1; index++ {
		if cases[index].Status() != conformance.StatusPassed {
			t.Fatalf("source case %d = %q", index, cases[index].Status())
		}
	}
	actual := cases[len(cases)-1]
	if actual.ID() != conformance.CaseActualGitHubTransport ||
		actual.Layer() != conformance.LayerActualGitHubTransport ||
		actual.Status() != conformance.StatusPending ||
		actual.Failure() != conformance.FailureActualProofPending {
		t.Fatalf("actual GitHub case = %+v", actual)
	}
	if _, err := conformance.NewAcquisitionGate(report); !errors.Is(
		err,
		conformance.ErrAcquisitionConformanceUnavailable,
	) {
		t.Fatalf("pending report acquisition gate error = %v", err)
	}
}

func TestFullReportPassRequiresInjectedActualTransportAndCleanup(
	t *testing.T,
) {
	t.Parallel()

	profile := newPublicProfile(t, true)
	report := conformance.Run(context.Background(), profile)
	if report.Status() != conformance.StatusPassed ||
		report.Failure() != conformance.FailureNone {
		t.Fatalf("status = %q/%q", report.Status(), report.Failure())
	}
	gate, err := conformance.NewAcquisitionGate(report)
	if err != nil {
		t.Fatalf("NewAcquisitionGate: %v", err)
	}
	binding := report.Binding()
	if err := gate.Verify(
		context.Background(),
		conformance.AcquisitionConformanceRequest{
			BuildID:         binding.BuildID(),
			HostProfileID:   binding.ProfileID(),
			FleetGeneration: binding.FleetGeneration(),
			Mode:            conformance.AcquisitionCanaryOnly,
		},
	); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if profile.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", profile.cleanupCalls)
	}
}

func TestFullReportFailsClosedBeforeReleaseAndCleanupTakesPrecedence(
	t *testing.T,
) {
	t.Parallel()

	componentLoss := newPublicProfile(t, true)
	componentLoss.actualErr[conformance.ActualBrokerEgress] =
		conformance.ErrInvariant
	report := conformance.Run(context.Background(), componentLoss)
	if report.Status() != conformance.StatusFailed ||
		report.Failure() != conformance.FailureInvariant {
		t.Fatalf("component-loss status = %q/%q", report.Status(), report.Failure())
	}
	if _, err := conformance.NewAcquisitionGate(report); err == nil {
		t.Fatal("component-loss report created acquisition authority")
	}

	cleanupLoss := newPublicProfile(t, true)
	cleanupLoss.actualErr[conformance.ActualBrokerEgress] =
		conformance.ErrPolicy
	cleanupLoss.cleanupErr = errors.New(
		"raw cleanup detail with secret-token-value",
	)
	report = conformance.Run(context.Background(), cleanupLoss)
	if report.Status() != conformance.StatusFailed ||
		report.Failure() != conformance.FailureCleanup ||
		report.Cleanup().Failure() != conformance.FailureCleanup {
		t.Fatalf("cleanup-loss report = %q/%q", report.Status(), report.Failure())
	}
	document, err := conformance.MarshalReport(report)
	if err != nil {
		t.Fatalf("MarshalReport: %v", err)
	}
	for _, forbidden := range []string{
		"secret-token-value",
		"/Users/",
		"/share/",
		"github_pat",
		"authorization:",
	} {
		if strings.Contains(string(document), forbidden) {
			t.Fatalf("report leaked forbidden marker %q", forbidden)
		}
	}
}

type publicProfile struct {
	binding       conformance.Binding
	actual        map[conformance.ActualHostCaseID]conformance.ActualHostResult
	actualErr     map[conformance.ActualHostCaseID]error
	synthetic     map[conformance.SyntheticCaseID]conformance.SyntheticResult
	syntheticErr  map[conformance.SyntheticCaseID]error
	github        conformance.ActualGitHubResult
	target        conformance.TargetObservation
	targetErr     error
	finalizeCalls int
	cleanup       conformance.CleanupEvidence
	cleanupErr    error
	cleanupCalls  int
}

func (p *publicProfile) Binding() (conformance.Binding, error) {
	return p.binding, nil
}

func (p *publicProfile) RunActualHost(
	_ context.Context,
	id conformance.ActualHostCaseID,
) (conformance.ActualHostResult, error) {
	return p.actual[id], p.actualErr[id]
}

func (p *publicProfile) RunSynthetic(
	_ context.Context,
	id conformance.SyntheticCaseID,
) (conformance.SyntheticResult, error) {
	return p.synthetic[id], p.syntheticErr[id]
}

func (p *publicProfile) RunActualGitHub(
	context.Context,
) (conformance.ActualGitHubResult, error) {
	return p.github, nil
}

func (p *publicProfile) FinalizeTarget(
	context.Context,
) (conformance.TargetObservation, error) {
	p.finalizeCalls++
	return p.target, p.targetErr
}

func (p *publicProfile) Cleanup(
	context.Context,
) (conformance.CleanupEvidence, error) {
	p.cleanupCalls++
	return p.cleanup, p.cleanupErr
}

func (*publicProfile) ActualHostTimeout(
	conformance.ActualHostCaseID,
) time.Duration {
	return time.Second
}

func (*publicProfile) SyntheticTimeout(
	conformance.SyntheticCaseID,
) time.Duration {
	return time.Second
}

func (*publicProfile) ActualGitHubTimeout() time.Duration {
	return time.Second
}

func (*publicProfile) CleanupTimeout() time.Duration {
	return time.Second
}

func newPublicProfile(t *testing.T, actualGitHub bool) *publicProfile {
	t.Helper()

	binding, err := conformance.NewBinding(conformance.BindingInput{
		SchemaVersion:                 1,
		BuildID:                       publicDigestA,
		SourceCommit:                  publicCommit,
		RuntimeManifestDigest:         publicDigestB,
		PrivateOverlayDigest:          publicDigestC,
		ConformanceInputDigest:        publicDigestD,
		AuthorizationDigest:           publicDigestA,
		RunID:                         publicDigestB,
		ProfileID:                     "qts-capless-root",
		FleetGeneration:               7,
		ExpectedProfileEvidenceDigest: publicDigestC,
		ExpectedNetworkEvidenceDigest: publicDigestD,
		PlanDigest:                    publicDigestA,
	})
	if err != nil {
		t.Fatalf("NewBinding: %v", err)
	}
	plain := conformance.ObservationInput{
		AssertionCount:    2,
		ObservationDigest: publicDigestB,
	}
	mustActual := func(
		result conformance.ActualHostResult,
		err error,
	) conformance.ActualHostResult {
		t.Helper()
		if err != nil {
			t.Fatalf("actual sealer: %v", err)
		}
		return result
	}
	mustSynthetic := func(
		result conformance.SyntheticResult,
		err error,
	) conformance.SyntheticResult {
		t.Helper()
		if err != nil {
			t.Fatalf("synthetic sealer: %v", err)
		}
		return result
	}
	actual := map[conformance.ActualHostCaseID]conformance.ActualHostResult{
		conformance.ActualHostProfile: mustActual(
			conformance.SealHostProfile(
				conformance.HostProfileObservation(plain),
			),
		),
		conformance.ActualNamespaceBaseline: mustActual(
			conformance.SealNamespaceBaseline(
				conformance.NamespaceObservation(plain),
			),
		),
		conformance.ActualBrokerEgress: mustActual(
			conformance.SealBrokerEgress(
				conformance.BrokerEgressObservation(plain),
			),
		),
		conformance.ActualMountAndSecretIsolation: mustActual(
			conformance.SealMountAndSecretIsolation(
				conformance.MountSecretObservation(plain),
			),
		),
		conformance.ActualRunnerSandbox: mustActual(
			conformance.SealRunnerSandbox(
				conformance.RunnerSandboxObservation(plain),
			),
		),
		conformance.ActualRunnerPayload: mustActual(
			conformance.SealRunnerPayload(
				conformance.RunnerPayloadObservation(plain),
			),
		),
		conformance.ActualProxyToolCompatibility: mustActual(
			conformance.SealProxyToolCompatibility(
				conformance.ProxyToolObservation(plain),
			),
		),
	}
	synthetic := map[conformance.SyntheticCaseID]conformance.SyntheticResult{
		conformance.SyntheticOneJob: mustSynthetic(
			conformance.SealSyntheticOneJob(
				conformance.SyntheticJobObservation(plain),
			),
		),
		conformance.SyntheticCleanupMatrix: mustSynthetic(
			conformance.SealCleanupMatrix(
				conformance.CleanupMatrixObservation(plain),
			),
		),
		conformance.SyntheticReclamationSeries: mustSynthetic(
			conformance.SealReclamationSeries(
				conformance.ReclamationObservation{
					AssertionCount:    2,
					ObservationDigest: publicDigestB,
					Measurements: []conformance.MeasurementInput{{
						Name:  "sample_count",
						Value: 3,
						Unit:  "count",
					}},
				},
			),
		),
		conformance.SyntheticSeedIsolation: mustSynthetic(
			conformance.SealSeedIsolation(
				conformance.SeedObservation(plain),
			),
		),
		conformance.SyntheticWatchdogRecovery: mustSynthetic(
			conformance.SealWatchdogRecovery(
				conformance.WatchdogObservation(plain),
			),
		),
		conformance.SyntheticLegacyFenceRecovery: mustSynthetic(
			conformance.SealLegacyFenceRecovery(
				conformance.LegacyFenceObservation(plain),
			),
		),
		conformance.SyntheticNoncancellableShutdown: mustSynthetic(
			conformance.SealNoncancellableShutdown(
				conformance.ShutdownObservation(plain),
			),
		),
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
	target, err := conformance.SealTargetObservation(
		conformance.TargetObservationInput{
			ProfileEvidenceDigest: publicDigestC,
			NetworkEvidenceDigest: publicDigestD,
		},
	)
	if err != nil {
		t.Fatalf("SealTargetObservation: %v", err)
	}
	return &publicProfile{
		binding:      binding,
		actual:       actual,
		actualErr:    make(map[conformance.ActualHostCaseID]error),
		synthetic:    synthetic,
		syntheticErr: make(map[conformance.SyntheticCaseID]error),
		github:       github,
		target:       target,
		cleanup:      cleanup,
	}
}
