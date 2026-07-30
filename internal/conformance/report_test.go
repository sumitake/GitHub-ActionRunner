package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDigestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testDigestD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testCommit  = "1111111111111111111111111111111111111111"
)

type profileStub struct {
	binding           Binding
	bindingErr        error
	actual            map[ActualHostCaseID]ActualHostResult
	actualErr         map[ActualHostCaseID]error
	synthetic         map[SyntheticCaseID]SyntheticResult
	syntheticErr      map[SyntheticCaseID]error
	github            ActualGitHubResult
	githubErr         error
	target            TargetObservation
	targetErr         error
	finalizeCalls     int
	finalizeContextOK bool
	cleanup           CleanupEvidence
	cleanupErr        error
	cleanupCalls      int
	cleanupContextOK  bool
	called            []CaseID
}

func (p *profileStub) Binding() (Binding, error) {
	return p.binding, p.bindingErr
}

func (p *profileStub) RunActualHost(
	_ context.Context,
	id ActualHostCaseID,
) (ActualHostResult, error) {
	definition, ok := lookupActualCase(id)
	if ok {
		p.called = append(p.called, definition.id)
	}
	return p.actual[id], p.actualErr[id]
}

func (p *profileStub) RunSynthetic(
	_ context.Context,
	id SyntheticCaseID,
) (SyntheticResult, error) {
	definition, ok := lookupSyntheticCase(id)
	if ok {
		p.called = append(p.called, definition.id)
	}
	return p.synthetic[id], p.syntheticErr[id]
}

func (p *profileStub) RunActualGitHub(
	_ context.Context,
) (ActualGitHubResult, error) {
	p.called = append(p.called, CaseActualGitHubTransport)
	return p.github, p.githubErr
}

func (p *profileStub) FinalizeTarget(
	ctx context.Context,
) (TargetObservation, error) {
	p.finalizeCalls++
	_, deadlineOK := ctx.Deadline()
	p.finalizeContextOK = ctx.Err() == nil && deadlineOK
	return p.target, p.targetErr
}

func (p *profileStub) Cleanup(ctx context.Context) (CleanupEvidence, error) {
	p.cleanupCalls++
	_, deadlineOK := ctx.Deadline()
	p.cleanupContextOK = ctx.Err() == nil && deadlineOK
	return p.cleanup, p.cleanupErr
}

func (*profileStub) ActualHostTimeout(ActualHostCaseID) time.Duration {
	return time.Second
}

func (*profileStub) SyntheticTimeout(SyntheticCaseID) time.Duration {
	return time.Second
}

func (*profileStub) ActualGitHubTimeout() time.Duration {
	return time.Second
}

func (*profileStub) CleanupTimeout() time.Duration {
	return time.Second
}

func TestRunAllPassedProducesCanonicalReport(t *testing.T) {
	t.Parallel()

	profile := validProfile(t, true)
	report := Run(context.Background(), profile)
	if report.Status() != StatusPassed || report.Failure() != FailureNone {
		t.Fatalf("report status = %q/%q", report.Status(), report.Failure())
	}
	if profile.cleanupCalls != 1 || !profile.cleanupContextOK {
		t.Fatalf(
			"cleanup calls/context = %d/%t, want 1/true",
			profile.cleanupCalls,
			profile.cleanupContextOK,
		)
	}
	if profile.finalizeCalls != 1 || !profile.finalizeContextOK {
		t.Fatalf(
			"finalize calls/context = %d/%t, want 1/true",
			profile.finalizeCalls,
			profile.finalizeContextOK,
		)
	}
	if report.ObservedProfileEvidenceDigest() != testDigestC ||
		report.ObservedNetworkEvidenceDigest() != testDigestD {
		t.Fatal("report omitted the independently finalized target observation")
	}
	cases := report.Cases()
	if len(cases) != len(requiredCaseRegistry) {
		t.Fatalf("case count = %d, want %d", len(cases), len(requiredCaseRegistry))
	}
	for index, evidence := range cases {
		if evidence.ID() != requiredCaseRegistry[index].id ||
			evidence.Layer() != requiredCaseRegistry[index].layer ||
			evidence.Status() != StatusPassed ||
			evidence.Failure() != FailureNone ||
			evidence.AssertionCount() == 0 ||
			evidence.ObservationDigest() == "" ||
			evidence.EvidenceDigest() == "" {
			t.Fatalf("case[%d] = %+v", index, evidence)
		}
	}
	if report.Digest() == "" || report.BuildSeal() == "" {
		t.Fatal("report omitted digest or build seal")
	}

	document, err := MarshalReport(report)
	if err != nil {
		t.Fatalf("MarshalReport: %v", err)
	}
	parsed, err := ParseReport(document, len(document))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	roundTrip, err := MarshalReport(parsed)
	if err != nil {
		t.Fatalf("MarshalReport(parsed): %v", err)
	}
	if string(roundTrip) != string(document) {
		t.Fatal("canonical report changed on round trip")
	}
}

func TestRunPendingActualGitHubForcesPendingReport(t *testing.T) {
	t.Parallel()

	profile := validProfile(t, false)
	report := Run(context.Background(), profile)
	if report.Status() != StatusPending ||
		report.Failure() != FailureActualProofPending {
		t.Fatalf("report status = %q/%q", report.Status(), report.Failure())
	}
	last := report.Cases()[len(report.Cases())-1]
	if last.ID() != CaseActualGitHubTransport ||
		last.Layer() != LayerActualGitHubTransport ||
		last.Status() != StatusPending ||
		last.Failure() != FailureActualProofPending {
		t.Fatalf("actual GitHub evidence = %+v", last)
	}
}

func TestRunStopsAfterFailureAndRecordsNotRunSuffix(t *testing.T) {
	t.Parallel()

	profile := validProfile(t, true)
	profile.actualErr[ActualBrokerEgress] = ErrPolicy
	report := Run(context.Background(), profile)
	if report.Status() != StatusFailed || report.Failure() != FailurePolicy {
		t.Fatalf("report status = %q/%q", report.Status(), report.Failure())
	}
	cases := report.Cases()
	if cases[2].Status() != StatusFailed ||
		cases[2].Failure() != FailurePolicy {
		t.Fatalf("failed case = %+v", cases[2])
	}
	for index := 3; index < len(cases); index++ {
		if cases[index].Status() != StatusNotRun ||
			cases[index].Failure() != FailurePrerequisite ||
			cases[index].AssertionCount() != 0 {
			t.Fatalf("case[%d] not-run evidence = %+v", index, cases[index])
		}
	}
	if len(profile.called) != 3 {
		t.Fatalf("executed cases = %d, want 3", len(profile.called))
	}
	if profile.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", profile.cleanupCalls)
	}
	if profile.finalizeCalls != 0 {
		t.Fatalf("finalize calls = %d, want 0", profile.finalizeCalls)
	}
}

func TestRunFailsClosedWhenFinalTargetObservationIsMissingOrMismatched(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(*profileStub){
		"missing": func(profile *profileStub) {
			profile.target = TargetObservation{}
		},
		"mismatched profile": func(profile *profileStub) {
			profile.target = mustTargetObservation(t, testDigestA, testDigestD)
		},
		"mismatched network": func(profile *profileStub) {
			profile.target = mustTargetObservation(t, testDigestC, testDigestA)
		},
		"finalizer error": func(profile *profileStub) {
			profile.targetErr = ErrObservation
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			profile := validProfile(t, false)
			mutate(profile)
			report := Run(context.Background(), profile)
			if report.Status() != StatusFailed ||
				report.Failure() != FailureInvariant {
				t.Fatalf(
					"status = %q/%q, want failed/invariant",
					report.Status(),
					report.Failure(),
				)
			}
			if profile.finalizeCalls != 1 || profile.cleanupCalls != 1 {
				t.Fatalf(
					"finalize/cleanup = %d/%d, want 1/1",
					profile.finalizeCalls,
					profile.cleanupCalls,
				)
			}
			if _, err := NewAcquisitionGate(report); err == nil {
				t.Fatal("mismatched target observation created acquisition gate")
			}
		})
	}
}

func TestRunCleanupFailureHasPrecedenceAndIgnoresCanceledParent(t *testing.T) {
	t.Parallel()

	profile := validProfile(t, true)
	profile.actualErr[ActualBrokerEgress] = ErrPolicy
	profile.cleanupErr = errors.New("raw cleanup detail")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report := Run(ctx, profile)
	if report.Status() != StatusFailed || report.Failure() != FailureCleanup {
		t.Fatalf("report status = %q/%q", report.Status(), report.Failure())
	}
	if report.Cleanup().Status() != StatusFailed ||
		report.Cleanup().Failure() != FailureCleanup ||
		!profile.cleanupContextOK {
		t.Fatalf(
			"cleanup = %+v contextOK=%t",
			report.Cleanup(),
			profile.cleanupContextOK,
		)
	}
	document, err := MarshalReport(report)
	if err != nil {
		t.Fatalf("MarshalReport: %v", err)
	}
	if strings.Contains(string(document), "raw cleanup detail") {
		t.Fatal("report leaked raw cleanup error")
	}
}

func TestReportParserRejectsWireDriftAndTampering(t *testing.T) {
	t.Parallel()

	document := mustMarshalReport(t, Run(context.Background(), validProfile(t, true)))
	tests := map[string][]byte{
		"trailing newline":   append(append([]byte(nil), document...), '\n'),
		"leading whitespace": append([]byte(" "), document...),
		"unknown field": []byte(
			strings.Replace(
				string(document),
				`"schema_version":1`,
				`"unknown":1,"schema_version":1`,
				1,
			),
		),
		"tampered status": []byte(
			strings.Replace(
				string(document),
				`"status":"passed"`,
				`"status":"pending"`,
				1,
			),
		),
		"tampered observation digest": []byte(
			strings.Replace(
				string(document),
				testDigestB,
				testDigestC,
				1,
			),
		),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReport(candidate, len(candidate)); err == nil {
				t.Fatal("ParseReport accepted invalid document")
			}
		})
	}
	if _, err := ParseReport(document, len(document)-1); err == nil {
		t.Fatal("ParseReport accepted oversize document")
	}
	if _, err := ParseReport([]byte{0xff}, 1); err == nil {
		t.Fatal("ParseReport accepted non-UTF-8 document")
	}
}

func TestSealersRejectCrossCaseAndInvalidObservation(t *testing.T) {
	t.Parallel()

	if _, err := SealHostProfile(HostProfileObservation{}); err == nil {
		t.Fatal("SealHostProfile accepted zero observation")
	}
	if _, err := SealTargetObservation(TargetObservationInput{}); err == nil {
		t.Fatal("SealTargetObservation accepted zero observation")
	}
	if _, err := SealReclamationSeries(ReclamationObservation{
		AssertionCount:    1,
		ObservationDigest: testDigestB,
		Measurements: []MeasurementInput{
			{Name: "sample_count", Value: 2, Unit: "count"},
		},
	}); err == nil {
		t.Fatal("SealReclamationSeries accepted fewer than three samples")
	}
}

func TestOpaqueTypesHaveNoExportedState(t *testing.T) {
	t.Parallel()

	values := []any{
		Binding{},
		Measurement{},
		CaseEvidence{},
		CleanupEvidence{},
		Report{},
		ActualHostResult{},
		SyntheticResult{},
		ActualGitHubResult{},
		TargetObservation{},
	}
	for _, value := range values {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			if typ.Field(index).IsExported() {
				t.Fatalf("%s field %q is exported", typ, typ.Field(index).Name)
			}
		}
	}
}

func TestMarshalReportUsesNoMapsOrNullableFields(t *testing.T) {
	t.Parallel()

	document := mustMarshalReport(t, Run(context.Background(), validProfile(t, true)))
	var decoded any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if strings.Contains(string(document), "null") {
		t.Fatal("canonical report contains null")
	}
}

func validProfile(t *testing.T, actualGitHub bool) *profileStub {
	t.Helper()
	mustActual := func(
		result ActualHostResult,
		err error,
	) ActualHostResult {
		t.Helper()
		if err != nil {
			t.Fatalf("actual sealer: %v", err)
		}
		return result
	}
	mustSynthetic := func(
		result SyntheticResult,
		err error,
	) SyntheticResult {
		t.Helper()
		if err != nil {
			t.Fatalf("synthetic sealer: %v", err)
		}
		return result
	}

	binding, err := NewBinding(BindingInput{
		SchemaVersion:                 1,
		BuildID:                       testDigestA,
		SourceCommit:                  testCommit,
		RuntimeManifestDigest:         testDigestB,
		PrivateOverlayDigest:          testDigestC,
		ConformanceInputDigest:        testDigestD,
		AuthorizationDigest:           testDigestA,
		RunID:                         testDigestB,
		ProfileID:                     "qts-capless-root",
		FleetGeneration:               7,
		ExpectedProfileEvidenceDigest: testDigestC,
		ExpectedNetworkEvidenceDigest: testDigestD,
		PlanDigest:                    testDigestA,
	})
	if err != nil {
		t.Fatalf("NewBinding: %v", err)
	}

	plain := ObservationInput{
		AssertionCount:    2,
		ObservationDigest: testDigestB,
	}
	actual := make(map[ActualHostCaseID]ActualHostResult)
	actual[ActualHostProfile] = mustActual(SealHostProfile(HostProfileObservation(plain)))
	actual[ActualNamespaceBaseline] = mustActual(
		SealNamespaceBaseline(NamespaceObservation(plain)),
	)
	actual[ActualBrokerEgress] = mustActual(
		SealBrokerEgress(BrokerEgressObservation(plain)),
	)
	actual[ActualMountAndSecretIsolation] = mustActual(
		SealMountAndSecretIsolation(MountSecretObservation(plain)),
	)
	actual[ActualRunnerSandbox] = mustActual(
		SealRunnerSandbox(RunnerSandboxObservation(plain)),
	)
	actual[ActualRunnerPayload] = mustActual(
		SealRunnerPayload(RunnerPayloadObservation(plain)),
	)
	actual[ActualProxyToolCompatibility] = mustActual(
		SealProxyToolCompatibility(ProxyToolObservation(plain)),
	)

	synthetic := make(map[SyntheticCaseID]SyntheticResult)
	synthetic[SyntheticOneJob] = mustSynthetic(
		SealSyntheticOneJob(SyntheticJobObservation(plain)),
	)
	synthetic[SyntheticCleanupMatrix] = mustSynthetic(
		SealCleanupMatrix(CleanupMatrixObservation(plain)),
	)
	synthetic[SyntheticReclamationSeries] = mustSynthetic(
		SealReclamationSeries(ReclamationObservation{
			AssertionCount:    2,
			ObservationDigest: testDigestB,
			Measurements: []MeasurementInput{
				{Name: "sample_count", Value: 3, Unit: "count"},
			},
		}),
	)
	synthetic[SyntheticSeedIsolation] = mustSynthetic(
		SealSeedIsolation(SeedObservation(plain)),
	)
	synthetic[SyntheticWatchdogRecovery] = mustSynthetic(
		SealWatchdogRecovery(WatchdogObservation(plain)),
	)
	synthetic[SyntheticLegacyFenceRecovery] = mustSynthetic(
		SealLegacyFenceRecovery(LegacyFenceObservation(plain)),
	)
	synthetic[SyntheticNoncancellableShutdown] = mustSynthetic(
		SealNoncancellableShutdown(ShutdownObservation(plain)),
	)
	cleanup, err := SealCleanup(CleanupObservation(plain))
	if err != nil {
		t.Fatalf("SealCleanup: %v", err)
	}
	github := PendingActualGitHubTransport()
	if actualGitHub {
		github, err = SealActualGitHubTransport(ActualGitHubObservation(plain))
		if err != nil {
			t.Fatalf("SealActualGitHubTransport: %v", err)
		}
	}
	target := mustTargetObservation(t, testDigestC, testDigestD)
	return &profileStub{
		binding:      binding,
		actual:       actual,
		actualErr:    make(map[ActualHostCaseID]error),
		synthetic:    synthetic,
		syntheticErr: make(map[SyntheticCaseID]error),
		github:       github,
		target:       target,
		cleanup:      cleanup,
	}
}

func mustTargetObservation(
	t *testing.T,
	profileDigest string,
	networkDigest string,
) TargetObservation {
	t.Helper()
	observation, err := SealTargetObservation(TargetObservationInput{
		ProfileEvidenceDigest: profileDigest,
		NetworkEvidenceDigest: networkDigest,
	})
	if err != nil {
		t.Fatalf("SealTargetObservation: %v", err)
	}
	return observation
}

func mustMarshalReport(t *testing.T, report Report) []byte {
	t.Helper()
	document, err := MarshalReport(report)
	if err != nil {
		t.Fatalf("MarshalReport: %v", err)
	}
	return document
}
