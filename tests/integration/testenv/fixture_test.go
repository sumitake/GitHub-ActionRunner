package testenv

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type fakeFixtureRootAuthority struct {
	trace *[]string
	err   error
}

func (a *fakeFixtureRootAuthority) Acquire(
	_ context.Context,
	_ FixtureBinding,
) (cleanupHandle, error) {
	*a.trace = append(*a.trace, "root-acquire")
	if a.err != nil {
		return cleanupHandle{}, a.err
	}
	return cleanupHandle{
		kind: CleanupFixtureRoot,
		id:   inputDigestA,
	}, nil
}

type fakeFixtureEffects struct {
	trace *[]string
	err   error
}

type fakeFixtureAuthorization struct {
	trace      *[]string
	consumeErr error
	consumes   int
	closes     int
}

func (a *fakeFixtureAuthorization) Consume() error {
	if a.trace != nil {
		*a.trace = append(*a.trace, "authorization-consume")
	}
	a.consumes++
	return a.consumeErr
}

func (a *fakeFixtureAuthorization) Close() error {
	a.closes++
	return nil
}

type fakeFixtureCases struct{}

func (fakeFixtureCases) RunActualHost(
	_ context.Context,
	id conformance.ActualHostCaseID,
) (conformance.ActualHostResult, error) {
	input := conformance.ObservationInput{
		AssertionCount:    1,
		ObservationDigest: inputDigestA,
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

func (fakeFixtureCases) RunSynthetic(
	_ context.Context,
	id conformance.SyntheticCaseID,
) (conformance.SyntheticResult, error) {
	input := conformance.ObservationInput{
		AssertionCount:    1,
		ObservationDigest: inputDigestA,
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
				AssertionCount:    1,
				ObservationDigest: inputDigestA,
				Measurements: []conformance.MeasurementInput{{
					Name: "sample_count", Value: 3, Unit: "count",
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

type fakeFixtureFinalizer struct {
	calls     int
	completed []conformance.CaseID
	result    conformance.TargetObservationInput
	err       error
}

func (f *fakeFixtureFinalizer) Finalize(
	_ context.Context,
	completed []conformance.CaseID,
) (conformance.TargetObservationInput, error) {
	f.calls++
	f.completed = append([]conformance.CaseID(nil), completed...)
	return f.result, f.err
}

func (e *fakeFixtureEffects) Start(
	_ context.Context,
	record func(cleanupHandle) error,
) error {
	*e.trace = append(*e.trace, "effects-start")
	for _, handle := range []cleanupHandle{
		{kind: CleanupAdapter, id: inputDigestB},
		{kind: CleanupBroker, id: inputDigestC},
		{kind: CleanupRunner, id: inputDigestD},
	} {
		if err := record(handle); err != nil {
			return err
		}
	}
	return e.err
}

type fakeFixtureCleanup struct {
	mu           sync.Mutex
	trace        []CleanupKind
	removeCalls  int
	proveCalls   int
	failKind     CleanupKind
	unexpected   bool
	deadlineSeen bool
}

func (c *fakeFixtureCleanup) Remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, c.deadlineSeen = ctx.Deadline()
	c.removeCalls++
	c.trace = append(c.trace, handle.kind)
	if handle.kind == c.failKind {
		return errors.New("raw remove failure")
	}
	return nil
}

func (c *fakeFixtureCleanup) Prove(
	ctx context.Context,
	_ []cleanupHandle,
	_ FixtureBinding,
) (conformance.CleanupObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, deadline := ctx.Deadline()
	c.deadlineSeen = c.deadlineSeen && deadline
	c.proveCalls++
	if c.unexpected {
		return conformance.CleanupObservation{}, ErrFixtureUnexpectedObject
	}
	return conformance.CleanupObservation{
		AssertionCount:    4,
		ObservationDigest: inputDigestA,
	}, nil
}

func TestFixtureStartupDecisionIsExplicitAndFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		goos    string
		values  map[string]string
		skip    bool
		wantErr bool
	}{
		{name: "darwin", goos: "darwin", skip: true},
		{name: "linux absent", goos: "linux", skip: true},
		{
			name: "linux enabled",
			goos: "linux",
			values: map[string]string{
				"PGHAR_INTEGRATION_DOCKER": "1",
				"PGHAR_CONFORMANCE_INPUT":  "/private/input.json",
			},
		},
		{
			name: "malformed opt in",
			goos: "linux",
			values: map[string]string{
				"PGHAR_INTEGRATION_DOCKER": "true",
				"PGHAR_CONFORMANCE_INPUT":  "/private/input.json",
			},
			wantErr: true,
		},
		{
			name: "input without opt in",
			goos: "linux",
			values: map[string]string{
				"PGHAR_CONFORMANCE_INPUT": "/private/input.json",
			},
			wantErr: true,
		},
		{
			name: "opt in without input",
			goos: "linux",
			values: map[string]string{
				"PGHAR_INTEGRATION_DOCKER": "1",
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := decideFixtureStartup(
				test.goos,
				func(key string) (string, bool) {
					value, ok := test.values[key]
					return value, ok
				},
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, test.wantErr)
			}
			if decision.Skip != test.skip {
				t.Fatalf("decision = %+v, want skip %t", decision, test.skip)
			}
			if test.skip && decision.Reason != unsupportedHostSkip {
				t.Fatalf("skip reason = %q", decision.Reason)
			}
		})
	}
}

func TestFixtureValidatesBeforeEffectsAndRegistersCleanupFirst(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	parsed := readValidParsedInput(t, now)
	trace := []string{}
	registered := func(cleanup func()) {
		trace = append(trace, "cleanup-register")
		if cleanup == nil {
			t.Fatal("registered nil cleanup")
		}
	}
	cleanup := &fakeFixtureCleanup{}
	fixture, err := startFixtureCore(
		context.Background(),
		parsed,
		FixtureHostFacts{
			OperatingSystem:           "linux",
			Architecture:              "amd64",
			EUID:                      uint32(os.Geteuid()),
			HostIdentityDigest:        inputDigestA,
			ControlHostIdentityDigest: inputDigestB,
		},
		fixtureStartDependencies{
			RegisterCleanup: registered,
			Authorization:   &fakeFixtureAuthorization{trace: &trace},
			Root:            &fakeFixtureRootAuthority{trace: &trace},
			Effects:         &fakeFixtureEffects{trace: &trace},
			Cleanup:         cleanup,
			Cases:           fakeFixtureCases{},
			Finalizer: &fakeFixtureFinalizer{result: conformance.TargetObservationInput{
				ProfileEvidenceDigest: inputDigestD,
				NetworkEvidenceDigest: inputDigestC,
			}},
		},
	)
	if err != nil {
		t.Fatalf("startFixtureCore: %v", err)
	}
	if fixture == nil || !reflect.DeepEqual(trace, []string{
		"cleanup-register",
		"authorization-consume",
		"root-acquire",
		"effects-start",
	}) {
		t.Fatalf("startup trace = %v", trace)
	}

	badTrace := []string{}
	_, err = startFixtureCore(
		context.Background(),
		parsed,
		FixtureHostFacts{
			OperatingSystem:           "linux",
			Architecture:              "amd64",
			EUID:                      uint32(os.Geteuid()),
			HostIdentityDigest:        inputDigestA,
			ControlHostIdentityDigest: inputDigestA,
		},
		fixtureStartDependencies{
			RegisterCleanup: func(func()) {
				badTrace = append(badTrace, "cleanup-register")
			},
			Authorization: &fakeFixtureAuthorization{trace: &badTrace},
			Root:          &fakeFixtureRootAuthority{trace: &badTrace},
			Effects:       &fakeFixtureEffects{trace: &badTrace},
			Cleanup:       &fakeFixtureCleanup{},
			Cases:         fakeFixtureCases{},
			Finalizer: &fakeFixtureFinalizer{result: conformance.TargetObservationInput{
				ProfileEvidenceDigest: inputDigestD,
				NetworkEvidenceDigest: inputDigestC,
			}},
		},
	)
	if err == nil {
		t.Fatal("accepted same host/control identity")
	}
	if len(badTrace) != 0 {
		t.Fatalf("invalid binding reached registration/effect: %v", badTrace)
	}
}

func TestFixtureConsumeFailureStartsNoRootOrEffectAndClosesLease(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	parsed := readValidParsedInput(t, now)
	trace := []string{}
	authorization := &fakeFixtureAuthorization{
		trace:      &trace,
		consumeErr: ErrAuthorizationConsumedRunAborted,
	}
	var safety func()
	_, err := startFixtureCore(
		context.Background(),
		parsed,
		FixtureHostFacts{
			OperatingSystem:           "linux",
			Architecture:              "amd64",
			EUID:                      uint32(os.Geteuid()),
			HostIdentityDigest:        inputDigestA,
			ControlHostIdentityDigest: inputDigestB,
		},
		fixtureStartDependencies{
			RegisterCleanup: func(cleanup func()) {
				trace = append(trace, "cleanup-register")
				safety = cleanup
			},
			Authorization: authorization,
			Root:          &fakeFixtureRootAuthority{trace: &trace},
			Effects:       &fakeFixtureEffects{trace: &trace},
			Cleanup:       &fakeFixtureCleanup{},
			Cases:         fakeFixtureCases{},
			Finalizer: &fakeFixtureFinalizer{result: conformance.TargetObservationInput{
				ProfileEvidenceDigest: inputDigestD,
				NetworkEvidenceDigest: inputDigestC,
			}},
		},
	)
	if !errors.Is(err, ErrAuthorizationConsumedRunAborted) {
		t.Fatalf("startFixtureCore = %v", err)
	}
	if !reflect.DeepEqual(trace, []string{
		"cleanup-register",
		"authorization-consume",
	}) {
		t.Fatalf("consume failure trace = %v", trace)
	}
	if authorization.consumes != 1 || authorization.closes != 1 {
		t.Fatalf(
			"authorization consumes/closes = %d/%d",
			authorization.consumes,
			authorization.closes,
		)
	}
	if safety == nil {
		t.Fatal("cleanup was not registered before consume")
	}
	safety()
	if authorization.closes != 1 {
		t.Fatalf(
			"safety cleanup closed authorization again: %d",
			authorization.closes,
		)
	}
}

func TestFixtureCleanupIsSingleCachedReverseOrderAuthority(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	parsed := readValidParsedInput(t, now)
	trace := []string{}
	backend := &fakeFixtureCleanup{}
	var safety func()
	fixture, err := startFixtureCore(
		context.Background(),
		parsed,
		FixtureHostFacts{
			OperatingSystem:           "linux",
			Architecture:              "amd64",
			EUID:                      uint32(os.Geteuid()),
			HostIdentityDigest:        inputDigestA,
			ControlHostIdentityDigest: inputDigestB,
		},
		fixtureStartDependencies{
			RegisterCleanup: func(cleanup func()) { safety = cleanup },
			Authorization:   &fakeFixtureAuthorization{},
			Root:            &fakeFixtureRootAuthority{trace: &trace},
			Effects:         &fakeFixtureEffects{trace: &trace},
			Cleanup:         backend,
			Cases:           fakeFixtureCases{},
			Finalizer: &fakeFixtureFinalizer{result: conformance.TargetObservationInput{
				ProfileEvidenceDigest: inputDigestD,
				NetworkEvidenceDigest: inputDigestC,
			}},
		},
	)
	if err != nil {
		t.Fatalf("startFixtureCore: %v", err)
	}
	first, err := fixture.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if first.Status() != conformance.StatusPassed ||
		first.Failure() != conformance.FailureNone {
		t.Fatalf("cleanup evidence = %+v", first)
	}
	if safety == nil {
		t.Fatal("safety cleanup not registered")
	}
	safety()
	second, err := fixture.Cleanup(context.Background())
	if err != nil ||
		second.EvidenceDigest() != first.EvidenceDigest() {
		t.Fatalf("cached Cleanup = %+v/%v", second, err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if !reflect.DeepEqual(backend.trace, []CleanupKind{
		CleanupRunner,
		CleanupBroker,
		CleanupAdapter,
		CleanupFixtureRoot,
	}) {
		t.Fatalf("cleanup order = %v", backend.trace)
	}
	if backend.removeCalls != 4 || backend.proveCalls != 1 ||
		!backend.deadlineSeen {
		t.Fatalf(
			"cleanup calls/proof/deadline = %d/%d/%t",
			backend.removeCalls,
			backend.proveCalls,
			backend.deadlineSeen,
		)
	}
}

func TestFixtureCleanupContinuesAfterFailureAndPreservesUnexpectedObject(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	for name, backend := range map[string]*fakeFixtureCleanup{
		"remove failure": {failKind: CleanupBroker},
		"unexpected":     {unexpected: true},
	} {
		t.Run(name, func(t *testing.T) {
			parsed := readValidParsedInput(t, now)
			trace := []string{}
			fixture, err := startFixtureCore(
				context.Background(),
				parsed,
				FixtureHostFacts{
					OperatingSystem:           "linux",
					Architecture:              "amd64",
					EUID:                      uint32(os.Geteuid()),
					HostIdentityDigest:        inputDigestA,
					ControlHostIdentityDigest: inputDigestB,
				},
				fixtureStartDependencies{
					RegisterCleanup: func(func()) {},
					Authorization:   &fakeFixtureAuthorization{},
					Root: &fakeFixtureRootAuthority{
						trace: &trace,
					},
					Effects: &fakeFixtureEffects{trace: &trace},
					Cleanup: backend,
					Cases:   fakeFixtureCases{},
					Finalizer: &fakeFixtureFinalizer{result: conformance.TargetObservationInput{
						ProfileEvidenceDigest: inputDigestD,
						NetworkEvidenceDigest: inputDigestC,
					}},
				},
			)
			if err != nil {
				t.Fatalf("startFixtureCore: %v", err)
			}
			if _, err := fixture.Cleanup(context.Background()); err == nil {
				t.Fatal("cleanup reported false success")
			}
			backend.mu.Lock()
			removeCalls, proveCalls := backend.removeCalls, backend.proveCalls
			backend.mu.Unlock()
			if removeCalls != 4 || proveCalls != 1 {
				t.Fatalf(
					"cleanup stopped early: remove=%d prove=%d",
					removeCalls,
					proveCalls,
				)
			}
		})
	}
}

func TestFixtureFinalizesOnlyAfterExactCurrentRunCaseSet(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	parsed := readValidParsedInput(t, now)
	trace := []string{}
	finalizer := &fakeFixtureFinalizer{
		result: conformance.TargetObservationInput{
			ProfileEvidenceDigest: inputDigestD,
			NetworkEvidenceDigest: inputDigestC,
		},
	}
	fixture, err := startFixtureCore(
		context.Background(),
		parsed,
		FixtureHostFacts{
			OperatingSystem:           "linux",
			Architecture:              "amd64",
			EUID:                      uint32(os.Geteuid()),
			HostIdentityDigest:        inputDigestA,
			ControlHostIdentityDigest: inputDigestB,
		},
		fixtureStartDependencies{
			RegisterCleanup: func(func()) {},
			Authorization:   &fakeFixtureAuthorization{},
			Root:            &fakeFixtureRootAuthority{trace: &trace},
			Effects:         &fakeFixtureEffects{trace: &trace},
			Cleanup:         &fakeFixtureCleanup{},
			Cases:           fakeFixtureCases{},
			Finalizer:       finalizer,
		},
	)
	if err != nil {
		t.Fatalf("startFixtureCore: %v", err)
	}
	if _, err := fixture.FinalizeTarget(context.Background()); err == nil {
		t.Fatal("finalized before any current-run cases completed")
	}
	if finalizer.calls != 0 {
		t.Fatal("incomplete case set reached target finalizer")
	}

	for _, actual := range []conformance.ActualHostCaseID{
		conformance.ActualHostProfile,
		conformance.ActualNamespaceBaseline,
		conformance.ActualBrokerEgress,
		conformance.ActualMountAndSecretIsolation,
		conformance.ActualRunnerSandbox,
		conformance.ActualRunnerPayload,
	} {
		if _, err := fixture.RunActualHost(context.Background(), actual); err != nil {
			t.Fatalf("RunActualHost(%d): %v", actual, err)
		}
	}
	for _, synthetic := range []conformance.SyntheticCaseID{
		conformance.SyntheticOneJob,
		conformance.SyntheticCleanupMatrix,
		conformance.SyntheticReclamationSeries,
	} {
		if _, err := fixture.RunSynthetic(context.Background(), synthetic); err != nil {
			t.Fatalf("RunSynthetic(%d): %v", synthetic, err)
		}
	}
	if _, err := fixture.RunActualHost(
		context.Background(),
		conformance.ActualProxyToolCompatibility,
	); err != nil {
		t.Fatalf("RunActualHost(proxy tools): %v", err)
	}
	for _, synthetic := range []conformance.SyntheticCaseID{
		conformance.SyntheticSeedIsolation,
		conformance.SyntheticWatchdogRecovery,
		conformance.SyntheticLegacyFenceRecovery,
		conformance.SyntheticNoncancellableShutdown,
	} {
		if _, err := fixture.RunSynthetic(context.Background(), synthetic); err != nil {
			t.Fatalf("RunSynthetic(%d): %v", synthetic, err)
		}
	}
	observation, err := fixture.FinalizeTarget(context.Background())
	if err != nil {
		t.Fatalf("FinalizeTarget: %v", err)
	}
	if finalizer.calls != 1 {
		t.Fatalf("finalizer calls = %d, want 1", finalizer.calls)
	}
	required := conformance.RequiredCases()
	if !reflect.DeepEqual(finalizer.completed, required[:len(required)-1]) {
		t.Fatalf("completed cases = %v", finalizer.completed)
	}
	if observation == (conformance.TargetObservation{}) {
		t.Fatal("finalizer returned zero target observation")
	}
}

func TestRawObservationClearsBytesAfterDigest(t *testing.T) {
	t.Parallel()

	bytes := []byte("bounded nonsecret observation")
	raw, err := newRawObservation(bytes, len(bytes))
	if err != nil {
		t.Fatalf("newRawObservation: %v", err)
	}
	digest, err := raw.Digest("fixture-observation-v1")
	if err != nil || digest == "" {
		t.Fatalf("Digest = %q/%v", digest, err)
	}
	for index, value := range bytes {
		if value != 0 {
			t.Fatalf("raw observation byte %d not cleared", index)
		}
	}
	if _, err := raw.Digest("fixture-observation-v1"); err == nil {
		t.Fatal("raw observation reused after destruction")
	}
}

func readValidParsedInput(
	t *testing.T,
	now time.Time,
) ParsedConformanceInput {
	t.Helper()
	input := validConformanceInput(t, t.TempDir(), now)
	path, document := writeConformanceInput(t, input)
	parsed, err := ReadConformanceInput(
		path,
		validReadOptions(now, len(document)),
	)
	if err != nil {
		t.Fatalf("ReadConformanceInput: %v", err)
	}
	return parsed
}
