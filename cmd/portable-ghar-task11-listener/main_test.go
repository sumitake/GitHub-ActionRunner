package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/sumitake/portable-ghar/internal/runtimeenv"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

const (
	listenerTestDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	listenerTestDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	listenerTestDigestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	listenerTestDigestD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	listenerTestDigestE = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	listenerTestDigestF = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func TestRunAcceptsOnlyVersionOrRun(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args   []string
		status int
		output string
	}{
		"version": {
			args:   []string{"--version"},
			status: 0,
			output: task11synthetic.ProtocolID + "\n",
		},
		"missing": {
			args:   nil,
			status: 2,
		},
		"extra": {
			args:   []string{"run", "extra"},
			status: 2,
		},
		"unknown": {
			args:   []string{"hold"},
			status: 2,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			status := run(test.args, &output, listenerRuntime{})
			if status != test.status || output.String() != test.output {
				t.Fatalf(
					"run(%v) = status %d output %q, want %d %q",
					test.args,
					status,
					output.String(),
					test.status,
					test.output,
				)
			}
		})
	}
}

func TestRunNormalConsumesExactEnvironmentAndEmitsBoundStream(t *testing.T) {
	t.Parallel()

	input, document := listenerInputForTest(t, task11synthetic.ScenarioOneJob)
	environment := newFakeListenerEnvironment(document)
	observer := newFakeListenerObserver()
	marker := &fakeRegistrationMarker{}
	var markerBytes [sha256.Size]byte
	exchangeCalls := 0
	runtime := listenerRuntime{
		environ:   environment.environ,
		lookupEnv: environment.lookup,
		unsetEnv:  environment.unset,
		newObserver: func() (listenerObserver, error) {
			return observer, nil
		},
		createRegistration: func(value [sha256.Size]byte) (registrationMarker, error) {
			markerBytes = value
			return marker, nil
		},
		exchangeHTTPS: func(
			context.Context,
			task11synthetic.Sentinel,
		) (string, error) {
			exchangeCalls++
			return input.Sentinel.ResponseBodyDigest, nil
		},
		prepareSeed: func(task11synthetic.Scenario) (seedSession, error) {
			t.Fatal("prepareSeed called for non-seed scenario")
			return nil, errors.New("unreachable")
		},
		createUpgradeStaging: func([sha256.Size]byte) error {
			t.Fatal("createUpgradeStaging called for normal scenario")
			return errors.New("unreachable")
		},
	}
	var output bytes.Buffer
	if status := run([]string{"run"}, &output, runtime); status != 0 {
		t.Fatalf("run status = %d, output = %q", status, output.Bytes())
	}
	if environment.hasJIT() ||
		!runtimeenv.MatchesImage(environment.environ()) {
		t.Fatalf("JIT environment survived: %v", environment.environ())
	}
	if exchangeCalls != 1 || marker.removeCalls != 1 {
		t.Fatalf(
			"exchange calls=%d marker removes=%d",
			exchangeCalls,
			marker.removeCalls,
		)
	}
	wantMarker, err := task11synthetic.DeriveJobMarkerDigest(
		input.CycleRunDigest,
		input.Nonce,
	)
	if err != nil {
		t.Fatalf("DeriveJobMarkerDigest: %v", err)
	}
	wantMarkerBytes, _ := hex.DecodeString(wantMarker)
	if !bytes.Equal(markerBytes[:], wantMarkerBytes) {
		t.Fatalf("registration marker = %x, want %x", markerBytes, wantMarkerBytes)
	}
	stream, err := task11synthetic.ParseStream(
		output.Bytes(),
		task11synthetic.StreamBinding{
			Scenario:        input.Scenario,
			CycleRunDigest:  input.CycleRunDigest,
			JobMarkerDigest: wantMarker,
			CgroupVersion:   task11synthetic.CgroupV2,
		},
	)
	if err != nil || stream.Terminal == nil {
		t.Fatalf("ParseStream() = %+v, %v; output=%q", stream, err, output.Bytes())
	}
	wantProxy, err := task11synthetic.DeriveProxyRequestDigest(
		input.CycleRunDigest,
		input.Nonce,
		input.Sentinel.PolicyEntryDigest,
		input.Sentinel.PolicyEvidenceDigest,
		input.Sentinel.ResponseBodyDigest,
	)
	if err != nil {
		t.Fatalf("DeriveProxyRequestDigest: %v", err)
	}
	wantResponse, err := task11synthetic.DeriveResponseBodyProofDigest(
		input.CycleRunDigest,
		input.Nonce,
		input.Sentinel.ResponseBodyDigest,
		input.Sentinel.ResponseBodyDigest,
	)
	if err != nil {
		t.Fatalf("DeriveResponseBodyProofDigest: %v", err)
	}
	if stream.Terminal.ProxyRequestDigest != wantProxy ||
		stream.Terminal.ResponseBodyProofDigest != wantResponse ||
		!stream.Terminal.RegistrationRemoved ||
		!slices.Equal(
			stream.Terminal.Resources,
			observer.resources,
		) {
		t.Fatalf("terminal = %+v", *stream.Terminal)
	}
	wantPoints := []listenerObservationPoint{
		observationListenerEntry,
		observationInputValidated,
		observationProxyComplete,
		observationBeforeTerminal,
	}
	if !slices.Equal(observer.points, wantPoints) ||
		observer.highWaterCalls != 1 {
		t.Fatalf(
			"observation points=%v high-water calls=%d",
			observer.points,
			observer.highWaterCalls,
		)
	}
}

func TestRunFaultScenariosEmitOnlyArmedBoundary(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		scenario     task11synthetic.Scenario
		status       int
		wantBoundary task11synthetic.Boundary
		wantUpgrade  bool
		wantPoints   []listenerObservationPoint
	}{
		"listener crash": {
			scenario:     task11synthetic.ScenarioCleanupListenerCrash,
			status:       task11synthetic.ListenerCrashExitStatus,
			wantBoundary: task11synthetic.BoundaryListenerCrashArmed,
			wantPoints: []listenerObservationPoint{
				observationListenerEntry,
				observationInputValidated,
				observationBeforeIntentionalExit,
			},
		},
		"upgrade interruption": {
			scenario:     task11synthetic.ScenarioCleanupUpgradeInterruption,
			status:       task11synthetic.UpgradeInterruptionExitStatus,
			wantBoundary: task11synthetic.BoundaryUpgradeInterruptionArmed,
			wantUpgrade:  true,
			wantPoints: []listenerObservationPoint{
				observationListenerEntry,
				observationInputValidated,
				observationUpgradeStaged,
				observationBeforeIntentionalExit,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			input, document := listenerInputForTest(t, test.scenario)
			environment := newFakeListenerEnvironment(document)
			observer := newFakeListenerObserver()
			marker := &fakeRegistrationMarker{}
			upgradeCalls := 0
			var staged [sha256.Size]byte
			runtime := listenerRuntime{
				environ:   environment.environ,
				lookupEnv: environment.lookup,
				unsetEnv:  environment.unset,
				newObserver: func() (listenerObserver, error) {
					return observer, nil
				},
				createRegistration: func(
					[sha256.Size]byte,
				) (registrationMarker, error) {
					return marker, nil
				},
				exchangeHTTPS: func(
					context.Context,
					task11synthetic.Sentinel,
				) (string, error) {
					t.Fatal("exchangeHTTPS called for fault scenario")
					return "", errors.New("unreachable")
				},
				prepareSeed: func(
					task11synthetic.Scenario,
				) (seedSession, error) {
					t.Fatal("prepareSeed called for fault scenario")
					return nil, errors.New("unreachable")
				},
				createUpgradeStaging: func(
					value [sha256.Size]byte,
				) error {
					upgradeCalls++
					staged = value
					return nil
				},
			}
			var output bytes.Buffer
			status := run([]string{"run"}, &output, runtime)
			if status != test.status {
				t.Fatalf("run status = %d, want %d", status, test.status)
			}
			markerDigest, err := task11synthetic.DeriveJobMarkerDigest(
				input.CycleRunDigest,
				input.Nonce,
			)
			if err != nil {
				t.Fatalf("DeriveJobMarkerDigest: %v", err)
			}
			stream, err := task11synthetic.ParseStream(
				output.Bytes(),
				task11synthetic.StreamBinding{
					Scenario:        test.scenario,
					CycleRunDigest:  input.CycleRunDigest,
					JobMarkerDigest: markerDigest,
					CgroupVersion:   task11synthetic.CgroupV2,
				},
			)
			if err != nil ||
				stream.Terminal != nil ||
				stream.Boundary.Boundary != test.wantBoundary ||
				stream.Boundary.UpgradeInterruptionExercised != test.wantUpgrade {
				t.Fatalf("ParseStream() = %+v, %v", stream, err)
			}
			if marker.removeCalls != 0 ||
				!slices.Equal(observer.points, test.wantPoints) {
				t.Fatalf(
					"marker removes=%d observation points=%v",
					marker.removeCalls,
					observer.points,
				)
			}
			if test.wantUpgrade {
				raw, _ := hex.DecodeString(markerDigest)
				if upgradeCalls != 1 || !bytes.Equal(staged[:], raw) {
					t.Fatalf(
						"upgrade calls=%d staged=%x want=%x",
						upgradeCalls,
						staged,
						raw,
					)
				}
			} else if upgradeCalls != 0 {
				t.Fatalf("unexpected upgrade calls = %d", upgradeCalls)
			}
		})
	}
}

func TestRunSeedScenariosBindPreparationAndTerminalProof(t *testing.T) {
	t.Parallel()

	for _, scenario := range []task11synthetic.Scenario{
		task11synthetic.ScenarioSeedFirst,
		task11synthetic.ScenarioSeedSecond,
	} {
		t.Run(string(scenario), func(t *testing.T) {
			input, document := listenerInputForTest(t, scenario)
			environment := newFakeListenerEnvironment(document)
			observer := newFakeListenerObserver()
			session := &fakeSeedSession{
				proof: validListenerSeedProof(scenario),
			}
			prepared := 0
			runtime := validListenerRuntimeForTest(
				t,
				input,
				environment,
				observer,
			)
			runtime.prepareSeed = func(
				got task11synthetic.Scenario,
			) (seedSession, error) {
				prepared++
				if got != scenario {
					t.Fatalf("prepareSeed scenario = %s, want %s", got, scenario)
				}
				return session, nil
			}
			var output bytes.Buffer
			if status := run([]string{"run"}, &output, runtime); status != 0 {
				t.Fatalf("run status = %d output=%q", status, output.Bytes())
			}
			marker, _ := task11synthetic.DeriveJobMarkerDigest(
				input.CycleRunDigest,
				input.Nonce,
			)
			stream, err := task11synthetic.ParseStream(
				output.Bytes(),
				task11synthetic.StreamBinding{
					Scenario:        scenario,
					CycleRunDigest:  input.CycleRunDigest,
					JobMarkerDigest: marker,
					CgroupVersion:   task11synthetic.CgroupV2,
				},
			)
			if err != nil ||
				stream.Terminal == nil ||
				stream.Terminal.Seed == nil ||
				*stream.Terminal.Seed != session.proof ||
				prepared != 1 ||
				session.finalizeCalls != 1 {
				t.Fatalf(
					"stream=%+v err=%v prepared=%d finalize=%d",
					stream,
					err,
					prepared,
					session.finalizeCalls,
				)
			}
			wantPoints := []listenerObservationPoint{
				observationListenerEntry,
				observationInputValidated,
				observationSeedVerified,
				observationProxyComplete,
				observationSeedFinalized,
				observationBeforeTerminal,
			}
			if !slices.Equal(observer.points, wantPoints) {
				t.Fatalf("observation points = %v, want %v", observer.points, wantPoints)
			}
		})
	}
}

func TestRunFailsClosedWithoutMintingTerminalEvidence(t *testing.T) {
	t.Parallel()

	tests := map[string]func(
		*listenerRuntime,
		*fakeListenerEnvironment,
		*fakeListenerObserver,
		*fakeRegistrationMarker,
	){
		"noncanonical environment": func(
			_ *listenerRuntime,
			environment *fakeListenerEnvironment,
			_ *fakeListenerObserver,
			_ *fakeRegistrationMarker,
		) {
			environment.entries = append(
				environment.entries,
				"HTTP_PROXY=http://"+
					net.JoinHostPort(
						net.IPv4(127, 0, 0, 1).String(),
						"9",
					),
			)
		},
		"unset fails": func(
			runtime *listenerRuntime,
			_ *fakeListenerEnvironment,
			_ *fakeListenerObserver,
			_ *fakeRegistrationMarker,
		) {
			runtime.unsetEnv = func(string) error {
				return errors.New("injected")
			}
		},
		"JIT remains after unset": func(
			runtime *listenerRuntime,
			_ *fakeListenerEnvironment,
			_ *fakeListenerObserver,
			_ *fakeRegistrationMarker,
		) {
			runtime.unsetEnv = func(string) error { return nil }
		},
		"observer fails": func(
			_ *listenerRuntime,
			_ *fakeListenerEnvironment,
			observer *fakeListenerObserver,
			_ *fakeRegistrationMarker,
		) {
			observer.failAt = observationInputValidated
		},
		"registration fails": func(
			runtime *listenerRuntime,
			_ *fakeListenerEnvironment,
			_ *fakeListenerObserver,
			_ *fakeRegistrationMarker,
		) {
			runtime.createRegistration = func(
				[sha256.Size]byte,
			) (registrationMarker, error) {
				return nil, errors.New("injected")
			}
		},
		"response mismatch": func(
			runtime *listenerRuntime,
			_ *fakeListenerEnvironment,
			_ *fakeListenerObserver,
			_ *fakeRegistrationMarker,
		) {
			runtime.exchangeHTTPS = func(
				context.Context,
				task11synthetic.Sentinel,
			) (string, error) {
				return listenerTestDigestA, nil
			}
		},
		"registration remove fails": func(
			_ *listenerRuntime,
			_ *fakeListenerEnvironment,
			_ *fakeListenerObserver,
			marker *fakeRegistrationMarker,
		) {
			marker.removeErr = errors.New("injected")
		},
		"high-water fails": func(
			_ *listenerRuntime,
			_ *fakeListenerEnvironment,
			observer *fakeListenerObserver,
			_ *fakeRegistrationMarker,
		) {
			observer.highWaterErr = errors.New("injected")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input, document := listenerInputForTest(
				t,
				task11synthetic.ScenarioOneJob,
			)
			environment := newFakeListenerEnvironment(document)
			observer := newFakeListenerObserver()
			marker := &fakeRegistrationMarker{}
			runtime := validListenerRuntimeForTest(
				t,
				input,
				environment,
				observer,
			)
			runtime.createRegistration = func(
				[sha256.Size]byte,
			) (registrationMarker, error) {
				return marker, nil
			}
			mutate(&runtime, environment, observer, marker)
			var output bytes.Buffer
			if status := run([]string{"run"}, &output, runtime); status != 1 {
				t.Fatalf("run status = %d, want 1; output=%q", status, output.Bytes())
			}
			if bytes.Count(output.Bytes(), []byte{'\n'}) > 1 {
				t.Fatalf("failure minted terminal evidence: %q", output.Bytes())
			}
		})
	}
}

func listenerInputForTest(
	t *testing.T,
	scenario task11synthetic.Scenario,
) (task11synthetic.Input, []byte) {
	t.Helper()
	input := task11synthetic.Input{
		SchemaVersion:  task11synthetic.SchemaVersion,
		ProtocolID:     task11synthetic.ProtocolID,
		Scenario:       scenario,
		CycleRunDigest: listenerTestDigestA,
		Nonce:          listenerTestDigestB,
		Sentinel: task11synthetic.Sentinel{
			URL:                  "https://example.com/probe",
			Host:                 "example.com",
			Port:                 443,
			HostIdentityDigest:   listenerTestDigestC,
			SPKIDigest:           listenerTestDigestD,
			CertificateDigest:    listenerTestDigestE,
			PolicyEntryDigest:    listenerTestDigestF,
			PolicyEvidenceDigest: listenerTestDigestA,
			ResponseBodyDigest:   listenerTestDigestB,
		},
	}
	if scenario == task11synthetic.ScenarioSeedFirst ||
		scenario == task11synthetic.ScenarioSeedSecond {
		input.SeedID = task11synthetic.SeedID
	}
	document, err := task11synthetic.MarshalInput(
		input,
		task11synthetic.MaximumWireBytes,
	)
	if err != nil {
		t.Fatalf("MarshalInput: %v", err)
	}
	return input, document
}

func validListenerRuntimeForTest(
	t *testing.T,
	input task11synthetic.Input,
	environment *fakeListenerEnvironment,
	observer *fakeListenerObserver,
) listenerRuntime {
	t.Helper()
	return listenerRuntime{
		environ:   environment.environ,
		lookupEnv: environment.lookup,
		unsetEnv:  environment.unset,
		newObserver: func() (listenerObserver, error) {
			return observer, nil
		},
		createRegistration: func(
			[sha256.Size]byte,
		) (registrationMarker, error) {
			return &fakeRegistrationMarker{}, nil
		},
		exchangeHTTPS: func(
			context.Context,
			task11synthetic.Sentinel,
		) (string, error) {
			return input.Sentinel.ResponseBodyDigest, nil
		},
		prepareSeed: func(
			task11synthetic.Scenario,
		) (seedSession, error) {
			return nil, errors.New("not a seed scenario")
		},
		createUpgradeStaging: func([sha256.Size]byte) error {
			return nil
		},
	}
}

type fakeListenerEnvironment struct {
	entries []string
	values  map[string]string
}

func newFakeListenerEnvironment(document []byte) *fakeListenerEnvironment {
	environment := &fakeListenerEnvironment{
		entries: runtimeenv.Listener(string(document)),
		values: map[string]string{
			"HOME":                     "/runner",
			"LANG":                     "C.UTF-8",
			"PATH":                     "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			listenerJITEnvironmentName: string(document),
		},
	}
	return environment
}

func (e *fakeListenerEnvironment) environ() []string {
	return slices.Clone(e.entries)
}

func (e *fakeListenerEnvironment) lookup(name string) (string, bool) {
	value, found := e.values[name]
	return value, found
}

func (e *fakeListenerEnvironment) unset(name string) error {
	delete(e.values, name)
	prefix := name + "="
	for index, entry := range e.entries {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			e.entries = append(e.entries[:index], e.entries[index+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

func (e *fakeListenerEnvironment) hasJIT() bool {
	_, found := e.values[listenerJITEnvironmentName]
	return found
}

type fakeListenerObserver struct {
	version        task11synthetic.CgroupVersion
	resources      []task11synthetic.ResourceHighWater
	points         []listenerObservationPoint
	failAt         listenerObservationPoint
	highWaterErr   error
	highWaterCalls int
}

func newFakeListenerObserver() *fakeListenerObserver {
	names := task11synthetic.Resources()
	resources := make([]task11synthetic.ResourceHighWater, len(names))
	for index, name := range names {
		resources[index] = task11synthetic.ResourceHighWater{
			Resource:  name,
			HighWater: uint64(index + 1),
		}
	}
	return &fakeListenerObserver{
		version:   task11synthetic.CgroupV2,
		resources: resources,
	}
}

func (o *fakeListenerObserver) CgroupVersion() task11synthetic.CgroupVersion {
	return o.version
}

func (o *fakeListenerObserver) Sample(point listenerObservationPoint) error {
	o.points = append(o.points, point)
	if point == o.failAt {
		return errors.New("injected")
	}
	return nil
}

func (o *fakeListenerObserver) HighWater() (
	[]task11synthetic.ResourceHighWater,
	error,
) {
	o.highWaterCalls++
	if o.highWaterErr != nil {
		return nil, o.highWaterErr
	}
	return slices.Clone(o.resources), nil
}

type fakeRegistrationMarker struct {
	removeCalls int
	removeErr   error
}

func (m *fakeRegistrationMarker) Remove() error {
	m.removeCalls++
	return m.removeErr
}

type fakeSeedSession struct {
	proof         task11synthetic.SeedProof
	finalizeCalls int
	finalizeErr   error
}

func (s *fakeSeedSession) Finalize() (
	task11synthetic.SeedProof,
	error,
) {
	s.finalizeCalls++
	return s.proof, s.finalizeErr
}

func validListenerSeedProof(
	scenario task11synthetic.Scenario,
) task11synthetic.SeedProof {
	return task11synthetic.SeedProof{
		SeedID:           task11synthetic.SeedID,
		SourceDigest:     task11synthetic.SeedSourceSHA256,
		CopyDigest:       task11synthetic.SeedSourceSHA256,
		MutationDigest:   task11synthetic.SeedMutationSHA256,
		SourcePostDigest: task11synthetic.SeedSourceSHA256,
		MutationAbsent:   scenario == task11synthetic.ScenarioSeedSecond,
		SourceImmutable:  true,
	}
}
