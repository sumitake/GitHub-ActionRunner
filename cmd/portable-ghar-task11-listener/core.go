package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"time"

	"github.com/sumitake/portable-ghar/internal/runtimeenv"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

const listenerJITEnvironmentName = "ACTIONS_RUNNER_INPUT_JITCONFIG"
const listenerProtocolTimeout = 30 * time.Second

type listenerObservationPoint uint8

const (
	observationListenerEntry listenerObservationPoint = iota + 1
	observationInputValidated
	observationSeedVerified
	observationProxyComplete
	observationSeedFinalized
	observationUpgradeStaged
	observationBeforeTerminal
	observationBeforeIntentionalExit
)

type listenerObserver interface {
	CgroupVersion() task11synthetic.CgroupVersion
	Sample(listenerObservationPoint) error
	HighWater() ([]task11synthetic.ResourceHighWater, error)
}

type registrationMarker interface {
	Remove() error
}

type seedSession interface {
	Finalize() (task11synthetic.SeedProof, error)
}

type listenerRuntime struct {
	environ   func() []string
	lookupEnv func(string) (string, bool)
	unsetEnv  func(string) error

	newObserver        func() (listenerObserver, error)
	createRegistration func(
		[sha256.Size]byte,
	) (registrationMarker, error)
	exchangeHTTPS func(
		context.Context,
		task11synthetic.Sentinel,
	) (string, error)
	prepareSeed          func(task11synthetic.Scenario) (seedSession, error)
	createUpgradeStaging func([sha256.Size]byte) error
}

func run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	runtime listenerRuntime,
) int {
	if len(args) != 1 || stdout == nil {
		return 2
	}
	switch args[0] {
	case "--version":
		if writeAll(
			stdout,
			[]byte(task11synthetic.ProtocolID+"\n"),
		) != nil {
			return 1
		}
		return 0
	case "run":
	default:
		return 2
	}
	if ctx == nil || ctx.Err() != nil || !validListenerRuntime(runtime) {
		return 1
	}
	runContext, cancel := context.WithTimeout(ctx, listenerProtocolTimeout)
	defer cancel()
	return runListener(runContext, stdout, runtime)
}

func runListener(
	ctx context.Context,
	stdout io.Writer,
	runtime listenerRuntime,
) int {
	if ctx == nil || ctx.Err() != nil {
		return 1
	}
	observer, err := runtime.newObserver()
	if err != nil || observer == nil ||
		!validListenerCgroupVersion(observer.CgroupVersion()) ||
		observer.Sample(observationListenerEntry) != nil {
		return 1
	}
	environment := runtime.environ()
	if !runtimeenv.MatchesListener(environment) {
		return 1
	}
	raw, found := runtime.lookupEnv(listenerJITEnvironmentName)
	if !found || raw == "" {
		return 1
	}
	document := []byte(raw)
	input, err := task11synthetic.ParseInput(
		document,
		task11synthetic.MaximumWireBytes,
	)
	zero(document)
	raw = ""
	if err != nil ||
		runtime.unsetEnv(listenerJITEnvironmentName) != nil {
		return 1
	}
	if _, stillPresent := runtime.lookupEnv(listenerJITEnvironmentName); stillPresent ||
		!runtimeenv.MatchesImage(runtime.environ()) ||
		observer.Sample(observationInputValidated) != nil {
		return 1
	}

	var seed seedSession
	if input.Scenario == task11synthetic.ScenarioSeedFirst ||
		input.Scenario == task11synthetic.ScenarioSeedSecond {
		seed, err = runtime.prepareSeed(input.Scenario)
		if err != nil || seed == nil ||
			observer.Sample(observationSeedVerified) != nil {
			return 1
		}
	}

	jobMarkerDigest, err := task11synthetic.DeriveJobMarkerDigest(
		input.CycleRunDigest,
		input.Nonce,
	)
	if err != nil {
		return 1
	}
	jobMarkerBytes, err := decodeMarkerDigest(jobMarkerDigest)
	if err != nil {
		return 1
	}
	marker, err := runtime.createRegistration(jobMarkerBytes)
	if err != nil || marker == nil {
		return 1
	}

	boundary := task11synthetic.BoundaryListenerReady
	upgrade := false
	switch input.Scenario {
	case task11synthetic.ScenarioCleanupListenerCrash:
		boundary = task11synthetic.BoundaryListenerCrashArmed
	case task11synthetic.ScenarioCleanupUpgradeInterruption:
		boundary = task11synthetic.BoundaryUpgradeInterruptionArmed
		upgrade = true
		if runtime.createUpgradeStaging(jobMarkerBytes) != nil ||
			observer.Sample(observationUpgradeStaged) != nil {
			return 1
		}
	}
	boundaryFrame := task11synthetic.BoundaryFrame{
		SchemaVersion:                task11synthetic.SchemaVersion,
		ProtocolID:                   task11synthetic.ProtocolID,
		Frame:                        task11synthetic.FrameBoundary,
		Scenario:                     input.Scenario,
		CycleRunDigest:               input.CycleRunDigest,
		JobMarkerDigest:              jobMarkerDigest,
		Boundary:                     boundary,
		SyntheticTokenAbsent:         true,
		ImmutablePayloadCount:        1,
		UpgradeInterruptionExercised: upgrade,
		CgroupVersion:                observer.CgroupVersion(),
		SeedID:                       input.SeedID,
	}
	boundaryDocument, err := task11synthetic.MarshalBoundaryFrame(boundaryFrame)
	if err != nil || ctx.Err() != nil ||
		writeAll(stdout, boundaryDocument) != nil {
		return 1
	}
	switch input.Scenario {
	case task11synthetic.ScenarioCleanupListenerCrash:
		if observer.Sample(observationBeforeIntentionalExit) != nil {
			return 1
		}
		return task11synthetic.ListenerCrashExitStatus
	case task11synthetic.ScenarioCleanupUpgradeInterruption:
		if observer.Sample(observationBeforeIntentionalExit) != nil {
			return 1
		}
		return task11synthetic.UpgradeInterruptionExitStatus
	}

	observedBodyDigest, err := runtime.exchangeHTTPS(
		ctx,
		input.Sentinel,
	)
	if err != nil || ctx.Err() != nil ||
		observedBodyDigest != input.Sentinel.ResponseBodyDigest ||
		observer.Sample(observationProxyComplete) != nil {
		return 1
	}
	proxyRequestDigest, err := task11synthetic.DeriveProxyRequestDigest(
		input.CycleRunDigest,
		input.Nonce,
		input.Sentinel.PolicyEntryDigest,
		input.Sentinel.PolicyEvidenceDigest,
		observedBodyDigest,
	)
	if err != nil {
		return 1
	}
	responseBodyProofDigest, err :=
		task11synthetic.DeriveResponseBodyProofDigest(
			input.CycleRunDigest,
			input.Nonce,
			observedBodyDigest,
			input.Sentinel.ResponseBodyDigest,
		)
	if err != nil {
		return 1
	}

	var seedProof *task11synthetic.SeedProof
	if seed != nil {
		proof, seedErr := seed.Finalize()
		if seedErr != nil ||
			observer.Sample(observationSeedFinalized) != nil {
			return 1
		}
		seedProof = &proof
	}
	if marker.Remove() != nil ||
		observer.Sample(observationBeforeTerminal) != nil {
		return 1
	}
	highWater, err := observer.HighWater()
	if err != nil || ctx.Err() != nil {
		return 1
	}
	terminalFrame := task11synthetic.TerminalFrame{
		SchemaVersion:                task11synthetic.SchemaVersion,
		ProtocolID:                   task11synthetic.ProtocolID,
		Frame:                        task11synthetic.FrameTerminal,
		Scenario:                     input.Scenario,
		CycleRunDigest:               input.CycleRunDigest,
		JobMarkerDigest:              jobMarkerDigest,
		Outcome:                      task11synthetic.OutcomeCompleted,
		ProxyRequestDigest:           proxyRequestDigest,
		ResponseBodyProofDigest:      responseBodyProofDigest,
		RegistrationRemoved:          true,
		SyntheticTokenAbsent:         true,
		ImmutablePayloadCount:        1,
		UpgradeInterruptionExercised: false,
		CgroupVersion:                observer.CgroupVersion(),
		Resources:                    highWater,
		Seed:                         seedProof,
	}
	terminalDocument, err := task11synthetic.MarshalTerminalFrame(terminalFrame)
	if err != nil || writeAll(stdout, terminalDocument) != nil {
		return 1
	}
	return task11synthetic.NormalExitStatus
}

func validListenerRuntime(runtime listenerRuntime) bool {
	return runtime.environ != nil &&
		runtime.lookupEnv != nil &&
		runtime.unsetEnv != nil &&
		runtime.newObserver != nil &&
		runtime.createRegistration != nil &&
		runtime.exchangeHTTPS != nil &&
		runtime.prepareSeed != nil &&
		runtime.createUpgradeStaging != nil
}

func validListenerCgroupVersion(
	version task11synthetic.CgroupVersion,
) bool {
	return version == task11synthetic.CgroupV1 ||
		version == task11synthetic.CgroupV2
}

func decodeMarkerDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, task11synthetic.ErrInvalidProtocol
	}
	copy(result[:], decoded)
	zero(decoded)
	return result, nil
}

func writeAll(target io.Writer, document []byte) error {
	written, err := target.Write(document)
	if err != nil || written != len(document) {
		return task11synthetic.ErrInvalidProtocol
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
