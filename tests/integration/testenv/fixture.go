package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

const unsupportedHostSkip = "SKIP unsupported host profile"

var (
	ErrFixtureOptIn            = errors.New("testenv: fixture opt-in invalid")
	ErrFixtureStart            = errors.New("testenv: fixture start failed")
	ErrFixtureCleanup          = errors.New("testenv: fixture cleanup failed")
	ErrFixtureUnexpectedObject = errors.New(
		"testenv: fixture contains unexpected object",
	)
)

type FixtureStartupDecision struct {
	Skip      bool
	Reason    string
	InputPath string
}

type FixtureHostFacts struct {
	OperatingSystem           string
	Architecture              string
	EUID                      uint32
	HostIdentityDigest        string
	ControlHostIdentityDigest string
}

type CleanupKind uint8

const (
	CleanupFixtureRoot CleanupKind = iota + 1
	CleanupNetwork
	CleanupTestProcess
	CleanupDialAuthority
	CleanupAdapter
	CleanupBroker
	CleanupHelper
	CleanupVerifier
	CleanupRunner
	CleanupSyntheticListener
)

type cleanupHandle struct {
	kind CleanupKind
	id   string
}

type fixtureRootAuthority interface {
	Acquire(context.Context, FixtureBinding) (cleanupHandle, error)
}

type fixtureAuthorization interface {
	Consume() error
	Close() error
}

type fixtureEffects interface {
	Start(context.Context, func(cleanupHandle) error) error
}

type fixtureCleanup interface {
	Remove(context.Context, cleanupHandle) error
	Prove(
		context.Context,
		[]cleanupHandle,
		FixtureBinding,
	) (conformance.CleanupObservation, error)
}

type fixtureCaseExecutor interface {
	RunActualHost(
		context.Context,
		conformance.ActualHostCaseID,
	) (conformance.ActualHostResult, error)
	RunSynthetic(
		context.Context,
		conformance.SyntheticCaseID,
	) (conformance.SyntheticResult, error)
}

type fixtureTargetFinalizer interface {
	Finalize(
		context.Context,
		[]conformance.CaseID,
	) (conformance.TargetObservationInput, error)
}

type fixtureStartDependencies struct {
	RegisterCleanup func(func())
	Authorization   fixtureAuthorization
	Root            fixtureRootAuthority
	Effects         fixtureEffects
	Cleanup         fixtureCleanup
	Cases           fixtureCaseExecutor
	Finalizer       fixtureTargetFinalizer
}

// Fixture owns exactly one target run and one idempotent cleanup state
// machine. Its handles are opaque outside testenv and are removed only by
// exact identity in reverse creation order.
type Fixture struct {
	input     ConformanceInput
	binding   conformance.Binding
	cases     fixtureCaseExecutor
	finalizer fixtureTargetFinalizer
	cleanup   fixtureCleanup
	authority fixtureAuthorization

	mu             sync.Mutex
	handles        []cleanupHandle
	completedCases []conformance.CaseID
	caseInProgress bool
	cleanupActive  bool

	cleanupOnce   sync.Once
	cleanupResult conformance.CleanupEvidence
	cleanupErr    error
	cleanupDone   chan struct{}
}

func decideFixtureStartup(
	goos string,
	lookup func(string) (string, bool),
) (FixtureStartupDecision, error) {
	if goos != "linux" {
		return FixtureStartupDecision{
			Skip:   true,
			Reason: unsupportedHostSkip,
		}, nil
	}
	if lookup == nil {
		return FixtureStartupDecision{}, ErrFixtureOptIn
	}
	dockerValue, dockerPresent := lookup("PGHAR_INTEGRATION_DOCKER")
	inputPath, inputPresent := lookup("PGHAR_CONFORMANCE_INPUT")
	if !dockerPresent && !inputPresent {
		return FixtureStartupDecision{
			Skip:   true,
			Reason: unsupportedHostSkip,
		}, nil
	}
	if !dockerPresent ||
		dockerValue != "1" ||
		!inputPresent ||
		!validAbsolutePath(inputPath) {
		return FixtureStartupDecision{}, ErrFixtureOptIn
	}
	return FixtureStartupDecision{InputPath: inputPath}, nil
}

func startFixtureCore(
	ctx context.Context,
	parsed ParsedConformanceInput,
	facts FixtureHostFacts,
	dependencies fixtureStartDependencies,
) (*Fixture, error) {
	if ctx == nil ||
		dependencies.RegisterCleanup == nil ||
		dependencies.Authorization == nil ||
		dependencies.Root == nil ||
		dependencies.Effects == nil ||
		dependencies.Cleanup == nil ||
		dependencies.Cases == nil ||
		dependencies.Finalizer == nil ||
		!validateParsedInputEnvelope(parsed) ||
		!validateFixtureHostFacts(parsed.Input.Target, facts) {
		return nil, ErrFixtureStart
	}
	binding, err := bindingFromParsedInput(parsed)
	if err != nil {
		return nil, ErrFixtureStart
	}
	fixture := &Fixture{
		input:       parsed.Input,
		binding:     binding,
		cases:       dependencies.Cases,
		finalizer:   dependencies.Finalizer,
		cleanup:     dependencies.Cleanup,
		authority:   dependencies.Authorization,
		cleanupDone: make(chan struct{}),
	}
	dependencies.RegisterCleanup(func() {
		_, _ = fixture.Cleanup(context.Background())
	})

	if err := dependencies.Authorization.Consume(); err != nil {
		if _, closeErr := fixture.Cleanup(context.Background()); closeErr != nil {
			return nil, ErrFixtureCleanup
		}
		return nil, err
	}
	fixture.mu.Lock()
	fixture.cleanupActive = true
	fixture.mu.Unlock()

	root, err := dependencies.Root.Acquire(ctx, parsed.Input.Fixture)
	if err != nil ||
		root.kind != CleanupFixtureRoot ||
		fixture.recordHandle(root) != nil {
		_, _ = fixture.Cleanup(context.Background())
		return nil, ErrFixtureStart
	}
	if err := dependencies.Effects.Start(ctx, fixture.recordHandle); err != nil {
		_, _ = fixture.Cleanup(context.Background())
		return nil, ErrFixtureStart
	}
	return fixture, nil
}

func (f *Fixture) beginCase(id conformance.CaseID) bool {
	if f == nil || id == "" {
		return false
	}
	required := conformance.RequiredCases()
	f.mu.Lock()
	defer f.mu.Unlock()
	index := len(f.completedCases)
	if f.caseInProgress ||
		index >= len(required)-1 ||
		required[index] != id {
		return false
	}
	f.caseInProgress = true
	return true
}

func (f *Fixture) finishCase(id conformance.CaseID, passed bool) bool {
	if f == nil || id == "" {
		return false
	}
	required := conformance.RequiredCases()
	f.mu.Lock()
	defer f.mu.Unlock()
	index := len(f.completedCases)
	if !f.caseInProgress ||
		index >= len(required)-1 ||
		required[index] != id {
		f.caseInProgress = false
		return false
	}
	f.caseInProgress = false
	if passed {
		f.completedCases = append(f.completedCases, id)
	}
	return true
}

func (f *Fixture) completedCaseSet() ([]conformance.CaseID, bool) {
	if f == nil {
		return nil, false
	}
	required := conformance.RequiredCases()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.caseInProgress ||
		len(f.completedCases) != len(required)-1 {
		return nil, false
	}
	for index := range f.completedCases {
		if f.completedCases[index] != required[index] {
			return nil, false
		}
	}
	return append([]conformance.CaseID(nil), f.completedCases...), true
}

func validateParsedInputEnvelope(parsed ParsedConformanceInput) bool {
	if len(parsed.Document) == 0 || !isLowerHex(parsed.Digest, 64) {
		return false
	}
	canonical, err := json.Marshal(parsed.Input)
	if err != nil || !bytes.Equal(canonical, parsed.Document) {
		return false
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(inputDigestDomain))
	_, _ = digest.Write(parsed.Document)
	return parsed.Digest == hex.EncodeToString(digest.Sum(nil))
}

func validateFixtureHostFacts(
	target TargetBinding,
	facts FixtureHostFacts,
) bool {
	return facts.OperatingSystem == target.OperatingSystem &&
		facts.Architecture == target.Architecture &&
		facts.EUID == target.ExpectedEUID &&
		facts.HostIdentityDigest == target.HostIdentityDigest &&
		facts.ControlHostIdentityDigest == target.ControlHostIdentityDigest &&
		facts.HostIdentityDigest != facts.ControlHostIdentityDigest &&
		isLowerHex(facts.HostIdentityDigest, 64) &&
		isLowerHex(facts.ControlHostIdentityDigest, 64)
}

func bindingFromParsedInput(
	parsed ParsedConformanceInput,
) (conformance.Binding, error) {
	input := parsed.Input
	return conformance.NewBinding(conformance.BindingInput{
		SchemaVersion:                 1,
		BuildID:                       input.Runtime.BuildID,
		SourceCommit:                  input.Runtime.SourceCommit,
		RuntimeManifestDigest:         input.Runtime.RuntimeManifestDigest,
		PrivateOverlayDigest:          input.Runtime.PrivateOverlayDigest,
		ConformanceInputDigest:        parsed.Digest,
		AuthorizationDigest:           input.Authorization.Digest,
		RunID:                         input.Authorization.RunID,
		ProfileID:                     input.Target.ProfileID,
		FleetGeneration:               input.Runtime.FleetGeneration,
		ExpectedProfileEvidenceDigest: input.Runtime.ExpectedProfileEvidenceDigest,
		ExpectedNetworkEvidenceDigest: input.Runtime.ExpectedNetworkEvidenceDigest,
		PlanDigest:                    input.Runtime.ConformancePlanDigest,
	})
}

func (f *Fixture) recordHandle(handle cleanupHandle) error {
	if f == nil || !validCleanupKind(handle.kind) ||
		!isLowerHex(handle.id, 64) {
		return ErrFixtureStart
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.handles {
		if existing.id == handle.id {
			return ErrFixtureStart
		}
	}
	f.handles = append(f.handles, handle)
	return nil
}

func validCleanupKind(kind CleanupKind) bool {
	return kind >= CleanupFixtureRoot && kind <= CleanupSyntheticListener
}

// Cleanup ignores cancellation of the caller and uses the input's independent
// bounded cleanup window. Concurrent and later callers receive the one cached
// typed result.
func (f *Fixture) Cleanup(
	context.Context,
) (conformance.CleanupEvidence, error) {
	if f == nil {
		return conformance.CleanupEvidence{}, ErrFixtureCleanup
	}
	f.cleanupOnce.Do(func() {
		defer close(f.cleanupDone)
		f.mu.Lock()
		active := f.cleanupActive
		f.mu.Unlock()
		if !active {
			if f.authority == nil || f.authority.Close() != nil {
				f.cleanupErr = ErrFixtureCleanup
			}
			return
		}
		timeout := durationMilliseconds(
			f.input.Limits.CleanupTimeoutMilliseconds,
		)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		f.mu.Lock()
		handles := append([]cleanupHandle(nil), f.handles...)
		f.mu.Unlock()
		var failed bool
		for index := len(handles) - 1; index >= 0; index-- {
			if err := f.cleanup.Remove(ctx, handles[index]); err != nil {
				failed = true
			}
		}
		observation, err := f.cleanup.Prove(
			ctx,
			append([]cleanupHandle(nil), handles...),
			f.input.Fixture,
		)
		if err != nil {
			failed = true
		}
		if f.authority == nil || f.authority.Close() != nil {
			failed = true
		}
		if !failed {
			f.cleanupResult, err = conformance.SealCleanup(observation)
			if err != nil {
				failed = true
			}
		}
		if failed {
			f.cleanupResult = conformance.CleanupEvidence{}
			f.cleanupErr = ErrFixtureCleanup
		}
	})
	<-f.cleanupDone
	return f.cleanupResult, f.cleanupErr
}

func durationMilliseconds(value uint64) time.Duration {
	return time.Duration(value) * time.Millisecond
}
