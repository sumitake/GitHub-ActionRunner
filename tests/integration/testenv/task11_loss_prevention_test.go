package testenv

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

func TestRecordingEngineOmitsEachAllowedReleasePreparedFact(t *testing.T) {
	t.Parallel()

	for _, fact := range task11AllowedMissingPreparedFacts() {
		fact := fact
		t.Run(task11MissingPreparedFactName(fact), func(t *testing.T) {
			t.Parallel()

			engine, runnerID := task11LossReadyRecordingEngine(t)
			if err := engine.omitReleasePreparedFact(
				runnerID,
				fact,
			); err != nil {
				t.Fatalf("omitReleasePreparedFact: %v", err)
			}
			engine.mu.Lock()
			runner := engine.handles[runnerID]
			if engine.releaseAuthorizationViewCompleteLocked(runner) {
				engine.mu.Unlock()
				t.Fatal("omitted fact left prepared view complete")
			}
			if runner.handle.id != runnerID ||
				runner.removed {
				engine.mu.Unlock()
				t.Fatal("omission changed cleanup authority")
			}
			engine.mu.Unlock()
			if err := engine.omitReleasePreparedFact(
				runnerID,
				fact,
			); err != ErrFixtureStart {
				t.Fatalf("repeat omission error = %v", err)
			}
		})
	}
}

func TestTask11LossPreventionRuntimeBindsSeparateFailureAndPrimaryReaudit(
	t *testing.T,
) {
	t.Parallel()

	_, prepared, dependencies := validTask11CasesThreeToSixRuntime(t)
	primarySeal, err := task11PreparedObservationSeal(
		prepared,
		dependencies.prepared.flood,
	)
	if err != nil {
		t.Fatalf("task11PreparedObservationSeal: %v", err)
	}
	attempt := &fakeTask11LossAttemptSource{
		observation: validTask11LossAttemptObservationForTest(),
	}
	runtime, err := newTask11LossPreventionRuntime(
		task11LossPreventionBinding{
			PrimaryRunDigest:      inputDigestA,
			PrimaryCapacitySlotID: 17,
			PrimaryJobGeneration:  29,
			MissingFact:           task11MissingBrokerAuditEvidence,
		},
		dependencies.prepared,
		attempt,
	)
	if err != nil {
		t.Fatalf("newTask11LossPreventionRuntime: %v", err)
	}
	proof, err := runtime.ProveLossPreventsRelease(
		t.Context(),
		prepared,
		primarySeal,
	)
	if err != nil {
		t.Fatalf("ProveLossPreventsRelease: %v", err)
	}
	if !proof.Matches(primarySeal) ||
		!isLowerHex(proof.Digest(), 64) ||
		attempt.calls != 1 ||
		dependencies.prepared.snapshotCalls != 2 {
		t.Fatalf(
			"proof=%+v calls=%d snapshots=%d",
			proof,
			attempt.calls,
			dependencies.prepared.snapshotCalls,
		)
	}
	if _, err := runtime.ProveLossPreventsRelease(
		t.Context(),
		prepared,
		primarySeal,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("repeat proof error = %v", err)
	}
}

func TestTask11LossPreventionRuntimeRejectsAliasedOrIncompleteAttempt(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(
		*task11LossAttemptObservation,
		fixtureRuntimeObservation,
	){
		"primary adapter alias": func(
			observation *task11LossAttemptObservation,
			primary fixtureRuntimeObservation,
		) {
			observation.Adapter = task11LossHandleFromCleanup(
				primary.Adapter,
			)
		},
		"release called": func(
			observation *task11LossAttemptObservation,
			_ fixtureRuntimeObservation,
		) {
			observation.ReleaseCalls = 1
		},
		"cleanup absent": func(
			observation *task11LossAttemptObservation,
			_ fixtureRuntimeObservation,
		) {
			observation.CleanupComplete = false
		},
		"wrong stage": func(
			observation *task11LossAttemptObservation,
			_ fixtureRuntimeObservation,
		) {
			observation.FailedStage =
				networkjail.StageRunnerArm.String()
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, prepared, dependencies :=
				validTask11CasesThreeToSixRuntime(t)
			primarySeal, err := task11PreparedObservationSeal(
				prepared,
				dependencies.prepared.flood,
			)
			if err != nil {
				t.Fatalf("task11PreparedObservationSeal: %v", err)
			}
			observation := validTask11LossAttemptObservationForTest()
			mutate(&observation, prepared)
			runtime, err := newTask11LossPreventionRuntime(
				task11LossPreventionBinding{
					PrimaryRunDigest:      inputDigestA,
					PrimaryCapacitySlotID: 17,
					PrimaryJobGeneration:  29,
					MissingFact:           task11MissingBrokerAuditEvidence,
				},
				dependencies.prepared,
				&fakeTask11LossAttemptSource{
					observation: observation,
				},
			)
			if err != nil {
				t.Fatalf("newTask11LossPreventionRuntime: %v", err)
			}
			if _, err := runtime.ProveLossPreventsRelease(
				t.Context(),
				prepared,
				primarySeal,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("ProveLossPreventsRelease error = %v", err)
			}
		})
	}
}

func TestTask11LossRunDigestDomainSeparatesEveryAllowedFact(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	for _, fact := range task11AllowedMissingPreparedFacts() {
		digest, err := task11LossRunDigest(inputDigestA, fact)
		if err != nil {
			t.Fatalf("task11LossRunDigest(%d): %v", fact, err)
		}
		if !isLowerHex(digest, 64) || digest == inputDigestA {
			t.Fatalf("loss digest = %q", digest)
		}
		if _, exists := seen[digest]; exists {
			t.Fatalf("loss digest aliased for fact %d", fact)
		}
		seen[digest] = struct{}{}
	}
}

func TestTask11ExactAssignmentStateReadsSeededTerminalState(t *testing.T) {
	t.Parallel()

	input, overlay, _, _, _ := validRuntimeSpecInputs(t)
	plan, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	store, err := state.OpenWithHistoryLimits(
		filepath.Join(t.TempDir(), "controller.db"),
		plan.HistoryLimits,
	)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := seedCompositionAssignment(
		t.Context(),
		store,
		plan,
		time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("seedCompositionAssignment: %v", err)
	}
	if err := store.Advance(
		t.Context(),
		plan.AssignmentKey,
		controller.StateDestroyed,
	); err != nil {
		t.Fatalf("Advance destroyed: %v", err)
	}
	got, err := task11ExactAssignmentState(
		t.Context(),
		store,
		plan.AssignmentKey,
	)
	if err != nil {
		t.Fatalf("task11ExactAssignmentState: %v", err)
	}
	if got != controller.StateDestroyed {
		t.Fatalf("state = %q", got)
	}
}

type fakeTask11LossAttemptSource struct {
	observation task11LossAttemptObservation
	err         error
	calls       int
}

func (s *fakeTask11LossAttemptSource) RunLossAttempt(
	ctx context.Context,
	fact task11MissingPreparedFact,
) (task11LossAttemptObservation, error) {
	s.calls++
	if ctx == nil || ctx.Err() != nil ||
		fact != s.observation.MissingFact {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	return s.observation, s.err
}

func validTask11LossAttemptObservationForTest() task11LossAttemptObservation {
	return task11LossAttemptObservation{
		RunDigest:      strings.Repeat("d", 64),
		CapacitySlotID: 31,
		JobGeneration:  37,
		Adapter: task11LossHandleObservation{
			Kind: CleanupAdapter,
			ID:   strings.Repeat("7", 64),
		},
		Broker: task11LossHandleObservation{
			Kind: CleanupBroker,
			ID:   strings.Repeat("8", 64),
		},
		Runner: task11LossHandleObservation{
			Kind: CleanupRunner,
			ID:   strings.Repeat("9", 64),
		},
		MissingFact:     task11MissingBrokerAuditEvidence,
		FailedStage:     networkjail.StageRunnerAuthorize.String(),
		TypedFailure:    networkjail.ErrSetupFailed.Error(),
		TerminalState:   controller.StateDestroyed,
		AuditCalls:      2,
		ReleaseCalls:    0,
		CleanupDigest:   strings.Repeat("e", 64),
		CleanupComplete: true,
	}
}

func task11LossReadyRecordingEngine(
	t *testing.T,
) (*recordingEngine, string) {
	t.Helper()

	adapterID := strings.Repeat("a", 64)
	brokerID := strings.Repeat("b", 64)
	runnerID := strings.Repeat("c", 64)
	engine := &recordingEngine{
		base:    &closedRecordingEngine{},
		binding: testRecordingRuntimeBinding(),
		handles: map[string]*recordedRuntimeHandle{},
	}
	engine.handles[adapterID] = &recordedRuntimeHandle{
		handle: cleanupHandle{
			kind: CleanupAdapter,
			id:   adapterID,
		},
		specDigest:        inputDigestA,
		emptinessDigest:   inputDigestB,
		peerBindingDigest: inputDigestC,
		egressDigest:      inputDigestD,
	}
	engine.handles[brokerID] = &recordedRuntimeHandle{
		handle: cleanupHandle{
			kind: CleanupBroker,
			id:   brokerID,
		},
		parentAdapter:           adapterID,
		specDigest:              inputDigestA,
		policyDigest:            inputDigestB,
		policyApplicationDigest: inputDigestC,
		authorityReceipt:        inputDigestD,
		authorityBound:          true,
		peerBindingDigest:       inputDigestC,
		egressDigest:            inputDigestD,
		auditDigest:             inputDigestA,
		auditCount:              1,
	}
	engine.handles[runnerID] = &recordedRuntimeHandle{
		handle: cleanupHandle{
			kind: CleanupRunner,
			id:   runnerID,
		},
		parentAdapter:         adapterID,
		auditDigest:           inputDigestD,
		auditCount:            1,
		armReceipt:            inputDigestA,
		finalNamespaceReceipt: inputDigestB,
	}
	return engine, runnerID
}

func task11MissingPreparedFactName(
	fact task11MissingPreparedFact,
) string {
	switch fact {
	case task11MissingRunnerComponent:
		return "component"
	case task11MissingPolicyApplication:
		return "policy"
	case task11MissingFinalNamespaceState:
		return "state"
	case task11MissingBrokerAuditEvidence:
		return "evidence"
	default:
		return "invalid"
	}
}
