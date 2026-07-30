package testenv

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type fakeRecoveryRuntime struct {
	proof SyntheticRecoveryProof
	calls int
}

func (r *fakeRecoveryRuntime) RecoveryObservation(
	context.Context,
	fixtureRuntimeObservation,
) (SyntheticRecoveryProof, error) {
	r.calls++
	if r.calls != 1 {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	return cloneSyntheticRecoveryProof(r.proof), nil
}

func validSyntheticRecoveryProof() SyntheticRecoveryProof {
	return SyntheticRecoveryProof{
		InitialFenceGeneration: 7,
		DisabledGeneration:     8,
		PersistedMode:          "disabled",
		PersistedCapacity:      0,
		ControllerKilled:       true,
		ControllerProcessDeath: ProcessDeathProof{
			Expected: []ProcessIdentity{{
				PID:          101,
				StartTime:    202,
				ProcessGroup: 101,
			}},
		},
		WatchdogRestarted:           true,
		RestartAfterControllerDeath: true,
		LegacyOwnsFence:             true,
		RebootRecoveredDark:         true,
		NoncancellableProcessDeath: ProcessDeathProof{
			Expected: []ProcessIdentity{{
				PID:          303,
				StartTime:    404,
				ProcessGroup: 303,
			}},
		},
		ObserverRestarted:         true,
		ObserverRestartAfterDeath: true,
		OrderedStates: []string{
			"portable-stopped",
			"disabled-persisted",
			"legacy-owned",
			"observer-started",
		},
		AssertionCount:    21,
		ObservationDigest: inputDigestA,
	}
}

func TestRecoverySourceFreezesWatchdogFenceAndShutdownInOrder(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughSeedIsolation(t, ledger)
	runtime := &fakeRecoveryRuntime{
		proof: validSyntheticRecoveryProof(),
	}
	source, err := newRecoveryMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newRecoveryMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		switch requirement.Case {
		case conformance.CaseWatchdogRecovery,
			conformance.CaseLegacyFenceRecovery,
			conformance.CaseNoncancellableShutdown:
		default:
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
		switch requirement.ID {
		case "watchdog-zero-traps":
			if _, _, frozen := ledger.snapshotAfterCase12(); !frozen {
				t.Fatal("case 12 ledger was not frozen")
			}
		case "legacy-zero-portable-acquisition":
			if _, _, frozen := ledger.snapshotAfterCase13(); !frozen {
				t.Fatal("case 13 ledger was not frozen")
			}
		case "noncancellable-observer-order":
			if _, _, frozen := ledger.snapshotAfterCase14(); !frozen {
				t.Fatal("case 14 ledger was not frozen")
			}
		}
	}
	if len(observations) != 7 || runtime.calls != 1 {
		t.Fatalf(
			"recovery observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
	for index, observation := range observations {
		if len(observation.Measurements) != 0 ||
			observation.AssertionCount == 0 {
			t.Fatalf("observation[%d] = %+v", index, observation)
		}
	}
}

func TestRecoverySourceRejectsUnfrozenTrapsOrEarlyObserverRestart(
	t *testing.T,
) {
	t.Parallel()

	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseWatchdogRecovery {
			first = requirement
			break
		}
	}
	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := &fakeRecoveryRuntime{
		proof: validSyntheticRecoveryProof(),
	}
	unfrozen, err := newRecoveryMatrixSource(
		unfrozenLedger,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if unfrozenRuntime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", unfrozenRuntime.calls)
	}

	for name, mutate := range map[string]func(*SyntheticRecoveryProof){
		"route writer trap": func(proof *SyntheticRecoveryProof) {
			proof.RouteWriterCalls = 1
		},
		"portable acquisition trap": func(proof *SyntheticRecoveryProof) {
			proof.AcquisitionCalls = 1
		},
		"poll process remains": func(proof *SyntheticRecoveryProof) {
			proof.NoncancellableProcessDeath.ObservedAfter =
				append(
					proof.NoncancellableProcessDeath.ObservedAfter,
					proof.NoncancellableProcessDeath.Expected[0],
				)
		},
		"observer restart before death": func(proof *SyntheticRecoveryProof) {
			proof.ObserverRestartAfterDeath = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			ledger, err := newPreparedRuntimeEvidenceLedger(
				64,
				validNamespaceEvidenceRuntime(),
			)
			if err != nil {
				t.Fatalf("new ledger: %v", err)
			}
			freezeThroughSeedIsolation(t, ledger)
			proof := validSyntheticRecoveryProof()
			mutate(&proof)
			runtime := &fakeRecoveryRuntime{proof: proof}
			source, err := newRecoveryMatrixSource(ledger, runtime)
			if err != nil {
				t.Fatalf("new source: %v", err)
			}
			if _, err := source.Observe(
				context.Background(),
				first,
			); !errors.Is(err, conformance.ErrObservation) {
				t.Fatalf("invalid proof error = %v", err)
			}
			if runtime.calls != 1 {
				t.Fatalf("runtime calls = %d", runtime.calls)
			}
		})
	}
}
