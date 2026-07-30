package testenv

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type fakeSeedIsolationRuntime struct {
	proof SeedIsolationProof
	calls int
}

func (r *fakeSeedIsolationRuntime) SeedIsolationObservation(
	context.Context,
	fixtureRuntimeObservation,
) (SeedIsolationProof, error) {
	r.calls++
	if r.calls != 1 {
		return SeedIsolationProof{}, ErrFixtureStart
	}
	return r.proof, nil
}

func validSeedIsolationProof() SeedIsolationProof {
	return SeedIsolationProof{
		SourceDigest:             inputDigestA,
		FirstCopyDigest:          inputDigestA,
		CurrentMutationDigest:    inputDigestB,
		SecondCopyDigest:         inputDigestA,
		SourcePostDigest:         inputDigestA,
		MutationAbsent:           true,
		SourceImmutable:          true,
		HostBackedWorkAbsent:     true,
		SharedSeedPathAbsent:     true,
		FirstWorkspaceReclaimed:  true,
		SecondWorkspaceReclaimed: true,
		WorkspacesReclaimed:      true,
	}
}

func TestSeedIsolationSourceBindsTwoFreshCopiesAndBothReclamations(
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
	freezeThroughWorkflowTools(t, ledger)
	runtime := &fakeSeedIsolationRuntime{
		proof: validSeedIsolationProof(),
	}
	source, err := newSeedIsolationMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newSeedIsolationMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseSeedIsolation {
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
	}
	if len(observations) != 4 || runtime.calls != 1 {
		t.Fatalf(
			"seed observations/calls = %d/%d",
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
	if _, _, frozen := ledger.snapshotAfterCase11(); !frozen {
		t.Fatal("case 11 ledger was not frozen")
	}
}

func TestSeedIsolationSourceRejectsUnfrozenSharedOrResidualState(
	t *testing.T,
) {
	t.Parallel()

	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSeedIsolation {
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
	unfrozenRuntime := &fakeSeedIsolationRuntime{
		proof: validSeedIsolationProof(),
	}
	unfrozen, err := newSeedIsolationMatrixSource(
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

	for name, mutate := range map[string]func(*SeedIsolationProof){
		"source changed": func(proof *SeedIsolationProof) {
			proof.SourcePostDigest = inputDigestC
		},
		"shared seed path": func(proof *SeedIsolationProof) {
			proof.SharedSeedPathAbsent = false
		},
		"first workspace remains": func(proof *SeedIsolationProof) {
			proof.FirstWorkspaceReclaimed = false
		},
		"second workspace remains": func(proof *SeedIsolationProof) {
			proof.SecondWorkspaceReclaimed = false
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
			freezeThroughWorkflowTools(t, ledger)
			proof := validSeedIsolationProof()
			mutate(&proof)
			runtime := &fakeSeedIsolationRuntime{proof: proof}
			source, err := newSeedIsolationMatrixSource(
				ledger,
				runtime,
			)
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
