package testenv

import (
	"context"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type seedIsolationRuntime interface {
	SeedIsolationObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (SeedIsolationProof, error)
}

type seedIsolationMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      seedIsolationRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

func newSeedIsolationMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime seedIsolationRuntime,
) (*seedIsolationMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSeedIsolation {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 4 {
		return nil, ErrFixtureStart
	}
	return &seedIsolationMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *seedIsolationMatrixSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed ||
		s.next >= len(s.requirements) ||
		requirement != s.requirements[s.next] {
		return matrixObservation{}, conformance.ErrObservation
	}
	if !s.ready {
		observations, err := s.acquire(ctx)
		if err != nil {
			s.failed = true
			return matrixObservation{}, conformance.ErrObservation
		}
		s.observations = observations
		s.ready = true
	}
	if len(s.observations) != len(s.requirements) ||
		s.observations[s.next].Requirement != requirement {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	observation := s.observations[s.next]
	s.next++
	if s.next == len(s.requirements) &&
		!s.ledger.freezeCase11() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *seedIsolationMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase10()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	proof, err := s.runtime.SeedIsolationObservation(ctx, prepared)
	if err != nil || ValidateSeedIsolation(proof) != nil {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := seedIsolationMatrixObservation(
			requirement,
			prepared.PreparedEvidenceDigest,
			proof,
		)
		if err != nil {
			return nil, conformance.ErrObservation
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func seedIsolationMatrixObservation(
	requirement ObservationRequirement,
	preparedEvidenceDigest string,
	proof SeedIsolationProof,
) (matrixObservation, error) {
	var (
		assertions uint64
		payload    any
	)
	switch requirement.ID {
	case "seed-current-job":
		assertions = 3
		payload = struct {
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
			SourceDigest           string `json:"source_digest"`
			FirstCopyDigest        string `json:"first_copy_digest"`
			CurrentMutationDigest  string `json:"current_mutation_digest"`
		}{
			PreparedEvidenceDigest: preparedEvidenceDigest,
			SourceDigest:           proof.SourceDigest,
			FirstCopyDigest:        proof.FirstCopyDigest,
			CurrentMutationDigest:  proof.CurrentMutationDigest,
		}
	case "seed-next-job":
		assertions = 3
		payload = struct {
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
			SecondCopyDigest       string `json:"second_copy_digest"`
			MutationAbsent         bool   `json:"mutation_absent"`
			SharedSeedPathAbsent   bool   `json:"shared_seed_path_absent"`
		}{
			PreparedEvidenceDigest: preparedEvidenceDigest,
			SecondCopyDigest:       proof.SecondCopyDigest,
			MutationAbsent:         proof.MutationAbsent,
			SharedSeedPathAbsent:   proof.SharedSeedPathAbsent,
		}
	case "seed-source-immutable":
		assertions = 3
		payload = struct {
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
			SourceDigest           string `json:"source_digest"`
			SourcePostDigest       string `json:"source_post_digest"`
			SourceImmutable        bool   `json:"source_immutable"`
		}{
			PreparedEvidenceDigest: preparedEvidenceDigest,
			SourceDigest:           proof.SourceDigest,
			SourcePostDigest:       proof.SourcePostDigest,
			SourceImmutable:        proof.SourceImmutable,
		}
	case "seed-workspaces-reclaimed":
		assertions = 5
		payload = struct {
			PreparedEvidenceDigest   string `json:"prepared_evidence_digest"`
			HostBackedWorkAbsent     bool   `json:"host_backed_work_absent"`
			SharedSeedPathAbsent     bool   `json:"shared_seed_path_absent"`
			FirstWorkspaceReclaimed  bool   `json:"first_workspace_reclaimed"`
			SecondWorkspaceReclaimed bool   `json:"second_workspace_reclaimed"`
			WorkspacesReclaimed      bool   `json:"workspaces_reclaimed"`
		}{
			PreparedEvidenceDigest:   preparedEvidenceDigest,
			HostBackedWorkAbsent:     proof.HostBackedWorkAbsent,
			SharedSeedPathAbsent:     proof.SharedSeedPathAbsent,
			FirstWorkspaceReclaimed:  proof.FirstWorkspaceReclaimed,
			SecondWorkspaceReclaimed: proof.SecondWorkspaceReclaimed,
			WorkspacesReclaimed:      proof.WorkspacesReclaimed,
		}
	default:
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		requirement,
		assertions,
		nil,
		payload,
	)
}

var _ matrixObservationSource = (*seedIsolationMatrixSource)(nil)
