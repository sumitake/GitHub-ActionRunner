package testenv

import (
	"context"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type cleanupMatrixRuntimeObservation struct {
	Success             CompleteCleanupProof
	Cancellation        CompleteCleanupProof
	PreListenerFailure  CompleteCleanupProof
	ListenerCrash       CompleteCleanupProof
	ControllerRestart   CompleteCleanupProof
	UpgradeInterruption CompleteCleanupProof
}

type cleanupMatrixRuntime interface {
	CleanupMatrixObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (cleanupMatrixRuntimeObservation, error)
}

type cleanupMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      cleanupMatrixRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

type cleanupRowPayload struct {
	PreparedEvidenceDigest  string `json:"prepared_evidence_digest"`
	ContainersAbsent        bool   `json:"containers_absent"`
	CgroupsAbsent           bool   `json:"cgroups_absent"`
	TmpfsAbsent             bool   `json:"tmpfs_absent"`
	WorkAbsent              bool   `json:"work_absent"`
	WorkUpdateAbsent        bool   `json:"work_update_absent"`
	ProcessesAbsent         bool   `json:"processes_absent"`
	NamespacesAbsent        bool   `json:"namespaces_absent"`
	SocketsAbsent           bool   `json:"sockets_absent"`
	AuthoritiesAbsent       bool   `json:"authorities_absent"`
	TemporaryFilesAbsent    bool   `json:"temporary_files_absent"`
	HostBackedWorkAbsent    bool   `json:"host_backed_work_absent"`
	UnexpectedObjectsAbsent bool   `json:"unexpected_objects_absent"`
	PayloadVersionCount     uint64 `json:"payload_version_count"`
	ObservationDigest       string `json:"observation_digest"`
}

func newCleanupMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime cleanupMatrixRuntime,
) (*cleanupMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseCleanupMatrix {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 6 {
		return nil, ErrFixtureStart
	}
	return &cleanupMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *cleanupMatrixSource) Observe(
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
		!s.ledger.freezeCase8() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *cleanupMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase7()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	runtimeObservation, err := s.runtime.CleanupMatrixObservation(
		ctx,
		prepared,
	)
	if err != nil {
		return nil, conformance.ErrObservation
	}
	proofs := [...]CompleteCleanupProof{
		runtimeObservation.Success,
		runtimeObservation.Cancellation,
		runtimeObservation.PreListenerFailure,
		runtimeObservation.ListenerCrash,
		runtimeObservation.ControllerRestart,
		runtimeObservation.UpgradeInterruption,
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for index, requirement := range s.requirements {
		proof := proofs[index]
		if _, err := SealCompleteCleanup(proof); err != nil {
			return nil, conformance.ErrObservation
		}
		observation, err := sealTypedMatrixObservation(
			requirement,
			proof.AssertionCount,
			nil,
			cleanupRowPayloadFrom(
				prepared.PreparedEvidenceDigest,
				proof,
			),
		)
		if err != nil {
			return nil, conformance.ErrObservation
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func cleanupRowPayloadFrom(
	preparedEvidenceDigest string,
	proof CompleteCleanupProof,
) cleanupRowPayload {
	return cleanupRowPayload{
		PreparedEvidenceDigest:  preparedEvidenceDigest,
		ContainersAbsent:        proof.ContainersAbsent,
		CgroupsAbsent:           proof.CgroupsAbsent,
		TmpfsAbsent:             proof.TmpfsAbsent,
		WorkAbsent:              proof.WorkAbsent,
		WorkUpdateAbsent:        proof.WorkUpdateAbsent,
		ProcessesAbsent:         proof.ProcessesAbsent,
		NamespacesAbsent:        proof.NamespacesAbsent,
		SocketsAbsent:           proof.SocketsAbsent,
		AuthoritiesAbsent:       proof.AuthoritiesAbsent,
		TemporaryFilesAbsent:    proof.TemporaryFilesAbsent,
		HostBackedWorkAbsent:    proof.HostBackedWorkAbsent,
		UnexpectedObjectsAbsent: proof.UnexpectedObjectsAbsent,
		PayloadVersionCount:     proof.PayloadVersionCount,
		ObservationDigest:       proof.ObservationDigest,
	}
}

var _ matrixObservationSource = (*cleanupMatrixSource)(nil)
