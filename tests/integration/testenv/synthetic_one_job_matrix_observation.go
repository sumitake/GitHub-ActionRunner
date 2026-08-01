package testenv

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type syntheticOneJobRuntimeObservation struct {
	JobCompleted         bool
	JobCompletionDigest  string
	ProxyRequestComplete bool
	ProxyRequestDigest   string
	Deregistered         bool
	DeregistrationDigest string
	Reclaimed            bool
	ReclamationDigest    string
}

type syntheticOneJobRuntime interface {
	SyntheticOneJobObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (syntheticOneJobRuntimeObservation, error)
}

type syntheticOneJobMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      syntheticOneJobRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

func newSyntheticOneJobMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime syntheticOneJobRuntime,
) (*syntheticOneJobMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSyntheticOneJob {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 4 {
		return nil, ErrFixtureStart
	}
	return &syntheticOneJobMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *syntheticOneJobMatrixSource) Observe(
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
		!s.ledger.freezeCase7() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *syntheticOneJobMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase6()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	runtimeObservation, err := s.runtime.SyntheticOneJobObservation(
		ctx,
		prepared,
	)
	if err != nil ||
		!validSyntheticOneJobRuntimeObservation(runtimeObservation) {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := syntheticOneJobMatrixObservation(
			requirement,
			prepared,
			runtimeObservation,
		)
		if err != nil {
			return nil, conformance.ErrObservation
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func validSyntheticOneJobRuntimeObservation(
	observation syntheticOneJobRuntimeObservation,
) bool {
	return observation.JobCompleted &&
		isLowerHex(observation.JobCompletionDigest, sha256.Size*2) &&
		observation.ProxyRequestComplete &&
		isLowerHex(observation.ProxyRequestDigest, sha256.Size*2) &&
		observation.Deregistered &&
		isLowerHex(observation.DeregistrationDigest, sha256.Size*2) &&
		observation.Reclaimed &&
		isLowerHex(observation.ReclamationDigest, sha256.Size*2)
}

func syntheticOneJobMatrixObservation(
	requirement ObservationRequirement,
	prepared fixtureRuntimeObservation,
	runtime syntheticOneJobRuntimeObservation,
) (matrixObservation, error) {
	var (
		assertions uint64
		passed     bool
		digest     string
	)
	switch requirement.ID {
	case "synthetic-job-completion":
		assertions = 2
		passed = runtime.JobCompleted
		digest = runtime.JobCompletionDigest
	case "synthetic-job-proxy":
		assertions = 2
		passed = runtime.ProxyRequestComplete
		digest = runtime.ProxyRequestDigest
	case "synthetic-job-deregistration":
		assertions = 2
		passed = runtime.Deregistered
		digest = runtime.DeregistrationDigest
	case "synthetic-job-reclamation":
		assertions = 8
		passed = runtime.Reclaimed
		digest = runtime.ReclamationDigest
	default:
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		requirement,
		assertions,
		nil,
		struct {
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
			RunnerSpecDigest       string `json:"runner_spec_digest"`
			ProbeBindingDigest     string `json:"probe_binding_digest"`
			Passed                 bool   `json:"passed"`
			Digest                 string `json:"digest"`
		}{
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
			RunnerSpecDigest:       prepared.RunnerSpecDigest,
			ProbeBindingDigest:     prepared.PreparedProbeBindingDigest,
			Passed:                 passed,
			Digest:                 digest,
		},
	)
}

var _ matrixObservationSource = (*syntheticOneJobMatrixSource)(nil)
