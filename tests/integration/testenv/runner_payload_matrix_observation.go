package testenv

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type runnerPayloadRuntimeObservation struct {
	SinglePayload          bool
	SinglePayloadDigest    string
	ListenerVersionMatches bool
	ListenerVersionDigest  string
	NoVersionPair          bool
	NoVersionPairDigest    string
	NoFileSweeper          bool
	NoFileSweeperDigest    string
	NoBakedJIT             bool
	NoBakedJITDigest       string
}

type runnerPayloadRuntime interface {
	RunnerPayloadObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (runnerPayloadRuntimeObservation, error)
}

type runnerPayloadMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      runnerPayloadRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

func newRunnerPayloadMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime runnerPayloadRuntime,
) (*runnerPayloadMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseRunnerPayload {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 5 {
		return nil, ErrFixtureStart
	}
	return &runnerPayloadMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *runnerPayloadMatrixSource) Observe(
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
		!s.ledger.freezeCase6() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *runnerPayloadMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase5()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	runtimeObservation, err := s.runtime.RunnerPayloadObservation(
		ctx,
		prepared,
	)
	if err != nil ||
		!validRunnerPayloadRuntimeObservation(runtimeObservation) {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := runnerPayloadMatrixObservation(
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

func validRunnerPayloadRuntimeObservation(
	observation runnerPayloadRuntimeObservation,
) bool {
	return observation.SinglePayload &&
		isLowerHex(observation.SinglePayloadDigest, sha256.Size*2) &&
		observation.ListenerVersionMatches &&
		isLowerHex(
			observation.ListenerVersionDigest,
			sha256.Size*2,
		) &&
		observation.NoVersionPair &&
		isLowerHex(observation.NoVersionPairDigest, sha256.Size*2) &&
		observation.NoFileSweeper &&
		isLowerHex(observation.NoFileSweeperDigest, sha256.Size*2) &&
		observation.NoBakedJIT &&
		isLowerHex(observation.NoBakedJITDigest, sha256.Size*2)
}

func runnerPayloadMatrixObservation(
	requirement ObservationRequirement,
	prepared fixtureRuntimeObservation,
	runtime runnerPayloadRuntimeObservation,
) (matrixObservation, error) {
	binding := struct {
		Runtime          brokerEvidenceBinding `json:"runtime"`
		RunnerSpecDigest string                `json:"runner_spec_digest"`
		RunnerAudit      string                `json:"runner_audit_digest"`
	}{
		Runtime: brokerEvidenceBinding{
			AdapterID:                    prepared.Adapter.id,
			BrokerID:                     prepared.Broker.id,
			RunnerID:                     prepared.Runner.id,
			PolicyDigest:                 prepared.PolicyDigest,
			PreparedEvidenceDigest:       prepared.PreparedEvidenceDigest,
			ProbeMembershipDigest:        prepared.ProbeMembershipDigest,
			PreparedProbeBindingDigest:   prepared.PreparedProbeBindingDigest,
			PermitUsageDigest:            prepared.PermitUsageDigest,
			PermitAuthorityBindingDigest: prepared.PermitAuthorityBindingDigest,
			NetworkEgressDigest:          prepared.NetworkEgressDigest,
			BrokerAuditDigest:            prepared.BrokerAuditDigest,
			RunnerAuditDigest:            prepared.RunnerAuditDigest,
			HeldSocketZeroDigest:         prepared.HeldSocketZeroDigest,
			BrokerReleaseDigest:          prepared.BrokerReleaseDigest,
			ReleaseAuthorizationReceipt:  prepared.ReleaseAuthorizationReceipt,
			ProbeReport:                  prepared.ProbeReport,
		},
		RunnerSpecDigest: prepared.RunnerSpecDigest,
		RunnerAudit:      prepared.RunnerAuditDigest,
	}
	var (
		assertions uint64
		passed     bool
		digest     string
	)
	switch requirement.ID {
	case "single-runner-payload":
		assertions = 1
		passed = runtime.SinglePayload
		digest = runtime.SinglePayloadDigest
	case "listener-version":
		assertions = 1
		passed = runtime.ListenerVersionMatches
		digest = runtime.ListenerVersionDigest
	case "no-version-pair":
		assertions = 2
		passed = runtime.NoVersionPair
		digest = runtime.NoVersionPairDigest
	case "no-file-sweeper":
		assertions = 2
		passed = runtime.NoFileSweeper
		digest = runtime.NoFileSweeperDigest
	case "no-baked-jit":
		assertions = 3
		passed = runtime.NoBakedJIT
		digest = runtime.NoBakedJITDigest
	default:
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		requirement,
		assertions,
		nil,
		struct {
			Binding any    `json:"binding"`
			Passed  bool   `json:"passed"`
			Digest  string `json:"digest"`
		}{
			Binding: binding,
			Passed:  passed,
			Digest:  digest,
		},
	)
}

var _ matrixObservationSource = (*runnerPayloadMatrixSource)(nil)
