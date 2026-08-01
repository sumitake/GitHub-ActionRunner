package testenv

import (
	"context"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type executionIdentityMatrixSource struct {
	target      TargetBinding
	observed    string
	requirement ObservationRequirement

	mu       sync.Mutex
	consumed bool
}

func newExecutionIdentityMatrixSource(
	target TargetBinding,
	observedDigest string,
) (*executionIdentityMatrixSource, error) {
	if !validateTarget(target) ||
		observedDigest != target.HostIdentityDigest {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.ID == "host-execution-identity" {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 1 ||
		requirements[0].Case != conformance.CaseHostProfile ||
		requirements[0].Source != SourceClosedTestCommand {
		return nil, ErrFixtureStart
	}
	return &executionIdentityMatrixSource{
		target:      target,
		observed:    observedDigest,
		requirement: requirements[0],
	}, nil
}

func (s *executionIdentityMatrixSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed ||
		requirement != s.requirement ||
		s.observed != s.target.HostIdentityDigest ||
		s.target.HostIdentityDigest ==
			s.target.ControlHostIdentityDigest {
		return matrixObservation{}, conformance.ErrObservation
	}
	observation, err := sealTypedMatrixObservation(
		requirement,
		3,
		nil,
		struct {
			OperatingSystem       string `json:"operating_system"`
			Architecture          string `json:"architecture"`
			EUID                  uint32 `json:"euid"`
			ProfileID             string `json:"profile_id"`
			TargetIdentityDigest  string `json:"target_identity_digest"`
			ControlIdentityDigest string `json:"control_identity_digest"`
			Separated             bool   `json:"separated"`
		}{
			OperatingSystem:       s.target.OperatingSystem,
			Architecture:          s.target.Architecture,
			EUID:                  s.target.ExpectedEUID,
			ProfileID:             s.target.ProfileID,
			TargetIdentityDigest:  s.observed,
			ControlIdentityDigest: s.target.ControlHostIdentityDigest,
			Separated:             s.target.IdentitySeparationRequired,
		},
	)
	if err != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.consumed = true
	return observation, nil
}

var _ matrixObservationSource = (*executionIdentityMatrixSource)(nil)
