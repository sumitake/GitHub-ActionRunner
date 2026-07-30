package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

var ErrAcquisitionConformance = errors.New(
	"controller: acquisition conformance unavailable",
)

func (s *Service) verifyAcquisitionConformance(
	ctx context.Context,
	mode AcquisitionMode,
) error {
	if mode == AcquisitionDisabled || mode == AcquisitionFatal {
		return nil
	}
	var requested conformance.AcquisitionMode
	switch mode {
	case AcquisitionCanaryOnly:
		requested = conformance.AcquisitionCanaryOnly
	case AcquisitionEnabled:
		requested = conformance.AcquisitionEnabled
	default:
		return ErrAcquisitionConformance
	}
	if s.conformance == nil || s.fleetGeneration == 0 {
		return ErrAcquisitionConformance
	}
	if err := s.conformance.Verify(
		ctx,
		conformance.AcquisitionConformanceRequest{
			BuildID:         s.buildID,
			HostProfileID:   s.hostProfileID,
			FleetGeneration: s.fleetGeneration,
			Mode:            requested,
		},
	); err != nil {
		return fmt.Errorf("%w: %w", ErrAcquisitionConformance, err)
	}
	return nil
}

// recheckActiveConformance runs before every operation capable of acquiring,
// admitting, or releasing listener authority. Losing proof in an active epoch
// uses the existing durable fatal transition, which closes and joins the epoch,
// revokes pre-running work, and publishes zero capacity before termination.
func (s *Service) recheckActiveConformance(ctx context.Context) error {
	policy, ready := s.policySnapshot()
	if !ready {
		return ErrServiceNotReady
	}
	if err := s.verifyAcquisitionConformance(ctx, policy.Mode); err != nil {
		if policy.Mode == AcquisitionCanaryOnly ||
			policy.Mode == AcquisitionEnabled {
			return s.enterFatal(ReasonAcquisitionResult, err)
		}
		return err
	}
	return nil
}
