package main

import (
	"context"
	"errors"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

var errProductionEnabledUnavailable = errors.New(
	"portable-ghar-controller: enabled acquisition requires production hosted and replay adapters",
)

// productionCanaryConformance preserves the report's exact authority while
// limiting this production composition to the approved D6 canary. A full case
// 15 pass proves target conformance; it does not implement the hosted/replay
// adapters that are still unavailable in openProductionAcquisitionController.
// Keep the restriction at the service's existing gate so direct transitions,
// startup recovery, and active-operation rechecks cannot bypass it.
type productionCanaryConformance struct {
	report conformance.AcquisitionConformance
}

func (gate productionCanaryConformance) Verify(
	ctx context.Context,
	request conformance.AcquisitionConformanceRequest,
) error {
	if ctx == nil {
		return conformance.ErrAcquisitionConformanceMismatch
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.Mode == conformance.AcquisitionEnabled {
		return errProductionEnabledUnavailable
	}
	if gate.report == nil {
		return conformance.ErrAcquisitionConformanceUnavailable
	}
	return gate.report.Verify(ctx, request)
}
