package conformance

import (
	"context"
	"errors"
)

var (
	ErrAcquisitionConformanceUnavailable = errors.New(
		"conformance: acquisition proof unavailable",
	)
	ErrAcquisitionConformanceMismatch = errors.New(
		"conformance: acquisition proof binding mismatch",
	)
)

// AcquisitionMode is the closed production authority requested from one
// immutable conformance report. Disabled observation never uses this port.
type AcquisitionMode string

const (
	AcquisitionCanaryOnly AcquisitionMode = "canary-only"
	AcquisitionEnabled    AcquisitionMode = "enabled"
)

// AcquisitionConformanceRequest binds one active acquisition decision to the
// exact build, host profile, and fleet generation proven by the report.
type AcquisitionConformanceRequest struct {
	BuildID         string
	HostProfileID   string
	FleetGeneration uint64
	Mode            AcquisitionMode
}

// AcquisitionConformance is the sole neutral production consumer of a fully
// passing conformance report.
type AcquisitionConformance interface {
	Verify(context.Context, AcquisitionConformanceRequest) error
}

type acquisitionGate struct {
	report Report
}

type unavailableAcquisitionGate struct{}

// NewAcquisitionGate creates active acquisition authority only from a fully
// passing, internally self-consistent report. There is no pending, source-only,
// digest-only, warning, force, or development constructor.
func NewAcquisitionGate(report Report) (AcquisitionConformance, error) {
	if err := validatePassingReport(report); err != nil {
		return nil, ErrAcquisitionConformanceUnavailable
	}
	return acquisitionGate{report: report}, nil
}

// NewUnavailableAcquisitionGate returns an explicit fail-closed composition
// for disabled-only or test services.
func NewUnavailableAcquisitionGate() AcquisitionConformance {
	return unavailableAcquisitionGate{}
}

func (g acquisitionGate) Verify(
	ctx context.Context,
	request AcquisitionConformanceRequest,
) error {
	if ctx == nil {
		return ErrAcquisitionConformanceMismatch
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePassingReport(g.report); err != nil {
		return ErrAcquisitionConformanceUnavailable
	}
	binding := g.report.Binding()
	if (request.Mode != AcquisitionCanaryOnly &&
		request.Mode != AcquisitionEnabled) ||
		request.BuildID != binding.BuildID() ||
		request.HostProfileID != binding.ProfileID() ||
		request.FleetGeneration != binding.FleetGeneration() {
		return ErrAcquisitionConformanceMismatch
	}
	return nil
}

func (unavailableAcquisitionGate) Verify(
	context.Context,
	AcquisitionConformanceRequest,
) error {
	return ErrAcquisitionConformanceUnavailable
}

func validatePassingReport(report Report) error {
	if validateReport(report) != nil ||
		report.Status() != StatusPassed ||
		report.Failure() != FailureNone {
		return ErrAcquisitionConformanceUnavailable
	}
	cases := report.Cases()
	if len(cases) != len(requiredCaseRegistry) {
		return ErrAcquisitionConformanceUnavailable
	}
	for index, definition := range requiredCaseRegistry {
		evidence := cases[index]
		if evidence.ID() != definition.id ||
			evidence.Layer() != definition.layer ||
			evidence.Status() != StatusPassed ||
			evidence.Failure() != FailureNone ||
			evidence.AssertionCount() == 0 {
			return ErrAcquisitionConformanceUnavailable
		}
	}
	actualGitHub := cases[len(cases)-1]
	if actualGitHub.ID() != CaseActualGitHubTransport ||
		actualGitHub.Layer() != LayerActualGitHubTransport {
		return ErrAcquisitionConformanceUnavailable
	}
	cleanup := report.Cleanup()
	if cleanup.Status() != StatusPassed ||
		cleanup.Failure() != FailureNone ||
		cleanup.AssertionCount() == 0 {
		return ErrAcquisitionConformanceUnavailable
	}
	return nil
}
