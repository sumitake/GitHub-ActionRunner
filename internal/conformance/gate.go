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

// AcquisitionConformance is the sole neutral production consumer of a
// conformance report.
type AcquisitionConformance interface {
	Verify(context.Context, AcquisitionConformanceRequest) error
}

type acquisitionGate struct {
	report Report
}

type unavailableAcquisitionGate struct{}

// NewAcquisitionGate creates active acquisition authority from an internally
// self-consistent report. A fully passing report allows every active mode. A
// report whose cases 1-14 passed and whose case 15, the actual GitHub
// transport, is still pending allows canary-only: case 15 can only pass
// during a canary that acquires a real job. Every other report is refused.
// There is no source-only, digest-only, warning, force, or development
// constructor.
func NewAcquisitionGate(report Report) (AcquisitionConformance, error) {
	if _, err := reportAuthority(report); err != nil {
		return nil, ErrAcquisitionConformanceUnavailable
	}
	return acquisitionGate{report: report}, nil
}

// RequireFullPass accepts only a fully passing, internally self-consistent
// report: every case, case 15 included, and cleanup passed. Anything that
// needs proof of the whole target, not canary authority, uses this.
func RequireFullPass(report Report) error {
	allowed, err := reportAuthority(report)
	if err != nil || allowed != AcquisitionEnabled {
		return ErrAcquisitionConformanceUnavailable
	}
	return nil
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
	allowed, err := reportAuthority(g.report)
	if err != nil {
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
	if request.Mode == AcquisitionEnabled && allowed != AcquisitionEnabled {
		return ErrAcquisitionConformanceUnavailable
	}
	return nil
}

func (unavailableAcquisitionGate) Verify(
	context.Context,
	AcquisitionConformanceRequest,
) error {
	return ErrAcquisitionConformanceUnavailable
}

// reportAuthority returns the most active authority a report allows:
// AcquisitionEnabled for a full pass, AcquisitionCanaryOnly when only case 15
// is pending, and an error for anything else.
func reportAuthority(report Report) (AcquisitionMode, error) {
	if validateReport(report) != nil {
		return "", ErrAcquisitionConformanceUnavailable
	}
	var full bool
	switch {
	case report.Status() == StatusPassed && report.Failure() == FailureNone:
		full = true
	case report.Status() == StatusPending &&
		report.Failure() == FailureActualProofPending:
		full = false
	default:
		return "", ErrAcquisitionConformanceUnavailable
	}
	cases := report.Cases()
	if len(cases) != len(requiredCaseRegistry) {
		return "", ErrAcquisitionConformanceUnavailable
	}
	last := len(cases) - 1
	for index, definition := range requiredCaseRegistry {
		evidence := cases[index]
		if evidence.ID() != definition.id ||
			evidence.Layer() != definition.layer {
			return "", ErrAcquisitionConformanceUnavailable
		}
		// validateReport already pins a pending report's case 15 to the fixed
		// pending evidence and allows no other pending case.
		if index == last && !full {
			continue
		}
		if evidence.Status() != StatusPassed ||
			evidence.Failure() != FailureNone ||
			evidence.AssertionCount() == 0 {
			return "", ErrAcquisitionConformanceUnavailable
		}
	}
	if cases[last].ID() != CaseActualGitHubTransport ||
		cases[last].Layer() != LayerActualGitHubTransport {
		return "", ErrAcquisitionConformanceUnavailable
	}
	cleanup := report.Cleanup()
	if cleanup.Status() != StatusPassed ||
		cleanup.Failure() != FailureNone ||
		cleanup.AssertionCount() == 0 {
		return "", ErrAcquisitionConformanceUnavailable
	}
	if full {
		return AcquisitionEnabled, nil
	}
	return AcquisitionCanaryOnly, nil
}
