package controller

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrHostPressure = errors.New("controller: host capacity unavailable")

type HostCapacityState uint8

const (
	HostCapacityNormal HostCapacityState = iota + 1
	HostCapacityWarning
	HostCapacityStop
)

type HostCapacityReport struct {
	State             HostCapacityState
	EffectiveCapacity int
	EvidenceDigest    string
	ObservedAt        time.Time
}

type HostCapacityProvider interface {
	Evaluate(context.Context) (HostCapacityReport, error)
}

// EvaluateHostPressure rereads the selected profile's current typed pressure
// projection. It can only retain or reduce capacity; healthy observations
// never restore capacity without a separate operator policy transition.
func (s *Service) EvaluateHostPressure(
	ctx context.Context,
) (HostCapacityReport, error) {
	current, ready := s.policySnapshot()
	if !ready {
		return HostCapacityReport{}, ErrServiceNotReady
	}
	report, err := s.hostCapacity.Evaluate(ctx)
	if err != nil {
		return HostCapacityReport{}, s.failHostPressure(
			ctx,
			fmt.Errorf("evaluate: %w", err),
		)
	}
	if err := s.validateHostCapacityReport(report); err != nil {
		return HostCapacityReport{}, s.failHostPressure(ctx, err)
	}
	if report.State == HostCapacityStop {
		return HostCapacityReport{}, s.failHostPressure(
			ctx,
			errors.New("stop pressure"),
		)
	}
	target := current.MaxCapacity
	if report.EffectiveCapacity < target {
		target = report.EffectiveCapacity
	}
	if target < current.MaxCapacity {
		if err := s.applyPressure(ctx, target); err != nil {
			return HostCapacityReport{}, fmt.Errorf(
				"%w: lower capacity: %w",
				ErrHostPressure,
				err,
			)
		}
	}
	return report, nil
}

func (s *Service) validateHostCapacityReport(report HostCapacityReport) error {
	now := s.now()
	if report.ObservedAt.IsZero() ||
		report.ObservedAt.After(now) ||
		now.Sub(report.ObservedAt) > s.hostCapacityMaxAge ||
		!isLowerHexDigest(report.EvidenceDigest) {
		return errors.New("invalid or stale report")
	}
	switch report.State {
	case HostCapacityNormal, HostCapacityWarning:
		if report.EffectiveCapacity <= 0 {
			return errors.New("invalid positive capacity")
		}
	case HostCapacityStop:
		if report.EffectiveCapacity != 0 {
			return errors.New("invalid stop capacity")
		}
	default:
		return errors.New("invalid state")
	}
	return nil
}

func (s *Service) failHostPressure(ctx context.Context, cause error) error {
	pressureErr := s.applyPressure(ctx, 0)
	if pressureErr != nil {
		return errors.Join(
			fmt.Errorf("%w: %v", ErrHostPressure, cause),
			pressureErr,
		)
	}
	return fmt.Errorf("%w: %v", ErrHostPressure, cause)
}

func isLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
