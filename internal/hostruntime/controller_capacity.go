package hostruntime

import (
	"context"
	"fmt"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

// ControllerCapacityConfig binds one already-selected host profile to the
// controller's narrow recurring-pressure port. The profile remains the sole
// owner of raw observations.
type ControllerCapacityConfig struct {
	Profile Profile
	Now     func() time.Time
}

type ControllerCapacityProvider struct {
	profile Profile
	now     func() time.Time
}

var _ controller.HostCapacityProvider = (*ControllerCapacityProvider)(nil)

func NewControllerCapacityProvider(
	config ControllerCapacityConfig,
) (*ControllerCapacityProvider, error) {
	if config.Profile == nil || config.Now == nil ||
		!validHostProfile(config.Profile.ID()) {
		return nil, ErrInvalidHostProfile
	}
	return &ControllerCapacityProvider{
		profile: config.Profile,
		now:     config.Now,
	}, nil
}

func (p *ControllerCapacityProvider) Evaluate(
	ctx context.Context,
) (controller.HostCapacityReport, error) {
	if p == nil || p.profile == nil || p.now == nil {
		return controller.HostCapacityReport{}, ErrInvalidHostProfile
	}
	if err := ctx.Err(); err != nil {
		return controller.HostCapacityReport{}, err
	}
	report, err := p.profile.Probe(ctx)
	if err != nil {
		return controller.HostCapacityReport{}, fmt.Errorf(
			"%w: recurring probe: %w",
			ErrInvalidHostProfile,
			err,
		)
	}
	if err := ValidateConformanceReport(report); err != nil ||
		report.ProfileID != p.profile.ID() ||
		uint64(report.EffectiveCapacity) > uint64(^uint(0)>>1) {
		return controller.HostCapacityReport{}, ErrInvalidHostProfile
	}
	state := controller.HostCapacityNormal
	switch report.State {
	case ProfileNormal, ProfileDegraded:
	case ProfileWarning:
		state = controller.HostCapacityWarning
	case ProfileStop:
		state = controller.HostCapacityStop
	default:
		return controller.HostCapacityReport{}, ErrInvalidHostProfile
	}
	observedAt := p.now().UTC()
	if observedAt.IsZero() {
		return controller.HostCapacityReport{}, ErrInvalidHostProfile
	}
	return controller.HostCapacityReport{
		State:             state,
		EffectiveCapacity: int(report.EffectiveCapacity),
		EvidenceDigest:    report.EvidenceDigest,
		ObservedAt:        observedAt,
	}, nil
}
