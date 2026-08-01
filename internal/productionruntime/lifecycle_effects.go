package productionruntime

import (
	"context"
	"errors"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

var ErrLifecycleEffects = errors.New(
	"productionruntime: lifecycle effect failed",
)

// LifecyclePhaseBackend exposes one typed phase effect. It cannot receive a
// command, argv, environment, stdin, or arbitrary operation name.
type LifecyclePhaseBackend interface {
	ObservePhase(
		context.Context,
		hostruntime.OperationBinding,
		hostruntime.OperationPhase,
	) (hostruntime.LifecycleEffectObservation, error)
	ApplyPhase(
		context.Context,
		hostruntime.OperationBinding,
		hostruntime.OperationPhase,
	) error
}

// LifecycleEffects is the single production adapter from the host lifecycle
// engine to fixed, phase-scoped target effects.
type LifecycleEffects struct {
	backend LifecyclePhaseBackend
}

func NewLifecycleEffects(
	backend LifecyclePhaseBackend,
) (*LifecycleEffects, error) {
	if backend == nil {
		return nil, ErrLifecycleEffects
	}
	return &LifecycleEffects{backend: backend}, nil
}

func (effects *LifecycleEffects) Observe(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) (hostruntime.LifecycleEffectObservation, error) {
	if effects == nil ||
		effects.backend == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		!lifecyclePhaseAllowed(binding, phase) {
		return hostruntime.LifecycleEffectObservation{},
			ErrLifecycleEffects
	}
	observation, err := effects.backend.ObservePhase(ctx, binding, phase)
	if err != nil ||
		validateLifecycleEffectObservation(
			observation,
			binding,
			phase,
		) != nil {
		return hostruntime.LifecycleEffectObservation{},
			errors.Join(ErrLifecycleEffects, err)
	}
	return observation, nil
}

func (effects *LifecycleEffects) Apply(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) (hostruntime.TargetPostcondition, error) {
	before, err := effects.Observe(ctx, binding, phase)
	if err != nil {
		return hostruntime.TargetPostcondition{}, err
	}
	switch before.State {
	case hostruntime.LifecycleEffectPresent:
		return *before.Postcondition, nil
	case hostruntime.LifecycleEffectAbsent:
	case hostruntime.LifecycleEffectAmbiguous:
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	default:
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	}

	if err := effects.backend.ApplyPhase(ctx, binding, phase); err != nil {
		return hostruntime.TargetPostcondition{},
			errors.Join(ErrLifecycleEffects, err)
	}
	after, err := effects.Observe(ctx, binding, phase)
	if err != nil ||
		after.State != hostruntime.LifecycleEffectPresent ||
		after.Postcondition == nil {
		return hostruntime.TargetPostcondition{},
			errors.Join(ErrLifecycleEffects, err)
	}
	return *after.Postcondition, nil
}

func lifecyclePhaseAllowed(
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) bool {
	_, err := hostruntime.DeriveOperationEffectKey(binding, phase)
	return err == nil
}

func validateLifecycleEffectObservation(
	observation hostruntime.LifecycleEffectObservation,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) error {
	switch observation.State {
	case hostruntime.LifecycleEffectAbsent,
		hostruntime.LifecycleEffectAmbiguous:
		if observation.Postcondition != nil {
			return ErrLifecycleEffects
		}
		return nil
	case hostruntime.LifecycleEffectPresent:
		if observation.Postcondition == nil ||
			hostruntime.ValidateTargetPostconditionAgainstBinding(
				*observation.Postcondition,
				binding,
				phase,
			) != nil {
			return ErrLifecycleEffects
		}
		return nil
	default:
		return ErrLifecycleEffects
	}
}

var _ hostruntime.LifecycleEffectAuthority = (*LifecycleEffects)(nil)
