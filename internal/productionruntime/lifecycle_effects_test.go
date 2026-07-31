package productionruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestLifecycleEffectsRejectsPhaseOutsideBinding(t *testing.T) {
	t.Parallel()

	binding := lifecycleEffectsBinding(t)
	backend := newFakeLifecyclePhaseBackend(binding)
	effects, err := NewLifecycleEffects(backend)
	if err != nil {
		t.Fatalf("NewLifecycleEffects() error = %v", err)
	}

	if _, err := effects.Observe(
		context.Background(),
		binding,
		hostruntime.OperationPhaseLegacyNormalizedProven,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("Observe(disallowed) error = %v", err)
	}
	if _, err := effects.Apply(
		context.Background(),
		binding,
		hostruntime.OperationPhaseLegacyNormalizedProven,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("Apply(disallowed) error = %v", err)
	}
	if backend.observeCalls != 0 || backend.applyCalls != 0 {
		t.Fatalf(
			"disallowed phase reached backend: observe=%d apply=%d",
			backend.observeCalls,
			backend.applyCalls,
		)
	}
}

func TestLifecycleEffectsAppliesOnceAndRequiresReadback(t *testing.T) {
	t.Parallel()

	binding := lifecycleEffectsBinding(t)
	phase := hostruntime.OperationPhasePrepared
	backend := newFakeLifecyclePhaseBackend(binding)
	backend.afterApply = lifecycleEffectsPostcondition(t, binding, phase, 1)
	effects, err := NewLifecycleEffects(backend)
	if err != nil {
		t.Fatalf("NewLifecycleEffects() error = %v", err)
	}

	first, err := effects.Apply(context.Background(), binding, phase)
	if err != nil {
		t.Fatalf("Apply(first) error = %v", err)
	}
	second, err := effects.Apply(context.Background(), binding, phase)
	if err != nil {
		t.Fatalf("Apply(replay) error = %v", err)
	}
	if backend.applyCalls != 1 {
		t.Fatalf("backend Apply calls = %d, want 1", backend.applyCalls)
	}
	if !sameLifecycleEffectsState(first, second) {
		t.Fatalf("replay changed state:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if backend.observeCalls != 3 {
		t.Fatalf("backend Observe calls = %d, want 3", backend.observeCalls)
	}
}

func TestLifecycleEffectsNeverAcceptsUnprovenApply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*fakeLifecyclePhaseBackend, hostruntime.OperationBinding)
	}{
		{
			name: "absent-after-apply",
			mutate: func(
				backend *fakeLifecyclePhaseBackend,
				_ hostruntime.OperationBinding,
			) {
				backend.keepAbsent = true
			},
		},
		{
			name: "ambiguous-after-apply",
			mutate: func(
				backend *fakeLifecyclePhaseBackend,
				_ hostruntime.OperationBinding,
			) {
				backend.ambiguousAfterApply = true
			},
		},
		{
			name: "wrong-binding-after-apply",
			mutate: func(
				backend *fakeLifecyclePhaseBackend,
				binding hostruntime.OperationBinding,
			) {
				wrong := backend.afterApply
				wrong.OperationID = strings.Repeat("f", 64)
				backend.afterApply = wrong
			},
		},
		{
			name: "apply-error-even-if-present",
			mutate: func(
				backend *fakeLifecyclePhaseBackend,
				_ hostruntime.OperationBinding,
			) {
				backend.applyErr = errors.New("effect failed after mutation")
				backend.publishOnApplyError = true
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding := lifecycleEffectsBinding(t)
			phase := hostruntime.OperationPhasePrepared
			backend := newFakeLifecyclePhaseBackend(binding)
			backend.afterApply = lifecycleEffectsPostcondition(
				t,
				binding,
				phase,
				1,
			)
			test.mutate(backend, binding)
			effects, err := NewLifecycleEffects(backend)
			if err != nil {
				t.Fatalf("NewLifecycleEffects() error = %v", err)
			}

			if _, err := effects.Apply(
				context.Background(),
				binding,
				phase,
			); !errors.Is(err, ErrLifecycleEffects) {
				t.Fatalf("Apply() error = %v", err)
			}
		})
	}
}

func TestLifecycleEffectsObserveValidatesClosedObservation(t *testing.T) {
	t.Parallel()

	binding := lifecycleEffectsBinding(t)
	phase := hostruntime.OperationPhasePrepared
	tests := []hostruntime.LifecycleEffectObservation{
		{},
		{
			State: hostruntime.LifecycleEffectAbsent,
			Postcondition: lifecycleEffectsPostconditionPointer(
				t,
				binding,
				phase,
				1,
			),
		},
		{
			State: hostruntime.LifecycleEffectAmbiguous,
			Postcondition: lifecycleEffectsPostconditionPointer(
				t,
				binding,
				phase,
				1,
			),
		},
		{
			State:         hostruntime.LifecycleEffectPresent,
			Postcondition: nil,
		},
	}
	for index, observation := range tests {
		backend := newFakeLifecyclePhaseBackend(binding)
		backend.override = &observation
		effects, err := NewLifecycleEffects(backend)
		if err != nil {
			t.Fatalf("NewLifecycleEffects(%d) error = %v", index, err)
		}
		if _, err := effects.Observe(
			context.Background(),
			binding,
			phase,
		); !errors.Is(err, ErrLifecycleEffects) {
			t.Fatalf("Observe(%d) error = %v", index, err)
		}
	}
}

type fakeLifecyclePhaseBackend struct {
	binding             hostruntime.OperationBinding
	current             *hostruntime.TargetPostcondition
	afterApply          hostruntime.TargetPostcondition
	override            *hostruntime.LifecycleEffectObservation
	applyErr            error
	keepAbsent          bool
	ambiguousAfterApply bool
	publishOnApplyError bool
	observeCalls        int
	applyCalls          int
}

func newFakeLifecyclePhaseBackend(
	binding hostruntime.OperationBinding,
) *fakeLifecyclePhaseBackend {
	return &fakeLifecyclePhaseBackend{binding: binding}
}

func (backend *fakeLifecyclePhaseBackend) ObservePhase(
	_ context.Context,
	binding hostruntime.OperationBinding,
	_ hostruntime.OperationPhase,
) (hostruntime.LifecycleEffectObservation, error) {
	backend.observeCalls++
	if binding != backend.binding {
		return hostruntime.LifecycleEffectObservation{},
			errors.New("binding drift")
	}
	if backend.override != nil {
		return *backend.override, nil
	}
	if backend.ambiguousAfterApply && backend.applyCalls > 0 {
		return hostruntime.LifecycleEffectObservation{
			State: hostruntime.LifecycleEffectAmbiguous,
		}, nil
	}
	if backend.current == nil {
		return hostruntime.LifecycleEffectObservation{
			State: hostruntime.LifecycleEffectAbsent,
		}, nil
	}
	copy := *backend.current
	return hostruntime.LifecycleEffectObservation{
		State:         hostruntime.LifecycleEffectPresent,
		Postcondition: &copy,
	}, nil
}

func (backend *fakeLifecyclePhaseBackend) ApplyPhase(
	_ context.Context,
	binding hostruntime.OperationBinding,
	_ hostruntime.OperationPhase,
) error {
	backend.applyCalls++
	if binding != backend.binding {
		return errors.New("binding drift")
	}
	if !backend.keepAbsent &&
		(backend.applyErr == nil || backend.publishOnApplyError) {
		copy := backend.afterApply
		backend.current = &copy
	}
	return backend.applyErr
}

func lifecycleEffectsBinding(t *testing.T) hostruntime.OperationBinding {
	t.Helper()
	disposition := hostruntime.InstallDispositionUpgradePortable
	prior := strings.Repeat("a", 64)
	target := strings.Repeat("b", 64)
	overlay := strings.Repeat("c", 64)
	operationID, err := hostruntime.DeriveOperationID(
		hostruntime.OperationKindInstall,
		&disposition,
		7,
		&prior,
		&target,
		fleetfence.FleetPortable,
		overlay,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	return hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     7,
		PriorManifestDigest:    &prior,
		TargetManifestDigest:   &target,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: overlay,
	}
}

func lifecycleEffectsPostcondition(
	t *testing.T,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	tick int,
) hostruntime.TargetPostcondition {
	t.Helper()
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	effectKey, err := hostruntime.DeriveOperationEffectKey(binding, phase)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey() error = %v", err)
	}
	filesystems := append(
		[]hostruntime.LifecycleFilesystemIdentity(nil),
		validStorageReservationFixture().Filesystems...,
	)
	result := hostruntime.TargetPostcondition{
		SchemaVersion:          1,
		OperationID:            binding.OperationID,
		BindingDigest:          bindingDigest,
		EffectKey:              effectKey,
		Phase:                  phase,
		ManifestDigest:         binding.TargetManifestDigest,
		PrivateOverlayRevision: binding.PrivateOverlayRevision,
		FenceGeneration:        binding.ExpectedGeneration,
		ActiveFleet:            binding.TargetFleet,
		Filesystems:            filesystems,
		Artifacts:              []hostruntime.ArtifactProjection{},
		Processes:              []hostruntime.ProcessProjection{},
		Policy: hostruntime.PolicyProjection{
			PolicyManifestDigest: strings.Repeat("d", 64),
			TransitionEpoch:      1,
		},
		Quiescence: hostruntime.QuiescenceProjection{},
		ObservedAt: time.Date(2026, 7, 30, 5, 0, tick, 0, time.UTC),
	}
	if _, _, err := hostruntime.MarshalTargetPostcondition(result); err != nil {
		t.Fatalf("MarshalTargetPostcondition() error = %v", err)
	}
	return result
}

func lifecycleEffectsPostconditionPointer(
	t *testing.T,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	tick int,
) *hostruntime.TargetPostcondition {
	t.Helper()
	result := lifecycleEffectsPostcondition(t, binding, phase, tick)
	return &result
}

func sameLifecycleEffectsState(
	left hostruntime.TargetPostcondition,
	right hostruntime.TargetPostcondition,
) bool {
	left.ObservedAt = time.Time{}
	right.ObservedAt = time.Time{}
	return reflect.DeepEqual(left, right)
}
