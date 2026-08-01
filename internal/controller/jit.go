package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

var (
	ErrJITAuthorization = errors.New("controller: JIT authorization failed")
	ErrJITMayHaveActed  = errors.New("controller: JIT request may have acted")
	ErrJITFatal         = errors.New("controller: JIT operation requires fatal transition")
)

const jitWorkFolder = "_work"

// JITAuthorizationRequest binds the exact active durable assignment and live
// scale-set session to one guarded JIT call. It contains no credential or JIT
// result bytes.
type JITAuthorizationRequest struct {
	Assignment   Assignment
	ScaleSetName string
	Session      githubscale.Session
	RunnerName   string
	Request      githubscale.JITRequest
}

// JITAuthorizer is the only lifecycle path allowed to invoke GenerateJIT.
type JITAuthorizer interface {
	GenerateJITAuthorized(context.Context, JITAuthorizationRequest) (githubscale.JITConfig, error)
}

// GenerateJITAuthorized performs one epoch-bound JIT request only after the
// durable acquisition, lifecycle, broker, slot, and policy identities all
// agree. Cleanup-only runner reads and removals intentionally do not use this
// path.
func (s *Service) GenerateJITAuthorized(
	ctx context.Context,
	request JITAuthorizationRequest,
) (githubscale.JITConfig, error) {
	if err := validateJITAuthorizationRequest(request); err != nil {
		return githubscale.JITConfig{}, err
	}
	if _, ready := s.policySnapshot(); !ready {
		return githubscale.JITConfig{}, ErrServiceNotReady
	}

	operationCtx, cancel := boundedContext(ctx, s.operationTimeout)
	defer cancel()
	guarded, err := s.acquireGuardedOperation(
		operationCtx,
		"jit",
		request.Assignment.Key.RepositoryAlias,
		request.ScaleSetName,
		func(current AcquisitionPolicy, capacity CapacitySummary) error {
			return s.revalidateJITAuthorization(
				operationCtx,
				current,
				capacity,
				request,
			)
		},
	)
	if err != nil {
		authorizationErr := fmt.Errorf("%w: %w", ErrJITAuthorization, err)
		if errors.Is(err, ErrAcquisitionGuardClose) {
			return githubscale.JITConfig{}, errors.Join(
				authorizationErr,
				ErrJITFatal,
			)
		}
		return githubscale.JITConfig{}, authorizationErr
	}

	config, pending, callErr, cancelErr := runTrackedCall(
		guarded.operation.Context(),
		s.transitionJoinTimeout,
		func(callCtx context.Context) (githubscale.JITConfig, error) {
			return request.Session.GenerateJIT(callCtx, request.Request)
		},
	)
	if pending != nil {
		go func() {
			completed := <-pending
			if completed.value.Encoded != nil {
				completed.value.Encoded.Destroy()
			}
			_ = guarded.Close()
		}()
		return githubscale.JITConfig{}, errors.Join(
			ErrJITMayHaveActed,
			ErrJITFatal,
			ErrAcquisitionOperationUnjoinable,
		)
	}
	if callErr != nil || cancelErr != nil {
		if config.Encoded != nil {
			config.Encoded.Destroy()
		}
		closeErr := guarded.Close()
		if closeErr != nil {
			closeErr = errors.Join(closeErr, ErrJITFatal)
		}
		return githubscale.JITConfig{}, errors.Join(
			ErrJITMayHaveActed,
			callErr,
			cancelErr,
			closeErr,
		)
	}
	if closeErr := guarded.Close(); closeErr != nil {
		if config.Encoded != nil {
			config.Encoded.Destroy()
		}
		return githubscale.JITConfig{}, errors.Join(
			ErrJITMayHaveActed,
			ErrJITFatal,
			closeErr,
		)
	}
	return config, nil
}

func validateJITAuthorizationRequest(request JITAuthorizationRequest) error {
	if request.Session == nil ||
		request.Assignment.Validate() != nil ||
		!validAcquisitionScalar(
			request.ScaleSetName,
			maxAcquisitionScaleSetBytes,
		) ||
		len(request.Assignment.Offer.RequestLabels) != 1 ||
		request.Assignment.Offer.RequestLabels[0] != request.ScaleSetName ||
		request.RunnerName != request.Assignment.Slot.OpaqueName ||
		request.Request.RunnerName != request.RunnerName ||
		request.Request.WorkFolder != jitWorkFolder {
		return ErrJITAuthorization
	}
	return nil
}

func (s *Service) revalidateJITAuthorization(
	ctx context.Context,
	current AcquisitionPolicy,
	capacity CapacitySummary,
	request JITAuthorizationRequest,
) error {
	key := request.Assignment.Key
	acquisition, err := s.state.AcquisitionAssignment(ctx, key)
	if err != nil ||
		acquisition.Key != key ||
		acquisition.Outcome != AssignmentAcquired ||
		acquisition.RevokedEpoch != 0 {
		return errors.Join(ErrJITAuthorization, err)
	}

	recoverable, err := s.state.ListRecoverable(ctx)
	if err != nil {
		return errors.Join(ErrJITAuthorization, err)
	}
	var (
		record RecoverableAssignment
		count  int
	)
	for _, candidate := range recoverable {
		if candidate.Key == key {
			record = candidate
			count++
		}
	}
	if count != 1 ||
		record.State != StateReleaseArmed ||
		record.Key != key ||
		!equalServiceOffer(record.Offer, request.Assignment.Offer) ||
		record.Slot != request.Assignment.Slot ||
		record.Slot.OpaqueName != request.RunnerName ||
		record.Slot.CapacitySlotID == 0 {
		return ErrJITAuthorization
	}

	durableReference := record.Admission
	durableReference.Offer = cloneServiceOffer(record.Offer)
	liveReference, present, err := s.broker.Reference(key)
	if err != nil ||
		!present ||
		!s.broker.HasLiveReference(key) ||
		liveReference.Key != key ||
		liveReference.Phase != AdmissionActive ||
		liveReference.SlotID != record.Slot.CapacitySlotID ||
		!equalAdmissionReference(durableReference, liveReference) ||
		!equalServiceOffer(liveReference.Offer, request.Assignment.Offer) {
		return errors.Join(ErrJITAuthorization, err)
	}
	if current.Epoch == 0 ||
		capacity.Epoch != current.Epoch ||
		capacity.EffectiveCapacity <= 0 ||
		!acquisitionPolicyAllows(
			current,
			key.RepositoryAlias,
			request.ScaleSetName,
		) {
		return ErrJITAuthorization
	}
	return nil
}

func equalAdmissionReference(left, right AdmissionReference) bool {
	left.Offer = cloneServiceOffer(left.Offer)
	right.Offer = cloneServiceOffer(right.Offer)
	return reflect.DeepEqual(left, right)
}

func equalServiceOffer(left, right githubscale.Offer) bool {
	left = cloneServiceOffer(left)
	right = cloneServiceOffer(right)
	return reflect.DeepEqual(left, right)
}
