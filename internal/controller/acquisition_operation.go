package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrAcquisitionOperationUnjoinable = errors.New(
	"controller: acquisition operation did not stop after cancellation",
)
var ErrAcquisitionGuardClose = errors.New(
	"controller: acquisition authority close failed",
)

type guardedAcquisitionOperation struct {
	operation       *acquisitionOperation
	operationCancel context.CancelFunc
	permit          AcquisitionPermitGuard
	host            AcquisitionGuard
	closeOnce       sync.Once
	closeErr        error
}

type trackedCallResult[T any] struct {
	value T
	err   error
}

func (s *Service) acquireGuardedOperation(
	ctx context.Context,
	kind string,
	repositoryAlias string,
	scaleSetName string,
	revalidate func(context.Context, AcquisitionPolicy, CapacitySummary) error,
) (*guardedAcquisitionOperation, error) {
	if err := s.recheckActiveConformance(ctx); err != nil {
		return nil, err
	}
	operationCtx, operationCancel := boundedContext(ctx, s.operationTimeout)
	barrier := s.barrierSnapshot()
	if barrier == nil {
		operationCancel()
		return nil, ErrServiceNotReady
	}
	operation, err := barrier.beginOperation(
		operationCtx,
		kind,
		repositoryAlias,
		scaleSetName,
	)
	if err != nil {
		operationCancel()
		return nil, err
	}
	fail := func(
		cause error,
		permit AcquisitionPermitGuard,
		host AcquisitionGuard,
	) error {
		var cleanup []error
		if permit != nil {
			cleanup = append(cleanup, permit.Close())
		}
		if host != nil {
			cleanup = append(cleanup, host.Close())
		}
		cleanup = append(cleanup, operation.Close())
		operationCancel()
		cleanupErr := errors.Join(cleanup...)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("%w: %v", ErrAcquisitionGuardClose, cleanupErr)
		}
		return errors.Join(cause, cleanupErr)
	}

	host, err := s.fleetGuards.AcquirePortable(operation.Context())
	if err != nil {
		return nil, fail(
			fmt.Errorf("%w: host guard: %w", ErrAcquisitionUnavailable, err),
			nil,
			nil,
		)
	}
	digest := operation.Digest()
	policy := operation.Policy()
	permit, err := s.permits.Acquire(operation.Context(), AcquisitionPermitRequest{
		OperationID:              operation.ID(),
		RepositoryAlias:          repositoryAlias,
		ScaleSetName:             scaleSetName,
		PolicyDigest:             hex.EncodeToString(digest[:]),
		OperationKind:            kind,
		PolicyEpoch:              operation.Epoch(),
		PolicyMode:               policy.Mode,
		MaxCapacity:              policy.MaxCapacity,
		RepositoryPolicyRevision: policy.RepositoryPolicyRevision,
	})
	if err != nil {
		return nil, fail(
			fmt.Errorf("%w: worker permit: %w", ErrAcquisitionUnavailable, err),
			nil,
			host,
		)
	}
	current, currentDigest, open := barrier.snapshot()
	if !open ||
		current.Epoch != operation.Epoch() ||
		currentDigest != operation.Digest() ||
		!acquisitionPolicyAllows(current, repositoryAlias, scaleSetName) {
		return nil, fail(ErrAcquisitionEpochSuperseded, permit, host)
	}
	if err := operation.Context().Err(); err != nil {
		return nil, fail(
			fmt.Errorf("%w: operation context: %w", ErrAcquisitionUnavailable, err),
			permit,
			host,
		)
	}
	capacity := s.broker.CapacitySummary()
	if capacity.Epoch != current.Epoch ||
		capacity.EffectiveCapacity <= 0 ||
		capacity.Available < 0 ||
		capacity.Occupied < 0 ||
		capacity.Queued < 0 {
		return nil, fail(ErrAdmissionConflict, permit, host)
	}
	if revalidate != nil {
		if err := revalidate(permit.Context(), current, capacity); err != nil {
			return nil, fail(err, permit, host)
		}
	}
	if err := permit.Revalidate(); err != nil {
		return nil, fail(
			fmt.Errorf("%w: worker permit changed: %w", ErrAcquisitionUnavailable, err),
			permit,
			host,
		)
	}
	return &guardedAcquisitionOperation{
		operation:       operation,
		operationCancel: operationCancel,
		permit:          permit,
		host:            host,
	}, nil
}

func (g *guardedAcquisitionOperation) Binding() AcquisitionPermitBinding {
	if g == nil || g.permit == nil {
		return AcquisitionPermitBinding{}
	}
	return g.permit.Binding()
}

func (g *guardedAcquisitionOperation) Revalidate() error {
	if g == nil || g.permit == nil {
		return ErrAcquisitionOperationClosed
	}
	return g.permit.Revalidate()
}

func (g *guardedAcquisitionOperation) ValidateBinding(
	ctx context.Context,
	binding AcquisitionPermitBinding,
) error {
	if g == nil || g.permit == nil {
		return ErrAcquisitionOperationClosed
	}
	return g.permit.ValidateBinding(ctx, binding)
}

func (g *guardedAcquisitionOperation) Context() context.Context {
	if g == nil || g.permit == nil {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(ErrAcquisitionOperationClosed)
		return ctx
	}
	return g.permit.Context()
}

func (g *guardedAcquisitionOperation) Admit() error {
	if g == nil || g.permit == nil {
		return ErrAcquisitionOperationClosed
	}
	return g.permit.Admit()
}

func (g *guardedAcquisitionOperation) Close() error {
	if g == nil || g.operation == nil {
		return ErrAcquisitionOperationClosed
	}
	g.closeOnce.Do(func() {
		permitErr := g.permit.Close()
		hostErr := g.host.Close()
		operationErr := g.operation.Close()
		if g.operationCancel != nil {
			g.operationCancel()
		}
		closeErr := errors.Join(permitErr, hostErr, operationErr)
		if closeErr != nil {
			g.closeErr = fmt.Errorf("%w: %v", ErrAcquisitionGuardClose, closeErr)
		}
	})
	return g.closeErr
}

func closeGuardedAfter[T any](
	g *guardedAcquisitionOperation,
	result <-chan trackedCallResult[T],
) {
	go func() {
		<-result
		_ = g.Close()
	}()
}

func runTrackedCall[T any](
	ctx context.Context,
	joinTimeout time.Duration,
	call func(context.Context) (T, error),
) (T, <-chan trackedCallResult[T], error, error) {
	if ctx == nil {
		var zero T
		return zero, nil, nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		var zero T
		cause := context.Cause(ctx)
		if cause == nil {
			cause = err
		}
		return zero, nil, nil, cause
	}
	result := make(chan trackedCallResult[T], 1)
	go func() {
		if err := ctx.Err(); err != nil {
			cause := context.Cause(ctx)
			if cause == nil {
				cause = err
			}
			result <- trackedCallResult[T]{err: cause}
			return
		}
		value, err := call(ctx)
		result <- trackedCallResult[T]{value: value, err: err}
	}()
	select {
	case completed := <-result:
		return completed.value, nil, completed.err, nil
	case <-ctx.Done():
		timer := time.NewTimer(joinTimeout)
		defer timer.Stop()
		select {
		case completed := <-result:
			return completed.value, nil, completed.err, context.Cause(ctx)
		case <-timer.C:
			var zero T
			return zero, result, nil, context.Cause(ctx)
		}
	}
}

func acquisitionPolicyAllows(
	policy AcquisitionPolicy,
	repositoryAlias string,
	scaleSetName string,
) bool {
	if policy.Mode != AcquisitionEnabled &&
		policy.Mode != AcquisitionCanaryOnly {
		return false
	}
	if policy.MaxCapacity <= 0 {
		return false
	}
	scaleSetEligible := false
	for _, eligible := range policy.EligibleScaleSets {
		if eligible == scaleSetName {
			scaleSetEligible = true
			break
		}
	}
	if !scaleSetEligible {
		return false
	}
	for _, repository := range policy.RepositoryPolicies {
		if repository.Alias == repositoryAlias {
			return repository.Eligibility == "active" &&
				repository.MaxConcurrency > 0
		}
	}
	return false
}
