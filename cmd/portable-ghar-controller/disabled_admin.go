package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

var errDisabledMethodUnavailable = fmt.Errorf(
	"%w: disabled method unavailable",
	controller.ErrRuntimeUnavailable,
)

var errShutdownEffectStuck = fmt.Errorf(
	"%w: shutdown_effect_stuck",
	controller.ErrRuntimeShutdown,
)

type disabledAdminConfig struct {
	Transitions        observerTransitioner
	Authority          completeLocalAuthority
	Broker             *zeroDemandBroker
	Fleet              fleetAuthority
	External           *unavailableExternalGraph
	Ownership          controllerOwnershipLease
	Desired            controller.AcquisitionPolicy
	ExpectedFleet      fleetfence.Fleet
	ExpectedGeneration uint64
	ObservationMaxAge  time.Duration
	Now                func() time.Time
	SocketProof        func() error
}

type contextEffectGate struct {
	token chan struct{}
}

func newContextEffectGate() *contextEffectGate {
	gate := &contextEffectGate{token: make(chan struct{}, 1)}
	gate.token <- struct{}{}
	return gate
}

func (gate *contextEffectGate) Acquire(ctx context.Context) error {
	if gate == nil || ctx == nil {
		return controller.ErrRuntimeUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gate.token:
		return nil
	}
}

func (gate *contextEffectGate) TryAcquire() bool {
	if gate == nil {
		return false
	}
	select {
	case <-gate.token:
		return true
	default:
		return false
	}
}

func (gate *contextEffectGate) Release() {
	gate.token <- struct{}{}
}

type disabledAdminService struct {
	effect             *contextEffectGate
	stateMu            sync.Mutex
	transitions        observerTransitioner
	authority          completeLocalAuthority
	broker             *zeroDemandBroker
	fleet              fleetAuthority
	external           *unavailableExternalGraph
	ownership          controllerOwnershipLease
	desired            controller.AcquisitionPolicy
	expectedFleet      fleetfence.Fleet
	expectedGeneration uint64
	observationMaxAge  time.Duration
	now                func() time.Time
	socketProof        func() error
	runCtx             context.Context
	runCancel          context.CancelFunc
	ready              bool
	busy               bool
	stickyFatal        bool
	shutdown           bool
	shutdownFinishing  bool
	shutdownFinished   bool
	prepared           bool
	preparedEpoch      uint64
	generation         uint64
	effectOwner        uint64
}

var _ controller.LiveAdmin = (*disabledAdminService)(nil)

func newDisabledAdminService(
	config disabledAdminConfig,
) (*disabledAdminService, error) {
	canonical, err := controller.CanonicalizeAcquisitionPolicy(config.Desired)
	if config.Transitions == nil ||
		config.Authority == nil ||
		config.Broker == nil ||
		config.Fleet == nil ||
		config.External == nil ||
		config.Ownership == nil ||
		config.Ownership.Validate() != nil ||
		err != nil ||
		canonical.Mode != controller.AcquisitionDisabled ||
		canonical.MaxCapacity != 0 ||
		len(canonical.EligibleScaleSets) != 0 ||
		canonical.RepositoryPolicyRevision == 0 ||
		len(canonical.RepositoryPolicies) == 0 ||
		(config.ExpectedFleet != fleetfence.FleetPortable &&
			config.ExpectedFleet != fleetfence.FleetLegacy) ||
		config.ExpectedGeneration == 0 ||
		config.ObservationMaxAge <= 0 ||
		config.Now == nil ||
		config.SocketProof == nil {
		return nil, errDisabledObserverInvalid
	}
	canonical.Epoch = 0
	return &disabledAdminService{
		effect:             newContextEffectGate(),
		transitions:        config.Transitions,
		authority:          config.Authority,
		broker:             config.Broker,
		fleet:              config.Fleet,
		external:           config.External,
		ownership:          config.Ownership,
		desired:            canonical,
		expectedFleet:      config.ExpectedFleet,
		expectedGeneration: config.ExpectedGeneration,
		observationMaxAge:  config.ObservationMaxAge,
		now:                config.Now,
		socketProof:        config.SocketProof,
	}, nil
}

func (service *disabledAdminService) Initialize(ctx context.Context) error {
	if err := service.Prepare(ctx); err != nil {
		return err
	}
	return service.Activate(ctx)
}

func (service *disabledAdminService) Prepare(ctx context.Context) error {
	if service == nil || ctx == nil {
		return controller.ErrRuntimeUnavailable
	}
	if err := service.effect.Acquire(ctx); err != nil {
		return controller.ErrRuntimeUnavailable
	}
	defer service.effect.Release()
	service.stateMu.Lock()
	if service.ready ||
		service.busy ||
		service.stickyFatal ||
		service.shutdown ||
		service.prepared ||
		service.runCtx != nil {
		service.stateMu.Unlock()
		return controller.ErrRuntimeUnavailable
	}
	service.runCtx, service.runCancel = context.WithCancel(ctx)
	service.stateMu.Unlock()
	persisted, err := service.transitionDisabled(ctx)
	if err == nil {
		err = service.broker.ApplyAcquisitionPolicy(persisted)
	}
	if err == nil {
		err = service.authority.ColdReconcile(ctx)
	}
	var status controller.PolicyStatus
	if err == nil {
		status, err = service.proveTerminal(ctx)
	}
	if err != nil || status.Epoch != persisted.Epoch {
		service.markFatal()
		return controller.ErrRuntimeUnavailable
	}
	service.stateMu.Lock()
	if service.stickyFatal || service.shutdown {
		service.stateMu.Unlock()
		return controller.ErrRuntimeUnavailable
	}
	service.prepared = true
	service.preparedEpoch = persisted.Epoch
	service.stateMu.Unlock()
	return nil
}

func (service *disabledAdminService) Activate(ctx context.Context) error {
	if service == nil || ctx == nil {
		return controller.ErrRuntimeUnavailable
	}
	if err := service.effect.Acquire(ctx); err != nil {
		return controller.ErrRuntimeUnavailable
	}
	defer service.effect.Release()
	service.stateMu.Lock()
	if !service.prepared ||
		service.preparedEpoch == 0 ||
		service.ready ||
		service.busy ||
		service.stickyFatal ||
		service.shutdown {
		service.stateMu.Unlock()
		return controller.ErrRuntimeUnavailable
	}
	preparedEpoch := service.preparedEpoch
	service.stateMu.Unlock()
	status, err := service.prove(ctx)
	if err != nil || status.Epoch != preparedEpoch {
		service.markFatal()
		return controller.ErrRuntimeUnavailable
	}
	service.stateMu.Lock()
	if !service.prepared ||
		service.preparedEpoch != preparedEpoch ||
		service.stickyFatal ||
		service.shutdown ||
		service.generation == math.MaxUint64 {
		service.stateMu.Unlock()
		return controller.ErrRuntimeUnavailable
	}
	service.generation++
	service.ready = true
	service.stateMu.Unlock()
	return nil
}

func (service *disabledAdminService) Probe(
	ctx context.Context,
) (controller.PolicyStatus, error) {
	methodCtx, cancel, err := service.methodContext(ctx)
	if err != nil {
		return controller.PolicyStatus{}, err
	}
	defer cancel()
	if err := service.acquireReadyEffect(methodCtx); err != nil {
		return controller.PolicyStatus{}, err
	}
	defer service.effect.Release()
	status, err := service.prove(methodCtx)
	if err != nil {
		service.markFatal()
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	if !service.stillReady() {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	return status, nil
}

func (service *disabledAdminService) ReconcileOnce(
	ctx context.Context,
) (controller.CycleReceipt, error) {
	methodCtx, cancel, err := service.methodContext(ctx)
	if err != nil {
		return controller.CycleReceipt{}, err
	}
	defer cancel()
	if err := service.beginLongEffect(methodCtx); err != nil {
		return controller.CycleReceipt{}, err
	}
	defer service.effect.Release()
	receipt, effectErr := service.authority.ReconcileOnce(methodCtx)
	if effectErr == nil && !validDisabledCycleReceipt(receipt, service.now()) {
		effectErr = controller.ErrRuntimeUnavailable
	}
	proofErr := service.finishLongEffect(methodCtx)
	if effectErr != nil || proofErr != nil {
		return controller.CycleReceipt{}, controller.ErrRuntimeUnavailable
	}
	return receipt, nil
}

func (service *disabledAdminService) Drain(
	ctx context.Context,
	policy controller.DrainPolicy,
) error {
	if policy != controller.DrainWait {
		return errDisabledMethodUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return controller.ErrRuntimeUnavailable
	}
	methodCtx, cancel, err := service.methodContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := service.beginLongEffect(methodCtx); err != nil {
		return err
	}
	defer service.effect.Release()
	effectErr := service.authority.DrainWait(methodCtx)
	proofErr := service.finishLongEffect(methodCtx)
	if effectErr != nil || proofErr != nil {
		return controller.ErrRuntimeUnavailable
	}
	return nil
}

func (service *disabledAdminService) SetAcquisition(
	ctx context.Context,
	change controller.AcquisitionChange,
) (controller.PolicyStatus, error) {
	if change.Set != controller.AcquisitionDisabled ||
		change.EligibleScaleSet != "" {
		return controller.PolicyStatus{}, errDisabledMethodUnavailable
	}
	methodCtx, cancel, err := service.methodContext(ctx)
	if err != nil {
		return controller.PolicyStatus{}, err
	}
	defer cancel()
	if err := service.acquireReadyEffect(methodCtx); err != nil {
		return controller.PolicyStatus{}, err
	}
	defer service.effect.Release()
	before, err := service.prove(methodCtx)
	if err != nil {
		service.markFatal()
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	if change.Expected != before.Mode {
		return controller.PolicyStatus{}, controller.ErrAdminConflict
	}
	persisted, err := service.transitionDisabled(methodCtx)
	if err == nil {
		err = service.broker.ApplyAcquisitionPolicy(persisted)
	}
	var after controller.PolicyStatus
	if err == nil {
		after, err = service.prove(methodCtx)
	}
	if err != nil || after.Epoch != before.Epoch+1 {
		service.markFatal()
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	if !service.stillReady() {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	return after, nil
}

func (service *disabledAdminService) Health(ctx context.Context) error {
	if service == nil || ctx == nil || !service.stillReady() {
		return controller.ErrRuntimeUnavailable
	}
	methodCtx, cancel, err := service.methodContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if !service.effect.TryAcquire() {
		return controller.ErrRuntimeUnavailable
	}
	defer service.effect.Release()
	if !service.stillReady() {
		return controller.ErrRuntimeUnavailable
	}
	if _, err := service.prove(methodCtx); err != nil {
		service.markFatal()
		return controller.ErrRuntimeUnavailable
	}
	if !service.stillReady() {
		return controller.ErrRuntimeUnavailable
	}
	return nil
}

func (service *disabledAdminService) Shutdown(ctx context.Context) error {
	if err := service.BeginShutdown(); err != nil {
		return err
	}
	return service.FinishShutdown(ctx)
}

func (service *disabledAdminService) BeginShutdown() error {
	if service == nil {
		return controller.ErrRuntimeShutdown
	}
	service.stateMu.Lock()
	if service.shutdown {
		service.stateMu.Unlock()
		return controller.ErrRuntimeShutdown
	}
	service.shutdown = true
	service.ready = false
	service.effectOwner = 0
	if service.generation != math.MaxUint64 {
		service.generation++
	}
	runCancel := service.runCancel
	service.stateMu.Unlock()
	if runCancel != nil {
		runCancel()
	}
	return nil
}

func (service *disabledAdminService) FinishShutdown(
	ctx context.Context,
) error {
	return service.FinishShutdownWithJoin(ctx, nil)
}

func (service *disabledAdminService) FinishShutdownWithJoin(
	ctx context.Context,
	join func(context.Context) error,
) error {
	if service == nil || ctx == nil {
		return controller.ErrRuntimeShutdown
	}
	service.stateMu.Lock()
	if !service.shutdown ||
		service.shutdownFinishing ||
		service.shutdownFinished {
		service.stateMu.Unlock()
		return controller.ErrRuntimeShutdown
	}
	service.shutdownFinishing = true
	service.stateMu.Unlock()
	if err := service.effect.Acquire(ctx); err != nil {
		return errors.Join(errShutdownEffectStuck, err)
	}
	defer service.effect.Release()
	service.stateMu.Lock()
	service.busy = false
	service.effectOwner = 0
	service.stateMu.Unlock()
	if join != nil {
		if err := join(ctx); err != nil {
			return errors.Join(errShutdownEffectStuck, err)
		}
	}

	if err := service.authority.RevokePreRunning(ctx); err != nil {
		return errors.Join(controller.ErrRuntimeShutdown, err)
	}
	persisted, err := service.transitionDisabled(ctx)
	if err == nil {
		err = service.broker.ApplyAcquisitionPolicy(persisted)
	}
	var status controller.PolicyStatus
	if err == nil {
		status, err = service.proveTerminal(ctx)
	}
	if err != nil || status.Epoch != persisted.Epoch {
		return errors.Join(controller.ErrRuntimeShutdown, err)
	}
	service.stateMu.Lock()
	service.shutdownFinishing = false
	service.shutdownFinished = true
	service.stateMu.Unlock()
	return nil
}

func (service *disabledAdminService) HandleLocal(
	ctx context.Context,
	request localRequest,
) localResponse {
	response := localResponse{SchemaVersion: localProtocolSchemaVersion}
	var err error
	switch request.Method {
	case localMethodProbe:
		var status controller.PolicyStatus
		status, err = service.Probe(ctx)
		if err == nil {
			response.Policy = localPolicyStatusFromController(status)
		}
	case localMethodReconcileOnce:
		var receipt controller.CycleReceipt
		receipt, err = service.ReconcileOnce(ctx)
		if err == nil {
			response.Receipt = localCycleReceiptFromController(receipt)
		}
	case localMethodDrain:
		if request.DrainPolicy == nil {
			err = controller.ErrRuntimeUnavailable
		} else {
			err = service.Drain(ctx, *request.DrainPolicy)
		}
	case localMethodSetAcquisition:
		if request.Acquisition == nil {
			err = controller.ErrRuntimeUnavailable
		} else {
			change := controller.AcquisitionChange{
				Set:      request.Acquisition.Set,
				Expected: request.Acquisition.Expected,
			}
			if request.Acquisition.EligibleScaleSet != nil {
				change.EligibleScaleSet =
					*request.Acquisition.EligibleScaleSet
			}
			var status controller.PolicyStatus
			status, err = service.SetAcquisition(ctx, change)
			if err == nil {
				response.Policy = localPolicyStatusFromController(status)
			}
		}
	case localMethodHealth:
		err = service.Health(ctx)
	default:
		err = errDisabledMethodUnavailable
	}
	switch {
	case err == nil:
		response.Status = localStatusOK
		response.Reason = localReasonNone
	case errors.Is(err, controller.ErrAdminConflict):
		response.Status = localStatusConflict
		response.Reason = localReasonPolicyDrift
	case errors.Is(err, context.DeadlineExceeded):
		response.Status = localStatusUnavailable
		response.Reason = localReasonDeadlineExceeded
	case errors.Is(err, errDisabledMethodUnavailable):
		response.Status = localStatusUnavailable
		response.Reason = localReasonMethodUnavailable
	default:
		response.Status = localStatusUnavailable
		response.Reason = localReasonNotReady
	}
	return response
}

func (service *disabledAdminService) acquireReadyEffect(
	ctx context.Context,
) error {
	if service == nil || ctx == nil {
		return controller.ErrRuntimeUnavailable
	}
	if err := service.effect.Acquire(ctx); err != nil {
		return controller.ErrRuntimeUnavailable
	}
	if !service.stillReady() {
		service.effect.Release()
		return controller.ErrRuntimeUnavailable
	}
	return nil
}

func (service *disabledAdminService) beginLongEffect(
	ctx context.Context,
) error {
	if err := service.acquireReadyEffect(ctx); err != nil {
		return err
	}
	service.stateMu.Lock()
	if !service.ready ||
		service.busy ||
		service.stickyFatal ||
		service.shutdown ||
		service.generation == math.MaxUint64 {
		service.stateMu.Unlock()
		service.effect.Release()
		return controller.ErrRuntimeUnavailable
	}
	service.generation++
	service.ready = false
	service.busy = true
	service.effectOwner = service.generation
	service.stateMu.Unlock()
	return nil
}

func (service *disabledAdminService) finishLongEffect(
	ctx context.Context,
) error {
	service.stateMu.Lock()
	if service.shutdown {
		service.stateMu.Unlock()
		return controller.ErrRuntimeUnavailable
	}
	service.stateMu.Unlock()
	status, err := service.prove(ctx)
	if err != nil || status.Epoch == 0 {
		service.markFatal()
		return controller.ErrRuntimeUnavailable
	}
	service.stateMu.Lock()
	defer service.stateMu.Unlock()
	if !service.busy ||
		service.effectOwner == 0 ||
		service.stickyFatal ||
		service.shutdown ||
		service.generation == math.MaxUint64 {
		return controller.ErrRuntimeUnavailable
	}
	service.generation++
	service.effectOwner = 0
	service.busy = false
	service.ready = true
	return nil
}

func (service *disabledAdminService) transitionDisabled(
	ctx context.Context,
) (controller.AcquisitionPolicy, error) {
	current, err := service.transitions.Snapshot(ctx)
	if err != nil || current.Epoch == math.MaxUint64 {
		return controller.AcquisitionPolicy{}, controller.ErrRuntimeUnavailable
	}
	next := cloneObserverDesired(service.desired)
	next.Epoch = current.Epoch
	persisted, err := service.transitions.Transition(
		ctx,
		current.Epoch,
		next,
	)
	if err != nil ||
		persisted.Epoch != current.Epoch+1 ||
		!sameObserverPolicy(persisted, service.desired) {
		return controller.AcquisitionPolicy{}, controller.ErrRuntimeUnavailable
	}
	return persisted, nil
}

func (service *disabledAdminService) prove(
	ctx context.Context,
) (controller.PolicyStatus, error) {
	return service.proveState(ctx, true)
}

func (service *disabledAdminService) proveTerminal(
	ctx context.Context,
) (controller.PolicyStatus, error) {
	return service.proveState(ctx, false)
}

func (service *disabledAdminService) proveState(
	ctx context.Context,
	requireSockets bool,
) (controller.PolicyStatus, error) {
	if ctx == nil || ctx.Err() != nil ||
		service.ownership.Validate() != nil {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	if requireSockets && service.socketProof() != nil {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	policy, err := service.transitions.Snapshot(ctx)
	if err != nil || !sameObserverPolicy(policy, service.desired) {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	canonical, err := controller.CanonicalizeAcquisitionPolicy(policy)
	if err != nil ||
		validateZeroCapacitySummary(
			service.broker.CapacitySummary(),
			canonical.Epoch,
		) != nil {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	observation, err := service.authority.Observe(ctx)
	now := service.now()
	if err != nil ||
		observation.Validate(now, service.observationMaxAge) != nil ||
		!observation.Zero() {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	fleetProof, err := service.fleet.Observe(ctx)
	if err != nil ||
		fleetProof.Validate(
			now,
			service.observationMaxAge,
			service.expectedFleet,
			service.expectedGeneration,
		) != nil {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	digest, err := controller.AcquisitionPolicyDigest(canonical)
	if err != nil {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	digestText := hex.EncodeToString(digest[:])
	if service.expectedFleet == fleetfence.FleetLegacy &&
		(fleetProof.LegacyProof == nil ||
			fleetProof.LegacyProof.PolicyEpoch != canonical.Epoch ||
			fleetProof.LegacyProof.PolicyDigest != digestText) {
		return controller.PolicyStatus{}, controller.ErrRuntimeUnavailable
	}
	return controller.PolicyStatus{
		Mode:     canonical.Mode,
		Epoch:    canonical.Epoch,
		Digest:   digestText,
		Capacity: service.broker.CapacitySummary().EffectiveCapacity,
	}, nil
}

func (service *disabledAdminService) stillReady() bool {
	if service == nil {
		return false
	}
	service.stateMu.Lock()
	defer service.stateMu.Unlock()
	return service.ready &&
		!service.busy &&
		!service.stickyFatal &&
		!service.shutdown
}

func (service *disabledAdminService) methodContext(
	caller context.Context,
) (context.Context, func(), error) {
	if service == nil || caller == nil || caller.Err() != nil {
		return nil, nil, controller.ErrRuntimeUnavailable
	}
	service.stateMu.Lock()
	runCtx := service.runCtx
	shutdown := service.shutdown
	service.stateMu.Unlock()
	if runCtx == nil || shutdown || runCtx.Err() != nil {
		return nil, nil, controller.ErrRuntimeUnavailable
	}
	base, baseCancel := context.WithCancel(runCtx)
	stopCaller := context.AfterFunc(caller, baseCancel)
	methodCtx := context.Context(base)
	deadlineCancel := func() {}
	if deadline, ok := caller.Deadline(); ok {
		methodCtx, deadlineCancel = context.WithDeadline(base, deadline)
	}
	cleanup := func() {
		stopCaller()
		deadlineCancel()
		baseCancel()
	}
	if caller.Err() != nil {
		cleanup()
		return nil, nil, controller.ErrRuntimeUnavailable
	}
	return methodCtx, cleanup, nil
}

func (service *disabledAdminService) markFatal() {
	service.stateMu.Lock()
	service.ready = false
	service.busy = false
	service.effectOwner = 0
	service.stickyFatal = true
	if service.generation != math.MaxUint64 {
		service.generation++
	}
	runCancel := service.runCancel
	service.stateMu.Unlock()
	if runCancel != nil {
		runCancel()
	}
}

func validDisabledCycleReceipt(
	receipt controller.CycleReceipt,
	now time.Time,
) bool {
	return validLocalScalar(receipt.CycleID) &&
		!receipt.CompletedAt.IsZero() &&
		!receipt.CompletedAt.After(now) &&
		receipt.AssignmentCount >= 0 &&
		receipt.OldestAge >= 0
}

func localPolicyStatusFromController(
	status controller.PolicyStatus,
) *localPolicyStatus {
	return &localPolicyStatus{
		Mode:     status.Mode,
		Epoch:    status.Epoch,
		Digest:   status.Digest,
		Capacity: status.Capacity,
	}
}

func localCycleReceiptFromController(
	receipt controller.CycleReceipt,
) *localCycleReceipt {
	return &localCycleReceipt{
		CycleID:              receipt.CycleID,
		CompletedAt:          receipt.CompletedAt.UTC().Format(time.RFC3339Nano),
		AssignmentCount:      uint64(receipt.AssignmentCount),
		OldestAgeNanoseconds: int64(receipt.OldestAge),
	}
}
