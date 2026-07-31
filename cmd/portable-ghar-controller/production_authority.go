package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type productionAuthorityState interface {
	controller.ReconcileState
	Snapshot(context.Context) (controller.AcquisitionPolicy, error)
	MarkPreRunningRevoked(
		context.Context,
		uint64,
		time.Time,
	) ([]controller.AssignmentKey, error)
	OperationalSummary(
		context.Context,
		time.Time,
	) (controller.OperationalSummary, error)
	Advance(context.Context, controller.AssignmentKey, controller.State) error
}

type productionCleanupWorker struct {
	state      productionAuthorityState
	recovery   hostruntime.ManagedRecovery
	buildID    string
	generation uint64
	brokerRoot string
}

var _ controller.AssignmentReconciler = (*productionCleanupWorker)(nil)

func newProductionCleanupWorker(
	state productionAuthorityState,
	recovery hostruntime.ManagedRecovery,
	buildID string,
	generation uint64,
	brokerRoot string,
) (*productionCleanupWorker, error) {
	if state == nil ||
		recovery == nil ||
		!validLowerDigest(buildID) ||
		generation == 0 ||
		!canonicalAbsolutePath(brokerRoot) ||
		brokerRoot == "/" {
		return nil, errDisabledProjectionIncomplete
	}
	return &productionCleanupWorker{
		state:      state,
		recovery:   recovery,
		buildID:    buildID,
		generation: generation,
		brokerRoot: brokerRoot,
	}, nil
}

func (worker *productionCleanupWorker) ReconcileAssignment(
	ctx context.Context,
	assignment controller.RecoverableAssignment,
) error {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return errDisabledProjectionIncomplete
	}
	if assignment.Released ||
		assignment.Ambiguous ||
		assignment.AmbiguousReason != "" {
		return errDisabledProjectionIncomplete
	}
	if assignment.State == controller.StateReceived {
		if assignment.Slot != (controller.RunnerSlot{}) {
			return errDisabledProjectionIncomplete
		}
		return worker.state.Advance(
			ctx,
			assignment.Key,
			controller.StateDestroyed,
		)
	}
	if !validProductionPreReleaseSlot(assignment) {
		return errDisabledProjectionIncomplete
	}
	spec, err := worker.recoverySpec(assignment)
	if err != nil {
		return err
	}
	snapshot, err := worker.recovery.InspectManaged(ctx, spec)
	if err != nil {
		return errors.Join(errDisabledProjectionIncomplete, err)
	}
	if err := worker.recovery.RemoveManaged(ctx, snapshot); err != nil {
		return errors.Join(errDisabledProjectionIncomplete, err)
	}
	if err := worker.state.Advance(
		ctx,
		assignment.Key,
		controller.StateDestroyed,
	); err != nil {
		return errors.Join(errDisabledProjectionIncomplete, err)
	}
	return nil
}

func validProductionPreReleaseSlot(
	assignment controller.RecoverableAssignment,
) bool {
	slot := assignment.Slot
	if assignment.Key.RepositoryAlias == "" ||
		assignment.Key.RunnerRequestID <= 0 ||
		slot.OpaqueName != controller.OpaqueSlotName(assignment.Key) ||
		slot.CapacitySlotID == 0 ||
		slot.UpstreamRunnerID != 0 ||
		slot.BoundRequestID != 0 {
		return false
	}
	adapter := validOptionalContainerID(slot.AdapterContainerID)
	broker := validOptionalContainerID(slot.BrokerContainerID)
	runner := validOptionalContainerID(slot.RunnerContainerID)
	if !adapter || !broker || !runner {
		return false
	}
	switch assignment.State {
	case controller.StateCapacityReserved:
		return slot.AdapterContainerID == "" &&
			slot.BrokerContainerID == "" &&
			slot.RunnerContainerID == ""
	case controller.StateAdapterCreated,
		controller.StateAdapterVerified:
		return slot.AdapterContainerID != "" &&
			slot.BrokerContainerID == "" &&
			slot.RunnerContainerID == ""
	case controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified:
		return slot.AdapterContainerID != "" &&
			slot.BrokerContainerID != "" &&
			slot.RunnerContainerID == ""
	case controller.StateRunnerHeld,
		controller.StateReleaseArmed:
		return slot.AdapterContainerID != "" &&
			slot.BrokerContainerID != "" &&
			slot.RunnerContainerID != ""
	default:
		return false
	}
}

func validOptionalContainerID(value string) bool {
	return value == "" || validLowerDigest(value)
}

func (worker *productionCleanupWorker) recoverySpec(
	assignment controller.RecoverableAssignment,
) (hostruntime.RecoverySpec, error) {
	const prefix = "pghar-slot-"
	slot := assignment.Slot
	if !strings.HasPrefix(slot.OpaqueName, prefix) {
		return hostruntime.RecoverySpec{}, errDisabledProjectionIncomplete
	}
	suffix := strings.TrimPrefix(slot.OpaqueName, prefix)
	decoded, err := hex.DecodeString(suffix)
	if err != nil || len(decoded) != 16 || strings.ToLower(suffix) != suffix {
		return hostruntime.RecoverySpec{}, errDisabledProjectionIncomplete
	}
	return hostruntime.RecoverySpec{
		SlotIdentity:      slot.OpaqueName,
		BuildID:           worker.buildID,
		FleetGeneration:   worker.generation,
		AdapterName:       "pghar-adapter-" + suffix,
		BrokerName:        "pghar-broker-" + suffix,
		RunnerName:        "pghar-runner-" + suffix,
		ExpectedAdapterID: slot.AdapterContainerID,
		ExpectedBrokerID:  slot.BrokerContainerID,
		ExpectedRunnerID:  slot.RunnerContainerID,
		RelayParent: filepath.Join(
			worker.brokerRoot,
			slot.OpaqueName,
			"relay",
		),
		AuthorityParent: filepath.Join(
			worker.brokerRoot,
			slot.OpaqueName,
			"authority",
		),
	}, nil
}

type productionLocalAuthorityConfig struct {
	State       productionAuthorityState
	Recovery    hostruntime.ManagedRecovery
	Quiescence  hostruntime.ManagedQuiescence
	BuildID     string
	Generation  uint64
	BrokerRoot  string
	Timeout     time.Duration
	Now         func() time.Time
	NextCycleID func() string
}

type productionLocalAuthority struct {
	state      productionAuthorityState
	reconciler controller.Reconciler
	quiescence hostruntime.ManagedQuiescence
	timeout    time.Duration
	now        func() time.Time
	sequence   atomic.Uint64
}

var _ completeLocalAuthority = (*productionLocalAuthority)(nil)

func newProductionLocalAuthority(
	config productionLocalAuthorityConfig,
) (*productionLocalAuthority, error) {
	if config.State == nil ||
		config.Quiescence == nil ||
		config.Timeout <= 0 ||
		config.Now == nil {
		return nil, errDisabledProjectionIncomplete
	}
	worker, err := newProductionCleanupWorker(
		config.State,
		config.Recovery,
		config.BuildID,
		config.Generation,
		config.BrokerRoot,
	)
	if err != nil {
		return nil, err
	}
	nextCycleID := config.NextCycleID
	if nextCycleID == nil {
		nextCycleID = productionCycleID
	}
	reconciler, err := controller.NewReconciler(
		config.State,
		worker,
		config.Now,
		nextCycleID,
	)
	if err != nil {
		return nil, errDisabledProjectionIncomplete
	}
	return &productionLocalAuthority{
		state:      config.State,
		reconciler: reconciler,
		quiescence: config.Quiescence,
		timeout:    config.Timeout,
		now:        config.Now,
	}, nil
}

func productionCycleID() string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ""
	}
	return "disabled-" + hex.EncodeToString(nonce[:])
}

func (authority *productionLocalAuthority) ColdReconcile(
	ctx context.Context,
) error {
	_, err := authority.ReconcileOnce(ctx)
	return err
}

func (authority *productionLocalAuthority) ReconcileOnce(
	ctx context.Context,
) (controller.CycleReceipt, error) {
	if authority == nil || ctx == nil || ctx.Err() != nil {
		return controller.CycleReceipt{}, errDisabledProjectionIncomplete
	}
	callCtx, cancel := context.WithTimeout(ctx, authority.timeout)
	defer cancel()
	receipt, err := authority.reconciler.Once(callCtx)
	if err != nil {
		return controller.CycleReceipt{}, errors.Join(
			errDisabledProjectionIncomplete,
			err,
		)
	}
	return receipt, nil
}

func (authority *productionLocalAuthority) DrainWait(
	ctx context.Context,
) error {
	if ctx == nil {
		return errDisabledProjectionIncomplete
	}
	if _, ok := ctx.Deadline(); !ok {
		return errDisabledProjectionIncomplete
	}
	if _, err := authority.ReconcileOnce(ctx); err != nil {
		return err
	}
	_, err := authority.Observe(ctx)
	return err
}

func (authority *productionLocalAuthority) RevokePreRunning(
	ctx context.Context,
) error {
	if authority == nil || ctx == nil || ctx.Err() != nil {
		return errDisabledProjectionIncomplete
	}
	callCtx, cancel := context.WithTimeout(ctx, authority.timeout)
	defer cancel()
	policy, err := authority.state.Snapshot(callCtx)
	if err != nil || policy.Epoch == math.MaxUint64 {
		return errors.Join(errDisabledProjectionIncomplete, err)
	}
	at := authority.now()
	if at.IsZero() {
		return errDisabledProjectionIncomplete
	}
	keys, err := authority.state.MarkPreRunningRevoked(
		callCtx,
		policy.Epoch+1,
		at,
	)
	if err != nil {
		return errors.Join(errDisabledProjectionIncomplete, err)
	}
	receipt, err := authority.ReconcileOnce(callCtx)
	if err != nil || receipt.AssignmentCount < len(keys) {
		return errors.Join(errDisabledProjectionIncomplete, err)
	}
	return nil
}

func (authority *productionLocalAuthority) Observe(
	ctx context.Context,
) (localObservation, error) {
	if authority == nil || ctx == nil || ctx.Err() != nil {
		return localObservation{}, errDisabledProjectionIncomplete
	}
	callCtx, cancel := context.WithTimeout(ctx, authority.timeout)
	defer cancel()
	at := authority.now()
	if at.IsZero() {
		return localObservation{}, errDisabledProjectionIncomplete
	}
	recoverable, err := authority.state.ListRecoverable(callCtx)
	if err != nil || len(recoverable) != 0 {
		return localObservation{}, errors.Join(
			errDisabledProjectionIncomplete,
			err,
		)
	}
	summary, err := authority.state.OperationalSummary(callCtx, at)
	if err != nil ||
		summary.AssignedJobs != 0 ||
		summary.RunningJobs != 0 ||
		summary.OldestLiveAssignmentAge != 0 ||
		summary.UnassignedReleasedListeners != 0 {
		return localObservation{}, errors.Join(
			errDisabledProjectionIncomplete,
			err,
		)
	}
	if err := authority.quiescence.ProveManagedQuiescence(callCtx); err != nil {
		return localObservation{}, errors.Join(
			errDisabledProjectionIncomplete,
			err,
		)
	}
	sequence, ok := nextObservationSequence(&authority.sequence)
	if !ok {
		return localObservation{}, errDisabledProjectionIncomplete
	}
	return localObservation{
		Sequence:   sequence,
		ObservedAt: at,
		Complete:   true,
	}, nil
}

func nextObservationSequence(sequence *atomic.Uint64) (uint64, bool) {
	for {
		current := sequence.Load()
		if current == math.MaxUint64 {
			return 0, false
		}
		if sequence.CompareAndSwap(current, current+1) {
			return current + 1, true
		}
	}
}
