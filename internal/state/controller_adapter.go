package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

const hostedRouteEffectKind = "hosted-route"
const hostedRouteFailureReason = "route-rejected"

// ControllerAdapter is the checked, acyclic translation boundary between the
// controller-owned durable-state port and this package's native Store.
type ControllerAdapter struct {
	store  Store
	limits HistoryLimits
}

var _ controller.DurableState = (*ControllerAdapter)(nil)

func NewControllerAdapter(store Store, limits HistoryLimits) (*ControllerAdapter, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil durable store", controller.ErrHistoryUnavailable)
	}
	if err := validateRecordLimits(limits); err != nil {
		return nil, fmt.Errorf("%w: invalid history limits", controller.ErrHistoryUnavailable)
	}
	return &ControllerAdapter{store: store, limits: limits}, nil
}

func (a *ControllerAdapter) RecordMessageReceipt(
	ctx context.Context,
	envelope controller.MessageEnvelope,
	at time.Time,
) (controller.MessageReceiptRecord, error) {
	record, err := a.store.RecordMessageReceipt(ctx, envelope, at)
	if err != nil {
		return controller.MessageReceiptRecord{}, mapControllerStateError(err)
	}
	state, err := controllerMessageAckState(record.State)
	if err != nil {
		return controller.MessageReceiptRecord{}, err
	}
	return controller.MessageReceiptRecord{
		Digest:   controller.MessageDigest(record.Digest),
		State:    state,
		Inserted: record.Inserted,
	}, nil
}

func (a *ControllerAdapter) RecordOffer(
	ctx context.Context,
	repositoryAlias string,
	offer githubscale.Offer,
	evidence controller.OfferEvidence,
) (controller.OfferRecord, error) {
	nativeEvidence, err := stateOfferEvidence(evidence)
	if err != nil {
		return controller.OfferRecord{}, err
	}
	record, err := a.store.RecordOffer(ctx, stateOfferIdentity(repositoryAlias, offer), nativeEvidence)
	if err != nil {
		return controller.OfferRecord{}, mapControllerStateError(err)
	}
	disposition, err := controllerOfferDisposition(record.Disposition)
	if err != nil {
		return controller.OfferRecord{}, err
	}
	return controller.OfferRecord{
		Key:         record.Key,
		Disposition: disposition,
		State:       record.State,
	}, nil
}

func (a *ControllerAdapter) PersistAdmission(
	ctx context.Context,
	key controller.AssignmentKey,
	ref controller.AdmissionReference,
) error {
	projection, err := stateAdmissionProjection(key, ref)
	if err != nil {
		return err
	}
	return mapControllerStateError(a.store.PersistAdmissionProjection(ctx, key, projection))
}

func (a *ControllerAdapter) ReserveActive(
	ctx context.Context,
	key controller.AssignmentKey,
	ref controller.AdmissionReference,
	opaqueName string,
) error {
	projection, err := stateAdmissionProjection(key, ref)
	if err != nil {
		return err
	}
	return mapControllerStateError(a.store.ReserveActive(ctx, key, projection, opaqueName))
}

func (a *ControllerAdapter) ClearAdmission(ctx context.Context, key controller.AssignmentKey) error {
	return mapControllerStateError(a.store.ClearAdmissionProjection(ctx, key))
}

func (a *ControllerAdapter) LookupHostedEffect(
	ctx context.Context,
	key controller.AssignmentKey,
	idempotencyKey string,
) (controller.HostedEffectRecord, error) {
	record, err := a.store.LookupEffect(ctx, key, idempotencyKey, hostedRouteEffectKind)
	if err != nil {
		return controller.HostedEffectRecord{}, mapControllerStateError(err)
	}
	state, err := controllerHostedEffectState(record.State)
	if err != nil {
		return controller.HostedEffectRecord{}, err
	}
	failure, err := controllerHostedFailure(record.State, record.ReasonCode)
	if err != nil {
		return controller.HostedEffectRecord{}, err
	}
	return controller.HostedEffectRecord{
		State:          state,
		ResultIdentity: record.ResultIdentity,
		Failure:        failure,
	}, nil
}

func (a *ControllerAdapter) BeginHostedEffect(
	ctx context.Context,
	key controller.AssignmentKey,
	idempotencyKey string,
) (bool, error) {
	began, err := a.store.BeginEffect(ctx, key, idempotencyKey, hostedRouteEffectKind)
	return began, mapControllerStateError(err)
}

func (a *ControllerAdapter) CompleteHostedEffect(
	ctx context.Context,
	idempotencyKey string,
	resultIdentity string,
) error {
	return mapControllerStateError(a.store.CompleteEffect(ctx, idempotencyKey, EffectResult{
		ResultIdentity: resultIdentity,
		Column:         IdentityNone,
	}))
}

func (a *ControllerAdapter) FailHostedEffect(
	ctx context.Context,
	idempotencyKey string,
) error {
	return mapControllerStateError(a.store.CompleteEffect(ctx, idempotencyKey, EffectResult{
		Column:     IdentityNone,
		ReasonCode: hostedRouteFailureReason,
	}))
}

func (a *ControllerAdapter) BeginAck(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	at time.Time,
) error {
	return mapControllerStateError(a.store.BeginMessageAck(ctx, repositoryAlias, messageID, at))
}

func (a *ControllerAdapter) ConfirmAck(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	at time.Time,
) error {
	return mapControllerStateError(a.store.ConfirmMessageAck(ctx, repositoryAlias, messageID, at))
}

func (a *ControllerAdapter) ObserveRedelivery(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	digest controller.MessageDigest,
	at time.Time,
) error {
	return mapControllerStateError(a.store.ObserveMessageRedelivery(
		ctx,
		repositoryAlias,
		messageID,
		[32]byte(digest),
		at,
	))
}

func (a *ControllerAdapter) ListUncertainAcks(
	ctx context.Context,
) ([]controller.UncertainMessageReceipt, error) {
	records, err := a.store.ListUncertainAcks(ctx)
	if err != nil {
		return nil, mapControllerStateError(err)
	}
	out := make([]controller.UncertainMessageReceipt, 0, len(records))
	for _, record := range records {
		out = append(out, controller.UncertainMessageReceipt{
			RepositoryAlias: record.RepositoryAlias,
			MessageID:       record.MessageID,
			Digest:          controller.MessageDigest(record.Digest),
			StartedAt:       record.StartedAt,
		})
	}
	return out, nil
}

func (a *ControllerAdapter) BindTerminalMessage(
	ctx context.Context,
	key controller.AssignmentKey,
	messageID int,
) error {
	return mapControllerStateError(a.store.BindTerminalMessage(ctx, key, messageID))
}

func (a *ControllerAdapter) Advance(
	ctx context.Context,
	key controller.AssignmentKey,
	next controller.State,
) error {
	return mapControllerStateError(a.store.Advance(ctx, key, next))
}

func (a *ControllerAdapter) ListRecoverable(
	ctx context.Context,
) ([]controller.RecoverableAssignment, error) {
	native, err := a.store.ListRecoverable(ctx)
	if err != nil {
		return nil, mapControllerStateError(err)
	}
	out := make([]controller.RecoverableAssignment, 0, len(native))
	for _, item := range native {
		admission, err := controllerAdmissionProjection(item.Key, item.Admission)
		if err != nil {
			return nil, err
		}
		out = append(out, controller.RecoverableAssignment{
			Key:             item.Key,
			State:           item.State,
			Offer:           controllerOffer(item.Offer),
			Admission:       admission,
			Released:        item.Released,
			Ambiguous:       item.Ambiguous,
			AmbiguousReason: item.AmbiguousReason,
			Slot:            item.Slot,
			UpdatedAt:       item.UpdatedAt,
		})
	}
	return out, nil
}

func (a *ControllerAdapter) CompactTerminal(
	ctx context.Context,
	key controller.AssignmentKey,
	at time.Time,
) error {
	return mapControllerStateError(a.store.CompactTerminal(ctx, key, a.limits, at))
}

func (a *ControllerAdapter) HistoryUsage(ctx context.Context) (controller.HistoryUsage, error) {
	usage, err := a.store.HistoryUsage(ctx, a.limits)
	if err != nil {
		return controller.HistoryUsage{}, mapControllerStateError(err)
	}
	return controller.HistoryUsage{
		LiveRows:                  usage.LiveRows,
		LiveLogicalBytes:          usage.LiveLogicalBytes,
		ProtectedTerminalRows:     usage.ProtectedTerminalRows,
		ProtectedTerminalBytes:    usage.ProtectedTerminalBytes,
		MessageReceiptRows:        usage.MessageReceiptRows,
		MessageReceiptBytes:       usage.MessageReceiptBytes,
		TombstoneRows:             usage.TombstoneRows,
		TombstoneLogicalBytes:     usage.TombstoneLogicalBytes,
		NetworkLedgerRows:         usage.NetworkLedgerRows,
		NetworkLedgerLogicalBytes: usage.NetworkLedgerLogicalBytes,
		InflightAssignments:       usage.InflightAssignments,
		ReservedRows:              usage.ReservedRows,
		ReservedLogicalBytes:      usage.ReservedLogicalBytes,
		OldestRetainedAt:          usage.OldestRetainedAt,
	}, nil
}

func stateOfferIdentity(repositoryAlias string, offer githubscale.Offer) OfferIdentity {
	return OfferIdentity{
		RepositoryAlias:    repositoryAlias,
		RunnerRequestID:    offer.RunnerRequestID,
		JobID:              offer.JobID,
		RepositoryName:     offer.RepositoryName,
		OwnerName:          offer.OwnerName,
		JobWorkflowRef:     offer.JobWorkflowRef,
		JobDisplayName:     offer.JobDisplayName,
		WorkflowRunID:      offer.WorkflowRunID,
		EventName:          offer.EventName,
		RequestLabels:      append([]string(nil), offer.RequestLabels...),
		QueueTime:          offer.QueueTime,
		ScaleSetAssignTime: offer.ScaleSetAssignTime,
		RunnerAssignTime:   offer.RunnerAssignTime,
		FinishTime:         offer.FinishTime,
		AcquireJobURL:      offer.AcquireJobURL,
	}
}

func controllerOffer(offer OfferIdentity) githubscale.Offer {
	return githubscale.Offer{
		JobRef: githubscale.JobRef{
			RunnerRequestID:    offer.RunnerRequestID,
			JobID:              offer.JobID,
			RepositoryName:     offer.RepositoryName,
			OwnerName:          offer.OwnerName,
			JobWorkflowRef:     offer.JobWorkflowRef,
			JobDisplayName:     offer.JobDisplayName,
			WorkflowRunID:      offer.WorkflowRunID,
			EventName:          offer.EventName,
			RequestLabels:      append([]string(nil), offer.RequestLabels...),
			QueueTime:          offer.QueueTime,
			ScaleSetAssignTime: offer.ScaleSetAssignTime,
			RunnerAssignTime:   offer.RunnerAssignTime,
			FinishTime:         offer.FinishTime,
		},
		AcquireJobURL: offer.AcquireJobURL,
	}
}

func stateOfferEvidence(evidence controller.OfferEvidence) (OfferEvidence, error) {
	var kind OfferEvidenceKind
	switch evidence.Kind {
	case controller.OfferEvidenceCurrentPoll:
		kind = EvidenceCurrentPoll
	case controller.OfferEvidenceSelectiveReadback:
		kind = EvidenceSelectiveReadback
	default:
		return OfferEvidence{}, fmt.Errorf("%w: invalid offer evidence kind", controller.ErrReplayUnavailable)
	}
	return OfferEvidence{
		Kind:       kind,
		MessageID:  evidence.MessageID,
		QueueTime:  evidence.QueueTime,
		ObservedAt: evidence.ObservedAt,
	}, nil
}

func stateAdmissionProjection(
	key controller.AssignmentKey,
	ref controller.AdmissionReference,
) (AdmissionProjection, error) {
	if ref.Key != key {
		return AdmissionProjection{}, fmt.Errorf("%w: admission key mismatch", controller.ErrAdmissionConflict)
	}
	var phase AdmissionPhase
	switch ref.Phase {
	case controller.AdmissionQueued:
		phase = AdmissionQueued
	case controller.AdmissionReserved:
		phase = AdmissionReserved
	case controller.AdmissionActive:
		phase = AdmissionActive
	default:
		return AdmissionProjection{}, fmt.Errorf("%w: invalid admission phase", controller.ErrAdmissionConflict)
	}
	return AdmissionProjection{
		Valid:           true,
		Phase:           phase,
		SlotID:          ref.SlotID,
		FullCharge:      stateResourceProjection(ref.FullCharge),
		LedgerCharge:    stateResourceProjection(ref.LedgerCharge),
		LedgerCreatedAt: ref.LedgerCreatedAt,
		LedgerEverUsed:  ref.LedgerEverUsed,
	}, nil
}

func controllerAdmissionProjection(
	key controller.AssignmentKey,
	projection AdmissionProjection,
) (controller.AdmissionReference, error) {
	if !projection.Valid {
		return controller.AdmissionReference{}, nil
	}
	var phase controller.AdmissionPhase
	switch projection.Phase {
	case AdmissionQueued:
		phase = controller.AdmissionQueued
	case AdmissionReserved:
		phase = controller.AdmissionReserved
	case AdmissionActive:
		phase = controller.AdmissionActive
	default:
		return controller.AdmissionReference{}, fmt.Errorf(
			"%w: invalid durable admission phase",
			controller.ErrDurableIdentityConflict,
		)
	}
	return controller.AdmissionReference{
		Key:             key,
		Phase:           phase,
		SlotID:          projection.SlotID,
		FullCharge:      controllerResourceProjection(projection.FullCharge),
		LedgerCharge:    controllerResourceProjection(projection.LedgerCharge),
		LedgerCreatedAt: projection.LedgerCreatedAt,
		LedgerEverUsed:  projection.LedgerEverUsed,
	}, nil
}

func stateResourceProjection(value controller.ResourceProjection) ResourceProjection {
	return ResourceProjection{
		MilliCPU:          value.MilliCPU,
		MemoryBytes:       value.MemoryBytes,
		PIDs:              value.PIDs,
		FileDescriptors:   value.FileDescriptors,
		TmpfsBytes:        value.TmpfsBytes,
		ScratchBytes:      value.ScratchBytes,
		SocketStateBytes:  value.SocketStateBytes,
		DurableStateBytes: value.DurableStateBytes,
		Inodes:            value.Inodes,
	}
}

func controllerResourceProjection(value ResourceProjection) controller.ResourceProjection {
	return controller.ResourceProjection{
		MilliCPU:          value.MilliCPU,
		MemoryBytes:       value.MemoryBytes,
		PIDs:              value.PIDs,
		FileDescriptors:   value.FileDescriptors,
		TmpfsBytes:        value.TmpfsBytes,
		ScratchBytes:      value.ScratchBytes,
		SocketStateBytes:  value.SocketStateBytes,
		DurableStateBytes: value.DurableStateBytes,
		Inodes:            value.Inodes,
	}
}

func controllerMessageAckState(state AckState) (controller.MessageAckState, error) {
	switch state {
	case AckPersisted:
		return controller.MessageAckPersisted, nil
	case AckStarted:
		return controller.MessageAckStarted, nil
	case AckRedeliveryProven:
		return controller.MessageAckRedeliveryProven, nil
	case AckConfirmed:
		return controller.MessageAckConfirmed, nil
	default:
		return 0, fmt.Errorf("%w: invalid durable acknowledgement state", controller.ErrAckUncertain)
	}
}

func controllerOfferDisposition(value OfferDisposition) (controller.OfferDisposition, error) {
	switch value {
	case OfferInserted:
		return controller.OfferInserted, nil
	case OfferActiveReplay:
		return controller.OfferActiveReplay, nil
	case OfferTerminalReplay:
		return controller.OfferTerminalReplay, nil
	default:
		return 0, fmt.Errorf("%w: invalid durable offer disposition", controller.ErrDurableIdentityConflict)
	}
}

func controllerHostedEffectState(state EffectState) (controller.HostedEffectState, error) {
	switch state {
	case EffectAbsent:
		return controller.HostedEffectAbsent, nil
	case EffectPending:
		return controller.HostedEffectPending, nil
	case EffectCompleted:
		return controller.HostedEffectCompleted, nil
	case EffectFailed:
		return controller.HostedEffectFailed, nil
	default:
		return 0, fmt.Errorf("%w: invalid durable effect state", controller.ErrDurableIdentityConflict)
	}
}

func controllerHostedFailure(
	state EffectState,
	reasonCode string,
) (controller.HostedFailure, error) {
	switch state {
	case EffectAbsent, EffectPending, EffectCompleted:
		if reasonCode != "" {
			return 0, fmt.Errorf("%w: unexpected durable hosted failure reason", controller.ErrDurableIdentityConflict)
		}
		return 0, nil
	case EffectFailed:
		if reasonCode != hostedRouteFailureReason {
			return 0, fmt.Errorf("%w: unknown durable hosted failure reason", controller.ErrDurableIdentityConflict)
		}
		return controller.HostedFailureRouteRejected, nil
	default:
		return 0, fmt.Errorf("%w: invalid durable hosted failure state", controller.ErrDurableIdentityConflict)
	}
}

func mapControllerStateError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrIdentityConflict):
		return fmt.Errorf("%w: durable tuple mismatch", controller.ErrDurableIdentityConflict)
	case errors.Is(err, ErrHistoryBudget):
		return fmt.Errorf("%w: durable history bound reached", controller.ErrHistoryUnavailable)
	case errors.Is(err, ErrReplayEvidence):
		return fmt.Errorf("%w: durable replay evidence missing", controller.ErrReplayUnavailable)
	case errors.Is(err, ErrAckUncertain):
		return fmt.Errorf("%w: durable acknowledgement outcome unresolved", controller.ErrAckUncertain)
	case errors.Is(err, ErrAckConfirmed):
		return fmt.Errorf("%w: durable acknowledgement already confirmed", controller.ErrAckConfirmed)
	default:
		return fmt.Errorf("%w: durable store operation failed", controller.ErrHistoryUnavailable)
	}
}
