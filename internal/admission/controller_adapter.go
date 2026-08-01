package admission

import (
	"errors"
	"fmt"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

// ControllerAdapter is the checked translation boundary between the
// controller-owned admission port and the Task-4 broker contracts.
type ControllerAdapter struct {
	broker    PolicyBroker
	history   LiveHistory
	templates map[string]RepositoryPolicy
	aliases   []string
}

var _ controller.AdmissionBroker = (*ControllerAdapter)(nil)

func NewControllerAdapter(
	broker PolicyBroker,
	history LiveHistory,
	templates []RepositoryPolicy,
	transientMode TransientMode,
) (*ControllerAdapter, error) {
	if broker == nil || history == nil {
		return nil, fmt.Errorf("%w: nil admission dependency", controller.ErrAdmissionUnavailable)
	}
	policies, aliases, err := validatePolicies(templates, transientMode)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: invalid immutable repository templates",
			controller.ErrAdmissionConflict,
		)
	}
	return &ControllerAdapter{
		broker:    broker,
		history:   history,
		templates: policies,
		aliases:   aliases,
	}, nil
}

func (a *ControllerAdapter) ApplyAcquisitionPolicy(
	policy controller.AcquisitionPolicy,
) error {
	canonical, err := controller.CanonicalizeAcquisitionPolicy(policy)
	if err != nil {
		return fmt.Errorf("%w: invalid acquisition policy", controller.ErrAdmissionConflict)
	}
	if len(canonical.RepositoryPolicies) != len(a.aliases) {
		return fmt.Errorf(
			"%w: repository policy set differs from immutable templates",
			controller.ErrAdmissionConflict,
		)
	}
	overlaid := make([]RepositoryPolicy, 0, len(canonical.RepositoryPolicies))
	seen := make(map[string]struct{}, len(canonical.RepositoryPolicies))
	for _, summary := range canonical.RepositoryPolicies {
		template, ok := a.templates[summary.Alias]
		if !ok {
			return fmt.Errorf(
				"%w: repository policy alias differs from immutable templates",
				controller.ErrAdmissionConflict,
			)
		}
		if _, duplicate := seen[summary.Alias]; duplicate {
			return fmt.Errorf(
				"%w: duplicate repository policy alias",
				controller.ErrAdmissionConflict,
			)
		}
		seen[summary.Alias] = struct{}{}
		var eligibility Eligibility
		switch summary.Eligibility {
		case string(EligibilityActive):
			eligibility = EligibilityActive
		case string(EligibilityArchivedDisabled):
			eligibility = EligibilityArchivedDisabled
		case string(EligibilityPendingReactivation):
			eligibility = EligibilityPendingReactivation
		default:
			return fmt.Errorf(
				"%w: unknown repository eligibility",
				controller.ErrAdmissionConflict,
			)
		}
		template.MaxConcurrency = summary.MaxConcurrency
		template.Eligibility = eligibility
		overlaid = append(overlaid, template)
	}
	return mapControllerAdmissionError(a.broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:             canonical.Epoch,
		EffectiveCapacity: canonical.MaxCapacity,
		Repositories:      overlaid,
	}))
}

func (a *ControllerAdapter) SetDemand(
	repositoryAlias string,
	epoch uint64,
	totalAssignedJobs int,
) error {
	return mapControllerAdmissionError(
		a.broker.SetDemand(repositoryAlias, epoch, totalAssignedJobs),
	)
}

func (a *ControllerAdapter) CapacitySummary() controller.CapacitySummary {
	snapshot := a.broker.CapacitySnapshot()
	return controller.CapacitySummary{
		Epoch:              snapshot.Epoch,
		ConfiguredCapacity: snapshot.ConfiguredCapacity,
		EffectiveCapacity:  snapshot.EffectiveCapacity,
		Occupied:           snapshot.Occupied,
		Available:          snapshot.Available,
		Queued:             snapshot.Queued,
	}
}

func (a *ControllerAdapter) CheckOffer(
	repositoryAlias string,
	offer githubscale.Offer,
) error {
	if repositoryAlias == "" {
		return fmt.Errorf("%w: empty repository alias", controller.ErrAdmissionConflict)
	}
	return mapControllerAdmissionError(a.history.CheckOffer(copyOfferForAlias(offer, repositoryAlias)))
}

func (a *ControllerAdapter) LeasePoll(
	repositoryAlias string,
	at time.Time,
) (controller.PollLease, error) {
	lease, err := a.broker.LeasePoll(repositoryAlias, at)
	if err != nil {
		return controller.PollLease{}, mapControllerAdmissionError(err)
	}
	return controller.PollLease{
		ID:              lease.ID,
		RepositoryAlias: lease.RepositoryAlias,
		Epoch:           lease.Epoch,
		Reserved:        lease.Reserved,
		PollCapacity:    lease.PollCapacity,
		ExpiresAt:       lease.ExpiresAt,
	}, nil
}

func (a *ControllerAdapter) EnsureQueuedBatch(
	epoch uint64,
	repositoryAlias string,
	offers []githubscale.Offer,
) ([]controller.AdmissionReference, error) {
	if repositoryAlias == "" {
		return nil, fmt.Errorf("%w: empty repository alias", controller.ErrAdmissionConflict)
	}
	copied := make([]githubscale.Offer, len(offers))
	originals := make(map[int64]githubscale.Offer, len(offers))
	for i, offer := range offers {
		copied[i] = copyOfferForAlias(offer, repositoryAlias)
		if _, exists := originals[offer.RunnerRequestID]; !exists {
			originals[offer.RunnerRequestID] = cloneControllerOffer(offer)
		}
	}
	refs, err := a.broker.EnsureQueuedBatchAtEpoch(epoch, copied)
	if err != nil {
		return nil, mapControllerAdmissionError(err)
	}
	out := make([]controller.AdmissionReference, 0, len(refs))
	for _, ref := range refs {
		converted, err := controllerAdmissionReference(ref)
		if err != nil {
			return nil, err
		}
		if original, ok := originals[ref.Key.RunnerRequestID]; ok {
			converted.Offer = original
		}
		out = append(out, converted)
	}
	return out, nil
}

func (a *ControllerAdapter) Restore(refs []controller.AdmissionReference) error {
	native := make([]LiveReference, 0, len(refs))
	for _, ref := range refs {
		converted, err := admissionLiveReference(ref)
		if err != nil {
			return err
		}
		native = append(native, converted)
	}
	return mapControllerAdmissionError(a.history.Restore(native))
}

func (a *ControllerAdapter) Admit(
	epoch uint64,
	at time.Time,
) ([]controller.AdmissionDecision, error) {
	decisions, err := a.broker.AdmitAtEpoch(epoch, at)
	if err != nil {
		return nil, mapControllerAdmissionError(err)
	}
	out := make([]controller.AdmissionDecision, 0, len(decisions))
	for _, decision := range decisions {
		ref, present, err := a.history.Reference(decision.Assignment)
		if err != nil {
			return nil, mapControllerAdmissionError(err)
		}
		if !present || ref.Phase != LiveActive || ref.SlotID != decision.SlotID ||
			ref.Key != decision.Assignment {
			return nil, fmt.Errorf(
				"%w: admitted assignment lacks exact active projection",
				controller.ErrAdmissionUnavailable,
			)
		}
		converted, err := controllerAdmissionReference(ref)
		if err != nil {
			return nil, err
		}
		out = append(out, controller.AdmissionDecision{
			Key:        decision.Assignment,
			Projection: converted,
		})
	}
	return out, nil
}

func (a *ControllerAdapter) Reference(
	key controller.AssignmentKey,
) (controller.AdmissionReference, bool, error) {
	ref, present, err := a.history.Reference(key)
	if err != nil {
		return controller.AdmissionReference{}, false, mapControllerAdmissionError(err)
	}
	if !present {
		return controller.AdmissionReference{}, false, nil
	}
	converted, err := controllerAdmissionReference(ref)
	if err != nil {
		return controller.AdmissionReference{}, false, err
	}
	return converted, true, nil
}

func (a *ControllerAdapter) SetPressure(maxCapacity int) (previous, current int, err error) {
	change, err := a.broker.SetPressure(Pressure{MaxCapacity: maxCapacity})
	if err != nil {
		return change.Previous, change.Current, mapControllerAdmissionError(err)
	}
	return change.Previous, change.Current, nil
}

func (a *ControllerAdapter) Release(key controller.AssignmentKey) error {
	return mapControllerAdmissionError(a.broker.Release(key))
}

func (a *ControllerAdapter) Retire(key controller.AssignmentKey) error {
	return mapControllerAdmissionError(a.history.Retire(key))
}

func (a *ControllerAdapter) HasLiveReference(key controller.AssignmentKey) bool {
	return a.history.HasLiveReference(key)
}

func admissionLiveReference(ref controller.AdmissionReference) (LiveReference, error) {
	var phase LivePhase
	switch ref.Phase {
	case controller.AdmissionQueued:
		phase = LiveQueued
	case controller.AdmissionReserved:
		phase = LiveReserved
	case controller.AdmissionActive:
		phase = LiveActive
	default:
		return LiveReference{}, fmt.Errorf("%w: invalid admission phase", controller.ErrAdmissionConflict)
	}
	if ref.Key.RepositoryAlias == "" ||
		ref.Key.RunnerRequestID <= 0 ||
		ref.Offer.RunnerRequestID != ref.Key.RunnerRequestID {
		return LiveReference{}, fmt.Errorf("%w: inconsistent admission identity", controller.ErrAdmissionConflict)
	}
	return LiveReference{
		Key:             ref.Key,
		Offer:           copyOfferForAlias(ref.Offer, ref.Key.RepositoryAlias),
		Phase:           phase,
		SlotID:          CapacitySlotID(ref.SlotID),
		FullCharge:      admissionResources(ref.FullCharge),
		LedgerCharge:    admissionResources(ref.LedgerCharge),
		LedgerCreatedAt: ref.LedgerCreatedAt,
		LedgerEverUsed:  ref.LedgerEverUsed,
	}, nil
}

func controllerAdmissionReference(ref LiveReference) (controller.AdmissionReference, error) {
	var phase controller.AdmissionPhase
	switch ref.Phase {
	case LiveQueued:
		phase = controller.AdmissionQueued
	case LiveReserved:
		phase = controller.AdmissionReserved
	case LiveActive:
		phase = controller.AdmissionActive
	default:
		return controller.AdmissionReference{}, fmt.Errorf(
			"%w: invalid broker admission phase",
			controller.ErrAdmissionUnavailable,
		)
	}
	return controller.AdmissionReference{
		Key:             ref.Key,
		Offer:           cloneControllerOffer(ref.Offer),
		Phase:           phase,
		SlotID:          uint32(ref.SlotID),
		FullCharge:      controllerResources(ref.FullCharge),
		LedgerCharge:    controllerResources(ref.LedgerCharge),
		LedgerCreatedAt: ref.LedgerCreatedAt,
		LedgerEverUsed:  ref.LedgerEverUsed,
	}, nil
}

func copyOfferForAlias(offer githubscale.Offer, alias string) githubscale.Offer {
	copied := cloneControllerOffer(offer)
	copied.RepositoryName = alias
	return copied
}

func cloneControllerOffer(offer githubscale.Offer) githubscale.Offer {
	copied := offer
	copied.RequestLabels = append([]string(nil), offer.RequestLabels...)
	return copied
}

func admissionResources(value controller.ResourceProjection) Resources {
	return Resources{
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

func controllerResources(value Resources) controller.ResourceProjection {
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

func mapControllerAdmissionError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrOfferTooLarge):
		return fmt.Errorf("%w: single offer bound reached", controller.ErrOfferTooLarge)
	case errors.Is(err, ErrLiveSetFull), errors.Is(err, ErrLiveBytesFull):
		return fmt.Errorf("%w: live admission history bound reached", controller.ErrAdmissionHeadroom)
	case errors.Is(err, ErrUnknownRepository),
		errors.Is(err, ErrDuplicateOffer),
		errors.Is(err, ErrOfferConflict),
		errors.Is(err, ErrInvalidOffer),
		errors.Is(err, ErrStalePolicyRevision),
		errors.Is(err, ErrPolicyInUse),
		errors.Is(err, ErrPressureIncrease),
		errors.Is(err, ErrDemandEpochMismatch),
		errors.Is(err, ErrUnknownAssignment),
		errors.Is(err, ErrLiveReferenceActive),
		errors.Is(err, ErrRestoreNotEmpty),
		errors.Is(err, ErrInvalidConfig):
		return fmt.Errorf("%w: broker identity or transition rejected", controller.ErrAdmissionConflict)
	default:
		return fmt.Errorf("%w: broker operation failed", controller.ErrAdmissionUnavailable)
	}
}
