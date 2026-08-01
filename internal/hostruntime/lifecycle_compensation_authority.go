package hostruntime

import (
	"context"
	"errors"
)

var ErrLifecycleCompensationAuthority = errors.New(
	"hostruntime: compensation authority failed",
)

type lifecycleCompensationAuthority struct {
	store *LifecycleStore
}

// NewLifecycleCompensationAuthority returns the sole production authority
// that can mint the package-opaque compensation authorization. It proves the
// source against the exact durable receipt chain in store.
func NewLifecycleCompensationAuthority(
	store *LifecycleStore,
) (LifecycleCompensationAuthority, error) {
	if store == nil {
		return nil, ErrLifecycleCompensationAuthority
	}
	return &lifecycleCompensationAuthority{store: store}, nil
}

func (authority *lifecycleCompensationAuthority) AuthorizeCompensation(
	ctx context.Context,
	binding OperationBinding,
	journal OperationJournal,
	source TargetPostcondition,
) (CompensationAuthorization, error) {
	if authority == nil ||
		authority.store == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		journal.CompensationPath != nil ||
		ValidateOperationJournalAgainstBinding(journal, binding) != nil ||
		ValidateTargetPostconditionAgainstBinding(
			source,
			binding,
			journal.Phase,
		) != nil {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}

	path, ok := selectLifecycleCompensationPath(binding, journal.Phase)
	if !ok {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}

	engine := LifecycleEngine{Store: authority.store}
	effectKey, err := DeriveOperationEffectKey(binding, journal.Phase)
	if err != nil {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}
	receiptDocument, err := authority.store.ReadCanonical(
		LifecycleReceipts,
		lifecycleReceiptName(effectKey),
		maxLifecycleReceiptBytes,
	)
	if err != nil {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}
	receipt, _, err := ParseOperationReceipt(
		receiptDocument,
		maxLifecycleReceiptBytes,
	)
	if err != nil || receipt.State != ReceiptStateApplied {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}
	persisted, err := engine.validateAppliedPhase(
		binding,
		receipt,
		receiptDocument,
	)
	if err != nil || !sameTargetState(persisted, source) {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}

	_, sourceProofDigest, err := MarshalTargetPostcondition(source)
	if err != nil {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}
	receiptDigest, sourcePhase, err := engine.compensationSourceAnchor(
		binding,
		path,
	)
	if err != nil || sourcePhase != journal.Phase {
		return CompensationAuthorization{},
			ErrLifecycleCompensationAuthority
	}
	return CompensationAuthorization{
		path:                path,
		sourcePhase:         sourcePhase,
		sourceProofDigest:   sourceProofDigest,
		sourceReceiptDigest: receiptDigest,
	}, nil
}

func selectLifecycleCompensationPath(
	binding OperationBinding,
	phase OperationPhase,
) (CompensationPath, bool) {
	paths := [...]CompensationPath{
		CompensationInstallGreenfieldPreHandoff,
		CompensationInstallGreenfieldPostHandoff,
		CompensationInstallGreenfieldPostSelection,
		CompensationInstallUpgradePreSelection,
		CompensationInstallUpgradePostSelection,
		CompensationInstallLegacyPreSelection,
		CompensationInstallLegacyPostSelection,
		CompensationSuspendExpiredAtNone,
		CompensationResumePreHandoff,
		CompensationResumePostHandoff,
		CompensationRollbackPreLegacyHandoff,
		CompensationRollbackPostLegacyHandoff,
	}
	var selected CompensationPath
	matches := 0
	for _, path := range paths {
		if compensationAllowedForBinding(path, binding) &&
			sourcePhaseAllowed(path, phase) {
			selected = path
			matches++
		}
	}
	return selected, matches == 1
}

var _ LifecycleCompensationAuthority = (*lifecycleCompensationAuthority)(nil)
