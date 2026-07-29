package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	operationJournalSchemaVersion = uint32(1)
	operationJournalDomain        = "portable-ghar-operation-journal-v1"
)

var ErrInvalidOperationJournal = errors.New("hostruntime: invalid operation journal")

type OperationPhase string
type CompensationPath string

const (
	OperationPhasePrepared                    OperationPhase = "prepared"
	OperationPhasePreflightProven             OperationPhase = "preflight-proven"
	OperationPhaseCandidateStaged             OperationPhase = "candidate-staged"
	OperationPhaseCandidateSmoked             OperationPhase = "candidate-smoked"
	OperationPhasePriorRetained               OperationPhase = "prior-retained"
	OperationPhaseDispositionGreenfieldProven OperationPhase = "disposition-greenfield-proven"
	OperationPhasePriorAbsenceProven          OperationPhase = "prior-absence-proven"
	OperationPhaseDispositionUpgradeProven    OperationPhase = "disposition-upgrade-proven"
	OperationPhasePriorAcquisitionDisabled    OperationPhase = "prior-acquisition-disabled"
	OperationPhasePriorDrained                OperationPhase = "prior-drained"
	OperationPhasePriorControllerStopped      OperationPhase = "prior-controller-stopped"
	OperationPhasePriorQuiescenceProven       OperationPhase = "prior-quiescence-proven"
	OperationPhaseFencePortableProven         OperationPhase = "fence-portable-proven"
	OperationPhaseDispositionLegacyProven     OperationPhase = "disposition-legacy-proven"
	OperationPhaseLegacyAcquisitionDisabled   OperationPhase = "legacy-acquisition-disabled"
	OperationPhaseLegacyDrained               OperationPhase = "legacy-drained"
	OperationPhaseLegacyControllerStopped     OperationPhase = "legacy-controller-stopped"
	OperationPhaseLegacyQuiescenceProven      OperationPhase = "legacy-quiescence-proven"
	OperationPhaseFenceLegacyProven           OperationPhase = "fence-legacy-proven"
	OperationPhaseLegacyNormalizedProven      OperationPhase = "legacy-normalized-proven"
	OperationPhaseWatchdogInstalled           OperationPhase = "watchdog-installed"
	OperationPhasePolicyDisabled              OperationPhase = "policy-disabled"
	OperationPhaseObserverStarted             OperationPhase = "observer-started"
	OperationPhaseZeroProven                  OperationPhase = "zero-proven"
	OperationPhaseCurrentSelected             OperationPhase = "current-selected"
	OperationPhaseVerified                    OperationPhase = "verified"
	OperationPhaseComplete                    OperationPhase = "complete"
	OperationPhaseHoldProven                  OperationPhase = "hold-proven"
	OperationPhaseWatchdogDisabled            OperationPhase = "watchdog-disabled"
	OperationPhaseDrained                     OperationPhase = "drained"
	OperationPhaseControllerStopped           OperationPhase = "controller-stopped"
	OperationPhaseQuiescenceProven            OperationPhase = "quiescence-proven"
	OperationPhaseFenceNone                   OperationPhase = "fence-none"
	OperationPhaseStoppedProven               OperationPhase = "stopped-proven"
	OperationPhaseFencePortable               OperationPhase = "fence-portable"
	OperationPhaseLegacyRestored              OperationPhase = "legacy-restored"
	OperationPhaseFenceLegacy                 OperationPhase = "fence-legacy"
	OperationPhaseLegacyStarted               OperationPhase = "legacy-started"
	OperationPhaseWatchdogRemoved             OperationPhase = "watchdog-removed"
	OperationPhaseControllerRemoved           OperationPhase = "controller-removed"
	OperationPhaseRegistrationRemoved         OperationPhase = "registration-removed"
	OperationPhaseRetentionProven             OperationPhase = "retention-proven"

	OperationPhaseCGPreStarted             OperationPhase = "cg-pre-started"
	OperationPhaseCGPreCandidateStopped    OperationPhase = "cg-pre-candidate-stopped"
	OperationPhaseCGPreCandidateRemoved    OperationPhase = "cg-pre-candidate-removed"
	OperationPhaseCGPreAbsenceProven       OperationPhase = "cg-pre-absence-proven"
	OperationPhaseCompGreenfieldAbsent     OperationPhase = "compensated-greenfield-absent"
	OperationPhaseCGFenceStarted           OperationPhase = "cg-fence-started"
	OperationPhaseCGFenceObserverStopped   OperationPhase = "cg-fence-observer-stopped"
	OperationPhaseCGFenceQuiescenceProven  OperationPhase = "cg-fence-quiescence-proven"
	OperationPhaseCGFenceNone              OperationPhase = "cg-fence-none"
	OperationPhaseCGFenceCandidateRemoved  OperationPhase = "cg-fence-candidate-removed"
	OperationPhaseCompGreenfieldNone       OperationPhase = "compensated-greenfield-none"
	OperationPhaseCGSelectStarted          OperationPhase = "cg-select-started"
	OperationPhaseCGSelectObserverStopped  OperationPhase = "cg-select-observer-stopped"
	OperationPhaseCGSelectQuiescenceProven OperationPhase = "cg-select-quiescence-proven"
	OperationPhaseCGSelectCurrentRemoved   OperationPhase = "cg-select-current-removed"
	OperationPhaseCGSelectNone             OperationPhase = "cg-select-none"
	OperationPhaseCGSelectCandidateRemoved OperationPhase = "cg-select-candidate-removed"
	OperationPhaseCompGreenfieldSelected   OperationPhase = "compensated-greenfield-selected-none"

	OperationPhaseCUPreStarted                 OperationPhase = "cu-pre-started"
	OperationPhaseCUPreCandidateStopped        OperationPhase = "cu-pre-candidate-stopped"
	OperationPhaseCUPreCandidateRemoved        OperationPhase = "cu-pre-candidate-removed"
	OperationPhaseCUPrePriorSelectionProven    OperationPhase = "cu-pre-prior-selection-proven"
	OperationPhaseCUPrePriorDisabledProven     OperationPhase = "cu-pre-prior-disabled-proven"
	OperationPhaseCompUpgradePrior             OperationPhase = "compensated-upgrade-prior"
	OperationPhaseCUSelectStarted              OperationPhase = "cu-select-started"
	OperationPhaseCUSelectObserverStopped      OperationPhase = "cu-select-observer-stopped"
	OperationPhaseCUSelectQuiescenceProven     OperationPhase = "cu-select-quiescence-proven"
	OperationPhaseCUSelectPriorRestored        OperationPhase = "cu-select-prior-restored"
	OperationPhaseCUSelectPriorObserverStarted OperationPhase = "cu-select-prior-observer-started-disabled"
	OperationPhaseCUSelectPriorZeroProven      OperationPhase = "cu-select-prior-zero-proven"
	OperationPhaseCUSelectCandidateRemoved     OperationPhase = "cu-select-candidate-removed"
	OperationPhaseCompUpgradeRestored          OperationPhase = "compensated-upgrade-restored"

	OperationPhaseCLPreStarted              OperationPhase = "cl-pre-started"
	OperationPhaseCLPreCandidateStopped     OperationPhase = "cl-pre-candidate-stopped"
	OperationPhaseCLPreCandidateRemoved     OperationPhase = "cl-pre-candidate-removed"
	OperationPhaseCLPrePriorSelectionProven OperationPhase = "cl-pre-prior-selection-proven"
	OperationPhaseCLPreLegacyZeroProven     OperationPhase = "cl-pre-legacy-zero-proven"
	OperationPhaseCompLegacyPrior           OperationPhase = "compensated-legacy-prior"
	OperationPhaseCLSelectStarted           OperationPhase = "cl-select-started"
	OperationPhaseCLSelectObserverStopped   OperationPhase = "cl-select-observer-stopped"
	OperationPhaseCLSelectQuiescenceProven  OperationPhase = "cl-select-quiescence-proven"
	OperationPhaseCLSelectPriorRestored     OperationPhase = "cl-select-prior-restored"
	OperationPhaseCLSelectLegacyStarted     OperationPhase = "cl-select-legacy-started-disabled"
	OperationPhaseCLSelectLegacyZeroProven  OperationPhase = "cl-select-legacy-zero-proven"
	OperationPhaseCLSelectCandidateRemoved  OperationPhase = "cl-select-candidate-removed"
	OperationPhaseCompLegacyRestored        OperationPhase = "compensated-legacy-restored"

	OperationPhaseCSNoneStarted           OperationPhase = "cs-none-started"
	OperationPhaseCSNoneDisabledProven    OperationPhase = "cs-none-disabled-proven"
	OperationPhaseCSNoneQuiescenceProven  OperationPhase = "cs-none-quiescence-proven"
	OperationPhaseCompSuspendNone         OperationPhase = "compensated-suspend-none"
	OperationPhaseCRPreStarted            OperationPhase = "cr-pre-started"
	OperationPhaseCRPreObserverAbsent     OperationPhase = "cr-pre-observer-absent"
	OperationPhaseCRPreWatchdogAbsent     OperationPhase = "cr-pre-watchdog-absent"
	OperationPhaseCRPreNoneDisabledProven OperationPhase = "cr-pre-none-disabled-proven"
	OperationPhaseCompResumeNone          OperationPhase = "compensated-resume-none"
	OperationPhaseCRPostStarted           OperationPhase = "cr-post-started"
	OperationPhaseCRPostObserverStopped   OperationPhase = "cr-post-observer-stopped"
	OperationPhaseCRPostQuiescenceProven  OperationPhase = "cr-post-quiescence-proven"
	OperationPhaseCRPostNone              OperationPhase = "cr-post-none"
	OperationPhaseCRPostWatchdogAbsent    OperationPhase = "cr-post-watchdog-absent"
	OperationPhaseCBPreStarted            OperationPhase = "cb-pre-started"
	OperationPhaseCBPreNoneProven         OperationPhase = "cb-pre-none-proven"
	OperationPhaseCompRollbackNone        OperationPhase = "compensated-rollback-none"
	OperationPhaseCBPostStarted           OperationPhase = "cb-post-started"
	OperationPhaseCBPostLegacyStopped     OperationPhase = "cb-post-legacy-stopped"
	OperationPhaseCBPostQuiescenceProven  OperationPhase = "cb-post-legacy-quiescence-proven"
	OperationPhaseCBPostNone              OperationPhase = "cb-post-none"
	OperationPhaseCompRollbackLegacyNone  OperationPhase = "compensated-rollback-legacy-none"
)

const (
	CompensationInstallGreenfieldPreHandoff    CompensationPath = "install-greenfield-pre-handoff"
	CompensationInstallGreenfieldPostHandoff   CompensationPath = "install-greenfield-post-handoff"
	CompensationInstallGreenfieldPostSelection CompensationPath = "install-greenfield-post-selection"
	CompensationInstallUpgradePreSelection     CompensationPath = "install-upgrade-pre-selection"
	CompensationInstallUpgradePostSelection    CompensationPath = "install-upgrade-post-selection"
	CompensationInstallLegacyPreSelection      CompensationPath = "install-legacy-pre-selection"
	CompensationInstallLegacyPostSelection     CompensationPath = "install-legacy-post-selection"
	CompensationSuspendExpiredAtNone           CompensationPath = "suspend-expired-at-none"
	CompensationResumePreHandoff               CompensationPath = "resume-pre-handoff"
	CompensationResumePostHandoff              CompensationPath = "resume-post-handoff"
	CompensationRollbackPreLegacyHandoff       CompensationPath = "rollback-pre-legacy-handoff"
	CompensationRollbackPostLegacyHandoff      CompensationPath = "rollback-post-legacy-handoff"
)

type OperationJournal struct {
	SchemaVersion      uint32            `json:"schema_version"`
	OperationID        string            `json:"operation_id"`
	BindingDigest      string            `json:"binding_digest"`
	Kind               OperationKind     `json:"kind"`
	Phase              OperationPhase    `json:"phase"`
	CompensationPath   *CompensationPath `json:"compensation_path"`
	ExpectedGeneration uint64            `json:"expected_generation"`
	PriorManifest      *RuntimeManifest  `json:"prior_manifest"`
	TargetManifest     *RuntimeManifest  `json:"target_manifest"`
	TargetFleet        fleetfence.Fleet  `json:"target_fleet"`
	StartedAt          time.Time         `json:"started_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

var compensationPhaseSequences = map[CompensationPath][]OperationPhase{
	CompensationInstallGreenfieldPreHandoff: {
		OperationPhaseCGPreStarted, OperationPhaseCGPreCandidateStopped,
		OperationPhaseCGPreCandidateRemoved, OperationPhaseCGPreAbsenceProven,
		OperationPhaseCompGreenfieldAbsent,
	},
	CompensationInstallGreenfieldPostHandoff: {
		OperationPhaseCGFenceStarted, OperationPhaseCGFenceObserverStopped,
		OperationPhaseCGFenceQuiescenceProven, OperationPhaseCGFenceNone,
		OperationPhaseCGFenceCandidateRemoved, OperationPhaseCompGreenfieldNone,
	},
	CompensationInstallGreenfieldPostSelection: {
		OperationPhaseCGSelectStarted, OperationPhaseCGSelectObserverStopped,
		OperationPhaseCGSelectQuiescenceProven, OperationPhaseCGSelectCurrentRemoved,
		OperationPhaseCGSelectNone, OperationPhaseCGSelectCandidateRemoved,
		OperationPhaseCompGreenfieldSelected,
	},
	CompensationInstallUpgradePreSelection: {
		OperationPhaseCUPreStarted, OperationPhaseCUPreCandidateStopped,
		OperationPhaseCUPreCandidateRemoved, OperationPhaseCUPrePriorSelectionProven,
		OperationPhaseCUPrePriorDisabledProven, OperationPhaseCompUpgradePrior,
	},
	CompensationInstallUpgradePostSelection: {
		OperationPhaseCUSelectStarted, OperationPhaseCUSelectObserverStopped,
		OperationPhaseCUSelectQuiescenceProven, OperationPhaseCUSelectPriorRestored,
		OperationPhaseCUSelectPriorObserverStarted, OperationPhaseCUSelectPriorZeroProven,
		OperationPhaseCUSelectCandidateRemoved, OperationPhaseCompUpgradeRestored,
	},
	CompensationInstallLegacyPreSelection: {
		OperationPhaseCLPreStarted, OperationPhaseCLPreCandidateStopped,
		OperationPhaseCLPreCandidateRemoved, OperationPhaseCLPrePriorSelectionProven,
		OperationPhaseCLPreLegacyZeroProven, OperationPhaseCompLegacyPrior,
	},
	CompensationInstallLegacyPostSelection: {
		OperationPhaseCLSelectStarted, OperationPhaseCLSelectObserverStopped,
		OperationPhaseCLSelectQuiescenceProven, OperationPhaseCLSelectPriorRestored,
		OperationPhaseCLSelectLegacyStarted, OperationPhaseCLSelectLegacyZeroProven,
		OperationPhaseCLSelectCandidateRemoved, OperationPhaseCompLegacyRestored,
	},
	CompensationSuspendExpiredAtNone: {
		OperationPhaseCSNoneStarted, OperationPhaseCSNoneDisabledProven,
		OperationPhaseCSNoneQuiescenceProven, OperationPhaseCompSuspendNone,
	},
	CompensationResumePreHandoff: {
		OperationPhaseCRPreStarted, OperationPhaseCRPreObserverAbsent,
		OperationPhaseCRPreWatchdogAbsent, OperationPhaseCRPreNoneDisabledProven,
		OperationPhaseCompResumeNone,
	},
	CompensationResumePostHandoff: {
		OperationPhaseCRPostStarted, OperationPhaseCRPostObserverStopped,
		OperationPhaseCRPostQuiescenceProven, OperationPhaseCRPostNone,
		OperationPhaseCRPostWatchdogAbsent, OperationPhaseCompResumeNone,
	},
	CompensationRollbackPreLegacyHandoff: {
		OperationPhaseCBPreStarted, OperationPhaseCBPreNoneProven,
		OperationPhaseCompRollbackNone,
	},
	CompensationRollbackPostLegacyHandoff: {
		OperationPhaseCBPostStarted, OperationPhaseCBPostLegacyStopped,
		OperationPhaseCBPostQuiescenceProven, OperationPhaseCBPostNone,
		OperationPhaseCompRollbackLegacyNone,
	},
}

func ParseOperationJournal(document []byte, maxBytes int) (OperationJournal, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return OperationJournal{}, "", ErrInvalidOperationJournal
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var journal OperationJournal
	if err := decoder.Decode(&journal); err != nil {
		return OperationJournal{}, "", ErrInvalidOperationJournal
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OperationJournal{}, "", ErrInvalidOperationJournal
	}
	if err := validateOperationJournal(journal); err != nil {
		return OperationJournal{}, "", err
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(canonical, document) {
		return OperationJournal{}, "", ErrInvalidOperationJournal
	}
	return journal, canonicalArtifactDigest(operationJournalDomain, canonical), nil
}

func MarshalOperationJournal(journal OperationJournal) ([]byte, string, error) {
	if err := validateOperationJournal(journal); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(journal)
	if err != nil {
		return nil, "", ErrInvalidOperationJournal
	}
	return canonical, canonicalArtifactDigest(operationJournalDomain, canonical), nil
}

func ValidateOperationJournalAgainstBinding(
	journal OperationJournal,
	binding OperationBinding,
) error {
	if err := validateOperationJournal(journal); err != nil {
		return err
	}
	bindingBytes, bindingDigest, err := MarshalOperationBinding(binding)
	if err != nil || len(bindingBytes) == 0 ||
		journal.OperationID != binding.OperationID ||
		journal.BindingDigest != bindingDigest ||
		journal.Kind != binding.Kind ||
		journal.ExpectedGeneration != binding.ExpectedGeneration ||
		journal.TargetFleet != binding.TargetFleet {
		return ErrInvalidOperationJournal
	}
	if !manifestPointerMatchesDigest(journal.PriorManifest, binding.PriorManifestDigest) ||
		!manifestPointerMatchesDigest(journal.TargetManifest, binding.TargetManifestDigest) {
		return ErrInvalidOperationJournal
	}
	sequence, ok := normalPhaseSequence(binding)
	if !ok {
		return ErrInvalidOperationJournal
	}
	if journal.CompensationPath == nil {
		if phaseIndex(sequence, journal.Phase) < 0 {
			return ErrInvalidOperationJournal
		}
		return nil
	}
	compensation, ok := compensationPhaseSequences[*journal.CompensationPath]
	if !ok || phaseIndex(compensation, journal.Phase) < 0 ||
		!compensationAllowedForBinding(*journal.CompensationPath, binding) {
		return ErrInvalidOperationJournal
	}
	return nil
}

func ValidateOperationJournalTransition(
	current OperationJournal,
	next OperationJournal,
	binding OperationBinding,
	allowedCompensation *CompensationPath,
) error {
	if err := ValidateOperationJournalAgainstBinding(current, binding); err != nil {
		return err
	}
	if err := ValidateOperationJournalAgainstBinding(next, binding); err != nil {
		return err
	}
	currentBytes, _, _ := MarshalOperationJournal(current)
	nextBytes, _, _ := MarshalOperationJournal(next)
	if bytes.Equal(currentBytes, nextBytes) {
		return nil
	}
	if !sameJournalIdentity(current, next) ||
		next.UpdatedAt.Before(current.UpdatedAt) ||
		next.UpdatedAt.Equal(current.UpdatedAt) {
		return ErrInvalidOperationJournal
	}

	if current.CompensationPath == nil && next.CompensationPath == nil {
		sequence, _ := normalPhaseSequence(binding)
		return requireAdjacentPhase(sequence, current.Phase, next.Phase)
	}
	if current.CompensationPath == nil && next.CompensationPath != nil {
		path := *next.CompensationPath
		sequence := compensationPhaseSequences[path]
		if allowedCompensation == nil ||
			*allowedCompensation != path ||
			len(sequence) == 0 ||
			next.Phase != sequence[0] ||
			!sourcePhaseAllowed(path, current.Phase) {
			return ErrInvalidOperationJournal
		}
		return nil
	}
	if current.CompensationPath == nil ||
		next.CompensationPath == nil ||
		*current.CompensationPath != *next.CompensationPath {
		return ErrInvalidOperationJournal
	}
	return requireAdjacentPhase(
		compensationPhaseSequences[*current.CompensationPath],
		current.Phase,
		next.Phase,
	)
}

func validateOperationJournal(journal OperationJournal) error {
	if journal.SchemaVersion != operationJournalSchemaVersion ||
		!isLowerHex64(journal.OperationID) ||
		!isLowerHex64(journal.BindingDigest) ||
		!validOperationKind(journal.Kind) ||
		!validFleet(journal.TargetFleet) ||
		journal.StartedAt.IsZero() ||
		journal.UpdatedAt.IsZero() ||
		journal.UpdatedAt.Before(journal.StartedAt) ||
		!utcTime(journal.StartedAt) ||
		!utcTime(journal.UpdatedAt) {
		return ErrInvalidOperationJournal
	}
	if journal.PriorManifest != nil {
		if _, _, err := MarshalRuntimeManifest(*journal.PriorManifest); err != nil {
			return ErrInvalidOperationJournal
		}
	}
	if journal.TargetManifest != nil {
		if _, _, err := MarshalRuntimeManifest(*journal.TargetManifest); err != nil {
			return ErrInvalidOperationJournal
		}
	}
	if journal.CompensationPath == nil {
		if !knownNormalPhase(journal.Kind, journal.Phase) {
			return ErrInvalidOperationJournal
		}
		return nil
	}
	sequence, ok := compensationPhaseSequences[*journal.CompensationPath]
	if !ok || phaseIndex(sequence, journal.Phase) < 0 {
		return ErrInvalidOperationJournal
	}
	return nil
}

func normalPhaseSequence(binding OperationBinding) ([]OperationPhase, bool) {
	switch binding.Kind {
	case OperationKindInstall:
		if binding.InstallDisposition == nil {
			return nil, false
		}
		prefix := []OperationPhase{
			OperationPhasePrepared,
			OperationPhasePreflightProven,
			OperationPhaseCandidateStaged,
			OperationPhaseCandidateSmoked,
			OperationPhasePriorRetained,
		}
		var disposition []OperationPhase
		switch *binding.InstallDisposition {
		case InstallDispositionGreenfieldPortable:
			disposition = []OperationPhase{
				OperationPhaseDispositionGreenfieldProven,
				OperationPhasePriorAbsenceProven,
				OperationPhaseFencePortable,
			}
		case InstallDispositionUpgradePortable:
			disposition = []OperationPhase{
				OperationPhaseDispositionUpgradeProven,
				OperationPhasePriorAcquisitionDisabled,
				OperationPhasePriorDrained,
				OperationPhasePriorControllerStopped,
				OperationPhasePriorQuiescenceProven,
				OperationPhaseFencePortableProven,
			}
		case InstallDispositionLegacyDisabledObserver:
			disposition = []OperationPhase{
				OperationPhaseDispositionLegacyProven,
				OperationPhaseLegacyAcquisitionDisabled,
				OperationPhaseLegacyDrained,
				OperationPhaseLegacyControllerStopped,
				OperationPhaseLegacyQuiescenceProven,
				OperationPhaseFenceLegacyProven,
				OperationPhaseLegacyNormalizedProven,
			}
		default:
			return nil, false
		}
		tail := []OperationPhase{
			OperationPhaseWatchdogInstalled,
			OperationPhasePolicyDisabled,
			OperationPhaseObserverStarted,
			OperationPhaseZeroProven,
			OperationPhaseCurrentSelected,
			OperationPhaseVerified,
			OperationPhaseComplete,
		}
		sequence := append(prefix, disposition...)
		return append(sequence, tail...), true
	case OperationKindSuspend:
		return []OperationPhase{
			OperationPhasePrepared, OperationPhaseHoldProven,
			OperationPhaseWatchdogDisabled, OperationPhasePolicyDisabled,
			OperationPhaseDrained, OperationPhaseControllerStopped,
			OperationPhaseQuiescenceProven, OperationPhaseFenceNone,
			OperationPhaseComplete,
		}, true
	case OperationKindResume:
		return []OperationPhase{
			OperationPhasePrepared, OperationPhaseStoppedProven,
			OperationPhasePolicyDisabled, OperationPhaseFencePortable,
			OperationPhaseObserverStarted, OperationPhaseWatchdogInstalled,
			OperationPhaseZeroProven, OperationPhaseComplete,
		}, true
	case OperationKindRollback:
		return []OperationPhase{
			OperationPhasePrepared, OperationPhaseHoldProven,
			OperationPhaseWatchdogDisabled, OperationPhasePolicyDisabled,
			OperationPhaseDrained, OperationPhaseControllerStopped,
			OperationPhaseQuiescenceProven, OperationPhaseFenceNone,
			OperationPhaseLegacyRestored, OperationPhaseFenceLegacy,
			OperationPhaseLegacyStarted, OperationPhaseComplete,
		}, true
	case OperationKindUninstall:
		return []OperationPhase{
			OperationPhasePrepared, OperationPhaseQuiescenceProven,
			OperationPhaseWatchdogRemoved, OperationPhaseControllerRemoved,
			OperationPhaseRegistrationRemoved, OperationPhaseRetentionProven,
			OperationPhaseComplete,
		}, true
	default:
		return nil, false
	}
}

func knownNormalPhase(kind OperationKind, phase OperationPhase) bool {
	bindings := representativeBindings(kind)
	for _, binding := range bindings {
		sequence, ok := normalPhaseSequence(binding)
		if ok && phaseIndex(sequence, phase) >= 0 {
			return true
		}
	}
	return false
}

func representativeBindings(kind OperationKind) []OperationBinding {
	if kind != OperationKindInstall {
		return []OperationBinding{{Kind: kind}}
	}
	greenfield := InstallDispositionGreenfieldPortable
	upgrade := InstallDispositionUpgradePortable
	legacy := InstallDispositionLegacyDisabledObserver
	return []OperationBinding{
		{Kind: kind, InstallDisposition: &greenfield},
		{Kind: kind, InstallDisposition: &upgrade},
		{Kind: kind, InstallDisposition: &legacy},
	}
}

func manifestPointerMatchesDigest(manifest *RuntimeManifest, digest *string) bool {
	if manifest == nil || digest == nil {
		return manifest == nil && digest == nil
	}
	_, actual, err := MarshalRuntimeManifest(*manifest)
	return err == nil && actual == *digest
}

func sameJournalIdentity(left, right OperationJournal) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.OperationID == right.OperationID &&
		left.BindingDigest == right.BindingDigest &&
		left.Kind == right.Kind &&
		left.ExpectedGeneration == right.ExpectedGeneration &&
		reflect.DeepEqual(left.PriorManifest, right.PriorManifest) &&
		reflect.DeepEqual(left.TargetManifest, right.TargetManifest) &&
		left.TargetFleet == right.TargetFleet &&
		left.StartedAt.Equal(right.StartedAt)
}

func utcTime(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

func phaseIndex(sequence []OperationPhase, phase OperationPhase) int {
	for index, candidate := range sequence {
		if candidate == phase {
			return index
		}
	}
	return -1
}

func requireAdjacentPhase(
	sequence []OperationPhase,
	current OperationPhase,
	next OperationPhase,
) error {
	index := phaseIndex(sequence, current)
	if index < 0 || index+1 >= len(sequence) || sequence[index+1] != next {
		return ErrInvalidOperationJournal
	}
	return nil
}

func compensationAllowedForBinding(path CompensationPath, binding OperationBinding) bool {
	switch path {
	case CompensationInstallGreenfieldPreHandoff,
		CompensationInstallGreenfieldPostHandoff,
		CompensationInstallGreenfieldPostSelection:
		return binding.Kind == OperationKindInstall &&
			binding.InstallDisposition != nil &&
			*binding.InstallDisposition == InstallDispositionGreenfieldPortable
	case CompensationInstallUpgradePreSelection,
		CompensationInstallUpgradePostSelection:
		return binding.Kind == OperationKindInstall &&
			binding.InstallDisposition != nil &&
			*binding.InstallDisposition == InstallDispositionUpgradePortable
	case CompensationInstallLegacyPreSelection,
		CompensationInstallLegacyPostSelection:
		return binding.Kind == OperationKindInstall &&
			binding.InstallDisposition != nil &&
			*binding.InstallDisposition == InstallDispositionLegacyDisabledObserver
	case CompensationSuspendExpiredAtNone:
		return binding.Kind == OperationKindSuspend
	case CompensationResumePreHandoff, CompensationResumePostHandoff:
		return binding.Kind == OperationKindResume
	case CompensationRollbackPreLegacyHandoff, CompensationRollbackPostLegacyHandoff:
		return binding.Kind == OperationKindRollback
	default:
		return false
	}
}

func sourcePhaseAllowed(path CompensationPath, phase OperationPhase) bool {
	var allowed []OperationPhase
	switch path {
	case CompensationInstallGreenfieldPreHandoff:
		allowed = []OperationPhase{
			OperationPhasePrepared, OperationPhasePreflightProven,
			OperationPhaseCandidateStaged, OperationPhaseCandidateSmoked,
			OperationPhasePriorRetained, OperationPhaseDispositionGreenfieldProven,
			OperationPhasePriorAbsenceProven,
		}
	case CompensationInstallGreenfieldPostHandoff:
		allowed = []OperationPhase{
			OperationPhaseFencePortable, OperationPhaseWatchdogInstalled,
			OperationPhasePolicyDisabled, OperationPhaseObserverStarted,
			OperationPhaseZeroProven,
		}
	case CompensationInstallGreenfieldPostSelection:
		allowed = []OperationPhase{OperationPhaseCurrentSelected}
	case CompensationInstallUpgradePreSelection:
		allowed = []OperationPhase{
			OperationPhasePrepared, OperationPhasePreflightProven,
			OperationPhaseCandidateStaged, OperationPhaseCandidateSmoked,
			OperationPhasePriorRetained, OperationPhaseDispositionUpgradeProven,
			OperationPhasePriorAcquisitionDisabled, OperationPhasePriorDrained,
			OperationPhasePriorControllerStopped, OperationPhasePriorQuiescenceProven,
			OperationPhaseFencePortableProven, OperationPhaseWatchdogInstalled,
			OperationPhasePolicyDisabled, OperationPhaseObserverStarted,
			OperationPhaseZeroProven,
		}
	case CompensationInstallUpgradePostSelection:
		allowed = []OperationPhase{OperationPhaseCurrentSelected}
	case CompensationInstallLegacyPreSelection:
		allowed = []OperationPhase{
			OperationPhasePrepared, OperationPhasePreflightProven,
			OperationPhaseCandidateStaged, OperationPhaseCandidateSmoked,
			OperationPhasePriorRetained, OperationPhaseDispositionLegacyProven,
			OperationPhaseLegacyAcquisitionDisabled, OperationPhaseLegacyDrained,
			OperationPhaseLegacyControllerStopped, OperationPhaseLegacyQuiescenceProven,
			OperationPhaseFenceLegacyProven, OperationPhaseLegacyNormalizedProven,
			OperationPhaseWatchdogInstalled, OperationPhasePolicyDisabled,
			OperationPhaseObserverStarted, OperationPhaseZeroProven,
		}
	case CompensationInstallLegacyPostSelection:
		allowed = []OperationPhase{OperationPhaseCurrentSelected}
	case CompensationSuspendExpiredAtNone:
		allowed = []OperationPhase{OperationPhaseFenceNone}
	case CompensationResumePreHandoff:
		allowed = []OperationPhase{
			OperationPhasePrepared, OperationPhaseStoppedProven,
			OperationPhasePolicyDisabled,
		}
	case CompensationResumePostHandoff:
		allowed = []OperationPhase{
			OperationPhaseFencePortable, OperationPhaseObserverStarted,
			OperationPhaseWatchdogInstalled,
		}
	case CompensationRollbackPreLegacyHandoff:
		allowed = []OperationPhase{
			OperationPhasePrepared, OperationPhaseHoldProven,
			OperationPhaseWatchdogDisabled, OperationPhasePolicyDisabled,
			OperationPhaseDrained, OperationPhaseControllerStopped,
			OperationPhaseQuiescenceProven, OperationPhaseFenceNone,
			OperationPhaseLegacyRestored,
		}
	case CompensationRollbackPostLegacyHandoff:
		allowed = []OperationPhase{
			OperationPhaseFenceLegacy, OperationPhaseLegacyStarted,
		}
	default:
		return false
	}
	return phaseIndex(allowed, phase) >= 0
}
