package upgrade

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"time"
)

const (
	journalSchemaVersion = uint32(1)
	journalDigestDomain  = "portable-ghar-runner-upgrade-journal-v1"
)

var (
	ErrInvalidJournal           = errors.New("upgrade: invalid journal")
	ErrInvalidJournalTransition = errors.New(
		"upgrade: invalid journal transition",
	)
)

// JournalPhase is the closed crash-resume phase set for one runner upgrade.
type JournalPhase string

const (
	JournalCurrent               JournalPhase = "current"
	JournalUpgradeRequired       JournalPhase = "upgrade-required"
	JournalDisableApplying       JournalPhase = "disable-applying"
	JournalDisabled              JournalPhase = "disabled"
	JournalStageApplying         JournalPhase = "stage-applying"
	JournalStaged                JournalPhase = "staged"
	JournalQualifyApplying       JournalPhase = "qualify-applying"
	JournalCandidateQualified    JournalPhase = "candidate-qualified"
	JournalPrepareApplying       JournalPhase = "prepare-applying"
	JournalPrepared              JournalPhase = "prepared"
	JournalQuiescenceProving     JournalPhase = "quiescence-proving"
	JournalQuiescent             JournalPhase = "quiescent"
	JournalReplacementValidating JournalPhase = "replacement-validating"
	JournalReplacementValidated  JournalPhase = "replacement-validated"
	JournalSelectApplying        JournalPhase = "select-applying"
	JournalSelectedDisabled      JournalPhase = "selected-disabled"
	JournalCanaryApplying        JournalPhase = "canary-applying"
	JournalCanaryActive          JournalPhase = "canary-active"
	JournalEnableApplying        JournalPhase = "enable-applying"
	JournalEnabled               JournalPhase = "enabled"
	JournalComplete              JournalPhase = "complete"
	JournalCandidateRejected     JournalPhase = "candidate-rejected"
)

// CandidateRejection is deliberately closed and carries no provider text.
type CandidateRejection string

const CandidateRejectionPermanent CandidateRejection = "permanent"

// AuthorizationRecord persists only closed, non-secret directive bindings.
type AuthorizationRecord struct {
	Phase                   RunnerMaintenancePhase `json:"phase"`
	BindingDigest           string                 `json:"binding_digest"`
	EnrollmentBindingDigest string                 `json:"enrollment_binding_digest"`
	EnrollmentEpoch         uint64                 `json:"enrollment_epoch"`
	ControlSequence         uint64                 `json:"control_sequence"`
}

// PolicyProof is the exact acquisition read-back at a journal boundary.
type PolicyProof struct {
	Mode     string `json:"mode"`
	Epoch    uint64 `json:"epoch"`
	Digest   string `json:"digest"`
	Capacity uint64 `json:"capacity"`
}

// Journal is the private, canonical, crash-resume record for one operation.
// It intentionally contains no response MAC, raw directive, provider text,
// command, path, or secret.
type Journal struct {
	SchemaVersion         uint32               `json:"schema_version"`
	Generation            uint64               `json:"generation"`
	ObservationSequence   uint64               `json:"observation_sequence"`
	Phase                 JournalPhase         `json:"phase"`
	ConfigurationRevision uint64               `json:"configuration_revision"`
	ConfigurationBinding  string               `json:"configuration_binding"`
	Selected              Selection            `json:"selected"`
	Observed              RunnerRelease        `json:"observed"`
	Candidate             *Candidate           `json:"candidate,omitempty"`
	Stage                 *StageObservation    `json:"stage,omitempty"`
	Qualified             *CompatibilityReport `json:"qualified,omitempty"`
	Quiescence            *Quiescence          `json:"quiescence,omitempty"`
	Replacement           *CompatibilityReport `json:"replacement,omitempty"`
	Policy                *PolicyProof         `json:"policy,omitempty"`
	Authorization         *AuthorizationRecord `json:"authorization,omitempty"`
	Rejection             *CandidateRejection  `json:"rejection,omitempty"`
	UpdatedAt             time.Time            `json:"updated_at"`
}

// MarshalJournal validates, canonically encodes, and domain-separates one
// journal document.
func MarshalJournal(journal Journal) ([]byte, string, error) {
	if err := journal.validate(); err != nil {
		return nil, "", err
	}
	document, err := json.Marshal(journal)
	if err != nil {
		return nil, "", ErrInvalidJournal
	}
	return document, journalDigest(document), nil
}

// ParseJournal accepts only the byte-exact canonical journal representation.
func ParseJournal(
	document []byte,
	maxBytes int,
) (Journal, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return Journal{}, "", ErrInvalidJournal
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var journal Journal
	if err := decoder.Decode(&journal); err != nil {
		return Journal{}, "", ErrInvalidJournal
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Journal{}, "", ErrInvalidJournal
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(canonical, document) {
		return Journal{}, "", ErrInvalidJournal
	}
	if err := journal.validate(); err != nil {
		return Journal{}, "", err
	}
	return journal, journalDigest(document), nil
}

func journalDigest(document []byte) string {
	hash := sha256.New()
	writeEvidenceField(hash, []byte(journalDigestDomain))
	writeEvidenceField(hash, document)
	return hex.EncodeToString(hash.Sum(nil))
}

func (journal Journal) validate() error {
	if journal.SchemaVersion != journalSchemaVersion ||
		journal.Generation == 0 ||
		journal.ObservationSequence == 0 ||
		journal.ConfigurationRevision == 0 ||
		!validRawDigest(journal.ConfigurationBinding) ||
		journal.Selected.Validate() != nil ||
		journal.Observed.Validate() != nil ||
		!validUTCTime(journal.UpdatedAt) ||
		!validJournalPhase(journal.Phase) {
		return ErrInvalidJournal
	}

	order, err := CompareRunnerVersions(
		journal.Observed.Version,
		journal.Selected.Version,
	)
	if err != nil {
		return ErrInvalidJournal
	}
	selectedPhase := phaseAtLeast(journal.Phase, JournalSelectedDisabled)
	if journal.Phase == JournalCurrent || selectedPhase {
		if order != 0 {
			return ErrInvalidJournal
		}
	} else if order <= 0 {
		return ErrInvalidJournal
	}

	if journal.Phase == JournalCurrent {
		if journal.Candidate != nil ||
			journal.Stage != nil ||
			journal.Qualified != nil ||
			journal.Quiescence != nil ||
			journal.Replacement != nil ||
			journal.Policy != nil ||
			journal.Authorization != nil ||
			journal.Rejection != nil {
			return ErrInvalidJournal
		}
		return nil
	}

	if journal.Phase == JournalUpgradeRequired {
		if journal.Candidate != nil &&
			!candidateMatchesRelease(*journal.Candidate, journal.Observed) {
			return ErrInvalidJournal
		}
		if journal.Stage != nil ||
			journal.Qualified != nil ||
			journal.Quiescence != nil ||
			journal.Replacement != nil ||
			journal.Policy != nil ||
			journal.Authorization != nil ||
			journal.Rejection != nil {
			return ErrInvalidJournal
		}
		return nil
	}

	if journal.Phase == JournalCandidateRejected {
		if journal.Candidate == nil ||
			!candidateMatchesRelease(*journal.Candidate, journal.Observed) ||
			journal.Rejection == nil ||
			*journal.Rejection != CandidateRejectionPermanent ||
			journal.Stage != nil ||
			journal.Qualified != nil ||
			journal.Quiescence != nil ||
			journal.Replacement != nil ||
			journal.Policy != nil ||
			journal.Authorization != nil {
			return ErrInvalidJournal
		}
		return nil
	}

	if journal.Candidate == nil ||
		!candidateMatchesRelease(*journal.Candidate, journal.Observed) ||
		journal.Authorization == nil ||
		validateAuthorization(*journal.Authorization) != nil ||
		journal.Authorization.Phase !=
			authorizationPhaseForJournal(journal.Phase) ||
		journal.Rejection != nil {
		return ErrInvalidJournal
	}
	candidate := *journal.Candidate

	if phaseAtLeast(journal.Phase, JournalStaged) {
		if journal.Stage == nil ||
			journal.Stage.Validate(candidate) != nil {
			return ErrInvalidJournal
		}
	} else if journal.Stage != nil {
		return ErrInvalidJournal
	}
	if phaseAtLeast(journal.Phase, JournalCandidateQualified) {
		if journal.Qualified == nil ||
			journal.Qualified.Validate(candidate) != nil {
			return ErrInvalidJournal
		}
	} else if journal.Qualified != nil {
		return ErrInvalidJournal
	}
	if phaseAtLeast(journal.Phase, JournalQuiescent) {
		if journal.Quiescence == nil ||
			journal.Quiescence.Validate() != nil {
			return ErrInvalidJournal
		}
	} else if journal.Quiescence != nil {
		return ErrInvalidJournal
	}
	if phaseAtLeast(journal.Phase, JournalReplacementValidated) {
		if journal.Replacement == nil ||
			journal.Replacement.Validate(candidate) != nil ||
			!reflect.DeepEqual(journal.Qualified, journal.Replacement) {
			return ErrInvalidJournal
		}
	} else if journal.Replacement != nil {
		return ErrInvalidJournal
	}

	if selectedPhase {
		if !selectionMatchesCandidate(journal.Selected, candidate) {
			return ErrInvalidJournal
		}
	} else if selectionMatchesCandidate(journal.Selected, candidate) {
		return ErrInvalidJournal
	}
	if !validPolicyForPhase(journal.Phase, journal.Policy) {
		return ErrInvalidJournal
	}
	return nil
}

func candidateMatchesRelease(
	candidate Candidate,
	release RunnerRelease,
) bool {
	return candidate.Validate() == nil &&
		candidate.Version == release.Version &&
		candidate.ReleaseEvidenceDigest == release.ObservationEvidence
}

func selectionMatchesCandidate(
	selection Selection,
	candidate Candidate,
) bool {
	return selection.Version == candidate.Version &&
		selection.ManifestDigest == candidate.ManifestDigest &&
		selection.ImageDigest == candidate.ImageDigest
}

func validateAuthorization(record AuthorizationRecord) error {
	if record.Phase == MaintenanceWaitHosted ||
		!validMaintenancePhase(record.Phase) ||
		!validRawDigest(record.BindingDigest) ||
		!validRawDigest(record.EnrollmentBindingDigest) ||
		record.EnrollmentEpoch == 0 ||
		record.ControlSequence == 0 {
		return ErrInvalidJournal
	}
	return nil
}

func validatePolicy(proof *PolicyProof, mode string, capacity uint64) bool {
	if proof == nil ||
		proof.Mode != mode ||
		proof.Capacity != capacity ||
		proof.Epoch == 0 ||
		!validRawDigest(proof.Digest) {
		return false
	}
	return true
}

func validPolicyForPhase(phase JournalPhase, proof *PolicyProof) bool {
	switch phase {
	case JournalDisableApplying:
		return proof == nil
	case JournalDisabled, JournalStageApplying, JournalStaged,
		JournalQualifyApplying, JournalCandidateQualified,
		JournalPrepareApplying, JournalPrepared,
		JournalQuiescenceProving, JournalQuiescent,
		JournalReplacementValidating, JournalReplacementValidated,
		JournalSelectApplying, JournalSelectedDisabled,
		JournalCanaryApplying:
		return validatePolicy(proof, "disabled", 0)
	case JournalCanaryActive, JournalEnableApplying:
		return validatePolicy(proof, "canary-only", 1)
	case JournalEnabled, JournalComplete:
		return proof != nil &&
			proof.Mode == "enabled" &&
			proof.Capacity > 0 &&
			proof.Epoch > 0 &&
			validRawDigest(proof.Digest)
	default:
		return false
	}
}

func validMaintenancePhase(phase RunnerMaintenancePhase) bool {
	switch phase {
	case MaintenanceWaitHosted, MaintenanceStagePermitted,
		MaintenanceReplacePermitted, MaintenanceCanaryPermitted,
		MaintenanceEnablePermitted, MaintenanceComplete:
		return true
	default:
		return false
	}
}

func authorizationPhaseForJournal(
	phase JournalPhase,
) RunnerMaintenancePhase {
	switch phase {
	case JournalDisableApplying, JournalDisabled,
		JournalStageApplying, JournalStaged,
		JournalQualifyApplying, JournalCandidateQualified:
		return MaintenanceStagePermitted
	case JournalPrepareApplying, JournalPrepared,
		JournalQuiescenceProving, JournalQuiescent,
		JournalReplacementValidating, JournalReplacementValidated,
		JournalSelectApplying, JournalSelectedDisabled:
		return MaintenanceReplacePermitted
	case JournalCanaryApplying, JournalCanaryActive:
		return MaintenanceCanaryPermitted
	case JournalEnableApplying, JournalEnabled:
		return MaintenanceEnablePermitted
	case JournalComplete:
		return MaintenanceComplete
	default:
		return ""
	}
}

func validJournalPhase(phase JournalPhase) bool {
	_, ok := journalPhaseIndex[phase]
	return ok || phase == JournalCandidateRejected
}

var journalPhaseIndex = map[JournalPhase]int{
	JournalCurrent:               0,
	JournalUpgradeRequired:       1,
	JournalDisableApplying:       2,
	JournalDisabled:              3,
	JournalStageApplying:         4,
	JournalStaged:                5,
	JournalQualifyApplying:       6,
	JournalCandidateQualified:    7,
	JournalPrepareApplying:       8,
	JournalPrepared:              9,
	JournalQuiescenceProving:     10,
	JournalQuiescent:             11,
	JournalReplacementValidating: 12,
	JournalReplacementValidated:  13,
	JournalSelectApplying:        14,
	JournalSelectedDisabled:      15,
	JournalCanaryApplying:        16,
	JournalCanaryActive:          17,
	JournalEnableApplying:        18,
	JournalEnabled:               19,
	JournalComplete:              20,
}

func phaseAtLeast(phase, minimum JournalPhase) bool {
	phaseIndex, phaseOK := journalPhaseIndex[phase]
	minimumIndex, minimumOK := journalPhaseIndex[minimum]
	return phaseOK && minimumOK && phaseIndex >= minimumIndex
}

func isApplyingPhase(phase JournalPhase) bool {
	switch phase {
	case JournalDisableApplying, JournalStageApplying,
		JournalQualifyApplying, JournalPrepareApplying,
		JournalQuiescenceProving, JournalReplacementValidating,
		JournalSelectApplying, JournalCanaryApplying,
		JournalEnableApplying:
		return true
	default:
		return false
	}
}

// ValidateJournalTransition permits only one durable state-machine edge.
func ValidateJournalTransition(previous, next Journal) error {
	if previous.validate() != nil || next.validate() != nil ||
		previous.Generation == math.MaxUint64 ||
		previous.ObservationSequence == math.MaxUint64 ||
		next.Generation != previous.Generation+1 ||
		next.ObservationSequence != previous.ObservationSequence+1 ||
		!next.UpdatedAt.After(previous.UpdatedAt) {
		return ErrInvalidJournalTransition
	}

	if previous.Phase == JournalCandidateRejected {
		return validateRejectedReentry(previous, next)
	}
	if previous.Phase == JournalComplete {
		if next.Phase != JournalCurrent ||
			!reflect.DeepEqual(previous.Selected, next.Selected) ||
			next.Observed.Version != next.Selected.Version {
			return ErrInvalidJournalTransition
		}
		return nil
	}

	if previous.ConfigurationRevision != next.ConfigurationRevision ||
		previous.ConfigurationBinding != next.ConfigurationBinding ||
		!validNonterminalBindings(previous, next) {
		return ErrInvalidJournalTransition
	}

	if previous.Phase == JournalUpgradeRequired &&
		next.Phase == JournalUpgradeRequired {
		if previous.Candidate != nil ||
			next.Candidate == nil ||
			!reflect.DeepEqual(previous.Selected, next.Selected) ||
			!reflect.DeepEqual(previous.Observed, next.Observed) {
			return ErrInvalidJournalTransition
		}
		return nil
	}

	if isApplyingPhase(previous.Phase) &&
		next.Phase == previous.Phase {
		if !sameExceptAuthorization(previous, next) ||
			!authorizationAdvanced(
				previous.Authorization,
				next.Authorization,
			) {
			return ErrInvalidJournalTransition
		}
		return nil
	}

	if previous.Phase == next.Phase {
		normalized := next
		normalized.Generation = previous.Generation
		normalized.ObservationSequence = previous.ObservationSequence
		normalized.UpdatedAt = previous.UpdatedAt
		if !reflect.DeepEqual(previous, normalized) {
			return ErrInvalidJournalTransition
		}
		return nil
	}

	if next.Phase == JournalCandidateRejected {
		if phaseAtLeast(previous.Phase, JournalSelectedDisabled) ||
			previous.Candidate == nil ||
			!reflect.DeepEqual(previous.Candidate, next.Candidate) ||
			!reflect.DeepEqual(previous.Selected, next.Selected) ||
			!reflect.DeepEqual(previous.Observed, next.Observed) {
			return ErrInvalidJournalTransition
		}
		return nil
	}

	previousIndex, previousOK := journalPhaseIndex[previous.Phase]
	nextIndex, nextOK := journalPhaseIndex[next.Phase]
	if !previousOK || !nextOK || nextIndex != previousIndex+1 {
		return ErrInvalidJournalTransition
	}

	if previous.Phase == JournalSelectApplying {
		if !selectionTransitionMatches(previous, next) {
			return ErrInvalidJournalTransition
		}
	} else if !reflect.DeepEqual(previous.Selected, next.Selected) {
		return ErrInvalidJournalTransition
	}

	if phaseAtLeast(previous.Phase, JournalUpgradeRequired) &&
		(!reflect.DeepEqual(previous.Observed, next.Observed) ||
			!reflect.DeepEqual(previous.Candidate, next.Candidate)) {
		return ErrInvalidJournalTransition
	}

	if next.Authorization != nil {
		if previous.Authorization == nil {
			if next.Phase != JournalDisableApplying {
				return ErrInvalidJournalTransition
			}
		} else if authorizationPhaseForJournal(previous.Phase) ==
			authorizationPhaseForJournal(next.Phase) {
			if isApplyingPhase(next.Phase) {
				if !authorizationAdvanced(
					previous.Authorization,
					next.Authorization,
				) {
					return ErrInvalidJournalTransition
				}
			} else if !reflect.DeepEqual(
				previous.Authorization,
				next.Authorization,
			) {
				return ErrInvalidJournalTransition
			}
		} else if !authorizationAdvanced(
			previous.Authorization,
			next.Authorization,
		) {
			return ErrInvalidJournalTransition
		}
	}
	return nil
}

func validNonterminalBindings(previous, next Journal) bool {
	if previous.Phase == JournalCurrent {
		return (next.Phase == JournalCurrent ||
			next.Phase == JournalUpgradeRequired) &&
			reflect.DeepEqual(previous.Selected, next.Selected)
	}
	return true
}

func selectionTransitionMatches(previous, next Journal) bool {
	if previous.Candidate == nil ||
		!selectionMatchesCandidate(next.Selected, *previous.Candidate) {
		return false
	}
	return next.Selected.RollbackVersion == previous.Selected.Version &&
		next.Selected.RollbackManifestDigest ==
			previous.Selected.ManifestDigest &&
		next.Selected.RollbackImageDigest ==
			previous.Selected.ImageDigest
}

func authorizationAdvanced(
	previous, next *AuthorizationRecord,
) bool {
	if previous == nil ||
		next == nil ||
		next.BindingDigest == previous.BindingDigest {
		return false
	}
	if next.EnrollmentEpoch == previous.EnrollmentEpoch {
		return next.EnrollmentBindingDigest ==
			previous.EnrollmentBindingDigest &&
			next.ControlSequence > previous.ControlSequence
	}
	return next.EnrollmentEpoch > previous.EnrollmentEpoch &&
		next.EnrollmentBindingDigest != previous.EnrollmentBindingDigest
}

func sameExceptAuthorization(previous, next Journal) bool {
	next.Authorization = previous.Authorization
	next.Generation = previous.Generation
	next.ObservationSequence = previous.ObservationSequence
	next.UpdatedAt = previous.UpdatedAt
	return reflect.DeepEqual(previous, next)
}

func validateRejectedReentry(previous, next Journal) error {
	if next.Phase != JournalUpgradeRequired ||
		previous.ConfigurationRevision != next.ConfigurationRevision ||
		previous.ConfigurationBinding != next.ConfigurationBinding ||
		!reflect.DeepEqual(previous.Selected, next.Selected) {
		return ErrInvalidJournalTransition
	}
	order, err := CompareRunnerVersions(
		previous.Observed.Version,
		next.Observed.Version,
	)
	if err != nil || order > 0 {
		return ErrInvalidJournalTransition
	}
	if order < 0 {
		return nil
	}
	if previous.Candidate == nil ||
		next.Candidate == nil ||
		reflect.DeepEqual(previous.Candidate, next.Candidate) {
		return ErrInvalidJournalTransition
	}
	return nil
}

// Status derives the exact public Phase 3 tuple from private journal state.
func (journal Journal) Status() (RunnerReleaseStatus, error) {
	if err := journal.validate(); err != nil {
		return RunnerReleaseStatus{}, err
	}
	status := RunnerReleaseStatus{
		ObservationSequence:    journal.ObservationSequence,
		ObservedVersion:        journal.Observed.Version,
		SelectedVersion:        journal.Selected.Version,
		SelectedManifestDigest: journal.Selected.ManifestDigest,
		SelectedImageDigest:    journal.Selected.ImageDigest,
	}
	switch {
	case journal.Phase == JournalCurrent ||
		phaseAtLeast(journal.Phase, JournalSelectedDisabled):
		status.State = RunnerReleaseCurrent
	case journal.Phase == JournalCandidateRejected:
		status.State = RunnerReleaseCandidateRejected
		status.CandidateVersion = stringPointer(journal.Candidate.Version)
		status.CandidateManifestDigest = stringPointer(
			journal.Candidate.ManifestDigest,
		)
		status.CandidateImageDigest = stringPointer(
			journal.Candidate.ImageDigest,
		)
	case phaseAtLeast(journal.Phase, JournalCandidateQualified):
		status.State = RunnerReleaseCandidateQualified
		status.CandidateVersion = stringPointer(journal.Candidate.Version)
		status.CandidateManifestDigest = stringPointer(
			journal.Candidate.ManifestDigest,
		)
		status.CandidateImageDigest = stringPointer(
			journal.Candidate.ImageDigest,
		)
	default:
		status.State = RunnerReleaseUpgradeRequired
	}
	if err := status.Validate(); err != nil {
		return RunnerReleaseStatus{}, ErrInvalidJournal
	}
	return status, nil
}

func stringPointer(value string) *string {
	copy := value
	return &copy
}
