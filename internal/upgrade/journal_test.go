package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

var allJournalPhases = []JournalPhase{
	JournalCurrent,
	JournalUpgradeRequired,
	JournalDisableApplying,
	JournalDisabled,
	JournalStageApplying,
	JournalStaged,
	JournalQualifyApplying,
	JournalCandidateQualified,
	JournalPrepareApplying,
	JournalPrepared,
	JournalQuiescenceProving,
	JournalQuiescent,
	JournalReplacementValidating,
	JournalReplacementValidated,
	JournalSelectApplying,
	JournalSelectedDisabled,
	JournalCanaryApplying,
	JournalCanaryActive,
	JournalEnableApplying,
	JournalEnabled,
	JournalComplete,
	JournalCandidateRejected,
}

func TestJournalCanonicalRoundTripAndStatusProjection(t *testing.T) {
	t.Parallel()

	current := validJournalForPhase(t, JournalCurrent)
	document, digest, err := MarshalJournal(current)
	if err != nil {
		t.Fatalf("MarshalJournal() error = %v", err)
	}
	if !validRawDigest(digest) {
		t.Fatalf("MarshalJournal() digest = %q", digest)
	}
	parsed, parsedDigest, err := ParseJournal(document, 1<<20)
	if err != nil {
		t.Fatalf("ParseJournal() error = %v", err)
	}
	if parsedDigest != digest || parsed.Phase != current.Phase {
		t.Fatalf("ParseJournal() = %#v/%s, want phase %s/digest %s", parsed, parsedDigest, current.Phase, digest)
	}
	status, err := parsed.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != RunnerReleaseCurrent ||
		status.CandidateVersion != nil {
		t.Fatalf("current status = %#v", status)
	}

	qualified := validJournalForPhase(t, JournalCandidateQualified)
	status, err = qualified.Status()
	if err != nil {
		t.Fatalf("qualified Status() error = %v", err)
	}
	if status.State != RunnerReleaseCandidateQualified ||
		status.CandidateManifestDigest == nil ||
		*status.CandidateManifestDigest != qualified.Candidate.ManifestDigest {
		t.Fatalf("qualified status = %#v", status)
	}

	selected := validJournalForPhase(t, JournalSelectedDisabled)
	status, err = selected.Status()
	if err != nil {
		t.Fatalf("selected Status() error = %v", err)
	}
	if status.State != RunnerReleaseCurrent ||
		status.ObservedVersion != selected.Selected.Version ||
		status.CandidateVersion != nil {
		t.Fatalf("selected status = %#v", status)
	}
}

func TestJournalTransitionSequenceAndTerminalReentry(t *testing.T) {
	t.Parallel()

	current := validJournalForPhase(t, JournalCurrent)
	upgrade := validJournalForPhase(t, JournalUpgradeRequired)
	upgrade.Candidate = nil
	upgrade.Generation = current.Generation + 1
	upgrade.ObservationSequence = current.ObservationSequence + 1
	upgrade.UpdatedAt = current.UpdatedAt.Add(time.Second)
	if err := ValidateJournalTransition(current, upgrade); err != nil {
		t.Fatalf("current -> upgrade error = %v", err)
	}

	withCandidate := upgrade
	candidate, _ := validCandidateAndManifest(t)
	withCandidate.Generation++
	withCandidate.ObservationSequence++
	withCandidate.UpdatedAt = withCandidate.UpdatedAt.Add(time.Second)
	withCandidate.Candidate = &candidate
	if err := ValidateJournalTransition(upgrade, withCandidate); err != nil {
		t.Fatalf("upgrade candidate bind error = %v", err)
	}

	applying := validJournalForPhase(t, JournalDisableApplying)
	applying.Generation = withCandidate.Generation + 1
	applying.ObservationSequence = withCandidate.ObservationSequence + 1
	applying.UpdatedAt = withCandidate.UpdatedAt.Add(time.Second)
	if err := ValidateJournalTransition(withCandidate, applying); err != nil {
		t.Fatalf("upgrade -> disable-applying error = %v", err)
	}

	skipped := applying
	skipped.Generation++
	skipped.ObservationSequence++
	skipped.UpdatedAt = skipped.UpdatedAt.Add(time.Second)
	skipped.Phase = JournalStaged
	if err := ValidateJournalTransition(applying, skipped); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf("skipped transition error = %v, want ErrInvalidJournalTransition", err)
	}

	rejected := validJournalForPhase(t, JournalCandidateRejected)
	identical := validJournalForPhase(t, JournalUpgradeRequired)
	identical.Generation = rejected.Generation + 1
	identical.ObservationSequence = rejected.ObservationSequence + 1
	identical.UpdatedAt = rejected.UpdatedAt.Add(time.Second)
	identical.Candidate = rejected.Candidate
	if err := ValidateJournalTransition(rejected, identical); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf("identical rejected reentry error = %v, want ErrInvalidJournalTransition", err)
	}
	different := identical
	changed := *different.Candidate
	changed.ManifestDigest = strings.Repeat("9", 64)
	different.Candidate = &changed
	if err := ValidateJournalTransition(rejected, different); err != nil {
		t.Fatalf("different candidate reentry error = %v", err)
	}

	complete := validJournalForPhase(t, JournalComplete)
	nextCurrent := validJournalForPhase(t, JournalCurrent)
	nextCurrent.Generation = complete.Generation + 1
	nextCurrent.ObservationSequence = complete.ObservationSequence + 1
	nextCurrent.UpdatedAt = complete.UpdatedAt.Add(time.Second)
	nextCurrent.Selected = complete.Selected
	nextCurrent.Observed = selectedReleaseForSelection(
		complete.Selected,
		complete.Observed,
	)
	if err := ValidateJournalTransition(complete, nextCurrent); err != nil {
		t.Fatalf("complete -> current error = %v", err)
	}
}

func TestJournalRejectsCandidateSubstitutionAndSequenceRollback(t *testing.T) {
	t.Parallel()

	previous := validJournalForPhase(t, JournalStageApplying)
	next := validJournalForPhase(t, JournalStaged)
	next.Generation = previous.Generation + 1
	next.ObservationSequence = previous.ObservationSequence + 1
	next.UpdatedAt = previous.UpdatedAt.Add(time.Second)
	if err := ValidateJournalTransition(previous, next); err != nil {
		t.Fatalf("valid transition error = %v", err)
	}

	substituted := next
	changed := *substituted.Candidate
	changed.ManifestDigest = strings.Repeat("9", 64)
	substituted.Candidate = &changed
	if err := ValidateJournalTransition(previous, substituted); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf("substitution error = %v, want ErrInvalidJournalTransition", err)
	}

	rollback := next
	rollback.ObservationSequence = previous.ObservationSequence
	if err := ValidateJournalTransition(previous, rollback); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf("sequence rollback error = %v, want ErrInvalidJournalTransition", err)
	}
}

func TestJournalAllPhasesValidateAndProject(t *testing.T) {
	t.Parallel()

	for _, phase := range allJournalPhases {
		phase := phase
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			journal := validJournalForPhase(t, phase)
			document, digest, err := MarshalJournal(journal)
			if err != nil {
				t.Fatalf("MarshalJournal() error = %v", err)
			}
			parsed, parsedDigest, err := ParseJournal(document, 1<<20)
			if err != nil {
				t.Fatalf("ParseJournal() error = %v", err)
			}
			if parsedDigest != digest || parsed.Phase != phase {
				t.Fatalf(
					"parsed phase/digest = %s/%s, want %s/%s",
					parsed.Phase,
					parsedDigest,
					phase,
					digest,
				)
			}
			status, err := parsed.Status()
			if err != nil {
				t.Fatalf("Status() error = %v", err)
			}
			wantState := expectedStatusState(phase)
			if status.State != wantState {
				t.Fatalf(
					"Status().State = %s, want %s",
					status.State,
					wantState,
				)
			}
			wantCandidate := wantState ==
				RunnerReleaseCandidateQualified ||
				wantState == RunnerReleaseCandidateRejected
			if (status.CandidateVersion != nil) != wantCandidate ||
				(status.CandidateManifestDigest != nil) !=
					wantCandidate ||
				(status.CandidateImageDigest != nil) !=
					wantCandidate {
				t.Fatalf("candidate projection = %#v", status)
			}
			if phaseAtLeast(phase, JournalSelectedDisabled) &&
				(status.SelectedVersion != journal.Candidate.Version ||
					status.CandidateVersion != nil) {
				t.Fatalf("selected projection = %#v", status)
			}
		})
	}
}

func TestJournalFullTransitionVector(t *testing.T) {
	t.Parallel()

	phases := allJournalPhases[:len(allJournalPhases)-1]
	previous := validJournalForPhase(t, phases[0])
	for _, phase := range phases[1:] {
		next := advanceJournalFixture(t, previous, phase)
		if err := ValidateJournalTransition(previous, next); err != nil {
			t.Fatalf(
				"%s -> %s error = %v",
				previous.Phase,
				next.Phase,
				err,
			)
		}
		previous = next
	}

	freshCurrent := validJournalForPhase(t, JournalCurrent)
	freshCurrent.Generation = previous.Generation + 1
	freshCurrent.ObservationSequence =
		previous.ObservationSequence + 1
	freshCurrent.UpdatedAt = previous.UpdatedAt.Add(time.Second)
	freshCurrent.Selected = previous.Selected
	freshCurrent.Observed = selectedReleaseForSelection(
		previous.Selected,
		previous.Observed,
	)
	if err := ValidateJournalTransition(
		previous,
		freshCurrent,
	); err != nil {
		t.Fatalf("complete -> current error = %v", err)
	}

	secondBump := validJournalForPhase(t, JournalUpgradeRequired)
	secondBump.Generation = freshCurrent.Generation + 1
	secondBump.ObservationSequence =
		freshCurrent.ObservationSequence + 1
	secondBump.UpdatedAt = freshCurrent.UpdatedAt.Add(time.Second)
	secondBump.Selected = freshCurrent.Selected
	secondBump.Observed.Version = "v2.337.0"
	secondBump.Observed.LinuxX64AssetName =
		"actions-runner-linux-x64-2.337.0.tar.gz"
	secondBump.Observed.ObservationEvidence = strings.Repeat("9", 64)
	secondBump.Candidate = nil
	if err := ValidateJournalTransition(
		freshCurrent,
		secondBump,
	); err != nil {
		t.Fatalf("second forced bump error = %v", err)
	}
}

func TestJournalApplyingResumeRequiresFreshAuthorization(t *testing.T) {
	t.Parallel()

	previous := validJournalForPhase(t, JournalStageApplying)
	next := previous
	next.Generation++
	next.ObservationSequence++
	next.UpdatedAt = next.UpdatedAt.Add(time.Second)
	next.Authorization = cloneAuthorization(previous.Authorization)
	next.Authorization.ControlSequence++
	next.Authorization.BindingDigest = testJournalDigest("resume")
	if err := ValidateJournalTransition(previous, next); err != nil {
		t.Fatalf("fresh applying reentry error = %v", err)
	}

	reusedSequence := next
	reusedSequence.Authorization = cloneAuthorization(
		previous.Authorization,
	)
	reusedSequence.Authorization.BindingDigest =
		testJournalDigest("different-binding")
	if err := ValidateJournalTransition(
		previous,
		reusedSequence,
	); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf(
			"reused sequence error = %v, want ErrInvalidJournalTransition",
			err,
		)
	}

	enrollmentDrift := next
	enrollmentDrift.Authorization = cloneAuthorization(next.Authorization)
	enrollmentDrift.Authorization.EnrollmentBindingDigest =
		strings.Repeat("8", 64)
	if err := ValidateJournalTransition(
		previous,
		enrollmentDrift,
	); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf(
			"enrollment drift error = %v, want ErrInvalidJournalTransition",
			err,
		)
	}
}

func TestJournalRejectsNoncanonicalAndCrossPhaseDocuments(t *testing.T) {
	t.Parallel()

	journal := validJournalForPhase(t, JournalStaged)
	document, _, err := MarshalJournal(journal)
	if err != nil {
		t.Fatalf("MarshalJournal() error = %v", err)
	}
	for name, changed := range map[string][]byte{
		"whitespace": append([]byte(" "), document...),
		"trailing":   append(append([]byte(nil), document...), '\n'),
		"unknown": bytesReplaceOnce(
			document,
			[]byte(`"schema_version":1`),
			[]byte(`"unknown":1,"schema_version":1`),
		),
		"duplicate": bytesReplaceOnce(
			document,
			[]byte(`"schema_version":1`),
			[]byte(`"schema_version":1,"schema_version":1`),
		),
	} {
		name := name
		changed := changed
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParseJournal(
				changed,
				1<<20,
			); !errors.Is(err, ErrInvalidJournal) {
				t.Fatalf(
					"ParseJournal() error = %v, want ErrInvalidJournal",
					err,
				)
			}
		})
	}

	earlySelection := validJournalForPhase(t, JournalQualifyApplying)
	earlySelection.Selected = validJournalForPhase(
		t,
		JournalSelectedDisabled,
	).Selected
	if _, _, err := MarshalJournal(
		earlySelection,
	); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf(
			"early selection error = %v, want ErrInvalidJournal",
			err,
		)
	}

	earlyPolicy := validJournalForPhase(t, JournalDisableApplying)
	earlyPolicy.Policy = &PolicyProof{
		Mode:     "disabled",
		Epoch:    1,
		Digest:   strings.Repeat("a", 64),
		Capacity: 0,
	}
	if _, _, err := MarshalJournal(
		earlyPolicy,
	); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf(
			"early policy error = %v, want ErrInvalidJournal",
			err,
		)
	}
}

func TestJournalTerminalReentryVectors(t *testing.T) {
	t.Parallel()

	rejected := validJournalForPhase(t, JournalCandidateRejected)
	newer := validJournalForPhase(t, JournalUpgradeRequired)
	newer.Generation = rejected.Generation + 1
	newer.ObservationSequence = rejected.ObservationSequence + 1
	newer.UpdatedAt = rejected.UpdatedAt.Add(time.Second)
	newer.Candidate = nil
	newer.Observed.Version = "v2.337.0"
	newer.Observed.LinuxX64AssetName =
		"actions-runner-linux-x64-2.337.0.tar.gz"
	newer.Observed.ObservationEvidence = strings.Repeat("9", 64)
	if err := ValidateJournalTransition(rejected, newer); err != nil {
		t.Fatalf("rejected -> newer release error = %v", err)
	}

	reversed := newer
	reversed.Observed.Version = "v2.335.0"
	reversed.Observed.LinuxX64AssetName =
		"actions-runner-linux-x64-2.335.0.tar.gz"
	if err := ValidateJournalTransition(
		rejected,
		reversed,
	); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf(
			"reversed release error = %v, want ErrInvalidJournalTransition",
			err,
		)
	}
}

func TestJournalRejectsGenerationWrapAndDirectiveReuse(t *testing.T) {
	t.Parallel()

	previous := validJournalForPhase(t, JournalStageApplying)
	previous.Generation = ^uint64(0)
	next := validJournalForPhase(t, JournalStaged)
	next.Generation = 0
	next.ObservationSequence = previous.ObservationSequence + 1
	next.UpdatedAt = previous.UpdatedAt.Add(time.Second)
	if err := ValidateJournalTransition(
		previous,
		next,
	); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf(
			"generation wrap error = %v, want ErrInvalidJournalTransition",
			err,
		)
	}

	proven := validJournalForPhase(t, JournalDisabled)
	applying := advanceJournalFixture(
		t,
		proven,
		JournalStageApplying,
	)
	applying.Authorization.BindingDigest =
		proven.Authorization.BindingDigest
	if err := ValidateJournalTransition(
		proven,
		applying,
	); !errors.Is(err, ErrInvalidJournalTransition) {
		t.Fatalf(
			"directive reuse error = %v, want ErrInvalidJournalTransition",
			err,
		)
	}
}

func expectedStatusState(phase JournalPhase) RunnerReleaseState {
	switch {
	case phase == JournalCurrent ||
		phaseAtLeast(phase, JournalSelectedDisabled):
		return RunnerReleaseCurrent
	case phase == JournalCandidateRejected:
		return RunnerReleaseCandidateRejected
	case phaseAtLeast(phase, JournalCandidateQualified):
		return RunnerReleaseCandidateQualified
	default:
		return RunnerReleaseUpgradeRequired
	}
}

func advanceJournalFixture(
	t *testing.T,
	previous Journal,
	phase JournalPhase,
) Journal {
	t.Helper()
	next := validJournalForPhase(t, phase)
	next.Generation = previous.Generation + 1
	next.ObservationSequence = previous.ObservationSequence + 1
	next.UpdatedAt = previous.UpdatedAt.Add(time.Second)
	if next.Authorization != nil {
		if previous.Authorization == nil {
			next.Authorization.ControlSequence = 1
			next.Authorization.BindingDigest =
				testJournalDigest(string(phase))
		} else if isApplyingPhase(previous.Phase) &&
			!isApplyingPhase(next.Phase) {
			next.Authorization = cloneAuthorization(
				previous.Authorization,
			)
		} else {
			next.Authorization.EnrollmentBindingDigest =
				previous.Authorization.EnrollmentBindingDigest
			next.Authorization.ControlSequence =
				previous.Authorization.ControlSequence + 1
			next.Authorization.BindingDigest = testJournalDigest(
				string(phase),
			)
		}
	}
	return next
}

func cloneAuthorization(
	value *AuthorizationRecord,
) *AuthorizationRecord {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func testJournalDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func bytesReplaceOnce(document, old, replacement []byte) []byte {
	index := strings.Index(string(document), string(old))
	if index < 0 {
		return append([]byte(nil), document...)
	}
	result := make([]byte, 0, len(document)-len(old)+len(replacement))
	result = append(result, document[:index]...)
	result = append(result, replacement...)
	result = append(result, document[index+len(old):]...)
	return result
}

func validJournalForPhase(t *testing.T, phase JournalPhase) Journal {
	t.Helper()
	candidate, manifest := validCandidateAndManifest(t)
	oldSelection := Selection{
		Version:                "v2.335.1",
		ManifestDigest:         strings.Repeat("7", 64),
		ImageDigest:            "sha256:" + strings.Repeat("6", 64),
		RollbackVersion:        "v2.334.0",
		RollbackManifestDigest: strings.Repeat("5", 64),
		RollbackImageDigest:    "sha256:" + strings.Repeat("4", 64),
		ObservedAt:             fixedModelTime(),
	}
	observed := validRunnerRelease()
	journal := Journal{
		SchemaVersion:         journalSchemaVersion,
		Generation:            10,
		ObservationSequence:   20,
		Phase:                 phase,
		ConfigurationRevision: 19,
		ConfigurationBinding:  strings.Repeat("3", 64),
		Selected:              oldSelection,
		Observed:              observed,
		UpdatedAt:             fixedModelTime(),
	}
	if phase == JournalCurrent {
		journal.Observed = selectedReleaseForSelection(oldSelection, observed)
		return journal
	}
	journal.Candidate = &candidate
	if phase == JournalUpgradeRequired {
		return journal
	}
	if phase == JournalCandidateRejected {
		rejection := CandidateRejectionPermanent
		journal.Rejection = &rejection
		return journal
	}
	journal.Authorization = &AuthorizationRecord{
		Phase:                   authorizationPhaseForJournal(phase),
		BindingDigest:           strings.Repeat("a", 64),
		EnrollmentBindingDigest: strings.Repeat("b", 64),
		EnrollmentEpoch:         7,
		ControlSequence:         11,
	}
	if phaseAtLeast(phase, JournalStaged) {
		stage := StageObservation{
			Version:               candidate.Version,
			ReleaseEvidenceDigest: candidate.ReleaseEvidenceDigest,
			ManifestDigest:        candidate.ManifestDigest,
			ImageDigest:           candidate.ImageDigest,
			Complete:              true,
			EvidenceDigest:        strings.Repeat("c", 64),
			ObservedAt:            fixedModelTime(),
		}
		journal.Stage = &stage
	}
	if phaseAtLeast(phase, JournalCandidateQualified) {
		report := validCompatibilityReport(t, candidate, manifest)
		journal.Qualified = &report
	}
	if phaseAtLeast(phase, JournalQuiescent) {
		proof := Quiescence{
			RetainedLedgers: true,
			EvidenceDigest:  strings.Repeat("d", 64),
			ObservedAt:      fixedModelTime(),
		}
		journal.Quiescence = &proof
	}
	if phaseAtLeast(phase, JournalReplacementValidated) {
		report := validCompatibilityReport(t, candidate, manifest)
		journal.Replacement = &report
	}
	if phaseAtLeast(phase, JournalSelectedDisabled) &&
		phase != JournalCandidateRejected {
		journal.Selected = Selection{
			Version:                candidate.Version,
			ManifestDigest:         candidate.ManifestDigest,
			ImageDigest:            candidate.ImageDigest,
			RollbackVersion:        oldSelection.Version,
			RollbackManifestDigest: oldSelection.ManifestDigest,
			RollbackImageDigest:    oldSelection.ImageDigest,
			ObservedAt:             fixedModelTime(),
		}
	}
	switch phase {
	case JournalDisabled, JournalStageApplying, JournalStaged,
		JournalQualifyApplying, JournalCandidateQualified,
		JournalPrepareApplying, JournalPrepared,
		JournalQuiescenceProving, JournalQuiescent,
		JournalReplacementValidating, JournalReplacementValidated,
		JournalSelectApplying, JournalSelectedDisabled:
		journal.Policy = &PolicyProof{
			Mode:     "disabled",
			Epoch:    31,
			Digest:   strings.Repeat("e", 64),
			Capacity: 0,
		}
	case JournalCanaryApplying:
		journal.Policy = &PolicyProof{
			Mode:     "disabled",
			Epoch:    31,
			Digest:   strings.Repeat("e", 64),
			Capacity: 0,
		}
	case JournalCanaryActive, JournalEnableApplying:
		journal.Policy = &PolicyProof{
			Mode:     "canary-only",
			Epoch:    32,
			Digest:   strings.Repeat("f", 64),
			Capacity: 1,
		}
	case JournalEnabled, JournalComplete:
		journal.Policy = &PolicyProof{
			Mode:     "enabled",
			Epoch:    33,
			Digest:   strings.Repeat("1", 64),
			Capacity: 4,
		}
	}
	return journal
}

func selectedReleaseForSelection(
	selection Selection,
	template RunnerRelease,
) RunnerRelease {
	return releaseForSelection(selection, template)
}
