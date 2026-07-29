package hostruntime

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const goldenOperationJournalDigest = "8b59f66c0ad828972f7a6b80ab928e83db22b9d268b4604c52ac356cfae80e9c"

func TestOperationJournalGolden(t *testing.T) {
	t.Parallel()

	manifest, _, err := ParseRuntimeManifest(
		[]byte(validRuntimeManifestJSON),
		len(validRuntimeManifestJSON),
	)
	if err != nil {
		t.Fatalf("ParseRuntimeManifest() error = %v", err)
	}
	started := time.Date(2026, 7, 29, 6, 30, 0, 123456789, time.UTC)
	updated := started.Add(time.Second)
	journal := OperationJournal{
		SchemaVersion:      1,
		OperationID:        goldenOperationID,
		BindingDigest:      goldenBindingDigest,
		Kind:               OperationKindInstall,
		Phase:              OperationPhasePrepared,
		CompensationPath:   nil,
		ExpectedGeneration: 41,
		PriorManifest:      &manifest,
		TargetManifest:     &manifest,
		TargetFleet:        fleetfence.FleetPortable,
		StartedAt:          started,
		UpdatedAt:          updated,
	}
	encoded, digest, err := MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	if digest != goldenOperationJournalDigest {
		t.Fatalf("MarshalOperationJournal() digest = %q, want %q; json=%s", digest, goldenOperationJournalDigest, encoded)
	}
	decoded, decodedDigest, err := ParseOperationJournal(encoded, len(encoded))
	if err != nil {
		t.Fatalf("ParseOperationJournal() error = %v; json=%s", err, encoded)
	}
	if decoded.Phase != OperationPhasePrepared ||
		decoded.CompensationPath != nil ||
		!decoded.StartedAt.Equal(started) ||
		!decoded.UpdatedAt.Equal(updated) {
		t.Fatalf("ParseOperationJournal() = %#v", decoded)
	}
	if decodedDigest != digest {
		t.Fatalf("ParseOperationJournal() digest = %q, want %q", decodedDigest, digest)
	}
}

func TestValidateOperationJournalAgainstBinding(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	journal := goldenUpgradeJournal(t, OperationPhasePrepared)
	if err := ValidateOperationJournalAgainstBinding(journal, binding); err != nil {
		t.Fatalf("ValidateOperationJournalAgainstBinding() error = %v", err)
	}

	changed := journal
	changed.ExpectedGeneration++
	if err := ValidateOperationJournalAgainstBinding(changed, binding); !errors.Is(err, ErrInvalidOperationJournal) {
		t.Fatalf("ValidateOperationJournalAgainstBinding(changed generation) error = %v", err)
	}
	changed = journal
	changed.BindingDigest = strings.Repeat("0", 64)
	if err := ValidateOperationJournalAgainstBinding(changed, binding); !errors.Is(err, ErrInvalidOperationJournal) {
		t.Fatalf("ValidateOperationJournalAgainstBinding(changed digest) error = %v", err)
	}
}

func TestValidateOperationJournalTransition(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	current := goldenUpgradeJournal(t, OperationPhasePrepared)
	next := current
	next.Phase = OperationPhasePreflightProven
	next.UpdatedAt = next.UpdatedAt.Add(time.Second)
	if err := ValidateOperationJournalTransition(current, next, binding, nil); err != nil {
		t.Fatalf("ValidateOperationJournalTransition(next) error = %v", err)
	}
	if err := ValidateOperationJournalTransition(current, current, binding, nil); err != nil {
		t.Fatalf("ValidateOperationJournalTransition(replay) error = %v", err)
	}

	skipped := next
	skipped.Phase = OperationPhaseCandidateStaged
	if err := ValidateOperationJournalTransition(current, skipped, binding, nil); !errors.Is(err, ErrInvalidOperationJournal) {
		t.Fatalf("ValidateOperationJournalTransition(skip) error = %v", err)
	}

	selected := goldenUpgradeJournal(t, OperationPhaseCurrentSelected)
	compensation := selected
	path := CompensationInstallUpgradePostSelection
	compensation.CompensationPath = &path
	compensation.Phase = OperationPhaseCUSelectStarted
	compensation.UpdatedAt = compensation.UpdatedAt.Add(time.Second)
	if err := ValidateOperationJournalTransition(
		selected,
		compensation,
		binding,
		&path,
	); err != nil {
		t.Fatalf("ValidateOperationJournalTransition(compensation) error = %v", err)
	}
	wrongPath := CompensationInstallLegacyPostSelection
	if err := ValidateOperationJournalTransition(
		selected,
		compensation,
		binding,
		&wrongPath,
	); !errors.Is(err, ErrInvalidOperationJournal) {
		t.Fatalf("ValidateOperationJournalTransition(wrong compensation) error = %v", err)
	}
}

func TestParseOperationJournalRejectsNoncanonicalAndPathMismatch(t *testing.T) {
	t.Parallel()

	journal := goldenUpgradeJournal(t, OperationPhasePrepared)
	encoded, _, err := MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	tests := map[string][]byte{
		"leading whitespace": append([]byte(" "), encoded...),
		"trailing newline":   append(append([]byte(nil), encoded...), '\n'),
		"unknown field": []byte(strings.TrimSuffix(string(encoded), "}") +
			`,"unknown":true}`),
		"wrong phase": []byte(strings.Replace(
			string(encoded),
			`"phase":"prepared"`,
			`"phase":"invented"`,
			1,
		)),
		"path on normal phase": []byte(strings.Replace(
			string(encoded),
			`"compensation_path":null`,
			`"compensation_path":"install-upgrade-post-selection"`,
			1,
		)),
		"non-UTC time": []byte(strings.Replace(
			string(encoded),
			`"started_at":"2026-07-29T06:30:00.123456789Z"`,
			`"started_at":"2026-07-28T23:30:00.123456789-07:00"`,
			1,
		)),
	}
	for name, document := range tests {
		name, document := name, document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParseOperationJournal(
				document,
				len(document)+1,
			); !errors.Is(err, ErrInvalidOperationJournal) {
				t.Fatalf("ParseOperationJournal() error = %v", err)
			}
		})
	}
}

func goldenUpgradeBinding(t *testing.T) OperationBinding {
	t.Helper()
	_, manifestDigest, err := ParseRuntimeManifest(
		[]byte(validRuntimeManifestJSON),
		len(validRuntimeManifestJSON),
	)
	if err != nil {
		t.Fatalf("ParseRuntimeManifest() error = %v", err)
	}
	disposition := InstallDispositionUpgradePortable
	overlay := strings.Repeat("c", 64)
	operationID, err := DeriveOperationID(
		OperationKindInstall,
		&disposition,
		41,
		&manifestDigest,
		&manifestDigest,
		fleetfence.FleetPortable,
		overlay,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	binding := OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     41,
		PriorManifestDigest:    &manifestDigest,
		TargetManifestDigest:   &manifestDigest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: overlay,
	}
	return binding
}

func goldenUpgradeJournal(t *testing.T, phase OperationPhase) OperationJournal {
	t.Helper()
	manifest, _, err := ParseRuntimeManifest(
		[]byte(validRuntimeManifestJSON),
		len(validRuntimeManifestJSON),
	)
	if err != nil {
		t.Fatalf("ParseRuntimeManifest() error = %v", err)
	}
	binding := goldenUpgradeBinding(t)
	_, bindingDigest, err := MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	started := time.Date(2026, 7, 29, 6, 30, 0, 123456789, time.UTC)
	return OperationJournal{
		SchemaVersion:      1,
		OperationID:        binding.OperationID,
		BindingDigest:      bindingDigest,
		Kind:               OperationKindInstall,
		Phase:              phase,
		ExpectedGeneration: 41,
		PriorManifest:      &manifest,
		TargetManifest:     &manifest,
		TargetFleet:        fleetfence.FleetPortable,
		StartedAt:          started,
		UpdatedAt:          started.Add(time.Second),
	}
}
