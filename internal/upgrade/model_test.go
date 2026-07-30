package upgrade

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestCompareRunnerVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		left  string
		right string
		want  int
	}{
		{name: "equal", left: "v2.336.0", right: "v2.336.0", want: 0},
		{name: "minor width", left: "v2.9.0", right: "v2.10.0", want: -1},
		{name: "major", left: "v10.0.0", right: "v2.999.999", want: 1},
		{name: "patch", left: "v2.336.11", right: "v2.336.2", want: 1},
		{name: "zero components", left: "v0.0.0", right: "v0.0.1", want: -1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := CompareRunnerVersions(test.left, test.right)
			if err != nil {
				t.Fatalf("CompareRunnerVersions(%q, %q) error = %v", test.left, test.right, err)
			}
			if got != test.want {
				t.Fatalf(
					"CompareRunnerVersions(%q, %q) = %d, want %d",
					test.left,
					test.right,
					got,
					test.want,
				)
			}
		})
	}
}

func TestCompareRunnerVersionsRejectsInvalidForms(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		"2.336.0",
		"V2.336.0",
		"v2.336",
		"v2.336.0.1",
		"v+2.336.0",
		"v-2.336.0",
		"v02.336.0",
		"v2.0336.0",
		"v2.336.00",
		"v2.336.0-rc.1",
		"v2.336.0+build",
		" v2.336.0",
		"v2.336.0 ",
		"v2.336.0\n",
		"v2..0",
		"v2.a.0",
		"v18446744073709551616.0.0",
	}
	for _, value := range invalid {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := CompareRunnerVersions(value, "v2.336.0"); !errors.Is(err, ErrInvalidRunnerVersion) {
				t.Fatalf("CompareRunnerVersions(%q, valid) error = %v, want ErrInvalidRunnerVersion", value, err)
			}
			if _, err := CompareRunnerVersions("v2.336.0", value); !errors.Is(err, ErrInvalidRunnerVersion) {
				t.Fatalf("CompareRunnerVersions(valid, %q) error = %v, want ErrInvalidRunnerVersion", value, err)
			}
		})
	}
}

func TestRunnerReleaseValidate(t *testing.T) {
	t.Parallel()

	release := validRunnerRelease()
	if err := release.Validate(); err != nil {
		t.Fatalf("valid release error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*RunnerRelease)
	}{
		{name: "version", mutate: func(value *RunnerRelease) { value.Version = "2.336.0" }},
		{name: "tag ref", mutate: func(value *RunnerRelease) { value.TagRefSHA = strings.Repeat("A", 40) }},
		{name: "source commit", mutate: func(value *RunnerRelease) { value.SourceCommitSHA = strings.Repeat("b", 39) }},
		{name: "asset name", mutate: func(value *RunnerRelease) { value.LinuxX64AssetName = "actions-runner-linux-arm64-2.336.0.tar.gz" }},
		{name: "asset size", mutate: func(value *RunnerRelease) { value.LinuxX64AssetSize = 0 }},
		{name: "asset digest", mutate: func(value *RunnerRelease) { value.LinuxX64AssetDigest = strings.Repeat("c", 64) }},
		{name: "publication time", mutate: func(value *RunnerRelease) { value.PublishedAt = time.Time{} }},
		{name: "non utc publication time", mutate: func(value *RunnerRelease) { value.PublishedAt = value.PublishedAt.In(time.FixedZone("offset", 3600)) }},
		{name: "observation evidence", mutate: func(value *RunnerRelease) { value.ObservationEvidence = strings.Repeat("D", 64) }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := release
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, ErrInvalidRunnerRelease) {
				t.Fatalf("Validate() error = %v, want ErrInvalidRunnerRelease", err)
			}
		})
	}
}

func TestCandidateSelectionAndStageObservationValidate(t *testing.T) {
	t.Parallel()

	candidate, _ := validCandidateAndManifest(t)
	if err := candidate.Validate(); err != nil {
		t.Fatalf("candidate Validate() error = %v", err)
	}

	selection := Selection{
		Version:                candidate.Version,
		ManifestDigest:         candidate.ManifestDigest,
		ImageDigest:            candidate.ImageDigest,
		RollbackVersion:        "v2.335.1",
		RollbackManifestDigest: strings.Repeat("9", 64),
		RollbackImageDigest:    "sha256:" + strings.Repeat("8", 64),
		ObservedAt:             fixedModelTime(),
	}
	if err := selection.Validate(); err != nil {
		t.Fatalf("selection Validate() error = %v", err)
	}
	selection.RollbackImageDigest = selection.ImageDigest
	if err := selection.Validate(); !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("selection duplicate rollback error = %v, want ErrInvalidSelection", err)
	}

	stage := StageObservation{
		Version:               candidate.Version,
		ReleaseEvidenceDigest: candidate.ReleaseEvidenceDigest,
		ManifestDigest:        candidate.ManifestDigest,
		ImageDigest:           candidate.ImageDigest,
		Complete:              true,
		Selected:              false,
		EvidenceDigest:        strings.Repeat("7", 64),
		ObservedAt:            fixedModelTime(),
	}
	if err := stage.Validate(candidate); err != nil {
		t.Fatalf("stage Validate() error = %v", err)
	}
	stage.Selected = true
	if err := stage.Validate(candidate); !errors.Is(err, ErrInvalidStageObservation) {
		t.Fatalf("selected stage error = %v, want ErrInvalidStageObservation", err)
	}
}

func TestCompatibilityReportValidateAndEvidenceBinding(t *testing.T) {
	t.Parallel()

	candidate, manifest := validCandidateAndManifest(t)
	report := validCompatibilityReport(t, candidate, manifest)
	if err := report.Validate(candidate); err != nil {
		t.Fatalf("report Validate() error = %v", err)
	}
	originalEvidence := report.EvidenceDigest

	mutations := []struct {
		name   string
		mutate func(*CompatibilityReport)
	}{
		{name: "runtime manifest", mutate: func(value *CompatibilityReport) { value.RuntimeManifest.LogPolicyDigest = strings.Repeat("1", 64) }},
		{name: "release manifest", mutate: func(value *CompatibilityReport) { value.RunnerReleaseManifestDigest = strings.Repeat("2", 64) }},
		{name: "attestation", mutate: func(value *CompatibilityReport) { value.AttestationDigest = strings.Repeat("3", 64) }},
		{name: "provenance", mutate: func(value *CompatibilityReport) { value.ProvenanceDigest = strings.Repeat("4", 64) }},
		{name: "listener proof", mutate: func(value *CompatibilityReport) { value.ListenerVersionEvidence = strings.Repeat("5", 64) }},
		{name: "disable update proof", mutate: func(value *CompatibilityReport) { value.DisableUpdateEvidence = strings.Repeat("6", 64) }},
		{name: "host proof", mutate: func(value *CompatibilityReport) { value.HostProbeEvidence = strings.Repeat("7", 64) }},
		{name: "reclamation proof", mutate: func(value *CompatibilityReport) { value.ReclamationEvidence = strings.Repeat("8", 64) }},
		{name: "false compatibility", mutate: func(value *CompatibilityReport) { value.DisableUpdateOK = false }},
	}
	for _, test := range mutations {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := report
			test.mutate(&value)
			if err := value.Validate(candidate); !errors.Is(err, ErrInvalidCompatibilityReport) {
				t.Fatalf("Validate() error = %v, want ErrInvalidCompatibilityReport", err)
			}
			value.EvidenceDigest = ""
			if digest, err := compatibilityEvidenceDigest(value); err == nil && digest == originalEvidence {
				t.Fatalf("compatibilityEvidenceDigest() did not change for %s", test.name)
			}
		})
	}
}

func TestQuiescenceValidate(t *testing.T) {
	t.Parallel()

	value := Quiescence{
		RetainedLedgers: true,
		EvidenceDigest:  strings.Repeat("a", 64),
		ObservedAt:      fixedModelTime(),
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	value.PendingEffects = 1
	if err := value.Validate(); !errors.Is(err, ErrInvalidQuiescence) {
		t.Fatalf("nonzero quiescence error = %v, want ErrInvalidQuiescence", err)
	}
	value.PendingEffects = 0
	value.RetainedLedgers = false
	if err := value.Validate(); !errors.Is(err, ErrInvalidQuiescence) {
		t.Fatalf("unsafe ledgers error = %v, want ErrInvalidQuiescence", err)
	}
}

func TestRunnerReleaseStatusValidateAndCanonicalJSON(t *testing.T) {
	t.Parallel()

	selectedManifest := strings.Repeat("a", 64)
	selectedImage := "sha256:" + strings.Repeat("b", 64)
	candidateVersion := "v2.336.0"
	candidateManifest := strings.Repeat("c", 64)
	candidateImage := "sha256:" + strings.Repeat("d", 64)

	tests := []RunnerReleaseStatus{
		{
			State:                  RunnerReleaseCurrent,
			ObservationSequence:    1,
			ObservedVersion:        "v2.335.1",
			SelectedVersion:        "v2.335.1",
			SelectedManifestDigest: selectedManifest,
			SelectedImageDigest:    selectedImage,
		},
		{
			State:                  RunnerReleaseUpgradeRequired,
			ObservationSequence:    2,
			ObservedVersion:        candidateVersion,
			SelectedVersion:        "v2.335.1",
			SelectedManifestDigest: selectedManifest,
			SelectedImageDigest:    selectedImage,
		},
		{
			State:                   RunnerReleaseCandidateQualified,
			ObservationSequence:     3,
			ObservedVersion:         candidateVersion,
			SelectedVersion:         "v2.335.1",
			SelectedManifestDigest:  selectedManifest,
			SelectedImageDigest:     selectedImage,
			CandidateVersion:        &candidateVersion,
			CandidateManifestDigest: &candidateManifest,
			CandidateImageDigest:    &candidateImage,
		},
		{
			State:                   RunnerReleaseCandidateRejected,
			ObservationSequence:     4,
			ObservedVersion:         candidateVersion,
			SelectedVersion:         "v2.335.1",
			SelectedManifestDigest:  selectedManifest,
			SelectedImageDigest:     selectedImage,
			CandidateVersion:        &candidateVersion,
			CandidateManifestDigest: nil,
			CandidateImageDigest:    nil,
		},
	}
	for _, value := range tests {
		if err := value.Validate(); err != nil {
			t.Fatalf("%s Validate() error = %v", value.State, err)
		}
	}

	current := tests[0]
	document, err := json.Marshal(current)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	const want = `{"state":"current","observationSequence":1,"observedVersion":"v2.335.1","selectedVersion":"v2.335.1","selectedManifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","selectedImageDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","candidateVersion":null,"candidateManifestDigest":null,"candidateImageDigest":null}`
	if string(document) != want {
		t.Fatalf("status JSON = %s, want %s", document, want)
	}

	invalid := tests[2]
	invalid.ObservationSequence = 0
	if err := invalid.Validate(); !errors.Is(err, ErrInvalidRunnerReleaseStatus) {
		t.Fatalf("zero sequence error = %v, want ErrInvalidRunnerReleaseStatus", err)
	}
	invalid = tests[2]
	invalid.CandidateVersion = nil
	if err := invalid.Validate(); !errors.Is(err, ErrInvalidRunnerReleaseStatus) {
		t.Fatalf("missing candidate error = %v, want ErrInvalidRunnerReleaseStatus", err)
	}
	invalid = tests[0]
	invalid.ObservedVersion = candidateVersion
	if err := invalid.Validate(); !errors.Is(err, ErrInvalidRunnerReleaseStatus) {
		t.Fatalf("mismatched current error = %v, want ErrInvalidRunnerReleaseStatus", err)
	}
}

func validRunnerRelease() RunnerRelease {
	return RunnerRelease{
		Version:             "v2.336.0",
		TagRefSHA:           strings.Repeat("a", 40),
		SourceCommitSHA:     strings.Repeat("b", 40),
		LinuxX64AssetName:   "actions-runner-linux-x64-2.336.0.tar.gz",
		LinuxX64AssetSize:   224_000_000,
		LinuxX64AssetDigest: "sha256:" + strings.Repeat("c", 64),
		PublishedAt:         fixedModelTime(),
		ObservationEvidence: strings.Repeat("d", 64),
	}
}

func validCandidateAndManifest(t *testing.T) (Candidate, hostruntime.RuntimeManifest) {
	t.Helper()
	archiveDigest := strings.Repeat("e", 64)
	manifest := hostruntime.RuntimeManifest{
		SchemaVersion:         1,
		BuildID:               strings.Repeat("1", 64),
		ControllerSHA256:      strings.Repeat("2", 64),
		RunnerImageDigest:     "sha256:" + strings.Repeat("3", 64),
		AdapterImageDigest:    "sha256:" + strings.Repeat("4", 64),
		BrokerImageDigest:     "sha256:" + strings.Repeat("5", 64),
		HelperImageDigest:     "sha256:" + strings.Repeat("6", 64),
		VerifierImageDigest:   "sha256:" + strings.Repeat("7", 64),
		TrustBundleDigest:     strings.Repeat("8", 64),
		SeccompProfileDigest:  strings.Repeat("9", 64),
		EgressMode:            "restricted-broker-v1",
		PolicyManifestDigest:  strings.Repeat("a", 64),
		ConntrackBudgetDigest: strings.Repeat("b", 64),
		StorageBudgetDigest:   strings.Repeat("c", 64),
		LogPolicyDigest:       strings.Repeat("d", 64),
		ArchiveManifestDigest: &archiveDigest,
		AcquisitionDefault:    "disabled",
		FleetGeneration:       7,
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	return Candidate{
		Version:                     "v2.336.0",
		ReleaseEvidenceDigest:       strings.Repeat("d", 64),
		RunnerReleaseManifestDigest: strings.Repeat("0", 64),
		ManifestDigest:              manifestDigest,
		ImageDigest:                 manifest.RunnerImageDigest,
		AttestationDigest:           strings.Repeat("1", 64),
		ProvenanceDigest:            strings.Repeat("2", 64),
	}, manifest
}

func validCompatibilityReport(
	t *testing.T,
	candidate Candidate,
	manifest hostruntime.RuntimeManifest,
) CompatibilityReport {
	t.Helper()
	report := CompatibilityReport{
		Version:                     candidate.Version,
		ManifestDigest:              candidate.ManifestDigest,
		ImageDigest:                 candidate.ImageDigest,
		ReleaseEvidenceDigest:       candidate.ReleaseEvidenceDigest,
		RunnerReleaseManifestDigest: candidate.RunnerReleaseManifestDigest,
		RuntimeManifest:             manifest,
		RuntimeManifestDigest:       candidate.ManifestDigest,
		AttestationDigest:           candidate.AttestationDigest,
		ProvenanceDigest:            candidate.ProvenanceDigest,
		ListenerVersionEvidence:     strings.Repeat("3", 64),
		DisableUpdateEvidence:       strings.Repeat("4", 64),
		HostProbeEvidence:           strings.Repeat("5", 64),
		ReclamationEvidence:         strings.Repeat("6", 64),
		ListenerVersionOK:           true,
		DisableUpdateOK:             true,
		SingleRunnerPayload:         true,
		UpdateStagingAbsent:         true,
		RuntimeManifestOK:           true,
		HostProfileOK:               true,
		ReclamationOK:               true,
		ObservedAt:                  fixedModelTime(),
	}
	digest, err := compatibilityEvidenceDigest(report)
	if err != nil {
		t.Fatalf("compatibilityEvidenceDigest() error = %v", err)
	}
	report.EvidenceDigest = digest
	return report
}

func fixedModelTime() time.Time {
	return time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
}
