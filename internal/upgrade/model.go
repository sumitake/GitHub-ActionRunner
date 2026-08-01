// Package upgrade defines the fail-closed runner-release upgrade state
// machine. Phase 2 exposes no routing authority and ships no live maintenance
// client.
package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"math"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	maxRunnerAssetBytes         = uint64(1 << 30)
	compatibilityEvidenceDomain = "portable-ghar-runner-compatibility-v1"
)

var (
	ErrInvalidRunnerVersion       = errors.New("upgrade: invalid runner version")
	ErrInvalidRunnerRelease       = errors.New("upgrade: invalid runner release")
	ErrInvalidCandidate           = errors.New("upgrade: invalid runner candidate")
	ErrInvalidSelection           = errors.New("upgrade: invalid runner selection")
	ErrInvalidStageObservation    = errors.New("upgrade: invalid stage observation")
	ErrInvalidCompatibilityReport = errors.New("upgrade: invalid compatibility report")
	ErrInvalidQuiescence          = errors.New("upgrade: invalid quiescence proof")
	ErrInvalidRunnerReleaseStatus = errors.New("upgrade: invalid runner release status")
)

// RunnerReleaseObserver observes only the fixed official actions/runner
// release source.
type RunnerReleaseObserver interface {
	Observe(context.Context) (RunnerRelease, error)
}

// RunnerRelease is the bounded official upstream release identity.
type RunnerRelease struct {
	Version             string    `json:"version"`
	TagRefSHA           string    `json:"tag_ref_sha"`
	SourceCommitSHA     string    `json:"source_commit_sha"`
	LinuxX64AssetName   string    `json:"linux_x64_asset_name"`
	LinuxX64AssetSize   uint64    `json:"linux_x64_asset_size"`
	LinuxX64AssetDigest string    `json:"linux_x64_asset_digest"`
	PublishedAt         time.Time `json:"published_at"`
	ObservationEvidence string    `json:"observation_evidence"`
}

// Candidate is one exact externally attested immutable runtime tuple.
type Candidate struct {
	Version                     string `json:"version"`
	ReleaseEvidenceDigest       string `json:"release_evidence_digest"`
	RunnerReleaseManifestDigest string `json:"runner_release_manifest_digest"`
	ManifestDigest              string `json:"manifest_digest"`
	ImageDigest                 string `json:"image_digest"`
	AttestationDigest           string `json:"attestation_digest"`
	ProvenanceDigest            string `json:"provenance_digest"`
}

// Selection is the exact selected and preserved rollback runtime identity.
type Selection struct {
	Version                string    `json:"version"`
	ManifestDigest         string    `json:"manifest_digest"`
	ImageDigest            string    `json:"image_digest"`
	RollbackVersion        string    `json:"rollback_version"`
	RollbackManifestDigest string    `json:"rollback_manifest_digest"`
	RollbackImageDigest    string    `json:"rollback_image_digest"`
	ObservedAt             time.Time `json:"observed_at"`
}

// StageObservation proves a complete candidate stage without live selection.
type StageObservation struct {
	Version               string    `json:"version"`
	ReleaseEvidenceDigest string    `json:"release_evidence_digest"`
	ManifestDigest        string    `json:"manifest_digest"`
	ImageDigest           string    `json:"image_digest"`
	Complete              bool      `json:"complete"`
	Selected              bool      `json:"selected"`
	EvidenceDigest        string    `json:"evidence_digest"`
	ObservedAt            time.Time `json:"observed_at"`
}

// CompatibilityReport binds every exact runtime and compatibility proof used
// for qualification and post-quiescence replacement validation.
type CompatibilityReport struct {
	Version                     string                      `json:"version"`
	ManifestDigest              string                      `json:"manifest_digest"`
	ImageDigest                 string                      `json:"image_digest"`
	ReleaseEvidenceDigest       string                      `json:"release_evidence_digest"`
	RunnerReleaseManifestDigest string                      `json:"runner_release_manifest_digest"`
	RuntimeManifest             hostruntime.RuntimeManifest `json:"runtime_manifest"`
	RuntimeManifestDigest       string                      `json:"runtime_manifest_digest"`
	AttestationDigest           string                      `json:"attestation_digest"`
	ProvenanceDigest            string                      `json:"provenance_digest"`
	ListenerVersionEvidence     string                      `json:"listener_version_evidence"`
	DisableUpdateEvidence       string                      `json:"disable_update_evidence"`
	HostProbeEvidence           string                      `json:"host_probe_evidence"`
	ReclamationEvidence         string                      `json:"reclamation_evidence"`
	ListenerVersionOK           bool                        `json:"listener_version_ok"`
	DisableUpdateOK             bool                        `json:"disable_update_ok"`
	SingleRunnerPayload         bool                        `json:"single_runner_payload"`
	UpdateStagingAbsent         bool                        `json:"update_staging_absent"`
	RuntimeManifestOK           bool                        `json:"runtime_manifest_ok"`
	HostProfileOK               bool                        `json:"host_profile_ok"`
	ReclamationOK               bool                        `json:"reclamation_ok"`
	EvidenceDigest              string                      `json:"evidence_digest"`
	ObservedAt                  time.Time                   `json:"observed_at"`
}

// Quiescence proves all executable surfaces absent while retained ledgers
// remain safe.
type Quiescence struct {
	Listeners        uint64    `json:"listeners"`
	Runners          uint64    `json:"runners"`
	Adapters         uint64    `json:"adapters"`
	HeldBrokers      uint64    `json:"held_brokers"`
	RunningBrokers   uint64    `json:"running_brokers"`
	Helpers          uint64    `json:"helpers"`
	Verifiers        uint64    `json:"verifiers"`
	PerJobSocketDirs uint64    `json:"per_job_socket_dirs"`
	ActiveDials      uint64    `json:"active_dials"`
	PendingEffects   uint64    `json:"pending_effects"`
	RetainedLedgers  bool      `json:"retained_ledgers"`
	EvidenceDigest   string    `json:"evidence_digest"`
	ObservedAt       time.Time `json:"observed_at"`
}

// RunnerReleaseState is the exact Phase 3 public release state.
type RunnerReleaseState string

const (
	RunnerReleaseCurrent            RunnerReleaseState = "current"
	RunnerReleaseUpgradeRequired    RunnerReleaseState = "upgrade-required"
	RunnerReleaseCandidateQualified RunnerReleaseState = "candidate-qualified"
	RunnerReleaseCandidateRejected  RunnerReleaseState = "candidate-rejected"
)

// RunnerReleaseStatus is byte-compatible with Phase 3
// RunnerReleaseStatusV1.
type RunnerReleaseStatus struct {
	State                   RunnerReleaseState `json:"state"`
	ObservationSequence     uint64             `json:"observationSequence"`
	ObservedVersion         string             `json:"observedVersion"`
	SelectedVersion         string             `json:"selectedVersion"`
	SelectedManifestDigest  string             `json:"selectedManifestDigest"`
	SelectedImageDigest     string             `json:"selectedImageDigest"`
	CandidateVersion        *string            `json:"candidateVersion"`
	CandidateManifestDigest *string            `json:"candidateManifestDigest"`
	CandidateImageDigest    *string            `json:"candidateImageDigest"`
}

// CompareRunnerVersions compares exact vMAJOR.MINOR.PATCH runner versions
// numerically. It rejects every permissive semver extension.
func CompareRunnerVersions(left, right string) (int, error) {
	leftParts, err := parseRunnerVersion(left)
	if err != nil {
		return 0, err
	}
	rightParts, err := parseRunnerVersion(right)
	if err != nil {
		return 0, err
	}
	for index := range leftParts {
		switch {
		case leftParts[index] < rightParts[index]:
			return -1, nil
		case leftParts[index] > rightParts[index]:
			return 1, nil
		}
	}
	return 0, nil
}

func parseRunnerVersion(value string) ([3]uint64, error) {
	var result [3]uint64
	if len(value) < len("v0.0.0") || value[0] != 'v' {
		return result, ErrInvalidRunnerVersion
	}
	cursor := 1
	for index := range result {
		if cursor >= len(value) {
			return [3]uint64{}, ErrInvalidRunnerVersion
		}
		start := cursor
		for cursor < len(value) && value[cursor] >= '0' && value[cursor] <= '9' {
			digit := uint64(value[cursor] - '0')
			if result[index] > (math.MaxUint64-digit)/10 {
				return [3]uint64{}, ErrInvalidRunnerVersion
			}
			result[index] = result[index]*10 + digit
			cursor++
		}
		if cursor == start || cursor-start > 1 && value[start] == '0' {
			return [3]uint64{}, ErrInvalidRunnerVersion
		}
		if index < len(result)-1 {
			if cursor >= len(value) || value[cursor] != '.' {
				return [3]uint64{}, ErrInvalidRunnerVersion
			}
			cursor++
		}
	}
	if cursor != len(value) {
		return [3]uint64{}, ErrInvalidRunnerVersion
	}
	return result, nil
}

// Validate rejects an incomplete, ambiguous, or non-official release tuple.
func (release RunnerRelease) Validate() error {
	if _, err := parseRunnerVersion(release.Version); err != nil ||
		!validLowerHex(release.TagRefSHA, 40) ||
		!validLowerHex(release.SourceCommitSHA, 40) ||
		release.LinuxX64AssetSize == 0 ||
		release.LinuxX64AssetSize > maxRunnerAssetBytes ||
		!validImageDigest(release.LinuxX64AssetDigest) ||
		!validUTCTime(release.PublishedAt) ||
		!validRawDigest(release.ObservationEvidence) {
		return ErrInvalidRunnerRelease
	}
	wantName := "actions-runner-linux-x64-" +
		strings.TrimPrefix(release.Version, "v") +
		".tar.gz"
	if release.LinuxX64AssetName != wantName {
		return ErrInvalidRunnerRelease
	}
	return nil
}

// Validate rejects an incomplete or open candidate identity.
func (candidate Candidate) Validate() error {
	if _, err := parseRunnerVersion(candidate.Version); err != nil ||
		!validRawDigest(candidate.ReleaseEvidenceDigest) ||
		!validRawDigest(candidate.RunnerReleaseManifestDigest) ||
		!validRawDigest(candidate.ManifestDigest) ||
		!validImageDigest(candidate.ImageDigest) ||
		!validRawDigest(candidate.AttestationDigest) ||
		!validRawDigest(candidate.ProvenanceDigest) {
		return ErrInvalidCandidate
	}
	return nil
}

// Validate rejects selection ambiguity or rollback aliasing.
func (selection Selection) Validate() error {
	if _, err := parseRunnerVersion(selection.Version); err != nil {
		return ErrInvalidSelection
	}
	if _, err := parseRunnerVersion(selection.RollbackVersion); err != nil {
		return ErrInvalidSelection
	}
	order, err := CompareRunnerVersions(
		selection.RollbackVersion,
		selection.Version,
	)
	if err != nil ||
		order > 0 ||
		!validRawDigest(selection.ManifestDigest) ||
		!validImageDigest(selection.ImageDigest) ||
		!validRawDigest(selection.RollbackManifestDigest) ||
		!validImageDigest(selection.RollbackImageDigest) ||
		selection.ManifestDigest == selection.RollbackManifestDigest ||
		selection.ImageDigest == selection.RollbackImageDigest ||
		!validUTCTime(selection.ObservedAt) {
		return ErrInvalidSelection
	}
	return nil
}

// Validate binds a stage observation to the exact candidate and proves it has
// not become the live selection.
func (observation StageObservation) Validate(candidate Candidate) error {
	if candidate.Validate() != nil ||
		observation.Version != candidate.Version ||
		observation.ReleaseEvidenceDigest != candidate.ReleaseEvidenceDigest ||
		observation.ManifestDigest != candidate.ManifestDigest ||
		observation.ImageDigest != candidate.ImageDigest ||
		!observation.Complete ||
		observation.Selected ||
		!validRawDigest(observation.EvidenceDigest) ||
		!validUTCTime(observation.ObservedAt) {
		return ErrInvalidStageObservation
	}
	return nil
}

// Validate binds qualification to the exact candidate and complete immutable
// runtime manifest.
func (report CompatibilityReport) Validate(candidate Candidate) error {
	if candidate.Validate() != nil ||
		report.Version != candidate.Version ||
		report.ManifestDigest != candidate.ManifestDigest ||
		report.ImageDigest != candidate.ImageDigest ||
		report.ReleaseEvidenceDigest != candidate.ReleaseEvidenceDigest ||
		report.RunnerReleaseManifestDigest !=
			candidate.RunnerReleaseManifestDigest ||
		report.AttestationDigest != candidate.AttestationDigest ||
		report.ProvenanceDigest != candidate.ProvenanceDigest ||
		!validRawDigest(report.ListenerVersionEvidence) ||
		!validRawDigest(report.DisableUpdateEvidence) ||
		!validRawDigest(report.HostProbeEvidence) ||
		!validRawDigest(report.ReclamationEvidence) ||
		!report.ListenerVersionOK ||
		!report.DisableUpdateOK ||
		!report.SingleRunnerPayload ||
		!report.UpdateStagingAbsent ||
		!report.RuntimeManifestOK ||
		!report.HostProfileOK ||
		!report.ReclamationOK ||
		!validUTCTime(report.ObservedAt) {
		return ErrInvalidCompatibilityReport
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(
		report.RuntimeManifest,
	)
	if err != nil ||
		report.RuntimeManifest.ArchiveManifestDigest == nil ||
		manifestDigest != report.RuntimeManifestDigest ||
		manifestDigest != candidate.ManifestDigest ||
		report.RuntimeManifest.RunnerImageDigest != candidate.ImageDigest {
		return ErrInvalidCompatibilityReport
	}
	evidence, err := compatibilityEvidenceDigest(report)
	if err != nil ||
		!validRawDigest(report.EvidenceDigest) ||
		report.EvidenceDigest != evidence {
		return ErrInvalidCompatibilityReport
	}
	return nil
}

func compatibilityEvidenceDigest(
	report CompatibilityReport,
) (string, error) {
	manifestDocument, manifestDigest, err := hostruntime.MarshalRuntimeManifest(
		report.RuntimeManifest,
	)
	if err != nil ||
		report.RuntimeManifestDigest != manifestDigest {
		return "", ErrInvalidCompatibilityReport
	}
	hash := sha256.New()
	writeEvidenceField(hash, []byte(compatibilityEvidenceDomain))
	fields := [][]byte{
		[]byte(report.Version),
		[]byte(report.ManifestDigest),
		[]byte(report.ImageDigest),
		[]byte(report.ReleaseEvidenceDigest),
		[]byte(report.RunnerReleaseManifestDigest),
		manifestDocument,
		[]byte(report.AttestationDigest),
		[]byte(report.ProvenanceDigest),
		[]byte(report.ListenerVersionEvidence),
		[]byte(report.DisableUpdateEvidence),
		[]byte(report.HostProbeEvidence),
		[]byte(report.ReclamationEvidence),
		encodeCompatibilityBits(report),
		[]byte(report.ObservedAt.UTC().Format(time.RFC3339Nano)),
	}
	for _, field := range fields {
		writeEvidenceField(hash, field)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func encodeCompatibilityBits(report CompatibilityReport) []byte {
	values := [...]bool{
		report.ListenerVersionOK,
		report.DisableUpdateOK,
		report.SingleRunnerPayload,
		report.UpdateStagingAbsent,
		report.RuntimeManifestOK,
		report.HostProfileOK,
		report.ReclamationOK,
	}
	result := make([]byte, len(values))
	for index, value := range values {
		if value {
			result[index] = 1
		}
	}
	return result
}

// Validate rejects any live surface or unsafe retained-ledger state.
func (proof Quiescence) Validate() error {
	if proof.Listeners != 0 ||
		proof.Runners != 0 ||
		proof.Adapters != 0 ||
		proof.HeldBrokers != 0 ||
		proof.RunningBrokers != 0 ||
		proof.Helpers != 0 ||
		proof.Verifiers != 0 ||
		proof.PerJobSocketDirs != 0 ||
		proof.ActiveDials != 0 ||
		proof.PendingEffects != 0 ||
		!proof.RetainedLedgers ||
		!validRawDigest(proof.EvidenceDigest) ||
		!validUTCTime(proof.ObservedAt) {
		return ErrInvalidQuiescence
	}
	return nil
}

// Validate enforces the exact closed Phase 3 release-status shapes.
func (status RunnerReleaseStatus) Validate() error {
	if status.ObservationSequence == 0 ||
		!validRawDigest(status.SelectedManifestDigest) ||
		!validImageDigest(status.SelectedImageDigest) {
		return ErrInvalidRunnerReleaseStatus
	}
	order, err := CompareRunnerVersions(
		status.ObservedVersion,
		status.SelectedVersion,
	)
	if err != nil {
		return ErrInvalidRunnerReleaseStatus
	}
	switch status.State {
	case RunnerReleaseCurrent:
		if order != 0 || !status.candidateFieldsNil() {
			return ErrInvalidRunnerReleaseStatus
		}
	case RunnerReleaseUpgradeRequired:
		if order <= 0 || !status.candidateFieldsNil() {
			return ErrInvalidRunnerReleaseStatus
		}
	case RunnerReleaseCandidateQualified:
		if order <= 0 ||
			status.CandidateVersion == nil ||
			status.CandidateManifestDigest == nil ||
			status.CandidateImageDigest == nil ||
			*status.CandidateVersion != status.ObservedVersion ||
			!validRawDigest(*status.CandidateManifestDigest) ||
			!validImageDigest(*status.CandidateImageDigest) {
			return ErrInvalidRunnerReleaseStatus
		}
	case RunnerReleaseCandidateRejected:
		if order <= 0 ||
			status.CandidateVersion == nil ||
			*status.CandidateVersion != status.ObservedVersion ||
			(status.CandidateManifestDigest != nil &&
				!validRawDigest(*status.CandidateManifestDigest)) ||
			(status.CandidateImageDigest != nil &&
				!validImageDigest(*status.CandidateImageDigest)) {
			return ErrInvalidRunnerReleaseStatus
		}
	default:
		return ErrInvalidRunnerReleaseStatus
	}
	return nil
}

func (status RunnerReleaseStatus) candidateFieldsNil() bool {
	return status.CandidateVersion == nil &&
		status.CandidateManifestDigest == nil &&
		status.CandidateImageDigest == nil
}

func validRawDigest(value string) bool {
	return validLowerHex(value, sha256.Size*2)
}

func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") &&
		validRawDigest(strings.TrimPrefix(value, "sha256:"))
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for index := range value {
		if value[index] < '0' ||
			value[index] > '9' && value[index] < 'a' ||
			value[index] > 'f' {
			return false
		}
	}
	return true
}

func validUTCTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func writeEvidenceField(writer hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func releaseForSelection(
	selection Selection,
	template RunnerRelease,
) RunnerRelease {
	template.Version = selection.Version
	template.LinuxX64AssetName = "actions-runner-linux-x64-" +
		strings.TrimPrefix(selection.Version, "v") +
		".tar.gz"
	return template
}
