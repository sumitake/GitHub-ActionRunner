package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	targetPostconditionSchemaVersion = uint32(1)
	operationReceiptSchemaVersion    = uint32(1)
	targetPostconditionDomain        = "portable-ghar-target-postcondition-v1"
	operationReceiptDomain           = "portable-ghar-operation-receipt-v1"
	operationEffectDomain            = "portable-ghar-operation-effect-v1"
	artifactIdentityDomain           = "portable-ghar-artifact-identity-v1"
)

var (
	ErrInvalidTargetPostcondition = errors.New("hostruntime: invalid target postcondition")
	ErrInvalidOperationReceipt    = errors.New("hostruntime: invalid operation receipt")
)

type ReceiptState string

const (
	ReceiptStateApplying ReceiptState = "applying"
	ReceiptStateApplied  ReceiptState = "applied"
)

type LifecycleFilesystemIdentity struct {
	Role        string `json:"role"`
	MountID     uint64 `json:"mount_id"`
	DeviceMajor uint32 `json:"device_major"`
	DeviceMinor uint32 `json:"device_minor"`
	RootInode   uint64 `json:"root_inode"`
	FSType      string `json:"fs_type"`
}

type ArtifactProjection struct {
	ObjectID        string  `json:"object_id"`
	Kind            string  `json:"kind"`
	Present         bool    `json:"present"`
	ContentDigest   *string `json:"content_digest"`
	IdentityDigest  *string `json:"identity_digest"`
	DeviceMajor     uint32  `json:"device_major"`
	DeviceMinor     uint32  `json:"device_minor"`
	Inode           uint64  `json:"inode"`
	Mode            uint32  `json:"mode"`
	Size            uint64  `json:"size"`
	LinkText        *string `json:"link_text"`
	RuntimeIdentity *string `json:"runtime_identity"`
}

type ProcessProjection struct {
	Role               string `json:"role"`
	PID                uint64 `json:"pid"`
	StartIdentity      string `json:"start_identity"`
	ExecutableDigest   string `json:"executable_digest"`
	AcquisitionCapable bool   `json:"acquisition_capable"`
}

type PolicyProjection struct {
	PolicyManifestDigest string `json:"policy_manifest_digest"`
	TransitionEpoch      uint64 `json:"transition_epoch"`
	AcquisitionEnabled   bool   `json:"acquisition_enabled"`
	PendingAcquisitions  uint64 `json:"pending_acquisitions"`
	ActiveListeners      uint64 `json:"active_listeners"`
}

type QuiescenceProjection struct {
	ControllerProcesses uint64 `json:"controller_processes"`
	LegacyProcesses     uint64 `json:"legacy_processes"`
	RunnerProcesses     uint64 `json:"runner_processes"`
	AdapterProcesses    uint64 `json:"adapter_processes"`
	BrokerProcesses     uint64 `json:"broker_processes"`
	HelperProcesses     uint64 `json:"helper_processes"`
	VerifierProcesses   uint64 `json:"verifier_processes"`
	ActiveDials         uint64 `json:"active_dials"`
	PerJobSockets       uint64 `json:"per_job_sockets"`
	PendingAcquisitions uint64 `json:"pending_acquisitions"`
	FleetGuards         uint64 `json:"fleet_guards"`
}

type CurrentSelectionProjection struct {
	ReleaseDirectoryDeviceMajor uint32           `json:"release_directory_device_major"`
	ReleaseDirectoryDeviceMinor uint32           `json:"release_directory_device_minor"`
	ReleaseDirectoryInode       uint64           `json:"release_directory_inode"`
	SymlinkDeviceMajor          uint32           `json:"symlink_device_major"`
	SymlinkDeviceMinor          uint32           `json:"symlink_device_minor"`
	SymlinkInode                uint64           `json:"symlink_inode"`
	RelativeLinkText            string           `json:"relative_link_text"`
	ManifestDeviceMajor         uint32           `json:"manifest_device_major"`
	ManifestDeviceMinor         uint32           `json:"manifest_device_minor"`
	ManifestInode               uint64           `json:"manifest_inode"`
	ManifestDigest              string           `json:"manifest_digest"`
	FenceGeneration             uint64           `json:"fence_generation"`
	ActiveFleet                 fleetfence.Fleet `json:"active_fleet"`
}

type LegacyNormalizationProjection struct {
	CommandDigest               string   `json:"command_digest"`
	ConfigurationDigest         string   `json:"configuration_digest"`
	ImageDigests                []string `json:"image_digests"`
	WatchdogDigest              string   `json:"watchdog_digest"`
	ForceDisabled               bool     `json:"force_disabled"`
	RunnerWorkerCount           uint64   `json:"runner_worker_count"`
	AcquisitionCapableProcesses uint64   `json:"acquisition_capable_processes"`
}

type TargetPostcondition struct {
	SchemaVersion          uint32                         `json:"schema_version"`
	OperationID            string                         `json:"operation_id"`
	BindingDigest          string                         `json:"binding_digest"`
	EffectKey              string                         `json:"effect_key"`
	Phase                  OperationPhase                 `json:"phase"`
	ManifestDigest         *string                        `json:"manifest_digest"`
	PrivateOverlayRevision string                         `json:"private_overlay_revision"`
	FenceGeneration        uint64                         `json:"fence_generation"`
	ActiveFleet            fleetfence.Fleet               `json:"active_fleet"`
	Filesystems            []LifecycleFilesystemIdentity  `json:"filesystems"`
	Artifacts              []ArtifactProjection           `json:"artifacts"`
	Processes              []ProcessProjection            `json:"processes"`
	Policy                 PolicyProjection               `json:"policy"`
	Quiescence             QuiescenceProjection           `json:"quiescence"`
	CurrentSelection       *CurrentSelectionProjection    `json:"current_selection"`
	LegacyNormalization    *LegacyNormalizationProjection `json:"legacy_normalization"`
	ObservedAt             time.Time                      `json:"observed_at"`
}

type OperationReceipt struct {
	SchemaVersion             uint32         `json:"schema_version"`
	OperationID               string         `json:"operation_id"`
	BindingDigest             string         `json:"binding_digest"`
	EffectKey                 string         `json:"effect_key"`
	Phase                     OperationPhase `json:"phase"`
	State                     ReceiptState   `json:"state"`
	PriorReceiptDigest        string         `json:"prior_receipt_digest"`
	TargetPostconditionDigest *string        `json:"target_postcondition_digest"`
	CreatedAt                 time.Time      `json:"created_at"`
	UpdatedAt                 time.Time      `json:"updated_at"`
}

var lifecycleFilesystemRoles = [...]string{
	"docker-root",
	"state",
	"staging",
	"rollback",
	"scratch",
	"logs",
}

func DeriveOperationEffectKey(
	binding OperationBinding,
	phase OperationPhase,
) (string, error) {
	if err := validateOperationBinding(binding); err != nil ||
		!phaseAllowedForBinding(binding, phase) {
		return "", ErrInvalidOperationReceipt
	}
	preimage := make([]byte, 0, 256)
	preimage = append(preimage, operationEffectDomain...)
	preimage = append(preimage, 0)
	operationID, _ := hex.DecodeString(binding.OperationID)
	preimage = append(preimage, operationID...)
	var ok bool
	if preimage, ok = appendLP(preimage, string(phase)); !ok {
		return "", ErrInvalidOperationReceipt
	}
	preimage = appendU64(preimage, binding.ExpectedGeneration)
	if preimage, ok = appendOptionalDigest(preimage, binding.PriorManifestDigest); !ok {
		return "", ErrInvalidOperationReceipt
	}
	if preimage, ok = appendOptionalDigest(preimage, binding.TargetManifestDigest); !ok {
		return "", ErrInvalidOperationReceipt
	}
	if preimage, ok = appendLP(preimage, string(binding.TargetFleet)); !ok {
		return "", ErrInvalidOperationReceipt
	}
	overlay, _ := hex.DecodeString(binding.PrivateOverlayRevision)
	preimage = append(preimage, overlay...)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

func ParseTargetPostcondition(
	document []byte,
	maxBytes int,
) (TargetPostcondition, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return TargetPostcondition{}, "", ErrInvalidTargetPostcondition
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var postcondition TargetPostcondition
	if err := decoder.Decode(&postcondition); err != nil {
		return TargetPostcondition{}, "", ErrInvalidTargetPostcondition
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return TargetPostcondition{}, "", ErrInvalidTargetPostcondition
	}
	if err := validateTargetPostcondition(postcondition); err != nil {
		return TargetPostcondition{}, "", err
	}
	canonical, err := json.Marshal(postcondition)
	if err != nil || !bytes.Equal(canonical, document) {
		return TargetPostcondition{}, "", ErrInvalidTargetPostcondition
	}
	return postcondition, canonicalArtifactDigest(targetPostconditionDomain, canonical), nil
}

func MarshalTargetPostcondition(
	postcondition TargetPostcondition,
) ([]byte, string, error) {
	if err := validateTargetPostcondition(postcondition); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(postcondition)
	if err != nil {
		return nil, "", ErrInvalidTargetPostcondition
	}
	return canonical, canonicalArtifactDigest(targetPostconditionDomain, canonical), nil
}

func ParseOperationReceipt(
	document []byte,
	maxBytes int,
) (OperationReceipt, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return OperationReceipt{}, "", ErrInvalidOperationReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var receipt OperationReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return OperationReceipt{}, "", ErrInvalidOperationReceipt
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OperationReceipt{}, "", ErrInvalidOperationReceipt
	}
	if err := validateOperationReceipt(receipt); err != nil {
		return OperationReceipt{}, "", err
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, document) {
		return OperationReceipt{}, "", ErrInvalidOperationReceipt
	}
	return receipt, canonicalArtifactDigest(operationReceiptDomain, canonical), nil
}

func MarshalOperationReceipt(receipt OperationReceipt) ([]byte, string, error) {
	if err := validateOperationReceipt(receipt); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return nil, "", ErrInvalidOperationReceipt
	}
	return canonical, canonicalArtifactDigest(operationReceiptDomain, canonical), nil
}

func ValidateTargetPostconditionAgainstBinding(
	postcondition TargetPostcondition,
	binding OperationBinding,
	phase OperationPhase,
) error {
	if err := validateTargetPostcondition(postcondition); err != nil {
		return err
	}
	_, bindingDigest, err := MarshalOperationBinding(binding)
	if err != nil {
		return ErrInvalidTargetPostcondition
	}
	effectKey, err := DeriveOperationEffectKey(binding, phase)
	if err != nil ||
		postcondition.OperationID != binding.OperationID ||
		postcondition.BindingDigest != bindingDigest ||
		postcondition.EffectKey != effectKey ||
		postcondition.Phase != phase ||
		postcondition.PrivateOverlayRevision != binding.PrivateOverlayRevision {
		return ErrInvalidTargetPostcondition
	}
	if postcondition.ManifestDigest != nil &&
		(binding.PriorManifestDigest == nil ||
			*postcondition.ManifestDigest != *binding.PriorManifestDigest) &&
		(binding.TargetManifestDigest == nil ||
			*postcondition.ManifestDigest != *binding.TargetManifestDigest) {
		return ErrInvalidTargetPostcondition
	}
	return nil
}

func ValidateAppliedReceipt(
	applying OperationReceipt,
	applied OperationReceipt,
	postcondition TargetPostcondition,
	binding OperationBinding,
) error {
	if err := validateOperationReceipt(applying); err != nil {
		return err
	}
	if err := validateOperationReceipt(applied); err != nil {
		return err
	}
	if applying.State != ReceiptStateApplying ||
		applied.State != ReceiptStateApplied ||
		applying.OperationID != applied.OperationID ||
		applying.BindingDigest != applied.BindingDigest ||
		applying.EffectKey != applied.EffectKey ||
		applying.Phase != applied.Phase ||
		applying.PriorReceiptDigest != applied.PriorReceiptDigest ||
		!applying.CreatedAt.Equal(applied.CreatedAt) ||
		!applied.UpdatedAt.After(applying.UpdatedAt) {
		return ErrInvalidOperationReceipt
	}
	if err := ValidateTargetPostconditionAgainstBinding(
		postcondition,
		binding,
		applied.Phase,
	); err != nil {
		return ErrInvalidOperationReceipt
	}
	_, targetDigest, err := MarshalTargetPostcondition(postcondition)
	if err != nil ||
		applied.TargetPostconditionDigest == nil ||
		*applied.TargetPostconditionDigest != targetDigest {
		return ErrInvalidOperationReceipt
	}
	return nil
}

func validateTargetPostcondition(postcondition TargetPostcondition) error {
	if postcondition.SchemaVersion != targetPostconditionSchemaVersion ||
		!isLowerHex64(postcondition.OperationID) ||
		!isLowerHex64(postcondition.BindingDigest) ||
		!isLowerHex64(postcondition.EffectKey) ||
		!knownAnyPhase(postcondition.Phase) ||
		!validOptionalLowerDigest(postcondition.ManifestDigest) ||
		!isLowerHex64(postcondition.PrivateOverlayRevision) ||
		!validFleet(postcondition.ActiveFleet) ||
		postcondition.Filesystems == nil ||
		postcondition.Artifacts == nil ||
		postcondition.Processes == nil ||
		!utcTime(postcondition.ObservedAt) ||
		postcondition.ObservedAt.IsZero() {
		return ErrInvalidTargetPostcondition
	}
	if err := validateLifecycleFilesystems(postcondition.Filesystems); err != nil {
		return err
	}
	if err := validateArtifacts(postcondition.Artifacts); err != nil {
		return err
	}
	if err := validateProcesses(postcondition.Processes); err != nil {
		return err
	}
	if !isLowerHex64(postcondition.Policy.PolicyManifestDigest) ||
		postcondition.Policy.TransitionEpoch == 0 {
		return ErrInvalidTargetPostcondition
	}
	if postcondition.CurrentSelection != nil &&
		!validCurrentSelection(*postcondition.CurrentSelection) {
		return ErrInvalidTargetPostcondition
	}
	if postcondition.LegacyNormalization != nil &&
		!validLegacyNormalization(*postcondition.LegacyNormalization) {
		return ErrInvalidTargetPostcondition
	}
	if (postcondition.Phase == OperationPhaseCurrentSelected ||
		postcondition.Phase == OperationPhaseVerified) &&
		postcondition.CurrentSelection == nil {
		return ErrInvalidTargetPostcondition
	}
	if postcondition.Phase == OperationPhaseLegacyNormalizedProven &&
		postcondition.LegacyNormalization == nil {
		return ErrInvalidTargetPostcondition
	}
	return nil
}

func validateOperationReceipt(receipt OperationReceipt) error {
	if receipt.SchemaVersion != operationReceiptSchemaVersion ||
		!isLowerHex64(receipt.OperationID) ||
		!isLowerHex64(receipt.BindingDigest) ||
		!isLowerHex64(receipt.EffectKey) ||
		!knownAnyPhase(receipt.Phase) ||
		!isLowerHex64(receipt.PriorReceiptDigest) ||
		receipt.CreatedAt.IsZero() ||
		receipt.UpdatedAt.IsZero() ||
		receipt.UpdatedAt.Before(receipt.CreatedAt) ||
		!utcTime(receipt.CreatedAt) ||
		!utcTime(receipt.UpdatedAt) {
		return ErrInvalidOperationReceipt
	}
	switch receipt.State {
	case ReceiptStateApplying:
		if receipt.TargetPostconditionDigest != nil {
			return ErrInvalidOperationReceipt
		}
	case ReceiptStateApplied:
		if receipt.TargetPostconditionDigest == nil ||
			!isLowerHex64(*receipt.TargetPostconditionDigest) {
			return ErrInvalidOperationReceipt
		}
	default:
		return ErrInvalidOperationReceipt
	}
	return nil
}

func validateLifecycleFilesystems(filesystems []LifecycleFilesystemIdentity) error {
	if len(filesystems) != len(lifecycleFilesystemRoles) {
		return ErrInvalidTargetPostcondition
	}
	byMount := make(map[uint64]LifecycleFilesystemIdentity, len(filesystems))
	for index, identity := range filesystems {
		if identity.Role != lifecycleFilesystemRoles[index] ||
			identity.MountID == 0 ||
			identity.DeviceMajor == 0 ||
			identity.RootInode == 0 ||
			!validLifecycleScalar(identity.FSType) {
			return ErrInvalidTargetPostcondition
		}
		if existing, ok := byMount[identity.MountID]; ok {
			if existing.DeviceMajor != identity.DeviceMajor ||
				existing.DeviceMinor != identity.DeviceMinor ||
				existing.FSType != identity.FSType {
				return ErrInvalidTargetPostcondition
			}
		} else {
			byMount[identity.MountID] = identity
		}
	}
	return nil
}

func validateArtifacts(artifacts []ArtifactProjection) error {
	if len(artifacts) > 4096 ||
		!sort.SliceIsSorted(artifacts, func(i, j int) bool {
			return artifacts[i].ObjectID < artifacts[j].ObjectID
		}) {
		return ErrInvalidTargetPostcondition
	}
	for index, artifact := range artifacts {
		if !validLifecycleScalar(artifact.ObjectID) ||
			(index > 0 && artifacts[index-1].ObjectID == artifact.ObjectID) {
			return ErrInvalidTargetPostcondition
		}
		if !artifact.Present {
			if artifact.ContentDigest != nil ||
				artifact.IdentityDigest != nil ||
				artifact.LinkText != nil ||
				artifact.RuntimeIdentity != nil ||
				artifact.DeviceMajor != 0 ||
				artifact.DeviceMinor != 0 ||
				artifact.Inode != 0 ||
				artifact.Mode != 0 ||
				artifact.Size != 0 {
				return ErrInvalidTargetPostcondition
			}
			continue
		}
		if artifact.IdentityDigest == nil ||
			!isLowerHex64(*artifact.IdentityDigest) {
			return ErrInvalidTargetPostcondition
		}
		derived, err := DeriveArtifactIdentity(artifact)
		if err != nil || derived != *artifact.IdentityDigest {
			return ErrInvalidTargetPostcondition
		}
	}
	return nil
}

func DeriveArtifactIdentity(artifact ArtifactProjection) (string, error) {
	if !artifact.Present ||
		!validLifecycleScalar(artifact.ObjectID) ||
		!validOptionalLowerDigest(artifact.ContentDigest) {
		return "", ErrInvalidTargetPostcondition
	}
	switch artifact.Kind {
	case "regular-file":
		if artifact.ContentDigest == nil ||
			artifact.DeviceMajor == 0 ||
			artifact.Inode == 0 ||
			artifact.Mode == 0 ||
			artifact.LinkText != nil ||
			artifact.RuntimeIdentity != nil {
			return "", ErrInvalidTargetPostcondition
		}
	case "symlink":
		if artifact.ContentDigest != nil ||
			artifact.DeviceMajor == 0 ||
			artifact.Inode == 0 ||
			artifact.Mode == 0 ||
			artifact.LinkText == nil ||
			!validLifecycleScalar(*artifact.LinkText) ||
			artifact.Size != uint64(len(*artifact.LinkText)) ||
			artifact.RuntimeIdentity != nil {
			return "", ErrInvalidTargetPostcondition
		}
	case "docker-image", "registration":
		if artifact.DeviceMajor != 0 ||
			artifact.DeviceMinor != 0 ||
			artifact.Inode != 0 ||
			artifact.Mode != 0 ||
			artifact.Size != 0 ||
			artifact.LinkText != nil ||
			artifact.RuntimeIdentity == nil ||
			!validLifecycleScalar(*artifact.RuntimeIdentity) {
			return "", ErrInvalidTargetPostcondition
		}
	default:
		return "", ErrInvalidTargetPostcondition
	}

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, artifactIdentityDomain...)
	preimage = append(preimage, 0)
	var ok bool
	if preimage, ok = appendLP(preimage, artifact.ObjectID); !ok {
		return "", ErrInvalidTargetPostcondition
	}
	if preimage, ok = appendLP(preimage, artifact.Kind); !ok {
		return "", ErrInvalidTargetPostcondition
	}
	if preimage, ok = appendOptionalDigest(preimage, artifact.ContentDigest); !ok {
		return "", ErrInvalidTargetPostcondition
	}
	preimage = appendU32(preimage, artifact.DeviceMajor)
	preimage = appendU32(preimage, artifact.DeviceMinor)
	preimage = appendU64(preimage, artifact.Inode)
	preimage = appendU32(preimage, artifact.Mode)
	preimage = appendU64(preimage, artifact.Size)
	if preimage, ok = appendOptionalLP(preimage, artifact.LinkText); !ok {
		return "", ErrInvalidTargetPostcondition
	}
	if preimage, ok = appendOptionalLP(preimage, artifact.RuntimeIdentity); !ok {
		return "", ErrInvalidTargetPostcondition
	}
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

func validateProcesses(processes []ProcessProjection) error {
	if len(processes) > 4096 ||
		!sort.SliceIsSorted(processes, func(i, j int) bool {
			if processes[i].Role != processes[j].Role {
				return processes[i].Role < processes[j].Role
			}
			return processes[i].PID < processes[j].PID
		}) {
		return ErrInvalidTargetPostcondition
	}
	for index, process := range processes {
		if process.PID == 0 ||
			!validLifecycleScalar(process.Role) ||
			!isLowerHex64(process.StartIdentity) ||
			!isLowerHex64(process.ExecutableDigest) ||
			(index > 0 &&
				processes[index-1].Role == process.Role &&
				processes[index-1].PID == process.PID) {
			return ErrInvalidTargetPostcondition
		}
	}
	return nil
}

func validCurrentSelection(selection CurrentSelectionProjection) bool {
	return selection.ReleaseDirectoryDeviceMajor != 0 &&
		selection.ReleaseDirectoryInode != 0 &&
		selection.SymlinkDeviceMajor != 0 &&
		selection.SymlinkInode != 0 &&
		validLifecycleScalar(selection.RelativeLinkText) &&
		selection.ManifestDeviceMajor != 0 &&
		selection.ManifestInode != 0 &&
		isLowerHex64(selection.ManifestDigest) &&
		validFleet(selection.ActiveFleet)
}

func validLegacyNormalization(normalization LegacyNormalizationProjection) bool {
	if !isLowerHex64(normalization.CommandDigest) ||
		!isLowerHex64(normalization.ConfigurationDigest) ||
		!isLowerHex64(normalization.WatchdogDigest) ||
		!normalization.ForceDisabled ||
		normalization.RunnerWorkerCount != 0 ||
		normalization.AcquisitionCapableProcesses != 0 ||
		normalization.ImageDigests == nil ||
		len(normalization.ImageDigests) == 0 {
		return false
	}
	for _, digest := range normalization.ImageDigests {
		if !validImageDigest(digest) {
			return false
		}
	}
	return true
}

func phaseAllowedForBinding(binding OperationBinding, phase OperationPhase) bool {
	normal, ok := normalPhaseSequence(binding)
	if ok && phaseIndex(normal, phase) >= 0 {
		return true
	}
	for path, sequence := range compensationPhaseSequences {
		if compensationAllowedForBinding(path, binding) &&
			phaseIndex(sequence, phase) >= 0 {
			return true
		}
	}
	return false
}

func knownAnyPhase(phase OperationPhase) bool {
	for _, kind := range []OperationKind{
		OperationKindInstall,
		OperationKindSuspend,
		OperationKindResume,
		OperationKindRollback,
		OperationKindUninstall,
	} {
		if knownNormalPhase(kind, phase) {
			return true
		}
	}
	for _, sequence := range compensationPhaseSequences {
		if phaseIndex(sequence, phase) >= 0 {
			return true
		}
	}
	return false
}

func validLifecycleScalar(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
