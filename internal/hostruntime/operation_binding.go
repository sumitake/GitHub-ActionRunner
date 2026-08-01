package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	operationBindingSchemaVersion = uint32(1)
	operationBindingDomain        = "portable-ghar-operation-binding-v1"
	operationIDDomain             = "portable-ghar-operation-id-v1"
)

var ErrInvalidOperationBinding = errors.New("hostruntime: invalid operation binding")

type OperationKind string

const (
	OperationKindInstall   OperationKind = "install"
	OperationKindSuspend   OperationKind = "suspend"
	OperationKindResume    OperationKind = "resume"
	OperationKindRollback  OperationKind = "rollback"
	OperationKindUninstall OperationKind = "uninstall"
)

type InstallDisposition string

const (
	InstallDispositionGreenfieldPortable     InstallDisposition = "greenfield-portable"
	InstallDispositionUpgradePortable        InstallDisposition = "upgrade-portable"
	InstallDispositionLegacyDisabledObserver InstallDisposition = "legacy-disabled-observer"
)

type OperationBinding struct {
	SchemaVersion          uint32              `json:"schema_version"`
	OperationID            string              `json:"operation_id"`
	Kind                   OperationKind       `json:"kind"`
	InstallDisposition     *InstallDisposition `json:"install_disposition"`
	ExpectedGeneration     uint64              `json:"expected_generation"`
	PriorManifestDigest    *string             `json:"prior_manifest_digest"`
	TargetManifestDigest   *string             `json:"target_manifest_digest"`
	TargetFleet            fleetfence.Fleet    `json:"target_fleet"`
	PrivateOverlayRevision string              `json:"private_overlay_revision"`
}

func DeriveOperationID(
	kind OperationKind,
	disposition *InstallDisposition,
	expectedGeneration uint64,
	priorManifestDigest *string,
	targetManifestDigest *string,
	targetFleet fleetfence.Fleet,
	privateOverlayRevision string,
) (string, error) {
	if err := validateOperationIdentity(
		kind,
		disposition,
		expectedGeneration,
		priorManifestDigest,
		targetManifestDigest,
		targetFleet,
		privateOverlayRevision,
	); err != nil {
		return "", err
	}

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, operationIDDomain...)
	preimage = append(preimage, 0)
	var ok bool
	if preimage, ok = appendLP(preimage, string(kind)); !ok {
		return "", ErrInvalidOperationBinding
	}
	preimage = appendU64(preimage, expectedGeneration)
	if preimage, ok = appendOptionalLP(preimage, disposition); !ok {
		return "", ErrInvalidOperationBinding
	}
	if preimage, ok = appendOptionalDigest(preimage, priorManifestDigest); !ok {
		return "", ErrInvalidOperationBinding
	}
	if preimage, ok = appendOptionalDigest(preimage, targetManifestDigest); !ok {
		return "", ErrInvalidOperationBinding
	}
	if preimage, ok = appendLP(preimage, string(targetFleet)); !ok {
		return "", ErrInvalidOperationBinding
	}
	overlay, err := hex.DecodeString(privateOverlayRevision)
	if err != nil || len(overlay) != sha256.Size {
		return "", ErrInvalidOperationBinding
	}
	preimage = append(preimage, overlay...)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

func ParseOperationBinding(document []byte, maxBytes int) (OperationBinding, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return OperationBinding{}, "", ErrInvalidOperationBinding
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var binding OperationBinding
	if err := decoder.Decode(&binding); err != nil {
		return OperationBinding{}, "", ErrInvalidOperationBinding
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OperationBinding{}, "", ErrInvalidOperationBinding
	}
	if err := validateOperationBinding(binding); err != nil {
		return OperationBinding{}, "", err
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(canonical, document) {
		return OperationBinding{}, "", ErrInvalidOperationBinding
	}
	return binding, canonicalArtifactDigest(operationBindingDomain, canonical), nil
}

func MarshalOperationBinding(binding OperationBinding) ([]byte, string, error) {
	if err := validateOperationBinding(binding); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(binding)
	if err != nil {
		return nil, "", ErrInvalidOperationBinding
	}
	return canonical, canonicalArtifactDigest(operationBindingDomain, canonical), nil
}

func validateOperationBinding(binding OperationBinding) error {
	if binding.SchemaVersion != operationBindingSchemaVersion ||
		!isLowerHex64(binding.OperationID) {
		return ErrInvalidOperationBinding
	}
	derived, err := DeriveOperationID(
		binding.Kind,
		binding.InstallDisposition,
		binding.ExpectedGeneration,
		binding.PriorManifestDigest,
		binding.TargetManifestDigest,
		binding.TargetFleet,
		binding.PrivateOverlayRevision,
	)
	if err != nil || derived != binding.OperationID {
		return ErrInvalidOperationBinding
	}
	return nil
}

func validateOperationIdentity(
	kind OperationKind,
	disposition *InstallDisposition,
	expectedGeneration uint64,
	priorManifestDigest *string,
	targetManifestDigest *string,
	targetFleet fleetfence.Fleet,
	privateOverlayRevision string,
) error {
	if !validOperationKind(kind) ||
		!validFleet(targetFleet) ||
		!isLowerHex64(privateOverlayRevision) ||
		!validOptionalLowerDigest(priorManifestDigest) ||
		!validOptionalLowerDigest(targetManifestDigest) {
		return ErrInvalidOperationBinding
	}
	if kind != OperationKindInstall && disposition != nil {
		return ErrInvalidOperationBinding
	}
	switch kind {
	case OperationKindInstall:
		if disposition == nil || targetManifestDigest == nil {
			return ErrInvalidOperationBinding
		}
		switch *disposition {
		case InstallDispositionGreenfieldPortable:
			if expectedGeneration != 0 ||
				priorManifestDigest != nil ||
				targetFleet != fleetfence.FleetPortable {
				return ErrInvalidOperationBinding
			}
		case InstallDispositionUpgradePortable:
			if expectedGeneration == 0 ||
				priorManifestDigest == nil ||
				targetFleet != fleetfence.FleetPortable {
				return ErrInvalidOperationBinding
			}
		case InstallDispositionLegacyDisabledObserver:
			if expectedGeneration == 0 ||
				priorManifestDigest == nil ||
				targetFleet != fleetfence.FleetLegacy {
				return ErrInvalidOperationBinding
			}
		default:
			return ErrInvalidOperationBinding
		}
	case OperationKindSuspend:
		if expectedGeneration == 0 ||
			priorManifestDigest == nil ||
			targetManifestDigest != nil ||
			targetFleet != fleetfence.FleetNone {
			return ErrInvalidOperationBinding
		}
	case OperationKindResume:
		if expectedGeneration == 0 ||
			targetManifestDigest == nil ||
			targetFleet != fleetfence.FleetPortable {
			return ErrInvalidOperationBinding
		}
	case OperationKindRollback:
		if expectedGeneration == 0 ||
			priorManifestDigest == nil ||
			targetManifestDigest != nil ||
			targetFleet != fleetfence.FleetLegacy {
			return ErrInvalidOperationBinding
		}
	case OperationKindUninstall:
		if expectedGeneration == 0 ||
			priorManifestDigest == nil ||
			targetManifestDigest != nil ||
			(targetFleet != fleetfence.FleetNone &&
				targetFleet != fleetfence.FleetLegacy) {
			return ErrInvalidOperationBinding
		}
	default:
		return ErrInvalidOperationBinding
	}
	return nil
}

func validOperationKind(kind OperationKind) bool {
	switch kind {
	case OperationKindInstall,
		OperationKindSuspend,
		OperationKindResume,
		OperationKindRollback,
		OperationKindUninstall:
		return true
	default:
		return false
	}
}

func validFleet(fleet fleetfence.Fleet) bool {
	return fleet == fleetfence.FleetNone ||
		fleet == fleetfence.FleetPortable ||
		fleet == fleetfence.FleetLegacy
}

func validOptionalLowerDigest(value *string) bool {
	return value == nil || isLowerHex64(*value)
}

func appendU32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendU64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendLP(destination []byte, value string) ([]byte, bool) {
	if uint64(len(value)) > math.MaxUint32 {
		return destination, false
	}
	destination = appendU32(destination, uint32(len(value)))
	return append(destination, value...), true
}

func appendOptionalLP[T ~string](destination []byte, value *T) ([]byte, bool) {
	if value == nil {
		return append(destination, 0), true
	}
	destination = append(destination, 1)
	return appendLP(destination, string(*value))
}

func appendOptionalDigest(destination []byte, value *string) ([]byte, bool) {
	if value == nil {
		return append(destination, 0), true
	}
	decoded, err := hex.DecodeString(*value)
	if err != nil || len(decoded) != sha256.Size {
		return destination, false
	}
	destination = append(destination, 1)
	return append(destination, decoded...), true
}
