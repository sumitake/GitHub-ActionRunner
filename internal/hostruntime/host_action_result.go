package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	hostActionResultSchemaVersion = uint32(1)
	hostActionResultDomain        = "portable-ghar-host-action-result-v1"
)

var ErrInvalidHostActionResult = errors.New(
	"hostruntime: invalid host action result",
)

type HostActionStatus string

const (
	HostActionComplete    HostActionStatus = "complete"
	HostActionRecoverable HostActionStatus = "recoverable"
	HostActionCompensated HostActionStatus = "compensated"
	HostActionFailed      HostActionStatus = "failed"
)

type HostActionResult struct {
	SchemaVersion     uint32           `json:"schema_version"`
	Status            HostActionStatus `json:"status"`
	OperationID       string           `json:"operation_id"`
	JournalDigest     string           `json:"journal_digest"`
	TargetProofDigest *string          `json:"target_proof_digest"`
	FenceGeneration   uint64           `json:"fence_generation"`
	ActiveFleet       fleetfence.Fleet `json:"active_fleet"`
	ErrorClass        string           `json:"error_class"`
}

func ParseHostActionResult(
	document []byte,
	maxBytes int,
) (HostActionResult, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return HostActionResult{}, "", ErrInvalidHostActionResult
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var result HostActionResult
	if err := decoder.Decode(&result); err != nil {
		return HostActionResult{}, "", ErrInvalidHostActionResult
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return HostActionResult{}, "", ErrInvalidHostActionResult
	}
	if err := validateHostActionResult(result); err != nil {
		return HostActionResult{}, "", err
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, document) {
		return HostActionResult{}, "", ErrInvalidHostActionResult
	}
	return result, canonicalArtifactDigest(hostActionResultDomain, canonical), nil
}

func MarshalHostActionResult(
	result HostActionResult,
) ([]byte, string, error) {
	if err := validateHostActionResult(result); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		return nil, "", ErrInvalidHostActionResult
	}
	return canonical, canonicalArtifactDigest(hostActionResultDomain, canonical), nil
}

func validateHostActionResult(result HostActionResult) error {
	if result.SchemaVersion != hostActionResultSchemaVersion ||
		!isLowerHex64(result.OperationID) ||
		!isLowerHex64(result.JournalDigest) ||
		!validFleet(result.ActiveFleet) {
		return ErrInvalidHostActionResult
	}
	switch result.Status {
	case HostActionComplete:
		if result.TargetProofDigest == nil ||
			!isLowerHex64(*result.TargetProofDigest) ||
			result.ErrorClass != "" {
			return ErrInvalidHostActionResult
		}
	case HostActionRecoverable, HostActionCompensated, HostActionFailed:
		if result.TargetProofDigest != nil ||
			!validLifecycleScalar(result.ErrorClass) {
			return ErrInvalidHostActionResult
		}
	default:
		return ErrInvalidHostActionResult
	}
	return nil
}
