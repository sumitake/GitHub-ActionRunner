package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	runtimeManifestSchemaVersion = uint32(1)
	runtimeManifestDomain        = "portable-ghar-runtime-manifest-v1"
	runtimeManifestEgressMode    = "restricted-broker-v1"
	runtimeManifestAcquisition   = "disabled"
)

var ErrInvalidRuntimeManifest = errors.New("hostruntime: invalid runtime manifest")

// RuntimeManifest is the public, immutable release identity consumed by the
// host lifecycle. It deliberately contains no target path, credential,
// repository, route, command, or mutable policy value.
type RuntimeManifest struct {
	SchemaVersion         uint32  `json:"schema_version"`
	BuildID               string  `json:"build_id"`
	ControllerSHA256      string  `json:"controller_sha256"`
	RunnerImageDigest     string  `json:"runner_image_digest"`
	AdapterImageDigest    string  `json:"adapter_image_digest"`
	BrokerImageDigest     string  `json:"broker_image_digest"`
	HelperImageDigest     string  `json:"helper_image_digest"`
	VerifierImageDigest   string  `json:"verifier_image_digest"`
	TrustBundleDigest     string  `json:"trust_bundle_digest"`
	SeccompProfileDigest  string  `json:"seccomp_profile_digest"`
	EgressMode            string  `json:"egress_mode"`
	PolicyManifestDigest  string  `json:"policy_manifest_digest"`
	ConntrackBudgetDigest string  `json:"conntrack_budget_digest"`
	StorageBudgetDigest   string  `json:"storage_budget_digest"`
	LogPolicyDigest       string  `json:"log_policy_digest"`
	ArchiveManifestDigest *string `json:"archive_manifest_digest"`
	AcquisitionDefault    string  `json:"acquisition_default"`
	FleetGeneration       uint64  `json:"fleet_generation"`
}

// ParseRuntimeManifest accepts only the byte-exact V1 canonical JSON form and
// returns its domain-separated digest.
func ParseRuntimeManifest(document []byte, maxBytes int) (RuntimeManifest, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return RuntimeManifest{}, "", ErrInvalidRuntimeManifest
	}

	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest RuntimeManifest
	if err := decoder.Decode(&manifest); err != nil {
		return RuntimeManifest{}, "", ErrInvalidRuntimeManifest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RuntimeManifest{}, "", ErrInvalidRuntimeManifest
	}
	if err := validateRuntimeManifest(manifest); err != nil {
		return RuntimeManifest{}, "", err
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, document) {
		return RuntimeManifest{}, "", ErrInvalidRuntimeManifest
	}
	return manifest, canonicalArtifactDigest(runtimeManifestDomain, canonical), nil
}

// MarshalRuntimeManifest validates and emits the only canonical V1 wire form.
func MarshalRuntimeManifest(manifest RuntimeManifest) ([]byte, string, error) {
	if err := validateRuntimeManifest(manifest); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", ErrInvalidRuntimeManifest
	}
	return canonical, canonicalArtifactDigest(runtimeManifestDomain, canonical), nil
}

func validateRuntimeManifest(manifest RuntimeManifest) error {
	rawDigests := [...]string{
		manifest.BuildID,
		manifest.ControllerSHA256,
		manifest.TrustBundleDigest,
		manifest.SeccompProfileDigest,
		manifest.PolicyManifestDigest,
		manifest.ConntrackBudgetDigest,
		manifest.StorageBudgetDigest,
		manifest.LogPolicyDigest,
	}
	for _, digest := range rawDigests {
		if !isLowerHex64(digest) {
			return ErrInvalidRuntimeManifest
		}
	}
	if manifest.ArchiveManifestDigest != nil &&
		!isLowerHex64(*manifest.ArchiveManifestDigest) {
		return ErrInvalidRuntimeManifest
	}
	imageDigests := [...]string{
		manifest.RunnerImageDigest,
		manifest.AdapterImageDigest,
		manifest.BrokerImageDigest,
		manifest.HelperImageDigest,
		manifest.VerifierImageDigest,
	}
	for _, digest := range imageDigests {
		if !validImageDigest(digest) {
			return ErrInvalidRuntimeManifest
		}
	}
	if manifest.SchemaVersion != runtimeManifestSchemaVersion ||
		manifest.EgressMode != runtimeManifestEgressMode ||
		manifest.AcquisitionDefault != runtimeManifestAcquisition ||
		manifest.FleetGeneration == 0 {
		return ErrInvalidRuntimeManifest
	}
	return nil
}

func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") &&
		len(value) == len("sha256:")+64 &&
		isLowerHex64(strings.TrimPrefix(value, "sha256:"))
}

func canonicalArtifactDigest(domain string, canonical []byte) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(canonical)
	return hex.EncodeToString(hasher.Sum(nil))
}
