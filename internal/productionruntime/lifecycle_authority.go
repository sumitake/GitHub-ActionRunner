package productionruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maximumHostedHoldEvidenceBytes = 1 << 20
	hostedHoldEvidenceDomain       = "portable-ghar-hosted-hold-evidence-v1"
)

var ErrLifecycleAuthority = errors.New(
	"productionruntime: lifecycle authority invalid",
)

type AuthorityValidity string

const (
	AuthorityValid       AuthorityValidity = "valid"
	AuthorityInvalid     AuthorityValidity = "invalid"
	AuthorityUnavailable AuthorityValidity = "unavailable"
)

type HostedHoldEvidence struct {
	SchemaVersion   uint32    `json:"schema_version"`
	HoldID          string    `json:"hold_id"`
	TransitionEpoch uint64    `json:"transition_epoch"`
	FenceGeneration uint64    `json:"fence_generation"`
	Route           string    `json:"route"`
	HoldActive      bool      `json:"hold_active"`
	Repositories    []string  `json:"repositories"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	ProofDigest     string    `json:"proof_digest"`
}

type HostedHoldExpectation struct {
	Path              string
	RepositoryAliases []string
	FenceGeneration   uint64
	EvidenceDigest    string
}

type HostedHoldValidation struct {
	Validity        AuthorityValidity
	EvidenceDigest  string
	ProofDigest     string
	TransitionEpoch uint64
}

type HostedHoldAuthority interface {
	Validate(context.Context, HostedHoldExpectation) HostedHoldValidation
}

type LegacyCommandExpectation struct {
	Path                string
	CommandDigest       string
	ConfigurationDigest string
	ImageDigests        []string
	WatchdogDigest      string
}

type LegacyCommandValidation struct {
	Validity AuthorityValidity
}

type LegacyCommandAuthority interface {
	Validate(context.Context, LegacyCommandExpectation) LegacyCommandValidation
}

// UnavailableLegacyCommandAuthority is the production fail-closed authority
// until a separately governed legacy executor can positively validate and
// apply the pinned command. It distinguishes malformed bindings from an
// otherwise valid but unavailable integration and never reports valid.
type UnavailableLegacyCommandAuthority struct{}

func NewUnavailableLegacyCommandAuthority() (
	*UnavailableLegacyCommandAuthority,
	error,
) {
	return &UnavailableLegacyCommandAuthority{}, nil
}

func (*UnavailableLegacyCommandAuthority) Validate(
	ctx context.Context,
	expectation LegacyCommandExpectation,
) LegacyCommandValidation {
	if !validLegacyCommandExpectation(expectation) {
		return LegacyCommandValidation{Validity: AuthorityInvalid}
	}
	if ctx == nil || ctx.Err() != nil {
		return LegacyCommandValidation{Validity: AuthorityUnavailable}
	}
	return LegacyCommandValidation{Validity: AuthorityUnavailable}
}

func validLegacyCommandExpectation(
	expectation LegacyCommandExpectation,
) bool {
	if !canonicalPath(expectation.Path) ||
		!lowerHexDigest(expectation.CommandDigest) ||
		!lowerHexDigest(expectation.ConfigurationDigest) ||
		!lowerHexDigest(expectation.WatchdogDigest) ||
		len(expectation.ImageDigests) == 0 ||
		!slices.IsSorted(expectation.ImageDigests) {
		return false
	}
	for index, digest := range expectation.ImageDigests {
		if !digestQualifiedImageReference(digest) ||
			(index > 0 && expectation.ImageDigests[index-1] == digest) {
			return false
		}
	}
	return true
}

type SystemHostedHoldAuthority struct {
	now func() time.Time
}

func NewSystemHostedHoldAuthority(
	now func() time.Time,
) (*SystemHostedHoldAuthority, error) {
	if now == nil {
		return nil, ErrLifecycleAuthority
	}
	return &SystemHostedHoldAuthority{now: now}, nil
}

func (authority *SystemHostedHoldAuthority) Validate(
	ctx context.Context,
	expectation HostedHoldExpectation,
) HostedHoldValidation {
	if authority == nil ||
		authority.now == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		!validHostedHoldExpectation(expectation) {
		return HostedHoldValidation{Validity: AuthorityUnavailable}
	}
	document, err := readPinnedAbsoluteFile(
		expectation.Path,
		0o600,
		maximumHostedHoldEvidenceBytes,
	)
	if err != nil {
		if _, statErr := os.Lstat(expectation.Path); errors.Is(
			statErr,
			os.ErrNotExist,
		) {
			return HostedHoldValidation{Validity: AuthorityUnavailable}
		}
		return HostedHoldValidation{Validity: AuthorityInvalid}
	}
	var evidence HostedHoldEvidence
	if !decodeClosed(document, &evidence) {
		return HostedHoldValidation{Validity: AuthorityInvalid}
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(canonical, document) {
		return HostedHoldValidation{Validity: AuthorityInvalid}
	}
	now := authority.now().UTC()
	if !validHostedHoldEvidence(evidence, expectation, now) {
		return HostedHoldValidation{Validity: AuthorityInvalid}
	}
	digest := digestArtifact(hostedHoldEvidenceDomain, canonical)
	if expectation.EvidenceDigest != "" &&
		expectation.EvidenceDigest != digest {
		return HostedHoldValidation{Validity: AuthorityInvalid}
	}
	return HostedHoldValidation{
		Validity:        AuthorityValid,
		EvidenceDigest:  digest,
		ProofDigest:     evidence.ProofDigest,
		TransitionEpoch: evidence.TransitionEpoch,
	}
}

func validHostedHoldExpectation(expectation HostedHoldExpectation) bool {
	if !canonicalPath(expectation.Path) ||
		filepath.Base(expectation.Path) == "." ||
		filepath.Base(expectation.Path) == ".." ||
		expectation.FenceGeneration == 0 ||
		expectation.RepositoryAliases == nil ||
		len(expectation.RepositoryAliases) == 0 ||
		!slices.IsSorted(expectation.RepositoryAliases) ||
		(expectation.EvidenceDigest != "" &&
			!lowerHexDigest(expectation.EvidenceDigest)) {
		return false
	}
	for index, alias := range expectation.RepositoryAliases {
		if !validAuthorityScalar(alias) ||
			(index > 0 && expectation.RepositoryAliases[index-1] == alias) {
			return false
		}
	}
	return true
}

func validHostedHoldEvidence(
	evidence HostedHoldEvidence,
	expectation HostedHoldExpectation,
	now time.Time,
) bool {
	if evidence.SchemaVersion != 1 ||
		!validAuthorityScalar(evidence.HoldID) ||
		evidence.TransitionEpoch == 0 ||
		evidence.FenceGeneration != expectation.FenceGeneration ||
		evidence.Route != "hosted" ||
		!evidence.HoldActive ||
		!slices.Equal(evidence.Repositories, expectation.RepositoryAliases) ||
		!lowerHexDigest(evidence.ProofDigest) ||
		evidence.NotBefore.IsZero() ||
		evidence.NotAfter.IsZero() ||
		!evidence.NotBefore.Before(evidence.NotAfter) ||
		now.Before(evidence.NotBefore) ||
		!now.Before(evidence.NotAfter) {
		return false
	}
	return true
}

func validAuthorityScalar(value string) bool {
	if len(value) == 0 ||
		len(value) > 1024 ||
		!utf8.ValidString(value) ||
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
