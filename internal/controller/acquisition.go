package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	acquisitionPolicyDomain        = "portable-ghar-acquisition-policy-v1\n"
	acquisitionPermitBindingDomain = "portable-ghar-acquisition-permit-binding-v1\n"
	maxAcquisitionScaleSetBytes    = 128
	maxAcquisitionRepositoryBytes  = 64
	maxAcquisitionSetEntries       = 1024
)

var (
	ErrInvalidAcquisitionPolicy   = errors.New("controller: invalid acquisition policy")
	ErrAcquisitionPermitAuthority = errors.New(
		"controller: acquisition permit authority invalid",
	)
)

// AcquisitionTransitioner is the single persisted epoch barrier used by
// startup, pressure, suspension, and fatal/zero transitions.
type AcquisitionTransitioner interface {
	Snapshot(context.Context) (AcquisitionPolicy, error)
	Transition(context.Context, uint64, AcquisitionPolicy) (AcquisitionPolicy, error)
}

// AcquisitionGuard is opaque authority whose lifetime covers exactly one
// guarded external operation. Closing it is part of the operation result.
type AcquisitionGuard interface {
	Close() error
}

// AcquisitionPermitGuard is the operation-local remote-authority guard. It is
// deliberately narrower than the shared host/fleet guard: its context bounds
// the external effect, Revalidate is the pre-effect barrier, and Admit is the
// sole post-effect transition that can release a trustworthy result.
type AcquisitionPermitGuard interface {
	AcquisitionGuard
	Context() context.Context
	Binding() AcquisitionPermitBinding
	ValidateBinding(context.Context, AcquisitionPermitBinding) error
	Revalidate() error
	Admit() error
}

// FleetGuardProvider acquires current host-local portable-fleet authority.
type FleetGuardProvider interface {
	AcquirePortable(context.Context) (AcquisitionGuard, error)
}

// AcquisitionPermitRequest is the secret-free, exact Worker permit binding.
// The provider validates Worker-owned response fields before returning an
// opaque guard; the controller never receives or stores a reusable bearer.
type AcquisitionPermitRequest struct {
	OperationID              string
	RepositoryAlias          string
	ScaleSetName             string
	PolicyDigest             string
	OperationKind            string
	PolicyEpoch              uint64
	PolicyMode               AcquisitionMode
	MaxCapacity              int
	RepositoryPolicyRevision uint64
}

// AcquisitionPermitBinding is the immutable, secret-free authority snapshot
// carried by a released listener. AuthorityKey is the provider's closed
// admission-authority key, not an HMAC or reusable bearer credential.
type AcquisitionPermitBinding struct {
	AuthorityRevision        uint64
	AuthorityKey             string
	FenceGeneration          uint64
	ServerEpoch              uint64
	SessionID                string
	LeaseGeneration          uint64
	OperationID              string
	RepositoryAlias          string
	ScaleSetName             string
	OperationKind            string
	PolicyDigest             string
	PolicyEpoch              uint64
	PolicyMode               AcquisitionMode
	MaxCapacity              int
	RepositoryPolicyRevision uint64
	OriginalLocalDeadline    time.Time
}

// AcquisitionPermitBindingDigest returns the fixed, domain-separated durable
// commitment used by the one listener-release effect. It commits every field,
// including the authority-clock domain, without persisting the variably sized
// admission-authority key itself.
func AcquisitionPermitBindingDigest(
	binding AcquisitionPermitBinding,
) ([sha256.Size]byte, error) {
	if binding.AuthorityRevision == 0 ||
		binding.AuthorityKey == "" ||
		binding.FenceGeneration == 0 ||
		binding.ServerEpoch == 0 ||
		binding.SessionID == "" ||
		binding.LeaseGeneration == 0 ||
		binding.OperationID == "" ||
		!validAcquisitionScalar(binding.RepositoryAlias, maxAcquisitionRepositoryBytes) ||
		!validAcquisitionScalar(binding.ScaleSetName, maxAcquisitionScaleSetBytes) ||
		binding.PolicyDigest == "" ||
		binding.PolicyEpoch == 0 ||
		binding.MaxCapacity <= 0 ||
		binding.RepositoryPolicyRevision == 0 ||
		binding.OriginalLocalDeadline.IsZero() ||
		binding.OriginalLocalDeadline.Unix() < 0 ||
		binding.OriginalLocalDeadline.Location().String() == "" {
		return [sha256.Size]byte{}, ErrInvalidAcquisitionPolicy
	}
	switch binding.OperationKind {
	case "poll", "acquire", "jit":
	default:
		return [sha256.Size]byte{}, ErrInvalidAcquisitionPolicy
	}
	switch binding.PolicyMode {
	case AcquisitionEnabled:
	case AcquisitionCanaryOnly:
		if binding.MaxCapacity != 1 {
			return [sha256.Size]byte{}, ErrInvalidAcquisitionPolicy
		}
	default:
		return [sha256.Size]byte{}, ErrInvalidAcquisitionPolicy
	}

	var document bytes.Buffer
	document.WriteString(acquisitionPermitBindingDomain)
	writeUint64 := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		document.Write(encoded[:])
	}
	writeString := func(value string) {
		writeUint64(uint64(len(value)))
		document.WriteString(value)
	}
	writeUint64(binding.AuthorityRevision)
	writeString(binding.AuthorityKey)
	writeUint64(binding.FenceGeneration)
	writeUint64(binding.ServerEpoch)
	writeString(binding.SessionID)
	writeUint64(binding.LeaseGeneration)
	writeString(binding.OperationID)
	writeString(binding.RepositoryAlias)
	writeString(binding.ScaleSetName)
	writeString(binding.OperationKind)
	writeString(binding.PolicyDigest)
	writeUint64(binding.PolicyEpoch)
	writeString(string(binding.PolicyMode))
	writeUint64(uint64(binding.MaxCapacity))
	writeUint64(binding.RepositoryPolicyRevision)
	writeUint64(uint64(binding.OriginalLocalDeadline.Unix()))
	writeUint64(uint64(binding.OriginalLocalDeadline.Nanosecond()))
	writeString(binding.OriginalLocalDeadline.Location().String())
	return sha256.Sum256(document.Bytes()), nil
}

// AcquisitionPermitProvider acquires one fresh outbound Worker permit.
type AcquisitionPermitProvider interface {
	Acquire(context.Context, AcquisitionPermitRequest) (AcquisitionPermitGuard, error)
	Invalidate(context.Context) error
}

// CanonicalizeAcquisitionPolicy validates the closed acquisition-policy shape,
// deep-copies it, and sorts both set projections by unsigned UTF-8 bytes.
func CanonicalizeAcquisitionPolicy(policy AcquisitionPolicy) (AcquisitionPolicy, error) {
	if len(policy.EligibleScaleSets) > maxAcquisitionSetEntries ||
		len(policy.RepositoryPolicies) > maxAcquisitionSetEntries {
		return AcquisitionPolicy{}, fmt.Errorf("%w: set bound", ErrInvalidAcquisitionPolicy)
	}

	switch policy.Mode {
	case AcquisitionDisabled, AcquisitionFatal:
		if policy.MaxCapacity != 0 || len(policy.EligibleScaleSets) != 0 {
			return AcquisitionPolicy{}, fmt.Errorf(
				"%w: zero mode shape",
				ErrInvalidAcquisitionPolicy,
			)
		}
	case AcquisitionCanaryOnly:
		if policy.MaxCapacity != 1 || len(policy.EligibleScaleSets) != 1 {
			return AcquisitionPolicy{}, fmt.Errorf(
				"%w: canary shape",
				ErrInvalidAcquisitionPolicy,
			)
		}
	case AcquisitionEnabled:
		if policy.MaxCapacity <= 0 {
			return AcquisitionPolicy{}, fmt.Errorf(
				"%w: enabled capacity",
				ErrInvalidAcquisitionPolicy,
			)
		}
	default:
		return AcquisitionPolicy{}, fmt.Errorf("%w: mode", ErrInvalidAcquisitionPolicy)
	}

	canonical := policy
	if len(policy.EligibleScaleSets) == 0 {
		canonical.EligibleScaleSets = nil
	} else {
		canonical.EligibleScaleSets = append([]string(nil), policy.EligibleScaleSets...)
		for _, name := range canonical.EligibleScaleSets {
			if !validAcquisitionScalar(name, maxAcquisitionScaleSetBytes) {
				return AcquisitionPolicy{}, fmt.Errorf(
					"%w: eligible scale set",
					ErrInvalidAcquisitionPolicy,
				)
			}
		}
		sort.Slice(canonical.EligibleScaleSets, func(i, j int) bool {
			return bytes.Compare(
				[]byte(canonical.EligibleScaleSets[i]),
				[]byte(canonical.EligibleScaleSets[j]),
			) < 0
		})
		for i := 1; i < len(canonical.EligibleScaleSets); i++ {
			if canonical.EligibleScaleSets[i-1] == canonical.EligibleScaleSets[i] {
				return AcquisitionPolicy{}, fmt.Errorf(
					"%w: duplicate eligible scale set",
					ErrInvalidAcquisitionPolicy,
				)
			}
		}
	}

	if len(policy.RepositoryPolicies) == 0 {
		canonical.RepositoryPolicies = nil
	} else {
		canonical.RepositoryPolicies = append(
			[]RepositoryPolicySummary(nil),
			policy.RepositoryPolicies...,
		)
		for _, repository := range canonical.RepositoryPolicies {
			if !validAcquisitionScalar(
				repository.Alias,
				maxAcquisitionRepositoryBytes,
			) || !validRepositoryEligibility(repository.Eligibility) {
				return AcquisitionPolicy{}, fmt.Errorf(
					"%w: repository policy",
					ErrInvalidAcquisitionPolicy,
				)
			}
		}
		sort.Slice(canonical.RepositoryPolicies, func(i, j int) bool {
			return bytes.Compare(
				[]byte(canonical.RepositoryPolicies[i].Alias),
				[]byte(canonical.RepositoryPolicies[j].Alias),
			) < 0
		})
		for i := 1; i < len(canonical.RepositoryPolicies); i++ {
			if canonical.RepositoryPolicies[i-1].Alias ==
				canonical.RepositoryPolicies[i].Alias {
				return AcquisitionPolicy{}, fmt.Errorf(
					"%w: duplicate repository alias",
					ErrInvalidAcquisitionPolicy,
				)
			}
		}
	}

	return canonical, nil
}

// AcquisitionPolicyDigest returns the public V1 digest. Epoch is deliberately
// excluded; the persisted epoch and digest are separately bound by permits.
func AcquisitionPolicyDigest(policy AcquisitionPolicy) ([sha256.Size]byte, error) {
	document, err := canonicalAcquisitionPolicyBytes(policy)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(document), nil
}

func canonicalAcquisitionPolicyBytes(policy AcquisitionPolicy) ([]byte, error) {
	canonical, err := CanonicalizeAcquisitionPolicy(policy)
	if err != nil {
		return nil, err
	}
	var document strings.Builder
	document.WriteString(acquisitionPolicyDomain)
	document.WriteString(string(canonical.Mode))
	document.WriteByte('\n')
	document.WriteString(strconv.Itoa(canonical.MaxCapacity))
	document.WriteByte('\n')
	document.WriteString(strconv.FormatUint(canonical.RepositoryPolicyRevision, 10))
	document.WriteByte('\n')
	for _, name := range canonical.EligibleScaleSets {
		document.WriteString(name)
		document.WriteByte('\n')
	}
	document.WriteString("--\n")
	for _, repository := range canonical.RepositoryPolicies {
		document.WriteString(repository.Alias)
		document.WriteByte('\t')
		document.WriteString(strconv.FormatUint(uint64(repository.MaxConcurrency), 10))
		document.WriteByte('\t')
		document.WriteString(repository.Eligibility)
		document.WriteByte('\n')
	}
	return []byte(document.String()), nil
}

func validAcquisitionScalar(value string, maxBytes int) bool {
	return value != "" &&
		len(value) <= maxBytes &&
		utf8.ValidString(value) &&
		!strings.ContainsAny(value, "\x00\t\r\n")
}

func validRepositoryEligibility(value string) bool {
	switch value {
	case "active", "archived-disabled", "pending-reactivation":
		return true
	default:
		return false
	}
}
