package hostruntime

import (
	"errors"
	"strings"
)

// EvidenceBinding identifies one exact build, profile, and evidence
// generation. Source and target evidence cannot be combined across bindings.
type EvidenceBinding struct {
	BuildID    string
	Profile    string
	Generation uint64
}

// SourceVerification is not TargetConformance and cannot be projected into a
// generic success boolean. Construction remains inside hostruntime verification
// code.
type SourceVerification struct {
	binding EvidenceBinding
	digest  string
}

// TargetConformance is reserved for positive Linux target evidence. A zero
// value represents no proof, not pending success.
type TargetConformance struct {
	binding EvidenceBinding
	digest  string
}

// DeploymentEligibility requires both proof types for one exact binding.
type DeploymentEligibility struct {
	binding EvidenceBinding
	source  string
	target  string
}

// Binding returns the nonsecret exact evidence identity.
func (d DeploymentEligibility) Binding() EvidenceBinding { return d.binding }

func recordSourceVerification(binding EvidenceBinding, digest string) (SourceVerification, error) {
	if err := validateEvidence(binding, digest); err != nil {
		return SourceVerification{}, err
	}
	return SourceVerification{binding: binding, digest: strings.ToLower(digest)}, nil
}

func recordTargetConformance(binding EvidenceBinding, digest string) (TargetConformance, error) {
	if err := validateEvidence(binding, digest); err != nil {
		return TargetConformance{}, err
	}
	return TargetConformance{binding: binding, digest: strings.ToLower(digest)}, nil
}

// NewDeploymentEligibility rejects every source-only, target-only, zero, or
// cross-generation construction.
func NewDeploymentEligibility(source SourceVerification, target TargetConformance) (DeploymentEligibility, error) {
	if source.digest == "" {
		return DeploymentEligibility{}, errors.New("hostruntime: source verification missing")
	}
	if target.digest == "" {
		return DeploymentEligibility{}, errors.New("hostruntime: target conformance missing")
	}
	if source.binding != target.binding {
		return DeploymentEligibility{}, errors.New("hostruntime: evidence binding mismatch")
	}
	return DeploymentEligibility{
		binding: source.binding,
		source:  source.digest,
		target:  target.digest,
	}, nil
}

func validateEvidence(binding EvidenceBinding, digest string) error {
	if binding.BuildID == "" || binding.Profile == "" || binding.Generation == 0 {
		return errors.New("hostruntime: incomplete evidence binding")
	}
	if hasControl(binding.BuildID) || hasControl(binding.Profile) {
		return errors.New("hostruntime: invalid evidence binding")
	}
	if !isLowerHex64(digest) {
		return errors.New("hostruntime: invalid evidence digest")
	}
	return nil
}
