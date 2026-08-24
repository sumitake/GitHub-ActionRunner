package failoverclient

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	ErrLease       = errors.New("failoverclient: lease")
	ErrLeaseBudget = errors.New("failoverclient: heartbeat budget")
	hex64Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fleetIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	aliasPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

const (
	maxJavaScriptSafeInteger        uint64 = 1<<53 - 1
	maxProtocolDurationMilliseconds int64  = 9_223_372_036_854
)

type LeaseHolder string

const (
	HolderPortable LeaseHolder = "portable"
	HolderLegacy   LeaseHolder = "legacy"
)

type LeaseMode string

const (
	LeaseDisabled   LeaseMode = "disabled"
	LeaseCanaryOnly LeaseMode = "canary-only"
	LeaseEnabled    LeaseMode = "enabled"
)

type AcquisitionLeaseV1 struct {
	ProtocolVersion          int         `json:"protocolVersion"`
	FleetID                  string      `json:"fleetId"`
	Holder                   LeaseHolder `json:"holder"`
	ServerEpoch              uint64      `json:"serverEpoch"`
	SessionID                string      `json:"sessionId"`
	LeaseGeneration          uint64      `json:"leaseGeneration"`
	Mode                     LeaseMode   `json:"mode"`
	PolicyDigest             string      `json:"policyDigest"`
	RepositoryPolicyRevision uint64      `json:"repositoryPolicyRevision"`
	LocalPolicyEpoch         uint64      `json:"localPolicyEpoch"`
	MaxCapacity              int         `json:"maxCapacity"`
	CanaryScaleSet           *string     `json:"canaryScaleSet"`
	ArchivedDisabledAliases  []string    `json:"archivedDisabledAliases"`
	DurationMs               int64       `json:"durationMs"`
	Expiry                   string      `json:"expiry"`
}

type HeartbeatBudget struct {
	LeaseDuration      time.Duration
	MaxAttemptInterval time.Duration
	Deadline           time.Duration
	ShorteningMargin   time.Duration
	LostRenewals       uint
}

func ParseLeaseV1(raw []byte) (AcquisitionLeaseV1, error) {
	var lease AcquisitionLeaseV1
	if _, err := decodeExactMessage(raw, leaseFields, &lease, "canaryScaleSet"); err != nil {
		return AcquisitionLeaseV1{}, err
	}
	if err := lease.validate(); err != nil {
		return AcquisitionLeaseV1{}, err
	}
	return lease, nil
}

func (lease AcquisitionLeaseV1) validate() error {
	if lease.ProtocolVersion != 1 ||
		!fleetIDPattern.MatchString(lease.FleetID) ||
		(lease.Holder != HolderPortable && lease.Holder != HolderLegacy) ||
		!hex64Pattern.MatchString(lease.SessionID) ||
		!hex64Pattern.MatchString(lease.PolicyDigest) ||
		lease.DurationMs <= 0 ||
		lease.DurationMs > maxProtocolDurationMilliseconds ||
		uint64(lease.DurationMs) > maxJavaScriptSafeInteger ||
		lease.ServerEpoch > maxJavaScriptSafeInteger ||
		lease.LeaseGeneration == 0 ||
		lease.LeaseGeneration > maxJavaScriptSafeInteger ||
		lease.RepositoryPolicyRevision > maxJavaScriptSafeInteger ||
		lease.LocalPolicyEpoch > maxJavaScriptSafeInteger ||
		lease.MaxCapacity < 0 ||
		uint64(lease.MaxCapacity) > maxJavaScriptSafeInteger {
		return fmt.Errorf("%w: identity", ErrLease)
	}
	if _, err := parseProtocolTimestamp(lease.Expiry); err != nil {
		return fmt.Errorf("%w: identity", ErrLease)
	}
	if err := validateAliasSet(lease.ArchivedDisabledAliases); err != nil {
		return err
	}
	switch lease.Mode {
	case LeaseCanaryOnly:
		if lease.MaxCapacity != 1 || lease.CanaryScaleSet == nil || !aliasPattern.MatchString(*lease.CanaryScaleSet) {
			return fmt.Errorf("%w: canary shape", ErrLease)
		}
	case LeaseDisabled:
		if lease.MaxCapacity != 0 || lease.CanaryScaleSet != nil {
			return fmt.Errorf("%w: disabled shape", ErrLease)
		}
	case LeaseEnabled:
		if lease.MaxCapacity < 1 || (lease.CanaryScaleSet != nil && !aliasPattern.MatchString(*lease.CanaryScaleSet)) {
			return fmt.Errorf("%w: enabled shape", ErrLease)
		}
	default:
		return fmt.Errorf("%w: mode", ErrLease)
	}
	return nil
}

func (lease AcquisitionLeaseV1) AdmissionAuthorityKey() (string, error) {
	if err := lease.validate(); err != nil {
		return "", err
	}
	key := map[string]any{
		"archivedDisabledAliases":  lease.ArchivedDisabledAliases,
		"canaryScaleSet":           lease.CanaryScaleSet,
		"durationMs":               lease.DurationMs,
		"fleetId":                  lease.FleetID,
		"holder":                   string(lease.Holder),
		"leaseGeneration":          lease.LeaseGeneration,
		"localPolicyEpoch":         lease.LocalPolicyEpoch,
		"maxCapacity":              lease.MaxCapacity,
		"mode":                     string(lease.Mode),
		"policyDigest":             lease.PolicyDigest,
		"protocolVersion":          lease.ProtocolVersion,
		"repositoryPolicyRevision": lease.RepositoryPolicyRevision,
		"serverEpoch":              lease.ServerEpoch,
		"sessionId":                lease.SessionID,
	}
	encoded, err := CanonicalJSON(key)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (budget HeartbeatBudget) Validate() error {
	if budget.LeaseDuration <= 0 ||
		budget.MaxAttemptInterval <= 0 ||
		budget.Deadline <= 0 ||
		budget.ShorteningMargin <= 0 ||
		budget.LostRenewals < 1 {
		return fmt.Errorf("%w: incomplete", ErrLeaseBudget)
	}
	if budget.LostRenewals == ^uint(0) {
		return fmt.Errorf("%w: overflow", ErrLeaseBudget)
	}
	const maxDuration = time.Duration(1<<63 - 1)
	renewalCount := uint64(budget.LostRenewals) + 1
	if renewalCount > uint64(maxDuration/budget.MaxAttemptInterval) {
		return fmt.Errorf("%w: overflow", ErrLeaseBudget)
	}
	right := time.Duration(renewalCount) * budget.MaxAttemptInterval
	if right > maxDuration-budget.Deadline {
		return fmt.Errorf("%w: overflow", ErrLeaseBudget)
	}
	right += budget.Deadline
	if right > maxDuration-budget.ShorteningMargin {
		return fmt.Errorf("%w: overflow", ErrLeaseBudget)
	}
	right += budget.ShorteningMargin
	if !(budget.LeaseDuration > right) {
		return fmt.Errorf("%w: inequality", ErrLeaseBudget)
	}
	return nil
}

func LocalLeaseDeadline(sendAnchor time.Time, duration, margin time.Duration) (time.Time, error) {
	if sendAnchor.IsZero() || duration <= 0 || margin <= 0 || duration <= margin {
		return time.Time{}, fmt.Errorf("%w: local deadline", ErrLease)
	}
	return sendAnchor.Add(duration - margin), nil
}

func validateAliasSet(aliases []string) error {
	for i, alias := range aliases {
		if !aliasPattern.MatchString(alias) {
			return fmt.Errorf("%w: alias", ErrLease)
		}
		if i > 0 && alias <= aliases[i-1] {
			return fmt.Errorf("%w: alias order", ErrLease)
		}
	}
	return nil
}
