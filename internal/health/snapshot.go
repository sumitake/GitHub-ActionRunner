// Package health defines closed, identity-bounded aggregate health documents.
// It is a dependency leaf: runtime packages may publish these values, while
// health never imports controller, state, admission, or host implementations.
package health

import (
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

var (
	ErrInvalidSnapshot        = errors.New("health: invalid heartbeat snapshot")
	ErrInvalidHistorySnapshot = errors.New("health: invalid history snapshot")
)

// AcquisitionMode is the closed public acquisition state.
type AcquisitionMode string

const (
	AcquisitionDisabled   AcquisitionMode = "disabled"
	AcquisitionCanaryOnly AcquisitionMode = "canary-only"
	AcquisitionEnabled    AcquisitionMode = "enabled"
	AcquisitionFatal      AcquisitionMode = "fatal"
)

// Pressure is the closed bounded-history pressure state.
type Pressure uint8

const (
	PressureNormal Pressure = iota + 1
	PressureWarning
	PressureStop
)

var aggregateIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// CapacitySummary is the closed, identity-free broker capacity projection.
type CapacitySummary struct {
	Configured int `json:"configured"`
	Effective  int `json:"effective"`
	Occupied   int `json:"occupied"`
	Available  int `json:"available"`
	Queued     int `json:"queued"`
}

func (c CapacitySummary) validate() bool {
	expectedAvailable := c.Effective - c.Occupied
	if expectedAvailable < 0 {
		expectedAvailable = 0
	}
	return c.Configured >= 0 &&
		c.Effective >= 0 &&
		c.Effective <= c.Configured &&
		c.Occupied >= 0 &&
		c.Occupied <= c.Configured &&
		c.Available >= 0 &&
		c.Available <= c.Effective &&
		c.Available == expectedAvailable &&
		c.Queued >= 0
}

// Snapshot is the Worker heartbeat. Its bounded fleet/profile/build strings
// are controller-owned operational identities, never repository, assignment,
// job, runner, message, path, route, or credential data.
type Snapshot struct {
	ObservedAt                  time.Time       `json:"observed_at"`
	FleetAlias                  string          `json:"fleet_alias"`
	AcquisitionMode             AcquisitionMode `json:"acquisition_mode"`
	PolicyEpoch                 uint64          `json:"policy_epoch"`
	PolicyDigest                string          `json:"policy_digest"`
	RepositoryPolicyRevision    uint64          `json:"repository_policy_revision"`
	Capacity                    CapacitySummary `json:"capacity"`
	AssignedJobs                uint64          `json:"assigned_jobs"`
	RunningJobs                 uint64          `json:"running_jobs"`
	OldestLiveAssignmentAge     time.Duration   `json:"oldest_live_assignment_age"`
	UnassignedReleasedListeners uint64          `json:"unassigned_released_listeners"`
	LastTerminalAt              time.Time       `json:"last_terminal_at,omitempty"`
	HostProfileID               string          `json:"host_profile_id"`
	Degraded                    bool            `json:"degraded"`
	BuildID                     string          `json:"build_id"`
}

// Validate rejects open or structurally ambiguous heartbeat documents before
// a publisher can expose them.
func (s Snapshot) Validate() error {
	if s.ObservedAt.IsZero() ||
		!validAcquisitionMode(s.AcquisitionMode) ||
		s.PolicyEpoch == 0 ||
		!isLowerHex64(s.PolicyDigest) ||
		s.RepositoryPolicyRevision == 0 ||
		!aggregateIDPattern.MatchString(s.FleetAlias) ||
		!validHostProfile(s.HostProfileID) ||
		!isLowerHex64(s.BuildID) ||
		!s.Capacity.validate() ||
		s.RunningJobs > s.AssignedJobs ||
		s.OldestLiveAssignmentAge < 0 ||
		(!s.LastTerminalAt.IsZero() &&
			s.LastTerminalAt.After(s.ObservedAt)) {
		return ErrInvalidSnapshot
	}
	return nil
}

// HistorySnapshot is the local bounded-history diagnostic document. It is
// deliberately separate from the Worker heartbeat.
type HistorySnapshot struct {
	ObservedAt                time.Time     `json:"observed_at"`
	Pressure                  Pressure      `json:"pressure"`
	HistoryRows               uint64        `json:"history_rows"`
	HistoryLogicalBytes       uint64        `json:"history_logical_bytes"`
	NetworkLedgerRows         uint64        `json:"network_ledger_rows"`
	NetworkLedgerLogicalBytes uint64        `json:"network_ledger_logical_bytes"`
	InflightWork              uint64        `json:"inflight_work"`
	UncertainAcknowledgements uint64        `json:"uncertain_acknowledgements"`
	OldestRetainedAge         time.Duration `json:"oldest_retained_age"`
	EffectiveCapacity         uint64        `json:"effective_capacity"`
	PolicyEpoch               uint64        `json:"policy_epoch"`
}

func (s HistorySnapshot) Validate() error {
	if s.ObservedAt.IsZero() ||
		(s.Pressure != PressureNormal &&
			s.Pressure != PressureWarning &&
			s.Pressure != PressureStop) ||
		s.OldestRetainedAge < 0 ||
		s.PolicyEpoch == 0 {
		return ErrInvalidHistorySnapshot
	}
	return nil
}

func validAcquisitionMode(mode AcquisitionMode) bool {
	switch mode {
	case AcquisitionDisabled,
		AcquisitionCanaryOnly,
		AcquisitionEnabled,
		AcquisitionFatal:
		return true
	default:
		return false
	}
}

func validHostProfile(profile string) bool {
	switch profile {
	case "strict-linux-v1", "qts-capless-root":
		return true
	default:
		return false
	}
}

func isLowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return false
	}
	for _, r := range value {
		if r >= 'A' && r <= 'F' {
			return false
		}
	}
	return true
}
