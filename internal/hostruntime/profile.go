package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	EgressBackendRestrictedBrokerV1 = "restricted-broker-v1"
	EgressBackendNftablesDirectV1   = "nftables-direct-v1"
)

var (
	ErrInvalidHostProfile   = errors.New("hostruntime: invalid host profile")
	ErrHostProfileSelection = errors.New("hostruntime: host profile selection failed")
	ErrInvalidRunnerSizing  = errors.New("hostruntime: invalid runner sizing")
	ErrInvalidConntrack     = errors.New("hostruntime: invalid conntrack sizing")
	ErrInvalidStorage       = errors.New("hostruntime: invalid storage sizing")
)

// Profile is one closed host-profile implementation. Its raw observations
// remain private; callers receive only validated, identity-free evidence.
type Profile interface {
	ID() HostProfile
	Probe(context.Context) (ConformanceReport, error)
	DiscoverNetworks(context.Context) (NetworkSnapshot, error)
}

type ProfileState string

const (
	ProfileNormal   ProfileState = "normal"
	ProfileDegraded ProfileState = "degraded"
	ProfileWarning  ProfileState = "warning"
	ProfileStop     ProfileState = "stop"
)

type ConformanceReport struct {
	ProfileID             HostProfile
	State                 ProfileState
	Degraded              bool
	EgressBackend         string
	Architecture          string
	KernelRelease         string
	RuntimeVersion        string
	EffectiveCapacity     uint32
	MemorySizingDigest    string
	ConntrackSizingDigest string
	StorageSizingDigest   string
	EvidenceDigest        string
}

type NetworkSnapshot struct {
	ProfileID          HostProfile
	RunnerNetworkMode  string
	BrokerNetworkID    string
	BrokerIPv6Enabled  bool
	RunnerLoopbackOnly bool
	RoutesComplete     bool
	EvidenceDigest     string
}

type ProfileSelectRequest struct {
	Explicit          HostProfile
	AllowDegradedRoot bool
}

type SelectedProfile struct {
	Profile Profile
	Report  ConformanceReport
	Network NetworkSnapshot
}

type PlatformFacts struct {
	OS                   string
	Architecture         string
	KernelRelease        string
	RuntimeVersion       string
	CgroupMemoryEnforced bool
	CgroupCPUEnforced    bool
	CgroupPIDsEnforced   bool
}

type CapabilitySets struct {
	EffectiveEmpty   bool
	PermittedEmpty   bool
	InheritableEmpty bool
	BoundingEmpty    bool
	AmbientEmpty     bool
}

// IsolationEvidence is the complete positive, typed host observation required
// before a profile can advertise runner capacity. It deliberately contains no
// path, interface, container, repository, or command-output field.
type IsolationEvidence struct {
	RunnerNetworkNone          bool
	RunnerTablesEmptyBefore    bool
	RunnerTablesEmptyAfter     bool
	RunnerConntrackEmptyBefore bool
	RunnerConntrackEmptyAfter  bool
	LoopbackFloodCompleted     bool
	NamespaceDenied            bool
	RawSocketDenied            bool
	BPFDenied                  bool
	UnshareDenied              bool
	SetNSDenied                bool
	Clone3Denied               bool
	HeldBrokerSocketCountZero  bool
	LegacyFilterRestored       bool
	IPv6PostureProven          bool
	RelayMountIdentityProven   bool
	DialMountIdentityProven    bool
	DoHPolicyProven            bool
	DurableConsumeBeforeDial   bool
	CPUEnforced                bool
	MemoryEnforced             bool
	PIDsEnforced               bool
	FDsEnforced                bool
	TmpfsEnforced              bool
	ReadOnlyRootEnforced       bool
	SeccompEnforced            bool
	CapabilitiesEnforced       bool
	WorkAreaReclamationProven  bool
	BoundedLogRetention        bool
	PolicyDigest               string
	EvidenceRevision           string
}

// ProfileObservation is the trusted typed input consumed by concrete profile
// implementations. The QTS and systemd sources obtain it from closed methods;
// no caller-provided command or argv enters this boundary.
type ProfileObservation struct {
	Platform     PlatformFacts
	UID          int
	Capabilities CapabilitySets
	Memory       RunnerSizingTuple
	Conntrack    ConntrackSizing
	Storage      StorageSizing
	Isolation    IsolationEvidence
}

// EvaluateProfileObservation validates one complete typed observation and
// returns only the identity-free conformance projection.
func EvaluateProfileObservation(
	profileID HostProfile,
	allowDegradedRoot bool,
	observation ProfileObservation,
) (ConformanceReport, error) {
	if !validHostProfile(profileID) ||
		ValidatePlatformFacts(observation.Platform) != nil ||
		ValidateIsolationEvidence(observation.Isolation) != nil {
		return ConformanceReport{}, ErrInvalidHostProfile
	}
	degraded := false
	switch profileID {
	case HostProfileStrictLinux:
		if observation.UID <= 0 || allowDegradedRoot {
			return ConformanceReport{}, ErrInvalidHostProfile
		}
	case HostProfileQTSCaplessRoot:
		if err := ValidateDegradedRootProof(
			profileID,
			allowDegradedRoot,
			observation.UID,
			observation.Capabilities,
		); err != nil {
			return ConformanceReport{}, err
		}
		degraded = true
	}
	memory, err := ValidateRunnerSizing(observation.Memory)
	if err != nil {
		return ConformanceReport{}, err
	}
	conntrack, err := ValidateConntrackSizing(observation.Conntrack)
	if err != nil {
		return ConformanceReport{}, err
	}
	storage, err := ValidateStorageSizing(observation.Storage)
	if err != nil {
		return ConformanceReport{}, err
	}
	effective := memory.EffectiveCapacity
	if conntrack.EffectiveCapacity < effective {
		effective = conntrack.EffectiveCapacity
	}
	if storage.EffectiveCapacity < effective {
		effective = storage.EffectiveCapacity
	}
	state := ProfileNormal
	if effective == 0 ||
		conntrack.State == ProfileStop ||
		storage.State == ProfileStop {
		state = ProfileStop
		effective = 0
	} else if conntrack.State == ProfileWarning ||
		storage.State == ProfileWarning {
		state = ProfileWarning
	} else if degraded {
		state = ProfileDegraded
	}
	evidenceInput := struct {
		ProfileID HostProfile
		Platform  PlatformFacts
		UID       int
		Memory    string
		Conntrack string
		Storage   string
		Isolation IsolationEvidence
		Degraded  bool
		State     ProfileState
		Capacity  uint32
	}{
		ProfileID: profileID,
		Platform:  observation.Platform,
		UID:       observation.UID,
		Memory:    memory.Digest,
		Conntrack: conntrack.Digest,
		Storage:   storage.Digest,
		Isolation: observation.Isolation,
		Degraded:  degraded,
		State:     state,
		Capacity:  effective,
	}
	evidenceDigest, err := digestCanonical(
		"portable-ghar-profile-evidence-v1",
		evidenceInput,
	)
	if err != nil {
		return ConformanceReport{}, ErrInvalidHostProfile
	}
	report := ConformanceReport{
		ProfileID:             profileID,
		State:                 state,
		Degraded:              degraded,
		EgressBackend:         observation.Conntrack.EgressBackend,
		Architecture:          observation.Platform.Architecture,
		KernelRelease:         observation.Platform.KernelRelease,
		RuntimeVersion:        observation.Platform.RuntimeVersion,
		EffectiveCapacity:     effective,
		MemorySizingDigest:    memory.Digest,
		ConntrackSizingDigest: conntrack.Digest,
		StorageSizingDigest:   storage.Digest,
		EvidenceDigest:        evidenceDigest,
	}
	if err := ValidateConformanceReport(report); err != nil {
		return ConformanceReport{}, err
	}
	return report, nil
}

func ValidateIsolationEvidence(evidence IsolationEvidence) error {
	if !evidence.RunnerNetworkNone ||
		!evidence.RunnerTablesEmptyBefore ||
		!evidence.RunnerTablesEmptyAfter ||
		!evidence.RunnerConntrackEmptyBefore ||
		!evidence.RunnerConntrackEmptyAfter ||
		!evidence.LoopbackFloodCompleted ||
		!evidence.NamespaceDenied ||
		!evidence.RawSocketDenied ||
		!evidence.BPFDenied ||
		!evidence.UnshareDenied ||
		!evidence.SetNSDenied ||
		!evidence.Clone3Denied ||
		!evidence.HeldBrokerSocketCountZero ||
		!evidence.LegacyFilterRestored ||
		!evidence.IPv6PostureProven ||
		!evidence.RelayMountIdentityProven ||
		!evidence.DialMountIdentityProven ||
		!evidence.DoHPolicyProven ||
		!evidence.DurableConsumeBeforeDial ||
		!evidence.CPUEnforced ||
		!evidence.MemoryEnforced ||
		!evidence.PIDsEnforced ||
		!evidence.FDsEnforced ||
		!evidence.TmpfsEnforced ||
		!evidence.ReadOnlyRootEnforced ||
		!evidence.SeccompEnforced ||
		!evidence.CapabilitiesEnforced ||
		!evidence.WorkAreaReclamationProven ||
		!evidence.BoundedLogRetention ||
		!isLowerHex64(evidence.PolicyDigest) ||
		!validEvidenceScalar(evidence.EvidenceRevision) {
		return ErrInvalidHostProfile
	}
	return nil
}

type NetworkDiscoveryDocument struct {
	ProfileID          HostProfile `json:"profile_id"`
	RunnerNetworkMode  string      `json:"runner_network_mode"`
	BrokerNetworkID    string      `json:"broker_network_id"`
	BrokerIPv6Enabled  bool        `json:"broker_ipv6_enabled"`
	RunnerLoopbackOnly bool        `json:"runner_loopback_only"`
	RoutesComplete     bool        `json:"routes_complete"`
	EvidenceRevision   string      `json:"evidence_revision"`
}

func ParseNetworkDiscovery(
	document []byte,
	maxBytes int,
) (NetworkSnapshot, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes ||
		!bytes.HasSuffix(document, []byte("\n")) {
		return NetworkSnapshot{}, ErrInvalidHostProfile
	}
	var decoded NetworkDiscoveryDocument
	if err := json.Unmarshal(document[:len(document)-1], &decoded); err != nil {
		return NetworkSnapshot{}, ErrInvalidHostProfile
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return NetworkSnapshot{}, ErrInvalidHostProfile
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, document) ||
		!validHostProfile(decoded.ProfileID) ||
		decoded.RunnerNetworkMode != "none" ||
		decoded.BrokerNetworkID != EgressBackendRestrictedBrokerV1 ||
		!decoded.RunnerLoopbackOnly ||
		!decoded.RoutesComplete ||
		!validEvidenceScalar(decoded.EvidenceRevision) {
		return NetworkSnapshot{}, ErrInvalidHostProfile
	}
	digest, err := digestCanonical(
		"portable-ghar-network-discovery-v1",
		decoded,
	)
	if err != nil {
		return NetworkSnapshot{}, ErrInvalidHostProfile
	}
	snapshot := NetworkSnapshot{
		ProfileID:          decoded.ProfileID,
		RunnerNetworkMode:  decoded.RunnerNetworkMode,
		BrokerNetworkID:    decoded.BrokerNetworkID,
		BrokerIPv6Enabled:  decoded.BrokerIPv6Enabled,
		RunnerLoopbackOnly: decoded.RunnerLoopbackOnly,
		RoutesComplete:     decoded.RoutesComplete,
		EvidenceDigest:     digest,
	}
	if err := ValidateNetworkSnapshot(snapshot); err != nil {
		return NetworkSnapshot{}, err
	}
	return snapshot, nil
}

func SelectProfile(
	ctx context.Context,
	request ProfileSelectRequest,
	candidates []Profile,
) (SelectedProfile, error) {
	if err := ctx.Err(); err != nil {
		return SelectedProfile{}, err
	}
	if len(candidates) == 0 {
		return SelectedProfile{}, fmt.Errorf("%w: no candidates", ErrHostProfileSelection)
	}
	byID := make(map[HostProfile]Profile, len(candidates))
	for _, candidate := range candidates {
		if candidate == nil || !validHostProfile(candidate.ID()) {
			return SelectedProfile{}, fmt.Errorf("%w: candidate", ErrHostProfileSelection)
		}
		if _, duplicate := byID[candidate.ID()]; duplicate {
			return SelectedProfile{}, fmt.Errorf("%w: duplicate candidate", ErrHostProfileSelection)
		}
		byID[candidate.ID()] = candidate
	}
	if request.Explicit != "" {
		if !validHostProfile(request.Explicit) {
			return SelectedProfile{}, fmt.Errorf("%w: explicit profile", ErrHostProfileSelection)
		}
		candidate, ok := byID[request.Explicit]
		if !ok {
			return SelectedProfile{}, fmt.Errorf("%w: explicit profile missing", ErrHostProfileSelection)
		}
		if request.Explicit == HostProfileQTSCaplessRoot && !request.AllowDegradedRoot {
			return SelectedProfile{}, fmt.Errorf("%w: degraded root not allowed", ErrHostProfileSelection)
		}
		return evaluateProfile(ctx, candidate, request)
	}
	if request.AllowDegradedRoot {
		return SelectedProfile{}, fmt.Errorf("%w: automatic degraded allow", ErrHostProfileSelection)
	}
	for _, candidate := range candidates {
		if candidate.ID() == HostProfileQTSCaplessRoot {
			continue
		}
		return evaluateProfile(ctx, candidate, request)
	}
	return SelectedProfile{}, fmt.Errorf("%w: no non-degraded candidate", ErrHostProfileSelection)
}

func evaluateProfile(
	ctx context.Context,
	candidate Profile,
	request ProfileSelectRequest,
) (SelectedProfile, error) {
	report, err := candidate.Probe(ctx)
	if err != nil {
		return SelectedProfile{}, fmt.Errorf("%w: probe: %w", ErrHostProfileSelection, err)
	}
	if err := ValidateConformanceReport(report); err != nil {
		return SelectedProfile{}, fmt.Errorf("%w: report: %w", ErrHostProfileSelection, err)
	}
	if report.ProfileID != candidate.ID() || report.State == ProfileStop {
		return SelectedProfile{}, fmt.Errorf("%w: report binding", ErrHostProfileSelection)
	}
	if candidate.ID() == HostProfileQTSCaplessRoot {
		if !request.AllowDegradedRoot || !report.Degraded ||
			(report.State != ProfileDegraded && report.State != ProfileWarning) {
			return SelectedProfile{}, fmt.Errorf("%w: degraded proof", ErrHostProfileSelection)
		}
	} else if report.Degraded || report.State == ProfileDegraded {
		return SelectedProfile{}, fmt.Errorf("%w: unexpected degraded report", ErrHostProfileSelection)
	}
	network, err := candidate.DiscoverNetworks(ctx)
	if err != nil {
		return SelectedProfile{}, fmt.Errorf("%w: discover: %w", ErrHostProfileSelection, err)
	}
	if err := ValidateNetworkSnapshot(network); err != nil {
		return SelectedProfile{}, fmt.Errorf("%w: network: %w", ErrHostProfileSelection, err)
	}
	if network.ProfileID != candidate.ID() {
		return SelectedProfile{}, fmt.Errorf("%w: network binding", ErrHostProfileSelection)
	}
	return SelectedProfile{Profile: candidate, Report: report, Network: network}, nil
}

func ValidatePlatformFacts(facts PlatformFacts) error {
	if facts.OS != "linux" ||
		!validEvidenceScalar(facts.Architecture) ||
		!validEvidenceScalar(facts.KernelRelease) ||
		!validEvidenceScalar(facts.RuntimeVersion) ||
		!facts.CgroupMemoryEnforced ||
		!facts.CgroupCPUEnforced ||
		!facts.CgroupPIDsEnforced {
		return ErrInvalidHostProfile
	}
	return nil
}

func ValidateDegradedRootProof(
	profile HostProfile,
	allowed bool,
	uid int,
	capabilities CapabilitySets,
) error {
	if profile != HostProfileQTSCaplessRoot || !allowed || uid != 0 ||
		!capabilities.EffectiveEmpty ||
		!capabilities.PermittedEmpty ||
		!capabilities.InheritableEmpty ||
		!capabilities.BoundingEmpty ||
		!capabilities.AmbientEmpty {
		return ErrInvalidHostProfile
	}
	return nil
}

func ValidateConformanceReport(report ConformanceReport) error {
	if !validHostProfile(report.ProfileID) ||
		report.EgressBackend != EgressBackendRestrictedBrokerV1 ||
		!validEvidenceScalar(report.Architecture) ||
		!validEvidenceScalar(report.KernelRelease) ||
		!validEvidenceScalar(report.RuntimeVersion) ||
		!isLowerHex64(report.MemorySizingDigest) ||
		!isLowerHex64(report.ConntrackSizingDigest) ||
		!isLowerHex64(report.StorageSizingDigest) ||
		!isLowerHex64(report.EvidenceDigest) {
		return ErrInvalidHostProfile
	}
	switch report.State {
	case ProfileNormal:
		if report.Degraded || report.EffectiveCapacity == 0 {
			return ErrInvalidHostProfile
		}
	case ProfileDegraded:
		if !report.Degraded || report.EffectiveCapacity == 0 {
			return ErrInvalidHostProfile
		}
	case ProfileWarning:
		if report.EffectiveCapacity == 0 {
			return ErrInvalidHostProfile
		}
	case ProfileStop:
		if report.EffectiveCapacity != 0 {
			return ErrInvalidHostProfile
		}
	default:
		return ErrInvalidHostProfile
	}
	return nil
}

func ValidateNetworkSnapshot(snapshot NetworkSnapshot) error {
	if !validHostProfile(snapshot.ProfileID) ||
		snapshot.RunnerNetworkMode != "none" ||
		snapshot.BrokerNetworkID != EgressBackendRestrictedBrokerV1 ||
		!snapshot.RunnerLoopbackOnly ||
		!snapshot.RoutesComplete ||
		!isLowerHex64(snapshot.EvidenceDigest) {
		return ErrInvalidHostProfile
	}
	return nil
}

type RunnerSizingTuple struct {
	OperatorApproved                bool
	RunnerTmpfsBytes                uint64
	RunnerP99Bytes                  uint64
	RunnerMarginBytes               uint64
	TmpTmpfsBytes                   uint64
	TmpP99Bytes                     uint64
	TmpMarginBytes                  uint64
	ScratchTmpfsBytes               uint64
	ScratchP99Bytes                 uint64
	ScratchMarginBytes              uint64
	RunnerCgroupP99Bytes            uint64
	ProcessMarginBytes              uint64
	RunnerMemoryBytes               uint64
	SwapLimitConfigured             bool
	SwapLimitBytes                  uint64
	MaxActiveConcurrency            uint64
	AuxiliarySlotMemoryBytes        uint64
	IdleControlPlaneBytes           uint64
	CandidateBuildAndSmokePeakBytes uint64
	HostAndGatewayReserveBytes      uint64
	UsableHostMemoryBytes           uint64
	MeasuredIdleRunnerBytes         uint64
	ReclamationObservationCadence   time.Duration
	EvidenceRevision                string
}

type SizingResult struct {
	EffectiveCapacity uint32
	Digest            string
}

func ValidateRunnerSizing(value RunnerSizingTuple) (SizingResult, error) {
	required := []uint64{
		value.RunnerTmpfsBytes,
		value.RunnerP99Bytes,
		value.RunnerMarginBytes,
		value.TmpTmpfsBytes,
		value.TmpP99Bytes,
		value.TmpMarginBytes,
		value.ScratchTmpfsBytes,
		value.ScratchP99Bytes,
		value.ScratchMarginBytes,
		value.RunnerCgroupP99Bytes,
		value.ProcessMarginBytes,
		value.RunnerMemoryBytes,
		value.MaxActiveConcurrency,
		value.AuxiliarySlotMemoryBytes,
		value.IdleControlPlaneBytes,
		value.CandidateBuildAndSmokePeakBytes,
		value.HostAndGatewayReserveBytes,
		value.UsableHostMemoryBytes,
		value.MeasuredIdleRunnerBytes,
	}
	if !value.OperatorApproved || !value.SwapLimitConfigured ||
		value.ReclamationObservationCadence <= 0 ||
		!validEvidenceScalar(value.EvidenceRevision) {
		return SizingResult{}, ErrInvalidRunnerSizing
	}
	for _, field := range required {
		if field == 0 {
			return SizingResult{}, ErrInvalidRunnerSizing
		}
	}
	if value.MaxActiveConcurrency > math.MaxUint32 {
		return SizingResult{}, ErrInvalidRunnerSizing
	}
	if value.MeasuredIdleRunnerBytes > value.RunnerP99Bytes ||
		!sumFits(value.RunnerP99Bytes, value.RunnerMarginBytes, value.RunnerTmpfsBytes) ||
		!sumFits(value.TmpP99Bytes, value.TmpMarginBytes, value.TmpTmpfsBytes) ||
		!sumFits(value.ScratchP99Bytes, value.ScratchMarginBytes, value.ScratchTmpfsBytes) ||
		!sumFits(value.RunnerCgroupP99Bytes, value.ProcessMarginBytes, value.RunnerMemoryBytes) {
		return SizingResult{}, ErrInvalidRunnerSizing
	}
	tmpfsTotal, ok := checkedSum(
		value.RunnerTmpfsBytes,
		value.TmpTmpfsBytes,
		value.ScratchTmpfsBytes,
		value.ProcessMarginBytes,
	)
	if !ok || tmpfsTotal > value.RunnerMemoryBytes {
		return SizingResult{}, ErrInvalidRunnerSizing
	}
	runnerTotal, ok := checkedMul(value.MaxActiveConcurrency, value.RunnerMemoryBytes)
	if !ok {
		return SizingResult{}, ErrInvalidRunnerSizing
	}
	auxiliaryTotal, ok := checkedMul(
		value.MaxActiveConcurrency,
		value.AuxiliarySlotMemoryBytes,
	)
	if !ok {
		return SizingResult{}, ErrInvalidRunnerSizing
	}
	hostTotal, ok := checkedSum(
		runnerTotal,
		auxiliaryTotal,
		value.IdleControlPlaneBytes,
		value.CandidateBuildAndSmokePeakBytes,
		value.HostAndGatewayReserveBytes,
	)
	if !ok || hostTotal > value.UsableHostMemoryBytes {
		return SizingResult{}, ErrInvalidRunnerSizing
	}
	digest, err := digestCanonical("portable-ghar-runner-sizing-v1", value)
	if err != nil {
		return SizingResult{}, fmt.Errorf("%w: digest", ErrInvalidRunnerSizing)
	}
	return SizingResult{
		EffectiveCapacity: uint32(value.MaxActiveConcurrency),
		Digest:            digest,
	}, nil
}

type ConntrackTimeout struct {
	Name    string
	Seconds uint64
}

type ConntrackSizing struct {
	CurrentEntries          uint64
	MaximumEntries          uint64
	HostReserveEntries      uint64
	MaximumRunnerCapacity   uint64
	MeasuredJobClassEntries uint64
	MeasuredDoHClassEntries uint64
	JobClassBudget          uint64
	DoHClassBudget          uint64
	Timeouts                []ConntrackTimeout
	DialTokenStateRevision  string
	ConsumeBeforeDial       bool
	EvidenceRevision        string
	EgressBackend           string
}

type ConntrackResult struct {
	State             ProfileState
	EffectiveCapacity uint32
	Digest            string
}

func ValidateConntrackSizing(value ConntrackSizing) (ConntrackResult, error) {
	if value.EgressBackend != EgressBackendRestrictedBrokerV1 ||
		value.MaximumEntries == 0 ||
		value.HostReserveEntries == 0 ||
		value.HostReserveEntries >= value.MaximumEntries ||
		value.MaximumRunnerCapacity == 0 ||
		value.MaximumRunnerCapacity > math.MaxUint32 ||
		value.MeasuredJobClassEntries == 0 ||
		value.MeasuredDoHClassEntries == 0 ||
		value.JobClassBudget < value.MeasuredJobClassEntries ||
		value.DoHClassBudget < value.MeasuredDoHClassEntries ||
		!value.ConsumeBeforeDial ||
		!validEvidenceScalar(value.DialTokenStateRevision) ||
		!validEvidenceScalar(value.EvidenceRevision) ||
		value.CurrentEntries > value.MaximumEntries ||
		len(value.Timeouts) == 0 {
		return ConntrackResult{}, ErrInvalidConntrack
	}
	timeouts := append([]ConntrackTimeout(nil), value.Timeouts...)
	sort.Slice(timeouts, func(i, j int) bool { return timeouts[i].Name < timeouts[j].Name })
	for index, timeout := range timeouts {
		if !validEvidenceScalar(timeout.Name) || timeout.Seconds == 0 ||
			(index > 0 && timeouts[index-1].Name == timeout.Name) {
			return ConntrackResult{}, ErrInvalidConntrack
		}
	}
	perSlot, ok := checkedSum(value.JobClassBudget, value.DoHClassBudget)
	if !ok {
		return ConntrackResult{}, ErrInvalidConntrack
	}
	configured, ok := checkedMul(value.MaximumRunnerCapacity, perSlot)
	if !ok || configured > value.MaximumEntries-value.HostReserveEntries {
		return ConntrackResult{}, ErrInvalidConntrack
	}
	available := uint64(0)
	if value.CurrentEntries < value.MaximumEntries-value.HostReserveEntries {
		available = value.MaximumEntries - value.HostReserveEntries - value.CurrentEntries
	}
	effective := available / perSlot
	if effective > value.MaximumRunnerCapacity {
		effective = value.MaximumRunnerCapacity
	}
	state := ProfileNormal
	if effective == 0 {
		state = ProfileStop
	} else if effective < value.MaximumRunnerCapacity {
		state = ProfileWarning
	}
	canonical := value
	canonical.Timeouts = timeouts
	digest, err := digestCanonical("portable-ghar-conntrack-sizing-v1", canonical)
	if err != nil {
		return ConntrackResult{}, fmt.Errorf("%w: digest", ErrInvalidConntrack)
	}
	return ConntrackResult{
		State:             state,
		EffectiveCapacity: uint32(effective),
		Digest:            digest,
	}, nil
}

type StorageRole string

const (
	StorageRoleDockerRoot StorageRole = "docker-root"
	StorageRoleState      StorageRole = "state"
	StorageRoleStaging    StorageRole = "staging"
	StorageRoleRollback   StorageRole = "rollback"
	StorageRoleScratch    StorageRole = "scratch"
	StorageRoleLogs       StorageRole = "logs"
)

var allStorageRoles = [...]StorageRole{
	StorageRoleDockerRoot,
	StorageRoleState,
	StorageRoleStaging,
	StorageRoleRollback,
	StorageRoleScratch,
	StorageRoleLogs,
}

type FilesystemIdentity struct {
	Device uint64
	Inode  uint64
}

type StorageObservation struct {
	Role       StorageRole
	Filesystem FilesystemIdentity
	FreeBytes  uint64
	FreeInodes uint64
}

type StorageRequirement struct {
	Role                   StorageRole
	CurrentReleaseBytes    uint64
	CurrentReleaseInodes   uint64
	CandidateReleaseBytes  uint64
	CandidateReleaseInodes uint64
	ExtractionBytes        uint64
	ExtractionInodes       uint64
	RollbackBytes          uint64
	RollbackInodes         uint64
	PerSlotBytes           uint64
	PerSlotInodes          uint64
	HelperBytes            uint64
	HelperInodes           uint64
	RelayBytes             uint64
	RelayInodes            uint64
	ControllerBytes        uint64
	ControllerInodes       uint64
	LedgerBytes            uint64
	LedgerInodes           uint64
	LogBytes               uint64
	LogInodes              uint64
	HostReserveBytes       uint64
	HostReserveInodes      uint64
	StopReserveBytes       uint64
	StopReserveInodes      uint64
	WarningReserveBytes    uint64
	WarningReserveInodes   uint64
}

type LogBounds struct {
	UsedBytes uint64
	MaxBytes  uint64
	UsedFiles uint64
	MaxFiles  uint64
}

type StorageSizing struct {
	MaximumActiveConcurrency uint64
	Observations             []StorageObservation
	Requirements             []StorageRequirement
	LogBounds                LogBounds
	EvidenceRevision         string
}

type StorageResult struct {
	State             ProfileState
	EffectiveCapacity uint32
	Digest            string
}

type filesystemPressure struct {
	identity      FilesystemIdentity
	freeBytes     uint64
	freeInodes    uint64
	requiredBytes uint64
	requiredNodes uint64
	stopBytes     uint64
	stopNodes     uint64
	warningBytes  uint64
	warningNodes  uint64
}

func ValidateStorageSizing(value StorageSizing) (StorageResult, error) {
	if value.MaximumActiveConcurrency == 0 ||
		value.MaximumActiveConcurrency > math.MaxUint32 ||
		!validEvidenceScalar(value.EvidenceRevision) ||
		len(value.Observations) != len(allStorageRoles) ||
		len(value.Requirements) != len(allStorageRoles) ||
		value.LogBounds.MaxBytes == 0 ||
		value.LogBounds.MaxFiles == 0 {
		return StorageResult{}, ErrInvalidStorage
	}
	observations := make(map[StorageRole]StorageObservation, len(value.Observations))
	for _, observation := range value.Observations {
		if !validStorageRole(observation.Role) ||
			observation.Filesystem.Device == 0 ||
			observation.Filesystem.Inode == 0 ||
			observation.FreeBytes == 0 ||
			observation.FreeInodes == 0 {
			return StorageResult{}, ErrInvalidStorage
		}
		if _, duplicate := observations[observation.Role]; duplicate {
			return StorageResult{}, ErrInvalidStorage
		}
		observations[observation.Role] = observation
	}
	requirements := make(map[StorageRole]StorageRequirement, len(value.Requirements))
	for _, requirement := range value.Requirements {
		if !validStorageRole(requirement.Role) ||
			!completeStorageRequirement(requirement) ||
			requirement.WarningReserveBytes <= requirement.StopReserveBytes ||
			requirement.WarningReserveInodes <= requirement.StopReserveInodes {
			return StorageResult{}, ErrInvalidStorage
		}
		if _, duplicate := requirements[requirement.Role]; duplicate {
			return StorageResult{}, ErrInvalidStorage
		}
		requirements[requirement.Role] = requirement
	}
	for _, role := range allStorageRoles {
		if _, ok := observations[role]; !ok {
			return StorageResult{}, ErrInvalidStorage
		}
		if _, ok := requirements[role]; !ok {
			return StorageResult{}, ErrInvalidStorage
		}
	}
	pressures := make(map[FilesystemIdentity]*filesystemPressure)
	for _, role := range allStorageRoles {
		observation := observations[role]
		requirement := requirements[role]
		slotBytes, ok := checkedMul(
			value.MaximumActiveConcurrency,
			requirement.PerSlotBytes,
		)
		if !ok {
			return StorageResult{}, ErrInvalidStorage
		}
		slotInodes, ok := checkedMul(
			value.MaximumActiveConcurrency,
			requirement.PerSlotInodes,
		)
		if !ok {
			return StorageResult{}, ErrInvalidStorage
		}
		requiredBytes, ok := checkedSum(
			requirement.CurrentReleaseBytes,
			requirement.CandidateReleaseBytes,
			requirement.ExtractionBytes,
			requirement.RollbackBytes,
			slotBytes,
			requirement.HelperBytes,
			requirement.RelayBytes,
			requirement.ControllerBytes,
			requirement.LedgerBytes,
			requirement.LogBytes,
			requirement.HostReserveBytes,
		)
		if !ok {
			return StorageResult{}, ErrInvalidStorage
		}
		requiredInodes, ok := checkedSum(
			requirement.CurrentReleaseInodes,
			requirement.CandidateReleaseInodes,
			requirement.ExtractionInodes,
			requirement.RollbackInodes,
			slotInodes,
			requirement.HelperInodes,
			requirement.RelayInodes,
			requirement.ControllerInodes,
			requirement.LedgerInodes,
			requirement.LogInodes,
			requirement.HostReserveInodes,
		)
		if !ok || requiredBytes == 0 || requiredInodes == 0 {
			return StorageResult{}, ErrInvalidStorage
		}
		pressure := pressures[observation.Filesystem]
		if pressure == nil {
			pressure = &filesystemPressure{
				identity:   observation.Filesystem,
				freeBytes:  observation.FreeBytes,
				freeInodes: observation.FreeInodes,
			}
			pressures[observation.Filesystem] = pressure
		} else if pressure.freeBytes != observation.FreeBytes ||
			pressure.freeInodes != observation.FreeInodes {
			return StorageResult{}, ErrInvalidStorage
		}
		if !checkedAccumulate(&pressure.requiredBytes, requiredBytes) ||
			!checkedAccumulate(&pressure.requiredNodes, requiredInodes) ||
			!checkedAccumulate(&pressure.stopBytes, requirement.StopReserveBytes) ||
			!checkedAccumulate(&pressure.stopNodes, requirement.StopReserveInodes) ||
			!checkedAccumulate(&pressure.warningBytes, requirement.WarningReserveBytes) ||
			!checkedAccumulate(&pressure.warningNodes, requirement.WarningReserveInodes) {
			return StorageResult{}, ErrInvalidStorage
		}
	}
	state := ProfileNormal
	if value.LogBounds.UsedBytes > value.LogBounds.MaxBytes ||
		value.LogBounds.UsedFiles > value.LogBounds.MaxFiles {
		state = ProfileStop
	}
	for _, pressure := range pressures {
		remainingBytes, bytesOK := checkedSubtract(
			pressure.freeBytes,
			pressure.requiredBytes,
		)
		remainingInodes, inodesOK := checkedSubtract(
			pressure.freeInodes,
			pressure.requiredNodes,
		)
		if !bytesOK || !inodesOK ||
			remainingBytes <= pressure.stopBytes ||
			remainingInodes <= pressure.stopNodes {
			state = ProfileStop
			continue
		}
		if state != ProfileStop &&
			(remainingBytes <= pressure.warningBytes ||
				remainingInodes <= pressure.warningNodes) {
			state = ProfileWarning
		}
	}
	effective := uint32(value.MaximumActiveConcurrency)
	switch state {
	case ProfileStop:
		effective = 0
	case ProfileWarning:
		if effective <= 1 {
			state = ProfileStop
			effective = 0
		} else {
			effective--
		}
	}
	canonical := canonicalStorageSizing(value)
	digest, err := digestCanonical("portable-ghar-storage-sizing-v1", canonical)
	if err != nil {
		return StorageResult{}, fmt.Errorf("%w: digest", ErrInvalidStorage)
	}
	return StorageResult{
		State:             state,
		EffectiveCapacity: effective,
		Digest:            digest,
	}, nil
}

func canonicalStorageSizing(value StorageSizing) StorageSizing {
	canonical := value
	canonical.Observations = append([]StorageObservation(nil), value.Observations...)
	canonical.Requirements = append([]StorageRequirement(nil), value.Requirements...)
	sort.Slice(canonical.Observations, func(i, j int) bool {
		return canonical.Observations[i].Role < canonical.Observations[j].Role
	})
	sort.Slice(canonical.Requirements, func(i, j int) bool {
		return canonical.Requirements[i].Role < canonical.Requirements[j].Role
	})
	return canonical
}

func completeStorageRequirement(requirement StorageRequirement) bool {
	values := [...]uint64{
		requirement.CurrentReleaseBytes,
		requirement.CurrentReleaseInodes,
		requirement.CandidateReleaseBytes,
		requirement.CandidateReleaseInodes,
		requirement.ExtractionBytes,
		requirement.ExtractionInodes,
		requirement.RollbackBytes,
		requirement.RollbackInodes,
		requirement.PerSlotBytes,
		requirement.PerSlotInodes,
		requirement.HelperBytes,
		requirement.HelperInodes,
		requirement.RelayBytes,
		requirement.RelayInodes,
		requirement.ControllerBytes,
		requirement.ControllerInodes,
		requirement.LedgerBytes,
		requirement.LedgerInodes,
		requirement.LogBytes,
		requirement.LogInodes,
		requirement.HostReserveBytes,
		requirement.HostReserveInodes,
		requirement.StopReserveBytes,
		requirement.StopReserveInodes,
		requirement.WarningReserveBytes,
		requirement.WarningReserveInodes,
	}
	for _, value := range values {
		if value == 0 {
			return false
		}
	}
	return true
}

func validHostProfile(profile HostProfile) bool {
	return profile == HostProfileStrictLinux || profile == HostProfileQTSCaplessRoot
}

func validStorageRole(role StorageRole) bool {
	switch role {
	case StorageRoleDockerRoot,
		StorageRoleState,
		StorageRoleStaging,
		StorageRoleRollback,
		StorageRoleScratch,
		StorageRoleLogs:
		return true
	default:
		return false
	}
}

func validEvidenceScalar(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("._+-", character):
		default:
			return false
		}
	}
	return true
}

func digestCanonical(domain string, value any) (string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var input bytes.Buffer
	input.WriteString(domain)
	input.WriteByte(0)
	input.Write(document)
	sum := sha256.Sum256(input.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func checkedSum(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if math.MaxUint64-total < value {
			return 0, false
		}
		total += value
	}
	return total, true
}

func checkedMul(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func checkedSubtract(left, right uint64) (uint64, bool) {
	if right > left {
		return 0, false
	}
	return left - right, true
}

func checkedAccumulate(target *uint64, value uint64) bool {
	total, ok := checkedSum(*target, value)
	if !ok {
		return false
	}
	*target = total
	return true
}

func sumFits(left, right, limit uint64) bool {
	total, ok := checkedSum(left, right)
	return ok && total <= limit
}
