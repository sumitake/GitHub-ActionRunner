package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	privateOverlaySchemaVersion = uint32(1)
	privateOverlayDomain        = "portable-ghar-private-overlay-v1"
)

var ErrInvalidPrivateOverlay = errors.New("hostruntime: invalid private overlay")

type PrivateOverlay struct {
	SchemaVersion  uint32                  `json:"schema_version"`
	Target         TargetIdentityOverlay   `json:"target"`
	Manifest       ManifestOverlay         `json:"manifest"`
	Paths          PathOverlay             `json:"paths"`
	Commands       CommandOverlay          `json:"commands"`
	Docker         DockerOverlay           `json:"docker"`
	Resources      ResourceOverlay         `json:"resources"`
	Repositories   []RepositoryOverlay     `json:"repositories"`
	Policy         PolicyOverlay           `json:"policy"`
	Controller     ControllerTimingOverlay `json:"controller"`
	Fence          FenceTimingOverlay      `json:"fence"`
	Health         HealthOverlay           `json:"health"`
	Profile        ProfileOverlay          `json:"profile"`
	Watchdog       WatchdogOverlay         `json:"watchdog"`
	Secrets        []NamedSecretRef        `json:"secrets"`
	Legacy         *LegacyOverlay          `json:"legacy"`
	AllowedActions []string                `json:"allowed_actions"`
}

type TargetIdentityOverlay struct {
	OS                        string `json:"os"`
	Architecture              string `json:"architecture"`
	ExpectedEUID              uint64 `json:"expected_euid"`
	HostIdentityDigest        string `json:"host_identity_digest"`
	ControlHostIdentityDigest string `json:"control_host_identity_digest"`
	ProfileID                 string `json:"profile_id"`
	OwnerID                   string `json:"owner_id"`
	DegradedAcknowledged      bool   `json:"degraded_acknowledged"`
}

type ManifestOverlay struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type PathOverlay struct {
	StateRoot        string `json:"state_root"`
	ReleaseRoot      string `json:"release_root"`
	StagingRoot      string `json:"staging_root"`
	RollbackRoot     string `json:"rollback_root"`
	ScratchRoot      string `json:"scratch_root"`
	LogRoot          string `json:"log_root"`
	FenceRoot        string `json:"fence_root"`
	JournalRoot      string `json:"journal_root"`
	ReceiptRoot      string `json:"receipt_root"`
	ReservationRoot  string `json:"reservation_root"`
	DatabasePath     string `json:"database_path"`
	AdminSocketPath  string `json:"admin_socket_path"`
	HealthSocketPath string `json:"health_socket_path"`
	BrokerRoot       string `json:"broker_root"`
	SeccompRoot      string `json:"seccomp_root"`
	PolicyPath       string `json:"policy_path"`
	TrustLockPath    string `json:"trust_lock_path"`
	LegacyRoot       string `json:"legacy_root"`
}

type CommandOverlay struct {
	DockerBinary      string `json:"docker_binary"`
	ControllerBinary  string `json:"controller_binary"`
	WatchdogBinary    string `json:"watchdog_binary"`
	HostRuntimeBinary string `json:"host_runtime_binary"`
	LegacyFenceBinary string `json:"legacy_fence_binary"`
}

type DockerOverlay struct {
	BrokerNetworkID    string `json:"broker_network_id"`
	RunnerNetworkMode  string `json:"runner_network_mode"`
	RunnerImage        string `json:"runner_image"`
	AdapterImage       string `json:"adapter_image"`
	BrokerImage        string `json:"broker_image"`
	HelperImage        string `json:"helper_image"`
	VerifierImage      string `json:"verifier_image"`
	ImmutableBuildMode string `json:"immutable_build_mode"`
}

type ResourceVectorOverlay struct {
	MilliCPU          uint64 `json:"milli_cpu"`
	MemoryBytes       uint64 `json:"memory_bytes"`
	PIDs              uint64 `json:"pids"`
	FileDescriptors   uint64 `json:"file_descriptors"`
	TmpfsBytes        uint64 `json:"tmpfs_bytes"`
	ScratchBytes      uint64 `json:"scratch_bytes"`
	SocketStateBytes  uint64 `json:"socket_state_bytes"`
	DurableStateBytes uint64 `json:"durable_state_bytes"`
	Inodes            uint64 `json:"inodes"`
}

type SlotResourcesOverlay struct {
	Runner            ResourceVectorOverlay `json:"runner"`
	Adapter           ResourceVectorOverlay `json:"adapter"`
	Broker            ResourceVectorOverlay `json:"broker"`
	DialAuthority     ResourceVectorOverlay `json:"dial_authority"`
	Helper            ResourceVectorOverlay `json:"helper"`
	Verifier          ResourceVectorOverlay `json:"verifier"`
	WorkflowToolProbe ResourceVectorOverlay `json:"workflow_tool_probe"`
}

type SwapLimitOverlay struct {
	Configured bool   `json:"configured"`
	Bytes      uint64 `json:"bytes"`
}

type ContainerSwapOverlay struct {
	Adapter           SwapLimitOverlay `json:"adapter"`
	Broker            SwapLimitOverlay `json:"broker"`
	Helper            SwapLimitOverlay `json:"helper"`
	Verifier          SwapLimitOverlay `json:"verifier"`
	WorkflowToolProbe SwapLimitOverlay `json:"workflow_tool_probe"`
}

type HistoryOverlay struct {
	MinRetention                 string `json:"min_retention"`
	MaxHistoryRows               uint64 `json:"max_history_rows"`
	MaxHistoryLogicalBytes       uint64 `json:"max_history_logical_bytes"`
	MaxNetworkLedgerRows         uint64 `json:"max_network_ledger_rows"`
	MaxNetworkLedgerLogicalBytes uint64 `json:"max_network_ledger_logical_bytes"`
	InflightReserveRows          uint64 `json:"inflight_reserve_rows"`
	InflightReserveLogicalBytes  uint64 `json:"inflight_reserve_logical_bytes"`
	GCBatchRows                  uint64 `json:"gc_batch_rows"`
	NetworkGCBatchRows           uint64 `json:"network_gc_batch_rows"`
	VacuumBatchPages             uint64 `json:"vacuum_batch_pages"`
	MaintenanceCadence           string `json:"maintenance_cadence"`
}

type RunnerSizingOverlay struct {
	OperatorApproved                bool   `json:"operator_approved"`
	RunnerTmpfsBytes                uint64 `json:"runner_tmpfs_bytes"`
	RunnerP99Bytes                  uint64 `json:"runner_p99_bytes"`
	RunnerMarginBytes               uint64 `json:"runner_margin_bytes"`
	TmpTmpfsBytes                   uint64 `json:"tmp_tmpfs_bytes"`
	TmpP99Bytes                     uint64 `json:"tmp_p99_bytes"`
	TmpMarginBytes                  uint64 `json:"tmp_margin_bytes"`
	ScratchTmpfsBytes               uint64 `json:"scratch_tmpfs_bytes"`
	ScratchP99Bytes                 uint64 `json:"scratch_p99_bytes"`
	ScratchMarginBytes              uint64 `json:"scratch_margin_bytes"`
	RunnerCgroupP99Bytes            uint64 `json:"runner_cgroup_p99_bytes"`
	ProcessMarginBytes              uint64 `json:"process_margin_bytes"`
	RunnerMemoryBytes               uint64 `json:"runner_memory_bytes"`
	SwapLimitConfigured             bool   `json:"swap_limit_configured"`
	SwapLimitBytes                  uint64 `json:"swap_limit_bytes"`
	MaxActiveConcurrency            uint64 `json:"max_active_concurrency"`
	AuxiliarySlotMemoryBytes        uint64 `json:"auxiliary_slot_memory_bytes"`
	IdleControlPlaneBytes           uint64 `json:"idle_control_plane_bytes"`
	CandidateBuildAndSmokePeakBytes uint64 `json:"candidate_build_and_smoke_peak_bytes"`
	HostAndGatewayReserveBytes      uint64 `json:"host_and_gateway_reserve_bytes"`
	UsableHostMemoryBytes           uint64 `json:"usable_host_memory_bytes"`
	MeasuredIdleRunnerBytes         uint64 `json:"measured_idle_runner_bytes"`
	ReclamationObservationCadence   string `json:"reclamation_observation_cadence"`
	EvidenceRevision                string `json:"evidence_revision"`
}

type ConntrackTimeoutOverlay struct {
	Name    string `json:"name"`
	Seconds uint64 `json:"seconds"`
}

type ConntrackOverlay struct {
	CurrentEntries          uint64                    `json:"current_entries"`
	MaximumEntries          uint64                    `json:"maximum_entries"`
	HostReserveEntries      uint64                    `json:"host_reserve_entries"`
	MaximumRunnerCapacity   uint64                    `json:"maximum_runner_capacity"`
	MeasuredJobClassEntries uint64                    `json:"measured_job_class_entries"`
	MeasuredDoHClassEntries uint64                    `json:"measured_doh_class_entries"`
	JobClassBudget          uint64                    `json:"job_class_budget"`
	DoHClassBudget          uint64                    `json:"doh_class_budget"`
	Timeouts                []ConntrackTimeoutOverlay `json:"timeouts"`
	DialTokenStateRevision  string                    `json:"dial_token_state_revision"`
	ConsumeBeforeDial       bool                      `json:"consume_before_dial"`
	EvidenceRevision        string                    `json:"evidence_revision"`
	EgressBackend           string                    `json:"egress_backend"`
}

type StorageObservationOverlay struct {
	Role       string `json:"role"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	FreeBytes  uint64 `json:"free_bytes"`
	FreeInodes uint64 `json:"free_inodes"`
}

type StorageRequirementOverlay struct {
	Role                   string `json:"role"`
	CurrentReleaseBytes    uint64 `json:"current_release_bytes"`
	CurrentReleaseInodes   uint64 `json:"current_release_inodes"`
	CandidateReleaseBytes  uint64 `json:"candidate_release_bytes"`
	CandidateReleaseInodes uint64 `json:"candidate_release_inodes"`
	ExtractionBytes        uint64 `json:"extraction_bytes"`
	ExtractionInodes       uint64 `json:"extraction_inodes"`
	RollbackBytes          uint64 `json:"rollback_bytes"`
	RollbackInodes         uint64 `json:"rollback_inodes"`
	PerSlotBytes           uint64 `json:"per_slot_bytes"`
	PerSlotInodes          uint64 `json:"per_slot_inodes"`
	HelperBytes            uint64 `json:"helper_bytes"`
	HelperInodes           uint64 `json:"helper_inodes"`
	RelayBytes             uint64 `json:"relay_bytes"`
	RelayInodes            uint64 `json:"relay_inodes"`
	ControllerBytes        uint64 `json:"controller_bytes"`
	ControllerInodes       uint64 `json:"controller_inodes"`
	LedgerBytes            uint64 `json:"ledger_bytes"`
	LedgerInodes           uint64 `json:"ledger_inodes"`
	LogBytes               uint64 `json:"log_bytes"`
	LogInodes              uint64 `json:"log_inodes"`
	HostReserveBytes       uint64 `json:"host_reserve_bytes"`
	HostReserveInodes      uint64 `json:"host_reserve_inodes"`
	StopReserveBytes       uint64 `json:"stop_reserve_bytes"`
	StopReserveInodes      uint64 `json:"stop_reserve_inodes"`
	WarningReserveBytes    uint64 `json:"warning_reserve_bytes"`
	WarningReserveInodes   uint64 `json:"warning_reserve_inodes"`
}

type LogBoundsOverlay struct {
	UsedBytes uint64 `json:"used_bytes"`
	MaxBytes  uint64 `json:"max_bytes"`
	UsedFiles uint64 `json:"used_files"`
	MaxFiles  uint64 `json:"max_files"`
}

type StorageSizingOverlay struct {
	MaximumActiveConcurrency uint64                      `json:"maximum_active_concurrency"`
	Observations             []StorageObservationOverlay `json:"observations"`
	Requirements             []StorageRequirementOverlay `json:"requirements"`
	LogBounds                LogBoundsOverlay            `json:"log_bounds"`
	EvidenceRevision         string                      `json:"evidence_revision"`
}

type ResourceOverlay struct {
	AdmissionCeiling          ResourceVectorOverlay `json:"admission_ceiling"`
	SlotResources             SlotResourcesOverlay  `json:"slot_resources"`
	ContainerSwap             ContainerSwapOverlay  `json:"container_swap"`
	MaxCapacity               uint64                `json:"max_capacity"`
	MaxLiveReferences         uint64                `json:"max_live_references"`
	MaxOfferLogicalBytes      uint64                `json:"max_offer_logical_bytes"`
	MaxLiveOfferLogicalBytes  uint64                `json:"max_live_offer_logical_bytes"`
	TransientMode             string                `json:"transient_mode"`
	PolicyRevision            uint64                `json:"policy_revision"`
	FleetConcurrency          uint64                `json:"fleet_concurrency"`
	NetworkLedgerReserveRows  uint64                `json:"network_ledger_reserve_rows"`
	NetworkLedgerReserveBytes uint64                `json:"network_ledger_reserve_bytes"`
	History                   HistoryOverlay        `json:"history"`
	RunnerSizing              RunnerSizingOverlay   `json:"runner_sizing"`
	Conntrack                 ConntrackOverlay      `json:"conntrack"`
	Storage                   StorageSizingOverlay  `json:"storage"`
}

type RepositoryOverlay struct {
	Alias          string               `json:"alias"`
	ConfigURL      string               `json:"config_url"`
	ScaleSetName   string               `json:"scale_set_name"`
	Eligibility    string               `json:"eligibility"`
	Weight         uint32               `json:"weight"`
	MaxConcurrency uint32               `json:"max_concurrency"`
	AgingThreshold string               `json:"aging_threshold"`
	CredentialName string               `json:"credential_name"`
	SlotResources  SlotResourcesOverlay `json:"slot_resources"`
}

type PolicyOverlay struct {
	ManifestDigest      string `json:"manifest_digest"`
	CompiledGraphDigest string `json:"compiled_graph_digest"`
	AcquisitionDefault  string `json:"acquisition_default"`
}

type ControllerTimingOverlay struct {
	AckTimeout            string `json:"ack_timeout"`
	OperationTimeout      string `json:"operation_timeout"`
	PollCycleTimeout      string `json:"poll_cycle_timeout"`
	ReconciliationTimeout string `json:"reconciliation_timeout"`
	PollCadence           string `json:"poll_cadence"`
	ReconciliationCadence string `json:"reconciliation_cadence"`
	DrainPollCadence      string `json:"drain_poll_cadence"`
	ShutdownTimeout       string `json:"shutdown_timeout"`
	SessionCloseTimeout   string `json:"session_close_timeout"`
	TransitionJoinTimeout string `json:"transition_join_timeout"`
	DurableFinishTimeout  string `json:"durable_finish_timeout"`
	ReplayEvidenceMaxAge  string `json:"replay_evidence_max_age"`
	HostCapacityMaxAge    string `json:"host_capacity_max_age"`
	PollLeaseTTL          string `json:"poll_lease_ttl"`
	LedgerTail            string `json:"ledger_tail"`
}

type FenceTimingOverlay struct {
	LockPollInterval string `json:"lock_poll_interval"`
	RenewalInterval  string `json:"renewal_interval"`
	RenewalTimeout   string `json:"renewal_timeout"`
}

type HealthOverlay struct {
	Sink              string `json:"sink"`
	MaxDocumentBytes  uint64 `json:"max_document_bytes"`
	ObservationMaxAge string `json:"observation_max_age"`
}

type ProfileOverlay struct {
	ConformanceEvidenceDigest string `json:"conformance_evidence_digest"`
	NetworkEvidenceDigest     string `json:"network_evidence_digest"`
	PlatformEvidenceRevision  string `json:"platform_evidence_revision"`
}

type LogPolicyOverlay struct {
	MaxBytes uint64 `json:"max_bytes"`
	MaxFiles uint64 `json:"max_files"`
	MaxAge   string `json:"max_age"`
}

type WatchdogOverlay struct {
	Cadence         string           `json:"cadence"`
	RestartDeadline string           `json:"restart_deadline"`
	ProcessGrace    string           `json:"process_grace"`
	HealthMaxAge    string           `json:"health_max_age"`
	Logs            LogPolicyOverlay `json:"logs"`
}

type NamedSecretRef struct {
	Name string           `json:"name"`
	Ref  SecretRefOverlay `json:"ref"`
}

type SecretRefOverlay struct {
	Source string `json:"source"`
	Ref    string `json:"ref"`
}

type LegacyOverlay struct {
	CommandFilePath     string   `json:"command_file_path"`
	CommandDigest       string   `json:"command_digest"`
	ConfigurationDigest string   `json:"configuration_digest"`
	ImageDigests        []string `json:"image_digests"`
	WatchdogDigest      string   `json:"watchdog_digest"`
}

func ParsePrivateOverlay(document []byte, maxBytes int) (PrivateOverlay, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return PrivateOverlay{}, "", ErrInvalidPrivateOverlay
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var overlay PrivateOverlay
	if err := decoder.Decode(&overlay); err != nil {
		return PrivateOverlay{}, "", ErrInvalidPrivateOverlay
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PrivateOverlay{}, "", ErrInvalidPrivateOverlay
	}
	if err := validatePrivateOverlay(overlay); err != nil {
		return PrivateOverlay{}, "", err
	}
	canonical, err := json.Marshal(overlay)
	if err != nil || !bytes.Equal(canonical, document) {
		return PrivateOverlay{}, "", ErrInvalidPrivateOverlay
	}
	return overlay, canonicalArtifactDigest(privateOverlayDomain, canonical), nil
}

func MarshalPrivateOverlay(overlay PrivateOverlay) ([]byte, string, error) {
	if err := validatePrivateOverlay(overlay); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(overlay)
	if err != nil {
		return nil, "", ErrInvalidPrivateOverlay
	}
	return canonical, canonicalArtifactDigest(privateOverlayDomain, canonical), nil
}

func validatePrivateOverlay(overlay PrivateOverlay) error {
	if overlay.SchemaVersion != privateOverlaySchemaVersion ||
		overlay.Target.OS != "linux" ||
		(overlay.Target.Architecture != "amd64" &&
			overlay.Target.Architecture != "arm64") ||
		overlay.Target.ExpectedEUID != 0 ||
		!isLowerHex64(overlay.Target.HostIdentityDigest) ||
		!isLowerHex64(overlay.Target.ControlHostIdentityDigest) ||
		overlay.Target.HostIdentityDigest == overlay.Target.ControlHostIdentityDigest ||
		!validHostProfile(HostProfile(overlay.Target.ProfileID)) ||
		!validLifecycleScalar(overlay.Target.OwnerID) ||
		(overlay.Target.ProfileID == string(HostProfileQTSCaplessRoot) &&
			!overlay.Target.DegradedAcknowledged) ||
		!validCanonicalAbsolutePath(overlay.Manifest.Path) ||
		!isLowerHex64(overlay.Manifest.Digest) {
		return ErrInvalidPrivateOverlay
	}
	if !validPathOverlay(overlay.Paths) ||
		!validCommandOverlay(overlay.Commands) ||
		!validDockerOverlay(overlay.Docker) ||
		!validResourceOverlay(overlay.Resources) ||
		!validRepositories(overlay.Repositories, overlay.Resources.MaxCapacity) ||
		!isLowerHex64(overlay.Policy.ManifestDigest) ||
		!isLowerHex64(overlay.Policy.CompiledGraphDigest) ||
		overlay.Policy.AcquisitionDefault != "disabled" ||
		!validControllerTimings(overlay.Controller) ||
		!validFenceTimings(overlay.Fence) ||
		overlay.Health.Sink != "local-closed-v1" ||
		overlay.Health.MaxDocumentBytes == 0 ||
		!validCanonicalDuration(overlay.Health.ObservationMaxAge) ||
		!isLowerHex64(overlay.Profile.ConformanceEvidenceDigest) ||
		!isLowerHex64(overlay.Profile.NetworkEvidenceDigest) ||
		!validLifecycleScalar(overlay.Profile.PlatformEvidenceRevision) ||
		!validWatchdogOverlay(overlay.Watchdog) ||
		!validSecretRefs(overlay.Secrets) ||
		!validLegacyOverlay(overlay.Legacy) ||
		!validAllowedActions(overlay.AllowedActions) {
		return ErrInvalidPrivateOverlay
	}
	return nil
}

func validPathOverlay(paths PathOverlay) bool {
	values := []string{
		paths.StateRoot, paths.ReleaseRoot, paths.StagingRoot,
		paths.RollbackRoot, paths.ScratchRoot, paths.LogRoot,
		paths.FenceRoot, paths.JournalRoot, paths.ReceiptRoot,
		paths.ReservationRoot, paths.DatabasePath, paths.AdminSocketPath,
		paths.HealthSocketPath, paths.BrokerRoot, paths.SeccompRoot,
		paths.PolicyPath, paths.TrustLockPath, paths.LegacyRoot,
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validCanonicalAbsolutePath(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validCommandOverlay(commands CommandOverlay) bool {
	for _, value := range []string{
		commands.DockerBinary,
		commands.ControllerBinary,
		commands.WatchdogBinary,
		commands.HostRuntimeBinary,
		commands.LegacyFenceBinary,
	} {
		if !validCanonicalAbsolutePath(value) {
			return false
		}
	}
	return true
}

func validDockerOverlay(docker DockerOverlay) bool {
	if docker.BrokerNetworkID != EgressBackendRestrictedBrokerV1 ||
		docker.RunnerNetworkMode != "none" {
		return false
	}
	switch docker.ImmutableBuildMode {
	case "attested-pull", "administrator-build", "rollback-commit":
	default:
		return false
	}
	for _, image := range []string{
		docker.RunnerImage,
		docker.AdapterImage,
		docker.BrokerImage,
		docker.HelperImage,
		docker.VerifierImage,
	} {
		if !validImmutableImageReference(image) {
			return false
		}
	}
	return true
}

func validResourceOverlay(resources ResourceOverlay) bool {
	if !validResourceVector(resources.AdmissionCeiling) ||
		!validSlotResources(resources.SlotResources) ||
		!validContainerSwap(resources) ||
		resources.MaxCapacity == 0 ||
		resources.MaxLiveReferences == 0 ||
		resources.MaxOfferLogicalBytes == 0 ||
		resources.MaxLiveOfferLogicalBytes < resources.MaxOfferLogicalBytes ||
		resources.TransientMode != "serialized" &&
			resources.TransientMode != "concurrent" ||
		resources.PolicyRevision == 0 ||
		resources.FleetConcurrency == 0 ||
		resources.NetworkLedgerReserveRows < resources.FleetConcurrency ||
		resources.NetworkLedgerReserveBytes < resources.FleetConcurrency ||
		!validHistoryOverlay(resources.History) {
		return false
	}
	runnerCadence, ok := canonicalDuration(
		resources.RunnerSizing.ReclamationObservationCadence,
	)
	if !ok {
		return false
	}
	runner := RunnerSizingTuple{
		OperatorApproved:                resources.RunnerSizing.OperatorApproved,
		RunnerTmpfsBytes:                resources.RunnerSizing.RunnerTmpfsBytes,
		RunnerP99Bytes:                  resources.RunnerSizing.RunnerP99Bytes,
		RunnerMarginBytes:               resources.RunnerSizing.RunnerMarginBytes,
		TmpTmpfsBytes:                   resources.RunnerSizing.TmpTmpfsBytes,
		TmpP99Bytes:                     resources.RunnerSizing.TmpP99Bytes,
		TmpMarginBytes:                  resources.RunnerSizing.TmpMarginBytes,
		ScratchTmpfsBytes:               resources.RunnerSizing.ScratchTmpfsBytes,
		ScratchP99Bytes:                 resources.RunnerSizing.ScratchP99Bytes,
		ScratchMarginBytes:              resources.RunnerSizing.ScratchMarginBytes,
		RunnerCgroupP99Bytes:            resources.RunnerSizing.RunnerCgroupP99Bytes,
		ProcessMarginBytes:              resources.RunnerSizing.ProcessMarginBytes,
		RunnerMemoryBytes:               resources.RunnerSizing.RunnerMemoryBytes,
		SwapLimitConfigured:             resources.RunnerSizing.SwapLimitConfigured,
		SwapLimitBytes:                  resources.RunnerSizing.SwapLimitBytes,
		MaxActiveConcurrency:            resources.RunnerSizing.MaxActiveConcurrency,
		AuxiliarySlotMemoryBytes:        resources.RunnerSizing.AuxiliarySlotMemoryBytes,
		IdleControlPlaneBytes:           resources.RunnerSizing.IdleControlPlaneBytes,
		CandidateBuildAndSmokePeakBytes: resources.RunnerSizing.CandidateBuildAndSmokePeakBytes,
		HostAndGatewayReserveBytes:      resources.RunnerSizing.HostAndGatewayReserveBytes,
		UsableHostMemoryBytes:           resources.RunnerSizing.UsableHostMemoryBytes,
		MeasuredIdleRunnerBytes:         resources.RunnerSizing.MeasuredIdleRunnerBytes,
		ReclamationObservationCadence:   runnerCadence,
		EvidenceRevision:                resources.RunnerSizing.EvidenceRevision,
	}
	runnerResult, err := ValidateRunnerSizing(runner)
	if err != nil ||
		uint64(runnerResult.EffectiveCapacity) != resources.MaxCapacity ||
		resources.MaxCapacity != resources.FleetConcurrency {
		return false
	}
	conntrack := ConntrackSizing{
		CurrentEntries:          resources.Conntrack.CurrentEntries,
		MaximumEntries:          resources.Conntrack.MaximumEntries,
		HostReserveEntries:      resources.Conntrack.HostReserveEntries,
		MaximumRunnerCapacity:   resources.Conntrack.MaximumRunnerCapacity,
		MeasuredJobClassEntries: resources.Conntrack.MeasuredJobClassEntries,
		MeasuredDoHClassEntries: resources.Conntrack.MeasuredDoHClassEntries,
		JobClassBudget:          resources.Conntrack.JobClassBudget,
		DoHClassBudget:          resources.Conntrack.DoHClassBudget,
		DialTokenStateRevision:  resources.Conntrack.DialTokenStateRevision,
		ConsumeBeforeDial:       resources.Conntrack.ConsumeBeforeDial,
		EvidenceRevision:        resources.Conntrack.EvidenceRevision,
		EgressBackend:           resources.Conntrack.EgressBackend,
	}
	if resources.Conntrack.Timeouts == nil ||
		!sort.SliceIsSorted(resources.Conntrack.Timeouts, func(i, j int) bool {
			return resources.Conntrack.Timeouts[i].Name <
				resources.Conntrack.Timeouts[j].Name
		}) {
		return false
	}
	for index, timeout := range resources.Conntrack.Timeouts {
		if index > 0 &&
			resources.Conntrack.Timeouts[index-1].Name == timeout.Name {
			return false
		}
		conntrack.Timeouts = append(conntrack.Timeouts, ConntrackTimeout(timeout))
	}
	if _, err := ValidateConntrackSizing(conntrack); err != nil {
		return false
	}
	storage, ok := storageSizingFromOverlay(resources.Storage)
	if !ok {
		return false
	}
	storageResult, err := ValidateStorageSizing(storage)
	return err == nil &&
		uint64(storageResult.EffectiveCapacity) == resources.MaxCapacity
}

func validResourceVector(vector ResourceVectorOverlay) bool {
	return vector.MilliCPU > 0 &&
		vector.MemoryBytes > 0 &&
		vector.PIDs > 0 &&
		vector.FileDescriptors > 0 &&
		vector.TmpfsBytes > 0 &&
		vector.ScratchBytes > 0 &&
		vector.SocketStateBytes > 0 &&
		vector.DurableStateBytes > 0 &&
		vector.Inodes > 0
}

func validSlotResources(resources SlotResourcesOverlay) bool {
	return validResourceVector(resources.Runner) &&
		validResourceVector(resources.Adapter) &&
		validResourceVector(resources.Broker) &&
		validResourceVector(resources.DialAuthority) &&
		validResourceVector(resources.Helper) &&
		validResourceVector(resources.Verifier) &&
		validResourceVector(resources.WorkflowToolProbe)
}

func validContainerSwap(resources ResourceOverlay) bool {
	return validSwapTotal(
		resources.SlotResources.Adapter.MemoryBytes,
		resources.ContainerSwap.Adapter,
	) &&
		validSwapTotal(
			resources.SlotResources.Broker.MemoryBytes,
			resources.ContainerSwap.Broker,
		) &&
		validSwapTotal(
			resources.SlotResources.Helper.MemoryBytes,
			resources.ContainerSwap.Helper,
		) &&
		validSwapTotal(
			resources.SlotResources.Verifier.MemoryBytes,
			resources.ContainerSwap.Verifier,
		) &&
		validSwapTotal(
			resources.SlotResources.WorkflowToolProbe.MemoryBytes,
			resources.ContainerSwap.WorkflowToolProbe,
		) &&
		validSwapTotal(
			resources.RunnerSizing.RunnerMemoryBytes,
			SwapLimitOverlay{
				Configured: resources.RunnerSizing.SwapLimitConfigured,
				Bytes:      resources.RunnerSizing.SwapLimitBytes,
			},
		)
}

func validSwapTotal(memoryBytes uint64, swap SwapLimitOverlay) bool {
	if !swap.Configured || memoryBytes == 0 || memoryBytes > math.MaxInt64 {
		return false
	}
	total, ok := checkedAdd(memoryBytes, swap.Bytes)
	return ok && total <= math.MaxInt64
}

func validHistoryOverlay(history HistoryOverlay) bool {
	return validCanonicalDuration(history.MinRetention) &&
		validCanonicalDuration(history.MaintenanceCadence) &&
		history.MaxHistoryRows > 0 &&
		history.MaxHistoryLogicalBytes > 0 &&
		history.MaxNetworkLedgerRows > 0 &&
		history.MaxNetworkLedgerLogicalBytes > 0 &&
		history.InflightReserveRows > 0 &&
		history.InflightReserveLogicalBytes > 0 &&
		history.GCBatchRows > 0 &&
		history.NetworkGCBatchRows > 0 &&
		history.VacuumBatchPages > 0
}

func storageSizingFromOverlay(overlay StorageSizingOverlay) (StorageSizing, bool) {
	if overlay.Observations == nil ||
		overlay.Requirements == nil ||
		len(overlay.Observations) != len(lifecycleFilesystemRoles) ||
		len(overlay.Requirements) != len(lifecycleFilesystemRoles) {
		return StorageSizing{}, false
	}
	storage := StorageSizing{
		MaximumActiveConcurrency: overlay.MaximumActiveConcurrency,
		LogBounds: LogBounds{
			UsedBytes: overlay.LogBounds.UsedBytes,
			MaxBytes:  overlay.LogBounds.MaxBytes,
			UsedFiles: overlay.LogBounds.UsedFiles,
			MaxFiles:  overlay.LogBounds.MaxFiles,
		},
		EvidenceRevision: overlay.EvidenceRevision,
	}
	for index, observation := range overlay.Observations {
		if observation.Role != lifecycleFilesystemRoles[index] {
			return StorageSizing{}, false
		}
		storage.Observations = append(storage.Observations, StorageObservation{
			Role: StorageRole(observation.Role),
			Filesystem: FilesystemIdentity{
				Device: observation.Device,
				Inode:  observation.Inode,
			},
			FreeBytes:  observation.FreeBytes,
			FreeInodes: observation.FreeInodes,
		})
	}
	for index, requirement := range overlay.Requirements {
		if requirement.Role != lifecycleFilesystemRoles[index] {
			return StorageSizing{}, false
		}
		storage.Requirements = append(storage.Requirements, StorageRequirement{
			Role:                   StorageRole(requirement.Role),
			CurrentReleaseBytes:    requirement.CurrentReleaseBytes,
			CurrentReleaseInodes:   requirement.CurrentReleaseInodes,
			CandidateReleaseBytes:  requirement.CandidateReleaseBytes,
			CandidateReleaseInodes: requirement.CandidateReleaseInodes,
			ExtractionBytes:        requirement.ExtractionBytes,
			ExtractionInodes:       requirement.ExtractionInodes,
			RollbackBytes:          requirement.RollbackBytes,
			RollbackInodes:         requirement.RollbackInodes,
			PerSlotBytes:           requirement.PerSlotBytes,
			PerSlotInodes:          requirement.PerSlotInodes,
			HelperBytes:            requirement.HelperBytes,
			HelperInodes:           requirement.HelperInodes,
			RelayBytes:             requirement.RelayBytes,
			RelayInodes:            requirement.RelayInodes,
			ControllerBytes:        requirement.ControllerBytes,
			ControllerInodes:       requirement.ControllerInodes,
			LedgerBytes:            requirement.LedgerBytes,
			LedgerInodes:           requirement.LedgerInodes,
			LogBytes:               requirement.LogBytes,
			LogInodes:              requirement.LogInodes,
			HostReserveBytes:       requirement.HostReserveBytes,
			HostReserveInodes:      requirement.HostReserveInodes,
			StopReserveBytes:       requirement.StopReserveBytes,
			StopReserveInodes:      requirement.StopReserveInodes,
			WarningReserveBytes:    requirement.WarningReserveBytes,
			WarningReserveInodes:   requirement.WarningReserveInodes,
		})
	}
	return storage, true
}

func validRepositories(repositories []RepositoryOverlay, capacity uint64) bool {
	if len(repositories) == 0 ||
		!sort.SliceIsSorted(repositories, func(i, j int) bool {
			return repositories[i].Alias < repositories[j].Alias
		}) {
		return false
	}
	var total uint64
	for index, repository := range repositories {
		if !validLifecycleScalar(repository.Alias) ||
			(index > 0 && repositories[index-1].Alias == repository.Alias) ||
			!validHTTPSURL(repository.ConfigURL) ||
			!validLifecycleScalar(repository.ScaleSetName) ||
			(repository.Eligibility != "active" &&
				repository.Eligibility != "archived-disabled" &&
				repository.Eligibility != "pending-reactivation") ||
			repository.Weight == 0 ||
			repository.MaxConcurrency == 0 ||
			!validCanonicalDuration(repository.AgingThreshold) ||
			!validLifecycleScalar(repository.CredentialName) ||
			!validSlotResources(repository.SlotResources) {
			return false
		}
		total += uint64(repository.MaxConcurrency)
		if total > capacity {
			return false
		}
	}
	return true
}

func validControllerTimings(timings ControllerTimingOverlay) bool {
	for _, duration := range []string{
		timings.AckTimeout,
		timings.OperationTimeout,
		timings.PollCycleTimeout,
		timings.ReconciliationTimeout,
		timings.PollCadence,
		timings.ReconciliationCadence,
		timings.DrainPollCadence,
		timings.ShutdownTimeout,
		timings.SessionCloseTimeout,
		timings.TransitionJoinTimeout,
		timings.DurableFinishTimeout,
		timings.ReplayEvidenceMaxAge,
		timings.HostCapacityMaxAge,
		timings.PollLeaseTTL,
		timings.LedgerTail,
	} {
		if !validCanonicalDuration(duration) {
			return false
		}
	}
	return true
}

func validFenceTimings(timings FenceTimingOverlay) bool {
	lock, ok := canonicalDuration(timings.LockPollInterval)
	if !ok {
		return false
	}
	renewal, ok := canonicalDuration(timings.RenewalInterval)
	if !ok {
		return false
	}
	timeout, ok := canonicalDuration(timings.RenewalTimeout)
	return ok && lock < renewal && renewal < timeout
}

func validWatchdogOverlay(watchdog WatchdogOverlay) bool {
	return validCanonicalDuration(watchdog.Cadence) &&
		validCanonicalDuration(watchdog.RestartDeadline) &&
		validCanonicalDuration(watchdog.ProcessGrace) &&
		validCanonicalDuration(watchdog.HealthMaxAge) &&
		watchdog.Logs.MaxBytes > 0 &&
		watchdog.Logs.MaxFiles > 0 &&
		validCanonicalDuration(watchdog.Logs.MaxAge)
}

func validSecretRefs(secrets []NamedSecretRef) bool {
	if len(secrets) == 0 ||
		!sort.SliceIsSorted(secrets, func(i, j int) bool {
			return secrets[i].Name < secrets[j].Name
		}) {
		return false
	}
	for index, secret := range secrets {
		if !validLifecycleScalar(secret.Name) ||
			(index > 0 && secrets[index-1].Name == secret.Name) {
			return false
		}
		switch secret.Ref.Source {
		case "file":
			if !validCanonicalAbsolutePath(secret.Ref.Ref) {
				return false
			}
		case "env":
			if !validLifecycleScalar(secret.Ref.Ref) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validLegacyOverlay(legacy *LegacyOverlay) bool {
	if legacy == nil {
		return true
	}
	if !validCanonicalAbsolutePath(legacy.CommandFilePath) ||
		!isLowerHex64(legacy.CommandDigest) ||
		!isLowerHex64(legacy.ConfigurationDigest) ||
		!isLowerHex64(legacy.WatchdogDigest) ||
		legacy.ImageDigests == nil ||
		len(legacy.ImageDigests) == 0 ||
		!sort.StringsAreSorted(legacy.ImageDigests) {
		return false
	}
	for index, digest := range legacy.ImageDigests {
		if !validImageDigest(digest) ||
			(index > 0 && legacy.ImageDigests[index-1] == digest) {
			return false
		}
	}
	return true
}

func validAllowedActions(actions []string) bool {
	if len(actions) == 0 ||
		!sort.StringsAreSorted(actions) {
		return false
	}
	for index, action := range actions {
		switch action {
		case "install", "verify", "suspend", "resume", "rollback", "uninstall":
		default:
			return false
		}
		if index > 0 && actions[index-1] == action {
			return false
		}
	}
	return true
}

func validCanonicalAbsolutePath(value string) bool {
	return filepath.IsAbs(value) &&
		filepath.Clean(value) == value &&
		validLifecycleScalar(value)
}

func validImmutableImageReference(value string) bool {
	index := strings.LastIndex(value, "@sha256:")
	if index <= 0 || index+len("@sha256:")+64 != len(value) {
		return false
	}
	return validLifecycleScalar(value[:index]) &&
		validImageDigest(value[index+1:])
}

func validHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == ""
}

func validCanonicalDuration(value string) bool {
	_, ok := canonicalDuration(value)
	return ok
}

func canonicalDuration(value string) (time.Duration, bool) {
	duration, err := time.ParseDuration(value)
	return duration, err == nil &&
		duration > 0 &&
		duration.String() == value
}
