// Package task11synthetic defines the closed Task 11 synthetic-listener
// protocol. It contains protocol semantics only; it grants no production,
// cleanup, release, or conformance authority.
package task11synthetic

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	SchemaVersion    uint32 = 1
	ProtocolID              = "portable-ghar-task11-synthetic-v1"
	SeedID                  = "portable-ghar-task11-seed-v1"
	MaximumWireBytes uint64 = 65536

	SeedSourceRelativePath = "task11/portable-ghar-task11-seed-v1.bin"
	SeedTargetPath         = "tools/portable-ghar-task11-seed-v1/payload.bin"
	SeedSourceAbsolutePath = "/opt/portable-ghar/seed-cache/" +
		SeedSourceRelativePath
	SeedCopyAbsolutePath = "/runner/_work/_tool/" + SeedTargetPath

	UpgradeStagingMarkerPath = "/runner/_work/_update/" +
		"portable-ghar-task11-upgrade-staging-v1"
	RegistrationMarkerPath = "/runner/_work/" +
		".portable-ghar-task11-registration-v1"

	SeedSourceSHA256   = "ef368121857519d3895e11481813b99d2e1d76d0555074a79d6af3ce9039e636"
	SeedMutationSHA256 = "bb69dc01bb526d5ce99678516845137b391164b6143d34140059650156ffc71f"

	NormalExitStatus              = 0
	ListenerCrashExitStatus       = 70
	UpgradeInterruptionExitStatus = 71

	seedSourcePayload  = "portable-ghar-task11-immutable-seed-v1\n"
	seedMutationSuffix = "portable-ghar-task11-current-copy-mutation-v1\n"
)

var HTTPSRelayEndpoint = net.JoinHostPort(
	net.IPv4(127, 0, 0, 1).String(),
	"18080",
)

var ErrInvalidProtocol = errors.New("task11synthetic: protocol invalid")

type Scenario string

const (
	ScenarioOneJob                     Scenario = "one-job"
	ScenarioCleanupSuccess             Scenario = "cleanup-success"
	ScenarioCleanupListenerCrash       Scenario = "cleanup-listener-crash"
	ScenarioCleanupUpgradeInterruption Scenario = "cleanup-upgrade-interruption"
	ScenarioReclamation                Scenario = "reclamation"
	ScenarioSeedFirst                  Scenario = "seed-first"
	ScenarioSeedSecond                 Scenario = "seed-second"
)

var scenarios = [...]Scenario{
	ScenarioOneJob,
	ScenarioCleanupSuccess,
	ScenarioCleanupListenerCrash,
	ScenarioCleanupUpgradeInterruption,
	ScenarioReclamation,
	ScenarioSeedFirst,
	ScenarioSeedSecond,
}

type CycleKind string

const (
	CycleOneJob                     CycleKind = "one-job"
	CycleCleanupSuccess             CycleKind = "cleanup-success"
	CycleCleanupCancellation        CycleKind = "cleanup-cancellation"
	CycleCleanupPreListenerFailure  CycleKind = "cleanup-pre-listener-failure"
	CycleCleanupListenerCrash       CycleKind = "cleanup-listener-crash"
	CycleCleanupControllerRestart   CycleKind = "cleanup-controller-restart"
	CycleCleanupUpgradeInterruption CycleKind = "cleanup-upgrade-interruption"
	CycleReclamation                CycleKind = "reclamation"
	CycleSeedFirst                  CycleKind = "seed-first"
	CycleSeedSecond                 CycleKind = "seed-second"
)

var cycleKinds = [...]CycleKind{
	CycleOneJob,
	CycleCleanupSuccess,
	CycleCleanupCancellation,
	CycleCleanupPreListenerFailure,
	CycleCleanupListenerCrash,
	CycleCleanupControllerRestart,
	CycleCleanupUpgradeInterruption,
	CycleReclamation,
	CycleSeedFirst,
	CycleSeedSecond,
}

type SetupStage string

const (
	SetupStageAdapterCreate   SetupStage = "network-adapter-create"
	SetupStageAdapterEmpty    SetupStage = "network-adapter-empty"
	SetupStageBrokerCreate    SetupStage = "network-broker-create"
	SetupStagePolicyApply     SetupStage = "network-policy-apply"
	SetupStageAuthorityStart  SetupStage = "dial-authority-start"
	SetupStageAuthorityBind   SetupStage = "dial-authority-bind"
	SetupStageBrokerRelease   SetupStage = "network-broker-release"
	SetupStageAdapterBind     SetupStage = "network-adapter-bind"
	SetupStageEgressVerify    SetupStage = "network-egress-verify"
	SetupStageRunnerCreate    SetupStage = "runner-create"
	SetupStageSeedHydrate     SetupStage = "runner-seed-hydrate"
	SetupStageNamespacePreArm SetupStage = "runner-namespace-prearm"
	SetupStageFinalAudit      SetupStage = "network-final-audit"
	SetupStageRunnerArm       SetupStage = "runner-arm"
	SetupStageNamespaceFinal  SetupStage = "runner-namespace-final"
	SetupStageRunnerAuthorize SetupStage = "runner-release-authorize"
)

var restartSetupStages = [...]SetupStage{
	SetupStageAdapterCreate,
	SetupStageAdapterEmpty,
	SetupStageBrokerCreate,
	SetupStagePolicyApply,
	SetupStageAuthorityStart,
	SetupStageAuthorityBind,
	SetupStageBrokerRelease,
	SetupStageAdapterBind,
	SetupStageEgressVerify,
	SetupStageRunnerCreate,
	SetupStageSeedHydrate,
	SetupStageNamespacePreArm,
	SetupStageFinalAudit,
	SetupStageRunnerArm,
	SetupStageNamespaceFinal,
	SetupStageRunnerAuthorize,
}

type Frame string

const (
	FrameBoundary Frame = "boundary"
	FrameTerminal Frame = "terminal"
)

type Boundary string

const (
	BoundaryListenerReady            Boundary = "listener-ready"
	BoundaryListenerCrashArmed       Boundary = "listener-crash-armed"
	BoundaryUpgradeInterruptionArmed Boundary = "upgrade-interruption-armed"
)

type Outcome string

const OutcomeCompleted Outcome = "completed"

type CgroupVersion string

const (
	CgroupV1 CgroupVersion = "1"
	CgroupV2 CgroupVersion = "2"
)

type Resource string

const (
	ResourceMemoryBytes      Resource = "memory_bytes"
	ResourceSwapBytes        Resource = "swap_bytes"
	ResourceRunnerTmpfsBytes Resource = "runner_tmpfs_bytes"
	ResourceTmpBytes         Resource = "tmp_bytes"
	ResourceScratchBytes     Resource = "scratch_bytes"
	ResourceContainers       Resource = "containers"
	ResourceProcesses        Resource = "processes"
	ResourceFileDescriptors  Resource = "file_descriptors"
	ResourceNamespaces       Resource = "namespaces"
	ResourceConntrackRows    Resource = "conntrack_rows"
	ResourceInodes           Resource = "inodes"
)

var resources = [...]Resource{
	ResourceMemoryBytes,
	ResourceSwapBytes,
	ResourceRunnerTmpfsBytes,
	ResourceTmpBytes,
	ResourceScratchBytes,
	ResourceContainers,
	ResourceProcesses,
	ResourceFileDescriptors,
	ResourceNamespaces,
	ResourceConntrackRows,
	ResourceInodes,
}

type Sentinel struct {
	URL                  string `json:"url"`
	Host                 string `json:"host"`
	Port                 uint16 `json:"port"`
	HostIdentityDigest   string `json:"host_identity_digest"`
	SPKIDigest           string `json:"spki_digest"`
	CertificateDigest    string `json:"certificate_digest"`
	PolicyEntryDigest    string `json:"policy_entry_digest"`
	PolicyEvidenceDigest string `json:"policy_evidence_digest"`
	ResponseBodyDigest   string `json:"response_body_digest"`
}

type Input struct {
	SchemaVersion  uint32   `json:"schema_version"`
	ProtocolID     string   `json:"protocol_id"`
	Scenario       Scenario `json:"scenario"`
	CycleRunDigest string   `json:"cycle_run_digest"`
	Nonce          string   `json:"nonce"`
	Sentinel       Sentinel `json:"sentinel"`
	SeedID         string   `json:"seed_id,omitempty"`
}

type BoundaryFrame struct {
	SchemaVersion                uint32        `json:"schema_version"`
	ProtocolID                   string        `json:"protocol_id"`
	Frame                        Frame         `json:"frame"`
	Scenario                     Scenario      `json:"scenario"`
	CycleRunDigest               string        `json:"cycle_run_digest"`
	JobMarkerDigest              string        `json:"job_marker_digest"`
	Boundary                     Boundary      `json:"boundary"`
	SyntheticTokenAbsent         bool          `json:"synthetic_token_absent"`
	ImmutablePayloadCount        uint32        `json:"immutable_payload_count"`
	UpgradeInterruptionExercised bool          `json:"upgrade_interruption_exercised"`
	CgroupVersion                CgroupVersion `json:"cgroup_version"`
	SeedID                       string        `json:"seed_id,omitempty"`
}

type ResourceHighWater struct {
	Resource  Resource `json:"resource"`
	HighWater uint64   `json:"high_water"`
}

type SeedProof struct {
	SeedID           string `json:"seed_id"`
	SourceDigest     string `json:"source_digest"`
	CopyDigest       string `json:"copy_digest"`
	MutationDigest   string `json:"mutation_digest"`
	SourcePostDigest string `json:"source_post_digest"`
	MutationAbsent   bool   `json:"mutation_absent"`
	SourceImmutable  bool   `json:"source_immutable"`
}

type TerminalFrame struct {
	SchemaVersion                uint32              `json:"schema_version"`
	ProtocolID                   string              `json:"protocol_id"`
	Frame                        Frame               `json:"frame"`
	Scenario                     Scenario            `json:"scenario"`
	CycleRunDigest               string              `json:"cycle_run_digest"`
	JobMarkerDigest              string              `json:"job_marker_digest"`
	Outcome                      Outcome             `json:"outcome"`
	ProxyRequestDigest           string              `json:"proxy_request_digest"`
	ResponseBodyProofDigest      string              `json:"response_body_proof_digest"`
	RegistrationRemoved          bool                `json:"registration_removed"`
	SyntheticTokenAbsent         bool                `json:"synthetic_token_absent"`
	ImmutablePayloadCount        uint32              `json:"immutable_payload_count"`
	UpgradeInterruptionExercised bool                `json:"upgrade_interruption_exercised"`
	CgroupVersion                CgroupVersion       `json:"cgroup_version"`
	Resources                    []ResourceHighWater `json:"resources"`
	Seed                         *SeedProof          `json:"seed,omitempty"`
}

type CleanupObservation struct {
	SchemaVersion           uint32        `json:"schema_version"`
	ProtocolID              string        `json:"protocol_id"`
	CycleRunDigest          string        `json:"cycle_run_digest"`
	CleanupDigest           string        `json:"cleanup_digest"`
	CgroupVersion           CgroupVersion `json:"cgroup_version"`
	ContainersAbsent        bool          `json:"containers_absent"`
	CgroupsAbsent           bool          `json:"cgroups_absent"`
	TmpfsAbsent             bool          `json:"tmpfs_absent"`
	WorkAbsent              bool          `json:"work_absent"`
	WorkUpdateAbsent        bool          `json:"work_update_absent"`
	ProcessesAbsent         bool          `json:"processes_absent"`
	NamespacesAbsent        bool          `json:"namespaces_absent"`
	SocketsAbsent           bool          `json:"sockets_absent"`
	AuthoritiesAbsent       bool          `json:"authorities_absent"`
	TemporaryFilesAbsent    bool          `json:"temporary_files_absent"`
	HostBackedWorkAbsent    bool          `json:"host_backed_work_absent"`
	UnexpectedObjectsAbsent bool          `json:"unexpected_objects_absent"`
	PayloadVersionCount     uint64        `json:"payload_version_count"`
	AssertionCount          uint64        `json:"assertion_count"`
}

type StreamBinding struct {
	Scenario        Scenario
	CycleRunDigest  string
	JobMarkerDigest string
	CgroupVersion   CgroupVersion
}

type Stream struct {
	Boundary BoundaryFrame
	Terminal *TerminalFrame
}

func Scenarios() []Scenario {
	return append([]Scenario(nil), scenarios[:]...)
}

func Resources() []Resource {
	return append([]Resource(nil), resources[:]...)
}

func RestartSetupStages() []SetupStage {
	return append([]SetupStage(nil), restartSetupStages[:]...)
}

func SeedSourceBytes() []byte {
	return []byte(seedSourcePayload)
}

func SeedMutationSuffix() []byte {
	return []byte(seedMutationSuffix)
}

func MarshalInput(input Input, maximumBytes uint64) ([]byte, error) {
	if maximumBytes == 0 || !validInput(input) {
		return nil, ErrInvalidProtocol
	}
	document, err := marshalCanonical(input)
	if err != nil || uint64(len(document)) > boundedInputMaximum(maximumBytes) {
		return nil, ErrInvalidProtocol
	}
	return document, nil
}

func ParseInput(document []byte, maximumBytes uint64) (Input, error) {
	var input Input
	if maximumBytes == 0 ||
		uint64(len(document)) > boundedInputMaximum(maximumBytes) ||
		decodeCanonical(document, &input) != nil ||
		!validInput(input) {
		return Input{}, ErrInvalidProtocol
	}
	return input, nil
}

func MarshalBoundaryFrame(frame BoundaryFrame) ([]byte, error) {
	if !validBoundaryFrame(frame) {
		return nil, ErrInvalidProtocol
	}
	document, err := marshalCanonical(frame)
	if err != nil {
		return nil, ErrInvalidProtocol
	}
	return document, nil
}

func MarshalTerminalFrame(frame TerminalFrame) ([]byte, error) {
	if !validTerminalFrame(frame) {
		return nil, ErrInvalidProtocol
	}
	document, err := marshalCanonical(frame)
	if err != nil {
		return nil, ErrInvalidProtocol
	}
	return document, nil
}

func MarshalCleanupObservation(
	observation CleanupObservation,
) ([]byte, error) {
	if !validCleanupObservation(observation) {
		return nil, ErrInvalidProtocol
	}
	document, err := json.Marshal(observation)
	if err != nil {
		return nil, ErrInvalidProtocol
	}
	return document, nil
}

func ParseCleanupObservation(
	document []byte,
) (CleanupObservation, error) {
	var observation CleanupObservation
	if decodeCanonicalWithoutLF(document, &observation) != nil ||
		!validCleanupObservation(observation) {
		return CleanupObservation{}, ErrInvalidProtocol
	}
	return observation, nil
}

func ParseStream(document []byte, binding StreamBinding) (Stream, error) {
	if !validStreamBinding(binding) ||
		len(document) == 0 ||
		document[len(document)-1] != '\n' {
		return Stream{}, ErrInvalidProtocol
	}
	lines := bytes.Split(document, []byte{'\n'})
	if len(lines) < 2 || len(lines[len(lines)-1]) != 0 {
		return Stream{}, ErrInvalidProtocol
	}
	frameCount := len(lines) - 1
	if frameCount != 1 && frameCount != 2 {
		return Stream{}, ErrInvalidProtocol
	}
	boundaryDocument := append(append([]byte(nil), lines[0]...), '\n')
	var boundary BoundaryFrame
	if decodeCanonical(boundaryDocument, &boundary) != nil ||
		!validBoundaryFrame(boundary) ||
		boundary.Scenario != binding.Scenario ||
		boundary.CycleRunDigest != binding.CycleRunDigest ||
		boundary.JobMarkerDigest != binding.JobMarkerDigest ||
		boundary.CgroupVersion != binding.CgroupVersion {
		return Stream{}, ErrInvalidProtocol
	}
	if isBoundaryOnlyScenario(binding.Scenario) {
		if frameCount != 1 {
			return Stream{}, ErrInvalidProtocol
		}
		return Stream{Boundary: boundary}, nil
	}
	if frameCount != 2 {
		return Stream{}, ErrInvalidProtocol
	}
	terminalDocument := append(append([]byte(nil), lines[1]...), '\n')
	var terminal TerminalFrame
	if decodeCanonical(terminalDocument, &terminal) != nil ||
		!validTerminalFrame(terminal) ||
		terminal.Scenario != binding.Scenario ||
		terminal.CycleRunDigest != binding.CycleRunDigest ||
		terminal.JobMarkerDigest != binding.JobMarkerDigest ||
		terminal.CgroupVersion != binding.CgroupVersion ||
		terminal.CgroupVersion != boundary.CgroupVersion {
		return Stream{}, ErrInvalidProtocol
	}
	return Stream{Boundary: boundary, Terminal: &terminal}, nil
}

func boundedInputMaximum(maximum uint64) uint64 {
	if maximum > MaximumWireBytes {
		return MaximumWireBytes
	}
	return maximum
}

func marshalCanonical(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(document, '\n'), nil
}

func decodeCanonical(document []byte, destination any) error {
	if len(document) == 0 || document[len(document)-1] != '\n' {
		return ErrInvalidProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidProtocol
	}
	canonical, err := marshalCanonical(destination)
	if err != nil || !bytes.Equal(document, canonical) {
		return ErrInvalidProtocol
	}
	return nil
}

func decodeCanonicalWithoutLF(document []byte, destination any) error {
	if len(document) == 0 {
		return ErrInvalidProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidProtocol
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(document, canonical) {
		return ErrInvalidProtocol
	}
	return nil
}

func validInput(input Input) bool {
	return input.SchemaVersion == SchemaVersion &&
		input.ProtocolID == ProtocolID &&
		validScenario(input.Scenario) &&
		validDigest(input.CycleRunDigest) &&
		validDigest(input.Nonce) &&
		validSentinel(input.Sentinel) &&
		validScenarioSeedID(input.Scenario, input.SeedID) &&
		!inputContainsCredentialShape(input)
}

func validSentinel(sentinel Sentinel) bool {
	return validPositiveHTTPSURL(
		sentinel.URL,
		sentinel.Host,
		sentinel.Port,
	) &&
		validDigest(sentinel.HostIdentityDigest) &&
		validDigest(sentinel.SPKIDigest) &&
		validDigest(sentinel.CertificateDigest) &&
		validDigest(sentinel.PolicyEntryDigest) &&
		validDigest(sentinel.PolicyEvidenceDigest) &&
		validDigest(sentinel.ResponseBodyDigest)
}

func validPositiveHTTPSURL(raw, host string, port uint16) bool {
	parsed, err := url.Parse(raw)
	if err != nil ||
		port == 0 ||
		parsed.Scheme != "https" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" ||
		parsed.RawPath != "" ||
		parsed.Path == "" ||
		!strings.HasPrefix(parsed.Path, "/") ||
		parsed.Hostname() != host ||
		parsed.String() != raw ||
		!validPublicDNSName(host) {
		return false
	}
	actualPort := parsed.Port()
	if actualPort == "" {
		return port == 443
	}
	numeric, parseErr := strconv.ParseUint(actualPort, 10, 16)
	return parseErr == nil &&
		uint16(numeric) == port &&
		actualPort == strconv.FormatUint(numeric, 10)
}

func validPublicDNSName(host string) bool {
	if len(host) < 3 ||
		len(host) > 253 ||
		host != strings.ToLower(host) ||
		strings.HasSuffix(host, ".") ||
		!strings.Contains(host, ".") ||
		net.ParseIP(host) != nil ||
		host == "localhost" ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 ||
			len(label) > 63 ||
			label[0] == '-' ||
			label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') &&
				character != '-' {
				return false
			}
		}
	}
	return true
}

func validBoundaryFrame(frame BoundaryFrame) bool {
	expectedBoundary, expectedUpgrade, ok := scenarioBoundary(frame.Scenario)
	return ok &&
		frame.SchemaVersion == SchemaVersion &&
		frame.ProtocolID == ProtocolID &&
		frame.Frame == FrameBoundary &&
		validDigest(frame.CycleRunDigest) &&
		validDigest(frame.JobMarkerDigest) &&
		frame.Boundary == expectedBoundary &&
		frame.SyntheticTokenAbsent &&
		frame.ImmutablePayloadCount == 1 &&
		frame.UpgradeInterruptionExercised == expectedUpgrade &&
		validCgroupVersion(frame.CgroupVersion) &&
		validScenarioSeedID(frame.Scenario, frame.SeedID)
}

func validTerminalFrame(frame TerminalFrame) bool {
	if !isNormalScenario(frame.Scenario) ||
		frame.SchemaVersion != SchemaVersion ||
		frame.ProtocolID != ProtocolID ||
		frame.Frame != FrameTerminal ||
		!validDigest(frame.CycleRunDigest) ||
		!validDigest(frame.JobMarkerDigest) ||
		frame.Outcome != OutcomeCompleted ||
		!validDigest(frame.ProxyRequestDigest) ||
		!validDigest(frame.ResponseBodyProofDigest) ||
		!frame.RegistrationRemoved ||
		!frame.SyntheticTokenAbsent ||
		frame.ImmutablePayloadCount != 1 ||
		frame.UpgradeInterruptionExercised ||
		!validCgroupVersion(frame.CgroupVersion) ||
		!validResourceVector(frame.Resources) {
		return false
	}
	if isSeedScenario(frame.Scenario) {
		return frame.Seed != nil && validSeedProof(frame.Scenario, *frame.Seed)
	}
	return frame.Seed == nil
}

func validCleanupObservation(observation CleanupObservation) bool {
	return observation.SchemaVersion == SchemaVersion &&
		observation.ProtocolID == ProtocolID &&
		validDigest(observation.CycleRunDigest) &&
		validDigest(observation.CleanupDigest) &&
		validCgroupVersion(observation.CgroupVersion) &&
		observation.ContainersAbsent &&
		observation.CgroupsAbsent &&
		observation.TmpfsAbsent &&
		observation.WorkAbsent &&
		observation.WorkUpdateAbsent &&
		observation.ProcessesAbsent &&
		observation.NamespacesAbsent &&
		observation.SocketsAbsent &&
		observation.AuthoritiesAbsent &&
		observation.TemporaryFilesAbsent &&
		observation.HostBackedWorkAbsent &&
		observation.UnexpectedObjectsAbsent &&
		observation.PayloadVersionCount == 1 &&
		observation.AssertionCount == 13
}

func validResourceVector(observations []ResourceHighWater) bool {
	if len(observations) != len(resources) {
		return false
	}
	for index, expected := range resources {
		if observations[index].Resource != expected {
			return false
		}
	}
	return true
}

func validSeedProof(scenario Scenario, proof SeedProof) bool {
	return isSeedScenario(scenario) &&
		proof.SeedID == SeedID &&
		proof.SourceDigest == SeedSourceSHA256 &&
		proof.CopyDigest == SeedSourceSHA256 &&
		proof.MutationDigest == SeedMutationSHA256 &&
		proof.MutationDigest != proof.SourceDigest &&
		proof.MutationDigest != proof.CopyDigest &&
		proof.SourcePostDigest == SeedSourceSHA256 &&
		proof.MutationAbsent == (scenario == ScenarioSeedSecond) &&
		proof.SourceImmutable
}

func validStreamBinding(binding StreamBinding) bool {
	return validScenario(binding.Scenario) &&
		validDigest(binding.CycleRunDigest) &&
		validDigest(binding.JobMarkerDigest) &&
		validCgroupVersion(binding.CgroupVersion)
}

func scenarioBoundary(scenario Scenario) (Boundary, bool, bool) {
	switch scenario {
	case ScenarioOneJob,
		ScenarioCleanupSuccess,
		ScenarioReclamation,
		ScenarioSeedFirst,
		ScenarioSeedSecond:
		return BoundaryListenerReady, false, true
	case ScenarioCleanupListenerCrash:
		return BoundaryListenerCrashArmed, false, true
	case ScenarioCleanupUpgradeInterruption:
		return BoundaryUpgradeInterruptionArmed, true, true
	default:
		return "", false, false
	}
}

func validScenario(scenario Scenario) bool {
	for _, candidate := range scenarios {
		if scenario == candidate {
			return true
		}
	}
	return false
}

func validCycleKind(kind CycleKind) bool {
	for _, candidate := range cycleKinds {
		if kind == candidate {
			return true
		}
	}
	return false
}

func validScenarioSeedID(scenario Scenario, seedID string) bool {
	if isSeedScenario(scenario) {
		return seedID == SeedID
	}
	return seedID == ""
}

func isSeedScenario(scenario Scenario) bool {
	return scenario == ScenarioSeedFirst || scenario == ScenarioSeedSecond
}

func isBoundaryOnlyScenario(scenario Scenario) bool {
	return scenario == ScenarioCleanupListenerCrash ||
		scenario == ScenarioCleanupUpgradeInterruption
}

func isNormalScenario(scenario Scenario) bool {
	return validScenario(scenario) && !isBoundaryOnlyScenario(scenario)
}

func validCgroupVersion(version CgroupVersion) bool {
	return version == CgroupV1 || version == CgroupV2
}

var credentialShapeNeedles = [...]string{
	"access_token",
	"refresh_token",
	"github_pat_",
	"ghp_",
	"gho_",
	"ghs_",
	"bearer ",
	"-----begin ",
	"password=",
	"token=",
}

func inputContainsCredentialShape(input Input) bool {
	values := [...]string{
		input.ProtocolID,
		string(input.Scenario),
		input.CycleRunDigest,
		input.Nonce,
		input.Sentinel.URL,
		input.Sentinel.Host,
		input.Sentinel.HostIdentityDigest,
		input.Sentinel.SPKIDigest,
		input.Sentinel.CertificateDigest,
		input.Sentinel.PolicyEntryDigest,
		input.Sentinel.PolicyEvidenceDigest,
		input.Sentinel.ResponseBodyDigest,
		input.SeedID,
	}
	for _, value := range values {
		lower := strings.ToLower(value)
		for _, needle := range credentialShapeNeedles {
			if strings.Contains(lower, needle) {
				return true
			}
		}
	}
	return false
}
