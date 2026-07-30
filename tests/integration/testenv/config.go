package testenv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"golang.org/x/sys/unix"
)

const (
	conformanceInputSchemaVersion = uint32(1)
	authorizationSchemaVersion    = uint32(1)
	inputDigestDomain             = "portable-ghar-conformance-input-v1\x00"
	authorizationDigestDomain     = "portable-ghar-conformance-authorization-v1\x00"
	maxDurationMilliseconds       = uint64((1<<63)-1) /
		uint64(time.Millisecond)
	maxDurationSeconds                  = uint64((1<<63)-1) / uint64(time.Second)
	maxDialAuthorityTimeoutMilliseconds = uint64(
		30 * time.Second / time.Millisecond,
	)
	loopbackFloodVerifierProcesses         = uint64(1)
	loopbackFloodPeakFileDescriptors       = uint64(8)
	loopbackFloodAttemptBudgetMilliseconds = uint64(1)
	emptyCapabilityMask                    = "0000000000000000"
)

var (
	ErrConformanceInput = errors.New(
		"testenv: conformance input invalid",
	)
	ErrConformanceInputFile = errors.New(
		"testenv: conformance input file invalid",
	)
	ErrConformanceAuthorization = errors.New(
		"testenv: conformance authorization invalid",
	)
	longLivedLogEmitters = [...]string{"adapter", "broker", "runner"}
)

type AuthorizationAction string

const ActionTargetConformance AuthorizationAction = "target_conformance"

type AddressClass string

const (
	AddressLoopback    AddressClass = "loopback"
	AddressPrivate     AddressClass = "private"
	AddressLinkLocal   AddressClass = "link-local"
	AddressMulticast   AddressClass = "multicast"
	AddressUnspecified AddressClass = "unspecified"
)

type ReclamationResource string

const (
	ResourceMemoryBytes     ReclamationResource = "memory_bytes"
	ResourceSwapBytes       ReclamationResource = "swap_bytes"
	ResourceRunnerTmpfs     ReclamationResource = "runner_tmpfs_bytes"
	ResourceTmp             ReclamationResource = "tmp_bytes"
	ResourceScratch         ReclamationResource = "scratch_bytes"
	ResourceContainers      ReclamationResource = "containers"
	ResourceProcesses       ReclamationResource = "processes"
	ResourceFileDescriptors ReclamationResource = "file_descriptors"
	ResourceNamespaces      ReclamationResource = "namespaces"
	ResourceConntrackRows   ReclamationResource = "conntrack_rows"
	ResourceInodes          ReclamationResource = "inodes"
)

type Authorization struct {
	SchemaVersion uint32              `json:"schema_version"`
	Action        AuthorizationAction `json:"action"`
	RunID         string              `json:"run_id"`
	NotBefore     string              `json:"not_before"`
	NotAfter      string              `json:"not_after"`
	Digest        string              `json:"digest"`
}

type TargetBinding struct {
	OperatingSystem            string `json:"operating_system"`
	Architecture               string `json:"architecture"`
	ExpectedEUID               uint32 `json:"expected_euid"`
	ProfileID                  string `json:"profile_id"`
	HostIdentityDigest         string `json:"host_identity_digest"`
	ControlHostIdentityDigest  string `json:"control_host_identity_digest"`
	IdentitySeparationRequired bool   `json:"identity_separation_required"`
}

type RuntimeBinding struct {
	SourceCommit                  string `json:"source_commit"`
	BuildID                       string `json:"build_id"`
	RuntimeManifestPath           string `json:"runtime_manifest_path"`
	RuntimeManifestDigest         string `json:"runtime_manifest_digest"`
	PrivateOverlayPath            string `json:"private_overlay_path"`
	PrivateOverlayDigest          string `json:"private_overlay_digest"`
	PolicyPath                    string `json:"policy_path"`
	PolicyDigest                  string `json:"policy_digest"`
	CAPath                        string `json:"ca_path"`
	CADigest                      string `json:"ca_digest"`
	SeccompPath                   string `json:"seccomp_path"`
	SeccompDigest                 string `json:"seccomp_digest"`
	ConformancePlanDigest         string `json:"conformance_plan_digest"`
	ExpectedProfileEvidenceDigest string `json:"expected_profile_evidence_digest"`
	ExpectedNetworkEvidenceDigest string `json:"expected_network_evidence_digest"`
	FleetGeneration               uint64 `json:"fleet_generation"`
}

type ImmutableImageBinding struct {
	ID        string `json:"id"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

type ImageBindings struct {
	Runner            ImmutableImageBinding `json:"runner"`
	Adapter           ImmutableImageBinding `json:"adapter"`
	Broker            ImmutableImageBinding `json:"broker"`
	Helper            ImmutableImageBinding `json:"helper"`
	Verifier          ImmutableImageBinding `json:"verifier"`
	SyntheticListener ImmutableImageBinding `json:"synthetic_listener"`
}

type PublicHTTPSSentinel struct {
	ID                   string `json:"id"`
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

type LiteralDenySentinel struct {
	ID             string       `json:"id"`
	Address        string       `json:"address"`
	Class          AddressClass `json:"class"`
	EvidenceDigest string       `json:"evidence_digest"`
}

type DNSDenySentinel struct {
	ID             string       `json:"id"`
	Host           string       `json:"host"`
	Class          AddressClass `json:"class"`
	EvidenceDigest string       `json:"evidence_digest"`
}

type SentinelBindings struct {
	Positive    PublicHTTPSSentinel   `json:"positive"`
	LiteralDeny []LiteralDenySentinel `json:"literal_deny"`
	DNSDeny     []DNSDenySentinel     `json:"dns_deny"`
}

type WorkflowToolBinding struct {
	ProbeID        string `json:"probe_id"`
	ImageReference string `json:"image_reference"`
	ImageDigest    string `json:"image_digest"`
}

type CaseTimeout struct {
	CaseID              conformance.CaseID `json:"case_id"`
	TimeoutMilliseconds uint64             `json:"timeout_milliseconds"`
}

type ConformanceLimits struct {
	CaseTimeouts                      []CaseTimeout `json:"case_timeouts"`
	CleanupTimeoutMilliseconds        uint64        `json:"cleanup_timeout_milliseconds"`
	CleanupSLOMilliseconds            uint64        `json:"cleanup_slo_milliseconds"`
	ObservationCadenceMilliseconds    uint64        `json:"observation_cadence_milliseconds"`
	ReclamationSampleCount            uint64        `json:"reclamation_sample_count"`
	MaximumEvidenceBytes              uint64        `json:"maximum_evidence_bytes"`
	MaximumCommandInputBytes          uint64        `json:"maximum_command_input_bytes"`
	DialReservationBlockSize          uint64        `json:"dial_reservation_block_size"`
	DialAuthorityMaximumClients       uint32        `json:"dial_authority_maximum_clients"`
	DialAuthorityTimeoutMilliseconds  uint64        `json:"dial_authority_timeout_milliseconds"`
	DockerLogMaximumBytes             uint64        `json:"docker_log_maximum_bytes"`
	DockerLogMaximumFiles             uint64        `json:"docker_log_maximum_files"`
	MaximumAuthorizationWindowSeconds uint64        `json:"maximum_authorization_window_seconds"`
	MaximumProcesses                  uint64        `json:"maximum_processes"`
	MaximumFileDescriptors            uint64        `json:"maximum_file_descriptors"`
	MaximumNamespaces                 uint64        `json:"maximum_namespaces"`
	MaximumConntrackRows              uint64        `json:"maximum_conntrack_rows"`
	MaximumLogBytes                   uint64        `json:"maximum_log_bytes"`
	MaximumTmpfsBytes                 uint64        `json:"maximum_tmpfs_bytes"`
	MaximumScratchBytes               uint64        `json:"maximum_scratch_bytes"`
	MaximumMemoryBytes                uint64        `json:"maximum_memory_bytes"`
	MaximumSwapBytes                  uint64        `json:"maximum_swap_bytes"`
	MaximumContainers                 uint64        `json:"maximum_containers"`
}

type ReclamationBaseline struct {
	Resource                ReclamationResource `json:"resource"`
	Baseline                uint64              `json:"baseline"`
	Margin                  uint64              `json:"margin"`
	MaximumSlopeNumerator   int64               `json:"maximum_slope_numerator"`
	MaximumSlopeDenominator int64               `json:"maximum_slope_denominator"`
}

type ReclamationBaselines struct {
	Resources []ReclamationBaseline `json:"resources"`
}

type FixtureBinding struct {
	Root                         string `json:"root"`
	ParentDevice                 uint64 `json:"parent_device"`
	ParentInode                  uint64 `json:"parent_inode"`
	RequiredEmptyDigest          string `json:"required_empty_digest"`
	ExecutionOwnerUID            uint32 `json:"execution_owner_uid"`
	ExecutionOwnerIdentityDigest string `json:"execution_owner_identity_digest"`
}

type ConformanceInput struct {
	SchemaVersion         uint32                `json:"schema_version"`
	Authorization         Authorization         `json:"authorization"`
	Target                TargetBinding         `json:"target"`
	Runtime               RuntimeBinding        `json:"runtime"`
	Images                ImageBindings         `json:"images"`
	Sentinels             SentinelBindings      `json:"sentinels"`
	WorkflowTools         []WorkflowToolBinding `json:"workflow_tools"`
	LoopbackFloodAttempts uint32                `json:"loopback_flood_attempts"`
	Limits                ConformanceLimits     `json:"limits"`
	Baselines             ReclamationBaselines  `json:"baselines"`
	Fixture               FixtureBinding        `json:"fixture"`
}

type AuthorizationUsage interface {
	Used(runID string) bool
}

type ConformanceInputReadOptions struct {
	ExpectedOwner uint32
	ExpectedMode  uint32
	MaximumBytes  int64
	Now           func() time.Time
	Usage         AuthorizationUsage

	afterOpen func()
	afterRead func()
}

type ParsedConformanceInput struct {
	Input    ConformanceInput
	Document []byte
	Digest   string
}

type inputFileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	uid    uint32
	nlink  uint64
}

var requiredWorkflowToolProbeIDs = [...]string{
	"actions-checkout",
	"actions-setup-go",
	"actions-setup-node",
	"actions-upload-artifact",
	"actions-attest",
	"anchore-sbom",
	"aquasecurity-trivy",
	"github-codeql",
	"actions-dependency-review",
	"gitleaks",
}

var requiredReclamationResources = [...]ReclamationResource{
	ResourceMemoryBytes,
	ResourceSwapBytes,
	ResourceRunnerTmpfs,
	ResourceTmp,
	ResourceScratch,
	ResourceContainers,
	ResourceProcesses,
	ResourceFileDescriptors,
	ResourceNamespaces,
	ResourceConntrackRows,
	ResourceInodes,
}

var immutableImageReferencePattern = regexp.MustCompile(
	`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$`,
)

func RequiredWorkflowToolProbeIDs() []string {
	return append([]string(nil), requiredWorkflowToolProbeIDs[:]...)
}

func RequiredReclamationResources() []ReclamationResource {
	return append([]ReclamationResource(nil), requiredReclamationResources[:]...)
}

// ComputeAuthorizationDigest returns the domain-separated digest of every
// authorization field except Digest itself.
func ComputeAuthorizationDigest(authorization Authorization) (string, error) {
	wire := struct {
		SchemaVersion uint32              `json:"schema_version"`
		Action        AuthorizationAction `json:"action"`
		RunID         string              `json:"run_id"`
		NotBefore     string              `json:"not_before"`
		NotAfter      string              `json:"not_after"`
	}{
		SchemaVersion: authorization.SchemaVersion,
		Action:        authorization.Action,
		RunID:         authorization.RunID,
		NotBefore:     authorization.NotBefore,
		NotAfter:      authorization.NotAfter,
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return "", ErrConformanceAuthorization
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(authorizationDigestDomain))
	_, _ = digest.Write(document)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func ReadConformanceInput(
	path string,
	options ConformanceInputReadOptions,
) (ParsedConformanceInput, error) {
	if !validInputReadOptions(path, options) {
		return ParsedConformanceInput{}, ErrConformanceInputFile
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return ParsedConformanceInput{}, ErrConformanceInputFile
	}
	file := os.NewFile(uintptr(fd), "conformance-input")
	if file == nil {
		_ = unix.Close(fd)
		return ParsedConformanceInput{}, ErrConformanceInputFile
	}
	defer file.Close()

	before, err := inputIdentityFromFD(fd)
	if err != nil || !validOpenedInputIdentity(before, options) {
		return ParsedConformanceInput{}, ErrConformanceInputFile
	}
	if options.afterOpen != nil {
		options.afterOpen()
	}
	document, err := io.ReadAll(io.LimitReader(file, options.MaximumBytes+1))
	if err != nil || int64(len(document)) != before.size ||
		int64(len(document)) > options.MaximumBytes {
		return ParsedConformanceInput{}, ErrConformanceInputFile
	}
	if options.afterRead != nil {
		options.afterRead()
	}
	after, err := inputIdentityFromFD(fd)
	if err != nil || after != before {
		return ParsedConformanceInput{}, ErrConformanceInputFile
	}
	pathIdentity, err := inputIdentityFromPath(path)
	if err != nil || pathIdentity != before {
		return ParsedConformanceInput{}, ErrConformanceInputFile
	}

	input, err := parseConformanceInput(document)
	if err != nil {
		return ParsedConformanceInput{}, err
	}
	now := options.Now().UTC()
	if err := validateConformanceInput(input, now, options.Usage); err != nil {
		return ParsedConformanceInput{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(inputDigestDomain))
	_, _ = digest.Write(document)
	return ParsedConformanceInput{
		Input:    input,
		Document: append([]byte(nil), document...),
		Digest:   hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func validInputReadOptions(
	path string,
	options ConformanceInputReadOptions,
) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		options.ExpectedMode > 0 &&
		options.ExpectedMode <= 0o777 &&
		options.MaximumBytes > 0 &&
		options.MaximumBytes < math.MaxInt64 &&
		options.Now != nil &&
		options.Usage != nil
}

func inputIdentityFromFD(fd int) (inputFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return inputFileIdentity{}, err
	}
	return normalizeInputIdentity(stat), nil
}

func inputIdentityFromPath(path string) (inputFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return inputFileIdentity{}, err
	}
	return normalizeInputIdentity(stat), nil
}

func normalizeInputIdentity(stat unix.Stat_t) inputFileIdentity {
	return inputFileIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		size:   stat.Size,
		mode:   uint32(stat.Mode),
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
	}
}

func validOpenedInputIdentity(
	identity inputFileIdentity,
	options ConformanceInputReadOptions,
) bool {
	return identity.mode&unix.S_IFMT == unix.S_IFREG &&
		identity.mode&0o777 == options.ExpectedMode &&
		identity.uid == options.ExpectedOwner &&
		identity.nlink == 1 &&
		identity.size > 0 &&
		identity.size <= options.MaximumBytes
}

func parseConformanceInput(document []byte) (ConformanceInput, error) {
	if len(document) == 0 || !utf8.Valid(document) {
		return ConformanceInput{}, ErrConformanceInput
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var input ConformanceInput
	if err := decoder.Decode(&input); err != nil {
		return ConformanceInput{}, ErrConformanceInput
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ConformanceInput{}, ErrConformanceInput
	}
	if input.WorkflowTools == nil ||
		input.Sentinels.LiteralDeny == nil ||
		input.Sentinels.DNSDeny == nil ||
		input.Limits.CaseTimeouts == nil ||
		input.Baselines.Resources == nil {
		return ConformanceInput{}, ErrConformanceInput
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(canonical, document) {
		return ConformanceInput{}, ErrConformanceInput
	}
	return input, nil
}

func validateConformanceInput(
	input ConformanceInput,
	now time.Time,
	usage AuthorizationUsage,
) error {
	if input.SchemaVersion != conformanceInputSchemaVersion ||
		!validateTarget(input.Target) ||
		!validateRuntime(input.Runtime) ||
		!validateImages(input.Images) ||
		!validateSentinels(
			input.Sentinels,
			input.Runtime.ExpectedNetworkEvidenceDigest,
		) ||
		!validateWorkflowTools(input.WorkflowTools, input.Images) ||
		!validateLimits(input.Limits) ||
		!validateLoopbackFlood(
			input.LoopbackFloodAttempts,
			input.Limits,
		) ||
		!validateBaselines(input.Baselines) ||
		!validateFixture(input.Fixture, input.Target, input.Runtime) ||
		containsSecretShapedValue(input) {
		return ErrConformanceInput
	}
	if err := validateAuthorization(
		input.Authorization,
		input.Limits.MaximumAuthorizationWindowSeconds,
		now,
		usage,
	); err != nil {
		return err
	}
	return nil
}

func validateAuthorization(
	authorization Authorization,
	maximumWindowSeconds uint64,
	now time.Time,
	usage AuthorizationUsage,
) error {
	if authorization.SchemaVersion != authorizationSchemaVersion ||
		authorization.Action != ActionTargetConformance ||
		!isLowerHex(authorization.RunID, 64) ||
		!isLowerHex(authorization.Digest, 64) {
		return ErrConformanceAuthorization
	}
	notBefore, ok := parseCanonicalUTC(authorization.NotBefore)
	if !ok {
		return ErrConformanceAuthorization
	}
	notAfter, ok := parseCanonicalUTC(authorization.NotAfter)
	if !ok || !notAfter.After(notBefore) ||
		now.Before(notBefore) || !now.Before(notAfter) {
		return ErrConformanceAuthorization
	}
	window := notAfter.Sub(notBefore)
	if maximumWindowSeconds == 0 ||
		maximumWindowSeconds > maxDurationSeconds ||
		window > time.Duration(maximumWindowSeconds)*time.Second {
		return ErrConformanceAuthorization
	}
	expected, err := ComputeAuthorizationDigest(authorization)
	if err != nil || expected != authorization.Digest ||
		usage.Used(authorization.RunID) {
		return ErrConformanceAuthorization
	}
	return nil
}

func parseCanonicalUTC(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC ||
		parsed.Format(time.RFC3339) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func validateTarget(target TargetBinding) bool {
	return target.OperatingSystem == "linux" &&
		(target.Architecture == "amd64" || target.Architecture == "arm64") &&
		(target.ProfileID == "strict-linux" ||
			target.ProfileID == "qts-capless-root") &&
		isLowerHex(target.HostIdentityDigest, 64) &&
		isLowerHex(target.ControlHostIdentityDigest, 64) &&
		target.HostIdentityDigest != target.ControlHostIdentityDigest &&
		target.IdentitySeparationRequired
}

func validateRuntime(runtime RuntimeBinding) bool {
	paths := []string{
		runtime.RuntimeManifestPath,
		runtime.PrivateOverlayPath,
		runtime.PolicyPath,
		runtime.CAPath,
		runtime.SeccompPath,
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !validAbsolutePath(path) {
			return false
		}
		if _, duplicate := seen[path]; duplicate {
			return false
		}
		seen[path] = struct{}{}
	}
	return isLowerHex(runtime.SourceCommit, 40) &&
		isLowerHex(runtime.BuildID, 64) &&
		isLowerHex(runtime.RuntimeManifestDigest, 64) &&
		isLowerHex(runtime.PrivateOverlayDigest, 64) &&
		isLowerHex(runtime.PolicyDigest, 64) &&
		isLowerHex(runtime.CADigest, 64) &&
		isLowerHex(runtime.SeccompDigest, 64) &&
		isLowerHex(runtime.ConformancePlanDigest, 64) &&
		isLowerHex(runtime.ExpectedProfileEvidenceDigest, 64) &&
		isLowerHex(runtime.ExpectedNetworkEvidenceDigest, 64) &&
		runtime.FleetGeneration != 0
}

func validateImages(images ImageBindings) bool {
	values := []struct {
		expected string
		binding  ImmutableImageBinding
	}{
		{"runner", images.Runner},
		{"adapter", images.Adapter},
		{"broker", images.Broker},
		{"helper", images.Helper},
		{"verifier", images.Verifier},
		{"synthetic-listener", images.SyntheticListener},
	}
	seenReferences := make(map[string]struct{}, len(values))
	seenDigests := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value.binding.ID != value.expected ||
			!validImmutableImageReference(
				value.binding.Reference,
				value.binding.Digest,
			) {
			return false
		}
		if _, duplicate := seenReferences[value.binding.Reference]; duplicate {
			return false
		}
		if _, duplicate := seenDigests[value.binding.Digest]; duplicate {
			return false
		}
		seenReferences[value.binding.Reference] = struct{}{}
		seenDigests[value.binding.Digest] = struct{}{}
	}
	return true
}

func validateSentinels(
	sentinels SentinelBindings,
	networkEvidenceDigest string,
) bool {
	positive := sentinels.Positive
	if !validID(positive.ID) ||
		positive.Port != 443 ||
		!validPublicHTTPSURL(positive.URL, positive.Host, positive.Port) ||
		!isLowerHex(positive.HostIdentityDigest, 64) ||
		!isLowerHex(positive.SPKIDigest, 64) ||
		!isLowerHex(positive.CertificateDigest, 64) ||
		!isLowerHex(positive.PolicyEntryDigest, 64) ||
		positive.PolicyEvidenceDigest != networkEvidenceDigest ||
		!isLowerHex(positive.ResponseBodyDigest, 64) ||
		len(sentinels.LiteralDeny) == 0 ||
		len(sentinels.DNSDeny) == 0 {
		return false
	}
	ids := map[string]struct{}{positive.ID: {}}
	addresses := make(map[string]struct{}, len(sentinels.LiteralDeny))
	for _, sentinel := range sentinels.LiteralDeny {
		if !validID(sentinel.ID) ||
			!isLowerHex(sentinel.EvidenceDigest, 64) ||
			!addressMatchesClass(sentinel.Address, sentinel.Class) {
			return false
		}
		if _, duplicate := ids[sentinel.ID]; duplicate {
			return false
		}
		if _, duplicate := addresses[sentinel.Address]; duplicate {
			return false
		}
		ids[sentinel.ID] = struct{}{}
		addresses[sentinel.Address] = struct{}{}
	}
	hosts := make(map[string]struct{}, len(sentinels.DNSDeny))
	for _, sentinel := range sentinels.DNSDeny {
		if !validID(sentinel.ID) ||
			!validDNSName(sentinel.Host) ||
			!validAddressClass(sentinel.Class) ||
			!isLowerHex(sentinel.EvidenceDigest, 64) {
			return false
		}
		if _, duplicate := ids[sentinel.ID]; duplicate {
			return false
		}
		if _, duplicate := hosts[sentinel.Host]; duplicate {
			return false
		}
		ids[sentinel.ID] = struct{}{}
		hosts[sentinel.Host] = struct{}{}
	}
	return true
}

func validateWorkflowTools(
	tools []WorkflowToolBinding,
	images ImageBindings,
) bool {
	if len(tools) != len(requiredWorkflowToolProbeIDs) {
		return false
	}
	seenReferences := make(map[string]struct{}, len(tools))
	seenDigests := make(map[string]struct{}, len(tools))
	for _, image := range []ImmutableImageBinding{
		images.Runner,
		images.Adapter,
		images.Broker,
		images.Helper,
		images.Verifier,
		images.SyntheticListener,
	} {
		seenReferences[image.Reference] = struct{}{}
		seenDigests[image.Digest] = struct{}{}
	}
	for index, expected := range requiredWorkflowToolProbeIDs {
		if tools[index].ProbeID != expected ||
			!validImmutableImageReference(
				tools[index].ImageReference,
				tools[index].ImageDigest,
			) {
			return false
		}
		if _, duplicate := seenReferences[tools[index].ImageReference]; duplicate {
			return false
		}
		if _, duplicate := seenDigests[tools[index].ImageDigest]; duplicate {
			return false
		}
		seenReferences[tools[index].ImageReference] = struct{}{}
		seenDigests[tools[index].ImageDigest] = struct{}{}
	}
	return true
}

func validImmutableImageReference(reference string, digest string) bool {
	return isLowerHex(digest, 64) &&
		immutableImageReferencePattern.MatchString(reference) &&
		strings.HasSuffix(reference, "@sha256:"+digest)
}

func validateLimits(limits ConformanceLimits) bool {
	requiredCases := conformance.RequiredCases()
	if len(limits.CaseTimeouts) != len(requiredCases) {
		return false
	}
	for index, expected := range requiredCases {
		if limits.CaseTimeouts[index].CaseID != expected ||
			limits.CaseTimeouts[index].TimeoutMilliseconds == 0 ||
			limits.CaseTimeouts[index].TimeoutMilliseconds >
				maxDurationMilliseconds {
			return false
		}
	}
	values := []uint64{
		limits.CleanupTimeoutMilliseconds,
		limits.CleanupSLOMilliseconds,
		limits.ObservationCadenceMilliseconds,
		limits.ReclamationSampleCount,
		limits.MaximumEvidenceBytes,
		limits.MaximumCommandInputBytes,
		limits.DialReservationBlockSize,
		uint64(limits.DialAuthorityMaximumClients),
		limits.DialAuthorityTimeoutMilliseconds,
		limits.DockerLogMaximumBytes,
		limits.DockerLogMaximumFiles,
		limits.MaximumAuthorizationWindowSeconds,
		limits.MaximumProcesses,
		limits.MaximumFileDescriptors,
		limits.MaximumNamespaces,
		limits.MaximumConntrackRows,
		limits.MaximumLogBytes,
		limits.MaximumTmpfsBytes,
		limits.MaximumScratchBytes,
		limits.MaximumMemoryBytes,
		limits.MaximumSwapBytes,
		limits.MaximumContainers,
	}
	for _, value := range values {
		if value == 0 {
			return false
		}
	}
	if limits.CleanupTimeoutMilliseconds > maxDurationMilliseconds ||
		limits.CleanupSLOMilliseconds > maxDurationMilliseconds ||
		limits.ObservationCadenceMilliseconds > maxDurationMilliseconds ||
		limits.MaximumCommandInputBytes > uint64(math.MaxInt) ||
		limits.DialReservationBlockSize > math.MaxUint32 ||
		limits.DialAuthorityTimeoutMilliseconds >
			maxDurationMilliseconds ||
		limits.DialAuthorityTimeoutMilliseconds >
			maxDialAuthorityTimeoutMilliseconds ||
		limits.MaximumAuthorizationWindowSeconds > maxDurationSeconds {
		return false
	}
	clients := uint64(limits.DialAuthorityMaximumClients)
	if clients > limits.MaximumProcesses ||
		clients > limits.MaximumFileDescriptors {
		return false
	}
	var brokerTimeout uint64
	for _, timeout := range limits.CaseTimeouts {
		if timeout.CaseID == conformance.CaseBrokerEgress {
			brokerTimeout = timeout.TimeoutMilliseconds
			break
		}
	}
	if brokerTimeout == 0 ||
		limits.DialAuthorityTimeoutMilliseconds > brokerTimeout {
		return false
	}
	perContainerLogBytes, ok := checkedMultiplyLimit(
		limits.DockerLogMaximumBytes,
		limits.DockerLogMaximumFiles,
	)
	if !ok {
		return false
	}
	fleetLogBytes, ok := checkedMultiplyLimit(
		perContainerLogBytes,
		uint64(len(longLivedLogEmitters)),
	)
	if !ok || fleetLogBytes > limits.MaximumLogBytes {
		return false
	}
	return limits.ReclamationSampleCount >= 3 &&
		limits.CleanupTimeoutMilliseconds <= limits.CleanupSLOMilliseconds &&
		limits.ObservationCadenceMilliseconds <=
			limits.CleanupSLOMilliseconds &&
		limits.MaximumEvidenceBytes <= 1<<30
}

func checkedMultiplyLimit(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func validateLoopbackFlood(
	attempts uint32,
	limits ConformanceLimits,
) bool {
	if attempts == 0 ||
		limits.MaximumProcesses < loopbackFloodVerifierProcesses ||
		limits.MaximumFileDescriptors <
			loopbackFloodPeakFileDescriptors ||
		uint64(loopbackFloodRequestBytes(attempts)) >
			limits.MaximumCommandInputBytes ||
		uint64(loopbackFloodReportBytes(attempts)) >
			limits.MaximumEvidenceBytes {
		return false
	}
	requiredMilliseconds, ok := checkedMultiplyLimit(
		uint64(attempts),
		loopbackFloodAttemptBudgetMilliseconds,
	)
	if !ok {
		return false
	}
	for _, timeout := range limits.CaseTimeouts {
		if timeout.CaseID == conformance.CaseNamespaceBaseline {
			return timeout.TimeoutMilliseconds >= requiredMilliseconds
		}
	}
	return false
}

func loopbackFloodRequestBytes(attempts uint32) int {
	document, err := json.Marshal(struct {
		Version  uint8  `json:"version"`
		Attempts uint32 `json:"attempts"`
	}{
		Version:  1,
		Attempts: attempts,
	})
	if err != nil {
		return 0
	}
	return len(document) + 1
}

func loopbackFloodReportBytes(attempts uint32) int {
	type capabilityWire struct {
		Effective   string `json:"effective"`
		Permitted   string `json:"permitted"`
		Inheritable string `json:"inheritable"`
		Bounding    string `json:"bounding"`
		Ambient     string `json:"ambient"`
	}
	type namespaceIdentityWire struct {
		Device uint64 `json:"device"`
		Inode  uint64 `json:"inode"`
	}
	type namespaceWire struct {
		Identity       namespaceIdentityWire `json:"identity"`
		LoopbackOnly   bool                  `json:"loopback_only"`
		TablesEmpty    bool                  `json:"tables_empty"`
		ConntrackEmpty bool                  `json:"conntrack_empty"`
	}
	document, err := json.Marshal(struct {
		Version        uint8          `json:"version"`
		Attempts       uint32         `json:"attempts"`
		Completed      bool           `json:"completed"`
		Capabilities   capabilityWire `json:"capabilities"`
		Namespace      namespaceWire  `json:"namespace"`
		RoutesComplete bool           `json:"routes_complete"`
	}{
		Version:   2,
		Attempts:  attempts,
		Completed: true,
		Capabilities: capabilityWire{
			Effective:   emptyCapabilityMask,
			Permitted:   emptyCapabilityMask,
			Inheritable: emptyCapabilityMask,
			Bounding:    emptyCapabilityMask,
			Ambient:     emptyCapabilityMask,
		},
		Namespace: namespaceWire{
			Identity: namespaceIdentityWire{
				Device: math.MaxUint64,
				Inode:  math.MaxUint64,
			},
			LoopbackOnly:   true,
			TablesEmpty:    true,
			ConntrackEmpty: true,
		},
		RoutesComplete: true,
	})
	if err != nil {
		return 0
	}
	return len(document) + 1
}

func validateBaselines(baselines ReclamationBaselines) bool {
	if len(baselines.Resources) != len(requiredReclamationResources) {
		return false
	}
	for index, expected := range requiredReclamationResources {
		resource := baselines.Resources[index]
		if resource.Resource != expected ||
			resource.Margin == 0 ||
			resource.MaximumSlopeNumerator < 0 ||
			resource.MaximumSlopeDenominator <= 0 ||
			resource.Baseline > math.MaxUint64-resource.Margin {
			return false
		}
	}
	return true
}

func validateFixture(
	fixture FixtureBinding,
	target TargetBinding,
	runtime RuntimeBinding,
) bool {
	if !validAbsolutePath(fixture.Root) ||
		fixture.ParentDevice == 0 ||
		fixture.ParentInode == 0 ||
		!isLowerHex(fixture.RequiredEmptyDigest, 64) ||
		fixture.ExecutionOwnerUID != target.ExpectedEUID ||
		!isLowerHex(fixture.ExecutionOwnerIdentityDigest, 64) {
		return false
	}
	for _, path := range []string{
		runtime.RuntimeManifestPath,
		runtime.PrivateOverlayPath,
		runtime.PolicyPath,
		runtime.CAPath,
		runtime.SeccompPath,
	} {
		if fixture.Root == path {
			return false
		}
	}
	return true
}

func validPublicHTTPSURL(raw, host string, port uint16) bool {
	parsed, err := url.Parse(raw)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" ||
		parsed.RawPath != "" ||
		parsed.Path == "" ||
		!strings.HasPrefix(parsed.Path, "/") ||
		parsed.Hostname() != host ||
		parsed.Hostname() != strings.ToLower(parsed.Hostname()) ||
		net.ParseIP(host) != nil ||
		parsed.String() != raw ||
		!isPublicHost(host) {
		return false
	}
	actualPort := parsed.Port()
	if actualPort == "" {
		return port == 443
	}
	return actualPort == "443" && port == 443
}

func isPublicHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsPrivate() &&
			!ip.IsLoopback() &&
			!ip.IsLinkLocalUnicast() &&
			!ip.IsLinkLocalMulticast() &&
			!ip.IsMulticast() &&
			!ip.IsUnspecified()
	}
	return validDNSName(host) &&
		host != "localhost" &&
		!strings.HasSuffix(host, ".local") &&
		!strings.HasSuffix(host, ".internal")
}

func validDNSName(host string) bool {
	if len(host) < 3 || len(host) > 253 ||
		host != strings.ToLower(host) ||
		strings.HasSuffix(host, ".") ||
		!strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
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

func addressMatchesClass(address string, class AddressClass) bool {
	ip := net.ParseIP(address)
	if ip == nil || ip.String() != address {
		return false
	}
	switch class {
	case AddressLoopback:
		return ip.IsLoopback()
	case AddressPrivate:
		return ip.IsPrivate()
	case AddressLinkLocal:
		return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
	case AddressMulticast:
		return ip.IsMulticast()
	case AddressUnspecified:
		return ip.IsUnspecified()
	default:
		return false
	}
}

func validAddressClass(class AddressClass) bool {
	switch class {
	case AddressLoopback,
		AddressPrivate,
		AddressLinkLocal,
		AddressMulticast,
		AddressUnspecified:
		return true
	default:
		return false
	}
}

func validAbsolutePath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!hasControl(path)
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}

func containsSecretShapedValue(input ConformanceInput) bool {
	for _, value := range inputStringValues(input) {
		if containsSecretShapedString(value) {
			return true
		}
	}
	return false
}

var secretShapeNeedles = [...]string{
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

func containsSecretShapedString(value string) bool {
	lower := strings.ToLower(value)
	for _, forbidden := range secretShapeNeedles {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	return false
}

func inputStringValues(input ConformanceInput) []string {
	values := []string{
		string(input.Authorization.Action),
		input.Authorization.RunID,
		input.Authorization.NotBefore,
		input.Authorization.NotAfter,
		input.Authorization.Digest,
		input.Target.OperatingSystem,
		input.Target.Architecture,
		input.Target.ProfileID,
		input.Target.HostIdentityDigest,
		input.Target.ControlHostIdentityDigest,
		input.Runtime.SourceCommit,
		input.Runtime.BuildID,
		input.Runtime.RuntimeManifestPath,
		input.Runtime.RuntimeManifestDigest,
		input.Runtime.PrivateOverlayPath,
		input.Runtime.PrivateOverlayDigest,
		input.Runtime.PolicyPath,
		input.Runtime.PolicyDigest,
		input.Runtime.CAPath,
		input.Runtime.CADigest,
		input.Runtime.SeccompPath,
		input.Runtime.SeccompDigest,
		input.Runtime.ConformancePlanDigest,
		input.Runtime.ExpectedProfileEvidenceDigest,
		input.Runtime.ExpectedNetworkEvidenceDigest,
		input.Fixture.Root,
		input.Fixture.RequiredEmptyDigest,
		input.Fixture.ExecutionOwnerIdentityDigest,
		input.Sentinels.Positive.ID,
		input.Sentinels.Positive.URL,
		input.Sentinels.Positive.Host,
		input.Sentinels.Positive.HostIdentityDigest,
		input.Sentinels.Positive.SPKIDigest,
		input.Sentinels.Positive.CertificateDigest,
		input.Sentinels.Positive.PolicyEntryDigest,
		input.Sentinels.Positive.PolicyEvidenceDigest,
		input.Sentinels.Positive.ResponseBodyDigest,
	}
	for _, image := range []ImmutableImageBinding{
		input.Images.Runner,
		input.Images.Adapter,
		input.Images.Broker,
		input.Images.Helper,
		input.Images.Verifier,
		input.Images.SyntheticListener,
	} {
		values = append(values, image.ID, image.Reference, image.Digest)
	}
	for _, sentinel := range input.Sentinels.LiteralDeny {
		values = append(
			values,
			sentinel.ID,
			sentinel.Address,
			string(sentinel.Class),
			sentinel.EvidenceDigest,
		)
	}
	for _, sentinel := range input.Sentinels.DNSDeny {
		values = append(
			values,
			sentinel.ID,
			sentinel.Host,
			string(sentinel.Class),
			sentinel.EvidenceDigest,
		)
	}
	for _, tool := range input.WorkflowTools {
		values = append(
			values,
			tool.ProbeID,
			tool.ImageReference,
			tool.ImageDigest,
		)
	}
	for _, timeout := range input.Limits.CaseTimeouts {
		values = append(values, string(timeout.CaseID))
	}
	for _, baseline := range input.Baselines.Resources {
		values = append(values, string(baseline.Resource))
	}
	return values
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func hasControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
