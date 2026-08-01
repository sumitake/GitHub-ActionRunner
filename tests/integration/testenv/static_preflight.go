package testenv

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

var ErrStaticPreflight = errors.New("testenv: static preflight failed")

func parseLinuxCapabilitySets(
	document []byte,
) (hostruntime.CapabilitySets, error) {
	if len(document) == 0 ||
		len(document) > 64<<10 ||
		!utf8.Valid(document) ||
		document[len(document)-1] != '\n' {
		return hostruntime.CapabilitySets{}, ErrStaticPreflight
	}
	names := [...]string{
		"CapInh:",
		"CapPrm:",
		"CapEff:",
		"CapBnd:",
		"CapAmb:",
	}
	values := make([]bool, len(names))
	seen := make([]bool, len(names))
	for _, line := range strings.Split(
		string(document[:len(document)-1]),
		"\n",
	) {
		for index, name := range names {
			if !strings.HasPrefix(line, name) {
				continue
			}
			if seen[index] ||
				len(line) != len(name)+1+16 ||
				line[len(name)] != '\t' {
				return hostruntime.CapabilitySets{},
					ErrStaticPreflight
			}
			raw := line[len(name)+1:]
			if !isLowerHex(raw, 16) {
				return hostruntime.CapabilitySets{},
					ErrStaticPreflight
			}
			value, err := strconv.ParseUint(raw, 16, 64)
			if err != nil {
				return hostruntime.CapabilitySets{},
					ErrStaticPreflight
			}
			seen[index] = true
			values[index] = value == 0
		}
	}
	for _, found := range seen {
		if !found {
			return hostruntime.CapabilitySets{}, ErrStaticPreflight
		}
	}
	return hostruntime.CapabilitySets{
		InheritableEmpty: values[0],
		PermittedEmpty:   values[1],
		EffectiveEmpty:   values[2],
		BoundingEmpty:    values[3],
		AmbientEmpty:     values[4],
	}, nil
}

// staticImageBinding is the immutable, declaration-ordered image authority
// expected from one private input. The order is part of the preflight
// contract so an observation cannot substitute one qualified image for
// another image role.
type staticImageBinding struct {
	ID        string
	Reference string
}

// staticImageObservation is the typed, raw-output-free projection of one
// immutable Docker image inspection.
type staticImageObservation struct {
	ID               string
	Reference        string
	OperatingSystem  string
	Architecture     string
	User             string
	ReferencePresent bool
}

// staticPreflightObservation is produced only by the Linux preflight
// collector. It intentionally has no final profile/network authority: those
// digests are legal only after cases 1-14 complete.
type staticPreflightObservation struct {
	ManifestDigest          string
	ManifestBuildID         string
	ManifestFleetGeneration uint64
	ManifestTrustDigest     string
	ManifestSeccompDigest   string
	ManifestPolicyDigest    string
	ManifestImageDigests    []string

	OverlayDigest                string
	OverlayManifestPath          string
	OverlayManifestDigest        string
	OverlayPolicyPath            string
	OverlaySeccompRoot           string
	OverlayDockerPath            string
	OverlayBrokerRoot            string
	OverlayBrokerNetwork         string
	OverlayTargetOS              string
	OverlayTargetArchitecture    string
	OverlayExpectedEUID          uint32
	OverlayProfileID             string
	OverlayHostIdentityDigest    string
	OverlayControlIdentityDigest string
	OverlayPolicyManifestDigest  string
	OverlayPolicyGraphDigest     string
	OverlayProfileEvidenceDigest string
	OverlayNetworkEvidenceDigest string
	OverlayImageReferences       []string

	PolicyDocumentDigest     string
	PolicyGraphDigest        string
	CADigest                 string
	SeccompDigest            string
	PlanDigest               string
	SourceCommit             string
	FixtureRootDigest        string
	HostFacts                FixtureHostFacts
	DockerInfo               staticDockerInfoObservation
	HostCapabilitiesObserved bool
	HostCapabilities         hostruntime.CapabilitySets
	Images                   []staticImageObservation

	// These fields exist as tripwires. A static collector that attempts to
	// promote an expected anchor into observed authority is rejected.
	FinalProfileEvidenceDigest string
	FinalNetworkEvidenceDigest string
}

type staticPreflightResult struct {
	ManifestBuildID   string
	PolicyGraphDigest string
	FixtureRootDigest string
	RunnerUser        string
	AdapterBrokerUser string
	VerifierUser      string
	WorkflowToolUsers []string
	HostFacts         FixtureHostFacts
	DockerInfo        staticDockerInfoObservation
	HostCapabilities  hostruntime.CapabilitySets
}

func validateStaticPreflight(
	parsed ParsedConformanceInput,
	observation staticPreflightObservation,
) (staticPreflightResult, error) {
	if !validateParsedInputEnvelope(parsed) ||
		observation.FinalProfileEvidenceDigest != "" ||
		observation.FinalNetworkEvidenceDigest != "" {
		return staticPreflightResult{}, ErrStaticPreflight
	}
	input := parsed.Input
	if !staticManifestMatches(input, observation) ||
		!staticOverlayMatches(input, observation) ||
		observation.PolicyDocumentDigest != input.Runtime.PolicyDigest ||
		observation.PolicyGraphDigest !=
			observation.OverlayPolicyGraphDigest ||
		observation.CADigest != input.Runtime.CADigest ||
		observation.SeccompDigest != input.Runtime.SeccompDigest ||
		observation.PlanDigest != input.Runtime.ConformancePlanDigest ||
		observation.SourceCommit != input.Runtime.SourceCommit ||
		observation.FixtureRootDigest !=
			input.Fixture.RequiredEmptyDigest ||
		!validateFixtureHostFacts(input.Target, observation.HostFacts) ||
		!staticDockerInfoMatches(input.Target, observation.DockerInfo) ||
		!validObservedHostCapabilities(
			input.Target,
			observation.HostCapabilitiesObserved,
			observation.HostCapabilities,
		) {
		return staticPreflightResult{}, ErrStaticPreflight
	}

	users, ok := validateStaticImages(input, observation.Images)
	if !ok {
		return staticPreflightResult{}, ErrStaticPreflight
	}
	return staticPreflightResult{
		ManifestBuildID:   observation.ManifestBuildID,
		PolicyGraphDigest: observation.PolicyGraphDigest,
		FixtureRootDigest: observation.FixtureRootDigest,
		RunnerUser:        users.runner,
		AdapterBrokerUser: users.adapterBroker,
		VerifierUser:      users.verifier,
		WorkflowToolUsers: append([]string(nil), users.workflow...),
		HostFacts:         observation.HostFacts,
		DockerInfo:        observation.DockerInfo,
		HostCapabilities:  observation.HostCapabilities,
	}, nil
}

func validObservedHostCapabilities(
	target TargetBinding,
	observed bool,
	capabilities hostruntime.CapabilitySets,
) bool {
	if !observed {
		return false
	}
	profile, ok := runtimeProfileFromTarget(target.ProfileID)
	if !ok {
		return false
	}
	switch profile {
	case hostruntime.HostProfileStrictLinux:
		return target.ExpectedEUID > 0
	case hostruntime.HostProfileQTSCaplessRoot:
		return hostruntime.ValidateDegradedRootProof(
			hostruntime.HostProfileQTSCaplessRoot,
			true,
			int(target.ExpectedEUID),
			capabilities,
		) == nil
	default:
		return false
	}
}

func staticManifestMatches(
	input ConformanceInput,
	observation staticPreflightObservation,
) bool {
	expectedImages := []ImmutableImageBinding{
		input.Images.Runner,
		input.Images.Adapter,
		input.Images.Broker,
		input.Images.Helper,
		input.Images.Verifier,
	}
	if observation.ManifestDigest != input.Runtime.RuntimeManifestDigest ||
		observation.ManifestBuildID != input.Runtime.BuildID ||
		observation.ManifestFleetGeneration != input.Runtime.FleetGeneration ||
		observation.ManifestTrustDigest != input.Runtime.CADigest ||
		observation.ManifestSeccompDigest != input.Runtime.SeccompDigest ||
		observation.ManifestPolicyDigest !=
			observation.OverlayPolicyManifestDigest ||
		len(observation.ManifestImageDigests) != len(expectedImages) {
		return false
	}
	for index, expected := range expectedImages {
		if observation.ManifestImageDigests[index] !=
			"sha256:"+expected.Digest {
			return false
		}
	}
	return true
}

func staticOverlayMatches(
	input ConformanceInput,
	observation staticPreflightObservation,
) bool {
	runtimeProfile, profileOK := runtimeProfileFromTarget(
		input.Target.ProfileID,
	)
	expectedImages := []ImmutableImageBinding{
		input.Images.Runner,
		input.Images.Adapter,
		input.Images.Broker,
		input.Images.Helper,
		input.Images.Verifier,
	}
	if observation.OverlayDigest != input.Runtime.PrivateOverlayDigest ||
		observation.OverlayManifestPath != input.Runtime.RuntimeManifestPath ||
		observation.OverlayManifestDigest !=
			input.Runtime.RuntimeManifestDigest ||
		observation.OverlayPolicyPath != input.Runtime.PolicyPath ||
		observation.OverlaySeccompRoot !=
			filepath.Dir(input.Runtime.SeccompPath) ||
		!validAbsolutePath(observation.OverlayDockerPath) ||
		!validAbsolutePath(observation.OverlayBrokerRoot) ||
		filepath.Dir(input.Fixture.Root) != observation.OverlayBrokerRoot ||
		observation.OverlayBrokerNetwork != "restricted-broker-v1" ||
		observation.OverlayTargetOS != input.Target.OperatingSystem ||
		observation.OverlayTargetArchitecture != input.Target.Architecture ||
		observation.OverlayExpectedEUID != input.Target.ExpectedEUID ||
		!profileOK ||
		observation.OverlayProfileID != string(runtimeProfile) ||
		observation.OverlayHostIdentityDigest !=
			input.Target.HostIdentityDigest ||
		observation.OverlayControlIdentityDigest !=
			input.Target.ControlHostIdentityDigest ||
		observation.OverlayProfileEvidenceDigest !=
			input.Runtime.ExpectedProfileEvidenceDigest ||
		observation.OverlayNetworkEvidenceDigest !=
			input.Runtime.ExpectedNetworkEvidenceDigest ||
		!isLowerHex(observation.OverlayPolicyManifestDigest, 64) ||
		!isLowerHex(observation.OverlayPolicyGraphDigest, 64) ||
		len(observation.OverlayImageReferences) != len(expectedImages) {
		return false
	}
	for index, expected := range expectedImages {
		if observation.OverlayImageReferences[index] != expected.Reference {
			return false
		}
	}
	return true
}

type staticImageUsers struct {
	runner        string
	adapterBroker string
	verifier      string
	workflow      []string
}

func validateStaticImages(
	input ConformanceInput,
	observed []staticImageObservation,
) (staticImageUsers, bool) {
	expected := expectedStaticImageBindings(input)
	if len(observed) != len(expected) {
		return staticImageUsers{}, false
	}
	for index, image := range observed {
		if image.ID != expected[index].ID ||
			image.Reference != expected[index].Reference ||
			!image.ReferencePresent ||
			image.OperatingSystem != input.Target.OperatingSystem ||
			image.Architecture != input.Target.Architecture {
			return staticImageUsers{}, false
		}
		if _, _, ok := parseStaticNumericUser(image.User); !ok {
			return staticImageUsers{}, false
		}
	}

	users := staticImageUsers{
		runner:        observed[0].User,
		adapterBroker: observed[1].User,
		verifier:      observed[4].User,
	}
	runnerUID, runnerGID, _ := parseStaticNumericUser(observed[0].User)
	syntheticUID, syntheticGID, _ := parseStaticNumericUser(observed[5].User)
	switch input.Target.ProfileID {
	case "strict-linux":
		if runnerUID == 0 || syntheticUID == 0 {
			return staticImageUsers{}, false
		}
	case "qts-capless-root":
		if runnerUID != 0 || runnerGID != 0 ||
			syntheticUID != 0 || syntheticGID != 0 {
			return staticImageUsers{}, false
		}
	default:
		return staticImageUsers{}, false
	}
	if observed[0].User != observed[5].User {
		return staticImageUsers{}, false
	}

	adapterUID, _, _ := parseStaticNumericUser(observed[1].User)
	brokerUID, _, _ := parseStaticNumericUser(observed[2].User)
	helperUID, helperGID, _ := parseStaticNumericUser(observed[3].User)
	verifierUID, _, _ := parseStaticNumericUser(observed[4].User)
	if adapterUID == 0 ||
		brokerUID == 0 ||
		observed[1].User != observed[2].User ||
		helperUID != 0 ||
		helperGID != 0 ||
		verifierUID == 0 {
		return staticImageUsers{}, false
	}

	users.workflow = make([]string, len(input.WorkflowTools))
	for index := range input.WorkflowTools {
		image := observed[6+index]
		uid, _, _ := parseStaticNumericUser(image.User)
		if uid == 0 {
			return staticImageUsers{}, false
		}
		users.workflow[index] = image.User
	}
	return users, true
}

func expectedStaticImageBindings(
	input ConformanceInput,
) []staticImageBinding {
	values := []ImmutableImageBinding{
		input.Images.Runner,
		input.Images.Adapter,
		input.Images.Broker,
		input.Images.Helper,
		input.Images.Verifier,
		input.Images.SyntheticListener,
	}
	result := make([]staticImageBinding, 0, len(values)+len(input.WorkflowTools))
	for _, value := range values {
		result = append(result, staticImageBinding{
			ID:        value.ID,
			Reference: value.Reference,
		})
	}
	for _, tool := range input.WorkflowTools {
		result = append(result, staticImageBinding{
			ID:        tool.ProbeID,
			Reference: tool.ImageReference,
		})
	}
	return result
}

func parseStaticNumericUser(value string) (uint64, uint64, bool) {
	if strings.Count(value, ":") != 1 {
		return 0, 0, false
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, false
	}
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != parts[0] {
		return 0, 0, false
	}
	gid, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || strconv.FormatUint(gid, 10) != parts[1] {
		return 0, 0, false
	}
	return uid, gid, true
}

func staticDockerInfoMatches(
	target TargetBinding,
	observation staticDockerInfoObservation,
) bool {
	if !validStaticDockerInfo(observation) {
		return false
	}
	architecture := observation.Architecture
	switch architecture {
	case "x86_64":
		architecture = "amd64"
	case "aarch64":
		architecture = "arm64"
	}
	return architecture == target.Architecture
}
