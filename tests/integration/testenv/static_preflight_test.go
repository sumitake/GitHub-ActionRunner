package testenv

import (
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestParseLinuxCapabilitySetsRequiresEveryCanonicalSet(
	t *testing.T,
) {
	t.Parallel()

	document := []byte(
		"Name:\tfixture\n" +
			"CapInh:\t0000000000000000\n" +
			"CapPrm:\t0000000000000000\n" +
			"CapEff:\t0000000000000000\n" +
			"CapBnd:\t0000000000000000\n" +
			"CapAmb:\t0000000000000000\n",
	)
	got, err := parseLinuxCapabilitySets(document)
	if err != nil {
		t.Fatalf("parseLinuxCapabilitySets: %v", err)
	}
	want := hostruntime.CapabilitySets{
		EffectiveEmpty:   true,
		PermittedEmpty:   true,
		InheritableEmpty: true,
		BoundingEmpty:    true,
		AmbientEmpty:     true,
	}
	if got != want {
		t.Fatalf("capability sets = %+v, want %+v", got, want)
	}

	for name, candidate := range map[string][]byte{
		"missing": []byte(
			"CapInh:\t0000000000000000\n" +
				"CapPrm:\t0000000000000000\n" +
				"CapEff:\t0000000000000000\n" +
				"CapBnd:\t0000000000000000\n",
		),
		"duplicate": append(
			append([]byte(nil), document...),
			[]byte("CapEff:\t0000000000000000\n")...,
		),
		"noncanonical": []byte(
			"CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\n" +
				"CapBnd:\t0\nCapAmb:\t0\n",
		),
		"nonzero": []byte(
			"CapInh:\t0000000000000000\n" +
				"CapPrm:\t0000000000000000\n" +
				"CapEff:\t0000000000000001\n" +
				"CapBnd:\t0000000000000000\n" +
				"CapAmb:\t0000000000000000\n",
		),
	} {
		name := name
		candidate := candidate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sets, err := parseLinuxCapabilitySets(candidate)
			if name == "nonzero" {
				if err != nil || sets.EffectiveEmpty {
					t.Fatalf("nonzero parse = %+v err=%v", sets, err)
				}
				return
			}
			if !errors.Is(err, ErrStaticPreflight) {
				t.Fatalf("error = %v, want static rejection", err)
			}
		})
	}
}

func TestStaticPreflightCrossBindsEveryImmutableAuthority(t *testing.T) {
	t.Parallel()

	parsed := staticPreflightParsedInput(t)
	observation := validStaticPreflightObservation(parsed.Input)
	result, err := validateStaticPreflight(parsed, observation)
	if err != nil {
		t.Fatalf("validateStaticPreflight: %v", err)
	}
	if result.ManifestBuildID != parsed.Input.Runtime.BuildID ||
		result.PolicyGraphDigest != observation.PolicyGraphDigest ||
		result.FixtureRootDigest !=
			parsed.Input.Fixture.RequiredEmptyDigest ||
		result.HostCapabilities != observation.HostCapabilities ||
		result.RunnerUser != "0:0" ||
		result.AdapterBrokerUser != "1001:1001" ||
		result.VerifierUser != "1002:1002" {
		t.Fatalf("static preflight result = %+v", result)
	}
}

func TestStaticPreflightRejectsCrossDocumentAndObservedSubstitution(
	t *testing.T,
) {
	t.Parallel()

	parsed := staticPreflightParsedInput(t)
	tests := []struct {
		name   string
		mutate func(*staticPreflightObservation)
	}{
		{
			name: "manifest digest",
			mutate: func(value *staticPreflightObservation) {
				value.ManifestDigest = inputDigestA
			},
		},
		{
			name: "manifest build",
			mutate: func(value *staticPreflightObservation) {
				value.ManifestBuildID = inputDigestB
			},
		},
		{
			name: "manifest fleet generation",
			mutate: func(value *staticPreflightObservation) {
				value.ManifestFleetGeneration++
			},
		},
		{
			name: "manifest runner digest",
			mutate: func(value *staticPreflightObservation) {
				value.ManifestImageDigests[0] = "sha256:" + inputDigestB
			},
		},
		{
			name: "overlay target",
			mutate: func(value *staticPreflightObservation) {
				value.OverlayHostIdentityDigest = inputDigestB
			},
		},
		{
			name: "overlay manifest path",
			mutate: func(value *staticPreflightObservation) {
				value.OverlayManifestPath += ".replacement"
			},
		},
		{
			name: "overlay policy path",
			mutate: func(value *staticPreflightObservation) {
				value.OverlayPolicyPath += ".replacement"
			},
		},
		{
			name: "fixture root outside broker root",
			mutate: func(value *staticPreflightObservation) {
				value.OverlayBrokerRoot = "/different/private/broker-root"
			},
		},
		{
			name: "overlay profile expected anchor",
			mutate: func(value *staticPreflightObservation) {
				value.OverlayProfileEvidenceDigest = inputDigestA
			},
		},
		{
			name: "policy raw digest",
			mutate: func(value *staticPreflightObservation) {
				value.PolicyDocumentDigest = inputDigestA
			},
		},
		{
			name: "compiled policy graph",
			mutate: func(value *staticPreflightObservation) {
				value.PolicyGraphDigest = inputDigestA
			},
		},
		{
			name: "trust bundle",
			mutate: func(value *staticPreflightObservation) {
				value.CADigest = inputDigestB
			},
		},
		{
			name: "seccomp",
			mutate: func(value *staticPreflightObservation) {
				value.SeccompDigest = inputDigestA
			},
		},
		{
			name: "source commit",
			mutate: func(value *staticPreflightObservation) {
				value.SourceCommit = "2222222222222222222222222222222222222222"
			},
		},
		{
			name: "plan",
			mutate: func(value *staticPreflightObservation) {
				value.PlanDigest = inputDigestA
			},
		},
		{
			name: "fixture root",
			mutate: func(value *staticPreflightObservation) {
				value.FixtureRootDigest = inputDigestA
			},
		},
		{
			name: "execution host",
			mutate: func(value *staticPreflightObservation) {
				value.HostFacts.HostIdentityDigest = inputDigestB
			},
		},
		{
			name: "docker cgroup enforcement",
			mutate: func(value *staticPreflightObservation) {
				value.DockerInfo.MemoryLimit = false
			},
		},
		{
			name: "capability observation absent",
			mutate: func(value *staticPreflightObservation) {
				value.HostCapabilitiesObserved = false
			},
		},
		{
			name: "degraded root effective capability",
			mutate: func(value *staticPreflightObservation) {
				value.HostCapabilities.EffectiveEmpty = false
			},
		},
		{
			name: "image order",
			mutate: func(value *staticPreflightObservation) {
				value.Images[0], value.Images[1] =
					value.Images[1], value.Images[0]
			},
		},
		{
			name: "image reference",
			mutate: func(value *staticPreflightObservation) {
				value.Images[0].Reference =
					parsed.Input.Images.Adapter.Reference
			},
		},
		{
			name: "image architecture",
			mutate: func(value *staticPreflightObservation) {
				value.Images[0].Architecture = "arm64"
			},
		},
		{
			name: "runner user",
			mutate: func(value *staticPreflightObservation) {
				value.Images[0].User = "1001:1001"
			},
		},
		{
			name: "adapter broker user mismatch",
			mutate: func(value *staticPreflightObservation) {
				value.Images[2].User = "1003:1003"
			},
		},
		{
			name: "helper nonroot",
			mutate: func(value *staticPreflightObservation) {
				value.Images[3].User = "1001:1001"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := validStaticPreflightObservation(parsed.Input)
			test.mutate(&observation)
			if _, err := validateStaticPreflight(
				parsed,
				observation,
			); err == nil {
				t.Fatal("static preflight accepted substituted authority")
			}
		})
	}
}

func TestStaticPreflightRejectsExpectedAnchorsAsObservedAuthority(
	t *testing.T,
) {
	t.Parallel()

	parsed := staticPreflightParsedInput(t)
	observation := validStaticPreflightObservation(parsed.Input)
	if _, err := validateStaticPreflight(parsed, observation); err != nil {
		t.Fatalf("validateStaticPreflight: %v", err)
	}
	if observation.FinalProfileEvidenceDigest != "" ||
		observation.FinalNetworkEvidenceDigest != "" {
		t.Fatal("test observation unexpectedly contains final authority")
	}

	observation.FinalProfileEvidenceDigest =
		parsed.Input.Runtime.ExpectedProfileEvidenceDigest
	if _, err := validateStaticPreflight(parsed, observation); err == nil {
		t.Fatal("static preflight accepted final profile authority")
	}

	observation = validStaticPreflightObservation(parsed.Input)
	observation.FinalNetworkEvidenceDigest =
		parsed.Input.Runtime.ExpectedNetworkEvidenceDigest
	if _, err := validateStaticPreflight(parsed, observation); err == nil {
		t.Fatal("static preflight accepted final network authority")
	}
}

func staticPreflightParsedInput(t *testing.T) ParsedConformanceInput {
	t.Helper()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	input := validConformanceInput(t, t.TempDir(), now)
	input.Target.ExpectedEUID = 0
	input.Fixture.ExecutionOwnerUID = 0
	path, document := writeConformanceInput(t, input)
	parsed, err := ReadConformanceInput(
		path,
		validReadOptions(now, len(document)),
	)
	if err != nil {
		t.Fatalf("ReadConformanceInput: %v", err)
	}
	return parsed
}

func validStaticPreflightObservation(
	input ConformanceInput,
) staticPreflightObservation {
	images := expectedStaticImageBindings(input)
	observedImages := make([]staticImageObservation, len(images))
	for index, image := range images {
		user := "1003:1003"
		switch image.ID {
		case "runner", "synthetic-listener":
			user = "0:0"
		case "adapter", "broker":
			user = "1001:1001"
		case "helper":
			user = "0:0"
		case "verifier":
			user = "1002:1002"
		}
		observedImages[index] = staticImageObservation{
			ID:               image.ID,
			Reference:        image.Reference,
			OperatingSystem:  input.Target.OperatingSystem,
			Architecture:     input.Target.Architecture,
			User:             user,
			ReferencePresent: true,
		}
	}
	return staticPreflightObservation{
		ManifestDigest:          input.Runtime.RuntimeManifestDigest,
		ManifestBuildID:         input.Runtime.BuildID,
		ManifestFleetGeneration: input.Runtime.FleetGeneration,
		ManifestTrustDigest:     input.Runtime.CADigest,
		ManifestSeccompDigest:   input.Runtime.SeccompDigest,
		ManifestPolicyDigest:    inputDigestA,
		ManifestImageDigests: []string{
			"sha256:" + input.Images.Runner.Digest,
			"sha256:" + input.Images.Adapter.Digest,
			"sha256:" + input.Images.Broker.Digest,
			"sha256:" + input.Images.Helper.Digest,
			"sha256:" + input.Images.Verifier.Digest,
		},
		OverlayDigest:                input.Runtime.PrivateOverlayDigest,
		OverlayManifestPath:          input.Runtime.RuntimeManifestPath,
		OverlayManifestDigest:        input.Runtime.RuntimeManifestDigest,
		OverlayPolicyPath:            input.Runtime.PolicyPath,
		OverlaySeccompRoot:           filepathDir(input.Runtime.SeccompPath),
		OverlayDockerPath:            "/usr/bin/docker",
		OverlayBrokerRoot:            filepathDir(input.Fixture.Root),
		OverlayBrokerNetwork:         "restricted-broker-v1",
		OverlayTargetOS:              input.Target.OperatingSystem,
		OverlayTargetArchitecture:    input.Target.Architecture,
		OverlayExpectedEUID:          input.Target.ExpectedEUID,
		OverlayProfileID:             input.Target.ProfileID,
		OverlayHostIdentityDigest:    input.Target.HostIdentityDigest,
		OverlayControlIdentityDigest: input.Target.ControlHostIdentityDigest,
		OverlayPolicyManifestDigest:  inputDigestA,
		OverlayPolicyGraphDigest:     inputDigestB,
		OverlayProfileEvidenceDigest: input.Runtime.ExpectedProfileEvidenceDigest,
		OverlayNetworkEvidenceDigest: input.Runtime.ExpectedNetworkEvidenceDigest,
		OverlayImageReferences: []string{
			input.Images.Runner.Reference,
			input.Images.Adapter.Reference,
			input.Images.Broker.Reference,
			input.Images.Helper.Reference,
			input.Images.Verifier.Reference,
		},
		PolicyDocumentDigest: input.Runtime.PolicyDigest,
		PolicyGraphDigest:    inputDigestB,
		CADigest:             input.Runtime.CADigest,
		SeccompDigest:        input.Runtime.SeccompDigest,
		PlanDigest:           input.Runtime.ConformancePlanDigest,
		SourceCommit:         input.Runtime.SourceCommit,
		FixtureRootDigest:    input.Fixture.RequiredEmptyDigest,
		HostFacts: FixtureHostFacts{
			OperatingSystem:           input.Target.OperatingSystem,
			Architecture:              input.Target.Architecture,
			EUID:                      input.Target.ExpectedEUID,
			HostIdentityDigest:        input.Target.HostIdentityDigest,
			ControlHostIdentityDigest: input.Target.ControlHostIdentityDigest,
		},
		DockerInfo: staticDockerInfoObservation{
			ServerVersion:   "28.0.1",
			OperatingSystem: "Example Linux",
			Architecture:    "x86_64",
			KernelVersion:   "6.12.1",
			CgroupVersion:   "2",
			MemoryLimit:     true,
			CPUCFS:          true,
			PIDsLimit:       true,
		},
		HostCapabilitiesObserved: true,
		HostCapabilities: hostruntime.CapabilitySets{
			EffectiveEmpty:   true,
			PermittedEmpty:   true,
			InheritableEmpty: true,
			BoundingEmpty:    true,
			AmbientEmpty:     true,
		},
		Images: observedImages,
	}
}

func filepathDir(path string) string {
	for index := len(path) - 1; index >= 0; index-- {
		if path[index] == '/' {
			if index == 0 {
				return "/"
			}
			return path[:index]
		}
	}
	return ""
}
