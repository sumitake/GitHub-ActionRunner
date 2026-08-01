package testenv

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

const (
	inputDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inputDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	inputDigestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	inputDigestD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

type usedAuthorizationSet map[string]bool

func (u usedAuthorizationSet) Used(runID string) bool { return u[runID] }

func TestReadConformanceInputAcceptsOnlyCanonicalFreshDocument(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	input := validConformanceInput(t, t.TempDir(), now)
	path, document := writeConformanceInput(t, input)

	parsed, err := ReadConformanceInput(path, ConformanceInputReadOptions{
		ExpectedOwner: uint32(os.Geteuid()),
		ExpectedMode:  0o400,
		MaximumBytes:  int64(len(document)),
		Now:           func() time.Time { return now },
		Usage:         usedAuthorizationSet{},
	})
	if err != nil {
		t.Fatalf("ReadConformanceInput: %v", err)
	}
	if !bytes.Equal(parsed.Document, document) ||
		parsed.Digest == "" ||
		parsed.Input.Authorization.RunID != input.Authorization.RunID ||
		parsed.Input.Runtime.BuildID != input.Runtime.BuildID {
		t.Fatalf("parsed input = %+v", parsed)
	}
	parsed.Document[0] ^= 1
	again, err := ReadConformanceInput(path, ConformanceInputReadOptions{
		ExpectedOwner: uint32(os.Geteuid()),
		ExpectedMode:  0o400,
		MaximumBytes:  int64(len(document)),
		Now:           func() time.Time { return now },
		Usage:         usedAuthorizationSet{},
	})
	if err != nil || !bytes.Equal(again.Document, document) {
		t.Fatal("returned document was not defensive")
	}
}

func TestReadConformanceInputRejectsInvalidBindingsAndAuthority(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	tests := map[string]func(*ConformanceInput){
		"wrong action": func(input *ConformanceInput) {
			input.Authorization.Action = AuthorizationAction("deploy")
			resealAuthorization(t, input)
		},
		"authorization digest": func(input *ConformanceInput) {
			input.Authorization.Digest = inputDigestD
		},
		"same target and control": func(input *ConformanceInput) {
			input.Target.ControlHostIdentityDigest =
				input.Target.HostIdentityDigest
		},
		"unknown profile": func(input *ConformanceInput) {
			input.Target.ProfileID = "large-tmpfs"
		},
		"relative path": func(input *ConformanceInput) {
			input.Runtime.PolicyPath = "policy.json"
		},
		"secret-shaped path": func(input *ConformanceInput) {
			input.Runtime.PolicyPath = "/private/access_token=ghp_" +
				strings.Repeat("a", 32)
		},
		"mutable image reference": func(input *ConformanceInput) {
			input.Images.Runner.Reference = "example/runner:latest"
		},
		"image reference digest mismatch": func(input *ConformanceInput) {
			input.Images.Runner.Reference =
				"example/runner@sha256:" + inputDigestB
		},
		"uppercase image reference": func(input *ConformanceInput) {
			input.Images.Runner.Reference =
				"Example/runner@sha256:" + inputDigestA
		},
		"duplicate image identity": func(input *ConformanceInput) {
			input.Images.Adapter.Digest = input.Images.Runner.Digest
		},
		"duplicate image reference": func(input *ConformanceInput) {
			input.Images.Adapter.Reference = input.Images.Runner.Reference
		},
		"synthetic production substitution": func(input *ConformanceInput) {
			input.Images.SyntheticListener.Reference =
				input.Images.Runner.Reference
		},
		"duplicate workflow tool": func(input *ConformanceInput) {
			input.WorkflowTools[1] = input.WorkflowTools[0]
		},
		"workflow tool order": func(input *ConformanceInput) {
			input.WorkflowTools[0], input.WorkflowTools[1] =
				input.WorkflowTools[1], input.WorkflowTools[0]
		},
		"workflow tool digest mismatch": func(input *ConformanceInput) {
			input.WorkflowTools[0].ImageReference =
				"example/tools/" + input.WorkflowTools[0].ProbeID +
					"@sha256:" + inputDigestD
		},
		"workflow tool image substitution": func(input *ConformanceInput) {
			input.WorkflowTools[0].ImageReference =
				input.Images.Runner.Reference
			input.WorkflowTools[0].ImageDigest =
				input.Images.Runner.Digest
		},
		"positive private sentinel": func(input *ConformanceInput) {
			input.Sentinels.Positive.URL = "https://127.0.0.1/probe"
			input.Sentinels.Positive.Host = "127.0.0.1"
		},
		"positive public literal sentinel": func(input *ConformanceInput) {
			input.Sentinels.Positive.URL = "https://8.8.8.8/probe"
			input.Sentinels.Positive.Host = "8.8.8.8"
		},
		"positive userinfo": func(input *ConformanceInput) {
			input.Sentinels.Positive.URL =
				"https://user@example.com/probe"
		},
		"positive query": func(input *ConformanceInput) {
			input.Sentinels.Positive.URL =
				"https://example.com/probe?leak=1"
		},
		"positive fragment": func(input *ConformanceInput) {
			input.Sentinels.Positive.URL =
				"https://example.com/probe#leak"
		},
		"policy evidence mismatch": func(input *ConformanceInput) {
			input.Sentinels.Positive.PolicyEvidenceDigest = inputDigestA
		},
		"duplicate literal sentinel": func(input *ConformanceInput) {
			input.Sentinels.LiteralDeny = append(
				input.Sentinels.LiteralDeny,
				input.Sentinels.LiteralDeny[0],
			)
		},
		"duplicate DNS sentinel": func(input *ConformanceInput) {
			input.Sentinels.DNSDeny = append(
				input.Sentinels.DNSDeny,
				input.Sentinels.DNSDeny[0],
			)
		},
		"zero loopback flood attempts": func(input *ConformanceInput) {
			input.LoopbackFloodAttempts = 0
		},
		"loopback flood exceeds case deadline": func(input *ConformanceInput) {
			input.LoopbackFloodAttempts = 501
		},
		"loopback flood exceeds process budget": func(input *ConformanceInput) {
			input.Limits.MaximumProcesses = 0
		},
		"loopback flood exceeds file descriptor budget": func(input *ConformanceInput) {
			input.Limits.MaximumFileDescriptors = 7
		},
		"loopback flood request exceeds input budget": func(input *ConformanceInput) {
			input.Limits.MaximumCommandInputBytes =
				uint64(loopbackFloodRequestBytes(
					input.LoopbackFloodAttempts,
				) - 1)
		},
		"loopback flood report exceeds evidence budget": func(input *ConformanceInput) {
			input.Limits.MaximumEvidenceBytes =
				uint64(loopbackFloodReportBytes(
					input.LoopbackFloodAttempts,
				) - 1)
		},
		"zero bounded limit": func(input *ConformanceInput) {
			input.Limits.MaximumEvidenceBytes = 0
		},
		"zero command input limit": func(input *ConformanceInput) {
			input.Limits.MaximumCommandInputBytes = 0
		},
		"command input int overflow": func(input *ConformanceInput) {
			input.Limits.MaximumCommandInputBytes = uint64(math.MaxInt) + 1
		},
		"zero dial reservation block": func(input *ConformanceInput) {
			input.Limits.DialReservationBlockSize = 0
		},
		"dial reservation block overflow": func(input *ConformanceInput) {
			input.Limits.DialReservationBlockSize = math.MaxUint32 + 1
		},
		"zero dial authority clients": func(input *ConformanceInput) {
			input.Limits.DialAuthorityMaximumClients = 0
		},
		"dial authority clients exceed processes": func(input *ConformanceInput) {
			input.Limits.DialAuthorityMaximumClients =
				uint32(input.Limits.MaximumProcesses + 1)
		},
		"dial authority clients exceed file descriptors": func(input *ConformanceInput) {
			input.Limits.MaximumProcesses = 2_000
			input.Limits.DialAuthorityMaximumClients =
				uint32(input.Limits.MaximumFileDescriptors + 1)
		},
		"zero dial authority timeout": func(input *ConformanceInput) {
			input.Limits.DialAuthorityTimeoutMilliseconds = 0
		},
		"dial authority timeout duration overflow": func(input *ConformanceInput) {
			input.Limits.DialAuthorityTimeoutMilliseconds =
				maxDurationMilliseconds + 1
		},
		"dial authority timeout exceeds production ceiling": func(input *ConformanceInput) {
			input.Limits.DialAuthorityTimeoutMilliseconds = 30_001
			input.Limits.CaseTimeouts[2].TimeoutMilliseconds = 31_000
		},
		"dial authority timeout exceeds broker case": func(input *ConformanceInput) {
			input.Limits.DialAuthorityTimeoutMilliseconds =
				input.Limits.CaseTimeouts[2].TimeoutMilliseconds + 1
		},
		"zero docker log bytes": func(input *ConformanceInput) {
			input.Limits.DockerLogMaximumBytes = 0
		},
		"zero docker log files": func(input *ConformanceInput) {
			input.Limits.DockerLogMaximumFiles = 0
		},
		"docker log product overflow": func(input *ConformanceInput) {
			input.Limits.DockerLogMaximumBytes = math.MaxUint64
			input.Limits.DockerLogMaximumFiles = 2
			input.Limits.MaximumLogBytes = math.MaxUint64
		},
		"docker log fleet exceeds run ceiling": func(input *ConformanceInput) {
			input.Limits.DockerLogMaximumBytes = 100
			input.Limits.DockerLogMaximumFiles = 2
			input.Limits.MaximumLogBytes = 599
		},
		"case timeout duration overflow": func(input *ConformanceInput) {
			input.Limits.CaseTimeouts[0].TimeoutMilliseconds =
				maxDurationMilliseconds + 1
		},
		"cleanup duration overflow": func(input *ConformanceInput) {
			input.Limits.CleanupTimeoutMilliseconds =
				maxDurationMilliseconds + 1
		},
		"authorization window duration overflow": func(input *ConformanceInput) {
			input.Limits.MaximumAuthorizationWindowSeconds =
				maxDurationSeconds + 1
		},
		"missing case timeout": func(input *ConformanceInput) {
			input.Limits.CaseTimeouts =
				input.Limits.CaseTimeouts[:len(input.Limits.CaseTimeouts)-1]
		},
		"reordered case timeout": func(input *ConformanceInput) {
			input.Limits.CaseTimeouts[0], input.Limits.CaseTimeouts[1] =
				input.Limits.CaseTimeouts[1], input.Limits.CaseTimeouts[0]
		},
		"missing reclamation resource": func(input *ConformanceInput) {
			input.Baselines.Resources =
				input.Baselines.Resources[:len(input.Baselines.Resources)-1]
		},
		"zero baseline margin": func(input *ConformanceInput) {
			input.Baselines.Resources[0].Margin = 0
		},
		"invalid slope denominator": func(input *ConformanceInput) {
			input.Baselines.Resources[0].MaximumSlopeDenominator = 0
		},
		"fixture not absolute": func(input *ConformanceInput) {
			input.Fixture.Root = "fixture"
		},
		"fixture parent identity missing": func(input *ConformanceInput) {
			input.Fixture.ParentInode = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := validConformanceInput(t, t.TempDir(), now)
			mutate(&input)
			path, document := writeConformanceInput(t, input)
			if _, err := ReadConformanceInput(
				path,
				validReadOptions(now, len(document)),
			); err == nil {
				t.Fatalf("ReadConformanceInput accepted %s", name)
			}
		})
	}
}

func TestReadConformanceInputRejectsNoncanonicalOrStaleDocument(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	input := validConformanceInput(t, t.TempDir(), now)
	_, canonical := writeConformanceInput(t, input)
	unknown := bytes.Replace(
		canonical,
		[]byte(`"schema_version":1`),
		[]byte(`"unknown":1,"schema_version":1`),
		1,
	)
	missingFloodAttempts := bytes.Replace(
		canonical,
		[]byte(`,"loopback_flood_attempts":64`),
		nil,
		1,
	)
	duplicateFloodAttempts := bytes.Replace(
		canonical,
		[]byte(`"loopback_flood_attempts":64`),
		[]byte(
			`"loopback_flood_attempts":64,`+
				`"loopback_flood_attempts":64`,
		),
		1,
	)
	reorderedFloodAttempts := bytes.Replace(
		canonical,
		[]byte(
			`"workflow_tools":[`,
		),
		[]byte(
			`"loopback_flood_attempts":64,"workflow_tools":[`,
		),
		1,
	)
	reorderedFloodAttempts = bytes.Replace(
		reorderedFloodAttempts,
		[]byte(`],"loopback_flood_attempts":64,"limits"`),
		[]byte(`],"limits"`),
		1,
	)
	overflowFloodAttempts := bytes.Replace(
		canonical,
		[]byte(`"loopback_flood_attempts":64`),
		[]byte(`"loopback_flood_attempts":4294967296`),
		1,
	)
	for name, document := range map[string][]byte{
		"leading whitespace":       append([]byte(" "), canonical...),
		"trailing newline":         append(append([]byte(nil), canonical...), '\n'),
		"unknown field":            unknown,
		"missing flood attempts":   missingFloodAttempts,
		"duplicate flood attempts": duplicateFloodAttempts,
		"reordered flood attempts": reorderedFloodAttempts,
		"overflow flood attempts":  overflowFloodAttempts,
		"duplicate field": bytes.Replace(
			canonical,
			[]byte(`"schema_version":1`),
			[]byte(`"schema_version":1,"schema_version":1`),
			1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRawConformanceInput(t, document, 0o400)
			if _, err := ReadConformanceInput(
				path,
				validReadOptions(now, len(document)),
			); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}

	t.Run("future", func(t *testing.T) {
		future := validConformanceInput(t, t.TempDir(), now.Add(2*time.Hour))
		path, document := writeConformanceInput(t, future)
		if _, err := ReadConformanceInput(
			path,
			validReadOptions(now, len(document)),
		); err == nil {
			t.Fatal("accepted future authorization")
		}
	})
	t.Run("expired", func(t *testing.T) {
		expired := validConformanceInput(t, t.TempDir(), now.Add(-2*time.Hour))
		path, document := writeConformanceInput(t, expired)
		if _, err := ReadConformanceInput(
			path,
			validReadOptions(now, len(document)),
		); err == nil {
			t.Fatal("accepted expired authorization")
		}
	})
	t.Run("reused", func(t *testing.T) {
		path, document := writeConformanceInput(t, input)
		options := validReadOptions(now, len(document))
		options.Usage = usedAuthorizationSet{input.Authorization.RunID: true}
		if _, err := ReadConformanceInput(path, options); err == nil {
			t.Fatal("accepted reused authorization")
		}
	})
}

func TestReadConformanceInputRejectsUnsafeFileIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	input := validConformanceInput(t, t.TempDir(), now)
	canonical, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	t.Run("wrong mode", func(t *testing.T) {
		path := writeRawConformanceInput(t, canonical, 0o600)
		if _, err := ReadConformanceInput(
			path,
			validReadOptions(now, len(canonical)),
		); err == nil {
			t.Fatal("accepted wrong mode")
		}
	})
	t.Run("wrong owner", func(t *testing.T) {
		path := writeRawConformanceInput(t, canonical, 0o400)
		options := validReadOptions(now, len(canonical))
		options.ExpectedOwner++
		if _, err := ReadConformanceInput(path, options); err == nil {
			t.Fatal("accepted wrong owner")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := writeRawConformanceInput(t, canonical, 0o400)
		link := filepath.Join(t.TempDir(), "input.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if _, err := ReadConformanceInput(
			link,
			validReadOptions(now, len(canonical)),
		); err == nil {
			t.Fatal("accepted symlink")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		path := writeRawConformanceInput(t, canonical, 0o400)
		if err := os.Link(path, path+".link"); err != nil {
			t.Fatalf("Link: %v", err)
		}
		if _, err := ReadConformanceInput(
			path,
			validReadOptions(now, len(canonical)),
		); err == nil {
			t.Fatal("accepted multiply linked input")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := ReadConformanceInput(
			t.TempDir(),
			validReadOptions(now, len(canonical)),
		); err == nil {
			t.Fatal("accepted directory")
		}
	})
	t.Run("oversize", func(t *testing.T) {
		path := writeRawConformanceInput(t, canonical, 0o400)
		if _, err := ReadConformanceInput(
			path,
			validReadOptions(now, len(canonical)-1),
		); err == nil {
			t.Fatal("accepted oversize input")
		}
	})
	for _, hookName := range []string{"after-open", "after-read"} {
		t.Run("replacement-"+hookName, func(t *testing.T) {
			path := writeRawConformanceInput(t, canonical, 0o400)
			replacement := append([]byte(nil), canonical...)
			replacement[len(replacement)-1] ^= 1
			replace := func() {
				newPath := path + ".replacement"
				if err := os.WriteFile(newPath, replacement, 0o400); err != nil {
					t.Fatalf("WriteFile(replacement): %v", err)
				}
				if err := os.Rename(newPath, path); err != nil {
					t.Fatalf("Rename(replacement): %v", err)
				}
			}
			options := validReadOptions(now, len(canonical))
			if hookName == "after-open" {
				options.afterOpen = replace
			} else {
				options.afterRead = replace
			}
			if _, err := ReadConformanceInput(path, options); err == nil {
				t.Fatalf("accepted %s replacement", hookName)
			}
		})
	}
}

func validConformanceInput(
	t *testing.T,
	root string,
	windowCenter time.Time,
) ConformanceInput {
	t.Helper()
	path := func(name string) string { return filepath.Join(root, name) }
	input := ConformanceInput{
		SchemaVersion: 1,
		Authorization: Authorization{
			SchemaVersion: 1,
			Action:        ActionTargetConformance,
			RunID:         inputDigestA,
			NotBefore:     windowCenter.Add(-time.Hour).Format(time.RFC3339),
			NotAfter:      windowCenter.Add(time.Hour).Format(time.RFC3339),
		},
		Target: TargetBinding{
			OperatingSystem:            "linux",
			Architecture:               "amd64",
			ExpectedEUID:               uint32(os.Geteuid()),
			ProfileID:                  "qts-capless-root",
			HostIdentityDigest:         inputDigestA,
			ControlHostIdentityDigest:  inputDigestB,
			IdentitySeparationRequired: true,
		},
		Runtime: RuntimeBinding{
			SourceCommit:                  "1111111111111111111111111111111111111111",
			BuildID:                       inputDigestA,
			RuntimeManifestPath:           path("runtime-manifest.json"),
			RuntimeManifestDigest:         inputDigestB,
			PrivateOverlayPath:            path("private-overlay.json"),
			PrivateOverlayDigest:          inputDigestC,
			PolicyPath:                    path("policy.json"),
			PolicyDigest:                  inputDigestD,
			CAPath:                        path("ca.pem"),
			CADigest:                      inputDigestA,
			SeccompPath:                   path("seccomp.json"),
			SeccompDigest:                 inputDigestB,
			ConformancePlanDigest:         inputDigestC,
			ExpectedProfileEvidenceDigest: inputDigestD,
			ExpectedNetworkEvidenceDigest: inputDigestC,
			FleetGeneration:               23,
		},
		Images: ImageBindings{
			Runner: ImmutableImageBinding{
				ID: "runner", Reference: "example/runner@sha256:" + inputDigestA,
				Digest: inputDigestA,
			},
			Adapter: ImmutableImageBinding{
				ID: "adapter", Reference: "example/adapter@sha256:" + inputDigestB,
				Digest: inputDigestB,
			},
			Broker: ImmutableImageBinding{
				ID: "broker", Reference: "example/broker@sha256:" + inputDigestC,
				Digest: inputDigestC,
			},
			Helper: ImmutableImageBinding{
				ID: "helper", Reference: "example/helper@sha256:" + inputDigestD,
				Digest: inputDigestD,
			},
			Verifier: ImmutableImageBinding{
				ID:        "verifier",
				Reference: "example/verifier@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
				Digest:    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			},
			SyntheticListener: ImmutableImageBinding{
				ID:        "synthetic-listener",
				Reference: "example/synthetic-listener@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				Digest:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			},
		},
		Sentinels: SentinelBindings{
			Positive: PublicHTTPSSentinel{
				ID:                   "public-https",
				URL:                  "https://example.com/probe",
				Host:                 "example.com",
				Port:                 443,
				HostIdentityDigest:   inputDigestA,
				SPKIDigest:           inputDigestB,
				CertificateDigest:    inputDigestC,
				PolicyEntryDigest:    inputDigestD,
				PolicyEvidenceDigest: inputDigestC,
				ResponseBodyDigest:   inputDigestA,
			},
			LiteralDeny: []LiteralDenySentinel{
				{
					ID: "deny-loopback", Address: "127.0.0.1",
					Class: AddressLoopback, EvidenceDigest: inputDigestA,
				},
				{
					ID: "deny-private", Address: "10.0.0.1",
					Class: AddressPrivate, EvidenceDigest: inputDigestB,
				},
			},
			DNSDeny: []DNSDenySentinel{{
				ID: "deny-private-dns", Host: "blocked.example.com",
				Class: AddressPrivate, EvidenceDigest: inputDigestC,
			}},
		},
		LoopbackFloodAttempts: 64,
		Limits: ConformanceLimits{
			CleanupTimeoutMilliseconds:        1_000,
			CleanupSLOMilliseconds:            2_000,
			ObservationCadenceMilliseconds:    10,
			ReclamationSampleCount:            3,
			MaximumEvidenceBytes:              65_536,
			MaximumCommandInputBytes:          65_536,
			MaximumAuthorizationWindowSeconds: 7_200,
			MaximumProcesses:                  100,
			MaximumFileDescriptors:            1_000,
			MaximumNamespaces:                 20,
			MaximumConntrackRows:              1_000,
			MaximumLogBytes:                   1_000_000,
			MaximumTmpfsBytes:                 1_000_000,
			MaximumScratchBytes:               1_000_000,
			MaximumMemoryBytes:                2_000_000,
			MaximumSwapBytes:                  1_000_000,
			MaximumContainers:                 10,
			DialReservationBlockSize:          16,
			DialAuthorityMaximumClients:       4,
			DialAuthorityTimeoutMilliseconds:  100,
			DockerLogMaximumBytes:             1_000,
			DockerLogMaximumFiles:             2,
		},
		Baselines: ReclamationBaselines{},
		Fixture: FixtureBinding{
			Root:                         path("fixture"),
			ParentDevice:                 7,
			ParentInode:                  11,
			RequiredEmptyDigest:          inputDigestD,
			ExecutionOwnerUID:            uint32(os.Geteuid()),
			ExecutionOwnerIdentityDigest: inputDigestB,
		},
	}
	for _, id := range conformance.RequiredCases() {
		input.Limits.CaseTimeouts = append(
			input.Limits.CaseTimeouts,
			CaseTimeout{CaseID: id, TimeoutMilliseconds: 500},
		)
	}
	for _, resource := range RequiredReclamationResources() {
		input.Baselines.Resources = append(
			input.Baselines.Resources,
			ReclamationBaseline{
				Resource:                resource,
				Baseline:                1,
				Margin:                  1,
				MaximumSlopeNumerator:   1,
				MaximumSlopeDenominator: 10,
			},
		)
	}
	for index, id := range RequiredWorkflowToolProbeIDs() {
		digestCharacters := []byte(inputDigestA)
		digestCharacters[0] = "0123456789"[index]
		input.WorkflowTools = append(
			input.WorkflowTools,
			WorkflowToolBinding{
				ProbeID: id,
				ImageReference: "example/tools/" + id + "@sha256:" +
					string(digestCharacters),
				ImageDigest: string(digestCharacters),
			},
		)
	}
	resealAuthorization(t, &input)
	return input
}

func resealAuthorization(t *testing.T, input *ConformanceInput) {
	t.Helper()
	input.Authorization.Digest = ""
	digest, err := ComputeAuthorizationDigest(input.Authorization)
	if err != nil {
		t.Fatalf("ComputeAuthorizationDigest: %v", err)
	}
	input.Authorization.Digest = digest
}

func writeConformanceInput(
	t *testing.T,
	input ConformanceInput,
) (string, []byte) {
	t.Helper()
	document, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return writeRawConformanceInput(t, document, 0o400), document
}

func writeRawConformanceInput(
	t *testing.T,
	document []byte,
	mode os.FileMode,
) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, document, mode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func validReadOptions(
	now time.Time,
	maximumBytes int,
) ConformanceInputReadOptions {
	return ConformanceInputReadOptions{
		ExpectedOwner: uint32(os.Geteuid()),
		ExpectedMode:  0o400,
		MaximumBytes:  int64(maximumBytes),
		Now:           func() time.Time { return now },
		Usage:         usedAuthorizationSet{},
	}
}
