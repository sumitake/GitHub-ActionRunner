package hostruntime

import (
	"errors"
	"strings"
	"testing"
)

var validRuntimeManifestJSON = `{"schema_version":1,"build_id":"` +
	strings.Repeat("a", 64) +
	`","controller_sha256":"` + strings.Repeat("b", 64) +
	`","runner_image_digest":"sha256:` + strings.Repeat("c", 64) +
	`","adapter_image_digest":"sha256:` + strings.Repeat("d", 64) +
	`","broker_image_digest":"sha256:` + strings.Repeat("e", 64) +
	`","helper_image_digest":"sha256:` + strings.Repeat("f", 64) +
	`","verifier_image_digest":"sha256:` + strings.Repeat("1", 64) +
	`","trust_bundle_digest":"` + strings.Repeat("2", 64) +
	`","seccomp_profile_digest":"` + strings.Repeat("3", 64) +
	`","egress_mode":"restricted-broker-v1","policy_manifest_digest":"` +
	strings.Repeat("4", 64) +
	`","conntrack_budget_digest":"` + strings.Repeat("5", 64) +
	`","storage_budget_digest":"` + strings.Repeat("6", 64) +
	`","log_policy_digest":"` + strings.Repeat("7", 64) +
	`","archive_manifest_digest":null,"acquisition_default":"disabled","fleet_generation":7}`

const validRuntimeManifestDigest = "8332243a6441b2b7b35d898a13f92dafee87167e182f2fb20df0b185ac2fedbc"

func TestParseRuntimeManifestGolden(t *testing.T) {
	t.Parallel()

	manifest, digest, err := ParseRuntimeManifest(
		[]byte(validRuntimeManifestJSON),
		len(validRuntimeManifestJSON),
	)
	if err != nil {
		t.Fatalf("ParseRuntimeManifest() error = %v", err)
	}
	if manifest.SchemaVersion != 1 ||
		manifest.BuildID != strings.Repeat("a", 64) ||
		manifest.FleetGeneration != 7 ||
		manifest.ArchiveManifestDigest != nil {
		t.Fatalf("ParseRuntimeManifest() manifest = %#v", manifest)
	}
	if digest != validRuntimeManifestDigest {
		t.Fatalf("ParseRuntimeManifest() digest = %q, want %q", digest, validRuntimeManifestDigest)
	}

	encoded, encodedDigest, err := MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	if string(encoded) != validRuntimeManifestJSON {
		t.Fatalf("MarshalRuntimeManifest() = %q", encoded)
	}
	if encodedDigest != validRuntimeManifestDigest {
		t.Fatalf("MarshalRuntimeManifest() digest = %q, want %q", encodedDigest, validRuntimeManifestDigest)
	}
}

func TestParseRuntimeManifestRejectsNoncanonicalOrInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty":                "",
		"leading whitespace":   " " + validRuntimeManifestJSON,
		"trailing newline":     validRuntimeManifestJSON + "\n",
		"duplicate field":      strings.Replace(validRuntimeManifestJSON, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"unknown field":        strings.TrimSuffix(validRuntimeManifestJSON, "}") + `,"unknown":1}`,
		"missing field":        strings.Replace(validRuntimeManifestJSON, `"build_id":"`+strings.Repeat("a", 64)+`",`, "", 1),
		"wrong field order":    strings.Replace(validRuntimeManifestJSON, `{"schema_version":1,"build_id":`, `{"build_id":`, 1),
		"uppercase digest":     strings.Replace(validRuntimeManifestJSON, strings.Repeat("b", 64), "B"+strings.Repeat("b", 63), 1),
		"tagless image digest": strings.Replace(validRuntimeManifestJSON, "sha256:"+strings.Repeat("c", 64), strings.Repeat("c", 64), 1),
		"wrong egress":         strings.Replace(validRuntimeManifestJSON, "restricted-broker-v1", "direct", 1),
		"enabled acquisition":  strings.Replace(validRuntimeManifestJSON, `"acquisition_default":"disabled"`, `"acquisition_default":"enabled"`, 1),
		"zero generation":      strings.Replace(validRuntimeManifestJSON, `"fleet_generation":7`, `"fleet_generation":0`, 1),
		"archive empty":        strings.Replace(validRuntimeManifestJSON, `"archive_manifest_digest":null`, `"archive_manifest_digest":""`, 1),
	}

	for name, document := range tests {
		name, document := name, document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParseRuntimeManifest([]byte(document), len(document)+1); !errors.Is(err, ErrInvalidRuntimeManifest) {
				t.Fatalf("ParseRuntimeManifest() error = %v, want ErrInvalidRuntimeManifest", err)
			}
		})
	}
}

func TestParseRuntimeManifestHonorsByteLimit(t *testing.T) {
	t.Parallel()

	if _, _, err := ParseRuntimeManifest(
		[]byte(validRuntimeManifestJSON),
		len(validRuntimeManifestJSON)-1,
	); !errors.Is(err, ErrInvalidRuntimeManifest) {
		t.Fatalf("ParseRuntimeManifest() error = %v, want ErrInvalidRuntimeManifest", err)
	}
}
