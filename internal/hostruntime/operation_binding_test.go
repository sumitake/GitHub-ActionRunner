package hostruntime

import (
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	goldenOperationID      = "0a473c1d939f346b0f6dabd7123b32facf56643d464171cc3e806b24260e6ee8"
	goldenOperationBinding = `{"schema_version":1,"operation_id":"0a473c1d939f346b0f6dabd7123b32facf56643d464171cc3e806b24260e6ee8","kind":"install","install_disposition":"upgrade-portable","expected_generation":41,"prior_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_manifest_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","target_fleet":"portable","private_overlay_revision":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`
	goldenBindingDigest    = "674e872a38185790ee01b46816ed68073994aa045e3eef953f2ff880404ab448"
)

func TestOperationBindingGolden(t *testing.T) {
	t.Parallel()

	prior := strings.Repeat("a", 64)
	target := strings.Repeat("b", 64)
	disposition := InstallDispositionUpgradePortable
	operationID, err := DeriveOperationID(
		OperationKindInstall,
		&disposition,
		41,
		&prior,
		&target,
		fleetfence.FleetPortable,
		strings.Repeat("c", 64),
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	if operationID != goldenOperationID {
		t.Fatalf("DeriveOperationID() = %q, want %q", operationID, goldenOperationID)
	}
	binding := OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     41,
		PriorManifestDigest:    &prior,
		TargetManifestDigest:   &target,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: strings.Repeat("c", 64),
	}
	encoded, digest, err := MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	if string(encoded) != goldenOperationBinding {
		t.Fatalf("MarshalOperationBinding() = %q", encoded)
	}
	if digest != goldenBindingDigest {
		t.Fatalf("MarshalOperationBinding() digest = %q, want %q", digest, goldenBindingDigest)
	}

	decoded, decodedDigest, err := ParseOperationBinding(
		[]byte(goldenOperationBinding),
		len(goldenOperationBinding),
	)
	if err != nil {
		t.Fatalf("ParseOperationBinding() error = %v", err)
	}
	if decoded.OperationID != operationID ||
		decoded.InstallDisposition == nil ||
		*decoded.InstallDisposition != disposition {
		t.Fatalf("ParseOperationBinding() = %#v", decoded)
	}
	if decodedDigest != goldenBindingDigest {
		t.Fatalf("ParseOperationBinding() digest = %q, want %q", decodedDigest, goldenBindingDigest)
	}
}

func TestOperationIDBindsInstallDispositionAndNil(t *testing.T) {
	t.Parallel()

	prior := strings.Repeat("a", 64)
	target := strings.Repeat("b", 64)
	overlay := strings.Repeat("c", 64)
	upgrade := InstallDispositionUpgradePortable
	greenfield := InstallDispositionGreenfieldPortable

	upgradeID, err := DeriveOperationID(
		OperationKindInstall, &upgrade, 41, &prior, &target,
		fleetfence.FleetPortable, overlay,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID(upgrade) error = %v", err)
	}
	greenfieldID, err := DeriveOperationID(
		OperationKindInstall, &greenfield, 0, nil, &target,
		fleetfence.FleetPortable, overlay,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID(greenfield) error = %v", err)
	}
	if upgradeID == greenfieldID {
		t.Fatal("DeriveOperationID() did not bind disposition/nil digests")
	}
	if _, err := DeriveOperationID(
		OperationKindInstall, nil, 41, &prior, &target,
		fleetfence.FleetPortable, overlay,
	); !errors.Is(err, ErrInvalidOperationBinding) {
		t.Fatalf("DeriveOperationID(install nil disposition) error = %v", err)
	}
	if _, err := DeriveOperationID(
		OperationKindSuspend, &upgrade, 41, &prior, nil,
		fleetfence.FleetNone, overlay,
	); !errors.Is(err, ErrInvalidOperationBinding) {
		t.Fatalf("DeriveOperationID(noninstall disposition) error = %v", err)
	}
}

func TestParseOperationBindingRejectsNoncanonicalOrChangedIdentity(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"leading whitespace": " " + goldenOperationBinding,
		"trailing newline":   goldenOperationBinding + "\n",
		"unknown field":      strings.TrimSuffix(goldenOperationBinding, "}") + `,"unknown":true}`,
		"duplicate field": strings.Replace(
			goldenOperationBinding,
			`"schema_version":1`,
			`"schema_version":1,"schema_version":1`,
			1,
		),
		"changed operation id": strings.Replace(
			goldenOperationBinding,
			goldenOperationID,
			strings.Repeat("0", 64),
			1,
		),
		"missing disposition": strings.Replace(
			goldenOperationBinding,
			`"install_disposition":"upgrade-portable"`,
			`"install_disposition":null`,
			1,
		),
		"uppercase overlay": strings.Replace(
			goldenOperationBinding,
			strings.Repeat("c", 64),
			"C"+strings.Repeat("c", 63),
			1,
		),
		"zero upgrade generation": strings.Replace(
			goldenOperationBinding,
			`"expected_generation":41`,
			`"expected_generation":0`,
			1,
		),
	}
	for name, document := range tests {
		name, document := name, document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParseOperationBinding(
				[]byte(document),
				len(document)+1,
			); !errors.Is(err, ErrInvalidOperationBinding) {
				t.Fatalf("ParseOperationBinding() error = %v", err)
			}
		})
	}
}
