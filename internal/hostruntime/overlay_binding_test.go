package hostruntime

import (
	"errors"
	"strings"
	"testing"
)

const boundManifestPath = "/opt/portable/release/runtime-manifest.json"

// bindingManifest returns a valid manifest whose release identities differ
// from every release-derived value in goldenPrivateOverlay.
func bindingManifest() RuntimeManifest {
	return RuntimeManifest{
		SchemaVersion:         runtimeManifestSchemaVersion,
		BuildID:               strings.Repeat("1", 64),
		ControllerSHA256:      strings.Repeat("2", 64),
		RunnerImageDigest:     "sha256:" + strings.Repeat("a", 64),
		AdapterImageDigest:    "sha256:" + strings.Repeat("b", 64),
		BrokerImageDigest:     "sha256:" + strings.Repeat("c", 64),
		HelperImageDigest:     "sha256:" + strings.Repeat("d", 64),
		VerifierImageDigest:   "sha256:" + strings.Repeat("e", 64),
		TrustBundleDigest:     strings.Repeat("3", 64),
		SeccompProfileDigest:  strings.Repeat("4", 64),
		EgressMode:            runtimeManifestEgressMode,
		PolicyManifestDigest:  strings.Repeat("f", 64),
		ConntrackBudgetDigest: strings.Repeat("5", 64),
		StorageBudgetDigest:   strings.Repeat("6", 64),
		LogPolicyDigest:       strings.Repeat("7", 64),
		AcquisitionDefault:    runtimeManifestAcquisition,
		FleetGeneration:       1,
	}
}

// bindingTemplate returns the golden overlay with every release-derived
// field cleared, the shape an operator authors.
func bindingTemplate() PrivateOverlay {
	template := goldenPrivateOverlay()
	template.Manifest.Path = ""
	template.Manifest.Digest = ""
	template.Policy.ManifestDigest = ""
	template.Docker.RunnerImage = ""
	template.Docker.AdapterImage = ""
	template.Docker.BrokerImage = ""
	template.Docker.HelperImage = ""
	template.Docker.VerifierImage = ""
	return template
}

func TestBindRuntimeManifestCopiesEveryReleaseIdentity(t *testing.T) {
	manifest := bindingManifest()
	bound, err := BindRuntimeManifest(bindingTemplate(), manifest, boundManifestPath)
	if err != nil {
		t.Fatalf("BindRuntimeManifest() error = %v", err)
	}
	_, manifestDigest, err := MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	for name, pair := range map[string][2]string{
		"manifest path":   {bound.Manifest.Path, boundManifestPath},
		"manifest digest": {bound.Manifest.Digest, manifestDigest},
		"policy digest":   {bound.Policy.ManifestDigest, manifest.PolicyManifestDigest},
		"runner image":    {bound.Docker.RunnerImage, manifest.RunnerImageDigest},
		"adapter image":   {bound.Docker.AdapterImage, manifest.AdapterImageDigest},
		"broker image":    {bound.Docker.BrokerImage, manifest.BrokerImageDigest},
		"helper image":    {bound.Docker.HelperImage, manifest.HelperImageDigest},
		"verifier image":  {bound.Docker.VerifierImage, manifest.VerifierImageDigest},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
	if _, _, err := MarshalPrivateOverlay(bound); err != nil {
		t.Fatalf("MarshalPrivateOverlay(bound) error = %v", err)
	}
}

func TestBindRuntimeManifestIsIdempotent(t *testing.T) {
	manifest := bindingManifest()
	first, err := BindRuntimeManifest(bindingTemplate(), manifest, boundManifestPath)
	if err != nil {
		t.Fatalf("first bind error = %v", err)
	}
	second, err := BindRuntimeManifest(first, manifest, boundManifestPath)
	if err != nil {
		t.Fatalf("second bind error = %v", err)
	}
	firstDocument, firstRevision, err := MarshalPrivateOverlay(first)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay(first) error = %v", err)
	}
	secondDocument, secondRevision, err := MarshalPrivateOverlay(second)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay(second) error = %v", err)
	}
	if string(firstDocument) != string(secondDocument) || firstRevision != secondRevision {
		t.Fatal("re-binding changed the overlay")
	}
}

func TestBindRuntimeManifestRejectsConflictingTemplateValues(t *testing.T) {
	tests := map[string]func(*PrivateOverlay){
		"manifest path": func(o *PrivateOverlay) {
			o.Manifest.Path = "/opt/portable/other.json"
		},
		"manifest digest": func(o *PrivateOverlay) {
			o.Manifest.Digest = strings.Repeat("0", 64)
		},
		"policy digest": func(o *PrivateOverlay) {
			o.Policy.ManifestDigest = strings.Repeat("0", 64)
		},
		"runner image": func(o *PrivateOverlay) {
			o.Docker.RunnerImage = "sha256:" + strings.Repeat("0", 64)
		},
		"adapter image": func(o *PrivateOverlay) {
			o.Docker.AdapterImage = "sha256:" + strings.Repeat("0", 64)
		},
		"broker image": func(o *PrivateOverlay) {
			o.Docker.BrokerImage = "sha256:" + strings.Repeat("0", 64)
		},
		"helper image": func(o *PrivateOverlay) {
			o.Docker.HelperImage = "sha256:" + strings.Repeat("0", 64)
		},
		"verifier image": func(o *PrivateOverlay) {
			o.Docker.VerifierImage = "sha256:" + strings.Repeat("0", 64)
		},
		"repository-qualified runner image": func(o *PrivateOverlay) {
			o.Docker.RunnerImage = "example.invalid/runner@sha256:" + strings.Repeat("a", 64)
		},
		"egress mode": func(o *PrivateOverlay) {
			o.Docker.BrokerNetworkID = "bridge"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			template := bindingTemplate()
			mutate(&template)
			_, err := BindRuntimeManifest(template, bindingManifest(), boundManifestPath)
			if !errors.Is(err, ErrOverlayManifestConflict) {
				t.Fatalf("BindRuntimeManifest() error = %v, want %v", err, ErrOverlayManifestConflict)
			}
		})
	}
}

func TestBindRuntimeManifestRejectsInvalidInputs(t *testing.T) {
	invalidManifest := bindingManifest()
	invalidManifest.FleetGeneration = 0
	if _, err := BindRuntimeManifest(bindingTemplate(), invalidManifest, boundManifestPath); !errors.Is(err, ErrInvalidRuntimeManifest) {
		t.Fatalf("invalid manifest error = %v, want %v", err, ErrInvalidRuntimeManifest)
	}
	if _, err := BindRuntimeManifest(bindingTemplate(), bindingManifest(), "relative/manifest.json"); !errors.Is(err, ErrInvalidPrivateOverlay) {
		t.Fatalf("relative manifest path error = %v, want %v", err, ErrInvalidPrivateOverlay)
	}
	incomplete := bindingTemplate()
	incomplete.Target.HostIdentityDigest = ""
	if _, err := BindRuntimeManifest(incomplete, bindingManifest(), boundManifestPath); !errors.Is(err, ErrInvalidPrivateOverlay) {
		t.Fatalf("incomplete template error = %v, want %v", err, ErrInvalidPrivateOverlay)
	}
}
