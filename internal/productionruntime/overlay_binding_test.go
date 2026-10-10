package productionruntime

import (
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// TestBoundOverlaySatisfiesTargetManifestMatch proves that an overlay built by
// hostruntime.BindRuntimeManifest passes the same check the target applies
// before it accepts a release, for a manifest whose identities all differ
// from the template's.
func TestBoundOverlaySatisfiesTargetManifestMatch(t *testing.T) {
	template, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	manifest.RunnerImageDigest = "sha256:" + strings.Repeat("e", 64)
	manifest.PolicyManifestDigest = strings.Repeat("f", 64)
	if runtimeManifestMatchesOverlay(manifest, template) {
		t.Fatal("fixture overlay already matches the manifest; test proves nothing")
	}
	template.Manifest.Path = ""
	template.Manifest.Digest = ""
	template.Policy.ManifestDigest = ""
	template.Docker.RunnerImage = ""
	template.Docker.AdapterImage = ""
	template.Docker.BrokerImage = ""
	template.Docker.HelperImage = ""
	template.Docker.VerifierImage = ""
	bound, err := hostruntime.BindRuntimeManifest(
		template,
		manifest,
		"/opt/portable/release/runtime-manifest.json",
	)
	if err != nil {
		t.Fatalf("BindRuntimeManifest() error = %v", err)
	}
	if !runtimeManifestMatchesOverlay(manifest, bound) {
		t.Fatal("bound overlay does not satisfy the target manifest match")
	}
}
