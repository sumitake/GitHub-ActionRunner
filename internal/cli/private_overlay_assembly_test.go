//go:build darwin || linux

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// assemblyFixture writes a template and a release manifest into a fresh
// private root and returns the template, manifest, and output paths.
func assemblyFixture(
	t *testing.T,
	mutate func(map[string]any),
) (string, string, string) {
	t.Helper()
	root := privateOverlayTestRoot(t)
	raw, err := os.ReadFile("testdata/private-overlay-template.json")
	if err != nil {
		t.Fatalf("ReadFile(template) error = %v", err)
	}
	var template map[string]any
	if err := json.Unmarshal(raw, &template); err != nil {
		t.Fatalf("Unmarshal(template) error = %v", err)
	}
	transport := template["management_transport"].(map[string]any)
	transport["known_hosts_file"] = filepath.Join(root, "ssh", "known_hosts")
	for _, entry := range template["secrets"].([]any) {
		secret := entry.(map[string]any)
		if secret["name"] == transport["credential_name"] {
			secret["ref"].(map[string]any)["ref"] = filepath.Join(root, "ssh", "id_ed25519")
		}
	}
	if mutate != nil {
		mutate(template)
	}
	document, err := json.Marshal(template)
	if err != nil {
		t.Fatalf("Marshal(template) error = %v", err)
	}
	templatePath := filepath.Join(root, "template.json")
	privateOverlayTestFile(t, templatePath, document)

	manifest, _, err := hostruntime.MarshalRuntimeManifest(cliTestManifest())
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	manifestPath := filepath.Join(root, "runtime-manifest.json")
	privateOverlayTestFile(t, manifestPath, manifest)
	return templatePath, manifestPath, filepath.Join(root, "controller-runtime.json")
}

func assemblyArgs(template, manifest, output string) []string {
	return []string{
		"assemble-private-overlay",
		"--template", template,
		"--manifest", manifest,
		"--output", output,
	}
}

func TestRunPrivateOverlayAssemblyWritesDeployableOverlay(t *testing.T) {
	t.Parallel()
	templatePath, manifestPath, outputPath := assemblyFixture(t, nil)

	receipt, err := RunPrivateOverlayAssembly(
		assemblyArgs(templatePath, manifestPath, outputPath),
	)
	if err != nil {
		t.Fatalf("RunPrivateOverlayAssembly() error = %v", err)
	}
	_, _, manifestDigest, err := LoadRuntimeManifestFile(manifestPath)
	if err != nil {
		t.Fatalf("LoadRuntimeManifestFile() error = %v", err)
	}
	if receipt.SchemaVersion != 1 || receipt.RuntimeManifestDigest != manifestDigest {
		t.Fatalf("receipt = %+v, want schema 1 and manifest %s", receipt, manifestDigest)
	}
	overlay, revision, err := LoadPrivateOverlayFile(outputPath)
	if err != nil {
		t.Fatalf("LoadPrivateOverlayFile(output) error = %v", err)
	}
	if revision != receipt.PrivateOverlayRevision {
		t.Fatalf("revision = %s, receipt %s", revision, receipt.PrivateOverlayRevision)
	}
	manifest := cliTestManifest()
	if overlay.Manifest.Path != manifestPath ||
		overlay.Manifest.Digest != manifestDigest ||
		overlay.Policy.ManifestDigest != manifest.PolicyManifestDigest ||
		overlay.Docker.RunnerImage != manifest.RunnerImageDigest ||
		overlay.Docker.VerifierImage != manifest.VerifierImageDigest {
		t.Fatalf("release identities not bound: %+v %+v", overlay.Manifest, overlay.Docker)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Stat(output) error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %v, want 0600", info.Mode().Perm())
	}

	again, err := RunPrivateOverlayAssembly(
		assemblyArgs(templatePath, manifestPath, outputPath),
	)
	if err != nil || again != receipt {
		t.Fatalf("re-assembly = %+v, %v; want identical receipt", again, err)
	}
	entries, err := os.ReadDir(filepath.Dir(outputPath))
	if err != nil {
		t.Fatalf("ReadDir(root) error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestRunPrivateOverlayAssemblyRejectsBadTemplatesWithoutOutput(t *testing.T) {
	t.Parallel()
	tests := map[string]func(map[string]any){
		"unknown field": func(template map[string]any) {
			template["unexpected"] = true
		},
		"conflicting runner image": func(template map[string]any) {
			template["docker"].(map[string]any)["runner_image"] =
				"sha256:" + strings.Repeat("0", 64)
		},
		"conflicting manifest digest": func(template map[string]any) {
			template["manifest"].(map[string]any)["digest"] = strings.Repeat("0", 64)
		},
		"incomplete target identity": func(template map[string]any) {
			template["target"].(map[string]any)["host_identity_digest"] = ""
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			templatePath, manifestPath, outputPath := assemblyFixture(t, mutate)
			_, err := RunPrivateOverlayAssembly(
				assemblyArgs(templatePath, manifestPath, outputPath),
			)
			if !errors.Is(err, ErrHostCommandFailed) {
				t.Fatalf("error = %v, want %v", err, ErrHostCommandFailed)
			}
			if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
				t.Fatalf("output exists after failure: %v", statErr)
			}
		})
	}
}

func TestRunPrivateOverlayAssemblyRejectsTrailingTemplateData(t *testing.T) {
	t.Parallel()
	templatePath, manifestPath, outputPath := assemblyFixture(t, nil)
	document, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("ReadFile(template) error = %v", err)
	}
	privateOverlayTestFile(t, templatePath, append(document, []byte(" {}")...))
	if _, err := RunPrivateOverlayAssembly(
		assemblyArgs(templatePath, manifestPath, outputPath),
	); !errors.Is(err, ErrHostCommandFailed) {
		t.Fatalf("error = %v, want %v", err, ErrHostCommandFailed)
	}
}

func TestRunPrivateOverlayAssemblyAcceptsOnlyExactGrammar(t *testing.T) {
	t.Parallel()
	valid := assemblyArgs("/p/template.json", "/p/manifest.json", "/p/out.json")
	for name, args := range map[string][]string{
		"empty":              nil,
		"wrong command":      append([]string{"assemble"}, valid[1:]...),
		"missing output":     valid[:5],
		"extra argument":     append(append([]string(nil), valid...), "--force"),
		"flag order":         {valid[0], valid[3], valid[4], valid[1], valid[2], valid[5], valid[6]},
		"relative template":  assemblyArgs("template.json", "/p/manifest.json", "/p/out.json"),
		"unclean output":     assemblyArgs("/p/template.json", "/p/manifest.json", "/p/../out.json"),
		"output is template": assemblyArgs("/p/template.json", "/p/manifest.json", "/p/template.json"),
		"output is manifest": assemblyArgs("/p/template.json", "/p/manifest.json", "/p/manifest.json"),
	} {
		if _, err := RunPrivateOverlayAssembly(args); !errors.Is(err, ErrHostUsage) {
			t.Errorf("%s: error = %v, want %v", name, err, ErrHostUsage)
		}
	}
}
