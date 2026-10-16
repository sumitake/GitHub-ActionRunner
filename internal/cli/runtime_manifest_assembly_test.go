//go:build darwin || linux

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func manifestAssemblyFixture(t *testing.T) (string, string) {
	t.Helper()
	root := privateOverlayTestRoot(t)
	template := cliTestManifest()
	template.FleetGeneration = 0
	document, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "identity-template.json")
	privateOverlayTestFile(t, input, document)
	// Separate roots ensure output validation cannot accidentally stand in for
	// validation of the template's private tree.
	return input, filepath.Join(privateOverlayTestRoot(t), "runtime-manifest.json")
}

func manifestAssemblyArgs(input, generation, output string) []string {
	return []string{"assemble-runtime-manifest", "--template", input, "--fleet-generation", generation, "--output", output}
}

func TestRuntimeManifestAssemblyBindsExplicitGeneration(t *testing.T) {
	input, output := manifestAssemblyFixture(t)
	receipt, err := RunRuntimeManifestAssembly(manifestAssemblyArgs(input, "8", output))
	if err != nil {
		t.Fatal(err)
	}
	manifest, document, digest, err := LoadRuntimeManifestFile(output)
	if err != nil {
		t.Fatal(err)
	}
	want := cliTestManifest()
	want.FleetGeneration = 8
	wantDocument, wantDigest, err := hostruntime.MarshalRuntimeManifest(want)
	if err != nil {
		t.Fatal(err)
	}
	if manifest != want || !bytes.Equal(document, wantDocument) || digest != wantDigest || receipt.RuntimeManifestDigest != wantDigest || receipt.FleetGeneration != 8 || receipt.SchemaVersion != 1 {
		t.Fatalf("assembly changed identities or failed to bind generation: %+v", receipt)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode: %v, %v", info, err)
	}
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := RunRuntimeManifestAssembly(manifestAssemblyArgs(input, "8", output))
	if err != nil || again != receipt {
		t.Fatalf("idempotent assembly: %+v, %v", again, err)
	}
	after, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("template changed")
	}
}

func TestRuntimeManifestAssemblyRejectsInvalidInputWithoutChangingOutput(t *testing.T) {
	for name, mutate := range map[string]func(string, string) []string{
		"zero":              func(i, o string) []string { return manifestAssemblyArgs(i, "0", o) },
		"overflow":          func(i, o string) []string { return manifestAssemblyArgs(i, "18446744073709551616", o) },
		"negative":          func(i, o string) []string { return manifestAssemblyArgs(i, "-1", o) },
		"extra argument":    func(i, o string) []string { return append(manifestAssemblyArgs(i, "8", o), "extra") },
		"missing arguments": func(_, _ string) []string { return nil },
		"bad command":       func(i, o string) []string { args := manifestAssemblyArgs(i, "8", o); args[0] = "other"; return args },
		"bad template flag": func(i, o string) []string { args := manifestAssemblyArgs(i, "8", o); args[1] = "--input"; return args },
		"bad output flag":   func(i, o string) []string { args := manifestAssemblyArgs(i, "8", o); args[5] = "--other"; return args },
		"same path":         func(i, _ string) []string { return manifestAssemblyArgs(i, "8", i) },
		"relative output":   func(i, _ string) []string { return manifestAssemblyArgs(i, "8", "relative.json") },
		"bad flag": func(i, o string) []string {
			args := manifestAssemblyArgs(i, "8", o)
			args[3] = "--generation"
			return args
		},
		"symlink input": func(i, o string) []string {
			link := i + ".link"
			if err := os.Symlink(i, link); err != nil {
				t.Fatal(err)
			}
			return manifestAssemblyArgs(link, "8", o)
		},
		"permissive template": func(i, o string) []string {
			if err := os.Chmod(i, 0o644); err != nil {
				t.Fatal(err)
			}
			return manifestAssemblyArgs(i, "8", o)
		},
		"invalid identity": func(i, o string) []string {
			privateOverlayTestFile(t, i, []byte(`{"schema_version":1}`))
			return manifestAssemblyArgs(i, "8", o)
		},
		"unknown field": func(i, o string) []string {
			raw, _ := os.ReadFile(i)
			raw = bytes.Replace(raw, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "unknown": true`), 1)
			privateOverlayTestFile(t, i, raw)
			return manifestAssemblyArgs(i, "8", o)
		},
		"trailing document": func(i, o string) []string {
			raw, _ := os.ReadFile(i)
			privateOverlayTestFile(t, i, append(raw, []byte(`{}`)...))
			return manifestAssemblyArgs(i, "8", o)
		},
		"conflicting generation": func(i, o string) []string {
			raw, _ := os.ReadFile(i)
			raw = bytes.Replace(raw, []byte(`"fleet_generation": 0`), []byte(`"fleet_generation": 9`), 1)
			privateOverlayTestFile(t, i, raw)
			return manifestAssemblyArgs(i, "8", o)
		},
		"nonprivate output directory": func(i, o string) []string {
			dir := filepath.Join(filepath.Dir(o), "nonprivate")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			return manifestAssemblyArgs(i, "8", filepath.Join(dir, "output.json"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			input, output := manifestAssemblyFixture(t)
			privateOverlayTestFile(t, output, []byte("existing-output"))
			args := mutate(input, output)
			_, err := RunRuntimeManifestAssembly(args)
			if err == nil {
				t.Fatal("invalid assembly accepted")
			}
			if !errors.Is(err, ErrHostUsage) && !errors.Is(err, ErrHostCommandFailed) {
				t.Fatalf("open error: %v", err)
			}
			raw, err := os.ReadFile(output)
			if err != nil || string(raw) != "existing-output" {
				t.Fatal("failed assembly changed output")
			}
		})
	}
}
