//go:build darwin || linux

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestRuntimeManifestAssemblyRejectsAmbiguousKeys(t *testing.T) {
	image := `"sha256:` + strings.Repeat("b", 64) + `"`
	for name, extra := range map[string]string{
		"duplicate image":      `"runner_image_digest":` + image,
		"escaped duplicate":    `"runner_\u0069mage_digest":` + image,
		"case alias":           `"Runner_Image_Digest":` + image,
		"escaped case alias":   `"\u0052unner_Image_Digest":` + image,
		"unicode case alias":   `"runner_image_digeſt":` + image,
		"duplicate generation": `"fleet_generation":8`,
		"duplicate null":       `"archive_manifest_digest":null`,
		"identical duplicate":  `"schema_version":1`,
	} {
		t.Run(name, func(t *testing.T) {
			input, output := manifestAssemblyFixture(t)
			document, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			// Both orders must be refused, even when the original value wins.
			for _, first := range []bool{false, true} {
				ambiguous := append([]byte(nil), document...)
				if first {
					ambiguous = bytes.Replace(ambiguous, []byte("{"), []byte("{"+extra+","), 1)
				} else {
					ambiguous = bytes.Replace(ambiguous, []byte("\n}"), []byte(","+extra+"\n}"), 1)
				}
				privateOverlayTestFile(t, input, ambiguous)
				privateOverlayTestFile(t, output, []byte("existing-output"))
				if _, err := RunRuntimeManifestAssembly(manifestAssemblyArgs(input, "8", output)); !errors.Is(err, ErrHostCommandFailed) {
					t.Fatalf("ambiguous template accepted (extra first=%v): %v", first, err)
				}
				if raw, err := os.ReadFile(output); err != nil || string(raw) != "existing-output" {
					t.Fatal("rejected template changed output")
				}
			}
		})
	}
}

func TestRuntimeManifestAssemblyRequiresExactFieldNames(t *testing.T) {
	input, output := manifestAssemblyFixture(t)
	document, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		t.Run(key, func(t *testing.T) {
			aliased := bytes.Replace(document, []byte(`"`+key+`"`), []byte(`"`+strings.ToUpper(key)+`"`), 1)
			privateOverlayTestFile(t, input, aliased)
			if _, err := RunRuntimeManifestAssembly(manifestAssemblyArgs(input, "8", output)); !errors.Is(err, ErrHostCommandFailed) {
				t.Fatalf("case-only field name accepted: %v", err)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected template created output: %v", err)
			}
		})
	}
}

func TestRuntimeManifestAssemblyPreservesUnambiguousTemplateEncoding(t *testing.T) {
	input, output := manifestAssemblyFixture(t)
	want := cliTestManifest()
	want.FleetGeneration = 0
	archive := strings.Repeat("c", 64)
	want.ArchiveManifestDigest = &archive
	document, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatal(err)
	}
	// Map marshaling changes field order; whitespace and escaped exact names
	// are valid in an identity template, even though the output is canonical.
	document, err = json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	document = bytes.Replace(document, []byte(`"runner_image_digest"`), []byte(`"runner_\u0069mage_digest"`), 1)
	privateOverlayTestFile(t, input, document)
	if _, err := RunRuntimeManifestAssembly(manifestAssemblyArgs(input, "8", output)); err != nil {
		t.Fatal(err)
	}
	want.FleetGeneration = 8
	wantDocument, wantDigest, err := hostruntime.MarshalRuntimeManifest(want)
	if err != nil {
		t.Fatal(err)
	}
	_, gotDocument, gotDigest, err := LoadRuntimeManifestFile(output)
	if err != nil || !bytes.Equal(gotDocument, wantDocument) || gotDigest != wantDigest {
		t.Fatal("unambiguous template changed identity or failed canonicalization")
	}
}
