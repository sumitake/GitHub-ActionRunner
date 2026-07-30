package archive

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestSyntheticManifestAcceptsOnlyExactTask11Seed(t *testing.T) {
	t.Parallel()

	manifest := validTask11SyntheticManifest()
	document, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	loaded, err := Load(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	reencoded, err := EncodeManifest(loaded)
	if err != nil || !bytes.Equal(document, reencoded) {
		t.Fatalf("canonical reencode = %q, %v", reencoded, err)
	}
	if len(loaded.Seeds) != 1 ||
		loaded.Seeds[0].Kind != Kind("synthetic") ||
		loaded.Seeds[0].Files[0].Mode != 0o644 {
		t.Fatalf("loaded synthetic manifest = %+v", loaded)
	}
}

func TestSyntheticManifestRejectsEveryTupleSubstitution(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Manifest){
		"id": func(manifest *Manifest) {
			manifest.Seeds[0].ID += "-other"
		},
		"kind": func(manifest *Manifest) {
			manifest.Seeds[0].Kind = KindTool
		},
		"source": func(manifest *Manifest) {
			manifest.Seeds[0].Source = "https://example.com/source"
		},
		"revision": func(manifest *Manifest) {
			manifest.Seeds[0].Revision = "v1"
		},
		"license": func(manifest *Manifest) {
			manifest.Seeds[0].License.SPDX = "MIT"
		},
		"path": func(manifest *Manifest) {
			manifest.Seeds[0].Files[0].Path += ".other"
		},
		"target": func(manifest *Manifest) {
			manifest.Seeds[0].Files[0].Target += ".other"
		},
		"digest": func(manifest *Manifest) {
			manifest.Seeds[0].Files[0].SHA256 =
				strings.Repeat("a", 64)
		},
		"size": func(manifest *Manifest) {
			manifest.Seeds[0].Files[0].Size++
		},
		"mode read-only": func(manifest *Manifest) {
			manifest.Seeds[0].Files[0].Mode = 0o444
		},
		"mode executable": func(manifest *Manifest) {
			manifest.Seeds[0].Files[0].Mode = 0o555
		},
		"second file": func(manifest *Manifest) {
			other := manifest.Seeds[0].Files[0]
			other.Path += ".other"
			other.Target += ".other"
			manifest.Seeds[0].Files = append(
				manifest.Seeds[0].Files,
				other,
			)
		},
		"second synthetic seed": func(manifest *Manifest) {
			other := manifest.Seeds[0]
			other.ID += "-other"
			manifest.Seeds = append(manifest.Seeds, other)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validTask11SyntheticManifest()
			mutate(&manifest)
			if _, err := EncodeManifest(manifest); err == nil {
				t.Fatal("EncodeManifest accepted substituted synthetic seed")
			}
		})
	}
}

func TestSyntheticManifestCannotMixWithProvenanceSeeds(t *testing.T) {
	t.Parallel()

	action := mustLoadManifest(t, validManifestJSON()).Seeds[0]
	synthetic := validTask11SyntheticManifest().Seeds[0]
	manifest := Manifest{
		SchemaVersion: 1,
		Seeds:         []Seed{action, synthetic},
	}
	if _, err := EncodeManifest(manifest); err == nil {
		t.Fatal("EncodeManifest accepted mixed synthetic/action catalog")
	}
}

func TestProvenanceSeedCannotUseSyntheticWritableMode(t *testing.T) {
	t.Parallel()

	document := strings.Replace(
		validManifestJSON(),
		`"mode":292`,
		`"mode":420`,
		1,
	)
	if _, err := Load(strings.NewReader(document)); err == nil {
		t.Fatal("Load accepted mode 0644 on a provenance seed")
	}
}

func validTask11SyntheticManifest() Manifest {
	source := task11synthetic.SeedSourceBytes()
	return Manifest{
		SchemaVersion: 1,
		Seeds: []Seed{
			{
				ID:       task11synthetic.SeedID,
				Kind:     Kind("synthetic"),
				Source:   "",
				Revision: "",
				License:  LicenseEvidence{},
				Files: []File{
					{
						Path:   task11synthetic.SeedSourceRelativePath,
						Target: task11synthetic.SeedTargetPath,
						SHA256: task11synthetic.SeedSourceSHA256,
						Size:   uint64(len(source)),
						Mode:   0o644,
					},
				},
			},
		},
	}
}
