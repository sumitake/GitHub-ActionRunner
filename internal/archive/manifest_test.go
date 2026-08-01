package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestLoadAcceptsCanonicalFirstPartyManifest(t *testing.T) {
	manifest := mustLoadManifest(t, validManifestJSON())
	if manifest.SchemaVersion != 1 || len(manifest.Seeds) != 1 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if manifest.Seeds[0].ID != "actions-checkout" || manifest.Seeds[0].Kind != KindAction {
		t.Fatalf("seed = %+v", manifest.Seeds[0])
	}
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	if string(encoded) != validManifestJSON()+"\n" {
		t.Fatalf("canonical manifest = %q", encoded)
	}
}

func TestLoadRejectsDuplicateOrUnknownJSONFields(t *testing.T) {
	valid := validManifestJSON()
	tests := map[string]string{
		"duplicate root key":   strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"duplicate nested key": strings.Replace(valid, `"id":"actions-checkout"`, `"id":"actions-checkout","id":"other"`, 1),
		"unknown root key":     strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"unknown":true`, 1),
		"unknown file key":     strings.Replace(valid, `"mode":292`, `"mode":292,"unknown":true`, 1),
		"trailing object":      valid + `{}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(document)); err == nil {
				t.Fatal("Load accepted non-closed JSON")
			}
		})
	}
}

func TestLoadRejectsURLParserDivergenceAndMutableRevisions(t *testing.T) {
	commit := strings.Repeat("a", 40)
	canonical := "https://github.com/actions/checkout/archive/" + commit + ".tar.gz"
	tests := map[string]string{
		"uppercase host":     "https://GitHub.com/actions/checkout/archive/" + commit + ".tar.gz",
		"userinfo":           "https://user@github.com/actions/checkout/archive/" + commit + ".tar.gz",
		"port":               "https://github.com:443/actions/checkout/archive/" + commit + ".tar.gz",
		"query":              canonical + "?download=1",
		"fragment":           canonical + "#x",
		"trailing host dot":  "https://github.com./actions/checkout/archive/" + commit + ".tar.gz",
		"escaped separator":  "https://github.com/actions%2fcheckout/archive/" + commit + ".tar.gz",
		"dot segment":        "https://github.com/actions/../evil/archive/" + commit + ".tar.gz",
		"wrong organization": "https://github.com/other/checkout/archive/" + commit + ".tar.gz",
		"mutable revision":   "https://github.com/actions/checkout/archive/main.tar.gz",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			document := strings.Replace(validManifestJSON(), canonical, source, 1)
			if name == "mutable revision" {
				document = strings.Replace(document, commit, "main", 1)
			}
			if _, err := Load(strings.NewReader(document)); err == nil {
				t.Fatal("Load accepted divergent source or mutable revision")
			}
		})
	}
}

func TestLoadRejectsPathAndCaseFoldCollisions(t *testing.T) {
	valid := validManifestJSON()
	tests := map[string]string{
		"traversal":       strings.Replace(valid, `"path":"checkout/action.yml"`, `"path":"../action.yml"`, 1),
		"absolute":        strings.Replace(valid, `"path":"checkout/action.yml"`, `"path":"/action.yml"`, 1),
		"backslash":       strings.Replace(valid, `"path":"checkout/action.yml"`, `"path":"checkout\\action.yml"`, 1),
		"wrong target":    strings.Replace(valid, `"target":"actions/checkout/`, `"target":"tools/checkout/`, 1),
		"unknown license": strings.Replace(valid, `"spdx":"MIT"`, `"spdx":"LicenseRef-Unknown"`, 1),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(document)); err == nil {
				t.Fatal("Load accepted invalid path or policy")
			}
		})
	}

	duplicate := strings.Replace(valid, `]}`, `,{"path":"checkout/ACTION.yml","target":"actions/checkout/`+strings.Repeat("a", 40)+`/ACTION.yml","sha256":"`+digestString("action")+`","size":6,"mode":292}]}`, 1)
	if _, err := Load(strings.NewReader(duplicate)); err == nil {
		t.Fatal("Load accepted case-fold file/target collision")
	}
}

func validManifestJSON() string {
	commit := strings.Repeat("a", 40)
	actionDigest := digestString("action")
	licenseDigest := digestString("license")
	return fmt.Sprintf(`{"schema_version":1,"seeds":[{"id":"actions-checkout","kind":"action","source":"https://github.com/actions/checkout/archive/%s.tar.gz","revision":"%s","license":{"spdx":"MIT","path":"checkout/LICENSE","size":7,"sha256":"%s"},"files":[{"path":"checkout/LICENSE","target":"actions/checkout/%s/LICENSE","sha256":"%s","size":7,"mode":292},{"path":"checkout/action.yml","target":"actions/checkout/%s/action.yml","sha256":"%s","size":6,"mode":292}]}]}`, commit, commit, licenseDigest, commit, licenseDigest, commit, actionDigest)
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
