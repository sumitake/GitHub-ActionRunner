package networkjail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestCABundleLockStrictlyBindsGeneratedInput(t *testing.T) {
	bundle := []byte("synthetic trust bundle\n")
	digest := sha256.Sum256(bundle)
	document := `{
  "schema_version": 1,
  "source_url": "https://example.com/cacert.pem",
  "source_revision": "2026-07-16",
  "sha256": "` + hex.EncodeToString(digest[:]) + `",
  "license_spdx": "MPL-2.0",
  "copied_path": "/etc/ssl/certs/ca-bundle.crt",
  "context_path": "images/trust/build/ca-bundle.pem",
  "sbom_path": "images/trust/ca-bundle.spdx.json"
}
`
	lock, err := LoadCABundleLock(strings.NewReader(document))
	if err != nil {
		t.Fatalf("LoadCABundleLock error = %v", err)
	}
	if err := lock.Verify(bytes.NewReader(bundle)); err != nil {
		t.Fatalf("Verify(valid) error = %v", err)
	}
	if err := lock.Verify(strings.NewReader("changed")); err == nil {
		t.Fatal("Verify accepted digest mismatch")
	}
}

func TestCABundleLockRejectsUnknownMissingOrTrailingData(t *testing.T) {
	base := `{
  "schema_version": 1,
  "source_url": "https://example.com/cacert.pem",
  "source_revision": "2026-07-16",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "license_spdx": "MPL-2.0",
  "copied_path": "/etc/ssl/certs/ca-bundle.crt",
  "context_path": "images/trust/build/ca-bundle.pem",
  "sbom_path": "images/trust/ca-bundle.spdx.json"
}`
	tests := []string{
		strings.Replace(base, `"schema_version": 1`, `"schema_version": 2`, 1),
		strings.Replace(base, `"source_revision": "2026-07-16",`, "", 1),
		strings.Replace(base, `"source_revision": "2026-07-16"`, `"source_revision": "2026-7-16"`, 1),
		strings.Replace(base, `"license_spdx": "MPL-2.0"`, `"license_spdx": "unknown"`, 1),
		strings.Replace(base, `"copied_path": "/etc/ssl/certs/ca-bundle.crt"`, `"copied_path": "../escape"`, 1),
		strings.Replace(base, `"sbom_path": "images/trust/ca-bundle.spdx.json"`, `"sbom_path": "other"`, 1),
		strings.Replace(base, `"schema_version": 1`, `"schema_version": 1, "unknown": true`, 1),
		base + `{}`,
	}
	for index, document := range tests {
		if _, err := LoadCABundleLock(strings.NewReader(document)); err == nil {
			t.Fatalf("case %d LoadCABundleLock accepted invalid document", index)
		}
	}
}

func TestCommittedCABundleLockMatchesReviewedCurlRevision(t *testing.T) {
	file, err := os.Open("../../images/trust/ca-bundle.lock.json")
	if err != nil {
		t.Fatalf("open committed CA lock: %v", err)
	}
	defer file.Close()
	lock, err := LoadCABundleLock(file)
	if err != nil {
		t.Fatalf("LoadCABundleLock(committed): %v", err)
	}
	if lock.SourceURL != "https://curl.se/ca/cacert-2026-07-16.pem" ||
		lock.SourceRevision != "2026-07-16" ||
		lock.SHA256 != "3ff344e30b9b1ed2971044eabb438a08f2e2245ddb5f8ab1a3ad8b63ab4eaf91" {
		t.Fatalf("committed CA lock drifted: %+v", lock)
	}
}
