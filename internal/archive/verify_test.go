package archive

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestVerifyReturnsLogicalDigestForExactTree(t *testing.T) {
	manifest := mustLoadManifest(t, validManifestJSON())
	tree := validMapFS()
	digest, err := Verify(tree, manifest)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(digest.Hex()) != 64 {
		t.Fatalf("logical digest = %q", digest.Hex())
	}
}

func TestVerifyRejectsContentModeLinkAndExtraDivergence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(fstest.MapFS)
	}{
		{"content", func(tree fstest.MapFS) { tree["checkout/action.yml"].Data = []byte("evil!!") }},
		{"mode", func(tree fstest.MapFS) { tree["checkout/action.yml"].Mode = 0o644 }},
		{"symlink", func(tree fstest.MapFS) { tree["checkout/action.yml"].Mode = fs.ModeSymlink }},
		{"extra", func(tree fstest.MapFS) { tree["checkout/extra"] = &fstest.MapFile{Data: []byte("x"), Mode: 0o444} }},
		{"missing", func(tree fstest.MapFS) { delete(tree, "checkout/action.yml") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := validMapFS()
			tt.mutate(tree)
			if _, err := Verify(tree, mustLoadManifest(t, validManifestJSON())); err == nil {
				t.Fatal("Verify accepted divergent logical tree")
			}
		})
	}
}

func TestLogicalDigestCannotAuthorizeTreeLockEmission(t *testing.T) {
	manifest := mustLoadManifest(t, validManifestJSON())
	digest, err := Verify(validMapFS(), manifest)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if digest.Hex() == "" {
		t.Fatal("logical digest unexpectedly empty")
	}
	var output bytes.Buffer
	if err := WriteTreeLock(&output, VerifiedDirectory{}); err == nil {
		t.Fatal("zero OS-identity authority emitted a tree lock")
	}
}

func validMapFS() fstest.MapFS {
	return fstest.MapFS{
		"checkout/LICENSE":    &fstest.MapFile{Data: []byte("license"), Mode: 0o444},
		"checkout/action.yml": &fstest.MapFile{Data: []byte("action"), Mode: 0o444},
	}
}

func mustLoadManifest(t *testing.T, document string) Manifest {
	t.Helper()
	manifest, err := Load(strings.NewReader(document))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return manifest
}
