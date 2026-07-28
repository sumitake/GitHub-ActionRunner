package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishVerifiedCopiesAndReverifiesExactTree(t *testing.T) {
	source := materializeDirectory(t)
	verified, err := VerifyDirectory(source, mustLoadManifest(t, validManifestJSON()), 11)
	if err != nil {
		t.Fatalf("VerifyDirectory: %v", err)
	}
	destination := filepath.Join(canonicalTempDir(t), "published")
	t.Cleanup(func() {
		makeSeedTreeRemovable(destination)
	})
	published, err := PublishVerified(verified, destination)
	if err != nil {
		t.Fatalf("PublishVerified: %v", err)
	}
	if published.TreeLockDigest() == verified.TreeLockDigest() ||
		published.ManifestDigest() != verified.ManifestDigest() ||
		published.Generation() != verified.Generation() {
		t.Fatalf("published authority differs: %+v %+v", published, verified)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "checkout", "action.yml")); err != nil || string(data) != "action" {
		t.Fatalf("published file = %q, %v", data, err)
	}
	if info, err := os.Lstat(filepath.Join(destination, "checkout")); err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("published directory = %v, %v", info, err)
	}
}

func TestPublishVerifiedRejectsZeroOrStaleAuthority(t *testing.T) {
	if _, err := PublishVerified(VerifiedDirectory{}, filepath.Join(canonicalTempDir(t), "zero")); err == nil {
		t.Fatal("PublishVerified accepted zero authority")
	}
	source := materializeDirectory(t)
	verified, err := VerifyDirectory(source, mustLoadManifest(t, validManifestJSON()), 11)
	if err != nil {
		t.Fatalf("VerifyDirectory: %v", err)
	}
	if err := os.Chmod(filepath.Join(source, "checkout", "action.yml"), 0o644); err != nil {
		t.Fatalf("Chmod source: %v", err)
	}
	destination := filepath.Join(canonicalTempDir(t), "stale")
	if _, err := PublishVerified(verified, destination); err == nil {
		t.Fatal("PublishVerified accepted stale source authority")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed publish left destination: %v", err)
	}
}

func TestPublishVerifiedRemovesSealedPartialTreeAfterLateFailure(t *testing.T) {
	source := materializeDirectory(t)
	verified, err := VerifyDirectory(source, mustLoadManifest(t, validManifestJSON()), 11)
	if err != nil {
		t.Fatalf("VerifyDirectory: %v", err)
	}
	destination := filepath.Join(canonicalTempDir(t), "late-failure")
	called := false
	if _, err := publishVerified(verified, destination, publishHooks{
		afterSeal: func() error {
			called = true
			return os.ErrInvalid
		},
	}); err == nil || !called {
		t.Fatalf("publishVerified error=%v called=%v", err, called)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("sealed failed publication remained: %v", err)
	}
}

func TestPublishVerifiedSupportsAnExplicitEmptyManifest(t *testing.T) {
	source := canonicalTempDir(t)
	if err := os.Chmod(source, 0o700); err != nil {
		t.Fatalf("Chmod source: %v", err)
	}
	manifest := Manifest{SchemaVersion: 1, Seeds: []Seed{}}
	verified, err := VerifyDirectory(source, manifest, 19)
	if err != nil {
		t.Fatalf("VerifyDirectory empty: %v", err)
	}
	destination := filepath.Join(canonicalTempDir(t), "empty")
	published, err := PublishVerified(verified, destination)
	if err != nil {
		t.Fatalf("PublishVerified empty: %v", err)
	}
	if published.Generation() != 19 ||
		published.ManifestDigest() != verified.ManifestDigest() ||
		published.TreeLockDigest() != verified.TreeLockDigest() {
		t.Fatalf("empty publication differs: %+v %+v", published, verified)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty publication entries=%v err=%v", entries, err)
	}
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks temp directory: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod temp directory: %v", err)
	}
	return directory
}
