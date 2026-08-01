package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestVerifyDirectoryReturnsOpaqueIdentityBoundAuthority(t *testing.T) {
	root := materializeDirectory(t)
	verified, err := VerifyDirectory(root, mustLoadManifest(t, validManifestJSON()), 7)
	if err != nil {
		t.Fatalf("VerifyDirectory: %v", err)
	}
	if verified.Generation() != 7 || len(verified.ManifestDigest()) != 64 || len(verified.TreeLockDigest()) != 64 {
		t.Fatalf("verified authority = generation=%d manifest=%q tree=%q", verified.Generation(), verified.ManifestDigest(), verified.TreeLockDigest())
	}
	var lock bytes.Buffer
	if err := WriteTreeLock(&lock, verified); err != nil {
		t.Fatalf("WriteTreeLock: %v", err)
	}
	if lock.Len() == 0 {
		t.Fatal("tree lock is empty")
	}
}

func TestVerifyDirectoryRejectsRootAliasHardlinkAndMidHashMutation(t *testing.T) {
	t.Run("root symlink", func(t *testing.T) {
		root := materializeDirectory(t)
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(root, alias); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if _, err := VerifyDirectory(alias, mustLoadManifest(t, validManifestJSON()), 7); err == nil {
			t.Fatal("VerifyDirectory accepted a root symlink")
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		root := materializeDirectory(t)
		if err := os.Link(filepath.Join(root, "checkout", "action.yml"), filepath.Join(root, "checkout", "alias")); err != nil {
			t.Fatalf("Link: %v", err)
		}
		if _, err := VerifyDirectory(root, mustLoadManifest(t, validManifestJSON()), 7); err == nil {
			t.Fatal("VerifyDirectory accepted a multiply linked file")
		}
	})

	t.Run("mid-hash mutation", func(t *testing.T) {
		root := materializeDirectory(t)
		hooks := directoryVerifyHooks{
			afterHash: func(path string) {
				if path == "checkout/action.yml" {
					_ = os.Chmod(filepath.Join(root, filepath.FromSlash(path)), 0o644)
				}
			},
		}
		if _, err := verifyDirectory(root, mustLoadManifest(t, validManifestJSON()), 7, hooks); err == nil {
			t.Fatal("VerifyDirectory accepted metadata mutation during hash")
		}
	})
}

func TestVerifyDirectoryRejectsZeroEvidenceGeneration(t *testing.T) {
	if _, err := VerifyDirectory(materializeDirectory(t), mustLoadManifest(t, validManifestJSON()), 0); err == nil {
		t.Fatal("VerifyDirectory accepted zero evidence generation")
	}
}

func TestVerifyDirectoryRejectsFIFOWithoutBlocking(t *testing.T) {
	root := materializeDirectory(t)
	path := filepath.Join(root, "checkout", "action.yml")
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := unix.Mkfifo(path, 0o444); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := VerifyDirectory(root, mustLoadManifest(t, validManifestJSON()), 7)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("VerifyDirectory accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("VerifyDirectory blocked opening a FIFO")
	}
}

func TestSeedImageVerificationIsNonAuthorizingAndRequiresInstalledModes(t *testing.T) {
	var _ seedImageEvidence = SeedImageVerification{}
	imageType := reflect.TypeOf(SeedImageVerification{})
	authorityType := reflect.TypeOf(VerifiedDirectory{})
	if imageType.AssignableTo(authorityType) || imageType.ConvertibleTo(authorityType) ||
		authorityType.AssignableTo(imageType) || authorityType.ConvertibleTo(imageType) {
		t.Fatal("installed seed evidence and staging authority are assignable or convertible")
	}
	if _, ok := any(SeedImageVerification{}).(seedDirectoryAuthority); ok {
		t.Fatal("installed seed evidence implements seed publication authority")
	}

	root := materializeDirectory(t)
	manifest := mustLoadManifest(t, validManifestJSON())
	staging, err := VerifyDirectory(root, manifest, 19)
	if err != nil {
		t.Fatalf("VerifyDirectory: %v", err)
	}
	if _, err := verifySeedImageDirectoryForOwner(
		root,
		manifest,
		19,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	); err == nil {
		t.Fatal("installed seed verification accepted private/writable directory modes")
	}
	if err := os.Chmod(filepath.Join(root, "checkout"), 0o555); err != nil {
		t.Fatalf("Chmod checkout: %v", err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatalf("Chmod root: %v", err)
	}
	image, err := verifySeedImageDirectoryForOwner(
		root,
		manifest,
		19,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	)
	if err != nil {
		t.Fatalf("verifySeedImageDirectoryForOwner: %v", err)
	}
	if image.Generation() != staging.Generation() ||
		image.ManifestDigest() != staging.ManifestDigest() {
		t.Fatalf("installed seed evidence differs: image=%d/%s staging=%d/%s",
			image.Generation(), image.ManifestDigest(),
			staging.Generation(), staging.ManifestDigest())
	}
}

func materializeDirectory(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod root: %v", err)
	}
	t.Cleanup(func() {
		makeSeedTreeRemovable(root)
	})
	checkout := filepath.Join(root, "checkout")
	if err := os.Mkdir(checkout, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	for name, data := range map[string][]byte{"LICENSE": []byte("license"), "action.yml": []byte("action")} {
		path := filepath.Join(checkout, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatalf("Chmod %s: %v", name, err)
		}
	}
	return root
}

func makeSeedTreeRemovable(root string) {
	_ = os.Chmod(root, 0o700)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}
