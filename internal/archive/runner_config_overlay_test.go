package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func addRunnerConfigLinks(t *testing.T, root string) {
	t.Helper()
	for _, name := range []string{".runner", ".credentials", ".credentials_rsaparams"} {
		if err := os.Symlink("/runner/"+name, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunnerRuntimeConfigOverlayIsExactAndRequired(t *testing.T) {
	for _, variant := range []string{"valid", "missing runner", "missing credentials", "missing rsa", "wrong runner target", "regular credential file", "extra credentials"} {
		t.Run(variant, func(t *testing.T) {
			root, manifest, baseline := installedRunnerImageFixture(t)
			addRunnerImageObject(t, root, func() {
				for _, name := range []string{"_diag", "_work"} {
					if err := os.Symlink("/runner/"+name, filepath.Join(root, name)); err != nil {
						t.Fatal(err)
					}
				}
				addRunnerConfigLinks(t, root)
				remove := func(name string) {
					if err := os.Remove(filepath.Join(root, name)); err != nil {
						t.Fatal(err)
					}
				}
				switch variant {
				case "missing runner":
					remove(".runner")
				case "missing credentials":
					remove(".credentials")
				case "missing rsa":
					remove(".credentials_rsaparams")
				case "wrong runner target":
					remove(".runner")
					if err := os.Symlink("/tmp/.runner", filepath.Join(root, ".runner")); err != nil {
						t.Fatal(err)
					}
				case "regular credential file":
					remove(".credentials")
					if err := os.WriteFile(filepath.Join(root, ".credentials"), []byte("synthetic"), 0o444); err != nil {
						t.Fatal(err)
					}
				case "extra credentials":
					if err := os.Symlink("/runner/.credentials_extra", filepath.Join(root, ".credentials_extra")); err != nil {
						t.Fatal(err)
					}
				}
			})
			proof, err := verifyRunnerImageDirectoryWithRuntimeOverlayForOwner(root, manifest, 47, uint32(os.Geteuid()), uint32(os.Getegid()))
			if variant != "valid" {
				if err == nil {
					t.Fatal("invalid runtime configuration overlay accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("fixed ephemeral configuration links rejected: %v", err)
			}
			if proof.ManifestDigest() != baseline.ManifestDigest() || proof.TreeLockDigest() != baseline.TreeLockDigest() {
				t.Fatal("runtime configuration changed immutable code identity")
			}
		})
	}
}
