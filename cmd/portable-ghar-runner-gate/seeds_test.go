package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"golang.org/x/sys/unix"
)

func TestSeedCatalogLoadsBoundLocksAndHydratesOnlySelectedTargets(t *testing.T) {
	fixture := newSeedCatalogFixture(t)
	catalog, err := loadSeedCatalog(
		fixture.root,
		fixture.manifestPath,
		fixture.treeLockPath,
		fixture.readyPath,
		fixture.uid,
		fixture.gid,
	)
	if err != nil {
		t.Fatalf("loadSeedCatalog: %v", err)
	}
	workRoot := filepath.Join(shortSocketRoot(t), "_work")
	if err := catalog.hydrate(workRoot, []string{"actions-checkout"}); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	commit := strings.Repeat("a", 40)
	actionPath := filepath.Join(workRoot, "_actions", "checkout", commit, "action.yml")
	if data, err := os.ReadFile(actionPath); err != nil || string(data) != "action" {
		t.Fatalf("hydrated action=%q err=%v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(workRoot, "_tool")); !os.IsNotExist(err) {
		t.Fatalf("unselected tool was hydrated: %v", err)
	}
	info, err := os.Lstat(actionPath)
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("hydrated action identity=%v err=%v", info, err)
	}
	if err := catalog.hydrate(workRoot, []string{"actions-checkout"}); err == nil {
		t.Fatal("seed catalog reused an existing work root")
	}
}

func TestSeedCatalogRejectsLockDriftUnknownSelectionAndMidCopyMutation(t *testing.T) {
	t.Run("tree lock drift", func(t *testing.T) {
		fixture := newSeedCatalogFixture(t)
		if err := os.Chmod(fixture.treeLockPath, 0o600); err != nil {
			t.Fatalf("Chmod tree lock: %v", err)
		}
		if err := os.WriteFile(fixture.treeLockPath, []byte("changed"), 0o600); err != nil {
			t.Fatalf("WriteFile tree lock: %v", err)
		}
		if err := os.Chmod(fixture.treeLockPath, 0o444); err != nil {
			t.Fatalf("Chmod tree lock read-only: %v", err)
		}
		if _, err := loadSeedCatalog(
			fixture.root,
			fixture.manifestPath,
			fixture.treeLockPath,
			fixture.readyPath,
			fixture.uid,
			fixture.gid,
		); err == nil {
			t.Fatal("loadSeedCatalog accepted tree-lock drift")
		}
	})

	t.Run("unknown selection", func(t *testing.T) {
		fixture := newSeedCatalogFixture(t)
		catalog, err := loadSeedCatalog(
			fixture.root,
			fixture.manifestPath,
			fixture.treeLockPath,
			fixture.readyPath,
			fixture.uid,
			fixture.gid,
		)
		if err != nil {
			t.Fatalf("loadSeedCatalog: %v", err)
		}
		workRoot := filepath.Join(shortSocketRoot(t), "_work")
		if err := catalog.hydrate(workRoot, []string{"unknown"}); err == nil {
			t.Fatal("hydrate accepted an unknown seed")
		}
		if _, err := os.Lstat(workRoot); !os.IsNotExist(err) {
			t.Fatalf("failed hydration left work root: %v", err)
		}
	})

	t.Run("source changed", func(t *testing.T) {
		fixture := newSeedCatalogFixture(t)
		catalog, err := loadSeedCatalog(
			fixture.root,
			fixture.manifestPath,
			fixture.treeLockPath,
			fixture.readyPath,
			fixture.uid,
			fixture.gid,
		)
		if err != nil {
			t.Fatalf("loadSeedCatalog: %v", err)
		}
		source := filepath.Join(fixture.root, "checkout", "action.yml")
		if err := os.Chmod(source, 0o600); err != nil {
			t.Fatalf("Chmod source: %v", err)
		}
		if err := os.WriteFile(source, []byte("mutate"), 0o600); err != nil {
			t.Fatalf("WriteFile source: %v", err)
		}
		if err := os.Chmod(source, 0o444); err != nil {
			t.Fatalf("Chmod source read-only: %v", err)
		}
		workRoot := filepath.Join(shortSocketRoot(t), "_work")
		if err := catalog.hydrate(workRoot, []string{"actions-checkout"}); err == nil {
			t.Fatal("hydrate accepted changed seed bytes")
		}
		if _, err := os.Lstat(workRoot); !os.IsNotExist(err) {
			t.Fatalf("failed changed-source hydration left work root: %v", err)
		}
	})
}

func TestSeedCatalogRejectsFIFOWithoutBlocking(t *testing.T) {
	fixture := newSeedCatalogFixture(t)
	source := filepath.Join(fixture.root, "checkout", "action.yml")
	if err := os.Chmod(filepath.Dir(source), 0o700); err != nil {
		t.Fatalf("Chmod source directory writable: %v", err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatalf("Remove source: %v", err)
	}
	if err := unix.Mkfifo(source, 0o444); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if err := os.Chmod(filepath.Dir(source), 0o555); err != nil {
		t.Fatalf("Chmod source directory sealed: %v", err)
	}

	catalog := seedCatalog{
		root:        fixture.root,
		expectedUID: fixture.uid,
		expectedGID: fixture.gid,
	}
	target := filepath.Join(shortSocketRoot(t), "hydrated")
	done := make(chan error, 1)
	go func() {
		done <- catalog.copyFile(
			"checkout/action.yml",
			target,
			seedarchive.File{Size: 6, SHA256: seedSHA([]byte("action")), Mode: 0o444},
		)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("copyFile accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("copyFile blocked opening a FIFO")
	}
}

type seedCatalogFixture struct {
	root         string
	manifestPath string
	treeLockPath string
	readyPath    string
	uid          uint32
	gid          uint32
}

func newSeedCatalogFixture(t *testing.T) seedCatalogFixture {
	t.Helper()
	parent := shortSocketRoot(t)
	root := filepath.Join(parent, "seed-cache")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	files := map[string]struct {
		contents []byte
		mode     os.FileMode
	}{
		"checkout/LICENSE":    {[]byte("license"), 0o444},
		"checkout/action.yml": {[]byte("action"), 0o444},
		"tool/LICENSE":        {[]byte("tool-license"), 0o444},
		"tool/go":             {[]byte("tool-binary"), 0o555},
	}
	for name, file := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("MkdirAll %s: %v", name, err)
		}
		if err := os.WriteFile(path, file.contents, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
		if err := os.Chmod(path, file.mode); err != nil {
			t.Fatalf("Chmod %s: %v", name, err)
		}
	}
	for _, directory := range []string{"checkout", "tool"} {
		if err := os.Chmod(filepath.Join(root, directory), 0o555); err != nil {
			t.Fatalf("Chmod directory %s: %v", directory, err)
		}
	}
	commit := strings.Repeat("a", 40)
	manifest := seedarchive.Manifest{
		SchemaVersion: 1,
		Seeds: []seedarchive.Seed{
			{
				ID: "actions-checkout", Kind: seedarchive.KindAction,
				Source: "https://github.com/actions/checkout/archive/" + commit + ".tar.gz", Revision: commit,
				License: seedarchive.LicenseEvidence{SPDX: "MIT", Path: "checkout/LICENSE", Size: 7, SHA256: seedSHA([]byte("license"))},
				Files: []seedarchive.File{
					{Path: "checkout/LICENSE", Target: "actions/checkout/" + commit + "/LICENSE", Size: 7, SHA256: seedSHA([]byte("license")), Mode: 0o444},
					{Path: "checkout/action.yml", Target: "actions/checkout/" + commit + "/action.yml", Size: 6, SHA256: seedSHA([]byte("action")), Mode: 0o444},
				},
			},
			{
				ID: "tool-go", Kind: seedarchive.KindTool,
				Source: "https://github.com/actions/setup-go/releases/download/v1.2.3/tool.tar.gz", Revision: "v1.2.3",
				License: seedarchive.LicenseEvidence{SPDX: "MIT", Path: "tool/LICENSE", Size: 12, SHA256: seedSHA([]byte("tool-license"))},
				Files: []seedarchive.File{
					{Path: "tool/LICENSE", Target: "tools/tool-go/v1.2.3/LICENSE", Size: 12, SHA256: seedSHA([]byte("tool-license")), Mode: 0o444},
					{Path: "tool/go", Target: "tools/tool-go/v1.2.3/go", Size: 11, SHA256: seedSHA([]byte("tool-binary")), Mode: 0o555},
				},
			},
		},
	}
	verified, err := seedarchive.VerifyDirectory(root, manifest, 31)
	if err != nil {
		t.Fatalf("VerifyDirectory: %v", err)
	}
	var treeLock bytes.Buffer
	if err := seedarchive.WriteTreeLock(&treeLock, verified); err != nil {
		t.Fatalf("WriteTreeLock: %v", err)
	}
	manifestDocument, err := seedarchive.EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatalf("Chmod root: %v", err)
	}
	var rootStat syscall.Stat_t
	if err := syscall.Lstat(root, &rootStat); err != nil {
		t.Fatalf("Lstat root: %v", err)
	}
	manifestPath := filepath.Join(parent, "seed-cache.manifest.json")
	treeLockPath := filepath.Join(parent, "seed-cache.tree-lock")
	readyPath := filepath.Join(parent, "seed-cache.READY")
	manifestHash := sha256.Sum256(bytes.TrimSuffix(manifestDocument, []byte("\n")))
	ready, err := json.Marshal(seedCatalogReadiness{
		SchemaVersion: 1, ManifestSHA256: hex.EncodeToString(manifestHash[:]),
		TreeLockSHA256: seedSHA(treeLock.Bytes()), EvidenceGeneration: 31, Empty: false,
	})
	if err != nil {
		t.Fatalf("Marshal readiness: %v", err)
	}
	for path, contents := range map[string][]byte{
		manifestPath: manifestDocument,
		treeLockPath: treeLock.Bytes(),
		readyPath:    append(ready, '\n'),
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatalf("Chmod %s: %v", path, err)
		}
	}
	return seedCatalogFixture{
		root: root, manifestPath: manifestPath, treeLockPath: treeLockPath, readyPath: readyPath,
		uid: rootStat.Uid, gid: rootStat.Gid,
	}
}

func seedSHA(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
