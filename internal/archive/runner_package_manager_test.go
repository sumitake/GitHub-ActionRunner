package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunnerPackageManagerPath(t *testing.T) {
	omitted := []string{
		"externals/node20/bin/npm",
		"externals/node20/bin/npx",
		"externals/node20/bin/corepack",
		"externals/node24_alpine/bin/npm",
		"externals/node20/lib/node_modules/npm",
		"externals/node20/lib/node_modules/npm/bin/npm-cli.js",
		"externals/node24/lib/node_modules/corepack",
		"externals/node24/lib/node_modules/corepack/dist/corepack.js",
	}
	for _, value := range omitted {
		if !runnerPackageManagerPath(value) {
			t.Errorf("runnerPackageManagerPath(%q) = false, want true", value)
		}
	}
	retained := []string{
		"bin/npm",
		"externals",
		"externals/node20",
		"externals/node20/bin",
		"externals/node20/bin/node",
		"externals/node20/bin/npm/extra",
		"externals/node20/bin/npmx",
		"externals/node20/lib",
		"externals/node20/lib/node_modules",
		"externals/node20/lib/node_modules/npmx",
		"externals/node20/include/node/npm",
		"externals/git/bin/npm",
		"externals/node20/lib/npm",
	}
	for _, value := range retained {
		if runnerPackageManagerPath(value) {
			t.Errorf("runnerPackageManagerPath(%q) = true, want false", value)
		}
	}
}

func TestExtractRunnerArchiveOmitsNodePackageManagers(t *testing.T) {
	entries := append(validRunnerTarEntries(),
		runnerTarEntry{name: "./externals/node/bin/node", typeflag: tar.TypeReg, mode: 0o755, body: []byte("node")},
		runnerTarEntry{name: "./externals/node/bin/npm", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../lib/node_modules/npm/bin/npm-cli.js"},
		runnerTarEntry{name: "./externals/node/bin/npx", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../lib/node_modules/npm/bin/npx-cli.js"},
		runnerTarEntry{name: "./externals/node/bin/corepack", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../lib/node_modules/corepack/dist/corepack.js"},
		runnerTarEntry{name: "./externals/node/lib/node_modules/npm/", typeflag: tar.TypeDir, mode: 0o755},
		runnerTarEntry{name: "./externals/node/lib/node_modules/npm/bin/", typeflag: tar.TypeDir, mode: 0o755},
		runnerTarEntry{name: "./externals/node/lib/node_modules/npm/bin/npm-cli.js", typeflag: tar.TypeReg, mode: 0o644, body: []byte("npm")},
		runnerTarEntry{name: "./externals/node/lib/node_modules/npm/bin/npx-cli.js", typeflag: tar.TypeReg, mode: 0o644, body: []byte("npx")},
		runnerTarEntry{name: "./externals/node/lib/node_modules/corepack/", typeflag: tar.TypeDir, mode: 0o755},
		runnerTarEntry{name: "./externals/node/lib/node_modules/corepack/dist/", typeflag: tar.TypeDir, mode: 0o755},
		runnerTarEntry{name: "./externals/node/lib/node_modules/corepack/dist/corepack.js", typeflag: tar.TypeReg, mode: 0o644, body: []byte("corepack")},
	)
	parent := canonicalTempDir(t)
	archivePath, digest := writeRunnerArchive(t, parent, entries)
	output := filepath.Join(parent, "runner-snapshot")
	defer makeRunnerTreeRemovable(output)

	verified, err := ExtractRunnerArchive(RunnerExtractOptions{
		ArchivePath:        archivePath,
		ExpectedSHA256:     digest,
		EvidenceGeneration: 3,
		OutputDirectory:    output,
	})
	if err != nil {
		t.Fatalf("ExtractRunnerArchive: %v", err)
	}
	for _, relative := range []string{
		"externals/node/bin/npm",
		"externals/node/bin/npx",
		"externals/node/bin/corepack",
		"externals/node/lib/node_modules/npm",
		"externals/node/lib/node_modules/corepack",
	} {
		if _, err := os.Lstat(filepath.Join(output, filepath.FromSlash(relative))); !os.IsNotExist(err) {
			t.Errorf("package-manager path %s present: %v", relative, err)
		}
	}
	if _, err := verified.File("externals/node/bin/node"); err != nil {
		t.Fatalf("node binary missing: %v", err)
	}
	if _, err := verified.Symlink("externals/node/bin/tool"); err != nil {
		t.Fatalf("unrelated symlink missing: %v", err)
	}
	var document bytes.Buffer
	if err := WriteRunnerManifest(&document, verified); err != nil {
		t.Fatalf("WriteRunnerManifest: %v", err)
	}
	manifest, err := LoadRunnerManifest(bytes.NewReader(document.Bytes()))
	if err != nil {
		t.Fatalf("LoadRunnerManifest: %v", err)
	}
	for _, entry := range manifest.Entries {
		if runnerPackageManagerPath(entry.Path) {
			t.Errorf("manifest retains package-manager path %s", entry.Path)
		}
	}
	if _, err := VerifyRunnerDirectory(output, manifest, 3); err != nil {
		t.Fatalf("VerifyRunnerDirectory: %v", err)
	}
}

func TestValidateRunnerManifestRejectsNodePackageManagers(t *testing.T) {
	base := RunnerTreeManifest{SchemaVersion: 1, Entries: []RunnerTreeEntry{
		{Path: "bin", Type: RunnerEntryDirectory, Mode: 0o555},
		{Path: "bin/Runner.Listener", Type: RunnerEntryRegular, SHA256: sha256String([]byte("listener")), Size: 8, Mode: 0o555},
		{Path: "externals", Type: RunnerEntryDirectory, Mode: 0o555},
		{Path: "externals/node", Type: RunnerEntryDirectory, Mode: 0o555},
		{Path: "externals/node/bin", Type: RunnerEntryDirectory, Mode: 0o555},
	}}
	if err := validateRunnerManifest(base); err != nil {
		t.Fatalf("base manifest rejected: %v", err)
	}
	for _, name := range []string{"npm", "NPM", "npx", "corepack"} {
		manifest := cloneRunnerManifest(base)
		manifest.Entries = append(manifest.Entries, RunnerTreeEntry{
			Path:   "externals/node/bin/" + name,
			Type:   RunnerEntryRegular,
			SHA256: sha256String([]byte("pm")),
			Size:   2,
			Mode:   0o555,
		})
		if err := validateRunnerManifest(manifest); err == nil {
			t.Errorf("manifest with externals/node/bin/%s accepted", name)
		}
	}
}
