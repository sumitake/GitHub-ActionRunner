package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestRegistrationMarkerIsFreshIdentityBoundAndExactlyRemoved(t *testing.T) {
	t.Parallel()

	root := directTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	payload := sha256.Sum256([]byte("marker"))
	marker, err := createRegistrationMarkerAt(
		root,
		"registration",
		payload,
		uint32(os.Geteuid()),
	)
	if err != nil {
		t.Fatalf("createRegistrationMarkerAt: %v", err)
	}
	path := filepath.Join(root, "registration")
	assertRegularFileForTest(t, path, 0o600, payload[:])
	if err := marker.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker remains: %v", err)
	}
	if err := marker.Remove(); err == nil {
		t.Fatal("second Remove succeeded")
	}
}

func TestRegistrationMarkerRejectsExistingOrReplacedIdentity(t *testing.T) {
	t.Parallel()

	payload := sha256.Sum256([]byte("marker"))
	for _, kind := range []string{"regular", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := directTempDir(t)
			path := filepath.Join(root, "registration")
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
					t.Fatalf("write existing: %v", err)
				}
			case "symlink":
				if err := os.Symlink("elsewhere", path); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			}
			if _, err := createRegistrationMarkerAt(
				root,
				"registration",
				payload,
				uint32(os.Geteuid()),
			); err == nil {
				t.Fatal("existing marker accepted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("existing object was removed: %v", err)
			}
		})
	}

	root := directTempDir(t)
	marker, err := createRegistrationMarkerAt(
		root,
		"registration",
		payload,
		uint32(os.Geteuid()),
	)
	if err != nil {
		t.Fatalf("createRegistrationMarkerAt: %v", err)
	}
	path := filepath.Join(root, "registration")
	original := filepath.Join(root, "original")
	if err := os.Rename(path, original); err != nil {
		t.Fatalf("rename original: %v", err)
	}
	replacement := []byte("replacement")
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := marker.Remove(); err == nil {
		t.Fatal("Remove accepted replacement identity")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("replacement changed: %q, %v", got, err)
	}
}

func TestUpgradeStagingCreatesOnlyExactEphemeralObject(t *testing.T) {
	t.Parallel()

	work := directTempDir(t)
	if err := os.Chmod(work, 0o700); err != nil {
		t.Fatalf("chmod work: %v", err)
	}
	payload := sha256.Sum256([]byte("upgrade"))
	if err := createUpgradeStagingAt(
		work,
		"_update",
		"portable-ghar-task11-upgrade-staging-v1",
		payload,
		uint32(os.Geteuid()),
	); err != nil {
		t.Fatalf("createUpgradeStagingAt: %v", err)
	}
	update := filepath.Join(work, "_update")
	info, err := os.Lstat(update)
	if err != nil ||
		!info.IsDir() ||
		info.Mode().Perm() != 0o700 {
		t.Fatalf("update directory = %+v, %v", info, err)
	}
	entries, err := os.ReadDir(update)
	if err != nil ||
		len(entries) != 1 ||
		entries[0].Name() != "portable-ghar-task11-upgrade-staging-v1" {
		t.Fatalf("update entries = %v, %v", entries, err)
	}
	assertRegularFileForTest(
		t,
		filepath.Join(update, entries[0].Name()),
		0o600,
		payload[:],
	)
	if err := createUpgradeStagingAt(
		work,
		"_update",
		"portable-ghar-task11-upgrade-staging-v1",
		payload,
		uint32(os.Geteuid()),
	); err == nil {
		t.Fatal("second staging create succeeded")
	}
}

func TestSeedSessionFirstMutatesOnlyCopyAndSecondProvesFreshness(t *testing.T) {
	t.Parallel()

	sourceRoot := directTempDir(t)
	source := filepath.Join(sourceRoot, "source.bin")
	if err := os.WriteFile(
		source,
		task11synthetic.SeedSourceBytes(),
		0o444,
	); err != nil {
		t.Fatalf("write source: %v", err)
	}
	sourceBefore, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	firstCopy := filepath.Join(directTempDir(t), "copy.bin")
	if err := os.WriteFile(
		firstCopy,
		task11synthetic.SeedSourceBytes(),
		0o644,
	); err != nil {
		t.Fatalf("write first copy: %v", err)
	}
	first, err := prepareSeedWithContract(
		task11synthetic.ScenarioSeedFirst,
		testSeedContract(source, firstCopy),
	)
	if err != nil {
		t.Fatalf("prepare first seed: %v", err)
	}
	firstProof, err := first.Finalize()
	if err != nil {
		t.Fatalf("finalize first seed: %v", err)
	}
	if firstProof != validListenerSeedProof(task11synthetic.ScenarioSeedFirst) {
		t.Fatalf("first proof = %+v", firstProof)
	}
	mutated, err := os.ReadFile(firstCopy)
	if err != nil {
		t.Fatalf("read mutated copy: %v", err)
	}
	wantMutated := append(
		task11synthetic.SeedSourceBytes(),
		task11synthetic.SeedMutationSuffix()...,
	)
	if !bytes.Equal(mutated, wantMutated) {
		t.Fatalf("mutated copy = %q, want %q", mutated, wantMutated)
	}
	sourceAfterFirst, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(sourceAfterFirst, sourceBefore) {
		t.Fatalf("source changed after first: %q, %v", sourceAfterFirst, err)
	}

	secondCopy := filepath.Join(directTempDir(t), "copy.bin")
	if err := os.WriteFile(
		secondCopy,
		task11synthetic.SeedSourceBytes(),
		0o644,
	); err != nil {
		t.Fatalf("write second copy: %v", err)
	}
	second, err := prepareSeedWithContract(
		task11synthetic.ScenarioSeedSecond,
		testSeedContract(source, secondCopy),
	)
	if err != nil {
		t.Fatalf("prepare second seed: %v", err)
	}
	secondProof, err := second.Finalize()
	if err != nil {
		t.Fatalf("finalize second seed: %v", err)
	}
	if secondProof != validListenerSeedProof(task11synthetic.ScenarioSeedSecond) {
		t.Fatalf("second proof = %+v", secondProof)
	}
	fresh, err := os.ReadFile(secondCopy)
	if err != nil ||
		!bytes.Equal(fresh, task11synthetic.SeedSourceBytes()) ||
		bytes.Contains(fresh, task11synthetic.SeedMutationSuffix()) {
		t.Fatalf("second copy not fresh: %q, %v", fresh, err)
	}
	sourceAfterSecond, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(sourceAfterSecond, sourceBefore) {
		t.Fatalf("source changed after second: %q, %v", sourceAfterSecond, err)
	}
}

func TestSeedSessionRejectsIndirectChangedOrWrongContent(t *testing.T) {
	t.Parallel()

	sourceRoot := directTempDir(t)
	source := filepath.Join(sourceRoot, "source.bin")
	if err := os.WriteFile(
		source,
		task11synthetic.SeedSourceBytes(),
		0o444,
	); err != nil {
		t.Fatalf("write source: %v", err)
	}
	copyRoot := directTempDir(t)
	copyPath := filepath.Join(copyRoot, "copy.bin")
	if err := os.WriteFile(
		copyPath,
		task11synthetic.SeedSourceBytes(),
		0o644,
	); err != nil {
		t.Fatalf("write copy: %v", err)
	}
	indirect := filepath.Join(copyRoot, "indirect.bin")
	if err := os.Symlink(copyPath, indirect); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	contract := testSeedContract(source, indirect)
	if _, err := prepareSeedWithContract(
		task11synthetic.ScenarioSeedFirst,
		contract,
	); err == nil {
		t.Fatal("symlink copy accepted")
	}

	session, err := prepareSeedWithContract(
		task11synthetic.ScenarioSeedFirst,
		testSeedContract(source, copyPath),
	)
	if err != nil {
		t.Fatalf("prepare seed: %v", err)
	}
	original := filepath.Join(copyRoot, "original.bin")
	if err := os.Rename(copyPath, original); err != nil {
		t.Fatalf("rename copy: %v", err)
	}
	if err := os.WriteFile(
		copyPath,
		task11synthetic.SeedSourceBytes(),
		0o644,
	); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if _, err := session.Finalize(); err == nil {
		t.Fatal("replacement copy accepted")
	}

	wrong := filepath.Join(directTempDir(t), "wrong.bin")
	if err := os.WriteFile(wrong, []byte("wrong\n"), 0o644); err != nil {
		t.Fatalf("write wrong copy: %v", err)
	}
	if _, err := prepareSeedWithContract(
		task11synthetic.ScenarioSeedSecond,
		testSeedContract(source, wrong),
	); err == nil {
		t.Fatal("wrong copy content accepted")
	}
}

func testSeedContract(source, copyPath string) seedFileContract {
	return seedFileContract{
		sourcePath:             source,
		copyPath:               copyPath,
		sourceUID:              uint32(os.Geteuid()),
		sourceGID:              uint32(os.Getegid()),
		copyUID:                uint32(os.Geteuid()),
		copyGID:                uint32(os.Getegid()),
		sourceMode:             0o444,
		copyMode:               0o644,
		requireSourceWriteDeny: true,
	}
}

func assertRegularFileForTest(
	t *testing.T,
	path string,
	mode os.FileMode,
	want []byte,
) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != mode {
		t.Fatalf("file %s = %+v, %v", path, info, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("file %s bytes = %x, %v; want %x", path, got, err, want)
	}
}

func directTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	direct, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve temp directory: %v", err)
	}
	return direct
}
