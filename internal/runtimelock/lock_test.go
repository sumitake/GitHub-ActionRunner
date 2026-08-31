package runtimelock

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
)

func TestNewRunnerLockBindsPinsTreeAndExactListener(t *testing.T) {
	verified := verifiedRunnerTree(t)
	lock, err := NewRunnerLock(verified, "bin/Runner.Listener")
	if err != nil {
		t.Fatalf("NewRunnerLock: %v", err)
	}
	if lock.RunnerVersion != "v2.336.0" || lock.Listener.Path != "/opt/actions-runner/bin/Runner.Listener" || lock.Listener.Mode != 0o555 {
		t.Fatalf("lock = %+v", lock)
	}
	encoded, err := Encode(lock)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	loaded, err := Load(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded != lock {
		t.Fatalf("round trip differs:\n got %+v\nwant %+v", loaded, lock)
	}
}

func TestNewSourceRunnerLockBindsSourceTreeAndBuiltPayload(t *testing.T) {
	const payloadSHA = "45f6a3449c950e6f89f29045d7b0e53e25a888206191dff8d7a887eefb8fc4e7"
	lock, err := NewSourceRunnerLock(verifiedRunnerTree(t), "bin/Runner.Listener", payloadSHA)
	if err != nil {
		t.Fatalf("NewSourceRunnerLock: %v", err)
	}
	if lock.SchemaVersion != 2 || lock.RunnerArchiveSHA256 != "" ||
		lock.RunnerPayloadSHA256 != payloadSHA ||
		lock.RunnerSourceTree != "3789e2e60ae52fc9c45b78e0d7f436ee2526b6d5" ||
		lock.RunnerReleaseEvidence != "cfd5c4acaa59579ff850aaad8d4e3f614afc6f80853e870a5271de7db516ba7b" {
		t.Fatalf("source lock = %+v", lock)
	}
	encoded, err := Encode(lock)
	if err != nil {
		t.Fatalf("Encode source lock: %v", err)
	}
	if strings.Contains(string(encoded), "runner_archive_sha256") {
		t.Fatalf("source lock retained archive authority: %s", encoded)
	}
	loaded, err := Load(strings.NewReader(string(encoded)))
	if err != nil || loaded != lock {
		t.Fatalf("source lock round trip got=%+v err=%v want=%+v", loaded, err, lock)
	}
}

func TestNewSourceRunnerLockRejectsUnboundPayloadIdentity(t *testing.T) {
	for _, digest := range []string{"", "bad", strings.Repeat("A", 64)} {
		if _, err := NewSourceRunnerLock(verifiedRunnerTree(t), "bin/Runner.Listener", digest); err == nil {
			t.Fatalf("NewSourceRunnerLock accepted digest %q", digest)
		}
	}
}

func TestLoadRejectsDuplicateUnknownOrPinDrift(t *testing.T) {
	lock, err := NewRunnerLock(verifiedRunnerTree(t), "bin/Runner.Listener")
	if err != nil {
		t.Fatalf("NewRunnerLock: %v", err)
	}
	encoded, err := Encode(lock)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	valid := string(encoded)
	tests := map[string]string{
		"duplicate":         strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"unknown":           strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"unknown":true`, 1),
		"version":           strings.Replace(valid, `"runner_version":"v2.336.0"`, `"runner_version":"v2.335.1"`, 1),
		"archive digest":    strings.Replace(valid, lock.RunnerArchiveSHA256, strings.Repeat("f", 64), 1),
		"source commit":     strings.Replace(valid, lock.RunnerSourceCommit, strings.Repeat("f", 40), 1),
		"tree digest shape": strings.Replace(valid, lock.TreeLockSHA256, "bad", 1),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(document)); err == nil {
				t.Fatal("Load accepted runtime-lock drift")
			}
		})
	}
}

func TestNewRunnerLockRequiresOpaqueVerifiedDirectory(t *testing.T) {
	if _, err := NewRunnerLock(seedarchive.VerifiedRunnerDirectory{}, "bin/Runner.Listener"); err == nil {
		t.Fatal("NewRunnerLock accepted zero directory authority")
	}
	if _, err := NewRunnerLock(verifiedRunnerTree(t), "other"); err == nil {
		t.Fatal("NewRunnerLock accepted a non-listener path")
	}
}

func verifiedRunnerTree(t *testing.T) seedarchive.VerifiedRunnerDirectory {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod root: %v", err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	for _, directory := range []string{"bin", "externals"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatalf("Mkdir %s: %v", directory, err)
		}
	}
	listener := []byte("runner-listener")
	listenerPath := filepath.Join(root, "bin", "Runner.Listener")
	if err := os.WriteFile(listenerPath, listener, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(listenerPath, 0o555); err != nil {
		t.Fatalf("Chmod listener: %v", err)
	}
	for _, directory := range []string{"bin", "externals"} {
		if err := os.Chmod(filepath.Join(root, directory), 0o555); err != nil {
			t.Fatalf("Chmod %s: %v", directory, err)
		}
	}
	manifest := seedarchive.RunnerTreeManifest{
		SchemaVersion: 1,
		Entries: []seedarchive.RunnerTreeEntry{
			{Path: "bin", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
			{Path: "bin/Runner.Listener", Type: seedarchive.RunnerEntryRegular, SHA256: shaHex(listener), Size: uint64(len(listener)), Mode: 0o555},
			{Path: "externals", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
		},
	}
	verified, err := seedarchive.VerifyRunnerDirectory(root, manifest, 9)
	if err != nil {
		t.Fatalf("VerifyRunnerDirectory: %v", err)
	}
	return verified
}

func shaHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
