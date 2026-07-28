package imageverify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/runtimelock"
)

func TestVerifyImageLayoutBindsRunnerSeedLocksAndReadiness(t *testing.T) {
	fixture := newImageLayoutFixture(t)
	backends := verificationBackends{
		runner: func(root string, manifest seedarchive.RunnerTreeManifest, generation uint64) (imageProof, error) {
			if root != fixture.layout.runnerRoot || generation != fixture.generation ||
				len(manifest.Entries) != 3 {
				return imageProof{}, errors.New("test: runner verifier inputs differ")
			}
			return fixture.runnerProof, nil
		},
		seed: func(root string, manifest seedarchive.Manifest, generation uint64) (imageProof, error) {
			if root != fixture.layout.seedRoot || generation != fixture.generation ||
				manifest.SchemaVersion != 1 || len(manifest.Seeds) != 0 {
				return imageProof{}, errors.New("test: seed verifier inputs differ")
			}
			return fixture.seedProof, nil
		},
	}
	if err := verifyImageLayout(fixture.layout, backends); err != nil {
		t.Fatalf("verifyImageLayout: %v", err)
	}
}

func TestVerifyImageLayoutRejectsTupleAndFileIdentityDrift(t *testing.T) {
	tests := map[string]func(*testing.T, *imageLayoutFixture){
		"runner tree lock": func(t *testing.T, fixture *imageLayoutFixture) {
			replaceLockedFile(t, fixture.layout.runnerTreeLock, []byte("changed\n"), 0o444)
		},
		"runner readiness generation": func(t *testing.T, fixture *imageLayoutFixture) {
			replaceLockedFile(t, fixture.layout.runnerReady, mustCanonicalJSON(t, runnerReadiness{
				SchemaVersion:      1,
				RuntimeLockSHA256:  fixture.runtimeLockDigest,
				TreeLockSHA256:     fixture.runnerProof.treeLockDigest,
				ManifestSHA256:     fixture.runnerProof.manifestDigest,
				EvidenceGeneration: fixture.generation + 1,
			}), 0o444)
		},
		"runtime listener": func(t *testing.T, fixture *imageLayoutFixture) {
			lock := fixture.runtimeLock
			lock.Listener.SHA256 = strings64("f")
			document, err := runtimelock.Encode(lock)
			if err != nil {
				t.Fatalf("Encode changed runtime lock: %v", err)
			}
			replaceLockedFile(t, fixture.layout.runnerRuntimeLock, document, 0o444)
		},
		"seed tree lock": func(t *testing.T, fixture *imageLayoutFixture) {
			replaceLockedFile(t, fixture.layout.seedTreeLock, []byte("changed\n"), 0o444)
		},
		"writable metadata": func(t *testing.T, fixture *imageLayoutFixture) {
			if err := os.Chmod(fixture.layout.seedReady, 0o644); err != nil {
				t.Fatalf("Chmod seed readiness: %v", err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newImageLayoutFixture(t)
			mutate(t, &fixture)
			backends := verificationBackends{
				runner: func(string, seedarchive.RunnerTreeManifest, uint64) (imageProof, error) {
					return fixture.runnerProof, nil
				},
				seed: func(string, seedarchive.Manifest, uint64) (imageProof, error) {
					return fixture.seedProof, nil
				},
			}
			if err := verifyImageLayout(fixture.layout, backends); err == nil {
				t.Fatal("verifyImageLayout accepted drift")
			}
		})
	}
}

func TestVerifyImageLayoutPropagatesInstalledProofFailure(t *testing.T) {
	fixture := newImageLayoutFixture(t)
	backends := verificationBackends{
		runner: func(string, seedarchive.RunnerTreeManifest, uint64) (imageProof, error) {
			return imageProof{}, errors.New("runner identity invalid")
		},
		seed: func(string, seedarchive.Manifest, uint64) (imageProof, error) {
			t.Fatal("seed verifier ran after runner failure")
			return imageProof{}, nil
		},
	}
	if err := verifyImageLayout(fixture.layout, backends); err == nil {
		t.Fatal("verifyImageLayout accepted failed installed proof")
	}
}

type imageLayoutFixture struct {
	layout            verificationLayout
	generation        uint64
	runnerProof       imageProof
	seedProof         imageProof
	runtimeLock       runtimelock.Lock
	runtimeLockDigest string
}

func newImageLayoutFixture(t *testing.T) imageLayoutFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	runnerRoot := filepath.Join(root, "runner")
	seedRoot := filepath.Join(root, "seeds")
	if err := os.Mkdir(runnerRoot, 0o700); err != nil {
		t.Fatalf("Mkdir runner: %v", err)
	}
	if err := os.Mkdir(seedRoot, 0o700); err != nil {
		t.Fatalf("Mkdir seeds: %v", err)
	}
	generation := uint64(31)
	listener := []byte("listener")
	listenerDigest := shaHex(listener)
	runnerManifest := seedarchive.RunnerTreeManifest{
		SchemaVersion: 1,
		Entries: []seedarchive.RunnerTreeEntry{
			{Path: "bin", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
			{
				Path: "bin/Runner.Listener", Type: seedarchive.RunnerEntryRegular,
				SHA256: listenerDigest, Size: uint64(len(listener)), Mode: 0o555,
			},
			{Path: "externals", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
		},
	}
	runnerManifestDocument, err := seedarchive.EncodeRunnerManifest(runnerManifest)
	if err != nil {
		t.Fatalf("EncodeRunnerManifest: %v", err)
	}
	runnerTreeLock := []byte("PGHAR-RUNNER-TREE-LOCK-V1\n")
	runnerProof := imageProof{
		generation:     generation,
		manifestDigest: shaHex(runnerManifestDocument),
		treeLockDigest: shaHex(runnerTreeLock),
	}
	pins := buildinfo.Pins()
	lock := runtimelock.Lock{
		SchemaVersion:         1,
		RunnerVersion:         pins.UpstreamRunner.Version,
		RunnerArchiveSHA256:   pins.UpstreamRunner.LinuxX64SHA256,
		RunnerSourceCommit:    pins.UpstreamRunner.SourceCommit,
		CommandSettingsSHA256: pins.UpstreamRunner.CommandSettingsSHA256,
		RunnerBaseImage:       pins.RunnerBaseImage,
		ManifestSHA256:        runnerProof.manifestDigest,
		TreeLockSHA256:        runnerProof.treeLockDigest,
		EvidenceGeneration:    generation,
		Listener: runtimelock.Listener{
			Path: "/opt/actions-runner/bin/Runner.Listener", SHA256: listenerDigest,
			Size: uint64(len(listener)), Mode: 0o555, UID: 0, GID: 0,
		},
	}
	lockDocument, err := runtimelock.Encode(lock)
	if err != nil {
		t.Fatalf("Encode runtime lock: %v", err)
	}
	runtimeLockDigest := shaHex(lockDocument)
	runnerReady := mustCanonicalJSON(t, runnerReadiness{
		SchemaVersion:      1,
		RuntimeLockSHA256:  runtimeLockDigest,
		TreeLockSHA256:     runnerProof.treeLockDigest,
		ManifestSHA256:     runnerProof.manifestDigest,
		EvidenceGeneration: generation,
	})

	seedManifest := seedarchive.Manifest{SchemaVersion: 1, Seeds: []seedarchive.Seed{}}
	seedManifestDocument, err := seedarchive.EncodeManifest(seedManifest)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	seedTreeLock := []byte("PGHAR-TREE-LOCK-V1\n")
	seedObject := seedManifestDocument[:len(seedManifestDocument)-1]
	seedProof := imageProof{
		generation:     generation,
		manifestDigest: shaHex(seedObject),
		treeLockDigest: shaHex(seedTreeLock),
	}
	seedReady := mustCanonicalJSON(t, seedReadiness{
		SchemaVersion:      1,
		ManifestSHA256:     seedProof.manifestDigest,
		TreeLockSHA256:     seedProof.treeLockDigest,
		EvidenceGeneration: generation,
		Empty:              true,
	})

	layout := verificationLayout{
		runnerRoot:        runnerRoot,
		runnerManifest:    filepath.Join(root, "runner.manifest.json"),
		runnerTreeLock:    filepath.Join(root, "runner.tree-lock"),
		runnerRuntimeLock: filepath.Join(root, "runner.runtime-lock.json"),
		runnerReady:       filepath.Join(root, "runner.READY"),
		seedRoot:          seedRoot,
		seedManifest:      filepath.Join(root, "seed.manifest.json"),
		seedTreeLock:      filepath.Join(root, "seed.tree-lock"),
		seedReady:         filepath.Join(root, "seed.READY"),
		expectedUID:       uint32(os.Geteuid()),
		expectedGID:       uint32(os.Getegid()),
	}
	for path, data := range map[string][]byte{
		layout.runnerManifest:    runnerManifestDocument,
		layout.runnerTreeLock:    runnerTreeLock,
		layout.runnerRuntimeLock: lockDocument,
		layout.runnerReady:       runnerReady,
		layout.seedManifest:      seedManifestDocument,
		layout.seedTreeLock:      seedTreeLock,
		layout.seedReady:         seedReady,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatalf("Chmod %s: %v", path, err)
		}
	}
	return imageLayoutFixture{
		layout: layout, generation: generation,
		runnerProof: runnerProof, seedProof: seedProof,
		runtimeLock: lock, runtimeLockDigest: runtimeLockDigest,
	}
}

func replaceLockedFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod final %s: %v", path, err)
	}
}

func mustCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return append(document, '\n')
}

func strings64(value string) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value[0]
	}
	return string(result)
}
