package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/runtimelock"
)

func TestRunPinsEmitsCanonicalRunnerAcquisitionPins(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pins"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run pins = %d, stderr=%q", code, stderr.String())
	}
	const expected = `{"schema_version":1,"runner_version":"v2.336.0","linux_x64_sha256":"04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d","source_commit":"98aabcd429c4e8402406c56ce2d26387fed3b9ce","command_settings_sha256":"937f6552579f7d1eeb0a6d0201586781eb3e2e5ea2ab3878429076560e0cab08","runner_base_image":"debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4"}` + "\n"
	if stdout.String() != expected || stderr.Len() != 0 {
		t.Fatalf("pins stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRunnerDownloadSpecDerivesCanonicalReleaseURLFromPins(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"runner-download-spec"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run runner-download-spec = %d, stderr=%q", code, stderr.String())
	}
	const expected = `{"schema_version":1,"source_url":"https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz","asset_name":"actions-runner-linux-x64-2.336.0.tar.gz","sha256":"04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d"}` + "\n"
	if stdout.String() != expected || stderr.Len() != 0 {
		t.Fatalf("download spec stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestValidateRunnerRedirectAcceptsOnlyBoundGitHubReleaseAsset(t *testing.T) {
	asset := "actions-runner-linux-x64-2.336.0.tar.gz"
	valid := "https://release-assets.githubusercontent.com/github-production-release-asset/184286875/4f75472f-4bf4-4f5e-b40a-660e7ceb303f" +
		"?response-content-disposition=attachment%3B%20filename%3D" + asset +
		"&response-content-type=application%2Foctet-stream&sig=public-release-signature"
	if got, err := validateRunnerRedirect(valid); err != nil || got != valid {
		t.Fatalf("validateRunnerRedirect valid got=%q err=%v", got, err)
	}

	tests := map[string]string{
		"http":                strings.Replace(valid, "https://", "http://", 1),
		"wrong host":          strings.Replace(valid, "release-assets.githubusercontent.com", "example.com", 1),
		"userinfo":            strings.Replace(valid, "https://", "https://user@", 1),
		"port":                strings.Replace(valid, ".com/", ".com:443/", 1),
		"fragment":            valid + "#fragment",
		"wrong repository":    strings.Replace(valid, "/184286875/", "/1/", 1),
		"wrong path family":   strings.Replace(valid, "github-production-release-asset", "other", 1),
		"encoded path":        strings.Replace(valid, "/4f75472f", "/%34f75472f", 1),
		"wrong filename":      strings.Replace(valid, asset, "actions-runner-linux-arm64-2.336.0.tar.gz", 1),
		"missing disposition": strings.Replace(valid, "response-content-disposition=", "other=", 1),
		"duplicate filename":  valid + "&response-content-disposition=attachment%3B%20filename%3D" + asset,
		"newline":             valid + "\n",
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := validateRunnerRedirect(candidate); err == nil {
				t.Fatal("validateRunnerRedirect accepted an unbound redirect")
			}
		})
	}
}

func TestRunValidateRunnerRedirectReadsBoundedStdinAndEmitsCanonicalURL(t *testing.T) {
	valid := "https://release-assets.githubusercontent.com/github-production-release-asset/184286875/4f75472f-4bf4-4f5e-b40a-660e7ceb303f" +
		"?response-content-disposition=attachment%3B%20filename%3Dactions-runner-linux-x64-2.336.0.tar.gz" +
		"&response-content-type=application%2Foctet-stream&sig=public-release-signature"
	var stdout, stderr bytes.Buffer
	if code := runWithInput([]string{"validate-runner-redirect"}, strings.NewReader(valid), &stdout, &stderr); code != 0 {
		t.Fatalf("validate-runner-redirect code=%d stderr=%q", code, stderr.String())
	}
	if stdout.String() != valid+"\n" || stderr.Len() != 0 {
		t.Fatalf("validate redirect stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	oversized := strings.Repeat("x", maxRunnerRedirectBytes+1)
	if code := runWithInput([]string{"validate-runner-redirect"}, strings.NewReader(oversized), &stdout, &stderr); code != 1 {
		t.Fatalf("oversized redirect code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestExtractRunnerRuntimePublishesVerifiedTreeAndBoundRuntimeLock(t *testing.T) {
	fixture := newRunnerTransactionFixture(t)
	defer removeRuntimeOutput(fixture.output)
	if err := extractRunnerRuntimeWith(extractOptions{
		archivePath:        fixture.archivePath,
		evidenceGeneration: fixture.generation,
		outputDirectory:    fixture.output,
	}, nil, fixture.extractor); err != nil {
		t.Fatalf("extractRunnerRuntimeWith: %v", err)
	}
	readyBytes, err := os.ReadFile(filepath.Join(fixture.output, "READY"))
	if err != nil {
		t.Fatalf("ReadFile READY: %v", err)
	}
	var ready readiness
	if err := json.Unmarshal(readyBytes, &ready); err != nil {
		t.Fatalf("READY json: %v", err)
	}
	if ready.SchemaVersion != 1 || ready.EvidenceGeneration != fixture.generation {
		t.Fatalf("READY = %+v", ready)
	}

	publishedRoot := filepath.Join(fixture.output, "runner")
	manifestFile, err := os.Open(filepath.Join(fixture.output, runnerManifestName))
	if err != nil {
		t.Fatalf("Open manifest: %v", err)
	}
	manifest, loadErr := seedarchive.LoadRunnerManifest(manifestFile)
	closeErr := manifestFile.Close()
	if loadErr != nil || closeErr != nil {
		t.Fatalf("Load manifest: %v, close=%v", loadErr, closeErr)
	}
	published, err := seedarchive.VerifyRunnerDirectory(publishedRoot, manifest, fixture.generation)
	if err != nil {
		t.Fatalf("VerifyRunnerDirectory published: %v", err)
	}
	if published.TreeLockDigest() != ready.TreeLockSHA256 || published.ManifestDigest() != ready.ManifestSHA256 {
		t.Fatalf("published digests do not match READY: %+v", ready)
	}

	lockBytes, err := os.ReadFile(filepath.Join(fixture.output, "runner.runtime-lock.json"))
	if err != nil {
		t.Fatalf("ReadFile runtime lock: %v", err)
	}
	lock, err := runtimelock.Load(bytes.NewReader(lockBytes))
	if err != nil {
		t.Fatalf("Load runtime lock: %v", err)
	}
	if lock.TreeLockSHA256 != published.TreeLockDigest() || lock.ManifestSHA256 != published.ManifestDigest() || lock.EvidenceGeneration != fixture.generation {
		t.Fatalf("runtime lock = %+v", lock)
	}
	if shaHexBytes(lockBytes) != ready.RuntimeLockSHA256 {
		t.Fatalf("runtime lock digest = %s, READY=%s", shaHexBytes(lockBytes), ready.RuntimeLockSHA256)
	}
	treeLockBytes, err := os.ReadFile(filepath.Join(fixture.output, "runner.tree-lock"))
	if err != nil {
		t.Fatalf("ReadFile tree lock: %v", err)
	}
	if shaHexBytes(treeLockBytes) != ready.TreeLockSHA256 {
		t.Fatalf("tree lock digest = %s, READY=%s", shaHexBytes(treeLockBytes), ready.TreeLockSHA256)
	}
	for _, relative := range []string{"READY", runnerManifestName, "runner.runtime-lock.json", "runner.tree-lock"} {
		info, err := os.Lstat(filepath.Join(fixture.output, relative))
		if err != nil || info.Mode().Perm() != 0o444 || !info.Mode().IsRegular() {
			t.Fatalf("%s identity = %v, %v", relative, info, err)
		}
	}
}

func TestExtractRunnerRuntimeWritesReadinessLastAndRemovesFailedTransaction(t *testing.T) {
	fixture := newRunnerTransactionFixture(t)
	observedBeforeReady := false
	err := extractRunnerRuntimeWith(extractOptions{
		archivePath:        fixture.archivePath,
		evidenceGeneration: fixture.generation,
		outputDirectory:    fixture.output,
	}, func(stage string) error {
		if stage != "before-ready" {
			return nil
		}
		observedBeforeReady = true
		if _, err := os.Lstat(filepath.Join(fixture.output, "READY")); !os.IsNotExist(err) {
			t.Fatalf("READY existed before final stage: %v", err)
		}
		for _, relative := range []string{"runner", runnerManifestName, "runner.runtime-lock.json", "runner.tree-lock"} {
			if _, err := os.Lstat(filepath.Join(fixture.output, relative)); err != nil {
				t.Fatalf("%s missing before READY: %v", relative, err)
			}
		}
		return errors.New("injected final failure")
	}, fixture.extractor)
	if err == nil || !observedBeforeReady {
		t.Fatalf("extractRunnerRuntimeWith = %v, observed=%v", err, observedBeforeReady)
	}
	if _, err := os.Lstat(fixture.output); !os.IsNotExist(err) {
		t.Fatalf("failed transaction remained: %v", err)
	}
}

func TestExtractRunnerRuntimeRejectsExistingOutputAndWrongAssetName(t *testing.T) {
	fixture := newRunnerTransactionFixture(t)
	if err := os.Mkdir(fixture.output, 0o700); err != nil {
		t.Fatalf("Mkdir output: %v", err)
	}
	if err := extractRunnerRuntimeWith(extractOptions{
		archivePath:        fixture.archivePath,
		evidenceGeneration: fixture.generation,
		outputDirectory:    fixture.output,
	}, nil, fixture.extractor); err == nil {
		t.Fatal("extractRunnerRuntimeWith accepted an existing output")
	}

	secondOutput := filepath.Join(filepath.Dir(fixture.output), "second-output")
	if err := extractRunnerRuntimeWith(extractOptions{
		archivePath:        filepath.Join(filepath.Dir(fixture.archivePath), "wrong-platform.tar.gz"),
		evidenceGeneration: fixture.generation,
		outputDirectory:    secondOutput,
	}, nil, fixture.extractor); err == nil {
		t.Fatal("extractRunnerRuntimeWith accepted a wrong asset name")
	}
	if _, err := os.Lstat(secondOutput); !os.IsNotExist(err) {
		t.Fatalf("indirect-source failure created output: %v", err)
	}
}

func TestRunExtractRunnerRejectsIncompleteArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"extract-runner", "--generation", "1"}, &stdout, &stderr); code != 2 {
		t.Fatalf("extract-runner incomplete code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStageSeedsPublishesVerifiedNonemptyAndExplicitEmptyCaches(t *testing.T) {
	t.Run("nonempty", func(t *testing.T) {
		fixture := newRuntimeLockFixture(t)
		var stdout, stderr bytes.Buffer
		code := run([]string{
			"stage-seeds",
			"--root", fixture.root,
			"--manifest", fixture.manifestPath,
			"--generation", strconv.FormatUint(fixture.generation, 10),
			"--output-dir", fixture.output,
		}, &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("stage-seeds code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		var ready seedReadiness
		if err := json.Unmarshal(stdout.Bytes(), &ready); err != nil {
			t.Fatalf("seed READY: %v", err)
		}
		if ready.Empty || ready.EvidenceGeneration != fixture.generation {
			t.Fatalf("seed READY=%+v", ready)
		}
		if _, err := os.Lstat(filepath.Join(fixture.output, runtimeLockName)); !os.IsNotExist(err) {
			t.Fatalf("seed stage emitted runner runtime lock: %v", err)
		}
		if data, err := os.ReadFile(filepath.Join(fixture.output, "seed-cache", "bin", "Runner.Listener")); err != nil || string(data) != "runner-listener" {
			t.Fatalf("staged listener=%q err=%v", data, err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		parent := canonicalTestDir(t)
		output := filepath.Join(parent, "empty-seeds")
		var stdout, stderr bytes.Buffer
		code := run([]string{
			"stage-seeds",
			"--generation", "23",
			"--output-dir", output,
		}, &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("stage empty code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		var ready seedReadiness
		if err := json.Unmarshal(stdout.Bytes(), &ready); err != nil {
			t.Fatalf("empty READY: %v", err)
		}
		if !ready.Empty || ready.EvidenceGeneration != 23 {
			t.Fatalf("empty READY=%+v", ready)
		}
		manifestBytes, err := os.ReadFile(filepath.Join(output, seedManifestName))
		if err != nil || string(manifestBytes) != `{"schema_version":1,"seeds":[]}`+"\n" {
			t.Fatalf("empty manifest=%q err=%v", manifestBytes, err)
		}
		entries, err := os.ReadDir(filepath.Join(output, seedCacheDirectory))
		if err != nil || len(entries) != 0 {
			t.Fatalf("empty seed cache entries=%v err=%v", entries, err)
		}
	})
}

func TestStageSeedsRejectsPartialSourcePair(t *testing.T) {
	parent := canonicalTestDir(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"stage-seeds",
		"--root", parent,
		"--generation", "1",
		"--output-dir", filepath.Join(parent, "output"),
	}, &stdout, &stderr); code != 2 {
		t.Fatalf("partial stage-seeds code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

type runnerTransactionFixture struct {
	archivePath string
	output      string
	generation  uint64
	extractor   runnerExtractor
}

func newRunnerTransactionFixture(t *testing.T) runnerTransactionFixture {
	t.Helper()
	parent := canonicalTestDir(t)
	archivePath := filepath.Join(parent, "actions-runner-linux-x64-2.336.0.tar.gz")
	listener := []byte("runner-listener")
	manifest := seedarchive.RunnerTreeManifest{
		SchemaVersion: 1,
		Entries: []seedarchive.RunnerTreeEntry{
			{Path: "bin", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
			{Path: "bin/Runner.Listener", Type: seedarchive.RunnerEntryRegular, SHA256: shaHexBytes(listener), Size: uint64(len(listener)), Mode: 0o555},
			{Path: "externals", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
		},
	}
	extractor := func(options seedarchive.RunnerExtractOptions) (seedarchive.VerifiedRunnerDirectory, error) {
		if options.ArchivePath != archivePath ||
			options.ExpectedSHA256 != "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d" ||
			options.EvidenceGeneration == 0 {
			return seedarchive.VerifiedRunnerDirectory{}, errors.New("fixture: extraction options invalid")
		}
		if err := os.Mkdir(options.OutputDirectory, 0o700); err != nil {
			return seedarchive.VerifiedRunnerDirectory{}, err
		}
		for _, directory := range []string{"bin", "externals"} {
			path := filepath.Join(options.OutputDirectory, directory)
			if err := os.Mkdir(path, 0o700); err != nil {
				return seedarchive.VerifiedRunnerDirectory{}, err
			}
		}
		listenerPath := filepath.Join(options.OutputDirectory, "bin", "Runner.Listener")
		if err := os.WriteFile(listenerPath, listener, 0o600); err != nil {
			return seedarchive.VerifiedRunnerDirectory{}, err
		}
		if err := os.Chmod(listenerPath, 0o555); err != nil {
			return seedarchive.VerifiedRunnerDirectory{}, err
		}
		for _, directory := range []string{"bin", "externals"} {
			if err := os.Chmod(filepath.Join(options.OutputDirectory, directory), 0o555); err != nil {
				return seedarchive.VerifiedRunnerDirectory{}, err
			}
		}
		return seedarchive.VerifyRunnerDirectory(options.OutputDirectory, manifest, options.EvidenceGeneration)
	}
	return runnerTransactionFixture{
		archivePath: archivePath,
		output:      filepath.Join(parent, "runtime-output"),
		generation:  17,
		extractor:   extractor,
	}
}

type runtimeLockFixture struct {
	root         string
	manifestPath string
	output       string
	generation   uint64
}

func newRuntimeLockFixture(t *testing.T) runtimeLockFixture {
	t.Helper()
	parent := canonicalTestDir(t)
	root := filepath.Join(parent, "runner-source")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatalf("Mkdir bin: %v", err)
	}
	listener := []byte("runner-listener")
	license := []byte("license")
	for path, contents := range map[string][]byte{
		filepath.Join(root, "LICENSE"):                license,
		filepath.Join(root, "bin", "Runner.Listener"): listener,
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		mode := os.FileMode(0o444)
		if strings.HasSuffix(path, "Runner.Listener") {
			mode = 0o555
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod %s: %v", path, err)
		}
	}
	manifest := seedarchive.Manifest{
		SchemaVersion: 1,
		Seeds: []seedarchive.Seed{{
			ID:       "github-actions-runner",
			Kind:     seedarchive.KindTool,
			Source:   "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz",
			Revision: "v2.336.0",
			License: seedarchive.LicenseEvidence{
				SPDX: "MIT", Path: "LICENSE", Size: uint64(len(license)), SHA256: shaHexBytes(license),
			},
			Files: []seedarchive.File{
				{Path: "LICENSE", Target: "tools/github-actions-runner/v2.336.0/LICENSE", SHA256: shaHexBytes(license), Size: uint64(len(license)), Mode: 0o444},
				{Path: "bin/Runner.Listener", Target: "tools/github-actions-runner/v2.336.0/bin/Runner.Listener", SHA256: shaHexBytes(listener), Size: uint64(len(listener)), Mode: 0o555},
			},
		}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	manifestPath := filepath.Join(parent, "manifest.json")
	if err := os.WriteFile(manifestPath, append(manifestBytes, '\n'), 0o400); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
	return runtimeLockFixture{
		root:         root,
		manifestPath: manifestPath,
		output:       filepath.Join(parent, "runtime-output"),
		generation:   17,
	}
}

func canonicalTestDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod temp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(directory, 0o700)
		_ = filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return directory
}

func shaHexBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
