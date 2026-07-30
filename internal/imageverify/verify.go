// Package imageverify binds an installed runner image to the immutable runner,
// seed, runtime-lock, and readiness tuple produced by the build transaction.
// Its proof is deliberately build-local and cannot authorize publication.
package imageverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/runtimelock"
	"golang.org/x/sys/unix"
)

const (
	maxRunnerManifestBytes = 8 << 20
	maxSeedManifestBytes   = 1 << 20
	maxTreeLockBytes       = 16 << 20
	maxRuntimeLockBytes    = 64 << 10
	maxReadinessBytes      = 64 << 10
)

type runnerReadiness struct {
	SchemaVersion      uint32 `json:"schema_version"`
	RuntimeLockSHA256  string `json:"runtime_lock_sha256"`
	TreeLockSHA256     string `json:"tree_lock_sha256"`
	ManifestSHA256     string `json:"manifest_sha256"`
	EvidenceGeneration uint64 `json:"evidence_generation"`
}

type seedReadiness struct {
	SchemaVersion      uint32 `json:"schema_version"`
	ManifestSHA256     string `json:"manifest_sha256"`
	TreeLockSHA256     string `json:"tree_lock_sha256"`
	EvidenceGeneration uint64 `json:"evidence_generation"`
	Empty              bool   `json:"empty"`
}

type imageProof struct {
	generation     uint64
	manifestDigest string
	treeLockDigest string
}

type verificationBackends struct {
	runner func(string, seedarchive.RunnerTreeManifest, uint64) (imageProof, error)
	seed   func(string, seedarchive.Manifest, uint64) (imageProof, error)
}

type verificationLayout struct {
	runnerRoot        string
	runnerManifest    string
	runnerTreeLock    string
	runnerRuntimeLock string
	runnerReady       string
	seedRoot          string
	seedManifest      string
	seedTreeLock      string
	seedReady         string
	expectedUID       uint32
	expectedGID       uint32
}

// VerifyInstalledRunnerImage verifies the fixed runner image layout. It is
// intended to run as one root-owned Docker build step before the final USER.
func VerifyInstalledRunnerImage() error {
	return verifyInstalledRunnerImage(false)
}

// VerifyInstalledRunnerImageWithDiagnosticsOverlay verifies the final sealed
// image shape. It requires the sole diagnostics overlay while binding the
// original manifest and tree-lock tuple.
func VerifyInstalledRunnerImageWithDiagnosticsOverlay() error {
	return verifyInstalledRunnerImage(true)
}

func verifyInstalledRunnerImage(withDiagnosticsOverlay bool) error {
	layout := verificationLayout{
		runnerRoot:        "/opt/actions-runner",
		runnerManifest:    "/opt/portable-ghar/runner.tree-manifest.json",
		runnerTreeLock:    "/opt/portable-ghar/runner.tree-lock",
		runnerRuntimeLock: "/opt/portable-ghar/runner.runtime-lock.json",
		runnerReady:       "/opt/portable-ghar/runner.READY",
		seedRoot:          "/opt/portable-ghar/seed-cache",
		seedManifest:      "/opt/portable-ghar/seed-cache.manifest.json",
		seedTreeLock:      "/opt/portable-ghar/seed-cache.tree-lock",
		seedReady:         "/opt/portable-ghar/seed-cache.READY",
		expectedUID:       0,
		expectedGID:       0,
	}
	backends := verificationBackends{
		runner: func(root string, manifest seedarchive.RunnerTreeManifest, generation uint64) (imageProof, error) {
			var verified seedarchive.RunnerImageVerification
			var err error
			if withDiagnosticsOverlay {
				verified, err = seedarchive.VerifyRunnerImageDirectoryWithDiagnosticsOverlay(
					root,
					manifest,
					generation,
				)
			} else {
				verified, err = seedarchive.VerifyRunnerImageDirectory(
					root,
					manifest,
					generation,
				)
			}
			if err != nil {
				return imageProof{}, err
			}
			return imageProof{
				generation: verified.Generation(), manifestDigest: verified.ManifestDigest(),
				treeLockDigest: verified.TreeLockDigest(),
			}, nil
		},
		seed: func(root string, manifest seedarchive.Manifest, generation uint64) (imageProof, error) {
			verified, err := seedarchive.VerifySeedImageDirectory(root, manifest, generation)
			if err != nil {
				return imageProof{}, err
			}
			return imageProof{
				generation: verified.Generation(), manifestDigest: verified.ManifestDigest(),
				treeLockDigest: verified.TreeLockDigest(),
			}, nil
		},
	}
	return verifyImageLayout(layout, backends)
}

func verifyImageLayout(layout verificationLayout, backends verificationBackends) error {
	if backends.runner == nil || backends.seed == nil || !validLayout(layout) {
		return errors.New("imageverify: verification inputs invalid")
	}

	runnerReadyBytes, err := readLockedFile(
		layout.runnerReady, maxReadinessBytes, layout.expectedUID, layout.expectedGID,
	)
	if err != nil {
		return err
	}
	var runnerReady runnerReadiness
	if err := decodeCanonical(runnerReadyBytes, &runnerReady); err != nil ||
		runnerReady.SchemaVersion != 1 || runnerReady.EvidenceGeneration == 0 ||
		!hex64(runnerReady.RuntimeLockSHA256) ||
		!hex64(runnerReady.TreeLockSHA256) ||
		!hex64(runnerReady.ManifestSHA256) {
		return errors.New("imageverify: runner readiness invalid")
	}

	runnerManifestBytes, err := readLockedFile(
		layout.runnerManifest, maxRunnerManifestBytes, layout.expectedUID, layout.expectedGID,
	)
	if err != nil {
		return err
	}
	runnerManifest, err := seedarchive.LoadRunnerManifest(bytes.NewReader(runnerManifestBytes))
	if err != nil {
		return errors.New("imageverify: runner manifest invalid")
	}
	runnerTreeLock, err := readLockedFile(
		layout.runnerTreeLock, maxTreeLockBytes, layout.expectedUID, layout.expectedGID,
	)
	if err != nil {
		return err
	}
	runtimeLockBytes, err := readLockedFile(
		layout.runnerRuntimeLock, maxRuntimeLockBytes, layout.expectedUID, layout.expectedGID,
	)
	if err != nil {
		return err
	}
	runtimeLock, err := runtimelock.Load(bytes.NewReader(runtimeLockBytes))
	if err != nil {
		return errors.New("imageverify: runner runtime lock invalid")
	}
	if runtimeLock.EvidenceGeneration != runnerReady.EvidenceGeneration {
		return errors.New("imageverify: runner generation differs")
	}
	runnerProof, err := backends.runner(
		layout.runnerRoot,
		runnerManifest,
		runnerReady.EvidenceGeneration,
	)
	if err != nil {
		return errors.New("imageverify: installed runner identity invalid")
	}
	if runnerProof.generation != runnerReady.EvidenceGeneration ||
		runnerProof.manifestDigest != runnerReady.ManifestSHA256 ||
		runnerProof.treeLockDigest != runnerReady.TreeLockSHA256 ||
		runtimeLock.ManifestSHA256 != runnerProof.manifestDigest ||
		runtimeLock.TreeLockSHA256 != runnerProof.treeLockDigest ||
		shaHex(runnerTreeLock) != runnerProof.treeLockDigest ||
		shaHex(runtimeLockBytes) != runnerReady.RuntimeLockSHA256 ||
		!runtimeListenerMatchesManifest(runtimeLock, runnerManifest) {
		return errors.New("imageverify: runner tuple differs")
	}

	seedReadyBytes, err := readLockedFile(
		layout.seedReady, maxReadinessBytes, layout.expectedUID, layout.expectedGID,
	)
	if err != nil {
		return err
	}
	var seedReady seedReadiness
	if err := decodeCanonical(seedReadyBytes, &seedReady); err != nil ||
		seedReady.SchemaVersion != 1 || seedReady.EvidenceGeneration == 0 ||
		!hex64(seedReady.TreeLockSHA256) ||
		!hex64(seedReady.ManifestSHA256) {
		return errors.New("imageverify: seed readiness invalid")
	}
	seedManifestBytes, err := readLockedFile(
		layout.seedManifest, maxSeedManifestBytes, layout.expectedUID, layout.expectedGID,
	)
	if err != nil {
		return err
	}
	seedManifest, err := seedarchive.Load(bytes.NewReader(seedManifestBytes))
	if err != nil {
		return errors.New("imageverify: seed manifest invalid")
	}
	seedTreeLock, err := readLockedFile(
		layout.seedTreeLock, maxTreeLockBytes, layout.expectedUID, layout.expectedGID,
	)
	if err != nil {
		return err
	}
	if seedReady.EvidenceGeneration != runnerReady.EvidenceGeneration ||
		seedReady.Empty != (len(seedManifest.Seeds) == 0) {
		return errors.New("imageverify: seed readiness differs")
	}
	seedProof, err := backends.seed(
		layout.seedRoot,
		seedManifest,
		seedReady.EvidenceGeneration,
	)
	if err != nil {
		return errors.New("imageverify: installed seed identity invalid")
	}
	if seedProof.generation != seedReady.EvidenceGeneration ||
		seedProof.manifestDigest != seedReady.ManifestSHA256 ||
		seedProof.treeLockDigest != seedReady.TreeLockSHA256 ||
		shaHex(seedTreeLock) != seedProof.treeLockDigest {
		return errors.New("imageverify: seed tuple differs")
	}
	return nil
}

func validLayout(layout verificationLayout) bool {
	seen := make(map[string]struct{}, 9)
	for _, candidate := range []string{
		layout.runnerRoot,
		layout.runnerManifest,
		layout.runnerTreeLock,
		layout.runnerRuntimeLock,
		layout.runnerReady,
		layout.seedRoot,
		layout.seedManifest,
		layout.seedTreeLock,
		layout.seedReady,
	} {
		if !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate ||
			strings.IndexByte(candidate, 0) >= 0 {
			return false
		}
		if _, duplicate := seen[candidate]; duplicate {
			return false
		}
		seen[candidate] = struct{}{}
	}
	return true
}

func readLockedFile(path string, limit int64, expectedUID, expectedGID uint32) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("imageverify: metadata limit invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("imageverify: metadata path indirect")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("imageverify: metadata open failed")
	}
	file := os.NewFile(uintptr(fd), "image-metadata")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("imageverify: metadata descriptor invalid")
	}
	var beforeStat unix.Stat_t
	if unix.Fstat(fd, &beforeStat) != nil {
		_ = file.Close()
		return nil, errors.New("imageverify: metadata fstat failed")
	}
	before := identityFromStat(&beforeStat)
	if before.mode&unix.S_IFMT != unix.S_IFREG ||
		before.mode&0o777 != 0o444 ||
		before.uid != expectedUID || before.gid != expectedGID ||
		before.nlink != 1 || before.size <= 0 || before.size > limit {
		_ = file.Close()
		return nil, errors.New("imageverify: metadata identity invalid")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	var afterStat unix.Stat_t
	statErr := unix.Fstat(fd, &afterStat)
	closeErr := file.Close()
	after := identityFromStat(&afterStat)
	var pathStat unix.Stat_t
	pathErr := unix.Lstat(path, &pathStat)
	pathIdentity := identityFromStat(&pathStat)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil ||
		int64(len(data)) != before.size ||
		!before.stableEqual(after) || !before.stableEqual(pathIdentity) {
		return nil, errors.New("imageverify: metadata changed during read")
	}
	return data, nil
}

func decodeCanonical(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("imageverify: metadata json invalid")
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return errors.New("imageverify: metadata json encode failed")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return errors.New("imageverify: metadata json noncanonical")
	}
	return nil
}

func runtimeListenerMatchesManifest(lock runtimelock.Lock, manifest seedarchive.RunnerTreeManifest) bool {
	for _, entry := range manifest.Entries {
		if entry.Path != "bin/Runner.Listener" {
			continue
		}
		return entry.Type == seedarchive.RunnerEntryRegular &&
			lock.Listener.Path == "/opt/actions-runner/bin/Runner.Listener" &&
			lock.Listener.SHA256 == entry.SHA256 &&
			lock.Listener.Size == entry.Size &&
			lock.Listener.Mode == entry.Mode &&
			lock.Listener.UID == 0 && lock.Listener.GID == 0
	}
	return false
}

func hex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func shaHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
