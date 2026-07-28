// Command portable-ghar-runtime-lock emits canonical runner acquisition pins
// and publishes one OS-identity-verified runner tree into a new immutable
// build context. READY is the final transaction marker.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/runtimelock"
	"golang.org/x/sys/unix"
)

const (
	runtimeLockName    = "runner.runtime-lock.json"
	runnerManifestName = "runner.tree-manifest.json"
	treeLockName       = "runner.tree-lock"
	readyName          = "READY"
	seedCacheDirectory = "seed-cache"
	seedManifestName   = "seed-cache.manifest.json"
	seedTreeLockName   = "seed-cache.tree-lock"
)

type acquisitionPins struct {
	SchemaVersion         uint32 `json:"schema_version"`
	RunnerVersion         string `json:"runner_version"`
	LinuxX64SHA256        string `json:"linux_x64_sha256"`
	SourceCommit          string `json:"source_commit"`
	CommandSettingsSHA256 string `json:"command_settings_sha256"`
	RunnerBaseImage       string `json:"runner_base_image"`
}

type readiness struct {
	SchemaVersion      uint32 `json:"schema_version"`
	RuntimeLockSHA256  string `json:"runtime_lock_sha256"`
	TreeLockSHA256     string `json:"tree_lock_sha256"`
	ManifestSHA256     string `json:"manifest_sha256"`
	EvidenceGeneration uint64 `json:"evidence_generation"`
}

type extractOptions struct {
	archivePath        string
	evidenceGeneration uint64
	outputDirectory    string
}

type extractHook func(stage string) error
type runnerExtractor func(seedarchive.RunnerExtractOptions) (seedarchive.VerifiedRunnerDirectory, error)

func run(args []string, stdout, stderr io.Writer) int {
	return runWithInput(args, os.Stdin, stdout, stderr)
}

func runWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil || len(args) == 0 {
		return unavailable(stderr, 2)
	}
	switch args[0] {
	case "pins":
		if len(args) != 1 {
			return unavailable(stderr, 2)
		}
		pins := buildinfo.Pins()
		document, err := encodeCanonical(acquisitionPins{
			SchemaVersion:         1,
			RunnerVersion:         pins.UpstreamRunner.Version,
			LinuxX64SHA256:        pins.UpstreamRunner.LinuxX64SHA256,
			SourceCommit:          pins.UpstreamRunner.SourceCommit,
			CommandSettingsSHA256: pins.UpstreamRunner.CommandSettingsSHA256,
			RunnerBaseImage:       pins.RunnerBaseImage,
		})
		if err != nil {
			return unavailable(stderr, 1)
		}
		if _, err := stdout.Write(document); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	case "runner-download-spec":
		if len(args) != 1 {
			return unavailable(stderr, 2)
		}
		spec, err := currentRunnerDownloadSpec()
		if err != nil {
			return unavailable(stderr, 1)
		}
		document, err := encodeCanonical(spec)
		if err != nil {
			return unavailable(stderr, 1)
		}
		if _, err := stdout.Write(document); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	case "validate-runner-redirect":
		if len(args) != 1 || stdin == nil {
			return unavailable(stderr, 2)
		}
		data, err := io.ReadAll(io.LimitReader(stdin, maxRunnerRedirectBytes+1))
		if err != nil {
			return unavailable(stderr, 1)
		}
		redirect, err := validateRunnerRedirect(string(data))
		if err != nil {
			return unavailable(stderr, 1)
		}
		if _, err := fmt.Fprintln(stdout, redirect); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	case "extract-runner":
		options, err := parseExtractOptions(args[1:])
		if err != nil {
			return unavailable(stderr, 2)
		}
		if err := extractRunnerRuntime(options, nil); err != nil {
			return unavailable(stderr, 1)
		}
		ready, err := os.ReadFile(filepath.Join(options.outputDirectory, readyName))
		if err != nil {
			return unavailable(stderr, 1)
		}
		if _, err := stdout.Write(ready); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	case "stage-seeds":
		options, err := parseStageSeedOptions(args[1:])
		if err != nil {
			return unavailable(stderr, 2)
		}
		if err := stageSeedCache(options); err != nil {
			return unavailable(stderr, 1)
		}
		ready, err := os.ReadFile(filepath.Join(options.outputDirectory, readyName))
		if err != nil {
			return unavailable(stderr, 1)
		}
		if _, err := stdout.Write(ready); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	default:
		return unavailable(stderr, 2)
	}
}

func unavailable(stderr io.Writer, code int) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-runtime-lock: unavailable")
	}
	return code
}

func parseExtractOptions(args []string) (extractOptions, error) {
	if len(args) != 6 {
		return extractOptions{}, errors.New("runtime-lock: extract arguments invalid")
	}
	values := make(map[string]string, 3)
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		switch name {
		case "--archive", "--generation", "--output-dir":
		default:
			return extractOptions{}, errors.New("runtime-lock: extract argument unknown")
		}
		if value == "" {
			return extractOptions{}, errors.New("runtime-lock: extract argument empty")
		}
		if _, exists := values[name]; exists {
			return extractOptions{}, errors.New("runtime-lock: extract argument duplicated")
		}
		values[name] = value
	}
	if len(values) != 3 {
		return extractOptions{}, errors.New("runtime-lock: extract arguments incomplete")
	}
	generation, err := strconv.ParseUint(values["--generation"], 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != values["--generation"] {
		return extractOptions{}, errors.New("runtime-lock: generation invalid")
	}
	return extractOptions{
		archivePath:        values["--archive"],
		evidenceGeneration: generation,
		outputDirectory:    values["--output-dir"],
	}, nil
}

func extractRunnerRuntime(options extractOptions, hook extractHook) error {
	return extractRunnerRuntimeWith(options, hook, seedarchive.ExtractRunnerArchive)
}

func extractRunnerRuntimeWith(options extractOptions, hook extractHook, extractor runnerExtractor) error {
	if options.evidenceGeneration == 0 ||
		!canonicalAbsolute(options.archivePath) ||
		!canonicalAbsolute(options.outputDirectory) || extractor == nil {
		return errors.New("runtime-lock: extract inputs invalid")
	}
	outputParent := filepath.Dir(options.outputDirectory)
	if err := validatePrivateDirectory(outputParent); err != nil {
		return err
	}
	if _, err := os.Lstat(options.outputDirectory); !os.IsNotExist(err) {
		return errors.New("runtime-lock: output already exists or cannot be inspected")
	}

	if err := os.Mkdir(options.outputDirectory, 0o700); err != nil {
		return errors.New("runtime-lock: output create failed")
	}
	committed := false
	defer func() {
		if !committed {
			removeRuntimeOutput(options.outputDirectory)
		}
	}()
	if err := validatePrivateDirectory(options.outputDirectory); err != nil {
		return err
	}

	pins := buildinfo.Pins()
	expectedAsset := "actions-runner-linux-x64-" + strings.TrimPrefix(pins.UpstreamRunner.Version, "v") + ".tar.gz"
	if filepath.Base(options.archivePath) != expectedAsset {
		return errors.New("runtime-lock: runner archive asset name invalid")
	}
	publishedRoot := filepath.Join(options.outputDirectory, "runner")
	published, err := extractor(seedarchive.RunnerExtractOptions{
		ArchivePath:        options.archivePath,
		ExpectedSHA256:     pins.UpstreamRunner.LinuxX64SHA256,
		EvidenceGeneration: options.evidenceGeneration,
		OutputDirectory:    publishedRoot,
	})
	if err != nil {
		return errors.New("runtime-lock: runner extraction failed")
	}

	var manifest bytes.Buffer
	if err := seedarchive.WriteRunnerManifest(&manifest, published); err != nil ||
		shaHex(manifest.Bytes()) != published.ManifestDigest() {
		return errors.New("runtime-lock: runner manifest generation failed")
	}
	if err := writeVerifiedFile(filepath.Join(options.outputDirectory, runnerManifestName), manifest.Bytes(), 0o444); err != nil {
		return err
	}

	var treeLock bytes.Buffer
	if err := seedarchive.WriteRunnerTreeLock(&treeLock, published); err != nil ||
		shaHex(treeLock.Bytes()) != published.TreeLockDigest() {
		return errors.New("runtime-lock: tree lock generation failed")
	}
	if err := writeVerifiedFile(filepath.Join(options.outputDirectory, treeLockName), treeLock.Bytes(), 0o444); err != nil {
		return err
	}

	lock, err := runtimelock.NewRunnerLock(published, "bin/Runner.Listener")
	if err != nil {
		return errors.New("runtime-lock: runner lock construction failed")
	}
	lockDocument, err := runtimelock.Encode(lock)
	if err != nil {
		return errors.New("runtime-lock: runner lock encoding failed")
	}
	if _, err := runtimelock.Load(bytes.NewReader(lockDocument)); err != nil {
		return errors.New("runtime-lock: runner lock readback failed")
	}
	if err := writeVerifiedFile(filepath.Join(options.outputDirectory, runtimeLockName), lockDocument, 0o444); err != nil {
		return err
	}

	loadedManifest, err := seedarchive.LoadRunnerManifest(bytes.NewReader(manifest.Bytes()))
	if err != nil {
		return errors.New("runtime-lock: runner manifest readback failed")
	}
	finalPublished, err := seedarchive.VerifyRunnerDirectory(publishedRoot, loadedManifest, options.evidenceGeneration)
	if err != nil ||
		finalPublished.ManifestDigest() != published.ManifestDigest() ||
		finalPublished.TreeLockDigest() != published.TreeLockDigest() {
		return errors.New("runtime-lock: published runner changed")
	}
	if hook != nil {
		if err := hook("before-ready"); err != nil {
			return errors.New("runtime-lock: readiness hook failed")
		}
	}
	readyDocument, err := encodeCanonical(readiness{
		SchemaVersion:      1,
		RuntimeLockSHA256:  shaHex(lockDocument),
		TreeLockSHA256:     published.TreeLockDigest(),
		ManifestSHA256:     published.ManifestDigest(),
		EvidenceGeneration: options.evidenceGeneration,
	})
	if err != nil {
		return errors.New("runtime-lock: readiness encoding failed")
	}
	if err := writeVerifiedFile(filepath.Join(options.outputDirectory, readyName), readyDocument, 0o444); err != nil {
		return err
	}
	if err := syncDirectory(options.outputDirectory); err != nil || syncDirectory(outputParent) != nil {
		return errors.New("runtime-lock: publication sync failed")
	}
	committed = true
	return nil
}

func removeRuntimeOutput(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		fd, openErr := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr == nil {
			_ = unix.Fchmod(fd, 0o700)
			_ = unix.Close(fd)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}

func canonicalAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

func pathsOverlap(left, right string) bool {
	separator := string(filepath.Separator)
	return left == right ||
		strings.HasPrefix(left, right+separator) ||
		strings.HasPrefix(right, left+separator)
}

func validatePrivateDirectory(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("runtime-lock: private directory indirect")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("runtime-lock: private directory invalid")
	}
	return nil
}

func loadCanonicalManifest(path string) (seedarchive.Manifest, error) {
	if !canonicalAbsolute(path) {
		return seedarchive.Manifest{}, errors.New("runtime-lock: manifest path invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return seedarchive.Manifest{}, errors.New("runtime-lock: manifest path indirect")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return seedarchive.Manifest{}, errors.New("runtime-lock: manifest identity invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return seedarchive.Manifest{}, errors.New("runtime-lock: manifest open failed")
	}
	file := os.NewFile(uintptr(fd), "runner-manifest")
	if file == nil {
		_ = unix.Close(fd)
		return seedarchive.Manifest{}, errors.New("runtime-lock: manifest descriptor invalid")
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return seedarchive.Manifest{}, errors.New("runtime-lock: manifest identity changed")
	}
	manifest, loadErr := seedarchive.Load(file)
	after, afterErr := file.Stat()
	closeErr := file.Close()
	pathAfter, pathErr := os.Lstat(path)
	if loadErr != nil || afterErr != nil || closeErr != nil || pathErr != nil ||
		!os.SameFile(before, after) || !os.SameFile(before, pathAfter) ||
		before.Size() != after.Size() || before.Mode() != after.Mode() ||
		!before.ModTime().Equal(after.ModTime()) {
		return seedarchive.Manifest{}, errors.New("runtime-lock: manifest changed or invalid")
	}
	return manifest, nil
}

func writeVerifiedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("runtime-lock: output file create failed")
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	chmodErr := file.Chmod(mode)
	secondSyncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || chmodErr != nil || secondSyncErr != nil || closeErr != nil || written != len(data) {
		return errors.New("runtime-lock: output file write failed")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode.Perm() ||
		info.Size() != int64(len(data)) {
		return errors.New("runtime-lock: output file readback invalid")
	}
	readback, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(readback, data) {
		return errors.New("runtime-lock: output file content changed")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func encodeCanonical(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(document, '\n'), nil
}

func shaHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
