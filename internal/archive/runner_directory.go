package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type VerifiedRunnerDirectory struct {
	root               string
	rootDevice         uint64
	rootInode          uint64
	rootUID            uint32
	rootGID            uint32
	manifestDigest     [sha256.Size]byte
	treeLockDigest     [sha256.Size]byte
	treeLock           []byte
	files              map[string]RunnerTreeEntry
	symlinks           map[string]RunnerTreeEntry
	manifest           RunnerTreeManifest
	evidenceGeneration uint64
}

// RunnerImageVerification is non-authorizing evidence that one installed,
// root-owned runner tree matches a prior manifest. It cannot be used to
// publish, extract, or emit staging authority.
type RunnerImageVerification struct {
	manifestDigest     [sha256.Size]byte
	treeLockDigest     [sha256.Size]byte
	evidenceGeneration uint64
}

type runnerDirectoryAuthority interface {
	runnerDirectoryAuthority()
}

type runnerImageEvidence interface {
	runnerImageEvidence()
}

type runnerDirectoryOverlay struct {
	diagnosticsSeen bool
}

const (
	runnerDiagnosticsOverlayPath   = "_diag"
	runnerDiagnosticsOverlayTarget = "/runner/_diag"
)

func (VerifiedRunnerDirectory) runnerDirectoryAuthority() {}
func (RunnerImageVerification) runnerImageEvidence()      {}

func (v VerifiedRunnerDirectory) Generation() uint64     { return v.evidenceGeneration }
func (v VerifiedRunnerDirectory) ManifestDigest() string { return hexDigest(v.manifestDigest) }
func (v VerifiedRunnerDirectory) TreeLockDigest() string { return hexDigest(v.treeLockDigest) }

func (v RunnerImageVerification) Generation() uint64 { return v.evidenceGeneration }
func (v RunnerImageVerification) ManifestDigest() string {
	return hexDigest(v.manifestDigest)
}
func (v RunnerImageVerification) TreeLockDigest() string {
	return hexDigest(v.treeLockDigest)
}

type VerifiedSymlink struct {
	Target string
	SHA256 string
	Size   uint64
	Mode   uint32
}

func (v VerifiedRunnerDirectory) File(relative string) (VerifiedFile, error) {
	if !validRunnerAuthority(v) {
		return VerifiedFile{}, errors.New("archive: verified runner authority required")
	}
	entry, ok := v.files[relative]
	if !ok {
		return VerifiedFile{}, errors.New("archive: verified runner file unavailable")
	}
	return VerifiedFile{SHA256: entry.SHA256, Size: entry.Size, Mode: entry.Mode}, nil
}

func (v VerifiedRunnerDirectory) Symlink(relative string) (VerifiedSymlink, error) {
	if !validRunnerAuthority(v) {
		return VerifiedSymlink{}, errors.New("archive: verified runner authority required")
	}
	entry, ok := v.symlinks[relative]
	if !ok {
		return VerifiedSymlink{}, errors.New("archive: verified runner symlink unavailable")
	}
	return VerifiedSymlink{Target: entry.LinkTarget, SHA256: entry.SHA256, Size: entry.Size, Mode: entry.Mode}, nil
}

func VerifyRunnerDirectory(root string, manifest RunnerTreeManifest, evidenceGeneration uint64) (VerifiedRunnerDirectory, error) {
	return verifyRunnerDirectory(
		root,
		manifest,
		evidenceGeneration,
		0o700,
		uint32(os.Geteuid()),
		nil,
		nil,
	)
}

// VerifyRunnerImageDirectory proves the final installed shape: root-owned,
// read-only/traversable, and byte-identical to the canonical manifest. The
// returned evidence is deliberately not runner publication authority.
func VerifyRunnerImageDirectory(
	root string,
	manifest RunnerTreeManifest,
	evidenceGeneration uint64,
) (RunnerImageVerification, error) {
	return verifyRunnerImageDirectoryForOwner(root, manifest, evidenceGeneration, 0, 0)
}

// VerifyRunnerImageDirectoryWithDiagnosticsOverlay proves the same immutable
// image tuple while requiring the sole post-manifest root overlay
// "_diag" -> "/runner/_diag". The overlay never contributes to the logical
// manifest or tree-lock digest.
func VerifyRunnerImageDirectoryWithDiagnosticsOverlay(
	root string,
	manifest RunnerTreeManifest,
	evidenceGeneration uint64,
) (RunnerImageVerification, error) {
	return verifyRunnerImageDirectoryWithDiagnosticsOverlayForOwner(
		root,
		manifest,
		evidenceGeneration,
		0,
		0,
	)
}

func verifyRunnerImageDirectoryForOwner(
	root string,
	manifest RunnerTreeManifest,
	evidenceGeneration uint64,
	expectedUID uint32,
	expectedGID uint32,
) (RunnerImageVerification, error) {
	verified, err := verifyRunnerDirectory(
		root,
		manifest,
		evidenceGeneration,
		0o555,
		expectedUID,
		&expectedGID,
		nil,
	)
	if err != nil {
		return RunnerImageVerification{}, err
	}
	return runnerImageVerification(verified), nil
}

func verifyRunnerImageDirectoryWithDiagnosticsOverlayForOwner(
	root string,
	manifest RunnerTreeManifest,
	evidenceGeneration uint64,
	expectedUID uint32,
	expectedGID uint32,
) (RunnerImageVerification, error) {
	verified, err := verifyRunnerDirectory(
		root,
		manifest,
		evidenceGeneration,
		0o555,
		expectedUID,
		&expectedGID,
		&runnerDirectoryOverlay{},
	)
	if err != nil {
		return RunnerImageVerification{}, err
	}
	return runnerImageVerification(verified), nil
}

func runnerImageVerification(
	verified VerifiedRunnerDirectory,
) RunnerImageVerification {
	return RunnerImageVerification{
		manifestDigest:     verified.manifestDigest,
		treeLockDigest:     verified.treeLockDigest,
		evidenceGeneration: verified.evidenceGeneration,
	}
}

func verifyRunnerDirectory(
	root string,
	manifest RunnerTreeManifest,
	evidenceGeneration uint64,
	rootMode uint32,
	expectedUID uint32,
	expectedGID *uint32,
	overlay *runnerDirectoryOverlay,
) (VerifiedRunnerDirectory, error) {
	if evidenceGeneration == 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.IndexByte(root, 0) >= 0 {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner directory verification inputs invalid")
	}
	if rootMode != 0o700 && rootMode != 0o555 {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner directory root policy invalid")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner directory root is indirect")
	}
	if err := validateRunnerManifest(manifest); err != nil {
		return VerifiedRunnerDirectory{}, err
	}

	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner directory root open failed")
	}
	rootFile := os.NewFile(uintptr(rootFD), "verified-runner-root")
	if rootFile == nil {
		_ = unix.Close(rootFD)
		return VerifiedRunnerDirectory{}, errors.New("archive: runner directory root descriptor invalid")
	}
	defer rootFile.Close()

	rootBefore, err := fstatFile(rootFile)
	if err != nil || rootBefore.mode&unix.S_IFMT != unix.S_IFDIR ||
		uint32(rootBefore.mode&0o777) != rootMode || rootBefore.uid != expectedUID ||
		(expectedGID != nil && rootBefore.gid != *expectedGID) {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner directory root identity invalid")
	}

	expected := make(map[string]RunnerTreeEntry, len(manifest.Entries))
	files := make(map[string]RunnerTreeEntry)
	symlinks := make(map[string]RunnerTreeEntry)
	for _, entry := range manifest.Entries {
		expected[entry.Path] = entry
		switch entry.Type {
		case RunnerEntryRegular:
			files[entry.Path] = entry
		case RunnerEntrySymlink:
			symlinks[entry.Path] = entry
		}
	}
	seen := make(map[string]struct{}, len(expected))
	seenInodes := make(map[[2]uint64]struct{}, len(files)+len(symlinks))
	lockLines := []string{"PGHAR-RUNNER-TREE-LOCK-V1\n"}
	if err := walkVerifiedRunnerDirectory(
		rootFile,
		"",
		rootBefore,
		rootMode,
		expected,
		seen,
		seenInodes,
		&lockLines,
		overlay,
	); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	rootAfter, err := fstatFile(rootFile)
	if err != nil || !rootBefore.stableEqual(rootAfter) ||
		len(seen) != len(expected) ||
		(overlay != nil && !overlay.diagnosticsSeen) {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner directory root changed or tree incomplete")
	}
	manifestHash, err := runnerManifestDigest(manifest)
	if err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	lockBytes := []byte(strings.Join(lockLines, ""))
	lockHash := sha256.Sum256(lockBytes)
	return VerifiedRunnerDirectory{
		root:               root,
		rootDevice:         rootBefore.device,
		rootInode:          rootBefore.inode,
		rootUID:            rootBefore.uid,
		rootGID:            rootBefore.gid,
		manifestDigest:     manifestHash,
		treeLockDigest:     lockHash,
		treeLock:           lockBytes,
		files:              files,
		symlinks:           symlinks,
		manifest:           cloneRunnerManifest(manifest),
		evidenceGeneration: evidenceGeneration,
	}, nil
}

func walkVerifiedRunnerDirectory(
	directory *os.File,
	prefix string,
	root fileIdentity,
	rootMode uint32,
	expected map[string]RunnerTreeEntry,
	seen map[string]struct{},
	seenInodes map[[2]uint64]struct{},
	lockLines *[]string,
	overlay *runnerDirectoryOverlay,
) error {
	before, err := fstatFile(directory)
	if err != nil || before.device != root.device || before.uid != root.uid || before.gid != root.gid ||
		before.mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("archive: runner directory identity invalid")
	}
	if prefix == "" {
		if uint32(before.mode&0o777) != rootMode {
			return errors.New("archive: runner root mode invalid")
		}
	} else if before.mode&0o777 != 0o555 {
		return errors.New("archive: runner child directory mode invalid")
	}

	entries, err := directory.ReadDir(-1)
	if err != nil {
		return errors.New("archive: runner directory enumeration failed")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, directoryEntry := range entries {
		name := directoryEntry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			return errors.New("archive: runner directory entry name invalid")
		}
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		want, ok := expected[relative]
		if !ok {
			if prefix == "" && overlay != nil &&
				!overlay.diagnosticsSeen &&
				relative == runnerDiagnosticsOverlayPath {
				target := []byte(runnerDiagnosticsOverlayTarget)
				overlayEntry := RunnerTreeEntry{
					Path:       runnerDiagnosticsOverlayPath,
					Type:       RunnerEntrySymlink,
					SHA256:     sha256String(target),
					Size:       uint64(len(target)),
					LinkTarget: runnerDiagnosticsOverlayTarget,
				}
				discardedLockLines := make([]string, 0, 1)
				if err := verifyRunnerSymlink(
					directory,
					name,
					relative,
					root,
					overlayEntry,
					seenInodes,
					&discardedLockLines,
				); err != nil {
					return err
				}
				overlay.diagnosticsSeen = true
				continue
			}
			return errors.New("archive: unexpected runner directory object")
		}
		if _, duplicate := seen[relative]; duplicate {
			return errors.New("archive: runner directory object duplicated")
		}

		switch want.Type {
		case RunnerEntryDirectory:
			fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return errors.New("archive: runner child directory open failed")
			}
			child := os.NewFile(uintptr(fd), relative)
			if child == nil {
				_ = unix.Close(fd)
				return errors.New("archive: runner child directory descriptor invalid")
			}
			identity, statErr := fstatFile(child)
			if statErr != nil || identity.device != root.device || identity.uid != root.uid ||
				identity.gid != root.gid || identity.mode&unix.S_IFMT != unix.S_IFDIR ||
				identity.mode&0o777 != want.Mode {
				_ = child.Close()
				return errors.New("archive: runner child directory identity invalid")
			}
			seen[relative] = struct{}{}
			*lockLines = append(*lockLines, fmt.Sprintf("D\t%s\t%04o\n", relative, identity.mode&0o777))
			walkErr := walkVerifiedRunnerDirectory(
				child,
				relative,
				root,
				rootMode,
				expected,
				seen,
				seenInodes,
				lockLines,
				overlay,
			)
			closeErr := child.Close()
			if walkErr != nil {
				return walkErr
			}
			if closeErr != nil {
				return errors.New("archive: runner child directory close failed")
			}
		case RunnerEntryRegular:
			if err := verifyRunnerRegular(directory, name, relative, root, want, seenInodes, lockLines); err != nil {
				return err
			}
			seen[relative] = struct{}{}
		case RunnerEntrySymlink:
			if err := verifyRunnerSymlink(directory, name, relative, root, want, seenInodes, lockLines); err != nil {
				return err
			}
			seen[relative] = struct{}{}
		default:
			return errors.New("archive: runner entry type unavailable")
		}
	}
	after, err := fstatFile(directory)
	if err != nil || !before.stableEqual(after) {
		return errors.New("archive: runner directory changed during verification")
	}
	return nil
}

func verifyRunnerRegular(
	directory *os.File,
	name string,
	relative string,
	root fileIdentity,
	want RunnerTreeEntry,
	seenInodes map[[2]uint64]struct{},
	lockLines *[]string,
) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("archive: runner file open failed")
	}
	file := os.NewFile(uintptr(fd), relative)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("archive: runner file descriptor invalid")
	}
	before, statErr := fstatFile(file)
	if statErr != nil || before.device != root.device || before.uid != root.uid || before.gid != root.gid ||
		before.mode&unix.S_IFMT != unix.S_IFREG || before.nlink != 1 || before.size < 0 ||
		uint64(before.size) != want.Size || uint32(before.mode&0o777) != want.Mode || before.sparse() {
		_ = file.Close()
		return errors.New("archive: runner file identity invalid")
	}
	key := [2]uint64{before.device, before.inode}
	if _, duplicate := seenInodes[key]; duplicate {
		_ = file.Close()
		return errors.New("archive: repeated runner object identity")
	}
	seenInodes[key] = struct{}{}

	hash := sha256.New()
	count, hashErr := io.Copy(hash, io.LimitReader(file, before.size+1))
	after, afterErr := fstatFile(file)
	closeErr := file.Close()
	digest := hex.EncodeToString(hash.Sum(nil))
	if hashErr != nil || afterErr != nil || closeErr != nil || count != before.size ||
		!before.stableEqual(after) || digest != want.SHA256 {
		return errors.New("archive: runner file changed or content differs")
	}
	*lockLines = append(*lockLines, fmt.Sprintf("F\t%s\t%04o\t%d\t%s\n", relative, before.mode&0o777, before.size, digest))
	return nil
}

func verifyRunnerSymlink(
	directory *os.File,
	name string,
	relative string,
	root fileIdentity,
	want RunnerTreeEntry,
	seenInodes map[[2]uint64]struct{},
	lockLines *[]string,
) error {
	before, err := lstatRunnerAt(int(directory.Fd()), name)
	if err != nil || before.device != root.device || before.uid != root.uid || before.gid != root.gid ||
		before.mode&unix.S_IFMT != unix.S_IFLNK || before.nlink != 1 || before.size < 0 ||
		uint64(before.size) != want.Size {
		return errors.New("archive: runner symlink identity invalid")
	}
	key := [2]uint64{before.device, before.inode}
	if _, duplicate := seenInodes[key]; duplicate {
		return errors.New("archive: repeated runner object identity")
	}
	seenInodes[key] = struct{}{}

	buffer := make([]byte, maxRunnerLinkBytes+1)
	count, err := unix.Readlinkat(int(directory.Fd()), name, buffer)
	if err != nil || count <= 0 || count > maxRunnerLinkBytes {
		return errors.New("archive: runner symlink read failed")
	}
	target := string(buffer[:count])
	after, err := lstatRunnerAt(int(directory.Fd()), name)
	if err != nil || !before.stableEqual(after) || target != want.LinkTarget ||
		sha256String([]byte(target)) != want.SHA256 {
		return errors.New("archive: runner symlink changed or target differs")
	}
	*lockLines = append(*lockLines, fmt.Sprintf("L\t%s\t0000\t%d\t%s\t%s\n",
		relative, before.size, want.SHA256, target))
	return nil
}

func lstatRunnerAt(directoryFD int, name string) (fileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileIdentity{}, err
	}
	return identityFromStat(&stat), nil
}

func WriteRunnerManifest(writer io.Writer, verified VerifiedRunnerDirectory) error {
	if writer == nil || !validRunnerAuthority(verified) {
		return errors.New("archive: verified runner authority required")
	}
	document, err := EncodeRunnerManifest(verified.manifest)
	if err != nil || sha256.Sum256(document) != verified.manifestDigest {
		return errors.New("archive: verified runner manifest invalid")
	}
	written, err := io.Copy(writer, bytes.NewReader(document))
	if err != nil || written != int64(len(document)) {
		return errors.New("archive: runner manifest write failed")
	}
	return nil
}

func WriteRunnerTreeLock(writer io.Writer, verified VerifiedRunnerDirectory) error {
	if writer == nil || !validRunnerAuthority(verified) {
		return errors.New("archive: verified runner authority required")
	}
	written, err := io.Copy(writer, bytes.NewReader(verified.treeLock))
	if err != nil || written != int64(len(verified.treeLock)) {
		return errors.New("archive: runner tree lock write failed")
	}
	return nil
}

func validRunnerAuthority(verified VerifiedRunnerDirectory) bool {
	return verified.root != "" && verified.rootDevice != 0 && verified.rootInode != 0 &&
		verified.evidenceGeneration != 0 && verified.manifest.SchemaVersion == 1 &&
		verified.manifestDigest != ([sha256.Size]byte{}) &&
		verified.treeLockDigest != ([sha256.Size]byte{}) &&
		len(verified.treeLock) != 0 && verified.files != nil && verified.symlinks != nil
}
