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

type VerifiedDirectory struct {
	root               string
	rootDevice         uint64
	rootInode          uint64
	rootUID            uint32
	rootGID            uint32
	manifestDigest     [sha256.Size]byte
	treeLockDigest     [sha256.Size]byte
	treeLock           []byte
	files              map[string]File
	manifest           Manifest
	evidenceGeneration uint64
}

// SeedImageVerification is non-authorizing evidence that one installed,
// root-owned seed tree matches a prior manifest. It cannot publish content or
// emit the staging tree lock.
type SeedImageVerification struct {
	manifestDigest     [sha256.Size]byte
	treeLockDigest     [sha256.Size]byte
	evidenceGeneration uint64
}

type seedDirectoryAuthority interface {
	seedDirectoryAuthority()
}

type seedImageEvidence interface {
	seedImageEvidence()
}

func (VerifiedDirectory) seedDirectoryAuthority() {}
func (SeedImageVerification) seedImageEvidence()  {}

func (v VerifiedDirectory) Generation() uint64     { return v.evidenceGeneration }
func (v VerifiedDirectory) ManifestDigest() string { return hexDigest(v.manifestDigest) }
func (v VerifiedDirectory) TreeLockDigest() string { return hexDigest(v.treeLockDigest) }

func (v SeedImageVerification) Generation() uint64 { return v.evidenceGeneration }
func (v SeedImageVerification) ManifestDigest() string {
	return hexDigest(v.manifestDigest)
}
func (v SeedImageVerification) TreeLockDigest() string {
	return hexDigest(v.treeLockDigest)
}

type directoryVerifyHooks struct {
	afterHash func(string)
}

type directoryVerifyPolicy struct {
	rootMode           uint32
	expectedUID        uint32
	expectedGID        *uint32
	childDirectoryMode *uint32
}

func VerifyDirectory(root string, manifest Manifest, evidenceGeneration uint64) (VerifiedDirectory, error) {
	return verifyDirectory(root, manifest, evidenceGeneration, directoryVerifyHooks{})
}

func verifyDirectory(root string, manifest Manifest, evidenceGeneration uint64, hooks directoryVerifyHooks) (VerifiedDirectory, error) {
	return verifyDirectoryWithPolicy(
		root,
		manifest,
		evidenceGeneration,
		directoryVerifyPolicy{
			rootMode:    0o700,
			expectedUID: uint32(os.Geteuid()),
		},
		hooks,
	)
}

// VerifySeedImageDirectory proves the final installed shape: root-owned,
// read-only/traversable, and byte-identical to the canonical manifest. The
// returned evidence is deliberately not seed publication authority.
func VerifySeedImageDirectory(
	root string,
	manifest Manifest,
	evidenceGeneration uint64,
) (SeedImageVerification, error) {
	return verifySeedImageDirectoryForOwner(root, manifest, evidenceGeneration, 0, 0)
}

func verifySeedImageDirectoryForOwner(
	root string,
	manifest Manifest,
	evidenceGeneration uint64,
	expectedUID uint32,
	expectedGID uint32,
) (SeedImageVerification, error) {
	childMode := uint32(0o555)
	verified, err := verifyDirectoryWithPolicy(
		root,
		manifest,
		evidenceGeneration,
		directoryVerifyPolicy{
			rootMode:           0o555,
			expectedUID:        expectedUID,
			expectedGID:        &expectedGID,
			childDirectoryMode: &childMode,
		},
		directoryVerifyHooks{},
	)
	if err != nil {
		return SeedImageVerification{}, err
	}
	return SeedImageVerification{
		manifestDigest:     verified.manifestDigest,
		treeLockDigest:     verified.treeLockDigest,
		evidenceGeneration: verified.evidenceGeneration,
	}, nil
}

func verifyDirectoryWithPolicy(
	root string,
	manifest Manifest,
	evidenceGeneration uint64,
	policy directoryVerifyPolicy,
	hooks directoryVerifyHooks,
) (VerifiedDirectory, error) {
	if evidenceGeneration == 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.IndexByte(root, 0) >= 0 {
		return VerifiedDirectory{}, errors.New("archive: directory verification inputs invalid")
	}
	if (policy.rootMode != 0o700 && policy.rootMode != 0o555) ||
		(policy.childDirectoryMode != nil && *policy.childDirectoryMode != 0o555) {
		return VerifiedDirectory{}, errors.New("archive: directory verification policy invalid")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return VerifiedDirectory{}, errors.New("archive: directory root is indirect")
	}
	if err := validateManifest(manifest); err != nil {
		return VerifiedDirectory{}, err
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return VerifiedDirectory{}, errors.New("archive: directory root open failed")
	}
	rootFile := os.NewFile(uintptr(rootFD), "verified-root")
	if rootFile == nil {
		_ = unix.Close(rootFD)
		return VerifiedDirectory{}, errors.New("archive: directory root descriptor invalid")
	}
	defer rootFile.Close()

	rootBefore, err := fstatFile(rootFile)
	if err != nil || rootBefore.mode&unix.S_IFMT != unix.S_IFDIR ||
		uint32(rootBefore.mode&0o777) != policy.rootMode ||
		rootBefore.uid != policy.expectedUID ||
		(policy.expectedGID != nil && rootBefore.gid != *policy.expectedGID) {
		return VerifiedDirectory{}, errors.New("archive: directory root identity invalid")
	}
	expected, directories := expectedFiles(manifest)
	seenFiles := make(map[string]struct{}, len(expected))
	seenInodes := make(map[[2]uint64]struct{}, len(expected))
	lockLines := []string{"PGHAR-TREE-LOCK-V1\n"}
	if err := walkVerifiedDirectory(
		rootFile,
		"",
		rootBefore,
		policy.childDirectoryMode,
		expected,
		directories,
		seenFiles,
		seenInodes,
		&lockLines,
		hooks,
	); err != nil {
		return VerifiedDirectory{}, err
	}
	rootAfter, err := fstatFile(rootFile)
	if err != nil || !rootBefore.stableEqual(rootAfter) || len(seenFiles) != len(expected) {
		return VerifiedDirectory{}, errors.New("archive: directory root changed or tree incomplete")
	}
	manifestHash, err := manifestDigest(manifest)
	if err != nil {
		return VerifiedDirectory{}, err
	}
	lockBytes := []byte(strings.Join(lockLines, ""))
	lockHash := sha256.Sum256(lockBytes)
	return VerifiedDirectory{
		root:               root,
		rootDevice:         rootBefore.device,
		rootInode:          rootBefore.inode,
		rootUID:            rootBefore.uid,
		rootGID:            rootBefore.gid,
		manifestDigest:     manifestHash,
		treeLockDigest:     lockHash,
		treeLock:           lockBytes,
		files:              cloneFiles(expected),
		manifest:           cloneManifest(manifest),
		evidenceGeneration: evidenceGeneration,
	}, nil
}

// VerifiedFile returns immutable file metadata only from an OS-identity
// verified authority. It does not expose the staging root.
type VerifiedFile struct {
	SHA256 string
	Size   uint64
	Mode   uint32
}

func (v VerifiedDirectory) File(relative string) (VerifiedFile, error) {
	if v.root == "" || v.evidenceGeneration == 0 || len(v.treeLock) == 0 {
		return VerifiedFile{}, errors.New("archive: verified directory authority required")
	}
	file, ok := v.files[relative]
	if !ok {
		return VerifiedFile{}, errors.New("archive: verified file unavailable")
	}
	return VerifiedFile{SHA256: file.SHA256, Size: file.Size, Mode: file.Mode}, nil
}

func cloneFiles(files map[string]File) map[string]File {
	cloned := make(map[string]File, len(files))
	for name, file := range files {
		cloned[name] = file
	}
	return cloned
}

func cloneManifest(manifest Manifest) Manifest {
	cloned := manifest
	if manifest.Seeds == nil {
		cloned.Seeds = nil
	} else {
		cloned.Seeds = append(make([]Seed, 0, len(manifest.Seeds)), manifest.Seeds...)
	}
	for i := range cloned.Seeds {
		if manifest.Seeds[i].Files == nil {
			cloned.Seeds[i].Files = nil
		} else {
			cloned.Seeds[i].Files = append(make([]File, 0, len(manifest.Seeds[i].Files)), manifest.Seeds[i].Files...)
		}
	}
	return cloned
}

func walkVerifiedDirectory(
	directory *os.File,
	prefix string,
	root fileIdentity,
	childDirectoryMode *uint32,
	expected map[string]File,
	expectedDirectories map[string]struct{},
	seenFiles map[string]struct{},
	seenInodes map[[2]uint64]struct{},
	lockLines *[]string,
	hooks directoryVerifyHooks,
) error {
	before, err := fstatFile(directory)
	if err != nil || before.device != root.device ||
		before.uid != root.uid || before.gid != root.gid ||
		before.mode&unix.S_IFMT != unix.S_IFDIR ||
		(prefix != "" && !validSeedChildDirectoryMode(before.mode, childDirectoryMode)) {
		return errors.New("archive: directory identity invalid")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return errors.New("archive: directory enumeration failed")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
			return errors.New("archive: directory entry name invalid")
		}
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		if _, isDirectory := expectedDirectories[relative]; isDirectory {
			fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return errors.New("archive: child directory open failed")
			}
			child := os.NewFile(uintptr(fd), relative)
			if child == nil {
				_ = unix.Close(fd)
				return errors.New("archive: child directory descriptor invalid")
			}
			identity, statErr := fstatFile(child)
			if statErr != nil || identity.device != root.device ||
				identity.uid != root.uid || identity.gid != root.gid ||
				identity.mode&unix.S_IFMT != unix.S_IFDIR ||
				!validSeedChildDirectoryMode(identity.mode, childDirectoryMode) {
				child.Close()
				return errors.New("archive: child directory identity invalid")
			}
			*lockLines = append(*lockLines, fmt.Sprintf("D\t%s\t%04o\n", relative, identity.mode&0o777))
			walkErr := walkVerifiedDirectory(
				child,
				relative,
				root,
				childDirectoryMode,
				expected,
				expectedDirectories,
				seenFiles,
				seenInodes,
				lockLines,
				hooks,
			)
			closeErr := child.Close()
			if walkErr != nil {
				return walkErr
			}
			if closeErr != nil {
				return errors.New("archive: child directory close failed")
			}
			continue
		}

		want, ok := expected[relative]
		if !ok {
			return errors.New("archive: unexpected directory object")
		}
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("archive: verified file open failed")
		}
		file := os.NewFile(uintptr(fd), relative)
		if file == nil {
			_ = unix.Close(fd)
			return errors.New("archive: verified file descriptor invalid")
		}
		identity, statErr := fstatFile(file)
		if statErr != nil || identity.device != root.device ||
			identity.uid != root.uid || identity.gid != root.gid ||
			identity.mode&unix.S_IFMT != unix.S_IFREG ||
			identity.nlink != 1 || identity.size < 0 ||
			uint64(identity.size) != want.Size ||
			uint32(identity.mode&0o777) != want.Mode || identity.sparse() {
			file.Close()
			return errors.New("archive: verified file identity invalid")
		}
		key := [2]uint64{identity.device, identity.inode}
		if _, exists := seenInodes[key]; exists {
			file.Close()
			return errors.New("archive: repeated file identity")
		}
		seenInodes[key] = struct{}{}
		hash := sha256.New()
		count, hashErr := io.Copy(hash, io.LimitReader(file, identity.size+1))
		if hooks.afterHash != nil {
			hooks.afterHash(relative)
		}
		after, afterErr := fstatFile(file)
		closeErr := file.Close()
		digest := hex.EncodeToString(hash.Sum(nil))
		if hashErr != nil || afterErr != nil || closeErr != nil || count != identity.size || !identity.stableEqual(after) || digest != want.SHA256 {
			return errors.New("archive: verified file changed or content differs")
		}
		seenFiles[relative] = struct{}{}
		*lockLines = append(*lockLines, fmt.Sprintf("F\t%s\t%04o\t%d\t%s\n", relative, identity.mode&0o777, identity.size, digest))
	}
	after, err := fstatFile(directory)
	if err != nil || !before.stableEqual(after) {
		return errors.New("archive: directory changed during verification")
	}
	return nil
}

func validSeedChildDirectoryMode(mode uint32, exact *uint32) bool {
	if exact != nil {
		return uint32(mode&0o777) == *exact
	}
	return mode&0o022 == 0
}

func fstatFile(file *os.File) (fileIdentity, error) {
	var stat unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &stat) != nil {
		return fileIdentity{}, errors.New("archive: fstat failed")
	}
	return identityFromStat(&stat), nil
}

func WriteTreeLock(writer io.Writer, verified VerifiedDirectory) error {
	if writer == nil || verified.root == "" || verified.rootDevice == 0 || verified.rootInode == 0 || verified.evidenceGeneration == 0 || len(verified.treeLock) == 0 || verified.treeLockDigest == ([sha256.Size]byte{}) {
		return errors.New("archive: verified directory authority required")
	}
	written, err := io.Copy(writer, bytes.NewReader(verified.treeLock))
	if err != nil || written != int64(len(verified.treeLock)) {
		return errors.New("archive: tree lock write failed")
	}
	return nil
}
