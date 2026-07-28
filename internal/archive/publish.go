package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type publishHooks struct {
	afterSeal func() error
}

// PublishVerified copies one verified snapshot into a new private directory
// while rechecking source descriptors and then returns fresh OS-identity
// authority for the published tree.
func PublishVerified(verified VerifiedDirectory, destination string) (VerifiedDirectory, error) {
	return publishVerified(verified, destination, publishHooks{})
}

func publishVerified(verified VerifiedDirectory, destination string, hooks publishHooks) (VerifiedDirectory, error) {
	if verified.root == "" || verified.rootDevice == 0 || verified.rootInode == 0 ||
		verified.evidenceGeneration == 0 || verified.manifest.SchemaVersion != 1 ||
		verified.manifestDigest == ([sha256.Size]byte{}) ||
		verified.treeLockDigest == ([sha256.Size]byte{}) ||
		len(verified.treeLock) == 0 || verified.files == nil {
		return VerifiedDirectory{}, errors.New("archive: verified directory authority required")
	}
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || strings.IndexByte(destination, 0) >= 0 {
		return VerifiedDirectory{}, errors.New("archive: publish destination invalid")
	}
	if destination == verified.root || strings.HasPrefix(destination, verified.root+string(filepath.Separator)) || strings.HasPrefix(verified.root, destination+string(filepath.Separator)) {
		return VerifiedDirectory{}, errors.New("archive: publish trees overlap")
	}
	parent := filepath.Dir(destination)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return VerifiedDirectory{}, errors.New("archive: publish parent indirect")
	}
	current, err := verifyDirectory(verified.root, verified.manifest, verified.evidenceGeneration, directoryVerifyHooks{})
	if err != nil || current.rootDevice != verified.rootDevice ||
		current.rootInode != verified.rootInode ||
		current.rootUID != verified.rootUID || current.rootGID != verified.rootGID ||
		current.manifestDigest != verified.manifestDigest ||
		current.treeLockDigest != verified.treeLockDigest {
		return VerifiedDirectory{}, errors.New("archive: publish source authority stale")
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return VerifiedDirectory{}, errors.New("archive: publish destination create failed")
	}
	committed := false
	defer func() {
		if !committed {
			removePublishedTree(destination)
		}
	}()

	_, directories := expectedFiles(verified.manifest)
	directoryNames := make([]string, 0, len(directories))
	for name := range directories {
		directoryNames = append(directoryNames, name)
	}
	sort.Slice(directoryNames, func(i, j int) bool {
		depthI, depthJ := strings.Count(directoryNames[i], "/"), strings.Count(directoryNames[j], "/")
		if depthI != depthJ {
			return depthI < depthJ
		}
		return directoryNames[i] < directoryNames[j]
	})
	for _, name := range directoryNames {
		sourceDirectory, err := openRelative(verified.root, name, true)
		if err != nil {
			return VerifiedDirectory{}, err
		}
		identity, statErr := fstatFile(sourceDirectory)
		closeErr := sourceDirectory.Close()
		if statErr != nil || closeErr != nil ||
			identity.device != verified.rootDevice ||
			identity.uid != verified.rootUID || identity.gid != verified.rootGID ||
			identity.mode&unix.S_IFMT != unix.S_IFDIR ||
			identity.mode&0o022 != 0 {
			return VerifiedDirectory{}, errors.New("archive: publish source directory invalid")
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.Mkdir(target, 0o700); err != nil || os.Chmod(target, 0o700) != nil {
			return VerifiedDirectory{}, errors.New("archive: publish directory create failed")
		}
	}

	fileNames := make([]string, 0, len(verified.files))
	for name := range verified.files {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		want := verified.files[name]
		source, err := openRelative(verified.root, name, false)
		if err != nil {
			return VerifiedDirectory{}, err
		}
		before, statErr := fstatFile(source)
		if statErr != nil || before.device != verified.rootDevice ||
			before.uid != verified.rootUID || before.gid != verified.rootGID ||
			before.mode&unix.S_IFMT != unix.S_IFREG ||
			before.nlink != 1 || before.size < 0 ||
			uint64(before.size) != want.Size ||
			uint32(before.mode&0o777) != want.Mode {
			source.Close()
			return VerifiedDirectory{}, errors.New("archive: publish source file invalid")
		}
		targetPath := filepath.Join(destination, filepath.FromSlash(name))
		target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			source.Close()
			return VerifiedDirectory{}, errors.New("archive: publish target file create failed")
		}
		hash := sha256.New()
		count, copyErr := io.Copy(io.MultiWriter(target, hash), io.LimitReader(source, before.size+1))
		after, afterErr := fstatFile(source)
		sourceCloseErr := source.Close()
		syncErr := target.Sync()
		chmodErr := target.Chmod(os.FileMode(want.Mode))
		targetCloseErr := target.Close()
		if copyErr != nil || afterErr != nil || sourceCloseErr != nil || syncErr != nil || chmodErr != nil || targetCloseErr != nil || count != before.size || !before.stableEqual(after) || hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
			return VerifiedDirectory{}, errors.New("archive: publish file changed or copy failed")
		}
	}

	for index := len(directoryNames) - 1; index >= 0; index-- {
		target := filepath.Join(destination, filepath.FromSlash(directoryNames[index]))
		if err := os.Chmod(target, 0o555); err != nil {
			return VerifiedDirectory{}, errors.New("archive: publish directory seal failed")
		}
	}
	if hooks.afterSeal != nil {
		if err := hooks.afterSeal(); err != nil {
			return VerifiedDirectory{}, errors.New("archive: publish post-seal hook failed")
		}
	}

	afterCopy, err := verifyDirectory(verified.root, verified.manifest, verified.evidenceGeneration, directoryVerifyHooks{})
	if err != nil || afterCopy.rootDevice != verified.rootDevice ||
		afterCopy.rootInode != verified.rootInode ||
		afterCopy.rootUID != verified.rootUID || afterCopy.rootGID != verified.rootGID ||
		afterCopy.treeLockDigest != verified.treeLockDigest {
		return VerifiedDirectory{}, errors.New("archive: publish source changed during copy")
	}
	published, err := verifyDirectory(destination, verified.manifest, verified.evidenceGeneration, directoryVerifyHooks{})
	if err != nil || published.manifestDigest != verified.manifestDigest {
		return VerifiedDirectory{}, errors.New("archive: published tree verification failed")
	}
	committed = true
	return published, nil
}

func openRelative(root, relative string, directory bool) (*os.File, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("archive: relative root open failed")
	}
	current := rootFD
	parts := strings.Split(relative, "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		next, openErr := unix.Openat(current, part, flags, 0)
		if current != rootFD {
			_ = unix.Close(current)
		}
		if openErr != nil {
			_ = unix.Close(rootFD)
			return nil, errors.New("archive: relative object open failed")
		}
		current = next
	}
	_ = unix.Close(rootFD)
	file := os.NewFile(uintptr(current), relative)
	if file == nil {
		_ = unix.Close(current)
		return nil, errors.New("archive: relative descriptor invalid")
	}
	return file, nil
}

func removePublishedTree(root string) {
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
