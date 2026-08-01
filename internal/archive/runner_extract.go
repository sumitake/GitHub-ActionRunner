package archive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type RunnerExtractOptions struct {
	ArchivePath        string
	ExpectedSHA256     string
	EvidenceGeneration uint64
	OutputDirectory    string
}

type runnerArchiveLimits struct {
	maxCompressedBytes int64
	maxEntries         int
	maxPathBytes       int
	maxLinkBytes       int
	maxFileBytes       uint64
	maxExpandedBytes   uint64
	maxTarPaddingBytes int64
}

var defaultRunnerArchiveLimits = runnerArchiveLimits{
	maxCompressedBytes: 256 << 20,
	maxEntries:         maxRunnerEntries,
	maxPathBytes:       maxRunnerPathBytes,
	maxLinkBytes:       maxRunnerLinkBytes,
	maxFileBytes:       maxRunnerFileBytes,
	maxExpandedBytes:   maxRunnerExpandedBytes,
	maxTarPaddingBytes: 20 << 10,
}

type runnerExtractHooks struct {
	beforeSecondPass func()
}

func ExtractRunnerArchive(options RunnerExtractOptions) (VerifiedRunnerDirectory, error) {
	return extractRunnerArchive(options, defaultRunnerArchiveLimits, runnerExtractHooks{})
}

func extractRunnerArchive(
	options RunnerExtractOptions,
	limits runnerArchiveLimits,
	hooks runnerExtractHooks,
) (VerifiedRunnerDirectory, error) {
	if err := validateRunnerExtractOptions(options, limits); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	parent := filepath.Dir(options.OutputDirectory)
	if err := validateRunnerPrivateDirectory(parent); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	if _, err := os.Lstat(options.OutputDirectory); !os.IsNotExist(err) {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner output already exists or cannot be inspected")
	}

	archiveFile, archiveIdentity, err := openStableRunnerArchive(options.ArchivePath, limits)
	if err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	defer archiveFile.Close()
	if err := verifyRunnerArchiveDigest(archiveFile, archiveIdentity, options.ExpectedSHA256); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	manifest, sequence, err := preflightRunnerArchive(archiveFile, archiveIdentity, limits)
	if err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	if err := verifyRunnerArchivePathIdentity(options.ArchivePath, archiveFile, archiveIdentity); err != nil {
		return VerifiedRunnerDirectory{}, err
	}

	if err := os.Mkdir(options.OutputDirectory, 0o700); err != nil {
		return VerifiedRunnerDirectory{}, errors.New("archive: runner output create failed")
	}
	committed := false
	defer func() {
		if !committed {
			removeRunnerSnapshot(options.OutputDirectory)
		}
	}()
	if err := validateRunnerPrivateDirectory(options.OutputDirectory); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	if hooks.beforeSecondPass != nil {
		hooks.beforeSecondPass()
	}
	if err := verifyRunnerArchivePathIdentity(options.ArchivePath, archiveFile, archiveIdentity); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	if err := extractRunnerArchiveSecondPass(archiveFile, archiveIdentity, limits, sequence, options.OutputDirectory); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	if err := verifyRunnerArchivePathIdentity(options.ArchivePath, archiveFile, archiveIdentity); err != nil {
		return VerifiedRunnerDirectory{}, err
	}
	verified, err := VerifyRunnerDirectory(options.OutputDirectory, manifest, options.EvidenceGeneration)
	if err != nil {
		return VerifiedRunnerDirectory{}, errors.New("archive: extracted runner verification failed")
	}
	committed = true
	return verified, nil
}

func validateRunnerExtractOptions(options RunnerExtractOptions, limits runnerArchiveLimits) error {
	if options.EvidenceGeneration == 0 ||
		!canonicalRunnerAbsolutePath(options.ArchivePath) ||
		!canonicalRunnerAbsolutePath(options.OutputDirectory) ||
		options.ArchivePath == options.OutputDirectory ||
		strings.HasPrefix(options.OutputDirectory, options.ArchivePath+string(filepath.Separator)) ||
		!hex64Pattern.MatchString(options.ExpectedSHA256) ||
		limits.maxCompressedBytes <= 0 || limits.maxEntries <= 0 ||
		limits.maxPathBytes <= 0 || limits.maxPathBytes > maxRunnerPathBytes ||
		limits.maxLinkBytes <= 0 || limits.maxLinkBytes > maxRunnerLinkBytes ||
		limits.maxFileBytes == 0 || limits.maxFileBytes > maxRunnerFileBytes ||
		limits.maxExpandedBytes == 0 || limits.maxExpandedBytes > maxRunnerExpandedBytes ||
		limits.maxTarPaddingBytes < 0 {
		return errors.New("archive: runner extraction inputs invalid")
	}
	return nil
}

func canonicalRunnerAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && strings.IndexByte(value, 0) < 0
}

func validateRunnerPrivateDirectory(directory string) error {
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("archive: runner private directory indirect")
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("archive: runner private directory open failed")
	}
	file := os.NewFile(uintptr(fd), "runner-private-directory")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("archive: runner private directory descriptor invalid")
	}
	identity, statErr := fstatFile(file)
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || identity.mode&unix.S_IFMT != unix.S_IFDIR ||
		identity.mode&0o777 != 0o700 || identity.uid != uint32(os.Geteuid()) {
		return errors.New("archive: runner private directory identity invalid")
	}
	return nil
}

func openStableRunnerArchive(path string, limits runnerArchiveLimits) (*os.File, fileIdentity, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, fileIdentity{}, errors.New("archive: runner archive path indirect")
	}
	var pathStat unix.Stat_t
	if err := unix.Lstat(path, &pathStat); err != nil {
		return nil, fileIdentity{}, errors.New("archive: runner archive lstat failed")
	}
	pathIdentity := identityFromStat(&pathStat)
	if pathIdentity.mode&unix.S_IFMT != unix.S_IFREG || pathIdentity.nlink != 1 ||
		pathIdentity.uid != uint32(os.Geteuid()) ||
		pathIdentity.mode&0o022 != 0 || pathIdentity.size <= 0 ||
		pathIdentity.size > limits.maxCompressedBytes {
		return nil, fileIdentity{}, errors.New("archive: runner archive identity invalid")
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fileIdentity{}, errors.New("archive: runner archive open failed")
	}
	file := os.NewFile(uintptr(fd), "runner-archive")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fileIdentity{}, errors.New("archive: runner archive descriptor invalid")
	}
	opened, err := fstatFile(file)
	if err != nil || !pathIdentity.stableEqual(opened) {
		_ = file.Close()
		return nil, fileIdentity{}, errors.New("archive: runner archive identity changed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, fileIdentity{}, errors.New("archive: runner archive is not seekable")
	}
	return file, opened, nil
}

func verifyRunnerArchiveDigest(file *os.File, identity fileIdentity, expected string) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("archive: runner archive rewind failed")
	}
	hash := sha256.New()
	count, copyErr := io.Copy(hash, io.LimitReader(file, identity.size+1))
	after, statErr := fstatFile(file)
	if copyErr != nil || statErr != nil || count != identity.size || !identity.stableEqual(after) ||
		hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("archive: runner archive digest or identity invalid")
	}
	return nil
}

func verifyRunnerArchivePathIdentity(path string, file *os.File, identity fileIdentity) error {
	opened, err := fstatFile(file)
	if err != nil || !identity.stableEqual(opened) {
		return errors.New("archive: runner archive descriptor changed")
	}
	var pathStat unix.Stat_t
	if err := unix.Lstat(path, &pathStat); err != nil || !identity.stableEqual(identityFromStat(&pathStat)) {
		return errors.New("archive: runner archive path changed")
	}
	return nil
}

type runnerTarStream struct {
	buffered *bufio.Reader
	gzip     *gzip.Reader
	tar      *tar.Reader
}

func openRunnerTarStream(file *os.File) (runnerTarStream, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return runnerTarStream{}, errors.New("archive: runner archive rewind failed")
	}
	buffered := bufio.NewReaderSize(file, 64<<10)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return runnerTarStream{}, errors.New("archive: runner gzip header invalid")
	}
	gzipReader.Multistream(false)
	return runnerTarStream{
		buffered: buffered,
		gzip:     gzipReader,
		tar:      tar.NewReader(gzipReader),
	}, nil
}

func (stream runnerTarStream) finish(maxPadding int64) error {
	buffer := make([]byte, 4096)
	var total int64
	for {
		count, err := stream.gzip.Read(buffer)
		if count > 0 {
			total += int64(count)
			if total > maxPadding {
				_ = stream.gzip.Close()
				return errors.New("archive: runner tar padding too large")
			}
			for _, value := range buffer[:count] {
				if value != 0 {
					_ = stream.gzip.Close()
					return errors.New("archive: runner tar trailing content invalid")
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = stream.gzip.Close()
			return errors.New("archive: runner gzip termination invalid")
		}
	}
	if err := stream.gzip.Close(); err != nil {
		return errors.New("archive: runner gzip close failed")
	}
	if _, err := stream.buffered.ReadByte(); err != io.EOF {
		return errors.New("archive: runner archive has a second member or trailing data")
	}
	return nil
}

func preflightRunnerArchive(
	file *os.File,
	identity fileIdentity,
	limits runnerArchiveLimits,
) (RunnerTreeManifest, []RunnerTreeEntry, error) {
	stream, err := openRunnerTarStream(file)
	if err != nil {
		return RunnerTreeManifest{}, nil, err
	}
	rootSeen := false
	sequence := make([]RunnerTreeEntry, 0, 12_000)
	seen := make(map[string]RunnerEntryType, 12_000)
	folded := make(map[string]struct{}, 12_000)
	var expanded uint64
	for index := 0; ; index++ {
		header, err := stream.tar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return RunnerTreeManifest{}, nil, errors.New("archive: runner tar parse failed")
		}
		if index >= limits.maxEntries {
			return RunnerTreeManifest{}, nil, errors.New("archive: runner archive entry count exceeded")
		}
		entry, root, err := runnerEntryFromHeader(header, limits)
		if err != nil {
			return RunnerTreeManifest{}, nil, err
		}
		if root {
			if index != 0 || rootSeen {
				return RunnerTreeManifest{}, nil, errors.New("archive: runner archive root invalid")
			}
			rootSeen = true
			continue
		}
		if !rootSeen {
			return RunnerTreeManifest{}, nil, errors.New("archive: runner archive root missing")
		}
		parent := path.Dir(entry.Path)
		if parent != "." && seen[parent] != RunnerEntryDirectory {
			return RunnerTreeManifest{}, nil, errors.New("archive: runner archive parent order invalid")
		}
		key := strings.ToLower(entry.Path)
		if _, exists := folded[key]; exists {
			return RunnerTreeManifest{}, nil, errors.New("archive: runner archive path collision")
		}
		folded[key] = struct{}{}
		seen[entry.Path] = entry.Type

		if entry.Type == RunnerEntryRegular {
			if entry.Size > limits.maxExpandedBytes || expanded > limits.maxExpandedBytes-entry.Size {
				return RunnerTreeManifest{}, nil, errors.New("archive: runner archive expanded size exceeded")
			}
			expanded += entry.Size
			hash := sha256.New()
			count, err := io.Copy(hash, io.LimitReader(stream.tar, int64(entry.Size)+1))
			if err != nil || count != int64(entry.Size) {
				return RunnerTreeManifest{}, nil, errors.New("archive: runner archive file body invalid")
			}
			entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
		}
		sequence = append(sequence, entry)
	}
	if !rootSeen {
		return RunnerTreeManifest{}, nil, errors.New("archive: runner archive root missing")
	}
	if err := stream.finish(limits.maxTarPaddingBytes); err != nil {
		return RunnerTreeManifest{}, nil, err
	}
	after, err := fstatFile(file)
	if err != nil || !identity.stableEqual(after) {
		return RunnerTreeManifest{}, nil, errors.New("archive: runner archive changed during preflight")
	}
	entries := append(make([]RunnerTreeEntry, 0, len(sequence)), sequence...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	manifest := RunnerTreeManifest{SchemaVersion: 1, Entries: entries}
	if err := validateRunnerManifest(manifest); err != nil {
		return RunnerTreeManifest{}, nil, err
	}
	return manifest, sequence, nil
}

func runnerEntryFromHeader(header *tar.Header, limits runnerArchiveLimits) (RunnerTreeEntry, bool, error) {
	if header == nil {
		return RunnerTreeEntry{}, false, errors.New("archive: runner tar header metadata invalid")
	}
	//lint:ignore SA1019 archive/tar still populates legacy Xattrs; rejecting either representation is intentional.
	hasLegacyXattrs := len(header.Xattrs) != 0
	if len(header.PAXRecords) != 0 || hasLegacyXattrs ||
		header.Devmajor != 0 || header.Devminor != 0 || header.Mode < 0 ||
		header.Mode&^0o777 != 0 {
		return RunnerTreeEntry{}, false, errors.New("archive: runner tar header metadata invalid")
	}
	if header.Name == "./" {
		if header.Typeflag != tar.TypeDir || header.Size != 0 || header.Linkname != "" {
			return RunnerTreeEntry{}, false, errors.New("archive: runner tar root header invalid")
		}
		return RunnerTreeEntry{}, true, nil
	}
	if !strings.HasPrefix(header.Name, "./") || len(header.Name) <= 2 {
		return RunnerTreeEntry{}, false, errors.New("archive: runner tar path noncanonical")
	}
	name := strings.TrimPrefix(header.Name, "./")
	isDirectory := header.Typeflag == tar.TypeDir
	if isDirectory {
		if !strings.HasSuffix(name, "/") {
			return RunnerTreeEntry{}, false, errors.New("archive: runner tar directory path invalid")
		}
		name = strings.TrimSuffix(name, "/")
	} else if strings.HasSuffix(name, "/") {
		return RunnerTreeEntry{}, false, errors.New("archive: runner tar object path invalid")
	}
	if len(name) > limits.maxPathBytes || validateRunnerRelativePath(name) != nil {
		return RunnerTreeEntry{}, false, errors.New("archive: runner tar path invalid")
	}

	entry := RunnerTreeEntry{Path: name}
	switch header.Typeflag {
	case tar.TypeDir:
		if header.Size != 0 || header.Linkname != "" {
			return RunnerTreeEntry{}, false, errors.New("archive: runner tar directory header invalid")
		}
		entry.Type = RunnerEntryDirectory
		entry.Mode = 0o555
	case tar.TypeReg:
		if header.Size < 0 || uint64(header.Size) > limits.maxFileBytes || header.Linkname != "" {
			return RunnerTreeEntry{}, false, errors.New("archive: runner tar file header invalid")
		}
		entry.Type = RunnerEntryRegular
		entry.Size = uint64(header.Size)
		entry.Mode = 0o444
		if header.Mode&0o111 != 0 {
			entry.Mode = 0o555
		}
	case tar.TypeSymlink:
		if header.Size != 0 || len(header.Linkname) > limits.maxLinkBytes ||
			validateRunnerLinkTarget(header.Linkname) != nil {
			return RunnerTreeEntry{}, false, errors.New("archive: runner tar symlink header invalid")
		}
		entry.Type = RunnerEntrySymlink
		entry.LinkTarget = header.Linkname
		entry.Size = uint64(len(header.Linkname))
		entry.Mode = 0
		entry.SHA256 = sha256String([]byte(header.Linkname))
	default:
		return RunnerTreeEntry{}, false, errors.New("archive: runner tar entry type prohibited")
	}
	return entry, false, nil
}

func extractRunnerArchiveSecondPass(
	file *os.File,
	identity fileIdentity,
	limits runnerArchiveLimits,
	sequence []RunnerTreeEntry,
	output string,
) error {
	stream, err := openRunnerTarStream(file)
	if err != nil {
		return err
	}
	rootFD, err := unix.Open(output, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("archive: runner extraction root open failed")
	}
	defer unix.Close(rootFD)

	sequenceIndex := 0
	rootSeen := false
	directories := make([]string, 0, 2048)
	for archiveIndex := 0; ; archiveIndex++ {
		header, err := stream.tar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("archive: runner extraction tar parse failed")
		}
		if archiveIndex >= limits.maxEntries {
			return errors.New("archive: runner extraction entry count exceeded")
		}
		entry, root, err := runnerEntryFromHeader(header, limits)
		if err != nil {
			return err
		}
		if root {
			if archiveIndex != 0 || rootSeen {
				return errors.New("archive: runner extraction root invalid")
			}
			rootSeen = true
			continue
		}
		if !rootSeen || sequenceIndex >= len(sequence) {
			return errors.New("archive: runner extraction sequence invalid")
		}
		expected := sequence[sequenceIndex]
		sequenceIndex++
		if entry.Path != expected.Path || entry.Type != expected.Type || entry.Size != expected.Size ||
			entry.Mode != expected.Mode || entry.LinkTarget != expected.LinkTarget ||
			(entry.Type != RunnerEntryRegular && entry.SHA256 != expected.SHA256) {
			return errors.New("archive: runner extraction header diverged")
		}
		switch entry.Type {
		case RunnerEntryDirectory:
			if err := createRunnerDirectoryAt(rootFD, entry.Path); err != nil {
				return err
			}
			directories = append(directories, entry.Path)
		case RunnerEntryRegular:
			if err := createRunnerFileAt(rootFD, entry, expected.SHA256, stream.tar); err != nil {
				return err
			}
		case RunnerEntrySymlink:
			if err := createRunnerSymlinkAt(rootFD, entry); err != nil {
				return err
			}
		default:
			return errors.New("archive: runner extraction type unavailable")
		}
	}
	if !rootSeen || sequenceIndex != len(sequence) {
		return errors.New("archive: runner extraction sequence incomplete")
	}
	if err := stream.finish(limits.maxTarPaddingBytes); err != nil {
		return err
	}
	after, err := fstatFile(file)
	if err != nil || !identity.stableEqual(after) {
		return errors.New("archive: runner archive changed during extraction")
	}
	if err := sealRunnerDirectories(rootFD, directories); err != nil {
		return err
	}
	return nil
}

func createRunnerDirectoryAt(rootFD int, relative string) error {
	parentFD, leaf, err := openRunnerParent(rootFD, relative)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Mkdirat(parentFD, leaf, 0o700); err != nil {
		return errors.New("archive: runner directory create failed")
	}
	identity, err := lstatRunnerAt(parentFD, leaf)
	if err != nil || identity.mode&unix.S_IFMT != unix.S_IFDIR ||
		identity.mode&0o777 != 0o700 || identity.uid != uint32(os.Geteuid()) {
		return errors.New("archive: runner directory create identity invalid")
	}
	return nil
}

func createRunnerFileAt(rootFD int, entry RunnerTreeEntry, expectedDigest string, source io.Reader) error {
	parentFD, leaf, err := openRunnerParent(rootFD, entry.Path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("archive: runner file create failed")
	}
	file := os.NewFile(uintptr(fd), entry.Path)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("archive: runner file descriptor invalid")
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(source, int64(entry.Size)+1))
	syncErr := file.Sync()
	chmodErr := file.Chmod(os.FileMode(entry.Mode))
	secondSyncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || chmodErr != nil || secondSyncErr != nil ||
		closeErr != nil || count != int64(entry.Size) ||
		hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return errors.New("archive: runner file copy or digest invalid")
	}
	identity, err := lstatRunnerAt(parentFD, leaf)
	if err != nil || identity.mode&unix.S_IFMT != unix.S_IFREG || identity.nlink != 1 ||
		identity.size != int64(entry.Size) || uint32(identity.mode&0o777) != entry.Mode ||
		identity.uid != uint32(os.Geteuid()) {
		return errors.New("archive: runner file output identity invalid")
	}
	return nil
}

func createRunnerSymlinkAt(rootFD int, entry RunnerTreeEntry) error {
	parentFD, leaf, err := openRunnerParent(rootFD, entry.Path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Symlinkat(entry.LinkTarget, parentFD, leaf); err != nil {
		return errors.New("archive: runner symlink create failed")
	}
	identity, err := lstatRunnerAt(parentFD, leaf)
	if err != nil || identity.mode&unix.S_IFMT != unix.S_IFLNK || identity.nlink != 1 ||
		identity.size != int64(entry.Size) ||
		identity.uid != uint32(os.Geteuid()) {
		return errors.New("archive: runner symlink output identity invalid")
	}
	buffer := make([]byte, maxRunnerLinkBytes+1)
	count, err := unix.Readlinkat(parentFD, leaf, buffer)
	if err != nil || string(buffer[:count]) != entry.LinkTarget {
		return errors.New("archive: runner symlink output target invalid")
	}
	return nil
}

func openRunnerParent(rootFD int, relative string) (int, string, error) {
	parts := strings.Split(relative, "/")
	if len(parts) == 0 {
		return -1, "", errors.New("archive: runner relative path invalid")
	}
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, "", errors.New("archive: runner root descriptor duplicate failed")
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if err != nil {
			return -1, "", errors.New("archive: runner parent directory open failed")
		}
		current = next
	}
	return current, parts[len(parts)-1], nil
}

func sealRunnerDirectories(rootFD int, directories []string) error {
	sort.Slice(directories, func(i, j int) bool {
		depthI, depthJ := strings.Count(directories[i], "/"), strings.Count(directories[j], "/")
		if depthI != depthJ {
			return depthI > depthJ
		}
		return directories[i] > directories[j]
	})
	for _, relative := range directories {
		fd, err := openRunnerDirectoryAt(rootFD, relative)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), relative)
		if file == nil {
			_ = unix.Close(fd)
			return errors.New("archive: runner directory descriptor invalid")
		}
		chmodErr := file.Chmod(0o555)
		syncErr := file.Sync()
		closeErr := file.Close()
		if chmodErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("archive: runner directory seal failed")
		}
	}
	if err := unix.Fsync(rootFD); err != nil {
		return errors.New("archive: runner root sync failed")
	}
	return nil
}

func openRunnerDirectoryAt(rootFD int, relative string) (int, error) {
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, errors.New("archive: runner root descriptor duplicate failed")
	}
	for _, part := range strings.Split(relative, "/") {
		next, err := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if err != nil {
			return -1, errors.New("archive: runner directory open failed")
		}
		current = next
	}
	return current, nil
}

func removeRunnerSnapshot(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}
