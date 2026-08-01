package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"golang.org/x/sys/unix"
)

const (
	syntheticListenerInputName = "portable-ghar-task11-listener"
	maxSyntheticListenerBytes  = 256 << 20
)

type syntheticListenerOptions struct {
	listenerPath       string
	evidenceGeneration uint64
	outputDirectory    string
}

func parseSyntheticListenerOptions(args []string) (syntheticListenerOptions, error) {
	if len(args) != 6 {
		return syntheticListenerOptions{}, errors.New("runtime-lock: synthetic listener arguments invalid")
	}
	values := make(map[string]string, 3)
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		switch name {
		case "--listener", "--generation", "--output-dir":
		default:
			return syntheticListenerOptions{}, errors.New("runtime-lock: synthetic listener argument unknown")
		}
		if value == "" {
			return syntheticListenerOptions{}, errors.New("runtime-lock: synthetic listener argument empty")
		}
		if _, exists := values[name]; exists {
			return syntheticListenerOptions{}, errors.New("runtime-lock: synthetic listener argument duplicated")
		}
		values[name] = value
	}
	if len(values) != 3 {
		return syntheticListenerOptions{}, errors.New("runtime-lock: synthetic listener arguments incomplete")
	}
	generation, err := strconv.ParseUint(values["--generation"], 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != values["--generation"] {
		return syntheticListenerOptions{}, errors.New("runtime-lock: synthetic listener generation invalid")
	}
	return syntheticListenerOptions{
		listenerPath:       values["--listener"],
		evidenceGeneration: generation,
		outputDirectory:    values["--output-dir"],
	}, nil
}

func stageSyntheticListener(options syntheticListenerOptions, hook extractHook) error {
	if options.evidenceGeneration == 0 ||
		!canonicalAbsolute(options.listenerPath) ||
		!canonicalAbsolute(options.outputDirectory) ||
		filepath.Base(options.listenerPath) != syntheticListenerInputName ||
		pathsOverlap(options.listenerPath, options.outputDirectory) {
		return errors.New("runtime-lock: synthetic listener inputs invalid")
	}
	if err := validatePrivateDirectory(filepath.Dir(options.listenerPath)); err != nil {
		return err
	}
	outputParent := filepath.Dir(options.outputDirectory)
	if err := validatePrivateDirectory(outputParent); err != nil {
		return err
	}
	if _, err := os.Lstat(options.outputDirectory); !os.IsNotExist(err) {
		return errors.New("runtime-lock: synthetic listener output already exists or cannot be inspected")
	}

	source, sourceInfo, err := openSyntheticListener(options.listenerPath)
	if err != nil {
		return err
	}
	defer source.Close()

	if err := os.Mkdir(options.outputDirectory, 0o700); err != nil {
		return errors.New("runtime-lock: synthetic listener output create failed")
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
	publishedRoot := filepath.Join(options.outputDirectory, "runner")
	if err := os.Mkdir(publishedRoot, 0o700); err != nil {
		return errors.New("runtime-lock: synthetic runner root create failed")
	}
	for _, relative := range []string{"bin", "externals"} {
		if err := os.Mkdir(filepath.Join(publishedRoot, relative), 0o700); err != nil {
			return errors.New("runtime-lock: synthetic runner directory create failed")
		}
	}

	listenerDigest, err := copySyntheticListener(
		source,
		sourceInfo,
		options.listenerPath,
		filepath.Join(publishedRoot, "bin", "Runner.Listener"),
	)
	if err != nil {
		return err
	}
	for _, relative := range []string{"bin", "externals"} {
		if err := os.Chmod(filepath.Join(publishedRoot, relative), 0o555); err != nil {
			return errors.New("runtime-lock: synthetic runner directory mode failed")
		}
	}
	manifest := seedarchive.RunnerTreeManifest{
		SchemaVersion: 1,
		Entries: []seedarchive.RunnerTreeEntry{
			{Path: "bin", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
			{
				Path:   "bin/Runner.Listener",
				Type:   seedarchive.RunnerEntryRegular,
				SHA256: listenerDigest,
				Size:   uint64(sourceInfo.Size()),
				Mode:   0o555,
			},
			{Path: "externals", Type: seedarchive.RunnerEntryDirectory, Mode: 0o555},
		},
	}
	published, err := seedarchive.VerifyRunnerDirectory(publishedRoot, manifest, options.evidenceGeneration)
	if err != nil {
		return errors.New("runtime-lock: synthetic runner verification failed")
	}
	if err := finalizeRunnerRuntime(
		options.outputDirectory,
		publishedRoot,
		published,
		options.evidenceGeneration,
		hook,
	); err != nil {
		return err
	}
	committed = true
	return nil
}

func openSyntheticListener(path string) (*os.File, os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, nil, errors.New("runtime-lock: synthetic listener path indirect")
	}
	before, err := os.Lstat(path)
	if err != nil || !validSyntheticListenerInfo(before) {
		return nil, nil, errors.New("runtime-lock: synthetic listener identity invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errors.New("runtime-lock: synthetic listener open failed")
	}
	file := os.NewFile(uintptr(fd), "synthetic-listener")
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, errors.New("runtime-lock: synthetic listener descriptor invalid")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !sameSyntheticListenerInfo(before, opened) {
		_ = file.Close()
		return nil, nil, errors.New("runtime-lock: synthetic listener identity changed")
	}
	return file, before, nil
}

func validSyntheticListenerInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 ||
		info.Size() <= 0 || info.Size() > maxSyntheticListenerBytes {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid()) && stat.Gid == uint32(os.Getegid())
}

func sameSyntheticListenerInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil &&
		os.SameFile(left, right) &&
		left.Mode() == right.Mode() &&
		left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime()) &&
		validSyntheticListenerInfo(right)
}

func copySyntheticListener(
	source *os.File,
	sourceInfo os.FileInfo,
	sourcePath string,
	destinationPath string,
) (string, error) {
	if source == nil || sourceInfo == nil {
		return "", errors.New("runtime-lock: synthetic listener authority required")
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("runtime-lock: synthetic listener destination create failed")
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, digest), io.LimitReader(source, maxSyntheticListenerBytes+1))
	syncErr := destination.Sync()
	chmodErr := destination.Chmod(0o555)
	secondSyncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil || syncErr != nil || chmodErr != nil || secondSyncErr != nil || closeErr != nil ||
		written != sourceInfo.Size() {
		return "", errors.New("runtime-lock: synthetic listener copy failed")
	}
	openedAfter, statErr := source.Stat()
	pathAfter, pathErr := os.Lstat(sourcePath)
	if statErr != nil || pathErr != nil ||
		!sameSyntheticListenerInfo(sourceInfo, openedAfter) ||
		!sameSyntheticListenerInfo(sourceInfo, pathAfter) {
		return "", errors.New("runtime-lock: synthetic listener changed during copy")
	}
	destinationInfo, err := os.Lstat(destinationPath)
	if err != nil || !destinationInfo.Mode().IsRegular() ||
		destinationInfo.Mode().Perm() != 0o555 ||
		destinationInfo.Size() != sourceInfo.Size() {
		return "", errors.New("runtime-lock: synthetic listener destination invalid")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
