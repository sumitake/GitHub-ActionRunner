package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"golang.org/x/sys/unix"
)

type seedCatalogReadiness struct {
	SchemaVersion      uint32 `json:"schema_version"`
	ManifestSHA256     string `json:"manifest_sha256"`
	TreeLockSHA256     string `json:"tree_lock_sha256"`
	EvidenceGeneration uint64 `json:"evidence_generation"`
	Empty              bool   `json:"empty"`
}

type seedCatalog struct {
	root        string
	manifest    seedarchive.Manifest
	readiness   seedCatalogReadiness
	expectedUID uint32
	expectedGID uint32
}

func loadSeedCatalog(root, manifestPath, treeLockPath, readyPath string, expectedUID, expectedGID uint32) (seedCatalog, error) {
	for _, candidate := range []string{root, manifestPath, treeLockPath, readyPath} {
		if !canonicalRuntimePath(candidate) {
			return seedCatalog{}, errors.New("runner-gate: seed catalog path invalid")
		}
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return seedCatalog{}, errors.New("runner-gate: seed catalog root indirect")
	}
	var rootBefore unix.Stat_t
	if unix.Lstat(root, &rootBefore) != nil ||
		uint32(rootBefore.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(rootBefore.Mode)&0o777 != 0o555 ||
		rootBefore.Uid != expectedUID || rootBefore.Gid != expectedGID {
		return seedCatalog{}, errors.New("runner-gate: seed catalog root identity invalid")
	}

	manifestData, err := readLockedFile(manifestPath, 1<<20)
	if err != nil {
		return seedCatalog{}, err
	}
	defer zero(manifestData)
	manifest, err := seedarchive.Load(bytes.NewReader(manifestData))
	if err != nil {
		return seedCatalog{}, errors.New("runner-gate: seed manifest invalid")
	}
	canonicalManifest, err := seedarchive.EncodeManifest(manifest)
	if err != nil || !bytes.Equal(canonicalManifest, manifestData) {
		return seedCatalog{}, errors.New("runner-gate: seed manifest noncanonical")
	}

	treeLockData, err := readLockedFile(treeLockPath, maxTreeLockBytes)
	if err != nil {
		return seedCatalog{}, err
	}
	defer zero(treeLockData)
	readyData, err := readLockedFile(readyPath, 64<<10)
	if err != nil {
		return seedCatalog{}, err
	}
	defer zero(readyData)
	readiness, err := parseSeedReadiness(readyData)
	if err != nil {
		return seedCatalog{}, err
	}
	manifestObject := bytes.TrimSuffix(manifestData, []byte("\n"))
	manifestDigest := sha256.Sum256(manifestObject)
	treeLockDigest := sha256.Sum256(treeLockData)
	if hex.EncodeToString(manifestDigest[:]) != readiness.ManifestSHA256 ||
		hex.EncodeToString(treeLockDigest[:]) != readiness.TreeLockSHA256 ||
		readiness.Empty != (len(manifest.Seeds) == 0) {
		return seedCatalog{}, errors.New("runner-gate: seed catalog lock differs")
	}
	logical, err := seedarchive.Verify(os.DirFS(root), manifest)
	if err != nil || logical.Hex() != readiness.ManifestSHA256 {
		return seedCatalog{}, errors.New("runner-gate: seed catalog content invalid")
	}
	var rootAfter unix.Stat_t
	if unix.Lstat(root, &rootAfter) != nil || !stableGateStat(rootBefore, rootAfter) {
		return seedCatalog{}, errors.New("runner-gate: seed catalog root changed")
	}
	return seedCatalog{
		root: root, manifest: manifest, readiness: readiness,
		expectedUID: expectedUID, expectedGID: expectedGID,
	}, nil
}

func parseSeedReadiness(data []byte) (seedCatalogReadiness, error) {
	var readiness seedCatalogReadiness
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&readiness) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		readiness.SchemaVersion != 1 ||
		!lowerHex64.MatchString(readiness.ManifestSHA256) ||
		!lowerHex64.MatchString(readiness.TreeLockSHA256) ||
		readiness.EvidenceGeneration == 0 {
		return seedCatalogReadiness{}, errors.New("runner-gate: seed readiness invalid")
	}
	canonical, err := json.Marshal(readiness)
	if err != nil {
		return seedCatalogReadiness{}, errors.New("runner-gate: seed readiness encoding failed")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return seedCatalogReadiness{}, errors.New("runner-gate: seed readiness noncanonical")
	}
	return readiness, nil
}

func (catalog seedCatalog) hydrate(workRoot string, ids []string) error {
	if catalog.root == "" || catalog.readiness.EvidenceGeneration == 0 ||
		!canonicalRuntimePath(workRoot) || len(ids) > maxSeedCount ||
		!sort.StringsAreSorted(ids) {
		return errors.New("runner-gate: seed hydration inputs invalid")
	}
	seeds := make(map[string]seedarchive.Seed, len(catalog.manifest.Seeds))
	for _, seed := range catalog.manifest.Seeds {
		seeds[seed.ID] = seed
	}
	selected := make([]seedarchive.Seed, 0, len(ids))
	for index, id := range ids {
		seed, exists := seeds[id]
		if !exists || (index > 0 && id == ids[index-1]) {
			return errors.New("runner-gate: seed selection unavailable")
		}
		selected = append(selected, seed)
	}
	parent := filepath.Dir(workRoot)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errors.New("runner-gate: work parent indirect")
	}
	var parentStat unix.Stat_t
	if unix.Lstat(parent, &parentStat) != nil ||
		uint32(parentStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(parentStat.Mode)&0o777 != 0o700 ||
		parentStat.Uid != uint32(os.Geteuid()) {
		return errors.New("runner-gate: work parent identity invalid")
	}
	var existing unix.Stat_t
	if err := unix.Lstat(workRoot, &existing); err == nil || !errors.Is(err, unix.ENOENT) {
		return errors.New("runner-gate: work root is not fresh")
	}
	oldMask := unix.Umask(0o077)
	err = os.Mkdir(workRoot, 0o700)
	unix.Umask(oldMask)
	if err != nil {
		return errors.New("runner-gate: work root create failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(workRoot)
		}
	}()

	directories := make(map[string]struct{})
	type copyPlan struct {
		source string
		target string
		file   seedarchive.File
	}
	var plans []copyPlan
	for _, seed := range selected {
		for _, file := range seed.Files {
			target, err := hydratedTarget(file.Target)
			if err != nil {
				return err
			}
			plans = append(plans, copyPlan{source: file.Path, target: target, file: file})
			for directory := path.Dir(target); directory != "."; directory = path.Dir(directory) {
				directories[directory] = struct{}{}
				if path.Dir(directory) == directory {
					break
				}
			}
		}
	}
	directoryNames := make([]string, 0, len(directories))
	for directory := range directories {
		directoryNames = append(directoryNames, directory)
	}
	sort.Slice(directoryNames, func(left, right int) bool {
		leftDepth := strings.Count(directoryNames[left], "/")
		rightDepth := strings.Count(directoryNames[right], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directoryNames[left] < directoryNames[right]
	})
	for _, directory := range directoryNames {
		if err := os.Mkdir(filepath.Join(workRoot, filepath.FromSlash(directory)), 0o700); err != nil {
			return errors.New("runner-gate: hydrated directory create failed")
		}
	}
	for _, plan := range plans {
		if err := catalog.copyFile(
			plan.source,
			filepath.Join(workRoot, filepath.FromSlash(plan.target)),
			plan.file,
		); err != nil {
			return err
		}
	}
	for index := len(directoryNames) - 1; index >= 0; index-- {
		if err := os.Chmod(filepath.Join(workRoot, filepath.FromSlash(directoryNames[index])), 0o555); err != nil {
			return errors.New("runner-gate: hydrated directory mode failed")
		}
	}
	committed = true
	return nil
}

func hydratedTarget(target string) (string, error) {
	switch {
	case strings.HasPrefix(target, "actions/"):
		return "_actions/" + strings.TrimPrefix(target, "actions/"), nil
	case strings.HasPrefix(target, "tools/"):
		return "_tool/" + strings.TrimPrefix(target, "tools/"), nil
	default:
		return "", errors.New("runner-gate: seed target namespace invalid")
	}
}

func (catalog seedCatalog) copyFile(relative, target string, want seedarchive.File) error {
	source, rootIdentity, err := catalog.openSourceFile(relative)
	if err != nil {
		return err
	}
	defer source.Close()
	before, err := gateFstat(source)
	if err != nil ||
		uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG ||
		uint32(before.Mode)&0o777 != want.Mode ||
		before.Uid != catalog.expectedUID || before.Gid != catalog.expectedGID ||
		uint64(before.Dev) != uint64(rootIdentity.Dev) ||
		before.Nlink != 1 || before.Size < 0 || uint64(before.Size) != want.Size {
		return errors.New("runner-gate: seed source file identity invalid")
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("runner-gate: hydrated file create failed")
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(source, before.Size+1))
	after, afterErr := gateFstat(source)
	syncErr := output.Sync()
	chmodErr := output.Chmod(os.FileMode(want.Mode))
	closeErr := output.Close()
	if copyErr != nil || afterErr != nil || syncErr != nil || chmodErr != nil || closeErr != nil ||
		count != before.Size || !stableGateStat(before, after) ||
		hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
		return errors.New("runner-gate: seed source changed or copy failed")
	}
	return nil
}

func (catalog seedCatalog) openSourceFile(relative string) (*os.File, unix.Stat_t, error) {
	rootFD, err := unix.Open(catalog.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, unix.Stat_t{}, errors.New("runner-gate: seed root open failed")
	}
	var rootIdentity unix.Stat_t
	if unix.Fstat(rootFD, &rootIdentity) != nil ||
		uint32(rootIdentity.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(rootIdentity.Mode)&0o777 != 0o555 ||
		rootIdentity.Uid != catalog.expectedUID || rootIdentity.Gid != catalog.expectedGID {
		_ = unix.Close(rootFD)
		return nil, unix.Stat_t{}, errors.New("runner-gate: seed root identity changed")
	}
	current := rootFD
	parts := strings.Split(relative, "/")
	for index, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(parts)-1 {
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
			return nil, unix.Stat_t{}, errors.New("runner-gate: seed source open failed")
		}
		if index < len(parts)-1 {
			var directory unix.Stat_t
			if unix.Fstat(next, &directory) != nil ||
				uint32(directory.Mode)&unix.S_IFMT != unix.S_IFDIR ||
				uint32(directory.Mode)&0o222 != 0 ||
				directory.Uid != catalog.expectedUID || directory.Gid != catalog.expectedGID ||
				uint64(directory.Dev) != uint64(rootIdentity.Dev) {
				_ = unix.Close(next)
				_ = unix.Close(rootFD)
				return nil, unix.Stat_t{}, errors.New("runner-gate: seed directory identity invalid")
			}
		}
		current = next
	}
	_ = unix.Close(rootFD)
	file := os.NewFile(uintptr(current), relative)
	if file == nil {
		_ = unix.Close(current)
		return nil, unix.Stat_t{}, errors.New("runner-gate: seed descriptor invalid")
	}
	return file, rootIdentity, nil
}
