package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
)

type seedReadiness struct {
	SchemaVersion      uint32 `json:"schema_version"`
	ManifestSHA256     string `json:"manifest_sha256"`
	TreeLockSHA256     string `json:"tree_lock_sha256"`
	EvidenceGeneration uint64 `json:"evidence_generation"`
	Empty              bool   `json:"empty"`
}

type stageSeedOptions struct {
	root               string
	manifestPath       string
	evidenceGeneration uint64
	outputDirectory    string
}

func parseStageSeedOptions(args []string) (stageSeedOptions, error) {
	if len(args) != 4 && len(args) != 8 {
		return stageSeedOptions{}, errors.New("runtime-lock: seed arguments invalid")
	}
	values := make(map[string]string, 4)
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		switch name {
		case "--root", "--manifest", "--generation", "--output-dir":
		default:
			return stageSeedOptions{}, errors.New("runtime-lock: seed argument unknown")
		}
		if value == "" {
			return stageSeedOptions{}, errors.New("runtime-lock: seed argument empty")
		}
		if _, exists := values[name]; exists {
			return stageSeedOptions{}, errors.New("runtime-lock: seed argument duplicated")
		}
		values[name] = value
	}
	generation, err := strconv.ParseUint(values["--generation"], 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != values["--generation"] ||
		values["--output-dir"] == "" {
		return stageSeedOptions{}, errors.New("runtime-lock: seed generation invalid")
	}
	rootPresent := values["--root"] != ""
	manifestPresent := values["--manifest"] != ""
	if rootPresent != manifestPresent || (len(args) == 4 && rootPresent) || (len(args) == 8 && !rootPresent) {
		return stageSeedOptions{}, errors.New("runtime-lock: seed source pair invalid")
	}
	return stageSeedOptions{
		root:               values["--root"],
		manifestPath:       values["--manifest"],
		evidenceGeneration: generation,
		outputDirectory:    values["--output-dir"],
	}, nil
}

func stageSeedCache(options stageSeedOptions) error {
	if options.evidenceGeneration == 0 || !canonicalAbsolute(options.outputDirectory) {
		return errors.New("runtime-lock: seed inputs invalid")
	}
	outputParent := filepath.Dir(options.outputDirectory)
	if err := validatePrivateDirectory(outputParent); err != nil {
		return err
	}
	if _, err := os.Lstat(options.outputDirectory); !os.IsNotExist(err) {
		return errors.New("runtime-lock: seed output already exists or cannot be inspected")
	}

	var (
		sourceRoot string
		manifest   seedarchive.Manifest
		temporary  string
		err        error
	)
	if options.root == "" {
		temporary, err = os.MkdirTemp(outputParent, ".portable-ghar-empty-seeds-")
		if err != nil {
			return errors.New("runtime-lock: empty seed source create failed")
		}
		defer os.RemoveAll(temporary)
		if err := os.Chmod(temporary, 0o700); err != nil {
			return errors.New("runtime-lock: empty seed source mode failed")
		}
		sourceRoot, err = filepath.EvalSymlinks(temporary)
		if err != nil || sourceRoot != temporary {
			return errors.New("runtime-lock: empty seed source indirect")
		}
		manifest = seedarchive.Manifest{SchemaVersion: 1, Seeds: []seedarchive.Seed{}}
	} else {
		if !canonicalAbsolute(options.root) || !canonicalAbsolute(options.manifestPath) ||
			pathsOverlap(options.root, options.outputDirectory) {
			return errors.New("runtime-lock: seed source invalid")
		}
		sourceRoot, err = filepath.EvalSymlinks(options.root)
		if err != nil || sourceRoot != options.root {
			return errors.New("runtime-lock: seed source indirect")
		}
		manifest, err = loadCanonicalManifest(options.manifestPath)
		if err != nil {
			return err
		}
	}

	source, err := seedarchive.VerifyDirectory(sourceRoot, manifest, options.evidenceGeneration)
	if err != nil {
		return errors.New("runtime-lock: seed source verification failed")
	}
	if err := os.Mkdir(options.outputDirectory, 0o700); err != nil {
		return errors.New("runtime-lock: seed output create failed")
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

	publishedRoot := filepath.Join(options.outputDirectory, seedCacheDirectory)
	published, err := seedarchive.PublishVerified(source, publishedRoot)
	if err != nil {
		return errors.New("runtime-lock: seed publication failed")
	}
	manifestDocument, err := seedarchive.EncodeManifest(manifest)
	if err != nil {
		return errors.New("runtime-lock: seed manifest encoding failed")
	}
	if err := writeVerifiedFile(filepath.Join(options.outputDirectory, seedManifestName), manifestDocument, 0o444); err != nil {
		return err
	}
	var treeLock bytes.Buffer
	if err := seedarchive.WriteTreeLock(&treeLock, published); err != nil ||
		shaHex(treeLock.Bytes()) != published.TreeLockDigest() {
		return errors.New("runtime-lock: seed tree lock generation failed")
	}
	if err := writeVerifiedFile(filepath.Join(options.outputDirectory, seedTreeLockName), treeLock.Bytes(), 0o444); err != nil {
		return err
	}
	finalPublished, err := seedarchive.VerifyDirectory(publishedRoot, manifest, options.evidenceGeneration)
	if err != nil ||
		finalPublished.ManifestDigest() != published.ManifestDigest() ||
		finalPublished.TreeLockDigest() != published.TreeLockDigest() {
		return errors.New("runtime-lock: published seed cache changed")
	}
	readyDocument, err := encodeCanonical(seedReadiness{
		SchemaVersion:      1,
		ManifestSHA256:     published.ManifestDigest(),
		TreeLockSHA256:     published.TreeLockDigest(),
		EvidenceGeneration: options.evidenceGeneration,
		Empty:              len(manifest.Seeds) == 0,
	})
	if err != nil {
		return errors.New("runtime-lock: seed readiness encoding failed")
	}
	if err := writeVerifiedFile(filepath.Join(options.outputDirectory, readyName), readyDocument, 0o444); err != nil {
		return err
	}
	if err := syncDirectory(options.outputDirectory); err != nil || syncDirectory(outputParent) != nil {
		return errors.New("runtime-lock: seed publication sync failed")
	}
	committed = true
	return nil
}
