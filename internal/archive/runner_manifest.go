package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
)

const (
	maxRunnerManifestBytes = 8 << 20
	maxRunnerEntries       = 16_384
	maxRunnerPathBytes     = 512
	maxRunnerLinkBytes     = 512
	maxRunnerFileBytes     = 256 << 20
	maxRunnerExpandedBytes = 1 << 30

	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type RunnerEntryType string

const (
	RunnerEntryDirectory RunnerEntryType = "directory"
	RunnerEntryRegular   RunnerEntryType = "regular"
	RunnerEntrySymlink   RunnerEntryType = "symlink"
)

// RunnerTreeManifest is the closed logical identity of one normalized
// upstream runner tree. It deliberately carries no action/tool provenance and
// cannot authorize seed publication.
type RunnerTreeManifest struct {
	SchemaVersion uint32            `json:"schema_version"`
	Entries       []RunnerTreeEntry `json:"entries"`
}

type RunnerTreeEntry struct {
	Path       string          `json:"path"`
	Type       RunnerEntryType `json:"type"`
	SHA256     string          `json:"sha256"`
	Size       uint64          `json:"size"`
	Mode       uint32          `json:"mode"`
	LinkTarget string          `json:"link_target"`
}

func LoadRunnerManifest(reader io.Reader) (RunnerTreeManifest, error) {
	if reader == nil {
		return RunnerTreeManifest{}, errors.New("archive: runner manifest reader required")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxRunnerManifestBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxRunnerManifestBytes {
		return RunnerTreeManifest{}, errors.New("archive: runner manifest size invalid")
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return RunnerTreeManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest RunnerTreeManifest
	if err := decoder.Decode(&manifest); err != nil {
		return RunnerTreeManifest{}, errors.New("archive: runner manifest json invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return RunnerTreeManifest{}, errors.New("archive: runner manifest has trailing data")
	}
	if err := validateRunnerManifest(manifest); err != nil {
		return RunnerTreeManifest{}, err
	}
	canonical, err := EncodeRunnerManifest(manifest)
	if err != nil || !bytes.Equal(data, canonical) {
		return RunnerTreeManifest{}, errors.New("archive: runner manifest encoding noncanonical")
	}
	return manifest, nil
}

func EncodeRunnerManifest(manifest RunnerTreeManifest) ([]byte, error) {
	if err := validateRunnerManifest(manifest); err != nil {
		return nil, err
	}
	document, err := json.Marshal(manifest)
	if err != nil {
		return nil, errors.New("archive: runner manifest encode failed")
	}
	return append(document, '\n'), nil
}

func validateRunnerManifest(manifest RunnerTreeManifest) error {
	if manifest.SchemaVersion != 1 || len(manifest.Entries) == 0 || len(manifest.Entries) > maxRunnerEntries {
		return errors.New("archive: runner manifest version or entry count invalid")
	}
	if !sort.SliceIsSorted(manifest.Entries, func(i, j int) bool {
		return manifest.Entries[i].Path < manifest.Entries[j].Path
	}) {
		return errors.New("archive: runner manifest entries not sorted")
	}

	entries := make(map[string]RunnerTreeEntry, len(manifest.Entries))
	folded := make(map[string]struct{}, len(manifest.Entries))
	var expanded uint64
	for _, entry := range manifest.Entries {
		if err := validateRunnerRelativePath(entry.Path); err != nil {
			return err
		}
		key := strings.ToLower(entry.Path)
		if _, exists := folded[key]; exists {
			return errors.New("archive: runner path collision")
		}
		folded[key] = struct{}{}
		entries[entry.Path] = entry

		switch entry.Type {
		case RunnerEntryDirectory:
			if entry.SHA256 != "" || entry.Size != 0 || entry.Mode != 0o555 || entry.LinkTarget != "" {
				return errors.New("archive: runner directory identity invalid")
			}
			if !strings.Contains(entry.Path, "/") && entry.Path != "bin" && entry.Path != "externals" {
				return errors.New("archive: unexpected runner top-level directory")
			}
		case RunnerEntryRegular:
			if !hex64Pattern.MatchString(entry.SHA256) ||
				(entry.Mode != 0o444 && entry.Mode != 0o555) ||
				entry.LinkTarget != "" ||
				entry.Size > maxRunnerFileBytes ||
				(entry.Size == 0 && entry.SHA256 != emptySHA256) {
				return errors.New("archive: runner file identity invalid")
			}
			if entry.Size > maxRunnerExpandedBytes || expanded > maxRunnerExpandedBytes-entry.Size {
				return errors.New("archive: runner expanded size invalid")
			}
			expanded += entry.Size
		case RunnerEntrySymlink:
			if entry.Mode != 0 || entry.Size == 0 || entry.Size > maxRunnerLinkBytes ||
				uint64(len(entry.LinkTarget)) != entry.Size ||
				entry.SHA256 != sha256String([]byte(entry.LinkTarget)) ||
				validateRunnerLinkTarget(entry.LinkTarget) != nil {
				return errors.New("archive: runner symlink identity invalid")
			}
		default:
			return errors.New("archive: runner entry type invalid")
		}
	}

	for _, entry := range manifest.Entries {
		parent := path.Dir(entry.Path)
		if parent != "." {
			parentEntry, exists := entries[parent]
			if !exists || parentEntry.Type != RunnerEntryDirectory {
				return errors.New("archive: runner parent directory missing")
			}
		}
		if entry.Type != RunnerEntrySymlink {
			continue
		}
		resolved := path.Clean(path.Join(path.Dir(entry.Path), entry.LinkTarget))
		if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
			return errors.New("archive: runner symlink escapes root")
		}
		target, exists := entries[resolved]
		if !exists || target.Type != RunnerEntryRegular {
			return errors.New("archive: runner symlink target is not a regular file")
		}
	}

	for _, required := range []string{"bin", "externals"} {
		entry, exists := entries[required]
		if !exists || entry.Type != RunnerEntryDirectory {
			return errors.New("archive: runner top-level tree missing")
		}
	}
	listener, exists := entries["bin/Runner.Listener"]
	if !exists || listener.Type != RunnerEntryRegular || listener.Mode != 0o555 || listener.Size == 0 {
		return errors.New("archive: runner listener missing or invalid")
	}
	return nil
}

func validateRunnerRelativePath(value string) error {
	if len(value) == 0 || len(value) > maxRunnerPathBytes || !asciiPrintable(value) ||
		strings.ContainsAny(value, `\`+"\x00") || strings.HasPrefix(value, "/") ||
		path.Clean(value) != value || value == "." || value == ".." ||
		strings.HasPrefix(value, "../") {
		return errors.New("archive: runner path invalid")
	}
	segments := strings.Split(value, "/")
	for index, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("archive: runner path segment invalid")
		}
		folded := strings.ToLower(segment)
		if folded == "_work" || folded == "_diag" || folded == "_update" ||
			folded == ".runner" || strings.HasPrefix(folded, ".credentials") {
			return errors.New("archive: mutable runner path prohibited")
		}
		if index == 0 && len(segments) > 1 && segment != "bin" && segment != "externals" {
			return errors.New("archive: unexpected runner top-level tree")
		}
	}
	return nil
}

func validateRunnerLinkTarget(value string) error {
	if len(value) == 0 || len(value) > maxRunnerLinkBytes || !asciiPrintable(value) ||
		strings.ContainsAny(value, `\`+"\x00") || strings.HasPrefix(value, "/") ||
		path.Clean(value) != value || value == "." {
		return errors.New("archive: runner symlink target invalid")
	}
	return nil
}

func runnerManifestDigest(manifest RunnerTreeManifest) ([sha256.Size]byte, error) {
	document, err := EncodeRunnerManifest(manifest)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(document), nil
}

func cloneRunnerManifest(manifest RunnerTreeManifest) RunnerTreeManifest {
	cloned := manifest
	cloned.Entries = append(make([]RunnerTreeEntry, 0, len(manifest.Entries)), manifest.Entries...)
	return cloned
}

func sha256String(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
