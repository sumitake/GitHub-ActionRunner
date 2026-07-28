// Package archive verifies bounded, first-party action/tool seed manifests.
// Logical content verification and OS directory identity are deliberately
// represented by different types.
package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	maxManifestBytes = 1 << 20
	maxSeeds         = 128
	maxFiles         = 10000
	maxPathBytes     = 512
	maxSourceBytes   = 2048
)

type Kind string

const (
	KindAction Kind = "action"
	KindTool   Kind = "tool"
)

// Manifest is a closed, deterministic seed manifest.
type Manifest struct {
	SchemaVersion uint32 `json:"schema_version"`
	Seeds         []Seed `json:"seeds"`
}

type Seed struct {
	ID       string          `json:"id"`
	Kind     Kind            `json:"kind"`
	Source   string          `json:"source"`
	Revision string          `json:"revision"`
	License  LicenseEvidence `json:"license"`
	Files    []File          `json:"files"`
}

type LicenseEvidence struct {
	SPDX   string `json:"spdx"`
	Path   string `json:"path"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}

type File struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
	Mode   uint32 `json:"mode"`
}

var (
	idPattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	hex40Pattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	toolRevision    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	sourceSegment   = regexp.MustCompile(`^[0-9A-Za-z._+-]+$`)
	approvedLicense = map[string]struct{}{
		"Apache-2.0":   {},
		"BSD-2-Clause": {},
		"BSD-3-Clause": {},
		"ISC":          {},
		"MIT":          {},
	}
)

// Load parses exactly one bounded JSON object, rejects duplicate and unknown
// fields, and validates all source/path/license policy.
func Load(reader io.Reader) (Manifest, error) {
	if reader == nil {
		return Manifest{}, errors.New("archive: manifest reader required")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxManifestBytes {
		return Manifest{}, errors.New("archive: manifest size invalid")
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return Manifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, errors.New("archive: manifest json invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Manifest{}, errors.New("archive: manifest has trailing data")
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func rejectDuplicateJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return errors.New("archive: duplicate or malformed json field")
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errors.New("archive: manifest has trailing data")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array not closed")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != 1 || len(manifest.Seeds) > maxSeeds {
		return errors.New("archive: manifest version or seed count invalid")
	}
	if !sort.SliceIsSorted(manifest.Seeds, func(i, j int) bool { return manifest.Seeds[i].ID < manifest.Seeds[j].ID }) {
		return errors.New("archive: seeds are not sorted")
	}
	seenSeed := make(map[string]struct{})
	seenSource := make(map[string]struct{})
	seenPath := make(map[string]struct{})
	seenTarget := make(map[string]struct{})
	totalFiles := 0
	for _, seed := range manifest.Seeds {
		foldedID := strings.ToLower(seed.ID)
		if !idPattern.MatchString(seed.ID) {
			return errors.New("archive: seed id invalid")
		}
		if _, exists := seenSeed[foldedID]; exists {
			return errors.New("archive: seed id collision")
		}
		seenSeed[foldedID] = struct{}{}
		repository, err := validateSource(seed)
		if err != nil {
			return err
		}
		sourceKey := seed.Source + "\x00" + seed.Revision
		if _, exists := seenSource[sourceKey]; exists {
			return errors.New("archive: source revision duplicated")
		}
		seenSource[sourceKey] = struct{}{}
		if _, ok := approvedLicense[seed.License.SPDX]; !ok || seed.License.Size == 0 || !hex64Pattern.MatchString(seed.License.SHA256) {
			return errors.New("archive: license evidence invalid")
		}
		if err := validateRelativePath(seed.License.Path); err != nil {
			return errors.New("archive: license path invalid")
		}
		if len(seed.Files) == 0 || totalFiles+len(seed.Files) > maxFiles || !sort.SliceIsSorted(seed.Files, func(i, j int) bool { return seed.Files[i].Path < seed.Files[j].Path }) {
			return errors.New("archive: seed file set invalid")
		}
		totalFiles += len(seed.Files)
		licenseFound := false
		for _, file := range seed.Files {
			if err := validateRelativePath(file.Path); err != nil || validateRelativePath(file.Target) != nil {
				return errors.New("archive: file path invalid")
			}
			if file.Size == 0 || !hex64Pattern.MatchString(file.SHA256) || (file.Mode != 0o444 && file.Mode != 0o555) {
				return errors.New("archive: file identity invalid")
			}
			wantPrefix := "actions/" + repository + "/" + seed.Revision + "/"
			if seed.Kind == KindTool {
				wantPrefix = "tools/" + seed.ID + "/" + seed.Revision + "/"
			}
			if !strings.HasPrefix(file.Target, wantPrefix) || len(file.Target) == len(wantPrefix) {
				return errors.New("archive: file target outside kind namespace")
			}
			foldedPath := strings.ToLower(file.Path)
			foldedTarget := strings.ToLower(file.Target)
			if _, exists := seenPath[foldedPath]; exists {
				return errors.New("archive: file path collision")
			}
			if _, exists := seenTarget[foldedTarget]; exists {
				return errors.New("archive: file target collision")
			}
			seenPath[foldedPath] = struct{}{}
			seenTarget[foldedTarget] = struct{}{}
			if file.Path == seed.License.Path && file.Size == seed.License.Size && file.SHA256 == seed.License.SHA256 {
				licenseFound = true
			}
		}
		if !licenseFound {
			return errors.New("archive: license file is not manifest-bound")
		}
	}
	return nil
}

func validateSource(seed Seed) (string, error) {
	if len(seed.Source) == 0 || len(seed.Source) > maxSourceBytes || !asciiPrintable(seed.Source) || strings.Contains(seed.Source, "%") {
		return "", errors.New("archive: source url invalid")
	}
	parsed, err := url.ParseRequestURI(seed.Source)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.Hostname() != "github.com" || parsed.Port() != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Opaque != "" || parsed.ForceQuery || parsed.String() != seed.Source {
		return "", errors.New("archive: source url noncanonical")
	}
	if !strings.HasPrefix(parsed.Path, "/") || strings.Contains(parsed.Path, "//") || path.Clean(parsed.Path) != parsed.Path {
		return "", errors.New("archive: source path invalid")
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(segments) < 3 || segments[0] != "actions" || !sourceSegment.MatchString(segments[1]) {
		return "", errors.New("archive: source organization invalid")
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || !sourceSegment.MatchString(segment) {
			return "", errors.New("archive: source segment invalid")
		}
	}
	switch seed.Kind {
	case KindAction:
		if !hex40Pattern.MatchString(seed.Revision) || !strings.Contains(parsed.Path, seed.Revision) {
			return "", errors.New("archive: action revision invalid")
		}
	case KindTool:
		if !toolRevision.MatchString(seed.Revision) || !strings.Contains(parsed.Path, "/releases/download/"+seed.Revision+"/") {
			return "", errors.New("archive: tool release invalid")
		}
	default:
		return "", errors.New("archive: seed kind invalid")
	}
	return segments[1], nil
}

func validateRelativePath(value string) error {
	if len(value) == 0 || len(value) > maxPathBytes || !asciiPrintable(value) || strings.ContainsAny(value, `\\:`) || !fs.ValidPath(value) || value == "." || path.Clean(value) != value {
		return errors.New("invalid relative path")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || !sourceSegment.MatchString(segment) {
			return errors.New("invalid path segment")
		}
	}
	return nil
}

func asciiPrintable(value string) bool {
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func manifestDigest(manifest Manifest) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("archive: canonical manifest encoding failed")
	}
	return sha256.Sum256(encoded), nil
}

// EncodeManifest emits the single canonical JSON representation used for
// immutable seed-cache publication. The manifest digest intentionally covers
// the JSON object bytes without the transport newline.
func EncodeManifest(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, errors.New("archive: canonical manifest encoding failed")
	}
	return append(encoded, '\n'), nil
}

func hexDigest(digest [sha256.Size]byte) string { return hex.EncodeToString(digest[:]) }
