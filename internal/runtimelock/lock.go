// Package runtimelock defines the canonical, immutable runner image lock.
package runtimelock

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	seedarchive "github.com/sumitake/portable-ghar/internal/archive"
	"github.com/sumitake/portable-ghar/internal/buildinfo"
)

const (
	maxLockBytes        = 64 << 10
	runtimeListenerPath = "/opt/actions-runner/bin/Runner.Listener"
)

var (
	hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Listener struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type Lock struct {
	SchemaVersion         uint32   `json:"schema_version"`
	RunnerVersion         string   `json:"runner_version"`
	RunnerArchiveSHA256   string   `json:"runner_archive_sha256"`
	RunnerSourceCommit    string   `json:"runner_source_commit"`
	CommandSettingsSHA256 string   `json:"command_settings_sha256"`
	RunnerBaseImage       string   `json:"runner_base_image"`
	ManifestSHA256        string   `json:"manifest_sha256"`
	TreeLockSHA256        string   `json:"tree_lock_sha256"`
	EvidenceGeneration    uint64   `json:"evidence_generation"`
	Listener              Listener `json:"listener"`
}

func NewRunnerLock(verified seedarchive.VerifiedRunnerDirectory, listenerRelative string) (Lock, error) {
	if listenerRelative != "bin/Runner.Listener" || verified.Generation() == 0 || !hex64.MatchString(verified.ManifestDigest()) || !hex64.MatchString(verified.TreeLockDigest()) {
		return Lock{}, errors.New("runtimelock: verified runner authority required")
	}
	listener, err := verified.File(listenerRelative)
	if err != nil || listener.Mode != 0o555 || listener.Size == 0 || !hex64.MatchString(listener.SHA256) {
		return Lock{}, errors.New("runtimelock: verified listener required")
	}
	pins := buildinfo.Pins()
	lock := Lock{
		SchemaVersion:         1,
		RunnerVersion:         pins.UpstreamRunner.Version,
		RunnerArchiveSHA256:   pins.UpstreamRunner.LinuxX64SHA256,
		RunnerSourceCommit:    pins.UpstreamRunner.SourceCommit,
		CommandSettingsSHA256: pins.UpstreamRunner.CommandSettingsSHA256,
		RunnerBaseImage:       pins.RunnerBaseImage,
		ManifestSHA256:        verified.ManifestDigest(),
		TreeLockSHA256:        verified.TreeLockDigest(),
		EvidenceGeneration:    verified.Generation(),
		Listener: Listener{
			Path:   runtimeListenerPath,
			SHA256: listener.SHA256,
			Size:   listener.Size,
			Mode:   listener.Mode,
			UID:    0,
			GID:    0,
		},
	}
	if err := validate(lock); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

func Encode(lock Lock) ([]byte, error) {
	if err := validate(lock); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(lock)
	if err != nil {
		return nil, errors.New("runtimelock: encode failed")
	}
	return append(encoded, '\n'), nil
}

func Load(reader io.Reader) (Lock, error) {
	if reader == nil {
		return Lock{}, errors.New("runtimelock: reader required")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxLockBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxLockBytes {
		return Lock{}, errors.New("runtimelock: size invalid")
	}
	if err := rejectDuplicateFields(data); err != nil {
		return Lock{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var lock Lock
	if err := decoder.Decode(&lock); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Lock{}, errors.New("runtimelock: json invalid")
	}
	if err := validate(lock); err != nil {
		return Lock{}, err
	}
	canonical, err := Encode(lock)
	if err != nil || !bytes.Equal(data, canonical) {
		return Lock{}, errors.New("runtimelock: encoding noncanonical")
	}
	return lock, nil
}

func validate(lock Lock) error {
	pins := buildinfo.Pins()
	if lock.SchemaVersion != 1 || lock.RunnerVersion != pins.UpstreamRunner.Version ||
		lock.RunnerArchiveSHA256 != pins.UpstreamRunner.LinuxX64SHA256 ||
		lock.RunnerSourceCommit != pins.UpstreamRunner.SourceCommit ||
		lock.CommandSettingsSHA256 != pins.UpstreamRunner.CommandSettingsSHA256 ||
		lock.RunnerBaseImage != pins.RunnerBaseImage || lock.EvidenceGeneration == 0 ||
		!hex40.MatchString(lock.RunnerSourceCommit) || !hex64.MatchString(lock.RunnerArchiveSHA256) ||
		!hex64.MatchString(lock.CommandSettingsSHA256) || !hex64.MatchString(lock.ManifestSHA256) ||
		!hex64.MatchString(lock.TreeLockSHA256) || lock.Listener.Path != runtimeListenerPath ||
		!hex64.MatchString(lock.Listener.SHA256) || lock.Listener.Size == 0 || lock.Listener.Mode != 0o555 ||
		lock.Listener.UID != 0 || lock.Listener.GID != 0 {
		return errors.New("runtimelock: lock identity invalid")
	}
	return nil
}

func rejectDuplicateFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanValue(decoder); err != nil {
		return errors.New("runtimelock: duplicate or malformed field")
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errors.New("runtimelock: trailing data")
	}
	return nil
}

func scanValue(decoder *json.Decoder) error {
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
				return errors.New("key invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("key duplicated")
			}
			seen[key] = struct{}{}
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array not closed")
		}
	default:
		return errors.New("delimiter invalid")
	}
	return nil
}
