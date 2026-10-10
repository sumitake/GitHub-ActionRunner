package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const privateOverlayAssemblySchemaVersion = uint32(1)

// PrivateOverlayAssemblyReceipt reports the revision of the written overlay
// and the runtime manifest it is bound to. It carries no private values.
type PrivateOverlayAssemblyReceipt struct {
	SchemaVersion          uint32 `json:"schema_version"`
	PrivateOverlayRevision string `json:"private_overlay_revision"`
	RuntimeManifestDigest  string `json:"runtime_manifest_digest"`
}

// RunPrivateOverlayAssembly binds an operator-authored overlay template to a
// release runtime manifest and writes the complete overlay:
//
//	assemble-private-overlay --template T --manifest M --output O
//
// Every release-derived field (manifest path and digest, policy manifest
// digest, five image IDs) comes from M; see hostruntime.BindRuntimeManifest.
// The overlay is written atomically with mode 0600 and then read back through
// the same loader the deploy command uses, so a successful receipt means
// "deploy --private O" will accept the file.
func RunPrivateOverlayAssembly(
	args []string,
) (PrivateOverlayAssemblyReceipt, error) {
	if len(args) != 7 ||
		args[0] != "assemble-private-overlay" ||
		args[1] != "--template" ||
		args[3] != "--manifest" ||
		args[5] != "--output" ||
		!canonicalHostPath(args[2]) ||
		!canonicalHostPath(args[4]) ||
		!canonicalHostPath(args[6]) ||
		args[6] == args[2] ||
		args[6] == args[4] {
		return PrivateOverlayAssemblyReceipt{}, ErrHostUsage
	}
	templatePath, manifestPath, outputPath := args[2], args[4], args[6]

	template, err := loadPrivateOverlayTemplate(templatePath)
	if err != nil {
		return PrivateOverlayAssemblyReceipt{}, ErrHostCommandFailed
	}
	manifest, _, manifestDigest, err := LoadRuntimeManifestFile(manifestPath)
	if err != nil {
		return PrivateOverlayAssemblyReceipt{}, ErrHostCommandFailed
	}
	bound, err := hostruntime.BindRuntimeManifest(template, manifest, manifestPath)
	if err != nil {
		return PrivateOverlayAssemblyReceipt{}, ErrHostCommandFailed
	}
	document, revision, err := hostruntime.MarshalPrivateOverlay(bound)
	if err != nil {
		return PrivateOverlayAssemblyReceipt{}, ErrHostCommandFailed
	}
	if _, parsedRevision, err := hostruntime.ParsePrivateOverlay(
		document,
		maxPrivateOverlayBytes,
	); err != nil || parsedRevision != revision {
		return PrivateOverlayAssemblyReceipt{}, ErrHostCommandFailed
	}
	if err := writeFileAtomic(outputPath, document); err != nil {
		return PrivateOverlayAssemblyReceipt{}, ErrHostCommandFailed
	}
	if _, readRevision, err := LoadPrivateOverlayFile(outputPath); err != nil ||
		readRevision != revision {
		_ = os.Remove(outputPath)
		return PrivateOverlayAssemblyReceipt{}, ErrHostCommandFailed
	}
	return PrivateOverlayAssemblyReceipt{
		SchemaVersion:          privateOverlayAssemblySchemaVersion,
		PrivateOverlayRevision: revision,
		RuntimeManifestDigest:  manifestDigest,
	}, nil
}

// loadPrivateOverlayTemplate decodes exactly one overlay object with no
// unknown fields. Release-derived fields may be empty; completeness is
// checked after binding.
func loadPrivateOverlayTemplate(path string) (hostruntime.PrivateOverlay, error) {
	document, err := readBoundedFile(path, maxPrivateOverlayBytes)
	if err != nil {
		return hostruntime.PrivateOverlay{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var template hostruntime.PrivateOverlay
	if err := decoder.Decode(&template); err != nil {
		return hostruntime.PrivateOverlay{}, ErrHostCommandFailed
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return hostruntime.PrivateOverlay{}, ErrHostCommandFailed
	}
	return template, nil
}

// writeFileAtomic writes document to path through a new sibling file, so a
// reader sees either the previous file or the complete new one.
func writeFileAtomic(path string, document []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return ErrHostCommandFailed
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return ErrHostCommandFailed
	}
	if _, err := temporary.Write(document); err != nil {
		_ = temporary.Close()
		return ErrHostCommandFailed
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return ErrHostCommandFailed
	}
	if err := temporary.Close(); err != nil {
		return ErrHostCommandFailed
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return ErrHostCommandFailed
	}
	committed = true
	parent, err := os.Open(directory)
	if err != nil {
		return ErrHostCommandFailed
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return ErrHostCommandFailed
	}
	return nil
}
