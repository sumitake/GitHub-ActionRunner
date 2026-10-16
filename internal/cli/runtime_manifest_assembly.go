package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// RuntimeManifestAssemblyReceipt identifies the canonical manifest without
// disclosing the private input or output paths.
type RuntimeManifestAssemblyReceipt struct {
	SchemaVersion         uint32 `json:"schema_version"`
	RuntimeManifestDigest string `json:"runtime_manifest_digest"`
	FleetGeneration       uint64 `json:"fleet_generation"`
}

// RunRuntimeManifestAssembly serializes an operator-approved identity template
// for the generation the next fence handover will write. It neither discovers
// nor authenticates release identities and never changes a release artifact.
// The template has the RuntimeManifest fields, with fleet_generation zero or
// equal to the requested generation. The output must be a separate private file.
func RunRuntimeManifestAssembly(args []string) (RuntimeManifestAssemblyReceipt, error) {
	if len(args) != 7 || args[0] != "assemble-runtime-manifest" ||
		args[1] != "--template" || args[3] != "--fleet-generation" ||
		args[5] != "--output" {
		return RuntimeManifestAssemblyReceipt{}, ErrHostUsage
	}
	generation, err := strconv.ParseUint(args[4], 10, 64)
	if err != nil {
		return RuntimeManifestAssemblyReceipt{}, ErrHostUsage
	}
	if sameExistingFile(args[2], args[6]) {
		return RuntimeManifestAssemblyReceipt{}, ErrHostUsage
	}
	document, err := readPrivateOverlayDocument(args[2], maxRuntimeManifestBytes)
	if err != nil {
		return RuntimeManifestAssemblyReceipt{}, ErrHostCommandFailed
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest hostruntime.RuntimeManifest
	if err := decoder.Decode(&manifest); err != nil {
		return RuntimeManifestAssemblyReceipt{}, ErrHostCommandFailed
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RuntimeManifestAssemblyReceipt{}, ErrHostCommandFailed
	}
	if manifest.FleetGeneration != 0 && manifest.FleetGeneration != generation {
		return RuntimeManifestAssemblyReceipt{}, ErrHostCommandFailed
	}
	manifest.FleetGeneration = generation
	canonical, digest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		return RuntimeManifestAssemblyReceipt{}, ErrHostCommandFailed
	}
	verify := func(path string) error {
		if _, err := readPrivateOverlayDocument(path, maxRuntimeManifestBytes); err != nil {
			return ErrHostCommandFailed
		}
		return nil
	}
	if err := writeFileAtomic(args[6], canonical, verify); err != nil {
		return RuntimeManifestAssemblyReceipt{}, ErrHostCommandFailed
	}
	return RuntimeManifestAssemblyReceipt{SchemaVersion: 1, RuntimeManifestDigest: digest, FleetGeneration: generation}, nil
}
