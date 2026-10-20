package buildinfo

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

//go:embed runner_rebuild.json
var runnerRebuildJSON []byte

// RunnerRebuildPin describes a separately authenticated rebuild. It never
// changes the identity or download digest of the upstream release.
type RunnerRebuildPin struct {
	SchemaVersion          uint32 `json:"schema_version"`
	Enabled                bool   `json:"enabled"`
	UpstreamVersion        string `json:"upstream_version,omitempty"`
	UpstreamSourceCommit   string `json:"upstream_source_commit,omitempty"`
	UpstreamLinuxX64SHA256 string `json:"upstream_linux_x64_sha256,omitempty"`
	DotnetSDKVersion       string `json:"dotnet_sdk_version,omitempty"`
	DotnetRuntimeVersion   string `json:"dotnet_runtime_version,omitempty"`
	SDKContainerImage      string `json:"sdk_container_image,omitempty"`
	SDKArchiveSHA512       string `json:"sdk_archive_sha512,omitempty"`
	SourcePatchSHA256      string `json:"source_patch_sha256,omitempty"`
	AssetName              string `json:"asset_name,omitempty"`
	LinuxX64SHA256         string `json:"linux_x64_sha256,omitempty"`
	ArchiveBytes           uint64 `json:"archive_bytes,omitempty"`
}

// RunnerPayload identifies the archive actually selected for preparation.
// ProvenanceSHA256 authenticates the exact embedded rebuild descriptor.
type RunnerPayload struct {
	Kind             string `json:"kind"`
	AssetName        string `json:"asset_name"`
	SHA256           string `json:"sha256"`
	UpstreamSHA256   string `json:"upstream_sha256"`
	ProvenanceSHA256 string `json:"provenance_sha256,omitempty"`
	ArchiveBytes     uint64 `json:"archive_bytes,omitempty"`
}

var sdkContainerImage = regexp.MustCompile(`^mcr\.microsoft\.com/dotnet/sdk@sha256:[0-9a-f]{64}$`)

var payloadVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

func payloadHex(value string, size int) bool {
	if len(value) != size || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// RunnerPayload selects a rebuild only for its bound official asset. A future
// official candidate automatically returns to the ordinary upstream path.
func (m Manifest) RunnerPayload() (RunnerPayload, error) {
	invalid := errors.New("buildinfo: runner payload descriptor invalid")
	var d RunnerRebuildPin
	if len(m.RunnerRebuildJSON) == 0 || len(m.RunnerRebuildJSON) > 8192 {
		return RunnerPayload{}, invalid
	}
	if err := json.Unmarshal(m.RunnerRebuildJSON, &d); err != nil {
		return RunnerPayload{}, invalid
	}
	canonical, err := json.MarshalIndent(d, "", "  ")
	// Exact canonical bytes also reject duplicate, unknown and case-folded keys.
	if err != nil || !bytes.Equal(append(canonical, '\n'), m.RunnerRebuildJSON) || d.SchemaVersion != 1 {
		return RunnerPayload{}, invalid
	}
	if !payloadVersion.MatchString(m.UpstreamRunner.Version) || !payloadHex(m.UpstreamRunner.LinuxX64SHA256, 64) {
		return RunnerPayload{}, invalid
	}
	official := RunnerPayload{Kind: "official", AssetName: "actions-runner-linux-x64-" + strings.TrimPrefix(m.UpstreamRunner.Version, "v") + ".tar.gz", SHA256: m.UpstreamRunner.LinuxX64SHA256, UpstreamSHA256: m.UpstreamRunner.LinuxX64SHA256}
	if !d.Enabled {
		if d != (RunnerRebuildPin{SchemaVersion: 1}) {
			return RunnerPayload{}, invalid
		}
		return official, nil
	}
	if !sdkContainerImage.MatchString(d.SDKContainerImage) || !payloadVersion.MatchString(d.UpstreamVersion) || !payloadHex(d.UpstreamSourceCommit, 40) || !payloadHex(d.UpstreamLinuxX64SHA256, 64) || !payloadHex(d.LinuxX64SHA256, 64) || !payloadHex(d.SDKArchiveSHA512, 128) || !payloadHex(d.SourcePatchSHA256, 64) || d.LinuxX64SHA256 == d.UpstreamLinuxX64SHA256 || d.DotnetSDKVersion != "8.0.426" || d.DotnetRuntimeVersion != "8.0.32" || d.ArchiveBytes == 0 || d.ArchiveBytes > 512<<20 || d.AssetName != "actions-runner-linux-x64-"+strings.TrimPrefix(d.UpstreamVersion, "v")+"-dotnet-8.0.32.tar.gz" {
		return RunnerPayload{}, invalid
	}
	if d.UpstreamLinuxX64SHA256 != m.UpstreamRunner.LinuxX64SHA256 {
		return official, nil
	}
	if d.UpstreamVersion != m.UpstreamRunner.Version || d.UpstreamSourceCommit != m.UpstreamRunner.SourceCommit {
		return RunnerPayload{}, invalid
	}
	digest := sha256.Sum256(m.RunnerRebuildJSON)
	return RunnerPayload{Kind: "dotnet-rebuild", AssetName: d.AssetName, SHA256: d.LinuxX64SHA256, UpstreamSHA256: d.UpstreamLinuxX64SHA256, ProvenanceSHA256: hex.EncodeToString(digest[:]), ArchiveBytes: d.ArchiveBytes}, nil
}
