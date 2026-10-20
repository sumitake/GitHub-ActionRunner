package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func descriptorBytes(t *testing.T, descriptor RunnerRebuildPin) []byte {
	t.Helper()
	data, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
func payloadFixture(t *testing.T) Manifest {
	t.Helper()
	descriptor := RunnerRebuildPin{SchemaVersion: 1, Enabled: true, UpstreamVersion: "v1.2.3", UpstreamSourceCommit: strings.Repeat("c", 40), UpstreamLinuxX64SHA256: strings.Repeat("a", 64), LinuxX64SHA256: strings.Repeat("b", 64), AssetName: "actions-runner-linux-x64-1.2.3-dotnet-8.0.32.tar.gz", DotnetRuntimeVersion: "8.0.32", DotnetSDKVersion: "8.0.426", SDKContainerImage: "mcr.microsoft.com/dotnet/sdk@sha256:" + strings.Repeat("e", 64), SDKArchiveSHA512: strings.Repeat("d", 128), SourcePatchSHA256: strings.Repeat("e", 64), ArchiveBytes: 1234}
	return Manifest{UpstreamRunner: UpstreamRunnerPin{Version: descriptor.UpstreamVersion, SourceCommit: descriptor.UpstreamSourceCommit, LinuxX64SHA256: descriptor.UpstreamLinuxX64SHA256}, RunnerRebuildJSON: descriptorBytes(t, descriptor)}
}
func TestRunnerPayloadSelectsOnlyAnExplicitlyBoundRebuild(t *testing.T) {
	m := payloadFixture(t)
	selected, err := m.RunnerPayload()
	digest := sha256.Sum256(m.RunnerRebuildJSON)
	if err != nil || selected.Kind != "dotnet-rebuild" || selected.SHA256 != strings.Repeat("b", 64) || selected.UpstreamSHA256 != m.UpstreamRunner.LinuxX64SHA256 || selected.ProvenanceSHA256 != hex.EncodeToString(digest[:]) || selected.ArchiveBytes != 1234 {
		t.Fatalf("bound rebuild = %+v, %v", selected, err)
	}
	m.UpstreamRunner.LinuxX64SHA256 = strings.Repeat("f", 64)
	m.UpstreamRunner.Version = "v1.2.4"
	selected, err = m.RunnerPayload()
	if err != nil || selected.Kind != "official" || selected.SHA256 != m.UpstreamRunner.LinuxX64SHA256 || selected.AssetName != "actions-runner-linux-x64-1.2.4.tar.gz" || selected.ProvenanceSHA256 != "" {
		t.Fatalf("new official candidate = %+v, %v", selected, err)
	}
	m = payloadFixture(t)
	m.RunnerRebuildJSON = descriptorBytes(t, RunnerRebuildPin{SchemaVersion: 1, Enabled: false})
	selected, err = m.RunnerPayload()
	if err != nil || selected.Kind != "official" || selected.SHA256 != m.UpstreamRunner.LinuxX64SHA256 {
		t.Fatalf("disabled rebuild = %+v, %v", selected, err)
	}
}
func TestRunnerPayloadRejectsMalformedOrAmbiguousRebuildPins(t *testing.T) {
	for _, change := range []string{"upstream", "archive", "same-digest", "asset", "runtime", "sdk", "sdk-hash", "sdk-image", "patch", "size", "source", "version", "unknown", "duplicate", "trailing", "noncanonical", "missing"} {
		t.Run(change, func(t *testing.T) {
			m := payloadFixture(t)
			var d RunnerRebuildPin
			if err := json.Unmarshal(m.RunnerRebuildJSON, &d); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "upstream":
				d.UpstreamLinuxX64SHA256 = "bad"
			case "archive":
				d.LinuxX64SHA256 = "bad"
			case "same-digest":
				d.LinuxX64SHA256 = d.UpstreamLinuxX64SHA256
			case "asset":
				d.AssetName = "../fixture.tar.gz"
			case "runtime":
				d.DotnetRuntimeVersion = "8.0.31"
			case "sdk":
				d.DotnetSDKVersion = "8.0.425"
			case "sdk-image":
				d.SDKContainerImage = "mcr.microsoft.com/dotnet/sdk:8.0.426"
			case "sdk-hash":
				d.SDKArchiveSHA512 = "bad"
			case "patch":
				d.SourcePatchSHA256 = "bad"
			case "size":
				d.ArchiveBytes = 0
			case "source":
				m.UpstreamRunner.SourceCommit = strings.Repeat("f", 40)
			case "version":
				m.UpstreamRunner.Version = "v1.2.4"
			}
			m.RunnerRebuildJSON = descriptorBytes(t, d)
			switch change {
			case "unknown":
				m.RunnerRebuildJSON = []byte(strings.Replace(string(m.RunnerRebuildJSON), "{", "{\"unknown\":true,", 1))
			case "duplicate":
				m.RunnerRebuildJSON = []byte(strings.Replace(string(m.RunnerRebuildJSON), "{", "{\"enabled\":false,", 1))
			case "trailing":
				m.RunnerRebuildJSON = append(m.RunnerRebuildJSON, []byte("{}")...)
			case "noncanonical":
				m.RunnerRebuildJSON = append([]byte(" "), m.RunnerRebuildJSON...)
			case "missing":
				m.RunnerRebuildJSON = nil
			}
			if _, err := m.RunnerPayload(); err == nil {
				t.Fatal("malformed rebuild accepted")
			}
		})
	}
}
func TestRunnerPayloadEmbeddedDescriptorIsValid(t *testing.T) {
	if _, err := Pins().RunnerPayload(); err != nil {
		t.Fatal(err)
	}
}
