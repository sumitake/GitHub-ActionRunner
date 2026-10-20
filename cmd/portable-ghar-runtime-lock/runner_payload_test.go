package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
)

func TestRunRunnerPayloadSpecPreservesUpstreamAuthority(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"runner-payload-spec"}, &stdout, &stderr); code != 0 {
		t.Fatalf("payload spec exit=%d stderr=%q", code, stderr.String())
	}
	var document struct {
		SchemaVersion uint32 `json:"schema_version"`
		buildinfo.RunnerPayload
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	pins := buildinfo.Pins()
	selected, err := pins.RunnerPayload()
	if err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != 1 || document.RunnerPayload != selected || document.UpstreamSHA256 != pins.UpstreamRunner.LinuxX64SHA256 || stderr.Len() != 0 {
		t.Fatalf("payload authority: %+v", document)
	}
}

func TestRunnerDownloadSpecRejectsRebuiltArchiveAsOfficial(t *testing.T) {
	d := buildinfo.RunnerRebuildPin{SchemaVersion: 1, Enabled: true, UpstreamVersion: "v1.2.3", UpstreamSourceCommit: strings.Repeat("c", 40), UpstreamLinuxX64SHA256: strings.Repeat("a", 64), DotnetSDKVersion: "8.0.426", DotnetRuntimeVersion: "8.0.32", SDKContainerImage: "mcr.microsoft.com/dotnet/sdk@sha256:" + strings.Repeat("e", 64), SDKArchiveSHA512: strings.Repeat("d", 128), SourcePatchSHA256: strings.Repeat("e", 64), AssetName: "actions-runner-linux-x64-1.2.3-dotnet-8.0.32.tar.gz", LinuxX64SHA256: strings.Repeat("b", 64), ArchiveBytes: 1234}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pins := buildinfo.Manifest{UpstreamRunner: buildinfo.UpstreamRunnerPin{Version: d.UpstreamVersion, SourceCommit: d.UpstreamSourceCommit, LinuxX64SHA256: d.UpstreamLinuxX64SHA256}, RunnerRebuildJSON: append(raw, '\n')}
	if _, err := runnerDownloadSpecForPins(pins); err == nil {
		t.Fatal("rebuild presented as official release")
	}
	pins.UpstreamRunner.Version = "v1.2.4"
	pins.UpstreamRunner.LinuxX64SHA256 = strings.Repeat("f", 64)
	spec, err := runnerDownloadSpecForPins(pins)
	if err != nil || spec.SourceURL != "https://github.com/actions/runner/releases/download/v1.2.4/actions-runner-linux-x64-1.2.4.tar.gz" || spec.SHA256 != pins.UpstreamRunner.LinuxX64SHA256 {
		t.Fatalf("official replacement = %+v, %v", spec, err)
	}
}

func officialTestPins() buildinfo.Manifest {
	pins := buildinfo.Pins()
	pins.RunnerRebuildJSON = []byte("{\n  \"schema_version\": 1,\n  \"enabled\": false\n}\n")
	return pins
}
