package main

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
)

const (
	maxRunnerRedirectBytes         = 8192
	runnerReleaseAssetRepositoryID = "184286875"
)

var runnerReleaseObjectPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type runnerDownloadSpec struct {
	SchemaVersion uint32 `json:"schema_version"`
	SourceURL     string `json:"source_url"`
	AssetName     string `json:"asset_name"`
	SHA256        string `json:"sha256"`
}

func currentRunnerDownloadSpec() (runnerDownloadSpec, error) {
	pins := buildinfo.Pins()
	version := pins.UpstreamRunner.Version
	if !strings.HasPrefix(version, "v") || len(version) < 2 {
		return runnerDownloadSpec{}, errors.New("runtime-lock: runner version invalid")
	}
	asset := "actions-runner-linux-x64-" + strings.TrimPrefix(version, "v") + ".tar.gz"
	return runnerDownloadSpec{
		SchemaVersion: 1,
		SourceURL:     "https://github.com/actions/runner/releases/download/" + version + "/" + asset,
		AssetName:     asset,
		SHA256:        pins.UpstreamRunner.LinuxX64SHA256,
	}, nil
}

func validateRunnerRedirect(raw string) (string, error) {
	if raw == "" || len(raw) > maxRunnerRedirectBytes || strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, "\x00\r\n\t#") {
		return "", errors.New("runtime-lock: runner redirect bytes invalid")
	}
	spec, err := currentRunnerDownloadSpec()
	if err != nil {
		return "", err
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" ||
		parsed.Host != "release-assets.githubusercontent.com" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawQuery == "" ||
		parsed.RawPath != "" || parsed.EscapedPath() != parsed.Path ||
		path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//") {
		return "", errors.New("runtime-lock: runner redirect origin invalid")
	}
	segments := strings.Split(parsed.Path, "/")
	if len(segments) != 4 || segments[0] != "" ||
		segments[1] != "github-production-release-asset" ||
		segments[2] != runnerReleaseAssetRepositoryID ||
		!runnerReleaseObjectPattern.MatchString(segments[3]) {
		return "", errors.New("runtime-lock: runner redirect object invalid")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return "", errors.New("runtime-lock: runner redirect query invalid")
	}
	disposition := "attachment; filename=" + spec.AssetName
	if values := query["response-content-disposition"]; len(values) != 1 || values[0] != disposition {
		return "", errors.New("runtime-lock: runner redirect asset invalid")
	}
	if values := query["response-content-type"]; len(values) != 1 || values[0] != "application/octet-stream" {
		return "", errors.New("runtime-lock: runner redirect content type invalid")
	}
	return raw, nil
}
