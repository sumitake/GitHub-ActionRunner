package productionruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	releaseImageCount                   = 5
	releaseArtifactReceiptSchema        = uint32(1)
	maximumReleaseArtifactReceiptBytes  = 1 << 16
	releaseImageVerificationReceiptName = "image-verification.json"
	releaseRunnerSmokeReceiptName       = "runner-smoke.json"
	releaseImageInspectFormat           = `{"architecture":{{json .Architecture}},"id":{{json .Id}},"os":{{json .Os}},"repo_digests":{{json .RepoDigests}}}`
	releaseRunnerListener               = "/opt/actions-runner/bin/Runner.Listener"
)

var ErrReleaseArtifacts = errors.New(
	"productionruntime: release artifact verification failed",
)

type releaseImageObservation struct {
	Architecture string   `json:"architecture"`
	ID           string   `json:"id"`
	OS           string   `json:"os"`
	RepoDigests  []string `json:"repo_digests"`
}

type VerifiedReleaseImages struct {
	References [releaseImageCount]string
	ImageIDs   [releaseImageCount]string
}

type releaseImageReceiptBinding struct {
	Role      string `json:"role"`
	Reference string `json:"reference"`
	ImageID   string `json:"image_id"`
}

type releaseImageVerificationReceipt struct {
	SchemaVersion          uint32                                        `json:"schema_version"`
	ManifestDigest         string                                        `json:"manifest_digest"`
	PrivateOverlayRevision string                                        `json:"private_overlay_revision"`
	OS                     string                                        `json:"os"`
	Architecture           string                                        `json:"architecture"`
	Images                 [releaseImageCount]releaseImageReceiptBinding `json:"images"`
}

type releaseRunnerSmokeReceipt struct {
	SchemaVersion          uint32 `json:"schema_version"`
	ManifestDigest         string `json:"manifest_digest"`
	PrivateOverlayRevision string `json:"private_overlay_revision"`
	RunnerReference        string `json:"runner_reference"`
	RunnerVersion          string `json:"runner_version"`
}

var releaseImageRoles = [releaseImageCount]string{
	"runner",
	"adapter",
	"broker",
	"helper",
	"verifier",
}

type ReleaseArtifactVerifier struct {
	dockerPath string
	runner     hostruntime.CommandRunner
}

type releaseArtifactAuthority interface {
	VerifyImages(
		context.Context,
		hostruntime.PrivateOverlay,
	) (VerifiedReleaseImages, error)
	SmokeRunner(context.Context, hostruntime.PrivateOverlay) (string, error)
}

func NewReleaseArtifactVerifier(
	dockerPath string,
	runner hostruntime.CommandRunner,
) (*ReleaseArtifactVerifier, error) {
	if !filepath.IsAbs(dockerPath) ||
		filepath.Clean(dockerPath) != dockerPath ||
		strings.ContainsRune(dockerPath, 0) ||
		runner == nil {
		return nil, ErrReleaseArtifacts
	}
	return &ReleaseArtifactVerifier{
		dockerPath: dockerPath,
		runner:     runner,
	}, nil
}

func (verifier *ReleaseArtifactVerifier) VerifyImages(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
) (VerifiedReleaseImages, error) {
	if verifier == nil ||
		verifier.runner == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		overlay.Commands.DockerBinary != verifier.dockerPath {
		return VerifiedReleaseImages{}, ErrReleaseArtifacts
	}
	references, err := releaseImageReferences(overlay.Docker)
	if err != nil {
		return VerifiedReleaseImages{}, ErrReleaseArtifacts
	}
	argv := append(
		[]string{
			verifier.dockerPath,
			"image",
			"inspect",
			"--format",
			releaseImageInspectFormat,
		},
		references[:]...,
	)
	result, err := verifier.runner.Run(ctx, argv, nil, nil)
	if err != nil {
		return VerifiedReleaseImages{}, ErrReleaseArtifacts
	}
	imageIDs, err := parseReleaseImageInspectOutput(result, references)
	if err != nil {
		return VerifiedReleaseImages{}, ErrReleaseArtifacts
	}
	return VerifiedReleaseImages{
		References: references,
		ImageIDs:   imageIDs,
	}, nil
}

func (verifier *ReleaseArtifactVerifier) SmokeRunner(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
) (string, error) {
	if verifier == nil ||
		verifier.runner == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		overlay.Commands.DockerBinary != verifier.dockerPath ||
		!digestQualifiedImageReference(overlay.Docker.RunnerImage) {
		return "", ErrReleaseArtifacts
	}
	pinned := buildinfo.Pins().UpstreamRunner.Version
	if !strings.HasPrefix(pinned, "v") || len(pinned) == 1 {
		return "", ErrReleaseArtifacts
	}
	wantVersion := strings.TrimPrefix(pinned, "v")
	result, err := verifier.runner.Run(
		ctx,
		[]string{
			verifier.dockerPath,
			"run",
			"--rm",
			"--network",
			"none",
			"--read-only",
			"--entrypoint",
			releaseRunnerListener,
			overlay.Docker.RunnerImage,
			"--version",
		},
		nil,
		nil,
	)
	if err != nil ||
		!cleanReleaseCommandResult(result) ||
		!bytes.Equal(result.Stdout, []byte(wantVersion+"\n")) {
		return "", ErrReleaseArtifacts
	}
	return wantVersion, nil
}

func releaseImageReferences(
	docker hostruntime.DockerOverlay,
) ([releaseImageCount]string, error) {
	references := [releaseImageCount]string{
		docker.RunnerImage,
		docker.AdapterImage,
		docker.BrokerImage,
		docker.HelperImage,
		docker.VerifierImage,
	}
	seen := make(map[string]struct{}, releaseImageCount)
	for _, reference := range references {
		if !digestQualifiedImageReference(reference) {
			return [releaseImageCount]string{}, ErrReleaseArtifacts
		}
		if _, duplicate := seen[reference]; duplicate {
			return [releaseImageCount]string{}, ErrReleaseArtifacts
		}
		seen[reference] = struct{}{}
	}
	return references, nil
}

func parseReleaseImageInspectOutput(
	result hostruntime.Result,
	references [releaseImageCount]string,
) ([releaseImageCount]string, error) {
	var imageIDs [releaseImageCount]string
	if !cleanReleaseCommandResult(result) ||
		len(result.Stdout) == 0 ||
		result.Stdout[len(result.Stdout)-1] != '\n' {
		return imageIDs, ErrReleaseArtifacts
	}
	lines := bytes.Split(result.Stdout, []byte{'\n'})
	if len(lines) != releaseImageCount+1 || len(lines[len(lines)-1]) != 0 {
		return imageIDs, ErrReleaseArtifacts
	}
	for index := range releaseImageCount {
		line := lines[index]
		if len(line) == 0 {
			return [releaseImageCount]string{}, ErrReleaseArtifacts
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var observation releaseImageObservation
		if err := decoder.Decode(&observation); err != nil {
			return [releaseImageCount]string{}, ErrReleaseArtifacts
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return [releaseImageCount]string{}, ErrReleaseArtifacts
		}
		canonical, err := json.Marshal(observation)
		if err != nil || !bytes.Equal(canonical, line) ||
			observation.OS != "linux" ||
			observation.Architecture != "amd64" ||
			!validReleaseImageID(observation.ID) ||
			!repoDigestsContainExactly(
				observation.RepoDigests,
				references[index],
			) {
			return [releaseImageCount]string{}, ErrReleaseArtifacts
		}
		imageIDs[index] = observation.ID
	}
	return imageIDs, nil
}

func cleanReleaseCommandResult(result hostruntime.Result) bool {
	return result.ExitCode == 0 &&
		!result.Signaled &&
		result.Signal == "" &&
		!result.StdoutTruncated &&
		!result.StderrTruncated &&
		len(result.Stderr) == 0
}

func repoDigestsContainExactly(values []string, expected string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	count := 0
	for _, value := range values {
		if !digestQualifiedImageReference(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
		if value == expected {
			count++
		}
	}
	return count == 1
}

func digestQualifiedImageReference(value string) bool {
	marker := strings.LastIndex(value, "@sha256:")
	if marker <= 0 || marker+len("@sha256:")+64 != len(value) {
		return false
	}
	return lowerHexDigest(value[marker+len("@sha256:"):])
}

func validReleaseImageID(value string) bool {
	return strings.HasPrefix(value, "sha256:") &&
		len(value) == len("sha256:")+64 &&
		lowerHexDigest(strings.TrimPrefix(value, "sha256:"))
}

func marshalImageVerificationReceipt(
	manifestDigest string,
	revision string,
	proof VerifiedReleaseImages,
) ([]byte, error) {
	if !lowerHexDigest(manifestDigest) || !lowerHexDigest(revision) {
		return nil, ErrReleaseArtifacts
	}
	seen := make(map[string]struct{}, releaseImageCount)
	receipt := releaseImageVerificationReceipt{
		SchemaVersion:          releaseArtifactReceiptSchema,
		ManifestDigest:         manifestDigest,
		PrivateOverlayRevision: revision,
		OS:                     "linux",
		Architecture:           "amd64",
	}
	for index := range releaseImageCount {
		reference := proof.References[index]
		if !digestQualifiedImageReference(reference) ||
			!validReleaseImageID(proof.ImageIDs[index]) {
			return nil, ErrReleaseArtifacts
		}
		if _, duplicate := seen[reference]; duplicate {
			return nil, ErrReleaseArtifacts
		}
		seen[reference] = struct{}{}
		receipt.Images[index] = releaseImageReceiptBinding{
			Role:      releaseImageRoles[index],
			Reference: reference,
			ImageID:   proof.ImageIDs[index],
		}
	}
	document, err := json.Marshal(receipt)
	if err != nil || len(document) > maximumReleaseArtifactReceiptBytes {
		return nil, ErrReleaseArtifacts
	}
	return document, nil
}

func validateImageVerificationReceipt(
	document []byte,
	manifestDigest string,
	revision string,
	docker hostruntime.DockerOverlay,
) error {
	if len(document) == 0 ||
		len(document) > maximumReleaseArtifactReceiptBytes {
		return ErrReleaseArtifacts
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var receipt releaseImageVerificationReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return ErrReleaseArtifacts
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrReleaseArtifacts
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, document) ||
		receipt.SchemaVersion != releaseArtifactReceiptSchema ||
		receipt.ManifestDigest != manifestDigest ||
		receipt.PrivateOverlayRevision != revision ||
		receipt.OS != "linux" ||
		receipt.Architecture != "amd64" {
		return ErrReleaseArtifacts
	}
	references, err := releaseImageReferences(docker)
	if err != nil {
		return ErrReleaseArtifacts
	}
	for index, image := range receipt.Images {
		if image.Role != releaseImageRoles[index] ||
			image.Reference != references[index] ||
			!validReleaseImageID(image.ImageID) {
			return ErrReleaseArtifacts
		}
	}
	return nil
}

func marshalRunnerSmokeReceipt(
	manifestDigest string,
	revision string,
	runnerReference string,
	runnerVersion string,
) ([]byte, error) {
	pinnedVersion := strings.TrimPrefix(
		buildinfo.Pins().UpstreamRunner.Version,
		"v",
	)
	if !lowerHexDigest(manifestDigest) ||
		!lowerHexDigest(revision) ||
		!digestQualifiedImageReference(runnerReference) ||
		runnerVersion == "" ||
		runnerVersion != pinnedVersion {
		return nil, ErrReleaseArtifacts
	}
	document, err := json.Marshal(releaseRunnerSmokeReceipt{
		SchemaVersion:          releaseArtifactReceiptSchema,
		ManifestDigest:         manifestDigest,
		PrivateOverlayRevision: revision,
		RunnerReference:        runnerReference,
		RunnerVersion:          runnerVersion,
	})
	if err != nil || len(document) > maximumReleaseArtifactReceiptBytes {
		return nil, ErrReleaseArtifacts
	}
	return document, nil
}

func validateRunnerSmokeReceipt(
	document []byte,
	manifestDigest string,
	revision string,
	runnerReference string,
) error {
	if len(document) == 0 ||
		len(document) > maximumReleaseArtifactReceiptBytes {
		return ErrReleaseArtifacts
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var receipt releaseRunnerSmokeReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return ErrReleaseArtifacts
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrReleaseArtifacts
	}
	canonical, err := json.Marshal(receipt)
	pinnedVersion := strings.TrimPrefix(
		buildinfo.Pins().UpstreamRunner.Version,
		"v",
	)
	if err != nil ||
		!bytes.Equal(canonical, document) ||
		receipt.SchemaVersion != releaseArtifactReceiptSchema ||
		receipt.ManifestDigest != manifestDigest ||
		receipt.PrivateOverlayRevision != revision ||
		receipt.RunnerReference != runnerReference ||
		receipt.RunnerVersion != pinnedVersion {
		return ErrReleaseArtifacts
	}
	return nil
}
