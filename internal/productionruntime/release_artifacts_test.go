package productionruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestSystemTargetHandlerStageReleaseIsReadOnlyAdmission(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	manifestPath := filepath.Join(root, "runtime-manifest.json")
	controllerPath := filepath.Join(root, "portable-ghar-controller")
	stagingRoot := filepath.Join(root, "must-not-create-staging")
	releaseRoot := filepath.Join(root, "must-not-create-releases")
	controller := []byte("controller-binary")
	if err := os.WriteFile(controllerPath, controller, 0o500); err != nil {
		t.Fatalf("WriteFile(controller) error = %v", err)
	}
	manifest := protocolTestManifest()
	controllerDigest := sha256.Sum256(controller)
	manifest.ControllerSHA256 = hex.EncodeToString(controllerDigest[:])
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestDocument, 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	overlay, _ := protocolTestOverlay(t)
	overlay.Manifest.Path = manifestPath
	overlay.Manifest.Digest = manifestDigest
	overlay.Commands.ControllerBinary = controllerPath
	overlay.Paths.StagingRoot = stagingRoot
	overlay.Paths.ReleaseRoot = releaseRoot
	overlay.Policy.ManifestDigest = manifest.PolicyManifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	target := protocolTestTarget(t, overlay, revision)
	handler := newSystemTargetHandler(
		func(
			context.Context,
			hostruntime.PrivateOverlay,
			string,
		) (cli.TargetProof, error) {
			return target, nil
		},
		nil,
	)
	if current, err := handler.ProveTarget(
		context.Background(),
		overlay,
		revision,
	); err != nil || !reflect.DeepEqual(current, target) {
		t.Fatalf("ProveTarget() = %#v, %v", current, err)
	}
	if got, err := readPinnedAbsoluteFile(
		manifestPath,
		0o600,
		maximumReleaseManifestBytes,
	); err != nil || !bytes.Equal(got, manifestDocument) {
		t.Fatalf("readPinnedAbsoluteFile(manifest) = %q, %v", got, err)
	}
	if got, err := digestPinnedExecutable(controllerPath); err != nil ||
		got != manifest.ControllerSHA256 {
		t.Fatalf("digestPinnedExecutable() = %q, %v", got, err)
	}
	if !runtimeManifestMatchesOverlay(manifest, overlay) {
		t.Fatal("runtimeManifestMatchesOverlay() = false")
	}

	proof, err := handler.StageRelease(
		context.Background(),
		overlay,
		revision,
		target,
		manifest,
		manifestDigest,
	)
	if err != nil {
		t.Fatalf("StageRelease() error = %v", err)
	}
	if proof.ManifestDigest != manifestDigest ||
		proof.PrivateOverlayRevision != revision ||
		proof.TargetProofDigest != target.ProofDigest ||
		proof.ProofDigest == "" {
		t.Fatalf("StageRelease() proof = %#v", proof)
	}
	for _, path := range []string{stagingRoot, releaseRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("StageRelease created %q: %v", path, err)
		}
	}
}

func TestReleaseArtifactVerifierUsesOneExactInspectCommand(t *testing.T) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	references, err := releaseImageReferences(overlay.Docker)
	if err != nil {
		t.Fatalf("releaseImageReferences() error = %v", err)
	}
	stdout, imageIDs := releaseInspectFixture(t, references)
	runner := &releaseArtifactCommandRunner{
		results: []hostruntime.Result{{
			Stdout:   stdout,
			ExitCode: 0,
		}},
	}
	verifier, err := NewReleaseArtifactVerifier(
		overlay.Commands.DockerBinary,
		runner,
	)
	if err != nil {
		t.Fatalf("NewReleaseArtifactVerifier() error = %v", err)
	}

	got, err := verifier.VerifyImages(context.Background(), overlay)
	if err != nil {
		t.Fatalf("VerifyImages() error = %v", err)
	}
	if got.References != references || got.ImageIDs != imageIDs {
		t.Fatalf("VerifyImages() = %#v", got)
	}
	wantArgv := append(
		[]string{
			overlay.Commands.DockerBinary,
			"image",
			"inspect",
			"--format",
			releaseImageInspectFormat,
		},
		references[:]...,
	)
	if !reflect.DeepEqual(runner.argv, [][]string{wantArgv}) {
		t.Fatalf("argv = %#v, want %#v", runner.argv, wantArgv)
	}
}

func TestParseReleaseImageInspectOutputFailsClosed(t *testing.T) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	references, err := releaseImageReferences(overlay.Docker)
	if err != nil {
		t.Fatalf("releaseImageReferences() error = %v", err)
	}
	valid, _ := releaseInspectFixture(t, references)

	tests := map[string]hostruntime.Result{
		"missing final newline": {
			Stdout:   bytes.TrimSuffix(valid, []byte("\n")),
			ExitCode: 0,
		},
		"extra output": {
			Stdout:   append(append([]byte(nil), valid...), []byte("{}\n")...),
			ExitCode: 0,
		},
		"stderr": {
			Stdout:   valid,
			Stderr:   []byte("diagnostic"),
			ExitCode: 0,
		},
		"nonzero": {
			Stdout:   valid,
			ExitCode: 1,
		},
		"truncated": {
			Stdout:          valid,
			StdoutTruncated: true,
			ExitCode:        0,
		},
		"signaled": {
			Stdout:   valid,
			ExitCode: -1,
			Signaled: true,
			Signal:   "killed",
		},
		"noncanonical json": {
			Stdout:   append([]byte(" "), valid...),
			ExitCode: 0,
		},
		"wrong platform": {
			Stdout: bytes.Replace(
				valid,
				[]byte(`"architecture":"amd64"`),
				[]byte(`"architecture":"arm64"`),
				1,
			),
			ExitCode: 0,
		},
		"wrong ordered reference": {
			Stdout: bytes.Replace(
				valid,
				[]byte(references[0]),
				[]byte(references[1]),
				1,
			),
			ExitCode: 0,
		},
		"duplicate repo digest": {
			Stdout: bytes.Replace(
				valid,
				[]byte(`"]}`),
				[]byte(`","`+references[0]+`"]}`),
				1,
			),
			ExitCode: 0,
		},
	}
	for name, result := range tests {
		name, result := name, result
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseReleaseImageInspectOutput(
				result,
				references,
			); !errors.Is(err, ErrReleaseArtifacts) {
				t.Fatalf("parseReleaseImageInspectOutput() error = %v", err)
			}
		})
	}
}

func TestReleaseArtifactVerifierSmokesExactPinnedListener(t *testing.T) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	wantVersion := strings.TrimPrefix(
		buildinfo.Pins().UpstreamRunner.Version,
		"v",
	)
	runner := &releaseArtifactCommandRunner{
		results: []hostruntime.Result{{
			Stdout:   []byte(wantVersion + "\n"),
			ExitCode: 0,
		}},
	}
	verifier, err := NewReleaseArtifactVerifier(
		overlay.Commands.DockerBinary,
		runner,
	)
	if err != nil {
		t.Fatalf("NewReleaseArtifactVerifier() error = %v", err)
	}

	got, err := verifier.SmokeRunner(context.Background(), overlay)
	if err != nil || got != wantVersion {
		t.Fatalf("SmokeRunner() = %q, %v", got, err)
	}
	wantArgv := []string{
		overlay.Commands.DockerBinary,
		"run",
		"--rm",
		"--network",
		"none",
		"--read-only",
		"--entrypoint",
		"/opt/actions-runner/bin/Runner.Listener",
		overlay.Docker.RunnerImage,
		"--version",
	}
	if !reflect.DeepEqual(runner.argv, [][]string{wantArgv}) {
		t.Fatalf("argv = %#v, want %#v", runner.argv, wantArgv)
	}
}

func TestReleaseArtifactVerifierRejectsNonexactSmokeOutput(t *testing.T) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	wantVersion := strings.TrimPrefix(
		buildinfo.Pins().UpstreamRunner.Version,
		"v",
	)
	for name, result := range map[string]hostruntime.Result{
		"missing newline": {Stdout: []byte(wantVersion), ExitCode: 0},
		"extra newline":   {Stdout: []byte(wantVersion + "\n\n"), ExitCode: 0},
		"wrong version":   {Stdout: []byte("0.0.0\n"), ExitCode: 0},
		"stderr":          {Stdout: []byte(wantVersion + "\n"), Stderr: []byte("x"), ExitCode: 0},
		"nonzero":         {Stdout: []byte(wantVersion + "\n"), ExitCode: 1},
	} {
		name, result := name, result
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := &releaseArtifactCommandRunner{results: []hostruntime.Result{result}}
			verifier, err := NewReleaseArtifactVerifier(
				overlay.Commands.DockerBinary,
				runner,
			)
			if err != nil {
				t.Fatalf("NewReleaseArtifactVerifier() error = %v", err)
			}
			if _, err := verifier.SmokeRunner(
				context.Background(),
				overlay,
			); !errors.Is(err, ErrReleaseArtifacts) {
				t.Fatalf("SmokeRunner() error = %v", err)
			}
		})
	}
}

func TestReleaseBundleStorePersistsExactArtifactReceipts(t *testing.T) {
	root := t.TempDir()
	stagingRoot := filepath.Join(root, "staging")
	releaseRoot := filepath.Join(root, "releases")
	for _, path := range []string{stagingRoot, releaseRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%q) error = %v", path, err)
		}
	}
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Paths.StagingRoot = stagingRoot
	overlay.Paths.ReleaseRoot = releaseRoot
	overlay.Manifest.Digest = manifestDigest
	overlayDocument, revision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	store, err := openReleaseBundleStore(stagingRoot, releaseRoot)
	if err != nil {
		t.Fatalf("openReleaseBundleStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close() error = %v", err)
		}
	})
	if err := store.Stage(
		manifestDigest,
		revision,
		overlayDocument,
		manifestDocument,
	); err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	references, err := releaseImageReferences(overlay.Docker)
	if err != nil {
		t.Fatalf("releaseImageReferences() error = %v", err)
	}
	_, imageIDs := releaseInspectFixture(t, references)
	verificationDocument, err := marshalImageVerificationReceipt(
		manifestDigest,
		revision,
		VerifiedReleaseImages{
			References: references,
			ImageIDs:   imageIDs,
		},
	)
	if err != nil {
		t.Fatalf("marshalImageVerificationReceipt() error = %v", err)
	}
	smokeDocument, err := marshalRunnerSmokeReceipt(
		manifestDigest,
		revision,
		overlay.Docker.RunnerImage,
		strings.TrimPrefix(buildinfo.Pins().UpstreamRunner.Version, "v"),
	)
	if err != nil {
		t.Fatalf("marshalRunnerSmokeReceipt() error = %v", err)
	}

	for _, receipt := range []struct {
		name     string
		document []byte
	}{
		{releaseImageVerificationReceiptName, verificationDocument},
		{releaseRunnerSmokeReceiptName, smokeDocument},
	} {
		if err := store.WriteStagedReceipt(
			manifestDigest,
			receipt.name,
			receipt.document,
		); err != nil {
			t.Fatalf("WriteStagedReceipt(%q) error = %v", receipt.name, err)
		}
		if err := store.WriteStagedReceipt(
			manifestDigest,
			receipt.name,
			receipt.document,
		); err != nil {
			t.Fatalf("idempotent WriteStagedReceipt(%q) error = %v", receipt.name, err)
		}
		got, present, err := store.InspectStagedReceipt(
			manifestDigest,
			receipt.name,
		)
		if err != nil || !present || !bytes.Equal(got, receipt.document) {
			t.Fatalf(
				"InspectStagedReceipt(%q) = (%q, %t, %v)",
				receipt.name,
				got,
				present,
				err,
			)
		}
		tampered := append(append([]byte(nil), receipt.document...), ' ')
		if err := store.WriteStagedReceipt(
			manifestDigest,
			receipt.name,
			tampered,
		); !errors.Is(err, ErrReleaseBundle) {
			t.Fatalf("WriteStagedReceipt(tampered) error = %v", err)
		}
	}
	if err := validateImageVerificationReceipt(
		verificationDocument,
		manifestDigest,
		revision,
		overlay.Docker,
	); err != nil {
		t.Fatalf("validateImageVerificationReceipt() error = %v", err)
	}
	if err := validateRunnerSmokeReceipt(
		smokeDocument,
		manifestDigest,
		revision,
		overlay.Docker.RunnerImage,
	); err != nil {
		t.Fatalf("validateRunnerSmokeReceipt() error = %v", err)
	}
}

func TestGreenfieldCandidateArtifactEffectsOwnWrites(t *testing.T) {
	root := t.TempDir()
	stagingRoot := filepath.Join(root, "staging")
	releaseRoot := filepath.Join(root, "releases")
	for _, path := range []string{stagingRoot, releaseRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%q) error = %v", path, err)
		}
	}
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Paths.StagingRoot = stagingRoot
	overlay.Paths.ReleaseRoot = releaseRoot
	overlay.Manifest.Digest = manifestDigest
	overlay.Policy.ManifestDigest = manifest.PolicyManifestDigest
	overlayDocument, revision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	store, err := openReleaseBundleStore(stagingRoot, releaseRoot)
	if err != nil {
		t.Fatalf("openReleaseBundleStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close() error = %v", err)
		}
	})
	references, err := releaseImageReferences(overlay.Docker)
	if err != nil {
		t.Fatalf("releaseImageReferences() error = %v", err)
	}
	_, imageIDs := releaseInspectFixture(t, references)
	artifacts := &fakeReleaseArtifactAuthority{
		images: VerifiedReleaseImages{
			References: references,
			ImageIDs:   imageIDs,
		},
		version: strings.TrimPrefix(
			buildinfo.Pins().UpstreamRunner.Version,
			"v",
		),
	}
	target := &systemLifecycleTarget{
		overlay:        overlay,
		revision:       revision,
		manifest:       manifest,
		manifestDigest: manifestDigest,
		releases:       store,
		artifacts:      artifacts,
	}
	binding := hostruntime.OperationBinding{
		Kind: hostruntime.OperationKindInstall,
	}

	if err := target.applyInstall(
		context.Background(),
		binding,
		effectCandidateStaged,
	); err != nil {
		t.Fatalf("apply(candidate-staged) error = %v", err)
	}
	staged, present, err := store.InspectStaged(manifestDigest, revision)
	if err != nil || !present ||
		!bytes.Equal(staged.overlayDocument, overlayDocument) ||
		!bytes.Equal(staged.manifestDocument, manifestDocument) {
		t.Fatalf("InspectStaged() = %#v, %t, %v", staged, present, err)
	}
	verification, present, err := store.InspectStagedReceipt(
		manifestDigest,
		releaseImageVerificationReceiptName,
	)
	if err != nil || !present || validateImageVerificationReceipt(
		verification,
		manifestDigest,
		revision,
		overlay.Docker,
	) != nil {
		t.Fatalf("verification receipt = %q, %t, %v", verification, present, err)
	}
	if artifacts.verifyCalls != 1 || artifacts.smokeCalls != 0 {
		t.Fatalf("artifact calls = verify %d, smoke %d", artifacts.verifyCalls, artifacts.smokeCalls)
	}
	cancelledContext, cancel := context.WithCancel(context.Background())
	artifacts.afterSmoke = cancel
	if err := target.applyInstall(
		cancelledContext,
		binding,
		effectCandidateSmoked,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("cancelled apply(candidate-smoked) error = %v", err)
	}
	if _, present, err := store.InspectStagedReceipt(
		manifestDigest,
		releaseRunnerSmokeReceiptName,
	); err != nil || present {
		t.Fatalf("cancelled smoke receipt present = %t, error = %v", present, err)
	}
	artifacts.afterSmoke = nil

	if err := target.applyInstall(
		context.Background(),
		binding,
		effectCandidateSmoked,
	); err != nil {
		t.Fatalf("apply(candidate-smoked) error = %v", err)
	}
	smoke, present, err := store.InspectStagedReceipt(
		manifestDigest,
		releaseRunnerSmokeReceiptName,
	)
	if err != nil || !present || validateRunnerSmokeReceipt(
		smoke,
		manifestDigest,
		revision,
		overlay.Docker.RunnerImage,
	) != nil {
		t.Fatalf("smoke receipt = %q, %t, %v", smoke, present, err)
	}
	if artifacts.verifyCalls != 1 || artifacts.smokeCalls != 2 {
		t.Fatalf("artifact calls = verify %d, smoke %d", artifacts.verifyCalls, artifacts.smokeCalls)
	}
}

func TestCandidateStageCancellationBeforeWriteLeavesNoBundle(t *testing.T) {
	root := t.TempDir()
	stagingRoot := filepath.Join(root, "staging")
	releaseRoot := filepath.Join(root, "releases")
	for _, path := range []string{stagingRoot, releaseRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%q) error = %v", path, err)
		}
	}
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Paths.StagingRoot = stagingRoot
	overlay.Paths.ReleaseRoot = releaseRoot
	overlay.Manifest.Digest = manifestDigest
	overlay.Policy.ManifestDigest = manifest.PolicyManifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	store, err := openReleaseBundleStore(stagingRoot, releaseRoot)
	if err != nil {
		t.Fatalf("openReleaseBundleStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	references, err := releaseImageReferences(overlay.Docker)
	if err != nil {
		t.Fatalf("releaseImageReferences() error = %v", err)
	}
	_, imageIDs := releaseInspectFixture(t, references)
	ctx, cancel := context.WithCancel(context.Background())
	artifacts := &fakeReleaseArtifactAuthority{
		images: VerifiedReleaseImages{
			References: references,
			ImageIDs:   imageIDs,
		},
		afterVerify: cancel,
	}
	target := &systemLifecycleTarget{
		overlay:        overlay,
		revision:       revision,
		manifest:       manifest,
		manifestDigest: manifestDigest,
		releases:       store,
		artifacts:      artifacts,
	}
	err = target.applyInstall(
		ctx,
		hostruntime.OperationBinding{Kind: hostruntime.OperationKindInstall},
		effectCandidateStaged,
	)
	if !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("apply(candidate-staged) error = %v", err)
	}
	if _, present, err := store.InspectStaged(
		manifestDigest,
		revision,
	); err != nil || present {
		t.Fatalf("InspectStaged() present = %t, error = %v", present, err)
	}
}

type releaseArtifactCommandRunner struct {
	results []hostruntime.Result
	errs    []error
	argv    [][]string
}

type fakeReleaseArtifactAuthority struct {
	images      VerifiedReleaseImages
	version     string
	verifyErr   error
	smokeErr    error
	afterVerify func()
	afterSmoke  func()
	verifyCalls int
	smokeCalls  int
}

func (authority *fakeReleaseArtifactAuthority) VerifyImages(
	_ context.Context,
	_ hostruntime.PrivateOverlay,
) (VerifiedReleaseImages, error) {
	authority.verifyCalls++
	if authority.afterVerify != nil {
		authority.afterVerify()
	}
	return authority.images, authority.verifyErr
}

func (authority *fakeReleaseArtifactAuthority) SmokeRunner(
	_ context.Context,
	_ hostruntime.PrivateOverlay,
) (string, error) {
	authority.smokeCalls++
	if authority.afterSmoke != nil {
		authority.afterSmoke()
	}
	return authority.version, authority.smokeErr
}

func (runner *releaseArtifactCommandRunner) Run(
	_ context.Context,
	argv []string,
	_ []*os.File,
	_ io.Reader,
) (hostruntime.Result, error) {
	runner.argv = append(runner.argv, append([]string(nil), argv...))
	index := len(runner.argv) - 1
	var err error
	if index < len(runner.errs) {
		err = runner.errs[index]
	}
	if index >= len(runner.results) {
		return hostruntime.Result{}, err
	}
	return runner.results[index], err
}

func releaseInspectFixture(
	t *testing.T,
	references [releaseImageCount]string,
) ([]byte, [releaseImageCount]string) {
	t.Helper()
	var output bytes.Buffer
	var imageIDs [releaseImageCount]string
	for index, reference := range references {
		imageIDs[index] = "sha256:" + strings.Repeat(
			string(rune('a'+index)),
			64,
		)
		line, err := json.Marshal(releaseImageObservation{
			Architecture: "amd64",
			ID:           imageIDs[index],
			OS:           "linux",
			RepoDigests:  []string{reference},
		})
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		output.Write(line)
		output.WriteByte('\n')
	}
	return output.Bytes(), imageIDs
}
