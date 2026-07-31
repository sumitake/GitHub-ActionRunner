package productionruntime

import (
	"bytes"
	"context"
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type targetOverlayLoader func(string) (
	hostruntime.PrivateOverlay,
	string,
	error,
)

type targetManifestLoader func(string) (
	hostruntime.RuntimeManifest,
	[]byte,
	string,
	error,
)

// SystemTargetHostExecutor is the target-local closed command adapter. It
// sequences the same prove, optional stage, and invoke operations as the
// control-side transport without exposing a generic execution surface.
type SystemTargetHostExecutor struct {
	handler      TargetHandler
	loadOverlay  targetOverlayLoader
	loadManifest targetManifestLoader
}

func NewSystemTargetHostExecutor(
	handler TargetHandler,
) *SystemTargetHostExecutor {
	return newSystemTargetHostExecutor(
		handler,
		loadPinnedTargetOverlay,
		loadPinnedTargetManifest,
	)
}

func newSystemTargetHostExecutor(
	handler TargetHandler,
	loadOverlay targetOverlayLoader,
	loadManifest targetManifestLoader,
) *SystemTargetHostExecutor {
	return &SystemTargetHostExecutor{
		handler:      handler,
		loadOverlay:  loadOverlay,
		loadManifest: loadManifest,
	}
}

func (executor *SystemTargetHostExecutor) ExecuteTargetHost(
	ctx context.Context,
	request hostruntime.TargetHostRequest,
) (hostruntime.HostActionResult, error) {
	action, ok := targetCLIAction(request)
	if executor == nil ||
		executor.handler == nil ||
		executor.loadOverlay == nil ||
		executor.loadManifest == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		!ok ||
		!validTargetRequestShape(request) {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}

	overlay, revision, err := executor.loadOverlay(request.PrivatePath)
	if err != nil ||
		!targetActionAllowed(overlay, request.Action) {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}
	canonicalOverlay, canonicalRevision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil ||
		len(canonicalOverlay) == 0 ||
		canonicalRevision != revision {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}
	manifest, manifestDocument, manifestDigest, err :=
		executor.loadManifest(overlay.Manifest.Path)
	if err != nil ||
		manifestDigest != overlay.Manifest.Digest ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}
	canonicalManifest, canonicalManifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil ||
		canonicalManifestDigest != manifestDigest ||
		!bytes.Equal(canonicalManifest, manifestDocument) {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}

	target, err := executor.handler.ProveTarget(ctx, overlay, revision)
	if err != nil ||
		!targetProofMatchesOverlay(target, overlay, revision) {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}
	sealedTarget, err := cli.SealTargetProof(target)
	if err != nil || sealedTarget.ProofDigest != target.ProofDigest {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}

	arguments := InvokeArguments{
		ManifestDigest:    manifestDigest,
		TargetProofDigest: target.ProofDigest,
	}
	switch action {
	case cli.ActionInstall:
		stage, stageErr := executor.handler.StageRelease(
			ctx,
			overlay,
			revision,
			target,
			manifest,
			manifestDigest,
		)
		sealedStage, sealErr := cli.SealStageProof(stage)
		if stageErr != nil ||
			sealErr != nil ||
			sealedStage != stage ||
			stage.TargetProofDigest != target.ProofDigest ||
			stage.PrivateOverlayRevision != revision ||
			stage.ManifestDigest != manifestDigest {
			return hostruntime.HostActionResult{},
				hostruntime.ErrTargetHostFailed
		}
		arguments.Acquisition = "disabled"
		arguments.StageProofDigest = stage.ProofDigest
	case cli.ActionVerify:
		arguments.RequireZero = true
	case cli.ActionSuspend:
		arguments.DrainPolicy = request.DrainPolicy
		arguments.HostedConfirmation = request.HostedConfirmation
		arguments.RequireZero = true
	case cli.ActionResume:
		arguments.Acquisition = "disabled"
	default:
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}

	operationID, generation, fleet, err := cli.ExpectedOperation(
		action,
		target,
		manifestDigest,
		revision,
	)
	if err != nil {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}
	result, err := executor.handler.Invoke(
		ctx,
		overlay,
		revision,
		target,
		action,
		arguments,
	)
	if err != nil ||
		result.Status != hostruntime.HostActionComplete ||
		result.OperationID != operationID ||
		result.FenceGeneration != generation ||
		result.ActiveFleet != fleet ||
		result.TargetProofDigest == nil {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}
	if _, _, err := hostruntime.MarshalHostActionResult(result); err != nil {
		return hostruntime.HostActionResult{},
			hostruntime.ErrTargetHostFailed
	}
	return result, nil
}

func targetCLIAction(
	request hostruntime.TargetHostRequest,
) (cli.HostAction, bool) {
	switch request.Action {
	case hostruntime.TargetInstall:
		return cli.ActionInstall, true
	case hostruntime.TargetVerify:
		return cli.ActionVerify, true
	case hostruntime.TargetSuspend:
		return cli.ActionSuspend, true
	case hostruntime.TargetResume:
		return cli.ActionResume, true
	default:
		return 0, false
	}
}

func validTargetRequestShape(request hostruntime.TargetHostRequest) bool {
	if !canonicalTargetFile(request.PrivatePath) {
		return false
	}
	switch request.Action {
	case hostruntime.TargetInstall:
		return canonicalTargetFile(request.ManifestPath) &&
			request.ManifestPath != request.PrivatePath &&
			request.DrainPolicy == "" &&
			request.HostedConfirmation == "" &&
			!request.RequireZero
	case hostruntime.TargetVerify:
		return canonicalTargetFile(request.ManifestPath) &&
			request.ManifestPath != request.PrivatePath &&
			request.DrainPolicy == "" &&
			request.HostedConfirmation == "" &&
			request.RequireZero
	case hostruntime.TargetSuspend:
		return request.ManifestPath == "" &&
			(request.DrainPolicy == "wait" ||
				request.DrainPolicy == "cancel") &&
			canonicalTargetFile(request.HostedConfirmation) &&
			request.HostedConfirmation != request.PrivatePath &&
			request.RequireZero
	case hostruntime.TargetResume:
		return request.ManifestPath == "" &&
			request.DrainPolicy == "" &&
			request.HostedConfirmation == "" &&
			!request.RequireZero
	default:
		return false
	}
}

func canonicalTargetFile(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func targetActionAllowed(
	overlay hostruntime.PrivateOverlay,
	action hostruntime.TargetHostAction,
) bool {
	for _, allowed := range overlay.AllowedActions {
		if allowed == string(action) {
			return true
		}
	}
	return false
}

func targetProofMatchesOverlay(
	target cli.TargetProof,
	overlay hostruntime.PrivateOverlay,
	revision string,
) bool {
	return target.PrivateOverlayRevision == revision &&
		target.HostIdentityDigest == overlay.Target.HostIdentityDigest &&
		target.ControlIdentityDigest ==
			overlay.Target.ControlHostIdentityDigest &&
		target.OS == overlay.Target.OS &&
		target.Architecture == overlay.Target.Architecture &&
		target.ExpectedEUID == overlay.Target.ExpectedEUID
}

func loadPinnedTargetOverlay(
	path string,
) (hostruntime.PrivateOverlay, string, error) {
	document, err := readPinnedAbsoluteFile(
		path,
		0o600,
		maximumReleaseOverlayBytes,
	)
	if err != nil {
		return hostruntime.PrivateOverlay{}, "", ErrProtocol
	}
	return hostruntime.ParsePrivateOverlay(
		document,
		maximumReleaseOverlayBytes,
	)
}

func loadPinnedTargetManifest(
	path string,
) (hostruntime.RuntimeManifest, []byte, string, error) {
	document, err := readPinnedAbsoluteFile(
		path,
		0o600,
		maximumReleaseManifestBytes,
	)
	if err != nil {
		return hostruntime.RuntimeManifest{}, nil, "", ErrProtocol
	}
	manifest, digest, err := hostruntime.ParseRuntimeManifest(
		document,
		maximumReleaseManifestBytes,
	)
	if err != nil {
		return hostruntime.RuntimeManifest{}, nil, "", ErrProtocol
	}
	return manifest, document, digest, nil
}

var _ hostruntime.TargetHostExecutor = (*SystemTargetHostExecutor)(nil)
