package productionruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type systemTargetProver func(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
) (cli.TargetProof, error)

type systemLifecycleInvoker func(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	cli.HostAction,
	InvokeArguments,
) (hostruntime.HostActionResult, error)

type SystemTargetHandler struct {
	prove  systemTargetProver
	invoke systemLifecycleInvoker
}

type hostTargetState struct {
	fencePresent  bool
	generation    uint64
	activeFleet   fleetfence.Fleet
	currentDigest *string
}

func NewSystemTargetHandler() *SystemTargetHandler {
	return newSystemTargetHandler(
		proveSystemTarget,
		invokeSystemLifecycle,
	)
}

func newSystemTargetHandler(
	prove systemTargetProver,
	invoke systemLifecycleInvoker,
) *SystemTargetHandler {
	return &SystemTargetHandler{
		prove:  prove,
		invoke: invoke,
	}
}

func (handler *SystemTargetHandler) ProveTarget(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
) (cli.TargetProof, error) {
	if handler == nil ||
		handler.prove == nil ||
		ctx == nil ||
		ctx.Err() != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	return handler.prove(ctx, overlay, revision)
}

func proveSystemTarget(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
) (cli.TargetProof, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		runtime.GOOS != overlay.Target.OS ||
		runtime.GOARCH != overlay.Target.Architecture ||
		uint64(os.Geteuid()) != overlay.Target.ExpectedEUID {
		return cli.TargetProof{}, ErrProtocol
	}
	_, canonicalRevision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil || canonicalRevision != revision {
		return cli.TargetProof{}, ErrProtocol
	}
	manifestDocument, err := readPinnedAbsoluteFile(
		overlay.Manifest.Path,
		0o600,
		maximumReleaseManifestBytes,
	)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	manifest, manifestDigest, err := hostruntime.ParseRuntimeManifest(
		manifestDocument,
		maximumReleaseManifestBytes,
	)
	if err != nil ||
		manifestDigest != overlay.Manifest.Digest ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return cli.TargetProof{}, ErrProtocol
	}
	state, err := inspectHostTargetState(ctx, overlay)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	return sealTargetProofForState(overlay, revision, state)
}

func (handler *SystemTargetHandler) StageRelease(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	manifest hostruntime.RuntimeManifest,
	manifestDigest string,
) (cli.StageProof, error) {
	if handler == nil || ctx == nil || ctx.Err() != nil {
		return cli.StageProof{}, ErrProtocol
	}
	current, err := handler.ProveTarget(ctx, overlay, revision)
	if err != nil || !reflect.DeepEqual(current, target) {
		return cli.StageProof{}, ErrProtocol
	}
	manifestDocument, canonicalDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil ||
		canonicalDigest != manifestDigest ||
		manifestDigest != overlay.Manifest.Digest ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return cli.StageProof{}, ErrProtocol
	}
	targetManifest, err := readPinnedAbsoluteFile(
		overlay.Manifest.Path,
		0o600,
		maximumReleaseManifestBytes,
	)
	if err != nil || !bytes.Equal(targetManifest, manifestDocument) {
		return cli.StageProof{}, ErrProtocol
	}
	controllerDigest, err := digestPinnedExecutable(
		overlay.Commands.ControllerBinary,
	)
	if err != nil || controllerDigest != manifest.ControllerSHA256 {
		return cli.StageProof{}, ErrProtocol
	}
	overlayDocument, canonicalRevision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil || canonicalRevision != revision {
		return cli.StageProof{}, ErrProtocol
	}
	store, err := openReleaseBundleStore(
		overlay.Paths.StagingRoot,
		overlay.Paths.ReleaseRoot,
	)
	if err != nil {
		return cli.StageProof{}, ErrProtocol
	}
	defer store.Close()
	if err := store.Stage(
		manifestDigest,
		revision,
		overlayDocument,
		manifestDocument,
	); err != nil {
		return cli.StageProof{}, ErrProtocol
	}
	proof, err := cli.SealStageProof(cli.StageProof{
		SchemaVersion:          1,
		TargetProofDigest:      target.ProofDigest,
		PrivateOverlayRevision: revision,
		ManifestDigest:         manifestDigest,
	})
	if err != nil {
		return cli.StageProof{}, ErrProtocol
	}
	return proof, nil
}

func (handler *SystemTargetHandler) Invoke(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	action cli.HostAction,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	if handler == nil ||
		handler.prove == nil ||
		handler.invoke == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		!targetActionAllowed(
			overlay,
			targetHostActionForCLI(action),
		) ||
		!validInvokeArguments(
			action,
			arguments,
			overlay,
			target.ProofDigest,
		) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	current, err := handler.ProveTarget(ctx, overlay, revision)
	if err != nil || !reflect.DeepEqual(current, target) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	sealedTarget, err := cli.SealTargetProof(target)
	if err != nil || sealedTarget.ProofDigest != target.ProofDigest {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	if action == cli.ActionInstall {
		expectedStage, sealErr := cli.SealStageProof(cli.StageProof{
			SchemaVersion:          1,
			TargetProofDigest:      target.ProofDigest,
			PrivateOverlayRevision: revision,
			ManifestDigest:         arguments.ManifestDigest,
		})
		if sealErr != nil ||
			expectedStage.ProofDigest != arguments.StageProofDigest {
			return hostruntime.HostActionResult{}, ErrProtocol
		}
	}
	operationID, generation, fleet, err := cli.ExpectedOperation(
		action,
		target,
		arguments.ManifestDigest,
		revision,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	result, err := handler.invoke(
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
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	if _, _, err := hostruntime.MarshalHostActionResult(result); err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	return result, nil
}

func targetHostActionForCLI(action cli.HostAction) hostruntime.TargetHostAction {
	switch action {
	case cli.ActionInstall:
		return hostruntime.TargetInstall
	case cli.ActionVerify:
		return hostruntime.TargetVerify
	case cli.ActionSuspend:
		return hostruntime.TargetSuspend
	case cli.ActionResume:
		return hostruntime.TargetResume
	default:
		return ""
	}
}

func inspectHostTargetState(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
) (hostTargetState, error) {
	if ctx == nil || ctx.Err() != nil {
		return hostTargetState{}, ErrProtocol
	}
	releases, err := openReleaseBundleStore(
		overlay.Paths.StagingRoot,
		overlay.Paths.ReleaseRoot,
	)
	if err != nil {
		return hostTargetState{}, ErrProtocol
	}
	current, currentPresent, currentErr := releases.Current()
	closeErr := releases.Close()
	if currentErr != nil || closeErr != nil {
		return hostTargetState{}, ErrProtocol
	}
	lockPoll, err := time.ParseDuration(
		overlay.Fence.LockPollInterval,
	)
	if err != nil || lockPoll <= 0 {
		return hostTargetState{}, ErrProtocol
	}
	fenceStore, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             overlay.Paths.FenceRoot,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: lockPoll,
	})
	if err != nil {
		return hostTargetState{}, ErrProtocol
	}
	snapshot, fencePresent, inspectErr :=
		fenceStore.InspectOptional(ctx)
	closeErr = fenceStore.Close()
	if inspectErr != nil || closeErr != nil ||
		currentPresent != fencePresent {
		return hostTargetState{}, ErrProtocol
	}
	if !fencePresent {
		return hostTargetState{}, nil
	}
	if current.manifestDigest == "" ||
		current.overlayRevision == "" {
		return hostTargetState{}, ErrProtocol
	}
	if snapshot.Header.ActiveFleet == fleetfence.FleetPortable {
		manifest, _, err := hostruntime.ParseRuntimeManifest(
			current.manifestDocument,
			maximumReleaseManifestBytes,
		)
		if err != nil ||
			manifest.FleetGeneration != snapshot.Header.Generation {
			return hostTargetState{}, ErrProtocol
		}
	}
	currentDigest := current.manifestDigest
	return hostTargetState{
		fencePresent:  true,
		generation:    snapshot.Header.Generation,
		activeFleet:   snapshot.Header.ActiveFleet,
		currentDigest: &currentDigest,
	}, nil
}

func sealTargetProofForState(
	overlay hostruntime.PrivateOverlay,
	revision string,
	state hostTargetState,
) (cli.TargetProof, error) {
	_, canonicalRevision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil || canonicalRevision != revision {
		return cli.TargetProof{}, ErrProtocol
	}
	proof := cli.TargetProof{
		SchemaVersion:          1,
		PrivateOverlayRevision: revision,
		HostIdentityDigest:     overlay.Target.HostIdentityDigest,
		ControlIdentityDigest:  overlay.Target.ControlHostIdentityDigest,
		OS:                     overlay.Target.OS,
		Architecture:           overlay.Target.Architecture,
		ExpectedEUID:           overlay.Target.ExpectedEUID,
		CurrentManifestDigest:  cloneTargetDigest(state.currentDigest),
	}
	switch {
	case !state.fencePresent:
		if state.generation != 0 ||
			state.activeFleet != "" ||
			state.currentDigest != nil {
			return cli.TargetProof{}, ErrProtocol
		}
		disposition := hostruntime.InstallDispositionGreenfieldPortable
		proof.ActiveFleet = fleetfence.FleetNone
		proof.InstallDisposition = &disposition
	case state.generation == 0 || state.currentDigest == nil:
		return cli.TargetProof{}, ErrProtocol
	case state.activeFleet == fleetfence.FleetPortable:
		disposition := hostruntime.InstallDispositionUpgradePortable
		proof.FenceGeneration = state.generation
		proof.ActiveFleet = state.activeFleet
		proof.InstallDisposition = &disposition
	case state.activeFleet == fleetfence.FleetNone:
		proof.FenceGeneration = state.generation
		proof.ActiveFleet = state.activeFleet
	case state.activeFleet == fleetfence.FleetLegacy:
		// Legacy normalization requires a separate, positively verified
		// authority that is intentionally not inferred from the portable
		// release state.
		return cli.TargetProof{}, ErrProtocol
	default:
		return cli.TargetProof{}, ErrProtocol
	}
	sealed, err := cli.SealTargetProof(proof)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	return sealed, nil
}

func cloneTargetDigest(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func runtimeManifestMatchesOverlay(
	manifest hostruntime.RuntimeManifest,
	overlay hostruntime.PrivateOverlay,
) bool {
	return manifest.EgressMode == overlay.Docker.BrokerNetworkID &&
		manifest.PolicyManifestDigest == overlay.Policy.ManifestDigest &&
		imageReferenceMatchesRuntimeDigest(
			overlay.Docker.RunnerImage,
			manifest.RunnerImageDigest,
		) &&
		imageReferenceMatchesRuntimeDigest(
			overlay.Docker.AdapterImage,
			manifest.AdapterImageDigest,
		) &&
		imageReferenceMatchesRuntimeDigest(
			overlay.Docker.BrokerImage,
			manifest.BrokerImageDigest,
		) &&
		imageReferenceMatchesRuntimeDigest(
			overlay.Docker.HelperImage,
			manifest.HelperImageDigest,
		) &&
		imageReferenceMatchesRuntimeDigest(
			overlay.Docker.VerifierImage,
			manifest.VerifierImageDigest,
		)
}

func imageReferenceMatchesRuntimeDigest(
	reference string,
	digest string,
) bool {
	return strings.HasSuffix(reference, "@"+digest) &&
		len(reference) > len(digest)+1
}

func digestPinnedExecutable(path string) (string, error) {
	document, err := readPinnedAbsoluteFile(path, 0o500, 1<<30)
	if err != nil {
		return "", ErrProtocol
	}
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:]), nil
}

var _ TargetHandler = (*SystemTargetHandler)(nil)
