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
	if !state.fencePresent {
		return sealSystemTargetProof(
			overlay,
			revision,
			manifest,
			state,
			nil,
		)
	}
	layout, err := hostruntime.LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	lifecycle, err := hostruntime.OpenLifecycleStoreLayout(layout, false)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	proof, proofErr := sealSystemTargetProof(
		overlay,
		revision,
		manifest,
		state,
		lifecycle,
	)
	closeErr := lifecycle.Close()
	if proofErr != nil || closeErr != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	return proof, nil
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
	_, canonicalRevision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil || canonicalRevision != revision {
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
	if inspectErr != nil || closeErr != nil {
		return hostTargetState{}, ErrProtocol
	}
	if !fencePresent {
		if currentPresent {
			return hostTargetState{}, ErrProtocol
		}
		return hostTargetState{}, nil
	}
	state := hostTargetState{
		fencePresent: true,
		generation:   snapshot.Header.Generation,
		activeFleet:  snapshot.Header.ActiveFleet,
	}
	if !currentPresent {
		return state, nil
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
	state.currentDigest = &currentDigest
	return state, nil
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

func sealGreenfieldContinuationProof(
	overlay hostruntime.PrivateOverlay,
	revision string,
	state hostTargetState,
	manifest hostruntime.RuntimeManifest,
	continuation greenfieldContinuation,
) (cli.TargetProof, error) {
	if !state.fencePresent ||
		state.generation != manifest.FleetGeneration ||
		state.activeFleet != fleetfence.FleetPortable {
		return cli.TargetProof{}, ErrProtocol
	}
	entry, err := sealTargetProofForState(
		overlay,
		revision,
		hostTargetState{},
	)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	binding, terminalGeneration, err := fixedGreenfieldBinding(
		entry,
		manifestDigest,
		revision,
	)
	if err != nil ||
		terminalGeneration != manifest.FleetGeneration ||
		validateGreenfieldContinuation(
			continuation,
			binding,
			nil,
			manifest,
		) != nil ||
		!greenfieldContinuationMatchesLiveState(
			continuation.journal.Phase,
			state.currentDigest,
			manifestDigest,
		) {
		return cli.TargetProof{}, ErrProtocol
	}
	return entry, nil
}

func sealSystemTargetProof(
	overlay hostruntime.PrivateOverlay,
	revision string,
	manifest hostruntime.RuntimeManifest,
	state hostTargetState,
	lifecycle *hostruntime.LifecycleStore,
) (cli.TargetProof, error) {
	if !state.fencePresent {
		return sealTargetProofForState(overlay, revision, state)
	}
	if lifecycle != nil {
		choice, present, readErr := selectPortableInstallContinuation(
			lifecycle,
			revision,
			manifest,
		)
		if readErr != nil {
			return cli.TargetProof{}, ErrProtocol
		}
		if present {
			entry, entryErr := continuationEntryProof(
				overlay,
				revision,
				choice.binding,
			)
			if entryErr != nil ||
				!portableContinuationMatchesLiveState(
					choice.binding,
					choice.continuation.journal.Phase,
					state.currentDigest,
				) {
				return cli.TargetProof{}, ErrProtocol
			}
			if choice.continuation.journal.Phase ==
				hostruntime.OperationPhaseComplete &&
				choice.continuation.reservation.State ==
					hostruntime.ReservationStateCommitted {
				return sealTargetProofForState(overlay, revision, state)
			} else {
				return entry, nil
			}
		}
	}
	if state.currentDigest == nil {
		return cli.TargetProof{}, ErrProtocol
	}
	return sealTargetProofForState(overlay, revision, state)
}

type portableInstallContinuationChoice struct {
	binding       hostruntime.OperationBinding
	priorManifest *hostruntime.RuntimeManifest
	continuation  greenfieldContinuation
}

func selectPortableInstallContinuation(
	store *hostruntime.LifecycleStore,
	overlayRevision string,
	manifest hostruntime.RuntimeManifest,
) (portableInstallContinuationChoice, bool, error) {
	var empty portableInstallContinuationChoice
	if store == nil || !lowerHexDigest(overlayRevision) {
		return empty, false, ErrProtocol
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		return empty, false, ErrProtocol
	}
	journalNames, err := store.ListCanonicalNames(hostruntime.LifecycleJournals)
	if err != nil {
		return empty, false, ErrProtocol
	}
	reservationNames, err := store.ListCanonicalNames(
		hostruntime.LifecycleReservations,
	)
	if err != nil {
		return empty, false, ErrProtocol
	}
	journalIDs, ok := watchdogLifecycleInventory(
		journalNames,
		".journal.json",
	)
	if !ok {
		return empty, false, ErrProtocol
	}
	reservationIDs, ok := watchdogLifecycleInventory(
		reservationNames,
		".reservation.json",
	)
	if !ok || !sameWatchdogInventory(journalIDs, reservationIDs) {
		return empty, false, ErrProtocol
	}
	candidates := make([]portableInstallContinuationChoice, 0, 1)
	for operationID, journalName := range journalIDs {
		journalDocument, readErr := store.ReadCanonical(
			hostruntime.LifecycleJournals,
			journalName,
			maximumProductionLifecycleJournalBytes,
		)
		if readErr != nil {
			return empty, false, ErrProtocol
		}
		journal, _, parseErr := hostruntime.ParseOperationJournal(
			journalDocument,
			maximumProductionLifecycleJournalBytes,
		)
		if parseErr != nil || journal.OperationID != operationID {
			return empty, false, ErrProtocol
		}
		reservationDocument, readErr := store.ReadCanonical(
			hostruntime.LifecycleReservations,
			reservationIDs[operationID],
			maximumProductionLifecycleReservationBytes,
		)
		if readErr != nil {
			return empty, false, ErrProtocol
		}
		reservation, _, parseErr := hostruntime.ParseStorageReservation(
			reservationDocument,
			maximumProductionLifecycleReservationBytes,
		)
		if parseErr != nil ||
			reservation.OperationID != operationID ||
			reservation.BindingDigest != journal.BindingDigest ||
			!watchdogReservationMatchesJournal(reservation, journal) {
			return empty, false, ErrProtocol
		}
		if journal.Kind != hostruntime.OperationKindInstall ||
			journal.TargetManifest == nil {
			continue
		}
		_, targetDigest, digestErr := hostruntime.MarshalRuntimeManifest(
			*journal.TargetManifest,
		)
		if digestErr != nil || targetDigest != manifestDigest {
			continue
		}
		binding, bindingErr := watchdogInstallBinding(
			journal,
			overlayRevision,
		)
		if bindingErr != nil ||
			binding.InstallDisposition == nil ||
			(*binding.InstallDisposition !=
				hostruntime.InstallDispositionGreenfieldPortable &&
				*binding.InstallDisposition !=
					hostruntime.InstallDispositionUpgradePortable) ||
			!watchdogTargetGenerationMatches(binding, manifest) {
			return empty, false, ErrProtocol
		}
		var priorManifest *hostruntime.RuntimeManifest
		if journal.PriorManifest != nil {
			copy := *journal.PriorManifest
			priorManifest = &copy
		}
		continuation, present, continuationErr := readGreenfieldContinuation(
			store,
			binding,
			priorManifest,
			manifest,
		)
		if continuationErr != nil || !present {
			return empty, false, ErrProtocol
		}
		candidates = append(candidates, portableInstallContinuationChoice{
			binding:       binding,
			priorManifest: priorManifest,
			continuation:  continuation,
		})
	}
	if len(candidates) == 0 {
		return empty, false, nil
	}
	if len(candidates) != 1 {
		return empty, false, ErrProtocol
	}
	return candidates[0], true, nil
}

func continuationEntryProof(
	overlay hostruntime.PrivateOverlay,
	revision string,
	binding hostruntime.OperationBinding,
) (cli.TargetProof, error) {
	if binding.InstallDisposition == nil {
		return cli.TargetProof{}, ErrProtocol
	}
	var state hostTargetState
	switch *binding.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
	case hostruntime.InstallDispositionUpgradePortable:
		if binding.PriorManifestDigest == nil ||
			binding.ExpectedGeneration == 0 {
			return cli.TargetProof{}, ErrProtocol
		}
		state = hostTargetState{
			fencePresent:  true,
			generation:    binding.ExpectedGeneration,
			activeFleet:   fleetfence.FleetPortable,
			currentDigest: cloneTargetDigest(binding.PriorManifestDigest),
		}
	default:
		return cli.TargetProof{}, ErrProtocol
	}
	entry, err := sealTargetProofForState(overlay, revision, state)
	if err != nil {
		return cli.TargetProof{}, ErrProtocol
	}
	derived, generation, err := fixedInstallBinding(
		entry,
		*binding.TargetManifestDigest,
		revision,
	)
	if err != nil || generation == 0 || !reflect.DeepEqual(derived, binding) {
		return cli.TargetProof{}, ErrProtocol
	}
	return entry, nil
}

func portableContinuationMatchesLiveState(
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	currentDigest *string,
) bool {
	if binding.InstallDisposition == nil ||
		binding.TargetManifestDigest == nil {
		return false
	}
	switch *binding.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		return greenfieldContinuationMatchesLiveState(
			phase,
			currentDigest,
			*binding.TargetManifestDigest,
		)
	case hostruntime.InstallDispositionUpgradePortable:
		if binding.PriorManifestDigest == nil || currentDigest == nil {
			return false
		}
		switch phase {
		case hostruntime.OperationPhasePrepared,
			hostruntime.OperationPhasePreflightProven,
			hostruntime.OperationPhaseCandidateStaged,
			hostruntime.OperationPhaseCandidateSmoked,
			hostruntime.OperationPhasePriorRetained,
			hostruntime.OperationPhaseDispositionUpgradeProven,
			hostruntime.OperationPhasePriorAcquisitionDisabled,
			hostruntime.OperationPhasePriorDrained,
			hostruntime.OperationPhasePriorControllerStopped,
			hostruntime.OperationPhasePriorQuiescenceProven,
			hostruntime.OperationPhaseFencePortableProven,
			hostruntime.OperationPhaseWatchdogInstalled,
			hostruntime.OperationPhasePolicyDisabled,
			hostruntime.OperationPhaseObserverStarted:
			return *currentDigest == *binding.PriorManifestDigest
		case hostruntime.OperationPhaseZeroProven:
			return *currentDigest == *binding.PriorManifestDigest ||
				*currentDigest == *binding.TargetManifestDigest
		case hostruntime.OperationPhaseCurrentSelected:
			return *currentDigest == *binding.PriorManifestDigest ||
				*currentDigest == *binding.TargetManifestDigest
		case hostruntime.OperationPhaseVerified,
			hostruntime.OperationPhaseComplete:
			return *currentDigest == *binding.TargetManifestDigest
		default:
			return false
		}
	default:
		return false
	}
}

func greenfieldContinuationMatchesLiveState(
	phase hostruntime.OperationPhase,
	currentDigest *string,
	targetManifestDigest string,
) bool {
	switch phase {
	case hostruntime.OperationPhaseFencePortable,
		hostruntime.OperationPhaseWatchdogInstalled,
		hostruntime.OperationPhasePolicyDisabled,
		hostruntime.OperationPhaseObserverStarted:
		return currentDigest == nil
	case hostruntime.OperationPhaseZeroProven:
		return currentDigest == nil ||
			*currentDigest == targetManifestDigest
	case hostruntime.OperationPhaseCurrentSelected:
		return currentDigest == nil ||
			*currentDigest == targetManifestDigest
	case hostruntime.OperationPhaseVerified,
		hostruntime.OperationPhaseComplete:
		return currentDigest != nil &&
			*currentDigest == targetManifestDigest
	default:
		return false
	}
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
