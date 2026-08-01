package productionruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/state"
)

type productionEffect uint8

const (
	maximumProductionLifecycleJournalBytes       = 1 << 20
	maximumProductionLifecyclePostconditionBytes = 4 << 20
	maximumProductionLifecycleReservationBytes   = 4 << 20
)

const (
	effectPreflight productionEffect = iota + 1
	effectCandidateStaged
	effectCandidateSmoked
	effectCandidatePromoted
	effectGreenfieldProven
	effectUpgradeProven
	effectPriorAcquisitionDisabled
	effectPriorDrained
	effectPriorControllerStopped
	effectPriorQuiescenceProven
	effectFencePortableProven
	effectFencePortable
	effectWatchdogInstalled
	effectPolicyDisabled
	effectObserverStarted
	effectZeroProven
	effectCurrentSelected
	effectVerified
)

// productionPhaseEffects is the sole phase-to-effect table. All lifecycle
// adapters below dispatch only on the closed effect value from this table.
var productionPhaseEffects = map[hostruntime.OperationPhase]productionEffect{
	hostruntime.OperationPhasePrepared:                    effectPreflight,
	hostruntime.OperationPhasePreflightProven:             effectPreflight,
	hostruntime.OperationPhaseCandidateStaged:             effectCandidateStaged,
	hostruntime.OperationPhaseCandidateSmoked:             effectCandidateSmoked,
	hostruntime.OperationPhasePriorRetained:               effectCandidatePromoted,
	hostruntime.OperationPhaseDispositionGreenfieldProven: effectGreenfieldProven,
	hostruntime.OperationPhasePriorAbsenceProven:          effectGreenfieldProven,
	hostruntime.OperationPhaseDispositionUpgradeProven:    effectUpgradeProven,
	hostruntime.OperationPhasePriorAcquisitionDisabled:    effectPriorAcquisitionDisabled,
	hostruntime.OperationPhasePriorDrained:                effectPriorDrained,
	hostruntime.OperationPhasePriorControllerStopped:      effectPriorControllerStopped,
	hostruntime.OperationPhasePriorQuiescenceProven:       effectPriorQuiescenceProven,
	hostruntime.OperationPhaseFencePortableProven:         effectFencePortableProven,
	hostruntime.OperationPhaseFencePortable:               effectFencePortable,
	hostruntime.OperationPhaseWatchdogInstalled:           effectWatchdogInstalled,
	hostruntime.OperationPhasePolicyDisabled:              effectPolicyDisabled,
	hostruntime.OperationPhaseObserverStarted:             effectObserverStarted,
	hostruntime.OperationPhaseZeroProven:                  effectZeroProven,
	hostruntime.OperationPhaseCurrentSelected:             effectCurrentSelected,
	hostruntime.OperationPhaseVerified:                    effectVerified,
	hostruntime.OperationPhaseComplete:                    effectVerified,
}

type productionLifecycleBackend struct {
	target *greenfieldSystemTarget
}

func (backend *productionLifecycleBackend) ObservePhase(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) (hostruntime.LifecycleEffectObservation, error) {
	effect, ok := productionPhaseEffects[phase]
	if backend == nil ||
		backend.target == nil ||
		!ok {
		return hostruntime.LifecycleEffectObservation{},
			ErrLifecycleEffects
	}
	return backend.target.observe(ctx, binding, phase, effect)
}

func (backend *productionLifecycleBackend) ApplyPhase(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) error {
	effect, ok := productionPhaseEffects[phase]
	if backend == nil ||
		backend.target == nil ||
		!ok {
		return ErrLifecycleEffects
	}
	return backend.target.apply(ctx, binding, effect)
}

type greenfieldSystemTarget struct {
	disposition    hostruntime.InstallDisposition
	overlay        hostruntime.PrivateOverlay
	revision       string
	manifest       hostruntime.RuntimeManifest
	manifestDigest string
	terminalFence  uint64
	pollInterval   time.Duration
	now            func() time.Time

	releases            *releaseBundleStore
	fence               *fleetfence.Store
	storage             *SystemStorageProbe
	docker              hostruntime.ManagedQuiescence
	process             *ProcessAuthority
	priorProcess        *ProcessAuthority
	processStore        *PinnedProcessRecordStore
	watchdog            *watchdogMarkerStore
	probe               DisabledControllerProbe
	priorAdmin          lifecycleControllerAdmin
	priorOverlay        *hostruntime.PrivateOverlay
	priorRevision       string
	priorManifestDigest string
	artifacts           releaseArtifactAuthority
}

type greenfieldSnapshot struct {
	fencePresent bool
	generation   uint64
	fleet        fleetfence.Fleet

	stagedPresent   bool
	imagesVerified  bool
	runnerSmoked    bool
	releasedPresent bool
	currentPresent  bool
	current         releaseBundleSnapshot

	watchdogPresent bool
	watchdogPrior   bool
	watchdogTarget  bool
	watchdog        hostruntime.ArtifactProjection
	processPresent  bool
	processPrior    bool
	processTarget   bool
	processRecord   ProcessRecord
	processIdentity string
	priorPolicy     controller.PolicyStatus
	priorDrained    bool
	assignedJobs    uint64
	runningJobs     uint64
	activeListeners uint64
	zero            bool
	policyEpoch     uint64
	filesystems     []hostruntime.LifecycleFilesystemIdentity
}

func invokeSystemLifecycle(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	action cli.HostAction,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	switch action {
	case cli.ActionInstall:
		return invokePortableInstall(
			ctx,
			overlay,
			revision,
			target,
			arguments,
		)
	case cli.ActionVerify:
		return verifyInstalledTarget(
			ctx,
			overlay,
			revision,
			target,
			arguments,
		)
	default:
		return hostruntime.HostActionResult{}, ErrProtocol
	}
}

func invokePortableInstall(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		target.InstallDisposition == nil ||
		!overlay.Resources.RunnerSizing.OperatorApproved {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	disposition := *target.InstallDisposition
	if disposition != hostruntime.InstallDispositionGreenfieldPortable &&
		disposition != hostruntime.InstallDispositionUpgradePortable {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	if disposition == hostruntime.InstallDispositionGreenfieldPortable &&
		(target.FenceGeneration != 0 ||
			target.ActiveFleet != fleetfence.FleetNone ||
			target.CurrentManifestDigest != nil) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	if disposition == hostruntime.InstallDispositionUpgradePortable &&
		(target.FenceGeneration == 0 ||
			target.ActiveFleet != fleetfence.FleetPortable ||
			target.CurrentManifestDigest == nil) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	manifest, manifestDocument, manifestDigest, err :=
		loadPinnedTargetManifest(overlay.Manifest.Path)
	if err != nil ||
		len(manifestDocument) == 0 ||
		manifestDigest != arguments.ManifestDigest ||
		manifestDigest != overlay.Manifest.Digest ||
		(disposition == hostruntime.InstallDispositionGreenfieldPortable &&
			manifest.FleetGeneration != 1) ||
		(disposition == hostruntime.InstallDispositionUpgradePortable &&
			manifest.FleetGeneration != target.FenceGeneration) ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	binding, terminalGeneration, err := fixedInstallBinding(
		target,
		manifestDigest,
		revision,
	)
	if err != nil || terminalGeneration != manifest.FleetGeneration {
		return hostruntime.HostActionResult{}, ErrProtocol
	}

	resources, request, err := openInstallOperation(
		ctx,
		overlay,
		revision,
		manifest,
		manifestDigest,
		binding,
		true,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	result, runErr := resources.engine.Execute(ctx, request)
	closeErr := resources.Close()
	if runErr != nil || closeErr != nil {
		return hostruntime.HostActionResult{},
			errors.Join(ErrProtocol, runErr, closeErr)
	}
	return result, nil
}

func fixedInstallBinding(
	target cli.TargetProof,
	manifestDigest string,
	revision string,
) (hostruntime.OperationBinding, uint64, error) {
	if target.InstallDisposition == nil {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	switch *target.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		return fixedGreenfieldBinding(target, manifestDigest, revision)
	case hostruntime.InstallDispositionUpgradePortable:
		return fixedUpgradeBinding(target, manifestDigest, revision)
	default:
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
}

func fixedGreenfieldBinding(
	target cli.TargetProof,
	manifestDigest string,
	revision string,
) (hostruntime.OperationBinding, uint64, error) {
	operationID, terminalGeneration, terminalFleet, err :=
		cli.ExpectedOperation(
			cli.ActionInstall,
			target,
			manifestDigest,
			revision,
		)
	if err != nil ||
		terminalFleet != fleetfence.FleetPortable ||
		target.InstallDisposition == nil ||
		*target.InstallDisposition !=
			hostruntime.InstallDispositionGreenfieldPortable {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	targetManifest := manifestDigest
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     0,
		PriorManifestDigest:    nil,
		TargetManifestDigest:   &targetManifest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	if _, _, err := hostruntime.MarshalOperationBinding(binding); err != nil {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	return binding, terminalGeneration, nil
}

func fixedUpgradeBinding(
	target cli.TargetProof,
	manifestDigest string,
	revision string,
) (hostruntime.OperationBinding, uint64, error) {
	operationID, terminalGeneration, terminalFleet, err :=
		cli.ExpectedOperation(
			cli.ActionInstall,
			target,
			manifestDigest,
			revision,
		)
	if err != nil ||
		terminalFleet != fleetfence.FleetPortable ||
		target.InstallDisposition == nil ||
		*target.InstallDisposition !=
			hostruntime.InstallDispositionUpgradePortable ||
		target.CurrentManifestDigest == nil ||
		*target.CurrentManifestDigest == manifestDigest {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	priorManifest := *target.CurrentManifestDigest
	targetManifest := manifestDigest
	disposition := hostruntime.InstallDispositionUpgradePortable
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     target.FenceGeneration,
		PriorManifestDigest:    &priorManifest,
		TargetManifestDigest:   &targetManifest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	if _, _, err := hostruntime.MarshalOperationBinding(binding); err != nil {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	return binding, terminalGeneration, nil
}

func loadPriorReleaseForInstall(
	releases *releaseBundleStore,
	binding hostruntime.OperationBinding,
	targetOverlay hostruntime.PrivateOverlay,
	targetManifest hostruntime.RuntimeManifest,
) (
	*hostruntime.RuntimeManifest,
	*hostruntime.PrivateOverlay,
	string,
	error,
) {
	if releases == nil || binding.InstallDisposition == nil {
		return nil, nil, "", ErrLifecycleEffects
	}
	switch *binding.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		if binding.PriorManifestDigest != nil {
			return nil, nil, "", ErrLifecycleEffects
		}
		return nil, nil, "", nil
	case hostruntime.InstallDispositionUpgradePortable:
		if binding.PriorManifestDigest == nil ||
			binding.TargetManifestDigest == nil ||
			*binding.PriorManifestDigest ==
				*binding.TargetManifestDigest {
			return nil, nil, "", ErrLifecycleEffects
		}
	default:
		return nil, nil, "", ErrLifecycleEffects
	}
	current, present, err := releases.InspectReleasedDigest(
		*binding.PriorManifestDigest,
	)
	if err != nil ||
		!present ||
		current.manifestDigest != *binding.PriorManifestDigest ||
		!lowerHexDigest(current.overlayRevision) {
		return nil, nil, "", ErrLifecycleEffects
	}
	priorManifest, parsedManifestDigest, err :=
		hostruntime.ParseRuntimeManifest(
			current.manifestDocument,
			maximumReleaseManifestBytes,
		)
	if err != nil ||
		parsedManifestDigest != current.manifestDigest ||
		priorManifest.FleetGeneration != binding.ExpectedGeneration ||
		priorManifest.FleetGeneration != targetManifest.FleetGeneration {
		return nil, nil, "", ErrLifecycleEffects
	}
	priorOverlay, parsedRevision, err := hostruntime.ParsePrivateOverlay(
		current.overlayDocument,
		maximumReleaseOverlayBytes,
	)
	if err != nil ||
		parsedRevision != current.overlayRevision ||
		priorOverlay.Manifest.Digest != current.manifestDigest ||
		priorOverlay.Paths != targetOverlay.Paths ||
		priorOverlay.Target != targetOverlay.Target ||
		!priorOverlay.Resources.RunnerSizing.OperatorApproved ||
		!runtimeManifestMatchesOverlay(priorManifest, priorOverlay) {
		return nil, nil, "", ErrLifecycleEffects
	}
	return &priorManifest, &priorOverlay, parsedRevision, nil
}

type greenfieldInstallResources struct {
	engine       hostruntime.LifecycleEngine
	lifecycle    *hostruntime.LifecycleStore
	releases     *releaseBundleStore
	fence        *fleetfence.Store
	processStore *PinnedProcessRecordStore
	watchdog     *watchdogMarkerStore
}

func openInstallOperation(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	manifest hostruntime.RuntimeManifest,
	manifestDigest string,
	binding hostruntime.OperationBinding,
	bootstrapLifecycle bool,
) (*greenfieldInstallResources, hostruntime.LifecycleRequest, error) {
	var request hostruntime.LifecycleRequest
	if ctx == nil || ctx.Err() != nil {
		return nil, request, ErrProtocol
	}
	releases, err := openReleaseBundleStore(
		overlay.Paths.StagingRoot,
		overlay.Paths.ReleaseRoot,
	)
	if err != nil {
		return nil, request, ErrProtocol
	}
	resources := &greenfieldInstallResources{releases: releases}
	fail := func(primary error) (
		*greenfieldInstallResources,
		hostruntime.LifecycleRequest,
		error,
	) {
		return nil, hostruntime.LifecycleRequest{},
			errors.Join(primary, resources.Close())
	}
	priorManifest, priorOverlay, priorRevision, err :=
		loadPriorReleaseForInstall(
			releases,
			binding,
			overlay,
			manifest,
		)
	if err != nil {
		return fail(ErrProtocol)
	}
	if _, err := digestPinnedExecutable(
		overlay.Commands.HostRuntimeBinary,
	); err != nil {
		return fail(ErrProtocol)
	}

	commandRunner := hostruntime.NewExecCommandRunner()
	commandRunner.StdoutLimit = maximumDockerRootOutputBytes
	commandRunner.StderrLimit = maximumDockerRootOutputBytes
	artifacts, err := NewReleaseArtifactVerifier(
		overlay.Commands.DockerBinary,
		commandRunner,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	storage, err := NewSystemStorageProbe(ctx, overlay, commandRunner)
	if err != nil {
		return fail(ErrProtocol)
	}
	availability, err := storage.Snapshot(ctx)
	if err != nil {
		return fail(ErrProtocol)
	}
	layout, err :=
		hostruntime.LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		return fail(ErrProtocol)
	}
	lifecycle, err := hostruntime.OpenLifecycleStoreLayout(
		layout,
		bootstrapLifecycle,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.lifecycle = lifecycle
	reservation, err := selectGreenfieldReservation(
		lifecycle,
		binding,
		priorManifest,
		manifest,
		func() (hostruntime.StorageReservation, error) {
			return BuildStorageReservation(
				binding,
				overlay,
				manifest,
				availability,
				time.Now().UTC(),
			)
		},
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	storageAuthority, err := NewReservationStorageAuthority(storage)
	if err != nil ||
		storageAuthority.Revalidate(ctx, reservation.persisted) != nil {
		return fail(ErrProtocol)
	}

	pollInterval, err := time.ParseDuration(
		overlay.Fence.LockPollInterval,
	)
	if err != nil || pollInterval <= 0 || pollInterval > time.Second {
		return fail(ErrProtocol)
	}
	fence, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             overlay.Paths.FenceRoot,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: pollInterval,
	})
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.fence = fence
	fenceSnapshot, fencePresent, err := fence.InspectOptional(ctx)
	if err != nil {
		return fail(ErrProtocol)
	}
	current, currentPresent, err := releases.Current()
	if err != nil {
		return fail(ErrProtocol)
	}
	switch *binding.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		if !reservation.continuationPresent &&
			(fencePresent || currentPresent) {
			return fail(ErrProtocol)
		}
	case hostruntime.InstallDispositionUpgradePortable:
		if !fencePresent ||
			fenceSnapshot.Header.Generation != binding.ExpectedGeneration ||
			fenceSnapshot.Header.ActiveFleet != fleetfence.FleetPortable ||
			!currentPresent ||
			(current.manifestDigest != *binding.PriorManifestDigest &&
				current.manifestDigest != *binding.TargetManifestDigest) ||
			(!reservation.continuationPresent &&
				current.manifestDigest != *binding.PriorManifestDigest) {
			return fail(ErrProtocol)
		}
	default:
		return fail(ErrProtocol)
	}

	processStore, err := OpenProcessRecordStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.processStore = processStore
	_, _, processPresent, err := processStore.Read(ctx)
	if err != nil ||
		(!reservation.continuationPresent &&
			*binding.InstallDisposition ==
				hostruntime.InstallDispositionGreenfieldPortable &&
			processPresent) ||
		(!reservation.continuationPresent &&
			*binding.InstallDisposition ==
				hostruntime.InstallDispositionUpgradePortable &&
			!processPresent) {
		return fail(ErrProtocol)
	}
	kernel, err := NewSystemProcessKernel()
	if err != nil {
		return fail(ErrProtocol)
	}
	processGrace, err := time.ParseDuration(
		overlay.Watchdog.ProcessGrace,
	)
	if err != nil || processGrace <= 0 {
		return fail(ErrProtocol)
	}
	newAuthority := func(
		boundOverlay hostruntime.PrivateOverlay,
		boundRevision string,
		boundManifest hostruntime.RuntimeManifest,
		boundDigest string,
	) (*ProcessAuthority, string, error) {
		releaseOverlayPath := filepath.Join(
			boundOverlay.Paths.ReleaseRoot,
			boundDigest,
			releaseOverlayName,
		)
		controllerDigest, err := digestPinnedExecutable(
			boundOverlay.Commands.ControllerBinary,
		)
		if err != nil || controllerDigest != boundManifest.ControllerSHA256 {
			return nil, "", ErrProtocol
		}
		authority, err := NewProcessAuthority(ProcessAuthorityConfig{
			Store:  processStore,
			Kernel: kernel,
			Binding: ProcessBinding{
				PrivateOverlayRevision: boundRevision,
				ManifestDigest:         boundDigest,
				ActiveFleet:            fleetfence.FleetPortable,
				FenceGeneration:        boundManifest.FleetGeneration,
			},
			Launch: ControllerLaunch{
				ControllerBinary: boundOverlay.Commands.ControllerBinary,
				PrivateOverlay:   releaseOverlayPath,
				DatabasePath:     boundOverlay.Paths.DatabasePath,
				StdoutLog: filepath.Join(
					boundOverlay.Paths.LogRoot,
					"controller.stdout.log",
				),
				StderrLog: filepath.Join(
					boundOverlay.Paths.LogRoot,
					"controller.stderr.log",
				),
				ExecutableDigest: controllerDigest,
			},
			Timing: ProcessTiming{
				PollInterval: pollInterval,
				TermGrace:    processGrace,
				KillGrace:    processGrace,
				CleanupGrace: processGrace,
			},
		})
		return authority, releaseOverlayPath, err
	}
	process, releaseOverlayPath, err := newAuthority(
		overlay,
		revision,
		manifest,
		manifestDigest,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	var priorProcess *ProcessAuthority
	var priorAdmin lifecycleControllerAdmin
	if priorManifest != nil && priorOverlay != nil {
		var priorOverlayPath string
		priorProcess, priorOverlayPath, err = newAuthority(
			*priorOverlay,
			priorRevision,
			*priorManifest,
			*binding.PriorManifestDigest,
		)
		if err != nil {
			return fail(ErrProtocol)
		}
		priorAdmin, err = NewSystemDisabledControllerProbe(
			priorOverlay.Commands.ControllerBinary,
			priorOverlayPath,
		)
		if err != nil {
			return fail(ErrProtocol)
		}
	}

	watchdog, err := openWatchdogMarkerStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.watchdog = watchdog
	targetWatchdogBinding := watchdogMarkerBinding{
		PrivateOverlayRevision: revision,
		ManifestDigest:         manifestDigest,
		WatchdogBinary:         overlay.Commands.WatchdogBinary,
	}
	if priorOverlay == nil {
		if _, present, err := watchdog.Inspect(
			targetWatchdogBinding,
		); err != nil || (!reservation.continuationPresent && present) {
			return fail(ErrProtocol)
		}
	} else {
		priorWatchdogBinding := watchdogMarkerBinding{
			PrivateOverlayRevision: priorRevision,
			ManifestDigest:         *binding.PriorManifestDigest,
			WatchdogBinary:         priorOverlay.Commands.WatchdogBinary,
		}
		_, matched, present, err := watchdog.InspectOneOf(
			priorWatchdogBinding,
			targetWatchdogBinding,
		)
		if err != nil ||
			!present ||
			(!reservation.continuationPresent && matched != 0) {
			return fail(ErrProtocol)
		}
	}

	docker, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    overlay.Commands.DockerBinary,
			BrokerRoot:    overlay.Paths.BrokerRoot,
			SeccompRoot:   overlay.Paths.SeccompRoot,
			BrokerNetwork: overlay.Docker.BrokerNetworkID,
		},
		commandRunner,
	)
	if err != nil ||
		(*binding.InstallDisposition ==
			hostruntime.InstallDispositionGreenfieldPortable &&
			docker.ProveManagedQuiescence(ctx) != nil) {
		return fail(ErrProtocol)
	}
	probe, err := NewSystemDisabledControllerProbe(
		overlay.Commands.ControllerBinary,
		releaseOverlayPath,
	)
	if err != nil {
		return fail(ErrProtocol)
	}

	backend := &productionLifecycleBackend{
		target: &greenfieldSystemTarget{
			disposition:    *binding.InstallDisposition,
			overlay:        overlay,
			revision:       revision,
			manifest:       manifest,
			manifestDigest: manifestDigest,
			terminalFence:  manifest.FleetGeneration,
			pollInterval:   pollInterval,
			now:            func() time.Time { return time.Now().UTC() },
			releases:       releases,
			fence:          fence,
			storage:        storage,
			docker:         docker,
			process:        process,
			priorProcess:   priorProcess,
			processStore:   processStore,
			watchdog:       watchdog,
			probe:          probe,
			priorAdmin:     priorAdmin,
			artifacts:      artifacts,
			priorOverlay:   priorOverlay,
			priorRevision:  priorRevision,
			priorManifestDigest: func() string {
				if binding.PriorManifestDigest == nil {
					return ""
				}
				return *binding.PriorManifestDigest
			}(),
		},
	}
	effects, err := NewLifecycleEffects(backend)
	if err != nil {
		return fail(ErrProtocol)
	}
	compensation, err :=
		hostruntime.NewLifecycleCompensationAuthority(lifecycle)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.engine = hostruntime.LifecycleEngine{
		Store:        lifecycle,
		Effects:      effects,
		Storage:      storageAuthority,
		Compensation: compensation,
		PollInterval: pollInterval,
		Now:          func() time.Time { return time.Now().UTC() },
	}
	request = hostruntime.LifecycleRequest{
		Binding:        binding,
		PriorManifest:  priorManifest,
		TargetManifest: &manifest,
		Reservation:    reservation.request,
	}
	return resources, request, nil
}

func (resources *greenfieldInstallResources) Close() error {
	if resources == nil {
		return nil
	}
	var result error
	if resources.lifecycle != nil {
		result = errors.Join(result, resources.lifecycle.Close())
		resources.lifecycle = nil
	}
	if resources.watchdog != nil {
		result = errors.Join(result, resources.watchdog.Close())
		resources.watchdog = nil
	}
	if resources.processStore != nil {
		result = errors.Join(result, resources.processStore.Close())
		resources.processStore = nil
	}
	if resources.fence != nil {
		result = errors.Join(result, resources.fence.Close())
		resources.fence = nil
	}
	if resources.releases != nil {
		result = errors.Join(result, resources.releases.Close())
		resources.releases = nil
	}
	return result
}

func (target *greenfieldSystemTarget) observe(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	effect productionEffect,
) (hostruntime.LifecycleEffectObservation, error) {
	if target == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		binding.Kind != hostruntime.OperationKindInstall ||
		binding.InstallDisposition == nil ||
		*binding.InstallDisposition != target.disposition ||
		(target.disposition !=
			hostruntime.InstallDispositionGreenfieldPortable &&
			target.disposition !=
				hostruntime.InstallDispositionUpgradePortable) {
		return hostruntime.LifecycleEffectObservation{},
			ErrLifecycleEffects
	}
	snapshot, err := target.snapshot(ctx, effect)
	if err != nil {
		return hostruntime.LifecycleEffectObservation{},
			errors.Join(ErrLifecycleEffects, err)
	}
	state := target.effectState(effect, snapshot)
	if state != hostruntime.LifecycleEffectPresent {
		return hostruntime.LifecycleEffectObservation{
			State: state,
		}, nil
	}
	postcondition, err := target.postcondition(
		binding,
		phase,
		snapshot,
	)
	if err != nil {
		return hostruntime.LifecycleEffectObservation{},
			errors.Join(ErrLifecycleEffects, err)
	}
	return hostruntime.LifecycleEffectObservation{
		State:         hostruntime.LifecycleEffectPresent,
		Postcondition: &postcondition,
	}, nil
}

func (target *greenfieldSystemTarget) effectState(
	effect productionEffect,
	snapshot greenfieldSnapshot,
) hostruntime.LifecycleEffectState {
	if target.effectPresent(effect, snapshot) {
		return hostruntime.LifecycleEffectPresent
	}
	if target.effectAbsent(effect, snapshot) {
		return hostruntime.LifecycleEffectAbsent
	}
	return hostruntime.LifecycleEffectAmbiguous
}

func (target *greenfieldSystemTarget) apply(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	effect productionEffect,
) error {
	if target == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		binding.Kind != hostruntime.OperationKindInstall {
		return ErrLifecycleEffects
	}
	switch effect {
	case effectCandidateStaged:
		if target.artifacts == nil || target.releases == nil {
			return ErrLifecycleEffects
		}
		images, err := target.artifacts.VerifyImages(ctx, target.overlay)
		if err != nil {
			return ErrLifecycleEffects
		}
		receipt, err := marshalImageVerificationReceipt(
			target.manifestDigest,
			target.revision,
			images,
		)
		if err != nil || validateImageVerificationReceipt(
			receipt,
			target.manifestDigest,
			target.revision,
			target.overlay.Docker,
		) != nil {
			return ErrLifecycleEffects
		}
		overlayDocument, revision, err :=
			hostruntime.MarshalPrivateOverlay(target.overlay)
		if err != nil || revision != target.revision {
			return ErrLifecycleEffects
		}
		manifestDocument, manifestDigest, err :=
			hostruntime.MarshalRuntimeManifest(target.manifest)
		if err != nil || manifestDigest != target.manifestDigest ||
			ctx.Err() != nil {
			return ErrLifecycleEffects
		}
		if err := target.releases.Stage(
			target.manifestDigest,
			target.revision,
			overlayDocument,
			manifestDocument,
		); err != nil || ctx.Err() != nil {
			return ErrLifecycleEffects
		}
		if err := target.releases.WriteStagedReceipt(
			target.manifestDigest,
			releaseImageVerificationReceiptName,
			receipt,
		); err != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectCandidateSmoked:
		if target.artifacts == nil || target.releases == nil ||
			target.verifyCandidateStage() != nil {
			return ErrLifecycleEffects
		}
		version, err := target.artifacts.SmokeRunner(ctx, target.overlay)
		if err != nil {
			return ErrLifecycleEffects
		}
		receipt, err := marshalRunnerSmokeReceipt(
			target.manifestDigest,
			target.revision,
			target.overlay.Docker.RunnerImage,
			version,
		)
		if err != nil || ctx.Err() != nil {
			return ErrLifecycleEffects
		}
		if err := target.releases.WriteStagedReceipt(
			target.manifestDigest,
			releaseRunnerSmokeReceiptName,
			receipt,
		); err != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectCandidatePromoted:
		return target.releases.Promote(
			target.manifestDigest,
			target.revision,
		)
	case effectFencePortable:
		if target.disposition !=
			hostruntime.InstallDispositionGreenfieldPortable {
			return ErrLifecycleEffects
		}
		request := fleetfence.HandoffRequest{
			From:               fleetfence.FleetNone,
			To:                 fleetfence.FleetPortable,
			ExpectedGeneration: 0,
		}
		request.OperationID = fleetfence.HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		)
		header, err := target.fence.Handoff(ctx, request)
		if err != nil ||
			header.Generation != target.terminalFence ||
			header.ActiveFleet != fleetfence.FleetPortable {
			return ErrLifecycleEffects
		}
		return nil
	case effectPriorAcquisitionDisabled:
		if target.disposition !=
			hostruntime.InstallDispositionUpgradePortable ||
			target.priorAdmin == nil {
			return ErrLifecycleEffects
		}
		status, err := target.priorAdmin.Disable(ctx)
		if err != nil ||
			status.Mode != controller.AcquisitionDisabled ||
			status.Capacity != 0 {
			return ErrLifecycleEffects
		}
		return nil
	case effectPriorDrained:
		if target.disposition !=
			hostruntime.InstallDispositionUpgradePortable ||
			target.priorAdmin == nil ||
			target.priorAdmin.Drain(ctx) != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectPriorControllerStopped:
		if target.disposition !=
			hostruntime.InstallDispositionUpgradePortable ||
			target.priorProcess == nil {
			return ErrLifecycleEffects
		}
		inspection, err := target.priorProcess.Inspect(ctx)
		if err != nil || inspection.State != ProcessRunning ||
			!lowerHexDigest(inspection.ProcessIdentity) ||
			target.priorProcess.Stop(
				ctx,
				inspection.ProcessIdentity,
			) != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectWatchdogInstalled:
		if target.disposition ==
			hostruntime.InstallDispositionUpgradePortable {
			if target.priorOverlay == nil {
				return ErrLifecycleEffects
			}
			return target.watchdog.Replace(
				watchdogMarkerBinding{
					PrivateOverlayRevision: target.priorRevision,
					ManifestDigest:         target.priorManifestDigest,
					WatchdogBinary:         target.priorOverlay.Commands.WatchdogBinary,
				},
				watchdogMarkerBinding{
					PrivateOverlayRevision: target.revision,
					ManifestDigest:         target.manifestDigest,
					WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
				},
			)
		}
		return target.watchdog.Install(watchdogMarkerBinding{
			PrivateOverlayRevision: target.revision,
			ManifestDigest:         target.manifestDigest,
			WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
		})
	case effectObserverStarted:
		inspection, err := target.process.StartDisabled(ctx)
		if err != nil ||
			inspection.State != ProcessRunning ||
			!lowerHexDigest(inspection.ProcessIdentity) {
			return ErrLifecycleEffects
		}
		return nil
	case effectZeroProven:
		return target.waitForZero(ctx)
	case effectCurrentSelected:
		return target.releases.Select(
			target.manifestDigest,
			target.revision,
		)
	default:
		return ErrLifecycleEffects
	}
}

func (target *greenfieldSystemTarget) verifyCandidateStage() error {
	if target == nil || target.releases == nil {
		return ErrLifecycleEffects
	}
	_, present, err := target.releases.InspectStaged(
		target.manifestDigest,
		target.revision,
	)
	if err != nil || !present {
		return ErrLifecycleEffects
	}
	document, present, err := target.releases.InspectStagedReceipt(
		target.manifestDigest,
		releaseImageVerificationReceiptName,
	)
	if err != nil || !present || validateImageVerificationReceipt(
		document,
		target.manifestDigest,
		target.revision,
		target.overlay.Docker,
	) != nil {
		return ErrLifecycleEffects
	}
	return nil
}

func (target *greenfieldSystemTarget) snapshot(
	ctx context.Context,
	effect productionEffect,
) (greenfieldSnapshot, error) {
	var snapshot greenfieldSnapshot
	if target == nil || ctx == nil || ctx.Err() != nil {
		return snapshot, ErrLifecycleEffects
	}
	header, fencePresent, err := target.fence.InspectOptional(ctx)
	if err != nil {
		return snapshot, ErrLifecycleEffects
	}
	snapshot.fencePresent = fencePresent
	snapshot.fleet = fleetfence.FleetNone
	if fencePresent {
		snapshot.generation = header.Header.Generation
		snapshot.fleet = header.Header.ActiveFleet
	}
	_, snapshot.stagedPresent, err = target.releases.InspectStaged(
		target.manifestDigest,
		target.revision,
	)
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	if snapshot.stagedPresent {
		verification, present, inspectErr :=
			target.releases.InspectStagedReceipt(
				target.manifestDigest,
				releaseImageVerificationReceiptName,
			)
		if inspectErr != nil {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		if present {
			if validateImageVerificationReceipt(
				verification,
				target.manifestDigest,
				target.revision,
				target.overlay.Docker,
			) != nil {
				return greenfieldSnapshot{}, ErrLifecycleEffects
			}
			snapshot.imagesVerified = true
		}
		smoke, present, inspectErr :=
			target.releases.InspectStagedReceipt(
				target.manifestDigest,
				releaseRunnerSmokeReceiptName,
			)
		if inspectErr != nil {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		if present {
			if validateRunnerSmokeReceipt(
				smoke,
				target.manifestDigest,
				target.revision,
				target.overlay.Docker.RunnerImage,
			) != nil {
				return greenfieldSnapshot{}, ErrLifecycleEffects
			}
			snapshot.runnerSmoked = true
		}
	}
	_, snapshot.releasedPresent, err =
		target.releases.InspectReleased(
			target.manifestDigest,
			target.revision,
		)
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	snapshot.current, snapshot.currentPresent, err =
		target.releases.Current()
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	targetWatchdog := watchdogMarkerBinding{
		PrivateOverlayRevision: target.revision,
		ManifestDigest:         target.manifestDigest,
		WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
	}
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		if target.priorOverlay == nil || target.priorProcess == nil {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		priorWatchdog := watchdogMarkerBinding{
			PrivateOverlayRevision: target.priorRevision,
			ManifestDigest:         target.priorManifestDigest,
			WatchdogBinary:         target.priorOverlay.Commands.WatchdogBinary,
		}
		var matched int
		snapshot.watchdog, matched, snapshot.watchdogPresent, err =
			target.watchdog.InspectOneOf(priorWatchdog, targetWatchdog)
		if err == nil && snapshot.watchdogPresent {
			snapshot.watchdogPrior = matched == 0
			snapshot.watchdogTarget = matched == 1
		}
	} else {
		snapshot.watchdog, snapshot.watchdogPresent, err =
			target.watchdog.Inspect(targetWatchdog)
		snapshot.watchdogTarget = snapshot.watchdogPresent
	}
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	record, identity, recordPresent, err := target.processStore.Read(ctx)
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	if recordPresent {
		var authority *ProcessAuthority
		switch {
		case target.priorProcess != nil &&
			processRecordMatchesBinding(record, target.priorProcess.binding):
			authority = target.priorProcess
			snapshot.processPrior = true
		case target.process != nil &&
			processRecordMatchesBinding(record, target.process.binding):
			authority = target.process
			snapshot.processTarget = true
		default:
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		inspection, inspectErr := authority.Inspect(ctx)
		if inspectErr != nil ||
			inspection.State != ProcessRunning ||
			identity != inspection.ProcessIdentity {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		snapshot.processPresent = true
		snapshot.processRecord = record
		snapshot.processIdentity = identity
	}
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		status, summary, inspectErr := target.inspectDurableState(ctx)
		if inspectErr != nil {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		snapshot.priorPolicy = status
		snapshot.policyEpoch = status.Epoch
		snapshot.assignedJobs = summary.AssignedJobs
		snapshot.runningJobs = summary.RunningJobs
		snapshot.activeListeners = summary.UnassignedReleasedListeners
		snapshot.priorDrained = summary.RunningJobs == 0 &&
			summary.UnassignedReleasedListeners == 0
		if snapshot.processPrior {
			live, liveErr := target.priorAdmin.Policy(ctx)
			if liveErr != nil || live != status {
				return greenfieldSnapshot{}, ErrLifecycleEffects
			}
		}
	}
	if target.effectRequiresManagedQuiescence(effect) {
		if err := target.docker.ProveManagedQuiescence(ctx); err != nil {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
	}
	availability, err := target.storage.Snapshot(ctx)
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	snapshot.filesystems = make(
		[]hostruntime.LifecycleFilesystemIdentity,
		len(availability),
	)
	for index, observation := range availability {
		snapshot.filesystems[index] = observation.Filesystem
	}
	if snapshot.policyEpoch == 0 {
		snapshot.policyEpoch = target.overlay.Resources.PolicyRevision
	}
	requireZeroProbe := effect == effectZeroProven ||
		effect == effectCurrentSelected ||
		effect == effectVerified
	if requireZeroProbe {
		if !snapshot.processTarget {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		observation, observeErr := observeDisabledZero(ctx, target.probe)
		if observeErr != nil {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		if target.disposition ==
			hostruntime.InstallDispositionUpgradePortable &&
			(observation.PolicyEpoch != snapshot.priorPolicy.Epoch ||
				observation.PolicyDigest != snapshot.priorPolicy.Digest ||
				snapshot.priorPolicy.Mode != controller.AcquisitionDisabled ||
				snapshot.priorPolicy.Capacity != 0) {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		snapshot.zero = true
		snapshot.policyEpoch = observation.PolicyEpoch
	}
	return snapshot, nil
}

func (target *greenfieldSystemTarget) inspectDurableState(
	ctx context.Context,
) (controller.PolicyStatus, state.OperationalSummary, error) {
	var empty state.OperationalSummary
	limits, err := lifecycleHistoryLimits(target.overlay.Resources.History)
	if err != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	store, err := state.OpenReadOnlyWithHistoryLimits(
		target.overlay.Paths.DatabasePath,
		limits,
	)
	if err != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	policy, policyErr := store.AcquisitionPolicy(ctx)
	summary, summaryErr := store.OperationalSummary(ctx, target.now())
	closeErr := store.Close()
	if policyErr != nil || summaryErr != nil || closeErr != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	canonical, err := controller.CanonicalizeAcquisitionPolicy(policy)
	if err != nil || canonical.Epoch == 0 {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	digest, err := controller.AcquisitionPolicyDigest(canonical)
	if err != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	status := controller.PolicyStatus{
		Mode:     canonical.Mode,
		Epoch:    canonical.Epoch,
		Digest:   hex.EncodeToString(digest[:]),
		Capacity: canonical.MaxCapacity,
	}
	if !validControllerPolicyStatus(status) {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	return status, summary, nil
}

func lifecycleHistoryLimits(
	history hostruntime.HistoryOverlay,
) (state.HistoryLimits, error) {
	minRetention, err := time.ParseDuration(history.MinRetention)
	if err != nil {
		return state.HistoryLimits{}, ErrLifecycleEffects
	}
	maintenanceCadence, err := time.ParseDuration(history.MaintenanceCadence)
	if err != nil {
		return state.HistoryLimits{}, ErrLifecycleEffects
	}
	limits := state.HistoryLimits{
		MinRetention:                 minRetention,
		MaxHistoryRows:               history.MaxHistoryRows,
		MaxHistoryLogicalBytes:       history.MaxHistoryLogicalBytes,
		MaxNetworkLedgerRows:         history.MaxNetworkLedgerRows,
		MaxNetworkLedgerLogicalBytes: history.MaxNetworkLedgerLogicalBytes,
		InflightReserveRows:          history.InflightReserveRows,
		InflightReserveLogicalBytes:  history.InflightReserveLogicalBytes,
		GCBatchRows:                  history.GCBatchRows,
		NetworkGCBatchRows:           history.NetworkGCBatchRows,
		VacuumBatchPages:             history.VacuumBatchPages,
		MaintenanceCadence:           maintenanceCadence,
	}
	if state.ValidateHistoryLimits(limits) != nil {
		return state.HistoryLimits{}, ErrLifecycleEffects
	}
	return limits, nil
}

func (target *greenfieldSystemTarget) effectRequiresManagedQuiescence(
	effect productionEffect,
) bool {
	if target.disposition ==
		hostruntime.InstallDispositionGreenfieldPortable {
		return true
	}
	switch effect {
	case effectPriorQuiescenceProven,
		effectFencePortableProven,
		effectWatchdogInstalled,
		effectPolicyDisabled,
		effectObserverStarted,
		effectZeroProven,
		effectCurrentSelected,
		effectVerified:
		return true
	default:
		return false
	}
}

func observeDisabledZero(
	ctx context.Context,
	probe DisabledControllerProbe,
) (DisabledControllerObservation, error) {
	if ctx == nil || ctx.Err() != nil || probe == nil {
		return DisabledControllerObservation{}, ErrLifecycleEffects
	}
	return probe.Observe(ctx)
}

func activeReservationView(
	persisted hostruntime.StorageReservation,
) (hostruntime.StorageReservation, error) {
	if _, _, err := hostruntime.MarshalStorageReservation(persisted); err != nil {
		return hostruntime.StorageReservation{}, ErrLifecycleEffects
	}
	view := persisted
	view.State = hostruntime.ReservationStateActive
	view.CommittedTargetProofDigest = nil
	view.ReleasedAbsenceProofDigest = nil
	if _, _, err := hostruntime.MarshalStorageReservation(view); err != nil {
		return hostruntime.StorageReservation{}, ErrLifecycleEffects
	}
	return view, nil
}

type greenfieldContinuation struct {
	journal     hostruntime.OperationJournal
	reservation hostruntime.StorageReservation
}

type greenfieldReservationChoice struct {
	persisted           hostruntime.StorageReservation
	request             hostruntime.StorageReservation
	continuation        greenfieldContinuation
	continuationPresent bool
}

type greenfieldReservationBuilder func() (
	hostruntime.StorageReservation,
	error,
)

func selectGreenfieldReservation(
	store *hostruntime.LifecycleStore,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
	buildFresh greenfieldReservationBuilder,
) (greenfieldReservationChoice, error) {
	if buildFresh == nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	continuation, present, err := readGreenfieldContinuation(
		store,
		binding,
		priorManifest,
		manifest,
	)
	if err != nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	if present {
		request, err := activeReservationView(continuation.reservation)
		if err != nil {
			return greenfieldReservationChoice{}, ErrLifecycleEffects
		}
		return greenfieldReservationChoice{
			persisted:           continuation.reservation,
			request:             request,
			continuation:        continuation,
			continuationPresent: true,
		}, nil
	}
	fresh, err := buildFresh()
	if err != nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	if fresh.State != hostruntime.ReservationStateActive ||
		validateGreenfieldReservation(fresh, binding, manifest) != nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	return greenfieldReservationChoice{
		persisted: fresh,
		request:   fresh,
	}, nil
}

func readGreenfieldContinuation(
	store *hostruntime.LifecycleStore,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) (greenfieldContinuation, bool, error) {
	if store == nil ||
		binding.InstallDisposition == nil ||
		binding.TargetManifestDigest == nil ||
		binding.TargetFleet != fleetfence.FleetPortable {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil || manifestDigest != *binding.TargetManifestDigest {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	if priorManifest == nil && binding.PriorManifestDigest != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	if priorManifest != nil {
		_, priorDigest, err := hostruntime.MarshalRuntimeManifest(*priorManifest)
		if err != nil ||
			binding.PriorManifestDigest == nil ||
			priorDigest != *binding.PriorManifestDigest {
			return greenfieldContinuation{}, false, ErrLifecycleEffects
		}
	}
	journalDocument, journalErr := store.ReadCanonical(
		hostruntime.LifecycleJournals,
		binding.OperationID+".journal.json",
		maximumProductionLifecycleJournalBytes,
	)
	reservationDocument, reservationErr := store.ReadCanonical(
		hostruntime.LifecycleReservations,
		binding.OperationID+".reservation.json",
		maximumProductionLifecycleReservationBytes,
	)
	journalAbsent := errors.Is(
		journalErr,
		hostruntime.ErrLifecycleStateAbsent,
	)
	reservationAbsent := errors.Is(
		reservationErr,
		hostruntime.ErrLifecycleStateAbsent,
	)
	if journalAbsent && reservationAbsent {
		return greenfieldContinuation{}, false, nil
	}
	if journalErr != nil || reservationErr != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	journal, _, err := hostruntime.ParseOperationJournal(
		journalDocument,
		maximumProductionLifecycleJournalBytes,
	)
	if err != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	reservation, _, err := hostruntime.ParseStorageReservation(
		reservationDocument,
		maximumProductionLifecycleReservationBytes,
	)
	continuation := greenfieldContinuation{
		journal:     journal,
		reservation: reservation,
	}
	if err != nil || validateGreenfieldContinuation(
		continuation,
		binding,
		priorManifest,
		manifest,
	) != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	return continuation, true, nil
}

func validateGreenfieldContinuation(
	continuation greenfieldContinuation,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) error {
	if hostruntime.ValidateOperationJournalAgainstBinding(
		continuation.journal,
		binding,
	) != nil || !manifestPointersEqualForLifecycle(
		continuation.journal.PriorManifest,
		priorManifest,
	) || validateGreenfieldReservation(
		continuation.reservation,
		binding,
		manifest,
	) != nil {
		return ErrLifecycleEffects
	}
	if continuation.journal.CompensationPath != nil {
		return ErrLifecycleEffects
	}
	if continuation.journal.Phase == hostruntime.OperationPhaseComplete {
		if continuation.reservation.State !=
			hostruntime.ReservationStateActive &&
			continuation.reservation.State !=
				hostruntime.ReservationStateCommitted {
			return ErrLifecycleEffects
		}
		return nil
	}
	if continuation.reservation.State !=
		hostruntime.ReservationStateActive {
		return ErrLifecycleEffects
	}
	return nil
}

func manifestPointersEqualForLifecycle(
	left *hostruntime.RuntimeManifest,
	right *hostruntime.RuntimeManifest,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftDocument, leftDigest, leftErr :=
		hostruntime.MarshalRuntimeManifest(*left)
	rightDocument, rightDigest, rightErr :=
		hostruntime.MarshalRuntimeManifest(*right)
	return leftErr == nil &&
		rightErr == nil &&
		leftDigest == rightDigest &&
		string(leftDocument) == string(rightDocument)
}

func validateGreenfieldReservation(
	reservation hostruntime.StorageReservation,
	binding hostruntime.OperationBinding,
	manifest hostruntime.RuntimeManifest,
) error {
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		return ErrLifecycleEffects
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil ||
		reservation.OperationID != binding.OperationID ||
		reservation.BindingDigest != bindingDigest ||
		reservation.TargetManifestDigest == nil ||
		*reservation.TargetManifestDigest != manifestDigest ||
		reservation.StorageBudgetDigest != manifest.StorageBudgetDigest {
		return ErrLifecycleEffects
	}
	if _, _, err := hostruntime.MarshalStorageReservation(
		reservation,
	); err != nil {
		return ErrLifecycleEffects
	}
	return nil
}

func verifyGreenfieldTerminal(
	ctx context.Context,
	store *hostruntime.LifecycleStore,
	effects hostruntime.LifecycleEffectAuthority,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || store == nil || effects == nil {
		return "", "", ErrLifecycleEffects
	}
	continuation, present, err := readGreenfieldContinuation(
		store,
		binding,
		priorManifest,
		manifest,
	)
	if err != nil ||
		!present ||
		continuation.journal.Phase !=
			hostruntime.OperationPhaseComplete ||
		continuation.reservation.State !=
			hostruntime.ReservationStateCommitted ||
		continuation.reservation.CommittedTargetProofDigest == nil {
		return "", "", ErrLifecycleEffects
	}
	_, journalDigest, err := hostruntime.MarshalOperationJournal(
		continuation.journal,
	)
	if err != nil {
		return "", "", ErrLifecycleEffects
	}
	effectKey, err := hostruntime.DeriveOperationEffectKey(
		binding,
		hostruntime.OperationPhaseComplete,
	)
	if err != nil {
		return "", "", ErrLifecycleEffects
	}
	document, err := store.ReadCanonical(
		hostruntime.LifecycleReceipts,
		effectKey+".postcondition.json",
		maximumProductionLifecyclePostconditionBytes,
	)
	if err != nil {
		return "", "", ErrLifecycleEffects
	}
	persisted, proofDigest, err := hostruntime.ParseTargetPostcondition(
		document,
		maximumProductionLifecyclePostconditionBytes,
	)
	if err != nil ||
		hostruntime.ValidateTargetPostconditionAgainstBinding(
			persisted,
			binding,
			hostruntime.OperationPhaseComplete,
		) != nil ||
		*continuation.reservation.CommittedTargetProofDigest != proofDigest {
		return "", "", ErrLifecycleEffects
	}
	observation, err := effects.Observe(
		ctx,
		binding,
		hostruntime.OperationPhaseComplete,
	)
	if err != nil ||
		observation.State != hostruntime.LifecycleEffectPresent ||
		observation.Postcondition == nil ||
		hostruntime.ValidateTargetPostconditionAgainstBinding(
			*observation.Postcondition,
			binding,
			hostruntime.OperationPhaseComplete,
		) != nil {
		return "", "", ErrLifecycleEffects
	}
	live := *observation.Postcondition
	live.ObservedAt = persisted.ObservedAt
	_, liveDigest, err := hostruntime.MarshalTargetPostcondition(live)
	if err != nil || liveDigest != proofDigest {
		return "", "", ErrLifecycleEffects
	}
	return journalDigest, proofDigest, nil
}

func (target *greenfieldSystemTarget) effectPresent(
	effect productionEffect,
	snapshot greenfieldSnapshot,
) bool {
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		return target.upgradeEffectPresent(effect, snapshot)
	}
	baseline := !snapshot.fencePresent &&
		snapshot.generation == 0 &&
		snapshot.fleet == fleetfence.FleetNone &&
		!snapshot.currentPresent &&
		!snapshot.watchdogPresent &&
		!snapshot.processPresent
	switch effect {
	case effectPreflight:
		return baseline &&
			target.candidateClean(snapshot)
	case effectCandidateStaged:
		return baseline &&
			target.candidateVerified(snapshot)
	case effectCandidateSmoked:
		return baseline &&
			target.candidateSmoked(snapshot) &&
			!snapshot.releasedPresent
	case effectCandidatePromoted:
		return baseline &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectGreenfieldProven:
		return baseline &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectFencePortable:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			!snapshot.watchdogPresent &&
			!snapshot.processPresent &&
			snapshot.releasedPresent
	case effectWatchdogInstalled, effectPolicyDisabled:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			!snapshot.processPresent &&
			snapshot.releasedPresent &&
			target.overlay.Policy.AcquisitionDefault == "disabled"
	case effectObserverStarted:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent
	case effectZeroProven:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent &&
			snapshot.zero
	case effectCurrentSelected, effectVerified:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			snapshot.currentPresent &&
			snapshot.current.manifestDigest ==
				target.manifestDigest &&
			snapshot.current.overlayRevision ==
				target.revision &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent &&
			snapshot.zero
	default:
		return false
	}
}

func (target *greenfieldSystemTarget) effectAbsent(
	effect productionEffect,
	snapshot greenfieldSnapshot,
) bool {
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		return target.upgradeEffectAbsent(effect, snapshot)
	}
	baseline := !snapshot.fencePresent &&
		snapshot.generation == 0 &&
		snapshot.fleet == fleetfence.FleetNone &&
		!snapshot.currentPresent &&
		!snapshot.watchdogPresent &&
		!snapshot.processPresent
	portable := snapshot.fencePresent &&
		snapshot.generation == target.terminalFence &&
		snapshot.fleet == fleetfence.FleetPortable &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		!snapshot.currentPresent
	switch effect {
	case effectCandidateStaged:
		return baseline && target.candidateStageAbsent(snapshot)
	case effectCandidateSmoked:
		return baseline && target.candidateVerified(snapshot)
	case effectCandidatePromoted:
		return baseline &&
			target.artifactsReady(snapshot) &&
			!snapshot.releasedPresent
	case effectFencePortable:
		return baseline &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectWatchdogInstalled:
		return portable &&
			!snapshot.watchdogPresent &&
			!snapshot.processPresent
	case effectObserverStarted:
		return portable &&
			snapshot.watchdogPresent &&
			!snapshot.processPresent
	case effectCurrentSelected:
		return portable &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.zero
	default:
		return false
	}
}

func (target *greenfieldSystemTarget) upgradeEffectPresent(
	effect productionEffect,
	snapshot greenfieldSnapshot,
) bool {
	priorServing := target.upgradePriorServing(snapshot)
	priorStopped := target.upgradePriorStopped(snapshot)
	targetStopped := target.upgradeTargetStopped(snapshot)
	targetRunningPriorSelected := target.upgradeTargetRunning(
		snapshot,
		false,
	)
	targetRunningSelected := target.upgradeTargetRunning(
		snapshot,
		true,
	)
	switch effect {
	case effectPreflight:
		return priorServing && target.candidateClean(snapshot)
	case effectCandidateStaged:
		return priorServing && target.candidateVerified(snapshot)
	case effectCandidateSmoked:
		return priorServing &&
			target.candidateSmoked(snapshot) &&
			!snapshot.releasedPresent
	case effectCandidatePromoted, effectUpgradeProven:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectPriorAcquisitionDisabled:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0
	case effectPriorDrained:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0 &&
			snapshot.priorDrained
	case effectPriorControllerStopped,
		effectPriorQuiescenceProven,
		effectFencePortableProven:
		return priorStopped
	case effectWatchdogInstalled, effectPolicyDisabled:
		return targetStopped &&
			target.overlay.Policy.AcquisitionDefault == "disabled"
	case effectObserverStarted:
		return targetRunningPriorSelected
	case effectZeroProven:
		return targetRunningPriorSelected && snapshot.zero
	case effectCurrentSelected, effectVerified:
		return targetRunningSelected && snapshot.zero
	default:
		return false
	}
}

func (target *greenfieldSystemTarget) upgradeEffectAbsent(
	effect productionEffect,
	snapshot greenfieldSnapshot,
) bool {
	priorServing := target.upgradePriorServing(snapshot)
	priorStopped := target.upgradePriorStopped(snapshot)
	targetStopped := target.upgradeTargetStopped(snapshot)
	targetRunningPriorSelected := target.upgradeTargetRunning(
		snapshot,
		false,
	)
	switch effect {
	case effectCandidateStaged:
		return priorServing && target.candidateStageAbsent(snapshot)
	case effectCandidateSmoked:
		return priorServing && target.candidateVerified(snapshot)
	case effectCandidatePromoted:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			!snapshot.releasedPresent
	case effectPriorAcquisitionDisabled:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			(snapshot.priorPolicy.Mode == controller.AcquisitionEnabled ||
				snapshot.priorPolicy.Mode == controller.AcquisitionCanaryOnly)
	case effectPriorDrained:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0 &&
			!snapshot.priorDrained
	case effectPriorControllerStopped:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0 &&
			snapshot.priorDrained
	case effectWatchdogInstalled:
		return priorStopped
	case effectObserverStarted:
		return targetStopped
	case effectCurrentSelected:
		return targetRunningPriorSelected && snapshot.zero
	default:
		return false
	}
}

func (target *greenfieldSystemTarget) upgradePriorServing(
	snapshot greenfieldSnapshot,
) bool {
	return target.upgradeCommon(snapshot) &&
		target.currentMatches(
			snapshot,
			target.priorManifestDigest,
			target.priorRevision,
		) &&
		snapshot.watchdogPresent &&
		snapshot.watchdogPrior &&
		!snapshot.watchdogTarget &&
		snapshot.processPresent &&
		snapshot.processPrior &&
		!snapshot.processTarget
}

func (target *greenfieldSystemTarget) upgradePriorStopped(
	snapshot greenfieldSnapshot,
) bool {
	return target.upgradeCommon(snapshot) &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		target.currentMatches(
			snapshot,
			target.priorManifestDigest,
			target.priorRevision,
		) &&
		snapshot.watchdogPresent &&
		snapshot.watchdogPrior &&
		!snapshot.watchdogTarget &&
		!snapshot.processPresent &&
		!snapshot.processPrior &&
		!snapshot.processTarget &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *greenfieldSystemTarget) upgradeTargetStopped(
	snapshot greenfieldSnapshot,
) bool {
	return target.upgradeCommon(snapshot) &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		target.currentMatches(
			snapshot,
			target.priorManifestDigest,
			target.priorRevision,
		) &&
		snapshot.watchdogPresent &&
		!snapshot.watchdogPrior &&
		snapshot.watchdogTarget &&
		!snapshot.processPresent &&
		!snapshot.processPrior &&
		!snapshot.processTarget &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *greenfieldSystemTarget) upgradeTargetRunning(
	snapshot greenfieldSnapshot,
	selected bool,
) bool {
	digest := target.priorManifestDigest
	revision := target.priorRevision
	if selected {
		digest = target.manifestDigest
		revision = target.revision
	}
	return target.upgradeCommon(snapshot) &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		target.currentMatches(snapshot, digest, revision) &&
		snapshot.watchdogPresent &&
		!snapshot.watchdogPrior &&
		snapshot.watchdogTarget &&
		snapshot.processPresent &&
		!snapshot.processPrior &&
		snapshot.processTarget &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *greenfieldSystemTarget) upgradeCommon(
	snapshot greenfieldSnapshot,
) bool {
	return snapshot.fencePresent &&
		snapshot.generation == target.terminalFence &&
		snapshot.fleet == fleetfence.FleetPortable
}

func (target *greenfieldSystemTarget) candidateClean(
	snapshot greenfieldSnapshot,
) bool {
	return !snapshot.stagedPresent &&
		!snapshot.imagesVerified &&
		!snapshot.runnerSmoked &&
		!snapshot.releasedPresent
}

func (target *greenfieldSystemTarget) candidateVerified(
	snapshot greenfieldSnapshot,
) bool {
	return snapshot.stagedPresent &&
		snapshot.imagesVerified &&
		!snapshot.runnerSmoked &&
		!snapshot.releasedPresent
}

func (target *greenfieldSystemTarget) candidateStageAbsent(
	snapshot greenfieldSnapshot,
) bool {
	return !snapshot.imagesVerified &&
		!snapshot.runnerSmoked &&
		!snapshot.releasedPresent
}

func (target *greenfieldSystemTarget) candidateSmoked(
	snapshot greenfieldSnapshot,
) bool {
	return target.artifactsReady(snapshot)
}

func (target *greenfieldSystemTarget) artifactsReady(
	snapshot greenfieldSnapshot,
) bool {
	return snapshot.stagedPresent &&
		snapshot.imagesVerified &&
		snapshot.runnerSmoked
}

func (target *greenfieldSystemTarget) currentMatches(
	snapshot greenfieldSnapshot,
	manifestDigest string,
	overlayRevision string,
) bool {
	return snapshot.currentPresent &&
		snapshot.current.manifestDigest == manifestDigest &&
		snapshot.current.overlayRevision == overlayRevision
}

func (target *greenfieldSystemTarget) postcondition(
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	snapshot greenfieldSnapshot,
) (hostruntime.TargetPostcondition, error) {
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	}
	effectKey, err :=
		hostruntime.DeriveOperationEffectKey(binding, phase)
	if err != nil {
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	}
	artifacts := []hostruntime.ArtifactProjection{}
	if snapshot.watchdogPresent {
		artifacts = append(artifacts, snapshot.watchdog)
	}
	processes := []hostruntime.ProcessProjection{}
	if snapshot.processPresent {
		role := "disabled-observer"
		acquisitionCapable := false
		if snapshot.processPrior {
			role = "prior-controller"
			acquisitionCapable =
				snapshot.priorPolicy.Mode == controller.AcquisitionEnabled ||
					snapshot.priorPolicy.Mode == controller.AcquisitionCanaryOnly
		}
		processes = append(processes, hostruntime.ProcessProjection{
			Role:               role,
			PID:                snapshot.processRecord.PID,
			StartIdentity:      snapshot.processIdentity,
			ExecutableDigest:   snapshot.processRecord.ExecutableDigest,
			AcquisitionCapable: acquisitionCapable,
		})
	}
	policyManifestDigest := target.overlay.Policy.ManifestDigest
	if snapshot.watchdogPrior && target.priorOverlay != nil {
		policyManifestDigest = target.priorOverlay.Policy.ManifestDigest
	}
	acquisitionEnabled :=
		snapshot.priorPolicy.Mode == controller.AcquisitionEnabled ||
			snapshot.priorPolicy.Mode == controller.AcquisitionCanaryOnly
	controllerProcesses := uint64(0)
	if snapshot.processPresent {
		controllerProcesses = 1
	}
	postcondition := hostruntime.TargetPostcondition{
		SchemaVersion:          1,
		OperationID:            binding.OperationID,
		BindingDigest:          bindingDigest,
		EffectKey:              effectKey,
		Phase:                  phase,
		ManifestDigest:         binding.TargetManifestDigest,
		PrivateOverlayRevision: binding.PrivateOverlayRevision,
		FenceGeneration:        snapshot.generation,
		ActiveFleet:            snapshot.fleet,
		Filesystems:            snapshot.filesystems,
		Artifacts:              artifacts,
		Processes:              processes,
		Policy: hostruntime.PolicyProjection{
			PolicyManifestDigest: policyManifestDigest,
			TransitionEpoch:      snapshot.policyEpoch,
			AcquisitionEnabled:   acquisitionEnabled,
			PendingAcquisitions:  snapshot.activeListeners,
			ActiveListeners:      snapshot.activeListeners,
		},
		Quiescence: hostruntime.QuiescenceProjection{
			ControllerProcesses: controllerProcesses,
			RunnerProcesses:     snapshot.runningJobs,
			PendingAcquisitions: snapshot.activeListeners,
		},
		ObservedAt: target.now(),
	}
	if snapshot.currentPresent {
		selection := snapshot.current.selection
		selection.FenceGeneration = snapshot.generation
		selection.ActiveFleet = snapshot.fleet
		postcondition.CurrentSelection = &selection
	}
	if _, _, err := hostruntime.MarshalTargetPostcondition(
		postcondition,
	); err != nil {
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	}
	return postcondition, nil
}

func (target *greenfieldSystemTarget) waitForZero(
	ctx context.Context,
) error {
	timer := time.NewTicker(target.pollInterval)
	defer timer.Stop()
	for {
		if _, err := target.probe.Observe(ctx); err == nil {
			if err := target.docker.ProveManagedQuiescence(ctx); err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ErrLifecycleEffects
		case <-timer.C:
		}
	}
}

func verifyInstalledTarget(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	sealedTarget, err := cli.SealTargetProof(target)
	if ctx == nil ||
		ctx.Err() != nil ||
		err != nil ||
		sealedTarget != target ||
		target.PrivateOverlayRevision != revision ||
		target.HostIdentityDigest != overlay.Target.HostIdentityDigest ||
		target.ControlIdentityDigest !=
			overlay.Target.ControlHostIdentityDigest ||
		target.FenceGeneration == 0 ||
		target.ActiveFleet != fleetfence.FleetPortable ||
		target.CurrentManifestDigest == nil ||
		*target.CurrentManifestDigest != arguments.ManifestDigest ||
		arguments.ManifestDigest != overlay.Manifest.Digest ||
		arguments.TargetProofDigest != target.ProofDigest ||
		!arguments.RequireZero ||
		!overlay.Resources.RunnerSizing.OperatorApproved {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	manifest, manifestDocument, manifestDigest, err :=
		loadPinnedTargetManifest(overlay.Manifest.Path)
	if err != nil ||
		len(manifestDocument) == 0 ||
		manifestDigest != arguments.ManifestDigest ||
		manifest.FleetGeneration != target.FenceGeneration ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	layout, err := hostruntime.LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	lookup, err := hostruntime.OpenLifecycleStoreLayout(layout, false)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	choice, present, selectErr := selectPortableInstallContinuation(
		lookup,
		revision,
		manifest,
	)
	lookupCloseErr := lookup.Close()
	if selectErr != nil ||
		lookupCloseErr != nil ||
		!present ||
		choice.continuation.journal.Phase !=
			hostruntime.OperationPhaseComplete ||
		choice.continuation.reservation.State !=
			hostruntime.ReservationStateCommitted ||
		!portableContinuationMatchesLiveState(
			choice.binding,
			choice.continuation.journal.Phase,
			target.CurrentManifestDigest,
		) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	resources, _, err := openInstallOperation(
		ctx,
		overlay,
		revision,
		manifest,
		manifestDigest,
		choice.binding,
		false,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	journalDigest, proofDigest, verifyErr := verifyGreenfieldTerminal(
		ctx,
		resources.lifecycle,
		resources.engine.Effects,
		choice.binding,
		choice.priorManifest,
		manifest,
	)
	closeErr := resources.Close()
	if verifyErr != nil || closeErr != nil {
		return hostruntime.HostActionResult{}, errors.Join(
			ErrProtocol,
			verifyErr,
			closeErr,
		)
	}
	operationID, generation, fleet, err := cli.ExpectedOperation(
		cli.ActionVerify,
		target,
		manifestDigest,
		revision,
	)
	if err != nil ||
		generation != manifest.FleetGeneration ||
		fleet != fleetfence.FleetPortable {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	result := hostruntime.HostActionResult{
		SchemaVersion:     1,
		Status:            hostruntime.HostActionComplete,
		OperationID:       operationID,
		JournalDigest:     journalDigest,
		TargetProofDigest: &proofDigest,
		FenceGeneration:   generation,
		ActiveFleet:       fleet,
	}
	if _, _, err := hostruntime.MarshalHostActionResult(result); err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	return result, nil
}

var _ LifecyclePhaseBackend = (*productionLifecycleBackend)(nil)
