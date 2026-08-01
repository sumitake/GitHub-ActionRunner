package productionruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
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
	overlay        hostruntime.PrivateOverlay
	revision       string
	manifest       hostruntime.RuntimeManifest
	manifestDigest string
	terminalFence  uint64
	pollInterval   time.Duration
	now            func() time.Time

	releases     *releaseBundleStore
	fence        *fleetfence.Store
	storage      *SystemStorageProbe
	docker       hostruntime.ManagedQuiescence
	process      *ProcessAuthority
	processStore *PinnedProcessRecordStore
	watchdog     *watchdogMarkerStore
	probe        DisabledControllerProbe
}

type greenfieldSnapshot struct {
	fencePresent bool
	generation   uint64
	fleet        fleetfence.Fleet

	stagedPresent   bool
	releasedPresent bool
	currentPresent  bool
	current         releaseBundleSnapshot

	watchdogPresent bool
	watchdog        hostruntime.ArtifactProjection
	processPresent  bool
	processRecord   ProcessRecord
	processIdentity string
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
		return invokeGreenfieldInstall(
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

func invokeGreenfieldInstall(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		target.InstallDisposition == nil ||
		*target.InstallDisposition !=
			hostruntime.InstallDispositionGreenfieldPortable ||
		target.FenceGeneration != 0 ||
		target.ActiveFleet != fleetfence.FleetNone ||
		target.CurrentManifestDigest != nil ||
		!overlay.Resources.RunnerSizing.OperatorApproved {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	manifest, manifestDocument, manifestDigest, err :=
		loadPinnedTargetManifest(overlay.Manifest.Path)
	if err != nil ||
		len(manifestDocument) == 0 ||
		manifestDigest != arguments.ManifestDigest ||
		manifestDigest != overlay.Manifest.Digest ||
		manifest.FleetGeneration != 1 ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	binding, terminalGeneration, err := fixedGreenfieldBinding(
		target,
		manifestDigest,
		revision,
	)
	if err != nil || terminalGeneration != manifest.FleetGeneration {
		return hostruntime.HostActionResult{}, ErrProtocol
	}

	resources, request, err := openGreenfieldOperation(
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

type greenfieldInstallResources struct {
	engine       hostruntime.LifecycleEngine
	lifecycle    *hostruntime.LifecycleStore
	releases     *releaseBundleStore
	fence        *fleetfence.Store
	processStore *PinnedProcessRecordStore
	watchdog     *watchdogMarkerStore
}

func openGreenfieldOperation(
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
	if _, present, err := releases.InspectStaged(
		manifestDigest,
		revision,
	); err != nil || !present {
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
	if _, present, err := fence.InspectOptional(ctx); err != nil ||
		(!reservation.continuationPresent && present) {
		return fail(ErrProtocol)
	}
	if _, present, err := releases.Current(); err != nil ||
		(!reservation.continuationPresent && present) {
		return fail(ErrProtocol)
	}

	processStore, err := OpenProcessRecordStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.processStore = processStore
	if _, _, present, err := processStore.Read(ctx); err != nil ||
		(!reservation.continuationPresent && present) {
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
	releaseOverlayPath := filepath.Join(
		overlay.Paths.ReleaseRoot,
		manifestDigest,
		releaseOverlayName,
	)
	controllerDigest, err := digestPinnedExecutable(
		overlay.Commands.ControllerBinary,
	)
	if err != nil ||
		controllerDigest != manifest.ControllerSHA256 {
		return fail(ErrProtocol)
	}
	process, err := NewProcessAuthority(ProcessAuthorityConfig{
		Store:  processStore,
		Kernel: kernel,
		Binding: ProcessBinding{
			PrivateOverlayRevision: revision,
			ManifestDigest:         manifestDigest,
			ActiveFleet:            fleetfence.FleetPortable,
			FenceGeneration:        manifest.FleetGeneration,
		},
		Launch: ControllerLaunch{
			ControllerBinary: overlay.Commands.ControllerBinary,
			PrivateOverlay:   releaseOverlayPath,
			DatabasePath:     overlay.Paths.DatabasePath,
			StdoutLog: filepath.Join(
				overlay.Paths.LogRoot,
				"controller.stdout.log",
			),
			StderrLog: filepath.Join(
				overlay.Paths.LogRoot,
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
	if err != nil {
		return fail(ErrProtocol)
	}

	watchdog, err := openWatchdogMarkerStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.watchdog = watchdog
	watchdogBinding := watchdogMarkerBinding{
		PrivateOverlayRevision: revision,
		ManifestDigest:         manifestDigest,
		WatchdogBinary:         overlay.Commands.WatchdogBinary,
	}
	if _, present, err := watchdog.Inspect(
		watchdogBinding,
	); err != nil || (!reservation.continuationPresent && present) {
		return fail(ErrProtocol)
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
	if err != nil || docker.ProveManagedQuiescence(ctx) != nil {
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
			processStore:   processStore,
			watchdog:       watchdog,
			probe:          probe,
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
		PriorManifest:  nil,
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
		*binding.InstallDisposition !=
			hostruntime.InstallDispositionGreenfieldPortable {
		return hostruntime.LifecycleEffectObservation{},
			ErrLifecycleEffects
	}
	snapshot, err := target.snapshot(
		ctx,
		effect >= effectZeroProven,
	)
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
	case effectCandidatePromoted:
		return target.releases.Promote(
			target.manifestDigest,
			target.revision,
		)
	case effectFencePortable:
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
	case effectWatchdogInstalled:
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

func (target *greenfieldSystemTarget) snapshot(
	ctx context.Context,
	requireZeroProbe bool,
) (greenfieldSnapshot, error) {
	var snapshot greenfieldSnapshot
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
	snapshot.watchdog, snapshot.watchdogPresent, err =
		target.watchdog.Inspect(watchdogMarkerBinding{
			PrivateOverlayRevision: target.revision,
			ManifestDigest:         target.manifestDigest,
			WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
		})
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	processInspection, err := target.process.Inspect(ctx)
	if err != nil && processInspection.State != ProcessAbsent {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	record, identity, recordPresent, err :=
		target.processStore.Read(ctx)
	if err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	switch processInspection.State {
	case ProcessAbsent:
		if recordPresent {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
	case ProcessRunning:
		if !recordPresent ||
			identity != processInspection.ProcessIdentity {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		snapshot.processPresent = true
		snapshot.processRecord = record
		snapshot.processIdentity = identity
	default:
		return greenfieldSnapshot{}, ErrLifecycleEffects
	}
	if err := target.docker.ProveManagedQuiescence(ctx); err != nil {
		return greenfieldSnapshot{}, ErrLifecycleEffects
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
	snapshot.policyEpoch = target.overlay.Resources.PolicyRevision
	if requireZeroProbe {
		if !snapshot.processPresent {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		observation, err := observeDisabledZero(ctx, target.probe)
		if err != nil {
			return greenfieldSnapshot{}, ErrLifecycleEffects
		}
		snapshot.zero = true
		snapshot.policyEpoch = observation.PolicyEpoch
	}
	return snapshot, nil
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
	manifest hostruntime.RuntimeManifest,
	buildFresh greenfieldReservationBuilder,
) (greenfieldReservationChoice, error) {
	if buildFresh == nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	continuation, present, err := readGreenfieldContinuation(
		store,
		binding,
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
	manifest hostruntime.RuntimeManifest,
) (greenfieldContinuation, bool, error) {
	if store == nil ||
		binding.InstallDisposition == nil ||
		*binding.InstallDisposition !=
			hostruntime.InstallDispositionGreenfieldPortable ||
		binding.ExpectedGeneration != 0 ||
		binding.PriorManifestDigest != nil ||
		binding.TargetManifestDigest == nil ||
		binding.TargetFleet != fleetfence.FleetPortable {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil || manifestDigest != *binding.TargetManifestDigest {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
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
		manifest,
	) != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	return continuation, true, nil
}

func validateGreenfieldContinuation(
	continuation greenfieldContinuation,
	binding hostruntime.OperationBinding,
	manifest hostruntime.RuntimeManifest,
) error {
	if hostruntime.ValidateOperationJournalAgainstBinding(
		continuation.journal,
		binding,
	) != nil || validateGreenfieldReservation(
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
	manifest hostruntime.RuntimeManifest,
) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || store == nil || effects == nil {
		return "", "", ErrLifecycleEffects
	}
	continuation, present, err := readGreenfieldContinuation(
		store,
		binding,
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
	baseline := !snapshot.fencePresent &&
		snapshot.generation == 0 &&
		snapshot.fleet == fleetfence.FleetNone &&
		!snapshot.currentPresent &&
		!snapshot.watchdogPresent &&
		!snapshot.processPresent
	switch effect {
	case effectPreflight:
		return baseline &&
			snapshot.stagedPresent &&
			!snapshot.releasedPresent
	case effectCandidateStaged, effectCandidateSmoked:
		return baseline &&
			snapshot.stagedPresent &&
			!snapshot.releasedPresent
	case effectCandidatePromoted:
		return baseline &&
			snapshot.stagedPresent &&
			snapshot.releasedPresent
	case effectGreenfieldProven:
		return baseline &&
			snapshot.stagedPresent &&
			snapshot.releasedPresent
	case effectFencePortable:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			snapshot.stagedPresent &&
			!snapshot.currentPresent &&
			!snapshot.watchdogPresent &&
			!snapshot.processPresent &&
			snapshot.releasedPresent
	case effectWatchdogInstalled, effectPolicyDisabled:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			snapshot.stagedPresent &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			!snapshot.processPresent &&
			snapshot.releasedPresent &&
			target.overlay.Policy.AcquisitionDefault == "disabled"
	case effectObserverStarted:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			snapshot.stagedPresent &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent
	case effectZeroProven:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			snapshot.stagedPresent &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent &&
			snapshot.zero
	case effectCurrentSelected, effectVerified:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			snapshot.stagedPresent &&
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
	baseline := !snapshot.fencePresent &&
		snapshot.generation == 0 &&
		snapshot.fleet == fleetfence.FleetNone &&
		!snapshot.currentPresent &&
		!snapshot.watchdogPresent &&
		!snapshot.processPresent
	portable := snapshot.fencePresent &&
		snapshot.generation == target.terminalFence &&
		snapshot.fleet == fleetfence.FleetPortable &&
		snapshot.stagedPresent &&
		snapshot.releasedPresent &&
		!snapshot.currentPresent
	switch effect {
	case effectCandidatePromoted:
		return baseline &&
			snapshot.stagedPresent &&
			!snapshot.releasedPresent
	case effectFencePortable:
		return baseline &&
			snapshot.stagedPresent &&
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
		processes = append(processes, hostruntime.ProcessProjection{
			Role:               "disabled-observer",
			PID:                snapshot.processRecord.PID,
			StartIdentity:      strconv.FormatUint(snapshot.processRecord.StartTimeTicks, 10),
			ExecutableDigest:   snapshot.processRecord.ExecutableDigest,
			AcquisitionCapable: false,
		})
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
			PolicyManifestDigest: target.overlay.Policy.ManifestDigest,
			TransitionEpoch:      snapshot.policyEpoch,
			AcquisitionEnabled:   false,
			PendingAcquisitions:  0,
			ActiveListeners:      0,
		},
		Quiescence: hostruntime.QuiescenceProjection{},
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
	entry, err := sealTargetProofForState(
		overlay,
		revision,
		hostTargetState{},
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	binding, terminalGeneration, err := fixedGreenfieldBinding(
		entry,
		manifestDigest,
		revision,
	)
	if err != nil || terminalGeneration != manifest.FleetGeneration {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	resources, _, err := openGreenfieldOperation(
		ctx,
		overlay,
		revision,
		manifest,
		manifestDigest,
		binding,
		false,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	journalDigest, proofDigest, verifyErr := verifyGreenfieldTerminal(
		ctx,
		resources.lifecycle,
		resources.engine.Effects,
		binding,
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
