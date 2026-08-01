package productionruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/watchdog"
)

var ErrSystemWatchdog = errors.New(
	"productionruntime: system watchdog failed",
)

type systemWatchdogLifecycleGate struct {
	store *hostruntime.LifecycleStore
}

func (gate *systemWatchdogLifecycleGate) Acquire(
	ctx context.Context,
	pollInterval time.Duration,
) (watchdog.LifecycleLease, error) {
	if gate == nil || gate.store == nil {
		return nil, ErrSystemWatchdog
	}
	lease, err := gate.store.Acquire(ctx, pollInterval)
	if err != nil {
		return nil, err
	}
	return &systemWatchdogLifecycleLease{
		store: gate.store,
		lease: lease,
	}, nil
}

type systemWatchdogLifecycleLease struct {
	store *hostruntime.LifecycleStore
	lease *hostruntime.LifecycleLease
}

func (lease *systemWatchdogLifecycleLease) Validate() error {
	if lease == nil || lease.lease == nil {
		return ErrSystemWatchdog
	}
	return lease.lease.Validate()
}

func (lease *systemWatchdogLifecycleLease) Owned() (bool, error) {
	if err := lease.Validate(); err != nil {
		return false, err
	}
	snapshot, err := hostruntime.InspectLifecycleOwnership(lease.store)
	if err != nil {
		return false, err
	}
	return snapshot.Owned(), nil
}

func (lease *systemWatchdogLifecycleLease) Close() error {
	if lease == nil || lease.lease == nil {
		return nil
	}
	return lease.lease.Close()
}

type systemWatchdogStorageProbeFactory func(
	context.Context,
) (StorageProbe, error)

type systemWatchdogStorageEnvelope struct {
	store            *hostruntime.LifecycleStore
	overlayRevision  string
	manifest         hostruntime.RuntimeManifest
	manifestDigest   string
	operationTimeout time.Duration
	probe            systemWatchdogStorageProbeFactory
}

func (envelope *systemWatchdogStorageEnvelope) Revalidate(
	ctx context.Context,
) error {
	if envelope == nil ||
		envelope.store == nil ||
		envelope.probe == nil ||
		envelope.operationTimeout <= 0 ||
		ctx == nil ||
		ctx.Err() != nil {
		return ErrSystemWatchdog
	}
	callCtx, cancel := context.WithTimeout(ctx, envelope.operationTimeout)
	defer cancel()
	reservation, err := selectWatchdogReservation(
		envelope.store,
		envelope.overlayRevision,
		envelope.manifest,
		envelope.manifestDigest,
	)
	if err != nil {
		return errors.Join(ErrSystemWatchdog, err)
	}
	probe, err := envelope.probe(callCtx)
	if err != nil || probe == nil {
		return errors.Join(ErrSystemWatchdog, err)
	}
	authority, err := NewReservationStorageAuthority(probe)
	if err != nil || authority.Revalidate(callCtx, reservation) != nil {
		return ErrSystemWatchdog
	}
	return nil
}

func selectWatchdogReservation(
	store *hostruntime.LifecycleStore,
	overlayRevision string,
	manifest hostruntime.RuntimeManifest,
	manifestDigest string,
) (hostruntime.StorageReservation, error) {
	if store == nil ||
		!lowerHexDigest(overlayRevision) ||
		!lowerHexDigest(manifestDigest) {
		return hostruntime.StorageReservation{}, ErrSystemWatchdog
	}
	_, canonicalManifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil || canonicalManifestDigest != manifestDigest {
		return hostruntime.StorageReservation{}, ErrSystemWatchdog
	}
	journalNames, err := store.ListCanonicalNames(
		hostruntime.LifecycleJournals,
	)
	if err != nil {
		return hostruntime.StorageReservation{}, ErrSystemWatchdog
	}
	reservationNames, err := store.ListCanonicalNames(
		hostruntime.LifecycleReservations,
	)
	if err != nil {
		return hostruntime.StorageReservation{}, ErrSystemWatchdog
	}
	journalIDs, ok := watchdogLifecycleInventory(
		journalNames,
		".journal.json",
	)
	if !ok {
		return hostruntime.StorageReservation{}, ErrSystemWatchdog
	}
	reservationIDs, ok := watchdogLifecycleInventory(
		reservationNames,
		".reservation.json",
	)
	if !ok || !sameWatchdogInventory(journalIDs, reservationIDs) {
		return hostruntime.StorageReservation{}, ErrSystemWatchdog
	}

	candidates := make([]hostruntime.StorageReservation, 0, 1)
	for operationID, journalName := range journalIDs {
		journalDocument, err := store.ReadCanonical(
			hostruntime.LifecycleJournals,
			journalName,
			maximumProductionLifecycleJournalBytes,
		)
		if err != nil {
			return hostruntime.StorageReservation{}, ErrSystemWatchdog
		}
		journal, _, err := hostruntime.ParseOperationJournal(
			journalDocument,
			maximumProductionLifecycleJournalBytes,
		)
		if err != nil || journal.OperationID != operationID {
			return hostruntime.StorageReservation{}, ErrSystemWatchdog
		}
		reservationDocument, err := store.ReadCanonical(
			hostruntime.LifecycleReservations,
			reservationIDs[operationID],
			maximumProductionLifecycleReservationBytes,
		)
		if err != nil {
			return hostruntime.StorageReservation{}, ErrSystemWatchdog
		}
		reservation, _, err := hostruntime.ParseStorageReservation(
			reservationDocument,
			maximumProductionLifecycleReservationBytes,
		)
		if err != nil ||
			reservation.OperationID != operationID ||
			reservation.BindingDigest != journal.BindingDigest ||
			!watchdogReservationMatchesJournal(reservation, journal) {
			return hostruntime.StorageReservation{}, ErrSystemWatchdog
		}

		if journal.Kind != hostruntime.OperationKindInstall ||
			journal.TargetManifest == nil {
			continue
		}
		_, targetDigest, err := hostruntime.MarshalRuntimeManifest(
			*journal.TargetManifest,
		)
		if err != nil || targetDigest != manifestDigest {
			continue
		}
		if journal.CompensationPath != nil ||
			journal.Phase != hostruntime.OperationPhaseComplete ||
			reservation.State != hostruntime.ReservationStateCommitted ||
			reservation.CommittedTargetProofDigest == nil ||
			reservation.ReleasedAbsenceProofDigest != nil ||
			reservation.StorageBudgetDigest != manifest.StorageBudgetDigest ||
			reservation.TargetManifestDigest == nil ||
			*reservation.TargetManifestDigest != manifestDigest {
			return hostruntime.StorageReservation{}, ErrSystemWatchdog
		}
		binding, err := watchdogInstallBinding(
			journal,
			overlayRevision,
		)
		if err != nil ||
			hostruntime.ValidateOperationJournalAgainstBinding(
				journal,
				binding,
			) != nil ||
			binding.PrivateOverlayRevision != overlayRevision ||
			watchdogBindingDigest(binding) != journal.BindingDigest {
			return hostruntime.StorageReservation{}, ErrSystemWatchdog
		}
		if !watchdogTargetGenerationMatches(binding, manifest) {
			return hostruntime.StorageReservation{}, ErrSystemWatchdog
		}
		candidates = append(candidates, reservation)
	}
	if len(candidates) != 1 {
		return hostruntime.StorageReservation{}, ErrSystemWatchdog
	}
	return candidates[0], nil
}

func watchdogLifecycleInventory(
	names []string,
	suffix string,
) (map[string]string, bool) {
	result := make(map[string]string, len(names))
	for _, name := range names {
		if !strings.HasSuffix(name, suffix) {
			return nil, false
		}
		operationID := strings.TrimSuffix(name, suffix)
		if !lowerHexDigest(operationID) {
			return nil, false
		}
		if _, exists := result[operationID]; exists {
			return nil, false
		}
		result[operationID] = name
	}
	return result, true
}

func sameWatchdogInventory(
	left map[string]string,
	right map[string]string,
) bool {
	if len(left) != len(right) {
		return false
	}
	for operationID := range left {
		if _, ok := right[operationID]; !ok {
			return false
		}
	}
	return true
}

func watchdogReservationMatchesJournal(
	reservation hostruntime.StorageReservation,
	journal hostruntime.OperationJournal,
) bool {
	if journal.TargetManifest == nil {
		return reservation.TargetManifestDigest == nil
	}
	_, targetDigest, err := hostruntime.MarshalRuntimeManifest(
		*journal.TargetManifest,
	)
	return err == nil &&
		reservation.TargetManifestDigest != nil &&
		*reservation.TargetManifestDigest == targetDigest &&
		reservation.StorageBudgetDigest ==
			journal.TargetManifest.StorageBudgetDigest
}

func watchdogInstallBinding(
	journal hostruntime.OperationJournal,
	overlayRevision string,
) (hostruntime.OperationBinding, error) {
	if journal.Kind != hostruntime.OperationKindInstall ||
		journal.TargetManifest == nil {
		return hostruntime.OperationBinding{}, ErrSystemWatchdog
	}
	var priorDigest *string
	if journal.PriorManifest != nil {
		_, digest, err := hostruntime.MarshalRuntimeManifest(
			*journal.PriorManifest,
		)
		if err != nil {
			return hostruntime.OperationBinding{}, ErrSystemWatchdog
		}
		priorDigest = &digest
	}
	_, targetDigest, err := hostruntime.MarshalRuntimeManifest(
		*journal.TargetManifest,
	)
	if err != nil {
		return hostruntime.OperationBinding{}, ErrSystemWatchdog
	}
	candidates := make([]hostruntime.OperationBinding, 0, 1)
	for _, disposition := range []hostruntime.InstallDisposition{
		hostruntime.InstallDispositionGreenfieldPortable,
		hostruntime.InstallDispositionUpgradePortable,
		hostruntime.InstallDispositionLegacyDisabledObserver,
	} {
		disposition := disposition
		operationID, err := hostruntime.DeriveOperationID(
			hostruntime.OperationKindInstall,
			&disposition,
			journal.ExpectedGeneration,
			priorDigest,
			&targetDigest,
			journal.TargetFleet,
			overlayRevision,
		)
		if err != nil || operationID != journal.OperationID {
			continue
		}
		binding := hostruntime.OperationBinding{
			SchemaVersion:          1,
			OperationID:            operationID,
			Kind:                   hostruntime.OperationKindInstall,
			InstallDisposition:     &disposition,
			ExpectedGeneration:     journal.ExpectedGeneration,
			PriorManifestDigest:    priorDigest,
			TargetManifestDigest:   &targetDigest,
			TargetFleet:            journal.TargetFleet,
			PrivateOverlayRevision: overlayRevision,
		}
		_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
		if err == nil && bindingDigest == journal.BindingDigest {
			candidates = append(candidates, binding)
		}
	}
	if len(candidates) != 1 {
		return hostruntime.OperationBinding{}, ErrSystemWatchdog
	}
	return candidates[0], nil
}

func watchdogTargetGenerationMatches(
	binding hostruntime.OperationBinding,
	manifest hostruntime.RuntimeManifest,
) bool {
	if binding.InstallDisposition == nil {
		return false
	}
	switch *binding.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		return binding.ExpectedGeneration == 0 &&
			manifest.FleetGeneration == 1
	case hostruntime.InstallDispositionUpgradePortable,
		hostruntime.InstallDispositionLegacyDisabledObserver:
		return binding.ExpectedGeneration == manifest.FleetGeneration
	default:
		return false
	}
}

type SystemWatchdogRunner struct {
	executable func() (string, error)
	kernel     func() (ProcessKernel, error)
}

func NewSystemWatchdogRunner() *SystemWatchdogRunner {
	return &SystemWatchdogRunner{
		executable: os.Executable,
		kernel:     NewSystemProcessKernel,
	}
}

func (runner *SystemWatchdogRunner) RunCycle(
	ctx context.Context,
	privatePath string,
	manifestPath string,
) (watchdog.Result, error) {
	failed := watchdog.Result{
		Status: watchdog.StatusFailed,
		Reason: watchdog.ReasonInspectFailed,
	}
	if runner == nil ||
		runner.executable == nil ||
		runner.kernel == nil ||
		ctx == nil ||
		ctx.Err() != nil {
		return failed, ErrSystemWatchdog
	}
	resources, machine, restartDeadline, err := runner.open(
		ctx,
		privatePath,
		manifestPath,
	)
	if err != nil {
		return failed, err
	}
	cycleCtx, cancel := context.WithTimeout(ctx, restartDeadline)
	result, runErr := machine.RunCycle(cycleCtx)
	cancel()
	closeErr := resources.Close()
	if runErr != nil || closeErr != nil {
		if runErr == nil {
			result = failed
		}
		return result, errors.Join(
			ErrSystemWatchdog,
			runErr,
			closeErr,
		)
	}
	return result, nil
}

type systemWatchdogResources struct {
	releases     *releaseBundleStore
	lifecycle    *hostruntime.LifecycleStore
	fence        *fleetfence.Store
	processStore *PinnedProcessRecordStore
	marker       *watchdogMarkerStore
}

func (resources *systemWatchdogResources) Close() error {
	if resources == nil {
		return nil
	}
	var result error
	if resources.marker != nil {
		result = errors.Join(result, resources.marker.Close())
		resources.marker = nil
	}
	if resources.processStore != nil {
		result = errors.Join(result, resources.processStore.Close())
		resources.processStore = nil
	}
	if resources.fence != nil {
		result = errors.Join(result, resources.fence.Close())
		resources.fence = nil
	}
	if resources.lifecycle != nil {
		result = errors.Join(result, resources.lifecycle.Close())
		resources.lifecycle = nil
	}
	if resources.releases != nil {
		result = errors.Join(result, resources.releases.Close())
		resources.releases = nil
	}
	return result
}

func (runner *SystemWatchdogRunner) open(
	ctx context.Context,
	privatePath string,
	manifestPath string,
) (
	*systemWatchdogResources,
	watchdog.Watchdog,
	time.Duration,
	error,
) {
	if !canonicalPath(privatePath) ||
		!canonicalPath(manifestPath) ||
		privatePath == manifestPath {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}
	overlay, revision, err := loadPinnedTargetOverlay(privatePath)
	if err != nil ||
		manifestPath != overlay.Manifest.Path ||
		runtime.GOOS != overlay.Target.OS ||
		runtime.GOARCH != overlay.Target.Architecture ||
		uint64(os.Geteuid()) != overlay.Target.ExpectedEUID ||
		!overlay.Resources.RunnerSizing.OperatorApproved {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}
	overlayDocument, canonicalRevision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil || canonicalRevision != revision {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}
	manifest, manifestDocument, manifestDigest, err :=
		loadPinnedTargetManifest(manifestPath)
	if err != nil ||
		manifestDigest != overlay.Manifest.Digest ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}
	canonicalManifest, canonicalManifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil ||
		canonicalManifestDigest != manifestDigest ||
		!bytes.Equal(canonicalManifest, manifestDocument) {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}
	executable, err := runner.executable()
	if err != nil ||
		!canonicalPath(executable) ||
		executable != overlay.Commands.WatchdogBinary {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}
	controllerDigest, err := digestPinnedExecutable(
		overlay.Commands.ControllerBinary,
	)
	if err != nil || controllerDigest != manifest.ControllerSHA256 {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}
	pollInterval, processGrace, operationTimeout, restartDeadline, err :=
		parseSystemWatchdogTimings(overlay)
	if err != nil {
		return nil, watchdog.Watchdog{}, 0, ErrSystemWatchdog
	}

	resources := &systemWatchdogResources{}
	fail := func(primary error) (
		*systemWatchdogResources,
		watchdog.Watchdog,
		time.Duration,
		error,
	) {
		return nil, watchdog.Watchdog{}, 0, errors.Join(
			primary,
			resources.Close(),
		)
	}
	releases, err := openReleaseBundleStore(
		overlay.Paths.StagingRoot,
		overlay.Paths.ReleaseRoot,
	)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	resources.releases = releases
	current, present, err := releases.Current()
	if err != nil ||
		!present ||
		current.manifestDigest != manifestDigest ||
		current.overlayRevision != revision ||
		!bytes.Equal(current.manifestDocument, manifestDocument) ||
		!bytes.Equal(current.overlayDocument, overlayDocument) {
		return fail(ErrSystemWatchdog)
	}

	layout, err := hostruntime.LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	lifecycle, err := hostruntime.OpenLifecycleStoreLayout(layout, false)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	resources.lifecycle = lifecycle
	fence, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             overlay.Paths.FenceRoot,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: pollInterval,
	})
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	resources.fence = fence
	processStore, err := OpenProcessRecordStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	resources.processStore = processStore
	kernel, err := runner.kernel()
	if err != nil || kernel == nil {
		return fail(ErrSystemWatchdog)
	}
	marker, err := openWatchdogMarkerStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	resources.marker = marker
	markerBinding := watchdogMarkerBinding{
		PrivateOverlayRevision: revision,
		ManifestDigest:         manifestDigest,
		WatchdogBinary:         overlay.Commands.WatchdogBinary,
	}
	if _, markerPresent, err := marker.Inspect(markerBinding); err != nil ||
		!markerPresent {
		return fail(ErrSystemWatchdog)
	}

	commandRunner := hostruntime.NewExecCommandRunner()
	commandRunner.StdoutLimit = maximumDockerRootOutputBytes
	commandRunner.StderrLimit = maximumDockerRootOutputBytes
	docker, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    overlay.Commands.DockerBinary,
			BrokerRoot:    overlay.Paths.BrokerRoot,
			SeccompRoot:   overlay.Paths.SeccompRoot,
			BrokerNetwork: overlay.Docker.BrokerNetworkID,
		},
		commandRunner,
	)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	releaseOverlayPath := filepath.Join(
		overlay.Paths.ReleaseRoot,
		manifestDigest,
		releaseOverlayName,
	)
	launch := ControllerLaunch{
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
	}
	processTiming := ProcessTiming{
		PollInterval: pollInterval,
		TermGrace:    processGrace,
		KillGrace:    processGrace,
		CleanupGrace: processGrace,
	}
	authorityFactory := func(
		binding ProcessBinding,
	) (systemWatchdogProcess, error) {
		return NewProcessAuthority(ProcessAuthorityConfig{
			Store:   processStore,
			Kernel:  kernel,
			Binding: binding,
			Launch:  launch,
			Timing:  processTiming,
		})
	}
	probe, err := NewSystemDisabledControllerProbe(
		overlay.Commands.ControllerBinary,
		releaseOverlayPath,
	)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	supervisor, err := newSystemWatchdogSupervisor(
		systemWatchdogSupervisorConfig{
			Fence:              fence,
			Store:              processStore,
			Authority:          authorityFactory,
			Probe:              probe,
			Quiescence:         docker,
			OverlayRevision:    revision,
			ManifestDigest:     manifestDigest,
			ManifestGeneration: manifest.FleetGeneration,
			OperationTimeout:   operationTimeout,
		},
	)
	if err != nil {
		return fail(ErrSystemWatchdog)
	}
	storage := &systemWatchdogStorageEnvelope{
		store:            lifecycle,
		overlayRevision:  revision,
		manifest:         manifest,
		manifestDigest:   manifestDigest,
		operationTimeout: operationTimeout,
		probe: func(callCtx context.Context) (StorageProbe, error) {
			return NewSystemStorageProbe(callCtx, overlay, commandRunner)
		},
	}
	machine := watchdog.Watchdog{
		Lifecycle:    &systemWatchdogLifecycleGate{store: lifecycle},
		Supervisor:   supervisor,
		Storage:      storage,
		PollInterval: pollInterval,
	}
	return resources, machine, restartDeadline, nil
}

func parseSystemWatchdogTimings(
	overlay hostruntime.PrivateOverlay,
) (time.Duration, time.Duration, time.Duration, time.Duration, error) {
	pollInterval, pollErr := time.ParseDuration(
		overlay.Fence.LockPollInterval,
	)
	processGrace, processErr := time.ParseDuration(
		overlay.Watchdog.ProcessGrace,
	)
	operationTimeout, operationErr := time.ParseDuration(
		overlay.Controller.OperationTimeout,
	)
	restartDeadline, restartErr := time.ParseDuration(
		overlay.Watchdog.RestartDeadline,
	)
	if pollErr != nil ||
		processErr != nil ||
		operationErr != nil ||
		restartErr != nil ||
		pollInterval <= 0 ||
		pollInterval > time.Second ||
		processGrace <= 0 ||
		operationTimeout <= 0 ||
		restartDeadline <= 0 {
		return 0, 0, 0, 0, ErrSystemWatchdog
	}
	return pollInterval, processGrace, operationTimeout, restartDeadline, nil
}

type systemWatchdogFence interface {
	Inspect(context.Context) (fleetfence.Snapshot, error)
}

type systemWatchdogProcess interface {
	Inspect(context.Context) (ProcessInspection, error)
	StartDisabled(context.Context) (ProcessInspection, error)
	Stop(context.Context, string) error
}

type systemWatchdogAuthorityFactory func(
	ProcessBinding,
) (systemWatchdogProcess, error)

type systemWatchdogSupervisorConfig struct {
	Fence              systemWatchdogFence
	Store              ProcessRecordStore
	Authority          systemWatchdogAuthorityFactory
	Probe              DisabledControllerProbe
	Quiescence         hostruntime.ManagedQuiescence
	OverlayRevision    string
	ManifestDigest     string
	ManifestGeneration uint64
	OperationTimeout   time.Duration
}

type systemWatchdogSupervisor struct {
	fence              systemWatchdogFence
	store              ProcessRecordStore
	authority          systemWatchdogAuthorityFactory
	probe              DisabledControllerProbe
	quiescence         hostruntime.ManagedQuiescence
	overlayRevision    string
	manifestDigest     string
	manifestGeneration uint64
	operationTimeout   time.Duration
}

func newSystemWatchdogSupervisor(
	config systemWatchdogSupervisorConfig,
) (*systemWatchdogSupervisor, error) {
	if config.Fence == nil ||
		config.Store == nil ||
		config.Authority == nil ||
		config.Probe == nil ||
		config.Quiescence == nil ||
		!lowerHexDigest(config.OverlayRevision) ||
		!lowerHexDigest(config.ManifestDigest) ||
		config.ManifestGeneration == 0 ||
		config.OperationTimeout <= 0 {
		return nil, ErrSystemWatchdog
	}
	return &systemWatchdogSupervisor{
		fence:              config.Fence,
		store:              config.Store,
		authority:          config.Authority,
		probe:              config.Probe,
		quiescence:         config.Quiescence,
		overlayRevision:    config.OverlayRevision,
		manifestDigest:     config.ManifestDigest,
		manifestGeneration: config.ManifestGeneration,
		operationTimeout:   config.OperationTimeout,
	}, nil
}

func (supervisor *systemWatchdogSupervisor) Inspect(
	ctx context.Context,
) (watchdog.Observation, error) {
	snapshot, fleet, err := supervisor.inspectFence(ctx)
	if err != nil {
		return watchdog.Observation{}, err
	}
	record, identity, present, err := supervisor.readRecord(ctx)
	if err != nil {
		return watchdog.Observation{}, err
	}
	base := watchdog.Observation{
		FenceGeneration: snapshot.Header.Generation,
		ActiveFleet:     fleet,
	}
	if !present {
		base.Process = watchdog.ProcessAbsent
		return base, nil
	}
	base.Process = watchdog.ProcessUnhealthy
	base.ProcessIdentity = identity
	authority, err := supervisor.authority(recordBinding(record))
	if err != nil {
		return watchdog.Observation{}, ErrSystemWatchdog
	}
	callCtx, cancel, err := supervisor.callContext(ctx)
	if err != nil {
		return watchdog.Observation{}, err
	}
	inspection, inspectErr := authority.Inspect(callCtx)
	cancel()
	if inspectErr != nil {
		if ctx.Err() != nil {
			return watchdog.Observation{}, errors.Join(
				ErrSystemWatchdog,
				ctx.Err(),
			)
		}
		return base, nil
	}
	if inspection.State != ProcessRunning ||
		inspection.ProcessIdentity != identity ||
		record.FenceGeneration != snapshot.Header.Generation ||
		record.ActiveFleet != snapshot.Header.ActiveFleet ||
		(snapshot.Header.ActiveFleet != fleetfence.FleetNone &&
			snapshot.Header.Generation != supervisor.manifestGeneration) {
		return base, nil
	}
	base.Process = watchdog.ProcessRunning
	return base, nil
}

func (supervisor *systemWatchdogSupervisor) SafeStop(
	ctx context.Context,
	observation watchdog.Observation,
) error {
	if !validWatchdogProcessObservation(observation, false) {
		return ErrSystemWatchdog
	}
	snapshot, fleet, err := supervisor.inspectFence(ctx)
	if err != nil ||
		snapshot.Header.Generation != observation.FenceGeneration ||
		fleet != observation.ActiveFleet {
		return ErrSystemWatchdog
	}
	record, identity, present, err := supervisor.readRecord(ctx)
	if err != nil || !present || identity != observation.ProcessIdentity {
		return ErrSystemWatchdog
	}
	authority, err := supervisor.authority(recordBinding(record))
	if err != nil {
		return ErrSystemWatchdog
	}
	cycleCtx, err := supervisor.cycleContext(ctx)
	if err != nil {
		return err
	}
	err = authority.Stop(cycleCtx, identity)
	if err != nil {
		return errors.Join(ErrSystemWatchdog, err)
	}
	return nil
}

func (supervisor *systemWatchdogSupervisor) StartDisabled(
	ctx context.Context,
	observation watchdog.Observation,
) (watchdog.Observation, error) {
	if !validWatchdogProcessObservation(observation, true) ||
		(observation.ActiveFleet != watchdog.FleetPortable &&
			observation.ActiveFleet != watchdog.FleetLegacy) {
		return watchdog.Observation{}, ErrSystemWatchdog
	}
	snapshot, fleet, err := supervisor.inspectFence(ctx)
	if err != nil ||
		snapshot.Header.Generation != observation.FenceGeneration ||
		fleet != observation.ActiveFleet ||
		snapshot.Header.Generation != supervisor.manifestGeneration {
		return watchdog.Observation{}, ErrSystemWatchdog
	}
	_, _, present, err := supervisor.readRecord(ctx)
	if err != nil || present {
		return watchdog.Observation{}, ErrSystemWatchdog
	}
	binding, err := liveProcessBinding(
		supervisor.overlayRevision,
		supervisor.manifestDigest,
		snapshot.Header,
	)
	if err != nil {
		return watchdog.Observation{}, err
	}
	authority, err := supervisor.authority(binding)
	if err != nil {
		return watchdog.Observation{}, ErrSystemWatchdog
	}
	cycleCtx, err := supervisor.cycleContext(ctx)
	if err != nil {
		return watchdog.Observation{}, err
	}
	inspection, startErr := authority.StartDisabled(cycleCtx)
	if startErr != nil ||
		inspection.State != ProcessRunning ||
		!lowerHexDigest(inspection.ProcessIdentity) {
		return watchdog.Observation{}, supervisor.cleanupFailedStart(
			ctx,
			startErr,
		)
	}
	after, afterFleet, afterErr := supervisor.inspectFence(ctx)
	if afterErr != nil ||
		after.Header.Generation != snapshot.Header.Generation ||
		afterFleet != fleet {
		stopCtx, stopCtxErr := supervisor.cycleContext(ctx)
		stopErr := stopCtxErr
		if stopCtxErr == nil {
			stopErr = authority.Stop(stopCtx, inspection.ProcessIdentity)
		}
		return watchdog.Observation{}, errors.Join(
			ErrSystemWatchdog,
			afterErr,
			stopErr,
		)
	}
	return watchdog.Observation{
		FenceGeneration: observation.FenceGeneration,
		ActiveFleet:     observation.ActiveFleet,
		Process:         watchdog.ProcessRunning,
		ProcessIdentity: inspection.ProcessIdentity,
	}, nil
}

func (supervisor *systemWatchdogSupervisor) cleanupFailedStart(
	ctx context.Context,
	startErr error,
) error {
	failure := errors.Join(ErrSystemWatchdog, startErr)
	observation, inspectErr := supervisor.Inspect(ctx)
	if inspectErr != nil {
		return errors.Join(failure, inspectErr)
	}
	if observation.Process == watchdog.ProcessAbsent {
		return failure
	}
	if observation.Process != watchdog.ProcessRunning &&
		observation.Process != watchdog.ProcessUnhealthy {
		return failure
	}

	stopErr := supervisor.SafeStop(ctx, observation)
	after, afterErr := supervisor.Inspect(ctx)
	if afterErr != nil ||
		after.FenceGeneration != observation.FenceGeneration ||
		after.ActiveFleet != observation.ActiveFleet ||
		after.Process != watchdog.ProcessAbsent ||
		after.ProcessIdentity != "" {
		return errors.Join(failure, stopErr, afterErr, ErrSystemWatchdog)
	}
	return errors.Join(failure, stopErr)
}

func (supervisor *systemWatchdogSupervisor) ProveDisabled(
	ctx context.Context,
	observation watchdog.Observation,
) (watchdog.DisabledProof, error) {
	if !validWatchdogProcessObservation(observation, false) ||
		observation.Process != watchdog.ProcessRunning ||
		(observation.ActiveFleet != watchdog.FleetPortable &&
			observation.ActiveFleet != watchdog.FleetLegacy) {
		return watchdog.DisabledProof{}, ErrSystemWatchdog
	}
	snapshot, fleet, err := supervisor.inspectFence(ctx)
	if err != nil ||
		snapshot.Header.Generation != observation.FenceGeneration ||
		fleet != observation.ActiveFleet {
		return watchdog.DisabledProof{}, ErrSystemWatchdog
	}
	record, identity, present, err := supervisor.readRecord(ctx)
	if err != nil || !present || identity != observation.ProcessIdentity ||
		record.FenceGeneration != snapshot.Header.Generation ||
		record.ActiveFleet != snapshot.Header.ActiveFleet {
		return watchdog.DisabledProof{}, ErrSystemWatchdog
	}
	authority, err := supervisor.authority(recordBinding(record))
	if err != nil {
		return watchdog.DisabledProof{}, ErrSystemWatchdog
	}
	if err := supervisor.proveProcess(ctx, authority, identity); err != nil {
		return watchdog.DisabledProof{}, err
	}
	cycleCtx, err := supervisor.cycleContext(ctx)
	if err != nil {
		return watchdog.DisabledProof{}, err
	}
	_, probeErr := supervisor.probe.Observe(cycleCtx)
	if probeErr != nil {
		return watchdog.DisabledProof{}, errors.Join(
			ErrSystemWatchdog,
			probeErr,
		)
	}
	callCtx, cancel, err := supervisor.callContext(ctx)
	if err != nil {
		return watchdog.DisabledProof{}, err
	}
	quiescenceErr := supervisor.quiescence.ProveManagedQuiescence(callCtx)
	cancel()
	if quiescenceErr != nil {
		return watchdog.DisabledProof{}, errors.Join(
			ErrSystemWatchdog,
			quiescenceErr,
		)
	}
	after, afterFleet, err := supervisor.inspectFence(ctx)
	if err != nil ||
		after.Header.Generation != snapshot.Header.Generation ||
		afterFleet != fleet ||
		supervisor.proveProcess(ctx, authority, identity) != nil {
		return watchdog.DisabledProof{}, ErrSystemWatchdog
	}
	return watchdog.DisabledProof{
		FenceGeneration:      observation.FenceGeneration,
		ActiveFleet:          observation.ActiveFleet,
		ProcessIdentity:      identity,
		PolicyDisabled:       true,
		PendingAcquisitions:  0,
		ActiveListeners:      0,
		ManagedProcesses:     1,
		AcquisitionProcesses: 0,
	}, nil
}

func (supervisor *systemWatchdogSupervisor) inspectFence(
	ctx context.Context,
) (fleetfence.Snapshot, watchdog.Fleet, error) {
	if supervisor == nil || supervisor.fence == nil {
		return fleetfence.Snapshot{}, "", ErrSystemWatchdog
	}
	callCtx, cancel, err := supervisor.callContext(ctx)
	if err != nil {
		return fleetfence.Snapshot{}, "", err
	}
	snapshot, err := supervisor.fence.Inspect(callCtx)
	cancel()
	if err != nil || snapshot.Header.Generation == 0 {
		return fleetfence.Snapshot{}, "", errors.Join(
			ErrSystemWatchdog,
			err,
		)
	}
	fleet, ok := watchdogFleet(snapshot.Header.ActiveFleet)
	if !ok {
		return fleetfence.Snapshot{}, "", ErrSystemWatchdog
	}
	return snapshot, fleet, nil
}

func (supervisor *systemWatchdogSupervisor) readRecord(
	ctx context.Context,
) (ProcessRecord, string, bool, error) {
	if supervisor == nil || supervisor.store == nil {
		return ProcessRecord{}, "", false, ErrSystemWatchdog
	}
	callCtx, cancel, err := supervisor.callContext(ctx)
	if err != nil {
		return ProcessRecord{}, "", false, err
	}
	record, identity, present, readErr := supervisor.store.Read(callCtx)
	cancel()
	if readErr != nil {
		return ProcessRecord{}, "", false, errors.Join(
			ErrSystemWatchdog,
			readErr,
		)
	}
	if !present {
		return ProcessRecord{}, "", false, nil
	}
	_, canonicalIdentity, err := MarshalProcessRecord(record)
	if err != nil ||
		canonicalIdentity != identity ||
		record.PrivateOverlayRevision != supervisor.overlayRevision ||
		record.ManifestDigest != supervisor.manifestDigest {
		return ProcessRecord{}, "", false, ErrSystemWatchdog
	}
	return record, identity, true, nil
}

func (supervisor *systemWatchdogSupervisor) proveProcess(
	ctx context.Context,
	authority systemWatchdogProcess,
	identity string,
) error {
	callCtx, cancel, err := supervisor.callContext(ctx)
	if err != nil {
		return err
	}
	inspection, inspectErr := authority.Inspect(callCtx)
	cancel()
	if inspectErr != nil ||
		inspection.State != ProcessRunning ||
		inspection.ProcessIdentity != identity {
		return errors.Join(ErrSystemWatchdog, inspectErr)
	}
	return nil
}

func (supervisor *systemWatchdogSupervisor) callContext(
	ctx context.Context,
) (context.Context, context.CancelFunc, error) {
	if supervisor == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		supervisor.operationTimeout <= 0 {
		return nil, nil, ErrSystemWatchdog
	}
	callCtx, cancel := context.WithTimeout(ctx, supervisor.operationTimeout)
	return callCtx, cancel, nil
}

func (supervisor *systemWatchdogSupervisor) cycleContext(
	ctx context.Context,
) (context.Context, error) {
	if supervisor == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrSystemWatchdog
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrSystemWatchdog
	}
	return ctx, nil
}

func recordBinding(record ProcessRecord) ProcessBinding {
	return ProcessBinding{
		PrivateOverlayRevision: record.PrivateOverlayRevision,
		ManifestDigest:         record.ManifestDigest,
		ActiveFleet:            record.ActiveFleet,
		FenceGeneration:        record.FenceGeneration,
	}
}

func liveProcessBinding(
	overlayRevision string,
	manifestDigest string,
	header fleetfence.Header,
) (ProcessBinding, error) {
	binding := ProcessBinding{
		PrivateOverlayRevision: overlayRevision,
		ManifestDigest:         manifestDigest,
		ActiveFleet:            header.ActiveFleet,
		FenceGeneration:        header.Generation,
	}
	if !validProcessBinding(binding) {
		return ProcessBinding{}, ErrSystemWatchdog
	}
	return binding, nil
}

func watchdogFleet(fleet fleetfence.Fleet) (watchdog.Fleet, bool) {
	switch fleet {
	case fleetfence.FleetNone:
		return watchdog.FleetNone, true
	case fleetfence.FleetPortable:
		return watchdog.FleetPortable, true
	case fleetfence.FleetLegacy:
		return watchdog.FleetLegacy, true
	default:
		return "", false
	}
}

func validWatchdogProcessObservation(
	observation watchdog.Observation,
	absent bool,
) bool {
	if observation.FenceGeneration == 0 ||
		(observation.ActiveFleet != watchdog.FleetNone &&
			observation.ActiveFleet != watchdog.FleetPortable &&
			observation.ActiveFleet != watchdog.FleetLegacy) {
		return false
	}
	if absent {
		return observation.Process == watchdog.ProcessAbsent &&
			observation.ProcessIdentity == ""
	}
	return (observation.Process == watchdog.ProcessRunning ||
		observation.Process == watchdog.ProcessUnhealthy) &&
		lowerHexDigest(observation.ProcessIdentity)
}

func watchdogBindingDigest(binding hostruntime.OperationBinding) string {
	_, digest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		return ""
	}
	return digest
}

var (
	_ watchdog.LifecycleGate  = (*systemWatchdogLifecycleGate)(nil)
	_ watchdog.LifecycleLease = (*systemWatchdogLifecycleLease)(nil)
	_ watchdog.Supervisor     = (*systemWatchdogSupervisor)(nil)
)
