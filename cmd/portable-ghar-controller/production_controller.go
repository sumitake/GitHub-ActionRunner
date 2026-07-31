package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/state"
)

const (
	maxProductionConfigBytes   = 1 << 20
	maxProductionManifestBytes = 1 << 16
)

func dialProductionAdmin(
	ctx context.Context,
) (controller.LiveAdmin, io.Closer, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, errCommandUnavailable
	}
	configPath := os.Getenv("PORTABLE_GHAR_PRIVATE_OVERLAY")
	if !canonicalAbsolutePath(configPath) {
		return nil, nil, errCommandUnavailable
	}
	configDocument, err := readPinnedRootFile(
		configPath,
		0o600,
		maxProductionConfigBytes,
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	overlay, _, err := hostruntime.ParsePrivateOverlay(
		configDocument,
		maxProductionConfigBytes,
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	if runtime.GOOS != overlay.Target.OS ||
		runtime.GOARCH != overlay.Target.Architecture ||
		uint64(os.Geteuid()) != overlay.Target.ExpectedEUID {
		return nil, nil, errCommandUnavailable
	}
	timeout, err := time.ParseDuration(
		overlay.Controller.OperationTimeout,
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	client, err := newLocalAdminClient(
		overlay.Paths.AdminSocketPath,
		uint32(overlay.Target.ExpectedEUID),
		timeout,
	)
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	return client, client, nil
}

func openProductionDisabledObserver(
	ctx context.Context,
	configPath string,
	databasePath string,
	ownership controllerOwnershipLease,
) (controllerProcess, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		ownership == nil ||
		ownership.Validate() != nil ||
		!canonicalAbsolutePath(configPath) ||
		!canonicalAbsolutePath(databasePath) ||
		configPath == databasePath {
		return nil, errCommandUnavailable
	}
	configDocument, err := readPinnedRootFile(
		configPath,
		0o600,
		maxProductionConfigBytes,
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	overlay, _, err := hostruntime.ParsePrivateOverlay(
		configDocument,
		maxProductionConfigBytes,
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	if runtime.GOOS != overlay.Target.OS ||
		runtime.GOARCH != overlay.Target.Architecture ||
		uint64(os.Geteuid()) != overlay.Target.ExpectedEUID ||
		databasePath != overlay.Paths.DatabasePath {
		return nil, errCommandUnavailable
	}
	manifestDocument, err := readPinnedRootFile(
		overlay.Manifest.Path,
		0o600,
		maxProductionManifestBytes,
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	manifest, manifestDigest, err := hostruntime.ParseRuntimeManifest(
		manifestDocument,
		maxProductionManifestBytes,
	)
	if err != nil ||
		manifestDigest != overlay.Manifest.Digest ||
		!controllerManifestMatchesOverlay(manifest, overlay) {
		return nil, errCommandUnavailable
	}
	executableDigest, err := currentControllerExecutableDigest()
	if err != nil || executableDigest != manifest.ControllerSHA256 {
		return nil, errCommandUnavailable
	}
	if err := validateProductionControllerPaths(
		overlay,
		uint32(overlay.Target.ExpectedEUID),
	); err != nil {
		return nil, errCommandUnavailable
	}
	timings, err := parseProductionControllerTimings(overlay)
	if err != nil ||
		overlay.Resources.MaxCapacity == 0 ||
		overlay.Resources.MaxCapacity > uint64(math.MaxInt) {
		return nil, errCommandUnavailable
	}
	desired, err := productionDisabledPolicy(overlay)
	if err != nil {
		return nil, errCommandUnavailable
	}
	historyLimits, err := productionHistoryLimits(overlay)
	if err != nil {
		return nil, errCommandUnavailable
	}

	resources := &productionControllerResources{}
	fail := func(primary error) (controllerProcess, error) {
		return nil, errors.Join(primary, resources.Close())
	}
	store, err := state.OpenWithHistoryLimits(
		databasePath,
		historyLimits,
	)
	if err != nil {
		return fail(errCommandUnavailable)
	}
	resources.Add(store)
	stateAdapter, err := state.NewControllerAdapter(
		store,
		historyLimits,
	)
	if err != nil {
		return fail(errCommandUnavailable)
	}

	fenceStore, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             overlay.Paths.FenceRoot,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: timings.fenceLock,
	})
	if err != nil {
		return fail(errCommandUnavailable)
	}
	resources.Add(fenceStore)
	callCtx, callCancel := context.WithTimeout(ctx, timings.operation)
	fenceSnapshot, err := fenceStore.Inspect(callCtx)
	callCancel()
	if err != nil ||
		fenceSnapshot.Header.Generation != manifest.FleetGeneration ||
		(fenceSnapshot.Header.ActiveFleet != fleetfence.FleetPortable &&
			fenceSnapshot.Header.ActiveFleet != fleetfence.FleetLegacy) {
		return fail(errCommandUnavailable)
	}
	expectedFleet := fenceSnapshot.Header.ActiveFleet

	var guard controller.AcquisitionGuard
	var guardFailure <-chan error
	if expectedFleet == fleetfence.FleetPortable {
		fenceAdapter, err := fleetfence.NewControllerAdapter(
			fleetfence.ControllerAdapterConfig{
				Store:           fenceStore,
				Generation:      manifest.FleetGeneration,
				OwnerID:         overlay.Target.OwnerID,
				PID:             os.Getpid(),
				RenewalInterval: timings.fenceRenewal,
				RenewalTimeout:  timings.fenceTimeout,
			},
		)
		if err != nil {
			return fail(errCommandUnavailable)
		}
		callCtx, callCancel = context.WithTimeout(ctx, timings.operation)
		guard, err = fenceAdapter.AcquirePortable(callCtx)
		callCancel()
		if err != nil || guard == nil {
			return fail(errCommandUnavailable)
		}
		resources.Add(guard)
		source, ok := guard.(interface{ Failure() <-chan error })
		if !ok || source.Failure() == nil {
			return fail(errCommandUnavailable)
		}
		guardFailure = source.Failure()
	} else {
		callCtx, callCancel = context.WithTimeout(ctx, timings.operation)
		legacyProof, normalizeErr := fleetfence.NormalizeLegacyObserver(
			callCtx,
			fenceStore,
			stateAdapter,
		)
		callCancel()
		if normalizeErr != nil ||
			legacyProof.FleetGeneration != manifest.FleetGeneration {
			return fail(errCommandUnavailable)
		}
	}

	commandRunner := hostruntime.NewExecCommandRunner()
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
		return fail(errCommandUnavailable)
	}
	localAuthority, err := newProductionLocalAuthority(
		productionLocalAuthorityConfig{
			State:      stateAdapter,
			Recovery:   docker,
			Quiescence: docker,
			BuildID:    manifest.BuildID,
			Generation: manifest.FleetGeneration,
			BrokerRoot: overlay.Paths.BrokerRoot,
			Timeout:    timings.reconciliation,
			Now:        time.Now,
		},
	)
	if err != nil {
		return fail(errCommandUnavailable)
	}
	fleetAuthority, err := newProductionFleetAuthority(
		productionFleetAuthorityConfig{
			Inspector:    fenceStore,
			Transitions:  stateAdapter,
			Fleet:        expectedFleet,
			Generation:   manifest.FleetGeneration,
			OwnerID:      portableOwner(expectedFleet, overlay.Target.OwnerID),
			PID:          portablePID(expectedFleet, os.Getpid()),
			GuardFailure: guardFailure,
			Timeout:      timings.operation,
			Now:          time.Now,
		},
	)
	if err != nil {
		return fail(errCommandUnavailable)
	}
	callCtx, callCancel = context.WithTimeout(ctx, timings.operation)
	currentPolicy, err := stateAdapter.Snapshot(callCtx)
	callCancel()
	if err != nil || currentPolicy.Epoch == math.MaxUint64 {
		return fail(errCommandUnavailable)
	}
	broker, err := newZeroDemandBroker(currentPolicy.Epoch + 1)
	if err != nil {
		return fail(errCommandUnavailable)
	}
	external := newUnavailableExternalGraph()
	process, err := newDisabledControllerProcess(
		disabledControllerProcessConfig{
			Admin: disabledAdminConfig{
				Transitions:        stateAdapter,
				Authority:          localAuthority,
				Broker:             broker,
				Fleet:              fleetAuthority,
				External:           &external,
				Ownership:          ownership,
				Desired:            desired,
				ExpectedFleet:      expectedFleet,
				ExpectedGeneration: manifest.FleetGeneration,
				ObservationMaxAge:  timings.observationMaxAge,
				Now:                time.Now,
			},
			StoreCloser:           resources,
			AdminSocketPath:       overlay.Paths.AdminSocketPath,
			HealthSocketPath:      overlay.Paths.HealthSocketPath,
			ExpectedUID:           uint32(overlay.Target.ExpectedEUID),
			AdmissionLimit:        int(overlay.Resources.MaxCapacity),
			IOTimeout:             timings.operation,
			OperationTimeout:      timings.operation,
			DrainTimeout:          timings.shutdown,
			ReconciliationCadence: timings.reconciliationCadence,
			ShutdownTimeout:       timings.shutdown,
		},
	)
	if err != nil {
		return fail(errCommandUnavailable)
	}
	if ownership.Validate() != nil {
		return fail(errCommandUnavailable)
	}
	return process, nil
}

type productionControllerTimings struct {
	operation             time.Duration
	reconciliation        time.Duration
	reconciliationCadence time.Duration
	shutdown              time.Duration
	observationMaxAge     time.Duration
	fenceLock             time.Duration
	fenceRenewal          time.Duration
	fenceTimeout          time.Duration
}

func productionHistoryLimits(
	overlay hostruntime.PrivateOverlay,
) (state.HistoryLimits, error) {
	history := overlay.Resources.History
	minRetention, err := time.ParseDuration(history.MinRetention)
	if err != nil {
		return state.HistoryLimits{}, errCommandUnavailable
	}
	maintenanceCadence, err := time.ParseDuration(
		history.MaintenanceCadence,
	)
	if err != nil {
		return state.HistoryLimits{}, errCommandUnavailable
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
	if state.ValidateHistoryLimits(limits) != nil ||
		overlay.Resources.FleetConcurrency == 0 ||
		overlay.Resources.NetworkLedgerReserveRows == 0 ||
		overlay.Resources.NetworkLedgerReserveBytes == 0 {
		return state.HistoryLimits{}, errCommandUnavailable
	}
	requiredRows, ok := multiplyStatusTotal(
		overlay.Resources.FleetConcurrency,
		limits.InflightReserveRows,
	)
	if !ok || requiredRows > limits.MaxHistoryRows {
		return state.HistoryLimits{}, errCommandUnavailable
	}
	requiredBytes, ok := multiplyStatusTotal(
		overlay.Resources.FleetConcurrency,
		limits.InflightReserveLogicalBytes,
	)
	if !ok || requiredBytes > limits.MaxHistoryLogicalBytes ||
		overlay.Resources.NetworkLedgerReserveRows <
			overlay.Resources.FleetConcurrency ||
		overlay.Resources.NetworkLedgerReserveRows >
			limits.MaxNetworkLedgerRows ||
		overlay.Resources.NetworkLedgerReserveBytes <
			overlay.Resources.FleetConcurrency ||
		overlay.Resources.NetworkLedgerReserveBytes >
			limits.MaxNetworkLedgerLogicalBytes {
		return state.HistoryLimits{}, errCommandUnavailable
	}
	return limits, nil
}

func parseProductionControllerTimings(
	overlay hostruntime.PrivateOverlay,
) (productionControllerTimings, error) {
	parse := func(value string) (time.Duration, error) {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return 0, errCommandUnavailable
		}
		return duration, nil
	}
	operation, err := parse(overlay.Controller.OperationTimeout)
	if err != nil {
		return productionControllerTimings{}, err
	}
	reconciliation, err := parse(
		overlay.Controller.ReconciliationTimeout,
	)
	if err != nil {
		return productionControllerTimings{}, err
	}
	cadence, err := parse(overlay.Controller.ReconciliationCadence)
	if err != nil {
		return productionControllerTimings{}, err
	}
	shutdown, err := parse(overlay.Controller.ShutdownTimeout)
	if err != nil {
		return productionControllerTimings{}, err
	}
	observation, err := parse(overlay.Health.ObservationMaxAge)
	if err != nil {
		return productionControllerTimings{}, err
	}
	fenceLock, err := parse(overlay.Fence.LockPollInterval)
	if err != nil {
		return productionControllerTimings{}, err
	}
	fenceRenewal, err := parse(overlay.Fence.RenewalInterval)
	if err != nil {
		return productionControllerTimings{}, err
	}
	fenceTimeout, err := parse(overlay.Fence.RenewalTimeout)
	if err != nil {
		return productionControllerTimings{}, err
	}
	return productionControllerTimings{
		operation:             operation,
		reconciliation:        reconciliation,
		reconciliationCadence: cadence,
		shutdown:              shutdown,
		observationMaxAge:     observation,
		fenceLock:             fenceLock,
		fenceRenewal:          fenceRenewal,
		fenceTimeout:          fenceTimeout,
	}, nil
}

func productionDisabledPolicy(
	overlay hostruntime.PrivateOverlay,
) (controller.AcquisitionPolicy, error) {
	policies := make(
		[]controller.RepositoryPolicySummary,
		len(overlay.Repositories),
	)
	for index, repository := range overlay.Repositories {
		policies[index] = controller.RepositoryPolicySummary{
			Alias:          repository.Alias,
			MaxConcurrency: repository.MaxConcurrency,
			Eligibility:    repository.Eligibility,
		}
	}
	return controller.CanonicalizeAcquisitionPolicy(
		controller.AcquisitionPolicy{
			Mode:                     controller.AcquisitionDisabled,
			RepositoryPolicyRevision: overlay.Resources.PolicyRevision,
			RepositoryPolicies:       policies,
		},
	)
}

func validateProductionControllerPaths(
	overlay hostruntime.PrivateOverlay,
	expectedUID uint32,
) error {
	if filepath.Dir(overlay.Paths.DatabasePath) != overlay.Paths.StateRoot ||
		filepath.Dir(overlay.Paths.AdminSocketPath) != overlay.Paths.StateRoot ||
		filepath.Dir(overlay.Paths.HealthSocketPath) != overlay.Paths.StateRoot {
		return errCommandUnavailable
	}
	for _, path := range []string{
		overlay.Paths.StateRoot,
		overlay.Paths.FenceRoot,
		overlay.Paths.BrokerRoot,
		overlay.Paths.SeccompRoot,
	} {
		fd, err := openProductionPrivateDirectory(path, expectedUID)
		if err == nil {
			err = unix.Close(fd)
		}
		if err != nil {
			return errCommandUnavailable
		}
	}
	var database unix.Stat_t
	if err := unix.Lstat(overlay.Paths.DatabasePath, &database); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return errCommandUnavailable
	}
	mode := uint32(database.Mode)
	if mode&unix.S_IFMT != unix.S_IFREG ||
		mode&0o777 != 0o600 ||
		database.Uid != expectedUID ||
		uint64(database.Nlink) != 1 ||
		database.Ino == 0 {
		return errCommandUnavailable
	}
	return nil
}

func openProductionPrivateDirectory(
	path string,
	expectedUID uint32,
) (int, error) {
	if !canonicalAbsolutePath(path) || path == "/" {
		return -1, errCommandUnavailable
	}
	fd, err := unix.Open(
		"/",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, errCommandUnavailable
	}
	for _, component := range strings.Split(
		strings.TrimPrefix(path, "/"),
		"/",
	) {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return -1, errCommandUnavailable
		}
		next, openErr := unix.Openat(
			fd,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		closeErr := unix.Close(fd)
		if openErr != nil || closeErr != nil {
			if openErr == nil {
				_ = unix.Close(next)
			}
			return -1, errCommandUnavailable
		}
		fd = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, errCommandUnavailable
	}
	mode := uint32(stat.Mode)
	if mode&unix.S_IFMT != unix.S_IFDIR ||
		mode&0o777 != 0o700 ||
		stat.Uid != expectedUID ||
		stat.Ino == 0 {
		_ = unix.Close(fd)
		return -1, errCommandUnavailable
	}
	return fd, nil
}

func portableOwner(fleet fleetfence.Fleet, owner string) string {
	if fleet == fleetfence.FleetPortable {
		return owner
	}
	return ""
}

func portablePID(fleet fleetfence.Fleet, pid int) int {
	if fleet == fleetfence.FleetPortable {
		return pid
	}
	return 0
}

type productionControllerResources struct {
	closers []io.Closer
}

func (resources *productionControllerResources) Add(closer io.Closer) {
	resources.closers = append(resources.closers, closer)
}

func (resources *productionControllerResources) Close() error {
	if resources == nil {
		return nil
	}
	var result error
	for index := len(resources.closers) - 1; index >= 0; index-- {
		result = errors.Join(result, resources.closers[index].Close())
	}
	resources.closers = nil
	return result
}

func controllerManifestMatchesOverlay(
	manifest hostruntime.RuntimeManifest,
	overlay hostruntime.PrivateOverlay,
) bool {
	return manifest.EgressMode == overlay.Docker.BrokerNetworkID &&
		manifest.PolicyManifestDigest == overlay.Policy.ManifestDigest &&
		imageReferenceMatchesDigest(
			overlay.Docker.RunnerImage,
			manifest.RunnerImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.AdapterImage,
			manifest.AdapterImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.BrokerImage,
			manifest.BrokerImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.HelperImage,
			manifest.HelperImageDigest,
		) &&
		imageReferenceMatchesDigest(
			overlay.Docker.VerifierImage,
			manifest.VerifierImageDigest,
		)
}

func imageReferenceMatchesDigest(reference string, digest string) bool {
	return strings.HasSuffix(reference, "@"+digest) &&
		len(reference) > len(digest)+1
}

func currentControllerExecutableDigest() (string, error) {
	fd, err := unix.Open(
		"/proc/self/exe",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "controller-executable")
	if file == nil {
		_ = unix.Close(fd)
		return "", errCommandUnavailable
	}
	defer file.Close()
	before, err := pinnedRootFileIdentity(fd, 0o500)
	if err != nil || before.size <= 0 || before.size > 1<<30 {
		return "", errCommandUnavailable
	}
	document, err := io.ReadAll(io.LimitReader(file, 1<<30+1))
	if err != nil || len(document) == 0 || len(document) > 1<<30 {
		return "", errCommandUnavailable
	}
	after, err := pinnedRootFileIdentity(fd, 0o500)
	if err != nil || before != after || int64(len(document)) != before.size {
		return "", errCommandUnavailable
	}
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:]), nil
}

func readPinnedRootFile(
	path string,
	mode uint32,
	maxBytes int,
) ([]byte, error) {
	if !canonicalAbsolutePath(path) || maxBytes <= 0 {
		return nil, errCommandUnavailable
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, errCommandUnavailable
	}
	file := os.NewFile(uintptr(fd), "private-runtime")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errCommandUnavailable
	}
	defer file.Close()
	before, err := pinnedRootFileIdentity(fd, mode)
	if err != nil || before.size <= 0 || before.size > int64(maxBytes) {
		return nil, errCommandUnavailable
	}
	document, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(document) == 0 || len(document) > maxBytes {
		return nil, errCommandUnavailable
	}
	after, err := pinnedRootFileIdentity(fd, mode)
	if err != nil || before != after || int64(len(document)) != before.size {
		return nil, errCommandUnavailable
	}
	var pathStat unix.Stat_t
	if err := unix.Lstat(path, &pathStat); err != nil {
		return nil, errCommandUnavailable
	}
	pathIdentity, err := validatePinnedRootStat(&pathStat, mode)
	if err != nil || pathIdentity != before {
		return nil, errCommandUnavailable
	}
	return document, nil
}

type pinnedRootIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	nlink  uint64
	size   int64
}

func pinnedRootFileIdentity(
	fd int,
	mode uint32,
) (pinnedRootIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return pinnedRootIdentity{}, errCommandUnavailable
	}
	return validatePinnedRootStat(&stat, mode)
}

func validatePinnedRootStat(
	stat *unix.Stat_t,
	mode uint32,
) (pinnedRootIdentity, error) {
	statMode := uint32(stat.Mode)
	if statMode&unix.S_IFMT != unix.S_IFREG ||
		statMode&0o777 != mode ||
		stat.Uid != 0 ||
		uint64(stat.Nlink) != 1 ||
		stat.Ino == 0 ||
		int64(stat.Size) < 0 {
		return pinnedRootIdentity{}, errCommandUnavailable
	}
	return pinnedRootIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		mode:   statMode,
		nlink:  uint64(stat.Nlink),
		size:   int64(stat.Size),
	}, nil
}

func canonicalAbsolutePath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsRune(path, 0)
}

var _ controllerProcess = (*disabledControllerProcess)(nil)
