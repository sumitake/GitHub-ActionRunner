package productionruntime

import (
	"context"
	"errors"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

var (
	ErrProcessAuthorityInvalid = errors.New(
		"productionruntime: process authority invalid",
	)
	ErrProcessIdentityDrift = errors.New(
		"productionruntime: process identity drift",
	)
	ErrProcessObservationUnavailable = errors.New(
		"productionruntime: process observation unavailable",
	)
	ErrProcessStartFailed = errors.New(
		"productionruntime: process start failed",
	)
	ErrProcessStopFailed = errors.New(
		"productionruntime: process stop failed",
	)
	ErrProcessTimeout = errors.New(
		"productionruntime: process timeout",
	)
)

type ProcessState string

const (
	ProcessAbsent    ProcessState = "absent"
	ProcessRunning   ProcessState = "running"
	ProcessUnhealthy ProcessState = "unhealthy"
)

type ProcessSignal uint8

const (
	ProcessSignalTerminate ProcessSignal = iota + 1
	ProcessSignalKill
)

type ProcessBinding struct {
	PrivateOverlayRevision string
	ManifestDigest         string
	ActiveFleet            fleetfence.Fleet
	FenceGeneration        uint64
}

// ControllerLaunch is the only process shape visible to the authority. The
// kernel adapter constructs the fixed controller argv and minimal environment;
// no arbitrary argv or environment reaches this package.
type ControllerLaunch struct {
	ControllerBinary string
	PrivateOverlay   string
	DatabasePath     string
	StdoutLog        string
	StderrLog        string
	ExecutableDigest string
}

type ProcessTiming struct {
	PollInterval time.Duration
	TermGrace    time.Duration
	KillGrace    time.Duration
	CleanupGrace time.Duration
}

type ProcessInspection struct {
	State           ProcessState
	ProcessIdentity string
}

type ProcessObservation struct {
	Present bool
	Start   hostruntime.ProcessStartObservation
}

type ProcessRecordStore interface {
	Read(context.Context) (ProcessRecord, string, bool, error)
	Create(context.Context, ProcessRecord) (string, error)
	Remove(context.Context, string) error
}

type ProcessKernel interface {
	LaunchDisabled(
		context.Context,
		ControllerLaunch,
	) (hostruntime.ProcessStartObservation, uint64, error)
	Observe(context.Context, uint64) (ProcessObservation, error)
	SignalGroup(context.Context, uint64, ProcessSignal) error
	GroupAbsent(context.Context, uint64) (bool, error)
	// CleanupStarted terminates the exact child returned by LaunchDisabled and
	// returns nil only after the child and its dedicated process group are
	// positively absent.
	CleanupStarted(context.Context, uint64, uint64) error
}

type ProcessAuthorityConfig struct {
	Store   ProcessRecordStore
	Kernel  ProcessKernel
	Binding ProcessBinding
	Launch  ControllerLaunch
	Timing  ProcessTiming
}

type ProcessAuthority struct {
	store   ProcessRecordStore
	kernel  ProcessKernel
	binding ProcessBinding
	launch  ControllerLaunch
	timing  ProcessTiming
}

func NewProcessAuthority(
	config ProcessAuthorityConfig,
) (*ProcessAuthority, error) {
	if config.Store == nil ||
		config.Kernel == nil ||
		!validProcessBinding(config.Binding) ||
		!validControllerLaunch(config.Launch) ||
		!validProcessTiming(config.Timing) {
		return nil, ErrProcessAuthorityInvalid
	}
	return &ProcessAuthority{
		store:   config.Store,
		kernel:  config.Kernel,
		binding: config.Binding,
		launch:  config.Launch,
		timing:  config.Timing,
	}, nil
}

func (authority *ProcessAuthority) Inspect(
	ctx context.Context,
) (ProcessInspection, error) {
	if authority == nil || ctx == nil {
		return ProcessInspection{State: ProcessUnhealthy},
			ErrProcessAuthorityInvalid
	}
	if err := ctx.Err(); err != nil {
		return ProcessInspection{State: ProcessUnhealthy},
			errors.Join(ErrProcessObservationUnavailable, err)
	}
	record, identity, present, err := authority.store.Read(ctx)
	if err != nil {
		return ProcessInspection{State: ProcessUnhealthy},
			ErrProcessObservationUnavailable
	}
	if !present {
		return ProcessInspection{State: ProcessAbsent}, nil
	}
	if !processRecordMatchesBinding(record, authority.binding) {
		return ProcessInspection{State: ProcessUnhealthy},
			ErrProcessIdentityDrift
	}
	observation, err := authority.stableObserve(ctx, record.PID)
	if err != nil {
		return ProcessInspection{State: ProcessUnhealthy}, err
	}
	if !observation.Present ||
		!processObservationMatchesRecord(observation.Start, record) {
		return ProcessInspection{State: ProcessUnhealthy},
			ErrProcessIdentityDrift
	}
	return ProcessInspection{
		State:           ProcessRunning,
		ProcessIdentity: identity,
	}, nil
}

func (authority *ProcessAuthority) StartDisabled(
	ctx context.Context,
) (ProcessInspection, error) {
	if authority == nil || ctx == nil {
		return ProcessInspection{}, ErrProcessAuthorityInvalid
	}
	if err := ctx.Err(); err != nil {
		return ProcessInspection{}, errors.Join(ErrProcessStartFailed, err)
	}
	inspection, err := authority.Inspect(ctx)
	if err != nil || inspection.State != ProcessAbsent {
		return ProcessInspection{}, ErrProcessStartFailed
	}

	launched, pgid, err := authority.kernel.LaunchDisabled(
		ctx,
		authority.launch,
	)
	if err != nil {
		return ProcessInspection{}, ErrProcessStartFailed
	}
	if !validLaunchedController(launched, pgid, authority.launch) {
		return ProcessInspection{}, authority.cleanupStartFailure(
			launched.PID,
			pgid,
			"",
			false,
		)
	}
	observed, err := authority.stableObserve(ctx, launched.PID)
	if err != nil ||
		!observed.Present ||
		observed.Start != launched {
		return ProcessInspection{}, authority.cleanupStartFailure(
			launched.PID,
			pgid,
			"",
			false,
		)
	}

	record := processRecordFromLaunch(
		launched,
		pgid,
		authority.binding,
	)
	_, expectedIdentity, err := MarshalProcessRecord(record)
	if err != nil {
		return ProcessInspection{}, authority.cleanupStartFailure(
			launched.PID,
			pgid,
			"",
			false,
		)
	}
	identity, err := authority.store.Create(ctx, record)
	if err != nil || identity != expectedIdentity {
		return ProcessInspection{}, authority.cleanupAmbiguousCreate(
			launched.PID,
			pgid,
			record,
			expectedIdentity,
		)
	}
	if err := authority.proveRunningExact(
		ctx,
		record,
		identity,
		launched,
	); err != nil {
		return ProcessInspection{}, authority.cleanupStartFailure(
			launched.PID,
			pgid,
			identity,
			true,
		)
	}
	return ProcessInspection{
		State:           ProcessRunning,
		ProcessIdentity: identity,
	}, nil
}

func (authority *ProcessAuthority) Stop(
	ctx context.Context,
	expectedIdentity string,
) error {
	if authority == nil ||
		ctx == nil ||
		!lowerHexDigest(expectedIdentity) {
		return ErrProcessAuthorityInvalid
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrProcessStopFailed, err)
	}
	record, err := authority.readExact(ctx, expectedIdentity)
	if err != nil {
		return err
	}
	if !processRecordMatchesBinding(record, authority.binding) {
		return ErrProcessIdentityDrift
	}

	present, err := authority.preSignal(
		ctx,
		record,
		expectedIdentity,
	)
	if err != nil {
		return err
	}
	if present {
		if err := authority.kernel.SignalGroup(
			ctx,
			record.PGID,
			ProcessSignalTerminate,
		); err != nil {
			return ErrProcessStopFailed
		}
		present, err = authority.waitDirect(
			ctx,
			record,
			authority.timing.TermGrace,
		)
		if err != nil {
			return err
		}
	}
	if present {
		present, err = authority.preSignal(
			ctx,
			record,
			expectedIdentity,
		)
		if err != nil {
			return err
		}
		if present {
			if err := authority.kernel.SignalGroup(
				ctx,
				record.PGID,
				ProcessSignalKill,
			); err != nil {
				return ErrProcessStopFailed
			}
			present, err = authority.waitDirect(
				ctx,
				record,
				authority.timing.KillGrace,
			)
			if err != nil {
				return err
			}
			if present {
				return ErrProcessTimeout
			}
		}
	}
	if err := authority.waitGroupAbsent(
		ctx,
		record.PGID,
		authority.timing.CleanupGrace,
	); err != nil {
		return err
	}
	if err := authority.store.Remove(ctx, expectedIdentity); err != nil {
		return ErrProcessStopFailed
	}
	_, _, stillPresent, err := authority.store.Read(ctx)
	if err != nil || stillPresent {
		return ErrProcessStopFailed
	}
	return nil
}

func (authority *ProcessAuthority) stableObserve(
	ctx context.Context,
	pid uint64,
) (ProcessObservation, error) {
	first, err := authority.kernel.Observe(ctx, pid)
	if err != nil {
		return ProcessObservation{}, ErrProcessObservationUnavailable
	}
	second, err := authority.kernel.Observe(ctx, pid)
	if err != nil {
		return ProcessObservation{}, ErrProcessObservationUnavailable
	}
	if first != second ||
		first.Present && first.Start.PID != pid ||
		!first.Present && first.Start != (hostruntime.ProcessStartObservation{}) {
		return ProcessObservation{}, ErrProcessIdentityDrift
	}
	return second, nil
}

func (authority *ProcessAuthority) preSignal(
	ctx context.Context,
	record ProcessRecord,
	expectedIdentity string,
) (bool, error) {
	observation, err := authority.stableObserve(ctx, record.PID)
	if err != nil {
		return false, err
	}
	if !observation.Present {
		return false, nil
	}
	if !processObservationMatchesRecord(observation.Start, record) {
		return false, ErrProcessIdentityDrift
	}
	exact, err := authority.readExact(ctx, expectedIdentity)
	if err != nil || exact != record {
		return false, ErrProcessIdentityDrift
	}
	return true, nil
}

func (authority *ProcessAuthority) waitDirect(
	ctx context.Context,
	record ProcessRecord,
	bound time.Duration,
) (bool, error) {
	timer := time.NewTimer(bound)
	defer timer.Stop()
	for {
		observation, err := authority.stableObserve(ctx, record.PID)
		if err != nil {
			return false, err
		}
		if !observation.Present {
			return false, nil
		}
		if !processObservationMatchesRecord(observation.Start, record) {
			return false, ErrProcessIdentityDrift
		}
		select {
		case <-ctx.Done():
			return false, errors.Join(ErrProcessStopFailed, ctx.Err())
		case <-timer.C:
			return true, nil
		case <-time.After(authority.timing.PollInterval):
		}
	}
}

func (authority *ProcessAuthority) waitGroupAbsent(
	ctx context.Context,
	pgid uint64,
	bound time.Duration,
) error {
	timer := time.NewTimer(bound)
	defer timer.Stop()
	for {
		absent, err := authority.kernel.GroupAbsent(ctx, pgid)
		if err != nil {
			return ErrProcessStopFailed
		}
		if absent {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ErrProcessStopFailed, ctx.Err())
		case <-timer.C:
			return ErrProcessTimeout
		case <-time.After(authority.timing.PollInterval):
		}
	}
}

func (authority *ProcessAuthority) readExact(
	ctx context.Context,
	expectedIdentity string,
) (ProcessRecord, error) {
	record, identity, present, err := authority.store.Read(ctx)
	if err != nil {
		return ProcessRecord{}, ErrProcessObservationUnavailable
	}
	if !present || identity != expectedIdentity {
		return ProcessRecord{}, ErrProcessIdentityDrift
	}
	return record, nil
}

func (authority *ProcessAuthority) proveRunningExact(
	ctx context.Context,
	expectedRecord ProcessRecord,
	expectedIdentity string,
	expectedStart hostruntime.ProcessStartObservation,
) error {
	record, err := authority.readExact(ctx, expectedIdentity)
	if err != nil || record != expectedRecord {
		return ErrProcessIdentityDrift
	}
	observation, err := authority.stableObserve(ctx, record.PID)
	if err != nil ||
		!observation.Present ||
		observation.Start != expectedStart ||
		!processObservationMatchesRecord(observation.Start, record) {
		return ErrProcessIdentityDrift
	}
	return nil
}

func (authority *ProcessAuthority) cleanupStartFailure(
	pid uint64,
	pgid uint64,
	identity string,
	recordCreated bool,
) error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		authority.timing.CleanupGrace,
	)
	defer cancel()
	if err := authority.kernel.CleanupStarted(ctx, pid, pgid); err != nil {
		return ErrProcessStartFailed
	}
	if recordCreated {
		if err := authority.store.Remove(ctx, identity); err != nil {
			return ErrProcessStartFailed
		}
		_, _, present, err := authority.store.Read(ctx)
		if err != nil || present {
			return ErrProcessStartFailed
		}
	}
	return ErrProcessStartFailed
}

func (authority *ProcessAuthority) cleanupAmbiguousCreate(
	pid uint64,
	pgid uint64,
	expectedRecord ProcessRecord,
	expectedIdentity string,
) error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		authority.timing.CleanupGrace,
	)
	defer cancel()
	if err := authority.kernel.CleanupStarted(ctx, pid, pgid); err != nil {
		return ErrProcessStartFailed
	}
	record, identity, present, err := authority.store.Read(ctx)
	if err != nil {
		return ErrProcessStartFailed
	}
	if !present {
		return ErrProcessStartFailed
	}
	if record != expectedRecord || identity != expectedIdentity {
		return ErrProcessStartFailed
	}
	if err := authority.store.Remove(ctx, expectedIdentity); err != nil {
		return ErrProcessStartFailed
	}
	_, _, present, err = authority.store.Read(ctx)
	if err != nil || present {
		return ErrProcessStartFailed
	}
	return ErrProcessStartFailed
}

func validProcessBinding(binding ProcessBinding) bool {
	return lowerHexDigest(binding.PrivateOverlayRevision) &&
		lowerHexDigest(binding.ManifestDigest) &&
		(binding.ActiveFleet == fleetfence.FleetPortable ||
			binding.ActiveFleet == fleetfence.FleetLegacy) &&
		binding.FenceGeneration > 0
}

func validControllerLaunch(launch ControllerLaunch) bool {
	paths := [...]string{
		launch.ControllerBinary,
		launch.PrivateOverlay,
		launch.DatabasePath,
		launch.StdoutLog,
		launch.StderrLog,
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !canonicalPath(path) || path == "/" {
			return false
		}
		if _, exists := seen[path]; exists {
			return false
		}
		seen[path] = struct{}{}
	}
	return lowerHexDigest(launch.ExecutableDigest)
}

func validProcessTiming(timing ProcessTiming) bool {
	const maxProcessDuration = 10 * time.Minute
	return timing.PollInterval > 0 &&
		timing.PollInterval <= time.Second &&
		timing.TermGrace > 0 &&
		timing.TermGrace <= maxProcessDuration &&
		timing.KillGrace > 0 &&
		timing.KillGrace <= maxProcessDuration &&
		timing.CleanupGrace > 0 &&
		timing.CleanupGrace <= maxProcessDuration
}

func validLaunchedController(
	observation hostruntime.ProcessStartObservation,
	pgid uint64,
	launch ControllerLaunch,
) bool {
	_, err := hostruntime.DeriveProcessStartIdentity(observation)
	return err == nil &&
		observation.PID > 0 &&
		pgid == observation.PID &&
		observation.ExecutableDigest == launch.ExecutableDigest &&
		observation.ExecutableDevice > 0 &&
		observation.ExecutableInode > 0 &&
		observation.ExecutableFileSize > 0
}

func processRecordFromLaunch(
	observation hostruntime.ProcessStartObservation,
	pgid uint64,
	binding ProcessBinding,
) ProcessRecord {
	return ProcessRecord{
		SchemaVersion:          processRecordSchemaVersion,
		PID:                    observation.PID,
		PGID:                   pgid,
		StartTimeTicks:         observation.StartTimeTicks,
		ExecutableDigest:       observation.ExecutableDigest,
		ExecutableDevice:       observation.ExecutableDevice,
		ExecutableInode:        observation.ExecutableInode,
		PrivateOverlayRevision: binding.PrivateOverlayRevision,
		ManifestDigest:         binding.ManifestDigest,
		ActiveFleet:            binding.ActiveFleet,
		FenceGeneration:        binding.FenceGeneration,
	}
}

func processRecordMatchesBinding(
	record ProcessRecord,
	binding ProcessBinding,
) bool {
	return record.PrivateOverlayRevision ==
		binding.PrivateOverlayRevision &&
		record.ManifestDigest == binding.ManifestDigest &&
		record.ActiveFleet == binding.ActiveFleet &&
		record.FenceGeneration == binding.FenceGeneration
}

func processObservationMatchesRecord(
	observation hostruntime.ProcessStartObservation,
	record ProcessRecord,
) bool {
	return observation.PID == record.PID &&
		observation.StartTimeTicks == record.StartTimeTicks &&
		observation.ExecutableDigest == record.ExecutableDigest &&
		observation.ExecutableDevice == record.ExecutableDevice &&
		observation.ExecutableInode == record.ExecutableInode
}
