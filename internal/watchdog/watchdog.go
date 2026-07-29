// Package watchdog owns the narrow, disabled-only controller supervision
// state machine. It cannot advance lifecycle journals, stage images, hand
// fences, select releases, or contact an external service.
package watchdog

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidConfiguration = errors.New("watchdog: invalid configuration")
	ErrLifecycleOwned       = errors.New("watchdog: lifecycle owned")
	ErrSupervisionFailed    = errors.New("watchdog: supervision failed")
)

type ProcessState string
type Fleet string

const (
	FleetNone     Fleet = "none"
	FleetPortable Fleet = "portable"
	FleetLegacy   Fleet = "legacy"
)

const (
	ProcessAbsent    ProcessState = "absent"
	ProcessRunning   ProcessState = "running"
	ProcessUnhealthy ProcessState = "unhealthy"
)

type Observation struct {
	FenceGeneration uint64
	ActiveFleet     Fleet
	Process         ProcessState
	ProcessIdentity string
}

type DisabledProof struct {
	FenceGeneration      uint64
	ActiveFleet          Fleet
	ProcessIdentity      string
	PolicyDisabled       bool
	PendingAcquisitions  uint64
	ActiveListeners      uint64
	ManagedProcesses     uint64
	AcquisitionProcesses uint64
}

// Supervisor is the complete watchdog authority. It deliberately omits
// install, select, fence handoff, image, journal, and arbitrary command APIs.
type Supervisor interface {
	Inspect(context.Context) (Observation, error)
	SafeStop(context.Context, Observation) error
	StartDisabled(context.Context, Observation) (Observation, error)
	ProveDisabled(context.Context, Observation) (DisabledProof, error)
}

type StorageEnvelope interface {
	Revalidate(context.Context) error
}

// LifecycleGate is the complete lifecycle dependency visible to the
// watchdog. An adapter may read the durable journal and reservation codecs,
// but this package cannot import or call their mutation engine.
type LifecycleGate interface {
	Acquire(context.Context, time.Duration) (LifecycleLease, error)
}

type LifecycleLease interface {
	Validate() error
	Owned() (bool, error)
	Close() error
}

type Status string
type Reason string

const (
	StatusOK          Status = "ok"
	StatusRecoverable Status = "recoverable"
	StatusFailed      Status = "failed"
)

const (
	ReasonHealthy        Reason = "disabled-and-zero"
	ReasonRestarted      Reason = "restarted-disabled"
	ReasonStoppedAtNone  Reason = "stopped-at-none"
	ReasonLifecycleOwned Reason = "lifecycle-owned"
	ReasonLifecycleBusy  Reason = "lifecycle-busy"
	ReasonStorageStop    Reason = "storage-stop"
	ReasonInspectFailed  Reason = "inspect-failed"
	ReasonStopFailed     Reason = "safe-stop-failed"
	ReasonStartFailed    Reason = "disabled-start-failed"
	ReasonProofFailed    Reason = "disabled-proof-failed"
	ReasonIdentityDrift  Reason = "process-identity-drift"
)

type Result struct {
	Status          Status `json:"status"`
	Reason          Reason `json:"reason"`
	FenceGeneration uint64 `json:"fence_generation"`
	ActiveFleet     Fleet  `json:"active_fleet"`
}

type Watchdog struct {
	Lifecycle    LifecycleGate
	Supervisor   Supervisor
	Storage      StorageEnvelope
	PollInterval time.Duration
}

func (watchdog Watchdog) RunCycle(
	ctx context.Context,
) (Result, error) {
	if ctx == nil ||
		watchdog.Lifecycle == nil ||
		watchdog.Supervisor == nil ||
		watchdog.Storage == nil ||
		watchdog.PollInterval <= 0 ||
		watchdog.PollInterval > time.Second {
		return Result{
			Status: StatusFailed,
			Reason: ReasonInspectFailed,
		}, ErrInvalidConfiguration
	}
	lease, err := watchdog.Lifecycle.Acquire(ctx, watchdog.PollInterval)
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return Result{
				Status: StatusRecoverable,
				Reason: ReasonLifecycleBusy,
			}, ErrLifecycleOwned
		}
		return Result{
			Status: StatusFailed,
			Reason: ReasonInspectFailed,
		}, ErrSupervisionFailed
	}
	defer lease.Close()
	if err := lease.Validate(); err != nil {
		return Result{
			Status: StatusFailed,
			Reason: ReasonInspectFailed,
		}, ErrSupervisionFailed
	}
	owned, err := lease.Owned()
	if err != nil {
		return Result{
			Status: StatusFailed,
			Reason: ReasonInspectFailed,
		}, ErrSupervisionFailed
	}
	if owned {
		return Result{
			Status: StatusRecoverable,
			Reason: ReasonLifecycleOwned,
		}, ErrLifecycleOwned
	}
	if err := watchdog.Storage.Revalidate(ctx); err != nil {
		return Result{
			Status: StatusRecoverable,
			Reason: ReasonStorageStop,
		}, ErrSupervisionFailed
	}
	observation, err := watchdog.Supervisor.Inspect(ctx)
	if err != nil || validateObservation(observation) != nil {
		return Result{
			Status: StatusFailed,
			Reason: ReasonInspectFailed,
		}, ErrSupervisionFailed
	}
	base := Result{
		FenceGeneration: observation.FenceGeneration,
		ActiveFleet:     observation.ActiveFleet,
	}
	if observation.ActiveFleet == FleetNone {
		if observation.Process != ProcessAbsent {
			if err := watchdog.Supervisor.SafeStop(
				ctx,
				observation,
			); err != nil {
				base.Status = StatusFailed
				base.Reason = ReasonStopFailed
				return base, ErrSupervisionFailed
			}
			after, err := watchdog.Supervisor.Inspect(ctx)
			if err != nil ||
				validateObservation(after) != nil ||
				after.ActiveFleet != FleetNone ||
				after.FenceGeneration != observation.FenceGeneration ||
				after.Process != ProcessAbsent {
				base.Status = StatusFailed
				base.Reason = ReasonProofFailed
				return base, ErrSupervisionFailed
			}
		}
		base.Status = StatusOK
		base.Reason = ReasonStoppedAtNone
		return base, nil
	}
	if observation.Process == ProcessRunning {
		if err := watchdog.proveDisabled(ctx, observation); err != nil {
			base.Status = StatusRecoverable
			base.Reason = ReasonProofFailed
			return base, ErrSupervisionFailed
		}
		base.Status = StatusOK
		base.Reason = ReasonHealthy
		return base, nil
	}
	if observation.Process == ProcessUnhealthy {
		if err := watchdog.Supervisor.SafeStop(
			ctx,
			observation,
		); err != nil {
			base.Status = StatusFailed
			base.Reason = ReasonStopFailed
			return base, ErrSupervisionFailed
		}
		stopped, err := watchdog.Supervisor.Inspect(ctx)
		if err != nil ||
			validateObservation(stopped) != nil ||
			stopped.FenceGeneration != observation.FenceGeneration ||
			stopped.ActiveFleet != observation.ActiveFleet ||
			stopped.Process != ProcessAbsent {
			base.Status = StatusFailed
			base.Reason = ReasonProofFailed
			return base, ErrSupervisionFailed
		}
		observation = stopped
	}
	started, err := watchdog.Supervisor.StartDisabled(ctx, observation)
	if err != nil ||
		validateObservation(started) != nil ||
		started.FenceGeneration != observation.FenceGeneration ||
		started.ActiveFleet != observation.ActiveFleet ||
		started.Process != ProcessRunning ||
		started.ProcessIdentity == observation.ProcessIdentity {
		base.Status = StatusFailed
		base.Reason = ReasonStartFailed
		return base, ErrSupervisionFailed
	}
	if err := watchdog.proveDisabled(ctx, started); err != nil {
		base.Status = StatusRecoverable
		base.Reason = ReasonProofFailed
		return base, ErrSupervisionFailed
	}
	base.Status = StatusOK
	base.Reason = ReasonRestarted
	return base, nil
}

func (watchdog Watchdog) proveDisabled(
	ctx context.Context,
	observation Observation,
) error {
	proof, err := watchdog.Supervisor.ProveDisabled(ctx, observation)
	if err != nil ||
		proof.FenceGeneration != observation.FenceGeneration ||
		proof.ActiveFleet != observation.ActiveFleet ||
		proof.ProcessIdentity != observation.ProcessIdentity ||
		!proof.PolicyDisabled ||
		proof.PendingAcquisitions != 0 ||
		proof.ActiveListeners != 0 ||
		proof.AcquisitionProcesses != 0 {
		return ErrSupervisionFailed
	}
	if observation.ActiveFleet == FleetPortable &&
		proof.ManagedProcesses == 0 {
		return ErrSupervisionFailed
	}
	return nil
}

func validateObservation(observation Observation) error {
	if observation.ActiveFleet != FleetNone &&
		observation.ActiveFleet != FleetPortable &&
		observation.ActiveFleet != FleetLegacy {
		return ErrSupervisionFailed
	}
	switch observation.Process {
	case ProcessAbsent:
		if observation.ProcessIdentity != "" {
			return ErrSupervisionFailed
		}
	case ProcessRunning, ProcessUnhealthy:
		if len(observation.ProcessIdentity) != 64 {
			return ErrSupervisionFailed
		}
		for _, character := range observation.ProcessIdentity {
			if character < '0' ||
				character > '9' && character < 'a' ||
				character > 'f' {
				return ErrSupervisionFailed
			}
		}
	default:
		return ErrSupervisionFailed
	}
	return nil
}
