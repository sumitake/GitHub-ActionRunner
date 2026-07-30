package testenv

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

const task11LossAttemptDigestDomain = "portable-ghar.task11.loss-attempt.v1\x00"

type task11MissingPreparedFact uint8

const (
	task11MissingRunnerComponent task11MissingPreparedFact = iota + 1
	task11MissingPolicyApplication
	task11MissingFinalNamespaceState
	task11MissingBrokerAuditEvidence
)

func task11AllowedMissingPreparedFacts() []task11MissingPreparedFact {
	return []task11MissingPreparedFact{
		task11MissingRunnerComponent,
		task11MissingPolicyApplication,
		task11MissingFinalNamespaceState,
		task11MissingBrokerAuditEvidence,
	}
}

func validTask11MissingPreparedFact(fact task11MissingPreparedFact) bool {
	return fact >= task11MissingRunnerComponent &&
		fact <= task11MissingBrokerAuditEvidence
}

// omitReleasePreparedFact removes exactly one closed fact from the
// test-local recording view immediately before StageRunnerAuthorize. It does
// not alter the opaque engine handles used by production cleanup.
func (e *recordingEngine) omitReleasePreparedFact(
	runnerID string,
	fact task11MissingPreparedFact,
) error {
	if e == nil ||
		!isLowerHex(runnerID, sha256.Size*2) ||
		!validTask11MissingPreparedFact(fact) {
		return ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	runner := e.handles[runnerID]
	if runner == nil ||
		runner.handle.kind != CleanupRunner ||
		runner.handle.id != runnerID ||
		runner.busy ||
		runner.removed ||
		runner.auditCount != 1 ||
		!isLowerHex(runner.auditDigest, sha256.Size*2) ||
		!isLowerHex(runner.parentAdapter, sha256.Size*2) ||
		runner.armReceipt == "" ||
		runner.finalNamespaceReceipt == "" ||
		runner.releaseAuthorizationReceipt != "" ||
		!e.releasePreparedViewCompleteLocked(runner) {
		return ErrFixtureStart
	}
	switch fact {
	case task11MissingRunnerComponent:
		runner.parentAdapter = ""
	case task11MissingPolicyApplication:
		broker := e.uniqueActiveBrokerForAdapterLocked(
			runner.parentAdapter,
		)
		if broker == nil {
			return ErrFixtureStart
		}
		broker.policyApplicationDigest = ""
	case task11MissingFinalNamespaceState:
		runner.finalNamespaceReceipt = ""
	case task11MissingBrokerAuditEvidence:
		broker := e.uniqueActiveBrokerForAdapterLocked(
			runner.parentAdapter,
		)
		if broker == nil {
			return ErrFixtureStart
		}
		broker.auditDigest = ""
	default:
		return ErrFixtureStart
	}
	return nil
}

func (e *recordingEngine) uniqueActiveBrokerForAdapterLocked(
	adapterID string,
) *recordedRuntimeHandle {
	if e == nil || !isLowerHex(adapterID, sha256.Size*2) {
		return nil
	}
	var broker *recordedRuntimeHandle
	for _, candidate := range e.handles {
		if candidate.handle.kind != CleanupBroker ||
			candidate.parentAdapter != adapterID ||
			candidate.busy ||
			candidate.removed {
			continue
		}
		if broker != nil {
			return nil
		}
		broker = candidate
	}
	return broker
}

// task11ReleaseLossEngine wraps the real recording engine only for the
// independent loss-prevention orchestration. The first held-runner audit is
// the final-audit input. Immediately before the second audit, which is the
// StageRunnerAuthorize readback, it removes one allowed fact. Every other
// method remains the production engine method through interface embedding.
type task11ReleaseLossEngine struct {
	hostruntime.Engine
	recording *recordingEngine
	fact      task11MissingPreparedFact

	mu           sync.Mutex
	auditCalls   uint32
	releaseCalls uint32
	injected     bool
}

func newTask11ReleaseLossEngine(
	engine *recordingEngine,
	fact task11MissingPreparedFact,
) (*task11ReleaseLossEngine, error) {
	if engine == nil || !validTask11MissingPreparedFact(fact) {
		return nil, ErrFixtureStart
	}
	return &task11ReleaseLossEngine{
		Engine:    engine,
		recording: engine,
		fact:      fact,
	}, nil
}

func (e *task11ReleaseLossEngine) AuditHeldRunner(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
) (hostruntime.HeldRunnerAudit, error) {
	if e == nil || e.Engine == nil || e.recording == nil {
		return hostruntime.HeldRunnerAudit{}, ErrFixtureStart
	}
	e.mu.Lock()
	call := e.auditCalls
	e.auditCalls++
	if call == 1 {
		if e.injected {
			e.mu.Unlock()
			return hostruntime.HeldRunnerAudit{}, ErrFixtureStart
		}
		if err := e.recording.omitReleasePreparedFact(
			handle.ID(),
			e.fact,
		); err != nil {
			e.mu.Unlock()
			return hostruntime.HeldRunnerAudit{}, ErrFixtureStart
		}
		e.injected = true
	}
	e.mu.Unlock()
	return e.Engine.AuditHeldRunner(ctx, handle)
}

func (e *task11ReleaseLossEngine) ReleaseRunner(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
	authorization hostruntime.ReleaseAuthorization,
	jit *redaction.Secret,
) error {
	if e == nil || e.Engine == nil {
		if jit != nil {
			jit.Destroy()
		}
		return ErrFixtureStart
	}
	e.mu.Lock()
	e.releaseCalls++
	e.mu.Unlock()
	return e.Engine.ReleaseRunner(ctx, handle, authorization, jit)
}

func (e *task11ReleaseLossEngine) observation() (
	auditCalls uint32,
	releaseCalls uint32,
	injected bool,
) {
	if e == nil {
		return 0, 0, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.auditCalls, e.releaseCalls, e.injected
}

type task11LossAttemptObservation struct {
	RunDigest       string                      `json:"run_digest"`
	CapacitySlotID  networkjail.CapacitySlotID  `json:"capacity_slot_id"`
	JobGeneration   networkjail.JobGeneration   `json:"job_generation"`
	Adapter         task11LossHandleObservation `json:"adapter"`
	Broker          task11LossHandleObservation `json:"broker"`
	Runner          task11LossHandleObservation `json:"runner"`
	MissingFact     task11MissingPreparedFact   `json:"missing_fact"`
	FailedStage     string                      `json:"failed_stage"`
	TypedFailure    string                      `json:"typed_failure"`
	TerminalState   controller.State            `json:"terminal_state"`
	AuditCalls      uint32                      `json:"audit_calls"`
	ReleaseCalls    uint32                      `json:"release_calls"`
	CleanupDigest   string                      `json:"cleanup_digest"`
	CleanupComplete bool                        `json:"cleanup_complete"`
}

type task11LossHandleObservation struct {
	Kind CleanupKind `json:"kind"`
	ID   string      `json:"id"`
}

type task11LossAttemptSource interface {
	RunLossAttempt(
		context.Context,
		task11MissingPreparedFact,
	) (task11LossAttemptObservation, error)
}

type task11LossPreventionBinding struct {
	PrimaryRunDigest      string                     `json:"primary_run_digest"`
	PrimaryCapacitySlotID networkjail.CapacitySlotID `json:"primary_capacity_slot_id"`
	PrimaryJobGeneration  networkjail.JobGeneration  `json:"primary_job_generation"`
	MissingFact           task11MissingPreparedFact  `json:"missing_fact"`
}

type task11LossPreventionRuntime struct {
	binding  task11LossPreventionBinding
	prepared task11PreparedRuntimeSource
	attempt  task11LossAttemptSource

	mu        sync.Mutex
	attempted bool
}

func newTask11LossPreventionRuntime(
	binding task11LossPreventionBinding,
	prepared task11PreparedRuntimeSource,
	attempt task11LossAttemptSource,
) (*task11LossPreventionRuntime, error) {
	if !isLowerHex(binding.PrimaryRunDigest, sha256.Size*2) ||
		binding.PrimaryCapacitySlotID == 0 ||
		binding.PrimaryJobGeneration == 0 ||
		!validTask11MissingPreparedFact(binding.MissingFact) ||
		prepared == nil ||
		attempt == nil {
		return nil, ErrFixtureStart
	}
	return &task11LossPreventionRuntime{
		binding:  binding,
		prepared: prepared,
		attempt:  attempt,
	}, nil
}

func (r *task11LossPreventionRuntime) ProveLossPreventsRelease(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
	primarySeal string,
) (task11LossPreventsReleaseProof, error) {
	if r == nil || ctx == nil || ctx.Err() != nil ||
		!validFixtureRuntimeObservation(prepared) ||
		!isLowerHex(primarySeal, sha256.Size*2) {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	r.mu.Lock()
	if r.attempted {
		r.mu.Unlock()
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	r.attempted = true
	r.mu.Unlock()

	beforeFlood, err := r.prepared.SnapshotPreparedEvidence(
		ctx,
		prepared,
	)
	if err != nil {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	beforeSeal, err := task11PreparedObservationSeal(
		prepared,
		beforeFlood,
	)
	if err != nil || beforeSeal != primarySeal {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	observation, err := r.attempt.RunLossAttempt(
		ctx,
		r.binding.MissingFact,
	)
	if err != nil ||
		!validTask11LossAttemptObservation(
			observation,
			r.binding,
			prepared,
		) {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	afterFlood, err := r.prepared.SnapshotPreparedEvidence(
		ctx,
		prepared,
	)
	if err != nil {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	afterSeal, err := task11PreparedObservationSeal(
		prepared,
		afterFlood,
	)
	if err != nil ||
		afterSeal != primarySeal ||
		afterFlood != beforeFlood {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	digest, err := recordingCanonicalDigest(
		task11LossAttemptDigestDomain,
		struct {
			SchemaVersion uint32                       `json:"schema_version"`
			PrimarySeal   string                       `json:"primary_seal"`
			Binding       task11LossPreventionBinding  `json:"binding"`
			Attempt       task11LossAttemptObservation `json:"attempt"`
			Success       bool                         `json:"success"`
		}{
			SchemaVersion: 1,
			PrimarySeal:   primarySeal,
			Binding:       r.binding,
			Attempt:       observation,
			Success:       true,
		},
	)
	if err != nil {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	return newTask11LossPreventsReleaseProof(primarySeal, digest)
}

func validTask11LossAttemptObservation(
	observation task11LossAttemptObservation,
	binding task11LossPreventionBinding,
	primary fixtureRuntimeObservation,
) bool {
	return isLowerHex(observation.RunDigest, sha256.Size*2) &&
		observation.RunDigest != binding.PrimaryRunDigest &&
		observation.CapacitySlotID != 0 &&
		observation.CapacitySlotID !=
			binding.PrimaryCapacitySlotID &&
		observation.JobGeneration != 0 &&
		observation.JobGeneration !=
			binding.PrimaryJobGeneration &&
		observation.Adapter.Kind == CleanupAdapter &&
		observation.Broker.Kind == CleanupBroker &&
		observation.Runner.Kind == CleanupRunner &&
		isLowerHex(observation.Adapter.ID, sha256.Size*2) &&
		isLowerHex(observation.Broker.ID, sha256.Size*2) &&
		isLowerHex(observation.Runner.ID, sha256.Size*2) &&
		observation.Adapter.ID != observation.Broker.ID &&
		observation.Adapter.ID != observation.Runner.ID &&
		observation.Broker.ID != observation.Runner.ID &&
		observation.Adapter.ID != primary.Adapter.id &&
		observation.Broker.ID != primary.Broker.id &&
		observation.Runner.ID != primary.Runner.id &&
		observation.MissingFact == binding.MissingFact &&
		observation.FailedStage ==
			networkjail.StageRunnerAuthorize.String() &&
		observation.TypedFailure ==
			networkjail.ErrSetupFailed.Error() &&
		observation.TerminalState == controller.StateDestroyed &&
		observation.AuditCalls == 2 &&
		observation.ReleaseCalls == 0 &&
		isLowerHex(observation.CleanupDigest, sha256.Size*2) &&
		observation.CleanupComplete
}

var _ hostruntime.Engine = (*task11ReleaseLossEngine)(nil)
var _ task11LossPreventionSource = (*task11LossPreventionRuntime)(nil)
