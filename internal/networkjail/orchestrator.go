package networkjail

import (
	"context"
	"errors"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

const setupCleanupTimeout = 30 * time.Second

// Orchestrator owns the pre-listener network-jail transaction. It exposes a
// LiveJail only after every external effect and the listener-release boundary
// have durable checkpoints.
type Orchestrator struct {
	runtime   setupRuntime
	journal   LifecycleJournal
	authority authorityManager
	verifier  setupVerifier
}

type setupResources struct {
	adapter   adapterRuntimeRef
	broker    brokerRuntimeRef
	runner    runnerRuntimeRef
	authority authorityLease
}

func newOrchestrator(
	runtime setupRuntime,
	journal LifecycleJournal,
	authority authorityManager,
	verifier setupVerifier,
) (*Orchestrator, error) {
	if runtime == nil || journal == nil || authority == nil || verifier == nil {
		return nil, ErrSetupInput
	}
	return &Orchestrator{
		runtime:   runtime,
		journal:   journal,
		authority: authority,
		verifier:  verifier,
	}, nil
}

// Configure preserves the Task-6 one-call surface while delegating to the
// Task-7 split transaction. The JIT remains caller-owned until Release and is
// destroyed on every terminal path.
func (o *Orchestrator) Configure(ctx context.Context, request SetupRequest) (LiveJail, error) {
	if request.JIT != nil {
		defer request.JIT.Destroy()
	}
	if o == nil || ctx == nil || validateSetupRequest(request) != nil {
		return LiveJail{}, ErrSetupInput
	}
	held, err := o.Prepare(ctx, preparedSetupRequest(request))
	if err != nil {
		return LiveJail{}, err
	}
	return o.Release(ctx, held, request.JIT)
}

// Prepare executes the exact held-adapter, held-broker, authority, runner, and
// audit sequence through the durable RELEASE_ARMED checkpoint. It accepts no
// JIT material and never invokes the listener-release effect.
func (o *Orchestrator) Prepare(
	ctx context.Context,
	request PreparedSetupRequest,
) (HeldJail, error) {
	if o == nil || ctx == nil || validatePreparedSetupRequest(request) != nil {
		return HeldJail{}, ErrSetupInput
	}
	conntrackBudget, err := request.ConntrackInput.Compute(
		request.Graph.manifest,
		request.MaxRunnerCapacity,
	)
	if err != nil {
		return HeldJail{}, ErrSetupInput
	}

	var resources setupResources
	fail := func(cause error) (HeldJail, error) {
		if errors.Is(cause, ErrSetupReplay) && !resources.any() {
			return HeldJail{}, ErrSetupReplay
		}
		if !o.cleanup(ctx, request.Key, resources) {
			return HeldJail{}, ErrSetupCleanup
		}
		if errors.Is(cause, ErrSetupReplay) {
			return HeldJail{}, ErrSetupReplay
		}
		return HeldJail{}, ErrSetupFailed
	}

	if err := o.effect(ctx, request.Key, StageAdapterCreate, func() (JournalResult, error) {
		var err error
		resources.adapter, err = o.runtime.CreateAdapter(ctx, request.Adapter)
		if err != nil || !resources.adapter.valid || resources.adapter.id == "" {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{
			Identity: resources.adapter.id,
			Column:   JournalIdentityAdapter,
		}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateAdapterCreated); err != nil {
		return fail(err)
	}

	var emptiness adapterEmptinessProof
	if err := o.effect(ctx, request.Key, StageAdapterEmpty, func() (JournalResult, error) {
		var err error
		emptiness, err = o.verifier.VerifyAdapterEmpty(
			ctx,
			resources.adapter,
			request.Verifier,
		)
		if err != nil || validateAdapterEmptiness(emptiness, resources.adapter) != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateAdapterVerified); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StageBrokerCreate, func() (JournalResult, error) {
		var err error
		resources.broker, err = o.runtime.CreateBroker(ctx, resources.adapter, request.Broker)
		if err != nil || !resources.broker.valid || resources.broker.id == "" {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{
			Identity: resources.broker.id,
			Column:   JournalIdentityBroker,
		}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateBrokerHeld); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StagePolicyApply, func() (JournalResult, error) {
		if err := o.runtime.ApplyPolicy(ctx, resources.broker, request.Policy); err != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{
			Identity: request.Policy.Digest(),
			Column:   JournalIdentityPolicy,
		}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateBrokerPolicyApplied); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StageAuthorityStart, func() (JournalResult, error) {
		var err error
		resources.authority, err = o.authority.Start(ctx, authorityRequest{
			slotID:        request.Broker.CapacitySlotID,
			jobGeneration: request.Broker.JobGeneration,
			directory:     request.Broker.AuthorityParent,
			user:          request.Broker.User,
		})
		if err != nil ||
			!resources.authority.valid ||
			resources.authority.slotID != request.Broker.CapacitySlotID ||
			resources.authority.jobGeneration != request.Broker.JobGeneration {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StageAuthorityBind, func() (JournalResult, error) {
		if err := o.runtime.BindAuthority(ctx, resources.broker, resources.authority); err != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateDialAuthorityReady); err != nil {
		return fail(err)
	}

	var peer brokerPeerRuntimeRef
	if err := o.effect(ctx, request.Key, StageBrokerRelease, func() (JournalResult, error) {
		var err error
		peer, err = o.runtime.ReleaseBroker(ctx, resources.broker)
		if err != nil || !peer.valid {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateBrokerReleased); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StageAdapterBind, func() (JournalResult, error) {
		if err := o.runtime.BindBrokerPeer(ctx, resources.adapter, peer); err != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}

	var egress egressVerification
	if err := o.effect(ctx, request.Key, StageEgressVerify, func() (JournalResult, error) {
		var err error
		egress, err = o.verifier.VerifyEgress(
			ctx,
			resources.adapter,
			resources.broker,
			request.Policy,
			request.Verifier,
		)
		if err != nil ||
			validateEgressVerification(
				egress,
				resources.adapter,
				resources.broker,
				request.Policy,
			) != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateEgressVerified); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StageRunnerCreate, func() (JournalResult, error) {
		var err error
		resources.runner, err = o.runtime.CreateRunner(ctx, resources.adapter, request.Runner)
		if err != nil || !resources.runner.valid || resources.runner.id == "" {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{
			Identity: resources.runner.id,
			Column:   JournalIdentityRunner,
		}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateRunnerHeld); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StageSeedHydrate, func() (JournalResult, error) {
		if err := o.runtime.HydrateSeeds(ctx, resources.runner, request.SeedIDs); err != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}

	var preArmNamespace namespaceRuntimeRef
	if err := o.effect(ctx, request.Key, StageNamespacePreArm, func() (JournalResult, error) {
		var err error
		preArmNamespace, err = o.runtime.ProbeNamespace(
			ctx,
			resources.runner,
			hostruntime.GateNetNSIDPreArm,
		)
		if err != nil || !preArmNamespace.valid {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}

	var finalAudit finalAuditProof
	if err := o.effect(ctx, request.Key, StageFinalAudit, func() (JournalResult, error) {
		brokerAudit, err := o.runtime.AuditBroker(ctx, resources.broker)
		if err != nil || !brokerAudit.valid || brokerAudit.digest == "" {
			return JournalResult{}, ErrSetupFailed
		}
		heldAudit, err := o.runtime.AuditHeldRunner(ctx, resources.runner)
		if err != nil || !heldAudit.valid || heldAudit.digest == "" {
			return JournalResult{}, ErrSetupFailed
		}
		auditRequest := finalAuditRequest{
			adapter:     resources.adapter,
			broker:      resources.broker,
			runner:      resources.runner,
			emptiness:   emptiness,
			egress:      egress,
			brokerAudit: brokerAudit,
			heldAudit:   heldAudit,
			graph:       request.Graph,
			budget:      conntrackBudget,
			policy:      request.Policy,
		}
		finalAudit, err = o.verifier.FinalAudit(ctx, auditRequest)
		if err != nil || validateFinalAudit(finalAudit, auditRequest) != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}

	if err := o.effect(ctx, request.Key, StageRunnerArm, func() (JournalResult, error) {
		if err := o.runtime.ArmRunner(ctx, resources.runner); err != nil {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}

	var finalNamespace namespaceRuntimeRef
	if err := o.effect(ctx, request.Key, StageNamespaceFinal, func() (JournalResult, error) {
		var err error
		finalNamespace, err = o.runtime.ProbeNamespace(
			ctx,
			resources.runner,
			hostruntime.GateNetNSIDFinal,
		)
		if err != nil || !finalNamespace.valid {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}

	var authorization releaseAuthorizationRuntimeRef
	if err := o.effect(ctx, request.Key, StageRunnerAuthorize, func() (JournalResult, error) {
		heldAudit, err := o.runtime.AuditHeldRunner(ctx, resources.runner)
		if err != nil || !heldAudit.valid {
			return JournalResult{}, ErrSetupFailed
		}
		authorization, err = o.runtime.AuthorizeRelease(
			ctx,
			resources.runner,
			preArmNamespace,
			finalNamespace,
		)
		if err != nil || !authorization.valid {
			return JournalResult{}, ErrSetupFailed
		}
		return JournalResult{}, nil
	}); err != nil {
		return fail(err)
	}
	if err := o.advance(ctx, request.Key, controller.StateReleaseArmed); err != nil {
		return fail(err)
	}

	return HeldJail{
		key:           request.Key,
		resources:     resources,
		authorization: authorization,
		report:        finalAudit.report,
	}, nil
}

// Release consumes one exact HeldJail plus one one-job JIT secret. Once the
// durable listener-release effect has begun, every non-success is ambiguous:
// the listener may already have exec'd, so resources are preserved for
// two-sided reconciliation rather than blindly destroyed.
func (o *Orchestrator) Release(
	ctx context.Context,
	held HeldJail,
	jit *redaction.Secret,
) (LiveJail, error) {
	if jit != nil {
		defer jit.Destroy()
	}
	if o == nil || ctx == nil || jit == nil ||
		held.key.RepositoryAlias == "" ||
		held.key.RunnerRequestID <= 0 ||
		!held.resources.adapter.valid ||
		!held.resources.broker.valid ||
		!held.resources.runner.valid ||
		!held.resources.authority.valid ||
		!held.authorization.valid ||
		ValidateProbeReport(held.report) != nil {
		return LiveJail{}, ErrSetupInput
	}

	if err := o.journal.Before(ctx, held.key, StageListenerRelease); err != nil {
		if errors.Is(err, ErrSetupReplay) {
			return LiveJail{}, ErrSetupReplay
		}
		if !o.cleanup(ctx, held.key, held.resources) {
			return LiveJail{}, ErrSetupCleanup
		}
		return LiveJail{}, ErrSetupFailed
	}
	if err := o.runtime.ReleaseRunner(
		ctx,
		held.resources.runner,
		held.authorization,
		jit,
	); err != nil {
		o.markListenerAmbiguous(ctx, held.key)
		return LiveJail{}, ErrListenerAmbiguous
	}

	if err := o.journal.Complete(
		ctx,
		held.key,
		StageListenerRelease,
		JournalResult{},
	); err != nil {
		o.markListenerAmbiguous(ctx, held.key)
		return LiveJail{}, ErrListenerAmbiguous
	}
	if err := o.journal.Advance(
		ctx,
		held.key,
		controller.StateListenerReleased,
	); err != nil {
		o.markListenerAmbiguous(ctx, held.key)
		return LiveJail{}, ErrListenerAmbiguous
	}

	return LiveJail{
		key:       held.key,
		adapter:   held.resources.adapter,
		broker:    held.resources.broker,
		runner:    held.resources.runner,
		authority: held.resources.authority,
		report:    held.report,
	}, nil
}

// DestroyHeld removes only the runtime graph represented by an
// orchestrator-issued held capability. The lifecycle owner persists the
// checked terminal transition after its upstream and runtime absence
// read-backs; this method never guesses whether listener release began.
func (o *Orchestrator) DestroyHeld(ctx context.Context, held HeldJail) error {
	if o == nil || ctx == nil ||
		held.key.RepositoryAlias == "" ||
		held.key.RunnerRequestID <= 0 ||
		!held.resources.any() {
		return ErrSetupInput
	}
	if !o.cleanupResources(ctx, held.resources) {
		return ErrSetupCleanup
	}
	return nil
}

// DestroyLive removes only the exact live runtime graph. It intentionally
// leaves the post-release durable state transition to lifecycle reconciliation.
func (o *Orchestrator) DestroyLive(ctx context.Context, live LiveJail) error {
	if o == nil || ctx == nil ||
		live.key.RepositoryAlias == "" ||
		live.key.RunnerRequestID <= 0 ||
		!live.adapter.valid ||
		!live.broker.valid ||
		!live.runner.valid ||
		!live.authority.valid {
		return ErrSetupInput
	}
	if !o.cleanupResources(ctx, setupResources{
		adapter:   live.adapter,
		broker:    live.broker,
		runner:    live.runner,
		authority: live.authority,
	}) {
		return ErrSetupCleanup
	}
	return nil
}

func (o *Orchestrator) effect(
	ctx context.Context,
	key controller.AssignmentKey,
	stage SetupStage,
	action func() (JournalResult, error),
) error {
	if err := o.journal.Before(ctx, key, stage); err != nil {
		if errors.Is(err, ErrSetupReplay) {
			return ErrSetupReplay
		}
		return ErrSetupFailed
	}
	result, err := action()
	if err != nil {
		o.recordFailure(ctx, key, stage)
		return ErrSetupFailed
	}
	if err := o.journal.Complete(ctx, key, stage, result); err != nil {
		return ErrSetupFailed
	}
	return nil
}

func (o *Orchestrator) advance(
	ctx context.Context,
	key controller.AssignmentKey,
	next controller.State,
) error {
	if err := o.journal.Advance(ctx, key, next); err != nil {
		return ErrSetupFailed
	}
	return nil
}

func (o *Orchestrator) recordFailure(
	ctx context.Context,
	key controller.AssignmentKey,
	stage SetupStage,
) {
	failureCtx, cancel := setupRecoveryContext(ctx)
	defer cancel()
	_ = o.journal.Complete(
		failureCtx,
		key,
		stage,
		JournalResult{Failure: true},
	)
}

func (o *Orchestrator) markListenerAmbiguous(
	ctx context.Context,
	key controller.AssignmentKey,
) {
	recoveryCtx, cancel := setupRecoveryContext(ctx)
	defer cancel()
	_ = o.journal.MarkAmbiguous(recoveryCtx, key)
}

func (o *Orchestrator) cleanup(
	ctx context.Context,
	key controller.AssignmentKey,
	resources setupResources,
) bool {
	if !o.cleanupResources(ctx, resources) {
		return false
	}
	cleanupCtx, cancel := setupRecoveryContext(ctx)
	defer cancel()
	if err := o.journal.Advance(
		cleanupCtx,
		key,
		controller.StateDestroyed,
	); err != nil {
		return false
	}
	return true
}

func (o *Orchestrator) cleanupResources(
	ctx context.Context,
	resources setupResources,
) bool {
	cleanupCtx, cancel := setupRecoveryContext(ctx)
	defer cancel()

	ok := true
	if resources.runner.valid {
		if err := o.runtime.RemoveRunner(cleanupCtx, resources.runner); err != nil {
			ok = false
		}
	}
	if resources.broker.valid {
		if err := o.runtime.RemoveBroker(cleanupCtx, resources.broker); err != nil {
			ok = false
		}
	}
	if resources.authority.valid {
		if err := o.authority.Stop(cleanupCtx, resources.authority); err != nil {
			ok = false
		}
	}
	if resources.adapter.valid {
		if err := o.runtime.RemoveAdapter(cleanupCtx, resources.adapter); err != nil {
			ok = false
		}
	}
	if !ok {
		return false
	}
	return true
}

func setupRecoveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), setupCleanupTimeout)
}

func (resources setupResources) any() bool {
	return resources.adapter.valid ||
		resources.broker.valid ||
		resources.runner.valid ||
		resources.authority.valid
}
