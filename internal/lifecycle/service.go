// Package lifecycle owns the one-job JIT lifetime and the same-key-exclusive
// bridge between durable controller assignments, GitHub scale-set sessions,
// Task 6's held network jail, and restart-only managed cleanup.
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/redaction"
	"github.com/sumitake/portable-ghar/internal/state"
)

var (
	ErrLifecycle        = errors.New("lifecycle: operation failed")
	ErrInvalidState     = errors.New("lifecycle: durable state invalid")
	ErrReleaseFailed    = errors.New("lifecycle: listener release failed")
	ErrReleaseAmbiguous = errors.New("lifecycle: listener release ambiguous")
	ErrCleanupUnproven  = errors.New("lifecycle: cleanup absence unproven")
)

const runnerWorkFolder = "_work"

const lifecycleFinalizeTimeout = 30 * time.Second

var opaqueSlotPattern = regexp.MustCompile(`^pghar-slot-([0-9a-f]{32})$`)

// Service is the canonical lifecycle command surface.
type Service interface {
	Prepare(context.Context, controller.Assignment) (controller.RunnerSlot, error)
	Release(context.Context, controller.AssignmentKey) error
	Observe(context.Context, githubscale.Event) error
	Destroy(context.Context, controller.AssignmentKey, controller.ReasonCode) error
}

// Runtime also satisfies the existing before-Ack batch recorder and
// controller reconciliation worker ports.
type Runtime interface {
	Service
	controller.BatchEventRecorder
	controller.AssignmentReconciler
	controller.AcquisitionRevoker
	controller.RunningCanceler
}

type DurableState interface {
	ListRecoverable(context.Context) ([]state.RecoverableAssignment, error)
	AcquisitionAssignment(
		context.Context,
		controller.AssignmentKey,
	) (state.AcquisitionAssignmentRecord, error)
	LookupAssignmentEffect(context.Context, controller.AssignmentKey, string) (state.EffectRecord, error)
	MarkAmbiguous(context.Context, controller.AssignmentKey, string) error
	ApplyRunnerObservation(context.Context, controller.AssignmentKey, state.RunnerObservation) error
	AdvancePreReleaseDestroyed(context.Context, controller.AssignmentKey) error
	Advance(context.Context, controller.AssignmentKey, controller.State) error
	BindTerminalMessage(context.Context, controller.AssignmentKey, int) error
	ResolvePostRelease(
		context.Context,
		controller.AssignmentKey,
		controller.PostReleaseOutcome,
		[sha256.Size]byte,
		time.Time,
	) error
}

type SessionProvider interface {
	Session(context.Context, string) (githubscale.Session, error)
}

type SetupBuilder interface {
	Build(
		context.Context,
		controller.Assignment,
	) (networkjail.PreparedSetupRequest, hostruntime.RecoverySpec, error)
}

type JailOrchestrator interface {
	Prepare(context.Context, networkjail.PreparedSetupRequest) (networkjail.HeldJail, error)
	Release(
		context.Context,
		networkjail.HeldJail,
		*redaction.Secret,
		controller.AcquisitionPermitGuard,
	) (networkjail.LiveJail, error)
	DestroyHeld(context.Context, networkjail.HeldJail) error
	DestroyLive(context.Context, networkjail.LiveJail) error
}

type service struct {
	state    DurableState
	sessions SessionProvider
	jit      controller.JITAuthorizer
	builder  SetupBuilder
	jails    JailOrchestrator
	recovery hostruntime.ManagedRecovery
	now      func() time.Time
	locks    keyedLocks

	cacheMu sync.Mutex
	held    map[controller.AssignmentKey]heldEntry
	live    map[controller.AssignmentKey]liveEntry
}

type heldEntry struct {
	assignment controller.Assignment
	recovery   hostruntime.RecoverySpec
	jail       networkjail.HeldJail
}

type liveEntry struct {
	assignment controller.Assignment
	recovery   hostruntime.RecoverySpec
	jail       networkjail.LiveJail
	permit     controller.AcquisitionPermitGuard
	binding    controller.AcquisitionPermitBinding
}

func NewService(
	durable DurableState,
	sessions SessionProvider,
	jit controller.JITAuthorizer,
	builder SetupBuilder,
	jails JailOrchestrator,
	recovery hostruntime.ManagedRecovery,
	now func() time.Time,
) (Runtime, error) {
	if durable == nil || sessions == nil || jit == nil || builder == nil ||
		jails == nil || recovery == nil || now == nil {
		return nil, fmt.Errorf("%w: dependencies required", ErrLifecycle)
	}
	return &service{
		state:    durable,
		sessions: sessions,
		jit:      jit,
		builder:  builder,
		jails:    jails,
		recovery: recovery,
		now:      now,
		locks:    keyedLocks{entries: make(map[controller.AssignmentKey]*keyedLock)},
		held:     make(map[controller.AssignmentKey]heldEntry),
		live:     make(map[controller.AssignmentKey]liveEntry),
	}, nil
}

func (s *service) Prepare(
	ctx context.Context,
	assignment controller.Assignment,
) (controller.RunnerSlot, error) {
	unlock := s.locks.lock(assignment.Key)
	defer unlock()
	return s.prepareLocked(ctx, assignment)
}

func (s *service) prepareLocked(
	ctx context.Context,
	assignment controller.Assignment,
) (controller.RunnerSlot, error) {
	if err := assignment.Validate(); err != nil {
		return controller.RunnerSlot{}, fmt.Errorf("%w: assignment: %w", ErrLifecycle, err)
	}
	record, err := s.record(ctx, assignment.Key)
	if err != nil {
		return controller.RunnerSlot{}, err
	}
	if record.State != controller.StateCapacityReserved ||
		record.Ambiguous ||
		!matchesAssignment(record, assignment) {
		return controller.RunnerSlot{}, ErrInvalidState
	}
	s.cacheMu.Lock()
	_, heldExists := s.held[assignment.Key]
	_, liveExists := s.live[assignment.Key]
	s.cacheMu.Unlock()
	if heldExists || liveExists {
		return controller.RunnerSlot{}, ErrInvalidState
	}

	prepared, recovery, err := s.builder.Build(ctx, assignment)
	if err != nil || !validBuiltSetup(assignment, prepared, recovery) {
		return controller.RunnerSlot{}, fmt.Errorf("%w: setup builder", ErrLifecycle)
	}
	held, err := s.jails.Prepare(ctx, prepared)
	if err != nil {
		return controller.RunnerSlot{}, fmt.Errorf("%w: prepare jail: %w", ErrLifecycle, err)
	}
	after, err := s.record(ctx, assignment.Key)
	if err != nil {
		return controller.RunnerSlot{}, err
	}
	if after.State != controller.StateReleaseArmed ||
		after.Slot.OpaqueName != assignment.Slot.OpaqueName ||
		after.Slot.CapacitySlotID != assignment.Slot.CapacitySlotID ||
		after.Slot.AdapterContainerID == "" ||
		after.Slot.BrokerContainerID == "" ||
		after.Slot.RunnerContainerID == "" {
		return controller.RunnerSlot{}, ErrInvalidState
	}
	recovery.ExpectedAdapterID = after.Slot.AdapterContainerID
	recovery.ExpectedBrokerID = after.Slot.BrokerContainerID
	recovery.ExpectedRunnerID = after.Slot.RunnerContainerID
	assignment.Slot = after.Slot
	s.cacheMu.Lock()
	s.held[assignment.Key] = heldEntry{
		assignment: assignment,
		recovery:   recovery,
		jail:       held,
	}
	s.cacheMu.Unlock()
	return after.Slot, nil
}

func (s *service) Release(
	ctx context.Context,
	key controller.AssignmentKey,
) error {
	unlock := s.locks.lock(key)
	defer unlock()
	return s.releaseLocked(ctx, key)
}

func (s *service) releaseLocked(
	ctx context.Context,
	key controller.AssignmentKey,
) (resultErr error) {
	record, err := s.record(ctx, key)
	if err != nil {
		return err
	}
	if record.Ambiguous {
		return ErrReleaseAmbiguous
	}
	if record.State != controller.StateReleaseArmed {
		return ErrInvalidState
	}
	s.cacheMu.Lock()
	entry, ok := s.held[key]
	s.cacheMu.Unlock()
	if !ok || !matchesAssignment(record, entry.assignment) {
		return ErrInvalidState
	}
	session, err := s.sessions.Session(ctx, key.RepositoryAlias)
	if err != nil || session == nil {
		return fmt.Errorf("%w: session unavailable", ErrReleaseFailed)
	}
	if err := removeStaleRunner(ctx, session, entry.assignment.Slot.OpaqueName); err != nil {
		_ = s.state.MarkAmbiguous(ctx, key, "upstream-pre-release-cleanup")
		return fmt.Errorf("%w: stale runner cleanup: %w", ErrReleaseAmbiguous, err)
	}
	scaleSetName, err := assignmentScaleSet(entry.assignment)
	if err != nil {
		return err
	}
	jitRequest := githubscale.JITRequest{
		RunnerName: entry.assignment.Slot.OpaqueName,
		WorkFolder: runnerWorkFolder,
	}
	authorization, err := s.jit.GenerateJITAuthorized(
		ctx,
		controller.JITAuthorizationRequest{
			Assignment:   entry.assignment,
			ScaleSetName: scaleSetName,
			Session:      session,
			RunnerName:   entry.assignment.Slot.OpaqueName,
			Request:      jitRequest,
		},
	)
	if err != nil {
		if errors.Is(err, controller.ErrJITMayHaveActed) {
			_ = s.state.MarkAmbiguous(ctx, key, "jit-effect-ambiguous")
			return fmt.Errorf("%w: generate JIT: %w", ErrReleaseAmbiguous, err)
		}
		return fmt.Errorf("%w: generate JIT", ErrReleaseFailed)
	}
	config := authorization.Config
	if config.Encoded != nil {
		defer config.Encoded.Destroy()
	}
	permit := authorization.Permit
	if permit != nil {
		defer s.finishReleasePermit(ctx, key, permit, &resultErr)
	}
	binding := controller.AcquisitionPermitBinding{}
	bindingErr := error(nil)
	if permit == nil {
		bindingErr = errors.New("permit unavailable")
	} else {
		binding = permit.Binding()
		_, bindingErr = controller.AcquisitionPermitBindingDigest(binding)
	}
	if config.Encoded == nil ||
		config.Runner.ID <= 0 ||
		config.Runner.Name != entry.assignment.Slot.OpaqueName ||
		bindingErr != nil {
		if config.Runner.ID > 0 {
			if cleanupErr := removeRunnerAndProve(ctx, session, config.Runner); cleanupErr != nil {
				_ = s.state.MarkAmbiguous(ctx, key, "upstream-cleanup-uncertain")
				return fmt.Errorf("%w: %w", ErrReleaseAmbiguous, cleanupErr)
			}
		}
		return fmt.Errorf("%w: generated runner identity or permit binding", ErrReleaseFailed)
	}

	live, releaseErr := s.jails.Release(
		permit.Context(),
		entry.jail,
		config.Encoded,
		permit,
	)
	if releaseErr != nil {
		if errors.Is(releaseErr, networkjail.ErrListenerAmbiguous) ||
			errors.Is(releaseErr, networkjail.ErrSetupReplay) {
			_ = s.state.MarkAmbiguous(ctx, key, "listener-release-ambiguous")
			return fmt.Errorf("%w: %w", ErrReleaseAmbiguous, releaseErr)
		}
		if err := removeRunnerAndProve(ctx, session, config.Runner); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, "upstream-cleanup-uncertain")
			return fmt.Errorf("%w: %w", ErrReleaseAmbiguous, err)
		}
		s.cacheMu.Lock()
		delete(s.held, key)
		s.cacheMu.Unlock()
		return fmt.Errorf("%w: %w", ErrReleaseFailed, releaseErr)
	}
	after, err := s.record(ctx, key)
	if err != nil || after.State != controller.StateListenerReleased {
		_ = s.state.MarkAmbiguous(ctx, key, "listener-release-checkpoint")
		return ErrReleaseAmbiguous
	}
	entry.assignment.Slot = after.Slot
	s.cacheMu.Lock()
	delete(s.held, key)
	s.live[key] = liveEntry{
		assignment: entry.assignment,
		recovery:   entry.recovery,
		jail:       live,
		permit:     permit,
		binding:    binding,
	}
	s.cacheMu.Unlock()
	return nil
}

func (s *service) finishReleasePermit(
	ctx context.Context,
	key controller.AssignmentKey,
	permit controller.AcquisitionPermitGuard,
	resultErr *error,
) {
	closeErr := permit.Close()
	if closeErr == nil {
		return
	}
	s.cacheMu.Lock()
	delete(s.live, key)
	s.cacheMu.Unlock()

	finishCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		lifecycleFinalizeTimeout,
	)
	defer cancel()
	markErr := s.state.MarkAmbiguous(
		finishCtx,
		key,
		"acquisition-permit-close",
	)
	*resultErr = errors.Join(
		*resultErr,
		ErrReleaseAmbiguous,
		controller.ErrAcquisitionGuardClose,
		closeErr,
		markErr,
	)
}

func assignmentScaleSet(assignment controller.Assignment) (string, error) {
	if len(assignment.Offer.RequestLabels) != 1 ||
		assignment.Offer.RequestLabels[0] == "" {
		return "", ErrInvalidState
	}
	return assignment.Offer.RequestLabels[0], nil
}

func removeStaleRunner(
	ctx context.Context,
	session githubscale.Session,
	name string,
) error {
	runner, found, err := session.GetRunnerByName(ctx, name)
	if err != nil {
		return err
	}
	if !found {
		if runner != (githubscale.RunnerRef{}) {
			return ErrInvalidState
		}
		return nil
	}
	if runner.ID <= 0 || runner.Name != name {
		return ErrInvalidState
	}
	return removeRunnerAndProve(ctx, session, runner)
}

func removeRunnerAndProve(
	ctx context.Context,
	session githubscale.Session,
	runner githubscale.RunnerRef,
) error {
	if runner.ID <= 0 || runner.Name == "" {
		return ErrInvalidState
	}
	if err := session.RemoveRunner(ctx, runner.ID); err != nil {
		return err
	}
	if byID, found, err := session.GetRunner(ctx, runner.ID); err != nil {
		return err
	} else if found || byID != (githubscale.RunnerRef{}) {
		return ErrCleanupUnproven
	}
	if byName, found, err := session.GetRunnerByName(ctx, runner.Name); err != nil {
		return err
	} else if found || byName != (githubscale.RunnerRef{}) {
		return ErrCleanupUnproven
	}
	return nil
}

func (s *service) record(
	ctx context.Context,
	key controller.AssignmentKey,
) (state.RecoverableAssignment, error) {
	records, err := s.state.ListRecoverable(ctx)
	if err != nil {
		return state.RecoverableAssignment{}, fmt.Errorf("%w: read durable assignment", ErrLifecycle)
	}
	var (
		found state.RecoverableAssignment
		count int
	)
	for _, record := range records {
		if record.Key == key {
			found = record
			count++
		}
	}
	if count != 1 {
		return state.RecoverableAssignment{}, ErrInvalidState
	}
	return found, nil
}

func matchesAssignment(
	record state.RecoverableAssignment,
	assignment controller.Assignment,
) bool {
	durableOffer := controllerRecoveryOffer(record.Offer)
	candidateOffer := assignment.Offer
	durableOffer.RequestLabels = append([]string{}, durableOffer.RequestLabels...)
	candidateOffer.RequestLabels = append([]string{}, candidateOffer.RequestLabels...)
	return record.Key == assignment.Key &&
		record.Offer.RepositoryAlias == assignment.Key.RepositoryAlias &&
		reflect.DeepEqual(durableOffer, candidateOffer) &&
		record.Slot == assignment.Slot
}

func validBuiltSetup(
	assignment controller.Assignment,
	prepared networkjail.PreparedSetupRequest,
	recovery hostruntime.RecoverySpec,
) bool {
	adapterName, brokerName, runnerName, err := componentNames(assignment.Slot.OpaqueName)
	if err != nil {
		return false
	}
	return prepared.Key == assignment.Key &&
		prepared.Adapter.Name == adapterName &&
		prepared.Broker.Name == brokerName &&
		prepared.Runner.Name == runnerName &&
		prepared.Adapter.SlotIdentity == assignment.Slot.OpaqueName &&
		prepared.Broker.SlotIdentity == assignment.Slot.OpaqueName &&
		prepared.Runner.SlotIdentity == assignment.Slot.OpaqueName &&
		prepared.Verifier.SlotIdentity == assignment.Slot.OpaqueName &&
		prepared.Broker.CapacitySlotID == assignment.Slot.CapacitySlotID &&
		recovery.SlotIdentity == assignment.Slot.OpaqueName &&
		recovery.AdapterName == adapterName &&
		recovery.BrokerName == brokerName &&
		recovery.RunnerName == runnerName &&
		recovery.BuildID == prepared.Adapter.BuildID &&
		recovery.FleetGeneration == prepared.Adapter.FleetGeneration &&
		recovery.RelayParent == prepared.Broker.RelayParent &&
		recovery.AuthorityParent == prepared.Broker.AuthorityParent
}

func componentNames(slotIdentity string) (string, string, string, error) {
	match := opaqueSlotPattern.FindStringSubmatch(slotIdentity)
	if len(match) != 2 {
		return "", "", "", ErrInvalidState
	}
	suffix := match[1]
	return "pghar-adapter-" + suffix,
		"pghar-broker-" + suffix,
		"pghar-runner-" + suffix,
		nil
}

func (s *service) Observe(ctx context.Context, event githubscale.Event) error {
	return s.observeEvents(ctx, "", []githubscale.Event{event})
}

type observationPlan struct {
	event           githubscale.Event
	repositoryAlias string
	keys            []controller.AssignmentKey
}

func (s *service) observeEvents(
	ctx context.Context,
	repositoryAlias string,
	events []githubscale.Event,
) error {
	return s.observeEventsForMessage(ctx, repositoryAlias, events, 0)
}

func (s *service) observeEventsForMessage(
	ctx context.Context,
	repositoryAlias string,
	events []githubscale.Event,
	messageID int,
) error {
	if len(events) == 0 {
		return nil
	}
	plans, keys, err := s.planObservations(ctx, repositoryAlias, events)
	if err != nil {
		return err
	}
	unlock := s.locks.lockMany(keys)
	defer unlock()
	for _, plan := range plans {
		if err := s.applyObservationPlan(ctx, plan); err != nil {
			return err
		}
		if plan.event.Kind() == githubscale.EventCompleted && messageID > 0 {
			if len(plan.keys) != 1 {
				return ErrInvalidState
			}
			if err := s.state.BindTerminalMessage(
				ctx,
				plan.keys[0],
				messageID,
			); err != nil {
				return fmt.Errorf("%w: bind terminal message", ErrLifecycle)
			}
		}
	}
	return nil
}

func (s *service) Destroy(
	ctx context.Context,
	key controller.AssignmentKey,
	reason controller.ReasonCode,
) error {
	if !lifecycleReason(reason) {
		return fmt.Errorf("%w: invalid destroy reason", ErrLifecycle)
	}
	unlock := s.locks.lock(key)
	defer unlock()
	return s.destroyLocked(ctx, key, reason)
}

// RevokePreRunning destroys the exact durable pre-running set marked by one
// acquisition epoch. It shares the lifecycle's per-assignment exclusion with
// Release, observation, and reconciliation.
func (s *service) RevokePreRunning(
	ctx context.Context,
	epoch uint64,
	keys []controller.AssignmentKey,
) error {
	if epoch == 0 || len(keys) == 0 {
		if epoch == 0 && len(keys) != 0 {
			return ErrInvalidState
		}
		return nil
	}
	ordered := canonicalAssignmentKeys(keys)
	if len(ordered) != len(keys) {
		return ErrInvalidState
	}
	for _, key := range ordered {
		if key.RepositoryAlias == "" || key.RunnerRequestID <= 0 {
			return ErrInvalidState
		}
	}
	unlock := s.locks.lockMany(ordered)
	defer unlock()
	for _, key := range ordered {
		acquisition, err := s.state.AcquisitionAssignment(ctx, key)
		if err != nil ||
			acquisition.Key != key ||
			acquisition.RevokedEpoch != epoch {
			return errors.Join(ErrInvalidState, err)
		}
		record, found, err := s.findRecord(ctx, key)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if record.State == controller.StateReceived {
			if record.Slot != (controller.RunnerSlot{}) {
				return ErrInvalidState
			}
			if err := s.state.AdvancePreReleaseDestroyed(ctx, key); err != nil {
				return fmt.Errorf(
					"%w: terminalize revoked pre-reservation assignment",
					ErrLifecycle,
				)
			}
			s.dropCache(key)
			continue
		}
		if acquisition.Outcome != state.AcquisitionOutcomeAcquired {
			return ErrInvalidState
		}
		if record.State == controller.StateJobRunning {
			continue
		}
		if !isPreRunning(record.State) {
			return ErrInvalidState
		}
		if err := s.revokePreRunningLocked(ctx, record); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, "acquisition-revocation")
			return err
		}
	}
	return nil
}

// CancelRunning is the explicitly destructive drain path. It snapshots the
// complete running set, takes every same-key lifecycle lock in canonical
// order, revalidates each record, proves upstream and runtime cleanup, and
// advances through both legal terminal checkpoints. Ordinary acquisition
// revocation never calls this method.
func (s *service) CancelRunning(ctx context.Context) error {
	records, err := s.state.ListRecoverable(ctx)
	if err != nil {
		return fmt.Errorf("%w: list running assignments", ErrLifecycle)
	}
	keys := make([]controller.AssignmentKey, 0, len(records))
	for _, record := range records {
		if record.State == controller.StateJobRunning {
			keys = append(keys, record.Key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	ordered := canonicalAssignmentKeys(keys)
	if len(ordered) != len(keys) {
		return ErrInvalidState
	}
	unlock := s.locks.lockMany(ordered)
	defer unlock()

	for _, key := range ordered {
		record, found, err := s.findRecord(ctx, key)
		if err != nil {
			return err
		}
		if !found || record.State != controller.StateJobRunning {
			continue
		}
		if err := s.cleanupBothSides(ctx, record); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, "drain-cancel")
			return fmt.Errorf("%w: drain-cancel cleanup: %w", ErrLifecycle, err)
		}
		if err := s.state.Advance(
			ctx,
			key,
			controller.StateJobFinished,
		); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, "drain-cancel")
			return fmt.Errorf("%w: drain-cancel finish checkpoint", ErrLifecycle)
		}
		if err := s.state.Advance(
			ctx,
			key,
			controller.StateDestroyed,
		); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, "drain-cancel")
			return fmt.Errorf("%w: drain-cancel destroy checkpoint", ErrLifecycle)
		}
		s.dropCache(key)
	}
	return nil
}

func (s *service) revokePreRunningLocked(
	ctx context.Context,
	record state.RecoverableAssignment,
) error {
	listener, err := s.state.LookupAssignmentEffect(
		ctx,
		record.Key,
		state.LifecycleEffectListenerRelease,
	)
	if err != nil {
		return fmt.Errorf("%w: listener effect read", ErrLifecycle)
	}
	if listener.State == state.EffectAbsent {
		return s.destroyLocked(
			ctx,
			record.Key,
			controller.ReasonAcquisitionRevoke,
		)
	}
	if record.State != controller.StateReleaseArmed &&
		record.State != controller.StateListenerReleased {
		return ErrReleaseAmbiguous
	}
	return s.destroyPreRunningPostReleaseLocked(
		ctx,
		record,
		githubscale.RunnerRef{},
	)
}

func (s *service) destroyPreRunningPostReleaseLocked(
	ctx context.Context,
	record state.RecoverableAssignment,
	expected githubscale.RunnerRef,
) error {
	session, upstream, found, snapshot, runtime, err := s.readBothSides(ctx, record)
	if err != nil {
		return err
	}
	if expected != (githubscale.RunnerRef{}) &&
		(expected.ID <= 0 ||
			expected.Name != record.Slot.OpaqueName ||
			(found && upstream != expected)) {
		return ErrInvalidState
	}
	if found {
		if err := removeRunnerAndProve(ctx, session, upstream); err != nil {
			return fmt.Errorf("%w: revoked upstream removal", ErrCleanupUnproven)
		}
	}
	if err := s.removeRuntimeAndProve(ctx, record, &snapshot); err != nil {
		return fmt.Errorf("%w: revoked runtime removal", ErrCleanupUnproven)
	}
	evidence := reconciliationEvidence(record, upstream, found, runtime, true)
	if err := s.state.ResolvePostRelease(
		ctx,
		record.Key,
		controller.PostReleaseDestroyed,
		evidence,
		s.now(),
	); err != nil {
		return fmt.Errorf("%w: revoked terminal checkpoint", ErrLifecycle)
	}
	s.dropCache(record.Key)
	return nil
}

func (s *service) RecordBatch(
	ctx context.Context,
	envelope controller.MessageEnvelope,
) error {
	if envelope.RepositoryAlias == "" {
		return fmt.Errorf("%w: repository alias required", ErrLifecycle)
	}
	events := make(
		[]githubscale.Event,
		0,
		len(envelope.Assigned)+len(envelope.Started)+len(envelope.Completed),
	)
	for _, assigned := range envelope.Assigned {
		event, err := githubscale.NewAssignedEvent(githubscale.AssignedEvent{
			JobRef: githubJobRef(assigned.Job),
		})
		if err != nil {
			return fmt.Errorf("%w: assigned event: %w", ErrLifecycle, err)
		}
		events = append(events, event)
	}
	for _, started := range envelope.Started {
		event, err := githubscale.NewStartedEvent(githubscale.StartedEvent{
			JobRef:     githubJobRef(started.Job),
			RunnerID:   started.RunnerID,
			RunnerName: started.RunnerName,
		})
		if err != nil {
			return fmt.Errorf("%w: started event: %w", ErrLifecycle, err)
		}
		events = append(events, event)
	}
	for _, completed := range envelope.Completed {
		event, err := githubscale.NewCompletedEvent(githubscale.CompletedEvent{
			JobRef:     githubJobRef(completed.Job),
			Result:     completed.Result,
			RunnerID:   completed.RunnerID,
			RunnerName: completed.RunnerName,
		})
		if err != nil {
			return fmt.Errorf("%w: completed event: %w", ErrLifecycle, err)
		}
		events = append(events, event)
	}
	return s.observeEventsForMessage(
		ctx,
		envelope.RepositoryAlias,
		events,
		envelope.MessageID,
	)
}

func (s *service) ReconcileAssignment(
	ctx context.Context,
	assignment controller.RecoverableAssignment,
) error {
	unlock := s.locks.lock(assignment.Key)
	defer unlock()
	record, found, err := s.findRecord(ctx, assignment.Key)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !sameControllerRecovery(record, assignment) {
		return ErrInvalidState
	}
	acquisition, err := s.state.AcquisitionAssignment(ctx, assignment.Key)
	if err != nil || acquisition.Key != assignment.Key {
		return errors.Join(ErrInvalidState, err)
	}
	if acquisition.RevokedEpoch != 0 {
		if acquisition.Outcome != state.AcquisitionOutcomeAcquired {
			return ErrInvalidState
		}
		if record.State == controller.StateJobRunning {
			return s.verifyRunning(ctx, record)
		}
		if !isPreRunning(record.State) {
			return ErrInvalidState
		}
		return s.revokePreRunningLocked(ctx, record)
	}
	return s.reconcileLocked(ctx, record)
}

func (s *service) planObservations(
	ctx context.Context,
	repositoryAlias string,
	events []githubscale.Event,
) ([]observationPlan, []controller.AssignmentKey, error) {
	records, err := s.state.ListRecoverable(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read assignments", ErrLifecycle)
	}
	now := s.now()
	plans := make([]observationPlan, 0, len(events))
	protected := make(map[controller.AssignmentKey]struct{})
	for _, event := range events {
		plan, err := planObservation(records, repositoryAlias, event, now)
		if err != nil {
			return nil, nil, err
		}
		plans = append(plans, plan)
		if event.Kind() == githubscale.EventStarted ||
			event.Kind() == githubscale.EventCompleted {
			protected[plan.keys[0]] = struct{}{}
		}
	}
	var keys []controller.AssignmentKey
	for index := range plans {
		if plans[index].event.Kind() == githubscale.EventAssigned {
			filtered := plans[index].keys[:0]
			for _, key := range plans[index].keys {
				if _, ok := protected[key]; !ok {
					filtered = append(filtered, key)
				}
			}
			plans[index].keys = filtered
		}
		keys = append(keys, plans[index].keys...)
	}
	return plans, canonicalAssignmentKeys(keys), nil
}

func planObservation(
	records []state.RecoverableAssignment,
	repositoryAlias string,
	event githubscale.Event,
	now time.Time,
) (observationPlan, error) {
	plan := observationPlan{
		event:           event,
		repositoryAlias: repositoryAlias,
	}
	job := event.Job()
	switch event.Kind() {
	case githubscale.EventStarted, githubscale.EventCompleted:
		observedAt := runnerEventTime(event)
		if observedAt.IsZero() || observedAt.After(now) {
			return observationPlan{}, fmt.Errorf("%w: event time invalid", ErrLifecycle)
		}
		for _, record := range records {
			if (repositoryAlias == "" || record.Key.RepositoryAlias == repositoryAlias) &&
				record.Slot.OpaqueName == event.RunnerName() &&
				sameJob(record.Offer, job) {
				plan.keys = append(plan.keys, record.Key)
			}
		}
		if len(plan.keys) != 1 {
			return observationPlan{}, ErrInvalidState
		}
		plan.repositoryAlias = plan.keys[0].RepositoryAlias
		return plan, nil
	case githubscale.EventAssigned:
		if job.ScaleSetAssignTime.IsZero() || job.ScaleSetAssignTime.After(now) {
			return observationPlan{}, fmt.Errorf(
				"%w: assignment event time invalid",
				ErrLifecycle,
			)
		}
		candidateRepo := repositoryAlias
		for _, record := range records {
			if (repositoryAlias != "" && record.Key.RepositoryAlias != repositoryAlias) ||
				!sameJob(record.Offer, job) ||
				record.Offer.RunnerRequestID == job.RunnerRequestID ||
				record.Slot.UpstreamRunnerID != 0 ||
				!isPreRunning(record.State) ||
				record.Offer.ScaleSetAssignTime.IsZero() ||
				!record.Offer.ScaleSetAssignTime.Before(job.ScaleSetAssignTime) {
				continue
			}
			if repositoryAlias == "" {
				if candidateRepo == "" {
					candidateRepo = record.Key.RepositoryAlias
				} else if candidateRepo != record.Key.RepositoryAlias {
					return observationPlan{}, ErrInvalidState
				}
			}
			plan.keys = append(plan.keys, record.Key)
		}
		plan.repositoryAlias = candidateRepo
		plan.keys = canonicalAssignmentKeys(plan.keys)
		return plan, nil
	default:
		return observationPlan{}, fmt.Errorf("%w: unknown event kind", ErrLifecycle)
	}
}

func (s *service) applyObservationPlan(
	ctx context.Context,
	plan observationPlan,
) error {
	switch plan.event.Kind() {
	case githubscale.EventAssigned:
		return s.observeAssignedLocked(
			ctx,
			plan.repositoryAlias,
			plan.event,
			plan.keys,
		)
	case githubscale.EventStarted, githubscale.EventCompleted:
		if len(plan.keys) != 1 {
			return ErrInvalidState
		}
		return s.observeRunnerLocked(
			ctx,
			plan.repositoryAlias,
			plan.event,
			plan.keys[0],
		)
	default:
		return fmt.Errorf("%w: unknown event kind", ErrLifecycle)
	}
}

func (s *service) observeRunnerLocked(
	ctx context.Context,
	repositoryAlias string,
	event githubscale.Event,
	key controller.AssignmentKey,
) error {
	job := event.Job()
	observedAt := runnerEventTime(event)
	current, err := s.record(ctx, key)
	if err != nil {
		return err
	}
	if current.Slot.OpaqueName != event.RunnerName() ||
		(repositoryAlias != "" && current.Key.RepositoryAlias != repositoryAlias) ||
		!sameJob(current.Offer, job) ||
		current.Slot.RunnerContainerID == "" {
		return ErrInvalidState
	}
	acquisition, err := s.state.AcquisitionAssignment(ctx, key)
	if err != nil || acquisition.Key != key {
		return errors.Join(ErrInvalidState, err)
	}
	if acquisition.RevokedEpoch != 0 {
		if acquisition.Outcome != state.AcquisitionOutcomeAcquired ||
			!isPreRunning(current.State) {
			return ErrInvalidState
		}
		listener, err := s.state.LookupAssignmentEffect(
			ctx,
			key,
			state.LifecycleEffectListenerRelease,
		)
		if err != nil ||
			(listener.State != state.EffectPending &&
				listener.State != state.EffectCompleted) {
			return errors.Join(ErrInvalidState, err)
		}
		return s.destroyPreRunningPostReleaseLocked(
			ctx,
			current,
			githubscale.RunnerRef{
				ID:   event.RunnerID(),
				Name: event.RunnerName(),
			},
		)
	}
	if current.State != controller.StateJobRunning {
		listener, err := s.state.LookupAssignmentEffect(
			ctx,
			key,
			state.LifecycleEffectListenerRelease,
		)
		if err != nil {
			return fmt.Errorf("%w: listener effect read", ErrLifecycle)
		}
		if listener.State == state.EffectAbsent {
			return ErrInvalidState
		}
		if current.State != controller.StateListenerReleased ||
			listener.State != state.EffectCompleted ||
			!s.listenerBindingCurrent(ctx, key) {
			cleanupErr := s.destroyPreRunningPostReleaseLocked(
				ctx,
				current,
				githubscale.RunnerRef{
					ID:   event.RunnerID(),
					Name: event.RunnerName(),
				},
			)
			if cleanupErr != nil {
				_ = s.state.MarkAmbiguous(ctx, key, "listener-binding-invalid")
			}
			return cleanupErr
		}
	}
	return s.state.ApplyRunnerObservation(ctx, key, state.RunnerObservation{
		UpstreamRunnerID:  event.RunnerID(),
		BoundRequestID:    job.RunnerRequestID,
		RunnerContainerID: current.Slot.RunnerContainerID,
		Finished:          event.Kind() == githubscale.EventCompleted,
		ObservedAt:        observedAt,
	})
}

func (s *service) listenerBindingCurrent(
	ctx context.Context,
	key controller.AssignmentKey,
) bool {
	s.cacheMu.Lock()
	live, ok := s.live[key]
	s.cacheMu.Unlock()
	if !ok || live.permit == nil || live.assignment.Key != key {
		return false
	}
	persistedDigest, err := controller.AcquisitionPermitBindingDigest(live.binding)
	if err != nil {
		return false
	}
	currentDigest, err := controller.AcquisitionPermitBindingDigest(live.permit.Binding())
	if err != nil || currentDigest != persistedDigest {
		return false
	}
	return live.permit.ValidateBinding(ctx, live.binding) == nil
}

func (s *service) observeAssignedLocked(
	ctx context.Context,
	repositoryAlias string,
	event githubscale.Event,
	keys []controller.AssignmentKey,
) error {
	job := event.Job()
	for _, key := range keys {
		current, found, err := s.findRecord(ctx, key)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if current.Slot.UpstreamRunnerID != 0 ||
			current.Key.RepositoryAlias != repositoryAlias ||
			!isPreRunning(current.State) ||
			!sameJob(current.Offer, job) ||
			current.Offer.RunnerRequestID == job.RunnerRequestID ||
			current.Offer.ScaleSetAssignTime.IsZero() ||
			!current.Offer.ScaleSetAssignTime.Before(job.ScaleSetAssignTime) {
			return ErrInvalidState
		}
		if err := s.destroyLocked(ctx, key, controller.ReasonLifecycleReassigned); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, "reassignment-retirement")
			return err
		}
	}
	return nil
}

func (s *service) destroyLocked(
	ctx context.Context,
	key controller.AssignmentKey,
	reason controller.ReasonCode,
) error {
	record, found, err := s.findRecord(ctx, key)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	listener, err := s.state.LookupAssignmentEffect(
		ctx,
		key,
		state.LifecycleEffectListenerRelease,
	)
	if err != nil {
		return fmt.Errorf("%w: listener effect read", ErrLifecycle)
	}
	switch record.State {
	case controller.StateJobFinished:
		if err := s.cleanupBothSides(ctx, record); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, destroyReason(reason))
			return err
		}
		if err := s.state.Advance(ctx, key, controller.StateDestroyed); err != nil {
			return fmt.Errorf("%w: finish terminal checkpoint", ErrLifecycle)
		}
		s.dropCache(key)
		return nil
	case controller.StateListenerReleased, controller.StateJobRunning:
		_ = s.state.MarkAmbiguous(ctx, key, destroyReason(reason))
		return ErrReleaseAmbiguous
	default:
		if !isPreRelease(record.State) {
			return ErrInvalidState
		}
		if listener.State != state.EffectAbsent {
			_ = s.state.MarkAmbiguous(ctx, key, destroyReason(reason))
			return ErrReleaseAmbiguous
		}
		if err := s.cleanupBothSides(ctx, record); err != nil {
			_ = s.state.MarkAmbiguous(ctx, key, destroyReason(reason))
			return err
		}
		if err := s.state.AdvancePreReleaseDestroyed(ctx, key); err != nil {
			return fmt.Errorf("%w: pre-release terminal checkpoint", ErrLifecycle)
		}
		s.dropCache(key)
		return nil
	}
}

func (s *service) reconcileLocked(
	ctx context.Context,
	record state.RecoverableAssignment,
) error {
	listener, err := s.state.LookupAssignmentEffect(
		ctx,
		record.Key,
		state.LifecycleEffectListenerRelease,
	)
	if err != nil {
		return fmt.Errorf("%w: listener effect read", ErrLifecycle)
	}
	switch record.State {
	case controller.StateReceived:
		return nil
	case controller.StateCapacityReserved:
		first, err := s.state.LookupAssignmentEffect(
			ctx,
			record.Key,
			networkjail.StageAdapterCreate.String(),
		)
		if err != nil {
			return err
		}
		if first.State == state.EffectAbsent && !record.Ambiguous {
			assignment, err := assignmentFromRecord(record)
			if err != nil {
				return err
			}
			if _, err := s.prepareLocked(ctx, assignment); err != nil {
				return err
			}
			return s.releaseLocked(ctx, record.Key)
		}
		return s.destroyLocked(ctx, record.Key, controller.ReasonLifecycleReconcile)
	case controller.StateReleaseArmed:
		if listener.State == state.EffectAbsent {
			return s.destroyLocked(ctx, record.Key, controller.ReasonLifecycleReconcile)
		}
		return s.reconcilePostRelease(ctx, record, listener)
	case controller.StateListenerReleased:
		if listener.State == state.EffectAbsent {
			return ErrInvalidState
		}
		return s.reconcilePostRelease(ctx, record, listener)
	case controller.StateJobRunning:
		return s.verifyRunning(ctx, record)
	case controller.StateJobFinished:
		return s.destroyLocked(ctx, record.Key, controller.ReasonLifecycleJobFinished)
	default:
		if isPreRelease(record.State) {
			if listener.State != state.EffectAbsent {
				return ErrInvalidState
			}
			return s.destroyLocked(ctx, record.Key, controller.ReasonLifecycleReconcile)
		}
		return ErrInvalidState
	}
}

func (s *service) reconcilePostRelease(
	ctx context.Context,
	record state.RecoverableAssignment,
	_ state.EffectRecord,
) error {
	session, upstream, found, snapshot, runtime, err := s.readBothSides(ctx, record)
	if err != nil {
		return err
	}
	runnerLive := runtimeGraphLive(runtime)
	runtimeResidue := runtime.AdapterPresent ||
		runtime.BrokerPresent ||
		runtime.RunnerPresent
	switch {
	case found && runnerLive:
		return s.resolveLivePostRelease(ctx, record, upstream, runtime)
	case !found && !runtimeResidue:
		if err := s.removeRuntimeAndProve(ctx, record, &snapshot); err != nil {
			return fmt.Errorf("%w: empty runtime cleanup", ErrCleanupUnproven)
		}
		evidence := reconciliationEvidence(
			record,
			githubscale.RunnerRef{},
			false,
			hostruntime.ManagedObservation{},
			true,
		)
		if err := s.state.ResolvePostRelease(
			ctx,
			record.Key,
			controller.PostReleaseDestroyed,
			evidence,
			s.now(),
		); err != nil {
			return err
		}
		s.dropCache(record.Key)
		return nil
	default:
		if found {
			if err := removeRunnerAndProve(ctx, session, upstream); err != nil {
				return fmt.Errorf("%w: upstream residue", ErrCleanupUnproven)
			}
		}
		if err := s.removeRuntimeAndProve(ctx, record, &snapshot); err != nil {
			return fmt.Errorf("%w: runtime residue", ErrCleanupUnproven)
		}
		evidence := reconciliationEvidence(
			record,
			upstream,
			found,
			runtime,
			true,
		)
		if err := s.state.ResolvePostRelease(
			ctx,
			record.Key,
			controller.PostReleaseDestroyed,
			evidence,
			s.now(),
		); err != nil {
			return err
		}
		s.dropCache(record.Key)
		return nil
	}
}

func (s *service) resolveLivePostRelease(
	ctx context.Context,
	record state.RecoverableAssignment,
	upstream githubscale.RunnerRef,
	runtime hostruntime.ManagedObservation,
) error {
	switch record.State {
	case controller.StateListenerReleased:
		return nil
	case controller.StateReleaseArmed:
	default:
		return ErrInvalidState
	}
	evidence := reconciliationEvidence(record, upstream, true, runtime, false)
	return s.state.ResolvePostRelease(
		ctx,
		record.Key,
		controller.PostReleaseListenerReleased,
		evidence,
		s.now(),
	)
}

func (s *service) verifyRunning(
	ctx context.Context,
	record state.RecoverableAssignment,
) error {
	_, upstream, found, _, runtime, err := s.readBothSides(ctx, record)
	if err != nil {
		return err
	}
	if !found ||
		record.Slot.UpstreamRunnerID <= 0 ||
		upstream.ID != record.Slot.UpstreamRunnerID ||
		upstream.Name != record.Slot.OpaqueName ||
		!runtimeGraphLive(runtime) {
		_ = s.state.MarkAmbiguous(ctx, record.Key, "running-readback-conflict")
		return ErrReleaseAmbiguous
	}
	return nil
}

func runtimeGraphLive(observation hostruntime.ManagedObservation) bool {
	return observation.AdapterPresent &&
		observation.AdapterRunning &&
		observation.BrokerPresent &&
		observation.BrokerRunning &&
		observation.RunnerPresent &&
		observation.RunnerRunning
}

func (s *service) readBothSides(
	ctx context.Context,
	record state.RecoverableAssignment,
) (
	githubscale.Session,
	githubscale.RunnerRef,
	bool,
	hostruntime.ManagedSnapshot,
	hostruntime.ManagedObservation,
	error,
) {
	session, err := s.sessions.Session(ctx, record.Key.RepositoryAlias)
	if err != nil || session == nil {
		return nil, githubscale.RunnerRef{}, false,
			hostruntime.ManagedSnapshot{}, hostruntime.ManagedObservation{},
			fmt.Errorf("%w: session unavailable", ErrLifecycle)
	}
	upstream, found, err := session.GetRunnerByName(ctx, record.Slot.OpaqueName)
	if err != nil {
		return nil, githubscale.RunnerRef{}, false,
			hostruntime.ManagedSnapshot{}, hostruntime.ManagedObservation{}, err
	}
	if found {
		if upstream.ID <= 0 || upstream.Name != record.Slot.OpaqueName ||
			(record.Slot.UpstreamRunnerID != 0 &&
				upstream.ID != record.Slot.UpstreamRunnerID) {
			return nil, githubscale.RunnerRef{}, false,
				hostruntime.ManagedSnapshot{}, hostruntime.ManagedObservation{},
				ErrInvalidState
		}
	} else if upstream != (githubscale.RunnerRef{}) {
		return nil, githubscale.RunnerRef{}, false,
			hostruntime.ManagedSnapshot{}, hostruntime.ManagedObservation{},
			ErrInvalidState
	}
	recovery, err := s.recoveryForRecord(ctx, record)
	if err != nil {
		return nil, githubscale.RunnerRef{}, false,
			hostruntime.ManagedSnapshot{}, hostruntime.ManagedObservation{}, err
	}
	snapshot, err := s.recovery.InspectManaged(ctx, recovery)
	if err != nil {
		return nil, githubscale.RunnerRef{}, false,
			hostruntime.ManagedSnapshot{}, hostruntime.ManagedObservation{},
			fmt.Errorf("%w: managed inspection", ErrLifecycle)
	}
	return session, upstream, found, snapshot, snapshot.Observation(), nil
}

func (s *service) cleanupBothSides(
	ctx context.Context,
	record state.RecoverableAssignment,
) error {
	if !isBeforeJIT(record.State) {
		session, err := s.sessions.Session(ctx, record.Key.RepositoryAlias)
		if err != nil || session == nil {
			return fmt.Errorf("%w: session unavailable", ErrCleanupUnproven)
		}
		upstream, found, err := session.GetRunnerByName(ctx, record.Slot.OpaqueName)
		if err != nil {
			return fmt.Errorf("%w: upstream read", ErrCleanupUnproven)
		}
		if found {
			if upstream.ID <= 0 || upstream.Name != record.Slot.OpaqueName ||
				(record.Slot.UpstreamRunnerID != 0 &&
					upstream.ID != record.Slot.UpstreamRunnerID) {
				return ErrInvalidState
			}
			if err := removeRunnerAndProve(ctx, session, upstream); err != nil {
				return fmt.Errorf("%w: upstream removal", ErrCleanupUnproven)
			}
		} else if upstream != (githubscale.RunnerRef{}) {
			return ErrInvalidState
		}
	}

	if err := s.removeRuntimeAndProve(ctx, record, nil); err != nil {
		return err
	}
	return nil
}

func isBeforeJIT(value controller.State) bool {
	switch value {
	case controller.StateReceived,
		controller.StateCapacityReserved,
		controller.StateAdapterCreated,
		controller.StateAdapterVerified,
		controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified,
		controller.StateRunnerHeld:
		return true
	default:
		return false
	}
}

func (s *service) removeRuntimeAndProve(
	ctx context.Context,
	record state.RecoverableAssignment,
	inspected *hostruntime.ManagedSnapshot,
) error {
	s.cacheMu.Lock()
	held, heldOK := s.held[record.Key]
	live, liveOK := s.live[record.Key]
	s.cacheMu.Unlock()
	if heldOK && liveOK {
		return ErrInvalidState
	}

	var (
		recovery hostruntime.RecoverySpec
		snapshot hostruntime.ManagedSnapshot
		err      error
	)
	switch {
	case heldOK:
		recovery = recoveryWithSlot(held.recovery, record.Slot)
		if err := s.jails.DestroyHeld(ctx, held.jail); err != nil {
			return fmt.Errorf("%w: held jail", ErrCleanupUnproven)
		}
		s.cacheMu.Lock()
		delete(s.held, record.Key)
		s.cacheMu.Unlock()
	case liveOK:
		recovery = recoveryWithSlot(live.recovery, record.Slot)
		if err := s.jails.DestroyLive(ctx, live.jail); err != nil {
			return fmt.Errorf("%w: live jail", ErrCleanupUnproven)
		}
		s.cacheMu.Lock()
		delete(s.live, record.Key)
		s.cacheMu.Unlock()
	default:
		recovery, err = s.recoveryForRecord(ctx, record)
		if err != nil {
			return err
		}
		if inspected != nil {
			snapshot = *inspected
		}
	}
	if heldOK || liveOK || inspected == nil {
		snapshot, err = s.recovery.InspectManaged(ctx, recovery)
		if err != nil {
			return fmt.Errorf("%w: managed absence inspection", ErrCleanupUnproven)
		}
	}
	if err := s.recovery.RemoveManaged(ctx, snapshot); err != nil {
		return fmt.Errorf("%w: managed removal", ErrCleanupUnproven)
	}
	return nil
}

func (s *service) recoveryForRecord(
	ctx context.Context,
	record state.RecoverableAssignment,
) (hostruntime.RecoverySpec, error) {
	s.cacheMu.Lock()
	if held, ok := s.held[record.Key]; ok {
		s.cacheMu.Unlock()
		return recoveryWithSlot(held.recovery, record.Slot), nil
	}
	if live, ok := s.live[record.Key]; ok {
		s.cacheMu.Unlock()
		return recoveryWithSlot(live.recovery, record.Slot), nil
	}
	s.cacheMu.Unlock()
	assignment, err := assignmentFromRecord(record)
	if err != nil {
		return hostruntime.RecoverySpec{}, err
	}
	prepared, recovery, err := s.builder.Build(ctx, assignment)
	if err != nil || !validBuiltSetup(assignment, prepared, recovery) {
		return hostruntime.RecoverySpec{}, ErrInvalidState
	}
	return recoveryWithSlot(recovery, record.Slot), nil
}

func assignmentFromRecord(
	record state.RecoverableAssignment,
) (controller.Assignment, error) {
	offer := githubscale.Offer{
		JobRef: githubscale.JobRef{
			RunnerRequestID:    record.Offer.RunnerRequestID,
			JobID:              record.Offer.JobID,
			RepositoryName:     record.Offer.RepositoryName,
			OwnerName:          record.Offer.OwnerName,
			JobWorkflowRef:     record.Offer.JobWorkflowRef,
			JobDisplayName:     record.Offer.JobDisplayName,
			WorkflowRunID:      record.Offer.WorkflowRunID,
			EventName:          record.Offer.EventName,
			RequestLabels:      append([]string(nil), record.Offer.RequestLabels...),
			QueueTime:          record.Offer.QueueTime,
			ScaleSetAssignTime: record.Offer.ScaleSetAssignTime,
			RunnerAssignTime:   record.Offer.RunnerAssignTime,
			FinishTime:         record.Offer.FinishTime,
		},
		AcquireJobURL: record.Offer.AcquireJobURL,
	}
	return controller.NewAssignment(record.Key, offer, record.Slot)
}

func (s *service) findRecord(
	ctx context.Context,
	key controller.AssignmentKey,
) (state.RecoverableAssignment, bool, error) {
	records, err := s.state.ListRecoverable(ctx)
	if err != nil {
		return state.RecoverableAssignment{}, false,
			fmt.Errorf("%w: read durable assignment", ErrLifecycle)
	}
	var (
		found state.RecoverableAssignment
		count int
	)
	for _, record := range records {
		if record.Key == key {
			found = record
			count++
		}
	}
	if count > 1 {
		return state.RecoverableAssignment{}, false, ErrInvalidState
	}
	return found, count == 1, nil
}

func (s *service) dropCache(key controller.AssignmentKey) {
	s.cacheMu.Lock()
	delete(s.held, key)
	delete(s.live, key)
	s.cacheMu.Unlock()
}

func isPreRelease(value controller.State) bool {
	switch value {
	case controller.StateReceived,
		controller.StateCapacityReserved,
		controller.StateAdapterCreated,
		controller.StateAdapterVerified,
		controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified,
		controller.StateRunnerHeld,
		controller.StateReleaseArmed:
		return true
	default:
		return false
	}
}

func isPreRunning(value controller.State) bool {
	return isPreRelease(value) || value == controller.StateListenerReleased
}

func destroyReason(reason controller.ReasonCode) string {
	switch reason {
	case controller.ReasonLifecycleCanceled:
		return "lifecycle-canceled"
	case controller.ReasonLifecyclePrepareFailed:
		return "lifecycle-prepare-failed"
	case controller.ReasonLifecycleReleaseAmbiguous:
		return "lifecycle-release-ambiguous"
	case controller.ReasonLifecycleReassigned:
		return "lifecycle-reassigned"
	case controller.ReasonLifecycleJobFinished:
		return "lifecycle-job-finished"
	case controller.ReasonLifecycleReconcile:
		return "lifecycle-reconcile"
	case controller.ReasonAcquisitionRevoke:
		return "acquisition-revoked"
	default:
		return "lifecycle-invalid"
	}
}

func githubJobRef(job controller.MessageJobRef) githubscale.JobRef {
	return githubscale.JobRef{
		RunnerRequestID:    job.RunnerRequestID,
		JobID:              job.JobID,
		RepositoryName:     job.RepositoryName,
		OwnerName:          job.OwnerName,
		JobWorkflowRef:     job.JobWorkflowRef,
		JobDisplayName:     job.JobDisplayName,
		WorkflowRunID:      job.WorkflowRunID,
		EventName:          job.EventName,
		RequestLabels:      append([]string(nil), job.RequestLabels...),
		QueueTime:          job.QueueTime,
		ScaleSetAssignTime: job.ScaleSetAssignTime,
		RunnerAssignTime:   job.RunnerAssignTime,
		FinishTime:         job.FinishTime,
	}
}

func sameControllerRecovery(
	native state.RecoverableAssignment,
	projected controller.RecoverableAssignment,
) bool {
	admission, ok := controllerRecoveryAdmission(native.Key, native.Admission)
	if !ok {
		return false
	}
	nativeOffer := controllerRecoveryOffer(native.Offer)
	projectedOffer := projected.Offer
	nativeOffer.RequestLabels = append([]string{}, nativeOffer.RequestLabels...)
	projectedOffer.RequestLabels = append([]string{}, projectedOffer.RequestLabels...)
	return native.Key == projected.Key &&
		native.State == projected.State &&
		reflect.DeepEqual(nativeOffer, projectedOffer) &&
		reflect.DeepEqual(admission, projected.Admission) &&
		native.Released == projected.Released &&
		native.Ambiguous == projected.Ambiguous &&
		native.AmbiguousReason == projected.AmbiguousReason &&
		native.Slot == projected.Slot &&
		native.UpdatedAt.Equal(projected.UpdatedAt)
}

func controllerRecoveryOffer(offer state.OfferIdentity) githubscale.Offer {
	return githubscale.Offer{
		JobRef: githubscale.JobRef{
			RunnerRequestID:    offer.RunnerRequestID,
			JobID:              offer.JobID,
			RepositoryName:     offer.RepositoryName,
			OwnerName:          offer.OwnerName,
			JobWorkflowRef:     offer.JobWorkflowRef,
			JobDisplayName:     offer.JobDisplayName,
			WorkflowRunID:      offer.WorkflowRunID,
			EventName:          offer.EventName,
			RequestLabels:      append([]string(nil), offer.RequestLabels...),
			QueueTime:          offer.QueueTime,
			ScaleSetAssignTime: offer.ScaleSetAssignTime,
			RunnerAssignTime:   offer.RunnerAssignTime,
			FinishTime:         offer.FinishTime,
		},
		AcquireJobURL: offer.AcquireJobURL,
	}
}

func controllerRecoveryAdmission(
	key controller.AssignmentKey,
	admission state.AdmissionProjection,
) (controller.AdmissionReference, bool) {
	if !admission.Valid {
		return controller.AdmissionReference{}, true
	}
	var phase controller.AdmissionPhase
	switch admission.Phase {
	case state.AdmissionQueued:
		phase = controller.AdmissionQueued
	case state.AdmissionReserved:
		phase = controller.AdmissionReserved
	case state.AdmissionActive:
		phase = controller.AdmissionActive
	default:
		return controller.AdmissionReference{}, false
	}
	return controller.AdmissionReference{
		Key:             key,
		Phase:           phase,
		SlotID:          admission.SlotID,
		FullCharge:      controllerRecoveryResources(admission.FullCharge),
		LedgerCharge:    controllerRecoveryResources(admission.LedgerCharge),
		LedgerCreatedAt: admission.LedgerCreatedAt,
		LedgerEverUsed:  admission.LedgerEverUsed,
	}, true
}

func controllerRecoveryResources(
	resources state.ResourceProjection,
) controller.ResourceProjection {
	return controller.ResourceProjection{
		MilliCPU:          resources.MilliCPU,
		MemoryBytes:       resources.MemoryBytes,
		PIDs:              resources.PIDs,
		FileDescriptors:   resources.FileDescriptors,
		TmpfsBytes:        resources.TmpfsBytes,
		ScratchBytes:      resources.ScratchBytes,
		SocketStateBytes:  resources.SocketStateBytes,
		DurableStateBytes: resources.DurableStateBytes,
		Inodes:            resources.Inodes,
	}
}

func reconciliationEvidence(
	record state.RecoverableAssignment,
	upstream githubscale.RunnerRef,
	upstreamFound bool,
	runtime hostruntime.ManagedObservation,
	cleanupAbsent bool,
) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("portable-ghar.lifecycle-reconciliation.v1\x00"))
	writeEvidenceString(hash, record.Slot.OpaqueName)
	writeEvidenceInt64(hash, record.Slot.UpstreamRunnerID)
	writeEvidenceString(hash, record.Slot.RunnerContainerID)
	writeEvidenceString(hash, record.Slot.AdapterContainerID)
	writeEvidenceString(hash, record.Slot.BrokerContainerID)
	writeEvidenceInt64(hash, upstream.ID)
	writeEvidenceString(hash, upstream.Name)
	for _, value := range []bool{
		upstreamFound,
		runtime.AdapterPresent,
		runtime.AdapterRunning,
		runtime.BrokerPresent,
		runtime.BrokerRunning,
		runtime.RunnerPresent,
		runtime.RunnerRunning,
		cleanupAbsent,
	} {
		if value {
			_, _ = hash.Write([]byte{1})
		} else {
			_, _ = hash.Write([]byte{0})
		}
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type evidenceWriter interface {
	Write([]byte) (int, error)
}

func writeEvidenceString(writer evidenceWriter, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func writeEvidenceInt64(writer evidenceWriter, value int64) {
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(value))
	_, _ = writer.Write(scalar[:])
}

type keyedLocks struct {
	mu      sync.Mutex
	entries map[controller.AssignmentKey]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func (locks *keyedLocks) lock(key controller.AssignmentKey) func() {
	locks.mu.Lock()
	entry := locks.entries[key]
	if entry == nil {
		entry = &keyedLock{}
		locks.entries[key] = entry
	}
	entry.refs++
	locks.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		locks.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(locks.entries, key)
		}
		locks.mu.Unlock()
	}
}

func (locks *keyedLocks) lockMany(keys []controller.AssignmentKey) func() {
	keys = canonicalAssignmentKeys(keys)
	unlocks := make([]func(), 0, len(keys))
	for _, key := range keys {
		unlocks = append(unlocks, locks.lock(key))
	}
	return func() {
		for index := len(unlocks) - 1; index >= 0; index-- {
			unlocks[index]()
		}
	}
}

func canonicalAssignmentKeys(
	keys []controller.AssignmentKey,
) []controller.AssignmentKey {
	keys = append([]controller.AssignmentKey(nil), keys...)
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].RepositoryAlias != keys[j].RepositoryAlias {
			return keys[i].RepositoryAlias < keys[j].RepositoryAlias
		}
		if keys[i].RunnerRequestID != keys[j].RunnerRequestID {
			return keys[i].RunnerRequestID < keys[j].RunnerRequestID
		}
		return keys[i].Attempt < keys[j].Attempt
	})
	unique := keys[:0]
	for _, key := range keys {
		if len(unique) == 0 || unique[len(unique)-1] != key {
			unique = append(unique, key)
		}
	}
	return unique
}

func lifecycleReason(reason controller.ReasonCode) bool {
	switch reason {
	case controller.ReasonLifecycleCanceled,
		controller.ReasonLifecyclePrepareFailed,
		controller.ReasonLifecycleReleaseAmbiguous,
		controller.ReasonLifecycleReassigned,
		controller.ReasonLifecycleJobFinished,
		controller.ReasonLifecycleReconcile:
		return true
	default:
		return false
	}
}

func sameJob(left state.OfferIdentity, right githubscale.JobRef) bool {
	return left.JobID != "" &&
		left.JobID == right.JobID &&
		left.RepositoryName == right.RepositoryName &&
		left.OwnerName == right.OwnerName
}

func runnerEventTime(event githubscale.Event) time.Time {
	job := event.Job()
	if event.Kind() == githubscale.EventCompleted {
		return job.FinishTime
	}
	return job.RunnerAssignTime
}

func recoveryWithSlot(
	base hostruntime.RecoverySpec,
	slot controller.RunnerSlot,
) hostruntime.RecoverySpec {
	base.ExpectedAdapterID = slot.AdapterContainerID
	base.ExpectedBrokerID = slot.BrokerContainerID
	base.ExpectedRunnerID = slot.RunnerContainerID
	return base
}
