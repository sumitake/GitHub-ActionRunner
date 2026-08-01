package testenv

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

const task11LossRunDigestDomain = "portable-ghar.task11.loss-run.v1\x00"

type task11RealLossAttemptSource struct {
	input        ConformanceInput
	overlay      hostruntime.PrivateOverlay
	static       staticPreflightResult
	seccomp      hostruntime.SeccompBinding
	graph        networkjail.DecisionGraph
	policy       hostruntime.PolicyArtifact
	probes       probeMembershipSeal
	primaryPlan  compositionPlan
	store        *state.SQLiteStore
	clock        networkjail.MonotonicClock
	peerObserver permitPeerProcessObserver
	record       func(cleanupHandle) error
	now          func() time.Time

	mu          sync.Mutex
	attempted   bool
	composition *fixtureRuntimeComposition
	handles     []cleanupHandle
}

func (s *task11RealLossAttemptSource) RunLossAttempt(
	ctx context.Context,
	fact task11MissingPreparedFact,
) (task11LossAttemptObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil ||
		!validTask11MissingPreparedFact(fact) {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	s.mu.Lock()
	if s.attempted {
		s.mu.Unlock()
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	s.attempted = true
	s.mu.Unlock()

	runDigest, err := task11LossRunDigest(
		s.input.Authorization.RunID,
		fact,
	)
	if err != nil {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	lossInput := s.input
	lossInput.Authorization.RunID = runDigest
	lossPlan, err := compositionPlanFrom(lossInput, s.overlay)
	if err != nil ||
		lossPlan.Identity.CapacitySlotID ==
			s.primaryPlan.Identity.CapacitySlotID ||
		lossPlan.Identity.JobGeneration ==
			s.primaryPlan.Identity.JobGeneration ||
		lossPlan.Identity.RunnerRequestID ==
			s.primaryPlan.Identity.RunnerRequestID ||
		lossPlan.Identity.AdapterName ==
			s.primaryPlan.Identity.AdapterName ||
		lossPlan.Identity.BrokerName ==
			s.primaryPlan.Identity.BrokerName ||
		lossPlan.Identity.RunnerName ==
			s.primaryPlan.Identity.RunnerName {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	now := s.now().UTC()
	if now.IsZero() ||
		seedCompositionAssignment(
			ctx,
			s.store,
			lossPlan,
			now,
		) != nil {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}

	var handles []cleanupHandle
	lossRecord := func(handle cleanupHandle) error {
		for _, existing := range handles {
			if existing.id == handle.id {
				return ErrFixtureStart
			}
		}
		if err := s.record(handle); err != nil {
			return ErrFixtureStart
		}
		handles = append(handles, handle)
		s.mu.Lock()
		s.handles = append(s.handles, handle)
		s.mu.Unlock()
		return nil
	}
	composition, err := newFixtureRuntimeComposition(
		ctx,
		lossInput,
		s.overlay,
		s.static,
		s.seccomp,
		s.graph,
		s.policy,
		s.probes,
		lossPlan,
		s.store,
		s.clock,
		s.peerObserver,
		lossRecord,
	)
	if err != nil {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	faultEngine, err := newTask11ReleaseLossEngine(
		composition.Engine,
		fact,
	)
	if err != nil {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	faultOrchestrator, err := networkjail.NewOrchestrator(
		faultEngine,
		composition.Journal,
		composition.AuthorityManager,
	)
	if err != nil {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	composition.Orchestrator = faultOrchestrator
	s.mu.Lock()
	s.composition = &composition
	s.mu.Unlock()

	_, prepareErr := composition.Orchestrator.Prepare(
		ctx,
		composition.Request,
	)
	auditCalls, releaseCalls, injected := faultEngine.observation()
	if !errors.Is(prepareErr, networkjail.ErrSetupFailed) ||
		!injected ||
		auditCalls != 2 ||
		releaseCalls != 0 ||
		len(handles) != 3 ||
		handles[0].kind != CleanupAdapter ||
		handles[1].kind != CleanupBroker ||
		handles[2].kind != CleanupRunner {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	for _, handle := range handles {
		if !composition.Engine.RecordedRemoved(handle) {
			return task11LossAttemptObservation{}, ErrFixtureStart
		}
	}
	effect, err := s.store.LookupAssignmentEffect(
		ctx,
		lossPlan.AssignmentKey,
		networkjail.StageRunnerAuthorize.String(),
	)
	if err != nil ||
		effect.State != state.EffectFailed ||
		effect.ResultIdentity != "" ||
		effect.ReasonCode != "network-setup-failed" {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	terminalState, err := task11ExactAssignmentState(
		ctx,
		s.store,
		lossPlan.AssignmentKey,
	)
	if err != nil || terminalState != controller.StateDestroyed {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	cleanupDigest, err := recordingCanonicalDigest(
		"portable-ghar.task11.loss-cleanup.v1\x00",
		struct {
			SchemaVersion uint32                        `json:"schema_version"`
			RunDigest     string                        `json:"run_digest"`
			Assignment    controller.AssignmentKey      `json:"assignment"`
			Handles       []task11LossHandleObservation `json:"handles"`
			State         controller.State              `json:"state"`
			Stage         string                        `json:"stage"`
			Reason        string                        `json:"reason"`
			Success       bool                          `json:"success"`
		}{
			SchemaVersion: 1,
			RunDigest:     runDigest,
			Assignment:    lossPlan.AssignmentKey,
			Handles: []task11LossHandleObservation{
				task11LossHandleFromCleanup(handles[0]),
				task11LossHandleFromCleanup(handles[1]),
				task11LossHandleFromCleanup(handles[2]),
			},
			State:   terminalState,
			Stage:   networkjail.StageRunnerAuthorize.String(),
			Reason:  effect.ReasonCode,
			Success: true,
		},
	)
	if err != nil {
		return task11LossAttemptObservation{}, ErrFixtureStart
	}
	return task11LossAttemptObservation{
		RunDigest: runDigest,
		CapacitySlotID: networkjail.CapacitySlotID(
			lossPlan.Identity.CapacitySlotID,
		),
		JobGeneration: networkjail.JobGeneration(
			lossPlan.Identity.JobGeneration,
		),
		Adapter:         task11LossHandleFromCleanup(handles[0]),
		Broker:          task11LossHandleFromCleanup(handles[1]),
		Runner:          task11LossHandleFromCleanup(handles[2]),
		MissingFact:     fact,
		FailedStage:     networkjail.StageRunnerAuthorize.String(),
		TypedFailure:    networkjail.ErrSetupFailed.Error(),
		TerminalState:   terminalState,
		AuditCalls:      auditCalls,
		ReleaseCalls:    releaseCalls,
		CleanupDigest:   cleanupDigest,
		CleanupComplete: true,
	}, nil
}

func task11LossHandleFromCleanup(
	handle cleanupHandle,
) task11LossHandleObservation {
	return task11LossHandleObservation{
		Kind: handle.kind,
		ID:   handle.id,
	}
}

func task11LossRunDigest(
	primaryRunDigest string,
	fact task11MissingPreparedFact,
) (string, error) {
	if !isLowerHex(primaryRunDigest, sha256.Size*2) ||
		!validTask11MissingPreparedFact(fact) {
		return "", ErrFixtureStart
	}
	return recordingCanonicalDigest(
		task11LossRunDigestDomain,
		struct {
			SchemaVersion uint32                    `json:"schema_version"`
			Primary       string                    `json:"primary"`
			MissingFact   task11MissingPreparedFact `json:"missing_fact"`
		}{
			SchemaVersion: 1,
			Primary:       primaryRunDigest,
			MissingFact:   fact,
		},
	)
}

func task11ExactAssignmentState(
	ctx context.Context,
	store *state.SQLiteStore,
	key controller.AssignmentKey,
) (controller.State, error) {
	if ctx == nil || ctx.Err() != nil ||
		store == nil ||
		store.DB() == nil ||
		key.RepositoryAlias == "" ||
		key.RunnerRequestID <= 0 {
		return "", ErrFixtureStart
	}
	var raw string
	if err := store.DB().QueryRowContext(ctx, `
		SELECT state
		FROM assignments
		WHERE repository_alias = ?
		  AND runner_request_id = ?
		  AND attempt = ?
	`, key.RepositoryAlias, key.RunnerRequestID, key.Attempt).Scan(
		&raw,
	); err != nil {
		return "", ErrFixtureStart
	}
	stateValue := controller.State(raw)
	if stateValue == "" {
		return "", ErrFixtureStart
	}
	return stateValue, nil
}

func (s *task11RealLossAttemptSource) owns(
	handle cleanupHandle,
) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, candidate := range s.handles {
		if candidate == handle {
			return true
		}
	}
	return false
}

func (s *task11RealLossAttemptSource) remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if s == nil || !s.owns(handle) {
		return ErrFixtureCleanup
	}
	s.mu.Lock()
	composition := s.composition
	s.mu.Unlock()
	if composition == nil ||
		composition.Engine.RemoveRecorded(ctx, handle) != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (s *task11RealLossAttemptSource) recordedRemoved(
	handle cleanupHandle,
) bool {
	if s == nil || !s.owns(handle) {
		return false
	}
	s.mu.Lock()
	composition := s.composition
	s.mu.Unlock()
	return composition != nil &&
		composition.Engine.RecordedRemoved(handle)
}

var _ task11LossAttemptSource = (*task11RealLossAttemptSource)(nil)
