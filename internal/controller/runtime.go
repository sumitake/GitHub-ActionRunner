package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

var (
	ErrRuntimeUnavailable = errors.New("controller: runtime unavailable")
	ErrRuntimeShutdown    = errors.New("controller: runtime shutdown failed")
	ErrAdminConflict      = errors.New("controller: admin request conflicts with live policy")
	ErrDrain              = errors.New("controller: drain failed")
)

// RunningCanceler is the explicitly named destructive drain path. Ordinary
// acquisition revocation deliberately preserves JOB_RUNNING assignments.
type RunningCanceler interface {
	CancelRunning(context.Context) error
}

// PollTarget is one already-constructed, compatibility-proven repository
// session. Service.Run does not start any target until cold recovery succeeds.
type PollTarget struct {
	Fleet   githubscale.Fleet
	Session githubscale.Session
}

// DrainPolicy is the closed operator drain behavior.
type DrainPolicy string

const (
	DrainWait   DrainPolicy = "wait"
	DrainCancel DrainPolicy = "cancel"
)

// AcquisitionChange is the exact live-admin policy request. EligibleScaleSet
// is accepted only for canary-only and never appears in PolicyStatus.
type AcquisitionChange struct {
	Set              AcquisitionMode
	Expected         AcquisitionMode
	EligibleScaleSet string
}

// PolicyStatus is the closed, identity-free admin response.
type PolicyStatus struct {
	Mode     AcquisitionMode `json:"mode"`
	Epoch    uint64          `json:"epoch"`
	Digest   string          `json:"digest"`
	Capacity int             `json:"capacity"`
}

// LiveAdmin is the only mutating command target. A command process must use a
// live implementation of this interface and may never open SQLite read-write.
type LiveAdmin interface {
	Probe(context.Context) (PolicyStatus, error)
	ReconcileOnce(context.Context) (CycleReceipt, error)
	Drain(context.Context, DrainPolicy) error
	SetAcquisition(context.Context, AcquisitionChange) (PolicyStatus, error)
}

var _ LiveAdmin = (*Service)(nil)

func validServiceRuntimeConfig(config ServiceConfig) bool {
	template, err := CanonicalizeAcquisitionPolicy(config.EnabledPolicyTemplate)
	if err != nil || template.Mode != AcquisitionEnabled ||
		template.MaxCapacity <= 0 || len(template.EligibleScaleSets) == 0 {
		return false
	}
	repositories := make(map[string]struct{}, len(template.RepositoryPolicies))
	for _, repository := range template.RepositoryPolicies {
		repositories[repository.Alias] = struct{}{}
	}
	scaleSets := make(map[string]struct{}, len(template.EligibleScaleSets))
	for _, name := range template.EligibleScaleSets {
		scaleSets[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(config.PollTargets))
	for _, target := range config.PollTargets {
		if target.Session == nil ||
			target.Fleet.RepositoryAlias == "" ||
			target.Fleet.ScaleSetName == "" {
			return false
		}
		if _, duplicate := seen[target.Fleet.RepositoryAlias]; duplicate {
			return false
		}
		seen[target.Fleet.RepositoryAlias] = struct{}{}
		if _, ok := repositories[target.Fleet.RepositoryAlias]; !ok {
			return false
		}
		if _, ok := scaleSets[target.Fleet.ScaleSetName]; !ok {
			return false
		}
		compatibility := target.Session.Compatibility()
		if !compatibility.SingleNameLabel || !compatibility.DisableUpdate {
			return false
		}
	}
	return config.SessionCloseTimeout <= config.ShutdownTimeout &&
		config.TransitionJoinTimeout <= config.ShutdownTimeout
}

func clonePollTargets(input []PollTarget) []PollTarget {
	return append([]PollTarget(nil), input...)
}

// Run performs cold recovery before launching any poll or central cycle. It
// owns all session lifetimes and returns only after bounded loop join, a newer
// disabled epoch, pre-running revocation, and bounded session close.
func (s *Service) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.Start(ctx); err != nil {
		closeErr := s.closeRuntimeSessions()
		return errors.Join(err, closeErr)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	errs := make(chan error, len(s.pollTargets)+1)
	for _, target := range s.pollTargets {
		target := target
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := s.runPollLoop(runCtx, target); err != nil &&
				!errors.Is(err, context.Canceled) {
				sendRuntimeError(errs, err)
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := s.runCentralLoop(runCtx); err != nil &&
			!errors.Is(err, context.Canceled) {
			sendRuntimeError(errs, err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errs:
	}
	runCancel()

	joined := make(chan struct{})
	go func() {
		workers.Wait()
		close(joined)
	}()
	shutdownTimer := time.NewTimer(s.shutdownTimeout)
	defer shutdownTimer.Stop()
	select {
	case <-joined:
	case <-shutdownTimer.C:
		fatalErr := s.enterFatal(
			ReasonAcquisitionJoin,
			fmt.Errorf("%w: loop join deadline", ErrRuntimeShutdown),
		)
		return errors.Join(runErr, fatalErr, s.closeRuntimeSessions())
	}

	disableErr := s.disableForShutdown()
	closeErr := s.closeRuntimeSessions()
	if runErr != nil || disableErr != nil || closeErr != nil {
		return errors.Join(runErr, disableErr, closeErr)
	}
	return nil
}

func sendRuntimeError(destination chan<- error, err error) {
	select {
	case destination <- err:
	default:
	}
}

func (s *Service) runPollLoop(ctx context.Context, target PollTarget) error {
	ticker := time.NewTicker(s.pollCadence)
	defer ticker.Stop()
	for {
		if err := s.PollOnce(ctx, target.Fleet, target.Session); err != nil {
			return fmt.Errorf("%w: poll loop: %w", ErrRuntimeUnavailable, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) runCentralLoop(ctx context.Context) error {
	ticker := time.NewTicker(s.reconciliationCadence)
	defer ticker.Stop()
	for {
		if _, err := s.EvaluateHistoryPressure(ctx); err != nil {
			return fmt.Errorf("%w: history pressure: %w", ErrRuntimeUnavailable, err)
		}
		if _, err := s.EvaluateHostPressure(ctx); err != nil {
			return fmt.Errorf("%w: host pressure: %w", ErrRuntimeUnavailable, err)
		}
		if _, err := s.admitOnceAfterHostPressure(ctx); err != nil {
			return fmt.Errorf("%w: admission: %w", ErrRuntimeUnavailable, err)
		}
		if _, err := s.reconcileOnceAfterHostPressure(ctx); err != nil {
			return fmt.Errorf("%w: reconciliation: %w", ErrRuntimeUnavailable, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) disableForShutdown() error {
	current, ready := s.policySnapshot()
	if !ready {
		return nil
	}
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionDisabled
	next.MaxCapacity = 0
	next.EligibleScaleSets = nil
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		s.shutdownTimeout,
	)
	defer cancel()
	if _, err := s.Transition(shutdownCtx, current.Epoch, next); err != nil {
		return fmt.Errorf("%w: disable: %w", ErrRuntimeShutdown, err)
	}
	return nil
}

func (s *Service) closeRuntimeSessions() error {
	var result error
	for _, target := range s.pollTargets {
		closeCtx, cancel := context.WithTimeout(
			context.Background(),
			s.sessionCloseTimeout,
		)
		err := target.Session.Close(closeCtx)
		cancel()
		if err != nil {
			result = errors.Join(
				result,
				fmt.Errorf("%w: session close", ErrRuntimeShutdown),
			)
		}
	}
	return result
}

// Probe returns only the current policy tuple and exact broker capacity.
func (s *Service) Probe(ctx context.Context) (PolicyStatus, error) {
	policy, err := s.Snapshot(ctx)
	if err != nil {
		return PolicyStatus{}, err
	}
	return s.policyStatus(policy)
}

// SetAcquisition validates an exact expected mode and delegates the only
// policy mutation to Service.Transition.
func (s *Service) SetAcquisition(
	ctx context.Context,
	change AcquisitionChange,
) (PolicyStatus, error) {
	current, err := s.Snapshot(ctx)
	if err != nil {
		return PolicyStatus{}, err
	}
	if current.Mode != change.Expected ||
		current.Mode == AcquisitionFatal {
		return PolicyStatus{}, ErrAdminConflict
	}
	var next AcquisitionPolicy
	switch change.Set {
	case AcquisitionDisabled:
		if change.EligibleScaleSet != "" {
			return PolicyStatus{}, ErrAdminConflict
		}
		next = cloneAcquisitionPolicy(current)
		next.Mode = AcquisitionDisabled
		next.MaxCapacity = 0
		next.EligibleScaleSets = nil
	case AcquisitionCanaryOnly:
		if !validAcquisitionScalar(
			change.EligibleScaleSet,
			maxAcquisitionScaleSetBytes,
		) {
			return PolicyStatus{}, ErrAdminConflict
		}
		next = cloneAcquisitionPolicy(s.enabledTemplate)
		next.Mode = AcquisitionCanaryOnly
		next.MaxCapacity = 1
		next.EligibleScaleSets = []string{change.EligibleScaleSet}
	case AcquisitionEnabled:
		if change.EligibleScaleSet != "" {
			return PolicyStatus{}, ErrAdminConflict
		}
		next = cloneAcquisitionPolicy(s.enabledTemplate)
	default:
		return PolicyStatus{}, ErrAdminConflict
	}
	next.Epoch = current.Epoch
	transitionCtx, cancel := boundedContext(ctx, s.operationTimeout)
	defer cancel()
	persisted, err := s.Transition(transitionCtx, current.Epoch, next)
	if err != nil {
		return PolicyStatus{}, err
	}
	return s.policyStatus(persisted)
}

func (s *Service) policyStatus(policy AcquisitionPolicy) (PolicyStatus, error) {
	capacity := s.broker.CapacitySummary()
	if capacity.Epoch != policy.Epoch ||
		capacity.EffectiveCapacity != policy.MaxCapacity {
		return PolicyStatus{}, ErrAdminConflict
	}
	digest, err := AcquisitionPolicyDigest(policy)
	if err != nil {
		return PolicyStatus{}, err
	}
	return PolicyStatus{
		Mode:     policy.Mode,
		Epoch:    policy.Epoch,
		Digest:   hex.EncodeToString(digest[:]),
		Capacity: policy.MaxCapacity,
	}, nil
}

// Drain publishes a newer disabled epoch, optionally uses the explicitly
// destructive JOB_RUNNING cancellation path, then proves running and
// unassigned-released counts have reached zero before returning.
func (s *Service) Drain(ctx context.Context, policy DrainPolicy) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrAcquisitionDeadlineRequired
	}
	if policy != DrainWait && policy != DrainCancel {
		return ErrDrain
	}
	current, err := s.Snapshot(ctx)
	if err != nil {
		return err
	}
	if _, err := s.SetAcquisition(ctx, AcquisitionChange{
		Set:      AcquisitionDisabled,
		Expected: current.Mode,
	}); err != nil {
		return fmt.Errorf("%w: disable: %w", ErrDrain, err)
	}
	if policy == DrainCancel {
		if err := s.runningCanceler.CancelRunning(ctx); err != nil {
			return fmt.Errorf("%w: cancel running: %w", ErrDrain, err)
		}
	}
	ticker := time.NewTicker(s.drainPollCadence)
	defer ticker.Stop()
	for {
		summary, err := s.state.OperationalSummary(ctx, s.now())
		if err != nil {
			return fmt.Errorf("%w: summary: %w", ErrDrain, err)
		}
		if summary.RunningJobs == 0 &&
			summary.UnassignedReleasedListeners == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrDrain, ctx.Err())
		case <-ticker.C:
		}
	}
}
