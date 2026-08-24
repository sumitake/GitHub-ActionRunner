package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/health"
)

type task5InvalidatingPermitProvider struct {
	mu        sync.Mutex
	started   chan struct{}
	release   <-chan struct{}
	err       error
	calls     int
	startOnce sync.Once
}

func newTask5InvalidatingPermitProvider(
	release <-chan struct{},
	err error,
) *task5InvalidatingPermitProvider {
	return &task5InvalidatingPermitProvider{
		started: make(chan struct{}),
		release: release,
		err:     err,
	}
}

func (p *task5InvalidatingPermitProvider) Acquire(
	ctx context.Context,
	_ AcquisitionPermitRequest,
) (AcquisitionPermitGuard, error) {
	return canonicalPermitGuardStub{ctx: ctx}, nil
}

func (p *task5InvalidatingPermitProvider) Invalidate(ctx context.Context) error {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	p.startOnce.Do(func() { close(p.started) })
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return p.err
}

func (p *task5InvalidatingPermitProvider) ValidateBinding(
	context.Context,
	AcquisitionPermitBinding,
) error {
	return nil
}

func (p *task5InvalidatingPermitProvider) Invalidations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type task5ReconcileResult struct {
	receipt CycleReceipt
	err     error
}

type task5TransitionResult struct {
	policy AcquisitionPolicy
	err    error
}

type task5ControlledReconciler struct {
	started   chan struct{}
	release   <-chan struct{}
	receipt   CycleReceipt
	startOnce sync.Once
}

func (r *task5ControlledReconciler) Once(ctx context.Context) (CycleReceipt, error) {
	r.startOnce.Do(func() { close(r.started) })
	select {
	case <-r.release:
		return r.receipt, nil
	case <-ctx.Done():
		return CycleReceipt{}, context.Cause(ctx)
	}
}

type task5NotifyingPublisher struct {
	published chan health.Snapshot
}

func (p *task5NotifyingPublisher) Publish(
	ctx context.Context,
	snapshot health.Snapshot,
) error {
	select {
	case p.published <- snapshot:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

type task5CancelablePublisher struct {
	started  chan health.Snapshot
	canceled chan error
	release  <-chan struct{}
}

func (p *task5CancelablePublisher) Publish(
	ctx context.Context,
	snapshot health.Snapshot,
) error {
	select {
	case p.started <- snapshot:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	select {
	case <-ctx.Done():
		cause := context.Cause(ctx)
		p.canceled <- cause
		<-p.release
		return cause
	case <-p.release:
		return nil
	}
}

type task5UnjoinablePublisher struct {
	started chan health.Snapshot
	release <-chan struct{}
}

type task5PostInvalidationPermitProvider struct {
	mu                  sync.Mutex
	firstInvalidation   chan struct{}
	publisherDone       <-chan struct{}
	invalidations       int
	staleLeaseInstalled bool
}

func (p *task5PostInvalidationPermitProvider) Acquire(
	ctx context.Context,
	_ AcquisitionPermitRequest,
) (AcquisitionPermitGuard, error) {
	return canonicalPermitGuardStub{ctx: ctx}, nil
}

func (p *task5PostInvalidationPermitProvider) Invalidate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	p.invalidations++
	call := p.invalidations
	p.mu.Unlock()
	if call == 1 {
		close(p.firstInvalidation)
		return nil
	}
	select {
	case <-p.publisherDone:
		p.mu.Lock()
		p.staleLeaseInstalled = false
		p.mu.Unlock()
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (p *task5PostInvalidationPermitProvider) ValidateBinding(
	context.Context,
	AcquisitionPermitBinding,
) error {
	return nil
}

func (p *task5PostInvalidationPermitProvider) installStaleLease() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.staleLeaseInstalled = true
}

func (p *task5PostInvalidationPermitProvider) Snapshot() (int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.invalidations, p.staleLeaseInstalled
}

type task5PostInvalidationPublisher struct {
	started chan struct{}
	first   <-chan struct{}
	done    chan struct{}
	permits *task5PostInvalidationPermitProvider
}

func (p *task5PostInvalidationPublisher) Publish(
	ctx context.Context,
	_ health.Snapshot,
) error {
	close(p.started)
	<-p.first
	p.permits.installStaleLease()
	close(p.done)
	<-ctx.Done()
	return context.Cause(ctx)
}

func (p *task5UnjoinablePublisher) Publish(
	_ context.Context,
	snapshot health.Snapshot,
) error {
	p.started <- snapshot
	<-p.release
	return nil
}

func task5CanaryPolicy(current AcquisitionPolicy) AcquisitionPolicy {
	next := cloneAcquisitionPolicy(current)
	next.Mode = AcquisitionCanaryOnly
	next.MaxCapacity = 1
	next.EligibleScaleSets = []string{"portable-ghar"}
	return next
}

func TestServiceTransitionInvalidatesPermitAuthorityAfterGateClosesBeforePersist(
	t *testing.T,
) {
	fixture := newTask8TransitionFixture(t, time.Second)
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	permits := newTask5InvalidatingPermitProvider(release, nil)
	fixture.service.permits = permits
	baselineTransitions := len(fixture.transitions.Transitions())
	current := fixture.service.Policy()

	result := make(chan task5TransitionResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		policy, err := fixture.service.Transition(
			ctx,
			current.Epoch,
			task5CanaryPolicy(current),
		)
		result <- task5TransitionResult{policy: policy, err: err}
	}()

	select {
	case <-permits.started:
	case got := <-result:
		t.Fatalf(
			"Transition completed before permit invalidation: policy=%+v err=%v",
			got.policy,
			got.err,
		)
	}

	operationCtx, operationCancel := context.WithTimeout(context.Background(), time.Second)
	defer operationCancel()
	operation, err := fixture.service.barrierSnapshot().beginOperation(
		operationCtx,
		"poll",
		"repo-a",
		"portable-ghar",
	)
	if operation != nil {
		_ = operation.Close()
	}
	if !errors.Is(err, ErrAcquisitionTransitioning) {
		t.Fatalf("beginOperation during invalidation = %v, want closed gate", err)
	}
	if got := len(fixture.transitions.Transitions()); got != baselineTransitions {
		t.Fatalf(
			"persisted transitions during invalidation = %d, want %d",
			got,
			baselineTransitions,
		)
	}
	if got := fixture.service.Policy(); !equalAcquisitionPolicy(got, current) {
		t.Fatalf("policy published before invalidation: got %+v want %+v", got, current)
	}

	close(release)
	released = true
	got := <-result
	if got.err != nil {
		t.Fatalf("Transition after invalidation: %v", got.err)
	}
	if got.policy.Epoch != current.Epoch+1 || got.policy.Mode != AcquisitionCanaryOnly {
		t.Fatalf("Transition policy = %+v, want canary epoch %d", got.policy, current.Epoch+1)
	}
	if calls := permits.Invalidations(); calls != 2 {
		t.Fatalf("permit invalidations = %d, want 2", calls)
	}
}

func TestServiceTransitionInvalidationFailureLeavesGateClosedWithoutPersist(
	t *testing.T,
) {
	fixture := newTask8TransitionFixture(t, time.Second)
	injected := errors.New("injected permit invalidation failure")
	permits := newTask5InvalidatingPermitProvider(nil, injected)
	fixture.service.permits = permits
	baselineTransitions := len(fixture.transitions.Transitions())
	current := fixture.service.Policy()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := fixture.service.Transition(
		ctx,
		current.Epoch,
		task5CanaryPolicy(current),
	)
	if !errors.Is(err, ErrAcquisitionTransition) || !errors.Is(err, injected) {
		t.Fatalf("Transition = (%+v, %v), want invalidation transition failure", got, err)
	}
	if fixture.service.Ready() {
		t.Fatal("service remained ready after authority invalidation failure")
	}
	if policy := fixture.service.Policy(); !equalAcquisitionPolicy(policy, current) {
		t.Fatalf("invalidation failure changed policy: got %+v want %+v", policy, current)
	}
	if transitions := len(fixture.transitions.Transitions()); transitions != baselineTransitions {
		t.Fatalf(
			"invalidation failure persisted %d transitions, want %d",
			transitions,
			baselineTransitions,
		)
	}
	operationCtx, operationCancel := context.WithTimeout(context.Background(), time.Second)
	defer operationCancel()
	operation, operationErr := fixture.service.barrierSnapshot().beginOperation(
		operationCtx,
		"poll",
		"repo-a",
		"portable-ghar",
	)
	if operation != nil {
		_ = operation.Close()
	}
	if !errors.Is(operationErr, ErrAcquisitionTransitioning) {
		t.Fatalf("beginOperation after invalidation failure = %v, want closed gate", operationErr)
	}
}

func TestServiceReconcileOncePublishesValidatedHeartbeatOnlyAfterCompleteReceipt(
	t *testing.T,
) {
	fixture := newReconcileServiceFixture(t)
	release := make(chan struct{})
	reconciler := &task5ControlledReconciler{
		started: make(chan struct{}),
		release: release,
		receipt: CycleReceipt{
			CycleID:         "cycle-task5-complete",
			CompletedAt:     fixture.now.Add(-time.Second),
			AssignmentCount: 2,
			OldestAge:       3 * time.Minute,
		},
	}
	publisher := &task5NotifyingPublisher{published: make(chan health.Snapshot, 1)}
	fixture.service.reconciler = reconciler
	fixture.service.health = publisher
	result := make(chan task5ReconcileResult, 1)
	go func() {
		receipt, err := fixture.service.ReconcileOnce(context.Background())
		result <- task5ReconcileResult{receipt: receipt, err: err}
	}()

	<-reconciler.started
	select {
	case snapshot := <-publisher.published:
		t.Fatalf("published heartbeat before complete receipt: %+v", snapshot)
	default:
	}
	close(release)
	snapshot := <-publisher.published
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("published invalid heartbeat: %v", err)
	}
	got := <-result
	if got.err != nil || got.receipt != reconciler.receipt {
		t.Fatalf(
			"ReconcileOnce = (%+v, %v), want complete receipt %+v",
			got.receipt,
			got.err,
			reconciler.receipt,
		)
	}
}

func TestServiceReconcileHeartbeatPublicationIsCanceledAndJoinedByTransition(
	t *testing.T,
) {
	fixture := newReconcileServiceFixture(t)
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	publisher := &task5CancelablePublisher{
		started:  make(chan health.Snapshot),
		canceled: make(chan error, 1),
		release:  release,
	}
	permits := newTask5InvalidatingPermitProvider(nil, nil)
	fixture.service.health = publisher
	fixture.service.permits = permits
	reconcileResult := make(chan task5ReconcileResult, 1)
	go func() {
		receipt, err := fixture.service.ReconcileOnce(context.Background())
		reconcileResult <- task5ReconcileResult{receipt: receipt, err: err}
	}()

	snapshot := <-publisher.started
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("heartbeat presented to publisher was invalid: %v", err)
	}
	current := fixture.service.Policy()
	transitionResult := make(chan task5TransitionResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		policy, err := fixture.service.Transition(
			ctx,
			current.Epoch,
			task5CanaryPolicy(current),
		)
		transitionResult <- task5TransitionResult{policy: policy, err: err}
	}()

	select {
	case cause := <-publisher.canceled:
		if !errors.Is(cause, ErrAcquisitionEpochSuperseded) {
			t.Fatalf("heartbeat cancellation cause = %v, want epoch superseded", cause)
		}
	case got := <-transitionResult:
		t.Fatalf(
			"Transition completed while heartbeat publication was live: policy=%+v err=%v",
			got.policy,
			got.err,
		)
	}

	close(release)
	released = true
	reconciled := <-reconcileResult
	if !errors.Is(reconciled.err, ErrReconciliation) ||
		reconciled.receipt != (CycleReceipt{}) {
		t.Fatalf(
			"canceled ReconcileOnce = (%+v, %v), want zero ErrReconciliation",
			reconciled.receipt,
			reconciled.err,
		)
	}
	transitioned := <-transitionResult
	if transitioned.err != nil || transitioned.policy.Epoch != current.Epoch+1 {
		t.Fatalf(
			"joined Transition = (%+v, %v), want next epoch",
			transitioned.policy,
			transitioned.err,
		)
	}
}

func TestServiceTransitionClearsLeaseInstalledAfterFirstInvalidation(t *testing.T) {
	fixture := newReconcileServiceFixture(t)
	first := make(chan struct{})
	done := make(chan struct{})
	permits := &task5PostInvalidationPermitProvider{
		firstInvalidation: first,
		publisherDone:     done,
	}
	publisher := &task5PostInvalidationPublisher{
		started: make(chan struct{}),
		first:   first,
		done:    done,
		permits: permits,
	}
	fixture.service.permits = permits
	fixture.service.health = publisher
	reconcileResult := make(chan task5ReconcileResult, 1)
	go func() {
		receipt, err := fixture.service.ReconcileOnce(context.Background())
		reconcileResult <- task5ReconcileResult{receipt: receipt, err: err}
	}()
	<-publisher.started

	current := fixture.service.Policy()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	transitioned, err := fixture.service.Transition(
		ctx,
		current.Epoch,
		task5CanaryPolicy(current),
	)
	if err != nil || transitioned.Epoch != current.Epoch+1 {
		t.Fatalf("Transition = (%+v, %v), want next epoch", transitioned, err)
	}
	invalidations, staleInstalled := permits.Snapshot()
	if invalidations != 2 || staleInstalled {
		t.Fatalf(
			"post-join authority = invalidations:%d stale:%v, want 2/false",
			invalidations,
			staleInstalled,
		)
	}
	reconciled := <-reconcileResult
	if !errors.Is(reconciled.err, ErrReconciliation) ||
		reconciled.receipt != (CycleReceipt{}) {
		t.Fatalf(
			"superseded ReconcileOnce = (%+v, %v), want zero ErrReconciliation",
			reconciled.receipt,
			reconciled.err,
		)
	}
}

func TestServiceReconcileUnjoinableHeartbeatUsesTransitionFailurePath(
	t *testing.T,
) {
	fixture := newReconcileServiceFixture(t)
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	publisher := &task5UnjoinablePublisher{
		started: make(chan health.Snapshot),
		release: release,
	}
	fixture.service.health = publisher
	fixture.service.permits = newTask5InvalidatingPermitProvider(nil, nil)
	fixture.service.transitionJoinTimeout = time.Nanosecond
	reconcileResult := make(chan task5ReconcileResult, 1)
	go func() {
		receipt, err := fixture.service.ReconcileOnce(context.Background())
		reconcileResult <- task5ReconcileResult{receipt: receipt, err: err}
	}()

	snapshot := <-publisher.started
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("heartbeat presented to publisher was invalid: %v", err)
	}
	current := fixture.service.Policy()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	policy, err := fixture.service.Transition(
		ctx,
		current.Epoch,
		task5CanaryPolicy(current),
	)
	if !errors.Is(err, ErrAcquisitionTransition) {
		t.Fatalf("unjoinable Transition = (%+v, %v), want transition failure", policy, err)
	}
	if fixture.service.Ready() ||
		fixture.service.Policy().Mode != AcquisitionFatal ||
		fixture.terminator.Count() != 1 ||
		fixture.terminator.LastReason() != ReasonAcquisitionJoin {
		t.Fatalf(
			"unjoinable state = ready:%v policy:%+v terminator:(%d,%d)",
			fixture.service.Ready(),
			fixture.service.Policy(),
			fixture.terminator.Count(),
			fixture.terminator.LastReason(),
		)
	}

	close(release)
	released = true
	reconciled := <-reconcileResult
	if !errors.Is(reconciled.err, ErrReconciliation) ||
		reconciled.receipt != (CycleReceipt{}) {
		t.Fatalf(
			"unjoinable ReconcileOnce = (%+v, %v), want zero ErrReconciliation",
			reconciled.receipt,
			reconciled.err,
		)
	}
}

func TestServiceHeartbeatFailureReducesAcquisitionToZero(t *testing.T) {
	fixture := newReconcileServiceFixture(t)
	fixture.publisher.err = errors.New("injected heartbeat authority failure")

	receipt, err := fixture.service.ReconcileOnce(context.Background())
	if receipt != (CycleReceipt{}) || !errors.Is(err, ErrReconciliation) {
		t.Fatalf("ReconcileOnce = (%+v, %v), want zero ErrReconciliation", receipt, err)
	}
	policy := fixture.service.Policy()
	if policy.Mode != AcquisitionDisabled || policy.MaxCapacity != 0 {
		t.Fatalf("heartbeat failure policy = %+v, want disabled zero", policy)
	}
}

func TestServiceHeartbeatNormalizationDoesNotHideNegativeAge(t *testing.T) {
	fixture := newReconcileServiceFixture(t)
	fixture.state.mu.Lock()
	fixture.state.summary.OldestLiveAssignmentAge = -time.Nanosecond
	fixture.state.mu.Unlock()

	receipt, err := fixture.service.ReconcileOnce(context.Background())
	if receipt != (CycleReceipt{}) || !errors.Is(err, ErrReconciliation) {
		t.Fatalf("ReconcileOnce = (%+v, %v), want zero ErrReconciliation", receipt, err)
	}
	if snapshots := fixture.publisher.Snapshots(); len(snapshots) != 0 {
		t.Fatalf("negative age published heartbeat: %+v", snapshots)
	}
}
