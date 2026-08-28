package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/redaction"
	"github.com/sumitake/portable-ghar/internal/state"
)

type fakeLifecycleState struct {
	mu               sync.Mutex
	record           state.RecoverableAssignment
	extra            []state.RecoverableAssignment
	effects          map[string]state.EffectRecord
	resolvedEvidence [32]byte
	resolvedOutcome  controller.PostReleaseOutcome
	resolveCalls     int
	acquisition      map[controller.AssignmentKey]state.AcquisitionAssignmentRecord
}

func (f *fakeLifecycleState) recordLocked(
	key controller.AssignmentKey,
) (*state.RecoverableAssignment, bool) {
	if f.record.Key == key {
		return &f.record, true
	}
	for index := range f.extra {
		if f.extra[index].Key == key {
			return &f.extra[index], true
		}
	}
	return nil, false
}

func (f *fakeLifecycleState) ListRecoverable(context.Context) ([]state.RecoverableAssignment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	records := make([]state.RecoverableAssignment, 0, 1+len(f.extra))
	if f.record.State != controller.StateDestroyed {
		records = append(records, f.record)
	}
	for _, record := range f.extra {
		if record.State != controller.StateDestroyed {
			records = append(records, record)
		}
	}
	return records, nil
}

func (f *fakeLifecycleState) AcquisitionAssignment(
	_ context.Context,
	key controller.AssignmentKey,
) (state.AcquisitionAssignmentRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.recordLocked(key); !ok {
		return state.AcquisitionAssignmentRecord{}, ErrInvalidState
	}
	if record, ok := f.acquisition[key]; ok {
		return record, nil
	}
	return state.AcquisitionAssignmentRecord{
		Key:     key,
		Outcome: state.AcquisitionOutcomeAcquired,
	}, nil
}

func (f *fakeLifecycleState) LookupAssignmentEffect(
	_ context.Context,
	_ controller.AssignmentKey,
	kind string,
) (state.EffectRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.effects[kind]
	if !ok {
		return state.EffectRecord{State: state.EffectAbsent}, nil
	}
	return record, nil
}

func (f *fakeLifecycleState) MarkAmbiguous(
	_ context.Context,
	key controller.AssignmentKey,
	reason string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.recordLocked(key)
	if !ok {
		return ErrInvalidState
	}
	record.Ambiguous = true
	record.AmbiguousReason = reason
	return nil
}

func (f *fakeLifecycleState) ApplyRunnerObservation(
	_ context.Context,
	key controller.AssignmentKey,
	observation state.RunnerObservation,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.recordLocked(key)
	if !ok {
		return ErrInvalidState
	}
	record.Slot.UpstreamRunnerID = observation.UpstreamRunnerID
	record.Slot.BoundRequestID = observation.BoundRequestID
	record.Ambiguous = false
	record.AmbiguousReason = ""
	record.Released = true
	record.State = controller.StateJobRunning
	if observation.Finished {
		record.State = controller.StateJobFinished
	}
	return nil
}

func (f *fakeLifecycleState) AdvancePreReleaseDestroyed(
	_ context.Context,
	key controller.AssignmentKey,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if effect := f.effects[state.LifecycleEffectListenerRelease]; effect.State != state.EffectAbsent && effect.State != 0 {
		return state.ErrIdentityConflict
	}
	record, ok := f.recordLocked(key)
	if !ok {
		return ErrInvalidState
	}
	record.State = controller.StateDestroyed
	return nil
}

func (f *fakeLifecycleState) Advance(
	_ context.Context,
	key controller.AssignmentKey,
	next controller.State,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.recordLocked(key)
	if !ok {
		return ErrInvalidState
	}
	record.State = next
	return nil
}

func (f *fakeLifecycleState) BindTerminalMessage(
	_ context.Context,
	key controller.AssignmentKey,
	messageID int,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.recordLocked(key)
	if !ok || messageID <= 0 ||
		(record.State != controller.StateJobFinished &&
			record.State != controller.StateDestroyed) {
		return ErrInvalidState
	}
	return nil
}

func (f *fakeLifecycleState) ResolvePostRelease(
	_ context.Context,
	key controller.AssignmentKey,
	outcome controller.PostReleaseOutcome,
	evidence [32]byte,
	_ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.recordLocked(key)
	if !ok {
		return ErrInvalidState
	}
	if f.resolveCalls != 0 {
		if f.resolvedOutcome == outcome {
			if f.resolvedEvidence != evidence {
				return state.ErrIdentityConflict
			}
			return nil
		}
		if !fakePostReleaseProgresses(record.State, outcome) {
			return state.ErrIdentityConflict
		}
	}
	switch outcome {
	case controller.PostReleaseListenerReleased:
		record.State = controller.StateListenerReleased
	case controller.PostReleaseJobRunning:
		record.State = controller.StateJobRunning
	case controller.PostReleaseJobFinished:
		record.State = controller.StateJobFinished
	case controller.PostReleaseDestroyed:
		record.State = controller.StateDestroyed
	}
	record.Ambiguous = false
	record.AmbiguousReason = ""
	record.Released = true
	f.resolvedEvidence = evidence
	f.resolvedOutcome = outcome
	f.resolveCalls++
	return nil
}

func fakePostReleaseProgresses(
	current controller.State,
	outcome controller.PostReleaseOutcome,
) bool {
	switch current {
	case controller.StateListenerReleased:
		return outcome == controller.PostReleaseJobRunning ||
			outcome == controller.PostReleaseJobFinished ||
			outcome == controller.PostReleaseDestroyed
	case controller.StateJobRunning:
		return outcome == controller.PostReleaseJobFinished ||
			outcome == controller.PostReleaseDestroyed
	default:
		return false
	}
}

type fakeSessionProvider struct {
	session githubscale.Session
	calls   int
	err     error
}

type fakeJITAuthorizer struct {
	mu     sync.Mutex
	calls  []controller.JITAuthorizationRequest
	permit *fakeLifecyclePermit
	err    error
}

func (f *fakeJITAuthorizer) GenerateJITAuthorized(
	ctx context.Context,
	request controller.JITAuthorizationRequest,
) (controller.JITAuthorizationResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, request)
	err := f.err
	permit := f.permit
	if permit == nil {
		permit = newFakeLifecyclePermit(request.Assignment)
		f.permit = permit
	}
	f.mu.Unlock()
	if err != nil {
		return controller.JITAuthorizationResult{}, err
	}
	config, err := request.Session.GenerateJIT(ctx, request.Request)
	return controller.JITAuthorizationResult{
		Config: config,
		Permit: permit,
	}, err
}

func (f *fakeJITAuthorizer) Calls() []controller.JITAuthorizationRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]controller.JITAuthorizationRequest(nil), f.calls...)
}

type fakeLifecyclePermit struct {
	mu              sync.Mutex
	ctx             context.Context
	binding         controller.AcquisitionPermitBinding
	validateErr     error
	revalidateErr   error
	admitErr        error
	closeErr        error
	validateCalls   int
	revalidateCalls int
	admitCalls      int
	closeCalls      int
}

func newFakeLifecyclePermit(
	assignment controller.Assignment,
) *fakeLifecyclePermit {
	return &fakeLifecyclePermit{
		ctx: context.Background(),
		binding: controller.AcquisitionPermitBinding{
			AuthorityRevision:        1,
			AuthorityKey:             "authority-key-a",
			FenceGeneration:          2,
			ServerEpoch:              3,
			SessionID:                "session-a",
			LeaseGeneration:          4,
			OperationID:              "jit-operation-a",
			RepositoryAlias:          assignment.Key.RepositoryAlias,
			ScaleSetName:             assignment.Offer.RequestLabels[0],
			OperationKind:            "jit",
			PolicyDigest:             "policy-digest-a",
			PolicyEpoch:              5,
			PolicyMode:               controller.AcquisitionEnabled,
			MaxCapacity:              1,
			RepositoryPolicyRevision: 6,
			OriginalLocalDeadline:    time.Unix(2_000_000_000, 123).UTC(),
		},
	}
}

func (p *fakeLifecyclePermit) Context() context.Context {
	if p == nil || p.ctx == nil {
		return context.Background()
	}
	return p.ctx
}

func (p *fakeLifecyclePermit) Binding() controller.AcquisitionPermitBinding {
	if p == nil {
		return controller.AcquisitionPermitBinding{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.binding
}

func (p *fakeLifecyclePermit) ValidateBinding(
	_ context.Context,
	binding controller.AcquisitionPermitBinding,
) error {
	if p == nil {
		return errors.New("missing permit")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.validateCalls++
	if binding != p.binding {
		return errors.New("binding mismatch")
	}
	return p.validateErr
}

func (p *fakeLifecyclePermit) Revalidate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revalidateCalls++
	return p.revalidateErr
}

func (p *fakeLifecyclePermit) Admit() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.admitCalls++
	return p.admitErr
}

func (p *fakeLifecyclePermit) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeCalls++
	return p.closeErr
}

func (p *fakeLifecyclePermit) counts() (int, int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validateCalls, p.revalidateCalls, p.admitCalls, p.closeCalls
}

func (f *fakeSessionProvider) Session(
	context.Context,
	string,
) (githubscale.Session, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeLifecycleSession struct {
	mu            sync.Mutex
	runners       map[string]githubscale.RunnerRef
	nextRunnerID  int64
	generateCalls int
	removeCalls   []int64
	lastSecret    *redaction.Secret
	generatedName string
	removeErr     error
	phantomOnMiss githubscale.RunnerRef
}

func (f *fakeLifecycleSession) Compatibility() githubscale.ScaleSetCompatibilityReport {
	return githubscale.ScaleSetCompatibilityReport{}
}
func (f *fakeLifecycleSession) Poll(context.Context, int, int) (githubscale.Batch, error) {
	return githubscale.Batch{}, errors.New("unexpected Poll")
}
func (f *fakeLifecycleSession) Ack(context.Context, int) error {
	return errors.New("unexpected Ack")
}
func (f *fakeLifecycleSession) Acquire(context.Context, []int64) ([]int64, error) {
	return nil, errors.New("unexpected Acquire")
}
func (f *fakeLifecycleSession) GenerateJIT(
	_ context.Context,
	request githubscale.JITRequest,
) (githubscale.JITConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generateCalls++
	f.nextRunnerID++
	name := request.RunnerName
	if f.generatedName != "" {
		name = f.generatedName
	}
	runner := githubscale.RunnerRef{ID: f.nextRunnerID, Name: name}
	f.runners[request.RunnerName] = runner
	f.lastSecret = redaction.SecretFromBytes([]byte("one-job-jit"))
	return githubscale.JITConfig{Runner: runner, Encoded: f.lastSecret}, nil
}
func (f *fakeLifecycleSession) GetRunnerByName(
	_ context.Context,
	name string,
) (githubscale.RunnerRef, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	runner, ok := f.runners[name]
	if !ok && f.phantomOnMiss != (githubscale.RunnerRef{}) {
		return f.phantomOnMiss, false, nil
	}
	return runner, ok, nil
}
func (f *fakeLifecycleSession) GetRunner(
	_ context.Context,
	id int64,
) (githubscale.RunnerRef, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, runner := range f.runners {
		if runner.ID == id {
			return runner, true, nil
		}
	}
	return githubscale.RunnerRef{}, false, nil
}
func (f *fakeLifecycleSession) RemoveRunner(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls = append(f.removeCalls, id)
	if f.removeErr != nil {
		return f.removeErr
	}
	for name, runner := range f.runners {
		if runner.ID == id {
			delete(f.runners, name)
		}
	}
	return nil
}
func (f *fakeLifecycleSession) Close(context.Context) error { return nil }

type fakeSetupBuilder struct {
	prepared networkjail.PreparedSetupRequest
	recovery hostruntime.RecoverySpec
	calls    int
}

func (f *fakeSetupBuilder) Build(
	_ context.Context,
	_ controller.Assignment,
) (networkjail.PreparedSetupRequest, hostruntime.RecoverySpec, error) {
	f.calls++
	return f.prepared, f.recovery, nil
}

type fakeJailOrchestrator struct {
	state         *fakeLifecycleState
	prepareCalls  int
	releaseCalls  int
	destroyHeld   int
	destroyLive   int
	releaseErr    error
	releaseStart  chan struct{}
	releaseGo     chan struct{}
	releasePermit controller.AcquisitionPermitGuard
}

func (f *fakeJailOrchestrator) Prepare(
	_ context.Context,
	_ networkjail.PreparedSetupRequest,
) (networkjail.HeldJail, error) {
	f.prepareCalls++
	f.state.mu.Lock()
	f.state.record.State = controller.StateReleaseArmed
	f.state.record.Slot.AdapterContainerID = "adapter-id"
	f.state.record.Slot.BrokerContainerID = "broker-id"
	f.state.record.Slot.RunnerContainerID = "runner-id"
	f.state.mu.Unlock()
	return networkjail.HeldJail{}, nil
}

func (f *fakeJailOrchestrator) Release(
	ctx context.Context,
	_ networkjail.HeldJail,
	_ *redaction.Secret,
	permit controller.AcquisitionPermitGuard,
) (networkjail.LiveJail, error) {
	f.releaseCalls++
	f.releasePermit = permit
	if permit == nil || permit.Context() != ctx {
		return networkjail.LiveJail{}, networkjail.ErrSetupInput
	}
	if f.releaseStart != nil {
		select {
		case f.releaseStart <- struct{}{}:
		default:
		}
	}
	if f.releaseGo != nil {
		<-f.releaseGo
	}
	if f.releaseErr != nil {
		if errors.Is(f.releaseErr, networkjail.ErrListenerAmbiguous) {
			f.state.mu.Lock()
			f.state.effects[state.LifecycleEffectListenerRelease] =
				state.EffectRecord{State: state.EffectPending}
			f.state.mu.Unlock()
		}
		return networkjail.LiveJail{}, f.releaseErr
	}
	bindingDigest, err := controller.AcquisitionPermitBindingDigest(permit.Binding())
	if err != nil {
		return networkjail.LiveJail{}, networkjail.ErrSetupInput
	}
	if err := permit.Revalidate(); err != nil {
		return networkjail.LiveJail{}, networkjail.ErrListenerAmbiguous
	}
	if err := permit.Admit(); err != nil {
		return networkjail.LiveJail{}, networkjail.ErrListenerAmbiguous
	}
	f.state.mu.Lock()
	f.state.record.State = controller.StateListenerReleased
	f.state.record.Released = true
	f.state.effects[state.LifecycleEffectListenerRelease] =
		state.EffectRecord{
			State:          state.EffectCompleted,
			ResultIdentity: fmt.Sprintf("%x", bindingDigest),
		}
	f.state.mu.Unlock()
	return networkjail.LiveJail{}, nil
}

func (f *fakeJailOrchestrator) DestroyHeld(context.Context, networkjail.HeldJail) error {
	f.destroyHeld++
	return nil
}
func (f *fakeJailOrchestrator) DestroyLive(context.Context, networkjail.LiveJail) error {
	f.destroyLive++
	return nil
}

type fakeManagedRecovery struct {
	inspectCalls int
	removeCalls  int
}

func (f *fakeManagedRecovery) InspectManaged(
	context.Context,
	hostruntime.RecoverySpec,
) (hostruntime.ManagedSnapshot, error) {
	f.inspectCalls++
	return hostruntime.ManagedSnapshot{}, nil
}
func (f *fakeManagedRecovery) RemoveManaged(
	context.Context,
	hostruntime.ManagedSnapshot,
) error {
	f.removeCalls++
	return nil
}

func TestServicePrepareStopsBeforeSessionAndReturnsPersistedSlot(t *testing.T) {
	fixture := newLifecycleFixture(t)
	slot, err := fixture.service.Prepare(context.Background(), fixture.assignment)
	if err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if fixture.sessions.calls != 0 || fixture.session.generateCalls != 0 {
		t.Fatalf("session calls during Prepare = provider=%d generate=%d, want zero",
			fixture.sessions.calls, fixture.session.generateCalls)
	}
	if fixture.jails.prepareCalls != 1 || fixture.jails.releaseCalls != 0 {
		t.Fatalf("jail calls = prepare=%d release=%d, want 1/0",
			fixture.jails.prepareCalls, fixture.jails.releaseCalls)
	}
	if slot.RunnerContainerID != "runner-id" ||
		slot.AdapterContainerID != "adapter-id" ||
		slot.BrokerContainerID != "broker-id" {
		t.Fatalf("Prepare slot = %+v, want persisted runtime identities", slot)
	}
}

func TestServicePrepareRejectsNonDurableOfferProjection(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.assignment.Offer.OwnerName = "caller-modified-owner"

	if _, err := fixture.service.Prepare(
		context.Background(),
		fixture.assignment,
	); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Prepare(modified offer) = %v, want ErrInvalidState", err)
	}
	if fixture.builderCalls() != 0 || fixture.jails.prepareCalls != 0 {
		t.Fatalf(
			"modified offer reached effects: builder=%d jail=%d",
			fixture.builderCalls(),
			fixture.jails.prepareCalls,
		)
	}
}

func TestServicePrepareRejectsRecoveryPathDrift(t *testing.T) {
	fixture := newLifecycleFixture(t)
	builder := fixture.service.(*service).builder.(*fakeSetupBuilder)
	builder.prepared.Broker.RelayParent = "/synthetic/broker/relay"
	builder.prepared.Broker.AuthorityParent = "/synthetic/broker/authority"

	if _, err := fixture.service.Prepare(
		context.Background(),
		fixture.assignment,
	); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("Prepare(recovery path drift) = %v, want ErrLifecycle", err)
	}
	if fixture.jails.prepareCalls != 0 {
		t.Fatalf("recovery path drift reached jail Prepare: %d", fixture.jails.prepareCalls)
	}
}

func TestServiceReleaseRemovesStaleRegistrationBeforeOneJIT(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	stale := githubscale.RunnerRef{ID: 71, Name: fixture.assignment.Slot.OpaqueName}
	fixture.session.runners[stale.Name] = stale

	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	if fixture.session.generateCalls != 1 ||
		len(fixture.session.removeCalls) != 1 ||
		fixture.session.removeCalls[0] != stale.ID ||
		fixture.jails.releaseCalls != 1 {
		t.Fatalf("release calls = generate=%d removed=%v jail=%d",
			fixture.session.generateCalls, fixture.session.removeCalls, fixture.jails.releaseCalls)
	}
	if fixture.jails.releasePermit != fixture.jit.permit {
		t.Fatal("listener release did not receive the JIT operation permit")
	}
	validateCalls, revalidateCalls, admitCalls, closeCalls := fixture.jit.permit.counts()
	if validateCalls != 0 || revalidateCalls != 1 || admitCalls != 1 || closeCalls != 1 {
		t.Fatalf(
			"permit calls after release = validate %d revalidate %d admit %d close %d, want 0/1/1/1",
			validateCalls,
			revalidateCalls,
			admitCalls,
			closeCalls,
		)
	}
	jitCalls := fixture.jit.Calls()
	if len(jitCalls) != 1 ||
		jitCalls[0].Assignment.Key != fixture.assignment.Key ||
		jitCalls[0].ScaleSetName != "portable-ghar" ||
		jitCalls[0].Session != fixture.session ||
		jitCalls[0].RunnerName != fixture.assignment.Slot.OpaqueName ||
		jitCalls[0].Request.RunnerName != fixture.assignment.Slot.OpaqueName ||
		jitCalls[0].Request.WorkFolder != runnerWorkFolder {
		t.Fatalf("JIT authorization binding = %+v", jitCalls)
	}
	if err := fixture.session.lastSecret.Use(func(io.Reader) error { return nil }); !errors.Is(err, redaction.ErrSecretScopeClosed) {
		t.Fatalf("JIT after Release = %v, want destroyed", err)
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err == nil {
		t.Fatal("second Release() = nil, want duplicate release rejection")
	}
	if fixture.session.generateCalls != 1 || fixture.jails.releaseCalls != 1 {
		t.Fatalf("duplicate Release repeated effects: generate=%d release=%d",
			fixture.session.generateCalls, fixture.jails.releaseCalls)
	}
}

func TestServiceReleasePermitCloseFailureIsAmbiguousAndUncached(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.jit.permit.closeErr = errors.New("injected close failure")
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}

	err := fixture.service.Release(context.Background(), fixture.assignment.Key)
	if !errors.Is(err, ErrReleaseAmbiguous) ||
		!errors.Is(err, controller.ErrAcquisitionGuardClose) {
		t.Fatalf("Release(close failure) = %v, want release and guard-close ambiguity", err)
	}
	if !fixture.state.record.Ambiguous ||
		fixture.state.record.AmbiguousReason != "acquisition-permit-close" {
		t.Fatalf("close failure ambiguity = %+v", fixture.state.record)
	}
	service := fixture.service.(*service)
	service.cacheMu.Lock()
	_, live := service.live[fixture.assignment.Key]
	service.cacheMu.Unlock()
	if live {
		t.Fatal("close failure left listener admitted in the live cache")
	}
	_, _, _, closeCalls := fixture.jit.permit.counts()
	if closeCalls != 1 {
		t.Fatalf("permit Close calls = %d, want exactly one", closeCalls)
	}
}

func TestServiceFirstRunnerObservationRequiresCurrentListenerBinding(t *testing.T) {
	tests := []struct {
		name  string
		event func(*testing.T, lifecycleFixture, githubscale.RunnerRef) githubscale.Event
	}{
		{
			name: "started",
			event: func(t *testing.T, fixture lifecycleFixture, runner githubscale.RunnerRef) githubscale.Event {
				t.Helper()
				event, err := githubscale.NewStartedEvent(githubscale.StartedEvent{
					JobRef: githubscale.JobRef{
						RunnerRequestID:  fixture.assignment.Key.RunnerRequestID,
						JobID:            fixture.assignment.Offer.JobID,
						RunnerAssignTime: time.Now().Add(-time.Second),
					},
					RunnerID:   runner.ID,
					RunnerName: runner.Name,
				})
				if err != nil {
					t.Fatalf("NewStartedEvent() = %v", err)
				}
				return event
			},
		},
		{
			name: "completed",
			event: func(t *testing.T, fixture lifecycleFixture, runner githubscale.RunnerRef) githubscale.Event {
				t.Helper()
				event, err := githubscale.NewCompletedEvent(githubscale.CompletedEvent{
					JobRef: githubscale.JobRef{
						RunnerRequestID: fixture.assignment.Key.RunnerRequestID,
						JobID:           fixture.assignment.Offer.JobID,
						FinishTime:      time.Now().Add(-time.Second),
					},
					Result:     "Succeeded",
					RunnerID:   runner.ID,
					RunnerName: runner.Name,
				})
				if err != nil {
					t.Fatalf("NewCompletedEvent() = %v", err)
				}
				return event
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name+" superseded", func(t *testing.T) {
			fixture := newLifecycleFixture(t)
			if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
				t.Fatalf("Prepare() = %v", err)
			}
			if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
				t.Fatalf("Release() = %v", err)
			}
			runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
			fixture.jit.permit.validateErr = errors.New("superseded binding")

			if err := fixture.service.Observe(
				context.Background(),
				test.event(t, fixture, runner),
			); err != nil {
				t.Fatalf("Observe(%s superseded) = %v", test.name, err)
			}
			if fixture.state.record.State != controller.StateDestroyed ||
				fixture.state.record.Slot.UpstreamRunnerID != 0 ||
				fixture.jails.destroyLive != 1 ||
				len(fixture.session.removeCalls) != 1 {
				t.Fatalf(
					"superseded %s = state %s slot %+v destroyLive %d removals %v",
					test.name,
					fixture.state.record.State,
					fixture.state.record.Slot,
					fixture.jails.destroyLive,
					fixture.session.removeCalls,
				)
			}
			validateCalls, _, _, _ := fixture.jit.permit.counts()
			if validateCalls != 1 {
				t.Fatalf("binding validations = %d, want one", validateCalls)
			}
		})

		t.Run(test.name+" after restart", func(t *testing.T) {
			fixture := newLifecycleFixture(t)
			if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
				t.Fatalf("Prepare() = %v", err)
			}
			if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
				t.Fatalf("Release() = %v", err)
			}
			runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
			fixture.service.(*service).dropCache(fixture.assignment.Key)

			if err := fixture.service.Observe(
				context.Background(),
				test.event(t, fixture, runner),
			); err != nil {
				t.Fatalf("Observe(%s after restart) = %v", test.name, err)
			}
			if fixture.state.record.State != controller.StateDestroyed ||
				fixture.state.record.Slot.UpstreamRunnerID != 0 ||
				fixture.jails.destroyLive != 0 ||
				fixture.recovery.removeCalls != 1 ||
				len(fixture.session.removeCalls) != 1 {
				t.Fatalf(
					"restart %s = state %s slot %+v destroyLive %d recovery %d removals %v",
					test.name,
					fixture.state.record.State,
					fixture.state.record.Slot,
					fixture.jails.destroyLive,
					fixture.recovery.removeCalls,
					fixture.session.removeCalls,
				)
			}
		})
	}
}

func TestServiceRunningJobDrainsAfterListenerBindingExpires(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
	started, err := githubscale.NewStartedEvent(githubscale.StartedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID:  fixture.assignment.Key.RunnerRequestID,
			JobID:            fixture.assignment.Offer.JobID,
			RunnerAssignTime: time.Now().Add(-time.Second),
		},
		RunnerID:   runner.ID,
		RunnerName: runner.Name,
	})
	if err != nil {
		t.Fatalf("NewStartedEvent() = %v", err)
	}
	if err := fixture.service.Observe(context.Background(), started); err != nil {
		t.Fatalf("Observe(started) = %v", err)
	}
	fixture.jit.permit.validateErr = errors.New("expired after admission")
	completed, err := githubscale.NewCompletedEvent(githubscale.CompletedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID: fixture.assignment.Key.RunnerRequestID,
			JobID:           fixture.assignment.Offer.JobID,
			FinishTime:      time.Now().Add(-time.Second),
		},
		Result:     "Succeeded",
		RunnerID:   runner.ID,
		RunnerName: runner.Name,
	})
	if err != nil {
		t.Fatalf("NewCompletedEvent() = %v", err)
	}
	if err := fixture.service.Observe(context.Background(), completed); err != nil {
		t.Fatalf("Observe(completed after expiry) = %v", err)
	}
	if fixture.state.record.State != controller.StateJobFinished {
		t.Fatalf("completed state = %s, want JOB_FINISHED", fixture.state.record.State)
	}
	validateCalls, _, _, _ := fixture.jit.permit.counts()
	if validateCalls != 1 {
		t.Fatalf("binding validations = %d, want only pre-running admission", validateCalls)
	}
}

func TestServiceReleasePersistsAmbiguityWhenJITMayHaveActed(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	fixture.jit.err = errors.Join(
		controller.ErrJITMayHaveActed,
		errors.New("post-boundary failure"),
	)

	err := fixture.service.Release(context.Background(), fixture.assignment.Key)
	if !errors.Is(err, ErrReleaseAmbiguous) ||
		!errors.Is(err, controller.ErrJITMayHaveActed) {
		t.Fatalf("Release() = %v, want JIT ambiguity", err)
	}
	if !fixture.state.record.Ambiguous ||
		fixture.state.record.AmbiguousReason != "jit-effect-ambiguous" {
		t.Fatalf("ambiguity = (%v,%q)",
			fixture.state.record.Ambiguous,
			fixture.state.record.AmbiguousReason,
		)
	}
	if fixture.session.generateCalls != 0 {
		t.Fatalf("fake authorizer unexpectedly delegated GenerateJIT: %d", fixture.session.generateCalls)
	}
}

func TestServiceRevokePreRunningDestroysHeldAndReleasedAssignments(t *testing.T) {
	t.Run("held pre-JIT", func(t *testing.T) {
		fixture := newLifecycleFixture(t)
		if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
			t.Fatalf("Prepare() = %v", err)
		}
		fixture.state.acquisition[fixture.assignment.Key] =
			state.AcquisitionAssignmentRecord{
				Key:          fixture.assignment.Key,
				Outcome:      state.AcquisitionOutcomeAcquired,
				RevokedEpoch: 19,
			}

		if err := fixture.service.RevokePreRunning(
			context.Background(),
			19,
			[]controller.AssignmentKey{fixture.assignment.Key},
		); err != nil {
			t.Fatalf("RevokePreRunning() = %v", err)
		}
		if fixture.state.record.State != controller.StateDestroyed ||
			fixture.jails.destroyHeld != 1 ||
			fixture.jit.Calls() != nil {
			t.Fatalf(
				"held revocation = state %s destroyHeld %d jit %d",
				fixture.state.record.State,
				fixture.jails.destroyHeld,
				len(fixture.jit.Calls()),
			)
		}
	})

	t.Run("released unbound listener", func(t *testing.T) {
		fixture := newLifecycleFixture(t)
		if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
			t.Fatalf("Prepare() = %v", err)
		}
		if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
			t.Fatalf("Release() = %v", err)
		}
		fixture.state.acquisition[fixture.assignment.Key] =
			state.AcquisitionAssignmentRecord{
				Key:          fixture.assignment.Key,
				Outcome:      state.AcquisitionOutcomeAcquired,
				RevokedEpoch: 20,
			}

		if err := fixture.service.RevokePreRunning(
			context.Background(),
			20,
			[]controller.AssignmentKey{fixture.assignment.Key},
		); err != nil {
			t.Fatalf("RevokePreRunning() = %v", err)
		}
		if fixture.state.record.State != controller.StateDestroyed ||
			fixture.jails.destroyLive != 1 ||
			len(fixture.session.removeCalls) != 1 {
			t.Fatalf(
				"released revocation = state %s destroyLive %d removals %v",
				fixture.state.record.State,
				fixture.jails.destroyLive,
				fixture.session.removeCalls,
			)
		}
	})
}

func TestServiceRevokePreRunningTerminalizesReceivedWithoutRuntime(
	t *testing.T,
) {
	for _, outcome := range []state.AcquisitionOutcome{
		state.AcquisitionOutcomeOffered,
		state.AcquisitionOutcomeRequested,
		state.AcquisitionOutcomeAcquired,
		state.AcquisitionOutcomeRejected,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			fixture := newLifecycleFixture(t)
			fixture.state.record.State = controller.StateReceived
			fixture.state.record.Slot = controller.RunnerSlot{}
			fixture.state.acquisition[fixture.assignment.Key] =
				state.AcquisitionAssignmentRecord{
					Key:          fixture.assignment.Key,
					Outcome:      outcome,
					RevokedEpoch: 23,
				}

			if err := fixture.service.RevokePreRunning(
				context.Background(),
				23,
				[]controller.AssignmentKey{fixture.assignment.Key},
			); err != nil {
				t.Fatalf("RevokePreRunning(%s) = %v", outcome, err)
			}
			if fixture.state.record.State != controller.StateDestroyed {
				t.Fatalf(
					"RevokePreRunning(%s) state = %s, want DESTROYED",
					outcome,
					fixture.state.record.State,
				)
			}
			if fixture.builderCalls() != 0 ||
				fixture.jails.destroyHeld != 0 ||
				fixture.jails.destroyLive != 0 {
				t.Fatalf(
					"RevokePreRunning(%s) built/cleaned nonexistent runtime: builder=%d held=%d live=%d",
					outcome,
					fixture.builderCalls(),
					fixture.jails.destroyHeld,
					fixture.jails.destroyLive,
				)
			}
		})
	}
}

func TestServiceRevokePreRunningRejectsNonAcquiredReservedAssignment(
	t *testing.T,
) {
	fixture := newLifecycleFixture(t)
	fixture.state.acquisition[fixture.assignment.Key] =
		state.AcquisitionAssignmentRecord{
			Key:          fixture.assignment.Key,
			Outcome:      state.AcquisitionOutcomeOffered,
			RevokedEpoch: 24,
		}

	if err := fixture.service.RevokePreRunning(
		context.Background(),
		24,
		[]controller.AssignmentKey{fixture.assignment.Key},
	); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("RevokePreRunning(non-acquired reserved) = %v, want ErrInvalidState", err)
	}
	if fixture.state.record.State == controller.StateDestroyed {
		t.Fatal("non-acquired reserved assignment was silently destroyed")
	}
}

func TestServiceOrdinaryRevocationPreservesRunningButExplicitCancelDestroys(
	t *testing.T,
) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(
		context.Background(),
		fixture.assignment,
	); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := fixture.service.Release(
		context.Background(),
		fixture.assignment.Key,
	); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
	started, err := githubscale.NewStartedEvent(githubscale.StartedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID:  fixture.assignment.Key.RunnerRequestID,
			JobID:            fixture.assignment.Offer.JobID,
			RunnerAssignTime: time.Now().Add(-time.Second),
		},
		RunnerID:   runner.ID,
		RunnerName: runner.Name,
	})
	if err != nil {
		t.Fatalf("NewStartedEvent() = %v", err)
	}
	if err := fixture.service.Observe(context.Background(), started); err != nil {
		t.Fatalf("Observe(started) = %v", err)
	}
	fixture.state.acquisition[fixture.assignment.Key] =
		state.AcquisitionAssignmentRecord{
			Key:          fixture.assignment.Key,
			Outcome:      state.AcquisitionOutcomeAcquired,
			RevokedEpoch: 29,
		}

	if err := fixture.service.RevokePreRunning(
		context.Background(),
		29,
		[]controller.AssignmentKey{fixture.assignment.Key},
	); err != nil {
		t.Fatalf("RevokePreRunning(running) = %v", err)
	}
	if fixture.state.record.State != controller.StateJobRunning ||
		fixture.jails.destroyLive != 0 ||
		len(fixture.session.removeCalls) != 0 {
		t.Fatalf(
			"ordinary revocation mutated running job: state=%s destroy=%d removals=%v",
			fixture.state.record.State,
			fixture.jails.destroyLive,
			fixture.session.removeCalls,
		)
	}

	if err := fixture.service.CancelRunning(context.Background()); err != nil {
		t.Fatalf("CancelRunning() = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed ||
		fixture.jails.destroyLive != 1 ||
		len(fixture.session.removeCalls) != 1 ||
		fixture.session.removeCalls[0] != runner.ID {
		t.Fatalf(
			"explicit cancel = state=%s destroy=%d removals=%v",
			fixture.state.record.State,
			fixture.jails.destroyLive,
			fixture.session.removeCalls,
		)
	}
	if _, found := fixture.session.runners[fixture.assignment.Slot.OpaqueName]; found {
		t.Fatal("explicit cancel left upstream runner registered")
	}
}

func TestServiceExplicitCancelPersistsAmbiguityOnUnprovenCleanup(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.State = controller.StateJobRunning
	fixture.state.record.Released = true
	fixture.state.record.Slot.RunnerContainerID = "runner-id"
	fixture.session.runners[fixture.assignment.Slot.OpaqueName] =
		githubscale.RunnerRef{
			ID:   991,
			Name: fixture.assignment.Slot.OpaqueName,
		}
	fixture.session.removeErr = errors.New("injected removal failure")

	if err := fixture.service.CancelRunning(
		context.Background(),
	); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("CancelRunning() = %v, want ErrLifecycle", err)
	}
	if fixture.state.record.State != controller.StateJobRunning ||
		!fixture.state.record.Ambiguous ||
		fixture.state.record.AmbiguousReason != "drain-cancel" {
		t.Fatalf("failed cancel state = %+v", fixture.state.record)
	}
}

func TestServiceStartedObservationCannotBindRevokedPreRunningListener(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
	fixture.state.acquisition[fixture.assignment.Key] =
		state.AcquisitionAssignmentRecord{
			Key:          fixture.assignment.Key,
			Outcome:      state.AcquisitionOutcomeAcquired,
			RevokedEpoch: 21,
		}
	event, err := githubscale.NewStartedEvent(githubscale.StartedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID:  944,
			JobID:            fixture.assignment.Offer.JobID,
			RunnerAssignTime: time.Now().Add(-time.Second),
		},
		RunnerID:   runner.ID,
		RunnerName: runner.Name,
	})
	if err != nil {
		t.Fatalf("NewStartedEvent() = %v", err)
	}

	if err := fixture.service.Observe(context.Background(), event); err != nil {
		t.Fatalf("Observe(revoked started) = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed ||
		fixture.state.record.Slot.UpstreamRunnerID != 0 ||
		fixture.jails.destroyLive != 1 ||
		len(fixture.session.removeCalls) != 1 {
		t.Fatalf(
			"revoked observation = state %s slot %+v destroyLive %d removals %v",
			fixture.state.record.State,
			fixture.state.record.Slot,
			fixture.jails.destroyLive,
			fixture.session.removeCalls,
		)
	}
}

func TestServiceReleaseInvalidJITWithUnprovenCleanupBecomesAmbiguous(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	fixture.session.generatedName = "wrong-runner-name"
	fixture.session.removeErr = errors.New("upstream remove unavailable")

	if err := fixture.service.Release(
		context.Background(),
		fixture.assignment.Key,
	); !errors.Is(err, ErrReleaseAmbiguous) {
		t.Fatalf("Release(invalid JIT, cleanup uncertain) = %v, want ErrReleaseAmbiguous", err)
	}
	if !fixture.state.record.Ambiguous ||
		fixture.state.record.AmbiguousReason != "upstream-cleanup-uncertain" {
		t.Fatalf(
			"invalid JIT cleanup ambiguity = (%v,%q), want persisted",
			fixture.state.record.Ambiguous,
			fixture.state.record.AmbiguousReason,
		)
	}
	if err := fixture.service.Release(
		context.Background(),
		fixture.assignment.Key,
	); !errors.Is(err, ErrReleaseAmbiguous) {
		t.Fatalf("Release(ambiguous replay) = %v, want ErrReleaseAmbiguous", err)
	}
	if fixture.session.generateCalls != 1 {
		t.Fatalf("ambiguous invalid-JIT replay regenerated JIT %d times", fixture.session.generateCalls)
	}
}

func TestRemoveStaleRunnerRejectsNonzeroNotFoundResult(t *testing.T) {
	session := &fakeLifecycleSession{
		runners:       make(map[string]githubscale.RunnerRef),
		phantomOnMiss: githubscale.RunnerRef{ID: 77, Name: "runner-a"},
	}
	if err := removeStaleRunner(
		context.Background(),
		session,
		"runner-a",
	); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("removeStaleRunner(nonzero not-found result) = %v, want ErrInvalidState", err)
	}
	if len(session.removeCalls) != 0 {
		t.Fatalf("nonzero not-found result triggered removal: %v", session.removeCalls)
	}
}

func TestServiceDestroyRejectsNonzeroNotFoundRunnerEvidence(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.State = controller.StateReleaseArmed
	fixture.session.phantomOnMiss = githubscale.RunnerRef{
		ID:   78,
		Name: fixture.assignment.Slot.OpaqueName,
	}

	if err := fixture.service.Destroy(
		context.Background(),
		fixture.assignment.Key,
		controller.ReasonLifecycleCanceled,
	); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Destroy(nonzero not-found runner) = %v, want ErrInvalidState", err)
	}
	if fixture.state.record.State == controller.StateDestroyed ||
		fixture.recovery.removeCalls != 0 {
		t.Fatalf(
			"unproven upstream absence destroyed state/runtime: state=%s removes=%d",
			fixture.state.record.State,
			fixture.recovery.removeCalls,
		)
	}
}

func TestServiceDestroyPreReleaseDoesNotDependOnUpstreamSession(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.State = controller.StateAdapterCreated
	fixture.state.record.Slot.AdapterContainerID = "adapter-id"
	fixture.sessions.err = errors.New("upstream unavailable")

	if err := fixture.service.Destroy(
		context.Background(),
		fixture.assignment.Key,
		controller.ReasonLifecycleCanceled,
	); err != nil {
		t.Fatalf("Destroy(pre-JIT with upstream unavailable) = %v", err)
	}
	if fixture.sessions.calls != 0 ||
		fixture.state.record.State != controller.StateDestroyed ||
		fixture.recovery.removeCalls != 1 {
		t.Fatalf(
			"pre-JIT cleanup = session calls %d state %s removes %d",
			fixture.sessions.calls,
			fixture.state.record.State,
			fixture.recovery.removeCalls,
		)
	}
}

func TestServiceReleaseAmbiguityRetainsRegistrationAndBlocksRetry(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.jails.releaseErr = networkjail.ErrListenerAmbiguous
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); !errors.Is(err, ErrReleaseAmbiguous) {
		t.Fatalf("Release() = %v, want ErrReleaseAmbiguous", err)
	}
	if _, found := fixture.session.runners[fixture.assignment.Slot.OpaqueName]; !found {
		t.Fatal("ambiguous Release removed upstream registration")
	}
	if !fixture.state.record.Ambiguous {
		t.Fatal("ambiguous Release did not persist ambiguity")
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); !errors.Is(err, ErrReleaseAmbiguous) {
		t.Fatalf("ambiguous retry = %v, want ErrReleaseAmbiguous", err)
	}
	if fixture.session.generateCalls != 1 || fixture.jails.releaseCalls != 1 {
		t.Fatalf("ambiguous retry repeated effects: generate=%d release=%d",
			fixture.session.generateCalls, fixture.jails.releaseCalls)
	}
}

func TestServiceObserveBindsByExactRunnerNameAndObservedRequest(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
	event, err := githubscale.NewStartedEvent(githubscale.StartedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID:  941,
			JobID:            fixture.assignment.Offer.JobID,
			RunnerAssignTime: time.Now().Add(-time.Second),
		},
		RunnerID:   runner.ID,
		RunnerName: runner.Name,
	})
	if err != nil {
		t.Fatalf("NewStartedEvent() = %v", err)
	}
	if err := fixture.service.Observe(context.Background(), event); err != nil {
		t.Fatalf("Observe(started) = %v", err)
	}
	if fixture.state.record.State != controller.StateJobRunning ||
		fixture.state.record.Slot.UpstreamRunnerID != runner.ID ||
		fixture.state.record.Slot.BoundRequestID != 941 {
		t.Fatalf("observed state = %+v", fixture.state.record)
	}
}

func TestServiceCompletionCanEstablishMissingStartThenDestroyExactlyOnce(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
	event, err := githubscale.NewCompletedEvent(githubscale.CompletedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID: 942,
			JobID:           fixture.assignment.Offer.JobID,
			FinishTime:      time.Now().Add(-time.Second),
		},
		RunnerID:   runner.ID,
		RunnerName: runner.Name,
		Result:     "Succeeded",
	})
	if err != nil {
		t.Fatalf("NewCompletedEvent() = %v", err)
	}
	if err := fixture.service.Observe(context.Background(), event); err != nil {
		t.Fatalf("Observe(completed) = %v", err)
	}
	if fixture.state.record.State != controller.StateJobFinished ||
		fixture.state.record.Slot.BoundRequestID != 942 {
		t.Fatalf("completed state = %+v", fixture.state.record)
	}
	if err := fixture.service.Destroy(
		context.Background(),
		fixture.assignment.Key,
		controller.ReasonLifecycleJobFinished,
	); err != nil {
		t.Fatalf("Destroy() = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed ||
		fixture.jails.destroyLive != 1 {
		t.Fatalf("destroy state=%s live calls=%d", fixture.state.record.State, fixture.jails.destroyLive)
	}
	if err := fixture.service.Destroy(
		context.Background(),
		fixture.assignment.Key,
		controller.ReasonLifecycleJobFinished,
	); err != nil {
		t.Fatalf("Destroy(replay) = %v", err)
	}
	if fixture.jails.destroyLive != 1 {
		t.Fatalf("Destroy replay repeated live cleanup: %d", fixture.jails.destroyLive)
	}
}

func TestServiceAssignedRetiresOnlyOlderUnboundPreRunningOffer(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.Offer.ScaleSetAssignTime = time.Now().Add(-2 * time.Minute)
	event, err := githubscale.NewAssignedEvent(githubscale.AssignedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID:    fixture.assignment.Key.RunnerRequestID + 100,
			JobID:              fixture.assignment.Offer.JobID,
			ScaleSetAssignTime: time.Now().Add(-time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("NewAssignedEvent() = %v", err)
	}
	if err := fixture.service.Observe(context.Background(), event); err != nil {
		t.Fatalf("Observe(assigned) = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed ||
		fixture.recovery.removeCalls != 1 {
		t.Fatalf("obsolete state=%s recovery removes=%d",
			fixture.state.record.State, fixture.recovery.removeCalls)
	}

	live := newLifecycleFixture(t)
	live.state.record.Offer.ScaleSetAssignTime = time.Now().Add(-2 * time.Minute)
	live.state.record.Slot.UpstreamRunnerID = 777
	if err := live.service.Observe(context.Background(), event); err != nil {
		t.Fatalf("Observe(assigned with live old runner) = %v", err)
	}
	if live.state.record.State == controller.StateDestroyed {
		t.Fatal("Assigned event destroyed an already-bound runner")
	}
}

func TestServiceObserveAssignedWithoutRepositoryScopeRejectsCrossFleetCollision(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.Offer.ScaleSetAssignTime = time.Now().Add(-2 * time.Minute)
	other := fixture.state.record
	other.Key = controller.AssignmentKey{
		RepositoryAlias: "repo-b",
		RunnerRequestID: fixture.assignment.Key.RunnerRequestID + 1,
		Attempt:         1,
	}
	other.Offer.RepositoryAlias = other.Key.RepositoryAlias
	other.Offer.RunnerRequestID = other.Key.RunnerRequestID
	other.Slot.OpaqueName = controller.OpaqueSlotName(other.Key)
	other.Slot.CapacitySlotID++
	fixture.state.extra = []state.RecoverableAssignment{other}

	event, err := githubscale.NewAssignedEvent(githubscale.AssignedEvent{
		JobRef: githubscale.JobRef{
			RunnerRequestID:    fixture.assignment.Key.RunnerRequestID + 100,
			JobID:              fixture.assignment.Offer.JobID,
			ScaleSetAssignTime: time.Now().Add(-time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("NewAssignedEvent() = %v", err)
	}
	if err := fixture.service.Observe(context.Background(), event); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Observe(cross-fleet Assigned) = %v, want ErrInvalidState", err)
	}
	if fixture.state.record.State == controller.StateDestroyed ||
		fixture.state.extra[0].State == controller.StateDestroyed ||
		fixture.recovery.removeCalls != 0 {
		t.Fatalf(
			"cross-fleet observation mutated state: first=%s second=%s removes=%d",
			fixture.state.record.State,
			fixture.state.extra[0].State,
			fixture.recovery.removeCalls,
		)
	}
}

func TestServiceRecordBatchScopesAssignedRetirementToRepositoryAlias(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.Offer.ScaleSetAssignTime = time.Now().Add(-2 * time.Minute)
	other := fixture.state.record
	other.Key = controller.AssignmentKey{
		RepositoryAlias: "repo-b",
		RunnerRequestID: fixture.assignment.Key.RunnerRequestID + 1,
		Attempt:         1,
	}
	other.Offer.RepositoryAlias = other.Key.RepositoryAlias
	other.Offer.RunnerRequestID = other.Key.RunnerRequestID
	other.Slot.OpaqueName = controller.OpaqueSlotName(other.Key)
	other.Slot.CapacitySlotID++
	fixture.state.extra = []state.RecoverableAssignment{other}

	if err := fixture.service.RecordBatch(context.Background(), controller.MessageEnvelope{
		RepositoryAlias: fixture.assignment.Key.RepositoryAlias,
		Assigned: []controller.MessageAssigned{{
			Job: controller.MessageJobRef{
				RunnerRequestID:    fixture.assignment.Key.RunnerRequestID + 100,
				JobID:              fixture.assignment.Offer.JobID,
				ScaleSetAssignTime: time.Now().Add(-time.Minute),
			},
		}},
	}); err != nil {
		t.Fatalf("RecordBatch(scoped Assigned) = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed {
		t.Fatalf("repo-a obsolete state = %s, want DESTROYED", fixture.state.record.State)
	}
	if fixture.state.extra[0].State == controller.StateDestroyed {
		t.Fatal("repo-a batch retired an identically shaped repo-b offer")
	}
}

func TestServiceRecordBatchLocksEveryAffectedKeyBeforeApplying(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.State = controller.StateListenerReleased
	fixture.state.record.Released = true
	fixture.state.record.Slot.RunnerContainerID = "runner-a"

	other := fixture.state.record
	other.Key = controller.AssignmentKey{
		RepositoryAlias: fixture.assignment.Key.RepositoryAlias,
		RunnerRequestID: fixture.assignment.Key.RunnerRequestID + 1,
		Attempt:         1,
	}
	other.Offer.RunnerRequestID = other.Key.RunnerRequestID
	other.Offer.JobID = "job-b"
	other.Slot.OpaqueName = controller.OpaqueSlotName(other.Key)
	other.Slot.CapacitySlotID++
	other.Slot.RunnerContainerID = "runner-b"
	fixture.state.extra = []state.RecoverableAssignment{other}
	installLiveBinding(t, fixture, fixture.state.record)
	installLiveBinding(t, fixture, other)

	implementation := fixture.service.(*service)
	unlockOther := implementation.locks.lock(other.Key)
	lockReleased := false
	defer func() {
		if !lockReleased {
			unlockOther()
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- fixture.service.RecordBatch(context.Background(), controller.MessageEnvelope{
			RepositoryAlias: fixture.assignment.Key.RepositoryAlias,
			Started: []controller.MessageStarted{
				{
					Job: controller.MessageJobRef{
						RunnerRequestID:  fixture.assignment.Key.RunnerRequestID,
						JobID:            fixture.assignment.Offer.JobID,
						RunnerAssignTime: time.Now().Add(-time.Second),
					},
					RunnerID:   501,
					RunnerName: fixture.assignment.Slot.OpaqueName,
				},
				{
					Job: controller.MessageJobRef{
						RunnerRequestID:  other.Key.RunnerRequestID,
						JobID:            other.Offer.JobID,
						RunnerAssignTime: time.Now().Add(-time.Second),
					},
					RunnerID:   502,
					RunnerName: other.Slot.OpaqueName,
				},
			},
		})
	}()

	deadline := time.Now().Add(time.Second)
	for {
		implementation.locks.mu.Lock()
		waiters := implementation.locks.entries[other.Key]
		refs := 0
		if waiters != nil {
			refs = waiters.refs
		}
		implementation.locks.mu.Unlock()
		if refs == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RecordBatch did not block while acquiring its full key set")
		}
		time.Sleep(time.Millisecond)
	}

	fixture.state.mu.Lock()
	firstState := fixture.state.record.State
	secondState := fixture.state.extra[0].State
	fixture.state.mu.Unlock()
	if firstState != controller.StateListenerReleased ||
		secondState != controller.StateListenerReleased {
		t.Fatalf(
			"batch partially applied before all locks: first=%s second=%s",
			firstState,
			secondState,
		)
	}

	unlockOther()
	lockReleased = true
	if err := <-done; err != nil {
		t.Fatalf("RecordBatch() = %v", err)
	}
	fixture.state.mu.Lock()
	first := fixture.state.record
	second := fixture.state.extra[0]
	fixture.state.mu.Unlock()
	if first.State != controller.StateJobRunning ||
		first.Slot.UpstreamRunnerID != 501 ||
		second.State != controller.StateJobRunning ||
		second.Slot.UpstreamRunnerID != 502 {
		t.Fatalf("batch observations = (%+v,%+v), want both running", first, second)
	}
}

func TestServiceRecordBatchRunnerEvidenceProtectsSameBatchFromRetirement(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.State = controller.StateListenerReleased
	fixture.state.record.Released = true
	fixture.state.record.Offer.ScaleSetAssignTime = time.Now().Add(-2 * time.Minute)
	fixture.state.record.Slot.RunnerContainerID = "runner-a"
	installLiveBinding(t, fixture, fixture.state.record)

	if err := fixture.service.RecordBatch(context.Background(), controller.MessageEnvelope{
		RepositoryAlias: fixture.assignment.Key.RepositoryAlias,
		Assigned: []controller.MessageAssigned{{
			Job: controller.MessageJobRef{
				RunnerRequestID:    fixture.assignment.Key.RunnerRequestID + 100,
				JobID:              fixture.assignment.Offer.JobID,
				ScaleSetAssignTime: time.Now().Add(-time.Minute),
			},
		}},
		Started: []controller.MessageStarted{{
			Job: controller.MessageJobRef{
				RunnerRequestID:  fixture.assignment.Key.RunnerRequestID,
				JobID:            fixture.assignment.Offer.JobID,
				RunnerAssignTime: time.Now().Add(-time.Second),
			},
			RunnerID:   503,
			RunnerName: fixture.assignment.Slot.OpaqueName,
		}},
	}); err != nil {
		t.Fatalf("RecordBatch(assigned+started) = %v", err)
	}
	if fixture.state.record.State != controller.StateJobRunning ||
		fixture.state.record.Slot.UpstreamRunnerID != 503 ||
		fixture.recovery.removeCalls != 0 {
		t.Fatalf(
			"same-batch live evidence lost: state=%s runner=%d removes=%d",
			fixture.state.record.State,
			fixture.state.record.Slot.UpstreamRunnerID,
			fixture.recovery.removeCalls,
		)
	}
}

func TestServiceRecordBatchBindsTwoRunnersInObservedOppositeOrder(t *testing.T) {
	fixture := newLifecycleFixture(t)
	fixture.state.record.State = controller.StateListenerReleased
	fixture.state.record.Released = true
	fixture.state.record.Slot.RunnerContainerID = "runner-a"

	other := fixture.state.record
	other.Key = controller.AssignmentKey{
		RepositoryAlias: fixture.assignment.Key.RepositoryAlias,
		RunnerRequestID: fixture.assignment.Key.RunnerRequestID + 1,
		Attempt:         1,
	}
	other.Offer.RunnerRequestID = other.Key.RunnerRequestID
	other.Slot.OpaqueName = controller.OpaqueSlotName(other.Key)
	other.Slot.CapacitySlotID++
	other.Slot.RunnerContainerID = "runner-b"
	fixture.state.extra = []state.RecoverableAssignment{other}
	installLiveBinding(t, fixture, fixture.state.record)
	installLiveBinding(t, fixture, other)

	if err := fixture.service.RecordBatch(context.Background(), controller.MessageEnvelope{
		RepositoryAlias: fixture.assignment.Key.RepositoryAlias,
		Started: []controller.MessageStarted{
			{
				Job: controller.MessageJobRef{
					RunnerRequestID:  other.Key.RunnerRequestID,
					JobID:            fixture.assignment.Offer.JobID,
					RunnerAssignTime: time.Now().Add(-time.Second),
				},
				RunnerID:   601,
				RunnerName: fixture.assignment.Slot.OpaqueName,
			},
			{
				Job: controller.MessageJobRef{
					RunnerRequestID:  fixture.assignment.Key.RunnerRequestID,
					JobID:            fixture.assignment.Offer.JobID,
					RunnerAssignTime: time.Now().Add(-time.Second),
				},
				RunnerID:   602,
				RunnerName: other.Slot.OpaqueName,
			},
		},
	}); err != nil {
		t.Fatalf("RecordBatch(opposite binding) = %v", err)
	}
	if fixture.state.record.Slot.BoundRequestID != other.Key.RunnerRequestID ||
		fixture.state.record.Slot.UpstreamRunnerID != 601 ||
		fixture.state.extra[0].Slot.BoundRequestID !=
			fixture.assignment.Key.RunnerRequestID ||
		fixture.state.extra[0].Slot.UpstreamRunnerID != 602 {
		t.Fatalf(
			"opposite observed bindings = (%+v,%+v)",
			fixture.state.record.Slot,
			fixture.state.extra[0].Slot,
		)
	}
}

func TestServiceReconcileCapacityStartsOneLifecycle(t *testing.T) {
	fixture := newLifecycleFixture(t)
	projected := projectedRecovery(fixture.state.record)
	if err := fixture.service.ReconcileAssignment(context.Background(), projected); err != nil {
		t.Fatalf("ReconcileAssignment() = %v", err)
	}
	if fixture.jails.prepareCalls != 1 ||
		fixture.jails.releaseCalls != 1 ||
		fixture.session.generateCalls != 1 ||
		fixture.state.record.State != controller.StateListenerReleased {
		t.Fatalf("reconcile effects prepare=%d release=%d jit=%d state=%s",
			fixture.jails.prepareCalls,
			fixture.jails.releaseCalls,
			fixture.session.generateCalls,
			fixture.state.record.State)
	}
}

func TestServiceReconcileRejectsAnyChangedControllerProjection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*controller.RecoverableAssignment)
	}{
		{
			name: "released",
			mutate: func(projected *controller.RecoverableAssignment) {
				projected.Released = !projected.Released
			},
		},
		{
			name: "ambiguity",
			mutate: func(projected *controller.RecoverableAssignment) {
				projected.Ambiguous = true
				projected.AmbiguousReason = "stale-projection"
			},
		},
		{
			name: "offer",
			mutate: func(projected *controller.RecoverableAssignment) {
				projected.Offer.JobID = "different-job"
			},
		},
		{
			name: "admission",
			mutate: func(projected *controller.RecoverableAssignment) {
				projected.Admission.SlotID++
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t)
			projected := projectedRecovery(fixture.state.record)
			test.mutate(&projected)
			if err := fixture.service.ReconcileAssignment(
				context.Background(),
				projected,
			); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("ReconcileAssignment(changed %s) = %v, want ErrInvalidState", test.name, err)
			}
			if fixture.jails.prepareCalls != 0 ||
				fixture.jails.releaseCalls != 0 ||
				fixture.session.generateCalls != 0 {
				t.Fatalf(
					"changed %s projection caused effects: prepare=%d release=%d jit=%d",
					test.name,
					fixture.jails.prepareCalls,
					fixture.jails.releaseCalls,
					fixture.session.generateCalls,
				)
			}
		})
	}
}

func TestServiceReconcileAmbiguousReleaseBothAbsentResolvesDestroyed(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	fixture.state.record.Ambiguous = true
	fixture.state.record.AmbiguousReason = "listener-release-checkpoint"
	fixture.state.effects[state.LifecycleEffectListenerRelease] =
		state.EffectRecord{State: state.EffectPending}
	projected := projectedRecovery(fixture.state.record)

	if err := fixture.service.ReconcileAssignment(context.Background(), projected); err != nil {
		t.Fatalf("ReconcileAssignment(ambiguous absent) = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed ||
		fixture.recovery.inspectCalls != 2 ||
		fixture.recovery.removeCalls != 1 ||
		fixture.jails.destroyHeld != 1 ||
		fixture.session.generateCalls != 0 {
		t.Fatalf("ambiguous resolution state=%s inspect=%d remove=%d held=%d jit=%d",
			fixture.state.record.State,
			fixture.recovery.inspectCalls,
			fixture.recovery.removeCalls,
			fixture.jails.destroyHeld,
			fixture.session.generateCalls)
	}
}

func TestServiceReconcileOneSidedResidueBindsPreCleanupEvidence(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	fixture.state.record.Ambiguous = true
	fixture.state.record.AmbiguousReason = "listener-release-checkpoint"
	fixture.state.effects[state.LifecycleEffectListenerRelease] =
		state.EffectRecord{State: state.EffectPending}
	upstream := githubscale.RunnerRef{
		ID:   991,
		Name: fixture.assignment.Slot.OpaqueName,
	}
	fixture.session.runners[upstream.Name] = upstream
	before := fixture.state.record

	if err := fixture.service.ReconcileAssignment(
		context.Background(),
		projectedRecovery(before),
	); err != nil {
		t.Fatalf("ReconcileAssignment(one-sided residue) = %v", err)
	}
	want := reconciliationEvidence(
		before,
		upstream,
		true,
		hostruntime.ManagedObservation{},
		true,
	)
	if fixture.state.resolvedEvidence != want {
		t.Fatalf(
			"one-sided evidence = %x, want pre-cleanup binding %x",
			fixture.state.resolvedEvidence,
			want,
		)
	}
}

func TestServiceReconcileLiveListenerDoesNotFreezeLaterDestroyedResolution(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := fixture.service.Release(context.Background(), fixture.assignment.Key); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	runner := fixture.session.runners[fixture.assignment.Slot.OpaqueName]
	live := hostruntime.ManagedObservation{
		AdapterPresent: true,
		AdapterRunning: true,
		BrokerPresent:  true,
		BrokerRunning:  true,
		RunnerPresent:  true,
		RunnerRunning:  true,
	}
	service := fixture.service.(*service)
	if err := service.resolveLivePostRelease(
		context.Background(),
		fixture.state.record,
		runner,
		live,
	); err != nil {
		t.Fatalf("resolveLivePostRelease(healthy listener) = %v", err)
	}
	if fixture.state.resolveCalls != 0 {
		t.Errorf(
			"healthy LISTENER_RELEASED persisted %d resolution effects, want zero",
			fixture.state.resolveCalls,
		)
	}

	delete(fixture.session.runners, fixture.assignment.Slot.OpaqueName)
	projected := projectedRecovery(fixture.state.record)
	if err := fixture.service.ReconcileAssignment(
		context.Background(),
		projected,
	); err != nil {
		t.Fatalf("ReconcileAssignment(later absent) = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed ||
		fixture.state.resolveCalls != 1 ||
		fixture.state.resolvedOutcome != controller.PostReleaseDestroyed {
		t.Fatalf(
			"later absence state=%s calls=%d outcome=%v, want DESTROYED/1/DESTROYED",
			fixture.state.record.State,
			fixture.state.resolveCalls,
			fixture.state.resolvedOutcome,
		)
	}
}

func TestServiceReconcileReleaseArmedLiveCanLaterResolveDestroyed(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	fixture.state.effects[state.LifecycleEffectListenerRelease] =
		state.EffectRecord{State: state.EffectPending}
	runner := githubscale.RunnerRef{
		ID:   991,
		Name: fixture.assignment.Slot.OpaqueName,
	}
	fixture.session.runners[runner.Name] = runner
	live := hostruntime.ManagedObservation{
		AdapterPresent: true,
		AdapterRunning: true,
		BrokerPresent:  true,
		BrokerRunning:  true,
		RunnerPresent:  true,
		RunnerRunning:  true,
	}
	service := fixture.service.(*service)
	if err := service.resolveLivePostRelease(
		context.Background(),
		fixture.state.record,
		runner,
		live,
	); err != nil {
		t.Fatalf("resolveLivePostRelease(RELEASE_ARMED) = %v", err)
	}
	if fixture.state.record.State != controller.StateListenerReleased ||
		fixture.state.resolveCalls != 1 {
		t.Fatalf(
			"live RELEASE_ARMED state=%s calls=%d, want LISTENER_RELEASED/1",
			fixture.state.record.State,
			fixture.state.resolveCalls,
		)
	}

	delete(fixture.session.runners, runner.Name)
	projected := projectedRecovery(fixture.state.record)
	if err := fixture.service.ReconcileAssignment(
		context.Background(),
		projected,
	); err != nil {
		t.Fatalf("ReconcileAssignment(later absent) = %v", err)
	}
	if fixture.state.record.State != controller.StateDestroyed ||
		fixture.state.resolveCalls != 2 ||
		fixture.state.resolvedOutcome != controller.PostReleaseDestroyed {
		t.Fatalf(
			"later absence state=%s calls=%d outcome=%v, want DESTROYED/2/DESTROYED",
			fixture.state.record.State,
			fixture.state.resolveCalls,
			fixture.state.resolvedOutcome,
		)
	}
}

func TestRuntimeGraphLiveRequiresEveryPrimaryComponentRunning(t *testing.T) {
	complete := hostruntime.ManagedObservation{
		AdapterPresent: true,
		AdapterRunning: true,
		BrokerPresent:  true,
		BrokerRunning:  true,
		RunnerPresent:  true,
		RunnerRunning:  true,
	}
	if !runtimeGraphLive(complete) {
		t.Fatal("complete running graph was not classified live")
	}
	tests := []struct {
		name   string
		mutate func(*hostruntime.ManagedObservation)
	}{
		{"adapter absent", func(value *hostruntime.ManagedObservation) { value.AdapterPresent = false }},
		{"adapter stopped", func(value *hostruntime.ManagedObservation) { value.AdapterRunning = false }},
		{"broker absent", func(value *hostruntime.ManagedObservation) { value.BrokerPresent = false }},
		{"broker stopped", func(value *hostruntime.ManagedObservation) { value.BrokerRunning = false }},
		{"runner absent", func(value *hostruntime.ManagedObservation) { value.RunnerPresent = false }},
		{"runner stopped", func(value *hostruntime.ManagedObservation) { value.RunnerRunning = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := complete
			test.mutate(&observation)
			if runtimeGraphLive(observation) {
				t.Fatalf("incomplete graph classified live: %+v", observation)
			}
		})
	}
}

func TestServiceSameKeyExclusionBlocksReconcileDuringRelease(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.service.Prepare(context.Background(), fixture.assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	fixture.jails.releaseStart = make(chan struct{}, 1)
	fixture.jails.releaseGo = make(chan struct{})
	releaseDone := make(chan error, 1)
	go func() {
		releaseDone <- fixture.service.Release(context.Background(), fixture.assignment.Key)
	}()
	<-fixture.jails.releaseStart

	reconcileDone := make(chan error, 1)
	projected := projectedRecovery(fixture.state.record)
	go func() {
		reconcileDone <- fixture.service.ReconcileAssignment(context.Background(), projected)
	}()
	select {
	case err := <-reconcileDone:
		t.Fatalf("ReconcileAssignment entered same key while Release held it: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(fixture.jails.releaseGo)
	if err := <-releaseDone; err != nil {
		t.Fatalf("Release() = %v", err)
	}
	// The queued reconciler sees the now-stale projection and fails closed; it
	// must not execute a second JIT or listener release.
	if err := <-reconcileDone; !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ReconcileAssignment(stale after release) = %v, want ErrInvalidState", err)
	}
	if fixture.session.generateCalls != 1 || fixture.jails.releaseCalls != 1 {
		t.Fatalf("same-key race repeated effects: jit=%d release=%d",
			fixture.session.generateCalls, fixture.jails.releaseCalls)
	}
}

type lifecycleFixture struct {
	service    Runtime
	state      *fakeLifecycleState
	session    *fakeLifecycleSession
	sessions   *fakeSessionProvider
	jit        *fakeJITAuthorizer
	jails      *fakeJailOrchestrator
	recovery   *fakeManagedRecovery
	assignment controller.Assignment
}

func (fixture lifecycleFixture) builderCalls() int {
	return fixture.service.(*service).builder.(*fakeSetupBuilder).calls
}

func installLiveBinding(
	t *testing.T,
	fixture lifecycleFixture,
	record state.RecoverableAssignment,
) *fakeLifecyclePermit {
	t.Helper()
	assignment, err := assignmentFromRecord(record)
	if err != nil {
		t.Fatalf("assignmentFromRecord() = %v", err)
	}
	permit := newFakeLifecyclePermit(assignment)
	service := fixture.service.(*service)
	service.cacheMu.Lock()
	service.live[record.Key] = liveEntry{
		assignment: assignment,
		permit:     permit,
		binding:    permit.Binding(),
	}
	service.cacheMu.Unlock()
	fixture.state.mu.Lock()
	fixture.state.effects[state.LifecycleEffectListenerRelease] =
		state.EffectRecord{State: state.EffectCompleted}
	fixture.state.mu.Unlock()
	return permit
}

func newLifecycleFixture(t *testing.T) lifecycleFixture {
	t.Helper()
	key := controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 41,
		Attempt:         1,
	}
	slot := controller.RunnerSlot{
		OpaqueName:     controller.OpaqueSlotName(key),
		CapacitySlotID: 7,
	}
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: key.RunnerRequestID,
		JobID:           "job-a",
		RequestLabels:   []string{"portable-ghar"},
	}}
	assignment, err := controller.NewAssignment(key, offer, slot)
	if err != nil {
		t.Fatalf("NewAssignment() = %v", err)
	}
	record := state.RecoverableAssignment{
		Key:   key,
		State: controller.StateCapacityReserved,
		Offer: state.OfferIdentity{
			RepositoryAlias: key.RepositoryAlias,
			RunnerRequestID: key.RunnerRequestID,
			JobID:           offer.JobID,
			RequestLabels:   append([]string(nil), offer.RequestLabels...),
		},
		Slot:      slot,
		UpdatedAt: time.Now().Add(-time.Minute),
	}
	durable := &fakeLifecycleState{
		record:  record,
		effects: make(map[string]state.EffectRecord),
		acquisition: map[controller.AssignmentKey]state.AcquisitionAssignmentRecord{
			key: {
				Key:     key,
				Outcome: state.AcquisitionOutcomeAcquired,
			},
		},
	}
	session := &fakeLifecycleSession{
		runners:      make(map[string]githubscale.RunnerRef),
		nextRunnerID: 100,
	}
	sessions := &fakeSessionProvider{session: session}
	jit := &fakeJITAuthorizer{permit: newFakeLifecyclePermit(assignment)}
	adapterName, brokerName, runnerName, err := componentNames(slot.OpaqueName)
	if err != nil {
		t.Fatalf("componentNames() = %v", err)
	}
	builder := &fakeSetupBuilder{
		prepared: networkjail.PreparedSetupRequest{
			Key: key,
			Adapter: hostruntime.AdapterSpec{
				Name:         adapterName,
				SlotIdentity: slot.OpaqueName,
			},
			Broker: hostruntime.BrokerSpec{
				Name:           brokerName,
				SlotIdentity:   slot.OpaqueName,
				CapacitySlotID: slot.CapacitySlotID,
			},
			Runner: hostruntime.RunnerSpec{
				Name:         runnerName,
				SlotIdentity: slot.OpaqueName,
			},
			Verifier: hostruntime.VerifierSpec{SlotIdentity: slot.OpaqueName},
		},
		recovery: hostruntime.RecoverySpec{
			SlotIdentity: slot.OpaqueName,
			AdapterName:  adapterName,
			BrokerName:   brokerName,
			RunnerName:   runnerName,
		},
	}
	jails := &fakeJailOrchestrator{state: durable}
	recovery := &fakeManagedRecovery{}
	service, err := NewService(
		durable,
		sessions,
		jit,
		builder,
		jails,
		recovery,
		time.Now,
	)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	return lifecycleFixture{
		service:    service,
		state:      durable,
		session:    session,
		sessions:   sessions,
		jit:        jit,
		jails:      jails,
		recovery:   recovery,
		assignment: assignment,
	}
}

func projectedRecovery(record state.RecoverableAssignment) controller.RecoverableAssignment {
	return controller.RecoverableAssignment{
		Key:   record.Key,
		State: record.State,
		Offer: githubscale.Offer{JobRef: githubscale.JobRef{
			RunnerRequestID:    record.Offer.RunnerRequestID,
			JobID:              record.Offer.JobID,
			RepositoryName:     record.Offer.RepositoryName,
			OwnerName:          record.Offer.OwnerName,
			RequestLabels:      append([]string(nil), record.Offer.RequestLabels...),
			ScaleSetAssignTime: record.Offer.ScaleSetAssignTime,
		}},
		Released:        record.Released,
		Ambiguous:       record.Ambiguous,
		AmbiguousReason: record.AmbiguousReason,
		Slot:            record.Slot,
		UpdatedAt:       record.UpdatedAt,
	}
}
