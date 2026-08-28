package failoverclient

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

type controlledAuthorityClock struct {
	mu       sync.Mutex
	now      time.Time
	started  chan time.Time
	release  chan error
	returned chan error
}

type secondNowGateClock struct {
	base    *controlledAuthorityClock
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func newSecondNowGateClock(base *controlledAuthorityClock) *secondNowGateClock {
	return &secondNowGateClock{
		base:    base,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (clock *secondNowGateClock) Capable() bool {
	return clock != nil && clock.base != nil && clock.base.Capable()
}

func (clock *secondNowGateClock) Now() (time.Time, error) {
	clock.mu.Lock()
	clock.calls++
	call := clock.calls
	clock.mu.Unlock()
	if call == 2 {
		close(clock.entered)
		<-clock.release
	}
	return clock.base.Now()
}

func (clock *secondNowGateClock) WaitUntil(
	ctx context.Context,
	deadline time.Time,
) error {
	return clock.base.WaitUntil(ctx, deadline)
}

func newControlledAuthorityClock(now time.Time) *controlledAuthorityClock {
	return &controlledAuthorityClock{
		now:      now,
		started:  make(chan time.Time, 8),
		release:  make(chan error, 8),
		returned: make(chan error, 8),
	}
}

func (clock *controlledAuthorityClock) Capable() bool { return clock != nil }

func (clock *controlledAuthorityClock) Now() (time.Time, error) {
	if clock == nil {
		return time.Time{}, ErrAuthorityClock
	}
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now, nil
}

func (clock *controlledAuthorityClock) SetNow(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

func (clock *controlledAuthorityClock) WaitUntil(
	ctx context.Context,
	deadline time.Time,
) error {
	select {
	case clock.started <- deadline:
	case <-ctx.Done():
		return ctx.Err()
	}
	var err error
	select {
	case err = <-clock.release:
		if err == nil {
			err = context.DeadlineExceeded
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	clock.returned <- err
	return err
}

type cachedPermitFixture struct {
	clock    *controlledAuthorityClock
	cache    *LeaseCache
	provider CachedLeasePermitProvider
	request  controller.AcquisitionPermitRequest
	lease    AcquisitionLeaseV1
	revision uint64
	anchor   time.Time
	deadline time.Time
}

func newCachedPermitFixture(t *testing.T, mode LeaseMode) *cachedPermitFixture {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	fixture := &cachedPermitFixture{
		clock:    newControlledAuthorityClock(now),
		cache:    &LeaseCache{},
		lease:    testLease(mode),
		anchor:   now.Add(-time.Second),
		deadline: now.Add(6 * time.Second),
		request: controller.AcquisitionPermitRequest{
			OperationID:              "operation-1",
			RepositoryAlias:          "repo-b",
			ScaleSetName:             "canary-set",
			PolicyDigest:             strings.Repeat("a", 64),
			OperationKind:            "poll",
			PolicyEpoch:              9,
			PolicyMode:               controller.AcquisitionEnabled,
			MaxCapacity:              2,
			RepositoryPolicyRevision: 4,
		},
	}
	fixture.install(t, fixture.lease, 4, fixture.anchor, fixture.deadline)
	provider, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           fixture.cache,
		Clock:           fixture.clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    2 * time.Second,
		TerminationTail: time.Second,
	})
	if err != nil {
		t.Fatalf("NewCachedLeasePermitProvider: %v", err)
	}
	fixture.provider = provider
	return fixture
}

func (fixture *cachedPermitFixture) install(
	t *testing.T,
	lease AcquisitionLeaseV1,
	sequence uint64,
	anchor time.Time,
	deadline time.Time,
) {
	t.Helper()
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		t.Fatalf("AdmissionAuthorityKey: %v", err)
	}
	revision, err := fixture.cache.CompareAndSwap(fixture.revision, &CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      sequence,
		Fence:         7,
		LocalDeadline: deadline,
		SendAnchor:    anchor,
	})
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	fixture.revision = revision
}

func (fixture *cachedPermitFixture) acquire(
	t *testing.T,
) controller.AcquisitionPermitGuard {
	t.Helper()
	guard, err := fixture.provider.Acquire(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	return guard
}

func testLease(mode LeaseMode) AcquisitionLeaseV1 {
	canary := "canary-set"
	lease := AcquisitionLeaseV1{
		ProtocolVersion:          1,
		FleetID:                  "example-fleet",
		Holder:                   HolderPortable,
		ServerEpoch:              2,
		SessionID:                strings.Repeat("b", 64),
		LeaseGeneration:          3,
		Mode:                     mode,
		PolicyDigest:             strings.Repeat("a", 64),
		RepositoryPolicyRevision: 4,
		LocalPolicyEpoch:         9,
		MaxCapacity:              1,
		DurationMs:               8000,
		Expiry:                   "2026-01-01T00:00:08.000Z",
	}
	if mode == LeaseCanaryOnly {
		lease.CanaryScaleSet = &canary
	}
	if mode == LeaseEnabled {
		lease.MaxCapacity = 2
	}
	return lease
}

func TestCachedLeasePermitRejectsStaleExpiredAndArchived(t *testing.T) {
	clock := newControlledAuthorityClock(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	cache := &LeaseCache{}
	lease := testLease(LeaseCanaryOnly)
	lease.ArchivedDisabledAliases = []string{"repo-a"}
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	revision, err := cache.CompareAndSwap(0, &CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      4,
		Fence:         7,
		LocalDeadline: time.Date(2026, 1, 1, 0, 0, 7, 0, time.UTC),
		SendAnchor:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	provider, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           cache,
		Clock:           clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    2 * time.Second,
		TerminationTail: time.Second,
	})
	if err != nil {
		t.Fatalf("NewCachedLeasePermitProvider: %v", err)
	}
	request := controller.AcquisitionPermitRequest{
		OperationID:              "op-1",
		RepositoryAlias:          "repo-b",
		ScaleSetName:             "canary-set",
		PolicyDigest:             strings.Repeat("a", 64),
		OperationKind:            "poll",
		PolicyEpoch:              9,
		PolicyMode:               controller.AcquisitionCanaryOnly,
		MaxCapacity:              1,
		RepositoryPolicyRevision: 4,
	}
	guard, err := provider.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire valid: %v", err)
	}
	<-clock.started
	if err := guard.Close(); err != nil {
		t.Fatalf("Close valid guard: %v", err)
	}
	<-clock.returned
	request.RepositoryAlias = "repo-a"
	if _, err := provider.Acquire(context.Background(), request); err == nil ||
		!errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatalf("archived alias error = %v, want permit-authority classification", err)
	}
	request.RepositoryAlias = "repo-b"
	clock.SetNow(time.Date(2026, 1, 1, 0, 0, 11, 0, time.UTC))
	if _, err := provider.Acquire(context.Background(), request); err == nil ||
		!errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatalf("expired lease error = %v, want permit-authority classification", err)
	}
	if _, err := cache.CompareAndSwap(revision, nil); err != nil {
		t.Fatalf("clear cache: %v", err)
	}
	clock.SetNow(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	if _, err := provider.Acquire(context.Background(), request); err == nil ||
		!errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatalf("empty cache error = %v, want permit-authority classification", err)
	}
}

func TestCachedLeasePermitBindsCompleteLocalPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*controller.AcquisitionPermitRequest)
	}{
		{
			name: "mode",
			mutate: func(request *controller.AcquisitionPermitRequest) {
				request.PolicyMode = controller.AcquisitionCanaryOnly
				request.MaxCapacity = 1
			},
		},
		{
			name: "maximum capacity",
			mutate: func(request *controller.AcquisitionPermitRequest) {
				request.MaxCapacity++
			},
		},
		{
			name: "repository policy revision",
			mutate: func(request *controller.AcquisitionPermitRequest) {
				request.RepositoryPolicyRevision++
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCachedPermitFixture(t, LeaseEnabled)
			test.mutate(&fixture.request)
			guard, err := fixture.provider.Acquire(context.Background(), fixture.request)
			if guard != nil {
				_ = guard.Close()
			}
			if !errors.Is(err, ErrLeasePermit) {
				t.Fatalf("Acquire mismatched local policy = %v, want ErrLeasePermit", err)
			}
			if !errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
				t.Fatalf("Acquire mismatch = %v, want permit-authority classification", err)
			}
		})
	}
}

func TestCachedLeasePermitInvalidateFencesAnEmptyCache(t *testing.T) {
	fixture := newCachedPermitFixture(t, LeaseEnabled)
	if _, err := fixture.cache.CompareAndSwap(fixture.revision, nil); err != nil {
		t.Fatalf("clear seeded lease: %v", err)
	}
	before, err := fixture.cache.MutationRevision()
	if err != nil {
		t.Fatalf("MutationRevision before invalidation: %v", err)
	}
	if err := fixture.provider.Invalidate(context.Background()); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	after, err := fixture.cache.MutationRevision()
	if err != nil {
		t.Fatalf("MutationRevision after invalidation: %v", err)
	}
	if after != before+1 {
		t.Fatalf("empty-cache invalidation revision = %d, want %d", after, before+1)
	}
	key, err := fixture.lease.AdmissionAuthorityKey()
	if err != nil {
		t.Fatalf("AdmissionAuthorityKey: %v", err)
	}
	stale := CachedLease{
		Lease:         fixture.lease,
		Key:           key,
		Sequence:      5,
		Fence:         7,
		LocalDeadline: fixture.deadline,
		SendAnchor:    fixture.anchor,
	}
	if _, err := fixture.cache.CompareAndSwap(before, &stale); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("stale in-flight install = %v, want ErrLeaseCache", err)
	}
	if _, err := fixture.cache.Snapshot(); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("stale install repopulated cache: %v", err)
	}
}

func TestUnsupportedClockCannotAuthorize(t *testing.T) {
	if _, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           &LeaseCache{},
		Clock:           NewUnsupportedAuthorityClock(),
		Holder:          HolderPortable,
		Fence:           1,
		CallDuration:    time.Second,
		TerminationTail: 100 * time.Millisecond,
	}); err == nil {
		t.Fatal("unsupported clock accepted")
	}
	provider := CachedLeasePermitProvider{
		Cache:  &LeaseCache{},
		Clock:  NewUnsupportedAuthorityClock(),
		Holder: HolderPortable,
		Fence:  1,
	}
	if _, err := provider.Acquire(context.Background(), controller.AcquisitionPermitRequest{
		PolicyDigest: strings.Repeat("a", 64),
		PolicyEpoch:  1,
	}); err == nil {
		t.Fatal("unsupported clock authorized")
	}
}

func TestCachedLeasePermitPreservesCanceledContextCause(t *testing.T) {
	fixture := newCachedPermitFixture(t, LeaseEnabled)
	ctx, cancel := context.WithCancelCause(context.Background())
	rootCause := errors.New("operator canceled")
	cancel(rootCause)

	if _, err := fixture.provider.Acquire(ctx, fixture.request); err == nil ||
		!errors.Is(err, ErrLeasePermit) ||
		!errors.Is(err, context.Canceled) ||
		!errors.Is(err, rootCause) {
		t.Fatalf("Acquire canceled context = %v", err)
	} else if errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatalf("caller cancellation misclassified as invalid authority: %v", err)
	}
}

func TestLeasePermitPureRenewalRevalidatesAndAdmits(t *testing.T) {
	fixture := newCachedPermitFixture(t, LeaseEnabled)
	guard := fixture.acquire(t)
	startedDeadline := <-fixture.clock.started
	binding := guard.Binding()
	if binding.AuthorityRevision == 0 ||
		binding.AuthorityKey == "" ||
		binding.FenceGeneration != 7 ||
		binding.ServerEpoch != fixture.lease.ServerEpoch ||
		binding.SessionID != fixture.lease.SessionID ||
		binding.LeaseGeneration != fixture.lease.LeaseGeneration ||
		binding.OperationID != fixture.request.OperationID ||
		binding.RepositoryAlias != fixture.request.RepositoryAlias ||
		binding.ScaleSetName != fixture.request.ScaleSetName ||
		binding.OperationKind != fixture.request.OperationKind ||
		binding.PolicyDigest != fixture.request.PolicyDigest ||
		binding.PolicyEpoch != fixture.request.PolicyEpoch ||
		binding.PolicyMode != fixture.request.PolicyMode ||
		binding.MaxCapacity != fixture.request.MaxCapacity ||
		binding.RepositoryPolicyRevision != fixture.request.RepositoryPolicyRevision ||
		!binding.OriginalLocalDeadline.Equal(fixture.deadline) {
		t.Fatalf("incomplete immutable binding: %+v", binding)
	}

	fixture.install(
		t,
		fixture.lease,
		5,
		fixture.anchor.Add(time.Second),
		fixture.deadline.Add(2*time.Second),
	)
	if err := guard.ValidateBinding(context.Background(), binding); err != nil {
		t.Fatalf("ValidateBinding renewal: %v", err)
	}
	if renewed := guard.Binding(); renewed != binding {
		t.Fatalf("renewal changed immutable binding: got %+v want %+v", renewed, binding)
	}
	if err := guard.Revalidate(); err != nil {
		t.Fatalf("Revalidate renewal: %v", err)
	}
	if err := guard.Admit(); err != nil {
		t.Fatalf("Admit renewal: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close admitted guard: %v", err)
	}
	if got := <-fixture.clock.returned; !errors.Is(got, context.Canceled) {
		t.Fatalf("waiter return = %v, want cancellation", got)
	}
	if want := time.Date(2026, 1, 1, 0, 0, 3, 0, time.UTC); !startedDeadline.Equal(want) {
		t.Fatalf("original deadline = %v, want %v", startedDeadline, want)
	}
}

func TestLeasePermitRevalidateAndAdmitShareCompleteValidation(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*testing.T, *cachedPermitFixture, time.Time)
	}{
		{
			name: "authority replacement",
			mutate: func(t *testing.T, fixture *cachedPermitFixture, _ time.Time) {
				fixture.install(
					t,
					testLease(LeaseCanaryOnly),
					5,
					fixture.anchor.Add(time.Second),
					fixture.deadline.Add(time.Second),
				)
			},
		},
		{
			name: "exact operation deadline",
			mutate: func(_ *testing.T, fixture *cachedPermitFixture, deadline time.Time) {
				fixture.clock.SetNow(deadline)
			},
		},
	}
	validations := []struct {
		name string
		call func(controller.AcquisitionPermitGuard) error
	}{
		{name: "revalidate", call: func(guard controller.AcquisitionPermitGuard) error {
			return guard.Revalidate()
		}},
		{name: "admit directly", call: func(guard controller.AcquisitionPermitGuard) error {
			return guard.Admit()
		}},
	}

	for _, mutation := range mutations {
		for _, validation := range validations {
			t.Run(mutation.name+"/"+validation.name, func(t *testing.T) {
				fixture := newCachedPermitFixture(t, LeaseEnabled)
				guard := fixture.acquire(t)
				operationDeadline := <-fixture.clock.started
				mutation.mutate(t, fixture, operationDeadline)
				if err := validation.call(guard); err == nil ||
					!errors.Is(err, ErrLeasePermit) ||
					!errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
					t.Fatalf("validation = %v, want invalid permit authority", err)
				}
				if err := guard.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				<-fixture.clock.returned
			})
		}
	}
}

func TestLeasePermitRejectsReplacementClearAndABA(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *cachedPermitFixture)
	}{
		{
			name: "replacement",
			mutate: func(t *testing.T, fixture *cachedPermitFixture) {
				replacement := testLease(LeaseCanaryOnly)
				fixture.install(
					t,
					replacement,
					5,
					fixture.anchor.Add(time.Second),
					fixture.deadline.Add(time.Second),
				)
			},
		},
		{
			name: "clear",
			mutate: func(t *testing.T, fixture *cachedPermitFixture) {
				var err error
				fixture.revision, err = fixture.cache.CompareAndSwap(fixture.revision, nil)
				if err != nil {
					t.Fatalf("clear: %v", err)
				}
			},
		},
		{
			name: "A-B-A",
			mutate: func(t *testing.T, fixture *cachedPermitFixture) {
				fixture.install(
					t,
					testLease(LeaseCanaryOnly),
					5,
					fixture.anchor.Add(time.Second),
					fixture.deadline.Add(time.Second),
				)
				fixture.install(
					t,
					fixture.lease,
					6,
					fixture.anchor.Add(2*time.Second),
					fixture.deadline.Add(2*time.Second),
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCachedPermitFixture(t, LeaseEnabled)
			guard := fixture.acquire(t)
			<-fixture.clock.started
			test.mutate(t, fixture)
			binding := guard.Binding()
			if err := guard.Revalidate(); err == nil {
				t.Fatal("changed authority revalidated")
			}
			if err := guard.ValidateBinding(context.Background(), binding); err == nil {
				t.Fatal("changed authority validated persisted binding")
			}
			if err := guard.Admit(); err == nil {
				t.Fatal("dropped authority admitted")
			}
			if err := guard.Close(); err != nil {
				t.Fatalf("Close dropped guard: %v", err)
			}
			if got := <-fixture.clock.returned; !errors.Is(got, context.Canceled) {
				t.Fatalf("waiter return = %v, want cancellation", got)
			}
		})
	}
}

func TestLeasePermitOriginalDeadlineCannotExtendAndEqualityDrops(t *testing.T) {
	fixture := newCachedPermitFixture(t, LeaseEnabled)
	guard := fixture.acquire(t)
	originalDeadline := <-fixture.clock.started
	binding := guard.Binding()
	fixture.install(
		t,
		fixture.lease,
		5,
		fixture.anchor.Add(time.Second),
		fixture.deadline.Add(time.Hour),
	)
	fixture.clock.SetNow(originalDeadline)
	if err := guard.Revalidate(); err == nil {
		t.Fatal("exact original deadline revalidated after renewal")
	}
	fixture.clock.SetNow(binding.OriginalLocalDeadline)
	if err := guard.ValidateBinding(context.Background(), binding); err == nil {
		t.Fatal("exact original local lease deadline validated after renewal")
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-fixture.clock.returned
}

func TestLeasePermitBindingValidationPreservesCanceledContextCause(t *testing.T) {
	fixture := newCachedPermitFixture(t, LeaseEnabled)
	guard := fixture.acquire(t)
	<-fixture.clock.started
	binding := guard.Binding()
	ctx, cancel := context.WithCancelCause(context.Background())
	rootCause := errors.New("listener canceled")
	cancel(rootCause)

	if err := guard.ValidateBinding(ctx, binding); err == nil ||
		!errors.Is(err, ErrLeasePermit) ||
		!errors.Is(err, context.Canceled) ||
		!errors.Is(err, rootCause) {
		t.Fatalf("ValidateBinding canceled context = %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-fixture.clock.returned
}

func TestLeasePermitDeadlineAndParentCancellationDropContext(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		fixture := newCachedPermitFixture(t, LeaseEnabled)
		guard := fixture.acquire(t)
		deadline := <-fixture.clock.started
		fixture.clock.SetNow(deadline)
		fixture.clock.release <- context.DeadlineExceeded
		<-guard.Context().Done()
		if err := guard.Admit(); err == nil {
			t.Fatal("deadline-dropped guard admitted")
		}
		if err := guard.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := <-fixture.clock.returned; !errors.Is(got, context.DeadlineExceeded) {
			t.Fatalf("waiter return = %v", got)
		}
	})

	t.Run("parent cancellation", func(t *testing.T) {
		fixture := newCachedPermitFixture(t, LeaseEnabled)
		parent, cancel := context.WithCancel(context.Background())
		guard, err := fixture.provider.Acquire(parent, fixture.request)
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		<-fixture.clock.started
		cancel()
		<-guard.Context().Done()
		if err := guard.Revalidate(); err == nil {
			t.Fatal("parent-canceled guard revalidated")
		}
		if err := guard.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := <-fixture.clock.returned; !errors.Is(got, context.Canceled) {
			t.Fatalf("waiter return = %v", got)
		}
	})
}

func TestLeasePermitSerializesDeadlineHandlerAndAdmission(t *testing.T) {
	t.Run("admission already in critical section wins", func(t *testing.T) {
		fixture := newCachedPermitFixture(t, LeaseEnabled)
		gatedClock := newSecondNowGateClock(fixture.clock)
		fixture.provider.Clock = gatedClock
		guard := fixture.acquire(t)
		<-fixture.clock.started

		admitDone := make(chan error, 1)
		go func() { admitDone <- guard.Admit() }()
		<-gatedClock.entered
		fixture.clock.release <- context.DeadlineExceeded
		<-fixture.clock.returned
		close(gatedClock.release)
		if err := <-admitDone; err != nil {
			t.Fatalf("Admit: %v", err)
		}
		if err := guard.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("deadline handler wins before admission", func(t *testing.T) {
		fixture := newCachedPermitFixture(t, LeaseEnabled)
		guard := fixture.acquire(t)
		<-fixture.clock.started
		fixture.clock.release <- context.DeadlineExceeded
		<-guard.Context().Done()
		if err := guard.Admit(); err == nil {
			t.Fatal("deadline-dropped guard admitted")
		}
		if err := guard.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		<-fixture.clock.returned
	})
}

func TestLeasePermitClockWaitFailureDropsAndJoins(t *testing.T) {
	fixture := newCachedPermitFixture(t, LeaseEnabled)
	guard := fixture.acquire(t)
	<-fixture.clock.started
	waitFailure := errors.New("timerfd failed")
	fixture.clock.release <- waitFailure
	<-guard.Context().Done()
	if err := guard.Admit(); err == nil || !strings.Contains(err.Error(), waitFailure.Error()) {
		t.Fatalf("Admit after wait failure = %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := <-fixture.clock.returned; !errors.Is(got, waitFailure) {
		t.Fatalf("waiter return = %v", got)
	}
}

func TestLeasePermitCloseIsIdempotentAndJoinsWaiter(t *testing.T) {
	fixture := newCachedPermitFixture(t, LeaseEnabled)
	guard := fixture.acquire(t)
	<-fixture.clock.started
	if err := guard.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := <-fixture.clock.returned; !errors.Is(got, context.Canceled) {
		t.Fatalf("waiter return = %v", got)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close second: %v", err)
	}
}

func TestNewCachedLeasePermitProviderRejectsIncompleteConfig(t *testing.T) {
	clock := NewFakeAuthorityClock(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	if _, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Clock:           clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    time.Second,
		TerminationTail: 100 * time.Millisecond,
	}); err == nil {
		t.Fatal("missing cache accepted")
	}
	if _, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           &LeaseCache{},
		Clock:           clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    0,
		TerminationTail: 100 * time.Millisecond,
	}); err == nil {
		t.Fatal("unset call duration accepted")
	}
}
