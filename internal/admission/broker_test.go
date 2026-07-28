package admission

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func resourcesWithAll(value int64) Resources {
	return Resources{
		MilliCPU:          value,
		MemoryBytes:       value,
		PIDs:              value,
		FileDescriptors:   value,
		TmpfsBytes:        value,
		ScratchBytes:      value,
		SocketStateBytes:  value,
		DurableStateBytes: value,
		Inodes:            value,
	}
}

func memoryProfile(bytes int64) SlotResources {
	return SlotResources{Runner: Resources{MemoryBytes: bytes}}
}

func policy(alias string, weight, maxConcurrency uint32, eligibility Eligibility, profile SlotResources) RepositoryPolicy {
	return RepositoryPolicy{
		Alias:          alias,
		Weight:         weight,
		MaxConcurrency: maxConcurrency,
		Eligibility:    eligibility,
		AgingThreshold: time.Hour,
		Profile:        profile,
	}
}

func offer(alias string, requestID int64, queued time.Time) githubscale.Offer {
	return githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: requestID,
		JobID:           fmt.Sprintf("fixture-job-%d", requestID),
		RepositoryName:  alias,
		OwnerName:       "owner",
		QueueTime:       queued,
	}}
}

func offerKey(candidate githubscale.Offer) controller.AssignmentKey {
	return controller.AssignmentKey{
		RepositoryAlias: candidate.RepositoryName,
		RunnerRequestID: candidate.RunnerRequestID,
		Attempt:         0,
	}
}

func mustOfferLogicalBytes(t *testing.T, candidate githubscale.Offer) uint64 {
	t.Helper()
	size, err := LiveOfferLogicalBytesV1(candidate)
	if err != nil {
		t.Fatalf("LiveOfferLogicalBytesV1: %v", err)
	}
	return size
}

func testConfig(clock *fakeClock, capacity int, ceiling Resources, policies ...RepositoryPolicy) Config {
	return Config{
		Ceiling:                  ceiling,
		MaxCapacity:              capacity,
		MaxLiveReferences:        64,
		MaxOfferLogicalBytes:     1 << 20,
		MaxLiveOfferLogicalBytes: 64 << 20,
		PollLeaseTTL:             30 * time.Second,
		LedgerTail:               10 * time.Minute,
		TransientMode:            TransientSerialized,
		PolicyRevision:           1,
		Repositories:             policies,
		Now:                      clock.Now,
	}
}

func mustBroker(t *testing.T, config Config) PolicyBroker {
	t.Helper()
	broker, err := NewBroker(config)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return broker
}

func implementation(t *testing.T, broker PolicyBroker) *brokerImpl {
	t.Helper()
	impl, ok := broker.(*brokerImpl)
	if !ok {
		t.Fatalf("broker implementation = %T, want *brokerImpl", broker)
	}
	return impl
}

func enqueueAll(t *testing.T, broker Broker, offers ...githubscale.Offer) {
	t.Helper()
	for _, candidate := range offers {
		if err := broker.Enqueue(candidate); err != nil {
			t.Fatalf("Enqueue(%s/%d): %v", candidate.RepositoryName, candidate.RunnerRequestID, err)
		}
	}
}

func decisionAliases(decisions []Decision) []string {
	aliases := make([]string, len(decisions))
	for i := range decisions {
		aliases[i] = decisions[i].Assignment.RepositoryAlias
	}
	return aliases
}

func decisionRequestIDs(decisions []Decision) []int64 {
	ids := make([]int64, len(decisions))
	for i := range decisions {
		ids[i] = decisions[i].Assignment.RunnerRequestID
	}
	return ids
}

func assertResourcesAtMost(t *testing.T, got, ceiling Resources) {
	t.Helper()
	checks := []struct {
		name string
		got  int64
		max  int64
	}{
		{"MilliCPU", got.MilliCPU, ceiling.MilliCPU},
		{"MemoryBytes", got.MemoryBytes, ceiling.MemoryBytes},
		{"PIDs", got.PIDs, ceiling.PIDs},
		{"FileDescriptors", got.FileDescriptors, ceiling.FileDescriptors},
		{"TmpfsBytes", got.TmpfsBytes, ceiling.TmpfsBytes},
		{"ScratchBytes", got.ScratchBytes, ceiling.ScratchBytes},
		{"SocketStateBytes", got.SocketStateBytes, ceiling.SocketStateBytes},
		{"DurableStateBytes", got.DurableStateBytes, ceiling.DurableStateBytes},
		{"Inodes", got.Inodes, ceiling.Inodes},
	}
	for _, check := range checks {
		if check.got < 0 || check.got > check.max {
			t.Errorf("%s usage = %d, want 0 <= usage <= %d", check.name, check.got, check.max)
		}
	}
}

func TestBrokerResourceCeilingEveryDimension(t *testing.T) {
	dimensions := []struct {
		name string
		set  func(*Resources, int64)
	}{
		{"cpu", func(r *Resources, v int64) { r.MilliCPU = v }},
		{"memory", func(r *Resources, v int64) { r.MemoryBytes = v }},
		{"pids", func(r *Resources, v int64) { r.PIDs = v }},
		{"file descriptors", func(r *Resources, v int64) { r.FileDescriptors = v }},
		{"tmpfs", func(r *Resources, v int64) { r.TmpfsBytes = v }},
		{"scratch", func(r *Resources, v int64) { r.ScratchBytes = v }},
		{"socket state", func(r *Resources, v int64) { r.SocketStateBytes = v }},
		{"durable state", func(r *Resources, v int64) { r.DurableStateBytes = v }},
		{"inodes", func(r *Resources, v int64) { r.Inodes = v }},
	}

	for _, dimension := range dimensions {
		t.Run(dimension.name, func(t *testing.T) {
			clock := newFakeClock()
			ceiling := resourcesWithAll(1_000)
			dimension.set(&ceiling, 10)
			runner := Resources{}
			dimension.set(&runner, 6)
			profile := SlotResources{Runner: runner}
			broker := mustBroker(t, testConfig(
				clock,
				2,
				ceiling,
				policy("repo-a", 1, 2, EligibilityActive, profile),
			))
			enqueueAll(t, broker,
				offer("repo-a", 1, clock.Now()),
				offer("repo-a", 2, clock.Now()),
			)

			decisions, err := broker.Admit(clock.Now())
			if err != nil {
				t.Fatalf("Admit: %v", err)
			}
			if len(decisions) != 1 {
				t.Fatalf("Admit decisions = %d, want 1 because the second complete slot exceeds %s", len(decisions), dimension.name)
			}
			impl := implementation(t, broker)
			impl.mu.Lock()
			used := impl.used
			impl.mu.Unlock()
			assertResourcesAtMost(t, used, ceiling)
		})
	}
}

func TestBrokerCompleteSlotChargeIncludesEveryComponent(t *testing.T) {
	clock := newFakeClock()
	profile := SlotResources{
		Runner:        Resources{MemoryBytes: 1},
		Adapter:       Resources{MemoryBytes: 2},
		Broker:        Resources{MemoryBytes: 3},
		DialAuthority: Resources{MemoryBytes: 4},
		Helper:        Resources{MemoryBytes: 5},
		Verifier:      Resources{MemoryBytes: 7},
	}
	// Serialized transient work charges max(helper, verifier), so one slot
	// costs 1+2+3+4+7 = 17 bytes in this synthetic one-dimensional case.
	broker := mustBroker(t, testConfig(
		clock,
		2,
		Resources{MemoryBytes: 17},
		policy("repo-a", 1, 2, EligibilityActive, profile),
	))
	enqueueAll(t, broker,
		offer("repo-a", 1, clock.Now()),
		offer("repo-a", 2, clock.Now()),
	)
	decisions, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("Admit decisions = %d, want 1 at the exact complete-slot ceiling", len(decisions))
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	got := impl.used.MemoryBytes
	impl.mu.Unlock()
	if got != 17 {
		t.Fatalf("used MemoryBytes = %d, want exact complete-slot charge 17", got)
	}
}

func TestBrokerSerializedVersusConcurrentTransientCharge(t *testing.T) {
	profile := SlotResources{
		Helper:   Resources{MemoryBytes: 6},
		Verifier: Resources{MemoryBytes: 7},
	}

	t.Run("serialized charges max peak", func(t *testing.T) {
		clock := newFakeClock()
		config := testConfig(clock, 1, Resources{MemoryBytes: 7},
			policy("repo-a", 1, 1, EligibilityActive, profile))
		config.TransientMode = TransientSerialized
		broker := mustBroker(t, config)
		enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
		decisions, err := broker.Admit(clock.Now())
		if err != nil || len(decisions) != 1 {
			t.Fatalf("serialized Admit = (%d, %v), want one decision", len(decisions), err)
		}
	})

	t.Run("concurrent rejects max-only ceiling", func(t *testing.T) {
		clock := newFakeClock()
		config := testConfig(clock, 1, Resources{MemoryBytes: 7},
			policy("repo-a", 1, 1, EligibilityActive, profile))
		config.TransientMode = TransientConcurrent
		broker := mustBroker(t, config)
		enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
		decisions, err := broker.Admit(clock.Now())
		if err != nil {
			t.Fatalf("Admit: %v", err)
		}
		if len(decisions) != 0 {
			t.Fatalf("concurrent Admit decisions = %d, want 0 when helper+verifier were not both charged", len(decisions))
		}
	})

	t.Run("concurrent accepts sum ceiling", func(t *testing.T) {
		clock := newFakeClock()
		config := testConfig(clock, 1, Resources{MemoryBytes: 13},
			policy("repo-a", 1, 1, EligibilityActive, profile))
		config.TransientMode = TransientConcurrent
		broker := mustBroker(t, config)
		enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
		decisions, err := broker.Admit(clock.Now())
		if err != nil || len(decisions) != 1 {
			t.Fatalf("concurrent Admit = (%d, %v), want one fully charged decision", len(decisions), err)
		}
	})
}

func TestBrokerWeightedDeficitSequenceAndFIFO(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		3,
		Resources{MemoryBytes: 3},
		policy("repo-a", 2, 3, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 3, EligibilityActive, memoryProfile(1)),
	))
	enqueueAll(t, broker,
		offer("repo-a", 20, clock.Now()),
		offer("repo-b", 30, clock.Now()),
		offer("repo-a", 10, clock.Now()),
	)

	decisions, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got, want := decisionAliases(decisions), []string{"repo-a", "repo-a", "repo-b"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("weighted aliases = %v, want %v", got, want)
	}
	if got, want := decisionRequestIDs(decisions), []int64{20, 10, 30}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("FIFO request IDs = %v, want arrival order %v", got, want)
	}
}

func TestBrokerAgingOverridesWeightWithStableTieBreak(t *testing.T) {
	t.Run("old low-volume repository wins", func(t *testing.T) {
		clock := newFakeClock()
		broker := mustBroker(t, testConfig(
			clock,
			1,
			Resources{MemoryBytes: 1},
			policy("repo-a", 10, 1, EligibilityActive, memoryProfile(1)),
			policy("repo-b", 1, 1, EligibilityActive, memoryProfile(1)),
		))
		enqueueAll(t, broker,
			offer("repo-a", 1, clock.Now()),
			offer("repo-b", 2, clock.Now().Add(-2*time.Hour)),
		)
		decisions, err := broker.Admit(clock.Now())
		if err != nil {
			t.Fatalf("Admit: %v", err)
		}
		if got := decisionAliases(decisions); len(got) != 1 || got[0] != "repo-b" {
			t.Fatalf("aged selection = %v, want [repo-b]", got)
		}
	})

	t.Run("equal-age tie uses alias", func(t *testing.T) {
		clock := newFakeClock()
		old := clock.Now().Add(-2 * time.Hour)
		broker := mustBroker(t, testConfig(
			clock,
			1,
			Resources{MemoryBytes: 1},
			policy("repo-b", 1, 1, EligibilityActive, memoryProfile(1)),
			policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
		))
		enqueueAll(t, broker,
			offer("repo-b", 1, old),
			offer("repo-a", 2, old),
		)
		decisions, err := broker.Admit(clock.Now())
		if err != nil {
			t.Fatalf("Admit: %v", err)
		}
		if got := decisionAliases(decisions); len(got) != 1 || got[0] != "repo-a" {
			t.Fatalf("aged tie selection = %v, want stable alias [repo-a]", got)
		}
	})
}

func TestBrokerSkipsNonFittingHeadWithoutCrossRepositoryStarvation(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		2,
		Resources{MemoryBytes: 10},
		policy("repo-a", 100, 2, EligibilityActive, memoryProfile(11)),
		policy("repo-b", 1, 2, EligibilityActive, memoryProfile(5)),
	))
	enqueueAll(t, broker,
		offer("repo-a", 1, clock.Now().Add(-2*time.Hour)),
		offer("repo-b", 2, clock.Now()),
	)
	decisions, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got := decisionAliases(decisions); len(got) != 1 || got[0] != "repo-b" {
		t.Fatalf("non-fitting head selection = %v, want fitting [repo-b]", got)
	}
}

func TestBrokerRepositoryMaxConcurrencySkipsAndReleases(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		3,
		Resources{MemoryBytes: 3},
		policy("repo-a", 10, 1, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 2, EligibilityActive, memoryProfile(1)),
	))
	enqueueAll(t, broker,
		offer("repo-a", 1, clock.Now()),
		offer("repo-a", 2, clock.Now()),
		offer("repo-b", 3, clock.Now()),
	)
	first, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got, want := decisionAliases(first), []string{"repo-a", "repo-b"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("first aliases = %v, want cap-skipping %v", got, want)
	}
	var repoAKey controller.AssignmentKey
	for _, decision := range first {
		if decision.Assignment.RepositoryAlias == "repo-a" {
			repoAKey = decision.Assignment
		}
	}
	if err := broker.Release(repoAKey); err != nil {
		t.Fatalf("Release(repo-a): %v", err)
	}
	second, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("second Admit: %v", err)
	}
	if got := decisionRequestIDs(second); len(got) != 1 || got[0] != 2 {
		t.Fatalf("second decisions = %v, want released repo-a request [2]", got)
	}
}

func TestBrokerRepositoryCapCountsPollReservations(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		3,
		Resources{MemoryBytes: 3},
		policy("repo-a", 10, 1, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 3, EligibilityActive, memoryProfile(1)),
	))
	first, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll(repo-a): %v", err)
	}
	second, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll(repo-a #2): %v", err)
	}
	other, err := broker.LeasePoll("repo-b", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll(repo-b): %v", err)
	}
	if first.Reserved != 1 || second.Reserved != 0 || other.Reserved != 2 {
		t.Fatalf("reserved counts = repo-a %d then %d, repo-b %d; want 1,0,2", first.Reserved, second.Reserved, other.Reserved)
	}
}

func TestBrokerEligibilityBlocksLeaseAndAdmission(t *testing.T) {
	for _, eligibility := range []Eligibility{EligibilityArchivedDisabled, EligibilityPendingReactivation} {
		t.Run(string(eligibility), func(t *testing.T) {
			clock := newFakeClock()
			broker := mustBroker(t, testConfig(
				clock,
				2,
				Resources{MemoryBytes: 2},
				policy("repo-a", math.MaxUint32, math.MaxUint32, eligibility, memoryProfile(1)),
			))
			lease, err := broker.LeasePoll("repo-a", clock.Now())
			if err != nil {
				t.Fatalf("LeasePoll: %v", err)
			}
			if lease.Reserved != 0 || lease.MaxCapacity != 0 {
				t.Fatalf("inactive lease = %+v, want zero effective capacity", lease)
			}
			enqueueAll(t, broker, offer("repo-a", 1, clock.Now().Add(-24*time.Hour)))
			decisions, err := broker.Admit(clock.Now())
			if err != nil {
				t.Fatalf("Admit: %v", err)
			}
			if len(decisions) != 0 {
				t.Fatalf("inactive decisions = %d, want 0", len(decisions))
			}
		})
	}
}

func TestBrokerEligibilityRevisionDrainsAndDoesNotSelfClear(t *testing.T) {
	clock := newFakeClock()
	initial := []RepositoryPolicy{
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
	}
	broker := mustBroker(t, testConfig(clock, 2, Resources{MemoryBytes: 2}, initial...))
	enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
	admitted, err := broker.Admit(clock.Now())
	if err != nil || len(admitted) != 1 {
		t.Fatalf("initial Admit = (%d, %v), want 1", len(admitted), err)
	}

	disabled := []RepositoryPolicy{
		policy("repo-a", 1, 2, EligibilityArchivedDisabled, memoryProfile(1)),
	}
	if err := broker.ApplyPolicyRevision(PolicyRevision{Epoch: 2, Repositories: disabled}); err != nil {
		t.Fatalf("ApplyPolicyRevision(disabled): %v", err)
	}
	// Mutating caller-owned policy memory is a bare live signal, not an
	// epoch-barrier update; the broker must have copied the revision.
	disabled[0].Eligibility = EligibilityActive
	enqueueAll(t, broker, offer("repo-a", 2, clock.Now()))
	if decisions, err := broker.Admit(clock.Now()); err != nil || len(decisions) != 0 {
		t.Fatalf("disabled Admit = (%d, %v), want 0", len(decisions), err)
	}
	if lease, err := broker.LeasePoll("repo-a", clock.Now()); err != nil || lease.Reserved != 0 {
		t.Fatalf("disabled LeasePoll = (%+v, %v), want zero", lease, err)
	}

	// Already-admitted work drains normally; disabling does not cancel it.
	if err := broker.Release(admitted[0].Assignment); err != nil {
		t.Fatalf("Release admitted slot after disable: %v", err)
	}
	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:        2,
		Repositories: []RepositoryPolicy{policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1))},
	}); !errors.Is(err, ErrStalePolicyRevision) {
		t.Fatalf("same-epoch reactivation err = %v, want ErrStalePolicyRevision", err)
	}
	if decisions, err := broker.Admit(clock.Now()); err != nil || len(decisions) != 0 {
		t.Fatalf("same-epoch Admit = (%d, %v), want latch still closed", len(decisions), err)
	}

	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:        3,
		Repositories: []RepositoryPolicy{policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1))},
	}); err != nil {
		t.Fatalf("ApplyPolicyRevision(active): %v", err)
	}
	reactivated, err := broker.Admit(clock.Now())
	if err != nil || len(reactivated) != 1 || reactivated[0].Assignment.RunnerRequestID != 2 {
		t.Fatalf("reactivated Admit = (%+v, %v), want queued request 2", reactivated, err)
	}
}

func TestBrokerPolicyRemovalCannotOrphanQueuedLiveReference(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	live := broker.(LiveHistory)
	key := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 7, Attempt: 0}
	if err := live.EnsureQueued(offer("repo-a", 7, clock.Now())); err != nil {
		t.Fatalf("EnsureQueued: %v", err)
	}
	removeA := PolicyRevision{
		Epoch:        2,
		Repositories: []RepositoryPolicy{policy("repo-b", 1, 1, EligibilityActive, memoryProfile(1))},
	}
	if err := broker.ApplyPolicyRevision(removeA); !errors.Is(err, ErrPolicyInUse) {
		t.Fatalf("ApplyPolicyRevision(remove queued repo) err = %v, want ErrPolicyInUse", err)
	}
	if !live.HasLiveReference(key) {
		t.Fatal("rejected policy removal mutated the queued live reference")
	}
	if err := live.Retire(key); err != nil {
		t.Fatalf("Retire queued reference: %v", err)
	}
	if err := broker.ApplyPolicyRevision(removeA); err != nil {
		t.Fatalf("ApplyPolicyRevision after Retire: %v", err)
	}
}

func TestBrokerPressureOnlyLowersAndReportsExactCapacity(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		3,
		Resources{MemoryBytes: 3},
		policy("repo-a", 1, 3, EligibilityActive, memoryProfile(1)),
	))
	change, err := broker.SetPressure(Pressure{MaxCapacity: 2})
	if err != nil {
		t.Fatalf("SetPressure(2): %v", err)
	}
	if change != (CapacityChange{Previous: 3, Current: 2}) {
		t.Fatalf("SetPressure change = %+v, want {Previous:3 Current:2}", change)
	}
	if _, err := broker.SetPressure(Pressure{MaxCapacity: 3}); !errors.Is(err, ErrPressureIncrease) {
		t.Fatalf("SetPressure increase err = %v, want ErrPressureIncrease", err)
	}
	same, err := broker.SetPressure(Pressure{MaxCapacity: 2})
	if err != nil || same != (CapacityChange{Previous: 2, Current: 2}) {
		t.Fatalf("SetPressure same = (%+v, %v), want {2 2}", same, err)
	}

	enqueueAll(t, broker,
		offer("repo-a", 1, clock.Now()),
		offer("repo-a", 2, clock.Now()),
		offer("repo-a", 3, clock.Now()),
	)
	decisions, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("pressure-limited decisions = %d, want 2", len(decisions))
	}
}

func TestBrokerConcurrentPollLeasesCannotOverAdvertise(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		4,
		Resources{MemoryBytes: 4},
		policy("repo-a", 1, 4, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 4, EligibilityActive, memoryProfile(1)),
	))

	start := make(chan struct{})
	results := make(chan CapacityLease, 2)
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for _, alias := range []string{"repo-a", "repo-b"} {
		wait.Add(1)
		go func(repo string) {
			defer wait.Done()
			<-start
			lease, err := broker.LeasePoll(repo, clock.Now())
			results <- lease
			errs <- err
		}(alias)
	}
	close(start)
	wait.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("LeasePoll: %v", err)
		}
	}
	total := 0
	for lease := range results {
		total += lease.Reserved
	}
	if total > 4 {
		t.Fatalf("concurrent reserved capacity = %d, want <= 4", total)
	}
	if total != 4 {
		t.Fatalf("concurrent reserved capacity = %d, want exact available capacity 4", total)
	}
}

func TestBrokerPollLeaseTransfersWithoutDoubleChargeAndExpiresUnused(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 2, EligibilityActive, memoryProfile(1)),
	))
	lease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll(repo-a): %v", err)
	}
	if lease.Reserved != 2 || lease.MaxCapacity != 2 || lease.Epoch != 1 {
		t.Fatalf("repo-a lease = %+v, want Reserved=2 MaxCapacity=2 Epoch=1", lease)
	}
	enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
	decisions, err := broker.Admit(clock.Now())
	if err != nil || len(decisions) != 1 {
		t.Fatalf("Admit = (%d, %v), want one transferred reservation", len(decisions), err)
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	usedBeforeExpiry := impl.used.MemoryBytes
	impl.mu.Unlock()
	if usedBeforeExpiry != 2 {
		t.Fatalf("used MemoryBytes = %d, want two charged slots (one active, one leased)", usedBeforeExpiry)
	}

	clock.Advance(31 * time.Second)
	other, err := broker.LeasePoll("repo-b", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll(repo-b): %v", err)
	}
	if other.Reserved != 1 {
		t.Fatalf("repo-b reserved after unused lease expiry = %d, want 1", other.Reserved)
	}
}

func TestBrokerOfferConsumesOldestOverlappingPollLease(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
	))

	firstLease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || firstLease.Reserved != 2 {
		t.Fatalf("first LeasePoll = (%+v, %v), want two reservations", firstLease, err)
	}
	enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
	first, err := broker.Admit(clock.Now())
	if err != nil || len(first) != 1 || first[0].SlotID != 1 {
		t.Fatalf("first Admit = (%+v, %v), want slot 1", first, err)
	}
	if err := broker.Release(first[0].Assignment); err != nil {
		t.Fatalf("Release first assignment: %v", err)
	}

	// Slot 2 still belongs to the older lease. Reusing free slot 1 creates a
	// newer overlapping lease whose smaller slot ID must not win.
	clock.Advance(time.Second)
	secondLease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || secondLease.Reserved != 1 || secondLease.ID <= firstLease.ID {
		t.Fatalf("second LeasePoll = (%+v, %v), want one newer reservation", secondLease, err)
	}
	enqueueAll(t, broker, offer("repo-a", 2, clock.Now()))
	second, err := broker.Admit(clock.Now())
	if err != nil || len(second) != 1 {
		t.Fatalf("second Admit = (%+v, %v), want one decision", second, err)
	}
	if second[0].SlotID != 2 {
		t.Fatalf("second Admit slot = %d, want slot 2 from oldest lease %d", second[0].SlotID, firstLease.ID)
	}
}

func TestBrokerStableSlotLedgerSurvivesReleaseAndReuse(t *testing.T) {
	clock := newFakeClock()
	profile := SlotResources{
		Runner: Resources{MemoryBytes: 1},
		DialAuthority: Resources{
			SocketStateBytes:  2,
			DurableStateBytes: 3,
			Inodes:            1,
		},
	}
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1, SocketStateBytes: 2, DurableStateBytes: 3, Inodes: 1},
		policy("repo-a", 1, 1, EligibilityActive, profile),
	))
	enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
	first, err := broker.Admit(clock.Now())
	if err != nil || len(first) != 1 {
		t.Fatalf("first Admit = (%d, %v), want 1", len(first), err)
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	born := impl.slots[first[0].SlotID].ledgerCreatedAt
	impl.mu.Unlock()

	if err := broker.Release(first[0].Assignment); err != nil {
		t.Fatalf("Release: %v", err)
	}
	impl.mu.Lock()
	tailUsage := impl.used
	impl.mu.Unlock()
	if tailUsage.MemoryBytes != 0 || tailUsage.SocketStateBytes != 2 || tailUsage.DurableStateBytes != 3 || tailUsage.Inodes != 1 {
		t.Fatalf("tail usage after Release = %+v, want only socket/durable/inode ledger charge", tailUsage)
	}

	clock.Advance(time.Minute)
	enqueueAll(t, broker, offer("repo-a", 2, clock.Now()))
	second, err := broker.Admit(clock.Now())
	if err != nil || len(second) != 1 {
		t.Fatalf("second Admit = (%d, %v), want 1", len(second), err)
	}
	if second[0].SlotID != first[0].SlotID {
		t.Fatalf("reused SlotID = %d, want stable %d", second[0].SlotID, first[0].SlotID)
	}
	impl.mu.Lock()
	reusedBorn := impl.slots[second[0].SlotID].ledgerCreatedAt
	reusedUsage := impl.used
	impl.mu.Unlock()
	if !reusedBorn.Equal(born) {
		t.Fatalf("ledgerCreatedAt changed on reuse: %s -> %s", born, reusedBorn)
	}
	if reusedUsage.SocketStateBytes != 2 || reusedUsage.DurableStateBytes != 3 || reusedUsage.Inodes != 1 {
		t.Fatalf("ledger charge doubled on reuse: %+v", reusedUsage)
	}
}

func TestBrokerStableSlotReuseNeverShrinksRetainedLedgerCharge(t *testing.T) {
	clock := newFakeClock()
	largeLedger := SlotResources{
		Runner:        Resources{MemoryBytes: 1},
		DialAuthority: Resources{SocketStateBytes: 7, DurableStateBytes: 11, Inodes: 5},
	}
	smallLedger := SlotResources{
		Runner:        Resources{MemoryBytes: 1},
		DialAuthority: Resources{SocketStateBytes: 1, DurableStateBytes: 2, Inodes: 1},
	}
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1, SocketStateBytes: 7, DurableStateBytes: 11, Inodes: 5},
		policy("repo-a", 1, 1, EligibilityActive, largeLedger),
	))

	enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
	first, err := broker.Admit(clock.Now())
	if err != nil || len(first) != 1 {
		t.Fatalf("first Admit = (%d, %v), want 1", len(first), err)
	}
	if err := broker.Release(first[0].Assignment); err != nil {
		t.Fatalf("Release first assignment: %v", err)
	}
	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:        2,
		Repositories: []RepositoryPolicy{policy("repo-a", 1, 1, EligibilityActive, smallLedger)},
	}); err != nil {
		t.Fatalf("ApplyPolicyRevision(smaller ledger): %v", err)
	}

	enqueueAll(t, broker, offer("repo-a", 2, clock.Now()))
	second, err := broker.Admit(clock.Now())
	if err != nil || len(second) != 1 {
		t.Fatalf("second Admit = (%d, %v), want 1", len(second), err)
	}
	if second[0].SlotID != first[0].SlotID {
		t.Fatalf("reused SlotID = %d, want stable %d", second[0].SlotID, first[0].SlotID)
	}

	impl := implementation(t, broker)
	impl.mu.Lock()
	slot := impl.slots[second[0].SlotID]
	used := impl.used
	impl.mu.Unlock()
	if slot.ledgerCharge.SocketStateBytes != 7 ||
		slot.ledgerCharge.DurableStateBytes != 11 ||
		slot.ledgerCharge.Inodes != 5 {
		t.Fatalf("retained ledger charge shrank on reuse: %+v", slot.ledgerCharge)
	}
	if used.SocketStateBytes != 7 || used.DurableStateBytes != 11 || used.Inodes != 5 {
		t.Fatalf("resource accounting shrank retained ledger on reuse: %+v", used)
	}
}

func TestBrokerPressureRetiresSlotButRetainsLedgerUntilTail(t *testing.T) {
	clock := newFakeClock()
	profile := SlotResources{
		Runner:        Resources{MemoryBytes: 1},
		DialAuthority: Resources{DurableStateBytes: 1, Inodes: 1},
	}
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2, DurableStateBytes: 2, Inodes: 2},
		policy("repo-a", 1, 2, EligibilityActive, profile),
	)
	config.LedgerTail = time.Hour
	broker := mustBroker(t, config)
	enqueueAll(t, broker, offer("repo-a", 1, clock.Now()), offer("repo-a", 2, clock.Now()))
	decisions, err := broker.Admit(clock.Now())
	if err != nil || len(decisions) != 2 {
		t.Fatalf("Admit = (%d, %v), want 2", len(decisions), err)
	}
	if _, err := broker.SetPressure(Pressure{MaxCapacity: 1}); err != nil {
		t.Fatalf("SetPressure: %v", err)
	}

	impl := implementation(t, broker)
	impl.mu.Lock()
	var retiring CapacitySlotID
	for id, slot := range impl.slots {
		if slot.retireOnRelease {
			retiring = id
			break
		}
	}
	impl.mu.Unlock()
	if retiring == 0 {
		t.Fatal("SetPressure did not mark an active excess slot for retirement")
	}
	var retiringKey controller.AssignmentKey
	for _, decision := range decisions {
		if decision.SlotID == retiring {
			retiringKey = decision.Assignment
		}
	}
	if err := broker.Release(retiringKey); err != nil {
		t.Fatalf("Release retiring slot: %v", err)
	}
	impl.mu.Lock()
	slot := impl.slots[retiring]
	retained := impl.used.DurableStateBytes
	impl.mu.Unlock()
	if slot == nil || !slot.retired || retained < 1 {
		t.Fatalf("retired slot = %+v, retained durable bytes = %d; want retained ledger", slot, retained)
	}

	clock.Advance(59 * time.Minute)
	if _, err := broker.Admit(clock.Now()); err != nil {
		t.Fatalf("Admit before tail: %v", err)
	}
	impl.mu.Lock()
	_, existsBefore := impl.slots[retiring]
	impl.mu.Unlock()
	if !existsBefore {
		t.Fatal("retired ledger was collected before tail T")
	}

	clock.Advance(2 * time.Minute)
	if _, err := broker.Admit(clock.Now()); err != nil {
		t.Fatalf("Admit after tail: %v", err)
	}
	impl.mu.Lock()
	_, existsAfter := impl.slots[retiring]
	impl.mu.Unlock()
	if existsAfter {
		t.Fatal("retired ledger was not guarded-GC eligible after tail T")
	}
}

func TestBrokerRejectsUnknownRepositoryAndDuplicateOffer(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	if err := broker.Enqueue(offer("repo-unknown", 1, clock.Now())); !errors.Is(err, ErrUnknownRepository) {
		t.Fatalf("unknown Enqueue err = %v, want ErrUnknownRepository", err)
	}
	candidate := offer("repo-a", 1, clock.Now())
	if err := broker.Enqueue(candidate); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := broker.Enqueue(candidate); !errors.Is(err, ErrDuplicateOffer) {
		t.Fatalf("duplicate Enqueue err = %v, want ErrDuplicateOffer", err)
	}
}

func TestBrokerEnsureQueuedIsIdempotentForEqualLiveOffer(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 1
	broker := mustBroker(t, config)
	live, ok := broker.(LiveHistory)
	if !ok {
		t.Fatalf("broker = %T, want LiveHistory", broker)
	}
	candidate := offer("repo-a", 41, clock.Now())
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued(first): %v", err)
	}
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued(equal replay): %v", err)
	}

	decisions, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if len(decisions) != 1 || decisions[0].Assignment.RunnerRequestID != 41 {
		t.Fatalf("Admit decisions = %+v, want exactly request 41", decisions)
	}
}

func TestBrokerEnsureQueuedRejectsConflictingSchedulingProjection(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	live := broker.(LiveHistory)
	candidate := offer("repo-a", 42, clock.Now())
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued(first): %v", err)
	}
	conflict := candidate
	conflict.QueueTime = conflict.QueueTime.Add(time.Second)
	if err := live.EnsureQueued(conflict); !errors.Is(err, ErrOfferConflict) {
		t.Fatalf("EnsureQueued(conflict) err = %v, want ErrOfferConflict", err)
	}
}

func TestBrokerRetireQueuedOfferRemovesLiveReferenceIdempotently(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	live := broker.(LiveHistory)
	candidate := offer("repo-a", 43, clock.Now())
	key := controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 43,
		Attempt:         0,
	}
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued: %v", err)
	}
	if !live.HasLiveReference(key) {
		t.Fatal("HasLiveReference = false before Retire, want true")
	}
	if err := live.Retire(key); err != nil {
		t.Fatalf("Retire(first): %v", err)
	}
	if err := live.Retire(key); err != nil {
		t.Fatalf("Retire(replay): %v", err)
	}
	if live.HasLiveReference(key) {
		t.Fatal("HasLiveReference = true after Retire, want false")
	}
	if decisions, err := broker.Admit(clock.Now()); err != nil || len(decisions) != 0 {
		t.Fatalf("Admit after Retire = (%+v, %v), want no decision", decisions, err)
	}
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued after durable caller reclassified retired identity: %v", err)
	}
	if !live.HasLiveReference(key) {
		t.Fatal("EnsureQueued after Retire did not recreate the live reference")
	}
}

func TestBrokerRetireRejectsActiveUntilCapacityRelease(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	live := broker.(LiveHistory)
	if err := live.EnsureQueued(offer("repo-a", 44, clock.Now())); err != nil {
		t.Fatalf("EnsureQueued: %v", err)
	}
	decisions, err := broker.Admit(clock.Now())
	if err != nil || len(decisions) != 1 {
		t.Fatalf("Admit = (%+v, %v), want one decision", decisions, err)
	}
	key := decisions[0].Assignment
	if err := live.Retire(key); !errors.Is(err, ErrLiveReferenceActive) {
		t.Fatalf("Retire(active) err = %v, want ErrLiveReferenceActive", err)
	}
	if !live.HasLiveReference(key) {
		t.Fatal("active Retire removed the live reference")
	}
	if err := broker.Release(key); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := live.Retire(key); err != nil {
		t.Fatalf("Retire(released): %v", err)
	}
	if live.HasLiveReference(key) {
		t.Fatal("released Retire left a live reference")
	}
}

func TestBrokerRetireQueuedOfferReturnsItsPollReservation(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	firstLease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || firstLease.Reserved != 1 {
		t.Fatalf("first LeasePoll = (%+v, %v), want one reservation", firstLease, err)
	}
	live := broker.(LiveHistory)
	candidate := offer("repo-a", 45, clock.Now())
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued: %v", err)
	}
	key := controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 45,
		Attempt:         0,
	}
	if err := live.Retire(key); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	replacement, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil {
		t.Fatalf("replacement LeasePoll: %v", err)
	}
	if replacement.Reserved != 1 {
		t.Fatalf("replacement LeasePoll reserved = %d, want returned capacity 1", replacement.Reserved)
	}
}

func TestBrokerLiveReferenceLimitRejectsNewIdentityUntilRetire(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	broker := mustBroker(t, config)
	live := broker.(LiveHistory)
	first := offer("repo-a", 46, clock.Now())
	second := offer("repo-a", 47, clock.Now())
	third := offer("repo-a", 48, clock.Now())
	if err := live.EnsureQueued(first); err != nil {
		t.Fatalf("EnsureQueued(first): %v", err)
	}
	if err := live.EnsureQueued(second); err != nil {
		t.Fatalf("EnsureQueued(second): %v", err)
	}
	if err := live.EnsureQueued(third); !errors.Is(err, ErrLiveSetFull) {
		t.Fatalf("EnsureQueued(over limit) err = %v, want ErrLiveSetFull", err)
	}
	if err := live.Retire(controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 46,
		Attempt:         0,
	}); err != nil {
		t.Fatalf("Retire(first): %v", err)
	}
	if err := live.EnsureQueued(third); err != nil {
		t.Fatalf("EnsureQueued(after Retire): %v", err)
	}
}

func TestBrokerLiveHistoryRemainsBoundedAcrossManyRetiredIdentities(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	broker := mustBroker(t, config)
	live := broker.(LiveHistory)
	const cycles = 512
	for requestID := int64(1); requestID <= cycles; requestID++ {
		candidate := offer("repo-a", requestID, clock.Now())
		if err := live.EnsureQueued(candidate); err != nil {
			t.Fatalf("cycle %d EnsureQueued: %v", requestID, err)
		}
		if err := live.EnsureQueued(candidate); err != nil {
			t.Fatalf("cycle %d equal replay: %v", requestID, err)
		}
		decisions, err := broker.Admit(clock.Now())
		if err != nil || len(decisions) != 1 {
			t.Fatalf("cycle %d Admit = (%+v, %v), want one", requestID, decisions, err)
		}
		key := decisions[0].Assignment
		if err := broker.Release(key); err != nil {
			t.Fatalf("cycle %d Release: %v", requestID, err)
		}
		if err := live.Retire(key); err != nil {
			t.Fatalf("cycle %d Retire: %v", requestID, err)
		}
		if live.HasLiveReference(key) {
			t.Fatalf("cycle %d retained a retired live reference", requestID)
		}
		clock.Advance(time.Second)
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	liveCount := len(impl.liveOffers)
	liveBytes := impl.liveOfferLogicalBytes
	queueCount := len(impl.queues["repo-a"])
	slotCount := len(impl.slots)
	impl.mu.Unlock()
	if liveCount != 0 || liveBytes != 0 || queueCount != 0 {
		t.Fatalf("post-soak live=%d bytes=%d queued=%d, want all zero", liveCount, liveBytes, queueCount)
	}
	if slotCount > 1 {
		t.Fatalf("post-soak stable slots = %d, want bounded by configured capacity 1", slotCount)
	}
}

func TestBrokerPollLeaseNeverAdvertisesPastLiveReferenceHeadroom(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 1
	broker := mustBroker(t, config)
	live := broker.(LiveHistory)
	candidate := offer("repo-a", 49, clock.Now())
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued: %v", err)
	}
	full, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll(full): %v", err)
	}
	if full.Reserved != 0 {
		t.Fatalf("LeasePoll at live limit reserved = %d, want 0", full.Reserved)
	}
	if err := live.Retire(controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 49,
		Attempt:         0,
	}); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	available, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll(available): %v", err)
	}
	if available.Reserved != 1 {
		t.Fatalf("LeasePoll with one live slot of headroom reserved = %d, want 1", available.Reserved)
	}
}

func TestBrokerUnleasedOfferCannotConsumeCommittedLiveHeadroom(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 2, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 1
	broker := mustBroker(t, config)
	lease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || lease.Reserved != 1 {
		t.Fatalf("LeasePoll(repo-a) = (%+v, %v), want one committed slot", lease, err)
	}
	live := broker.(LiveHistory)
	if err := live.EnsureQueued(offer("repo-b", 50, clock.Now())); !errors.Is(err, ErrLiveSetFull) {
		t.Fatalf("EnsureQueued(unleased repo-b) err = %v, want ErrLiveSetFull", err)
	}
	if err := live.EnsureQueued(offer("repo-a", 51, clock.Now())); err != nil {
		t.Fatalf("EnsureQueued(repo-a consuming lease): %v", err)
	}
}

func TestLiveOfferLogicalBytesV1ChargesPayloadAndEmptyLabels(t *testing.T) {
	base := offer("repo-a", 80, time.Unix(0, 0))
	baseSize := mustOfferLogicalBytes(t, base)

	withPayload := base
	withPayload.JobDisplayName = strings.Repeat("x", 31)
	if got := mustOfferLogicalBytes(t, withPayload); got-baseSize != 31 {
		t.Fatalf("payload logical-byte delta = %d, want 31", got-baseSize)
	}

	withEmptyLabels := base
	withEmptyLabels.RequestLabels = make([]string, 32)
	if got := mustOfferLogicalBytes(t, withEmptyLabels); got-baseSize != 32*16 {
		t.Fatalf("empty-label logical-byte delta = %d, want 512 structural bytes", got-baseSize)
	}
}

func TestBrokerRejectsSingleOfferAboveLogicalByteLimitWithoutMutation(t *testing.T) {
	clock := newFakeClock()
	candidate := offer("repo-a", 81, clock.Now())
	size := mustOfferLogicalBytes(t, candidate)
	config := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	)
	config.MaxOfferLogicalBytes = size - 1
	config.MaxLiveOfferLogicalBytes = size
	broker := mustBroker(t, config)
	live := broker.(LiveHistory)

	if err := live.EnsureQueued(candidate); !errors.Is(err, ErrOfferTooLarge) {
		t.Fatalf("EnsureQueued(oversized) err = %v, want ErrOfferTooLarge", err)
	}
	if live.HasLiveReference(offerKey(candidate)) {
		t.Fatal("oversized offer created a live reference")
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	gotBytes := impl.liveOfferLogicalBytes
	gotQueue := len(impl.queues["repo-a"])
	impl.mu.Unlock()
	if gotBytes != 0 || gotQueue != 0 {
		t.Fatalf("oversized offer mutated broker: live bytes=%d queue=%d", gotBytes, gotQueue)
	}
}

func TestBrokerLiveOfferByteLimitReturnsHeadroomAfterRetire(t *testing.T) {
	clock := newFakeClock()
	first := offer("repo-a", 82, clock.Now())
	second := offer("repo-a", 83, clock.Now())
	size := mustOfferLogicalBytes(t, first)
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	config.MaxOfferLogicalBytes = size
	config.MaxLiveOfferLogicalBytes = size
	broker := mustBroker(t, config)
	live := broker.(LiveHistory)

	if err := live.EnsureQueued(first); err != nil {
		t.Fatalf("EnsureQueued(first): %v", err)
	}
	if err := live.EnsureQueued(first); err != nil {
		t.Fatalf("EnsureQueued(equal replay at byte cap): %v", err)
	}
	if err := live.EnsureQueued(second); !errors.Is(err, ErrLiveBytesFull) {
		t.Fatalf("EnsureQueued(over byte cap) err = %v, want ErrLiveBytesFull", err)
	}
	if err := live.Retire(offerKey(first)); err != nil {
		t.Fatalf("Retire(first): %v", err)
	}
	if err := live.EnsureQueued(second); err != nil {
		t.Fatalf("EnsureQueued(after byte headroom returned): %v", err)
	}

	impl := implementation(t, broker)
	impl.mu.Lock()
	gotBytes := impl.liveOfferLogicalBytes
	impl.mu.Unlock()
	if gotBytes != size {
		t.Fatalf("live logical bytes = %d, want %d", gotBytes, size)
	}
}

func TestBrokerPollLeaseReservesWorstCaseBytesPerSlot(t *testing.T) {
	clock := newFakeClock()
	first := offer("repo-a", 84, clock.Now())
	second := offer("repo-a", 85, clock.Now().Add(time.Second))
	size := mustOfferLogicalBytes(t, first)
	maxOffer := size + 64
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	config.MaxOfferLogicalBytes = maxOffer
	config.MaxLiveOfferLogicalBytes = 2 * maxOffer
	broker := mustBroker(t, config)

	lease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || lease.Reserved != 2 {
		t.Fatalf("LeasePoll = (%+v, %v), want two byte-reserved slots", lease, err)
	}
	refs, err := broker.(LiveHistory).EnsureQueuedBatch([]githubscale.Offer{second, first})
	if err != nil {
		t.Fatalf("EnsureQueuedBatch: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("EnsureQueuedBatch refs = %d, want 2", len(refs))
	}
	if refs[0].Key.RunnerRequestID != 84 || refs[0].SlotID != 2 ||
		refs[1].Key.RunnerRequestID != 85 || refs[1].SlotID != 1 {
		t.Fatalf("refs = %+v, want identity-sorted output with batch-order slots 84->2 and 85->1", refs)
	}
	for i, ref := range refs {
		if ref.Phase != LiveReserved {
			t.Fatalf("ref[%d] phase = %d, want LiveReserved", i, ref.Phase)
		}
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	gotBytes := impl.liveOfferLogicalBytes
	gotLeases := impl.leasedCountLocked()
	impl.mu.Unlock()
	wantBytes := mustOfferLogicalBytes(t, first) + mustOfferLogicalBytes(t, second)
	if gotBytes != wantBytes || gotLeases != 0 {
		t.Fatalf("post-batch live bytes=%d leases=%d, want bytes=%d leases=0", gotBytes, gotLeases, wantBytes)
	}

	oneSlotConfig := config
	oneSlotConfig.MaxLiveOfferLogicalBytes = maxOffer
	oneSlotBroker := mustBroker(t, oneSlotConfig)
	oneSlotLease, err := oneSlotBroker.LeasePoll("repo-a", clock.Now())
	if err != nil || oneSlotLease.Reserved != 1 {
		t.Fatalf("byte-limited LeasePoll = (%+v, %v), want exactly one reserved slot", oneSlotLease, err)
	}
}

func TestBrokerEnsureQueuedBatchRejectsFinalOversizedOfferAtomically(t *testing.T) {
	clock := newFakeClock()
	first := offer("repo-a", 86, clock.Now())
	second := offer("repo-a", 87, clock.Now().Add(time.Second))
	size := mustOfferLogicalBytes(t, first)
	oversized := second
	oversized.JobDisplayName = strings.Repeat("x", 65)
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	config.MaxOfferLogicalBytes = size + 64
	config.MaxLiveOfferLogicalBytes = 2 * (size + 64)
	broker := mustBroker(t, config)
	lease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || lease.Reserved != 2 {
		t.Fatalf("LeasePoll = (%+v, %v), want two reservations", lease, err)
	}

	refs, err := broker.(LiveHistory).EnsureQueuedBatch([]githubscale.Offer{first, oversized})
	if !errors.Is(err, ErrOfferTooLarge) {
		t.Fatalf("EnsureQueuedBatch err = %v, want ErrOfferTooLarge", err)
	}
	if refs != nil {
		t.Fatalf("failed EnsureQueuedBatch refs = %+v, want nil", refs)
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	gotLive := len(impl.liveOffers)
	gotQueue := len(impl.queues["repo-a"])
	gotLeases := impl.leasedCountLocked()
	gotBytes := impl.liveOfferLogicalBytes
	impl.mu.Unlock()
	if gotLive != 0 || gotQueue != 0 || gotLeases != 2 || gotBytes != 0 {
		t.Fatalf("failed batch mutated broker: live=%d queue=%d leases=%d bytes=%d",
			gotLive, gotQueue, gotLeases, gotBytes)
	}
}

func TestBrokerEnsureQueuedBatchRejectsAggregateHeadroomAtomically(t *testing.T) {
	clock := newFakeClock()
	first := offer("repo-a", 90, clock.Now())
	second := offer("repo-a", 91, clock.Now().Add(time.Second))
	firstSize := mustOfferLogicalBytes(t, first)
	secondSize := mustOfferLogicalBytes(t, second)
	maxOffer := max(firstSize, secondSize)
	cases := []struct {
		name          string
		maxReferences int
		maxLiveBytes  uint64
		want          error
	}{
		{
			name:          "reference headroom",
			maxReferences: 1,
			maxLiveBytes:  2 * maxOffer,
			want:          ErrLiveSetFull,
		},
		{
			name:          "byte headroom",
			maxReferences: 2,
			maxLiveBytes:  firstSize + secondSize - 1,
			want:          ErrLiveBytesFull,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfig(
				clock,
				2,
				Resources{MemoryBytes: 2},
				policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
			)
			config.MaxLiveReferences = tc.maxReferences
			config.MaxOfferLogicalBytes = maxOffer
			config.MaxLiveOfferLogicalBytes = tc.maxLiveBytes
			broker := mustBroker(t, config)
			refs, err := broker.(LiveHistory).EnsureQueuedBatch([]githubscale.Offer{first, second})
			if !errors.Is(err, tc.want) {
				t.Fatalf("EnsureQueuedBatch err = %v, want %v", err, tc.want)
			}
			if refs != nil {
				t.Fatalf("failed EnsureQueuedBatch refs = %+v, want nil", refs)
			}
			impl := implementation(t, broker)
			impl.mu.Lock()
			gotLive := len(impl.liveOffers)
			gotQueue := len(impl.queues["repo-a"])
			gotBytes := impl.liveOfferLogicalBytes
			impl.mu.Unlock()
			if gotLive != 0 || gotQueue != 0 || gotBytes != 0 {
				t.Fatalf("failed batch mutated broker: live=%d queue=%d bytes=%d",
					gotLive, gotQueue, gotBytes)
			}
		})
	}
}

func TestBrokerEnsureQueuedBatchReturnsExactActiveReplayProjection(t *testing.T) {
	clock := newFakeClock()
	candidate := offer("repo-a", 94, clock.Now())
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 3, DurableStateBytes: 2},
		policy("repo-a", 1, 1, EligibilityActive, SlotResources{
			Runner:        Resources{MemoryBytes: 3},
			DialAuthority: Resources{DurableStateBytes: 2},
		}),
	))
	live := broker.(LiveHistory)
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued: %v", err)
	}
	decisions, err := broker.Admit(clock.Now())
	if err != nil || len(decisions) != 1 {
		t.Fatalf("Admit = (%+v, %v), want one decision", decisions, err)
	}

	refs, err := live.EnsureQueuedBatch([]githubscale.Offer{candidate})
	if err != nil {
		t.Fatalf("EnsureQueuedBatch(active replay): %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("active replay refs = %d, want 1", len(refs))
	}
	ref := refs[0]
	if ref.Key != decisions[0].Assignment || ref.Phase != LiveActive ||
		ref.SlotID != decisions[0].SlotID ||
		ref.FullCharge != (Resources{MemoryBytes: 3, DurableStateBytes: 2}) ||
		ref.LedgerCharge != (Resources{DurableStateBytes: 2}) ||
		!ref.LedgerEverUsed {
		t.Fatalf("active replay ref = %+v, want exact active slot and persisted charges", ref)
	}
}

func TestLiveHistoryReferenceReturnsExactQueuedAndActiveProjection(t *testing.T) {
	clock := newFakeClock()
	candidate := offer("repo-a", 9101, clock.Now())
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 3, DurableStateBytes: 2},
		policy("repo-a", 1, 1, EligibilityActive, SlotResources{
			Runner:        Resources{MemoryBytes: 3},
			DialAuthority: Resources{DurableStateBytes: 2},
		}),
	))
	live := broker.(LiveHistory)
	if err := live.EnsureQueued(candidate); err != nil {
		t.Fatalf("EnsureQueued: %v", err)
	}
	key := offerKey(candidate)
	queued, ok, err := live.Reference(key)
	if err != nil || !ok {
		t.Fatalf("Reference(queued) = (%+v, %v, %v), want present", queued, ok, err)
	}
	if queued.Key != key || queued.Phase != LiveQueued || queued.Offer.RunnerRequestID != candidate.RunnerRequestID {
		t.Fatalf("queued reference = %+v, want exact queued identity", queued)
	}

	decisions, err := broker.Admit(clock.Now())
	if err != nil || len(decisions) != 1 {
		t.Fatalf("Admit = (%+v, %v), want one", decisions, err)
	}
	active, ok, err := live.Reference(key)
	if err != nil || !ok {
		t.Fatalf("Reference(active) = (%+v, %v, %v), want present", active, ok, err)
	}
	if active.Phase != LiveActive || active.SlotID != decisions[0].SlotID ||
		active.FullCharge != (Resources{MemoryBytes: 3, DurableStateBytes: 2}) ||
		active.LedgerCharge != (Resources{DurableStateBytes: 2}) ||
		!active.LedgerEverUsed {
		t.Fatalf("active reference = %+v, want exact active projection", active)
	}

	missing, ok, err := live.Reference(controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 9999,
	})
	if err != nil || ok || missing.Key != (controller.AssignmentKey{}) ||
		missing.Phase != 0 || missing.Offer.RunnerRequestID != 0 {
		t.Fatalf("Reference(missing) = (%+v, %v, %v), want zero/false/nil", missing, ok, err)
	}
}

func TestBrokerUnleasedOfferCannotConsumeCommittedLiveBytes(t *testing.T) {
	clock := newFakeClock()
	leasedOffer := offer("repo-a", 92, clock.Now())
	unleasedOffer := offer("repo-b", 93, clock.Now())
	maxOffer := max(
		mustOfferLogicalBytes(t, leasedOffer),
		mustOfferLogicalBytes(t, unleasedOffer),
	)
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 2, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	config.MaxOfferLogicalBytes = maxOffer
	config.MaxLiveOfferLogicalBytes = maxOffer
	broker := mustBroker(t, config)
	lease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || lease.Reserved != 1 {
		t.Fatalf("LeasePoll(repo-a) = (%+v, %v), want one byte-reserved slot", lease, err)
	}
	live := broker.(LiveHistory)
	if err := live.EnsureQueued(unleasedOffer); !errors.Is(err, ErrLiveBytesFull) {
		t.Fatalf("EnsureQueued(unleased repo-b) err = %v, want ErrLiveBytesFull", err)
	}
	if err := live.EnsureQueued(leasedOffer); err != nil {
		t.Fatalf("EnsureQueued(repo-a consuming byte reservation): %v", err)
	}
}

func TestBrokerRestoreRejectsLiveOfferLogicalByteOverflowAtomically(t *testing.T) {
	clock := newFakeClock()
	first := offer("repo-a", 88, clock.Now())
	second := offer("repo-a", 89, clock.Now().Add(time.Second))
	firstSize := mustOfferLogicalBytes(t, first)
	secondSize := mustOfferLogicalBytes(t, second)
	maxOffer := max(firstSize, secondSize)
	config := testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 2, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	config.MaxOfferLogicalBytes = maxOffer
	config.MaxLiveOfferLogicalBytes = firstSize + secondSize - 1
	broker := mustBroker(t, config)
	live := broker.(LiveHistory)
	err := live.Restore([]LiveReference{
		{Key: offerKey(first), Offer: first, Phase: LiveQueued},
		{Key: offerKey(second), Offer: second, Phase: LiveQueued},
	})
	if !errors.Is(err, ErrLiveBytesFull) {
		t.Fatalf("Restore(over byte cap) err = %v, want ErrLiveBytesFull", err)
	}
	if live.HasLiveReference(offerKey(first)) || live.HasLiveReference(offerKey(second)) {
		t.Fatal("failed byte-limited Restore left a partial live reference")
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	gotBytes := impl.liveOfferLogicalBytes
	impl.mu.Unlock()
	if gotBytes != 0 {
		t.Fatalf("failed Restore live logical bytes = %d, want 0", gotBytes)
	}
}

func TestBrokerRestoreQueuesInDeterministicDurableOrder(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		3,
		Resources{MemoryBytes: 3},
		policy("repo-a", 1, 3, EligibilityActive, memoryProfile(1)),
	))
	oldest := clock.Now().Add(-2 * time.Minute)
	tied := clock.Now().Add(-time.Minute)
	refs := []LiveReference{
		{
			Key:   controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 3, Attempt: 0},
			Offer: offer("repo-a", 3, tied),
			Phase: LiveQueued,
		},
		{
			Key:   controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 1, Attempt: 0},
			Offer: offer("repo-a", 1, oldest),
			Phase: LiveQueued,
		},
		{
			Key:   controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 2, Attempt: 0},
			Offer: offer("repo-a", 2, tied),
			Phase: LiveQueued,
		},
	}
	if err := broker.(LiveHistory).Restore(refs); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	decisions, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got, want := decisionRequestIDs(decisions), []int64{1, 2, 3}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("restored admission order = %v, want %v", got, want)
	}
}

func TestBrokerRestoreRebuildsReservedAndActiveResourceAccounting(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		3,
		Resources{MemoryBytes: 3},
		policy("repo-a", 1, 3, EligibilityActive, memoryProfile(1)),
	))
	activeKey := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 51, Attempt: 0}
	reservedKey := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 52, Attempt: 0}
	queuedKey := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 53, Attempt: 0}
	refs := []LiveReference{
		{Key: queuedKey, Offer: offer("repo-a", 53, clock.Now()), Phase: LiveQueued},
		{
			Key:             activeKey,
			Offer:           offer("repo-a", 51, clock.Now().Add(-3*time.Minute)),
			Phase:           LiveActive,
			SlotID:          3,
			FullCharge:      Resources{MemoryBytes: 1},
			LedgerCreatedAt: clock.Now().Add(-3 * time.Minute),
		},
		{
			Key:             reservedKey,
			Offer:           offer("repo-a", 52, clock.Now().Add(-2*time.Minute)),
			Phase:           LiveReserved,
			SlotID:          1,
			FullCharge:      Resources{MemoryBytes: 1},
			LedgerCreatedAt: clock.Now().Add(-2 * time.Minute),
		},
	}
	live := broker.(LiveHistory)
	if err := live.Restore(refs); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for _, key := range []controller.AssignmentKey{activeKey, reservedKey, queuedKey} {
		if !live.HasLiveReference(key) {
			t.Fatalf("HasLiveReference(%+v) = false after Restore", key)
		}
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	restoredUsage := impl.used.MemoryBytes
	activeSlot := impl.assignments[activeKey]
	impl.mu.Unlock()
	if restoredUsage != 2 {
		t.Fatalf("restored MemoryBytes = %d, want active+reserved charge 2", restoredUsage)
	}
	if activeSlot != 3 {
		t.Fatalf("restored active slot = %d, want stable slot 3", activeSlot)
	}

	decisions, err := broker.Admit(clock.Now())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got, want := decisionRequestIDs(decisions), []int64{52, 53}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("post-restore decisions = %v, want %v", got, want)
	}
	if decisions[0].SlotID != 1 || decisions[1].SlotID != 2 {
		t.Fatalf("post-restore slots = [%d %d], want stable reserved 1 then free 2",
			decisions[0].SlotID, decisions[1].SlotID)
	}
	impl.mu.Lock()
	finalUsage := impl.used.MemoryBytes
	impl.mu.Unlock()
	if finalUsage != 3 {
		t.Fatalf("post-admit MemoryBytes = %d, want full capacity charge 3", finalUsage)
	}
}

func TestBrokerRestoreInvalidFinalReferenceLeavesBrokerUnchanged(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	validKey := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 61, Attempt: 0}
	invalidKey := controller.AssignmentKey{RepositoryAlias: "repo-missing", RunnerRequestID: 62, Attempt: 0}
	live := broker.(LiveHistory)
	err := live.Restore([]LiveReference{
		{Key: validKey, Offer: offer("repo-a", 61, clock.Now()), Phase: LiveQueued},
		{Key: invalidKey, Offer: offer("repo-missing", 62, clock.Now()), Phase: LiveQueued},
	})
	if !errors.Is(err, ErrUnknownRepository) {
		t.Fatalf("Restore invalid final reference err = %v, want ErrUnknownRepository", err)
	}
	if live.HasLiveReference(validKey) || live.HasLiveReference(invalidKey) {
		t.Fatal("failed Restore left a partial live reference")
	}
	if err := broker.Enqueue(offer("repo-a", 63, clock.Now())); err != nil {
		t.Fatalf("Enqueue after failed Restore: %v", err)
	}
}

func TestBrokerRestoreRejectsSnapshotAboveLiveReferenceLimit(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	)
	config.MaxLiveReferences = 2
	broker := mustBroker(t, config)
	refs := make([]LiveReference, 0, 3)
	for requestID := int64(71); requestID <= 73; requestID++ {
		refs = append(refs, LiveReference{
			Key: controller.AssignmentKey{
				RepositoryAlias: "repo-a",
				RunnerRequestID: requestID,
				Attempt:         0,
			},
			Offer: offer("repo-a", requestID, clock.Now()),
			Phase: LiveQueued,
		})
	}
	live := broker.(LiveHistory)
	if err := live.Restore(refs); !errors.Is(err, ErrLiveSetFull) {
		t.Fatalf("Restore(over limit) err = %v, want ErrLiveSetFull", err)
	}
	for _, ref := range refs {
		if live.HasLiveReference(ref.Key) {
			t.Fatalf("failed over-limit Restore retained %+v", ref.Key)
		}
	}
}

func TestBrokerRestoreRejectsNonEmptyBrokerWithoutMutation(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	existing := offer("repo-a", 64, clock.Now())
	if err := broker.Enqueue(existing); err != nil {
		t.Fatalf("Enqueue existing: %v", err)
	}
	err := broker.(LiveHistory).Restore([]LiveReference{{
		Key:   controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 65, Attempt: 0},
		Offer: offer("repo-a", 65, clock.Now()),
		Phase: LiveQueued,
	}})
	if !errors.Is(err, ErrRestoreNotEmpty) {
		t.Fatalf("Restore(nonempty) err = %v, want ErrRestoreNotEmpty", err)
	}
	decisions, admitErr := broker.Admit(clock.Now())
	if admitErr != nil || len(decisions) != 1 || decisions[0].Assignment.RunnerRequestID != 64 {
		t.Fatalf("existing broker state after rejected Restore = (%+v, %v), want request 64", decisions, admitErr)
	}
}

func TestBrokerRestoreUsesPersistedChargeInsteadOfShrunkenCurrentProfile(t *testing.T) {
	clock := newFakeClock()
	current := SlotResources{
		Runner:        Resources{MemoryBytes: 1},
		DialAuthority: Resources{SocketStateBytes: 1, DurableStateBytes: 2, Inodes: 1},
	}
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1, SocketStateBytes: 7, DurableStateBytes: 11, Inodes: 5},
		policy("repo-a", 1, 1, EligibilityActive, current),
	))
	key := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 66, Attempt: 0}
	persistedLedger := Resources{SocketStateBytes: 7, DurableStateBytes: 11, Inodes: 5}
	persistedFull := Resources{
		MemoryBytes:       1,
		SocketStateBytes:  7,
		DurableStateBytes: 11,
		Inodes:            5,
	}
	if err := broker.(LiveHistory).Restore([]LiveReference{{
		Key:             key,
		Offer:           offer("repo-a", 66, clock.Now().Add(-time.Minute)),
		Phase:           LiveActive,
		SlotID:          1,
		FullCharge:      persistedFull,
		LedgerCharge:    persistedLedger,
		LedgerCreatedAt: clock.Now().Add(-time.Minute),
	}}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	restored := impl.used
	impl.mu.Unlock()
	if restored != persistedFull {
		t.Fatalf("restored charge = %+v, want persisted %+v", restored, persistedFull)
	}
	if err := broker.Release(key); err != nil {
		t.Fatalf("Release: %v", err)
	}
	impl.mu.Lock()
	tail := impl.used
	impl.mu.Unlock()
	if tail != persistedLedger {
		t.Fatalf("released tail charge = %+v, want persisted %+v", tail, persistedLedger)
	}
}

func TestBrokerRestoreReservedReusedSlotRetainsPersistedLedgerOnRetire(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1, DurableStateBytes: 3},
		policy("repo-a", 1, 1, EligibilityActive, SlotResources{
			Runner:        Resources{MemoryBytes: 1},
			DialAuthority: Resources{DurableStateBytes: 1},
		}),
	))
	key := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 67, Attempt: 0}
	if err := broker.(LiveHistory).Restore([]LiveReference{{
		Key:             key,
		Offer:           offer("repo-a", 67, clock.Now()),
		Phase:           LiveReserved,
		SlotID:          1,
		FullCharge:      Resources{MemoryBytes: 1, DurableStateBytes: 3},
		LedgerCharge:    Resources{DurableStateBytes: 3},
		LedgerCreatedAt: clock.Now().Add(-time.Hour),
		LedgerEverUsed:  true,
	}}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := broker.(LiveHistory).Retire(key); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	impl := implementation(t, broker)
	impl.mu.Lock()
	retained := impl.used
	impl.mu.Unlock()
	if retained != (Resources{DurableStateBytes: 3}) {
		t.Fatalf("retained charge = %+v, want persisted durable tail 3", retained)
	}
}

func TestBrokerRestoreRejectsInvalidPersistedCharges(t *testing.T) {
	clock := newFakeClock()
	base := LiveReference{
		Key:             controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 68, Attempt: 0},
		Offer:           offer("repo-a", 68, clock.Now()),
		Phase:           LiveActive,
		SlotID:          1,
		FullCharge:      Resources{MemoryBytes: 1, DurableStateBytes: 1},
		LedgerCharge:    Resources{DurableStateBytes: 1},
		LedgerCreatedAt: clock.Now().Add(-time.Minute),
		LedgerEverUsed:  true,
	}
	cases := []struct {
		name   string
		mutate func(*LiveReference)
	}{
		{"ledger exceeds full", func(ref *LiveReference) {
			ref.LedgerCharge.DurableStateBytes = 2
		}},
		{"ledger uses non-ledger dimension", func(ref *LiveReference) {
			ref.LedgerCharge.MemoryBytes = 1
		}},
		{"future creation time", func(ref *LiveReference) {
			ref.LedgerCreatedAt = clock.Now().Add(time.Second)
		}},
		{"queued reference carries charge", func(ref *LiveReference) {
			ref.Phase = LiveQueued
			ref.SlotID = 0
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			broker := mustBroker(t, testConfig(
				clock,
				1,
				Resources{MemoryBytes: 1, DurableStateBytes: 2},
				policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
			))
			ref := base
			tc.mutate(&ref)
			if err := broker.(LiveHistory).Restore([]LiveReference{ref}); !errors.Is(err, ErrInvalidOffer) {
				t.Fatalf("Restore invalid charge err = %v, want ErrInvalidOffer", err)
			}
		})
	}
}

func TestBrokerDecisionKeyMatchesPersistedInitialOfferIdentity(t *testing.T) {
	clock := newFakeClock()
	broker := mustBroker(t, testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	enqueueAll(t, broker, offer("repo-a", 77, clock.Now()))

	decisions, err := broker.Admit(clock.Now())
	if err != nil || len(decisions) != 1 {
		t.Fatalf("Admit = (%d, %v), want 1", len(decisions), err)
	}
	want := controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 77,
		Attempt:         0,
	}
	if got := decisions[0].Assignment; got != want {
		t.Fatalf("Decision.Assignment = %+v, want persisted RecordOffer key %+v", got, want)
	}
}

func TestBrokerRejectsInvalidConfiguration(t *testing.T) {
	clock := newFakeClock()
	base := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
	)
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"zero capacity", func(c *Config) { c.MaxCapacity = 0 }},
		{"capacity exceeds slot id", func(c *Config) { c.MaxCapacity = int(math.MaxUint32) + 1 }},
		{"zero live reference limit", func(c *Config) { c.MaxLiveReferences = 0 }},
		{"zero offer logical byte limit", func(c *Config) { c.MaxOfferLogicalBytes = 0 }},
		{"zero live offer logical byte limit", func(c *Config) { c.MaxLiveOfferLogicalBytes = 0 }},
		{"live offer byte limit below one offer", func(c *Config) {
			c.MaxLiveOfferLogicalBytes = c.MaxOfferLogicalBytes - 1
		}},
		{"negative ceiling", func(c *Config) { c.Ceiling.MemoryBytes = -1 }},
		{"zero lease ttl", func(c *Config) { c.PollLeaseTTL = 0 }},
		{"zero ledger tail", func(c *Config) { c.LedgerTail = 0 }},
		{"unknown transient mode", func(c *Config) { c.TransientMode = "unknown" }},
		{"zero revision", func(c *Config) { c.PolicyRevision = 0 }},
		{"duplicate alias", func(c *Config) { c.Repositories = append(c.Repositories, c.Repositories[0]) }},
		{"empty alias", func(c *Config) { c.Repositories[0].Alias = "" }},
		{"zero weight", func(c *Config) { c.Repositories[0].Weight = 0 }},
		{"unknown eligibility", func(c *Config) { c.Repositories[0].Eligibility = "unknown" }},
		{"negative profile", func(c *Config) { c.Repositories[0].Profile.Runner.MemoryBytes = -1 }},
		{"nil clock", func(c *Config) { c.Now = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := base
			config.Repositories = append([]RepositoryPolicy(nil), base.Repositories...)
			tc.mutate(&config)
			if _, err := NewBroker(config); err == nil {
				t.Fatal("NewBroker: got nil error for invalid configuration")
			}
		})
	}
}

func TestBrokerAcceptsFullCapacitySlotIDDomainWithoutEagerAllocation(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		int(math.MaxUint32),
		Resources{},
		policy("repo-a", 1, 1, EligibilityActive, SlotResources{}),
	)
	broker := mustBroker(t, config)
	enqueueAll(t, broker, offer("repo-a", 1, clock.Now()))
	decisions, err := broker.Admit(clock.Now())
	if err != nil || len(decisions) != 1 {
		t.Fatalf("Admit at full CapacitySlotID domain = (%d, %v), want one lazily allocated slot", len(decisions), err)
	}
	if decisions[0].SlotID != 1 {
		t.Fatalf("first lazy SlotID = %d, want 1", decisions[0].SlotID)
	}
}

func TestBrokerInterfaceContract(t *testing.T) {
	var _ Broker = (*brokerImpl)(nil)
	var _ PolicyBroker = (*brokerImpl)(nil)
	var _ LiveHistory = (*brokerImpl)(nil)
}
