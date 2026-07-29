package admission

import (
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestBrokerAcquisitionEpochCapacityInvalidatesLeasesAndResetsDemand(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	config := testConfig(
		clock,
		3,
		Resources{MemoryBytes: 3},
		policy("repo-a", 1, 3, EligibilityActive, memoryProfile(1)),
	)
	broker, err := NewBroker(config)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	if err := broker.SetDemand("repo-a", 1, 1); err != nil {
		t.Fatalf("SetDemand(epoch 1): %v", err)
	}
	firstLease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || firstLease.Reserved != 3 || firstLease.Epoch != 1 {
		t.Fatalf("LeasePoll(epoch 1) = (%+v, %v)", firstLease, err)
	}
	firstOffer := offer("repo-a", 7101, clock.Now())
	if err := broker.Enqueue(firstOffer); err != nil {
		t.Fatalf("Enqueue(first): %v", err)
	}
	first, err := broker.Admit(clock.Now())
	if err != nil || len(first) != 1 {
		t.Fatalf("Admit(first) = (%+v, %v)", first, err)
	}

	repository := policy("repo-a", 1, 3, EligibilityActive, memoryProfile(1))
	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:             2,
		EffectiveCapacity: 1,
		Repositories:      []RepositoryPolicy{repository},
	}); err != nil {
		t.Fatalf("ApplyPolicyRevision(disable excess): %v", err)
	}
	snapshot := broker.CapacitySnapshot()
	if snapshot.Epoch != 2 ||
		snapshot.ConfiguredCapacity != 3 ||
		snapshot.EffectiveCapacity != 1 ||
		snapshot.Occupied != 1 ||
		snapshot.Available != 0 {
		t.Fatalf("capacity after reduction = %+v", snapshot)
	}
	if lease, err := broker.LeasePoll("repo-a", clock.Now()); err != nil ||
		lease.Epoch != 2 || lease.Reserved != 0 {
		t.Fatalf("LeasePoll(epoch 2) = (%+v, %v)", lease, err)
	}
	if err := broker.SetDemand("repo-a", 1, 2); !errors.Is(err, ErrDemandEpochMismatch) {
		t.Fatalf("SetDemand(stale epoch) = %v, want ErrDemandEpochMismatch", err)
	}
	if _, err := broker.SetPressure(Pressure{MaxCapacity: 3}); !errors.Is(err, ErrPressureIncrease) {
		t.Fatalf("SetPressure(increase) = %v, want ErrPressureIncrease", err)
	}

	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:             3,
		EffectiveCapacity: 3,
		Repositories:      []RepositoryPolicy{repository},
	}); err != nil {
		t.Fatalf("ApplyPolicyRevision(increase): %v", err)
	}
	secondOffer := offer("repo-a", 7102, clock.Now())
	if err := broker.Enqueue(secondOffer); err != nil {
		t.Fatalf("Enqueue(second): %v", err)
	}
	if decisions, err := broker.Admit(clock.Now()); err != nil || len(decisions) != 0 {
		t.Fatalf("Admit(before epoch-3 demand) = (%+v, %v), want none", decisions, err)
	}
	if err := broker.SetDemand("repo-a", 3, 2); err != nil {
		t.Fatalf("SetDemand(epoch 3): %v", err)
	}
	second, err := broker.Admit(clock.Now())
	if err != nil || len(second) != 1 ||
		second[0].Assignment.RunnerRequestID != secondOffer.RunnerRequestID {
		t.Fatalf("Admit(epoch 3 demand) = (%+v, %v)", second, err)
	}
}

func TestBrokerPollCapacityClampsResidualActiveOwnershipAfterReduction(
	t *testing.T,
) {
	t.Parallel()

	clock := newFakeClock()
	repository := policy(
		"repo-a",
		1,
		2,
		EligibilityActive,
		memoryProfile(1),
	)
	broker, err := NewBroker(testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		repository,
	))
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	if err := broker.SetDemand("repo-a", 1, 2); err != nil {
		t.Fatalf("SetDemand(epoch 1): %v", err)
	}
	firstLease, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || firstLease.Reserved != 2 ||
		firstLease.PollCapacity != 2 {
		t.Fatalf("LeasePoll(epoch 1) = (%+v, %v), want reserved/poll 2/2", firstLease, err)
	}
	enqueueAll(
		t,
		broker,
		offer("repo-a", 7151, clock.Now()),
		offer("repo-a", 7152, clock.Now()),
	)
	active, err := broker.Admit(clock.Now())
	if err != nil || len(active) != 2 {
		t.Fatalf("Admit(epoch 1) = (%+v, %v), want two active", active, err)
	}

	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:             2,
		EffectiveCapacity: 1,
		Repositories:      []RepositoryPolicy{repository},
	}); err != nil {
		t.Fatalf("ApplyPolicyRevision(reduced): %v", err)
	}
	reduced, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || reduced.Reserved != 0 ||
		reduced.PollCapacity != 1 {
		t.Fatalf(
			"LeasePoll(reduced with residual active) = (%+v, %v), want reserved/poll 0/1",
			reduced,
			err,
		)
	}

	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:             3,
		EffectiveCapacity: 0,
		Repositories:      []RepositoryPolicy{repository},
	}); err != nil {
		t.Fatalf("ApplyPolicyRevision(disabled): %v", err)
	}
	disabled, err := broker.LeasePoll("repo-a", clock.Now())
	if err != nil || disabled.Reserved != 0 ||
		disabled.PollCapacity != 0 {
		t.Fatalf(
			"LeasePoll(disabled with residual active) = (%+v, %v), want reserved/poll 0/0",
			disabled,
			err,
		)
	}
}

func TestBrokerDemandIsEpochBoundAndRepositoryIsolated(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	broker, err := NewBroker(testConfig(
		clock,
		2,
		Resources{MemoryBytes: 2},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	enqueueAll(t, broker,
		offer("repo-a", 7201, clock.Now()),
		offer("repo-b", 7202, clock.Now()),
	)
	if decisions, err := broker.Admit(clock.Now()); err != nil || len(decisions) != 0 {
		t.Fatalf("Admit(zero demand) = (%+v, %v), want none", decisions, err)
	}
	if err := broker.SetDemand("repo-a", 1, 1); err != nil {
		t.Fatalf("SetDemand(repo-a): %v", err)
	}
	first, err := broker.Admit(clock.Now())
	if err != nil || len(first) != 1 ||
		first[0].Assignment.RepositoryAlias != "repo-a" {
		t.Fatalf("Admit(repo-a demand) = (%+v, %v)", first, err)
	}
	if err := broker.SetDemand("repo-b", 1, -1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("SetDemand(negative) = %v, want ErrInvalidConfig", err)
	}
	if err := broker.SetDemand("repo-b", 1, 1); err != nil {
		t.Fatalf("SetDemand(repo-b): %v", err)
	}
	second, err := broker.Admit(clock.Now())
	if err != nil || len(second) != 1 ||
		second[0].Assignment.RepositoryAlias != "repo-b" {
		t.Fatalf("Admit(repo-b demand) = (%+v, %v)", second, err)
	}
	snapshot := broker.CapacitySnapshot()
	if snapshot.Queued != 0 ||
		snapshot.Occupied != 2 ||
		snapshot.Available != 0 {
		t.Fatalf("CapacitySnapshot = %+v", snapshot)
	}
}

func TestBrokerPolicyRevisionRejectsCapacityOutsideConfiguredCeiling(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	repository := policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1))
	broker, err := NewBroker(testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		repository,
	))
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	if err := broker.ApplyPolicyRevision(PolicyRevision{
		Epoch:             2,
		EffectiveCapacity: 2,
		Repositories:      []RepositoryPolicy{repository},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ApplyPolicyRevision(over ceiling) = %v, want ErrInvalidConfig", err)
	}
	if got := broker.CapacitySnapshot().Epoch; got != 1 {
		t.Fatalf("epoch after rejected revision = %d, want 1", got)
	}
}

func TestBrokerDemandNeverUsesAnotherRepositoryQueue(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	broker, err := NewBroker(testConfig(
		clock,
		1,
		Resources{MemoryBytes: 1},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(1)),
		policy("repo-b", 1, 1, EligibilityActive, memoryProfile(1)),
	))
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	if err := broker.SetDemand("repo-a", 1, 1); err != nil {
		t.Fatalf("SetDemand(repo-a): %v", err)
	}
	candidate := offer("repo-b", 7301, clock.Now())
	if err := broker.Enqueue(candidate); err != nil {
		t.Fatalf("Enqueue(repo-b): %v", err)
	}
	if decisions, err := broker.Admit(clock.Now()); err != nil || len(decisions) != 0 {
		t.Fatalf("Admit(cross-repo queue) = (%+v, %v), want none", decisions, err)
	}
	if broker.(LiveHistory).HasLiveReference(controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: candidate.RunnerRequestID,
	}) {
		t.Fatal("repo-a demand created a foreign live reference")
	}
}
