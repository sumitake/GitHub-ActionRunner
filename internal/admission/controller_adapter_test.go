package admission

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func TestControllerAdmissionAdapterUsesAliasCopiesAndReturnsExactActiveProjection(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 3, DurableStateBytes: 2},
		policy("repo-a", 1, 1, EligibilityActive, SlotResources{
			Runner:        Resources{MemoryBytes: 3},
			DialAuthority: Resources{DurableStateBytes: 2},
		}),
	)
	broker := mustBroker(t, config)
	history := broker.(LiveHistory)
	adapter, err := NewControllerAdapter(
		broker,
		history,
		config.Repositories,
		config.TransientMode,
	)
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}
	var _ controller.AdmissionBroker = adapter

	candidate := offer("owner/repository", 9201, clock.Now())
	originalRepository := candidate.RepositoryName
	if err := adapter.CheckOffer("repo-a", candidate); err != nil {
		t.Fatalf("CheckOffer(valid): %v", err)
	}
	epoch := adapter.CapacitySummary().Epoch
	refs, err := adapter.EnsureQueuedBatch(epoch, "repo-a", []githubscale.Offer{candidate})
	if err != nil {
		t.Fatalf("EnsureQueuedBatch: %v", err)
	}
	if candidate.RepositoryName != originalRepository {
		t.Fatalf("EnsureQueuedBatch mutated caller offer repository %q -> %q", originalRepository, candidate.RepositoryName)
	}
	if len(refs) != 1 || refs[0].Key != (controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 9201,
	}) || refs[0].Phase != controller.AdmissionQueued {
		t.Fatalf("queued controller refs = %+v", refs)
	}

	decisions, err := adapter.Admit(epoch, clock.Now())
	if err != nil || len(decisions) != 1 {
		t.Fatalf("Admit = (%+v, %v), want one", decisions, err)
	}
	got := decisions[0]
	if got.Key != refs[0].Key || got.Projection.Key != got.Key ||
		got.Projection.Phase != controller.AdmissionActive ||
		got.Projection.SlotID == 0 ||
		got.Projection.FullCharge != (controller.ResourceProjection{MemoryBytes: 3, DurableStateBytes: 2}) ||
		got.Projection.LedgerCharge != (controller.ResourceProjection{DurableStateBytes: 2}) ||
		!got.Projection.LedgerEverUsed {
		t.Fatalf("active controller decision = %+v", got)
	}
	exact, present, err := adapter.Reference(got.Key)
	if err != nil || !present || !reflect.DeepEqual(exact, got.Projection) {
		t.Fatalf("Reference(active) = (%+v, %v, %v), want exact decision projection", exact, present, err)
	}
}

func TestControllerAdmissionAdapterRestoreAndClosedErrors(t *testing.T) {
	clock := newFakeClock()
	newAdapter := func(t *testing.T) *ControllerAdapter {
		t.Helper()
		config := testConfig(
			clock,
			1,
			Resources{MemoryBytes: 3},
			policy("repo-a", 1, 1, EligibilityActive, memoryProfile(3)),
		)
		config.MaxLiveReferences = 1
		broker := mustBroker(t, config)
		adapter, err := NewControllerAdapter(
			broker,
			broker.(LiveHistory),
			config.Repositories,
			config.TransientMode,
		)
		if err != nil {
			t.Fatalf("NewControllerAdapter: %v", err)
		}
		return adapter
	}

	invalid := newAdapter(t)
	err := invalid.Restore([]controller.AdmissionReference{{
		Key:   controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 9301},
		Offer: offer("owner/repository", 9301, clock.Now()),
		Phase: controller.AdmissionPhase(255),
	}})
	if !errors.Is(err, controller.ErrAdmissionConflict) {
		t.Fatalf("Restore(invalid phase) err = %v, want controller.ErrAdmissionConflict", err)
	}

	adapter := newAdapter(t)
	ref := controller.AdmissionReference{
		Key:   controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 9302},
		Offer: offer("owner/repository", 9302, clock.Now()),
		Phase: controller.AdmissionQueued,
	}
	if err := adapter.Restore([]controller.AdmissionReference{ref}); err != nil {
		t.Fatalf("Restore(queued): %v", err)
	}
	if err := adapter.SetDemand("repo-a", adapter.CapacitySummary().Epoch, 1); err != nil {
		t.Fatalf("SetDemand(after restore): %v", err)
	}
	decisions, err := adapter.Admit(adapter.CapacitySummary().Epoch, clock.Now())
	if err != nil || len(decisions) != 1 || decisions[0].Key != ref.Key {
		t.Fatalf("Admit(restored) = (%+v, %v), want exact key", decisions, err)
	}

	overfull := newAdapter(t)
	candidates := []githubscale.Offer{
		offer("owner/repository", 9401, clock.Now()),
		offer("owner/repository", 9402, clock.Now()),
	}
	if _, err := overfull.EnsureQueuedBatch(
		overfull.CapacitySummary().Epoch,
		"repo-a",
		candidates,
	); !errors.Is(err, controller.ErrAdmissionHeadroom) {
		t.Fatalf("EnsureQueuedBatch(over headroom) err = %v, want controller.ErrAdmissionHeadroom", err)
	}
	if overfull.HasLiveReference(controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 9401}) {
		t.Fatal("failed batch left partial live reference")
	}
}

func TestControllerAdmissionAdapterLeaseAndPureOversizePreflight(t *testing.T) {
	clock := newFakeClock()
	config := testConfig(
		clock,
		1,
		Resources{MemoryBytes: 3},
		policy("repo-a", 1, 1, EligibilityActive, memoryProfile(3)),
	)
	small := offer("owner/repository", 9501, clock.Now())
	config.MaxOfferLogicalBytes = mustOfferLogicalBytes(t, copyOfferForAlias(small, "repo-a"))
	config.MaxLiveOfferLogicalBytes = config.MaxOfferLogicalBytes
	broker := mustBroker(t, config)
	adapter, err := NewControllerAdapter(
		broker,
		broker.(LiveHistory),
		config.Repositories,
		config.TransientMode,
	)
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}

	lease, err := adapter.LeasePoll("repo-a", clock.Now())
	if err != nil {
		t.Fatalf("LeasePoll: %v", err)
	}
	if lease.RepositoryAlias != "repo-a" ||
		lease.Reserved != 1 ||
		lease.PollCapacity != 1 {
		t.Fatalf("LeasePoll = %+v", lease)
	}

	oversize := cloneControllerOffer(small)
	oversize.RunnerRequestID++
	oversize.JobDisplayName += "x"
	if err := adapter.CheckOffer("repo-a", oversize); !errors.Is(err, controller.ErrOfferTooLarge) {
		t.Fatalf("CheckOffer(oversize) err = %v, want controller.ErrOfferTooLarge", err)
	}
	if adapter.HasLiveReference(controller.AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: oversize.RunnerRequestID,
	}) {
		t.Fatal("pure oversize preflight mutated broker live history")
	}
}

func TestControllerAdmissionAdapterOverlaysOnlyMutablePolicyFields(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	template := policy(
		"repo-a",
		7,
		3,
		EligibilityActive,
		SlotResources{
			Runner:        Resources{MemoryBytes: 2},
			DialAuthority: Resources{DurableStateBytes: 1},
		},
	)
	template.AgingThreshold = 17 * time.Minute
	config := testConfig(
		clock,
		3,
		Resources{MemoryBytes: 6, DurableStateBytes: 3},
		template,
	)
	broker := mustBroker(t, config)
	adapter, err := NewControllerAdapter(
		broker,
		broker.(LiveHistory),
		config.Repositories,
		config.TransientMode,
	)
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}
	next := controller.AcquisitionPolicy{
		Mode:                     controller.AcquisitionEnabled,
		EligibleScaleSets:        []string{"scale-a"},
		MaxCapacity:              1,
		RepositoryPolicyRevision: 2,
		RepositoryPolicies: []controller.RepositoryPolicySummary{{
			Alias:          "repo-a",
			MaxConcurrency: 2,
			Eligibility:    string(EligibilityPendingReactivation),
		}},
		Epoch: 2,
	}
	if err := adapter.ApplyAcquisitionPolicy(next); err != nil {
		t.Fatalf("ApplyAcquisitionPolicy: %v", err)
	}
	impl := implementation(t, broker)
	got := impl.policies["repo-a"]
	if got.Weight != template.Weight ||
		got.AgingThreshold != template.AgingThreshold ||
		got.Profile != template.Profile ||
		got.MaxConcurrency != 2 ||
		got.Eligibility != EligibilityPendingReactivation {
		t.Fatalf("overlaid policy = %+v, template = %+v", got, template)
	}
	summary := adapter.CapacitySummary()
	if summary.Epoch != 2 ||
		summary.ConfiguredCapacity != 3 ||
		summary.EffectiveCapacity != 1 {
		t.Fatalf("CapacitySummary = %+v", summary)
	}
	if err := adapter.SetDemand("repo-a", 1, 1); !errors.Is(err, controller.ErrAdmissionConflict) {
		t.Fatalf("SetDemand(stale epoch) = %v, want ErrAdmissionConflict", err)
	}
	if err := adapter.SetDemand("repo-a", 2, 1); err != nil {
		t.Fatalf("SetDemand(current epoch): %v", err)
	}

	changedAlias := next
	changedAlias.Epoch = 3
	changedAlias.RepositoryPolicies = []controller.RepositoryPolicySummary{{
		Alias:          "repo-b",
		MaxConcurrency: 1,
		Eligibility:    string(EligibilityActive),
	}}
	if err := adapter.ApplyAcquisitionPolicy(changedAlias); !errors.Is(
		err,
		controller.ErrAdmissionConflict,
	) {
		t.Fatalf("ApplyAcquisitionPolicy(changed alias) = %v, want ErrAdmissionConflict", err)
	}
	if got := adapter.CapacitySummary().Epoch; got != 2 {
		t.Fatalf("epoch after rejected alias change = %d, want 2", got)
	}
}
