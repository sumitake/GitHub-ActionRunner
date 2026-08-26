package testenv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

type task11SyntheticRestartJournalFake struct {
	completed []networkjail.SetupStage
	effect    state.EffectRecord
	err       error
}

func (fake *task11SyntheticRestartJournalFake) Before(
	context.Context,
	controller.AssignmentKey,
	networkjail.SetupStage,
) error {
	return nil
}

func (*task11SyntheticRestartJournalFake) BeforeListenerRelease(
	context.Context,
	controller.AssignmentKey,
	[32]byte,
) error {
	return errors.New("unexpected listener release")
}

func (fake *task11SyntheticRestartJournalFake) Complete(
	_ context.Context,
	_ controller.AssignmentKey,
	stage networkjail.SetupStage,
	result networkjail.JournalResult,
) error {
	if fake.err != nil {
		return fake.err
	}
	fake.completed = append(fake.completed, stage)
	fake.effect = state.EffectRecord{
		State:          state.EffectCompleted,
		ResultIdentity: result.Identity,
	}
	return nil
}

func (*task11SyntheticRestartJournalFake) CompleteListenerRelease(
	context.Context,
	controller.AssignmentKey,
	[32]byte,
) error {
	return errors.New("unexpected listener release")
}

func (fake *task11SyntheticRestartJournalFake) Advance(
	context.Context,
	controller.AssignmentKey,
	controller.State,
) error {
	return nil
}

func (fake *task11SyntheticRestartJournalFake) MarkAmbiguous(
	context.Context,
	controller.AssignmentKey,
) error {
	return nil
}

func (fake *task11SyntheticRestartJournalFake) LookupAssignmentEffect(
	context.Context,
	controller.AssignmentKey,
	string,
) (state.EffectRecord, error) {
	if fake.err != nil {
		return state.EffectRecord{}, fake.err
	}
	return fake.effect, nil
}

func TestTask11SyntheticRestartCheckpointsMatchProductionStageOrder(t *testing.T) {
	t.Parallel()
	expectedStates := []controller.State{
		controller.StateCapacityReserved,
		controller.StateAdapterCreated,
		controller.StateAdapterVerified,
		controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateBrokerReleased,
		controller.StateEgressVerified,
		controller.StateRunnerHeld,
		controller.StateRunnerHeld,
		controller.StateRunnerHeld,
		controller.StateRunnerHeld,
		controller.StateRunnerHeld,
		controller.StateRunnerHeld,
	}
	stages := task11synthetic.RestartSetupStages()
	if len(stages) != len(expectedStates) {
		t.Fatalf("restart stage count = %d", len(stages))
	}
	for index, stage := range stages {
		checkpoint, err := task11SyntheticRestartCheckpointAt(
			stage,
			uint64(index),
		)
		if err != nil {
			t.Fatalf("checkpoint %d: %v", index, err)
		}
		expected := hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
		}
		if index >= 2 {
			expected.BrokerPresent = true
			expected.BrokerRunning = true
		}
		if index >= 9 {
			expected.RunnerPresent = true
			expected.RunnerRunning = true
		}
		if checkpoint.ProtocolStage != stage ||
			checkpoint.DeclarationIndex != uint64(index) ||
			checkpoint.JournalStage.String() != string(stage) ||
			checkpoint.State != expectedStates[index] ||
			checkpoint.Expected != expected ||
			checkpoint.AuthorityExpected != (index >= 4) ||
			checkpoint.RelaySocketExpected != (index >= 6) {
			t.Fatalf("checkpoint %d drifted: %+v", index, checkpoint)
		}
	}
	if _, err := task11SyntheticRestartCheckpointAt(
		stages[0],
		1,
	); err == nil {
		t.Fatal("restart checkpoint accepted a wrong declaration index")
	}
}

func TestTask11SyntheticRestartJournalResultIsStageClosed(t *testing.T) {
	t.Parallel()
	identities := hostruntime.RecoveredIdentities{
		AdapterID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BrokerID:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RunnerID:  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	policy := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	stages := task11synthetic.RestartSetupStages()
	for index, stage := range stages {
		checkpoint, err := task11SyntheticRestartCheckpointAt(
			stage,
			uint64(index),
		)
		if err != nil {
			t.Fatalf("checkpoint %d: %v", index, err)
		}
		got, err := checkpoint.expectedJournalResult(identities, policy)
		if err != nil {
			t.Fatalf("journal result %d: %v", index, err)
		}
		want := networkjail.JournalResult{}
		switch stage {
		case task11synthetic.SetupStageAdapterCreate:
			want = networkjail.JournalResult{
				Identity: identities.AdapterID,
				Column:   networkjail.JournalIdentityAdapter,
			}
		case task11synthetic.SetupStageBrokerCreate:
			want = networkjail.JournalResult{
				Identity: identities.BrokerID,
				Column:   networkjail.JournalIdentityBroker,
			}
		case task11synthetic.SetupStagePolicyApply:
			want = networkjail.JournalResult{
				Identity: policy,
				Column:   networkjail.JournalIdentityPolicy,
			}
		case task11synthetic.SetupStageRunnerCreate:
			want = networkjail.JournalResult{
				Identity: identities.RunnerID,
				Column:   networkjail.JournalIdentityRunner,
			}
		}
		if got != want {
			t.Fatalf("journal result %d = %+v, want %+v", index, got, want)
		}
	}
}

func TestTask11SyntheticRestartJournalCrashesOnlyAfterDurableReadback(
	t *testing.T,
) {
	t.Parallel()
	checkpoint, err := task11SyntheticRestartCheckpointAt(
		task11synthetic.SetupStageAdapterCreate,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	key := controller.AssignmentKey{
		RepositoryAlias: "portable-ghar-conformance",
		RunnerRequestID: 17,
	}
	fake := &task11SyntheticRestartJournalFake{}
	journal, err := newTask11SyntheticRestartJournal(
		fake,
		fake,
		key,
		checkpoint,
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	)
	if err != nil {
		t.Fatal(err)
	}
	result := networkjail.JournalResult{
		Identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Column:   networkjail.JournalIdentityAdapter,
	}
	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		_ = journal.Complete(
			context.Background(),
			key,
			networkjail.StageAdapterCreate,
			result,
		)
	}()
	want := task11SyntheticRestartSentinel{
		stage:            task11synthetic.SetupStageAdapterCreate,
		declarationIndex: 0,
	}
	if recovered != want ||
		!journal.didFire() ||
		len(fake.completed) != 1 ||
		fake.completed[0] != networkjail.StageAdapterCreate {
		t.Fatalf(
			"restart crash did not bind durable completion: recovered=%#v completed=%v",
			recovered,
			fake.completed,
		)
	}
}

func TestTask11SyntheticRestartJournalDoesNotCrashBeforeReadback(
	t *testing.T,
) {
	t.Parallel()
	checkpoint, err := task11SyntheticRestartCheckpointAt(
		task11synthetic.SetupStageAdapterCreate,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	key := controller.AssignmentKey{
		RepositoryAlias: "portable-ghar-conformance",
		RunnerRequestID: 18,
	}
	fake := &task11SyntheticRestartJournalFake{
		err: errors.New("readback unavailable"),
	}
	journal, err := newTask11SyntheticRestartJournal(
		fake,
		fake,
		key,
		checkpoint,
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	)
	if err != nil {
		t.Fatal(err)
	}
	err = journal.Complete(
		context.Background(),
		key,
		networkjail.StageAdapterCreate,
		networkjail.JournalResult{
			Identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Column:   networkjail.JournalIdentityAdapter,
		},
	)
	if !errors.Is(err, fake.err) || journal.didFire() {
		t.Fatalf("journal error = %v, fired=%v", err, journal.didFire())
	}
}

func TestTask11SyntheticRestartRecoveryBindsExactDurableRow(
	t *testing.T,
) {
	t.Parallel()
	primaryRoot := t.TempDir()
	primary, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		"1111111111111111111111111111111111111111111111111111111111111111",
		task11SyntheticCycleRequest{
			Kind: task11CycleCleanupControllerRestart,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := deriveTask11SyntheticRestartStageIdentity(
		primaryRoot,
		"1111111111111111111111111111111111111111111111111111111111111111",
		primary,
		task11synthetic.SetupStageBrokerCreate,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := compositionPlan{
		Identity: cycle.Composition,
		AssignmentKey: controller.AssignmentKey{
			RepositoryAlias: "portable-ghar-conformance",
			RunnerRequestID: cycle.Composition.RunnerRequestID,
		},
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	offer, _, err := compositionOfferFrom(plan, now)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := task11SyntheticRestartCheckpointAt(
		task11synthetic.SetupStageBrokerCreate,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := hostruntime.RecoveredIdentities{
		AdapterID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BrokerID:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	row := state.RecoverableAssignment{
		Key:       plan.AssignmentKey,
		State:     checkpoint.State,
		Offer:     offer,
		UpdatedAt: now,
		Slot: controller.RunnerSlot{
			OpaqueName:         cycle.Composition.SlotIdentity,
			CapacitySlotID:     cycle.Composition.CapacitySlotID,
			AdapterContainerID: want.AdapterID,
			BrokerContainerID:  want.BrokerID,
		},
	}
	got, err := checkpoint.recoveredIdentities(
		cycle,
		plan,
		offer,
		[]state.RecoverableAssignment{row},
	)
	if err != nil || got != want {
		t.Fatalf("recovered identities = %+v err=%v", got, err)
	}
	row.Slot.UpstreamRunnerID = 1
	if _, err := checkpoint.recoveredIdentities(
		cycle,
		plan,
		offer,
		[]state.RecoverableAssignment{row},
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("upstream-bound recovery error = %v", err)
	}
}
