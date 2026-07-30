package testenv

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/state"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestTask11SyntheticRestartAggregateSealsEveryOrderedChild(
	t *testing.T,
) {
	t.Parallel()

	parent, children := validTask11SyntheticRestartChildren(t)
	builder, err := newTask11SyntheticRestartAggregateBuilder(parent)
	if err != nil {
		t.Fatalf("new aggregate builder: %v", err)
	}
	for index, child := range children {
		if err := builder.appendSuccess(child); err != nil {
			t.Fatalf("append child %d: %v", index, err)
		}
	}
	evidence, err := builder.seal()
	if err != nil {
		t.Fatalf("seal aggregate: %v", err)
	}
	if !validTask11SyntheticRestartAggregateEvidence(evidence) {
		t.Fatalf("aggregate evidence = %+v", evidence)
	}
	if evidence.proof.AssertionCount !=
		uint64(len(task11synthetic.RestartSetupStages())*13) ||
		evidence.proof.PayloadVersionCount != 1 ||
		!isLowerHex(evidence.proof.ObservationDigest, 64) {
		t.Fatalf("aggregate proof = %+v", evidence.proof)
	}
	if _, err := SealCompleteCleanup(evidence.proof); err != nil {
		t.Fatalf("public cleanup seal: %v", err)
	}
}

func TestTask11SyntheticRestartAggregateRejectsIncompleteOrFailurePath(
	t *testing.T,
) {
	t.Parallel()

	parent, children := validTask11SyntheticRestartChildren(t)
	incomplete, err := newTask11SyntheticRestartAggregateBuilder(parent)
	if err != nil {
		t.Fatalf("new incomplete builder: %v", err)
	}
	for _, child := range children[:len(children)-1] {
		if err := incomplete.appendSuccess(child); err != nil {
			t.Fatalf("append incomplete child: %v", err)
		}
	}
	if _, err := incomplete.seal(); err == nil {
		t.Fatal("incomplete aggregate sealed")
	}

	failed, err := newTask11SyntheticRestartAggregateBuilder(parent)
	if err != nil {
		t.Fatalf("new failed builder: %v", err)
	}
	if err := failed.appendSuccess(children[0]); err != nil {
		t.Fatalf("append first child: %v", err)
	}
	failed.fail()
	if err := failed.appendSuccess(children[1]); err == nil {
		t.Fatal("failed builder accepted child")
	}
	if _, err := failed.seal(); err == nil {
		t.Fatal("failed builder sealed")
	}
}

func TestTask11SyntheticRestartAggregateRejectsDriftedPrivateEvidence(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(
		*task11SyntheticRestartAggregateEvidence,
	){
		"child order": func(value *task11SyntheticRestartAggregateEvidence) {
			value.children[0], value.children[1] =
				value.children[1], value.children[0]
		},
		"child observation": func(value *task11SyntheticRestartAggregateEvidence) {
			value.children[0].cleanup.proof.ObservationDigest =
				strings.Repeat("f", 64)
		},
		"borrowed child": func(value *task11SyntheticRestartAggregateEvidence) {
			value.children[1].cleanup =
				value.children[0].cleanup
		},
		"completion": func(value *task11SyntheticRestartAggregateEvidence) {
			value.children[0].completion.terminalOfferReplay = false
		},
		"removal": func(value *task11SyntheticRestartAggregateEvidence) {
			value.children[0].removal.allRemoved = false
		},
		"aggregate count": func(value *task11SyntheticRestartAggregateEvidence) {
			value.proof.AssertionCount = 13
		},
		"aggregate digest": func(value *task11SyntheticRestartAggregateEvidence) {
			value.proof.ObservationDigest = strings.Repeat("e", 64)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			evidence := validTask11SyntheticRestartAggregate(t)
			mutate(&evidence)
			if validTask11SyntheticRestartAggregateEvidence(evidence) {
				t.Fatal("drifted aggregate evidence was accepted")
			}
		})
	}
}

func TestTask11SyntheticRestartPrivateTokensRejectFalseSuccess(t *testing.T) {
	t.Parallel()

	_, children := validTask11SyntheticRestartChildren(t)
	child := children[0]
	if _, err := newTask11SyntheticRestartSuccessCompletion(
		child.cycle,
		state.OfferReceipt{
			Key:         child.completion.assignmentKey,
			Disposition: state.OfferActiveReplay,
			State:       controller.StateDestroyed,
		},
		state.EffectRecord{State: state.EffectAbsent},
	); err == nil {
		t.Fatal("active replay minted success completion")
	}
	if _, err := newTask11SyntheticRestartSuccessCompletion(
		child.cycle,
		state.OfferReceipt{
			Key:         child.completion.assignmentKey,
			Disposition: state.OfferTerminalReplay,
			State:       controller.StateDestroyed,
		},
		state.EffectRecord{State: state.EffectCompleted},
	); err == nil {
		t.Fatal("listener effect minted pre-release completion")
	}

	rootHandle, err := task11CycleRootHandle(child.cycle)
	if err != nil {
		t.Fatalf("root handle: %v", err)
	}
	if _, err := newTask11SyntheticCycleRemovalSnapshot(
		child.cycle,
		[]cleanupHandle{rootHandle},
		func(cleanupHandle) bool { return false },
	); err == nil {
		t.Fatal("unremoved handle minted removal snapshot")
	}
}

func validTask11SyntheticRestartAggregate(
	t *testing.T,
) task11SyntheticRestartAggregateEvidence {
	t.Helper()

	parent, children := validTask11SyntheticRestartChildren(t)
	builder, err := newTask11SyntheticRestartAggregateBuilder(parent)
	if err != nil {
		t.Fatalf("new aggregate builder: %v", err)
	}
	for index, child := range children {
		if err := builder.appendSuccess(child); err != nil {
			t.Fatalf("append child %d: %v", index, err)
		}
	}
	evidence, err := builder.seal()
	if err != nil {
		t.Fatalf("seal aggregate: %v", err)
	}
	return evidence
}

func validTask11SyntheticRestartChildren(
	t *testing.T,
) (
	task11SyntheticCycleIdentity,
	[]task11SyntheticRestartChildEvidence,
) {
	t.Helper()

	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primaryRunDigest := strings.Repeat("a", 64)
	parent, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		task11SyntheticCycleRequest{
			Kind: task11CycleCleanupControllerRestart,
		},
	)
	if err != nil {
		t.Fatalf("derive restart parent: %v", err)
	}
	stages := task11synthetic.RestartSetupStages()
	children := make(
		[]task11SyntheticRestartChildEvidence,
		0,
		len(stages),
	)
	for index, stage := range stages {
		cycle, err := deriveTask11SyntheticRestartStageIdentity(
			primaryRoot,
			primaryRunDigest,
			parent,
			stage,
			uint64(index),
		)
		if err != nil {
			t.Fatalf("derive child %d: %v", index, err)
		}
		binding := task11SyntheticCleanupObserverBinding{
			PrimaryRoot:      primaryRoot,
			PrimaryRunDigest: primaryRunDigest,
			Cycle:            cycle,
			Recovery: hostruntime.RecoverySpec{
				SlotIdentity:      cycle.Composition.SlotIdentity,
				BuildID:           strings.Repeat("b", 64),
				FleetGeneration:   7,
				AdapterName:       cycle.Composition.AdapterName,
				BrokerName:        cycle.Composition.BrokerName,
				RunnerName:        cycle.Composition.RunnerName,
				ExpectedAdapterID: task11RestartTestDigest("adapter", index),
				ExpectedBrokerID:  task11RestartTestDigest("broker", index),
				ExpectedRunnerID:  task11RestartTestDigest("runner", index),
				RelayParent:       filepath.Join(cycle.Root, "relay"),
				AuthorityParent:   filepath.Join(cycle.Root, "authority"),
			},
			Expected: hostruntime.ManagedObservation{
				AdapterPresent: true,
				AdapterRunning: true,
				BrokerPresent:  true,
				BrokerRunning:  true,
				RunnerPresent:  true,
				RunnerRunning:  true,
			},
			CapacitySlotID:         cycle.Composition.CapacitySlotID,
			JobGeneration:          cycle.Composition.JobGeneration,
			CgroupVersion:          task11synthetic.CgroupV2,
			MaximumProcesses:       16,
			MaximumFileDescriptors: 32,
			Cadence:                10 * time.Millisecond,
			Deadline:               time.Second,
			PayloadVersionCount:    1,
			AuthorityExpected:      true,
			RelaySocketExpected:    true,
		}
		observation := task11synthetic.CleanupObservation{
			SchemaVersion:           task11synthetic.SchemaVersion,
			ProtocolID:              task11synthetic.ProtocolID,
			CycleRunDigest:          cycle.RunDigest,
			CleanupDigest:           cycle.CleanupDigest,
			CgroupVersion:           task11synthetic.CgroupV2,
			ContainersAbsent:        true,
			CgroupsAbsent:           true,
			TmpfsAbsent:             true,
			WorkAbsent:              true,
			WorkUpdateAbsent:        true,
			ProcessesAbsent:         true,
			NamespacesAbsent:        true,
			SocketsAbsent:           true,
			AuthoritiesAbsent:       true,
			TemporaryFilesAbsent:    true,
			HostBackedWorkAbsent:    true,
			UnexpectedObjectsAbsent: true,
			PayloadVersionCount:     1,
			AssertionCount:          13,
		}
		digest, err :=
			task11synthetic.DeriveCleanupObservationDigest(observation)
		if err != nil {
			t.Fatalf("derive child observation %d: %v", index, err)
		}
		proof := CompleteCleanupProof{
			ContainersAbsent:        true,
			CgroupsAbsent:           true,
			TmpfsAbsent:             true,
			WorkAbsent:              true,
			WorkUpdateAbsent:        true,
			ProcessesAbsent:         true,
			NamespacesAbsent:        true,
			SocketsAbsent:           true,
			AuthoritiesAbsent:       true,
			TemporaryFilesAbsent:    true,
			HostBackedWorkAbsent:    true,
			UnexpectedObjectsAbsent: true,
			PayloadVersionCount:     1,
			AssertionCount:          13,
			ObservationDigest:       digest,
		}
		var structural [sha256.Size]byte
		structural[0] = byte(index + 1)
		cleanup := task11SyntheticProvedCleanup{
			binding:        binding,
			observation:    observation,
			proof:          proof,
			structuralSeal: structural,
			outcomeKind:    task11CleanupOutcomeNoListener,
			outcomeDigest:  task11RestartTestDigest("outcome", index),
		}
		assignmentKey := controller.AssignmentKey{
			RepositoryAlias: "portable-ghar-conformance",
			RunnerRequestID: cycle.Composition.RunnerRequestID,
			Attempt:         0,
		}
		completion, err := newTask11SyntheticRestartSuccessCompletion(
			cycle,
			state.OfferReceipt{
				Key:         assignmentKey,
				Disposition: state.OfferTerminalReplay,
				State:       controller.StateDestroyed,
			},
			state.EffectRecord{State: state.EffectAbsent},
		)
		if err != nil {
			t.Fatalf("new completion %d: %v", index, err)
		}
		rootHandle, err := task11CycleRootHandle(cycle)
		if err != nil {
			t.Fatalf("root handle %d: %v", index, err)
		}
		removal, err := newTask11SyntheticCycleRemovalSnapshot(
			cycle,
			[]cleanupHandle{rootHandle},
			func(handle cleanupHandle) bool {
				return handle == rootHandle
			},
		)
		if err != nil {
			t.Fatalf("new removal snapshot %d: %v", index, err)
		}
		children = append(children, task11SyntheticRestartChildEvidence{
			stage:            stage,
			declarationIndex: uint64(index),
			cycle:            cycle,
			cleanup:          cleanup,
			completion:       completion,
			removal:          removal,
		})
	}
	return parent, children
}

func task11RestartTestDigest(label string, index int) string {
	value := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", label, index)))
	return hex.EncodeToString(value[:])
}
