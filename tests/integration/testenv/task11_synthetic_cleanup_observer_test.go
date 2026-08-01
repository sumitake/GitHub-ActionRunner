package testenv

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

type fakeTask11SyntheticCleanupProbe struct {
	capture       task11SyntheticCleanupCapture
	outcome       task11SyntheticCleanupOutcomeSeal
	observation   task11synthetic.CleanupObservation
	armCalls      int
	proveCalls    int
	armError      error
	proveError    error
	cleanupAbsent bool
}

func (p *fakeTask11SyntheticCleanupProbe) ArmStructural(
	ctx context.Context,
	_ task11SyntheticCleanupObserverBinding,
	_ hostruntime.ManagedSnapshot,
) (task11SyntheticCleanupCapture, error) {
	if ctx == nil || ctx.Err() != nil {
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	p.armCalls++
	if p.armError != nil {
		return task11SyntheticCleanupCapture{}, p.armError
	}
	return p.capture, nil
}

func (p *fakeTask11SyntheticCleanupProbe) Prove(
	ctx context.Context,
	_ task11SyntheticCleanupObserverBinding,
	capture task11SyntheticCleanupCapture,
	outcome task11SyntheticCleanupOutcomeSeal,
) (task11synthetic.CleanupObservation, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		capture != p.capture ||
		outcome.bindingDigest != capture.bindingDigest ||
		outcome.structuralSeal != capture.seal ||
		(outcome.kind != task11CleanupOutcomeListener &&
			outcome.kind != task11CleanupOutcomeNoListener) ||
		!isLowerHex(outcome.digest, 64) {
		return task11synthetic.CleanupObservation{}, ErrFixtureCleanup
	}
	p.outcome = outcome
	p.proveCalls++
	if p.proveError != nil || !p.cleanupAbsent {
		if p.proveError != nil {
			return task11synthetic.CleanupObservation{}, p.proveError
		}
		return task11synthetic.CleanupObservation{}, ErrFixtureCleanup
	}
	return p.observation, nil
}

func TestTask11SyntheticCleanupObserverIsOneUseFourPhase(t *testing.T) {
	t.Parallel()

	binding := validTask11SyntheticCleanupObserverBinding(t)
	probe := validTask11SyntheticCleanupProbe(t, binding)
	observer, err := newTask11SyntheticCleanupObserver(binding, probe)
	if err != nil {
		t.Fatalf("newTask11SyntheticCleanupObserver: %v", err)
	}
	if _, err := observer.Prove(
		context.Background(),
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("pre-arm prove error = %v", err)
	}

	observer, err = newTask11SyntheticCleanupObserver(binding, probe)
	if err != nil {
		t.Fatalf("new observer after pre-arm probe: %v", err)
	}
	if err := observer.ArmStructural(
		context.Background(),
		hostruntime.ManagedSnapshot{},
	); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if probe.armCalls != 1 {
		t.Fatalf("arm calls = %d", probe.armCalls)
	}
	if err := observer.SealListenerOutcome(
		context.Background(),
		validTask11SyntheticListenerOutcome(t, binding),
	); err != nil {
		t.Fatalf("SealListenerOutcome: %v", err)
	}

	probe.cleanupAbsent = true
	proof, err := observer.Prove(context.Background())
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if _, err := SealCompleteCleanup(proof); err != nil {
		t.Fatalf("SealCompleteCleanup: %v", err)
	}
	if proof.AssertionCount != 13 ||
		proof.ObservationDigest == "" ||
		proof.ObservationDigest !=
			mustTask11CleanupObservationDigest(
				t,
				probe.observation,
			) {
		t.Fatalf("proof = %+v", proof)
	}
	if probe.proveCalls != 1 {
		t.Fatalf("prove calls = %d", probe.proveCalls)
	}
	if _, err := observer.Prove(
		context.Background(),
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("second Prove error = %v", err)
	}
	if err := observer.ArmStructural(
		context.Background(),
		hostruntime.ManagedSnapshot{},
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("post-proof Arm error = %v", err)
	}
}

func TestTask11SyntheticCleanupObserverFailureIsTerminal(t *testing.T) {
	t.Parallel()

	for _, phase := range []string{"arm", "prove"} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			t.Parallel()

			binding := validTask11SyntheticCleanupObserverBinding(t)
			probe := validTask11SyntheticCleanupProbe(t, binding)
			if phase == "arm" {
				probe.armError = ErrFixtureStart
			}
			observer, err := newTask11SyntheticCleanupObserver(
				binding,
				probe,
			)
			if err != nil {
				t.Fatalf("new observer: %v", err)
			}
			armErr := observer.ArmStructural(
				context.Background(),
				hostruntime.ManagedSnapshot{},
			)
			if phase == "arm" {
				if !errors.Is(armErr, ErrFixtureStart) {
					t.Fatalf("arm error = %v", armErr)
				}
			} else {
				if armErr != nil {
					t.Fatalf("Arm: %v", armErr)
				}
				if err := observer.SealListenerOutcome(
					context.Background(),
					validTask11SyntheticListenerOutcome(
						t,
						binding,
					),
				); err != nil {
					t.Fatalf("SealListenerOutcome: %v", err)
				}
				if _, err := observer.Prove(
					context.Background(),
				); !errors.Is(err, ErrFixtureCleanup) {
					t.Fatalf("live Prove error = %v", err)
				}
			}
			if err := observer.ArmStructural(
				context.Background(),
				hostruntime.ManagedSnapshot{},
			); err == nil {
				t.Fatal("failed observer accepted a new arm")
			}
			if _, err := observer.Prove(
				context.Background(),
			); err == nil {
				t.Fatal("failed observer accepted a new proof")
			}
		})
	}
}

func TestTask11SyntheticCleanupObserverRejectsSubstitutedObservation(
	t *testing.T,
) {
	t.Parallel()

	mutations := map[string]func(*task11synthetic.CleanupObservation){
		"cycle": func(value *task11synthetic.CleanupObservation) {
			value.CycleRunDigest = strings.Repeat("f", 64)
		},
		"cleanup": func(value *task11synthetic.CleanupObservation) {
			value.CleanupDigest = strings.Repeat("f", 64)
		},
		"cgroup": func(value *task11synthetic.CleanupObservation) {
			value.CgroupVersion = task11synthetic.CgroupV1
		},
		"missing catalog": func(value *task11synthetic.CleanupObservation) {
			value.WorkUpdateAbsent = false
		},
		"payload count": func(value *task11synthetic.CleanupObservation) {
			value.PayloadVersionCount = 2
		},
		"assertion count": func(value *task11synthetic.CleanupObservation) {
			value.AssertionCount = 12
		},
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			binding := validTask11SyntheticCleanupObserverBinding(t)
			probe := validTask11SyntheticCleanupProbe(t, binding)
			mutate(&probe.observation)
			probe.cleanupAbsent = true
			observer, err := newTask11SyntheticCleanupObserver(
				binding,
				probe,
			)
			if err != nil {
				t.Fatalf("new observer: %v", err)
			}
			if err := observer.ArmStructural(
				context.Background(),
				hostruntime.ManagedSnapshot{},
			); err != nil {
				t.Fatalf("Arm: %v", err)
			}
			if err := observer.SealListenerOutcome(
				context.Background(),
				validTask11SyntheticListenerOutcome(
					t,
					binding,
				),
			); err != nil {
				t.Fatalf("SealListenerOutcome: %v", err)
			}
			if _, err := observer.Prove(
				context.Background(),
			); !errors.Is(err, ErrFixtureCleanup) {
				t.Fatalf("substituted proof error = %v", err)
			}
			if _, err := observer.Prove(
				context.Background(),
			); err == nil {
				t.Fatal("substituted proof was retryable")
			}
		})
	}
}

func TestTask11SyntheticCleanupObserverRejectsOpenBinding(t *testing.T) {
	t.Parallel()

	valid := validTask11SyntheticCleanupObserverBinding(t)
	tests := map[string]func(*task11SyntheticCleanupObserverBinding){
		"relative primary": func(value *task11SyntheticCleanupObserverBinding) {
			value.PrimaryRoot = "relative"
		},
		"cycle root drift": func(value *task11SyntheticCleanupObserverBinding) {
			value.Cycle.Root += "-drift"
		},
		"cleanup drift": func(value *task11SyntheticCleanupObserverBinding) {
			value.Cycle.CleanupDigest = strings.Repeat("f", 64)
		},
		"recovery slot drift": func(value *task11SyntheticCleanupObserverBinding) {
			value.Recovery.SlotIdentity += "-drift"
		},
		"recovery parent drift": func(value *task11SyntheticCleanupObserverBinding) {
			value.Recovery.RelayParent = value.PrimaryRoot
		},
		"zero maximum processes": func(value *task11SyntheticCleanupObserverBinding) {
			value.MaximumProcesses = 0
		},
		"zero maximum descriptors": func(value *task11SyntheticCleanupObserverBinding) {
			value.MaximumFileDescriptors = 0
		},
		"zero cadence": func(value *task11SyntheticCleanupObserverBinding) {
			value.Cadence = 0
		},
		"zero deadline": func(value *task11SyntheticCleanupObserverBinding) {
			value.Deadline = 0
		},
		"unknown cgroup": func(value *task11SyntheticCleanupObserverBinding) {
			value.CgroupVersion = "3"
		},
		"invalid inventory": func(value *task11SyntheticCleanupObserverBinding) {
			value.Expected = hostruntime.ManagedObservation{
				RunnerPresent: true,
				RunnerRunning: true,
			}
		},
		"relay socket without broker": func(value *task11SyntheticCleanupObserverBinding) {
			value.AuthorityExpected = false
			value.Expected.BrokerPresent = false
			value.Expected.BrokerRunning = false
			value.Expected.RunnerPresent = false
			value.Expected.RunnerRunning = false
			value.Recovery.ExpectedBrokerID = ""
			value.Recovery.ExpectedRunnerID = ""
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			candidate := valid
			mutate(&candidate)
			if _, err := newTask11SyntheticCleanupObserver(
				candidate,
				validTask11SyntheticCleanupProbe(t, candidate),
			); err == nil {
				t.Fatal("invalid observer binding was accepted")
			}
		})
	}
	if _, err := newTask11SyntheticCleanupObserver(valid, nil); err == nil {
		t.Fatal("nil cleanup probe was accepted")
	}
}

func TestTask11SyntheticCleanupObserverAcceptsExactStoppedRunnerState(t *testing.T) {
	t.Parallel()

	binding := validTask11SyntheticCleanupObserverBinding(t)
	binding.Expected.RunnerRunning = false
	if _, err := newTask11SyntheticCleanupObserver(
		binding,
		validTask11SyntheticCleanupProbe(t, binding),
	); err != nil {
		t.Fatalf("stopped but present runner was rejected: %v", err)
	}

	binding.Expected.RunnerPresent = false
	binding.Expected.RunnerRunning = true
	binding.Recovery.ExpectedRunnerID = ""
	if _, err := newTask11SyntheticCleanupObserver(
		binding,
		validTask11SyntheticCleanupProbe(t, binding),
	); err == nil {
		t.Fatal("running but absent runner was admitted")
	}
}

func TestTask11SyntheticCleanupObserverAcceptsExactRestartChildBinding(
	t *testing.T,
) {
	t.Parallel()

	binding := validTask11SyntheticCleanupObserverBinding(t)
	parent, err := deriveTask11SyntheticCycleIdentity(
		binding.PrimaryRoot,
		binding.PrimaryRunDigest,
		task11SyntheticCycleRequest{
			Kind: task11CycleCleanupControllerRestart,
		},
	)
	if err != nil {
		t.Fatalf("derive restart parent: %v", err)
	}
	stage := task11synthetic.RestartSetupStages()[4]
	child, err := deriveTask11SyntheticRestartStageIdentity(
		binding.PrimaryRoot,
		binding.PrimaryRunDigest,
		parent,
		stage,
		4,
	)
	if err != nil {
		t.Fatalf("derive restart child: %v", err)
	}
	binding.Cycle = child
	binding.Recovery.SlotIdentity = child.Composition.SlotIdentity
	binding.Recovery.AdapterName = child.Composition.AdapterName
	binding.Recovery.BrokerName = child.Composition.BrokerName
	binding.Recovery.RunnerName = child.Composition.RunnerName
	binding.Recovery.RelayParent = filepath.Join(child.Root, "relay")
	binding.Recovery.AuthorityParent = filepath.Join(child.Root, "authority")
	binding.CapacitySlotID = child.Composition.CapacitySlotID
	binding.JobGeneration = child.Composition.JobGeneration
	if _, err := newTask11SyntheticCleanupObserver(
		binding,
		validTask11SyntheticCleanupProbe(t, binding),
	); err != nil {
		t.Fatalf("exact restart child binding: %v", err)
	}

	binding.Cycle.Restart.DeclarationIndex++
	if _, err := newTask11SyntheticCleanupObserver(
		binding,
		validTask11SyntheticCleanupProbe(t, binding),
	); err == nil {
		t.Fatal("drifted restart child binding was accepted")
	}
}

func validTask11SyntheticCleanupObserverBinding(
	t *testing.T,
) task11SyntheticCleanupObserverBinding {
	t.Helper()

	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	cycle, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		strings.Repeat("a", 64),
		task11SyntheticCycleRequest{Kind: task11CycleCleanupSuccess},
	)
	if err != nil {
		t.Fatalf("derive cycle: %v", err)
	}
	return task11SyntheticCleanupObserverBinding{
		PrimaryRoot:      primaryRoot,
		PrimaryRunDigest: strings.Repeat("a", 64),
		Cycle:            cycle,
		Recovery: hostruntime.RecoverySpec{
			SlotIdentity:      cycle.Composition.SlotIdentity,
			BuildID:           strings.Repeat("b", 64),
			FleetGeneration:   29,
			AdapterName:       cycle.Composition.AdapterName,
			BrokerName:        cycle.Composition.BrokerName,
			RunnerName:        cycle.Composition.RunnerName,
			ExpectedAdapterID: strings.Repeat("c", 64),
			ExpectedBrokerID:  strings.Repeat("d", 64),
			ExpectedRunnerID:  strings.Repeat("e", 64),
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
}

func validTask11SyntheticCleanupProbe(
	t *testing.T,
	binding task11SyntheticCleanupObserverBinding,
) *fakeTask11SyntheticCleanupProbe {
	t.Helper()

	capture, err := newTask11SyntheticCleanupCapture(
		binding,
		[32]byte{1, 2, 3},
	)
	if err != nil {
		t.Fatalf("newTask11SyntheticCleanupCapture: %v", err)
	}
	return &fakeTask11SyntheticCleanupProbe{
		capture: capture,
		observation: task11synthetic.CleanupObservation{
			SchemaVersion:           task11synthetic.SchemaVersion,
			ProtocolID:              task11synthetic.ProtocolID,
			CycleRunDigest:          binding.Cycle.RunDigest,
			CleanupDigest:           binding.Cycle.CleanupDigest,
			CgroupVersion:           binding.CgroupVersion,
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
		},
	}
}

func mustTask11CleanupObservationDigest(
	t *testing.T,
	observation task11synthetic.CleanupObservation,
) string {
	t.Helper()
	digest, err := task11synthetic.DeriveCleanupObservationDigest(
		observation,
	)
	if err != nil {
		t.Fatalf("DeriveCleanupObservationDigest: %v", err)
	}
	return digest
}
