package testenv

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestTask11SyntheticCleanupObserverRequiresOutcomeSealBeforeProof(
	t *testing.T,
) {
	t.Parallel()

	binding := validTask11SyntheticCleanupObserverBinding(t)
	probe := validTask11SyntheticCleanupProbe(t, binding)
	observer, err := newTask11SyntheticCleanupObserver(binding, probe)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	if err := observer.ArmStructural(
		context.Background(),
		hostruntime.ManagedSnapshot{},
	); err != nil {
		t.Fatalf("ArmStructural: %v", err)
	}
	probe.cleanupAbsent = true
	if _, err := observer.Prove(
		context.Background(),
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("proof before outcome seal error = %v", err)
	}
	if err := observer.SealListenerOutcome(
		context.Background(),
		validTask11SyntheticListenerOutcome(t, binding),
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("seal after failed proof error = %v", err)
	}
}

func TestTask11SyntheticCleanupObserverContextFailureIsTerminal(
	t *testing.T,
) {
	t.Parallel()

	for _, phase := range []string{"arm", "seal", "prove"} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			t.Parallel()

			binding := validTask11SyntheticCleanupObserverBinding(t)
			probe := validTask11SyntheticCleanupProbe(t, binding)
			probe.cleanupAbsent = true
			observer, err := newTask11SyntheticCleanupObserver(
				binding,
				probe,
			)
			if err != nil {
				t.Fatalf("new observer: %v", err)
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			switch phase {
			case "arm":
				if err := observer.ArmStructural(
					canceled,
					hostruntime.ManagedSnapshot{},
				); !errors.Is(err, ErrFixtureStart) {
					t.Fatalf("canceled arm error = %v", err)
				}
			case "seal":
				if err := observer.ArmStructural(
					context.Background(),
					hostruntime.ManagedSnapshot{},
				); err != nil {
					t.Fatalf("ArmStructural: %v", err)
				}
				if err := observer.SealListenerOutcome(
					canceled,
					validTask11SyntheticListenerOutcome(t, binding),
				); !errors.Is(err, ErrFixtureStart) {
					t.Fatalf("canceled seal error = %v", err)
				}
			case "prove":
				if err := observer.ArmStructural(
					context.Background(),
					hostruntime.ManagedSnapshot{},
				); err != nil {
					t.Fatalf("ArmStructural: %v", err)
				}
				if err := observer.SealListenerOutcome(
					context.Background(),
					validTask11SyntheticListenerOutcome(t, binding),
				); err != nil {
					t.Fatalf("SealListenerOutcome: %v", err)
				}
				if _, err := observer.Prove(
					canceled,
				); !errors.Is(err, ErrFixtureCleanup) {
					t.Fatalf("canceled prove error = %v", err)
				}
			}
			if err := observer.ArmStructural(
				context.Background(),
				hostruntime.ManagedSnapshot{},
			); err == nil {
				t.Fatal("context-failed observer accepted a new arm")
			}
			if err := observer.SealListenerOutcome(
				context.Background(),
				validTask11SyntheticListenerOutcome(t, binding),
			); err == nil {
				t.Fatal("context-failed observer accepted a new seal")
			}
			if _, err := observer.Prove(
				context.Background(),
			); err == nil {
				t.Fatal("context-failed observer accepted a proof")
			}
		})
	}
}

func TestTask11SyntheticCleanupObserverSealsExactListenerOutcome(
	t *testing.T,
) {
	t.Parallel()

	binding := validTask11SyntheticCleanupObserverBinding(t)
	probe := validTask11SyntheticCleanupProbe(t, binding)
	observer, err := newTask11SyntheticCleanupObserver(binding, probe)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	if err := observer.ArmStructural(
		context.Background(),
		hostruntime.ManagedSnapshot{},
	); err != nil {
		t.Fatalf("ArmStructural: %v", err)
	}
	if err := observer.SealListenerOutcome(
		context.Background(),
		validTask11SyntheticListenerOutcome(t, binding),
	); err != nil {
		t.Fatalf("SealListenerOutcome: %v", err)
	}
	if err := observer.SealListenerOutcome(
		context.Background(),
		validTask11SyntheticListenerOutcome(t, binding),
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("second listener seal error = %v", err)
	}
	if _, err := observer.Prove(
		context.Background(),
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("proof after repeated seal error = %v", err)
	}

	probe = validTask11SyntheticCleanupProbe(t, binding)
	probe.cleanupAbsent = true
	observer, err = newTask11SyntheticCleanupObserver(binding, probe)
	if err != nil {
		t.Fatalf("new successful observer: %v", err)
	}
	if err := observer.ArmStructural(
		context.Background(),
		hostruntime.ManagedSnapshot{},
	); err != nil {
		t.Fatalf("successful ArmStructural: %v", err)
	}
	outcome := validTask11SyntheticListenerOutcome(t, binding)
	if err := observer.SealListenerOutcome(
		context.Background(),
		outcome,
	); err != nil {
		t.Fatalf("successful SealListenerOutcome: %v", err)
	}
	proof, err := observer.Prove(context.Background())
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if _, err := SealCompleteCleanup(proof); err != nil {
		t.Fatalf("SealCompleteCleanup: %v", err)
	}
	if probe.outcome.kind != task11CleanupOutcomeListener ||
		probe.outcome.digest == "" {
		t.Fatalf("probe outcome seal = %+v", probe.outcome)
	}
}

func TestTask11SyntheticCleanupObserverRetainsExactPrivateEvidence(
	t *testing.T,
) {
	t.Parallel()

	binding := validTask11SyntheticCleanupObserverBinding(t)
	probe := validTask11SyntheticCleanupProbe(t, binding)
	probe.cleanupAbsent = true
	observer, err := newTask11SyntheticCleanupObserver(binding, probe)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	if err := observer.ArmStructural(
		context.Background(),
		hostruntime.ManagedSnapshot{},
	); err != nil {
		t.Fatalf("ArmStructural: %v", err)
	}
	if err := observer.SealListenerOutcome(
		context.Background(),
		validTask11SyntheticListenerOutcome(t, binding),
	); err != nil {
		t.Fatalf("SealListenerOutcome: %v", err)
	}
	evidence, err := observer.proveEvidence(context.Background())
	if err != nil {
		t.Fatalf("proveEvidence: %v", err)
	}
	if !validTask11SyntheticProvedCleanup(evidence, binding) {
		t.Fatalf("private cleanup evidence = %+v", evidence)
	}
	if _, err := observer.Prove(
		context.Background(),
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("second proof error = %v", err)
	}

	drifted := evidence
	drifted.observation.CycleRunDigest =
		drifted.observation.CleanupDigest
	if validTask11SyntheticProvedCleanup(drifted, binding) {
		t.Fatal("drifted private cleanup evidence was accepted")
	}
}

func TestTask11SyntheticCleanupObserverRejectsSubstitutedListenerOutcome(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(*task11SyntheticListenerOutcome){
		"runner": func(value *task11SyntheticListenerOutcome) {
			value.RunnerID = value.Stream.Boundary.CycleRunDigest
		},
		"exit": func(value *task11SyntheticListenerOutcome) {
			value.ExitCode = task11synthetic.ListenerCrashExitStatus
		},
		"cycle": func(value *task11SyntheticListenerOutcome) {
			value.Stream.Boundary.CycleRunDigest =
				value.Stream.Boundary.JobMarkerDigest
		},
		"cgroup": func(value *task11SyntheticListenerOutcome) {
			value.Stream.Boundary.CgroupVersion = task11synthetic.CgroupV1
		},
		"terminal missing": func(value *task11SyntheticListenerOutcome) {
			value.Stream.Terminal = nil
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			binding := validTask11SyntheticCleanupObserverBinding(t)
			probe := validTask11SyntheticCleanupProbe(t, binding)
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
				t.Fatalf("ArmStructural: %v", err)
			}
			outcome := validTask11SyntheticListenerOutcome(t, binding)
			mutate(&outcome)
			if err := observer.SealListenerOutcome(
				context.Background(),
				outcome,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("substituted outcome error = %v", err)
			}
			if _, err := observer.Prove(
				context.Background(),
			); err == nil {
				t.Fatal("failed listener seal remained usable")
			}
		})
	}
}

func TestTask11SyntheticCleanupObserverSealsOnlyClosedNoListenerOutcome(
	t *testing.T,
) {
	t.Parallel()

	binding := validTask11SyntheticCleanupObserverBindingForKind(
		t,
		task11synthetic.CycleCleanupCancellation,
	)
	probe := validTask11SyntheticCleanupProbe(t, binding)
	probe.cleanupAbsent = true
	observer, err := newTask11SyntheticCleanupObserver(binding, probe)
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	if err := observer.ArmStructural(
		context.Background(),
		hostruntime.ManagedSnapshot{},
	); err != nil {
		t.Fatalf("ArmStructural: %v", err)
	}
	if err := observer.SealNoListenerOutcome(
		context.Background(),
		task11SyntheticNoListenerOutcome{
			Reason: task11NoListenerCancellation,
		},
	); err != nil {
		t.Fatalf("SealNoListenerOutcome: %v", err)
	}
	if _, err := observer.Prove(context.Background()); err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if probe.outcome.kind != task11CleanupOutcomeNoListener {
		t.Fatalf("probe outcome kind = %v", probe.outcome.kind)
	}

	tests := map[string]func(
		*task11SyntheticCleanupObserverBinding,
		*task11SyntheticNoListenerOutcome,
	){
		"listener cycle": func(
			binding *task11SyntheticCleanupObserverBinding,
			_ *task11SyntheticNoListenerOutcome,
		) {
			*binding = validTask11SyntheticCleanupObserverBinding(t)
		},
		"wrong reason": func(
			_ *task11SyntheticCleanupObserverBinding,
			outcome *task11SyntheticNoListenerOutcome,
		) {
			outcome.Reason = task11NoListenerControllerRestart
		},
		"attach started": func(
			_ *task11SyntheticCleanupObserverBinding,
			outcome *task11SyntheticNoListenerOutcome,
		) {
			outcome.AttachStarted = true
		},
		"release completed": func(
			_ *task11SyntheticCleanupObserverBinding,
			outcome *task11SyntheticNoListenerOutcome,
		) {
			outcome.ReleaseEffectCompleted = true
		},
		"release ambiguous": func(
			_ *task11SyntheticCleanupObserverBinding,
			outcome *task11SyntheticNoListenerOutcome,
		) {
			outcome.ReleaseEffectAmbiguous = true
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			candidate := validTask11SyntheticCleanupObserverBindingForKind(
				t,
				task11synthetic.CycleCleanupCancellation,
			)
			outcome := task11SyntheticNoListenerOutcome{
				Reason: task11NoListenerCancellation,
			}
			mutate(&candidate, &outcome)
			probe := validTask11SyntheticCleanupProbe(t, candidate)
			observer, err := newTask11SyntheticCleanupObserver(
				candidate,
				probe,
			)
			if err != nil {
				t.Fatalf("new observer: %v", err)
			}
			if err := observer.ArmStructural(
				context.Background(),
				hostruntime.ManagedSnapshot{},
			); err != nil {
				t.Fatalf("ArmStructural: %v", err)
			}
			if err := observer.SealNoListenerOutcome(
				context.Background(),
				outcome,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("invalid no-listener outcome error = %v", err)
			}
			if _, err := observer.Prove(
				context.Background(),
			); err == nil {
				t.Fatal("failed no-listener seal remained usable")
			}
		})
	}
}

func validTask11SyntheticListenerOutcome(
	t *testing.T,
	binding task11SyntheticCleanupObserverBinding,
) task11SyntheticListenerOutcome {
	t.Helper()

	scenario, listener, ok := task11SyntheticScenario(
		binding.Cycle.ProtocolKind,
	)
	if !ok || !listener {
		t.Fatalf("cycle %q is not listener-bearing", binding.Cycle.ProtocolKind)
	}
	terminal := validTask11TerminalForCycle(
		scenario,
		binding.Cycle.RunDigest,
	)
	return task11SyntheticListenerOutcome{
		RunnerID: binding.Recovery.ExpectedRunnerID,
		ExitCode: task11synthetic.NormalExitStatus,
		Stream: task11synthetic.Stream{
			Boundary: validTask11BoundaryForCycle(
				scenario,
				binding.Cycle.RunDigest,
			),
			Terminal: &terminal,
		},
	}
}

func validTask11SyntheticCleanupObserverBindingForKind(
	t *testing.T,
	kind task11synthetic.CycleKind,
) task11SyntheticCleanupObserverBinding {
	t.Helper()

	binding := validTask11SyntheticCleanupObserverBinding(t)
	var requestKind task11SyntheticCycleKind
	switch kind {
	case task11synthetic.CycleCleanupCancellation:
		requestKind = task11CycleCleanupCancellation
	case task11synthetic.CycleCleanupPreListenerFailure:
		requestKind = task11CycleCleanupPreListenerFailure
	case task11synthetic.CycleCleanupControllerRestart:
		requestKind = task11CycleCleanupControllerRestart
	default:
		t.Fatalf("unsupported no-listener cycle %q", kind)
	}
	cycle, err := deriveTask11SyntheticCycleIdentity(
		binding.PrimaryRoot,
		binding.PrimaryRunDigest,
		task11SyntheticCycleRequest{Kind: requestKind},
	)
	if err != nil {
		t.Fatalf("derive no-listener cycle: %v", err)
	}
	binding.Cycle = cycle
	binding.Recovery.SlotIdentity = cycle.Composition.SlotIdentity
	binding.Recovery.AdapterName = cycle.Composition.AdapterName
	binding.Recovery.BrokerName = cycle.Composition.BrokerName
	binding.Recovery.RunnerName = cycle.Composition.RunnerName
	binding.Recovery.RelayParent = filepath.Join(cycle.Root, "relay")
	binding.Recovery.AuthorityParent = filepath.Join(
		cycle.Root,
		"authority",
	)
	binding.CapacitySlotID = cycle.Composition.CapacitySlotID
	binding.JobGeneration = cycle.Composition.JobGeneration
	return binding
}
