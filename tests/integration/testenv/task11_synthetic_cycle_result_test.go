package testenv

import (
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestTask11SyntheticScenarioMappingIsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind     task11synthetic.CycleKind
		scenario task11synthetic.Scenario
		listener bool
	}{
		{task11synthetic.CycleOneJob, task11synthetic.ScenarioOneJob, true},
		{task11synthetic.CycleCleanupSuccess, task11synthetic.ScenarioCleanupSuccess, true},
		{task11synthetic.CycleCleanupCancellation, "", false},
		{task11synthetic.CycleCleanupPreListenerFailure, "", false},
		{task11synthetic.CycleCleanupListenerCrash, task11synthetic.ScenarioCleanupListenerCrash, true},
		{task11synthetic.CycleCleanupControllerRestart, "", false},
		{task11synthetic.CycleCleanupUpgradeInterruption, task11synthetic.ScenarioCleanupUpgradeInterruption, true},
		{task11synthetic.CycleReclamation, task11synthetic.ScenarioReclamation, true},
		{task11synthetic.CycleSeedFirst, task11synthetic.ScenarioSeedFirst, true},
		{task11synthetic.CycleSeedSecond, task11synthetic.ScenarioSeedSecond, true},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.kind), func(t *testing.T) {
			t.Parallel()
			scenario, listener, ok := task11SyntheticScenario(test.kind)
			if !ok || scenario != test.scenario || listener != test.listener {
				t.Fatalf(
					"scenario mapping = (%q,%t,%t), want (%q,%t,true)",
					scenario,
					listener,
					ok,
					test.scenario,
					test.listener,
				)
			}
		})
	}
	if _, _, ok := task11SyntheticScenario("unknown"); ok {
		t.Fatal("unknown cycle kind was admitted")
	}
}

func TestTask11SyntheticInputBindsOnlyCycleSentinelAndSeed(t *testing.T) {
	t.Parallel()
	primary := validConformanceInput(t, t.TempDir(), time.Now().UTC())
	cycle, err := deriveTask11SyntheticProtocolCycleIdentity(
		primary.Fixture.Root,
		primary.Authorization.RunID,
		task11synthetic.CycleSeedFirst,
		0,
	)
	if err != nil {
		t.Fatalf("deriveTask11SyntheticProtocolCycleIdentity: %v", err)
	}
	nonce := strings.Repeat("e", 64)
	input, binding, document, err := task11SyntheticListenerInput(
		primary,
		cycle,
		task11synthetic.ScenarioSeedFirst,
		nonce,
		task11synthetic.CgroupV2,
		primary.Limits.MaximumCommandInputBytes,
	)
	if err != nil {
		t.Fatalf("task11SyntheticListenerInput: %v", err)
	}
	if input.CycleRunDigest != cycle.RunDigest ||
		input.Nonce != nonce ||
		input.SeedID != task11synthetic.SeedID ||
		input.Sentinel.URL != primary.Sentinels.Positive.URL ||
		binding.Scenario != input.Scenario ||
		binding.CycleRunDigest != cycle.RunDigest ||
		binding.CgroupVersion != task11synthetic.CgroupV2 ||
		len(document) == 0 {
		t.Fatal("listener input lost an exact binding")
	}
	parsed, err := task11synthetic.ParseInput(
		document,
		primary.Limits.MaximumCommandInputBytes,
	)
	if err != nil || parsed != input {
		t.Fatal("listener input was not canonical")
	}

	for name, mutate := range map[string]func(){
		"non-seed seed": func() {
			_, _, _, err = task11SyntheticListenerInput(
				primary,
				cycle,
				task11synthetic.ScenarioOneJob,
				nonce,
				task11synthetic.CgroupV2,
				primary.Limits.MaximumCommandInputBytes,
			)
		},
		"wrong cgroup": func() {
			_, _, _, err = task11SyntheticListenerInput(
				primary,
				cycle,
				task11synthetic.ScenarioSeedFirst,
				nonce,
				"3",
				primary.Limits.MaximumCommandInputBytes,
			)
		},
		"short nonce": func() {
			_, _, _, err = task11SyntheticListenerInput(
				primary,
				cycle,
				task11synthetic.ScenarioSeedFirst,
				"abcd",
				task11synthetic.CgroupV2,
				primary.Limits.MaximumCommandInputBytes,
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutate()
			if err == nil {
				t.Fatal("invalid listener input was admitted")
			}
		})
	}
}

func TestTask11SyntheticNormalResultUsesTerminalAndCleanupDigests(t *testing.T) {
	t.Parallel()
	cycle := task11SyntheticCycleIdentity{
		Request: task11SyntheticCycleRequest{
			Kind:    task11CycleOneJob,
			Ordinal: 0,
		},
		ProtocolKind:  task11synthetic.CycleOneJob,
		RunDigest:     strings.Repeat("a", 64),
		CleanupDigest: strings.Repeat("b", 64),
	}
	terminal := validTask11TerminalForCycle(
		task11synthetic.ScenarioOneJob,
		cycle.RunDigest,
	)
	stream := task11synthetic.Stream{
		Boundary: validTask11BoundaryForCycle(
			task11synthetic.ScenarioOneJob,
			cycle.RunDigest,
		),
		Terminal: &terminal,
	}
	cleanup := validCompleteCleanupProofForCycle()
	result, err := task11SyntheticCycleResultFromStream(
		cycle,
		stream,
		cleanup,
	)
	if err != nil {
		t.Fatalf("task11SyntheticCycleResultFromStream: %v", err)
	}
	canonical, _ := task11synthetic.MarshalTerminalFrame(terminal)
	jobDigest, _ := task11synthetic.DeriveJobCompletionDigest(
		cycle.RunDigest,
		terminal.JobMarkerDigest,
		canonical,
	)
	deregistration, _ := task11synthetic.DeriveDeregistrationDigest(
		cycle.RunDigest,
		terminal.JobMarkerDigest,
		canonical,
	)
	if result.Kind != task11CycleOneJob ||
		result.Ordinal != 0 ||
		result.OneJob.JobCompletionDigest != jobDigest ||
		result.OneJob.ProxyRequestDigest != terminal.ProxyRequestDigest ||
		result.OneJob.DeregistrationDigest != deregistration ||
		result.OneJob.ReclamationDigest != cleanup.ObservationDigest ||
		len(result.Resources) != 0 {
		t.Fatal("one-job result did not use the exact terminal and cleanup")
	}

	reclamationCycle := cycle
	reclamationCycle.Request.Kind = task11CycleReclamation
	reclamationCycle.Request.Ordinal = 7
	reclamationCycle.ProtocolKind = task11synthetic.CycleReclamation
	reclamationTerminal := validTask11TerminalForCycle(
		task11synthetic.ScenarioReclamation,
		cycle.RunDigest,
	)
	reclamationStream := task11synthetic.Stream{
		Boundary: validTask11BoundaryForCycle(
			task11synthetic.ScenarioReclamation,
			cycle.RunDigest,
		),
		Terminal: &reclamationTerminal,
	}
	reclamation, err := task11SyntheticCycleResultFromStream(
		reclamationCycle,
		reclamationStream,
		cleanup,
	)
	if err != nil ||
		len(reclamation.Resources) != len(requiredReclamationResources) ||
		!reclamation.VersionStagingAbsent ||
		!isLowerHex(reclamation.VersionStagingAbsenceDigest, 64) {
		t.Fatal("reclamation result was not closed")
	}
	for index, resource := range reclamation.Resources {
		if resource.Resource != requiredReclamationResources[index] ||
			resource.HighWater != uint64(index+1) ||
			resource.PostCleanup != 0 {
			t.Fatal("reclamation vector was changed or reordered")
		}
	}
}

func TestTask11SyntheticResultRejectsCrossScenarioAndPartialShapes(t *testing.T) {
	t.Parallel()
	cycle := task11SyntheticCycleIdentity{
		Request:       task11SyntheticCycleRequest{Kind: task11CycleOneJob},
		ProtocolKind:  task11synthetic.CycleOneJob,
		RunDigest:     strings.Repeat("a", 64),
		CleanupDigest: strings.Repeat("b", 64),
	}
	terminal := validTask11TerminalForCycle(
		task11synthetic.ScenarioCleanupSuccess,
		cycle.RunDigest,
	)
	stream := task11synthetic.Stream{
		Boundary: validTask11BoundaryForCycle(
			task11synthetic.ScenarioCleanupSuccess,
			cycle.RunDigest,
		),
		Terminal: &terminal,
	}
	if _, err := task11SyntheticCycleResultFromStream(
		cycle,
		stream,
		validCompleteCleanupProofForCycle(),
	); err == nil {
		t.Fatal("cross-scenario stream was admitted")
	}
	stream.Terminal = nil
	stream.Boundary = validTask11BoundaryForCycle(
		task11synthetic.ScenarioOneJob,
		cycle.RunDigest,
	)
	if _, err := task11SyntheticCycleResultFromStream(
		cycle,
		stream,
		validCompleteCleanupProofForCycle(),
	); err == nil {
		t.Fatal("normal cycle without terminal was admitted")
	}
}

func TestTask11SyntheticSeedIsolationResultBindsFreshCopiesAndCleanup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first, err := deriveTask11SyntheticProtocolCycleIdentity(
		root,
		strings.Repeat("9", 64),
		task11synthetic.CycleSeedFirst,
		0,
	)
	if err != nil {
		t.Fatalf("derive first seed cycle: %v", err)
	}
	second, err := deriveTask11SyntheticProtocolCycleIdentity(
		root,
		strings.Repeat("9", 64),
		task11synthetic.CycleSeedSecond,
		0,
	)
	if err != nil {
		t.Fatalf("derive second seed cycle: %v", err)
	}
	firstTerminal := validTask11TerminalForCycle(
		task11synthetic.ScenarioSeedFirst,
		first.RunDigest,
	)
	secondTerminal := validTask11TerminalForCycle(
		task11synthetic.ScenarioSeedSecond,
		second.RunDigest,
	)
	firstCleanup := validCompleteCleanupProofForCycle()
	secondCleanup := validCompleteCleanupProofForCycle()
	secondCleanup.ObservationDigest = strings.Repeat("8", 64)
	result, err := task11SyntheticSeedIsolationResultFromStreams(
		root,
		strings.Repeat("9", 64),
		first,
		task11synthetic.Stream{
			Boundary: validTask11BoundaryForCycle(
				task11synthetic.ScenarioSeedFirst,
				first.RunDigest,
			),
			Terminal: &firstTerminal,
		},
		firstCleanup,
		second,
		task11synthetic.Stream{
			Boundary: validTask11BoundaryForCycle(
				task11synthetic.ScenarioSeedSecond,
				second.RunDigest,
			),
			Terminal: &secondTerminal,
		},
		secondCleanup,
	)
	if err != nil {
		t.Fatalf("task11SyntheticSeedIsolationResultFromStreams: %v", err)
	}
	if ValidateSeedIsolation(result.Proof) != nil ||
		result.FirstCleanup != firstCleanup ||
		result.SecondCleanup != secondCleanup ||
		result.Proof.SourceDigest != task11synthetic.SeedSourceSHA256 ||
		result.Proof.CurrentMutationDigest !=
			task11synthetic.SeedMutationSHA256 {
		t.Fatal("seed isolation result lost exact seed or cleanup evidence")
	}

	for name, mutate := range map[string]func(
		*task11SyntheticCycleIdentity,
		*task11synthetic.TerminalFrame,
		*CompleteCleanupProof,
		*task11SyntheticCycleIdentity,
		*task11synthetic.TerminalFrame,
		*CompleteCleanupProof,
	){
		"shared cycle root": func(
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
			second *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
		) {
			second.Root = first.Root
		},
		"first mutation absent": func(
			_ *task11SyntheticCycleIdentity,
			first *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
		) {
			first.Seed.MutationAbsent = true
		},
		"second mutation present": func(
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
			_ *task11SyntheticCycleIdentity,
			second *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
		) {
			second.Seed.MutationAbsent = false
		},
		"shared cleanup digest": func(
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			second *CompleteCleanupProof,
		) {
			second.ObservationDigest = firstCleanup.ObservationDigest
		},
		"first workspace remains": func(
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			first *CompleteCleanupProof,
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
		) {
			first.WorkAbsent = false
		},
		"host-backed work": func(
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			_ *CompleteCleanupProof,
			_ *task11SyntheticCycleIdentity,
			_ *task11synthetic.TerminalFrame,
			second *CompleteCleanupProof,
		) {
			second.HostBackedWorkAbsent = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			firstCycle := first
			secondCycle := second
			firstFrame := firstTerminal
			secondFrame := secondTerminal
			firstProof := firstCleanup
			secondProof := secondCleanup
			mutate(
				&firstCycle,
				&firstFrame,
				&firstProof,
				&secondCycle,
				&secondFrame,
				&secondProof,
			)
			if _, err := task11SyntheticSeedIsolationResultFromStreams(
				root,
				strings.Repeat("9", 64),
				firstCycle,
				task11synthetic.Stream{
					Boundary: validTask11BoundaryForCycle(
						task11synthetic.ScenarioSeedFirst,
						first.RunDigest,
					),
					Terminal: &firstFrame,
				},
				firstProof,
				secondCycle,
				task11synthetic.Stream{
					Boundary: validTask11BoundaryForCycle(
						task11synthetic.ScenarioSeedSecond,
						second.RunDigest,
					),
					Terminal: &secondFrame,
				},
				secondProof,
			); err == nil {
				t.Fatal("drifted seed isolation evidence was admitted")
			}
		})
	}
}

func validTask11BoundaryForCycle(
	scenario task11synthetic.Scenario,
	cycle string,
) task11synthetic.BoundaryFrame {
	boundary := task11synthetic.BoundaryListenerReady
	upgrade := false
	switch scenario {
	case task11synthetic.ScenarioCleanupListenerCrash:
		boundary = task11synthetic.BoundaryListenerCrashArmed
	case task11synthetic.ScenarioCleanupUpgradeInterruption:
		boundary = task11synthetic.BoundaryUpgradeInterruptionArmed
		upgrade = true
	}
	seed := ""
	if scenario == task11synthetic.ScenarioSeedFirst ||
		scenario == task11synthetic.ScenarioSeedSecond {
		seed = task11synthetic.SeedID
	}
	return task11synthetic.BoundaryFrame{
		SchemaVersion:                task11synthetic.SchemaVersion,
		ProtocolID:                   task11synthetic.ProtocolID,
		Frame:                        task11synthetic.FrameBoundary,
		Scenario:                     scenario,
		CycleRunDigest:               cycle,
		JobMarkerDigest:              strings.Repeat("c", 64),
		Boundary:                     boundary,
		SyntheticTokenAbsent:         true,
		ImmutablePayloadCount:        1,
		UpgradeInterruptionExercised: upgrade,
		CgroupVersion:                task11synthetic.CgroupV2,
		SeedID:                       seed,
	}
}

func validTask11TerminalForCycle(
	scenario task11synthetic.Scenario,
	cycle string,
) task11synthetic.TerminalFrame {
	resources := make(
		[]task11synthetic.ResourceHighWater,
		0,
		len(task11synthetic.Resources()),
	)
	for index, resource := range task11synthetic.Resources() {
		resources = append(resources, task11synthetic.ResourceHighWater{
			Resource:  resource,
			HighWater: uint64(index + 1),
		})
	}
	var seed *task11synthetic.SeedProof
	if scenario == task11synthetic.ScenarioSeedFirst ||
		scenario == task11synthetic.ScenarioSeedSecond {
		seed = &task11synthetic.SeedProof{
			SeedID:           task11synthetic.SeedID,
			SourceDigest:     task11synthetic.SeedSourceSHA256,
			CopyDigest:       task11synthetic.SeedSourceSHA256,
			MutationDigest:   task11synthetic.SeedMutationSHA256,
			SourcePostDigest: task11synthetic.SeedSourceSHA256,
			MutationAbsent: scenario ==
				task11synthetic.ScenarioSeedSecond,
			SourceImmutable: true,
		}
	}
	return task11synthetic.TerminalFrame{
		SchemaVersion:           task11synthetic.SchemaVersion,
		ProtocolID:              task11synthetic.ProtocolID,
		Frame:                   task11synthetic.FrameTerminal,
		Scenario:                scenario,
		CycleRunDigest:          cycle,
		JobMarkerDigest:         strings.Repeat("c", 64),
		Outcome:                 task11synthetic.OutcomeCompleted,
		ProxyRequestDigest:      strings.Repeat("d", 64),
		ResponseBodyProofDigest: strings.Repeat("e", 64),
		RegistrationRemoved:     true,
		SyntheticTokenAbsent:    true,
		ImmutablePayloadCount:   1,
		CgroupVersion:           task11synthetic.CgroupV2,
		Resources:               resources,
		Seed:                    seed,
	}
}

func validCompleteCleanupProofForCycle() CompleteCleanupProof {
	return CompleteCleanupProof{
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
		ObservationDigest:       strings.Repeat("f", 64),
	}
}
