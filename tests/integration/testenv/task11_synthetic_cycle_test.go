package testenv

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestDeriveTask11SyntheticCycleIdentityBindsDirectChildRoot(t *testing.T) {
	t.Parallel()

	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primaryRunDigest := strings.Repeat("a", 64)
	requests := []task11SyntheticCycleRequest{
		{Kind: task11CycleOneJob},
		{Kind: task11CycleCleanupSuccess},
		{Kind: task11CycleCleanupCancellation},
		{Kind: task11CycleCleanupPreListenerFailure},
		{Kind: task11CycleCleanupListenerCrash},
		{Kind: task11CycleCleanupControllerRestart},
		{Kind: task11CycleCleanupUpgradeInterruption},
		{Kind: task11CycleReclamation, Ordinal: 7},
	}
	seenRuns := make(map[string]struct{}, len(requests))
	seenRoots := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		request := request
		t.Run(string(request.Kind), func(t *testing.T) {
			t.Parallel()

			derived, err := deriveTask11SyntheticCycleIdentity(
				primaryRoot,
				primaryRunDigest,
				request,
			)
			if err != nil {
				t.Fatalf("deriveTask11SyntheticCycleIdentity: %v", err)
			}
			protocolKind, ok := task11ProtocolCycleKind(request.Kind)
			if !ok {
				t.Fatal("closed local kind did not map to protocol kind")
			}
			wantRun, err := task11synthetic.DeriveCycleRunDigest(
				primaryRunDigest,
				protocolKind,
				request.Ordinal,
			)
			if err != nil {
				t.Fatalf("DeriveCycleRunDigest: %v", err)
			}
			wantCleanup, err := task11synthetic.DeriveCleanupDigest(wantRun)
			if err != nil {
				t.Fatalf("DeriveCleanupDigest: %v", err)
			}
			wantComposition, err := deriveCompositionIdentity(wantRun)
			if err != nil {
				t.Fatalf("deriveCompositionIdentity: %v", err)
			}
			if derived.Request != request ||
				derived.ProtocolKind != protocolKind ||
				derived.RunDigest != wantRun ||
				derived.CleanupDigest != wantCleanup ||
				derived.Composition != wantComposition {
				t.Fatalf("derived identity = %+v", derived)
			}
			if filepath.Dir(derived.Root) != primaryRoot ||
				filepath.Base(derived.Root) !=
					derived.Composition.SlotIdentity ||
				derived.Root == primaryRoot ||
				!validAbsolutePath(derived.Root) {
				t.Fatalf("derived root = %q", derived.Root)
			}
		})
	}

	for _, request := range requests {
		derived, err := deriveTask11SyntheticCycleIdentity(
			primaryRoot,
			primaryRunDigest,
			request,
		)
		if err != nil {
			t.Fatalf("derive identity for uniqueness: %v", err)
		}
		if _, exists := seenRuns[derived.RunDigest]; exists {
			t.Fatalf("duplicate run digest %q", derived.RunDigest)
		}
		if _, exists := seenRoots[derived.Root]; exists {
			t.Fatalf("duplicate root %q", derived.Root)
		}
		seenRuns[derived.RunDigest] = struct{}{}
		seenRoots[derived.Root] = struct{}{}
	}
}

func TestDeriveTask11SyntheticSeedCycleIdentityIsClosed(t *testing.T) {
	t.Parallel()

	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primaryRunDigest := strings.Repeat("b", 64)
	first, err := deriveTask11SyntheticProtocolCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		task11synthetic.CycleSeedFirst,
		0,
	)
	if err != nil {
		t.Fatalf("derive seed first: %v", err)
	}
	second, err := deriveTask11SyntheticProtocolCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		task11synthetic.CycleSeedSecond,
		0,
	)
	if err != nil {
		t.Fatalf("derive seed second: %v", err)
	}
	if first.ProtocolKind != task11synthetic.CycleSeedFirst ||
		second.ProtocolKind != task11synthetic.CycleSeedSecond ||
		first.RunDigest == second.RunDigest ||
		first.Root == second.Root ||
		first.CleanupDigest == second.CleanupDigest {
		t.Fatalf("seed identities first=%+v second=%+v", first, second)
	}
}

func TestDeriveTask11SyntheticRestartStageIdentitiesAreClosedAndOrdered(
	t *testing.T,
) {
	t.Parallel()

	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primaryRunDigest := strings.Repeat("d", 64)
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
	seen := make(map[string]struct{}, len(stages))
	for index, stage := range stages {
		child, err := deriveTask11SyntheticRestartStageIdentity(
			primaryRoot,
			primaryRunDigest,
			parent,
			stage,
			uint64(index),
		)
		if err != nil {
			t.Fatalf("derive stage %d: %v", index, err)
		}
		wantRun, err := task11synthetic.DeriveRestartCycleRunDigest(
			parent.RunDigest,
			stage,
			uint64(index),
		)
		if err != nil {
			t.Fatalf("derive stage digest %d: %v", index, err)
		}
		wantCleanup, err := task11synthetic.DeriveCleanupDigest(wantRun)
		if err != nil {
			t.Fatalf("derive cleanup digest %d: %v", index, err)
		}
		if child.Request != parent.Request ||
			child.ProtocolKind !=
				task11synthetic.CycleCleanupControllerRestart ||
			child.RunDigest != wantRun ||
			child.CleanupDigest != wantCleanup ||
			child.Restart != (task11SyntheticRestartStageIdentity{
				ParentRunDigest:  parent.RunDigest,
				Stage:            stage,
				DeclarationIndex: uint64(index),
			}) ||
			filepath.Dir(child.Root) != primaryRoot ||
			filepath.Base(child.Root) !=
				child.Composition.SlotIdentity ||
			child.Root == parent.Root {
			t.Fatalf("child %d = %+v", index, child)
		}
		if _, exists := seen[child.RunDigest]; exists {
			t.Fatalf("duplicate child digest %q", child.RunDigest)
		}
		seen[child.RunDigest] = struct{}{}
	}
}

func TestDeriveTask11SyntheticRestartStageIdentityRejectsDrift(
	t *testing.T,
) {
	t.Parallel()

	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primaryRunDigest := strings.Repeat("e", 64)
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
	if _, err := deriveTask11SyntheticRestartStageIdentity(
		primaryRoot,
		primaryRunDigest,
		parent,
		stages[1],
		0,
	); err == nil {
		t.Fatal("stage/index mismatch was accepted")
	}
	ordinary, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		task11SyntheticCycleRequest{Kind: task11CycleOneJob},
	)
	if err != nil {
		t.Fatalf("derive ordinary parent: %v", err)
	}
	if _, err := deriveTask11SyntheticRestartStageIdentity(
		primaryRoot,
		primaryRunDigest,
		ordinary,
		stages[0],
		0,
	); err == nil {
		t.Fatal("ordinary parent was accepted")
	}
}

func TestDeriveTask11SyntheticCycleIdentityRejectsOpenOrAliasedInput(
	t *testing.T,
) {
	t.Parallel()

	validRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	validDigest := strings.Repeat("c", 64)
	tests := map[string]struct {
		root    string
		digest  string
		request task11SyntheticCycleRequest
	}{
		"relative root": {
			root:    "relative/root",
			digest:  validDigest,
			request: task11SyntheticCycleRequest{Kind: task11CycleOneJob},
		},
		"unclean root": {
			root:    validRoot + string(filepath.Separator) + ".",
			digest:  validDigest,
			request: task11SyntheticCycleRequest{Kind: task11CycleOneJob},
		},
		"root filesystem": {
			root:    string(filepath.Separator),
			digest:  validDigest,
			request: task11SyntheticCycleRequest{Kind: task11CycleOneJob},
		},
		"invalid digest": {
			root:    validRoot,
			digest:  strings.Repeat("g", 64),
			request: task11SyntheticCycleRequest{Kind: task11CycleOneJob},
		},
		"unknown kind": {
			root:    validRoot,
			digest:  validDigest,
			request: task11SyntheticCycleRequest{Kind: "unknown"},
		},
		"nonzero ordinary ordinal": {
			root:   validRoot,
			digest: validDigest,
			request: task11SyntheticCycleRequest{
				Kind:    task11CycleOneJob,
				Ordinal: 1,
			},
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := deriveTask11SyntheticCycleIdentity(
				test.root,
				test.digest,
				test.request,
			); err == nil {
				t.Fatal("invalid cycle identity was accepted")
			}
		})
	}

	if _, err := deriveTask11SyntheticProtocolCycleIdentity(
		validRoot,
		validDigest,
		task11synthetic.CycleSeedFirst,
		1,
	); err == nil {
		t.Fatal("nonzero seed ordinal was accepted")
	}
	if _, err := deriveTask11SyntheticProtocolCycleIdentity(
		validRoot,
		validDigest,
		task11synthetic.CycleKind("unknown"),
		0,
	); err == nil {
		t.Fatal("unknown protocol kind was accepted")
	}
}

func TestTask11SyntheticCycleCompositionInputsCloneOnlyClosedBindings(
	t *testing.T,
) {
	t.Parallel()

	primary, overlay := validCompositionPlanInputs()
	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primary.Authorization.SchemaVersion = authorizationSchemaVersion
	primary.Authorization.Action = ActionTargetConformance
	primary.Fixture.Root = primaryRoot
	primary.Target.ExpectedEUID = 501
	overlay.Paths.BrokerRoot = filepath.Dir(primaryRoot)

	derived, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		primary.Authorization.RunID,
		task11SyntheticCycleRequest{Kind: task11CycleOneJob},
	)
	if err != nil {
		t.Fatalf("deriveTask11SyntheticCycleIdentity: %v", err)
	}
	binding := FixtureBinding{
		Root:                         derived.Root,
		ParentDevice:                 7,
		ParentInode:                  11,
		RequiredEmptyDigest:          strings.Repeat("d", 64),
		ExecutionOwnerUID:            primary.Target.ExpectedEUID,
		ExecutionOwnerIdentityDigest: strings.Repeat("e", 64),
	}
	cycle, cycleOverlay, plan, seedIDs, err :=
		task11SyntheticCycleCompositionInputs(
			primary,
			overlay,
			binding,
			derived,
		)
	if err != nil {
		t.Fatalf("task11SyntheticCycleCompositionInputs: %v", err)
	}
	if cycle.Authorization.RunID != derived.RunDigest ||
		cycle.Fixture != binding ||
		plan.Identity != derived.Composition ||
		plan.AssignmentKey.RunnerRequestID !=
			derived.Composition.RunnerRequestID ||
		cycleOverlay.Paths.BrokerRoot != primaryRoot ||
		len(seedIDs) != 0 {
		t.Fatalf(
			"cycle=%+v overlay=%+v plan=%+v seeds=%v",
			cycle,
			cycleOverlay.Paths,
			plan,
			seedIDs,
		)
	}
	expectedAuthorizationDigest, err := ComputeAuthorizationDigest(
		cycle.Authorization,
	)
	if err != nil ||
		cycle.Authorization.Digest != expectedAuthorizationDigest {
		t.Fatalf(
			"cycle authorization digest = %q, want %q err=%v",
			cycle.Authorization.Digest,
			expectedAuthorizationDigest,
			err,
		)
	}
	if primary.Fixture.Root != primaryRoot ||
		primary.Authorization.RunID == cycle.Authorization.RunID ||
		overlay.Paths.BrokerRoot != filepath.Dir(primaryRoot) {
		t.Fatal("primary input or overlay was mutated")
	}
}

func TestTask11SyntheticCycleCompositionInputsAcceptsExactRestartChild(
	t *testing.T,
) {
	t.Parallel()

	primary, overlay := validCompositionPlanInputs()
	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primary.Authorization.SchemaVersion = authorizationSchemaVersion
	primary.Authorization.Action = ActionTargetConformance
	primary.Fixture.Root = primaryRoot
	primary.Target.ExpectedEUID = 501
	overlay.Paths.BrokerRoot = filepath.Dir(primaryRoot)
	parent, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		primary.Authorization.RunID,
		task11SyntheticCycleRequest{
			Kind: task11CycleCleanupControllerRestart,
		},
	)
	if err != nil {
		t.Fatalf("derive restart parent: %v", err)
	}
	stage := task11synthetic.RestartSetupStages()[3]
	child, err := deriveTask11SyntheticRestartStageIdentity(
		primaryRoot,
		primary.Authorization.RunID,
		parent,
		stage,
		3,
	)
	if err != nil {
		t.Fatalf("derive restart child: %v", err)
	}
	binding := FixtureBinding{
		Root:                         child.Root,
		ParentDevice:                 7,
		ParentInode:                  11,
		RequiredEmptyDigest:          strings.Repeat("d", 64),
		ExecutionOwnerUID:            501,
		ExecutionOwnerIdentityDigest: strings.Repeat("e", 64),
	}
	cycle, cycleOverlay, plan, seeds, err :=
		task11SyntheticCycleCompositionInputs(
			primary,
			overlay,
			binding,
			child,
		)
	if err != nil {
		t.Fatalf("composition inputs: %v", err)
	}
	if cycle.Authorization.RunID != child.RunDigest ||
		cycle.Fixture != binding ||
		cycleOverlay.Paths.BrokerRoot != primaryRoot ||
		plan.Identity != child.Composition ||
		len(seeds) != 0 {
		t.Fatalf(
			"cycle=%+v overlay=%+v plan=%+v seeds=%v",
			cycle,
			cycleOverlay.Paths,
			plan,
			seeds,
		)
	}
}

func TestTask11SyntheticCycleCompositionInputsSelectsOnlyFixedSeed(
	t *testing.T,
) {
	t.Parallel()

	for _, kind := range []task11synthetic.CycleKind{
		task11synthetic.CycleSeedFirst,
		task11synthetic.CycleSeedSecond,
	} {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			primary, overlay := validCompositionPlanInputs()
			primaryRoot := filepath.Join(
				string(filepath.Separator),
				"private",
				"portable-ghar",
				"fixture",
			)
			primary.Authorization.SchemaVersion = authorizationSchemaVersion
			primary.Authorization.Action = ActionTargetConformance
			primary.Fixture.Root = primaryRoot
			primary.Target.ExpectedEUID = 501
			overlay.Paths.BrokerRoot = filepath.Dir(primaryRoot)
			derived, err :=
				deriveTask11SyntheticProtocolCycleIdentity(
					primaryRoot,
					primary.Authorization.RunID,
					kind,
					0,
				)
			if err != nil {
				t.Fatalf("derive seed identity: %v", err)
			}
			binding := FixtureBinding{
				Root:                         derived.Root,
				ParentDevice:                 7,
				ParentInode:                  11,
				RequiredEmptyDigest:          strings.Repeat("d", 64),
				ExecutionOwnerUID:            501,
				ExecutionOwnerIdentityDigest: strings.Repeat("e", 64),
			}
			_, _, _, seeds, err :=
				task11SyntheticCycleCompositionInputs(
					primary,
					overlay,
					binding,
					derived,
				)
			if err != nil {
				t.Fatalf("composition inputs: %v", err)
			}
			if len(seeds) != 1 ||
				seeds[0] != task11synthetic.SeedID {
				t.Fatalf("seed IDs = %v", seeds)
			}
		})
	}
}

func TestTask11SyntheticCycleCompositionInputsRejectsDrift(t *testing.T) {
	t.Parallel()

	primary, overlay := validCompositionPlanInputs()
	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primary.Authorization.SchemaVersion = authorizationSchemaVersion
	primary.Authorization.Action = ActionTargetConformance
	primary.Fixture.Root = primaryRoot
	primary.Target.ExpectedEUID = 501
	overlay.Paths.BrokerRoot = filepath.Dir(primaryRoot)
	derived, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		primary.Authorization.RunID,
		task11SyntheticCycleRequest{Kind: task11CycleCleanupSuccess},
	)
	if err != nil {
		t.Fatalf("deriveTask11SyntheticCycleIdentity: %v", err)
	}
	validBinding := FixtureBinding{
		Root:                         derived.Root,
		ParentDevice:                 7,
		ParentInode:                  11,
		RequiredEmptyDigest:          strings.Repeat("d", 64),
		ExecutionOwnerUID:            501,
		ExecutionOwnerIdentityDigest: strings.Repeat("e", 64),
	}
	tests := map[string]func(
		*ConformanceInput,
		*hostruntime.PrivateOverlay,
		*FixtureBinding,
		*task11SyntheticCycleIdentity,
	){
		"primary broker parent mismatch": func(
			_ *ConformanceInput,
			value *hostruntime.PrivateOverlay,
			_ *FixtureBinding,
			_ *task11SyntheticCycleIdentity,
		) {
			value.Paths.BrokerRoot = primaryRoot
		},
		"cycle root mismatch": func(
			_ *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			value *FixtureBinding,
			_ *task11SyntheticCycleIdentity,
		) {
			value.Root += "-drift"
		},
		"cycle owner mismatch": func(
			_ *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			value *FixtureBinding,
			_ *task11SyntheticCycleIdentity,
		) {
			value.ExecutionOwnerUID++
		},
		"derived run mismatch": func(
			_ *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			_ *FixtureBinding,
			value *task11SyntheticCycleIdentity,
		) {
			value.RunDigest = strings.Repeat("f", 64)
		},
		"derived slot mismatch": func(
			_ *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			_ *FixtureBinding,
			value *task11SyntheticCycleIdentity,
		) {
			value.Composition.SlotIdentity += "-drift"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			candidateInput := primary
			candidateOverlay := overlay
			candidateBinding := validBinding
			candidateDerived := derived
			mutate(
				&candidateInput,
				&candidateOverlay,
				&candidateBinding,
				&candidateDerived,
			)
			if _, _, _, _, err :=
				task11SyntheticCycleCompositionInputs(
					candidateInput,
					candidateOverlay,
					candidateBinding,
					candidateDerived,
				); err == nil {
				t.Fatal("drifted cycle composition was accepted")
			}
		})
	}
}

func TestTask11SyntheticRecoveryBindingRequiresExactHierarchicalInventory(
	t *testing.T,
) {
	t.Parallel()

	primaryRoot := filepath.Join(
		string(filepath.Separator),
		"private",
		"portable-ghar",
		"fixture",
	)
	primary := ConformanceInput{
		Authorization: Authorization{
			RunID: strings.Repeat("a", 64),
		},
		Runtime: RuntimeBinding{
			BuildID:         strings.Repeat("b", 64),
			FleetGeneration: 29,
		},
		Fixture: FixtureBinding{Root: primaryRoot},
	}
	cycle, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		primary.Authorization.RunID,
		task11SyntheticCycleRequest{Kind: task11CycleCleanupSuccess},
	)
	if err != nil {
		t.Fatalf("derive cycle: %v", err)
	}
	identities := hostruntime.RecoveredIdentities{
		AdapterID: strings.Repeat("c", 64),
		BrokerID:  strings.Repeat("d", 64),
		RunnerID:  strings.Repeat("e", 64),
	}
	spec, expected, err := task11SyntheticRecoveryBinding(
		primary,
		cycle,
		identities,
	)
	if err != nil {
		t.Fatalf("task11SyntheticRecoveryBinding: %v", err)
	}
	if spec != (hostruntime.RecoverySpec{
		SlotIdentity:      cycle.Composition.SlotIdentity,
		BuildID:           primary.Runtime.BuildID,
		FleetGeneration:   primary.Runtime.FleetGeneration,
		AdapterName:       cycle.Composition.AdapterName,
		BrokerName:        cycle.Composition.BrokerName,
		RunnerName:        cycle.Composition.RunnerName,
		ExpectedAdapterID: identities.AdapterID,
		ExpectedBrokerID:  identities.BrokerID,
		ExpectedRunnerID:  identities.RunnerID,
		RelayParent:       filepath.Join(cycle.Root, "relay"),
		AuthorityParent:   filepath.Join(cycle.Root, "authority"),
	}) {
		t.Fatalf("recovery spec = %+v", spec)
	}
	if expected != (hostruntime.ManagedObservation{
		AdapterPresent: true,
		AdapterRunning: true,
		BrokerPresent:  true,
		BrokerRunning:  true,
		RunnerPresent:  true,
		RunnerRunning:  true,
	}) {
		t.Fatalf("managed expectation = %+v", expected)
	}

	partial := identities
	partial.BrokerID = ""
	partial.RunnerID = ""
	_, expected, err = task11SyntheticRecoveryBinding(
		primary,
		cycle,
		partial,
	)
	if err != nil ||
		expected != (hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
		}) {
		t.Fatalf("partial expectation = %+v err=%v", expected, err)
	}

	for name, invalid := range map[string]hostruntime.RecoveredIdentities{
		"missing adapter": {
			BrokerID: identities.BrokerID,
		},
		"missing broker": {
			AdapterID: identities.AdapterID,
			RunnerID:  identities.RunnerID,
		},
		"malformed": {
			AdapterID: "abcd",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := task11SyntheticRecoveryBinding(
				primary,
				cycle,
				invalid,
			); err == nil {
				t.Fatal("invalid recovery inventory was accepted")
			}
		})
	}
}
