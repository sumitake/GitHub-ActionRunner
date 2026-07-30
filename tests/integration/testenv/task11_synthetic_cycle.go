package testenv

import (
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

type task11SyntheticCycleIdentity struct {
	Request       task11SyntheticCycleRequest
	ProtocolKind  task11synthetic.CycleKind
	RunDigest     string
	CleanupDigest string
	Composition   compositionIdentity
	Root          string
	Restart       task11SyntheticRestartStageIdentity
}

type task11SyntheticRestartStageIdentity struct {
	ParentRunDigest  string
	Stage            task11synthetic.SetupStage
	DeclarationIndex uint64
}

func deriveTask11SyntheticCycleIdentity(
	primaryRoot string,
	primaryRunDigest string,
	request task11SyntheticCycleRequest,
) (task11SyntheticCycleIdentity, error) {
	protocolKind, ok := task11ProtocolCycleKind(request.Kind)
	if !ok || (request.Kind != task11CycleReclamation &&
		request.Ordinal != 0) {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	derived, err := deriveTask11SyntheticProtocolCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		protocolKind,
		request.Ordinal,
	)
	if err != nil {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	derived.Request = request
	return derived, nil
}

func deriveTask11SyntheticProtocolCycleIdentity(
	primaryRoot string,
	primaryRunDigest string,
	protocolKind task11synthetic.CycleKind,
	ordinal uint64,
) (task11SyntheticCycleIdentity, error) {
	if !validAbsolutePath(primaryRoot) ||
		primaryRoot == string(filepath.Separator) ||
		(protocolKind != task11synthetic.CycleReclamation &&
			ordinal != 0) {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	runDigest, err := task11synthetic.DeriveCycleRunDigest(
		primaryRunDigest,
		protocolKind,
		ordinal,
	)
	if err != nil {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	cleanupDigest, err := task11synthetic.DeriveCleanupDigest(runDigest)
	if err != nil {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	composition, err := deriveCompositionIdentity(runDigest)
	if err != nil || composition.SlotIdentity == "" {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	root := filepath.Join(primaryRoot, composition.SlotIdentity)
	if !validAbsolutePath(root) ||
		root == primaryRoot ||
		filepath.Dir(root) != primaryRoot ||
		filepath.Base(root) != composition.SlotIdentity {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	return task11SyntheticCycleIdentity{
		ProtocolKind:  protocolKind,
		RunDigest:     runDigest,
		CleanupDigest: cleanupDigest,
		Composition:   composition,
		Root:          root,
	}, nil
}

func deriveTask11SyntheticRestartStageIdentity(
	primaryRoot string,
	primaryRunDigest string,
	parent task11SyntheticCycleIdentity,
	stage task11synthetic.SetupStage,
	declarationIndex uint64,
) (task11SyntheticCycleIdentity, error) {
	expectedParent, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		task11SyntheticCycleRequest{
			Kind: task11CycleCleanupControllerRestart,
		},
	)
	stages := task11synthetic.RestartSetupStages()
	if err != nil ||
		parent != expectedParent ||
		declarationIndex >= uint64(len(stages)) ||
		stages[declarationIndex] != stage {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	runDigest, err := task11synthetic.DeriveRestartCycleRunDigest(
		parent.RunDigest,
		stage,
		declarationIndex,
	)
	if err != nil {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	cleanupDigest, err := task11synthetic.DeriveCleanupDigest(runDigest)
	if err != nil {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	composition, err := deriveCompositionIdentity(runDigest)
	if err != nil || composition.SlotIdentity == "" {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	root := filepath.Join(primaryRoot, composition.SlotIdentity)
	if !validAbsolutePath(root) ||
		root == primaryRoot ||
		root == parent.Root ||
		filepath.Dir(root) != primaryRoot ||
		filepath.Base(root) != composition.SlotIdentity {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	return task11SyntheticCycleIdentity{
		Request:       parent.Request,
		ProtocolKind:  task11synthetic.CycleCleanupControllerRestart,
		RunDigest:     runDigest,
		CleanupDigest: cleanupDigest,
		Composition:   composition,
		Root:          root,
		Restart: task11SyntheticRestartStageIdentity{
			ParentRunDigest:  parent.RunDigest,
			Stage:            stage,
			DeclarationIndex: declarationIndex,
		},
	}, nil
}

func task11ProtocolCycleKind(
	kind task11SyntheticCycleKind,
) (task11synthetic.CycleKind, bool) {
	switch kind {
	case task11CycleOneJob:
		return task11synthetic.CycleOneJob, true
	case task11CycleCleanupSuccess:
		return task11synthetic.CycleCleanupSuccess, true
	case task11CycleCleanupCancellation:
		return task11synthetic.CycleCleanupCancellation, true
	case task11CycleCleanupPreListenerFailure:
		return task11synthetic.CycleCleanupPreListenerFailure, true
	case task11CycleCleanupListenerCrash:
		return task11synthetic.CycleCleanupListenerCrash, true
	case task11CycleCleanupControllerRestart:
		return task11synthetic.CycleCleanupControllerRestart, true
	case task11CycleCleanupUpgradeInterruption:
		return task11synthetic.CycleCleanupUpgradeInterruption, true
	case task11CycleReclamation:
		return task11synthetic.CycleReclamation, true
	default:
		return "", false
	}
}

func task11SyntheticCycleCompositionInputs(
	primary ConformanceInput,
	primaryOverlay hostruntime.PrivateOverlay,
	binding FixtureBinding,
	derived task11SyntheticCycleIdentity,
) (
	ConformanceInput,
	hostruntime.PrivateOverlay,
	compositionPlan,
	[]string,
	error,
) {
	if !validAbsolutePath(primary.Fixture.Root) ||
		primary.Fixture.Root == string(filepath.Separator) ||
		filepath.Dir(primary.Fixture.Root) !=
			primaryOverlay.Paths.BrokerRoot ||
		binding.Root != derived.Root ||
		filepath.Dir(binding.Root) != primary.Fixture.Root ||
		filepath.Base(binding.Root) != derived.Composition.SlotIdentity ||
		!validateFixture(binding, primary.Target, primary.Runtime) {
		return ConformanceInput{},
			hostruntime.PrivateOverlay{},
			compositionPlan{},
			nil,
			ErrFixtureStart
	}
	ordinal := derived.Request.Ordinal
	if derived.Request.Kind != "" {
		mapped, ok := task11ProtocolCycleKind(derived.Request.Kind)
		if !ok || mapped != derived.ProtocolKind {
			return ConformanceInput{},
				hostruntime.PrivateOverlay{},
				compositionPlan{},
				nil,
				ErrFixtureStart
		}
	} else if derived.ProtocolKind != task11synthetic.CycleSeedFirst &&
		derived.ProtocolKind != task11synthetic.CycleSeedSecond {
		return ConformanceInput{},
			hostruntime.PrivateOverlay{},
			compositionPlan{},
			nil,
			ErrFixtureStart
	}
	var expected task11SyntheticCycleIdentity
	var err error
	if derived.Restart != (task11SyntheticRestartStageIdentity{}) {
		parent, parentErr := deriveTask11SyntheticCycleIdentity(
			primary.Fixture.Root,
			primary.Authorization.RunID,
			task11SyntheticCycleRequest{
				Kind: task11CycleCleanupControllerRestart,
			},
		)
		if parentErr != nil {
			return ConformanceInput{},
				hostruntime.PrivateOverlay{},
				compositionPlan{},
				nil,
				ErrFixtureStart
		}
		expected, err = deriveTask11SyntheticRestartStageIdentity(
			primary.Fixture.Root,
			primary.Authorization.RunID,
			parent,
			derived.Restart.Stage,
			derived.Restart.DeclarationIndex,
		)
	} else {
		expected, err = deriveTask11SyntheticProtocolCycleIdentity(
			primary.Fixture.Root,
			primary.Authorization.RunID,
			derived.ProtocolKind,
			ordinal,
		)
	}
	if err != nil ||
		expected.ProtocolKind != derived.ProtocolKind ||
		expected.RunDigest != derived.RunDigest ||
		expected.CleanupDigest != derived.CleanupDigest ||
		expected.Composition != derived.Composition ||
		expected.Root != derived.Root ||
		expected.Restart != derived.Restart {
		return ConformanceInput{},
			hostruntime.PrivateOverlay{},
			compositionPlan{},
			nil,
			ErrFixtureStart
	}

	cycle := primary
	cycle.Authorization.RunID = derived.RunDigest
	cycle.Authorization.Digest = ""
	cycle.Fixture = binding
	authorizationDigest, err := ComputeAuthorizationDigest(
		cycle.Authorization,
	)
	if err != nil {
		return ConformanceInput{},
			hostruntime.PrivateOverlay{},
			compositionPlan{},
			nil,
			ErrFixtureStart
	}
	cycle.Authorization.Digest = authorizationDigest

	cycleOverlay := primaryOverlay
	cycleOverlay.Paths.BrokerRoot = primary.Fixture.Root
	plan, err := compositionPlanFrom(cycle, cycleOverlay)
	if err != nil ||
		plan.Identity != derived.Composition ||
		plan.AssignmentKey.RunnerRequestID !=
			derived.Composition.RunnerRequestID {
		return ConformanceInput{},
			hostruntime.PrivateOverlay{},
			compositionPlan{},
			nil,
			ErrFixtureStart
	}
	seedIDs := make([]string, 0)
	switch derived.ProtocolKind {
	case task11synthetic.CycleSeedFirst,
		task11synthetic.CycleSeedSecond:
		seedIDs = append(seedIDs, task11synthetic.SeedID)
	case task11synthetic.CycleOneJob,
		task11synthetic.CycleCleanupSuccess,
		task11synthetic.CycleCleanupCancellation,
		task11synthetic.CycleCleanupPreListenerFailure,
		task11synthetic.CycleCleanupListenerCrash,
		task11synthetic.CycleCleanupControllerRestart,
		task11synthetic.CycleCleanupUpgradeInterruption,
		task11synthetic.CycleReclamation:
	default:
		return ConformanceInput{},
			hostruntime.PrivateOverlay{},
			compositionPlan{},
			nil,
			ErrFixtureStart
	}
	return cycle, cycleOverlay, plan, seedIDs, nil
}

func task11CycleRootHandle(
	cycle task11SyntheticCycleIdentity,
) (cleanupHandle, error) {
	return compositionCleanupHandle(
		CleanupSyntheticListener,
		"portable-ghar.task11.synthetic-cycle-root.v1\x00",
		cycle.RunDigest,
	)
}

func task11SyntheticRecoveryBinding(
	primary ConformanceInput,
	cycle task11SyntheticCycleIdentity,
	identities hostruntime.RecoveredIdentities,
) (
	hostruntime.RecoverySpec,
	hostruntime.ManagedObservation,
	error,
) {
	if !validAbsolutePath(primary.Fixture.Root) ||
		primary.Fixture.Root == string(filepath.Separator) ||
		!isLowerHex(primary.Authorization.RunID, 64) ||
		!isLowerHex(primary.Runtime.BuildID, 64) ||
		primary.Runtime.FleetGeneration == 0 ||
		filepath.Dir(cycle.Root) != primary.Fixture.Root ||
		filepath.Base(cycle.Root) != cycle.Composition.SlotIdentity ||
		cycle.Root == primary.Fixture.Root ||
		identities.AdapterID == "" ||
		(identities.BrokerID != "" && identities.AdapterID == "") ||
		(identities.RunnerID != "" && identities.BrokerID == "") {
		return hostruntime.RecoverySpec{},
			hostruntime.ManagedObservation{},
			ErrFixtureStart
	}
	for _, id := range []string{
		identities.AdapterID,
		identities.BrokerID,
		identities.RunnerID,
	} {
		if id != "" && !isLowerHex(id, 64) {
			return hostruntime.RecoverySpec{},
				hostruntime.ManagedObservation{},
				ErrFixtureStart
		}
	}
	var expected task11SyntheticCycleIdentity
	var err error
	if cycle.Restart != (task11SyntheticRestartStageIdentity{}) {
		parent, parentErr := deriveTask11SyntheticCycleIdentity(
			primary.Fixture.Root,
			primary.Authorization.RunID,
			task11SyntheticCycleRequest{
				Kind: task11CycleCleanupControllerRestart,
			},
		)
		if parentErr != nil {
			return hostruntime.RecoverySpec{},
				hostruntime.ManagedObservation{},
				ErrFixtureStart
		}
		expected, err = deriveTask11SyntheticRestartStageIdentity(
			primary.Fixture.Root,
			primary.Authorization.RunID,
			parent,
			cycle.Restart.Stage,
			cycle.Restart.DeclarationIndex,
		)
	} else {
		expected, err = deriveTask11SyntheticProtocolCycleIdentity(
			primary.Fixture.Root,
			primary.Authorization.RunID,
			cycle.ProtocolKind,
			cycle.Request.Ordinal,
		)
	}
	if err != nil ||
		expected.ProtocolKind != cycle.ProtocolKind ||
		expected.RunDigest != cycle.RunDigest ||
		expected.CleanupDigest != cycle.CleanupDigest ||
		expected.Composition != cycle.Composition ||
		expected.Root != cycle.Root ||
		expected.Restart != cycle.Restart {
		return hostruntime.RecoverySpec{},
			hostruntime.ManagedObservation{},
			ErrFixtureStart
	}
	adapter := identities.AdapterID != ""
	broker := identities.BrokerID != ""
	runner := identities.RunnerID != ""
	return hostruntime.RecoverySpec{
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
		}, hostruntime.ManagedObservation{
			AdapterPresent: adapter,
			AdapterRunning: adapter,
			BrokerPresent:  broker,
			BrokerRunning:  broker,
			RunnerPresent:  runner,
			RunnerRunning:  runner,
		}, nil
}
