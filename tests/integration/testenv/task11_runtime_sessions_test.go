package testenv

import (
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func TestTask11RuntimeSessionSourceLazilyRunsOneClosedDenialsSession(
	t *testing.T,
) {
	t.Parallel()

	source, prepared, runner := validTask11RuntimeSessionSource(t)
	observation, err := source.ObserveClosedDenials(
		t.Context(),
		prepared,
	)
	if err != nil {
		t.Fatalf("ObserveClosedDenials: %v", err)
	}
	if !validClosedDenialsSessionObservation(
		observation,
		source.composition.Request.Graph,
	) {
		t.Fatalf("observation = %+v", observation)
	}
	if len(runner.argv) != 2 {
		t.Fatalf("command count = %d", len(runner.argv))
	}
	before := len(runner.argv)
	if _, err := source.ObserveClosedDenials(
		t.Context(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("repeat error = %v", err)
	}
	if len(runner.argv) != before {
		t.Fatal("repeat reached command runner")
	}
}

func TestTask11RuntimeSessionSourceRejectsPreparedSubstitutionBeforeCommand(
	t *testing.T,
) {
	t.Parallel()

	source, prepared, runner := validTask11RuntimeSessionSource(t)
	prepared.BrokerAuditDigest = inputDigestA
	if _, err := source.ObserveClosedDenials(
		t.Context(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("substitution error = %v", err)
	}
	if len(runner.argv) != 0 {
		t.Fatal("substitution reached command runner")
	}
}

func TestOrchestratedFixtureRuntimeBindsOwnedTask11CasesBeforePrepare(
	t *testing.T,
) {
	t.Parallel()

	source, _, _ := validTask11RuntimeSessionSource(t)
	runtime := &orchestratedFixtureRuntime{
		composition:    source.composition,
		lossPrevention: &task11LossPreventionRuntime{},
		lossAttempt:    &task11RealLossAttemptSource{},
	}
	if err := runtime.bindTask11CasesThreeToSix(); err != nil {
		t.Fatalf("bindTask11CasesThreeToSix: %v", err)
	}
	if runtime.task11Sessions == nil ||
		runtime.task11Cases == nil ||
		runtime.task11Sessions.prepared != runtime ||
		runtime.task11Cases.prepared != runtime ||
		runtime.task11Cases.loss != runtime ||
		runtime.task11Cases.closed != runtime.task11Sessions ||
		runtime.task11Cases.capture != runtime.task11Sessions {
		t.Fatal("Task 11 provider ownership was not exact")
	}
	if err := runtime.bindTask11CasesThreeToSix(); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("duplicate bind error = %v", err)
	}
}

func TestOrchestratedFixtureRuntimeRejectsLateOrUnarmedTask11CasesBind(
	t *testing.T,
) {
	t.Parallel()

	source, _, _ := validTask11RuntimeSessionSource(t)
	unarmed := &orchestratedFixtureRuntime{
		composition: source.composition,
	}
	if err := unarmed.bindTask11CasesThreeToSix(); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("unarmed bind error = %v", err)
	}
	late := &orchestratedFixtureRuntime{
		composition:      source.composition,
		lossPrevention:   &task11LossPreventionRuntime{},
		lossAttempt:      &task11RealLossAttemptSource{},
		prepareAttempted: true,
	}
	if err := late.bindTask11CasesThreeToSix(); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("late bind error = %v", err)
	}
}

func validTask11RuntimeSessionSource(
	t *testing.T,
) (
	*task11RuntimeSessionSource,
	fixtureRuntimeObservation,
	*orderedClosedRunner,
) {
	t.Helper()

	_, prepared, dependencies := validTask11CasesThreeToSixRuntime(t)
	networkBinding := validClosedNetworkSessionBinding(t)
	networkBinding.Adapter = prepared.Adapter
	networkBinding.Broker = prepared.Broker
	prepared.PolicyDigest = networkBinding.Graph.Digest().String()
	prepared.NetworkEgressReport.PolicyDigest = prepared.PolicyDigest
	prepared.ProbeReport.PolicyDigest = prepared.PolicyDigest
	dependencies.prepared.prepared = prepared
	expectedName, _, err := closedDenialsIdentity(networkBinding)
	if err != nil {
		t.Fatalf("closedDenialsIdentity: %v", err)
	}
	runner := &orderedClosedRunner{
		results: []orderedClosedResult{
			{result: hostruntime.Result{
				Stdout: closedDenialsDocumentForTest(
					networkBinding.Graph,
				),
			}},
			{result: closedAbsentResultForTest(expectedName)},
		},
	}
	surface, err := newClosedCommandSurface(
		closedCommandConfig{
			DockerPath:   "/usr/bin/docker",
			FixtureRoot:  "/private/tmp/portable-ghar-fixture",
			MaximumBytes: 64 << 10,
		},
		runner,
	)
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	leases, err := newTask11OneShotLeaseAuthority(
		"/usr/bin/docker",
		64<<10,
		runner,
		func(cleanupHandle) error { return nil },
	)
	if err != nil {
		t.Fatalf("newTask11OneShotLeaseAuthority: %v", err)
	}
	oneShotBinding := oneShotTestRecorderBinding()
	oneShots, err := newTask11OneShotRecorder(
		runner,
		oneShotBinding,
	)
	if err != nil {
		t.Fatalf("newTask11OneShotRecorder: %v", err)
	}
	matrix := matrixScannerBindingForTest()
	matrix.RunID = networkBinding.RunDigest
	matrix.BuildID = networkBinding.BuildID
	matrix.FleetGeneration = networkBinding.FleetGeneration
	matrix.SlotIdentity = networkBinding.SlotIdentity
	matrix.GraphDigest = networkBinding.Graph.Digest().String()
	request := networkjail.PreparedSetupRequest{
		Adapter: hostruntime.AdapterSpec{
			BuildID:         networkBinding.BuildID,
			FleetGeneration: networkBinding.FleetGeneration,
			SlotIdentity:    networkBinding.SlotIdentity,
		},
		Broker: hostruntime.BrokerSpec{
			BuildID:         networkBinding.BuildID,
			FleetGeneration: networkBinding.FleetGeneration,
			SlotIdentity:    networkBinding.SlotIdentity,
			CapacitySlotID: uint32(
				dependencies.prepared.slot,
			),
			JobGeneration: uint64(
				dependencies.prepared.generation,
			),
		},
		Runner: hostruntime.RunnerSpec{
			BuildID:         networkBinding.BuildID,
			FleetGeneration: networkBinding.FleetGeneration,
			SlotIdentity:    networkBinding.SlotIdentity,
		},
		Verifier: hostruntime.VerifierSpec{
			Image:           networkBinding.VerifierImage,
			BuildID:         networkBinding.BuildID,
			FleetGeneration: networkBinding.FleetGeneration,
			SlotIdentity:    networkBinding.SlotIdentity,
			User:            networkBinding.VerifierUser,
			Seccomp:         networkBinding.VerifierSeccomp,
			Limits:          networkBinding.VerifierLimits,
		},
		Graph: networkBinding.Graph,
	}
	source, err := newTask11RuntimeSessionSource(
		fixtureRuntimeComposition{
			OneShotRecorder: oneShots,
			OneShotLeases:   leases,
			ClosedSurface:   surface,
			MatrixBinding:   matrix,
			RunnerUser:      "65532:65532",
			MaximumEvidence: 64 << 10,
			Request:         request,
			FloodAttempts: uint32(
				dependencies.prepared.flood.Report.Attempts,
			),
		},
		dependencies.prepared,
	)
	if err != nil {
		t.Fatalf("newTask11RuntimeSessionSource: %v", err)
	}
	return source, prepared, runner
}
