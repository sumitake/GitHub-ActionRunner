package testenv

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

func TestCommandRunnerFromConformanceLimitsUsesExactExplicitBounds(
	t *testing.T,
) {
	t.Parallel()

	limits := ConformanceLimits{
		MaximumEvidenceBytes:     1234,
		MaximumCommandInputBytes: 5678,
	}
	runner, err := commandRunnerFromConformanceLimits(limits)
	if err != nil {
		t.Fatalf("commandRunnerFromConformanceLimits: %v", err)
	}
	if runner.StdoutLimit != 1234 ||
		runner.StderrLimit != 1234 ||
		runner.StdinLimit != 5678 {
		t.Fatalf("runner limits = %+v", runner)
	}
}

func TestCommandRunnerFromConformanceLimitsRejectsDefaultOrOverflow(
	t *testing.T,
) {
	t.Parallel()

	tests := []ConformanceLimits{
		{MaximumEvidenceBytes: 0, MaximumCommandInputBytes: 1},
		{MaximumEvidenceBytes: 1, MaximumCommandInputBytes: 0},
		{
			MaximumEvidenceBytes:     uint64(math.MaxInt) + 1,
			MaximumCommandInputBytes: 1,
		},
		{
			MaximumEvidenceBytes:     1,
			MaximumCommandInputBytes: uint64(math.MaxInt) + 1,
		},
	}
	for _, limits := range tests {
		if _, err := commandRunnerFromConformanceLimits(limits); !errors.Is(
			err,
			ErrFixtureStart,
		) {
			t.Fatalf("limits %+v error = %v", limits, err)
		}
	}
}

func TestDialAuthorityCompositionUsesExactInputAndOverlayCeilings(
	t *testing.T,
) {
	t.Parallel()

	limits := ConformanceLimits{
		DialReservationBlockSize:         17,
		DialAuthorityMaximumClients:      4,
		DialAuthorityTimeoutMilliseconds: 250,
		MaximumProcesses:                 100,
		MaximumFileDescriptors:           200,
	}
	limits.CaseTimeouts = requiredCaseTimeouts(500)
	overlay := hostruntime.PrivateOverlay{}
	overlay.Resources.SlotResources.DialAuthority.PIDs = 8
	overlay.Resources.SlotResources.DialAuthority.FileDescriptors = 9

	got, err := dialAuthorityCompositionFrom(limits, overlay)
	if err != nil {
		t.Fatalf("dialAuthorityCompositionFrom: %v", err)
	}
	if got.ReservationBlockSize != 17 ||
		got.MaximumClients != 4 ||
		got.Timeout != 250*time.Millisecond {
		t.Fatalf("authority composition = %+v", got)
	}

	overlay.Resources.SlotResources.DialAuthority.PIDs = 3
	if _, err := dialAuthorityCompositionFrom(limits, overlay); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("PID ceiling error = %v", err)
	}
	overlay.Resources.SlotResources.DialAuthority.PIDs = 8
	overlay.Resources.SlotResources.DialAuthority.FileDescriptors = 3
	if _, err := dialAuthorityCompositionFrom(limits, overlay); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("FD ceiling error = %v", err)
	}
}

func TestDockerLogCompositionUsesCheckedResidualBudgets(t *testing.T) {
	t.Parallel()

	limits := ConformanceLimits{
		DockerLogMaximumBytes: 10,
		DockerLogMaximumFiles: 2,
		MaximumLogBytes:       60,
	}
	overlay := hostruntime.PrivateOverlay{}
	overlay.Resources.Storage.LogBounds = hostruntime.LogBoundsOverlay{
		UsedBytes: 40,
		MaxBytes:  100,
		UsedFiles: 4,
		MaxFiles:  10,
	}
	got, err := dockerLogCompositionFrom(limits, overlay)
	if err != nil {
		t.Fatalf("dockerLogCompositionFrom: %v", err)
	}
	if got.Bytes != 10 || got.Files != 2 ||
		got.FleetBytes != 60 || got.FleetFiles != 6 {
		t.Fatalf("log composition = %+v", got)
	}
	if !reflect.DeepEqual(
		longLivedLogEmitters[:],
		[]string{"adapter", "broker", "runner"},
	) {
		t.Fatalf("log emitters = %v", longLivedLogEmitters)
	}

	for name, mutate := range map[string]func(*ConformanceLimits, *hostruntime.PrivateOverlay){
		"run ceiling": func(value *ConformanceLimits, _ *hostruntime.PrivateOverlay) {
			value.MaximumLogBytes = 59
		},
		"residual bytes": func(_ *ConformanceLimits, value *hostruntime.PrivateOverlay) {
			value.Resources.Storage.LogBounds.UsedBytes = 41
		},
		"residual files": func(_ *ConformanceLimits, value *hostruntime.PrivateOverlay) {
			value.Resources.Storage.LogBounds.UsedFiles = 5
		},
		"invalid observed bytes": func(_ *ConformanceLimits, value *hostruntime.PrivateOverlay) {
			value.Resources.Storage.LogBounds.UsedBytes = 101
		},
		"product overflow": func(value *ConformanceLimits, _ *hostruntime.PrivateOverlay) {
			value.DockerLogMaximumBytes = math.MaxUint64
			value.DockerLogMaximumFiles = 2
			value.MaximumLogBytes = math.MaxUint64
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateLimits := limits
			candidateOverlay := overlay
			mutate(&candidateLimits, &candidateOverlay)
			if _, err := dockerLogCompositionFrom(
				candidateLimits,
				candidateOverlay,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDeriveCompositionIdentityIsGoldenAndDomainSeparated(t *testing.T) {
	t.Parallel()

	runDigest := strings.Repeat("a", 64)
	got, err := deriveCompositionIdentity(runDigest)
	if err != nil {
		t.Fatalf("deriveCompositionIdentity: %v", err)
	}
	want := compositionIdentity{
		RunnerRequestID: 8331475315255287649,
		CapacitySlotID:  549508202,
		JobGeneration:   16350042032659808245,
		SlotIdentity:    "pghar-slot-bba77bcc92810baf67cc",
		AdapterName:     "pghar-adapter-2f6bdefbec407a7e482c",
		BrokerName:      "pghar-broker-f086b765181c62db3842",
		RunnerName:      "pghar-runner-86590ee35d723ac3d5f0",
	}
	if got != want {
		t.Fatalf("identity = %+v, want %+v", got, want)
	}
	again, err := deriveCompositionIdentity(runDigest)
	if err != nil || again != got {
		t.Fatalf("second identity = %+v, %v", again, err)
	}
	mutated, err := deriveCompositionIdentity(
		strings.Repeat("a", 63) + "b",
	)
	if err != nil || mutated == got {
		t.Fatalf("mutated identity = %+v, %v", mutated, err)
	}
	if got.RunnerRequestID <= 0 ||
		got.CapacitySlotID == 0 ||
		got.JobGeneration == 0 {
		t.Fatalf("nonpositive identity = %+v", got)
	}
	for _, name := range []string{
		got.SlotIdentity,
		got.AdapterName,
		got.BrokerName,
		got.RunnerName,
	} {
		if len(name) > 128 || !compositionContainerNamePattern.MatchString(name) {
			t.Fatalf("invalid generated name %q", name)
		}
	}
}

func TestDeriveCompositionIdentityFailsClosed(t *testing.T) {
	t.Parallel()

	for _, runDigest := range []string{
		"",
		"abcd",
		strings.Repeat("A", 64),
		strings.Repeat("g", 64),
	} {
		if _, err := deriveCompositionIdentity(runDigest); !errors.Is(
			err,
			ErrFixtureStart,
		) {
			t.Fatalf("digest %q error = %v", runDigest, err)
		}
	}
	var zero [32]byte
	if _, ok := positiveInt64FromHash(zero); ok {
		t.Fatal("accepted zero int64 hash")
	}
	if _, ok := positiveUint32FromHash(zero); ok {
		t.Fatal("accepted zero uint32 hash")
	}
	if _, ok := positiveUint64FromHash(zero); ok {
		t.Fatal("accepted zero uint64 hash")
	}
	if _, ok := compositionName("", zero); ok {
		t.Fatal("accepted empty name prefix")
	}
	if _, ok := compositionName(strings.Repeat("x", 120), zero); ok {
		t.Fatal("accepted overlong name")
	}
}

func TestRuntimeLimitCompositionMapsEveryExactAuthority(t *testing.T) {
	t.Parallel()

	overlay := validRuntimeLimitOverlay()
	logs := dockerLogComposition{Bytes: 101, Files: 7}
	got, err := runtimeLimitCompositionFrom(overlay, logs)
	if err != nil {
		t.Fatalf("runtimeLimitCompositionFrom: %v", err)
	}
	want := runtimeLimitComposition{
		Adapter: hostruntime.ContainerLimits{
			MilliCPU:        101,
			MemoryBytes:     1_000,
			MemorySwapBytes: 1_100,
			PIDs:            11,
			FileDescriptors: 21,
			TmpfsBytes:      300,
			ScratchBytes:    200,
			LogBytes:        101,
			LogFiles:        7,
		},
		Broker: hostruntime.BrokerLimits{
			MilliCPU:        102,
			MemoryBytes:     1_100,
			MemorySwapBytes: 1_300,
			PIDs:            12,
			FileDescriptors: 22,
			StateBytes:      400,
			ScratchBytes:    300,
			LogBytes:        101,
			LogFiles:        7,
		},
		Runner: hostruntime.RunnerLimits{
			MilliCPU:           103,
			MemoryBytes:        8_000,
			MemorySwapBytes:    8_500,
			PIDs:               13,
			FileDescriptors:    23,
			ScratchBytes:       1_000,
			LogBytes:           101,
			LogFiles:           7,
			RunnerTmpfsBytes:   3_000,
			TmpTmpfsBytes:      1_000,
			ProcessMarginBytes: 1_000,
		},
		Helper: hostruntime.OneShotLimits{
			MilliCPU:        104,
			MemoryBytes:     65_536,
			MemorySwapBytes: 65_536,
			PIDs:            14,
			FileDescriptors: 24,
		},
		Verifier: hostruntime.OneShotLimits{
			MilliCPU:        105,
			MemoryBytes:     65_537,
			MemorySwapBytes: 65_538,
			PIDs:            15,
			FileDescriptors: 25,
		},
		WorkflowToolProbe: workflowToolProbeLimits{
			MilliCPU:        106,
			MemoryBytes:     70_000,
			MemorySwapBytes: 70_300,
			PIDs:            16,
			FileDescriptors: 26,
			WorkTmpfsBytes:  200,
			ScratchBytes:    100,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime limits = %+v, want %+v", got, want)
	}
}

func TestRuntimeLimitCompositionRejectsMismatchOverflowOrDefault(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(*hostruntime.PrivateOverlay, *dockerLogComposition){
		"runner memory mismatch": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Runner.MemoryBytes++
		},
		"runner tmpfs mismatch": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Runner.TmpfsBytes++
		},
		"runner scratch mismatch": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Runner.ScratchBytes++
		},
		"adapter tmpfs exceeds memory": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Adapter.MemoryBytes = 499
		},
		"broker tmpfs exceeds memory": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Broker.MemoryBytes = 699
		},
		"runner envelope exceeds memory": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.RunnerSizing.RunnerMemoryBytes = 5_999
			value.Resources.SlotResources.Runner.MemoryBytes = 5_999
		},
		"docker cpu overflow": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Adapter.MilliCPU =
				uint64(math.MaxInt64/1_000_000) + 1
		},
		"docker memory overflow": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Broker.MemoryBytes =
				uint64(math.MaxInt64) + 1
		},
		"docker pid overflow": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Runner.PIDs =
				uint64(math.MaxInt64) + 1
		},
		"docker fd overflow": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Verifier.FileDescriptors =
				uint64(math.MaxInt64) + 1
		},
		"adapter swap omitted": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.ContainerSwap.Adapter.Configured = false
		},
		"explicit zero helper swap remains configured": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.ContainerSwap.Helper.Configured = false
		},
		"runner swap omitted": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.RunnerSizing.SwapLimitConfigured = false
		},
		"workflow tool swap overflow": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.ContainerSwap.WorkflowToolProbe.Bytes = math.MaxUint64
		},
		"missing workflow tool vector": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.WorkflowToolProbe =
				hostruntime.ResourceVectorOverlay{}
		},
		"helper memory below fixed tmpfs": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Helper.MemoryBytes = 65_535
		},
		"verifier memory below production minimum": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Verifier.MemoryBytes = 65_535
		},
		"zero adapter field": func(value *hostruntime.PrivateOverlay, _ *dockerLogComposition) {
			value.Resources.SlotResources.Adapter.PIDs = 0
		},
		"zero log bytes": func(_ *hostruntime.PrivateOverlay, logs *dockerLogComposition) {
			logs.Bytes = 0
		},
		"zero log files": func(_ *hostruntime.PrivateOverlay, logs *dockerLogComposition) {
			logs.Files = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			overlay := validRuntimeLimitOverlay()
			logs := dockerLogComposition{Bytes: 101, Files: 7}
			mutate(&overlay, &logs)
			if _, err := runtimeLimitCompositionFrom(
				overlay,
				logs,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCompositionPlanBindsEveryPreEffectQuantity(t *testing.T) {
	t.Parallel()

	input, overlay := validCompositionPlanInputs()
	got, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	if got.AssignmentKey != (controller.AssignmentKey{
		RepositoryAlias: "portable-ghar-conformance",
		RunnerRequestID: got.Identity.RunnerRequestID,
		Attempt:         0,
	}) {
		t.Fatalf("assignment key = %+v", got.AssignmentKey)
	}
	if got.ConntrackInput != (networkjail.Budget{
		NFConntrackMax:   10_000,
		NFConntrackCount: 100,
		TailTimeoutID:    "conntrack-evidence-v1",
	}) {
		t.Fatalf("conntrack input = %+v", got.ConntrackInput)
	}
	if got.MaxRunnerCapacity != 6 {
		t.Fatalf("max runner capacity = %d", got.MaxRunnerCapacity)
	}
	if got.CommandRunner.StdoutLimit !=
		int(input.Limits.MaximumEvidenceBytes) ||
		got.CommandRunner.StdinLimit !=
			int(input.Limits.MaximumCommandInputBytes) {
		t.Fatalf("command runner = %+v", got.CommandRunner)
	}
	if got.Authority.ReservationBlockSize != 17 ||
		got.Authority.MaximumClients != 4 ||
		got.Authority.Timeout != 250*time.Millisecond ||
		got.Logs.FleetBytes != 60 ||
		got.Logs.FleetFiles != 6 ||
		got.RuntimeLimits.Runner.MemoryBytes != 8_000 ||
		got.HistoryLimits.MaxHistoryRows != 101 {
		t.Fatalf("composition plan = %+v", got)
	}
}

func TestCompositionPlanRejectsUnboundQuantity(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ConformanceInput, *hostruntime.PrivateOverlay){
		"run identity": func(input *ConformanceInput, _ *hostruntime.PrivateOverlay) {
			input.Authorization.RunID = ""
		},
		"conntrack maximum": func(_ *ConformanceInput, overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.Conntrack.MaximumEntries = 0
		},
		"conntrack count": func(_ *ConformanceInput, overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.Conntrack.CurrentEntries =
				overlay.Resources.Conntrack.MaximumEntries + 1
		},
		"conntrack evidence": func(_ *ConformanceInput, overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.Conntrack.EvidenceRevision = ""
		},
		"runner capacity": func(_ *ConformanceInput, overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.Conntrack.MaximumRunnerCapacity = 0
		},
		"loopback flood attempts": func(input *ConformanceInput, _ *hostruntime.PrivateOverlay) {
			input.LoopbackFloodAttempts = 0
		},
		"loopback flood verifier processes": func(_ *ConformanceInput, overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.SlotResources.Verifier.PIDs =
				loopbackFloodVerifierProcesses - 1
		},
		"loopback flood verifier file descriptors": func(_ *ConformanceInput, overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.SlotResources.Verifier.FileDescriptors =
				loopbackFloodPeakFileDescriptors - 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input, overlay := validCompositionPlanInputs()
			mutate(&input, &overlay)
			if _, err := compositionPlanFrom(
				input,
				overlay,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRuntimeSpecCompositionBindsExactStaticAuthorities(t *testing.T) {
	t.Parallel()

	input, overlay, static, seccomp, plan := validRuntimeSpecInputs(t)
	got, err := runtimeSpecCompositionFrom(
		input,
		overlay,
		static,
		seccomp,
		plan,
		hostruntime.AdapterHandle{},
	)
	if err != nil {
		t.Fatalf("runtimeSpecCompositionFrom: %v", err)
	}
	relay := filepath.Join(input.Fixture.Root, "relay")
	authority := filepath.Join(input.Fixture.Root, "authority")
	if got.Adapter.Name != plan.Identity.AdapterName ||
		got.Adapter.Image != input.Images.Adapter.Reference ||
		got.Adapter.BuildID != input.Runtime.BuildID ||
		got.Adapter.FleetGeneration != input.Runtime.FleetGeneration ||
		got.Adapter.SlotIdentity != plan.Identity.SlotIdentity ||
		got.Adapter.BrokerParent != relay ||
		got.Adapter.User != static.AdapterBrokerUser ||
		got.Adapter.Seccomp != seccomp ||
		got.Adapter.Limits != plan.RuntimeLimits.Adapter {
		t.Fatalf("adapter spec = %+v", got.Adapter)
	}
	if got.Broker.Name != plan.Identity.BrokerName ||
		got.Broker.Image != input.Images.Broker.Reference ||
		got.Broker.HelperImage != input.Images.Helper.Reference ||
		got.Broker.CapacitySlotID != plan.Identity.CapacitySlotID ||
		got.Broker.JobGeneration != plan.Identity.JobGeneration ||
		got.Broker.RelayParent != relay ||
		got.Broker.AuthorityParent != authority ||
		got.Broker.Limits != plan.RuntimeLimits.Broker ||
		got.Broker.HelperLimits != plan.RuntimeLimits.Helper {
		t.Fatalf("broker spec = %+v", got.Broker)
	}
	if got.Runner.Name != plan.Identity.RunnerName ||
		got.Runner.Image != input.Images.Runner.Reference ||
		got.Runner.Profile != hostruntime.HostProfileQTSCaplessRoot ||
		got.Runner.User != static.RunnerUser ||
		got.Runner.Limits != plan.RuntimeLimits.Runner {
		t.Fatalf("runner spec = %+v", got.Runner)
	}
	if got.Verifier.Image != input.Images.Verifier.Reference ||
		got.Verifier.User != static.VerifierUser ||
		got.Verifier.Limits != plan.RuntimeLimits.Verifier {
		t.Fatalf("verifier spec = %+v", got.Verifier)
	}
}

func TestRuntimeSpecCompositionRejectsAuthoritySubstitution(t *testing.T) {
	t.Parallel()

	tests := map[string]func(
		*ConformanceInput,
		*hostruntime.PrivateOverlay,
		*staticPreflightResult,
		*hostruntime.SeccompBinding,
		*compositionPlan,
	){
		"build mismatch": func(
			input *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			static *staticPreflightResult,
			_ *hostruntime.SeccompBinding,
			_ *compositionPlan,
		) {
			static.ManifestBuildID = strings.Repeat("b", 64)
			input.Runtime.BuildID = strings.Repeat("a", 64)
		},
		"broker root substitution": func(
			_ *ConformanceInput,
			overlay *hostruntime.PrivateOverlay,
			_ *staticPreflightResult,
			_ *hostruntime.SeccompBinding,
			_ *compositionPlan,
		) {
			overlay.Paths.BrokerRoot = "/different"
		},
		"missing adapter user": func(
			_ *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			static *staticPreflightResult,
			_ *hostruntime.SeccompBinding,
			_ *compositionPlan,
		) {
			static.AdapterBrokerUser = ""
		},
		"seccomp path substitution": func(
			_ *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			_ *staticPreflightResult,
			seccomp *hostruntime.SeccompBinding,
			_ *compositionPlan,
		) {
			seccomp.Path = "/different/seccomp.json"
		},
		"unknown profile": func(
			input *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			_ *staticPreflightResult,
			_ *hostruntime.SeccompBinding,
			_ *compositionPlan,
		) {
			input.Target.ProfileID = "other"
		},
		"zero fleet generation": func(
			input *ConformanceInput,
			_ *hostruntime.PrivateOverlay,
			_ *staticPreflightResult,
			_ *hostruntime.SeccompBinding,
			_ *compositionPlan,
		) {
			input.Runtime.FleetGeneration = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input, overlay, static, seccomp, plan :=
				validRuntimeSpecInputs(t)
			mutate(&input, &overlay, &static, &seccomp, &plan)
			if _, err := runtimeSpecCompositionFrom(
				input,
				overlay,
				static,
				seccomp,
				plan,
				hostruntime.AdapterHandle{},
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSeedCompositionAssignmentCreatesExactReservedState(t *testing.T) {
	t.Parallel()

	input, overlay := validCompositionPlanInputs()
	plan, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	store, err := state.OpenWithHistoryLimits(
		filepath.Join(t.TempDir(), "controller.db"),
		plan.HistoryLimits,
	)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	if err := seedCompositionAssignment(
		context.Background(),
		store,
		plan,
		now,
	); err != nil {
		t.Fatalf("seedCompositionAssignment: %v", err)
	}
	recoverable, err := store.ListRecoverable(context.Background())
	if err != nil {
		t.Fatalf("ListRecoverable: %v", err)
	}
	if len(recoverable) != 1 ||
		recoverable[0].Key != plan.AssignmentKey ||
		recoverable[0].State != controller.StateCapacityReserved ||
		recoverable[0].Slot.CapacitySlotID != plan.Identity.CapacitySlotID ||
		recoverable[0].Slot.OpaqueName != plan.Identity.SlotIdentity {
		t.Fatalf("recoverable = %+v", recoverable)
	}
}

func TestSeedCompositionAssignmentRejectsInvalidOrCanceledInput(
	t *testing.T,
) {
	t.Parallel()

	input, overlay := validCompositionPlanInputs()
	plan, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	store, err := state.OpenWithHistoryLimits(
		filepath.Join(t.TempDir(), "controller.db"),
		plan.HistoryLimits,
	)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := seedCompositionAssignment(
		ctx,
		store,
		plan,
		time.Now().UTC(),
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("canceled error = %v", err)
	}
	plan.Identity.CapacitySlotID = 0
	if err := seedCompositionAssignment(
		context.Background(),
		store,
		plan,
		time.Now().UTC(),
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("invalid error = %v", err)
	}
}

func validRuntimeSpecInputs(t *testing.T) (
	ConformanceInput,
	hostruntime.PrivateOverlay,
	staticPreflightResult,
	hostruntime.SeccompBinding,
	compositionPlan,
) {
	t.Helper()
	input, overlay := validCompositionPlanInputs()
	root := filepath.Join(overlay.Paths.BrokerRoot, "fixture")
	if overlay.Paths.BrokerRoot == "" {
		overlay.Paths.BrokerRoot = filepath.Join(t.TempDir(), "broker")
		root = filepath.Join(overlay.Paths.BrokerRoot, "fixture")
	}
	input.Fixture.Root = root
	input.Runtime.BuildID = strings.Repeat("a", 64)
	input.Runtime.FleetGeneration = 7
	input.Runtime.SeccompPath = filepath.Join(
		t.TempDir(),
		"seccomp.json",
	)
	input.Runtime.SeccompDigest = strings.Repeat("b", 64)
	input.Target.ProfileID = "qts-capless-root"
	input.Images.Runner = ImmutableImageBinding{
		ID: "runner", Reference: "example/runner@sha256:" + strings.Repeat("1", 64),
		Digest: strings.Repeat("1", 64),
	}
	input.Images.Adapter = ImmutableImageBinding{
		ID: "adapter", Reference: "example/adapter@sha256:" + strings.Repeat("2", 64),
		Digest: strings.Repeat("2", 64),
	}
	input.Images.Broker = ImmutableImageBinding{
		ID: "broker", Reference: "example/broker@sha256:" + strings.Repeat("3", 64),
		Digest: strings.Repeat("3", 64),
	}
	input.Images.Helper = ImmutableImageBinding{
		ID: "helper", Reference: "example/helper@sha256:" + strings.Repeat("4", 64),
		Digest: strings.Repeat("4", 64),
	}
	input.Images.Verifier = ImmutableImageBinding{
		ID: "verifier", Reference: "example/verifier@sha256:" + strings.Repeat("5", 64),
		Digest: strings.Repeat("5", 64),
	}
	plan, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	static := staticPreflightResult{
		ManifestBuildID:   input.Runtime.BuildID,
		RunnerUser:        "0:0",
		AdapterBrokerUser: "65532:65532",
		VerifierUser:      "65532:65532",
	}
	seccomp := hostruntime.SeccompBinding{
		Path:   input.Runtime.SeccompPath,
		SHA256: input.Runtime.SeccompDigest,
	}
	return input, overlay, static, seccomp, plan
}

func validCompositionPlanInputs() (
	ConformanceInput,
	hostruntime.PrivateOverlay,
) {
	overlay := validRuntimeLimitOverlay()
	overlay.Resources.SlotResources.DialAuthority =
		hostruntime.ResourceVectorOverlay{
			MilliCPU:          106,
			MemoryBytes:       65_536,
			PIDs:              8,
			FileDescriptors:   9,
			TmpfsBytes:        1,
			ScratchBytes:      1,
			SocketStateBytes:  1,
			DurableStateBytes: 1,
			Inodes:            1,
		}
	overlay.Resources.Storage.LogBounds = hostruntime.LogBoundsOverlay{
		UsedBytes: 40,
		MaxBytes:  100,
		UsedFiles: 4,
		MaxFiles:  10,
	}
	overlay.Resources.Conntrack.MaximumEntries = 10_000
	overlay.Resources.Conntrack.CurrentEntries = 100
	overlay.Resources.Conntrack.MaximumRunnerCapacity = 6
	overlay.Resources.Conntrack.EvidenceRevision = "conntrack-evidence-v1"
	overlay.Resources.History = hostruntime.HistoryOverlay{
		MinRetention:                 "2h0m0s",
		MaxHistoryRows:               101,
		MaxHistoryLogicalBytes:       1 << 20,
		MaxNetworkLedgerRows:         103,
		MaxNetworkLedgerLogicalBytes: 104,
		InflightReserveRows:          11,
		InflightReserveLogicalBytes:  1 << 10,
		GCBatchRows:                  13,
		NetworkGCBatchRows:           14,
		VacuumBatchPages:             15,
		MaintenanceCadence:           "3m0s",
	}
	input := ConformanceInput{}
	input.Authorization.RunID = strings.Repeat("a", 64)
	input.LoopbackFloodAttempts = 64
	input.Limits = ConformanceLimits{
		MaximumEvidenceBytes:              1234,
		MaximumCommandInputBytes:          5678,
		DialReservationBlockSize:          17,
		DialAuthorityMaximumClients:       4,
		DialAuthorityTimeoutMilliseconds:  250,
		DockerLogMaximumBytes:             10,
		DockerLogMaximumFiles:             2,
		MaximumLogBytes:                   60,
		MaximumProcesses:                  100,
		MaximumFileDescriptors:            200,
		MaximumAuthorizationWindowSeconds: 1,
	}
	input.Limits.CaseTimeouts = requiredCaseTimeouts(500)
	return input, overlay
}

func validRuntimeLimitOverlay() hostruntime.PrivateOverlay {
	vector := func(
		cpu, memory, pids, fds, tmpfs, scratch uint64,
	) hostruntime.ResourceVectorOverlay {
		return hostruntime.ResourceVectorOverlay{
			MilliCPU:          cpu,
			MemoryBytes:       memory,
			PIDs:              pids,
			FileDescriptors:   fds,
			TmpfsBytes:        tmpfs,
			ScratchBytes:      scratch,
			SocketStateBytes:  1,
			DurableStateBytes: 1,
			Inodes:            1,
		}
	}
	overlay := hostruntime.PrivateOverlay{}
	overlay.Resources.SlotResources.Adapter =
		vector(101, 1_000, 11, 21, 300, 200)
	overlay.Resources.SlotResources.Broker =
		vector(102, 1_100, 12, 22, 400, 300)
	overlay.Resources.SlotResources.Runner =
		vector(103, 8_000, 13, 23, 3_000, 1_000)
	overlay.Resources.SlotResources.Helper =
		vector(104, 65_536, 14, 24, 1, 1)
	overlay.Resources.SlotResources.Verifier =
		vector(105, 65_537, 15, 25, 1, 1)
	overlay.Resources.SlotResources.WorkflowToolProbe =
		vector(106, 70_000, 16, 26, 200, 100)
	overlay.Resources.ContainerSwap = hostruntime.ContainerSwapOverlay{
		Adapter: hostruntime.SwapLimitOverlay{
			Configured: true,
			Bytes:      100,
		},
		Broker: hostruntime.SwapLimitOverlay{
			Configured: true,
			Bytes:      200,
		},
		Helper: hostruntime.SwapLimitOverlay{
			Configured: true,
			Bytes:      0,
		},
		Verifier: hostruntime.SwapLimitOverlay{
			Configured: true,
			Bytes:      1,
		},
		WorkflowToolProbe: hostruntime.SwapLimitOverlay{
			Configured: true,
			Bytes:      300,
		},
	}
	overlay.Resources.RunnerSizing = hostruntime.RunnerSizingOverlay{
		RunnerMemoryBytes:   8_000,
		RunnerTmpfsBytes:    3_000,
		TmpTmpfsBytes:       1_000,
		ScratchTmpfsBytes:   1_000,
		ProcessMarginBytes:  1_000,
		SwapLimitConfigured: true,
		SwapLimitBytes:      500,
	}
	return overlay
}

func requiredCaseTimeouts(milliseconds uint64) []CaseTimeout {
	result := make([]CaseTimeout, 0, len(conformance.RequiredCases()))
	for _, id := range conformance.RequiredCases() {
		result = append(result, CaseTimeout{
			CaseID:              id,
			TimeoutMilliseconds: milliseconds,
		})
	}
	return result
}

func TestHistoryLimitsFromOverlayPreservesEveryExplicitField(
	t *testing.T,
) {
	t.Parallel()

	overlay := hostruntime.HistoryOverlay{
		MinRetention:                 "2h0m0s",
		MaxHistoryRows:               101,
		MaxHistoryLogicalBytes:       102,
		MaxNetworkLedgerRows:         103,
		MaxNetworkLedgerLogicalBytes: 104,
		InflightReserveRows:          11,
		InflightReserveLogicalBytes:  12,
		GCBatchRows:                  13,
		NetworkGCBatchRows:           14,
		VacuumBatchPages:             15,
		MaintenanceCadence:           "3m0s",
	}
	got, err := historyLimitsFromOverlay(overlay)
	if err != nil {
		t.Fatalf("historyLimitsFromOverlay: %v", err)
	}
	want := state.HistoryLimits{
		MinRetention:                 2 * time.Hour,
		MaxHistoryRows:               101,
		MaxHistoryLogicalBytes:       102,
		MaxNetworkLedgerRows:         103,
		MaxNetworkLedgerLogicalBytes: 104,
		InflightReserveRows:          11,
		InflightReserveLogicalBytes:  12,
		GCBatchRows:                  13,
		NetworkGCBatchRows:           14,
		VacuumBatchPages:             15,
		MaintenanceCadence:           3 * time.Minute,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("history limits = %+v, want %+v", got, want)
	}
}

func TestHistoryLimitsFromOverlayRejectsInvalidOrInconsistentValues(
	t *testing.T,
) {
	t.Parallel()

	valid := hostruntime.HistoryOverlay{
		MinRetention:                 "2h0m0s",
		MaxHistoryRows:               101,
		MaxHistoryLogicalBytes:       102,
		MaxNetworkLedgerRows:         103,
		MaxNetworkLedgerLogicalBytes: 104,
		InflightReserveRows:          11,
		InflightReserveLogicalBytes:  12,
		GCBatchRows:                  13,
		NetworkGCBatchRows:           14,
		VacuumBatchPages:             15,
		MaintenanceCadence:           "3m0s",
	}
	tests := []struct {
		name   string
		mutate func(*hostruntime.HistoryOverlay)
	}{
		{
			name: "noncanonical duration",
			mutate: func(value *hostruntime.HistoryOverlay) {
				value.MinRetention = "120m0s"
			},
		},
		{
			name: "reserve exceeds cap",
			mutate: func(value *hostruntime.HistoryOverlay) {
				value.InflightReserveRows = value.MaxHistoryRows + 1
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			candidate := valid
			testCase.mutate(&candidate)
			if _, err := historyLimitsFromOverlay(candidate); !errors.Is(
				err,
				ErrFixtureStart,
			) {
				t.Fatalf("error = %v, want fixture-start rejection", err)
			}
		})
	}
}
