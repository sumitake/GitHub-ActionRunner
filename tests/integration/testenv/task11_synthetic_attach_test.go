package testenv

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestTask11SyntheticAttachArgvIsExactAndClosed(t *testing.T) {
	t.Parallel()

	dockerPath := filepath.Join(
		string(filepath.Separator),
		"usr",
		"bin",
		"docker",
	)
	runnerID := strings.Repeat("a", 64)
	argv, err := task11SyntheticAttachArgv(dockerPath, runnerID)
	if err != nil {
		t.Fatalf("task11SyntheticAttachArgv: %v", err)
	}
	want := []string{
		dockerPath,
		"attach",
		"--no-stdin",
		"--sig-proxy=false",
		runnerID,
	}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v", argv)
	}
	for index := range want {
		if argv[index] != want[index] {
			t.Fatalf("argv[%d] = %q, want %q", index, argv[index], want[index])
		}
	}
	for _, test := range []struct {
		dockerPath string
		runnerID   string
	}{
		{"docker", runnerID},
		{dockerPath + string(filepath.Separator) + ".", runnerID},
		{dockerPath, ""},
		{dockerPath, strings.Repeat("g", 64)},
		{dockerPath, strings.Repeat("a", 63)},
	} {
		if _, err := task11SyntheticAttachArgv(
			test.dockerPath,
			test.runnerID,
		); err == nil {
			t.Fatalf("invalid attach binding was accepted: %+v", test)
		}
	}
}

func TestValidateTask11SyntheticAttachResultAcceptsOnlyJointTerminal(
	t *testing.T,
) {
	t.Parallel()

	binding, streamDocument := validTask11AttachStream(
		t,
		task11synthetic.ScenarioOneJob,
	)
	result := hostruntime.Result{
		Stdout:   streamDocument,
		ExitCode: task11synthetic.NormalExitStatus,
	}
	inspect := task11SyntheticContainerExit{
		ExitCode: task11synthetic.NormalExitStatus,
	}
	stream, err := validateTask11SyntheticAttachResult(
		result,
		inspect,
		binding,
		uint64(len(streamDocument)),
	)
	if err != nil || stream.Terminal == nil {
		t.Fatalf("stream = %+v err=%v", stream, err)
	}
	if stream.Boundary.Scenario != binding.Scenario ||
		stream.Terminal.Scenario != binding.Scenario {
		t.Fatalf("stream binding = %+v", stream)
	}
}

func TestValidateTask11SyntheticAttachResultAcceptsOnlyJointBoundaryExit(
	t *testing.T,
) {
	t.Parallel()

	for _, test := range []struct {
		scenario task11synthetic.Scenario
		exit     int
	}{
		{
			scenario: task11synthetic.ScenarioCleanupListenerCrash,
			exit:     task11synthetic.ListenerCrashExitStatus,
		},
		{
			scenario: task11synthetic.ScenarioCleanupUpgradeInterruption,
			exit:     task11synthetic.UpgradeInterruptionExitStatus,
		},
	} {
		test := test
		t.Run(string(test.scenario), func(t *testing.T) {
			t.Parallel()

			binding, document := validTask11AttachStream(
				t,
				test.scenario,
			)
			stream, err := validateTask11SyntheticAttachResult(
				hostruntime.Result{
					Stdout:   document,
					ExitCode: test.exit,
				},
				task11SyntheticContainerExit{ExitCode: test.exit},
				binding,
				uint64(len(document)),
			)
			if err != nil {
				t.Fatalf("validate attach: %v", err)
			}
			if stream.Terminal != nil {
				t.Fatal("boundary-only scenario accepted a terminal")
			}
		})
	}
}

func TestValidateTask11SyntheticAttachResultRejectsAnyPartialPredicate(
	t *testing.T,
) {
	t.Parallel()

	binding, document := validTask11AttachStream(
		t,
		task11synthetic.ScenarioCleanupListenerCrash,
	)
	validResult := hostruntime.Result{
		Stdout:   document,
		ExitCode: task11synthetic.ListenerCrashExitStatus,
	}
	validInspect := task11SyntheticContainerExit{
		ExitCode: task11synthetic.ListenerCrashExitStatus,
	}
	tests := map[string]func(
		*hostruntime.Result,
		*task11SyntheticContainerExit,
		*task11synthetic.StreamBinding,
		*uint64,
	){
		"attach wrong exit": func(
			result *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			result.ExitCode = 0
		},
		"inspect wrong exit": func(
			_ *hostruntime.Result,
			inspect *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			inspect.ExitCode = 0
		},
		"container running": func(
			_ *hostruntime.Result,
			inspect *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			inspect.Running = true
		},
		"container oom killed": func(
			_ *hostruntime.Result,
			inspect *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			inspect.OOMKilled = true
		},
		"container error": func(
			_ *hostruntime.Result,
			inspect *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			inspect.Error = "closed"
		},
		"attach stderr": func(
			result *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			result.Stderr = []byte("closed")
		},
		"attach signaled": func(
			result *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			result.Signaled = true
			result.Signal = "killed"
		},
		"stdout truncated": func(
			result *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			result.StdoutTruncated = true
		},
		"stderr truncated": func(
			result *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			result.StderrTruncated = true
		},
		"oversized": func(
			_ *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			maximum *uint64,
		) {
			*maximum--
		},
		"wrong cgroup": func(
			_ *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			binding *task11synthetic.StreamBinding,
			_ *uint64,
		) {
			binding.CgroupVersion = task11synthetic.CgroupV1
		},
		"trailing frame": func(
			result *hostruntime.Result,
			_ *task11SyntheticContainerExit,
			_ *task11synthetic.StreamBinding,
			maximum *uint64,
		) {
			result.Stdout = append(
				append([]byte(nil), result.Stdout...),
				result.Stdout...,
			)
			*maximum = uint64(len(result.Stdout))
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := validResult
			result.Stdout = append([]byte(nil), validResult.Stdout...)
			result.Stderr = append([]byte(nil), validResult.Stderr...)
			inspect := validInspect
			candidateBinding := binding
			maximum := uint64(len(document))
			mutate(&result, &inspect, &candidateBinding, &maximum)
			if _, err := validateTask11SyntheticAttachResult(
				result,
				inspect,
				candidateBinding,
				maximum,
			); err == nil {
				t.Fatal("partial listener predicate was accepted")
			}
		})
	}
}

func TestParseTask11SyntheticContainerExitIsCanonicalAndClosed(t *testing.T) {
	t.Parallel()

	valid := []byte(
		`{"running":false,"oom_killed":false,"error":"","exit_code":70}` +
			"\n",
	)
	got, err := parseTask11SyntheticContainerExit(valid)
	if err != nil ||
		got != (task11SyntheticContainerExit{ExitCode: 70}) {
		t.Fatalf("exit = %+v err=%v", got, err)
	}
	for _, document := range [][]byte{
		nil,
		bytes.TrimSuffix(valid, []byte{'\n'}),
		append(append([]byte(nil), valid...), '\n'),
		[]byte(
			`{"oom_killed":false,"running":false,"error":"","exit_code":70}` +
				"\n",
		),
		[]byte(
			`{"running":false,"oom_killed":false,"error":"","exit_code":70,"extra":true}` +
				"\n",
		),
		[]byte(
			`{"running":false,"oom_killed":false,"error":"","exit_code":-1}` +
				"\n",
		),
	} {
		if _, err := parseTask11SyntheticContainerExit(document); err == nil {
			t.Fatalf("invalid inspect was accepted: %q", document)
		}
	}
}

func validTask11AttachStream(
	t *testing.T,
	scenario task11synthetic.Scenario,
) (task11synthetic.StreamBinding, []byte) {
	t.Helper()

	runDigest := strings.Repeat("a", 64)
	jobMarker := strings.Repeat("b", 64)
	binding := task11synthetic.StreamBinding{
		Scenario:        scenario,
		CycleRunDigest:  runDigest,
		JobMarkerDigest: jobMarker,
		CgroupVersion:   task11synthetic.CgroupV2,
	}
	boundary := task11synthetic.BoundaryFrame{
		SchemaVersion:         task11synthetic.SchemaVersion,
		ProtocolID:            task11synthetic.ProtocolID,
		Frame:                 task11synthetic.FrameBoundary,
		Scenario:              scenario,
		CycleRunDigest:        runDigest,
		JobMarkerDigest:       jobMarker,
		SyntheticTokenAbsent:  true,
		ImmutablePayloadCount: 1,
		CgroupVersion:         task11synthetic.CgroupV2,
	}
	switch scenario {
	case task11synthetic.ScenarioCleanupListenerCrash:
		boundary.Boundary =
			task11synthetic.BoundaryListenerCrashArmed
	case task11synthetic.ScenarioCleanupUpgradeInterruption:
		boundary.Boundary =
			task11synthetic.BoundaryUpgradeInterruptionArmed
		boundary.UpgradeInterruptionExercised = true
	default:
		boundary.Boundary = task11synthetic.BoundaryListenerReady
	}
	if scenario == task11synthetic.ScenarioSeedFirst ||
		scenario == task11synthetic.ScenarioSeedSecond {
		boundary.SeedID = task11synthetic.SeedID
	}
	boundaryDocument, err := task11synthetic.MarshalBoundaryFrame(boundary)
	if err != nil {
		t.Fatalf("MarshalBoundaryFrame: %v", err)
	}
	if scenario == task11synthetic.ScenarioCleanupListenerCrash ||
		scenario ==
			task11synthetic.ScenarioCleanupUpgradeInterruption {
		return binding, boundaryDocument
	}
	resources := make(
		[]task11synthetic.ResourceHighWater,
		len(task11synthetic.Resources()),
	)
	for index, resource := range task11synthetic.Resources() {
		resources[index] = task11synthetic.ResourceHighWater{
			Resource:  resource,
			HighWater: uint64(index),
		}
	}
	terminal := task11synthetic.TerminalFrame{
		SchemaVersion:           task11synthetic.SchemaVersion,
		ProtocolID:              task11synthetic.ProtocolID,
		Frame:                   task11synthetic.FrameTerminal,
		Scenario:                scenario,
		CycleRunDigest:          runDigest,
		JobMarkerDigest:         jobMarker,
		Outcome:                 task11synthetic.OutcomeCompleted,
		ProxyRequestDigest:      strings.Repeat("c", 64),
		ResponseBodyProofDigest: strings.Repeat("d", 64),
		RegistrationRemoved:     true,
		SyntheticTokenAbsent:    true,
		ImmutablePayloadCount:   1,
		CgroupVersion:           task11synthetic.CgroupV2,
		Resources:               resources,
	}
	if scenario == task11synthetic.ScenarioSeedFirst ||
		scenario == task11synthetic.ScenarioSeedSecond {
		terminal.Seed = &task11synthetic.SeedProof{
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
	terminalDocument, err := task11synthetic.MarshalTerminalFrame(terminal)
	if err != nil {
		t.Fatalf("MarshalTerminalFrame: %v", err)
	}
	return binding, append(boundaryDocument, terminalDocument...)
}
