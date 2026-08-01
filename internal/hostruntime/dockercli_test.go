package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedCommand struct {
	argv  []string
	stdin []byte
}

type scriptedCommandRunner struct {
	mu        sync.Mutex
	commands  []recordedCommand
	contexts  []commandContext
	results   []Result
	errors    []error
	resultPos int
}

type commandContext struct {
	canceled    bool
	hasDeadline bool
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type failAfterReader struct {
	remaining int
	err       error
}

func (r *failAfterReader) Read(data []byte) (int, error) {
	if r.remaining == 0 {
		return 0, r.err
	}
	count := min(len(data), r.remaining)
	for i := range data[:count] {
		data[i] = byte(i + 1)
	}
	r.remaining -= count
	return count, nil
}

func (r *scriptedCommandRunner) Run(ctx context.Context, argv []string, _ []*os.File, stdin io.Reader) (Result, error) {
	var input []byte
	if stdin != nil {
		var err error
		input, err = io.ReadAll(stdin)
		if err != nil {
			return Result{}, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, recordedCommand{argv: slices.Clone(argv), stdin: input})
	_, hasDeadline := ctx.Deadline()
	r.contexts = append(r.contexts, commandContext{
		canceled:    ctx.Err() != nil,
		hasDeadline: hasDeadline,
	})

	var result Result
	if r.resultPos < len(r.results) {
		result = r.results[r.resultPos]
	}
	var err error
	if r.resultPos < len(r.errors) {
		err = r.errors[r.resultPos]
	}
	r.resultPos++
	return result, err
}

type blockingAdapterCreateRunner struct {
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
	calls   int
	id      string
}

func (r *blockingAdapterCreateRunner) Run(
	ctx context.Context,
	argv []string,
	_ []*os.File,
	_ io.Reader,
) (Result, error) {
	r.mu.Lock()
	r.calls++
	call := r.calls
	r.mu.Unlock()
	if call != 1 {
		return Result{}, errors.New("unexpected second command")
	}
	close(r.started)
	select {
	case <-r.release:
		return Result{Stdout: []byte(r.id + "\n")}, nil
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

func (r *blockingAdapterCreateRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func testSeccompBinding(t *testing.T) (SeccompBinding, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve seccomp fixture root: %v", err)
	}
	path := filepath.Join(root, "portable-ghar-capless-v1.json")
	contents := validSeccompJSON()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write seccomp fixture: %v", err)
	}
	digest := sha256.Sum256(contents)
	return SeccompBinding{Path: path, SHA256: hex.EncodeToString(digest[:])}, root
}

func TestValidateSeccompJSONRequiresClosedNamespaceBPFRawSocketDenials(t *testing.T) {
	valid := validSeccompJSON()
	if err := validateSeccompJSON(valid); err != nil {
		t.Fatalf("validateSeccompJSON valid profile: %v", err)
	}
	for name, mutation := range map[string]func([]byte) []byte{
		"allow by default": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"defaultAction":"SCMP_ACT_ALLOW"`), []byte(`"defaultAction":"SCMP_ACT_ERRNO"`), 1)
		},
		"missing setns": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"setns",`), nil, 1)
		},
		"missing clone newnet": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":1073741824,"valueTwo":1073741824,"op":"SCMP_CMP_MASKED_EQ"}]},`), nil, 1)
		},
		"missing packet socket": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`{"names":["socket"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":17,"valueTwo":0,"op":"SCMP_CMP_EQ"}]},`), nil, 1)
		},
		"raw socket changed to allow": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`{"names":["socket"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":1,"value":15,"valueTwo":3,"op":"SCMP_CMP_MASKED_EQ"}]}`), []byte(`{"names":["socket"],"action":"SCMP_ACT_ALLOW","errnoRet":1,"args":[{"index":1,"value":15,"valueTwo":3,"op":"SCMP_CMP_MASKED_EQ"}]}`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSeccompJSON(mutation(slices.Clone(valid))); err == nil {
				t.Fatal("validateSeccompJSON accepted weakened profile")
			}
		})
	}
}

func TestValidateSeccompProfileReturnsExactRawDigest(t *testing.T) {
	t.Parallel()

	document := validSeccompJSON()
	digest, err := ValidateSeccompProfile(document, len(document))
	if err != nil {
		t.Fatalf("ValidateSeccompProfile: %v", err)
	}
	expected := sha256.Sum256(document)
	if digest != hex.EncodeToString(expected[:]) {
		t.Fatalf("digest = %q, want %x", digest, expected)
	}
	if _, err := ValidateSeccompProfile(
		document,
		len(document)-1,
	); err == nil {
		t.Fatal("ValidateSeccompProfile accepted an oversized document")
	}
	invalid := bytes.Replace(
		document,
		[]byte(`"unshare"`),
		[]byte(`"getpid"`),
		1,
	)
	if _, err := ValidateSeccompProfile(
		invalid,
		len(invalid),
	); err == nil {
		t.Fatal("ValidateSeccompProfile accepted a weakened profile")
	}
}

func TestRepositorySeccompProfileMatchesClosedSourcePolicy(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(testFile), "..", "..", "config", "seccomp", "portable-ghar-capless-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile repository seccomp: %v", err)
	}
	if err := validateSeccompJSON(data); err != nil {
		t.Fatalf("repository seccomp policy: %v", err)
	}
}

func validSeccompJSON() []byte {
	return []byte(`{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["bpf","clone3","setns","unshare"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[]},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":131072,"valueTwo":131072,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":33554432,"valueTwo":33554432,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":67108864,"valueTwo":67108864,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":134217728,"valueTwo":134217728,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":268435456,"valueTwo":268435456,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":536870912,"valueTwo":536870912,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":1073741824,"valueTwo":1073741824,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["socket"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":0,"value":17,"valueTwo":0,"op":"SCMP_CMP_EQ"}]},{"names":["socket"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"args":[{"index":1,"value":15,"valueTwo":3,"op":"SCMP_CMP_MASKED_EQ"}]}]}` + "\n")
}

func validAdapterSpec(t *testing.T) (AdapterSpec, DockerCLIConfig) {
	t.Helper()
	seccomp, seccompRoot := testSeccompBinding(t)
	brokerRoot := t.TempDir()
	brokerParent := filepath.Join(brokerRoot, "slot-000007", "broker")

	return AdapterSpec{
			Name:            "pghar-adapter-000007",
			Image:           "portable-ghar/network-adapter@sha256:" + strings.Repeat("a", 64),
			BuildID:         strings.Repeat("b", 64),
			FleetGeneration: 17,
			SlotIdentity:    "slot-000007",
			BrokerParent:    brokerParent,
			User:            "65532:65532",
			Seccomp:         seccomp,
			Limits: ContainerLimits{
				MilliCPU:        250,
				MemoryBytes:     256 << 20,
				MemorySwapBytes: 320 << 20,
				PIDs:            64,
				FileDescriptors: 256,
				TmpfsBytes:      16 << 20,
				ScratchBytes:    32 << 20,
				LogBytes:        1 << 20,
				LogFiles:        2,
			},
		}, DockerCLIConfig{
			DockerPath:  "/usr/bin/docker",
			BrokerRoot:  brokerRoot,
			SeccompRoot: seccompRoot,
		}
}

func TestCreateNetworkAdapterUsesClosedIsolationArgv(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	containerID := strings.Repeat("c", 64)
	runner := &scriptedCommandRunner{results: []Result{{Stdout: []byte(containerID + "\n")}}}
	cli, err := NewDockerCLI(cfg, runner)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}

	handle, err := cli.CreateNetworkAdapter(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	if handle.ID() != containerID {
		t.Fatalf("handle ID = %q, want %q", handle.ID(), containerID)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("command count = %d, want 1", len(runner.commands))
	}
	argv := runner.commands[0].argv
	if len(argv) < 3 || argv[1] != "run" || argv[2] != "--detach" {
		t.Fatalf("adapter was not started as held namespace owner: %q", argv)
	}

	requireArgPair(t, argv, "--network", "none")
	requireArgPair(t, argv, "--cap-drop", "ALL")
	requireArg(t, argv, "--read-only")
	requireArgPair(t, argv, "--security-opt", "no-new-privileges=true")
	requireArgPair(t, argv, "--security-opt", "seccomp="+spec.Seccomp.Path)
	requireArgPair(t, argv, "--restart", "no")
	requireArgPair(t, argv, "--user", spec.User)
	requireArgPair(t, argv, "--pids-limit", "64")
	requireArgPair(t, argv, "--memory", fmt.Sprint(spec.Limits.MemoryBytes))
	requireArgPair(t, argv, "--memory-swap", fmt.Sprint(spec.Limits.MemorySwapBytes))
	requireArgPair(t, argv, "--ulimit", "nofile=256:256")
	requireArgPair(t, argv, "--log-driver", "local")
	requireArgPair(t, argv, "--mount", "type=bind,src="+spec.BrokerParent+",dst=/run/portable-ghar/broker,readonly")
	requireArgPair(t, argv, "--entrypoint", "/usr/local/bin/portable-ghar-network-adapter")

	if got := countArg(argv, "--mount"); got != 1 {
		t.Errorf("--mount count = %d, want 1", got)
	}
	for _, forbidden := range []string{"--privileged", "--publish", "--device", "--volume", "--env", "--env-file", "--pid", "--ipc", "--uts"} {
		if slices.Contains(argv, forbidden) {
			t.Errorf("adapter argv contains forbidden flag %q: %q", forbidden, argv)
		}
	}
	if len(runner.commands[0].stdin) != 0 {
		t.Fatalf("adapter create stdin length = %d, want 0", len(runner.commands[0].stdin))
	}
}

func TestCreateNetworkAdapterNeverDeletesWithoutAcceptedContainerID(t *testing.T) {
	runFailure := errors.New("adapter run failed")
	validID := strings.Repeat("c", 64)
	tests := []struct {
		name   string
		result Result
		runErr error
	}{
		{name: "runner error", runErr: runFailure},
		{name: "nonzero exit", result: Result{ExitCode: 17}},
		{name: "signal", result: Result{ExitCode: -1, Signaled: true, Signal: "killed"}},
		{name: "stdout truncated", result: Result{Stdout: []byte(validID), StdoutTruncated: true}},
		{name: "stderr truncated", result: Result{Stdout: []byte(validID), StderrTruncated: true}},
		{name: "nonempty stderr", result: Result{Stdout: []byte(validID), Stderr: []byte("warning")}},
		{name: "empty stdout"},
		{name: "malformed id", result: Result{Stdout: []byte("not-a-container-id\n")}},
		{name: "extra id", result: Result{Stdout: []byte(validID + "\n" + validID + "\n")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, cfg := validAdapterSpec(t)
			commands := &scriptedCommandRunner{
				results: []Result{tt.result},
				errors:  []error{tt.runErr},
			}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}

			_, err = cli.CreateNetworkAdapter(context.Background(), spec)
			if err == nil {
				t.Fatal("CreateNetworkAdapter accepted rejected Docker result")
			}
			if tt.runErr != nil && !errors.Is(err, tt.runErr) {
				t.Fatalf("CreateNetworkAdapter error %v does not preserve %v", err, tt.runErr)
			}
			if len(commands.commands) != 1 {
				t.Fatalf("commands = %q, want create only", commands.commands)
			}
		})
	}
}

func TestCreateRunnerNeverDeletesWithoutAcceptedContainerID(t *testing.T) {
	runFailure := errors.New("runner run failed")
	validID := strings.Repeat("d", 64)
	tests := []struct {
		name   string
		result Result
		runErr error
	}{
		{name: "runner error", runErr: runFailure},
		{name: "nonzero exit", result: Result{ExitCode: 17}},
		{name: "signal", result: Result{ExitCode: -1, Signaled: true, Signal: "killed"}},
		{name: "stdout truncated", result: Result{Stdout: []byte(validID), StdoutTruncated: true}},
		{name: "stderr truncated", result: Result{Stdout: []byte(validID), StderrTruncated: true}},
		{name: "nonempty stderr", result: Result{Stdout: []byte(validID), Stderr: []byte("warning")}},
		{name: "empty stdout"},
		{name: "malformed id", result: Result{Stdout: []byte("not-a-container-id\n")}},
		{name: "extra id", result: Result{Stdout: []byte(validID + "\n" + validID + "\n")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapterSpec, cfg := validAdapterSpec(t)
			adapterID := strings.Repeat("c", 64)
			commands := &scriptedCommandRunner{
				results: []Result{
					{Stdout: []byte(adapterID + "\n")},
					{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
					tt.result,
				},
				errors: []error{nil, nil, tt.runErr},
			}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
			if err != nil {
				t.Fatalf("CreateNetworkAdapter: %v", err)
			}
			spec := validRunnerSpec(adapter, adapterSpec.Seccomp)

			_, err = cli.CreateRunner(context.Background(), spec)
			if err == nil {
				t.Fatal("CreateRunner accepted rejected Docker result")
			}
			if tt.runErr != nil && !errors.Is(err, tt.runErr) {
				t.Fatalf("CreateRunner error %v does not preserve %v", err, tt.runErr)
			}
			if len(commands.commands) != 3 {
				t.Fatalf("commands = %q, want adapter+inspect+create", commands.commands)
			}
		})
	}
}

func TestRejectedCreateCleanupUsesIndependentBoundedContext(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	expected := rejectedCreateIdentity{
		ContainerID:     strings.Repeat("c", 64),
		Name:            spec.Name,
		Kind:            "network-adapter",
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
	}
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(rejectedCreateInspectJSON(
			expected.ContainerID,
			expected.Name,
			expected.Kind,
			expected.BuildID,
			expected.FleetGeneration,
			expected.SlotIdentity,
		))},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	primary := errors.New("create sentinel")
	err = cli.cleanupRejectedCreate(ctx, expected, primary)
	if !errors.Is(err, primary) {
		t.Fatalf("cleanup error = %v, want primary preserved", err)
	}
	if len(commands.contexts) != 2 {
		t.Fatalf("command contexts = %+v", commands.contexts)
	}
	for _, call := range commands.contexts {
		if call.canceled || !call.hasDeadline {
			t.Fatalf("cleanup command contexts = %+v", commands.contexts)
		}
	}
}

func TestRejectedCreateJoinsCleanupFailureAfterPrimaryFailure(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	expected := rejectedCreateIdentity{
		ContainerID:     strings.Repeat("c", 64),
		Name:            spec.Name,
		Kind:            "network-adapter",
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
	}
	primary := errors.New("create sentinel")
	cleanupErr := errors.New("cleanup sentinel")
	validInspect := Result{Stdout: []byte(rejectedCreateInspectJSON(
		expected.ContainerID,
		expected.Name,
		expected.Kind,
		expected.BuildID,
		expected.FleetGeneration,
		expected.SlotIdentity,
	))}

	for _, test := range []struct {
		name     string
		results  []Result
		errors   []error
		commands int
	}{
		{
			name:     "inspection",
			results:  []Result{{}},
			errors:   []error{cleanupErr},
			commands: 1,
		},
		{
			name:     "removal",
			results:  []Result{validInspect, {}},
			errors:   []error{nil, cleanupErr},
			commands: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := &scriptedCommandRunner{
				results: test.results,
				errors:  test.errors,
			}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			err = cli.cleanupRejectedCreate(
				context.Background(),
				expected,
				primary,
			)
			if !errors.Is(err, primary) || !errors.Is(err, cleanupErr) {
				t.Fatalf("cleanup error = %v, want both failures", err)
			}
			if len(commands.commands) != test.commands {
				t.Fatalf("commands = %q", commands.commands)
			}
		})
	}
}

func TestRejectedCreateCleanupNeverRemovesUnprovedContainer(t *testing.T) {
	t.Parallel()

	spec, cfg := validAdapterSpec(t)
	expected := rejectedCreateIdentity{
		ContainerID:     strings.Repeat("c", 64),
		Name:            spec.Name,
		Kind:            "network-adapter",
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
	}
	primary := errors.New("create sentinel")
	validDocument := func() []map[string]any {
		return []map[string]any{{
			"Id":   expected.ContainerID,
			"Name": "/" + expected.Name,
			"Config": map[string]any{"Labels": map[string]any{
				"io.portable-ghar.managed":          "true",
				"io.portable-ghar.kind":             expected.Kind,
				"io.portable-ghar.build-id":         expected.BuildID,
				"io.portable-ghar.fleet-generation": fmt.Sprint(expected.FleetGeneration),
				"io.portable-ghar.slot":             expected.SlotIdentity,
			}},
		}}
	}
	labels := func(document []map[string]any) map[string]any {
		return document[0]["Config"].(map[string]any)["Labels"].(map[string]any)
	}

	jsonCases := []struct {
		name   string
		mutate func([]map[string]any) []map[string]any
		raw    []byte
	}{
		{
			name: "wrong id",
			mutate: func(document []map[string]any) []map[string]any {
				document[0]["Id"] = strings.Repeat("d", 64)
				return document
			},
		},
		{
			name: "wrong name",
			mutate: func(document []map[string]any) []map[string]any {
				document[0]["Name"] = "/foreign"
				return document
			},
		},
		{
			name: "missing label",
			mutate: func(document []map[string]any) []map[string]any {
				delete(labels(document), "io.portable-ghar.slot")
				return document
			},
		},
		{
			name: "extra label",
			mutate: func(document []map[string]any) []map[string]any {
				labels(document)["foreign"] = "true"
				return document
			},
		},
		{
			name: "wrong label",
			mutate: func(document []map[string]any) []map[string]any {
				labels(document)["io.portable-ghar.kind"] = "runner"
				return document
			},
		},
		{
			name: "non-string label",
			mutate: func(document []map[string]any) []map[string]any {
				labels(document)["io.portable-ghar.managed"] = true
				return document
			},
		},
		{
			name: "nil labels",
			mutate: func(document []map[string]any) []map[string]any {
				document[0]["Config"].(map[string]any)["Labels"] = nil
				return document
			},
		},
		{
			name: "extra document",
			mutate: func(document []map[string]any) []map[string]any {
				return append(document, map[string]any{})
			},
		},
		{name: "malformed json", raw: []byte("[")},
		{name: "trailing json", raw: []byte("[]{}")},
	}

	for _, test := range jsonCases {
		t.Run(test.name, func(t *testing.T) {
			stdout := test.raw
			if test.mutate != nil {
				document := test.mutate(validDocument())
				var err error
				stdout, err = json.Marshal(document)
				if err != nil {
					t.Fatalf("marshal inspect fixture: %v", err)
				}
			}
			commands := &scriptedCommandRunner{results: []Result{{Stdout: stdout}}}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			if err := cli.cleanupRejectedCreate(
				context.Background(), expected, primary,
			); !errors.Is(err, primary) {
				t.Fatalf("cleanup error = %v, want primary preserved", err)
			}
			if len(commands.commands) != 1 {
				t.Fatalf("cleanup removed unproved container: %q", commands.commands)
			}
			if got := commands.commands[0].argv; !slices.Equal(got, []string{
				cfg.DockerPath, "inspect", "--type", "container", expected.ContainerID,
			}) {
				t.Fatalf("cleanup inspect argv = %q", got)
			}
		})
	}

	validJSON := []byte(rejectedCreateInspectJSON(
		expected.ContainerID,
		expected.Name,
		expected.Kind,
		expected.BuildID,
		expected.FleetGeneration,
		expected.SlotIdentity,
	))
	for _, test := range []struct {
		name   string
		result Result
		err    error
	}{
		{name: "runner error", err: errors.New("inspect failed")},
		{name: "nonzero exit", result: Result{ExitCode: 1}},
		{name: "signal", result: Result{Signaled: true}},
		{name: "stdout truncated", result: Result{Stdout: validJSON, StdoutTruncated: true}},
		{name: "stderr truncated", result: Result{Stdout: validJSON, StderrTruncated: true}},
		{name: "nonempty stderr", result: Result{Stdout: validJSON, Stderr: []byte("warning")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := &scriptedCommandRunner{
				results: []Result{test.result},
				errors:  []error{test.err},
			}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			if err := cli.cleanupRejectedCreate(
				context.Background(), expected, primary,
			); !errors.Is(err, primary) {
				t.Fatalf("cleanup error = %v, want primary preserved", err)
			}
			if len(commands.commands) != 1 {
				t.Fatalf("cleanup removed after failed inspection: %q", commands.commands)
			}
		})
	}
}

func TestRejectedNamedCreateCleanupProvesOwnedIDRemovalAndNameAbsence(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	id := strings.Repeat("c", 64)
	expected := rejectedCreateIdentity{
		Name:            "pghar-broker-000007-policy",
		Kind:            "network-policy-helper",
		Image:           "portable-ghar/network-helper@sha256:" + strings.Repeat("f", 64),
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
		Entrypoint:      []string{helperEntrypoint},
		Cmd:             []string{"apply"},
		NetworkMode:     "container:" + strings.Repeat("e", 64),
	}
	primary := errors.New("create sentinel")
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(id + "\n")},
		{Stdout: []byte(managedRejectedCreateInspectJSON(func() rejectedCreateIdentity {
			owned := expected
			owned.ContainerID = id
			return owned
		}()))},
		{},
		{},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	err = cli.cleanupRejectedNamedCreate(context.Background(), expected, primary)
	if !errors.Is(err, primary) || err.Error() != primary.Error() {
		t.Fatalf("cleanup error = %v, want primary only", err)
	}
	if got := commands.commands[2].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "rm", "-f", id,
	}) {
		t.Fatalf("cleanup removal argv = %q", got)
	}
	if len(commands.commands) != 5 {
		t.Fatalf("cleanup commands = %q", commands.commands)
	}
}

func TestRejectedNamedCreateCleanupNeverRemovesUnprovedInventory(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	id := strings.Repeat("c", 64)
	expected := rejectedCreateIdentity{
		Name:            "pghar-broker-000007",
		Kind:            "network-broker",
		Image:           "portable-ghar/network-broker-dialer@sha256:" + strings.Repeat("d", 64),
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
		Entrypoint:      []string{brokerEntrypoint},
		Cmd:             []string{"hold"},
		NetworkMode:     "pghar-egress",
	}
	primary := errors.New("create sentinel")
	for _, test := range []struct {
		name    string
		results []Result
	}{
		{name: "short id", results: []Result{{Stdout: []byte("abc123\n")}}},
		{name: "multiple ids", results: []Result{{Stdout: []byte(id + "\n" + strings.Repeat("d", 64) + "\n")}}},
		{
			name: "foreign identity",
			results: []Result{
				{Stdout: []byte(id + "\n")},
				{Stdout: []byte(rejectedCreateInspectJSON(
					id, expected.Name, "runner", expected.BuildID,
					expected.FleetGeneration, expected.SlotIdentity,
				))},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			commands := &scriptedCommandRunner{results: test.results}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			err = cli.cleanupRejectedNamedCreate(context.Background(), expected, primary)
			if !errors.Is(err, primary) || err.Error() == primary.Error() {
				t.Fatalf("cleanup error = %v, want primary plus proof failure", err)
			}
			for _, command := range commands.commands {
				if slices.Contains(command.argv, "rm") {
					t.Fatalf("unproved container was removed: %q", command.argv)
				}
			}
		})
	}
}

func TestRejectedNamedCreateCleanupAcceptsInspectGoneOnlyAfterBothAbsenceProofs(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	id := strings.Repeat("c", 64)
	expected := rejectedCreateIdentity{
		Name:            "pghar-broker-000007-policy",
		Kind:            "network-policy-helper",
		Image:           "portable-ghar/network-helper@sha256:" + strings.Repeat("f", 64),
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
		Entrypoint:      []string{helperEntrypoint},
		Cmd:             []string{"apply"},
		NetworkMode:     "container:" + strings.Repeat("e", 64),
	}
	primary := errors.New("create sentinel")
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(id + "\n")},
		{ExitCode: 1},
		{},
		{},
		{},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	err = cli.cleanupRejectedNamedCreate(context.Background(), expected, primary)
	if !errors.Is(err, primary) || err.Error() != primary.Error() {
		t.Fatalf("cleanup error = %v, want primary only", err)
	}
	for _, command := range commands.commands {
		if slices.Contains(command.argv, "rm") {
			t.Fatalf("already-gone container was removed: %q", command.argv)
		}
	}
	if len(commands.commands) != 6 {
		t.Fatalf("cleanup commands = %q", commands.commands)
	}
}

func TestRejectedNamedCreateCleanupRejectsNameReuseWithoutRemovingReplacement(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	id := strings.Repeat("c", 64)
	foreignID := strings.Repeat("d", 64)
	expected := rejectedCreateIdentity{
		Name:            "pghar-broker-000007-policy",
		Kind:            "network-policy-helper",
		Image:           "portable-ghar/network-helper@sha256:" + strings.Repeat("f", 64),
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
		Entrypoint:      []string{helperEntrypoint},
		Cmd:             []string{"apply"},
		NetworkMode:     "container:" + strings.Repeat("e", 64),
	}
	owned := expected
	owned.ContainerID = id
	primary := errors.New("create sentinel")
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(id + "\n")},
		{Stdout: []byte(managedRejectedCreateInspectJSON(owned))},
		{},
		{},
		{Stdout: []byte(foreignID + "\n")},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	err = cli.cleanupRejectedNamedCreate(context.Background(), expected, primary)
	if !errors.Is(err, primary) || err.Error() == primary.Error() {
		t.Fatalf("cleanup error = %v, want primary plus name-reuse failure", err)
	}
	removeCount := 0
	for _, command := range commands.commands {
		if slices.Contains(command.argv, "rm") {
			removeCount++
			if !slices.Equal(command.argv, []string{
				cfg.DockerPath, "rm", "-f", id,
			}) {
				t.Fatalf("replacement container was targeted: %q", command.argv)
			}
		}
	}
	if removeCount != 1 {
		t.Fatalf("cleanup removals = %d, want 1", removeCount)
	}
}

func TestCreateNonceFailuresDoNotRemoveAndReleaseTokenFailureDoes(t *testing.T) {
	randomErr := errors.New("random source failed")

	t.Run("adapter nonce", func(t *testing.T) {
		spec, cfg := validAdapterSpec(t)
		commands := &scriptedCommandRunner{}
		cli, err := NewDockerCLI(cfg, commands)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		cli.createRandom = failingReader{err: randomErr}
		if _, err := cli.CreateNetworkAdapter(context.Background(), spec); err == nil {
			t.Fatal("CreateNetworkAdapter accepted nonce failure")
		}
		if len(commands.commands) != 0 {
			t.Fatalf("commands = %q, want none", commands.commands)
		}
	})

	t.Run("runner nonce", func(t *testing.T) {
		adapterSpec, cfg := validAdapterSpec(t)
		adapterID := strings.Repeat("c", 64)
		commands := &scriptedCommandRunner{results: []Result{
			{Stdout: []byte(adapterID + "\n")},
			{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		}}
		cli, err := NewDockerCLI(cfg, commands)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
		if err != nil {
			t.Fatalf("CreateNetworkAdapter: %v", err)
		}
		cli.createRandom = failingReader{err: randomErr}
		if _, err := cli.CreateRunner(context.Background(), validRunnerSpec(adapter, adapterSpec.Seccomp)); err == nil {
			t.Fatal("CreateRunner accepted nonce failure")
		}
		if len(commands.commands) != 2 {
			t.Fatalf("command count = %d, want adapter create+inspect only", len(commands.commands))
		}
	})

	t.Run("runner release token", func(t *testing.T) {
		adapterSpec, cfg := validAdapterSpec(t)
		adapterID := strings.Repeat("c", 64)
		runnerID := strings.Repeat("d", 64)
		commands := &scriptedCommandRunner{results: []Result{
			{Stdout: []byte(adapterID + "\n")},
			{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
			{Stdout: []byte(runnerID + "\n")},
			{Stdout: []byte(rejectedCreateInspectJSON(
				runnerID,
				"pghar-runner-000007",
				"runner",
				adapterSpec.BuildID,
				adapterSpec.FleetGeneration,
				adapterSpec.SlotIdentity,
			))},
			{},
		}}
		cli, err := NewDockerCLI(cfg, commands)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
		if err != nil {
			t.Fatalf("CreateNetworkAdapter: %v", err)
		}
		cli.createRandom = &failAfterReader{remaining: 32, err: randomErr}
		spec := validRunnerSpec(adapter, adapterSpec.Seccomp)
		if _, err := cli.CreateRunner(context.Background(), spec); err == nil {
			t.Fatal("CreateRunner accepted release-token failure")
		}
		if len(commands.commands) != 5 {
			t.Fatalf("command count = %d, want adapter+inspect+create+cleanup-proof+cleanup", len(commands.commands))
		}
		if got := commands.commands[3].argv; !slices.Equal(got, []string{
			cfg.DockerPath, "inspect", "--type", "container", runnerID,
		}) {
			t.Fatalf("cleanup inspect argv = %q", got)
		}
		if got := commands.commands[4].argv; !slices.Equal(got, []string{
			cfg.DockerPath, "rm", "-f", runnerID,
		}) {
			t.Fatalf("cleanup argv = %q", got)
		}
	})
}

func TestPostIDNonceCollisionsRemoveOnlyExactInspectedContainer(t *testing.T) {
	t.Run("adapter", func(t *testing.T) {
		first, cfg := validAdapterSpec(t)
		second := first
		second.Name = "pghar-adapter-000008"
		second.SlotIdentity = "slot-000008"
		second.BrokerParent = filepath.Join(
			cfg.BrokerRoot,
			second.SlotIdentity,
			"broker",
		)
		firstID := strings.Repeat("c", 64)
		secondID := strings.Repeat("d", 64)
		commands := &scriptedCommandRunner{results: []Result{
			{Stdout: []byte(firstID + "\n")},
			{Stdout: []byte(secondID + "\n")},
			{Stdout: []byte(rejectedCreateInspectJSON(
				secondID,
				second.Name,
				"network-adapter",
				second.BuildID,
				second.FleetGeneration,
				second.SlotIdentity,
			))},
			{},
		}}
		cli, err := NewDockerCLI(cfg, commands)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		nonce := bytes.Repeat([]byte{0x11}, 32)
		random := append([]byte{}, nonce...)
		random = append(random, nonce...)
		cli.createRandom = bytes.NewReader(random)
		if _, err := cli.CreateNetworkAdapter(context.Background(), first); err != nil {
			t.Fatalf("first CreateNetworkAdapter: %v", err)
		}
		if _, err := cli.CreateNetworkAdapter(context.Background(), second); err == nil {
			t.Fatal("second CreateNetworkAdapter accepted nonce collision")
		}
		if len(commands.commands) != 4 {
			t.Fatalf("commands = %q", commands.commands)
		}
		if got := commands.commands[2].argv; !slices.Equal(got, []string{
			cfg.DockerPath, "inspect", "--type", "container", secondID,
		}) {
			t.Fatalf("cleanup inspect argv = %q", got)
		}
		if got := commands.commands[3].argv; !slices.Equal(got, []string{
			cfg.DockerPath, "rm", "-f", secondID,
		}) {
			t.Fatalf("cleanup argv = %q", got)
		}
	})

	t.Run("runner", func(t *testing.T) {
		adapterSpec, cfg := validAdapterSpec(t)
		adapterID := strings.Repeat("c", 64)
		firstRunnerID := strings.Repeat("d", 64)
		secondRunnerID := strings.Repeat("e", 64)
		commands := &scriptedCommandRunner{results: []Result{
			{Stdout: []byte(adapterID + "\n")},
			{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
			{Stdout: []byte(firstRunnerID + "\n")},
			{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
			{Stdout: []byte(secondRunnerID + "\n")},
			{Stdout: []byte(rejectedCreateInspectJSON(
				secondRunnerID,
				"pghar-runner-000008",
				"runner",
				adapterSpec.BuildID,
				adapterSpec.FleetGeneration,
				adapterSpec.SlotIdentity,
			))},
			{},
		}}
		cli, err := NewDockerCLI(cfg, commands)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		adapter, err := cli.CreateNetworkAdapter(
			context.Background(),
			adapterSpec,
		)
		if err != nil {
			t.Fatalf("CreateNetworkAdapter: %v", err)
		}
		nonce := bytes.Repeat([]byte{0x11}, 32)
		firstToken := bytes.Repeat([]byte{0x22}, releaseTokenBytes)
		secondToken := bytes.Repeat([]byte{0x33}, releaseTokenBytes)
		random := append([]byte{}, nonce...)
		random = append(random, firstToken...)
		random = append(random, nonce...)
		random = append(random, secondToken...)
		cli.createRandom = bytes.NewReader(random)
		first := validRunnerSpec(adapter, adapterSpec.Seccomp)
		if _, err := cli.CreateRunner(context.Background(), first); err != nil {
			t.Fatalf("first CreateRunner: %v", err)
		}
		second := first
		second.Name = "pghar-runner-000008"
		if _, err := cli.CreateRunner(context.Background(), second); err == nil {
			t.Fatal("second CreateRunner accepted nonce collision")
		}
		if len(commands.commands) != 7 {
			t.Fatalf("commands = %q", commands.commands)
		}
		if got := commands.commands[5].argv; !slices.Equal(got, []string{
			cfg.DockerPath, "inspect", "--type", "container", secondRunnerID,
		}) {
			t.Fatalf("cleanup inspect argv = %q", got)
		}
		if got := commands.commands[6].argv; !slices.Equal(got, []string{
			cfg.DockerPath, "rm", "-f", secondRunnerID,
		}) {
			t.Fatalf("cleanup argv = %q", got)
		}
	})
}

func TestCreateNameReservationRejectsPendingAndLiveDuplicatesBeforeRun(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	create := &blockingAdapterCreateRunner{
		started: make(chan struct{}),
		release: make(chan struct{}),
		id:      strings.Repeat("c", 64),
	}
	cli, err := NewDockerCLI(cfg, create)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, createErr := cli.CreateNetworkAdapter(context.Background(), spec)
		firstDone <- createErr
	}()
	select {
	case <-create.started:
	case <-time.After(time.Second):
		t.Fatal("first create did not reach Docker run")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, createErr := cli.CreateNetworkAdapter(context.Background(), spec)
		secondDone <- createErr
	}()
	select {
	case err := <-secondDone:
		if err == nil {
			t.Fatal("pending duplicate create succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("pending duplicate create blocked instead of failing")
	}
	if got := create.callCount(); got != 1 {
		t.Fatalf("Docker calls while first pending = %d, want 1", got)
	}

	close(create.release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first CreateNetworkAdapter: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first create did not finish")
	}
	if _, err := cli.CreateNetworkAdapter(context.Background(), spec); err == nil {
		t.Fatal("live duplicate create succeeded")
	}
	if got := create.callCount(); got != 1 {
		t.Fatalf("Docker calls after live duplicate = %d, want 1", got)
	}
}

func TestCreateNameReservationReleasesAfterRejectedCreateForRetry(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	containerID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{ExitCode: 17},
		{Stdout: []byte(containerID + "\n")},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	if _, err := cli.CreateNetworkAdapter(context.Background(), spec); err == nil {
		t.Fatal("first CreateNetworkAdapter accepted failed create")
	}
	handle, err := cli.CreateNetworkAdapter(context.Background(), spec)
	if err != nil {
		t.Fatalf("retry CreateNetworkAdapter: %v", err)
	}
	if handle.ID() != containerID {
		t.Fatalf("retry ID = %q, want %q", handle.ID(), containerID)
	}
	if len(commands.commands) != 2 {
		t.Fatalf("command count = %d, want create+retry", len(commands.commands))
	}
}

func TestRemoveNetworkAdapterUsesOpaqueHandleAndBoundsRecords(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	containerID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(containerID + "\n")},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	handle, err := cli.CreateNetworkAdapter(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	if err := cli.RemoveNetworkAdapter(context.Background(), handle); err != nil {
		t.Fatalf("RemoveNetworkAdapter: %v", err)
	}
	if len(cli.adapters) != 0 {
		t.Fatalf("adapter records=%d, want 0", len(cli.adapters))
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "rm", "-f", containerID,
	}) {
		t.Fatalf("RemoveNetworkAdapter argv=%q", got)
	}
	if err := cli.RemoveNetworkAdapter(context.Background(), AdapterHandle{}); err == nil {
		t.Fatal("RemoveNetworkAdapter accepted a zero handle")
	}
}

func TestRemoveNetworkAdapterRetainsOnlyRetryableTombstoneOnDockerFailure(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	containerID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(containerID + "\n")},
		{ExitCode: 1},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	handle, err := cli.CreateNetworkAdapter(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	if err := cli.RemoveNetworkAdapter(context.Background(), handle); err == nil {
		t.Fatal("RemoveNetworkAdapter accepted failed Docker removal")
	}
	record := cli.adapters[handle.nonce]
	if record == nil || !record.destroyed || record.busy {
		t.Fatalf("failed-removal tombstone=%+v", record)
	}
	if err := cli.RemoveNetworkAdapter(context.Background(), handle); err != nil {
		t.Fatalf("RemoveNetworkAdapter retry: %v", err)
	}
	if len(cli.adapters) != 0 {
		t.Fatalf("adapter records after retry=%d, want 0", len(cli.adapters))
	}
}

func TestCreateNetworkAdapterRejectsOptionAndPathInjectionBeforeCommand(t *testing.T) {
	base, cfg := validAdapterSpec(t)
	tests := []struct {
		name   string
		mutate func(*AdapterSpec)
	}{
		{"option name", func(s *AdapterSpec) { s.Name = "--privileged" }},
		{"newline name", func(s *AdapterSpec) { s.Name = "pghar\n--privileged" }},
		{"mutable image tag", func(s *AdapterSpec) { s.Image = "portable-ghar/network-adapter:latest" }},
		{"broker escape", func(s *AdapterSpec) { s.BrokerParent = filepath.Join(cfg.BrokerRoot, "..", "escape") }},
		{"user option", func(s *AdapterSpec) { s.User = "--user=0" }},
		{"bad build id", func(s *AdapterSpec) { s.BuildID = "job-controlled" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := base
			tt.mutate(&spec)
			runner := &scriptedCommandRunner{}
			cli, err := NewDockerCLI(cfg, runner)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			if _, err := cli.CreateNetworkAdapter(context.Background(), spec); err == nil {
				t.Fatal("CreateNetworkAdapter accepted injected value")
			}
			if len(runner.commands) != 0 {
				t.Fatalf("command count = %d, want 0", len(runner.commands))
			}
		})
	}
}

func TestResourceLimitsRejectMilliCPUThatOverflowsDockerNanoCPUs(t *testing.T) {
	tooLarge := uint64(math.MaxInt64)/1_000_000 + 1
	adapter, cfg := validAdapterSpec(t)
	adapter.Limits.MilliCPU = tooLarge
	commands := &scriptedCommandRunner{}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	if _, err := cli.CreateNetworkAdapter(context.Background(), adapter); err == nil {
		t.Fatal("CreateNetworkAdapter accepted MilliCPU that overflows NanoCPUs")
	}

	adapter.Limits.MilliCPU = 250
	adapterID := strings.Repeat("c", 64)
	commands.results = append(commands.results, Result{Stdout: []byte(adapterID + "\n")})
	handle, err := cli.CreateNetworkAdapter(context.Background(), adapter)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	runnerSpec := validRunnerSpec(handle, adapter.Seccomp)
	runnerSpec.Limits.MilliCPU = tooLarge
	if _, err := cli.CreateRunner(context.Background(), runnerSpec); err == nil {
		t.Fatal("CreateRunner accepted MilliCPU that overflows NanoCPUs")
	}
}

func TestDockerMemorySwapTotalsRejectOmissionUnderflowAndOverflow(t *testing.T) {
	adapter, _ := validAdapterSpec(t)
	runner := validRunnerSpec(AdapterHandle{}, adapter.Seccomp)
	broker := BrokerLimits{
		MilliCPU:        1,
		MemoryBytes:     4,
		MemorySwapBytes: 4,
		PIDs:            1,
		FileDescriptors: 1,
		StateBytes:      1,
		ScratchBytes:    1,
		LogBytes:        1,
		LogFiles:        1,
	}
	oneShot := OneShotLimits{
		MilliCPU:        1,
		MemoryBytes:     helperRunTmpfsBytes,
		MemorySwapBytes: helperRunTmpfsBytes,
		PIDs:            1,
		FileDescriptors: 1,
	}

	tests := map[string]struct {
		validate func() error
	}{
		"adapter omitted": {
			validate: func() error {
				value := adapter.Limits
				value.MemorySwapBytes = 0
				return validateContainerLimits(value)
			},
		},
		"adapter below memory": {
			validate: func() error {
				value := adapter.Limits
				value.MemorySwapBytes = value.MemoryBytes - 1
				return validateContainerLimits(value)
			},
		},
		"runner above docker range": {
			validate: func() error {
				value := runner.Limits
				value.MemorySwapBytes = uint64(math.MaxInt64) + 1
				return validateRunnerLimits(value)
			},
		},
		"broker below memory": {
			validate: func() error {
				value := broker
				value.MemorySwapBytes = value.MemoryBytes - 1
				return validateBrokerLimits(value)
			},
		},
		"one shot omitted": {
			validate: func() error {
				value := oneShot
				value.MemorySwapBytes = 0
				return validateOneShotLimits(value)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := test.validate(); err == nil {
				t.Fatal("invalid memory-plus-swap total accepted")
			}
		})
	}
	if err := validateOneShotLimits(oneShot); err != nil {
		t.Fatalf("explicit zero-swap one-shot total rejected: %v", err)
	}
}

func TestCreateNetworkAdapterRejectsUnverifiedSeccompIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AdapterSpec, DockerCLIConfig) error
	}{
		{
			name: "digest mismatch",
			mutate: func(spec *AdapterSpec, _ DockerCLIConfig) error {
				spec.Seccomp.SHA256 = strings.Repeat("f", 64)
				return nil
			},
		},
		{
			name: "malformed json with matching digest",
			mutate: func(spec *AdapterSpec, _ DockerCLIConfig) error {
				contents := []byte(`{"defaultAction":`)
				if err := os.WriteFile(spec.Seccomp.Path, contents, 0o600); err != nil {
					return err
				}
				digest := sha256.Sum256(contents)
				spec.Seccomp.SHA256 = hex.EncodeToString(digest[:])
				return nil
			},
		},
		{
			name: "symlink alias",
			mutate: func(spec *AdapterSpec, cfg DockerCLIConfig) error {
				alias := filepath.Join(cfg.SeccompRoot, "alias.json")
				if err := os.Symlink(spec.Seccomp.Path, alias); err != nil {
					return err
				}
				spec.Seccomp.Path = alias
				return nil
			},
		},
		{
			name: "group writable",
			mutate: func(spec *AdapterSpec, _ DockerCLIConfig) error {
				return os.Chmod(spec.Seccomp.Path, 0o620)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, cfg := validAdapterSpec(t)
			if err := tt.mutate(&spec, cfg); err != nil {
				t.Fatalf("mutate fixture: %v", err)
			}
			runner := &scriptedCommandRunner{}
			cli, err := NewDockerCLI(cfg, runner)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			if _, err := cli.CreateNetworkAdapter(context.Background(), spec); err == nil {
				t.Fatal("CreateNetworkAdapter accepted unverified seccomp identity")
			}
			if len(runner.commands) != 0 {
				t.Fatalf("command count = %d, want 0", len(runner.commands))
			}
		})
	}
}

func TestCreateNetworkAdapterRejectsResourceArithmeticOverflow(t *testing.T) {
	spec, cfg := validAdapterSpec(t)
	spec.Limits.MemoryBytes = math.MaxInt64
	spec.Limits.TmpfsBytes = math.MaxUint64
	spec.Limits.ScratchBytes = 1
	runner := &scriptedCommandRunner{}
	cli, err := NewDockerCLI(cfg, runner)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	if _, err := cli.CreateNetworkAdapter(context.Background(), spec); err == nil {
		t.Fatal("CreateNetworkAdapter accepted overflowing resource sum")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("command count = %d, want 0", len(runner.commands))
	}
}

func TestCreateRunnerReinspectsOpaqueAdapterAndUsesFixedProxyEnvironment(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	runnerID := strings.Repeat("d", 64)
	inspect := managedAdapterInspectJSON(adapterID, adapterSpec)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(inspect)},
		{Stdout: []byte(runnerID + "\n")},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}

	runnerSpec := validRunnerSpec(adapter, adapterSpec.Seccomp)
	handle, err := cli.CreateRunner(context.Background(), runnerSpec)
	if err != nil {
		t.Fatalf("CreateRunner: %v", err)
	}
	if handle.ID() != runnerID {
		t.Fatalf("runner ID = %q, want %q", handle.ID(), runnerID)
	}
	if len(commands.commands) != 3 {
		t.Fatalf("command count = %d, want 3", len(commands.commands))
	}
	if !slices.Contains(commands.commands[1].argv, "inspect") {
		t.Fatalf("second command is not adapter re-inspection: %q", commands.commands[1].argv)
	}
	argv := commands.commands[2].argv
	if len(argv) < 3 || argv[1] != "run" || argv[2] != "--detach" {
		t.Fatalf("runner was not started as held gate owner: %q", argv)
	}
	requireArgPair(t, argv, "--network", "container:"+adapterID)
	requireArgPair(t, argv, "--user", "65532:65532")
	requireArgPair(t, argv, "--cap-drop", "ALL")
	requireArg(t, argv, "--read-only")
	requireArgPair(t, argv, "--security-opt", "no-new-privileges=true")
	requireArgPair(t, argv, "--restart", "no")
	requireArgPair(t, argv, "--entrypoint", "/usr/local/bin/portable-ghar-runner-gate")
	requireArgPair(t, argv, "--memory-swap", fmt.Sprint(runnerSpec.Limits.MemorySwapBytes))
	requireArgPair(t, argv, "--tmpfs", fmt.Sprintf("/runner:rw,exec,nosuid,nodev,size=%d,uid=65532,gid=65532,mode=0700", runnerSpec.Limits.RunnerTmpfsBytes))
	requireArgPair(t, argv, "--tmpfs", fmt.Sprintf("/tmp:rw,exec,nosuid,nodev,size=%d,uid=65532,gid=65532,mode=0700", runnerSpec.Limits.TmpTmpfsBytes))
	loopback := strings.Join([]string{"127", "0", "0", "1"}, ".")
	ipv6Loopback := strings.Join([]string{"", "", "1"}, ":")
	requireArgPair(t, argv, "--env", "HTTPS_PROXY=http://"+loopback+":18080")
	requireArgPair(t, argv, "--env", "https_proxy=http://"+loopback+":18080")
	requireArgPair(t, argv, "--env", "NO_PROXY="+loopback+","+ipv6Loopback)
	requireArgPair(t, argv, "--env", "no_proxy="+loopback+","+ipv6Loopback)
	if got := countArg(argv, "--env"); got != 4 {
		t.Fatalf("runner env count = %d, want 4", got)
	}
	for index, arg := range argv {
		if index > 0 && argv[index-1] == "--env" &&
			strings.HasPrefix(arg, "HTTP_PROXY=") {
			t.Fatalf("runner argv enables plaintext HTTP proxy: %q", argv)
		}
	}

	for _, forbidden := range []string{"--mount", "--volume", "--device", "--env-file", "--publish", "--privileged"} {
		if slices.Contains(argv, forbidden) {
			t.Errorf("runner argv contains forbidden flag %q: %q", forbidden, argv)
		}
	}
	secretCorpus := []string{"opaque-jit-fixture", "one-use-token-fixture"}
	joined := strings.Join(argv, "\x00")
	for _, secret := range secretCorpus {
		if strings.Contains(joined, secret) {
			t.Errorf("runner argv leaked secret corpus %q", secret)
		}
	}
}

func TestCreateRunnerRejectsTmpfsThatCannotFitMemoryCgroup(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}

	spec := validRunnerSpec(adapter, adapterSpec.Seccomp)
	spec.Limits.MemoryBytes = 2 << 30
	spec.Limits.RunnerTmpfsBytes = 2162 << 20
	spec.Limits.TmpTmpfsBytes = 128 << 20
	spec.Limits.ProcessMarginBytes = 256 << 20
	if _, err := cli.CreateRunner(context.Background(), spec); err == nil {
		t.Fatal("CreateRunner accepted tmpfs+margin above memory cgroup")
	}
	if len(commands.commands) != 1 {
		t.Fatalf("command count = %d, want only adapter create before local rejection", len(commands.commands))
	}
}

func TestCreateRunnerRejectsZeroOrStaleAdapterHandle(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cli, err := NewDockerCLI(cfg, &scriptedCommandRunner{})
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	spec := validRunnerSpec(AdapterHandle{}, adapterSpec.Seccomp)
	if _, err := cli.CreateRunner(context.Background(), spec); err == nil {
		t.Fatal("CreateRunner accepted zero AdapterHandle")
	}
}

func TestCreateRunnerRejectsHandleFromAnotherEngine(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	issuerRunner := &scriptedCommandRunner{results: []Result{{Stdout: []byte(adapterID + "\n")}}}
	issuer, err := NewDockerCLI(cfg, issuerRunner)
	if err != nil {
		t.Fatalf("NewDockerCLI issuer: %v", err)
	}
	adapter, err := issuer.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}

	otherRunner := &scriptedCommandRunner{}
	other, err := NewDockerCLI(cfg, otherRunner)
	if err != nil {
		t.Fatalf("NewDockerCLI other: %v", err)
	}
	if _, err := other.CreateRunner(context.Background(), validRunnerSpec(adapter, adapterSpec.Seccomp)); err == nil {
		t.Fatal("CreateRunner accepted a handle issued by another engine")
	}
	if len(otherRunner.commands) != 0 {
		t.Fatalf("other engine command count = %d, want 0", len(otherRunner.commands))
	}
}

func TestCreateRunnerRejectsBuildOrGenerationMismatchBeforeInspect(t *testing.T) {
	for _, mutate := range []func(*RunnerSpec){
		func(spec *RunnerSpec) { spec.BuildID = strings.Repeat("a", 64) },
		func(spec *RunnerSpec) { spec.FleetGeneration++ },
	} {
		adapterSpec, cfg := validAdapterSpec(t)
		adapterID := strings.Repeat("c", 64)
		commands := &scriptedCommandRunner{results: []Result{{Stdout: []byte(adapterID + "\n")}}}
		cli, err := NewDockerCLI(cfg, commands)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
		if err != nil {
			t.Fatalf("CreateNetworkAdapter: %v", err)
		}
		spec := validRunnerSpec(adapter, adapterSpec.Seccomp)
		mutate(&spec)
		if _, err := cli.CreateRunner(context.Background(), spec); err == nil {
			t.Fatal("CreateRunner accepted mismatched adapter binding")
		}
		if len(commands.commands) != 1 {
			t.Fatalf("command count = %d, want adapter create only", len(commands.commands))
		}
	}
}

func TestCreateRunnerRejectsAdapterInspectDrift(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{"id", strings.Repeat("c", 64), strings.Repeat("f", 64)},
		{"image", "portable-ghar/network-adapter@sha256:" + strings.Repeat("a", 64), "portable-ghar/network-adapter@sha256:" + strings.Repeat("f", 64)},
		{"managed label", `"io.portable-ghar.managed":"true"`, `"io.portable-ghar.managed":"false"`},
		{"running state", `"Running":true`, `"Running":false`},
		{"network mode", `"NetworkMode":"none"`, `"NetworkMode":"bridge"`},
		{"restart policy", `"Name":"no"`, `"Name":"always"`},
		{"readonly root", `"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`},
		{"cap drop", `"CapDrop":["ALL"]`, `"CapDrop":[]`},
		{"memory swap", `"MemorySwap":335544320`, `"MemorySwap":335544319`},
		{"mount writable", `"RW":false`, `"RW":true`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapterSpec, cfg := validAdapterSpec(t)
			adapterID := strings.Repeat("c", 64)
			inspect := managedAdapterInspectJSON(adapterID, adapterSpec)
			inspect = strings.Replace(inspect, tt.old, tt.new, 1)
			commands := &scriptedCommandRunner{results: []Result{
				{Stdout: []byte(adapterID + "\n")},
				{Stdout: []byte(inspect)},
			}}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
			if err != nil {
				t.Fatalf("CreateNetworkAdapter: %v", err)
			}
			if _, err := cli.CreateRunner(context.Background(), validRunnerSpec(adapter, adapterSpec.Seccomp)); err == nil {
				t.Fatal("CreateRunner accepted drifted adapter inspection")
			}
			if len(commands.commands) != 2 {
				t.Fatalf("command count = %d, want create+inspect", len(commands.commands))
			}
		})
	}
}

func TestCreateRunnerRejectsResourceArithmeticOverflow(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{{Stdout: []byte(adapterID + "\n")}}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validRunnerSpec(adapter, adapterSpec.Seccomp)
	spec.Limits.MemoryBytes = math.MaxInt64
	spec.Limits.RunnerTmpfsBytes = math.MaxUint64
	spec.Limits.TmpTmpfsBytes = 1
	if _, err := cli.CreateRunner(context.Background(), spec); err == nil {
		t.Fatal("CreateRunner accepted overflowing tmpfs sum")
	}
	if len(commands.commands) != 1 {
		t.Fatalf("command count = %d, want adapter create only", len(commands.commands))
	}
}

func TestCreateRunnerCarriesCompleteBoundedResourceVector(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(strings.Repeat("d", 64) + "\n")},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validRunnerSpec(adapter, adapterSpec.Seccomp)
	if _, err := cli.CreateRunner(context.Background(), spec); err != nil {
		t.Fatalf("CreateRunner: %v", err)
	}
	argv := commands.commands[2].argv
	for _, pair := range [][2]string{
		{"--cpus", "1.5"},
		{"--memory", fmt.Sprint(spec.Limits.MemoryBytes)},
		{"--memory-swap", fmt.Sprint(spec.Limits.MemorySwapBytes)},
		{"--pids-limit", "512"},
		{"--ulimit", "nofile=1024:1024"},
		{"--tmpfs", fmt.Sprintf("/scratch:rw,exec,nosuid,nodev,size=%d,uid=65532,gid=65532,mode=0700", spec.Limits.ScratchBytes)},
		{"--log-driver", "local"},
		{"--log-opt", fmt.Sprintf("max-size=%db", spec.Limits.LogBytes)},
		{"--log-opt", "max-file=2"},
	} {
		requireArgPair(t, argv, pair[0], pair[1])
	}
	if countArg(argv, "--tmpfs") != 3 {
		t.Fatalf("runner --tmpfs count = %d, want 3", countArg(argv, "--tmpfs"))
	}
}

func TestQTSRootProfileIsExplicitlyDegradedAndStrictProfileRejectsRoot(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(strings.Repeat("d", 64) + "\n")},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}

	strict := validRunnerSpec(adapter, adapterSpec.Seccomp)
	strict.User = "0:0"
	if _, err := cli.CreateRunner(context.Background(), strict); err == nil {
		t.Fatal("strict-linux accepted UID 0")
	}

	degraded := validRunnerSpec(adapter, adapterSpec.Seccomp)
	degraded.Profile = HostProfileQTSCaplessRoot
	degraded.User = "0:0"
	handle, err := cli.CreateRunner(context.Background(), degraded)
	if err != nil {
		t.Fatalf("qts-capless-root CreateRunner: %v", err)
	}
	if !handle.Degraded() {
		t.Fatal("qts-capless-root handle did not report degraded")
	}
}

func validRunnerSpec(adapter AdapterHandle, seccomp SeccompBinding) RunnerSpec {
	return RunnerSpec{
		Name:            "pghar-runner-000007",
		Image:           "portable-ghar/runner@sha256:" + strings.Repeat("e", 64),
		BuildID:         strings.Repeat("b", 64),
		FleetGeneration: 17,
		SlotIdentity:    adapter.slotIdentity,
		Adapter:         adapter,
		Profile:         HostProfileStrictLinux,
		User:            "65532:65532",
		Seccomp:         seccomp,
		Limits: RunnerLimits{
			MilliCPU:           1500,
			MemoryBytes:        5 << 30,
			MemorySwapBytes:    6 << 30,
			PIDs:               512,
			FileDescriptors:    1024,
			ScratchBytes:       1 << 30,
			LogBytes:           4 << 20,
			LogFiles:           2,
			RunnerTmpfsBytes:   3 << 30,
			TmpTmpfsBytes:      256 << 20,
			ProcessMarginBytes: 512 << 20,
		},
	}
}

func TestHeldRunnerEnvironmentIsClosedAndOrderIndependent(t *testing.T) {
	valid := [][]string{
		{runnerHome, runnerLanguage, baseRunnerPath},
		{baseRunnerPath, runnerHome, runnerLanguage},
		{runnerLanguage, baseRunnerPath, runnerHome},
	}
	for _, environment := range valid {
		if !validHeldRunnerEnvironment(environment) {
			t.Fatalf("validHeldRunnerEnvironment rejected %q", environment)
		}
	}

	invalid := [][]string{
		nil,
		{},
		{baseRunnerPath},
		{runnerHome, runnerLanguage, baseRunnerPath, baseRunnerPath},
		{runnerHome, runnerLanguage, "PATH=/usr/bin"},
		{runnerHome, runnerLanguage, baseRunnerPath, "TOKEN=secret"},
		{"HOME=/tmp", runnerLanguage, baseRunnerPath},
		{runnerHome, "LANG=en_US.UTF-8", baseRunnerPath},
	}
	for _, environment := range invalid {
		if validHeldRunnerEnvironment(environment) {
			t.Fatalf("validHeldRunnerEnvironment accepted %q", environment)
		}
	}
}

func managedAdapterInspectJSON(id string, spec AdapterSpec) string {
	document := []map[string]any{{
		"Id": id,
		"Config": map[string]any{
			"Image": spec.Image,
			"Labels": map[string]string{
				"io.portable-ghar.managed":          "true",
				"io.portable-ghar.kind":             "network-adapter",
				"io.portable-ghar.build-id":         spec.BuildID,
				"io.portable-ghar.fleet-generation": fmt.Sprint(spec.FleetGeneration),
				"io.portable-ghar.slot":             spec.SlotIdentity,
			},
			"Env":        []string{},
			"Entrypoint": []string{adapterEntrypoint},
			"Cmd":        []string{"hold"},
			"User":       spec.User,
		},
		"State": map[string]any{
			"Running": true, "Restarting": false, "Dead": false, "Pid": 7000, "ExitCode": 0,
		},
		"HostConfig": map[string]any{
			"NetworkMode":     "none",
			"ReadonlyRootfs":  true,
			"CapAdd":          []string{},
			"CapDrop":         []string{"ALL"},
			"SecurityOpt":     []string{"no-new-privileges=true", "seccomp=" + spec.Seccomp.Path},
			"Binds":           []string{},
			"Devices":         []any{},
			"Privileged":      false,
			"PortBindings":    map[string]any{},
			"PublishAllPorts": false,
			"PidMode":         "",
			"IpcMode":         "",
			"UTSMode":         "",
			"Tmpfs":           adapterTmpfs(spec),
			"Memory":          int64(spec.Limits.MemoryBytes),
			"MemorySwap":      int64(spec.Limits.MemorySwapBytes),
			"NanoCpus":        int64(spec.Limits.MilliCPU) * 1_000_000,
			"PidsLimit":       int64(spec.Limits.PIDs),
			"Ulimits": []map[string]any{{
				"Name": "nofile", "Soft": int64(spec.Limits.FileDescriptors), "Hard": int64(spec.Limits.FileDescriptors),
			}},
			"LogConfig": map[string]any{
				"Type": "local",
				"Config": map[string]string{
					"max-size": fmt.Sprint(spec.Limits.LogBytes) + "b",
					"max-file": fmt.Sprint(spec.Limits.LogFiles),
				},
			},
			"RestartPolicy": map[string]any{"Name": "no"},
		},
		"Mounts": []map[string]any{{
			"Type":        "bind",
			"Source":      spec.BrokerParent,
			"Destination": adapterMountDst,
			"Mode":        "",
			"RW":          false,
			"Propagation": "rprivate",
		}},
	}}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func rejectedCreateInspectJSON(
	id string,
	name string,
	kind string,
	buildID string,
	generation uint64,
	slot string,
) string {
	document := []map[string]any{{
		"Id":   id,
		"Name": "/" + name,
		"Config": map[string]any{"Labels": map[string]string{
			"io.portable-ghar.managed":          "true",
			"io.portable-ghar.kind":             kind,
			"io.portable-ghar.build-id":         buildID,
			"io.portable-ghar.fleet-generation": fmt.Sprint(generation),
			"io.portable-ghar.slot":             slot,
		}},
	}}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func managedRejectedCreateInspectJSON(identity rejectedCreateIdentity) string {
	document := []map[string]any{{
		"Id":   identity.ContainerID,
		"Name": "/" + identity.Name,
		"Config": map[string]any{
			"Image": identity.Image,
			"Labels": map[string]string{
				"io.portable-ghar.managed":          "true",
				"io.portable-ghar.kind":             identity.Kind,
				"io.portable-ghar.build-id":         identity.BuildID,
				"io.portable-ghar.fleet-generation": fmt.Sprint(identity.FleetGeneration),
				"io.portable-ghar.slot":             identity.SlotIdentity,
			},
			"Entrypoint": identity.Entrypoint,
			"Cmd":        identity.Cmd,
		},
		"HostConfig": map[string]any{
			"NetworkMode": identity.NetworkMode,
		},
	}}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func managedRunnerInspectJSON(id string, spec RunnerSpec, pid int64) string {
	document := []map[string]any{{
		"Id": id,
		"Config": map[string]any{
			"Image": spec.Image,
			"Labels": map[string]string{
				"io.portable-ghar.managed":          "true",
				"io.portable-ghar.kind":             "runner",
				"io.portable-ghar.build-id":         spec.BuildID,
				"io.portable-ghar.fleet-generation": fmt.Sprint(spec.FleetGeneration),
				"io.portable-ghar.slot":             spec.SlotIdentity,
			},
			"Env":        []string{baseRunnerPath, runnerHome, runnerLanguage},
			"Entrypoint": []string{runnerEntrypoint},
			"Cmd":        []string{"hold"},
			"User":       spec.User,
		},
		"State": map[string]any{
			"Running": true, "Restarting": false, "Dead": false, "Pid": pid, "ExitCode": 0,
		},
		"HostConfig": map[string]any{
			"NetworkMode":     "container:" + spec.Adapter.id,
			"ReadonlyRootfs":  true,
			"CapAdd":          []string{},
			"CapDrop":         []string{"ALL"},
			"SecurityOpt":     []string{"no-new-privileges=true", "seccomp=" + spec.Seccomp.Path},
			"Binds":           []string{},
			"Devices":         []any{},
			"Privileged":      false,
			"PortBindings":    map[string]any{},
			"PublishAllPorts": false,
			"PidMode":         "",
			"IpcMode":         "",
			"UTSMode":         "",
			"Tmpfs":           runnerTmpfs(spec),
			"Memory":          int64(spec.Limits.MemoryBytes),
			"MemorySwap":      int64(spec.Limits.MemorySwapBytes),
			"NanoCpus":        int64(spec.Limits.MilliCPU) * 1_000_000,
			"PidsLimit":       int64(spec.Limits.PIDs),
			"Ulimits": []map[string]any{{
				"Name": "nofile", "Soft": int64(spec.Limits.FileDescriptors), "Hard": int64(spec.Limits.FileDescriptors),
			}},
			"LogConfig": map[string]any{
				"Type": "local",
				"Config": map[string]string{
					"max-size": fmt.Sprint(spec.Limits.LogBytes) + "b",
					"max-file": fmt.Sprint(spec.Limits.LogFiles),
				},
			},
			"RestartPolicy": map[string]any{"Name": "no"},
		},
		"Mounts": []any{},
	}}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func requireArg(t *testing.T, argv []string, want string) {
	t.Helper()
	if !slices.Contains(argv, want) {
		t.Errorf("argv %q does not contain %q", argv, want)
	}
}

func requireArgPair(t *testing.T, argv []string, key, value string) {
	t.Helper()
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == key && argv[i+1] == value {
			return
		}
	}
	t.Errorf("argv %q does not contain pair %q %q", argv, key, value)
}

func countArg(argv []string, want string) int {
	count := 0
	for _, arg := range argv {
		if arg == want {
			count++
		}
	}
	return count
}
