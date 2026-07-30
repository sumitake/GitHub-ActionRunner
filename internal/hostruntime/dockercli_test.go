package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type recordedCommand struct {
	argv  []string
	stdin []byte
}

type scriptedCommandRunner struct {
	commands  []recordedCommand
	results   []Result
	errors    []error
	resultPos int
}

func (r *scriptedCommandRunner) Run(_ context.Context, argv []string, _ []*os.File, stdin io.Reader) (Result, error) {
	var input []byte
	if stdin != nil {
		var err error
		input, err = io.ReadAll(stdin)
		if err != nil {
			return Result{}, err
		}
	}
	r.commands = append(r.commands, recordedCommand{argv: slices.Clone(argv), stdin: input})

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

func TestCreateRunnerReinspectsOpaqueAdapterAndUsesNoMountOrSecretMetadata(t *testing.T) {
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

	for _, forbidden := range []string{"--mount", "--volume", "--device", "--env", "--env-file", "--publish", "--privileged"} {
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
