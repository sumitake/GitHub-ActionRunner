package hostruntime

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/canary"
)

func canaryProbeFixture(t *testing.T) []byte {
	t.Helper()
	value := canary.Workflow{Version: 1, ReportDigest: strings.Repeat("a", 64), WorkflowRunID: 42, Revision: strings.Repeat("b", 40), CheckoutHTTPS: true, SandboxVerified: true, InheritedJITAbsent: true, ListenerProcReadable: true, DecodedCredentialsReadable: true, CredentialProbeCompleted: true, Tools: canary.RequiredTools()}
	probe, err := canary.MarshalProbe(canary.Probe{Version: 1, Workflow: &value})
	if err != nil {
		t.Fatal(err)
	}
	return append(probe, '\n')
}

func canaryDockerFixture(t *testing.T, running bool, logs Result) (*DockerCLI, *scriptedCommandRunner, RecoverySpec) {
	t.Helper()
	root := t.TempDir()
	slot := "slot-example"
	spec := RecoverySpec{SlotIdentity: slot, BuildID: strings.Repeat("f", 64), FleetGeneration: 7, AdapterName: "example-adapter", BrokerName: "example-broker", RunnerName: "example-runner", ExpectedRunnerID: strings.Repeat("c", 64), RelayParent: filepath.Join(root, slot, "relay"), AuthorityParent: filepath.Join(root, slot, "authority")}
	runner := &scriptedCommandRunner{results: []Result{{Stdout: []byte(spec.ExpectedRunnerID + "\n")}, {Stdout: managedRecoveryInspectJSON(spec.ExpectedRunnerID, spec.RunnerName, "runner", spec, running, nil)}, logs}}
	cli, err := NewDockerCLI(DockerCLIConfig{DockerPath: "/usr/bin/docker", BrokerRoot: root, SeccompRoot: root}, runner)
	if err != nil {
		t.Fatal(err)
	}
	return cli, runner, spec
}

func TestReadCanaryWorkflowUsesExactLiveManagedContainer(t *testing.T) {
	for _, running := range []bool{true} {
		cli, runner, spec := canaryDockerFixture(t, running, Result{Stdout: canaryProbeFixture(t)})
		result, err := cli.ReadCanaryWorkflow(context.Background(), spec)
		if err != nil || result.WorkflowRunID != 42 {
			t.Fatalf("result: %+v %v", result, err)
		}
		if len(runner.commands) != 3 || !reflect.DeepEqual(runner.commands[2].argv, []string{"/usr/bin/docker", "exec", spec.ExpectedRunnerID, runnerEntrypoint, "canary-read"}) {
			t.Fatal("did not query the exact managed runner", runner.commands)
		}
	}
}

func TestReadCanaryWorkflowRefusesAmbiguousUnboundedOrFailedProbeReads(t *testing.T) {
	for name, change := range map[string]func(*Result){
		"exit":             func(r *Result) { r.ExitCode = 1 },
		"signal":           func(r *Result) { r.Signaled = true },
		"stdout truncated": func(r *Result) { r.StdoutTruncated = true },
		"stderr truncated": func(r *Result) { r.StderrTruncated = true },
		"too large":        func(r *Result) { r.Stderr = []byte(strings.Repeat("x", canary.MaxProbeBytes)) },
		"duplicate stderr": func(r *Result) { r.Stderr = canaryProbeFixture(t) },
		"absent":           func(r *Result) { r.Stdout = []byte("listener finished\n") },
	} {
		t.Run(name, func(t *testing.T) {
			logs := Result{Stdout: canaryProbeFixture(t)}
			change(&logs)
			cli, _, spec := canaryDockerFixture(t, true, logs)
			if _, err := cli.ReadCanaryWorkflow(context.Background(), spec); err == nil {
				t.Fatal("unproven workflow result accepted")
			}
		})
	}
	cli, runner, spec := canaryDockerFixture(t, true, Result{Stdout: canaryProbeFixture(t)})
	runner.errors = []error{nil, nil, errors.New("synthetic private diagnostic")}
	if _, err := cli.ReadCanaryWorkflow(context.Background(), spec); err == nil || strings.Contains(err.Error(), "private diagnostic") {
		t.Fatal("command failure lost or raw diagnostic exposed")
	}
}

func TestReadCanaryWorkflowRequiresPersistedRunnerIdentityAndClosedInventory(t *testing.T) {
	for _, kind := range []string{"missing identity", "missing runner", "drifted inventory", "nil context", "stopped runner"} {
		t.Run(kind, func(t *testing.T) {
			cli, runner, spec := canaryDockerFixture(t, true, Result{Stdout: canaryProbeFixture(t)})
			ctx := context.Background()
			switch kind {
			case "missing identity":
				spec.ExpectedRunnerID = ""
			case "missing runner":
				runner.results[0].Stdout = nil
			case "drifted inventory":
				runner.results[1].Stdout = managedRecoveryInspectJSON(spec.ExpectedRunnerID, spec.RunnerName, "runner", spec, false, func(m map[string]any) { m["Name"] = "/other-runner" })
			case "nil context":
				ctx = nil
			case "stopped runner":
				runner.results[1].Stdout = managedRecoveryInspectJSON(spec.ExpectedRunnerID, spec.RunnerName, "runner", spec, false, nil)
			}
			if _, err := cli.ReadCanaryWorkflow(ctx, spec); err == nil {
				t.Fatal("unbound runner probe accepted")
			}
			for _, command := range runner.commands {
				if len(command.argv) > 1 && command.argv[1] == "exec" {
					t.Fatal("invalid identity reached probe read")
				}
			}

		})
	}
}

func TestReadCanaryWorkflowPendingCreatesNoObservation(t *testing.T) {
	document, err := canary.MarshalProbe(canary.Probe{Version: 1, Pending: true})
	if err != nil {
		t.Fatal(err)
	}
	cli, _, spec := canaryDockerFixture(t, true, Result{Stdout: append(document, '\n')})
	workflow, err := cli.ReadCanaryWorkflow(context.Background(), spec)
	if err != nil || workflow != nil {
		t.Fatal("pending response became workflow evidence", err)
	}
}
