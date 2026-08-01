package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func quiescenceRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return root
}

func TestProveManagedQuiescenceRequiresExactEmptyRuntimeAndBrokerRoot(t *testing.T) {
	t.Parallel()

	root := quiescenceRoot(t)
	runner := &scriptedCommandRunner{results: []Result{{}}}
	cli, err := NewDockerCLI(DockerCLIConfig{
		DockerPath:  "/usr/bin/docker",
		BrokerRoot:  root,
		SeccompRoot: root,
	}, runner)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	if err := cli.ProveManagedQuiescence(context.Background()); err != nil {
		t.Fatalf("ProveManagedQuiescence: %v", err)
	}
	want := []string{
		"/usr/bin/docker",
		"ps",
		"-a",
		"--no-trunc",
		"--filter",
		"label=io.portable-ghar.managed=true",
		"--format",
		"{{.ID}}",
	}
	if len(runner.commands) != 1 ||
		!slices.Equal(runner.commands[0].argv, want) {
		t.Fatalf("commands = %#v, want %#v", runner.commands, want)
	}
}

func TestProveManagedQuiescenceRejectsAnyManagedContainer(t *testing.T) {
	t.Parallel()

	root := quiescenceRoot(t)
	runner := &scriptedCommandRunner{results: []Result{{
		Stdout: []byte(strings.Repeat("a", 64) + "\n"),
	}}}
	cli, err := NewDockerCLI(DockerCLIConfig{
		DockerPath:  "/usr/bin/docker",
		BrokerRoot:  root,
		SeccompRoot: root,
	}, runner)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}

	if err := cli.ProveManagedQuiescence(context.Background()); err == nil {
		t.Fatal("ProveManagedQuiescence accepted a managed container")
	}
}

func TestProveManagedQuiescenceRejectsUnboundedOrFailedDockerResult(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result Result
		err    error
	}{
		"runner error":     {err: errors.New("runner failed")},
		"nonzero":          {result: Result{ExitCode: 1}},
		"signaled":         {result: Result{Signaled: true}},
		"stdout truncated": {result: Result{StdoutTruncated: true}},
		"stderr truncated": {result: Result{StderrTruncated: true}},
		"stderr":           {result: Result{Stderr: []byte("diagnostic")}},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := quiescenceRoot(t)
			runner := &scriptedCommandRunner{
				results: []Result{test.result},
				errors:  []error{test.err},
			}
			cli, err := NewDockerCLI(DockerCLIConfig{
				DockerPath:  "/usr/bin/docker",
				BrokerRoot:  root,
				SeccompRoot: root,
			}, runner)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			if err := cli.ProveManagedQuiescence(context.Background()); err == nil {
				t.Fatal("ProveManagedQuiescence accepted an inexact Docker result")
			}
		})
	}
}

func TestProveManagedQuiescenceRejectsNonemptyOrIndirectBrokerRoot(t *testing.T) {
	t.Parallel()

	t.Run("nonempty", func(t *testing.T) {
		t.Parallel()
		root := quiescenceRoot(t)
		if err := os.Mkdir(filepath.Join(root, "slot"), 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		runner := &scriptedCommandRunner{results: []Result{{}}}
		cli, err := NewDockerCLI(DockerCLIConfig{
			DockerPath:  "/usr/bin/docker",
			BrokerRoot:  root,
			SeccompRoot: root,
		}, runner)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		if err := cli.ProveManagedQuiescence(context.Background()); err == nil {
			t.Fatal("ProveManagedQuiescence accepted a nonempty broker root")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		parent := quiescenceRoot(t)
		root := filepath.Join(parent, "broker")
		target := quiescenceRoot(t)
		if err := os.Symlink(target, root); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		runner := &scriptedCommandRunner{results: []Result{{}}}
		cli, err := NewDockerCLI(DockerCLIConfig{
			DockerPath:  "/usr/bin/docker",
			BrokerRoot:  root,
			SeccompRoot: target,
		}, runner)
		if err != nil {
			t.Fatalf("NewDockerCLI: %v", err)
		}
		if err := cli.ProveManagedQuiescence(context.Background()); err == nil {
			t.Fatal("ProveManagedQuiescence accepted an indirect broker root")
		}
	})
}

func TestProveManagedQuiescenceRejectsInvalidReceiverOrContext(t *testing.T) {
	t.Parallel()

	if err := (*DockerCLI)(nil).ProveManagedQuiescence(context.Background()); err == nil {
		t.Fatal("nil DockerCLI accepted")
	}
	root := quiescenceRoot(t)
	cli, err := NewDockerCLI(DockerCLIConfig{
		DockerPath:  "/usr/bin/docker",
		BrokerRoot:  root,
		SeccompRoot: root,
	}, &scriptedCommandRunner{})
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	var nilContext context.Context
	if err := cli.ProveManagedQuiescence(nilContext); err == nil {
		t.Fatal("nil context accepted")
	}
}
