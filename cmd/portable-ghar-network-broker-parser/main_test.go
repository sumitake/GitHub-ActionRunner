package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
)

func TestRunServeInstallsSandboxBeforeOpeningRuntime(t *testing.T) {
	var events []string
	runtime := parserRuntime{
		sandbox: func() (sandboxProof, error) {
			events = append(events, "sandbox")
			return sandboxProof{taskCount: 3, tasksVerified: 3}, nil
		},
		serve: func(_ context.Context, proof sandboxProof) error {
			events = append(events, "serve")
			if proof.taskCount != 3 || proof.tasksVerified != 3 {
				t.Fatalf("proof=%+v", proof)
			}
			return nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run(
		context.Background(),
		[]string{"serve"},
		&stdout,
		&stderr,
		runtime,
	); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !slices.Equal(events, []string{"sandbox", "serve"}) ||
		stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("events=%q stdout=%q stderr=%q", events, stdout.String(), stderr.String())
	}
}

func TestRunServeFailsClosedWhenSandboxOrRuntimeFails(t *testing.T) {
	tests := []struct {
		name    string
		runtime parserRuntime
	}{
		{
			name: "sandbox",
			runtime: parserRuntime{
				sandbox: func() (sandboxProof, error) {
					return sandboxProof{}, errors.New("synthetic")
				},
				serve: func(context.Context, sandboxProof) error {
					t.Fatal("serve ran after sandbox failure")
					return nil
				},
			},
		},
		{
			name: "runtime",
			runtime: parserRuntime{
				sandbox: func() (sandboxProof, error) {
					return sandboxProof{taskCount: 1, tasksVerified: 1}, nil
				},
				serve: func(context.Context, sandboxProof) error {
					return errors.New("synthetic")
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(
				context.Background(),
				[]string{"serve"},
				&stdout,
				&stderr,
				test.runtime,
			); code != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 ||
				stderr.String() != "portable-ghar-network-broker-parser: unavailable\n" {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}
