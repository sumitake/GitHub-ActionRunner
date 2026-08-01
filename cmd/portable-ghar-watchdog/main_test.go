package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/productionruntime"
	"github.com/sumitake/portable-ghar/internal/watchdog"
)

func TestProductionDependenciesUseConcreteSystemRunner(t *testing.T) {
	t.Parallel()

	_, err := productionDependencies().RunCycle(
		context.Background(),
		"/missing/private.json",
		"/missing/manifest.json",
	)
	if !errors.Is(err, productionruntime.ErrSystemWatchdog) {
		t.Fatalf("production RunCycle() error = %v", err)
	}
}

func TestWatchdogCommandExactGrammarAndClosedOutput(t *testing.T) {
	t.Parallel()

	dependencies := commandDependencies{
		RunCycle: func(
			context.Context,
			string,
			string,
		) (watchdog.Result, error) {
			return watchdog.Result{
				Status:          watchdog.StatusOK,
				Reason:          watchdog.ReasonHealthy,
				FenceGeneration: 19,
				ActiveFleet:     watchdog.FleetPortable,
			}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	exit := run(
		context.Background(),
		[]string{
			"run",
			"--private",
			"/private/runtime.json",
			"--manifest",
			"/release/manifest.json",
		},
		&stdout,
		&stderr,
		dependencies,
	)
	if exit != 0 ||
		stderr.Len() != 0 ||
		stdout.String() !=
			"{\"status\":\"ok\",\"reason\":\"disabled-and-zero\","+
				"\"fence_generation\":19,\"active_fleet\":\"portable\"}\n" {
		t.Fatalf(
			"run() = exit %d stdout=%q stderr=%q",
			exit,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestWatchdogCommandRejectsReorderedAndSanitizesFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		args   []string
		runErr error
		exit   int
		stderr string
	}{
		{
			name: "reordered",
			args: []string{
				"run",
				"--manifest",
				"/release/manifest.json",
				"--private",
				"/private/runtime.json",
			},
			exit: 2,
			stderr: "usage: portable-ghar-watchdog run --private PATH " +
				"--manifest PATH\n",
		},
		{
			name: "failure",
			args: []string{
				"run",
				"--private",
				"/private/runtime.json",
				"--manifest",
				"/release/manifest.json",
			},
			runErr: errors.New("secret /target/path"),
			exit:   1,
			stderr: "portable-ghar-watchdog: cycle failed\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dependencies := commandDependencies{
				RunCycle: func(
					context.Context,
					string,
					string,
				) (watchdog.Result, error) {
					return watchdog.Result{}, test.runErr
				},
			}
			var stdout, stderr bytes.Buffer
			exit := run(
				context.Background(),
				test.args,
				&stdout,
				&stderr,
				dependencies,
			)
			if exit != test.exit ||
				stdout.Len() != 0 ||
				stderr.String() != test.stderr {
				t.Fatalf(
					"run() = exit %d stdout=%q stderr=%q",
					exit,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}
