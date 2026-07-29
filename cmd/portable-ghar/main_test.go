package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestCommandEmitsOneClosedSuccessDocument(t *testing.T) {
	t.Parallel()

	proof := strings.Repeat("c", 64)
	dependencies := commandDependencies{
		RunHost: func(
			context.Context,
			[]string,
		) (cli.PublicHostResult, error) {
			return cli.PublicHostResult{
				Status:            hostruntime.HostActionComplete,
				Action:            "verify",
				OperationID:       strings.Repeat("a", 64),
				JournalDigest:     strings.Repeat("b", 64),
				TargetProofDigest: proof,
				FenceGeneration:   7,
				ActiveFleet:       fleetfence.FleetPortable,
			}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	exit := run(
		context.Background(),
		[]string{"verify", "host"},
		&stdout,
		&stderr,
		dependencies,
	)
	if exit != 0 || stderr.Len() != 0 ||
		stdout.String() !=
			`{"status":"complete","action":"verify","operation_id":"`+
				strings.Repeat("a", 64)+
				`","journal_digest":"`+strings.Repeat("b", 64)+
				`","target_proof_digest":"`+proof+
				`","fence_generation":7,"active_fleet":"portable"}`+"\n" {
		t.Fatalf(
			"run() = exit %d stdout=%q stderr=%q",
			exit,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestCommandSeparatesUsageFromSanitizedFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		exit       int
		stderrText string
	}{
		{
			"usage",
			cli.ErrHostUsage,
			2,
			"usage: portable-ghar deploy|verify|suspend|resume host [exact arguments]\n",
		},
		{
			"failure",
			errors.New("secret /private/target"),
			1,
			"portable-ghar: host command failed\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dependencies := commandDependencies{
				RunHost: func(
					context.Context,
					[]string,
				) (cli.PublicHostResult, error) {
					return cli.PublicHostResult{}, test.err
				},
			}
			var stdout, stderr bytes.Buffer
			exit := run(
				context.Background(),
				[]string{"verify", "host"},
				&stdout,
				&stderr,
				dependencies,
			)
			if exit != test.exit ||
				stdout.Len() != 0 ||
				stderr.String() != test.stderrText {
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

func TestCommandDispatchesTargetRuntimeWithoutPublicJSONShape(t *testing.T) {
	t.Parallel()

	proof := strings.Repeat("c", 64)
	dependencies := commandDependencies{
		RunTarget: func(
			context.Context,
			[]string,
		) (hostruntime.HostActionResult, error) {
			return hostruntime.HostActionResult{
				SchemaVersion:     1,
				Status:            hostruntime.HostActionComplete,
				OperationID:       strings.Repeat("a", 64),
				JournalDigest:     strings.Repeat("b", 64),
				TargetProofDigest: &proof,
				FenceGeneration:   7,
				ActiveFleet:       fleetfence.FleetPortable,
			}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	exit := run(
		context.Background(),
		[]string{
			"host-runtime",
			"verify",
			"--private",
			"/private/runtime.json",
			"--manifest",
			"/release/manifest.json",
			"--require-zero-listeners",
		},
		&stdout,
		&stderr,
		dependencies,
	)
	if exit != 0 ||
		stderr.Len() != 0 ||
		stdout.String() !=
			`{"schema_version":1,"status":"complete","operation_id":"`+
				strings.Repeat("a", 64)+
				`","journal_digest":"`+strings.Repeat("b", 64)+
				`","target_proof_digest":"`+proof+
				`","fence_generation":7,"active_fleet":"portable","error_class":""}`+
				"\n" {
		t.Fatalf(
			"run() = exit %d stdout=%q stderr=%q",
			exit,
			stdout.String(),
			stderr.String(),
		)
	}
}
