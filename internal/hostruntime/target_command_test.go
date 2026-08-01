package hostruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

func TestParseTargetHostCommandAcceptsOnlyClosedGrammars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want TargetHostRequest
	}{
		{
			name: "install",
			args: []string{
				"install", "--private", "/private/runtime.json",
				"--manifest", "/release/manifest.json",
				"--acquisition", "disabled",
			},
			want: TargetHostRequest{
				Action:       TargetInstall,
				PrivatePath:  "/private/runtime.json",
				ManifestPath: "/release/manifest.json",
			},
		},
		{
			name: "verify",
			args: []string{
				"verify", "--private", "/private/runtime.json",
				"--manifest", "/release/manifest.json",
				"--require-zero-listeners",
			},
			want: TargetHostRequest{
				Action:       TargetVerify,
				PrivatePath:  "/private/runtime.json",
				ManifestPath: "/release/manifest.json",
				RequireZero:  true,
			},
		},
		{
			name: "suspend",
			args: []string{
				"suspend", "--private", "/private/runtime.json",
				"--drain-policy=cancel",
				"--hosted-confirmation", "/private/hold.json",
				"--require-zero-listeners",
			},
			want: TargetHostRequest{
				Action:             TargetSuspend,
				PrivatePath:        "/private/runtime.json",
				DrainPolicy:        "cancel",
				HostedConfirmation: "/private/hold.json",
				RequireZero:        true,
			},
		},
		{
			name: "resume",
			args: []string{
				"resume", "--private", "/private/runtime.json",
				"--acquisition", "disabled",
			},
			want: TargetHostRequest{
				Action:      TargetResume,
				PrivatePath: "/private/runtime.json",
			},
		},
		{
			name: "rollback",
			args: []string{
				"rollback", "--private", "/private/runtime.json",
				"--expected-generation", "42",
				"--hosted-confirmation", "/private/hold.json",
				"--legacy-command-file", "/private/legacy.json",
			},
			want: TargetHostRequest{
				Action:             TargetRollback,
				PrivatePath:        "/private/runtime.json",
				ExpectedGeneration: 42,
				HostedConfirmation: "/private/hold.json",
				LegacyCommandFile:  "/private/legacy.json",
			},
		},
		{
			name: "uninstall",
			args: []string{
				"uninstall", "--private", "/private/runtime.json",
				"--retain-state",
			},
			want: TargetHostRequest{
				Action:      TargetUninstall,
				PrivatePath: "/private/runtime.json",
				RetainState: true,
			},
		},
		{
			name: "watchdog install",
			args: []string{
				"watchdog-install", "--private", "/private/runtime.json",
				"--manifest", "/release/manifest.json",
			},
			want: TargetHostRequest{
				Action:       TargetWatchdogInstall,
				PrivatePath:  "/private/runtime.json",
				ManifestPath: "/release/manifest.json",
			},
		},
		{
			name: "watchdog uninstall",
			args: []string{
				"watchdog-uninstall", "--private", "/private/runtime.json",
			},
			want: TargetHostRequest{
				Action:      TargetWatchdogUninstall,
				PrivatePath: "/private/runtime.json",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTargetHostCommand(test.args)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf(
					"ParseTargetHostCommand() = %#v, error=%v, want %#v",
					got,
					err,
					test.want,
				)
			}
		})
	}
}

func TestParseTargetHostCommandRejectsInjectionAndReordering(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		nil,
		{"install", "--private", "relative", "--manifest", "/m", "--acquisition", "disabled"},
		{"install", "--manifest", "/m", "--private", "/p", "--acquisition", "disabled"},
		{"install", "--private", "/p", "--manifest", "/m", "--acquisition", "enabled"},
		{"suspend", "--private", "/p", "--drain-policy=kill", "--hosted-confirmation", "/h", "--require-zero-listeners"},
		{"rollback", "--private", "/p", "--expected-generation", "01", "--hosted-confirmation", "/h", "--legacy-command-file", "/l"},
		{"uninstall", "--private", "/p", "--purge-state-after-retention"},
		{"watchdog-install", "--private", "/same", "--manifest", "/same"},
	}
	for _, args := range tests {
		args := append([]string(nil), args...)
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			if _, err := ParseTargetHostCommand(args); !errors.Is(
				err,
				ErrTargetHostUsage,
			) {
				t.Fatalf("ParseTargetHostCommand(%q) error = %v", args, err)
			}
		})
	}
}

func TestRunTargetHostCommandRejectsFalseSuccess(t *testing.T) {
	t.Parallel()

	executor := targetExecutorFunc(func(
		context.Context,
		TargetHostRequest,
	) (HostActionResult, error) {
		return HostActionResult{
			SchemaVersion:     1,
			Status:            HostActionComplete,
			OperationID:       strings.Repeat("a", 64),
			JournalDigest:     strings.Repeat("b", 64),
			TargetProofDigest: nil,
			FenceGeneration:   1,
			ActiveFleet:       fleetfence.FleetPortable,
		}, nil
	})
	if _, err := RunTargetHostCommand(
		context.Background(),
		[]string{
			"resume", "--private", "/private/runtime.json",
			"--acquisition", "disabled",
		},
		executor,
	); !errors.Is(err, ErrTargetHostFailed) {
		t.Fatalf("RunTargetHostCommand() error = %v", err)
	}
}

type targetExecutorFunc func(
	context.Context,
	TargetHostRequest,
) (HostActionResult, error)

func (function targetExecutorFunc) ExecuteTargetHost(
	ctx context.Context,
	request TargetHostRequest,
) (HostActionResult, error) {
	return function(ctx, request)
}
