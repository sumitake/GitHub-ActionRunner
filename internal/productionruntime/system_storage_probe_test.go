//go:build darwin || linux

package productionruntime

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestSystemStorageProbeUsesOneFixedDockerRootReadAndPinnedRoles(
	t *testing.T,
) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	root := t.TempDir()
	dockerRoot := filepath.Join(root, "docker")
	setStorageProbePaths(t, &overlay, root, dockerRoot)
	expected := bindStorageProbeObservations(t, &overlay, dockerRoot)
	document, err := json.Marshal(dockerRoot)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	runner := &storageProbeRunner{
		result: hostruntime.Result{
			Stdout:   append(document, '\n'),
			ExitCode: 0,
		},
	}
	probe, err := NewSystemStorageProbe(
		context.Background(),
		overlay,
		runner,
	)
	if err != nil {
		t.Fatalf("NewSystemStorageProbe() error = %v", err)
	}
	if !reflect.DeepEqual(runner.argv, []string{
		overlay.Commands.DockerBinary,
		"info",
		"--format",
		"{{json .DockerRootDir}}",
	}) {
		t.Fatalf("docker argv = %#v", runner.argv)
	}
	snapshot, err := probe.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if !reflect.DeepEqual(snapshot, expected) {
		t.Fatalf("Snapshot() = %#v, want %#v", snapshot, expected)
	}
	for _, availability := range expected {
		observed, err := probe.Observe(
			context.Background(),
			availability.Filesystem,
		)
		if err != nil || observed != availability {
			t.Fatalf(
				"Observe(%q) = %#v, %v",
				availability.Filesystem.Role,
				observed,
				err,
			)
		}
	}
}

func TestSystemStorageProbeFailsClosedOnDriftOrUnboundedDockerOutput(
	t *testing.T,
) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	root := t.TempDir()
	dockerRoot := filepath.Join(root, "docker")
	setStorageProbePaths(t, &overlay, root, dockerRoot)
	bindStorageProbeObservations(t, &overlay, dockerRoot)

	tests := []struct {
		name   string
		result hostruntime.Result
		mutate func(*hostruntime.PrivateOverlay)
	}{
		{
			name: "truncated output",
			result: hostruntime.Result{
				Stdout:          []byte(`"/private/docker"`),
				StdoutTruncated: true,
				ExitCode:        0,
			},
		},
		{
			name: "stderr",
			result: hostruntime.Result{
				Stdout:   []byte(`"/private/docker"`),
				Stderr:   []byte("warning"),
				ExitCode: 0,
			},
		},
		{
			name: "identity drift",
			result: hostruntime.Result{
				Stdout:   append(mustJSONStoragePath(t, dockerRoot), '\n'),
				ExitCode: 0,
			},
			mutate: func(overlay *hostruntime.PrivateOverlay) {
				overlay.Resources.Storage.Observations[0].Inode++
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testOverlay := overlay
			testOverlay.Resources.Storage.Observations = append(
				[]hostruntime.StorageObservationOverlay(nil),
				overlay.Resources.Storage.Observations...,
			)
			if test.mutate != nil {
				test.mutate(&testOverlay)
			}
			probe, err := NewSystemStorageProbe(
				context.Background(),
				testOverlay,
				&storageProbeRunner{result: test.result},
			)
			if test.name != "identity drift" {
				if err == nil || probe != nil {
					t.Fatal("NewSystemStorageProbe() accepted invalid output")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSystemStorageProbe() error = %v", err)
			}
			if _, err := probe.Snapshot(context.Background()); err == nil {
				t.Fatal("Snapshot() accepted identity drift")
			}
		})
	}
}

type storageProbeRunner struct {
	result hostruntime.Result
	err    error
	argv   []string
}

func (runner *storageProbeRunner) Run(
	_ context.Context,
	argv []string,
	extraFiles []*os.File,
	stdin io.Reader,
) (hostruntime.Result, error) {
	if len(extraFiles) != 0 || stdin != nil || len(runner.argv) != 0 {
		return hostruntime.Result{}, ErrStorageEnvelope
	}
	runner.argv = append([]string(nil), argv...)
	return runner.result, runner.err
}

func setStorageProbePaths(
	t *testing.T,
	overlay *hostruntime.PrivateOverlay,
	root string,
	dockerRoot string,
) {
	t.Helper()
	directories := []string{
		dockerRoot,
		filepath.Join(root, "state"),
		filepath.Join(root, "releases"),
		filepath.Join(root, "staging"),
		filepath.Join(root, "rollback"),
		filepath.Join(root, "scratch"),
		filepath.Join(root, "logs"),
		filepath.Join(root, "fence"),
		filepath.Join(root, "journal"),
		filepath.Join(root, "receipts"),
		filepath.Join(root, "reservations"),
		filepath.Join(root, "broker"),
		filepath.Join(root, "seccomp"),
		filepath.Join(root, "legacy"),
	}
	for _, directory := range directories {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("Mkdir(%q) error = %v", directory, err)
		}
	}
	overlay.Paths = hostruntime.PathOverlay{
		StateRoot:        filepath.Join(root, "state"),
		ReleaseRoot:      filepath.Join(root, "releases"),
		StagingRoot:      filepath.Join(root, "staging"),
		RollbackRoot:     filepath.Join(root, "rollback"),
		ScratchRoot:      filepath.Join(root, "scratch"),
		LogRoot:          filepath.Join(root, "logs"),
		FenceRoot:        filepath.Join(root, "fence"),
		JournalRoot:      filepath.Join(root, "journal"),
		ReceiptRoot:      filepath.Join(root, "receipts"),
		ReservationRoot:  filepath.Join(root, "reservations"),
		DatabasePath:     filepath.Join(root, "state", "controller.db"),
		AdminSocketPath:  filepath.Join(root, "state", "admin.sock"),
		HealthSocketPath: filepath.Join(root, "state", "health.sock"),
		BrokerRoot:       filepath.Join(root, "broker"),
		SeccompRoot:      filepath.Join(root, "seccomp"),
		PolicyPath:       filepath.Join(root, "policy.json"),
		TrustLockPath:    filepath.Join(root, "trust.lock"),
		LegacyRoot:       filepath.Join(root, "legacy"),
	}
	overlay.Commands.DockerBinary = filepath.Join(root, "docker-bin")
}

func bindStorageProbeObservations(
	t *testing.T,
	overlay *hostruntime.PrivateOverlay,
	dockerRoot string,
) []StorageAvailability {
	t.Helper()
	paths := []string{
		dockerRoot,
		overlay.Paths.StateRoot,
		overlay.Paths.StagingRoot,
		overlay.Paths.RollbackRoot,
		overlay.Paths.ScratchRoot,
		overlay.Paths.LogRoot,
	}
	result := make([]StorageAvailability, 0, len(paths))
	for index, path := range paths {
		availability, err := observeStoragePath(
			context.Background(),
			path,
			overlay.Resources.Storage.Observations[index].Role,
		)
		if err != nil {
			t.Fatalf("observeStoragePath(%q) error = %v", path, err)
		}
		overlay.Resources.Storage.Observations[index].Device =
			availability.Device
		overlay.Resources.Storage.Observations[index].Inode =
			availability.Filesystem.RootInode
		overlay.Resources.Storage.Observations[index].FreeBytes =
			availability.FreeBytes
		overlay.Resources.Storage.Observations[index].FreeInodes =
			availability.FreeInodes
		result = append(result, availability)
	}
	if _, _, err := hostruntime.MarshalPrivateOverlay(*overlay); err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	return result
}

func mustJSONStoragePath(t *testing.T, path string) []byte {
	t.Helper()
	document, err := json.Marshal(path)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return document
}

var _ hostruntime.CommandRunner = (*storageProbeRunner)(nil)
