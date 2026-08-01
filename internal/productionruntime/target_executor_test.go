package productionruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestSystemTargetHostExecutorRunsOneClosedInstallSequence(t *testing.T) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Manifest.Digest = manifestDigest
	overlay.Manifest.Path = "/release/runtime-manifest.json"
	overlay.Policy.ManifestDigest = manifest.PolicyManifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	target := protocolTestTarget(t, overlay, revision)
	targetManifest := manifestDigest
	operationID, err := hostruntime.DeriveOperationID(
		hostruntime.OperationKindInstall,
		target.InstallDisposition,
		target.FenceGeneration,
		target.CurrentManifestDigest,
		&targetManifest,
		fleetfence.FleetPortable,
		revision,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	resultProof := strings.Repeat("e", 64)
	handler := &targetExecutorHandler{
		target: target,
		result: hostruntime.HostActionResult{
			SchemaVersion:     1,
			Status:            hostruntime.HostActionComplete,
			OperationID:       operationID,
			JournalDigest:     strings.Repeat("f", 64),
			TargetProofDigest: &resultProof,
			FenceGeneration:   1,
			ActiveFleet:       fleetfence.FleetPortable,
		},
	}
	executor := newSystemTargetHostExecutor(
		handler,
		func(path string) (
			hostruntime.PrivateOverlay,
			string,
			error,
		) {
			if path != "/private/runtime.json" {
				t.Fatalf("overlay path = %q", path)
			}
			return overlay, revision, nil
		},
		func(path string) (
			hostruntime.RuntimeManifest,
			[]byte,
			string,
			error,
		) {
			if path != overlay.Manifest.Path {
				t.Fatalf("manifest path = %q", path)
			}
			return manifest, manifestDocument, manifestDigest, nil
		},
	)

	got, err := executor.ExecuteTargetHost(
		context.Background(),
		hostruntime.TargetHostRequest{
			Action:       hostruntime.TargetInstall,
			PrivatePath:  "/private/runtime.json",
			ManifestPath: overlay.Manifest.Path,
		},
	)
	if err != nil {
		t.Fatalf("ExecuteTargetHost() error = %v", err)
	}
	if got != handler.result {
		t.Fatalf("ExecuteTargetHost() = %#v, want %#v", got, handler.result)
	}
	if handler.proveCalls != 1 ||
		handler.stageCalls != 1 ||
		handler.invokeCalls != 1 ||
		handler.action != cli.ActionInstall ||
		handler.arguments.Acquisition != "disabled" ||
		handler.arguments.ManifestDigest != manifestDigest ||
		handler.arguments.TargetProofDigest != target.ProofDigest ||
		handler.arguments.StageProofDigest == "" {
		t.Fatalf("handler calls = %#v", handler)
	}
}

func TestSystemTargetHostExecutorRejectsUnsupportedActionBeforeHandler(
	t *testing.T,
) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	handler := &targetExecutorHandler{}
	executor := newSystemTargetHostExecutor(
		handler,
		func(string) (
			hostruntime.PrivateOverlay,
			string,
			error,
		) {
			return overlay, revision, nil
		},
		func(string) (
			hostruntime.RuntimeManifest,
			[]byte,
			string,
			error,
		) {
			return hostruntime.RuntimeManifest{}, nil, "", errors.New(
				"manifest loader must not run",
			)
		},
	)

	if _, err := executor.ExecuteTargetHost(
		context.Background(),
		hostruntime.TargetHostRequest{
			Action:      hostruntime.TargetRollback,
			PrivatePath: "/private/runtime.json",
		},
	); !errors.Is(err, hostruntime.ErrTargetHostFailed) {
		t.Fatalf("ExecuteTargetHost() error = %v", err)
	}
	if handler.proveCalls != 0 ||
		handler.stageCalls != 0 ||
		handler.invokeCalls != 0 {
		t.Fatalf("handler calls = %#v", handler)
	}
}

func TestSystemTargetHostExecutorRejectsManifestPathSubstitutionBeforeLoad(
	t *testing.T,
) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	overlay.Manifest.Path = "/release/runtime-manifest.json"
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	handler := &targetExecutorHandler{}
	manifestLoads := 0
	executor := newSystemTargetHostExecutor(
		handler,
		func(string) (
			hostruntime.PrivateOverlay,
			string,
			error,
		) {
			return overlay, revision, nil
		},
		func(string) (
			hostruntime.RuntimeManifest,
			[]byte,
			string,
			error,
		) {
			manifestLoads++
			return hostruntime.RuntimeManifest{}, nil, "", errors.New(
				"manifest loader must not run",
			)
		},
	)

	if _, err := executor.ExecuteTargetHost(
		context.Background(),
		hostruntime.TargetHostRequest{
			Action:       hostruntime.TargetInstall,
			PrivatePath:  "/private/runtime.json",
			ManifestPath: "/attacker/runtime-manifest.json",
		},
	); !errors.Is(err, hostruntime.ErrTargetHostFailed) {
		t.Fatalf("ExecuteTargetHost() error = %v", err)
	}
	if manifestLoads != 0 ||
		handler.proveCalls != 0 ||
		handler.stageCalls != 0 ||
		handler.invokeCalls != 0 {
		t.Fatalf(
			"manifest loads = %d, handler calls = %#v",
			manifestLoads,
			handler,
		)
	}
}

func TestSystemTargetHostExecutorRoutesTargetOnlyLifecycleActions(t *testing.T) {
	t.Parallel()

	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	for _, test := range []struct {
		name               string
		action             hostruntime.TargetHostAction
		activeFleet        fleetfence.Fleet
		expectedGeneration uint64
		retainState        bool
		wantAction         cli.HostAction
		wantFleet          fleetfence.Fleet
		wantGeneration     uint64
	}{
		{
			name:               "rollback",
			action:             hostruntime.TargetRollback,
			activeFleet:        fleetfence.FleetPortable,
			expectedGeneration: 7,
			wantAction:         cli.ActionRollback,
			wantFleet:          fleetfence.FleetLegacy,
			wantGeneration:     8,
		},
		{
			name:           "uninstall",
			action:         hostruntime.TargetUninstall,
			activeFleet:    fleetfence.FleetNone,
			retainState:    true,
			wantAction:     cli.ActionUninstall,
			wantFleet:      fleetfence.FleetNone,
			wantGeneration: 7,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			overlay, _ := protocolTestOverlay(t)
			overlay.Manifest.Path = "/release/runtime-manifest.json"
			overlay.Manifest.Digest = manifestDigest
			overlay.Policy.ManifestDigest = manifest.PolicyManifestDigest
			overlay.Legacy = &hostruntime.LegacyOverlay{
				CommandFilePath:     "/opt/portable/legacy/command.json",
				CommandDigest:       strings.Repeat("a", 64),
				ConfigurationDigest: strings.Repeat("b", 64),
				WatchdogDigest:      strings.Repeat("c", 64),
				ImageDigests:        []string{"sha256:" + strings.Repeat("d", 64)},
			}
			_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
			if err != nil {
				t.Fatalf("MarshalPrivateOverlay() error = %v", err)
			}
			current := manifestDigest
			target, err := cli.SealTargetProof(cli.TargetProof{
				SchemaVersion:          1,
				PrivateOverlayRevision: revision,
				HostIdentityDigest:     overlay.Target.HostIdentityDigest,
				ControlIdentityDigest:  overlay.Target.ControlHostIdentityDigest,
				OS:                     overlay.Target.OS,
				Architecture:           overlay.Target.Architecture,
				ExpectedEUID:           overlay.Target.ExpectedEUID,
				FenceGeneration:        7,
				ActiveFleet:            test.activeFleet,
				CurrentManifestDigest:  &current,
			})
			if err != nil {
				t.Fatalf("SealTargetProof() error = %v", err)
			}
			operationID, generation, fleet, err := cli.ExpectedOperation(
				test.wantAction,
				target,
				manifestDigest,
				revision,
			)
			if err != nil || generation != test.wantGeneration || fleet != test.wantFleet {
				t.Fatalf("ExpectedOperation() = %q, %d, %q, %v", operationID, generation, fleet, err)
			}
			resultProof := strings.Repeat("e", 64)
			handler := &targetExecutorHandler{
				target: target,
				result: hostruntime.HostActionResult{
					SchemaVersion:     1,
					Status:            hostruntime.HostActionComplete,
					OperationID:       operationID,
					JournalDigest:     strings.Repeat("f", 64),
					TargetProofDigest: &resultProof,
					FenceGeneration:   generation,
					ActiveFleet:       fleet,
				},
			}
			executor := newSystemTargetHostExecutor(
				handler,
				func(string) (hostruntime.PrivateOverlay, string, error) {
					return overlay, revision, nil
				},
				func(path string) (hostruntime.RuntimeManifest, []byte, string, error) {
					if path != overlay.Manifest.Path {
						t.Fatalf("manifest path = %q", path)
					}
					return manifest, manifestDocument, manifestDigest, nil
				},
			)
			request := hostruntime.TargetHostRequest{
				Action:             test.action,
				PrivatePath:        "/private/runtime.json",
				ExpectedGeneration: test.expectedGeneration,
				RetainState:        test.retainState,
			}
			if test.action == hostruntime.TargetRollback {
				request.HostedConfirmation = filepath.Join(
					overlay.Paths.StateRoot,
					"hosted-evidence",
					"rollback.json",
				)
				request.LegacyCommandFile = overlay.Legacy.CommandFilePath
			}
			if _, err := executor.ExecuteTargetHost(
				context.Background(),
				request,
			); err != nil {
				t.Fatalf("ExecuteTargetHost() error = %v", err)
			}
			if handler.invokeCalls != 1 ||
				handler.action != test.wantAction ||
				handler.arguments.ExpectedGeneration != test.expectedGeneration ||
				handler.arguments.LegacyCommandFile != request.LegacyCommandFile ||
				handler.arguments.RetainState != test.retainState {
				t.Fatalf("handler calls = %#v", handler)
			}
		})
	}
}

func TestSystemTargetHostExecutorRoutesWatchdogMarkerActions(t *testing.T) {
	t.Parallel()

	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	for _, action := range []hostruntime.TargetHostAction{
		hostruntime.TargetWatchdogInstall,
		hostruntime.TargetWatchdogUninstall,
	} {
		action := action
		t.Run(string(action), func(t *testing.T) {
			t.Parallel()
			overlay, _ := protocolTestOverlay(t)
			overlay.Manifest.Path = "/release/runtime-manifest.json"
			overlay.Manifest.Digest = manifestDigest
			overlay.Policy.ManifestDigest = manifest.PolicyManifestDigest
			_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
			if err != nil {
				t.Fatalf("MarshalPrivateOverlay() error = %v", err)
			}
			target := protocolTestTarget(t, overlay, revision)
			operationID := targetWatchdogOperationID(
				action,
				target,
				manifestDigest,
				revision,
			)
			handler := &targetExecutorHandler{
				target: target,
				markerResult: hostruntime.HostActionResult{
					SchemaVersion:     1,
					Status:            hostruntime.HostActionComplete,
					OperationID:       operationID,
					JournalDigest:     strings.Repeat("f", 64),
					TargetProofDigest: &target.ProofDigest,
					FenceGeneration:   target.FenceGeneration,
					ActiveFleet:       target.ActiveFleet,
				},
			}
			executor := newSystemTargetHostExecutor(
				handler,
				func(string) (hostruntime.PrivateOverlay, string, error) {
					return overlay, revision, nil
				},
				func(path string) (hostruntime.RuntimeManifest, []byte, string, error) {
					if path != overlay.Manifest.Path {
						t.Fatalf("manifest path = %q", path)
					}
					return manifest, manifestDocument, manifestDigest, nil
				},
			)
			request := hostruntime.TargetHostRequest{
				Action:      action,
				PrivatePath: "/private/runtime.json",
			}
			if action == hostruntime.TargetWatchdogInstall {
				request.ManifestPath = overlay.Manifest.Path
			}
			if _, err := executor.ExecuteTargetHost(
				context.Background(),
				request,
			); err != nil {
				t.Fatalf("ExecuteTargetHost() error = %v", err)
			}
			if handler.markerCalls != 1 ||
				handler.markerAction != action ||
				handler.invokeCalls != 0 ||
				handler.stageCalls != 0 {
				t.Fatalf("handler calls = %#v", handler)
			}
		})
	}
}

func TestValidTargetRequestShapeRejectsEveryIrrelevantField(t *testing.T) {
	t.Parallel()

	const (
		privatePath  = "/private/runtime.json"
		manifestPath = "/release/runtime-manifest.json"
		hostedPath   = "/state/hosted-evidence/hold.json"
		legacyPath   = "/legacy/command.json"
	)
	tests := []struct {
		name      string
		request   hostruntime.TargetHostRequest
		forbidden []string
	}{
		{
			name: "install",
			request: hostruntime.TargetHostRequest{
				Action:       hostruntime.TargetInstall,
				PrivatePath:  privatePath,
				ManifestPath: manifestPath,
			},
			forbidden: []string{
				"drain", "hosted", "legacy", "generation", "zero", "retain",
			},
		},
		{
			name: "verify",
			request: hostruntime.TargetHostRequest{
				Action:       hostruntime.TargetVerify,
				PrivatePath:  privatePath,
				ManifestPath: manifestPath,
				RequireZero:  true,
			},
			forbidden: []string{
				"drain", "hosted", "legacy", "generation", "retain",
			},
		},
		{
			name: "suspend",
			request: hostruntime.TargetHostRequest{
				Action:             hostruntime.TargetSuspend,
				PrivatePath:        privatePath,
				DrainPolicy:        "wait",
				HostedConfirmation: hostedPath,
				RequireZero:        true,
			},
			forbidden: []string{"manifest", "legacy", "generation", "retain"},
		},
		{
			name: "resume",
			request: hostruntime.TargetHostRequest{
				Action:      hostruntime.TargetResume,
				PrivatePath: privatePath,
			},
			forbidden: []string{
				"manifest", "drain", "hosted", "legacy", "generation", "zero", "retain",
			},
		},
		{
			name: "rollback",
			request: hostruntime.TargetHostRequest{
				Action:             hostruntime.TargetRollback,
				PrivatePath:        privatePath,
				HostedConfirmation: hostedPath,
				LegacyCommandFile:  legacyPath,
				ExpectedGeneration: 7,
			},
			forbidden: []string{"manifest", "drain", "zero", "retain"},
		},
		{
			name: "uninstall",
			request: hostruntime.TargetHostRequest{
				Action:      hostruntime.TargetUninstall,
				PrivatePath: privatePath,
				RetainState: true,
			},
			forbidden: []string{
				"manifest", "drain", "hosted", "legacy", "generation", "zero",
			},
		},
		{
			name: "watchdog install",
			request: hostruntime.TargetHostRequest{
				Action:       hostruntime.TargetWatchdogInstall,
				PrivatePath:  privatePath,
				ManifestPath: manifestPath,
			},
			forbidden: []string{
				"drain", "hosted", "legacy", "generation", "zero", "retain",
			},
		},
		{
			name: "watchdog uninstall",
			request: hostruntime.TargetHostRequest{
				Action:      hostruntime.TargetWatchdogUninstall,
				PrivatePath: privatePath,
			},
			forbidden: []string{
				"manifest", "drain", "hosted", "legacy", "generation", "zero", "retain",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !validTargetRequestShape(test.request) {
				t.Fatalf("validTargetRequestShape(valid %#v) = false", test.request)
			}
			for _, field := range test.forbidden {
				field := field
				t.Run(field, func(t *testing.T) {
					t.Parallel()
					mutated := test.request
					switch field {
					case "manifest":
						mutated.ManifestPath = manifestPath
					case "drain":
						mutated.DrainPolicy = "wait"
					case "hosted":
						mutated.HostedConfirmation = hostedPath
					case "legacy":
						mutated.LegacyCommandFile = legacyPath
					case "generation":
						mutated.ExpectedGeneration = 7
					case "zero":
						mutated.RequireZero = true
					case "retain":
						mutated.RetainState = true
					default:
						t.Fatalf("unknown field %q", field)
					}
					if validTargetRequestShape(mutated) {
						t.Fatalf("validTargetRequestShape(%s=%q) = true", field, field)
					}
				})
			}
		})
	}
}

type targetExecutorHandler struct {
	target cli.TargetProof
	result hostruntime.HostActionResult

	proveCalls   int
	stageCalls   int
	invokeCalls  int
	action       cli.HostAction
	arguments    InvokeArguments
	markerResult hostruntime.HostActionResult
	markerCalls  int
	markerAction hostruntime.TargetHostAction
}

func (handler *targetExecutorHandler) ChangeWatchdogMarker(
	_ context.Context,
	_ hostruntime.PrivateOverlay,
	_ string,
	_ cli.TargetProof,
	action hostruntime.TargetHostAction,
	_ hostruntime.RuntimeManifest,
	_ string,
) (hostruntime.HostActionResult, error) {
	handler.markerCalls++
	handler.markerAction = action
	return handler.markerResult, nil
}

func (handler *targetExecutorHandler) ProveTarget(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
) (cli.TargetProof, error) {
	handler.proveCalls++
	return handler.target, nil
}

func (handler *targetExecutorHandler) StageRelease(
	_ context.Context,
	_ hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	_ hostruntime.RuntimeManifest,
	manifestDigest string,
) (cli.StageProof, error) {
	handler.stageCalls++
	return cli.SealStageProof(cli.StageProof{
		SchemaVersion:          1,
		TargetProofDigest:      target.ProofDigest,
		PrivateOverlayRevision: revision,
		ManifestDigest:         manifestDigest,
	})
}

func (handler *targetExecutorHandler) Invoke(
	_ context.Context,
	_ hostruntime.PrivateOverlay,
	_ string,
	_ cli.TargetProof,
	action cli.HostAction,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	handler.invokeCalls++
	handler.action = action
	handler.arguments = arguments
	return handler.result, nil
}

var _ TargetHandler = (*targetExecutorHandler)(nil)
