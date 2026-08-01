package productionruntime

import (
	"context"
	"errors"
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

type targetExecutorHandler struct {
	target cli.TargetProof
	result hostruntime.HostActionResult

	proveCalls  int
	stageCalls  int
	invokeCalls int
	action      cli.HostAction
	arguments   InvokeArguments
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
