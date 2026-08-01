package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestParseHostCommandAcceptsOnlyExactOrderedForms(t *testing.T) {
	t.Parallel()

	valid := []struct {
		args   []string
		action HostAction
	}{
		{
			[]string{
				"deploy", "host", "--private", "/private/runtime.json",
				"--acquisition", "disabled",
			},
			ActionInstall,
		},
		{
			[]string{
				"verify", "host", "--private", "/private/runtime.json",
				"--require-zero-listeners",
			},
			ActionVerify,
		},
		{
			[]string{
				"suspend", "host", "--private", "/private/runtime.json",
				"--drain-policy=wait", "--hosted-confirmation",
				"/private/hold.json",
			},
			ActionSuspend,
		},
		{
			[]string{
				"resume", "host", "--private", "/private/runtime.json",
				"--acquisition", "disabled",
			},
			ActionResume,
		},
	}
	for _, test := range valid {
		request, err := ParseHostCommand(test.args)
		if err != nil || request.Action != test.action {
			t.Fatalf("ParseHostCommand(%v) = %#v, %v", test.args, request, err)
		}
	}
	invalid := [][]string{
		nil,
		{"deploy", "host", "--acquisition", "disabled", "--private", "/x"},
		{"deploy", "host", "--private", "/x", "--acquisition=disabled"},
		{"deploy", "host", "--private", "relative", "--acquisition", "disabled"},
		{"verify", "host", "--private", "/x"},
		{"verify", "host", "--private", "/x", "--require-zero-listeners=true"},
		{"suspend", "host", "--private", "/x", "--drain-policy=stop", "--hosted-confirmation", "/h"},
		{"suspend", "host", "--private", "/x", "--drain-policy=wait", "--hosted-confirmation", "/x"},
		{"resume", "host", "--private", "/x", "--acquisition", "enabled"},
		{"resume", "host", "--private", "/x", "--acquisition", "disabled", "extra"},
	}
	for _, args := range invalid {
		if _, err := ParseHostCommand(args); !errors.Is(err, ErrHostUsage) {
			t.Fatalf("ParseHostCommand(%v) error = %v", args, err)
		}
	}
}

func TestSealTargetProofRejectsArm64Target(t *testing.T) {
	t.Parallel()

	overlay, revision := cliTestOverlay()
	_, err := SealTargetProof(TargetProof{
		SchemaVersion:          1,
		PrivateOverlayRevision: revision,
		HostIdentityDigest:     overlay.Target.HostIdentityDigest,
		ControlIdentityDigest:  overlay.Target.ControlHostIdentityDigest,
		OS:                     "linux",
		Architecture:           "arm64",
		ExpectedEUID:           0,
		FenceGeneration:        0,
		ActiveFleet:            fleetfence.FleetNone,
	})
	if !errors.Is(err, ErrHostCommandFailed) {
		t.Fatalf("SealTargetProof() error = %v", err)
	}
}

func TestRunHostCommandDeployProvesStagesThenInvokesExactBinding(t *testing.T) {
	t.Parallel()

	overlay, revision := cliTestOverlay()
	manifest := cliTestManifest()
	manifestDocument, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Manifest.Digest = manifestDigest
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	target, err := SealTargetProof(TargetProof{
		SchemaVersion:          1,
		PrivateOverlayRevision: revision,
		HostIdentityDigest:     overlay.Target.HostIdentityDigest,
		ControlIdentityDigest:  overlay.Target.ControlHostIdentityDigest,
		OS:                     overlay.Target.OS,
		Architecture:           overlay.Target.Architecture,
		ExpectedEUID:           overlay.Target.ExpectedEUID,
		FenceGeneration:        0,
		ActiveFleet:            fleetfence.FleetNone,
		CurrentManifestDigest:  nil,
		InstallDisposition:     &disposition,
	})
	if err != nil {
		t.Fatalf("SealTargetProof() error = %v", err)
	}
	transport := &cliTransportFixture{target: target}
	factoryCalls := 0
	deps := HostCommandDependencies{
		LoadPrivateOverlay: func(string) (
			hostruntime.PrivateOverlay,
			string,
			error,
		) {
			return overlay, revision, nil
		},
		LoadRuntimeManifest: func(string) (
			hostruntime.RuntimeManifest,
			[]byte,
			string,
			error,
		) {
			return manifest, manifestDocument, manifestDigest, nil
		},
		TransportForOverlay: func(got hostruntime.PrivateOverlay) (
			HostTransport,
			error,
		) {
			factoryCalls++
			if got.Target.HostIdentityDigest !=
				overlay.Target.HostIdentityDigest {
				t.Fatalf("transport factory received wrong overlay")
			}
			return transport, nil
		},
	}
	result, err := RunHostCommand(
		context.Background(),
		[]string{
			"deploy", "host", "--private", "/private/runtime.json",
			"--acquisition", "disabled",
		},
		deps,
	)
	if err != nil {
		t.Fatalf("RunHostCommand() error = %v", err)
	}
	if result.Status != hostruntime.HostActionComplete ||
		result.Action != "deploy" ||
		transport.proveCalls != 1 ||
		transport.stageCalls != 1 ||
		transport.invokeCalls != 1 ||
		factoryCalls != 1 ||
		transport.lastAction != ActionInstall ||
		transport.lastArguments.Acquisition() != "disabled" ||
		transport.lastArguments.ExpectedOperationID() == "" {
		t.Fatalf("result=%#v transport=%#v", result, transport)
	}
}

func TestRunHostCommandRejectsTargetStageAndTerminalDrift(t *testing.T) {
	t.Parallel()

	overlay, revision := cliTestOverlay()
	manifest := cliTestManifest()
	manifestDocument, manifestDigest, _ := hostruntime.MarshalRuntimeManifest(manifest)
	overlay.Manifest.Digest = manifestDigest
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	target, _ := SealTargetProof(TargetProof{
		SchemaVersion:          1,
		PrivateOverlayRevision: revision,
		HostIdentityDigest:     overlay.Target.HostIdentityDigest,
		ControlIdentityDigest:  overlay.Target.ControlHostIdentityDigest,
		OS:                     overlay.Target.OS,
		Architecture:           overlay.Target.Architecture,
		ExpectedEUID:           0,
		FenceGeneration:        0,
		ActiveFleet:            fleetfence.FleetNone,
		InstallDisposition:     &disposition,
	})
	baseDeps := func(transport *cliTransportFixture) HostCommandDependencies {
		return HostCommandDependencies{
			LoadPrivateOverlay: func(string) (
				hostruntime.PrivateOverlay,
				string,
				error,
			) {
				return overlay, revision, nil
			},
			LoadRuntimeManifest: func(string) (
				hostruntime.RuntimeManifest,
				[]byte,
				string,
				error,
			) {
				return manifest, manifestDocument, manifestDigest, nil
			},
			TransportForOverlay: func(hostruntime.PrivateOverlay) (
				HostTransport,
				error,
			) {
				return transport, nil
			},
		}
	}
	args := []string{
		"deploy", "host", "--private", "/private/runtime.json",
		"--acquisition", "disabled",
	}
	tests := map[string]*cliTransportFixture{
		"target revision": {
			target: func() TargetProof {
				drift := target
				drift.PrivateOverlayRevision = strings.Repeat("d", 64)
				drift, _ = SealTargetProof(drift)
				return drift
			}(),
		},
		"stage proof": {
			target:       target,
			corruptStage: true,
		},
		"terminal status": {
			target:         target,
			terminalStatus: hostruntime.HostActionRecoverable,
		},
		"operation mismatch": {
			target:           target,
			corruptOperation: true,
		},
	}
	for name, transport := range tests {
		name, transport := name, transport
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := RunHostCommand(
				context.Background(),
				args,
				baseDeps(transport),
			); !errors.Is(err, ErrHostCommandFailed) {
				t.Fatalf("RunHostCommand() error = %v", err)
			}
		})
	}
}

func TestRunHostCommandRejectsTransportFactoryFailureBeforeInvocation(t *testing.T) {
	t.Parallel()

	overlay, revision := cliTestOverlay()
	factoryCalls := 0
	dependencies := HostCommandDependencies{
		LoadPrivateOverlay: func(string) (
			hostruntime.PrivateOverlay,
			string,
			error,
		) {
			return overlay, revision, nil
		},
		LoadRuntimeManifest: func(string) (
			hostruntime.RuntimeManifest,
			[]byte,
			string,
			error,
		) {
			t.Fatal("manifest loader called after transport factory failure")
			return hostruntime.RuntimeManifest{}, nil, "", nil
		},
		TransportForOverlay: func(hostruntime.PrivateOverlay) (
			HostTransport,
			error,
		) {
			factoryCalls++
			return nil, errors.New("unavailable")
		},
	}
	if _, err := RunHostCommand(
		context.Background(),
		[]string{
			"verify", "host", "--private", "/private/runtime.json",
			"--require-zero-listeners",
		},
		dependencies,
	); !errors.Is(err, ErrHostCommandFailed) {
		t.Fatalf("RunHostCommand() error = %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("transport factory calls = %d, want 1", factoryCalls)
	}
}

func TestExpectedOperationKeepsLegacyInstallOnLegacyFence(t *testing.T) {
	t.Parallel()

	disposition := hostruntime.InstallDispositionLegacyDisabledObserver
	current := strings.Repeat("c", 64)
	target := TargetProof{
		InstallDisposition:    &disposition,
		FenceGeneration:       42,
		ActiveFleet:           fleetfence.FleetLegacy,
		CurrentManifestDigest: &current,
	}
	operationID, terminalGeneration, terminalFleet, err := expectedOperation(
		ActionInstall,
		target,
		strings.Repeat("d", 64),
		strings.Repeat("e", 64),
	)
	if err != nil ||
		!validLowerDigest(operationID) ||
		terminalGeneration != target.FenceGeneration ||
		terminalFleet != fleetfence.FleetLegacy {
		t.Fatalf(
			"expectedOperation() = %q, %d, %q, error=%v",
			operationID,
			terminalGeneration,
			terminalFleet,
			err,
		)
	}
}

type cliTransportFixture struct {
	target           TargetProof
	proveCalls       int
	stageCalls       int
	invokeCalls      int
	lastAction       HostAction
	lastArguments    FixedArguments
	corruptStage     bool
	terminalStatus   hostruntime.HostActionStatus
	corruptOperation bool
}

func (fixture *cliTransportFixture) ProveTarget(
	context.Context,
	hostruntime.PrivateOverlay,
) (TargetProof, error) {
	fixture.proveCalls++
	return fixture.target, nil
}

func (fixture *cliTransportFixture) Stage(
	_ context.Context,
	target TargetProof,
	release StagedRelease,
) (StageProof, error) {
	fixture.stageCalls++
	proof, err := SealStageProof(StageProof{
		SchemaVersion:          1,
		TargetProofDigest:      target.ProofDigest,
		PrivateOverlayRevision: release.PrivateOverlayRevision(),
		ManifestDigest:         release.ManifestDigest(),
	})
	if fixture.corruptStage {
		proof.ManifestDigest = strings.Repeat("e", 64)
	}
	return proof, err
}

func (fixture *cliTransportFixture) Invoke(
	_ context.Context,
	_ TargetProof,
	action HostAction,
	arguments FixedArguments,
) (ActionResult, error) {
	fixture.invokeCalls++
	fixture.lastAction = action
	fixture.lastArguments = arguments
	status := fixture.terminalStatus
	if status == "" {
		status = hostruntime.HostActionComplete
	}
	operationID := arguments.ExpectedOperationID()
	if fixture.corruptOperation {
		operationID = strings.Repeat("f", 64)
	}
	var proof *string
	errorClass := ""
	if status == hostruntime.HostActionComplete {
		value := strings.Repeat("c", 64)
		proof = &value
	} else {
		errorClass = "recoverable"
	}
	return ActionResult{
		Result: hostruntime.HostActionResult{
			SchemaVersion:     1,
			Status:            status,
			OperationID:       operationID,
			JournalDigest:     strings.Repeat("b", 64),
			TargetProofDigest: proof,
			FenceGeneration:   arguments.ExpectedFenceGeneration(),
			ActiveFleet:       arguments.ExpectedFleet(),
			ErrorClass:        errorClass,
		},
	}, nil
}

func cliTestOverlay() (hostruntime.PrivateOverlay, string) {
	return hostruntime.PrivateOverlay{
		Target: hostruntime.TargetIdentityOverlay{
			OS:                        "linux",
			Architecture:              "amd64",
			ExpectedEUID:              0,
			HostIdentityDigest:        strings.Repeat("1", 64),
			ControlHostIdentityDigest: strings.Repeat("2", 64),
		},
		Manifest: hostruntime.ManifestOverlay{
			Path:   "/private/manifest.json",
			Digest: strings.Repeat("a", 64),
		},
	}, strings.Repeat("9", 64)
}

func cliTestManifest() hostruntime.RuntimeManifest {
	return hostruntime.RuntimeManifest{
		SchemaVersion:         1,
		BuildID:               strings.Repeat("1", 64),
		ControllerSHA256:      strings.Repeat("2", 64),
		RunnerImageDigest:     "sha256:" + strings.Repeat("3", 64),
		AdapterImageDigest:    "sha256:" + strings.Repeat("4", 64),
		BrokerImageDigest:     "sha256:" + strings.Repeat("5", 64),
		HelperImageDigest:     "sha256:" + strings.Repeat("6", 64),
		VerifierImageDigest:   "sha256:" + strings.Repeat("7", 64),
		TrustBundleDigest:     strings.Repeat("8", 64),
		SeccompProfileDigest:  strings.Repeat("9", 64),
		EgressMode:            "restricted-broker-v1",
		PolicyManifestDigest:  strings.Repeat("a", 64),
		ConntrackBudgetDigest: strings.Repeat("b", 64),
		StorageBudgetDigest:   strings.Repeat("c", 64),
		LogPolicyDigest:       strings.Repeat("d", 64),
		ArchiveManifestDigest: nil,
		AcquisitionDefault:    "disabled",
		FleetGeneration:       1,
	}
}
