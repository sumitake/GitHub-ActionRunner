package productionruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestSystemTargetHandlerInvokeReprovesAndBindsClosedInstall(
	t *testing.T,
) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	target := protocolTestTarget(t, overlay, revision)
	stage, err := cli.SealStageProof(cli.StageProof{
		SchemaVersion:          1,
		TargetProofDigest:      target.ProofDigest,
		PrivateOverlayRevision: revision,
		ManifestDigest:         overlay.Manifest.Digest,
	})
	if err != nil {
		t.Fatalf("SealStageProof() error = %v", err)
	}
	operationID, generation, fleet, err := cli.ExpectedOperation(
		cli.ActionInstall,
		target,
		overlay.Manifest.Digest,
		revision,
	)
	if err != nil {
		t.Fatalf("ExpectedOperation() error = %v", err)
	}
	resultProof := strings.Repeat("e", 64)
	want := hostruntime.HostActionResult{
		SchemaVersion:     1,
		Status:            hostruntime.HostActionComplete,
		OperationID:       operationID,
		JournalDigest:     strings.Repeat("f", 64),
		TargetProofDigest: &resultProof,
		FenceGeneration:   generation,
		ActiveFleet:       fleet,
	}
	proveCalls := 0
	invokeCalls := 0
	handler := newSystemTargetHandler(
		func(
			context.Context,
			hostruntime.PrivateOverlay,
			string,
		) (cli.TargetProof, error) {
			proveCalls++
			return target, nil
		},
		func(
			_ context.Context,
			gotOverlay hostruntime.PrivateOverlay,
			gotRevision string,
			gotTarget cli.TargetProof,
			gotAction cli.HostAction,
			gotArguments InvokeArguments,
		) (hostruntime.HostActionResult, error) {
			invokeCalls++
			if !reflect.DeepEqual(gotOverlay, overlay) ||
				gotRevision != revision ||
				gotTarget != target ||
				gotAction != cli.ActionInstall ||
				gotArguments.Acquisition != "disabled" ||
				gotArguments.ManifestDigest != overlay.Manifest.Digest ||
				gotArguments.StageProofDigest != stage.ProofDigest ||
				gotArguments.TargetProofDigest != target.ProofDigest {
				t.Fatalf(
					"invoke = %#v, %q, %#v, %v, %#v",
					gotOverlay,
					gotRevision,
					gotTarget,
					gotAction,
					gotArguments,
				)
			}
			return want, nil
		},
	)

	got, err := handler.Invoke(
		context.Background(),
		overlay,
		revision,
		target,
		cli.ActionInstall,
		InvokeArguments{
			Acquisition:       "disabled",
			ManifestDigest:    overlay.Manifest.Digest,
			StageProofDigest:  stage.ProofDigest,
			TargetProofDigest: target.ProofDigest,
		},
	)
	if err != nil || got != want {
		t.Fatalf("Invoke() = %#v, %v; want %#v", got, err, want)
	}
	if proveCalls != 1 || invokeCalls != 1 {
		t.Fatalf("calls = prove %d, invoke %d", proveCalls, invokeCalls)
	}
}

func TestSystemTargetHandlerInvokeRejectsDriftBeforeLifecycle(
	t *testing.T,
) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	target := protocolTestTarget(t, overlay, revision)
	invokeCalls := 0
	handler := newSystemTargetHandler(
		func(
			context.Context,
			hostruntime.PrivateOverlay,
			string,
		) (cli.TargetProof, error) {
			return target, nil
		},
		func(
			context.Context,
			hostruntime.PrivateOverlay,
			string,
			cli.TargetProof,
			cli.HostAction,
			InvokeArguments,
		) (hostruntime.HostActionResult, error) {
			invokeCalls++
			return hostruntime.HostActionResult{}, errors.New(
				"must not invoke",
			)
		},
	)

	tampered := target
	tampered.ProofDigest = strings.Repeat("0", 64)
	if _, err := handler.Invoke(
		context.Background(),
		overlay,
		revision,
		tampered,
		cli.ActionInstall,
		InvokeArguments{
			Acquisition:       "disabled",
			ManifestDigest:    overlay.Manifest.Digest,
			StageProofDigest:  strings.Repeat("1", 64),
			TargetProofDigest: tampered.ProofDigest,
		},
	); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Invoke() error = %v", err)
	}
	if invokeCalls != 0 {
		t.Fatalf("invoke calls = %d", invokeCalls)
	}
}

func TestInspectHostTargetStateDistinguishesGreenfieldAndPortable(
	t *testing.T,
) {
	root := t.TempDir()
	stagingRoot := filepath.Join(root, "staging")
	releaseRoot := filepath.Join(root, "releases")
	fenceRoot := filepath.Join(root, "fence")
	for _, path := range []string{stagingRoot, releaseRoot, fenceRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Paths.StagingRoot = stagingRoot
	overlay.Paths.ReleaseRoot = releaseRoot
	overlay.Paths.FenceRoot = fenceRoot
	overlay.Manifest.Digest = manifestDigest
	overlayDocument, revision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancel()
	state, err := inspectHostTargetState(ctx, overlay)
	if err != nil || state != (hostTargetState{}) {
		t.Fatalf("greenfield state = %#v, %v", state, err)
	}
	releases, err := openReleaseBundleStore(stagingRoot, releaseRoot)
	if err != nil {
		t.Fatalf("openReleaseBundleStore() error = %v", err)
	}
	if err := releases.Stage(
		manifestDigest,
		revision,
		overlayDocument,
		manifestDocument,
	); err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := releases.Select(manifestDigest, revision); err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if err := releases.Close(); err != nil {
		t.Fatalf("releases.Close() error = %v", err)
	}
	fence, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             fenceRoot,
		Identity:         targetTestIdentity{},
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("fleetfence.OpenStore() error = %v", err)
	}
	request := fleetfence.HandoffRequest{
		From:               fleetfence.FleetNone,
		To:                 fleetfence.FleetPortable,
		ExpectedGeneration: 0,
	}
	request.OperationID = fleetfence.HandoffOperationID(
		request.ExpectedGeneration,
		request.From,
		request.To,
	)
	header, err := fence.Handoff(ctx, request)
	if err != nil {
		t.Fatalf("Handoff() error = %v", err)
	}
	if err := fence.Close(); err != nil {
		t.Fatalf("fence.Close() error = %v", err)
	}
	state, err = inspectHostTargetState(ctx, overlay)
	if err != nil ||
		!state.fencePresent ||
		state.generation != header.Generation ||
		state.activeFleet != fleetfence.FleetPortable ||
		state.currentDigest == nil ||
		*state.currentDigest != manifestDigest {
		t.Fatalf("portable state = %#v, %v", state, err)
	}
}

func TestInspectHostTargetStateReportsIncompletePostFenceState(
	t *testing.T,
) {
	root := t.TempDir()
	stagingRoot := filepath.Join(root, "staging")
	releaseRoot := filepath.Join(root, "releases")
	fenceRoot := filepath.Join(root, "fence")
	for _, path := range []string{stagingRoot, releaseRoot, fenceRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	overlay, _ := protocolTestOverlay(t)
	overlay.Paths.StagingRoot = stagingRoot
	overlay.Paths.ReleaseRoot = releaseRoot
	overlay.Paths.FenceRoot = fenceRoot
	fence, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             fenceRoot,
		Identity:         targetTestIdentity{},
		Now:              time.Now,
		LockPollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("fleetfence.OpenStore() error = %v", err)
	}
	request := fleetfence.HandoffRequest{
		From:               fleetfence.FleetNone,
		To:                 fleetfence.FleetPortable,
		ExpectedGeneration: 0,
	}
	request.OperationID = fleetfence.HandoffOperationID(
		request.ExpectedGeneration,
		request.From,
		request.To,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := fence.Handoff(ctx, request); err != nil {
		t.Fatalf("Handoff() error = %v", err)
	}
	if err := fence.Close(); err != nil {
		t.Fatalf("fence.Close() error = %v", err)
	}

	state, err := inspectHostTargetState(ctx, overlay)
	if err != nil {
		t.Fatalf("inspectHostTargetState() error = %v", err)
	}
	if !state.fencePresent ||
		state.generation != 1 ||
		state.activeFleet != fleetfence.FleetPortable ||
		state.currentDigest != nil {
		t.Fatalf("incomplete state = %#v", state)
	}
}

type targetTestIdentity struct{}

func (targetTestIdentity) Current(
	context.Context,
	int,
) (fleetfence.ProcessIdentity, error) {
	return fleetfence.ProcessIdentity{
		BootID:         "boot-test",
		ProcessStartID: "process-test",
	}, nil
}

func TestReleaseBundleStoreStagesAndSelectsExactBundle(t *testing.T) {
	root := t.TempDir()
	stagingRoot := filepath.Join(root, "staging")
	releaseRoot := filepath.Join(root, "releases")
	for _, path := range []string{stagingRoot, releaseRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	overlay, revision := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	manifestDocument, manifestDigest, err :=
		hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Paths.StagingRoot = stagingRoot
	overlay.Paths.ReleaseRoot = releaseRoot
	overlay.Manifest.Digest = manifestDigest
	overlayDocument, revision, err :=
		hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}

	store, err := openReleaseBundleStore(stagingRoot, releaseRoot)
	if err != nil {
		t.Fatalf("openReleaseBundleStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close() error = %v", err)
		}
	})
	if _, present, err := store.Current(); err != nil || present {
		t.Fatalf("Current() before selection = (_, %t, %v)", present, err)
	}
	if err := store.Stage(
		manifestDigest,
		revision,
		overlayDocument,
		manifestDocument,
	); err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if err := store.Stage(
		manifestDigest,
		revision,
		overlayDocument,
		manifestDocument,
	); err != nil {
		t.Fatalf("idempotent Stage() error = %v", err)
	}
	if err := store.Promote(manifestDigest, revision); err != nil {
		t.Fatalf("Promote() error = %v", err)
	}
	if err := store.Promote(manifestDigest, revision); err != nil {
		t.Fatalf("idempotent Promote() error = %v", err)
	}
	released, err := store.Released(manifestDigest, revision)
	if err != nil ||
		!released.present ||
		string(released.overlayDocument) != string(overlayDocument) ||
		string(released.manifestDocument) != string(manifestDocument) {
		t.Fatalf("Released() = %#v, %v", released, err)
	}
	if _, present, err := store.Current(); err != nil || present {
		t.Fatalf("Current() after promotion = (_, %t, %v)", present, err)
	}
	staged, err := store.Staged(manifestDigest, revision)
	if err != nil ||
		!staged.present ||
		string(staged.overlayDocument) != string(overlayDocument) ||
		string(staged.manifestDocument) != string(manifestDocument) {
		t.Fatalf("Staged() = %#v, %v", staged, err)
	}
	if err := store.Select(manifestDigest, revision); err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if err := store.Select(manifestDigest, revision); err != nil {
		t.Fatalf("idempotent Select() error = %v", err)
	}
	current, present, err := store.Current()
	if err != nil || !present ||
		current.manifestDigest != manifestDigest ||
		current.overlayRevision != revision ||
		current.selection.RelativeLinkText != manifestDigest ||
		current.selection.ManifestDigest != manifestDigest ||
		current.selection.ReleaseDirectoryInode == 0 ||
		current.selection.SymlinkInode == 0 ||
		current.selection.ManifestInode == 0 {
		t.Fatalf("Current() = (%#v, %t, %v)", current, present, err)
	}
}

func TestReleaseBundleStoreFailsClosedOnAmbiguousSelection(t *testing.T) {
	root := t.TempDir()
	stagingRoot := filepath.Join(root, "staging")
	releaseRoot := filepath.Join(root, "releases")
	for _, path := range []string{stagingRoot, releaseRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.Symlink("../outside", filepath.Join(releaseRoot, "current")); err != nil {
		t.Fatalf("symlink current: %v", err)
	}
	store, err := openReleaseBundleStore(stagingRoot, releaseRoot)
	if err != nil {
		t.Fatalf("openReleaseBundleStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, _, err := store.Current(); err == nil {
		t.Fatal("Current() accepted an escaping selection")
	}
}

func TestWatchdogMarkerStoreBindsExactBinaryAndRelease(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	binary := filepath.Join(t.TempDir(), "portable-ghar-watchdog")
	if err := os.WriteFile(binary, []byte("watchdog-v1"), 0o500); err != nil {
		t.Fatalf("write watchdog: %v", err)
	}
	store, err := openWatchdogMarkerStore(root)
	if err != nil {
		t.Fatalf("openWatchdogMarkerStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close() error = %v", err)
		}
	})
	binding := watchdogMarkerBinding{
		PrivateOverlayRevision: strings.Repeat("a", 64),
		ManifestDigest:         strings.Repeat("b", 64),
		WatchdogBinary:         binary,
	}
	if _, present, err := store.Inspect(binding); err != nil || present {
		t.Fatalf("Inspect(absent) = (_, %t, %v)", present, err)
	}
	if err := store.Install(binding); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if err := store.Install(binding); err != nil {
		t.Fatalf("idempotent Install() error = %v", err)
	}
	artifact, present, err := store.Inspect(binding)
	if err != nil ||
		!present ||
		artifact.ObjectID != "watchdog-marker" ||
		artifact.Kind != "regular-file" ||
		artifact.ContentDigest == nil ||
		artifact.IdentityDigest == nil ||
		artifact.Inode == 0 {
		t.Fatalf("Inspect(installed) = (%#v, %t, %v)", artifact, present, err)
	}
	if err := os.Chmod(binary, 0o700); err != nil {
		t.Fatalf("chmod watchdog writable: %v", err)
	}
	if err := os.WriteFile(binary, []byte("watchdog-v2"), 0o700); err != nil {
		t.Fatalf("mutate watchdog: %v", err)
	}
	if err := os.Chmod(binary, 0o500); err != nil {
		t.Fatalf("chmod watchdog pinned: %v", err)
	}
	if _, _, err := store.Inspect(binding); err == nil {
		t.Fatal("Inspect() accepted a changed watchdog binary")
	}
}

func TestSealTargetProofForStateClassifiesSupportedStates(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	current := strings.Repeat("c", 64)
	greenfield := hostTargetState{}
	portable := hostTargetState{
		fencePresent:  true,
		generation:    41,
		activeFleet:   fleetfence.FleetPortable,
		currentDigest: &current,
	}
	suspended := hostTargetState{
		fencePresent:  true,
		generation:    42,
		activeFleet:   fleetfence.FleetNone,
		currentDigest: &current,
	}

	tests := []struct {
		name            string
		state           hostTargetState
		wantDisposition *hostruntime.InstallDisposition
		wantGeneration  uint64
		wantFleet       fleetfence.Fleet
		wantCurrent     *string
	}{
		{
			name:  "greenfield",
			state: greenfield,
			wantDisposition: dispositionPointer(
				hostruntime.InstallDispositionGreenfieldPortable,
			),
			wantFleet: fleetfence.FleetNone,
		},
		{
			name:  "portable upgrade",
			state: portable,
			wantDisposition: dispositionPointer(
				hostruntime.InstallDispositionUpgradePortable,
			),
			wantGeneration: 41,
			wantFleet:      fleetfence.FleetPortable,
			wantCurrent:    &current,
		},
		{
			name:           "suspended portable",
			state:          suspended,
			wantGeneration: 42,
			wantFleet:      fleetfence.FleetNone,
			wantCurrent:    &current,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			proof, err := sealTargetProofForState(
				overlay,
				revision,
				test.state,
			)
			if err != nil {
				t.Fatalf("sealTargetProofForState() error = %v", err)
			}
			if proof.PrivateOverlayRevision != revision ||
				proof.HostIdentityDigest !=
					overlay.Target.HostIdentityDigest ||
				proof.ControlIdentityDigest !=
					overlay.Target.ControlHostIdentityDigest ||
				proof.FenceGeneration != test.wantGeneration ||
				proof.ActiveFleet != test.wantFleet ||
				!equalOptionalString(
					proof.CurrentManifestDigest,
					test.wantCurrent,
				) ||
				!equalDisposition(
					proof.InstallDisposition,
					test.wantDisposition,
				) ||
				proof.ProofDigest == "" {
				t.Fatalf("proof = %#v", proof)
			}
		})
	}
}

func TestSealTargetProofForStateRejectsAmbiguousOrLegacyState(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	current := strings.Repeat("c", 64)
	tests := []hostTargetState{
		{
			fencePresent: true,
			generation:   1,
			activeFleet:  fleetfence.FleetPortable,
		},
		{
			currentDigest: &current,
		},
		{
			fencePresent:  true,
			generation:    1,
			activeFleet:   fleetfence.FleetLegacy,
			currentDigest: &current,
		},
		{
			fencePresent:  true,
			generation:    0,
			activeFleet:   fleetfence.FleetPortable,
			currentDigest: &current,
		},
	}
	for index, state := range tests {
		if _, err := sealTargetProofForState(
			overlay,
			revision,
			state,
		); err == nil {
			t.Fatalf("state %d was accepted: %#v", index, state)
		}
	}
}

func dispositionPointer(
	value hostruntime.InstallDisposition,
) *hostruntime.InstallDisposition {
	return &value
}

func equalOptionalString(left *string, right *string) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func equalDisposition(
	left *hostruntime.InstallDisposition,
	right *hostruntime.InstallDisposition,
) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}
