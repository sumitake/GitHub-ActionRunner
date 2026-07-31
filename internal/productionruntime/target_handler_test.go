package productionruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

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
