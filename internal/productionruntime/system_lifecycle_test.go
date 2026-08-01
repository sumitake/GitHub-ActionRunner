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
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type disabledControllerProbeFunc func(
	context.Context,
) (DisabledControllerObservation, error)

type fixedLifecycleEffectAuthority struct {
	observation hostruntime.LifecycleEffectObservation
	err         error
	applyCalls  int
}

func (authority *fixedLifecycleEffectAuthority) Observe(
	context.Context,
	hostruntime.OperationBinding,
	hostruntime.OperationPhase,
) (hostruntime.LifecycleEffectObservation, error) {
	return authority.observation, authority.err
}

func (authority *fixedLifecycleEffectAuthority) Apply(
	context.Context,
	hostruntime.OperationBinding,
	hostruntime.OperationPhase,
) (hostruntime.TargetPostcondition, error) {
	authority.applyCalls++
	return hostruntime.TargetPostcondition{}, errors.New("apply forbidden")
}

func (probe disabledControllerProbeFunc) Observe(
	ctx context.Context,
) (DisabledControllerObservation, error) {
	return probe(ctx)
}

func TestObserveDisabledZeroPreservesProbeFailure(t *testing.T) {
	want := errors.New("probe failed")
	probe := disabledControllerProbeFunc(func(
		context.Context,
	) (DisabledControllerObservation, error) {
		return DisabledControllerObservation{}, want
	})

	if _, err := observeDisabledZero(
		context.Background(),
		probe,
	); !errors.Is(err, want) {
		t.Fatalf("observeDisabledZero() error = %v, want %v", err, want)
	}
}

func TestObserveDisabledZeroReturnsSuccessfulObservation(t *testing.T) {
	want := DisabledControllerObservation{
		PolicyEpoch:  7,
		PolicyDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	probe := disabledControllerProbeFunc(func(
		context.Context,
	) (DisabledControllerObservation, error) {
		return want, nil
	})

	got, err := observeDisabledZero(context.Background(), probe)
	if err != nil {
		t.Fatalf("observeDisabledZero() error = %v", err)
	}
	if got != want {
		t.Fatalf("observeDisabledZero() = %#v, want %#v", got, want)
	}
}

func TestActiveReservationViewPreservesPersistedIdentity(t *testing.T) {
	persisted := validStorageReservationFixture()
	proof := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	persisted.State = hostruntime.ReservationStateCommitted
	persisted.CommittedTargetProofDigest = &proof
	persisted.UpdatedAt = persisted.UpdatedAt.Add(time.Second)

	want := persisted
	want.State = hostruntime.ReservationStateActive
	want.CommittedTargetProofDigest = nil
	want.ReleasedAbsenceProofDigest = nil

	got, err := activeReservationView(persisted)
	if err != nil {
		t.Fatalf("activeReservationView() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("activeReservationView() = %#v, want %#v", got, want)
	}
	if _, _, err := hostruntime.MarshalStorageReservation(got); err != nil {
		t.Fatalf("active request reservation is invalid: %v", err)
	}
}

func TestReadGreenfieldContinuationReturnsExactDurableState(t *testing.T) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	persistGreenfieldContinuation(t, store, journal, reservation)

	got, present, err := readGreenfieldContinuation(
		store,
		binding,
		nil,
		manifest,
	)
	if err != nil {
		t.Fatalf("readGreenfieldContinuation() error = %v", err)
	}
	if !present {
		t.Fatal("readGreenfieldContinuation() present = false")
	}
	if !reflect.DeepEqual(got.journal, journal) ||
		!reflect.DeepEqual(got.reservation, reservation) {
		t.Fatalf("readGreenfieldContinuation() = %#v", got)
	}
}

func TestReadGreenfieldContinuationRejectsOneSidedState(t *testing.T) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, _ := greenfieldContinuationFixture(t)
	document, _, err := hostruntime.MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	if err := store.CreateCanonical(
		hostruntime.LifecycleJournals,
		binding.OperationID+".journal.json",
		document,
		1<<20,
	); err != nil {
		t.Fatalf("CreateCanonical(journal) error = %v", err)
	}

	if _, _, err := readGreenfieldContinuation(
		store,
		binding,
		nil,
		manifest,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("readGreenfieldContinuation() error = %v", err)
	}
}

func TestReadGreenfieldContinuationRejectsCommittedNonterminalState(
	t *testing.T,
) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	journal.Phase = hostruntime.OperationPhaseFencePortable
	proof := strings.Repeat("f", 64)
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &proof
	reservation.UpdatedAt = reservation.UpdatedAt.Add(time.Second)
	persistGreenfieldContinuation(t, store, journal, reservation)

	if _, _, err := readGreenfieldContinuation(
		store,
		binding,
		nil,
		manifest,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("readGreenfieldContinuation() error = %v", err)
	}
}

func TestVerifyGreenfieldTerminalReturnsPersistedByteStableProof(t *testing.T) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	journal.Phase = hostruntime.OperationPhaseComplete
	persisted := lifecycleEffectsPostcondition(
		t,
		binding,
		hostruntime.OperationPhaseComplete,
		1,
	)
	persisted.FenceGeneration = manifest.FleetGeneration
	current := strings.Repeat("a", 64)
	persisted.CurrentSelection = &hostruntime.CurrentSelectionProjection{
		ReleaseDirectoryDeviceMajor: 8,
		ReleaseDirectoryDeviceMinor: 1,
		ReleaseDirectoryInode:       100,
		SymlinkDeviceMajor:          8,
		SymlinkDeviceMinor:          1,
		SymlinkInode:                101,
		RelativeLinkText:            "release-a",
		ManifestDeviceMajor:         8,
		ManifestDeviceMinor:         1,
		ManifestInode:               102,
		ManifestDigest:              current,
		FenceGeneration:             manifest.FleetGeneration,
		ActiveFleet:                 fleetfence.FleetPortable,
	}
	document, proofDigest, err :=
		hostruntime.MarshalTargetPostcondition(persisted)
	if err != nil {
		t.Fatalf("MarshalTargetPostcondition() error = %v", err)
	}
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &proofDigest
	reservation.UpdatedAt = reservation.UpdatedAt.Add(time.Second)
	persistGreenfieldContinuation(t, store, journal, reservation)
	if err := store.CreateCanonical(
		hostruntime.LifecycleReceipts,
		persisted.EffectKey+".postcondition.json",
		document,
		4<<20,
	); err != nil {
		t.Fatalf("CreateCanonical(postcondition) error = %v", err)
	}
	live := persisted
	live.ObservedAt = live.ObservedAt.Add(time.Hour)
	authority := &fixedLifecycleEffectAuthority{
		observation: hostruntime.LifecycleEffectObservation{
			State:         hostruntime.LifecycleEffectPresent,
			Postcondition: &live,
		},
	}

	journalDigest, gotProof, err := verifyGreenfieldTerminal(
		context.Background(),
		store,
		authority,
		binding,
		nil,
		manifest,
	)
	if err != nil {
		t.Fatalf("verifyGreenfieldTerminal() error = %v", err)
	}
	_, wantJournalDigest, err := hostruntime.MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	if journalDigest != wantJournalDigest || gotProof != proofDigest {
		t.Fatalf(
			"verifyGreenfieldTerminal() = (%q, %q), want (%q, %q)",
			journalDigest,
			gotProof,
			wantJournalDigest,
			proofDigest,
		)
	}
	if authority.applyCalls != 0 {
		t.Fatalf("apply calls = %d, want 0", authority.applyCalls)
	}
}

func TestVerifyGreenfieldTerminalRejectsLiveStateDriftWithoutApply(t *testing.T) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	journal.Phase = hostruntime.OperationPhaseComplete
	persisted := lifecycleEffectsPostcondition(
		t,
		binding,
		hostruntime.OperationPhaseComplete,
		1,
	)
	document, proofDigest, err :=
		hostruntime.MarshalTargetPostcondition(persisted)
	if err != nil {
		t.Fatalf("MarshalTargetPostcondition() error = %v", err)
	}
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &proofDigest
	reservation.UpdatedAt = reservation.UpdatedAt.Add(time.Second)
	persistGreenfieldContinuation(t, store, journal, reservation)
	if err := store.CreateCanonical(
		hostruntime.LifecycleReceipts,
		persisted.EffectKey+".postcondition.json",
		document,
		4<<20,
	); err != nil {
		t.Fatalf("CreateCanonical(postcondition) error = %v", err)
	}
	live := persisted
	live.Policy.TransitionEpoch++
	authority := &fixedLifecycleEffectAuthority{
		observation: hostruntime.LifecycleEffectObservation{
			State:         hostruntime.LifecycleEffectPresent,
			Postcondition: &live,
		},
	}

	if _, _, err := verifyGreenfieldTerminal(
		context.Background(),
		store,
		authority,
		binding,
		nil,
		manifest,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("verifyGreenfieldTerminal() error = %v", err)
	}
	if authority.applyCalls != 0 {
		t.Fatalf("apply calls = %d, want 0", authority.applyCalls)
	}
}

func TestSealGreenfieldContinuationProofKeepsOriginalOperationIdentity(
	t *testing.T,
) {
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Manifest.Digest = manifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	fresh, err := sealTargetProofForState(
		overlay,
		revision,
		hostTargetState{},
	)
	if err != nil {
		t.Fatalf("fresh sealTargetProofForState() error = %v", err)
	}
	operationID, _, _, err := cli.ExpectedOperation(
		cli.ActionInstall,
		fresh,
		manifestDigest,
		revision,
	)
	if err != nil {
		t.Fatalf("ExpectedOperation() error = %v", err)
	}
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     0,
		PriorManifestDigest:    nil,
		TargetManifestDigest:   &manifestDigest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	now := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	journal := hostruntime.OperationJournal{
		SchemaVersion:      1,
		OperationID:        operationID,
		BindingDigest:      bindingDigest,
		Kind:               hostruntime.OperationKindInstall,
		Phase:              hostruntime.OperationPhaseFencePortable,
		ExpectedGeneration: 0,
		TargetManifest:     &manifest,
		TargetFleet:        fleetfence.FleetPortable,
		StartedAt:          now,
		UpdatedAt:          now,
	}
	reservation := validStorageReservationFixture()
	reservation.OperationID = operationID
	reservation.BindingDigest = bindingDigest
	reservation.StorageBudgetDigest = manifest.StorageBudgetDigest
	reservation.TargetManifestDigest = &manifestDigest
	reservation.CreatedAt = now
	reservation.UpdatedAt = now

	got, err := sealGreenfieldContinuationProof(
		overlay,
		revision,
		hostTargetState{
			fencePresent: true,
			generation:   manifest.FleetGeneration,
			activeFleet:  fleetfence.FleetPortable,
		},
		manifest,
		greenfieldContinuation{
			journal:     journal,
			reservation: reservation,
		},
	)
	if err != nil {
		t.Fatalf("sealGreenfieldContinuationProof() error = %v", err)
	}
	if !reflect.DeepEqual(got, fresh) {
		t.Fatalf("continuation proof = %#v, want original %#v", got, fresh)
	}
	gotOperationID, _, _, err := cli.ExpectedOperation(
		cli.ActionInstall,
		got,
		manifestDigest,
		revision,
	)
	if err != nil || gotOperationID != operationID {
		t.Fatalf(
			"continuation operation = %q, %v; want %q",
			gotOperationID,
			err,
			operationID,
		)
	}
}

func TestSealSystemTargetProofAdmitsOnlyJournalOwnedContinuation(
	t *testing.T,
) {
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Manifest.Digest = manifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	fresh, err := sealTargetProofForState(
		overlay,
		revision,
		hostTargetState{},
	)
	if err != nil {
		t.Fatalf("sealTargetProofForState() error = %v", err)
	}
	operationID, _, _, err := cli.ExpectedOperation(
		cli.ActionInstall,
		fresh,
		manifestDigest,
		revision,
	)
	if err != nil {
		t.Fatalf("ExpectedOperation() error = %v", err)
	}
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     0,
		TargetManifestDigest:   &manifestDigest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	now := time.Date(2026, 7, 31, 14, 0, 0, 0, time.UTC)
	journal := hostruntime.OperationJournal{
		SchemaVersion:      1,
		OperationID:        operationID,
		BindingDigest:      bindingDigest,
		Kind:               hostruntime.OperationKindInstall,
		Phase:              hostruntime.OperationPhaseFencePortable,
		ExpectedGeneration: 0,
		TargetManifest:     &manifest,
		TargetFleet:        fleetfence.FleetPortable,
		StartedAt:          now,
		UpdatedAt:          now,
	}
	reservation := validStorageReservationFixture()
	reservation.OperationID = operationID
	reservation.BindingDigest = bindingDigest
	reservation.StorageBudgetDigest = manifest.StorageBudgetDigest
	reservation.TargetManifestDigest = &manifestDigest
	reservation.CreatedAt = now
	reservation.UpdatedAt = now
	state := hostTargetState{
		fencePresent: true,
		generation:   manifest.FleetGeneration,
		activeFleet:  fleetfence.FleetPortable,
	}

	ownedStore := openProductionLifecycleTestStore(t)
	persistGreenfieldContinuation(t, ownedStore, journal, reservation)
	got, err := sealSystemTargetProof(
		overlay,
		revision,
		manifest,
		state,
		ownedStore,
	)
	if err != nil {
		t.Fatalf("sealSystemTargetProof(owned) error = %v", err)
	}
	if !reflect.DeepEqual(got, fresh) {
		t.Fatalf("owned continuation proof = %#v, want %#v", got, fresh)
	}

	orphanStore := openProductionLifecycleTestStore(t)
	if _, err := sealSystemTargetProof(
		overlay,
		revision,
		manifest,
		state,
		orphanStore,
	); !errors.Is(err, ErrProtocol) {
		t.Fatalf("sealSystemTargetProof(orphan) error = %v", err)
	}
}

func TestSealSystemTargetProofReturnsLivePortableProofForTerminalContinuation(
	t *testing.T,
) {
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Manifest.Digest = manifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	binding, _, journal, reservation := greenfieldContinuationFixture(t)
	binding.PrivateOverlayRevision = revision
	binding.TargetManifestDigest = &manifestDigest
	entry, err := sealTargetProofForState(overlay, revision, hostTargetState{})
	if err != nil {
		t.Fatalf("sealTargetProofForState() error = %v", err)
	}
	binding, _, err = fixedGreenfieldBinding(
		entry,
		manifestDigest,
		revision,
	)
	if err != nil {
		t.Fatalf("fixedGreenfieldBinding() error = %v", err)
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	journal.OperationID = binding.OperationID
	journal.BindingDigest = bindingDigest
	journal.TargetManifest = &manifest
	journal.Phase = hostruntime.OperationPhaseComplete
	reservation.OperationID = binding.OperationID
	reservation.BindingDigest = bindingDigest
	reservation.TargetManifestDigest = &manifestDigest
	reservation.StorageBudgetDigest = manifest.StorageBudgetDigest
	proofDigest := strings.Repeat("f", 64)
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &proofDigest
	reservation.UpdatedAt = reservation.UpdatedAt.Add(time.Second)
	store := openProductionLifecycleTestStore(t)
	persistGreenfieldContinuation(t, store, journal, reservation)

	got, err := sealSystemTargetProof(
		overlay,
		revision,
		manifest,
		hostTargetState{
			fencePresent:  true,
			generation:    manifest.FleetGeneration,
			activeFleet:   fleetfence.FleetPortable,
			currentDigest: &manifestDigest,
		},
		store,
	)
	if err != nil {
		t.Fatalf("sealSystemTargetProof() error = %v", err)
	}
	if got.FenceGeneration != manifest.FleetGeneration ||
		got.ActiveFleet != fleetfence.FleetPortable ||
		got.CurrentManifestDigest == nil ||
		*got.CurrentManifestDigest != manifestDigest ||
		got.InstallDisposition == nil ||
		*got.InstallDisposition !=
			hostruntime.InstallDispositionUpgradePortable {
		t.Fatalf("terminal target proof = %#v", got)
	}
}

func TestSealSystemTargetProofPreservesUpgradeOperationAcrossSelectionCrash(
	t *testing.T,
) {
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Manifest.Digest = manifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	binding, prior, journal, reservation := upgradeContinuationFixture(
		t,
		revision,
		manifest,
	)
	journal.Phase = hostruntime.OperationPhaseCurrentSelected
	store := openProductionLifecycleTestStore(t)
	persistGreenfieldContinuation(t, store, journal, reservation)

	got, err := sealSystemTargetProof(
		overlay,
		revision,
		manifest,
		hostTargetState{
			fencePresent:  true,
			generation:    manifest.FleetGeneration,
			activeFleet:   fleetfence.FleetPortable,
			currentDigest: binding.TargetManifestDigest,
		},
		store,
	)
	if err != nil {
		t.Fatalf("sealSystemTargetProof() error = %v", err)
	}
	want, err := sealTargetProofForState(
		overlay,
		revision,
		hostTargetState{
			fencePresent:  true,
			generation:    manifest.FleetGeneration,
			activeFleet:   fleetfence.FleetPortable,
			currentDigest: binding.PriorManifestDigest,
		},
	)
	if err != nil {
		t.Fatalf("sealTargetProofForState() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("upgrade continuation proof = %#v, want %#v", got, want)
	}
	if journal.PriorManifest == nil ||
		!reflect.DeepEqual(*journal.PriorManifest, prior) {
		t.Fatal("upgrade fixture lost prior manifest")
	}
}

func TestPortableContinuationMatchesLiveStateAllowsSelectReadbackBeforeJournalAdvance(
	t *testing.T,
) {
	prior := strings.Repeat("1", 64)
	target := strings.Repeat("2", 64)
	greenfield := hostruntime.InstallDispositionGreenfieldPortable
	upgrade := hostruntime.InstallDispositionUpgradePortable

	tests := []struct {
		name    string
		binding hostruntime.OperationBinding
		phase   hostruntime.OperationPhase
		current *string
		want    bool
	}{
		{
			name: "greenfield select readback",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &greenfield,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseZeroProven,
			current: &target,
			want:    true,
		},
		{
			name: "greenfield target before zero proof",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &greenfield,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseObserverStarted,
			current: &target,
			want:    false,
		},
		{
			name: "upgrade select readback",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &upgrade,
				PriorManifestDigest:  &prior,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseZeroProven,
			current: &target,
			want:    true,
		},
		{
			name: "upgrade predecessor before select",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &upgrade,
				PriorManifestDigest:  &prior,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseZeroProven,
			current: &prior,
			want:    true,
		},
		{
			name: "upgrade target before zero proof",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &upgrade,
				PriorManifestDigest:  &prior,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseObserverStarted,
			current: &target,
			want:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := portableContinuationMatchesLiveState(
				test.binding,
				test.phase,
				test.current,
			); got != test.want {
				t.Fatalf(
					"portableContinuationMatchesLiveState() = %t, want %t",
					got,
					test.want,
				)
			}
		})
	}
}

func TestSealSystemTargetProofReturnsLiveProofAfterUpgradeComplete(t *testing.T) {
	overlay, _ := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay.Manifest.Digest = manifestDigest
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	binding, _, journal, reservation := upgradeContinuationFixture(
		t,
		revision,
		manifest,
	)
	journal.Phase = hostruntime.OperationPhaseComplete
	proof := strings.Repeat("9", 64)
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &proof
	reservation.UpdatedAt = reservation.UpdatedAt.Add(time.Second)
	store := openProductionLifecycleTestStore(t)
	persistGreenfieldContinuation(t, store, journal, reservation)
	state := hostTargetState{
		fencePresent:  true,
		generation:    manifest.FleetGeneration,
		activeFleet:   fleetfence.FleetPortable,
		currentDigest: binding.TargetManifestDigest,
	}

	got, err := sealSystemTargetProof(
		overlay,
		revision,
		manifest,
		state,
		store,
	)
	if err != nil {
		t.Fatalf("sealSystemTargetProof() error = %v", err)
	}
	want, err := sealTargetProofForState(overlay, revision, state)
	if err != nil {
		t.Fatalf("sealTargetProofForState() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("terminal upgrade proof = %#v, want %#v", got, want)
	}
}

func TestSelectGreenfieldReservationReusesDurableIdentity(t *testing.T) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, persisted :=
		greenfieldContinuationFixture(t)
	journal.Phase = hostruntime.OperationPhaseComplete
	proof := strings.Repeat("f", 64)
	persisted.State = hostruntime.ReservationStateCommitted
	persisted.CommittedTargetProofDigest = &proof
	persisted.UpdatedAt = persisted.UpdatedAt.Add(time.Second)
	persistGreenfieldContinuation(t, store, journal, persisted)

	freshCalls := 0

	choice, err := selectGreenfieldReservation(
		store,
		binding,
		nil,
		manifest,
		func() (hostruntime.StorageReservation, error) {
			freshCalls++
			return hostruntime.StorageReservation{}, errors.New(
				"fresh builder must not run",
			)
		},
	)
	if err != nil {
		t.Fatalf("selectGreenfieldReservation() error = %v", err)
	}
	if !choice.continuationPresent {
		t.Fatal("selectGreenfieldReservation() continuationPresent = false")
	}
	if freshCalls != 0 {
		t.Fatalf("fresh builder calls = %d, want 0", freshCalls)
	}
	if !reflect.DeepEqual(choice.persisted, persisted) {
		t.Fatalf("persisted reservation = %#v, want %#v", choice.persisted, persisted)
	}
	wantRequest, err := activeReservationView(persisted)
	if err != nil {
		t.Fatalf("activeReservationView() error = %v", err)
	}
	if !reflect.DeepEqual(choice.request, wantRequest) {
		t.Fatalf("request reservation = %#v, want %#v", choice.request, wantRequest)
	}
}

func TestSelectGreenfieldReservationBuildsFreshOnlyWhenDurableStateAbsent(
	t *testing.T,
) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, _, fresh := greenfieldContinuationFixture(t)
	freshCalls := 0

	choice, err := selectGreenfieldReservation(
		store,
		binding,
		nil,
		manifest,
		func() (hostruntime.StorageReservation, error) {
			freshCalls++
			return fresh, nil
		},
	)
	if err != nil {
		t.Fatalf("selectGreenfieldReservation() error = %v", err)
	}
	if choice.continuationPresent {
		t.Fatal("selectGreenfieldReservation() continuationPresent = true")
	}
	if freshCalls != 1 {
		t.Fatalf("fresh builder calls = %d, want 1", freshCalls)
	}
	if !reflect.DeepEqual(choice.persisted, fresh) ||
		!reflect.DeepEqual(choice.request, fresh) {
		t.Fatalf("fresh choice = %#v, want %#v", choice, fresh)
	}
}

func TestGreenfieldEffectStateAdmitsOnlyExactWritablePredecessor(t *testing.T) {
	t.Parallel()

	target := greenfieldSystemTarget{
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		terminalFence:  1,
		overlay: hostruntime.PrivateOverlay{
			Policy: hostruntime.PolicyOverlay{
				AcquisitionDefault: "disabled",
			},
		},
	}
	clean := greenfieldSnapshot{
		fleet: fleetfence.FleetNone,
	}
	stagedWithoutReceipt := clean
	stagedWithoutReceipt.stagedPresent = true
	verified := stagedWithoutReceipt
	verified.imagesVerified = true
	smoked := verified
	smoked.runnerSmoked = true
	base := smoked
	base.stagedPresent = true
	base.fleet = fleetfence.FleetNone
	released := base
	released.releasedPresent = true
	portable := released
	portable.fencePresent = true
	portable.generation = 1
	portable.fleet = fleetfence.FleetPortable
	watchdog := portable
	watchdog.watchdogPresent = true
	observer := watchdog
	observer.processPresent = true
	zero := observer
	zero.zero = true

	tests := []struct {
		name     string
		effect   productionEffect
		snapshot greenfieldSnapshot
		want     hostruntime.LifecycleEffectState
	}{
		{
			name:     "preflight clean baseline",
			effect:   effectPreflight,
			snapshot: clean,
			want:     hostruntime.LifecycleEffectPresent,
		},
		{
			name:     "candidate stage clean predecessor",
			effect:   effectCandidateStaged,
			snapshot: clean,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "candidate stage crash before receipt reruns",
			effect:   effectCandidateStaged,
			snapshot: stagedWithoutReceipt,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "candidate stage exact readback",
			effect:   effectCandidateStaged,
			snapshot: verified,
			want:     hostruntime.LifecycleEffectPresent,
		},
		{
			name:     "candidate smoke exact predecessor",
			effect:   effectCandidateSmoked,
			snapshot: verified,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "candidate smoke exact readback",
			effect:   effectCandidateSmoked,
			snapshot: smoked,
			want:     hostruntime.LifecycleEffectPresent,
		},
		{
			name:     "promotion exact predecessor",
			effect:   effectCandidatePromoted,
			snapshot: base,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "fence exact predecessor",
			effect:   effectFencePortable,
			snapshot: released,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "watchdog exact predecessor",
			effect:   effectWatchdogInstalled,
			snapshot: portable,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "observer exact predecessor",
			effect:   effectObserverStarted,
			snapshot: watchdog,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "selection exact predecessor",
			effect:   effectCurrentSelected,
			snapshot: zero,
			want:     hostruntime.LifecycleEffectAbsent,
		},
		{
			name:     "watchdog missing fence is ambiguous",
			effect:   effectWatchdogInstalled,
			snapshot: released,
			want:     hostruntime.LifecycleEffectAmbiguous,
		},
		{
			name:     "observer missing watchdog is ambiguous",
			effect:   effectObserverStarted,
			snapshot: portable,
			want:     hostruntime.LifecycleEffectAmbiguous,
		},
		{
			name:     "pure proof missing release is ambiguous",
			effect:   effectGreenfieldProven,
			snapshot: base,
			want:     hostruntime.LifecycleEffectAmbiguous,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := target.effectState(test.effect, test.snapshot); got != test.want {
				t.Fatalf("effectState() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestUpgradeEffectStateTracksExactCrashBoundaries(t *testing.T) {
	t.Parallel()

	priorDigest := strings.Repeat("a", 64)
	priorRevision := strings.Repeat("b", 64)
	target := greenfieldSystemTarget{
		disposition:         hostruntime.InstallDispositionUpgradePortable,
		manifestDigest:      strings.Repeat("c", 64),
		revision:            strings.Repeat("d", 64),
		priorManifestDigest: priorDigest,
		priorRevision:       priorRevision,
		terminalFence:       7,
		overlay: hostruntime.PrivateOverlay{
			Policy: hostruntime.PolicyOverlay{
				AcquisitionDefault: "disabled",
			},
		},
	}
	clean := greenfieldSnapshot{
		fencePresent:   true,
		generation:     7,
		fleet:          fleetfence.FleetPortable,
		currentPresent: true,
		current: releaseBundleSnapshot{
			manifestDigest:  priorDigest,
			overlayRevision: priorRevision,
		},
		watchdogPresent: true,
		watchdogPrior:   true,
		processPresent:  true,
		processPrior:    true,
		priorPolicy: controller.PolicyStatus{
			Mode:     controller.AcquisitionEnabled,
			Epoch:    3,
			Digest:   strings.Repeat("e", 64),
			Capacity: 4,
		},
	}
	stagedWithoutReceipt := clean
	stagedWithoutReceipt.stagedPresent = true
	verified := stagedWithoutReceipt
	verified.imagesVerified = true
	smoked := verified
	smoked.runnerSmoked = true
	base := smoked
	promoted := base
	promoted.releasedPresent = true
	disabled := promoted
	disabled.priorPolicy.Mode = controller.AcquisitionDisabled
	disabled.priorPolicy.Capacity = 0
	disabled.priorPolicy.Epoch++
	drained := disabled
	drained.priorDrained = true
	stopped := drained
	stopped.processPresent = false
	stopped.processPrior = false
	targetWatchdog := stopped
	targetWatchdog.watchdogPrior = false
	targetWatchdog.watchdogTarget = true
	targetObserver := targetWatchdog
	targetObserver.processPresent = true
	targetObserver.processTarget = true
	zero := targetObserver
	zero.zero = true
	selected := zero
	selected.current = releaseBundleSnapshot{
		manifestDigest:  target.manifestDigest,
		overlayRevision: target.revision,
	}

	tests := []struct {
		name     string
		effect   productionEffect
		snapshot greenfieldSnapshot
		want     hostruntime.LifecycleEffectState
	}{
		{"preflight present", effectPreflight, clean, hostruntime.LifecycleEffectPresent},
		{"candidate stage predecessor", effectCandidateStaged, clean, hostruntime.LifecycleEffectAbsent},
		{"candidate stage crash before receipt reruns", effectCandidateStaged, stagedWithoutReceipt, hostruntime.LifecycleEffectAbsent},
		{"candidate stage present", effectCandidateStaged, verified, hostruntime.LifecycleEffectPresent},
		{"candidate smoke predecessor", effectCandidateSmoked, verified, hostruntime.LifecycleEffectAbsent},
		{"candidate smoke present", effectCandidateSmoked, smoked, hostruntime.LifecycleEffectPresent},
		{"promote predecessor", effectCandidatePromoted, base, hostruntime.LifecycleEffectAbsent},
		{"promote crash readback", effectCandidatePromoted, promoted, hostruntime.LifecycleEffectPresent},
		{"upgrade proof", effectUpgradeProven, promoted, hostruntime.LifecycleEffectPresent},
		{"disable predecessor", effectPriorAcquisitionDisabled, promoted, hostruntime.LifecycleEffectAbsent},
		{"disable crash readback", effectPriorAcquisitionDisabled, disabled, hostruntime.LifecycleEffectPresent},
		{"drain predecessor", effectPriorDrained, disabled, hostruntime.LifecycleEffectAbsent},
		{"drain crash readback", effectPriorDrained, drained, hostruntime.LifecycleEffectPresent},
		{"stop predecessor", effectPriorControllerStopped, drained, hostruntime.LifecycleEffectAbsent},
		{"stop crash readback", effectPriorControllerStopped, stopped, hostruntime.LifecycleEffectPresent},
		{"quiescence proof", effectPriorQuiescenceProven, stopped, hostruntime.LifecycleEffectPresent},
		{"fence proof", effectFencePortableProven, stopped, hostruntime.LifecycleEffectPresent},
		{"watchdog predecessor", effectWatchdogInstalled, stopped, hostruntime.LifecycleEffectAbsent},
		{"watchdog crash readback", effectWatchdogInstalled, targetWatchdog, hostruntime.LifecycleEffectPresent},
		{"policy proof", effectPolicyDisabled, targetWatchdog, hostruntime.LifecycleEffectPresent},
		{"observer predecessor", effectObserverStarted, targetWatchdog, hostruntime.LifecycleEffectAbsent},
		{"observer crash readback", effectObserverStarted, targetObserver, hostruntime.LifecycleEffectPresent},
		{"zero proof", effectZeroProven, zero, hostruntime.LifecycleEffectPresent},
		{"selection predecessor", effectCurrentSelected, zero, hostruntime.LifecycleEffectAbsent},
		{"selection crash readback", effectCurrentSelected, selected, hostruntime.LifecycleEffectPresent},
		{"verified", effectVerified, selected, hostruntime.LifecycleEffectPresent},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := target.effectState(test.effect, test.snapshot); got != test.want {
				t.Fatalf("effectState() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestUpgradeEffectStateRejectsForeignCurrentSelection(t *testing.T) {
	t.Parallel()
	target := greenfieldSystemTarget{
		disposition:         hostruntime.InstallDispositionUpgradePortable,
		manifestDigest:      strings.Repeat("a", 64),
		revision:            strings.Repeat("b", 64),
		priorManifestDigest: strings.Repeat("c", 64),
		priorRevision:       strings.Repeat("d", 64),
		terminalFence:       7,
	}
	snapshot := greenfieldSnapshot{
		fencePresent:    true,
		generation:      7,
		fleet:           fleetfence.FleetPortable,
		stagedPresent:   true,
		imagesVerified:  true,
		runnerSmoked:    true,
		releasedPresent: true,
		currentPresent:  true,
		current: releaseBundleSnapshot{
			manifestDigest:  strings.Repeat("e", 64),
			overlayRevision: target.priorRevision,
		},
		watchdogPresent: true,
		watchdogPrior:   true,
		processPresent:  true,
		processPrior:    true,
		priorPolicy: controller.PolicyStatus{
			Mode:     controller.AcquisitionEnabled,
			Epoch:    3,
			Digest:   strings.Repeat("f", 64),
			Capacity: 4,
		},
	}
	if got := target.effectState(effectUpgradeProven, snapshot); got !=
		hostruntime.LifecycleEffectAmbiguous {
		t.Fatalf("effectState() = %q, want ambiguous", got)
	}
}

func TestGreenfieldEffectStateRejectsForeignCurrentSelection(t *testing.T) {
	t.Parallel()

	target := greenfieldSystemTarget{
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		terminalFence:  1,
	}
	snapshot := greenfieldSnapshot{
		fencePresent:    true,
		generation:      1,
		fleet:           fleetfence.FleetPortable,
		stagedPresent:   true,
		imagesVerified:  true,
		runnerSmoked:    true,
		releasedPresent: true,
		currentPresent:  true,
		current: releaseBundleSnapshot{
			manifestDigest:  strings.Repeat("c", 64),
			overlayRevision: target.revision,
		},
		watchdogPresent: true,
		processPresent:  true,
		zero:            true,
	}
	if got := target.effectState(
		effectCurrentSelected,
		snapshot,
	); got != hostruntime.LifecycleEffectAmbiguous {
		t.Fatalf("effectState() = %q, want ambiguous", got)
	}
}

func TestGreenfieldEffectStateRecognizesCrashAfterEffect(t *testing.T) {
	t.Parallel()

	target := greenfieldSystemTarget{
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		terminalFence:  1,
		overlay: hostruntime.PrivateOverlay{
			Policy: hostruntime.PolicyOverlay{
				AcquisitionDefault: "disabled",
			},
		},
	}
	promoted := greenfieldSnapshot{
		fleet:           fleetfence.FleetNone,
		stagedPresent:   true,
		imagesVerified:  true,
		runnerSmoked:    true,
		releasedPresent: true,
	}
	portable := promoted
	portable.fencePresent = true
	portable.generation = 1
	portable.fleet = fleetfence.FleetPortable
	watchdog := portable
	watchdog.watchdogPresent = true
	observer := watchdog
	observer.processPresent = true
	zero := observer
	zero.zero = true
	selected := zero
	selected.currentPresent = true
	selected.current = releaseBundleSnapshot{
		manifestDigest:  target.manifestDigest,
		overlayRevision: target.revision,
	}

	tests := []struct {
		name     string
		effect   productionEffect
		snapshot greenfieldSnapshot
	}{
		{name: "promotion", effect: effectCandidatePromoted, snapshot: promoted},
		{name: "fence", effect: effectFencePortable, snapshot: portable},
		{name: "watchdog", effect: effectWatchdogInstalled, snapshot: watchdog},
		{name: "observer", effect: effectObserverStarted, snapshot: observer},
		{name: "zero", effect: effectZeroProven, snapshot: zero},
		{name: "selection", effect: effectCurrentSelected, snapshot: selected},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := target.effectState(
				test.effect,
				test.snapshot,
			); got != hostruntime.LifecycleEffectPresent {
				t.Fatalf("effectState() = %q, want present", got)
			}
		})
	}
}

func openProductionLifecycleTestStore(
	t *testing.T,
) *hostruntime.LifecycleStore {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	makeDirectory := func(name string) string {
		path := filepath.Join(parent, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%q) error = %v", path, err)
		}
		return path
	}
	store, err := hostruntime.OpenLifecycleStoreLayout(
		hostruntime.LifecycleStoreLayout{
			LockRoot:        makeDirectory("state"),
			JournalRoot:     makeDirectory("journal"),
			ReceiptRoot:     makeDirectory("receipt"),
			ReservationRoot: makeDirectory("reservation"),
		},
		true,
	)
	if err != nil {
		t.Fatalf("OpenLifecycleStoreLayout() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("LifecycleStore.Close() error = %v", err)
		}
	})
	return store
}

func greenfieldContinuationFixture(
	t *testing.T,
) (
	hostruntime.OperationBinding,
	hostruntime.RuntimeManifest,
	hostruntime.OperationJournal,
	hostruntime.StorageReservation,
) {
	t.Helper()
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	revision := strings.Repeat("e", 64)
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	operationID, err := hostruntime.DeriveOperationID(
		hostruntime.OperationKindInstall,
		&disposition,
		0,
		nil,
		&manifestDigest,
		fleetfence.FleetPortable,
		revision,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     0,
		PriorManifestDigest:    nil,
		TargetManifestDigest:   &manifestDigest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	journal := hostruntime.OperationJournal{
		SchemaVersion:      1,
		OperationID:        operationID,
		BindingDigest:      bindingDigest,
		Kind:               hostruntime.OperationKindInstall,
		Phase:              hostruntime.OperationPhaseFencePortable,
		CompensationPath:   nil,
		ExpectedGeneration: 0,
		PriorManifest:      nil,
		TargetManifest:     &manifest,
		TargetFleet:        fleetfence.FleetPortable,
		StartedAt:          now,
		UpdatedAt:          now,
	}
	reservation := validStorageReservationFixture()
	reservation.OperationID = operationID
	reservation.BindingDigest = bindingDigest
	reservation.StorageBudgetDigest = manifest.StorageBudgetDigest
	reservation.TargetManifestDigest = &manifestDigest
	reservation.CreatedAt = now
	reservation.UpdatedAt = now
	return binding, manifest, journal, reservation
}

func upgradeContinuationFixture(
	t *testing.T,
	revision string,
	manifest hostruntime.RuntimeManifest,
) (
	hostruntime.OperationBinding,
	hostruntime.RuntimeManifest,
	hostruntime.OperationJournal,
	hostruntime.StorageReservation,
) {
	t.Helper()
	prior := manifest
	prior.ControllerSHA256 = strings.Repeat("7", 64)
	_, priorDigest, err := hostruntime.MarshalRuntimeManifest(prior)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest(prior) error = %v", err)
	}
	_, targetDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest(target) error = %v", err)
	}
	disposition := hostruntime.InstallDispositionUpgradePortable
	operationID, err := hostruntime.DeriveOperationID(
		hostruntime.OperationKindInstall,
		&disposition,
		manifest.FleetGeneration,
		&priorDigest,
		&targetDigest,
		fleetfence.FleetPortable,
		revision,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     manifest.FleetGeneration,
		PriorManifestDigest:    &priorDigest,
		TargetManifestDigest:   &targetDigest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	now := time.Date(2026, 7, 31, 15, 0, 0, 0, time.UTC)
	journal := hostruntime.OperationJournal{
		SchemaVersion:      1,
		OperationID:        operationID,
		BindingDigest:      bindingDigest,
		Kind:               hostruntime.OperationKindInstall,
		Phase:              hostruntime.OperationPhasePriorDrained,
		CompensationPath:   nil,
		ExpectedGeneration: manifest.FleetGeneration,
		PriorManifest:      &prior,
		TargetManifest:     &manifest,
		TargetFleet:        fleetfence.FleetPortable,
		StartedAt:          now,
		UpdatedAt:          now,
	}
	reservation := validStorageReservationFixture()
	reservation.OperationID = operationID
	reservation.BindingDigest = bindingDigest
	reservation.StorageBudgetDigest = manifest.StorageBudgetDigest
	reservation.TargetManifestDigest = &targetDigest
	reservation.CreatedAt = now
	reservation.UpdatedAt = now
	return binding, prior, journal, reservation
}

func persistGreenfieldContinuation(
	t *testing.T,
	store *hostruntime.LifecycleStore,
	journal hostruntime.OperationJournal,
	reservation hostruntime.StorageReservation,
) {
	t.Helper()
	journalDocument, _, err := hostruntime.MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	if err := store.CreateCanonical(
		hostruntime.LifecycleJournals,
		journal.OperationID+".journal.json",
		journalDocument,
		1<<20,
	); err != nil {
		t.Fatalf("CreateCanonical(journal) error = %v", err)
	}
	reservationDocument, _, err :=
		hostruntime.MarshalStorageReservation(reservation)
	if err != nil {
		t.Fatalf("MarshalStorageReservation() error = %v", err)
	}
	if err := store.CreateCanonical(
		hostruntime.LifecycleReservations,
		reservation.OperationID+".reservation.json",
		reservationDocument,
		4<<20,
	); err != nil {
		t.Fatalf("CreateCanonical(reservation) error = %v", err)
	}
}
