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

func TestReadGreenfieldContinuationAcceptsActiveCompensationState(
	t *testing.T,
) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	path := hostruntime.CompensationInstallGreenfieldPostHandoff
	journal.CompensationPath = &path
	journal.Phase = hostruntime.OperationPhaseCGFenceObserverStopped
	journal.UpdatedAt = journal.UpdatedAt.Add(time.Second)
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
	if !present || !reflect.DeepEqual(got.journal, journal) ||
		!reflect.DeepEqual(got.reservation, reservation) {
		t.Fatalf("readGreenfieldContinuation() = %#v, present=%v", got, present)
	}
}

func TestReadGreenfieldContinuationAcceptsReleasedCompensationTerminal(
	t *testing.T,
) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	path := hostruntime.CompensationInstallGreenfieldPostHandoff
	journal.CompensationPath = &path
	journal.Phase = hostruntime.OperationPhaseCompGreenfieldNone
	journal.UpdatedAt = journal.UpdatedAt.Add(time.Second)
	absence := strings.Repeat("9", 64)
	reservation.State = hostruntime.ReservationStateReleased
	reservation.ReleasedAbsenceProofDigest = &absence
	reservation.UpdatedAt = reservation.UpdatedAt.Add(time.Second)
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
	if !present || !reflect.DeepEqual(got.journal, journal) ||
		!reflect.DeepEqual(got.reservation, reservation) {
		t.Fatalf("readGreenfieldContinuation() = %#v, present=%v", got, present)
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

func TestVerifyEvolvedInstallTerminalAcceptsLaterLiveFenceGeneration(
	t *testing.T,
) {
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
	document, persistedProof, err :=
		hostruntime.MarshalTargetPostcondition(persisted)
	if err != nil {
		t.Fatalf("MarshalTargetPostcondition(persisted) error = %v", err)
	}
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &persistedProof
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
	live.FenceGeneration = manifest.FleetGeneration + 2
	live.ObservedAt = live.ObservedAt.Add(2 * time.Hour)
	live.CurrentSelection = &hostruntime.CurrentSelectionProjection{
		ReleaseDirectoryDeviceMajor: 8,
		ReleaseDirectoryDeviceMinor: 1,
		ReleaseDirectoryInode:       100,
		SymlinkDeviceMajor:          8,
		SymlinkDeviceMinor:          1,
		SymlinkInode:                101,
		RelativeLinkText:            *binding.TargetManifestDigest,
		ManifestDeviceMajor:         8,
		ManifestDeviceMinor:         1,
		ManifestInode:               102,
		ManifestDigest:              *binding.TargetManifestDigest,
		FenceGeneration:             live.FenceGeneration,
		ActiveFleet:                 fleetfence.FleetPortable,
	}
	_, wantLiveProof, err := hostruntime.MarshalTargetPostcondition(live)
	if err != nil {
		t.Fatalf("MarshalTargetPostcondition(live) error = %v", err)
	}
	authority := &fixedLifecycleEffectAuthority{
		observation: hostruntime.LifecycleEffectObservation{
			State:         hostruntime.LifecycleEffectPresent,
			Postcondition: &live,
		},
	}

	journalDigest, gotLiveProof, err := verifyEvolvedInstallTerminal(
		context.Background(),
		store,
		authority,
		binding,
		nil,
		manifest,
	)
	if err != nil {
		t.Fatalf("verifyEvolvedInstallTerminal() error = %v", err)
	}
	_, wantJournalDigest, err := hostruntime.MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	if journalDigest != wantJournalDigest || gotLiveProof != wantLiveProof {
		t.Fatalf(
			"verifyEvolvedInstallTerminal() = (%q, %q), want (%q, %q)",
			journalDigest,
			gotLiveProof,
			wantJournalDigest,
			wantLiveProof,
		)
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
		{
			name: "greenfield selected compensation before clear",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &greenfield,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseCGSelectQuiescenceProven,
			current: &target,
			want:    true,
		},
		{
			name: "greenfield selected compensation clear readback",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &greenfield,
				TargetManifestDigest: &target,
			},
			phase: hostruntime.OperationPhaseCGSelectCurrentRemoved,
			want:  true,
		},
		{
			name: "upgrade compensation before restore",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &upgrade,
				PriorManifestDigest:  &prior,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseCUSelectQuiescenceProven,
			current: &target,
			want:    true,
		},
		{
			name: "upgrade compensation restore readback",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &upgrade,
				PriorManifestDigest:  &prior,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseCUSelectPriorRestored,
			current: &prior,
			want:    true,
		},
		{
			name: "upgrade compensated terminal prior",
			binding: hostruntime.OperationBinding{
				InstallDisposition:   &upgrade,
				PriorManifestDigest:  &prior,
				TargetManifestDigest: &target,
			},
			phase:   hostruntime.OperationPhaseCompUpgradeRestored,
			current: &prior,
			want:    true,
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

func TestSelectLifecycleReservationReusesExactTransitionState(t *testing.T) {
	store := openProductionLifecycleTestStore(t)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	revision := strings.Repeat("e", 64)
	operationID, err := hostruntime.DeriveOperationID(
		hostruntime.OperationKindResume,
		nil,
		7,
		&manifestDigest,
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
		Kind:                   hostruntime.OperationKindResume,
		ExpectedGeneration:     7,
		PriorManifestDigest:    &manifestDigest,
		TargetManifestDigest:   &manifestDigest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	journal := hostruntime.OperationJournal{
		SchemaVersion:      1,
		OperationID:        operationID,
		BindingDigest:      bindingDigest,
		Kind:               hostruntime.OperationKindResume,
		Phase:              hostruntime.OperationPhasePrepared,
		ExpectedGeneration: 7,
		PriorManifest:      &manifest,
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
	persistGreenfieldContinuation(t, store, journal, reservation)
	freshCalls := 0

	choice, err := selectLifecycleReservation(
		store,
		binding,
		&manifest,
		&manifest,
		manifest,
		func() (hostruntime.StorageReservation, error) {
			freshCalls++
			return hostruntime.StorageReservation{}, errors.New("fresh forbidden")
		},
	)
	if err != nil {
		t.Fatalf("selectLifecycleReservation() error = %v", err)
	}
	if !choice.continuationPresent || freshCalls != 0 ||
		!reflect.DeepEqual(choice.persisted, reservation) ||
		!reflect.DeepEqual(choice.request, reservation) {
		t.Fatalf("selectLifecycleReservation() = %#v, fresh=%d", choice, freshCalls)
	}
}

func TestSelectLifecycleReservationRejectsOneSidedTransitionState(t *testing.T) {
	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, _ := transitionContinuationFixture(t)
	document, _, err := hostruntime.MarshalOperationJournal(journal)
	if err != nil {
		t.Fatalf("MarshalOperationJournal() error = %v", err)
	}
	if err := store.CreateCanonical(
		hostruntime.LifecycleJournals,
		binding.OperationID+".journal.json",
		document,
		maximumProductionLifecycleJournalBytes,
	); err != nil {
		t.Fatalf("CreateCanonical() error = %v", err)
	}
	if _, err := selectLifecycleReservation(
		store,
		binding,
		&manifest,
		&manifest,
		manifest,
		func() (hostruntime.StorageReservation, error) {
			return validStorageReservationFixture(), nil
		},
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("selectLifecycleReservation() error = %v", err)
	}
}

func TestTransitionCurrentSelectionAllowsOnlyExactUninstallReentry(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("a", 64)
	revision := strings.Repeat("b", 64)
	prior := digest
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            strings.Repeat("c", 64),
		Kind:                   hostruntime.OperationKindUninstall,
		ExpectedGeneration:     9,
		PriorManifestDigest:    &prior,
		TargetFleet:            fleetfence.FleetNone,
		PrivateOverlayRevision: revision,
	}
	exact := releaseBundleSnapshot{
		manifestDigest:  digest,
		overlayRevision: revision,
	}
	foreign := exact
	foreign.manifestDigest = strings.Repeat("d", 64)

	tests := []struct {
		name         string
		binding      hostruntime.OperationBinding
		continuation bool
		phase        hostruntime.OperationPhase
		current      releaseBundleSnapshot
		present      bool
		want         bool
	}{
		{name: "fresh exact selection", binding: binding, current: exact, present: true, want: true},
		{name: "fresh absent selection", binding: binding},
		{name: "continuation exact selection", binding: binding, continuation: true, phase: hostruntime.OperationPhaseWatchdogRemoved, current: exact, present: true, want: true},
		{name: "continuation foreign selection", binding: binding, continuation: true, phase: hostruntime.OperationPhaseRegistrationRemoved, current: foreign, present: true},
		{name: "before removal absent", binding: binding, continuation: true, phase: hostruntime.OperationPhaseControllerRemoved},
		{name: "removal crash absent", binding: binding, continuation: true, phase: hostruntime.OperationPhaseRegistrationRemoved, want: true},
		{name: "retention absent", binding: binding, continuation: true, phase: hostruntime.OperationPhaseRetentionProven, want: true},
		{name: "complete absent", binding: binding, continuation: true, phase: hostruntime.OperationPhaseComplete, want: true},
		{
			name: "resume absent",
			binding: func() hostruntime.OperationBinding {
				value := binding
				value.Kind = hostruntime.OperationKindResume
				value.TargetManifestDigest = &digest
				value.TargetFleet = fleetfence.FleetPortable
				return value
			}(),
			continuation: true,
			phase:        hostruntime.OperationPhaseComplete,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := transitionCurrentSelectionAdmissible(
				test.binding,
				test.continuation,
				test.phase,
				test.current,
				test.present,
				digest,
				revision,
			); got != test.want {
				t.Fatalf("transitionCurrentSelectionAdmissible() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestInstallWatchdogAdmissionAllowsOnlyOwnedCompensationAbsence(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name         string
		disposition  hostruntime.InstallDisposition
		continuation bool
		phase        hostruntime.OperationPhase
		matched      int
		present      bool
		want         bool
	}{
		{name: "fresh greenfield absent", disposition: hostruntime.InstallDispositionGreenfieldPortable, want: true},
		{name: "fresh greenfield marker forbidden", disposition: hostruntime.InstallDispositionGreenfieldPortable, present: true},
		{name: "greenfield continuation target", disposition: hostruntime.InstallDispositionGreenfieldPortable, continuation: true, present: true, want: true},
		{name: "fresh upgrade prior", disposition: hostruntime.InstallDispositionUpgradePortable, present: true, want: true},
		{name: "fresh upgrade target forbidden", disposition: hostruntime.InstallDispositionUpgradePortable, matched: 1, present: true},
		{name: "upgrade continuation target", disposition: hostruntime.InstallDispositionUpgradePortable, continuation: true, matched: 1, present: true, want: true},
		{name: "upgrade normal continuation absent forbidden", disposition: hostruntime.InstallDispositionUpgradePortable, continuation: true, phase: hostruntime.OperationPhasePriorDrained},
		{name: "upgrade pre compensation absent", disposition: hostruntime.InstallDispositionUpgradePortable, continuation: true, phase: hostruntime.OperationPhaseCUPreCandidateStopped, want: true},
		{name: "upgrade post compensation absent", disposition: hostruntime.InstallDispositionUpgradePortable, continuation: true, phase: hostruntime.OperationPhaseCUSelectPriorRestored, want: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := installWatchdogAdmissible(
				test.disposition,
				test.continuation,
				test.phase,
				test.matched,
				test.present,
			); got != test.want {
				t.Fatalf("installWatchdogAdmissible() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestProductionPhaseEffectsCoverEveryExistingLifecyclePhase(t *testing.T) {
	phases := []hostruntime.OperationPhase{
		hostruntime.OperationPhasePrepared,
		hostruntime.OperationPhasePreflightProven,
		hostruntime.OperationPhaseCandidateStaged,
		hostruntime.OperationPhaseCandidateSmoked,
		hostruntime.OperationPhasePriorRetained,
		hostruntime.OperationPhaseDispositionGreenfieldProven,
		hostruntime.OperationPhasePriorAbsenceProven,
		hostruntime.OperationPhaseDispositionUpgradeProven,
		hostruntime.OperationPhasePriorAcquisitionDisabled,
		hostruntime.OperationPhasePriorDrained,
		hostruntime.OperationPhasePriorControllerStopped,
		hostruntime.OperationPhasePriorQuiescenceProven,
		hostruntime.OperationPhaseFencePortableProven,
		hostruntime.OperationPhaseDispositionLegacyProven,
		hostruntime.OperationPhaseLegacyAcquisitionDisabled,
		hostruntime.OperationPhaseLegacyDrained,
		hostruntime.OperationPhaseLegacyControllerStopped,
		hostruntime.OperationPhaseLegacyQuiescenceProven,
		hostruntime.OperationPhaseFenceLegacyProven,
		hostruntime.OperationPhaseLegacyNormalizedProven,
		hostruntime.OperationPhaseWatchdogInstalled,
		hostruntime.OperationPhasePolicyDisabled,
		hostruntime.OperationPhaseObserverStarted,
		hostruntime.OperationPhaseZeroProven,
		hostruntime.OperationPhaseCurrentSelected,
		hostruntime.OperationPhaseVerified,
		hostruntime.OperationPhaseComplete,
		hostruntime.OperationPhaseHoldProven,
		hostruntime.OperationPhaseWatchdogDisabled,
		hostruntime.OperationPhaseDrained,
		hostruntime.OperationPhaseControllerStopped,
		hostruntime.OperationPhaseQuiescenceProven,
		hostruntime.OperationPhaseFenceNone,
		hostruntime.OperationPhaseStoppedProven,
		hostruntime.OperationPhaseFencePortable,
		hostruntime.OperationPhaseLegacyRestored,
		hostruntime.OperationPhaseFenceLegacy,
		hostruntime.OperationPhaseLegacyStarted,
		hostruntime.OperationPhaseWatchdogRemoved,
		hostruntime.OperationPhaseControllerRemoved,
		hostruntime.OperationPhaseRegistrationRemoved,
		hostruntime.OperationPhaseRetentionProven,
		hostruntime.OperationPhaseCGPreStarted,
		hostruntime.OperationPhaseCGPreCandidateStopped,
		hostruntime.OperationPhaseCGPreCandidateRemoved,
		hostruntime.OperationPhaseCGPreAbsenceProven,
		hostruntime.OperationPhaseCompGreenfieldAbsent,
		hostruntime.OperationPhaseCGFenceStarted,
		hostruntime.OperationPhaseCGFenceObserverStopped,
		hostruntime.OperationPhaseCGFenceQuiescenceProven,
		hostruntime.OperationPhaseCGFenceNone,
		hostruntime.OperationPhaseCGFenceCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldNone,
		hostruntime.OperationPhaseCGSelectStarted,
		hostruntime.OperationPhaseCGSelectObserverStopped,
		hostruntime.OperationPhaseCGSelectQuiescenceProven,
		hostruntime.OperationPhaseCGSelectCurrentRemoved,
		hostruntime.OperationPhaseCGSelectNone,
		hostruntime.OperationPhaseCGSelectCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldSelected,
		hostruntime.OperationPhaseCUPreStarted,
		hostruntime.OperationPhaseCUPreCandidateStopped,
		hostruntime.OperationPhaseCUPreCandidateRemoved,
		hostruntime.OperationPhaseCUPrePriorSelectionProven,
		hostruntime.OperationPhaseCUPrePriorDisabledProven,
		hostruntime.OperationPhaseCompUpgradePrior,
		hostruntime.OperationPhaseCUSelectStarted,
		hostruntime.OperationPhaseCUSelectObserverStopped,
		hostruntime.OperationPhaseCUSelectQuiescenceProven,
		hostruntime.OperationPhaseCUSelectPriorRestored,
		hostruntime.OperationPhaseCUSelectPriorObserverStarted,
		hostruntime.OperationPhaseCUSelectPriorZeroProven,
		hostruntime.OperationPhaseCUSelectCandidateRemoved,
		hostruntime.OperationPhaseCompUpgradeRestored,
		hostruntime.OperationPhaseCLPreStarted,
		hostruntime.OperationPhaseCLPreCandidateStopped,
		hostruntime.OperationPhaseCLPreCandidateRemoved,
		hostruntime.OperationPhaseCLPrePriorSelectionProven,
		hostruntime.OperationPhaseCLPreLegacyZeroProven,
		hostruntime.OperationPhaseCompLegacyPrior,
		hostruntime.OperationPhaseCLSelectStarted,
		hostruntime.OperationPhaseCLSelectObserverStopped,
		hostruntime.OperationPhaseCLSelectQuiescenceProven,
		hostruntime.OperationPhaseCLSelectPriorRestored,
		hostruntime.OperationPhaseCLSelectLegacyStarted,
		hostruntime.OperationPhaseCLSelectLegacyZeroProven,
		hostruntime.OperationPhaseCLSelectCandidateRemoved,
		hostruntime.OperationPhaseCompLegacyRestored,
		hostruntime.OperationPhaseCSNoneStarted,
		hostruntime.OperationPhaseCSNoneDisabledProven,
		hostruntime.OperationPhaseCSNoneQuiescenceProven,
		hostruntime.OperationPhaseCompSuspendNone,
		hostruntime.OperationPhaseCRPreStarted,
		hostruntime.OperationPhaseCRPreObserverAbsent,
		hostruntime.OperationPhaseCRPreWatchdogAbsent,
		hostruntime.OperationPhaseCRPreNoneDisabledProven,
		hostruntime.OperationPhaseCompResumeNone,
		hostruntime.OperationPhaseCRPostStarted,
		hostruntime.OperationPhaseCRPostObserverStopped,
		hostruntime.OperationPhaseCRPostQuiescenceProven,
		hostruntime.OperationPhaseCRPostNone,
		hostruntime.OperationPhaseCRPostWatchdogAbsent,
		hostruntime.OperationPhaseCBPreStarted,
		hostruntime.OperationPhaseCBPreNoneProven,
		hostruntime.OperationPhaseCompRollbackNone,
		hostruntime.OperationPhaseCBPostStarted,
		hostruntime.OperationPhaseCBPostLegacyStopped,
		hostruntime.OperationPhaseCBPostQuiescenceProven,
		hostruntime.OperationPhaseCBPostNone,
		hostruntime.OperationPhaseCompRollbackLegacyNone,
	}
	for _, phase := range phases {
		effect, present := productionPhaseEffects[phase]
		if !present || effect == 0 {
			t.Errorf("productionPhaseEffects[%q] is unmapped", phase)
		}
	}
}

func TestFixedTransitionBindingDerivesEveryClosedTargetLocalOperation(t *testing.T) {
	t.Parallel()

	revision := strings.Repeat("b", 64)
	manifestDigest := strings.Repeat("a", 64)
	current := manifestDigest
	base := cli.TargetProof{
		FenceGeneration:       7,
		ActiveFleet:           fleetfence.FleetPortable,
		CurrentManifestDigest: &current,
	}
	tests := []struct {
		name               string
		action             cli.HostAction
		target             cli.TargetProof
		expectedGeneration uint64
		wantKind           hostruntime.OperationKind
		wantFleet          fleetfence.Fleet
		wantTerminal       uint64
	}{
		{name: "suspend", action: cli.ActionSuspend, target: base, wantKind: hostruntime.OperationKindSuspend, wantFleet: fleetfence.FleetNone, wantTerminal: 8},
		{name: "rollback", action: cli.ActionRollback, target: base, expectedGeneration: 7, wantKind: hostruntime.OperationKindRollback, wantFleet: fleetfence.FleetLegacy, wantTerminal: 8},
		{name: "uninstall", action: cli.ActionUninstall, target: cli.TargetProof{FenceGeneration: 7, ActiveFleet: fleetfence.FleetNone, CurrentManifestDigest: &current}, wantKind: hostruntime.OperationKindUninstall, wantFleet: fleetfence.FleetNone, wantTerminal: 7},
		{name: "resume", action: cli.ActionResume, target: cli.TargetProof{FenceGeneration: 7, ActiveFleet: fleetfence.FleetNone, CurrentManifestDigest: &current}, wantKind: hostruntime.OperationKindResume, wantFleet: fleetfence.FleetPortable, wantTerminal: 8},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding, terminal, fleet, err := fixedTransitionBinding(
				test.action,
				test.target,
				manifestDigest,
				revision,
				test.expectedGeneration,
			)
			if err != nil {
				t.Fatalf("fixedTransitionBinding() error = %v", err)
			}
			if binding.Kind != test.wantKind ||
				binding.ExpectedGeneration != test.target.FenceGeneration ||
				binding.TargetFleet != test.wantFleet ||
				terminal != test.wantTerminal || fleet != test.wantFleet ||
				binding.PriorManifestDigest == nil ||
				*binding.PriorManifestDigest != manifestDigest {
				t.Fatalf("fixedTransitionBinding() = %#v, terminal=%d fleet=%q", binding, terminal, fleet)
			}
			if test.action == cli.ActionResume {
				if binding.TargetManifestDigest == nil || *binding.TargetManifestDigest != manifestDigest {
					t.Fatalf("resume target digest = %#v", binding.TargetManifestDigest)
				}
			} else if binding.TargetManifestDigest != nil {
				t.Fatalf("non-resume target digest = %#v", binding.TargetManifestDigest)
			}
		})
	}
}

func TestFixedTransitionBindingRejectsMissingOrForeignCurrentSelection(t *testing.T) {
	t.Parallel()

	revision := strings.Repeat("b", 64)
	manifestDigest := strings.Repeat("a", 64)
	target := cli.TargetProof{
		FenceGeneration: 7,
		ActiveFleet:     fleetfence.FleetNone,
	}
	if _, _, _, err := fixedTransitionBinding(
		cli.ActionResume,
		target,
		manifestDigest,
		revision,
		0,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("missing current error = %v", err)
	}
	foreign := strings.Repeat("c", 64)
	target.CurrentManifestDigest = &foreign
	if _, _, _, err := fixedTransitionBinding(
		cli.ActionResume,
		target,
		manifestDigest,
		revision,
		0,
	); !errors.Is(err, ErrLifecycleEffects) {
		t.Fatalf("foreign current error = %v", err)
	}
}

func TestGreenfieldEffectStateAdmitsOnlyExactWritablePredecessor(t *testing.T) {
	t.Parallel()

	target := systemLifecycleTarget{
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		terminalFence:  1,
		overlay: hostruntime.PrivateOverlay{
			Policy: hostruntime.PolicyOverlay{
				AcquisitionDefault: "disabled",
			},
		},
	}
	clean := systemLifecycleSnapshot{
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
		snapshot systemLifecycleSnapshot
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
	target := systemLifecycleTarget{
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
	clean := systemLifecycleSnapshot{
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
		snapshot systemLifecycleSnapshot
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
	target := systemLifecycleTarget{
		disposition:         hostruntime.InstallDispositionUpgradePortable,
		manifestDigest:      strings.Repeat("a", 64),
		revision:            strings.Repeat("b", 64),
		priorManifestDigest: strings.Repeat("c", 64),
		priorRevision:       strings.Repeat("d", 64),
		terminalFence:       7,
	}
	snapshot := systemLifecycleSnapshot{
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

	target := systemLifecycleTarget{
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		terminalFence:  1,
	}
	snapshot := systemLifecycleSnapshot{
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

	target := systemLifecycleTarget{
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		terminalFence:  1,
		overlay: hostruntime.PrivateOverlay{
			Policy: hostruntime.PolicyOverlay{
				AcquisitionDefault: "disabled",
			},
		},
	}
	promoted := systemLifecycleSnapshot{
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
		snapshot systemLifecycleSnapshot
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

func TestResumeEffectStateTracksExactCrashBoundaries(t *testing.T) {
	t.Parallel()

	target := systemLifecycleTarget{
		kind:           hostruntime.OperationKindResume,
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		entryFence:     7,
		terminalFence:  8,
	}
	entry := systemLifecycleSnapshot{
		fencePresent:    true,
		generation:      7,
		fleet:           fleetfence.FleetNone,
		releasedPresent: true,
		currentPresent:  true,
		current: releaseBundleSnapshot{
			manifestDigest:  strings.Repeat("a", 64),
			overlayRevision: strings.Repeat("b", 64),
		},
		priorPolicy: controller.PolicyStatus{
			Mode:     controller.AcquisitionDisabled,
			Capacity: 0,
			Epoch:    11,
			Digest:   strings.Repeat("c", 64),
		},
		priorDrained: true,
	}
	portable := entry
	portable.generation = 8
	portable.fleet = fleetfence.FleetPortable
	observer := portable
	observer.processPresent = true
	observer.processTarget = true
	watchdog := observer
	watchdog.watchdogPresent = true
	watchdog.watchdogTarget = true
	zero := watchdog
	zero.zero = true

	tests := []struct {
		name     string
		effect   productionEffect
		snapshot systemLifecycleSnapshot
		want     hostruntime.LifecycleEffectState
	}{
		{name: "prepared", effect: effectPreflight, snapshot: entry, want: hostruntime.LifecycleEffectPresent},
		{name: "stopped", effect: effectStoppedProven, snapshot: entry, want: hostruntime.LifecycleEffectPresent},
		{name: "disabled", effect: effectPolicyDisabled, snapshot: entry, want: hostruntime.LifecycleEffectPresent},
		{name: "handoff pending", effect: effectFencePortable, snapshot: entry, want: hostruntime.LifecycleEffectAbsent},
		{name: "handoff complete", effect: effectFencePortable, snapshot: portable, want: hostruntime.LifecycleEffectPresent},
		{name: "observer pending", effect: effectObserverStarted, snapshot: portable, want: hostruntime.LifecycleEffectAbsent},
		{name: "observer complete", effect: effectObserverStarted, snapshot: observer, want: hostruntime.LifecycleEffectPresent},
		{name: "watchdog pending", effect: effectWatchdogInstalled, snapshot: observer, want: hostruntime.LifecycleEffectAbsent},
		{name: "watchdog complete", effect: effectWatchdogInstalled, snapshot: watchdog, want: hostruntime.LifecycleEffectPresent},
		{name: "zero pending", effect: effectZeroProven, snapshot: watchdog, want: hostruntime.LifecycleEffectAbsent},
		{name: "zero complete", effect: effectZeroProven, snapshot: zero, want: hostruntime.LifecycleEffectPresent},
		{name: "complete", effect: effectVerified, snapshot: zero, want: hostruntime.LifecycleEffectPresent},
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

	foreign := entry
	foreign.current.manifestDigest = strings.Repeat("d", 64)
	if got := target.effectState(effectPreflight, foreign); got != hostruntime.LifecycleEffectAmbiguous {
		t.Fatalf("foreign selection state = %q, want ambiguous", got)
	}
}

func TestSuspendEffectStateTracksExactCrashBoundaries(t *testing.T) {
	t.Parallel()

	target := systemLifecycleTarget{
		kind:           hostruntime.OperationKindSuspend,
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		entryFence:     7,
		terminalFence:  8,
		terminalFleet:  fleetfence.FleetNone,
		drainPolicy:    "wait",
	}
	entry := systemLifecycleSnapshot{
		fencePresent:    true,
		generation:      7,
		fleet:           fleetfence.FleetPortable,
		releasedPresent: true,
		currentPresent:  true,
		current: releaseBundleSnapshot{
			manifestDigest:  strings.Repeat("a", 64),
			overlayRevision: strings.Repeat("b", 64),
		},
		watchdogPresent: true,
		watchdogTarget:  true,
		processPresent:  true,
		processTarget:   true,
		priorPolicy: controller.PolicyStatus{
			Mode:     controller.AcquisitionEnabled,
			Capacity: 4,
			Epoch:    11,
			Digest:   strings.Repeat("c", 64),
		},
	}
	watchdogDisabled := entry
	watchdogDisabled.watchdogPresent = false
	watchdogDisabled.watchdogTarget = false
	disabled := watchdogDisabled
	disabled.priorPolicy.Mode = controller.AcquisitionDisabled
	disabled.priorPolicy.Capacity = 0
	disabled.priorPolicy.Epoch++
	drained := disabled
	drained.priorDrained = true
	stopped := drained
	stopped.processPresent = false
	stopped.processTarget = false
	none := stopped
	none.generation = 8
	none.fleet = fleetfence.FleetNone

	tests := []struct {
		name     string
		effect   productionEffect
		snapshot systemLifecycleSnapshot
		want     hostruntime.LifecycleEffectState
	}{
		{name: "prepared", effect: effectPreflight, snapshot: entry, want: hostruntime.LifecycleEffectPresent},
		{name: "hosted hold", effect: effectHoldProven, snapshot: entry, want: hostruntime.LifecycleEffectPresent},
		{name: "watchdog pending", effect: effectWatchdogDisabled, snapshot: entry, want: hostruntime.LifecycleEffectAbsent},
		{name: "watchdog disabled", effect: effectWatchdogDisabled, snapshot: watchdogDisabled, want: hostruntime.LifecycleEffectPresent},
		{name: "policy pending", effect: effectPolicyDisabled, snapshot: watchdogDisabled, want: hostruntime.LifecycleEffectAbsent},
		{name: "policy disabled", effect: effectPolicyDisabled, snapshot: disabled, want: hostruntime.LifecycleEffectPresent},
		{name: "drain pending", effect: effectDrained, snapshot: disabled, want: hostruntime.LifecycleEffectAbsent},
		{name: "drained", effect: effectDrained, snapshot: drained, want: hostruntime.LifecycleEffectPresent},
		{name: "stop pending", effect: effectControllerStopped, snapshot: drained, want: hostruntime.LifecycleEffectAbsent},
		{name: "stopped", effect: effectControllerStopped, snapshot: stopped, want: hostruntime.LifecycleEffectPresent},
		{name: "quiescent", effect: effectQuiescenceProven, snapshot: stopped, want: hostruntime.LifecycleEffectPresent},
		{name: "handoff pending", effect: effectFenceNone, snapshot: stopped, want: hostruntime.LifecycleEffectAbsent},
		{name: "handoff complete", effect: effectFenceNone, snapshot: none, want: hostruntime.LifecycleEffectPresent},
		{name: "complete", effect: effectVerified, snapshot: none, want: hostruntime.LifecycleEffectPresent},
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

	foreign := entry
	foreign.current.overlayRevision = strings.Repeat("d", 64)
	if got := target.effectState(effectPreflight, foreign); got != hostruntime.LifecycleEffectAmbiguous {
		t.Fatalf("foreign selection state = %q, want ambiguous", got)
	}
}

func TestTransitionCompensationEffectStateTracksClosedRecoveryPaths(
	t *testing.T,
) {
	t.Parallel()

	digest := strings.Repeat("a", 64)
	revision := strings.Repeat("b", 64)
	disabled := controller.PolicyStatus{
		Mode:     controller.AcquisitionDisabled,
		Capacity: 0,
		Epoch:    11,
		Digest:   strings.Repeat("c", 64),
	}
	resume := systemLifecycleTarget{
		kind:           hostruntime.OperationKindResume,
		manifestDigest: digest,
		revision:       revision,
		entryFence:     7,
		terminalFence:  8,
		terminalFleet:  fleetfence.FleetPortable,
	}
	resumePre := systemLifecycleSnapshot{
		fencePresent:    true,
		generation:      7,
		fleet:           fleetfence.FleetNone,
		releasedPresent: true,
		currentPresent:  true,
		current: releaseBundleSnapshot{
			manifestDigest:  digest,
			overlayRevision: revision,
		},
		priorPolicy:  disabled,
		priorDrained: true,
	}
	resumePost := resumePre
	resumePost.generation = 8
	resumePost.fleet = fleetfence.FleetPortable
	resumePost.processPresent = true
	resumePost.processTarget = true
	resumePost.watchdogPresent = true
	resumePost.watchdogTarget = true
	resumeStopped := resumePost
	resumeStopped.processPresent = false
	resumeStopped.processTarget = false
	resumeNoneWithWatchdog := resumeStopped
	resumeNoneWithWatchdog.generation = 9
	resumeNoneWithWatchdog.fleet = fleetfence.FleetNone
	resumeCompensated := resumeNoneWithWatchdog
	resumeCompensated.watchdogPresent = false
	resumeCompensated.watchdogTarget = false

	suspend := systemLifecycleTarget{
		kind:           hostruntime.OperationKindSuspend,
		manifestDigest: digest,
		revision:       revision,
		entryFence:     7,
		terminalFence:  8,
		terminalFleet:  fleetfence.FleetNone,
	}
	suspendNone := resumePre
	suspendNone.generation = 8

	tests := []struct {
		name     string
		target   *systemLifecycleTarget
		phase    hostruntime.OperationPhase
		effect   productionEffect
		snapshot systemLifecycleSnapshot
		want     hostruntime.LifecycleEffectState
	}{
		{name: "resume pre start", target: &resume, phase: hostruntime.OperationPhaseCRPreStarted, effect: effectCompensationStarted, snapshot: resumePre, want: hostruntime.LifecycleEffectPresent},
		{name: "resume pre observer absent", target: &resume, phase: hostruntime.OperationPhaseCRPreObserverAbsent, effect: effectObserverStopped, snapshot: resumePre, want: hostruntime.LifecycleEffectPresent},
		{name: "resume pre watchdog absent", target: &resume, phase: hostruntime.OperationPhaseCRPreWatchdogAbsent, effect: effectWatchdogDisabled, snapshot: resumePre, want: hostruntime.LifecycleEffectPresent},
		{name: "resume pre none disabled", target: &resume, phase: hostruntime.OperationPhaseCRPreNoneDisabledProven, effect: effectNoneDisabledProven, snapshot: resumePre, want: hostruntime.LifecycleEffectPresent},
		{name: "resume pre compensated", target: &resume, phase: hostruntime.OperationPhaseCompResumeNone, effect: effectCompensated, snapshot: resumePre, want: hostruntime.LifecycleEffectPresent},
		{name: "resume post start", target: &resume, phase: hostruntime.OperationPhaseCRPostStarted, effect: effectCompensationStarted, snapshot: resumePost, want: hostruntime.LifecycleEffectPresent},
		{name: "resume post stop pending", target: &resume, phase: hostruntime.OperationPhaseCRPostObserverStopped, effect: effectObserverStopped, snapshot: resumePost, want: hostruntime.LifecycleEffectAbsent},
		{name: "resume post stopped", target: &resume, phase: hostruntime.OperationPhaseCRPostObserverStopped, effect: effectObserverStopped, snapshot: resumeStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "resume post quiescent", target: &resume, phase: hostruntime.OperationPhaseCRPostQuiescenceProven, effect: effectQuiescenceProven, snapshot: resumeStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "resume post handoff pending", target: &resume, phase: hostruntime.OperationPhaseCRPostNone, effect: effectFenceNone, snapshot: resumeStopped, want: hostruntime.LifecycleEffectAbsent},
		{name: "resume post handoff complete", target: &resume, phase: hostruntime.OperationPhaseCRPostNone, effect: effectFenceNone, snapshot: resumeNoneWithWatchdog, want: hostruntime.LifecycleEffectPresent},
		{name: "resume post watchdog pending", target: &resume, phase: hostruntime.OperationPhaseCRPostWatchdogAbsent, effect: effectWatchdogDisabled, snapshot: resumeNoneWithWatchdog, want: hostruntime.LifecycleEffectAbsent},
		{name: "resume post watchdog absent", target: &resume, phase: hostruntime.OperationPhaseCRPostWatchdogAbsent, effect: effectWatchdogDisabled, snapshot: resumeCompensated, want: hostruntime.LifecycleEffectPresent},
		{name: "resume post compensated", target: &resume, phase: hostruntime.OperationPhaseCompResumeNone, effect: effectCompensated, snapshot: resumeCompensated, want: hostruntime.LifecycleEffectPresent},
		{name: "suspend compensation start", target: &suspend, phase: hostruntime.OperationPhaseCSNoneStarted, effect: effectCompensationStarted, snapshot: suspendNone, want: hostruntime.LifecycleEffectPresent},
		{name: "suspend none disabled", target: &suspend, phase: hostruntime.OperationPhaseCSNoneDisabledProven, effect: effectNoneDisabledProven, snapshot: suspendNone, want: hostruntime.LifecycleEffectPresent},
		{name: "suspend quiescent", target: &suspend, phase: hostruntime.OperationPhaseCSNoneQuiescenceProven, effect: effectQuiescenceProven, snapshot: suspendNone, want: hostruntime.LifecycleEffectPresent},
		{name: "suspend compensated", target: &suspend, phase: hostruntime.OperationPhaseCompSuspendNone, effect: effectCompensated, snapshot: suspendNone, want: hostruntime.LifecycleEffectPresent},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.target.effectStateForPhase(
				test.phase,
				test.effect,
				test.snapshot,
			); got != test.want {
				t.Fatalf("effectStateForPhase() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInstallCompensationEffectStateTracksClosedRecoveryPaths(
	t *testing.T,
) {
	t.Parallel()

	targetDigest := strings.Repeat("a", 64)
	targetRevision := strings.Repeat("b", 64)
	priorDigest := strings.Repeat("c", 64)
	priorRevision := strings.Repeat("d", 64)
	disabled := controller.PolicyStatus{
		Mode:     controller.AcquisitionDisabled,
		Epoch:    4,
		Digest:   strings.Repeat("e", 64),
		Capacity: 0,
	}
	selected := func(
		digest string,
		revision string,
	) releaseBundleSnapshot {
		return releaseBundleSnapshot{
			present:         true,
			manifestDigest:  digest,
			overlayRevision: revision,
		}
	}
	candidate := func() systemLifecycleSnapshot {
		return systemLifecycleSnapshot{
			stagedPresent:   true,
			imagesVerified:  true,
			runnerSmoked:    true,
			releasedPresent: true,
			priorPolicy:     disabled,
			priorDrained:    true,
		}
	}

	greenfield := systemLifecycleTarget{
		disposition:    hostruntime.InstallDispositionGreenfieldPortable,
		manifestDigest: targetDigest,
		revision:       targetRevision,
		terminalFence:  1,
	}
	gPre := candidate()
	gPre.fleet = fleetfence.FleetNone
	gPreClean := gPre
	gPreClean.stagedPresent = false
	gPreClean.imagesVerified = false
	gPreClean.runnerSmoked = false
	gPreClean.releasedPresent = false
	gPreClean.zero = true
	gPortable := candidate()
	gPortable.fencePresent = true
	gPortable.generation = 1
	gPortable.fleet = fleetfence.FleetPortable
	gPortable.watchdogPresent = true
	gPortable.watchdogTarget = true
	gPortable.processPresent = true
	gPortable.processTarget = true
	gStopped := gPortable
	gStopped.watchdogPresent = false
	gStopped.watchdogTarget = false
	gStopped.processPresent = false
	gStopped.processTarget = false
	gStopped.zero = true
	gSelected := gPortable
	gSelected.currentPresent = true
	gSelected.current = selected(targetDigest, targetRevision)
	gSelectedStopped := gSelected
	gSelectedStopped.watchdogPresent = false
	gSelectedStopped.watchdogTarget = false
	gSelectedStopped.processPresent = false
	gSelectedStopped.processTarget = false
	gSelectedStopped.zero = true
	gNone := gStopped
	gNone.generation = 2
	gNone.fleet = fleetfence.FleetNone
	gNoneClean := gNone
	gNoneClean.stagedPresent = false
	gNoneClean.imagesVerified = false
	gNoneClean.runnerSmoked = false
	gNoneClean.releasedPresent = false

	upgrade := systemLifecycleTarget{
		disposition:         hostruntime.InstallDispositionUpgradePortable,
		manifestDigest:      targetDigest,
		revision:            targetRevision,
		priorManifestDigest: priorDigest,
		priorRevision:       priorRevision,
		terminalFence:       7,
	}
	uPre := candidate()
	uPre.fencePresent = true
	uPre.generation = 7
	uPre.fleet = fleetfence.FleetPortable
	uPre.currentPresent = true
	uPre.current = selected(priorDigest, priorRevision)
	uPre.watchdogPresent = true
	uPre.watchdogTarget = true
	uPre.processPresent = true
	uPre.processTarget = true
	uStopped := uPre
	uStopped.watchdogPresent = false
	uStopped.watchdogTarget = false
	uStopped.processPresent = false
	uStopped.processTarget = false
	uStopped.zero = true
	uPreClean := uStopped
	uPreClean.stagedPresent = false
	uPreClean.imagesVerified = false
	uPreClean.runnerSmoked = false
	uPreClean.releasedPresent = false
	uSelected := uPre
	uSelected.current = selected(targetDigest, targetRevision)
	uSelectedStopped := uSelected
	uSelectedStopped.watchdogPresent = false
	uSelectedStopped.watchdogTarget = false
	uSelectedStopped.processPresent = false
	uSelectedStopped.processTarget = false
	uSelectedStopped.zero = true
	uRestored := uSelectedStopped
	uRestored.current = selected(priorDigest, priorRevision)
	uPriorRunning := uRestored
	uPriorRunning.processPresent = true
	uPriorRunning.processPrior = true
	uPriorRunning.zero = true
	uRestoredClean := uPriorRunning
	uRestoredClean.stagedPresent = false
	uRestoredClean.imagesVerified = false
	uRestoredClean.runnerSmoked = false
	uRestoredClean.releasedPresent = false

	tests := []struct {
		name     string
		target   *systemLifecycleTarget
		phase    hostruntime.OperationPhase
		snapshot systemLifecycleSnapshot
		want     hostruntime.LifecycleEffectState
	}{
		{name: "greenfield pre started", target: &greenfield, phase: hostruntime.OperationPhaseCGPreStarted, snapshot: gPre, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield pre stopped", target: &greenfield, phase: hostruntime.OperationPhaseCGPreCandidateStopped, snapshot: gPre, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield pre remove pending", target: &greenfield, phase: hostruntime.OperationPhaseCGPreCandidateRemoved, snapshot: gPre, want: hostruntime.LifecycleEffectAbsent},
		{name: "greenfield pre removed", target: &greenfield, phase: hostruntime.OperationPhaseCGPreCandidateRemoved, snapshot: gPreClean, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield pre terminal", target: &greenfield, phase: hostruntime.OperationPhaseCompGreenfieldAbsent, snapshot: gPreClean, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield fence started", target: &greenfield, phase: hostruntime.OperationPhaseCGFenceStarted, snapshot: gPortable, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield fence stop pending", target: &greenfield, phase: hostruntime.OperationPhaseCGFenceObserverStopped, snapshot: gPortable, want: hostruntime.LifecycleEffectAbsent},
		{name: "greenfield fence stopped", target: &greenfield, phase: hostruntime.OperationPhaseCGFenceObserverStopped, snapshot: gStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield fence quiescent", target: &greenfield, phase: hostruntime.OperationPhaseCGFenceQuiescenceProven, snapshot: gStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield fence handoff pending", target: &greenfield, phase: hostruntime.OperationPhaseCGFenceNone, snapshot: gStopped, want: hostruntime.LifecycleEffectAbsent},
		{name: "greenfield fence remove pending", target: &greenfield, phase: hostruntime.OperationPhaseCGFenceCandidateRemoved, snapshot: gNone, want: hostruntime.LifecycleEffectAbsent},
		{name: "greenfield fence terminal", target: &greenfield, phase: hostruntime.OperationPhaseCompGreenfieldNone, snapshot: gNoneClean, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield selected started", target: &greenfield, phase: hostruntime.OperationPhaseCGSelectStarted, snapshot: gSelected, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield selected stopped", target: &greenfield, phase: hostruntime.OperationPhaseCGSelectObserverStopped, snapshot: gSelectedStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield selected clear pending", target: &greenfield, phase: hostruntime.OperationPhaseCGSelectCurrentRemoved, snapshot: gSelectedStopped, want: hostruntime.LifecycleEffectAbsent},
		{name: "greenfield selected cleared", target: &greenfield, phase: hostruntime.OperationPhaseCGSelectCurrentRemoved, snapshot: gStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "greenfield selected terminal", target: &greenfield, phase: hostruntime.OperationPhaseCompGreenfieldSelected, snapshot: gNoneClean, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade pre started", target: &upgrade, phase: hostruntime.OperationPhaseCUPreStarted, snapshot: uPre, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade pre stop pending", target: &upgrade, phase: hostruntime.OperationPhaseCUPreCandidateStopped, snapshot: uPre, want: hostruntime.LifecycleEffectAbsent},
		{name: "upgrade pre stopped", target: &upgrade, phase: hostruntime.OperationPhaseCUPreCandidateStopped, snapshot: uStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade pre remove pending", target: &upgrade, phase: hostruntime.OperationPhaseCUPreCandidateRemoved, snapshot: uStopped, want: hostruntime.LifecycleEffectAbsent},
		{name: "upgrade pre terminal", target: &upgrade, phase: hostruntime.OperationPhaseCompUpgradePrior, snapshot: uPreClean, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade selected started", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectStarted, snapshot: uSelected, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade selected stopped", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectObserverStopped, snapshot: uSelectedStopped, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade prior restore pending", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectPriorRestored, snapshot: uSelectedStopped, want: hostruntime.LifecycleEffectAbsent},
		{name: "upgrade prior restored", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectPriorRestored, snapshot: uRestored, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade prior start pending", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectPriorObserverStarted, snapshot: uRestored, want: hostruntime.LifecycleEffectAbsent},
		{name: "upgrade prior running", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectPriorObserverStarted, snapshot: uPriorRunning, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade prior zero", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectPriorZeroProven, snapshot: uPriorRunning, want: hostruntime.LifecycleEffectPresent},
		{name: "upgrade candidate remove pending", target: &upgrade, phase: hostruntime.OperationPhaseCUSelectCandidateRemoved, snapshot: uPriorRunning, want: hostruntime.LifecycleEffectAbsent},
		{name: "upgrade terminal", target: &upgrade, phase: hostruntime.OperationPhaseCompUpgradeRestored, snapshot: uRestoredClean, want: hostruntime.LifecycleEffectPresent},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			effect := productionPhaseEffects[test.phase]
			if got := test.target.effectStateForPhase(
				test.phase,
				effect,
				test.snapshot,
			); got != test.want {
				t.Fatalf("effectStateForPhase() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestUninstallEffectStateRetainsReleaseAndRemovesOnlyRegistration(t *testing.T) {
	t.Parallel()

	target := systemLifecycleTarget{
		kind:           hostruntime.OperationKindUninstall,
		manifestDigest: strings.Repeat("a", 64),
		revision:       strings.Repeat("b", 64),
		entryFence:     8,
		terminalFence:  8,
		terminalFleet:  fleetfence.FleetNone,
		retainState:    true,
	}
	entry := systemLifecycleSnapshot{
		fencePresent:    true,
		generation:      8,
		fleet:           fleetfence.FleetNone,
		releasedPresent: true,
		currentPresent:  true,
		current: releaseBundleSnapshot{
			manifestDigest:  strings.Repeat("a", 64),
			overlayRevision: strings.Repeat("b", 64),
		},
		watchdogPresent: true,
		watchdogTarget:  true,
		processPresent:  true,
		processTarget:   true,
		priorPolicy: controller.PolicyStatus{
			Mode:     controller.AcquisitionDisabled,
			Capacity: 0,
			Epoch:    11,
			Digest:   strings.Repeat("c", 64),
		},
		priorDrained: true,
	}
	watchdogRemoved := entry
	watchdogRemoved.watchdogPresent = false
	watchdogRemoved.watchdogTarget = false
	controllerRemoved := watchdogRemoved
	controllerRemoved.processPresent = false
	controllerRemoved.processTarget = false
	registrationRemoved := controllerRemoved
	registrationRemoved.currentPresent = false

	tests := []struct {
		name     string
		effect   productionEffect
		snapshot systemLifecycleSnapshot
		want     hostruntime.LifecycleEffectState
	}{
		{name: "prepared", effect: effectPreflight, snapshot: entry, want: hostruntime.LifecycleEffectPresent},
		{name: "quiescent", effect: effectQuiescenceProven, snapshot: entry, want: hostruntime.LifecycleEffectPresent},
		{name: "watchdog pending", effect: effectWatchdogRemoved, snapshot: entry, want: hostruntime.LifecycleEffectAbsent},
		{name: "watchdog removed", effect: effectWatchdogRemoved, snapshot: watchdogRemoved, want: hostruntime.LifecycleEffectPresent},
		{name: "controller pending", effect: effectControllerRemoved, snapshot: watchdogRemoved, want: hostruntime.LifecycleEffectAbsent},
		{name: "controller removed", effect: effectControllerRemoved, snapshot: controllerRemoved, want: hostruntime.LifecycleEffectPresent},
		{name: "registration pending", effect: effectRegistrationRemoved, snapshot: controllerRemoved, want: hostruntime.LifecycleEffectAbsent},
		{name: "registration removed", effect: effectRegistrationRemoved, snapshot: registrationRemoved, want: hostruntime.LifecycleEffectPresent},
		{name: "retained", effect: effectRetentionProven, snapshot: registrationRemoved, want: hostruntime.LifecycleEffectPresent},
		{name: "complete", effect: effectVerified, snapshot: registrationRemoved, want: hostruntime.LifecycleEffectPresent},
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

	deletedRelease := registrationRemoved
	deletedRelease.releasedPresent = false
	if got := target.effectState(effectRetentionProven, deletedRelease); got != hostruntime.LifecycleEffectAmbiguous {
		t.Fatalf("deleted retained release state = %q, want ambiguous", got)
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

func transitionContinuationFixture(
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
	operationID, err := hostruntime.DeriveOperationID(
		hostruntime.OperationKindResume,
		nil,
		7,
		&manifestDigest,
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
		Kind:                   hostruntime.OperationKindResume,
		ExpectedGeneration:     7,
		PriorManifestDigest:    &manifestDigest,
		TargetManifestDigest:   &manifestDigest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	journal := hostruntime.OperationJournal{
		SchemaVersion:      1,
		OperationID:        operationID,
		BindingDigest:      bindingDigest,
		Kind:               hostruntime.OperationKindResume,
		Phase:              hostruntime.OperationPhasePrepared,
		ExpectedGeneration: 7,
		PriorManifest:      &manifest,
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
