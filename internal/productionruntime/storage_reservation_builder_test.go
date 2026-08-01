package productionruntime

import (
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestBuildStorageReservationBindsCheckedLiveEnvelope(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	binding := storageBuilderBinding(t, revision, overlay.Manifest.Digest)
	availability := storageBuilderAvailability()
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)

	reservation, err := BuildStorageReservation(
		binding,
		overlay,
		manifest,
		availability,
		now,
	)
	if err != nil {
		t.Fatalf("BuildStorageReservation() error = %v", err)
	}
	if reservation.OperationID != binding.OperationID ||
		reservation.State != hostruntime.ReservationStateActive ||
		reservation.StorageBudgetDigest != manifest.StorageBudgetDigest ||
		reservation.TargetManifestDigest == nil ||
		*reservation.TargetManifestDigest != overlay.Manifest.Digest ||
		!reservation.CreatedAt.Equal(now) ||
		!reservation.UpdatedAt.Equal(now) ||
		len(reservation.Roles) != 6 ||
		len(reservation.Filesystems) != 6 ||
		len(reservation.CrashOrphans) != 0 {
		t.Fatalf("BuildStorageReservation() = %#v", reservation)
	}
	requirement := overlay.Resources.Storage.Requirements[0]
	wantRequiredBytes :=
		requirement.CurrentReleaseBytes +
			requirement.CandidateReleaseBytes +
			requirement.ExtractionBytes +
			requirement.RollbackBytes +
			overlay.Resources.Storage.MaximumActiveConcurrency*
				requirement.PerSlotBytes +
			requirement.HelperBytes +
			requirement.RelayBytes +
			requirement.ControllerBytes +
			requirement.LedgerBytes +
			requirement.LogBytes +
			requirement.HostReserveBytes
	wantRequiredInodes :=
		requirement.CurrentReleaseInodes +
			requirement.CandidateReleaseInodes +
			requirement.ExtractionInodes +
			requirement.RollbackInodes +
			overlay.Resources.Storage.MaximumActiveConcurrency*
				requirement.PerSlotInodes +
			requirement.HelperInodes +
			requirement.RelayInodes +
			requirement.ControllerInodes +
			requirement.LedgerInodes +
			requirement.LogInodes +
			requirement.HostReserveInodes
	if got := reservation.Roles[0]; got.RequiredBytes != wantRequiredBytes ||
		got.RequiredInodes != wantRequiredInodes ||
		got.CompensationBytes != requirement.WarningReserveBytes ||
		got.CompensationInodes != requirement.WarningReserveInodes ||
		got.ObservedFreeBytes != availability[0].FreeBytes ||
		got.ObservedFreeInodes != availability[0].FreeInodes ||
		got.MountID != availability[0].Filesystem.MountID {
		t.Fatalf("first role = %#v", got)
	}
	if _, _, err := hostruntime.MarshalStorageReservation(
		reservation,
	); err != nil {
		t.Fatalf("reservation is not canonical: %v", err)
	}
}

func TestBuildStorageReservationFailsClosedBeforeMutationInputs(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	manifest := protocolTestManifest()
	binding := storageBuilderBinding(t, revision, overlay.Manifest.Digest)
	availability := storageBuilderAvailability()
	now := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)

	tests := []struct {
		name   string
		mutate func(
			*hostruntime.OperationBinding,
			*hostruntime.PrivateOverlay,
			*hostruntime.RuntimeManifest,
			*[]StorageAvailability,
			*time.Time,
		)
	}{
		{
			name: "invalid binding",
			mutate: func(
				binding *hostruntime.OperationBinding,
				_ *hostruntime.PrivateOverlay,
				_ *hostruntime.RuntimeManifest,
				_ *[]StorageAvailability,
				_ *time.Time,
			) {
				binding.OperationID = strings.Repeat("f", 64)
			},
		},
		{
			name: "overlay does not match binding",
			mutate: func(
				_ *hostruntime.OperationBinding,
				overlay *hostruntime.PrivateOverlay,
				_ *hostruntime.RuntimeManifest,
				_ *[]StorageAvailability,
				_ *time.Time,
			) {
				overlay.Manifest.Digest = strings.Repeat("e", 64)
			},
		},
		{
			name: "wrong manifest identity",
			mutate: func(
				_ *hostruntime.OperationBinding,
				_ *hostruntime.PrivateOverlay,
				manifest *hostruntime.RuntimeManifest,
				_ *[]StorageAvailability,
				_ *time.Time,
			) {
				manifest.StorageBudgetDigest = "not-a-digest"
			},
		},
		{
			name: "reordered availability",
			mutate: func(
				_ *hostruntime.OperationBinding,
				_ *hostruntime.PrivateOverlay,
				_ *hostruntime.RuntimeManifest,
				availability *[]StorageAvailability,
				_ *time.Time,
			) {
				(*availability)[0], (*availability)[1] =
					(*availability)[1], (*availability)[0]
			},
		},
		{
			name: "identity drift",
			mutate: func(
				_ *hostruntime.OperationBinding,
				_ *hostruntime.PrivateOverlay,
				_ *hostruntime.RuntimeManifest,
				availability *[]StorageAvailability,
				_ *time.Time,
			) {
				(*availability)[0].Filesystem.RootInode++
			},
		},
		{
			name: "insufficient bytes",
			mutate: func(
				_ *hostruntime.OperationBinding,
				_ *hostruntime.PrivateOverlay,
				_ *hostruntime.RuntimeManifest,
				availability *[]StorageAvailability,
				_ *time.Time,
			) {
				(*availability)[0].FreeBytes = 1
			},
		},
		{
			name: "non utc timestamp",
			mutate: func(
				_ *hostruntime.OperationBinding,
				_ *hostruntime.PrivateOverlay,
				_ *hostruntime.RuntimeManifest,
				_ *[]StorageAvailability,
				now *time.Time,
			) {
				*now = now.In(time.FixedZone("offset", 3600))
			},
		},
		{
			name: "overflow",
			mutate: func(
				_ *hostruntime.OperationBinding,
				overlay *hostruntime.PrivateOverlay,
				_ *hostruntime.RuntimeManifest,
				_ *[]StorageAvailability,
				_ *time.Time,
			) {
				overlay.Resources.Storage.MaximumActiveConcurrency = ^uint64(0)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testBinding := binding
			testOverlay := overlay
			testManifest := manifest
			testAvailability := append(
				[]StorageAvailability(nil),
				availability...,
			)
			testNow := now
			test.mutate(
				&testBinding,
				&testOverlay,
				&testManifest,
				&testAvailability,
				&testNow,
			)
			if _, err := BuildStorageReservation(
				testBinding,
				testOverlay,
				testManifest,
				testAvailability,
				testNow,
			); err == nil {
				t.Fatal("BuildStorageReservation() accepted invalid input")
			}
		})
	}
}

func storageBuilderBinding(
	t *testing.T,
	revision string,
	manifestDigest string,
) hostruntime.OperationBinding {
	t.Helper()
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
	return hostruntime.OperationBinding{
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
}

func storageBuilderAvailability() []StorageAvailability {
	roles := []string{
		"docker-root",
		"state",
		"staging",
		"rollback",
		"scratch",
		"logs",
	}
	availability := make([]StorageAvailability, 0, len(roles))
	for index, role := range roles {
		availability = append(availability, StorageAvailability{
			Device: uint64(index + 1),
			Filesystem: hostruntime.LifecycleFilesystemIdentity{
				Role:        role,
				MountID:     uint64(index + 1),
				DeviceMajor: 8,
				DeviceMinor: uint32(index + 1),
				RootInode:   uint64(index + 11),
				FSType:      "ext4",
			},
			FreeBytes:  1 << 40,
			FreeInodes: 1 << 30,
		})
	}
	return availability
}
