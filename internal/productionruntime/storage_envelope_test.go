package productionruntime

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestReservationStorageAuthorityRevalidatesCompleteEnvelope(t *testing.T) {
	t.Parallel()

	reservation := validStorageReservationFixture()
	probe := storageProbeFromReservation(reservation)
	authority, err := NewReservationStorageAuthority(probe)
	if err != nil {
		t.Fatalf("NewReservationStorageAuthority() error = %v", err)
	}
	if err := authority.Revalidate(
		context.Background(),
		reservation,
	); err != nil {
		t.Fatalf("Revalidate() error = %v", err)
	}
	if len(probe.calls) != len(reservation.Filesystems) {
		t.Fatalf("probe calls = %d", len(probe.calls))
	}
}

func TestReservationStorageAuthorityAggregatesSharedMountsAndOrphans(
	t *testing.T,
) {
	t.Parallel()

	reservation := validStorageReservationFixture()
	reservation.Filesystems[1].MountID = reservation.Filesystems[0].MountID
	reservation.Filesystems[1].DeviceMajor =
		reservation.Filesystems[0].DeviceMajor
	reservation.Filesystems[1].DeviceMinor =
		reservation.Filesystems[0].DeviceMinor
	reservation.Filesystems[1].RootInode =
		reservation.Filesystems[0].RootInode
	reservation.Filesystems[1].FSType =
		reservation.Filesystems[0].FSType
	reservation.Roles[1].MountID = reservation.Roles[0].MountID
	reservation.Roles[1].ObservedFreeBytes =
		reservation.Roles[0].ObservedFreeBytes
	reservation.Roles[1].ObservedFreeInodes =
		reservation.Roles[0].ObservedFreeInodes
	reservation.CrashOrphans = []hostruntime.CrashOrphanReservation{
		{
			ObjectID:       "orphan-a",
			FilesystemRole: "state",
			Bytes:          5,
			Inodes:         1,
		},
	}
	probe := storageProbeFromReservation(reservation)
	dockerRoot := probe.observations["docker-root"]
	dockerRoot.FreeBytes = 225
	dockerRoot.FreeInodes = 23
	state := probe.observations["state"]
	state.FreeBytes = 225
	state.FreeInodes = 23
	probe.observations["docker-root"] = dockerRoot
	probe.observations["state"] = state
	authority, err := NewReservationStorageAuthority(probe)
	if err != nil {
		t.Fatalf("NewReservationStorageAuthority() error = %v", err)
	}
	if err := authority.Revalidate(
		context.Background(),
		reservation,
	); err != nil {
		t.Fatalf("Revalidate() error = %v", err)
	}

	dockerRoot.FreeBytes--
	state.FreeBytes--
	probe.observations["docker-root"] = dockerRoot
	probe.observations["state"] = state
	if err := authority.Revalidate(
		context.Background(),
		reservation,
	); !errors.Is(err, ErrStorageEnvelope) {
		t.Fatalf("insufficient Revalidate() error = %v", err)
	}
}

func TestReservationStorageAuthorityFailsClosedOnDriftAndAmbiguity(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*hostruntime.StorageReservation, *fakeStorageProbe)
	}{
		{
			"filesystem-identity",
			func(
				_ *hostruntime.StorageReservation,
				probe *fakeStorageProbe,
			) {
				observation := probe.observations["state"]
				observation.Filesystem.RootInode++
				probe.observations["state"] = observation
			},
		},
		{
			"free-bytes",
			func(
				_ *hostruntime.StorageReservation,
				probe *fakeStorageProbe,
			) {
				observation := probe.observations["state"]
				observation.FreeBytes = 109
				probe.observations["state"] = observation
			},
		},
		{
			"free-inodes",
			func(
				_ *hostruntime.StorageReservation,
				probe *fakeStorageProbe,
			) {
				observation := probe.observations["state"]
				observation.FreeInodes = 10
				probe.observations["state"] = observation
			},
		},
		{
			"probe-error",
			func(
				_ *hostruntime.StorageReservation,
				probe *fakeStorageProbe,
			) {
				probe.err = errors.New("probe failed")
			},
		},
		{
			"orphan-overflow",
			func(
				reservation *hostruntime.StorageReservation,
				_ *fakeStorageProbe,
			) {
				reservation.CrashOrphans =
					[]hostruntime.CrashOrphanReservation{
						{
							ObjectID:       "orphan-a",
							FilesystemRole: "state",
							Bytes:          math.MaxUint64,
							Inodes:         math.MaxUint64,
						},
					}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reservation := validStorageReservationFixture()
			probe := storageProbeFromReservation(reservation)
			test.mutate(&reservation, probe)
			authority, err := NewReservationStorageAuthority(probe)
			if err != nil {
				t.Fatalf("NewReservationStorageAuthority() error = %v", err)
			}
			if err := authority.Revalidate(
				context.Background(),
				reservation,
			); !errors.Is(err, ErrStorageEnvelope) {
				t.Fatalf("Revalidate() error = %v", err)
			}
		})
	}
}

func TestReservationStorageAuthorityRejectsInvalidOrCancelledUse(
	t *testing.T,
) {
	t.Parallel()

	if _, err := NewReservationStorageAuthority(
		nil,
	); !errors.Is(err, ErrStorageEnvelope) {
		t.Fatalf("NewReservationStorageAuthority(nil) error = %v", err)
	}
	reservation := validStorageReservationFixture()
	probe := storageProbeFromReservation(reservation)
	authority, err := NewReservationStorageAuthority(probe)
	if err != nil {
		t.Fatalf("NewReservationStorageAuthority() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := authority.Revalidate(
		ctx,
		reservation,
	); !errors.Is(err, ErrStorageEnvelope) {
		t.Fatalf("cancelled Revalidate() error = %v", err)
	}
}

type fakeStorageProbe struct {
	observations map[string]StorageAvailability
	calls        []string
	err          error
}

func (probe *fakeStorageProbe) Observe(
	_ context.Context,
	expected hostruntime.LifecycleFilesystemIdentity,
) (StorageAvailability, error) {
	probe.calls = append(probe.calls, expected.Role)
	if probe.err != nil {
		return StorageAvailability{}, probe.err
	}
	observation, ok := probe.observations[expected.Role]
	if !ok {
		return StorageAvailability{}, errors.New("missing observation")
	}
	return observation, nil
}

func storageProbeFromReservation(
	reservation hostruntime.StorageReservation,
) *fakeStorageProbe {
	observations := make(map[string]StorageAvailability)
	for index, filesystem := range reservation.Filesystems {
		role := reservation.Roles[index]
		observations[filesystem.Role] = StorageAvailability{
			Filesystem: filesystem,
			FreeBytes:  role.ObservedFreeBytes,
			FreeInodes: role.ObservedFreeInodes,
		}
	}
	return &fakeStorageProbe{observations: observations}
}

func validStorageReservationFixture() hostruntime.StorageReservation {
	roles := [...]string{
		"docker-root",
		"state",
		"staging",
		"rollback",
		"scratch",
		"logs",
	}
	filesystems := make([]hostruntime.LifecycleFilesystemIdentity, 0, len(roles))
	reservations := make([]hostruntime.StorageRoleReservation, 0, len(roles))
	for index, role := range roles {
		filesystems = append(
			filesystems,
			hostruntime.LifecycleFilesystemIdentity{
				Role:        role,
				MountID:     uint64(index + 1),
				DeviceMajor: 8,
				DeviceMinor: uint32(index + 1),
				RootInode:   uint64(index + 11),
				FSType:      "ext4",
			},
		)
		reservations = append(
			reservations,
			hostruntime.StorageRoleReservation{
				Role:               role,
				MountID:            uint64(index + 1),
				RequiredBytes:      100,
				RequiredInodes:     10,
				CompensationBytes:  10,
				CompensationInodes: 1,
				ObservedFreeBytes:  1000,
				ObservedFreeInodes: 100,
			},
		)
	}
	now := time.Date(2026, 7, 30, 1, 2, 3, 0, time.UTC)
	target := strings.Repeat("d", 64)
	return hostruntime.StorageReservation{
		SchemaVersion:              1,
		OperationID:                strings.Repeat("a", 64),
		BindingDigest:              strings.Repeat("b", 64),
		State:                      hostruntime.ReservationStateActive,
		StorageBudgetDigest:        strings.Repeat("c", 64),
		TargetManifestDigest:       &target,
		Filesystems:                filesystems,
		Roles:                      reservations,
		CrashOrphans:               []hostruntime.CrashOrphanReservation{},
		CommittedTargetProofDigest: nil,
		ReleasedAbsenceProofDigest: nil,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}
}
