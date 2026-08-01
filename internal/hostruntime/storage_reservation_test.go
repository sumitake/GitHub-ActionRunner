package hostruntime

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	goldenStorageReservationDigest = "26e4a017f49d9659ca40928c1ceef56d83e21d4dd2dab86ce5557c6deb73e245"
)

func TestStorageReservationGoldenAndTransitions(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	created := time.Date(2026, 7, 29, 7, 15, 0, 0, time.UTC)
	active := goldenStorageReservation(t, binding, created)

	encoded, digest, err := MarshalStorageReservation(active)
	if err != nil {
		t.Fatalf("MarshalStorageReservation() error = %v", err)
	}
	if digest != goldenStorageReservationDigest {
		t.Fatalf(
			"MarshalStorageReservation() digest = %q, want %q; json=%s",
			digest,
			goldenStorageReservationDigest,
			encoded,
		)
	}
	decoded, decodedDigest, err := ParseStorageReservation(encoded, len(encoded))
	if err != nil {
		t.Fatalf("ParseStorageReservation() error = %v", err)
	}
	if decoded.State != ReservationStateActive || decodedDigest != digest {
		t.Fatalf("ParseStorageReservation() = %#v, digest=%q", decoded, decodedDigest)
	}

	targetProof := strings.Repeat("d", 64)
	committed := active
	committed.State = ReservationStateCommitted
	committed.CommittedTargetProofDigest = &targetProof
	committed.UpdatedAt = created.Add(time.Second)
	if err := ValidateStorageReservationTransition(active, committed); err != nil {
		t.Fatalf("ValidateStorageReservationTransition(committed) error = %v", err)
	}

	absenceProof := strings.Repeat("e", 64)
	released := active
	released.State = ReservationStateReleased
	released.ReleasedAbsenceProofDigest = &absenceProof
	released.UpdatedAt = created.Add(time.Second)
	if err := ValidateStorageReservationTransition(active, released); err != nil {
		t.Fatalf("ValidateStorageReservationTransition(released) error = %v", err)
	}
}

func TestStorageReservationRejectsIncompleteOrMisorderedEnvelope(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	valid := goldenStorageReservation(
		t,
		binding,
		time.Date(2026, 7, 29, 7, 15, 0, 0, time.UTC),
	)
	tests := map[string]func(*StorageReservation){
		"misordered role": func(reservation *StorageReservation) {
			reservation.Roles[0], reservation.Roles[1] =
				reservation.Roles[1], reservation.Roles[0]
		},
		"wrong mount": func(reservation *StorageReservation) {
			reservation.Roles[0].MountID++
		},
		"zero requirement": func(reservation *StorageReservation) {
			reservation.Roles[0].RequiredBytes = 0
		},
		"insufficient free": func(reservation *StorageReservation) {
			reservation.Roles[0].ObservedFreeBytes = 1
		},
		"active with terminal proof": func(reservation *StorageReservation) {
			digest := strings.Repeat("d", 64)
			reservation.CommittedTargetProofDigest = &digest
		},
		"unsorted orphan": func(reservation *StorageReservation) {
			reservation.CrashOrphans = []CrashOrphanReservation{
				{ObjectID: "z", FilesystemRole: "state", Bytes: 1, Inodes: 1},
				{ObjectID: "a", FilesystemRole: "state", Bytes: 1, Inodes: 1},
			}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reservation := valid
			reservation.Filesystems = append(
				[]LifecycleFilesystemIdentity(nil),
				valid.Filesystems...,
			)
			reservation.Roles = append(
				[]StorageRoleReservation(nil),
				valid.Roles...,
			)
			reservation.CrashOrphans = append(
				[]CrashOrphanReservation(nil),
				valid.CrashOrphans...,
			)
			mutate(&reservation)
			if _, _, err := MarshalStorageReservation(reservation); !errors.Is(err, ErrInvalidStorageReservation) {
				t.Fatalf("MarshalStorageReservation() error = %v", err)
			}
		})
	}
}

func goldenStorageReservation(
	t *testing.T,
	binding OperationBinding,
	created time.Time,
) StorageReservation {
	t.Helper()
	postcondition := goldenPostcondition(t, binding, strings.Repeat("a", 64))
	roles := make([]StorageRoleReservation, 0, len(postcondition.Filesystems))
	for index, filesystem := range postcondition.Filesystems {
		roles = append(roles, StorageRoleReservation{
			Role:               filesystem.Role,
			MountID:            filesystem.MountID,
			RequiredBytes:      uint64(1000 + index),
			RequiredInodes:     uint64(100 + index),
			CompensationBytes:  uint64(100 + index),
			CompensationInodes: uint64(10 + index),
			ObservedFreeBytes:  uint64(10000 + index),
			ObservedFreeInodes: uint64(1000 + index),
		})
	}
	target := *binding.TargetManifestDigest
	return StorageReservation{
		SchemaVersion:              1,
		OperationID:                binding.OperationID,
		BindingDigest:              goldenBindingDigestFor(t, binding),
		State:                      ReservationStateActive,
		StorageBudgetDigest:        strings.Repeat("6", 64),
		TargetManifestDigest:       &target,
		Filesystems:                postcondition.Filesystems,
		Roles:                      roles,
		CrashOrphans:               []CrashOrphanReservation{},
		CommittedTargetProofDigest: nil,
		ReleasedAbsenceProofDigest: nil,
		CreatedAt:                  created,
		UpdatedAt:                  created,
	}
}
