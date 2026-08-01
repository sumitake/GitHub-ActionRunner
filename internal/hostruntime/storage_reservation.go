package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"sort"
	"time"
)

const (
	storageReservationSchemaVersion = uint32(1)
	storageReservationDomain        = "portable-ghar-storage-reservation-v1"
)

var ErrInvalidStorageReservation = errors.New("hostruntime: invalid storage reservation")

type ReservationState string

const (
	ReservationStateActive    ReservationState = "active"
	ReservationStateCommitted ReservationState = "committed"
	ReservationStateReleased  ReservationState = "released"
)

type StorageRoleReservation struct {
	Role               string `json:"role"`
	MountID            uint64 `json:"mount_id"`
	RequiredBytes      uint64 `json:"required_bytes"`
	RequiredInodes     uint64 `json:"required_inodes"`
	CompensationBytes  uint64 `json:"compensation_bytes"`
	CompensationInodes uint64 `json:"compensation_inodes"`
	ObservedFreeBytes  uint64 `json:"observed_free_bytes"`
	ObservedFreeInodes uint64 `json:"observed_free_inodes"`
}

type CrashOrphanReservation struct {
	ObjectID       string `json:"object_id"`
	FilesystemRole string `json:"filesystem_role"`
	Bytes          uint64 `json:"bytes"`
	Inodes         uint64 `json:"inodes"`
}

type StorageReservation struct {
	SchemaVersion              uint32                        `json:"schema_version"`
	OperationID                string                        `json:"operation_id"`
	BindingDigest              string                        `json:"binding_digest"`
	State                      ReservationState              `json:"state"`
	StorageBudgetDigest        string                        `json:"storage_budget_digest"`
	TargetManifestDigest       *string                       `json:"target_manifest_digest"`
	Filesystems                []LifecycleFilesystemIdentity `json:"filesystems"`
	Roles                      []StorageRoleReservation      `json:"roles"`
	CrashOrphans               []CrashOrphanReservation      `json:"crash_orphans"`
	CommittedTargetProofDigest *string                       `json:"committed_target_proof_digest"`
	ReleasedAbsenceProofDigest *string                       `json:"released_absence_proof_digest"`
	CreatedAt                  time.Time                     `json:"created_at"`
	UpdatedAt                  time.Time                     `json:"updated_at"`
}

func ParseStorageReservation(
	document []byte,
	maxBytes int,
) (StorageReservation, string, error) {
	if maxBytes <= 0 || len(document) == 0 || len(document) > maxBytes {
		return StorageReservation{}, "", ErrInvalidStorageReservation
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var reservation StorageReservation
	if err := decoder.Decode(&reservation); err != nil {
		return StorageReservation{}, "", ErrInvalidStorageReservation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return StorageReservation{}, "", ErrInvalidStorageReservation
	}
	if err := validateStorageReservation(reservation); err != nil {
		return StorageReservation{}, "", err
	}
	canonical, err := json.Marshal(reservation)
	if err != nil || !bytes.Equal(canonical, document) {
		return StorageReservation{}, "", ErrInvalidStorageReservation
	}
	return reservation, canonicalArtifactDigest(storageReservationDomain, canonical), nil
}

func MarshalStorageReservation(
	reservation StorageReservation,
) ([]byte, string, error) {
	if err := validateStorageReservation(reservation); err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(reservation)
	if err != nil {
		return nil, "", ErrInvalidStorageReservation
	}
	return canonical, canonicalArtifactDigest(storageReservationDomain, canonical), nil
}

func ValidateStorageReservationTransition(
	current StorageReservation,
	next StorageReservation,
) error {
	if err := validateStorageReservation(current); err != nil {
		return err
	}
	if err := validateStorageReservation(next); err != nil {
		return err
	}
	currentBytes, _, _ := MarshalStorageReservation(current)
	nextBytes, _, _ := MarshalStorageReservation(next)
	if bytes.Equal(currentBytes, nextBytes) {
		return nil
	}
	if !sameStorageReservationIdentity(current, next) ||
		!next.UpdatedAt.After(current.UpdatedAt) {
		return ErrInvalidStorageReservation
	}
	switch {
	case current.State == ReservationStateActive &&
		(next.State == ReservationStateCommitted ||
			next.State == ReservationStateReleased):
		return nil
	case current.State == ReservationStateCommitted &&
		next.State == ReservationStateReleased:
		return nil
	default:
		return ErrInvalidStorageReservation
	}
}

func validateStorageReservation(reservation StorageReservation) error {
	if reservation.SchemaVersion != storageReservationSchemaVersion ||
		!isLowerHex64(reservation.OperationID) ||
		!isLowerHex64(reservation.BindingDigest) ||
		!isLowerHex64(reservation.StorageBudgetDigest) ||
		!validOptionalLowerDigest(reservation.TargetManifestDigest) ||
		reservation.Filesystems == nil ||
		reservation.Roles == nil ||
		reservation.CrashOrphans == nil ||
		reservation.CreatedAt.IsZero() ||
		reservation.UpdatedAt.IsZero() ||
		reservation.UpdatedAt.Before(reservation.CreatedAt) ||
		!utcTime(reservation.CreatedAt) ||
		!utcTime(reservation.UpdatedAt) {
		return ErrInvalidStorageReservation
	}
	if err := validateLifecycleFilesystems(reservation.Filesystems); err != nil {
		return ErrInvalidStorageReservation
	}
	if err := validateStorageRoles(reservation.Filesystems, reservation.Roles); err != nil {
		return err
	}
	if err := validateCrashOrphans(reservation.CrashOrphans); err != nil {
		return err
	}
	switch reservation.State {
	case ReservationStateActive:
		if reservation.CommittedTargetProofDigest != nil ||
			reservation.ReleasedAbsenceProofDigest != nil {
			return ErrInvalidStorageReservation
		}
	case ReservationStateCommitted:
		if reservation.CommittedTargetProofDigest == nil ||
			!isLowerHex64(*reservation.CommittedTargetProofDigest) ||
			reservation.ReleasedAbsenceProofDigest != nil {
			return ErrInvalidStorageReservation
		}
	case ReservationStateReleased:
		if reservation.CommittedTargetProofDigest != nil ||
			reservation.ReleasedAbsenceProofDigest == nil ||
			!isLowerHex64(*reservation.ReleasedAbsenceProofDigest) {
			return ErrInvalidStorageReservation
		}
	default:
		return ErrInvalidStorageReservation
	}
	return nil
}

type mountReservationTotal struct {
	freeBytes  uint64
	freeInodes uint64
	bytes      uint64
	inodes     uint64
}

func validateStorageRoles(
	filesystems []LifecycleFilesystemIdentity,
	roles []StorageRoleReservation,
) error {
	if len(roles) != len(lifecycleFilesystemRoles) {
		return ErrInvalidStorageReservation
	}
	totals := make(map[uint64]mountReservationTotal, len(roles))
	for index, role := range roles {
		if role.Role != lifecycleFilesystemRoles[index] ||
			role.MountID != filesystems[index].MountID ||
			role.RequiredBytes == 0 ||
			role.RequiredInodes == 0 ||
			role.ObservedFreeBytes == 0 ||
			role.ObservedFreeInodes == 0 {
			return ErrInvalidStorageReservation
		}
		requiredBytes, ok := checkedUint64Add(
			role.RequiredBytes,
			role.CompensationBytes,
		)
		if !ok {
			return ErrInvalidStorageReservation
		}
		requiredInodes, ok := checkedUint64Add(
			role.RequiredInodes,
			role.CompensationInodes,
		)
		if !ok {
			return ErrInvalidStorageReservation
		}
		total, found := totals[role.MountID]
		if found &&
			(total.freeBytes != role.ObservedFreeBytes ||
				total.freeInodes != role.ObservedFreeInodes) {
			return ErrInvalidStorageReservation
		}
		total.freeBytes = role.ObservedFreeBytes
		total.freeInodes = role.ObservedFreeInodes
		total.bytes, ok = checkedUint64Add(total.bytes, requiredBytes)
		if !ok {
			return ErrInvalidStorageReservation
		}
		total.inodes, ok = checkedUint64Add(total.inodes, requiredInodes)
		if !ok {
			return ErrInvalidStorageReservation
		}
		totals[role.MountID] = total
	}
	for _, total := range totals {
		if total.bytes > total.freeBytes || total.inodes > total.freeInodes {
			return ErrInvalidStorageReservation
		}
	}
	return nil
}

func validateCrashOrphans(orphans []CrashOrphanReservation) error {
	if len(orphans) > 4096 ||
		!sort.SliceIsSorted(orphans, func(i, j int) bool {
			if orphans[i].FilesystemRole != orphans[j].FilesystemRole {
				return orphans[i].FilesystemRole < orphans[j].FilesystemRole
			}
			return orphans[i].ObjectID < orphans[j].ObjectID
		}) {
		return ErrInvalidStorageReservation
	}
	for index, orphan := range orphans {
		if !validLifecycleScalar(orphan.ObjectID) ||
			!knownLifecycleFilesystemRole(orphan.FilesystemRole) ||
			orphan.Bytes == 0 ||
			orphan.Inodes == 0 ||
			(index > 0 &&
				orphans[index-1].FilesystemRole == orphan.FilesystemRole &&
				orphans[index-1].ObjectID == orphan.ObjectID) {
			return ErrInvalidStorageReservation
		}
	}
	return nil
}

func knownLifecycleFilesystemRole(role string) bool {
	for _, candidate := range lifecycleFilesystemRoles {
		if role == candidate {
			return true
		}
	}
	return false
}

func checkedUint64Add(left, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}

func sameStorageReservationIdentity(
	left StorageReservation,
	right StorageReservation,
) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.OperationID == right.OperationID &&
		left.BindingDigest == right.BindingDigest &&
		left.StorageBudgetDigest == right.StorageBudgetDigest &&
		reflect.DeepEqual(left.TargetManifestDigest, right.TargetManifestDigest) &&
		reflect.DeepEqual(left.Filesystems, right.Filesystems) &&
		reflect.DeepEqual(left.Roles, right.Roles) &&
		reflect.DeepEqual(left.CrashOrphans, right.CrashOrphans) &&
		left.CreatedAt.Equal(right.CreatedAt)
}
