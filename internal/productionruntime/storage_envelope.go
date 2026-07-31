package productionruntime

import (
	"context"
	"errors"
	"math"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

var ErrStorageEnvelope = errors.New(
	"productionruntime: storage envelope failed",
)

type StorageAvailability struct {
	Filesystem hostruntime.LifecycleFilesystemIdentity
	FreeBytes  uint64
	FreeInodes uint64
}

type StorageProbe interface {
	Observe(
		context.Context,
		hostruntime.LifecycleFilesystemIdentity,
	) (StorageAvailability, error)
}

type ReservationStorageAuthority struct {
	probe StorageProbe
}

func NewReservationStorageAuthority(
	probe StorageProbe,
) (*ReservationStorageAuthority, error) {
	if probe == nil {
		return nil, ErrStorageEnvelope
	}
	return &ReservationStorageAuthority{probe: probe}, nil
}

func (authority *ReservationStorageAuthority) Revalidate(
	ctx context.Context,
	reservation hostruntime.StorageReservation,
) error {
	if authority == nil || authority.probe == nil || ctx == nil ||
		ctx.Err() != nil {
		return ErrStorageEnvelope
	}
	if _, _, err := hostruntime.MarshalStorageReservation(
		reservation,
	); err != nil {
		return ErrStorageEnvelope
	}

	type mountEnvelope struct {
		requiredBytes  uint64
		requiredInodes uint64
		freeBytes      uint64
		freeInodes     uint64
		observed       bool
	}
	mounts := make(map[uint64]mountEnvelope, len(reservation.Roles))
	roleMounts := make(map[string]uint64, len(reservation.Roles))
	for index, role := range reservation.Roles {
		filesystem := reservation.Filesystems[index]
		requiredBytes, ok := addStorageAmount(
			role.RequiredBytes,
			role.CompensationBytes,
		)
		if !ok {
			return ErrStorageEnvelope
		}
		requiredInodes, ok := addStorageAmount(
			role.RequiredInodes,
			role.CompensationInodes,
		)
		if !ok {
			return ErrStorageEnvelope
		}
		envelope := mounts[filesystem.MountID]
		envelope.requiredBytes, ok = addStorageAmount(
			envelope.requiredBytes,
			requiredBytes,
		)
		if !ok {
			return ErrStorageEnvelope
		}
		envelope.requiredInodes, ok = addStorageAmount(
			envelope.requiredInodes,
			requiredInodes,
		)
		if !ok {
			return ErrStorageEnvelope
		}
		mounts[filesystem.MountID] = envelope
		roleMounts[filesystem.Role] = filesystem.MountID
	}
	for _, orphan := range reservation.CrashOrphans {
		mountID, ok := roleMounts[orphan.FilesystemRole]
		if !ok {
			return ErrStorageEnvelope
		}
		envelope := mounts[mountID]
		envelope.requiredBytes, ok = addStorageAmount(
			envelope.requiredBytes,
			orphan.Bytes,
		)
		if !ok {
			return ErrStorageEnvelope
		}
		envelope.requiredInodes, ok = addStorageAmount(
			envelope.requiredInodes,
			orphan.Inodes,
		)
		if !ok {
			return ErrStorageEnvelope
		}
		mounts[mountID] = envelope
	}

	for _, expected := range reservation.Filesystems {
		if ctx.Err() != nil {
			return ErrStorageEnvelope
		}
		observation, err := authority.probe.Observe(ctx, expected)
		if err != nil ||
			observation.Filesystem != expected ||
			observation.FreeBytes == 0 ||
			observation.FreeInodes == 0 {
			return ErrStorageEnvelope
		}
		envelope := mounts[expected.MountID]
		if envelope.observed &&
			(envelope.freeBytes != observation.FreeBytes ||
				envelope.freeInodes != observation.FreeInodes) {
			return ErrStorageEnvelope
		}
		envelope.freeBytes = observation.FreeBytes
		envelope.freeInodes = observation.FreeInodes
		envelope.observed = true
		mounts[expected.MountID] = envelope
	}
	for _, envelope := range mounts {
		if !envelope.observed ||
			envelope.freeBytes < envelope.requiredBytes ||
			envelope.freeInodes < envelope.requiredInodes {
			return ErrStorageEnvelope
		}
	}
	return nil
}

func addStorageAmount(left uint64, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}

var _ hostruntime.LifecycleStorageAuthority = (*ReservationStorageAuthority)(nil)
