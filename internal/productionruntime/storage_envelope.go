package productionruntime

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

var ErrStorageEnvelope = errors.New(
	"productionruntime: storage envelope failed",
)

type StorageAvailability struct {
	Filesystem hostruntime.LifecycleFilesystemIdentity
	Device     uint64
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
		if !envelope.observed {
			envelope.freeBytes = observation.FreeBytes
			envelope.freeInodes = observation.FreeInodes
			envelope.observed = true
		} else {
			envelope.freeBytes = minStorageAmount(
				envelope.freeBytes,
				observation.FreeBytes,
			)
			envelope.freeInodes = minStorageAmount(
				envelope.freeInodes,
				observation.FreeInodes,
			)
		}
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

func minStorageAmount(left uint64, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func addStorageAmount(left uint64, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}

// BuildStorageReservation binds one validated overlay and runtime manifest to
// a fresh, complete live filesystem snapshot. The warning reserve is retained
// as compensation headroom so the disabled watchdog stops before the tighter
// stop boundary rather than trying to implement a second capacity controller.
func BuildStorageReservation(
	binding hostruntime.OperationBinding,
	overlay hostruntime.PrivateOverlay,
	manifest hostruntime.RuntimeManifest,
	availability []StorageAvailability,
	now time.Time,
) (hostruntime.StorageReservation, error) {
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		return hostruntime.StorageReservation{}, ErrStorageEnvelope
	}
	_, overlayRevision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil || overlayRevision != binding.PrivateOverlayRevision {
		return hostruntime.StorageReservation{}, ErrStorageEnvelope
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil ||
		manifestDigest != overlay.Manifest.Digest ||
		!bindingContainsManifest(binding, manifestDigest) {
		return hostruntime.StorageReservation{}, ErrStorageEnvelope
	}
	_, offset := now.Zone()
	if now.IsZero() || offset != 0 ||
		len(availability) != len(overlay.Resources.Storage.Observations) ||
		len(availability) != len(overlay.Resources.Storage.Requirements) {
		return hostruntime.StorageReservation{}, ErrStorageEnvelope
	}

	filesystems := make(
		[]hostruntime.LifecycleFilesystemIdentity,
		0,
		len(availability),
	)
	roles := make(
		[]hostruntime.StorageRoleReservation,
		0,
		len(availability),
	)
	for index, live := range availability {
		observation := overlay.Resources.Storage.Observations[index]
		requirement := overlay.Resources.Storage.Requirements[index]
		if live.Filesystem.Role != observation.Role ||
			requirement.Role != observation.Role ||
			live.Device != observation.Device ||
			live.Filesystem.RootInode != observation.Inode ||
			live.FreeBytes == 0 ||
			live.FreeInodes == 0 {
			return hostruntime.StorageReservation{}, ErrStorageEnvelope
		}
		slotBytes, ok := multiplyStorageAmount(
			overlay.Resources.Storage.MaximumActiveConcurrency,
			requirement.PerSlotBytes,
		)
		if !ok {
			return hostruntime.StorageReservation{}, ErrStorageEnvelope
		}
		slotInodes, ok := multiplyStorageAmount(
			overlay.Resources.Storage.MaximumActiveConcurrency,
			requirement.PerSlotInodes,
		)
		if !ok {
			return hostruntime.StorageReservation{}, ErrStorageEnvelope
		}
		requiredBytes, ok := sumStorageAmounts(
			requirement.CurrentReleaseBytes,
			requirement.CandidateReleaseBytes,
			requirement.ExtractionBytes,
			requirement.RollbackBytes,
			slotBytes,
			requirement.HelperBytes,
			requirement.RelayBytes,
			requirement.ControllerBytes,
			requirement.LedgerBytes,
			requirement.LogBytes,
			requirement.HostReserveBytes,
		)
		if !ok {
			return hostruntime.StorageReservation{}, ErrStorageEnvelope
		}
		requiredInodes, ok := sumStorageAmounts(
			requirement.CurrentReleaseInodes,
			requirement.CandidateReleaseInodes,
			requirement.ExtractionInodes,
			requirement.RollbackInodes,
			slotInodes,
			requirement.HelperInodes,
			requirement.RelayInodes,
			requirement.ControllerInodes,
			requirement.LedgerInodes,
			requirement.LogInodes,
			requirement.HostReserveInodes,
		)
		if !ok {
			return hostruntime.StorageReservation{}, ErrStorageEnvelope
		}
		filesystems = append(filesystems, live.Filesystem)
		roles = append(roles, hostruntime.StorageRoleReservation{
			Role:               live.Filesystem.Role,
			MountID:            live.Filesystem.MountID,
			RequiredBytes:      requiredBytes,
			RequiredInodes:     requiredInodes,
			CompensationBytes:  requirement.WarningReserveBytes,
			CompensationInodes: requirement.WarningReserveInodes,
			ObservedFreeBytes:  live.FreeBytes,
			ObservedFreeInodes: live.FreeInodes,
		})
	}
	targetManifestDigest := cloneStorageDigest(
		binding.TargetManifestDigest,
	)
	reservation := hostruntime.StorageReservation{
		SchemaVersion:              1,
		OperationID:                binding.OperationID,
		BindingDigest:              bindingDigest,
		State:                      hostruntime.ReservationStateActive,
		StorageBudgetDigest:        manifest.StorageBudgetDigest,
		TargetManifestDigest:       targetManifestDigest,
		Filesystems:                filesystems,
		Roles:                      roles,
		CrashOrphans:               []hostruntime.CrashOrphanReservation{},
		CommittedTargetProofDigest: nil,
		ReleasedAbsenceProofDigest: nil,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}
	if _, _, err := hostruntime.MarshalStorageReservation(
		reservation,
	); err != nil {
		return hostruntime.StorageReservation{}, ErrStorageEnvelope
	}
	return reservation, nil
}

func bindingContainsManifest(
	binding hostruntime.OperationBinding,
	digest string,
) bool {
	return binding.PriorManifestDigest != nil &&
		*binding.PriorManifestDigest == digest ||
		binding.TargetManifestDigest != nil &&
			*binding.TargetManifestDigest == digest
}

func multiplyStorageAmount(left uint64, right uint64) (uint64, bool) {
	if left == 0 || right == 0 || left > math.MaxUint64/right {
		return 0, false
	}
	return left * right, true
}

func sumStorageAmounts(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		var ok bool
		total, ok = addStorageAmount(total, value)
		if !ok {
			return 0, false
		}
	}
	return total, total != 0
}

func cloneStorageDigest(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

var _ hostruntime.LifecycleStorageAuthority = (*ReservationStorageAuthority)(nil)
