package fleetfence

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"reflect"

	"github.com/sumitake/portable-ghar/internal/controller"
)

var ErrLegacyObserverUnavailable = errors.New(
	"fleetfence: legacy observer normalization unavailable",
)

type Inspector interface {
	Inspect(context.Context) (Snapshot, error)
}

type LegacyObserverProof struct {
	FleetGeneration uint64
	PolicyEpoch     uint64
	PolicyDigest    string
}

func NormalizeLegacyObserver(
	ctx context.Context,
	inspector Inspector,
	transitions controller.AcquisitionTransitioner,
) (LegacyObserverProof, error) {
	if inspector == nil || transitions == nil {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	beforeFence, err := inspector.Inspect(ctx)
	if err != nil ||
		beforeFence.Header.ActiveFleet != FleetLegacy ||
		beforeFence.Header.Generation == 0 {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	current, err := transitions.Snapshot(ctx)
	if err != nil || current.Epoch == math.MaxUint64 {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	current, err = controller.CanonicalizeAcquisitionPolicy(current)
	if err != nil {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	next := current
	next.Mode = controller.AcquisitionDisabled
	next.MaxCapacity = 0
	next.EligibleScaleSets = nil
	persisted, err := transitions.Transition(ctx, current.Epoch, next)
	if err != nil {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	persisted, err = controller.CanonicalizeAcquisitionPolicy(persisted)
	if err != nil ||
		persisted.Epoch != current.Epoch+1 ||
		persisted.Mode != controller.AcquisitionDisabled ||
		persisted.MaxCapacity != 0 ||
		len(persisted.EligibleScaleSets) != 0 {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	afterFence, err := inspector.Inspect(ctx)
	if err != nil ||
		afterFence.Header.ActiveFleet != FleetLegacy ||
		afterFence.Header.Generation != beforeFence.Header.Generation {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	readBack, err := transitions.Snapshot(ctx)
	if err != nil {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	readBack, err = controller.CanonicalizeAcquisitionPolicy(readBack)
	if err != nil || !reflect.DeepEqual(readBack, persisted) {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	digest, err := controller.AcquisitionPolicyDigest(readBack)
	if err != nil {
		return LegacyObserverProof{}, ErrLegacyObserverUnavailable
	}
	return LegacyObserverProof{
		FleetGeneration: afterFence.Header.Generation,
		PolicyEpoch:     readBack.Epoch,
		PolicyDigest:    hex.EncodeToString(digest[:]),
	}, nil
}
