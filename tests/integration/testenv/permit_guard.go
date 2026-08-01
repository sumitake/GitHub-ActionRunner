package testenv

import (
	"context"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

type permitPeerIdentity struct {
	PID       int
	UID       uint32
	StartTime uint64
}

type permitPeerProcessObservation struct {
	UID       uint32
	StartTime uint64
}

type permitPeerProcessObserver interface {
	ObservePermitPeerProcess(
		context.Context,
		int,
	) (permitPeerProcessObservation, error)
}

type compositionPermitPeerGuard struct {
	slot       networkjail.CapacitySlotID
	generation networkjail.JobGeneration
	uid        uint32
	observer   permitPeerProcessObserver
}

func newCompositionPermitPeerGuard(
	plan compositionPlan,
	brokerUser string,
	observer permitPeerProcessObserver,
) (*compositionPermitPeerGuard, error) {
	uid, _, ok := parseStaticNumericUser(brokerUser)
	if !ok || uid == 0 || observer == nil ||
		plan.Identity.CapacitySlotID == 0 ||
		plan.Identity.JobGeneration == 0 {
		return nil, ErrFixtureStart
	}
	return &compositionPermitPeerGuard{
		slot: networkjail.CapacitySlotID(
			plan.Identity.CapacitySlotID,
		),
		generation: networkjail.JobGeneration(
			plan.Identity.JobGeneration,
		),
		uid:      uint32(uid),
		observer: observer,
	}, nil
}

func (g *compositionPermitPeerGuard) ValidatePermitPeer(
	ctx context.Context,
	slot networkjail.CapacitySlotID,
	generation networkjail.JobGeneration,
	class networkjail.DialClass,
	peer networkjail.PermitPeer,
) error {
	return g.validate(ctx, slot, generation, class, permitPeerIdentity{
		PID:       peer.PID(),
		UID:       peer.UID(),
		StartTime: peer.StartTime(),
	})
}

func (g *compositionPermitPeerGuard) validate(
	ctx context.Context,
	slot networkjail.CapacitySlotID,
	generation networkjail.JobGeneration,
	class networkjail.DialClass,
	peer permitPeerIdentity,
) error {
	if g == nil || ctx == nil || ctx.Err() != nil ||
		g.slot == 0 || g.generation == 0 || g.uid == 0 ||
		g.observer == nil ||
		slot != g.slot || generation != g.generation ||
		(class != networkjail.DialClassJob &&
			class != networkjail.DialClassDoH) ||
		peer.PID <= 0 || peer.UID != g.uid ||
		peer.StartTime == 0 {
		return networkjail.ErrPermitPeerInvalid
	}
	observation, err := g.observer.ObservePermitPeerProcess(
		ctx,
		peer.PID,
	)
	if err != nil ||
		observation.UID != g.uid ||
		observation.UID != peer.UID ||
		observation.StartTime == 0 ||
		observation.StartTime != peer.StartTime {
		return networkjail.ErrPermitPeerInvalid
	}
	return nil
}

type compositionLedgerReferenceGuard struct {
	store *state.SQLiteStore
	slot  networkjail.CapacitySlotID
	key   controller.AssignmentKey
}

func newCompositionLedgerReferenceGuard(
	store *state.SQLiteStore,
	plan compositionPlan,
) (*compositionLedgerReferenceGuard, error) {
	if store == nil || store.DB() == nil ||
		plan.Identity.CapacitySlotID == 0 ||
		plan.AssignmentKey.RepositoryAlias == "" ||
		plan.AssignmentKey.RunnerRequestID <= 0 ||
		plan.AssignmentKey.Attempt != 0 {
		return nil, ErrFixtureStart
	}
	return &compositionLedgerReferenceGuard{
		store: store,
		slot: networkjail.CapacitySlotID(
			plan.Identity.CapacitySlotID,
		),
		key: plan.AssignmentKey,
	}, nil
}

func (g *compositionLedgerReferenceGuard) HasLedgerReferences(
	ctx context.Context,
	slot networkjail.CapacitySlotID,
) (bool, error) {
	if g == nil || g.store == nil || g.store.DB() == nil ||
		ctx == nil || ctx.Err() != nil ||
		slot == 0 || slot != g.slot {
		return false, networkjail.ErrPermitAuthorityUnavailable
	}
	recoverable, err := g.store.ListRecoverable(ctx)
	if err != nil {
		return false, networkjail.ErrPermitAuthorityUnavailable
	}
	var found bool
	for _, assignment := range recoverable {
		assignmentSlot := networkjail.CapacitySlotID(
			assignment.Slot.CapacitySlotID,
		)
		if assignment.Key == g.key {
			if assignmentSlot != g.slot {
				return false,
					networkjail.ErrPermitAuthorityUnavailable
			}
			found = true
			continue
		}
		if assignmentSlot == g.slot {
			return false, networkjail.ErrPermitAuthorityUnavailable
		}
	}
	return found, nil
}

type rejectCompositionRebase struct{}

func (rejectCompositionRebase) ValidateEmptyConntrack(
	context.Context,
	networkjail.CapacitySlotID,
	networkjail.BootID,
	networkjail.BootID,
	networkjail.EmptyConntrackProof,
) error {
	return networkjail.ErrEmptyConntrackProofInvalid
}

var _ networkjail.PermitPeerValidator = (*compositionPermitPeerGuard)(nil)
var _ networkjail.LedgerReferenceGuard = (*compositionLedgerReferenceGuard)(nil)
var _ networkjail.EmptyConntrackValidator = rejectCompositionRebase{}
