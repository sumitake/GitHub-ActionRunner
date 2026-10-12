package testenv

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

type fakePermitPeerProcessObserver struct {
	observation permitPeerProcessObservation
	err         error
}

func (o fakePermitPeerProcessObserver) ObservePermitPeerProcess(
	context.Context,
	int,
) (permitPeerProcessObservation, error) {
	return o.observation, o.err
}

func TestCompositionPermitPeerGuardBindsAssignmentClassAndProcess(
	t *testing.T,
) {
	t.Parallel()

	guard := compositionPermitPeerGuard{
		slot:       17,
		generation: 29,
		uid:        1001,
		observer: fakePermitPeerProcessObserver{
			observation: permitPeerProcessObservation{
				UID:       1001,
				StartTime: 7001,
			},
		},
	}
	peer := permitPeerIdentity{PID: 71, UID: 1001, StartTime: 7001}
	for _, class := range []networkjail.DialClass{
		networkjail.DialClassJob,
		networkjail.DialClassDoH,
	} {
		if err := guard.validate(
			context.Background(),
			17,
			29,
			class,
			peer,
		); err != nil {
			t.Fatalf("class %d: %v", class, err)
		}
	}
	tests := map[string]func(
		*compositionPermitPeerGuard,
		*networkjail.CapacitySlotID,
		*networkjail.JobGeneration,
		*networkjail.DialClass,
		*permitPeerIdentity,
	){
		"slot": func(
			_ *compositionPermitPeerGuard,
			value *networkjail.CapacitySlotID,
			_ *networkjail.JobGeneration,
			_ *networkjail.DialClass,
			_ *permitPeerIdentity,
		) {
			*value = 18
		},
		"generation": func(
			_ *compositionPermitPeerGuard,
			_ *networkjail.CapacitySlotID,
			value *networkjail.JobGeneration,
			_ *networkjail.DialClass,
			_ *permitPeerIdentity,
		) {
			*value = 30
		},
		"class": func(
			_ *compositionPermitPeerGuard,
			_ *networkjail.CapacitySlotID,
			_ *networkjail.JobGeneration,
			value *networkjail.DialClass,
			_ *permitPeerIdentity,
		) {
			*value = 0
		},
		"peer uid": func(
			_ *compositionPermitPeerGuard,
			_ *networkjail.CapacitySlotID,
			_ *networkjail.JobGeneration,
			_ *networkjail.DialClass,
			value *permitPeerIdentity,
		) {
			value.UID++
		},
		"peer start time": func(
			_ *compositionPermitPeerGuard,
			_ *networkjail.CapacitySlotID,
			_ *networkjail.JobGeneration,
			_ *networkjail.DialClass,
			value *permitPeerIdentity,
		) {
			value.StartTime++
		},
		"observed uid": func(
			value *compositionPermitPeerGuard,
			_ *networkjail.CapacitySlotID,
			_ *networkjail.JobGeneration,
			_ *networkjail.DialClass,
			_ *permitPeerIdentity,
		) {
			value.observer = fakePermitPeerProcessObserver{
				observation: permitPeerProcessObservation{
					UID:       1002,
					StartTime: 7001,
				},
			}
		},
		"observed start time": func(
			value *compositionPermitPeerGuard,
			_ *networkjail.CapacitySlotID,
			_ *networkjail.JobGeneration,
			_ *networkjail.DialClass,
			_ *permitPeerIdentity,
		) {
			value.observer = fakePermitPeerProcessObserver{
				observation: permitPeerProcessObservation{
					UID:       1001,
					StartTime: 7002,
				},
			}
		},
		"observer error": func(
			value *compositionPermitPeerGuard,
			_ *networkjail.CapacitySlotID,
			_ *networkjail.JobGeneration,
			_ *networkjail.DialClass,
			_ *permitPeerIdentity,
		) {
			value.observer = fakePermitPeerProcessObserver{
				err: errors.New("closed observer failure"),
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := guard
			slot := networkjail.CapacitySlotID(17)
			generation := networkjail.JobGeneration(29)
			class := networkjail.DialClassJob
			candidatePeer := peer
			mutate(
				&candidate,
				&slot,
				&generation,
				&class,
				&candidatePeer,
			)
			if err := candidate.validate(
				context.Background(),
				slot,
				generation,
				class,
				candidatePeer,
			); !errors.Is(err, networkjail.ErrPermitPeerInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCompositionLedgerReferenceGuardBindsExactRecoverableSlot(
	t *testing.T,
) {
	t.Parallel()

	input, overlay := validCompositionPlanInputs()
	plan, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	store, err := state.OpenWithHistoryLimits(
		filepath.Join(t.TempDir(), "controller.db"),
		plan.HistoryLimits,
	)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := seedCompositionAssignment(
		context.Background(),
		store,
		plan,
		time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("seedCompositionAssignment: %v", err)
	}
	guard, err := newCompositionLedgerReferenceGuard(store, plan)
	if err != nil {
		t.Fatalf("newCompositionLedgerReferenceGuard: %v", err)
	}
	referenced, err := guard.HasLedgerReferences(
		context.Background(),
		networkjail.CapacitySlotID(plan.Identity.CapacitySlotID),
	)
	if err != nil || !referenced {
		t.Fatalf("referenced/error = %t/%v", referenced, err)
	}
	if _, err := guard.HasLedgerReferences(
		context.Background(),
		networkjail.CapacitySlotID(plan.Identity.CapacitySlotID+1),
	); !errors.Is(err, networkjail.ErrPermitAuthorityUnavailable) {
		t.Fatalf("mismatched slot error = %v", err)
	}
}
