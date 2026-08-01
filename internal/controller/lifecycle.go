package controller

import (
	"errors"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

var ErrLifecycleAssignment = errors.New("controller: lifecycle assignment invalid")

// Assignment is the already-durable input to the one-job lifecycle. It carries
// no runtime handle, credential, JIT value, path, or caller-selected Docker
// option.
type Assignment struct {
	Key   AssignmentKey
	Offer githubscale.Offer
	Slot  RunnerSlot
}

func NewAssignment(
	key AssignmentKey,
	offer githubscale.Offer,
	slot RunnerSlot,
) (Assignment, error) {
	assignment := Assignment{Key: key, Offer: offer, Slot: slot}
	assignment.Offer.RequestLabels = append([]string(nil), offer.RequestLabels...)
	if err := assignment.Validate(); err != nil {
		return Assignment{}, err
	}
	return assignment, nil
}

func (assignment Assignment) Validate() error {
	if assignment.Key.RepositoryAlias == "" ||
		assignment.Key.RunnerRequestID <= 0 ||
		assignment.Offer.RunnerRequestID != assignment.Key.RunnerRequestID ||
		assignment.Offer.JobID == "" ||
		assignment.Slot.OpaqueName != OpaqueSlotName(assignment.Key) ||
		assignment.Slot.CapacitySlotID == 0 {
		return ErrLifecycleAssignment
	}
	return nil
}

// CycleReceipt is emitted only after one complete successful reconciliation
// cycle. It contains aggregate timing/count evidence and no assignment
// identity.
type CycleReceipt struct {
	CycleID         string
	CompletedAt     time.Time
	AssignmentCount int
	OldestAge       time.Duration
}

// PostReleaseOutcome is the closed set of outcomes a two-sided read-back may
// persist for an ambiguous listener release.
type PostReleaseOutcome uint8

const (
	PostReleaseListenerReleased PostReleaseOutcome = iota + 1
	PostReleaseJobRunning
	PostReleaseJobFinished
	PostReleaseDestroyed
)
