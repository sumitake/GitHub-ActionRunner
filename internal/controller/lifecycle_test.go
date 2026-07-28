package controller

import (
	"testing"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func TestNewAssignmentAcceptsInitialAttemptZero(t *testing.T) {
	key := AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: 41,
		Attempt:         0,
	}
	assignment, err := NewAssignment(
		key,
		githubscale.Offer{JobRef: githubscale.JobRef{
			RunnerRequestID: key.RunnerRequestID,
			JobID:           "job-a",
		}},
		RunnerSlot{
			OpaqueName:     OpaqueSlotName(key),
			CapacitySlotID: 1,
		},
	)
	if err != nil {
		t.Fatalf("NewAssignment(initial attempt zero) = %v", err)
	}
	if assignment.Key != key {
		t.Fatalf("assignment key = %+v, want %+v", assignment.Key, key)
	}
}
