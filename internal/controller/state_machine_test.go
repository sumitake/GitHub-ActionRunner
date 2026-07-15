package controller

import "testing"

// orderedStatesForTest mirrors the fixed happy-path order documented on the
// State constants. Tests iterate this slice directly (rather than relying
// on an unexported symbol from state_machine.go) so the test file states
// its own expectation of the order independently of the implementation.
var orderedStatesForTest = []State{
	StateReceived,
	StateCapacityReserved,
	StateAdapterCreated,
	StateAdapterVerified,
	StateBrokerHeld,
	StateBrokerPolicyApplied,
	StateDialAuthorityReady,
	StateBrokerReleased,
	StateEgressVerified,
	StateRunnerHeld,
	StateReleaseArmed,
	StateListenerReleased,
	StateJobRunning,
	StateJobFinished,
	StateDestroyed,
}

// releaseBoundaryIndex is the index of StateListenerReleased within
// orderedStatesForTest: the "point of no return" per the plan. States at or
// after this index are post-release; states before it are pre-release.
const releaseBoundaryIndex = 11

// TestStateTransitionAdjacentLegalOrder proves every adjacent step in the
// fixed 15-state happy path is legal, in exact external-effect order, for
// both the pre-release (released=false) and post-release (released=true)
// legs.
func TestStateTransitionAdjacentLegalOrder(t *testing.T) {
	for i := 0; i < len(orderedStatesForTest)-1; i++ {
		current := orderedStatesForTest[i]
		next := orderedStatesForTest[i+1]
		released := i+1 >= releaseBoundaryIndex // released once next has crossed the boundary
		t.Run(string(current)+"->"+string(next), func(t *testing.T) {
			if err := Transition(current, next, released); err != nil {
				t.Fatalf("Transition(%s, %s, released=%v) = %v, want nil", current, next, released, err)
			}
		})
	}
}

// TestStateTransitionIdempotentReplay proves re-applying the same
// transition (current == next) is a no-op success for every state, not an
// error -- required so a crash-and-replay of the last completed effect
// never fails the reconciler.
func TestStateTransitionIdempotentReplay(t *testing.T) {
	for _, s := range orderedStatesForTest {
		for _, released := range []bool{true, false} {
			t.Run(string(s), func(t *testing.T) {
				if err := Transition(s, s, released); err != nil {
					t.Fatalf("Transition(%s, %s, released=%v) = %v, want nil (idempotent replay)", s, s, released, err)
				}
			})
		}
	}
}

// TestStateTransitionPreReleaseFailureToDestroyed proves every pre-release
// checkpoint (RECEIVED through RELEASE_ARMED) may transition directly to
// DESTROYED when released=false: nothing external is committed to a
// running job yet, so tearing down from any of these checkpoints is safe.
func TestStateTransitionPreReleaseFailureToDestroyed(t *testing.T) {
	for i := 0; i < releaseBoundaryIndex; i++ {
		current := orderedStatesForTest[i]
		t.Run(string(current), func(t *testing.T) {
			if err := Transition(current, StateDestroyed, false); err != nil {
				t.Fatalf("Transition(%s, DESTROYED, released=false) = %v, want nil", current, err)
			}
		})
	}
}

// TestStateTransitionPostReleaseDirectDestroyRejected proves that once
// released=true, a failure must NOT re-trigger release/destroy blindly: a
// direct jump to DESTROYED that skips JOB_RUNNING/JOB_FINISHED is illegal
// for every post-release state except the one already-adjacent step
// (JOB_FINISHED -> DESTROYED, covered by the adjacent-order test). This is
// what prevents a duplicate listener release after ambiguity -- resolution
// must go through MarkAmbiguous (internal/state), never a direct
// post-release destroy.
func TestStateTransitionPostReleaseDirectDestroyRejected(t *testing.T) {
	for i := releaseBoundaryIndex; i < len(orderedStatesForTest)-1; i++ {
		current := orderedStatesForTest[i]
		if current == StateJobFinished {
			continue // JOB_FINISHED -> DESTROYED is the legal adjacent step
		}
		t.Run(string(current), func(t *testing.T) {
			if err := Transition(current, StateDestroyed, true); err == nil {
				t.Fatalf("Transition(%s, DESTROYED, released=true) = nil, want error (no blind post-release destroy)", current)
			}
		})
	}
}

// TestStateTransitionRejectsSkippedStates proves every non-adjacent
// forward jump in the happy-path order is illegal. Jumps whose target is
// StateDestroyed are excluded here: with released=false those are the
// legal pre-release failure shortcut covered by
// TestStateTransitionPreReleaseFailureToDestroyed, not an illegal skip.
func TestStateTransitionRejectsSkippedStates(t *testing.T) {
	for i := 0; i < len(orderedStatesForTest); i++ {
		for j := i + 2; j < len(orderedStatesForTest); j++ {
			current := orderedStatesForTest[i]
			next := orderedStatesForTest[j]
			if next == StateDestroyed {
				continue
			}
			t.Run(string(current)+"->"+string(next), func(t *testing.T) {
				if err := Transition(current, next, false); err == nil {
					t.Fatalf("Transition(%s, %s, released=false) = nil, want error (skipped state)", current, next)
				}
			})
		}
	}
}

// TestStateTransitionRejectsReversedStates proves every backward move is
// illegal, both pre- and post-release.
func TestStateTransitionRejectsReversedStates(t *testing.T) {
	for i := 1; i < len(orderedStatesForTest); i++ {
		for j := 0; j < i; j++ {
			current := orderedStatesForTest[i]
			next := orderedStatesForTest[j]
			released := i >= releaseBoundaryIndex
			t.Run(string(current)+"->"+string(next), func(t *testing.T) {
				if err := Transition(current, next, released); err == nil {
					t.Fatalf("Transition(%s, %s, released=%v) = nil, want error (reversed state)", current, next, released)
				}
			})
		}
	}
}

// TestStateTransitionUnknownStateRejected proves an unrecognized state
// value on either side is rejected rather than silently accepted.
func TestStateTransitionUnknownStateRejected(t *testing.T) {
	const bogus State = "NOT_A_REAL_STATE"

	if err := Transition(bogus, StateCapacityReserved, false); err == nil {
		t.Fatal("Transition(bogus current, ...) = nil, want error")
	}
	if err := Transition(StateReceived, bogus, false); err == nil {
		t.Fatal("Transition(..., bogus next, ...) = nil, want error")
	}
}
