package controller

import "fmt"

// orderedStates is the fixed happy-path sequence every assignment moves
// through. Transition validates the happy-path leg purely from each
// state's position in this list.
var orderedStates = []State{
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

// stateIndex maps each state to its position in orderedStates.
var stateIndex = func() map[State]int {
	m := make(map[State]int, len(orderedStates))
	for i, s := range orderedStates {
		m[s] = i
	}
	return m
}()

// HasReleasedListener reports whether s is at or after the
// StateListenerReleased "point of no return" boundary in the fixed
// happy-path order (see Transition's doc). This is the single source of
// truth for that boundary: callers outside this package -- notably
// internal/state.Store.Advance, which must derive the released invariant
// from an assignment's persisted state rather than trust a caller-supplied
// flag -- use this instead of duplicating orderedStates' ordering. An
// unrecognized state reports false (it cannot be at/after a boundary it
// isn't ordered relative to); Transition is what rejects unknown states
// outright.
func HasReleasedListener(s State) bool {
	i, ok := stateIndex[s]
	if !ok {
		return false
	}
	return i >= stateIndex[StateListenerReleased]
}

// Transition reports whether moving an assignment from current to next is
// legal, given released -- whether the assignment has already passed the
// StateListenerReleased "point of no return" boundary. It never mutates
// anything; callers (internal/state.Store) persist the result.
//
// Three shapes of transition are legal:
//
//  1. Idempotent replay: current == next is always a no-op success,
//     regardless of released. Re-applying the last completed effect after
//     a crash-and-restart must never fail the reconciler.
//  2. The happy-path adjacent step: next is the very next state after
//     current in the fixed 15-state order. This covers both legs --
//     pre-release states advancing toward StateListenerReleased, and the
//     post-release leg StateListenerReleased -> StateJobRunning ->
//     StateJobFinished -> StateDestroyed -- because each of those is
//     itself an adjacent step.
//  3. Pre-release failure to StateDestroyed: when released is false, any
//     current state may transition directly to StateDestroyed, because
//     nothing external has been committed to a running job yet and
//     tearing down is safe. This shortcut does NOT apply once released is
//     true: a post-release failure must never re-trigger a blind
//     destroy (which could mean a second, duplicate listener release, or
//     abandoning a job that is actually still running) -- that ambiguity
//     is resolved by reconciliation, not by Transition (see
//     internal/state.Store.MarkAmbiguous).
//
// Every other combination -- skipping ahead, moving backward, or a
// post-release jump straight to StateDestroyed that isn't the single
// legal adjacent step from StateJobFinished -- is rejected.
func Transition(current, next State, released bool) error {
	ci, ok := stateIndex[current]
	if !ok {
		return fmt.Errorf("controller: unknown current state %q", current)
	}
	ni, ok := stateIndex[next]
	if !ok {
		return fmt.Errorf("controller: unknown next state %q", next)
	}

	if current == next {
		return nil
	}

	if ni == ci+1 {
		return nil
	}

	if next == StateDestroyed && !released {
		return nil
	}

	return fmt.Errorf("controller: illegal transition from %q to %q (released=%v)", current, next, released)
}
