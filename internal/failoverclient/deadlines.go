package failoverclient

import (
	"fmt"
	"time"
)

func OperationDeadline(now, leaseDeadline time.Time, callDuration, tail time.Duration) (time.Time, error) {
	if now.IsZero() || leaseDeadline.IsZero() || callDuration <= 0 || tail <= 0 {
		return time.Time{}, fmt.Errorf("%w: deadline terms", ErrLease)
	}
	safeLease := leaseDeadline.Add(-tail)
	if !now.Before(safeLease) {
		return time.Time{}, fmt.Errorf("%w: insufficient slack", ErrLease)
	}
	callEnd := now.Add(callDuration)
	if callEnd.Before(safeLease) {
		return callEnd, nil
	}
	return safeLease, nil
}

func ListenerAuthorized(
	now, localDeadline time.Time,
	session string,
	generation uint64,
	currentSession string,
	currentGeneration uint64,
) bool {
	if now.IsZero() || localDeadline.IsZero() || session == "" || currentSession == "" {
		return false
	}
	if session != currentSession || generation != currentGeneration {
		return false
	}
	return now.Before(localDeadline)
}
