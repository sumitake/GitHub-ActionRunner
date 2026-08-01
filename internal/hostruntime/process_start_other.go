//go:build !linux

package hostruntime

func ObserveLinuxProcessStartIdentity(
	uint64,
) (ProcessStartObservation, string, error) {
	return ProcessStartObservation{}, "", ErrProcessIdentityUnavailable
}
