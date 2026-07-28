//go:build linux

package networkjail

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const linuxBootIDPath = "/proc/sys/kernel/random/boot_id"

type SystemMonotonicClock struct {
	mu           sync.Mutex
	bootID       BootID
	lastObserved uint64
}

func NewSystemMonotonicClock() (*SystemMonotonicClock, error) {
	clock := &SystemMonotonicClock{}
	if _, err := clock.Observe(context.Background()); err != nil {
		return nil, ErrPermitAuthorityUnavailable
	}
	return clock, nil
}

func (clock *SystemMonotonicClock) Observe(
	ctx context.Context,
) (ClockObservation, error) {
	if err := ctx.Err(); err != nil {
		return ClockObservation{}, err
	}
	bootID, err := readLinuxBootID(linuxBootIDPath)
	if err != nil {
		return ClockObservation{}, ErrPermitAuthorityUnavailable
	}
	var timespec unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &timespec); err != nil ||
		timespec.Sec < 0 || timespec.Nsec < 0 ||
		timespec.Nsec >= int64(nanosPerSecond) {
		return ClockObservation{}, ErrPermitAuthorityUnavailable
	}
	seconds := uint64(timespec.Sec)
	if seconds > (^uint64(0)-uint64(timespec.Nsec))/nanosPerSecond {
		return ClockObservation{}, ErrPermitArithmetic
	}
	monotonic := seconds*nanosPerSecond + uint64(timespec.Nsec)
	observation := ClockObservation{
		BootID:         bootID,
		MonotonicNanos: monotonic,
	}
	if err := observation.validate(); err != nil {
		return ClockObservation{}, err
	}

	clock.mu.Lock()
	defer clock.mu.Unlock()
	if clock.bootID != (BootID{}) && clock.bootID != bootID {
		return ClockObservation{}, ErrBootRebaseRequired
	}
	if monotonic < clock.lastObserved {
		return ClockObservation{}, ErrMonotonicClockRegression
	}
	clock.bootID = bootID
	clock.lastObserved = monotonic
	return observation, nil
}

func readLinuxBootID(path string) (BootID, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return BootID{}, err
	}
	value := string(raw)
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if strings.ContainsAny(value, "\r\n\t ") {
		return BootID{}, errors.New("networkjail: boot identity invalid")
	}
	return ParseBootID(value)
}

var _ MonotonicClock = (*SystemMonotonicClock)(nil)
