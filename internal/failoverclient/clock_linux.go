//go:build linux

package failoverclient

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

type linuxBoottimeClock struct{}

func NewProductionAuthorityClock() (AuthorityClock, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return nil, fmt.Errorf("%w: boottime", ErrAuthorityClock)
	}
	return linuxBoottimeClock{}, nil
}

func (linuxBoottimeClock) Capable() bool { return true }

func (linuxBoottimeClock) Now() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil || ts.Sec < 0 || ts.Nsec < 0 {
		return time.Time{}, fmt.Errorf("%w: now", ErrAuthorityClock)
	}
	return time.Unix(ts.Sec, ts.Nsec), nil
}

func (clock linuxBoottimeClock) WaitUntil(ctx context.Context, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now, err := clock.Now()
		if err != nil {
			return err
		}
		if !now.Before(deadline) {
			return context.DeadlineExceeded
		}
		remaining := deadline.Sub(now)
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
