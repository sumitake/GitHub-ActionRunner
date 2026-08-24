//go:build linux

package failoverclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const linuxClockProbeTimeoutMilliseconds = 250

var linuxBoottimeLocation = time.FixedZone("CLOCK_BOOTTIME", 0)

type linuxBoottimeClock struct{}

func NewProductionAuthorityClock() (AuthorityClock, error) {
	if err := probeLinuxBoottimeClock(); err != nil {
		return nil, err
	}
	return linuxBoottimeClock{}, nil
}

func (linuxBoottimeClock) Capable() bool { return true }

func (linuxBoottimeClock) Now() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil || !validLinuxTimespec(ts) {
		return time.Time{}, fmt.Errorf("%w: now", ErrAuthorityClock)
	}
	return time.Unix(ts.Sec, ts.Nsec).In(linuxBoottimeLocation), nil
}

func (linuxBoottimeClock) WaitUntil(ctx context.Context, deadline time.Time) (result error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return fmt.Errorf("%w: missing context", ErrAuthorityClock)
		}
		return ctx.Err()
	}
	if deadline.IsZero() || deadline.Location() != linuxBoottimeLocation {
		return fmt.Errorf("%w: deadline domain", ErrAuthorityClock)
	}
	deadlineSpec := unix.Timespec{Sec: deadline.Unix(), Nsec: int64(deadline.Nanosecond())}
	if !validLinuxTimespec(deadlineSpec) {
		return fmt.Errorf("%w: deadline", ErrAuthorityClock)
	}

	timerFD, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return fmt.Errorf("%w: timerfd create", ErrAuthorityClock)
	}
	pipeFDs := []int{-1, -1}
	if err := unix.Pipe2(pipeFDs, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return errors.Join(
			fmt.Errorf("%w: cancellation pipe", ErrAuthorityClock),
			closeLinuxFD(timerFD, "timerfd"),
		)
	}
	if err := unix.TimerfdSettime(timerFD, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: deadlineSpec}, nil); err != nil {
		return errors.Join(
			fmt.Errorf("%w: timerfd arm", ErrAuthorityClock),
			closeLinuxFD(pipeFDs[1], "cancellation writer"),
			closeLinuxFD(pipeFDs[0], "cancellation reader"),
			closeLinuxFD(timerFD, "timerfd"),
		)
	}

	var closeWriter sync.Once
	var closeWriterErr error
	closeCancellationWriter := func() {
		closeWriter.Do(func() {
			closeWriterErr = closeLinuxFD(pipeFDs[1], "cancellation writer")
		})
	}
	callbackDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		closeCancellationWriter()
		close(callbackDone)
	})
	defer func() {
		if stopCancellation() {
			closeCancellationWriter()
		} else {
			<-callbackDone
		}
		result = errors.Join(
			result,
			closeWriterErr,
			closeLinuxFD(pipeFDs[0], "cancellation reader"),
			closeLinuxFD(timerFD, "timerfd"),
		)
	}()

	fds := []unix.PollFd{
		{Fd: int32(timerFD), Events: unix.POLLIN},
		{Fd: int32(pipeFDs[0]), Events: unix.POLLIN | unix.POLLHUP},
	}
	for {
		ready, pollErr := unix.Poll(fds, -1)
		if errors.Is(pollErr, unix.EINTR) {
			continue
		}
		if pollErr != nil || ready < 1 {
			return fmt.Errorf("%w: poll", ErrAuthorityClock)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if unexpectedPollEvents(fds[0].Revents, unix.POLLIN) ||
			unexpectedPollEvents(fds[1].Revents, unix.POLLIN|unix.POLLHUP) {
			return fmt.Errorf("%w: poll events", ErrAuthorityClock)
		}
		if fds[1].Revents != 0 {
			return fmt.Errorf("%w: cancellation wake without cancellation", ErrAuthorityClock)
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			if err := consumeLinuxTimerFD(timerFD); err != nil {
				return err
			}
			return context.DeadlineExceeded
		}
		return fmt.Errorf("%w: empty readiness", ErrAuthorityClock)
	}
}

func probeLinuxBoottimeClock() (result error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil || !validLinuxTimespec(now) {
		return fmt.Errorf("%w: boottime", ErrAuthorityClock)
	}

	timerFD, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return fmt.Errorf("%w: timerfd probe create", ErrAuthorityClock)
	}
	defer func() { result = errors.Join(result, closeLinuxFD(timerFD, "timerfd probe")) }()
	if err := unix.TimerfdSettime(timerFD, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: now}, nil); err != nil {
		return fmt.Errorf("%w: timerfd probe arm", ErrAuthorityClock)
	}
	timerPoll := []unix.PollFd{{Fd: int32(timerFD), Events: unix.POLLIN}}
	ready, err := unix.Poll(timerPoll, linuxClockProbeTimeoutMilliseconds)
	if err != nil || ready != 1 || timerPoll[0].Revents != unix.POLLIN {
		return fmt.Errorf("%w: timerfd probe poll", ErrAuthorityClock)
	}
	if err := consumeLinuxTimerFD(timerFD); err != nil {
		return fmt.Errorf("%w: timerfd probe read", err)
	}

	pipeFDs := []int{-1, -1}
	if err := unix.Pipe2(pipeFDs, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return fmt.Errorf("%w: cancellation probe pipe", ErrAuthorityClock)
	}
	defer func() {
		result = errors.Join(
			result,
			closeLinuxFD(pipeFDs[0], "cancellation probe reader"),
		)
	}()
	if err := unix.Close(pipeFDs[1]); err != nil {
		return fmt.Errorf("%w: cancellation probe close", ErrAuthorityClock)
	}
	cancelPoll := []unix.PollFd{{Fd: int32(pipeFDs[0]), Events: unix.POLLIN | unix.POLLHUP}}
	ready, err = unix.Poll(cancelPoll, linuxClockProbeTimeoutMilliseconds)
	if err != nil || ready != 1 || cancelPoll[0].Revents&unix.POLLHUP == 0 ||
		unexpectedPollEvents(cancelPoll[0].Revents, unix.POLLIN|unix.POLLHUP) {
		return fmt.Errorf("%w: cancellation probe poll", ErrAuthorityClock)
	}
	return nil
}

func consumeLinuxTimerFD(fd int) error {
	var raw [8]byte
	read, err := unix.Read(fd, raw[:])
	if err != nil || read != len(raw) || binary.NativeEndian.Uint64(raw[:]) != 1 {
		return fmt.Errorf("%w: timerfd read", ErrAuthorityClock)
	}
	return nil
}

func closeLinuxFD(fd int, label string) error {
	if fd < 0 {
		return nil
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("%w: close %s", ErrAuthorityClock, label)
	}
	return nil
}

func validLinuxTimespec(value unix.Timespec) bool {
	return value.Sec >= 0 && value.Nsec >= 0 && value.Nsec < int64(time.Second)
}

func unexpectedPollEvents(actual, allowed int16) bool {
	return actual&^allowed != 0
}
