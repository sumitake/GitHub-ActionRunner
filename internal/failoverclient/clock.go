package failoverclient

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrAuthorityClock = errors.New("failoverclient: authority clock")

// AuthorityClock is the single injected suspend-aware clock for send anchors,
// lease deadlines, and absolute waits. A target that cannot prove Now and
// WaitUntil leaves acquisition disabled.
type AuthorityClock interface {
	Capable() bool
	Now() (time.Time, error)
	WaitUntil(ctx context.Context, deadline time.Time) error
}

type FakeAuthorityClock struct {
	now     time.Time
	capable bool
}

func NewFakeAuthorityClock(now time.Time) *FakeAuthorityClock {
	return &FakeAuthorityClock{now: now, capable: true}
}

func (clock *FakeAuthorityClock) Capable() bool { return clock != nil && clock.capable }

func (clock *FakeAuthorityClock) Disable() {
	if clock != nil {
		clock.capable = false
	}
}

func (clock *FakeAuthorityClock) Advance(delta time.Duration) {
	if clock != nil {
		clock.now = clock.now.Add(delta)
	}
}

func (clock *FakeAuthorityClock) Now() (time.Time, error) {
	if clock == nil || !clock.capable {
		return time.Time{}, fmt.Errorf("%w: unavailable", ErrAuthorityClock)
	}
	return clock.now, nil
}

func (clock *FakeAuthorityClock) WaitUntil(ctx context.Context, deadline time.Time) error {
	if clock == nil || !clock.capable {
		return fmt.Errorf("%w: unavailable", ErrAuthorityClock)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !clock.now.Before(deadline) {
		return context.DeadlineExceeded
	}
	clock.now = deadline
	return context.DeadlineExceeded
}

type unsupportedAuthorityClock struct{}

func NewUnsupportedAuthorityClock() AuthorityClock {
	return unsupportedAuthorityClock{}
}

func (unsupportedAuthorityClock) Capable() bool { return false }

func (unsupportedAuthorityClock) Now() (time.Time, error) {
	return time.Time{}, fmt.Errorf("%w: unsupported", ErrAuthorityClock)
}

func (unsupportedAuthorityClock) WaitUntil(context.Context, time.Time) error {
	return fmt.Errorf("%w: unsupported", ErrAuthorityClock)
}
