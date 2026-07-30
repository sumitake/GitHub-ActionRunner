package testenv

import (
	"errors"
	"testing"
	"time"
)

type scriptedRetainedAuthorization struct {
	consumeAt  time.Time
	consumeErr error
	closeErr   error
	closeCalls int
}

func (a *scriptedRetainedAuthorization) Consume(at time.Time) error {
	a.consumeAt = at
	return a.consumeErr
}

func (a *scriptedRetainedAuthorization) Close() error {
	a.closeCalls++
	return a.closeErr
}

type scriptedFixtureRootCloser struct {
	err   error
	calls int
}

func (c *scriptedFixtureRootCloser) Close() error {
	c.calls++
	return c.err
}

type scriptedFixturePrestartCloser struct {
	err   error
	calls int
}

func (c *scriptedFixturePrestartCloser) CloseUnstarted() error {
	c.calls++
	return c.err
}

func TestFixtureStartAuthorizationConsumesAtInjectedTimeAndClosesAllOwners(
	t *testing.T,
) {
	at := time.Unix(1_900_000_000, 0).UTC()
	lease := &scriptedRetainedAuthorization{}
	root := &scriptedFixtureRootCloser{}
	runtime := &scriptedFixturePrestartCloser{}
	authorization, err := newFixtureStartAuthorization(
		lease,
		root,
		runtime,
		func() time.Time { return at },
	)
	if err != nil {
		t.Fatalf("newFixtureStartAuthorization: %v", err)
	}
	if err := authorization.Consume(); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if lease.consumeAt != at {
		t.Fatalf("consume time = %v, want %v", lease.consumeAt, at)
	}
	if err := authorization.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := authorization.Close(); err != nil {
		t.Fatalf("cached Close: %v", err)
	}
	if lease.closeCalls != 1 || root.calls != 1 || runtime.calls != 1 {
		t.Fatalf(
			"close calls = lease %d root %d runtime %d",
			lease.closeCalls,
			root.calls,
			runtime.calls,
		)
	}
}

func TestFixtureStartAuthorizationFailsClosedAndStillClosesEveryOwner(
	t *testing.T,
) {
	leaseFailure := errors.New("lease close")
	rootFailure := errors.New("root close")
	runtimeFailure := errors.New("runtime close")
	lease := &scriptedRetainedAuthorization{closeErr: leaseFailure}
	root := &scriptedFixtureRootCloser{err: rootFailure}
	runtime := &scriptedFixturePrestartCloser{err: runtimeFailure}
	authorization, err := newFixtureStartAuthorization(
		lease,
		root,
		runtime,
		time.Now,
	)
	if err != nil {
		t.Fatalf("newFixtureStartAuthorization: %v", err)
	}
	closeErr := authorization.Close()
	for _, expected := range []error{
		leaseFailure,
		rootFailure,
		runtimeFailure,
	} {
		if !errors.Is(closeErr, expected) {
			t.Fatalf("Close error %v does not include %v", closeErr, expected)
		}
	}
	if lease.closeCalls != 1 || root.calls != 1 || runtime.calls != 1 {
		t.Fatalf(
			"close calls = lease %d root %d runtime %d",
			lease.closeCalls,
			root.calls,
			runtime.calls,
		)
	}
}

func TestFixtureStartAuthorizationRejectsIncompleteDependencies(t *testing.T) {
	lease := &scriptedRetainedAuthorization{}
	root := &scriptedFixtureRootCloser{}
	runtime := &scriptedFixturePrestartCloser{}
	for name, test := range map[string]func() error{
		"lease": func() error {
			_, err := newFixtureStartAuthorization(
				nil,
				root,
				runtime,
				time.Now,
			)
			return err
		},
		"root": func() error {
			_, err := newFixtureStartAuthorization(
				lease,
				nil,
				runtime,
				time.Now,
			)
			return err
		},
		"runtime": func() error {
			_, err := newFixtureStartAuthorization(
				lease,
				root,
				nil,
				time.Now,
			)
			return err
		},
		"clock": func() error {
			_, err := newFixtureStartAuthorization(
				lease,
				root,
				runtime,
				nil,
			)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := test(); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("error = %v, want ErrFixtureStart", err)
			}
		})
	}
}
