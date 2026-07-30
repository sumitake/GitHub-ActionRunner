package testenv

import (
	"errors"
	"sync"
	"time"
)

type retainedFixtureAuthorization interface {
	Consume(time.Time) error
	Close() error
}

type fixtureRootCloser interface {
	Close() error
}

type fixturePrestartCloser interface {
	CloseUnstarted() error
}

type fixtureStartAuthorization struct {
	lease   retainedFixtureAuthorization
	root    fixtureRootCloser
	runtime fixturePrestartCloser
	now     func() time.Time

	closeOnce sync.Once
	closeErr  error
}

func newFixtureStartAuthorization(
	lease retainedFixtureAuthorization,
	root fixtureRootCloser,
	runtime fixturePrestartCloser,
	now func() time.Time,
) (*fixtureStartAuthorization, error) {
	if lease == nil || root == nil || runtime == nil || now == nil {
		return nil, ErrFixtureStart
	}
	return &fixtureStartAuthorization{
		lease:   lease,
		root:    root,
		runtime: runtime,
		now:     now,
	}, nil
}

func (a *fixtureStartAuthorization) Consume() error {
	if a == nil || a.lease == nil || a.now == nil {
		return ErrFixtureStart
	}
	at := a.now().UTC()
	if at.IsZero() {
		return ErrFixtureStart
	}
	return a.lease.Consume(at)
}

func (a *fixtureStartAuthorization) Close() error {
	if a == nil {
		return ErrFixtureCleanup
	}
	a.closeOnce.Do(func() {
		a.closeErr = errors.Join(
			a.runtime.CloseUnstarted(),
			a.root.Close(),
			a.lease.Close(),
		)
	})
	return a.closeErr
}

var _ fixtureAuthorization = (*fixtureStartAuthorization)(nil)
