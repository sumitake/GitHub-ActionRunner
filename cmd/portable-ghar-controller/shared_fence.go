package main

import (
	"context"
	"errors"
	"sync"

	"github.com/sumitake/portable-ghar/internal/controller"
)

// sharedFenceGuard holds the process's one portable fence guard and lends it.
// The fence store keys a holder record by process identity, so a second
// Acquire from this process conflicts with the first. The service takes a
// guard for every acquisition and every heartbeat, often at the same time,
// so each takes a view of the one guard instead. A view is refused once the
// guard has failed, and closing a view releases nothing: the guard itself is
// closed with the process resources.
type sharedFenceGuard struct {
	lost chan struct{}
	stop chan struct{}

	mu        sync.Mutex
	cause     error
	closeOnce sync.Once
}

var _ controller.FleetGuardProvider = (*sharedFenceGuard)(nil)

// newSharedFenceGuard watches the guard's failure channel, which receives at
// most one error, and becomes the only reader of it.
func newSharedFenceGuard(failure <-chan error) *sharedFenceGuard {
	shared := &sharedFenceGuard{
		lost: make(chan struct{}),
		stop: make(chan struct{}),
	}
	go func() {
		select {
		case err := <-failure:
			if err == nil {
				err = errAcquisitionFenceLost
			}
			shared.mu.Lock()
			shared.cause = err
			shared.mu.Unlock()
			close(shared.lost)
		case <-shared.stop:
		}
	}()
	return shared
}

func (shared *sharedFenceGuard) AcquirePortable(
	ctx context.Context,
) (controller.AcquisitionGuard, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errAcquisitionFenceLost
	}
	select {
	case <-shared.lost:
		shared.mu.Lock()
		cause := shared.cause
		shared.mu.Unlock()
		return nil, errors.Join(errAcquisitionFenceLost, cause)
	default:
		return fenceView{shared: shared}, nil
	}
}

// Lost is closed once the guard has failed.
func (shared *sharedFenceGuard) Lost() <-chan struct{} { return shared.lost }

// Close stops the watcher. It does not close the guard.
func (shared *sharedFenceGuard) Close() error {
	shared.closeOnce.Do(func() { close(shared.stop) })
	return nil
}

// fenceView is one borrower's hold on the shared guard. Close releases
// nothing, but reports a guard lost while the view was held: the service
// treats a guard-close error as lost host authority, so an operation or
// heartbeat that spanned the loss is not accepted.
type fenceView struct{ shared *sharedFenceGuard }

func (view fenceView) Close() error {
	select {
	case <-view.shared.lost:
		view.shared.mu.Lock()
		cause := view.shared.cause
		view.shared.mu.Unlock()
		return errors.Join(errAcquisitionFenceLost, cause)
	default:
		return nil
	}
}
