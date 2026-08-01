package fleetfence

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

type ControllerAdapterConfig struct {
	Store           *Store
	Generation      uint64
	OwnerID         string
	PID             int
	RenewalInterval time.Duration
	RenewalTimeout  time.Duration
}

type ControllerAdapter struct {
	store           *Store
	generation      uint64
	ownerID         string
	pid             int
	renewalInterval time.Duration
	renewalTimeout  time.Duration
}

var _ controller.FleetGuardProvider = (*ControllerAdapter)(nil)

// ControllerRuntimeConfig is the complete Task 9 production composition for
// the host-local fence authority. It deliberately has no sizing or timing
// defaults.
type ControllerRuntimeConfig struct {
	StateDir         string
	Generation       uint64
	OwnerID          string
	PID              int
	Now              func() time.Time
	LockPollInterval time.Duration
	RenewalInterval  time.Duration
	RenewalTimeout   time.Duration
}

// ControllerRuntime owns the store behind one controller guard provider.
// Later controller composition may consume Provider, but this type exposes no
// handoff or legacy mutation surface.
type ControllerRuntime struct {
	store    *Store
	provider *ControllerAdapter
}

type renewingGuard struct {
	guard Guard
	stop  chan struct{}
	done  chan struct{}

	stopOnce sync.Once
	mu       sync.Mutex
	renewErr error
}

func OpenControllerRuntime(
	config ControllerRuntimeConfig,
) (*ControllerRuntime, error) {
	return openControllerRuntime(config, NewSystemIdentitySource())
}

func openControllerRuntime(
	config ControllerRuntimeConfig,
	identity IdentitySource,
) (*ControllerRuntime, error) {
	store, err := OpenStore(StoreConfig{
		Root:             config.StateDir,
		Identity:         identity,
		Now:              config.Now,
		LockPollInterval: config.LockPollInterval,
	})
	if err != nil {
		return nil, err
	}
	provider, err := NewControllerAdapter(ControllerAdapterConfig{
		Store:           store,
		Generation:      config.Generation,
		OwnerID:         config.OwnerID,
		PID:             config.PID,
		RenewalInterval: config.RenewalInterval,
		RenewalTimeout:  config.RenewalTimeout,
	})
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return &ControllerRuntime{store: store, provider: provider}, nil
}

func (r *ControllerRuntime) Provider() controller.FleetGuardProvider {
	if r == nil {
		return nil
	}
	return r.provider
}

func (r *ControllerRuntime) Close() error {
	if r == nil || r.store == nil {
		return nil
	}
	return r.store.Close()
}

func NewControllerAdapter(
	config ControllerAdapterConfig,
) (*ControllerAdapter, error) {
	if config.Store == nil ||
		config.Generation == 0 ||
		!validScalar(config.OwnerID) ||
		config.PID <= 0 ||
		config.RenewalInterval <= 0 ||
		config.RenewalTimeout <= 0 {
		return nil, ErrInvalidState
	}
	return &ControllerAdapter{
		store:           config.Store,
		generation:      config.Generation,
		ownerID:         config.OwnerID,
		pid:             config.PID,
		renewalInterval: config.RenewalInterval,
		renewalTimeout:  config.RenewalTimeout,
	}, nil
}

func (a *ControllerAdapter) AcquirePortable(
	ctx context.Context,
) (controller.AcquisitionGuard, error) {
	guard, err := a.store.Acquire(ctx, AcquireRequest{
		Fleet:      FleetPortable,
		Generation: a.generation,
		OwnerID:    a.ownerID,
		PID:        a.pid,
	})
	if err != nil {
		return nil, fmt.Errorf("fleetfence: acquire portable: %w", err)
	}
	wrapped := &renewingGuard{
		guard: guard,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go wrapped.run(a.renewalInterval, a.renewalTimeout)
	return wrapped, nil
}

func (g *renewingGuard) run(interval, timeout time.Duration) {
	defer close(g.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			err := g.guard.Renew(ctx)
			cancel()
			if err != nil {
				g.mu.Lock()
				g.renewErr = err
				g.mu.Unlock()
				return
			}
		}
	}
}

func (g *renewingGuard) Close() error {
	g.stopOnce.Do(func() { close(g.stop) })
	<-g.done
	closeErr := g.guard.Close()
	g.mu.Lock()
	renewErr := g.renewErr
	g.mu.Unlock()
	if renewErr != nil {
		renewErr = fmt.Errorf("fleetfence: renew: %w", renewErr)
	}
	return errors.Join(renewErr, closeErr)
}

// Failure exposes only the terminal health of the already-opaque guard. It
// does not expose holder identity or any mutation capability.
func (g *renewingGuard) Failure() <-chan error {
	if g == nil || g.guard == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return g.guard.Failure()
}
