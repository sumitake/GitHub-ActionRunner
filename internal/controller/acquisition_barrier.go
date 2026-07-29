package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrAcquisitionTransitioning    = errors.New("controller: acquisition epoch transitioning")
	ErrAcquisitionEpochMismatch    = errors.New("controller: acquisition epoch mismatch")
	ErrAcquisitionEpochSuperseded  = errors.New("controller: acquisition epoch superseded")
	ErrAcquisitionDeadlineRequired = errors.New("controller: acquisition deadline required")
	ErrAcquisitionOperationClosed  = errors.New("controller: acquisition operation closed")
	ErrAcquisitionCriticalBusy     = errors.New("controller: acquisition message critical section busy")
	ErrAcquisitionUnavailable      = errors.New("controller: acquisition unavailable")
)

type acquisitionMessageKey struct {
	repositoryAlias string
	messageID       int
}

// acquisitionEpoch is immutable except for the registry and gate fields,
// which are protected by acquisitionBarrier.mu. The epoch context is
// cancelled only after a newer persisted epoch has been published.
type acquisitionEpoch struct {
	policy AcquisitionPolicy
	digest [32]byte
	ctx    context.Context
	cancel context.CancelCauseFunc

	gateOpen      bool
	transitioning bool
	operations    map[string]*acquisitionOperation
	criticals     map[acquisitionMessageKey]*acquisitionCritical
	idle          chan struct{}
}

// acquisitionBarrier serializes epoch publication while allowing unrelated
// state work to proceed concurrently. Closing the gate makes registry Add and
// wait race-free: after closeGate returns, no new work can enter that epoch.
type acquisitionBarrier struct {
	mu      sync.Mutex
	current *acquisitionEpoch
}

type acquisitionOperation struct {
	mu       sync.Mutex
	barrier  *acquisitionBarrier
	epoch    *acquisitionEpoch
	id       string
	kind     string
	repo     string
	scaleSet string
	ctx      context.Context
	cancel   context.CancelCauseFunc
	stop     func() bool
	closed   bool
}

type acquisitionCritical struct {
	mu      sync.Mutex
	barrier *acquisitionBarrier
	epoch   *acquisitionEpoch
	key     acquisitionMessageKey
	ctx     context.Context
	cancel  context.CancelCauseFunc
	stop    func() bool
	closed  bool
}

func newAcquisitionBarrier(
	policy AcquisitionPolicy,
	open bool,
) (*acquisitionBarrier, error) {
	epoch, err := newAcquisitionEpoch(policy)
	if err != nil {
		return nil, err
	}
	epoch.gateOpen = open
	return &acquisitionBarrier{current: epoch}, nil
}

func newAcquisitionEpoch(policy AcquisitionPolicy) (*acquisitionEpoch, error) {
	canonical, err := CanonicalizeAcquisitionPolicy(policy)
	if err != nil {
		return nil, err
	}
	digest, err := AcquisitionPolicyDigest(canonical)
	if err != nil {
		return nil, err
	}
	epochContext, cancel := context.WithCancelCause(context.Background())
	idle := make(chan struct{})
	close(idle)
	return &acquisitionEpoch{
		policy:     canonical,
		digest:     digest,
		ctx:        epochContext,
		cancel:     cancel,
		operations: make(map[string]*acquisitionOperation),
		criticals:  make(map[acquisitionMessageKey]*acquisitionCritical),
		idle:       idle,
	}, nil
}

func (b *acquisitionBarrier) snapshot() (
	AcquisitionPolicy,
	[32]byte,
	bool,
) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return cloneAcquisitionPolicy(b.current.policy),
		b.current.digest,
		b.current.gateOpen && !b.current.transitioning
}

func (b *acquisitionBarrier) beginOperation(
	ctx context.Context,
	kind string,
	repositoryAlias string,
	scaleSetName string,
) (*acquisitionOperation, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrAcquisitionDeadlineRequired
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch kind {
	case "poll", "acquire", "jit", "observer-poll":
	default:
		return nil, fmt.Errorf("%w: operation kind", ErrAcquisitionUnavailable)
	}
	if !validAcquisitionScalar(repositoryAlias, maxAcquisitionRepositoryBytes) ||
		!validAcquisitionScalar(scaleSetName, maxAcquisitionScaleSetBytes) {
		return nil, fmt.Errorf("%w: operation binding", ErrAcquisitionUnavailable)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	epoch := b.current
	if !epoch.gateOpen || epoch.transitioning {
		return nil, ErrAcquisitionTransitioning
	}
	if kind != "observer-poll" {
		if epoch.policy.Mode != AcquisitionEnabled &&
			epoch.policy.Mode != AcquisitionCanaryOnly {
			return nil, ErrAcquisitionUnavailable
		}
		if epoch.policy.MaxCapacity <= 0 {
			return nil, ErrAcquisitionUnavailable
		}
	}

	id, err := freshAcquisitionOperationID(epoch.operations)
	if err != nil {
		return nil, err
	}
	operationContext, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(epoch.ctx, func() {
		cancel(context.Cause(epoch.ctx))
	})
	operation := &acquisitionOperation{
		barrier:  b,
		epoch:    epoch,
		id:       id,
		kind:     kind,
		repo:     repositoryAlias,
		scaleSet: scaleSetName,
		ctx:      operationContext,
		cancel:   cancel,
		stop:     stop,
	}
	b.prepareAddLocked(epoch)
	epoch.operations[id] = operation
	return operation, nil
}

func (b *acquisitionBarrier) beginCritical(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
) (*acquisitionCritical, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrAcquisitionDeadlineRequired
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validAcquisitionScalar(repositoryAlias, maxAcquisitionRepositoryBytes) ||
		messageID < 0 {
		return nil, fmt.Errorf("%w: critical binding", ErrAcquisitionUnavailable)
	}
	key := acquisitionMessageKey{
		repositoryAlias: repositoryAlias,
		messageID:       messageID,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	epoch := b.current
	if !epoch.gateOpen || epoch.transitioning {
		return nil, ErrAcquisitionTransitioning
	}
	if _, exists := epoch.criticals[key]; exists {
		return nil, ErrAcquisitionCriticalBusy
	}
	criticalContext, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(epoch.ctx, func() {
		cancel(context.Cause(epoch.ctx))
	})
	critical := &acquisitionCritical{
		barrier: b,
		epoch:   epoch,
		key:     key,
		ctx:     criticalContext,
		cancel:  cancel,
		stop:    stop,
	}
	b.prepareAddLocked(epoch)
	epoch.criticals[key] = critical
	return critical, nil
}

func (b *acquisitionBarrier) prepareAddLocked(epoch *acquisitionEpoch) {
	if len(epoch.operations)+len(epoch.criticals) == 0 {
		epoch.idle = make(chan struct{})
	}
}

func (b *acquisitionBarrier) closeGate(expectedEpoch uint64) (*acquisitionEpoch, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current.policy.Epoch != expectedEpoch {
		return nil, ErrAcquisitionEpochMismatch
	}
	if b.current.transitioning {
		return nil, ErrAcquisitionTransitioning
	}
	b.current.gateOpen = false
	b.current.transitioning = true
	return b.current, nil
}

func (b *acquisitionBarrier) reopen(epoch *acquisitionEpoch) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != epoch || context.Cause(epoch.ctx) != nil {
		return ErrAcquisitionEpochMismatch
	}
	if !epoch.transitioning {
		return ErrAcquisitionTransitioning
	}
	epoch.transitioning = false
	epoch.gateOpen = true
	return nil
}

func (b *acquisitionBarrier) publish(
	closed *acquisitionEpoch,
	next AcquisitionPolicy,
) (*acquisitionEpoch, error) {
	nextEpoch, err := newAcquisitionEpoch(next)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	if b.current != closed ||
		!closed.transitioning ||
		closed.gateOpen ||
		nextEpoch.policy.Epoch <= closed.policy.Epoch {
		b.mu.Unlock()
		nextEpoch.cancel(ErrAcquisitionEpochSuperseded)
		return nil, ErrAcquisitionEpochMismatch
	}
	b.current = nextEpoch
	b.mu.Unlock()

	closed.cancel(ErrAcquisitionEpochSuperseded)
	return closed, nil
}

func (b *acquisitionBarrier) open(expectedEpoch uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current.policy.Epoch != expectedEpoch ||
		context.Cause(b.current.ctx) != nil {
		return ErrAcquisitionEpochMismatch
	}
	if b.current.gateOpen && !b.current.transitioning {
		return nil
	}
	b.current.transitioning = false
	b.current.gateOpen = true
	return nil
}

func (b *acquisitionBarrier) waitEpoch(
	ctx context.Context,
	epoch *acquisitionEpoch,
) error {
	b.mu.Lock()
	idle := epoch.idle
	b.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *acquisitionBarrier) epochCounts(epoch *acquisitionEpoch) (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(epoch.operations), len(epoch.criticals)
}

func (o *acquisitionOperation) ID() string {
	return o.id
}

func (o *acquisitionOperation) Epoch() uint64 {
	return o.epoch.policy.Epoch
}

func (o *acquisitionOperation) Policy() AcquisitionPolicy {
	return cloneAcquisitionPolicy(o.epoch.policy)
}

func (o *acquisitionOperation) Digest() [32]byte {
	return o.epoch.digest
}

func (o *acquisitionOperation) Context() context.Context {
	return o.ctx
}

func (o *acquisitionOperation) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return ErrAcquisitionOperationClosed
	}
	o.closed = true
	o.mu.Unlock()

	o.stop()
	o.cancel(ErrAcquisitionOperationClosed)
	o.barrier.mu.Lock()
	defer o.barrier.mu.Unlock()
	if current, ok := o.epoch.operations[o.id]; !ok || current != o {
		return ErrAcquisitionOperationClosed
	}
	delete(o.epoch.operations, o.id)
	o.barrier.finishRemoveLocked(o.epoch)
	return nil
}

func (c *acquisitionCritical) Epoch() uint64 {
	return c.epoch.policy.Epoch
}

func (c *acquisitionCritical) Policy() AcquisitionPolicy {
	return cloneAcquisitionPolicy(c.epoch.policy)
}

func (c *acquisitionCritical) Context() context.Context {
	return c.ctx
}

func (c *acquisitionCritical) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrAcquisitionOperationClosed
	}
	c.closed = true
	c.mu.Unlock()

	c.stop()
	c.cancel(ErrAcquisitionOperationClosed)
	c.barrier.mu.Lock()
	defer c.barrier.mu.Unlock()
	if current, ok := c.epoch.criticals[c.key]; !ok || current != c {
		return ErrAcquisitionOperationClosed
	}
	delete(c.epoch.criticals, c.key)
	c.barrier.finishRemoveLocked(c.epoch)
	return nil
}

func (b *acquisitionBarrier) finishRemoveLocked(epoch *acquisitionEpoch) {
	if len(epoch.operations)+len(epoch.criticals) == 0 {
		close(epoch.idle)
	}
}

func freshAcquisitionOperationID(
	existing map[string]*acquisitionOperation,
) (string, error) {
	for attempts := 0; attempts < 4; attempts++ {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", fmt.Errorf("controller: create operation identity: %w", err)
		}
		id := "op-v1-" + hex.EncodeToString(raw[:])
		if _, collision := existing[id]; !collision {
			return id, nil
		}
	}
	return "", fmt.Errorf("controller: create unique operation identity")
}
