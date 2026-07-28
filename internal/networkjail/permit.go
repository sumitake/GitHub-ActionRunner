package networkjail

import (
	"context"
	"errors"
	"math"
	"sync"
)

var (
	ErrPermitLedgerConflict       = errors.New("networkjail: permit ledger conflict")
	ErrPermitBudgetExhausted      = errors.New("networkjail: permit budget exhausted")
	ErrPermitSequence             = errors.New("networkjail: permit sequence invalid")
	ErrPermitAssignment           = errors.New("networkjail: permit assignment invalid")
	ErrMonotonicClockRegression   = errors.New("networkjail: monotonic clock regression")
	ErrBootRebaseRequired         = errors.New("networkjail: boot rebase required")
	ErrBootRebaseReplay           = errors.New("networkjail: boot rebase replay")
	ErrEmptyConntrackProofInvalid = errors.New("networkjail: empty conntrack proof invalid")
	ErrLedgerRetained             = errors.New("networkjail: permit ledger retained")
	ErrLedgerReferenced           = errors.New("networkjail: permit ledger referenced")
	ErrPermitAuthorityUnavailable = errors.New("networkjail: permit authority unavailable")
	ErrPermitPeerInvalid          = errors.New("networkjail: permit peer invalid")
	ErrPermitArithmetic           = errors.New("networkjail: permit arithmetic overflow")
)

type Permit struct {
	slot   CapacitySlotID
	class  DialClass
	number uint64
}

type PermitAuthority struct {
	mu         sync.Mutex
	graph      DecisionGraph
	clock      MonotonicClock
	store      permitStore
	peers      PermitPeerValidator
	references LedgerReferenceGuard
	rebase     EmptyConntrackValidator
	blockSize  uint64
	ledgers    map[CapacitySlotID]permitLedger
}

func newPermitAuthority(
	graph DecisionGraph,
	clock MonotonicClock,
	store permitStore,
	peers PermitPeerValidator,
	references LedgerReferenceGuard,
	rebase EmptyConntrackValidator,
	blockSize uint64,
) (*PermitAuthority, error) {
	if graph.digest == (Digest{}) || clock == nil || store == nil || peers == nil ||
		references == nil || rebase == nil || blockSize == 0 ||
		blockSize > math.MaxUint32 {
		return nil, ErrPermitAuthorityUnavailable
	}
	if _, ok := checkedMultiply64(graph.manifest.JobDialBurst, nanosPerSecond); !ok {
		return nil, ErrPermitArithmetic
	}
	if _, ok := checkedMultiply64(graph.manifest.DoHDialBurst, nanosPerSecond); !ok {
		return nil, ErrPermitArithmetic
	}
	return &PermitAuthority{
		graph:      graph,
		clock:      clock,
		store:      store,
		peers:      peers,
		references: references,
		rebase:     rebase,
		blockSize:  blockSize,
		ledgers:    make(map[CapacitySlotID]permitLedger),
	}, nil
}

func (authority *PermitAuthority) Activate(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
) error {
	if slot == 0 || generation == 0 {
		return ErrPermitAssignment
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()

	observation, err := authority.observe(ctx)
	if err != nil {
		return err
	}
	current, found, err := authority.load(ctx, slot)
	if err != nil {
		return err
	}
	if !found {
		next, err := authority.newLedger(slot, generation, observation)
		if err != nil {
			return err
		}
		if err := authority.store.compareAndSwap(ctx, slot, 0, next); err != nil {
			return err
		}
		authority.ledgers[slot] = next
		return nil
	}
	if err := validateObservation(current, observation); err != nil {
		return err
	}
	if current.ActiveJobGeneration == generation {
		current.LastMonotonicNanos = observation.MonotonicNanos
		authority.ledgers[slot] = current
		return nil
	}
	if current.ActiveJobGeneration != 0 {
		return ErrPermitAssignment
	}

	next := current
	wasteReservations(&next.Job)
	wasteReservations(&next.DoH)
	resetSequences(&next.Job)
	resetSequences(&next.DoH)
	next.ActiveJobGeneration = generation
	next.RetainedUntilNanos = 0
	next.LastMonotonicNanos = observation.MonotonicNanos
	next.Revision++
	if err := authority.store.compareAndSwap(ctx, slot, current.Revision, next); err != nil {
		return err
	}
	authority.ledgers[slot] = next
	return nil
}

// ActiveRevision returns the durable revision for the exact active slot/job
// binding. It is identity metadata for the Unix authority proof, never a
// permit or a refill input.
func (authority *PermitAuthority) ActiveRevision(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
) (uint64, error) {
	if authority == nil || slot == 0 || generation == 0 {
		return 0, ErrPermitAssignment
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	current, found, err := authority.load(ctx, slot)
	if err != nil || !found ||
		current.ActiveJobGeneration != generation ||
		current.Revision == 0 {
		return 0, ErrPermitAssignment
	}
	return current.Revision, nil
}

func (authority *PermitAuthority) Consume(
	ctx context.Context,
	request DialPermitRequest,
	peer PermitPeer,
) (Permit, error) {
	if err := request.validate(); err != nil {
		return Permit{}, err
	}
	if !peer.valid() {
		return Permit{}, ErrPermitPeerInvalid
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()

	observation, err := authority.observe(ctx)
	if err != nil {
		return Permit{}, err
	}
	current, found, err := authority.load(ctx, request.SlotID)
	if err != nil {
		return Permit{}, err
	}
	if !found || current.ActiveJobGeneration != request.JobGeneration {
		return Permit{}, ErrPermitAssignment
	}
	if err := validateObservation(current, observation); err != nil {
		return Permit{}, err
	}
	if err := authority.peers.ValidatePermitPeer(
		ctx,
		request.SlotID,
		request.JobGeneration,
		request.Class,
		peer,
	); err != nil {
		return Permit{}, ErrPermitPeerInvalid
	}

	class := classLedger(&current, request.Class)
	if request.Sequence <= class.IssuedSequence {
		return Permit{}, ErrPermitSequence
	}
	if class.IssuedHighWater < class.ReservedHighWater &&
		request.Sequence <= class.ReservedSequence {
		class.IssuedHighWater++
		class.IssuedSequence = request.Sequence
		current.LastMonotonicNanos = observation.MonotonicNanos
		authority.ledgers[request.SlotID] = current
		return Permit{
			slot:   request.SlotID,
			class:  request.Class,
			number: class.IssuedHighWater,
		}, nil
	}

	// A sequence jump outside the reserved fence invalidates every unissued
	// member of that block. It is never refunded.
	wasteReservations(class)
	next := current
	nextClass := classLedger(&next, request.Class)
	if err := refillClass(
		nextClass,
		classRate(authority.graph.manifest, request.Class),
		classBurst(authority.graph.manifest, request.Class),
		observation.MonotonicNanos,
	); err != nil {
		return Permit{}, err
	}
	available := nextClass.TokenUnits / nanosPerSecond
	if available == 0 {
		current.LastMonotonicNanos = observation.MonotonicNanos
		authority.ledgers[request.SlotID] = current
		return Permit{}, ErrPermitBudgetExhausted
	}
	count := min(available, authority.blockSize)
	reserved, ok := checkedAdd64(nextClass.ReservedHighWater, count)
	if !ok {
		return Permit{}, ErrPermitArithmetic
	}
	sequenceEnd, ok := checkedAdd64(uint64(request.Sequence), count-1)
	if !ok {
		return Permit{}, ErrPermitArithmetic
	}
	charge, ok := checkedMultiply64(count, nanosPerSecond)
	if !ok || charge > nextClass.TokenUnits {
		return Permit{}, ErrPermitArithmetic
	}
	nextClass.TokenUnits -= charge
	nextClass.IssuedHighWater = class.IssuedHighWater
	nextClass.IssuedSequence = class.IssuedSequence
	nextClass.ReservedHighWater = reserved
	nextClass.ReservedSequence = PermitSequence(sequenceEnd)
	next.LastMonotonicNanos = observation.MonotonicNanos
	next.Revision++
	if err := authority.store.compareAndSwap(
		ctx,
		request.SlotID,
		current.Revision,
		next,
	); err != nil {
		return Permit{}, err
	}

	nextClass.IssuedHighWater++
	nextClass.IssuedSequence = request.Sequence
	authority.ledgers[request.SlotID] = next
	return Permit{
		slot:   request.SlotID,
		class:  request.Class,
		number: nextClass.IssuedHighWater,
	}, nil
}

func (authority *PermitAuthority) Deactivate(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
) error {
	if slot == 0 || generation == 0 {
		return ErrPermitAssignment
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()

	observation, err := authority.observe(ctx)
	if err != nil {
		return err
	}
	current, found, err := authority.load(ctx, slot)
	if err != nil {
		return err
	}
	if !found || current.ActiveJobGeneration != generation {
		return ErrPermitAssignment
	}
	if err := validateObservation(current, observation); err != nil {
		return err
	}
	tailNanos, ok := checkedMultiply64(
		authority.graph.manifest.TailTimeoutSeconds,
		nanosPerSecond,
	)
	if !ok {
		return ErrPermitArithmetic
	}
	retainedUntil, ok := checkedAdd64(observation.MonotonicNanos, tailNanos)
	if !ok {
		return ErrPermitArithmetic
	}
	next := current
	wasteReservations(&next.Job)
	wasteReservations(&next.DoH)
	next.ActiveJobGeneration = 0
	next.LastMonotonicNanos = observation.MonotonicNanos
	next.RetainedUntilNanos = retainedUntil
	next.Revision++
	if err := authority.store.compareAndSwap(ctx, slot, current.Revision, next); err != nil {
		return err
	}
	authority.ledgers[slot] = next
	return nil
}

func (authority *PermitAuthority) Rebase(
	ctx context.Context,
	slot CapacitySlotID,
	proof EmptyConntrackProof,
) error {
	if slot == 0 {
		return ErrPermitAssignment
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()

	observation, err := authority.observe(ctx)
	if err != nil {
		return err
	}
	current, found, err := authority.load(ctx, slot)
	if err != nil {
		return err
	}
	if !found {
		return ErrPermitAssignment
	}
	if current.BootID == observation.BootID {
		if current.LastRebaseBootID == observation.BootID {
			return ErrBootRebaseReplay
		}
		return ErrPermitAssignment
	}
	if err := authority.rebase.ValidateEmptyConntrack(
		ctx,
		slot,
		current.BootID,
		observation.BootID,
		proof,
	); err != nil {
		return ErrEmptyConntrackProofInvalid
	}
	next, err := authority.newLedger(slot, 0, observation)
	if err != nil {
		return err
	}
	next.Revision = current.Revision + 1
	next.LastRebaseBootID = observation.BootID
	if err := authority.store.compareAndSwap(ctx, slot, current.Revision, next); err != nil {
		return err
	}
	authority.ledgers[slot] = next
	return nil
}

func (authority *PermitAuthority) Collect(
	ctx context.Context,
	slot CapacitySlotID,
) error {
	if slot == 0 {
		return ErrPermitAssignment
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()

	observation, err := authority.observe(ctx)
	if err != nil {
		return err
	}
	current, found, err := authority.load(ctx, slot)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if err := validateObservation(current, observation); err != nil {
		return err
	}
	if current.ActiveJobGeneration != 0 || current.RetainedUntilNanos == 0 ||
		observation.MonotonicNanos < current.RetainedUntilNanos {
		return ErrLedgerRetained
	}
	referenced, err := authority.references.HasLedgerReferences(ctx, slot)
	if err != nil {
		return err
	}
	if referenced {
		return ErrLedgerReferenced
	}
	if err := authority.store.delete(ctx, slot, current.Revision); err != nil {
		return err
	}
	delete(authority.ledgers, slot)
	return nil
}

func (authority *PermitAuthority) observe(
	ctx context.Context,
) (ClockObservation, error) {
	observation, err := authority.clock.Observe(ctx)
	if err != nil {
		return ClockObservation{}, ErrPermitAuthorityUnavailable
	}
	if err := observation.validate(); err != nil {
		return ClockObservation{}, err
	}
	return observation, nil
}

func (authority *PermitAuthority) load(
	ctx context.Context,
	slot CapacitySlotID,
) (permitLedger, bool, error) {
	if current, found := authority.ledgers[slot]; found {
		return current, true, nil
	}
	current, found, err := authority.store.load(ctx, slot)
	if err != nil || !found {
		return permitLedger{}, found, err
	}
	if err := validatePermitLedger(current, slot); err != nil {
		return permitLedger{}, false, err
	}
	// The last durable block may have been only partly issued. Recovery
	// conservatively burns every remaining member and its sequence fence.
	wasteReservations(&current.Job)
	wasteReservations(&current.DoH)
	authority.ledgers[slot] = current
	return current, true, nil
}

func (authority *PermitAuthority) newLedger(
	slot CapacitySlotID,
	generation JobGeneration,
	observation ClockObservation,
) (permitLedger, error) {
	jobTokens, ok := checkedMultiply64(
		authority.graph.manifest.JobDialBurst,
		nanosPerSecond,
	)
	if !ok {
		return permitLedger{}, ErrPermitArithmetic
	}
	dohTokens, ok := checkedMultiply64(
		authority.graph.manifest.DoHDialBurst,
		nanosPerSecond,
	)
	if !ok {
		return permitLedger{}, ErrPermitArithmetic
	}
	return permitLedger{
		Version:             permitLedgerVersion,
		SlotID:              slot,
		BootID:              observation.BootID,
		Revision:            1,
		ActiveJobGeneration: generation,
		LastMonotonicNanos:  observation.MonotonicNanos,
		Job: permitClassLedger{
			TokenUnits:      jobTokens,
			LastRefillNanos: observation.MonotonicNanos,
		},
		DoH: permitClassLedger{
			TokenUnits:      dohTokens,
			LastRefillNanos: observation.MonotonicNanos,
		},
	}, nil
}

func validateObservation(
	current permitLedger,
	observation ClockObservation,
) error {
	if current.BootID != observation.BootID {
		return ErrBootRebaseRequired
	}
	if observation.MonotonicNanos < current.LastMonotonicNanos {
		return ErrMonotonicClockRegression
	}
	return nil
}

func validatePermitLedger(current permitLedger, slot CapacitySlotID) error {
	if current.Version != permitLedgerVersion || current.SlotID != slot ||
		current.BootID == (BootID{}) || current.Revision == 0 ||
		current.LastMonotonicNanos == 0 ||
		current.Job.IssuedHighWater > current.Job.ReservedHighWater ||
		current.DoH.IssuedHighWater > current.DoH.ReservedHighWater ||
		current.Job.IssuedSequence > current.Job.ReservedSequence ||
		current.DoH.IssuedSequence > current.DoH.ReservedSequence {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func refillClass(
	class *permitClassLedger,
	rate uint64,
	burst uint64,
	now uint64,
) error {
	if now < class.LastRefillNanos {
		return ErrMonotonicClockRegression
	}
	capacity, ok := checkedMultiply64(burst, nanosPerSecond)
	if !ok {
		return ErrPermitArithmetic
	}
	elapsed := now - class.LastRefillNanos
	refill, ok := checkedMultiply64(elapsed, rate)
	if !ok {
		refill = math.MaxUint64
	}
	if refill >= capacity || class.TokenUnits >= capacity-refill {
		class.TokenUnits = capacity
	} else {
		class.TokenUnits += refill
	}
	class.LastRefillNanos = now
	return nil
}

func classLedger(ledger *permitLedger, class DialClass) *permitClassLedger {
	if class == DialClassDoH {
		return &ledger.DoH
	}
	return &ledger.Job
}

func classRate(manifest PolicyManifest, class DialClass) uint64 {
	if class == DialClassDoH {
		return manifest.DoHDialRate
	}
	return manifest.JobDialRate
}

func classBurst(manifest PolicyManifest, class DialClass) uint64 {
	if class == DialClassDoH {
		return manifest.DoHDialBurst
	}
	return manifest.JobDialBurst
}

func wasteReservations(class *permitClassLedger) {
	class.IssuedHighWater = class.ReservedHighWater
	class.IssuedSequence = class.ReservedSequence
}

func resetSequences(class *permitClassLedger) {
	class.IssuedSequence = 0
	class.ReservedSequence = 0
}
