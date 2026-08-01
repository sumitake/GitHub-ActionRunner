package networkjail

import (
	"context"
	"sync"
	"testing"
)

type fakeMonotonicClock struct {
	mu          sync.Mutex
	bootID      BootID
	monotonicNS uint64
}

func (c *fakeMonotonicClock) Observe(context.Context) (ClockObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ClockObservation{BootID: c.bootID, MonotonicNanos: c.monotonicNS}, nil
}

func (c *fakeMonotonicClock) advance(delta uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.monotonicNS += delta
}

func (c *fakeMonotonicClock) setMonotonic(value uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.monotonicNS = value
}

func (c *fakeMonotonicClock) setBoot(bootID BootID, monotonic uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bootID = bootID
	c.monotonicNS = monotonic
}

type memoryPermitStore struct {
	mu       sync.Mutex
	records  map[CapacitySlotID]permitLedger
	writes   int
	failNext bool
}

func newMemoryPermitStore() *memoryPermitStore {
	return &memoryPermitStore{records: make(map[CapacitySlotID]permitLedger)}
}

func (s *memoryPermitStore) load(
	_ context.Context,
	slot CapacitySlotID,
) (permitLedger, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.records[slot]
	return record, found, nil
}

func (s *memoryPermitStore) compareAndSwap(
	_ context.Context,
	slot CapacitySlotID,
	expectedRevision uint64,
	next permitLedger,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, found := s.records[slot]
	if (!found && expectedRevision != 0) || (found && current.Revision != expectedRevision) {
		return ErrPermitLedgerConflict
	}
	if s.failNext {
		s.failNext = false
		return ErrPermitAuthorityUnavailable
	}
	s.records[slot] = next
	s.writes++
	return nil
}

func (s *memoryPermitStore) delete(
	_ context.Context,
	slot CapacitySlotID,
	expectedRevision uint64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, found := s.records[slot]
	if !found || current.Revision != expectedRevision {
		return ErrPermitLedgerConflict
	}
	delete(s.records, slot)
	s.writes++
	return nil
}

func (s *memoryPermitStore) mustLoad(t *testing.T, slot CapacitySlotID) permitLedger {
	t.Helper()
	record, found, err := s.load(context.Background(), slot)
	if err != nil || !found {
		t.Fatalf("load ledger = found:%v err:%v", found, err)
	}
	return record
}

func (s *memoryPermitStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func (s *memoryPermitStore) failNextWrite() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = true
}

type acceptingPermitGuard struct{}

func (acceptingPermitGuard) ValidatePermitPeer(
	context.Context,
	CapacitySlotID,
	JobGeneration,
	DialClass,
	PermitPeer,
) error {
	return nil
}

type fakeReferenceGuard struct {
	mu         sync.Mutex
	referenced bool
}

func (g *fakeReferenceGuard) HasLedgerReferences(
	context.Context,
	CapacitySlotID,
) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.referenced, nil
}

func (g *fakeReferenceGuard) set(value bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.referenced = value
}

type fakeRebaseValidator struct {
	key [32]byte
}

func (v fakeRebaseValidator) ValidateEmptyConntrack(
	_ context.Context,
	slot CapacitySlotID,
	from BootID,
	to BootID,
	proof EmptyConntrackProof,
) error {
	if proof != newEmptyConntrackProof(v.key, slot, from, to) {
		return ErrEmptyConntrackProofInvalid
	}
	return nil
}

type permitFixture struct {
	t          *testing.T
	slot       CapacitySlotID
	tailNanos  uint64
	clock      *fakeMonotonicClock
	store      *memoryPermitStore
	references *fakeReferenceGuard
	validator  fakeRebaseValidator
	authority  *PermitAuthority
}

func newPermitFixture(t *testing.T, blockSize uint64) *permitFixture {
	t.Helper()
	manifest := validPolicyManifest()
	manifest.JobDialRate = 1
	manifest.JobDialBurst = blockSize
	manifest.DoHDialRate = 1
	manifest.DoHDialBurst = blockSize
	manifest.TailTimeoutSeconds = 5
	graph, _, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	fixture := &permitFixture{
		t:          t,
		slot:       3,
		tailNanos:  manifest.TailTimeoutSeconds * nanosPerSecond,
		clock:      &fakeMonotonicClock{bootID: testBootID(1), monotonicNS: 100},
		store:      newMemoryPermitStore(),
		references: &fakeReferenceGuard{},
		validator:  fakeRebaseValidator{key: [32]byte{1, 2, 3, 4}},
	}
	fixture.authority, err = newPermitAuthority(
		graph,
		fixture.clock,
		fixture.store,
		acceptingPermitGuard{},
		fixture.references,
		fixture.validator,
		blockSize,
	)
	if err != nil {
		t.Fatalf("newPermitAuthority: %v", err)
	}
	return fixture
}

func (f *permitFixture) activate(generation JobGeneration) {
	f.t.Helper()
	if err := f.authority.Activate(context.Background(), f.slot, generation); err != nil {
		f.t.Fatalf("Activate(%d): %v", generation, err)
	}
}

func (f *permitFixture) consume(
	generation JobGeneration,
	class DialClass,
	sequence uint64,
) (Permit, error) {
	return f.authority.Consume(
		context.Background(),
		DialPermitRequest{
			SlotID:        f.slot,
			JobGeneration: generation,
			Class:         class,
			Sequence:      PermitSequence(sequence),
		},
		newPermitPeer(51, 1001, 9001),
	)
}

func (f *permitFixture) restart(t *testing.T) *permitFixture {
	t.Helper()
	restarted := *f
	var err error
	restarted.authority, err = newPermitAuthority(
		f.authority.graph,
		f.clock,
		f.store,
		acceptingPermitGuard{},
		f.references,
		f.validator,
		f.authority.blockSize,
	)
	if err != nil {
		t.Fatalf("restart newPermitAuthority: %v", err)
	}
	return &restarted
}

func (f *permitFixture) rebaseProof() EmptyConntrackProof {
	state := f.store.mustLoad(f.t, f.slot)
	observation, err := f.clock.Observe(context.Background())
	if err != nil {
		f.t.Fatalf("Observe: %v", err)
	}
	if state.BootID == observation.BootID {
		f.t.Fatal("rebase proof requested without boot change")
	}
	return newEmptyConntrackProof(
		f.validator.key,
		f.slot,
		state.BootID,
		observation.BootID,
	)
}

func testBootID(marker byte) BootID {
	var boot BootID
	for index := range boot {
		boot[index] = marker
	}
	return boot
}

var _ MonotonicClock = (*fakeMonotonicClock)(nil)
var _ permitStore = (*memoryPermitStore)(nil)
var _ PermitPeerValidator = acceptingPermitGuard{}
var _ LedgerReferenceGuard = (*fakeReferenceGuard)(nil)
var _ EmptyConntrackValidator = fakeRebaseValidator{}
