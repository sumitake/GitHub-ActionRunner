package admission

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

type slotState uint8

const (
	slotLeased slotState = iota + 1
	slotReserved
	slotActive
	slotFree
	slotRetired
)

type capacitySlot struct {
	id              CapacitySlotID
	state           slotState
	repositoryAlias string
	fullCharge      Resources
	ledgerCharge    Resources
	leaseID         uint64
	expiresAt       time.Time
	assignment      controller.AssignmentKey

	ledgerCreatedAt time.Time
	tailUntil       time.Time
	ledgerEverUsed  bool
	retireOnRelease bool
	retired         bool
}

type queuedOffer struct {
	offer        githubscale.Offer
	reservedSlot CapacitySlotID
}

type offerIdentity struct {
	repositoryAlias string
	runnerRequestID int64
}

type liveOfferEntry struct {
	offer        githubscale.Offer
	logicalBytes uint64
}

type brokerImpl struct {
	mu sync.Mutex

	ceiling                  Resources
	configuredCapacity       int
	currentCapacity          int
	maxLiveReferences        int
	maxOfferLogicalBytes     uint64
	maxLiveOfferLogicalBytes uint64
	pollLeaseTTL             time.Duration
	ledgerTail               time.Duration
	transientMode            TransientMode
	now                      func() time.Time

	policyEpoch uint64
	policies    map[string]RepositoryPolicy
	aliases     []string
	queues      map[string][]*queuedOffer
	deficits    map[string]int64
	cursor      int

	used                  Resources
	slots                 map[CapacitySlotID]*capacitySlot
	assignments           map[controller.AssignmentKey]CapacitySlotID
	liveOffers            map[offerIdentity]liveOfferEntry
	liveOfferLogicalBytes uint64
	nextLeaseID           uint64
}

var _ Broker = (*brokerImpl)(nil)
var _ PolicyBroker = (*brokerImpl)(nil)
var _ LiveHistory = (*brokerImpl)(nil)

// NewBroker validates and copies the complete policy snapshot before making
// any capacity available.
func NewBroker(config Config) (PolicyBroker, error) {
	if config.MaxCapacity <= 0 || uint64(config.MaxCapacity) > uint64(math.MaxUint32) {
		return nil, fmt.Errorf("%w: MaxCapacity must fit a positive CapacitySlotID", ErrInvalidConfig)
	}
	if config.MaxLiveReferences <= 0 {
		return nil, fmt.Errorf("%w: MaxLiveReferences must be positive", ErrInvalidConfig)
	}
	if config.MaxOfferLogicalBytes == 0 {
		return nil, fmt.Errorf("%w: MaxOfferLogicalBytes must be positive", ErrInvalidConfig)
	}
	if config.MaxLiveOfferLogicalBytes < config.MaxOfferLogicalBytes {
		return nil, fmt.Errorf(
			"%w: MaxLiveOfferLogicalBytes must fit at least one MaxOfferLogicalBytes reservation",
			ErrInvalidConfig,
		)
	}
	if config.PollLeaseTTL <= 0 {
		return nil, fmt.Errorf("%w: PollLeaseTTL must be positive", ErrInvalidConfig)
	}
	if config.LedgerTail <= 0 {
		return nil, fmt.Errorf("%w: LedgerTail must be positive", ErrInvalidConfig)
	}
	if config.PolicyRevision == 0 {
		return nil, fmt.Errorf("%w: PolicyRevision must be positive", ErrInvalidConfig)
	}
	if config.Now == nil {
		return nil, fmt.Errorf("%w: Now must be provided", ErrInvalidConfig)
	}
	if err := config.Ceiling.validate("Ceiling"); err != nil {
		return nil, err
	}
	policies, aliases, err := validatePolicies(config.Repositories, config.TransientMode)
	if err != nil {
		return nil, err
	}

	queues := make(map[string][]*queuedOffer, len(aliases))
	for _, alias := range aliases {
		queues[alias] = nil
	}
	return &brokerImpl{
		ceiling:                  config.Ceiling,
		configuredCapacity:       config.MaxCapacity,
		currentCapacity:          config.MaxCapacity,
		maxLiveReferences:        config.MaxLiveReferences,
		maxOfferLogicalBytes:     config.MaxOfferLogicalBytes,
		maxLiveOfferLogicalBytes: config.MaxLiveOfferLogicalBytes,
		pollLeaseTTL:             config.PollLeaseTTL,
		ledgerTail:               config.LedgerTail,
		transientMode:            config.TransientMode,
		now:                      config.Now,
		policyEpoch:              config.PolicyRevision,
		policies:                 policies,
		aliases:                  aliases,
		queues:                   queues,
		deficits:                 make(map[string]int64, len(aliases)),
		// MaxCapacity is permitted to span the complete CapacitySlotID
		// domain. Do not turn that logical ceiling into an eager allocation.
		slots:       make(map[CapacitySlotID]*capacitySlot),
		assignments: make(map[controller.AssignmentKey]CapacitySlotID),
		liveOffers:  make(map[offerIdentity]liveOfferEntry),
	}, nil
}

func (b *brokerImpl) Enqueue(offer githubscale.Offer) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if err := b.cleanupLocked(now); err != nil {
		return err
	}
	_, err := b.enqueueBatchLocked([]githubscale.Offer{offer}, false, false)
	return err
}

func (b *brokerImpl) EnsureQueued(offer githubscale.Offer) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if err := b.cleanupLocked(now); err != nil {
		return err
	}
	_, err := b.enqueueBatchLocked([]githubscale.Offer{offer}, true, false)
	return err
}

func (b *brokerImpl) EnsureQueuedBatch(offers []githubscale.Offer) ([]LiveReference, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if err := b.cleanupLocked(now); err != nil {
		return nil, err
	}
	return b.enqueueBatchLocked(offers, true, true)
}

func (b *brokerImpl) Restore(refs []LiveReference) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.liveOffers) != 0 ||
		b.liveOfferLogicalBytes != 0 ||
		len(b.assignments) != 0 ||
		len(b.slots) != 0 ||
		b.used != (Resources{}) {
		return ErrRestoreNotEmpty
	}
	for _, queue := range b.queues {
		if len(queue) != 0 {
			return ErrRestoreNotEmpty
		}
	}
	if len(refs) > b.maxLiveReferences {
		return ErrLiveSetFull
	}

	ordered := append([]LiveReference(nil), refs...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if !left.Offer.QueueTime.Equal(right.Offer.QueueTime) {
			return left.Offer.QueueTime.Before(right.Offer.QueueTime)
		}
		if left.Key.RepositoryAlias != right.Key.RepositoryAlias {
			return left.Key.RepositoryAlias < right.Key.RepositoryAlias
		}
		if left.Key.RunnerRequestID != right.Key.RunnerRequestID {
			return left.Key.RunnerRequestID < right.Key.RunnerRequestID
		}
		return left.Key.Attempt < right.Key.Attempt
	})

	queues := make(map[string][]*queuedOffer, len(b.aliases))
	for _, alias := range b.aliases {
		queues[alias] = nil
	}
	liveOffers := make(map[offerIdentity]liveOfferEntry, len(ordered))
	var liveOfferLogicalBytes uint64
	slots := make(map[CapacitySlotID]*capacitySlot)
	assignments := make(map[controller.AssignmentKey]CapacitySlotID)
	used := Resources{}
	now := b.now()

	for _, ref := range ordered {
		if ref.Key.Attempt != 0 ||
			ref.Key.RepositoryAlias != ref.Offer.RepositoryName ||
			ref.Key.RunnerRequestID != ref.Offer.RunnerRequestID ||
			ref.Key.RunnerRequestID <= 0 {
			return fmt.Errorf("%w: inconsistent restore identity %+v", ErrInvalidOffer, ref.Key)
		}
		if _, ok := b.policies[ref.Key.RepositoryAlias]; !ok {
			return fmt.Errorf("%w: %q", ErrUnknownRepository, ref.Key.RepositoryAlias)
		}
		identity := offerIdentity{
			repositoryAlias: ref.Key.RepositoryAlias,
			runnerRequestID: ref.Key.RunnerRequestID,
		}
		if _, duplicate := liveOffers[identity]; duplicate {
			return fmt.Errorf("%w: %s/%d", ErrDuplicateOffer, identity.repositoryAlias, identity.runnerRequestID)
		}
		copied := cloneOffer(ref.Offer)
		logicalBytes, sizeErr := LiveOfferLogicalBytesV1(copied)
		if sizeErr != nil {
			return sizeErr
		}
		if logicalBytes > b.maxOfferLogicalBytes {
			return fmt.Errorf("%w: %s/%d", ErrOfferTooLarge, identity.repositoryAlias, identity.runnerRequestID)
		}
		nextLiveBytes, sizeErr := addLogicalBytes(liveOfferLogicalBytes, logicalBytes)
		if sizeErr != nil {
			return sizeErr
		}
		if nextLiveBytes > b.maxLiveOfferLogicalBytes {
			return ErrLiveBytesFull
		}
		liveOfferLogicalBytes = nextLiveBytes

		switch ref.Phase {
		case LiveQueued:
			if ref.SlotID != 0 ||
				ref.FullCharge != (Resources{}) ||
				ref.LedgerCharge != (Resources{}) ||
				!ref.LedgerCreatedAt.IsZero() ||
				ref.LedgerEverUsed {
				return fmt.Errorf("%w: queued restore carries slot or charge", ErrInvalidOffer)
			}
			queues[ref.Key.RepositoryAlias] = append(
				queues[ref.Key.RepositoryAlias],
				&queuedOffer{offer: copied},
			)

		case LiveReserved, LiveActive:
			if ref.SlotID == 0 || uint64(ref.SlotID) > uint64(b.configuredCapacity) {
				return fmt.Errorf("%w: restore slot %d is outside capacity", ErrInvalidOffer, ref.SlotID)
			}
			if _, duplicate := slots[ref.SlotID]; duplicate {
				return fmt.Errorf("%w: duplicate restore slot %d", ErrInvalidOffer, ref.SlotID)
			}
			if err := ref.FullCharge.validate("LiveReference.FullCharge"); err != nil {
				return fmt.Errorf("%w: invalid full charge: %v", ErrInvalidOffer, err)
			}
			if err := ref.LedgerCharge.validate("LiveReference.LedgerCharge"); err != nil {
				return fmt.Errorf("%w: invalid ledger charge: %v", ErrInvalidOffer, err)
			}
			if !validLedgerCharge(ref.LedgerCharge) ||
				!resourceAtMost(ref.LedgerCharge, ref.FullCharge) ||
				ref.LedgerCreatedAt.IsZero() ||
				ref.LedgerCreatedAt.After(now) {
				return fmt.Errorf("%w: inconsistent persisted charge", ErrInvalidOffer)
			}
			next, err := addResources(used, ref.FullCharge)
			if err != nil || !resourceAtMost(next, b.ceiling) {
				return fmt.Errorf("%w: restored resources exceed ceiling", ErrResourceOverflow)
			}
			used = next

			state := slotReserved
			if ref.Phase == LiveActive {
				state = slotActive
			}
			slot := &capacitySlot{
				id:              ref.SlotID,
				state:           state,
				repositoryAlias: ref.Key.RepositoryAlias,
				fullCharge:      ref.FullCharge,
				ledgerCharge:    ref.LedgerCharge,
				ledgerCreatedAt: ref.LedgerCreatedAt,
				ledgerEverUsed:  ref.LedgerEverUsed || ref.Phase == LiveActive,
			}
			if ref.Phase == LiveReserved {
				queues[ref.Key.RepositoryAlias] = append(
					queues[ref.Key.RepositoryAlias],
					&queuedOffer{offer: copied, reservedSlot: ref.SlotID},
				)
			} else {
				slot.assignment = ref.Key
				assignments[ref.Key] = ref.SlotID
			}
			slots[ref.SlotID] = slot

		default:
			return fmt.Errorf("%w: unsupported restore phase %d", ErrInvalidOffer, ref.Phase)
		}
		liveOffers[identity] = liveOfferEntry{offer: copied, logicalBytes: logicalBytes}
	}

	b.queues = queues
	b.liveOffers = liveOffers
	b.liveOfferLogicalBytes = liveOfferLogicalBytes
	b.slots = slots
	b.assignments = assignments
	b.used = used
	b.deficits = make(map[string]int64, len(b.aliases))
	b.cursor = 0
	return nil
}

func (b *brokerImpl) Retire(key controller.AssignmentKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if key.Attempt != 0 {
		return fmt.Errorf("%w: unsupported attempt %d", ErrInvalidOffer, key.Attempt)
	}
	identity := offerIdentity{
		repositoryAlias: key.RepositoryAlias,
		runnerRequestID: key.RunnerRequestID,
	}
	entry, live := b.liveOffers[identity]
	if !live {
		return nil
	}
	if b.liveOfferLogicalBytes < entry.logicalBytes {
		return ErrResourceOverflow
	}
	if _, active := b.assignments[key]; active {
		return fmt.Errorf("%w: %+v", ErrLiveReferenceActive, key)
	}
	queue := b.queues[key.RepositoryAlias]
	for i, queued := range queue {
		if queued.offer.RunnerRequestID != key.RunnerRequestID {
			continue
		}
		if queued.reservedSlot != 0 {
			slot := b.slots[queued.reservedSlot]
			if slot == nil || slot.state != slotReserved {
				return fmt.Errorf("%w: stale reservation for %+v", ErrInvalidOffer, key)
			}
			if err := b.cancelNonActiveSlotLocked(slot, b.now()); err != nil {
				return err
			}
		}
		copy(queue[i:], queue[i+1:])
		queue[len(queue)-1] = nil
		b.queues[key.RepositoryAlias] = queue[:len(queue)-1]
		b.liveOfferLogicalBytes -= entry.logicalBytes
		delete(b.liveOffers, identity)
		return nil
	}
	b.liveOfferLogicalBytes -= entry.logicalBytes
	delete(b.liveOffers, identity)
	return nil
}

func (b *brokerImpl) HasLiveReference(key controller.AssignmentKey) bool {
	if key.Attempt != 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.liveOffers[offerIdentity{
		repositoryAlias: key.RepositoryAlias,
		runnerRequestID: key.RunnerRequestID,
	}]
	return ok
}

type stagedQueuedOffer struct {
	identity offerIdentity
	entry    liveOfferEntry
	slot     *capacitySlot
}

func (b *brokerImpl) enqueueBatchLocked(
	offers []githubscale.Offer,
	idempotent bool,
	project bool,
) ([]LiveReference, error) {
	seenInput := make(map[offerIdentity]githubscale.Offer, len(offers))
	resultIdentities := make([]offerIdentity, 0, len(offers))
	staged := make([]stagedQueuedOffer, 0, len(offers))
	var stagedLogicalBytes uint64

	for _, offer := range offers {
		alias := offer.RepositoryName
		if _, ok := b.policies[alias]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownRepository, alias)
		}
		if offer.RunnerRequestID <= 0 {
			return nil, fmt.Errorf("%w: RunnerRequestID must be positive", ErrInvalidOffer)
		}
		identity := offerIdentity{
			repositoryAlias: alias,
			runnerRequestID: offer.RunnerRequestID,
		}
		if prior, duplicate := seenInput[identity]; duplicate {
			if !idempotent {
				return nil, fmt.Errorf("%w: %s/%d", ErrDuplicateOffer, alias, offer.RunnerRequestID)
			}
			if !sameSchedulingProjection(prior, offer) {
				return nil, fmt.Errorf("%w: %s/%d", ErrOfferConflict, alias, offer.RunnerRequestID)
			}
			continue
		}
		seenInput[identity] = offer
		resultIdentities = append(resultIdentities, identity)

		if existing, duplicate := b.liveOffers[identity]; duplicate {
			if !idempotent {
				return nil, fmt.Errorf("%w: %s/%d", ErrDuplicateOffer, alias, offer.RunnerRequestID)
			}
			if !sameSchedulingProjection(existing.offer, offer) {
				return nil, fmt.Errorf("%w: %s/%d", ErrOfferConflict, alias, offer.RunnerRequestID)
			}
			continue
		}

		copied := cloneOffer(offer)
		logicalBytes, err := LiveOfferLogicalBytesV1(copied)
		if err != nil {
			return nil, err
		}
		if logicalBytes > b.maxOfferLogicalBytes {
			return nil, fmt.Errorf("%w: %s/%d", ErrOfferTooLarge, alias, offer.RunnerRequestID)
		}
		stagedLogicalBytes, err = addLogicalBytes(stagedLogicalBytes, logicalBytes)
		if err != nil {
			return nil, err
		}
		staged = append(staged, stagedQueuedOffer{
			identity: identity,
			entry: liveOfferEntry{
				offer:        copied,
				logicalBytes: logicalBytes,
			},
		})
	}

	leasedByAlias := make(map[string][]*capacitySlot)
	leaseCursor := make(map[string]int)
	consumedLeases := 0
	for i := range staged {
		alias := staged[i].identity.repositoryAlias
		slots, loaded := leasedByAlias[alias]
		if !loaded {
			slots = b.leasedSlotsLocked(alias)
			leasedByAlias[alias] = slots
		}
		cursor := leaseCursor[alias]
		if cursor < len(slots) {
			staged[i].slot = slots[cursor]
			leaseCursor[alias] = cursor + 1
			consumedLeases++
		}
	}

	prospectiveLiveCommitments, err := addLogicalBytes(
		uint64(len(b.liveOffers)),
		uint64(b.leasedCountLocked()),
		uint64(len(staged)),
	)
	if err != nil {
		return nil, err
	}
	if prospectiveLiveCommitments < uint64(consumedLeases) {
		return nil, ErrResourceOverflow
	}
	prospectiveLiveCommitments -= uint64(consumedLeases)
	if prospectiveLiveCommitments > uint64(b.maxLiveReferences) {
		return nil, ErrLiveSetFull
	}
	committedBytes, err := b.liveOfferCommitmentBytesLocked()
	if err != nil {
		return nil, err
	}
	consumedLeaseBytes, err := multiplyLogicalBytes(
		uint64(consumedLeases),
		b.maxOfferLogicalBytes,
	)
	if err != nil {
		return nil, err
	}
	if committedBytes < consumedLeaseBytes {
		return nil, ErrResourceOverflow
	}
	prospectiveCommittedBytes, err := addLogicalBytes(
		committedBytes-consumedLeaseBytes,
		stagedLogicalBytes,
	)
	if err != nil {
		return nil, err
	}
	if prospectiveCommittedBytes > b.maxLiveOfferLogicalBytes {
		return nil, ErrLiveBytesFull
	}
	nextLiveBytes, err := addLogicalBytes(b.liveOfferLogicalBytes, stagedLogicalBytes)
	if err != nil {
		return nil, err
	}

	var refs []LiveReference
	if project {
		refs = make([]LiveReference, 0, len(resultIdentities))
		for _, identity := range resultIdentities {
			if _, existing := b.liveOffers[identity]; !existing {
				continue
			}
			ref, refErr := b.liveReferenceLocked(identity)
			if refErr != nil {
				return nil, refErr
			}
			refs = append(refs, ref)
		}
		for _, pending := range staged {
			ref := LiveReference{
				Key: controller.AssignmentKey{
					RepositoryAlias: pending.identity.repositoryAlias,
					RunnerRequestID: pending.identity.runnerRequestID,
					Attempt:         0,
				},
				Offer: cloneOffer(pending.entry.offer),
				Phase: LiveQueued,
			}
			if pending.slot != nil {
				ref.Phase = LiveReserved
				ref.SlotID = pending.slot.id
				ref.FullCharge = pending.slot.fullCharge
				ref.LedgerCharge = pending.slot.ledgerCharge
				ref.LedgerCreatedAt = pending.slot.ledgerCreatedAt
				ref.LedgerEverUsed = pending.slot.ledgerEverUsed
			}
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Key.RepositoryAlias != refs[j].Key.RepositoryAlias {
				return refs[i].Key.RepositoryAlias < refs[j].Key.RepositoryAlias
			}
			if refs[i].Key.RunnerRequestID != refs[j].Key.RunnerRequestID {
				return refs[i].Key.RunnerRequestID < refs[j].Key.RunnerRequestID
			}
			return refs[i].Key.Attempt < refs[j].Key.Attempt
		})
	}

	for _, pending := range staged {
		queued := &queuedOffer{offer: pending.entry.offer}
		if pending.slot != nil {
			pending.slot.state = slotReserved
			queued.reservedSlot = pending.slot.id
		}
		alias := pending.identity.repositoryAlias
		b.queues[alias] = append(b.queues[alias], queued)
		b.liveOffers[pending.identity] = pending.entry
	}
	b.liveOfferLogicalBytes = nextLiveBytes
	return refs, nil
}

func (b *brokerImpl) LeasePoll(repo string, now time.Time) (CapacityLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.cleanupLocked(now); err != nil {
		return CapacityLease{}, err
	}
	policy, ok := b.policies[repo]
	if !ok {
		return CapacityLease{}, fmt.Errorf("%w: %q", ErrUnknownRepository, repo)
	}
	leaseID, err := b.nextLeaseIDLocked()
	if err != nil {
		return CapacityLease{}, err
	}
	lease := CapacityLease{
		ID:              leaseID,
		RepositoryAlias: repo,
		Epoch:           b.policyEpoch,
		ExpiresAt:       now.Add(b.pollLeaseTTL),
	}
	if policy.Eligibility != EligibilityActive {
		return lease, nil
	}

	repositoryAvailable := int64(policy.MaxConcurrency) - int64(b.ownedCountLocked(repo))
	fleetAvailable := int64(b.currentCapacity - b.occupiedCountLocked())
	liveAvailable := int64(b.maxLiveReferences - len(b.liveOffers) - b.leasedCountLocked())
	committedBytes, err := b.liveOfferCommitmentBytesLocked()
	if err != nil {
		return CapacityLease{}, err
	}
	byteAvailable := (b.maxLiveOfferLogicalBytes - committedBytes) / b.maxOfferLogicalBytes
	for repositoryAvailable > 0 && fleetAvailable > 0 && liveAvailable > 0 && byteAvailable > 0 {
		slot, allocated, allocateErr := b.allocateSlotLocked(
			repo,
			policy.Profile,
			slotLeased,
			lease.ID,
			lease.ExpiresAt,
			now,
		)
		if allocateErr != nil {
			return CapacityLease{}, allocateErr
		}
		if !allocated {
			break
		}
		slot.leaseID = lease.ID
		lease.Reserved++
		repositoryAvailable--
		fleetAvailable--
		liveAvailable--
		byteAvailable--
	}
	lease.MaxCapacity = b.ownedCountLocked(repo)
	return lease, nil
}

func (b *brokerImpl) Admit(now time.Time) ([]Decision, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.cleanupLocked(now); err != nil {
		return nil, err
	}
	// currentCapacity spans the full CapacitySlotID domain and is a logical
	// limit, not a safe allocation hint.
	decisions := make([]Decision, 0)
	for {
		alias, queued, aged := b.selectAgedLocked(now)
		weighted := false
		if queued == nil {
			alias, queued = b.selectWeightedLocked()
			weighted = queued != nil
		}
		if queued == nil {
			break
		}

		decision, err := b.admitLocked(alias, queued, now)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
		if weighted && !aged {
			b.afterWeightedAdmissionLocked(alias)
		}
	}
	return decisions, nil
}

func (b *brokerImpl) SetPressure(pressure Pressure) (CapacityChange, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	previous := b.currentCapacity
	if pressure.MaxCapacity < 0 {
		return CapacityChange{Previous: previous, Current: previous},
			fmt.Errorf("%w: negative capacity", ErrInvalidConfig)
	}
	if pressure.MaxCapacity > previous {
		return CapacityChange{Previous: previous, Current: previous}, ErrPressureIncrease
	}
	if pressure.MaxCapacity == previous {
		return CapacityChange{Previous: previous, Current: previous}, nil
	}
	now := b.now()
	if err := b.cleanupLocked(now); err != nil {
		return CapacityChange{Previous: previous, Current: previous}, err
	}

	b.currentCapacity = pressure.MaxCapacity
	for b.occupiedCountLocked() > b.currentCapacity {
		slot := b.highestNonActiveOccupiedSlotLocked()
		if slot == nil {
			break
		}
		if err := b.cancelNonActiveSlotLocked(slot, now); err != nil {
			b.currentCapacity = previous
			return CapacityChange{Previous: previous, Current: previous}, err
		}
	}

	for id, slot := range b.slots {
		if int(id) <= b.currentCapacity {
			continue
		}
		switch slot.state {
		case slotActive:
			slot.retireOnRelease = true
		case slotFree:
			slot.state = slotRetired
			slot.retired = true
		case slotLeased, slotReserved:
			if err := b.cancelNonActiveSlotLocked(slot, now); err != nil {
				return CapacityChange{Previous: previous, Current: b.currentCapacity}, err
			}
		}
	}
	return CapacityChange{Previous: previous, Current: b.currentCapacity}, nil
}

func (b *brokerImpl) Release(key controller.AssignmentKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	id, ok := b.assignments[key]
	if !ok {
		return fmt.Errorf("%w: %+v", ErrUnknownAssignment, key)
	}
	slot := b.slots[id]
	if slot == nil || slot.state != slotActive || slot.assignment != key {
		return fmt.Errorf("%w: inconsistent slot for %+v", ErrUnknownAssignment, key)
	}
	base, err := subtractResources(b.used, slot.fullCharge)
	if err != nil {
		return err
	}
	next, err := addResources(base, slot.ledgerCharge)
	if err != nil {
		return err
	}
	b.used = next
	delete(b.assignments, key)

	slot.assignment = controller.AssignmentKey{}
	slot.repositoryAlias = ""
	slot.leaseID = 0
	slot.expiresAt = time.Time{}
	slot.tailUntil = b.now().Add(b.ledgerTail)
	slot.ledgerEverUsed = true
	if slot.retireOnRelease || int(slot.id) > b.currentCapacity {
		slot.state = slotRetired
		slot.retired = true
	} else {
		slot.state = slotFree
		slot.retired = false
	}
	return nil
}

func (b *brokerImpl) ApplyPolicyRevision(revision PolicyRevision) error {
	policies, aliases, err := validatePolicies(revision.Repositories, b.transientMode)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if revision.Epoch <= b.policyEpoch {
		return ErrStalePolicyRevision
	}
	for identity := range b.liveOffers {
		if _, retained := policies[identity.repositoryAlias]; !retained {
			return fmt.Errorf("%w: %q", ErrPolicyInUse, identity.repositoryAlias)
		}
	}
	now := b.now()
	if err := b.cleanupLocked(now); err != nil {
		return err
	}
	for _, id := range b.sortedSlotIDsLocked() {
		slot := b.slots[id]
		if slot != nil && (slot.state == slotLeased || slot.state == slotReserved) {
			if err := b.cancelNonActiveSlotLocked(slot, now); err != nil {
				return err
			}
		}
	}

	b.policies = policies
	b.aliases = aliases
	b.policyEpoch = revision.Epoch
	b.deficits = make(map[string]int64, len(aliases))
	b.cursor = 0
	for _, alias := range aliases {
		if _, ok := b.queues[alias]; !ok {
			b.queues[alias] = nil
		}
	}
	return nil
}

func (b *brokerImpl) selectAgedLocked(now time.Time) (string, *queuedOffer, bool) {
	var selectedAlias string
	var selected *queuedOffer
	for _, alias := range b.aliases {
		queue := b.queues[alias]
		if len(queue) == 0 {
			continue
		}
		candidate := queue[0]
		policy := b.policies[alias]
		if candidate.offer.QueueTime.IsZero() ||
			now.Before(candidate.offer.QueueTime) ||
			now.Sub(candidate.offer.QueueTime) < policy.AgingThreshold ||
			!b.canAdmitLocked(alias, candidate) {
			continue
		}
		if selected == nil ||
			candidate.offer.QueueTime.Before(selected.offer.QueueTime) ||
			(candidate.offer.QueueTime.Equal(selected.offer.QueueTime) &&
				(alias < selectedAlias ||
					(alias == selectedAlias &&
						candidate.offer.RunnerRequestID < selected.offer.RunnerRequestID))) {
			selectedAlias = alias
			selected = candidate
		}
	}
	return selectedAlias, selected, selected != nil
}

func (b *brokerImpl) selectWeightedLocked() (string, *queuedOffer) {
	if len(b.aliases) == 0 {
		return "", nil
	}
	for visited := 0; visited < len(b.aliases); visited++ {
		if b.cursor >= len(b.aliases) {
			b.cursor = 0
		}
		alias := b.aliases[b.cursor]
		queue := b.queues[alias]
		if len(queue) == 0 {
			b.deficits[alias] = 0
			b.advanceCursorLocked()
			continue
		}
		if b.deficits[alias] <= 0 {
			b.deficits[alias] += int64(b.policies[alias].Weight)
		}
		if b.canAdmitLocked(alias, queue[0]) {
			return alias, queue[0]
		}
		b.advanceCursorLocked()
	}
	return "", nil
}

func (b *brokerImpl) afterWeightedAdmissionLocked(alias string) {
	b.deficits[alias]--
	if b.deficits[alias] <= 0 || len(b.queues[alias]) == 0 {
		if len(b.queues[alias]) == 0 {
			b.deficits[alias] = 0
		}
		b.advanceCursorLocked()
	}
}

func (b *brokerImpl) advanceCursorLocked() {
	if len(b.aliases) == 0 {
		b.cursor = 0
		return
	}
	b.cursor = (b.cursor + 1) % len(b.aliases)
}

func (b *brokerImpl) canAdmitLocked(alias string, queued *queuedOffer) bool {
	policy, ok := b.policies[alias]
	if !ok || policy.Eligibility != EligibilityActive {
		return false
	}
	if queued.reservedSlot != 0 {
		slot := b.slots[queued.reservedSlot]
		return slot != nil &&
			slot.state == slotReserved &&
			slot.repositoryAlias == alias
	}
	if uint64(b.ownedCountLocked(alias)) >= uint64(policy.MaxConcurrency) {
		return false
	}
	if b.occupiedCountLocked() >= b.currentCapacity {
		return false
	}
	return b.profileCanAllocateLocked(policy.Profile)
}

func (b *brokerImpl) profileCanAllocateLocked(profile SlotResources) bool {
	full, ledger, err := profile.charges(b.transientMode)
	if err != nil {
		return false
	}
	for _, id := range b.sortedSlotIDsLocked() {
		slot := b.slots[id]
		if slot == nil || slot.state != slotFree {
			continue
		}
		effectiveFull, _, chargeErr := retainedReuseCharges(full, ledger, slot.ledgerCharge)
		if chargeErr != nil {
			return false
		}
		base, subtractErr := subtractResources(b.used, slot.ledgerCharge)
		if subtractErr == nil && resourcesFit(base, effectiveFull, b.ceiling) {
			return true
		}
	}
	if b.firstUnusedSlotIDLocked() == 0 {
		return false
	}
	return resourcesFit(b.used, full, b.ceiling)
}

func (b *brokerImpl) admitLocked(alias string, queued *queuedOffer, now time.Time) (Decision, error) {
	policy := b.policies[alias]
	var slot *capacitySlot
	if queued.reservedSlot != 0 {
		slot = b.slots[queued.reservedSlot]
		if slot == nil || slot.state != slotReserved || slot.repositoryAlias != alias {
			return Decision{}, fmt.Errorf("%w: stale reservation for %s/%d",
				ErrInvalidOffer, alias, queued.offer.RunnerRequestID)
		}
	} else {
		var allocated bool
		var err error
		slot, allocated, err = b.allocateSlotLocked(
			alias,
			policy.Profile,
			slotActive,
			0,
			time.Time{},
			now,
		)
		if err != nil {
			return Decision{}, err
		}
		if !allocated {
			return Decision{}, fmt.Errorf("%w: selected offer no longer fits", ErrResourceOverflow)
		}
	}

	key := controller.AssignmentKey{
		RepositoryAlias: alias,
		RunnerRequestID: queued.offer.RunnerRequestID,
		// state.Store.UpsertOffer persists the initial acquisition offer as
		// attempt zero. Admission must preserve that exact durable identity;
		// a later retry mechanism may allocate a higher attempt explicitly,
		// but the broker must never manufacture one independently.
		Attempt: 0,
	}
	slot.state = slotActive
	slot.assignment = key
	slot.leaseID = 0
	slot.expiresAt = time.Time{}
	slot.ledgerEverUsed = true
	b.assignments[key] = slot.id
	b.queues[alias] = b.queues[alias][1:]

	return Decision{
		Assignment: key,
		Offer:      cloneOffer(queued.offer),
		SlotID:     slot.id,
	}, nil
}

func (b *brokerImpl) allocateSlotLocked(
	alias string,
	profile SlotResources,
	state slotState,
	leaseID uint64,
	expiresAt time.Time,
	now time.Time,
) (*capacitySlot, bool, error) {
	full, ledger, err := profile.charges(b.transientMode)
	if err != nil {
		return nil, false, err
	}
	for _, id := range b.sortedSlotIDsLocked() {
		slot := b.slots[id]
		if slot == nil || slot.state != slotFree {
			continue
		}
		effectiveFull, effectiveLedger, chargeErr := retainedReuseCharges(full, ledger, slot.ledgerCharge)
		if chargeErr != nil {
			return nil, false, chargeErr
		}
		base, subtractErr := subtractResources(b.used, slot.ledgerCharge)
		if subtractErr != nil {
			return nil, false, subtractErr
		}
		if !resourcesFit(base, effectiveFull, b.ceiling) {
			continue
		}
		next, addErr := addResources(base, effectiveFull)
		if addErr != nil {
			return nil, false, addErr
		}
		b.used = next
		slot.state = state
		slot.repositoryAlias = alias
		slot.fullCharge = effectiveFull
		slot.ledgerCharge = effectiveLedger
		slot.leaseID = leaseID
		slot.expiresAt = expiresAt
		slot.assignment = controller.AssignmentKey{}
		slot.tailUntil = time.Time{}
		slot.retireOnRelease = false
		slot.retired = false
		return slot, true, nil
	}

	id := b.firstUnusedSlotIDLocked()
	if id == 0 || !resourcesFit(b.used, full, b.ceiling) {
		return nil, false, nil
	}
	next, err := addResources(b.used, full)
	if err != nil {
		return nil, false, err
	}
	slot := &capacitySlot{
		id:              id,
		state:           state,
		repositoryAlias: alias,
		fullCharge:      full,
		ledgerCharge:    ledger,
		leaseID:         leaseID,
		expiresAt:       expiresAt,
		ledgerCreatedAt: now,
	}
	b.used = next
	b.slots[id] = slot
	return slot, true, nil
}

func (b *brokerImpl) cleanupLocked(now time.Time) error {
	for _, id := range b.sortedSlotIDsLocked() {
		slot := b.slots[id]
		if slot == nil {
			continue
		}
		switch slot.state {
		case slotLeased, slotReserved:
			if !slot.expiresAt.IsZero() && !now.Before(slot.expiresAt) {
				if err := b.cancelNonActiveSlotLocked(slot, now); err != nil {
					return err
				}
			}
		case slotFree, slotRetired:
			if !slot.tailUntil.IsZero() && !now.Before(slot.tailUntil) {
				next, err := subtractResources(b.used, slot.ledgerCharge)
				if err != nil {
					return err
				}
				b.used = next
				delete(b.slots, id)
			}
		}
	}
	return nil
}

func (b *brokerImpl) cancelNonActiveSlotLocked(slot *capacitySlot, now time.Time) error {
	if slot.state != slotLeased && slot.state != slotReserved {
		return nil
	}
	if slot.state == slotReserved {
		b.clearQueueReservationLocked(slot.id)
	}
	base, err := subtractResources(b.used, slot.fullCharge)
	if err != nil {
		return err
	}
	if !slot.ledgerEverUsed {
		b.used = base
		delete(b.slots, slot.id)
		return nil
	}
	next, err := addResources(base, slot.ledgerCharge)
	if err != nil {
		return err
	}
	b.used = next
	slot.repositoryAlias = ""
	slot.leaseID = 0
	slot.expiresAt = time.Time{}
	slot.assignment = controller.AssignmentKey{}
	slot.tailUntil = now.Add(b.ledgerTail)
	if slot.retireOnRelease || int(slot.id) > b.currentCapacity {
		slot.state = slotRetired
		slot.retired = true
	} else {
		slot.state = slotFree
		slot.retired = false
	}
	return nil
}

func (b *brokerImpl) clearQueueReservationLocked(id CapacitySlotID) {
	for _, queue := range b.queues {
		for _, queued := range queue {
			if queued.reservedSlot == id {
				queued.reservedSlot = 0
				return
			}
		}
	}
}

func (b *brokerImpl) leasedSlotsLocked(alias string) []*capacitySlot {
	var selected []*capacitySlot
	for _, slot := range b.slots {
		if slot.state != slotLeased || slot.repositoryAlias != alias {
			continue
		}
		selected = append(selected, slot)
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].leaseID != selected[j].leaseID {
			return selected[i].leaseID < selected[j].leaseID
		}
		return selected[i].id < selected[j].id
	})
	return selected
}

func (b *brokerImpl) liveOfferCommitmentBytesLocked() (uint64, error) {
	if b.liveOfferLogicalBytes > b.maxLiveOfferLogicalBytes {
		return 0, ErrResourceOverflow
	}
	remaining := b.maxLiveOfferLogicalBytes - b.liveOfferLogicalBytes
	leased := uint64(b.leasedCountLocked())
	if leased > remaining/b.maxOfferLogicalBytes {
		return 0, ErrResourceOverflow
	}
	reserved := leased * b.maxOfferLogicalBytes
	return addLogicalBytes(b.liveOfferLogicalBytes, reserved)
}

func multiplyLogicalBytes(count, size uint64) (uint64, error) {
	if count != 0 && size > math.MaxUint64/count {
		return 0, ErrResourceOverflow
	}
	return count * size, nil
}

func (b *brokerImpl) liveReferenceLocked(identity offerIdentity) (LiveReference, error) {
	entry, ok := b.liveOffers[identity]
	if !ok {
		return LiveReference{}, fmt.Errorf(
			"%w: missing live identity %s/%d",
			ErrInvalidOffer,
			identity.repositoryAlias,
			identity.runnerRequestID,
		)
	}
	key := controller.AssignmentKey{
		RepositoryAlias: identity.repositoryAlias,
		RunnerRequestID: identity.runnerRequestID,
		Attempt:         0,
	}
	if slotID, active := b.assignments[key]; active {
		slot := b.slots[slotID]
		if slot == nil || slot.state != slotActive || slot.assignment != key {
			return LiveReference{}, fmt.Errorf("%w: inconsistent active live reference", ErrInvalidOffer)
		}
		return LiveReference{
			Key:             key,
			Offer:           cloneOffer(entry.offer),
			Phase:           LiveActive,
			SlotID:          slot.id,
			FullCharge:      slot.fullCharge,
			LedgerCharge:    slot.ledgerCharge,
			LedgerCreatedAt: slot.ledgerCreatedAt,
			LedgerEverUsed:  slot.ledgerEverUsed,
		}, nil
	}
	for _, queued := range b.queues[identity.repositoryAlias] {
		if queued.offer.RunnerRequestID != identity.runnerRequestID {
			continue
		}
		ref := LiveReference{
			Key:   key,
			Offer: cloneOffer(entry.offer),
			Phase: LiveQueued,
		}
		if queued.reservedSlot == 0 {
			return ref, nil
		}
		slot := b.slots[queued.reservedSlot]
		if slot == nil || slot.state != slotReserved {
			return LiveReference{}, fmt.Errorf("%w: inconsistent reserved live reference", ErrInvalidOffer)
		}
		ref.Phase = LiveReserved
		ref.SlotID = slot.id
		ref.FullCharge = slot.fullCharge
		ref.LedgerCharge = slot.ledgerCharge
		ref.LedgerCreatedAt = slot.ledgerCreatedAt
		ref.LedgerEverUsed = slot.ledgerEverUsed
		return ref, nil
	}
	return LiveReference{}, fmt.Errorf("%w: live identity has no restorable phase", ErrInvalidOffer)
}

func (b *brokerImpl) ownedCountLocked(alias string) int {
	count := 0
	for _, slot := range b.slots {
		if slot.repositoryAlias != alias {
			continue
		}
		switch slot.state {
		case slotLeased, slotReserved, slotActive:
			count++
		}
	}
	return count
}

func (b *brokerImpl) occupiedCountLocked() int {
	count := 0
	for _, slot := range b.slots {
		switch slot.state {
		case slotLeased, slotReserved, slotActive:
			count++
		}
	}
	return count
}

func (b *brokerImpl) leasedCountLocked() int {
	count := 0
	for _, slot := range b.slots {
		if slot.state == slotLeased {
			count++
		}
	}
	return count
}

func (b *brokerImpl) highestNonActiveOccupiedSlotLocked() *capacitySlot {
	var selected *capacitySlot
	for _, slot := range b.slots {
		if slot.state != slotLeased && slot.state != slotReserved {
			continue
		}
		if selected == nil || slot.id > selected.id {
			selected = slot
		}
	}
	return selected
}

func (b *brokerImpl) firstUnusedSlotIDLocked() CapacitySlotID {
	for candidate := 1; candidate <= b.configuredCapacity; candidate++ {
		id := CapacitySlotID(candidate)
		if _, exists := b.slots[id]; !exists {
			return id
		}
	}
	return 0
}

func (b *brokerImpl) sortedSlotIDsLocked() []CapacitySlotID {
	ids := make([]CapacitySlotID, 0, len(b.slots))
	for id := range b.slots {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return ids
}

func (b *brokerImpl) nextLeaseIDLocked() (uint64, error) {
	if b.nextLeaseID == math.MaxUint64 {
		return 0, ErrResourceOverflow
	}
	b.nextLeaseID++
	return b.nextLeaseID, nil
}

func cloneOffer(offer githubscale.Offer) githubscale.Offer {
	copied := offer
	copied.RequestLabels = append([]string(nil), offer.RequestLabels...)
	return copied
}

func sameSchedulingProjection(a, b githubscale.Offer) bool {
	return a.RepositoryName == b.RepositoryName &&
		a.RunnerRequestID == b.RunnerRequestID &&
		a.QueueTime.Equal(b.QueueTime)
}

func validLedgerCharge(charge Resources) bool {
	return charge.MilliCPU == 0 &&
		charge.MemoryBytes == 0 &&
		charge.PIDs == 0 &&
		charge.FileDescriptors == 0 &&
		charge.TmpfsBytes == 0 &&
		charge.ScratchBytes == 0
}
