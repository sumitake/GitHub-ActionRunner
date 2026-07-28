// Package admission provides fleet-wide resource accounting, fair
// repository scheduling, and bounded poll-capacity leases.
package admission

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

// Resources is the canonical multi-dimensional resource vector charged for
// every complete runner slot and retained ledger tail.
type Resources struct {
	MilliCPU          int64
	MemoryBytes       int64
	PIDs              int64
	FileDescriptors   int64
	TmpfsBytes        int64
	ScratchBytes      int64
	SocketStateBytes  int64
	DurableStateBytes int64
	Inodes            int64
}

// SlotResources lists every component of one complete runner slot.
type SlotResources struct {
	Runner        Resources
	Adapter       Resources
	Broker        Resources
	DialAuthority Resources
	Helper        Resources
	Verifier      Resources
}

// Eligibility is the acquisition latch state for one repository.
type Eligibility string

const (
	EligibilityActive              Eligibility = "active"
	EligibilityArchivedDisabled    Eligibility = "archived-disabled"
	EligibilityPendingReactivation Eligibility = "pending-reactivation"
)

// RepositoryPolicy is one revision-bound repository admission policy.
//
// Alias is matched against githubscale.Offer.RepositoryName because the
// canonical Enqueue signature carries no separate fleet alias. Callers must
// therefore translate their configured repository alias into that field
// before enqueueing.
type RepositoryPolicy struct {
	Alias          string
	Weight         uint32
	MaxConcurrency uint32
	Eligibility    Eligibility
	AgingThreshold time.Duration
	Profile        SlotResources
}

// CapacitySlotID is the stable, bounded identity of one scheduling slot and
// its egress ledger.
type CapacitySlotID uint32

// CapacityChange reports an exact pressure transition.
type CapacityChange struct {
	Previous int
	Current  int
}

// Pressure may only reduce the broker's effective scheduling capacity.
type Pressure struct {
	MaxCapacity int
}

// TransientMode declares whether Helper and Verifier peaks are serialized
// per slot or may overlap.
type TransientMode string

const (
	TransientSerialized TransientMode = "serialized"
	TransientConcurrent TransientMode = "concurrent"
)

// Config constructs the in-memory admission broker.
type Config struct {
	Ceiling     Resources
	MaxCapacity int
	// MaxLiveReferences is an explicit bound on queued, reserved, active, and
	// not-yet-consumed poll commitments. It has no production default.
	MaxLiveReferences int
	// MaxOfferLogicalBytes bounds one retained Offer's V1 logical size.
	// MaxLiveOfferLogicalBytes bounds all retained offers plus a worst-case
	// MaxOfferLogicalBytes reservation for each unconsumed poll slot. Neither
	// has a production default.
	MaxOfferLogicalBytes     uint64
	MaxLiveOfferLogicalBytes uint64
	PollLeaseTTL             time.Duration
	LedgerTail               time.Duration
	TransientMode            TransientMode
	PolicyRevision           uint64
	Repositories             []RepositoryPolicy

	// Now is injected so Release and guarded ledger GC remain deterministic.
	Now func() time.Time
}

// PolicyRevision is the only input that may change repository eligibility.
// Epoch must increase strictly.
type PolicyRevision struct {
	Epoch        uint64
	Repositories []RepositoryPolicy
}

// CapacityLease is the broker-owned reservation returned before a GitHub
// poll. Reserved is newly reserved capacity for this call; MaxCapacity is the
// repository's total active-plus-reserved capacity after the call.
type CapacityLease struct {
	ID              uint64
	RepositoryAlias string
	Epoch           uint64
	Reserved        int
	MaxCapacity     int
	ExpiresAt       time.Time
}

// Decision binds one admitted offer to one stable capacity slot.
type Decision struct {
	Assignment controller.AssignmentKey
	Offer      githubscale.Offer
	SlotID     CapacitySlotID
}

// Broker is the fixed Task-4 admission contract.
type Broker interface {
	Enqueue(githubscale.Offer) error
	LeasePoll(repo string, now time.Time) (CapacityLease, error)
	Admit(now time.Time) ([]Decision, error)
	SetPressure(Pressure) (CapacityChange, error)
	Release(controller.AssignmentKey) error
}

// PolicyBroker extends the fixed scheduling contract with the explicit
// acquisition-policy epoch barrier used to change eligibility.
type PolicyBroker interface {
	Broker
	ApplyPolicyRevision(PolicyRevision) error
}

// LivePhase is the broker residency reconstructed from durable controller
// state before polling resumes after a restart.
type LivePhase uint8

const (
	LiveQueued LivePhase = iota + 1
	LiveReserved
	LiveActive
)

// LiveReference is one secret-free durable broker projection. Occupied
// references carry the exact validated charge persisted when their stable slot
// was allocated, so restart cannot undercount after a policy profile changes.
type LiveReference struct {
	Key             controller.AssignmentKey
	Offer           githubscale.Offer
	Phase           LivePhase
	SlotID          CapacitySlotID
	FullCharge      Resources
	LedgerCharge    Resources
	LedgerCreatedAt time.Time
	LedgerEverUsed  bool
}

// LiveHistory is the controller-only companion to Broker. EnsureQueued is
// idempotent for an equal offer that is already queued or active; Restore
// atomically rebuilds an empty broker from durable state; Retire removes a
// terminal identity only after active capacity was released. Broker's public
// Enqueue method retains its strict duplicate-error contract.
type LiveHistory interface {
	CheckOffer(githubscale.Offer) error
	EnsureQueued(githubscale.Offer) error
	EnsureQueuedBatch([]githubscale.Offer) ([]LiveReference, error)
	Restore([]LiveReference) error
	Reference(controller.AssignmentKey) (LiveReference, bool, error)
	Retire(controller.AssignmentKey) error
	HasLiveReference(controller.AssignmentKey) bool
}

var (
	ErrInvalidConfig       = errors.New("admission: invalid configuration")
	ErrUnknownRepository   = errors.New("admission: unknown repository alias")
	ErrDuplicateOffer      = errors.New("admission: duplicate offer")
	ErrOfferConflict       = errors.New("admission: conflicting live offer")
	ErrInvalidOffer        = errors.New("admission: invalid offer")
	ErrStalePolicyRevision = errors.New("admission: policy revision is not newer")
	ErrPolicyInUse         = errors.New("admission: removed policy still has live references")
	ErrPressureIncrease    = errors.New("admission: pressure cannot increase capacity")
	ErrUnknownAssignment   = errors.New("admission: assignment is not active")
	ErrLiveReferenceActive = errors.New("admission: live reference is still active")
	ErrLiveSetFull         = errors.New("admission: live reference limit reached")
	ErrOfferTooLarge       = errors.New("admission: offer logical byte limit exceeded")
	ErrLiveBytesFull       = errors.New("admission: live offer logical byte limit reached")
	ErrRestoreNotEmpty     = errors.New("admission: restore requires an empty broker")
	ErrResourceOverflow    = errors.New("admission: resource arithmetic overflow")
)

const (
	liveOfferStringStructuralBytes = uint64(16)
	liveOfferSliceStructuralBytes  = uint64(24)
)

// LiveOfferLogicalBytesV1 returns a deterministic, conservative logical size
// for Offer's variable data. MaxLiveReferences separately bounds fixed broker
// entry overhead; this formula bounds UTF-8 payload bytes and the variable
// RequestLabels backing array, including empty-label string headers.
func LiveOfferLogicalBytesV1(offer githubscale.Offer) (uint64, error) {
	total := liveOfferSliceStructuralBytes
	strings := [...]string{
		offer.JobID,
		offer.RepositoryName,
		offer.OwnerName,
		offer.JobWorkflowRef,
		offer.JobDisplayName,
		offer.EventName,
		offer.AcquireJobURL,
	}
	for _, value := range strings {
		var err error
		total, err = addLogicalBytes(total, liveOfferStringStructuralBytes, uint64(len(value)))
		if err != nil {
			return 0, err
		}
	}
	for _, label := range offer.RequestLabels {
		var err error
		total, err = addLogicalBytes(total, liveOfferStringStructuralBytes, uint64(len(label)))
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func addLogicalBytes(total uint64, values ...uint64) (uint64, error) {
	for _, value := range values {
		if math.MaxUint64-total < value {
			return 0, ErrResourceOverflow
		}
		total += value
	}
	return total, nil
}

func (r Resources) validate(label string) error {
	values := []struct {
		name  string
		value int64
	}{
		{"MilliCPU", r.MilliCPU},
		{"MemoryBytes", r.MemoryBytes},
		{"PIDs", r.PIDs},
		{"FileDescriptors", r.FileDescriptors},
		{"TmpfsBytes", r.TmpfsBytes},
		{"ScratchBytes", r.ScratchBytes},
		{"SocketStateBytes", r.SocketStateBytes},
		{"DurableStateBytes", r.DurableStateBytes},
		{"Inodes", r.Inodes},
	}
	for _, field := range values {
		if field.value < 0 {
			return fmt.Errorf("%w: %s.%s is negative", ErrInvalidConfig, label, field.name)
		}
	}
	return nil
}

func (s SlotResources) validate(label string) error {
	components := []struct {
		name      string
		resources Resources
	}{
		{"Runner", s.Runner},
		{"Adapter", s.Adapter},
		{"Broker", s.Broker},
		{"DialAuthority", s.DialAuthority},
		{"Helper", s.Helper},
		{"Verifier", s.Verifier},
	}
	for _, component := range components {
		if err := component.resources.validate(label + "." + component.name); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicies(policies []RepositoryPolicy, mode TransientMode) (map[string]RepositoryPolicy, []string, error) {
	if len(policies) == 0 {
		return nil, nil, fmt.Errorf("%w: at least one repository policy is required", ErrInvalidConfig)
	}
	byAlias := make(map[string]RepositoryPolicy, len(policies))
	aliases := make([]string, 0, len(policies))
	for i, candidate := range policies {
		candidate.Alias = strings.TrimSpace(candidate.Alias)
		if candidate.Alias == "" {
			return nil, nil, fmt.Errorf("%w: repository policy %d has an empty alias", ErrInvalidConfig, i)
		}
		if _, exists := byAlias[candidate.Alias]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate repository alias %q", ErrInvalidConfig, candidate.Alias)
		}
		if candidate.Weight == 0 {
			return nil, nil, fmt.Errorf("%w: repository %q has zero weight", ErrInvalidConfig, candidate.Alias)
		}
		switch candidate.Eligibility {
		case EligibilityActive, EligibilityArchivedDisabled, EligibilityPendingReactivation:
		default:
			return nil, nil, fmt.Errorf("%w: repository %q has unknown eligibility %q", ErrInvalidConfig, candidate.Alias, candidate.Eligibility)
		}
		if candidate.AgingThreshold < 0 {
			return nil, nil, fmt.Errorf("%w: repository %q has a negative aging threshold", ErrInvalidConfig, candidate.Alias)
		}
		if err := candidate.Profile.validate("repository[" + candidate.Alias + "].Profile"); err != nil {
			return nil, nil, err
		}
		if _, _, err := candidate.Profile.charges(mode); err != nil {
			return nil, nil, fmt.Errorf("%w: repository %q: %v", ErrInvalidConfig, candidate.Alias, err)
		}
		byAlias[candidate.Alias] = candidate
		aliases = append(aliases, candidate.Alias)
	}
	sortStrings(aliases)
	return byAlias, aliases, nil
}

func (s SlotResources) charges(mode TransientMode) (Resources, Resources, error) {
	stable, err := addResources(s.Runner, s.Adapter, s.Broker, s.DialAuthority)
	if err != nil {
		return Resources{}, Resources{}, err
	}
	var transient Resources
	switch mode {
	case TransientSerialized:
		transient = maxResources(s.Helper, s.Verifier)
	case TransientConcurrent:
		transient, err = addResources(s.Helper, s.Verifier)
		if err != nil {
			return Resources{}, Resources{}, err
		}
	default:
		return Resources{}, Resources{}, fmt.Errorf("%w: unknown transient mode %q", ErrInvalidConfig, mode)
	}
	complete, err := addResources(stable, transient)
	if err != nil {
		return Resources{}, Resources{}, err
	}
	ledger := Resources{
		SocketStateBytes:  s.DialAuthority.SocketStateBytes,
		DurableStateBytes: s.DialAuthority.DurableStateBytes,
		Inodes:            s.DialAuthority.Inodes,
	}
	return complete, ledger, nil
}

// retainedReuseCharges preserves the largest per-dimension ledger charge when
// a stable slot is reused under a different repository profile. The old
// ledger survives assignment release/reuse for at least the tail window, so a
// smaller new profile cannot truthfully shrink its accounting. The requested
// full charge already contains requestedLedger; replace only that component
// with the retained maximum to avoid either dropping or double-counting it.
func retainedReuseCharges(full, requestedLedger, retainedLedger Resources) (Resources, Resources, error) {
	withoutRequestedLedger, err := subtractResources(full, requestedLedger)
	if err != nil {
		return Resources{}, Resources{}, err
	}
	effectiveLedger := maxResources(requestedLedger, retainedLedger)
	effectiveFull, err := addResources(withoutRequestedLedger, effectiveLedger)
	if err != nil {
		return Resources{}, Resources{}, err
	}
	return effectiveFull, effectiveLedger, nil
}

func addResources(all ...Resources) (Resources, error) {
	var out Resources
	var err error
	for _, next := range all {
		if out.MilliCPU, err = addInt64(out.MilliCPU, next.MilliCPU); err != nil {
			return Resources{}, err
		}
		if out.MemoryBytes, err = addInt64(out.MemoryBytes, next.MemoryBytes); err != nil {
			return Resources{}, err
		}
		if out.PIDs, err = addInt64(out.PIDs, next.PIDs); err != nil {
			return Resources{}, err
		}
		if out.FileDescriptors, err = addInt64(out.FileDescriptors, next.FileDescriptors); err != nil {
			return Resources{}, err
		}
		if out.TmpfsBytes, err = addInt64(out.TmpfsBytes, next.TmpfsBytes); err != nil {
			return Resources{}, err
		}
		if out.ScratchBytes, err = addInt64(out.ScratchBytes, next.ScratchBytes); err != nil {
			return Resources{}, err
		}
		if out.SocketStateBytes, err = addInt64(out.SocketStateBytes, next.SocketStateBytes); err != nil {
			return Resources{}, err
		}
		if out.DurableStateBytes, err = addInt64(out.DurableStateBytes, next.DurableStateBytes); err != nil {
			return Resources{}, err
		}
		if out.Inodes, err = addInt64(out.Inodes, next.Inodes); err != nil {
			return Resources{}, err
		}
	}
	return out, nil
}

func addInt64(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, ErrResourceOverflow
	}
	return a + b, nil
}

func subtractResources(a, b Resources) (Resources, error) {
	if !resourceAtMost(b, a) {
		return Resources{}, ErrResourceOverflow
	}
	return Resources{
		MilliCPU:          a.MilliCPU - b.MilliCPU,
		MemoryBytes:       a.MemoryBytes - b.MemoryBytes,
		PIDs:              a.PIDs - b.PIDs,
		FileDescriptors:   a.FileDescriptors - b.FileDescriptors,
		TmpfsBytes:        a.TmpfsBytes - b.TmpfsBytes,
		ScratchBytes:      a.ScratchBytes - b.ScratchBytes,
		SocketStateBytes:  a.SocketStateBytes - b.SocketStateBytes,
		DurableStateBytes: a.DurableStateBytes - b.DurableStateBytes,
		Inodes:            a.Inodes - b.Inodes,
	}, nil
}

func maxResources(a, b Resources) Resources {
	return Resources{
		MilliCPU:          maxInt64(a.MilliCPU, b.MilliCPU),
		MemoryBytes:       maxInt64(a.MemoryBytes, b.MemoryBytes),
		PIDs:              maxInt64(a.PIDs, b.PIDs),
		FileDescriptors:   maxInt64(a.FileDescriptors, b.FileDescriptors),
		TmpfsBytes:        maxInt64(a.TmpfsBytes, b.TmpfsBytes),
		ScratchBytes:      maxInt64(a.ScratchBytes, b.ScratchBytes),
		SocketStateBytes:  maxInt64(a.SocketStateBytes, b.SocketStateBytes),
		DurableStateBytes: maxInt64(a.DurableStateBytes, b.DurableStateBytes),
		Inodes:            maxInt64(a.Inodes, b.Inodes),
	}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func resourceAtMost(a, b Resources) bool {
	return a.MilliCPU <= b.MilliCPU &&
		a.MemoryBytes <= b.MemoryBytes &&
		a.PIDs <= b.PIDs &&
		a.FileDescriptors <= b.FileDescriptors &&
		a.TmpfsBytes <= b.TmpfsBytes &&
		a.ScratchBytes <= b.ScratchBytes &&
		a.SocketStateBytes <= b.SocketStateBytes &&
		a.DurableStateBytes <= b.DurableStateBytes &&
		a.Inodes <= b.Inodes
}

func resourcesFit(used, charge, ceiling Resources) bool {
	next, err := addResources(used, charge)
	return err == nil && resourceAtMost(next, ceiling)
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
