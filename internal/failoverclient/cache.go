package failoverclient

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var ErrLeaseCache = errors.New("failoverclient: lease cache")

type CachedLease struct {
	Lease         AcquisitionLeaseV1
	Key           string
	Sequence      uint64
	Fence         uint64
	LocalDeadline time.Time
	SendAnchor    time.Time
}

// LeaseAuthorityToken identifies one authority interval. It remains stable
// across an authority-equivalent renewal and changes on every replacement,
// clear, or reinstall, including an A-to-B-to-A sequence.
type LeaseAuthorityToken struct {
	AuthorityRevision uint64
	Key               string
	Fence             uint64
}

// CachedLeaseSnapshot is an immutable-by-ownership view of the cache. The
// mutation revision is for writer CAS; the authority token is for operation
// barriers and intentionally has different renewal semantics.
type CachedLeaseSnapshot struct {
	CachedLease
	MutationRevision uint64
	AuthorityToken   LeaseAuthorityToken
}

type leaseCacheEntry struct {
	lease             CachedLease
	authorityRevision uint64
}

type LeaseCache struct {
	mu               sync.Mutex
	entry            *leaseCacheEntry
	mutationRevision uint64
	poisoned         bool
}

func (cache *LeaseCache) Snapshot() (*CachedLeaseSnapshot, error) {
	if cache == nil {
		return nil, fmt.Errorf("%w: missing", ErrLeaseCache)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.snapshotLocked()
}

// MutationRevision returns the writer CAS revision even while the cache is
// empty. It never grants authority; callers use it only to bind a later exact
// install or clear.
func (cache *LeaseCache) MutationRevision() (uint64, error) {
	if cache == nil {
		return 0, fmt.Errorf("%w: missing", ErrLeaseCache)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.poisoned {
		return cache.mutationRevision, fmt.Errorf("%w: poisoned", ErrLeaseCache)
	}
	return cache.mutationRevision, nil
}

// Revalidate atomically proves that token still names the current authority
// and returns the latest renewal envelope for that authority.
func (cache *LeaseCache) Revalidate(token LeaseAuthorityToken) (*CachedLeaseSnapshot, error) {
	if cache == nil {
		return nil, fmt.Errorf("%w: missing", ErrLeaseCache)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.poisoned || cache.entry == nil {
		return nil, fmt.Errorf("%w: unavailable", ErrLeaseCache)
	}
	if token != cache.authorityTokenLocked() {
		return nil, fmt.Errorf("%w: authority changed", ErrLeaseCache)
	}
	return cache.snapshotLocked()
}

// CompareAndSwap is the cache's only mutation primitive. The caller must bind
// the expected revision before starting any work that can produce next. A nil
// next clears the cache at that exact revision.
func (cache *LeaseCache) CompareAndSwap(expectedRevision uint64, next *CachedLease) (uint64, error) {
	if cache == nil {
		return 0, fmt.Errorf("%w: missing", ErrLeaseCache)
	}
	prepared, err := prepareCachedLease(next)
	if err != nil {
		return 0, err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.compareAndSwapLocked(expectedRevision, prepared)
}

// invalidate always advances the mutation revision, including when the cache
// is already empty. That single atomic step fences an install which captured
// the prior empty revision before an acquisition-policy transition.
func (cache *LeaseCache) invalidate() (uint64, error) {
	if cache == nil {
		return 0, fmt.Errorf("%w: missing", ErrLeaseCache)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.compareAndSwapLocked(cache.mutationRevision, nil)
}

func (cache *LeaseCache) compareAndSwapLocked(
	expectedRevision uint64,
	prepared *CachedLease,
) (uint64, error) {
	if cache.poisoned {
		return cache.mutationRevision, fmt.Errorf("%w: poisoned", ErrLeaseCache)
	}
	if expectedRevision != cache.mutationRevision {
		return cache.mutationRevision, fmt.Errorf("%w: stale revision", ErrLeaseCache)
	}
	if cache.mutationRevision == math.MaxUint64 {
		cache.entry = nil
		cache.poisoned = true
		return cache.mutationRevision, fmt.Errorf("%w: revision overflow", ErrLeaseCache)
	}

	nextRevision := cache.mutationRevision + 1
	if prepared == nil {
		cache.entry = nil
		cache.mutationRevision = nextRevision
		return nextRevision, nil
	}

	authorityRevision := nextRevision
	if cache.entry != nil {
		if err := validateCacheTransition(cache.entry.lease, *prepared); err != nil {
			return cache.mutationRevision, err
		}
		if cache.entry.lease.Key == prepared.Key && cache.entry.lease.Fence == prepared.Fence {
			authorityRevision = cache.entry.authorityRevision
		}
	}
	cache.entry = &leaseCacheEntry{
		lease:             *prepared,
		authorityRevision: authorityRevision,
	}
	cache.mutationRevision = nextRevision
	return nextRevision, nil
}

func prepareCachedLease(next *CachedLease) (*CachedLease, error) {
	if next == nil {
		return nil, nil
	}
	prepared := cloneCachedLease(*next)
	if err := prepared.Lease.validate(); err != nil {
		return nil, err
	}
	derivedKey, err := prepared.Lease.AdmissionAuthorityKey()
	if err != nil {
		return nil, err
	}
	if prepared.Key != derivedKey {
		return nil, fmt.Errorf("%w: authority key", ErrLeaseCache)
	}
	if prepared.Sequence == 0 || prepared.Sequence > maxJavaScriptSafeInteger ||
		prepared.Fence == 0 || prepared.Fence > maxJavaScriptSafeInteger ||
		prepared.SendAnchor.IsZero() || prepared.LocalDeadline.IsZero() ||
		!prepared.LocalDeadline.After(prepared.SendAnchor) {
		return nil, fmt.Errorf("%w: invalid entry", ErrLeaseCache)
	}
	return &prepared, nil
}

func validateCacheTransition(current, next CachedLease) error {
	if next.SendAnchor.Before(current.SendAnchor) {
		return fmt.Errorf("%w: regressing send anchor", ErrLeaseCache)
	}
	if next.Lease.LeaseGeneration < current.Lease.LeaseGeneration {
		return fmt.Errorf("%w: regressing lease generation", ErrLeaseCache)
	}
	if next.Fence < current.Fence {
		return fmt.Errorf("%w: regressing fence", ErrLeaseCache)
	}

	if next.Lease.SessionID == current.Lease.SessionID {
		if next.Lease.ServerEpoch != current.Lease.ServerEpoch || next.Sequence <= current.Sequence {
			return fmt.Errorf("%w: stale session", ErrLeaseCache)
		}
	} else if next.Lease.ServerEpoch <= current.Lease.ServerEpoch ||
		next.Lease.LeaseGeneration <= current.Lease.LeaseGeneration {
		return fmt.Errorf("%w: stale replacement session", ErrLeaseCache)
	}

	if next.Key == current.Key && next.Fence == current.Fence &&
		next.LocalDeadline.Before(current.LocalDeadline) {
		return fmt.Errorf("%w: regressing renewal deadline", ErrLeaseCache)
	}
	return nil
}

func (cache *LeaseCache) snapshotLocked() (*CachedLeaseSnapshot, error) {
	if cache.poisoned || cache.entry == nil {
		return nil, fmt.Errorf("%w: empty", ErrLeaseCache)
	}
	return &CachedLeaseSnapshot{
		CachedLease:      cloneCachedLease(cache.entry.lease),
		MutationRevision: cache.mutationRevision,
		AuthorityToken:   cache.authorityTokenLocked(),
	}, nil
}

func (cache *LeaseCache) authorityTokenLocked() LeaseAuthorityToken {
	return LeaseAuthorityToken{
		AuthorityRevision: cache.entry.authorityRevision,
		Key:               cache.entry.lease.Key,
		Fence:             cache.entry.lease.Fence,
	}
}

func cloneCachedLease(source CachedLease) CachedLease {
	copy := source
	if source.Lease.ArchivedDisabledAliases != nil {
		copy.Lease.ArchivedDisabledAliases = append([]string{}, source.Lease.ArchivedDisabledAliases...)
	}
	if source.Lease.CanaryScaleSet != nil {
		canary := *source.Lease.CanaryScaleSet
		copy.Lease.CanaryScaleSet = &canary
	}
	return copy
}
