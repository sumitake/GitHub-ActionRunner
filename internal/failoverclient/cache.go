package failoverclient

import (
	"errors"
	"fmt"
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

type LeaseCache struct {
	mu    sync.Mutex
	entry *CachedLease
}

func (cache *LeaseCache) Snapshot() (*CachedLease, error) {
	if cache == nil {
		return nil, fmt.Errorf("%w: missing", ErrLeaseCache)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entry == nil {
		return nil, fmt.Errorf("%w: empty", ErrLeaseCache)
	}
	copy := *cache.entry
	return &copy, nil
}

func (cache *LeaseCache) Clear() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	cache.entry = nil
	cache.mu.Unlock()
}

func (cache *LeaseCache) Install(next CachedLease) error {
	if cache == nil || next.Key == "" || next.LocalDeadline.IsZero() {
		return fmt.Errorf("%w: install", ErrLeaseCache)
	}
	if err := next.Lease.validate(); err != nil {
		return err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entry = &next
	return nil
}

func (cache *LeaseCache) RenewEnvelope(sequence uint64, deadline time.Time) error {
	if cache == nil || deadline.IsZero() {
		return fmt.Errorf("%w: renew", ErrLeaseCache)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entry == nil {
		return fmt.Errorf("%w: empty", ErrLeaseCache)
	}
	if sequence < cache.entry.Sequence || !deadline.After(cache.entry.LocalDeadline) && !deadline.Equal(cache.entry.LocalDeadline) {
		return fmt.Errorf("%w: regressing", ErrLeaseCache)
	}
	if deadline.Before(cache.entry.LocalDeadline) {
		return fmt.Errorf("%w: regressing deadline", ErrLeaseCache)
	}
	updated := *cache.entry
	updated.Sequence = sequence
	updated.LocalDeadline = deadline
	cache.entry = &updated
	return nil
}
