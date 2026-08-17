package failoverclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

var ErrLeasePermit = errors.New("failoverclient: lease permit")

type leaseGuard struct {
	clock    AuthorityClock
	deadline time.Time
}

func (guard leaseGuard) Close() error {
	if guard.clock == nil {
		return fmt.Errorf("%w: unavailable", ErrLeasePermit)
	}
	now, err := guard.clock.Now()
	if err != nil || !now.Before(guard.deadline) {
		return fmt.Errorf("%w: expired", ErrLeasePermit)
	}
	return nil
}

// CachedLeasePermitProvider derives a local operation proof from the process
// memory lease cache. It makes no network call and persists no remote record.
type CachedLeasePermitProvider struct {
	Cache           *LeaseCache
	Clock           AuthorityClock
	Holder          LeaseHolder
	Fence           uint64
	CallDuration    time.Duration
	TerminationTail time.Duration
}

type CachedLeasePermitConfig struct {
	Cache           *LeaseCache
	Clock           AuthorityClock
	Holder          LeaseHolder
	Fence           uint64
	CallDuration    time.Duration
	TerminationTail time.Duration
}

func NewCachedLeasePermitProvider(
	config CachedLeasePermitConfig,
) (CachedLeasePermitProvider, error) {
	if config.Cache == nil ||
		config.Clock == nil ||
		!config.Clock.Capable() ||
		config.Fence == 0 ||
		config.CallDuration <= 0 ||
		config.TerminationTail <= 0 ||
		(config.Holder != HolderPortable && config.Holder != HolderLegacy) {
		return CachedLeasePermitProvider{}, fmt.Errorf("%w: incomplete", ErrLeasePermit)
	}
	return CachedLeasePermitProvider{
		Cache:           config.Cache,
		Clock:           config.Clock,
		Holder:          config.Holder,
		Fence:           config.Fence,
		CallDuration:    config.CallDuration,
		TerminationTail: config.TerminationTail,
	}, nil
}

func (provider CachedLeasePermitProvider) Acquire(
	ctx context.Context,
	request controller.AcquisitionPermitRequest,
) (controller.AcquisitionGuard, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("%w: canceled", ErrLeasePermit)
	}
	if provider.Cache == nil || provider.Clock == nil || !provider.Clock.Capable() {
		return nil, fmt.Errorf("%w: unavailable", ErrLeasePermit)
	}
	entry, err := provider.Cache.Snapshot()
	if err != nil {
		return nil, err
	}
	now, err := provider.Clock.Now()
	if err != nil || !now.Before(entry.LocalDeadline) {
		return nil, fmt.Errorf("%w: expired", ErrLeasePermit)
	}
	lease := entry.Lease
	if lease.Holder != provider.Holder ||
		entry.Fence != provider.Fence ||
		lease.LocalPolicyEpoch != request.PolicyEpoch ||
		lease.PolicyDigest != request.PolicyDigest {
		return nil, fmt.Errorf("%w: mismatch", ErrLeasePermit)
	}
	if lease.Mode != LeaseEnabled && lease.Mode != LeaseCanaryOnly {
		return nil, fmt.Errorf("%w: mode", ErrLeasePermit)
	}
	if slices.Contains(lease.ArchivedDisabledAliases, request.RepositoryAlias) {
		return nil, fmt.Errorf("%w: archived", ErrLeasePermit)
	}
	if lease.Mode == LeaseCanaryOnly &&
		(lease.CanaryScaleSet == nil || *lease.CanaryScaleSet != request.ScaleSetName) {
		return nil, fmt.Errorf("%w: canary set", ErrLeasePermit)
	}
	deadline, err := OperationDeadline(
		now,
		entry.LocalDeadline,
		provider.CallDuration,
		provider.TerminationTail,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLeasePermit, err)
	}
	return leaseGuard{clock: provider.Clock, deadline: deadline}, nil
}

var _ controller.AcquisitionPermitProvider = CachedLeasePermitProvider{}
