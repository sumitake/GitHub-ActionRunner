package failoverclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

var ErrLeasePermit = errors.New("failoverclient: lease permit")

var errLeasePermitAuthority = fmt.Errorf(
	"%w: %w",
	ErrLeasePermit,
	controller.ErrAcquisitionPermitAuthority,
)

type leasePermitState uint8

const (
	leasePermitActive leasePermitState = iota
	leasePermitAdmitted
	leasePermitDropped
)

type leaseGuard struct {
	mu           sync.Mutex
	closeOnce    sync.Once
	provider     CachedLeasePermitProvider
	binding      controller.AcquisitionPermitBinding
	deadline     time.Time
	ctx          context.Context
	cancel       context.CancelCauseFunc
	waitCtx      context.Context
	cancelWait   context.CancelFunc
	waitReturned chan struct{}
	waitDone     chan struct{}
	waitErr      error
	state        leasePermitState
	dropCause    error
}

func (guard *leaseGuard) Binding() controller.AcquisitionPermitBinding {
	if guard == nil {
		return controller.AcquisitionPermitBinding{}
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.binding
}

func (guard *leaseGuard) ValidateBinding(
	ctx context.Context,
	binding controller.AcquisitionPermitBinding,
) error {
	if guard == nil {
		return fmt.Errorf("%w: unavailable", ErrLeasePermit)
	}
	return guard.provider.validateBindingAt(ctx, binding, time.Time{})
}

func (guard *leaseGuard) Context() context.Context {
	if guard == nil || guard.ctx == nil {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(fmt.Errorf("%w: unavailable", ErrLeasePermit))
		return ctx
	}
	return guard.ctx
}

func (guard *leaseGuard) Revalidate() error {
	if guard == nil {
		return fmt.Errorf("%w: unavailable", ErrLeasePermit)
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if err := guard.validateCurrentLocked(); err != nil {
		return guard.dropLocked(err)
	}
	return nil
}

func (guard *leaseGuard) Admit() error {
	if guard == nil {
		return fmt.Errorf("%w: unavailable", ErrLeasePermit)
	}
	guard.mu.Lock()
	if err := guard.validateCurrentLocked(); err != nil {
		err = guard.dropLocked(err)
		guard.mu.Unlock()
		guard.stopAndJoinWaiter()
		return err
	}
	guard.state = leasePermitAdmitted
	guard.mu.Unlock()
	guard.stopAndJoinWaiter()
	return nil
}

func (guard *leaseGuard) Close() error {
	if guard == nil {
		return fmt.Errorf("%w: unavailable", ErrLeasePermit)
	}
	guard.closeOnce.Do(func() {
		guard.mu.Lock()
		if guard.state == leasePermitActive {
			guard.dropLocked(fmt.Errorf("%w: closed", ErrLeasePermit))
		}
		guard.mu.Unlock()
		if guard.cancel != nil {
			guard.cancel(fmt.Errorf("%w: closed", ErrLeasePermit))
		}
		guard.stopAndJoinWaiter()
	})
	return nil
}

func (guard *leaseGuard) validateCurrentLocked() error {
	switch guard.state {
	case leasePermitActive:
	case leasePermitAdmitted:
		return fmt.Errorf("%w: already admitted", ErrLeasePermit)
	case leasePermitDropped:
		if guard.dropCause != nil {
			return guard.dropCause
		}
		return fmt.Errorf("%w: dropped", ErrLeasePermit)
	default:
		return fmt.Errorf("%w: invalid state", ErrLeasePermit)
	}
	if cause := context.Cause(guard.ctx); cause != nil {
		return fmt.Errorf("%w: canceled: %w", ErrLeasePermit, cause)
	}
	select {
	case <-guard.waitReturned:
		return guard.waitFailure()
	default:
	}

	return guard.provider.validateBindingAt(
		guard.ctx,
		guard.binding,
		guard.deadline,
	)
}

func (guard *leaseGuard) dropLocked(cause error) error {
	if guard.state == leasePermitActive {
		guard.state = leasePermitDropped
		if cause == nil {
			cause = fmt.Errorf("%w: dropped", ErrLeasePermit)
		}
		guard.dropCause = cause
		guard.cancel(cause)
	}
	if guard.dropCause != nil {
		return guard.dropCause
	}
	return cause
}

func (guard *leaseGuard) waitFailure() error {
	err := guard.waitErr
	if err == nil {
		err = fmt.Errorf("%w: deadline wait returned without cause", ErrAuthorityClock)
	}
	return fmt.Errorf("%w: deadline wait: %w", errLeasePermitAuthority, err)
}

func (guard *leaseGuard) stopAndJoinWaiter() {
	if guard.cancelWait != nil {
		guard.cancelWait()
	}
	if guard.waitDone != nil {
		<-guard.waitDone
	}
}

func (guard *leaseGuard) waitForDeadline() {
	err := guard.provider.Clock.WaitUntil(guard.waitCtx, guard.deadline)
	guard.waitErr = err
	close(guard.waitReturned)

	guard.mu.Lock()
	if guard.state == leasePermitActive {
		guard.dropLocked(guard.waitFailure())
	}
	guard.mu.Unlock()
	close(guard.waitDone)
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
	return CachedLeasePermitProvider(config), nil
}

func (provider CachedLeasePermitProvider) Acquire(
	ctx context.Context,
	request controller.AcquisitionPermitRequest,
) (controller.AcquisitionPermitGuard, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: missing context", ErrLeasePermit)
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf(
			"%w: canceled: %w",
			ErrLeasePermit,
			errors.Join(ctx.Err(), context.Cause(ctx)),
		)
	}
	if provider.Cache == nil || provider.Clock == nil || !provider.Clock.Capable() {
		return nil, fmt.Errorf("%w: unavailable", errLeasePermitAuthority)
	}
	if err := validatePermitRequest(request); err != nil {
		return nil, err
	}
	entry, err := provider.Cache.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("%w: cache: %w", errLeasePermitAuthority, err)
	}
	now, err := provider.Clock.Now()
	if err != nil {
		return nil, fmt.Errorf("%w: clock: %w", errLeasePermitAuthority, err)
	}
	if err := validatePermitEntry(
		entry,
		entry.AuthorityToken,
		provider.Holder,
		provider.Fence,
		request,
	); err != nil {
		return nil, err
	}
	deadline, err := OperationDeadline(
		now,
		entry.LocalDeadline,
		provider.CallDuration,
		provider.TerminationTail,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errLeasePermitAuthority, err)
	}
	callContext, cancelCall := context.WithCancelCause(ctx)
	waitContext, cancelWait := context.WithCancel(ctx)
	guard := &leaseGuard{
		provider: provider,
		binding: controller.AcquisitionPermitBinding{
			AuthorityRevision:        entry.AuthorityToken.AuthorityRevision,
			AuthorityKey:             entry.AuthorityToken.Key,
			FenceGeneration:          entry.AuthorityToken.Fence,
			ServerEpoch:              entry.Lease.ServerEpoch,
			SessionID:                entry.Lease.SessionID,
			LeaseGeneration:          entry.Lease.LeaseGeneration,
			OperationID:              request.OperationID,
			RepositoryAlias:          request.RepositoryAlias,
			ScaleSetName:             request.ScaleSetName,
			OperationKind:            request.OperationKind,
			PolicyDigest:             request.PolicyDigest,
			PolicyEpoch:              request.PolicyEpoch,
			PolicyMode:               request.PolicyMode,
			MaxCapacity:              request.MaxCapacity,
			RepositoryPolicyRevision: request.RepositoryPolicyRevision,
			OriginalLocalDeadline:    entry.LocalDeadline,
		},
		deadline:     deadline,
		ctx:          callContext,
		cancel:       cancelCall,
		waitCtx:      waitContext,
		cancelWait:   cancelWait,
		waitReturned: make(chan struct{}),
		waitDone:     make(chan struct{}),
		state:        leasePermitActive,
	}
	go guard.waitForDeadline()
	return guard, nil
}

// validateBindingAt is the single complete authority validator used by
// pre-effect revalidation, post-effect admission, and persisted listeners.
// A nonzero operationDeadline additionally applies the operation cancellation
// window and the current renewal's termination tail.
func (provider CachedLeasePermitProvider) validateBindingAt(
	ctx context.Context,
	binding controller.AcquisitionPermitBinding,
	operationDeadline time.Time,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrLeasePermit)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"%w: canceled: %w",
			ErrLeasePermit,
			errors.Join(err, context.Cause(ctx)),
		)
	}
	if provider.Cache == nil || provider.Clock == nil || !provider.Clock.Capable() {
		return fmt.Errorf("%w: unavailable", errLeasePermitAuthority)
	}
	request := controller.AcquisitionPermitRequest{
		OperationID:              binding.OperationID,
		RepositoryAlias:          binding.RepositoryAlias,
		ScaleSetName:             binding.ScaleSetName,
		PolicyDigest:             binding.PolicyDigest,
		OperationKind:            binding.OperationKind,
		PolicyEpoch:              binding.PolicyEpoch,
		PolicyMode:               binding.PolicyMode,
		MaxCapacity:              binding.MaxCapacity,
		RepositoryPolicyRevision: binding.RepositoryPolicyRevision,
	}
	if binding.AuthorityRevision == 0 ||
		binding.AuthorityKey == "" ||
		binding.FenceGeneration == 0 ||
		binding.FenceGeneration > maxJavaScriptSafeInteger ||
		binding.LeaseGeneration == 0 ||
		binding.LeaseGeneration > maxJavaScriptSafeInteger ||
		binding.OriginalLocalDeadline.IsZero() ||
		validatePermitRequest(request) != nil {
		return fmt.Errorf("%w: incomplete binding", errLeasePermitAuthority)
	}
	token := LeaseAuthorityToken{
		AuthorityRevision: binding.AuthorityRevision,
		Key:               binding.AuthorityKey,
		Fence:             binding.FenceGeneration,
	}
	entry, err := provider.Cache.Revalidate(token)
	if err != nil {
		return fmt.Errorf("%w: cache: %w", errLeasePermitAuthority, err)
	}
	if err := validatePermitEntry(
		entry,
		token,
		provider.Holder,
		provider.Fence,
		request,
	); err != nil {
		return err
	}
	if entry.Lease.ServerEpoch != binding.ServerEpoch ||
		entry.Lease.SessionID != binding.SessionID ||
		entry.Lease.LeaseGeneration != binding.LeaseGeneration {
		return fmt.Errorf("%w: enrollment changed", errLeasePermitAuthority)
	}
	now, err := provider.Clock.Now()
	if err != nil {
		return fmt.Errorf("%w: clock: %w", errLeasePermitAuthority, err)
	}
	if !now.Before(binding.OriginalLocalDeadline) {
		return fmt.Errorf("%w: expired", errLeasePermitAuthority)
	}
	if !operationDeadline.IsZero() {
		currentDeadline := entry.LocalDeadline.Add(-provider.TerminationTail)
		if !now.Before(operationDeadline) || !now.Before(currentDeadline) {
			return fmt.Errorf("%w: expired", errLeasePermitAuthority)
		}
	}
	return nil
}

// Invalidate discards permit authority at the acquisition-policy barrier. The
// cache mutation itself is one bounded in-memory CAS and advances its revision
// even when no lease is currently installed.
func (provider CachedLeasePermitProvider) Invalidate(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrLeasePermit)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"%w: canceled: %w",
			ErrLeasePermit,
			errors.Join(err, context.Cause(ctx)),
		)
	}
	if provider.Cache == nil {
		return fmt.Errorf("%w: unavailable", ErrLeasePermit)
	}
	if _, err := provider.Cache.invalidate(); err != nil {
		return fmt.Errorf("%w: invalidate: %w", ErrLeasePermit, err)
	}
	return nil
}

func validatePermitRequest(request controller.AcquisitionPermitRequest) error {
	if request.OperationID == "" ||
		request.RepositoryAlias == "" ||
		request.ScaleSetName == "" ||
		request.PolicyDigest == "" ||
		request.PolicyEpoch == 0 ||
		request.RepositoryPolicyRevision == 0 ||
		request.MaxCapacity <= 0 ||
		uint64(request.MaxCapacity) > maxJavaScriptSafeInteger {
		return fmt.Errorf("%w: incomplete request", ErrLeasePermit)
	}
	switch request.PolicyMode {
	case controller.AcquisitionCanaryOnly:
		if request.MaxCapacity != 1 {
			return fmt.Errorf("%w: policy mode", ErrLeasePermit)
		}
	case controller.AcquisitionEnabled:
	default:
		return fmt.Errorf("%w: policy mode", ErrLeasePermit)
	}
	switch request.OperationKind {
	case "poll", "acquire", "jit":
		return nil
	default:
		return fmt.Errorf("%w: operation kind", ErrLeasePermit)
	}
}

func validatePermitEntry(
	entry *CachedLeaseSnapshot,
	expectedToken LeaseAuthorityToken,
	holder LeaseHolder,
	fence uint64,
	request controller.AcquisitionPermitRequest,
) error {
	if entry == nil || entry.AuthorityToken != expectedToken {
		return fmt.Errorf("%w: authority changed", errLeasePermitAuthority)
	}
	lease := entry.Lease
	if err := lease.validate(); err != nil {
		return fmt.Errorf("%w: invalid lease: %w", errLeasePermitAuthority, err)
	}
	key, err := lease.AdmissionAuthorityKey()
	if err != nil || key != entry.Key || key != expectedToken.Key {
		return fmt.Errorf("%w: authority key", errLeasePermitAuthority)
	}
	if lease.Holder != holder ||
		entry.Fence != fence ||
		expectedToken.Fence != fence ||
		lease.LocalPolicyEpoch != request.PolicyEpoch ||
		lease.PolicyDigest != request.PolicyDigest ||
		lease.RepositoryPolicyRevision != request.RepositoryPolicyRevision ||
		lease.MaxCapacity != request.MaxCapacity {
		return fmt.Errorf("%w: mismatch", errLeasePermitAuthority)
	}
	if (lease.Mode == LeaseEnabled && request.PolicyMode != controller.AcquisitionEnabled) ||
		(lease.Mode == LeaseCanaryOnly && request.PolicyMode != controller.AcquisitionCanaryOnly) ||
		(lease.Mode != LeaseEnabled && lease.Mode != LeaseCanaryOnly) {
		return fmt.Errorf("%w: mode", errLeasePermitAuthority)
	}
	if slices.Contains(lease.ArchivedDisabledAliases, request.RepositoryAlias) {
		return fmt.Errorf("%w: archived", errLeasePermitAuthority)
	}
	if lease.Mode == LeaseCanaryOnly &&
		(lease.CanaryScaleSet == nil || *lease.CanaryScaleSet != request.ScaleSetName) {
		return fmt.Errorf("%w: canary set", errLeasePermitAuthority)
	}
	return nil
}

var _ controller.AcquisitionPermitProvider = CachedLeasePermitProvider{}
var _ controller.AcquisitionPermitGuard = (*leaseGuard)(nil)
