package failoverclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/health"
)

var ErrHeartbeatSession = errors.New("failoverclient: heartbeat session")

// HeartbeatSessionConfig is the complete process-memory owner of one Portable
// Worker enrollment. It adds no scheduler or persistence: Service's existing
// reconciliation cadence calls Publish synchronously.
type HeartbeatSessionConfig struct {
	Client          *ProtocolClient
	Cache           *LeaseCache
	FleetGuards     controller.FleetGuardProvider
	FleetID         string
	BuildID         string
	Holder          Holder
	FenceGeneration uint64
	Budget          HeartbeatBudget
	NextNonce       func() (string, error)
}

type heartbeatEnrollment struct {
	epoch      uint64
	sessionID  string
	sequence   uint64
	generation uint64
}

// HeartbeatSession owns one synchronous enrollment/heartbeat state machine.
// A transport failure consumes its request identity and is never replayed.
type HeartbeatSession struct {
	mu sync.Mutex

	client          *ProtocolClient
	cache           *LeaseCache
	fleetGuards     controller.FleetGuardProvider
	fleetID         string
	buildID         string
	holder          Holder
	fenceGeneration uint64
	budget          HeartbeatBudget
	nextNonce       func() (string, error)

	enrollment *heartbeatEnrollment
	closed     bool
}

func NewHeartbeatSession(config HeartbeatSessionConfig) (*HeartbeatSession, error) {
	if config.Client == nil ||
		config.Cache == nil ||
		config.FleetGuards == nil ||
		!fleetIDPattern.MatchString(config.FleetID) ||
		!hex64Pattern.MatchString(config.BuildID) ||
		config.Holder != HeartbeatHolderPortable ||
		config.FenceGeneration == 0 ||
		config.FenceGeneration > maxJavaScriptSafeInteger ||
		config.NextNonce == nil ||
		config.Budget.LeaseDuration%time.Millisecond != 0 ||
		config.Budget.LeaseDuration.Milliseconds() > maxProtocolDurationMilliseconds {
		return nil, fmt.Errorf("%w: configuration", ErrHeartbeatSession)
	}
	if err := config.Budget.Validate(); err != nil {
		return nil, fmt.Errorf("%w: budget: %w", ErrHeartbeatSession, err)
	}
	if _, err := config.Cache.MutationRevision(); err != nil {
		return nil, fmt.Errorf("%w: cache: %w", ErrHeartbeatSession, err)
	}
	return &HeartbeatSession{
		client:          config.Client,
		cache:           config.Cache,
		fleetGuards:     config.FleetGuards,
		fleetID:         config.FleetID,
		buildID:         config.BuildID,
		holder:          config.Holder,
		fenceGeneration: config.FenceGeneration,
		budget:          config.Budget,
		nextNonce:       config.NextNonce,
	}, nil
}

// Publish performs at most one session request and one heartbeat request. A
// verified existing enrollment skips the session request. No call is retried.
func (session *HeartbeatSession) Publish(
	ctx context.Context,
	snapshot health.Snapshot,
) error {
	if session == nil {
		return fmt.Errorf("%w: unavailable", ErrHeartbeatSession)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return fmt.Errorf("%w: closed", ErrHeartbeatSession)
	}
	if ctx == nil {
		return session.invalidateAll("missing context", context.Canceled)
	}
	wireSnapshot, err := HeartbeatSnapshotFromHealth(snapshot)
	if err != nil {
		return session.invalidateAll("snapshot", err)
	}
	if wireSnapshot.FleetAlias != session.fleetID || wireSnapshot.BuildID != session.buildID {
		return session.invalidateAll("snapshot identity", ErrProtocolBinding)
	}
	revision, err := session.cache.MutationRevision()
	if err != nil {
		return fmt.Errorf("%w: cache revision: %w", ErrHeartbeatSession, err)
	}
	if err := ctx.Err(); err != nil {
		return session.failAndClear(revision, "canceled", errors.Join(err, context.Cause(ctx)))
	}
	guard, err := session.fleetGuards.AcquirePortable(ctx)
	if err != nil {
		return session.failAndClear(revision, "fleet guard", err)
	}
	publishErr := session.publishLocked(ctx, wireSnapshot, revision)
	closeErr := guard.Close()
	if closeErr != nil {
		_, invalidateErr := session.cache.invalidate()
		publishErr = errors.Join(
			publishErr,
			fmt.Errorf("fleet guard close: %w", closeErr),
			invalidateErr,
		)
	}
	if publishErr != nil {
		return fmt.Errorf("%w: publish: %w", ErrHeartbeatSession, publishErr)
	}
	return nil
}

func (session *HeartbeatSession) publishLocked(
	ctx context.Context,
	snapshot HeartbeatSnapshotV1,
	revision uint64,
) error {
	if session.enrollment == nil {
		nonce, err := session.nextNonce()
		if err != nil {
			return session.clearExpected(revision, fmt.Errorf("nonce: %w", err))
		}
		verified, err := session.client.OpenSession(ctx, SessionDraftV1{
			FleetID: session.fleetID,
			Nonce:   nonce,
			BuildID: session.buildID,
		})
		if err != nil {
			return session.clearExpected(revision, fmt.Errorf("open session: %w", err))
		}
		session.enrollment = &heartbeatEnrollment{
			epoch:      verified.Response.Epoch,
			sessionID:  verified.Response.SessionID,
			generation: verified.Response.LeaseGeneration,
		}
	}
	if err := ctx.Err(); err != nil {
		return session.clearExpected(
			revision,
			fmt.Errorf("canceled after enrollment: %w", errors.Join(err, context.Cause(ctx))),
		)
	}
	if session.enrollment.sequence >= maxJavaScriptSafeInteger {
		session.enrollment = nil
		return session.clearExpected(revision, errors.New("heartbeat sequence exhausted"))
	}
	session.enrollment.sequence++
	verified, err := session.client.Heartbeat(ctx, HeartbeatDraftV1{
		FleetID:         session.fleetID,
		Epoch:           session.enrollment.epoch,
		SessionID:       session.enrollment.sessionID,
		Sequence:        session.enrollment.sequence,
		Holder:          session.holder,
		FenceGeneration: session.fenceGeneration,
		Snapshot:        snapshot,
	})
	if err != nil {
		if !errors.Is(err, ErrProtocolTransport) {
			session.enrollment = nil
		}
		return session.clearExpected(revision, fmt.Errorf("heartbeat: %w", err))
	}
	if verified.Response.Maintenance.LeaseGeneration < session.enrollment.generation {
		session.enrollment = nil
		return session.clearExpected(revision, errors.New("regressing lease generation"))
	}
	session.enrollment.generation = verified.Response.Maintenance.LeaseGeneration
	if verified.Response.Lease == nil {
		return session.clearExpected(revision, nil)
	}
	lease := *verified.Response.Lease
	if err := validateHeartbeatLeaseForSnapshot(
		lease,
		verified,
		snapshot,
		session.enrollment,
		session.holder,
		session.budget,
	); err != nil {
		session.enrollment = nil
		return session.clearExpected(revision, err)
	}
	deadline, err := LocalLeaseDeadline(
		verified.SendAnchor,
		session.budget.LeaseDuration,
		session.budget.ShorteningMargin,
	)
	if err != nil {
		return session.clearExpected(revision, err)
	}
	now, err := session.client.authorityClock.Now()
	if err != nil || now.IsZero() {
		return session.clearExpected(revision, fmt.Errorf("authority clock: %w", err))
	}
	if !now.Before(deadline) {
		return session.clearExpected(revision, errors.New("lease response reached local deadline"))
	}
	if err := ctx.Err(); err != nil {
		return session.clearExpected(
			revision,
			fmt.Errorf("canceled before lease install: %w", errors.Join(err, context.Cause(ctx))),
		)
	}
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		return session.clearExpected(revision, err)
	}
	next := CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      verified.Request.Sequence,
		Fence:         session.fenceGeneration,
		LocalDeadline: deadline,
		SendAnchor:    verified.SendAnchor,
	}
	if _, err := session.cache.CompareAndSwap(revision, &next); err != nil {
		return fmt.Errorf("install lease: %w", err)
	}
	return nil
}

func validateHeartbeatLeaseForSnapshot(
	lease AcquisitionLeaseV1,
	verified VerifiedHeartbeatV1,
	snapshot HeartbeatSnapshotV1,
	enrollment *heartbeatEnrollment,
	holder Holder,
	budget HeartbeatBudget,
) error {
	if enrollment == nil ||
		lease.FleetID != verified.Request.FleetID ||
		lease.Holder != LeaseHolder(holder) ||
		lease.ServerEpoch != enrollment.epoch ||
		lease.SessionID != enrollment.sessionID ||
		lease.LeaseGeneration != verified.Response.Maintenance.LeaseGeneration ||
		lease.LeaseGeneration < enrollment.generation ||
		lease.PolicyDigest != snapshot.PolicyDigest ||
		lease.RepositoryPolicyRevision != snapshot.RepositoryPolicyRevision ||
		lease.LocalPolicyEpoch != snapshot.PolicyEpoch ||
		lease.MaxCapacity != int(snapshot.Capacity.Effective) ||
		lease.DurationMs != budget.LeaseDuration.Milliseconds() {
		return errors.New("lease does not match the complete heartbeat authority")
	}
	switch snapshot.AcquisitionMode {
	case AcquisitionModeCanaryOnly:
		if lease.Mode != LeaseCanaryOnly || snapshot.Capacity.Effective != 1 {
			return errors.New("lease mode does not match canary policy")
		}
	case AcquisitionModeEnabled:
		if lease.Mode != LeaseEnabled || snapshot.Capacity.Effective == 0 {
			return errors.New("lease mode does not match enabled policy")
		}
	default:
		return errors.New("non-acquiring policy received a lease")
	}
	return nil
}

func (session *HeartbeatSession) clearExpected(revision uint64, cause error) error {
	_, clearErr := session.cache.CompareAndSwap(revision, nil)
	return errors.Join(cause, clearErr)
}

func (session *HeartbeatSession) failAndClear(
	revision uint64,
	label string,
	cause error,
) error {
	return fmt.Errorf(
		"%w: %s: %w",
		ErrHeartbeatSession,
		label,
		session.clearExpected(revision, cause),
	)
}

func (session *HeartbeatSession) invalidateAll(label string, cause error) error {
	_, invalidateErr := session.cache.invalidate()
	return fmt.Errorf(
		"%w: %s: %w",
		ErrHeartbeatSession,
		label,
		errors.Join(cause, invalidateErr),
	)
}

// Close clears all locally cached authority and releases idle transport
// resources exactly once. There is no background heartbeat goroutine to join.
func (session *HeartbeatSession) Close() error {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	session.closed = true
	session.enrollment = nil
	_, err := session.cache.invalidate()
	session.client.CloseIdleConnections()
	if err != nil {
		return fmt.Errorf("%w: close: %w", ErrHeartbeatSession, err)
	}
	return nil
}

// HeartbeatSnapshotFromHealth performs the sole complete health-to-wire
// conversion. It rejects values that the V1 integer/millisecond schema would
// otherwise truncate.
func HeartbeatSnapshotFromHealth(snapshot health.Snapshot) (HeartbeatSnapshotV1, error) {
	if err := snapshot.Validate(); err != nil {
		return HeartbeatSnapshotV1{}, fmt.Errorf("%w: invalid health snapshot: %w", ErrHeartbeatSession, err)
	}
	if !wholeMillisecondTime(snapshot.ObservedAt) ||
		(!snapshot.LastTerminalAt.IsZero() && !wholeMillisecondTime(snapshot.LastTerminalAt)) ||
		snapshot.OldestLiveAssignmentAge%time.Millisecond != 0 {
		return HeartbeatSnapshotV1{}, fmt.Errorf("%w: lossy millisecond conversion", ErrHeartbeatSession)
	}
	capacity, err := heartbeatCapacityFromHealth(snapshot.Capacity)
	if err != nil {
		return HeartbeatSnapshotV1{}, err
	}
	if snapshot.AssignedJobs > maxJavaScriptSafeInteger ||
		snapshot.RunningJobs > maxJavaScriptSafeInteger ||
		snapshot.UnassignedReleasedListeners > maxJavaScriptSafeInteger {
		return HeartbeatSnapshotV1{}, fmt.Errorf("%w: unsafe integer", ErrHeartbeatSession)
	}
	ageMilliseconds := snapshot.OldestLiveAssignmentAge.Milliseconds()
	if ageMilliseconds < 0 || uint64(ageMilliseconds) > maxJavaScriptSafeInteger {
		return HeartbeatSnapshotV1{}, fmt.Errorf("%w: unsafe assignment age", ErrHeartbeatSession)
	}
	mode, err := heartbeatModeFromHealth(snapshot.AcquisitionMode)
	if err != nil {
		return HeartbeatSnapshotV1{}, err
	}
	var terminal *string
	if !snapshot.LastTerminalAt.IsZero() {
		value := FormatProtocolTimestamp(snapshot.LastTerminalAt)
		terminal = &value
	}
	wire := HeartbeatSnapshotV1{
		ObservedAt:                  FormatProtocolTimestamp(snapshot.ObservedAt),
		FleetAlias:                  snapshot.FleetAlias,
		AcquisitionMode:             mode,
		PolicyEpoch:                 snapshot.PolicyEpoch,
		PolicyDigest:                snapshot.PolicyDigest,
		RepositoryPolicyRevision:    snapshot.RepositoryPolicyRevision,
		Capacity:                    capacity,
		AssignedJobs:                snapshot.AssignedJobs,
		RunningJobs:                 snapshot.RunningJobs,
		OldestLiveAssignmentAgeMs:   uint64(ageMilliseconds),
		UnassignedReleasedListeners: snapshot.UnassignedReleasedListeners,
		LastTerminalAt:              terminal,
		HostProfileID:               HostProfileID(snapshot.HostProfileID),
		Degraded:                    snapshot.Degraded,
		BuildID:                     snapshot.BuildID,
	}
	if err := validateHeartbeatSnapshot(snapshot.FleetAlias, wire); err != nil {
		return HeartbeatSnapshotV1{}, fmt.Errorf("%w: wire snapshot: %w", ErrHeartbeatSession, err)
	}
	return wire, nil
}

func heartbeatCapacityFromHealth(
	capacity health.CapacitySummary,
) (HeartbeatCapacityV1, error) {
	values := []int{
		capacity.Configured,
		capacity.Effective,
		capacity.Occupied,
		capacity.Available,
		capacity.Queued,
	}
	for _, value := range values {
		if value < 0 || uint64(value) > maxJavaScriptSafeInteger {
			return HeartbeatCapacityV1{}, fmt.Errorf("%w: unsafe capacity", ErrHeartbeatSession)
		}
	}
	return HeartbeatCapacityV1{
		Configured: uint64(capacity.Configured),
		Effective:  uint64(capacity.Effective),
		Occupied:   uint64(capacity.Occupied),
		Available:  uint64(capacity.Available),
		Queued:     uint64(capacity.Queued),
	}, nil
}

func heartbeatModeFromHealth(mode health.AcquisitionMode) (AcquisitionMode, error) {
	switch mode {
	case health.AcquisitionDisabled:
		return AcquisitionModeDisabled, nil
	case health.AcquisitionCanaryOnly:
		return AcquisitionModeCanaryOnly, nil
	case health.AcquisitionEnabled:
		return AcquisitionModeEnabled, nil
	case health.AcquisitionFatal:
		return AcquisitionModeFatal, nil
	default:
		return "", fmt.Errorf("%w: acquisition mode", ErrHeartbeatSession)
	}
}

func wholeMillisecondTime(value time.Time) bool {
	return !value.IsZero() && value.Equal(value.UTC().Truncate(time.Millisecond))
}
