package testenv

import (
	"context"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/failoverclient"
)

const (
	task11SyntheticPermitDomain = "portable-ghar.task11.synthetic-permit.v1\x00"
	// The fixture has no Worker, so its lease names the conformance fleet and
	// scale set itself. Both satisfy the lease alias grammar.
	task11SyntheticPermitFleetID  = "portable-ghar-conformance"
	task11SyntheticPermitScaleSet = "portable-ghar-conformance"
	task11SyntheticPermitTimeFmt  = "2006-01-02T15:04:05.000Z"
)

// acquireTask11SyntheticReleasePermit returns the operation guard that
// Orchestrator.Release requires, produced by the production lease-permit
// provider rather than a hand-written guard. The synthetic fixture has no
// Worker, so the cached lease it derives from is installed locally; it is
// bounded by the conformance authorization expiry and, like a Worker lease,
// ends the permit when the authority clock passes its deadline.
//
// The caller owns the guard and must Close it once Release has returned.
func acquireTask11SyntheticReleasePermit(
	ctx context.Context,
	clock failoverclient.AuthorityClock,
	cycle task11SyntheticCycleIdentity,
	repositoryAlias string,
	policyDigest string,
	now time.Time,
	notAfter time.Time,
	terminationTail time.Duration,
) (controller.AcquisitionPermitGuard, error) {
	remaining := notAfter.Sub(now)
	if ctx == nil || clock == nil || !clock.Capable() ||
		repositoryAlias == "" ||
		!isLowerHex(policyDigest, 64) ||
		terminationTail <= 0 ||
		remaining <= terminationTail {
		return nil, ErrFixtureStart
	}
	identity, err := recordingCanonicalDigest(
		task11SyntheticPermitDomain,
		struct {
			SchemaVersion uint32                   `json:"schema_version"`
			Cycle         task11SyntheticCycleKind `json:"cycle"`
			Ordinal       uint64                   `json:"ordinal"`
			RunDigest     string                   `json:"run_digest"`
		}{
			SchemaVersion: 1,
			Cycle:         cycle.Request.Kind,
			Ordinal:       cycle.Request.Ordinal,
			RunDigest:     cycle.RunDigest,
		},
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	authorityNow, err := clock.Now()
	if err != nil {
		return nil, ErrFixtureStart
	}

	scaleSet := task11SyntheticPermitScaleSet
	lease := failoverclient.AcquisitionLeaseV1{
		ProtocolVersion:          1,
		FleetID:                  task11SyntheticPermitFleetID,
		Holder:                   failoverclient.HolderPortable,
		ServerEpoch:              1,
		SessionID:                identity,
		LeaseGeneration:          1,
		Mode:                     failoverclient.LeaseCanaryOnly,
		PolicyDigest:             policyDigest,
		RepositoryPolicyRevision: 1,
		LocalPolicyEpoch:         1,
		MaxCapacity:              1,
		CanaryScaleSet:           &scaleSet,
		DurationMs:               remaining.Milliseconds(),
		Expiry: notAfter.UTC().
			Truncate(time.Millisecond).
			Format(task11SyntheticPermitTimeFmt),
	}
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		return nil, ErrFixtureStart
	}
	const fence uint64 = 1
	cache := &failoverclient.LeaseCache{}
	if _, err := cache.CompareAndSwap(0, &failoverclient.CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      1,
		Fence:         fence,
		LocalDeadline: authorityNow.Add(remaining),
		SendAnchor:    authorityNow,
	}); err != nil {
		return nil, ErrFixtureStart
	}
	provider, err := failoverclient.NewCachedLeasePermitProvider(
		failoverclient.CachedLeasePermitConfig{
			Cache:           cache,
			Clock:           clock,
			Holder:          failoverclient.HolderPortable,
			Fence:           fence,
			CallDuration:    remaining,
			TerminationTail: terminationTail,
		},
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	permit, err := provider.Acquire(ctx, controller.AcquisitionPermitRequest{
		OperationID:              identity,
		RepositoryAlias:          repositoryAlias,
		ScaleSetName:             scaleSet,
		PolicyDigest:             policyDigest,
		OperationKind:            "jit",
		PolicyEpoch:              lease.LocalPolicyEpoch,
		PolicyMode:               controller.AcquisitionCanaryOnly,
		MaxCapacity:              1,
		RepositoryPolicyRevision: lease.RepositoryPolicyRevision,
	})
	if err != nil {
		return nil, ErrFixtureStart
	}
	return permit, nil
}
