package failoverclient

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func testLease(mode LeaseMode) AcquisitionLeaseV1 {
	canary := "canary-set"
	lease := AcquisitionLeaseV1{
		ProtocolVersion:          1,
		FleetID:                  "example-fleet",
		Holder:                   HolderPortable,
		ServerEpoch:              2,
		SessionID:                strings.Repeat("b", 64),
		LeaseGeneration:          3,
		Mode:                     mode,
		PolicyDigest:             strings.Repeat("a", 64),
		RepositoryPolicyRevision: 4,
		LocalPolicyEpoch:         9,
		MaxCapacity:              1,
		DurationMs:               8000,
		Expiry:                   "2026-01-01T00:00:08.000Z",
	}
	if mode == LeaseCanaryOnly {
		lease.CanaryScaleSet = &canary
	}
	if mode == LeaseEnabled {
		lease.MaxCapacity = 2
	}
	return lease
}

func TestCachedLeasePermitRejectsStaleExpiredAndArchived(t *testing.T) {
	clock := NewFakeAuthorityClock(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	cache := &LeaseCache{}
	lease := testLease(LeaseCanaryOnly)
	lease.ArchivedDisabledAliases = []string{"repo-a"}
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := cache.Install(CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      4,
		Fence:         7,
		LocalDeadline: time.Date(2026, 1, 1, 0, 0, 7, 0, time.UTC),
		SendAnchor:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	provider, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           cache,
		Clock:           clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    2 * time.Second,
		TerminationTail: time.Second,
	})
	if err != nil {
		t.Fatalf("NewCachedLeasePermitProvider: %v", err)
	}
	request := controller.AcquisitionPermitRequest{
		OperationID:     "op-1",
		RepositoryAlias: "repo-b",
		ScaleSetName:    "canary-set",
		PolicyDigest:    strings.Repeat("a", 64),
		OperationKind:   "poll",
		PolicyEpoch:     9,
	}
	if _, err := provider.Acquire(context.Background(), request); err != nil {
		t.Fatalf("Acquire valid: %v", err)
	}
	request.RepositoryAlias = "repo-a"
	if _, err := provider.Acquire(context.Background(), request); err == nil {
		t.Fatal("archived alias authorized")
	}
	request.RepositoryAlias = "repo-b"
	clock.Advance(10 * time.Second)
	if _, err := provider.Acquire(context.Background(), request); err == nil {
		t.Fatal("expired lease authorized")
	}
	cache.Clear()
	clock = NewFakeAuthorityClock(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	provider.Clock = clock
	if _, err := provider.Acquire(context.Background(), request); err == nil {
		t.Fatal("empty cache authorized")
	}
}

func TestUnsupportedClockCannotAuthorize(t *testing.T) {
	if _, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           &LeaseCache{},
		Clock:           NewUnsupportedAuthorityClock(),
		Holder:          HolderPortable,
		Fence:           1,
		CallDuration:    time.Second,
		TerminationTail: 100 * time.Millisecond,
	}); err == nil {
		t.Fatal("unsupported clock accepted")
	}
	provider := CachedLeasePermitProvider{
		Cache:  &LeaseCache{},
		Clock:  NewUnsupportedAuthorityClock(),
		Holder: HolderPortable,
		Fence:  1,
	}
	if _, err := provider.Acquire(context.Background(), controller.AcquisitionPermitRequest{
		PolicyDigest: strings.Repeat("a", 64),
		PolicyEpoch:  1,
	}); err == nil {
		t.Fatal("unsupported clock authorized")
	}
}

func TestLeaseGuardCloseFailsAfterOperationDeadline(t *testing.T) {
	clock := NewFakeAuthorityClock(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	cache := &LeaseCache{}
	lease := testLease(LeaseEnabled)
	key, err := lease.AdmissionAuthorityKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := cache.Install(CachedLease{
		Lease:         lease,
		Key:           key,
		Sequence:      4,
		Fence:         7,
		LocalDeadline: time.Date(2026, 1, 1, 0, 0, 7, 0, time.UTC),
		SendAnchor:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	provider, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           cache,
		Clock:           clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    2 * time.Second,
		TerminationTail: time.Second,
	})
	if err != nil {
		t.Fatalf("NewCachedLeasePermitProvider: %v", err)
	}
	guard, err := provider.Acquire(context.Background(), controller.AcquisitionPermitRequest{
		PolicyDigest: strings.Repeat("a", 64),
		PolicyEpoch:  9,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("Close while current: %v", err)
	}
	guard, err = provider.Acquire(context.Background(), controller.AcquisitionPermitRequest{
		PolicyDigest: strings.Repeat("a", 64),
		PolicyEpoch:  9,
	})
	if err != nil {
		t.Fatalf("Acquire second: %v", err)
	}
	clock.Advance(10 * time.Second)
	if err := guard.Close(); err == nil {
		t.Fatal("Close after deadline succeeded")
	}
}

func TestNewCachedLeasePermitProviderRejectsIncompleteConfig(t *testing.T) {
	clock := NewFakeAuthorityClock(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	if _, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Clock:           clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    time.Second,
		TerminationTail: 100 * time.Millisecond,
	}); err == nil {
		t.Fatal("missing cache accepted")
	}
	if _, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{
		Cache:           &LeaseCache{},
		Clock:           clock,
		Holder:          HolderPortable,
		Fence:           7,
		CallDuration:    0,
		TerminationTail: 100 * time.Millisecond,
	}); err == nil {
		t.Fatal("unset call duration accepted")
	}
}
