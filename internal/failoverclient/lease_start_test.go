package failoverclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestEmptyLeaseCacheIsPendingButNeverGrantsAPermit(t *testing.T) {
	f := newCachedPermitFixture(t, LeaseEnabled)
	if err := f.provider.Invalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
	permit, err := f.provider.Acquire(context.Background(), f.request)
	if permit != nil || !errors.Is(err, controller.ErrAcquisitionLeasePending) || !errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatal("empty post-transition cache was not distinguished from broken authority", err)
	}
	if _, err := f.cache.Revalidate(LeaseAuthorityToken{}); errors.Is(err, errLeaseCacheAwaiting) {
		t.Fatal("issued-permit revalidation became a pending wait")
	}
	f.cache.mu.Lock()
	f.cache.poisoned = true
	f.cache.mu.Unlock()
	permit, err = f.provider.Acquire(context.Background(), f.request)
	if permit != nil || errors.Is(err, controller.ErrAcquisitionLeasePending) || !errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatal("poisoned cache became a normal wait", err)
	}
}

func TestAnIssuedPermitNeverBecomesAPendingWaitAfterCacheClear(t *testing.T) {
	f := newCachedPermitFixture(t, LeaseEnabled)
	permit, err := f.provider.Acquire(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	if err := f.provider.Invalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Revalidate(); err == nil || errors.Is(err, controller.ErrAcquisitionLeasePending) {
		t.Fatal("issued permit waited instead of dropping authority", err)
	}
	if err := permit.Admit(); err == nil || errors.Is(err, controller.ErrAcquisitionLeasePending) {
		t.Fatal("cleared permit was admitted or waited", err)
	}
}

func TestAuthenticatedNoLeaseDenialIsNeverAStartupWait(t *testing.T) {
	for _, reason := range []NoLeaseReason{NoLeasePolicyMismatch, NoLeaseHostedHold, NoLeaseQueueRisk, NoLeaseRoutingHosted} {
		t.Run(string(reason), func(t *testing.T) {
			f := newHeartbeatSessionFixture(t)
			provider, err := NewCachedLeasePermitProvider(CachedLeasePermitConfig{Cache: f.cache, Clock: f.clock, Holder: HolderPortable, Fence: 7, CallDuration: 2 * time.Second, TerminationTail: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.Invalidate(context.Background()); err != nil {
				t.Fatal(err)
			}
			request := controller.AcquisitionPermitRequest{OperationID: "example-poll", RepositoryAlias: "repo-b", ScaleSetName: "canary-set", PolicyDigest: strings.Repeat("a", 64), OperationKind: "poll", PolicyEpoch: 9, PolicyMode: controller.AcquisitionEnabled, MaxCapacity: 2, RepositoryPolicyRevision: 4}
			if _, err := provider.Acquire(context.Background(), request); !errors.Is(err, controller.ErrAcquisitionLeasePending) {
				t.Fatal("transition did not wait", err)
			}
			f.transport.steps = []heartbeatStep{f.sessionStep(strings.Repeat("c", 64), 1, 1), func(exchange heartbeatExchange) (*http.Response, error) {
				response := HeartbeatResponseV1{ProtocolVersion: 1, FleetID: exchange.heartbeat.FleetID, SessionID: exchange.heartbeat.SessionID, Sequence: exchange.heartbeat.Sequence, ReceiptTime: exchange.heartbeat.Timestamp, RoutingState: RoutingHosted, Maintenance: MaintenanceDirectiveV1{Kind: MaintenanceNone, SessionID: exchange.heartbeat.SessionID, LeaseGeneration: 1}, NoLeaseReason: &reason}
				return f.signedResponse(HeartbeatPath, exchange.heartbeat.Timestamp, response), nil
			}}
			if err := f.session.Publish(context.Background(), heartbeatHealthSnapshot()); err != nil {
				t.Fatal(err)
			}
			permit, err := provider.Acquire(context.Background(), request)
			if permit != nil || errors.Is(err, controller.ErrAcquisitionLeasePending) || !errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
				t.Fatal("authenticated denial became an active-policy wait", err)
			}
		})
	}
}

func TestOrdinaryCacheClearIsNeverAStartupWait(t *testing.T) {
	f := newCachedPermitFixture(t, LeaseEnabled)
	if _, err := f.cache.CompareAndSwap(f.revision, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.provider.Acquire(context.Background(), f.request); errors.Is(err, controller.ErrAcquisitionLeasePending) || !errors.Is(err, controller.ErrAcquisitionPermitAuthority) {
		t.Fatal("ordinary clear became a transition wait", err)
	}
}

func TestStaleDenialCannotOverwriteANewerTransitionWait(t *testing.T) {
	f := newCachedPermitFixture(t, LeaseEnabled)
	if err := f.provider.Invalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cache.CompareAndSwap(f.revision, nil); err == nil {
		t.Fatal("stale denial overwrote a new cache revision")
	}
	if _, err := f.provider.Acquire(context.Background(), f.request); !errors.Is(err, controller.ErrAcquisitionLeasePending) {
		t.Fatal("stale denial erased the transition wait", err)
	}
}
