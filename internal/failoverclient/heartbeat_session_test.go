package failoverclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/health"
)

type heartbeatFleetGuardProvider struct {
	acquired int
	closed   int
	err      error
	closeErr error
}

type heartbeatFleetGuard struct {
	provider *heartbeatFleetGuardProvider
	closed   bool
}

func (provider *heartbeatFleetGuardProvider) AcquirePortable(
	context.Context,
) (controller.AcquisitionGuard, error) {
	provider.acquired++
	if provider.err != nil {
		return nil, provider.err
	}
	return &heartbeatFleetGuard{provider: provider}, nil
}

func (guard *heartbeatFleetGuard) Close() error {
	if guard.closed {
		return errors.New("heartbeat fleet guard closed twice")
	}
	guard.closed = true
	guard.provider.closed++
	return guard.provider.closeErr
}

type heartbeatExchange struct {
	path      string
	session   SessionRequestV1
	heartbeat HeartbeatRequestV1
}

type heartbeatStep func(heartbeatExchange) (*http.Response, error)

type scriptedHeartbeatTransport struct {
	t          *testing.T
	key        []byte
	steps      []heartbeatStep
	exchanges  []heartbeatExchange
	idleCloses int
}

func (transport *scriptedHeartbeatTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		transport.t.Fatalf("read request body: %v", err)
	}
	exchange := heartbeatExchange{path: request.URL.Path}
	switch request.URL.Path {
	case SessionPath:
		exchange.session, err = ParseSessionRequestV1(body)
	case HeartbeatPath:
		exchange.heartbeat, err = ParseHeartbeatRequestV1(body)
	default:
		transport.t.Fatalf("unexpected request path %q", request.URL.Path)
	}
	if err != nil {
		transport.t.Fatalf("parse %s request: %v", request.URL.Path, err)
	}
	transport.exchanges = append(transport.exchanges, exchange)
	stepIndex := len(transport.exchanges) - 1
	if stepIndex >= len(transport.steps) {
		transport.t.Fatalf("unexpected request %d to %s", stepIndex+1, request.URL.Path)
	}
	return transport.steps[stepIndex](exchange)
}

func (transport *scriptedHeartbeatTransport) CloseIdleConnections() {
	transport.idleCloses++
}

type heartbeatSessionFixture struct {
	t         *testing.T
	transport *scriptedHeartbeatTransport
	clock     *FakeAuthorityClock
	cache     *LeaseCache
	session   *HeartbeatSession
	guards    *heartbeatFleetGuardProvider
	budget    HeartbeatBudget
	nonces    []string
	nonceCall int
}

func newHeartbeatSessionFixture(t *testing.T) *heartbeatSessionFixture {
	t.Helper()
	key := []byte(strings.Repeat("k", 32))
	transport := &scriptedHeartbeatTransport{t: t, key: key}
	clock := NewFakeAuthorityClock(time.Unix(100, 0))
	clientConfig := protocolClientConfig(transport)
	clientConfig.HMACKey = key
	clientConfig.AuthorityClock = clock
	client, err := NewProtocolClient(clientConfig)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	fixture := &heartbeatSessionFixture{
		t:         t,
		transport: transport,
		clock:     clock,
		cache:     &LeaseCache{},
		guards:    &heartbeatFleetGuardProvider{},
		budget: HeartbeatBudget{
			LeaseDuration:      8 * time.Second,
			MaxAttemptInterval: time.Second,
			Deadline:           time.Second,
			ShorteningMargin:   2 * time.Second,
			LostRenewals:       1,
		},
		nonces: []string{
			strings.Repeat("a", 64),
			strings.Repeat("d", 64),
			strings.Repeat("f", 64),
		},
	}
	fixture.session, err = NewHeartbeatSession(HeartbeatSessionConfig{
		Client:          client,
		Cache:           fixture.cache,
		FleetGuards:     fixture.guards,
		FleetID:         "example-fleet",
		BuildID:         strings.Repeat("b", 64),
		Holder:          HeartbeatHolderPortable,
		FenceGeneration: 7,
		Budget:          fixture.budget,
		NextNonce: func() (string, error) {
			if fixture.nonceCall >= len(fixture.nonces) {
				return "", fmt.Errorf("nonce fixture exhausted")
			}
			nonce := fixture.nonces[fixture.nonceCall]
			fixture.nonceCall++
			return nonce, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHeartbeatSession: %v", err)
	}
	t.Cleanup(func() {
		if err := fixture.session.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return fixture
}

func heartbeatHealthSnapshot() health.Snapshot {
	observedAt := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	return health.Snapshot{
		ObservedAt:                  observedAt,
		FleetAlias:                  "example-fleet",
		AcquisitionMode:             health.AcquisitionEnabled,
		PolicyEpoch:                 9,
		PolicyDigest:                strings.Repeat("a", 64),
		RepositoryPolicyRevision:    4,
		Capacity:                    health.CapacitySummary{Configured: 4, Effective: 3, Occupied: 1, Available: 2, Queued: 1},
		AssignedJobs:                2,
		RunningJobs:                 1,
		OldestLiveAssignmentAge:     1500 * time.Millisecond,
		UnassignedReleasedListeners: 1,
		LastTerminalAt:              observedAt.Add(-time.Second),
		HostProfileID:               "qts-capless-root",
		Degraded:                    true,
		BuildID:                     strings.Repeat("b", 64),
	}
}

func (fixture *heartbeatSessionFixture) sessionStep(sessionID string, epoch, generation uint64) heartbeatStep {
	return func(exchange heartbeatExchange) (*http.Response, error) {
		fixture.t.Helper()
		if exchange.path != SessionPath {
			fixture.t.Fatalf("request path = %q, want %q", exchange.path, SessionPath)
		}
		response := SessionResponseV1{
			ProtocolVersion: 1,
			FleetID:         exchange.session.FleetID,
			Nonce:           exchange.session.Nonce,
			Epoch:           epoch,
			SessionID:       sessionID,
			Sequence:        0,
			LeaseGeneration: generation,
			LeaseNotBefore:  exchange.session.Timestamp,
			ReceiptTime:     exchange.session.Timestamp,
		}
		return fixture.signedResponse(SessionPath, exchange.session.Timestamp, response), nil
	}
}

func (fixture *heartbeatSessionFixture) leaseStep(generation uint64, beforeResponse func()) heartbeatStep {
	return func(exchange heartbeatExchange) (*http.Response, error) {
		fixture.t.Helper()
		if exchange.path != HeartbeatPath {
			fixture.t.Fatalf("request path = %q, want %q", exchange.path, HeartbeatPath)
		}
		if beforeResponse != nil {
			beforeResponse()
		}
		response := fixture.leaseResponse(exchange.heartbeat, generation)
		return fixture.signedResponse(HeartbeatPath, exchange.heartbeat.Timestamp, response), nil
	}
}

func (fixture *heartbeatSessionFixture) noLeaseStep(generation uint64) heartbeatStep {
	return func(exchange heartbeatExchange) (*http.Response, error) {
		fixture.t.Helper()
		if exchange.path != HeartbeatPath {
			fixture.t.Fatalf("request path = %q, want %q", exchange.path, HeartbeatPath)
		}
		reason := NoLeaseDisabled
		response := HeartbeatResponseV1{
			ProtocolVersion: 1,
			FleetID:         exchange.heartbeat.FleetID,
			SessionID:       exchange.heartbeat.SessionID,
			Sequence:        exchange.heartbeat.Sequence,
			ReceiptTime:     exchange.heartbeat.Timestamp,
			RoutingState:    RoutingHosted,
			Maintenance: MaintenanceDirectiveV1{
				Kind:            MaintenanceNone,
				SessionID:       exchange.heartbeat.SessionID,
				LeaseGeneration: generation,
			},
			NoLeaseReason: &reason,
		}
		return fixture.signedResponse(HeartbeatPath, exchange.heartbeat.Timestamp, response), nil
	}
}

func (fixture *heartbeatSessionFixture) transportErrorStep(path string, injected error) heartbeatStep {
	return func(exchange heartbeatExchange) (*http.Response, error) {
		fixture.t.Helper()
		if exchange.path != path {
			fixture.t.Fatalf("request path = %q, want %q", exchange.path, path)
		}
		return nil, injected
	}
}

func (fixture *heartbeatSessionFixture) badMACStep(generation uint64) heartbeatStep {
	return func(exchange heartbeatExchange) (*http.Response, error) {
		fixture.t.Helper()
		response := fixture.signedResponse(
			HeartbeatPath,
			exchange.heartbeat.Timestamp,
			fixture.leaseResponse(exchange.heartbeat, generation),
		)
		response.Header.Set(MACHeader, strings.Repeat("0", 64))
		return response, nil
	}
}

func (fixture *heartbeatSessionFixture) wrongBindingStep(generation uint64) heartbeatStep {
	return func(exchange heartbeatExchange) (*http.Response, error) {
		fixture.t.Helper()
		response := fixture.leaseResponse(exchange.heartbeat, generation)
		response.Sequence++
		return fixture.signedResponse(HeartbeatPath, exchange.heartbeat.Timestamp, response), nil
	}
}

func (fixture *heartbeatSessionFixture) leaseResponse(request HeartbeatRequestV1, generation uint64) HeartbeatResponseV1 {
	fixture.t.Helper()
	receipt, err := parseProtocolTimestamp(request.Timestamp)
	if err != nil {
		fixture.t.Fatalf("parse request timestamp: %v", err)
	}
	lease := AcquisitionLeaseV1{
		ProtocolVersion:          1,
		FleetID:                  request.FleetID,
		Holder:                   LeaseHolder(request.Holder),
		ServerEpoch:              request.Epoch,
		SessionID:                request.SessionID,
		LeaseGeneration:          generation,
		Mode:                     LeaseEnabled,
		PolicyDigest:             request.Snapshot.PolicyDigest,
		RepositoryPolicyRevision: request.Snapshot.RepositoryPolicyRevision,
		LocalPolicyEpoch:         request.Snapshot.PolicyEpoch,
		MaxCapacity:              int(request.Snapshot.Capacity.Effective),
		ArchivedDisabledAliases:  []string{},
		DurationMs:               fixture.budget.LeaseDuration.Milliseconds(),
		Expiry:                   FormatProtocolTimestamp(receipt.Add(fixture.budget.LeaseDuration)),
	}
	return HeartbeatResponseV1{
		ProtocolVersion: 1,
		FleetID:         request.FleetID,
		SessionID:       request.SessionID,
		Sequence:        request.Sequence,
		ReceiptTime:     request.Timestamp,
		RoutingState:    RoutingPortable,
		Maintenance: MaintenanceDirectiveV1{
			Kind:            MaintenanceNone,
			SessionID:       request.SessionID,
			LeaseGeneration: generation,
		},
		Lease: &lease,
	}
}

func (fixture *heartbeatSessionFixture) signedResponse(path, timestamp string, document any) *http.Response {
	fixture.t.Helper()
	body, err := CanonicalJSON(document)
	if err != nil {
		fixture.t.Fatalf("CanonicalJSON response: %v", err)
	}
	return signedResponse(fixture.t, fixture.transport.key, path, timestamp, body, http.StatusOK)
}

func (fixture *heartbeatSessionFixture) sessionRequests() []SessionRequestV1 {
	var requests []SessionRequestV1
	for _, exchange := range fixture.transport.exchanges {
		if exchange.path == SessionPath {
			requests = append(requests, exchange.session)
		}
	}
	return requests
}

func (fixture *heartbeatSessionFixture) heartbeatRequests() []HeartbeatRequestV1 {
	var requests []HeartbeatRequestV1
	for _, exchange := range fixture.transport.exchanges {
		if exchange.path == HeartbeatPath {
			requests = append(requests, exchange.heartbeat)
		}
	}
	return requests
}

func requireHeartbeatCacheEmpty(t *testing.T, cache *LeaseCache) {
	t.Helper()
	if snapshot, err := cache.Snapshot(); !errors.Is(err, ErrLeaseCache) {
		t.Fatalf("cache retained authority: snapshot=%+v error=%v", snapshot, err)
	}
}

func requireHeartbeatCachedLease(t *testing.T, cache *LeaseCache) *CachedLeaseSnapshot {
	t.Helper()
	snapshot, err := cache.Snapshot()
	if err != nil {
		t.Fatalf("cache Snapshot: %v", err)
	}
	return snapshot
}

func TestLeaseCacheMutationRevisionRemainsObservableWhenEmpty(t *testing.T) {
	cache := &LeaseCache{}
	if revision, err := cache.MutationRevision(); err != nil || revision != 0 {
		t.Fatalf("initial MutationRevision = (%d, %v), want (0, nil)", revision, err)
	}
	anchor := time.Unix(100, 0)
	lease := cachedLeaseForTest(t, testLease(LeaseEnabled), 1, 7, anchor, anchor.Add(6*time.Second))
	revision, err := cache.CompareAndSwap(0, &lease)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	revision, err = cache.CompareAndSwap(revision, nil)
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got, gotErr := cache.MutationRevision(); gotErr != nil || got != revision {
		t.Fatalf("empty MutationRevision = (%d, %v), want (%d, nil)", got, gotErr, revision)
	}
}

func TestHeartbeatSessionUncertainEnrollmentUsesFreshNonce(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	fixture.transport.steps = []heartbeatStep{
		fixture.transportErrorStep(SessionPath, errors.New("ambiguous enrollment")),
		fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
		fixture.noLeaseStep(1),
	}

	if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); !errors.Is(err, ErrHeartbeatSession) {
		t.Fatalf("uncertain enrollment error = %v", err)
	}
	requireHeartbeatCacheEmpty(t, fixture.cache)
	if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); err != nil {
		t.Fatalf("fresh enrollment Publish: %v", err)
	}

	sessions := fixture.sessionRequests()
	if len(sessions) != 2 || sessions[0].Nonce == sessions[1].Nonce || sessions[0].Nonce != fixture.nonces[0] || sessions[1].Nonce != fixture.nonces[1] {
		t.Fatalf("session nonces = %+v, want two fresh nonces", sessions)
	}
	heartbeats := fixture.heartbeatRequests()
	if len(heartbeats) != 1 || heartbeats[0].Sequence != 1 || heartbeats[0].SessionID != strings.Repeat("c", 64) {
		t.Fatalf("heartbeats after uncertain enrollment = %+v", heartbeats)
	}
}

func TestHeartbeatSessionEnrollsOnceThenPublishesBoundHeartbeats(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	fixture.transport.steps = []heartbeatStep{
		fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
		fixture.leaseStep(1, nil),
		fixture.leaseStep(1, nil),
	}
	snapshot := heartbeatHealthSnapshot()
	if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
		t.Fatalf("second Publish: %v", err)
	}

	if sessions := fixture.sessionRequests(); len(sessions) != 1 {
		t.Fatalf("session requests = %d, want 1", len(sessions))
	}
	heartbeats := fixture.heartbeatRequests()
	if len(heartbeats) != 2 || heartbeats[0].Sequence != 1 || heartbeats[1].Sequence != 2 ||
		heartbeats[0].SessionID != heartbeats[1].SessionID {
		t.Fatalf("heartbeat sequence/session = %+v", heartbeats)
	}
	if fixture.guards.acquired != 2 || fixture.guards.closed != 2 {
		t.Fatalf(
			"fleet guard lifecycle = acquired:%d closed:%d, want 2/2",
			fixture.guards.acquired,
			fixture.guards.closed,
		)
	}
	requestSnapshot := heartbeats[0].Snapshot
	if requestSnapshot.FleetAlias != snapshot.FleetAlias ||
		requestSnapshot.OldestLiveAssignmentAgeMs != 1500 ||
		requestSnapshot.LastTerminalAt == nil ||
		requestSnapshot.Capacity.Available != 2 ||
		requestSnapshot.BuildID != snapshot.BuildID {
		t.Fatalf("converted heartbeat snapshot = %+v", requestSnapshot)
	}
}

func TestHeartbeatSessionConsumesAmbiguousSequenceWithoutReplay(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	fixture.transport.steps = []heartbeatStep{
		fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
		fixture.leaseStep(1, nil),
		fixture.transportErrorStep(HeartbeatPath, errors.New("ambiguous heartbeat")),
		fixture.leaseStep(1, nil),
	}
	snapshot := heartbeatHealthSnapshot()
	if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	if err := fixture.session.Publish(context.Background(), snapshot); !errors.Is(err, ErrHeartbeatSession) {
		t.Fatalf("ambiguous Publish error = %v", err)
	}
	requireHeartbeatCacheEmpty(t, fixture.cache)
	if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
		t.Fatalf("post-ambiguity Publish: %v", err)
	}

	heartbeats := fixture.heartbeatRequests()
	if len(heartbeats) != 3 || heartbeats[0].Sequence != 1 || heartbeats[1].Sequence != 2 || heartbeats[2].Sequence != 3 {
		t.Fatalf("heartbeat sequences = %+v, want 1,2,3", heartbeats)
	}
	if len(fixture.sessionRequests()) != 1 {
		t.Fatalf("ambiguous heartbeat replaced verified session: %+v", fixture.sessionRequests())
	}
}

func TestHeartbeatSessionAuthenticatedOrBindingFailureForcesReplacement(t *testing.T) {
	for _, failure := range []string{"authentication", "binding"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newHeartbeatSessionFixture(t)
			var failed heartbeatStep
			if failure == "authentication" {
				failed = fixture.badMACStep(1)
			} else {
				failed = fixture.wrongBindingStep(1)
			}
			fixture.transport.steps = []heartbeatStep{
				fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
				fixture.leaseStep(1, nil),
				failed,
				fixture.sessionStep(strings.Repeat("e", 64), 2, 2),
				fixture.leaseStep(2, nil),
			}
			snapshot := heartbeatHealthSnapshot()
			if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
				t.Fatalf("first Publish: %v", err)
			}
			if err := fixture.session.Publish(context.Background(), snapshot); !errors.Is(err, ErrHeartbeatSession) {
				t.Fatalf("failed Publish error = %v", err)
			}
			requireHeartbeatCacheEmpty(t, fixture.cache)
			if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
				t.Fatalf("replacement Publish: %v", err)
			}

			sessions := fixture.sessionRequests()
			if len(sessions) != 2 || sessions[0].Nonce == sessions[1].Nonce {
				t.Fatalf("replacement sessions = %+v", sessions)
			}
			heartbeats := fixture.heartbeatRequests()
			if len(heartbeats) != 3 ||
				heartbeats[0].SessionID != strings.Repeat("c", 64) || heartbeats[0].Sequence != 1 ||
				heartbeats[1].SessionID != strings.Repeat("c", 64) || heartbeats[1].Sequence != 2 ||
				heartbeats[2].SessionID != strings.Repeat("e", 64) || heartbeats[2].Sequence != 1 {
				t.Fatalf("replacement heartbeat identity = %+v", heartbeats)
			}
		})
	}
}

func TestHeartbeatSessionRejectsGenerationRegressionFromEnrollment(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	fixture.transport.steps = []heartbeatStep{
		fixture.sessionStep(strings.Repeat("c", 64), 1, 2),
		fixture.noLeaseStep(1),
	}

	if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); !errors.Is(err, ErrHeartbeatSession) {
		t.Fatalf("generation-regressing Publish = %v, want ErrHeartbeatSession", err)
	}
	requireHeartbeatCacheEmpty(t, fixture.cache)
}

func TestHeartbeatSessionFleetGuardFailuresLeaveNoAuthority(t *testing.T) {
	for _, failure := range []string{"acquire", "close"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newHeartbeatSessionFixture(t)
			if failure == "acquire" {
				fixture.guards.err = errors.New("injected fleet guard acquisition failure")
			} else {
				fixture.guards.closeErr = errors.New("injected fleet guard close failure")
				fixture.transport.steps = []heartbeatStep{
					fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
					fixture.leaseStep(1, nil),
				}
			}
			if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); !errors.Is(err, ErrHeartbeatSession) {
				t.Fatalf("%s failure Publish = %v, want ErrHeartbeatSession", failure, err)
			}
			requireHeartbeatCacheEmpty(t, fixture.cache)
			if failure == "acquire" && len(fixture.transport.exchanges) != 0 {
				t.Fatalf("fleet guard acquisition failure reached transport: %+v", fixture.transport.exchanges)
			}
		})
	}
}

func TestHeartbeatSessionCloseIsIdleAndIdempotent(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	if err := fixture.session.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := fixture.session.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if fixture.transport.idleCloses != 1 || len(fixture.transport.exchanges) != 0 {
		t.Fatalf("close effects idle=%d exchanges=%d, want 1/0", fixture.transport.idleCloses, len(fixture.transport.exchanges))
	}
	if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); !errors.Is(err, ErrHeartbeatSession) {
		t.Fatalf("Publish after Close error = %v", err)
	}
}

func TestHeartbeatSessionRejectsLossyHealthSnapshotBeforeTransport(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*health.Snapshot)
	}{
		{
			name: "age is not whole milliseconds",
			mutate: func(snapshot *health.Snapshot) {
				snapshot.OldestLiveAssignmentAge += time.Nanosecond
			},
		},
		{
			name: "observed time is not whole milliseconds",
			mutate: func(snapshot *health.Snapshot) {
				snapshot.ObservedAt = snapshot.ObservedAt.Add(time.Nanosecond)
			},
		},
		{
			name: "terminal time is not whole milliseconds",
			mutate: func(snapshot *health.Snapshot) {
				snapshot.LastTerminalAt = snapshot.LastTerminalAt.Add(time.Nanosecond)
			},
		},
	}
	if strconv.IntSize == 64 {
		tests = append(tests, struct {
			name   string
			mutate func(*health.Snapshot)
		}{
			name: "capacity exceeds the wire integer domain",
			mutate: func(snapshot *health.Snapshot) {
				overflow := uint64(maxJavaScriptSafeInteger) + 1
				snapshot.Capacity.Configured = int(overflow)
				snapshot.Capacity.Effective = int(overflow)
				snapshot.Capacity.Occupied = 0
				snapshot.Capacity.Available = int(overflow)
			},
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHeartbeatSessionFixture(t)
			snapshot := heartbeatHealthSnapshot()
			test.mutate(&snapshot)
			if err := snapshot.Validate(); err != nil {
				t.Fatalf("health snapshot precondition: %v", err)
			}
			if err := fixture.session.Publish(context.Background(), snapshot); !errors.Is(err, ErrHeartbeatSession) {
				t.Fatalf("lossy Publish error = %v", err)
			}
			if len(fixture.transport.exchanges) != 0 {
				t.Fatalf("lossy snapshot reached transport: %+v", fixture.transport.exchanges)
			}
		})
	}
}

func TestHeartbeatSessionClearsLeaseOnNoLeaseErrorAndExactLateResponse(t *testing.T) {
	for _, outcome := range []string{"no lease", "transport error", "exact deadline"} {
		t.Run(outcome, func(t *testing.T) {
			fixture := newHeartbeatSessionFixture(t)
			var second heartbeatStep
			wantError := false
			switch outcome {
			case "no lease":
				second = fixture.noLeaseStep(1)
			case "transport error":
				second = fixture.transportErrorStep(HeartbeatPath, errors.New("heartbeat unavailable"))
				wantError = true
			case "exact deadline":
				second = fixture.leaseStep(1, func() {
					fixture.clock.Advance(fixture.budget.LeaseDuration - fixture.budget.ShorteningMargin)
				})
				wantError = true
			}
			fixture.transport.steps = []heartbeatStep{
				fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
				fixture.leaseStep(1, nil),
				second,
			}
			snapshot := heartbeatHealthSnapshot()
			if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
				t.Fatalf("seed Publish: %v", err)
			}
			requireHeartbeatCachedLease(t, fixture.cache)
			err := fixture.session.Publish(context.Background(), snapshot)
			if wantError && !errors.Is(err, ErrHeartbeatSession) {
				t.Fatalf("Publish error = %v", err)
			}
			if !wantError && err != nil {
				t.Fatalf("no-lease Publish: %v", err)
			}
			requireHeartbeatCacheEmpty(t, fixture.cache)
		})
	}
}

func TestHeartbeatSessionInstallsLeaseWithSendAnchoredDeadline(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	fixture.transport.steps = []heartbeatStep{
		fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
		fixture.leaseStep(1, nil),
	}
	if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	cached := requireHeartbeatCachedLease(t, fixture.cache)
	wantAnchor := time.Unix(100, 0)
	wantDeadline := wantAnchor.Add(fixture.budget.LeaseDuration - fixture.budget.ShorteningMargin)
	if !cached.SendAnchor.Equal(wantAnchor) || !cached.LocalDeadline.Equal(wantDeadline) ||
		cached.Sequence != 1 || cached.Fence != 7 || cached.Lease.SessionID != strings.Repeat("c", 64) {
		t.Fatalf("cached lease = %+v, want anchor=%s deadline=%s sequence=1 fence=7", cached, wantAnchor, wantDeadline)
	}
}

func TestHeartbeatSessionRejectsLeaseOutsideExactLocalPolicy(t *testing.T) {
	for _, mismatch := range []string{"mode", "maximum capacity", "duration"} {
		t.Run(mismatch, func(t *testing.T) {
			fixture := newHeartbeatSessionFixture(t)
			fixture.transport.steps = []heartbeatStep{
				fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
				func(exchange heartbeatExchange) (*http.Response, error) {
					response := fixture.leaseResponse(exchange.heartbeat, 1)
					switch mismatch {
					case "mode":
						response.RoutingState = RoutingPortableCanary
						response.Lease.Mode = LeaseCanaryOnly
						response.Lease.MaxCapacity = 1
						canary := "canary-set"
						response.Lease.CanaryScaleSet = &canary
					case "maximum capacity":
						response.Lease.MaxCapacity--
					case "duration":
						response.Lease.DurationMs--
						receipt, err := parseProtocolTimestamp(response.ReceiptTime)
						if err != nil {
							t.Fatalf("parse response receipt: %v", err)
						}
						response.Lease.Expiry = FormatProtocolTimestamp(
							receipt.Add(time.Duration(response.Lease.DurationMs) * time.Millisecond),
						)
					}
					return fixture.signedResponse(HeartbeatPath, exchange.heartbeat.Timestamp, response), nil
				},
			}
			if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); !errors.Is(err, ErrHeartbeatSession) {
				t.Fatalf("Publish with %s mismatch = %v, want ErrHeartbeatSession", mismatch, err)
			}
			requireHeartbeatCacheEmpty(t, fixture.cache)
		})
	}
}

func TestHeartbeatSessionPureRenewalKeepsTokenAndReplacementChangesIt(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	fixture.transport.steps = []heartbeatStep{
		fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
		fixture.leaseStep(1, nil),
		fixture.leaseStep(1, nil),
		fixture.wrongBindingStep(1),
		fixture.sessionStep(strings.Repeat("e", 64), 2, 2),
		fixture.leaseStep(2, nil),
	}
	snapshot := heartbeatHealthSnapshot()
	if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
		t.Fatalf("initial Publish: %v", err)
	}
	initial := requireHeartbeatCachedLease(t, fixture.cache)
	if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
		t.Fatalf("renewal Publish: %v", err)
	}
	renewed := requireHeartbeatCachedLease(t, fixture.cache)
	if renewed.AuthorityToken != initial.AuthorityToken || renewed.MutationRevision == initial.MutationRevision {
		t.Fatalf("renewal token/revision = (%+v, %d), initial=(%+v, %d)",
			renewed.AuthorityToken, renewed.MutationRevision, initial.AuthorityToken, initial.MutationRevision)
	}
	if err := fixture.session.Publish(context.Background(), snapshot); !errors.Is(err, ErrHeartbeatSession) {
		t.Fatalf("binding failure error = %v", err)
	}
	if err := fixture.session.Publish(context.Background(), snapshot); err != nil {
		t.Fatalf("replacement Publish: %v", err)
	}
	replacement := requireHeartbeatCachedLease(t, fixture.cache)
	if replacement.AuthorityToken == initial.AuthorityToken {
		t.Fatalf("replacement preserved authority token: %+v", replacement.AuthorityToken)
	}
}

func TestHeartbeatSessionCASConflictFailsClosedWithoutClobberingWinner(t *testing.T) {
	fixture := newHeartbeatSessionFixture(t)
	fixture.transport.steps = []heartbeatStep{
		fixture.sessionStep(strings.Repeat("c", 64), 1, 1),
		fixture.leaseStep(1, func() {
			anchor, err := fixture.clock.Now()
			if err != nil {
				t.Fatalf("clock Now: %v", err)
			}
			lease := testLease(LeaseEnabled)
			lease.SessionID = strings.Repeat("9", 64)
			lease.ServerEpoch = 9
			lease.LeaseGeneration = 9
			winner := cachedLeaseForTest(t, lease, 1, 7, anchor, anchor.Add(6*time.Second))
			if _, err := fixture.cache.CompareAndSwap(0, &winner); err != nil {
				t.Fatalf("install competing authority: %v", err)
			}
		}),
	}

	if err := fixture.session.Publish(context.Background(), heartbeatHealthSnapshot()); !errors.Is(err, ErrHeartbeatSession) {
		t.Fatalf("CAS-conflicted Publish error = %v", err)
	}
	winner := requireHeartbeatCachedLease(t, fixture.cache)
	if winner.Lease.SessionID != strings.Repeat("9", 64) || winner.Lease.LeaseGeneration != 9 || winner.Sequence != 1 {
		t.Fatalf("CAS conflict clobbered winner: %+v", winner)
	}
}
