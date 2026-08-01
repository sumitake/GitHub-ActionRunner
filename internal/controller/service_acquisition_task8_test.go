package controller

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

type task8RecordingGuard struct {
	mu    sync.Mutex
	name  string
	trace *callTrace
	err   error
	calls int
}

func (g *task8RecordingGuard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if g.trace != nil {
		g.trace.Add("guard:close:" + g.name)
	}
	return g.err
}

type task8FleetGuardProvider struct {
	guard AcquisitionGuard
	err   error
}

func (p *task8FleetGuardProvider) AcquirePortable(context.Context) (AcquisitionGuard, error) {
	return p.guard, p.err
}

type task8PermitProvider struct {
	mu       sync.Mutex
	guard    AcquisitionGuard
	err      error
	guards   map[string]AcquisitionGuard
	errors   map[string]error
	requests []AcquisitionPermitRequest
}

func (p *task8PermitProvider) Acquire(
	_ context.Context,
	request AcquisitionPermitRequest,
) (AcquisitionGuard, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, request)
	if err, ok := p.errors[request.OperationKind]; ok {
		return nil, err
	}
	if guard, ok := p.guards[request.OperationKind]; ok {
		return guard, nil
	}
	return p.guard, p.err
}

func TestPollAcquiresExactSubsetBeforeDemandProjectionAndAck(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 0, 0, 0, time.UTC)
	trace := &callTrace{}
	first := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8101,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	second := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8102,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	acquiredKey := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 8102}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        2,
			PollCapacity:    2,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{
			Key:   acquiredKey,
			Offer: second,
			Phase: AdmissionQueued,
		}},
	}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{
			MessageID:  811,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 7},
			Offers:     []githubscale.Offer{second, first},
		},
		acquiredIDs: []int64{8102},
	}
	service, _ := startPollService(t, now, trace, state, broker, &fakeEventRecorder{trace: trace})

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if got, want := session.AcquireRequests(), [][]int64{{8101, 8102}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Acquire requests = %v, want %v", got, want)
	}
	if got, want := broker.DemandCalls(), []fakeDemandCall{{
		repositoryAlias: "repo-a",
		epoch:           9,
		total:           7,
	}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demand calls = %+v, want %+v", got, want)
	}
	if broker.EnsureCalls() != 1 || session.AckCount() != 1 {
		t.Fatalf("ensure/ack calls = (%d,%d), want (1,1)", broker.EnsureCalls(), session.AckCount())
	}
	assertTraceOrder(
		t,
		trace.Snapshot(),
		"state:begin-acquisition",
		"session:acquire",
		"state:complete-acquisition",
		"broker:demand",
		"broker:ensure",
		"state:persist:queued",
		"state:begin-ack",
		"session:ack",
		"state:confirm-ack",
	)
}

func TestZeroCapacityObserverPersistsAndAcksWithoutAcquire(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 5, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8151,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{lease: PollLease{
		RepositoryAlias: "repo-a",
		Epoch:           9,
		Reserved:        0,
		PollCapacity:    0,
		ExpiresAt:       now.Add(time.Minute),
	}}
	session := &fakeSession{batch: githubscale.Batch{
		MessageID:  816,
		Statistics: githubscale.Statistics{TotalAssignedJobs: 4},
		Offers:     []githubscale.Offer{offer},
	}}
	service, _ := startPollService(
		t,
		now,
		nil,
		state,
		broker,
		&fakeEventRecorder{},
	)

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{
			RepositoryAlias: "repo-a",
			ScaleSetName:    "portable-ghar",
		},
		session,
	); err != nil {
		t.Fatalf("PollOnce(observer): %v", err)
	}
	if session.LastPollCapacity() != 0 ||
		len(session.AcquireRequests()) != 0 ||
		broker.EnsureCalls() != 0 ||
		session.AckCount() != 1 {
		t.Fatalf(
			"observer effects = poll %d acquire %v ensure %d ack %d",
			session.LastPollCapacity(),
			session.AcquireRequests(),
			broker.EnsureCalls(),
			session.AckCount(),
		)
	}
	if calls := broker.DemandCalls(); len(calls) != 1 || calls[0].total != 4 {
		t.Fatalf("observer demand calls = %+v, want total 4", calls)
	}
}

func TestResidualPollCapacityWithoutReservationCannotAcquire(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 6, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8161,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{lease: PollLease{
		RepositoryAlias: "repo-a",
		Epoch:           9,
		Reserved:        0,
		PollCapacity:    1,
		ExpiresAt:       now.Add(time.Minute),
	}}
	session := &fakeSession{batch: githubscale.Batch{
		MessageID:  817,
		Statistics: githubscale.Statistics{TotalAssignedJobs: 3},
		Offers:     []githubscale.Offer{offer},
	}}
	service, _ := startPollService(
		t,
		now,
		nil,
		state,
		broker,
		&fakeEventRecorder{},
	)

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{
			RepositoryAlias: "repo-a",
			ScaleSetName:    "portable-ghar",
		},
		session,
	); err != nil {
		t.Fatalf("PollOnce(residual): %v", err)
	}
	if session.LastPollCapacity() != 1 ||
		len(session.AcquireRequests()) != 0 ||
		broker.EnsureCalls() != 0 ||
		session.AckCount() != 1 {
		t.Fatalf(
			"residual effects = poll %d acquire %v ensure %d ack %d",
			session.LastPollCapacity(),
			session.AcquireRequests(),
			broker.EnsureCalls(),
			session.AckCount(),
		)
	}
}

func TestPollAcquireRequestCannotExceedNewLeaseReservation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 7, 0, 0, time.UTC)
	first := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8171,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	second := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8172,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	acquiredKey := AssignmentKey{
		RepositoryAlias: "repo-a",
		RunnerRequestID: first.RunnerRequestID,
	}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    2,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{
			Key:   acquiredKey,
			Offer: first,
			Phase: AdmissionQueued,
		}},
	}
	session := &fakeSession{
		batch: githubscale.Batch{
			MessageID:  818,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 2},
			Offers:     []githubscale.Offer{second, first},
		},
		acquiredIDs: []int64{first.RunnerRequestID},
	}
	service, _ := startPollService(
		t,
		now,
		nil,
		state,
		broker,
		&fakeEventRecorder{},
	)

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{
			RepositoryAlias: "repo-a",
			ScaleSetName:    "portable-ghar",
		},
		session,
	); err != nil {
		t.Fatalf("PollOnce(capped acquire): %v", err)
	}
	if got, want := session.AcquireRequests(), [][]int64{{8171}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Acquire requests = %v, want %v", got, want)
	}
	if session.LastPollCapacity() != 2 ||
		broker.EnsureCalls() != 1 ||
		session.AckCount() != 1 {
		t.Fatalf(
			"capped effects = poll %d ensure %d ack %d",
			session.LastPollCapacity(),
			broker.EnsureCalls(),
			session.AckCount(),
		)
	}
}

func TestPollCompletedAllRejectedAcquisitionStillUpdatesDemandAndAcks(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 10, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8201,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{lease: PollLease{
		RepositoryAlias: "repo-a",
		Epoch:           9,
		Reserved:        1,
		PollCapacity:    1,
		ExpiresAt:       now.Add(time.Minute),
	}}
	session := &fakeSession{
		batch: githubscale.Batch{
			MessageID:  821,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 3},
			Offers:     []githubscale.Offer{offer},
		},
		acquiredIDs: []int64{},
	}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})

	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if broker.EnsureCalls() != 0 || session.AckCount() != 1 {
		t.Fatalf("all-rejected ensure/ack = (%d,%d), want (0,1)", broker.EnsureCalls(), session.AckCount())
	}
	if calls := broker.DemandCalls(); len(calls) != 1 || calls[0].total != 3 {
		t.Fatalf("demand calls = %+v", calls)
	}
}

func TestPollAcquireFailurePersistsAmbiguousSuppressesAckAndEntersFatal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 20, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8301,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	trace := &callTrace{}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
	}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{
			MessageID:  831,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 1},
			Offers:     []githubscale.Offer{offer},
		},
		acquireErr: errors.New("injected acquire failure"),
	}
	service, terminator := startPollService(t, now, trace, state, broker, &fakeEventRecorder{trace: trace})

	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrPollFatal) {
		t.Fatalf("PollOnce = %v, want ErrPollFatal", err)
	}
	if session.AckCount() != 0 || broker.EnsureCalls() != 0 {
		t.Fatalf("ambiguous acquire ack/ensure = (%d,%d)", session.AckCount(), broker.EnsureCalls())
	}
	if terminator.Count() != 1 || service.Ready() || service.Policy().Mode != AcquisitionFatal {
		t.Fatalf("fatal state = terminator %d ready %v policy %+v", terminator.Count(), service.Ready(), service.Policy())
	}
	assertTraceOrder(
		t,
		trace.Snapshot(),
		"state:begin-acquisition",
		"session:acquire",
		"state:ambiguous-acquisition",
		"transition:fatal",
	)
}

func TestPollCompletedAcquisitionRedeliveryDoesNotAcquireTwice(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 30, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8401,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 8401}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{Key: key, Offer: offer, Phase: AdmissionQueued}},
	}
	session := &fakeSession{
		batch: githubscale.Batch{
			MessageID:  841,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 1},
			Offers:     []githubscale.Offer{offer},
		},
	}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("first PollOnce: %v", err)
	}
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("redelivered PollOnce: %v", err)
	}
	if got := session.AcquireRequests(); len(got) != 1 {
		t.Fatalf("Acquire called %d times, want exactly once", len(got))
	}
}

func TestPollConfirmedExactRedeliverySkipsCompactedLifecycleEffects(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 35, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8451,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	key := AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 8451}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
		ensureRefs: []AdmissionReference{{
			Key:   key,
			Offer: offer,
			Phase: AdmissionQueued,
		}},
	}
	session := &fakeSession{batch: githubscale.Batch{
		MessageID:  846,
		Statistics: githubscale.Statistics{TotalAssignedJobs: 2},
		Offers:     []githubscale.Offer{offer},
	}}
	events := &fakeEventRecorder{}
	service, _ := startPollService(t, now, nil, state, broker, events)
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("first PollOnce: %v", err)
	}
	events.mu.Lock()
	events.err = errors.New("compacted lifecycle graph must not be replayed")
	events.mu.Unlock()
	if err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	); err != nil {
		t.Fatalf("confirmed redelivery PollOnce: %v", err)
	}
	if events.Calls() != 1 {
		t.Fatalf("RecordBatch calls = %d, want one pre-compaction call", events.Calls())
	}
	if got := session.AcquireRequests(); len(got) != 1 {
		t.Fatalf("Acquire calls = %d, want one", len(got))
	}
	if calls := broker.DemandCalls(); len(calls) != 2 ||
		calls[1].total != 2 {
		t.Fatalf("redelivery demand calls = %+v", calls)
	}
	if state.ObserveCalls() != 1 || session.AckCount() != 2 {
		t.Fatalf(
			"redelivery proof/ack = (%d,%d), want (1,2)",
			state.ObserveCalls(),
			session.AckCount(),
		)
	}
}

func TestPollMissingStatisticsCannotAuthorizeDemandAcquireOrAck(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 40, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8501,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{lease: PollLease{
		RepositoryAlias: "repo-a",
		Epoch:           9,
		Reserved:        1,
		PollCapacity:    1,
		ExpiresAt:       now.Add(time.Minute),
	}}
	session := &fakeSession{
		batch: githubscale.Batch{
			MessageID: 851,
			Offers:    []githubscale.Offer{offer},
		},
		statisticsMissing: true,
	}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrPollCycle) {
		t.Fatalf("PollOnce = %v, want ErrPollCycle", err)
	}
	if len(session.AcquireRequests()) != 0 ||
		len(broker.DemandCalls()) != 0 ||
		session.AckCount() != 0 {
		t.Fatalf(
			"missing stats crossed effect boundary: acquire=%v demand=%v ack=%d",
			session.AcquireRequests(),
			broker.DemandCalls(),
			session.AckCount(),
		)
	}
}

func TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 22, 50, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8601,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	trace := &callTrace{}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
	}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{
			MessageID:  861,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 1},
			Offers:     []githubscale.Offer{offer},
		},
	}
	service, terminator := startPollService(t, now, trace, state, broker, &fakeEventRecorder{trace: trace})
	hostGuard := &task8RecordingGuard{name: "host", trace: trace}
	service.fleetGuards = &task8FleetGuardProvider{guard: hostGuard}
	service.permits = &task8PermitProvider{
		guard: &task8RecordingGuard{name: "poll-permit", trace: trace},
		errors: map[string]error{
			"acquire": errors.New("permit unavailable"),
		},
	}
	trace.Reset()

	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrPollCycle) || errors.Is(err, ErrPollFatal) {
		t.Fatalf("PollOnce = %v, want nonfatal ErrPollCycle", err)
	}
	if len(session.AcquireRequests()) != 0 || session.AckCount() != 0 {
		t.Fatalf("pre-call permit failure crossed effect boundary: acquire=%v ack=%d", session.AcquireRequests(), session.AckCount())
	}
	if !service.Ready() || terminator.Count() != 0 {
		t.Fatalf("pre-call permit failure changed service: ready=%v terminator=%d", service.Ready(), terminator.Count())
	}
	state.mu.Lock()
	status := state.acquisitionBatches[861].Status
	state.mu.Unlock()
	if status != AcquisitionBatchNotAttempted {
		t.Fatalf("batch status = %v, want not_attempted; trace=%v", status, trace.Snapshot())
	}
	assertTraceOrder(
		t,
		trace.Snapshot(),
		"state:begin-acquisition",
		"guard:close:host",
		"state:abort-acquisition",
	)
}

func TestPollPermitCloseFailurePreservesCompletedResultThenEntersFatal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8701,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	trace := &callTrace{}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{
		trace: trace,
		lease: PollLease{
			RepositoryAlias: "repo-a",
			Epoch:           9,
			Reserved:        1,
			PollCapacity:    1,
			ExpiresAt:       now.Add(time.Minute),
		},
	}
	session := &fakeSession{
		trace: trace,
		batch: githubscale.Batch{
			MessageID:  871,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 1},
			Offers:     []githubscale.Offer{offer},
		},
	}
	service, terminator := startPollService(t, now, trace, state, broker, &fakeEventRecorder{trace: trace})
	service.fleetGuards = &task8FleetGuardProvider{
		guard: &task8RecordingGuard{name: "host", trace: trace},
	}
	service.permits = &task8PermitProvider{
		guards: map[string]AcquisitionGuard{
			"poll": &task8RecordingGuard{name: "poll-permit", trace: trace},
			"acquire": &task8RecordingGuard{
				name:  "permit",
				trace: trace,
				err:   errors.New("permit close failed"),
			},
		},
	}
	trace.Reset()

	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrPollFatal) {
		t.Fatalf("PollOnce = %v, want ErrPollFatal", err)
	}
	state.mu.Lock()
	status := state.acquisitionBatches[871].Status
	state.mu.Unlock()
	if status != AcquisitionBatchCompleted {
		t.Fatalf("close failure rewrote durable result to %v; trace=%v", status, trace.Snapshot())
	}
	if session.AckCount() != 0 || terminator.Count() != 1 {
		t.Fatalf("close failure ack/terminator = (%d,%d)", session.AckCount(), terminator.Count())
	}
	assertTraceOrder(
		t,
		trace.Snapshot(),
		"session:acquire",
		"state:complete-acquisition",
		"guard:close:permit",
		"guard:close:host",
		"transition:fatal",
	)
}

func TestPollDuplicateAcquireResultIsAmbiguousAndCannotQueue(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 23, 10, 0, 0, time.UTC)
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8801,
		RepositoryName:  "owner/repository",
		QueueTime:       now.Add(-time.Minute),
	}}
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{lease: PollLease{
		RepositoryAlias: "repo-a",
		Epoch:           9,
		Reserved:        1,
		PollCapacity:    1,
		ExpiresAt:       now.Add(time.Minute),
	}}
	session := &fakeSession{
		batch: githubscale.Batch{
			MessageID:  881,
			Statistics: githubscale.Statistics{TotalAssignedJobs: 1},
			Offers:     []githubscale.Offer{offer},
		},
		acquiredIDs: []int64{8801, 8801},
	}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	err := service.PollOnce(
		context.Background(),
		githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"},
		session,
	)
	if !errors.Is(err, ErrPollFatal) {
		t.Fatalf("PollOnce = %v, want ErrPollFatal", err)
	}
	if broker.EnsureCalls() != 0 || session.AckCount() != 0 {
		t.Fatalf("invalid result crossed queue/ack = (%d,%d)", broker.EnsureCalls(), session.AckCount())
	}
}
