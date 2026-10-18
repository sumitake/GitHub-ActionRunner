package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func TestCanaryPollWithoutExpectedJobRejectsBeforeAcquire(t *testing.T) {
	now := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{lease: PollLease{RepositoryAlias: "repo-a", Reserved: 1, PollCapacity: 1, ExpiresAt: now.Add(time.Hour)}}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	if _, err := service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionEnabled, EligibleScaleSet: "portable-ghar"}); err != nil {
		t.Fatal(err)
	}
	upstream := &fakeSession{batch: githubscale.Batch{MessageID: 501, Offers: []githubscale.Offer{{JobRef: githubscale.JobRef{RunnerRequestID: 1001, JobID: "job", OwnerName: "owner", RepositoryName: "owner/repository", WorkflowRunID: 42, JobWorkflowRef: "owner/repository/.github/workflows/canary.yml@refs/heads/main", EventName: "workflow_dispatch", RequestLabels: []string{"portable-ghar"}, QueueTime: now}}}}}
	err := service.PollOnce(context.Background(), githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}, upstream)
	if err == nil || len(upstream.AcquireRequests()) != 0 {
		t.Fatalf("unbound canary reached acquisition: error=%v acquire=%v", err, upstream.AcquireRequests())
	}
}

func testExpectedCanaryJob() CanaryJobIdentity {
	return CanaryJobIdentity{RepositoryAlias: "repo-a", Repository: "owner/repository", ScaleSet: "portable-ghar", WorkflowRef: "owner/repository/.github/workflows/canary.yml@refs/heads/main", WorkflowRunID: 42, WorkflowRunAttempt: 1, JobID: "job", EventName: "workflow_dispatch"}
}
func testApprovedCanaryOffer(now time.Time) githubscale.Offer {
	job := testExpectedCanaryJob()
	return githubscale.Offer{JobRef: githubscale.JobRef{RunnerRequestID: 1001, JobID: "job", OwnerName: "owner", RepositoryName: job.Repository, WorkflowRunID: job.WorkflowRunID, JobWorkflowRef: job.WorkflowRef, EventName: job.EventName, RequestLabels: []string{job.ScaleSet}, QueueTime: now}}
}

func TestCanaryJobIdentityRejectsEveryUnexpectedOffer(t *testing.T) {
	expected := testExpectedCanaryJob()
	for name, mutate := range map[string]func(*githubscale.Offer){
		"run":                   func(o *githubscale.Offer) { o.WorkflowRunID++ },
		"other job in same run": func(o *githubscale.Offer) { o.JobID = "another-job" },
		"rerun job in same run": func(o *githubscale.Offer) { o.JobID = "later-attempt-job" },
		"ref": func(o *githubscale.Offer) {
			o.JobWorkflowRef = "owner/repository/.github/workflows/canary.yml@refs/heads/other"
		},
		"workflow": func(o *githubscale.Offer) {
			o.JobWorkflowRef = "owner/repository/.github/workflows/other.yml@refs/heads/main"
		},
		"event":       func(o *githubscale.Offer) { o.EventName = "pull_request" },
		"repository":  func(o *githubscale.Offer) { o.RepositoryName = "owner/other" },
		"owner":       func(o *githubscale.Offer) { o.OwnerName = "other" },
		"label":       func(o *githubscale.Offer) { o.RequestLabels = []string{"other"} },
		"extra label": func(o *githubscale.Offer) { o.RequestLabels = []string{"self-hosted", "portable-ghar"} },
	} {
		t.Run(name, func(t *testing.T) {
			offer := testApprovedCanaryOffer(time.Now())
			mutate(&offer)
			if err := expected.VerifyCanaryOffer(context.Background(), "repo-a", "portable-ghar", offer); err == nil {
				t.Fatal("unexpected offer admitted")
			}
		})
	}
	offer := testApprovedCanaryOffer(time.Now())
	for _, args := range [][2]string{{"other", "portable-ghar"}, {"repo-a", "other"}} {
		if expected.VerifyCanaryOffer(context.Background(), args[0], args[1], offer) == nil {
			t.Fatal("unexpected session admitted")
		}
	}
	if err := expected.VerifyCanaryOffer(context.Background(), "repo-a", "portable-ghar", offer); err != nil {
		t.Fatal("approved offer refused", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if expected.VerifyCanaryOffer(ctx, "repo-a", "portable-ghar", offer) == nil {
		t.Fatal("canceled authority accepted")
	}
}

func TestCanaryPollAcceptsApprovedJobAndDeclinesUnrelatedMixedOffer(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "approved", true: "mixed"}[mixed], func(t *testing.T) {
			now := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
			state := &fakeDurableState{}
			broker := &fakeAdmissionBroker{lease: PollLease{RepositoryAlias: "repo-a", Reserved: 1, PollCapacity: 1, ExpiresAt: now.Add(time.Hour)}, ensureRefs: []AdmissionReference{{Key: AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 1001}, Phase: AdmissionQueued}}}
			service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
			service.canaryJobs = newTestCanaryJobProvider()
			if _, err := service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionEnabled, EligibleScaleSet: "portable-ghar"}); err != nil {
				t.Fatal(err)
			}
			offers := []githubscale.Offer{testApprovedCanaryOffer(now)}
			if mixed {
				bad := testApprovedCanaryOffer(now)
				bad.RunnerRequestID++
				bad.WorkflowRunID++
				offers = append(offers, bad)
			}
			upstream := &fakeSession{batch: githubscale.Batch{MessageID: 501, Offers: offers}}
			err := service.PollOnce(context.Background(), githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}, upstream)
			if err != nil || len(upstream.AcquireRequests()) != 1 || upstream.AckCount() != 1 {
				t.Fatalf("approved job not acquired and unrelated job declined: %v %v", err, upstream.AcquireRequests())
			}
			if got := upstream.AcquireRequests()[0]; len(got) != 1 || got[0] != 1001 {
				t.Fatal("unrelated request acquired", got)
			}

		})
	}
}

type pendingCanaryJobs struct{ ready bool }

func (p *pendingCanaryJobs) ExpectedCanaryJob(context.Context) (CanaryJobIdentity, error) {
	if !p.ready {
		return CanaryJobIdentity{}, ErrCanaryJobPending
	}
	return testExpectedCanaryJob(), nil
}

func TestCanaryApprovalPendingWaitsBeforePollingThenAllowsBoundJob(t *testing.T) {
	f := newRuntimeServiceFixture(t, nil, nil, nil)
	provider := &pendingCanaryJobs{}
	f.service.canaryJobs = provider
	if err := f.service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionDisabled, EligibleScaleSet: "portable-ghar"}); err != nil {
		t.Fatal(err)
	}
	f.broker.lease.PollCapacity = 1
	upstream := &fakeSession{batch: githubscale.Batch{Empty: true}, lastPollCapacity: -1}
	fleet := githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}
	for range 3 {
		if err := f.service.PollOnce(context.Background(), fleet, upstream); err != nil {
			t.Fatal("pending approval stopped run", err)
		}
		if upstream.LastPollCapacity() != -1 || f.service.Policy().Mode != AcquisitionCanaryOnly {
			t.Fatal("pending approval granted polling or changed policy")
		}
	}
	provider.ready = true
	if err := f.service.PollOnce(context.Background(), fleet, upstream); err != nil || upstream.LastPollCapacity() != 1 {
		t.Fatal("bound approval did not allow normal polling", err)
	}
}

func TestCanaryPollDeclinesUnexpectedRunRefEventBeforeAcquisition(t *testing.T) {
	for name, mutate := range map[string]func(*githubscale.Offer){
		"run":                   func(o *githubscale.Offer) { o.WorkflowRunID++ },
		"other job in same run": func(o *githubscale.Offer) { o.JobID = "another-job" },
		"rerun job in same run": func(o *githubscale.Offer) { o.JobID = "later-attempt-job" },
		"ref": func(o *githubscale.Offer) {
			o.JobWorkflowRef = "owner/repository/.github/workflows/canary.yml@refs/heads/other"
		},
		"event": func(o *githubscale.Offer) { o.EventName = "pull_request" },
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
			trace := &callTrace{}
			state := &fakeDurableState{trace: trace}
			broker := &fakeAdmissionBroker{trace: trace, lease: PollLease{RepositoryAlias: "repo-a", Reserved: 1, PollCapacity: 1, ExpiresAt: now.Add(time.Hour)}}
			service, _ := startPollService(t, now, trace, state, broker, &fakeEventRecorder{})
			service.canaryJobs = newTestCanaryJobProvider()
			if _, err := service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionEnabled, EligibleScaleSet: "portable-ghar"}); err != nil {
				t.Fatal(err)
			}
			offer := testApprovedCanaryOffer(now)
			mutate(&offer)
			upstream := &fakeSession{batch: githubscale.Batch{MessageID: 501, Offers: []githubscale.Offer{offer}}}
			trace.Reset()
			if err := service.PollOnce(context.Background(), githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}, upstream); err != nil {
				t.Fatal(err)
			}
			if len(upstream.AcquireRequests()) != 0 || broker.EnsureCalls() != 0 || upstream.AckCount() != 1 {
				t.Fatal("unrelated job was claimed or notification not declined")
			}
			for _, call := range trace.Snapshot() {
				if call == "state:offer" || call == "state:begin-acquisition" {
					t.Fatal("unrelated job reached durable acquisition", call)
				}
			}
		})
	}
}

type canaryJobProviderFunc func(context.Context) (CanaryJobIdentity, error)

func (f canaryJobProviderFunc) ExpectedCanaryJob(ctx context.Context) (CanaryJobIdentity, error) {
	return f(ctx)
}

func TestCanaryApprovalRevocationAbortsBeforeUpstreamAcquire(t *testing.T) {
	now := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
	trace := &callTrace{}
	state := &fakeDurableState{trace: trace}
	broker := &fakeAdmissionBroker{trace: trace, lease: PollLease{RepositoryAlias: "repo-a", Reserved: 1, PollCapacity: 1, ExpiresAt: now.Add(time.Hour)}}
	service, _ := startPollService(t, now, trace, state, broker, &fakeEventRecorder{})
	calls := 0
	service.canaryJobs = canaryJobProviderFunc(func(context.Context) (CanaryJobIdentity, error) {
		calls++
		if calls >= 3 {
			return CanaryJobIdentity{}, ErrCanaryJobRejected
		}
		return testExpectedCanaryJob(), nil
	})
	if _, err := service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionEnabled, EligibleScaleSet: "portable-ghar"}); err != nil {
		t.Fatal(err)
	}
	upstream := &fakeSession{batch: githubscale.Batch{MessageID: 501, Offers: []githubscale.Offer{testApprovedCanaryOffer(now)}}}
	trace.Reset()
	if err := service.PollOnce(context.Background(), githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}, upstream); err == nil || len(upstream.AcquireRequests()) != 0 || calls != 3 {
		t.Fatal("revoked approval reached upstream acquisition", err, calls)
	}
	aborted := false
	for _, call := range trace.Snapshot() {
		aborted = aborted || call == "state:abort-acquisition"
	}
	if !aborted {
		t.Fatal("pre-effect acquisition intent not aborted")
	}
}

func TestCanaryJITRejectsUnexpectedRunBeforeReadingDurableAuthority(t *testing.T) {
	service := &Service{canaryJobs: testExpectedCanaryJob()}
	offer := testApprovedCanaryOffer(time.Now())
	offer.WorkflowRunID++
	request := JITAuthorizationRequest{ScaleSetName: "portable-ghar", Assignment: Assignment{Key: AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 1001}, Offer: offer}}
	if err := service.revalidateJITAuthorization(context.Background(), AcquisitionPolicy{Mode: AcquisitionCanaryOnly}, CapacitySummary{}, request); err == nil {
		t.Fatal("unexpected JIT run authorized")
	}
}

func TestCanaryJobAcceptsPinnedAdapterOwnerAndBareRepository(t *testing.T) {
	job := testExpectedCanaryJob()
	offer := testApprovedCanaryOffer(time.Now())
	// The pinned SDK adapter preserves ownerName and the bare repositoryName.
	offer.RepositoryName = "repository"
	if err := job.VerifyCanaryOffer(context.Background(), "repo-a", "portable-ghar", offer); err != nil {
		t.Fatal("pinned adapter repository form refused", err)
	}
	for _, repository := range []string{"other", "/repository", "other/repository", "owner/owner/repository"} {
		offer.RepositoryName = repository
		if job.VerifyCanaryOffer(context.Background(), "repo-a", "portable-ghar", offer) == nil {
			t.Fatal("different or ambiguous repository admitted", repository)
		}
	}
}

type testCanaryJobProvider struct {
	mu    sync.Mutex
	spent bool
}

func newTestCanaryJobProvider() *testCanaryJobProvider { return &testCanaryJobProvider{} }
func (p *testCanaryJobProvider) ExpectedCanaryJob(ctx context.Context) (CanaryJobIdentity, error) {
	return testExpectedCanaryJob().ExpectedCanaryJob(ctx)
}
func (p *testCanaryJobProvider) ConsumeCanaryAcquisition(ctx context.Context, alias, scaleSet string, offer githubscale.Offer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spent || testExpectedCanaryJob().VerifyCanaryOffer(ctx, alias, scaleSet, offer) != nil {
		return ErrCanaryJobRejected
	}
	p.spent = true
	return nil
}
func (p *pendingCanaryJobs) ConsumeCanaryAcquisition(ctx context.Context, alias, scaleSet string, offer githubscale.Offer) error {
	if !p.ready {
		return ErrCanaryJobRejected
	}
	return testExpectedCanaryJob().VerifyCanaryOffer(ctx, alias, scaleSet, offer)
}

func TestSpentCanaryApprovalAbortsBeforeAcquire(t *testing.T) {
	now := time.Date(2026, 7, 28, 23, 0, 0, 0, time.UTC)
	state := &fakeDurableState{}
	broker := &fakeAdmissionBroker{lease: PollLease{RepositoryAlias: "repo-a", Reserved: 1, PollCapacity: 1, ExpiresAt: now.Add(time.Hour)}}
	service, _ := startPollService(t, now, nil, state, broker, &fakeEventRecorder{})
	service.canaryJobs = &testCanaryJobProvider{spent: true}
	if _, err := service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionEnabled, EligibleScaleSet: "portable-ghar"}); err != nil {
		t.Fatal(err)
	}
	upstream := &fakeSession{batch: githubscale.Batch{MessageID: 501, Offers: []githubscale.Offer{testApprovedCanaryOffer(now)}}}
	if err := service.PollOnce(context.Background(), githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}, upstream); err == nil || len(upstream.AcquireRequests()) != 0 {
		t.Fatal("spent approval reached upstream", err)
	}
}
