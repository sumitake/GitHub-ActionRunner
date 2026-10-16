package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

type startingLeaseProvider struct {
	canonicalPermitProviderStub
	err error
}

func (p *startingLeaseProvider) Acquire(ctx context.Context, request AcquisitionPermitRequest) (AcquisitionPermitGuard, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.canonicalPermitProviderStub.Acquire(ctx, request)
}

func TestActivePollWaitsForTheFirstWorkerLeaseWithoutCallingGitHub(t *testing.T) {
	f := newRuntimeServiceFixture(t, nil, nil, nil)
	permits := &startingLeaseProvider{err: errors.Join(ErrAcquisitionPermitAuthority, ErrAcquisitionLeasePending)}
	f.service.permits = permits
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
			t.Fatal("normal empty post-transition cache stopped the run", err)
		}
		if upstream.LastPollCapacity() != -1 || f.service.Policy().Mode != AcquisitionCanaryOnly || f.terminator.Count() != 0 {
			t.Fatal("waiting granted a poll or changed authority")
		}
	}
	permits.err = nil // The next authenticated heartbeat supplies the lease.
	if err := f.service.PollOnce(context.Background(), fleet, upstream); err != nil {
		t.Fatal(err)
	}
	if upstream.LastPollCapacity() != 1 {
		t.Fatal("fresh authority did not permit the normal poll")
	}
}

func TestActivePollDoesNotWaitAwayAnInvalidAuthority(t *testing.T) {
	f := newRuntimeServiceFixture(t, nil, nil, nil)
	f.service.permits = &startingLeaseProvider{err: ErrAcquisitionPermitAuthority}
	if err := f.service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionDisabled, EligibleScaleSet: "portable-ghar"}); err != nil {
		t.Fatal(err)
	}
	f.broker.lease.PollCapacity = 1
	upstream := &fakeSession{batch: githubscale.Batch{Empty: true}, lastPollCapacity: -1}
	if err := f.service.PollOnce(context.Background(), githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}, upstream); !errors.Is(err, ErrAcquisitionPermitAuthority) {
		t.Fatal("invalid authority stopped failing closed", err)
	}
	if upstream.LastPollCapacity() != -1 {
		t.Fatal("invalid authority reached GitHub")
	}
}

func TestWaitingForALeaseDoesNotMaskHostGuardCleanupFailure(t *testing.T) {
	f := newRuntimeServiceFixture(t, nil, nil, nil)
	if err := f.service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.SetAcquisition(context.Background(), AcquisitionChange{Set: AcquisitionCanaryOnly, Expected: AcquisitionDisabled, EligibleScaleSet: "portable-ghar"}); err != nil {
		t.Fatal(err)
	}
	f.service.permits = &startingLeaseProvider{err: errors.Join(ErrAcquisitionPermitAuthority, ErrAcquisitionLeasePending)}
	f.service.fleetGuards = &task8FleetGuardProvider{guard: &task8RecordingGuard{err: errors.New("synthetic close failure")}}
	f.broker.lease.PollCapacity = 1
	upstream := &fakeSession{batch: githubscale.Batch{Empty: true}, lastPollCapacity: -1}
	err := f.service.PollOnce(context.Background(), githubscale.Fleet{RepositoryAlias: "repo-a", ScaleSetName: "portable-ghar"}, upstream)
	if !errors.Is(err, ErrPollFatal) || f.terminator.Count() != 1 || upstream.LastPollCapacity() != -1 {
		t.Fatal("pending lease masked uncertain guard cleanup", err)
	}
}
