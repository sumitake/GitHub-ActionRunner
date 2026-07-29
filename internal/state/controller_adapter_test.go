package state

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func TestControllerAdapterClosesUnexpectedStoreErrors(t *testing.T) {
	const sensitiveDetail = "/private/operator/path/runtime.sqlite"
	err := mapControllerStateError(errors.New("sqlite open failed: " + sensitiveDetail))
	if !errors.Is(err, controller.ErrHistoryUnavailable) {
		t.Fatalf("mapControllerStateError err = %v, want ErrHistoryUnavailable", err)
	}
	if strings.Contains(err.Error(), sensitiveDetail) ||
		strings.Contains(err.Error(), "sqlite open failed") {
		t.Fatalf("unexpected store error crossed the controller boundary: %v", err)
	}
}

func controllerAdmission(phase controller.AdmissionPhase, slotID uint32) controller.AdmissionReference {
	ref := controller.AdmissionReference{
		Key:    controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 8101},
		Phase:  phase,
		SlotID: slotID,
		FullCharge: controller.ResourceProjection{
			MilliCPU:          1000,
			MemoryBytes:       2 << 30,
			PIDs:              64,
			FileDescriptors:   256,
			TmpfsBytes:        3 << 30,
			ScratchBytes:      1 << 30,
			SocketStateBytes:  4096,
			DurableStateBytes: 8192,
			Inodes:            1024,
		},
		LedgerCharge: controller.ResourceProjection{
			SocketStateBytes:  4096,
			DurableStateBytes: 8192,
			Inodes:            2,
		},
		LedgerCreatedAt: time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC),
		LedgerEverUsed:  true,
	}
	if phase == controller.AdmissionQueued {
		ref.SlotID = 0
		ref.FullCharge = controller.ResourceProjection{}
		ref.LedgerCharge = controller.ResourceProjection{}
		ref.LedgerCreatedAt = time.Time{}
		ref.LedgerEverUsed = false
	}
	return ref
}

func TestControllerStateAdapterConvertsWithoutLosingMessageOrOfferFields(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	adapter, err := NewControllerAdapter(s, testHistoryLimits())
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}
	var _ controller.DurableState = adapter

	at := time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC)
	envelope := taskDEnvelope("repo-a", 801)
	message, err := adapter.RecordMessageReceipt(ctx, envelope, at)
	if err != nil {
		t.Fatalf("RecordMessageReceipt: %v", err)
	}
	native, err := s.RecordMessageReceipt(ctx, envelope, at.Add(time.Minute))
	if err != nil {
		t.Fatalf("native RecordMessageReceipt replay: %v", err)
	}
	if message.Digest != controller.MessageDigest(native.Digest) ||
		message.State != controller.MessageAckPersisted || !message.Inserted {
		t.Fatalf("controller message = %+v, native = %+v", message, native)
	}

	upstream := githubscale.Offer{
		JobRef: githubscale.JobRef{
			RunnerRequestID:    8101,
			JobID:              "job-guid-8101",
			RepositoryName:     "owner/repository",
			OwnerName:          "owner",
			JobWorkflowRef:     "owner/repository/.github/workflows/test.yml@refs/heads/main",
			JobDisplayName:     "adapter offer",
			WorkflowRunID:      9101,
			EventName:          "push",
			RequestLabels:      []string{"self-hosted", "portable-ghar"},
			QueueTime:          at,
			ScaleSetAssignTime: at.Add(time.Second),
			RunnerAssignTime:   at.Add(2 * time.Second),
			FinishTime:         at.Add(3 * time.Second),
		},
		AcquireJobURL: "https://example.invalid/acquire/8101",
	}
	recorded, err := adapter.RecordOffer(ctx, "repo-a", upstream, controller.OfferEvidence{
		Kind:       controller.OfferEvidenceCurrentPoll,
		MessageID:  801,
		QueueTime:  at,
		ObservedAt: at.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("RecordOffer: %v", err)
	}
	if recorded.Key != (controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 8101}) ||
		recorded.Disposition != controller.OfferInserted ||
		recorded.State != controller.StateReceived {
		t.Fatalf("RecordOffer = %+v", recorded)
	}
	begun, err := adapter.BeginAcquisition(
		ctx,
		"repo-a",
		801,
		[]controller.AssignmentKey{recorded.Key},
		at.Add(2*time.Second),
	)
	if err != nil {
		t.Fatalf("BeginAcquisition: %v", err)
	}
	if begun.Status != controller.AcquisitionBatchBegun ||
		!begun.Inserted ||
		!begun.CallAuthorized ||
		begun.RequestedCount != 1 {
		t.Fatalf("BeginAcquisition = %+v", begun)
	}
	completedBatch, err := adapter.CompleteAcquisition(
		ctx,
		"repo-a",
		801,
		[]controller.AssignmentKey{recorded.Key},
		at.Add(3*time.Second),
	)
	if err != nil {
		t.Fatalf("CompleteAcquisition: %v", err)
	}
	if completedBatch.Status != controller.AcquisitionBatchCompleted ||
		completedBatch.AcquiredCount != 1 {
		t.Fatalf("CompleteAcquisition = %+v", completedBatch)
	}
	acquisition, err := adapter.AcquisitionAssignment(ctx, recorded.Key)
	if err != nil {
		t.Fatalf("AcquisitionAssignment: %v", err)
	}
	if acquisition.Outcome != controller.AssignmentAcquired ||
		acquisition.RevokedEpoch != 0 {
		t.Fatalf("AcquisitionAssignment = %+v", acquisition)
	}

	queued := controllerAdmission(controller.AdmissionQueued, 0)
	if err := adapter.PersistAdmission(ctx, recorded.Key, queued); err != nil {
		t.Fatalf("PersistAdmission(queued): %v", err)
	}
	active := controllerAdmission(controller.AdmissionActive, 9)
	active.Key = recorded.Key
	if err := adapter.ReserveActive(ctx, recorded.Key, active, "opaque-slot-9"); err != nil {
		t.Fatalf("ReserveActive: %v", err)
	}

	recovered, err := adapter.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable: %v", err)
	}
	if len(recovered) != 1 {
		t.Fatalf("ListRecoverable length = %d, want 1", len(recovered))
	}
	got := recovered[0]
	if got.Key != recorded.Key || got.State != controller.StateCapacityReserved ||
		!reflect.DeepEqual(got.Admission, active) ||
		got.Offer.RunnerRequestID != upstream.RunnerRequestID ||
		got.Offer.RepositoryName != upstream.RepositoryName ||
		got.Offer.AcquireJobURL != upstream.AcquireJobURL ||
		len(got.Offer.RequestLabels) != len(upstream.RequestLabels) {
		t.Fatalf("recovered controller assignment lost conversion data: %+v", got)
	}
}

func TestControllerStateAdapterMapsClosedErrorsAndHostedEffects(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	adapter, err := NewControllerAdapter(s, testHistoryLimits())
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}
	now := time.Date(2026, 7, 28, 14, 0, 0, 0, time.UTC)

	if err := adapter.BeginAck(ctx, "repo-a", 901, now); !errors.Is(err, controller.ErrReplayUnavailable) {
		t.Fatalf("BeginAck(missing receipt) err = %v, want controller.ErrReplayUnavailable", err)
	}
	envelope := taskDEnvelope("repo-a", 903)
	recordedMessage, err := adapter.RecordMessageReceipt(ctx, envelope, now)
	if err != nil {
		t.Fatalf("RecordMessageReceipt: %v", err)
	}
	if err := adapter.BeginAck(ctx, "repo-a", 903, now.Add(time.Second)); err != nil {
		t.Fatalf("BeginAck(recorded receipt): %v", err)
	}
	uncertain, err := adapter.ListUncertainAcks(ctx)
	if err != nil {
		t.Fatalf("ListUncertainAcks: %v", err)
	}
	if len(uncertain) != 1 ||
		uncertain[0].RepositoryAlias != "repo-a" ||
		uncertain[0].MessageID != 903 ||
		uncertain[0].Digest != recordedMessage.Digest ||
		uncertain[0].StartedAt != now.Add(time.Second) {
		t.Fatalf("ListUncertainAcks = %+v", uncertain)
	}
	if err := adapter.PersistAdmission(
		ctx,
		controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 1},
		controller.AdmissionReference{Phase: controller.AdmissionPhase(255)},
	); !errors.Is(err, controller.ErrAdmissionConflict) {
		t.Fatalf("PersistAdmission(invalid enum) err = %v, want controller.ErrAdmissionConflict", err)
	}

	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID: 8201,
		JobID:           "job-guid-8201",
		RepositoryName:  "owner/repository",
		OwnerName:       "owner",
		QueueTime:       now,
	}}
	recorded, err := adapter.RecordOffer(ctx, "repo-a", offer, controller.OfferEvidence{
		Kind:       controller.OfferEvidenceCurrentPoll,
		MessageID:  902,
		QueueTime:  now,
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("RecordOffer: %v", err)
	}
	const key = "hosted-route-v1:stable-assignment-digest"
	absent, err := adapter.LookupHostedEffect(ctx, recorded.Key, key)
	if err != nil || absent.State != controller.HostedEffectAbsent {
		t.Fatalf("LookupHostedEffect(absent) = (%+v, %v)", absent, err)
	}
	began, err := adapter.BeginHostedEffect(ctx, recorded.Key, key)
	if err != nil || !began {
		t.Fatalf("BeginHostedEffect = (%v, %v)", began, err)
	}
	if err := adapter.CompleteHostedEffect(ctx, key, "opaque-hosted-proof"); err != nil {
		t.Fatalf("CompleteHostedEffect: %v", err)
	}
	completed, err := adapter.LookupHostedEffect(ctx, recorded.Key, key)
	if err != nil {
		t.Fatalf("LookupHostedEffect(completed): %v", err)
	}
	if completed.State != controller.HostedEffectCompleted ||
		completed.ResultIdentity != "opaque-hosted-proof" {
		t.Fatalf("completed hosted effect = %+v", completed)
	}
	if err := adapter.CompleteHostedEffect(ctx, key, "changed-proof"); !errors.Is(err, controller.ErrDurableIdentityConflict) {
		t.Fatalf("CompleteHostedEffect(conflict) err = %v, want controller.ErrDurableIdentityConflict", err)
	}

	const failedKey = "hosted-route-v1:failed-assignment-digest"
	if began, err := adapter.BeginHostedEffect(ctx, recorded.Key, failedKey); err != nil || !began {
		t.Fatalf("BeginHostedEffect(failed) = (%v, %v)", began, err)
	}
	if err := adapter.FailHostedEffect(ctx, failedKey); err != nil {
		t.Fatalf("FailHostedEffect: %v", err)
	}
	failed, err := adapter.LookupHostedEffect(ctx, recorded.Key, failedKey)
	if err != nil {
		t.Fatalf("LookupHostedEffect(failed): %v", err)
	}
	if failed.State != controller.HostedEffectFailed ||
		failed.ResultIdentity != "" ||
		failed.Failure != controller.HostedFailureRouteRejected {
		t.Fatalf("failed hosted effect = %+v", failed)
	}
}
