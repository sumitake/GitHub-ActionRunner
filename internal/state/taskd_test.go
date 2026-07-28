package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func taskDEnvelope(repositoryAlias string, messageID int) controller.MessageEnvelope {
	base := githubscale.JobRef{
		RunnerRequestID:    7001,
		JobID:              "job-guid-7001",
		RepositoryName:     "owner/repository",
		OwnerName:          "owner",
		JobWorkflowRef:     "owner/repository/.github/workflows/test.yml@refs/heads/main",
		JobDisplayName:     "task d receipt",
		WorkflowRunID:      9001,
		EventName:          "pull_request",
		RequestLabels:      []string{"self-hosted", "portable-ghar"},
		QueueTime:          time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC),
		ScaleSetAssignTime: time.Date(2026, 7, 28, 8, 0, 1, 0, time.UTC),
		RunnerAssignTime:   time.Date(2026, 7, 28, 8, 0, 2, 0, time.UTC),
		FinishTime:         time.Date(2026, 7, 28, 8, 1, 0, 0, time.UTC),
	}
	return controller.NewMessageEnvelope(
		repositoryAlias,
		githubscale.Batch{
			MessageID: messageID,
			Statistics: githubscale.Statistics{
				TotalAvailableJobs:     1,
				TotalAcquiredJobs:      2,
				TotalAssignedJobs:      3,
				TotalRunningJobs:       4,
				TotalRegisteredRunners: 5,
				TotalBusyRunners:       6,
				TotalIdleRunners:       7,
			},
			Offers: []githubscale.Offer{{
				JobRef:        base,
				AcquireJobURL: "https://example.invalid/acquire/7001",
			}},
			Assigned: []githubscale.AssignedEvent{{JobRef: base}},
			Started: []githubscale.StartedEvent{{
				JobRef:     base,
				RunnerID:   8001,
				RunnerName: "opaque-runner-1",
			}},
			Completed: []githubscale.CompletedEvent{{
				JobRef:     base,
				Result:     "succeeded",
				RunnerID:   8001,
				RunnerName: "opaque-runner-1",
			}},
		},
	)
}

func taskDProjection(phase AdmissionPhase, slotID uint32) AdmissionProjection {
	projection := AdmissionProjection{
		Valid:  true,
		Phase:  phase,
		SlotID: slotID,
		FullCharge: ResourceProjection{
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
		LedgerCharge: ResourceProjection{
			SocketStateBytes:  4096,
			DurableStateBytes: 8192,
			Inodes:            2,
		},
		LedgerCreatedAt: time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC),
		LedgerEverUsed:  true,
	}
	if phase == AdmissionQueued {
		projection.SlotID = 0
		projection.FullCharge = ResourceProjection{}
		projection.LedgerCharge = ResourceProjection{}
		projection.LedgerCreatedAt = time.Time{}
		projection.LedgerEverUsed = false
	}
	return projection
}

func TestPollPersistAckWholeBatchReceiptIsExactAndStrict(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	at := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)

	envelope := taskDEnvelope("repo-a", 501)
	first, err := s.RecordMessageReceipt(ctx, envelope, at)
	if err != nil {
		t.Fatalf("RecordMessageReceipt(first): %v", err)
	}
	if first.Digest == ([sha256.Size]byte{}) {
		t.Fatal("RecordMessageReceipt returned a zero digest")
	}
	if first.State != AckPersisted || !first.Inserted {
		t.Fatalf("first receipt = %+v, want inserted persisted", first)
	}

	replay, err := s.RecordMessageReceipt(ctx, envelope, at.Add(time.Hour))
	if err != nil {
		t.Fatalf("RecordMessageReceipt(equal replay): %v", err)
	}
	if replay.Digest != first.Digest || replay.State != AckPersisted || replay.Inserted {
		t.Fatalf("equal replay = %+v, want same digest/non-inserted persisted", replay)
	}

	otherNamespace := taskDEnvelope("repo-b", 501)
	other, err := s.RecordMessageReceipt(ctx, otherNamespace, at.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("RecordMessageReceipt(other namespace): %v", err)
	}
	if other.Digest != first.Digest {
		t.Fatalf("repository namespace changed message-intrinsic digest: %x != %x", other.Digest, first.Digest)
	}

	mutated := envelope
	mutated.Statistics.TotalAssignedJobs++
	if _, err := s.RecordMessageReceipt(ctx, mutated, at.Add(3*time.Hour)); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("mutated same-ID receipt err = %v, want ErrIdentityConflict", err)
	}

	eventOnly := taskDEnvelope("repo-a", 502)
	eventOnly.Offers = nil
	if _, err := s.RecordMessageReceipt(ctx, eventOnly, at); err != nil {
		t.Fatalf("RecordMessageReceipt(event-only): %v", err)
	}
	if err := s.BeginMessageAck(ctx, "repo-a", 502, at.Add(time.Second)); err != nil {
		t.Fatalf("BeginMessageAck(event-only receipt): %v", err)
	}

	if err := s.BeginMessageAck(ctx, "repo-a", 999, at); !errors.Is(err, ErrReplayEvidence) {
		t.Fatalf("BeginMessageAck(without receipt) err = %v, want ErrReplayEvidence", err)
	}
	var missing int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM message_receipts WHERE repository_alias = 'repo-a' AND message_id = 999`,
	).Scan(&missing); err != nil {
		t.Fatalf("count missing receipt: %v", err)
	}
	if missing != 0 {
		t.Fatalf("strict BeginMessageAck inserted %d missing receipts, want 0", missing)
	}
}

func TestAuthenticatedCurrentPollCanJournalMissingQueueTime(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	observedAt := time.Date(2026, 7, 28, 9, 15, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 7051, 8051, observedAt)
	offer.QueueTime = time.Time{}

	record, err := s.RecordOffer(ctx, offer, OfferEvidence{
		Kind:       EvidenceCurrentPoll,
		MessageID:  551,
		QueueTime:  time.Time{},
		ObservedAt: observedAt,
	})
	if err != nil {
		t.Fatalf("RecordOffer(authenticated poll with missing QueueTime): %v", err)
	}
	if record.Disposition != OfferInserted || record.State != controller.StateReceived {
		t.Fatalf("RecordOffer = %+v, want inserted RECEIVED", record)
	}
}

func TestPollPersistAckWholeBatchDigestBindsOrderAndEveryEventField(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 7, 28, 9, 30, 0, 0, time.UTC)

	baseStore := newHistoryStore(t)
	base := taskDEnvelope("repo-a", 601)
	want, err := baseStore.RecordMessageReceipt(ctx, base, at)
	if err != nil {
		t.Fatalf("RecordMessageReceipt(base): %v", err)
	}

	cases := map[string]func(*controller.MessageEnvelope){
		"message id": func(v *controller.MessageEnvelope) { v.MessageID++ },
		"offer URL": func(v *controller.MessageEnvelope) {
			v.Offers[0].AcquireJobURL += "/changed"
		},
		"assigned field": func(v *controller.MessageEnvelope) {
			v.Assigned[0].Job.JobDisplayName += " changed"
		},
		"started runner": func(v *controller.MessageEnvelope) { v.Started[0].RunnerID++ },
		"completed result": func(v *controller.MessageEnvelope) {
			v.Completed[0].Result = "failed"
		},
		"slice order": func(v *controller.MessageEnvelope) {
			v.Offers = append(v.Offers, v.Offers[0])
			v.Offers[1].Job.RunnerRequestID++
			v.Offers[0], v.Offers[1] = v.Offers[1], v.Offers[0]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := newHistoryStore(t)
			candidate := taskDEnvelope("repo-a", 601)
			mutate(&candidate)
			got, err := s.RecordMessageReceipt(ctx, candidate, at)
			if err != nil {
				t.Fatalf("RecordMessageReceipt(%s): %v", name, err)
			}
			if got.Digest == want.Digest {
				t.Fatalf("%s mutation did not change V2 digest %x", name, got.Digest)
			}
		})
	}
}

func TestPollPersistAckEffectLookupIsExactAndCompletionCannotRewrite(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 7101, 8101, now)
	receipt, err := s.RecordOffer(ctx, offer, currentPollEvidence(701, now, now))
	if err != nil {
		t.Fatalf("RecordOffer: %v", err)
	}

	const (
		idempotencyKey = "hosted-route-v1:opaque-digest"
		kind           = "hosted-route"
	)
	absent, err := s.LookupEffect(ctx, receipt.Key, idempotencyKey, kind)
	if err != nil {
		t.Fatalf("LookupEffect(absent): %v", err)
	}
	if absent.State != EffectAbsent {
		t.Fatalf("absent effect = %+v, want EffectAbsent", absent)
	}

	began, err := s.BeginEffect(ctx, receipt.Key, idempotencyKey, kind)
	if err != nil || !began {
		t.Fatalf("BeginEffect(first) = (%v, %v), want (true, nil)", began, err)
	}
	pending, err := s.LookupEffect(ctx, receipt.Key, idempotencyKey, kind)
	if err != nil {
		t.Fatalf("LookupEffect(pending): %v", err)
	}
	if pending.State != EffectPending {
		t.Fatalf("pending effect = %+v, want EffectPending", pending)
	}

	proof := "opaque-hosted-proof"
	if err := s.CompleteEffect(ctx, idempotencyKey, EffectResult{ResultIdentity: proof}); err != nil {
		t.Fatalf("CompleteEffect(success): %v", err)
	}
	complete, err := s.LookupEffect(ctx, receipt.Key, idempotencyKey, kind)
	if err != nil {
		t.Fatalf("LookupEffect(complete): %v", err)
	}
	if complete.State != EffectCompleted || complete.ResultIdentity != proof || complete.ReasonCode != "" {
		t.Fatalf("completed effect = %+v, want exact successful proof", complete)
	}

	if err := s.CompleteEffect(ctx, idempotencyKey, EffectResult{ResultIdentity: "different-proof"}); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("CompleteEffect(conflicting replay) err = %v, want ErrIdentityConflict", err)
	}
	unchanged, err := s.LookupEffect(ctx, receipt.Key, idempotencyKey, kind)
	if err != nil {
		t.Fatalf("LookupEffect(after conflict): %v", err)
	}
	if unchanged != complete {
		t.Fatalf("conflicting completion rewrote effect: %+v -> %+v", complete, unchanged)
	}

	if began, err := s.BeginEffect(ctx, receipt.Key, idempotencyKey, "different-kind"); !errors.Is(err, ErrIdentityConflict) || began {
		t.Fatalf("BeginEffect(kind conflict) = (%v, %v), want (false, ErrIdentityConflict)", began, err)
	}
}

func TestPollPersistAckReserveActiveIsAtomicAndExact(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	now := time.Date(2026, 7, 28, 11, 0, 0, 0, time.UTC)

	offerA := historyOffer("repo-a", 7201, 8201, now)
	a, err := s.RecordOffer(ctx, offerA, currentPollEvidence(721, now, now))
	if err != nil {
		t.Fatalf("RecordOffer(A): %v", err)
	}
	queuedA := taskDProjection(AdmissionQueued, 0)
	if err := s.PersistAdmissionProjection(ctx, a.Key, queuedA); err != nil {
		t.Fatalf("PersistAdmissionProjection(A queued): %v", err)
	}
	activeA := taskDProjection(AdmissionActive, 7)
	if err := s.ReserveActive(ctx, a.Key, activeA, "opaque-slot-7"); err != nil {
		t.Fatalf("ReserveActive(A): %v", err)
	}
	if err := s.ReserveActive(ctx, a.Key, activeA, "opaque-slot-7"); err != nil {
		t.Fatalf("ReserveActive(A replay): %v", err)
	}
	recovered, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable: %v", err)
	}
	gotA, ok := findRecoverable(t, recovered, a.Key)
	if !ok {
		t.Fatal("reserved assignment A missing from recovery")
	}
	if gotA.State != controller.StateCapacityReserved || gotA.Admission != activeA ||
		gotA.Slot.CapacitySlotID != 7 || gotA.Slot.OpaqueName != "opaque-slot-7" {
		t.Fatalf("reserved assignment A = %+v, want exact active projection and stable slot", gotA)
	}
	if err := s.ReserveActive(ctx, a.Key, taskDProjection(AdmissionActive, 8), "opaque-slot-8"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ReserveActive(A conflict) err = %v, want ErrIdentityConflict", err)
	}

	offerB := historyOffer("repo-a", 7202, 8202, now)
	b, err := s.RecordOffer(ctx, offerB, currentPollEvidence(722, now, now))
	if err != nil {
		t.Fatalf("RecordOffer(B): %v", err)
	}
	queuedB := taskDProjection(AdmissionQueued, 0)
	if err := s.PersistAdmissionProjection(ctx, b.Key, queuedB); err != nil {
		t.Fatalf("PersistAdmissionProjection(B queued): %v", err)
	}
	if err := s.ReserveActive(ctx, b.Key, taskDProjection(AdmissionActive, 7), "opaque-slot-other"); err == nil {
		t.Fatal("ReserveActive(B duplicate slot) succeeded")
	}
	recovered, err = s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable(after B failure): %v", err)
	}
	gotB, ok := findRecoverable(t, recovered, b.Key)
	if !ok {
		t.Fatal("assignment B missing after rejected reservation")
	}
	if gotB.State != controller.StateReceived || gotB.Admission != queuedB ||
		gotB.Slot != (controller.RunnerSlot{}) {
		t.Fatalf("rejected B reservation partially mutated state: %+v", gotB)
	}
}

func TestReserveActivePreservesPriorReservedSlotAndCharges(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	now := time.Date(2026, 7, 28, 11, 30, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 7251, 8251, now)
	receipt, err := s.RecordOffer(ctx, offer, currentPollEvidence(725, now, now))
	if err != nil {
		t.Fatalf("RecordOffer: %v", err)
	}
	reserved := AdmissionProjection{
		Valid:           true,
		Phase:           AdmissionReserved,
		SlotID:          9,
		FullCharge:      ResourceProjection{MemoryBytes: 10, DurableStateBytes: 2},
		LedgerCharge:    ResourceProjection{DurableStateBytes: 2},
		LedgerCreatedAt: now,
		LedgerEverUsed:  false,
	}
	if err := s.PersistAdmissionProjection(ctx, receipt.Key, reserved); err != nil {
		t.Fatalf("PersistAdmissionProjection(reserved): %v", err)
	}
	active := reserved
	active.Phase = AdmissionActive
	active.LedgerEverUsed = true

	mismatchedSlot := active
	mismatchedSlot.SlotID++
	if err := s.ReserveActive(ctx, receipt.Key, mismatchedSlot, "opaque-slot-10"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ReserveActive(mismatched reserved slot) err = %v, want ErrIdentityConflict", err)
	}
	mismatchedCharge := active
	mismatchedCharge.FullCharge.MemoryBytes++
	if err := s.ReserveActive(ctx, receipt.Key, mismatchedCharge, "opaque-slot-9"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("ReserveActive(mismatched reserved charge) err = %v, want ErrIdentityConflict", err)
	}
	if err := s.ReserveActive(ctx, receipt.Key, active, "opaque-slot-9"); err != nil {
		t.Fatalf("ReserveActive(exact reserved projection): %v", err)
	}
}

func TestDurableReadbackRejectsIntegerEncodingsThatCouldWrapOrCoerce(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 11, 45, 0, 0, time.UTC)
	cases := []struct {
		name       string
		corruptSQL string
		corruptArg int64
	}{
		{
			name:       "admission slot exceeds uint32",
			corruptSQL: `UPDATE assignments SET admission_slot_id = ?`,
			corruptArg: (int64(1) << 32) + 1,
		},
		{
			name:       "ledger boolean is not canonical",
			corruptSQL: `UPDATE assignments SET ledger_ever_used = ?`,
			corruptArg: 2,
		},
		{
			name:       "attempt exceeds uint32",
			corruptSQL: `UPDATE assignments SET attempt = ?`,
			corruptArg: int64(1) << 32,
		},
		{
			name:       "released boolean is not canonical",
			corruptSQL: `UPDATE assignments SET released = ?`,
			corruptArg: 2,
		},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newHistoryStore(t)
			offer := historyOffer("repo-a", 7270+int64(index), 8270+int64(index), now)
			receipt, err := s.RecordOffer(
				ctx,
				offer,
				currentPollEvidence(727+index, now, now),
			)
			if err != nil {
				t.Fatalf("RecordOffer: %v", err)
			}
			reserved := taskDProjection(AdmissionReserved, 9)
			reserved.LedgerEverUsed = false
			if err := s.PersistAdmissionProjection(ctx, receipt.Key, reserved); err != nil {
				t.Fatalf("PersistAdmissionProjection: %v", err)
			}
			if _, err := s.DB().ExecContext(ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
				t.Fatalf("enable corruption fixture: %v", err)
			}
			if _, err := s.DB().ExecContext(ctx, tc.corruptSQL, tc.corruptArg); err != nil {
				t.Fatalf("corrupt durable integer: %v", err)
			}
			if _, err := s.ListRecoverable(ctx); err == nil {
				t.Fatal("ListRecoverable accepted a noncanonical durable integer")
			}

			if tc.name == "admission slot exceeds uint32" {
				active := reserved
				active.Phase = AdmissionActive
				active.SlotID = 1
				active.LedgerEverUsed = true
				if err := s.ReserveActive(ctx, receipt.Key, active, "opaque-slot-1"); err == nil {
					t.Fatal("ReserveActive accepted a wrapped durable admission slot")
				}
			}
		})
	}
}

func TestPollPersistAckClearProjectionAndBindTerminalAreFailClosed(t *testing.T) {
	ctx := context.Background()
	s := newHistoryStore(t)
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	offer := historyOffer("repo-a", 7301, 8301, now)
	recorded, err := s.RecordOffer(ctx, offer, currentPollEvidence(731, now, now))
	if err != nil {
		t.Fatalf("RecordOffer: %v", err)
	}
	if err := s.PersistAdmissionProjection(ctx, recorded.Key, taskDProjection(AdmissionQueued, 0)); err != nil {
		t.Fatalf("PersistAdmissionProjection: %v", err)
	}
	if err := s.ClearAdmissionProjection(ctx, recorded.Key); err != nil {
		t.Fatalf("ClearAdmissionProjection: %v", err)
	}
	recovered, err := s.ListRecoverable(ctx)
	if err != nil {
		t.Fatalf("ListRecoverable: %v", err)
	}
	got, ok := findRecoverable(t, recovered, recorded.Key)
	if !ok || got.Admission.Valid {
		t.Fatalf("cleared projection = %+v, want Valid=false", got.Admission)
	}

	envelope := taskDEnvelope("repo-a", 732)
	if _, err := s.RecordMessageReceipt(ctx, envelope, now); err != nil {
		t.Fatalf("RecordMessageReceipt: %v", err)
	}
	if err := s.BindTerminalMessage(ctx, recorded.Key, 732); err == nil {
		t.Fatal("BindTerminalMessage before DESTROYED succeeded")
	}
	if err := s.Advance(ctx, recorded.Key, controller.StateDestroyed); err != nil {
		t.Fatalf("Advance(DESTROYED): %v", err)
	}
	if err := s.BindTerminalMessage(ctx, recorded.Key, 999); !errors.Is(err, ErrReplayEvidence) {
		t.Fatalf("BindTerminalMessage(missing receipt) err = %v, want ErrReplayEvidence", err)
	}
	if err := s.BindTerminalMessage(ctx, recorded.Key, 732); err != nil {
		t.Fatalf("BindTerminalMessage: %v", err)
	}
	if err := s.BindTerminalMessage(ctx, recorded.Key, 732); err != nil {
		t.Fatalf("BindTerminalMessage(replay): %v", err)
	}
	if err := s.BindTerminalMessage(ctx, recorded.Key, 733); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("BindTerminalMessage(conflict) err = %v, want ErrIdentityConflict", err)
	}
}
