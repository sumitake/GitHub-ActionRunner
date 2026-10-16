package state

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/canary"
)

func canarySeed() canary.Record {
	return canary.Record{Version: 1, ReportDigest: strings.Repeat("a", 64), BindingDigest: strings.Repeat("b", 64), FleetGeneration: 7}
}

func TestCanaryEvidenceIsBoundedDurableAndPreservesSameRunOnRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	store, err := OpenWithHistoryLimits(path, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	before, err := store.HistoryUsage(ctx, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	seed := canarySeed()
	if err := store.InitCanaryEvidence(ctx, seed); err != nil {
		t.Fatal(err)
	}
	got, err := store.CanaryEvidence(ctx)
	if err != nil || !reflect.DeepEqual(got, seed) {
		t.Fatalf("initial record: %+v %v", got, err)
	}
	usage, err := store.HistoryUsage(ctx, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	if usage.CanaryEvidenceRows != 1 || usage.CanaryEvidenceLogicalBytes != canary.MaxRecordBytes || usage.LiveRows != before.LiveRows {
		t.Fatal("evidence was not charged independently at its maximum bounded size")
	}
	// Seeding/restarting never clears observations or changes acquisition mode.
	got.Invalid = true
	b, _ := json.Marshal(got)
	if _, err := store.DB().ExecContext(ctx, `UPDATE canary_evidence SET document = ? WHERE id = 1`, string(b)); err != nil {
		t.Fatal(err)
	}
	if err := store.InitCanaryEvidence(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenWithHistoryLimits(path, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := store.CanaryEvidence(ctx)
	if err != nil || !reopened.Invalid {
		t.Fatal("restart reset evidence")
	}
	other := seed
	other.ReportDigest = strings.Repeat("c", 64)
	if err := store.InitCanaryEvidence(ctx, other); err != nil {
		t.Fatal("fresh report evidence must not become acquisition authority", err)
	}
	fresh, err := store.CanaryEvidence(ctx)
	if err != nil || !reflect.DeepEqual(fresh, other) {
		t.Fatal("new report retained old proof")
	}

	var mode string
	if err := store.DB().QueryRowContext(ctx, `SELECT mode FROM acquisition_state WHERE id = 1`).Scan(&mode); err != nil || mode != "disabled" {
		t.Fatal("evidence changed acquisition authority")
	}
	for _, document := range []string{"{}", strings.Repeat("x", canary.MaxRecordBytes+1)} {
		if _, err := store.DB().ExecContext(ctx, `UPDATE canary_evidence SET document = ? WHERE id = 1`, document); err != nil {
			continue
		}
		if _, err := store.CanaryEvidence(ctx); err == nil {
			t.Fatal("malformed evidence accepted")
		}
	}
}

func TestCanaryEvidenceRejectsInvalidSeedAndMissingReadback(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	if _, err := store.CanaryEvidence(ctx); err == nil {
		t.Fatal("absent evidence accepted")
	}
	for name, change := range map[string]func(*canary.Record){
		"empty":                 func(r *canary.Record) { *r = canary.Record{} },
		"arbitrary observation": func(r *canary.Record) { r.JITCount = 1 },
		"invalidated":           func(r *canary.Record) { r.Invalid = true },
		"generation":            func(r *canary.Record) { r.FleetGeneration = 0 },
		"binding":               func(r *canary.Record) { r.BindingDigest = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			seed := canarySeed()
			change(&seed)
			if store.InitCanaryEvidence(ctx, seed) == nil {
				t.Fatal("invalid evidence seed accepted")
			}
		})
	}
}

func TestCanaryEvidenceReservationRespectsHistoryBudget(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	limits := testHistoryLimits()
	limits.MaxHistoryLogicalBytes = canary.MaxRecordBytes - 1
	limits.InflightReserveLogicalBytes = 4096
	store.historyLimits = &limits
	if store.InitCanaryEvidence(ctx, canarySeed()) == nil {
		t.Fatal("evidence exceeded history byte budget")
	}
	if _, err := store.CanaryEvidence(ctx); err == nil {
		t.Fatal("failed reservation wrote evidence")
	}
	store.historyLimits = nil
	if store.InitCanaryEvidence(ctx, canarySeed()) == nil {
		t.Fatal("unbounded store accepted evidence reservation")
	}
}

func TestCanaryEvidenceMigratesVersionThreeWithoutChangingAssignments(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	store, err := OpenWithHistoryLimits(path, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	key := seedAssignment(t, ctx, store, "repo-a", 42)
	before, err := store.ListRecoverable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `DROP TABLE canary_evidence; PRAGMA user_version=3`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenWithHistoryLimits(path, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	after, err := store.ListRecoverable(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || after[0].Key != key {
		t.Fatal("migration changed assignments")
	}
	if err := store.InitCanaryEvidence(ctx, canarySeed()); err != nil {
		t.Fatal(err)
	}
}

func seedCanaryRelease(t *testing.T, s *SQLiteStore, id int64) controller.AssignmentKey {
	t.Helper()
	ctx := context.Background()
	at := time.Now().Add(-time.Minute)
	keys := seedAcquisitionOffers(t, s, "repo-a", int(id), at, id)
	if _, err := s.BeginAcquisition(ctx, "repo-a", int(id), keys, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteAcquisition(ctx, "repo-a", int(id), keys, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Reserve(ctx, keys[0], "slot-example", nextCapacitySlotID(t)); err != nil {
		t.Fatal(err)
	}
	advanceTo(t, ctx, s, keys[0], controller.StateReleaseArmed)
	return keys[0]
}

func canaryPermit() controller.AcquisitionPermitBinding {
	return controller.AcquisitionPermitBinding{AuthorityRevision: 1, AuthorityKey: "synthetic-authority", FenceGeneration: 7, ServerEpoch: 1, SessionID: "synthetic-session", LeaseGeneration: 1, OperationID: "synthetic-operation", RepositoryAlias: "repo-a", ScaleSetName: "example-canary", OperationKind: "jit", PolicyDigest: strings.Repeat("c", 64), PolicyEpoch: 1, PolicyMode: controller.AcquisitionCanaryOnly, MaxCapacity: 1, RepositoryPolicyRevision: 1, OriginalLocalDeadline: time.Now().Add(time.Minute)}
}

func TestCanaryEvidenceCapturesActualAcquisitionAndSurvivesFinalCompaction(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seed := canarySeed()
	if err := s.InitCanaryEvidence(ctx, seed); err != nil {
		t.Fatal(err)
	}
	key := seedCanaryRelease(t, s, 420)
	compatibility := githubscale.ScaleSetCompatibilityReport{DisableUpdate: true, SingleNameLabel: true}
	if err := s.BeginCanaryJIT(ctx, seed.ReportDigest, key, compatibility); err != nil {
		t.Fatal(err)
	}
	permit := canaryPermit()
	if err := s.BindCanaryJITPermit(ctx, seed.ReportDigest, key, permit); err != nil {
		t.Fatal(err)
	}
	binding, err := controller.AcquisitionPermitBindingDigest(permit)
	if err != nil {
		t.Fatal(err)
	}
	if began, err := s.BeginListenerReleaseEffect(ctx, key, binding); err != nil || !began {
		t.Fatalf("listener effect: %v", err)
	}
	if err := s.CompleteEffect(ctx, hex.EncodeToString(binding[:]), EffectResult{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(ctx, key, controller.StateListenerReleased); err != nil {
		t.Fatal(err)
	}
	current, _ := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	if err := s.ApplyRunnerObservation(ctx, key, RunnerObservation{UpstreamRunnerID: 100, BoundRequestID: key.RunnerRequestID, RunnerContainerID: current.Slot.RunnerContainerID, Finished: false, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	workflow := canary.Workflow{Version: 1, ReportDigest: seed.ReportDigest, WorkflowRunID: 11420, Revision: strings.Repeat("d", 40), CheckoutHTTPS: true, SandboxVerified: true, InheritedJITAbsent: true, ListenerProcReadable: true, DecodedCredentialsReadable: true, CredentialProbeCompleted: true, Tools: canary.RequiredTools()}
	// The workflow frame is durably captured while the job is still running.

	if recorded, err := s.CanaryWorkflowRecorded(ctx, seed.ReportDigest, key); err != nil || recorded {
		t.Fatal("uncaptured frame reported as recorded")
	}
	if err := s.RecordCanaryWorkflow(ctx, seed.ReportDigest, key, workflow); err != nil {
		t.Fatal(err)
	}
	if recorded, err := s.CanaryWorkflowRecorded(ctx, seed.ReportDigest, key); err != nil || !recorded {
		t.Fatal("durable frame not reported")
	}
	if err := s.ApplyRunnerObservation(ctx, key, RunnerObservation{UpstreamRunnerID: 100, BoundRequestID: key.RunnerRequestID, RunnerContainerID: current.Slot.RunnerContainerID, Finished: true, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteCanaryJob(ctx, seed.ReportDigest, key, "success"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkCanaryCleanup(ctx, seed.ReportDigest, key); err != nil {
		t.Fatal(err)
	}
	record, err := s.CanaryEvidence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if record.Ready(seed.ReportDigest, seed.BindingDigest, seed.FleetGeneration) == nil {
		t.Fatal("unreclaimed capacity accepted")
	}
	if err := s.Advance(ctx, key, controller.StateDestroyed); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearTerminalRuntime(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearAdmissionProjection(ctx, key); err != nil {
		t.Fatal(err)
	}
	terminalMessage(t, s, key, 420)
	if err := s.BeginMessageAck(ctx, "repo-a", 420, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmMessageAck(ctx, "repo-a", 420, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.CompactTerminal(ctx, key, testHistoryLimits(), time.Now()); err != nil {
		t.Fatal(err)
	}
	record, err = s.CanaryEvidence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Ready(seed.ReportDigest, seed.BindingDigest, seed.FleetGeneration); err != nil {
		t.Fatalf("final evidence: %+v %v", record, err)
	}
	if err := s.CompactTerminal(ctx, key, testHistoryLimits(), time.Now()); err != nil {
		t.Fatal(err)
	}
	after, err := s.CanaryEvidence(ctx)
	if err != nil || !reflect.DeepEqual(record, after) {
		t.Fatal("compaction replay changed evidence")
	}
}

func TestExtraCanaryJITInvalidatesEvidenceWithoutConsumingAcquisition(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seed := canarySeed()
	if err := s.InitCanaryEvidence(ctx, seed); err != nil {
		t.Fatal(err)
	}
	key := seedCanaryRelease(t, s, 421)
	compatibility := githubscale.ScaleSetCompatibilityReport{DisableUpdate: true, SingleNameLabel: true}
	for range 3 {
		if err := s.BeginCanaryJIT(ctx, seed.ReportDigest, key, compatibility); err != nil {
			t.Fatal("evidence must not deny acquisition", err)
		}
	}
	r, err := s.CanaryEvidence(ctx)
	if err != nil || r.JITCount != 2 || !r.Invalid {
		t.Fatal("extra JIT did not invalidate bounded evidence")
	}
	acquisition, err := s.AcquisitionAssignment(ctx, key)
	if err != nil || acquisition.Outcome != AcquisitionOutcomeAcquired || acquisition.RevokedEpoch != 0 {
		t.Fatal("evidence changed acquisition authority")
	}
}

func TestCanaryJITIntentRequiresDurableAcquisitionAtReleaseArmed(t *testing.T) {
	for name, sql := range map[string]string{
		"not acquired":     `UPDATE assignments SET acquisition_outcome = 'requested'`,
		"revoked":          `UPDATE assignments SET pre_running_revoked_epoch = 2`,
		"wrong checkpoint": `UPDATE assignments SET state = 'RUNNER_HELD'`,
		"zero run":         `UPDATE assignments SET workflow_run_id=0`,
		"unproven batch":   `UPDATE message_acquisitions SET state='ambiguous',result_digest=NULL,acquired_count=NULL`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := newTestStore(t)
			seed := canarySeed()
			if err := s.InitCanaryEvidence(ctx, seed); err != nil {
				t.Fatal(err)
			}
			key := seedCanaryRelease(t, s, 422)
			if _, err := s.DB().ExecContext(ctx, sql); err != nil {
				t.Fatal(err)
			}
			if s.BeginCanaryJIT(ctx, seed.ReportDigest, key, githubscale.ScaleSetCompatibilityReport{DisableUpdate: true, SingleNameLabel: true}) == nil {
				t.Fatal("unproven acquisition accepted")
			}
		})
	}
}

func TestCanaryJITPermitRecordsOnlyMatchingGovernedEvidence(t *testing.T) {
	for name, change := range map[string]func(*controller.AcquisitionPermitBinding){
		"fence":        func(b *controller.AcquisitionPermitBinding) { b.FenceGeneration++ },
		"repository":   func(b *controller.AcquisitionPermitBinding) { b.RepositoryAlias = "other-repo" },
		"operation":    func(b *controller.AcquisitionPermitBinding) { b.OperationKind = "poll" },
		"enabled mode": func(b *controller.AcquisitionPermitBinding) { b.PolicyMode = controller.AcquisitionEnabled },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := newTestStore(t)
			seed := canarySeed()
			if err := s.InitCanaryEvidence(ctx, seed); err != nil {
				t.Fatal(err)
			}
			key := seedCanaryRelease(t, s, 423)
			if err := s.BeginCanaryJIT(ctx, seed.ReportDigest, key, githubscale.ScaleSetCompatibilityReport{DisableUpdate: true, SingleNameLabel: true}); err != nil {
				t.Fatal(err)
			}
			permit := canaryPermit()
			change(&permit)
			if err := s.BindCanaryJITPermit(ctx, seed.ReportDigest, key, permit); err != nil {
				t.Fatal("evidence must not deny a governed operation", err)
			}
			r, err := s.CanaryEvidence(ctx)
			if err != nil || !r.Invalid {
				t.Fatal("mismatched permit did not invalidate evidence")
			}
		})
	}
}

func TestCanaryEvidenceSQLHasOneBoundedRecord(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.InitCanaryEvidence(ctx, canarySeed()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO canary_evidence (id,document) VALUES (2,'{}')`); err == nil {
		t.Fatal("second evidence row accepted")
	}
	if _, err := s.DB().ExecContext(ctx, `UPDATE canary_evidence SET document = ? WHERE id = 1`, strings.Repeat("x", canary.MaxRecordBytes+1)); err == nil {
		t.Fatal("oversized persisted evidence accepted")
	}
}

func TestCanarySealSnapshotIsReadOnlyAndRequiresDisabledQuiescence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.InitCanaryEvidence(ctx, canarySeed()); err != nil {
		t.Fatal(err)
	}
	readonly, err := OpenReadOnlyWithHistoryLimits(s.path, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readonly.Close() }()
	record, err := readonly.CanarySealSnapshot(ctx)
	if err != nil || record.ReportDigest != canarySeed().ReportDigest {
		t.Fatal("disabled snapshot unavailable", err)
	}
	active := controller.AcquisitionPolicy{Mode: controller.AcquisitionCanaryOnly, EligibleScaleSets: []string{"example-canary"}, MaxCapacity: 1, RepositoryPolicyRevision: 1, RepositoryPolicies: []controller.RepositoryPolicySummary{{Alias: "repo-a", MaxConcurrency: 1, Eligibility: "active"}}}
	if _, err := s.CompareAndSetAcquisition(ctx, 0, active); err != nil {
		t.Fatal(err)
	}
	if _, err := readonly.CanarySealSnapshot(ctx); err == nil {
		t.Fatal("active acquisition accepted for sealing")
	}
	if _, err := s.CompareAndSetAcquisition(ctx, 1, controller.AcquisitionPolicy{Mode: controller.AcquisitionDisabled}); err != nil {
		t.Fatal(err)
	}
	key := seedAssignment(t, ctx, s, "repo-a", 430)
	if _, err := readonly.CanarySealSnapshot(ctx); err == nil {
		t.Fatal("live assignment accepted for sealing")
	}
	if _, err := s.DB().ExecContext(ctx, `UPDATE assignments SET state='DESTROYED' WHERE runner_request_id=430`); err != nil {
		t.Fatal(err)
	}
	if _, err := readonly.CanarySealSnapshot(ctx); err == nil {
		t.Fatal("remaining capacity/slot accepted for sealing")
	}
	if err := s.ClearTerminalRuntime(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearAdmissionProjection(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := readonly.CanarySealSnapshot(ctx); err != nil {
		t.Fatal("retained terminal metadata is not a live resource", err)
	}
}

func seedRunningCanary(t *testing.T) (*SQLiteStore, controller.AssignmentKey, canary.Workflow) {
	t.Helper()
	ctx := context.Background()
	s := newTestStore(t)
	seed := canarySeed()
	if err := s.InitCanaryEvidence(ctx, seed); err != nil {
		t.Fatal(err)
	}
	key := seedCanaryRelease(t, s, 440)
	if err := s.BeginCanaryJIT(ctx, seed.ReportDigest, key, githubscale.ScaleSetCompatibilityReport{DisableUpdate: true, SingleNameLabel: true}); err != nil {
		t.Fatal(err)
	}
	permit := canaryPermit()
	if err := s.BindCanaryJITPermit(ctx, seed.ReportDigest, key, permit); err != nil {
		t.Fatal(err)
	}
	digest, err := controller.AcquisitionPermitBindingDigest(permit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginListenerReleaseEffect(ctx, key, digest); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteEffect(ctx, hex.EncodeToString(digest[:]), EffectResult{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(ctx, key, controller.StateListenerReleased); err != nil {
		t.Fatal(err)
	}
	current, _ := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	if err := s.ApplyRunnerObservation(ctx, key, RunnerObservation{UpstreamRunnerID: 100, BoundRequestID: key.RunnerRequestID, RunnerContainerID: current.Slot.RunnerContainerID, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return s, key, canary.Workflow{Version: 1, ReportDigest: seed.ReportDigest, WorkflowRunID: 11440, Revision: strings.Repeat("d", 40), CheckoutHTTPS: true, SandboxVerified: true, InheritedJITAbsent: true, CredentialProbeCompleted: true, Tools: canary.RequiredTools()}
}

func TestCanaryWorkflowCaptureRequiresTheSameRunningJobAndRelease(t *testing.T) {
	for _, scenario := range []string{"wrong report", "wrong run", "invalid frame", "conflict", "replay", "wrong checkpoint", "wrong release", "missing permit", "missing workflow", "unfinished completion", "unfinished cleanup", "different assignment"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			s, key, workflow := seedRunningCanary(t)
			seed := canarySeed()
			switch scenario {
			case "wrong report":
				workflow.ReportDigest = strings.Repeat("f", 64)
			case "wrong run":
				workflow.WorkflowRunID++
			case "invalid frame":
				workflow.Tools = nil
			case "conflict", "replay":
				if err := s.RecordCanaryWorkflow(ctx, seed.ReportDigest, key, workflow); err != nil {
					t.Fatal(err)
				}
				if scenario == "conflict" {
					workflow.Revision = strings.Repeat("e", 40)
				}
			case "wrong checkpoint":
				if _, err := s.DB().ExecContext(ctx, `UPDATE assignments SET state='LISTENER_RELEASED'`); err != nil {
					t.Fatal(err)
				}
			case "wrong release":
				if _, err := s.DB().ExecContext(ctx, `UPDATE effects SET idempotency_key=? WHERE kind=?`, strings.Repeat("f", 64), LifecycleEffectListenerRelease); err != nil {
					t.Fatal(err)
				}
			case "missing permit":
				r, err := s.CanaryEvidence(ctx)
				if err != nil {
					t.Fatal(err)
				}
				r.PermitDigest = ""
				b, _ := json.Marshal(r)
				if _, err := s.DB().ExecContext(ctx, `UPDATE canary_evidence SET document=?`, string(b)); err != nil {
					t.Fatal(err)
				}
			case "missing workflow":
				if _, err := s.DB().ExecContext(ctx, `UPDATE assignments SET state='JOB_FINISHED'`); err != nil {
					t.Fatal(err)
				}
				if err := s.CompleteCanaryJob(ctx, seed.ReportDigest, key, "success"); err != nil {
					t.Fatal(err)
				}
			case "unfinished completion":
				if err := s.CompleteCanaryJob(ctx, seed.ReportDigest, key, "success"); err == nil {
					t.Fatal("unfinished job completed")
				}
				return
			case "unfinished cleanup":
				if err := s.MarkCanaryCleanup(ctx, seed.ReportDigest, key); err == nil {
					t.Fatal("unfinished job reclaimed")
				}
				return
			case "different assignment":
				key.RunnerRequestID++
			}
			if scenario != "missing workflow" {
				err := s.RecordCanaryWorkflow(ctx, seed.ReportDigest, key, workflow)
				if scenario == "wrong checkpoint" {
					if err == nil {
						t.Fatal("non-running frame accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			r, err := s.CanaryEvidence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "replay" {
				if r.Invalid {
					t.Fatal("same durable observation replay invalidated proof")
				}
			} else if !r.Invalid {
				t.Fatal("unproven workflow did not invalidate evidence")
			}
		})
	}
}

func TestCanaryCompletionReplayPreservesTheOriginalResult(t *testing.T) {
	for _, result := range []string{"success", "failure", "unexpected upstream value"} {
		t.Run(result, func(t *testing.T) {
			ctx := context.Background()
			s, key, w := seedRunningCanary(t)
			seed := canarySeed()
			if err := s.RecordCanaryWorkflow(ctx, seed.ReportDigest, key, w); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().ExecContext(ctx, `UPDATE assignments SET state='JOB_FINISHED'`); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteCanaryJob(ctx, seed.ReportDigest, key, "success"); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteCanaryJob(ctx, seed.ReportDigest, key, result); err != nil {
				t.Fatal(err)
			}
			r, err := s.CanaryEvidence(ctx)
			if err != nil || r.JobCount != 1 || r.JobResult != "success" || r.Invalid != (result != "success") {
				t.Fatal("completion replay replaced original proof", r, err)
			}
		})
	}
}

func TestCanaryFinalizationRequiresBothAbsenceProofs(t *testing.T) {
	for _, missing := range []string{"upstream", "runtime", "neither"} {
		t.Run(missing, func(t *testing.T) {
			ctx := context.Background()
			s, key, _ := seedRunningCanary(t)
			r, err := s.CanaryEvidence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			r.UpstreamAbsent = missing != "upstream"
			r.RuntimeAbsent = missing != "runtime"
			b, _ := json.Marshal(r)
			if _, err := s.DB().ExecContext(ctx, `UPDATE canary_evidence SET document=?`, string(b)); err != nil {
				t.Fatal(err)
			}
			tx, err := s.DB().BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := finalizeCanaryEvidence(ctx, tx, key); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			got, err := s.CanaryEvidence(ctx)
			if err != nil || got.Finalized != (missing == "neither") {
				t.Fatal("absence proof lost", got, err)
			}
		})
	}
}

func TestCanaryEvidenceRestartRefusesChangingTheSameReportBinding(t *testing.T) {
	for _, field := range []string{"binding", "generation"} {
		t.Run(field, func(t *testing.T) {
			s := newTestStore(t)
			seed := canarySeed()
			ctx := context.Background()
			if err := s.InitCanaryEvidence(ctx, seed); err != nil {
				t.Fatal(err)
			}
			if field == "binding" {
				seed.BindingDigest = strings.Repeat("f", 64)
			} else {
				seed.FleetGeneration++
			}
			if err := s.InitCanaryEvidence(ctx, seed); err == nil {
				t.Fatal("same report changed binding")
			}
		})
	}
}

func TestCanarySealSnapshotRefusesEachRemainingDurableResource(t *testing.T) {
	for _, resource := range []string{"slot", "reservation", "admission phase", "admission slot"} {
		t.Run(resource, func(t *testing.T) {
			s, key, _ := seedRunningCanary(t)
			ctx := context.Background()
			if _, err := s.DB().ExecContext(ctx, `UPDATE assignments SET state='DESTROYED'`); err != nil {
				t.Fatal(err)
			}
			if resource != "slot" {
				if _, err := s.DB().ExecContext(ctx, `DELETE FROM runner_slots`); err != nil {
					t.Fatal(err)
				}
			}
			if resource != "reservation" {
				if _, err := s.DB().ExecContext(ctx, `DELETE FROM reservations`); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.ClearAdmissionProjection(ctx, key); err != nil {
				t.Fatal(err)
			}
			if resource == "admission phase" {
				if _, err := s.DB().ExecContext(ctx, `UPDATE assignments SET admission_phase=1`); err != nil {
					t.Fatal(err)
				}
			}
			if resource == "admission slot" {
				if _, err := s.DB().ExecContext(ctx, `UPDATE assignments SET admission_slot_id=1`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.CanarySealSnapshot(ctx); err == nil {
				t.Fatal("remaining resource accepted", resource)
			}
		})
	}
}

func TestCanaryWritesRejectAChangedOriginalReportDigest(t *testing.T) {
	ctx := context.Background()
	s, key, w := seedRunningCanary(t)
	other := strings.Repeat("f", 64)
	if err := s.RecordCanaryWorkflow(ctx, other, key, w); err == nil {
		t.Fatal("changed original report accepted")
	}
	if _, err := s.CanaryWorkflowRecorded(ctx, other, key); err == nil {
		t.Fatal("changed readback report accepted")
	}
}

func TestCanaryEvidenceIsChargedToFutureHistoryReservations(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.InitCanaryEvidence(ctx, canarySeed()); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	totals, err := historyBudgetTotalsTx(ctx, tx)
	if err != nil || totals.rows != 1 || totals.logicalBytes != canary.MaxRecordBytes {
		t.Fatal("retained evidence escaped future reservation accounting", totals, err)
	}
}
