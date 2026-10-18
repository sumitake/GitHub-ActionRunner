package state

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestCanaryCompletionSurvivesRestartBeforeObserverCallback(t *testing.T) {
	ctx := context.Background()
	s, key, workflow := seedRunningCanary(t)
	workflow.ListenerProcReadable, workflow.DecodedCredentialsReadable = true, true
	seed := canarySeed()
	if err := s.RecordCanaryWorkflow(ctx, seed.ReportDigest, key, workflow); err != nil {
		t.Fatal(err)
	}
	current, _ := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	observation := RunnerObservation{UpstreamRunnerID: 100, BoundRequestID: key.RunnerRequestID, RunnerContainerID: current.Slot.RunnerContainerID, Finished: true, ObservedAt: time.Now(), CanaryCompletion: &CanaryCompletion{ReportDigest: seed.ReportDigest, Result: "success"}}
	if err := s.ApplyRunnerObservation(ctx, key, observation); err != nil {
		t.Fatal(err)
	}
	// Simulate termination immediately after the observation transaction. No
	// Completed callback or upstream event redelivery can fill in missing proof.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithHistoryLimits(s.path, testHistoryLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, found := findRecoverable(t, mustListRecoverable(t, ctx, reopened), key)
	record, err := reopened.CanaryEvidence(ctx)
	if err != nil || !found || current.State != controller.StateJobFinished || record.JobCount != 1 || record.JobResult != "success" {
		t.Fatalf("finished checkpoint lost its result across restart: state=%s record=%+v error=%v", current.State, record, err)
	}
	// The existing restart cleanup and terminal compaction preserve that result.
	if err := reopened.MarkCanaryCleanup(ctx, seed.ReportDigest, key); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Advance(ctx, key, controller.StateDestroyed); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ClearTerminalRuntime(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ClearAdmissionProjection(ctx, key); err != nil {
		t.Fatal(err)
	}
	terminalMessage(t, reopened, key, 440)
	if err := reopened.BeginMessageAck(ctx, "repo-a", 440, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ConfirmMessageAck(ctx, "repo-a", 440, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := reopened.CompactTerminal(ctx, key, testHistoryLimits(), time.Now()); err != nil {
		t.Fatal(err)
	}
	record, err = reopened.CanaryEvidence(ctx)
	if err != nil || record.Ready(seed.ReportDigest, seed.BindingDigest, seed.FleetGeneration) != nil {
		t.Fatalf("recovered one-job proof cannot seal: %+v %v", record, err)
	}
}

func TestCanaryCompletionWriteFailureRollsBackFinishedCheckpoint(t *testing.T) {
	ctx := context.Background()
	s, key, workflow := seedRunningCanary(t)
	if err := s.RecordCanaryWorkflow(ctx, canarySeed().ReportDigest, key, workflow); err != nil {
		t.Fatal(err)
	}
	before, _ := s.CanaryEvidence(ctx)
	if _, err := s.DB().ExecContext(ctx, `CREATE TRIGGER reject_completion BEFORE UPDATE ON canary_evidence BEGIN SELECT RAISE(ABORT, 'synthetic journal failure'); END`); err != nil {
		t.Fatal(err)
	}
	current, _ := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	err := s.ApplyRunnerObservation(ctx, key, RunnerObservation{UpstreamRunnerID: 100, BoundRequestID: key.RunnerRequestID, RunnerContainerID: current.Slot.RunnerContainerID, Finished: true, ObservedAt: time.Now(), CanaryCompletion: &CanaryCompletion{ReportDigest: canarySeed().ReportDigest, Result: "success"}})
	if err == nil {
		t.Fatal("journal write failure committed a finished checkpoint")
	}
	current, _ = findRecoverable(t, mustListRecoverable(t, ctx, s), key)
	after, readErr := s.CanaryEvidence(ctx)
	if readErr != nil || current.State != controller.StateJobRunning || !reflect.DeepEqual(before, after) {
		t.Fatal("failed completion partially committed", current.State, after, readErr)
	}
}

func TestAtomicCanaryCompletionPreservesBindingAndReplayChecks(t *testing.T) {
	for _, scenario := range []string{"identity mismatch", "report mismatch", "nonterminal", "missing journal", "corrupt journal", "same replay", "conflicting replay", "unknown result"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			s, key, workflow := seedRunningCanary(t)
			if err := s.RecordCanaryWorkflow(ctx, canarySeed().ReportDigest, key, workflow); err != nil {
				t.Fatal(err)
			}
			current, _ := findRecoverable(t, mustListRecoverable(t, ctx, s), key)
			observation := RunnerObservation{UpstreamRunnerID: 100, BoundRequestID: key.RunnerRequestID, RunnerContainerID: current.Slot.RunnerContainerID, Finished: true, ObservedAt: time.Now(), CanaryCompletion: &CanaryCompletion{ReportDigest: canarySeed().ReportDigest, Result: "success"}}
			wantFailure := true
			switch scenario {
			case "identity mismatch":
				observation.UpstreamRunnerID++
			case "report mismatch":
				observation.CanaryCompletion.ReportDigest = strings.Repeat("c", 64)
			case "nonterminal":
				observation.Finished = false
			case "missing journal":
				if _, err := s.DB().ExecContext(ctx, `DELETE FROM canary_evidence`); err != nil {
					t.Fatal(err)
				}
			case "corrupt journal":
				if _, err := s.DB().ExecContext(ctx, `UPDATE canary_evidence SET document='{}'`); err != nil {
					t.Fatal(err)
				}
			case "same replay", "conflicting replay":
				if err := s.ApplyRunnerObservation(ctx, key, observation); err != nil {
					t.Fatal(err)
				}
				if scenario == "conflicting replay" {
					observation.CanaryCompletion.Result = "failure"
				}
				wantFailure = false
			case "unknown result":
				observation.CanaryCompletion.Result = "unrecognized upstream result"
				wantFailure = false
			}
			err := s.ApplyRunnerObservation(ctx, key, observation)
			if (err != nil) != wantFailure {
				t.Fatalf("observation error=%v, want failure=%v", err, wantFailure)
			}
			current, _ = findRecoverable(t, mustListRecoverable(t, ctx, s), key)
			if wantFailure {
				if current.State != controller.StateJobRunning {
					t.Fatal("rejected completion changed checkpoint", current.State)
				}
				return
			}
			r, err := s.CanaryEvidence(ctx)
			wantResult := "success"
			if scenario == "unknown result" {
				wantResult = "unknown"
			}
			if err != nil || r.JobCount != 1 || r.JobResult != wantResult || r.Invalid != (scenario == "conflicting replay") {
				t.Fatal("completion replay/result guard changed", r, err)
			}
		})
	}
}
