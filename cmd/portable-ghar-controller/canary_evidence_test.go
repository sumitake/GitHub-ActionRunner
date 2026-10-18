package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/canary"
	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func pendingCanaryFixture(t *testing.T) conformance.Report {
	t.Helper()
	document, err := os.ReadFile("../../tests/fixtures/conformance/pending-case15.fixture")
	if err != nil {
		t.Fatal(err)
	}
	report, err := conformance.ParseReport(document, len(document))
	if err != nil {
		t.Fatal(err)
	}
	return report
}
func readyCanaryFixture(report conformance.Report) canary.Record {
	workflow := canary.Workflow{Version: 1, ReportDigest: report.Digest(), WorkflowRunID: 42, Revision: strings.Repeat("b", 40), CheckoutHTTPS: true, SandboxVerified: true, InheritedJITAbsent: true, ListenerProcReadable: true, DecodedCredentialsReadable: true, CredentialProbeCompleted: true, Tools: canary.RequiredTools()}
	return canary.Record{Version: 1, ReportDigest: report.Digest(), BindingDigest: report.Binding().Digest(), FleetGeneration: report.Binding().FleetGeneration(), AssignmentDigest: strings.Repeat("c", 64), AcquisitionDigest: strings.Repeat("d", 64), PermitDigest: strings.Repeat("e", 64), PolicyDigest: strings.Repeat("f", 64), WorkflowRunID: 42, JITCount: 1, JobCount: 1, DisableUpdate: true, SingleNameLabel: true, CanaryCapacityOne: true, ListenerReleased: true, JobResult: "success", Workflow: workflow, UpstreamAbsent: true, RuntimeAbsent: true, Finalized: true}
}

func TestCanaryReportCompletionUsesOnlyBoundDurableObservations(t *testing.T) {
	pending := pendingCanaryFixture(t)
	record := readyCanaryFixture(pending)
	completed, err := completeCanaryReport(pending, record)
	if err != nil {
		t.Fatal(err)
	}
	if conformance.RequireFullPass(completed) != nil {
		t.Fatal("completed report is not passing")
	}
	if !reflect.DeepEqual(completed.Binding(), pending.Binding()) || !reflect.DeepEqual(completed.Cases()[:14], pending.Cases()[:14]) || !reflect.DeepEqual(completed.Cleanup(), pending.Cleanup()) {
		t.Fatal("completion changed prior evidence")
	}
	digest, err := record.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if completed.Cases()[14].ObservationDigest() != digest {
		t.Fatal("case 15 did not commit exact durable observations")
	}
	for name, change := range map[string]func(*canary.Record){
		"incomplete": func(r *canary.Record) { r.Finalized = false },
		"different report": func(r *canary.Record) {
			r.ReportDigest = strings.Repeat("1", 64)
			r.Workflow.ReportDigest = r.ReportDigest
		},
		"different binding": func(r *canary.Record) { r.BindingDigest = strings.Repeat("1", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			r := record
			change(&r)
			if _, err := completeCanaryReport(pending, r); err == nil {
				t.Fatal("unbound/incomplete observations sealed")
			}
		})
	}
	if _, err := completeCanaryReport(completed, record); err == nil {
		t.Fatal("completed report treated as pending")
	}
}

type canaryStoreFixture struct {
	seed      canary.Record
	calls     []string
	initErr   error
	recorded  bool
	readErr   error
	completed *canary.Workflow
	result    string
}

func (s *canaryStoreFixture) InitCanaryEvidence(_ context.Context, r canary.Record) error {
	s.seed = r
	return s.initErr
}
func (s *canaryStoreFixture) BeginCanaryJIT(context.Context, string, controller.AssignmentKey, githubscale.ScaleSetCompatibilityReport) error {
	s.calls = append(s.calls, "intent")
	return nil
}
func (s *canaryStoreFixture) BindCanaryJITPermit(context.Context, string, controller.AssignmentKey, controller.AcquisitionPermitBinding) error {
	s.calls = append(s.calls, "permit")
	return nil
}
func (s *canaryStoreFixture) CanaryWorkflowRecorded(context.Context, string, controller.AssignmentKey) (bool, error) {
	return s.recorded, s.readErr
}
func (s *canaryStoreFixture) RecordCanaryWorkflow(_ context.Context, _ string, _ controller.AssignmentKey, w canary.Workflow) error {
	s.calls = append(s.calls, "workflow")
	s.completed = &w
	return nil
}
func (s *canaryStoreFixture) CompleteCanaryJob(_ context.Context, _ string, _ controller.AssignmentKey, result string) error {
	s.calls = append(s.calls, "completed")
	s.result = result
	return nil
}
func (s *canaryStoreFixture) MarkCanaryCleanup(context.Context, string, controller.AssignmentKey) error {
	s.calls = append(s.calls, "cleanup")
	return nil
}

type canaryReaderFixture struct {
	workflow *canary.Workflow
	err      error
	calls    int
}

func (r *canaryReaderFixture) ReadCanaryWorkflow(context.Context, hostruntime.RecoverySpec) (*canary.Workflow, error) {
	r.calls++
	return r.workflow, r.err
}

func canaryRuntimeFixture(report conformance.Report) productionRuntime {
	var runtime productionRuntime
	runtime.manifest.BuildID = report.Binding().BuildID()
	runtime.manifest.FleetGeneration = report.Binding().FleetGeneration()
	runtime.overlay.Target.ProfileID = report.Binding().ProfileID()
	runtime.overlay.Manifest.Digest = report.Binding().RuntimeManifestDigest()
	runtime.overlayDigest = report.Binding().PrivateOverlayDigest()
	return runtime
}
func TestProductionCanaryObserverBindsTheEntirePendingRuntime(t *testing.T) {
	report := pendingCanaryFixture(t)
	ctx := context.Background()
	for name, change := range map[string]func(*productionRuntime){
		"build":              func(r *productionRuntime) { r.manifest.BuildID = strings.Repeat("1", 64) },
		"profile":            func(r *productionRuntime) { r.overlay.Target.ProfileID = "other-profile" },
		"generation":         func(r *productionRuntime) { r.manifest.FleetGeneration++ },
		"manifest and image": func(r *productionRuntime) { r.overlay.Manifest.Digest = strings.Repeat("1", 64) },
		"overlay":            func(r *productionRuntime) { r.overlayDigest = strings.Repeat("1", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			runtime := canaryRuntimeFixture(report)
			change(&runtime)
			s := &canaryStoreFixture{}
			if _, err := newProductionCanaryObserver(ctx, report, runtime, s, &canaryReaderFixture{}); err == nil || s.seed.Version != 0 {
				t.Fatal("runtime drift initialized canary evidence")
			}
		})
	}
	s := &canaryStoreFixture{}
	w := readyCanaryFixture(report).Workflow
	reader := &canaryReaderFixture{workflow: &w}
	observer, err := newProductionCanaryObserver(ctx, report, canaryRuntimeFixture(report), s, reader)
	if err != nil || observer == nil {
		t.Fatal(err)
	}
	if s.seed.ReportDigest != report.Digest() || observer.ReportDigest() != report.Digest() || s.seed.BindingDigest != report.Binding().Digest() || s.seed.JITCount != 0 {
		t.Fatal("evidence seed did not bind original pending report")
	}
	key := controller.AssignmentKey{RepositoryAlias: "repo-a", RunnerRequestID: 42}
	if err := observer.BeforeJIT(ctx, key, githubscale.ScaleSetCompatibilityReport{}); err != nil {
		t.Fatal(err)
	}
	if err := observer.AuthorizedJIT(ctx, key, controller.AcquisitionPermitBinding{}); err != nil {
		t.Fatal(err)
	}
	if err := observer.Collect(ctx, key, hostruntime.RecoverySpec{}); err != nil {
		t.Fatal(err)
	}
	if err := observer.Completed(ctx, key, "success"); err != nil {
		t.Fatal(err)
	}
	if s.completed == nil || s.result != "success" || reader.calls != 1 {
		t.Fatal("workflow result was not recorded")
	}
	if err := observer.Reclaimed(ctx, key); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.calls, []string{"intent", "permit", "workflow", "completed", "cleanup"}) {
		t.Fatal(s.calls)
	}
	reader.err = errors.New("unavailable")
	if err := observer.Collect(ctx, key, hostruntime.RecoverySpec{}); err == nil {
		t.Fatal("unreadable frame accepted")
	}
	if err := observer.Completed(ctx, key, "failure"); err != nil || s.result != "failure" {
		t.Fatal("read failure blocked upstream completion")
	}

}

func TestProductionCanaryObserverInitializationIsOptionalAndFailsClosed(t *testing.T) {
	report := pendingCanaryFixture(t)
	runtime := canaryRuntimeFixture(report)
	if observer, err := newProductionCanaryObserver(context.Background(), conformance.Report{}, runtime, nil, nil); err != nil || observer != nil {
		t.Fatal("missing report initialized evidence")
	}
	full, err := completeCanaryReport(report, readyCanaryFixture(report))
	if err != nil {
		t.Fatal(err)
	}
	if observer, err := newProductionCanaryObserver(context.Background(), full, runtime, nil, nil); err != nil || observer != nil {
		t.Fatal("passing report initialized canary evidence")
	}
	if _, err := newProductionCanaryObserver(context.Background(), report, runtime, nil, &canaryReaderFixture{}); err == nil {
		t.Fatal("missing store accepted")
	}
	if _, err := newProductionCanaryObserver(context.Background(), report, runtime, &canaryStoreFixture{}, nil); err == nil {
		t.Fatal("missing reader accepted")
	}
	s := &canaryStoreFixture{initErr: errors.New("private diagnostic")}
	if _, err := newProductionCanaryObserver(context.Background(), report, runtime, s, &canaryReaderFixture{}); err == nil || strings.Contains(err.Error(), "private diagnostic") {
		t.Fatal("store failure ignored or exposed")
	}
	var nilContext context.Context
	if _, err := newProductionCanaryObserver(nilContext, report, runtime, &canaryStoreFixture{}, &canaryReaderFixture{}); err == nil {
		t.Fatal("nil context accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newProductionCanaryObserver(canceled, report, runtime, &canaryStoreFixture{}, &canaryReaderFixture{}); err == nil {
		t.Fatal("canceled context accepted")
	}
}

func TestCanaryCollectionPendingAndRecordedDoNotRewriteObservations(t *testing.T) {
	report := pendingCanaryFixture(t)
	for _, scenario := range []string{"pending", "recorded", "store error"} {
		t.Run(scenario, func(t *testing.T) {
			s := &canaryStoreFixture{}
			reader := &canaryReaderFixture{}
			o, err := newProductionCanaryObserver(context.Background(), report, canaryRuntimeFixture(report), s, reader)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "recorded" {
				s.recorded = true
			}
			if scenario == "store error" {
				s.readErr = errors.New("unavailable")
			}
			err = o.Collect(context.Background(), controller.AssignmentKey{}, hostruntime.RecoverySpec{})
			if (err != nil) != (scenario == "store error") {
				t.Fatal("collection error lost", err)
			}
			wantReads := 0
			if scenario == "pending" {
				wantReads = 1
			}
			if reader.calls != wantReads || len(s.calls) != 0 {
				t.Fatal("pending or existing observation rewritten")
			}
		})
	}
}
