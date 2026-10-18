package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/canary"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
)

func canaryApprovalFixture(t *testing.T) (canaryReadback, canaryJobRequest, canaryJobApproval) {
	t.Helper()
	report := pendingCanaryFixture(t)
	runtime := canaryRuntimeFixture(report)
	overlay := templateOverlay(t)
	runtime.overlay = overlay
	runtime.overlay.Target.ProfileID = report.Binding().ProfileID()
	runtime.overlay.Manifest.Digest = report.Binding().RuntimeManifestDigest()
	runtime.overlay.Repositories[0].ConfigURL = "https://github.com/owner/repository"
	runtime.overlay.Repositories[0].Eligibility = "active"
	request := canaryJobRequest{Alias: runtime.overlay.Repositories[0].Alias, WorkflowRef: "owner/repository/.github/workflows/canary.yml@refs/heads/main", EventName: "workflow_dispatch", RunID: 42, RunAttempt: 1, JobID: "job"}
	record := canary.Record{Version: 1, ReportDigest: report.Digest(), BindingDigest: report.Binding().Digest(), FleetGeneration: report.Binding().FleetGeneration()}
	rb := canaryReadback{runtime: runtime, report: report, record: record}
	a, err := buildCanaryJobApproval(rb, request)
	if err != nil {
		t.Fatal(err)
	}
	return rb, request, a
}

func TestCanaryApprovalUsesExactRuntimeAndFreshEvidence(t *testing.T) {
	rb, request, good := canaryApprovalFixture(t)
	if good.Job.WorkflowRunID != 42 || good.Job.Repository != "owner/repository" || good.ReportDigest != rb.report.Digest() {
		t.Fatal("wrong approval")
	}
	for name, mutate := range map[string]func(*canaryReadback){
		"generation": func(r *canaryReadback) { r.runtime.manifest.FleetGeneration++ },
		"report":     func(r *canaryReadback) { r.record.ReportDigest = strings.Repeat("f", 64) },
		"binding":    func(r *canaryReadback) { r.record.BindingDigest = strings.Repeat("f", 64) },
		"jit":        func(r *canaryReadback) { r.record.JITCount = 1 },
		"job":        func(r *canaryReadback) { r.record.JobCount = 1 },
		"run":        func(r *canaryReadback) { r.record.WorkflowRunID = 43 },
		"invalid":    func(r *canaryReadback) { r.record.Invalid = true },
	} {
		t.Run(name, func(t *testing.T) {
			bad := rb
			mutate(&bad)
			if _, err := buildCanaryJobApproval(bad, request); err == nil {
				t.Fatal("stale approval accepted")
			}
		})
	}
	for _, r := range []canaryJobRequest{{Alias: "other", WorkflowRef: request.WorkflowRef, EventName: request.EventName, RunID: 42}, {Alias: request.Alias, WorkflowRef: request.WorkflowRef, EventName: "pull_request", RunID: 42}, {Alias: request.Alias, WorkflowRef: request.WorkflowRef, EventName: request.EventName, RunID: 0}} {
		if _, err := buildCanaryJobApproval(rb, r); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestCanaryApprovalParserRefusesAmbiguousOrNoncanonicalInput(t *testing.T) {
	_, _, approval := canaryApprovalFixture(t)
	raw, _ := json.Marshal(approval)
	if _, err := parseCanaryJobApproval(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), '\n'),
		[]byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		[]byte(strings.Replace(string(raw), `"workflow_run_id":42`, `"Workflow_Run_ID":42`, 1)),
		[]byte(strings.Replace(string(raw), `"workflow_run_id":42`, `"workflow_run_id":42,"workflow_\u0072un_id":42`, 1)),
		append(append([]byte(nil), raw...), []byte(`{}`)...),
	} {
		if _, err := parseCanaryJobApproval(bad); err == nil {
			t.Fatal("ambiguous approval accepted")
		}
	}
}

func TestCanaryApprovalFileIsExclusivePrivateAndPinned(t *testing.T) {
	rb, _, a := canaryApprovalFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, canaryJobApprovalName)
	provider := newFileCanaryJobProvider(rb.runtime, rb.report)
	provider.read = func() ([]byte, error) {
		return readCanaryApprovalFile(path, uint32(os.Geteuid()))
	}
	if _, err := provider.ExpectedCanaryJob(context.Background()); err == nil {
		t.Fatal("missing approval authorized")
	}
	if _, err := writeCanaryJobApproval(context.Background(), path, a); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0400 {
		t.Fatal("wrong approval mode")
	}
	expected, err := provider.ExpectedCanaryJob(context.Background())
	if err != nil || expected != a.Job {
		t.Fatal("valid publication not observed", err)
	}
	before, _ := os.ReadFile(path)
	other := a
	other.Job.WorkflowRunID++
	if _, err := writeCanaryJobApproval(context.Background(), path, other); err == nil {
		t.Fatal("existing approval replaced")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("refusal changed approval")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ExpectedCanaryJob(context.Background()); err == nil {
		t.Fatal("changed permissions accepted")
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ExpectedCanaryJob(context.Background()); err == nil {
		t.Fatal("poisoned approval recovered automatically")
	}
}

func TestCanaryBindCommandIsRootOnlyAndClosed(t *testing.T) {
	deps := productionCommandDependencies(time.Now)
	deps.IsRoot = func() bool { return true }
	calls := 0
	deps.CanaryBind = func(_ context.Context, config string, r canaryJobRequest) (canaryJobReceipt, error) {
		calls++
		if config != "/private/overlay.json" || r.RunID != 42 {
			t.Fatal("wrong binding arguments")
		}
		return canaryJobReceipt{SchemaVersion: 1, Created: true}, nil
	}
	args := []string{"canary-bind", "--config=/private/overlay.json", "--alias=example", "--run-id=42", "--workflow-ref=owner/repository/.github/workflows/canary.yml@refs/heads/main", "--event=workflow_dispatch", "--job-id=job", "--run-attempt=1"}
	var out, errout bytes.Buffer
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 0 || calls != 1 {
		t.Fatal("binding command failed", code, errout.String())
	}
	deps.IsRoot = func() bool { return false }
	out.Reset()
	errout.Reset()
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 1 || calls != 1 {
		t.Fatal("non-root binding accepted")
	}
	deps.IsRoot = func() bool { return true }
	deps.CanaryBind = func(context.Context, string, canaryJobRequest) (canaryJobReceipt, error) {
		return canaryJobReceipt{}, errors.New("private detail")
	}
	out.Reset()
	errout.Reset()
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 1 || strings.Contains(errout.String(), "private detail") {
		t.Fatal("open failure surface")
	}
}

func TestCanaryApprovalCancellationAndUnsafePrivateFileNeverAuthorize(t *testing.T) {
	_, _, approval := canaryApprovalFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, canaryJobApprovalName)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writeCanaryJobApproval(ctx, path, approval); err == nil {
		t.Fatal("canceled publication succeeded")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled publication left target")
	}
	if _, err := readCanaryApprovalFile(path, uint32(os.Geteuid())); !errors.Is(err, controller.ErrCanaryJobPending) {
		t.Fatal("private absent approval not pending", err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := readCanaryApprovalFile(path, uint32(os.Geteuid())); errors.Is(err, controller.ErrCanaryJobPending) || err == nil {
		t.Fatal("unsafe parent reported healthy pending")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(approval)
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, raw, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readCanaryApprovalFile(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlink approval accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readCanaryApprovalFile(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("multiply linked approval accepted")
	}
}

func TestCanaryBindReportsVisibleApprovalWhenDurabilityFails(t *testing.T) {
	deps := productionCommandDependencies(time.Now)
	deps.IsRoot = func() bool { return true }
	deps.CanaryBind = func(context.Context, string, canaryJobRequest) (canaryJobReceipt, error) {
		return canaryJobReceipt{SchemaVersion: 1, WorkflowRunID: 42, Created: true}, errors.New("synthetic post-publication sync failure")
	}
	var out, errout bytes.Buffer
	args := []string{"canary-bind", "--config=/private/overlay.json", "--alias=example", "--run-id=42", "--workflow-ref=owner/repository/.github/workflows/canary.yml@refs/heads/main", "--event=workflow_dispatch", "--job-id=job", "--run-attempt=1"}
	if code := runWithDependencies(context.Background(), args, &out, &errout, deps); code != 1 {
		t.Fatal("uncertain durability returned success")
	}
	var receipt canaryJobReceipt
	if json.Unmarshal(out.Bytes(), &receipt) != nil || !receipt.Created || !strings.Contains(errout.String(), "published") {
		t.Fatal("visible approval reported as unpublished", out.String(), errout.String())
	}
}

func TestCanaryApprovalSyncFailureReportsPublicationAndRefusesReplacement(t *testing.T) {
	_, _, approval := canaryApprovalFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, canaryJobApprovalName)
	receipt, err := writeCanaryJobApprovalWithSync(context.Background(), path, approval, func(*os.File) error { return errors.New("synthetic directory sync fault") })
	if err == nil || !receipt.Created || receipt.Durable {
		t.Fatal("ambiguous post-publication state", receipt, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("visible approval silently removed", err)
	}
	if _, err := writeCanaryJobApproval(context.Background(), path, approval); err == nil {
		t.Fatal("published approval replaced after uncertain result")
	}
}

func TestCanaryAcquisitionApprovalIsSpentBeforeRetryOrRestart(t *testing.T) {
	rb, _, approval := canaryApprovalFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	rb.runtime.overlay.Paths.StateRoot = root
	path := filepath.Join(root, canaryJobApprovalName)
	if _, err := writeCanaryJobApproval(context.Background(), path, approval); err != nil {
		t.Fatal(err)
	}
	provider := func() *fileCanaryJobProvider {
		p := newFileCanaryJobProvider(rb.runtime, rb.report)
		p.read = func() ([]byte, error) { return readCanaryApprovalFile(path, uint32(os.Geteuid())) }
		return p
	}
	offer := githubscale.Offer{JobRef: githubscale.JobRef{RunnerRequestID: 1001, JobID: approval.Job.JobID, OwnerName: "owner", RepositoryName: "repository", WorkflowRunID: 42, JobWorkflowRef: approval.Job.WorkflowRef, EventName: "workflow_dispatch", RequestLabels: []string{approval.Job.ScaleSet}}}
	first := provider()
	if err := first.ConsumeCanaryAcquisition(context.Background(), approval.Job.RepositoryAlias, approval.Job.ScaleSet, offer); err != nil {
		t.Fatal(err)
	}
	offer.RunnerRequestID++
	for _, p := range []*fileCanaryJobProvider{first, provider()} {
		if p.ConsumeCanaryAcquisition(context.Background(), approval.Job.RepositoryAlias, approval.Job.ScaleSet, offer) == nil {
			t.Fatal("second acquisition authorized")
		}
	}
}
