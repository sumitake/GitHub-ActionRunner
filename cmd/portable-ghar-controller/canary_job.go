package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
)

const canaryJobApprovalName = "canary-job-approval.json"
const maxCanaryJobApprovalBytes = 4096

type canaryJobApproval struct {
	SchemaVersion   uint32                       `json:"schema_version"`
	ReportDigest    string                       `json:"report_digest"`
	BindingDigest   string                       `json:"binding_digest"`
	FleetGeneration uint64                       `json:"fleet_generation"`
	Job             controller.CanaryJobIdentity `json:"job"`
}

type canaryJobRequest struct {
	Alias, WorkflowRef, EventName string
	RunID                         int64
}
type canaryJobReceipt struct {
	SchemaVersion  uint32 `json:"schema_version"`
	ReportDigest   string `json:"report_digest"`
	ApprovalDigest string `json:"approval_digest"`
	WorkflowRunID  int64  `json:"workflow_run_id"`
	Created        bool   `json:"created"`
}

// fileCanaryJobProvider adds an approval intersection, never substitutes for
// the existing fence/Worker/epoch/conformance authorities. A missing file can
// become bound after dispatch; an already accepted approval can never change.
type fileCanaryJobProvider struct {
	mu                          sync.Mutex
	read                        func() ([]byte, error)
	reportDigest, bindingDigest string
	generation                  uint64
	repositories                map[string]controller.CanaryJobIdentity
	pinned                      []byte
	poisoned                    bool
}

func newFileCanaryJobProvider(runtime productionRuntime, report conformance.Report) *fileCanaryJobProvider {
	path := filepath.Join(runtime.overlay.Paths.StateRoot, canaryJobApprovalName)
	p := &fileCanaryJobProvider{read: func() ([]byte, error) { return readCanaryApprovalFile(path, 0) }, reportDigest: report.Digest(), bindingDigest: report.Binding().Digest(), generation: runtime.manifest.FleetGeneration, repositories: map[string]controller.CanaryJobIdentity{}}
	for _, repo := range runtime.overlay.Repositories {
		u, err := url.Parse(repo.ConfigURL)
		if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && repo.Eligibility == "active" {
			p.repositories[repo.Alias] = controller.CanaryJobIdentity{RepositoryAlias: repo.Alias, Repository: strings.TrimPrefix(u.Path, "/"), ScaleSet: repo.ScaleSetName}
		}
	}
	return p
}

func readCanaryApprovalFile(path string, expectedUID uint32) ([]byte, error) {
	fd, err := openProductionPrivateDirectory(filepath.Dir(path), expectedUID)
	if err != nil {
		return nil, errCommandUnavailable
	}
	if unix.Close(fd) != nil {
		return nil, errCommandUnavailable
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, controller.ErrCanaryJobPending
	}
	return readPinnedOwnedFile(path, 0400, maxCanaryJobApprovalBytes, expectedUID)
}

func parseCanaryJobApproval(raw []byte) (canaryJobApproval, error) {
	if len(raw) == 0 || len(raw) > maxCanaryJobApprovalBytes {
		return canaryJobApproval{}, errCommandUnavailable
	}
	var a canaryJobApproval
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil {
		return a, errCommandUnavailable
	}
	canonical, err := json.Marshal(a)
	// Byte-exact re-encoding rejects duplicate, escaped, case-alias and trailing
	// keys/documents as well as noncanonical numbers or whitespace.
	if err != nil || !bytes.Equal(raw, canonical) || a.SchemaVersion != 1 || !canaryApprovalDigest(a.ReportDigest) || !canaryApprovalDigest(a.BindingDigest) || a.FleetGeneration == 0 || a.Job.Validate() != nil {
		return a, errCommandUnavailable
	}
	return a, nil
}

func canaryApprovalDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (p *fileCanaryJobProvider) ExpectedCanaryJob(ctx context.Context) (controller.CanaryJobIdentity, error) {
	if ctx == nil || ctx.Err() != nil {
		return controller.CanaryJobIdentity{}, controller.ErrCanaryJobRejected
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.poisoned {
		return controller.CanaryJobIdentity{}, controller.ErrCanaryJobRejected
	}
	raw, err := p.read()
	if err != nil {
		if p.pinned != nil {
			p.poisoned = true
		} else if errors.Is(err, controller.ErrCanaryJobPending) {
			return controller.CanaryJobIdentity{}, controller.ErrCanaryJobPending
		}
		return controller.CanaryJobIdentity{}, controller.ErrCanaryJobRejected
	}
	a, err := parseCanaryJobApproval(raw)
	repo, known := p.repositories[a.Job.RepositoryAlias]
	if err != nil || a.ReportDigest != p.reportDigest || a.BindingDigest != p.bindingDigest || a.FleetGeneration != p.generation || !known || a.Job.Repository != repo.Repository || a.Job.ScaleSet != repo.ScaleSet || p.pinned != nil && !bytes.Equal(raw, p.pinned) {
		if p.pinned != nil {
			p.poisoned = true
		}
		return controller.CanaryJobIdentity{}, controller.ErrCanaryJobRejected
	}
	if p.pinned == nil {
		p.pinned = append([]byte(nil), raw...)
	}
	return a.Job, nil
}

func executeCanaryJobBind(ctx context.Context, args []string, stdout, stderr io.Writer, deps commandDependencies) int {
	flags, err := parseExactFlags(args, map[string]bool{"config": true, "alias": true, "run-id": true, "workflow-ref": true, "event": true})
	if err != nil || len(flags) != 5 || deps.CanaryBind == nil {
		return commandUsage(stderr)
	}
	for _, v := range flags {
		if v == "" {
			return commandUsage(stderr)
		}
	}
	id, err := strconv.ParseInt(flags["run-id"], 10, 64)
	if err != nil || strconv.FormatInt(id, 10) != flags["run-id"] || id <= 0 {
		return commandUsage(stderr)
	}
	if !deps.IsRoot() {
		return commandFailure(stderr, "canary job binding")
	}
	callCtx, cancel := context.WithTimeout(ctx, deps.AdminTimeout)
	defer cancel()
	receipt, err := deps.CanaryBind(callCtx, flags["config"], canaryJobRequest{Alias: flags["alias"], WorkflowRef: flags["workflow-ref"], EventName: flags["event"], RunID: id})
	if err != nil || json.NewEncoder(stdout).Encode(receipt) != nil {
		return commandFailure(stderr, "canary job binding")
	}
	return 0
}

func buildCanaryJobApproval(readback canaryReadback, request canaryJobRequest) (canaryJobApproval, error) {
	r := readback.report
	record := readback.record
	if r.Status() != conformance.StatusPending || !reportMatchesCanaryRuntime(r, readback.runtime) || record.ReportDigest != r.Digest() || record.BindingDigest != r.Binding().Digest() || record.FleetGeneration != r.Binding().FleetGeneration() || record.Version != 1 || record.Invalid || record.JITCount != 0 || record.JobCount != 0 || record.WorkflowRunID != 0 || record.Finalized || record.Workflow.Version != 0 || record.JobResult != "" || record.AssignmentDigest != "" || record.AcquisitionDigest != "" || record.PermitDigest != "" || record.ListenerReleased {
		return canaryJobApproval{}, errCommandUnavailable
	}
	provider := newFileCanaryJobProvider(readback.runtime, r)
	job, ok := provider.repositories[request.Alias]
	if !ok {
		return canaryJobApproval{}, errCommandUnavailable
	}
	job.WorkflowRef = request.WorkflowRef
	job.WorkflowRunID = request.RunID
	job.EventName = request.EventName
	if job.Validate() != nil {
		return canaryJobApproval{}, errCommandUnavailable
	}
	return canaryJobApproval{SchemaVersion: 1, ReportDigest: r.Digest(), BindingDigest: r.Binding().Digest(), FleetGeneration: r.Binding().FleetGeneration(), Job: job}, nil
}

func writeCanaryJobApproval(ctx context.Context, path string, approval canaryJobApproval) (canaryJobReceipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return canaryJobReceipt{}, errCommandUnavailable
	}
	raw, err := json.Marshal(approval)
	if err != nil {
		return canaryJobReceipt{}, errCommandUnavailable
	}
	if _, err = parseCanaryJobApproval(raw); err != nil {
		return canaryJobReceipt{}, err
	}
	sum := sha256.Sum256(raw)
	receipt := canaryJobReceipt{SchemaVersion: 1, ReportDigest: approval.ReportDigest, ApprovalDigest: hex.EncodeToString(sum[:]), WorkflowRunID: approval.Job.WorkflowRunID}
	// Stage complete bytes before atomic, exclusive publication. Readers can
	// see only absence or one complete single-link file. Reuse the platform's
	// no-replace rename contract; never overwrite or repair an existing path.
	f, err := os.CreateTemp(filepath.Dir(path), ".canary-job-approval-")
	if err != nil {
		return receipt, errCommandUnavailable
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(raw); err == nil {
		err = f.Chmod(0400)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return receipt, errCommandUnavailable
	}
	if ctx.Err() != nil {
		return receipt, errCommandUnavailable
	}
	if err = renameCanaryApprovalNoReplace(temp, path); err != nil {
		return receipt, errCommandUnavailable
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return receipt, errCommandUnavailable
	}
	syncErr := dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil || closeErr != nil {
		return receipt, errCommandUnavailable
	}
	receipt.Created = true
	return receipt, nil
}

// Binding only reads the existing runtime/evidence database, then publishes one
// private approval file. It does not dispatch, alter policy or request a token.
func productionCanaryBind(ctx context.Context, config string, request canaryJobRequest) (canaryJobReceipt, error) {
	readback, err := readCanaryReadback(ctx, config, false)
	if err != nil {
		return canaryJobReceipt{}, err
	}
	approval, err := buildCanaryJobApproval(readback, request)
	if err != nil {
		return canaryJobReceipt{}, err
	}
	return writeCanaryJobApproval(ctx, filepath.Join(readback.runtime.overlay.Paths.StateRoot, canaryJobApprovalName), approval)
}
