package main

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/canary"
	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/state"
)

type canaryStatusReceipt struct {
	SchemaVersion              uint32                 `json:"schema_version"`
	ReportStatus               conformance.CaseStatus `json:"report_status"`
	ReportDigest               string                 `json:"report_digest"`
	EvidenceForReportDigest    string                 `json:"evidence_for_report_digest"`
	FleetGeneration            uint64                 `json:"fleet_generation"`
	ReadyToSeal                bool                   `json:"ready_to_seal"`
	Invalid                    bool                   `json:"invalid"`
	JITCount                   uint8                  `json:"jit_count"`
	JobCount                   uint8                  `json:"job_count"`
	JobResult                  string                 `json:"job_result"`
	Finalized                  bool                   `json:"finalized"`
	WorkflowRunID              uint64                 `json:"workflow_run_id"`
	Revision                   string                 `json:"revision"`
	PolicyDigest               string                 `json:"policy_digest"`
	ListenerProcReadable       bool                   `json:"listener_proc_readable"`
	DecodedCredentialsReadable bool                   `json:"decoded_credentials_readable"`
}
type canarySealReceipt struct {
	SchemaVersion           uint32 `json:"schema_version"`
	OriginalReportDigest    string `json:"original_report_digest"`
	ReportDigest            string `json:"report_digest"`
	Case15ObservationDigest string `json:"case15_observation_digest"`
	JobCount                uint8  `json:"job_count"`
	ToolCount               uint64 `json:"tool_count"`
}

func executeCanaryEvidence(ctx context.Context, args []string, stdout, stderr io.Writer, deps commandDependencies, sealing bool) int {
	flags, err := parseExactFlags(args, map[string]bool{"config": true})
	if err != nil || flags["config"] == "" || (!sealing && deps.CanaryStatus == nil) || (sealing && deps.CanarySeal == nil) {
		return commandUsage(stderr)
	}
	if !deps.IsRoot() {
		return commandFailure(stderr, "canary evidence")
	}
	callCtx, cancel := context.WithTimeout(ctx, deps.AdminTimeout)
	defer cancel()
	var receipt any
	if sealing {
		receipt, err = deps.CanarySeal(callCtx, flags["config"])
	} else {
		receipt, err = deps.CanaryStatus(callCtx, flags["config"])
	}
	if err != nil {
		return commandFailure(stderr, "canary evidence")
	}
	if json.NewEncoder(stdout).Encode(receipt) != nil {
		return commandFailure(stderr, "canary evidence")
	}
	return 0
}

func buildCanaryStatus(report conformance.Report, record canary.Record) canaryStatusReceipt {
	return canaryStatusReceipt{SchemaVersion: 1, ReportStatus: report.Status(), ReportDigest: report.Digest(), EvidenceForReportDigest: record.ReportDigest, FleetGeneration: record.FleetGeneration,
		ReadyToSeal: report.Status() == conformance.StatusPending && record.Ready(report.Digest(), report.Binding().Digest(), report.Binding().FleetGeneration()) == nil,
		Invalid:     record.Invalid, JITCount: record.JITCount, JobCount: record.JobCount, JobResult: record.JobResult, Finalized: record.Finalized, WorkflowRunID: record.Workflow.WorkflowRunID, Revision: record.Workflow.Revision, PolicyDigest: record.PolicyDigest, ListenerProcReadable: record.Workflow.ListenerProcReadable, DecodedCredentialsReadable: record.Workflow.DecodedCredentialsReadable}
}

type canaryReadback struct {
	runtime  productionRuntime
	report   conformance.Report
	document []byte
	record   canary.Record
}

func readCanaryReadback(ctx context.Context, configPath string, sealing bool) (canaryReadback, error) {
	overlay, err := readProductionOverlay(configPath)
	if err != nil {
		return canaryReadback{}, errCommandUnavailable
	}
	runtime, err := readProductionRuntime(ctx, configPath, overlay.Paths.DatabasePath)
	if err != nil {
		return canaryReadback{}, errCommandUnavailable
	}
	document, err := readPinnedRootFile(filepath.Join(runtime.overlay.Paths.StateRoot, conformanceReportName), 0600, maxConformanceReportBytes)
	if err != nil {
		return canaryReadback{}, errCommandUnavailable
	}
	report, err := conformance.ParseReport(document, maxConformanceReportBytes)
	if err != nil || !reportMatchesCanaryRuntime(report, runtime) {
		return canaryReadback{}, errCommandUnavailable
	}
	if _, err := conformance.NewAcquisitionGate(report); err != nil {
		return canaryReadback{}, errCommandUnavailable
	}
	store, err := state.OpenReadOnlyWithHistoryLimits(runtime.overlay.Paths.DatabasePath, runtime.history)
	if err != nil {
		return canaryReadback{}, errCommandUnavailable
	}
	var record canary.Record
	if sealing {
		record, err = store.CanarySealSnapshot(ctx)
	} else {
		record, err = store.CanaryEvidence(ctx)
	}
	closeErr := store.Close()
	if err != nil || closeErr != nil {
		return canaryReadback{}, errCommandUnavailable
	}
	return canaryReadback{runtime: runtime, report: report, document: document, record: record}, nil
}
func productionCanaryStatus(ctx context.Context, configPath string) (canaryStatusReceipt, error) {
	readback, err := readCanaryReadback(ctx, configPath, false)
	if err != nil {
		return canaryStatusReceipt{}, err
	}
	return buildCanaryStatus(readback.report, readback.record), nil
}
func productionCanarySeal(ctx context.Context, configPath string) (canarySealReceipt, error) {
	overlay, err := readProductionOverlay(configPath)
	if err != nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	return sealCanaryReport(ctx, overlay.Paths.DatabasePath, func(ctx context.Context) (canaryReadback, error) {
		return readCanaryReadback(ctx, configPath, true)
	}, replaceCanaryReport)
}

func sealCanaryReport(ctx context.Context, databasePath string, read func(context.Context) (canaryReadback, error), replace func(string, []byte, []byte, uint32) error) (receipt canarySealReceipt, resultErr error) {
	if ctx == nil || ctx.Err() != nil || !canonicalAbsolutePath(databasePath) || read == nil || replace == nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	ownership, err := acquireFileOwnership(databasePath + ".owner.lock")
	if err != nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	defer func() {
		if ownership.Close() != nil {
			receipt, resultErr = canarySealReceipt{}, errCommandUnavailable
		}
	}()
	readback, err := read(ctx)
	if err != nil || readback.runtime.overlay.Paths.DatabasePath != databasePath || ownership.Validate() != nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	completed, err := completeCanaryReport(readback.report, readback.record)
	if err != nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	document, err := conformance.MarshalReport(completed)
	if err != nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	path := filepath.Join(readback.runtime.overlay.Paths.StateRoot, conformanceReportName)
	if ctx.Err() != nil || ownership.Validate() != nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	if err := replace(path, readback.document, document, uint32(readback.runtime.overlay.Target.ExpectedEUID)); err != nil {
		return canarySealReceipt{}, errCommandUnavailable
	}
	return canarySealReceipt{SchemaVersion: 1, OriginalReportDigest: readback.report.Digest(), ReportDigest: completed.Digest(), Case15ObservationDigest: completed.Cases()[14].ObservationDigest(), JobCount: readback.record.JobCount, ToolCount: uint64(len(readback.record.Workflow.Tools))}, nil
}
