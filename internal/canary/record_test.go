package canary

import (
	"encoding/json"
	"strings"
	"testing"
)

func completeRecord() Record {
	return Record{Version: 1, ReportDigest: strings.Repeat("a", 64), BindingDigest: strings.Repeat("c", 64), FleetGeneration: 7, AssignmentDigest: strings.Repeat("d", 64), AcquisitionDigest: strings.Repeat("e", 64), PermitDigest: strings.Repeat("f", 64), PolicyDigest: strings.Repeat("1", 64), WorkflowRunID: 42, JITCount: 1, JobCount: 1, DisableUpdate: true, SingleNameLabel: true, CanaryCapacityOne: true, ListenerReleased: true, JobResult: "success", Workflow: workflowFixture(), UpstreamAbsent: true, RuntimeAbsent: true, Finalized: true}
}

func TestRecordReadyRequiresEveryIndependentObservationAndBinding(t *testing.T) {
	good := completeRecord()
	if err := good.Ready(good.ReportDigest, good.BindingDigest, 7); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Record){
		"schema":             func(r *Record) { r.Version++ },
		"report":             func(r *Record) { r.ReportDigest = strings.Repeat("2", 64); r.Workflow.ReportDigest = r.ReportDigest },
		"binding":            func(r *Record) { r.BindingDigest = strings.Repeat("2", 64) },
		"generation":         func(r *Record) { r.FleetGeneration++ },
		"assignment":         func(r *Record) { r.AssignmentDigest = "" },
		"acquisition":        func(r *Record) { r.AcquisitionDigest = "" },
		"permit":             func(r *Record) { r.PermitDigest = "" },
		"policy":             func(r *Record) { r.PolicyDigest = "" },
		"no JIT":             func(r *Record) { r.JITCount = 0 },
		"extra JIT":          func(r *Record) { r.JITCount = 2 },
		"no job":             func(r *Record) { r.JobCount = 0 },
		"extra job":          func(r *Record) { r.JobCount = 2 },
		"update enabled":     func(r *Record) { r.DisableUpdate = false },
		"label":              func(r *Record) { r.SingleNameLabel = false },
		"capacity or mode":   func(r *Record) { r.CanaryCapacityOne = false },
		"listener":           func(r *Record) { r.ListenerReleased = false },
		"failed job":         func(r *Record) { r.JobResult = "failure" },
		"no workflow":        func(r *Record) { r.Workflow = Workflow{} },
		"workflow run":       func(r *Record) { r.Workflow.WorkflowRunID++ },
		"workflow binding":   func(r *Record) { r.Workflow.ReportDigest = strings.Repeat("2", 64) },
		"deregistration":     func(r *Record) { r.UpstreamAbsent = false },
		"runtime":            func(r *Record) { r.RuntimeAbsent = false },
		"capacity reclaimed": func(r *Record) { r.Finalized = false },
		"invalidated":        func(r *Record) { r.Invalid = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := completeRecord()
			mutate(&r)
			if r.Ready(good.ReportDigest, good.BindingDigest, 7) == nil {
				t.Fatal("missing or mismatched evidence accepted")
			}
		})
	}
	first, err := good.Digest()
	if err != nil {
		t.Fatal(err)
	}
	good.Workflow.ListenerProcReadable = false
	second, err := good.Digest()
	if err != nil || first == second {
		t.Fatal("exposure measurement not committed")
	}
}

func TestRecordEncodingIsBoundedCanonicalAndRejectsUnknownFields(t *testing.T) {
	record := completeRecord()
	b, _ := json.Marshal(record)
	parsed, err := ParseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Ready(record.ReportDigest, record.BindingDigest, 7) != nil {
		t.Fatal("roundtrip changed evidence")
	}
	for _, b := range [][]byte{append(b, '\n'), append([]byte(`{"other":1,`), b[1:]...), []byte("null"), []byte(strings.Repeat("x", MaxRecordBytes+1))} {
		if _, err := ParseRecord(b); err == nil {
			t.Fatal("invalid record accepted")
		}
	}
}

func TestRecordParserRejectsCorruptPersistedFields(t *testing.T) {
	for name, change := range map[string]func(*Record){
		"version":            func(r *Record) { r.Version = 2 },
		"report":             func(r *Record) { r.ReportDigest = "invalid" },
		"binding":            func(r *Record) { r.BindingDigest = "invalid" },
		"generation":         func(r *Record) { r.FleetGeneration = 0 },
		"JIT overflow":       func(r *Record) { r.JITCount = 3 },
		"job overflow":       func(r *Record) { r.JobCount = 3 },
		"assignment":         func(r *Record) { r.AssignmentDigest = "invalid" },
		"acquisition":        func(r *Record) { r.AcquisitionDigest = "invalid" },
		"permit":             func(r *Record) { r.PermitDigest = "invalid" },
		"policy":             func(r *Record) { r.PolicyDigest = "invalid" },
		"arbitrary result":   func(r *Record) { r.JobResult = "arbitrary" },
		"arbitrary workflow": func(r *Record) { r.Workflow.Revision = "arbitrary" },
	} {
		t.Run(name, func(t *testing.T) {
			r := completeRecord()
			change(&r)
			b, _ := json.Marshal(r)
			if _, err := ParseRecord(b); err == nil {
				t.Fatal("corrupt persisted record accepted")
			}
			if _, err := r.Digest(); err == nil {
				t.Fatal("corrupt persisted record digested")
			}
		})
	}
}

func TestOversizePersistedRecordIsRefusedBeforeParsing(t *testing.T) {
	document := []byte(strings.Repeat("x", MaxRecordBytes+1))
	if allocations := testing.AllocsPerRun(1, func() { _, _ = ParseRecord(document) }); allocations != 0 {
		t.Fatalf("oversized record reached allocating parser: %v allocations", allocations)
	}
}
