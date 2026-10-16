package canary

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func workflowFixture() Workflow {
	return Workflow{Version: 1, ReportDigest: strings.Repeat("a", 64), WorkflowRunID: 42, Revision: strings.Repeat("b", 40), CheckoutHTTPS: true, SandboxVerified: true, InheritedJITAbsent: true, ListenerProcReadable: true, DecodedCredentialsReadable: true, CredentialProbeCompleted: true, Tools: RequiredTools()}
}

func TestWorkflowRecordRequiresExactCanonicalBoundedShape(t *testing.T) {
	want := workflowFixture()
	document, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseWorkflow(document)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown":                   func(b []byte) []byte { return append([]byte(`{"unknown":1,`), b[1:]...) },
		"duplicate":                 func(b []byte) []byte { return append([]byte(`{"version":1,`), b[1:]...) },
		"missing false observation": func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(`"listener_proc_readable":true,`), nil) },
		"noncanonical":              func(b []byte) []byte { return append(b, '\n') },
		"oversize":                  func([]byte) []byte { return bytes.Repeat([]byte("x"), MaxWorkflowBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseWorkflow(mutate(bytes.Clone(document))); err == nil {
				t.Fatal("invalid workflow record accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Workflow){
		"version":            func(w *Workflow) { w.Version++ },
		"report":             func(w *Workflow) { w.ReportDigest = "invalid" },
		"run":                func(w *Workflow) { w.WorkflowRunID = 0 },
		"unsafe run integer": func(w *Workflow) { w.WorkflowRunID = 9007199254740992 },
		"revision":           func(w *Workflow) { w.Revision = "invalid" },
		"checkout":           func(w *Workflow) { w.CheckoutHTTPS = false },
		"sandbox":            func(w *Workflow) { w.SandboxVerified = false },
		"inherited JIT":      func(w *Workflow) { w.InheritedJITAbsent = false },
		"unperformed probe":  func(w *Workflow) { w.CredentialProbeCompleted = false },
		"missing tool":       func(w *Workflow) { w.Tools = w.Tools[:len(w.Tools)-1] },
		"wrong tool":         func(w *Workflow) { w.Tools[0] = "other" },
		"duplicate tool":     func(w *Workflow) { w.Tools[1] = w.Tools[0] },
		"extra tool":         func(w *Workflow) { w.Tools = append(w.Tools, "other") },
	} {
		t.Run(name, func(t *testing.T) {
			w := workflowFixture()
			mutate(&w)
			b, _ := json.Marshal(w)
			if _, err := ParseWorkflow(b); err == nil {
				t.Fatal("invalid observations accepted")
			}
		})
	}
	// The amendment records exposure, rather than asserting it must be hidden.
	for _, visible := range []bool{false, true} {
		w := workflowFixture()
		w.ListenerProcReadable = visible
		w.DecodedCredentialsReadable = visible
		b, _ := json.Marshal(w)
		if _, err := ParseWorkflow(b); err != nil {
			t.Fatal(err)
		}
	}
	tools := RequiredTools()
	tools[0] = "changed"
	if RequiredTools()[0] == "changed" {
		t.Fatal("tool inventory aliases caller memory")
	}
}

func TestOversizeWorkflowIsRefusedBeforeParsing(t *testing.T) {
	document := bytes.Repeat([]byte("x"), MaxWorkflowBytes+1)
	if allocations := testing.AllocsPerRun(1, func() { _, _ = ParseWorkflow(document) }); allocations != 0 {
		t.Fatalf("oversized input reached allocating parser: %v allocations", allocations)
	}
}
