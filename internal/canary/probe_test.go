package canary

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestProbeResponseDistinguishesPendingAndOneValidatedWorkflow(t *testing.T) {
	workflow := workflowFixture()
	for _, want := range []Probe{{Version: 1, Pending: true}, {Version: 1, Workflow: &workflow}} {
		document, err := MarshalProbe(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseProbe(document)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("probe roundtrip failed", err)
		}
	}
	for _, value := range []Probe{{}, {Version: 2, Pending: true}, {Version: 1}, {Version: 1, Pending: true, Workflow: &workflow}, {Version: 1, Workflow: &Workflow{}}} {
		document, _ := json.Marshal(value)
		if _, err := MarshalProbe(value); err == nil {
			t.Fatal("invalid response emitted")
		}
		if _, err := ParseProbe(document); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	document, _ := MarshalProbe(Probe{Version: 1, Workflow: &workflow})
	for _, value := range [][]byte{append(bytes.Clone(document), '\n'), append([]byte(`{"extra":1,`), document[1:]...), bytes.Repeat([]byte("x"), MaxProbeBytes+1)} {
		if _, err := ParseProbe(value); err == nil {
			t.Fatal("unbounded or noncanonical response accepted")
		}
	}
}

func TestOversizeProbeIsRefusedBeforeParsing(t *testing.T) {
	document := bytes.Repeat([]byte("x"), MaxProbeBytes+1)
	if allocations := testing.AllocsPerRun(1, func() { _, _ = ParseProbe(document) }); allocations != 0 {
		t.Fatalf("oversized probe reached parser: %v allocations", allocations)
	}
}
