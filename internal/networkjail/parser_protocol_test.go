package networkjail

import (
	"bytes"
	"testing"
)

func TestParserPolicyAndReadinessFramesAreCanonicalAndBounded(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	policy, err := EncodeDecisionGraph(graph)
	if err != nil {
		t.Fatalf("EncodeDecisionGraph: %v", err)
	}
	var transport bytes.Buffer
	if err := WriteParserPolicy(&transport, policy); err != nil {
		t.Fatalf("WriteParserPolicy: %v", err)
	}
	decoded, err := ReadParserPolicy(&transport)
	if err != nil || !bytes.Equal(decoded, policy) {
		t.Fatalf("decoded policy mismatch: err=%v", err)
	}

	proof := ParserReadiness{
		Version:       1,
		ControlFD:     ParserControlFD,
		FilterVersion: ParserFilterVersion,
		FilterTSYNC:   true,
		AFINETErrno:   ParserSocketErrno,
		AFINET6Errno:  ParserSocketErrno,
		UnexpectedFDs: 0,
		TaskCount:     4,
		TasksVerified: 4,
	}
	transport.Reset()
	if err := WriteParserReadiness(&transport, proof); err != nil {
		t.Fatalf("WriteParserReadiness: %v", err)
	}
	got, err := ReadParserReadiness(&transport)
	if err != nil || got != proof {
		t.Fatalf("readiness=%+v err=%v", got, err)
	}
}
