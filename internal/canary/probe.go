package canary

import (
	"bytes"
	"encoding/json"
)

const MaxProbeBytes = MaxWorkflowBytes + 128

// Probe is the closed result of reading the job's fixed Unix socket. Pending means
// no result is available yet. It neither creates nor consumes authority.
type Probe struct {
	Version  uint8     `json:"version"`
	Pending  bool      `json:"pending"`
	Workflow *Workflow `json:"workflow"`
}

func MarshalProbe(probe Probe) ([]byte, error) {
	if probe.Version != 1 || probe.Pending != (probe.Workflow == nil) {
		return nil, ErrEvidence
	}
	if probe.Workflow != nil {
		document, err := json.Marshal(probe.Workflow)
		if err != nil {
			return nil, ErrEvidence
		}
		if _, err := ParseWorkflow(document); err != nil {
			return nil, err
		}
	}
	return json.Marshal(probe)
}
func ParseProbe(document []byte) (Probe, error) {
	if len(document) == 0 || len(document) > MaxProbeBytes {
		return Probe{}, ErrEvidence
	}
	var probe Probe
	if json.Unmarshal(document, &probe) != nil {
		return Probe{}, ErrEvidence
	}
	canonical, err := MarshalProbe(probe)
	if err != nil || !bytes.Equal(canonical, document) {
		return Probe{}, ErrEvidence
	}
	return probe, nil
}
