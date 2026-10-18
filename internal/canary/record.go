package canary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

const MaxRecordBytes = 8192

// Record is a singleton, non-authorizing evidence journal for one report run.
// Counts saturate at two; extra work invalidates the one-job proof, but this
// record is never consulted to decide whether acquisition is authorized.
type Record struct {
	WorkflowRunID     uint64   `json:"workflow_run_id"`
	Version           uint8    `json:"version"`
	ReportDigest      string   `json:"report_digest"`
	BindingDigest     string   `json:"binding_digest"`
	FleetGeneration   uint64   `json:"fleet_generation"`
	AssignmentDigest  string   `json:"assignment_digest"`
	AcquisitionDigest string   `json:"acquisition_digest"`
	PermitDigest      string   `json:"permit_digest"`
	PolicyDigest      string   `json:"policy_digest"`
	JITCount          uint8    `json:"jit_count"`
	JobCount          uint8    `json:"job_count"`
	DisableUpdate     bool     `json:"disable_update"`
	SingleNameLabel   bool     `json:"single_name_label"`
	CanaryCapacityOne bool     `json:"canary_capacity_one"`
	ListenerReleased  bool     `json:"listener_released"`
	JobResult         string   `json:"job_result"`
	Workflow          Workflow `json:"workflow"`
	UpstreamAbsent    bool     `json:"upstream_absent"`
	RuntimeAbsent     bool     `json:"runtime_absent"`
	Finalized         bool     `json:"finalized"`
	Invalid           bool     `json:"invalid"`
}

func ParseRecord(document []byte) (Record, error) {
	if len(document) == 0 || len(document) > MaxRecordBytes {
		return Record{}, ErrEvidence
	}
	var result Record
	d := json.NewDecoder(bytes.NewReader(document))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil {
		return Record{}, ErrEvidence
	}
	b, err := json.Marshal(result)
	if err != nil || !bytes.Equal(b, document) || result.Version != 1 || !digestPattern.MatchString(result.ReportDigest) || !digestPattern.MatchString(result.BindingDigest) || result.FleetGeneration == 0 || result.JITCount > 2 || result.JobCount > 2 {
		return Record{}, ErrEvidence
	}
	for _, digest := range []string{result.AssignmentDigest, result.AcquisitionDigest, result.PermitDigest, result.PolicyDigest} {
		if digest != "" && !digestPattern.MatchString(digest) {
			return Record{}, ErrEvidence
		}
	}
	switch result.JobResult {
	case "", "success", "failure", "canceled", "skipped", "unknown":
	default:
		return Record{}, ErrEvidence
	}
	if !reflect.DeepEqual(result.Workflow, Workflow{}) {
		b, err := json.Marshal(result.Workflow)
		if err != nil {
			return Record{}, ErrEvidence
		}
		if _, err := ParseWorkflow(b); err != nil {
			return Record{}, err
		}
	}
	return result, nil
}

func (r Record) Ready(reportDigest, bindingDigest string, generation uint64) error {
	b, err := json.Marshal(r)
	if err != nil {
		return ErrEvidence
	}
	if _, err := ParseRecord(b); err != nil {
		return err
	}
	if r.ReportDigest != reportDigest || r.BindingDigest != bindingDigest || r.FleetGeneration != generation || r.Invalid || r.AssignmentDigest == "" || r.AcquisitionDigest == "" || r.PermitDigest == "" || r.PolicyDigest == "" || r.JITCount != 1 || r.JobCount != 1 || !r.DisableUpdate || !r.SingleNameLabel || !r.CanaryCapacityOne || !r.ListenerReleased || r.JobResult != "success" || !r.UpstreamAbsent || !r.RuntimeAbsent || !r.Finalized || r.Workflow.ReportDigest != r.ReportDigest || r.Workflow.WorkflowRunID != r.WorkflowRunID {
		return ErrEvidence
	}
	return nil
}

func (r Record) Digest() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", ErrEvidence
	}
	if _, err := ParseRecord(b); err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("portable-ghar.canary-evidence.v1\x00"), b...))
	return hex.EncodeToString(digest[:]), nil
}
