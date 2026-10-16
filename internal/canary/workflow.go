// Package canary contains bounded, non-authorizing case 15 observations. None
// of these records grants acquisition, a lease, or listener release authority.
package canary

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	MaxWorkflowBytes = 4096
)

var ErrEvidence = errors.New("canary: evidence incomplete or invalid")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var requiredTools = []string{
	"actions-checkout", "actions-setup-go", "actions-setup-node",
	"actions-upload-artifact", "actions-attest", "anchore-sbom",
	"aquasecurity-trivy", "github-codeql", "actions-dependency-review", "gitleaks",
}

func RequiredTools() []string { return slices.Clone(requiredTools) }

// Workflow is emitted only by the final successful step of the reviewed canary
// workflow. It records observations without credential bytes, paths, addresses,
// repository coordinates, arbitrary messages, or tool output. Readability of
// this job's own one-job credentials is recorded, not rejected.
type Workflow struct {
	Version                    uint8    `json:"version"`
	ReportDigest               string   `json:"report_digest"`
	WorkflowRunID              uint64   `json:"workflow_run_id"`
	Revision                   string   `json:"revision"`
	CheckoutHTTPS              bool     `json:"checkout_https"`
	SandboxVerified            bool     `json:"sandbox_verified"`
	InheritedJITAbsent         bool     `json:"inherited_jit_absent"`
	ListenerProcReadable       bool     `json:"listener_proc_readable"`
	DecodedCredentialsReadable bool     `json:"decoded_credentials_readable"`
	CredentialProbeCompleted   bool     `json:"credential_probe_completed"`
	Tools                      []string `json:"tools"`
}

func ParseWorkflow(document []byte) (Workflow, error) {
	if len(document) == 0 || len(document) > MaxWorkflowBytes {
		return Workflow{}, ErrEvidence
	}
	var result Workflow
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil {
		return Workflow{}, ErrEvidence
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(document, canonical) {
		return Workflow{}, ErrEvidence
	}
	if result.Version != 1 || !digestPattern.MatchString(result.ReportDigest) || result.WorkflowRunID == 0 || result.WorkflowRunID > 9007199254740991 || !revisionPattern.MatchString(result.Revision) || !result.CheckoutHTTPS || !result.SandboxVerified || !result.InheritedJITAbsent || !result.CredentialProbeCompleted || !slices.Equal(result.Tools, requiredTools) {
		return Workflow{}, ErrEvidence
	}
	return result, nil
}
