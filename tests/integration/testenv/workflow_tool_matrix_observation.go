package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const workflowToolProbeIdentityDomain = "portable-ghar.task11.workflow-tool-probe.v1\x00"

type workflowToolAction string

const (
	workflowToolCheckout         workflowToolAction = "checkout"
	workflowToolSetupGo          workflowToolAction = "setup-go"
	workflowToolSetupNode        workflowToolAction = "setup-node"
	workflowToolUploadArtifact   workflowToolAction = "upload-artifact"
	workflowToolAttest           workflowToolAction = "attest"
	workflowToolAnchoreSBOM      workflowToolAction = "anchore-sbom"
	workflowToolTrivy            workflowToolAction = "trivy"
	workflowToolCodeQL           workflowToolAction = "codeql"
	workflowToolDependencyReview workflowToolAction = "dependency-review"
	workflowToolGitleaks         workflowToolAction = "gitleaks"
)

type workflowToolCleanupLease struct {
	ProbeID        string
	Name           string
	IdentityDigest string
}

type workflowToolProbeSpec struct {
	ProbeID            string
	Action             workflowToolAction
	Name               string
	ImageReference     string
	ImageDigest        string
	User               string
	NetworkContainerID string
	Seccomp            hostruntime.SeccompBinding
	Limits             workflowToolProbeLimits
}

type workflowToolExecution struct {
	ProbeID          string
	Status           WorkflowToolStatus
	OutputBytes      uint64
	OutputDigest     string
	InvocationDigest string
}

type workflowToolProbeRuntime interface {
	RegisterWorkflowToolCleanup(
		context.Context,
		workflowToolCleanupLease,
	) (string, error)
	RunWorkflowTool(
		context.Context,
		workflowToolProbeSpec,
	) (workflowToolExecution, error)
	ProveWorkflowToolAbsent(
		context.Context,
		workflowToolCleanupLease,
	) (string, error)
}

type workflowToolMatrixSource struct {
	ledger      *preparedRuntimeEvidenceLedger
	bindings    []WorkflowToolBinding
	users       []string
	limits      workflowToolProbeLimits
	seccomp     hostruntime.SeccompBinding
	runtime     workflowToolProbeRuntime
	requirement ObservationRequirement

	mu          sync.Mutex
	observation matrixObservation
	ready       bool
	consumed    bool
	failed      bool
}

type workflowToolProbeEvidence struct {
	ProbeID                   string                  `json:"probe_id"`
	Action                    workflowToolAction      `json:"action"`
	Name                      string                  `json:"name"`
	ImageReference            string                  `json:"image_reference"`
	ImageDigest               string                  `json:"image_digest"`
	User                      string                  `json:"user"`
	NetworkContainerID        string                  `json:"network_container_id"`
	SeccompPath               string                  `json:"seccomp_path"`
	SeccompDigest             string                  `json:"seccomp_digest"`
	Limits                    workflowToolProbeLimits `json:"limits"`
	Status                    WorkflowToolStatus      `json:"status"`
	OutputBytes               uint64                  `json:"output_bytes"`
	OutputDigest              string                  `json:"output_digest"`
	InvocationDigest          string                  `json:"invocation_digest"`
	CleanupRegistrationDigest string                  `json:"cleanup_registration_digest"`
	ExactNameAbsenceDigest    string                  `json:"exact_name_absence_digest"`
}

func newWorkflowToolMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	bindings []WorkflowToolBinding,
	users []string,
	limits workflowToolProbeLimits,
	seccomp hostruntime.SeccompBinding,
	runtime workflowToolProbeRuntime,
) (*workflowToolMatrixSource, error) {
	if ledger == nil ||
		runtime == nil ||
		!validWorkflowToolSourceBindings(bindings, users) ||
		!validWorkflowToolProbeLimits(limits) ||
		!validAbsolutePath(seccomp.Path) ||
		!isLowerHex(seccomp.SHA256, sha256.Size*2) {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseProxyToolCompatibility {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 1 {
		return nil, ErrFixtureStart
	}
	return &workflowToolMatrixSource{
		ledger:      ledger,
		bindings:    append([]WorkflowToolBinding(nil), bindings...),
		users:       append([]string(nil), users...),
		limits:      limits,
		seccomp:     seccomp,
		runtime:     runtime,
		requirement: requirements[0],
	}, nil
}

func (s *workflowToolMatrixSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.consumed || requirement != s.requirement {
		return matrixObservation{}, conformance.ErrObservation
	}
	if !s.ready {
		observation, err := s.acquire(ctx)
		if err != nil {
			s.failed = true
			return matrixObservation{}, conformance.ErrObservation
		}
		s.observation = observation
		s.ready = true
	}
	if s.observation.Requirement != requirement ||
		!s.ledger.freezeCase10() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	s.consumed = true
	return s.observation, nil
}

func (s *workflowToolMatrixSource) acquire(
	ctx context.Context,
) (matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase9()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return matrixObservation{}, conformance.ErrObservation
	}
	results := make([]WorkflowToolResult, 0, len(s.bindings))
	evidence := make(
		[]workflowToolProbeEvidence,
		0,
		len(s.bindings),
	)
	var totalOutputBytes uint64
	for index, binding := range s.bindings {
		if ctx.Err() != nil {
			return matrixObservation{}, conformance.ErrObservation
		}
		action, ok := workflowToolActionFor(binding.ProbeID)
		if !ok {
			return matrixObservation{}, conformance.ErrObservation
		}
		lease, ok := workflowToolLeaseFor(
			prepared.Runner.id,
			binding.ProbeID,
		)
		if !ok {
			return matrixObservation{}, conformance.ErrObservation
		}
		spec := workflowToolProbeSpec{
			ProbeID:            binding.ProbeID,
			Action:             action,
			Name:               lease.Name,
			ImageReference:     binding.ImageReference,
			ImageDigest:        binding.ImageDigest,
			User:               s.users[index],
			NetworkContainerID: prepared.Runner.id,
			Seccomp:            s.seccomp,
			Limits:             s.limits,
		}
		if !validWorkflowToolProbeSpec(spec, binding, lease) {
			return matrixObservation{}, conformance.ErrObservation
		}
		registration, err := s.runtime.RegisterWorkflowToolCleanup(
			ctx,
			lease,
		)
		if err != nil ||
			!isLowerHex(registration, sha256.Size*2) {
			return matrixObservation{}, conformance.ErrObservation
		}
		execution, err := s.runtime.RunWorkflowTool(ctx, spec)
		if err != nil ||
			!validWorkflowToolExecution(
				execution,
				binding.ProbeID,
				s.requirement.MaxBytes,
			) {
			return matrixObservation{}, conformance.ErrObservation
		}
		absence, err := s.runtime.ProveWorkflowToolAbsent(ctx, lease)
		if err != nil || !isLowerHex(absence, sha256.Size*2) {
			return matrixObservation{}, conformance.ErrObservation
		}
		if execution.OutputBytes >
			s.requirement.MaxBytes-totalOutputBytes {
			return matrixObservation{}, conformance.ErrObservation
		}
		totalOutputBytes += execution.OutputBytes
		results = append(results, WorkflowToolResult{
			ProbeID: execution.ProbeID,
			Status:  execution.Status,
		})
		evidence = append(evidence, workflowToolProbeEvidence{
			ProbeID:                   spec.ProbeID,
			Action:                    spec.Action,
			Name:                      spec.Name,
			ImageReference:            spec.ImageReference,
			ImageDigest:               spec.ImageDigest,
			User:                      spec.User,
			NetworkContainerID:        spec.NetworkContainerID,
			SeccompPath:               spec.Seccomp.Path,
			SeccompDigest:             spec.Seccomp.SHA256,
			Limits:                    spec.Limits,
			Status:                    execution.Status,
			OutputBytes:               execution.OutputBytes,
			OutputDigest:              execution.OutputDigest,
			InvocationDigest:          execution.InvocationDigest,
			CleanupRegistrationDigest: registration,
			ExactNameAbsenceDigest:    absence,
		})
	}
	if ValidateWorkflowToolResults(results) != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	assertions, ok := checkedWorkflowToolAssertions(uint64(len(evidence)))
	if !ok {
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		s.requirement,
		assertions,
		[]conformance.MeasurementInput{{
			Name:  "tool_count",
			Value: uint64(len(evidence)),
			Unit:  "count",
		}},
		struct {
			PreparedEvidenceDigest string                      `json:"prepared_evidence_digest"`
			TotalOutputBytes       uint64                      `json:"total_output_bytes"`
			ClosedPolicy           string                      `json:"closed_policy"`
			Probes                 []workflowToolProbeEvidence `json:"probes"`
		}{
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
			TotalOutputBytes:       totalOutputBytes,
			ClosedPolicy:           "workflow-tool-probe-v1",
			Probes:                 evidence,
		},
	)
}

func workflowToolActionFor(
	probeID string,
) (workflowToolAction, bool) {
	switch probeID {
	case "actions-checkout":
		return workflowToolCheckout, true
	case "actions-setup-go":
		return workflowToolSetupGo, true
	case "actions-setup-node":
		return workflowToolSetupNode, true
	case "actions-upload-artifact":
		return workflowToolUploadArtifact, true
	case "actions-attest":
		return workflowToolAttest, true
	case "anchore-sbom":
		return workflowToolAnchoreSBOM, true
	case "aquasecurity-trivy":
		return workflowToolTrivy, true
	case "github-codeql":
		return workflowToolCodeQL, true
	case "actions-dependency-review":
		return workflowToolDependencyReview, true
	case "gitleaks":
		return workflowToolGitleaks, true
	default:
		return "", false
	}
}

func workflowToolLeaseFor(
	runnerID string,
	probeID string,
) (workflowToolCleanupLease, bool) {
	if !isLowerHex(runnerID, sha256.Size*2) {
		return workflowToolCleanupLease{}, false
	}
	if _, ok := workflowToolActionFor(probeID); !ok {
		return workflowToolCleanupLease{}, false
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(workflowToolProbeIdentityDomain))
	_, _ = digest.Write([]byte(runnerID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(probeID))
	identity := hex.EncodeToString(digest.Sum(nil))
	return workflowToolCleanupLease{
		ProbeID:        probeID,
		Name:           "pghar-wft-" + identity,
		IdentityDigest: identity,
	}, true
}

func validWorkflowToolSourceBindings(
	bindings []WorkflowToolBinding,
	users []string,
) bool {
	if len(bindings) != len(requiredWorkflowToolProbeIDs) ||
		len(users) != len(bindings) {
		return false
	}
	references := make(map[string]struct{}, len(bindings))
	digests := make(map[string]struct{}, len(bindings))
	for index, expected := range requiredWorkflowToolProbeIDs {
		binding := bindings[index]
		uid, _, userOK := parseStaticNumericUser(users[index])
		if binding.ProbeID != expected ||
			!validImmutableImageReference(
				binding.ImageReference,
				binding.ImageDigest,
			) ||
			!userOK || uid == 0 {
			return false
		}
		if _, duplicate := references[binding.ImageReference]; duplicate {
			return false
		}
		if _, duplicate := digests[binding.ImageDigest]; duplicate {
			return false
		}
		references[binding.ImageReference] = struct{}{}
		digests[binding.ImageDigest] = struct{}{}
	}
	return true
}

func validWorkflowToolProbeLimits(
	limits workflowToolProbeLimits,
) bool {
	return limits.MilliCPU > 0 &&
		limits.MilliCPU <= maxCompositionDockerCPU &&
		limits.MemoryBytes > 0 &&
		limits.MemoryBytes <= uint64(math.MaxInt64) &&
		limits.MemorySwapBytes >= limits.MemoryBytes &&
		limits.MemorySwapBytes <= uint64(math.MaxInt64) &&
		limits.PIDs > 0 &&
		limits.PIDs <= uint64(math.MaxInt64) &&
		limits.FileDescriptors > 0 &&
		limits.FileDescriptors <= uint64(math.MaxInt64) &&
		limits.WorkTmpfsBytes > 0 &&
		limits.ScratchBytes > 0
}

func validWorkflowToolProbeSpec(
	spec workflowToolProbeSpec,
	binding WorkflowToolBinding,
	lease workflowToolCleanupLease,
) bool {
	action, actionOK := workflowToolActionFor(spec.ProbeID)
	uid, _, userOK := parseStaticNumericUser(spec.User)
	return actionOK &&
		spec.ProbeID == binding.ProbeID &&
		spec.Action == action &&
		spec.Name == lease.Name &&
		lease.ProbeID == spec.ProbeID &&
		isLowerHex(lease.IdentityDigest, sha256.Size*2) &&
		spec.ImageReference == binding.ImageReference &&
		spec.ImageDigest == binding.ImageDigest &&
		userOK && uid != 0 &&
		isLowerHex(spec.NetworkContainerID, sha256.Size*2) &&
		validAbsolutePath(spec.Seccomp.Path) &&
		isLowerHex(spec.Seccomp.SHA256, sha256.Size*2) &&
		validWorkflowToolProbeLimits(spec.Limits)
}

func validWorkflowToolExecution(
	execution workflowToolExecution,
	probeID string,
	maxBytes uint64,
) bool {
	validStatus := execution.Status == WorkflowToolSupported ||
		execution.Status == WorkflowToolUnsupported ||
		execution.Status == WorkflowToolFailed
	return execution.ProbeID == probeID &&
		validStatus &&
		execution.OutputBytes > 0 &&
		execution.OutputBytes <= maxBytes &&
		isLowerHex(execution.OutputDigest, sha256.Size*2) &&
		isLowerHex(execution.InvocationDigest, sha256.Size*2)
}

func checkedWorkflowToolAssertions(
	probes uint64,
) (uint64, bool) {
	const assertionsPerProbe = uint64(9)
	if probes == 0 ||
		probes > (math.MaxUint64-1)/assertionsPerProbe {
		return 0, false
	}
	return probes*assertionsPerProbe + 1, true
}

var _ matrixObservationSource = (*workflowToolMatrixSource)(nil)
