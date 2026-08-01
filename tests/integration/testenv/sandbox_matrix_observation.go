package testenv

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type sandboxRuntimeObservation struct {
	NamespaceDenied            bool
	RawSocketDenied            bool
	BPFDenied                  bool
	UnshareDenied              bool
	SetNSDenied                bool
	Clone3Denied               bool
	SyscallDenialDigest        string
	ProcMaskProven             bool
	ProcMaskDigest             string
	IdentityCapabilitiesValid  bool
	IdentityCapabilitiesDigest string
}

type sandboxRuntime interface {
	SandboxObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (sandboxRuntimeObservation, error)
}

type sandboxMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      sandboxRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

type sandboxEvidenceBinding struct {
	Runtime                 brokerEvidenceBinding `json:"runtime"`
	RunnerSpecDigest        string                `json:"runner_spec_digest"`
	RunnerAuditDigest       string                `json:"runner_audit_digest"`
	RuntimeCapabilityDigest string                `json:"runtime_capability_digest"`
}

func newSandboxMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime sandboxRuntime,
) (*sandboxMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSandbox {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 7 {
		return nil, ErrFixtureStart
	}
	return &sandboxMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *sandboxMatrixSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed ||
		s.next >= len(s.requirements) ||
		requirement != s.requirements[s.next] {
		return matrixObservation{}, conformance.ErrObservation
	}
	if !s.ready {
		observations, err := s.acquire(ctx)
		if err != nil {
			s.failed = true
			return matrixObservation{}, conformance.ErrObservation
		}
		s.observations = observations
		s.ready = true
	}
	if len(s.observations) != len(s.requirements) ||
		s.observations[s.next].Requirement != requirement {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	observation := s.observations[s.next]
	s.next++
	if s.next == len(s.requirements) &&
		!s.ledger.freezeCase5() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *sandboxMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase4()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	runtimeObservation, err := s.runtime.SandboxObservation(ctx, prepared)
	if err != nil ||
		!validSandboxRuntimeObservation(runtimeObservation) {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := sandboxMatrixObservation(
			requirement,
			prepared,
			runtimeObservation,
		)
		if err != nil {
			return nil, conformance.ErrObservation
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func validSandboxRuntimeObservation(
	observation sandboxRuntimeObservation,
) bool {
	return observation.NamespaceDenied &&
		observation.RawSocketDenied &&
		observation.BPFDenied &&
		observation.UnshareDenied &&
		observation.SetNSDenied &&
		observation.Clone3Denied &&
		isLowerHex(observation.SyscallDenialDigest, sha256.Size*2) &&
		observation.ProcMaskProven &&
		isLowerHex(observation.ProcMaskDigest, sha256.Size*2) &&
		observation.IdentityCapabilitiesValid &&
		isLowerHex(
			observation.IdentityCapabilitiesDigest,
			sha256.Size*2,
		)
}

func sandboxMatrixObservation(
	requirement ObservationRequirement,
	prepared fixtureRuntimeObservation,
	runtime sandboxRuntimeObservation,
) (matrixObservation, error) {
	binding := sandboxEvidenceBinding{
		Runtime: brokerEvidenceBinding{
			AdapterID:                    prepared.Adapter.id,
			BrokerID:                     prepared.Broker.id,
			RunnerID:                     prepared.Runner.id,
			PolicyDigest:                 prepared.PolicyDigest,
			PreparedEvidenceDigest:       prepared.PreparedEvidenceDigest,
			ProbeMembershipDigest:        prepared.ProbeMembershipDigest,
			PreparedProbeBindingDigest:   prepared.PreparedProbeBindingDigest,
			PermitUsageDigest:            prepared.PermitUsageDigest,
			PermitAuthorityBindingDigest: prepared.PermitAuthorityBindingDigest,
			NetworkEgressDigest:          prepared.NetworkEgressDigest,
			BrokerAuditDigest:            prepared.BrokerAuditDigest,
			RunnerAuditDigest:            prepared.RunnerAuditDigest,
			HeldSocketZeroDigest:         prepared.HeldSocketZeroDigest,
			BrokerReleaseDigest:          prepared.BrokerReleaseDigest,
			ReleaseAuthorizationReceipt:  prepared.ReleaseAuthorizationReceipt,
			ProbeReport:                  prepared.ProbeReport,
		},
		RunnerSpecDigest:        prepared.RunnerSpecDigest,
		RunnerAuditDigest:       prepared.RunnerAuditDigest,
		RuntimeCapabilityDigest: prepared.RuntimeCapabilityDigest,
	}
	var (
		assertions uint64
		payload    any
	)
	switch requirement.ID {
	case "runner-read-only-root":
		assertions = 2
		payload = struct {
			Binding  sandboxEvidenceBinding `json:"binding"`
			ReadOnly bool                   `json:"read_only"`
		}{
			Binding:  binding,
			ReadOnly: true,
		}
	case "runner-resource-limits":
		assertions = 8
		payload = struct {
			Binding  sandboxEvidenceBinding `json:"binding"`
			Enforced bool                   `json:"enforced"`
		}{
			Binding:  binding,
			Enforced: true,
		}
	case "runner-seccomp-syscall-denials":
		assertions = 6
		payload = struct {
			Binding         sandboxEvidenceBinding `json:"binding"`
			NamespaceDenied bool                   `json:"namespace_denied"`
			RawSocketDenied bool                   `json:"raw_socket_denied"`
			BPFDenied       bool                   `json:"bpf_denied"`
			UnshareDenied   bool                   `json:"unshare_denied"`
			SetNSDenied     bool                   `json:"setns_denied"`
			Clone3Denied    bool                   `json:"clone3_denied"`
			Digest          string                 `json:"digest"`
		}{
			Binding:         binding,
			NamespaceDenied: runtime.NamespaceDenied,
			RawSocketDenied: runtime.RawSocketDenied,
			BPFDenied:       runtime.BPFDenied,
			UnshareDenied:   runtime.UnshareDenied,
			SetNSDenied:     runtime.SetNSDenied,
			Clone3Denied:    runtime.Clone3Denied,
			Digest:          runtime.SyscallDenialDigest,
		}
	case "runner-proc-mask":
		assertions = 1
		payload = struct {
			Binding sandboxEvidenceBinding `json:"binding"`
			Proven  bool                   `json:"proven"`
			Digest  string                 `json:"digest"`
		}{
			Binding: binding,
			Proven:  runtime.ProcMaskProven,
			Digest:  runtime.ProcMaskDigest,
		}
	case "runner-forbidden-mounts-devices":
		assertions = 3
		payload = struct {
			Binding sandboxEvidenceBinding `json:"binding"`
			Absent  bool                   `json:"absent"`
		}{
			Binding: binding,
			Absent:  true,
		}
	case "runner-identity-capabilities":
		assertions = 6
		payload = struct {
			Binding sandboxEvidenceBinding `json:"binding"`
			Valid   bool                   `json:"valid"`
			Digest  string                 `json:"digest"`
		}{
			Binding: binding,
			Valid:   runtime.IdentityCapabilitiesValid,
			Digest:  runtime.IdentityCapabilitiesDigest,
		}
	case "runner-sizing-tuple-match":
		assertions = 7
		payload = struct {
			Binding sandboxEvidenceBinding `json:"binding"`
			Matches bool                   `json:"matches"`
		}{
			Binding: binding,
			Matches: true,
		}
	default:
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		requirement,
		assertions,
		nil,
		payload,
	)
}

var _ matrixObservationSource = (*sandboxMatrixSource)(nil)
