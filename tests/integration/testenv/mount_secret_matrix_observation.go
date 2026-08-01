package testenv

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type mountSecretRuntimeObservation struct {
	MountTopologyProven         bool
	MountTopologyDigest         string
	OneShotMountAbsenceProven   bool
	OneShotMountAbsenceDigest   string
	ControllerSQLiteInvisible   bool
	ControllerSQLiteDigest      string
	HostControlInvisible        bool
	HostControlDigest           string
	RuntimeSecretScanClean      bool
	RuntimeSecretScanDigest     string
	SyntheticTokenAbsent        bool
	SyntheticTokenAbsenceDigest string
}

type mountSecretRuntime interface {
	MountSecretObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (mountSecretRuntimeObservation, error)
}

type mountSecretMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      mountSecretRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

type mountEvidenceBinding struct {
	Runtime                 brokerEvidenceBinding `json:"runtime"`
	AdapterSpecDigest       string                `json:"adapter_spec_digest"`
	BrokerSpecDigest        string                `json:"broker_spec_digest"`
	RunnerSpecDigest        string                `json:"runner_spec_digest"`
	VerifierSpecDigest      string                `json:"verifier_spec_digest"`
	PolicyApplicationDigest string                `json:"policy_application_digest"`
	HelperCapabilityDigest  string                `json:"helper_capability_digest"`
	RuntimeCapabilityDigest string                `json:"runtime_capability_digest"`
	MountTopologyDigest     string                `json:"mount_topology_digest"`
	OneShotAbsenceDigest    string                `json:"one_shot_absence_digest"`
}

func newMountSecretMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime mountSecretRuntime,
) (*mountSecretMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case ==
			conformance.CaseMountAndSecretIsolation {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 6 {
		return nil, ErrFixtureStart
	}
	return &mountSecretMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *mountSecretMatrixSource) Observe(
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
		!s.ledger.freezeCase4() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *mountSecretMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase3()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	runtimeObservation, err := s.runtime.MountSecretObservation(
		ctx,
		prepared,
	)
	if err != nil ||
		!validMountSecretRuntimeObservation(runtimeObservation) {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := mountSecretMatrixObservation(
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

func validMountSecretRuntimeObservation(
	observation mountSecretRuntimeObservation,
) bool {
	return observation.MountTopologyProven &&
		isLowerHex(observation.MountTopologyDigest, sha256.Size*2) &&
		observation.OneShotMountAbsenceProven &&
		isLowerHex(
			observation.OneShotMountAbsenceDigest,
			sha256.Size*2,
		) &&
		observation.ControllerSQLiteInvisible &&
		isLowerHex(
			observation.ControllerSQLiteDigest,
			sha256.Size*2,
		) &&
		observation.HostControlInvisible &&
		isLowerHex(observation.HostControlDigest, sha256.Size*2) &&
		observation.RuntimeSecretScanClean &&
		isLowerHex(
			observation.RuntimeSecretScanDigest,
			sha256.Size*2,
		) &&
		observation.SyntheticTokenAbsent &&
		isLowerHex(
			observation.SyntheticTokenAbsenceDigest,
			sha256.Size*2,
		)
}

func mountSecretMatrixObservation(
	requirement ObservationRequirement,
	prepared fixtureRuntimeObservation,
	runtime mountSecretRuntimeObservation,
) (matrixObservation, error) {
	binding := mountEvidenceBinding{
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
		AdapterSpecDigest:       prepared.AdapterSpecDigest,
		BrokerSpecDigest:        prepared.BrokerSpecDigest,
		RunnerSpecDigest:        prepared.RunnerSpecDigest,
		VerifierSpecDigest:      prepared.VerifierSpecDigest,
		PolicyApplicationDigest: prepared.PolicyApplicationDigest,
		HelperCapabilityDigest:  prepared.HelperCapabilityDigest,
		RuntimeCapabilityDigest: prepared.RuntimeCapabilityDigest,
		MountTopologyDigest:     runtime.MountTopologyDigest,
		OneShotAbsenceDigest:    runtime.OneShotMountAbsenceDigest,
	}
	var (
		assertions uint64
		payload    any
	)
	switch requirement.ID {
	case "relay-mount-visibility":
		assertions = 8
		payload = struct {
			Binding              mountEvidenceBinding `json:"binding"`
			MountTopologyProven  bool                 `json:"mount_topology_proven"`
			OneShotAbsenceProven bool                 `json:"one_shot_absence_proven"`
			RelayVisibilityClass string               `json:"relay_visibility_class"`
		}{
			Binding:              binding,
			MountTopologyProven:  runtime.MountTopologyProven,
			OneShotAbsenceProven: runtime.OneShotMountAbsenceProven,
			RelayVisibilityClass: "adapter-ro-broker-rw",
		}
	case "authority-mount-visibility":
		assertions = 7
		payload = struct {
			Binding              mountEvidenceBinding `json:"binding"`
			MountTopologyProven  bool                 `json:"mount_topology_proven"`
			OneShotAbsenceProven bool                 `json:"one_shot_absence_proven"`
			AuthorityAccessClass string               `json:"authority_access_class"`
		}{
			Binding:              binding,
			MountTopologyProven:  runtime.MountTopologyProven,
			OneShotAbsenceProven: runtime.OneShotMountAbsenceProven,
			AuthorityAccessClass: "broker-ro-only",
		}
	case "controller-sqlite-invisible":
		assertions = 1
		payload = struct {
			Binding   mountEvidenceBinding `json:"binding"`
			Invisible bool                 `json:"invisible"`
			Digest    string               `json:"digest"`
		}{
			Binding:   binding,
			Invisible: runtime.ControllerSQLiteInvisible,
			Digest:    runtime.ControllerSQLiteDigest,
		}
	case "host-control-invisible":
		assertions = 9
		payload = struct {
			Binding              mountEvidenceBinding `json:"binding"`
			Invisible            bool                 `json:"invisible"`
			Digest               string               `json:"digest"`
			OneShotAbsenceProven bool                 `json:"one_shot_absence_proven"`
		}{
			Binding:              binding,
			Invisible:            runtime.HostControlInvisible,
			Digest:               runtime.HostControlDigest,
			OneShotAbsenceProven: runtime.OneShotMountAbsenceProven,
		}
	case "runtime-secret-scan":
		assertions = 5
		payload = struct {
			Binding mountEvidenceBinding `json:"binding"`
			Clean   bool                 `json:"clean"`
			Digest  string               `json:"digest"`
		}{
			Binding: binding,
			Clean:   runtime.RuntimeSecretScanClean,
			Digest:  runtime.RuntimeSecretScanDigest,
		}
	case "synthetic-token-absence":
		assertions = 2
		payload = struct {
			Binding mountEvidenceBinding `json:"binding"`
			Absent  bool                 `json:"absent"`
			Digest  string               `json:"digest"`
		}{
			Binding: binding,
			Absent:  runtime.SyntheticTokenAbsent,
			Digest:  runtime.SyntheticTokenAbsenceDigest,
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

var _ matrixObservationSource = (*mountSecretMatrixSource)(nil)
