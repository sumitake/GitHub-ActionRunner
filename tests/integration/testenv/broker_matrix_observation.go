package testenv

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type brokerCaseRuntimeObservation struct {
	DirectProtocolsDenied     bool
	DirectProtocolsDigest     string
	PlaintextHTTPDenied       bool
	PlaintextHTTPDigest       string
	ConnectPortDenied         bool
	ConnectPortDigest         string
	SOCKSOperationsDenied     bool
	SOCKSOperationsDigest     string
	DenialBoundaryDigest      string
	FloodBoundsProven         bool
	FloodBoundsDigest         string
	LossPreventsRelease       bool
	LossPreventsReleaseDigest string
}

type brokerCaseRuntime interface {
	BrokerCaseObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (brokerCaseRuntimeObservation, error)
}

type brokerEgressMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      brokerCaseRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

type brokerEvidenceBinding struct {
	AdapterID                    string                  `json:"adapter_id"`
	BrokerID                     string                  `json:"broker_id"`
	RunnerID                     string                  `json:"runner_id"`
	PolicyDigest                 string                  `json:"policy_digest"`
	PreparedEvidenceDigest       string                  `json:"prepared_evidence_digest"`
	ProbeMembershipDigest        string                  `json:"probe_membership_digest"`
	PreparedProbeBindingDigest   string                  `json:"prepared_probe_binding_digest"`
	PermitUsageDigest            string                  `json:"permit_usage_digest"`
	PermitAuthorityBindingDigest string                  `json:"permit_authority_binding_digest"`
	NetworkEgressDigest          string                  `json:"network_egress_digest"`
	BrokerAuditDigest            string                  `json:"broker_audit_digest"`
	RunnerAuditDigest            string                  `json:"runner_audit_digest"`
	HeldSocketZeroDigest         string                  `json:"held_socket_zero_digest"`
	BrokerReleaseDigest          string                  `json:"broker_release_digest"`
	ReleaseAuthorizationReceipt  string                  `json:"release_authorization_receipt"`
	ProbeReport                  networkjail.ProbeReport `json:"probe_report"`
}

func newBrokerEgressMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime brokerCaseRuntime,
) (*brokerEgressMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseBrokerEgress {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 12 {
		return nil, ErrFixtureStart
	}
	return &brokerEgressMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *brokerEgressMatrixSource) Observe(
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
		!s.ledger.freezeCase3() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *brokerEgressMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, flood, frozen := s.ledger.snapshotAfterCase2()
	if !frozen ||
		!validFixtureRuntimeObservation(prepared) ||
		!validFixtureFloodObservation(flood, s.ledger.attempts) {
		return nil, conformance.ErrObservation
	}
	runtimeObservation, err := s.runtime.BrokerCaseObservation(
		ctx,
		prepared,
	)
	if err != nil ||
		!validBrokerCaseRuntimeObservation(runtimeObservation) {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := brokerMatrixObservation(
			requirement,
			prepared,
			flood,
			runtimeObservation,
		)
		if err != nil {
			return nil, conformance.ErrObservation
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func validBrokerCaseRuntimeObservation(
	observation brokerCaseRuntimeObservation,
) bool {
	return observation.DirectProtocolsDenied &&
		isLowerHex(
			observation.DirectProtocolsDigest,
			sha256.Size*2,
		) &&
		observation.PlaintextHTTPDenied &&
		isLowerHex(
			observation.PlaintextHTTPDigest,
			sha256.Size*2,
		) &&
		observation.ConnectPortDenied &&
		isLowerHex(
			observation.ConnectPortDigest,
			sha256.Size*2,
		) &&
		observation.SOCKSOperationsDenied &&
		isLowerHex(
			observation.SOCKSOperationsDigest,
			sha256.Size*2,
		) &&
		isLowerHex(
			observation.DenialBoundaryDigest,
			sha256.Size*2,
		) &&
		observation.FloodBoundsProven &&
		isLowerHex(
			observation.FloodBoundsDigest,
			sha256.Size*2,
		) &&
		observation.LossPreventsRelease &&
		isLowerHex(
			observation.LossPreventsReleaseDigest,
			sha256.Size*2,
		)
}

func brokerMatrixObservation(
	requirement ObservationRequirement,
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
	runtime brokerCaseRuntimeObservation,
) (matrixObservation, error) {
	binding := brokerEvidenceBinding{
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
	}
	var (
		assertions   uint64
		measurements []conformance.MeasurementInput
		payload      any
	)
	switch requirement.ID {
	case "held-broker-sockets-zero":
		assertions = 1
		payload = struct {
			Binding         brokerEvidenceBinding `json:"binding"`
			ZeroSocketProof string                `json:"zero_socket_proof"`
		}{
			Binding:         binding,
			ZeroSocketProof: prepared.HeldSocketZeroDigest,
		}
	case "broker-positive-https":
		assertions = 3
		payload = struct {
			Binding    brokerEvidenceBinding `json:"binding"`
			PositiveOK bool                  `json:"positive_ok"`
			EgressOK   bool                  `json:"egress_ok"`
		}{
			Binding:    binding,
			PositiveOK: prepared.ProbeReport.PositiveOK,
			EgressOK:   prepared.NetworkEgressReport.PositiveOK,
		}
	case "broker-denied-literal", "broker-denied-dns":
		assertions = 3
		payload = struct {
			Binding     brokerEvidenceBinding `json:"binding"`
			DenialClass string                `json:"denial_class"`
			NegativeOK  bool                  `json:"negative_ok"`
			EgressOK    bool                  `json:"egress_ok"`
		}{
			Binding: binding,
			DenialClass: map[ObservationID]string{
				"broker-denied-literal": "literal",
				"broker-denied-dns":     "dns",
			}[requirement.ID],
			NegativeOK: prepared.ProbeReport.NegativeOK,
			EgressOK:   prepared.NetworkEgressReport.NegativeOK,
		}
	case "broker-denied-direct-protocols":
		assertions = 1
		payload = struct {
			Binding brokerEvidenceBinding `json:"binding"`
			Denied  bool                  `json:"denied"`
			Digest  string                `json:"digest"`
		}{
			Binding: binding,
			Denied:  runtime.DirectProtocolsDenied,
			Digest:  runtime.DirectProtocolsDigest,
		}
	case "broker-denied-plaintext-http":
		assertions = 1
		payload = struct {
			Binding brokerEvidenceBinding `json:"binding"`
			Denied  bool                  `json:"denied"`
			Digest  string                `json:"digest"`
		}{
			Binding: binding,
			Denied:  runtime.PlaintextHTTPDenied,
			Digest:  runtime.PlaintextHTTPDigest,
		}
	case "broker-denied-connect-port":
		assertions = 1
		payload = struct {
			Binding brokerEvidenceBinding `json:"binding"`
			Denied  bool                  `json:"denied"`
			Digest  string                `json:"digest"`
		}{
			Binding: binding,
			Denied:  runtime.ConnectPortDenied,
			Digest:  runtime.ConnectPortDigest,
		}
	case "broker-denied-socks-operations":
		assertions = 1
		payload = struct {
			Binding brokerEvidenceBinding `json:"binding"`
			Denied  bool                  `json:"denied"`
			Digest  string                `json:"digest"`
		}{
			Binding: binding,
			Denied:  runtime.SOCKSOperationsDenied,
			Digest:  runtime.SOCKSOperationsDigest,
		}
	case "broker-denial-boundary":
		assertions = 7
		payload = struct {
			Binding               brokerEvidenceBinding `json:"binding"`
			ProbeNegativeOK       bool                  `json:"probe_negative_ok"`
			DirectProtocolsDigest string                `json:"direct_protocols_digest"`
			PlaintextHTTPDigest   string                `json:"plaintext_http_digest"`
			ConnectPortDigest     string                `json:"connect_port_digest"`
			SOCKSOperationsDigest string                `json:"socks_operations_digest"`
			DenialBoundaryDigest  string                `json:"denial_boundary_digest"`
		}{
			Binding:               binding,
			ProbeNegativeOK:       prepared.ProbeReport.NegativeOK,
			DirectProtocolsDigest: runtime.DirectProtocolsDigest,
			PlaintextHTTPDigest:   runtime.PlaintextHTTPDigest,
			ConnectPortDigest:     runtime.ConnectPortDigest,
			SOCKSOperationsDigest: runtime.SOCKSOperationsDigest,
			DenialBoundaryDigest:  runtime.DenialBoundaryDigest,
		}
	case "broker-policy-ledger-authority-match":
		assertions = 8
		payload = struct {
			Binding brokerEvidenceBinding `json:"binding"`
		}{Binding: binding}
	case "broker-flood-bounds":
		assertions = 4
		measurements = []conformance.MeasurementInput{{
			Name:  "loopback_flood_attempts",
			Value: flood.Report.Attempts,
			Unit:  "count",
		}}
		payload = struct {
			Binding             brokerEvidenceBinding `json:"binding"`
			BoundsProven        bool                  `json:"bounds_proven"`
			BoundsDigest        string                `json:"bounds_digest"`
			FloodEvidenceDigest string                `json:"flood_evidence_digest"`
			FloodCompleted      bool                  `json:"flood_completed"`
		}{
			Binding:             binding,
			BoundsProven:        runtime.FloodBoundsProven,
			BoundsDigest:        runtime.FloodBoundsDigest,
			FloodEvidenceDigest: flood.EvidenceDigest,
			FloodCompleted:      flood.Report.Completed,
		}
	case "broker-loss-prevents-release":
		assertions = 3
		payload = struct {
			Binding             brokerEvidenceBinding `json:"binding"`
			LossPreventsRelease bool                  `json:"loss_prevents_release"`
			ReleaseTrapDigest   string                `json:"release_trap_digest"`
		}{
			Binding:             binding,
			LossPreventsRelease: runtime.LossPreventsRelease,
			ReleaseTrapDigest:   runtime.LossPreventsReleaseDigest,
		}
	default:
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		requirement,
		assertions,
		measurements,
		payload,
	)
}

var _ matrixObservationSource = (*brokerEgressMatrixSource)(nil)
