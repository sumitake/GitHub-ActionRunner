package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const finalMatrixEvidenceDomain = "portable-ghar.task11.final-evidence-ledger.v1\x00"

type matrixEvidenceBinding struct {
	RunID           string `json:"run_id"`
	BuildID         string `json:"build_id"`
	FleetGeneration uint64 `json:"fleet_generation"`
	ProfileID       string `json:"profile_id"`
	SlotIdentity    string `json:"slot_identity"`
	GraphDigest     string `json:"graph_digest"`
}

type matrixEvidenceRow struct {
	Case           conformance.CaseID             `json:"case"`
	ID             ObservationID                  `json:"id"`
	Layer          conformance.ProofLayer         `json:"layer"`
	Source         ObservationSource              `json:"source"`
	Operation      string                         `json:"operation"`
	Parser         string                         `json:"parser"`
	AssertionCount uint64                         `json:"assertion_count"`
	Measurements   []conformance.MeasurementInput `json:"measurements"`
	Digest         string                         `json:"digest"`
}

type matrixRuntimeEvidenceWire struct {
	AdapterID                    string `json:"adapter_id"`
	BrokerID                     string `json:"broker_id"`
	RunnerID                     string `json:"runner_id"`
	AdapterSpecDigest            string `json:"adapter_spec_digest"`
	BrokerSpecDigest             string `json:"broker_spec_digest"`
	RunnerSpecDigest             string `json:"runner_spec_digest"`
	VerifierSpecDigest           string `json:"verifier_spec_digest"`
	AdapterEmptinessDigest       string `json:"adapter_emptiness_digest"`
	AdapterNamespaceDevice       uint64 `json:"adapter_namespace_device"`
	AdapterNamespaceInode        uint64 `json:"adapter_namespace_inode"`
	PolicyDigest                 string `json:"policy_digest"`
	PolicyApplicationDigest      string `json:"policy_application_digest"`
	HelperCapabilityDigest       string `json:"helper_capability_digest"`
	AuthorityBindingReceipt      string `json:"authority_binding_receipt"`
	BrokerPeerBindingDigest      string `json:"broker_peer_binding_digest"`
	NetworkEgressDigest          string `json:"network_egress_digest"`
	NamespacePreArmReceipt       string `json:"namespace_pre_arm_receipt"`
	NamespaceFinalReceipt        string `json:"namespace_final_receipt"`
	ReleaseAuthorizationReceipt  string `json:"release_authorization_receipt"`
	RuntimeCapabilityDigest      string `json:"runtime_capability_digest"`
	PreparedEvidenceDigest       string `json:"prepared_evidence_digest"`
	BrokerAuditDigest            string `json:"broker_audit_digest"`
	RunnerAuditDigest            string `json:"runner_audit_digest"`
	HeldSocketZeroDigest         string `json:"held_socket_zero_digest"`
	BrokerReleaseDigest          string `json:"broker_release_digest"`
	PermitUsageDigest            string `json:"permit_usage_digest"`
	PermitAuthorityBindingDigest string `json:"permit_authority_binding_digest"`
	ProbeMembershipDigest        string `json:"probe_membership_digest"`
	PreparedProbeBindingDigest   string `json:"prepared_probe_binding_digest"`
	FinalNamespaceDevice         uint64 `json:"final_namespace_device"`
	FinalNamespaceInode          uint64 `json:"final_namespace_inode"`
	FloodEvidenceDigest          string `json:"flood_evidence_digest"`
	FloodAttempts                uint64 `json:"flood_attempts"`
	FloodNamespaceDevice         uint64 `json:"flood_namespace_device"`
	FloodNamespaceInode          uint64 `json:"flood_namespace_inode"`
}

type finalMatrixEvidenceWire struct {
	SchemaVersion uint32                    `json:"schema_version"`
	Binding       matrixEvidenceBinding     `json:"binding"`
	Runtime       matrixRuntimeEvidenceWire `json:"runtime"`
	Rows          []matrixEvidenceRow       `json:"rows"`
}

type compositeMatrixObservationSource struct {
	binding      matrixEvidenceBinding
	prepared     *preparedRuntimeEvidenceLedger
	requirements []ObservationRequirement
	routes       map[ObservationID]matrixObservationSource

	mu             sync.Mutex
	rows           []matrixEvidenceRow
	next           int
	failed         bool
	finalized      bool
	targetObserved bool
}

func newCompositeMatrixObservationSource(
	binding matrixEvidenceBinding,
	prepared *preparedRuntimeEvidenceLedger,
	routes map[ObservationID]matrixObservationSource,
) (*compositeMatrixObservationSource, error) {
	requirements := preCanaryObservationRequirements()
	if !validMatrixEvidenceBinding(binding) ||
		prepared == nil ||
		len(routes) != len(requirements) {
		return nil, ErrFixtureStart
	}
	copied := make(
		map[ObservationID]matrixObservationSource,
		len(routes),
	)
	for _, requirement := range requirements {
		source := routes[requirement.ID]
		if source == nil {
			return nil, ErrFixtureStart
		}
		copied[requirement.ID] = source
	}
	return &compositeMatrixObservationSource{
		binding:      binding,
		prepared:     prepared,
		requirements: requirements,
		routes:       copied,
		rows:         make([]matrixEvidenceRow, 0, len(requirements)),
	}, nil
}

func (s *compositeMatrixObservationSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.finalized ||
		s.next >= len(s.requirements) ||
		requirement != s.requirements[s.next] {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	source := s.routes[requirement.ID]
	if source == nil {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	observation, err := source.Observe(ctx, requirement)
	if err != nil ||
		observation.Requirement != requirement ||
		observation.AssertionCount == 0 ||
		!isLowerHex(observation.Digest, sha256.Size*2) {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	s.rows = append(s.rows, matrixEvidenceRow{
		Case:           requirement.Case,
		ID:             requirement.ID,
		Layer:          requirement.Layer,
		Source:         requirement.Source,
		Operation:      requirement.Operation,
		Parser:         requirement.Parser,
		AssertionCount: observation.AssertionCount,
		Measurements: append(
			[]conformance.MeasurementInput(nil),
			observation.Measurements...,
		),
		Digest: observation.Digest,
	})
	s.next++
	return observation, nil
}

func (s *compositeMatrixObservationSource) FinalObservation(
	ctx context.Context,
) (targetRuntimeObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return targetRuntimeObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.finalized || s.targetObserved ||
		s.next != len(s.requirements) ||
		len(s.rows) != len(s.requirements) {
		return targetRuntimeObservation{}, conformance.ErrObservation
	}
	prepared, flood, frozen := s.prepared.snapshotAfterCase14()
	if !frozen ||
		!validFixtureRuntimeObservation(prepared) ||
		!validFixtureFloodObservation(flood, s.prepared.attempts) ||
		prepared.PolicyDigest != s.binding.GraphDigest ||
		prepared.ProbeReport.PolicyDigest != s.binding.GraphDigest ||
		prepared.NetworkEgressReport.PolicyDigest !=
			s.binding.GraphDigest ||
		prepared.AdapterNamespace != flood.Report.Namespace {
		s.failed = true
		return targetRuntimeObservation{}, conformance.ErrObservation
	}
	passed := make(map[ObservationID]bool, len(s.rows))
	for index, row := range s.rows {
		requirement := s.requirements[index]
		if row.Case != requirement.Case ||
			row.ID != requirement.ID ||
			row.Layer != requirement.Layer ||
			row.Source != requirement.Source ||
			row.Operation != requirement.Operation ||
			row.Parser != requirement.Parser ||
			row.AssertionCount == 0 ||
			!isLowerHex(row.Digest, sha256.Size*2) ||
			passed[row.ID] {
			s.failed = true
			return targetRuntimeObservation{},
				conformance.ErrObservation
		}
		passed[row.ID] = true
	}
	has := func(ids ...ObservationID) bool {
		for _, id := range ids {
			if !passed[id] {
				return false
			}
		}
		return true
	}
	syscallDenials := has("runner-seccomp-syscall-denials")
	resourceLimits := has(
		"host-cgroup-controls",
		"runner-resource-limits",
		"runner-sizing-tuple-match",
	)
	isolation := hostruntime.IsolationEvidence{
		RunnerNetworkNone: has(
			"adapter-runner-netns-identity",
			"runner-loopback-only",
			"namespace-stable-after-attach",
		) &&
			prepared.ProbeReport.RunnerLoopbackOnly,
		RunnerTablesEmptyBefore: has("runner-tables-empty") &&
			prepared.ProbeReport.RunnerTablesEmpty,
		RunnerTablesEmptyAfter: has("runner-tables-after-flood") &&
			flood.Report.TablesEmpty,
		RunnerConntrackEmptyBefore: has("runner-conntrack-before") &&
			prepared.ProbeReport.RunnerConntrackEmpty,
		RunnerConntrackEmptyAfter: has("runner-conntrack-after") &&
			flood.Report.ConntrackEmpty,
		LoopbackFloodCompleted: has("loopback-flood") &&
			flood.Report.Completed &&
			flood.Report.Attempts == uint64(s.prepared.attempts),
		NamespaceDenied: syscallDenials,
		RawSocketDenied: syscallDenials,
		BPFDenied:       syscallDenials,
		UnshareDenied:   syscallDenials,
		SetNSDenied:     syscallDenials,
		Clone3Denied:    syscallDenials,
		HeldBrokerSocketCountZero: has(
			"held-broker-sockets-zero",
			"broker-policy-ledger-authority-match",
		),
		LegacyFilterRestored: has(
			"helper-capabilities-lifetime",
			"broker-policy-ledger-authority-match",
			"namespace-stable-after-attach",
		),
		IPv6PostureProven: has(
			"broker-positive-https",
			"broker-denial-boundary",
			"broker-policy-ledger-authority-match",
		),
		RelayMountIdentityProven: has(
			"relay-mount-visibility",
			"host-control-invisible",
			"runner-forbidden-mounts-devices",
		),
		DialMountIdentityProven: has(
			"authority-mount-visibility",
			"host-control-invisible",
			"runner-forbidden-mounts-devices",
		),
		DoHPolicyProven: has(
			"broker-positive-https",
			"broker-denied-dns",
			"broker-denial-boundary",
			"broker-policy-ledger-authority-match",
		) &&
			prepared.ProbeReport.PositiveOK &&
			prepared.ProbeReport.NegativeOK,
		DurableConsumeBeforeDial: has(
			"broker-positive-https",
			"broker-policy-ledger-authority-match",
			"broker-loss-prevents-release",
		),
		CPUEnforced:    resourceLimits,
		MemoryEnforced: resourceLimits,
		PIDsEnforced:   resourceLimits,
		FDsEnforced: resourceLimits && has(
			"host-sizing-envelopes",
			"workflow-tool-probes",
		),
		TmpfsEnforced: resourceLimits && has(
			"runner-forbidden-mounts-devices",
		),
		ReadOnlyRootEnforced: has(
			"runner-read-only-root",
			"runner-forbidden-mounts-devices",
			"workflow-tool-probes",
		),
		SeccompEnforced: syscallDenials && has(
			"runner-identity-capabilities",
			"workflow-tool-probes",
		),
		CapabilitiesEnforced: has(
			"host-capability-sets",
			"helper-capabilities-lifetime",
			"runtime-capabilities-empty",
			"runner-identity-capabilities",
		),
		WorkAreaReclamationProven: has(
			"synthetic-job-completion",
			"synthetic-job-reclamation",
			"cleanup-success",
			"cleanup-cancellation",
			"cleanup-pre-listener-failure",
			"cleanup-listener-crash",
			"cleanup-controller-restart",
			"cleanup-upgrade-interruption",
			"reclamation-post-cleanup",
			"reclamation-version-staging-absence",
			"seed-workspaces-reclaimed",
		),
		BoundedLogRetention: has(
			"host-sizing-envelopes",
			"runner-resource-limits",
			"workflow-tool-probes",
			"reclamation-post-cleanup",
			"seed-workspaces-reclaimed",
		),
		PolicyDigest: prepared.PolicyDigest,
	}
	validatedIsolation := isolation
	validatedIsolation.EvidenceRevision = s.binding.RunID
	if hostruntime.ValidateIsolationEvidence(validatedIsolation) != nil ||
		networkjail.ValidateProbeReport(prepared.ProbeReport) != nil ||
		!has("runner-route-absence") ||
		!flood.Report.RoutesComplete {
		s.failed = true
		return targetRuntimeObservation{}, conformance.ErrObservation
	}
	s.targetObserved = true
	return targetRuntimeObservation{
		Isolation:            isolation,
		ProbeReport:          prepared.ProbeReport,
		RunnerRoutesComplete: flood.Report.RoutesComplete,
	}, nil
}

func (s *compositeMatrixObservationSource) FinalEvidenceDigest() (
	string,
	error,
) {
	if s == nil {
		return "", conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.finalized ||
		s.next != len(s.requirements) ||
		len(s.rows) != len(s.requirements) {
		return "", conformance.ErrObservation
	}
	prepared, flood, frozen := s.prepared.snapshotAfterCase14()
	if !frozen ||
		!validFixtureRuntimeObservation(prepared) ||
		!validFixtureFloodObservation(
			flood,
			s.prepared.attempts,
		) ||
		prepared.PolicyDigest != s.binding.GraphDigest {
		return "", conformance.ErrObservation
	}
	wire := finalMatrixEvidenceWire{
		SchemaVersion: 1,
		Binding:       s.binding,
		Runtime:       matrixRuntimeEvidenceFrom(prepared, flood),
		Rows: append(
			[]matrixEvidenceRow(nil),
			s.rows...,
		),
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return "", conformance.ErrObservation
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(finalMatrixEvidenceDomain))
	_, _ = digest.Write(document)
	value := hex.EncodeToString(digest.Sum(nil))
	if !isLowerHex(value, sha256.Size*2) {
		return "", conformance.ErrObservation
	}
	s.finalized = true
	return value, nil
}

func preCanaryObservationRequirements() []ObservationRequirement {
	var result []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseActualGitHubTransport {
			continue
		}
		result = append(result, requirement)
	}
	return result
}

func validMatrixEvidenceBinding(binding matrixEvidenceBinding) bool {
	return isLowerHex(binding.RunID, sha256.Size*2) &&
		isLowerHex(binding.BuildID, sha256.Size*2) &&
		binding.FleetGeneration > 0 &&
		(binding.ProfileID == "strict-linux" ||
			binding.ProfileID == "qts-capless-root") &&
		compositionContainerNamePattern.MatchString(
			binding.SlotIdentity,
		) &&
		isLowerHex(binding.GraphDigest, sha256.Size*2)
}

func matrixRuntimeEvidenceFrom(
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
) matrixRuntimeEvidenceWire {
	return matrixRuntimeEvidenceWire{
		AdapterID:                    prepared.Adapter.id,
		BrokerID:                     prepared.Broker.id,
		RunnerID:                     prepared.Runner.id,
		AdapterSpecDigest:            prepared.AdapterSpecDigest,
		BrokerSpecDigest:             prepared.BrokerSpecDigest,
		RunnerSpecDigest:             prepared.RunnerSpecDigest,
		VerifierSpecDigest:           prepared.VerifierSpecDigest,
		AdapterEmptinessDigest:       prepared.AdapterEmptinessDigest,
		AdapterNamespaceDevice:       prepared.AdapterNamespace.Device,
		AdapterNamespaceInode:        prepared.AdapterNamespace.Inode,
		PolicyDigest:                 prepared.PolicyDigest,
		PolicyApplicationDigest:      prepared.PolicyApplicationDigest,
		HelperCapabilityDigest:       prepared.HelperCapabilityDigest,
		AuthorityBindingReceipt:      prepared.AuthorityBindingReceipt,
		BrokerPeerBindingDigest:      prepared.BrokerPeerBindingDigest,
		NetworkEgressDigest:          prepared.NetworkEgressDigest,
		NamespacePreArmReceipt:       prepared.NamespacePreArmReceipt,
		NamespaceFinalReceipt:        prepared.NamespaceFinalReceipt,
		ReleaseAuthorizationReceipt:  prepared.ReleaseAuthorizationReceipt,
		RuntimeCapabilityDigest:      prepared.RuntimeCapabilityDigest,
		PreparedEvidenceDigest:       prepared.PreparedEvidenceDigest,
		BrokerAuditDigest:            prepared.BrokerAuditDigest,
		RunnerAuditDigest:            prepared.RunnerAuditDigest,
		HeldSocketZeroDigest:         prepared.HeldSocketZeroDigest,
		BrokerReleaseDigest:          prepared.BrokerReleaseDigest,
		PermitUsageDigest:            prepared.PermitUsageDigest,
		PermitAuthorityBindingDigest: prepared.PermitAuthorityBindingDigest,
		ProbeMembershipDigest:        prepared.ProbeMembershipDigest,
		PreparedProbeBindingDigest:   prepared.PreparedProbeBindingDigest,
		FinalNamespaceDevice:         prepared.ProbeReport.RunnerNetNSID.Device,
		FinalNamespaceInode:          prepared.ProbeReport.RunnerNetNSID.Inode,
		FloodEvidenceDigest:          flood.EvidenceDigest,
		FloodAttempts:                flood.Report.Attempts,
		FloodNamespaceDevice:         flood.Report.Namespace.Device,
		FloodNamespaceInode:          flood.Report.Namespace.Inode,
	}
}

var (
	_ matrixObservationSource = (*compositeMatrixObservationSource)(nil)
	_ targetObservationSource = (*compositeMatrixObservationSource)(nil)
	_ targetEvidenceLedger    = (*compositeMatrixObservationSource)(nil)
)
