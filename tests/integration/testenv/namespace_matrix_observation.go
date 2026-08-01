package testenv

import (
	"context"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type namespaceEvidenceRuntime interface {
	RuntimeObservation(
		context.Context,
	) (fixtureRuntimeObservation, error)
	LoopbackFlood(
		context.Context,
		uint32,
	) (fixtureFloodObservation, error)
}

type namespaceBaselineMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

type preparedRuntimeEvidenceLedger struct {
	attempts uint32
	runtime  namespaceEvidenceRuntime

	mu            sync.Mutex
	prepared      fixtureRuntimeObservation
	flood         fixtureFloodObservation
	ready         bool
	failed        bool
	frozenThrough runtimeEvidenceStage
}

type runtimeEvidenceStage uint8

const (
	runtimeEvidenceUnfrozen runtimeEvidenceStage = iota
	runtimeEvidenceCase2
	runtimeEvidenceCase3
	runtimeEvidenceCase4
	runtimeEvidenceCase5
	runtimeEvidenceCase6
	runtimeEvidenceCase7
	runtimeEvidenceCase8
	runtimeEvidenceCase9
	runtimeEvidenceCase10
	runtimeEvidenceCase11
	runtimeEvidenceCase12
	runtimeEvidenceCase13
	runtimeEvidenceCase14
)

func newPreparedRuntimeEvidenceLedger(
	attempts uint32,
	runtime namespaceEvidenceRuntime,
) (*preparedRuntimeEvidenceLedger, error) {
	if attempts == 0 || runtime == nil {
		return nil, ErrFixtureStart
	}
	return &preparedRuntimeEvidenceLedger{
		attempts: attempts,
		runtime:  runtime,
	}, nil
}

func newNamespaceBaselineMatrixSource(
	attempts uint32,
	runtime namespaceEvidenceRuntime,
) (*namespaceBaselineMatrixSource, error) {
	ledger, err := newPreparedRuntimeEvidenceLedger(attempts, runtime)
	if err != nil {
		return nil, err
	}
	return newNamespaceBaselineMatrixSourceFromLedger(ledger)
}

func newNamespaceBaselineMatrixSourceFromLedger(
	ledger *preparedRuntimeEvidenceLedger,
) (*namespaceBaselineMatrixSource, error) {
	if ledger == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseNamespaceBaseline {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 11 {
		return nil, ErrFixtureStart
	}
	return &namespaceBaselineMatrixSource{
		ledger:       ledger,
		requirements: requirements,
	}, nil
}

func (s *namespaceBaselineMatrixSource) Observe(
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
		!s.ledger.freezeCase2() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *namespaceBaselineMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, flood, err := s.ledger.acquire(ctx)
	if err != nil {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := namespaceMatrixObservation(
			requirement,
			s.ledger.attempts,
			prepared,
			flood,
		)
		if err != nil {
			return nil, conformance.ErrObservation
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func (l *preparedRuntimeEvidenceLedger) acquire(
	ctx context.Context,
) (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	error,
) {
	if l == nil || ctx == nil || ctx.Err() != nil {
		return fixtureRuntimeObservation{},
			fixtureFloodObservation{},
			conformance.ErrObservation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed {
		return fixtureRuntimeObservation{},
			fixtureFloodObservation{},
			conformance.ErrObservation
	}
	if l.ready {
		return l.prepared, l.flood, nil
	}
	prepared, err := l.runtime.RuntimeObservation(ctx)
	if err != nil || !validFixtureRuntimeObservation(prepared) {
		l.failed = true
		return fixtureRuntimeObservation{},
			fixtureFloodObservation{},
			conformance.ErrObservation
	}
	flood, err := l.runtime.LoopbackFlood(ctx, l.attempts)
	if err != nil || !validFixtureFloodObservation(flood, l.attempts) ||
		prepared.AdapterNamespace != flood.Report.Namespace ||
		prepared.AdapterNamespace.Device !=
			prepared.ProbeReport.RunnerNetNSID.Device ||
		prepared.AdapterNamespace.Inode !=
			prepared.ProbeReport.RunnerNetNSID.Inode {
		l.failed = true
		return fixtureRuntimeObservation{},
			fixtureFloodObservation{},
			conformance.ErrObservation
	}
	l.prepared = prepared
	l.flood = flood
	l.ready = true
	return prepared, flood, nil
}

func (l *preparedRuntimeEvidenceLedger) freezeCase2() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceUnfrozen,
		runtimeEvidenceCase2,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase2() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase2)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase3() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase2,
		runtimeEvidenceCase3,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase3() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase3)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase4() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase3,
		runtimeEvidenceCase4,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase4() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase4)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase5() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase4,
		runtimeEvidenceCase5,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase5() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase5)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase6() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase5,
		runtimeEvidenceCase6,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase6() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase6)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase7() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase6,
		runtimeEvidenceCase7,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase7() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase7)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase8() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase7,
		runtimeEvidenceCase8,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase8() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase8)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase9() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase8,
		runtimeEvidenceCase9,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase9() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase9)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase10() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase9,
		runtimeEvidenceCase10,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase10() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase10)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase11() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase10,
		runtimeEvidenceCase11,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase11() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase11)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase12() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase11,
		runtimeEvidenceCase12,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase12() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase12)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase13() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase12,
		runtimeEvidenceCase13,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase13() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase13)
}

func (l *preparedRuntimeEvidenceLedger) freezeCase14() bool {
	return l.freezeRuntimeEvidence(
		runtimeEvidenceCase13,
		runtimeEvidenceCase14,
	)
}

func (l *preparedRuntimeEvidenceLedger) snapshotAfterCase14() (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	return l.snapshotRuntimeEvidence(runtimeEvidenceCase14)
}

func (l *preparedRuntimeEvidenceLedger) freezeRuntimeEvidence(
	previous runtimeEvidenceStage,
	next runtimeEvidenceStage,
) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed || !l.ready ||
		l.frozenThrough != previous ||
		next != previous+1 {
		return false
	}
	l.frozenThrough = next
	return true
}

func (l *preparedRuntimeEvidenceLedger) snapshotRuntimeEvidence(
	stage runtimeEvidenceStage,
) (
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	bool,
) {
	if l == nil {
		return fixtureRuntimeObservation{},
			fixtureFloodObservation{},
			false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed || !l.ready || l.frozenThrough != stage {
		return fixtureRuntimeObservation{},
			fixtureFloodObservation{},
			false
	}
	return l.prepared, l.flood, true
}

func namespaceMatrixObservation(
	requirement ObservationRequirement,
	attempts uint32,
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
) (matrixObservation, error) {
	var (
		assertions   uint64
		measurements []conformance.MeasurementInput
		payload      any
	)
	switch requirement.ID {
	case "adapter-runner-netns-identity":
		assertions = 5
		payload = struct {
			AdapterID                   string                               `json:"adapter_id"`
			RunnerID                    string                               `json:"runner_id"`
			AdapterNamespace            hostruntime.NetworkNamespaceIdentity `json:"adapter_namespace"`
			ProbeNamespace              networkjail.NamespaceIdentity        `json:"probe_namespace"`
			PostFloodNamespace          hostruntime.NetworkNamespaceIdentity `json:"post_flood_namespace"`
			AdapterEmptinessDigest      string                               `json:"adapter_emptiness_digest"`
			ReleaseAuthorizationReceipt string                               `json:"release_authorization_receipt"`
			PreparedEvidenceDigest      string                               `json:"prepared_evidence_digest"`
		}{
			AdapterID:                   prepared.Adapter.id,
			RunnerID:                    prepared.Runner.id,
			AdapterNamespace:            prepared.AdapterNamespace,
			ProbeNamespace:              prepared.ProbeReport.RunnerNetNSID,
			PostFloodNamespace:          flood.Report.Namespace,
			AdapterEmptinessDigest:      prepared.AdapterEmptinessDigest,
			ReleaseAuthorizationReceipt: prepared.ReleaseAuthorizationReceipt,
			PreparedEvidenceDigest:      prepared.PreparedEvidenceDigest,
		}
	case "runner-loopback-only":
		assertions = 1
		payload = struct {
			LoopbackOnly           bool   `json:"loopback_only"`
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
		}{
			LoopbackOnly:           prepared.ProbeReport.RunnerLoopbackOnly,
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
		}
	case "runner-tables-empty":
		assertions = 1
		payload = struct {
			TablesEmpty            bool   `json:"tables_empty"`
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
		}{
			TablesEmpty:            prepared.ProbeReport.RunnerTablesEmpty,
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
		}
	case "runner-conntrack-before":
		assertions = 1
		payload = struct {
			ConntrackEmpty         bool   `json:"conntrack_empty"`
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
		}{
			ConntrackEmpty:         prepared.ProbeReport.RunnerConntrackEmpty,
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
		}
	case "loopback-flood":
		assertions = 2
		measurements = []conformance.MeasurementInput{{
			Name:  "loopback_flood_attempts",
			Value: uint64(attempts),
			Unit:  "count",
		}}
		payload = struct {
			Attempts       uint64 `json:"attempts"`
			Completed      bool   `json:"completed"`
			EvidenceDigest string `json:"evidence_digest"`
		}{
			Attempts:       flood.Report.Attempts,
			Completed:      flood.Report.Completed,
			EvidenceDigest: flood.EvidenceDigest,
		}
	case "runner-tables-after-flood":
		assertions = 1
		payload = struct {
			TablesEmpty    bool   `json:"tables_empty"`
			EvidenceDigest string `json:"evidence_digest"`
		}{
			TablesEmpty:    flood.Report.TablesEmpty,
			EvidenceDigest: flood.EvidenceDigest,
		}
	case "runner-conntrack-after":
		assertions = 1
		payload = struct {
			ConntrackEmpty bool   `json:"conntrack_empty"`
			EvidenceDigest string `json:"evidence_digest"`
		}{
			ConntrackEmpty: flood.Report.ConntrackEmpty,
			EvidenceDigest: flood.EvidenceDigest,
		}
	case "runner-route-absence":
		assertions = 1
		payload = struct {
			RoutesComplete bool   `json:"routes_complete"`
			EvidenceDigest string `json:"evidence_digest"`
		}{
			RoutesComplete: flood.Report.RoutesComplete,
			EvidenceDigest: flood.EvidenceDigest,
		}
	case "namespace-stable-after-attach":
		assertions = 4
		payload = struct {
			Namespace                   hostruntime.NetworkNamespaceIdentity `json:"namespace"`
			PreArmReceipt               string                               `json:"pre_arm_receipt"`
			FinalReceipt                string                               `json:"final_receipt"`
			ReleaseAuthorizationReceipt string                               `json:"release_authorization_receipt"`
			PreparedEvidenceDigest      string                               `json:"prepared_evidence_digest"`
		}{
			Namespace:                   flood.Report.Namespace,
			PreArmReceipt:               prepared.NamespacePreArmReceipt,
			FinalReceipt:                prepared.NamespaceFinalReceipt,
			ReleaseAuthorizationReceipt: prepared.ReleaseAuthorizationReceipt,
			PreparedEvidenceDigest:      prepared.PreparedEvidenceDigest,
		}
	case "helper-capabilities-lifetime":
		assertions = 1
		payload = struct {
			CapabilityDigest        string `json:"capability_digest"`
			PolicyApplicationDigest string `json:"policy_application_digest"`
			PolicyDigest            string `json:"policy_digest"`
		}{
			CapabilityDigest:        prepared.HelperCapabilityDigest,
			PolicyApplicationDigest: prepared.PolicyApplicationDigest,
			PolicyDigest:            prepared.PolicyDigest,
		}
	case "runtime-capabilities-empty":
		assertions = 1
		payload = struct {
			CapabilityDigest    string `json:"capability_digest"`
			AdapterSpecDigest   string `json:"adapter_spec_digest"`
			BrokerSpecDigest    string `json:"broker_spec_digest"`
			RunnerSpecDigest    string `json:"runner_spec_digest"`
			VerifierSpecDigest  string `json:"verifier_spec_digest"`
			BrokerAuditDigest   string `json:"broker_audit_digest"`
			RunnerAuditDigest   string `json:"runner_audit_digest"`
			EmptinessDigest     string `json:"emptiness_digest"`
			NetworkEgressDigest string `json:"network_egress_digest"`
			FloodEvidenceDigest string `json:"flood_evidence_digest"`
		}{
			CapabilityDigest:    prepared.RuntimeCapabilityDigest,
			AdapterSpecDigest:   prepared.AdapterSpecDigest,
			BrokerSpecDigest:    prepared.BrokerSpecDigest,
			RunnerSpecDigest:    prepared.RunnerSpecDigest,
			VerifierSpecDigest:  prepared.VerifierSpecDigest,
			BrokerAuditDigest:   prepared.BrokerAuditDigest,
			RunnerAuditDigest:   prepared.RunnerAuditDigest,
			EmptinessDigest:     prepared.AdapterEmptinessDigest,
			NetworkEgressDigest: prepared.NetworkEgressDigest,
			FloodEvidenceDigest: flood.EvidenceDigest,
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

var _ matrixObservationSource = (*namespaceBaselineMatrixSource)(nil)
