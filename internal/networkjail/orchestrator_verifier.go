package networkjail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type hostSetupVerifier struct {
	engine hostruntime.Engine
}

func newHostSetupVerifier(
	engine hostruntime.Engine,
) (*hostSetupVerifier, error) {
	if engine == nil {
		return nil, errors.New("networkjail: verifier runtime required")
	}
	return &hostSetupVerifier{engine: engine}, nil
}

func (verifier *hostSetupVerifier) VerifyAdapterEmpty(
	ctx context.Context,
	adapter adapterRuntimeRef,
	spec hostruntime.VerifierSpec,
) (adapterEmptinessProof, error) {
	if verifier == nil || verifier.engine == nil || !adapter.valid {
		return adapterEmptinessProof{},
			errors.New("networkjail: adapter verifier unavailable")
	}
	spec.Adapter = adapter.handle
	host, err := verifier.engine.VerifyNetworkAdapterEmpty(
		ctx,
		adapter.handle,
		spec,
	)
	digest, digestErr := decodeVerifierDigest(host.Digest())
	if err != nil || digestErr != nil ||
		host.AdapterID() != adapter.id ||
		host.Namespace().Device == 0 ||
		host.Namespace().Inode == 0 {
		return adapterEmptinessProof{},
			errors.New("networkjail: adapter verifier failed")
	}
	return adapterEmptinessProof{
		adapterID: adapter.id,
		digest:    digest,
		host:      host,
		valid:     true,
	}, nil
}

func (verifier *hostSetupVerifier) VerifyEgress(
	ctx context.Context,
	adapter adapterRuntimeRef,
	broker brokerRuntimeRef,
	policy hostruntime.PolicyArtifact,
	spec hostruntime.VerifierSpec,
) (egressVerification, error) {
	if verifier == nil || verifier.engine == nil ||
		!adapter.valid || !broker.valid || !policy.Valid() {
		return egressVerification{},
			errors.New("networkjail: egress verifier unavailable")
	}
	spec.Adapter = adapter.handle
	host, err := verifier.engine.VerifyNetworkEgress(
		ctx,
		adapter.handle,
		broker.handle,
		policy,
		spec,
	)
	digest, digestErr := decodeVerifierDigest(host.Digest())
	report := host.Report()
	if err != nil || digestErr != nil ||
		host.AdapterID() != adapter.id ||
		host.BrokerID() != broker.id ||
		host.PolicyArtifactDigest() != policy.Digest() ||
		!validHostVerifierReport(report) {
		return egressVerification{},
			errors.New("networkjail: egress verifier failed")
	}
	return egressVerification{
		adapterID: adapter.id,
		brokerID:  broker.id,
		policy:    policy.Digest(),
		digest:    digest,
		host:      host,
		valid:     true,
	}, nil
}

func (verifier *hostSetupVerifier) FinalAudit(
	_ context.Context,
	request finalAuditRequest,
) (finalAuditProof, error) {
	if verifier == nil || verifier.engine == nil ||
		validateAdapterEmptiness(request.emptiness, request.adapter) != nil ||
		validateEgressVerification(
			request.egress,
			request.adapter,
			request.broker,
			request.policy,
		) != nil ||
		!request.runner.valid ||
		!request.brokerAudit.valid ||
		!request.heldAudit.valid ||
		!validLowerHexDigest(request.brokerAudit.digest) ||
		!validLowerHexDigest(request.heldAudit.digest) ||
		request.budget.Digest == (Digest{}) {
		return finalAuditProof{},
			errors.New("networkjail: final verifier unavailable")
	}
	emptyHost := request.emptiness.host
	egressHost := request.egress.host
	hostReport := egressHost.Report()
	if emptyHost.AdapterID() != request.adapter.id ||
		egressHost.AdapterID() != request.adapter.id ||
		egressHost.BrokerID() != request.broker.id ||
		egressHost.PolicyArtifactDigest() != request.policy.Digest() ||
		emptyHost.Namespace() != hostReport.RunnerNetNSID ||
		!validHostVerifierReport(hostReport) ||
		hostReport.PolicyDigest != request.graph.Digest().String() {
		return finalAuditProof{},
			errors.New("networkjail: final verifier evidence mismatch")
	}
	report := ProbeReport{
		Version:              1,
		PolicyDigest:         hostReport.PolicyDigest,
		EgressBackend:        EgressBackend(hostReport.EgressBackend),
		RunnerNetNSID:        namespaceFromHost(hostReport.RunnerNetNSID),
		BrokerNetNSID:        namespaceFromHost(hostReport.BrokerNetNSID),
		RunnerLoopbackOnly:   hostReport.RunnerLoopbackOnly,
		RunnerTablesEmpty:    hostReport.RunnerTablesEmpty,
		RunnerConntrackEmpty: hostReport.RunnerConntrackEmpty,
		ParserHasNoSocket:    hostReport.ParserHasNoSocket,
		PositiveOK:           hostReport.PositiveOK,
		NegativeOK:           hostReport.NegativeOK,
		ConntrackBudgetOK:    true,
	}
	if ValidateProbeReport(report) != nil {
		return finalAuditProof{},
			errors.New("networkjail: final verifier report invalid")
	}
	preimage, err := json.Marshal(struct {
		Version         uint8       `json:"version"`
		AdapterID       string      `json:"adapter_id"`
		BrokerID        string      `json:"broker_id"`
		RunnerID        string      `json:"runner_id"`
		PolicyArtifact  string      `json:"policy_artifact"`
		GraphDigest     string      `json:"graph_digest"`
		BudgetDigest    string      `json:"budget_digest"`
		BrokerAudit     string      `json:"broker_audit"`
		HeldRunnerAudit string      `json:"held_runner_audit"`
		EmptyEvidence   string      `json:"empty_evidence"`
		EgressEvidence  string      `json:"egress_evidence"`
		Report          ProbeReport `json:"report"`
	}{
		Version:         1,
		AdapterID:       request.adapter.id,
		BrokerID:        request.broker.id,
		RunnerID:        request.runner.id,
		PolicyArtifact:  request.policy.Digest(),
		GraphDigest:     request.graph.Digest().String(),
		BudgetDigest:    request.budget.Digest.String(),
		BrokerAudit:     request.brokerAudit.digest,
		HeldRunnerAudit: request.heldAudit.digest,
		EmptyEvidence:   emptyHost.Digest(),
		EgressEvidence:  egressHost.Digest(),
		Report:          report,
	})
	if err != nil {
		return finalAuditProof{},
			errors.New("networkjail: final verifier encoding failed")
	}
	digest := sha256.Sum256(preimage)
	zeroOrchestratorBytes(preimage)
	return finalAuditProof{
		adapterID:   request.adapter.id,
		brokerID:    request.broker.id,
		runnerID:    request.runner.id,
		policy:      request.policy.Digest(),
		brokerAudit: request.brokerAudit.digest,
		heldAudit:   request.heldAudit.digest,
		budget:      request.budget.Digest.String(),
		report:      report,
		digest:      digest,
		valid:       true,
	}, nil
}

func validHostVerifierReport(
	report hostruntime.NetworkVerifierReport,
) bool {
	return validLowerHexDigest(report.PolicyDigest) &&
		report.EgressBackend == string(RestrictedBrokerV1) &&
		report.RunnerNetNSID.Device != 0 &&
		report.RunnerNetNSID.Inode != 0 &&
		report.BrokerNetNSID.Device != 0 &&
		report.BrokerNetNSID.Inode != 0 &&
		report.RunnerNetNSID != report.BrokerNetNSID &&
		report.RunnerLoopbackOnly &&
		report.RunnerTablesEmpty &&
		report.RunnerConntrackEmpty &&
		report.ParserHasNoSocket &&
		report.PositiveOK &&
		report.NegativeOK
}

func namespaceFromHost(
	identity hostruntime.NetworkNamespaceIdentity,
) NamespaceIdentity {
	return NamespaceIdentity{
		Device: identity.Device,
		Inode:  identity.Inode,
	}
}

func decodeVerifierDigest(
	value string,
) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !validLowerHexDigest(value) {
		return digest, errors.New("networkjail: verifier digest invalid")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return digest, errors.New("networkjail: verifier digest invalid")
	}
	copy(digest[:], decoded)
	if digest == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{},
			errors.New("networkjail: verifier digest invalid")
	}
	return digest, nil
}

var _ setupVerifier = (*hostSetupVerifier)(nil)
