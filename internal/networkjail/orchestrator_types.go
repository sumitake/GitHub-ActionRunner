package networkjail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

type authorityRequest struct {
	slotID        uint32
	jobGeneration uint64
	directory     string
	user          string
}

type authorityLease struct {
	proof         hostruntime.AuthorityProof
	slotID        uint32
	jobGeneration uint64
	socketPath    string
	socket        hostruntime.SocketIdentity
	endpoint      authorityEndpoint
	valid         bool
}

type authorityEndpoint interface {
	close() error
}

type authorityManager interface {
	Start(context.Context, authorityRequest) (authorityLease, error)
	Stop(context.Context, authorityLease) error
}

type adapterEmptinessProof struct {
	adapterID string
	digest    [sha256.Size]byte
	host      hostruntime.AdapterEmptinessEvidence
	valid     bool
}

type egressVerification struct {
	adapterID string
	brokerID  string
	policy    string
	digest    [sha256.Size]byte
	host      hostruntime.NetworkEgressEvidence
	valid     bool
}

type finalAuditProof struct {
	adapterID   string
	brokerID    string
	runnerID    string
	policy      string
	brokerAudit string
	heldAudit   string
	budget      string
	report      ProbeReport
	digest      [sha256.Size]byte
	valid       bool
}

type finalAuditRequest struct {
	adapter     adapterRuntimeRef
	broker      brokerRuntimeRef
	runner      runnerRuntimeRef
	emptiness   adapterEmptinessProof
	egress      egressVerification
	brokerAudit brokerAuditRuntimeRef
	heldAudit   heldRunnerAuditRuntimeRef
	graph       DecisionGraph
	budget      ConntrackBudget
	policy      hostruntime.PolicyArtifact
}

type setupVerifier interface {
	VerifyAdapterEmpty(context.Context, adapterRuntimeRef, hostruntime.VerifierSpec) (adapterEmptinessProof, error)
	VerifyEgress(context.Context, adapterRuntimeRef, brokerRuntimeRef, hostruntime.PolicyArtifact, hostruntime.VerifierSpec) (egressVerification, error)
	FinalAudit(context.Context, finalAuditRequest) (finalAuditProof, error)
}

type SetupRequest struct {
	Key               controller.AssignmentKey
	Adapter           hostruntime.AdapterSpec
	Broker            hostruntime.BrokerSpec
	Runner            hostruntime.RunnerSpec
	Verifier          hostruntime.VerifierSpec
	Graph             DecisionGraph
	Policy            hostruntime.PolicyArtifact
	ConntrackInput    Budget
	MaxRunnerCapacity uint64
	SeedIDs           []string
	JIT               *redaction.Secret
}

// PreparedSetupRequest is the complete nonsecret input to the held-jail
// transaction. Listener authority and JIT material are deliberately absent:
// Prepare stops at the durable RELEASE_ARMED checkpoint, and Release accepts
// the one-job secret only after every held-runtime proof is complete.
type PreparedSetupRequest struct {
	Key               controller.AssignmentKey
	Adapter           hostruntime.AdapterSpec
	Broker            hostruntime.BrokerSpec
	Runner            hostruntime.RunnerSpec
	Verifier          hostruntime.VerifierSpec
	Graph             DecisionGraph
	Policy            hostruntime.PolicyArtifact
	ConntrackInput    Budget
	MaxRunnerCapacity uint64
	SeedIDs           []string
}

// HeldJail is returned only after the release authorization and
// StateReleaseArmed checkpoint are durable. Every authority-bearing field is
// private so a caller cannot synthesize or replay listener release.
type HeldJail struct {
	key           controller.AssignmentKey
	resources     setupResources
	authorization releaseAuthorizationRuntimeRef
	report        ProbeReport
}

func (j HeldJail) AdapterID() string { return j.resources.adapter.id }
func (j HeldJail) BrokerID() string  { return j.resources.broker.id }
func (j HeldJail) RunnerID() string  { return j.resources.runner.id }
func (j HeldJail) ProbeReport() ProbeReport {
	return j.report
}

// LiveJail is returned only after the listener-release checkpoint is durable.
// It exposes nonsecret container identities while keeping all release proofs
// and cleanup authority internal.
type LiveJail struct {
	key       controller.AssignmentKey
	adapter   adapterRuntimeRef
	broker    brokerRuntimeRef
	runner    runnerRuntimeRef
	authority authorityLease
	report    ProbeReport
}

func (j LiveJail) AdapterID() string { return j.adapter.id }
func (j LiveJail) BrokerID() string  { return j.broker.id }
func (j LiveJail) RunnerID() string  { return j.runner.id }
func (j LiveJail) ProbeReport() ProbeReport {
	return j.report
}

func validateSetupRequest(request SetupRequest) error {
	if request.JIT == nil {
		return ErrSetupInput
	}
	return validatePreparedSetupRequest(preparedSetupRequest(request))
}

func validatePreparedSetupRequest(request PreparedSetupRequest) error {
	if request.Key.RepositoryAlias == "" ||
		request.Key.RunnerRequestID <= 0 ||
		request.Broker.Adapter.ID() != "" ||
		request.Runner.Adapter.ID() != "" ||
		request.Verifier.Adapter.ID() != "" ||
		request.Adapter.BuildID == "" ||
		request.Broker.BuildID != request.Adapter.BuildID ||
		request.Runner.BuildID != request.Adapter.BuildID ||
		request.Verifier.BuildID != request.Adapter.BuildID ||
		request.Broker.FleetGeneration != request.Adapter.FleetGeneration ||
		request.Runner.FleetGeneration != request.Adapter.FleetGeneration ||
		request.Verifier.FleetGeneration != request.Adapter.FleetGeneration ||
		request.Adapter.SlotIdentity == "" ||
		request.Broker.SlotIdentity != request.Adapter.SlotIdentity ||
		request.Runner.SlotIdentity != request.Adapter.SlotIdentity ||
		request.Verifier.SlotIdentity != request.Adapter.SlotIdentity ||
		request.Broker.CapacitySlotID == 0 ||
		request.Broker.JobGeneration == 0 ||
		request.Graph.digest == (Digest{}) ||
		!request.Policy.Valid() {
		return ErrSetupInput
	}
	runtimePolicy := request.Policy.RuntimePolicy()
	defer zeroOrchestratorBytes(runtimePolicy)
	graphDocument, err := EncodeDecisionGraph(request.Graph)
	if err != nil {
		return ErrSetupInput
	}
	defer zeroOrchestratorBytes(graphDocument)
	if !bytes.Equal(runtimePolicy, graphDocument) {
		return ErrSetupInput
	}
	if _, err := request.ConntrackInput.Compute(
		request.Graph.manifest,
		request.MaxRunnerCapacity,
	); err != nil {
		return ErrSetupInput
	}
	return nil
}

func preparedSetupRequest(request SetupRequest) PreparedSetupRequest {
	return PreparedSetupRequest{
		Key:               request.Key,
		Adapter:           request.Adapter,
		Broker:            request.Broker,
		Runner:            request.Runner,
		Verifier:          request.Verifier,
		Graph:             request.Graph,
		Policy:            request.Policy,
		ConntrackInput:    request.ConntrackInput,
		MaxRunnerCapacity: request.MaxRunnerCapacity,
		SeedIDs:           append([]string(nil), request.SeedIDs...),
	}
}

func validateAdapterEmptiness(
	proof adapterEmptinessProof,
	adapter adapterRuntimeRef,
) error {
	if !proof.valid || !adapter.valid || proof.adapterID != adapter.id ||
		proof.digest == ([sha256.Size]byte{}) {
		return errors.New("networkjail: adapter emptiness proof invalid")
	}
	return nil
}

func validateEgressVerification(
	proof egressVerification,
	adapter adapterRuntimeRef,
	broker brokerRuntimeRef,
	policy hostruntime.PolicyArtifact,
) error {
	if !proof.valid || !adapter.valid || !broker.valid ||
		proof.adapterID != adapter.id || proof.brokerID != broker.id ||
		proof.policy != policy.Digest() ||
		proof.digest == ([sha256.Size]byte{}) {
		return errors.New("networkjail: egress verification invalid")
	}
	return nil
}

func validateFinalAudit(
	proof finalAuditProof,
	request finalAuditRequest,
) error {
	if !proof.valid ||
		proof.adapterID != request.adapter.id ||
		proof.brokerID != request.broker.id ||
		proof.runnerID != request.runner.id ||
		proof.policy != request.policy.Digest() ||
		proof.brokerAudit != request.brokerAudit.digest ||
		proof.heldAudit != request.heldAudit.digest ||
		proof.budget != request.budget.Digest.String() ||
		proof.report.PolicyDigest != request.graph.Digest().String() ||
		ValidateProbeReport(proof.report) != nil ||
		proof.digest == ([sha256.Size]byte{}) {
		return errors.New("networkjail: final audit invalid")
	}
	return nil
}

func zeroOrchestratorBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
