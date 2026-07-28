// Package hostruntime owns the closed host command and container-runtime
// boundary used by Portable-GHAR. It deliberately exposes typed specs and
// opaque handles instead of caller-controlled Docker argument fragments.
package hostruntime

import (
	"context"
	"encoding/hex"
	"io"
	"os"

	"github.com/sumitake/portable-ghar/internal/redaction"
)

// CommandRunner executes one absolute argv directly, without a shell.
type CommandRunner interface {
	Run(context.Context, []string, []*os.File, io.Reader) (Result, error)
}

// Engine is the Task-5 host-runtime surface. Later tasks extend it with held
// broker lifecycle methods without widening any method to accept raw Docker
// arguments or caller-synthesized container identities.
type Engine interface {
	CreateNetworkAdapter(context.Context, AdapterSpec) (AdapterHandle, error)
	CreateNetworkBrokerHeld(context.Context, BrokerSpec) (BrokerHandle, error)
	ApplyNetworkPolicy(context.Context, BrokerHandle, PolicyArtifact) error
	BindDialAuthority(context.Context, BrokerHandle, AuthorityProof) error
	ReleaseNetworkBroker(context.Context, BrokerHandle) (BrokerPeerProof, error)
	AuditNetworkBroker(context.Context, BrokerHandle) (BrokerAudit, error)
	BindBrokerPeer(context.Context, AdapterHandle, BrokerPeerProof) error
	VerifyNetworkAdapterEmpty(context.Context, AdapterHandle, VerifierSpec) (AdapterEmptinessEvidence, error)
	VerifyNetworkEgress(context.Context, AdapterHandle, BrokerHandle, PolicyArtifact, VerifierSpec) (NetworkEgressEvidence, error)
	CreateRunner(context.Context, RunnerSpec) (RunnerHandle, error)
	HydrateSeeds(context.Context, RunnerHandle, []string) error
	ProbeRunnerNetworkNamespace(context.Context, RunnerHandle, GateOperation) (NetworkNamespaceProof, error)
	ArmRunner(context.Context, RunnerHandle) error
	AuditHeldRunner(context.Context, RunnerHandle) (HeldRunnerAudit, error)
	AuthorizeRelease(context.Context, RunnerHandle, NetworkNamespaceProof, NetworkNamespaceProof) (ReleaseAuthorization, error)
	ReleaseRunner(context.Context, RunnerHandle, ReleaseAuthorization, *redaction.Secret) error
	RemoveRunner(context.Context, RunnerHandle) error
	RemoveNetworkBroker(context.Context, BrokerHandle) error
	RemoveNetworkAdapter(context.Context, AdapterHandle) error
}

// HostProfile is a closed runner identity profile.
type HostProfile string

const (
	HostProfileStrictLinux    HostProfile = "strict-linux-v1"
	HostProfileQTSCaplessRoot HostProfile = "qts-capless-root"
)

// NetworkNamespaceProof is an engine-issued, generation-bound namespace
// identity. Its fields are intentionally opaque so a caller cannot turn an
// arbitrary device/inode pair into release authority.
type NetworkNamespaceProof struct {
	device     uint64
	inode      uint64
	generation uint64
	issuer     [32]byte
}

// ReleaseAuthorization is constructed only after the pre-arm, final, and
// freshly inspected adapter namespace proofs are exactly equal.
type ReleaseAuthorization struct {
	runnerNonce [32]byte
	issuer      [32]byte
	generation  uint64
	namespace   NetworkNamespaceProof
}

// HeldRunnerAudit is issued only after exact container configuration and
// single-process inventory are read back for the same runner generation.
// Its construction is intentionally opaque and it is never interchangeable
// with target-conformance evidence.
type HeldRunnerAudit struct {
	runnerNonce [32]byte
	issuer      [32]byte
	generation  uint64
	digest      [32]byte
}

// BrokerAudit binds a released broker's immutable container configuration,
// namespace owner, parser child, filter proof, sockets, policy, authority, and
// exact process inventory. Construction remains inside the host runtime.
type BrokerAudit struct {
	brokerNonce [32]byte
	issuer      [32]byte
	generation  uint64
	digest      [32]byte
}

// Digest returns the nonsecret canonical evidence digest.
func (a BrokerAudit) Digest() string {
	return hex.EncodeToString(a.digest[:])
}

// Digest returns the nonsecret canonical held-runner evidence digest.
func (a HeldRunnerAudit) Digest() string {
	return hex.EncodeToString(a.digest[:])
}

// NetworkNamespaceIdentity is a nonsecret device/inode observation. It becomes
// authority only while sealed inside an engine-issued opaque evidence value.
type NetworkNamespaceIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// NetworkVerifierReport is the exact capability-less verifier observation
// prior to the controller adding host conntrack-budget evidence.
type NetworkVerifierReport struct {
	PolicyDigest         string
	EgressBackend        string
	RunnerNetNSID        NetworkNamespaceIdentity
	BrokerNetNSID        NetworkNamespaceIdentity
	RunnerLoopbackOnly   bool
	RunnerTablesEmpty    bool
	RunnerConntrackEmpty bool
	ParserHasNoSocket    bool
	PositiveOK           bool
	NegativeOK           bool
}

// AdapterEmptinessEvidence can be issued only after the engine re-inspects the
// same held adapter on both sides of a capability-less one-shot verifier.
type AdapterEmptinessEvidence struct {
	adapterID string
	namespace NetworkNamespaceIdentity
	issuer    [32]byte
	nonce     [32]byte
	digest    [32]byte
}

func (e AdapterEmptinessEvidence) AdapterID() string {
	return e.adapterID
}

func (e AdapterEmptinessEvidence) Namespace() NetworkNamespaceIdentity {
	return e.namespace
}

func (e AdapterEmptinessEvidence) Digest() string {
	return hex.EncodeToString(e.digest[:])
}

// NetworkEgressEvidence binds both disjoint namespaces, the parser sandbox,
// the exact immutable policy artifact, and the one-shot proxy results.
type NetworkEgressEvidence struct {
	adapterID      string
	brokerID       string
	policyArtifact string
	report         NetworkVerifierReport
	issuer         [32]byte
	adapterNonce   [32]byte
	brokerNonce    [32]byte
	digest         [32]byte
}

func (e NetworkEgressEvidence) AdapterID() string {
	return e.adapterID
}

func (e NetworkEgressEvidence) BrokerID() string {
	return e.brokerID
}

func (e NetworkEgressEvidence) PolicyArtifactDigest() string {
	return e.policyArtifact
}

func (e NetworkEgressEvidence) Report() NetworkVerifierReport {
	return e.report
}

func (e NetworkEgressEvidence) Digest() string {
	return hex.EncodeToString(e.digest[:])
}

// GateOperation is the complete ordered Docker-exec surface of a held runner.
// Implementations must enforce the declared order; no generic exec operation
// exists.
type GateOperation uint8

const (
	GateHydrateSeeds GateOperation = iota + 1
	GateNetNSIDPreArm
	GateArm
	GateNetNSIDFinal
	GateRelease
)

// SeccompBinding identifies a controller-owned profile. This source layer
// proves path, SHA-256, and minimal JSON shape only. It does not claim that a
// Docker daemon or kernel applied the profile.
type SeccompBinding struct {
	Path   string
	SHA256 string
}

// ContainerLimits is the adapter's complete locally enforced resource vector.
// Values have no production defaults; zero is invalid.
type ContainerLimits struct {
	MilliCPU        uint64
	MemoryBytes     uint64
	PIDs            uint64
	FileDescriptors uint64
	TmpfsBytes      uint64
	ScratchBytes    uint64
	LogBytes        uint64
	LogFiles        uint64
}

// RunnerLimits includes every tmpfs sub-limit that consumes the enclosing
// memory cgroup. Values have no production defaults; zero is invalid.
type RunnerLimits struct {
	MilliCPU           uint64
	MemoryBytes        uint64
	PIDs               uint64
	FileDescriptors    uint64
	ScratchBytes       uint64
	LogBytes           uint64
	LogFiles           uint64
	RunnerTmpfsBytes   uint64
	TmpTmpfsBytes      uint64
	ProcessMarginBytes uint64
}

// BrokerLimits contains every persistent broker-container resource ceiling.
// StateBytes and ScratchBytes are tmpfs sub-limits charged inside MemoryBytes.
type BrokerLimits struct {
	MilliCPU        uint64
	MemoryBytes     uint64
	PIDs            uint64
	FileDescriptors uint64
	StateBytes      uint64
	ScratchBytes    uint64
	LogBytes        uint64
	LogFiles        uint64
}

// OneShotLimits bounds the short-lived NET_ADMIN policy helper. Its private
// 64 KiB /run tmpfs and disabled Docker log are fixed by the implementation.
type OneShotLimits struct {
	MilliCPU        uint64
	MemoryBytes     uint64
	PIDs            uint64
	FileDescriptors uint64
}

// VerifierSpec is the complete closed configuration of the capability-less
// one-shot verifier. The container name is derived from engine-issued nonces,
// never supplied by a job.
type VerifierSpec struct {
	Image           string
	BuildID         string
	FleetGeneration uint64
	Adapter         AdapterHandle
	User            string
	Seccomp         SeccompBinding
	Limits          OneShotLimits
}

// AdapterSpec contains no pass-through options, environment map, or secret.
type AdapterSpec struct {
	Name            string
	Image           string
	BuildID         string
	FleetGeneration uint64
	BrokerParent    string
	User            string
	Seccomp         SeccompBinding
	Limits          ContainerLimits
}

// RunnerSpec binds network identity through an opaque AdapterHandle. It
// contains no JIT, readiness token, mount, environment, or Docker option list.
type RunnerSpec struct {
	Name            string
	Image           string
	BuildID         string
	FleetGeneration uint64
	Adapter         AdapterHandle
	Profile         HostProfile
	User            string
	Seccomp         SeccompBinding
	Limits          RunnerLimits
}

// BrokerSpec contains no Docker option fragments, arbitrary environment, raw
// container identity, or secret. The broker network itself is fixed in
// DockerCLIConfig so a job cannot select it.
type BrokerSpec struct {
	Name            string
	Image           string
	HelperImage     string
	BuildID         string
	FleetGeneration uint64
	CapacitySlotID  uint32
	JobGeneration   uint64
	Adapter         AdapterHandle
	RelayParent     string
	AuthorityParent string
	User            string
	Seccomp         SeccompBinding
	Limits          BrokerLimits
	HelperLimits    OneShotLimits
}

var _ Engine = (*DockerCLI)(nil)
