// Package hostruntime owns the closed host command and container-runtime
// boundary used by Portable-GHAR. It deliberately exposes typed specs and
// opaque handles instead of caller-controlled Docker argument fragments.
package hostruntime

import (
	"context"
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
	BindBrokerPeer(context.Context, AdapterHandle, BrokerPeerProof) error
	CreateRunner(context.Context, RunnerSpec) (RunnerHandle, error)
	HydrateSeeds(context.Context, RunnerHandle, []string) error
	ProbeRunnerNetworkNamespace(context.Context, RunnerHandle, GateOperation) (NetworkNamespaceProof, error)
	ArmRunner(context.Context, RunnerHandle) error
	AuditHeldRunner(context.Context, RunnerHandle) (HeldRunnerAudit, error)
	AuthorizeRelease(context.Context, RunnerHandle, NetworkNamespaceProof, NetworkNamespaceProof) (ReleaseAuthorization, error)
	ReleaseRunner(context.Context, RunnerHandle, ReleaseAuthorization, *redaction.Secret) error
	RemoveRunner(context.Context, RunnerHandle) error
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

var _ Engine = (*DockerCLI)(nil)
