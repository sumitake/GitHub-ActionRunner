package main

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const maxRunnerConformanceOutput = 16 << 10

var errRunnerConformance = errors.New("runner-gate: conformance unavailable")

type runnerConformanceWire struct {
	Version      uint8         `json:"version"`
	EUID         uint32        `json:"euid"`
	EGID         uint32        `json:"egid"`
	Capabilities linuxcap.Wire `json:"capabilities"`

	RawSocketDenied bool `json:"raw_socket_denied"`
	BPFDenied       bool `json:"bpf_denied"`
	UnshareDenied   bool `json:"unshare_denied"`
	SetNSDenied     bool `json:"setns_denied"`
	Clone3Denied    bool `json:"clone3_denied"`
	NamespaceDenied bool `json:"namespace_denied"`

	ProcSysReadOnly  bool `json:"proc_sys_read_only"`
	ProcMasksPresent bool `json:"proc_masks_present"`

	ControllerDatabaseAbsent bool `json:"controller_database_absent"`
	DockerAuthorityAbsent    bool `json:"docker_authority_absent"`
	HostControlAbsent        bool `json:"host_control_absent"`
	SecretEnvironmentAbsent  bool `json:"secret_environment_absent"`
	JITEnvironmentAbsent     bool `json:"jit_environment_absent"`
	SyntheticTokenAbsent     bool `json:"synthetic_token_absent"`
}

type runnerProcFacts struct {
	SysReadOnly  bool
	MasksPresent bool
}

type runnerProjectionFacts struct {
	ControllerDatabaseAbsent bool
	DockerAuthorityAbsent    bool
	HostControlAbsent        bool
	SecretEnvironmentAbsent  bool
	JITEnvironmentAbsent     bool
	SyntheticTokenAbsent     bool
}

type runnerConformanceProbeRuntime struct {
	identity     func() (uint64, uint64, error)
	capabilities func() (linuxcap.Wire, error)
	namespace    func() (networkjail.NamespaceIdentity, error)
	rawSocket    func() error
	bpf          func() error
	unshare      func() error
	setns        func() error
	clone3       func() error
	proc         func() (runnerProcFacts, error)
	projections  func() (runnerProjectionFacts, error)
}

func observeRunnerConformance(
	runtime runnerConformanceProbeRuntime,
) (runnerConformanceWire, error) {
	if runtime.identity == nil ||
		runtime.capabilities == nil ||
		runtime.namespace == nil ||
		runtime.rawSocket == nil ||
		runtime.bpf == nil ||
		runtime.unshare == nil ||
		runtime.setns == nil ||
		runtime.clone3 == nil ||
		runtime.proc == nil ||
		runtime.projections == nil {
		return runnerConformanceWire{}, errRunnerConformance
	}
	euid, egid, err := runtime.identity()
	if err != nil || euid > math.MaxUint32 || egid > math.MaxUint32 {
		return runnerConformanceWire{}, errRunnerConformance
	}
	capabilities, err := runtime.capabilities()
	if err != nil || linuxcap.ValidateEmpty(capabilities) != nil {
		return runnerConformanceWire{}, errRunnerConformance
	}
	before, err := runtime.namespace()
	if err != nil || !validRunnerNamespaceIdentity(before) {
		return runnerConformanceWire{}, errRunnerConformance
	}
	for _, probe := range []func() error{
		runtime.rawSocket,
		runtime.bpf,
		runtime.unshare,
		runtime.setns,
		runtime.clone3,
	} {
		if !runnerPermissionDenied(probe()) {
			return runnerConformanceWire{}, errRunnerConformance
		}
	}
	after, err := runtime.namespace()
	if err != nil ||
		!validRunnerNamespaceIdentity(after) ||
		after != before {
		return runnerConformanceWire{}, errRunnerConformance
	}
	proc, err := runtime.proc()
	if err != nil || !proc.SysReadOnly || !proc.MasksPresent {
		return runnerConformanceWire{}, errRunnerConformance
	}
	projections, err := runtime.projections()
	if err != nil ||
		!projections.ControllerDatabaseAbsent ||
		!projections.DockerAuthorityAbsent ||
		!projections.HostControlAbsent ||
		!projections.SecretEnvironmentAbsent ||
		!projections.JITEnvironmentAbsent ||
		!projections.SyntheticTokenAbsent {
		return runnerConformanceWire{}, errRunnerConformance
	}
	wire := runnerConformanceWire{
		Version:                  1,
		EUID:                     uint32(euid),
		EGID:                     uint32(egid),
		Capabilities:             capabilities,
		RawSocketDenied:          true,
		BPFDenied:                true,
		UnshareDenied:            true,
		SetNSDenied:              true,
		Clone3Denied:             true,
		NamespaceDenied:          true,
		ProcSysReadOnly:          true,
		ProcMasksPresent:         true,
		ControllerDatabaseAbsent: true,
		DockerAuthorityAbsent:    true,
		HostControlAbsent:        true,
		SecretEnvironmentAbsent:  true,
		JITEnvironmentAbsent:     true,
		SyntheticTokenAbsent:     true,
	}
	if !validRunnerConformanceWire(wire) {
		return runnerConformanceWire{}, errRunnerConformance
	}
	return wire, nil
}

func validRunnerNamespaceIdentity(
	identity networkjail.NamespaceIdentity,
) bool {
	return identity.Device != 0 && identity.Inode != 0
}

func runnerPermissionDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func validRunnerConformanceWire(wire runnerConformanceWire) bool {
	return wire.Version == 1 &&
		linuxcap.ValidateEmpty(wire.Capabilities) == nil &&
		wire.RawSocketDenied &&
		wire.BPFDenied &&
		wire.UnshareDenied &&
		wire.SetNSDenied &&
		wire.Clone3Denied &&
		wire.NamespaceDenied &&
		wire.ProcSysReadOnly &&
		wire.ProcMasksPresent &&
		wire.ControllerDatabaseAbsent &&
		wire.DockerAuthorityAbsent &&
		wire.HostControlAbsent &&
		wire.SecretEnvironmentAbsent &&
		wire.JITEnvironmentAbsent &&
		wire.SyntheticTokenAbsent
}

func writeRunnerConformance(
	writer io.Writer,
	wire runnerConformanceWire,
) error {
	if writer == nil || !validRunnerConformanceWire(wire) {
		return errRunnerConformance
	}
	document, err := json.Marshal(wire)
	if err != nil || len(document)+1 > maxRunnerConformanceOutput {
		zero(document)
		return errRunnerConformance
	}
	document = append(document, '\n')
	defer zero(document)
	for len(document) > 0 {
		count, writeErr := writer.Write(document)
		if writeErr != nil || count <= 0 {
			return errRunnerConformance
		}
		document = document[count:]
	}
	return nil
}
