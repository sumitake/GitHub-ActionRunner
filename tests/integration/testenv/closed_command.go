package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

var ErrClosedCommand = errors.New("testenv: closed command failed")

const (
	imageInspectFormat = `{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"operating_system":{{json .Os}},"architecture":{{json .Architecture}},"user":{{json .Config.User}}}`
	dockerInfoFormat   = `{"server_version":{{json .ServerVersion}},"operating_system":{{json .OperatingSystem}},"architecture":{{json .Architecture}},"kernel_version":{{json .KernelVersion}},"cgroup_version":{{json .CgroupVersion}},"memory_limit":{{json .MemoryLimit}},"cpu_cfs":{{json .CPUCfs}},"pids_limit":{{json .PidsLimit}}}`
)

type ClosedOperation uint8

const (
	ClosedDockerServerVersion ClosedOperation = iota + 1
	ClosedDockerInfo
	ClosedImageInspect
	ClosedListenerVersionSmoke
	ClosedContainerInspect
	ClosedContainerProcesses
	ClosedContainerStats
	ClosedContainerCgroup
	ClosedContainerMounts
	ClosedContainerUser
	ClosedContainerCapabilities
	ClosedContainerSeccomp
	ClosedContainerMaskedPaths
	ClosedNamespaceIdentity
	ClosedNamespaceRoutes
	ClosedNamespaceLinks
	ClosedNamespaceTables
	ClosedNamespaceConntrack
	ClosedLoopbackFlood
	ClosedBrokerHTTPS
	ClosedBrokerDeny
	ClosedBrokerProtocol
	ClosedPathAbsence
	ClosedSeedDigest
	ClosedFixtureStat
	ClosedFixtureEmpty
	ClosedFixtureRemove
	ClosedFixtureFSync
	ClosedTestController
	ClosedTestWatchdog
	ClosedTestFence
)

type ClosedCommandObservation struct {
	Digest string
	Bytes  uint64
}

type staticDockerInfoObservation struct {
	ServerVersion   string `json:"server_version"`
	OperatingSystem string `json:"operating_system"`
	Architecture    string `json:"architecture"`
	KernelVersion   string `json:"kernel_version"`
	CgroupVersion   string `json:"cgroup_version"`
	MemoryLimit     bool   `json:"memory_limit"`
	CPUCFS          bool   `json:"cpu_cfs"`
	PIDsLimit       bool   `json:"pids_limit"`
}

type closedCommandConfig struct {
	DockerPath   string
	FixtureRoot  string
	MaximumBytes uint64
	Images       []staticImageBinding
}

type closedCommandSurface struct {
	config closedCommandConfig
	runner hostruntime.CommandRunner
}

type preflightSession struct {
	surface *closedCommandSurface
}

type networkSession struct {
	surface *closedCommandSurface
	binding networkSessionBinding
	leases  closedOneShotLeaseAuthority
	name    string
	cleanup cleanupHandle

	mu               sync.Mutex
	observationTaken bool
	scannerTaken     bool
	scannerDocument  []byte
}

type networkSessionBinding struct {
	Adapter            cleanupHandle
	Broker             cleanupHandle
	RunDigest          string
	BuildID            string
	FleetGeneration    uint64
	SlotIdentity       string
	VerifierImage      string
	VerifierUser       string
	VerifierSeccomp    hostruntime.SeccompBinding
	VerifierLimits     hostruntime.OneShotLimits
	VerifierSpecDigest string
	Graph              networkjail.DecisionGraph
}

type closedOneShotLeaseAuthority interface {
	Register(cleanupHandle, string) error
	Retire(cleanupHandle) error
}

type runnerSession struct {
	surface *closedCommandSurface
	binding runnerSessionBinding

	mu               sync.Mutex
	observationTaken bool
	scannerTaken     bool
	scannerEvidence  runnerScannerEvidence
}

type runnerSessionBinding struct {
	Runner cleanupHandle
	User   string
}

func newClosedCommandSurface(
	config closedCommandConfig,
	runner hostruntime.CommandRunner,
) (*closedCommandSurface, error) {
	if runner == nil ||
		!filepath.IsAbs(config.DockerPath) ||
		filepath.Clean(config.DockerPath) != config.DockerPath ||
		!validAbsolutePath(config.FixtureRoot) ||
		config.MaximumBytes == 0 ||
		!validClosedImageBindings(config.Images) {
		return nil, ErrClosedCommand
	}
	config.Images = append([]staticImageBinding(nil), config.Images...)
	return &closedCommandSurface{config: config, runner: runner}, nil
}

func newPreflightSession(
	config closedCommandConfig,
	runner hostruntime.CommandRunner,
) (*preflightSession, error) {
	surface, err := newClosedCommandSurface(config, runner)
	if err != nil {
		return nil, err
	}
	return &preflightSession{surface: surface}, nil
}

func newNetworkSession(
	surface *closedCommandSurface,
	binding networkSessionBinding,
	leases closedOneShotLeaseAuthority,
) (*networkSession, error) {
	if surface == nil ||
		leases == nil ||
		!validNetworkSessionBinding(binding) {
		return nil, ErrClosedCommand
	}
	name, cleanup, err := closedDenialsIdentity(binding)
	if err != nil {
		return nil, ErrClosedCommand
	}
	return &networkSession{
		surface: surface,
		binding: binding,
		leases:  leases,
		name:    name,
		cleanup: cleanup,
	}, nil
}

func newRunnerSession(
	surface *closedCommandSurface,
	binding runnerSessionBinding,
) (*runnerSession, error) {
	uid, gid, userOK := parseStaticNumericUser(binding.User)
	if surface == nil ||
		binding.Runner.kind != CleanupRunner ||
		!isLowerHex(binding.Runner.id, 64) ||
		!userOK ||
		uid > math.MaxUint32 ||
		gid > math.MaxUint32 {
		return nil, ErrClosedCommand
	}
	return &runnerSession{
		surface: surface,
		binding: binding,
	}, nil
}

func (s *preflightSession) Run(
	ctx context.Context,
	operation ClosedOperation,
) (ClosedCommandObservation, error) {
	if s == nil || s.surface == nil || !preflightOperation(operation) {
		return ClosedCommandObservation{}, ErrClosedCommand
	}
	return s.surface.Run(ctx, operation)
}

func (s *preflightSession) InspectImages(
	ctx context.Context,
) ([]staticImageObservation, error) {
	if s == nil || s.surface == nil || len(s.surface.config.Images) == 0 {
		return nil, ErrClosedCommand
	}
	result, err := s.surface.execute(ctx, ClosedImageInspect)
	defer destroyCommandResult(&result)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(result.Stdout, []byte{'\n'})
	if len(lines) != len(s.surface.config.Images)+1 ||
		len(lines[len(lines)-1]) != 0 {
		return nil, ErrClosedCommand
	}
	observations := make([]staticImageObservation, len(s.surface.config.Images))
	for index, expected := range s.surface.config.Images {
		var wire closedImageInspectWire
		decoder := json.NewDecoder(bytes.NewReader(lines[index]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&wire); err != nil ||
			decoder.Decode(&struct{}{}) != io.EOF ||
			!validClosedImageInspectWire(wire, expected.Reference) {
			return nil, ErrClosedCommand
		}
		canonical, err := json.Marshal(wire)
		if err != nil || !bytes.Equal(canonical, lines[index]) {
			return nil, ErrClosedCommand
		}
		observations[index] = staticImageObservation{
			ID:               expected.ID,
			Reference:        expected.Reference,
			OperatingSystem:  wire.OperatingSystem,
			Architecture:     wire.Architecture,
			User:             wire.User,
			ReferencePresent: true,
		}
	}
	return observations, nil
}

func (s *preflightSession) InspectDockerInfo(
	ctx context.Context,
) (staticDockerInfoObservation, error) {
	if s == nil || s.surface == nil {
		return staticDockerInfoObservation{}, ErrClosedCommand
	}
	result, err := s.surface.execute(ctx, ClosedDockerInfo)
	defer destroyCommandResult(&result)
	if err != nil {
		return staticDockerInfoObservation{}, err
	}
	if !bytes.HasSuffix(result.Stdout, []byte{'\n'}) {
		return staticDockerInfoObservation{}, ErrClosedCommand
	}
	document := result.Stdout[:len(result.Stdout)-1]
	var observation staticDockerInfoObservation
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		!validStaticDockerInfo(observation) {
		return staticDockerInfoObservation{}, ErrClosedCommand
	}
	canonical, err := json.Marshal(observation)
	if err != nil || !bytes.Equal(canonical, document) {
		return staticDockerInfoObservation{}, ErrClosedCommand
	}
	return observation, nil
}

func (s *networkSession) Run(
	ctx context.Context,
	operation ClosedOperation,
) (ClosedCommandObservation, error) {
	if s == nil || s.surface == nil || !networkOperation(operation) {
		return ClosedCommandObservation{}, ErrClosedCommand
	}
	return ClosedCommandObservation{}, ErrClosedCommand
}

func (s *runnerSession) Run(
	ctx context.Context,
	operation ClosedOperation,
) (ClosedCommandObservation, error) {
	if s == nil || s.surface == nil || !runnerOperation(operation) {
		return ClosedCommandObservation{}, ErrClosedCommand
	}
	return ClosedCommandObservation{}, ErrClosedCommand
}

func preflightOperation(operation ClosedOperation) bool {
	switch operation {
	case ClosedDockerServerVersion,
		ClosedDockerInfo,
		ClosedImageInspect,
		ClosedListenerVersionSmoke:
		return true
	default:
		return false
	}
}

func networkOperation(operation ClosedOperation) bool {
	switch operation {
	case ClosedNamespaceIdentity,
		ClosedNamespaceRoutes,
		ClosedNamespaceLinks,
		ClosedNamespaceTables,
		ClosedNamespaceConntrack,
		ClosedLoopbackFlood,
		ClosedBrokerHTTPS,
		ClosedBrokerDeny,
		ClosedBrokerProtocol:
		return true
	default:
		return false
	}
}

func runnerOperation(operation ClosedOperation) bool {
	switch operation {
	case ClosedContainerInspect,
		ClosedContainerProcesses,
		ClosedContainerStats,
		ClosedContainerCgroup,
		ClosedContainerMounts,
		ClosedContainerUser,
		ClosedContainerCapabilities,
		ClosedContainerSeccomp,
		ClosedContainerMaskedPaths,
		ClosedPathAbsence,
		ClosedSeedDigest:
		return true
	default:
		return false
	}
}

func (s *closedCommandSurface) Run(
	ctx context.Context,
	operation ClosedOperation,
) (ClosedCommandObservation, error) {
	result, err := s.execute(ctx, operation)
	defer destroyCommandResult(&result)
	if err != nil {
		return ClosedCommandObservation{}, ErrClosedCommand
	}
	total := uint64(len(result.Stdout))
	digest := sha256.New()
	_, _ = digest.Write([]byte("portable-ghar-closed-command-v1\x00"))
	_ = binary.Write(digest, binary.BigEndian, uint16(operation))
	_ = binary.Write(digest, binary.BigEndian, uint64(len(result.Stdout)))
	_, _ = digest.Write(result.Stdout)
	return ClosedCommandObservation{
		Digest: hex.EncodeToString(digest.Sum(nil)),
		Bytes:  total,
	}, nil
}

func (s *closedCommandSurface) execute(
	ctx context.Context,
	operation ClosedOperation,
) (hostruntime.Result, error) {
	if s == nil || ctx == nil {
		return hostruntime.Result{}, ErrClosedCommand
	}
	argv, ok := s.argv(operation)
	if !ok {
		return hostruntime.Result{}, ErrClosedCommand
	}
	return s.executeExact(ctx, argv, nil, false)
}

func (s *closedCommandSurface) executeExact(
	ctx context.Context,
	argv []string,
	stdin io.Reader,
	allowStderr bool,
) (hostruntime.Result, error) {
	if s == nil ||
		ctx == nil ||
		len(argv) == 0 ||
		(argv[0] != s.config.DockerPath &&
			argv[0] != "/usr/bin/stat") {
		return hostruntime.Result{}, ErrClosedCommand
	}
	result, err := s.runner.Run(ctx, argv, nil, stdin)
	total := uint64(len(result.Stdout)) + uint64(len(result.Stderr))
	if err != nil ||
		result.ExitCode != 0 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		(!allowStderr && len(result.Stderr) != 0) ||
		total > s.config.MaximumBytes {
		return result, ErrClosedCommand
	}
	return result, nil
}

func (s *closedCommandSurface) argv(
	operation ClosedOperation,
) ([]string, bool) {
	switch operation {
	case ClosedDockerServerVersion:
		return []string{
			s.config.DockerPath,
			"version",
			"--format",
			"{{json .Server}}",
		}, true
	case ClosedDockerInfo:
		return []string{
			s.config.DockerPath,
			"info",
			"--format",
			dockerInfoFormat,
		}, true
	case ClosedImageInspect:
		if len(s.config.Images) == 0 {
			return nil, false
		}
		argv := []string{
			s.config.DockerPath,
			"image",
			"inspect",
			"--format",
			imageInspectFormat,
		}
		for _, image := range s.config.Images {
			argv = append(argv, image.Reference)
		}
		return argv, true
	case ClosedFixtureStat:
		return []string{"/usr/bin/stat", "-f", "%d:%i:%p", s.config.FixtureRoot}, true
	default:
		return nil, false
	}
}

type closedImageInspectWire struct {
	ID              string   `json:"id"`
	RepoDigests     []string `json:"repo_digests"`
	OperatingSystem string   `json:"operating_system"`
	Architecture    string   `json:"architecture"`
	User            string   `json:"user"`
}

func validClosedImageInspectWire(
	wire closedImageInspectWire,
	expectedReference string,
) bool {
	if !strings.HasPrefix(wire.ID, "sha256:") ||
		!isLowerHex(strings.TrimPrefix(wire.ID, "sha256:"), 64) ||
		len(wire.RepoDigests) == 0 ||
		wire.OperatingSystem == "" ||
		wire.Architecture == "" {
		return false
	}
	if _, _, ok := parseStaticNumericUser(wire.User); !ok {
		return false
	}
	found := 0
	for index, reference := range wire.RepoDigests {
		if !immutableImageReferencePattern.MatchString(reference) {
			return false
		}
		for prior := 0; prior < index; prior++ {
			if wire.RepoDigests[prior] == reference {
				return false
			}
		}
		if reference == expectedReference {
			found++
		}
	}
	return found == 1
}

func validClosedImageBindings(bindings []staticImageBinding) bool {
	for index, binding := range bindings {
		if !validID(binding.ID) ||
			!immutableImageReferencePattern.MatchString(binding.Reference) {
			return false
		}
		for prior := 0; prior < index; prior++ {
			if bindings[prior].ID == binding.ID ||
				bindings[prior].Reference == binding.Reference {
				return false
			}
		}
	}
	return true
}

func validStaticDockerInfo(value staticDockerInfoObservation) bool {
	for _, scalar := range []string{
		value.ServerVersion,
		value.OperatingSystem,
		value.Architecture,
		value.KernelVersion,
	} {
		if scalar == "" ||
			len(scalar) > 128 ||
			hasControl(scalar) {
			return false
		}
	}
	return (value.CgroupVersion == "1" ||
		value.CgroupVersion == "2") &&
		value.MemoryLimit &&
		value.CPUCFS &&
		value.PIDsLimit
}

func destroyCommandResult(result *hostruntime.Result) {
	if result == nil {
		return
	}
	for index := range result.Stdout {
		result.Stdout[index] = 0
	}
	for index := range result.Stderr {
		result.Stderr[index] = 0
	}
	result.Stdout = nil
	result.Stderr = nil
}
