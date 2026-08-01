package testenv

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
)

const scannerInspectProjection = `{"version":1,"env":{{json .Config.Env}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"labels":{{json .Config.Labels}},"mounts":{{json .Mounts}},"binds":{{json .HostConfig.Binds}},"devices":{{json .HostConfig.Devices}},"security_options":{{json .HostConfig.SecurityOpt}}}`

type closedRuntimeSurfaceID string

const (
	surfaceAdapterInspect    closedRuntimeSurfaceID = "adapter-inspect"
	surfaceAdapterTop        closedRuntimeSurfaceID = "adapter-top"
	surfaceAdapterLogsStdout closedRuntimeSurfaceID = "adapter-logs-stdout"
	surfaceAdapterLogsStderr closedRuntimeSurfaceID = "adapter-logs-stderr"

	surfaceBrokerInspect    closedRuntimeSurfaceID = "broker-inspect"
	surfaceBrokerTop        closedRuntimeSurfaceID = "broker-top"
	surfaceBrokerLogsStdout closedRuntimeSurfaceID = "broker-logs-stdout"
	surfaceBrokerLogsStderr closedRuntimeSurfaceID = "broker-logs-stderr"

	surfaceRunnerInspect         closedRuntimeSurfaceID = "runner-inspect"
	surfaceRunnerFinalInventory  closedRuntimeSurfaceID = "runner-final-inventory"
	surfaceRunnerLogsStdout      closedRuntimeSurfaceID = "runner-logs-stdout"
	surfaceRunnerLogsStderr      closedRuntimeSurfaceID = "runner-logs-stderr"
	surfaceRunnerConformance     closedRuntimeSurfaceID = "runner-conformance"
	surfaceRunnerVerifyImage     closedRuntimeSurfaceID = "runner-verify-image"
	surfaceRunnerListenerVersion closedRuntimeSurfaceID = "runner-listener-version"

	surfaceAdapterEmptinessVerifier closedRuntimeSurfaceID = "adapter-emptiness-verifier"
	surfaceAdapterEmptinessAbsence  closedRuntimeSurfaceID = "adapter-emptiness-absence"
	surfacePolicyHelperApplication  closedRuntimeSurfaceID = "policy-helper-application"
	surfacePolicyHelperAbsence      closedRuntimeSurfaceID = "policy-helper-absence"
	surfaceAuthorityFilesystem      closedRuntimeSurfaceID = "authority-filesystem"
	surfaceHeldSocketAudit          closedRuntimeSurfaceID = "held-socket-audit"
	surfaceBrokerRelease            closedRuntimeSurfaceID = "broker-release"
	surfaceBrokerAudit              closedRuntimeSurfaceID = "broker-audit"
	surfaceAdapterPeerBind          closedRuntimeSurfaceID = "adapter-peer-bind"
	surfaceProxyVerifier            closedRuntimeSurfaceID = "proxy-verifier"
	surfaceProxyVerifierAbsence     closedRuntimeSurfaceID = "proxy-verifier-absence"
	surfaceBrokerNamespaceVerifier  closedRuntimeSurfaceID = "broker-namespace-verifier"
	surfaceBrokerNamespaceAbsence   closedRuntimeSurfaceID = "broker-namespace-absence"
	surfaceRunnerPreNamespace       closedRuntimeSurfaceID = "runner-pre-namespace"
	surfaceRunnerFinalNamespace     closedRuntimeSurfaceID = "runner-final-namespace"
	surfaceLoopbackFloodVerifier    closedRuntimeSurfaceID = "loopback-flood-verifier"
	surfaceLoopbackFloodAbsence     closedRuntimeSurfaceID = "loopback-flood-absence"

	surfacePreparedRuntime         closedRuntimeSurfaceID = "prepared-runtime"
	surfaceClosedDenials           closedRuntimeSurfaceID = "closed-denials"
	surfaceCase1Matrix             closedRuntimeSurfaceID = "case-1-matrix"
	surfaceCase2Matrix             closedRuntimeSurfaceID = "case-2-matrix"
	surfaceCase3Matrix             closedRuntimeSurfaceID = "case-3-matrix"
	surfaceCase4Matrix             closedRuntimeSurfaceID = "case-4-matrix"
	surfaceFixedNegativeProjection closedRuntimeSurfaceID = "fixed-negative-projection"
)

type closedRuntimeSurfaceEncoding uint8

const (
	closedRuntimeSurfaceStructuredJSON closedRuntimeSurfaceEncoding = iota + 1
	closedRuntimeSurfaceRaw
)

type closedRuntimeSurface struct {
	ID       closedRuntimeSurfaceID
	Encoding closedRuntimeSurfaceEncoding
	Document []byte
}

type scannerSessionCapture struct {
	RunnerUser string
	Surfaces   []closedRuntimeSurface
}

type scannerSessionBinding struct {
	Adapter cleanupHandle
	Broker  cleanupHandle
	Runner  cleanupHandle
}

type scannerSession struct {
	surface        *closedCommandSurface
	binding        scannerSessionBinding
	runnerUser     string
	runnerEvidence runnerScannerEvidence

	mu      sync.Mutex
	started bool
}

type scannerInspectProjectionWire struct {
	Version         uint8               `json:"version"`
	Environment     []string            `json:"env"`
	Entrypoint      []string            `json:"entrypoint"`
	Command         []string            `json:"cmd"`
	Labels          map[string]string   `json:"labels"`
	Mounts          []scannerMountWire  `json:"mounts"`
	Binds           []string            `json:"binds"`
	Devices         []scannerDeviceWire `json:"devices"`
	SecurityOptions []string            `json:"security_options"`
}

type scannerMountWire struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Driver      string `json:"Driver"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
	Propagation string `json:"Propagation"`
}

type scannerDeviceWire struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}

func newScannerSession(
	surface *closedCommandSurface,
	binding scannerSessionBinding,
	runner *runnerSession,
) (*scannerSession, error) {
	if surface == nil ||
		runner == nil ||
		runner.surface != surface ||
		binding.Adapter.kind != CleanupAdapter ||
		binding.Broker.kind != CleanupBroker ||
		binding.Runner.kind != CleanupRunner ||
		!isLowerHex(binding.Adapter.id, 64) ||
		!isLowerHex(binding.Broker.id, 64) ||
		!isLowerHex(binding.Runner.id, 64) ||
		binding.Adapter.id == binding.Broker.id ||
		binding.Adapter.id == binding.Runner.id ||
		binding.Broker.id == binding.Runner.id ||
		runner.binding.Runner != binding.Runner {
		return nil, ErrClosedCommand
	}
	evidence, err := runner.takeScannerEvidence()
	if err != nil {
		return nil, ErrClosedCommand
	}
	return &scannerSession{
		surface:        surface,
		binding:        binding,
		runnerUser:     runner.binding.User,
		runnerEvidence: evidence,
	}, nil
}

func (s *scannerSession) Capture(
	ctx context.Context,
) (scannerSessionCapture, error) {
	if s == nil || s.surface == nil || ctx == nil || ctx.Err() != nil {
		return scannerSessionCapture{}, ErrClosedCommand
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return scannerSessionCapture{}, ErrClosedCommand
	}
	s.started = true
	s.mu.Unlock()

	capture := scannerSessionCapture{
		RunnerUser: s.runnerUser,
		Surfaces:   make([]closedRuntimeSurface, 0, 15),
	}
	fail := func() (scannerSessionCapture, error) {
		destroyScannerCapture(&capture)
		destroyRunnerScannerEvidence(&s.runnerEvidence)
		return scannerSessionCapture{}, ErrClosedCommand
	}
	if err := s.captureCommandRole(
		ctx,
		s.binding.Adapter,
		surfaceAdapterInspect,
		surfaceAdapterTop,
		surfaceAdapterLogsStdout,
		surfaceAdapterLogsStderr,
		&capture,
	); err != nil {
		return fail()
	}
	if err := s.captureCommandRole(
		ctx,
		s.binding.Broker,
		surfaceBrokerInspect,
		surfaceBrokerTop,
		surfaceBrokerLogsStdout,
		surfaceBrokerLogsStderr,
		&capture,
	); err != nil {
		return fail()
	}
	if err := s.captureInspect(
		ctx,
		s.binding.Runner,
		surfaceRunnerInspect,
		&capture,
	); err != nil {
		return fail()
	}
	if !validHeldGateInventory(s.runnerEvidence.inventory) {
		return fail()
	}
	capture.Surfaces = append(capture.Surfaces, closedRuntimeSurface{
		ID:       surfaceRunnerFinalInventory,
		Encoding: closedRuntimeSurfaceRaw,
		Document: takeClosedBytes(&s.runnerEvidence.inventory),
	})
	if err := s.captureLogs(
		ctx,
		s.binding.Runner,
		surfaceRunnerLogsStdout,
		surfaceRunnerLogsStderr,
		&capture,
	); err != nil {
		return fail()
	}
	if _, err := parseRunnerConformance(
		s.runnerEvidence.conformance,
		s.runnerUser,
	); err != nil {
		return fail()
	}
	capture.Surfaces = append(
		capture.Surfaces,
		closedRuntimeSurface{
			ID:       surfaceRunnerConformance,
			Encoding: closedRuntimeSurfaceStructuredJSON,
			Document: takeClosedBytes(
				&s.runnerEvidence.conformance,
			),
		},
		closedRuntimeSurface{
			ID:       surfaceRunnerVerifyImage,
			Encoding: closedRuntimeSurfaceRaw,
			Document: takeClosedBytes(
				&s.runnerEvidence.verifyImage,
			),
		},
		closedRuntimeSurface{
			ID:       surfaceRunnerListenerVersion,
			Encoding: closedRuntimeSurfaceRaw,
			Document: takeClosedBytes(
				&s.runnerEvidence.listener,
			),
		},
	)
	destroyRunnerScannerEvidence(&s.runnerEvidence)
	if !validScannerSessionCapture(capture) {
		return fail()
	}
	return capture, nil
}

func (s *scannerSession) captureCommandRole(
	ctx context.Context,
	handle cleanupHandle,
	inspectID,
	topID,
	logsStdoutID,
	logsStderrID closedRuntimeSurfaceID,
	capture *scannerSessionCapture,
) error {
	if err := s.captureInspect(
		ctx,
		handle,
		inspectID,
		capture,
	); err != nil {
		return ErrClosedCommand
	}
	if err := s.captureTop(
		ctx,
		handle,
		topID,
		capture,
	); err != nil {
		return ErrClosedCommand
	}
	return s.captureLogs(
		ctx,
		handle,
		logsStdoutID,
		logsStderrID,
		capture,
	)
}

func (s *scannerSession) captureInspect(
	ctx context.Context,
	handle cleanupHandle,
	id closedRuntimeSurfaceID,
	capture *scannerSessionCapture,
) error {
	result, err := s.surface.executeExact(
		ctx,
		[]string{
			s.surface.config.DockerPath,
			"inspect",
			"--type",
			"container",
			"--format",
			scannerInspectProjection,
			handle.id,
		},
		nil,
		false,
	)
	defer destroyCommandResult(&result)
	if err != nil ||
		parseScannerInspectProjection(result.Stdout) != nil {
		return ErrClosedCommand
	}
	capture.Surfaces = append(capture.Surfaces, closedRuntimeSurface{
		ID:       id,
		Encoding: closedRuntimeSurfaceStructuredJSON,
		Document: append([]byte(nil), result.Stdout...),
	})
	return nil
}

func (s *scannerSession) captureTop(
	ctx context.Context,
	handle cleanupHandle,
	id closedRuntimeSurfaceID,
	capture *scannerSessionCapture,
) error {
	result, err := s.surface.executeExact(
		ctx,
		[]string{
			s.surface.config.DockerPath,
			"top",
			handle.id,
			"-eo",
			"pid=,args=",
		},
		nil,
		false,
	)
	defer destroyCommandResult(&result)
	if err != nil ||
		len(result.Stdout) == 0 ||
		result.Stdout[len(result.Stdout)-1] != '\n' {
		return ErrClosedCommand
	}
	capture.Surfaces = append(capture.Surfaces, closedRuntimeSurface{
		ID:       id,
		Encoding: closedRuntimeSurfaceRaw,
		Document: append([]byte(nil), result.Stdout...),
	})
	return nil
}

func (s *scannerSession) captureLogs(
	ctx context.Context,
	handle cleanupHandle,
	stdoutID,
	stderrID closedRuntimeSurfaceID,
	capture *scannerSessionCapture,
) error {
	result, err := s.surface.executeExact(
		ctx,
		[]string{
			s.surface.config.DockerPath,
			"logs",
			handle.id,
		},
		nil,
		true,
	)
	defer destroyCommandResult(&result)
	if err != nil {
		return ErrClosedCommand
	}
	capture.Surfaces = append(
		capture.Surfaces,
		closedRuntimeSurface{
			ID:       stdoutID,
			Encoding: closedRuntimeSurfaceRaw,
			Document: append([]byte(nil), result.Stdout...),
		},
		closedRuntimeSurface{
			ID:       stderrID,
			Encoding: closedRuntimeSurfaceRaw,
			Document: append([]byte(nil), result.Stderr...),
		},
	)
	return nil
}

func parseScannerInspectProjection(document []byte) error {
	if len(document) == 0 ||
		len(document) > 64<<10 ||
		document[len(document)-1] != '\n' {
		return ErrClosedCommand
	}
	body := document[:len(document)-1]
	var wire scannerInspectProjectionWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		wire.Version != 1 {
		return ErrClosedCommand
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, body) {
		zeroClosedBytes(canonical)
		return ErrClosedCommand
	}
	zeroClosedBytes(canonical)
	return nil
}

func validScannerSessionCapture(capture scannerSessionCapture) bool {
	expected := [...]closedRuntimeSurfaceID{
		surfaceAdapterInspect,
		surfaceAdapterTop,
		surfaceAdapterLogsStdout,
		surfaceAdapterLogsStderr,
		surfaceBrokerInspect,
		surfaceBrokerTop,
		surfaceBrokerLogsStdout,
		surfaceBrokerLogsStderr,
		surfaceRunnerInspect,
		surfaceRunnerFinalInventory,
		surfaceRunnerLogsStdout,
		surfaceRunnerLogsStderr,
		surfaceRunnerConformance,
		surfaceRunnerVerifyImage,
		surfaceRunnerListenerVersion,
	}
	if _, _, ok := parseStaticNumericUser(capture.RunnerUser); !ok ||
		len(capture.Surfaces) != len(expected) {
		return false
	}
	for index := range expected {
		surface := capture.Surfaces[index]
		if surface.ID != expected[index] ||
			surface.Encoding == 0 {
			return false
		}
		if surface.ID != surfaceAdapterLogsStdout &&
			surface.ID != surfaceAdapterLogsStderr &&
			surface.ID != surfaceBrokerLogsStdout &&
			surface.ID != surfaceBrokerLogsStderr &&
			surface.ID != surfaceRunnerLogsStdout &&
			surface.ID != surfaceRunnerLogsStderr &&
			len(surface.Document) == 0 {
			return false
		}
	}
	return true
}

func destroyScannerCapture(capture *scannerSessionCapture) {
	if capture == nil {
		return
	}
	for index := range capture.Surfaces {
		zeroClosedBytes(capture.Surfaces[index].Document)
		capture.Surfaces[index].Document = nil
	}
	capture.RunnerUser = ""
	capture.Surfaces = nil
}

func takeClosedBytes(document *[]byte) []byte {
	if document == nil {
		return nil
	}
	value := *document
	*document = nil
	return value
}
