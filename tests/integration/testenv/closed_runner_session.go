package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/linuxcap"
)

const (
	closedRunnerGatePath = "/usr/local/bin/portable-ghar-runner-gate"
	closedListenerPath   = "/opt/actions-runner/bin/Runner.Listener"
	closedHeldGateArgv   = "/usr/local/bin/portable-ghar-runner-gate hold"
)

type runnerConformanceObservation struct {
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

type runnerSessionObservation struct {
	Version                 string
	Conformance             runnerConformanceObservation
	InventoryDigest         string
	ConformanceDigest       string
	VerifyImageDigest       string
	ListenerVersionDigest   string
	ScannerEvidencePrepared bool
}

type runnerScannerEvidence struct {
	inventory   []byte
	conformance []byte
	verifyImage []byte
	listener    []byte
}

func (s *runnerSession) Observe(
	ctx context.Context,
) (runnerSessionObservation, error) {
	if s == nil || s.surface == nil || ctx == nil || ctx.Err() != nil {
		return runnerSessionObservation{}, ErrClosedCommand
	}
	s.mu.Lock()
	if s.observationTaken || s.scannerTaken ||
		len(s.scannerEvidence.inventory) != 0 {
		s.mu.Unlock()
		return runnerSessionObservation{}, ErrClosedCommand
	}
	s.observationTaken = true
	s.mu.Unlock()

	fail := func() (runnerSessionObservation, error) {
		s.mu.Lock()
		destroyRunnerScannerEvidence(&s.scannerEvidence)
		s.mu.Unlock()
		return runnerSessionObservation{}, ErrClosedCommand
	}

	firstInventory, err := s.captureHeldGateInventory(ctx)
	if err != nil {
		return fail()
	}
	defer zeroClosedBytes(firstInventory)

	conformanceDocument, conformance, err :=
		s.captureRunnerConformance(ctx)
	if err != nil {
		return fail()
	}
	defer zeroClosedBytes(conformanceDocument)

	secondInventory, err := s.captureHeldGateInventory(ctx)
	if err != nil {
		return fail()
	}
	defer zeroClosedBytes(secondInventory)
	if !bytes.Equal(firstInventory, secondInventory) {
		return fail()
	}

	expectedVersion := strings.TrimPrefix(
		buildinfo.Pins().UpstreamRunner.Version,
		"v",
	)
	if expectedVersion == "" {
		return fail()
	}
	verifyImage, err := s.captureRunnerVersion(
		ctx,
		closedRunnerGatePath,
		"verify-image",
		expectedVersion,
	)
	if err != nil {
		return fail()
	}
	defer zeroClosedBytes(verifyImage)
	listener, err := s.captureRunnerVersion(
		ctx,
		closedListenerPath,
		"--version",
		expectedVersion,
	)
	if err != nil {
		return fail()
	}
	defer zeroClosedBytes(listener)
	if !bytes.Equal(verifyImage, listener) {
		return fail()
	}

	finalInventory, err := s.captureHeldGateInventory(ctx)
	if err != nil {
		return fail()
	}
	defer zeroClosedBytes(finalInventory)
	if !bytes.Equal(firstInventory, finalInventory) {
		return fail()
	}

	evidence := runnerScannerEvidence{
		inventory:   append([]byte(nil), finalInventory...),
		conformance: append([]byte(nil), conformanceDocument...),
		verifyImage: append([]byte(nil), verifyImage...),
		listener:    append([]byte(nil), listener...),
	}
	observation := runnerSessionObservation{
		Version:     expectedVersion,
		Conformance: conformance,
		InventoryDigest: closedSessionDigest(
			"portable-ghar.task11.held-gate-inventory.v1\x00",
			finalInventory,
		),
		ConformanceDigest: closedSessionDigest(
			"portable-ghar.task11.runner-conformance.v1\x00",
			conformanceDocument,
		),
		VerifyImageDigest: closedSessionDigest(
			"portable-ghar.task11.verify-image.v1\x00",
			verifyImage,
		),
		ListenerVersionDigest: closedSessionDigest(
			"portable-ghar.task11.listener-version.v1\x00",
			listener,
		),
		ScannerEvidencePrepared: true,
	}
	if !validRunnerSessionObservation(
		observation,
		s.binding.User,
	) {
		destroyRunnerScannerEvidence(&evidence)
		return fail()
	}
	s.mu.Lock()
	if len(s.scannerEvidence.inventory) != 0 {
		s.mu.Unlock()
		destroyRunnerScannerEvidence(&evidence)
		return fail()
	}
	s.scannerEvidence = evidence
	s.mu.Unlock()
	return observation, nil
}

func (s *runnerSession) captureHeldGateInventory(
	ctx context.Context,
) ([]byte, error) {
	result, err := s.surface.executeExact(
		ctx,
		[]string{
			s.surface.config.DockerPath,
			"top",
			s.binding.Runner.id,
			"-eo",
			"pid=,args=",
		},
		nil,
		false,
	)
	defer destroyCommandResult(&result)
	if err != nil || !validHeldGateInventory(result.Stdout) {
		return nil, ErrClosedCommand
	}
	return append([]byte(nil), result.Stdout...), nil
}

func (s *runnerSession) captureRunnerConformance(
	ctx context.Context,
) ([]byte, runnerConformanceObservation, error) {
	result, err := s.surface.executeExact(
		ctx,
		[]string{
			s.surface.config.DockerPath,
			"exec",
			"--user",
			s.binding.User,
			s.binding.Runner.id,
			closedRunnerGatePath,
			"conformance-observe",
		},
		nil,
		false,
	)
	defer destroyCommandResult(&result)
	if err != nil {
		return nil, runnerConformanceObservation{}, ErrClosedCommand
	}
	observation, err := parseRunnerConformance(
		result.Stdout,
		s.binding.User,
	)
	if err != nil {
		return nil, runnerConformanceObservation{}, ErrClosedCommand
	}
	return append([]byte(nil), result.Stdout...), observation, nil
}

func (s *runnerSession) captureRunnerVersion(
	ctx context.Context,
	executable,
	operation,
	expected string,
) ([]byte, error) {
	result, err := s.surface.executeExact(
		ctx,
		[]string{
			s.surface.config.DockerPath,
			"exec",
			"--user",
			s.binding.User,
			s.binding.Runner.id,
			executable,
			operation,
		},
		nil,
		false,
	)
	defer destroyCommandResult(&result)
	if err != nil ||
		!bytes.Equal(result.Stdout, []byte(expected+"\n")) {
		return nil, ErrClosedCommand
	}
	return append([]byte(nil), result.Stdout...), nil
}

func parseRunnerConformance(
	document []byte,
	expectedUser string,
) (runnerConformanceObservation, error) {
	uid, gid, userOK := parseStaticNumericUser(expectedUser)
	if !userOK ||
		len(document) == 0 ||
		len(document) > 16<<10 ||
		document[len(document)-1] != '\n' {
		return runnerConformanceObservation{}, ErrClosedCommand
	}
	body := document[:len(document)-1]
	var observation runnerConformanceObservation
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		observation.Version != 1 ||
		uint64(observation.EUID) != uid ||
		uint64(observation.EGID) != gid ||
		linuxcap.ValidateEmpty(observation.Capabilities) != nil ||
		!observation.RawSocketDenied ||
		!observation.BPFDenied ||
		!observation.UnshareDenied ||
		!observation.SetNSDenied ||
		!observation.Clone3Denied ||
		!observation.NamespaceDenied ||
		!observation.ProcSysReadOnly ||
		!observation.ProcMasksPresent ||
		!observation.ControllerDatabaseAbsent ||
		!observation.DockerAuthorityAbsent ||
		!observation.HostControlAbsent ||
		!observation.SecretEnvironmentAbsent ||
		!observation.JITEnvironmentAbsent ||
		!observation.SyntheticTokenAbsent {
		return runnerConformanceObservation{}, ErrClosedCommand
	}
	canonical, err := json.Marshal(observation)
	if err != nil || !bytes.Equal(canonical, body) {
		return runnerConformanceObservation{}, ErrClosedCommand
	}
	return observation, nil
}

func validHeldGateInventory(document []byte) bool {
	if len(document) == 0 ||
		len(document) > 16<<10 ||
		document[len(document)-1] != '\n' ||
		bytes.Count(document, []byte{'\n'}) != 1 {
		return false
	}
	line := string(document[:len(document)-1])
	separator := strings.IndexByte(line, ' ')
	if separator <= 0 ||
		line[separator+1:] != closedHeldGateArgv {
		return false
	}
	pid := line[:separator]
	value, err := strconv.ParseUint(pid, 10, 64)
	return err == nil &&
		value != 0 &&
		strconv.FormatUint(value, 10) == pid
}

func validRunnerSessionObservation(
	observation runnerSessionObservation,
	expectedUser string,
) bool {
	uid, gid, ok := parseStaticNumericUser(expectedUser)
	return ok &&
		observation.Version != "" &&
		observation.Conformance.Version == 1 &&
		uint64(observation.Conformance.EUID) == uid &&
		uint64(observation.Conformance.EGID) == gid &&
		isLowerHex(observation.InventoryDigest, sha256.Size*2) &&
		isLowerHex(observation.ConformanceDigest, sha256.Size*2) &&
		isLowerHex(observation.VerifyImageDigest, sha256.Size*2) &&
		isLowerHex(observation.ListenerVersionDigest, sha256.Size*2) &&
		observation.ScannerEvidencePrepared
}

func (s *runnerSession) takeScannerEvidence() (runnerScannerEvidence, error) {
	if s == nil || s.surface == nil {
		return runnerScannerEvidence{}, ErrClosedCommand
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.observationTaken ||
		s.scannerTaken ||
		len(s.scannerEvidence.inventory) == 0 ||
		len(s.scannerEvidence.conformance) == 0 ||
		len(s.scannerEvidence.verifyImage) == 0 ||
		len(s.scannerEvidence.listener) == 0 {
		return runnerScannerEvidence{}, ErrClosedCommand
	}
	s.scannerTaken = true
	evidence := s.scannerEvidence
	s.scannerEvidence = runnerScannerEvidence{}
	return evidence, nil
}

func closedSessionDigest(domain string, document []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(document)
	return hex.EncodeToString(hash.Sum(nil))
}

func destroyRunnerScannerEvidence(evidence *runnerScannerEvidence) {
	if evidence == nil {
		return
	}
	zeroClosedBytes(evidence.inventory)
	zeroClosedBytes(evidence.conformance)
	zeroClosedBytes(evidence.verifyImage)
	zeroClosedBytes(evidence.listener)
	*evidence = runnerScannerEvidence{}
}

func zeroClosedBytes(document []byte) {
	for index := range document {
		document[index] = 0
	}
}
