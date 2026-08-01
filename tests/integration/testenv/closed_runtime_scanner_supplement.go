package testenv

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const completeRuntimeSurfaceCount = 39

type oneShotTranscriptCapture struct {
	surfaces           []closedRuntimeSurface
	commandDigest      string
	mountAbsenceDigest string
	valid              bool
}

type matrixScannerCapture struct {
	surfaces []closedRuntimeSurface
	valid    bool
}

type scannerSupplementInput struct {
	Prepared          fixtureRuntimeObservation
	Flood             fixtureFloodObservation
	Graph             networkjail.DecisionGraph
	ClosedDenials     closedDenialsSessionObservation
	ClosedDocument    []byte
	RunnerConformance runnerConformanceObservation
	OneShots          oneShotTranscriptCapture
	MatrixDocuments   matrixScannerCapture
}

type fixedNegativeProjectionWire struct {
	Version                   uint8         `json:"version"`
	Capabilities              linuxcap.Wire `json:"capabilities"`
	ControllerDatabaseAbsent  bool          `json:"controller_database_absent"`
	DockerAuthorityAbsent     bool          `json:"docker_authority_absent"`
	HostControlAbsent         bool          `json:"host_control_absent"`
	SecretEnvironmentAbsent   bool          `json:"secret_environment_absent"`
	JITEnvironmentAbsent      bool          `json:"jit_environment_absent"`
	SyntheticTokenAbsent      bool          `json:"synthetic_token_absent"`
	RunnerMountAuditDigest    string        `json:"runner_mount_audit_digest"`
	OneShotVerifierSpecDigest string        `json:"one_shot_verifier_spec_digest"`
	PolicyApplicationDigest   string        `json:"policy_application_digest"`
	HelperCapabilityDigest    string        `json:"helper_capability_digest"`
}

func (s *closedRuntimeSurfaceScanner) ScanCompleteCapture(
	capture *scannerSessionCapture,
	supplements *scannerSupplementInput,
) (closedRuntimeSurfaceScanResult, error) {
	if capture == nil || supplements == nil {
		if capture != nil {
			destroyScannerCapture(capture)
		}
		if supplements != nil {
			destroyScannerSupplementInput(supplements)
		}
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	defer destroyScannerCapture(capture)
	defer destroyScannerSupplementInput(supplements)
	if s == nil ||
		s.maximumSurfaceBytes == 0 ||
		!validScannerSessionCapture(*capture) {
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	additional, err := buildScannerSupplementSurfaces(
		*capture,
		supplements,
	)
	if err != nil {
		destroyClosedRuntimeSurfaces(additional)
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	capture.Surfaces = append(capture.Surfaces, additional...)
	if !validCompleteRuntimeCapture(*capture) {
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	return s.scanValidatedCapture(capture)
}

func buildScannerSupplementSurfaces(
	commandCapture scannerSessionCapture,
	input *scannerSupplementInput,
) ([]closedRuntimeSurface, error) {
	if input == nil ||
		!validFixtureRuntimeObservation(input.Prepared) ||
		!validFixtureFloodObservation(
			input.Flood,
			uint32(input.Flood.Report.Attempts),
		) ||
		input.Prepared.AdapterNamespace !=
			input.Flood.Report.Namespace ||
		!validClosedDenialsSessionObservation(
			input.ClosedDenials,
			input.Graph,
		) ||
		input.Graph.Digest().String() != input.Prepared.PolicyDigest ||
		!validRunnerSessionConformanceForSupplement(
			input.RunnerConformance,
			commandCapture.RunnerUser,
		) ||
		!validOneShotTranscriptCapture(input.OneShots) ||
		!validMatrixScannerCapture(input.MatrixDocuments) {
		return nil, ErrClosedCommand
	}
	wire, canonicalClosed, err := parseClosedDenialsObservation(
		input.ClosedDocument,
		input.Graph,
	)
	if err != nil ||
		closedSessionDigest(
			"portable-ghar.task11.closed-denials.v1\x00",
			canonicalClosed,
		) != input.ClosedDenials.Digest ||
		wire.PolicyDigest != input.Prepared.PolicyDigest {
		zeroClosedBytes(canonicalClosed)
		return nil, ErrClosedCommand
	}
	zeroClosedBytes(canonicalClosed)

	preparedDocument, err := canonicalScannerJSONLine(
		matrixRuntimeEvidenceFrom(input.Prepared, input.Flood),
	)
	if err != nil {
		return nil, ErrClosedCommand
	}
	fixedDocument, err := canonicalScannerJSONLine(
		fixedNegativeProjectionWire{
			Version:                   1,
			Capabilities:              input.RunnerConformance.Capabilities,
			ControllerDatabaseAbsent:  input.RunnerConformance.ControllerDatabaseAbsent,
			DockerAuthorityAbsent:     input.RunnerConformance.DockerAuthorityAbsent,
			HostControlAbsent:         input.RunnerConformance.HostControlAbsent,
			SecretEnvironmentAbsent:   input.RunnerConformance.SecretEnvironmentAbsent,
			JITEnvironmentAbsent:      input.RunnerConformance.JITEnvironmentAbsent,
			SyntheticTokenAbsent:      input.RunnerConformance.SyntheticTokenAbsent,
			RunnerMountAuditDigest:    input.Prepared.RunnerAuditDigest,
			OneShotVerifierSpecDigest: input.Prepared.VerifierSpecDigest,
			PolicyApplicationDigest:   input.Prepared.PolicyApplicationDigest,
			HelperCapabilityDigest:    input.Prepared.HelperCapabilityDigest,
		},
	)
	if err != nil {
		zeroClosedBytes(preparedDocument)
		return nil, ErrClosedCommand
	}
	surfaces := make(
		[]closedRuntimeSurface,
		0,
		len(input.OneShots.surfaces)+
			len(input.MatrixDocuments.surfaces)+3,
	)
	surfaces = append(
		surfaces,
		takeClosedRuntimeSurfaces(&input.OneShots.surfaces)...,
	)
	input.OneShots.valid = false
	surfaces = append(surfaces, closedRuntimeSurface{
		ID:       surfacePreparedRuntime,
		Encoding: closedRuntimeSurfaceStructuredJSON,
		Document: preparedDocument,
	})
	surfaces = append(surfaces, closedRuntimeSurface{
		ID:       surfaceClosedDenials,
		Encoding: closedRuntimeSurfaceStructuredJSON,
		Document: takeClosedBytes(&input.ClosedDocument),
	})
	surfaces = append(
		surfaces,
		takeClosedRuntimeSurfaces(
			&input.MatrixDocuments.surfaces,
		)...,
	)
	input.MatrixDocuments.valid = false
	surfaces = append(surfaces, closedRuntimeSurface{
		ID:       surfaceFixedNegativeProjection,
		Encoding: closedRuntimeSurfaceStructuredJSON,
		Document: fixedDocument,
	})
	return surfaces, nil
}

func validRunnerSessionConformanceForSupplement(
	observation runnerConformanceObservation,
	user string,
) bool {
	uid, gid, ok := parseStaticNumericUser(user)
	return ok &&
		observation.Version == 1 &&
		uint64(observation.EUID) == uid &&
		uint64(observation.EGID) == gid &&
		linuxcap.ValidateEmpty(observation.Capabilities) == nil &&
		observation.RawSocketDenied &&
		observation.BPFDenied &&
		observation.UnshareDenied &&
		observation.SetNSDenied &&
		observation.Clone3Denied &&
		observation.NamespaceDenied &&
		observation.ProcSysReadOnly &&
		observation.ProcMasksPresent &&
		observation.ControllerDatabaseAbsent &&
		observation.DockerAuthorityAbsent &&
		observation.HostControlAbsent &&
		observation.SecretEnvironmentAbsent &&
		observation.JITEnvironmentAbsent &&
		observation.SyntheticTokenAbsent
}

func canonicalScannerJSONLine(value any) ([]byte, error) {
	if value == nil {
		return nil, ErrClosedCommand
	}
	document, err := json.Marshal(value)
	if err != nil || len(document) == 0 {
		return nil, ErrClosedCommand
	}
	return append(document, '\n'), nil
}

func validOneShotTranscriptCapture(
	capture oneShotTranscriptCapture,
) bool {
	expected := oneShotRuntimeSurfaceOrder()
	if !capture.valid ||
		!isLowerHex(capture.commandDigest, 64) ||
		!isLowerHex(capture.mountAbsenceDigest, 64) ||
		capture.commandDigest == capture.mountAbsenceDigest ||
		len(capture.surfaces) != len(expected) {
		return false
	}
	for index, id := range expected {
		surface := capture.surfaces[index]
		if surface.ID != id ||
			!validScannerSurfaceEncoding(
				surface.ID,
				surface.Encoding,
			) ||
			!validTask11TranscriptDocument(surface) {
			return false
		}
	}
	return true
}

func validTask11TranscriptDocument(
	surface closedRuntimeSurface,
) bool {
	switch surface.Encoding {
	case closedRuntimeSurfaceStructuredJSON:
		value, err := parseGenericCanonicalJSONLine(
			surface.Document,
		)
		return err == nil &&
			!genericJSONValuesContainSecret(value)
	case closedRuntimeSurfaceRaw:
		switch surface.ID {
		case surfaceAdapterPeerBind:
			return bytes.Equal(surface.Document, []byte("OK\n"))
		case surfaceAdapterEmptinessAbsence,
			surfacePolicyHelperAbsence,
			surfaceProxyVerifierAbsence,
			surfaceBrokerNamespaceAbsence,
			surfaceLoopbackFloodAbsence:
			return len(surface.Document) == 0
		}
	}
	return false
}

func validMatrixScannerCapture(capture matrixScannerCapture) bool {
	if !capture.valid || len(capture.surfaces) != 4 ||
		len(capture.surfaces[0].Document) == 0 {
		return false
	}
	decoder := json.NewDecoder(
		bytes.NewReader(capture.surfaces[0].Document),
	)
	decoder.DisallowUnknownFields()
	var first matrixScannerDocumentWire
	if decoder.Decode(&first) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	return validMatrixScannerCaptureForBinding(
		capture,
		first.Binding,
	)
}

func validCompleteRuntimeCapture(capture scannerSessionCapture) bool {
	expected := completeRuntimeSurfaceOrder()
	if len(expected) != completeRuntimeSurfaceCount ||
		len(capture.Surfaces) != len(expected) {
		return false
	}
	for index, id := range expected {
		surface := capture.Surfaces[index]
		if surface.ID != id ||
			!validScannerSurfaceEncoding(
				surface.ID,
				surface.Encoding,
			) {
			return false
		}
	}
	return true
}

func completeRuntimeSurfaceOrder() []closedRuntimeSurfaceID {
	order := append(
		[]closedRuntimeSurfaceID(nil),
		commandRuntimeSurfaceOrder()...,
	)
	order = append(order, oneShotRuntimeSurfaceOrder()...)
	order = append(
		order,
		surfacePreparedRuntime,
		surfaceClosedDenials,
		surfaceCase1Matrix,
		surfaceCase2Matrix,
		surfaceCase3Matrix,
		surfaceCase4Matrix,
		surfaceFixedNegativeProjection,
	)
	return order
}

func oneShotRuntimeSurfaceOrder() []closedRuntimeSurfaceID {
	return []closedRuntimeSurfaceID{
		surfaceAdapterEmptinessVerifier,
		surfaceAdapterEmptinessAbsence,
		surfacePolicyHelperApplication,
		surfacePolicyHelperAbsence,
		surfaceAuthorityFilesystem,
		surfaceHeldSocketAudit,
		surfaceBrokerRelease,
		surfaceBrokerAudit,
		surfaceAdapterPeerBind,
		surfaceProxyVerifier,
		surfaceProxyVerifierAbsence,
		surfaceBrokerNamespaceVerifier,
		surfaceBrokerNamespaceAbsence,
		surfaceRunnerPreNamespace,
		surfaceRunnerFinalNamespace,
		surfaceLoopbackFloodVerifier,
		surfaceLoopbackFloodAbsence,
	}
}

func commandRuntimeSurfaceOrder() []closedRuntimeSurfaceID {
	return []closedRuntimeSurfaceID{
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
}

func takeClosedRuntimeSurfaces(
	surfaces *[]closedRuntimeSurface,
) []closedRuntimeSurface {
	if surfaces == nil {
		return nil
	}
	value := *surfaces
	*surfaces = nil
	return value
}

func destroyScannerSupplementInput(input *scannerSupplementInput) {
	if input == nil {
		return
	}
	zeroClosedBytes(input.ClosedDocument)
	input.ClosedDocument = nil
	destroyClosedRuntimeSurfaces(input.OneShots.surfaces)
	input.OneShots = oneShotTranscriptCapture{}
	destroyClosedRuntimeSurfaces(input.MatrixDocuments.surfaces)
	input.MatrixDocuments = matrixScannerCapture{}
	*input = scannerSupplementInput{}
}

func destroyClosedRuntimeSurfaces(surfaces []closedRuntimeSurface) {
	for index := range surfaces {
		zeroClosedBytes(surfaces[index].Document)
		surfaces[index].Document = nil
	}
}

func parseGenericCanonicalJSONLine(document []byte) (any, error) {
	if len(document) == 0 ||
		document[len(document)-1] != '\n' {
		return nil, ErrClosedCommand
	}
	body := document[:len(document)-1]
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&value); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrClosedCommand
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil ||
		!bytes.Equal(compact.Bytes(), body) {
		zeroClosedBytes(compact.Bytes())
		return nil, ErrClosedCommand
	}
	zeroClosedBytes(compact.Bytes())
	return value, nil
}

func genericJSONValuesContainSecret(value any) bool {
	switch typed := value.(type) {
	case string:
		return containsSecretShapedString(typed)
	case []any:
		for _, item := range typed {
			if genericJSONValuesContainSecret(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if genericJSONValuesContainSecret(item) {
				return true
			}
		}
	}
	return false
}

func validSupplementPreparedRuntime(
	document []byte,
) bool {
	value, err := parseGenericCanonicalJSONLine(document)
	return err == nil && !genericJSONValuesContainSecret(value)
}

func validSupplementClosedDenials(
	document []byte,
) bool {
	value, err := parseGenericCanonicalJSONLine(document)
	if err != nil || genericJSONValuesContainSecret(value) {
		return false
	}
	var wire closedDenialsObservationWire
	decoder := json.NewDecoder(
		bytes.NewReader(document[:len(document)-1]),
	)
	decoder.DisallowUnknownFields()
	return decoder.Decode(&wire) == nil &&
		decoder.Decode(&struct{}{}) == io.EOF &&
		wire.Version == 1 &&
		linuxcap.ValidateEmpty(wire.Capabilities) == nil &&
		wire.Completed
}

func validSupplementFixedProjection(
	document []byte,
) bool {
	value, err := parseGenericCanonicalJSONLine(document)
	if err != nil || genericJSONValuesContainSecret(value) {
		return false
	}
	var wire fixedNegativeProjectionWire
	decoder := json.NewDecoder(
		bytes.NewReader(document[:len(document)-1]),
	)
	decoder.DisallowUnknownFields()
	return decoder.Decode(&wire) == nil &&
		decoder.Decode(&struct{}{}) == io.EOF &&
		wire.Version == 1 &&
		linuxcap.ValidateEmpty(wire.Capabilities) == nil &&
		wire.ControllerDatabaseAbsent &&
		wire.DockerAuthorityAbsent &&
		wire.HostControlAbsent &&
		wire.SecretEnvironmentAbsent &&
		wire.JITEnvironmentAbsent &&
		wire.SyntheticTokenAbsent &&
		isLowerHex(wire.RunnerMountAuditDigest, 64) &&
		isLowerHex(wire.OneShotVerifierSpecDigest, 64) &&
		isLowerHex(wire.PolicyApplicationDigest, 64) &&
		isLowerHex(wire.HelperCapabilityDigest, 64)
}
