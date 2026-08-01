package testenv

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
)

const runtimeSurfaceSequenceDomain = "portable-ghar.task11.runtime-surface-sequence.v1\x00"

type closedRuntimeSurfaceScanner struct {
	maximumSurfaceBytes uint64
}

type closedRuntimeSurfaceScanResult struct {
	Version        uint8
	SurfaceCount   uint32
	SequenceDigest string
	Clean          bool
}

func newClosedRuntimeSurfaceScanner(
	maximumSurfaceBytes uint64,
) (*closedRuntimeSurfaceScanner, error) {
	if maximumSurfaceBytes == 0 {
		return nil, ErrClosedCommand
	}
	return &closedRuntimeSurfaceScanner{
		maximumSurfaceBytes: maximumSurfaceBytes,
	}, nil
}

func (s *closedRuntimeSurfaceScanner) ScanSessionCapture(
	capture *scannerSessionCapture,
) (closedRuntimeSurfaceScanResult, error) {
	if capture == nil {
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	defer destroyScannerCapture(capture)
	if s == nil ||
		s.maximumSurfaceBytes == 0 ||
		!validScannerSessionCapture(*capture) {
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	return s.scanValidatedCapture(capture)
}

func (s *closedRuntimeSurfaceScanner) scanValidatedCapture(
	capture *scannerSessionCapture,
) (closedRuntimeSurfaceScanResult, error) {
	if s == nil ||
		s.maximumSurfaceBytes == 0 ||
		capture == nil ||
		len(capture.Surfaces) == 0 {
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(runtimeSurfaceSequenceDomain))
	for index := range capture.Surfaces {
		surface := capture.Surfaces[index]
		if uint64(len(surface.Document)) >
			s.maximumSurfaceBytes ||
			!validScannerSurfaceEncoding(
				surface.ID,
				surface.Encoding,
			) ||
			scanClosedRuntimeSurface(
				surface,
				capture.RunnerUser,
			) != nil {
			return closedRuntimeSurfaceScanResult{},
				ErrClosedCommand
		}
		writeRuntimeSurfaceSequenceField(
			hash,
			string(surface.ID),
		)
		_ = binary.Write(
			hash,
			binary.BigEndian,
			uint8(surface.Encoding),
		)
		_ = binary.Write(
			hash,
			binary.BigEndian,
			uint64(len(surface.Document)),
		)
		_, _ = hash.Write(surface.Document)
	}
	result := closedRuntimeSurfaceScanResult{
		Version:        1,
		SurfaceCount:   uint32(len(capture.Surfaces)),
		SequenceDigest: hex.EncodeToString(hash.Sum(nil)),
		Clean:          true,
	}
	if result.SurfaceCount == 0 ||
		!isLowerHex(result.SequenceDigest, sha256.Size*2) {
		return closedRuntimeSurfaceScanResult{}, ErrClosedCommand
	}
	return result, nil
}

func validScannerSurfaceEncoding(
	id closedRuntimeSurfaceID,
	encoding closedRuntimeSurfaceEncoding,
) bool {
	switch id {
	case surfaceAdapterInspect,
		surfaceBrokerInspect,
		surfaceRunnerInspect,
		surfaceRunnerConformance,
		surfaceAdapterEmptinessVerifier,
		surfacePolicyHelperApplication,
		surfaceAuthorityFilesystem,
		surfaceHeldSocketAudit,
		surfaceBrokerRelease,
		surfaceBrokerAudit,
		surfaceProxyVerifier,
		surfaceBrokerNamespaceVerifier,
		surfaceRunnerPreNamespace,
		surfaceRunnerFinalNamespace,
		surfaceLoopbackFloodVerifier,
		surfacePreparedRuntime,
		surfaceClosedDenials,
		surfaceCase1Matrix,
		surfaceCase2Matrix,
		surfaceCase3Matrix,
		surfaceCase4Matrix,
		surfaceFixedNegativeProjection:
		return encoding == closedRuntimeSurfaceStructuredJSON
	case surfaceAdapterTop,
		surfaceAdapterLogsStdout,
		surfaceAdapterLogsStderr,
		surfaceBrokerTop,
		surfaceBrokerLogsStdout,
		surfaceBrokerLogsStderr,
		surfaceRunnerFinalInventory,
		surfaceRunnerLogsStdout,
		surfaceRunnerLogsStderr,
		surfaceRunnerVerifyImage,
		surfaceRunnerListenerVersion,
		surfaceAdapterEmptinessAbsence,
		surfacePolicyHelperAbsence,
		surfaceAdapterPeerBind,
		surfaceProxyVerifierAbsence,
		surfaceBrokerNamespaceAbsence,
		surfaceLoopbackFloodAbsence:
		return encoding == closedRuntimeSurfaceRaw
	default:
		return false
	}
}

func scanClosedRuntimeSurface(
	surface closedRuntimeSurface,
	runnerUser string,
) error {
	switch surface.ID {
	case surfaceAdapterInspect,
		surfaceBrokerInspect,
		surfaceRunnerInspect:
		wire, err := decodeScannerInspectProjection(surface.Document)
		if err != nil ||
			scannerInspectProjectionContainsSecret(wire) {
			return ErrClosedCommand
		}
		return nil
	case surfaceRunnerConformance:
		wire, err := parseRunnerConformance(
			surface.Document,
			runnerUser,
		)
		if err != nil ||
			runnerConformanceContainsSecret(wire) {
			return ErrClosedCommand
		}
		return nil
	case surfacePreparedRuntime:
		if !validSupplementPreparedRuntime(surface.Document) {
			return ErrClosedCommand
		}
		return nil
	case surfaceClosedDenials:
		if !validSupplementClosedDenials(surface.Document) {
			return ErrClosedCommand
		}
		return nil
	case surfaceFixedNegativeProjection:
		if !validSupplementFixedProjection(surface.Document) {
			return ErrClosedCommand
		}
		return nil
	case surfaceAdapterEmptinessVerifier,
		surfacePolicyHelperApplication,
		surfaceAuthorityFilesystem,
		surfaceHeldSocketAudit,
		surfaceBrokerRelease,
		surfaceBrokerAudit,
		surfaceProxyVerifier,
		surfaceBrokerNamespaceVerifier,
		surfaceRunnerPreNamespace,
		surfaceRunnerFinalNamespace,
		surfaceLoopbackFloodVerifier,
		surfaceCase1Matrix,
		surfaceCase2Matrix,
		surfaceCase3Matrix,
		surfaceCase4Matrix:
		value, err := parseGenericCanonicalJSONLine(
			surface.Document,
		)
		if err != nil || genericJSONValuesContainSecret(value) {
			return ErrClosedCommand
		}
		return nil
	default:
		if containsSecretShapedBytes(surface.Document) {
			return ErrClosedCommand
		}
		return nil
	}
}

func decodeScannerInspectProjection(
	document []byte,
) (scannerInspectProjectionWire, error) {
	if parseScannerInspectProjection(document) != nil {
		return scannerInspectProjectionWire{}, ErrClosedCommand
	}
	body := document[:len(document)-1]
	var wire scannerInspectProjectionWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return scannerInspectProjectionWire{}, ErrClosedCommand
	}
	return wire, nil
}

func scannerInspectProjectionContainsSecret(
	wire scannerInspectProjectionWire,
) bool {
	var values []string
	values = append(values, wire.Environment...)
	values = append(values, wire.Entrypoint...)
	values = append(values, wire.Command...)
	for key, value := range wire.Labels {
		values = append(values, key, value)
	}
	for _, mount := range wire.Mounts {
		values = append(
			values,
			mount.Type,
			mount.Name,
			mount.Source,
			mount.Destination,
			mount.Driver,
			mount.Mode,
			mount.Propagation,
		)
	}
	values = append(values, wire.Binds...)
	for _, device := range wire.Devices {
		values = append(
			values,
			device.PathOnHost,
			device.PathInContainer,
			device.CgroupPermissions,
		)
	}
	values = append(values, wire.SecurityOptions...)
	for _, value := range values {
		if containsSecretShapedString(value) {
			return true
		}
	}
	return false
}

func runnerConformanceContainsSecret(
	wire runnerConformanceObservation,
) bool {
	for _, value := range []string{
		wire.Capabilities.Effective,
		wire.Capabilities.Permitted,
		wire.Capabilities.Inheritable,
		wire.Capabilities.Bounding,
		wire.Capabilities.Ambient,
	} {
		if containsSecretShapedString(value) {
			return true
		}
	}
	return false
}

func containsSecretShapedBytes(document []byte) bool {
	lower := bytes.ToLower(document)
	defer zeroClosedBytes(lower)
	for _, forbidden := range secretShapeNeedles {
		if bytes.Contains(lower, []byte(forbidden)) {
			return true
		}
	}
	return false
}

func writeRuntimeSurfaceSequenceField(
	writer io.Writer,
	value string,
) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}
