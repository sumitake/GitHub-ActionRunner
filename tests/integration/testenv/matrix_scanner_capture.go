package testenv

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type matrixScannerRequirementWire struct {
	ID        ObservationID          `json:"id"`
	Case      conformance.CaseID     `json:"case"`
	Layer     conformance.ProofLayer `json:"layer"`
	Source    ObservationSource      `json:"source"`
	Operation string                 `json:"operation"`
	MaxBytes  uint64                 `json:"max_bytes"`
	Parser    string                 `json:"parser"`
}

type matrixScannerDocumentWire struct {
	SchemaVersion uint8                          `json:"schema_version"`
	Binding       matrixEvidenceBinding          `json:"binding"`
	Case          conformance.CaseID             `json:"case"`
	Requirements  []matrixScannerRequirementWire `json:"requirements"`
}

type matrixScannerCaptureSource struct {
	binding matrixEvidenceBinding

	mu    sync.Mutex
	taken bool
}

func newMatrixScannerCaptureSource(
	binding matrixEvidenceBinding,
) (*matrixScannerCaptureSource, error) {
	if !validMatrixEvidenceBinding(binding) ||
		ValidateObservationMatrix(
			RequiredObservationMatrix(),
		) != nil {
		return nil, ErrFixtureStart
	}
	for _, caseID := range matrixScannerCases() {
		if len(matrixScannerRequirements(caseID)) == 0 {
			return nil, ErrFixtureStart
		}
	}
	return &matrixScannerCaptureSource{
		binding: binding,
	}, nil
}

func (s *matrixScannerCaptureSource) Take() (
	matrixScannerCapture,
	error,
) {
	if s == nil {
		return matrixScannerCapture{}, ErrClosedCommand
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taken {
		return matrixScannerCapture{}, ErrClosedCommand
	}
	s.taken = true

	capture := matrixScannerCapture{
		surfaces: make([]closedRuntimeSurface, 0, 4),
		valid:    true,
	}
	for index, caseID := range matrixScannerCases() {
		document, err := canonicalScannerJSONLine(
			matrixScannerDocumentWire{
				SchemaVersion: 1,
				Binding:       s.binding,
				Case:          caseID,
				Requirements: matrixScannerRequirements(
					caseID,
				),
			},
		)
		if err != nil {
			destroyClosedRuntimeSurfaces(capture.surfaces)
			return matrixScannerCapture{}, ErrClosedCommand
		}
		capture.surfaces = append(
			capture.surfaces,
			closedRuntimeSurface{
				ID:       matrixScannerSurfaceIDs()[index],
				Encoding: closedRuntimeSurfaceStructuredJSON,
				Document: document,
			},
		)
	}
	if !validMatrixScannerCaptureForBinding(
		capture,
		s.binding,
	) {
		destroyClosedRuntimeSurfaces(capture.surfaces)
		return matrixScannerCapture{}, ErrClosedCommand
	}
	return capture, nil
}

func matrixScannerCases() []conformance.CaseID {
	return []conformance.CaseID{
		conformance.CaseHostProfile,
		conformance.CaseNamespaceBaseline,
		conformance.CaseBrokerEgress,
		conformance.CaseMountAndSecretIsolation,
	}
}

func matrixScannerSurfaceIDs() []closedRuntimeSurfaceID {
	return []closedRuntimeSurfaceID{
		surfaceCase1Matrix,
		surfaceCase2Matrix,
		surfaceCase3Matrix,
		surfaceCase4Matrix,
	}
}

func matrixScannerRequirements(
	caseID conformance.CaseID,
) []matrixScannerRequirementWire {
	var result []matrixScannerRequirementWire
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != caseID {
			continue
		}
		result = append(
			result,
			matrixScannerRequirementWire(requirement),
		)
	}
	return result
}

func validMatrixScannerCaptureForBinding(
	capture matrixScannerCapture,
	binding matrixEvidenceBinding,
) bool {
	cases := matrixScannerCases()
	ids := matrixScannerSurfaceIDs()
	if !capture.valid ||
		!validMatrixEvidenceBinding(binding) ||
		len(capture.surfaces) != len(cases) ||
		len(ids) != len(cases) {
		return false
	}
	for index, surface := range capture.surfaces {
		if surface.ID != ids[index] ||
			surface.Encoding !=
				closedRuntimeSurfaceStructuredJSON ||
			!validMatrixScannerDocument(
				surface.Document,
				binding,
				cases[index],
			) {
			return false
		}
	}
	return true
}

func validMatrixScannerDocument(
	document []byte,
	binding matrixEvidenceBinding,
	caseID conformance.CaseID,
) bool {
	if len(document) == 0 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire matrixScannerDocumentWire
	if decoder.Decode(&wire) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		wire.SchemaVersion != 1 ||
		wire.Binding != binding ||
		wire.Case != caseID ||
		!slices.Equal(
			wire.Requirements,
			matrixScannerRequirements(caseID),
		) {
		return false
	}
	canonical, err := canonicalScannerJSONLine(wire)
	if err != nil {
		return false
	}
	equal := bytes.Equal(canonical, document)
	zeroClosedBytes(canonical)
	return equal
}
