package testenv

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

func TestMatrixScannerCaptureSourceSealsExactCasesOneThroughFourOnce(
	t *testing.T,
) {
	t.Parallel()

	binding := matrixScannerBindingForTest()
	source, err := newMatrixScannerCaptureSource(binding)
	if err != nil {
		t.Fatalf("newMatrixScannerCaptureSource: %v", err)
	}
	capture, err := source.Take()
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !validMatrixScannerCapture(capture) ||
		len(capture.surfaces) != 4 {
		t.Fatalf("capture = %+v", capture)
	}
	expectedCases := []conformance.CaseID{
		conformance.CaseHostProfile,
		conformance.CaseNamespaceBaseline,
		conformance.CaseBrokerEgress,
		conformance.CaseMountAndSecretIsolation,
	}
	expectedIDs := []closedRuntimeSurfaceID{
		surfaceCase1Matrix,
		surfaceCase2Matrix,
		surfaceCase3Matrix,
		surfaceCase4Matrix,
	}
	for index, surface := range capture.surfaces {
		if surface.ID != expectedIDs[index] ||
			surface.Encoding !=
				closedRuntimeSurfaceStructuredJSON {
			t.Fatalf("surface %d = %+v", index, surface)
		}
		var document matrixScannerDocumentWire
		if err := json.Unmarshal(
			surface.Document,
			&document,
		); err != nil {
			t.Fatalf("Unmarshal surface %d: %v", index, err)
		}
		if document.SchemaVersion != 1 ||
			document.Binding != binding ||
			document.Case != expectedCases[index] ||
			!reflect.DeepEqual(
				document.Requirements,
				matrixScannerRequirements(
					expectedCases[index],
				),
			) {
			t.Fatalf(
				"surface %d document = %+v",
				index,
				document,
			)
		}
	}
	if _, err := source.Take(); err != ErrClosedCommand {
		t.Fatalf("second Take error = %v", err)
	}
}

func TestMatrixScannerCaptureRejectsBindingOrDocumentDrift(
	t *testing.T,
) {
	t.Parallel()

	invalid := matrixScannerBindingForTest()
	invalid.GraphDigest = ""
	if _, err := newMatrixScannerCaptureSource(
		invalid,
	); err != ErrFixtureStart {
		t.Fatalf("invalid binding error = %v", err)
	}

	source, err := newMatrixScannerCaptureSource(
		matrixScannerBindingForTest(),
	)
	if err != nil {
		t.Fatalf("newMatrixScannerCaptureSource: %v", err)
	}
	capture, err := source.Take()
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	capture.surfaces[2].Document[0] = '['
	if validMatrixScannerCapture(capture) {
		t.Fatal("accepted mutated matrix document")
	}
	destroyClosedRuntimeSurfaces(capture.surfaces)
}

func matrixScannerBindingForTest() matrixEvidenceBinding {
	return matrixEvidenceBinding{
		RunID:           inputDigestA,
		BuildID:         inputDigestB,
		FleetGeneration: 7,
		ProfileID:       "strict-linux",
		SlotIdentity:    "slot-test",
		GraphDigest:     inputDigestC,
	}
}
