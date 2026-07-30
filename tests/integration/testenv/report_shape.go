package testenv

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

var ErrConformanceTerminalReport = errors.New(
	"testenv: conformance terminal report invalid",
)

const zeroReportDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// ValidateConformanceTerminalReport accepts only one of the two closed Task 11
// terminal shapes: source evidence with the actual-GitHub case pending, or an
// authentic canary with every required case passed.
func ValidateConformanceTerminalReport(report conformance.Report) error {
	if _, err := conformance.MarshalReport(report); err != nil {
		return ErrConformanceTerminalReport
	}

	binding := report.Binding()
	for _, digest := range []string{
		binding.BuildID(),
		binding.RuntimeManifestDigest(),
		binding.PrivateOverlayDigest(),
		binding.ConformanceInputDigest(),
		binding.AuthorizationDigest(),
		binding.RunID(),
		binding.ExpectedProfileEvidenceDigest(),
		binding.ExpectedNetworkEvidenceDigest(),
		binding.PlanDigest(),
		binding.Digest(),
		report.ObservedProfileEvidenceDigest(),
		report.ObservedNetworkEvidenceDigest(),
		report.Digest(),
		report.BuildSeal(),
	} {
		if !isNonzeroLowerHexDigest(digest) {
			return ErrConformanceTerminalReport
		}
	}
	if report.ObservedProfileEvidenceDigest() !=
		binding.ExpectedProfileEvidenceDigest() ||
		report.ObservedNetworkEvidenceDigest() !=
			binding.ExpectedNetworkEvidenceDigest() {
		return ErrConformanceTerminalReport
	}

	required := conformance.RequiredCases()
	cases := report.Cases()
	if len(cases) != len(required) {
		return ErrConformanceTerminalReport
	}
	for index, requiredID := range required {
		evidence := cases[index]
		requiredLayer, ok := conformance.RequiredLayer(requiredID)
		if !ok ||
			evidence.ID() != requiredID ||
			evidence.Layer() != requiredLayer ||
			!isNonzeroLowerHexDigest(evidence.ObservationDigest()) ||
			!isNonzeroLowerHexDigest(evidence.EvidenceDigest()) {
			return ErrConformanceTerminalReport
		}
		if index < len(required)-1 &&
			(evidence.Status() != conformance.StatusPassed ||
				evidence.Failure() != conformance.FailureNone ||
				evidence.AssertionCount() == 0) {
			return ErrConformanceTerminalReport
		}
	}

	cleanup := report.Cleanup()
	if cleanup.Status() != conformance.StatusPassed ||
		cleanup.Failure() != conformance.FailureNone ||
		cleanup.AssertionCount() == 0 ||
		!isNonzeroLowerHexDigest(cleanup.ObservationDigest()) ||
		!isNonzeroLowerHexDigest(cleanup.EvidenceDigest()) {
		return ErrConformanceTerminalReport
	}

	actual := cases[len(cases)-1]
	switch report.Status() {
	case conformance.StatusPending:
		if report.Failure() != conformance.FailureActualProofPending ||
			actual.Status() != conformance.StatusPending ||
			actual.Failure() != conformance.FailureActualProofPending ||
			actual.AssertionCount() != 0 ||
			len(actual.Measurements()) != 0 {
			return ErrConformanceTerminalReport
		}
	case conformance.StatusPassed:
		if report.Failure() != conformance.FailureNone ||
			actual.Status() != conformance.StatusPassed ||
			actual.Failure() != conformance.FailureNone ||
			actual.AssertionCount() == 0 {
			return ErrConformanceTerminalReport
		}
	default:
		return ErrConformanceTerminalReport
	}
	return nil
}

func isNonzeroLowerHexDigest(value string) bool {
	if len(value) != 64 ||
		value == zeroReportDigest ||
		strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
