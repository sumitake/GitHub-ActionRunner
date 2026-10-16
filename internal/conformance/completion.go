package conformance

// CompleteActualGitHubTransport completes the same pending report after the
// real canary. Its caller must derive result from durable observations bound
// to this report. Completion preserves every existing identity, target
// observation, case 1-14, and cleanup; it grants no acquisition authority by
// itself. The returned report must pass the normal conformance gate.
func CompleteActualGitHubTransport(pending Report, result ActualGitHubResult) (Report, error) {
	// reportAuthority returns a nonempty mode only for a validated report.
	mode, _ := reportAuthority(pending)
	if mode != AcquisitionCanaryOnly || result.pending {
		return Report{}, ErrInvalidReport
	}
	completed := pending
	completed.cases = cloneCaseEvidence(pending.cases)
	definition := requiredCaseRegistry[len(requiredCaseRegistry)-1]
	evidence, err := newPassedEvidence(
		completed.binding, definition, result.assertionCount,
		result.measurements, result.observationDigest,
	)
	if err != nil {
		return Report{}, err
	}
	completed.cases[len(completed.cases)-1] = evidence
	completed.status, completed.failure = aggregateReportStatus(
		completed.cases,
		TargetObservation{
			profileEvidenceDigest: completed.observedProfileEvidenceDigest,
			networkEvidenceDigest: completed.observedNetworkEvidenceDigest,
		},
		completed.binding, completed.cleanup,
	)
	completed.reportDigest, err = computeReportDigest(completed)
	if err != nil {
		return Report{}, ErrInvalidReport
	}
	completed.buildSeal, err = computeBuildSeal(completed)
	if err != nil {
		return Report{}, ErrInvalidReport
	}
	if err := validateReport(completed); err != nil {
		return Report{}, err
	}
	return completed, nil
}
