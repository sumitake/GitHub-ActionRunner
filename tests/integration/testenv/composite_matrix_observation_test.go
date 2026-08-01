package testenv

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type exactStubMatrixSource struct {
	requirement ObservationRequirement
	digest      string
	calls       int
}

func (s *exactStubMatrixSource) Observe(
	_ context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	s.calls++
	if s.calls != 1 || requirement != s.requirement {
		return matrixObservation{}, conformance.ErrObservation
	}
	return matrixObservation{
		Requirement:    requirement,
		AssertionCount: 1,
		Digest:         s.digest,
	}, nil
}

func finalizablePreparedLedger(
	t *testing.T,
) *preparedRuntimeEvidenceLedger {
	t.Helper()
	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	if _, _, err := ledger.acquire(context.Background()); err != nil {
		t.Fatalf("ledger acquire: %v", err)
	}
	ledger.mu.Lock()
	ledger.frozenThrough = runtimeEvidenceCase14
	ledger.mu.Unlock()
	return ledger
}

func preCanaryStubRoutes(
	digest string,
) map[ObservationID]matrixObservationSource {
	routes := make(map[ObservationID]matrixObservationSource)
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseActualGitHubTransport {
			continue
		}
		routes[requirement.ID] = &exactStubMatrixSource{
			requirement: requirement,
			digest:      digest,
		}
	}
	return routes
}

func matrixEvidenceBindingForTest(
	ledger *preparedRuntimeEvidenceLedger,
) matrixEvidenceBinding {
	prepared, _, frozen := ledger.snapshotAfterCase14()
	if !frozen {
		panic("ledger is not frozen")
	}
	return matrixEvidenceBinding{
		RunID:           inputDigestA,
		BuildID:         inputDigestB,
		FleetGeneration: 7,
		ProfileID:       "qts-capless-root",
		SlotIdentity:    "pghar-slot-0123456789abcdef",
		GraphDigest:     prepared.PolicyDigest,
	}
}

func TestCompositeMatrixSourceRoutesExactOrderAndFinalizesLedger(
	t *testing.T,
) {
	t.Parallel()

	ledger := finalizablePreparedLedger(t)
	source, err := newCompositeMatrixObservationSource(
		matrixEvidenceBindingForTest(ledger),
		ledger,
		preCanaryStubRoutes(inputDigestC),
	)
	if err != nil {
		t.Fatalf("newCompositeMatrixObservationSource: %v", err)
	}
	if _, err := source.FinalEvidenceDigest(); !errors.Is(
		err,
		conformance.ErrObservation,
	) {
		t.Fatalf("early final digest error = %v", err)
	}
	var count int
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseActualGitHubTransport {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		if observation.Requirement != requirement {
			t.Fatalf("observation %s = %+v", requirement.ID, observation)
		}
		count++
	}
	digest, err := source.FinalEvidenceDigest()
	if err != nil {
		t.Fatalf("FinalEvidenceDigest: %v", err)
	}
	if count == 0 || !isLowerHex(digest, 64) {
		t.Fatalf("count/digest = %d/%s", count, digest)
	}
	if _, err := source.FinalEvidenceDigest(); !errors.Is(
		err,
		conformance.ErrObservation,
	) {
		t.Fatalf("second final digest error = %v", err)
	}
}

func TestCompositeMatrixSourceDerivesTargetObservationFromPassedRows(
	t *testing.T,
) {
	t.Parallel()

	ledger := finalizablePreparedLedger(t)
	source, err := newCompositeMatrixObservationSource(
		matrixEvidenceBindingForTest(ledger),
		ledger,
		preCanaryStubRoutes(inputDigestC),
	)
	if err != nil {
		t.Fatalf("newCompositeMatrixObservationSource: %v", err)
	}
	for _, requirement := range preCanaryObservationRequirements() {
		if _, err := source.Observe(
			context.Background(),
			requirement,
		); err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
	}
	prepared, flood, frozen := ledger.snapshotAfterCase14()
	if !frozen {
		t.Fatal("prepared ledger is not frozen through Case 14")
	}
	observation, err := source.FinalObservation(context.Background())
	if err != nil {
		t.Fatalf("FinalObservation: %v", err)
	}
	if observation.Isolation != validTargetIsolation(
		prepared.PolicyDigest,
	) {
		t.Fatalf("isolation = %+v", observation.Isolation)
	}
	if observation.ProbeReport != prepared.ProbeReport ||
		observation.RunnerRoutesComplete != flood.Report.RoutesComplete {
		t.Fatalf("target observation = %+v", observation)
	}
	if _, err := source.FinalObservation(
		context.Background(),
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("second FinalObservation error = %v", err)
	}
	digest, err := source.FinalEvidenceDigest()
	if err != nil {
		t.Fatalf("FinalEvidenceDigest: %v", err)
	}
	if !isLowerHex(digest, 64) {
		t.Fatalf("final evidence digest = %q", digest)
	}
}

func TestCompositeMatrixSourceRejectsSubstitutedTargetFactRow(
	t *testing.T,
) {
	t.Parallel()

	ledger := finalizablePreparedLedger(t)
	source, err := newCompositeMatrixObservationSource(
		matrixEvidenceBindingForTest(ledger),
		ledger,
		preCanaryStubRoutes(inputDigestC),
	)
	if err != nil {
		t.Fatalf("newCompositeMatrixObservationSource: %v", err)
	}
	for _, requirement := range preCanaryObservationRequirements() {
		if _, err := source.Observe(
			context.Background(),
			requirement,
		); err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
	}
	source.mu.Lock()
	for index := range source.rows {
		if source.rows[index].ID == "cleanup-success" {
			source.rows[index].ID = "cleanup-substituted"
			break
		}
	}
	source.mu.Unlock()
	if _, err := source.FinalObservation(
		context.Background(),
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("substituted target fact error = %v", err)
	}
}

func TestCompositeMatrixSourceRejectsMissingReorderedOrChangedEvidence(
	t *testing.T,
) {
	t.Parallel()

	ledger := finalizablePreparedLedger(t)
	binding := matrixEvidenceBindingForTest(ledger)
	missing := preCanaryStubRoutes(inputDigestC)
	for id := range missing {
		delete(missing, id)
		break
	}
	if _, err := newCompositeMatrixObservationSource(
		binding,
		ledger,
		missing,
	); err != ErrFixtureStart {
		t.Fatalf("missing route error = %v", err)
	}

	requirements := RequiredObservationMatrix()
	reordered, err := newCompositeMatrixObservationSource(
		binding,
		ledger,
		preCanaryStubRoutes(inputDigestC),
	)
	if err != nil {
		t.Fatalf("new reordered source: %v", err)
	}
	if _, err := reordered.Observe(
		context.Background(),
		requirements[1],
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("reordered error = %v", err)
	}

	finalize := func(
		t *testing.T,
		rowDigest string,
	) string {
		t.Helper()
		ledger := finalizablePreparedLedger(t)
		source, err := newCompositeMatrixObservationSource(
			matrixEvidenceBindingForTest(ledger),
			ledger,
			preCanaryStubRoutes(rowDigest),
		)
		if err != nil {
			t.Fatalf("new source: %v", err)
		}
		for _, requirement := range RequiredObservationMatrix() {
			if requirement.Case ==
				conformance.CaseActualGitHubTransport {
				continue
			}
			if _, err := source.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf("Observe(%s): %v", requirement.ID, err)
			}
		}
		digest, err := source.FinalEvidenceDigest()
		if err != nil {
			t.Fatalf("FinalEvidenceDigest: %v", err)
		}
		return digest
	}
	first := finalize(t, inputDigestC)
	second := finalize(t, inputDigestD)
	if first == second {
		t.Fatal("changed row evidence preserved final ledger digest")
	}
}
