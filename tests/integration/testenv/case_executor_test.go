package testenv

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type fakeMatrixObservationSource struct {
	fail       ObservationID
	substitute bool
	calls      []ObservationID
}

func (s *fakeMatrixObservationSource) Observe(
	_ context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	s.calls = append(s.calls, requirement.ID)
	if requirement.ID == s.fail {
		return matrixObservation{}, errors.New("closed observation failure")
	}
	if s.substitute {
		requirement.ID = "substituted"
	}
	observation := matrixObservation{
		Requirement:    requirement,
		AssertionCount: 1,
		Digest:         inputDigestA,
	}
	if requirement.Case == conformance.CaseReclamationSeries &&
		requirement.ID == "reclamation-high-water" {
		observation.Measurements = []conformance.MeasurementInput{{
			Name: "sample_count", Value: 3, Unit: "count",
		}}
	}
	return observation, nil
}

func TestMatrixCaseExecutorConsumesEveryRequirementExactlyOnce(t *testing.T) {
	t.Parallel()

	source := &fakeMatrixObservationSource{}
	executor, err := newMatrixCaseExecutor(source)
	if err != nil {
		t.Fatalf("newMatrixCaseExecutor: %v", err)
	}
	for _, id := range []conformance.ActualHostCaseID{
		conformance.ActualHostProfile,
		conformance.ActualNamespaceBaseline,
		conformance.ActualBrokerEgress,
		conformance.ActualMountAndSecretIsolation,
		conformance.ActualRunnerSandbox,
		conformance.ActualRunnerPayload,
	} {
		if _, err := executor.RunActualHost(
			context.Background(),
			id,
		); err != nil {
			t.Fatalf("RunActualHost(%d): %v", id, err)
		}
	}
	for _, id := range []conformance.SyntheticCaseID{
		conformance.SyntheticOneJob,
		conformance.SyntheticCleanupMatrix,
		conformance.SyntheticReclamationSeries,
	} {
		if _, err := executor.RunSynthetic(
			context.Background(),
			id,
		); err != nil {
			t.Fatalf("RunSynthetic(%d): %v", id, err)
		}
	}
	if _, err := executor.RunActualHost(
		context.Background(),
		conformance.ActualProxyToolCompatibility,
	); err != nil {
		t.Fatalf("RunActualHost(proxy tools): %v", err)
	}
	for _, id := range []conformance.SyntheticCaseID{
		conformance.SyntheticSeedIsolation,
		conformance.SyntheticWatchdogRecovery,
		conformance.SyntheticLegacyFenceRecovery,
		conformance.SyntheticNoncancellableShutdown,
	} {
		if _, err := executor.RunSynthetic(
			context.Background(),
			id,
		); err != nil {
			t.Fatalf("RunSynthetic(%d): %v", id, err)
		}
	}
	var expected []ObservationID
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseActualGitHubTransport {
			expected = append(expected, requirement.ID)
		}
	}
	if len(source.calls) != len(expected) {
		t.Fatalf("calls = %d, want %d", len(source.calls), len(expected))
	}
	for index := range expected {
		if source.calls[index] != expected[index] {
			t.Fatalf(
				"call[%d] = %q, want %q",
				index,
				source.calls[index],
				expected[index],
			)
		}
	}
}

func TestMatrixCaseExecutorRejectsFailureAndSubstitution(t *testing.T) {
	t.Parallel()

	requirements := RequiredObservationMatrix()
	var hostRequirement ObservationID
	for _, requirement := range requirements {
		if requirement.Case == conformance.CaseHostProfile {
			hostRequirement = requirement.ID
			break
		}
	}
	for _, test := range []struct {
		name   string
		source *fakeMatrixObservationSource
	}{
		{
			name: "closed observation failure",
			source: &fakeMatrixObservationSource{
				fail: hostRequirement,
			},
		},
		{
			name: "requirement substitution",
			source: &fakeMatrixObservationSource{
				substitute: true,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, err := newMatrixCaseExecutor(test.source)
			if err != nil {
				t.Fatalf("newMatrixCaseExecutor: %v", err)
			}
			if _, err := executor.RunActualHost(
				context.Background(),
				conformance.ActualHostProfile,
			); !errors.Is(err, conformance.ErrObservation) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
