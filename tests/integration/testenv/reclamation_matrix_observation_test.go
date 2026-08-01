package testenv

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type fakeReclamationRuntime struct {
	observation reclamationRuntimeObservation
	calls       int
}

func (r *fakeReclamationRuntime) ReclamationObservation(
	context.Context,
	fixtureRuntimeObservation,
) (reclamationRuntimeObservation, error) {
	r.calls++
	if r.calls != 1 {
		return reclamationRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func validReclamationInputs() (
	ReclamationBaselines,
	uint64,
	*fakeReclamationRuntime,
) {
	const samples = uint64(3)
	baselines := ReclamationBaselines{
		Resources: make(
			[]ReclamationBaseline,
			0,
			len(requiredReclamationResources),
		),
	}
	series := make(
		[]ReclamationResourceSeries,
		0,
		len(requiredReclamationResources),
	)
	for _, resource := range requiredReclamationResources {
		baselines.Resources = append(
			baselines.Resources,
			ReclamationBaseline{
				Resource:                resource,
				Baseline:                10,
				Margin:                  10,
				MaximumSlopeNumerator:   1,
				MaximumSlopeDenominator: 4,
			},
		)
		current := ReclamationResourceSeries{Resource: resource}
		for index := uint64(0); index < samples; index++ {
			current.HighWater = append(
				current.HighWater,
				ReclamationSample{Index: index, Value: 15},
			)
			current.PostCleanup = append(
				current.PostCleanup,
				ReclamationSample{Index: index, Value: 10},
			)
		}
		series = append(series, current)
	}
	return baselines, samples, &fakeReclamationRuntime{
		observation: reclamationRuntimeObservation{
			Series:                      series,
			VersionStagingAbsent:        true,
			VersionStagingAbsenceDigest: inputDigestA,
		},
	}
}

func TestReclamationSourceUsesEveryApprovedBaselineAndFreezesRows(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughCleanupMatrix(t, ledger)
	baselines, sampleCount, runtime := validReclamationInputs()
	source, err := newReclamationMatrixSource(
		ledger,
		baselines,
		sampleCount,
		runtime,
	)
	if err != nil {
		t.Fatalf("newReclamationMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseReclamationSeries {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
	}
	if len(observations) != 3 || runtime.calls != 1 {
		t.Fatalf(
			"reclamation observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
	if len(observations[0].Measurements) != 10 ||
		len(observations[1].Measurements) != 0 ||
		len(observations[2].Measurements) != 0 {
		t.Fatalf("measurement allocation = %+v", observations)
	}
}

func TestReclamationSourceRejectsUnfrozenOrLeakingSeries(
	t *testing.T,
) {
	t.Parallel()

	baselines, sampleCount, runtime := validReclamationInputs()
	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozen, err := newReclamationMatrixSource(
		unfrozenLedger,
		baselines,
		sampleCount,
		runtime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseReclamationSeries {
			first = requirement
			break
		}
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if runtime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", runtime.calls)
	}

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughCleanupMatrix(t, ledger)
	baselines, sampleCount, invalidRuntime := validReclamationInputs()
	invalidRuntime.observation.Series[0].PostCleanup = []ReclamationSample{
		{Index: 0, Value: 10},
		{Index: 1, Value: 11},
		{Index: 2, Value: 12},
	}
	invalid, err := newReclamationMatrixSource(
		ledger,
		baselines,
		sampleCount,
		invalidRuntime,
	)
	if err != nil {
		t.Fatalf("new invalid source: %v", err)
	}
	if _, err := invalid.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("leaking series error = %v", err)
	}
	if invalidRuntime.calls != 1 {
		t.Fatalf("invalid runtime calls = %d", invalidRuntime.calls)
	}
}
