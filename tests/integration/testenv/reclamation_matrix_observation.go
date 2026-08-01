package testenv

import (
	"context"
	"crypto/sha256"
	"math"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type ReclamationResourceSeries struct {
	Resource    ReclamationResource
	HighWater   []ReclamationSample
	PostCleanup []ReclamationSample
}

type reclamationRuntimeObservation struct {
	Series                      []ReclamationResourceSeries
	VersionStagingAbsent        bool
	VersionStagingAbsenceDigest string
}

type reclamationRuntime interface {
	ReclamationObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (reclamationRuntimeObservation, error)
}

type reclamationMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	baselines    ReclamationBaselines
	sampleCount  uint64
	runtime      reclamationRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

type reclamationSeriesWire struct {
	Resource         ReclamationResource `json:"resource"`
	Baseline         uint64              `json:"baseline"`
	Margin           uint64              `json:"margin"`
	SlopeNumerator   int64               `json:"maximum_slope_numerator"`
	SlopeDenominator int64               `json:"maximum_slope_denominator"`
	HighWater        []ReclamationSample `json:"high_water"`
	PostCleanup      []ReclamationSample `json:"post_cleanup"`
}

func newReclamationMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	baselines ReclamationBaselines,
	sampleCount uint64,
	runtime reclamationRuntime,
) (*reclamationMatrixSource, error) {
	if ledger == nil ||
		runtime == nil ||
		sampleCount < 3 ||
		len(baselines.Resources) != len(requiredReclamationResources) {
		return nil, ErrFixtureStart
	}
	for index, resource := range requiredReclamationResources {
		if baselines.Resources[index].Resource != resource {
			return nil, ErrFixtureStart
		}
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseReclamationSeries {
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 3 {
		return nil, ErrFixtureStart
	}
	return &reclamationMatrixSource{
		ledger: ledger,
		baselines: ReclamationBaselines{
			Resources: append(
				[]ReclamationBaseline(nil),
				baselines.Resources...,
			),
		},
		sampleCount:  sampleCount,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *reclamationMatrixSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed ||
		s.next >= len(s.requirements) ||
		requirement != s.requirements[s.next] {
		return matrixObservation{}, conformance.ErrObservation
	}
	if !s.ready {
		observations, err := s.acquire(ctx)
		if err != nil {
			s.failed = true
			return matrixObservation{}, conformance.ErrObservation
		}
		s.observations = observations
		s.ready = true
	}
	if len(s.observations) != len(s.requirements) ||
		s.observations[s.next].Requirement != requirement {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	observation := s.observations[s.next]
	s.next++
	if s.next == len(s.requirements) &&
		!s.ledger.freezeCase9() {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *reclamationMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase8()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	runtimeObservation, err := s.runtime.ReclamationObservation(
		ctx,
		prepared,
	)
	if err != nil ||
		!validReclamationRuntimeObservation(
			runtimeObservation,
			s.baselines,
			s.sampleCount,
		) {
		return nil, conformance.ErrObservation
	}
	series := make(
		[]reclamationSeriesWire,
		len(runtimeObservation.Series),
	)
	for index, observed := range runtimeObservation.Series {
		baseline := s.baselines.Resources[index]
		series[index] = reclamationSeriesWire{
			Resource:         observed.Resource,
			Baseline:         baseline.Baseline,
			Margin:           baseline.Margin,
			SlopeNumerator:   baseline.MaximumSlopeNumerator,
			SlopeDenominator: baseline.MaximumSlopeDenominator,
			HighWater: append(
				[]ReclamationSample(nil),
				observed.HighWater...,
			),
			PostCleanup: append(
				[]ReclamationSample(nil),
				observed.PostCleanup...,
			),
		}
	}
	assertions, ok := checkedReclamationAssertions(
		uint64(len(series)),
		s.sampleCount,
	)
	if !ok {
		return nil, conformance.ErrObservation
	}
	measurements, ok := reclamationMeasurements(
		runtimeObservation.Series,
		s.sampleCount,
	)
	if !ok {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, 3)
	highWater, err := sealTypedMatrixObservation(
		s.requirements[0],
		assertions,
		measurements,
		struct {
			PreparedEvidenceDigest string                  `json:"prepared_evidence_digest"`
			Series                 []reclamationSeriesWire `json:"series"`
		}{
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
			Series:                 series,
		},
	)
	if err != nil {
		return nil, conformance.ErrObservation
	}
	observations = append(observations, highWater)
	postCleanup, err := sealTypedMatrixObservation(
		s.requirements[1],
		assertions,
		nil,
		struct {
			PreparedEvidenceDigest string                  `json:"prepared_evidence_digest"`
			Series                 []reclamationSeriesWire `json:"series"`
		}{
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
			Series:                 series,
		},
	)
	if err != nil {
		return nil, conformance.ErrObservation
	}
	observations = append(observations, postCleanup)
	staging, err := sealTypedMatrixObservation(
		s.requirements[2],
		2,
		nil,
		struct {
			PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
			Absent                 bool   `json:"absent"`
			Digest                 string `json:"digest"`
		}{
			PreparedEvidenceDigest: prepared.PreparedEvidenceDigest,
			Absent:                 runtimeObservation.VersionStagingAbsent,
			Digest: runtimeObservation.
				VersionStagingAbsenceDigest,
		},
	)
	if err != nil {
		return nil, conformance.ErrObservation
	}
	return append(observations, staging), nil
}

func validReclamationRuntimeObservation(
	observation reclamationRuntimeObservation,
	baselines ReclamationBaselines,
	sampleCount uint64,
) bool {
	if len(observation.Series) != len(baselines.Resources) ||
		len(observation.Series) != len(requiredReclamationResources) ||
		!observation.VersionStagingAbsent ||
		!isLowerHex(
			observation.VersionStagingAbsenceDigest,
			sha256.Size*2,
		) {
		return false
	}
	for index, expected := range requiredReclamationResources {
		series := observation.Series[index]
		baseline := baselines.Resources[index]
		if series.Resource != expected ||
			baseline.Resource != expected ||
			uint64(len(series.HighWater)) != sampleCount ||
			uint64(len(series.PostCleanup)) != sampleCount ||
			ValidateReclamationSeries(
				series.PostCleanup,
				baseline,
			) != nil {
			return false
		}
		for sampleIndex := range series.HighWater {
			high := series.HighWater[sampleIndex]
			post := series.PostCleanup[sampleIndex]
			if high.Index != uint64(sampleIndex) ||
				post.Index != uint64(sampleIndex) ||
				high.Value < post.Value {
				return false
			}
		}
	}
	return true
}

func checkedReclamationAssertions(
	resources uint64,
	samples uint64,
) (uint64, bool) {
	if resources == 0 || samples == 0 ||
		resources > math.MaxUint64/samples {
		return 0, false
	}
	value := resources * samples
	if value > (math.MaxUint64-uint64(2))/2 {
		return 0, false
	}
	return value*2 + 2, true
}

func reclamationMeasurements(
	series []ReclamationResourceSeries,
	sampleCount uint64,
) ([]conformance.MeasurementInput, bool) {
	maximum := func(resource ReclamationResource) (uint64, bool) {
		for _, current := range series {
			if current.Resource != resource {
				continue
			}
			var value uint64
			for _, sample := range current.HighWater {
				if sample.Value > value {
					value = sample.Value
				}
			}
			return value, true
		}
		return 0, false
	}
	type measurementSpec struct {
		resource   ReclamationResource
		name       string
		unit       string
		fixedValue uint64
		fixed      bool
	}
	specs := [...]measurementSpec{
		{resource: ResourceContainers, name: "container_count", unit: "count"},
		{resource: ResourceFileDescriptors, name: "file_descriptor_count", unit: "count"},
		{resource: ResourceMemoryBytes, name: "memory_bytes", unit: "bytes"},
		{resource: ResourceNamespaces, name: "namespace_count", unit: "count"},
		{resource: ResourceProcesses, name: "process_count", unit: "count"},
		{resource: ResourceRunnerTmpfs, name: "runner_tmpfs_bytes", unit: "bytes"},
		{name: "sample_count", unit: "count", fixedValue: sampleCount, fixed: true},
		{resource: ResourceScratch, name: "scratch_bytes", unit: "bytes"},
		{resource: ResourceSwapBytes, name: "swap_bytes", unit: "bytes"},
		{resource: ResourceTmp, name: "tmp_tmpfs_bytes", unit: "bytes"},
	}
	result := make([]conformance.MeasurementInput, 0, len(specs))
	for _, spec := range specs {
		value := spec.fixedValue
		found := spec.fixed
		if !spec.fixed {
			value, found = maximum(spec.resource)
		}
		if !found {
			return nil, false
		}
		result = append(result, conformance.MeasurementInput{
			Name:  spec.name,
			Value: value,
			Unit:  spec.unit,
		})
	}
	return result, true
}

var _ matrixObservationSource = (*reclamationMatrixSource)(nil)
