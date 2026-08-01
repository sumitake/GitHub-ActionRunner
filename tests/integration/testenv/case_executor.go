package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

const matrixCaseEvidenceDomain = "portable-ghar.task11.case-evidence.v1\x00"

type matrixObservation struct {
	Requirement    ObservationRequirement
	AssertionCount uint64
	Measurements   []conformance.MeasurementInput
	Digest         string
}

type matrixObservationSource interface {
	Observe(
		context.Context,
		ObservationRequirement,
	) (matrixObservation, error)
}

type matrixCaseExecutor struct {
	source       matrixObservationSource
	requirements []ObservationRequirement
}

func newMatrixCaseExecutor(
	source matrixObservationSource,
) (*matrixCaseExecutor, error) {
	requirements := RequiredObservationMatrix()
	if source == nil || ValidateObservationMatrix(requirements) != nil {
		return nil, ErrFixtureStart
	}
	return &matrixCaseExecutor{
		source:       source,
		requirements: requirements,
	}, nil
}

func (e *matrixCaseExecutor) RunActualHost(
	ctx context.Context,
	id conformance.ActualHostCaseID,
) (conformance.ActualHostResult, error) {
	caseID := actualCaseToID(id)
	if e == nil || e.source == nil || ctx == nil ||
		ctx.Err() != nil || caseID == "" {
		return conformance.ActualHostResult{},
			conformance.ErrObservation
	}
	input, err := e.collect(ctx, caseID)
	if err != nil {
		return conformance.ActualHostResult{},
			conformance.ErrObservation
	}
	switch id {
	case conformance.ActualHostProfile:
		return conformance.SealHostProfile(
			conformance.HostProfileObservation(input),
		)
	case conformance.ActualNamespaceBaseline:
		return conformance.SealNamespaceBaseline(
			conformance.NamespaceObservation(input),
		)
	case conformance.ActualBrokerEgress:
		return conformance.SealBrokerEgress(
			conformance.BrokerEgressObservation(input),
		)
	case conformance.ActualMountAndSecretIsolation:
		return conformance.SealMountAndSecretIsolation(
			conformance.MountSecretObservation(input),
		)
	case conformance.ActualRunnerSandbox:
		return conformance.SealRunnerSandbox(
			conformance.RunnerSandboxObservation(input),
		)
	case conformance.ActualRunnerPayload:
		return conformance.SealRunnerPayload(
			conformance.RunnerPayloadObservation(input),
		)
	case conformance.ActualProxyToolCompatibility:
		return conformance.SealProxyToolCompatibility(
			conformance.ProxyToolObservation(input),
		)
	default:
		return conformance.ActualHostResult{},
			conformance.ErrObservation
	}
}

func (e *matrixCaseExecutor) RunSynthetic(
	ctx context.Context,
	id conformance.SyntheticCaseID,
) (conformance.SyntheticResult, error) {
	caseID := syntheticCaseToID(id)
	if e == nil || e.source == nil || ctx == nil ||
		ctx.Err() != nil || caseID == "" {
		return conformance.SyntheticResult{},
			conformance.ErrObservation
	}
	input, err := e.collect(ctx, caseID)
	if err != nil {
		return conformance.SyntheticResult{},
			conformance.ErrObservation
	}
	switch id {
	case conformance.SyntheticOneJob:
		return conformance.SealSyntheticOneJob(
			conformance.SyntheticJobObservation(input),
		)
	case conformance.SyntheticCleanupMatrix:
		return conformance.SealCleanupMatrix(
			conformance.CleanupMatrixObservation(input),
		)
	case conformance.SyntheticReclamationSeries:
		return conformance.SealReclamationSeries(
			conformance.ReclamationObservation(input),
		)
	case conformance.SyntheticSeedIsolation:
		return conformance.SealSeedIsolation(
			conformance.SeedObservation(input),
		)
	case conformance.SyntheticWatchdogRecovery:
		return conformance.SealWatchdogRecovery(
			conformance.WatchdogObservation(input),
		)
	case conformance.SyntheticLegacyFenceRecovery:
		return conformance.SealLegacyFenceRecovery(
			conformance.LegacyFenceObservation(input),
		)
	case conformance.SyntheticNoncancellableShutdown:
		return conformance.SealNoncancellableShutdown(
			conformance.ShutdownObservation(input),
		)
	default:
		return conformance.SyntheticResult{},
			conformance.ErrObservation
	}
}

func (e *matrixCaseExecutor) collect(
	ctx context.Context,
	caseID conformance.CaseID,
) (conformance.ObservationInput, error) {
	if e == nil || e.source == nil || ctx == nil ||
		ctx.Err() != nil || caseID == "" {
		return conformance.ObservationInput{}, conformance.ErrObservation
	}
	wire := matrixCaseEvidenceWire{
		SchemaVersion: 1,
		CaseID:        caseID,
	}
	var (
		assertions   uint64
		measurements []conformance.MeasurementInput
	)
	for _, requirement := range e.requirements {
		if requirement.Case != caseID {
			continue
		}
		if requirement.Case == conformance.CaseActualGitHubTransport {
			return conformance.ObservationInput{},
				conformance.ErrObservation
		}
		observation, err := e.source.Observe(ctx, requirement)
		if err != nil ||
			observation.Requirement != requirement ||
			observation.AssertionCount == 0 ||
			!isLowerHex(observation.Digest, sha256.Size*2) ||
			assertions > math.MaxUint64-observation.AssertionCount {
			return conformance.ObservationInput{},
				conformance.ErrObservation
		}
		assertions += observation.AssertionCount
		measurements = append(
			measurements,
			observation.Measurements...,
		)
		wire.Observations = append(
			wire.Observations,
			matrixCaseObservationWire{
				ID:             requirement.ID,
				Source:         requirement.Source,
				Operation:      requirement.Operation,
				Parser:         requirement.Parser,
				MaximumBytes:   requirement.MaxBytes,
				AssertionCount: observation.AssertionCount,
				Measurements:   observation.Measurements,
				Digest:         observation.Digest,
			},
		)
	}
	if len(wire.Observations) == 0 || assertions == 0 {
		return conformance.ObservationInput{},
			conformance.ErrObservation
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return conformance.ObservationInput{},
			conformance.ErrObservation
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(matrixCaseEvidenceDomain))
	_, _ = digest.Write(document)
	return conformance.ObservationInput{
		AssertionCount:    assertions,
		Measurements:      measurements,
		ObservationDigest: hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

type matrixCaseObservationWire struct {
	ID             ObservationID                  `json:"id"`
	Source         ObservationSource              `json:"source"`
	Operation      string                         `json:"operation"`
	Parser         string                         `json:"parser"`
	MaximumBytes   uint64                         `json:"maximum_bytes"`
	AssertionCount uint64                         `json:"assertion_count"`
	Measurements   []conformance.MeasurementInput `json:"measurements"`
	Digest         string                         `json:"digest"`
}

type matrixCaseEvidenceWire struct {
	SchemaVersion uint32                      `json:"schema_version"`
	CaseID        conformance.CaseID          `json:"case_id"`
	Observations  []matrixCaseObservationWire `json:"observations"`
}

var _ fixtureCaseExecutor = (*matrixCaseExecutor)(nil)
