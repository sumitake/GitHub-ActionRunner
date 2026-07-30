package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"
)

const (
	reportSchemaVersion = uint32(1)
	zeroDigest          = "0000000000000000000000000000000000000000000000000000000000000000"
)

const (
	bindingDomain            = "portable-ghar-conformance-binding-v1\x00"
	caseDomain               = "portable-ghar-conformance-case-v1\x00"
	cleanupDomain            = "portable-ghar-conformance-cleanup-v1\x00"
	reportDomain             = "portable-ghar-conformance-report-v1\x00"
	buildSealDomain          = "portable-ghar-conformance-build-seal-v1\x00"
	failureObservationDomain = "portable-ghar-conformance-failure-v1\x00"
	notRunObservationDomain  = "portable-ghar-conformance-not-run-v1\x00"
	pendingObservationDomain = "portable-ghar-conformance-pending-v1\x00"
)

var (
	ErrInvalidReport      = errors.New("conformance: invalid report")
	ErrInput              = errors.New("conformance: input invalid")
	ErrObservation        = errors.New("conformance: observation failed")
	ErrInvariant          = errors.New("conformance: invariant failed")
	ErrPolicy             = errors.New("conformance: policy failed")
	ErrArithmetic         = errors.New("conformance: arithmetic failed")
	ErrActualProofPending = errors.New("conformance: actual proof pending")
)

// CaseStatus is one closed evidence state.
type CaseStatus string

const (
	StatusPassed  CaseStatus = "passed"
	StatusFailed  CaseStatus = "failed"
	StatusPending CaseStatus = "pending"
	StatusNotRun  CaseStatus = "not-run"
)

// FailureClass is one secret-free terminal class.
type FailureClass string

const (
	FailureNone               FailureClass = "none"
	FailureInput              FailureClass = "input_invalid"
	FailureUnsupported        FailureClass = "unsupported_profile"
	FailureDeadline           FailureClass = "deadline_expired"
	FailureObservation        FailureClass = "observation_failed"
	FailureInvariant          FailureClass = "invariant_failed"
	FailurePolicy             FailureClass = "policy_failed"
	FailureArithmetic         FailureClass = "arithmetic_failed"
	FailureCleanup            FailureClass = "cleanup_failed"
	FailureActualProofPending FailureClass = "actual_proof_pending"
	FailurePrerequisite       FailureClass = "prerequisite_failed"
)

// BindingInput contains only the exact nonsecret values used to construct one
// immutable report binding. BindingDigest is always computed internally.
type BindingInput struct {
	SchemaVersion                 uint32
	BuildID                       string
	SourceCommit                  string
	RuntimeManifestDigest         string
	PrivateOverlayDigest          string
	ConformanceInputDigest        string
	AuthorizationDigest           string
	RunID                         string
	ProfileID                     string
	FleetGeneration               uint64
	ExpectedProfileEvidenceDigest string
	ExpectedNetworkEvidenceDigest string
	PlanDigest                    string
}

// MeasurementInput is accepted only by one case-specific observation sealer.
type MeasurementInput struct {
	Name  string
	Value uint64
	Unit  string
}

// ObservationInput is the common field layout behind distinct case-specific
// observation types. It has no case, layer, status, or failure field.
type ObservationInput struct {
	AssertionCount    uint64
	Measurements      []MeasurementInput
	ObservationDigest string
}

type HostProfileObservation ObservationInput
type NamespaceObservation ObservationInput
type BrokerEgressObservation ObservationInput
type MountSecretObservation ObservationInput
type RunnerSandboxObservation ObservationInput
type RunnerPayloadObservation ObservationInput
type ProxyToolObservation ObservationInput
type SyntheticJobObservation ObservationInput
type CleanupMatrixObservation ObservationInput
type ReclamationObservation ObservationInput
type SeedObservation ObservationInput
type WatchdogObservation ObservationInput
type LegacyFenceObservation ObservationInput
type ShutdownObservation ObservationInput
type ActualGitHubObservation ObservationInput
type CleanupObservation ObservationInput

// TargetObservationInput contains only the two independently recomputed
// dynamic target digests. Expected binding anchors are not accepted here.
type TargetObservationInput struct {
	ProfileEvidenceDigest string
	NetworkEvidenceDigest string
}

// Binding is package-opaque report identity.
type Binding struct {
	wire bindingWire
}

// Measurement is package-opaque numeric evidence.
type Measurement struct {
	name  string
	value uint64
	unit  string
}

// CaseEvidence is package-opaque case evidence.
type CaseEvidence struct {
	id                CaseID
	layer             ProofLayer
	status            CaseStatus
	failure           FailureClass
	assertionCount    uint64
	measurements      []Measurement
	observationDigest string
	evidenceDigest    string
}

// CleanupEvidence is package-opaque mandatory cleanup evidence. Before Run
// binds it, evidenceDigest is empty.
type CleanupEvidence struct {
	status            CaseStatus
	failure           FailureClass
	assertionCount    uint64
	observationDigest string
	evidenceDigest    string
}

// Report is one package-opaque canonical conformance document.
type Report struct {
	schemaVersion                 uint32
	binding                       Binding
	observedProfileEvidenceDigest string
	observedNetworkEvidenceDigest string
	cases                         []CaseEvidence
	cleanup                       CleanupEvidence
	status                        CaseStatus
	failure                       FailureClass
	reportDigest                  string
	buildSeal                     string
}

// ActualHostResult is returned only by an actual-host case-specific sealer.
type ActualHostResult struct {
	id                ActualHostCaseID
	assertionCount    uint64
	measurements      []Measurement
	observationDigest string
}

// SyntheticResult is returned only by a synthetic-lifecycle case sealer.
type SyntheticResult struct {
	id                SyntheticCaseID
	assertionCount    uint64
	measurements      []Measurement
	observationDigest string
}

// ActualGitHubResult is either the one canonical pending result or sealed
// actual-GitHub evidence.
type ActualGitHubResult struct {
	pending           bool
	assertionCount    uint64
	measurements      []Measurement
	observationDigest string
}

// TargetObservation is the package-opaque output of post-case target
// finalization.
type TargetObservation struct {
	profileEvidenceDigest string
	networkEvidenceDigest string
}

type bindingWire struct {
	SchemaVersion                 uint32 `json:"schema_version"`
	BuildID                       string `json:"build_id"`
	SourceCommit                  string `json:"source_commit"`
	RuntimeManifestDigest         string `json:"runtime_manifest_digest"`
	PrivateOverlayDigest          string `json:"private_overlay_digest"`
	ConformanceInputDigest        string `json:"conformance_input_digest"`
	AuthorizationDigest           string `json:"authorization_digest"`
	RunID                         string `json:"run_id"`
	ProfileID                     string `json:"profile_id"`
	FleetGeneration               uint64 `json:"fleet_generation"`
	ExpectedProfileEvidenceDigest string `json:"expected_profile_evidence_digest"`
	ExpectedNetworkEvidenceDigest string `json:"expected_network_evidence_digest"`
	PlanDigest                    string `json:"plan_digest"`
	BindingDigest                 string `json:"binding_digest"`
}

type measurementWire struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Unit  string `json:"unit"`
}

type caseEvidenceWire struct {
	ID                CaseID            `json:"id"`
	Layer             ProofLayer        `json:"layer"`
	Status            CaseStatus        `json:"status"`
	Failure           FailureClass      `json:"failure"`
	AssertionCount    uint64            `json:"assertion_count"`
	Measurements      []measurementWire `json:"measurements"`
	ObservationDigest string            `json:"observation_digest"`
	EvidenceDigest    string            `json:"evidence_digest"`
}

type cleanupEvidenceWire struct {
	Status            CaseStatus   `json:"status"`
	Failure           FailureClass `json:"failure"`
	AssertionCount    uint64       `json:"assertion_count"`
	ObservationDigest string       `json:"observation_digest"`
	EvidenceDigest    string       `json:"evidence_digest"`
}

type reportWire struct {
	SchemaVersion                 uint32              `json:"schema_version"`
	Binding                       bindingWire         `json:"binding"`
	ObservedProfileEvidenceDigest string              `json:"observed_profile_evidence_digest"`
	ObservedNetworkEvidenceDigest string              `json:"observed_network_evidence_digest"`
	Cases                         []caseEvidenceWire  `json:"cases"`
	Cleanup                       cleanupEvidenceWire `json:"cleanup"`
	Status                        CaseStatus          `json:"status"`
	Failure                       FailureClass        `json:"failure"`
	ReportDigest                  string              `json:"report_digest"`
	BuildSeal                     string              `json:"build_seal"`
}

// HostProfile is the closed conformance execution surface.
type HostProfile interface {
	Binding() (Binding, error)
	RunActualHost(context.Context, ActualHostCaseID) (ActualHostResult, error)
	RunSynthetic(context.Context, SyntheticCaseID) (SyntheticResult, error)
	RunActualGitHub(context.Context) (ActualGitHubResult, error)
	FinalizeTarget(context.Context) (TargetObservation, error)
	Cleanup(context.Context) (CleanupEvidence, error)
	ActualHostTimeout(ActualHostCaseID) time.Duration
	SyntheticTimeout(SyntheticCaseID) time.Duration
	ActualGitHubTimeout() time.Duration
	CleanupTimeout() time.Duration
}

// NewBinding validates and seals one exact report binding.
func NewBinding(input BindingInput) (Binding, error) {
	wire := bindingWire{
		SchemaVersion:                 input.SchemaVersion,
		BuildID:                       input.BuildID,
		SourceCommit:                  input.SourceCommit,
		RuntimeManifestDigest:         input.RuntimeManifestDigest,
		PrivateOverlayDigest:          input.PrivateOverlayDigest,
		ConformanceInputDigest:        input.ConformanceInputDigest,
		AuthorizationDigest:           input.AuthorizationDigest,
		RunID:                         input.RunID,
		ProfileID:                     input.ProfileID,
		FleetGeneration:               input.FleetGeneration,
		ExpectedProfileEvidenceDigest: input.ExpectedProfileEvidenceDigest,
		ExpectedNetworkEvidenceDigest: input.ExpectedNetworkEvidenceDigest,
		PlanDigest:                    input.PlanDigest,
		BindingDigest:                 zeroDigest,
	}
	digest, err := computeBindingDigest(wire)
	if err != nil {
		return Binding{}, ErrInvalidReport
	}
	wire.BindingDigest = digest
	if err := validateBindingWire(wire); err != nil {
		return Binding{}, err
	}
	return Binding{wire: wire}, nil
}

func SealHostProfile(input HostProfileObservation) (ActualHostResult, error) {
	return sealActual(ActualHostProfile, ObservationInput(input))
}

func SealNamespaceBaseline(input NamespaceObservation) (ActualHostResult, error) {
	return sealActual(ActualNamespaceBaseline, ObservationInput(input))
}

func SealBrokerEgress(input BrokerEgressObservation) (ActualHostResult, error) {
	return sealActual(ActualBrokerEgress, ObservationInput(input))
}

func SealMountAndSecretIsolation(input MountSecretObservation) (ActualHostResult, error) {
	return sealActual(ActualMountAndSecretIsolation, ObservationInput(input))
}

func SealRunnerSandbox(input RunnerSandboxObservation) (ActualHostResult, error) {
	return sealActual(ActualRunnerSandbox, ObservationInput(input))
}

func SealRunnerPayload(input RunnerPayloadObservation) (ActualHostResult, error) {
	return sealActual(ActualRunnerPayload, ObservationInput(input))
}

func SealProxyToolCompatibility(input ProxyToolObservation) (ActualHostResult, error) {
	return sealActual(ActualProxyToolCompatibility, ObservationInput(input))
}

func SealSyntheticOneJob(input SyntheticJobObservation) (SyntheticResult, error) {
	return sealSynthetic(SyntheticOneJob, ObservationInput(input))
}

func SealCleanupMatrix(input CleanupMatrixObservation) (SyntheticResult, error) {
	return sealSynthetic(SyntheticCleanupMatrix, ObservationInput(input))
}

func SealReclamationSeries(input ReclamationObservation) (SyntheticResult, error) {
	value := ObservationInput(input)
	if sampleCount(value.Measurements) < 3 {
		return SyntheticResult{}, ErrArithmetic
	}
	return sealSynthetic(SyntheticReclamationSeries, value)
}

func SealSeedIsolation(input SeedObservation) (SyntheticResult, error) {
	return sealSynthetic(SyntheticSeedIsolation, ObservationInput(input))
}

func SealWatchdogRecovery(input WatchdogObservation) (SyntheticResult, error) {
	return sealSynthetic(SyntheticWatchdogRecovery, ObservationInput(input))
}

func SealLegacyFenceRecovery(input LegacyFenceObservation) (SyntheticResult, error) {
	return sealSynthetic(SyntheticLegacyFenceRecovery, ObservationInput(input))
}

func SealNoncancellableShutdown(input ShutdownObservation) (SyntheticResult, error) {
	return sealSynthetic(SyntheticNoncancellableShutdown, ObservationInput(input))
}

func SealCleanup(input CleanupObservation) (CleanupEvidence, error) {
	value := ObservationInput(input)
	if value.AssertionCount == 0 ||
		!isLowerHex(value.ObservationDigest, 64) ||
		len(value.Measurements) != 0 {
		return CleanupEvidence{}, ErrInvariant
	}
	return CleanupEvidence{
		status:            StatusPassed,
		failure:           FailureNone,
		assertionCount:    value.AssertionCount,
		observationDigest: value.ObservationDigest,
	}, nil
}

// SealTargetObservation validates one independently recomputed final target
// observation. Equality with the expected binding is checked only by Run and
// report validation.
func SealTargetObservation(
	input TargetObservationInput,
) (TargetObservation, error) {
	if !isLowerHex(input.ProfileEvidenceDigest, 64) ||
		input.ProfileEvidenceDigest == zeroDigest ||
		!isLowerHex(input.NetworkEvidenceDigest, 64) ||
		input.NetworkEvidenceDigest == zeroDigest {
		return TargetObservation{}, ErrInvariant
	}
	return TargetObservation{
		profileEvidenceDigest: input.ProfileEvidenceDigest,
		networkEvidenceDigest: input.NetworkEvidenceDigest,
	}, nil
}

// PendingActualGitHubTransport is the sole source-checkpoint result for case
// 15. It can never be converted into passing evidence.
func PendingActualGitHubTransport() ActualGitHubResult {
	return ActualGitHubResult{
		pending: true,
		observationDigest: fixedObservationDigest(
			pendingObservationDomain,
			CaseActualGitHubTransport,
			FailureActualProofPending,
		),
	}
}

func SealActualGitHubTransport(
	input ActualGitHubObservation,
) (ActualGitHubResult, error) {
	value := ObservationInput(input)
	measurements, err := validateMeasurements(
		CaseActualGitHubTransport,
		value.Measurements,
	)
	if err != nil ||
		value.AssertionCount == 0 ||
		!isLowerHex(value.ObservationDigest, 64) {
		return ActualGitHubResult{}, ErrInvariant
	}
	return ActualGitHubResult{
		assertionCount:    value.AssertionCount,
		measurements:      measurements,
		observationDigest: value.ObservationDigest,
	}, nil
}

func sealActual(
	id ActualHostCaseID,
	input ObservationInput,
) (ActualHostResult, error) {
	definition, ok := lookupActualCase(id)
	if !ok || definition.layer != LayerActualHostImmutable {
		return ActualHostResult{}, ErrInvariant
	}
	measurements, err := validateMeasurements(definition.id, input.Measurements)
	if err != nil ||
		input.AssertionCount == 0 ||
		!isLowerHex(input.ObservationDigest, 64) {
		return ActualHostResult{}, ErrInvariant
	}
	return ActualHostResult{
		id:                id,
		assertionCount:    input.AssertionCount,
		measurements:      measurements,
		observationDigest: input.ObservationDigest,
	}, nil
}

func sealSynthetic(
	id SyntheticCaseID,
	input ObservationInput,
) (SyntheticResult, error) {
	definition, ok := lookupSyntheticCase(id)
	if !ok || definition.layer != LayerSyntheticLifecycle {
		return SyntheticResult{}, ErrInvariant
	}
	measurements, err := validateMeasurements(definition.id, input.Measurements)
	if err != nil ||
		input.AssertionCount == 0 ||
		!isLowerHex(input.ObservationDigest, 64) {
		return SyntheticResult{}, ErrInvariant
	}
	return SyntheticResult{
		id:                id,
		assertionCount:    input.AssertionCount,
		measurements:      measurements,
		observationDigest: input.ObservationDigest,
	}, nil
}

// Run executes every case in registry order, then the one mandatory cleanup.
func Run(parent context.Context, profile HostProfile) Report {
	if parent == nil || profile == nil {
		return Report{}
	}
	binding, bindingErr := profile.Binding()
	if bindingErr != nil || validateBindingWire(binding.wire) != nil {
		runCleanupWithoutReport(parent, profile)
		return Report{}
	}

	cases := make([]CaseEvidence, 0, len(requiredCaseRegistry))
	stopped := false
	for _, definition := range requiredCaseRegistry {
		if stopped {
			cases = append(cases, newNotRunEvidence(binding, definition))
			continue
		}
		evidence, err := runCase(parent, profile, binding, definition)
		if err != nil {
			evidence = newFailedEvidence(
				binding,
				definition,
				classifyFailure(err),
			)
		}
		cases = append(cases, evidence)
		if evidence.status == StatusFailed {
			stopped = true
		}
	}

	target := zeroTargetObservation()
	if casesEligibleForFinalization(cases) {
		target = runTargetFinalization(parent, profile)
	}
	cleanup := runCleanup(parent, profile, binding)
	status, failure := aggregateReportStatus(cases, target, binding, cleanup)
	report := Report{
		schemaVersion:                 reportSchemaVersion,
		binding:                       binding,
		observedProfileEvidenceDigest: target.profileEvidenceDigest,
		observedNetworkEvidenceDigest: target.networkEvidenceDigest,
		cases:                         cloneCaseEvidence(cases),
		cleanup:                       cleanup,
		status:                        status,
		failure:                       failure,
		reportDigest:                  zeroDigest,
		buildSeal:                     zeroDigest,
	}
	digest, err := computeReportDigest(report)
	if err != nil {
		return Report{}
	}
	report.reportDigest = digest
	seal, err := computeBuildSeal(report)
	if err != nil {
		return Report{}
	}
	report.buildSeal = seal
	if validateReport(report) != nil {
		return Report{}
	}
	return report
}

func casesEligibleForFinalization(cases []CaseEvidence) bool {
	if len(cases) != len(requiredCaseRegistry) {
		return false
	}
	for index, evidence := range cases {
		if index == len(cases)-1 {
			return evidence.id == CaseActualGitHubTransport &&
				(evidence.status == StatusPassed ||
					evidence.status == StatusPending)
		}
		if evidence.status != StatusPassed ||
			evidence.failure != FailureNone {
			return false
		}
	}
	return false
}

func runTargetFinalization(
	parent context.Context,
	profile HostProfile,
) TargetObservation {
	timeout := profile.ActualHostTimeout(ActualHostProfile)
	if timeout <= 0 {
		return zeroTargetObservation()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	observation, err := profile.FinalizeTarget(ctx)
	if err != nil ||
		!validTargetObservation(observation) {
		return zeroTargetObservation()
	}
	return observation
}

func zeroTargetObservation() TargetObservation {
	return TargetObservation{
		profileEvidenceDigest: zeroDigest,
		networkEvidenceDigest: zeroDigest,
	}
}

func validTargetObservation(observation TargetObservation) bool {
	return isLowerHex(observation.profileEvidenceDigest, 64) &&
		observation.profileEvidenceDigest != zeroDigest &&
		isLowerHex(observation.networkEvidenceDigest, 64) &&
		observation.networkEvidenceDigest != zeroDigest
}

func runCase(
	parent context.Context,
	profile HostProfile,
	binding Binding,
	definition caseDefinition,
) (CaseEvidence, error) {
	if err := parent.Err(); err != nil {
		return CaseEvidence{}, err
	}
	var timeout time.Duration
	switch definition.layer {
	case LayerActualHostImmutable:
		timeout = profile.ActualHostTimeout(definition.actual)
	case LayerSyntheticLifecycle:
		timeout = profile.SyntheticTimeout(definition.synthetic)
	case LayerActualGitHubTransport:
		timeout = profile.ActualGitHubTimeout()
	default:
		return CaseEvidence{}, ErrInvariant
	}
	if timeout <= 0 {
		return CaseEvidence{}, ErrInput
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	switch definition.layer {
	case LayerActualHostImmutable:
		result, err := profile.RunActualHost(ctx, definition.actual)
		if err != nil {
			return CaseEvidence{}, err
		}
		if result.id != definition.actual ||
			result.assertionCount == 0 ||
			!isLowerHex(result.observationDigest, 64) {
			return CaseEvidence{}, ErrInvariant
		}
		return newPassedEvidence(
			binding,
			definition,
			result.assertionCount,
			result.measurements,
			result.observationDigest,
		)
	case LayerSyntheticLifecycle:
		result, err := profile.RunSynthetic(ctx, definition.synthetic)
		if err != nil {
			return CaseEvidence{}, err
		}
		if result.id != definition.synthetic ||
			result.assertionCount == 0 ||
			!isLowerHex(result.observationDigest, 64) {
			return CaseEvidence{}, ErrInvariant
		}
		return newPassedEvidence(
			binding,
			definition,
			result.assertionCount,
			result.measurements,
			result.observationDigest,
		)
	case LayerActualGitHubTransport:
		result, err := profile.RunActualGitHub(ctx)
		if err != nil {
			return CaseEvidence{}, err
		}
		if result.pending {
			if result.assertionCount != 0 ||
				len(result.measurements) != 0 ||
				result.observationDigest != fixedObservationDigest(
					pendingObservationDomain,
					CaseActualGitHubTransport,
					FailureActualProofPending,
				) {
				return CaseEvidence{}, ErrInvariant
			}
			return newCaseEvidence(
				binding,
				definition,
				StatusPending,
				FailureActualProofPending,
				0,
				nil,
				result.observationDigest,
			)
		}
		if result.assertionCount == 0 ||
			!isLowerHex(result.observationDigest, 64) {
			return CaseEvidence{}, ErrInvariant
		}
		return newPassedEvidence(
			binding,
			definition,
			result.assertionCount,
			result.measurements,
			result.observationDigest,
		)
	default:
		return CaseEvidence{}, ErrInvariant
	}
}

func runCleanup(
	parent context.Context,
	profile HostProfile,
	binding Binding,
) CleanupEvidence {
	timeout := profile.CleanupTimeout()
	if timeout <= 0 {
		return newFailedCleanup(binding)
	}
	base := context.WithoutCancel(parent)
	ctx, cancel := context.WithTimeout(base, timeout)
	defer cancel()
	evidence, err := profile.Cleanup(ctx)
	if err != nil ||
		evidence.status != StatusPassed ||
		evidence.failure != FailureNone ||
		evidence.assertionCount == 0 ||
		!isLowerHex(evidence.observationDigest, 64) ||
		evidence.evidenceDigest != "" {
		return newFailedCleanup(binding)
	}
	evidence.evidenceDigest = cleanupEvidenceDigest(binding, evidence)
	return evidence
}

func runCleanupWithoutReport(parent context.Context, profile HostProfile) {
	timeout := profile.CleanupTimeout()
	if timeout <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	defer cancel()
	_, _ = profile.Cleanup(ctx)
}

func newPassedEvidence(
	binding Binding,
	definition caseDefinition,
	assertionCount uint64,
	measurements []Measurement,
	observationDigest string,
) (CaseEvidence, error) {
	return newCaseEvidence(
		binding,
		definition,
		StatusPassed,
		FailureNone,
		assertionCount,
		measurements,
		observationDigest,
	)
}

func newFailedEvidence(
	binding Binding,
	definition caseDefinition,
	failure FailureClass,
) CaseEvidence {
	observation := fixedObservationDigest(
		failureObservationDomain,
		definition.id,
		failure,
	)
	evidence, err := newCaseEvidence(
		binding,
		definition,
		StatusFailed,
		failure,
		0,
		nil,
		observation,
	)
	if err != nil {
		return CaseEvidence{}
	}
	return evidence
}

func newNotRunEvidence(
	binding Binding,
	definition caseDefinition,
) CaseEvidence {
	observation := fixedObservationDigest(
		notRunObservationDomain,
		definition.id,
		FailurePrerequisite,
	)
	evidence, err := newCaseEvidence(
		binding,
		definition,
		StatusNotRun,
		FailurePrerequisite,
		0,
		nil,
		observation,
	)
	if err != nil {
		return CaseEvidence{}
	}
	return evidence
}

func newCaseEvidence(
	binding Binding,
	definition caseDefinition,
	status CaseStatus,
	failure FailureClass,
	assertionCount uint64,
	measurements []Measurement,
	observationDigest string,
) (CaseEvidence, error) {
	evidence := CaseEvidence{
		id:                definition.id,
		layer:             definition.layer,
		status:            status,
		failure:           failure,
		assertionCount:    assertionCount,
		measurements:      cloneMeasurements(measurements),
		observationDigest: observationDigest,
	}
	if validateCaseEvidenceShape(evidence, false) != nil {
		return CaseEvidence{}, ErrInvalidReport
	}
	evidence.evidenceDigest = caseEvidenceDigest(binding, evidence)
	return evidence, nil
}

func newFailedCleanup(binding Binding) CleanupEvidence {
	evidence := CleanupEvidence{
		status:  StatusFailed,
		failure: FailureCleanup,
		observationDigest: fixedObservationDigest(
			failureObservationDomain,
			CaseID("cleanup"),
			FailureCleanup,
		),
	}
	evidence.evidenceDigest = cleanupEvidenceDigest(binding, evidence)
	return evidence
}

func aggregateReportStatus(
	cases []CaseEvidence,
	target TargetObservation,
	binding Binding,
	cleanup CleanupEvidence,
) (CaseStatus, FailureClass) {
	if cleanup.status != StatusPassed || cleanup.failure != FailureNone {
		return StatusFailed, FailureCleanup
	}
	for _, evidence := range cases {
		if evidence.status == StatusFailed {
			return StatusFailed, evidence.failure
		}
	}
	if casesEligibleForFinalization(cases) &&
		(!validTargetObservation(target) ||
			target.profileEvidenceDigest !=
				binding.wire.ExpectedProfileEvidenceDigest ||
			target.networkEvidenceDigest !=
				binding.wire.ExpectedNetworkEvidenceDigest) {
		return StatusFailed, FailureInvariant
	}
	for _, evidence := range cases {
		if evidence.status == StatusPending {
			return StatusPending, evidence.failure
		}
	}
	return StatusPassed, FailureNone
}

func classifyFailure(err error) FailureClass {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return FailureDeadline
	case errors.Is(err, ErrInput):
		return FailureInput
	case errors.Is(err, ErrInvariant):
		return FailureInvariant
	case errors.Is(err, ErrPolicy):
		return FailurePolicy
	case errors.Is(err, ErrArithmetic):
		return FailureArithmetic
	default:
		return FailureObservation
	}
}

// MarshalReport returns the exact canonical V1 report bytes.
func MarshalReport(report Report) ([]byte, error) {
	if err := validateReport(report); err != nil {
		return nil, err
	}
	document, err := json.Marshal(reportToWire(report))
	if err != nil {
		return nil, ErrInvalidReport
	}
	return document, nil
}

// ParseReport parses one exact canonical V1 report.
func ParseReport(document []byte, maxBytes int) (Report, error) {
	if maxBytes <= 0 ||
		len(document) == 0 ||
		len(document) > maxBytes ||
		!utf8.Valid(document) {
		return Report{}, ErrInvalidReport
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire reportWire
	if err := decoder.Decode(&wire); err != nil {
		return Report{}, ErrInvalidReport
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Report{}, ErrInvalidReport
	}
	if wire.Cases == nil {
		return Report{}, ErrInvalidReport
	}
	for _, evidence := range wire.Cases {
		if evidence.Measurements == nil {
			return Report{}, ErrInvalidReport
		}
	}
	report, err := reportFromWire(wire)
	if err != nil {
		return Report{}, err
	}
	canonical, err := json.Marshal(reportToWire(report))
	if err != nil || !bytes.Equal(canonical, document) {
		return Report{}, ErrInvalidReport
	}
	return report, nil
}

// ValidateReport validates all canonical fields and derived digests.
func ValidateReport(report Report) error {
	return validateReport(report)
}

func validateReport(report Report) error {
	if report.schemaVersion != reportSchemaVersion ||
		validateBindingWire(report.binding.wire) != nil ||
		len(report.cases) != len(requiredCaseRegistry) ||
		report.cleanup.evidenceDigest == "" ||
		!isLowerHex(report.observedProfileEvidenceDigest, 64) ||
		!isLowerHex(report.observedNetworkEvidenceDigest, 64) ||
		!isLowerHex(report.reportDigest, 64) ||
		!isLowerHex(report.buildSeal, 64) {
		return ErrInvalidReport
	}
	failed := false
	for index, definition := range requiredCaseRegistry {
		evidence := report.cases[index]
		if evidence.id != definition.id ||
			evidence.layer != definition.layer ||
			validateCaseEvidenceShape(evidence, true) != nil ||
			evidence.evidenceDigest != caseEvidenceDigest(report.binding, evidence) {
			return ErrInvalidReport
		}
		switch evidence.status {
		case StatusFailed:
			if failed {
				return ErrInvalidReport
			}
			failed = true
		case StatusNotRun:
			if !failed {
				return ErrInvalidReport
			}
		case StatusPending:
			if failed ||
				definition.id != CaseActualGitHubTransport ||
				index != len(requiredCaseRegistry)-1 {
				return ErrInvalidReport
			}
		case StatusPassed:
			if failed {
				return ErrInvalidReport
			}
		default:
			return ErrInvalidReport
		}
	}
	if validateCleanupEvidence(report.binding, report.cleanup) != nil {
		return ErrInvalidReport
	}
	target := TargetObservation{
		profileEvidenceDigest: report.observedProfileEvidenceDigest,
		networkEvidenceDigest: report.observedNetworkEvidenceDigest,
	}
	eligible := casesEligibleForFinalization(report.cases)
	if (!eligible &&
		(report.observedProfileEvidenceDigest != zeroDigest ||
			report.observedNetworkEvidenceDigest != zeroDigest)) ||
		(eligible && !validTargetObservation(target) &&
			(report.observedProfileEvidenceDigest != zeroDigest ||
				report.observedNetworkEvidenceDigest != zeroDigest)) {
		return ErrInvalidReport
	}
	status, failure := aggregateReportStatus(
		report.cases,
		target,
		report.binding,
		report.cleanup,
	)
	if report.status != status || report.failure != failure {
		return ErrInvalidReport
	}
	digest, err := computeReportDigest(report)
	if err != nil || report.reportDigest != digest {
		return ErrInvalidReport
	}
	seal, err := computeBuildSeal(report)
	if err != nil || report.buildSeal != seal {
		return ErrInvalidReport
	}
	return nil
}

func validateCaseEvidenceShape(
	evidence CaseEvidence,
	requireDigest bool,
) error {
	definition, ok := lookupCase(evidence.id)
	if !ok ||
		evidence.layer != definition.layer ||
		!isLowerHex(evidence.observationDigest, 64) ||
		(requireDigest && !isLowerHex(evidence.evidenceDigest, 64)) ||
		validateMeasurementsValue(evidence.id, evidence.measurements) != nil {
		return ErrInvalidReport
	}
	switch evidence.status {
	case StatusPassed:
		if evidence.failure != FailureNone || evidence.assertionCount == 0 {
			return ErrInvalidReport
		}
	case StatusFailed:
		if !validCaseFailure(evidence.failure) ||
			evidence.assertionCount != 0 ||
			len(evidence.measurements) != 0 ||
			evidence.observationDigest != fixedObservationDigest(
				failureObservationDomain,
				evidence.id,
				evidence.failure,
			) {
			return ErrInvalidReport
		}
	case StatusPending:
		if evidence.id != CaseActualGitHubTransport ||
			evidence.layer != LayerActualGitHubTransport ||
			evidence.failure != FailureActualProofPending ||
			evidence.assertionCount != 0 ||
			len(evidence.measurements) != 0 ||
			evidence.observationDigest != fixedObservationDigest(
				pendingObservationDomain,
				evidence.id,
				evidence.failure,
			) {
			return ErrInvalidReport
		}
	case StatusNotRun:
		if evidence.failure != FailurePrerequisite ||
			evidence.assertionCount != 0 ||
			len(evidence.measurements) != 0 ||
			evidence.observationDigest != fixedObservationDigest(
				notRunObservationDomain,
				evidence.id,
				evidence.failure,
			) {
			return ErrInvalidReport
		}
	default:
		return ErrInvalidReport
	}
	return nil
}

func validCaseFailure(failure FailureClass) bool {
	switch failure {
	case FailureInput,
		FailureUnsupported,
		FailureDeadline,
		FailureObservation,
		FailureInvariant,
		FailurePolicy,
		FailureArithmetic:
		return true
	default:
		return false
	}
}

func validateCleanupEvidence(
	binding Binding,
	evidence CleanupEvidence,
) error {
	if !isLowerHex(evidence.observationDigest, 64) ||
		!isLowerHex(evidence.evidenceDigest, 64) ||
		evidence.evidenceDigest != cleanupEvidenceDigest(binding, evidence) {
		return ErrInvalidReport
	}
	switch evidence.status {
	case StatusPassed:
		if evidence.failure != FailureNone || evidence.assertionCount == 0 {
			return ErrInvalidReport
		}
	case StatusFailed:
		if evidence.failure != FailureCleanup ||
			evidence.assertionCount != 0 ||
			evidence.observationDigest != fixedObservationDigest(
				failureObservationDomain,
				CaseID("cleanup"),
				FailureCleanup,
			) {
			return ErrInvalidReport
		}
	default:
		return ErrInvalidReport
	}
	return nil
}

func computeBindingDigest(wire bindingWire) (string, error) {
	wire.BindingDigest = zeroDigest
	if validateBindingWireShape(wire) != nil {
		return "", ErrInvalidReport
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return "", ErrInvalidReport
	}
	return hashBytes(bindingDomain, document), nil
}

func validateBindingWire(wire bindingWire) error {
	if validateBindingWireShape(wire) != nil ||
		!isLowerHex(wire.BindingDigest, 64) {
		return ErrInvalidReport
	}
	digest, err := computeBindingDigest(wire)
	if err != nil || wire.BindingDigest != digest {
		return ErrInvalidReport
	}
	return nil
}

func validateBindingWireShape(wire bindingWire) error {
	if wire.SchemaVersion != reportSchemaVersion ||
		!isLowerHex(wire.BuildID, 64) ||
		!isLowerHex(wire.SourceCommit, 40) ||
		!isLowerHex(wire.RuntimeManifestDigest, 64) ||
		!isLowerHex(wire.PrivateOverlayDigest, 64) ||
		!isLowerHex(wire.ConformanceInputDigest, 64) ||
		!isLowerHex(wire.AuthorizationDigest, 64) ||
		!isLowerHex(wire.RunID, 64) ||
		!validProfileID(wire.ProfileID) ||
		wire.FleetGeneration == 0 ||
		!isLowerHex(wire.ExpectedProfileEvidenceDigest, 64) ||
		wire.ExpectedProfileEvidenceDigest == zeroDigest ||
		!isLowerHex(wire.ExpectedNetworkEvidenceDigest, 64) ||
		wire.ExpectedNetworkEvidenceDigest == zeroDigest ||
		!isLowerHex(wire.PlanDigest, 64) {
		return ErrInvalidReport
	}
	return nil
}

func validProfileID(value string) bool {
	return value == "strict-linux" || value == "qts-capless-root"
}

func validateMeasurements(
	id CaseID,
	input []MeasurementInput,
) ([]Measurement, error) {
	if input == nil {
		return []Measurement{}, nil
	}
	values := make([]Measurement, len(input))
	for index, measurement := range input {
		values[index] = Measurement{
			name:  measurement.Name,
			value: measurement.Value,
			unit:  measurement.Unit,
		}
	}
	if validateMeasurementsValue(id, values) != nil {
		return nil, ErrInvariant
	}
	return values, nil
}

func validateMeasurementsValue(id CaseID, values []Measurement) error {
	for index, measurement := range values {
		unit, ok := allowedMeasurement(id, measurement.name)
		if !ok || measurement.unit != unit {
			return ErrInvalidReport
		}
		if index > 0 && values[index-1].name >= measurement.name {
			return ErrInvalidReport
		}
	}
	return nil
}

func allowedMeasurement(id CaseID, name string) (string, bool) {
	switch id {
	case CaseHostProfile:
		if name == "effective_capacity" {
			return "count", true
		}
	case CaseNamespaceBaseline:
		if name == "conntrack_entries" ||
			name == "loopback_flood_attempts" ||
			name == "namespace_count" {
			return "count", true
		}
	case CaseBrokerEgress:
		switch name {
		case "conntrack_entries",
			"file_descriptor_count",
			"loopback_flood_attempts",
			"process_count":
			return "count", true
		}
	case CaseCleanupMatrix:
		if name == "cleanup_rows" {
			return "count", true
		}
	case CaseReclamationSeries:
		switch name {
		case "container_count",
			"file_descriptor_count",
			"namespace_count",
			"process_count",
			"sample_count":
			return "count", true
		case "memory_bytes",
			"runner_tmpfs_bytes",
			"scratch_bytes",
			"swap_bytes",
			"tmp_tmpfs_bytes":
			return "bytes", true
		}
	case CaseProxyToolCompatibility:
		if name == "tool_count" {
			return "count", true
		}
	case CaseActualGitHubTransport:
		if name == "job_count" || name == "tool_count" {
			return "count", true
		}
	}
	return "", false
}

func sampleCount(values []MeasurementInput) uint64 {
	for _, value := range values {
		if value.Name == "sample_count" && value.Unit == "count" {
			return value.Value
		}
	}
	return 0
}

func caseEvidenceDigest(binding Binding, evidence CaseEvidence) string {
	var buffer bytes.Buffer
	buffer.WriteString(caseDomain)
	writeLP(&buffer, string(evidence.id))
	writeLP(&buffer, string(evidence.layer))
	writeLP(&buffer, string(evidence.status))
	writeLP(&buffer, string(evidence.failure))
	writeU64(&buffer, evidence.assertionCount)
	writeU32(&buffer, uint32(len(evidence.measurements)))
	for _, measurement := range evidence.measurements {
		writeLP(&buffer, measurement.name)
		writeU64(&buffer, measurement.value)
		writeLP(&buffer, measurement.unit)
	}
	writeDigest(&buffer, binding.wire.BindingDigest)
	writeDigest(&buffer, evidence.observationDigest)
	sum := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(sum[:])
}

func cleanupEvidenceDigest(
	binding Binding,
	evidence CleanupEvidence,
) string {
	var buffer bytes.Buffer
	buffer.WriteString(cleanupDomain)
	writeLP(&buffer, string(evidence.status))
	writeLP(&buffer, string(evidence.failure))
	writeU64(&buffer, evidence.assertionCount)
	writeDigest(&buffer, binding.wire.BindingDigest)
	writeDigest(&buffer, evidence.observationDigest)
	sum := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(sum[:])
}

func computeReportDigest(report Report) (string, error) {
	wire := reportToWire(report)
	wire.ReportDigest = zeroDigest
	wire.BuildSeal = zeroDigest
	document, err := json.Marshal(wire)
	if err != nil {
		return "", ErrInvalidReport
	}
	return hashBytes(reportDomain, document), nil
}

func computeBuildSeal(report Report) (string, error) {
	var buffer bytes.Buffer
	buffer.WriteString(buildSealDomain)
	if !writeDigest(&buffer, report.binding.wire.BuildID) ||
		!writeDigest(&buffer, report.binding.wire.BindingDigest) ||
		!writeDigest(&buffer, report.reportDigest) {
		return "", ErrInvalidReport
	}
	sum := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func fixedObservationDigest(
	domain string,
	id CaseID,
	failure FailureClass,
) string {
	var buffer bytes.Buffer
	buffer.WriteString(domain)
	writeLP(&buffer, string(id))
	writeLP(&buffer, string(failure))
	sum := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(sum[:])
}

func hashBytes(domain string, document []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(document)
	return hex.EncodeToString(hash.Sum(nil))
}

func writeLP(buffer *bytes.Buffer, value string) {
	writeU32(buffer, uint32(len([]byte(value))))
	buffer.WriteString(value)
}

func writeU32(buffer *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeU64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeDigest(buffer *bytes.Buffer, value string) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	buffer.Write(decoded)
	return true
}

func reportToWire(report Report) reportWire {
	cases := make([]caseEvidenceWire, len(report.cases))
	for index, evidence := range report.cases {
		measurements := make([]measurementWire, len(evidence.measurements))
		for measurementIndex, measurement := range evidence.measurements {
			measurements[measurementIndex] = measurementWire{
				Name:  measurement.name,
				Value: measurement.value,
				Unit:  measurement.unit,
			}
		}
		cases[index] = caseEvidenceWire{
			ID:                evidence.id,
			Layer:             evidence.layer,
			Status:            evidence.status,
			Failure:           evidence.failure,
			AssertionCount:    evidence.assertionCount,
			Measurements:      measurements,
			ObservationDigest: evidence.observationDigest,
			EvidenceDigest:    evidence.evidenceDigest,
		}
	}
	return reportWire{
		SchemaVersion:                 report.schemaVersion,
		Binding:                       report.binding.wire,
		ObservedProfileEvidenceDigest: report.observedProfileEvidenceDigest,
		ObservedNetworkEvidenceDigest: report.observedNetworkEvidenceDigest,
		Cases:                         cases,
		Cleanup: cleanupEvidenceWire{
			Status:            report.cleanup.status,
			Failure:           report.cleanup.failure,
			AssertionCount:    report.cleanup.assertionCount,
			ObservationDigest: report.cleanup.observationDigest,
			EvidenceDigest:    report.cleanup.evidenceDigest,
		},
		Status:       report.status,
		Failure:      report.failure,
		ReportDigest: report.reportDigest,
		BuildSeal:    report.buildSeal,
	}
}

func reportFromWire(wire reportWire) (Report, error) {
	cases := make([]CaseEvidence, len(wire.Cases))
	for index, encoded := range wire.Cases {
		measurements := make([]Measurement, len(encoded.Measurements))
		for measurementIndex, measurement := range encoded.Measurements {
			measurements[measurementIndex] = Measurement{
				name:  measurement.Name,
				value: measurement.Value,
				unit:  measurement.Unit,
			}
		}
		cases[index] = CaseEvidence{
			id:                encoded.ID,
			layer:             encoded.Layer,
			status:            encoded.Status,
			failure:           encoded.Failure,
			assertionCount:    encoded.AssertionCount,
			measurements:      measurements,
			observationDigest: encoded.ObservationDigest,
			evidenceDigest:    encoded.EvidenceDigest,
		}
	}
	report := Report{
		schemaVersion:                 wire.SchemaVersion,
		binding:                       Binding{wire: wire.Binding},
		observedProfileEvidenceDigest: wire.ObservedProfileEvidenceDigest,
		observedNetworkEvidenceDigest: wire.ObservedNetworkEvidenceDigest,
		cases:                         cases,
		cleanup: CleanupEvidence{
			status:            wire.Cleanup.Status,
			failure:           wire.Cleanup.Failure,
			assertionCount:    wire.Cleanup.AssertionCount,
			observationDigest: wire.Cleanup.ObservationDigest,
			evidenceDigest:    wire.Cleanup.EvidenceDigest,
		},
		status:       wire.Status,
		failure:      wire.Failure,
		reportDigest: wire.ReportDigest,
		buildSeal:    wire.BuildSeal,
	}
	if err := validateReport(report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidReport
	}
	return nil
}

func cloneMeasurements(input []Measurement) []Measurement {
	if len(input) == 0 {
		return []Measurement{}
	}
	return append([]Measurement(nil), input...)
}

func cloneCaseEvidence(input []CaseEvidence) []CaseEvidence {
	output := make([]CaseEvidence, len(input))
	for index, evidence := range input {
		output[index] = evidence
		output[index].measurements = cloneMeasurements(evidence.measurements)
	}
	return output
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// Binding getters.
func (b Binding) BuildID() string               { return b.wire.BuildID }
func (b Binding) SourceCommit() string          { return b.wire.SourceCommit }
func (b Binding) RuntimeManifestDigest() string { return b.wire.RuntimeManifestDigest }
func (b Binding) PrivateOverlayDigest() string  { return b.wire.PrivateOverlayDigest }
func (b Binding) ConformanceInputDigest() string {
	return b.wire.ConformanceInputDigest
}
func (b Binding) AuthorizationDigest() string { return b.wire.AuthorizationDigest }
func (b Binding) RunID() string               { return b.wire.RunID }
func (b Binding) ProfileID() string           { return b.wire.ProfileID }
func (b Binding) FleetGeneration() uint64     { return b.wire.FleetGeneration }
func (b Binding) ExpectedProfileEvidenceDigest() string {
	return b.wire.ExpectedProfileEvidenceDigest
}
func (b Binding) ExpectedNetworkEvidenceDigest() string {
	return b.wire.ExpectedNetworkEvidenceDigest
}
func (b Binding) PlanDigest() string { return b.wire.PlanDigest }
func (b Binding) Digest() string     { return b.wire.BindingDigest }

// Measurement getters.
func (m Measurement) Name() string  { return m.name }
func (m Measurement) Value() uint64 { return m.value }
func (m Measurement) Unit() string  { return m.unit }

// CaseEvidence getters.
func (e CaseEvidence) ID() CaseID                  { return e.id }
func (e CaseEvidence) Layer() ProofLayer           { return e.layer }
func (e CaseEvidence) Status() CaseStatus          { return e.status }
func (e CaseEvidence) Failure() FailureClass       { return e.failure }
func (e CaseEvidence) AssertionCount() uint64      { return e.assertionCount }
func (e CaseEvidence) ObservationDigest() string   { return e.observationDigest }
func (e CaseEvidence) EvidenceDigest() string      { return e.evidenceDigest }
func (e CaseEvidence) Measurements() []Measurement { return cloneMeasurements(e.measurements) }

// CleanupEvidence getters.
func (e CleanupEvidence) Status() CaseStatus        { return e.status }
func (e CleanupEvidence) Failure() FailureClass     { return e.failure }
func (e CleanupEvidence) AssertionCount() uint64    { return e.assertionCount }
func (e CleanupEvidence) ObservationDigest() string { return e.observationDigest }
func (e CleanupEvidence) EvidenceDigest() string    { return e.evidenceDigest }

// Report getters.
func (r Report) Binding() Binding { return r.binding }
func (r Report) ObservedProfileEvidenceDigest() string {
	return r.observedProfileEvidenceDigest
}
func (r Report) ObservedNetworkEvidenceDigest() string {
	return r.observedNetworkEvidenceDigest
}
func (r Report) Cases() []CaseEvidence    { return cloneCaseEvidence(r.cases) }
func (r Report) Cleanup() CleanupEvidence { return r.cleanup }
func (r Report) Status() CaseStatus       { return r.status }
func (r Report) Failure() FailureClass    { return r.failure }
func (r Report) Digest() string           { return r.reportDigest }
func (r Report) BuildSeal() string        { return r.buildSeal }
