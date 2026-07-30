package testenv

import (
	"context"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

func (f *Fixture) Binding() (conformance.Binding, error) {
	if f == nil {
		return conformance.Binding{}, conformance.ErrInput
	}
	return f.binding, nil
}

func (f *Fixture) RunActualHost(
	ctx context.Context,
	id conformance.ActualHostCaseID,
) (conformance.ActualHostResult, error) {
	if f == nil || f.cases == nil {
		return conformance.ActualHostResult{}, conformance.ErrObservation
	}
	caseID := actualCaseToID(id)
	if !f.beginCase(caseID) {
		return conformance.ActualHostResult{}, conformance.ErrInvariant
	}
	result, err := f.cases.RunActualHost(ctx, id)
	if !f.finishCase(caseID, err == nil) {
		return conformance.ActualHostResult{}, conformance.ErrInvariant
	}
	return result, err
}

func (f *Fixture) RunSynthetic(
	ctx context.Context,
	id conformance.SyntheticCaseID,
) (conformance.SyntheticResult, error) {
	if f == nil || f.cases == nil {
		return conformance.SyntheticResult{}, conformance.ErrObservation
	}
	caseID := syntheticCaseToID(id)
	if !f.beginCase(caseID) {
		return conformance.SyntheticResult{}, conformance.ErrInvariant
	}
	result, err := f.cases.RunSynthetic(ctx, id)
	if !f.finishCase(caseID, err == nil) {
		return conformance.SyntheticResult{}, conformance.ErrInvariant
	}
	return result, err
}

func (*Fixture) RunActualGitHub(
	context.Context,
) (conformance.ActualGitHubResult, error) {
	return conformance.PendingActualGitHubTransport(), nil
}

func (f *Fixture) FinalizeTarget(
	ctx context.Context,
) (conformance.TargetObservation, error) {
	if f == nil || f.finalizer == nil || ctx == nil {
		return conformance.TargetObservation{}, conformance.ErrObservation
	}
	completed, ok := f.completedCaseSet()
	if !ok {
		return conformance.TargetObservation{}, conformance.ErrInvariant
	}
	input, err := f.finalizer.Finalize(ctx, completed)
	if err != nil {
		return conformance.TargetObservation{}, err
	}
	return conformance.SealTargetObservation(input)
}

func (f *Fixture) ActualHostTimeout(
	id conformance.ActualHostCaseID,
) time.Duration {
	return f.caseTimeout(actualCaseToID(id))
}

func (f *Fixture) SyntheticTimeout(
	id conformance.SyntheticCaseID,
) time.Duration {
	return f.caseTimeout(syntheticCaseToID(id))
}

func (f *Fixture) ActualGitHubTimeout() time.Duration {
	return f.caseTimeout(conformance.CaseActualGitHubTransport)
}

func (f *Fixture) CleanupTimeout() time.Duration {
	if f == nil {
		return 0
	}
	return durationMilliseconds(f.input.Limits.CleanupTimeoutMilliseconds)
}

func (f *Fixture) caseTimeout(id conformance.CaseID) time.Duration {
	if f == nil || id == "" {
		return 0
	}
	for _, timeout := range f.input.Limits.CaseTimeouts {
		if timeout.CaseID == id {
			return durationMilliseconds(timeout.TimeoutMilliseconds)
		}
	}
	return 0
}

func actualCaseToID(id conformance.ActualHostCaseID) conformance.CaseID {
	switch id {
	case conformance.ActualHostProfile:
		return conformance.CaseHostProfile
	case conformance.ActualNamespaceBaseline:
		return conformance.CaseNamespaceBaseline
	case conformance.ActualBrokerEgress:
		return conformance.CaseBrokerEgress
	case conformance.ActualMountAndSecretIsolation:
		return conformance.CaseMountAndSecretIsolation
	case conformance.ActualRunnerSandbox:
		return conformance.CaseSandbox
	case conformance.ActualRunnerPayload:
		return conformance.CaseRunnerPayload
	case conformance.ActualProxyToolCompatibility:
		return conformance.CaseProxyToolCompatibility
	default:
		return ""
	}
}

func syntheticCaseToID(id conformance.SyntheticCaseID) conformance.CaseID {
	switch id {
	case conformance.SyntheticOneJob:
		return conformance.CaseSyntheticOneJob
	case conformance.SyntheticCleanupMatrix:
		return conformance.CaseCleanupMatrix
	case conformance.SyntheticReclamationSeries:
		return conformance.CaseReclamationSeries
	case conformance.SyntheticSeedIsolation:
		return conformance.CaseSeedIsolation
	case conformance.SyntheticWatchdogRecovery:
		return conformance.CaseWatchdogRecovery
	case conformance.SyntheticLegacyFenceRecovery:
		return conformance.CaseLegacyFenceRecovery
	case conformance.SyntheticNoncancellableShutdown:
		return conformance.CaseNoncancellableShutdown
	default:
		return ""
	}
}

func (f *Fixture) VerifyHostProfile(ctx context.Context) error {
	_, err := f.RunActualHost(ctx, conformance.ActualHostProfile)
	return err
}

func (f *Fixture) VerifyNamespaceBaseline(ctx context.Context) error {
	_, err := f.RunActualHost(ctx, conformance.ActualNamespaceBaseline)
	return err
}

func (f *Fixture) VerifyBrokerEgress(ctx context.Context) error {
	_, err := f.RunActualHost(ctx, conformance.ActualBrokerEgress)
	return err
}

func (f *Fixture) VerifyMountAndSecretIsolation(ctx context.Context) error {
	_, err := f.RunActualHost(
		ctx,
		conformance.ActualMountAndSecretIsolation,
	)
	return err
}

func (f *Fixture) VerifyRunnerSandbox(ctx context.Context) error {
	_, err := f.RunActualHost(ctx, conformance.ActualRunnerSandbox)
	return err
}

func (f *Fixture) VerifyRunnerPayload(ctx context.Context) error {
	_, err := f.RunActualHost(ctx, conformance.ActualRunnerPayload)
	return err
}

func (f *Fixture) VerifyWorkflowTools(ctx context.Context) error {
	_, err := f.RunActualHost(
		ctx,
		conformance.ActualProxyToolCompatibility,
	)
	return err
}

func (f *Fixture) VerifySyntheticOneJob(ctx context.Context) error {
	_, err := f.RunSynthetic(ctx, conformance.SyntheticOneJob)
	return err
}

func (f *Fixture) VerifyCleanupMatrix(ctx context.Context) error {
	_, err := f.RunSynthetic(ctx, conformance.SyntheticCleanupMatrix)
	return err
}

func (f *Fixture) VerifyReclamationSeries(ctx context.Context) error {
	_, err := f.RunSynthetic(ctx, conformance.SyntheticReclamationSeries)
	return err
}

func (f *Fixture) VerifySeedIsolation(ctx context.Context) error {
	_, err := f.RunSynthetic(ctx, conformance.SyntheticSeedIsolation)
	return err
}

func (f *Fixture) VerifyWatchdogRecovery(ctx context.Context) error {
	_, err := f.RunSynthetic(ctx, conformance.SyntheticWatchdogRecovery)
	return err
}

func (f *Fixture) VerifyLegacyFenceRecovery(ctx context.Context) error {
	_, err := f.RunSynthetic(ctx, conformance.SyntheticLegacyFenceRecovery)
	return err
}

func (f *Fixture) VerifyNoncancellableShutdown(ctx context.Context) error {
	_, err := f.RunSynthetic(
		ctx,
		conformance.SyntheticNoncancellableShutdown,
	)
	return err
}
