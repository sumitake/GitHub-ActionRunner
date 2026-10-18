package main

import (
	"context"

	"github.com/sumitake/portable-ghar/internal/canary"
	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/lifecycle"
)

type canaryEvidenceWriter interface {
	InitCanaryEvidence(context.Context, canary.Record) error
	BeginCanaryJIT(context.Context, string, controller.AssignmentKey, githubscale.ScaleSetCompatibilityReport) error
	BindCanaryJITPermit(context.Context, string, controller.AssignmentKey, controller.AcquisitionPermitBinding) error
	CanaryWorkflowRecorded(context.Context, string, controller.AssignmentKey) (bool, error)
	RecordCanaryWorkflow(context.Context, string, controller.AssignmentKey, canary.Workflow) error
	CompleteCanaryJob(context.Context, string, controller.AssignmentKey, string) error
	MarkCanaryCleanup(context.Context, string, controller.AssignmentKey) error
}
type canaryWorkflowReader interface {
	ReadCanaryWorkflow(context.Context, hostruntime.RecoverySpec) (*canary.Workflow, error)
}
type productionCanaryObserver struct {
	reportDigest string
	store        canaryEvidenceWriter
	reader       canaryWorkflowReader
}

func (o *productionCanaryObserver) ReportDigest() string { return o.reportDigest }

func newProductionCanaryObserver(ctx context.Context, report conformance.Report, runtime productionRuntime, store canaryEvidenceWriter, reader canaryWorkflowReader) (lifecycle.CanaryObserver, error) {
	if report.Status() != conformance.StatusPending {
		return nil, nil
	}
	if ctx == nil || ctx.Err() != nil || store == nil || reader == nil {
		return nil, errCommandUnavailable
	}
	binding := report.Binding()
	// The manifest commits the image, policy, network, and storage tuple. The
	// overlay commits the concrete host composition. Keep the original D2 run's
	// complete binding rather than reconstructing or relaxing any of its anchors.
	if !reportMatchesCanaryRuntime(report, runtime) {
		return nil, errCommandUnavailable
	}
	seed := canary.Record{Version: 1, ReportDigest: report.Digest(), BindingDigest: binding.Digest(), FleetGeneration: binding.FleetGeneration()}
	if err := store.InitCanaryEvidence(ctx, seed); err != nil {
		return nil, errCommandUnavailable
	}
	return &productionCanaryObserver{reportDigest: report.Digest(), store: store, reader: reader}, nil
}
func (o *productionCanaryObserver) BeforeJIT(ctx context.Context, key controller.AssignmentKey, compatibility githubscale.ScaleSetCompatibilityReport) error {
	return o.store.BeginCanaryJIT(ctx, o.reportDigest, key, compatibility)
}
func (o *productionCanaryObserver) AuthorizedJIT(ctx context.Context, key controller.AssignmentKey, binding controller.AcquisitionPermitBinding) error {
	return o.store.BindCanaryJITPermit(ctx, o.reportDigest, key, binding)
}
func (o *productionCanaryObserver) Collect(ctx context.Context, key controller.AssignmentKey, spec hostruntime.RecoverySpec) error {
	recorded, err := o.store.CanaryWorkflowRecorded(ctx, o.reportDigest, key)
	if err != nil || recorded {
		return err
	}
	workflow, err := o.reader.ReadCanaryWorkflow(ctx, spec)
	if err != nil {
		return err
	}
	if workflow == nil {
		return nil
	}
	return o.store.RecordCanaryWorkflow(ctx, o.reportDigest, key, *workflow)
}
func (o *productionCanaryObserver) Completed(ctx context.Context, key controller.AssignmentKey, result string) error {
	return o.store.CompleteCanaryJob(ctx, o.reportDigest, key, result)
}
func (o *productionCanaryObserver) Reclaimed(ctx context.Context, key controller.AssignmentKey) error {
	return o.store.MarkCanaryCleanup(ctx, o.reportDigest, key)
}

func completeCanaryReport(pending conformance.Report, record canary.Record) (conformance.Report, error) {
	if err := record.Ready(pending.Digest(), pending.Binding().Digest(), pending.Binding().FleetGeneration()); err != nil {
		return conformance.Report{}, err
	}
	digest, err := record.Digest()
	if err != nil {
		return conformance.Report{}, err
	}
	// One aggregate lifecycle/sandbox assertion plus each successful tool probe.
	result, err := conformance.SealActualGitHubTransport(conformance.ActualGitHubObservation{
		AssertionCount: uint64(1 + len(record.Workflow.Tools)), ObservationDigest: digest,
		Measurements: []conformance.MeasurementInput{{Name: "job_count", Value: 1, Unit: "count"}, {Name: "tool_count", Value: uint64(len(record.Workflow.Tools)), Unit: "count"}},
	})
	if err != nil {
		return conformance.Report{}, err
	}
	return conformance.CompleteActualGitHubTransport(pending, result)
}

func reportMatchesCanaryRuntime(report conformance.Report, runtime productionRuntime) bool {
	binding := report.Binding()
	return binding.BuildID() == runtime.manifest.BuildID && binding.ProfileID() == runtime.overlay.Target.ProfileID && binding.FleetGeneration() == runtime.manifest.FleetGeneration && binding.RuntimeManifestDigest() == runtime.overlay.Manifest.Digest && binding.PrivateOverlayDigest() == runtime.overlayDigest
}
