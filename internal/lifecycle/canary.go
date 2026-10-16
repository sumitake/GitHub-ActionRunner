package lifecycle

import (
	"context"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// CanaryObserver records secret-free evidence at the existing lifecycle
// boundaries. It receives no JIT or reusable credential and grants no authority.
// Collect runs under the existing running reconciliation lock. Completed runs
// after the exact upstream event is durable and before teardown;
// a failure there leaves JOB_FINISHED available for ordinary cleanup.
type CanaryObserver interface {
	BeforeJIT(context.Context, controller.AssignmentKey, githubscale.ScaleSetCompatibilityReport) error
	AuthorizedJIT(context.Context, controller.AssignmentKey, controller.AcquisitionPermitBinding) error
	Collect(context.Context, controller.AssignmentKey, hostruntime.RecoverySpec) error
	Completed(context.Context, controller.AssignmentKey, string) error
	Reclaimed(context.Context, controller.AssignmentKey) error
}
