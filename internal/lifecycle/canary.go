package lifecycle

import (
	"context"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// CanaryObserver records secret-free evidence at the existing lifecycle
// boundaries. It receives no JIT or reusable credential and grants no authority.
// Collect runs under the existing running reconciliation lock. ReportDigest
// binds completion evidence to the same atomic upstream event checkpoint.
// Completed is an idempotent post-commit callback before teardown; its failure
// leaves the checkpoint and result durable for ordinary cleanup.
type CanaryObserver interface {
	ReportDigest() string
	BeforeJIT(context.Context, controller.AssignmentKey, githubscale.ScaleSetCompatibilityReport) error
	AuthorizedJIT(context.Context, controller.AssignmentKey, controller.AcquisitionPermitBinding) error
	Collect(context.Context, controller.AssignmentKey, hostruntime.RecoverySpec) error
	Completed(context.Context, controller.AssignmentKey, string) error
	Reclaimed(context.Context, controller.AssignmentKey) error
}
