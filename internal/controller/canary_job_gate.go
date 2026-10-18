package controller

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/sumitake/portable-ghar/internal/githubscale"
)

var ErrCanaryJobRejected = errors.New("controller: canary job rejected")

// ErrCanaryJobPending is valid only before the first approved identity exists.
// It grants no poll/acquire/JIT authority and is never used after revocation.
var ErrCanaryJobPending = errors.New("controller: canary job approval pending")
var errPollAwaitCanaryJob = errors.New("controller: waiting for canary job approval")

// CanaryJobProvider supplies the independent, operator-approved job identity.
// A missing verifier grants no canary acquisition. It does not replace host,
// Worker, conformance, epoch or capacity authority.
type CanaryJobProvider interface {
	ExpectedCanaryJob(context.Context) (CanaryJobIdentity, error)
}

// CanaryJobIdentity identifies the single approved manual run. The operator
// obtains its run ID and immutable revision from authenticated GitHub metadata;
// the scale-set offer carries the run ID/ref/event, but no source revision.
type CanaryJobIdentity struct {
	RepositoryAlias string `json:"repository_alias"`
	Repository      string `json:"repository"`
	ScaleSet        string `json:"scale_set"`
	WorkflowRef     string `json:"workflow_ref"`
	WorkflowRunID   int64  `json:"workflow_run_id"`
	EventName       string `json:"event_name"`
}

var canaryRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$`)
var canaryWorkflowRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml@refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9/_.-]{0,255}$`)

func (job CanaryJobIdentity) Validate() error {
	if !validAcquisitionScalar(job.RepositoryAlias, maxAcquisitionRepositoryBytes) ||
		!validAcquisitionScalar(job.ScaleSet, maxAcquisitionScaleSetBytes) ||
		!canaryRepositoryPattern.MatchString(job.Repository) ||
		job.WorkflowRunID <= 0 || job.WorkflowRunID > 9007199254740991 ||
		job.EventName != "workflow_dispatch" {
		return ErrCanaryJobRejected
	}
	prefix := job.Repository + "/.github/workflows/"
	if !strings.HasPrefix(job.WorkflowRef, prefix) || !canaryWorkflowRefPattern.MatchString(strings.TrimPrefix(job.WorkflowRef, prefix)) || strings.Contains(job.WorkflowRef, "..") || strings.HasSuffix(job.WorkflowRef, "/") || strings.HasSuffix(job.WorkflowRef, ".") {
		return ErrCanaryJobRejected
	}
	return nil
}

func (job CanaryJobIdentity) VerifyCanaryOffer(ctx context.Context, alias, scaleSet string, offer githubscale.Offer) error {
	// The pinned adapter preserves the wire's separate owner and bare repository
	// fields. Existing durable offers can also contain the qualified spelling.
	// Both must resolve to the same exact owner/repository and workflow ref.
	repository := offer.RepositoryName
	if !strings.Contains(repository, "/") {
		repository = offer.OwnerName + "/" + repository
	}
	if ctx == nil || ctx.Err() != nil || job.Validate() != nil ||
		alias != job.RepositoryAlias || scaleSet != job.ScaleSet ||
		repository != job.Repository || offer.OwnerName != strings.SplitN(job.Repository, "/", 2)[0] ||
		offer.WorkflowRunID != job.WorkflowRunID || offer.JobWorkflowRef != job.WorkflowRef ||
		offer.EventName != job.EventName || len(offer.RequestLabels) != 1 || offer.RequestLabels[0] != job.ScaleSet {
		return ErrCanaryJobRejected
	}
	return nil
}

func (job CanaryJobIdentity) ExpectedCanaryJob(ctx context.Context) (CanaryJobIdentity, error) {
	if ctx == nil || ctx.Err() != nil || job.Validate() != nil {
		return CanaryJobIdentity{}, ErrCanaryJobRejected
	}
	return job, nil
}

func (s *Service) expectedCanaryJob(ctx context.Context) (CanaryJobIdentity, error) {
	if s.canaryJobs == nil {
		return CanaryJobIdentity{}, ErrCanaryJobRejected
	}
	job, err := s.canaryJobs.ExpectedCanaryJob(ctx)
	if errors.Is(err, ErrCanaryJobPending) {
		return CanaryJobIdentity{}, ErrCanaryJobPending
	}
	if err != nil || job.Validate() != nil {
		return CanaryJobIdentity{}, ErrCanaryJobRejected
	}
	return job, nil
}

func (s *Service) verifyCanaryOffer(ctx context.Context, policy AcquisitionPolicy, alias, scaleSet string, offer githubscale.Offer) error {
	if policy.Mode != AcquisitionCanaryOnly {
		return nil
	}
	expected, err := s.expectedCanaryJob(ctx)
	if err != nil {
		return ErrCanaryJobRejected
	}
	return expected.VerifyCanaryOffer(ctx, alias, scaleSet, cloneServiceOffer(offer))
}
