package githubscale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/actions/scaleset"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

// withOperationDeadline derives a child context bounded by timeout,
// applied on TOP of ctx's own deadline. context.WithTimeout always keeps
// whichever of the two deadlines is EARLIER, so this never loosens a
// caller-supplied tighter deadline -- it only guarantees an upper bound
// exists even when the caller passes context.Background(). Every Session
// method below calls this before issuing its single upstream request.
func withOperationDeadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// v040Session is Session's only production implementation: a pinned
// wrapper around one *scaleset.Client (for JIT/runner operations) and one
// *scaleset.MessageSessionClient (for poll/ack/acquire), as produced by
// (*client).Open. No exported method returns or accepts an upstream
// scaleset type.
type v040Session struct {
	upstreamClient  *scaleset.Client
	upstreamSession *scaleset.MessageSessionClient
	scaleSetID      int
	opTimeout       time.Duration
	gate            *serializationGate
	compatibility   ScaleSetCompatibilityReport
}

// Compatibility implements Session.
func (s *v040Session) Compatibility() ScaleSetCompatibilityReport {
	return s.compatibility
}

func (s *v040Session) beginOperation(ctx context.Context) (context.Context, func(), error) {
	cctx, cancel := withOperationDeadline(ctx, s.opTimeout)
	release, err := s.gate.enter(cctx)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return cctx, func() {
		cancel()
		release()
	}, nil
}

// Poll implements Session. It never acks (deletes) the message it
// returns -- see Ack.
func (s *v040Session) Poll(ctx context.Context, lastMessageID, maxCapacity int) (Batch, error) {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return Batch{}, fmt.Errorf("githubscale: poll: wait for serialization: %w", err)
	}
	defer done()

	msg, err := s.upstreamSession.GetMessage(cctx, lastMessageID, maxCapacity)
	if err != nil {
		return Batch{}, sanitizeUpstreamError(cctx, "poll", err)
	}
	return translateBatch(msg), nil
}

// Ack implements Session: a separate, explicit call from Poll. The
// adapter itself never calls this internally from Poll -- see
// TestAckDisciplineNeverCalledInternallyByPoll.
func (s *v040Session) Ack(ctx context.Context, messageID int) error {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return fmt.Errorf("githubscale: ack: wait for serialization: %w", err)
	}
	defer done()

	if err := s.upstreamSession.DeleteMessage(cctx, messageID); err != nil {
		return sanitizeUpstreamError(cctx, "ack", err)
	}
	return nil
}

// Acquire implements Session.
func (s *v040Session) Acquire(ctx context.Context, requestIDs []int64) ([]int64, error) {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return nil, fmt.Errorf("githubscale: acquire: wait for serialization: %w", err)
	}
	defer done()

	ids, err := s.upstreamSession.AcquireJobs(cctx, requestIDs)
	if err != nil {
		return nil, sanitizeUpstreamError(cctx, "acquire", err)
	}
	return ids, nil
}

// GenerateJIT implements Session. It rejects (with ErrJITShapeMismatch) any
// upstream response missing its runner reference or its encoded config,
// and wraps the encoded JIT bytes into a redaction.Secret immediately --
// the upstream string is cleared from the response struct in the same
// step so no further Go-visible reference to the plaintext remains outside
// the Secret.
func (s *v040Session) GenerateJIT(ctx context.Context, req JITRequest) (JITConfig, error) {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return JITConfig{}, fmt.Errorf("githubscale: generate jit: wait for serialization: %w", err)
	}
	defer done()

	cfg, err := s.upstreamClient.GenerateJitRunnerConfig(
		cctx,
		&scaleset.RunnerScaleSetJitRunnerSetting{
			Name:       req.RunnerName,
			WorkFolder: req.WorkFolder,
		},
		s.scaleSetID,
	)
	if err != nil {
		return JITConfig{}, sanitizeUpstreamError(cctx, "generate jit", err)
	}
	if cfg == nil {
		return JITConfig{}, fmt.Errorf("githubscale: generate jit: %w", ErrJITShapeMismatch)
	}

	var secret *redaction.Secret
	if cfg.EncodedJITConfig != "" {
		secret = redaction.SecretFromBytes([]byte(cfg.EncodedJITConfig))
		cfg.EncodedJITConfig = ""
	}
	if cfg.Runner == nil || secret == nil {
		if secret != nil {
			secret.Destroy()
		}
		return JITConfig{}, fmt.Errorf("githubscale: generate jit: %w", ErrJITShapeMismatch)
	}
	if err := verifyRunnerIdentity(cfg.Runner, s.scaleSetID, req.RunnerName, nil); err != nil {
		secret.Destroy()
		return JITConfig{}, fmt.Errorf("githubscale: generate jit: %w", err)
	}

	return JITConfig{
		Runner:  translateRunnerRef(cfg.Runner),
		Encoded: secret,
	}, nil
}

// sanitizeUpstreamError preserves only closed, adapter-owned error
// classifications. The pinned upstream client includes untrusted response
// bodies in many error strings, so no upstream error value may cross this
// package boundary -- even when the body is not expected to carry JIT data.
func sanitizeUpstreamError(ctx context.Context, operation string, err error) error {
	if errors.Is(err, ErrResponseTooLarge) {
		return fmt.Errorf("githubscale: %s: %w", operation, ErrResponseTooLarge)
	}
	if ctx != nil {
		switch ctx.Err() {
		case context.Canceled:
			return fmt.Errorf("githubscale: %s: %w", operation, context.Canceled)
		case context.DeadlineExceeded:
			return fmt.Errorf("githubscale: %s: %w", operation, context.DeadlineExceeded)
		}
	}

	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Errorf("githubscale: %s: %w", operation, ErrUpstreamTimeout)
	default:
		return fmt.Errorf("githubscale: %s: %w", operation, ErrUpstreamRequest)
	}
}

// GetRunnerByName implements Session.
func (s *v040Session) GetRunnerByName(ctx context.Context, name string) (RunnerRef, bool, error) {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return RunnerRef{}, false, fmt.Errorf("githubscale: get runner by name: wait for serialization: %w", err)
	}
	defer done()

	ref, err := s.upstreamClient.GetRunnerByName(cctx, name)
	if err != nil {
		if errors.Is(err, scaleset.RunnerNotFoundError) {
			return RunnerRef{}, false, nil
		}
		return RunnerRef{}, false, sanitizeUpstreamError(cctx, "get runner by name", err)
	}
	if ref == nil {
		return RunnerRef{}, false, nil
	}
	if err := verifyRunnerIdentity(ref, s.scaleSetID, name, nil); err != nil {
		return RunnerRef{}, false, fmt.Errorf("githubscale: get runner by name: %w", err)
	}
	return translateRunnerRef(ref), true, nil
}

// GetRunner implements Session.
func (s *v040Session) GetRunner(ctx context.Context, id int64) (RunnerRef, bool, error) {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return RunnerRef{}, false, fmt.Errorf("githubscale: get runner: wait for serialization: %w", err)
	}
	defer done()

	ref, err := s.upstreamClient.GetRunner(cctx, int(id))
	if err != nil {
		if errors.Is(err, scaleset.RunnerNotFoundError) {
			return RunnerRef{}, false, nil
		}
		return RunnerRef{}, false, sanitizeUpstreamError(cctx, "get runner", err)
	}
	if ref == nil {
		return RunnerRef{}, false, nil
	}
	if err := verifyRunnerIdentity(ref, s.scaleSetID, "", &id); err != nil {
		return RunnerRef{}, false, fmt.Errorf("githubscale: get runner: %w", err)
	}
	return translateRunnerRef(ref), true, nil
}

func verifyRunnerIdentity(ref *scaleset.RunnerReference, scaleSetID int, expectedName string, expectedID *int64) error {
	if ref.RunnerScaleSetID != scaleSetID {
		return fmt.Errorf("%w: runner scale-set id %d does not match session scale-set id %d", ErrIdentityMismatch, ref.RunnerScaleSetID, scaleSetID)
	}
	if expectedName != "" && ref.Name != expectedName {
		return fmt.Errorf("%w: returned runner name %q does not match requested name %q", ErrIdentityMismatch, ref.Name, expectedName)
	}
	if expectedID != nil && int64(ref.ID) != *expectedID {
		return fmt.Errorf("%w: returned runner id %d does not match requested id %d", ErrIdentityMismatch, ref.ID, *expectedID)
	}
	return nil
}

// RemoveRunner implements Session.
func (s *v040Session) RemoveRunner(ctx context.Context, id int64) error {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return fmt.Errorf("githubscale: remove runner: wait for serialization: %w", err)
	}
	defer done()

	ref, err := s.upstreamClient.GetRunner(cctx, int(id))
	if err != nil {
		if errors.Is(err, scaleset.RunnerNotFoundError) {
			return nil
		}
		return sanitizeUpstreamError(cctx, "remove runner: lookup", err)
	}
	if ref == nil {
		return nil
	}
	if err := verifyRunnerIdentity(ref, s.scaleSetID, "", &id); err != nil {
		return fmt.Errorf("githubscale: remove runner: %w", err)
	}

	if err := s.upstreamClient.RemoveRunner(cctx, id); err != nil {
		if errors.Is(err, scaleset.RunnerNotFoundError) {
			return nil
		}
		return sanitizeUpstreamError(cctx, "remove runner: delete", err)
	}
	return nil
}

// Close implements Session: it releases the upstream message session. It
// does not close or otherwise invalidate the Client that opened this
// Session (s.upstreamClient is left alone).
func (s *v040Session) Close(ctx context.Context) error {
	cctx, done, err := s.beginOperation(ctx)
	if err != nil {
		return fmt.Errorf("githubscale: close: wait for serialization: %w", err)
	}
	defer done()

	if err := s.upstreamSession.Close(cctx); err != nil {
		return sanitizeUpstreamError(cctx, "close", err)
	}
	return nil
}

// translateBatch converts an upstream *scaleset.RunnerScaleSetMessage --
// including the upstream API's documented nil response for "no message
// available" -- into this package's internal Batch. No upstream type
// survives past this function.
func translateBatch(msg *scaleset.RunnerScaleSetMessage) Batch {
	if msg == nil {
		return Batch{Empty: true}
	}

	b := Batch{
		MessageID:         msg.MessageID,
		StatisticsPresent: msg.Statistics != nil,
		Statistics:        translateStatistics(msg.Statistics),
	}

	for _, m := range msg.JobAvailableMessages {
		if m == nil {
			continue
		}
		b.Offers = append(b.Offers, Offer{
			JobRef:        translateJobRef(m.JobMessageBase),
			AcquireJobURL: m.AcquireJobURL,
		})
	}
	for _, m := range msg.JobAssignedMessages {
		if m == nil {
			continue
		}
		b.Assigned = append(b.Assigned, AssignedEvent{
			JobRef: translateJobRef(m.JobMessageBase),
		})
	}
	for _, m := range msg.JobStartedMessages {
		if m == nil {
			continue
		}
		b.Started = append(b.Started, StartedEvent{
			JobRef:     translateJobRef(m.JobMessageBase),
			RunnerID:   int64(m.RunnerID),
			RunnerName: m.RunnerName,
		})
	}
	for _, m := range msg.JobCompletedMessages {
		if m == nil {
			continue
		}
		b.Completed = append(b.Completed, CompletedEvent{
			JobRef:     translateJobRef(m.JobMessageBase),
			Result:     m.Result,
			RunnerID:   int64(m.RunnerID),
			RunnerName: m.RunnerName,
		})
	}

	return b
}

// translateJobRef converts upstream's scaleset.JobMessageBase (the fields
// shared by all four job-message shapes) into this package's JobRef.
func translateJobRef(base scaleset.JobMessageBase) JobRef {
	return JobRef{
		RunnerRequestID:    base.RunnerRequestID,
		JobID:              base.JobID,
		RepositoryName:     base.RepositoryName,
		OwnerName:          base.OwnerName,
		JobWorkflowRef:     base.JobWorkflowRef,
		JobDisplayName:     base.JobDisplayName,
		WorkflowRunID:      base.WorkflowRunID,
		EventName:          base.EventName,
		RequestLabels:      append([]string(nil), base.RequestLabels...),
		QueueTime:          base.QueueTime,
		ScaleSetAssignTime: base.ScaleSetAssignTime,
		RunnerAssignTime:   base.RunnerAssignTime,
		FinishTime:         base.FinishTime,
	}
}

// translateStatistics converts upstream's *scaleset.RunnerScaleSetStatistic
// into this package's Statistics, preserving TotalAssignedJobs (and every
// other counter) unchanged. A nil upstream pointer translates to the zero
// value.
func translateStatistics(stats *scaleset.RunnerScaleSetStatistic) Statistics {
	if stats == nil {
		return Statistics{}
	}
	return Statistics{
		TotalAvailableJobs:     stats.TotalAvailableJobs,
		TotalAcquiredJobs:      stats.TotalAcquiredJobs,
		TotalAssignedJobs:      stats.TotalAssignedJobs,
		TotalRunningJobs:       stats.TotalRunningJobs,
		TotalRegisteredRunners: stats.TotalRegisteredRunners,
		TotalBusyRunners:       stats.TotalBusyRunners,
		TotalIdleRunners:       stats.TotalIdleRunners,
	}
}

// translateRunnerRef converts upstream's *scaleset.RunnerReference into
// this package's RunnerRef. Callers must not pass a nil ref (both call
// sites in this file check for nil first and return ErrRunnerNotFound /
// ErrJITShapeMismatch instead).
func translateRunnerRef(ref *scaleset.RunnerReference) RunnerRef {
	return RunnerRef{
		ID:               int64(ref.ID),
		Name:             ref.Name,
		RunnerScaleSetID: ref.RunnerScaleSetID,
	}
}
