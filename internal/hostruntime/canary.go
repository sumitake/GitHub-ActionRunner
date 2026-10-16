package hostruntime

import (
	"bytes"
	"context"

	"github.com/sumitake/portable-ghar/internal/canary"
)

// ReadCanaryWorkflow queries the fixed, bounded reporting command in the exact
// live runner identity after checking its managed slot inventory. The workflow's
// final step remains alive until this stream has been read. Nil means pending.
// Raw command bytes never become errors or durable evidence.
func (c *DockerCLI) ReadCanaryWorkflow(ctx context.Context, spec RecoverySpec) (*canary.Workflow, error) {
	if ctx == nil || spec.ExpectedRunnerID == "" {
		return nil, canary.ErrEvidence
	}
	snapshot, err := c.InspectManaged(ctx, spec)
	if err != nil {
		return nil, canary.ErrEvidence
	}
	runnerID := snapshot.Identities().RunnerID
	if runnerID == "" || !snapshot.Observation().RunnerRunning {
		return nil, canary.ErrEvidence
	}
	result, err := c.runner.Run(ctx, []string{c.cfg.DockerPath, "exec", runnerID, runnerEntrypoint, "canary-read"}, nil, nil)
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	if err != nil || result.ExitCode != 0 || result.Signaled || result.StdoutTruncated || result.StderrTruncated || len(result.Stderr) != 0 {
		return nil, canary.ErrEvidence
	}
	document := bytes.TrimSuffix(result.Stdout, []byte{'\n'})
	probe, err := canary.ParseProbe(document)
	if err != nil {
		return nil, err
	}
	return probe.Workflow, nil
}
