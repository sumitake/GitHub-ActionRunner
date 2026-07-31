package hostruntime

import (
	"context"
	"errors"
)

// ManagedQuiescence proves that the closed Portable-GHAR Docker namespace and
// broker root are both empty. It is an observation only; it never performs
// cleanup or creates missing directories.
type ManagedQuiescence interface {
	ProveManagedQuiescence(context.Context) error
}

var _ ManagedQuiescence = (*DockerCLI)(nil)

// ProveManagedQuiescence accepts only an exact empty Docker result followed by
// an exact empty, directly opened broker root.
func (c *DockerCLI) ProveManagedQuiescence(ctx context.Context) error {
	if c == nil {
		return errors.New("hostruntime: docker cli required")
	}
	if ctx == nil {
		return errors.New("hostruntime: context required")
	}
	result, err := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath,
			"ps",
			"-a",
			"--no-trunc",
			"--filter",
			"label=io.portable-ghar.managed=true",
			"--format",
			"{{.ID}}",
		},
		nil,
		nil,
	)
	if err != nil ||
		result.ExitCode != 0 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stdout) != 0 ||
		len(result.Stderr) != 0 {
		return errors.New("hostruntime: managed container quiescence unavailable")
	}
	if err := proveBrokerRootEmpty(c.cfg.BrokerRoot); err != nil {
		return errors.New("hostruntime: broker root quiescence unavailable")
	}
	return nil
}
