package hostruntime

import (
	"context"
	"errors"
)

// RemoveRunner consumes only an engine-issued opaque handle. A successfully
// released runner no longer needs an in-memory gate record, so its still-valid
// handle remains sufficient for later whole-container reclamation.
func (c *DockerCLI) RemoveRunner(ctx context.Context, handle RunnerHandle) error {
	if c == nil || !handle.validFor(c.issuer) {
		return errors.New("hostruntime: runner handle invalid")
	}
	c.mu.Lock()
	record := c.runners[handle.nonce]
	if record != nil {
		if record.handle.id != handle.id || record.busy {
			c.mu.Unlock()
			return errors.New("hostruntime: runner removal state invalid")
		}
		record.destroyed = true
		zeroToken(&record.token)
	}
	c.mu.Unlock()
	if err := c.removeRunnerID(ctx, handle.id); err != nil {
		return err
	}
	c.forgetRunnerRecord(record)
	return nil
}

// RemoveNetworkAdapter reclaims an adapter and its bounded controller record.
// Failed Docker removal retains only the tombstone needed for an explicit
// retry; successful removal deletes it immediately.
func (c *DockerCLI) RemoveNetworkAdapter(ctx context.Context, handle AdapterHandle) error {
	if c == nil || !handle.validFor(c.issuer) {
		return errors.New("hostruntime: adapter handle invalid")
	}
	c.mu.Lock()
	record := c.adapters[handle.nonce]
	if record != nil {
		if record.handle.id != handle.id || record.busy {
			c.mu.Unlock()
			return errors.New("hostruntime: adapter removal state invalid")
		}
		for _, runner := range c.runners {
			if runner != nil && runner.adapter.nonce == handle.nonce {
				c.mu.Unlock()
				return errors.New("hostruntime: adapter still owns a runner")
			}
		}
		record.destroyed = true
	}
	c.mu.Unlock()
	if err := c.removeAdapterID(ctx, handle.id); err != nil {
		return err
	}
	c.forgetAdapterRecord(record)
	return nil
}

func (c *DockerCLI) forgetRunnerRecord(record *runnerRecord) {
	if c == nil || record == nil {
		return
	}
	c.mu.Lock()
	if c.runners[record.handle.nonce] == record {
		delete(c.runners, record.handle.nonce)
	}
	c.mu.Unlock()
}

func (c *DockerCLI) forgetAdapterRecord(record *adapterRecord) {
	if c == nil || record == nil {
		return
	}
	c.mu.Lock()
	if c.adapters[record.handle.nonce] == record {
		delete(c.adapters, record.handle.nonce)
	}
	c.mu.Unlock()
}

func (c *DockerCLI) removeFailedRunner(ctx context.Context, record *runnerRecord) {
	if record != nil && c.removeRunnerID(ctx, record.handle.id) == nil {
		c.forgetRunnerRecord(record)
	}
}

func (c *DockerCLI) removeFailedAdapter(ctx context.Context, record *adapterRecord) {
	if record != nil && c.removeAdapterID(ctx, record.handle.id) == nil {
		c.forgetAdapterRecord(record)
	}
}
