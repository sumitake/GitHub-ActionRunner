package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// RemoveNetworkBroker reclaims the one broker container before removing its
// two per-job socket directories. A failed step retains only a retryable
// tombstone; successful cleanup deletes the bounded record.
func (c *DockerCLI) RemoveNetworkBroker(
	ctx context.Context,
	handle BrokerHandle,
) error {
	if c == nil || !handle.validFor(c.issuer) {
		return errors.New("hostruntime: broker handle invalid")
	}
	c.mu.Lock()
	record := c.brokers[handle.nonce]
	if record == nil || record.handle.id != handle.id {
		c.mu.Unlock()
		return errors.New("hostruntime: broker record unavailable")
	}
	if record.busy {
		c.mu.Unlock()
		return errors.New("hostruntime: broker removal state invalid")
	}
	record.destroyed = true
	zeroToken(&record.token)
	c.mu.Unlock()

	if err := c.removeBrokerResources(ctx, record); err != nil {
		return err
	}
	c.forgetBrokerRecord(record)
	return nil
}

func (c *DockerCLI) removeBrokerID(parent context.Context, id string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), cleanupTimeout)
	defer cancel()
	result, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "rm", "-f", id},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated {
		return errors.New("hostruntime: broker removal failed")
	}
	return nil
}

func (c *DockerCLI) removeBrokerResources(
	ctx context.Context,
	record *brokerRecord,
) error {
	if record == nil {
		return errors.New("hostruntime: broker removal record unavailable")
	}
	c.mu.Lock()
	containerRemoved := record.containerRemoved
	directoriesGone := record.directoriesGone
	c.mu.Unlock()

	if !containerRemoved {
		if err := c.removeBrokerID(ctx, record.handle.id); err != nil {
			return err
		}
		c.mu.Lock()
		record.containerRemoved = true
		c.mu.Unlock()
	}
	if !directoriesGone {
		if err := c.removeBrokerDirectory(record.spec.AuthorityParent); err != nil {
			return err
		}
		if err := c.removeBrokerDirectory(record.spec.RelayParent); err != nil {
			return err
		}
		c.mu.Lock()
		record.directoriesGone = true
		c.mu.Unlock()
	}
	return nil
}

func (c *DockerCLI) removeBrokerDirectory(path string) error {
	if err := validateDescendant(c.cfg.BrokerRoot, path, "broker cleanup path"); err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(c.cfg.BrokerRoot)
	if err != nil {
		return errors.New("hostruntime: broker cleanup root unavailable")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || (parent != root &&
		!strings.HasPrefix(parent, root+string(filepath.Separator))) {
		return errors.New("hostruntime: broker cleanup parent indirect")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("hostruntime: broker cleanup identity unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(path); err != nil {
			return errors.New("hostruntime: broker cleanup failed")
		}
		return nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	relative, relativeErr := filepath.Rel(
		filepath.Clean(c.cfg.BrokerRoot),
		filepath.Clean(path),
	)
	if err != nil || relativeErr != nil ||
		resolved != filepath.Join(root, relative) || !info.IsDir() {
		return errors.New("hostruntime: broker cleanup identity invalid")
	}
	if err := os.RemoveAll(path); err != nil {
		return errors.New("hostruntime: broker cleanup failed")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("hostruntime: broker cleanup not confirmed")
	}
	return nil
}

func (c *DockerCLI) forgetBrokerRecord(record *brokerRecord) {
	if c == nil || record == nil {
		return
	}
	c.mu.Lock()
	if c.brokers[record.handle.nonce] == record {
		delete(c.brokers, record.handle.nonce)
	}
	c.mu.Unlock()
}

func (c *DockerCLI) removeFailedBroker(ctx context.Context, record *brokerRecord) {
	if record != nil && c.removeBrokerResources(ctx, record) == nil {
		c.forgetBrokerRecord(record)
	}
}
