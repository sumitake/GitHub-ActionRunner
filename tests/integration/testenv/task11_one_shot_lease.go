package testenv

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	task11ClosedVerifierNamePrefix = "pghar-task11-verifier-"
	task11ClosedVerifierNameSuffix = "-denials"
)

type task11OneShotLeaseEntry struct {
	handle  cleanupHandle
	name    string
	retired bool
	busy    bool
	removed bool
}

type task11OneShotLeaseAuthority struct {
	dockerPath   string
	maximumBytes uint64
	runner       hostruntime.CommandRunner
	record       func(cleanupHandle) error

	mu      sync.Mutex
	entries map[cleanupHandle]*task11OneShotLeaseEntry
	names   map[string]cleanupHandle
}

func newTask11OneShotLeaseAuthority(
	dockerPath string,
	maximumBytes uint64,
	runner hostruntime.CommandRunner,
	record func(cleanupHandle) error,
) (*task11OneShotLeaseAuthority, error) {
	if !filepath.IsAbs(dockerPath) ||
		filepath.Clean(dockerPath) != dockerPath ||
		maximumBytes == 0 ||
		runner == nil ||
		record == nil {
		return nil, ErrFixtureStart
	}
	return &task11OneShotLeaseAuthority{
		dockerPath:   dockerPath,
		maximumBytes: maximumBytes,
		runner:       runner,
		record:       record,
		entries:      make(map[cleanupHandle]*task11OneShotLeaseEntry),
		names:        make(map[string]cleanupHandle),
	}, nil
}

func (a *task11OneShotLeaseAuthority) Register(
	handle cleanupHandle,
	name string,
) error {
	if a == nil ||
		handle.kind != CleanupVerifier ||
		!isLowerHex(handle.id, 64) ||
		!validTask11ClosedVerifierName(name) {
		return ErrFixtureStart
	}
	entry := &task11OneShotLeaseEntry{
		handle: handle,
		name:   name,
	}
	a.mu.Lock()
	if _, exists := a.entries[handle]; exists {
		a.mu.Unlock()
		return ErrFixtureStart
	}
	if _, exists := a.names[name]; exists {
		a.mu.Unlock()
		return ErrFixtureStart
	}
	a.entries[handle] = entry
	a.names[name] = handle
	a.mu.Unlock()

	if err := a.record(handle); err != nil {
		a.mu.Lock()
		if a.entries[handle] == entry {
			delete(a.entries, handle)
			delete(a.names, name)
		}
		a.mu.Unlock()
		return ErrFixtureStart
	}
	return nil
}

func (a *task11OneShotLeaseAuthority) Retire(
	handle cleanupHandle,
) error {
	if a == nil ||
		handle.kind != CleanupVerifier ||
		!isLowerHex(handle.id, 64) {
		return ErrFixtureStart
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := a.entries[handle]
	if entry == nil ||
		entry.handle != handle ||
		entry.busy ||
		entry.retired ||
		entry.removed {
		return ErrFixtureStart
	}
	entry.retired = true
	return nil
}

func (a *task11OneShotLeaseAuthority) Remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if a == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		handle.kind != CleanupVerifier ||
		!isLowerHex(handle.id, 64) {
		return ErrFixtureCleanup
	}
	a.mu.Lock()
	entry := a.entries[handle]
	if entry == nil ||
		entry.handle != handle ||
		entry.busy {
		a.mu.Unlock()
		return ErrFixtureCleanup
	}
	if entry.removed {
		a.mu.Unlock()
		return nil
	}
	if entry.retired {
		entry.removed = true
		a.mu.Unlock()
		return nil
	}
	entry.busy = true
	name := entry.name
	a.mu.Unlock()

	result, err := a.runner.Run(
		ctx,
		[]string{a.dockerPath, "rm", "-f", name},
		nil,
		nil,
	)
	removeOK := validTask11OneShotRemoval(
		result,
		err,
		name,
		a.maximumBytes,
	)
	destroyCommandResult(&result)
	if !removeOK {
		a.finishFailedRemoval(entry)
		return ErrFixtureCleanup
	}
	result, err = a.runner.Run(
		ctx,
		[]string{
			a.dockerPath,
			"inspect",
			"--type",
			"container",
			name,
		},
		nil,
		nil,
	)
	absenceOK := validTask11OneShotAbsence(
		result,
		err,
		name,
		a.maximumBytes,
	)
	destroyCommandResult(&result)
	if !absenceOK {
		a.finishFailedRemoval(entry)
		return ErrFixtureCleanup
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.entries[handle] != entry ||
		!entry.busy ||
		entry.removed {
		entry.busy = false
		return ErrFixtureCleanup
	}
	entry.busy = false
	entry.removed = true
	return nil
}

func (a *task11OneShotLeaseAuthority) RecordedRemoved(
	handle cleanupHandle,
) bool {
	if a == nil ||
		handle.kind != CleanupVerifier ||
		!isLowerHex(handle.id, 64) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := a.entries[handle]
	return entry != nil &&
		entry.handle == handle &&
		entry.removed &&
		!entry.busy
}

func (a *task11OneShotLeaseAuthority) finishFailedRemoval(
	entry *task11OneShotLeaseEntry,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if entry != nil &&
		a.entries[entry.handle] == entry {
		entry.busy = false
	}
}

func validTask11ClosedVerifierName(name string) bool {
	if !strings.HasPrefix(name, task11ClosedVerifierNamePrefix) ||
		!strings.HasSuffix(name, task11ClosedVerifierNameSuffix) {
		return false
	}
	identity := strings.TrimSuffix(
		strings.TrimPrefix(name, task11ClosedVerifierNamePrefix),
		task11ClosedVerifierNameSuffix,
	)
	return isLowerHex(identity, 32) &&
		validTask11ContainerName(name)
}

func validTask11OneShotRemoval(
	result hostruntime.Result,
	err error,
	name string,
	maximumBytes uint64,
) bool {
	total := uint64(len(result.Stdout)) + uint64(len(result.Stderr))
	return err == nil &&
		result.ExitCode == 0 &&
		!result.Signaled &&
		!result.StdoutTruncated &&
		!result.StderrTruncated &&
		bytes.Equal(result.Stdout, []byte(name+"\n")) &&
		len(result.Stderr) == 0 &&
		total <= maximumBytes
}

func validTask11OneShotAbsence(
	result hostruntime.Result,
	err error,
	name string,
	maximumBytes uint64,
) bool {
	total := uint64(len(result.Stdout)) + uint64(len(result.Stderr))
	if err != nil ||
		result.ExitCode != 1 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stdout) != 0 ||
		total > maximumBytes {
		return false
	}
	return bytes.Equal(
		result.Stderr,
		[]byte("Error: No such object: "+name+"\n"),
	) || bytes.Equal(
		result.Stderr,
		[]byte(
			"Error response from daemon: No such container: "+
				name+
				"\n",
		),
	)
}

var _ closedOneShotLeaseAuthority = (*task11OneShotLeaseAuthority)(nil)
