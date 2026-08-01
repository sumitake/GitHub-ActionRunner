//go:build integration && linux

package testenv

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

const task11SyntheticExitInspectFormat = `{"running":{{json .State.Running}},"oom_killed":{{json .State.OOMKilled}},"error":{{json .State.Error}},"exit_code":{{json .State.ExitCode}}}`

func task11SyntheticExitInspectArgv(
	dockerPath string,
	runnerID string,
) ([]string, error) {
	if !filepath.IsAbs(dockerPath) ||
		filepath.Clean(dockerPath) != dockerPath ||
		!isLowerHex(runnerID, 64) {
		return nil, ErrFixtureStart
	}
	return []string{
		dockerPath,
		"container",
		"inspect",
		"--format",
		task11SyntheticExitInspectFormat,
		runnerID,
	}, nil
}

type task11SyntheticBoundedCapture struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *task11SyntheticBoundedCapture) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(value), nil
	}
	if len(value) > remaining {
		_, _ = b.buffer.Write(value[:remaining])
		b.truncated = true
		return len(value), nil
	}
	_, _ = b.buffer.Write(value)
	return len(value), nil
}

func (b *task11SyntheticBoundedCapture) result() (
	[]byte,
	bool,
) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes()), b.truncated
}

type task11SyntheticAttachSession struct {
	dockerPath   string
	runnerID     string
	maximumBytes uint64
	command      *exec.Cmd
	stdout       *task11SyntheticBoundedCapture
	stderr       *task11SyntheticBoundedCapture
	waited       chan error

	mu       sync.Mutex
	finished bool
}

func startTask11SyntheticAttach(
	dockerPath string,
	runnerID string,
	maximumBytes uint64,
) (*task11SyntheticAttachSession, error) {
	argv, err := task11SyntheticAttachArgv(dockerPath, runnerID)
	if err != nil || maximumBytes == 0 ||
		maximumBytes > uint64(^uint(0)>>1) {
		return nil, ErrFixtureStart
	}
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout := &task11SyntheticBoundedCapture{limit: int(maximumBytes)}
	stderr := &task11SyntheticBoundedCapture{limit: int(maximumBytes)}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, ErrFixtureStart
	}
	session := &task11SyntheticAttachSession{
		dockerPath:   dockerPath,
		runnerID:     runnerID,
		maximumBytes: maximumBytes,
		command:      command,
		stdout:       stdout,
		stderr:       stderr,
		waited:       make(chan error, 1),
	}
	go func() {
		session.waited <- command.Wait()
		close(session.waited)
	}()
	return session, nil
}

func (s *task11SyntheticAttachSession) waitAndInspect(
	ctx context.Context,
	runner *hostruntime.ExecCommandRunner,
	binding task11synthetic.StreamBinding,
) (task11synthetic.Stream, error) {
	if s == nil || ctx == nil || runner == nil ||
		ctx.Err() != nil {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	s.finished = true
	s.mu.Unlock()

	var (
		waitErr  error
		canceled bool
	)
	select {
	case waitErr = <-s.waited:
	case <-ctx.Done():
		canceled = true
		if s.command != nil && s.command.Process != nil {
			_ = syscall.Kill(-s.command.Process.Pid, syscall.SIGKILL)
		}
		waitErr = <-s.waited
	}
	result := s.result()
	if canceled {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return task11synthetic.Stream{}, ErrFixtureStart
		}
	}
	inspectArgv, err := task11SyntheticExitInspectArgv(
		s.dockerPath,
		s.runnerID,
	)
	if err != nil {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	inspectResult, err := runner.Run(ctx, inspectArgv, nil, nil)
	if err != nil ||
		inspectResult.ExitCode != 0 ||
		inspectResult.Signaled ||
		inspectResult.StdoutTruncated ||
		inspectResult.StderrTruncated ||
		len(inspectResult.Stderr) != 0 {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	exit, err := parseTask11SyntheticContainerExit(inspectResult.Stdout)
	if err != nil {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	stream, err := validateTask11SyntheticAttachResult(
		result,
		exit,
		binding,
		s.maximumBytes,
	)
	if err != nil {
		return task11synthetic.Stream{}, ErrFixtureStart
	}
	return stream, nil
}

func (s *task11SyntheticAttachSession) terminate() error {
	if s == nil {
		return ErrFixtureCleanup
	}
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return nil
	}
	s.finished = true
	s.mu.Unlock()
	if s.command != nil && s.command.Process != nil {
		_ = syscall.Kill(-s.command.Process.Pid, syscall.SIGKILL)
	}
	if err := <-s.waited; err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return ErrFixtureCleanup
		}
	}
	return nil
}

func (s *task11SyntheticAttachSession) result() hostruntime.Result {
	stdout, stdoutTruncated := s.stdout.result()
	stderr, stderrTruncated := s.stderr.result()
	result := hostruntime.Result{
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: stdoutTruncated,
		StderrTruncated: stderrTruncated,
		ExitCode:        -1,
	}
	if s.command == nil || s.command.ProcessState == nil {
		return result
	}
	result.ExitCode = s.command.ProcessState.ExitCode()
	if status, ok := s.command.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		result.Signaled = true
		result.Signal = status.Signal().String()
	}
	return result
}
