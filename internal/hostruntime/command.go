package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

const (
	defaultCommandStdoutLimit = 1 << 20
	defaultCommandStderrLimit = 1 << 20
	defaultCommandStdinLimit  = 1 << 20
)

// Result is a bounded command result. A nonzero exit is represented in fields,
// not by interpolating command or output bytes into an error.
type Result struct {
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	Signaled        bool
	Signal          string
}

// ExecCommandRunner directly executes absolute argv vectors. It supplies an
// empty environment, bounds all streams, owns a process group, and kills that
// entire group when the context is canceled.
type ExecCommandRunner struct {
	StdoutLimit int
	StderrLimit int
	StdinLimit  int
	// ReapTimeout bounds Wait after the owned process group is signaled.
	// A nonpositive value restores, rather than removes, the bound.
	ReapTimeout time.Duration
}

// NewExecCommandRunner returns fixed safe stream bounds. Callers may lower the
// public fields but a nonpositive value restores, rather than removes, bounds.
func NewExecCommandRunner() *ExecCommandRunner {
	return &ExecCommandRunner{
		StdoutLimit: defaultCommandStdoutLimit,
		StderrLimit: defaultCommandStderrLimit,
		StdinLimit:  defaultCommandStdinLimit,
	}
}

// Run implements CommandRunner.
func (r *ExecCommandRunner) Run(ctx context.Context, argv []string, extraFiles []*os.File, stdin io.Reader) (Result, error) {
	if r == nil || ctx == nil {
		return Result{}, errors.New("hostruntime: invalid command runner")
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return Result{}, errors.New("hostruntime: executable must be absolute")
	}
	for _, arg := range argv {
		if arg == "" || hasNUL(arg) {
			return Result{}, errors.New("hostruntime: invalid argv")
		}
	}
	for _, file := range extraFiles {
		if file == nil {
			return Result{}, errors.New("hostruntime: invalid extra file")
		}
	}

	stdinLimit := positiveOr(r.StdinLimit, defaultCommandStdinLimit)
	var input []byte
	if stdin != nil {
		var err error
		input, err = readAtMost(stdin, stdinLimit)
		if err != nil {
			return Result{}, err
		}
		defer zeroBytes(input)
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{}
	cmd.ExtraFiles = slices.Clone(extraFiles)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}

	stdout := &boundedCapture{limit: positiveOr(r.StdoutLimit, defaultCommandStdoutLimit)}
	stderr := &boundedCapture{limit: positiveOr(r.StderrLimit, defaultCommandStderrLimit)}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if ctx.Err() != nil {
		return Result{}, errors.New("hostruntime: command canceled")
	}
	if err := cmd.Start(); err != nil {
		return Result{}, errors.New("hostruntime: command start failed")
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	var waitErr error
	canceled := false
	reaped := true
	select {
	case waitErr = <-waited:
	case <-ctx.Done():
		canceled = true
		waitErr, reaped = FinishOwnedProcess(cmd.Process.Pid, waited, r.ReapTimeout)
	}

	if canceled && !reaped {
		return Result{ExitCode: -1}, errors.New("hostruntime: command cleanup failed")
	}
	result := commandResult(cmd, stdout, stderr)
	if canceled {
		return result, errors.New("hostruntime: command canceled")
	}
	if waitErr == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return result, nil
	}
	return result, errors.New("hostruntime: command wait failed")
}

func commandResult(cmd *exec.Cmd, stdout, stderr *boundedCapture) Result {
	result := Result{
		Stdout:          stdout.Bytes(),
		Stderr:          stderr.Bytes(),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
		ExitCode:        -1,
	}
	if cmd.ProcessState == nil {
		return result
	}
	result.ExitCode = cmd.ProcessState.ExitCode()
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		result.Signaled = true
		result.Signal = status.Signal().String()
	}
	return result
}

func readAtMost(reader io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, errors.New("hostruntime: stdin read failed")
	}
	if len(data) > limit {
		zeroBytes(data)
		return nil, errors.New("hostruntime: stdin exceeds bound")
	}
	return data, nil
}

type boundedCapture struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedCapture) Write(data []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.buffer.Write(data[:remaining])
		b.truncated = true
		return len(data), nil
	}
	_, _ = b.buffer.Write(data)
	return len(data), nil
}

func (b *boundedCapture) Bytes() []byte {
	return slices.Clone(b.buffer.Bytes())
}

func positiveOr(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

var _ CommandRunner = (*ExecCommandRunner)(nil)
