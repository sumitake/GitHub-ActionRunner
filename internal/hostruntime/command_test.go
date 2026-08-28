package hostruntime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecCommandRunnerBoundsOutputAndKeepsErrorsSecretFree(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	runner := NewExecCommandRunner()
	runner.StdoutLimit = 4
	runner.StderrLimit = 5

	result, err := runner.Run(
		context.Background(),
		[]string{executable, "-test.run=^TestHostruntimeCommandHelper$", "--", "emit"},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 17 {
		t.Fatalf("ExitCode = %d, want 17", result.ExitCode)
	}
	if string(result.Stdout) != "stdo" || !result.StdoutTruncated {
		t.Fatalf("stdout = %q truncated=%t, want bounded prefix", result.Stdout, result.StdoutTruncated)
	}
	if string(result.Stderr) != "stder" || !result.StderrTruncated {
		t.Fatalf("stderr = %q truncated=%t, want bounded prefix", result.Stderr, result.StderrTruncated)
	}
	if strings.Contains(fmt.Sprint(err), "secret") {
		t.Fatal("command error leaked output corpus")
	}
}

func TestExecCommandRunnerRejectsOversizeStdinBeforeStart(t *testing.T) {
	runner := NewExecCommandRunner()
	runner.StdinLimit = 4
	_, err := runner.Run(context.Background(), []string{"/does/not/run"}, nil, strings.NewReader("secret"))
	if err == nil {
		t.Fatal("Run accepted oversize stdin")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("oversize-stdin error leaked input corpus")
	}
}

func TestExecCommandRunnerRejectsRelativeOrNULArgv(t *testing.T) {
	runner := NewExecCommandRunner()
	for _, argv := range [][]string{{"relative"}, {"/bin/echo", "bad\x00arg"}} {
		if _, err := runner.Run(context.Background(), argv, nil, nil); err == nil {
			t.Fatalf("Run accepted argv %q", argv)
		}
	}
}

func TestExecCommandRunnerRejectsCanceledContextBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewExecCommandRunner().Run(
		ctx,
		[]string{"/does/not/run"},
		nil,
		nil,
	)
	if err == nil || err.Error() != "hostruntime: command canceled" {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestExecCommandRunnerCancellationDoesNotBlockWhenChildIgnoresKill(t *testing.T) {
	previousKill := killOwnedProcessGroup
	killOwnedProcessGroup = func(int) error { return nil }
	t.Cleanup(func() { killOwnedProcessGroup = previousKill })

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer readPipe.Close()
	defer writePipe.Close()

	runner := NewExecCommandRunner()
	runner.ReapTimeout = 40 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, runErr := runner.Run(
			ctx,
			[]string{executable, "-test.run=^TestHostruntimeCommandHelper$", "--", "ignore-term"},
			[]*os.File{writePipe},
			nil,
		)
		done <- outcome{result: result, err: runErr}
	}()

	_ = readPipe.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(readPipe).ReadString('\n')
	if err != nil {
		cancel()
		t.Fatalf("read helper pid: %v", err)
	}
	helperPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || helperPID <= 0 {
		cancel()
		t.Fatalf("helper pid = %q: %v", line, err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(helperPID, syscall.SIGKILL)
	})

	cancel()
	select {
	case got := <-done:
		if got.err == nil || got.err.Error() != "hostruntime: command cleanup failed" {
			t.Fatalf("hung-child error = %v, want cleanup failure", got.err)
		}
		if got.result.ExitCode == 0 && !got.result.Signaled {
			t.Fatalf("cleanup failure must not report success: %+v", got.result)
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("Run blocked after kill deadline for a child that ignored termination")
	}
}

func TestExecCommandRunnerCancellationKillsOwnedProcessGroup(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer readPipe.Close()
	defer writePipe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, runErr := NewExecCommandRunner().Run(
			ctx,
			[]string{executable, "-test.run=^TestHostruntimeCommandHelper$", "--", "group-parent"},
			[]*os.File{writePipe},
			nil,
		)
		done <- outcome{result: result, err: runErr}
	}()

	_ = readPipe.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(readPipe).ReadString('\n')
	if err != nil {
		cancel()
		t.Fatalf("read grandchild pid: %v", err)
	}
	grandchildPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || grandchildPID <= 0 {
		cancel()
		t.Fatalf("grandchild pid = %q: %v", line, err)
	}

	cancel()
	select {
	case got := <-done:
		if got.err == nil || got.err.Error() != "hostruntime: command canceled" {
			t.Fatalf("cancellation error = %v", got.err)
		}
		if !got.result.Signaled {
			t.Fatalf("canceled result = %+v, want signaled", got.result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		err := syscall.Kill(grandchildPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			t.Fatalf("probe grandchild %d: %v", grandchildPID, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d survived process-group cancellation", grandchildPID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHostruntimeCommandHelper(t *testing.T) {
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}

	switch os.Args[separator+1] {
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		signal.Ignore(syscall.SIGINT)
		pidPipe := os.NewFile(3, "helper-pid")
		if pidPipe == nil {
			os.Exit(93)
		}
		_, _ = fmt.Fprintf(pidPipe, "%d\n", os.Getpid())
		_ = pidPipe.Close()
		for {
			time.Sleep(time.Hour)
		}
	case "emit":
		_, _ = os.Stdout.WriteString("stdout-secret")
		_, _ = os.Stderr.WriteString("stderr-secret")
		os.Exit(17)
	case "group-child":
		for {
			time.Sleep(time.Hour)
		}
	case "group-parent":
		executable, err := os.Executable()
		if err != nil {
			os.Exit(90)
		}
		child := exec.Command(executable, "-test.run=^TestHostruntimeCommandHelper$", "--", "group-child")
		child.Env = []string{}
		if err := child.Start(); err != nil {
			os.Exit(91)
		}
		pidPipe := os.NewFile(3, "grandchild-pid")
		if pidPipe == nil {
			_ = child.Process.Kill()
			os.Exit(92)
		}
		_, _ = fmt.Fprintf(pidPipe, "%d\n", child.Process.Pid)
		_ = pidPipe.Close()
		_ = child.Wait()
		os.Exit(0)
	}
}
