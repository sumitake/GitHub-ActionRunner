// Command portable-ghar-watchdog exposes one closed, source-only watchdog
// cycle. Production composition remains fail-closed until the operator-approved
// private overlay and target conformance gates are supplied.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/watchdog"
)

var errWatchdogUnavailable = errors.New(
	"portable-ghar-watchdog: production composition unavailable",
)

type commandDependencies struct {
	RunCycle func(context.Context, string, string) (watchdog.Result, error)
}

func productionDependencies() commandDependencies {
	return commandDependencies{
		RunCycle: func(
			context.Context,
			string,
			string,
		) (watchdog.Result, error) {
			return watchdog.Result{
				Status: watchdog.StatusFailed,
				Reason: watchdog.ReasonInspectFailed,
			}, errWatchdogUnavailable
		},
	}
}

func run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	dependencies commandDependencies,
) int {
	if ctx == nil ||
		stdout == nil ||
		stderr == nil ||
		dependencies.RunCycle == nil {
		return writeUsage(stderr)
	}
	privatePath, manifestPath, ok := parseCommand(args)
	if !ok {
		return writeUsage(stderr)
	}
	result, err := dependencies.RunCycle(ctx, privatePath, manifestPath)
	if err != nil {
		_, _ = io.WriteString(
			stderr,
			"portable-ghar-watchdog: cycle failed\n",
		)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = io.WriteString(
			stderr,
			"portable-ghar-watchdog: output failed\n",
		)
		return 1
	}
	return 0
}

func parseCommand(args []string) (string, string, bool) {
	if len(args) != 5 ||
		args[0] != "run" ||
		args[1] != "--private" ||
		args[3] != "--manifest" ||
		!canonicalAbsolutePath(args[2]) ||
		!canonicalAbsolutePath(args[4]) ||
		args[2] == args[4] {
		return "", "", false
	}
	return args[2], args[4], true
}

func canonicalAbsolutePath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsRune(path, 0)
}

func writeUsage(stderr io.Writer) int {
	_, _ = io.WriteString(
		stderr,
		"usage: portable-ghar-watchdog run --private PATH --manifest PATH\n",
	)
	return 2
}

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()
	os.Exit(run(
		ctx,
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		productionDependencies(),
	))
}
