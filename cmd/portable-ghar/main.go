// Command portable-ghar exposes the closed public host lifecycle dispatcher.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type commandDependencies struct {
	RunHost   func(context.Context, []string) (cli.PublicHostResult, error)
	RunTarget func(context.Context, []string) (hostruntime.HostActionResult, error)
}

func productionCommandDependencies() commandDependencies {
	transport := unavailableHostTransport{}
	dependencies := cli.DefaultHostCommandDependencies(transport)
	return commandDependencies{
		RunHost: func(
			ctx context.Context,
			args []string,
		) (cli.PublicHostResult, error) {
			return cli.RunHostCommand(ctx, args, dependencies)
		},
		RunTarget: func(
			ctx context.Context,
			args []string,
		) (hostruntime.HostActionResult, error) {
			return hostruntime.RunTargetHostCommand(
				ctx,
				args,
				unavailableTargetHostExecutor{},
			)
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
		len(args) == 0 {
		return writeUsage(stderr)
	}
	if args[0] == "host-runtime" {
		return runTarget(
			ctx,
			args[1:],
			stdout,
			stderr,
			dependencies.RunTarget,
		)
	}
	if dependencies.RunHost == nil {
		return writeUsage(stderr)
	}
	result, err := dependencies.RunHost(ctx, args)
	if errors.Is(err, cli.ErrHostUsage) {
		return writeUsage(stderr)
	}
	if err != nil {
		_, _ = io.WriteString(stderr, "portable-ghar: host command failed\n")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = io.WriteString(stderr, "portable-ghar: output failed\n")
		return 1
	}
	return 0
}

func runTarget(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	runTarget func(
		context.Context,
		[]string,
	) (hostruntime.HostActionResult, error),
) int {
	if runTarget == nil {
		return writeTargetUsage(stderr)
	}
	result, err := runTarget(ctx, args)
	if errors.Is(err, hostruntime.ErrTargetHostUsage) {
		return writeTargetUsage(stderr)
	}
	if err != nil {
		_, _ = io.WriteString(
			stderr,
			"portable-ghar: target host action failed\n",
		)
		return 1
	}
	document, _, err := hostruntime.MarshalHostActionResult(result)
	if err != nil {
		_, _ = io.WriteString(
			stderr,
			"portable-ghar: target output failed\n",
		)
		return 1
	}
	document = append(document, '\n')
	if _, err := stdout.Write(document); err != nil {
		_, _ = io.WriteString(
			stderr,
			"portable-ghar: target output failed\n",
		)
		return 1
	}
	return 0
}

func writeUsage(stderr io.Writer) int {
	_, _ = io.WriteString(
		stderr,
		"usage: portable-ghar deploy|verify|suspend|resume host [exact arguments]\n",
	)
	return 2
}

func writeTargetUsage(stderr io.Writer) int {
	_, _ = io.WriteString(
		stderr,
		"usage: portable-ghar host-runtime "+
			"install|verify|suspend|resume|rollback|uninstall|"+
			"watchdog-install|watchdog-uninstall [exact arguments]\n",
	)
	return 2
}

type unavailableHostTransport struct{}

func (unavailableHostTransport) ProveTarget(
	context.Context,
	hostruntime.PrivateOverlay,
) (cli.TargetProof, error) {
	return cli.TargetProof{}, cli.ErrHostCommandFailed
}

func (unavailableHostTransport) Stage(
	context.Context,
	cli.TargetProof,
	cli.StagedRelease,
) (cli.StageProof, error) {
	return cli.StageProof{}, cli.ErrHostCommandFailed
}

func (unavailableHostTransport) Invoke(
	context.Context,
	cli.TargetProof,
	cli.HostAction,
	cli.FixedArguments,
) (cli.ActionResult, error) {
	return cli.ActionResult{}, cli.ErrHostCommandFailed
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
		productionCommandDependencies(),
	))
}

var _ cli.HostTransport = unavailableHostTransport{}

type unavailableTargetHostExecutor struct{}

func (unavailableTargetHostExecutor) ExecuteTargetHost(
	context.Context,
	hostruntime.TargetHostRequest,
) (hostruntime.HostActionResult, error) {
	return hostruntime.HostActionResult{}, hostruntime.ErrTargetHostFailed
}

var _ hostruntime.TargetHostExecutor = unavailableTargetHostExecutor{}
