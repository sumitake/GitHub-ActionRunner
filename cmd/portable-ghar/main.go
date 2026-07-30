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
	"github.com/sumitake/portable-ghar/internal/productionruntime"
	"golang.org/x/term"
)

type commandDependencies struct {
	RunHost      func(context.Context, []string) (cli.PublicHostResult, error)
	RunTarget    func(context.Context, []string) (hostruntime.HostActionResult, error)
	RunTransport func(context.Context, io.Reader, io.Writer, bool) error
}

func productionCommandDependencies() commandDependencies {
	dependencies := cli.DefaultHostCommandDependencies(
		func(
			overlay hostruntime.PrivateOverlay,
		) (cli.HostTransport, error) {
			return productionruntime.NewSSHTransport(
				overlay,
				hostruntime.NewExecCommandRunner(),
			)
		},
	)
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
		RunTransport: func(
			ctx context.Context,
			stdin io.Reader,
			stdout io.Writer,
			tty bool,
		) error {
			return productionruntime.Serve(
				ctx,
				stdin,
				stdout,
				tty,
				unavailableProductionHandler{},
			)
		},
	}
}

func run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	tty bool,
	dependencies commandDependencies,
) int {
	if ctx == nil ||
		stdin == nil ||
		stdout == nil ||
		stderr == nil ||
		len(args) == 0 {
		return writeUsage(stderr)
	}
	if transportServeRequested(args) {
		if dependencies.RunTransport == nil ||
			dependencies.RunTransport(ctx, stdin, stdout, tty) != nil {
			return 1
		}
		return 0
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

func transportServeRequested(args []string) bool {
	return len(args) == 1 && args[0] == "transport-serve"
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

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	args := os.Args[1:]
	tty := false
	if transportServeRequested(args) {
		tty = term.IsTerminal(int(os.Stdin.Fd()))
		os.Clearenv()
	}
	exit := run(
		ctx,
		args,
		os.Stdin,
		os.Stdout,
		os.Stderr,
		tty,
		productionCommandDependencies(),
	)
	cancel()
	os.Exit(exit)
}

type unavailableTargetHostExecutor struct{}

func (unavailableTargetHostExecutor) ExecuteTargetHost(
	context.Context,
	hostruntime.TargetHostRequest,
) (hostruntime.HostActionResult, error) {
	return hostruntime.HostActionResult{}, hostruntime.ErrTargetHostFailed
}

var _ hostruntime.TargetHostExecutor = unavailableTargetHostExecutor{}

type unavailableProductionHandler struct{}

func (unavailableProductionHandler) ProveTarget(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
) (cli.TargetProof, error) {
	return cli.TargetProof{}, productionruntime.ErrProtocol
}

func (unavailableProductionHandler) StageRelease(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	hostruntime.RuntimeManifest,
	string,
) (cli.StageProof, error) {
	return cli.StageProof{}, productionruntime.ErrProtocol
}

func (unavailableProductionHandler) Invoke(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	cli.HostAction,
	productionruntime.InvokeArguments,
) (hostruntime.HostActionResult, error) {
	return hostruntime.HostActionResult{}, productionruntime.ErrProtocol
}

var _ productionruntime.TargetHandler = unavailableProductionHandler{}
