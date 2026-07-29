package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sumitake/portable-ghar/internal/config"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/state"
)

var errCommandUnavailable = errors.New("portable-ghar-controller: unavailable")

type controllerProcess interface {
	Run(context.Context) error
	Close() error
}

type commandDependencies struct {
	Clock             func() time.Time
	IsRoot            func() bool
	AcquireOwnership  func(string) (io.Closer, error)
	OpenController    func(context.Context, string, string) (controllerProcess, error)
	DialAdmin         func(context.Context) (controller.LiveAdmin, io.Closer, error)
	AdminTimeout      time.Duration
	DrainTimeout      time.Duration
	StatusReadTimeout time.Duration
}

func productionCommandDependencies(clock func() time.Time) commandDependencies {
	return commandDependencies{
		Clock:            clock,
		IsRoot:           func() bool { return os.Geteuid() == 0 },
		AcquireOwnership: acquireFileOwnership,
		OpenController: func(
			context.Context,
			string,
			string,
		) (controllerProcess, error) {
			// The Task 8 command boundary is complete, but the production
			// composition remains deliberately unavailable until the fleet and
			// host-authority loaders can construct the disabled observer without
			// inventing configuration.
			return nil, errCommandUnavailable
		},
		DialAdmin: func(
			context.Context,
		) (controller.LiveAdmin, io.Closer, error) {
			return nil, nil, errCommandUnavailable
		},
		AdminTimeout:      10 * time.Second,
		DrainTimeout:      10 * time.Minute,
		StatusReadTimeout: 10 * time.Second,
	}
}

func run(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	clock func() time.Time,
) int {
	return runWithDependencies(
		context.Background(),
		args,
		stdout,
		stderr,
		productionCommandDependencies(clock),
	)
}

func runWithDependencies(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	deps commandDependencies,
) int {
	if ctx == nil || stdout == nil || stderr == nil ||
		!validCommandDependencies(deps) || len(args) == 0 {
		return commandUsage(stderr)
	}
	switch args[0] {
	case "run":
		return executeRun(ctx, args[1:], stderr, deps)
	case "probe":
		if len(args) != 1 {
			return commandUsage(stderr)
		}
		return executeAdmin(
			ctx,
			false,
			deps.AdminTimeout,
			stdout,
			stderr,
			deps,
			func(callCtx context.Context, admin controller.LiveAdmin) error {
				status, err := admin.Probe(callCtx)
				if err != nil {
					return err
				}
				return json.NewEncoder(stdout).Encode(status)
			},
		)
	case "reconcile":
		flags, err := parseExactFlags(
			args[1:],
			map[string]bool{"once": false},
		)
		if err != nil || flags["once"] != "true" {
			return commandUsage(stderr)
		}
		return executeAdmin(
			ctx,
			true,
			deps.AdminTimeout,
			stdout,
			stderr,
			deps,
			func(callCtx context.Context, admin controller.LiveAdmin) error {
				if _, err := admin.ReconcileOnce(callCtx); err != nil {
					return err
				}
				return encodeOK(stdout)
			},
		)
	case "drain":
		flags, err := parseExactFlags(
			args[1:],
			map[string]bool{"policy": true},
		)
		if err != nil {
			return commandUsage(stderr)
		}
		policy := controller.DrainPolicy(flags["policy"])
		if policy != controller.DrainWait && policy != controller.DrainCancel {
			return commandUsage(stderr)
		}
		return executeAdmin(
			ctx,
			true,
			deps.DrainTimeout,
			stdout,
			stderr,
			deps,
			func(callCtx context.Context, admin controller.LiveAdmin) error {
				if err := admin.Drain(callCtx, policy); err != nil {
					return err
				}
				return encodeOK(stdout)
			},
		)
	case "acquisition":
		return executeAcquisition(ctx, args[1:], stdout, stderr, deps)
	case "status":
		return executeStatus(ctx, args[1:], stdout, stderr, deps)
	default:
		return commandUsage(stderr)
	}
}

func validCommandDependencies(deps commandDependencies) bool {
	return deps.Clock != nil &&
		deps.IsRoot != nil &&
		deps.AcquireOwnership != nil &&
		deps.OpenController != nil &&
		deps.DialAdmin != nil &&
		deps.AdminTimeout > 0 &&
		deps.DrainTimeout > 0 &&
		deps.StatusReadTimeout > 0
}

func executeRun(
	ctx context.Context,
	args []string,
	stderr io.Writer,
	deps commandDependencies,
) int {
	flags, err := parseExactFlags(
		args,
		map[string]bool{"config": true, "database": true},
	)
	if err != nil || flags["config"] == "" || flags["database"] == "" {
		return commandUsage(stderr)
	}
	if !deps.IsRoot() {
		return commandFailure(stderr, "run")
	}
	ownership, err := deps.AcquireOwnership(flags["database"] + ".owner.lock")
	if err != nil || ownership == nil {
		return commandFailure(stderr, "run")
	}
	process, openErr := deps.OpenController(
		ctx,
		flags["config"],
		flags["database"],
	)
	if openErr != nil || process == nil {
		_ = ownership.Close()
		return commandFailure(stderr, "run")
	}
	runErr := process.Run(ctx)
	processCloseErr := process.Close()
	ownershipCloseErr := ownership.Close()
	if runErr != nil || processCloseErr != nil || ownershipCloseErr != nil {
		return commandFailure(stderr, "run")
	}
	return 0
}

func executeAcquisition(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	deps commandDependencies,
) int {
	flags, err := parseExactFlags(
		args,
		map[string]bool{
			"set":                true,
			"expected":           true,
			"eligible-scale-set": true,
			"json":               false,
		},
	)
	if err != nil || flags["json"] != "true" {
		return commandUsage(stderr)
	}
	set, ok := operatorAcquisitionMode(flags["set"])
	if !ok {
		return commandUsage(stderr)
	}
	expected, ok := operatorAcquisitionMode(flags["expected"])
	if !ok {
		return commandUsage(stderr)
	}
	eligible := flags["eligible-scale-set"]
	if (set == controller.AcquisitionCanaryOnly && eligible == "") ||
		(set != controller.AcquisitionCanaryOnly && eligible != "") {
		return commandUsage(stderr)
	}
	return executeAdmin(
		ctx,
		true,
		deps.AdminTimeout,
		stdout,
		stderr,
		deps,
		func(callCtx context.Context, admin controller.LiveAdmin) error {
			status, err := admin.SetAcquisition(
				callCtx,
				controller.AcquisitionChange{
					Set:              set,
					Expected:         expected,
					EligibleScaleSet: eligible,
				},
			)
			if err != nil {
				return err
			}
			return json.NewEncoder(stdout).Encode(status)
		},
	)
}

func executeAdmin(
	parent context.Context,
	requireRoot bool,
	timeout time.Duration,
	_ io.Writer,
	stderr io.Writer,
	deps commandDependencies,
	call func(context.Context, controller.LiveAdmin) error,
) int {
	if requireRoot && !deps.IsRoot() {
		return commandFailure(stderr, "admin")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	admin, closer, err := deps.DialAdmin(ctx)
	if err != nil || admin == nil || closer == nil {
		return commandFailure(stderr, "admin")
	}
	callErr := call(ctx, admin)
	closeErr := closer.Close()
	if callErr != nil || closeErr != nil {
		return commandFailure(stderr, "admin")
	}
	return 0
}

func executeStatus(
	parent context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	deps commandDependencies,
) int {
	flags, err := parseExactFlags(
		args,
		map[string]bool{
			"json":     false,
			"config":   true,
			"database": true,
		},
	)
	if err != nil ||
		flags["json"] != "true" ||
		flags["config"] == "" ||
		flags["database"] == "" {
		return commandUsage(stderr)
	}
	configFile, err := os.Open(flags["config"])
	if err != nil {
		return commandFailure(stderr, "status")
	}
	runtime, loadErr := config.LoadControllerRuntime(configFile)
	closeErr := configFile.Close()
	if loadErr != nil || closeErr != nil {
		return commandFailure(stderr, "status")
	}
	store, err := state.OpenReadOnlyWithHistoryLimits(
		flags["database"],
		runtime.HistoryLimits(),
	)
	if err != nil {
		return commandFailure(stderr, "status")
	}
	ctx, cancel := context.WithTimeout(parent, deps.StatusReadTimeout)
	defer cancel()
	usage, usageErr := store.HistoryUsage(ctx, runtime.HistoryLimits())
	storeCloseErr := store.Close()
	if usageErr != nil || storeCloseErr != nil {
		return commandFailure(stderr, "status")
	}
	document, err := buildHistoryStatus(
		deps.Clock().UTC(),
		usage,
		runtime.HistoryLimits(),
		runtime.FleetConcurrency,
		runtime.NetworkLedgerReserveRows,
		runtime.NetworkLedgerReserveLogicalBytes,
	)
	if err != nil || json.NewEncoder(stdout).Encode(document) != nil {
		return commandFailure(stderr, "status")
	}
	return 0
}

func parseExactFlags(
	args []string,
	allowed map[string]bool,
) (map[string]string, error) {
	values := make(map[string]string, len(allowed))
	for index := 0; index < len(args); index++ {
		token := args[index]
		if !strings.HasPrefix(token, "--") || token == "--" {
			return nil, errCommandUnavailable
		}
		nameValue := strings.TrimPrefix(token, "--")
		name, value, hasEquals := strings.Cut(nameValue, "=")
		takesValue, ok := allowed[name]
		if !ok || name == "" {
			return nil, errCommandUnavailable
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errCommandUnavailable
		}
		if !takesValue {
			if hasEquals {
				return nil, errCommandUnavailable
			}
			values[name] = "true"
			continue
		}
		if hasEquals {
			if value == "" {
				return nil, errCommandUnavailable
			}
			values[name] = value
			continue
		}
		index++
		if index >= len(args) ||
			args[index] == "" ||
			strings.HasPrefix(args[index], "--") {
			return nil, errCommandUnavailable
		}
		values[name] = args[index]
	}
	return values, nil
}

func operatorAcquisitionMode(value string) (controller.AcquisitionMode, bool) {
	mode := controller.AcquisitionMode(value)
	switch mode {
	case controller.AcquisitionDisabled,
		controller.AcquisitionCanaryOnly,
		controller.AcquisitionEnabled:
		return mode, true
	default:
		return "", false
	}
}

func encodeOK(output io.Writer) error {
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

func commandUsage(stderr io.Writer) int {
	_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: invalid command")
	return 2
}

func commandFailure(stderr io.Writer, command string) int {
	_, _ = fmt.Fprintf(
		stderr,
		"portable-ghar-controller: %s unavailable\n",
		command,
	)
	return 1
}

type fileOwnership struct {
	file *os.File
}

func acquireFileOwnership(path string) (io.Closer, error) {
	if path == "" {
		return nil, errCommandUnavailable
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(
		int(file.Fd()),
		unix.LOCK_EX|unix.LOCK_NB,
	); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &fileOwnership{file: file}, nil
}

func (ownership *fileOwnership) Close() error {
	if ownership == nil || ownership.file == nil {
		return errCommandUnavailable
	}
	unlockErr := unix.Flock(int(ownership.file.Fd()), unix.LOCK_UN)
	closeErr := ownership.file.Close()
	ownership.file = nil
	return errors.Join(unlockErr, closeErr)
}
