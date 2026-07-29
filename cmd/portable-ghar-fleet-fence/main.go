// Command portable-ghar-fleet-fence owns the host-local portable/legacy fleet
// generation fence. It never invokes a shell or repairs malformed state.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

type commandDependencies struct {
	identity         fleetfence.IdentitySource
	now              func() time.Time
	effectiveUID     func() int
	lockPollInterval time.Duration
	operationTimeout time.Duration
	renewalInterval  time.Duration
	renewalTimeout   time.Duration
	terminationGrace time.Duration
}

type guardOptions struct {
	stateDir   string
	fleet      fleetfence.Fleet
	generation uint64
	command    []string
}

type inspectOptions struct {
	stateDir string
}

type handoffOptions struct {
	stateDir           string
	from               fleetfence.Fleet
	to                 fleetfence.Fleet
	expectedGeneration uint64
}

type handoffOutput struct {
	Generation  uint64           `json:"generation"`
	ActiveFleet fleetfence.Fleet `json:"active_fleet"`
}

type inspectOutput struct {
	Generation  uint64                      `json:"generation"`
	ActiveFleet fleetfence.Fleet            `json:"active_fleet"`
	Holders     []fleetfence.HolderIdentity `json:"holders"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	return runWithDependencies(
		arguments,
		stdout,
		stderr,
		commandDependencies{
			identity:         fleetfence.NewSystemIdentitySource(),
			now:              time.Now,
			effectiveUID:     os.Geteuid,
			lockPollInterval: 10 * time.Millisecond,
			operationTimeout: 30 * time.Second,
			renewalInterval:  10 * time.Second,
			renewalTimeout:   2 * time.Second,
			terminationGrace: 5 * time.Second,
		},
	)
}

func runWithDependencies(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	dependencies commandDependencies,
) int {
	if stdout == nil || stderr == nil || !validDependencies(dependencies) ||
		len(arguments) == 0 {
		return unavailable(stderr, 2)
	}
	switch arguments[0] {
	case "guard":
		options, err := parseGuard(arguments[1:])
		if err != nil {
			return unavailable(stderr, 2)
		}
		if dependencies.effectiveUID() != 0 {
			return unavailable(stderr, 1)
		}
		if err := executeGuard(options, stdout, stderr, dependencies); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	case "inspect":
		options, err := parseInspect(arguments[1:])
		if err != nil {
			return unavailable(stderr, 2)
		}
		if err := executeInspect(options, stdout, dependencies); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	case "handoff":
		options, err := parseHandoff(arguments[1:])
		if err != nil {
			return unavailable(stderr, 2)
		}
		if dependencies.effectiveUID() != 0 {
			return unavailable(stderr, 1)
		}
		if err := executeHandoff(options, stdout, dependencies); err != nil {
			return unavailable(stderr, 1)
		}
		return 0
	default:
		return unavailable(stderr, 2)
	}
}

func validDependencies(dependencies commandDependencies) bool {
	return dependencies.identity != nil &&
		dependencies.now != nil &&
		dependencies.effectiveUID != nil &&
		dependencies.lockPollInterval > 0 &&
		dependencies.operationTimeout > 0 &&
		dependencies.renewalInterval > 0 &&
		dependencies.renewalTimeout > 0 &&
		dependencies.terminationGrace > 0
}

func parseGuard(arguments []string) (guardOptions, error) {
	if len(arguments) < 8 ||
		arguments[0] != "--state-dir" ||
		arguments[2] != "--fleet" ||
		arguments[4] != "--generation" ||
		arguments[6] != "--" {
		return guardOptions{}, errors.New("guard arguments invalid")
	}
	stateDir := arguments[1]
	fleet, err := parseAcquirableFleet(arguments[3])
	if err != nil {
		return guardOptions{}, err
	}
	generation, err := parseCanonicalUint(arguments[5], false)
	if err != nil {
		return guardOptions{}, err
	}
	command := append([]string(nil), arguments[7:]...)
	if !canonicalAbsolute(stateDir) || len(command) == 0 ||
		!canonicalAbsolute(command[0]) {
		return guardOptions{}, errors.New("guard values invalid")
	}
	for _, argument := range command {
		if argument == "" || strings.IndexByte(argument, 0) >= 0 ||
			isFenceFlag(argument) {
			return guardOptions{}, errors.New("guard command invalid")
		}
	}
	return guardOptions{
		stateDir:   stateDir,
		fleet:      fleet,
		generation: generation,
		command:    command,
	}, nil
}

func parseInspect(arguments []string) (inspectOptions, error) {
	if len(arguments) != 3 ||
		arguments[0] != "--state-dir" ||
		arguments[2] != "--json" ||
		!canonicalAbsolute(arguments[1]) {
		return inspectOptions{}, errors.New("inspect arguments invalid")
	}
	return inspectOptions{stateDir: arguments[1]}, nil
}

func parseHandoff(arguments []string) (handoffOptions, error) {
	if len(arguments) != 9 ||
		arguments[0] != "--state-dir" ||
		arguments[2] != "--from" ||
		arguments[4] != "--to" ||
		arguments[6] != "--expected-generation" ||
		arguments[8] != "--json" ||
		!canonicalAbsolute(arguments[1]) {
		return handoffOptions{}, errors.New("handoff arguments invalid")
	}
	from, err := parseFleet(arguments[3])
	if err != nil {
		return handoffOptions{}, err
	}
	to, err := parseFleet(arguments[5])
	if err != nil || from == to {
		return handoffOptions{}, errors.New("handoff fleet invalid")
	}
	expected, err := parseCanonicalUint(arguments[7], true)
	if err != nil ||
		(expected == 0 && from != fleetfence.FleetNone) {
		return handoffOptions{}, errors.New("handoff generation invalid")
	}
	return handoffOptions{
		stateDir:           arguments[1],
		from:               from,
		to:                 to,
		expectedGeneration: expected,
	}, nil
}

func parseFleet(value string) (fleetfence.Fleet, error) {
	switch fleetfence.Fleet(value) {
	case fleetfence.FleetNone,
		fleetfence.FleetPortable,
		fleetfence.FleetLegacy:
		return fleetfence.Fleet(value), nil
	default:
		return "", errors.New("fleet invalid")
	}
}

func parseAcquirableFleet(value string) (fleetfence.Fleet, error) {
	fleet, err := parseFleet(value)
	if err != nil || fleet == fleetfence.FleetNone {
		return "", errors.New("acquirable fleet invalid")
	}
	return fleet, nil
}

func parseCanonicalUint(value string, allowZero bool) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value ||
		(!allowZero && parsed == 0) {
		return 0, errors.New("integer invalid")
	}
	return parsed, nil
}

func canonicalAbsolute(value string) bool {
	return value != "" &&
		filepath.IsAbs(value) &&
		filepath.Clean(value) == value &&
		strings.IndexByte(value, 0) < 0
}

func isFenceFlag(value string) bool {
	switch value {
	case "--state-dir", "--fleet", "--generation",
		"--from", "--to", "--expected-generation", "--json", "--":
		return true
	default:
		return false
	}
}

func openStore(
	stateDir string,
	dependencies commandDependencies,
) (*fleetfence.Store, error) {
	return fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             stateDir,
		Identity:         dependencies.identity,
		Now:              dependencies.now,
		LockPollInterval: dependencies.lockPollInterval,
	})
}

func operationContext(
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

func executeInspect(
	options inspectOptions,
	stdout io.Writer,
	dependencies commandDependencies,
) error {
	store, err := openStore(options.stateDir, dependencies)
	if err != nil {
		return err
	}
	ctx, cancel := operationContext(dependencies.operationTimeout)
	snapshot, inspectErr := store.Inspect(ctx)
	cancel()
	closeErr := store.Close()
	if inspectErr != nil || closeErr != nil {
		return errors.Join(inspectErr, closeErr)
	}
	holders := append([]fleetfence.HolderIdentity(nil), snapshot.Holders...)
	if holders == nil {
		holders = make([]fleetfence.HolderIdentity, 0)
	}
	return writeCanonical(stdout, inspectOutput{
		Generation:  snapshot.Header.Generation,
		ActiveFleet: snapshot.Header.ActiveFleet,
		Holders:     holders,
	})
}

func executeHandoff(
	options handoffOptions,
	stdout io.Writer,
	dependencies commandDependencies,
) error {
	store, err := openStore(options.stateDir, dependencies)
	if err != nil {
		return err
	}
	request := fleetfence.HandoffRequest{
		From:               options.from,
		To:                 options.to,
		ExpectedGeneration: options.expectedGeneration,
	}
	request.OperationID = fleetfence.HandoffOperationID(
		request.ExpectedGeneration,
		request.From,
		request.To,
	)
	ctx, cancel := operationContext(dependencies.operationTimeout)
	header, handoffErr := store.Handoff(ctx, request)
	cancel()
	closeErr := store.Close()
	if handoffErr != nil || closeErr != nil {
		return errors.Join(handoffErr, closeErr)
	}
	return writeCanonical(stdout, handoffOutput{
		Generation:  header.Generation,
		ActiveFleet: header.ActiveFleet,
	})
}

func executeGuard(
	options guardOptions,
	stdout io.Writer,
	stderr io.Writer,
	dependencies commandDependencies,
) error {
	store, err := openStore(options.stateDir, dependencies)
	if err != nil {
		return err
	}
	ctx, cancel := operationContext(dependencies.operationTimeout)
	guard, acquireErr := store.Acquire(ctx, fleetfence.AcquireRequest{
		Fleet:      options.fleet,
		Generation: options.generation,
		OwnerID:    "fence-cli-" + strconv.Itoa(os.Getpid()),
		PID:        os.Getpid(),
	})
	cancel()
	if acquireErr != nil {
		return errors.Join(acquireErr, store.Close())
	}
	childAuthority, err := fleetfence.ChildAuthorityFile(guard)
	if err != nil {
		return errors.Join(err, guard.Close(), store.Close())
	}

	command := exec.Command(options.command[0], options.command[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = stdout
	command.Stderr = stderr
	command.ExtraFiles = []*os.File{childAuthority}
	if err := command.Start(); err != nil {
		return errors.Join(
			err,
			childAuthority.Close(),
			guard.Close(),
			store.Close(),
		)
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- command.Wait() }()
	if err := childAuthority.Close(); err != nil {
		childErr := terminateChild(
			command,
			waitResult,
			dependencies.terminationGrace,
		)
		return errors.Join(
			err,
			childErr,
			guard.Close(),
			store.Close(),
		)
	}

	stopRenewal := make(chan struct{})
	renewalResult := make(chan error, 1)
	renewalDone := make(chan struct{})
	go renewGuard(
		guard,
		stopRenewal,
		renewalResult,
		renewalDone,
		dependencies.renewalInterval,
		dependencies.renewalTimeout,
	)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	var childErr error
	var authorityErr error
	waiting := true
	for waiting {
		select {
		case childErr = <-waitResult:
			waiting = false
		case authorityErr = <-renewalResult:
			childErr = terminateChild(
				command,
				waitResult,
				dependencies.terminationGrace,
			)
			waiting = false
		case received := <-signals:
			childErr = terminateChildWithSignal(
				command,
				waitResult,
				received,
				dependencies.terminationGrace,
			)
			waiting = false
		}
	}
	close(stopRenewal)
	<-renewalDone
	if authorityErr == nil {
		select {
		case renewalErr := <-renewalResult:
			authorityErr = renewalErr
		default:
		}
	}
	closeErr := guard.Close()
	storeErr := store.Close()
	if authorityErr != nil || closeErr != nil || storeErr != nil {
		return errors.Join(authorityErr, closeErr, storeErr)
	}
	return childErr
}

func renewGuard(
	guard fleetfence.Guard,
	stop <-chan struct{},
	result chan<- error,
	done chan<- struct{},
	interval time.Duration,
	timeout time.Duration,
) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			err := guard.Renew(ctx)
			cancel()
			if err != nil {
				result <- err
				return
			}
		}
	}
}

func terminateChild(
	command *exec.Cmd,
	waitResult <-chan error,
	grace time.Duration,
) error {
	return terminateChildWithSignal(
		command,
		waitResult,
		syscall.SIGTERM,
		grace,
	)
}

func terminateChildWithSignal(
	command *exec.Cmd,
	waitResult <-chan error,
	initial os.Signal,
	grace time.Duration,
) error {
	if command.Process != nil {
		_ = command.Process.Signal(initial)
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-waitResult:
		return err
	case <-timer.C:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		return <-waitResult
	}
}

func writeCanonical(output io.Writer, value any) error {
	document, err := json.Marshal(value)
	if err != nil {
		return err
	}
	document = append(document, '\n')
	_, err = output.Write(document)
	return err
}

func unavailable(stderr io.Writer, code int) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-fleet-fence: unavailable")
	}
	return code
}
