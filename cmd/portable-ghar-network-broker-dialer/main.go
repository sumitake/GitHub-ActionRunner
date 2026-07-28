// Command portable-ghar-network-broker-dialer is the single held namespace
// owner. It has no routable listener before its one-use release and remains the
// only process with AF_INET/AF_INET6 socket authority afterward.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	maxBrokerCommandResponse = 16 << 10
	defaultBrokerIOTimeout   = 15 * time.Second
)

type brokerOperation uint8

const (
	brokerOpArm brokerOperation = iota + 1
	brokerOpRelease
	brokerOpAudit
)

type brokerPhase uint8

const (
	brokerPhaseHeld brokerPhase = iota + 1
	brokerPhaseArmed
	brokerPhaseReleased
	brokerPhaseFailed
)

type brokerReleaseFunc func(
	context.Context,
	hostruntime.BrokerReleaseCommand,
) ([]byte, error)

type brokerMachine struct {
	mu      sync.Mutex
	phase   brokerPhase
	digest  [sha256.Size]byte
	release brokerReleaseFunc
	audit   func(context.Context) ([]byte, error)
}

func newBrokerMachine(
	release brokerReleaseFunc,
	audit func(context.Context) ([]byte, error),
) *brokerMachine {
	return &brokerMachine{
		phase:   brokerPhaseHeld,
		release: release,
		audit:   audit,
	}
}

func (machine *brokerMachine) apply(
	ctx context.Context,
	operation brokerOperation,
	payload []byte,
) ([]byte, error) {
	if machine == nil || ctx == nil {
		return nil, errors.New("broker-dialer: machine unavailable")
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	fail := func() ([]byte, error) {
		zero(machine.digest[:])
		machine.phase = brokerPhaseFailed
		return nil, errors.New("broker-dialer: operation rejected")
	}
	switch machine.phase {
	case brokerPhaseHeld:
		if operation != brokerOpArm || machine.release == nil ||
			machine.audit == nil {
			return fail()
		}
		digest, err := hostruntime.DecodeBrokerArmDigest(bytes.NewReader(payload))
		if err != nil {
			return fail()
		}
		machine.digest = digest
		machine.phase = brokerPhaseArmed
		return []byte("OK\n"), nil
	case brokerPhaseArmed:
		if operation != brokerOpRelease {
			return fail()
		}
		command, err := hostruntime.DecodeBrokerReleaseCommand(
			bytes.NewReader(payload),
		)
		if err != nil {
			return fail()
		}
		defer command.Destroy()
		token := command.ReleaseToken()
		digest := sha256.Sum256(token[:])
		zero(token[:])
		if subtle.ConstantTimeCompare(digest[:], machine.digest[:]) != 1 {
			zero(digest[:])
			return fail()
		}
		zero(digest[:])
		zero(machine.digest[:])
		machine.phase = brokerPhaseFailed
		readiness, err := machine.release(ctx, command)
		if err != nil || len(readiness) == 0 ||
			len(readiness) > maxBrokerCommandResponse {
			zero(readiness)
			return nil, errors.New("broker-dialer: release failed")
		}
		machine.phase = brokerPhaseReleased
		return readiness, nil
	case brokerPhaseReleased:
		if operation != brokerOpAudit || len(payload) != 0 {
			return fail()
		}
		readiness, err := machine.audit(ctx)
		if err != nil || len(readiness) == 0 ||
			len(readiness) > maxBrokerCommandResponse {
			zero(readiness)
			return fail()
		}
		return readiness, nil
	default:
		return nil, errors.New("broker-dialer: terminal state")
	}
}

type brokerRuntime struct {
	ioTimeout   time.Duration
	hold        func(context.Context) error
	forward     func(context.Context, brokerOperation, io.Reader, io.Writer) error
	authorityID func() ([]byte, error)
}

func defaultBrokerRuntime() brokerRuntime {
	return brokerRuntime{
		ioTimeout: defaultBrokerIOTimeout,
		hold:      holdBroker,
		forward: func(
			ctx context.Context,
			operation brokerOperation,
			input io.Reader,
			output io.Writer,
		) error {
			return forwardBroker(ctx, operation, input, output)
		},
		authorityID: inspectAuthorityFilesystem,
	}
}

func run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout,
	stderr io.Writer,
	runtime brokerRuntime,
) int {
	if ctx == nil || len(args) != 1 || stdout == nil || stderr == nil ||
		runtime.hold == nil || runtime.forward == nil ||
		runtime.authorityID == nil {
		return brokerUnavailable(stderr, 2)
	}
	switch args[0] {
	case "hold":
		if requireEmptyInput(stdin) != nil || runtime.hold(ctx) != nil {
			return brokerUnavailable(stderr, 1)
		}
		return 0
	case "authority-id":
		if requireEmptyInput(stdin) != nil {
			return brokerUnavailable(stderr, 1)
		}
		document, err := runtime.authorityID()
		if err != nil || len(document) == 0 ||
			len(document) > maxBrokerCommandResponse {
			zero(document)
			return brokerUnavailable(stderr, 1)
		}
		if _, err := stdout.Write(document); err != nil {
			zero(document)
			return brokerUnavailable(stderr, 1)
		}
		zero(document)
		return 0
	case "arm", "release", "audit":
		operation := brokerOpArm
		if args[0] == "release" {
			operation = brokerOpRelease
		} else if args[0] == "audit" {
			operation = brokerOpAudit
			if requireEmptyInput(stdin) != nil {
				return brokerUnavailable(stderr, 1)
			}
			stdin = nil
		}
		timeout := runtime.ioTimeout
		if timeout <= 0 {
			timeout = defaultBrokerIOTimeout
		}
		bounded, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := runtime.forward(bounded, operation, stdin, stdout); err != nil {
			return brokerUnavailable(stderr, 1)
		}
		return 0
	default:
		return brokerUnavailable(stderr, 2)
	}
}

func requireEmptyInput(reader io.Reader) error {
	if reader == nil {
		return nil
	}
	var probe [1]byte
	count, err := reader.Read(probe[:])
	if count != 0 || (err != nil && err != io.EOF) {
		return errors.New("broker-dialer: input-free operation received input")
	}
	return nil
}

func brokerUnavailable(stderr io.Writer, code int) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(
			stderr,
			"portable-ghar-network-broker-dialer: unavailable",
		)
	}
	return code
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()
	os.Exit(run(
		ctx,
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
		defaultBrokerRuntime(),
	))
}
