// Command portable-ghar-network-broker-parser consumes untrusted proxy
// handshakes only after a process-wide TSYNC seccomp filter has removed all
// routable socket authority from the parser process.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const (
	relayDirectory    = "/run/portable-ghar/relay"
	relaySocket       = "/run/portable-ghar/relay/https.sock"
	dialerSocket      = "/run/portable-ghar/state/dialer.sock"
	parserControlName = "portable-ghar-parser-control"
)

type sandboxProof struct {
	taskCount     uint32
	tasksVerified uint32
}

type parserRuntime struct {
	sandbox func() (sandboxProof, error)
	serve   func(context.Context, sandboxProof) error
}

func defaultParserRuntime() parserRuntime {
	return parserRuntime{
		sandbox: installParserSandbox,
		serve:   serveParser,
	}
}

func run(
	ctx context.Context,
	args []string,
	stdout,
	stderr io.Writer,
	runtime parserRuntime,
) int {
	if ctx == nil || len(args) != 1 || args[0] != "serve" ||
		stdout == nil || stderr == nil ||
		runtime.sandbox == nil || runtime.serve == nil {
		return parserUnavailable(stderr)
	}
	proof, err := runtime.sandbox()
	if err != nil || proof.taskCount == 0 ||
		proof.tasksVerified != proof.taskCount {
		return parserUnavailable(stderr)
	}
	if err := runtime.serve(ctx, proof); err != nil {
		return parserUnavailable(stderr)
	}
	return 0
}

func serveParser(ctx context.Context, sandbox sandboxProof) error {
	control := os.NewFile(
		uintptr(networkjail.ParserControlFD),
		parserControlName,
	)
	if control == nil {
		return errors.New("broker-parser: control unavailable")
	}
	defer control.Close()
	policyDocument, err := networkjail.ReadParserPolicy(control)
	if err != nil {
		return errors.New("broker-parser: policy unavailable")
	}
	graph, err := networkjail.DecodeDecisionGraph(bytes.NewReader(policyDocument))
	if err != nil {
		zero(policyDocument)
		return errors.New("broker-parser: policy invalid")
	}
	zero(policyDocument)

	listener, listenerFD, err := createRelayListener(relayDirectory, relaySocket)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(relaySocket)
	}()
	parser, err := networkjail.NewBrokerParser(
		graph,
		networkjail.UnixControlConnector{
			Path:    dialerSocket,
			Timeout: 5 * time.Second,
		},
		networkjail.ParserRuntimeConfig{
			HandshakeTimeout: 10 * time.Second,
			RelayTimeout: time.Duration(
				graph.TailTimeoutSeconds(),
			) * time.Second,
			MaxClients: uint32(graph.JobOpenCap()),
		},
	)
	if err != nil {
		return errors.New("broker-parser: runtime unavailable")
	}
	unexpected, err := countUnexpectedFDs(map[int]struct{}{
		0:                           {},
		1:                           {},
		2:                           {},
		networkjail.ParserControlFD: {},
		listenerFD:                  {},
	})
	if err != nil || unexpected != 0 {
		return errors.New("broker-parser: descriptor inventory invalid")
	}
	if err := networkjail.WriteParserReadiness(
		control,
		networkjail.ParserReadiness{
			Version:       1,
			ControlFD:     networkjail.ParserControlFD,
			FilterVersion: networkjail.ParserFilterVersion,
			FilterTSYNC:   true,
			AFINETErrno:   networkjail.ParserSocketErrno,
			AFINET6Errno:  networkjail.ParserSocketErrno,
			UnexpectedFDs: 0,
			TaskCount:     sandbox.taskCount,
			TasksVerified: sandbox.tasksVerified,
		},
	); err != nil {
		return errors.New("broker-parser: readiness failed")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return parser.Serve(ctx, listener)
}

func createRelayListener(
	directory,
	socket string,
) (*net.UnixListener, int, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		socket != filepath.Join(directory, "https.sock") {
		return nil, 0, errors.New("broker-parser: relay path invalid")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, 0, errors.New("broker-parser: relay directory invalid")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		return nil, 0, errors.New("broker-parser: relay socket already exists")
	}
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: socket, Net: "unix"},
	)
	if err != nil {
		return nil, 0, errors.New("broker-parser: relay listen failed")
	}
	listener.SetUnlinkOnClose(false)
	fail := func() (*net.UnixListener, int, error) {
		_ = listener.Close()
		_ = os.Remove(socket)
		return nil, 0, errors.New("broker-parser: relay identity invalid")
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		return fail()
	}
	socketInfo, err := os.Lstat(socket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 ||
		socketInfo.Mode().Perm() != 0o600 {
		return fail()
	}
	raw, err := listener.SyscallConn()
	if err != nil {
		return fail()
	}
	fd := -1
	if err := raw.Control(func(value uintptr) { fd = int(value) }); err != nil ||
		fd < 0 {
		return fail()
	}
	return listener, fd, nil
}

func countUnexpectedFDs(allowed map[int]struct{}) (uint32, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, errors.New("broker-parser: descriptor inventory unavailable")
	}
	var unexpected uint32
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			return 0, errors.New("broker-parser: descriptor inventory invalid")
		}
		if _, found := allowed[fd]; found {
			continue
		}
		if _, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name())); err != nil {
			continue
		}
		unexpected++
	}
	return unexpected, nil
}

func parserUnavailable(stderr io.Writer) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(
			stderr,
			"portable-ghar-network-broker-parser: unavailable",
		)
	}
	return 1
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
		os.Stdout,
		os.Stderr,
		defaultParserRuntime(),
	))
}
