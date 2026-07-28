// Command portable-ghar-network-verifier is a capability-less one-shot
// observer. It verifies the adapter/runner network namespace is loopback-only
// and executes only the policy's fixed positive and negative proxy probes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const maxVerifierOutputBytes = 16 << 10

type namespaceReport struct {
	Version   uint8                         `json:"version"`
	Namespace networkjail.NamespaceSnapshot `json:"namespace"`
}

type namespaceIdentityReport struct {
	Version  uint8                         `json:"version"`
	Identity networkjail.NamespaceIdentity `json:"identity"`
}

type verifierRuntime struct {
	identity func() (networkjail.NamespaceIdentity, error)
	inspect  func() (networkjail.NamespaceSnapshot, error)
	verify   func(
		context.Context,
		networkjail.DecisionGraph,
		networkjail.NamespaceSnapshot,
	) (networkjail.ProxyProbeReport, error)
}

func defaultVerifierRuntime() verifierRuntime {
	return verifierRuntime{
		identity: inspectNamespaceIdentity,
		inspect:  inspectCurrentNamespace,
		verify: func(
			ctx context.Context,
			graph networkjail.DecisionGraph,
			snapshot networkjail.NamespaceSnapshot,
		) (networkjail.ProxyProbeReport, error) {
			return networkjail.VerifyProxyEgress(
				ctx,
				graph,
				snapshot,
				loopbackProbeClient{},
			)
		},
	}
}

func run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout,
	stderr io.Writer,
	runtime verifierRuntime,
) int {
	if ctx == nil || len(args) != 1 || stdout == nil || stderr == nil {
		return verifierUnavailable(stderr, 2)
	}
	var result any
	switch args[0] {
	case "namespace-id":
		if runtime.identity == nil || requireVerifierEOF(stdin) != nil {
			return verifierUnavailable(stderr, 1)
		}
		identity, err := runtime.identity()
		if err != nil || identity.Device == 0 || identity.Inode == 0 {
			return verifierUnavailable(stderr, 1)
		}
		result = namespaceIdentityReport{Version: 1, Identity: identity}
	case "namespace-empty":
		if runtime.inspect == nil || requireVerifierEOF(stdin) != nil {
			return verifierUnavailable(stderr, 1)
		}
		snapshot, err := runtime.inspect()
		if err != nil {
			return verifierUnavailable(stderr, 1)
		}
		if snapshot.Identity.Device == 0 ||
			snapshot.Identity.Inode == 0 ||
			!snapshot.LoopbackOnly ||
			!snapshot.TablesEmpty ||
			!snapshot.ConntrackEmpty {
			return verifierUnavailable(stderr, 1)
		}
		result = namespaceReport{Version: 1, Namespace: snapshot}
	case "probe":
		if runtime.inspect == nil || runtime.verify == nil {
			return verifierUnavailable(stderr, 1)
		}
		snapshot, err := runtime.inspect()
		if err != nil {
			return verifierUnavailable(stderr, 1)
		}
		graph, err := networkjail.DecodeDecisionGraph(stdin)
		if err != nil {
			return verifierUnavailable(stderr, 1)
		}
		report, err := runtime.verify(ctx, graph, snapshot)
		if err != nil || networkjail.ValidateProxyProbeReport(report) != nil {
			return verifierUnavailable(stderr, 1)
		}
		result = report
	default:
		return verifierUnavailable(stderr, 2)
	}
	document, err := json.Marshal(result)
	if err != nil || len(document)+1 > maxVerifierOutputBytes {
		zero(document)
		return verifierUnavailable(stderr, 1)
	}
	document = append(document, '\n')
	if err := writeVerifierOutput(stdout, document); err != nil {
		zero(document)
		return verifierUnavailable(stderr, 1)
	}
	zero(document)
	return 0
}

func requireVerifierEOF(reader io.Reader) error {
	if reader == nil {
		return nil
	}
	var value [1]byte
	count, err := reader.Read(value[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return errors.New("network-verifier: unexpected input")
	}
	return nil
}

func writeVerifierOutput(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil || count <= 0 {
			return errors.New("network-verifier: output failed")
		}
		data = data[count:]
	}
	return nil
}

func verifierUnavailable(stderr io.Writer, code int) int {
	if stderr != nil {
		_, _ = fmt.Fprintln(
			stderr,
			"portable-ghar-network-verifier: unavailable",
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
		defaultVerifierRuntime(),
	))
}
