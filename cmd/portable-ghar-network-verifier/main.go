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

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const maxVerifierOutputBytes = 16 << 10

type namespaceReport struct {
	Version      uint8                         `json:"version"`
	Capabilities linuxcap.Wire                 `json:"capabilities"`
	Namespace    networkjail.NamespaceSnapshot `json:"namespace"`
}

type namespaceIdentityReport struct {
	Version      uint8                         `json:"version"`
	Capabilities linuxcap.Wire                 `json:"capabilities"`
	Identity     networkjail.NamespaceIdentity `json:"identity"`
}

type proxyReport struct {
	Version              uint8                         `json:"version"`
	Capabilities         linuxcap.Wire                 `json:"capabilities"`
	PolicyDigest         string                        `json:"policy_digest"`
	EgressBackend        networkjail.EgressBackend     `json:"egress_backend"`
	RunnerNetNSID        networkjail.NamespaceIdentity `json:"runner_netns_id"`
	RunnerLoopbackOnly   bool                          `json:"runner_loopback_only"`
	RunnerTablesEmpty    bool                          `json:"runner_tables_empty"`
	RunnerConntrackEmpty bool                          `json:"runner_conntrack_empty"`
	PositiveOK           bool                          `json:"positive_ok"`
	NegativeOK           bool                          `json:"negative_ok"`
}

type floodReport struct {
	Version        uint8                         `json:"version"`
	Attempts       uint64                        `json:"attempts"`
	Completed      bool                          `json:"completed"`
	Capabilities   linuxcap.Wire                 `json:"capabilities"`
	Namespace      networkjail.NamespaceSnapshot `json:"namespace"`
	RoutesComplete bool                          `json:"routes_complete"`
}

type verifierRuntime struct {
	capabilities func() (linuxcap.Wire, error)
	identity     func() (networkjail.NamespaceIdentity, error)
	inspect      func() (networkjail.NamespaceSnapshot, error)
	flood        func(context.Context, uint64) error
	verify       func(
		context.Context,
		networkjail.DecisionGraph,
		networkjail.NamespaceSnapshot,
	) (networkjail.ProxyProbeReport, error)
	closedPlatform func() error
	closedDenials  func(
		context.Context,
		networkjail.DecisionGraph,
		linuxcap.Wire,
	) (closedDenialsWire, error)
}

func defaultVerifierRuntime() verifierRuntime {
	return verifierRuntime{
		capabilities:   linuxcap.ReadSelf,
		identity:       inspectNamespaceIdentity,
		inspect:        inspectCurrentNamespace,
		flood:          runLoopbackFlood,
		closedPlatform: closedDenialsPlatform,
		closedDenials: func(
			ctx context.Context,
			graph networkjail.DecisionGraph,
			capabilities linuxcap.Wire,
		) (closedDenialsWire, error) {
			return observeClosedDenials(
				ctx,
				graph,
				capabilities,
				defaultClosedDenialsProbeRuntime(),
			)
		},
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
	if args[0] == "closed-denials" {
		if runtime.closedPlatform == nil ||
			runtime.closedPlatform() != nil {
			return verifierUnavailable(stderr, 1)
		}
	}
	if runtime.capabilities == nil {
		return verifierUnavailable(stderr, 1)
	}
	capabilities, err := runtime.capabilities()
	if err != nil || linuxcap.ValidateEmpty(capabilities) != nil {
		return verifierUnavailable(stderr, 1)
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
		result = namespaceIdentityReport{
			Version:      2,
			Capabilities: capabilities,
			Identity:     identity,
		}
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
		result = namespaceReport{
			Version:      2,
			Capabilities: capabilities,
			Namespace:    snapshot,
		}
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
		result = proxyReport{
			Version:              2,
			Capabilities:         capabilities,
			PolicyDigest:         report.PolicyDigest,
			EgressBackend:        report.EgressBackend,
			RunnerNetNSID:        report.RunnerNetNSID,
			RunnerLoopbackOnly:   report.RunnerLoopbackOnly,
			RunnerTablesEmpty:    report.RunnerTablesEmpty,
			RunnerConntrackEmpty: report.RunnerConntrackEmpty,
			PositiveOK:           report.PositiveOK,
			NegativeOK:           report.NegativeOK,
		}
	case "loopback-flood":
		if runtime.inspect == nil || runtime.flood == nil {
			return verifierUnavailable(stderr, 1)
		}
		request, err := decodeFloodRequest(stdin)
		if err != nil {
			return verifierUnavailable(stderr, 1)
		}
		before, err := runtime.inspect()
		if err != nil || !validEmptyNamespaceSnapshot(before) {
			return verifierUnavailable(stderr, 1)
		}
		if err := runtime.flood(ctx, request.Attempts); err != nil {
			return verifierUnavailable(stderr, 1)
		}
		after, err := runtime.inspect()
		if err != nil ||
			!validEmptyNamespaceSnapshot(after) ||
			after.Identity != before.Identity {
			return verifierUnavailable(stderr, 1)
		}
		result = floodReport{
			Version:        2,
			Attempts:       request.Attempts,
			Completed:      true,
			Capabilities:   capabilities,
			Namespace:      after,
			RoutesComplete: true,
		}
	case "closed-denials":
		if runtime.closedDenials == nil {
			return verifierUnavailable(stderr, 1)
		}
		graph, err := networkjail.DecodeDecisionGraph(stdin)
		if err != nil {
			return verifierUnavailable(stderr, 1)
		}
		report, err := runtime.closedDenials(
			ctx,
			graph,
			capabilities,
		)
		if err != nil || !validClosedDenialsWire(report) {
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

func validEmptyNamespaceSnapshot(
	snapshot networkjail.NamespaceSnapshot,
) bool {
	return snapshot.Identity.Device != 0 &&
		snapshot.Identity.Inode != 0 &&
		snapshot.LoopbackOnly &&
		snapshot.TablesEmpty &&
		snapshot.ConntrackEmpty
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
