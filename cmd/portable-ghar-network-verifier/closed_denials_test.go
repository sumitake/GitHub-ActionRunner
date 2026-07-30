package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func TestRunClosedDenialsEmitsExactCanonicalReport(t *testing.T) {
	graph, _, err := networkjail.Compile(verifierPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	document, err := networkjail.EncodeDecisionGraph(graph)
	if err != nil {
		t.Fatalf("EncodeDecisionGraph: %v", err)
	}
	runtime := verifierRuntime{
		capabilities: func() (linuxcap.Wire, error) {
			return verifierEmptyCapabilities(), nil
		},
		closedPlatform: func() error { return nil },
		closedDenials: func(
			ctx context.Context,
			got networkjail.DecisionGraph,
			capabilities linuxcap.Wire,
		) (closedDenialsWire, error) {
			if got.Digest() != graph.Digest() ||
				capabilities != verifierEmptyCapabilities() {
				t.Fatal("closed-denials inputs drifted")
			}
			return observeClosedDenials(
				ctx,
				got,
				capabilities,
				validClosedDenialsRuntime(nil),
			)
		},
	}
	var stdout, stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"closed-denials"},
		bytes.NewReader(document),
		&stdout,
		&stderr,
		runtime,
	)
	want := `{"version":1,"capabilities":{"effective":"0000000000000000",` +
		`"permitted":"0000000000000000","inheritable":"0000000000000000",` +
		`"bounding":"0000000000000000","ambient":"0000000000000000"},` +
		`"policy_digest":"` + graph.Digest().String() + `",` +
		`"ip_family":"public_ipv4_only",` +
		`"broker_ipv6_posture":"kernel-disabled",` +
		`"before":{"identity":{"device":11,"inode":22},` +
		`"loopback_only":true,"tables_empty":true,"conntrack_empty":true},` +
		`"direct_after":{"identity":{"device":11,"inode":22},` +
		`"loopback_only":true,"tables_empty":true,"conntrack_empty":true},` +
		`"parser_after":{"identity":{"device":11,"inode":22},` +
		`"loopback_only":true,"tables_empty":true,"conntrack":"unmeasured"},` +
		`"ipv4_tcp":"ipv4_tcp_no_route","ipv4_udp":"ipv4_udp_no_route",` +
		`"ipv6_tcp":"ipv6_tcp_family_unavailable",` +
		`"ipv6_udp":"ipv6_udp_family_unavailable",` +
		`"dns_udp":"dns_udp_no_route",` +
		`"raw_icmp":"raw_icmp_permission_denied",` +
		`"plaintext_http":"plaintext_http_parser_rejected",` +
		`"unsupported_connect_port":"unsupported_connect_port_parser_rejected",` +
		`"socks_bind":"socks_bind_parser_rejected",` +
		`"socks_udp_associate":"socks_udp_associate_parser_rejected",` +
		`"completed":true}` + "\n"
	if code != 0 || stdout.String() != want || stderr.Len() != 0 {
		t.Fatalf(
			"code=%d stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestObserveClosedDenialsRunsExactOrderAndAcceptsBothIPv6Classes(
	t *testing.T,
) {
	graph, _, err := networkjail.Compile(verifierPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var trace []closedDenialOperation
	runtime := validClosedDenialsRuntime(&trace)
	wire, err := observeClosedDenials(
		context.Background(),
		graph,
		verifierEmptyCapabilities(),
		runtime,
	)
	if err != nil {
		t.Fatalf("observeClosedDenials: %v", err)
	}
	wantTrace := []closedDenialOperation{
		closedIPv4TCP,
		closedIPv4UDP,
		closedIPv6TCP,
		closedIPv6UDP,
		closedDNSUDP,
		closedRawICMP,
		closedPlaintextHTTP,
		closedUnsupportedConnectPort,
		closedSOCKSBind,
		closedSOCKSUDPAssociate,
	}
	if !slices.Equal(trace, wantTrace) ||
		wire.IPv6TCP != classIPv6TCPFamilyUnavailable ||
		wire.IPv6UDP != classIPv6UDPFamilyUnavailable {
		t.Fatalf("trace=%v wire=%+v", trace, wire)
	}

	runtime = validClosedDenialsRuntime(nil)
	runtime.direct = func(
		_ context.Context,
		operation closedDenialOperation,
	) error {
		if operation == closedRawICMP {
			return syscall.EPERM
		}
		return syscall.ENETUNREACH
	}
	wire, err = observeClosedDenials(
		context.Background(),
		graph,
		verifierEmptyCapabilities(),
		runtime,
	)
	if err != nil ||
		wire.IPv6TCP != classIPv6TCPNoRoute ||
		wire.IPv6UDP != classIPv6UDPNoRoute {
		t.Fatalf("IPv6 no-route wire=%+v err=%v", wire, err)
	}
}

func TestObserveClosedDenialsRejectsWrongBoundaryOrTopology(t *testing.T) {
	graph, _, err := networkjail.Compile(verifierPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tests := map[string]func(*closedDenialsProbeRuntime){
		"direct success": func(runtime *closedDenialsProbeRuntime) {
			runtime.direct = func(
				context.Context,
				closedDenialOperation,
			) error {
				return nil
			}
		},
		"direct refused": func(runtime *closedDenialsProbeRuntime) {
			runtime.direct = func(
				context.Context,
				closedDenialOperation,
			) error {
				return syscall.ECONNREFUSED
			}
		},
		"ipv4 family error": func(runtime *closedDenialsProbeRuntime) {
			runtime.direct = func(
				_ context.Context,
				operation closedDenialOperation,
			) error {
				if operation == closedRawICMP {
					return syscall.EPERM
				}
				return syscall.EAFNOSUPPORT
			}
		},
		"raw wrong errno": func(runtime *closedDenialsProbeRuntime) {
			runtime.direct = func(
				_ context.Context,
				operation closedDenialOperation,
			) error {
				if operation == closedRawICMP {
					return syscall.EINVAL
				}
				if operation == closedIPv6TCP ||
					operation == closedIPv6UDP {
					return syscall.EAFNOSUPPORT
				}
				return syscall.ENETUNREACH
			}
		},
		"parser success": func(runtime *closedDenialsProbeRuntime) {
			runtime.parser = func(
				context.Context,
				closedParserRequest,
			) error {
				return nil
			}
		},
		"parser wrong class": func(runtime *closedDenialsProbeRuntime) {
			runtime.parser = func(
				context.Context,
				closedParserRequest,
			) error {
				return errClosedPlaintextHTTPRejected
			}
		},
		"direct identity changed": func(runtime *closedDenialsProbeRuntime) {
			calls := 0
			runtime.inspectEmpty = func() (
				networkjail.NamespaceSnapshot,
				error,
			) {
				calls++
				snapshot := validClosedEmptySnapshot()
				if calls == 2 {
					snapshot.Identity.Inode++
				}
				return snapshot, nil
			}
		},
		"parser tables present": func(runtime *closedDenialsProbeRuntime) {
			runtime.inspectParser = func() (
				closedParserTopology,
				error,
			) {
				topology := completeClosedParserTopology()
				topology.TablesEmpty = false
				return topology, nil
			}
		},
		"missing operation": func(runtime *closedDenialsProbeRuntime) {
			runtime.parser = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runtime := validClosedDenialsRuntime(nil)
			mutate(&runtime)
			if _, err := observeClosedDenials(
				context.Background(),
				graph,
				verifierEmptyCapabilities(),
				runtime,
			); err == nil {
				t.Fatal("invalid denial observation was accepted")
			}
		})
	}
}

func TestObserveClosedDenialsRejectsUnsupportedPortOrMissingHTTPPositive(
	t *testing.T,
) {
	port80 := verifierPolicy()
	port80.AllowedConnectPorts = []uint16{80, 443}
	graph80, _, err := networkjail.Compile(port80)
	if err != nil {
		t.Fatalf("Compile port80: %v", err)
	}
	called := false
	runtime := validClosedDenialsRuntime(nil)
	runtime.inspectEmpty = func() (networkjail.NamespaceSnapshot, error) {
		called = true
		return validClosedEmptySnapshot(), nil
	}
	if _, err := observeClosedDenials(
		context.Background(),
		graph80,
		verifierEmptyCapabilities(),
		runtime,
	); err == nil || called {
		t.Fatalf("port80 accepted err=%v called=%v", err, called)
	}

	noHTTP := verifierPolicy()
	noHTTP.EnabledProtocols = []networkjail.ProxyProtocol{
		networkjail.SOCKS5Connect,
	}
	noHTTP.PositiveProbes[0].Protocol = networkjail.SOCKS5Connect
	noHTTP.NegativeProbes[0].Protocol = networkjail.SOCKS5Connect
	graphNoHTTP, _, err := networkjail.Compile(noHTTP)
	if err != nil {
		t.Fatalf("Compile noHTTP: %v", err)
	}
	if _, err := observeClosedDenials(
		context.Background(),
		graphNoHTTP,
		verifierEmptyCapabilities(),
		validClosedDenialsRuntime(nil),
	); err == nil {
		t.Fatal("graph without one HTTP positive was accepted")
	}
}

func TestObserveClosedDenialsRejectsCancellationAndGraphSubstitution(
	t *testing.T,
) {
	graph, _, err := networkjail.Compile(verifierPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observeClosedDenials(
		ctx,
		graph,
		verifierEmptyCapabilities(),
		validClosedDenialsRuntime(nil),
	); err == nil {
		t.Fatal("canceled observation was accepted")
	}

	dual := verifierPolicy()
	dual.IPFamily = networkjail.PublicDualStack
	dual.BrokerIPv6Posture = networkjail.DenyViaIP6Tables
	dual.DoHBootstrap[0].Bootstrap = []netip.Addr{
		netip.AddrFrom16([16]byte{
			0x20, 0x01, 0x48, 0x60,
			0x48, 0x60, 0, 0,
			0, 0, 0, 0,
			0, 0, 0x88, 0x88,
		}),
	}
	graphDual, _, err := networkjail.Compile(dual)
	if err != nil {
		t.Fatalf("Compile dual: %v", err)
	}
	wire, err := observeClosedDenials(
		context.Background(),
		graphDual,
		verifierEmptyCapabilities(),
		validClosedDenialsRuntime(nil),
	)
	if err != nil ||
		wire.IPFamily != networkjail.PublicDualStack ||
		wire.BrokerIPv6Posture != networkjail.DenyViaIP6Tables ||
		wire.IPv6TCP != classIPv6TCPFamilyUnavailable {
		t.Fatalf("dual wire=%+v err=%v", wire, err)
	}
}

func validClosedDenialsRuntime(
	trace *[]closedDenialOperation,
) closedDenialsProbeRuntime {
	return closedDenialsProbeRuntime{
		inspectEmpty: func() (networkjail.NamespaceSnapshot, error) {
			return validClosedEmptySnapshot(), nil
		},
		inspectParser: func() (closedParserTopology, error) {
			return completeClosedParserTopology(), nil
		},
		direct: func(
			_ context.Context,
			operation closedDenialOperation,
		) error {
			if trace != nil {
				*trace = append(*trace, operation)
			}
			switch operation {
			case closedIPv6TCP, closedIPv6UDP:
				return syscall.EAFNOSUPPORT
			case closedRawICMP:
				return syscall.EPERM
			default:
				return syscall.ENETUNREACH
			}
		},
		parser: func(
			_ context.Context,
			request closedParserRequest,
		) error {
			if trace != nil {
				*trace = append(*trace, request.Operation)
			}
			switch request.Operation {
			case closedPlaintextHTTP:
				return errClosedPlaintextHTTPRejected
			case closedUnsupportedConnectPort:
				if request.Host != "example.com" ||
					request.Port != 80 {
					return errors.New("wrong connect request")
				}
				return errClosedUnsupportedConnectRejected
			case closedSOCKSBind:
				return errClosedSOCKSBindRejected
			case closedSOCKSUDPAssociate:
				return errClosedSOCKSUDPAssociateRejected
			default:
				return errors.New("wrong parser operation")
			}
		},
	}
}

func validClosedEmptySnapshot() networkjail.NamespaceSnapshot {
	return networkjail.NamespaceSnapshot{
		Identity:       networkjail.NamespaceIdentity{Device: 11, Inode: 22},
		LoopbackOnly:   true,
		TablesEmpty:    true,
		ConntrackEmpty: true,
	}
}

func completeClosedParserTopology() closedParserTopology {
	return closedParserTopology{
		Identity:     networkjail.NamespaceIdentity{Device: 11, Inode: 22},
		LoopbackOnly: true,
		TablesEmpty:  true,
	}
}
