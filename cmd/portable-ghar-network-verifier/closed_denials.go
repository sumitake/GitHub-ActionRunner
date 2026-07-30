package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"syscall"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

var (
	ErrClosedDenialsUnsupportedPlatform = errors.New(
		"network-verifier: closed denials unsupported platform",
	)
	errClosedDenials = errors.New(
		"network-verifier: closed denials unavailable",
	)
	errClosedPlaintextHTTPRejected = errors.New(
		"network-verifier: plaintext http parser rejected",
	)
	errClosedUnsupportedConnectRejected = errors.New(
		"network-verifier: unsupported connect parser rejected",
	)
	errClosedSOCKSBindRejected = errors.New(
		"network-verifier: socks bind parser rejected",
	)
	errClosedSOCKSUDPAssociateRejected = errors.New(
		"network-verifier: socks udp associate parser rejected",
	)
)

type closedDenialOperation uint8

const (
	closedIPv4TCP closedDenialOperation = iota + 1
	closedIPv4UDP
	closedIPv6TCP
	closedIPv6UDP
	closedDNSUDP
	closedRawICMP
	closedPlaintextHTTP
	closedUnsupportedConnectPort
	closedSOCKSBind
	closedSOCKSUDPAssociate
)

type closedDenialClass string

const (
	classIPv4TCPNoRoute                       closedDenialClass = "ipv4_tcp_no_route"
	classIPv4UDPNoRoute                       closedDenialClass = "ipv4_udp_no_route"
	classIPv6TCPNoRoute                       closedDenialClass = "ipv6_tcp_no_route"
	classIPv6TCPFamilyUnavailable             closedDenialClass = "ipv6_tcp_family_unavailable"
	classIPv6UDPNoRoute                       closedDenialClass = "ipv6_udp_no_route"
	classIPv6UDPFamilyUnavailable             closedDenialClass = "ipv6_udp_family_unavailable"
	classDNSUDPNoRoute                        closedDenialClass = "dns_udp_no_route"
	classRawICMPPermissionDenied              closedDenialClass = "raw_icmp_permission_denied"
	classPlaintextHTTPParserRejected          closedDenialClass = "plaintext_http_parser_rejected"
	classUnsupportedConnectPortParserRejected closedDenialClass = "unsupported_connect_port_parser_rejected"
	classSOCKSBindParserRejected              closedDenialClass = "socks_bind_parser_rejected"
	classSOCKSUDPAssociateParserRejected      closedDenialClass = "socks_udp_associate_parser_rejected"
)

const (
	closedUnsupportedPort uint16 = 80
	closedParserConntrack        = "unmeasured"
)

type closedParserRequest struct {
	Operation closedDenialOperation
	Host      string
	Port      uint16
}

type closedParserTopology struct {
	Identity     networkjail.NamespaceIdentity
	LoopbackOnly bool
	TablesEmpty  bool
}

type closedParserTopologyWire struct {
	Identity     networkjail.NamespaceIdentity `json:"identity"`
	LoopbackOnly bool                          `json:"loopback_only"`
	TablesEmpty  bool                          `json:"tables_empty"`
	Conntrack    string                        `json:"conntrack"`
}

type closedDenialsWire struct {
	Version           uint8                         `json:"version"`
	Capabilities      linuxcap.Wire                 `json:"capabilities"`
	PolicyDigest      string                        `json:"policy_digest"`
	IPFamily          networkjail.IPFamily          `json:"ip_family"`
	BrokerIPv6Posture networkjail.BrokerIPv6Posture `json:"broker_ipv6_posture"`
	Before            networkjail.NamespaceSnapshot `json:"before"`
	DirectAfter       networkjail.NamespaceSnapshot `json:"direct_after"`
	ParserAfter       closedParserTopologyWire      `json:"parser_after"`
	IPv4TCP           closedDenialClass             `json:"ipv4_tcp"`
	IPv4UDP           closedDenialClass             `json:"ipv4_udp"`
	IPv6TCP           closedDenialClass             `json:"ipv6_tcp"`
	IPv6UDP           closedDenialClass             `json:"ipv6_udp"`
	DNSUDP            closedDenialClass             `json:"dns_udp"`
	RawICMP           closedDenialClass             `json:"raw_icmp"`
	PlaintextHTTP     closedDenialClass             `json:"plaintext_http"`
	UnsupportedPort   closedDenialClass             `json:"unsupported_connect_port"`
	SOCKSBind         closedDenialClass             `json:"socks_bind"`
	SOCKSUDPAssociate closedDenialClass             `json:"socks_udp_associate"`
	Completed         bool                          `json:"completed"`
}

type closedDenialsProbeRuntime struct {
	inspectEmpty  func() (networkjail.NamespaceSnapshot, error)
	inspectParser func() (closedParserTopology, error)
	direct        func(context.Context, closedDenialOperation) error
	parser        func(context.Context, closedParserRequest) error
}

func observeClosedDenials(
	ctx context.Context,
	graph networkjail.DecisionGraph,
	capabilities linuxcap.Wire,
	runtime closedDenialsProbeRuntime,
) (closedDenialsWire, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		graph.Digest() == (networkjail.Digest{}) ||
		linuxcap.ValidateEmpty(capabilities) != nil ||
		runtime.inspectEmpty == nil ||
		runtime.inspectParser == nil ||
		runtime.direct == nil ||
		runtime.parser == nil {
		return closedDenialsWire{}, errClosedDenials
	}
	host, err := selectClosedParserHost(graph)
	if err != nil {
		return closedDenialsWire{}, errClosedDenials
	}
	before, err := runtime.inspectEmpty()
	if err != nil || !validEmptyNamespaceSnapshot(before) {
		return closedDenialsWire{}, errClosedDenials
	}
	wire := closedDenialsWire{
		Version:           1,
		Capabilities:      capabilities,
		PolicyDigest:      graph.Digest().String(),
		IPFamily:          graph.IPFamily(),
		BrokerIPv6Posture: graph.BrokerIPv6Posture(),
		Before:            before,
	}
	directOperations := []struct {
		operation closedDenialOperation
		target    *closedDenialClass
	}{
		{closedIPv4TCP, &wire.IPv4TCP},
		{closedIPv4UDP, &wire.IPv4UDP},
		{closedIPv6TCP, &wire.IPv6TCP},
		{closedIPv6UDP, &wire.IPv6UDP},
		{closedDNSUDP, &wire.DNSUDP},
		{closedRawICMP, &wire.RawICMP},
	}
	for _, operation := range directOperations {
		if ctx.Err() != nil {
			return closedDenialsWire{}, errClosedDenials
		}
		class, ok := classifyClosedDirect(
			operation.operation,
			runtime.direct(ctx, operation.operation),
		)
		if !ok {
			return closedDenialsWire{}, errClosedDenials
		}
		*operation.target = class
	}
	directAfter, err := runtime.inspectEmpty()
	if err != nil ||
		!validEmptyNamespaceSnapshot(directAfter) ||
		directAfter.Identity != before.Identity {
		return closedDenialsWire{}, errClosedDenials
	}
	wire.DirectAfter = directAfter

	parserOperations := []struct {
		request closedParserRequest
		want    error
		class   closedDenialClass
		target  *closedDenialClass
	}{
		{
			request: closedParserRequest{Operation: closedPlaintextHTTP},
			want:    errClosedPlaintextHTTPRejected,
			class:   classPlaintextHTTPParserRejected,
			target:  &wire.PlaintextHTTP,
		},
		{
			request: closedParserRequest{
				Operation: closedUnsupportedConnectPort,
				Host:      host,
				Port:      closedUnsupportedPort,
			},
			want:   errClosedUnsupportedConnectRejected,
			class:  classUnsupportedConnectPortParserRejected,
			target: &wire.UnsupportedPort,
		},
		{
			request: closedParserRequest{
				Operation: closedSOCKSBind,
				Host:      host,
				Port:      closedUnsupportedPort,
			},
			want:   errClosedSOCKSBindRejected,
			class:  classSOCKSBindParserRejected,
			target: &wire.SOCKSBind,
		},
		{
			request: closedParserRequest{
				Operation: closedSOCKSUDPAssociate,
				Host:      host,
				Port:      closedUnsupportedPort,
			},
			want:   errClosedSOCKSUDPAssociateRejected,
			class:  classSOCKSUDPAssociateParserRejected,
			target: &wire.SOCKSUDPAssociate,
		},
	}
	for _, operation := range parserOperations {
		if ctx.Err() != nil ||
			!errors.Is(
				runtime.parser(ctx, operation.request),
				operation.want,
			) {
			return closedDenialsWire{}, errClosedDenials
		}
		*operation.target = operation.class
	}
	parserAfter, err := runtime.inspectParser()
	if err != nil ||
		!validClosedParserTopology(parserAfter) ||
		parserAfter.Identity != before.Identity {
		return closedDenialsWire{}, errClosedDenials
	}
	wire.ParserAfter = closedParserTopologyWire{
		Identity:     parserAfter.Identity,
		LoopbackOnly: true,
		TablesEmpty:  true,
		Conntrack:    closedParserConntrack,
	}
	wire.Completed = true
	if !validClosedDenialsWire(wire) {
		return closedDenialsWire{}, errClosedDenials
	}
	return wire, nil
}

func selectClosedParserHost(
	graph networkjail.DecisionGraph,
) (string, error) {
	if slices.Contains(
		graph.AllowedConnectPorts(),
		closedUnsupportedPort,
	) {
		return "", errClosedDenials
	}
	var destination string
	for _, probe := range graph.PositiveProbes() {
		if probe.Protocol != networkjail.HTTPConnect {
			continue
		}
		if destination != "" ||
			probe.Host == "" ||
			probe.Port == 0 {
			return "", errClosedDenials
		}
		if _, err := netip.ParseAddr(probe.Host); err == nil {
			return "", errClosedDenials
		}
		allowed := slices.Contains(
			graph.AllowedConnectPorts(),
			probe.Port,
		)
		if !allowed {
			return "", errClosedDenials
		}
		destination = probe.Host
	}
	if destination == "" {
		return "", errClosedDenials
	}
	return destination, nil
}

func classifyClosedDirect(
	operation closedDenialOperation,
	err error,
) (closedDenialClass, bool) {
	noRoute := errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH)
	familyUnavailable := errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EPROTONOSUPPORT)
	switch operation {
	case closedIPv4TCP:
		return classIPv4TCPNoRoute, noRoute
	case closedIPv4UDP:
		return classIPv4UDPNoRoute, noRoute
	case closedIPv6TCP:
		if noRoute {
			return classIPv6TCPNoRoute, true
		}
		return classIPv6TCPFamilyUnavailable, familyUnavailable
	case closedIPv6UDP:
		if noRoute {
			return classIPv6UDPNoRoute, true
		}
		return classIPv6UDPFamilyUnavailable, familyUnavailable
	case closedDNSUDP:
		return classDNSUDPNoRoute, noRoute
	case closedRawICMP:
		return classRawICMPPermissionDenied,
			errors.Is(err, syscall.EPERM) ||
				errors.Is(err, syscall.EACCES)
	default:
		return "", false
	}
}

func validClosedParserTopology(topology closedParserTopology) bool {
	return topology.Identity.Device != 0 &&
		topology.Identity.Inode != 0 &&
		topology.LoopbackOnly &&
		topology.TablesEmpty
}

func validClosedDenialsWire(wire closedDenialsWire) bool {
	return wire.Version == 1 &&
		linuxcap.ValidateEmpty(wire.Capabilities) == nil &&
		wire.PolicyDigest != "" &&
		wire.IPFamily != "" &&
		wire.BrokerIPv6Posture != "" &&
		validEmptyNamespaceSnapshot(wire.Before) &&
		validEmptyNamespaceSnapshot(wire.DirectAfter) &&
		wire.DirectAfter.Identity == wire.Before.Identity &&
		wire.ParserAfter.Identity == wire.Before.Identity &&
		wire.ParserAfter.LoopbackOnly &&
		wire.ParserAfter.TablesEmpty &&
		wire.ParserAfter.Conntrack == closedParserConntrack &&
		wire.IPv4TCP == classIPv4TCPNoRoute &&
		wire.IPv4UDP == classIPv4UDPNoRoute &&
		(wire.IPv6TCP == classIPv6TCPNoRoute ||
			wire.IPv6TCP == classIPv6TCPFamilyUnavailable) &&
		(wire.IPv6UDP == classIPv6UDPNoRoute ||
			wire.IPv6UDP == classIPv6UDPFamilyUnavailable) &&
		wire.DNSUDP == classDNSUDPNoRoute &&
		wire.RawICMP == classRawICMPPermissionDenied &&
		wire.PlaintextHTTP == classPlaintextHTTPParserRejected &&
		wire.UnsupportedPort ==
			classUnsupportedConnectPortParserRejected &&
		wire.SOCKSBind == classSOCKSBindParserRejected &&
		wire.SOCKSUDPAssociate ==
			classSOCKSUDPAssociateParserRejected &&
		wire.Completed
}
