package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const (
	closedDenialsIdentityDomain = "portable-ghar.task11.closed-denials-name.v1\x00"
	closedDenialsEntrypoint     = "/usr/local/bin/portable-ghar-network-verifier"
	closedDenialsMode           = "closed-denials"
	closedOneShotMinimumMemory  = uint64(64 << 10)
	closedMaximumDockerMilliCPU = uint64(math.MaxInt64 / 1_000_000)
)

type closedDenialClass string

const (
	closedIPv4TCPNoRoute closedDenialClass = "ipv4_tcp_no_route"
	closedIPv4UDPNoRoute closedDenialClass = "ipv4_udp_no_route"

	closedIPv6TCPNoRoute           closedDenialClass = "ipv6_tcp_no_route"
	closedIPv6TCPFamilyUnavailable closedDenialClass = "ipv6_tcp_family_unavailable"
	closedIPv6UDPNoRoute           closedDenialClass = "ipv6_udp_no_route"
	closedIPv6UDPFamilyUnavailable closedDenialClass = "ipv6_udp_family_unavailable"

	closedDNSUDPNoRoute                    closedDenialClass = "dns_udp_no_route"
	closedRawICMPPermissionDenied          closedDenialClass = "raw_icmp_permission_denied"
	closedPlaintextHTTPParserRejected      closedDenialClass = "plaintext_http_parser_rejected"
	closedUnsupportedConnectParserRejected closedDenialClass = "unsupported_connect_port_parser_rejected"
	closedSOCKSBindParserRejected          closedDenialClass = "socks_bind_parser_rejected"
	closedSOCKSUDPAssociateParserRejected  closedDenialClass = "socks_udp_associate_parser_rejected"
)

type closedParserTopologyObservation struct {
	Identity     networkjail.NamespaceIdentity `json:"identity"`
	LoopbackOnly bool                          `json:"loopback_only"`
	TablesEmpty  bool                          `json:"tables_empty"`
	Conntrack    string                        `json:"conntrack"`
}

type closedDenialsObservationWire struct {
	Version           uint8                           `json:"version"`
	Capabilities      linuxcap.Wire                   `json:"capabilities"`
	PolicyDigest      string                          `json:"policy_digest"`
	IPFamily          networkjail.IPFamily            `json:"ip_family"`
	BrokerIPv6Posture networkjail.BrokerIPv6Posture   `json:"broker_ipv6_posture"`
	Before            networkjail.NamespaceSnapshot   `json:"before"`
	DirectAfter       networkjail.NamespaceSnapshot   `json:"direct_after"`
	ParserAfter       closedParserTopologyObservation `json:"parser_after"`
	IPv4TCP           closedDenialClass               `json:"ipv4_tcp"`
	IPv4UDP           closedDenialClass               `json:"ipv4_udp"`
	IPv6TCP           closedDenialClass               `json:"ipv6_tcp"`
	IPv6UDP           closedDenialClass               `json:"ipv6_udp"`
	DNSUDP            closedDenialClass               `json:"dns_udp"`
	RawICMP           closedDenialClass               `json:"raw_icmp"`
	PlaintextHTTP     closedDenialClass               `json:"plaintext_http"`
	UnsupportedPort   closedDenialClass               `json:"unsupported_connect_port"`
	SOCKSBind         closedDenialClass               `json:"socks_bind"`
	SOCKSUDPAssociate closedDenialClass               `json:"socks_udp_associate"`
	Completed         bool                            `json:"completed"`
}

type closedDenialsSessionObservation struct {
	Name              string
	Cleanup           cleanupHandle
	PolicyDigest      string
	IPFamily          networkjail.IPFamily
	BrokerIPv6Posture networkjail.BrokerIPv6Posture
	BeforeDigest      string
	DirectAfterDigest string
	ParserAfterDigest string
	IPv4TCP           closedDenialClass
	IPv4UDP           closedDenialClass
	IPv6TCP           closedDenialClass
	IPv6UDP           closedDenialClass
	DNSUDP            closedDenialClass
	RawICMP           closedDenialClass
	PlaintextHTTP     closedDenialClass
	UnsupportedPort   closedDenialClass
	SOCKSBind         closedDenialClass
	SOCKSUDPAssociate closedDenialClass
	Digest            string
	Completed         bool
}

func validNetworkSessionBinding(binding networkSessionBinding) bool {
	uid, _, userOK := parseStaticNumericUser(binding.VerifierUser)
	limits := binding.VerifierLimits
	graphDigest := binding.Graph.Digest()
	httpPositive := 0
	for _, probe := range binding.Graph.PositiveProbes() {
		if probe.Protocol == networkjail.HTTPConnect {
			httpPositive++
		}
	}
	return binding.Adapter.kind == CleanupAdapter &&
		binding.Broker.kind == CleanupBroker &&
		isLowerHex(binding.Adapter.id, sha256.Size*2) &&
		isLowerHex(binding.Broker.id, sha256.Size*2) &&
		binding.Adapter.id != binding.Broker.id &&
		isLowerHex(binding.RunDigest, sha256.Size*2) &&
		isLowerHex(binding.BuildID, sha256.Size*2) &&
		binding.FleetGeneration != 0 &&
		validID(binding.SlotIdentity) &&
		immutableImageReferencePattern.MatchString(
			binding.VerifierImage,
		) &&
		userOK &&
		uid != 0 &&
		validAbsolutePath(binding.VerifierSeccomp.Path) &&
		filepath.Clean(binding.VerifierSeccomp.Path) ==
			binding.VerifierSeccomp.Path &&
		isLowerHex(
			binding.VerifierSeccomp.SHA256,
			sha256.Size*2,
		) &&
		limits.MilliCPU != 0 &&
		limits.MilliCPU <= closedMaximumDockerMilliCPU &&
		limits.MemoryBytes >= closedOneShotMinimumMemory &&
		limits.MemoryBytes <= math.MaxInt64 &&
		limits.MemorySwapBytes >= limits.MemoryBytes &&
		limits.MemorySwapBytes <= math.MaxInt64 &&
		limits.PIDs != 0 &&
		limits.PIDs <= math.MaxInt64 &&
		limits.FileDescriptors != 0 &&
		limits.FileDescriptors <= math.MaxInt64 &&
		isLowerHex(
			binding.VerifierSpecDigest,
			sha256.Size*2,
		) &&
		graphDigest != (networkjail.Digest{}) &&
		!slices.Contains(
			binding.Graph.AllowedConnectPorts(),
			uint16(80),
		) &&
		httpPositive == 1
}

func closedDenialsIdentity(
	binding networkSessionBinding,
) (string, cleanupHandle, error) {
	if !validNetworkSessionBinding(binding) {
		return "", cleanupHandle{}, ErrClosedCommand
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(closedDenialsIdentityDomain))
	for _, field := range []string{
		binding.Adapter.id,
		binding.RunDigest,
		binding.BuildID,
		strconv.FormatUint(binding.FleetGeneration, 10),
		binding.VerifierImage,
		binding.VerifierSpecDigest,
	} {
		_, _ = io.WriteString(hash, field)
	}
	full := hash.Sum(nil)
	name := "pghar-task11-verifier-" +
		hex.EncodeToString(full[:16]) +
		"-denials"
	if !compositionContainerNamePattern.MatchString(name) {
		return "", cleanupHandle{}, ErrClosedCommand
	}
	return name, cleanupHandle{
		kind: CleanupVerifier,
		id:   hex.EncodeToString(full),
	}, nil
}

func (s *networkSession) ObserveClosedDenials(
	ctx context.Context,
) (closedDenialsSessionObservation, error) {
	if s == nil ||
		s.surface == nil ||
		s.leases == nil ||
		ctx == nil ||
		ctx.Err() != nil {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	s.mu.Lock()
	if s.observationTaken || s.scannerTaken ||
		len(s.scannerDocument) != 0 {
		s.mu.Unlock()
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	s.observationTaken = true
	s.mu.Unlock()

	if err := s.leases.Register(s.cleanup, s.name); err != nil {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	graphDocument, err := networkjail.EncodeDecisionGraph(s.binding.Graph)
	if err != nil {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	defer zeroClosedBytes(graphDocument)

	result, runErr := s.surface.executeExact(
		ctx,
		s.closedDenialsArgv(),
		bytes.NewReader(graphDocument),
		false,
	)
	defer destroyCommandResult(&result)
	absenceErr := s.proveClosedDenialsAbsent(ctx)
	if runErr != nil || absenceErr != nil {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	wire, canonical, parseErr := parseClosedDenialsObservation(
		result.Stdout,
		s.binding.Graph,
	)
	if parseErr != nil {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	defer zeroClosedBytes(canonical)
	if err := s.leases.Retire(s.cleanup); err != nil {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	beforeDigest, beforeErr := closedStructuredDigest(
		"portable-ghar.task11.closed-denials.before.v1\x00",
		wire.Before,
	)
	directAfterDigest, directAfterErr := closedStructuredDigest(
		"portable-ghar.task11.closed-denials.direct-after.v1\x00",
		wire.DirectAfter,
	)
	parserAfterDigest, parserAfterErr := closedStructuredDigest(
		"portable-ghar.task11.closed-denials.parser-after.v1\x00",
		wire.ParserAfter,
	)
	if beforeErr != nil ||
		directAfterErr != nil ||
		parserAfterErr != nil {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	observation := closedDenialsSessionObservation{
		Name:              s.name,
		Cleanup:           s.cleanup,
		PolicyDigest:      wire.PolicyDigest,
		IPFamily:          wire.IPFamily,
		BrokerIPv6Posture: wire.BrokerIPv6Posture,
		BeforeDigest:      beforeDigest,
		DirectAfterDigest: directAfterDigest,
		ParserAfterDigest: parserAfterDigest,
		IPv4TCP:           wire.IPv4TCP,
		IPv4UDP:           wire.IPv4UDP,
		IPv6TCP:           wire.IPv6TCP,
		IPv6UDP:           wire.IPv6UDP,
		DNSUDP:            wire.DNSUDP,
		RawICMP:           wire.RawICMP,
		PlaintextHTTP:     wire.PlaintextHTTP,
		UnsupportedPort:   wire.UnsupportedPort,
		SOCKSBind:         wire.SOCKSBind,
		SOCKSUDPAssociate: wire.SOCKSUDPAssociate,
		Digest: closedSessionDigest(
			"portable-ghar.task11.closed-denials.v1\x00",
			canonical,
		),
		Completed: true,
	}
	if !validClosedDenialsSessionObservation(
		observation,
		s.binding.Graph,
	) {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	s.mu.Lock()
	if len(s.scannerDocument) != 0 {
		s.mu.Unlock()
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	s.scannerDocument = append([]byte(nil), canonical...)
	s.mu.Unlock()
	return observation, nil
}

func (s *networkSession) takeScannerDocument() ([]byte, error) {
	if s == nil || s.surface == nil {
		return nil, ErrClosedCommand
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.observationTaken ||
		s.scannerTaken ||
		len(s.scannerDocument) == 0 {
		return nil, ErrClosedCommand
	}
	s.scannerTaken = true
	document := s.scannerDocument
	s.scannerDocument = nil
	return document, nil
}

func (s *networkSession) closedDenialsArgv() []string {
	limits := s.binding.VerifierLimits
	return []string{
		s.surface.config.DockerPath, "run", "--rm",
		"--name", s.name,
		"--network", "container:" + s.binding.Adapter.id,
		"--cap-drop", "ALL",
		"--read-only",
		"--security-opt", "no-new-privileges=true",
		"--security-opt", "seccomp=" + s.binding.VerifierSeccomp.Path,
		"--user", s.binding.VerifierUser,
		"--cpus", formatClosedMilliCPU(limits.MilliCPU),
		"--memory", strconv.FormatUint(limits.MemoryBytes, 10),
		"--memory-swap", strconv.FormatUint(
			limits.MemorySwapBytes,
			10,
		),
		"--pids-limit", strconv.FormatUint(limits.PIDs, 10),
		"--ulimit", fmt.Sprintf(
			"nofile=%d:%d",
			limits.FileDescriptors,
			limits.FileDescriptors,
		),
		"--log-driver", "none",
		"--label", "io.portable-ghar.managed=true",
		"--label", "io.portable-ghar.kind=network-verifier",
		"--label", "io.portable-ghar.build-id=" + s.binding.BuildID,
		"--label", "io.portable-ghar.fleet-generation=" +
			strconv.FormatUint(s.binding.FleetGeneration, 10),
		"--label", "io.portable-ghar.slot=" + s.binding.SlotIdentity,
		"--entrypoint", closedDenialsEntrypoint,
		s.binding.VerifierImage,
		closedDenialsMode,
	}
}

func (s *networkSession) proveClosedDenialsAbsent(
	ctx context.Context,
) error {
	if s == nil || s.surface == nil || ctx == nil {
		return ErrClosedCommand
	}
	result, err := s.surface.runner.Run(
		ctx,
		[]string{
			s.surface.config.DockerPath,
			"inspect",
			"--type",
			"container",
			s.name,
		},
		nil,
		nil,
	)
	defer destroyCommandResult(&result)
	total := uint64(len(result.Stdout)) + uint64(len(result.Stderr))
	if err != nil ||
		result.ExitCode != 1 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stdout) != 0 ||
		total > s.surface.config.MaximumBytes {
		return ErrClosedCommand
	}
	want := [][]byte{
		[]byte("Error: No such object: " + s.name + "\n"),
		[]byte(
			"Error response from daemon: No such container: " +
				s.name + "\n",
		),
	}
	for _, expected := range want {
		if bytes.Equal(result.Stderr, expected) {
			return nil
		}
	}
	return ErrClosedCommand
}

func parseClosedDenialsObservation(
	document []byte,
	graph networkjail.DecisionGraph,
) (closedDenialsObservationWire, []byte, error) {
	if len(document) == 0 ||
		len(document) > 16<<10 ||
		document[len(document)-1] != '\n' {
		return closedDenialsObservationWire{}, nil, ErrClosedCommand
	}
	body := document[:len(document)-1]
	var wire closedDenialsObservationWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		!validClosedDenialsObservationWire(wire, graph) {
		return closedDenialsObservationWire{}, nil, ErrClosedCommand
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, body) {
		zeroClosedBytes(canonical)
		return closedDenialsObservationWire{}, nil, ErrClosedCommand
	}
	canonical = append(canonical, '\n')
	return wire, canonical, nil
}

func validClosedDenialsObservationWire(
	wire closedDenialsObservationWire,
	graph networkjail.DecisionGraph,
) bool {
	before := wire.Before
	direct := wire.DirectAfter
	parser := wire.ParserAfter
	return wire.Version == 1 &&
		linuxcap.ValidateEmpty(wire.Capabilities) == nil &&
		wire.PolicyDigest == graph.Digest().String() &&
		wire.IPFamily == graph.IPFamily() &&
		wire.BrokerIPv6Posture == graph.BrokerIPv6Posture() &&
		validClosedEmptyNamespace(before) &&
		validClosedEmptyNamespace(direct) &&
		direct.Identity == before.Identity &&
		parser.Identity == before.Identity &&
		parser.LoopbackOnly &&
		parser.TablesEmpty &&
		parser.Conntrack == "unmeasured" &&
		wire.IPv4TCP == closedIPv4TCPNoRoute &&
		wire.IPv4UDP == closedIPv4UDPNoRoute &&
		(wire.IPv6TCP == closedIPv6TCPNoRoute ||
			wire.IPv6TCP == closedIPv6TCPFamilyUnavailable) &&
		(wire.IPv6UDP == closedIPv6UDPNoRoute ||
			wire.IPv6UDP == closedIPv6UDPFamilyUnavailable) &&
		wire.DNSUDP == closedDNSUDPNoRoute &&
		wire.RawICMP == closedRawICMPPermissionDenied &&
		wire.PlaintextHTTP == closedPlaintextHTTPParserRejected &&
		wire.UnsupportedPort == closedUnsupportedConnectParserRejected &&
		wire.SOCKSBind == closedSOCKSBindParserRejected &&
		wire.SOCKSUDPAssociate ==
			closedSOCKSUDPAssociateParserRejected &&
		wire.Completed
}

func validClosedEmptyNamespace(
	snapshot networkjail.NamespaceSnapshot,
) bool {
	return snapshot.Identity.Device != 0 &&
		snapshot.Identity.Inode != 0 &&
		snapshot.LoopbackOnly &&
		snapshot.TablesEmpty &&
		snapshot.ConntrackEmpty
}

func validClosedDenialsSessionObservation(
	observation closedDenialsSessionObservation,
	graph networkjail.DecisionGraph,
) bool {
	return compositionContainerNamePattern.MatchString(observation.Name) &&
		observation.Cleanup.kind == CleanupVerifier &&
		isLowerHex(observation.Cleanup.id, sha256.Size*2) &&
		observation.PolicyDigest == graph.Digest().String() &&
		observation.IPFamily == graph.IPFamily() &&
		observation.BrokerIPv6Posture == graph.BrokerIPv6Posture() &&
		isLowerHex(observation.BeforeDigest, sha256.Size*2) &&
		isLowerHex(observation.DirectAfterDigest, sha256.Size*2) &&
		isLowerHex(observation.ParserAfterDigest, sha256.Size*2) &&
		observation.IPv4TCP == closedIPv4TCPNoRoute &&
		observation.IPv4UDP == closedIPv4UDPNoRoute &&
		(observation.IPv6TCP == closedIPv6TCPNoRoute ||
			observation.IPv6TCP ==
				closedIPv6TCPFamilyUnavailable) &&
		(observation.IPv6UDP == closedIPv6UDPNoRoute ||
			observation.IPv6UDP ==
				closedIPv6UDPFamilyUnavailable) &&
		observation.DNSUDP == closedDNSUDPNoRoute &&
		observation.RawICMP == closedRawICMPPermissionDenied &&
		observation.PlaintextHTTP ==
			closedPlaintextHTTPParserRejected &&
		observation.UnsupportedPort ==
			closedUnsupportedConnectParserRejected &&
		observation.SOCKSBind == closedSOCKSBindParserRejected &&
		observation.SOCKSUDPAssociate ==
			closedSOCKSUDPAssociateParserRejected &&
		isLowerHex(observation.Digest, sha256.Size*2) &&
		observation.Completed
}

func closedStructuredDigest(domain string, value any) (string, error) {
	if domain == "" || value == nil {
		return "", ErrClosedCommand
	}
	document, err := json.Marshal(value)
	if err != nil || len(document) == 0 {
		return "", ErrClosedCommand
	}
	defer zeroClosedBytes(document)
	return closedSessionDigest(domain, document), nil
}

func formatClosedMilliCPU(value uint64) string {
	whole := value / 1000
	fraction := value % 1000
	if fraction == 0 {
		return strconv.FormatUint(whole, 10)
	}
	formatted := fmt.Sprintf("%d.%03d", whole, fraction)
	return string(bytes.TrimRight([]byte(formatted), "0"))
}
