// Package networkjail compiles and enforces Portable-GHAR's bounded egress
// policy. It deliberately has no runtime fallback between egress backends or
// address-family postures.
package networkjail

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"
)

type EgressBackend string

const (
	RestrictedBrokerV1 EgressBackend = "restricted-broker-v1"
	NFTablesDirectV1   EgressBackend = "nftables-direct-v1"
)

type IPFamily string

const (
	PublicIPv4Only  IPFamily = "public_ipv4_only"
	PublicDualStack IPFamily = "public_dual_stack"
)

type BrokerIPv6Posture string

const (
	DenyViaIP6Tables   BrokerIPv6Posture = "deny-via-ip6tables"
	IPv6KernelDisabled BrokerIPv6Posture = "kernel-disabled"
)

type ProxyProtocol string

const (
	HTTPConnect   ProxyProtocol = "http-connect"
	SOCKS5Connect ProxyProtocol = "socks5-connect"
)

type DialClass uint8

const (
	DialClassJob DialClass = iota + 1
	DialClassDoH
)

type DoHEndpoint struct {
	ServerName string
	Bootstrap  []netip.Addr
	Path       string
}

type Probe struct {
	Protocol ProxyProtocol
	Host     string
	Port     uint16
}

type PolicyManifest struct {
	EgressBackend                 EgressBackend
	IPFamily                      IPFamily
	BrokerIPv6Posture             BrokerIPv6Posture
	EnabledProtocols              []ProxyProtocol
	AllowedConnectPorts           []uint16
	DoHBootstrap                  []DoHEndpoint
	DynamicDeny                   []netip.Prefix
	DockerHost                    []netip.Addr
	JobOpenCap                    uint64
	JobDialRate                   uint64
	JobDialBurst                  uint64
	DoHOpenCap                    uint64
	DoHDialRate                   uint64
	DoHDialBurst                  uint64
	TailTimeoutSeconds            uint64
	ConntrackEntriesPerActualDial uint64
	HostReserveEntries            uint64
	PositiveProbes                []Probe
	NegativeProbes                []Probe
}

type Digest [sha256.Size]byte

func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

type DialRequest struct {
	Host string
	Port uint16
}

// DecisionGraph is the immutable result of compiling one complete manifest.
// Its slices are never returned directly.
type DecisionGraph struct {
	manifest PolicyManifest
	digest   Digest
}

func Compile(input PolicyManifest) (DecisionGraph, Digest, error) {
	manifest, err := normalizeManifest(input)
	if err != nil {
		return DecisionGraph{}, Digest{}, err
	}
	graph := DecisionGraph{manifest: manifest}
	if err := graph.validateProbes(); err != nil {
		return DecisionGraph{}, Digest{}, err
	}
	graph.digest = digestManifest(manifest)
	return graph, graph.digest, nil
}

func (g DecisionGraph) AllowedConnectPorts() []uint16 {
	return slices.Clone(g.manifest.AllowedConnectPorts)
}

func (g DecisionGraph) Digest() Digest {
	return g.digest
}

func (g DecisionGraph) BrokerIPv6Posture() BrokerIPv6Posture {
	return g.manifest.BrokerIPv6Posture
}

func (g DecisionGraph) EgressBackend() EgressBackend {
	return g.manifest.EgressBackend
}

func (g DecisionGraph) DoHEndpointCount() int {
	return len(g.manifest.DoHBootstrap)
}

func (g DecisionGraph) JobOpenCap() uint64 {
	return g.manifest.JobOpenCap
}

func (g DecisionGraph) TailTimeoutSeconds() uint64 {
	return g.manifest.TailTimeoutSeconds
}

func (g DecisionGraph) PositiveProbes() []Probe {
	return slices.Clone(g.manifest.PositiveProbes)
}

func (g DecisionGraph) NegativeProbes() []Probe {
	return slices.Clone(g.manifest.NegativeProbes)
}

func (g DecisionGraph) protocolEnabled(protocol ProxyProtocol) bool {
	_, found := slices.BinarySearch(g.manifest.EnabledProtocols, protocol)
	return found
}

func (g DecisionGraph) portAllowed(port uint16) bool {
	_, found := slices.BinarySearch(g.manifest.AllowedConnectPorts, port)
	return found
}

func normalizeManifest(input PolicyManifest) (PolicyManifest, error) {
	if input.EgressBackend != RestrictedBrokerV1 {
		return PolicyManifest{}, errors.New("networkjail: egress backend unavailable")
	}
	switch input.IPFamily {
	case PublicIPv4Only:
		if input.BrokerIPv6Posture != IPv6KernelDisabled {
			return PolicyManifest{}, errors.New("networkjail: ipv4-only posture mismatch")
		}
	case PublicDualStack:
		if input.BrokerIPv6Posture != DenyViaIP6Tables {
			return PolicyManifest{}, errors.New("networkjail: dual-stack posture mismatch")
		}
	default:
		return PolicyManifest{}, errors.New("networkjail: ip family invalid")
	}
	if err := validateProtocols(input.EnabledProtocols); err != nil {
		return PolicyManifest{}, err
	}
	if err := validatePorts(input.AllowedConnectPorts); err != nil {
		return PolicyManifest{}, err
	}
	if input.JobOpenCap == 0 || input.JobOpenCap > 1024 ||
		input.JobDialRate == 0 || input.JobDialBurst == 0 ||
		input.DoHOpenCap == 0 || input.DoHDialRate == 0 || input.DoHDialBurst == 0 ||
		input.TailTimeoutSeconds == 0 || input.TailTimeoutSeconds > 30 ||
		input.ConntrackEntriesPerActualDial == 0 ||
		input.HostReserveEntries == 0 {
		return PolicyManifest{}, errors.New("networkjail: budget inputs incomplete")
	}
	if len(input.DoHBootstrap) == 0 || len(input.PositiveProbes) == 0 ||
		len(input.NegativeProbes) == 0 || len(input.DoHBootstrap) > 8 {
		return PolicyManifest{}, errors.New("networkjail: policy evidence incomplete")
	}

	manifest := input
	manifest.EnabledProtocols = slices.Clone(input.EnabledProtocols)
	manifest.AllowedConnectPorts = slices.Clone(input.AllowedConnectPorts)

	dynamic, err := normalizePrefixes(input.DynamicDeny)
	if err != nil {
		return PolicyManifest{}, err
	}
	manifest.DynamicDeny = dynamic

	dockerHosts, err := normalizeAddresses(input.DockerHost)
	if err != nil {
		return PolicyManifest{}, err
	}
	manifest.DockerHost = dockerHosts

	manifest.DoHBootstrap, err = normalizeDoHEndpoints(
		input.DoHBootstrap,
		manifest.IPFamily,
		manifest.DynamicDeny,
		manifest.DockerHost,
	)
	if err != nil {
		return PolicyManifest{}, err
	}

	manifest.PositiveProbes, err = normalizeProbes(input.PositiveProbes)
	if err != nil {
		return PolicyManifest{}, err
	}
	manifest.NegativeProbes, err = normalizeProbes(input.NegativeProbes)
	if err != nil {
		return PolicyManifest{}, err
	}
	return manifest, nil
}

func validateProtocols(protocols []ProxyProtocol) error {
	if len(protocols) == 0 || !slices.IsSorted(protocols) {
		return errors.New("networkjail: protocols not canonical")
	}
	for index, protocol := range protocols {
		switch protocol {
		case HTTPConnect, SOCKS5Connect:
		default:
			return errors.New("networkjail: protocol invalid")
		}
		if index > 0 && protocol == protocols[index-1] {
			return errors.New("networkjail: protocol duplicated")
		}
	}
	return nil
}

func validatePorts(ports []uint16) error {
	if len(ports) == 0 || !slices.IsSorted(ports) {
		return errors.New("networkjail: ports not canonical")
	}
	for index, port := range ports {
		if port == 0 || (index > 0 && port == ports[index-1]) {
			return errors.New("networkjail: port invalid")
		}
	}
	return nil
}

func normalizePrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	result := slices.Clone(prefixes)
	for index, prefix := range result {
		if !prefix.IsValid() || prefix != prefix.Masked() ||
			normalizeEmbedded(prefix.Addr()) != prefix.Addr() {
			return nil, errors.New("networkjail: dynamic deny prefix invalid")
		}
		if index > 0 && comparePrefix(result[index-1], prefix) >= 0 {
			return nil, errors.New("networkjail: dynamic deny prefixes not canonical")
		}
	}
	return result, nil
}

func comparePrefix(left, right netip.Prefix) int {
	if compared := left.Addr().Compare(right.Addr()); compared != 0 {
		return compared
	}
	switch {
	case left.Bits() < right.Bits():
		return -1
	case left.Bits() > right.Bits():
		return 1
	default:
		return 0
	}
}

func normalizeAddresses(addresses []netip.Addr) ([]netip.Addr, error) {
	result := slices.Clone(addresses)
	for index, address := range result {
		if !address.IsValid() || address.Zone() != "" ||
			normalizeEmbedded(address) != address {
			return nil, errors.New("networkjail: docker host address invalid")
		}
		if index > 0 && result[index-1].Compare(address) >= 0 {
			return nil, errors.New("networkjail: docker host addresses not canonical")
		}
	}
	return result, nil
}

func normalizeDoHEndpoints(
	endpoints []DoHEndpoint,
	family IPFamily,
	dynamic []netip.Prefix,
	dockerHosts []netip.Addr,
) ([]DoHEndpoint, error) {
	result := make([]DoHEndpoint, len(endpoints))
	var previous string
	for index, endpoint := range endpoints {
		serverName, err := normalizeName(endpoint.ServerName)
		if err != nil || serverName != strings.ToLower(endpoint.ServerName) ||
			endpoint.Path != "/dns-query" || len(endpoint.Bootstrap) == 0 {
			return nil, errors.New("networkjail: doh endpoint invalid")
		}
		key := serverName + "\x00" + endpoint.Path
		if index > 0 && key <= previous {
			return nil, errors.New("networkjail: doh endpoints not canonical")
		}
		previous = key
		bootstrap := slices.Clone(endpoint.Bootstrap)
		for addressIndex, address := range bootstrap {
			if !address.IsValid() || address.Zone() != "" ||
				normalizeEmbedded(address) != address ||
				!addressAllowed(address, family, dynamic, dockerHosts) {
				return nil, errors.New("networkjail: doh bootstrap invalid")
			}
			if addressIndex > 0 && bootstrap[addressIndex-1].Compare(address) >= 0 {
				return nil, errors.New("networkjail: doh bootstrap not canonical")
			}
		}
		result[index] = DoHEndpoint{
			ServerName: serverName,
			Bootstrap:  bootstrap,
			Path:       endpoint.Path,
		}
	}
	return result, nil
}

func normalizeProbes(probes []Probe) ([]Probe, error) {
	result := make([]Probe, len(probes))
	var previous string
	for index, probe := range probes {
		if probe.Port == 0 {
			return nil, errors.New("networkjail: probe port invalid")
		}
		switch probe.Protocol {
		case HTTPConnect, SOCKS5Connect:
		default:
			return nil, errors.New("networkjail: probe protocol invalid")
		}
		host, _, err := normalizeHostOrLiteral(probe.Host)
		if err != nil {
			return nil, errors.New("networkjail: probe host invalid")
		}
		portKey := []byte{byte(probe.Port >> 8), byte(probe.Port)}
		key := string(probe.Protocol) + "\x00" + host + "\x00" + string(portKey)
		if index > 0 && key <= previous {
			return nil, errors.New("networkjail: probes not canonical")
		}
		previous = key
		result[index] = Probe{Protocol: probe.Protocol, Host: host, Port: probe.Port}
	}
	return result, nil
}

func (g DecisionGraph) validateProbes() error {
	for _, probe := range g.manifest.PositiveProbes {
		if !g.protocolEnabled(probe.Protocol) || !g.portAllowed(probe.Port) {
			return errors.New("networkjail: positive probe outside policy")
		}
		if _, err := g.NormalizeDestination(probe.Host, probe.Port); err != nil {
			return errors.New("networkjail: positive probe denied")
		}
	}
	for _, probe := range g.manifest.NegativeProbes {
		if !g.protocolEnabled(probe.Protocol) || !g.portAllowed(probe.Port) {
			return errors.New("networkjail: negative probe outside policy")
		}
	}
	return nil
}

func digestManifest(manifest PolicyManifest) Digest {
	var buffer bytes.Buffer
	writePolicyString(&buffer, "portable-ghar.network-policy.v1")
	writePolicyString(&buffer, string(manifest.EgressBackend))
	writePolicyString(&buffer, string(manifest.IPFamily))
	writePolicyString(&buffer, string(manifest.BrokerIPv6Posture))
	writePolicyUint64(&buffer, uint64(len(manifest.EnabledProtocols)))
	for _, protocol := range manifest.EnabledProtocols {
		writePolicyString(&buffer, string(protocol))
	}
	writePolicyUint64(&buffer, uint64(len(manifest.AllowedConnectPorts)))
	for _, port := range manifest.AllowedConnectPorts {
		writePolicyUint64(&buffer, uint64(port))
	}
	writePolicyUint64(&buffer, uint64(len(manifest.DoHBootstrap)))
	for _, endpoint := range manifest.DoHBootstrap {
		writePolicyString(&buffer, endpoint.ServerName)
		writePolicyString(&buffer, endpoint.Path)
		writePolicyUint64(&buffer, uint64(len(endpoint.Bootstrap)))
		for _, address := range endpoint.Bootstrap {
			writePolicyString(&buffer, address.String())
		}
	}
	writePolicyUint64(&buffer, uint64(len(manifest.DynamicDeny)))
	for _, prefix := range manifest.DynamicDeny {
		writePolicyString(&buffer, prefix.String())
	}
	writePolicyUint64(&buffer, uint64(len(manifest.DockerHost)))
	for _, address := range manifest.DockerHost {
		writePolicyString(&buffer, address.String())
	}
	for _, value := range []uint64{
		manifest.JobOpenCap,
		manifest.JobDialRate,
		manifest.JobDialBurst,
		manifest.DoHOpenCap,
		manifest.DoHDialRate,
		manifest.DoHDialBurst,
		manifest.TailTimeoutSeconds,
		manifest.ConntrackEntriesPerActualDial,
		manifest.HostReserveEntries,
	} {
		writePolicyUint64(&buffer, value)
	}
	writePolicyProbes(&buffer, manifest.PositiveProbes)
	writePolicyProbes(&buffer, manifest.NegativeProbes)
	return sha256.Sum256(buffer.Bytes())
}

func writePolicyProbes(buffer *bytes.Buffer, probes []Probe) {
	writePolicyUint64(buffer, uint64(len(probes)))
	for _, probe := range probes {
		writePolicyString(buffer, string(probe.Protocol))
		writePolicyString(buffer, probe.Host)
		writePolicyUint64(buffer, uint64(probe.Port))
	}
}

func writePolicyString(buffer *bytes.Buffer, value string) {
	if uint64(len(value)) > math.MaxUint32 {
		panic("networkjail: internal policy string exceeds uint32")
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(len(value)))
	_, _ = buffer.Write(encoded[:])
	_, _ = buffer.WriteString(value)
}

func writePolicyUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = buffer.Write(encoded[:])
}
