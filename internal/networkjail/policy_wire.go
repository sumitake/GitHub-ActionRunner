package networkjail

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const maxDecisionGraphBytes = 128 << 10

type decisionGraphWire struct {
	Version                       uint8             `json:"version"`
	PolicyDigest                  string            `json:"policy_digest"`
	EgressBackend                 EgressBackend     `json:"egress_backend"`
	IPFamily                      IPFamily          `json:"ip_family"`
	BrokerIPv6Posture             BrokerIPv6Posture `json:"broker_ipv6_posture"`
	EnabledProtocols              []ProxyProtocol   `json:"enabled_protocols"`
	AllowedConnectPorts           []uint16          `json:"allowed_connect_ports"`
	DoHBootstrap                  []doHEndpointWire `json:"doh_bootstrap"`
	DynamicDeny                   []string          `json:"dynamic_deny"`
	DockerHost                    []string          `json:"docker_host"`
	JobOpenCap                    uint64            `json:"job_open_cap"`
	JobDialRate                   uint64            `json:"job_dial_rate"`
	JobDialBurst                  uint64            `json:"job_dial_burst"`
	DoHOpenCap                    uint64            `json:"doh_open_cap"`
	DoHDialRate                   uint64            `json:"doh_dial_rate"`
	DoHDialBurst                  uint64            `json:"doh_dial_burst"`
	TailTimeoutSeconds            uint64            `json:"tail_timeout_seconds"`
	ConntrackEntriesPerActualDial uint64            `json:"conntrack_entries_per_actual_dial"`
	HostReserveEntries            uint64            `json:"host_reserve_entries"`
	PositiveProbes                []probeWire       `json:"positive_probes"`
	NegativeProbes                []probeWire       `json:"negative_probes"`
}

type doHEndpointWire struct {
	ServerName string   `json:"server_name"`
	Bootstrap  []string `json:"bootstrap"`
	Path       string   `json:"path"`
}

type probeWire struct {
	Protocol ProxyProtocol `json:"protocol"`
	Host     string        `json:"host"`
	Port     uint16        `json:"port"`
}

// EncodeDecisionGraph returns the exact runtime policy document consumed by
// the parser and dialer. The embedded digest is recomputed from the private
// immutable manifest; a zero or internally inconsistent graph is rejected.
func EncodeDecisionGraph(graph DecisionGraph) ([]byte, error) {
	if graph.digest == (Digest{}) ||
		digestManifest(graph.manifest) != graph.digest {
		return nil, errors.New("networkjail: decision graph invalid")
	}
	wire := decisionGraphToWire(graph)
	document, err := json.Marshal(wire)
	if err != nil || len(document)+1 > maxDecisionGraphBytes {
		return nil, errors.New("networkjail: decision graph encoding failed")
	}
	return append(document, '\n'), nil
}

// DecodeDecisionGraph requires one canonical JSON document, reconstructs the
// public manifest, and recompiles it so no wire field bypasses normalization.
func DecodeDecisionGraph(reader io.Reader) (DecisionGraph, error) {
	if reader == nil {
		return DecisionGraph{}, errors.New("networkjail: decision graph unavailable")
	}
	document, err := io.ReadAll(io.LimitReader(reader, maxDecisionGraphBytes+1))
	if err != nil || len(document) == 0 || len(document) > maxDecisionGraphBytes {
		return DecisionGraph{}, errors.New("networkjail: decision graph invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire decisionGraphWire
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		wire.Version != 1 {
		return DecisionGraph{}, errors.New("networkjail: decision graph invalid")
	}
	manifest, err := decisionGraphManifest(wire)
	if err != nil {
		return DecisionGraph{}, errors.New("networkjail: decision graph invalid")
	}
	graph, digest, err := Compile(manifest)
	if err != nil || wire.PolicyDigest != digest.String() {
		return DecisionGraph{}, errors.New("networkjail: decision graph digest invalid")
	}
	canonical, err := EncodeDecisionGraph(graph)
	if err != nil || !bytes.Equal(canonical, document) {
		return DecisionGraph{}, errors.New("networkjail: decision graph noncanonical")
	}
	return graph, nil
}

func decisionGraphToWire(graph DecisionGraph) decisionGraphWire {
	manifest := graph.manifest
	wire := decisionGraphWire{
		Version:                       1,
		PolicyDigest:                  graph.digest.String(),
		EgressBackend:                 manifest.EgressBackend,
		IPFamily:                      manifest.IPFamily,
		BrokerIPv6Posture:             manifest.BrokerIPv6Posture,
		EnabledProtocols:              slices.Clone(manifest.EnabledProtocols),
		AllowedConnectPorts:           slices.Clone(manifest.AllowedConnectPorts),
		JobOpenCap:                    manifest.JobOpenCap,
		JobDialRate:                   manifest.JobDialRate,
		JobDialBurst:                  manifest.JobDialBurst,
		DoHOpenCap:                    manifest.DoHOpenCap,
		DoHDialRate:                   manifest.DoHDialRate,
		DoHDialBurst:                  manifest.DoHDialBurst,
		TailTimeoutSeconds:            manifest.TailTimeoutSeconds,
		ConntrackEntriesPerActualDial: manifest.ConntrackEntriesPerActualDial,
		HostReserveEntries:            manifest.HostReserveEntries,
	}
	wire.DoHBootstrap = make([]doHEndpointWire, len(manifest.DoHBootstrap))
	for index, endpoint := range manifest.DoHBootstrap {
		bootstrap := make([]string, len(endpoint.Bootstrap))
		for addressIndex, address := range endpoint.Bootstrap {
			bootstrap[addressIndex] = address.String()
		}
		wire.DoHBootstrap[index] = doHEndpointWire{
			ServerName: endpoint.ServerName,
			Bootstrap:  bootstrap,
			Path:       endpoint.Path,
		}
	}
	wire.DynamicDeny = make([]string, len(manifest.DynamicDeny))
	for index, prefix := range manifest.DynamicDeny {
		wire.DynamicDeny[index] = prefix.String()
	}
	wire.DockerHost = make([]string, len(manifest.DockerHost))
	for index, address := range manifest.DockerHost {
		wire.DockerHost[index] = address.String()
	}
	wire.PositiveProbes = probesToWire(manifest.PositiveProbes)
	wire.NegativeProbes = probesToWire(manifest.NegativeProbes)
	return wire
}

func probesToWire(probes []Probe) []probeWire {
	result := make([]probeWire, len(probes))
	for index, probe := range probes {
		result[index] = probeWire(probe)
	}
	return result
}

func decisionGraphManifest(wire decisionGraphWire) (PolicyManifest, error) {
	manifest := PolicyManifest{
		EgressBackend:                 wire.EgressBackend,
		IPFamily:                      wire.IPFamily,
		BrokerIPv6Posture:             wire.BrokerIPv6Posture,
		EnabledProtocols:              slices.Clone(wire.EnabledProtocols),
		AllowedConnectPorts:           slices.Clone(wire.AllowedConnectPorts),
		JobOpenCap:                    wire.JobOpenCap,
		JobDialRate:                   wire.JobDialRate,
		JobDialBurst:                  wire.JobDialBurst,
		DoHOpenCap:                    wire.DoHOpenCap,
		DoHDialRate:                   wire.DoHDialRate,
		DoHDialBurst:                  wire.DoHDialBurst,
		TailTimeoutSeconds:            wire.TailTimeoutSeconds,
		ConntrackEntriesPerActualDial: wire.ConntrackEntriesPerActualDial,
		HostReserveEntries:            wire.HostReserveEntries,
	}
	manifest.DoHBootstrap = make([]DoHEndpoint, len(wire.DoHBootstrap))
	for index, endpoint := range wire.DoHBootstrap {
		bootstrap := make([]netip.Addr, len(endpoint.Bootstrap))
		for addressIndex, raw := range endpoint.Bootstrap {
			address, err := netip.ParseAddr(raw)
			if err != nil || address.String() != raw {
				return PolicyManifest{}, errors.New("networkjail: doh bootstrap wire invalid")
			}
			bootstrap[addressIndex] = address
		}
		manifest.DoHBootstrap[index] = DoHEndpoint{
			ServerName: endpoint.ServerName,
			Bootstrap:  bootstrap,
			Path:       endpoint.Path,
		}
	}
	manifest.DynamicDeny = make([]netip.Prefix, len(wire.DynamicDeny))
	for index, raw := range wire.DynamicDeny {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.String() != raw {
			return PolicyManifest{}, errors.New("networkjail: dynamic deny wire invalid")
		}
		manifest.DynamicDeny[index] = prefix
	}
	manifest.DockerHost = make([]netip.Addr, len(wire.DockerHost))
	for index, raw := range wire.DockerHost {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.String() != raw {
			return PolicyManifest{}, errors.New("networkjail: docker host wire invalid")
		}
		manifest.DockerHost[index] = address
	}
	manifest.PositiveProbes = probesFromWire(wire.PositiveProbes)
	manifest.NegativeProbes = probesFromWire(wire.NegativeProbes)
	return manifest, nil
}

func probesFromWire(probes []probeWire) []Probe {
	result := make([]Probe, len(probes))
	for index, probe := range probes {
		result[index] = Probe(probe)
	}
	return result
}

// CompilePolicyArtifact binds the immutable runtime decision graph to exact
// default-drop iptables-legacy restore programs.
func CompilePolicyArtifact(graph DecisionGraph) (hostruntime.PolicyArtifact, error) {
	runtimePolicy, err := EncodeDecisionGraph(graph)
	if err != nil {
		return hostruntime.PolicyArtifact{}, err
	}
	ipv4 := compileFilterProgram(graph, true)
	var ipv6 []byte
	var posture hostruntime.PolicyIPv6Posture
	switch graph.manifest.BrokerIPv6Posture {
	case DenyViaIP6Tables:
		ipv6 = compileFilterProgram(graph, false)
		posture = hostruntime.PolicyIPv6DenyViaIP6Tables
	case IPv6KernelDisabled:
		posture = hostruntime.PolicyIPv6KernelDisabled
	default:
		return hostruntime.PolicyArtifact{}, errors.New("networkjail: ipv6 posture invalid")
	}
	return hostruntime.NewPolicyArtifact(ipv4, ipv6, runtimePolicy, posture)
}
