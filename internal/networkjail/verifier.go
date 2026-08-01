package networkjail

import (
	"context"
	"errors"
)

type NamespaceIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type NamespaceSnapshot struct {
	Identity       NamespaceIdentity `json:"identity"`
	LoopbackOnly   bool              `json:"loopback_only"`
	TablesEmpty    bool              `json:"tables_empty"`
	ConntrackEmpty bool              `json:"conntrack_empty"`
}

// ProxyProbeReport is the exact one-shot verifier output from the runner
// namespace. Broker-namespace, parser, and host-budget evidence are added only
// by the controller's final audit and therefore cannot be claimed here.
type ProxyProbeReport struct {
	Version              uint8             `json:"version"`
	PolicyDigest         string            `json:"policy_digest"`
	EgressBackend        EgressBackend     `json:"egress_backend"`
	RunnerNetNSID        NamespaceIdentity `json:"runner_netns_id"`
	RunnerLoopbackOnly   bool              `json:"runner_loopback_only"`
	RunnerTablesEmpty    bool              `json:"runner_tables_empty"`
	RunnerConntrackEmpty bool              `json:"runner_conntrack_empty"`
	PositiveOK           bool              `json:"positive_ok"`
	NegativeOK           bool              `json:"negative_ok"`
}

// ProbeReport is the complete controller verification record required before
// a held runner can be armed. It combines the one-shot proxy report with
// disjoint broker-namespace, parser-sandbox, and host conntrack-budget proof.
type ProbeReport struct {
	Version              uint8             `json:"version"`
	PolicyDigest         string            `json:"policy_digest"`
	EgressBackend        EgressBackend     `json:"egress_backend"`
	RunnerNetNSID        NamespaceIdentity `json:"runner_netns_id"`
	BrokerNetNSID        NamespaceIdentity `json:"broker_netns_id"`
	RunnerLoopbackOnly   bool              `json:"runner_loopback_only"`
	RunnerTablesEmpty    bool              `json:"runner_tables_empty"`
	RunnerConntrackEmpty bool              `json:"runner_conntrack_empty"`
	ParserHasNoSocket    bool              `json:"parser_has_no_socket"`
	PositiveOK           bool              `json:"positive_ok"`
	NegativeOK           bool              `json:"negative_ok"`
	ConntrackBudgetOK    bool              `json:"conntrack_budget_ok"`
}

type ProxyProbeClient interface {
	Probe(context.Context, Probe) error
}

func VerifyProxyEgress(
	ctx context.Context,
	graph DecisionGraph,
	namespace NamespaceSnapshot,
	client ProxyProbeClient,
) (ProxyProbeReport, error) {
	if ctx == nil || graph.digest == (Digest{}) || client == nil ||
		namespace.Identity.Device == 0 ||
		namespace.Identity.Inode == 0 ||
		!namespace.LoopbackOnly ||
		!namespace.TablesEmpty ||
		!namespace.ConntrackEmpty {
		return ProxyProbeReport{}, errors.New("networkjail: verifier inputs invalid")
	}
	for _, probe := range graph.manifest.PositiveProbes {
		if err := client.Probe(ctx, probe); err != nil {
			return ProxyProbeReport{}, errors.New("networkjail: positive probe failed")
		}
	}
	for _, probe := range graph.manifest.NegativeProbes {
		if err := client.Probe(ctx, probe); err == nil {
			return ProxyProbeReport{}, errors.New("networkjail: negative probe succeeded")
		}
	}
	return ProxyProbeReport{
		Version:              1,
		PolicyDigest:         graph.digest.String(),
		EgressBackend:        graph.manifest.EgressBackend,
		RunnerNetNSID:        namespace.Identity,
		RunnerLoopbackOnly:   true,
		RunnerTablesEmpty:    true,
		RunnerConntrackEmpty: true,
		PositiveOK:           true,
		NegativeOK:           true,
	}, nil
}

func ValidateProxyProbeReport(report ProxyProbeReport) error {
	if report.Version != 1 ||
		!validLowerHexDigest(report.PolicyDigest) ||
		report.EgressBackend != RestrictedBrokerV1 ||
		report.RunnerNetNSID.Device == 0 ||
		report.RunnerNetNSID.Inode == 0 ||
		!report.RunnerLoopbackOnly ||
		!report.RunnerTablesEmpty ||
		!report.RunnerConntrackEmpty ||
		!report.PositiveOK ||
		!report.NegativeOK {
		return errors.New("networkjail: proxy probe report invalid")
	}
	return nil
}

func ValidateProbeReport(report ProbeReport) error {
	if report.Version != 1 ||
		!validLowerHexDigest(report.PolicyDigest) ||
		report.EgressBackend != RestrictedBrokerV1 ||
		report.RunnerNetNSID.Device == 0 ||
		report.RunnerNetNSID.Inode == 0 ||
		report.BrokerNetNSID.Device == 0 ||
		report.BrokerNetNSID.Inode == 0 ||
		report.RunnerNetNSID == report.BrokerNetNSID ||
		!report.RunnerLoopbackOnly ||
		!report.RunnerTablesEmpty ||
		!report.RunnerConntrackEmpty ||
		!report.ParserHasNoSocket ||
		!report.PositiveOK ||
		!report.NegativeOK ||
		!report.ConntrackBudgetOK {
		return errors.New("networkjail: probe report invalid")
	}
	return nil
}

func validLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
