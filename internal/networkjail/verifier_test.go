package networkjail

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeProxyProbeClient struct {
	results map[string]error
	calls   []Probe
}

func (client *fakeProxyProbeClient) Probe(
	_ context.Context,
	probe Probe,
) error {
	client.calls = append(client.calls, probe)
	return client.results[probe.Host]
}

func TestVerifyProxyEgressRequiresAllPositiveAndNegativeEvidence(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	client := &fakeProxyProbeClient{results: map[string]error{
		deniedDocumentationV4().String(): errors.New("synthetic denial"),
	}}
	report, err := VerifyProxyEgress(
		context.Background(),
		graph,
		NamespaceSnapshot{
			Identity:       NamespaceIdentity{Device: 11, Inode: 12},
			LoopbackOnly:   true,
			TablesEmpty:    true,
			ConntrackEmpty: true,
		},
		client,
	)
	if err != nil || ValidateProxyProbeReport(report) != nil ||
		len(client.calls) != 2 ||
		!report.PositiveOK || !report.NegativeOK {
		t.Fatalf("report=%+v calls=%v err=%v", report, client.calls, err)
	}
}

func TestValidateProbeReportRequiresBrokerParserAndBudgetEvidence(t *testing.T) {
	report := ProbeReport{
		Version:              1,
		PolicyDigest:         strings.Repeat("a", 64),
		EgressBackend:        RestrictedBrokerV1,
		RunnerNetNSID:        NamespaceIdentity{Device: 11, Inode: 12},
		BrokerNetNSID:        NamespaceIdentity{Device: 21, Inode: 22},
		RunnerLoopbackOnly:   true,
		RunnerTablesEmpty:    true,
		RunnerConntrackEmpty: true,
		ParserHasNoSocket:    true,
		PositiveOK:           true,
		NegativeOK:           true,
		ConntrackBudgetOK:    true,
	}
	if err := ValidateProbeReport(report); err != nil {
		t.Fatalf("ValidateProbeReport: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ProbeReport)
	}{
		{
			name: "broker namespace",
			mutate: func(value *ProbeReport) {
				value.BrokerNetNSID = NamespaceIdentity{}
			},
		},
		{
			name: "parser socket proof",
			mutate: func(value *ProbeReport) {
				value.ParserHasNoSocket = false
			},
		},
		{
			name: "conntrack budget",
			mutate: func(value *ProbeReport) {
				value.ConntrackBudgetOK = false
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := report
			test.mutate(&candidate)
			if err := ValidateProbeReport(candidate); err == nil {
				t.Fatal("ValidateProbeReport accepted incomplete evidence")
			}
		})
	}
}

func TestVerifyProxyEgressRejectsPositiveNegativeOrNamespaceFailure(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	valid := NamespaceSnapshot{
		Identity:       NamespaceIdentity{Device: 11, Inode: 12},
		LoopbackOnly:   true,
		TablesEmpty:    true,
		ConntrackEmpty: true,
	}
	tests := []struct {
		name      string
		namespace NamespaceSnapshot
		results   map[string]error
	}{
		{
			name:      "positive denied",
			namespace: valid,
			results: map[string]error{
				"example.com":                    errors.New("synthetic"),
				deniedDocumentationV4().String(): errors.New("synthetic"),
			},
		},
		{
			name:      "negative allowed",
			namespace: valid,
			results:   map[string]error{},
		},
		{
			name: "route present",
			namespace: NamespaceSnapshot{
				Identity:       valid.Identity,
				TablesEmpty:    true,
				ConntrackEmpty: true,
			},
			results: map[string]error{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyProxyEgress(
				context.Background(),
				graph,
				test.namespace,
				&fakeProxyProbeClient{results: test.results},
			); err == nil {
				t.Fatal("invalid evidence was accepted")
			}
		})
	}
}
