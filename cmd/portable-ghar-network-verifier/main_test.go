package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func TestRunNamespaceAndProbeEmitClosedCanonicalReports(t *testing.T) {
	graph, _, err := networkjail.Compile(verifierPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	document, err := networkjail.EncodeDecisionGraph(graph)
	if err != nil {
		t.Fatalf("EncodeDecisionGraph: %v", err)
	}
	snapshot := networkjail.NamespaceSnapshot{
		Identity:       networkjail.NamespaceIdentity{Device: 11, Inode: 12},
		LoopbackOnly:   true,
		TablesEmpty:    true,
		ConntrackEmpty: true,
	}
	runtime := verifierRuntime{
		inspect: func() (networkjail.NamespaceSnapshot, error) {
			return snapshot, nil
		},
		verify: func(
			_ context.Context,
			got networkjail.DecisionGraph,
			gotSnapshot networkjail.NamespaceSnapshot,
		) (networkjail.ProxyProbeReport, error) {
			if got.Digest() != graph.Digest() || gotSnapshot != snapshot {
				t.Fatal("verifier inputs drifted")
			}
			return networkjail.ProxyProbeReport{
				Version:              1,
				PolicyDigest:         graph.Digest().String(),
				EgressBackend:        networkjail.RestrictedBrokerV1,
				RunnerNetNSID:        snapshot.Identity,
				RunnerLoopbackOnly:   true,
				RunnerTablesEmpty:    true,
				RunnerConntrackEmpty: true,
				PositiveOK:           true,
				NegativeOK:           true,
			}, nil
		},
	}
	tests := []struct {
		command string
		input   []byte
		want    []byte
	}{
		{
			command: "namespace-empty",
			want: []byte(
				`{"version":1,"namespace":{"identity":{"device":11,"inode":12},` +
					`"loopback_only":true,"tables_empty":true,"conntrack_empty":true}}` +
					"\n",
			),
		},
		{
			command: "probe",
			input:   document,
			want: []byte(
				`{"version":1,"policy_digest":"` + graph.Digest().String() +
					`","egress_backend":"restricted-broker-v1",` +
					`"runner_netns_id":{"device":11,"inode":12},` +
					`"runner_loopback_only":true,"runner_tables_empty":true,` +
					`"runner_conntrack_empty":true,"positive_ok":true,` +
					`"negative_ok":true}` + "\n",
			),
		},
	}
	for _, test := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(
			context.Background(),
			[]string{test.command},
			bytes.NewReader(test.input),
			&stdout,
			&stderr,
			runtime,
		); code != 0 {
			t.Fatalf(
				"%s code=%d stdout=%q stderr=%q",
				test.command,
				code,
				stdout.String(),
				stderr.String(),
			)
		}
		if !bytes.Equal(stdout.Bytes(), test.want) || stderr.Len() != 0 {
			t.Fatalf(
				"%s stdout=%q want=%q stderr=%q",
				test.command,
				stdout.Bytes(),
				test.want,
				stderr.String(),
			)
		}
	}
}

func TestRunNamespaceIDDoesNotRequireAnEmptyNamespace(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"namespace-id"},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
		verifierRuntime{
			identity: func() (networkjail.NamespaceIdentity, error) {
				return networkjail.NamespaceIdentity{Device: 21, Inode: 22}, nil
			},
		},
	)
	if code != 0 ||
		stdout.String() != `{"version":1,"identity":{"device":21,"inode":22}}`+"\n" ||
		stderr.Len() != 0 {
		t.Fatalf(
			"code=%d stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestRunFailsClosedWithoutNamespaceOrProbeEvidence(t *testing.T) {
	tests := []verifierRuntime{
		{
			inspect: func() (networkjail.NamespaceSnapshot, error) {
				return networkjail.NamespaceSnapshot{}, errors.New("synthetic")
			},
			verify: func(
				context.Context,
				networkjail.DecisionGraph,
				networkjail.NamespaceSnapshot,
			) (networkjail.ProxyProbeReport, error) {
				return networkjail.ProxyProbeReport{}, nil
			},
		},
		{
			inspect: func() (networkjail.NamespaceSnapshot, error) {
				return networkjail.NamespaceSnapshot{
					Identity:       networkjail.NamespaceIdentity{Device: 1, Inode: 2},
					LoopbackOnly:   true,
					TablesEmpty:    true,
					ConntrackEmpty: true,
				}, nil
			},
			verify: func(
				context.Context,
				networkjail.DecisionGraph,
				networkjail.NamespaceSnapshot,
			) (networkjail.ProxyProbeReport, error) {
				return networkjail.ProxyProbeReport{}, errors.New("synthetic")
			},
		},
	}
	graph, _, err := networkjail.Compile(verifierPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	document, _ := networkjail.EncodeDecisionGraph(graph)
	for index, runtime := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(
			context.Background(),
			[]string{"probe"},
			bytes.NewReader(document),
			&stdout,
			&stderr,
			runtime,
		); code != 1 ||
			stdout.Len() != 0 ||
			stderr.String() != "portable-ghar-network-verifier: unavailable\n" {
			t.Fatalf(
				"case %d code=%d stdout=%q stderr=%q",
				index,
				code,
				stdout.String(),
				stderr.String(),
			)
		}
	}
}

func verifierPolicy() networkjail.PolicyManifest {
	public := netip.MustParseAddr("8.8.8.8")
	return networkjail.PolicyManifest{
		EgressBackend:       networkjail.RestrictedBrokerV1,
		IPFamily:            networkjail.PublicIPv4Only,
		BrokerIPv6Posture:   networkjail.IPv6KernelDisabled,
		EnabledProtocols:    []networkjail.ProxyProtocol{networkjail.HTTPConnect},
		AllowedConnectPorts: []uint16{443},
		DoHBootstrap: []networkjail.DoHEndpoint{{
			ServerName: "dns.example.com",
			Bootstrap:  []netip.Addr{public},
			Path:       "/dns-query",
		}},
		DynamicDeny: []netip.Prefix{
			netip.MustParsePrefix("9.9.9.9/32"),
		},
		DockerHost: []netip.Addr{
			netip.MustParseAddr("11.11.11.11"),
		},
		JobOpenCap:                    2,
		JobDialRate:                   3,
		JobDialBurst:                  4,
		DoHOpenCap:                    1,
		DoHDialRate:                   1,
		DoHDialBurst:                  2,
		TailTimeoutSeconds:            5,
		ConntrackEntriesPerActualDial: 2,
		HostReserveEntries:            10,
		PositiveProbes: []networkjail.Probe{{
			Protocol: networkjail.HTTPConnect,
			Host:     "example.com",
			Port:     443,
		}},
		NegativeProbes: []networkjail.Probe{{
			Protocol: networkjail.HTTPConnect,
			Host:     "192.0.2.1",
			Port:     443,
		}},
	}
}
