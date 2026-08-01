package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
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
		capabilities: func() (linuxcap.Wire, error) {
			return verifierEmptyCapabilities(), nil
		},
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
				`{"version":2,"capabilities":{"effective":"0000000000000000",` +
					`"permitted":"0000000000000000","inheritable":"0000000000000000",` +
					`"bounding":"0000000000000000","ambient":"0000000000000000"},` +
					`"namespace":{"identity":{"device":11,"inode":12},` +
					`"loopback_only":true,"tables_empty":true,"conntrack_empty":true}}` +
					"\n",
			),
		},
		{
			command: "probe",
			input:   document,
			want: []byte(
				`{"version":2,"capabilities":{"effective":"0000000000000000",` +
					`"permitted":"0000000000000000","inheritable":"0000000000000000",` +
					`"bounding":"0000000000000000","ambient":"0000000000000000"},` +
					`"policy_digest":"` + graph.Digest().String() +
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
			capabilities: func() (linuxcap.Wire, error) {
				return verifierEmptyCapabilities(), nil
			},
			identity: func() (networkjail.NamespaceIdentity, error) {
				return networkjail.NamespaceIdentity{Device: 21, Inode: 22}, nil
			},
		},
	)
	if code != 0 ||
		stdout.String() != `{"version":2,"capabilities":{`+
			`"effective":"0000000000000000","permitted":"0000000000000000",`+
			`"inheritable":"0000000000000000","bounding":"0000000000000000",`+
			`"ambient":"0000000000000000"},"identity":{"device":21,"inode":22}}`+"\n" ||
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
			capabilities: func() (linuxcap.Wire, error) {
				return verifierEmptyCapabilities(), nil
			},
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
			capabilities: func() (linuxcap.Wire, error) {
				return verifierEmptyCapabilities(), nil
			},
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

func TestRunRejectsNonemptyCapabilitiesBeforeEveryOperation(t *testing.T) {
	graph, _, err := networkjail.Compile(verifierPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	document, err := networkjail.EncodeDecisionGraph(graph)
	if err != nil {
		t.Fatalf("EncodeDecisionGraph: %v", err)
	}
	nonempty := verifierEmptyCapabilities()
	nonempty.Effective = "0000000000001000"
	for _, test := range []struct {
		operation string
		input     []byte
	}{
		{operation: "namespace-id"},
		{operation: "namespace-empty"},
		{operation: "probe", input: document},
	} {
		t.Run(test.operation, func(t *testing.T) {
			called := false
			runtime := verifierRuntime{
				capabilities: func() (linuxcap.Wire, error) {
					return nonempty, nil
				},
				identity: func() (networkjail.NamespaceIdentity, error) {
					called = true
					return networkjail.NamespaceIdentity{}, nil
				},
				inspect: func() (networkjail.NamespaceSnapshot, error) {
					called = true
					return networkjail.NamespaceSnapshot{}, nil
				},
				verify: func(
					context.Context,
					networkjail.DecisionGraph,
					networkjail.NamespaceSnapshot,
				) (networkjail.ProxyProbeReport, error) {
					called = true
					return networkjail.ProxyProbeReport{}, nil
				},
			}
			var stdout, stderr bytes.Buffer
			if code := run(
				context.Background(),
				[]string{test.operation},
				bytes.NewReader(test.input),
				&stdout,
				&stderr,
				runtime,
			); code != 1 || called || stdout.Len() != 0 {
				t.Fatalf(
					"code=%d called=%v stdout=%q stderr=%q",
					code,
					called,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}

func TestRunLoopbackFloodEmitsOneCanonicalPostFloodReport(t *testing.T) {
	snapshot := networkjail.NamespaceSnapshot{
		Identity:       networkjail.NamespaceIdentity{Device: 31, Inode: 32},
		LoopbackOnly:   true,
		TablesEmpty:    true,
		ConntrackEmpty: true,
	}
	inspectCalls := 0
	floodCalls := 0
	runtime := verifierRuntime{
		capabilities: func() (linuxcap.Wire, error) {
			return verifierEmptyCapabilities(), nil
		},
		inspect: func() (networkjail.NamespaceSnapshot, error) {
			inspectCalls++
			return snapshot, nil
		},
		flood: func(_ context.Context, attempts uint64) error {
			floodCalls++
			if attempts != 3 {
				t.Fatalf("attempts=%d want=3", attempts)
			}
			return nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run(
		context.Background(),
		[]string{"loopback-flood"},
		bytes.NewBufferString("{\"version\":1,\"attempts\":3}\n"),
		&stdout,
		&stderr,
		runtime,
	); code != 0 {
		t.Fatalf(
			"code=%d stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
	want := `{"version":2,"attempts":3,"completed":true,` +
		`"capabilities":{"effective":"0000000000000000",` +
		`"permitted":"0000000000000000","inheritable":"0000000000000000",` +
		`"bounding":"0000000000000000","ambient":"0000000000000000"},` +
		`"namespace":{"identity":{"device":31,"inode":32},"loopback_only":true,` +
		`"tables_empty":true,"conntrack_empty":true},"routes_complete":true}` + "\n"
	if stdout.String() != want ||
		stderr.Len() != 0 ||
		inspectCalls != 2 ||
		floodCalls != 1 {
		t.Fatalf(
			"stdout=%q stderr=%q inspect=%d flood=%d",
			stdout.String(),
			stderr.String(),
			inspectCalls,
			floodCalls,
		)
	}
}

func TestRunLoopbackFloodRejectsInvalidInputBeforeNetworkActivity(t *testing.T) {
	valid := "{\"version\":1,\"attempts\":3}\n"
	tests := map[string]string{
		"missing":       "{\"version\":1}\n",
		"zero":          "{\"version\":1,\"attempts\":0}\n",
		"duplicate":     "{\"version\":1,\"attempts\":3,\"attempts\":3}\n",
		"unknown":       "{\"version\":1,\"attempts\":3,\"host\":\"example.com\"}\n",
		"reordered":     "{\"attempts\":3,\"version\":1}\n",
		"trailing":      valid + "x",
		"old version":   "{\"version\":2,\"attempts\":3}\n",
		"negative":      "{\"version\":1,\"attempts\":-1}\n",
		"overflow":      "{\"version\":1,\"attempts\":18446744073709551616}\n",
		"not canonical": "{\"version\":1, \"attempts\":3}\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			runtime := verifierRuntime{
				capabilities: func() (linuxcap.Wire, error) {
					return verifierEmptyCapabilities(), nil
				},
				inspect: func() (networkjail.NamespaceSnapshot, error) {
					called = true
					return networkjail.NamespaceSnapshot{}, nil
				},
				flood: func(context.Context, uint64) error {
					called = true
					return nil
				},
			}
			var stdout, stderr bytes.Buffer
			if code := run(
				context.Background(),
				[]string{"loopback-flood"},
				bytes.NewBufferString(input),
				&stdout,
				&stderr,
				runtime,
			); code != 1 || called || stdout.Len() != 0 {
				t.Fatalf(
					"code=%d called=%v stdout=%q stderr=%q",
					code,
					called,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}

func TestRunLoopbackFloodRejectsPartialCompletionAndIdentityDrift(t *testing.T) {
	snapshot := networkjail.NamespaceSnapshot{
		Identity:       networkjail.NamespaceIdentity{Device: 41, Inode: 42},
		LoopbackOnly:   true,
		TablesEmpty:    true,
		ConntrackEmpty: true,
	}
	tests := map[string]verifierRuntime{
		"partial completion": {
			capabilities: func() (linuxcap.Wire, error) {
				return verifierEmptyCapabilities(), nil
			},
			inspect: func() (networkjail.NamespaceSnapshot, error) {
				return snapshot, nil
			},
			flood: func(context.Context, uint64) error {
				return errors.New("synthetic")
			},
		},
		"identity drift": {
			capabilities: func() (linuxcap.Wire, error) {
				return verifierEmptyCapabilities(), nil
			},
			inspect: func() func() (networkjail.NamespaceSnapshot, error) {
				calls := 0
				return func() (networkjail.NamespaceSnapshot, error) {
					calls++
					value := snapshot
					if calls == 2 {
						value.Identity.Inode++
					}
					return value, nil
				}
			}(),
			flood: func(context.Context, uint64) error { return nil },
		},
	}
	for name, runtime := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(
				context.Background(),
				[]string{"loopback-flood"},
				bytes.NewBufferString("{\"version\":1,\"attempts\":2}\n"),
				&stdout,
				&stderr,
				runtime,
			); code != 1 || stdout.Len() != 0 {
				t.Fatalf(
					"code=%d stdout=%q stderr=%q",
					code,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}

func TestLoopbackFloodCompletesExactSerialExchangesAndHonorsCancellation(t *testing.T) {
	if err := runLoopbackFlood(context.Background(), 16); err != nil {
		t.Fatalf("runLoopbackFlood: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runLoopbackFlood(ctx, 1); err == nil {
		t.Fatal("runLoopbackFlood accepted canceled context")
	}
	if err := runLoopbackFlood(context.Background(), 0); err == nil {
		t.Fatal("runLoopbackFlood accepted zero attempts")
	}
}

func verifierPolicy() networkjail.PolicyManifest {
	public := verifierIPv4(8, 8, 8, 8)
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
			netip.PrefixFrom(verifierIPv4(9, 9, 9, 9), 32),
		},
		DockerHost: []netip.Addr{
			verifierIPv4(11, 11, 11, 11),
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
			Host:     verifierIPv4(192, 0, 2, 1).String(),
			Port:     443,
		}},
	}
}

func verifierIPv4(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

func verifierEmptyCapabilities() linuxcap.Wire {
	return linuxcap.Wire{
		Effective:   "0000000000000000",
		Permitted:   "0000000000000000",
		Inheritable: "0000000000000000",
		Bounding:    "0000000000000000",
		Ambient:     "0000000000000000",
	}
}
