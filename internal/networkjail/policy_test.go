package networkjail

import (
	"math"
	"net/netip"
	"slices"
	"testing"
)

func TestCompilePolicyIsDeterministicAndOwnsInput(t *testing.T) {
	manifest := validPolicyManifest()
	graphA, digestA, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile(valid) error = %v", err)
	}
	graphB, digestB, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile(valid clone) error = %v", err)
	}
	if digestA != digestB || digestA.String() == "" {
		t.Fatalf("digests = (%q, %q), want equal nonempty", digestA, digestB)
	}

	manifest.AllowedConnectPorts[0] = 1
	manifest.DoHBootstrap[0].Bootstrap[0] = deniedDocumentationV4()
	manifest.DynamicDeny[0] = netip.PrefixFrom(publicV4(12, 12, 12, 12), 32)
	manifest.DockerHost[0] = publicV4(13, 13, 13, 13)

	request, err := graphA.NormalizeDestination("example.com", 443)
	if err != nil || request.Host != "example.com" || request.Port != 443 {
		t.Fatalf("compiled graph changed with caller slices: request=%+v err=%v", request, err)
	}
	if _, err := graphB.NormalizeDestination(publicV4(9, 9, 9, 9).String(), 443); err == nil {
		t.Fatal("compiled dynamic deny was lost after caller mutation")
	}
}

func TestDecisionGraphExposesExactFamilyWithoutConflatingIPv6Posture(
	t *testing.T,
) {
	manifest := validPolicyManifest()
	manifest.IPFamily = PublicDualStack
	manifest.BrokerIPv6Posture = DenyViaIP6Tables
	graph, _, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if graph.IPFamily() != PublicDualStack ||
		graph.BrokerIPv6Posture() != DenyViaIP6Tables {
		t.Fatalf(
			"family/posture = %q/%q",
			graph.IPFamily(),
			graph.BrokerIPv6Posture(),
		)
	}
}

func TestCompileRejectsIncompleteOrNoncanonicalPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PolicyManifest)
	}{
		{"unavailable backend", func(m *PolicyManifest) { m.EgressBackend = NFTablesDirectV1 }},
		{"unknown backend", func(m *PolicyManifest) { m.EgressBackend = EgressBackend("other") }},
		{"unknown family", func(m *PolicyManifest) { m.IPFamily = IPFamily("other") }},
		{"unknown ipv6 posture", func(m *PolicyManifest) { m.BrokerIPv6Posture = BrokerIPv6Posture("other") }},
		{"ipv4 only with ip6tables", func(m *PolicyManifest) {
			m.IPFamily = PublicIPv4Only
			m.BrokerIPv6Posture = DenyViaIP6Tables
		}},
		{"dual stack kernel disabled", func(m *PolicyManifest) {
			m.IPFamily = PublicDualStack
			m.BrokerIPv6Posture = IPv6KernelDisabled
		}},
		{"duplicate protocol", func(m *PolicyManifest) {
			m.EnabledProtocols = []ProxyProtocol{HTTPConnect, HTTPConnect}
		}},
		{"unsorted protocols", func(m *PolicyManifest) {
			m.EnabledProtocols = []ProxyProtocol{SOCKS5Connect, HTTPConnect}
		}},
		{"duplicate port", func(m *PolicyManifest) { m.AllowedConnectPorts = []uint16{443, 443} }},
		{"unsorted port", func(m *PolicyManifest) { m.AllowedConnectPorts = []uint16{8443, 443} }},
		{"zero port", func(m *PolicyManifest) { m.AllowedConnectPorts = []uint16{0} }},
		{"no doh", func(m *PolicyManifest) { m.DoHBootstrap = nil }},
		{"nonpublic doh", func(m *PolicyManifest) {
			m.DoHBootstrap[0].Bootstrap[0] = deniedDocumentationV4()
		}},
		{"duplicate dynamic deny", func(m *PolicyManifest) {
			m.DynamicDeny = append(m.DynamicDeny, m.DynamicDeny[0])
		}},
		{"unmasked dynamic deny", func(m *PolicyManifest) {
			m.DynamicDeny[0] = netip.PrefixFrom(publicV4(9, 9, 9, 10), 24)
		}},
		{"duplicate docker host", func(m *PolicyManifest) {
			m.DockerHost = append(m.DockerHost, m.DockerHost[0])
		}},
		{"zero job open", func(m *PolicyManifest) { m.JobOpenCap = 0 }},
		{"zero job rate", func(m *PolicyManifest) { m.JobDialRate = 0 }},
		{"zero job burst", func(m *PolicyManifest) { m.JobDialBurst = 0 }},
		{"zero doh open", func(m *PolicyManifest) { m.DoHOpenCap = 0 }},
		{"zero doh rate", func(m *PolicyManifest) { m.DoHDialRate = 0 }},
		{"zero doh burst", func(m *PolicyManifest) { m.DoHDialBurst = 0 }},
		{"zero tail", func(m *PolicyManifest) { m.TailTimeoutSeconds = 0 }},
		{"zero factor", func(m *PolicyManifest) { m.ConntrackEntriesPerActualDial = 0 }},
		{"zero reserve", func(m *PolicyManifest) { m.HostReserveEntries = 0 }},
		{"no positive probe", func(m *PolicyManifest) { m.PositiveProbes = nil }},
		{"no negative probe", func(m *PolicyManifest) { m.NegativeProbes = nil }},
		{"probe port outside policy", func(m *PolicyManifest) { m.PositiveProbes[0].Port = 80 }},
		{"probe protocol outside policy", func(m *PolicyManifest) {
			m.EnabledProtocols = []ProxyProtocol{HTTPConnect}
			m.PositiveProbes[0].Protocol = SOCKS5Connect
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := validPolicyManifest()
			tc.mutate(&manifest)
			if _, _, err := Compile(manifest); err == nil {
				t.Fatal("Compile accepted invalid policy")
			}
		})
	}
}

func TestPolicyDigestBindsEveryBudgetScalar(t *testing.T) {
	base := validPolicyManifest()
	_, want, err := Compile(base)
	if err != nil {
		t.Fatalf("Compile(base) error = %v", err)
	}
	mutations := []func(*PolicyManifest){
		func(m *PolicyManifest) { m.JobOpenCap++ },
		func(m *PolicyManifest) { m.JobDialRate++ },
		func(m *PolicyManifest) { m.JobDialBurst++ },
		func(m *PolicyManifest) { m.DoHOpenCap++ },
		func(m *PolicyManifest) { m.DoHDialRate++ },
		func(m *PolicyManifest) { m.DoHDialBurst++ },
		func(m *PolicyManifest) { m.TailTimeoutSeconds++ },
		func(m *PolicyManifest) { m.ConntrackEntriesPerActualDial++ },
		func(m *PolicyManifest) { m.HostReserveEntries++ },
	}
	for index, mutate := range mutations {
		candidate := validPolicyManifest()
		mutate(&candidate)
		_, got, err := Compile(candidate)
		if err != nil {
			t.Fatalf("mutation %d Compile error = %v", index, err)
		}
		if got == want {
			t.Fatalf("mutation %d did not change digest", index)
		}
	}
}

func TestBudgetCheckedArithmetic(t *testing.T) {
	manifest := validPolicyManifest()
	budget := Budget{
		NFConntrackMax:   1_000,
		NFConntrackCount: 100,
		TailTimeoutID:    "synthetic-tail-v1",
	}
	got, err := budget.Compute(manifest, 3)
	if err != nil {
		t.Fatalf("Compute error = %v", err)
	}
	if got.JobClassEntries != 46 ||
		got.DoHClassEntries != 18 ||
		got.PerRunnerEntries != 64 ||
		got.FleetEntries != 192 ||
		got.RequiredWithReserve != 202 ||
		got.AvailableEntries != 900 {
		t.Fatalf("budget = %+v", got)
	}
	if got.Digest.String() == "" {
		t.Fatal("budget digest empty")
	}
}

func TestBudgetRejectsOverflowAndUnavailableHeadroom(t *testing.T) {
	tests := []struct {
		name     string
		manifest PolicyManifest
		budget   Budget
		capacity uint64
	}{
		{
			name:     "zero capacity",
			manifest: validPolicyManifest(),
			budget:   Budget{NFConntrackMax: 1_000, NFConntrackCount: 1, TailTimeoutID: "tail"},
		},
		{
			name:     "count above max",
			manifest: validPolicyManifest(),
			budget:   Budget{NFConntrackMax: 10, NFConntrackCount: 11, TailTimeoutID: "tail"},
			capacity: 1,
		},
		{
			name: "rate times tail overflow",
			manifest: func() PolicyManifest {
				m := validPolicyManifest()
				m.JobDialRate = math.MaxUint64
				return m
			}(),
			budget:   Budget{NFConntrackMax: math.MaxUint64, NFConntrackCount: 1, TailTimeoutID: "tail"},
			capacity: 1,
		},
		{
			name: "factor overflow",
			manifest: func() PolicyManifest {
				m := validPolicyManifest()
				m.ConntrackEntriesPerActualDial = math.MaxUint64
				return m
			}(),
			budget:   Budget{NFConntrackMax: math.MaxUint64, NFConntrackCount: 1, TailTimeoutID: "tail"},
			capacity: 1,
		},
		{
			name:     "fleet overflow",
			manifest: validPolicyManifest(),
			budget:   Budget{NFConntrackMax: math.MaxUint64, NFConntrackCount: 1, TailTimeoutID: "tail"},
			capacity: math.MaxUint64,
		},
		{
			name:     "reserve consumes max",
			manifest: validPolicyManifest(),
			budget:   Budget{NFConntrackMax: 10, NFConntrackCount: 1, TailTimeoutID: "tail"},
			capacity: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.budget.Compute(tc.manifest, tc.capacity); err == nil {
				t.Fatal("Compute accepted unavailable budget")
			}
		})
	}
}

func TestCompiledCollectionsAreCanonical(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	if !slices.IsSorted(graph.AllowedConnectPorts()) {
		t.Fatalf("ports = %v, want sorted", graph.AllowedConnectPorts())
	}
	ports := graph.AllowedConnectPorts()
	ports[0] = 1
	if graph.AllowedConnectPorts()[0] != 443 {
		t.Fatal("AllowedConnectPorts exposed mutable backing storage")
	}
}

func TestNormalizeProbesPreservesDistinctHighPorts(t *testing.T) {
	probes := []Probe{
		{Protocol: HTTPConnect, Host: "example.com", Port: 0xd7ff},
		{Protocol: HTTPConnect, Host: "example.com", Port: 0xd800},
		{Protocol: HTTPConnect, Host: "example.com", Port: 0xd801},
		{Protocol: HTTPConnect, Host: "example.com", Port: 0xe000},
	}
	normalized, err := normalizeProbes(probes)
	if err != nil {
		t.Fatalf("normalizeProbes: %v", err)
	}
	if !slices.Equal(normalized, probes) {
		t.Fatalf("normalizeProbes=%+v want=%+v", normalized, probes)
	}
}
