package testenv

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

type fixedCompositionClock struct {
	observation networkjail.ClockObservation
}

func (c fixedCompositionClock) Observe(
	ctx context.Context,
) (networkjail.ClockObservation, error) {
	if ctx == nil || ctx.Err() != nil {
		return networkjail.ClockObservation{}, ctx.Err()
	}
	return c.observation, nil
}

func TestNewFixtureRuntimeCompositionBindsExistingProductionConstructors(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, seccomp, plan :=
		validRuntimeSpecInputs(t)
	overlay.Commands.DockerBinary = "/usr/bin/docker"
	overlay.Paths.SeccompRoot = filepath.Dir(input.Runtime.SeccompPath)
	overlay.Docker.BrokerNetworkID = "portable-ghar-broker"
	sentinels, manifest := validProbeMembershipManifest()
	input.Sentinels = sentinels
	graph, _, err := networkjail.Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	policy, err := networkjail.CompilePolicyArtifact(graph)
	if err != nil {
		t.Fatalf("CompilePolicyArtifact: %v", err)
	}
	probes, err := newProbeMembershipSeal(input.Sentinels, graph)
	if err != nil {
		t.Fatalf("newProbeMembershipSeal: %v", err)
	}
	static.PolicyGraphDigest = graph.Digest().String()
	overlay.Policy.CompiledGraphDigest = graph.Digest().String()
	store, err := state.OpenWithHistoryLimits(
		filepath.Join(t.TempDir(), "controller.db"),
		plan.HistoryLimits,
	)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := seedCompositionAssignment(
		context.Background(),
		store,
		plan,
		time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("seedCompositionAssignment: %v", err)
	}
	composed, err := newFixtureRuntimeComposition(
		context.Background(),
		input,
		overlay,
		static,
		seccomp,
		graph,
		policy,
		probes,
		plan,
		store,
		fixedCompositionClock{
			observation: networkjail.ClockObservation{
				BootID:         networkjail.BootID{1},
				MonotonicNanos: 1,
			},
		},
		fakePermitPeerProcessObserver{
			observation: permitPeerProcessObservation{
				UID:       65532,
				StartTime: 1,
			},
		},
		func(cleanupHandle) error { return nil },
	)
	if err != nil {
		t.Fatalf("newFixtureRuntimeComposition: %v", err)
	}
	if composed.Engine == nil ||
		composed.Journal == nil ||
		composed.Authority == nil ||
		composed.AuthorityManager == nil ||
		composed.Orchestrator == nil ||
		composed.OneShotRecorder == nil ||
		composed.ClosedSurface == nil ||
		composed.MatrixBinding.RunID != input.Authorization.RunID ||
		composed.RunnerUser != static.RunnerUser ||
		composed.MaximumEvidence !=
			input.Limits.MaximumEvidenceBytes {
		t.Fatalf("composition = %+v", composed)
	}
	request := composed.Request
	if request.Key != plan.AssignmentKey ||
		request.Graph.Digest() != graph.Digest() ||
		request.Policy.Digest() != policy.Digest() ||
		request.ConntrackInput != plan.ConntrackInput ||
		request.MaxRunnerCapacity != plan.MaxRunnerCapacity ||
		request.SeedIDs == nil ||
		len(request.SeedIDs) != 0 ||
		request.Adapter.Name != plan.Identity.AdapterName ||
		request.Broker.CapacitySlotID !=
			plan.Identity.CapacitySlotID ||
		request.Broker.JobGeneration !=
			plan.Identity.JobGeneration ||
		request.Runner.Name != plan.Identity.RunnerName {
		t.Fatalf("request = %+v", request)
	}
}

func TestNewFixtureRuntimeCompositionRejectsUnboundOrMismatchedInput(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, seccomp, plan :=
		validRuntimeSpecInputs(t)
	overlay.Commands.DockerBinary = "/usr/bin/docker"
	overlay.Paths.SeccompRoot = filepath.Dir(input.Runtime.SeccompPath)
	overlay.Docker.BrokerNetworkID = "portable-ghar-broker"
	sentinels, manifest := validProbeMembershipManifest()
	input.Sentinels = sentinels
	graph, _, err := networkjail.Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	policy, err := networkjail.CompilePolicyArtifact(graph)
	if err != nil {
		t.Fatalf("CompilePolicyArtifact: %v", err)
	}
	probes, err := newProbeMembershipSeal(input.Sentinels, graph)
	if err != nil {
		t.Fatalf("newProbeMembershipSeal: %v", err)
	}
	static.PolicyGraphDigest = graph.Digest().String()
	overlay.Policy.CompiledGraphDigest = graph.Digest().String()
	store, err := state.OpenWithHistoryLimits(
		filepath.Join(t.TempDir(), "controller.db"),
		plan.HistoryLimits,
	)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	clock := fixedCompositionClock{
		observation: networkjail.ClockObservation{
			BootID:         networkjail.BootID{1},
			MonotonicNanos: 1,
		},
	}
	observer := fakePermitPeerProcessObserver{
		observation: permitPeerProcessObservation{
			UID:       65532,
			StartTime: 1,
		},
	}
	if _, err := newFixtureRuntimeComposition(
		context.Background(),
		input,
		overlay,
		static,
		seccomp,
		graph,
		policy,
		probes,
		plan,
		store,
		clock,
		observer,
		func(cleanupHandle) error { return nil },
	); err != ErrFixtureStart {
		t.Fatalf("unseeded error = %v", err)
	}
	if err := seedCompositionAssignment(
		context.Background(),
		store,
		plan,
		time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("seedCompositionAssignment: %v", err)
	}
	static.PolicyGraphDigest = strings.Repeat("f", 64)
	if _, err := newFixtureRuntimeComposition(
		context.Background(),
		input,
		overlay,
		static,
		seccomp,
		graph,
		policy,
		probes,
		plan,
		store,
		clock,
		observer,
		func(cleanupHandle) error { return nil },
	); err != ErrFixtureStart {
		t.Fatalf("graph mismatch error = %v", err)
	}
}

func validCompositionPolicyManifest() networkjail.PolicyManifest {
	public := func(a, b, c, d byte) netip.Addr {
		return netip.AddrFrom4([4]byte{a, b, c, d})
	}
	return networkjail.PolicyManifest{
		EgressBackend:     networkjail.RestrictedBrokerV1,
		IPFamily:          networkjail.PublicDualStack,
		BrokerIPv6Posture: networkjail.DenyViaIP6Tables,
		EnabledProtocols: []networkjail.ProxyProtocol{
			networkjail.HTTPConnect,
			networkjail.SOCKS5Connect,
		},
		AllowedConnectPorts: []uint16{443, 8443},
		DoHBootstrap: []networkjail.DoHEndpoint{{
			ServerName: "dns.example.com",
			Bootstrap:  []netip.Addr{public(8, 8, 8, 8)},
			Path:       "/dns-query",
		}},
		DynamicDeny: []netip.Prefix{
			netip.PrefixFrom(public(9, 9, 9, 9), 32),
		},
		DockerHost:                    []netip.Addr{public(11, 11, 11, 11)},
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
