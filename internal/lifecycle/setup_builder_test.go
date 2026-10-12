package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func testSetupConfig(t *testing.T) SetupConfig {
	t.Helper()
	graph, _, err := networkjail.Compile(networkjail.PolicyManifest{
		EgressBackend:                 networkjail.RestrictedBrokerV1,
		IPFamily:                      networkjail.PublicDualStack,
		BrokerIPv6Posture:             networkjail.DenyViaIP6Tables,
		EnabledProtocols:              []networkjail.ProxyProtocol{networkjail.HTTPConnect},
		AllowedConnectPorts:           []uint16{443},
		DoHBootstrap:                  []networkjail.DoHEndpoint{{ServerName: "dns.example.com", Bootstrap: []netip.Addr{netip.AddrFrom4([4]byte{8, 8, 8, 8})}, Path: "/dns-query"}},
		DockerHost:                    []netip.Addr{netip.AddrFrom4([4]byte{11, 11, 11, 11})},
		JobOpenCap:                    2,
		JobDialRate:                   3,
		JobDialBurst:                  4,
		DoHOpenCap:                    1,
		DoHDialRate:                   1,
		DoHDialBurst:                  2,
		TailTimeoutSeconds:            5,
		ConntrackEntriesPerActualDial: 2,
		HostReserveEntries:            10,
		PositiveProbes:                []networkjail.Probe{{Protocol: networkjail.HTTPConnect, Host: "example.com", Port: 443}},
		NegativeProbes:                []networkjail.Probe{{Protocol: networkjail.HTTPConnect, Host: netip.AddrFrom4([4]byte{192, 0, 2, 1}).String(), Port: 443}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	policy, err := networkjail.CompilePolicyArtifact(graph)
	if err != nil {
		t.Fatalf("CompilePolicyArtifact: %v", err)
	}
	return SetupConfig{
		BuildID:         strings.Repeat("a", 64),
		FleetGeneration: 3,
		BrokerRoot:      "/var/lib/portable-ghar/broker",
		Profile:         hostruntime.HostProfileStrictLinux,
		Images: SetupImages{
			Adapter: "adapter@sha256:" + strings.Repeat("1", 64),
			Broker:  "broker@sha256:" + strings.Repeat("2", 64),
			Helper:  "helper@sha256:" + strings.Repeat("3", 64),
			Runner:  "runner@sha256:" + strings.Repeat("4", 64),
			Verifier: "verifier@sha256:" +
				strings.Repeat("5", 64),
		},
		Users:             SetupUsers{AdapterBroker: "1001:1001", Runner: "1002:1002", Verifier: "1003:1003"},
		Seccomp:           hostruntime.SeccompBinding{Path: "/etc/portable-ghar/seccomp.json", SHA256: strings.Repeat("6", 64)},
		Graph:             graph,
		Policy:            policy,
		ConntrackInput:    networkjail.Budget{NFConntrackMax: 262144, NFConntrackCount: 10, TailTimeoutID: "tcp_fin_wait"},
		MaxRunnerCapacity: 1,
	}
}

func testAssignment(t *testing.T) controller.Assignment {
	t.Helper()
	key := controller.AssignmentKey{RepositoryAlias: "example-fleet", RunnerRequestID: 42}
	assignment, err := controller.NewAssignment(
		key,
		githubscale.Offer{JobRef: githubscale.JobRef{RunnerRequestID: 42, JobID: "job-1"}},
		controller.RunnerSlot{OpaqueName: controller.OpaqueSlotName(key), CapacitySlotID: 7},
	)
	if err != nil {
		t.Fatalf("NewAssignment: %v", err)
	}
	return assignment
}

func TestSetupBuilderOutputPassesOrchestratorAndLifecycleChecks(t *testing.T) {
	builder, err := NewSetupBuilder(testSetupConfig(t))
	if err != nil {
		t.Fatalf("NewSetupBuilder: %v", err)
	}
	assignment := testAssignment(t)
	prepared, recovery, err := builder.Build(context.Background(), assignment)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := networkjail.ValidatePreparedSetupRequest(prepared); err != nil {
		t.Fatalf("ValidatePreparedSetupRequest: %v", err)
	}
	if !validBuiltSetup(assignment, prepared, recovery) {
		t.Fatal("validBuiltSetup rejected the builder's output")
	}
	slot := assignment.Slot.OpaqueName
	if prepared.Broker.RelayParent != "/var/lib/portable-ghar/broker/"+slot+"/relay" ||
		prepared.Broker.AuthorityParent != "/var/lib/portable-ghar/broker/"+slot+"/authority" ||
		prepared.Adapter.BrokerParent != prepared.Broker.RelayParent ||
		prepared.Broker.CapacitySlotID != 7 ||
		prepared.Runner.Profile != hostruntime.HostProfileStrictLinux {
		t.Fatalf("relay %q, authority %q, adapter parent %q, slot %d, profile %q",
			prepared.Broker.RelayParent, prepared.Broker.AuthorityParent,
			prepared.Adapter.BrokerParent, prepared.Broker.CapacitySlotID, prepared.Runner.Profile)
	}
	generation, err := JobGeneration(assignment.Key)
	if err != nil || prepared.Broker.JobGeneration != generation {
		t.Fatalf("job generation = %d, want %d (%v)", prepared.Broker.JobGeneration, generation, err)
	}

	again, againRecovery, err := builder.Build(context.Background(), assignment)
	if err != nil || !reflect.DeepEqual(again, prepared) || againRecovery != recovery {
		t.Fatalf("Build is not deterministic: %v", err)
	}
}

func TestJobGenerationIsStablePerKeyAndDistinctAcrossKeys(t *testing.T) {
	key := controller.AssignmentKey{RepositoryAlias: "example-fleet", RunnerRequestID: 42}
	first, err := JobGeneration(key)
	if err != nil || first == 0 {
		t.Fatalf("JobGeneration = %d, %v", first, err)
	}
	if again, _ := JobGeneration(key); again != first {
		t.Fatalf("JobGeneration changed: %d then %d", first, again)
	}
	for _, other := range []controller.AssignmentKey{
		{RepositoryAlias: "example-fleet", RunnerRequestID: 43},
		{RepositoryAlias: "example-fleet", RunnerRequestID: 42, Attempt: 1},
		{RepositoryAlias: "other-fleet", RunnerRequestID: 42},
	} {
		if generation, _ := JobGeneration(other); generation == first {
			t.Fatalf("JobGeneration(%+v) collides with %+v", other, key)
		}
	}
	if _, err := JobGeneration(controller.AssignmentKey{}); err == nil {
		t.Fatal("JobGeneration accepted an empty key")
	}
}

func TestNewSetupBuilderRejectsUnsafeConfig(t *testing.T) {
	tests := map[string]func(*SetupConfig){
		"short build id":        func(c *SetupConfig) { c.BuildID = "abc" },
		"zero fleet generation": func(c *SetupConfig) { c.FleetGeneration = 0 },
		"relative broker root":  func(c *SetupConfig) { c.BrokerRoot = "broker" },
		"unclean broker root":   func(c *SetupConfig) { c.BrokerRoot = "/var/lib/../broker" },
		"missing image":         func(c *SetupConfig) { c.Images.Helper = "" },
		"root broker":           func(c *SetupConfig) { c.Users.AdapterBroker = "0:0" },
		"root verifier":         func(c *SetupConfig) { c.Users.Verifier = "0:1003" },
		"root strict runner":    func(c *SetupConfig) { c.Users.Runner = "0:0" },
		"non-root qts runner":   func(c *SetupConfig) { c.Profile = hostruntime.HostProfileQTSCaplessRoot },
		"unknown profile":       func(c *SetupConfig) { c.Profile = "other" },
		"named user":            func(c *SetupConfig) { c.Users.Runner = "runner" },
		"relative seccomp":      func(c *SetupConfig) { c.Seccomp.Path = "seccomp.json" },
		"invalid policy":        func(c *SetupConfig) { c.Policy = hostruntime.PolicyArtifact{} },
		"zero capacity":         func(c *SetupConfig) { c.MaxRunnerCapacity = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := testSetupConfig(t)
			mutate(&config)
			if _, err := NewSetupBuilder(config); !errors.Is(err, ErrLifecycle) {
				t.Fatalf("NewSetupBuilder error = %v, want ErrLifecycle", err)
			}
		})
	}
	config := testSetupConfig(t)
	config.Profile = hostruntime.HostProfileQTSCaplessRoot
	config.Users.Runner = "0:0"
	if _, err := NewSetupBuilder(config); err != nil {
		t.Fatalf("qts-capless-root with a 0:0 runner: %v", err)
	}
}

type recordingJails struct {
	JailOrchestrator
	prepared int
	err      error
}

func (jails *recordingJails) Prepare(context.Context, networkjail.PreparedSetupRequest) (networkjail.HeldJail, error) {
	jails.prepared++
	return networkjail.HeldJail{}, jails.err
}

func TestWithSlotDirectoriesCreatesDirectoriesBeforePrepare(t *testing.T) {
	builder, err := NewSetupBuilder(testSetupConfig(t))
	if err != nil {
		t.Fatalf("NewSetupBuilder: %v", err)
	}
	prepared, _, err := builder.Build(context.Background(), testAssignment(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	inner := &recordingJails{}
	wrapped, err := WithSlotDirectories(inner, "/var/lib/portable-ghar/broker")
	if err != nil {
		t.Fatalf("WithSlotDirectories: %v", err)
	}
	type call struct {
		root, slot string
		uid, gid   uint32
	}
	var calls []call
	jails := wrapped.(*slotDirectoryJails)
	jails.create = func(root, slot string, uid, gid uint32) error {
		calls = append(calls, call{root, slot, uid, gid})
		if inner.prepared != 0 {
			t.Fatal("directories created after Prepare")
		}
		return nil
	}
	if _, err := wrapped.Prepare(context.Background(), prepared); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(calls) != 1 || calls[0] != (call{"/var/lib/portable-ghar/broker", prepared.Broker.SlotIdentity, 1001, 1001}) || inner.prepared != 1 {
		t.Fatalf("calls = %+v, prepared %d", calls, inner.prepared)
	}

	var removed []string
	jails.remove = func(_ string, slot string) error {
		removed = append(removed, slot)
		return nil
	}
	if len(removed) != 0 {
		t.Fatal("directories removed after a successful Prepare")
	}
	jails.create = func(string, string, uint32, uint32) error { return nil }
	inner.err = errors.New("adapter create failed")
	if _, err := wrapped.Prepare(context.Background(), prepared); !errors.Is(err, inner.err) ||
		len(removed) != 1 || removed[0] != prepared.Broker.SlotIdentity {
		t.Fatalf("failed Prepare = %v, removed %v; want the inner error and one rollback", err, removed)
	}
	removed = nil
	inner.err = fmt.Errorf("adapter remove: %w", networkjail.ErrSetupCleanup)
	if _, err := wrapped.Prepare(context.Background(), prepared); !errors.Is(err, networkjail.ErrSetupCleanup) || len(removed) != 0 {
		t.Fatalf("unproven cleanup = %v, removed %v; want the directories kept for recovery", err, removed)
	}
	inner.err = nil
	inner.prepared = 1

	jails.create = func(string, string, uint32, uint32) error { return errors.New("exists") }
	if _, err := wrapped.Prepare(context.Background(), prepared); !errors.Is(err, ErrLifecycle) || inner.prepared != 1 {
		t.Fatalf("Prepare after a directory failure = %v, prepared %d; want no jail", err, inner.prepared)
	}

	jails.create = func(string, string, uint32, uint32) error { return nil }
	moved := prepared
	moved.Broker.RelayParent = "/tmp/relay"
	if _, err := wrapped.Prepare(context.Background(), moved); !errors.Is(err, ErrLifecycle) || inner.prepared != 1 {
		t.Fatalf("Prepare outside the broker root = %v, prepared %d; want no jail", err, inner.prepared)
	}
}
