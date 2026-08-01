package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
)

func helperNetAdminCapabilityWire() linuxcap.Wire {
	return linuxcap.Wire{
		Effective:   "0000000000001000",
		Permitted:   "0000000000001000",
		Inheritable: "0000000000000000",
		Bounding:    "0000000000001000",
		Ambient:     "0000000000000000",
	}
}

func TestParsePolicyApplicationRequiresNetAdminOnlyCapabilityWire(t *testing.T) {
	valid := policyApplicationWire{
		Version:      2,
		Digest:       strings.Repeat("a", 64),
		IPv6Posture:  "deny-via-ip6tables",
		Capabilities: helperNetAdminCapabilityWire(),
	}
	if _, err := parsePolicyApplication(
		canonicalJSONLine(t, valid),
	); err != nil {
		t.Fatalf("parsePolicyApplication(valid): %v", err)
	}
	for name, mutate := range map[string]func(*policyApplicationWire){
		"old version": func(wire *policyApplicationWire) {
			wire.Version = 1
		},
		"missing capability": func(wire *policyApplicationWire) {
			wire.Capabilities.Ambient = ""
		},
		"empty effective": func(wire *policyApplicationWire) {
			wire.Capabilities.Effective = "0000000000000000"
		},
		"extra permitted": func(wire *policyApplicationWire) {
			wire.Capabilities.Permitted = "0000000000001001"
		},
		"ambient nonzero": func(wire *policyApplicationWire) {
			wire.Capabilities.Ambient = "0000000000001000"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := parsePolicyApplication(
				canonicalJSONLine(t, candidate),
			); err == nil {
				t.Fatal("parsePolicyApplication accepted invalid capabilities")
			}
		})
	}
}

func TestParseHeldSocketAuditRequiresEveryInternetSocketCountZero(t *testing.T) {
	valid := heldSocketAuditWire{Version: 1}
	if _, err := parseHeldSocketAudit(
		canonicalJSONLine(t, valid),
	); err != nil {
		t.Fatalf("parseHeldSocketAudit(valid): %v", err)
	}
	for name, mutate := range map[string]func(*heldSocketAuditWire){
		"old version": func(wire *heldSocketAuditWire) {
			wire.Version = 2
		},
		"tcp4": func(wire *heldSocketAuditWire) {
			wire.TCP4 = 1
		},
		"tcp6": func(wire *heldSocketAuditWire) {
			wire.TCP6 = 1
		},
		"udp4": func(wire *heldSocketAuditWire) {
			wire.UDP4 = 1
		},
		"udp6": func(wire *heldSocketAuditWire) {
			wire.UDP6 = 1
		},
		"raw4": func(wire *heldSocketAuditWire) {
			wire.Raw4 = 1
		},
		"raw6": func(wire *heldSocketAuditWire) {
			wire.Raw6 = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := parseHeldSocketAudit(
				canonicalJSONLine(t, candidate),
			); err == nil {
				t.Fatal("parseHeldSocketAudit accepted nonzero socket count")
			}
		})
	}
}

func TestAuthorityProofMatchesOnlyExactPermitActivation(t *testing.T) {
	t.Parallel()

	proof, err := NewAuthorityProof(AuthorityBinding{
		Version:        1,
		CapacitySlotID: 7,
		JobGeneration:  19,
		LedgerRevision: 23,
		Directory: DirectoryIdentity{
			Device: 11,
			Inode:  12,
			UID:    1001,
			GID:    1001,
			Mode:   0o700,
		},
		Socket: SocketIdentity{
			Name:   dialAuthoritySocketName,
			Device: 11,
			Inode:  13,
			UID:    1001,
			GID:    1001,
			Mode:   0o600,
		},
		Peer: ProcessIdentity{
			PID:       71,
			StartTime: 72,
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorityProof: %v", err)
	}
	if !proof.MatchesPermitActivation(7, 19, 23) {
		t.Fatal("exact permit activation did not match")
	}
	for _, candidate := range []struct {
		slot       uint32
		generation uint64
		revision   uint64
	}{
		{slot: 0, generation: 19, revision: 23},
		{slot: 7, generation: 0, revision: 23},
		{slot: 7, generation: 19, revision: 0},
		{slot: 8, generation: 19, revision: 23},
		{slot: 7, generation: 20, revision: 23},
		{slot: 7, generation: 19, revision: 24},
	} {
		if proof.MatchesPermitActivation(
			candidate.slot,
			candidate.generation,
			candidate.revision,
		) {
			t.Fatalf("mismatched permit activation matched: %+v", candidate)
		}
	}
	if (AuthorityProof{}).MatchesPermitActivation(7, 19, 23) {
		t.Fatal("zero authority proof matched")
	}
}

func validBrokerSpec(t *testing.T, adapter AdapterHandle, adapterSpec AdapterSpec, cfg DockerCLIConfig) BrokerSpec {
	t.Helper()
	relayParent := adapterSpec.BrokerParent
	authorityParent := filepath.Join(cfg.BrokerRoot, "slot-000007", "authority")
	for _, path := range []string{relayParent, authorityParent} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("create broker fixture directory: %v", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatalf("chmod broker fixture directory: %v", err)
		}
	}
	return BrokerSpec{
		Name:              "pghar-broker-000007",
		Image:             "portable-ghar/network-broker-dialer@sha256:" + strings.Repeat("d", 64),
		HelperImage:       "portable-ghar/network-helper@sha256:" + strings.Repeat("f", 64),
		PolicyIPv6Posture: PolicyIPv6DenyViaIP6Tables,
		BuildID:           adapterSpec.BuildID,
		FleetGeneration:   adapterSpec.FleetGeneration,
		SlotIdentity:      adapterSpec.SlotIdentity,
		CapacitySlotID:    7,
		JobGeneration:     19,
		Adapter:           adapter,
		RelayParent:       relayParent,
		AuthorityParent:   authorityParent,
		User:              adapterSpec.User,
		Seccomp:           adapterSpec.Seccomp,
		Limits: BrokerLimits{
			MilliCPU:        500,
			MemoryBytes:     512 << 20,
			MemorySwapBytes: 640 << 20,
			PIDs:            64,
			FileDescriptors: 512,
			StateBytes:      32 << 20,
			ScratchBytes:    64 << 20,
			LogBytes:        1 << 20,
			LogFiles:        2,
		},
		HelperLimits: OneShotLimits{
			MilliCPU:        250,
			MemoryBytes:     128 << 20,
			MemorySwapBytes: 160 << 20,
			PIDs:            16,
			FileDescriptors: 64,
		},
	}
}

func TestBrokerKernelDisabledPostureUsesAndAuditsExactSysctls(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	brokerID := strings.Repeat("e", 64)
	spec := validBrokerSpec(t, AdapterHandle{}, adapterSpec, cfg)
	spec.PolicyIPv6Posture = PolicyIPv6KernelDisabled
	cli := &DockerCLI{cfg: cfg}
	argv := cli.brokerCreateArgv(spec)
	want := map[string]string{
		"net.ipv6.conf.all.disable_ipv6":     "1",
		"net.ipv6.conf.default.disable_ipv6": "1",
	}
	if countArg(argv, "--sysctl") != len(want) {
		t.Fatalf("broker sysctl count = %d, want %d: %q", countArg(argv, "--sysctl"), len(want), argv)
	}
	for name, value := range want {
		requireArgPair(t, argv, "--sysctl", name+"="+value)
	}

	raw := managedBrokerInspectJSON(
		brokerID,
		7000,
		adapterSpec,
		cfg,
		func(document map[string]any) {
			document["HostConfig"].(map[string]any)["Sysctls"] = want
		},
	)
	var documents []adapterInspect
	if err := json.Unmarshal([]byte(raw), &documents); err != nil || len(documents) != 1 {
		t.Fatalf("decode broker inspect fixture: %v", err)
	}
	record := &brokerRecord{
		handle: BrokerHandle{id: brokerID},
		spec:   spec,
	}
	if err := validateBrokerInspect(documents[0], record, cfg.BrokerNetwork); err != nil {
		t.Fatalf("validateBrokerInspect(exact sysctls): %v", err)
	}
	delete(documents[0].HostConfig.Sysctls, "net.ipv6.conf.default.disable_ipv6")
	if err := validateBrokerInspect(documents[0], record, cfg.BrokerNetwork); err == nil {
		t.Fatal("validateBrokerInspect accepted missing kernel-disabled sysctl")
	}
}

func TestCreateNetworkBrokerHeldUsesClosedArgvAndOpaqueHandle(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	brokerID := strings.Repeat("e", 64)
	brokerPID := int64(7000)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte("OK\n")},
		{Stdout: []byte(managedBrokerInspectJSON(brokerID, brokerPID, adapterSpec, cfg, nil))},
		{Stdout: []byte(fmt.Sprintf("%d 1 %s hold\n", brokerPID, brokerEntrypoint))},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)

	handle, err := cli.CreateNetworkBrokerHeld(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkBrokerHeld: %v", err)
	}
	if handle.ID() != brokerID {
		t.Fatalf("broker ID = %q, want %q", handle.ID(), brokerID)
	}
	if len(cli.brokers) != 1 {
		t.Fatalf("broker record count = %d, want 1", len(cli.brokers))
	}
	if len(commands.commands) != 7 {
		t.Fatalf("command count = %d, want 7", len(commands.commands))
	}

	argv := commands.commands[2].argv
	requireArgPair(t, argv, "--network", cfg.BrokerNetwork)
	requireArgPair(t, argv, "--cap-drop", "ALL")
	requireArg(t, argv, "--read-only")
	requireArgPair(t, argv, "--security-opt", "no-new-privileges=true")
	requireArgPair(t, argv, "--security-opt", "seccomp="+spec.Seccomp.Path)
	requireArgPair(t, argv, "--restart", "no")
	requireArgPair(t, argv, "--user", spec.User)
	requireArgPair(t, argv, "--memory", fmt.Sprint(spec.Limits.MemoryBytes))
	requireArgPair(t, argv, "--memory-swap", fmt.Sprint(spec.Limits.MemorySwapBytes))
	requireArgPair(t, argv, "--pids-limit", fmt.Sprint(spec.Limits.PIDs))
	requireArgPair(t, argv, "--ulimit", "nofile=512:512")
	requireArgPair(t, argv, "--mount", "type=bind,src="+spec.RelayParent+",dst="+brokerRelayMountDst)
	requireArgPair(t, argv, "--mount", "type=bind,src="+spec.AuthorityParent+",dst="+brokerAuthorityMountDst+",readonly")
	requireArgPair(t, argv, "--entrypoint", brokerEntrypoint)
	if countArg(argv, "--mount") != 2 {
		t.Fatalf("broker --mount count = %d, want 2", countArg(argv, "--mount"))
	}
	for _, forbidden := range []string{
		"--privileged", "--publish", "--device", "--volume", "--env",
		"--env-file", "--pid", "--ipc", "--uts",
	} {
		if slices.Contains(argv, forbidden) {
			t.Errorf("broker argv contains forbidden flag %q: %q", forbidden, argv)
		}
	}
	if got := commands.commands[3].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "start", brokerID,
	}) {
		t.Fatalf("broker start argv = %q", got)
	}
	if got := commands.commands[4].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "exec", "-i", brokerID, brokerEntrypoint, "arm",
	}) {
		t.Fatalf("broker arm argv = %q", got)
	}
	if len(commands.commands[4].stdin) != brokerArmFrameBytes {
		t.Fatalf("broker arm frame length = %d, want %d", len(commands.commands[4].stdin), brokerArmFrameBytes)
	}
}

func TestCreateNetworkBrokerHeldNeverRemovesForeignNameCollision(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	foreignID := strings.Repeat("d", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{ExitCode: 1},
		{Stdout: []byte(foreignID + "\n")},
		{Stdout: []byte(rejectedCreateInspectJSON(
			foreignID,
			"pghar-broker-000007",
			"runner",
			strings.Repeat("a", 64),
			1,
			"foreign-slot",
		))},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	if _, err := cli.CreateNetworkBrokerHeld(context.Background(), spec); err == nil {
		t.Fatal("CreateNetworkBrokerHeld accepted a failed create")
	}
	for _, command := range commands.commands {
		if slices.Contains(command.argv, "rm") {
			t.Fatalf("foreign name collision was removed: %q", command.argv)
		}
	}
	if len(commands.commands) != 5 {
		t.Fatalf("command count = %d, want 5: %q", len(commands.commands), commands.commands)
	}
}

func TestCreateNetworkBrokerHeldReclaimsOwnedIDAfterMalformedCreateOutput(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	brokerID := strings.Repeat("e", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte("malformed\n")},
		{Stdout: []byte(brokerID + "\n")},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	commands.results = append(commands.results,
		Result{Stdout: []byte(managedRejectedCreateInspectJSON(rejectedCreateIdentity{
			ContainerID:     brokerID,
			Name:            spec.Name,
			Kind:            "network-broker",
			Image:           spec.Image,
			BuildID:         spec.BuildID,
			FleetGeneration: spec.FleetGeneration,
			SlotIdentity:    spec.SlotIdentity,
			Entrypoint:      []string{brokerEntrypoint},
			Cmd:             []string{"hold"},
			NetworkMode:     cfg.BrokerNetwork,
		}))},
		Result{},
		Result{},
		Result{},
	)
	if _, err := cli.CreateNetworkBrokerHeld(context.Background(), spec); err == nil {
		t.Fatal("CreateNetworkBrokerHeld accepted malformed create output")
	}
	if len(commands.commands) != 8 {
		t.Fatalf("command count = %d, want 8: %q", len(commands.commands), commands.commands)
	}
	if got := commands.commands[5].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "rm", "-f", brokerID,
	}) {
		t.Fatalf("broker cleanup argv = %q", got)
	}
}

func TestApplyNetworkPolicyCancellationReclaimsHelperBeforeBroker(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	brokerID := strings.Repeat("e", 64)
	helperID := strings.Repeat("f", 64)
	brokerPID := int64(7000)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte("OK\n")},
		{Stdout: []byte(managedBrokerInspectJSON(brokerID, brokerPID, adapterSpec, cfg, nil))},
		{Stdout: []byte(fmt.Sprintf("%d 1 %s hold\n", brokerPID, brokerEntrypoint))},
		{},
		{Stdout: []byte(helperID + "\n")},
	}}
	commands.errors = make([]error, 14)
	commands.errors[7] = context.Canceled
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	commands.results = append(commands.results,
		Result{Stdout: []byte(managedRejectedCreateInspectJSON(rejectedCreateIdentity{
			ContainerID:     helperID,
			Name:            spec.Name + "-policy",
			Kind:            "network-policy-helper",
			Image:           spec.HelperImage,
			BuildID:         spec.BuildID,
			FleetGeneration: spec.FleetGeneration,
			SlotIdentity:    spec.SlotIdentity,
			Entrypoint:      []string{helperEntrypoint},
			Cmd:             []string{"apply"},
			NetworkMode:     "container:" + brokerID,
		}))},
		Result{},
		Result{},
		Result{},
		Result{},
	)
	handle, err := cli.CreateNetworkBrokerHeld(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkBrokerHeld: %v", err)
	}
	artifact, err := NewPolicyArtifact(
		testPolicyProgram(),
		testPolicyProgram(),
		[]byte("{\"version\":1}\n"),
		PolicyIPv6DenyViaIP6Tables,
	)
	if err != nil {
		t.Fatalf("NewPolicyArtifact: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cli.ApplyNetworkPolicy(ctx, handle, artifact); err == nil {
		t.Fatal("ApplyNetworkPolicy accepted a cancelled helper")
	}
	if slices.Contains(commands.commands[7].argv, "--rm") {
		t.Fatalf("policy helper still relies on implicit --rm: %q", commands.commands[7].argv)
	}
	if got := commands.commands[10].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "rm", "-f", helperID,
	}) {
		t.Fatalf("helper cleanup argv = %q", got)
	}
	if got := commands.commands[13].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "rm", "-f", brokerID,
	}) {
		t.Fatalf("broker cleanup argv = %q", got)
	}
	for _, call := range commands.contexts[8:13] {
		if call.canceled || !call.hasDeadline {
			t.Fatalf("helper cleanup context = %+v", call)
		}
	}
}

func TestCreateNetworkBrokerHeldCleansPartialStartAndRetainsOnlyRetryableTombstone(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	brokerID := strings.Repeat("e", 64)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(brokerID + "\n")},
		{ExitCode: 1},
		{ExitCode: 1},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)

	handle, err := cli.CreateNetworkBrokerHeld(context.Background(), spec)
	if err == nil {
		t.Fatal("CreateNetworkBrokerHeld accepted a failed start")
	}
	if handle.ID() != brokerID {
		t.Fatalf("partial broker handle ID = %q, want %q", handle.ID(), brokerID)
	}
	record := cli.brokers[handle.nonce]
	if record == nil || !record.destroyed || record.busy {
		t.Fatalf("partial broker tombstone = %+v", record)
	}
	if err := cli.RemoveNetworkBroker(context.Background(), handle); err != nil {
		t.Fatalf("RemoveNetworkBroker retry: %v", err)
	}
	if len(cli.brokers) != 0 {
		t.Fatalf("broker records after retry = %d, want 0", len(cli.brokers))
	}
}

func TestPolicyArtifactIsCanonicalAndCallerCannotSupplyDigest(t *testing.T) {
	ipv4 := testPolicyProgram()
	ipv6 := testPolicyProgram()
	runtimePolicy := []byte("{\"version\":1}\n")
	artifact, err := NewPolicyArtifact(
		ipv4,
		ipv6,
		runtimePolicy,
		PolicyIPv6DenyViaIP6Tables,
	)
	if err != nil {
		t.Fatalf("NewPolicyArtifact: %v", err)
	}
	if artifact.Digest() == "" || len(artifact.Digest()) != 64 {
		t.Fatalf("artifact digest = %q", artifact.Digest())
	}
	expectedIPv4 := slices.Clone(ipv4)
	ipv4[1] = 'X'
	payload, err := encodePolicyArtifact(artifact)
	if err != nil {
		t.Fatalf("encodePolicyArtifact: %v", err)
	}
	if strings.Contains(string(payload), "*Xilter") {
		t.Fatal("policy artifact retained caller-owned mutable bytes")
	}
	if _, err := NewPolicyArtifact(
		ipv4,
		nil,
		runtimePolicy,
		PolicyIPv6DenyViaIP6Tables,
	); err == nil {
		t.Fatal("dual-stack policy accepted an empty IPv6 program")
	}
	if _, err := NewPolicyArtifact(
		ipv4,
		ipv6,
		runtimePolicy,
		PolicyIPv6KernelDisabled,
	); err == nil {
		t.Fatal("kernel-disabled policy accepted an IPv6 program")
	}

	decoded, err := DecodePolicyArtifact(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("DecodePolicyArtifact: %v", err)
	}
	if !decoded.Valid() || decoded.Digest() != artifact.Digest() ||
		!bytes.Equal(decoded.IPv4Program(), expectedIPv4) ||
		!bytes.Equal(decoded.IPv6Program(), ipv6) ||
		!bytes.Equal(decoded.RuntimePolicy(), runtimePolicy) ||
		decoded.IPv6Posture() != PolicyIPv6DenyViaIP6Tables {
		t.Fatal("decoded policy artifact did not preserve canonical identity")
	}
	corrupt := slices.Clone(payload)
	corrupt[policyFrameHeaderBytes] ^= 1
	if _, err := DecodePolicyArtifact(bytes.NewReader(corrupt)); err == nil {
		t.Fatal("DecodePolicyArtifact accepted a corrupt digest")
	}
	if _, err := DecodePolicyArtifact(bytes.NewReader(
		append(slices.Clone(payload), 0),
	)); err == nil {
		t.Fatal("DecodePolicyArtifact accepted trailing bytes")
	}
}

func TestBrokerPolicyAuthorityReleaseAndAuditAreExactlyOrdered(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	brokerID := strings.Repeat("e", 64)
	helperID := strings.Repeat("f", 64)
	brokerPID := int64(7000)
	parserPID := uint32(7001)
	artifact, err := NewPolicyArtifact(
		testPolicyProgram(),
		testPolicyProgram(),
		[]byte("{\"version\":1}\n"),
		PolicyIPv6DenyViaIP6Tables,
	)
	if err != nil {
		t.Fatalf("NewPolicyArtifact: %v", err)
	}
	authorityBinding := AuthorityBinding{
		Version:        1,
		CapacitySlotID: 7,
		JobGeneration:  19,
		LedgerRevision: 23,
		Directory: DirectoryIdentity{
			Device: 201, Inode: 202, UID: 65532, GID: 65532, Mode: 0o700,
		},
		Socket: SocketIdentity{
			Name: dialAuthoritySocketName, Device: 201, Inode: 203,
			UID: 65532, GID: 65532, Mode: 0o600,
		},
		Peer: ProcessIdentity{PID: 7100, StartTime: 7101},
	}
	authority, err := NewAuthorityProof(authorityBinding)
	if err != nil {
		t.Fatalf("NewAuthorityProof: %v", err)
	}
	readiness := brokerReadinessWire{
		Version:           1,
		ReleaseGeneration: 1,
		PolicyDigest:      artifact.Digest(),
		PolicyIPv6Posture: "deny-via-ip6tables",
		NamespaceOwner:    ProcessIdentity{PID: uint32(brokerPID), StartTime: 8000},
		Parser: childProcessIdentity{
			PID: parserPID, PPID: uint32(brokerPID), StartTime: 8001,
		},
		RelayDirectory: DirectoryIdentity{
			Device: 101, Inode: 102, UID: 65532, GID: 65532, Mode: 0o700,
		},
		RelaySocket: SocketIdentity{
			Name: "https.sock", Device: 101, Inode: 103,
			UID: 65532, GID: 65532, Mode: 0o600,
		},
		Control:             controlSocketIdentity{Device: 301, DialerInode: 302, ParserInode: 303},
		AuthorityDirectory:  authorityBinding.Directory,
		AuthoritySocket:     authorityBinding.Socket,
		AuthorityPeer:       authorityBinding.Peer,
		ParserControlFD:     parserControlFD,
		FilterVersion:       parserFilterVersion,
		FilterTSYNC:         true,
		AFINETErrno:         parserSocketErrno,
		AFINET6Errno:        parserSocketErrno,
		ParserTaskCount:     4,
		ParserTasksVerified: 4,
	}
	readinessBytes, err := encodeBrokerReadiness(readiness)
	if err != nil {
		t.Fatalf("encodeBrokerReadiness: %v", err)
	}
	policyBytes := canonicalJSONLine(t, policyApplicationWire{
		Version:      2,
		Digest:       artifact.Digest(),
		IPv6Posture:  "deny-via-ip6tables",
		Capabilities: helperNetAdminCapabilityWire(),
	})
	socketBytes := canonicalJSONLine(t, heldSocketAuditWire{Version: 1})
	authorityBytes := canonicalJSONLine(t, authorityFilesystemWire{
		Version:   1,
		Directory: authorityBinding.Directory,
		Socket:    authorityBinding.Socket,
	})
	heldTop := []byte(fmt.Sprintf("%d 1 %s hold\n", brokerPID, brokerEntrypoint))
	releasedTop := []byte(fmt.Sprintf(
		"%d 1 %s hold\n%d %d %s serve\n",
		brokerPID, brokerEntrypoint,
		parserPID, brokerPID, brokerParserEntrypoint,
	))
	inspect := []byte(managedBrokerInspectJSON(brokerID, brokerPID, adapterSpec, cfg, nil))
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte("OK\n")},
		{Stdout: slices.Clone(inspect)},
		{Stdout: heldTop},
		{Stdout: policyBytes},
		{Stdout: []byte(helperID + "\n")},
		{Stdout: []byte(managedRejectedCreateInspectJSON(rejectedCreateIdentity{
			ContainerID:     helperID,
			Name:            "pghar-broker-000007-policy",
			Kind:            "network-policy-helper",
			Image:           "portable-ghar/network-helper@sha256:" + strings.Repeat("f", 64),
			BuildID:         adapterSpec.BuildID,
			FleetGeneration: adapterSpec.FleetGeneration,
			SlotIdentity:    adapterSpec.SlotIdentity,
			Entrypoint:      []string{helperEntrypoint},
			Cmd:             []string{"apply"},
			NetworkMode:     "container:" + brokerID,
		}))},
		{},
		{},
		{},
		{Stdout: slices.Clone(inspect)},
		{Stdout: heldTop},
		{Stdout: authorityBytes},
		{Stdout: slices.Clone(inspect)},
		{Stdout: heldTop},
		{Stdout: slices.Clone(inspect)},
		{Stdout: heldTop},
		{Stdout: socketBytes},
		{Stdout: slices.Clone(inspect)},
		{Stdout: heldTop},
		{Stdout: readinessBytes},
		{Stdout: slices.Clone(inspect)},
		{Stdout: readinessBytes},
		{Stdout: releasedTop},
		{Stdout: slices.Clone(inspect)},
		{Stdout: readinessBytes},
		{Stdout: releasedTop},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	handle, err := cli.CreateNetworkBrokerHeld(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkBrokerHeld: %v", err)
	}
	if err := cli.ApplyNetworkPolicy(context.Background(), handle, artifact); err != nil {
		t.Fatalf("ApplyNetworkPolicy: %v", err)
	}
	helperArgv := commands.commands[7].argv
	requireArgPair(t, helperArgv, "--network", "container:"+brokerID)
	requireArgPair(t, helperArgv, "--cap-drop", "ALL")
	requireArgPair(t, helperArgv, "--cap-add", "NET_ADMIN")
	requireArgPair(t, helperArgv, "--user", "0:0")
	requireArgPair(t, helperArgv, "--env", "XTABLES_LOCKFILE=/run/xtables.lock")
	requireArgPair(t, helperArgv, "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=65536,uid=0,gid=0,mode=0700")
	requireArgPair(t, helperArgv, "--memory-swap", fmt.Sprint(spec.HelperLimits.MemorySwapBytes))
	requireArgPair(t, helperArgv, "--log-driver", "none")
	if slices.Contains(helperArgv, "--rm") {
		t.Fatalf("policy helper still relies on implicit --rm: %q", helperArgv)
	}
	if countArg(helperArgv, "--env") != 1 {
		t.Fatalf("policy helper env count = %d, want 1", countArg(helperArgv, "--env"))
	}
	for _, forbidden := range []string{"--privileged", "--device", "--volume", "--publish"} {
		if slices.Contains(helperArgv, forbidden) {
			t.Errorf("policy helper argv contains forbidden flag %q: %q", forbidden, helperArgv)
		}
	}
	if err := cli.BindDialAuthority(context.Background(), handle, authority); err != nil {
		t.Fatalf("BindDialAuthority: %v", err)
	}
	peer, err := cli.ReleaseNetworkBroker(context.Background(), handle)
	if err != nil {
		t.Fatalf("ReleaseNetworkBroker: %v", err)
	}
	if !validBrokerPeerProof(peer, adapter, cli.issuer, adapterSpec) {
		t.Fatal("ReleaseNetworkBroker returned an invalid peer proof")
	}
	if !isLowerHex64(peer.HeldSocketZeroDigest()) {
		t.Fatalf(
			"held socket zero digest=%q",
			peer.HeldSocketZeroDigest(),
		)
	}
	audit, err := cli.AuditNetworkBroker(context.Background(), handle)
	if err != nil {
		t.Fatalf("AuditNetworkBroker: %v", err)
	}
	if audit.Digest() == strings.Repeat("0", 64) || len(audit.Digest()) != 64 {
		t.Fatalf("broker audit digest = %q", audit.Digest())
	}
	if _, err := cli.ReleaseNetworkBroker(context.Background(), handle); err == nil {
		t.Fatal("ReleaseNetworkBroker accepted a second release")
	}
	if len(cli.brokers) != 0 {
		t.Fatalf("broker record count after duplicate release = %d, want 0", len(cli.brokers))
	}
	if len(commands.commands) != len(commands.results) {
		t.Fatalf("commands executed = %d, scripted = %d", len(commands.commands), len(commands.results))
	}
	if got := commands.commands[20].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "exec", brokerID, brokerEntrypoint, "socket-audit",
	}) {
		t.Fatalf("socket audit argv = %q", got)
	}
	if got := commands.commands[23].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "exec", "-i", brokerID, brokerEntrypoint, "release",
	}) {
		t.Fatalf("release argv = %q", got)
	}
	releaseInput := commands.commands[23].stdin
	if len(releaseInput) <= brokerReleasePrefix+releaseTokenBytes ||
		!strings.HasPrefix(string(releaseInput[:8]), "PGHBRREL") {
		t.Fatalf("release frame invalid: length=%d", len(releaseInput))
	}
	releaseCommand, err := DecodeBrokerReleaseCommand(bytes.NewReader(releaseInput))
	if err != nil {
		t.Fatalf("DecodeBrokerReleaseCommand: %v", err)
	}
	defer releaseCommand.Destroy()
	wantRuntimeDigest := sha256.Sum256(artifact.RuntimePolicy())
	if releaseCommand.RuntimePolicyDigest() != wantRuntimeDigest {
		t.Fatal("release frame did not bind the exact runtime policy digest")
	}
	joinedArgv := make([]string, 0)
	for _, command := range commands.commands {
		joinedArgv = append(joinedArgv, command.argv...)
	}
	if strings.Contains(strings.Join(joinedArgv, "\x00"), artifact.Digest()) {
		t.Fatal("policy digest leaked into Docker argv")
	}
}

func testPolicyProgram() []byte {
	return []byte(
		"*filter\n" +
			":INPUT DROP [0:0]\n" +
			":FORWARD DROP [0:0]\n" +
			":OUTPUT DROP [0:0]\n" +
			"-A INPUT -i lo -j ACCEPT\n" +
			"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
			"-A OUTPUT -o lo -j ACCEPT\n" +
			"-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
			"COMMIT\n",
	)
}

func TestPolicyArtifactRejectsFailOpenOrNoncanonicalRestorePrograms(t *testing.T) {
	runtimePolicy := []byte("{\"version\":1}\n")
	for name, program := range map[string][]byte{
		"default accept": []byte(
			"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n" +
				":OUTPUT ACCEPT [0:0]\nCOMMIT\n",
		),
		"unconditional accept": []byte(
			"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n" +
				":OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n" +
				"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
				"-A OUTPUT -o lo -j ACCEPT\n" +
				"-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
				"-A OUTPUT -j ACCEPT\nCOMMIT\n",
		),
		"deny after allow": []byte(
			"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n" +
				":OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n" +
				"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
				"-A OUTPUT -o lo -j ACCEPT\n" +
				"-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
				"-A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT\n" +
				"-A OUTPUT -m conntrack --ctstate INVALID -j DROP\nCOMMIT\n",
		),
		"missing established": []byte(
			"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n" +
				":OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n" +
				"-A OUTPUT -o lo -j ACCEPT\nCOMMIT\n",
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPolicyArtifact(
				program,
				testPolicyProgram(),
				runtimePolicy,
				PolicyIPv6DenyViaIP6Tables,
			); err == nil {
				t.Fatal("NewPolicyArtifact accepted a fail-open program")
			}
		})
	}
}

func TestBrokerMutatingOperationOutOfOrderIsTerminalAndCleanupFirst(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	brokerID := strings.Repeat("e", 64)
	brokerPID := int64(7000)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte(brokerID + "\n")},
		{Stdout: []byte("OK\n")},
		{Stdout: []byte(managedBrokerInspectJSON(brokerID, brokerPID, adapterSpec, cfg, nil))},
		{Stdout: []byte(fmt.Sprintf("%d 1 %s hold\n", brokerPID, brokerEntrypoint))},
		{},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	handle, err := cli.CreateNetworkBrokerHeld(context.Background(), spec)
	if err != nil {
		t.Fatalf("CreateNetworkBrokerHeld: %v", err)
	}
	if _, err := cli.ReleaseNetworkBroker(context.Background(), handle); err == nil {
		t.Fatal("ReleaseNetworkBroker accepted a missing policy/authority")
	}
	if len(cli.brokers) != 0 {
		t.Fatalf("terminal out-of-order broker record count = %d, want 0", len(cli.brokers))
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Equal(got, []string{
		cfg.DockerPath, "rm", "-f", brokerID,
	}) {
		t.Fatalf("terminal cleanup argv = %q", got)
	}
}

func TestCreateNetworkBrokerHeldRejectsEveryReadbackDriftAndCleans(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{"network", `"NetworkMode":"pghar-egress"`, `"NetworkMode":"bridge"`},
		{"cap add", `"CapAdd":[]`, `"CapAdd":["NET_ADMIN"]`},
		{"readonly root", `"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`},
		{"memory swap", `"MemorySwap":671088640`, `"MemorySwap":671088639`},
		{"restart", `"Name":"no"`, `"Name":"always"`},
		{"relay writable", `"Destination":"/run/portable-ghar/relay","Mode":"","Propagation":"rprivate","RW":true`, `"Destination":"/run/portable-ghar/relay","Mode":"ro","Propagation":"rprivate","RW":false`},
		{"authority readonly", `"Destination":"/run/portable-ghar/authority","Mode":"ro","Propagation":"rprivate","RW":false`, `"Destination":"/run/portable-ghar/authority","Mode":"","Propagation":"rprivate","RW":true`},
		{"running", `"Running":true`, `"Running":false`},
		{"owner pid", `"Pid":7000`, `"Pid":0`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapterSpec, cfg := validAdapterSpec(t)
			cfg.BrokerNetwork = "pghar-egress"
			adapterID := strings.Repeat("c", 64)
			brokerID := strings.Repeat("e", 64)
			inspect := managedBrokerInspectJSON(brokerID, 7000, adapterSpec, cfg, nil)
			drifted := strings.Replace(inspect, tt.old, tt.new, 1)
			if drifted == inspect {
				t.Fatalf("fixture mutation %q did not match", tt.name)
			}
			commands := &scriptedCommandRunner{results: []Result{
				{Stdout: []byte(adapterID + "\n")},
				{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
				{Stdout: []byte(brokerID + "\n")},
				{Stdout: []byte(brokerID + "\n")},
				{Stdout: []byte("OK\n")},
				{Stdout: []byte(drifted)},
				{},
			}}
			cli, err := NewDockerCLI(cfg, commands)
			if err != nil {
				t.Fatalf("NewDockerCLI: %v", err)
			}
			adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
			if err != nil {
				t.Fatalf("CreateNetworkAdapter: %v", err)
			}
			spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
			handle, err := cli.CreateNetworkBrokerHeld(context.Background(), spec)
			if err == nil {
				t.Fatal("CreateNetworkBrokerHeld accepted drifted readback")
			}
			if handle.ID() != brokerID {
				t.Fatalf("partial handle ID = %q, want %q", handle.ID(), brokerID)
			}
			if strings.Contains(err.Error(), brokerID) ||
				strings.Contains(err.Error(), spec.RelayParent) {
				t.Fatalf("closed error leaked identity: %v", err)
			}
			if len(cli.brokers) != 0 {
				t.Fatalf("broker record count = %d, want 0", len(cli.brokers))
			}
		})
	}
}

func TestCreateNetworkBrokerHeldRejectsAtBoundedRecordCapacityBeforeEffect(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{{Stdout: []byte(adapterID + "\n")}}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	for index := 0; index < maxBrokerRecords; index++ {
		var key [32]byte
		key[0] = byte(index)
		key[1] = byte(index >> 8)
		cli.brokers[key] = nil
	}
	if _, err := cli.CreateNetworkBrokerHeld(context.Background(), spec); err == nil {
		t.Fatal("CreateNetworkBrokerHeld accepted full broker record map")
	}
	if len(commands.commands) != 1 {
		t.Fatalf("command count = %d, want adapter create only", len(commands.commands))
	}
}

func TestBrokerReservationClosesConcurrentDuplicateAndCapacityWindow(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	commands := &scriptedCommandRunner{results: []Result{{Stdout: []byte(adapterID + "\n")}}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	spec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	var first [32]byte
	var second [32]byte
	first[0] = 1
	second[0] = 2
	if err := cli.reserveBrokerRecordSlot(spec, first); err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	if err := cli.reserveBrokerRecordSlot(spec, second); err == nil {
		t.Fatal("duplicate broker reservation succeeded")
	}
	if len(cli.brokerReservations) != 1 {
		t.Fatalf("broker reservation count = %d, want 1", len(cli.brokerReservations))
	}
	cli.releaseBrokerReservation(first)
	if len(cli.brokerReservations) != 0 {
		t.Fatalf("broker reservation count after release = %d, want 0", len(cli.brokerReservations))
	}
}

func canonicalJSONLine(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return append(document, '\n')
}

func managedBrokerInspectJSON(
	id string,
	pid int64,
	adapterSpec AdapterSpec,
	cfg DockerCLIConfig,
	override func(map[string]any),
) string {
	spec := BrokerSpec{
		Name:              "pghar-broker-000007",
		Image:             "portable-ghar/network-broker-dialer@sha256:" + strings.Repeat("d", 64),
		HelperImage:       "portable-ghar/network-helper@sha256:" + strings.Repeat("f", 64),
		PolicyIPv6Posture: PolicyIPv6DenyViaIP6Tables,
		BuildID:           adapterSpec.BuildID,
		FleetGeneration:   adapterSpec.FleetGeneration,
		SlotIdentity:      adapterSpec.SlotIdentity,
		CapacitySlotID:    7,
		JobGeneration:     19,
		RelayParent:       adapterSpec.BrokerParent,
		AuthorityParent:   filepath.Join(cfg.BrokerRoot, "slot-000007", "authority"),
		User:              adapterSpec.User,
		Seccomp:           adapterSpec.Seccomp,
		Limits: BrokerLimits{
			MilliCPU:        500,
			MemoryBytes:     512 << 20,
			MemorySwapBytes: 640 << 20,
			PIDs:            64,
			FileDescriptors: 512,
			StateBytes:      32 << 20,
			ScratchBytes:    64 << 20,
			LogBytes:        1 << 20,
			LogFiles:        2,
		},
	}
	document := map[string]any{
		"Id": id,
		"Config": map[string]any{
			"Image": spec.Image,
			"Labels": map[string]string{
				"io.portable-ghar.managed":          "true",
				"io.portable-ghar.kind":             "network-broker",
				"io.portable-ghar.build-id":         spec.BuildID,
				"io.portable-ghar.fleet-generation": fmt.Sprint(spec.FleetGeneration),
				"io.portable-ghar.slot":             spec.SlotIdentity,
			},
			"Env":        []string{},
			"Entrypoint": []string{brokerEntrypoint},
			"Cmd":        []string{"hold"},
			"User":       spec.User,
		},
		"State": map[string]any{
			"Running": true, "Restarting": false, "Dead": false, "Pid": pid, "ExitCode": 0,
		},
		"HostConfig": map[string]any{
			"NetworkMode":     cfg.BrokerNetwork,
			"Sysctls":         map[string]string{},
			"ReadonlyRootfs":  true,
			"CapAdd":          []string{},
			"CapDrop":         []string{"ALL"},
			"SecurityOpt":     []string{"no-new-privileges=true", "seccomp=" + spec.Seccomp.Path},
			"Binds":           []string{},
			"Devices":         []any{},
			"Privileged":      false,
			"PortBindings":    map[string]any{},
			"PublishAllPorts": false,
			"PidMode":         "",
			"IpcMode":         "",
			"UTSMode":         "",
			"Tmpfs":           brokerTmpfs(spec),
			"Memory":          int64(spec.Limits.MemoryBytes),
			"MemorySwap":      int64(spec.Limits.MemorySwapBytes),
			"NanoCpus":        int64(spec.Limits.MilliCPU) * 1_000_000,
			"PidsLimit":       int64(spec.Limits.PIDs),
			"Ulimits": []map[string]any{{
				"Name": "nofile", "Soft": int64(spec.Limits.FileDescriptors), "Hard": int64(spec.Limits.FileDescriptors),
			}},
			"LogConfig": map[string]any{
				"Type": "local",
				"Config": map[string]string{
					"max-size": fmt.Sprint(spec.Limits.LogBytes) + "b",
					"max-file": fmt.Sprint(spec.Limits.LogFiles),
				},
			},
			"RestartPolicy": map[string]any{"Name": "no"},
		},
		"Mounts": []map[string]any{
			{
				"Type": "bind", "Source": spec.RelayParent,
				"Destination": brokerRelayMountDst, "Mode": "", "RW": true, "Propagation": "rprivate",
			},
			{
				"Type": "bind", "Source": spec.AuthorityParent,
				"Destination": brokerAuthorityMountDst, "Mode": "ro", "RW": false, "Propagation": "rprivate",
			},
		},
	}
	if override != nil {
		override(document)
	}
	encoded, err := json.Marshal([]map[string]any{document})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
