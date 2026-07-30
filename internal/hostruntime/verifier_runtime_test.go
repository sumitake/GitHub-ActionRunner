package hostruntime

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
)

func validVerifierSpec(adapter AdapterHandle, spec AdapterSpec) VerifierSpec {
	return VerifierSpec{
		Image:           "portable-ghar/network-verifier@sha256:" + strings.Repeat("9", 64),
		BuildID:         spec.BuildID,
		FleetGeneration: spec.FleetGeneration,
		SlotIdentity:    spec.SlotIdentity,
		Adapter:         adapter,
		User:            spec.User,
		Seccomp:         spec.Seccomp,
		Limits: OneShotLimits{
			MilliCPU:        250,
			MemoryBytes:     128 << 20,
			MemorySwapBytes: 160 << 20,
			PIDs:            16,
			FileDescriptors: 64,
		},
	}
}

func TestVerifyNetworkAdapterEmptyUsesClosedOneShotVerifier(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	namespace := NetworkNamespaceIdentity{Device: 11, Inode: 12}
	reportWire := verifierNamespaceWire{
		Version:      2,
		Capabilities: emptyVerifierCapabilities(),
	}
	reportWire.Namespace.Identity = namespace
	reportWire.Namespace.LoopbackOnly = true
	reportWire.Namespace.TablesEmpty = true
	reportWire.Namespace.ConntrackEmpty = true
	report := canonicalJSONLine(t, reportWire)
	inspect := managedAdapterInspectJSON(adapterID, adapterSpec)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(inspect)},
		{Stdout: report},
		{},
		{Stdout: []byte(inspect)},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	verifier := validVerifierSpec(adapter, adapterSpec)

	evidence, err := cli.VerifyNetworkAdapterEmpty(
		context.Background(),
		adapter,
		verifier,
	)
	if err != nil {
		t.Fatalf("VerifyNetworkAdapterEmpty: %v", err)
	}
	if evidence.AdapterID() != adapterID ||
		evidence.Namespace() != namespace ||
		len(evidence.Digest()) != 64 {
		t.Fatalf(
			"evidence adapter=%q namespace=%+v digest=%q",
			evidence.AdapterID(),
			evidence.Namespace(),
			evidence.Digest(),
		)
	}
	argv := commands.commands[2].argv
	requireArgPair(t, argv, "--network", "container:"+adapterID)
	requireArgPair(t, argv, "--cap-drop", "ALL")
	requireArg(t, argv, "--read-only")
	requireArgPair(t, argv, "--security-opt", "no-new-privileges=true")
	requireArgPair(t, argv, "--security-opt", "seccomp="+verifier.Seccomp.Path)
	requireArgPair(t, argv, "--user", verifier.User)
	requireArgPair(t, argv, "--memory-swap", fmt.Sprint(verifier.Limits.MemorySwapBytes))
	requireArgPair(t, argv, "--log-driver", "none")
	requireArgPair(t, argv, "--entrypoint", verifierEntrypoint)
	if !slices.Equal(argv[len(argv)-2:], []string{
		verifier.Image,
		"namespace-empty",
	}) {
		t.Fatalf("verifier tail=%q", argv[len(argv)-2:])
	}
	for _, forbidden := range []string{
		"--cap-add", "--privileged", "--mount", "--volume", "--env",
		"--device", "--publish", "--pid", "--ipc", "--uts",
	} {
		if slices.Contains(argv, forbidden) {
			t.Errorf("verifier argv contains forbidden flag %q: %q", forbidden, argv)
		}
	}
}

func TestVerifyNetworkAdapterEmptyRemovesAmbiguousLingeringVerifier(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	namespace := NetworkNamespaceIdentity{Device: 11, Inode: 12}
	reportWire := verifierNamespaceWire{
		Version:      2,
		Capabilities: emptyVerifierCapabilities(),
	}
	reportWire.Namespace.Identity = namespace
	reportWire.Namespace.LoopbackOnly = true
	reportWire.Namespace.TablesEmpty = true
	reportWire.Namespace.ConntrackEmpty = true
	report := canonicalJSONLine(t, reportWire)
	inspect := managedAdapterInspectJSON(adapterID, adapterSpec)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(inspect)},
		{Stdout: report},
		{Stdout: []byte("lingering-verifier-id\n")},
		{Stdout: []byte("lingering-verifier-id\n")},
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
	verifier := validVerifierSpec(adapter, adapterSpec)

	if _, err := cli.VerifyNetworkAdapterEmpty(
		context.Background(),
		adapter,
		verifier,
	); err == nil {
		t.Fatal("VerifyNetworkAdapterEmpty accepted ambiguous verifier lifetime")
	}
	name := verifierContainerName(adapter.nonce, "namespace-empty")
	if got := commands.commands[4].argv; !slices.Equal(
		got,
		[]string{cfg.DockerPath, "rm", "-f", name},
	) {
		t.Fatalf("cleanup argv=%q", got)
	}
	if got := commands.commands[5].argv; !slices.Equal(
		got,
		[]string{
			cfg.DockerPath, "ps", "-a",
			"--filter", "name=^/" + name + "$",
			"--format", "{{.ID}}",
		},
	) {
		t.Fatalf("post-cleanup absence argv=%q", got)
	}
}

func TestVerifyNetworkEgressBindsBothNamespacesParserAndPolicy(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	cfg.BrokerNetwork = "pghar-egress"
	adapterID := strings.Repeat("c", 64)
	brokerID := strings.Repeat("e", 64)
	var adapterNonce, brokerNonce [32]byte
	adapterNonce[0] = 1
	brokerNonce[0] = 2

	commands := &scriptedCommandRunner{}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter := newAdapterHandle(
		adapterID,
		adapterSpec.Image,
		adapterSpec.BuildID,
		adapterSpec.SlotIdentity,
		adapterSpec.FleetGeneration,
		cli.issuer,
		adapterNonce,
	)
	adapterSpec.BrokerParent = validBrokerParent(t, cfg.BrokerRoot)
	cli.adapters[adapterNonce] = &adapterRecord{
		handle: adapter,
		spec:   adapterSpec,
		bound:  true,
	}
	brokerSpec := validBrokerSpec(t, adapter, adapterSpec, cfg)
	broker := newBrokerHandle(
		brokerID,
		brokerSpec.BuildID,
		brokerSpec.SlotIdentity,
		brokerSpec.FleetGeneration,
		adapterNonce,
		cli.issuer,
		brokerNonce,
	)
	graphDigest := strings.Repeat("a", 64)
	runtimePolicy := []byte(
		`{"version":1,"policy_digest":"` + graphDigest +
			`","egress_backend":"restricted-broker-v1"}` + "\n",
	)
	artifact, err := NewPolicyArtifact(
		testPolicyProgram(),
		testPolicyProgram(),
		runtimePolicy,
		PolicyIPv6DenyViaIP6Tables,
	)
	if err != nil {
		t.Fatalf("NewPolicyArtifact: %v", err)
	}
	readiness := validVerifierBrokerReadiness(artifact, 7000, 7001)
	cli.brokers[brokerNonce] = &brokerRecord{
		handle:        broker,
		spec:          brokerSpec,
		phase:         brokerPhaseReleased,
		policyDigest:  artifact.digest,
		policyPosture: artifact.posture,
		readiness:     readiness,
	}
	adapterInspect := managedAdapterInspectJSON(adapterID, adapterSpec)
	brokerInspect := managedBrokerInspectJSON(
		brokerID,
		7000,
		adapterSpec,
		cfg,
		nil,
	)
	proxyReport := canonicalJSONLine(t, verifierProxyWire{
		Version:              2,
		Capabilities:         emptyVerifierCapabilities(),
		PolicyDigest:         graphDigest,
		EgressBackend:        "restricted-broker-v1",
		RunnerNetNSID:        NetworkNamespaceIdentity{Device: 11, Inode: 12},
		RunnerLoopbackOnly:   true,
		RunnerTablesEmpty:    true,
		RunnerConntrackEmpty: true,
		PositiveOK:           true,
		NegativeOK:           true,
	})
	brokerNamespace := canonicalJSONLine(t, verifierIdentityWire{
		Version:      2,
		Capabilities: emptyVerifierCapabilities(),
		Identity:     NetworkNamespaceIdentity{Device: 21, Inode: 22},
	})
	commands.results = []Result{
		{Stdout: []byte(adapterInspect)},
		{Stdout: []byte(brokerInspect)},
		{Stdout: proxyReport},
		{},
		{Stdout: brokerNamespace},
		{},
		{Stdout: []byte(adapterInspect)},
		{Stdout: []byte(brokerInspect)},
	}
	verifier := validVerifierSpec(adapter, adapterSpec)

	evidence, err := cli.VerifyNetworkEgress(
		context.Background(),
		adapter,
		broker,
		artifact,
		verifier,
	)
	if err != nil {
		t.Fatalf("VerifyNetworkEgress: %v", err)
	}
	report := evidence.Report()
	if evidence.AdapterID() != adapterID ||
		evidence.BrokerID() != brokerID ||
		evidence.PolicyArtifactDigest() != artifact.Digest() ||
		report.PolicyDigest != graphDigest ||
		report.RunnerNetNSID != (NetworkNamespaceIdentity{Device: 11, Inode: 12}) ||
		report.BrokerNetNSID != (NetworkNamespaceIdentity{Device: 21, Inode: 22}) ||
		!report.ParserHasNoSocket ||
		!report.PositiveOK ||
		!report.NegativeOK ||
		len(evidence.Digest()) != 64 {
		t.Fatalf("evidence=%+v report=%+v", evidence, report)
	}
	if got := commands.commands[2].stdin; !slices.Equal(got, runtimePolicy) {
		t.Fatalf("probe stdin=%q want=%q", got, runtimePolicy)
	}
	if got := commands.commands[2].argv; !slices.Equal(
		got[len(got)-2:],
		[]string{verifier.Image, "probe"},
	) {
		t.Fatalf("probe argv tail=%q", got[len(got)-2:])
	}
	if got := commands.commands[4].argv; !slices.Equal(
		got[len(got)-2:],
		[]string{verifier.Image, "namespace-id"},
	) {
		t.Fatalf("broker namespace argv tail=%q", got[len(got)-2:])
	}
	requireArgPair(
		t,
		commands.commands[4].argv,
		"--network",
		"container:"+brokerID,
	)
}

func TestVerifierParsersRequireClosedEmptyCapabilityWire(t *testing.T) {
	namespace := verifierNamespaceWire{
		Version:      2,
		Capabilities: emptyVerifierCapabilities(),
	}
	namespace.Namespace.Identity = NetworkNamespaceIdentity{Device: 11, Inode: 12}
	namespace.Namespace.LoopbackOnly = true
	namespace.Namespace.TablesEmpty = true
	namespace.Namespace.ConntrackEmpty = true
	if _, err := parseVerifierNamespace(
		canonicalJSONLine(t, namespace),
	); err != nil {
		t.Fatalf("parseVerifierNamespace(valid): %v", err)
	}

	for name, mutate := range map[string]func(*verifierNamespaceWire){
		"old version": func(wire *verifierNamespaceWire) {
			wire.Version = 1
		},
		"nonempty effective": func(wire *verifierNamespaceWire) {
			wire.Capabilities.Effective = "0000000000001000"
		},
		"missing mask": func(wire *verifierNamespaceWire) {
			wire.Capabilities.Ambient = ""
		},
		"mixed case": func(wire *verifierNamespaceWire) {
			wire.Capabilities.Bounding = "000000000000000A"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := namespace
			mutate(&candidate)
			if _, err := parseVerifierNamespace(
				canonicalJSONLine(t, candidate),
			); err == nil {
				t.Fatal("parseVerifierNamespace accepted invalid capability proof")
			}
		})
	}
}

func validBrokerParent(t *testing.T, root string) string {
	t.Helper()
	return strings.TrimSuffix(root, "/") + "/slot-000007/broker"
}

func TestParseVerifierFloodRequiresExactCompletedPostFloodProof(t *testing.T) {
	wire := verifierFloodWire{
		Version:        2,
		Attempts:       7,
		Completed:      true,
		Capabilities:   emptyVerifierCapabilities(),
		RoutesComplete: true,
	}
	wire.Namespace.Identity = NetworkNamespaceIdentity{Device: 51, Inode: 52}
	wire.Namespace.LoopbackOnly = true
	wire.Namespace.TablesEmpty = true
	wire.Namespace.ConntrackEmpty = true
	report, err := parseVerifierFlood(canonicalJSONLine(t, wire), 7)
	if err != nil {
		t.Fatalf("parseVerifierFlood(valid): %v", err)
	}
	if report.Attempts != 7 ||
		report.Namespace != wire.Namespace.Identity ||
		!report.Completed ||
		!report.LoopbackOnly ||
		!report.TablesEmpty ||
		!report.ConntrackEmpty ||
		!report.RoutesComplete {
		t.Fatalf("report=%+v", report)
	}
	for name, mutate := range map[string]func(*verifierFloodWire){
		"attempt drift": func(value *verifierFloodWire) {
			value.Attempts++
		},
		"incomplete": func(value *verifierFloodWire) {
			value.Completed = false
		},
		"capability": func(value *verifierFloodWire) {
			value.Capabilities.Bounding = "0000000000001000"
		},
		"identity": func(value *verifierFloodWire) {
			value.Namespace.Identity = NetworkNamespaceIdentity{}
		},
		"routes": func(value *verifierFloodWire) {
			value.RoutesComplete = false
		},
		"tables": func(value *verifierFloodWire) {
			value.Namespace.TablesEmpty = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := wire
			mutate(&candidate)
			if _, err := parseVerifierFlood(
				canonicalJSONLine(t, candidate),
				7,
			); err == nil {
				t.Fatal("parseVerifierFlood accepted invalid report")
			}
		})
	}
}

func TestVerifyLoopbackFloodUsesOneClosedVerifierAndBindsAdapter(t *testing.T) {
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	namespace := NetworkNamespaceIdentity{Device: 61, Inode: 62}
	wire := verifierFloodWire{
		Version:        2,
		Attempts:       9,
		Completed:      true,
		Capabilities:   emptyVerifierCapabilities(),
		RoutesComplete: true,
	}
	wire.Namespace.Identity = namespace
	wire.Namespace.LoopbackOnly = true
	wire.Namespace.TablesEmpty = true
	wire.Namespace.ConntrackEmpty = true
	inspect := managedAdapterInspectJSON(adapterID, adapterSpec)
	commands := &scriptedCommandRunner{results: []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(inspect)},
		{Stdout: canonicalJSONLine(t, wire)},
		{},
		{Stdout: []byte(inspect)},
	}}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	cli.adapters[adapter.nonce].bound = true
	verifier := validVerifierSpec(adapter, adapterSpec)

	evidence, err := cli.VerifyLoopbackFlood(
		context.Background(),
		adapter,
		verifier,
		9,
	)
	if err != nil {
		t.Fatalf("VerifyLoopbackFlood: %v", err)
	}
	report := evidence.Report()
	if evidence.AdapterID() != adapterID ||
		report.Attempts != 9 ||
		report.Namespace != namespace ||
		!report.Completed ||
		!report.LoopbackOnly ||
		!report.TablesEmpty ||
		!report.ConntrackEmpty ||
		!report.RoutesComplete ||
		len(evidence.Digest()) != 64 {
		t.Fatalf("evidence=%+v report=%+v", evidence, report)
	}
	if got := commands.commands[2].stdin; !slices.Equal(
		got,
		[]byte("{\"version\":1,\"attempts\":9}\n"),
	) {
		t.Fatalf("flood stdin=%q", got)
	}
	if got := commands.commands[2].argv; !slices.Equal(
		got[len(got)-2:],
		[]string{verifier.Image, "loopback-flood"},
	) {
		t.Fatalf("flood argv tail=%q", got[len(got)-2:])
	}
}

func validVerifierBrokerReadiness(
	artifact PolicyArtifact,
	ownerPID,
	parserPID uint32,
) brokerReadinessWire {
	return brokerReadinessWire{
		Version:           1,
		ReleaseGeneration: 1,
		PolicyDigest:      artifact.Digest(),
		PolicyIPv6Posture: "deny-via-ip6tables",
		NamespaceOwner: ProcessIdentity{
			PID: ownerPID, StartTime: 8000,
		},
		Parser: childProcessIdentity{
			PID: parserPID, PPID: ownerPID, StartTime: 8001,
		},
		RelayDirectory: DirectoryIdentity{
			Device: 101, Inode: 102, UID: 65532, GID: 65532, Mode: 0o700,
		},
		RelaySocket: SocketIdentity{
			Name: "https.sock", Device: 101, Inode: 103,
			UID: 65532, GID: 65532, Mode: 0o600,
		},
		Control: controlSocketIdentity{
			Device: 301, DialerInode: 302, ParserInode: 303,
		},
		AuthorityDirectory: DirectoryIdentity{
			Device: 201, Inode: 202, UID: 65532, GID: 65532, Mode: 0o700,
		},
		AuthoritySocket: SocketIdentity{
			Name: dialAuthoritySocketName, Device: 201, Inode: 203,
			UID: 65532, GID: 65532, Mode: 0o600,
		},
		AuthorityPeer:       ProcessIdentity{PID: 7100, StartTime: 7101},
		ParserControlFD:     parserControlFD,
		FilterVersion:       parserFilterVersion,
		FilterTSYNC:         true,
		AFINETErrno:         parserSocketErrno,
		AFINET6Errno:        parserSocketErrno,
		UnexpectedFDs:       0,
		ParserTaskCount:     4,
		ParserTasksVerified: 4,
	}
}

func emptyVerifierCapabilities() linuxcap.Wire {
	return linuxcap.Wire{
		Effective:   "0000000000000000",
		Permitted:   "0000000000000000",
		Inheritable: "0000000000000000",
		Bounding:    "0000000000000000",
		Ambient:     "0000000000000000",
	}
}
