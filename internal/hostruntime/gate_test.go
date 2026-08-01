package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/redaction"
)

func TestGateOperationsUseClosedOrderAndSecretFreeArgv(t *testing.T) {
	cli, runner, commands := gateTestEngine(t,
		Result{Stdout: namespaceJSON(11, 22)},
		Result{Stdout: namespaceJSON(11, 22)},
		Result{Stdout: namespaceJSON(11, 22)},
	)

	if err := cli.HydrateSeeds(context.Background(), runner, []string{"actions-checkout", "tool-go"}); err != nil {
		t.Fatalf("HydrateSeeds: %v", err)
	}
	pre, err := cli.ProbeRunnerNetworkNamespace(context.Background(), runner, GateNetNSIDPreArm)
	if err != nil {
		t.Fatalf("pre-arm ProbeRunnerNetworkNamespace: %v", err)
	}
	if err := cli.ArmRunner(context.Background(), runner); err != nil {
		t.Fatalf("ArmRunner: %v", err)
	}
	final, err := cli.ProbeRunnerNetworkNamespace(context.Background(), runner, GateNetNSIDFinal)
	if err != nil {
		t.Fatalf("final ProbeRunnerNetworkNamespace: %v", err)
	}
	authority, err := cli.AuthorizeRelease(context.Background(), runner, pre, final)
	if err != nil {
		t.Fatalf("AuthorizeRelease: %v", err)
	}
	adapterID := cli.runners[runner.nonce].adapter.ID()

	jitCorpus := "opaque-jit-fixture-that-must-not-enter-argv"
	jit := redaction.SecretFromBytes([]byte(jitCorpus))
	if err := cli.ReleaseRunner(context.Background(), runner, authority, jit); err != nil {
		t.Fatalf("ReleaseRunner: %v", err)
	}
	if len(cli.runners) != 1 {
		t.Fatalf("live released runner records=%d, want 1", len(cli.runners))
	}
	if err := jit.Use(func(_ io.Reader) error { return nil }); !errors.Is(err, redaction.ErrSecretScopeClosed) {
		t.Fatalf("JIT secret after release = %v, want destroyed", err)
	}

	if len(commands.commands) != 12 {
		t.Fatalf("command count = %d, want 12", len(commands.commands))
	}
	wantOperations := []string{"hydrate-seeds", "netns-id", "arm", "netns-id", "netns-id", "release"}
	commandIndexes := []int{3, 4, 5, 6, 7, 11}
	for i, want := range wantOperations {
		argv := commands.commands[commandIndexes[i]].argv
		if !slices.Contains(argv, want) {
			t.Errorf("command %d argv %q does not contain operation %q", commandIndexes[i], argv, want)
		}
		if strings.Contains(strings.Join(argv, "\x00"), jitCorpus) {
			t.Errorf("command %d argv leaked JIT corpus", commandIndexes[i])
		}
	}
	if got := commands.commands[8].argv; !slices.Contains(got, "inspect") || !slices.Contains(got, adapterID) {
		t.Fatalf("fresh adapter audit missing: %q", got)
	}
	if got := commands.commands[9].argv; !slices.Contains(got, "inspect") || !slices.Contains(got, runner.ID()) {
		t.Fatalf("runner config audit missing: %q", got)
	}
	if got := commands.commands[10].argv; !slices.Contains(got, "top") || !slices.Contains(got, "pid=,args=") {
		t.Fatalf("runner process audit missing: %q", got)
	}

	armFrame := commands.commands[5].stdin
	if len(armFrame) != 44 || string(armFrame[:8]) != "PGHARARM" {
		t.Fatalf("arm frame shape = %x", armFrame)
	}
	releaseFrame := commands.commands[11].stdin
	if len(releaseFrame) != 47+len(jitCorpus) || string(releaseFrame[:8]) != "PGHARREL" {
		t.Fatalf("release frame shape length=%d prefix=%q", len(releaseFrame), releaseFrame[:min(8, len(releaseFrame))])
	}
	tokenDigest := sha256.Sum256(releaseFrame[15:47])
	if !slices.Equal(armFrame[12:44], tokenDigest[:]) {
		t.Fatal("release token does not match the digest sent in arm")
	}
	if string(releaseFrame[47:]) != jitCorpus {
		t.Fatal("release frame did not carry the exact scoped JIT bytes")
	}
	commands.results = append(commands.results, Result{})
	if err := cli.RemoveRunner(context.Background(), runner); err != nil {
		t.Fatalf("RemoveRunner after release: %v", err)
	}
	if len(cli.runners) != 0 {
		t.Fatalf("removed runner records=%d, want 0", len(cli.runners))
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Contains(got, "rm") ||
		!slices.Contains(got, "-f") || !slices.Contains(got, runner.ID()) {
		t.Fatalf("RemoveRunner argv=%q", got)
	}
}

func TestAuditHeldRunnerRejectsExtraProcessAndDestroysRunner(t *testing.T) {
	cli, runner, commands := gateTestEngine(t,
		Result{Stdout: namespaceJSON(11, 22)},
		Result{Stdout: namespaceJSON(11, 22)},
	)
	if err := cli.HydrateSeeds(context.Background(), runner, nil); err != nil {
		t.Fatalf("HydrateSeeds: %v", err)
	}
	if _, err := cli.ProbeRunnerNetworkNamespace(context.Background(), runner, GateNetNSIDPreArm); err != nil {
		t.Fatalf("pre-arm namespace: %v", err)
	}
	if err := cli.ArmRunner(context.Background(), runner); err != nil {
		t.Fatalf("ArmRunner: %v", err)
	}
	if _, err := cli.ProbeRunnerNetworkNamespace(context.Background(), runner, GateNetNSIDFinal); err != nil {
		t.Fatalf("final namespace: %v", err)
	}
	record := cli.runners[runner.nonce]
	const pid = int64(4242)
	commands.results = append(commands.results,
		Result{Stdout: []byte(managedAdapterInspectJSON(record.adapter.id, adapterSpecFromRecord(record)))},
		Result{Stdout: []byte(managedRunnerInspectJSON(runner.id, record.spec, pid))},
		Result{Stdout: []byte("4242 " + runnerEntrypoint + " hold\n4243 /bin/extra\n")},
		Result{},
	)
	if _, err := cli.AuditHeldRunner(context.Background(), runner); err == nil {
		t.Fatal("AuditHeldRunner accepted an extra process")
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Contains(got, "rm") || !slices.Contains(got, "-f") {
		t.Fatalf("failed held audit did not remove runner: %q", got)
	}
}

func TestAuditHeldRunnerRejectsMemorySwapReadbackDrift(t *testing.T) {
	cli, runner, commands := gateTestEngine(t,
		Result{Stdout: namespaceJSON(11, 22)},
		Result{Stdout: namespaceJSON(11, 22)},
	)
	if err := cli.HydrateSeeds(context.Background(), runner, nil); err != nil {
		t.Fatalf("HydrateSeeds: %v", err)
	}
	if _, err := cli.ProbeRunnerNetworkNamespace(
		context.Background(),
		runner,
		GateNetNSIDPreArm,
	); err != nil {
		t.Fatalf("pre-arm namespace: %v", err)
	}
	if err := cli.ArmRunner(context.Background(), runner); err != nil {
		t.Fatalf("ArmRunner: %v", err)
	}
	if _, err := cli.ProbeRunnerNetworkNamespace(
		context.Background(),
		runner,
		GateNetNSIDFinal,
	); err != nil {
		t.Fatalf("final namespace: %v", err)
	}
	record := cli.runners[runner.nonce]
	const pid = int64(4242)
	inspect := managedRunnerInspectJSON(runner.id, record.spec, pid)
	want := `"MemorySwap":` +
		strconv.FormatUint(record.spec.Limits.MemorySwapBytes, 10)
	drifted := strings.Replace(
		inspect,
		want,
		`"MemorySwap":`+
			strconv.FormatUint(record.spec.Limits.MemorySwapBytes-1, 10),
		1,
	)
	if drifted == inspect {
		t.Fatal("runner MemorySwap fixture mutation did not match")
	}
	commands.results = append(commands.results,
		Result{Stdout: []byte(managedAdapterInspectJSON(
			record.adapter.id,
			adapterSpecFromRecord(record),
		))},
		Result{Stdout: []byte(drifted)},
		Result{},
	)
	if _, err := cli.AuditHeldRunner(
		context.Background(),
		runner,
	); err == nil {
		t.Fatal("AuditHeldRunner accepted MemorySwap readback drift")
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Contains(got, "rm") || !slices.Contains(got, "-f") {
		t.Fatalf("failed MemorySwap audit did not remove runner: %q", got)
	}
}

func TestGateRejectsOutOfOrderOperationAndDestroysRunner(t *testing.T) {
	cli, runner, commands := gateTestEngine(t)
	if err := cli.ArmRunner(context.Background(), runner); err == nil {
		t.Fatal("ArmRunner accepted before mandatory hydrate and pre-arm probe")
	}
	if len(commands.commands) != 4 {
		t.Fatalf("command count = %d, want adapter-create/inspect/runner-create/rm", len(commands.commands))
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Contains(got, "rm") || !slices.Contains(got, "-f") {
		t.Fatalf("terminal ordering failure did not remove runner: %q", got)
	}
	if len(cli.runners) != 0 {
		t.Fatalf("removed runner records=%d, want 0", len(cli.runners))
	}
}

func TestGateRejectsUnknownNamespaceProbeOperation(t *testing.T) {
	cli, runner, commands := gateTestEngine(t)
	if _, err := cli.ProbeRunnerNetworkNamespace(context.Background(), runner, GateOperation(255)); err == nil {
		t.Fatal("ProbeRunnerNetworkNamespace accepted unknown operation")
	}
	if len(commands.commands) != 4 {
		t.Fatalf("command count = %d, want adapter-create/inspect/runner-create/rm", len(commands.commands))
	}
}

func TestAdapterRemovalRequiresRunnerReclamationFirst(t *testing.T) {
	cli, runner, commands := gateTestEngine(t)
	adapter := cli.runners[runner.nonce].adapter
	commandCount := len(commands.commands)
	if err := cli.RemoveNetworkAdapter(context.Background(), adapter); err == nil {
		t.Fatal("RemoveNetworkAdapter accepted a live runner dependency")
	}
	if len(commands.commands) != commandCount {
		t.Fatal("dependency rejection invoked Docker")
	}
	commands.results = append(commands.results, Result{}, Result{})
	if err := cli.RemoveRunner(context.Background(), runner); err != nil {
		t.Fatalf("RemoveRunner: %v", err)
	}
	if err := cli.RemoveNetworkAdapter(context.Background(), adapter); err != nil {
		t.Fatalf("RemoveNetworkAdapter: %v", err)
	}
	if len(cli.runners) != 0 || len(cli.adapters) != 0 {
		t.Fatalf("records after ordered cleanup runners=%d adapters=%d", len(cli.runners), len(cli.adapters))
	}
}

func TestAuthorizeReleaseRequiresExactNamespaceEqualityTriangle(t *testing.T) {
	cli, runner, commands := gateTestEngine(t,
		Result{Stdout: namespaceJSON(11, 22)},
		Result{Stdout: namespaceJSON(11, 23)},
	)
	if err := cli.HydrateSeeds(context.Background(), runner, nil); err != nil {
		t.Fatalf("HydrateSeeds: %v", err)
	}
	pre, err := cli.ProbeRunnerNetworkNamespace(context.Background(), runner, GateNetNSIDPreArm)
	if err != nil {
		t.Fatalf("pre-arm probe: %v", err)
	}
	if err := cli.ArmRunner(context.Background(), runner); err != nil {
		t.Fatalf("ArmRunner: %v", err)
	}
	final, err := cli.ProbeRunnerNetworkNamespace(context.Background(), runner, GateNetNSIDFinal)
	if err != nil {
		t.Fatalf("final probe: %v", err)
	}
	if _, err := cli.AuthorizeRelease(context.Background(), runner, pre, final); err == nil {
		t.Fatal("AuthorizeRelease accepted unequal pre-arm and final proofs")
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Contains(got, "rm") {
		t.Fatalf("namespace mismatch did not remove runner: %q", got)
	}
}

func TestReleaseRejectsZeroOrForeignAuthorization(t *testing.T) {
	cli, runner, commands := gateTestEngine(t)
	jit := redaction.SecretFromBytes([]byte("jit"))
	if err := cli.ReleaseRunner(context.Background(), runner, ReleaseAuthorization{}, jit); err == nil {
		t.Fatal("ReleaseRunner accepted zero authorization")
	}
	if got := commands.commands[len(commands.commands)-1].argv; !slices.Contains(got, "rm") {
		t.Fatalf("invalid authorization did not remove runner: %q", got)
	}
}

func gateTestEngine(t *testing.T, namespaceResults ...Result) (*DockerCLI, RunnerHandle, *scriptedCommandRunner) {
	t.Helper()
	adapterSpec, cfg := validAdapterSpec(t)
	adapterID := strings.Repeat("c", 64)
	runnerID := strings.Repeat("d", 64)
	results := []Result{
		{Stdout: []byte(adapterID + "\n")},
		{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
		{Stdout: []byte(runnerID + "\n")},
	}
	for i, namespace := range namespaceResults {
		switch i {
		case 0:
			results = append(results, Result{Stdout: []byte("OK\n")}, namespace, Result{Stdout: []byte("OK\n")})
		case 1, 2:
			results = append(results, namespace)
		}
	}
	if len(namespaceResults) == 3 {
		runnerSpec := validRunnerSpec(
			AdapterHandle{id: adapterID, slotIdentity: adapterSpec.SlotIdentity},
			adapterSpec.Seccomp,
		)
		results = append(results,
			Result{Stdout: []byte(managedAdapterInspectJSON(adapterID, adapterSpec))},
			Result{Stdout: []byte(managedRunnerInspectJSON(runnerID, runnerSpec, 4242))},
			Result{Stdout: []byte("4242 " + runnerEntrypoint + " hold\n")},
		)
		results = append(results, Result{Stdout: []byte("OK\n")})
	}
	commands := &scriptedCommandRunner{results: results}
	cli, err := NewDockerCLI(cfg, commands)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	adapter, err := cli.CreateNetworkAdapter(context.Background(), adapterSpec)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	runner, err := cli.CreateRunner(context.Background(), validRunnerSpec(adapter, adapterSpec.Seccomp))
	if err != nil {
		t.Fatalf("CreateRunner: %v", err)
	}
	return cli, runner, commands
}

func adapterSpecFromRecord(record *runnerRecord) AdapterSpec {
	return AdapterSpec{
		Image:           record.adapter.image,
		BuildID:         record.adapter.buildID,
		FleetGeneration: record.adapter.fleetGeneration,
		SlotIdentity:    record.adapter.slotIdentity,
	}
}

func namespaceJSON(device, inode uint64) []byte {
	encoded, _ := json.Marshal(namespaceWire{Version: 1, Device: device, Inode: inode})
	return append(encoded, '\n')
}
