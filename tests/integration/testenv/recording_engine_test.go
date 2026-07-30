package testenv

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type recordingEngineCommandRunner struct {
	containerID string
	createCalls int
	removeCalls int
}

func testRecordingRuntimeBinding() recordingRuntimeBinding {
	return recordingRuntimeBinding{
		RunID:           inputDigestA,
		BuildID:         strings.Repeat("2", 64),
		FleetGeneration: 1,
		SlotIdentity:    "portable-ghar-slot",
		CapacitySlotID:  11,
		JobGeneration:   13,
	}
}

func TestRecordingEngineRetainsOpaqueAuthorityOnExactBrokerRecord(
	t *testing.T,
) {
	t.Parallel()

	brokerID := strings.Repeat("b", 64)
	proof := validRecordingAuthorityProof(t, 7, 19, 23)
	engine, err := newRecordingEngine(
		&recordingAuthorityEngine{Engine: &closedRecordingEngine{}},
		func(cleanupHandle) error { return nil },
		testRecordingRuntimeBinding(),
	)
	if err != nil {
		t.Fatalf("newRecordingEngine: %v", err)
	}
	entry := &recordedRuntimeHandle{
		handle: cleanupHandle{
			kind: CleanupBroker,
			id:   brokerID,
		},
		specDigest:              inputDigestA,
		policyDigest:            inputDigestB,
		policyApplicationDigest: inputDigestC,
	}
	engine.handles[brokerID] = entry

	if err := engine.retainBoundAuthority(brokerID, proof); err != nil {
		t.Fatalf("retainBoundAuthority: %v", err)
	}
	if !entry.authorityBound ||
		!entry.authorityProof.MatchesPermitActivation(7, 19, 23) {
		t.Fatalf(
			"retained authority = bound:%t",
			entry.authorityBound,
		)
	}
	if err := engine.retainBoundAuthority(
		brokerID,
		proof,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate retainBoundAuthority error = %v", err)
	}

	entry.busy = true
	engine.finishRemoval(entry, nil)
	if entry.authorityBound ||
		entry.authorityProof.MatchesPermitActivation(7, 19, 23) {
		t.Fatal("removed broker retained opaque authority")
	}
}

type recordingAuthorityEngine struct {
	hostruntime.Engine
}

type closedRecordingEngine struct {
	hostruntime.Engine
}

func TestRecordingEngineRejectsAuthorityForUnknownBroker(t *testing.T) {
	t.Parallel()

	engine, err := newRecordingEngine(
		&recordingAuthorityEngine{Engine: &closedRecordingEngine{}},
		func(cleanupHandle) error { return nil },
		testRecordingRuntimeBinding(),
	)
	if err != nil {
		t.Fatalf("newRecordingEngine: %v", err)
	}
	if err := engine.retainBoundAuthority(
		strings.Repeat("c", 64),
		validRecordingAuthorityProof(t, 7, 19, 23),
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("unknown broker error = %v", err)
	}
}

func TestRecordingEngineAcknowledgesOnlyExactRecoveredRemoval(
	t *testing.T,
) {
	t.Parallel()
	engine, err := newRecordingEngine(
		&closedRecordingEngine{},
		func(cleanupHandle) error { return nil },
		testRecordingRuntimeBinding(),
	)
	if err != nil {
		t.Fatal(err)
	}
	identities := hostruntime.RecoveredIdentities{
		AdapterID: strings.Repeat("a", 64),
		BrokerID:  strings.Repeat("b", 64),
		RunnerID:  strings.Repeat("c", 64),
	}
	for kind, id := range map[CleanupKind]string{
		CleanupAdapter: identities.AdapterID,
		CleanupBroker:  identities.BrokerID,
		CleanupRunner:  identities.RunnerID,
	} {
		engine.handles[id] = &recordedRuntimeHandle{
			handle: cleanupHandle{kind: kind, id: id},
		}
	}
	if err := engine.markRecoveredRemoved(identities); err != nil {
		t.Fatalf("markRecoveredRemoved: %v", err)
	}
	for kind, id := range map[CleanupKind]string{
		CleanupAdapter: identities.AdapterID,
		CleanupBroker:  identities.BrokerID,
		CleanupRunner:  identities.RunnerID,
	} {
		if !engine.RecordedRemoved(cleanupHandle{kind: kind, id: id}) {
			t.Fatalf("%s was not recorded removed", id)
		}
	}
	if err := engine.markRecoveredRemoved(
		identities,
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("duplicate recovered removal error = %v", err)
	}
}

func TestRecordingEngineRejectsIncompleteRecoveredRemoval(
	t *testing.T,
) {
	t.Parallel()
	engine, err := newRecordingEngine(
		&closedRecordingEngine{},
		func(cleanupHandle) error { return nil },
		testRecordingRuntimeBinding(),
	)
	if err != nil {
		t.Fatal(err)
	}
	adapterID := strings.Repeat("a", 64)
	brokerID := strings.Repeat("b", 64)
	engine.handles[adapterID] = &recordedRuntimeHandle{
		handle: cleanupHandle{kind: CleanupAdapter, id: adapterID},
	}
	engine.handles[brokerID] = &recordedRuntimeHandle{
		handle: cleanupHandle{kind: CleanupBroker, id: brokerID},
	}
	if err := engine.markRecoveredRemoved(
		hostruntime.RecoveredIdentities{AdapterID: adapterID},
	); !errors.Is(err, ErrFixtureCleanup) {
		t.Fatalf("incomplete recovered removal error = %v", err)
	}
	if engine.RecordedRemoved(
		cleanupHandle{kind: CleanupAdapter, id: adapterID},
	) {
		t.Fatal("incomplete recovered removal mutated accounting")
	}
}

func (r *recordingEngineCommandRunner) Run(
	_ context.Context,
	argv []string,
	_ []*os.File,
	_ io.Reader,
) (hostruntime.Result, error) {
	if len(argv) < 2 {
		return hostruntime.Result{}, errors.New("closed argv")
	}
	switch argv[1] {
	case "run":
		r.createCalls++
		return hostruntime.Result{
			Stdout: []byte(r.containerID + "\n"),
		}, nil
	case "rm":
		r.removeCalls++
		return hostruntime.Result{}, nil
	default:
		return hostruntime.Result{}, errors.New("closed operation")
	}
}

func validRecordingAuthorityProof(
	t *testing.T,
	slot uint32,
	generation uint64,
	revision uint64,
) hostruntime.AuthorityProof {
	t.Helper()
	proof, err := hostruntime.NewAuthorityProof(hostruntime.AuthorityBinding{
		Version:        1,
		CapacitySlotID: slot,
		JobGeneration:  generation,
		LedgerRevision: revision,
		Directory: hostruntime.DirectoryIdentity{
			Device: 11,
			Inode:  12,
			UID:    1001,
			GID:    1001,
			Mode:   0o700,
		},
		Socket: hostruntime.SocketIdentity{
			Name:   "dial-authority.sock",
			Device: 11,
			Inode:  13,
			UID:    1001,
			GID:    1001,
			Mode:   0o600,
		},
		Peer: hostruntime.ProcessIdentity{
			PID:       71,
			StartTime: 72,
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorityProof: %v", err)
	}
	return proof
}

func TestRecordingEngineRecordsAndRemovesExactOpaqueAdapter(t *testing.T) {
	t.Parallel()

	base, runner, spec := validRecordingAdapterRuntime(t)
	var recorded []cleanupHandle
	engine, err := newRecordingEngine(
		base,
		func(handle cleanupHandle) error {
			recorded = append(recorded, handle)
			return nil
		},
		testRecordingRuntimeBinding(),
	)
	if err != nil {
		t.Fatalf("newRecordingEngine: %v", err)
	}
	handle, err := engine.CreateNetworkAdapter(
		context.Background(),
		spec,
	)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	if handle.ID() != runner.containerID ||
		len(recorded) != 1 ||
		recorded[0] != (cleanupHandle{
			kind: CleanupAdapter,
			id:   runner.containerID,
		}) {
		t.Fatalf("handle/recorded = %q/%+v", handle.ID(), recorded)
	}
	if engine.RecordedRemoved(recorded[0]) {
		t.Fatal("fresh handle reported removed")
	}
	entry := engine.handles[handle.ID()]
	wantSpecDigest, err := recordingAdapterSpecDigest(
		testRecordingRuntimeBinding(),
		spec,
		handle.ID(),
	)
	if err != nil ||
		entry == nil ||
		entry.specDigest != wantSpecDigest {
		gotSpecDigest := ""
		if entry != nil {
			gotSpecDigest = entry.specDigest
		}
		t.Fatalf(
			"adapter spec digest = %q want %q err=%v",
			gotSpecDigest,
			wantSpecDigest,
			err,
		)
	}
	if err := engine.RemoveRecorded(
		context.Background(),
		recorded[0],
	); err != nil {
		t.Fatalf("RemoveRecorded: %v", err)
	}
	if !engine.RecordedRemoved(recorded[0]) {
		t.Fatal("removed handle was not proven removed")
	}
	if entry.specDigest != "" {
		t.Fatalf("removed adapter retained spec digest %q", entry.specDigest)
	}
	if err := engine.RemoveRecorded(
		context.Background(),
		recorded[0],
	); err != nil {
		t.Fatalf("idempotent RemoveRecorded: %v", err)
	}
	if runner.createCalls != 1 || runner.removeCalls != 1 {
		t.Fatalf(
			"create/remove calls = %d/%d",
			runner.createCalls,
			runner.removeCalls,
		)
	}
}

func TestRecordingCreationSpecDigestsBindExactRuntimeIdentity(t *testing.T) {
	t.Parallel()

	base, _, adapterSpec := validRecordingAdapterRuntime(t)
	binding := testRecordingRuntimeBinding()
	engine, err := newRecordingEngine(
		base,
		func(cleanupHandle) error { return nil },
		binding,
	)
	if err != nil {
		t.Fatalf("newRecordingEngine: %v", err)
	}
	adapter, err := engine.CreateNetworkAdapter(
		context.Background(),
		adapterSpec,
	)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	brokerSpec := hostruntime.BrokerSpec{
		Name:            "portable-ghar-broker",
		Image:           "example/broker@sha256:" + inputDigestA,
		HelperImage:     "example/helper@sha256:" + inputDigestB,
		BuildID:         binding.BuildID,
		FleetGeneration: binding.FleetGeneration,
		SlotIdentity:    binding.SlotIdentity,
		CapacitySlotID:  binding.CapacitySlotID,
		JobGeneration:   binding.JobGeneration,
		Adapter:         adapter,
		RelayParent:     "/relay",
		AuthorityParent: "/authority",
		User:            "65532:65532",
		Limits: hostruntime.BrokerLimits{
			MilliCPU: 1,
		},
		HelperLimits: hostruntime.OneShotLimits{
			MilliCPU: 1,
		},
	}
	brokerDigest, err := recordingBrokerSpecDigest(
		binding,
		brokerSpec,
		inputDigestB,
	)
	if err != nil {
		t.Fatalf("recordingBrokerSpecDigest: %v", err)
	}
	mutatedBroker := brokerSpec
	mutatedBroker.HelperLimits.PIDs = 1
	mutatedBrokerDigest, err := recordingBrokerSpecDigest(
		binding,
		mutatedBroker,
		inputDigestB,
	)
	if err != nil || mutatedBrokerDigest == brokerDigest {
		t.Fatalf(
			"mutated broker digest = %q original=%q err=%v",
			mutatedBrokerDigest,
			brokerDigest,
			err,
		)
	}
	wrongBroker := brokerSpec
	wrongBroker.CapacitySlotID++
	if _, err := recordingBrokerSpecDigest(
		binding,
		wrongBroker,
		inputDigestB,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("wrong broker binding error = %v", err)
	}

	runnerSpec := hostruntime.RunnerSpec{
		Name:            "portable-ghar-runner",
		Image:           "example/runner@sha256:" + inputDigestC,
		BuildID:         binding.BuildID,
		FleetGeneration: binding.FleetGeneration,
		SlotIdentity:    binding.SlotIdentity,
		Adapter:         adapter,
		Profile:         hostruntime.HostProfileStrictLinux,
		User:            "65532:65532",
		Limits: hostruntime.RunnerLimits{
			MilliCPU: 1,
		},
	}
	runnerDigest, err := recordingRunnerSpecDigest(
		binding,
		runnerSpec,
		inputDigestC,
	)
	if err != nil || runnerDigest == brokerDigest {
		t.Fatalf(
			"runner digest = %q broker=%q err=%v",
			runnerDigest,
			brokerDigest,
			err,
		)
	}
	wrongRunner := runnerSpec
	wrongRunner.Adapter = hostruntime.AdapterHandle{}
	if _, err := recordingRunnerSpecDigest(
		binding,
		wrongRunner,
		inputDigestC,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("wrong runner adapter binding error = %v", err)
	}
}

func TestRecordingEngineReclaimsWhenHandleRegistrationFails(
	t *testing.T,
) {
	t.Parallel()

	base, runner, spec := validRecordingAdapterRuntime(t)
	engine, err := newRecordingEngine(
		base,
		func(cleanupHandle) error { return ErrFixtureStart },
		testRecordingRuntimeBinding(),
	)
	if err != nil {
		t.Fatalf("newRecordingEngine: %v", err)
	}
	handle, err := engine.CreateNetworkAdapter(
		context.Background(),
		spec,
	)
	if !errors.Is(err, ErrFixtureStart) || handle.ID() != "" {
		t.Fatalf("handle/error = %q/%v", handle.ID(), err)
	}
	if runner.createCalls != 1 || runner.removeCalls != 1 {
		t.Fatalf(
			"create/remove calls = %d/%d",
			runner.createCalls,
			runner.removeCalls,
		)
	}
}

func TestRecordingEngineRunsAndRetainsOneExactLoopbackFlood(t *testing.T) {
	t.Parallel()

	base, _, adapterSpec := validRecordingAdapterRuntime(t)
	engine, err := newRecordingEngine(
		base,
		func(cleanupHandle) error { return nil },
		testRecordingRuntimeBinding(),
	)
	if err != nil {
		t.Fatalf("newRecordingEngine: %v", err)
	}
	adapter, err := engine.CreateNetworkAdapter(
		context.Background(),
		adapterSpec,
	)
	if err != nil {
		t.Fatalf("CreateNetworkAdapter: %v", err)
	}
	want := fixtureFloodObservation{
		EvidenceDigest: inputDigestA,
		Report: hostruntime.LoopbackFloodReport{
			Attempts:       17,
			Completed:      true,
			Namespace:      hostruntime.NetworkNamespaceIdentity{Device: 31, Inode: 32},
			LoopbackOnly:   true,
			TablesEmpty:    true,
			ConntrackEmpty: true,
			RoutesComplete: true,
		},
	}
	var operationCalls int
	engine.floodOperation = func(
		_ context.Context,
		gotAdapter hostruntime.AdapterHandle,
		_ hostruntime.VerifierSpec,
		attempts uint64,
	) (fixtureFloodObservation, error) {
		operationCalls++
		if gotAdapter.ID() != adapter.ID() || attempts != 17 {
			return fixtureFloodObservation{}, ErrFixtureStart
		}
		return want, nil
	}
	verifier := hostruntime.VerifierSpec{
		Image:           "example/verifier@sha256:" + inputDigestA,
		BuildID:         adapterSpec.BuildID,
		FleetGeneration: adapterSpec.FleetGeneration,
		SlotIdentity:    adapterSpec.SlotIdentity,
		Adapter:         adapter,
		User:            adapterSpec.User,
		Seccomp:         adapterSpec.Seccomp,
		Limits: hostruntime.OneShotLimits{
			MilliCPU:        1,
			MemoryBytes:     1,
			MemorySwapBytes: 1,
			PIDs:            1,
			FileDescriptors: 8,
		},
	}
	verifierDigest, err := recordingVerifierSpecDigest(
		testRecordingRuntimeBinding(),
		verifier,
	)
	if err != nil {
		t.Fatalf("recordingVerifierSpecDigest: %v", err)
	}
	engine.handles[adapter.ID()].verifierDigest = verifierDigest
	engine.observationTaken = true
	got, err := engine.VerifyLoopbackFlood(
		context.Background(),
		adapter.ID(),
		verifier,
		17,
	)
	if err != nil || got != want {
		t.Fatalf("VerifyLoopbackFlood = %+v err=%v", got, err)
	}
	if operationCalls != 1 {
		t.Fatalf("operation calls = %d", operationCalls)
	}
	entry := engine.handles[adapter.ID()]
	if entry == nil || !entry.floodReady || entry.flood != want {
		t.Fatalf("recorded flood = %+v", entry)
	}
	if _, err := engine.VerifyLoopbackFlood(
		context.Background(),
		adapter.ID(),
		verifier,
		17,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate flood error = %v", err)
	}
	if operationCalls != 1 {
		t.Fatalf("duplicate operation calls = %d", operationCalls)
	}
}

func validRecordingAdapterRuntime(
	t *testing.T,
) (*hostruntime.DockerCLI, *recordingEngineCommandRunner, hostruntime.AdapterSpec) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks temp root: %v", err)
	}
	relay := filepath.Join(root, "relay")
	if err := os.Mkdir(relay, 0o700); err != nil {
		t.Fatalf("Mkdir relay: %v", err)
	}
	sourceSeccomp := filepath.Join(
		"..",
		"..",
		"..",
		"config",
		"seccomp",
		"portable-ghar-capless-v1.json",
	)
	document, err := os.ReadFile(sourceSeccomp)
	if err != nil {
		t.Fatalf("ReadFile seccomp: %v", err)
	}
	seccompRoot := filepath.Join(root, "seccomp")
	if err := os.Mkdir(seccompRoot, 0o700); err != nil {
		t.Fatalf("Mkdir seccomp: %v", err)
	}
	seccompPath := filepath.Join(seccompRoot, "profile.json")
	if err := os.WriteFile(seccompPath, document, 0o600); err != nil {
		t.Fatalf("WriteFile seccomp: %v", err)
	}
	digest, err := hostruntime.ValidateSeccompProfile(
		document,
		len(document),
	)
	if err != nil {
		t.Fatalf("ValidateSeccompProfile: %v", err)
	}
	runner := &recordingEngineCommandRunner{
		containerID: strings.Repeat("a", 64),
	}
	engine, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    "/usr/bin/docker",
			BrokerRoot:    root,
			SeccompRoot:   seccompRoot,
			BrokerNetwork: "portable-ghar-broker",
		},
		runner,
	)
	if err != nil {
		t.Fatalf("NewDockerCLI: %v", err)
	}
	return engine, runner, hostruntime.AdapterSpec{
		Name:            "portable-ghar-adapter",
		Image:           "example/adapter@sha256:" + strings.Repeat("1", 64),
		BuildID:         strings.Repeat("2", 64),
		FleetGeneration: 1,
		SlotIdentity:    "portable-ghar-slot",
		BrokerParent:    relay,
		User:            "65532:65532",
		Seccomp: hostruntime.SeccompBinding{
			Path:   seccompPath,
			SHA256: digest,
		},
		Limits: hostruntime.ContainerLimits{
			MilliCPU:        1,
			MemoryBytes:     4,
			MemorySwapBytes: 4,
			PIDs:            1,
			FileDescriptors: 1,
			TmpfsBytes:      1,
			ScratchBytes:    1,
			LogBytes:        1,
			LogFiles:        1,
		},
	}
}
