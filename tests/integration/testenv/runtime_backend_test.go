package testenv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

type fakeFixtureRootRemover struct {
	trace   *[]string
	handle  cleanupHandle
	removed bool
}

func (r *fakeFixtureRootRemover) RemoveRoot(
	_ context.Context,
	handle cleanupHandle,
) error {
	if handle != r.handle || r.removed {
		return ErrFixtureCleanup
	}
	*r.trace = append(*r.trace, "root-remove")
	r.removed = true
	return nil
}

type fakeFixtureRuntimeGraph struct {
	trace       *[]string
	record      func(cleanupHandle) error
	handles     []cleanupHandle
	removed     map[cleanupHandle]bool
	observation fixtureRuntimeObservation
	flood       fixtureFloodObservation
	floodCalls  int
}

func (g *fakeFixtureRuntimeGraph) Prepare(context.Context) error {
	*g.trace = append(*g.trace, "runtime-prepare")
	for _, handle := range g.handles {
		if err := g.record(handle); err != nil {
			return err
		}
	}
	return nil
}

func (g *fakeFixtureRuntimeGraph) Remove(
	_ context.Context,
	handle cleanupHandle,
) error {
	*g.trace = append(
		*g.trace,
		fmt.Sprintf("runtime-remove-%d", handle.kind),
	)
	found := false
	for _, expected := range g.handles {
		if expected == handle {
			found = true
			break
		}
	}
	if !found {
		return ErrFixtureCleanup
	}
	if handle.kind == CleanupRunner {
		for _, expected := range g.handles {
			g.removed[expected] = true
		}
		return nil
	}
	if !g.removed[handle] {
		return ErrFixtureCleanup
	}
	return nil
}

func (g *fakeFixtureRuntimeGraph) RecordedRemoved(
	handle cleanupHandle,
) bool {
	return g.removed[handle]
}

func (g *fakeFixtureRuntimeGraph) RuntimeObservation(
	context.Context,
) (fixtureRuntimeObservation, error) {
	return g.observation, nil
}

func (g *fakeFixtureRuntimeGraph) LoopbackFlood(
	_ context.Context,
	attempts uint32,
) (fixtureFloodObservation, error) {
	g.floodCalls++
	if attempts == 0 ||
		uint64(attempts) != g.flood.Report.Attempts ||
		g.floodCalls != 1 {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	return g.flood, nil
}

func TestFixtureRuntimeBackendRegistersWorkspaceSeedsAndCleansInReverse(
	t *testing.T,
) {
	t.Parallel()

	input, overlay := validCompositionPlanInputs()
	plan, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "state"), 0o700); err != nil {
		t.Fatalf("Mkdir state: %v", err)
	}
	input.Fixture = FixtureBinding{
		Root:                rootPath,
		ParentDevice:        1,
		ParentInode:         2,
		RequiredEmptyDigest: inputDigestA,
		ExecutionOwnerUID:   501,
	}
	trace := []string{}
	workspaceHandle, err := compositionCleanupHandle(
		CleanupTestProcess,
		"portable-ghar.task11.workspace.v1\x00",
		input.Authorization.RunID,
	)
	if err != nil {
		t.Fatalf("compositionCleanupHandle: %v", err)
	}
	workspaceOps := &fakeFixtureWorkspaceOperations{
		trace:    &trace,
		database: filepath.Join(rootPath, "state", "controller.db"),
	}
	workspace, err := newFixtureWorkspace(workspaceOps, workspaceHandle)
	if err != nil {
		t.Fatalf("newFixtureWorkspace: %v", err)
	}
	rootHandle := cleanupHandle{
		kind: CleanupFixtureRoot,
		id:   input.Fixture.RequiredEmptyDigest,
	}
	root := &fakeFixtureRootRemover{
		trace:  &trace,
		handle: rootHandle,
	}
	verifierHandle, err := compositionCleanupHandle(
		CleanupVerifier,
		"portable-ghar.test.runtime-verifier.v1\x00",
		inputDigestA,
	)
	if err != nil {
		t.Fatalf("compositionCleanupHandle verifier: %v", err)
	}
	syntheticHandle, err := compositionCleanupHandle(
		CleanupSyntheticListener,
		"portable-ghar.test.runtime-synthetic.v1\x00",
		inputDigestA,
	)
	if err != nil {
		t.Fatalf("compositionCleanupHandle synthetic: %v", err)
	}
	runtimeHandles := []cleanupHandle{
		{kind: CleanupAdapter, id: inputDigestB},
		{kind: CleanupBroker, id: inputDigestC},
		verifierHandle,
		syntheticHandle,
		{kind: CleanupRunner, id: inputDigestD},
	}
	probeReport := networkjail.ProbeReport{
		Version:       1,
		PolicyDigest:  inputDigestC,
		EgressBackend: networkjail.RestrictedBrokerV1,
		RunnerNetNSID: networkjail.NamespaceIdentity{
			Device: 1,
			Inode:  2,
		},
		BrokerNetNSID: networkjail.NamespaceIdentity{
			Device: 3,
			Inode:  4,
		},
		RunnerLoopbackOnly:   true,
		RunnerTablesEmpty:    true,
		RunnerConntrackEmpty: true,
		ParserHasNoSocket:    true,
		PositiveOK:           true,
		NegativeOK:           true,
		ConntrackBudgetOK:    true,
	}
	runtimeObservation := fixtureRuntimeObservation{
		Adapter:                runtimeHandles[0],
		Broker:                 runtimeHandles[1],
		Runner:                 runtimeHandles[4],
		AdapterSpecDigest:      inputDigestA,
		BrokerSpecDigest:       inputDigestB,
		RunnerSpecDigest:       inputDigestC,
		VerifierSpecDigest:     inputDigestD,
		AdapterEmptinessDigest: inputDigestA,
		AdapterNamespace: hostruntime.NetworkNamespaceIdentity{
			Device: 1,
			Inode:  2,
		},
		PolicyDigest:            inputDigestC,
		PolicyApplicationDigest: inputDigestA,
		HelperCapabilityDigest:  inputDigestB,
		AuthorityBindingReceipt: inputDigestC,
		BrokerPeerBindingDigest: inputDigestD,
		NetworkEgressDigest:     inputDigestA,
		NetworkEgressReport: hostruntime.NetworkVerifierReport{
			PolicyDigest:  inputDigestC,
			EgressBackend: string(networkjail.RestrictedBrokerV1),
			RunnerNetNSID: hostruntime.NetworkNamespaceIdentity{
				Device: 1,
				Inode:  2,
			},
			BrokerNetNSID: hostruntime.NetworkNamespaceIdentity{
				Device: 3,
				Inode:  4,
			},
			RunnerLoopbackOnly:   true,
			RunnerTablesEmpty:    true,
			RunnerConntrackEmpty: true,
			ParserHasNoSocket:    true,
			PositiveOK:           true,
			NegativeOK:           true,
		},
		NamespacePreArmReceipt:       inputDigestB,
		NamespaceFinalReceipt:        inputDigestC,
		ReleaseAuthorizationReceipt:  inputDigestD,
		RuntimeCapabilityDigest:      inputDigestA,
		PreparedEvidenceDigest:       inputDigestB,
		BrokerAuditDigest:            inputDigestA,
		RunnerAuditDigest:            inputDigestB,
		HeldSocketZeroDigest:         inputDigestC,
		BrokerReleaseDigest:          inputDigestD,
		PermitUsageDigest:            inputDigestC,
		PermitAuthorityBindingDigest: inputDigestD,
		ProbeMembershipDigest:        inputDigestA,
		PreparedProbeBindingDigest:   inputDigestB,
		ProbeReport:                  probeReport,
	}
	floodObservation := fixtureFloodObservation{
		EvidenceDigest: inputDigestA,
		Report: hostruntime.LoopbackFloodReport{
			Attempts:       uint64(input.LoopbackFloodAttempts),
			Completed:      true,
			Namespace:      hostruntime.NetworkNamespaceIdentity{Device: 1, Inode: 2},
			LoopbackOnly:   true,
			TablesEmpty:    true,
			ConntrackEmpty: true,
			RoutesComplete: true,
		},
	}
	var openedStore *state.SQLiteStore
	backend, err := newFixtureRuntimeBackend(
		input,
		plan,
		"65532:65531",
		workspace,
		root,
		func(
			path string,
			limits state.HistoryLimits,
		) (*state.SQLiteStore, error) {
			trace = append(trace, "store-open")
			store, openErr := state.OpenWithHistoryLimits(path, limits)
			openedStore = store
			return store, openErr
		},
		func(
			ctx context.Context,
			store *state.SQLiteStore,
			record func(cleanupHandle) error,
		) (fixtureRuntimeGraph, error) {
			trace = append(trace, "runtime-compose")
			recoverable, listErr := store.ListRecoverable(ctx)
			if listErr != nil ||
				len(recoverable) != 1 ||
				recoverable[0].Key != plan.AssignmentKey {
				return nil, ErrFixtureStart
			}
			return &fakeFixtureRuntimeGraph{
				trace:       &trace,
				record:      record,
				handles:     append([]cleanupHandle(nil), runtimeHandles...),
				removed:     make(map[cleanupHandle]bool),
				observation: runtimeObservation,
				flood:       floodObservation,
			}, nil
		},
		func() time.Time {
			return time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
		},
	)
	if err != nil {
		t.Fatalf("newFixtureRuntimeBackend: %v", err)
	}
	var recorded []cleanupHandle
	if err := backend.Start(
		context.Background(),
		func(handle cleanupHandle) error {
			trace = append(
				trace,
				fmt.Sprintf("record-%d", handle.kind),
			)
			recorded = append(recorded, handle)
			return nil
		},
	); err != nil {
		t.Fatalf("Start: %v", err)
	}
	expectedRecorded := append(
		[]cleanupHandle{workspaceHandle},
		runtimeHandles...,
	)
	if fmt.Sprint(recorded) != fmt.Sprint(expectedRecorded) {
		t.Fatalf("recorded = %+v", recorded)
	}
	gotRuntimeObservation, err := backend.RuntimeObservation(
		context.Background(),
	)
	if err != nil || gotRuntimeObservation != runtimeObservation {
		t.Fatalf(
			"runtime observation = %+v err=%v",
			gotRuntimeObservation,
			err,
		)
	}
	if _, err := backend.RuntimeObservation(
		context.Background(),
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate runtime observation error = %v", err)
	}
	gotFlood, err := backend.LoopbackFlood(
		context.Background(),
		input.LoopbackFloodAttempts,
	)
	if err != nil || gotFlood != floodObservation {
		t.Fatalf("flood observation = %+v err=%v", gotFlood, err)
	}
	if _, err := backend.LoopbackFlood(
		context.Background(),
		input.LoopbackFloodAttempts,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate loopback flood error = %v", err)
	}
	handles := append([]cleanupHandle{rootHandle}, recorded...)
	for index := len(handles) - 1; index >= 0; index-- {
		if err := backend.Remove(
			context.Background(),
			handles[index],
		); err != nil {
			t.Fatalf("Remove(%+v): %v", handles[index], err)
		}
	}
	observation, err := backend.Prove(
		context.Background(),
		handles,
		input.Fixture,
	)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if _, err := conformance.SealCleanup(observation); err != nil {
		t.Fatalf("SealCleanup: %v", err)
	}
	if openedStore == nil {
		t.Fatal("store was not opened")
	}
	if err := openedStore.DB().Ping(); err == nil {
		t.Fatal("store remained open after workspace cleanup")
	}
	expectedTrace := []string{
		"record-3",
		"prepare",
		"database",
		"store-open",
		"runtime-compose",
		"runtime-prepare",
		"record-5",
		"record-6",
		"record-8",
		"record-10",
		"record-9",
		"runtime-remove-9",
		"runtime-remove-10",
		"runtime-remove-8",
		"runtime-remove-6",
		"runtime-remove-5",
		"remove",
		"close",
		"root-remove",
	}
	if fmt.Sprint(trace) != fmt.Sprint(expectedTrace) {
		t.Fatalf("trace = %v", trace)
	}
}

func TestFixtureRuntimeBackendRejectsDuplicateStart(t *testing.T) {
	t.Parallel()

	input, overlay := validCompositionPlanInputs()
	plan, err := compositionPlanFrom(input, overlay)
	if err != nil {
		t.Fatalf("compositionPlanFrom: %v", err)
	}
	input.Fixture = FixtureBinding{
		Root:                t.TempDir(),
		ParentDevice:        1,
		ParentInode:         2,
		RequiredEmptyDigest: inputDigestA,
		ExecutionOwnerUID:   501,
	}
	if err := os.Mkdir(
		filepath.Join(input.Fixture.Root, "state"),
		0o700,
	); err != nil {
		t.Fatalf("Mkdir state: %v", err)
	}
	trace := []string{}
	handle, err := compositionCleanupHandle(
		CleanupTestProcess,
		"portable-ghar.task11.workspace.v1\x00",
		input.Authorization.RunID,
	)
	if err != nil {
		t.Fatalf("compositionCleanupHandle: %v", err)
	}
	workspace, err := newFixtureWorkspace(
		&fakeFixtureWorkspaceOperations{
			trace: &trace,
			database: filepath.Join(
				input.Fixture.Root,
				"state",
				"controller.db",
			),
		},
		handle,
	)
	if err != nil {
		t.Fatalf("newFixtureWorkspace: %v", err)
	}
	backend, err := newFixtureRuntimeBackend(
		input,
		plan,
		"65532:65532",
		workspace,
		&fakeFixtureRootRemover{
			trace: &trace,
			handle: cleanupHandle{
				kind: CleanupFixtureRoot,
				id:   inputDigestA,
			},
		},
		state.OpenWithHistoryLimits,
		func(
			context.Context,
			*state.SQLiteStore,
			func(cleanupHandle) error,
		) (fixtureRuntimeGraph, error) {
			return &fakeFixtureRuntimeGraph{
				trace:   &trace,
				removed: make(map[cleanupHandle]bool),
			}, nil
		},
		time.Now,
	)
	if err != nil {
		t.Fatalf("newFixtureRuntimeBackend: %v", err)
	}
	record := func(cleanupHandle) error { return nil }
	if err := backend.Start(context.Background(), record); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := backend.Start(
		context.Background(),
		record,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("duplicate Start error = %v", err)
	}
}
