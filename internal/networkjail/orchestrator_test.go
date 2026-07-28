package networkjail

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

type fakeSetupRuntime struct {
	events        *[]string
	failAt        string
	cleanupFailAt string
	invalidAt     string
}

func (f *fakeSetupRuntime) event(name string) error {
	*f.events = append(*f.events, name)
	if f.failAt == name || f.cleanupFailAt == name {
		return errors.New("injected runtime failure")
	}
	return nil
}

func (f *fakeSetupRuntime) CreateAdapter(context.Context, hostruntime.AdapterSpec) (adapterRuntimeRef, error) {
	err := f.event("runtime:create-adapter")
	return adapterRuntimeRef{id: "adapter-id", valid: err == nil}, err
}

func (f *fakeSetupRuntime) CreateBroker(context.Context, adapterRuntimeRef, hostruntime.BrokerSpec) (brokerRuntimeRef, error) {
	err := f.event("runtime:create-broker")
	return brokerRuntimeRef{id: "broker-id", valid: true}, err
}

func (f *fakeSetupRuntime) ApplyPolicy(context.Context, brokerRuntimeRef, hostruntime.PolicyArtifact) error {
	return f.event("runtime:apply-policy")
}

func (f *fakeSetupRuntime) BindAuthority(context.Context, brokerRuntimeRef, authorityLease) error {
	return f.event("runtime:bind-authority")
}

func (f *fakeSetupRuntime) ReleaseBroker(context.Context, brokerRuntimeRef) (brokerPeerRuntimeRef, error) {
	err := f.event("runtime:release-broker")
	return brokerPeerRuntimeRef{valid: err == nil && f.invalidAt != "runtime:release-broker"}, err
}

func (f *fakeSetupRuntime) BindBrokerPeer(context.Context, adapterRuntimeRef, brokerPeerRuntimeRef) error {
	return f.event("runtime:bind-peer")
}

func (f *fakeSetupRuntime) AuditBroker(context.Context, brokerRuntimeRef) (brokerAuditRuntimeRef, error) {
	err := f.event("runtime:audit-broker")
	return brokerAuditRuntimeRef{
		digest: strings.Repeat("a", 64),
		valid:  err == nil && f.invalidAt != "runtime:audit-broker",
	}, err
}

func (f *fakeSetupRuntime) CreateRunner(context.Context, adapterRuntimeRef, hostruntime.RunnerSpec) (runnerRuntimeRef, error) {
	err := f.event("runtime:create-runner")
	return runnerRuntimeRef{id: "runner-id", valid: err == nil}, err
}

func (f *fakeSetupRuntime) HydrateSeeds(context.Context, runnerRuntimeRef, []string) error {
	return f.event("runtime:hydrate-seeds")
}

func (f *fakeSetupRuntime) ProbeNamespace(_ context.Context, _ runnerRuntimeRef, operation hostruntime.GateOperation) (namespaceRuntimeRef, error) {
	name := "runtime:namespace-prearm"
	if operation == hostruntime.GateNetNSIDFinal {
		name = "runtime:namespace-final"
	}
	err := f.event(name)
	return namespaceRuntimeRef{valid: err == nil && f.invalidAt != name}, err
}

func (f *fakeSetupRuntime) ArmRunner(context.Context, runnerRuntimeRef) error {
	return f.event("runtime:arm-runner")
}

func (f *fakeSetupRuntime) AuditHeldRunner(context.Context, runnerRuntimeRef) (heldRunnerAuditRuntimeRef, error) {
	err := f.event("runtime:audit-held-runner")
	return heldRunnerAuditRuntimeRef{
		digest: strings.Repeat("b", 64),
		valid:  err == nil && f.invalidAt != "runtime:audit-held-runner",
	}, err
}

func (f *fakeSetupRuntime) AuthorizeRelease(context.Context, runnerRuntimeRef, namespaceRuntimeRef, namespaceRuntimeRef) (releaseAuthorizationRuntimeRef, error) {
	err := f.event("runtime:authorize-runner")
	return releaseAuthorizationRuntimeRef{
		valid: err == nil && f.invalidAt != "runtime:authorize-runner",
	}, err
}

func (f *fakeSetupRuntime) ReleaseRunner(_ context.Context, _ runnerRuntimeRef, _ releaseAuthorizationRuntimeRef, jit *redaction.Secret) error {
	if jit != nil {
		jit.Destroy()
	}
	return f.event("runtime:release-listener")
}

func (f *fakeSetupRuntime) RemoveRunner(context.Context, runnerRuntimeRef) error {
	return f.event("cleanup:runner")
}

func (f *fakeSetupRuntime) RemoveBroker(context.Context, brokerRuntimeRef) error {
	return f.event("cleanup:broker")
}

func (f *fakeSetupRuntime) RemoveAdapter(context.Context, adapterRuntimeRef) error {
	return f.event("cleanup:adapter")
}

type fakeAuthorityManager struct {
	events *[]string
	failAt string
}

func (f *fakeAuthorityManager) Start(_ context.Context, request authorityRequest) (authorityLease, error) {
	*f.events = append(*f.events, "authority:start")
	if f.failAt == "authority:start" {
		return authorityLease{}, errors.New("injected authority failure")
	}
	return authorityLease{
		slotID: request.slotID, jobGeneration: request.jobGeneration, valid: true,
	}, nil
}

func (f *fakeAuthorityManager) Stop(context.Context, authorityLease) error {
	*f.events = append(*f.events, "cleanup:authority")
	if f.failAt == "cleanup:authority" {
		return errors.New("injected authority cleanup failure")
	}
	return nil
}

type fakeSetupVerifier struct {
	events    *[]string
	failAt    string
	corruptAt string
}

func (f *fakeSetupVerifier) event(name string) error {
	*f.events = append(*f.events, name)
	if f.failAt == name {
		return errors.New("injected verifier failure")
	}
	return nil
}

func (f *fakeSetupVerifier) VerifyAdapterEmpty(
	_ context.Context,
	adapter adapterRuntimeRef,
	_ hostruntime.VerifierSpec,
) (adapterEmptinessProof, error) {
	err := f.event("verify:adapter-empty")
	adapterID := adapter.id
	if f.corruptAt == "verify:adapter-empty" {
		adapterID = "wrong-adapter"
	}
	return adapterEmptinessProof{
		adapterID: adapterID, digest: sha256.Sum256([]byte("empty")), valid: err == nil,
	}, err
}

func (f *fakeSetupVerifier) VerifyEgress(
	_ context.Context,
	adapter adapterRuntimeRef,
	broker brokerRuntimeRef,
	policy hostruntime.PolicyArtifact,
	_ hostruntime.VerifierSpec,
) (egressVerification, error) {
	err := f.event("verify:egress")
	policyDigest := policy.Digest()
	if f.corruptAt == "verify:egress" {
		policyDigest = strings.Repeat("f", 64)
	}
	return egressVerification{
		adapterID: adapter.id, brokerID: broker.id, policy: policyDigest,
		digest: sha256.Sum256([]byte("egress")), valid: err == nil,
	}, err
}

func (f *fakeSetupVerifier) FinalAudit(_ context.Context, request finalAuditRequest) (finalAuditProof, error) {
	err := f.event("verify:final-audit")
	brokerAudit := request.brokerAudit.digest
	if f.corruptAt == "verify:final-audit" {
		brokerAudit = strings.Repeat("f", 64)
	}
	return finalAuditProof{
		adapterID: request.adapter.id, brokerID: request.broker.id,
		runnerID: request.runner.id, policy: request.policy.Digest(),
		brokerAudit: brokerAudit,
		heldAudit:   request.heldAudit.digest,
		budget:      request.budget.Digest.String(),
		report: ProbeReport{
			Version:              1,
			PolicyDigest:         request.graph.Digest().String(),
			EgressBackend:        RestrictedBrokerV1,
			RunnerNetNSID:        NamespaceIdentity{Device: 11, Inode: 12},
			BrokerNetNSID:        NamespaceIdentity{Device: 21, Inode: 22},
			RunnerLoopbackOnly:   true,
			RunnerTablesEmpty:    true,
			RunnerConntrackEmpty: true,
			ParserHasNoSocket:    true,
			PositiveOK:           true,
			NegativeOK:           true,
			ConntrackBudgetOK:    true,
		},
		digest: sha256.Sum256([]byte("final")), valid: err == nil,
	}, err
}

type fakeLifecycleJournal struct {
	events   *[]string
	failAt   string
	replayAt SetupStage
}

func (j *fakeLifecycleJournal) Before(_ context.Context, _ controller.AssignmentKey, stage SetupStage) error {
	event := "journal:before:" + stage.String()
	*j.events = append(*j.events, event)
	if j.replayAt == stage {
		return ErrSetupReplay
	}
	if j.failAt == event {
		return errors.New("injected journal failure")
	}
	return nil
}

func (j *fakeLifecycleJournal) Complete(_ context.Context, _ controller.AssignmentKey, stage SetupStage, result JournalResult) error {
	suffix := "success"
	if result.Failure {
		suffix = "failure"
	}
	event := "journal:complete:" + stage.String() + ":" + suffix
	*j.events = append(*j.events, event)
	if j.failAt == event {
		return errors.New("injected journal failure")
	}
	return nil
}

func (j *fakeLifecycleJournal) Advance(_ context.Context, _ controller.AssignmentKey, next controller.State) error {
	event := "journal:advance:" + string(next)
	*j.events = append(*j.events, event)
	if j.failAt == event {
		return errors.New("injected journal failure")
	}
	return nil
}

func (j *fakeLifecycleJournal) MarkAmbiguous(context.Context, controller.AssignmentKey) error {
	*j.events = append(*j.events, "journal:ambiguous")
	return nil
}

func validSetupRequest(t *testing.T) SetupRequest {
	t.Helper()
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	policy, err := CompilePolicyArtifact(graph)
	if err != nil {
		t.Fatalf("CompilePolicyArtifact: %v", err)
	}
	slotIdentity := "pghar-slot-" + strings.Repeat("1", 32)
	return SetupRequest{
		Key: controller.AssignmentKey{
			RepositoryAlias: "repo-a", RunnerRequestID: 42, Attempt: 1,
		},
		Adapter: hostruntime.AdapterSpec{
			BuildID: strings.Repeat("b", 64), FleetGeneration: 17,
			SlotIdentity: slotIdentity,
		},
		Broker: hostruntime.BrokerSpec{
			BuildID: strings.Repeat("b", 64), FleetGeneration: 17,
			CapacitySlotID: 7, JobGeneration: 19,
			AuthorityParent: "/synthetic/authority", User: "65532:65532",
			SlotIdentity: slotIdentity,
		},
		Runner: hostruntime.RunnerSpec{
			BuildID: strings.Repeat("b", 64), FleetGeneration: 17,
			SlotIdentity: slotIdentity,
		},
		Verifier: hostruntime.VerifierSpec{
			Image: "portable-ghar/network-verifier@sha256:" +
				strings.Repeat("9", 64),
			BuildID:         strings.Repeat("b", 64),
			FleetGeneration: 17,
			SlotIdentity:    slotIdentity,
			User:            "65532:65532",
		},
		Graph:             graph,
		Policy:            policy,
		ConntrackInput:    Budget{NFConntrackMax: 1_000, NFConntrackCount: 100, TailTimeoutID: "tail-v1"},
		MaxRunnerCapacity: 3,
		SeedIDs:           []string{"seed-a"},
		JIT:               redaction.SecretFromBytes([]byte("synthetic-jit")),
	}
}

func TestOrchestratorPersistsExactOrderAndAuditsBeforeArm(t *testing.T) {
	var events []string
	runtime := &fakeSetupRuntime{events: &events}
	authority := &fakeAuthorityManager{events: &events}
	verifier := &fakeSetupVerifier{events: &events}
	journal := &fakeLifecycleJournal{events: &events}
	orchestrator, err := newOrchestrator(runtime, journal, authority, verifier)
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	live, err := orchestrator.Configure(context.Background(), validSetupRequest(t))
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if live.AdapterID() != "adapter-id" ||
		live.BrokerID() != "broker-id" ||
		live.RunnerID() != "runner-id" {
		t.Fatalf("live jail identities = %q/%q/%q", live.AdapterID(), live.BrokerID(), live.RunnerID())
	}
	if err := ValidateProbeReport(live.ProbeReport()); err != nil {
		t.Fatalf("live probe report: %v", err)
	}
	assertEventBefore(t, events, "verify:final-audit", "runtime:arm-runner")
	assertEventBefore(t, events, "runtime:audit-broker", "verify:final-audit")
	assertEventBefore(t, events, "runtime:audit-held-runner", "verify:final-audit")
	assertEventBefore(t, events, "runtime:authorize-runner", "journal:advance:RELEASE_ARMED")
	assertEventBefore(t, events, "journal:advance:RELEASE_ARMED", "runtime:release-listener")
	assertEventBefore(t, events, "runtime:release-listener", "journal:advance:LISTENER_RELEASED")
	for _, state := range []controller.State{
		controller.StateAdapterCreated,
		controller.StateAdapterVerified,
		controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified,
		controller.StateRunnerHeld,
		controller.StateReleaseArmed,
		controller.StateListenerReleased,
	} {
		if !slices.Contains(events, "journal:advance:"+string(state)) {
			t.Errorf("missing durable state %s: %q", state, events)
		}
	}
	if slices.Contains(events, "cleanup:runner") ||
		slices.Contains(events, "cleanup:broker") ||
		slices.Contains(events, "cleanup:authority") ||
		slices.Contains(events, "cleanup:adapter") {
		t.Fatalf("successful setup performed cleanup: %q", events)
	}
}

func TestOrchestratorAcceptsInitialAssignmentAttemptZero(t *testing.T) {
	request := validSetupRequest(t)
	request.Key.Attempt = 0
	defer request.JIT.Destroy()
	if err := validatePreparedSetupRequest(preparedSetupRequest(request)); err != nil {
		t.Fatalf("validatePreparedSetupRequest(initial attempt zero) = %v", err)
	}
}

func TestOrchestratorPrepareStopsAtReleaseArmedWithoutJIT(t *testing.T) {
	var events []string
	runtime := &fakeSetupRuntime{events: &events}
	authority := &fakeAuthorityManager{events: &events}
	verifier := &fakeSetupVerifier{events: &events}
	journal := &fakeLifecycleJournal{events: &events}
	orchestrator, err := newOrchestrator(runtime, journal, authority, verifier)
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	setup := validSetupRequest(t)
	jit := setup.JIT
	setup.JIT = nil
	held, err := orchestrator.Prepare(context.Background(), PreparedSetupRequest{
		Key:               setup.Key,
		Adapter:           setup.Adapter,
		Broker:            setup.Broker,
		Runner:            setup.Runner,
		Verifier:          setup.Verifier,
		Graph:             setup.Graph,
		Policy:            setup.Policy,
		ConntrackInput:    setup.ConntrackInput,
		MaxRunnerCapacity: setup.MaxRunnerCapacity,
		SeedIDs:           setup.SeedIDs,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(jit.Destroy)
	if held.AdapterID() != "adapter-id" ||
		held.BrokerID() != "broker-id" ||
		held.RunnerID() != "runner-id" {
		t.Fatalf(
			"held jail identities = %q/%q/%q",
			held.AdapterID(),
			held.BrokerID(),
			held.RunnerID(),
		)
	}
	if !slices.Contains(events, "journal:advance:RELEASE_ARMED") {
		t.Fatalf("Prepare did not persist RELEASE_ARMED: %q", events)
	}
	if slices.Contains(events, "runtime:release-listener") ||
		slices.Contains(events, "journal:advance:LISTENER_RELEASED") {
		t.Fatalf("Prepare crossed listener-release boundary: %q", events)
	}
	if err := jit.Use(func(io.Reader) error { return nil }); err != nil {
		t.Fatalf("Prepare consumed caller-owned JIT: %v", err)
	}
}

func TestOrchestratorDestroyHeldRemovesResourcesWithoutDurableTransition(t *testing.T) {
	var events []string
	runtime := &fakeSetupRuntime{events: &events}
	authority := &fakeAuthorityManager{events: &events}
	verifier := &fakeSetupVerifier{events: &events}
	journal := &fakeLifecycleJournal{events: &events}
	orchestrator, err := newOrchestrator(runtime, journal, authority, verifier)
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	setup := validSetupRequest(t)
	defer setup.JIT.Destroy()
	held, err := orchestrator.Prepare(
		context.Background(),
		preparedSetupRequest(setup),
	)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	beforeDestroy := len(events)
	if err := orchestrator.DestroyHeld(context.Background(), held); err != nil {
		t.Fatalf("DestroyHeld: %v", err)
	}
	destroyEvents := events[beforeDestroy:]
	for _, expected := range []string{
		"cleanup:runner",
		"cleanup:broker",
		"cleanup:authority",
		"cleanup:adapter",
	} {
		if !slices.Contains(destroyEvents, expected) {
			t.Errorf("DestroyHeld missing %s: %q", expected, destroyEvents)
		}
	}
	if slices.Contains(destroyEvents, "journal:advance:DESTROYED") ||
		slices.Contains(destroyEvents, "runtime:release-listener") {
		t.Fatalf("DestroyHeld crossed lifecycle boundary: %q", destroyEvents)
	}
}

func TestOrchestratorDestroyLiveRemovesResourcesWithoutDurableTransition(t *testing.T) {
	var events []string
	runtime := &fakeSetupRuntime{events: &events}
	authority := &fakeAuthorityManager{events: &events}
	verifier := &fakeSetupVerifier{events: &events}
	journal := &fakeLifecycleJournal{events: &events}
	orchestrator, err := newOrchestrator(runtime, journal, authority, verifier)
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	setup := validSetupRequest(t)
	jit := setup.JIT
	setup.JIT = nil
	held, err := orchestrator.Prepare(
		context.Background(),
		PreparedSetupRequest{
			Key:               setup.Key,
			Adapter:           setup.Adapter,
			Broker:            setup.Broker,
			Runner:            setup.Runner,
			Verifier:          setup.Verifier,
			Graph:             setup.Graph,
			Policy:            setup.Policy,
			ConntrackInput:    setup.ConntrackInput,
			MaxRunnerCapacity: setup.MaxRunnerCapacity,
			SeedIDs:           setup.SeedIDs,
		},
	)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	live, err := orchestrator.Release(context.Background(), held, jit)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	beforeDestroy := len(events)
	if err := orchestrator.DestroyLive(context.Background(), live); err != nil {
		t.Fatalf("DestroyLive: %v", err)
	}
	destroyEvents := events[beforeDestroy:]
	for _, expected := range []string{
		"cleanup:runner",
		"cleanup:broker",
		"cleanup:authority",
		"cleanup:adapter",
	} {
		if !slices.Contains(destroyEvents, expected) {
			t.Errorf("DestroyLive missing %s: %q", expected, destroyEvents)
		}
	}
	if slices.Contains(destroyEvents, "journal:advance:DESTROYED") {
		t.Fatalf("DestroyLive advanced durable state: %q", destroyEvents)
	}
}

func TestOrchestratorReleaseInvocationFailureRemainsAmbiguousWithoutCleanup(t *testing.T) {
	var events []string
	runtime := &fakeSetupRuntime{
		events: &events,
		failAt: "runtime:release-listener",
	}
	authority := &fakeAuthorityManager{events: &events}
	verifier := &fakeSetupVerifier{events: &events}
	journal := &fakeLifecycleJournal{events: &events}
	orchestrator, err := newOrchestrator(runtime, journal, authority, verifier)
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	setup := validSetupRequest(t)
	jit := setup.JIT
	setup.JIT = nil
	held, err := orchestrator.Prepare(context.Background(), PreparedSetupRequest{
		Key:               setup.Key,
		Adapter:           setup.Adapter,
		Broker:            setup.Broker,
		Runner:            setup.Runner,
		Verifier:          setup.Verifier,
		Graph:             setup.Graph,
		Policy:            setup.Policy,
		ConntrackInput:    setup.ConntrackInput,
		MaxRunnerCapacity: setup.MaxRunnerCapacity,
		SeedIDs:           setup.SeedIDs,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := orchestrator.Release(context.Background(), held, jit); !errors.Is(err, ErrListenerAmbiguous) {
		t.Fatalf("Release error = %v, want ErrListenerAmbiguous", err)
	}
	if !slices.Contains(events, "journal:before:runner-listener-release") {
		t.Fatalf("listener-release intent was not durable before invocation: %q", events)
	}
	for _, forbidden := range []string{
		"cleanup:runner",
		"cleanup:broker",
		"cleanup:authority",
		"cleanup:adapter",
	} {
		if slices.Contains(events, forbidden) {
			t.Fatalf("ambiguous release performed %s: %q", forbidden, events)
		}
	}
	if err := jit.Use(func(io.Reader) error { return nil }); err == nil {
		t.Fatal("Release failure left JIT usable")
	}
}

func TestValidateSetupRequestBindsGraphPolicyAndConntrackBudget(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SetupRequest)
	}{
		{
			name: "zero capacity",
			mutate: func(request *SetupRequest) {
				request.MaxRunnerCapacity = 0
			},
		},
		{
			name: "unavailable headroom",
			mutate: func(request *SetupRequest) {
				request.ConntrackInput.NFConntrackMax = 10
			},
		},
		{
			name: "policy graph mismatch",
			mutate: func(request *SetupRequest) {
				manifest := validPolicyManifest()
				manifest.JobDialRate++
				graph, _, err := Compile(manifest)
				if err != nil {
					t.Fatalf("Compile mutation: %v", err)
				}
				request.Graph = graph
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validSetupRequest(t)
			test.mutate(&request)
			if err := validateSetupRequest(request); err == nil {
				t.Fatal("validateSetupRequest accepted inconsistent proof inputs")
			}
			request.JIT.Destroy()
		})
	}
}

func TestOrchestratorFaultInjectionNeverArmsEarlyAndCleansReverseOwnership(t *testing.T) {
	failures := []string{
		"runtime:create-adapter",
		"verify:adapter-empty",
		"runtime:create-broker",
		"runtime:apply-policy",
		"authority:start",
		"runtime:bind-authority",
		"runtime:release-broker",
		"runtime:bind-peer",
		"verify:egress",
		"runtime:create-runner",
		"runtime:hydrate-seeds",
		"runtime:namespace-prearm",
		"runtime:audit-broker",
		"verify:final-audit",
		"runtime:arm-runner",
		"runtime:namespace-final",
		"runtime:audit-held-runner",
		"runtime:authorize-runner",
	}
	for _, failAt := range failures {
		t.Run(failAt, func(t *testing.T) {
			var events []string
			runtime := &fakeSetupRuntime{events: &events}
			authority := &fakeAuthorityManager{events: &events}
			verifier := &fakeSetupVerifier{events: &events}
			switch {
			case strings.HasPrefix(failAt, "runtime:"):
				runtime.failAt = failAt
			case strings.HasPrefix(failAt, "verify:"):
				verifier.failAt = failAt
			case strings.HasPrefix(failAt, "authority:"):
				authority.failAt = failAt
			}
			journal := &fakeLifecycleJournal{events: &events}
			orchestrator, err := newOrchestrator(runtime, journal, authority, verifier)
			if err != nil {
				t.Fatalf("newOrchestrator: %v", err)
			}
			request := validSetupRequest(t)
			if _, err := orchestrator.Configure(context.Background(), request); err == nil {
				t.Fatal("Configure accepted injected failure")
			}
			if slices.Contains(events, "journal:advance:LISTENER_RELEASED") {
				t.Fatalf("failure advanced listener release: %q", events)
			}
			if eventIndex(events, "verify:final-audit") < 0 &&
				slices.Contains(events, "runtime:arm-runner") {
				t.Fatalf("runner armed before final audit: %q", events)
			}
			assertCleanupReverseOrder(t, events)
			if !slices.Contains(events, "journal:advance:DESTROYED") {
				t.Fatalf("pre-release failure was not destroyed: %q", events)
			}
			if useErr := request.JIT.Use(func(io.Reader) error { return nil }); useErr == nil {
				t.Fatal("JIT remained usable after failed setup")
			}
		})
	}
}

func TestOrchestratorListenerCheckpointFailureMarksAmbiguousWithoutCleanup(t *testing.T) {
	var events []string
	runtime := &fakeSetupRuntime{events: &events}
	authority := &fakeAuthorityManager{events: &events}
	verifier := &fakeSetupVerifier{events: &events}
	journal := &fakeLifecycleJournal{
		events: &events,
		failAt: "journal:advance:LISTENER_RELEASED",
	}
	orchestrator, err := newOrchestrator(runtime, journal, authority, verifier)
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	if _, err := orchestrator.Configure(context.Background(), validSetupRequest(t)); !errors.Is(err, ErrListenerAmbiguous) {
		t.Fatalf("Configure error = %v, want ErrListenerAmbiguous", err)
	}
	if !slices.Contains(events, "journal:ambiguous") {
		t.Fatalf("listener checkpoint failure was not marked ambiguous: %q", events)
	}
	for _, cleanup := range []string{"cleanup:runner", "cleanup:broker", "cleanup:authority", "cleanup:adapter"} {
		if slices.Contains(events, cleanup) {
			t.Fatalf("post-release ambiguity performed %s: %q", cleanup, events)
		}
	}
}

func TestOrchestratorRejectsCorruptRuntimeAndVerifierProofs(t *testing.T) {
	tests := []struct {
		name            string
		invalidRuntime  string
		corruptVerifier string
	}{
		{name: "adapter-emptiness", corruptVerifier: "verify:adapter-empty"},
		{name: "broker-peer", invalidRuntime: "runtime:release-broker"},
		{name: "egress", corruptVerifier: "verify:egress"},
		{name: "broker-audit", invalidRuntime: "runtime:audit-broker"},
		{name: "final-audit", corruptVerifier: "verify:final-audit"},
		{name: "pre-arm-namespace", invalidRuntime: "runtime:namespace-prearm"},
		{name: "final-namespace", invalidRuntime: "runtime:namespace-final"},
		{name: "held-runner-audit", invalidRuntime: "runtime:audit-held-runner"},
		{name: "release-authorization", invalidRuntime: "runtime:authorize-runner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			runtime := &fakeSetupRuntime{
				events:    &events,
				invalidAt: test.invalidRuntime,
			}
			verifier := &fakeSetupVerifier{
				events:    &events,
				corruptAt: test.corruptVerifier,
			}
			orchestrator, err := newOrchestrator(
				runtime,
				&fakeLifecycleJournal{events: &events},
				&fakeAuthorityManager{events: &events},
				verifier,
			)
			if err != nil {
				t.Fatalf("newOrchestrator: %v", err)
			}
			if _, err := orchestrator.Configure(
				context.Background(),
				validSetupRequest(t),
			); !errors.Is(err, ErrSetupFailed) {
				t.Fatalf("Configure error = %v, want ErrSetupFailed", err)
			}
			if slices.Contains(events, "runtime:release-listener") {
				t.Fatalf("corrupt proof released listener: %q", events)
			}
			assertCleanupReverseOrder(t, events)
			if !slices.Contains(events, "journal:advance:DESTROYED") {
				t.Fatalf("corrupt proof did not reach DESTROYED: %q", events)
			}
		})
	}
}

func TestOrchestratorJournalIntentAndCompletionFailuresFailClosed(t *testing.T) {
	for _, stage := range allSetupStages() {
		for _, point := range []string{"before", "complete"} {
			t.Run(stage.String()+"/"+point, func(t *testing.T) {
				var events []string
				failAt := "journal:" + point + ":" + stage.String()
				if point == "complete" {
					failAt += ":success"
				}
				orchestrator, err := newOrchestrator(
					&fakeSetupRuntime{events: &events},
					&fakeLifecycleJournal{events: &events, failAt: failAt},
					&fakeAuthorityManager{events: &events},
					&fakeSetupVerifier{events: &events},
				)
				if err != nil {
					t.Fatalf("newOrchestrator: %v", err)
				}
				_, configureErr := orchestrator.Configure(
					context.Background(),
					validSetupRequest(t),
				)
				if stage == StageListenerRelease && point == "complete" {
					if !errors.Is(configureErr, ErrListenerAmbiguous) {
						t.Fatalf("Configure error = %v, want ErrListenerAmbiguous", configureErr)
					}
					if !slices.Contains(events, "journal:ambiguous") {
						t.Fatalf("listener completion failure was not marked ambiguous: %q", events)
					}
					for _, cleanup := range []string{
						"cleanup:runner",
						"cleanup:broker",
						"cleanup:authority",
						"cleanup:adapter",
					} {
						if slices.Contains(events, cleanup) {
							t.Fatalf("post-release ambiguity performed %s: %q", cleanup, events)
						}
					}
					return
				}
				if !errors.Is(configureErr, ErrSetupFailed) {
					t.Fatalf("Configure error = %v, want ErrSetupFailed", configureErr)
				}
				assertCleanupReverseOrder(t, events)
				if !slices.Contains(events, "journal:advance:DESTROYED") {
					t.Fatalf("journal failure did not reach DESTROYED: %q", events)
				}
				if point == "before" {
					action := setupStageAction(stage)
					failureIndex := eventIndex(events, failAt)
					if failureIndex < 0 {
						t.Fatalf("missing failed journal intent %q: %q", failAt, events)
					}
					if action != "" && slices.Contains(events[failureIndex+1:], action) {
						t.Fatalf("external action ran without durable intent: %q", events)
					}
				}
			})
		}
	}
}

func TestOrchestratorCheckpointFailuresBeforeReleaseCleanUp(t *testing.T) {
	for _, state := range []controller.State{
		controller.StateAdapterCreated,
		controller.StateAdapterVerified,
		controller.StateBrokerHeld,
		controller.StateBrokerPolicyApplied,
		controller.StateDialAuthorityReady,
		controller.StateBrokerReleased,
		controller.StateEgressVerified,
		controller.StateRunnerHeld,
		controller.StateReleaseArmed,
	} {
		t.Run(string(state), func(t *testing.T) {
			var events []string
			orchestrator, err := newOrchestrator(
				&fakeSetupRuntime{events: &events},
				&fakeLifecycleJournal{
					events: &events,
					failAt: "journal:advance:" + string(state),
				},
				&fakeAuthorityManager{events: &events},
				&fakeSetupVerifier{events: &events},
			)
			if err != nil {
				t.Fatalf("newOrchestrator: %v", err)
			}
			if _, err := orchestrator.Configure(
				context.Background(),
				validSetupRequest(t),
			); !errors.Is(err, ErrSetupFailed) {
				t.Fatalf("Configure error = %v, want ErrSetupFailed", err)
			}
			if slices.Contains(events, "runtime:release-listener") {
				t.Fatalf("failed checkpoint released listener: %q", events)
			}
			assertCleanupReverseOrder(t, events)
			if !slices.Contains(events, "journal:advance:DESTROYED") {
				t.Fatalf("checkpoint failure did not reach DESTROYED: %q", events)
			}
		})
	}
}

func TestOrchestratorReplayDoesNotRepeatExternalEffect(t *testing.T) {
	for _, stage := range []SetupStage{StageAdapterCreate, StageBrokerCreate} {
		t.Run(stage.String(), func(t *testing.T) {
			var events []string
			request := validSetupRequest(t)
			orchestrator, err := newOrchestrator(
				&fakeSetupRuntime{events: &events},
				&fakeLifecycleJournal{events: &events, replayAt: stage},
				&fakeAuthorityManager{events: &events},
				&fakeSetupVerifier{events: &events},
			)
			if err != nil {
				t.Fatalf("newOrchestrator: %v", err)
			}
			if _, err := orchestrator.Configure(
				context.Background(),
				request,
			); !errors.Is(err, ErrSetupReplay) {
				t.Fatalf("Configure error = %v, want ErrSetupReplay", err)
			}
			if action := setupStageAction(stage); slices.Contains(events, action) {
				t.Fatalf("replay repeated external action %s: %q", action, events)
			}
			if stage == StageAdapterCreate &&
				slices.Contains(events, "journal:advance:DESTROYED") {
				t.Fatalf("unknown replay state was blindly destroyed: %q", events)
			}
			if useErr := request.JIT.Use(func(io.Reader) error { return nil }); useErr == nil {
				t.Fatal("JIT remained usable after replay rejection")
			}
		})
	}
}

func TestOrchestratorCleanupFailureAttemptsRemainingOwnersAndStaysRecoverable(t *testing.T) {
	var events []string
	runtime := &fakeSetupRuntime{
		events:        &events,
		failAt:        "runtime:hydrate-seeds",
		cleanupFailAt: "cleanup:broker",
	}
	orchestrator, err := newOrchestrator(
		runtime,
		&fakeLifecycleJournal{events: &events},
		&fakeAuthorityManager{events: &events},
		&fakeSetupVerifier{events: &events},
	)
	if err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	if _, err := orchestrator.Configure(
		context.Background(),
		validSetupRequest(t),
	); !errors.Is(err, ErrSetupCleanup) {
		t.Fatalf("Configure error = %v, want ErrSetupCleanup", err)
	}
	for _, cleanup := range []string{
		"cleanup:runner",
		"cleanup:broker",
		"cleanup:authority",
		"cleanup:adapter",
	} {
		if !slices.Contains(events, cleanup) {
			t.Fatalf("cleanup failure skipped %s: %q", cleanup, events)
		}
	}
	if slices.Contains(events, "journal:advance:DESTROYED") {
		t.Fatalf("incomplete cleanup was marked DESTROYED: %q", events)
	}
}

func allSetupStages() []SetupStage {
	stages := make([]SetupStage, 0, int(StageListenerRelease))
	for stage := StageAdapterCreate; stage <= StageListenerRelease; stage++ {
		stages = append(stages, stage)
	}
	return stages
}

func setupStageAction(stage SetupStage) string {
	switch stage {
	case StageAdapterCreate:
		return "runtime:create-adapter"
	case StageAdapterEmpty:
		return "verify:adapter-empty"
	case StageBrokerCreate:
		return "runtime:create-broker"
	case StagePolicyApply:
		return "runtime:apply-policy"
	case StageAuthorityStart:
		return "authority:start"
	case StageAuthorityBind:
		return "runtime:bind-authority"
	case StageBrokerRelease:
		return "runtime:release-broker"
	case StageAdapterBind:
		return "runtime:bind-peer"
	case StageEgressVerify:
		return "verify:egress"
	case StageRunnerCreate:
		return "runtime:create-runner"
	case StageSeedHydrate:
		return "runtime:hydrate-seeds"
	case StageNamespacePreArm:
		return "runtime:namespace-prearm"
	case StageFinalAudit:
		return "runtime:audit-broker"
	case StageRunnerArm:
		return "runtime:arm-runner"
	case StageNamespaceFinal:
		return "runtime:namespace-final"
	case StageRunnerAuthorize:
		return "runtime:audit-held-runner"
	case StageListenerRelease:
		return "runtime:release-listener"
	default:
		return ""
	}
}

func assertEventBefore(t *testing.T, events []string, first, second string) {
	t.Helper()
	firstIndex := eventIndex(events, first)
	secondIndex := eventIndex(events, second)
	if firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex {
		t.Fatalf("%q must precede %q: %q", first, second, events)
	}
}

func eventIndex(events []string, want string) int {
	for index, event := range events {
		if event == want {
			return index
		}
	}
	return -1
}

func assertCleanupReverseOrder(t *testing.T, events []string) {
	t.Helper()
	previous := -1
	for _, cleanup := range []string{"cleanup:runner", "cleanup:broker", "cleanup:authority", "cleanup:adapter"} {
		index := eventIndex(events, cleanup)
		if index < 0 {
			continue
		}
		if previous >= index {
			t.Fatalf("cleanup is not reverse ownership order: %q", events)
		}
		previous = index
	}
}
