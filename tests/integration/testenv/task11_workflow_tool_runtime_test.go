package testenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestTask11WorkflowToolRuntimeRunsExactRegisteredOneShot(
	t *testing.T,
) {
	t.Parallel()

	runtime, owner, runner, recorded, bindings, users, limits, seccomp :=
		validTask11WorkflowToolRuntime(t)
	binding := bindings[0]
	action, ok := workflowToolActionFor(binding.ProbeID)
	if !ok {
		t.Fatal("workflowToolActionFor rejected fixture binding")
	}
	lease, ok := workflowToolLeaseFor(
		owner.observation.Runner.id,
		binding.ProbeID,
	)
	if !ok {
		t.Fatal("workflowToolLeaseFor rejected fixture binding")
	}
	spec := workflowToolProbeSpec{
		ProbeID:            binding.ProbeID,
		Action:             action,
		Name:               lease.Name,
		ImageReference:     binding.ImageReference,
		ImageDigest:        binding.ImageDigest,
		User:               users[0],
		NetworkContainerID: owner.observation.Runner.id,
		Seccomp:            seccomp,
		Limits:             limits,
	}
	document := workflowToolOutputDocumentForTest(spec, WorkflowToolSupported)
	runner.results = []orderedClosedResult{
		{result: hostruntime.Result{Stdout: document}},
		{result: closedAbsentResultForTest(lease.Name)},
	}

	registration, err := runtime.RegisterWorkflowToolCleanup(
		context.Background(),
		lease,
	)
	if err != nil || !isLowerHex(registration, 64) {
		t.Fatalf("registration = %q err=%v", registration, err)
	}
	if len(*recorded) != 1 ||
		(*recorded)[0] != (cleanupHandle{
			kind: CleanupVerifier,
			id:   lease.IdentityDigest,
		}) {
		t.Fatalf("recorded = %+v", *recorded)
	}
	execution, err := runtime.RunWorkflowTool(
		context.Background(),
		spec,
	)
	if err != nil ||
		execution.ProbeID != spec.ProbeID ||
		execution.Status != WorkflowToolSupported ||
		execution.OutputBytes != uint64(len(document)) ||
		!isLowerHex(execution.OutputDigest, 64) ||
		!isLowerHex(execution.InvocationDigest, 64) {
		t.Fatalf("execution = %+v err=%v", execution, err)
	}
	absence, err := runtime.ProveWorkflowToolAbsent(
		context.Background(),
		lease,
	)
	if err != nil || !isLowerHex(absence, 64) {
		t.Fatalf("absence = %q err=%v", absence, err)
	}
	handle := cleanupHandle{
		kind: CleanupVerifier,
		id:   lease.IdentityDigest,
	}
	if !runtime.owns(handle) ||
		!runtime.recordedRemoved(handle) {
		t.Fatal("successful one-shot was not retired")
	}
	if len(runner.argv) != 2 {
		t.Fatalf("argv count = %d", len(runner.argv))
	}
	expected := task11WorkflowToolArgv(
		"/usr/bin/docker",
		spec,
	)
	if fmt.Sprint(runner.argv[0]) != fmt.Sprint(expected) {
		t.Fatalf("run argv = %v, want %v", runner.argv[0], expected)
	}
	if fmt.Sprint(runner.argv[1]) != fmt.Sprint(
		task11WorkflowToolInspectArgv("/usr/bin/docker", lease.Name),
	) {
		t.Fatalf("inspect argv = %v", runner.argv[1])
	}
}

func TestTask11WorkflowToolRuntimeRejectsSubstitutionBeforeCommand(
	t *testing.T,
) {
	t.Parallel()

	runtime, owner, runner, _, bindings, users, limits, seccomp :=
		validTask11WorkflowToolRuntime(t)
	binding := bindings[0]
	action, _ := workflowToolActionFor(binding.ProbeID)
	lease, _ := workflowToolLeaseFor(
		owner.observation.Runner.id,
		binding.ProbeID,
	)
	if _, err := runtime.RegisterWorkflowToolCleanup(
		context.Background(),
		lease,
	); err != nil {
		t.Fatalf("RegisterWorkflowToolCleanup: %v", err)
	}
	spec := workflowToolProbeSpec{
		ProbeID:            binding.ProbeID,
		Action:             action,
		Name:               lease.Name,
		ImageReference:     binding.ImageReference,
		ImageDigest:        binding.ImageDigest,
		User:               users[0],
		NetworkContainerID: owner.observation.Runner.id,
		Seccomp:            seccomp,
		Limits:             limits,
	}
	spec.ImageDigest = inputDigestA
	if _, err := runtime.RunWorkflowTool(
		context.Background(),
		spec,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("substitution error = %v", err)
	}
	if len(runner.argv) != 0 {
		t.Fatal("substitution reached command runner")
	}
}

func TestTask11WorkflowToolRuntimeRetainsExactCleanupAfterFailure(
	t *testing.T,
) {
	t.Parallel()

	runtime, owner, runner, _, bindings, users, limits, seccomp :=
		validTask11WorkflowToolRuntime(t)
	binding := bindings[0]
	action, _ := workflowToolActionFor(binding.ProbeID)
	lease, _ := workflowToolLeaseFor(
		owner.observation.Runner.id,
		binding.ProbeID,
	)
	spec := workflowToolProbeSpec{
		ProbeID:            binding.ProbeID,
		Action:             action,
		Name:               lease.Name,
		ImageReference:     binding.ImageReference,
		ImageDigest:        binding.ImageDigest,
		User:               users[0],
		NetworkContainerID: owner.observation.Runner.id,
		Seccomp:            seccomp,
		Limits:             limits,
	}
	runner.results = []orderedClosedResult{
		{result: hostruntime.Result{Stdout: []byte("{}\n")}},
		{result: closedAbsentResultForTest(lease.Name)},
		{result: closedAbsentResultForTest(lease.Name)},
	}
	if _, err := runtime.RegisterWorkflowToolCleanup(
		context.Background(),
		lease,
	); err != nil {
		t.Fatalf("RegisterWorkflowToolCleanup: %v", err)
	}
	if _, err := runtime.RunWorkflowTool(
		context.Background(),
		spec,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("malformed output error = %v", err)
	}
	handle := cleanupHandle{
		kind: CleanupVerifier,
		id:   lease.IdentityDigest,
	}
	if runtime.recordedRemoved(handle) {
		t.Fatal("failed one-shot was prematurely retired")
	}
	if err := runtime.remove(context.Background(), handle); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !runtime.recordedRemoved(handle) {
		t.Fatal("cleanup did not prove exact absence")
	}
}

func TestOrchestratedFixtureRuntimeBindsOwnedWorkflowToolBeforePrepare(
	t *testing.T,
) {
	t.Parallel()

	workflow, owner, _, _, _, _, _, _ :=
		validTask11WorkflowToolRuntime(t)
	if err := owner.bindTask11WorkflowTool(workflow); err != nil {
		t.Fatalf("bindTask11WorkflowTool: %v", err)
	}
	if owner.task11Workflow != workflow {
		t.Fatal("workflow runtime ownership was not exact")
	}
	if err := owner.bindTask11WorkflowTool(workflow); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("duplicate bind error = %v", err)
	}
	lateWorkflow, late, _, _, _, _, _, _ :=
		validTask11WorkflowToolRuntime(t)
	late.prepareAttempted = true
	if err := late.bindTask11WorkflowTool(lateWorkflow); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("late bind error = %v", err)
	}
}

func validTask11WorkflowToolRuntime(
	t *testing.T,
) (
	*task11WorkflowToolRuntime,
	*orchestratedFixtureRuntime,
	*orderedClosedRunner,
	*[]cleanupHandle,
	[]WorkflowToolBinding,
	[]string,
	workflowToolProbeLimits,
	hostruntime.SeccompBinding,
) {
	t.Helper()

	bindings, users, limits, seccomp := validWorkflowToolSourceInputs(t)
	owner := &orchestratedFixtureRuntime{
		observationReady: true,
		observation: fixtureRuntimeObservation{
			Runner: cleanupHandle{
				kind: CleanupRunner,
				id:   inputDigestD,
			},
		},
	}
	runner := &orderedClosedRunner{}
	recorded := &[]cleanupHandle{}
	runtime, err := newTask11WorkflowToolRuntime(
		owner,
		"/usr/bin/docker",
		64<<10,
		runner,
		func(handle cleanupHandle) error {
			*recorded = append(*recorded, handle)
			return nil
		},
		bindings,
		users,
		limits,
		seccomp,
	)
	if err != nil {
		t.Fatalf("newTask11WorkflowToolRuntime: %v", err)
	}
	return runtime, owner, runner, recorded, bindings, users, limits, seccomp
}

func workflowToolOutputDocumentForTest(
	spec workflowToolProbeSpec,
	status WorkflowToolStatus,
) []byte {
	document, err := json.Marshal(task11WorkflowToolOutputWire{
		Version: 1,
		ProbeID: spec.ProbeID,
		Action:  spec.Action,
		Status:  status,
	})
	if err != nil {
		panic(err)
	}
	return append(document, '\n')
}
