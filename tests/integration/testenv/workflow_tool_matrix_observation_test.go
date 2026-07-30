package testenv

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type fakeWorkflowToolRuntime struct {
	registered   map[string]workflowToolCleanupLease
	trace        []string
	specs        []workflowToolProbeSpec
	statuses     map[string]WorkflowToolStatus
	failRegister bool
	active       int
	maxActive    int
}

func newFakeWorkflowToolRuntime() *fakeWorkflowToolRuntime {
	return &fakeWorkflowToolRuntime{
		registered: make(map[string]workflowToolCleanupLease),
		statuses:   make(map[string]WorkflowToolStatus),
	}
}

func (r *fakeWorkflowToolRuntime) RegisterWorkflowToolCleanup(
	_ context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	r.trace = append(r.trace, "register:"+lease.ProbeID)
	if r.failRegister {
		return "", ErrFixtureStart
	}
	if _, exists := r.registered[lease.Name]; exists {
		return "", ErrFixtureStart
	}
	r.registered[lease.Name] = lease
	return inputDigestA, nil
}

func (r *fakeWorkflowToolRuntime) RunWorkflowTool(
	_ context.Context,
	spec workflowToolProbeSpec,
) (workflowToolExecution, error) {
	r.trace = append(r.trace, "run:"+spec.ProbeID)
	if _, exists := r.registered[spec.Name]; !exists {
		return workflowToolExecution{}, ErrFixtureStart
	}
	r.active++
	if r.active > r.maxActive {
		r.maxActive = r.active
	}
	defer func() { r.active-- }()
	r.specs = append(r.specs, spec)
	status := r.statuses[spec.ProbeID]
	if status == "" {
		status = WorkflowToolSupported
	}
	return workflowToolExecution{
		ProbeID:          spec.ProbeID,
		Status:           status,
		OutputBytes:      64,
		OutputDigest:     inputDigestB,
		InvocationDigest: inputDigestC,
	}, nil
}

func (r *fakeWorkflowToolRuntime) ProveWorkflowToolAbsent(
	_ context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	r.trace = append(r.trace, "absent:"+lease.ProbeID)
	if registered, exists := r.registered[lease.Name]; !exists ||
		registered != lease {
		return "", ErrFixtureStart
	}
	return inputDigestD, nil
}

func validWorkflowToolSourceInputs(
	t *testing.T,
) (
	[]WorkflowToolBinding,
	[]string,
	workflowToolProbeLimits,
	hostruntime.SeccompBinding,
) {
	t.Helper()
	ids := RequiredWorkflowToolProbeIDs()
	bindings := make([]WorkflowToolBinding, 0, len(ids))
	users := make([]string, 0, len(ids))
	for index, id := range ids {
		digest := fmt.Sprintf("%064x", index+1)
		bindings = append(bindings, WorkflowToolBinding{
			ProbeID:        id,
			ImageReference: "example/tools/" + id + "@sha256:" + digest,
			ImageDigest:    digest,
		})
		users = append(users, "65532:65532")
	}
	return bindings, users, workflowToolProbeLimits{
			MilliCPU:        106,
			MemoryBytes:     70_000,
			MemorySwapBytes: 70_300,
			PIDs:            16,
			FileDescriptors: 26,
			WorkTmpfsBytes:  200,
			ScratchBytes:    100,
		}, hostruntime.SeccompBinding{
			Path:   filepath.Join(t.TempDir(), "seccomp.json"),
			SHA256: strings.Repeat("e", 64),
		}
}

func TestWorkflowToolSourceSerializesEveryClosedProbeAndFreezesCase(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughReclamation(t, ledger)
	bindings, users, limits, seccomp := validWorkflowToolSourceInputs(t)
	runtime := newFakeWorkflowToolRuntime()
	source, err := newWorkflowToolMatrixSource(
		ledger,
		bindings,
		users,
		limits,
		seccomp,
		runtime,
	)
	if err != nil {
		t.Fatalf("newWorkflowToolMatrixSource: %v", err)
	}
	var requirement ObservationRequirement
	for _, current := range RequiredObservationMatrix() {
		if current.Case == conformance.CaseProxyToolCompatibility {
			requirement = current
			break
		}
	}
	observation, err := source.Observe(
		context.Background(),
		requirement,
	)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Requirement != requirement ||
		len(observation.Measurements) != 1 ||
		observation.Measurements[0] !=
			(conformance.MeasurementInput{
				Name:  "tool_count",
				Value: uint64(len(bindings)),
				Unit:  "count",
			}) ||
		runtime.maxActive != 1 ||
		len(runtime.specs) != len(bindings) {
		t.Fatalf(
			"observation/runtime = %+v max=%d specs=%d",
			observation,
			runtime.maxActive,
			len(runtime.specs),
		)
	}
	for index, binding := range bindings {
		spec := runtime.specs[index]
		action, ok := workflowToolActionFor(binding.ProbeID)
		if !ok ||
			spec.ProbeID != binding.ProbeID ||
			spec.Action != action ||
			spec.ImageReference != binding.ImageReference ||
			spec.ImageDigest != binding.ImageDigest ||
			spec.User != users[index] ||
			spec.Seccomp != seccomp ||
			spec.Limits != limits ||
			spec.NetworkContainerID == "" {
			t.Fatalf("spec[%d] = %+v", index, spec)
		}
		wantTrace := []string{
			"register:" + binding.ProbeID,
			"run:" + binding.ProbeID,
			"absent:" + binding.ProbeID,
		}
		if got := runtime.trace[index*3 : index*3+3]; strings.Join(got, "\n") != strings.Join(wantTrace, "\n") {
			t.Fatalf("trace[%d] = %v, want %v", index, got, wantTrace)
		}
	}
	if _, _, frozen := ledger.snapshotAfterCase10(); !frozen {
		t.Fatal("case 10 ledger was not frozen")
	}
	if _, err := source.Observe(
		context.Background(),
		requirement,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("second Observe error = %v", err)
	}
}

func TestWorkflowToolSourceRejectsUnfrozenUnsupportedOrUnregisteredProbe(
	t *testing.T,
) {
	t.Parallel()

	var requirement ObservationRequirement
	for _, current := range RequiredObservationMatrix() {
		if current.Case == conformance.CaseProxyToolCompatibility {
			requirement = current
			break
		}
	}
	bindings, users, limits, seccomp := validWorkflowToolSourceInputs(t)
	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := newFakeWorkflowToolRuntime()
	unfrozen, err := newWorkflowToolMatrixSource(
		unfrozenLedger,
		bindings,
		users,
		limits,
		seccomp,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		requirement,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if len(unfrozenRuntime.trace) != 0 {
		t.Fatalf("unfrozen trace = %v", unfrozenRuntime.trace)
	}

	newFrozenLedger := func(t *testing.T) *preparedRuntimeEvidenceLedger {
		t.Helper()
		ledger, err := newPreparedRuntimeEvidenceLedger(
			64,
			validNamespaceEvidenceRuntime(),
		)
		if err != nil {
			t.Fatalf("new ledger: %v", err)
		}
		freezeThroughReclamation(t, ledger)
		return ledger
	}

	unsupportedRuntime := newFakeWorkflowToolRuntime()
	unsupportedRuntime.statuses[bindings[0].ProbeID] =
		WorkflowToolUnsupported
	unsupported, err := newWorkflowToolMatrixSource(
		newFrozenLedger(t),
		bindings,
		users,
		limits,
		seccomp,
		unsupportedRuntime,
	)
	if err != nil {
		t.Fatalf("new unsupported source: %v", err)
	}
	if _, err := unsupported.Observe(
		context.Background(),
		requirement,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unsupported error = %v", err)
	}
	if got := unsupportedRuntime.trace; len(got) != len(bindings)*3 ||
		got[0] != "register:"+bindings[0].ProbeID ||
		got[1] != "run:"+bindings[0].ProbeID ||
		got[2] != "absent:"+bindings[0].ProbeID {
		t.Fatalf("unsupported trace = %v", got)
	}

	unregisteredRuntime := newFakeWorkflowToolRuntime()
	unregisteredRuntime.failRegister = true
	unregistered, err := newWorkflowToolMatrixSource(
		newFrozenLedger(t),
		bindings,
		users,
		limits,
		seccomp,
		unregisteredRuntime,
	)
	if err != nil {
		t.Fatalf("new unregistered source: %v", err)
	}
	if _, err := unregistered.Observe(
		context.Background(),
		requirement,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unregistered error = %v", err)
	}
	if got := unregisteredRuntime.trace; len(got) != 1 ||
		got[0] != "register:"+bindings[0].ProbeID {
		t.Fatalf("unregistered trace = %v", got)
	}
}
