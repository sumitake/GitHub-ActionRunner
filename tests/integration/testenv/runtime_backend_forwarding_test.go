package testenv

import (
	"context"
	"errors"
	"testing"
)

type forwardingRuntimeGraph struct {
	broker    brokerCaseRuntimeObservation
	synthetic syntheticOneJobRuntimeObservation
	workflow  workflowToolExecution
	recovery  SyntheticRecoveryProof
}

func (*forwardingRuntimeGraph) Prepare(context.Context) error {
	return nil
}

func (*forwardingRuntimeGraph) LoopbackFlood(
	context.Context,
	uint32,
) (fixtureFloodObservation, error) {
	return fixtureFloodObservation{}, nil
}

func (*forwardingRuntimeGraph) Remove(context.Context, cleanupHandle) error {
	return nil
}

func (*forwardingRuntimeGraph) RecordedRemoved(cleanupHandle) bool {
	return true
}

func (*forwardingRuntimeGraph) RuntimeObservation(
	context.Context,
) (fixtureRuntimeObservation, error) {
	return fixtureRuntimeObservation{}, nil
}

func (r *forwardingRuntimeGraph) BrokerCaseObservation(
	context.Context,
	fixtureRuntimeObservation,
) (brokerCaseRuntimeObservation, error) {
	return r.broker, nil
}

func (r *forwardingRuntimeGraph) SyntheticOneJobObservation(
	context.Context,
	fixtureRuntimeObservation,
) (syntheticOneJobRuntimeObservation, error) {
	return r.synthetic, nil
}

func (*forwardingRuntimeGraph) RegisterWorkflowToolCleanup(
	context.Context,
	workflowToolCleanupLease,
) (string, error) {
	return "registered", nil
}

func (r *forwardingRuntimeGraph) RunWorkflowTool(
	context.Context,
	workflowToolProbeSpec,
) (workflowToolExecution, error) {
	return r.workflow, nil
}

func (*forwardingRuntimeGraph) ProveWorkflowToolAbsent(
	context.Context,
	workflowToolCleanupLease,
) (string, error) {
	return "absent", nil
}

func (r *forwardingRuntimeGraph) RecoveryObservation(
	context.Context,
	fixtureRuntimeObservation,
) (SyntheticRecoveryProof, error) {
	return r.recovery, nil
}

func TestFixtureRuntimeBackendForwardsLazyCaseRuntimesAfterStart(t *testing.T) {
	graph := &forwardingRuntimeGraph{
		broker: brokerCaseRuntimeObservation{
			DirectProtocolsDenied: true,
		},
		synthetic: syntheticOneJobRuntimeObservation{
			JobCompleted: true,
		},
		workflow: workflowToolExecution{
			ProbeID: "fixture-forwarding",
		},
		recovery: SyntheticRecoveryProof{
			InitialFenceGeneration: 9,
		},
	}
	backend := &fixtureRuntimeBackend{
		startAttempted: true,
		runtime:        graph,
	}
	ctx := context.Background()
	if got, err := backend.BrokerCaseObservation(
		ctx,
		fixtureRuntimeObservation{},
	); err != nil || got != graph.broker {
		t.Fatalf("BrokerCaseObservation = %+v, %v", got, err)
	}
	if got, err := backend.SyntheticOneJobObservation(
		ctx,
		fixtureRuntimeObservation{},
	); err != nil || got != graph.synthetic {
		t.Fatalf("SyntheticOneJobObservation = %+v, %v", got, err)
	}
	if got, err := backend.RunWorkflowTool(
		ctx,
		workflowToolProbeSpec{},
	); err != nil || got != graph.workflow {
		t.Fatalf("RunWorkflowTool = %+v, %v", got, err)
	}
	if got, err := backend.RecoveryObservation(
		ctx,
		fixtureRuntimeObservation{},
	); err != nil ||
		got.InitialFenceGeneration !=
			graph.recovery.InitialFenceGeneration {
		t.Fatalf("RecoveryObservation = %+v, %v", got, err)
	}
}

func TestFixtureRuntimeBackendRejectsCaseForwardingBeforeStartOrAfterRemoval(
	t *testing.T,
) {
	backend := &fixtureRuntimeBackend{runtime: &forwardingRuntimeGraph{}}
	if _, err := backend.BrokerCaseObservation(
		context.Background(),
		fixtureRuntimeObservation{},
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("before-start error = %v", err)
	}
	backend.startAttempted = true
	backend.workspaceRemoved = true
	if _, err := backend.BrokerCaseObservation(
		context.Background(),
		fixtureRuntimeObservation{},
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("after-removal error = %v", err)
	}
}
