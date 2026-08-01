package lifecycle

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/redaction"
	"github.com/sumitake/portable-ghar/internal/state"
)

type sqliteLifecycleJail struct {
	store       state.Store
	destroyLive int
}

func (j *sqliteLifecycleJail) Prepare(
	ctx context.Context,
	request networkjail.PreparedSetupRequest,
) (networkjail.HeldJail, error) {
	steps := []struct {
		stage    networkjail.SetupStage
		next     controller.State
		identity string
		column   state.IdentityColumn
	}{
		{
			networkjail.StageAdapterCreate,
			controller.StateAdapterCreated,
			strings.Repeat("a", 64),
			state.IdentityAdapterContainer,
		},
		{
			networkjail.StageAdapterEmpty,
			controller.StateAdapterVerified,
			"",
			state.IdentityNone,
		},
		{
			networkjail.StageBrokerCreate,
			controller.StateBrokerHeld,
			strings.Repeat("b", 64),
			state.IdentityBrokerContainer,
		},
		{
			networkjail.StagePolicyApply,
			controller.StateBrokerPolicyApplied,
			strings.Repeat("d", 64),
			state.IdentityPolicySocketDigest,
		},
		{
			networkjail.StageAuthorityBind,
			controller.StateDialAuthorityReady,
			"",
			state.IdentityNone,
		},
		{
			networkjail.StageBrokerRelease,
			controller.StateBrokerReleased,
			"",
			state.IdentityNone,
		},
		{
			networkjail.StageEgressVerify,
			controller.StateEgressVerified,
			"",
			state.IdentityNone,
		},
		{
			networkjail.StageRunnerCreate,
			controller.StateRunnerHeld,
			strings.Repeat("c", 64),
			state.IdentityRunnerContainer,
		},
		{
			networkjail.StageRunnerAuthorize,
			controller.StateReleaseArmed,
			"",
			state.IdentityNone,
		},
	}
	for index, step := range steps {
		idempotencyKey := fmt.Sprintf("sqlite-lifecycle-prepare-%02d", index)
		began, err := j.store.BeginEffect(
			ctx,
			request.Key,
			idempotencyKey,
			step.stage.String(),
		)
		if err != nil || !began {
			return networkjail.HeldJail{}, fmt.Errorf(
				"begin integration effect %s: began=%v err=%w",
				step.stage,
				began,
				err,
			)
		}
		if err := j.store.CompleteEffect(ctx, idempotencyKey, state.EffectResult{
			ResultIdentity: step.identity,
			Column:         step.column,
		}); err != nil {
			return networkjail.HeldJail{}, err
		}
		if err := j.store.Advance(ctx, request.Key, step.next); err != nil {
			return networkjail.HeldJail{}, err
		}
	}
	return networkjail.HeldJail{}, nil
}

func (j *sqliteLifecycleJail) Release(
	ctx context.Context,
	_ networkjail.HeldJail,
	jit *redaction.Secret,
) (networkjail.LiveJail, error) {
	defer jit.Destroy()
	records, err := j.store.ListRecoverable(ctx)
	if err != nil || len(records) != 1 {
		return networkjail.LiveJail{}, fmt.Errorf("integration release record unavailable")
	}
	key := records[0].Key
	const idempotencyKey = "sqlite-lifecycle-listener-release"
	began, err := j.store.BeginEffect(
		ctx,
		key,
		idempotencyKey,
		state.LifecycleEffectListenerRelease,
	)
	if err != nil || !began {
		return networkjail.LiveJail{}, fmt.Errorf(
			"begin integration listener release: began=%v err=%w",
			began,
			err,
		)
	}
	if err := j.store.CompleteEffect(
		ctx,
		idempotencyKey,
		state.EffectResult{Column: state.IdentityNone},
	); err != nil {
		return networkjail.LiveJail{}, err
	}
	if err := j.store.Advance(ctx, key, controller.StateListenerReleased); err != nil {
		return networkjail.LiveJail{}, err
	}
	return networkjail.LiveJail{}, nil
}

func (*sqliteLifecycleJail) DestroyHeld(context.Context, networkjail.HeldJail) error {
	return nil
}

func (j *sqliteLifecycleJail) DestroyLive(context.Context, networkjail.LiveJail) error {
	j.destroyLive++
	return nil
}

func TestServiceRunsOneJobLifecycleAgainstSQLiteAttemptZero(t *testing.T) {
	ctx := context.Background()
	store, err := state.OpenWithHistoryLimits(
		filepath.Join(t.TempDir(), "controller.sqlite"),
		state.HistoryLimits{
			MinRetention:                 24 * time.Hour,
			MaxHistoryRows:               256,
			MaxHistoryLogicalBytes:       1 << 20,
			MaxNetworkLedgerRows:         64,
			MaxNetworkLedgerLogicalBytes: 1 << 18,
			InflightReserveRows:          8,
			InflightReserveLogicalBytes:  1 << 14,
			GCBatchRows:                  16,
			NetworkGCBatchRows:           8,
			VacuumBatchPages:             4,
			MaintenanceCadence:           time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits() = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	})

	baseTime := time.Now().Add(-2 * time.Minute).UTC()
	offer := githubscale.Offer{JobRef: githubscale.JobRef{
		RunnerRequestID:    88,
		JobID:              "job-sqlite",
		RepositoryName:     "repo-a",
		OwnerName:          "owner-a",
		RequestLabels:      []string{"portable-ghar"},
		QueueTime:          baseTime,
		ScaleSetAssignTime: baseTime.Add(time.Second),
	}}
	receipt, err := store.RecordOffer(ctx, state.OfferIdentity{
		RepositoryAlias:    offer.RepositoryName,
		RunnerRequestID:    offer.RunnerRequestID,
		JobID:              offer.JobID,
		RepositoryName:     offer.RepositoryName,
		OwnerName:          offer.OwnerName,
		RequestLabels:      append([]string(nil), offer.RequestLabels...),
		QueueTime:          offer.QueueTime,
		ScaleSetAssignTime: offer.ScaleSetAssignTime,
	}, state.OfferEvidence{
		Kind:       state.EvidenceSelectiveReadback,
		ObservedAt: baseTime,
	})
	if err != nil {
		t.Fatalf("RecordOffer() = %v", err)
	}
	if receipt.Key.Attempt != 0 {
		t.Fatalf("initial durable attempt = %d, want 0", receipt.Key.Attempt)
	}
	opaqueName := controller.OpaqueSlotName(receipt.Key)
	if err := store.Reserve(ctx, receipt.Key, opaqueName, 1); err != nil {
		t.Fatalf("Reserve() = %v", err)
	}
	records, err := store.ListRecoverable(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("ListRecoverable() = (%d,%v), want one", len(records), err)
	}
	assignment, err := controller.NewAssignment(receipt.Key, offer, records[0].Slot)
	if err != nil {
		t.Fatalf("NewAssignment(attempt zero) = %v", err)
	}

	adapterName, brokerName, runnerName, err := componentNames(opaqueName)
	if err != nil {
		t.Fatalf("componentNames() = %v", err)
	}
	builder := &fakeSetupBuilder{
		prepared: networkjail.PreparedSetupRequest{
			Key:      receipt.Key,
			Adapter:  hostruntime.AdapterSpec{Name: adapterName, SlotIdentity: opaqueName},
			Broker:   hostruntime.BrokerSpec{Name: brokerName, SlotIdentity: opaqueName, CapacitySlotID: 1},
			Runner:   hostruntime.RunnerSpec{Name: runnerName, SlotIdentity: opaqueName},
			Verifier: hostruntime.VerifierSpec{SlotIdentity: opaqueName},
		},
		recovery: hostruntime.RecoverySpec{
			SlotIdentity: opaqueName,
			AdapterName:  adapterName,
			BrokerName:   brokerName,
			RunnerName:   runnerName,
		},
	}
	session := &fakeLifecycleSession{
		runners:      make(map[string]githubscale.RunnerRef),
		nextRunnerID: 300,
	}
	jail := &sqliteLifecycleJail{store: store}
	service, err := NewService(
		store,
		&fakeSessionProvider{session: session},
		&fakeJITAuthorizer{},
		builder,
		jail,
		&fakeManagedRecovery{},
		time.Now,
	)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	if _, err := service.Prepare(ctx, assignment); err != nil {
		t.Fatalf("Prepare() = %v", err)
	}
	if err := service.Release(ctx, receipt.Key); err != nil {
		t.Fatalf("Release() = %v", err)
	}
	runner := session.runners[opaqueName]
	observedRequestID := offer.RunnerRequestID + 100
	if err := service.RecordBatch(ctx, controller.MessageEnvelope{
		RepositoryAlias: receipt.Key.RepositoryAlias,
		Started: []controller.MessageStarted{{
			Job: controller.MessageJobRef{
				RunnerRequestID:  observedRequestID,
				JobID:            offer.JobID,
				RepositoryName:   offer.RepositoryName,
				OwnerName:        offer.OwnerName,
				RunnerAssignTime: time.Now().Add(-time.Second),
			},
			RunnerID:   runner.ID,
			RunnerName: runner.Name,
		}},
	}); err != nil {
		t.Fatalf("RecordBatch(started) = %v", err)
	}
	records, err = store.ListRecoverable(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("ListRecoverable(started) = (%d,%v), want one", len(records), err)
	}
	if records[0].State != controller.StateJobRunning ||
		records[0].Slot.UpstreamRunnerID != runner.ID ||
		records[0].Slot.BoundRequestID != observedRequestID {
		t.Fatalf("SQLite running record = %+v", records[0])
	}

	if err := service.RecordBatch(ctx, controller.MessageEnvelope{
		RepositoryAlias: receipt.Key.RepositoryAlias,
		Completed: []controller.MessageCompleted{{
			Job: controller.MessageJobRef{
				RunnerRequestID: observedRequestID,
				JobID:           offer.JobID,
				RepositoryName:  offer.RepositoryName,
				OwnerName:       offer.OwnerName,
				FinishTime:      time.Now().Add(-time.Second),
			},
			Result:     "Succeeded",
			RunnerID:   runner.ID,
			RunnerName: runner.Name,
		}},
	}); err != nil {
		t.Fatalf("RecordBatch(completed) = %v", err)
	}
	if err := service.Destroy(
		ctx,
		receipt.Key,
		controller.ReasonLifecycleJobFinished,
	); err != nil {
		t.Fatalf("Destroy() = %v", err)
	}
	if records, err := store.ListRecoverable(ctx); err != nil || len(records) != 0 {
		t.Fatalf("ListRecoverable(destroyed) = (%d,%v), want zero", len(records), err)
	}
	if jail.destroyLive != 1 {
		t.Fatalf("DestroyLive calls = %d, want 1", jail.destroyLive)
	}
}
