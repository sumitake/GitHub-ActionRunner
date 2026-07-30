package testenv

import (
	"context"
	"sync"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

type task11SyntheticRestartCheckpoint struct {
	ProtocolStage       task11synthetic.SetupStage
	DeclarationIndex    uint64
	JournalStage        networkjail.SetupStage
	State               controller.State
	Expected            hostruntime.ManagedObservation
	AuthorityExpected   bool
	RelaySocketExpected bool
}

type task11SyntheticRestartEffectLookup interface {
	LookupAssignmentEffect(
		context.Context,
		controller.AssignmentKey,
		string,
	) (state.EffectRecord, error)
}

type task11SyntheticRestartSentinel struct {
	stage            task11synthetic.SetupStage
	declarationIndex uint64
}

type task11SyntheticRestartJournal struct {
	networkjail.LifecycleJournal
	lookup     task11SyntheticRestartEffectLookup
	key        controller.AssignmentKey
	checkpoint task11SyntheticRestartCheckpoint
	policy     string

	mu    sync.Mutex
	busy  bool
	fired bool
}

var task11SyntheticRestartCheckpoints = [...]task11SyntheticRestartCheckpoint{
	{
		ProtocolStage:    task11synthetic.SetupStageAdapterCreate,
		DeclarationIndex: 0,
		JournalStage:     networkjail.StageAdapterCreate,
		State:            controller.StateCapacityReserved,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
		},
	},
	{
		ProtocolStage:    task11synthetic.SetupStageAdapterEmpty,
		DeclarationIndex: 1,
		JournalStage:     networkjail.StageAdapterEmpty,
		State:            controller.StateAdapterCreated,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
		},
	},
	{
		ProtocolStage:    task11synthetic.SetupStageBrokerCreate,
		DeclarationIndex: 2,
		JournalStage:     networkjail.StageBrokerCreate,
		State:            controller.StateAdapterVerified,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
		},
	},
	{
		ProtocolStage:    task11synthetic.SetupStagePolicyApply,
		DeclarationIndex: 3,
		JournalStage:     networkjail.StagePolicyApply,
		State:            controller.StateBrokerHeld,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageAuthorityStart,
		DeclarationIndex:    4,
		JournalStage:        networkjail.StageAuthorityStart,
		State:               controller.StateBrokerPolicyApplied,
		AuthorityExpected:   true,
		RelaySocketExpected: false,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageAuthorityBind,
		DeclarationIndex:    5,
		JournalStage:        networkjail.StageAuthorityBind,
		State:               controller.StateBrokerPolicyApplied,
		AuthorityExpected:   true,
		RelaySocketExpected: false,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageBrokerRelease,
		DeclarationIndex:    6,
		JournalStage:        networkjail.StageBrokerRelease,
		State:               controller.StateDialAuthorityReady,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageAdapterBind,
		DeclarationIndex:    7,
		JournalStage:        networkjail.StageAdapterBind,
		State:               controller.StateBrokerReleased,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageEgressVerify,
		DeclarationIndex:    8,
		JournalStage:        networkjail.StageEgressVerify,
		State:               controller.StateBrokerReleased,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageRunnerCreate,
		DeclarationIndex:    9,
		JournalStage:        networkjail.StageRunnerCreate,
		State:               controller.StateEgressVerified,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
			RunnerPresent:  true,
			RunnerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageSeedHydrate,
		DeclarationIndex:    10,
		JournalStage:        networkjail.StageSeedHydrate,
		State:               controller.StateRunnerHeld,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
			RunnerPresent:  true,
			RunnerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageNamespacePreArm,
		DeclarationIndex:    11,
		JournalStage:        networkjail.StageNamespacePreArm,
		State:               controller.StateRunnerHeld,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
			RunnerPresent:  true,
			RunnerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageFinalAudit,
		DeclarationIndex:    12,
		JournalStage:        networkjail.StageFinalAudit,
		State:               controller.StateRunnerHeld,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
			RunnerPresent:  true,
			RunnerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageRunnerArm,
		DeclarationIndex:    13,
		JournalStage:        networkjail.StageRunnerArm,
		State:               controller.StateRunnerHeld,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
			RunnerPresent:  true,
			RunnerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageNamespaceFinal,
		DeclarationIndex:    14,
		JournalStage:        networkjail.StageNamespaceFinal,
		State:               controller.StateRunnerHeld,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
			RunnerPresent:  true,
			RunnerRunning:  true,
		},
	},
	{
		ProtocolStage:       task11synthetic.SetupStageRunnerAuthorize,
		DeclarationIndex:    15,
		JournalStage:        networkjail.StageRunnerAuthorize,
		State:               controller.StateRunnerHeld,
		AuthorityExpected:   true,
		RelaySocketExpected: true,
		Expected: hostruntime.ManagedObservation{
			AdapterPresent: true,
			AdapterRunning: true,
			BrokerPresent:  true,
			BrokerRunning:  true,
			RunnerPresent:  true,
			RunnerRunning:  true,
		},
	},
}

func newTask11SyntheticRestartJournal(
	journal networkjail.LifecycleJournal,
	lookup task11SyntheticRestartEffectLookup,
	key controller.AssignmentKey,
	checkpoint task11SyntheticRestartCheckpoint,
	policyDigest string,
) (*task11SyntheticRestartJournal, error) {
	verified, err := task11SyntheticRestartCheckpointAt(
		checkpoint.ProtocolStage,
		checkpoint.DeclarationIndex,
	)
	if journal == nil ||
		lookup == nil ||
		err != nil ||
		verified != checkpoint ||
		key.RepositoryAlias == "" ||
		key.RunnerRequestID <= 0 ||
		!isLowerHex(policyDigest, 64) {
		return nil, ErrFixtureStart
	}
	return &task11SyntheticRestartJournal{
		LifecycleJournal: journal,
		lookup:           lookup,
		key:              key,
		checkpoint:       checkpoint,
		policy:           policyDigest,
	}, nil
}

func (journal *task11SyntheticRestartJournal) Complete(
	ctx context.Context,
	key controller.AssignmentKey,
	stage networkjail.SetupStage,
	result networkjail.JournalResult,
) error {
	if journal == nil ||
		journal.LifecycleJournal == nil ||
		journal.lookup == nil ||
		ctx == nil ||
		ctx.Err() != nil {
		return ErrFixtureStart
	}
	if stage != journal.checkpoint.JournalStage {
		return journal.LifecycleJournal.Complete(ctx, key, stage, result)
	}
	if key != journal.key ||
		!journal.checkpoint.validJournalResult(result, journal.policy) {
		return ErrFixtureStart
	}

	journal.mu.Lock()
	if journal.busy || journal.fired {
		journal.mu.Unlock()
		return ErrFixtureStart
	}
	journal.busy = true
	journal.mu.Unlock()

	if err := journal.LifecycleJournal.Complete(
		ctx,
		key,
		stage,
		result,
	); err != nil {
		journal.mu.Lock()
		journal.busy = false
		journal.mu.Unlock()
		return err
	}
	effect, err := journal.lookup.LookupAssignmentEffect(
		ctx,
		key,
		stage.String(),
	)
	if err != nil ||
		effect.State != state.EffectCompleted ||
		effect.ResultIdentity != result.Identity ||
		effect.ReasonCode != "" {
		journal.mu.Lock()
		journal.busy = false
		journal.mu.Unlock()
		return ErrFixtureStart
	}
	journal.mu.Lock()
	journal.busy = false
	journal.fired = true
	journal.mu.Unlock()
	panic(task11SyntheticRestartSentinel{
		stage:            journal.checkpoint.ProtocolStage,
		declarationIndex: journal.checkpoint.DeclarationIndex,
	})
}

func (journal *task11SyntheticRestartJournal) didFire() bool {
	if journal == nil {
		return false
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.fired && !journal.busy
}

func task11SyntheticRestartCheckpointAt(
	stage task11synthetic.SetupStage,
	declarationIndex uint64,
) (task11SyntheticRestartCheckpoint, error) {
	if declarationIndex >= uint64(len(task11SyntheticRestartCheckpoints)) {
		return task11SyntheticRestartCheckpoint{}, ErrFixtureStart
	}
	checkpoint := task11SyntheticRestartCheckpoints[declarationIndex]
	if checkpoint.ProtocolStage != stage ||
		checkpoint.DeclarationIndex != declarationIndex ||
		checkpoint.JournalStage.String() != string(stage) {
		return task11SyntheticRestartCheckpoint{}, ErrFixtureStart
	}
	return checkpoint, nil
}

func (checkpoint task11SyntheticRestartCheckpoint) expectedJournalResult(
	identities hostruntime.RecoveredIdentities,
	policyDigest string,
) (networkjail.JournalResult, error) {
	var result networkjail.JournalResult
	switch checkpoint.JournalStage {
	case networkjail.StageAdapterCreate:
		result = networkjail.JournalResult{
			Identity: identities.AdapterID,
			Column:   networkjail.JournalIdentityAdapter,
		}
	case networkjail.StageBrokerCreate:
		result = networkjail.JournalResult{
			Identity: identities.BrokerID,
			Column:   networkjail.JournalIdentityBroker,
		}
	case networkjail.StagePolicyApply:
		result = networkjail.JournalResult{
			Identity: policyDigest,
			Column:   networkjail.JournalIdentityPolicy,
		}
	case networkjail.StageRunnerCreate:
		result = networkjail.JournalResult{
			Identity: identities.RunnerID,
			Column:   networkjail.JournalIdentityRunner,
		}
	}
	if !checkpoint.validJournalResult(result, policyDigest) {
		return networkjail.JournalResult{}, ErrFixtureStart
	}
	return result, nil
}

func (checkpoint task11SyntheticRestartCheckpoint) validJournalResult(
	result networkjail.JournalResult,
	policyDigest string,
) bool {
	if checkpoint.ProtocolStage == "" ||
		checkpoint.JournalStage.String() != string(checkpoint.ProtocolStage) ||
		result.Failure {
		return false
	}
	switch checkpoint.JournalStage {
	case networkjail.StageAdapterCreate:
		return result.Column == networkjail.JournalIdentityAdapter &&
			isLowerHex(result.Identity, 64)
	case networkjail.StageBrokerCreate:
		return result.Column == networkjail.JournalIdentityBroker &&
			isLowerHex(result.Identity, 64)
	case networkjail.StagePolicyApply:
		return result.Column == networkjail.JournalIdentityPolicy &&
			isLowerHex(policyDigest, 64) &&
			result.Identity == policyDigest
	case networkjail.StageRunnerCreate:
		return result.Column == networkjail.JournalIdentityRunner &&
			isLowerHex(result.Identity, 64)
	default:
		return result == (networkjail.JournalResult{})
	}
}

func (checkpoint task11SyntheticRestartCheckpoint) recoveredIdentities(
	cycle task11SyntheticCycleIdentity,
	plan compositionPlan,
	offer state.OfferIdentity,
	rows []state.RecoverableAssignment,
) (hostruntime.RecoveredIdentities, error) {
	if len(rows) != 1 {
		return hostruntime.RecoveredIdentities{}, ErrFixtureStart
	}
	row := rows[0]
	if row.Key != plan.AssignmentKey ||
		row.State != checkpoint.State ||
		row.Released ||
		row.Ambiguous ||
		row.AmbiguousReason != "" ||
		row.Slot.OpaqueName != cycle.Composition.SlotIdentity ||
		row.Slot.CapacitySlotID != cycle.Composition.CapacitySlotID ||
		row.Slot.UpstreamRunnerID != 0 ||
		row.Slot.BoundRequestID != 0 ||
		row.UpdatedAt.IsZero() ||
		row.Admission != (state.AdmissionProjection{}) ||
		state.CanonicalOfferDigest(row.Offer) !=
			state.CanonicalOfferDigest(offer) ||
		state.CanonicalOfferPayloadDigest(row.Offer) !=
			state.CanonicalOfferPayloadDigest(offer) {
		return hostruntime.RecoveredIdentities{}, ErrFixtureStart
	}
	identities := hostruntime.RecoveredIdentities{
		AdapterID: row.Slot.AdapterContainerID,
		BrokerID:  row.Slot.BrokerContainerID,
		RunnerID:  row.Slot.RunnerContainerID,
	}
	presence := hostruntime.ManagedObservation{
		AdapterPresent: identities.AdapterID != "",
		AdapterRunning: identities.AdapterID != "",
		BrokerPresent:  identities.BrokerID != "",
		BrokerRunning:  identities.BrokerID != "",
		RunnerPresent:  identities.RunnerID != "",
		RunnerRunning:  identities.RunnerID != "",
	}
	if presence != checkpoint.Expected ||
		(identities.AdapterID != "" &&
			!isLowerHex(identities.AdapterID, 64)) ||
		(identities.BrokerID != "" &&
			!isLowerHex(identities.BrokerID, 64)) ||
		(identities.RunnerID != "" &&
			!isLowerHex(identities.RunnerID, 64)) {
		return hostruntime.RecoveredIdentities{}, ErrFixtureStart
	}
	return identities, nil
}
