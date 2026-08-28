package networkjail

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/state"
)

var (
	ErrSetupReplay       = errors.New("networkjail: setup effect requires reconciliation")
	ErrSetupFailed       = errors.New("networkjail: setup failed")
	ErrSetupCleanup      = errors.New("networkjail: setup cleanup failed")
	ErrListenerAmbiguous = errors.New("networkjail: listener release checkpoint ambiguous")
	ErrSetupInput        = errors.New("networkjail: setup input invalid")
)

type SetupStage uint8

const (
	StageAdapterCreate SetupStage = iota + 1
	StageAdapterEmpty
	StageBrokerCreate
	StagePolicyApply
	StageAuthorityStart
	StageAuthorityBind
	StageBrokerRelease
	StageAdapterBind
	StageEgressVerify
	StageRunnerCreate
	StageSeedHydrate
	StageNamespacePreArm
	StageFinalAudit
	StageRunnerArm
	StageNamespaceFinal
	StageRunnerAuthorize
	StageListenerRelease
)

func (stage SetupStage) String() string {
	switch stage {
	case StageAdapterCreate:
		return "network-adapter-create"
	case StageAdapterEmpty:
		return "network-adapter-empty"
	case StageBrokerCreate:
		return "network-broker-create"
	case StagePolicyApply:
		return "network-policy-apply"
	case StageAuthorityStart:
		return "dial-authority-start"
	case StageAuthorityBind:
		return "dial-authority-bind"
	case StageBrokerRelease:
		return "network-broker-release"
	case StageAdapterBind:
		return "network-adapter-bind"
	case StageEgressVerify:
		return "network-egress-verify"
	case StageRunnerCreate:
		return "runner-create"
	case StageSeedHydrate:
		return "runner-seed-hydrate"
	case StageNamespacePreArm:
		return "runner-namespace-prearm"
	case StageFinalAudit:
		return "network-final-audit"
	case StageRunnerArm:
		return "runner-arm"
	case StageNamespaceFinal:
		return "runner-namespace-final"
	case StageRunnerAuthorize:
		return "runner-release-authorize"
	case StageListenerRelease:
		return state.LifecycleEffectListenerRelease
	default:
		return ""
	}
}

type JournalIdentity uint8

const (
	JournalIdentityNone JournalIdentity = iota
	JournalIdentityAdapter
	JournalIdentityBroker
	JournalIdentityRunner
	JournalIdentityPolicy
)

type JournalResult struct {
	Identity string
	Column   JournalIdentity
	Failure  bool
}

// LifecycleJournal persists intent before every external action and a bounded
// result before the next checkpoint. A false replay is never silently rerun.
type LifecycleJournal interface {
	Before(context.Context, controller.AssignmentKey, SetupStage) error
	BeforeListenerRelease(context.Context, controller.AssignmentKey, [sha256.Size]byte) error
	Complete(context.Context, controller.AssignmentKey, SetupStage, JournalResult) error
	CompleteListenerRelease(context.Context, controller.AssignmentKey, [sha256.Size]byte) error
	Advance(context.Context, controller.AssignmentKey, controller.State) error
	MarkAmbiguous(context.Context, controller.AssignmentKey) error
}

type StateLifecycleJournal struct {
	store state.Store
}

func NewStateLifecycleJournal(store state.Store) (*StateLifecycleJournal, error) {
	if store == nil {
		return nil, errors.New("networkjail: state store required")
	}
	return &StateLifecycleJournal{store: store}, nil
}

func (j *StateLifecycleJournal) Before(
	ctx context.Context,
	key controller.AssignmentKey,
	stage SetupStage,
) error {
	if stage.String() == "" || stage == StageListenerRelease {
		return ErrSetupInput
	}
	began, err := j.store.BeginEffect(
		ctx,
		key,
		setupEffectKey(key, stage),
		stage.String(),
	)
	if err != nil {
		return err
	}
	if !began {
		return ErrSetupReplay
	}
	return nil
}

func (j *StateLifecycleJournal) BeforeListenerRelease(
	ctx context.Context,
	key controller.AssignmentKey,
	bindingDigest [sha256.Size]byte,
) error {
	began, err := j.store.BeginListenerReleaseEffect(ctx, key, bindingDigest)
	if errors.Is(err, state.ErrIdentityConflict) || (err == nil && !began) {
		return ErrSetupReplay
	}
	return err
}

func (j *StateLifecycleJournal) Complete(
	ctx context.Context,
	key controller.AssignmentKey,
	stage SetupStage,
	result JournalResult,
) error {
	if stage == StageListenerRelease {
		return ErrSetupInput
	}
	native, err := stateJournalResult(result)
	if err != nil {
		return err
	}
	return j.store.CompleteEffect(ctx, setupEffectKey(key, stage), native)
}

func (j *StateLifecycleJournal) CompleteListenerRelease(
	ctx context.Context,
	_ controller.AssignmentKey,
	bindingDigest [sha256.Size]byte,
) error {
	if bindingDigest == ([sha256.Size]byte{}) {
		return ErrSetupInput
	}
	return j.store.CompleteEffect(
		ctx,
		hex.EncodeToString(bindingDigest[:]),
		state.EffectResult{Column: state.IdentityNone},
	)
}

func (j *StateLifecycleJournal) Advance(
	ctx context.Context,
	key controller.AssignmentKey,
	next controller.State,
) error {
	return j.store.Advance(ctx, key, next)
}

func (j *StateLifecycleJournal) MarkAmbiguous(
	ctx context.Context,
	key controller.AssignmentKey,
) error {
	return j.store.MarkAmbiguous(ctx, key, "listener-release-checkpoint")
}

func stateJournalResult(result JournalResult) (state.EffectResult, error) {
	native := state.EffectResult{}
	if result.Failure {
		if result.Identity != "" || result.Column != JournalIdentityNone {
			return state.EffectResult{}, ErrSetupInput
		}
		native.ReasonCode = "network-setup-failed"
		return native, nil
	}
	native.ResultIdentity = result.Identity
	switch result.Column {
	case JournalIdentityNone:
		native.Column = state.IdentityNone
	case JournalIdentityAdapter:
		native.Column = state.IdentityAdapterContainer
	case JournalIdentityBroker:
		native.Column = state.IdentityBrokerContainer
	case JournalIdentityRunner:
		native.Column = state.IdentityRunnerContainer
	case JournalIdentityPolicy:
		native.Column = state.IdentityPolicySocketDigest
	default:
		return state.EffectResult{}, ErrSetupInput
	}
	return native, nil
}

func setupEffectKey(key controller.AssignmentKey, stage SetupStage) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("portable-ghar.network-setup.v1\x00"))
	_, _ = hash.Write([]byte(key.RepositoryAlias))
	_, _ = hash.Write([]byte{0})
	var numeric [20]byte
	binary.BigEndian.PutUint64(numeric[:8], uint64(key.RunnerRequestID))
	binary.BigEndian.PutUint32(numeric[8:12], key.Attempt)
	binary.BigEndian.PutUint64(numeric[12:20], uint64(stage))
	_, _ = hash.Write(numeric[:])
	return hex.EncodeToString(hash.Sum(nil))
}
