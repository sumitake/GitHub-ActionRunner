package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

var (
	ErrInvalidUpgradeConfig = errors.New(
		"upgrade: invalid service configuration",
	)
	ErrUpgradeUnauthorized = errors.New(
		"upgrade: phase unauthorized",
	)
	ErrUpgradeAbsent = errors.New(
		"upgrade: exact target absent",
	)
	ErrUpgradeUnavailable = errors.New(
		"upgrade: dependency unavailable",
	)
	ErrUpgradeRejected = errors.New(
		"upgrade: candidate permanently rejected",
	)
	ErrUpgradeAmbiguous = errors.New(
		"upgrade: effect outcome ambiguous",
	)
	ErrUpgradeIntegrity = errors.New(
		"upgrade: integrity failure",
	)
)

// SelectionSource reads the exact currently selected and retained rollback
// identity.
type SelectionSource interface {
	CurrentSelection(context.Context) (Selection, error)
}

// CandidateSource performs read-only immutable candidate discovery.
type CandidateSource interface {
	ObserveCandidate(context.Context, RunnerRelease) (Candidate, error)
}

// CandidateRuntime exposes only exact candidate lifecycle operations.
type CandidateRuntime interface {
	InspectStage(context.Context, Candidate) (StageObservation, error)
	Stage(context.Context, Candidate) error
	Qualify(context.Context, Candidate) (CompatibilityReport, error)
	InspectSelection(context.Context) (Selection, error)
	ProveQuiescent(context.Context) (Quiescence, error)
	ValidateReplacement(
		context.Context,
		Candidate,
	) (CompatibilityReport, error)
	Select(context.Context, Candidate) error
}

// MaintenanceRequestSource constructs the live enrolled status request.
type MaintenanceRequestSource interface {
	CurrentMaintenanceRequest(
		context.Context,
		string,
		*string,
	) (RunnerMaintenanceStatusRequest, error)
}

// ReleaseStatusPublisher emits only the closed Phase 3 public tuple. Delivery
// is at least once across reconciliation and crash recovery, so implementations
// must idempotently accept a repeated observation sequence.
type ReleaseStatusPublisher interface {
	PublishRunnerRelease(context.Context, RunnerReleaseStatus) error
}

// Config freezes every local dependency and operator-selected policy binding.
type Config struct {
	Admin      controller.LiveAdmin
	Store      JournalStore
	Observer   RunnerReleaseObserver
	Selection  SelectionSource
	Candidates CandidateSource
	Runtime    CandidateRuntime
	Requests   MaintenanceRequestSource
	Publisher  ReleaseStatusPublisher

	ConfigurationRevision uint64
	DrainPolicy           controller.DrainPolicy
	CanaryScaleSet        string
	EnabledCapacity       uint64
	CanaryPolicyDigest    string
	EnabledPolicyDigest   string
	OperationTimeout      time.Duration
	DirectiveMaxFuture    time.Duration
	Now                   func() time.Time
}

// Upgrade owns one journaled, externally authorized upgrade state machine.
type Upgrade struct {
	admin      controller.LiveAdmin
	store      JournalStore
	observer   RunnerReleaseObserver
	selection  SelectionSource
	candidates CandidateSource
	runtime    CandidateRuntime
	requests   MaintenanceRequestSource
	publisher  ReleaseStatusPublisher

	configurationRevision uint64
	configurationBinding  string
	drainPolicy           controller.DrainPolicy
	canaryScaleSet        string
	enabledCapacity       uint64
	canaryPolicyDigest    string
	enabledPolicyDigest   string
	operationTimeout      time.Duration
	directiveMaxFuture    time.Duration
	now                   func() time.Time
}

type phaseCapabilityContextKey struct{}

type phaseCapability struct {
	phase   JournalPhase
	journal Journal
	used    atomic.Bool
}

// New validates dependencies and performs a bounded read-only store probe.
func New(config Config) (*Upgrade, error) {
	if nilDependency(config.Admin) ||
		nilDependency(config.Store) ||
		nilDependency(config.Observer) ||
		nilDependency(config.Selection) ||
		nilDependency(config.Candidates) ||
		nilDependency(config.Runtime) ||
		nilDependency(config.Requests) ||
		nilDependency(config.Publisher) ||
		config.ConfigurationRevision == 0 ||
		(config.DrainPolicy != controller.DrainWait &&
			config.DrainPolicy != controller.DrainCancel) ||
		!validBoundedID(config.CanaryScaleSet, 128) ||
		config.EnabledCapacity == 0 ||
		config.EnabledCapacity > uint64(math.MaxInt) ||
		!validRawDigest(config.CanaryPolicyDigest) ||
		!validRawDigest(config.EnabledPolicyDigest) ||
		config.CanaryPolicyDigest == config.EnabledPolicyDigest ||
		config.OperationTimeout <= 0 ||
		config.DirectiveMaxFuture <= 0 ||
		config.Now == nil {
		return nil, ErrInvalidUpgradeConfig
	}
	now := config.Now()
	if !validUTCTime(now) {
		return nil, ErrInvalidUpgradeConfig
	}
	configBinding := upgradeConfigurationBinding(config)
	probeCtx, cancel := context.WithTimeout(
		context.Background(),
		config.OperationTimeout,
	)
	defer cancel()
	lease, err := config.Store.Acquire(probeCtx)
	if err != nil {
		return nil, ErrInvalidUpgradeConfig
	}
	document, readErr := lease.Read()
	closeErr := lease.Close()
	if closeErr != nil {
		return nil, ErrInvalidUpgradeConfig
	}
	if readErr == nil {
		journal, _, parseErr := ParseJournal(document, maxJournalDocumentSize)
		if parseErr != nil ||
			journal.ConfigurationRevision !=
				config.ConfigurationRevision ||
			journal.ConfigurationBinding != configBinding {
			return nil, ErrInvalidUpgradeConfig
		}
	} else if !errors.Is(readErr, ErrJournalAbsent) {
		return nil, ErrInvalidUpgradeConfig
	}
	return &Upgrade{
		admin:                 config.Admin,
		store:                 config.Store,
		observer:              config.Observer,
		selection:             config.Selection,
		candidates:            config.Candidates,
		runtime:               config.Runtime,
		requests:              config.Requests,
		publisher:             config.Publisher,
		configurationRevision: config.ConfigurationRevision,
		configurationBinding:  configBinding,
		drainPolicy:           config.DrainPolicy,
		canaryScaleSet:        config.CanaryScaleSet,
		enabledCapacity:       config.EnabledCapacity,
		canaryPolicyDigest:    config.CanaryPolicyDigest,
		enabledPolicyDigest:   config.EnabledPolicyDigest,
		operationTimeout:      config.OperationTimeout,
		directiveMaxFuture:    config.DirectiveMaxFuture,
		now:                   config.Now,
	}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflection := reflect.ValueOf(value)
	switch reflection.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflection.IsNil()
	default:
		return false
	}
}

// StageRunnerCandidate is capability-gated and cannot be used as a manual
// staging API.
func (upgrade *Upgrade) StageRunnerCandidate(
	ctx context.Context,
	release RunnerRelease,
) (Candidate, error) {
	candidate, _, err := upgrade.stageRunnerCandidate(ctx, release)
	return candidate, err
}

func (upgrade *Upgrade) stageRunnerCandidate(
	ctx context.Context,
	release RunnerRelease,
) (Candidate, StageObservation, error) {
	capability, err := consumePhaseCapability(
		ctx,
		JournalStageApplying,
	)
	if err != nil {
		return Candidate{}, StageObservation{}, err
	}
	if !reflect.DeepEqual(release, capability.journal.Observed) ||
		capability.journal.Candidate == nil {
		return Candidate{}, StageObservation{}, ErrUpgradeUnauthorized
	}
	candidate := *capability.journal.Candidate
	observation, inspectErr := upgrade.runtime.InspectStage(ctx, candidate)
	switch {
	case inspectErr == nil:
		if observation.Validate(candidate) != nil {
			return Candidate{}, StageObservation{}, ErrUpgradeIntegrity
		}
		return candidate, observation, nil
	case !errors.Is(inspectErr, ErrUpgradeAbsent):
		return Candidate{}, StageObservation{},
			classifyUpgradeError(inspectErr)
	}
	if err := upgrade.runtime.Stage(ctx, candidate); err != nil {
		return Candidate{}, StageObservation{}, classifyUpgradeError(err)
	}
	observation, err = upgrade.runtime.InspectStage(ctx, candidate)
	if err != nil {
		return Candidate{}, StageObservation{}, classifyUpgradeError(err)
	}
	if observation.Validate(candidate) != nil {
		return Candidate{}, StageObservation{}, ErrUpgradeIntegrity
	}
	return candidate, observation, nil
}

// QualifyRunnerCandidate is capability-gated and binds the full report.
func (upgrade *Upgrade) QualifyRunnerCandidate(
	ctx context.Context,
	candidate Candidate,
) (CompatibilityReport, error) {
	capability, err := consumePhaseCapability(
		ctx,
		JournalQualifyApplying,
	)
	if err != nil {
		return CompatibilityReport{}, err
	}
	if capability.journal.Candidate == nil ||
		!reflect.DeepEqual(candidate, *capability.journal.Candidate) {
		return CompatibilityReport{}, ErrUpgradeUnauthorized
	}
	report, err := upgrade.runtime.Qualify(ctx, candidate)
	if err != nil {
		return CompatibilityReport{}, classifyUpgradeError(err)
	}
	if report.Validate(candidate) != nil {
		return CompatibilityReport{}, ErrUpgradeIntegrity
	}
	return report, nil
}

// Prepare is capability-gated and accepts only the configured drain policy.
func (upgrade *Upgrade) Prepare(
	ctx context.Context,
	policy controller.DrainPolicy,
) error {
	if _, err := consumePhaseCapability(
		ctx,
		JournalPrepareApplying,
	); err != nil {
		return err
	}
	if policy != upgrade.drainPolicy {
		return ErrUpgradeUnauthorized
	}
	if err := upgrade.admin.Drain(ctx, policy); err != nil {
		return classifyUpgradeError(err)
	}
	return nil
}

// ProveQuiescent is capability-gated and rejects every live surface.
func (upgrade *Upgrade) ProveQuiescent(
	ctx context.Context,
) (Quiescence, error) {
	if _, err := consumePhaseCapability(
		ctx,
		JournalQuiescenceProving,
	); err != nil {
		return Quiescence{}, err
	}
	proof, err := upgrade.runtime.ProveQuiescent(ctx)
	if err != nil {
		return Quiescence{}, classifyUpgradeError(err)
	}
	if proof.Validate() != nil {
		return Quiescence{}, ErrUpgradeIntegrity
	}
	return proof, nil
}

// ValidateReplacement is capability-gated and reads its candidate only from
// the immutable journal.
func (upgrade *Upgrade) ValidateReplacement(
	ctx context.Context,
) (CompatibilityReport, error) {
	capability, err := consumePhaseCapability(
		ctx,
		JournalReplacementValidating,
	)
	if err != nil {
		return CompatibilityReport{}, err
	}
	if capability.journal.Candidate == nil {
		return CompatibilityReport{}, ErrUpgradeIntegrity
	}
	candidate := *capability.journal.Candidate
	report, err := upgrade.runtime.ValidateReplacement(ctx, candidate)
	if err != nil {
		return CompatibilityReport{}, classifyUpgradeError(err)
	}
	if report.Validate(candidate) != nil ||
		capability.journal.Qualified == nil ||
		!reflect.DeepEqual(report, *capability.journal.Qualified) {
		return CompatibilityReport{}, ErrUpgradeIntegrity
	}
	return report, nil
}

func consumePhaseCapability(
	ctx context.Context,
	expected JournalPhase,
) (*phaseCapability, error) {
	if ctx == nil {
		return nil, ErrUpgradeUnauthorized
	}
	capability, ok := ctx.Value(
		phaseCapabilityContextKey{},
	).(*phaseCapability)
	if !ok ||
		capability == nil ||
		capability.phase != expected ||
		capability.journal.Phase != expected ||
		!capability.used.CompareAndSwap(false, true) {
		return nil, ErrUpgradeUnauthorized
	}
	return capability, nil
}

func contextWithPhaseCapability(
	ctx context.Context,
	journal Journal,
) context.Context {
	return context.WithValue(
		ctx,
		phaseCapabilityContextKey{},
		&phaseCapability{
			phase:   journal.Phase,
			journal: journal,
		},
	)
}

func classifyUpgradeError(err error) error {
	switch {
	case errors.Is(err, ErrUpgradeAbsent):
		return ErrUpgradeAbsent
	case errors.Is(err, ErrUpgradeRejected):
		return ErrUpgradeRejected
	case errors.Is(err, ErrUpgradeAmbiguous):
		return ErrUpgradeAmbiguous
	case errors.Is(err, ErrUpgradeIntegrity):
		return ErrUpgradeIntegrity
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrUpgradeUnavailable):
		return ErrUpgradeUnavailable
	default:
		return ErrUpgradeUnavailable
	}
}

// ReconcileRunnerRelease advances no more than one externally meaningful
// phase and never treats an unavailable directive as local authority.
func (upgrade *Upgrade) ReconcileRunnerRelease(
	ctx context.Context,
	provider MaintenanceDirectiveProvider,
) (result error) {
	if ctx == nil {
		return ErrUpgradeUnavailable
	}
	operationCtx, cancel := context.WithTimeout(
		ctx,
		upgrade.operationTimeout,
	)
	defer cancel()
	lease, err := upgrade.store.Acquire(operationCtx)
	if err != nil {
		return ErrUpgradeIntegrity
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			if result == nil {
				result = ErrUpgradeIntegrity
			} else {
				result = errors.Join(ErrUpgradeIntegrity, result)
			}
		}
	}()

	document, err := lease.Read()
	if errors.Is(err, ErrJournalAbsent) {
		return upgrade.initializeJournal(operationCtx, lease)
	}
	if err != nil {
		return ErrUpgradeIntegrity
	}
	journal, _, err := ParseJournal(document, maxJournalDocumentSize)
	if err != nil ||
		journal.ConfigurationRevision !=
			upgrade.configurationRevision {
		return ErrUpgradeIntegrity
	}
	if err := upgrade.publishJournal(operationCtx, journal); err != nil {
		return err
	}

	switch journal.Phase {
	case JournalCurrent:
		return upgrade.observeFromCurrent(
			operationCtx,
			lease,
			document,
			journal,
		)
	case JournalUpgradeRequired:
		return upgrade.reconcileUpgradeRequired(
			operationCtx,
			lease,
			document,
			journal,
			provider,
		)
	case JournalDisableApplying:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileDisable(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalDisabled:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileStage(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalStageApplying:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileStage(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalStaged:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileQualify(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalQualifyApplying:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileQualify(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalCandidateQualified:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcilePrepare(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalPrepareApplying:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcilePrepare(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalPrepared:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileQuiescence(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalQuiescenceProving:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileQuiescence(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalQuiescent:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileReplacement(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalReplacementValidating:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileReplacement(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalReplacementValidated:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileSelect(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalSelectApplying:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileSelect(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalSelectedDisabled:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileCanary(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalCanaryApplying:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileCanary(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalCanaryActive:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileEnable(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			false,
		)
	case JournalEnableApplying:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileEnable(
			operationCtx,
			lease,
			document,
			journal,
			provider,
			true,
		)
	case JournalEnabled:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return upgrade.reconcileComplete(
			operationCtx,
			lease,
			document,
			journal,
			provider,
		)
	case JournalComplete:
		return upgrade.resetCompletedJournal(
			operationCtx,
			lease,
			document,
			journal,
		)
	case JournalCandidateRejected:
		return upgrade.reconcileRejectedTerminal(
			operationCtx,
			lease,
			document,
			journal,
		)
	default:
		if _, err := upgrade.observeFrozenRelease(operationCtx, journal.Observed); err != nil {
			return err
		}
		return ErrMaintenanceUnavailable
	}
}

func (upgrade *Upgrade) reconcileRejectedTerminal(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	previous Journal,
) error {
	selection, release, order, err := upgrade.observeSelection(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(selection, previous.Selected) ||
		order <= 0 {
		return ErrUpgradeIntegrity
	}
	candidate, err := upgrade.candidates.ObserveCandidate(ctx, release)
	if err != nil {
		return classifyUpgradeError(err)
	}
	if !candidateMatchesRelease(candidate, release) {
		return ErrUpgradeIntegrity
	}
	if release.Version == previous.Observed.Version &&
		previous.Candidate != nil &&
		reflect.DeepEqual(candidate, *previous.Candidate) {
		return ErrUpgradeRejected
	}
	next := Journal{
		SchemaVersion:         journalSchemaVersion,
		Generation:            previous.Generation + 1,
		ObservationSequence:   previous.ObservationSequence + 1,
		Phase:                 JournalUpgradeRequired,
		ConfigurationRevision: previous.ConfigurationRevision,
		ConfigurationBinding:  previous.ConfigurationBinding,
		Selected:              selection,
		Observed:              release,
		Candidate:             &candidate,
		UpdatedAt:             upgrade.now(),
	}
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		previousDocument,
		previous,
		next,
	)
}

func (upgrade *Upgrade) initializeJournal(
	ctx context.Context,
	lease JournalLease,
) error {
	selection, release, order, err := upgrade.observeSelection(ctx)
	if err != nil {
		return err
	}
	journal := Journal{
		SchemaVersion:         journalSchemaVersion,
		Generation:            1,
		ObservationSequence:   1,
		ConfigurationRevision: upgrade.configurationRevision,
		ConfigurationBinding:  upgrade.configurationBinding,
		Selected:              selection,
		Observed:              release,
		UpdatedAt:             upgrade.now(),
	}
	switch order {
	case 0:
		journal.Phase = JournalCurrent
	case 1:
		journal.Phase = JournalUpgradeRequired
	default:
		return ErrUpgradeIntegrity
	}
	return upgrade.createAndPublish(ctx, lease, journal)
}

func (upgrade *Upgrade) observeFromCurrent(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	previous Journal,
) error {
	selection, release, order, err := upgrade.observeSelection(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(selection, previous.Selected) {
		return ErrUpgradeIntegrity
	}
	if order < 0 {
		return ErrUpgradeIntegrity
	}
	if order == 0 {
		if !reflect.DeepEqual(release, previous.Observed) {
			return ErrUpgradeIntegrity
		}
		next := previous
		next.Generation++
		next.ObservationSequence++
		next.UpdatedAt = upgrade.now()
		return upgrade.replaceAndPublish(
			ctx,
			lease,
			previousDocument,
			previous,
			next,
		)
	}
	next := previous
	next.Generation++
	next.ObservationSequence++
	next.Phase = JournalUpgradeRequired
	next.Observed = release
	next.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		previousDocument,
		previous,
		next,
	)
}

func (upgrade *Upgrade) observeSelection(
	ctx context.Context,
) (Selection, RunnerRelease, int, error) {
	selection, err := upgrade.selection.CurrentSelection(ctx)
	if err != nil || selection.Validate() != nil {
		return Selection{}, RunnerRelease{}, 0, ErrUpgradeIntegrity
	}
	release, err := upgrade.observer.Observe(ctx)
	if err != nil {
		return Selection{}, RunnerRelease{}, 0, classifyUpgradeError(err)
	}
	if release.Validate() != nil {
		return Selection{}, RunnerRelease{}, 0, ErrUpgradeIntegrity
	}
	order, err := CompareRunnerVersions(
		release.Version,
		selection.Version,
	)
	if err != nil || order < 0 {
		return Selection{}, RunnerRelease{}, 0, ErrUpgradeIntegrity
	}
	return selection, release, order, nil
}

func (upgrade *Upgrade) observeFrozenRelease(
	ctx context.Context,
	expected RunnerRelease,
) (RunnerRelease, error) {
	release, err := upgrade.observer.Observe(ctx)
	if err != nil {
		return RunnerRelease{}, classifyUpgradeError(err)
	}
	if release.Validate() != nil {
		return RunnerRelease{}, ErrUpgradeIntegrity
	}
	order, err := CompareRunnerVersions(
		release.Version,
		expected.Version,
	)
	if err != nil ||
		order < 0 ||
		order == 0 && !reflect.DeepEqual(release, expected) {
		return RunnerRelease{}, ErrUpgradeIntegrity
	}
	return release, nil
}

func (upgrade *Upgrade) reconcileUpgradeRequired(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
) error {
	if _, err := upgrade.observeFrozenRelease(ctx, journal.Observed); err != nil {
		return err
	}
	if journal.Candidate == nil {
		candidate, err := upgrade.candidates.ObserveCandidate(
			ctx,
			journal.Observed,
		)
		if err != nil {
			return classifyUpgradeError(err)
		}
		if !candidateMatchesRelease(candidate, journal.Observed) {
			return ErrUpgradeIntegrity
		}
		next := journal
		next.Generation++
		next.ObservationSequence++
		next.Candidate = &candidate
		next.UpdatedAt = upgrade.now()
		return upgrade.replaceAndPublish(
			ctx,
			lease,
			previousDocument,
			journal,
			next,
		)
	}
	return upgrade.reconcileDisable(
		ctx,
		lease,
		previousDocument,
		journal,
		provider,
		false,
	)
}

func (upgrade *Upgrade) reconcileDisable(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceStagePermitted,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		JournalDisableApplying,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	proof, err := upgrade.disableAcquisition(ctx)
	if err != nil {
		return err
	}
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = JournalDisabled
	proven.Policy = &proof
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) disableAcquisition(
	ctx context.Context,
) (PolicyProof, error) {
	before, err := upgrade.admin.Probe(ctx)
	if err != nil {
		return PolicyProof{}, classifyUpgradeError(err)
	}
	if !validPolicyStatus(before) ||
		before.Mode == controller.AcquisitionFatal {
		return PolicyProof{}, ErrUpgradeIntegrity
	}
	if before.Mode == controller.AcquisitionDisabled {
		if before.Capacity != 0 {
			return PolicyProof{}, ErrUpgradeIntegrity
		}
		return policyProofFromStatus(before), nil
	}
	after, err := upgrade.admin.SetAcquisition(
		ctx,
		controller.AcquisitionChange{
			Set:      controller.AcquisitionDisabled,
			Expected: before.Mode,
		},
	)
	if err != nil {
		return PolicyProof{}, classifyUpgradeError(err)
	}
	if !validPolicyStatus(after) ||
		after.Mode != controller.AcquisitionDisabled ||
		after.Capacity != 0 ||
		after.Epoch <= before.Epoch {
		return PolicyProof{}, ErrUpgradeIntegrity
	}
	return policyProofFromStatus(after), nil
}

func validPolicyStatus(status controller.PolicyStatus) bool {
	if status.Epoch == 0 ||
		!validRawDigest(status.Digest) ||
		status.Capacity < 0 {
		return false
	}
	switch status.Mode {
	case controller.AcquisitionDisabled:
		return status.Capacity == 0
	case controller.AcquisitionCanaryOnly:
		return status.Capacity == 1
	case controller.AcquisitionEnabled:
		return status.Capacity > 0
	default:
		return false
	}
}

func policyProofFromStatus(
	status controller.PolicyStatus,
) PolicyProof {
	return PolicyProof{
		Mode:     string(status.Mode),
		Epoch:    status.Epoch,
		Digest:   status.Digest,
		Capacity: uint64(status.Capacity),
	}
}

func (upgrade *Upgrade) reconcileStage(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceStagePermitted,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		JournalStageApplying,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	capabilityCtx := contextWithPhaseCapability(ctx, applying)
	_, observation, err := upgrade.stageRunnerCandidate(
		capabilityCtx,
		applying.Observed,
	)
	if err != nil {
		if errors.Is(err, ErrUpgradeRejected) {
			return upgrade.persistCandidateRejected(
				ctx,
				lease,
				applyingDocument,
				applying,
			)
		}
		return err
	}
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = JournalStaged
	proven.Stage = &observation
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) reconcileQualify(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceStagePermitted,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		JournalQualifyApplying,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	if applying.Candidate == nil {
		return ErrUpgradeIntegrity
	}
	report, err := upgrade.QualifyRunnerCandidate(
		contextWithPhaseCapability(ctx, applying),
		*applying.Candidate,
	)
	if err != nil {
		if errors.Is(err, ErrUpgradeRejected) {
			return upgrade.persistCandidateRejected(
				ctx,
				lease,
				applyingDocument,
				applying,
			)
		}
		return err
	}
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = JournalCandidateQualified
	proven.Qualified = &report
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) authorizeJournalPhase(
	ctx context.Context,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	phase RunnerMaintenancePhase,
) (*AuthorizationRecord, error) {
	if provider == nil || journal.Candidate == nil {
		return nil, ErrMaintenanceUnavailable
	}
	liveSelection, err := upgrade.selection.CurrentSelection(ctx)
	if err != nil ||
		liveSelection.Validate() != nil ||
		!selectionAuthorizesJournal(liveSelection, journal) {
		return nil, ErrUpgradeIntegrity
	}
	candidateDigest := journal.Candidate.ManifestDigest
	request, err := upgrade.requests.CurrentMaintenanceRequest(
		ctx,
		liveSelection.ManifestDigest,
		&candidateDigest,
	)
	if err != nil ||
		request.Validate() != nil ||
		request.SelectedManifestDigest !=
			liveSelection.ManifestDigest ||
		request.CandidateManifestDigest == nil ||
		*request.CandidateManifestDigest != candidateDigest {
		return nil, ErrUpgradeIntegrity
	}
	directive, err := provider.Current(ctx, request)
	if err != nil {
		return nil, classifyMaintenanceProviderError(err)
	}
	if directive.verified &&
		directive.wire.Phase == MaintenanceWaitHosted {
		return nil, ErrMaintenanceUnavailable
	}
	authorized, err := directive.authorize(
		request,
		upgrade.now(),
		upgrade.directiveMaxFuture,
		phase,
		journal.Candidate,
		upgrade.configurationRevision,
		upgrade.canaryPolicyDigest,
		upgrade.enabledPolicyDigest,
	)
	if err != nil {
		return nil, ErrUpgradeUnauthorized
	}
	record := &AuthorizationRecord{
		Phase:                   authorized.phase,
		BindingDigest:           authorized.bindingDigest,
		EnrollmentBindingDigest: authorized.enrollmentBindingDigest,
		EnrollmentEpoch:         authorized.enrollmentEpoch,
		ControlSequence:         authorized.controlSequence,
	}
	if journal.Authorization != nil &&
		!authorizationAdvanced(journal.Authorization, record) {
		return nil, ErrUpgradeUnauthorized
	}
	return record, nil
}

func selectionAuthorizesJournal(live Selection, journal Journal) bool {
	if reflect.DeepEqual(live, journal.Selected) {
		return true
	}
	return journal.Phase == JournalSelectApplying &&
		journal.Candidate != nil &&
		validSelectedReplacement(live, *journal.Candidate, journal.Selected)
}

func (upgrade *Upgrade) persistApplying(
	lease JournalLease,
	previousDocument []byte,
	previous Journal,
	phase JournalPhase,
	authorization *AuthorizationRecord,
	resume bool,
) (Journal, []byte, error) {
	if authorization == nil ||
		(resume && previous.Phase != phase) ||
		(!resume && previous.Phase == phase) {
		return Journal{}, nil, ErrUpgradeIntegrity
	}
	next := previous
	next.Generation++
	next.ObservationSequence++
	next.Phase = phase
	next.Authorization = authorization
	next.UpdatedAt = upgrade.now()
	if err := ValidateJournalTransition(previous, next); err != nil {
		return Journal{}, nil, ErrUpgradeIntegrity
	}
	document, _, err := MarshalJournal(next)
	if err != nil {
		return Journal{}, nil, ErrUpgradeIntegrity
	}
	if err := lease.Replace(previousDocument, document); err != nil {
		return Journal{}, nil, ErrUpgradeIntegrity
	}
	return next, document, nil
}

func (upgrade *Upgrade) persistCandidateRejected(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	previous Journal,
) error {
	rejection := CandidateRejectionPermanent
	next := Journal{
		SchemaVersion:         journalSchemaVersion,
		Generation:            previous.Generation + 1,
		ObservationSequence:   previous.ObservationSequence + 1,
		Phase:                 JournalCandidateRejected,
		ConfigurationRevision: previous.ConfigurationRevision,
		ConfigurationBinding:  previous.ConfigurationBinding,
		Selected:              previous.Selected,
		Observed:              previous.Observed,
		Candidate:             previous.Candidate,
		Rejection:             &rejection,
		UpdatedAt:             upgrade.now(),
	}
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		previousDocument,
		previous,
		next,
	)
}

func (upgrade *Upgrade) reconcilePrepare(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceReplacePermitted,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		JournalPrepareApplying,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	if err := upgrade.Prepare(
		contextWithPhaseCapability(ctx, applying),
		upgrade.drainPolicy,
	); err != nil {
		return err
	}
	status, err := upgrade.admin.Probe(ctx)
	if err != nil {
		return classifyUpgradeError(err)
	}
	if !validPolicyStatus(status) ||
		status.Mode != controller.AcquisitionDisabled ||
		status.Capacity != 0 ||
		applying.Policy == nil ||
		status.Epoch <= applying.Policy.Epoch {
		return ErrUpgradeIntegrity
	}
	proof := policyProofFromStatus(status)
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = JournalPrepared
	proven.Policy = &proof
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) reconcileQuiescence(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceReplacePermitted,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		JournalQuiescenceProving,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	proof, err := upgrade.ProveQuiescent(
		contextWithPhaseCapability(ctx, applying),
	)
	if err != nil {
		return err
	}
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = JournalQuiescent
	proven.Quiescence = &proof
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) reconcileReplacement(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceReplacePermitted,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		JournalReplacementValidating,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	report, err := upgrade.ValidateReplacement(
		contextWithPhaseCapability(ctx, applying),
	)
	if err != nil {
		if errors.Is(err, ErrUpgradeRejected) {
			return upgrade.persistCandidateRejected(
				ctx,
				lease,
				applyingDocument,
				applying,
			)
		}
		return err
	}
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = JournalReplacementValidated
	proven.Replacement = &report
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) reconcileSelect(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceReplacePermitted,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		JournalSelectApplying,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	selection, err := upgrade.selectCandidate(
		contextWithPhaseCapability(ctx, applying),
	)
	if err != nil {
		if errors.Is(err, ErrUpgradeRejected) {
			return upgrade.persistCandidateRejected(
				ctx,
				lease,
				applyingDocument,
				applying,
			)
		}
		return err
	}
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = JournalSelectedDisabled
	proven.Selected = selection
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) selectCandidate(
	ctx context.Context,
) (Selection, error) {
	capability, err := consumePhaseCapability(
		ctx,
		JournalSelectApplying,
	)
	if err != nil {
		return Selection{}, err
	}
	if capability.journal.Candidate == nil {
		return Selection{}, ErrUpgradeIntegrity
	}
	candidate := *capability.journal.Candidate
	selection, inspectErr := upgrade.runtime.InspectSelection(ctx)
	switch {
	case inspectErr == nil:
		if !validSelectedReplacement(
			selection,
			candidate,
			capability.journal.Selected,
		) {
			return Selection{}, ErrUpgradeIntegrity
		}
		return selection, nil
	case !errors.Is(inspectErr, ErrUpgradeAbsent):
		return Selection{}, classifyUpgradeError(inspectErr)
	}
	if err := upgrade.runtime.Select(ctx, candidate); err != nil {
		return Selection{}, classifyUpgradeError(err)
	}
	selection, err = upgrade.runtime.InspectSelection(ctx)
	if err != nil {
		return Selection{}, classifyUpgradeError(err)
	}
	if !validSelectedReplacement(
		selection,
		candidate,
		capability.journal.Selected,
	) {
		return Selection{}, ErrUpgradeIntegrity
	}
	return selection, nil
}

func validSelectedReplacement(
	selection Selection,
	candidate Candidate,
	previous Selection,
) bool {
	return selection.Validate() == nil &&
		selectionMatchesCandidate(selection, candidate) &&
		selection.RollbackVersion == previous.Version &&
		selection.RollbackManifestDigest ==
			previous.ManifestDigest &&
		selection.RollbackImageDigest == previous.ImageDigest
}

func (upgrade *Upgrade) reconcileCanary(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	return upgrade.reconcilePolicyTransition(
		ctx,
		lease,
		previousDocument,
		journal,
		provider,
		resume,
		MaintenanceCanaryPermitted,
		JournalCanaryApplying,
		JournalCanaryActive,
		controller.AcquisitionDisabled,
		controller.AcquisitionCanaryOnly,
		upgrade.canaryScaleSet,
		1,
		upgrade.canaryPolicyDigest,
	)
}

func (upgrade *Upgrade) reconcileEnable(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
) error {
	return upgrade.reconcilePolicyTransition(
		ctx,
		lease,
		previousDocument,
		journal,
		provider,
		resume,
		MaintenanceEnablePermitted,
		JournalEnableApplying,
		JournalEnabled,
		controller.AcquisitionCanaryOnly,
		controller.AcquisitionEnabled,
		"",
		upgrade.enabledCapacity,
		upgrade.enabledPolicyDigest,
	)
}

func (upgrade *Upgrade) reconcilePolicyTransition(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
	resume bool,
	maintenancePhase RunnerMaintenancePhase,
	applyingPhase JournalPhase,
	provenPhase JournalPhase,
	expectedMode controller.AcquisitionMode,
	targetMode controller.AcquisitionMode,
	eligibleScaleSet string,
	targetCapacity uint64,
	targetDigest string,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		maintenancePhase,
	)
	if err != nil {
		return err
	}
	applying, applyingDocument, err := upgrade.persistApplying(
		lease,
		previousDocument,
		journal,
		applyingPhase,
		authorization,
		resume,
	)
	if err != nil {
		return err
	}
	proof, err := upgrade.transitionAcquisition(
		ctx,
		applying,
		expectedMode,
		targetMode,
		eligibleScaleSet,
		targetCapacity,
		targetDigest,
	)
	if err != nil {
		return err
	}
	proven := applying
	proven.Generation++
	proven.ObservationSequence++
	proven.Phase = provenPhase
	proven.Policy = &proof
	proven.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		applyingDocument,
		applying,
		proven,
	)
}

func (upgrade *Upgrade) transitionAcquisition(
	ctx context.Context,
	journal Journal,
	expectedMode, targetMode controller.AcquisitionMode,
	eligibleScaleSet string,
	targetCapacity uint64,
	targetDigest string,
) (PolicyProof, error) {
	before, err := upgrade.admin.Probe(ctx)
	if err != nil {
		return PolicyProof{}, classifyUpgradeError(err)
	}
	if !validPolicyStatus(before) ||
		journal.Policy == nil {
		return PolicyProof{}, ErrUpgradeIntegrity
	}
	if before.Mode == targetMode {
		if uint64(before.Capacity) != targetCapacity ||
			before.Digest != targetDigest {
			return PolicyProof{}, ErrUpgradeIntegrity
		}
		return policyProofFromStatus(before), nil
	}
	if before.Mode != expectedMode ||
		string(before.Mode) != journal.Policy.Mode ||
		before.Epoch != journal.Policy.Epoch ||
		before.Digest != journal.Policy.Digest ||
		uint64(before.Capacity) != journal.Policy.Capacity {
		return PolicyProof{}, ErrUpgradeIntegrity
	}
	after, err := upgrade.admin.SetAcquisition(
		ctx,
		controller.AcquisitionChange{
			Set:              targetMode,
			Expected:         expectedMode,
			EligibleScaleSet: eligibleScaleSet,
		},
	)
	if err != nil {
		return PolicyProof{}, classifyUpgradeError(err)
	}
	if !validPolicyStatus(after) ||
		after.Mode != targetMode ||
		uint64(after.Capacity) != targetCapacity ||
		after.Digest != targetDigest ||
		after.Epoch <= before.Epoch {
		return PolicyProof{}, ErrUpgradeIntegrity
	}
	return policyProofFromStatus(after), nil
}

func (upgrade *Upgrade) reconcileComplete(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
	provider MaintenanceDirectiveProvider,
) error {
	authorization, err := upgrade.authorizeJournalPhase(
		ctx,
		journal,
		provider,
		MaintenanceComplete,
	)
	if err != nil {
		return err
	}
	next := journal
	next.Generation++
	next.ObservationSequence++
	next.Phase = JournalComplete
	next.Authorization = authorization
	next.UpdatedAt = upgrade.now()
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		previousDocument,
		journal,
		next,
	)
}

func (upgrade *Upgrade) resetCompletedJournal(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	journal Journal,
) error {
	selection, err := upgrade.selection.CurrentSelection(ctx)
	if err != nil ||
		selection.Validate() != nil ||
		!reflect.DeepEqual(selection, journal.Selected) {
		return ErrUpgradeIntegrity
	}
	next := Journal{
		SchemaVersion:         journalSchemaVersion,
		Generation:            journal.Generation + 1,
		ObservationSequence:   journal.ObservationSequence + 1,
		Phase:                 JournalCurrent,
		ConfigurationRevision: journal.ConfigurationRevision,
		ConfigurationBinding:  journal.ConfigurationBinding,
		Selected:              selection,
		Observed: releaseForSelection(
			selection,
			journal.Observed,
		),
		UpdatedAt: upgrade.now(),
	}
	return upgrade.replaceAndPublish(
		ctx,
		lease,
		previousDocument,
		journal,
		next,
	)
}

func upgradeConfigurationBinding(config Config) string {
	hash := sha256.New()
	for _, field := range [][]byte{
		[]byte("portable-ghar-upgrade-configuration-v1"),
		[]byte(strconv.FormatUint(config.ConfigurationRevision, 10)),
		[]byte(config.DrainPolicy),
		[]byte(config.CanaryScaleSet),
		[]byte(strconv.FormatUint(config.EnabledCapacity, 10)),
		[]byte(config.CanaryPolicyDigest),
		[]byte(config.EnabledPolicyDigest),
	} {
		writeEvidenceField(hash, field)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func classifyMaintenanceProviderError(err error) error {
	if errors.Is(err, ErrMaintenanceUnavailable) {
		return ErrMaintenanceUnavailable
	}
	return ErrUpgradeUnavailable
}

func (upgrade *Upgrade) createAndPublish(
	ctx context.Context,
	lease JournalLease,
	journal Journal,
) error {
	document, _, err := MarshalJournal(journal)
	if err != nil {
		return ErrUpgradeIntegrity
	}
	if err := lease.Create(document); err != nil {
		return ErrUpgradeIntegrity
	}
	return upgrade.publishJournal(ctx, journal)
}

func (upgrade *Upgrade) replaceAndPublish(
	ctx context.Context,
	lease JournalLease,
	previousDocument []byte,
	previous, next Journal,
) error {
	if err := ValidateJournalTransition(previous, next); err != nil {
		return ErrUpgradeIntegrity
	}
	document, _, err := MarshalJournal(next)
	if err != nil {
		return ErrUpgradeIntegrity
	}
	if err := lease.Replace(previousDocument, document); err != nil {
		return ErrUpgradeIntegrity
	}
	return upgrade.publishJournal(ctx, next)
}

func (upgrade *Upgrade) publishJournal(
	ctx context.Context,
	journal Journal,
) error {
	status, err := journal.Status()
	if err != nil {
		return ErrUpgradeIntegrity
	}
	if err := upgrade.publisher.PublishRunnerRelease(
		ctx,
		status,
	); err != nil {
		return ErrUpgradeUnavailable
	}
	return nil
}
