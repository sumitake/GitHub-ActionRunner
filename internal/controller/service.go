package controller

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/health"
	"github.com/sumitake/portable-ghar/internal/observability"
)

var (
	ErrDurableIdentityConflict = errors.New("controller: durable identity conflict")
	ErrHistoryUnavailable      = errors.New("controller: history capacity unavailable")
	ErrReplayUnavailable       = errors.New("controller: replay evidence unavailable")
	ErrAckUncertain            = errors.New("controller: message acknowledgement uncertain")
	ErrAckConfirmed            = errors.New("controller: message acknowledgement confirmed")
	ErrAdmissionHeadroom       = errors.New("controller: admission headroom unavailable")
	ErrOfferTooLarge           = errors.New("controller: offer exceeds single-offer bound")
	ErrAdmissionConflict       = errors.New("controller: admission identity conflict")
	ErrAdmissionUnavailable    = errors.New("controller: admission unavailable")
	ErrServiceNotReady         = errors.New("controller: service is not ready")
	ErrServiceStarted          = errors.New("controller: service already started")
	ErrStartupRestore          = errors.New("controller: startup restore failed")
	ErrPressureTransition      = errors.New("controller: pressure transition rejected")
	ErrPollCycle               = errors.New("controller: poll cycle failed")
	ErrPollFatal               = errors.New("controller: poll cycle entered fatal state")
	ErrHostedUnavailable       = errors.New("controller: hosted routing unavailable")
	ErrTerminalFinalize        = errors.New("controller: terminal finalization failed")
	ErrHistoryPressure         = errors.New("controller: history pressure evaluation failed")
	ErrAcquisitionTransition   = errors.New("controller: acquisition transition failed")
	ErrAcquisitionQuiescence   = errors.New("controller: acquisition quiescence not proven")
)

// ReasonCode is a closed, identity-free service failure classification. It is
// safe to pass to the injected process terminator and observability adapters.
type ReasonCode uint8

const (
	ReasonRestoreInvalid ReasonCode = iota + 1
	ReasonRestoreStateRead
	ReasonRestoreBroker
	ReasonRestoreAckRead
	ReasonRestoreTransition
	ReasonPressureTransition
	ReasonPressureBroker
	ReasonProjectionPersist
	ReasonActivePersist
	ReasonLifecycleCanceled
	ReasonLifecyclePrepareFailed
	ReasonLifecycleReleaseAmbiguous
	ReasonLifecycleReassigned
	ReasonLifecycleJobFinished
	ReasonLifecycleReconcile
	ReasonAcquisitionBroker
	ReasonAcquisitionJoin
	ReasonAcquisitionRevoke
	ReasonAcquisitionQuiescence
	ReasonAcquisitionResult
)

// MessageEnvelope is the controller-owned, secret-free durable projection of
// one nonempty message returned by the pinned scale-set adapter.
//
// RepositoryAlias is the stable local fleet namespace. It is not part of the
// message-intrinsic payload digest. Every other field is copied from the
// translated upstream Batch; raw wire payloads and credentials never cross
// this boundary.
type MessageEnvelope struct {
	RepositoryAlias string
	MessageID       int
	Statistics      MessageStatistics
	Offers          []MessageOffer
	Assigned        []MessageAssigned
	Started         []MessageStarted
	Completed       []MessageCompleted
}

// MessageJobRef is the controller-owned copy of the fields common to all
// translated scale-set job-message shapes.
type MessageJobRef struct {
	RunnerRequestID    int64
	JobID              string
	RepositoryName     string
	OwnerName          string
	JobWorkflowRef     string
	JobDisplayName     string
	WorkflowRunID      int64
	EventName          string
	RequestLabels      []string
	QueueTime          time.Time
	ScaleSetAssignTime time.Time
	RunnerAssignTime   time.Time
	FinishTime         time.Time
}

type MessageOffer struct {
	Job           MessageJobRef
	AcquireJobURL string
}

type MessageAssigned struct {
	Job MessageJobRef
}

type MessageStarted struct {
	Job        MessageJobRef
	RunnerID   int64
	RunnerName string
}

type MessageCompleted struct {
	Job        MessageJobRef
	Result     string
	RunnerID   int64
	RunnerName string
}

type MessageStatistics struct {
	TotalAvailableJobs     int
	TotalAcquiredJobs      int
	TotalAssignedJobs      int
	TotalRunningJobs       int
	TotalRegisteredRunners int
	TotalBusyRunners       int
	TotalIdleRunners       int
}

// NewMessageEnvelope makes the checked dependency boundary explicit and
// deep-copies every slice so later adapter or caller mutation cannot change the
// durable digest input after construction.
func NewMessageEnvelope(repositoryAlias string, batch githubscale.Batch) MessageEnvelope {
	out := MessageEnvelope{
		RepositoryAlias: repositoryAlias,
		MessageID:       batch.MessageID,
		Statistics: MessageStatistics{
			TotalAvailableJobs:     batch.Statistics.TotalAvailableJobs,
			TotalAcquiredJobs:      batch.Statistics.TotalAcquiredJobs,
			TotalAssignedJobs:      batch.Statistics.TotalAssignedJobs,
			TotalRunningJobs:       batch.Statistics.TotalRunningJobs,
			TotalRegisteredRunners: batch.Statistics.TotalRegisteredRunners,
			TotalBusyRunners:       batch.Statistics.TotalBusyRunners,
			TotalIdleRunners:       batch.Statistics.TotalIdleRunners,
		},
	}
	for _, offer := range batch.Offers {
		out.Offers = append(out.Offers, MessageOffer{
			Job:           copyMessageJobRef(offer.JobRef),
			AcquireJobURL: offer.AcquireJobURL,
		})
	}
	for _, event := range batch.Assigned {
		out.Assigned = append(out.Assigned, MessageAssigned{Job: copyMessageJobRef(event.JobRef)})
	}
	for _, event := range batch.Started {
		out.Started = append(out.Started, MessageStarted{
			Job:        copyMessageJobRef(event.JobRef),
			RunnerID:   event.RunnerID,
			RunnerName: event.RunnerName,
		})
	}
	for _, event := range batch.Completed {
		out.Completed = append(out.Completed, MessageCompleted{
			Job:        copyMessageJobRef(event.JobRef),
			Result:     event.Result,
			RunnerID:   event.RunnerID,
			RunnerName: event.RunnerName,
		})
	}
	return out
}

func copyMessageJobRef(ref githubscale.JobRef) MessageJobRef {
	return MessageJobRef{
		RunnerRequestID:    ref.RunnerRequestID,
		JobID:              ref.JobID,
		RepositoryName:     ref.RepositoryName,
		OwnerName:          ref.OwnerName,
		JobWorkflowRef:     ref.JobWorkflowRef,
		JobDisplayName:     ref.JobDisplayName,
		WorkflowRunID:      ref.WorkflowRunID,
		EventName:          ref.EventName,
		RequestLabels:      append([]string(nil), ref.RequestLabels...),
		QueueTime:          ref.QueueTime,
		ScaleSetAssignTime: ref.ScaleSetAssignTime,
		RunnerAssignTime:   ref.RunnerAssignTime,
		FinishTime:         ref.FinishTime,
	}
}

// MessageDigest is the fixed V2 message-receipt digest.
type MessageDigest [sha256.Size]byte

type MessageAckState uint8

const (
	MessageAckPersisted MessageAckState = iota + 1
	MessageAckStarted
	MessageAckRedeliveryProven
	MessageAckConfirmed
)

type MessageReceiptRecord struct {
	Digest   MessageDigest
	State    MessageAckState
	Inserted bool
}

// UncertainMessageReceipt is the bounded restart authority for one Ack whose
// network outcome was never durably confirmed. It contains no payload bytes.
type UncertainMessageReceipt struct {
	RepositoryAlias string
	MessageID       int
	Digest          MessageDigest
	StartedAt       time.Time
}

type OfferEvidenceKind uint8

const (
	OfferEvidenceCurrentPoll OfferEvidenceKind = iota + 1
	OfferEvidenceSelectiveReadback
)

type OfferEvidence struct {
	Kind       OfferEvidenceKind
	MessageID  int
	QueueTime  time.Time
	ObservedAt time.Time
}

type OfferDisposition uint8

const (
	OfferInserted OfferDisposition = iota + 1
	OfferActiveReplay
	OfferTerminalReplay
)

type OfferRecord struct {
	Key         AssignmentKey
	Disposition OfferDisposition
	State       State
}

type AcquisitionBatchStatus uint8

const (
	AcquisitionBatchBegun AcquisitionBatchStatus = iota + 1
	AcquisitionBatchNotAttempted
	AcquisitionBatchCompleted
	AcquisitionBatchAmbiguous
)

type AssignmentAcquisitionOutcome uint8

const (
	AssignmentOffered AssignmentAcquisitionOutcome = iota + 1
	AssignmentRequested
	AssignmentAcquired
	AssignmentRejected
)

type AcquisitionBatchRecord struct {
	RepositoryAlias string
	MessageID       int
	RequestDigest   MessageDigest
	ResultDigest    MessageDigest
	Status          AcquisitionBatchStatus
	RequestedCount  int
	AcquiredCount   int
	BegunAt         time.Time
	UpdatedAt       time.Time
	Inserted        bool
	CallAuthorized  bool
}

type AssignmentAcquisitionRecord struct {
	Key          AssignmentKey
	Outcome      AssignmentAcquisitionOutcome
	RevokedEpoch uint64
}

type OperationalSummary struct {
	AssignedJobs                uint64
	RunningJobs                 uint64
	OldestLiveAssignmentAge     time.Duration
	UnassignedReleasedListeners uint64
	LatestTerminalAt            time.Time
}

type ResourceProjection struct {
	MilliCPU          int64
	MemoryBytes       int64
	PIDs              int64
	FileDescriptors   int64
	TmpfsBytes        int64
	ScratchBytes      int64
	SocketStateBytes  int64
	DurableStateBytes int64
	Inodes            int64
}

type AdmissionPhase uint8

const (
	AdmissionQueued AdmissionPhase = iota + 1
	AdmissionReserved
	AdmissionActive
)

type AdmissionReference struct {
	Key             AssignmentKey
	Offer           githubscale.Offer
	Phase           AdmissionPhase
	SlotID          uint32
	FullCharge      ResourceProjection
	LedgerCharge    ResourceProjection
	LedgerCreatedAt time.Time
	LedgerEverUsed  bool
}

type AdmissionDecision struct {
	Key        AssignmentKey
	Projection AdmissionReference
}

type PollLease struct {
	ID              uint64
	RepositoryAlias string
	Epoch           uint64
	Reserved        int
	PollCapacity    int
	ExpiresAt       time.Time
}

type CapacitySummary struct {
	Epoch              uint64
	ConfiguredCapacity int
	EffectiveCapacity  int
	Occupied           int
	Available          int
	Queued             int
}

type RecoverableAssignment struct {
	Key             AssignmentKey
	State           State
	Offer           githubscale.Offer
	Admission       AdmissionReference
	Released        bool
	Ambiguous       bool
	AmbiguousReason string
	Slot            RunnerSlot
	UpdatedAt       time.Time
}

type TerminalFinalization struct {
	Key       AssignmentKey
	MessageID int
	At        time.Time
}

type HostedEffectState uint8

const (
	HostedEffectAbsent HostedEffectState = iota + 1
	HostedEffectPending
	HostedEffectCompleted
	HostedEffectFailed
)

type HostedFailure uint8

const (
	HostedFailureRouteRejected HostedFailure = iota + 1
)

type HostedEffectRecord struct {
	State          HostedEffectState
	ResultIdentity string
	Failure        HostedFailure
}

type HistoryUsage struct {
	LiveRows                  uint64
	LiveLogicalBytes          uint64
	ProtectedTerminalRows     uint64
	ProtectedTerminalBytes    uint64
	MessageReceiptRows        uint64
	MessageReceiptBytes       uint64
	AcquisitionRows           uint64
	AcquisitionLogicalBytes   uint64
	TombstoneRows             uint64
	TombstoneLogicalBytes     uint64
	NetworkLedgerRows         uint64
	NetworkLedgerLogicalBytes uint64
	InflightAssignments       uint64
	ReservedRows              uint64
	ReservedLogicalBytes      uint64
	OldestRetainedAt          time.Time
}

// DurableState is the acyclic controller-owned persistence port implemented
// by package state through a checked adapter.
type DurableState interface {
	RecordMessageReceipt(context.Context, MessageEnvelope, time.Time) (MessageReceiptRecord, error)
	RecordOffer(context.Context, string, githubscale.Offer, OfferEvidence) (OfferRecord, error)
	BeginAcquisition(context.Context, string, int, []AssignmentKey, time.Time) (AcquisitionBatchRecord, error)
	AbortAcquisitionBeforeCall(context.Context, string, int, time.Time) (AcquisitionBatchRecord, error)
	CompleteAcquisition(context.Context, string, int, []AssignmentKey, time.Time) (AcquisitionBatchRecord, error)
	MarkAcquisitionAmbiguous(context.Context, string, int, time.Time) (AcquisitionBatchRecord, error)
	PromoteBegunAcquisitions(context.Context, time.Time) (int, error)
	AcquisitionBatch(context.Context, string, int) (AcquisitionBatchRecord, error)
	AcquisitionAssignment(context.Context, AssignmentKey) (AssignmentAcquisitionRecord, error)
	MarkPreRunningRevoked(context.Context, uint64, time.Time) ([]AssignmentKey, error)
	PersistAdmission(context.Context, AssignmentKey, AdmissionReference) error
	ReserveActive(context.Context, AssignmentKey, AdmissionReference, string) error
	ClearAdmission(context.Context, AssignmentKey) error
	ClearTerminalRuntime(context.Context, AssignmentKey) error
	LookupHostedEffect(context.Context, AssignmentKey, string) (HostedEffectRecord, error)
	BeginHostedEffect(context.Context, AssignmentKey, string) (bool, error)
	CompleteHostedEffect(context.Context, string, string) error
	FailHostedEffect(context.Context, string) error
	BeginAck(context.Context, string, int, time.Time) error
	ConfirmAck(context.Context, string, int, time.Time) error
	ObserveRedelivery(context.Context, string, int, MessageDigest, time.Time) error
	ListUncertainAcks(context.Context) ([]UncertainMessageReceipt, error)
	BindTerminalMessage(context.Context, AssignmentKey, int) error
	Advance(context.Context, AssignmentKey, State) error
	ListRecoverable(context.Context) ([]RecoverableAssignment, error)
	ListTerminalFinalizations(context.Context) ([]TerminalFinalization, error)
	CompactTerminal(context.Context, AssignmentKey, time.Time) error
	HistoryUsage(context.Context) (HistoryUsage, error)
	OperationalSummary(context.Context, time.Time) (OperationalSummary, error)
}

// AdmissionBroker is the controller-owned broker port. Its adapter rewrites
// only the broker's repository-routing field on copies; message-intrinsic and
// durable offer projections remain unchanged.
type AdmissionBroker interface {
	ApplyAcquisitionPolicy(AcquisitionPolicy) error
	SetDemand(string, uint64, int) error
	CapacitySummary() CapacitySummary
	CheckOffer(string, githubscale.Offer) error
	LeasePoll(string, time.Time) (PollLease, error)
	EnsureQueuedBatch(uint64, string, []githubscale.Offer) ([]AdmissionReference, error)
	Restore([]AdmissionReference) error
	Admit(uint64, time.Time) ([]AdmissionDecision, error)
	Reference(AssignmentKey) (AdmissionReference, bool, error)
	SetPressure(int) (previous, current int, err error)
	Release(AssignmentKey) error
	Retire(AssignmentKey) error
	HasLiveReference(AssignmentKey) bool
}

// BatchEventRecorder durably applies assigned/started/completed observations
// idempotently before the enclosing message may be acknowledged.
type BatchEventRecorder interface {
	RecordBatch(context.Context, MessageEnvelope) error
}

type ReplayVerification uint8

const (
	ReplayCurrent ReplayVerification = iota + 1
	ReplayNotCurrent
	ReplayUnknown
)

type ReplayVerifier interface {
	VerifyCurrentOffer(context.Context, githubscale.Fleet, githubscale.Offer) (ReplayVerification, error)
}

type HostedReason uint8

const (
	HostedReasonOfferTooLarge HostedReason = iota + 1
	HostedReasonQueueTimeMissing
	HostedReasonQueueTimeStale
	HostedReasonReplayNotCurrent
	HostedReasonReplayUnknown
)

type HostedReadinessProof struct {
	RepositoryAlias   string
	PolicyEpoch       uint64
	ObservedAt        time.Time
	ExpiresAt         time.Time
	AvailableCapacity uint64
}

type HostedRouter interface {
	Readiness(context.Context, string, uint64) (HostedReadinessProof, error)
	RouteHosted(context.Context, AssignmentKey, string, HostedReason) (string, error)
}

// HistoryPressureThresholds is the complete injected bounded-history
// envelope. No production default is supplied. Assignment history and the
// network ledger remain independently budgeted.
type HistoryPressureThresholds struct {
	WarningHistoryRows        uint64
	StopHistoryRows           uint64
	WarningHistoryBytes       uint64
	StopHistoryBytes          uint64
	WarningNetworkLedgerRows  uint64
	StopNetworkLedgerRows     uint64
	WarningNetworkLedgerBytes uint64
	StopNetworkLedgerBytes    uint64
	WarningMaxCapacity        int
}

// HealthPublisher publishes only the identity-free aggregate health leaf.
type HealthPublisher interface {
	Publish(context.Context, health.Snapshot) error
}

// EventSink receives only closed, identity-free observability events.
type EventSink interface {
	Emit(context.Context, observability.Event) error
}

// FatalTerminator is invoked only after the service has persisted a zero or
// fatal acquisition state. Production implementations terminate the process;
// tests record the closed reason.
type FatalTerminator interface {
	TerminateAfterPersist(ReasonCode)
}

// AcquisitionRevoker destroys every durably marked pre-running listener under
// the lifecycle package's same-key exclusion. JOB_RUNNING assignments are not
// passed to this interface by DurableState.MarkPreRunningRevoked.
type AcquisitionRevoker interface {
	RevokePreRunning(context.Context, uint64, []AssignmentKey) error
}

type ServiceConfig struct {
	State                 DurableState
	Broker                AdmissionBroker
	Transitions           AcquisitionTransitioner
	Revoker               AcquisitionRevoker
	RunningCanceler       RunningCanceler
	Terminator            FatalTerminator
	Events                BatchEventRecorder
	Replay                ReplayVerifier
	Hosted                HostedRouter
	FleetGuards           FleetGuardProvider
	Permits               AcquisitionPermitProvider
	HostCapacity          HostCapacityProvider
	HistoryPressure       HistoryPressureThresholds
	HealthPublisher       HealthPublisher
	EventSink             EventSink
	Reconciler            Reconciler
	FleetAlias            string
	HostProfileID         string
	BuildID               string
	Degraded              bool
	EnabledPolicyTemplate AcquisitionPolicy
	PollTargets           []PollTarget
	Now                   func() time.Time
	AckTimeout            time.Duration
	OperationTimeout      time.Duration
	PollCycleTimeout      time.Duration
	ReconciliationTimeout time.Duration
	PollCadence           time.Duration
	ReconciliationCadence time.Duration
	DrainPollCadence      time.Duration
	ShutdownTimeout       time.Duration
	SessionCloseTimeout   time.Duration
	TransitionJoinTimeout time.Duration
	DurableFinishTimeout  time.Duration
	ReplayEvidenceMaxAge  time.Duration
	HostCapacityMaxAge    time.Duration
}

type messageReceiptKey struct {
	repositoryAlias string
	messageID       int
}

type observedOffer struct {
	offer  githubscale.Offer
	record OfferRecord
}

type fatalOperationError struct {
	reason ReasonCode
	cause  error
}

func (e *fatalOperationError) Error() string {
	return fmt.Sprintf("controller: fatal operation reason %d: %v", e.reason, e.cause)
}

func (e *fatalOperationError) Unwrap() error {
	return e.cause
}

// Service serializes only persisted epoch publication. External effects and
// reconciliation sections enter the live acquisition barrier instead of
// holding one global network-call mutex.
type Service struct {
	transitionMu sync.Mutex
	mu           sync.RWMutex

	state                 DurableState
	broker                AdmissionBroker
	transitions           AcquisitionTransitioner
	revoker               AcquisitionRevoker
	runningCanceler       RunningCanceler
	terminator            FatalTerminator
	events                BatchEventRecorder
	replay                ReplayVerifier
	hosted                HostedRouter
	fleetGuards           FleetGuardProvider
	permits               AcquisitionPermitProvider
	hostCapacity          HostCapacityProvider
	pressure              HistoryPressureThresholds
	health                HealthPublisher
	eventSink             EventSink
	reconciler            Reconciler
	fleetAlias            string
	hostProfileID         string
	buildID               string
	degraded              bool
	enabledTemplate       AcquisitionPolicy
	pollTargets           []PollTarget
	now                   func() time.Time
	ackTimeout            time.Duration
	operationTimeout      time.Duration
	pollCycleTimeout      time.Duration
	reconciliationTimeout time.Duration
	pollCadence           time.Duration
	reconciliationCadence time.Duration
	drainPollCadence      time.Duration
	shutdownTimeout       time.Duration
	sessionCloseTimeout   time.Duration
	transitionJoinTimeout time.Duration
	durableFinishTimeout  time.Duration
	replayAge             time.Duration
	hostCapacityMaxAge    time.Duration
	sequencer             *keySequencer

	started   bool
	ready     bool
	policy    AcquisitionPolicy
	barrier   *acquisitionBarrier
	uncertain map[messageReceiptKey]UncertainMessageReceipt
	lastID    map[string]int
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.State == nil ||
		config.Broker == nil ||
		config.Transitions == nil ||
		config.Revoker == nil ||
		config.RunningCanceler == nil ||
		config.Terminator == nil ||
		config.Events == nil ||
		config.Replay == nil ||
		config.Hosted == nil ||
		config.FleetGuards == nil ||
		config.Permits == nil ||
		config.HostCapacity == nil ||
		config.HealthPublisher == nil ||
		config.EventSink == nil ||
		config.Reconciler == nil ||
		config.Now == nil ||
		config.AckTimeout <= 0 ||
		config.OperationTimeout <= 0 ||
		config.PollCycleTimeout <= 0 ||
		config.ReconciliationTimeout <= 0 ||
		config.PollCadence <= 0 ||
		config.ReconciliationCadence <= 0 ||
		config.DrainPollCadence <= 0 ||
		config.ShutdownTimeout <= 0 ||
		config.SessionCloseTimeout <= 0 ||
		config.TransitionJoinTimeout <= 0 ||
		config.DurableFinishTimeout <= 0 ||
		config.ReplayEvidenceMaxAge <= 0 ||
		config.HostCapacityMaxAge <= 0 ||
		!validServiceHealthIdentity(config) ||
		!validServiceRuntimeConfig(config) ||
		!validHistoryPressureThresholds(config.HistoryPressure) {
		return nil, fmt.Errorf("%w: incomplete service dependencies", ErrServiceNotReady)
	}
	return &Service{
		state:                 config.State,
		broker:                config.Broker,
		transitions:           config.Transitions,
		revoker:               config.Revoker,
		runningCanceler:       config.RunningCanceler,
		terminator:            config.Terminator,
		events:                config.Events,
		replay:                config.Replay,
		hosted:                config.Hosted,
		fleetGuards:           config.FleetGuards,
		permits:               config.Permits,
		hostCapacity:          config.HostCapacity,
		pressure:              config.HistoryPressure,
		health:                config.HealthPublisher,
		eventSink:             config.EventSink,
		reconciler:            config.Reconciler,
		fleetAlias:            config.FleetAlias,
		hostProfileID:         config.HostProfileID,
		buildID:               config.BuildID,
		degraded:              config.Degraded,
		enabledTemplate:       cloneAcquisitionPolicy(config.EnabledPolicyTemplate),
		pollTargets:           clonePollTargets(config.PollTargets),
		now:                   config.Now,
		ackTimeout:            config.AckTimeout,
		operationTimeout:      config.OperationTimeout,
		pollCycleTimeout:      config.PollCycleTimeout,
		reconciliationTimeout: config.ReconciliationTimeout,
		pollCadence:           config.PollCadence,
		reconciliationCadence: config.ReconciliationCadence,
		drainPollCadence:      config.DrainPollCadence,
		shutdownTimeout:       config.ShutdownTimeout,
		sessionCloseTimeout:   config.SessionCloseTimeout,
		transitionJoinTimeout: config.TransitionJoinTimeout,
		durableFinishTimeout:  config.DurableFinishTimeout,
		replayAge:             config.ReplayEvidenceMaxAge,
		hostCapacityMaxAge:    config.HostCapacityMaxAge,
		sequencer:             newKeySequencer(),
		uncertain:             make(map[messageReceiptKey]UncertainMessageReceipt),
		lastID:                make(map[string]int),
	}, nil
}

func validServiceHealthIdentity(config ServiceConfig) bool {
	probe := health.Snapshot{
		ObservedAt:               time.Unix(1, 0).UTC(),
		FleetAlias:               config.FleetAlias,
		AcquisitionMode:          health.AcquisitionDisabled,
		PolicyEpoch:              1,
		PolicyDigest:             fmt.Sprintf("%064x", 0),
		RepositoryPolicyRevision: 1,
		HostProfileID:            config.HostProfileID,
		BuildID:                  config.BuildID,
	}
	return probe.Validate() == nil
}

// Start persists acquisition zero, promotes any interrupted acquisition call
// to ambiguous, reconstructs the complete live broker under that zero epoch,
// and remains disabled until an explicit operator transition.
func (s *Service) Start(ctx context.Context) error {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()

	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ErrServiceStarted
	}
	s.ready = false
	s.mu.Unlock()

	desired, err := s.transitions.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("%w: read acquisition policy: %w", ErrStartupRestore, err)
	}
	desired, err = CanonicalizeAcquisitionPolicy(desired)
	if err != nil {
		return fmt.Errorf("%w: invalid acquisition policy: %w", ErrStartupRestore, err)
	}
	zeroRequest := cloneAcquisitionPolicy(desired)
	zeroRequest.Mode = AcquisitionDisabled
	zeroRequest.MaxCapacity = 0
	zeroRequest.EligibleScaleSets = nil
	zeroed, err := s.transitions.Transition(ctx, desired.Epoch, zeroRequest)
	if err != nil {
		return fmt.Errorf("%w: persist startup zero: %w", ErrStartupRestore, err)
	}
	zeroed, err = validatePersistedAcquisitionTransition(desired.Epoch, zeroRequest, zeroed)
	if err != nil {
		return fmt.Errorf("%w: invalid startup zero: %w", ErrStartupRestore, err)
	}
	barrier, err := newAcquisitionBarrier(zeroed, false)
	if err != nil {
		return fmt.Errorf("%w: initialize startup barrier: %w", ErrStartupRestore, err)
	}
	s.mu.Lock()
	s.started = true
	s.policy = cloneAcquisitionPolicy(zeroed)
	s.barrier = barrier
	s.mu.Unlock()

	if err := s.broker.ApplyAcquisitionPolicy(zeroed); err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreBroker, err)
	}
	if _, err := s.state.PromoteBegunAcquisitions(ctx, s.now()); err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreStateRead, err)
	}
	recoverable, err := s.state.ListRecoverable(ctx)
	if err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreStateRead, err)
	}
	refs, err := validateRecoveryProjection(recoverable)
	if err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreInvalid, err)
	}
	if err := s.broker.Restore(refs); err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreBroker, err)
	}
	uncertain, err := s.state.ListUncertainAcks(ctx)
	if err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreAckRead, err)
	}
	uncertainByKey, err := validateUncertainReceipts(uncertain)
	if err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreInvalid, err)
	}

	revoked, err := s.state.MarkPreRunningRevoked(ctx, zeroed.Epoch, s.now())
	if err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreStateRead, err)
	}
	if err := s.revoker.RevokePreRunning(ctx, zeroed.Epoch, revoked); err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreInvalid, err)
	}
	if err := s.retireRevokedReferences(ctx, revoked); err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreBroker, err)
	}
	summary, err := s.state.OperationalSummary(ctx, s.now())
	if err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreStateRead, err)
	}
	if summary.UnassignedReleasedListeners != 0 {
		return s.failStartupLocked(
			ctx,
			zeroed,
			ReasonRestoreInvalid,
			ErrAcquisitionQuiescence,
		)
	}
	if err := barrier.open(zeroed.Epoch); err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreTransition, err)
	}

	s.mu.Lock()
	s.uncertain = uncertainByKey
	s.ready = true
	s.mu.Unlock()
	return nil
}

func (s *Service) failStartupLocked(
	ctx context.Context,
	current AcquisitionPolicy,
	reason ReasonCode,
	cause error,
) error {
	fatalRequest := cloneAcquisitionPolicy(current)
	fatalRequest.Mode = AcquisitionFatal
	fatalRequest.MaxCapacity = 0
	fatalRequest.EligibleScaleSets = nil
	barrier := s.barrierSnapshot()
	var closed *acquisitionEpoch
	var transitionErr error
	if barrier == nil {
		transitionErr = errors.New("controller: startup barrier unavailable")
	} else {
		closed, transitionErr = barrier.closeGate(current.Epoch)
	}
	var fatal AcquisitionPolicy
	if transitionErr == nil {
		fatal, transitionErr = s.transitions.Transition(ctx, current.Epoch, fatalRequest)
	}
	if transitionErr == nil {
		fatal, transitionErr = validatePersistedAcquisitionTransition(
			current.Epoch,
			fatalRequest,
			fatal,
		)
	}
	if transitionErr == nil {
		_, transitionErr = barrier.publish(closed, fatal)
	}
	if transitionErr == nil {
		s.setPolicy(fatal)
		_ = s.broker.ApplyAcquisitionPolicy(fatal)
	}
	s.mu.Lock()
	s.ready = false
	s.mu.Unlock()
	// A disabled/zero epoch already persisted before restoration began, so
	// this call always satisfies FatalTerminator's after-persist contract.
	s.terminator.TerminateAfterPersist(reason)
	if transitionErr != nil {
		return errors.Join(
			fmt.Errorf("%w: %w", ErrStartupRestore, cause),
			fmt.Errorf("controller: persist fatal startup state: %w", transitionErr),
		)
	}
	return fmt.Errorf("%w: %w", ErrStartupRestore, cause)
}

// Snapshot returns the live service policy. The raw transitioner remains an
// implementation detail so every mutation must pass through Transition.
func (s *Service) Snapshot(ctx context.Context) (AcquisitionPolicy, error) {
	if err := ctx.Err(); err != nil {
		return AcquisitionPolicy{}, err
	}
	policy, ready := s.policySnapshot()
	if !ready {
		return AcquisitionPolicy{}, ErrServiceNotReady
	}
	return policy, nil
}

// Transition is the only in-process policy mutation path. It closes the old
// admission gate before the durable CAS, publishes/cancels only after CAS
// success, joins all old work, revokes pre-running listeners, proves required
// quiescence, and only then opens the new epoch.
func (s *Service) Transition(
	ctx context.Context,
	expectedEpoch uint64,
	next AcquisitionPolicy,
) (AcquisitionPolicy, error) {
	if _, ok := ctx.Deadline(); !ok {
		return AcquisitionPolicy{}, ErrAcquisitionDeadlineRequired
	}
	if err := ctx.Err(); err != nil {
		return AcquisitionPolicy{}, err
	}
	canonical, err := CanonicalizeAcquisitionPolicy(next)
	if err != nil {
		return AcquisitionPolicy{}, fmt.Errorf("%w: policy: %w", ErrAcquisitionTransition, err)
	}
	if canonical.Epoch != expectedEpoch {
		return AcquisitionPolicy{}, fmt.Errorf(
			"%w: request epoch: %w",
			ErrAcquisitionTransition,
			ErrAcquisitionEpochMismatch,
		)
	}

	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	current, ready := s.policySnapshot()
	if !ready {
		return AcquisitionPolicy{}, ErrServiceNotReady
	}
	if current.Epoch != expectedEpoch {
		return AcquisitionPolicy{}, fmt.Errorf(
			"%w: current epoch: %w",
			ErrAcquisitionTransition,
			ErrAcquisitionEpochMismatch,
		)
	}
	barrier := s.barrierSnapshot()
	if barrier == nil {
		return AcquisitionPolicy{}, ErrServiceNotReady
	}
	closed, err := barrier.closeGate(expectedEpoch)
	if err != nil {
		return AcquisitionPolicy{}, fmt.Errorf("%w: close gate: %w", ErrAcquisitionTransition, err)
	}
	persisted, transitionErr := s.transitions.Transition(ctx, expectedEpoch, canonical)
	if transitionErr != nil {
		proofCtx, proofCancel := context.WithTimeout(
			context.Background(),
			s.durableFinishTimeout,
		)
		defer proofCancel()
		if observed, snapshotErr := s.transitions.Snapshot(proofCtx); snapshotErr == nil &&
			equalAcquisitionPolicy(observed, current) {
			if reopenErr := barrier.reopen(closed); reopenErr != nil {
				s.markNotReady()
				return AcquisitionPolicy{}, errors.Join(
					fmt.Errorf("%w: persist: %w", ErrAcquisitionTransition, transitionErr),
					fmt.Errorf("%w: reopen gate: %w", ErrAcquisitionTransition, reopenErr),
				)
			}
			return AcquisitionPolicy{}, fmt.Errorf(
				"%w: persist: %w",
				ErrAcquisitionTransition,
				transitionErr,
			)
		}
		s.markNotReady()
		return AcquisitionPolicy{}, fmt.Errorf(
			"%w: persistence outcome is not proven unchanged: %w",
			ErrAcquisitionTransition,
			transitionErr,
		)
	}
	persisted, err = validatePersistedAcquisitionTransition(
		expectedEpoch,
		canonical,
		persisted,
	)
	if err != nil {
		s.markNotReady()
		return AcquisitionPolicy{}, fmt.Errorf(
			"%w: invalid persisted result: %w",
			ErrAcquisitionTransition,
			err,
		)
	}
	old, err := barrier.publish(closed, persisted)
	if err != nil {
		s.markNotReady()
		return AcquisitionPolicy{}, fmt.Errorf("%w: publish: %w", ErrAcquisitionTransition, err)
	}
	s.setPolicy(persisted)

	if err := s.broker.ApplyAcquisitionPolicy(persisted); err != nil {
		return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
			persisted,
			old,
			ReasonAcquisitionBroker,
			err,
		)
	}
	joinCtx, joinCancel := context.WithTimeout(
		context.Background(),
		s.transitionJoinTimeout,
	)
	defer joinCancel()
	if err := barrier.waitEpoch(joinCtx, old); err != nil {
		return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
			persisted,
			old,
			ReasonAcquisitionJoin,
			err,
		)
	}
	operations, criticals := barrier.epochCounts(old)
	if operations != 0 || criticals != 0 {
		return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
			persisted,
			old,
			ReasonAcquisitionJoin,
			ErrAcquisitionQuiescence,
		)
	}
	revoked, err := s.state.MarkPreRunningRevoked(joinCtx, persisted.Epoch, s.now())
	if err != nil {
		return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
			persisted,
			old,
			ReasonAcquisitionRevoke,
			err,
		)
	}
	if err := s.revoker.RevokePreRunning(joinCtx, persisted.Epoch, revoked); err != nil {
		return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
			persisted,
			old,
			ReasonAcquisitionRevoke,
			err,
		)
	}
	if err := s.retireRevokedReferences(joinCtx, revoked); err != nil {
		return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
			persisted,
			old,
			ReasonAcquisitionRevoke,
			err,
		)
	}
	if requiresAcquisitionQuiescence(persisted) {
		summary, err := s.state.OperationalSummary(joinCtx, s.now())
		if err != nil {
			return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
				persisted,
				old,
				ReasonAcquisitionQuiescence,
				err,
			)
		}
		if summary.UnassignedReleasedListeners != 0 {
			return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
				persisted,
				old,
				ReasonAcquisitionQuiescence,
				ErrAcquisitionQuiescence,
			)
		}
	}
	if err := barrier.open(persisted.Epoch); err != nil {
		return AcquisitionPolicy{}, s.failTransitionAfterCASLocked(
			persisted,
			old,
			ReasonAcquisitionQuiescence,
			err,
		)
	}
	return cloneAcquisitionPolicy(persisted), nil
}

func (s *Service) failTransitionAfterCASLocked(
	current AcquisitionPolicy,
	old *acquisitionEpoch,
	reason ReasonCode,
	cause error,
) error {
	s.markNotReady()
	barrier := s.barrierSnapshot()
	if barrier == nil {
		return fmt.Errorf("%w: barrier unavailable: %w", ErrAcquisitionTransition, cause)
	}
	joinCtx, joinCancel := context.WithTimeout(
		context.Background(),
		s.transitionJoinTimeout,
	)
	defer joinCancel()

	var cleanupErr error
	if old != nil {
		cleanupErr = barrier.waitEpoch(joinCtx, old)
	}
	fatalRequest := cloneAcquisitionPolicy(current)
	fatalRequest.Mode = AcquisitionFatal
	fatalRequest.MaxCapacity = 0
	fatalRequest.EligibleScaleSets = nil
	closed, closeErr := barrier.closeGate(current.Epoch)
	if closeErr != nil {
		return errors.Join(
			fmt.Errorf("%w: %w", ErrAcquisitionTransition, cause),
			cleanupErr,
			fmt.Errorf("%w: close fatal gate: %w", ErrAcquisitionTransition, closeErr),
		)
	}
	fatalCtx, fatalCancel := context.WithTimeout(
		context.Background(),
		s.transitionJoinTimeout,
	)
	defer fatalCancel()
	fatal, fatalErr := s.transitions.Transition(
		fatalCtx,
		current.Epoch,
		fatalRequest,
	)
	if fatalErr == nil {
		fatal, fatalErr = validatePersistedAcquisitionTransition(
			current.Epoch,
			fatalRequest,
			fatal,
		)
	}
	if fatalErr == nil {
		_, fatalErr = barrier.publish(closed, fatal)
	}
	if fatalErr != nil {
		return errors.Join(
			fmt.Errorf("%w: %w", ErrAcquisitionTransition, cause),
			cleanupErr,
			fmt.Errorf("%w: persist fatal: %w", ErrAcquisitionTransition, fatalErr),
		)
	}
	s.setPolicy(fatal)
	_ = s.broker.ApplyAcquisitionPolicy(fatal)
	s.terminator.TerminateAfterPersist(reason)
	return errors.Join(
		fmt.Errorf("%w: %w", ErrAcquisitionTransition, cause),
		cleanupErr,
	)
}

func (s *Service) enterFatal(reason ReasonCode, cause error) error {
	current, ready := s.policySnapshot()
	if !ready {
		return fmt.Errorf("%w: %w", ErrPollFatal, cause)
	}
	fatalRequest := cloneAcquisitionPolicy(current)
	fatalRequest.Mode = AcquisitionFatal
	fatalRequest.MaxCapacity = 0
	fatalRequest.EligibleScaleSets = nil
	ctx, cancel := context.WithTimeout(
		context.Background(),
		s.transitionJoinTimeout,
	)
	defer cancel()
	if _, err := s.Transition(ctx, current.Epoch, fatalRequest); err != nil {
		return errors.Join(
			fmt.Errorf("%w: %w", ErrPollFatal, cause),
			err,
		)
	}
	s.markNotReady()
	s.terminator.TerminateAfterPersist(reason)
	return fmt.Errorf("%w: %w", ErrPollFatal, cause)
}

// ApplyPressure may only reduce effective capacity. It queues behind startup
// and persists the new epoch before changing broker scheduling capacity.
func (s *Service) ApplyPressure(ctx context.Context, maxCapacity int) error {
	return s.applyPressure(ctx, maxCapacity)
}

func (s *Service) applyPressure(ctx context.Context, maxCapacity int) error {
	current, ready := s.policySnapshot()
	if !ready {
		return ErrServiceNotReady
	}
	if maxCapacity < 0 || maxCapacity > current.MaxCapacity {
		return ErrPressureTransition
	}
	if maxCapacity == current.MaxCapacity {
		return nil
	}
	next := cloneAcquisitionPolicy(current)
	next.MaxCapacity = maxCapacity
	if maxCapacity == 0 {
		next.Mode = AcquisitionDisabled
		next.EligibleScaleSets = nil
	}
	transitionCtx, cancel := boundedContext(ctx, s.transitionJoinTimeout)
	defer cancel()
	_, err := s.Transition(transitionCtx, current.Epoch, next)
	if err != nil {
		return fmt.Errorf("%w: persist epoch: %w", ErrPressureTransition, err)
	}
	return nil
}

// EvaluateHistoryPressure accounts for the complete assignment-history graph,
// its in-flight reservation, and the independent network-ledger budget under
// the global service-cycle latch. It can only retain or reduce effective
// capacity; recovery requires a separate explicit policy transition.
func (s *Service) EvaluateHistoryPressure(ctx context.Context) (health.HistorySnapshot, error) {
	current, ready := s.policySnapshot()
	if !ready {
		return health.HistorySnapshot{}, ErrServiceNotReady
	}
	usage, err := s.state.HistoryUsage(ctx)
	if err != nil {
		// Failure to measure a required budget cannot authorize another
		// acquisition. Persist zero through the same epoch barrier before
		// returning the typed measurement failure.
		pressureErr := s.applyPressure(ctx, 0)
		if pressureErr != nil {
			return health.HistorySnapshot{}, errors.Join(
				fmt.Errorf("%w: read aggregate usage: %w", ErrHistoryPressure, err),
				pressureErr,
			)
		}
		return health.HistorySnapshot{}, fmt.Errorf(
			"%w: read aggregate usage: %w",
			ErrHistoryPressure,
			err,
		)
	}

	historyRows, rowsOverflow := addHistoryTotals(
		usage.LiveRows,
		usage.ProtectedTerminalRows,
		usage.MessageReceiptRows,
		usage.AcquisitionRows,
		usage.TombstoneRows,
		usage.ReservedRows,
	)
	historyBytes, bytesOverflow := addHistoryTotals(
		usage.LiveLogicalBytes,
		usage.ProtectedTerminalBytes,
		usage.MessageReceiptBytes,
		usage.AcquisitionLogicalBytes,
		usage.TombstoneLogicalBytes,
		usage.ReservedLogicalBytes,
	)
	reasons := pressureReasons(
		s.pressure,
		historyRows,
		historyBytes,
		usage.NetworkLedgerRows,
		usage.NetworkLedgerLogicalBytes,
	)
	level := pressureLevel(s.pressure, historyRows, historyBytes, usage)
	if rowsOverflow || bytesOverflow {
		level = health.PressureStop
		reasons |= observability.PressureReasonArithmeticOverflow
	}

	targetCapacity := current.MaxCapacity
	switch level {
	case health.PressureNormal:
	case health.PressureWarning:
		if s.pressure.WarningMaxCapacity < targetCapacity {
			targetCapacity = s.pressure.WarningMaxCapacity
		}
	case health.PressureStop:
		targetCapacity = 0
	default:
		return health.HistorySnapshot{}, ErrHistoryPressure
	}
	if targetCapacity < current.MaxCapacity {
		if err := s.applyPressure(ctx, targetCapacity); err != nil {
			return health.HistorySnapshot{}, fmt.Errorf(
				"%w: lower capacity: %w",
				ErrHistoryPressure,
				err,
			)
		}
	}
	persisted, ready := s.policySnapshot()
	if !ready || persisted.MaxCapacity < 0 {
		return health.HistorySnapshot{}, ErrHistoryPressure
	}
	observedAt := s.now()
	oldestAge := time.Duration(0)
	if !usage.OldestRetainedAt.IsZero() {
		if usage.OldestRetainedAt.After(observedAt) {
			return health.HistorySnapshot{}, fmt.Errorf(
				"%w: retained history timestamp is in the future",
				ErrHistoryPressure,
			)
		}
		oldestAge = observedAt.Sub(usage.OldestRetainedAt)
	}
	snapshot := health.HistorySnapshot{
		ObservedAt:                observedAt,
		Pressure:                  level,
		HistoryRows:               historyRows,
		HistoryLogicalBytes:       historyBytes,
		NetworkLedgerRows:         usage.NetworkLedgerRows,
		NetworkLedgerLogicalBytes: usage.NetworkLedgerLogicalBytes,
		InflightWork:              usage.InflightAssignments,
		UncertainAcknowledgements: uint64(s.UncertainAckCount()),
		OldestRetainedAge:         oldestAge,
		EffectiveCapacity:         uint64(persisted.MaxCapacity),
		PolicyEpoch:               persisted.Epoch,
	}
	if err := snapshot.Validate(); err != nil {
		return health.HistorySnapshot{}, fmt.Errorf("%w: validate snapshot: %w", ErrHistoryPressure, err)
	}
	event := observability.Event{
		Kind:     observability.EventHistoryPressureEvaluated,
		Reasons:  reasons,
		Snapshot: snapshot,
	}
	if err := event.Validate(); err != nil {
		return health.HistorySnapshot{}, fmt.Errorf("%w: validate event: %w", ErrHistoryPressure, err)
	}
	if err := s.eventSink.Emit(ctx, event); err != nil {
		return health.HistorySnapshot{}, fmt.Errorf("%w: emit event: %w", ErrHistoryPressure, err)
	}
	return snapshot, nil
}

// ReconcileOnce completes one bounded Task 7 reconciliation cycle, finalizes
// every newly destroyed assignment in stable identity order, and publishes
// exactly one closed Worker heartbeat. Any failure returns a zero receipt and
// publishes no heartbeat.
func (s *Service) ReconcileOnce(ctx context.Context) (CycleReceipt, error) {
	if _, err := s.EvaluateHostPressure(ctx); err != nil {
		return CycleReceipt{}, fmt.Errorf(
			"%w: host pressure: %w",
			ErrReconciliation,
			err,
		)
	}
	return s.reconcileOnceAfterHostPressure(ctx)
}

func (s *Service) reconcileOnceAfterHostPressure(
	ctx context.Context,
) (CycleReceipt, error) {
	policy, ready := s.policySnapshot()
	if !ready {
		return CycleReceipt{}, ErrServiceNotReady
	}
	reconcileCtx, cancel := boundedContext(ctx, s.reconciliationTimeout)
	defer cancel()

	receipt, err := s.reconciler.Once(reconcileCtx)
	if err != nil {
		if errors.Is(err, ErrJITFatal) {
			return CycleReceipt{}, s.enterFatal(ReasonAcquisitionJoin, err)
		}
		return CycleReceipt{}, fmt.Errorf("%w: cycle: %w", ErrReconciliation, err)
	}
	observedAt := s.now()
	if !validCycleReceipt(receipt, observedAt) {
		return CycleReceipt{}, fmt.Errorf(
			"%w: invalid cycle receipt",
			ErrReconciliation,
		)
	}

	finalizations, err := s.state.ListTerminalFinalizations(reconcileCtx)
	if err != nil {
		return CycleReceipt{}, fmt.Errorf(
			"%w: list terminal finalizations: %w",
			ErrReconciliation,
			err,
		)
	}
	finalizations, lastTerminalAt, err := canonicalTerminalFinalizations(
		finalizations,
		observedAt,
	)
	if err != nil {
		return CycleReceipt{}, fmt.Errorf(
			"%w: terminal finalizations: %w",
			ErrReconciliation,
			err,
		)
	}
	for _, finalization := range finalizations {
		if err := s.FinalizeTerminal(
			reconcileCtx,
			finalization.Key,
			finalization.MessageID,
			finalization.At,
		); err != nil {
			var fatal *fatalOperationError
			if errors.As(err, &fatal) {
				return CycleReceipt{}, s.enterFatal(fatal.reason, fatal.cause)
			}
			return CycleReceipt{}, fmt.Errorf(
				"%w: finalize terminal: %w",
				ErrReconciliation,
				err,
			)
		}
	}

	summary, err := s.state.OperationalSummary(reconcileCtx, observedAt)
	if err != nil {
		return CycleReceipt{}, fmt.Errorf(
			"%w: operational summary: %w",
			ErrReconciliation,
			err,
		)
	}
	if summary.LatestTerminalAt.After(lastTerminalAt) {
		lastTerminalAt = summary.LatestTerminalAt
	}
	current, ready := s.policySnapshot()
	if !ready || !equalAcquisitionPolicy(policy, current) {
		return CycleReceipt{}, fmt.Errorf(
			"%w: policy changed during cycle",
			ErrReconciliation,
		)
	}
	capacity := s.broker.CapacitySummary()
	if capacity.Epoch != current.Epoch ||
		capacity.EffectiveCapacity != current.MaxCapacity {
		return CycleReceipt{}, fmt.Errorf(
			"%w: capacity epoch or limit mismatch",
			ErrReconciliation,
		)
	}
	mode, err := healthAcquisitionMode(current.Mode)
	if err != nil {
		return CycleReceipt{}, fmt.Errorf("%w: %w", ErrReconciliation, err)
	}
	digest, err := AcquisitionPolicyDigest(current)
	if err != nil {
		return CycleReceipt{}, fmt.Errorf(
			"%w: policy digest: %w",
			ErrReconciliation,
			err,
		)
	}
	snapshot := health.Snapshot{
		ObservedAt:                  observedAt,
		FleetAlias:                  s.fleetAlias,
		AcquisitionMode:             mode,
		PolicyEpoch:                 current.Epoch,
		PolicyDigest:                hex.EncodeToString(digest[:]),
		RepositoryPolicyRevision:    current.RepositoryPolicyRevision,
		Capacity:                    healthCapacitySummary(capacity),
		AssignedJobs:                summary.AssignedJobs,
		RunningJobs:                 summary.RunningJobs,
		OldestLiveAssignmentAge:     summary.OldestLiveAssignmentAge,
		UnassignedReleasedListeners: summary.UnassignedReleasedListeners,
		LastTerminalAt:              lastTerminalAt,
		HostProfileID:               s.hostProfileID,
		Degraded:                    s.degraded,
		BuildID:                     s.buildID,
	}
	if err := snapshot.Validate(); err != nil {
		return CycleReceipt{}, fmt.Errorf(
			"%w: validate heartbeat: %w",
			ErrReconciliation,
			err,
		)
	}
	if err := s.health.Publish(reconcileCtx, snapshot); err != nil {
		return CycleReceipt{}, fmt.Errorf(
			"%w: publish heartbeat: %w",
			ErrReconciliation,
			err,
		)
	}
	return receipt, nil
}

func validCycleReceipt(receipt CycleReceipt, observedAt time.Time) bool {
	return validAcquisitionScalar(receipt.CycleID, 128) &&
		!receipt.CompletedAt.IsZero() &&
		!receipt.CompletedAt.After(observedAt) &&
		receipt.AssignmentCount >= 0 &&
		receipt.OldestAge >= 0
}

func canonicalTerminalFinalizations(
	input []TerminalFinalization,
	observedAt time.Time,
) ([]TerminalFinalization, time.Time, error) {
	ordered := append([]TerminalFinalization(nil), input...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i].Key, ordered[j].Key
		if left.RepositoryAlias != right.RepositoryAlias {
			return left.RepositoryAlias < right.RepositoryAlias
		}
		if left.RunnerRequestID != right.RunnerRequestID {
			return left.RunnerRequestID < right.RunnerRequestID
		}
		return left.Attempt < right.Attempt
	})
	var lastTerminalAt time.Time
	for index, finalization := range ordered {
		if finalization.Key.RepositoryAlias == "" ||
			finalization.Key.RunnerRequestID <= 0 ||
			finalization.MessageID <= 0 ||
			finalization.At.IsZero() ||
			finalization.At.After(observedAt) ||
			(index > 0 && ordered[index-1].Key == finalization.Key) {
			return nil, time.Time{}, ErrDurableIdentityConflict
		}
		if finalization.At.After(lastTerminalAt) {
			lastTerminalAt = finalization.At
		}
	}
	return ordered, lastTerminalAt, nil
}

func healthAcquisitionMode(mode AcquisitionMode) (health.AcquisitionMode, error) {
	switch mode {
	case AcquisitionDisabled:
		return health.AcquisitionDisabled, nil
	case AcquisitionCanaryOnly:
		return health.AcquisitionCanaryOnly, nil
	case AcquisitionEnabled:
		return health.AcquisitionEnabled, nil
	case AcquisitionFatal:
		return health.AcquisitionFatal, nil
	default:
		return "", ErrInvalidAcquisitionPolicy
	}
}

func healthCapacitySummary(capacity CapacitySummary) health.CapacitySummary {
	return health.CapacitySummary{
		Configured: capacity.ConfiguredCapacity,
		Effective:  capacity.EffectiveCapacity,
		Occupied:   capacity.Occupied,
		Available:  capacity.Available,
		Queued:     capacity.Queued,
	}
}

// PollOnce owns one repository-scoped epoch critical section from before lease
// acquisition through durable completion and Ack. A transition cancels its
// epoch and joins this section rather than waiting on one global network-call
// mutex shared by unrelated repositories.
func (s *Service) PollOnce(
	ctx context.Context,
	fleet githubscale.Fleet,
	session githubscale.Session,
) error {
	if _, err := s.EvaluateHostPressure(ctx); err != nil {
		return fmt.Errorf("%w: host pressure: %w", ErrPollCycle, err)
	}
	return s.pollOnceAfterHostPressure(ctx, fleet, session)
}

func (s *Service) pollOnceAfterHostPressure(
	ctx context.Context,
	fleet githubscale.Fleet,
	session githubscale.Session,
) error {
	_, ready := s.policySnapshot()
	if !ready {
		return ErrServiceNotReady
	}
	if session == nil ||
		fleet.RepositoryAlias == "" ||
		fleet.ScaleSetName == "" {
		return fmt.Errorf("%w: invalid poll boundary", ErrPollCycle)
	}
	cycleCtx, cycleCancel := boundedContext(ctx, s.pollCycleTimeout)
	defer cycleCancel()
	barrier := s.barrierSnapshot()
	if barrier == nil {
		return ErrServiceNotReady
	}
	critical, err := barrier.beginCritical(cycleCtx, fleet.RepositoryAlias, 0)
	if err != nil {
		return fmt.Errorf("%w: enter epoch: %w", ErrPollCycle, err)
	}
	pollErr := s.pollOnceCritical(
		critical.Context(),
		critical.Policy(),
		fleet,
		session,
	)
	closeErr := critical.Close()
	if closeErr != nil {
		pollErr = errors.Join(
			pollErr,
			&fatalOperationError{
				reason: ReasonAcquisitionJoin,
				cause:  closeErr,
			},
		)
	}
	var fatal *fatalOperationError
	if errors.As(pollErr, &fatal) {
		return s.enterFatal(fatal.reason, fatal.cause)
	}
	return pollErr
}

func (s *Service) retireRevokedReferences(
	ctx context.Context,
	keys []AssignmentKey,
) error {
	ordered := append([]AssignmentKey(nil), keys...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].RepositoryAlias != ordered[j].RepositoryAlias {
			return ordered[i].RepositoryAlias < ordered[j].RepositoryAlias
		}
		if ordered[i].RunnerRequestID != ordered[j].RunnerRequestID {
			return ordered[i].RunnerRequestID < ordered[j].RunnerRequestID
		}
		return ordered[i].Attempt < ordered[j].Attempt
	})
	for index, key := range ordered {
		if key.RepositoryAlias == "" || key.RunnerRequestID <= 0 ||
			(index != 0 && key == ordered[index-1]) {
			return fmt.Errorf(
				"%w: invalid revoked assignment identity",
				ErrAcquisitionQuiescence,
			)
		}
		ref, present, err := s.broker.Reference(key)
		if err != nil {
			return fmt.Errorf(
				"%w: inspect revoked broker reference: %w",
				ErrAcquisitionQuiescence,
				err,
			)
		}
		if present {
			if ref.Key != key {
				return fmt.Errorf(
					"%w: revoked broker reference identity mismatch",
					ErrAcquisitionQuiescence,
				)
			}
			switch ref.Phase {
			case AdmissionActive:
				if err := s.broker.Release(key); err != nil {
					return fmt.Errorf(
						"%w: release revoked active reference: %w",
						ErrAcquisitionQuiescence,
						err,
					)
				}
			case AdmissionQueued, AdmissionReserved:
			default:
				return fmt.Errorf(
					"%w: invalid revoked broker reference phase",
					ErrAcquisitionQuiescence,
				)
			}
			if err := s.broker.Retire(key); err != nil {
				return fmt.Errorf(
					"%w: retire revoked broker reference: %w",
					ErrAcquisitionQuiescence,
					err,
				)
			}
		}
		if s.broker.HasLiveReference(key) {
			return fmt.Errorf(
				"%w: revoked broker reference remains live",
				ErrAcquisitionQuiescence,
			)
		}
		if err := s.state.ClearAdmission(ctx, key); err != nil {
			return fmt.Errorf(
				"%w: clear revoked durable admission: %w",
				ErrAcquisitionQuiescence,
				err,
			)
		}
	}
	return nil
}

func (s *Service) pollOnceCritical(
	ctx context.Context,
	policy AcquisitionPolicy,
	fleet githubscale.Fleet,
	session githubscale.Session,
) error {
	now := s.now()
	lease, err := s.broker.LeasePoll(fleet.RepositoryAlias, now)
	if err != nil {
		return fmt.Errorf("%w: lease: %w", ErrPollCycle, err)
	}
	if lease.RepositoryAlias != fleet.RepositoryAlias ||
		lease.Epoch != policy.Epoch ||
		lease.Reserved < 0 ||
		lease.Reserved > lease.PollCapacity ||
		lease.PollCapacity < 0 ||
		lease.PollCapacity > policy.MaxCapacity ||
		(policy.Mode == AcquisitionCanaryOnly && lease.PollCapacity > 1) ||
		lease.ExpiresAt.IsZero() ||
		!lease.ExpiresAt.After(now) {
		return fmt.Errorf("%w: invalid poll lease", ErrPollCycle)
	}

	lastMessageID := s.lastMessageIDLocked(fleet.RepositoryAlias)
	batch, err := s.pollBatch(ctx, policy, fleet, lease, session, lastMessageID)
	if err != nil {
		return fmt.Errorf("%w: upstream poll: %w", ErrPollCycle, err)
	}
	if batch.Empty {
		return nil
	}
	if batch.MessageID <= 0 {
		return fmt.Errorf("%w: nonempty batch has invalid message identity", ErrPollCycle)
	}
	if !batch.StatisticsPresent {
		return fmt.Errorf("%w: nonempty batch omitted statistics", ErrPollCycle)
	}
	envelope := NewMessageEnvelope(fleet.RepositoryAlias, batch)
	keys := make([]AssignmentKey, 0, len(batch.Offers))
	for _, offer := range batch.Offers {
		keys = append(keys, AssignmentKey{
			RepositoryAlias: fleet.RepositoryAlias,
			RunnerRequestID: offer.RunnerRequestID,
		})
	}
	releaseKeys := s.sequencer.Acquire(keys)
	defer releaseKeys()

	receipt, err := s.state.RecordMessageReceipt(ctx, envelope, now)
	if err != nil {
		return fmt.Errorf("%w: persist message receipt: %w", ErrPollCycle, err)
	}
	if receipt.State == MessageAckConfirmed {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: epoch cancelled before demand: %w", ErrPollCycle, err)
		}
		if batch.Statistics.TotalAssignedJobs < 0 {
			return fmt.Errorf("%w: invalid assigned-job demand", ErrPollCycle)
		}
		if err := s.broker.SetDemand(
			fleet.RepositoryAlias,
			policy.Epoch,
			batch.Statistics.TotalAssignedJobs,
		); err != nil {
			return fmt.Errorf("%w: restore exact-redelivery demand: %w", ErrPollCycle, err)
		}
		return s.ackMessage(
			ctx,
			fleet.RepositoryAlias,
			batch.MessageID,
			receipt,
			session,
			now,
		)
	}
	if err := s.events.RecordBatch(ctx, envelope); err != nil {
		return fmt.Errorf("%w: persist batch events: %w", ErrPollCycle, err)
	}

	observed := make([]observedOffer, 0, len(batch.Offers))
	seen := make(map[AssignmentKey]struct{}, len(batch.Offers))
	for _, offer := range batch.Offers {
		record, err := s.state.RecordOffer(ctx, fleet.RepositoryAlias, offer, OfferEvidence{
			Kind:       OfferEvidenceCurrentPoll,
			MessageID:  batch.MessageID,
			QueueTime:  offer.QueueTime,
			ObservedAt: now,
		})
		if err != nil {
			return fmt.Errorf("%w: persist offer: %w", ErrPollCycle, err)
		}
		if _, duplicate := seen[record.Key]; duplicate {
			continue
		}
		seen[record.Key] = struct{}{}
		observed = append(observed, observedOffer{
			offer:  cloneServiceOffer(offer),
			record: record,
		})
	}

	local := make([]observedOffer, 0, len(observed))
	for _, item := range observed {
		if item.record.Disposition == OfferTerminalReplay ||
			item.record.State != StateReceived {
			continue
		}
		localEligible, hostedReason := s.localEligibility(ctx, now, fleet, item.offer)
		if localEligible {
			if err := s.broker.CheckOffer(fleet.RepositoryAlias, item.offer); err != nil {
				if errors.Is(err, ErrOfferTooLarge) {
					if err := s.routeHostedLocked(
						ctx,
						policy,
						item.record,
						batch.MessageID,
						HostedReasonOfferTooLarge,
					); err != nil {
						return err
					}
					continue
				}
				return fmt.Errorf("%w: offer preflight: %w", ErrPollCycle, err)
			}
			local = append(local, item)
			continue
		}
		if err := s.routeHostedLocked(
			ctx,
			policy,
			item.record,
			batch.MessageID,
			hostedReason,
		); err != nil {
			return err
		}
	}

	var acquiredLocal []observedOffer
	if len(local) != 0 && lease.Reserved > 0 {
		acquiredLocal, err = s.acquireLocalOffers(
			ctx,
			policy,
			fleet,
			session,
			batch.MessageID,
			lease,
			local,
		)
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: epoch cancelled before demand: %w", ErrPollCycle, err)
	}
	if batch.Statistics.TotalAssignedJobs < 0 {
		return fmt.Errorf("%w: invalid assigned-job demand", ErrPollCycle)
	}
	if err := s.broker.SetDemand(
		fleet.RepositoryAlias,
		policy.Epoch,
		batch.Statistics.TotalAssignedJobs,
	); err != nil {
		return fmt.Errorf("%w: set assigned-job demand: %w", ErrPollCycle, err)
	}

	if len(acquiredLocal) != 0 {
		offers := make([]githubscale.Offer, len(acquiredLocal))
		localByKey := make(map[AssignmentKey]struct{}, len(acquiredLocal))
		for i, item := range acquiredLocal {
			offers[i] = cloneServiceOffer(item.offer)
			localByKey[item.record.Key] = struct{}{}
		}
		projections, err := s.broker.EnsureQueuedBatch(
			policy.Epoch,
			fleet.RepositoryAlias,
			offers,
		)
		if err != nil {
			if errors.Is(err, ErrAdmissionHeadroom) {
				if clearErr := s.clearQueuedProjectionsLocked(ctx, acquiredLocal); clearErr != nil {
					return &fatalOperationError{
						reason: ReasonProjectionPersist,
						cause:  fmt.Errorf("clear queued projections after broker refusal: %w", clearErr),
					}
				}
				return err
			}
			return &fatalOperationError{
				reason: ReasonProjectionPersist,
				cause:  fmt.Errorf("broker queued batch outcome uncertain: %w", err),
			}
		}
		if len(projections) != len(localByKey) {
			return &fatalOperationError{
				reason: ReasonProjectionPersist,
				cause:  fmt.Errorf("broker returned incomplete projection set"),
			}
		}
		for _, projection := range projections {
			if _, expected := localByKey[projection.Key]; !expected ||
				(projection.Phase != AdmissionQueued && projection.Phase != AdmissionReserved) {
				return &fatalOperationError{
					reason: ReasonProjectionPersist,
					cause:  fmt.Errorf("broker returned invalid projection"),
				}
			}
			delete(localByKey, projection.Key)
			if err := s.state.PersistAdmission(ctx, projection.Key, projection); err != nil {
				return &fatalOperationError{
					reason: ReasonProjectionPersist,
					cause:  err,
				}
			}
		}
		if len(localByKey) != 0 {
			return &fatalOperationError{
				reason: ReasonProjectionPersist,
				cause:  fmt.Errorf("broker omitted projection identity"),
			}
		}
	}

	return s.ackMessage(
		ctx,
		fleet.RepositoryAlias,
		batch.MessageID,
		receipt,
		session,
		now,
	)
}

func (s *Service) ackMessage(
	ctx context.Context,
	repositoryAlias string,
	messageID int,
	receipt MessageReceiptRecord,
	session githubscale.Session,
	now time.Time,
) error {
	switch receipt.State {
	case MessageAckPersisted, MessageAckRedeliveryProven:
	case MessageAckStarted, MessageAckConfirmed:
		if err := s.state.ObserveRedelivery(
			ctx,
			repositoryAlias,
			messageID,
			receipt.Digest,
			now,
		); err != nil {
			return fmt.Errorf("%w: prove exact redelivery: %w", ErrAckUncertain, err)
		}
	default:
		return fmt.Errorf("%w: invalid durable receipt state", ErrAckUncertain)
	}
	if err := s.state.BeginAck(ctx, repositoryAlias, messageID, now); err != nil {
		return fmt.Errorf("%w: begin durable acknowledgement: %w", ErrAckUncertain, err)
	}
	s.rememberUncertain(UncertainMessageReceipt{
		RepositoryAlias: repositoryAlias,
		MessageID:       messageID,
		Digest:          receipt.Digest,
		StartedAt:       now,
	})
	ackCtx, cancel := context.WithTimeout(ctx, s.ackTimeout)
	defer cancel()
	if err := session.Ack(ackCtx, messageID); err != nil {
		return fmt.Errorf("%w: upstream acknowledgement: %w", ErrAckUncertain, err)
	}
	confirmedAt := s.now()
	if err := s.state.ConfirmAck(
		ctx,
		repositoryAlias,
		messageID,
		confirmedAt,
	); err != nil {
		return fmt.Errorf("%w: persist acknowledgement confirmation: %w", ErrAckUncertain, err)
	}
	s.confirmMessage(repositoryAlias, messageID)
	return nil
}

func (s *Service) pollBatch(
	ctx context.Context,
	policy AcquisitionPolicy,
	fleet githubscale.Fleet,
	lease PollLease,
	session githubscale.Session,
	lastMessageID int,
) (githubscale.Batch, error) {
	operationCtx, cancel := boundedContext(ctx, s.operationTimeout)
	defer cancel()
	if lease.PollCapacity == 0 {
		operation, err := s.barrierSnapshot().beginOperation(
			operationCtx,
			"observer-poll",
			fleet.RepositoryAlias,
			fleet.ScaleSetName,
		)
		if err != nil {
			return githubscale.Batch{}, err
		}
		batch, pending, callErr, cancelErr := runTrackedCall(
			operation.Context(),
			s.transitionJoinTimeout,
			func(callCtx context.Context) (githubscale.Batch, error) {
				return session.Poll(callCtx, lastMessageID, 0)
			},
		)
		if pending != nil {
			go func() {
				<-pending
				_ = operation.Close()
			}()
			return githubscale.Batch{}, &fatalOperationError{
				reason: ReasonAcquisitionJoin,
				cause:  ErrAcquisitionOperationUnjoinable,
			}
		}
		closeErr := operation.Close()
		if closeErr != nil {
			return githubscale.Batch{}, &fatalOperationError{
				reason: ReasonAcquisitionJoin,
				cause:  closeErr,
			}
		}
		return batch, errors.Join(cancelErr, callErr)
	}

	guarded, err := s.acquireGuardedOperation(
		operationCtx,
		"poll",
		fleet.RepositoryAlias,
		fleet.ScaleSetName,
		func(current AcquisitionPolicy, capacity CapacitySummary) error {
			if current.Epoch != policy.Epoch ||
				lease.Epoch != current.Epoch ||
				!lease.ExpiresAt.After(s.now()) ||
				lease.PollCapacity <= 0 ||
				lease.PollCapacity > current.MaxCapacity ||
				capacity.EffectiveCapacity < lease.PollCapacity {
				return ErrAdmissionConflict
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, ErrAcquisitionGuardClose) {
			return githubscale.Batch{}, &fatalOperationError{
				reason: ReasonAcquisitionResult,
				cause:  err,
			}
		}
		return githubscale.Batch{}, err
	}
	batch, pending, callErr, cancelErr := runTrackedCall(
		guarded.operation.Context(),
		s.transitionJoinTimeout,
		func(callCtx context.Context) (githubscale.Batch, error) {
			return session.Poll(callCtx, lastMessageID, lease.PollCapacity)
		},
	)
	if pending != nil {
		closeGuardedAfter(guarded, pending)
		return githubscale.Batch{}, &fatalOperationError{
			reason: ReasonAcquisitionJoin,
			cause:  ErrAcquisitionOperationUnjoinable,
		}
	}
	closeErr := guarded.Close()
	if closeErr != nil {
		return githubscale.Batch{}, &fatalOperationError{
			reason: ReasonAcquisitionJoin,
			cause:  closeErr,
		}
	}
	return batch, errors.Join(cancelErr, callErr)
}

func (s *Service) acquireLocalOffers(
	ctx context.Context,
	policy AcquisitionPolicy,
	fleet githubscale.Fleet,
	session githubscale.Session,
	messageID int,
	lease PollLease,
	local []observedOffer,
) ([]observedOffer, error) {
	ordered := append([]observedOffer(nil), local...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i].record.Key, ordered[j].record.Key
		if left.RepositoryAlias != right.RepositoryAlias {
			return left.RepositoryAlias < right.RepositoryAlias
		}
		if left.RunnerRequestID != right.RunnerRequestID {
			return left.RunnerRequestID < right.RunnerRequestID
		}
		return left.Attempt < right.Attempt
	})
	if lease.Reserved <= 0 ||
		lease.Reserved > lease.PollCapacity ||
		lease.PollCapacity > policy.MaxCapacity ||
		!lease.ExpiresAt.After(s.now()) {
		return nil, fmt.Errorf("%w: invalid acquisition lease", ErrPollCycle)
	}
	if len(ordered) > lease.Reserved {
		ordered = ordered[:lease.Reserved]
	}
	keys := make([]AssignmentKey, len(ordered))
	for i, item := range ordered {
		keys[i] = item.record.Key
	}
	batchRecord, err := s.state.BeginAcquisition(
		ctx,
		fleet.RepositoryAlias,
		messageID,
		keys,
		s.now(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: persist acquisition intent: %w", ErrPollCycle, err)
	}
	if batchRecord.RepositoryAlias != fleet.RepositoryAlias ||
		batchRecord.MessageID != messageID ||
		batchRecord.RequestedCount != len(keys) {
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause:  ErrDurableIdentityConflict,
		}
	}
	switch batchRecord.Status {
	case AcquisitionBatchCompleted:
		if batchRecord.CallAuthorized {
			return nil, &fatalOperationError{
				reason: ReasonAcquisitionResult,
				cause:  ErrDurableIdentityConflict,
			}
		}
		return s.completedAcquisitionOffers(ctx, ordered, batchRecord)
	case AcquisitionBatchBegun:
		if !batchRecord.CallAuthorized {
			return nil, &fatalOperationError{
				reason: ReasonAcquisitionResult,
				cause:  ErrAckUncertain,
			}
		}
	case AcquisitionBatchAmbiguous:
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause:  ErrAckUncertain,
		}
	default:
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause:  ErrDurableIdentityConflict,
		}
	}

	operationCtx, operationCancel := boundedContext(ctx, s.operationTimeout)
	defer operationCancel()
	guarded, err := s.acquireGuardedOperation(
		operationCtx,
		"acquire",
		fleet.RepositoryAlias,
		fleet.ScaleSetName,
		func(current AcquisitionPolicy, capacity CapacitySummary) error {
			if current.Epoch != policy.Epoch ||
				lease.Epoch != current.Epoch ||
				!lease.ExpiresAt.After(s.now()) ||
				lease.Reserved <= 0 ||
				lease.PollCapacity <= 0 ||
				capacity.Epoch != current.Epoch ||
				capacity.EffectiveCapacity < lease.PollCapacity {
				return ErrAdmissionConflict
			}
			return nil
		},
	)
	if err != nil {
		finishCtx, finishCancel := context.WithTimeout(
			context.Background(),
			s.durableFinishTimeout,
		)
		defer finishCancel()
		if _, abortErr := s.state.AbortAcquisitionBeforeCall(
			finishCtx,
			fleet.RepositoryAlias,
			messageID,
			s.now(),
		); abortErr != nil {
			return nil, &fatalOperationError{
				reason: ReasonAcquisitionResult,
				cause:  errors.Join(err, abortErr),
			}
		}
		if errors.Is(err, ErrAcquisitionGuardClose) {
			return nil, &fatalOperationError{
				reason: ReasonAcquisitionResult,
				cause:  err,
			}
		}
		return nil, fmt.Errorf("%w: acquire authority: %w", ErrPollCycle, err)
	}

	requestIDs := make([]int64, len(keys))
	for i, key := range keys {
		requestIDs[i] = key.RunnerRequestID
	}
	acquiredIDs, pending, callErr, cancelErr := runTrackedCall(
		guarded.operation.Context(),
		s.transitionJoinTimeout,
		func(callCtx context.Context) ([]int64, error) {
			return session.Acquire(callCtx, requestIDs)
		},
	)
	if pending != nil {
		finishErr := s.markAcquisitionAmbiguous(
			fleet.RepositoryAlias,
			messageID,
		)
		closeGuardedAfter(guarded, pending)
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionJoin,
			cause: errors.Join(
				ErrAcquisitionOperationUnjoinable,
				cancelErr,
				finishErr,
			),
		}
	}
	if callErr != nil {
		finishErr := s.markAcquisitionAmbiguous(
			fleet.RepositoryAlias,
			messageID,
		)
		closeErr := guarded.Close()
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause:  errors.Join(callErr, cancelErr, finishErr, closeErr),
		}
	}
	acquiredKeys, validationErr := validateAcquiredIDs(
		fleet.RepositoryAlias,
		keys,
		acquiredIDs,
	)
	if validationErr != nil {
		finishErr := s.markAcquisitionAmbiguous(
			fleet.RepositoryAlias,
			messageID,
		)
		closeErr := guarded.Close()
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause:  errors.Join(validationErr, cancelErr, finishErr, closeErr),
		}
	}
	finishCtx, finishCancel := context.WithTimeout(
		context.Background(),
		s.durableFinishTimeout,
	)
	completed, completeErr := s.state.CompleteAcquisition(
		finishCtx,
		fleet.RepositoryAlias,
		messageID,
		acquiredKeys,
		s.now(),
	)
	finishCancel()
	if completeErr != nil ||
		completed.Status != AcquisitionBatchCompleted ||
		completed.AcquiredCount != len(acquiredKeys) ||
		completed.RequestedCount != len(keys) {
		ambiguousErr := s.markAcquisitionAmbiguous(
			fleet.RepositoryAlias,
			messageID,
		)
		closeErr := guarded.Close()
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause: errors.Join(
				ErrDurableIdentityConflict,
				completeErr,
				ambiguousErr,
				closeErr,
			),
		}
	}
	if closeErr := guarded.Close(); closeErr != nil {
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause:  closeErr,
		}
	}
	acquired := selectAcquiredOffers(ordered, acquiredKeys)
	if cancelErr != nil {
		return nil, fmt.Errorf(
			"%w: acquisition completed after epoch cancellation: %w",
			ErrPollCycle,
			cancelErr,
		)
	}
	return acquired, nil
}

func (s *Service) completedAcquisitionOffers(
	ctx context.Context,
	ordered []observedOffer,
	batch AcquisitionBatchRecord,
) ([]observedOffer, error) {
	acquired := make([]AssignmentKey, 0, batch.AcquiredCount)
	for _, item := range ordered {
		record, err := s.state.AcquisitionAssignment(ctx, item.record.Key)
		if err != nil ||
			record.Key != item.record.Key ||
			record.RevokedEpoch != 0 {
			return nil, &fatalOperationError{
				reason: ReasonAcquisitionResult,
				cause:  errors.Join(ErrDurableIdentityConflict, err),
			}
		}
		switch record.Outcome {
		case AssignmentAcquired:
			acquired = append(acquired, record.Key)
		case AssignmentRejected:
		default:
			return nil, &fatalOperationError{
				reason: ReasonAcquisitionResult,
				cause:  ErrDurableIdentityConflict,
			}
		}
	}
	if len(acquired) != batch.AcquiredCount {
		return nil, &fatalOperationError{
			reason: ReasonAcquisitionResult,
			cause:  ErrDurableIdentityConflict,
		}
	}
	return selectAcquiredOffers(ordered, acquired), nil
}

func (s *Service) markAcquisitionAmbiguous(
	repositoryAlias string,
	messageID int,
) error {
	finishCtx, cancel := context.WithTimeout(
		context.Background(),
		s.durableFinishTimeout,
	)
	defer cancel()
	record, err := s.state.MarkAcquisitionAmbiguous(
		finishCtx,
		repositoryAlias,
		messageID,
		s.now(),
	)
	if err != nil {
		return err
	}
	if record.Status != AcquisitionBatchAmbiguous {
		return ErrDurableIdentityConflict
	}
	return nil
}

func validateAcquiredIDs(
	repositoryAlias string,
	requested []AssignmentKey,
	acquiredIDs []int64,
) ([]AssignmentKey, error) {
	requestedByID := make(map[int64]AssignmentKey, len(requested))
	for _, key := range requested {
		if key.RepositoryAlias != repositoryAlias ||
			key.RunnerRequestID <= 0 ||
			key.Attempt != 0 {
			return nil, ErrDurableIdentityConflict
		}
		requestedByID[key.RunnerRequestID] = key
	}
	acquired := make([]AssignmentKey, 0, len(acquiredIDs))
	seen := make(map[int64]struct{}, len(acquiredIDs))
	for _, requestID := range acquiredIDs {
		key, ok := requestedByID[requestID]
		if !ok {
			return nil, ErrDurableIdentityConflict
		}
		if _, duplicate := seen[requestID]; duplicate {
			return nil, ErrDurableIdentityConflict
		}
		seen[requestID] = struct{}{}
		acquired = append(acquired, key)
	}
	sort.Slice(acquired, func(i, j int) bool {
		return acquired[i].RunnerRequestID < acquired[j].RunnerRequestID
	})
	return acquired, nil
}

func selectAcquiredOffers(
	ordered []observedOffer,
	acquired []AssignmentKey,
) []observedOffer {
	acquiredSet := make(map[AssignmentKey]struct{}, len(acquired))
	for _, key := range acquired {
		acquiredSet[key] = struct{}{}
	}
	out := make([]observedOffer, 0, len(acquired))
	for _, item := range ordered {
		if _, ok := acquiredSet[item.record.Key]; ok {
			out = append(out, item)
		}
	}
	return out
}

// AdmitOnce consumes the broker's already-mutated decisions and immediately
// commits each exact active projection, stable slot identity, and
// RECEIVED-to-CAPACITY_RESERVED transition in one durable transaction.
func (s *Service) AdmitOnce(ctx context.Context) ([]AdmissionDecision, error) {
	if _, err := s.EvaluateHostPressure(ctx); err != nil {
		return nil, fmt.Errorf(
			"%w: host pressure: %w",
			ErrAdmissionUnavailable,
			err,
		)
	}
	return s.admitOnceAfterHostPressure(ctx)
}

func (s *Service) admitOnceAfterHostPressure(
	ctx context.Context,
) ([]AdmissionDecision, error) {
	if _, ready := s.policySnapshot(); !ready {
		return nil, ErrServiceNotReady
	}
	admitCtx, cancel := boundedContext(ctx, s.durableFinishTimeout)
	defer cancel()
	barrier := s.barrierSnapshot()
	if barrier == nil {
		return nil, ErrServiceNotReady
	}
	critical, err := barrier.beginCritical(admitCtx, "controller-admit", 0)
	if err != nil {
		return nil, fmt.Errorf("%w: enter epoch: %w", ErrAdmissionUnavailable, err)
	}
	decisions, admitErr := s.admitOnceCritical(critical.Context(), critical.Epoch())
	closeErr := critical.Close()
	if closeErr != nil {
		admitErr = errors.Join(
			admitErr,
			&fatalOperationError{reason: ReasonAcquisitionJoin, cause: closeErr},
		)
	}
	var fatal *fatalOperationError
	if errors.As(admitErr, &fatal) {
		return nil, s.enterFatal(fatal.reason, fatal.cause)
	}
	return decisions, admitErr
}

func (s *Service) admitOnceCritical(
	ctx context.Context,
	epoch uint64,
) ([]AdmissionDecision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if capacity := s.broker.CapacitySummary(); capacity.Epoch != epoch {
		return nil, ErrAdmissionConflict
	}
	decisions, err := s.broker.Admit(epoch, s.now())
	if err != nil {
		return nil, &fatalOperationError{
			reason: ReasonActivePersist,
			cause:  fmt.Errorf("broker admit may be partially applied: %w", err),
		}
	}
	finishCtx, finishCancel := context.WithTimeout(
		context.Background(),
		s.durableFinishTimeout,
	)
	defer finishCancel()
	keys := make([]AssignmentKey, len(decisions))
	for i, decision := range decisions {
		keys[i] = decision.Key
	}
	releaseKeys := s.sequencer.Acquire(keys)
	defer releaseKeys()

	seen := make(map[AssignmentKey]struct{}, len(decisions))
	for _, decision := range decisions {
		projection := decision.Projection
		if _, duplicate := seen[decision.Key]; duplicate ||
			projection.Key != decision.Key ||
			projection.Phase != AdmissionActive ||
			projection.SlotID == 0 ||
			projection.LedgerCreatedAt.IsZero() ||
			!projection.LedgerEverUsed ||
			!validControllerResources(projection.FullCharge) ||
			!validControllerResources(projection.LedgerCharge) ||
			!controllerResourcesContain(projection.FullCharge, projection.LedgerCharge) {
			return nil, &fatalOperationError{
				reason: ReasonActivePersist,
				cause:  fmt.Errorf("broker returned invalid active projection"),
			}
		}
		seen[decision.Key] = struct{}{}
		acquisition, err := s.state.AcquisitionAssignment(finishCtx, decision.Key)
		if err != nil ||
			acquisition.Key != decision.Key ||
			acquisition.Outcome != AssignmentAcquired ||
			acquisition.RevokedEpoch != 0 {
			return nil, &fatalOperationError{
				reason: ReasonActivePersist,
				cause:  errors.Join(ErrAdmissionConflict, err),
			}
		}
		if err := s.state.ReserveActive(
			finishCtx,
			decision.Key,
			projection,
			opaqueSlotName(decision.Key),
		); err != nil {
			return nil, &fatalOperationError{
				reason: ReasonActivePersist,
				cause:  err,
			}
		}
	}
	return append([]AdmissionDecision(nil), decisions...), nil
}

// FinalizeTerminal serializes broker retirement and compaction against every
// Poll/admission/policy operation and the same assignment's keyed sequence.
func (s *Service) FinalizeTerminal(
	ctx context.Context,
	key AssignmentKey,
	messageID int,
	at time.Time,
) error {
	if key.RepositoryAlias == "" || key.RunnerRequestID <= 0 ||
		messageID <= 0 || at.IsZero() {
		return fmt.Errorf("%w: invalid terminal identity", ErrTerminalFinalize)
	}
	finishCtx, cancel := boundedContext(ctx, s.durableFinishTimeout)
	defer cancel()
	barrier := s.barrierSnapshot()
	if barrier == nil {
		return ErrServiceNotReady
	}
	critical, err := barrier.beginCritical(
		finishCtx,
		key.RepositoryAlias,
		messageID,
	)
	if err != nil {
		return fmt.Errorf("%w: enter epoch: %w", ErrTerminalFinalize, err)
	}
	releaseKey := s.sequencer.Acquire([]AssignmentKey{key})
	finalizeErr := func() error {
		ref, present, err := s.broker.Reference(key)
		if err != nil {
			return fmt.Errorf("%w: inspect broker reference: %w", ErrTerminalFinalize, err)
		}
		if present {
			if ref.Key != key {
				return fmt.Errorf("%w: broker reference identity mismatch", ErrTerminalFinalize)
			}
			switch ref.Phase {
			case AdmissionActive:
				if err := s.broker.Release(key); err != nil {
					return fmt.Errorf("%w: release capacity: %w", ErrTerminalFinalize, err)
				}
			case AdmissionQueued, AdmissionReserved:
			default:
				return fmt.Errorf("%w: invalid broker reference phase", ErrTerminalFinalize)
			}
			if err := s.broker.Retire(key); err != nil {
				return fmt.Errorf("%w: retire broker identity: %w", ErrTerminalFinalize, err)
			}
		}
		if s.broker.HasLiveReference(key) {
			return fmt.Errorf("%w: broker identity remains live", ErrTerminalFinalize)
		}
		if err := s.state.ClearTerminalRuntime(finishCtx, key); err != nil {
			return fmt.Errorf("%w: clear durable terminal runtime: %w", ErrTerminalFinalize, err)
		}
		if err := s.state.ClearAdmission(finishCtx, key); err != nil {
			return fmt.Errorf("%w: clear durable admission: %w", ErrTerminalFinalize, err)
		}
		if err := s.state.BindTerminalMessage(finishCtx, key, messageID); err != nil {
			return fmt.Errorf("%w: bind terminal message: %w", ErrTerminalFinalize, err)
		}
		if err := s.state.CompactTerminal(finishCtx, key, at); err != nil {
			return fmt.Errorf("%w: compact terminal history: %w", ErrTerminalFinalize, err)
		}
		return nil
	}()
	releaseKey()
	if closeErr := critical.Close(); closeErr != nil {
		return errors.Join(
			finalizeErr,
			&fatalOperationError{
				reason: ReasonAcquisitionJoin,
				cause:  fmt.Errorf("%w: close epoch: %w", ErrTerminalFinalize, closeErr),
			},
		)
	}
	return finalizeErr
}

func (s *Service) localEligibility(
	ctx context.Context,
	now time.Time,
	fleet githubscale.Fleet,
	offer githubscale.Offer,
) (bool, HostedReason) {
	if !offer.QueueTime.IsZero() &&
		!offer.QueueTime.After(now) &&
		now.Sub(offer.QueueTime) <= s.replayAge {
		return true, 0
	}
	result, err := s.replay.VerifyCurrentOffer(ctx, fleet, cloneServiceOffer(offer))
	if err != nil || result == ReplayUnknown {
		if offer.QueueTime.IsZero() {
			return false, HostedReasonQueueTimeMissing
		}
		return false, HostedReasonReplayUnknown
	}
	if result == ReplayCurrent {
		return true, 0
	}
	if offer.QueueTime.IsZero() {
		return false, HostedReasonQueueTimeMissing
	}
	if now.Sub(offer.QueueTime) > s.replayAge {
		return false, HostedReasonQueueTimeStale
	}
	return false, HostedReasonReplayNotCurrent
}

func (s *Service) routeHostedLocked(
	ctx context.Context,
	policy AcquisitionPolicy,
	record OfferRecord,
	messageID int,
	reason HostedReason,
) error {
	idempotencyKey := hostedIdempotencyKey(record.Key)
	effect, err := s.state.LookupHostedEffect(ctx, record.Key, idempotencyKey)
	if err != nil {
		return fmt.Errorf("%w: lookup hosted effect: %w", ErrHostedUnavailable, err)
	}
	switch effect.State {
	case HostedEffectCompleted:
		if effect.ResultIdentity == "" || effect.Failure != 0 {
			return fmt.Errorf("%w: completed hosted effect lacks proof", ErrHostedUnavailable)
		}
	case HostedEffectFailed:
		if effect.Failure != HostedFailureRouteRejected ||
			effect.ResultIdentity != "" {
			return fmt.Errorf("%w: invalid failed hosted effect", ErrHostedUnavailable)
		}
		return fmt.Errorf("%w: prior hosted effect failed", ErrHostedUnavailable)
	case HostedEffectAbsent, HostedEffectPending:
		proof, err := s.hosted.Readiness(ctx, record.Key.RepositoryAlias, policy.Epoch)
		if err != nil || !validHostedReadiness(proof, record.Key.RepositoryAlias, policy.Epoch, s.now()) {
			return fmt.Errorf("%w: fresh hosted readiness not proven", ErrHostedUnavailable)
		}
		if _, err := s.state.BeginHostedEffect(ctx, record.Key, idempotencyKey); err != nil {
			return fmt.Errorf("%w: persist hosted intent: %w", ErrHostedUnavailable, err)
		}
		resultIdentity, err := s.hosted.RouteHosted(ctx, record.Key, idempotencyKey, reason)
		if err != nil {
			if failErr := s.state.FailHostedEffect(ctx, idempotencyKey); failErr != nil {
				return errors.Join(
					fmt.Errorf("%w: route hosted: %w", ErrHostedUnavailable, err),
					fmt.Errorf("%w: persist hosted failure: %w", ErrHostedUnavailable, failErr),
				)
			}
			return fmt.Errorf("%w: route hosted: %w", ErrHostedUnavailable, err)
		}
		if resultIdentity == "" {
			proofErr := fmt.Errorf("%w: hosted route returned empty proof", ErrHostedUnavailable)
			if failErr := s.state.FailHostedEffect(ctx, idempotencyKey); failErr != nil {
				return errors.Join(
					proofErr,
					fmt.Errorf("%w: persist hosted failure: %w", ErrHostedUnavailable, failErr),
				)
			}
			return proofErr
		}
		if err := s.state.CompleteHostedEffect(ctx, idempotencyKey, resultIdentity); err != nil {
			return fmt.Errorf("%w: persist hosted ownership: %w", ErrHostedUnavailable, err)
		}
	default:
		return fmt.Errorf("%w: invalid hosted effect state", ErrHostedUnavailable)
	}
	if record.State == StateReceived {
		if err := s.state.Advance(ctx, record.Key, StateDestroyed); err != nil {
			return fmt.Errorf("%w: persist hosted terminal state: %w", ErrHostedUnavailable, err)
		}
	}
	if err := s.state.BindTerminalMessage(ctx, record.Key, messageID); err != nil {
		return fmt.Errorf("%w: bind hosted terminal message: %w", ErrHostedUnavailable, err)
	}
	return nil
}

func validHostedReadiness(
	proof HostedReadinessProof,
	repositoryAlias string,
	policyEpoch uint64,
	now time.Time,
) bool {
	return proof.RepositoryAlias == repositoryAlias &&
		proof.PolicyEpoch == policyEpoch &&
		!proof.ObservedAt.IsZero() &&
		!proof.ObservedAt.After(now) &&
		proof.ExpiresAt.After(now) &&
		proof.AvailableCapacity > 0
}

func validHistoryPressureThresholds(thresholds HistoryPressureThresholds) bool {
	return thresholds.WarningHistoryRows > 0 &&
		thresholds.WarningHistoryRows < thresholds.StopHistoryRows &&
		thresholds.WarningHistoryBytes > 0 &&
		thresholds.WarningHistoryBytes < thresholds.StopHistoryBytes &&
		thresholds.WarningNetworkLedgerRows > 0 &&
		thresholds.WarningNetworkLedgerRows < thresholds.StopNetworkLedgerRows &&
		thresholds.WarningNetworkLedgerBytes > 0 &&
		thresholds.WarningNetworkLedgerBytes < thresholds.StopNetworkLedgerBytes &&
		thresholds.WarningMaxCapacity > 0
}

func addHistoryTotals(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if ^uint64(0)-total < value {
			return ^uint64(0), true
		}
		total += value
	}
	return total, false
}

func pressureLevel(
	thresholds HistoryPressureThresholds,
	historyRows uint64,
	historyBytes uint64,
	usage HistoryUsage,
) health.Pressure {
	if historyRows >= thresholds.StopHistoryRows ||
		historyBytes >= thresholds.StopHistoryBytes ||
		usage.NetworkLedgerRows >= thresholds.StopNetworkLedgerRows ||
		usage.NetworkLedgerLogicalBytes >= thresholds.StopNetworkLedgerBytes {
		return health.PressureStop
	}
	if historyRows >= thresholds.WarningHistoryRows ||
		historyBytes >= thresholds.WarningHistoryBytes ||
		usage.NetworkLedgerRows >= thresholds.WarningNetworkLedgerRows ||
		usage.NetworkLedgerLogicalBytes >= thresholds.WarningNetworkLedgerBytes {
		return health.PressureWarning
	}
	return health.PressureNormal
}

func pressureReasons(
	thresholds HistoryPressureThresholds,
	historyRows uint64,
	historyBytes uint64,
	networkRows uint64,
	networkBytes uint64,
) observability.PressureReason {
	var reasons observability.PressureReason
	if historyRows >= thresholds.WarningHistoryRows {
		reasons |= observability.PressureReasonHistoryRows
	}
	if historyBytes >= thresholds.WarningHistoryBytes {
		reasons |= observability.PressureReasonHistoryBytes
	}
	if networkRows >= thresholds.WarningNetworkLedgerRows {
		reasons |= observability.PressureReasonNetworkLedgerRows
	}
	if networkBytes >= thresholds.WarningNetworkLedgerBytes {
		reasons |= observability.PressureReasonNetworkLedgerBytes
	}
	return reasons
}

func hostedIdempotencyKey(key AssignmentKey) string {
	h := sha256.New()
	_, _ = h.Write([]byte("portable-ghar.hosted-route.v1"))
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(len(key.RepositoryAlias)))
	_, _ = h.Write(scalar[:])
	_, _ = h.Write([]byte(key.RepositoryAlias))
	binary.BigEndian.PutUint64(scalar[:], uint64(key.RunnerRequestID))
	_, _ = h.Write(scalar[:])
	var attempt [4]byte
	binary.BigEndian.PutUint32(attempt[:], key.Attempt)
	_, _ = h.Write(attempt[:])
	return fmt.Sprintf("hosted-route-v1:%x", h.Sum(nil))
}

func opaqueSlotName(key AssignmentKey) string {
	h := sha256.New()
	_, _ = h.Write([]byte("portable-ghar.slot.v1"))
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(len(key.RepositoryAlias)))
	_, _ = h.Write(scalar[:])
	_, _ = h.Write([]byte(key.RepositoryAlias))
	binary.BigEndian.PutUint64(scalar[:], uint64(key.RunnerRequestID))
	_, _ = h.Write(scalar[:])
	var attempt [4]byte
	binary.BigEndian.PutUint32(attempt[:], key.Attempt)
	_, _ = h.Write(attempt[:])
	sum := h.Sum(nil)
	return fmt.Sprintf("pghar-slot-%x", sum[:16])
}

// OpaqueSlotName returns the single canonical slot identity derived from an
// assignment key. Lifecycle builders use the same source of truth rather than
// accepting a caller-selected container label or name.
func OpaqueSlotName(key AssignmentKey) string {
	return opaqueSlotName(key)
}

func (s *Service) clearQueuedProjectionsLocked(
	ctx context.Context,
	local []observedOffer,
) error {
	for _, item := range local {
		if err := s.state.ClearAdmission(ctx, item.record.Key); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) rememberUncertain(record UncertainMessageReceipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uncertain[messageReceiptKey{
		repositoryAlias: record.RepositoryAlias,
		messageID:       record.MessageID,
	}] = record
}

func (s *Service) confirmMessage(repositoryAlias string, messageID int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.uncertain, messageReceiptKey{
		repositoryAlias: repositoryAlias,
		messageID:       messageID,
	})
	s.lastID[repositoryAlias] = messageID
}

func (s *Service) lastMessageIDLocked(repositoryAlias string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastID[repositoryAlias]
}

func (s *Service) LastMessageID(repositoryAlias string) int {
	return s.lastMessageIDLocked(repositoryAlias)
}

func (s *Service) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

func (s *Service) Policy() AcquisitionPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneAcquisitionPolicy(s.policy)
}

func (s *Service) UncertainAckCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.uncertain)
}

func (s *Service) setPolicy(policy AcquisitionPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = cloneAcquisitionPolicy(policy)
}

func (s *Service) markNotReady() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = false
}

func (s *Service) barrierSnapshot() *acquisitionBarrier {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.barrier
}

func (s *Service) policySnapshot() (AcquisitionPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneAcquisitionPolicy(s.policy), s.ready
}

func validatePersistedAcquisitionTransition(
	expectedEpoch uint64,
	request AcquisitionPolicy,
	persisted AcquisitionPolicy,
) (AcquisitionPolicy, error) {
	if expectedEpoch == math.MaxUint64 {
		return AcquisitionPolicy{}, ErrAcquisitionEpochMismatch
	}
	canonicalRequest, err := CanonicalizeAcquisitionPolicy(request)
	if err != nil {
		return AcquisitionPolicy{}, err
	}
	canonicalPersisted, err := CanonicalizeAcquisitionPolicy(persisted)
	if err != nil {
		return AcquisitionPolicy{}, err
	}
	if canonicalPersisted.Epoch != expectedEpoch+1 {
		return AcquisitionPolicy{}, ErrAcquisitionEpochMismatch
	}
	requestDigest, err := AcquisitionPolicyDigest(canonicalRequest)
	if err != nil {
		return AcquisitionPolicy{}, err
	}
	persistedDigest, err := AcquisitionPolicyDigest(canonicalPersisted)
	if err != nil {
		return AcquisitionPolicy{}, err
	}
	if requestDigest != persistedDigest {
		return AcquisitionPolicy{}, ErrAcquisitionEpochMismatch
	}
	return canonicalPersisted, nil
}

func equalAcquisitionPolicy(left, right AcquisitionPolicy) bool {
	leftCanonical, leftErr := CanonicalizeAcquisitionPolicy(left)
	rightCanonical, rightErr := CanonicalizeAcquisitionPolicy(right)
	if leftErr != nil || rightErr != nil ||
		leftCanonical.Epoch != rightCanonical.Epoch {
		return false
	}
	leftDigest, leftErr := AcquisitionPolicyDigest(leftCanonical)
	rightDigest, rightErr := AcquisitionPolicyDigest(rightCanonical)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func requiresAcquisitionQuiescence(policy AcquisitionPolicy) bool {
	return policy.Mode == AcquisitionDisabled || policy.Mode == AcquisitionFatal
}

func boundedContext(
	parent context.Context,
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

func cloneAcquisitionPolicy(policy AcquisitionPolicy) AcquisitionPolicy {
	policy.EligibleScaleSets = append([]string(nil), policy.EligibleScaleSets...)
	policy.RepositoryPolicies = append(
		[]RepositoryPolicySummary(nil),
		policy.RepositoryPolicies...,
	)
	return policy
}

func validateRecoveryProjection(
	assignments []RecoverableAssignment,
) ([]AdmissionReference, error) {
	refs := make([]AdmissionReference, 0, len(assignments))
	seen := make(map[AssignmentKey]struct{}, len(assignments))
	for _, assignment := range assignments {
		if assignment.Key.RepositoryAlias == "" ||
			assignment.Key.RunnerRequestID <= 0 ||
			assignment.Key.Attempt != 0 ||
			assignment.Admission.Key != assignment.Key ||
			assignment.Offer.RunnerRequestID != assignment.Key.RunnerRequestID {
			return nil, fmt.Errorf("controller: inconsistent recoverable identity")
		}
		if _, duplicate := seen[assignment.Key]; duplicate {
			return nil, fmt.Errorf("controller: duplicate recoverable identity")
		}
		seen[assignment.Key] = struct{}{}
		if _, ok := stateIndex[assignment.State]; !ok || assignment.State == StateDestroyed {
			return nil, fmt.Errorf("controller: invalid recoverable state")
		}

		ref := assignment.Admission
		switch ref.Phase {
		case AdmissionQueued:
			if assignment.State != StateReceived ||
				ref.SlotID != 0 ||
				ref.FullCharge != (ResourceProjection{}) ||
				ref.LedgerCharge != (ResourceProjection{}) ||
				!ref.LedgerCreatedAt.IsZero() ||
				ref.LedgerEverUsed ||
				assignment.Slot != (RunnerSlot{}) {
				return nil, fmt.Errorf("controller: inconsistent queued recovery projection")
			}
		case AdmissionReserved:
			if assignment.State != StateReceived ||
				ref.SlotID == 0 ||
				ref.LedgerCreatedAt.IsZero() ||
				assignment.Slot != (RunnerSlot{}) {
				return nil, fmt.Errorf("controller: inconsistent reserved recovery projection")
			}
		case AdmissionActive:
			if stateIndex[assignment.State] < stateIndex[StateCapacityReserved] ||
				ref.SlotID == 0 ||
				ref.LedgerCreatedAt.IsZero() ||
				!ref.LedgerEverUsed ||
				assignment.Slot.CapacitySlotID != ref.SlotID ||
				assignment.Slot.OpaqueName == "" {
				return nil, fmt.Errorf("controller: inconsistent active recovery projection")
			}
		default:
			return nil, fmt.Errorf("controller: missing or invalid recovery projection")
		}
		if !validControllerResources(ref.FullCharge) ||
			!validControllerResources(ref.LedgerCharge) ||
			!controllerResourcesContain(ref.FullCharge, ref.LedgerCharge) {
			return nil, fmt.Errorf("controller: invalid recovery resource projection")
		}
		ref.Offer = cloneServiceOffer(assignment.Offer)
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Key.RepositoryAlias != refs[j].Key.RepositoryAlias {
			return refs[i].Key.RepositoryAlias < refs[j].Key.RepositoryAlias
		}
		if refs[i].Key.RunnerRequestID != refs[j].Key.RunnerRequestID {
			return refs[i].Key.RunnerRequestID < refs[j].Key.RunnerRequestID
		}
		return refs[i].Key.Attempt < refs[j].Key.Attempt
	})
	return refs, nil
}

func validateUncertainReceipts(
	records []UncertainMessageReceipt,
) (map[messageReceiptKey]UncertainMessageReceipt, error) {
	out := make(map[messageReceiptKey]UncertainMessageReceipt, len(records))
	for _, record := range records {
		if record.RepositoryAlias == "" || record.MessageID <= 0 || record.StartedAt.IsZero() {
			return nil, fmt.Errorf("controller: invalid uncertain acknowledgement")
		}
		key := messageReceiptKey{
			repositoryAlias: record.RepositoryAlias,
			messageID:       record.MessageID,
		}
		if _, duplicate := out[key]; duplicate {
			return nil, fmt.Errorf("controller: duplicate uncertain acknowledgement")
		}
		out[key] = record
	}
	return out, nil
}

func validControllerResources(value ResourceProjection) bool {
	return value.MilliCPU >= 0 &&
		value.MemoryBytes >= 0 &&
		value.PIDs >= 0 &&
		value.FileDescriptors >= 0 &&
		value.TmpfsBytes >= 0 &&
		value.ScratchBytes >= 0 &&
		value.SocketStateBytes >= 0 &&
		value.DurableStateBytes >= 0 &&
		value.Inodes >= 0
}

func controllerResourcesContain(full, part ResourceProjection) bool {
	return part.MilliCPU <= full.MilliCPU &&
		part.MemoryBytes <= full.MemoryBytes &&
		part.PIDs <= full.PIDs &&
		part.FileDescriptors <= full.FileDescriptors &&
		part.TmpfsBytes <= full.TmpfsBytes &&
		part.ScratchBytes <= full.ScratchBytes &&
		part.SocketStateBytes <= full.SocketStateBytes &&
		part.DurableStateBytes <= full.DurableStateBytes &&
		part.Inodes <= full.Inodes
}

func cloneServiceOffer(offer githubscale.Offer) githubscale.Offer {
	offer.RequestLabels = append([]string(nil), offer.RequestLabels...)
	return offer
}

type keySequencerEntry struct {
	mu   sync.Mutex
	refs int
}

type keySequencer struct {
	mu      sync.Mutex
	entries map[AssignmentKey]*keySequencerEntry
}

func newKeySequencer() *keySequencer {
	return &keySequencer{entries: make(map[AssignmentKey]*keySequencerEntry)}
}

// Acquire locks the sorted unique key set and returns an idempotent release
// function. Map entries are reference-counted waiters plus holders, never
// durable seen identities.
func (s *keySequencer) Acquire(keys []AssignmentKey) func() {
	ordered := append([]AssignmentKey(nil), keys...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].RepositoryAlias != ordered[j].RepositoryAlias {
			return ordered[i].RepositoryAlias < ordered[j].RepositoryAlias
		}
		if ordered[i].RunnerRequestID != ordered[j].RunnerRequestID {
			return ordered[i].RunnerRequestID < ordered[j].RunnerRequestID
		}
		return ordered[i].Attempt < ordered[j].Attempt
	})
	unique := ordered[:0]
	for _, key := range ordered {
		if len(unique) == 0 || unique[len(unique)-1] != key {
			unique = append(unique, key)
		}
	}
	entries := make([]*keySequencerEntry, len(unique))
	s.mu.Lock()
	for i, key := range unique {
		entry := s.entries[key]
		if entry == nil {
			entry = &keySequencerEntry{}
			s.entries[key] = entry
		}
		entry.refs++
		entries[i] = entry
	}
	s.mu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			for i := len(entries) - 1; i >= 0; i-- {
				entries[i].mu.Unlock()
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			for i, key := range unique {
				entry := entries[i]
				entry.refs--
				if entry.refs == 0 {
					delete(s.entries, key)
				}
			}
		})
	}
}

func (s *keySequencer) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
