package controller

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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
	MaxCapacity     int
	ExpiresAt       time.Time
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
	PersistAdmission(context.Context, AssignmentKey, AdmissionReference) error
	ReserveActive(context.Context, AssignmentKey, AdmissionReference, string) error
	ClearAdmission(context.Context, AssignmentKey) error
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
	CompactTerminal(context.Context, AssignmentKey, time.Time) error
	HistoryUsage(context.Context) (HistoryUsage, error)
}

// AdmissionBroker is the controller-owned broker port. Its adapter rewrites
// only the broker's repository-routing field on copies; message-intrinsic and
// durable offer projections remain unchanged.
type AdmissionBroker interface {
	CheckOffer(string, githubscale.Offer) error
	LeasePoll(string, time.Time) (PollLease, error)
	EnsureQueuedBatch(string, []githubscale.Offer) ([]AdmissionReference, error)
	Restore([]AdmissionReference) error
	Admit(time.Time) ([]AdmissionDecision, error)
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

// AcquisitionTransitioner is the single persisted epoch barrier used by
// startup, pressure, suspension, and fatal/zero transitions.
type AcquisitionTransitioner interface {
	Current(context.Context) (AcquisitionPolicy, error)
	Transition(context.Context, uint64, AcquisitionPolicy) (AcquisitionPolicy, error)
}

// FatalTerminator is invoked only after the service has persisted a zero or
// fatal acquisition state. Production implementations terminate the process;
// tests record the closed reason.
type FatalTerminator interface {
	TerminateAfterPersist(ReasonCode)
}

type ServiceConfig struct {
	State                DurableState
	Broker               AdmissionBroker
	Transitions          AcquisitionTransitioner
	Terminator           FatalTerminator
	Events               BatchEventRecorder
	Replay               ReplayVerifier
	Hosted               HostedRouter
	HistoryPressure      HistoryPressureThresholds
	HealthPublisher      HealthPublisher
	EventSink            EventSink
	Now                  func() time.Time
	AckTimeout           time.Duration
	ReplayEvidenceMaxAge time.Duration
}

type messageReceiptKey struct {
	repositoryAlias string
	messageID       int
}

type observedOffer struct {
	offer  githubscale.Offer
	record OfferRecord
}

// Service owns the one global service-cycle latch. The smaller state mutex
// protects read-only snapshots without allowing any mutation to bypass that
// latch.
type Service struct {
	cycle sync.Mutex
	mu    sync.RWMutex

	state       DurableState
	broker      AdmissionBroker
	transitions AcquisitionTransitioner
	terminator  FatalTerminator
	events      BatchEventRecorder
	replay      ReplayVerifier
	hosted      HostedRouter
	pressure    HistoryPressureThresholds
	health      HealthPublisher
	eventSink   EventSink
	now         func() time.Time
	ackTimeout  time.Duration
	replayAge   time.Duration
	sequencer   *keySequencer

	started   bool
	ready     bool
	policy    AcquisitionPolicy
	uncertain map[messageReceiptKey]UncertainMessageReceipt
	lastID    map[string]int
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.State == nil ||
		config.Broker == nil ||
		config.Transitions == nil ||
		config.Terminator == nil ||
		config.Events == nil ||
		config.Replay == nil ||
		config.Hosted == nil ||
		config.HealthPublisher == nil ||
		config.EventSink == nil ||
		config.Now == nil ||
		config.AckTimeout <= 0 ||
		config.ReplayEvidenceMaxAge <= 0 ||
		!validHistoryPressureThresholds(config.HistoryPressure) {
		return nil, fmt.Errorf("%w: incomplete service dependencies", ErrServiceNotReady)
	}
	return &Service{
		state:       config.State,
		broker:      config.Broker,
		transitions: config.Transitions,
		terminator:  config.Terminator,
		events:      config.Events,
		replay:      config.Replay,
		hosted:      config.Hosted,
		pressure:    config.HistoryPressure,
		health:      config.HealthPublisher,
		eventSink:   config.EventSink,
		now:         config.Now,
		ackTimeout:  config.AckTimeout,
		replayAge:   config.ReplayEvidenceMaxAge,
		sequencer:   newKeySequencer(),
		uncertain:   make(map[messageReceiptKey]UncertainMessageReceipt),
		lastID:      make(map[string]int),
	}, nil
}

// Start persists acquisition zero, reconstructs the complete live broker, and
// only then restores the desired policy through a second epoch.
func (s *Service) Start(ctx context.Context) error {
	s.cycle.Lock()
	defer s.cycle.Unlock()

	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ErrServiceStarted
	}
	s.ready = false
	s.mu.Unlock()

	desired, err := s.transitions.Current(ctx)
	if err != nil {
		return fmt.Errorf("%w: read acquisition policy: %w", ErrStartupRestore, err)
	}
	desired = cloneAcquisitionPolicy(desired)
	zeroRequest := cloneAcquisitionPolicy(desired)
	zeroRequest.Mode = AcquisitionDisabled
	zeroRequest.MaxCapacity = 0
	zeroRequest.EligibleScaleSets = nil
	zeroed, err := s.transitions.Transition(ctx, desired.Epoch, zeroRequest)
	if err != nil {
		return fmt.Errorf("%w: persist startup zero: %w", ErrStartupRestore, err)
	}
	s.mu.Lock()
	s.started = true
	s.policy = cloneAcquisitionPolicy(zeroed)
	s.mu.Unlock()

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

	restoredRequest := cloneAcquisitionPolicy(desired)
	restoredRequest.Epoch = zeroed.Epoch
	restored, err := s.transitions.Transition(ctx, zeroed.Epoch, restoredRequest)
	if err != nil {
		return s.failStartupLocked(ctx, zeroed, ReasonRestoreTransition, err)
	}

	s.mu.Lock()
	s.policy = cloneAcquisitionPolicy(restored)
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
	fatal, transitionErr := s.transitions.Transition(ctx, current.Epoch, fatalRequest)
	if transitionErr == nil {
		s.setPolicy(fatal)
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

// ApplyPressure may only reduce effective capacity. It queues behind startup
// and persists the new epoch before changing broker scheduling capacity.
func (s *Service) ApplyPressure(ctx context.Context, maxCapacity int) error {
	s.cycle.Lock()
	defer s.cycle.Unlock()

	return s.applyPressureLocked(ctx, maxCapacity)
}

func (s *Service) applyPressureLocked(ctx context.Context, maxCapacity int) error {
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
	persisted, err := s.transitions.Transition(ctx, current.Epoch, next)
	if err != nil {
		return fmt.Errorf("%w: persist epoch: %w", ErrPressureTransition, err)
	}
	s.setPolicy(persisted)
	if _, _, err := s.broker.SetPressure(maxCapacity); err != nil {
		fatalRequest := cloneAcquisitionPolicy(persisted)
		fatalRequest.Mode = AcquisitionFatal
		fatalRequest.MaxCapacity = 0
		fatalRequest.EligibleScaleSets = nil
		fatal, fatalErr := s.transitions.Transition(ctx, persisted.Epoch, fatalRequest)
		if fatalErr == nil {
			s.setPolicy(fatal)
		}
		s.mu.Lock()
		s.ready = false
		s.mu.Unlock()
		if fatalErr == nil {
			s.terminator.TerminateAfterPersist(ReasonPressureBroker)
		}
		if fatalErr != nil {
			return errors.Join(
				fmt.Errorf("%w: broker pressure: %w", ErrPressureTransition, err),
				fmt.Errorf("controller: persist fatal pressure state: %w", fatalErr),
			)
		}
		return fmt.Errorf("%w: broker pressure: %w", ErrPressureTransition, err)
	}
	return nil
}

// EvaluateHistoryPressure accounts for the complete assignment-history graph,
// its in-flight reservation, and the independent network-ledger budget under
// the global service-cycle latch. It can only retain or reduce effective
// capacity; recovery requires a separate explicit policy transition.
func (s *Service) EvaluateHistoryPressure(ctx context.Context) (health.Snapshot, error) {
	s.cycle.Lock()
	defer s.cycle.Unlock()

	current, ready := s.policySnapshot()
	if !ready {
		return health.Snapshot{}, ErrServiceNotReady
	}
	usage, err := s.state.HistoryUsage(ctx)
	if err != nil {
		// Failure to measure a required budget cannot authorize another
		// acquisition. Persist zero through the same epoch barrier before
		// returning the typed measurement failure.
		pressureErr := s.applyPressureLocked(ctx, 0)
		if pressureErr != nil {
			return health.Snapshot{}, errors.Join(
				fmt.Errorf("%w: read aggregate usage: %w", ErrHistoryPressure, err),
				pressureErr,
			)
		}
		return health.Snapshot{}, fmt.Errorf(
			"%w: read aggregate usage: %w",
			ErrHistoryPressure,
			err,
		)
	}

	historyRows, rowsOverflow := addHistoryTotals(
		usage.LiveRows,
		usage.ProtectedTerminalRows,
		usage.MessageReceiptRows,
		usage.TombstoneRows,
		usage.ReservedRows,
	)
	historyBytes, bytesOverflow := addHistoryTotals(
		usage.LiveLogicalBytes,
		usage.ProtectedTerminalBytes,
		usage.MessageReceiptBytes,
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
		return health.Snapshot{}, ErrHistoryPressure
	}
	if targetCapacity < current.MaxCapacity {
		if err := s.applyPressureLocked(ctx, targetCapacity); err != nil {
			return health.Snapshot{}, fmt.Errorf(
				"%w: lower capacity: %w",
				ErrHistoryPressure,
				err,
			)
		}
	}
	persisted, ready := s.policySnapshot()
	if !ready || persisted.MaxCapacity < 0 {
		return health.Snapshot{}, ErrHistoryPressure
	}
	observedAt := s.now()
	oldestAge := time.Duration(0)
	if !usage.OldestRetainedAt.IsZero() {
		if usage.OldestRetainedAt.After(observedAt) {
			return health.Snapshot{}, fmt.Errorf(
				"%w: retained history timestamp is in the future",
				ErrHistoryPressure,
			)
		}
		oldestAge = observedAt.Sub(usage.OldestRetainedAt)
	}
	snapshot := health.Snapshot{
		ObservedAt:                observedAt,
		Readiness:                 health.ReadinessReady,
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
		return health.Snapshot{}, fmt.Errorf("%w: validate snapshot: %w", ErrHistoryPressure, err)
	}
	event := observability.Event{
		Kind:     observability.EventHistoryPressureEvaluated,
		Reasons:  reasons,
		Snapshot: snapshot,
	}
	if err := event.Validate(); err != nil {
		return health.Snapshot{}, fmt.Errorf("%w: validate event: %w", ErrHistoryPressure, err)
	}
	if err := s.health.Publish(ctx, snapshot); err != nil {
		return health.Snapshot{}, fmt.Errorf("%w: publish health: %w", ErrHistoryPressure, err)
	}
	if err := s.eventSink.Emit(ctx, event); err != nil {
		return health.Snapshot{}, fmt.Errorf("%w: emit event: %w", ErrHistoryPressure, err)
	}
	return snapshot, nil
}

// PollOnce holds the global service-cycle latch through the Ack network call
// and immediate local confirmation. Consequently a concurrent stop/fatal
// transition is delayed by at most the explicit Ack timeout, never an
// unbounded provider call.
func (s *Service) PollOnce(
	ctx context.Context,
	fleet githubscale.Fleet,
	session githubscale.Session,
) error {
	s.cycle.Lock()
	defer s.cycle.Unlock()

	policy, ready := s.policySnapshot()
	if !ready {
		return ErrServiceNotReady
	}
	if session == nil ||
		fleet.RepositoryAlias == "" ||
		fleet.ScaleSetName == "" {
		return fmt.Errorf("%w: invalid poll boundary", ErrPollCycle)
	}
	now := s.now()
	lease, err := s.broker.LeasePoll(fleet.RepositoryAlias, now)
	if err != nil {
		return fmt.Errorf("%w: lease: %w", ErrPollCycle, err)
	}
	if lease.RepositoryAlias != fleet.RepositoryAlias ||
		lease.Epoch != policy.RepositoryPolicyRevision ||
		lease.MaxCapacity < 0 ||
		lease.MaxCapacity > policy.MaxCapacity ||
		lease.ExpiresAt.IsZero() ||
		!lease.ExpiresAt.After(now) {
		return fmt.Errorf("%w: invalid poll lease", ErrPollCycle)
	}
	if lease.MaxCapacity == 0 {
		return nil
	}

	lastMessageID := s.lastMessageIDLocked(fleet.RepositoryAlias)
	batch, err := session.Poll(ctx, lastMessageID, lease.MaxCapacity)
	if err != nil {
		return fmt.Errorf("%w: upstream poll: %w", ErrPollCycle, err)
	}
	if batch.Empty {
		return nil
	}
	if batch.MessageID <= 0 {
		return fmt.Errorf("%w: nonempty batch has invalid message identity", ErrPollCycle)
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
			queued := AdmissionReference{
				Key:   item.record.Key,
				Offer: cloneServiceOffer(item.offer),
				Phase: AdmissionQueued,
			}
			if err := s.state.PersistAdmission(ctx, item.record.Key, queued); err != nil {
				return fmt.Errorf("%w: persist queued projection: %w", ErrPollCycle, err)
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

	if len(local) != 0 {
		offers := make([]githubscale.Offer, len(local))
		localByKey := make(map[AssignmentKey]struct{}, len(local))
		for i, item := range local {
			offers[i] = cloneServiceOffer(item.offer)
			localByKey[item.record.Key] = struct{}{}
		}
		projections, err := s.broker.EnsureQueuedBatch(fleet.RepositoryAlias, offers)
		if err != nil {
			if errors.Is(err, ErrAdmissionHeadroom) {
				if clearErr := s.clearQueuedProjectionsLocked(ctx, local); clearErr != nil {
					return s.failOperationalLocked(
						ctx,
						ReasonProjectionPersist,
						fmt.Errorf("clear queued projections after broker refusal: %w", clearErr),
					)
				}
				return err
			}
			return s.failOperationalLocked(
				ctx,
				ReasonProjectionPersist,
				fmt.Errorf("broker queued batch outcome uncertain: %w", err),
			)
		}
		if len(projections) != len(localByKey) {
			return s.failOperationalLocked(
				ctx,
				ReasonProjectionPersist,
				fmt.Errorf("broker returned incomplete projection set"),
			)
		}
		for _, projection := range projections {
			if _, expected := localByKey[projection.Key]; !expected ||
				(projection.Phase != AdmissionQueued && projection.Phase != AdmissionReserved) {
				return s.failOperationalLocked(
					ctx,
					ReasonProjectionPersist,
					fmt.Errorf("broker returned invalid projection"),
				)
			}
			delete(localByKey, projection.Key)
			if err := s.state.PersistAdmission(ctx, projection.Key, projection); err != nil {
				return s.failOperationalLocked(ctx, ReasonProjectionPersist, err)
			}
		}
		if len(localByKey) != 0 {
			return s.failOperationalLocked(
				ctx,
				ReasonProjectionPersist,
				fmt.Errorf("broker omitted projection identity"),
			)
		}
	}

	switch receipt.State {
	case MessageAckPersisted, MessageAckRedeliveryProven:
	case MessageAckStarted, MessageAckConfirmed:
		if err := s.state.ObserveRedelivery(
			ctx,
			fleet.RepositoryAlias,
			batch.MessageID,
			receipt.Digest,
			now,
		); err != nil {
			return fmt.Errorf("%w: prove exact redelivery: %w", ErrAckUncertain, err)
		}
	default:
		return fmt.Errorf("%w: invalid durable receipt state", ErrAckUncertain)
	}
	if err := s.state.BeginAck(ctx, fleet.RepositoryAlias, batch.MessageID, now); err != nil {
		return fmt.Errorf("%w: begin durable acknowledgement: %w", ErrAckUncertain, err)
	}
	s.rememberUncertain(UncertainMessageReceipt{
		RepositoryAlias: fleet.RepositoryAlias,
		MessageID:       batch.MessageID,
		Digest:          receipt.Digest,
		StartedAt:       now,
	})
	ackCtx, cancel := context.WithTimeout(ctx, s.ackTimeout)
	defer cancel()
	if err := session.Ack(ackCtx, batch.MessageID); err != nil {
		return fmt.Errorf("%w: upstream acknowledgement: %w", ErrAckUncertain, err)
	}
	confirmedAt := s.now()
	if err := s.state.ConfirmAck(
		ctx,
		fleet.RepositoryAlias,
		batch.MessageID,
		confirmedAt,
	); err != nil {
		return fmt.Errorf("%w: persist acknowledgement confirmation: %w", ErrAckUncertain, err)
	}
	s.confirmMessage(fleet.RepositoryAlias, batch.MessageID)
	return nil
}

// AdmitOnce consumes the broker's already-mutated decisions and immediately
// commits each exact active projection, stable slot identity, and
// RECEIVED-to-CAPACITY_RESERVED transition in one durable transaction.
func (s *Service) AdmitOnce(ctx context.Context) ([]AdmissionDecision, error) {
	s.cycle.Lock()
	defer s.cycle.Unlock()

	if _, ready := s.policySnapshot(); !ready {
		return nil, ErrServiceNotReady
	}
	decisions, err := s.broker.Admit(s.now())
	if err != nil {
		return nil, s.failOperationalLocked(
			ctx,
			ReasonActivePersist,
			fmt.Errorf("broker admit may be partially applied: %w", err),
		)
	}
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
			return nil, s.failOperationalLocked(
				ctx,
				ReasonActivePersist,
				fmt.Errorf("broker returned invalid active projection"),
			)
		}
		seen[decision.Key] = struct{}{}
		if err := s.state.ReserveActive(
			ctx,
			decision.Key,
			projection,
			opaqueSlotName(decision.Key),
		); err != nil {
			return nil, s.failOperationalLocked(ctx, ReasonActivePersist, err)
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
	s.cycle.Lock()
	defer s.cycle.Unlock()
	releaseKey := s.sequencer.Acquire([]AssignmentKey{key})
	defer releaseKey()

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
	if err := s.state.ClearAdmission(ctx, key); err != nil {
		return fmt.Errorf("%w: clear durable admission: %w", ErrTerminalFinalize, err)
	}
	if err := s.state.BindTerminalMessage(ctx, key, messageID); err != nil {
		return fmt.Errorf("%w: bind terminal message: %w", ErrTerminalFinalize, err)
	}
	if err := s.state.CompactTerminal(ctx, key, at); err != nil {
		return fmt.Errorf("%w: compact terminal history: %w", ErrTerminalFinalize, err)
	}
	return nil
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

func (s *Service) failOperationalLocked(
	ctx context.Context,
	reason ReasonCode,
	cause error,
) error {
	current, _ := s.policySnapshot()
	fatalRequest := cloneAcquisitionPolicy(current)
	fatalRequest.Mode = AcquisitionFatal
	fatalRequest.MaxCapacity = 0
	fatalRequest.EligibleScaleSets = nil
	fatal, err := s.transitions.Transition(ctx, current.Epoch, fatalRequest)
	s.mu.Lock()
	s.ready = false
	if err == nil {
		s.policy = cloneAcquisitionPolicy(fatal)
	}
	s.mu.Unlock()
	if err != nil {
		return errors.Join(
			fmt.Errorf("%w: %w", ErrPollFatal, cause),
			fmt.Errorf("controller: persist fatal poll state: %w", err),
		)
	}
	s.terminator.TerminateAfterPersist(reason)
	return fmt.Errorf("%w: %w", ErrPollFatal, cause)
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

func (s *Service) policySnapshot() (AcquisitionPolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneAcquisitionPolicy(s.policy), s.ready
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
