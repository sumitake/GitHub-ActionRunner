// Package state implements the controller's crash-safe assignment store: a
// single-writer SQLite database that journals external-effect intent
// before the effect runs, so a controller restart can reconcile every
// in-flight assignment idempotently from its last durable checkpoint.
//
// Scope for Task 2 is the store itself: schema, the Store interface, and
// the SQLite implementation. It does not implement the reconciler, the
// admission broker, or the acquisition-transition guards that later tasks
// build on top of Store -- see internal/controller's package doc for the
// matching scope note on the domain types.
package state

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

// OfferIdentity is the store-owned, secret-free canonical offer projection.
// It deliberately mirrors only fields required for replay identity, bounded
// logical-byte accounting, and admission restoration; it never carries JIT,
// token, workflow-document, or diagnostic payload bytes.
type OfferIdentity struct {
	RepositoryAlias    string
	RunnerRequestID    int64
	WorkflowJobID      int64
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
	AcquireJobURL      string
}

// IdentityColumn designates which long-lived RunnerSlot identity column a
// completed effect's result should be written into. IdentityNone means the
// effect produced no identity to persist (for example, egress
// verification produces only a pass/fail reason code).
type IdentityColumn int

const (
	IdentityNone IdentityColumn = iota
	IdentityAdapterContainer
	IdentityBrokerContainer
	IdentityRunnerContainer
	IdentityPolicySocketDigest
)

// EffectResult is what CompleteEffect records for a previously begun
// effect. ResultIdentity holds only an opaque name, ID, or digest -- never
// a redaction.Secret, raw token, JIT payload, or secret reference (see the
// package-level reject-secret-columns rule enforced by
// TestStoreAPISurfaceRejectsSecretTypes in sqlite_test.go). ReasonCode is
// non-empty exactly when the effect failed.
type EffectResult struct {
	ResultIdentity string
	Column         IdentityColumn
	ReasonCode     string
}

const (
	// LifecycleEffectListenerRelease is the durable external-effect boundary
	// after which blind cleanup is forbidden.
	LifecycleEffectListenerRelease = "runner-listener-release"

	// LifecycleEffectPostReleaseResolution records the closed reconciliation
	// evidence digest used to resolve an ambiguous listener release.
	LifecycleEffectPostReleaseResolution = "post-release-resolution"
)

// RunnerObservation is the exact, secret-free upstream tuple established by
// a Started or Completed scale-set event.
type RunnerObservation struct {
	UpstreamRunnerID  int64
	BoundRequestID    int64
	RunnerContainerID string
	Finished          bool
	ObservedAt        time.Time
}

// RecoverableAssignment is one row ListRecoverable returns: an assignment
// not yet DESTROYED, with every identity persisted for it so far, so a
// restarted controller can reconcile it from whatever checkpoint it last
// reached -- including an orphaned held broker with no further progress.
type RecoverableAssignment struct {
	Key             controller.AssignmentKey
	State           controller.State
	Offer           OfferIdentity
	Admission       AdmissionProjection
	Released        bool
	Ambiguous       bool
	AmbiguousReason string
	Slot            controller.RunnerSlot
	UpdatedAt       time.Time
}

// Store is the controller's crash-safe assignment persistence boundary.
// Every method's parameters and return types are opaque names, IDs,
// digests, reason codes, timestamps, or the domain value types in package
// controller -- never a redaction.Secret, raw token, JIT payload, or
// secret reference. That is a structural, compile-time property of this
// interface, not a runtime check: see TestStoreAPISurfaceRejectsSecretTypes
// in sqlite_test.go for the automated proof.
type Store interface {
	// RecordMessageReceipt persists a V2 digest over the complete
	// message-intrinsic controller envelope before any batch side effect.
	RecordMessageReceipt(ctx context.Context, envelope controller.MessageEnvelope, persistedAt time.Time) (MessageReceipt, error)

	// RecordOffer is the authoritative replay/identity boundary. It inserts a
	// new, evidence-backed offer only when configured history reserve is
	// available; an equal active or terminal replay is classified without a
	// second row, while a same-key/different-digest replay fails closed.
	RecordOffer(ctx context.Context, offer OfferIdentity, evidence OfferEvidence) (OfferReceipt, error)

	// PersistAdmissionProjection writes the exact queued/reserved/active
	// projection returned by the broker before Ack or any acquisition effect.
	PersistAdmissionProjection(ctx context.Context, key controller.AssignmentKey, projection AdmissionProjection) error

	// BeginMessageAck durably records ack_started before the network call.
	// ErrAckConfirmed means no network call is authorized because this exact
	// delivery was already confirmed; only exact redelivery may reopen it.
	BeginMessageAck(ctx context.Context, repositoryAlias string, messageID int, startedAt time.Time) error

	// ConfirmMessageAck records success only after the upstream Ack returns.
	ConfirmMessageAck(ctx context.Context, repositoryAlias string, messageID int, confirmedAt time.Time) error

	// ObserveMessageRedelivery proves that an ack_started delivery is
	// outstanding again and may be retried only when its exact digest matches.
	ObserveMessageRedelivery(ctx context.Context, repositoryAlias string, messageID int, payloadDigest [sha256.Size]byte, observedAt time.Time) error

	// ListUncertainAcks returns every protected ack_started receipt so startup
	// can account for it without cursor or absence inference.
	ListUncertainAcks(ctx context.Context) ([]UncertainMessageReceipt, error)

	// LookupEffect returns the exact bounded state for one
	// assignment/idempotency-key/kind tuple. A key already owned by a different
	// tuple fails closed with ErrIdentityConflict.
	LookupEffect(ctx context.Context, key controller.AssignmentKey, idempotencyKey, kind string) (EffectRecord, error)

	// ReserveActive atomically persists an exact active broker projection,
	// stable reservation/runner-slot identity, and RECEIVED ->
	// CAPACITY_RESERVED transition.
	ReserveActive(ctx context.Context, key controller.AssignmentKey, projection AdmissionProjection, opaqueName string) error

	// ClearAdmissionProjection removes a queued projection after a normal
	// all-or-nothing broker refusal or after terminal broker retirement.
	ClearAdmissionProjection(ctx context.Context, key controller.AssignmentKey) error

	// BindTerminalMessage durably binds a DESTROYED assignment to an existing
	// message receipt. The first binding is immutable.
	BindTerminalMessage(ctx context.Context, key controller.AssignmentKey, messageID int) error

	// CompactTerminal atomically inserts a digest-bound tombstone, detaches
	// independently retained network ledgers, and deletes the full assignment
	// graph only after every durable terminal/Ack/cleanup precondition holds.
	CompactTerminal(ctx context.Context, key controller.AssignmentKey, limits HistoryLimits, now time.Time) error

	// HistoryUsage and CollectHistory expose aggregate bounded-state accounting.
	// Collection behavior is implemented by the later maintenance slice.
	HistoryUsage(ctx context.Context, limits HistoryLimits) (HistoryUsage, error)
	CollectHistory(ctx context.Context, limits HistoryLimits, now time.Time) (HistoryUsage, error)

	// Reserve performs the RECEIVED -> CAPACITY_RESERVED transition inside
	// a single BEGIN IMMEDIATE transaction: it takes the write-intent lock,
	// creates the runner slot's stable identity (opaqueName,
	// capacitySlotID), and advances the assignment's persisted state, or
	// fails atomically with no partial write surviving (for example, if
	// capacitySlotID or opaqueName collides with another assignment's
	// slot).
	Reserve(ctx context.Context, key controller.AssignmentKey, opaqueName string, capacitySlotID uint32) error

	// BeginEffect records intent to perform an external effect (kind, an
	// opaque short label) for key, under idempotencyKey. It returns
	// began=true the first time idempotencyKey is recorded, and
	// began=false (with no error and no additional row) on every replay of
	// the same idempotencyKey -- the caller uses began to decide whether to
	// actually (re)perform the external effect.
	BeginEffect(ctx context.Context, key controller.AssignmentKey, idempotencyKey, kind string) (began bool, err error)

	// CompleteEffect durably records the result of the effect previously
	// begun under idempotencyKey: the reason code on failure, or the
	// opaque result identity on success, copied into the RunnerSlot column
	// named by result.Column. CompleteEffect is idempotent: replaying the
	// same idempotencyKey with the same result is a no-op success.
	CompleteEffect(ctx context.Context, idempotencyKey string, result EffectResult) error

	// Advance validates the requested state transition via
	// controller.Transition and, if legal, durably persists it as key's new
	// checkpoint before the next effect may begin. The store itself derives
	// whether this assignment has already passed the LISTENER_RELEASED
	// boundary (see controller.Transition's doc and controller.
	// HasReleasedListener) from the row's currently persisted state --
	// there is no released parameter for a caller to get wrong -- and uses
	// that derived value both for the controller.Transition call and for
	// the persisted assignments.released column. Advancing into
	// StateListenerReleased increments the assignment's persisted release
	// generation exactly once (not on idempotent replay).
	Advance(ctx context.Context, key controller.AssignmentKey, next controller.State) error

	// MarkAmbiguous records that key's outcome is ambiguous (for example, a
	// release call timed out with an unknown result) without changing its
	// persisted state, so a reconciler -- not a blind duplicate release or
	// destroy -- resolves it. Idempotent: replaying the same reasonCode is
	// a no-op success.
	MarkAmbiguous(ctx context.Context, key controller.AssignmentKey, reasonCode string) error

	// BindRunner records that the exact observed upstream runner, request, and
	// container tuple is now bound to key's runner slot. An acquisition offer
	// is never itself a binding. The first tuple is immutable and an exact
	// replay is a no-op.
	BindRunner(ctx context.Context, key controller.AssignmentKey, upstreamRunnerID, boundRequestID int64, runnerContainerID string) error

	// LookupAssignmentEffect returns the unique effect of kind for key. More
	// than one matching effect is an identity conflict.
	LookupAssignmentEffect(ctx context.Context, key controller.AssignmentKey, kind string) (EffectRecord, error)

	// AdvancePreReleaseDestroyed is the checked pre-release terminal shortcut.
	// It succeeds only while no listener-release effect exists.
	AdvancePreReleaseDestroyed(ctx context.Context, key controller.AssignmentKey) error

	// ApplyRunnerObservation atomically establishes the exact runner binding,
	// proves the listener-release boundary, clears stale ambiguity, and
	// advances to JOB_RUNNING or JOB_FINISHED.
	ApplyRunnerObservation(ctx context.Context, key controller.AssignmentKey, observation RunnerObservation) error

	// ResolvePostRelease records a nonzero, closed evidence digest and resolves
	// one ambiguous post-release state without using the ordinary pre-release
	// DESTROYED shortcut. A later legal forward outcome atomically supersedes
	// that evidence; exact-state replay remains digest-identical.
	ResolvePostRelease(ctx context.Context, key controller.AssignmentKey, outcome controller.PostReleaseOutcome, evidence [sha256.Size]byte, resolvedAt time.Time) error

	// Reconcile-cycle methods retain at most the current incomplete cycle and
	// the latest terminal cycle.
	BeginReconcileCycle(ctx context.Context, cycleID string, startedAt time.Time) error
	CompleteReconcileCycle(ctx context.Context, receipt controller.CycleReceipt) error
	AbortReconcileCycle(ctx context.Context, cycleID string, completedAt time.Time, reasonCode string) error

	// ListRecoverable returns every assignment not yet in StateDestroyed,
	// so a restarted controller can reconcile from any checkpoint,
	// including one whose held broker (or adapter, or runner) was never
	// torn down before the crash.
	ListRecoverable(ctx context.Context) ([]RecoverableAssignment, error)

	// AcquisitionPolicy returns the controller's current persisted
	// acquisition policy.
	AcquisitionPolicy(ctx context.Context) (controller.AcquisitionPolicy, error)

	// CompareAndSetAcquisition atomically replaces the persisted
	// acquisition policy with next, but only if the currently stored
	// policy's Epoch equals expectedEpoch; on success the returned policy's
	// Epoch is expectedEpoch+1. On a mismatch, CompareAndSetAcquisition
	// returns the current stored policy (unchanged) and a non-nil error so
	// the caller can retry against the current epoch rather than clobber a
	// concurrent transition.
	CompareAndSetAcquisition(ctx context.Context, expectedEpoch uint64, next controller.AcquisitionPolicy) (controller.AcquisitionPolicy, error)
}
