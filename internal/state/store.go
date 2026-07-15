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
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

// OfferIdentity is the minimal, store-local shape of an acquisition offer
// that UpsertOffer persists. It intentionally does not depend on
// githubscale.Offer -- that adapter type belongs to Task 3 and does not
// exist yet. Task 3/4 map the real githubscale.Offer into this shape (or
// this type is widened then, under review) rather than this package
// importing a not-yet-existent package now.
type OfferIdentity struct {
	RepositoryAlias string
	RunnerRequestID int64
	WorkflowJobID   int64
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

// RecoverableAssignment is one row ListRecoverable returns: an assignment
// not yet DESTROYED, with every identity persisted for it so far, so a
// restarted controller can reconcile it from whatever checkpoint it last
// reached -- including an orphaned held broker with no further progress.
type RecoverableAssignment struct {
	Key             controller.AssignmentKey
	State           controller.State
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
	// UpsertOffer persists offer as a new assignment at StateReceived, or
	// returns the existing assignment's key unchanged if an assignment for
	// the same (RepositoryAlias, RunnerRequestID) already exists. Offer
	// identity is unique on that pair; UpsertOffer never creates a second
	// row for the same offer.
	UpsertOffer(ctx context.Context, offer OfferIdentity) (controller.AssignmentKey, error)

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

	// BindRunner records that upstreamRunnerID and runnerContainerID are
	// now bound to key's runner slot, from a JobAssigned/JobStarted
	// observation. An acquisition offer is never itself a binding; only
	// BindRunner establishes it. upstreamRunnerID must be unique across
	// live runner slots.
	BindRunner(ctx context.Context, key controller.AssignmentKey, upstreamRunnerID int64, runnerContainerID string) error

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
