// Package githubscale wraps the Public-Preview github.com/actions/scaleset
// v0.4.0 client behind a pinned, internal contract. No upstream scaleset
// type ever crosses this package's exported surface: every exported type
// below is this adapter's own canonical shape, translated from the
// upstream wire types inside adapter_v040.go. Later controller tasks
// (admission, lifecycle) consume only these internal types -- Batch,
// Offer, the job-lifecycle events, JITConfig, RunnerRef -- never
// *scaleset.RunnerScaleSetMessage, *scaleset.RunnerScaleSetJitRunnerConfig,
// or any other upstream struct.
//
// Scope for Task 3 is the adapter itself: Client.Open, Session's
// Poll/Ack/Acquire/GenerateJIT/runner operations, and the startup
// CompatibilityReport gate (probe.go). It does not implement the admission
// broker, the reconciler, or the acquisition-policy state machine that
// later tasks build on top of this package -- see internal/controller's
// and internal/state's package docs for the matching scope notes on the
// domain types those own.
package githubscale

import (
	"context"
	"errors"
	"time"

	"github.com/sumitake/portable-ghar/internal/redaction"
)

// Fleet identifies the specific GitHub Actions runner scale set a Session
// polls: which GitHub organization/repository/enterprise config URL to
// authenticate against, and which scale set (by name) within it. Fleet
// never carries a credential -- that is supplied once, to NewClient, via
// ClientConfig.
type Fleet struct {
	// RepositoryAlias is the controller's own opaque name for this fleet
	// (see controller.AssignmentKey.RepositoryAlias). It is passed to the
	// upstream message-session as the session owner label so a session
	// created by this controller is identifiable in GitHub-side diagnostics,
	// but it is never interpreted by this package.
	RepositoryAlias string

	// GitHubConfigURL is the GitHub org/repo/enterprise URL that scopes the
	// scale set lookup (for example "https://github.com/owner/repository").
	GitHubConfigURL string

	// ScaleSetName is the exact scale-set name Open resolves and validates
	// against the single-name-label rule (see verifySingleNameLabel in
	// client.go) before any acquisition against it is possible.
	ScaleSetName string
}

// JobRef carries the fields common to all four upstream job-message
// shapes (JobAvailable, JobAssigned, JobStarted, JobCompleted). It is the
// translated, internal equivalent of scaleset.JobMessageBase -- every
// field here has a same-named or renamed counterpart there; see
// translateJobRef in adapter_v040.go for the exact mapping.
type JobRef struct {
	// RunnerRequestID is the acquisition-offer identity: a JobAvailable
	// runner-request ID is an offer, not a promise (see
	// controller.AssignmentKey's doc). The SAME underlying GitHub job (same
	// JobID) can reappear under a NEW RunnerRequestID if GitHub re-queues
	// it -- RunnerRequestID, not JobID, is this package's uniqueness
	// boundary for an offer.
	RunnerRequestID int64

	// JobID is GitHub's own opaque job identifier (a GUID string on the
	// wire). It stays constant across a job's re-queues even when
	// RunnerRequestID changes.
	JobID string

	RepositoryName string
	OwnerName      string
	JobWorkflowRef string
	JobDisplayName string
	WorkflowRunID  int64
	EventName      string
	RequestLabels  []string

	QueueTime          time.Time
	ScaleSetAssignTime time.Time
	RunnerAssignTime   time.Time
	FinishTime         time.Time
}

// Offer is the translated form of an upstream JobAvailable message: a
// candidate acquisition opportunity. Offers are batched into Poll's
// returned Batch; Acquire is the separate, explicit call that attempts to
// claim one or more of them.
type Offer struct {
	JobRef

	// AcquireJobURL is upstream diagnostic/informational metadata carried
	// on JobAvailable; this adapter's Acquire always calls the pinned
	// v0.4.0 AcquireJobs API directly (never this URL, and never upstream's
	// own listener package).
	AcquireJobURL string
}

// AssignedEvent is the translated form of an upstream JobAssigned message:
// GitHub has bound RunnerRequestID to an upstream runner. This is an
// observation, not an acquisition outcome -- see controller.RunnerSlot's
// doc on BindRunner being the only thing that establishes a binding.
type AssignedEvent struct {
	JobRef
}

// StartedEvent is the translated form of an upstream JobStarted message.
type StartedEvent struct {
	JobRef

	RunnerID   int64
	RunnerName string
}

// CompletedEvent is the translated form of an upstream JobCompleted
// message.
type CompletedEvent struct {
	JobRef

	Result     string
	RunnerID   int64
	RunnerName string
}

// Statistics is the translated form of upstream *scaleset.RunnerScaleSetStatistic.
// When the upstream message carries no statistics block, Statistics is the
// zero value -- callers that need to distinguish "no stats reported" from
// "all counters are genuinely zero" should treat a Batch with no offers or
// events and a zero Statistics as the former, since GitHub always attaches
// statistics to a real message.
type Statistics struct {
	TotalAvailableJobs     int
	TotalAcquiredJobs      int
	TotalAssignedJobs      int
	TotalRunningJobs       int
	TotalRegisteredRunners int
	TotalBusyRunners       int
	TotalIdleRunners       int
}

// Batch is the translated form of upstream *scaleset.RunnerScaleSetMessage:
// everything Poll observed in one call, with all four job-message shapes
// already sorted into their own slices and no upstream type anywhere in
// it. Poll never acks (deletes) the underlying message; Batch.MessageID is
// the value the caller passes to Ack once -- and only once -- it has
// durably persisted whatever it needed from this Batch.
type Batch struct {
	// Empty is true when Poll observed no message at all (the upstream
	// v0.4.0 API's documented (nil, nil) "nothing available" response).
	// When Empty is true every other field is its zero value and there is
	// nothing to Ack.
	Empty bool

	// MessageID is the upstream message's ID, needed by Ack. It is
	// meaningless when Empty is true.
	MessageID int

	Statistics Statistics
	Offers     []Offer
	Assigned   []AssignedEvent
	Started    []StartedEvent
	Completed  []CompletedEvent
}

// JITRequest is this adapter's own shape for a just-in-time runner
// configuration request; GenerateJIT translates it into upstream's
// RunnerScaleSetJitRunnerSetting.
type JITRequest struct {
	RunnerName string
	WorkFolder string
}

// RunnerRef is the translated form of upstream *scaleset.RunnerReference.
type RunnerRef struct {
	ID               int64
	Name             string
	RunnerScaleSetID int
}

// JITConfig is the translated form of upstream
// *scaleset.RunnerScaleSetJitRunnerConfig. Encoded is deliberately a
// *redaction.Secret, never a string or []byte: per
// internal/redaction.Secret's doc, a Secret must be referenced only by
// pointer for its copy-safety guard (embedded noCopy, enforced by `go
// vet`'s copylocks analysis) to hold -- storing it as a non-pointer struct
// field would make every ordinary `cfg := session.GenerateJIT(...)`
// assignment at every call site a copylocks violation and fail `go vet
// ./...`. See adapter_contract_test.go's
// TestJITConfigEncodedFieldIsPointerForCopySafety (and this package's
// report) for the empirical proof this package's design is built on.
type JITConfig struct {
	Runner  RunnerRef
	Encoded *redaction.Secret
}

// CompatibilityReport is Probe's result: what actions/scaleset dependency
// this adapter was written against (ModulePath, ExpectedVersion, Commit,
// License), what is actually linked into the running binary
// (LinkedVersion), and whether they match.
type CompatibilityReport struct {
	ModulePath      string
	ExpectedVersion string
	LinkedVersion   string
	Commit          string
	License         string

	// Compatible is true only when LinkedVersion == ExpectedVersion. A
	// caller must treat any non-Compatible report as a hard startup
	// failure -- see probe.go's Probe doc.
	Compatible bool

	// Reason is populated whenever Compatible is false, describing exactly
	// what mismatched.
	Reason string
}

// Client is this adapter's top-level entry point: it authenticates once
// against a GitHub config URL and, from there, opens per-fleet Sessions
// and runs the startup compatibility Probe. No upstream scaleset type
// appears in this interface.
type Client interface {
	// Open resolves fleet.ScaleSetName within the default runner group,
	// enforces the single-name-label rule (see client.go), opens an
	// upstream message session, and returns a Session bound to it. Open
	// returns a non-nil error -- and no Session -- for every case that must
	// keep acquisition disabled: the scale set not found, a label mismatch,
	// a scale-set-identity mismatch, a session-creation failure, or context
	// cancellation.
	Open(ctx context.Context, fleet Fleet) (Session, error)

	// Probe runs the startup compatibility check (see probe.go) and
	// returns its CompatibilityReport. It does not depend on Fleet or any
	// live GitHub API call -- it inspects only this binary's own linked
	// module version.
	Probe(ctx context.Context) (CompatibilityReport, error)
}

// Session is one fleet's live connection to the pinned v0.4.0 scale-set
// API: message polling/acknowledgement/acquisition, JIT runner
// configuration, and runner lookups. Every method takes an explicit
// per-operation context deadline in addition to whatever deadline the
// caller's ctx already carries (see adapter_v040.go's withOperationDeadline)
// and the underlying HTTP transport carries its own response-header
// timeout (see client.go's newHTTPTransport) -- neither Poll, Acquire,
// GenerateJIT, nor any runner call can hang past those bounds.
type Session interface {
	// Poll fetches the next batch of messages after lastMessageID, capped
	// at maxCapacity (passed through to the upstream API unchanged). Poll
	// never acks (deletes) the message it returns -- see Ack.
	Poll(ctx context.Context, lastMessageID, maxCapacity int) (Batch, error)

	// Ack acknowledges (deletes) messageID. It is a separate, explicit
	// call from Poll -- a message is never auto-acked. Callers must
	// durably persist whatever they needed from the corresponding Batch
	// BEFORE calling Ack: if persistence fails, the caller must not call
	// Ack, so the message is redelivered on the next Poll.
	Ack(ctx context.Context, messageID int) error

	// Acquire attempts to claim the given runner-request IDs and returns
	// the subset actually acquired.
	Acquire(ctx context.Context, requestIDs []int64) ([]int64, error)

	// GenerateJIT requests a just-in-time runner configuration. It returns
	// a non-nil error -- never a zero-value JITConfig with an unusable
	// Encoded -- when the upstream response is shape-mismatched (missing
	// Runner or an empty encoded config).
	GenerateJIT(ctx context.Context, req JITRequest) (JITConfig, error)

	GetRunnerByName(ctx context.Context, name string) (RunnerRef, error)
	GetRunner(ctx context.Context, id int64) (RunnerRef, error)
	RemoveRunner(ctx context.Context, id int64) error

	// Close releases the upstream message session. It does not close or
	// otherwise invalidate the Client that opened this Session.
	Close(ctx context.Context) error
}

// Sentinel errors this package returns, always wrapped with additional
// context via fmt.Errorf's %w. Callers should compare with errors.Is.
var (
	// ErrScaleSetNotFound is returned by Open when no scale set exists
	// with the requested Fleet.ScaleSetName.
	ErrScaleSetNotFound = errors.New("githubscale: scale set not found")

	// ErrLabelMismatch is returned by Open when the resolved scale set's
	// labels do not satisfy the single-name-label rule: exactly one label,
	// equal to Fleet.ScaleSetName.
	ErrLabelMismatch = errors.New("githubscale: scale set does not carry exactly one label matching its name")

	// ErrJITShapeMismatch is returned by GenerateJIT when the upstream
	// response is missing its runner reference or its encoded config.
	ErrJITShapeMismatch = errors.New("githubscale: JIT runner config response is missing its runner or encoded config")

	// ErrRunnerNotFound is returned by GetRunnerByName when the upstream
	// lookup finds no matching runner (upstream's (nil, nil) "not found"
	// response).
	ErrRunnerNotFound = errors.New("githubscale: runner not found")

	// ErrIncompatibleModuleVersion is returned by Probe when the linked
	// actions/scaleset module version does not exactly match the pinned
	// v0.4.0 this adapter was written against.
	ErrIncompatibleModuleVersion = errors.New("githubscale: linked actions/scaleset module version does not match the pinned v0.4.0")

	// ErrBuildInfoUnavailable is returned by Probe when
	// runtime/debug.ReadBuildInfo reports no build info at all (for
	// example, a binary built without module mode).
	ErrBuildInfoUnavailable = errors.New("githubscale: runtime/debug.ReadBuildInfo unavailable")
)
