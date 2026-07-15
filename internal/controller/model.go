// Package controller defines the canonical assignment domain that every
// GitHub Actions runner assignment moves through: the fixed, ordered
// lifecycle State machine, the identifiers that key an assignment and its
// runner slot, and the acquisition-policy value types the controller's
// local fleet-generation fence persists and compare-and-sets.
//
// Scope for Task 2 is deliberately narrow. This file defines the State
// enum, AssignmentKey, RunnerSlot, and the acquisition-policy value types
// consumed by internal/state.Store.AcquisitionPolicy and
// CompareAndSetAcquisition. It intentionally does NOT define
// AcquisitionTransitioner, AcquisitionGuard, FleetGuardProvider,
// AcquisitionPermitProvider, AcquisitionPermitRequest, or CycleReceipt --
// those belong to later tasks (7/8) that drive the fleet-generation fence
// and acquisition transitions. Defining them here, ahead of the code that
// consumes them, would be premature per the plan's Canonical Runtime
// Contracts (docs/superpowers/plans/2026-07-11-controller-runtime.md).
package controller

// State is one checkpoint in the fixed, ordered assignment lifecycle. The
// legal transitions between states are defined by Transition in
// state_machine.go, not by this type.
type State string

// The fifteen ordered lifecycle states, in the exact sequence the happy
// path moves through. Order matters: state_machine.go's Transition
// validates that a non-idempotent, non-DESTROYED move only ever advances
// to the very next state in this list -- never skips ahead and never goes
// backward.
const (
	StateReceived            State = "RECEIVED"
	StateCapacityReserved    State = "CAPACITY_RESERVED"
	StateAdapterCreated      State = "ADAPTER_CREATED"
	StateAdapterVerified     State = "ADAPTER_VERIFIED"
	StateBrokerHeld          State = "BROKER_HELD"
	StateBrokerPolicyApplied State = "BROKER_POLICY_APPLIED"
	StateDialAuthorityReady  State = "DIAL_AUTHORITY_READY"
	StateBrokerReleased      State = "BROKER_RELEASED"
	StateEgressVerified      State = "EGRESS_VERIFIED"
	StateRunnerHeld          State = "RUNNER_HELD"
	StateReleaseArmed        State = "RELEASE_ARMED"
	StateListenerReleased    State = "LISTENER_RELEASED"
	StateJobRunning          State = "JOB_RUNNING"
	StateJobFinished         State = "JOB_FINISHED"
	StateDestroyed           State = "DESTROYED"
)

// AssignmentKey identifies one assignment attempt: a specific acquisition
// offer (RunnerRequestID) for a specific repository (RepositoryAlias), on a
// specific retry (Attempt). A JobAvailable runner-request ID is an
// acquisition offer, not a promise -- RepositoryAlias plus RunnerRequestID
// is therefore the natural uniqueness boundary for an offer, and Attempt
// distinguishes a retry of the same offer from the original.
type AssignmentKey struct {
	RepositoryAlias string
	RunnerRequestID int64
	Attempt         uint32
}

// RunnerSlot is the persisted identity of the per-assignment resource set:
// the stable capacity-slot reservation plus the adapter, held-broker, and
// runner container identities as each is created, and the upstream runner
// binding once GitHub's JobAssigned/JobStarted observation confirms it.
type RunnerSlot struct {
	// OpaqueName is the stable, human-opaque name assigned to this slot at
	// reservation time (CAPACITY_RESERVED). It never encodes secret or
	// job-controlled material.
	OpaqueName string

	// UpstreamRunnerID and BoundRequestID are populated only once GitHub's
	// JobAssigned/JobStarted observation binds an actual upstream runner to
	// this slot -- an offer is never itself a binding.
	UpstreamRunnerID int64
	BoundRequestID   int64

	RunnerContainerID  string
	AdapterContainerID string
	BrokerContainerID  string

	// CapacitySlotID is the stable capacity-slot identity reserved at
	// CAPACITY_RESERVED and held for the assignment's lifetime.
	CapacitySlotID uint32
}

// AcquisitionMode enumerates the controller's local acquisition-policy
// modes.
type AcquisitionMode string

const (
	AcquisitionDisabled   AcquisitionMode = "disabled"
	AcquisitionCanaryOnly AcquisitionMode = "canary-only"
	AcquisitionEnabled    AcquisitionMode = "enabled"
	AcquisitionFatal      AcquisitionMode = "fatal"
)

// AcquisitionPolicy is the controller's local acquisition policy: which
// scale sets are eligible, the effective capacity ceiling, and the
// per-repository policy set, each guarded by a monotonic Epoch that every
// compare-and-set transition and broker poll lease must agree on.
type AcquisitionPolicy struct {
	Mode                     AcquisitionMode
	EligibleScaleSets        []string
	MaxCapacity              int
	RepositoryPolicyRevision uint64
	RepositoryPolicies       []RepositoryPolicySummary
	Epoch                    uint64
}

// RepositoryPolicySummary is one repository's admission policy within an
// AcquisitionPolicy.
type RepositoryPolicySummary struct {
	Alias          string
	MaxConcurrency uint32
	Eligibility    string // active | archived-disabled | pending-reactivation
}
