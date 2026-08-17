package main

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/health"
)

var (
	errDisabledProjectionIncomplete = errors.New(
		"portable-ghar-controller: local projection incomplete",
	)
	errDisabledFleetAuthority = errors.New(
		"portable-ghar-controller: fleet authority unavailable",
	)
	errDisabledExternalUnavailable = errors.New(
		"portable-ghar-controller: external authority unavailable",
	)
)

type localObservation struct {
	Sequence            uint64
	ObservedAt          time.Time
	Complete            bool
	RunningJobs         uint64
	PendingAcquisitions uint64
	ReleasedListeners   uint64
	Runners             uint64
	Adapters            uint64
	Brokers             uint64
	Helpers             uint64
	Verifiers           uint64
	ActiveDials         uint64
	PerJobSockets       uint64
}

func (observation localObservation) Validate(
	now time.Time,
	maxAge time.Duration,
) error {
	if observation.Sequence == 0 ||
		!observation.Complete ||
		observation.ObservedAt.IsZero() ||
		maxAge <= 0 ||
		now.IsZero() ||
		observation.ObservedAt.After(now) ||
		now.Sub(observation.ObservedAt) > maxAge {
		return errDisabledProjectionIncomplete
	}
	return nil
}

func (observation localObservation) Zero() bool {
	return observation.Complete &&
		observation.Sequence != 0 &&
		observation.RunningJobs == 0 &&
		observation.PendingAcquisitions == 0 &&
		observation.ReleasedListeners == 0 &&
		observation.Runners == 0 &&
		observation.Adapters == 0 &&
		observation.Brokers == 0 &&
		observation.Helpers == 0 &&
		observation.Verifiers == 0 &&
		observation.ActiveDials == 0 &&
		observation.PerJobSockets == 0
}

type completeLocalAuthority interface {
	ColdReconcile(context.Context) error
	ReconcileOnce(context.Context) (controller.CycleReceipt, error)
	DrainWait(context.Context) error
	RevokePreRunning(context.Context) error
	Observe(context.Context) (localObservation, error)
}

type fleetAuthorityProof struct {
	Sequence       uint64
	ObservedAt     time.Time
	Fleet          fleetfence.Fleet
	Generation     uint64
	SelfGuardToken string
	LegacyProof    *fleetfence.LegacyObserverProof
}

func (proof fleetAuthorityProof) Validate(
	now time.Time,
	maxAge time.Duration,
	expectedFleet fleetfence.Fleet,
	expectedGeneration uint64,
) error {
	if proof.Sequence == 0 ||
		proof.ObservedAt.IsZero() ||
		maxAge <= 0 ||
		now.IsZero() ||
		proof.ObservedAt.After(now) ||
		now.Sub(proof.ObservedAt) > maxAge ||
		expectedGeneration == 0 ||
		proof.Generation != expectedGeneration ||
		proof.Fleet != expectedFleet {
		return errDisabledFleetAuthority
	}
	switch proof.Fleet {
	case fleetfence.FleetPortable:
		if !validLocalScalar(proof.SelfGuardToken) ||
			proof.LegacyProof != nil {
			return errDisabledFleetAuthority
		}
	case fleetfence.FleetLegacy:
		if proof.SelfGuardToken != "" ||
			proof.LegacyProof == nil ||
			proof.LegacyProof.FleetGeneration != proof.Generation ||
			proof.LegacyProof.PolicyEpoch == 0 ||
			!validLowerDigest(proof.LegacyProof.PolicyDigest) {
			return errDisabledFleetAuthority
		}
	default:
		return errDisabledFleetAuthority
	}
	return nil
}

type fleetAuthority interface {
	Observe(context.Context) (fleetAuthorityProof, error)
}

type zeroDemandBroker struct {
	mu      sync.Mutex
	summary controller.CapacitySummary
}

var _ controller.AdmissionBroker = (*zeroDemandBroker)(nil)

func newZeroDemandBroker(epoch uint64) (*zeroDemandBroker, error) {
	if epoch == 0 {
		return nil, errDisabledProjectionIncomplete
	}
	return &zeroDemandBroker{
		summary: controller.CapacitySummary{Epoch: epoch},
	}, nil
}

func (broker *zeroDemandBroker) ApplyAcquisitionPolicy(
	policy controller.AcquisitionPolicy,
) error {
	canonical, err := controller.CanonicalizeAcquisitionPolicy(policy)
	if err != nil ||
		canonical.Mode != controller.AcquisitionDisabled ||
		canonical.Epoch == 0 ||
		canonical.MaxCapacity != 0 ||
		len(canonical.EligibleScaleSets) != 0 {
		return errDisabledExternalUnavailable
	}
	broker.mu.Lock()
	broker.summary = controller.CapacitySummary{Epoch: canonical.Epoch}
	broker.mu.Unlock()
	return nil
}

func (broker *zeroDemandBroker) SetDemand(string, uint64, int) error {
	return errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) CapacitySummary() controller.CapacitySummary {
	if broker == nil {
		return controller.CapacitySummary{}
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	return broker.summary
}

func (broker *zeroDemandBroker) CheckOffer(
	string,
	githubscale.Offer,
) error {
	return errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) LeasePoll(
	string,
	time.Time,
) (controller.PollLease, error) {
	return controller.PollLease{}, errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) EnsureQueuedBatch(
	uint64,
	string,
	[]githubscale.Offer,
) ([]controller.AdmissionReference, error) {
	return nil, errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) Restore(
	references []controller.AdmissionReference,
) error {
	if len(references) != 0 {
		return errDisabledExternalUnavailable
	}
	return nil
}

func (broker *zeroDemandBroker) Admit(
	uint64,
	time.Time,
) ([]controller.AdmissionDecision, error) {
	return nil, errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) Reference(
	controller.AssignmentKey,
) (controller.AdmissionReference, bool, error) {
	return controller.AdmissionReference{}, false, errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) SetPressure(
	int,
) (int, int, error) {
	return 0, 0, errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) Release(controller.AssignmentKey) error {
	return errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) Retire(controller.AssignmentKey) error {
	return errDisabledExternalUnavailable
}

func (broker *zeroDemandBroker) HasLiveReference(
	controller.AssignmentKey,
) bool {
	return false
}

func validateZeroCapacitySummary(
	summary controller.CapacitySummary,
	expectedEpoch uint64,
) error {
	if expectedEpoch == 0 ||
		summary.Epoch != expectedEpoch ||
		summary.ConfiguredCapacity != 0 ||
		summary.EffectiveCapacity != 0 ||
		summary.Occupied != 0 ||
		summary.Available != 0 ||
		summary.Queued != 0 {
		return errDisabledProjectionIncomplete
	}
	return nil
}

type disabledExternalGraph interface {
	controller.AcquisitionPermitProvider
	controller.ReplayVerifier
	controller.HostedRouter
	controller.HealthPublisher
	PollTargets() []controller.PollTarget
}

type unavailableExternalGraph struct{}

var (
	_ controller.AcquisitionPermitProvider = unavailableExternalGraph{}
	_ controller.ReplayVerifier            = unavailableExternalGraph{}
	_ controller.HostedRouter              = unavailableExternalGraph{}
	_ controller.HealthPublisher           = unavailableExternalGraph{}
)

func newUnavailableExternalGraph() unavailableExternalGraph {
	return unavailableExternalGraph{}
}

func (unavailableExternalGraph) Acquire(
	context.Context,
	controller.AcquisitionPermitRequest,
) (controller.AcquisitionGuard, error) {
	return nil, errDisabledExternalUnavailable
}

func (unavailableExternalGraph) VerifyCurrentOffer(
	context.Context,
	githubscale.Fleet,
	githubscale.Offer,
) (controller.ReplayVerification, error) {
	return 0, errDisabledExternalUnavailable
}

func (unavailableExternalGraph) Readiness(
	context.Context,
	string,
	uint64,
) (controller.HostedReadinessProof, error) {
	return controller.HostedReadinessProof{}, errDisabledExternalUnavailable
}

func (unavailableExternalGraph) RouteHosted(
	context.Context,
	controller.AssignmentKey,
	string,
	controller.HostedReason,
) (string, error) {
	return "", errDisabledExternalUnavailable
}

func (unavailableExternalGraph) Publish(
	context.Context,
	health.Snapshot,
) error {
	return errDisabledExternalUnavailable
}

func (unavailableExternalGraph) PollTargets() []controller.PollTarget {
	return nil
}

func validLowerDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
