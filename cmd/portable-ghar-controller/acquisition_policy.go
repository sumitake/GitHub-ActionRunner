package main

import (
	"math"
	"sort"
	"time"

	"github.com/sumitake/portable-ghar/internal/admission"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/state"
)

// productionEnabledPolicyTemplate is the policy an operator enables: every
// overlay repository at its configured concurrency, every scale set eligible,
// and the overlay's capacity. It shares its repository list with
// productionDisabledPolicy, so enabling and disabling cannot drift apart.
func productionEnabledPolicyTemplate(
	overlay hostruntime.PrivateOverlay,
) (controller.AcquisitionPolicy, error) {
	disabled, err := productionDisabledPolicy(overlay)
	if err != nil || overlay.Resources.MaxCapacity > uint64(math.MaxInt) {
		return controller.AcquisitionPolicy{}, errCommandUnavailable
	}
	scaleSets := make([]string, 0, len(overlay.Repositories))
	seen := make(map[string]bool, len(overlay.Repositories))
	for _, repository := range overlay.Repositories {
		if !seen[repository.ScaleSetName] {
			seen[repository.ScaleSetName] = true
			scaleSets = append(scaleSets, repository.ScaleSetName)
		}
	}
	sort.Strings(scaleSets)
	enabled := disabled
	enabled.Mode = controller.AcquisitionEnabled
	enabled.MaxCapacity = int(overlay.Resources.MaxCapacity)
	enabled.EligibleScaleSets = scaleSets
	return controller.CanonicalizeAcquisitionPolicy(enabled)
}

// productionAdmissionConfig maps the overlay's admission ceiling, capacity
// bounds, poll timings, and repository profiles to the admission broker.
// The broker starts at the durable policy epoch: the service's first act is
// to persist a zeroed policy at the next epoch and apply it to the broker.
// The lifecycle sizes every job's containers from the overlay's one slot
// vector, so a repository profile must equal it: admission then charges
// exactly what each job is given.
func productionAdmissionConfig(
	overlay hostruntime.PrivateOverlay,
	policyEpoch uint64,
	now func() time.Time,
) (admission.Config, error) {
	resources := overlay.Resources
	ceiling, ok := admissionResources(resources.AdmissionCeiling)
	pollLeaseTTL, ttlErr := time.ParseDuration(overlay.Controller.PollLeaseTTL)
	ledgerTail, tailErr := time.ParseDuration(overlay.Controller.LedgerTail)
	if !ok || ttlErr != nil || tailErr != nil || now == nil || policyEpoch == 0 ||
		resources.MaxCapacity > uint64(math.MaxInt) ||
		resources.MaxLiveReferences > uint64(math.MaxInt) {
		return admission.Config{}, errCommandUnavailable
	}
	repositories := make([]admission.RepositoryPolicy, len(overlay.Repositories))
	for index, repository := range overlay.Repositories {
		aging, err := time.ParseDuration(repository.AgingThreshold)
		profile, profileOK := admissionSlotResources(repository.SlotResources)
		if err != nil || !profileOK || repository.SlotResources != resources.SlotResources {
			return admission.Config{}, errCommandUnavailable
		}
		repositories[index] = admission.RepositoryPolicy{
			Alias:          repository.Alias,
			Weight:         repository.Weight,
			MaxConcurrency: repository.MaxConcurrency,
			Eligibility:    admission.Eligibility(repository.Eligibility),
			AgingThreshold: aging,
			Profile:        profile,
		}
	}
	return admission.Config{
		Ceiling:                  ceiling,
		MaxCapacity:              int(resources.MaxCapacity),
		MaxLiveReferences:        int(resources.MaxLiveReferences),
		MaxOfferLogicalBytes:     resources.MaxOfferLogicalBytes,
		MaxLiveOfferLogicalBytes: resources.MaxLiveOfferLogicalBytes,
		PollLeaseTTL:             pollLeaseTTL,
		LedgerTail:               ledgerTail,
		TransientMode:            admission.TransientMode(resources.TransientMode),
		PolicyRevision:           policyEpoch,
		Repositories:             repositories,
		Now:                      now,
	}, nil
}

func admissionSlotResources(
	slot hostruntime.SlotResourcesOverlay,
) (admission.SlotResources, bool) {
	runner, runnerOK := admissionResources(slot.Runner)
	adapter, adapterOK := admissionResources(slot.Adapter)
	broker, brokerOK := admissionResources(slot.Broker)
	dial, dialOK := admissionResources(slot.DialAuthority)
	helper, helperOK := admissionResources(slot.Helper)
	verifier, verifierOK := admissionResources(slot.Verifier)
	return admission.SlotResources{
		Runner:        runner,
		Adapter:       adapter,
		Broker:        broker,
		DialAuthority: dial,
		Helper:        helper,
		Verifier:      verifier,
	}, runnerOK && adapterOK && brokerOK && dialOK && helperOK && verifierOK
}

func admissionResources(vector hostruntime.ResourceVectorOverlay) (admission.Resources, bool) {
	values := []uint64{
		vector.MilliCPU, vector.MemoryBytes, vector.PIDs,
		vector.FileDescriptors, vector.TmpfsBytes, vector.ScratchBytes,
		vector.SocketStateBytes, vector.DurableStateBytes, vector.Inodes,
	}
	for _, value := range values {
		if value > math.MaxInt64 {
			return admission.Resources{}, false
		}
	}
	return admission.Resources{
		MilliCPU:          int64(vector.MilliCPU),
		MemoryBytes:       int64(vector.MemoryBytes),
		PIDs:              int64(vector.PIDs),
		FileDescriptors:   int64(vector.FileDescriptors),
		TmpfsBytes:        int64(vector.TmpfsBytes),
		ScratchBytes:      int64(vector.ScratchBytes),
		SocketStateBytes:  int64(vector.SocketStateBytes),
		DurableStateBytes: int64(vector.DurableStateBytes),
		Inodes:            int64(vector.Inodes),
	}, true
}

// productionHistoryPressure derives the pressure thresholds from limits the
// overlay already sets, rather than adding new tunables. Stop is the store's
// hard limit. Warning is that limit less the reserve held for in-flight work
// at full concurrency, the same reserve productionHistoryLimits checks fits.
// Under warning the service caps acquisition at one slot.
func productionHistoryPressure(
	overlay hostruntime.PrivateOverlay,
	limits state.HistoryLimits,
) (controller.HistoryPressureThresholds, error) {
	concurrency := overlay.Resources.FleetConcurrency
	reserveRows, rowsOK := multiplyStatusTotal(concurrency, limits.InflightReserveRows)
	reserveBytes, bytesOK := multiplyStatusTotal(concurrency, limits.InflightReserveLogicalBytes)
	ledgerRows := overlay.Resources.NetworkLedgerReserveRows
	ledgerBytes := overlay.Resources.NetworkLedgerReserveBytes
	if !rowsOK || !bytesOK ||
		reserveRows >= limits.MaxHistoryRows ||
		reserveBytes >= limits.MaxHistoryLogicalBytes ||
		ledgerRows >= limits.MaxNetworkLedgerRows ||
		ledgerBytes >= limits.MaxNetworkLedgerLogicalBytes {
		return controller.HistoryPressureThresholds{}, errCommandUnavailable
	}
	return controller.HistoryPressureThresholds{
		WarningHistoryRows:        limits.MaxHistoryRows - reserveRows,
		StopHistoryRows:           limits.MaxHistoryRows,
		WarningHistoryBytes:       limits.MaxHistoryLogicalBytes - reserveBytes,
		StopHistoryBytes:          limits.MaxHistoryLogicalBytes,
		WarningNetworkLedgerRows:  limits.MaxNetworkLedgerRows - ledgerRows,
		StopNetworkLedgerRows:     limits.MaxNetworkLedgerRows,
		WarningNetworkLedgerBytes: limits.MaxNetworkLedgerLogicalBytes - ledgerBytes,
		StopNetworkLedgerBytes:    limits.MaxNetworkLedgerLogicalBytes,
		WarningMaxCapacity:        1,
	}, nil
}
