package testenv

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const maximumTargetNetworkDocumentBytes = 64 << 10

type targetRuntimeObservation struct {
	Isolation            hostruntime.IsolationEvidence
	ProbeReport          networkjail.ProbeReport
	RunnerRoutesComplete bool
}

type targetObservationSource interface {
	FinalObservation(
		context.Context,
	) (targetRuntimeObservation, error)
}

type targetEvidenceLedger interface {
	FinalEvidenceDigest() (string, error)
}

type dynamicTargetFinalizer struct {
	targetProfileID string
	profileID       hostruntime.HostProfile
	allowDegraded   bool
	overlay         hostruntime.PrivateOverlay
	static          staticPreflightResult
	graph           networkjail.DecisionGraph
	source          targetObservationSource
	ledger          targetEvidenceLedger
}

func newDynamicTargetFinalizer(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
	graph networkjail.DecisionGraph,
	source targetObservationSource,
	ledger targetEvidenceLedger,
) (*dynamicTargetFinalizer, error) {
	profileID, profileOK := runtimeProfileFromTarget(
		input.Target.ProfileID,
	)
	allowDegraded := profileID == hostruntime.HostProfileQTSCaplessRoot
	if source == nil ||
		ledger == nil ||
		input.Target.OperatingSystem != "linux" ||
		input.Target.OperatingSystem != overlay.Target.OS ||
		input.Target.OperatingSystem != static.HostFacts.OperatingSystem ||
		input.Target.Architecture != overlay.Target.Architecture ||
		input.Target.Architecture != static.HostFacts.Architecture ||
		uint64(input.Target.ExpectedEUID) != overlay.Target.ExpectedEUID ||
		input.Target.ExpectedEUID != static.HostFacts.EUID ||
		input.Target.HostIdentityDigest !=
			static.HostFacts.HostIdentityDigest ||
		string(profileID) != overlay.Target.ProfileID ||
		!isLowerHex(input.Target.HostIdentityDigest, 64) ||
		!validStaticDockerInfo(static.DockerInfo) ||
		!staticDockerInfoMatches(input.Target, static.DockerInfo) ||
		!validObservedHostCapabilities(
			input.Target,
			true,
			static.HostCapabilities,
		) ||
		overlay.Docker.RunnerNetworkMode != "none" ||
		overlay.Docker.BrokerNetworkID !=
			hostruntime.EgressBackendRestrictedBrokerV1 ||
		overlay.Profile.PlatformEvidenceRevision == "" ||
		graph.Digest().String() == "" ||
		graph.EgressBackend() != networkjail.RestrictedBrokerV1 ||
		!profileOK ||
		(profileID == hostruntime.HostProfileStrictLinux &&
			(allowDegraded ||
				overlay.Target.DegradedAcknowledged ||
				input.Target.ExpectedEUID == 0)) ||
		(profileID == hostruntime.HostProfileQTSCaplessRoot &&
			(!allowDegraded ||
				!overlay.Target.DegradedAcknowledged ||
				input.Target.ExpectedEUID != 0)) {
		return nil, ErrFixtureStart
	}
	return &dynamicTargetFinalizer{
		targetProfileID: input.Target.ProfileID,
		profileID:       profileID,
		allowDegraded:   allowDegraded,
		overlay:         overlay,
		static:          static,
		graph:           graph,
		source:          source,
		ledger:          ledger,
	}, nil
}

func (f *dynamicTargetFinalizer) Finalize(
	ctx context.Context,
	completed []conformance.CaseID,
) (conformance.TargetObservationInput, error) {
	if f == nil || f.source == nil || f.ledger == nil ||
		ctx == nil || ctx.Err() != nil ||
		!exactDynamicCompletedCases(completed) {
		return conformance.TargetObservationInput{},
			conformance.ErrObservation
	}
	observation, err := f.source.FinalObservation(ctx)
	if err != nil || ctx.Err() != nil ||
		observation.Isolation.EvidenceRevision != "" ||
		networkjail.ValidateProbeReport(observation.ProbeReport) != nil ||
		observation.ProbeReport.PolicyDigest != f.graph.Digest().String() ||
		observation.ProbeReport.EgressBackend != f.graph.EgressBackend() ||
		observation.Isolation.PolicyDigest != f.graph.Digest().String() ||
		!observation.RunnerRoutesComplete {
		return conformance.TargetObservationInput{},
			conformance.ErrObservation
	}
	evidenceRevision, err := f.ledger.FinalEvidenceDigest()
	if err != nil ||
		!isLowerHex(evidenceRevision, 64) ||
		ctx.Err() != nil {
		return conformance.TargetObservationInput{},
			conformance.ErrObservation
	}
	observation.Isolation.EvidenceRevision = evidenceRevision
	profileObservation, err := profileObservationFromTarget(
		f.targetProfileID,
		f.overlay,
		f.static,
		f.static.HostCapabilities,
		observation.Isolation,
	)
	if err != nil {
		return conformance.TargetObservationInput{},
			conformance.ErrObservation
	}
	profileReport, err := hostruntime.EvaluateProfileObservation(
		f.profileID,
		f.allowDegraded,
		profileObservation,
	)
	if err != nil {
		return conformance.TargetObservationInput{},
			conformance.ErrObservation
	}
	networkDocument := hostruntime.NetworkDiscoveryDocument{
		ProfileID:         f.profileID,
		RunnerNetworkMode: f.overlay.Docker.RunnerNetworkMode,
		BrokerNetworkID:   f.overlay.Docker.BrokerNetworkID,
		BrokerIPv6Enabled: f.graph.BrokerIPv6Posture() ==
			networkjail.DenyViaIP6Tables,
		RunnerLoopbackOnly: observation.ProbeReport.RunnerLoopbackOnly,
		RoutesComplete:     observation.RunnerRoutesComplete,
		EvidenceRevision:   evidenceRevision,
	}
	document, err := json.Marshal(networkDocument)
	if err != nil {
		return conformance.TargetObservationInput{},
			conformance.ErrObservation
	}
	document = append(document, '\n')
	network, err := hostruntime.ParseNetworkDiscovery(
		document,
		maximumTargetNetworkDocumentBytes,
	)
	if err != nil {
		return conformance.TargetObservationInput{},
			conformance.ErrObservation
	}
	return conformance.TargetObservationInput{
		ProfileEvidenceDigest: profileReport.EvidenceDigest,
		NetworkEvidenceDigest: network.EvidenceDigest,
	}, nil
}

func exactDynamicCompletedCases(completed []conformance.CaseID) bool {
	required := conformance.RequiredCases()
	if len(required) < 2 || len(completed) != len(required)-1 {
		return false
	}
	for index := range completed {
		if completed[index] != required[index] {
			return false
		}
	}
	return required[len(required)-1] ==
		conformance.CaseActualGitHubTransport
}

func profileObservationFromTarget(
	profileID string,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
	capabilities hostruntime.CapabilitySets,
	isolation hostruntime.IsolationEvidence,
) (hostruntime.ProfileObservation, error) {
	runtimeProfile, profileOK := runtimeProfileFromTarget(profileID)
	if !profileOK ||
		string(runtimeProfile) != overlay.Target.ProfileID ||
		uint64(static.HostFacts.EUID) > uint64(math.MaxInt) ||
		static.HostFacts.OperatingSystem != "linux" ||
		static.HostFacts.OperatingSystem != overlay.Target.OS ||
		static.HostFacts.Architecture != overlay.Target.Architecture ||
		uint64(static.HostFacts.EUID) != overlay.Target.ExpectedEUID ||
		!validStaticDockerInfo(static.DockerInfo) {
		return hostruntime.ProfileObservation{}, ErrFixtureStart
	}
	memory, err := runnerSizingFromTargetOverlay(
		overlay.Resources.RunnerSizing,
	)
	if err != nil {
		return hostruntime.ProfileObservation{}, ErrFixtureStart
	}
	conntrack, err := conntrackFromTargetOverlay(
		overlay.Resources.Conntrack,
	)
	if err != nil {
		return hostruntime.ProfileObservation{}, ErrFixtureStart
	}
	storage, err := storageFromTargetOverlay(
		overlay.Resources.Storage,
	)
	if err != nil {
		return hostruntime.ProfileObservation{}, ErrFixtureStart
	}
	observation := hostruntime.ProfileObservation{
		Platform: hostruntime.PlatformFacts{
			OS:                   static.HostFacts.OperatingSystem,
			Architecture:         static.HostFacts.Architecture,
			KernelRelease:        static.DockerInfo.KernelVersion,
			RuntimeVersion:       static.DockerInfo.ServerVersion,
			CgroupMemoryEnforced: static.DockerInfo.MemoryLimit,
			CgroupCPUEnforced:    static.DockerInfo.CPUCFS,
			CgroupPIDsEnforced:   static.DockerInfo.PIDsLimit,
		},
		UID:          int(static.HostFacts.EUID),
		Capabilities: capabilities,
		Memory:       memory,
		Conntrack:    conntrack,
		Storage:      storage,
		Isolation:    isolation,
	}
	allowDegraded := runtimeProfile ==
		hostruntime.HostProfileQTSCaplessRoot
	if _, err := hostruntime.EvaluateProfileObservation(
		runtimeProfile,
		allowDegraded,
		observation,
	); err != nil {
		return hostruntime.ProfileObservation{}, ErrFixtureStart
	}
	return observation, nil
}

func runtimeProfileFromTarget(
	value string,
) (hostruntime.HostProfile, bool) {
	switch value {
	case "strict-linux":
		return hostruntime.HostProfileStrictLinux, true
	case "qts-capless-root":
		return hostruntime.HostProfileQTSCaplessRoot, true
	default:
		return "", false
	}
}

func runnerSizingFromTargetOverlay(
	value hostruntime.RunnerSizingOverlay,
) (hostruntime.RunnerSizingTuple, error) {
	cadence, err := time.ParseDuration(
		value.ReclamationObservationCadence,
	)
	if err != nil ||
		cadence <= 0 ||
		cadence.String() != value.ReclamationObservationCadence {
		return hostruntime.RunnerSizingTuple{}, ErrFixtureStart
	}
	result := hostruntime.RunnerSizingTuple{
		OperatorApproved:                value.OperatorApproved,
		RunnerTmpfsBytes:                value.RunnerTmpfsBytes,
		RunnerP99Bytes:                  value.RunnerP99Bytes,
		RunnerMarginBytes:               value.RunnerMarginBytes,
		TmpTmpfsBytes:                   value.TmpTmpfsBytes,
		TmpP99Bytes:                     value.TmpP99Bytes,
		TmpMarginBytes:                  value.TmpMarginBytes,
		ScratchTmpfsBytes:               value.ScratchTmpfsBytes,
		ScratchP99Bytes:                 value.ScratchP99Bytes,
		ScratchMarginBytes:              value.ScratchMarginBytes,
		RunnerCgroupP99Bytes:            value.RunnerCgroupP99Bytes,
		ProcessMarginBytes:              value.ProcessMarginBytes,
		RunnerMemoryBytes:               value.RunnerMemoryBytes,
		SwapLimitConfigured:             value.SwapLimitConfigured,
		SwapLimitBytes:                  value.SwapLimitBytes,
		MaxActiveConcurrency:            value.MaxActiveConcurrency,
		AuxiliarySlotMemoryBytes:        value.AuxiliarySlotMemoryBytes,
		IdleControlPlaneBytes:           value.IdleControlPlaneBytes,
		CandidateBuildAndSmokePeakBytes: value.CandidateBuildAndSmokePeakBytes,
		HostAndGatewayReserveBytes:      value.HostAndGatewayReserveBytes,
		UsableHostMemoryBytes:           value.UsableHostMemoryBytes,
		MeasuredIdleRunnerBytes:         value.MeasuredIdleRunnerBytes,
		ReclamationObservationCadence:   cadence,
		EvidenceRevision:                value.EvidenceRevision,
	}
	if _, err := hostruntime.ValidateRunnerSizing(result); err != nil {
		return hostruntime.RunnerSizingTuple{}, ErrFixtureStart
	}
	return result, nil
}

func conntrackFromTargetOverlay(
	value hostruntime.ConntrackOverlay,
) (hostruntime.ConntrackSizing, error) {
	if value.Timeouts == nil {
		return hostruntime.ConntrackSizing{}, ErrFixtureStart
	}
	result := hostruntime.ConntrackSizing{
		CurrentEntries:          value.CurrentEntries,
		MaximumEntries:          value.MaximumEntries,
		HostReserveEntries:      value.HostReserveEntries,
		MaximumRunnerCapacity:   value.MaximumRunnerCapacity,
		MeasuredJobClassEntries: value.MeasuredJobClassEntries,
		MeasuredDoHClassEntries: value.MeasuredDoHClassEntries,
		JobClassBudget:          value.JobClassBudget,
		DoHClassBudget:          value.DoHClassBudget,
		DialTokenStateRevision:  value.DialTokenStateRevision,
		ConsumeBeforeDial:       value.ConsumeBeforeDial,
		EvidenceRevision:        value.EvidenceRevision,
		EgressBackend:           value.EgressBackend,
	}
	for index, timeout := range value.Timeouts {
		if index > 0 &&
			value.Timeouts[index-1].Name >= timeout.Name {
			return hostruntime.ConntrackSizing{}, ErrFixtureStart
		}
		result.Timeouts = append(
			result.Timeouts,
			hostruntime.ConntrackTimeout(timeout),
		)
	}
	if _, err := hostruntime.ValidateConntrackSizing(result); err != nil {
		return hostruntime.ConntrackSizing{}, ErrFixtureStart
	}
	return result, nil
}

func storageFromTargetOverlay(
	value hostruntime.StorageSizingOverlay,
) (hostruntime.StorageSizing, error) {
	roles := [...]hostruntime.StorageRole{
		hostruntime.StorageRoleDockerRoot,
		hostruntime.StorageRoleState,
		hostruntime.StorageRoleStaging,
		hostruntime.StorageRoleRollback,
		hostruntime.StorageRoleScratch,
		hostruntime.StorageRoleLogs,
	}
	if len(value.Observations) != len(roles) ||
		len(value.Requirements) != len(roles) {
		return hostruntime.StorageSizing{}, ErrFixtureStart
	}
	result := hostruntime.StorageSizing{
		MaximumActiveConcurrency: value.MaximumActiveConcurrency,
		LogBounds: hostruntime.LogBounds{
			UsedBytes: value.LogBounds.UsedBytes,
			MaxBytes:  value.LogBounds.MaxBytes,
			UsedFiles: value.LogBounds.UsedFiles,
			MaxFiles:  value.LogBounds.MaxFiles,
		},
		EvidenceRevision: value.EvidenceRevision,
	}
	for index, value := range value.Observations {
		if value.Role != string(roles[index]) {
			return hostruntime.StorageSizing{}, ErrFixtureStart
		}
		result.Observations = append(
			result.Observations,
			hostruntime.StorageObservation{
				Role: hostruntime.StorageRole(value.Role),
				Filesystem: hostruntime.FilesystemIdentity{
					Device: value.Device,
					Inode:  value.Inode,
				},
				FreeBytes:  value.FreeBytes,
				FreeInodes: value.FreeInodes,
			},
		)
	}
	for index, value := range value.Requirements {
		if value.Role != string(roles[index]) {
			return hostruntime.StorageSizing{}, ErrFixtureStart
		}
		result.Requirements = append(
			result.Requirements,
			hostruntime.StorageRequirement{
				Role:                   hostruntime.StorageRole(value.Role),
				CurrentReleaseBytes:    value.CurrentReleaseBytes,
				CurrentReleaseInodes:   value.CurrentReleaseInodes,
				CandidateReleaseBytes:  value.CandidateReleaseBytes,
				CandidateReleaseInodes: value.CandidateReleaseInodes,
				ExtractionBytes:        value.ExtractionBytes,
				ExtractionInodes:       value.ExtractionInodes,
				RollbackBytes:          value.RollbackBytes,
				RollbackInodes:         value.RollbackInodes,
				PerSlotBytes:           value.PerSlotBytes,
				PerSlotInodes:          value.PerSlotInodes,
				HelperBytes:            value.HelperBytes,
				HelperInodes:           value.HelperInodes,
				RelayBytes:             value.RelayBytes,
				RelayInodes:            value.RelayInodes,
				ControllerBytes:        value.ControllerBytes,
				ControllerInodes:       value.ControllerInodes,
				LedgerBytes:            value.LedgerBytes,
				LedgerInodes:           value.LedgerInodes,
				LogBytes:               value.LogBytes,
				LogInodes:              value.LogInodes,
				HostReserveBytes:       value.HostReserveBytes,
				HostReserveInodes:      value.HostReserveInodes,
				StopReserveBytes:       value.StopReserveBytes,
				StopReserveInodes:      value.StopReserveInodes,
				WarningReserveBytes:    value.WarningReserveBytes,
				WarningReserveInodes:   value.WarningReserveInodes,
			},
		)
	}
	if _, err := hostruntime.ValidateStorageSizing(result); err != nil {
		return hostruntime.StorageSizing{}, ErrFixtureStart
	}
	return result, nil
}

var _ fixtureTargetFinalizer = (*dynamicTargetFinalizer)(nil)
