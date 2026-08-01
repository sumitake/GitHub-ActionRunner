package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"path/filepath"
	"regexp"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

const (
	runnerRequestIdentityDomain = "portable-ghar.task11.runner-request-id.v1\x00"
	capacitySlotIdentityDomain  = "portable-ghar.task11.capacity-slot-id.v1\x00"
	jobGenerationIdentityDomain = "portable-ghar.task11.job-generation.v1\x00"
	slotIdentityDomain          = "portable-ghar.task11.slot-identity.v1\x00"
	adapterNameIdentityDomain   = "portable-ghar.task11.adapter-name.v1\x00"
	brokerNameIdentityDomain    = "portable-ghar.task11.broker-name.v1\x00"
	runnerNameIdentityDomain    = "portable-ghar.task11.runner-name.v1\x00"
	oneShotMinimumMemoryBytes   = uint64(64 << 10)
	maxCompositionDockerCPU     = uint64(math.MaxInt64 / 1_000_000)
)

var compositionContainerNamePattern = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`,
)

type dialAuthorityComposition struct {
	ReservationBlockSize uint64
	MaximumClients       uint32
	Timeout              time.Duration
}

type dockerLogComposition struct {
	Bytes      uint64
	Files      uint64
	FleetBytes uint64
	FleetFiles uint64
}

type compositionIdentity struct {
	RunnerRequestID int64
	CapacitySlotID  uint32
	JobGeneration   uint64
	SlotIdentity    string
	AdapterName     string
	BrokerName      string
	RunnerName      string
}

type runtimeLimitComposition struct {
	Adapter           hostruntime.ContainerLimits
	Broker            hostruntime.BrokerLimits
	Runner            hostruntime.RunnerLimits
	Helper            hostruntime.OneShotLimits
	Verifier          hostruntime.OneShotLimits
	WorkflowToolProbe workflowToolProbeLimits
}

type workflowToolProbeLimits struct {
	MilliCPU        uint64
	MemoryBytes     uint64
	MemorySwapBytes uint64
	PIDs            uint64
	FileDescriptors uint64
	WorkTmpfsBytes  uint64
	ScratchBytes    uint64
}

type compositionPlan struct {
	Identity          compositionIdentity
	CommandRunner     *hostruntime.ExecCommandRunner
	HistoryLimits     state.HistoryLimits
	Authority         dialAuthorityComposition
	Logs              dockerLogComposition
	RuntimeLimits     runtimeLimitComposition
	AssignmentKey     controller.AssignmentKey
	ConntrackInput    networkjail.Budget
	MaxRunnerCapacity uint64
}

type runtimeSpecComposition struct {
	Adapter  hostruntime.AdapterSpec
	Broker   hostruntime.BrokerSpec
	Runner   hostruntime.RunnerSpec
	Verifier hostruntime.VerifierSpec
}

func seedCompositionAssignment(
	ctx context.Context,
	store *state.SQLiteStore,
	plan compositionPlan,
	now time.Time,
) error {
	offer, evidence, err := compositionOfferFrom(plan, now)
	if ctx == nil || store == nil || store.DB() == nil ||
		err != nil || ctx.Err() != nil ||
		plan.Identity.RunnerRequestID <= 0 ||
		plan.Identity.CapacitySlotID == 0 ||
		plan.Identity.SlotIdentity == "" ||
		plan.AssignmentKey.RepositoryAlias !=
			"portable-ghar-conformance" ||
		plan.AssignmentKey.RunnerRequestID !=
			plan.Identity.RunnerRequestID ||
		plan.AssignmentKey.Attempt != 0 {
		return ErrFixtureStart
	}
	receipt, err := store.RecordOffer(ctx, offer, evidence)
	if err != nil ||
		receipt.Disposition != state.OfferInserted ||
		receipt.Key != plan.AssignmentKey ||
		receipt.State != controller.StateReceived {
		return ErrFixtureStart
	}
	if err := store.Reserve(
		ctx,
		plan.AssignmentKey,
		plan.Identity.SlotIdentity,
		plan.Identity.CapacitySlotID,
	); err != nil {
		return ErrFixtureStart
	}
	return nil
}

func compositionOfferFrom(
	plan compositionPlan,
	now time.Time,
) (state.OfferIdentity, state.OfferEvidence, error) {
	if now.IsZero() ||
		plan.AssignmentKey.RepositoryAlias !=
			"portable-ghar-conformance" ||
		plan.AssignmentKey.RunnerRequestID <= 0 ||
		plan.AssignmentKey.RunnerRequestID !=
			plan.Identity.RunnerRequestID ||
		plan.AssignmentKey.Attempt != 0 {
		return state.OfferIdentity{},
			state.OfferEvidence{},
			ErrFixtureStart
	}
	at := now.UTC()
	return state.OfferIdentity{
			RepositoryAlias: plan.AssignmentKey.RepositoryAlias,
			RunnerRequestID: plan.AssignmentKey.RunnerRequestID,
			WorkflowJobID:   plan.AssignmentKey.RunnerRequestID,
			QueueTime:       at,
		}, state.OfferEvidence{
			Kind:       state.EvidenceSelectiveReadback,
			ObservedAt: at,
		}, nil
}

func compositionPlanFrom(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
) (compositionPlan, error) {
	identity, err := deriveCompositionIdentity(input.Authorization.RunID)
	if err != nil {
		return compositionPlan{}, ErrFixtureStart
	}
	commandRunner, err := commandRunnerFromConformanceLimits(input.Limits)
	if err != nil {
		return compositionPlan{}, ErrFixtureStart
	}
	history, err := historyLimitsFromOverlay(overlay.Resources.History)
	if err != nil {
		return compositionPlan{}, ErrFixtureStart
	}
	authority, err := dialAuthorityCompositionFrom(input.Limits, overlay)
	if err != nil {
		return compositionPlan{}, ErrFixtureStart
	}
	logs, err := dockerLogCompositionFrom(input.Limits, overlay)
	if err != nil {
		return compositionPlan{}, ErrFixtureStart
	}
	runtimeLimits, err := runtimeLimitCompositionFrom(overlay, logs)
	if err != nil {
		return compositionPlan{}, ErrFixtureStart
	}
	if !validateLoopbackFlood(input.LoopbackFloodAttempts, input.Limits) ||
		runtimeLimits.Verifier.PIDs <
			loopbackFloodVerifierProcesses ||
		runtimeLimits.Verifier.FileDescriptors <
			loopbackFloodPeakFileDescriptors {
		return compositionPlan{}, ErrFixtureStart
	}
	conntrack := overlay.Resources.Conntrack
	if conntrack.MaximumEntries == 0 ||
		conntrack.CurrentEntries > conntrack.MaximumEntries ||
		conntrack.MaximumRunnerCapacity == 0 ||
		conntrack.MaximumRunnerCapacity > math.MaxUint32 ||
		conntrack.EvidenceRevision == "" {
		return compositionPlan{}, ErrFixtureStart
	}
	return compositionPlan{
		Identity:      identity,
		CommandRunner: commandRunner,
		HistoryLimits: history,
		Authority:     authority,
		Logs:          logs,
		RuntimeLimits: runtimeLimits,
		AssignmentKey: controller.AssignmentKey{
			RepositoryAlias: "portable-ghar-conformance",
			RunnerRequestID: identity.RunnerRequestID,
			Attempt:         0,
		},
		ConntrackInput: networkjail.Budget{
			NFConntrackMax:   conntrack.MaximumEntries,
			NFConntrackCount: conntrack.CurrentEntries,
			TailTimeoutID:    conntrack.EvidenceRevision,
		},
		MaxRunnerCapacity: conntrack.MaximumRunnerCapacity,
	}, nil
}

func runtimeSpecCompositionFrom(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
	seccomp hostruntime.SeccompBinding,
	plan compositionPlan,
	adapter hostruntime.AdapterHandle,
) (runtimeSpecComposition, error) {
	if !isLowerHex(input.Runtime.BuildID, 64) ||
		input.Runtime.BuildID != static.ManifestBuildID ||
		input.Runtime.FleetGeneration == 0 ||
		!validAbsolutePath(input.Fixture.Root) ||
		filepath.Dir(input.Fixture.Root) != overlay.Paths.BrokerRoot ||
		seccomp.Path != input.Runtime.SeccompPath ||
		seccomp.SHA256 != input.Runtime.SeccompDigest ||
		static.RunnerUser == "" ||
		static.AdapterBrokerUser == "" ||
		static.VerifierUser == "" {
		return runtimeSpecComposition{}, ErrFixtureStart
	}
	expectedIdentity, err := deriveCompositionIdentity(
		input.Authorization.RunID,
	)
	if err != nil || expectedIdentity != plan.Identity {
		return runtimeSpecComposition{}, ErrFixtureStart
	}
	adapterUID, _, adapterOK := parseStaticNumericUser(
		static.AdapterBrokerUser,
	)
	verifierUID, _, verifierOK := parseStaticNumericUser(
		static.VerifierUser,
	)
	runnerUID, runnerGID, runnerOK := parseStaticNumericUser(
		static.RunnerUser,
	)
	if !adapterOK || adapterUID == 0 ||
		!verifierOK || verifierUID == 0 ||
		!runnerOK {
		return runtimeSpecComposition{}, ErrFixtureStart
	}
	var profile hostruntime.HostProfile
	switch input.Target.ProfileID {
	case "strict-linux":
		if runnerUID == 0 {
			return runtimeSpecComposition{}, ErrFixtureStart
		}
		profile = hostruntime.HostProfileStrictLinux
	case "qts-capless-root":
		if runnerUID != 0 || runnerGID != 0 {
			return runtimeSpecComposition{}, ErrFixtureStart
		}
		profile = hostruntime.HostProfileQTSCaplessRoot
	default:
		return runtimeSpecComposition{}, ErrFixtureStart
	}
	relayParent := filepath.Join(input.Fixture.Root, "relay")
	authorityParent := filepath.Join(input.Fixture.Root, "authority")
	return runtimeSpecComposition{
		Adapter: hostruntime.AdapterSpec{
			Name:            plan.Identity.AdapterName,
			Image:           input.Images.Adapter.Reference,
			BuildID:         input.Runtime.BuildID,
			FleetGeneration: input.Runtime.FleetGeneration,
			SlotIdentity:    plan.Identity.SlotIdentity,
			BrokerParent:    relayParent,
			User:            static.AdapterBrokerUser,
			Seccomp:         seccomp,
			Limits:          plan.RuntimeLimits.Adapter,
		},
		Broker: hostruntime.BrokerSpec{
			Name:            plan.Identity.BrokerName,
			Image:           input.Images.Broker.Reference,
			HelperImage:     input.Images.Helper.Reference,
			BuildID:         input.Runtime.BuildID,
			FleetGeneration: input.Runtime.FleetGeneration,
			SlotIdentity:    plan.Identity.SlotIdentity,
			CapacitySlotID:  plan.Identity.CapacitySlotID,
			JobGeneration:   plan.Identity.JobGeneration,
			Adapter:         adapter,
			RelayParent:     relayParent,
			AuthorityParent: authorityParent,
			User:            static.AdapterBrokerUser,
			Seccomp:         seccomp,
			Limits:          plan.RuntimeLimits.Broker,
			HelperLimits:    plan.RuntimeLimits.Helper,
		},
		Runner: hostruntime.RunnerSpec{
			Name:            plan.Identity.RunnerName,
			Image:           input.Images.Runner.Reference,
			BuildID:         input.Runtime.BuildID,
			FleetGeneration: input.Runtime.FleetGeneration,
			SlotIdentity:    plan.Identity.SlotIdentity,
			Adapter:         adapter,
			Profile:         profile,
			User:            static.RunnerUser,
			Seccomp:         seccomp,
			Limits:          plan.RuntimeLimits.Runner,
		},
		Verifier: hostruntime.VerifierSpec{
			Image:           input.Images.Verifier.Reference,
			BuildID:         input.Runtime.BuildID,
			FleetGeneration: input.Runtime.FleetGeneration,
			SlotIdentity:    plan.Identity.SlotIdentity,
			Adapter:         adapter,
			User:            static.VerifierUser,
			Seccomp:         seccomp,
			Limits:          plan.RuntimeLimits.Verifier,
		},
	}, nil
}

func deriveCompositionIdentity(runDigest string) (compositionIdentity, error) {
	if !isLowerHex(runDigest, sha256.Size*2) {
		return compositionIdentity{}, ErrFixtureStart
	}
	raw, err := hex.DecodeString(runDigest)
	if err != nil || len(raw) != sha256.Size {
		return compositionIdentity{}, ErrFixtureStart
	}
	requestID, ok := positiveInt64FromHash(
		compositionHash(runnerRequestIdentityDomain, raw),
	)
	if !ok {
		return compositionIdentity{}, ErrFixtureStart
	}
	slotID, ok := positiveUint32FromHash(
		compositionHash(capacitySlotIdentityDomain, raw),
	)
	if !ok {
		return compositionIdentity{}, ErrFixtureStart
	}
	generation, ok := positiveUint64FromHash(
		compositionHash(jobGenerationIdentityDomain, raw),
	)
	if !ok {
		return compositionIdentity{}, ErrFixtureStart
	}
	slotIdentity, ok := compositionName(
		"pghar-slot",
		compositionHash(slotIdentityDomain, raw),
	)
	if !ok {
		return compositionIdentity{}, ErrFixtureStart
	}
	adapterName, ok := compositionName(
		"pghar-adapter",
		compositionHash(adapterNameIdentityDomain, raw),
	)
	if !ok {
		return compositionIdentity{}, ErrFixtureStart
	}
	brokerName, ok := compositionName(
		"pghar-broker",
		compositionHash(brokerNameIdentityDomain, raw),
	)
	if !ok {
		return compositionIdentity{}, ErrFixtureStart
	}
	runnerName, ok := compositionName(
		"pghar-runner",
		compositionHash(runnerNameIdentityDomain, raw),
	)
	if !ok {
		return compositionIdentity{}, ErrFixtureStart
	}
	return compositionIdentity{
		RunnerRequestID: requestID,
		CapacitySlotID:  slotID,
		JobGeneration:   generation,
		SlotIdentity:    slotIdentity,
		AdapterName:     adapterName,
		BrokerName:      brokerName,
		RunnerName:      runnerName,
	}, nil
}

func compositionHash(domain string, runDigest []byte) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write(runDigest)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func positiveInt64FromHash(digest [sha256.Size]byte) (int64, bool) {
	value := binary.BigEndian.Uint64(digest[:8]) & uint64(math.MaxInt64)
	return int64(value), value != 0
}

func positiveUint32FromHash(digest [sha256.Size]byte) (uint32, bool) {
	value := binary.BigEndian.Uint32(digest[:4])
	return value, value != 0
}

func positiveUint64FromHash(digest [sha256.Size]byte) (uint64, bool) {
	value := binary.BigEndian.Uint64(digest[:8])
	return value, value != 0
}

func compositionName(
	prefix string,
	digest [sha256.Size]byte,
) (string, bool) {
	if prefix == "" || digest == ([sha256.Size]byte{}) {
		return "", false
	}
	name := prefix + "-" + hex.EncodeToString(digest[:])[:20]
	return name, compositionContainerNamePattern.MatchString(name)
}

func commandRunnerFromConformanceLimits(
	limits ConformanceLimits,
) (*hostruntime.ExecCommandRunner, error) {
	if limits.MaximumEvidenceBytes == 0 ||
		limits.MaximumEvidenceBytes > uint64(math.MaxInt) ||
		limits.MaximumCommandInputBytes == 0 ||
		limits.MaximumCommandInputBytes > uint64(math.MaxInt) {
		return nil, ErrFixtureStart
	}
	runner := hostruntime.NewExecCommandRunner()
	runner.StdoutLimit = int(limits.MaximumEvidenceBytes)
	runner.StderrLimit = int(limits.MaximumEvidenceBytes)
	runner.StdinLimit = int(limits.MaximumCommandInputBytes)
	return runner, nil
}

func dialAuthorityCompositionFrom(
	limits ConformanceLimits,
	overlay hostruntime.PrivateOverlay,
) (dialAuthorityComposition, error) {
	if limits.DialReservationBlockSize == 0 ||
		limits.DialReservationBlockSize > math.MaxUint32 ||
		limits.DialAuthorityMaximumClients == 0 ||
		limits.DialAuthorityTimeoutMilliseconds == 0 ||
		limits.DialAuthorityTimeoutMilliseconds >
			maxDurationMilliseconds ||
		limits.DialAuthorityTimeoutMilliseconds >
			maxDialAuthorityTimeoutMilliseconds {
		return dialAuthorityComposition{}, ErrFixtureStart
	}
	clients := uint64(limits.DialAuthorityMaximumClients)
	dialResources := overlay.Resources.SlotResources.DialAuthority
	if clients > limits.MaximumProcesses ||
		clients > limits.MaximumFileDescriptors ||
		clients > dialResources.PIDs ||
		clients > dialResources.FileDescriptors {
		return dialAuthorityComposition{}, ErrFixtureStart
	}
	var brokerTimeout uint64
	for _, timeout := range limits.CaseTimeouts {
		if timeout.CaseID == conformance.CaseBrokerEgress {
			brokerTimeout = timeout.TimeoutMilliseconds
			break
		}
	}
	if brokerTimeout == 0 ||
		limits.DialAuthorityTimeoutMilliseconds > brokerTimeout {
		return dialAuthorityComposition{}, ErrFixtureStart
	}
	return dialAuthorityComposition{
		ReservationBlockSize: limits.DialReservationBlockSize,
		MaximumClients:       limits.DialAuthorityMaximumClients,
		Timeout: time.Duration(
			limits.DialAuthorityTimeoutMilliseconds,
		) * time.Millisecond,
	}, nil
}

func dockerLogCompositionFrom(
	limits ConformanceLimits,
	overlay hostruntime.PrivateOverlay,
) (dockerLogComposition, error) {
	if limits.DockerLogMaximumBytes == 0 ||
		limits.DockerLogMaximumFiles == 0 ||
		limits.MaximumLogBytes == 0 {
		return dockerLogComposition{}, ErrFixtureStart
	}
	perContainerBytes, ok := checkedMultiplyLimit(
		limits.DockerLogMaximumBytes,
		limits.DockerLogMaximumFiles,
	)
	if !ok {
		return dockerLogComposition{}, ErrFixtureStart
	}
	fleetBytes, ok := checkedMultiplyLimit(
		perContainerBytes,
		uint64(len(longLivedLogEmitters)),
	)
	if !ok || fleetBytes > limits.MaximumLogBytes {
		return dockerLogComposition{}, ErrFixtureStart
	}
	fleetFiles, ok := checkedMultiplyLimit(
		limits.DockerLogMaximumFiles,
		uint64(len(longLivedLogEmitters)),
	)
	if !ok {
		return dockerLogComposition{}, ErrFixtureStart
	}
	bounds := overlay.Resources.Storage.LogBounds
	if bounds.MaxBytes == 0 ||
		bounds.MaxFiles == 0 ||
		bounds.UsedBytes > bounds.MaxBytes ||
		bounds.UsedFiles > bounds.MaxFiles ||
		fleetBytes > bounds.MaxBytes-bounds.UsedBytes ||
		fleetFiles > bounds.MaxFiles-bounds.UsedFiles {
		return dockerLogComposition{}, ErrFixtureStart
	}
	return dockerLogComposition{
		Bytes:      limits.DockerLogMaximumBytes,
		Files:      limits.DockerLogMaximumFiles,
		FleetBytes: fleetBytes,
		FleetFiles: fleetFiles,
	}, nil
}

func runtimeLimitCompositionFrom(
	overlay hostruntime.PrivateOverlay,
	logs dockerLogComposition,
) (runtimeLimitComposition, error) {
	if logs.Bytes == 0 || logs.Files == 0 {
		return runtimeLimitComposition{}, ErrFixtureStart
	}
	slot := overlay.Resources.SlotResources
	sizing := overlay.Resources.RunnerSizing
	adapterMemorySwap, adapterSwapOK := compositionMemorySwap(
		slot.Adapter.MemoryBytes,
		overlay.Resources.ContainerSwap.Adapter,
	)
	brokerMemorySwap, brokerSwapOK := compositionMemorySwap(
		slot.Broker.MemoryBytes,
		overlay.Resources.ContainerSwap.Broker,
	)
	runnerMemorySwap, runnerSwapOK := compositionMemorySwap(
		sizing.RunnerMemoryBytes,
		hostruntime.SwapLimitOverlay{
			Configured: sizing.SwapLimitConfigured,
			Bytes:      sizing.SwapLimitBytes,
		},
	)
	helperMemorySwap, helperSwapOK := compositionMemorySwap(
		slot.Helper.MemoryBytes,
		overlay.Resources.ContainerSwap.Helper,
	)
	verifierMemorySwap, verifierSwapOK := compositionMemorySwap(
		slot.Verifier.MemoryBytes,
		overlay.Resources.ContainerSwap.Verifier,
	)
	workflowToolMemorySwap, workflowToolSwapOK := compositionMemorySwap(
		slot.WorkflowToolProbe.MemoryBytes,
		overlay.Resources.ContainerSwap.WorkflowToolProbe,
	)
	if !validDockerVector(slot.Adapter) ||
		!validDockerVector(slot.Broker) ||
		!validDockerVector(slot.Runner) ||
		!validDockerVector(slot.Helper) ||
		!validDockerVector(slot.Verifier) ||
		!validDockerVector(slot.WorkflowToolProbe) ||
		!adapterSwapOK ||
		!brokerSwapOK ||
		!runnerSwapOK ||
		!helperSwapOK ||
		!verifierSwapOK ||
		!workflowToolSwapOK ||
		!compositionSumFits(
			slot.Adapter.MemoryBytes,
			slot.Adapter.TmpfsBytes,
			slot.Adapter.ScratchBytes,
		) ||
		!compositionSumFits(
			slot.Broker.MemoryBytes,
			slot.Broker.TmpfsBytes,
			slot.Broker.ScratchBytes,
		) ||
		slot.Helper.MemoryBytes < oneShotMinimumMemoryBytes ||
		slot.Verifier.MemoryBytes < oneShotMinimumMemoryBytes ||
		slot.Runner.MemoryBytes != sizing.RunnerMemoryBytes ||
		slot.Runner.TmpfsBytes != sizing.RunnerTmpfsBytes ||
		slot.Runner.ScratchBytes != sizing.ScratchTmpfsBytes ||
		sizing.RunnerMemoryBytes == 0 ||
		sizing.RunnerTmpfsBytes == 0 ||
		sizing.TmpTmpfsBytes == 0 ||
		sizing.ScratchTmpfsBytes == 0 ||
		sizing.ProcessMarginBytes == 0 ||
		!compositionSumFits(
			sizing.RunnerMemoryBytes,
			sizing.RunnerTmpfsBytes,
			sizing.TmpTmpfsBytes,
			sizing.ScratchTmpfsBytes,
			sizing.ProcessMarginBytes,
		) {
		return runtimeLimitComposition{}, ErrFixtureStart
	}
	return runtimeLimitComposition{
		Adapter: hostruntime.ContainerLimits{
			MilliCPU:        slot.Adapter.MilliCPU,
			MemoryBytes:     slot.Adapter.MemoryBytes,
			MemorySwapBytes: adapterMemorySwap,
			PIDs:            slot.Adapter.PIDs,
			FileDescriptors: slot.Adapter.FileDescriptors,
			TmpfsBytes:      slot.Adapter.TmpfsBytes,
			ScratchBytes:    slot.Adapter.ScratchBytes,
			LogBytes:        logs.Bytes,
			LogFiles:        logs.Files,
		},
		Broker: hostruntime.BrokerLimits{
			MilliCPU:        slot.Broker.MilliCPU,
			MemoryBytes:     slot.Broker.MemoryBytes,
			MemorySwapBytes: brokerMemorySwap,
			PIDs:            slot.Broker.PIDs,
			FileDescriptors: slot.Broker.FileDescriptors,
			StateBytes:      slot.Broker.TmpfsBytes,
			ScratchBytes:    slot.Broker.ScratchBytes,
			LogBytes:        logs.Bytes,
			LogFiles:        logs.Files,
		},
		Runner: hostruntime.RunnerLimits{
			MilliCPU:           slot.Runner.MilliCPU,
			MemoryBytes:        sizing.RunnerMemoryBytes,
			MemorySwapBytes:    runnerMemorySwap,
			PIDs:               slot.Runner.PIDs,
			FileDescriptors:    slot.Runner.FileDescriptors,
			ScratchBytes:       sizing.ScratchTmpfsBytes,
			LogBytes:           logs.Bytes,
			LogFiles:           logs.Files,
			RunnerTmpfsBytes:   sizing.RunnerTmpfsBytes,
			TmpTmpfsBytes:      sizing.TmpTmpfsBytes,
			ProcessMarginBytes: sizing.ProcessMarginBytes,
		},
		Helper: hostruntime.OneShotLimits{
			MilliCPU:        slot.Helper.MilliCPU,
			MemoryBytes:     slot.Helper.MemoryBytes,
			MemorySwapBytes: helperMemorySwap,
			PIDs:            slot.Helper.PIDs,
			FileDescriptors: slot.Helper.FileDescriptors,
		},
		Verifier: hostruntime.OneShotLimits{
			MilliCPU:        slot.Verifier.MilliCPU,
			MemoryBytes:     slot.Verifier.MemoryBytes,
			MemorySwapBytes: verifierMemorySwap,
			PIDs:            slot.Verifier.PIDs,
			FileDescriptors: slot.Verifier.FileDescriptors,
		},
		WorkflowToolProbe: workflowToolProbeLimits{
			MilliCPU:        slot.WorkflowToolProbe.MilliCPU,
			MemoryBytes:     slot.WorkflowToolProbe.MemoryBytes,
			MemorySwapBytes: workflowToolMemorySwap,
			PIDs:            slot.WorkflowToolProbe.PIDs,
			FileDescriptors: slot.WorkflowToolProbe.FileDescriptors,
			WorkTmpfsBytes:  slot.WorkflowToolProbe.TmpfsBytes,
			ScratchBytes:    slot.WorkflowToolProbe.ScratchBytes,
		},
	}, nil
}

func compositionMemorySwap(
	memoryBytes uint64,
	swap hostruntime.SwapLimitOverlay,
) (uint64, bool) {
	if !swap.Configured || memoryBytes == 0 ||
		memoryBytes > uint64(math.MaxInt64) ||
		swap.Bytes > math.MaxUint64-memoryBytes {
		return 0, false
	}
	total := memoryBytes + swap.Bytes
	return total, total <= uint64(math.MaxInt64)
}

func validDockerVector(vector hostruntime.ResourceVectorOverlay) bool {
	return vector.MilliCPU > 0 &&
		vector.MilliCPU <= maxCompositionDockerCPU &&
		vector.MemoryBytes > 0 &&
		vector.MemoryBytes <= uint64(math.MaxInt64) &&
		vector.PIDs > 0 &&
		vector.PIDs <= uint64(math.MaxInt64) &&
		vector.FileDescriptors > 0 &&
		vector.FileDescriptors <= uint64(math.MaxInt64) &&
		vector.TmpfsBytes > 0 &&
		vector.ScratchBytes > 0
}

func compositionSumFits(limit uint64, values ...uint64) bool {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return false
		}
		total += value
	}
	return total <= limit
}

func historyLimitsFromOverlay(
	overlay hostruntime.HistoryOverlay,
) (state.HistoryLimits, error) {
	minRetention, err := time.ParseDuration(overlay.MinRetention)
	if err != nil ||
		minRetention <= 0 ||
		minRetention.String() != overlay.MinRetention {
		return state.HistoryLimits{}, ErrFixtureStart
	}
	maintenanceCadence, err := time.ParseDuration(
		overlay.MaintenanceCadence,
	)
	if err != nil ||
		maintenanceCadence <= 0 ||
		maintenanceCadence.String() != overlay.MaintenanceCadence {
		return state.HistoryLimits{}, ErrFixtureStart
	}
	limits := state.HistoryLimits{
		MinRetention:                 minRetention,
		MaxHistoryRows:               overlay.MaxHistoryRows,
		MaxHistoryLogicalBytes:       overlay.MaxHistoryLogicalBytes,
		MaxNetworkLedgerRows:         overlay.MaxNetworkLedgerRows,
		MaxNetworkLedgerLogicalBytes: overlay.MaxNetworkLedgerLogicalBytes,
		InflightReserveRows:          overlay.InflightReserveRows,
		InflightReserveLogicalBytes:  overlay.InflightReserveLogicalBytes,
		GCBatchRows:                  overlay.GCBatchRows,
		NetworkGCBatchRows:           overlay.NetworkGCBatchRows,
		VacuumBatchPages:             overlay.VacuumBatchPages,
		MaintenanceCadence:           maintenanceCadence,
	}
	if err := state.ValidateHistoryLimits(limits); err != nil {
		return state.HistoryLimits{}, ErrFixtureStart
	}
	return limits, nil
}
