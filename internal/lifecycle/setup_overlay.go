package lifecycle

import (
	"fmt"
	"math"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const (
	// minimumOneShotMemoryBytes is the smallest memory limit a helper or
	// verifier container can start with.
	minimumOneShotMemoryBytes = uint64(64 << 10)
	// maxDockerMilliCPU keeps --cpus representable as Docker's nano-CPUs.
	maxDockerMilliCPU = uint64(math.MaxInt64 / 1_000_000)
)

// SetupConfigFromOverlay builds the production SetupConfig from a validated
// private overlay and its runtime manifest. The caller decodes the policy
// graph and compiles its artifact, since both come from the pinned policy
// file. The overlay must carry a jail section. NewSetupBuilder validates the
// identity, user, and image parts of the result; this checks the limits up
// front so a bad vector fails at startup instead of at the first job.
func SetupConfigFromOverlay(
	overlay hostruntime.PrivateOverlay,
	manifest hostruntime.RuntimeManifest,
	graph networkjail.DecisionGraph,
	policy hostruntime.PolicyArtifact,
) (SetupConfig, error) {
	jail := overlay.Jail
	if jail == nil {
		return SetupConfig{}, fmt.Errorf("%w: overlay has no jail section", ErrLifecycle)
	}
	limits, err := setupLimitsFromOverlay(overlay.Resources, *jail)
	if err != nil {
		return SetupConfig{}, err
	}
	conntrack := overlay.Resources.Conntrack
	return SetupConfig{
		BuildID:         manifest.BuildID,
		FleetGeneration: manifest.FleetGeneration,
		BrokerRoot:      overlay.Paths.BrokerRoot,
		Profile:         hostruntime.HostProfile(overlay.Target.ProfileID),
		Images: SetupImages{
			Adapter:  overlay.Docker.AdapterImage,
			Broker:   overlay.Docker.BrokerImage,
			Helper:   overlay.Docker.HelperImage,
			Runner:   overlay.Docker.RunnerImage,
			Verifier: overlay.Docker.VerifierImage,
		},
		Users: SetupUsers{
			AdapterBroker: jail.AdapterBrokerUser,
			Runner:        jail.RunnerUser,
			Verifier:      jail.VerifierUser,
		},
		Seccomp: hostruntime.SeccompBinding{
			Path:   jail.SeccompProfilePath,
			SHA256: manifest.SeccompProfileDigest,
		},
		Limits: limits,
		Graph:  graph,
		Policy: policy,
		ConntrackInput: networkjail.Budget{
			NFConntrackMax:   conntrack.MaximumEntries,
			NFConntrackCount: conntrack.CurrentEntries,
			TailTimeoutID:    conntrack.EvidenceRevision,
		},
		MaxRunnerCapacity: conntrack.MaximumRunnerCapacity,
	}, nil
}

// setupLimitsFromOverlay maps the slot resource vectors, runner sizing, and
// swap allowances to per-container limits. The runner's vector must agree
// with its sizing, and each tmpfs is charged inside its container's memory.
func setupLimitsFromOverlay(
	resources hostruntime.ResourceOverlay,
	jail hostruntime.JailOverlay,
) (SetupLimits, error) {
	slot := resources.SlotResources
	sizing := resources.RunnerSizing
	swap := resources.ContainerSwap
	adapterSwap, adapterOK := memoryWithSwap(slot.Adapter.MemoryBytes, swap.Adapter)
	brokerSwap, brokerOK := memoryWithSwap(slot.Broker.MemoryBytes, swap.Broker)
	helperSwap, helperOK := memoryWithSwap(slot.Helper.MemoryBytes, swap.Helper)
	verifierSwap, verifierOK := memoryWithSwap(slot.Verifier.MemoryBytes, swap.Verifier)
	runnerSwap, runnerOK := memoryWithSwap(
		sizing.RunnerMemoryBytes,
		hostruntime.SwapLimitOverlay{
			Configured: sizing.SwapLimitConfigured,
			Bytes:      sizing.SwapLimitBytes,
		},
	)
	if !adapterOK || !brokerOK || !helperOK || !verifierOK || !runnerOK ||
		!validContainerVector(slot.Adapter) ||
		!validContainerVector(slot.Broker) ||
		!validContainerVector(slot.Runner) ||
		!validContainerVector(slot.Helper) ||
		!validContainerVector(slot.Verifier) ||
		!sumFits(slot.Adapter.MemoryBytes, slot.Adapter.TmpfsBytes, slot.Adapter.ScratchBytes) ||
		!sumFits(slot.Broker.MemoryBytes, slot.Broker.TmpfsBytes, slot.Broker.ScratchBytes) ||
		slot.Helper.MemoryBytes < minimumOneShotMemoryBytes ||
		slot.Verifier.MemoryBytes < minimumOneShotMemoryBytes ||
		slot.Runner.MemoryBytes != sizing.RunnerMemoryBytes ||
		slot.Runner.TmpfsBytes != sizing.RunnerTmpfsBytes ||
		slot.Runner.ScratchBytes != sizing.ScratchTmpfsBytes ||
		sizing.TmpTmpfsBytes == 0 ||
		sizing.ProcessMarginBytes == 0 ||
		!sumFits(
			sizing.RunnerMemoryBytes,
			sizing.RunnerTmpfsBytes,
			sizing.TmpTmpfsBytes,
			sizing.ScratchTmpfsBytes,
			sizing.ProcessMarginBytes,
		) ||
		jail.ContainerLogMaxBytes == 0 ||
		jail.ContainerLogMaxFiles == 0 {
		return SetupLimits{}, fmt.Errorf("%w: invalid setup limits", ErrLifecycle)
	}
	logBytes, logFiles := jail.ContainerLogMaxBytes, jail.ContainerLogMaxFiles
	return SetupLimits{
		Adapter: hostruntime.ContainerLimits{
			MilliCPU:        slot.Adapter.MilliCPU,
			MemoryBytes:     slot.Adapter.MemoryBytes,
			MemorySwapBytes: adapterSwap,
			PIDs:            slot.Adapter.PIDs,
			FileDescriptors: slot.Adapter.FileDescriptors,
			TmpfsBytes:      slot.Adapter.TmpfsBytes,
			ScratchBytes:    slot.Adapter.ScratchBytes,
			LogBytes:        logBytes,
			LogFiles:        logFiles,
		},
		Broker: hostruntime.BrokerLimits{
			MilliCPU:        slot.Broker.MilliCPU,
			MemoryBytes:     slot.Broker.MemoryBytes,
			MemorySwapBytes: brokerSwap,
			PIDs:            slot.Broker.PIDs,
			FileDescriptors: slot.Broker.FileDescriptors,
			StateBytes:      slot.Broker.TmpfsBytes,
			ScratchBytes:    slot.Broker.ScratchBytes,
			LogBytes:        logBytes,
			LogFiles:        logFiles,
		},
		Runner: hostruntime.RunnerLimits{
			MilliCPU:           slot.Runner.MilliCPU,
			MemoryBytes:        sizing.RunnerMemoryBytes,
			MemorySwapBytes:    runnerSwap,
			PIDs:               slot.Runner.PIDs,
			FileDescriptors:    slot.Runner.FileDescriptors,
			ScratchBytes:       sizing.ScratchTmpfsBytes,
			LogBytes:           logBytes,
			LogFiles:           logFiles,
			RunnerTmpfsBytes:   sizing.RunnerTmpfsBytes,
			TmpTmpfsBytes:      sizing.TmpTmpfsBytes,
			ProcessMarginBytes: sizing.ProcessMarginBytes,
		},
		Helper: hostruntime.OneShotLimits{
			MilliCPU:        slot.Helper.MilliCPU,
			MemoryBytes:     slot.Helper.MemoryBytes,
			MemorySwapBytes: helperSwap,
			PIDs:            slot.Helper.PIDs,
			FileDescriptors: slot.Helper.FileDescriptors,
		},
		Verifier: hostruntime.OneShotLimits{
			MilliCPU:        slot.Verifier.MilliCPU,
			MemoryBytes:     slot.Verifier.MemoryBytes,
			MemorySwapBytes: verifierSwap,
			PIDs:            slot.Verifier.PIDs,
			FileDescriptors: slot.Verifier.FileDescriptors,
		},
	}, nil
}

// memoryWithSwap returns Docker's --memory-swap value: memory plus the
// allowed swap. Swap must be configured explicitly, even when it is zero.
func memoryWithSwap(memoryBytes uint64, swap hostruntime.SwapLimitOverlay) (uint64, bool) {
	if !swap.Configured || memoryBytes == 0 ||
		memoryBytes > uint64(math.MaxInt64) ||
		swap.Bytes > math.MaxUint64-memoryBytes {
		return 0, false
	}
	total := memoryBytes + swap.Bytes
	return total, total <= uint64(math.MaxInt64)
}

func validContainerVector(vector hostruntime.ResourceVectorOverlay) bool {
	return vector.MilliCPU > 0 &&
		vector.MilliCPU <= maxDockerMilliCPU &&
		vector.MemoryBytes > 0 &&
		vector.MemoryBytes <= uint64(math.MaxInt64) &&
		vector.PIDs > 0 &&
		vector.PIDs <= uint64(math.MaxInt64) &&
		vector.FileDescriptors > 0 &&
		vector.FileDescriptors <= uint64(math.MaxInt64) &&
		vector.TmpfsBytes > 0 &&
		vector.ScratchBytes > 0
}

// sumFits reports whether values sum to at most limit without overflow.
func sumFits(limit uint64, values ...uint64) bool {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return false
		}
		total += value
	}
	return total <= limit
}
