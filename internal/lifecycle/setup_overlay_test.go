package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func testSetupOverlay() (hostruntime.PrivateOverlay, hostruntime.RuntimeManifest) {
	vector := func(memory uint64) hostruntime.ResourceVectorOverlay {
		return hostruntime.ResourceVectorOverlay{
			MilliCPU:        500,
			MemoryBytes:     memory,
			PIDs:            64,
			FileDescriptors: 256,
			TmpfsBytes:      1 << 20,
			ScratchBytes:    1 << 20,
		}
	}
	swap := hostruntime.SwapLimitOverlay{Configured: true, Bytes: 0}
	var overlay hostruntime.PrivateOverlay
	overlay.Target.ProfileID = string(hostruntime.HostProfileStrictLinux)
	overlay.Paths.BrokerRoot = "/var/lib/portable-ghar/broker"
	overlay.Docker = hostruntime.DockerOverlay{
		AdapterImage:  "adapter@sha256:" + strings.Repeat("1", 64),
		BrokerImage:   "broker@sha256:" + strings.Repeat("2", 64),
		HelperImage:   "helper@sha256:" + strings.Repeat("3", 64),
		RunnerImage:   "runner@sha256:" + strings.Repeat("4", 64),
		VerifierImage: "verifier@sha256:" + strings.Repeat("5", 64),
	}
	overlay.Resources.SlotResources = hostruntime.SlotResourcesOverlay{
		Adapter:  vector(64 << 20),
		Broker:   vector(64 << 20),
		Helper:   vector(64 << 20),
		Verifier: vector(64 << 20),
		Runner: hostruntime.ResourceVectorOverlay{
			MilliCPU:        2000,
			MemoryBytes:     4 << 30,
			PIDs:            4096,
			FileDescriptors: 65536,
			TmpfsBytes:      512 << 20,
			ScratchBytes:    256 << 20,
		},
	}
	overlay.Resources.ContainerSwap = hostruntime.ContainerSwapOverlay{
		Adapter: swap, Broker: swap, Helper: swap, Verifier: swap, WorkflowToolProbe: swap,
	}
	overlay.Resources.RunnerSizing = hostruntime.RunnerSizingOverlay{
		RunnerMemoryBytes:   4 << 30,
		RunnerTmpfsBytes:    512 << 20,
		TmpTmpfsBytes:       256 << 20,
		ScratchTmpfsBytes:   256 << 20,
		ProcessMarginBytes:  1 << 30,
		SwapLimitConfigured: true,
		SwapLimitBytes:      1 << 30,
	}
	overlay.Resources.Conntrack = hostruntime.ConntrackOverlay{
		CurrentEntries:        10,
		MaximumEntries:        262144,
		MaximumRunnerCapacity: 1,
		EvidenceRevision:      "tcp_fin_wait",
	}
	overlay.Jail = &hostruntime.JailOverlay{
		AdapterBrokerUser:        "1001:1001",
		RunnerUser:               "1002:1002",
		VerifierUser:             "1003:1003",
		SeccompProfilePath:       "/etc/portable-ghar/seccomp/jail.json",
		ContainerLogMaxBytes:     1 << 20,
		ContainerLogMaxFiles:     2,
		DialReservationBlockSize: 4,
		DialAuthorityMaxClients:  4,
		DialAuthorityTimeout:     "2s",
	}
	manifest := hostruntime.RuntimeManifest{
		BuildID:              strings.Repeat("a", 64),
		FleetGeneration:      3,
		SeccompProfileDigest: strings.Repeat("6", 64),
	}
	return overlay, manifest
}

func TestSetupConfigFromOverlayFeedsTheSetupBuilder(t *testing.T) {
	reference := testSetupConfig(t)
	overlay, manifest := testSetupOverlay()
	config, err := SetupConfigFromOverlay(overlay, manifest, reference.Graph, reference.Policy)
	if err != nil {
		t.Fatalf("SetupConfigFromOverlay: %v", err)
	}
	builder, err := NewSetupBuilder(config)
	if err != nil {
		t.Fatalf("NewSetupBuilder: %v", err)
	}
	assignment := testAssignment(t)
	prepared, _, err := builder.Build(context.Background(), assignment)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := networkjail.ValidatePreparedSetupRequest(prepared); err != nil {
		t.Fatalf("ValidatePreparedSetupRequest: %v", err)
	}

	sizing := overlay.Resources.RunnerSizing
	slot := overlay.Resources.SlotResources
	limits := config.Limits
	if config.Users.Runner != "1002:1002" ||
		config.Seccomp.Path != overlay.Jail.SeccompProfilePath ||
		config.Seccomp.SHA256 != manifest.SeccompProfileDigest ||
		config.Images.Helper != overlay.Docker.HelperImage ||
		config.ConntrackInput.TailTimeoutID != "tcp_fin_wait" ||
		limits.Runner.MemoryBytes != sizing.RunnerMemoryBytes ||
		limits.Runner.MemorySwapBytes != sizing.RunnerMemoryBytes+sizing.SwapLimitBytes ||
		limits.Runner.ScratchBytes != sizing.ScratchTmpfsBytes ||
		limits.Broker.StateBytes != slot.Broker.TmpfsBytes ||
		limits.Adapter.MemorySwapBytes != slot.Adapter.MemoryBytes ||
		limits.Verifier.PIDs != slot.Verifier.PIDs ||
		limits.Broker.LogBytes != overlay.Jail.ContainerLogMaxBytes ||
		limits.Runner.LogFiles != overlay.Jail.ContainerLogMaxFiles {
		t.Fatalf("SetupConfigFromOverlay mapped %+v", config)
	}
}

func TestSetupConfigFromOverlayRejectsBadInputs(t *testing.T) {
	reference := testSetupConfig(t)
	tests := map[string]func(*hostruntime.PrivateOverlay){
		"no jail section": func(overlay *hostruntime.PrivateOverlay) { overlay.Jail = nil },
		"unconfigured swap": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.ContainerSwap.Broker.Configured = false
		},
		"runner vector disagrees with sizing": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.SlotResources.Runner.MemoryBytes++
		},
		"runner tmpfs over memory": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.RunnerSizing.ProcessMarginBytes = 4 << 30
		},
		"adapter tmpfs over memory": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.SlotResources.Adapter.MemoryBytes = 1 << 20
		},
		"helper below the one-shot minimum": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.SlotResources.Helper.MemoryBytes = 1 << 10
		},
		"zero verifier pids": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.SlotResources.Verifier.PIDs = 0
		},
		"zero log files": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Jail.ContainerLogMaxFiles = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			overlay, manifest := testSetupOverlay()
			mutate(&overlay)
			if _, err := SetupConfigFromOverlay(
				overlay, manifest, reference.Graph, reference.Policy,
			); !errors.Is(err, ErrLifecycle) {
				t.Fatalf("SetupConfigFromOverlay error = %v, want ErrLifecycle", err)
			}
		})
	}
}
