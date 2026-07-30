package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestLoadRuntimeRemainsCompatibleWithoutControllerOverlay(t *testing.T) {
	t.Parallel()

	document := `{"egress_backend":"restricted-broker-v1","ip_family":"public_ipv4_only","secret":{"source":"env","ref":"PORTABLE_GHAR_TEST_SECRET"}}`
	runtime, err := LoadRuntime(strings.NewReader(document))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if runtime.Controller != nil {
		t.Fatalf("LoadRuntime() controller = %#v", runtime.Controller)
	}
}

func TestLoadControllerRuntimeRequiresAndBindsPrivateOverlay(t *testing.T) {
	t.Parallel()

	document := validControllerRuntimeDocument()
	runtime, err := loadControllerRuntimeDocument(t, document)
	if err != nil {
		t.Fatalf("LoadControllerRuntime() error = %v", err)
	}
	overlay, revision, ok := runtime.ControllerPrivateOverlay()
	if !ok ||
		overlay.Resources.FleetConcurrency != runtime.FleetConcurrency ||
		overlay.Resources.NetworkLedgerReserveRows !=
			runtime.NetworkLedgerReserveRows ||
		overlay.Resources.NetworkLedgerReserveBytes !=
			runtime.NetworkLedgerReserveLogicalBytes ||
		len(revision) != 64 {
		t.Fatalf(
			"ControllerPrivateOverlay() = %#v, %q, %t",
			overlay,
			revision,
			ok,
		)
	}

	delete(document, "controller")
	if _, err := loadControllerRuntimeDocument(t, document); err == nil {
		t.Fatal("LoadControllerRuntime() accepted missing controller")
	}
}

func TestLoadControllerRuntimeRejectsNestedUnknownAndCrossFieldDrift(t *testing.T) {
	t.Parallel()

	tests := map[string]func(map[string]any){
		"unknown nested": func(document map[string]any) {
			controller := controllerOverlayMap(t, document)
			controller["unknown"] = true
			document["controller"] = controller
		},
		"fleet concurrency drift": func(document map[string]any) {
			document["fleet_concurrency"] = uint64(5)
		},
		"network row reserve drift": func(document map[string]any) {
			document["network_ledger_reserve_rows"] = uint64(11)
		},
		"history drift": func(document map[string]any) {
			document["history"].(map[string]any)["max_history_rows"] = uint64(255)
		},
		"egress drift": func(document map[string]any) {
			controller := controllerOverlayMap(t, document)
			docker := controller["docker"].(map[string]any)
			docker["broker_network_id"] = "wrong"
			document["controller"] = controller
		},
		"secret drift": func(document map[string]any) {
			document["secret"] = map[string]any{
				"source": "env",
				"ref":    "OTHER_SECRET",
			}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := validControllerRuntimeDocument()
			mutate(document)
			if _, err := loadControllerRuntimeDocument(t, document); err == nil {
				t.Fatal("LoadControllerRuntime() accepted drift")
			}
		})
	}
}

func controllerOverlayMap(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(document["controller"])
	if err != nil {
		t.Fatalf("json.Marshal(controller) error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(controller) error = %v", err)
	}
	return decoded
}

func validControllerPrivateOverlay() hostruntime.PrivateOverlay {
	vector := hostruntime.ResourceVectorOverlay{
		MilliCPU:          100,
		MemoryBytes:       1024,
		PIDs:              8,
		FileDescriptors:   16,
		TmpfsBytes:        512,
		ScratchBytes:      512,
		SocketStateBytes:  128,
		DurableStateBytes: 256,
		Inodes:            16,
	}
	slot := hostruntime.SlotResourcesOverlay{
		Runner:            vector,
		Adapter:           vector,
		Broker:            vector,
		DialAuthority:     vector,
		Helper:            vector,
		Verifier:          vector,
		WorkflowToolProbe: vector,
	}
	roles := []string{
		"docker-root",
		"state",
		"staging",
		"rollback",
		"scratch",
		"logs",
	}
	observations := make([]hostruntime.StorageObservationOverlay, 0, len(roles))
	requirements := make([]hostruntime.StorageRequirementOverlay, 0, len(roles))
	for index, role := range roles {
		observations = append(observations, hostruntime.StorageObservationOverlay{
			Role:       role,
			Device:     uint64(index + 1),
			Inode:      uint64(index + 11),
			FreeBytes:  1 << 30,
			FreeInodes: 1 << 20,
		})
		requirements = append(requirements, hostruntime.StorageRequirementOverlay{
			Role:                   role,
			CurrentReleaseBytes:    1,
			CurrentReleaseInodes:   1,
			CandidateReleaseBytes:  1,
			CandidateReleaseInodes: 1,
			ExtractionBytes:        1,
			ExtractionInodes:       1,
			RollbackBytes:          1,
			RollbackInodes:         1,
			PerSlotBytes:           1,
			PerSlotInodes:          1,
			HelperBytes:            1,
			HelperInodes:           1,
			RelayBytes:             1,
			RelayInodes:            1,
			ControllerBytes:        1,
			ControllerInodes:       1,
			LedgerBytes:            1,
			LedgerInodes:           1,
			LogBytes:               1,
			LogInodes:              1,
			HostReserveBytes:       1,
			HostReserveInodes:      1,
			StopReserveBytes:       1,
			StopReserveInodes:      1,
			WarningReserveBytes:    2,
			WarningReserveInodes:   2,
		})
	}
	return hostruntime.PrivateOverlay{
		SchemaVersion: 1,
		Target: hostruntime.TargetIdentityOverlay{
			OS:                        "linux",
			Architecture:              "amd64",
			ExpectedEUID:              0,
			HostIdentityDigest:        strings.Repeat("1", 64),
			ControlHostIdentityDigest: strings.Repeat("2", 64),
			ProfileID:                 "qts-capless-root",
			OwnerID:                   "portable-owner",
			DegradedAcknowledged:      true,
		},
		Manifest: hostruntime.ManifestOverlay{
			Path:   "/opt/portable/manifest.json",
			Digest: strings.Repeat("a", 64),
		},
		Paths: hostruntime.PathOverlay{
			StateRoot:        "/opt/portable/state",
			ReleaseRoot:      "/opt/portable/releases",
			StagingRoot:      "/opt/portable/staging",
			RollbackRoot:     "/opt/portable/rollback",
			ScratchRoot:      "/opt/portable/scratch",
			LogRoot:          "/opt/portable/logs",
			FenceRoot:        "/opt/portable/fence",
			JournalRoot:      "/opt/portable/journal",
			ReceiptRoot:      "/opt/portable/receipts",
			ReservationRoot:  "/opt/portable/reservations",
			DatabasePath:     "/opt/portable/state/controller.db",
			AdminSocketPath:  "/opt/portable/state/admin.sock",
			HealthSocketPath: "/opt/portable/state/health.sock",
			BrokerRoot:       "/opt/portable/broker",
			SeccompRoot:      "/opt/portable/seccomp",
			PolicyPath:       "/opt/portable/policy.json",
			TrustLockPath:    "/opt/portable/trust.lock",
			LegacyRoot:       "/opt/portable/legacy",
		},
		Commands: hostruntime.CommandOverlay{
			DockerBinary:      "/usr/local/bin/docker",
			ControllerBinary:  "/opt/portable/bin/portable-ghar-controller",
			WatchdogBinary:    "/opt/portable/bin/portable-ghar-watchdog",
			HostRuntimeBinary: "/opt/portable/bin/portable-ghar",
			LegacyFenceBinary: "/opt/portable/bin/run-legacy-fenced",
		},
		Docker: hostruntime.DockerOverlay{
			BrokerNetworkID:    "restricted-broker-v1",
			RunnerNetworkMode:  "none",
			RunnerImage:        configImmutableImage("runner", "3"),
			AdapterImage:       configImmutableImage("adapter", "4"),
			BrokerImage:        configImmutableImage("broker", "5"),
			HelperImage:        configImmutableImage("helper", "6"),
			VerifierImage:      configImmutableImage("verifier", "7"),
			ImmutableBuildMode: "attested-pull",
		},
		Resources: hostruntime.ResourceOverlay{
			AdmissionCeiling: vector,
			SlotResources:    slot,
			ContainerSwap: hostruntime.ContainerSwapOverlay{
				Adapter: hostruntime.SwapLimitOverlay{
					Configured: true,
				},
				Broker: hostruntime.SwapLimitOverlay{
					Configured: true,
				},
				Helper: hostruntime.SwapLimitOverlay{
					Configured: true,
				},
				Verifier: hostruntime.SwapLimitOverlay{
					Configured: true,
				},
				WorkflowToolProbe: hostruntime.SwapLimitOverlay{
					Configured: true,
				},
			},
			MaxCapacity:               6,
			MaxLiveReferences:         16,
			MaxOfferLogicalBytes:      1024,
			MaxLiveOfferLogicalBytes:  16384,
			TransientMode:             "serialized",
			PolicyRevision:            1,
			FleetConcurrency:          6,
			NetworkLedgerReserveRows:  12,
			NetworkLedgerReserveBytes: 4096,
			History: hostruntime.HistoryOverlay{
				MinRetention:                 "24h0m0s",
				MaxHistoryRows:               256,
				MaxHistoryLogicalBytes:       1 << 20,
				MaxNetworkLedgerRows:         64,
				MaxNetworkLedgerLogicalBytes: 1 << 18,
				InflightReserveRows:          8,
				InflightReserveLogicalBytes:  1 << 14,
				GCBatchRows:                  16,
				NetworkGCBatchRows:           8,
				VacuumBatchPages:             4,
				MaintenanceCadence:           "1m0s",
			},
			RunnerSizing: hostruntime.RunnerSizingOverlay{
				OperatorApproved:                true,
				RunnerTmpfsBytes:                3072,
				RunnerP99Bytes:                  2162,
				RunnerMarginBytes:               512,
				TmpTmpfsBytes:                   1024,
				TmpP99Bytes:                     512,
				TmpMarginBytes:                  256,
				ScratchTmpfsBytes:               1024,
				ScratchP99Bytes:                 512,
				ScratchMarginBytes:              256,
				RunnerCgroupP99Bytes:            2162,
				ProcessMarginBytes:              512,
				RunnerMemoryBytes:               8192,
				SwapLimitConfigured:             true,
				SwapLimitBytes:                  1024,
				MaxActiveConcurrency:            6,
				AuxiliarySlotMemoryBytes:        512,
				IdleControlPlaneBytes:           1024,
				CandidateBuildAndSmokePeakBytes: 1024,
				HostAndGatewayReserveBytes:      4096,
				UsableHostMemoryBytes:           65536,
				MeasuredIdleRunnerBytes:         666,
				ReclamationObservationCadence:   "1m0s",
				EvidenceRevision:                "evidence-v1",
			},
			Conntrack: hostruntime.ConntrackOverlay{
				CurrentEntries:          10,
				MaximumEntries:          10000,
				HostReserveEntries:      100,
				MaximumRunnerCapacity:   6,
				MeasuredJobClassEntries: 10,
				MeasuredDoHClassEntries: 5,
				JobClassBudget:          20,
				DoHClassBudget:          10,
				Timeouts: []hostruntime.ConntrackTimeoutOverlay{
					{Name: "established", Seconds: 60},
				},
				DialTokenStateRevision: "dial-v1",
				ConsumeBeforeDial:      true,
				EvidenceRevision:       "evidence-v1",
				EgressBackend:          "restricted-broker-v1",
			},
			Storage: hostruntime.StorageSizingOverlay{
				MaximumActiveConcurrency: 6,
				Observations:             observations,
				Requirements:             requirements,
				LogBounds: hostruntime.LogBoundsOverlay{
					UsedBytes: 1,
					MaxBytes:  1024,
					UsedFiles: 1,
					MaxFiles:  10,
				},
				EvidenceRevision: "evidence-v1",
			},
		},
		Repositories: []hostruntime.RepositoryOverlay{{
			Alias:          "repo-a",
			ConfigURL:      "https://github.com/example/repo-a",
			ScaleSetName:   "portable-repo-a",
			Eligibility:    "active",
			Weight:         1,
			MaxConcurrency: 6,
			AgingThreshold: "1m0s",
			CredentialName: "github",
			SlotResources:  slot,
		}},
		Policy: hostruntime.PolicyOverlay{
			ManifestDigest:      strings.Repeat("8", 64),
			CompiledGraphDigest: strings.Repeat("9", 64),
			AcquisitionDefault:  "disabled",
		},
		Controller: hostruntime.ControllerTimingOverlay{
			AckTimeout:            "1s",
			OperationTimeout:      "2s",
			PollCycleTimeout:      "3s",
			ReconciliationTimeout: "4s",
			PollCadence:           "5s",
			ReconciliationCadence: "6s",
			DrainPollCadence:      "7s",
			ShutdownTimeout:       "8s",
			SessionCloseTimeout:   "7s",
			TransitionJoinTimeout: "6s",
			DurableFinishTimeout:  "5s",
			ReplayEvidenceMaxAge:  "12s",
			HostCapacityMaxAge:    "13s",
			PollLeaseTTL:          "14s",
			LedgerTail:            "15s",
		},
		Fence: hostruntime.FenceTimingOverlay{
			LockPollInterval: "10ms",
			RenewalInterval:  "1s",
			RenewalTimeout:   "2s",
		},
		Health: hostruntime.HealthOverlay{
			Sink:              "local-closed-v1",
			MaxDocumentBytes:  4096,
			ObservationMaxAge: "5s",
		},
		Profile: hostruntime.ProfileOverlay{
			ConformanceEvidenceDigest: strings.Repeat("a", 64),
			NetworkEvidenceDigest:     strings.Repeat("b", 64),
			PlatformEvidenceRevision:  "platform-v1",
		},
		Watchdog: hostruntime.WatchdogOverlay{
			Cadence:         "30s",
			RestartDeadline: "1m0s",
			ProcessGrace:    "5s",
			HealthMaxAge:    "10s",
			Logs: hostruntime.LogPolicyOverlay{
				MaxBytes: 1024,
				MaxFiles: 10,
				MaxAge:   "1h0m0s",
			},
		},
		ManagementTransport: hostruntime.ManagementTransportOverlay{
			Mode:              "openssh-subsystem-v1",
			OpenSSHBinary:     "/usr/bin/ssh",
			Host:              "rhonas.example",
			Port:              22,
			User:              "portable_ghar",
			KnownHostsFile:    "/Users/control/.ssh/known_hosts",
			CredentialName:    "ssh-control",
			ControlUID:        501,
			Subsystem:         "portable-ghar-v1",
			ConnectionTimeout: "5s",
			OperationTimeout:  "30s",
		},
		Secrets: []hostruntime.NamedSecretRef{
			{
				Name: "github",
				Ref: hostruntime.SecretRefOverlay{
					Source: "env",
					Ref:    "PORTABLE_GHAR_TEST_SECRET",
				},
			},
			{
				Name: "ssh-control",
				Ref: hostruntime.SecretRefOverlay{
					Source: "file",
					Ref:    "/Users/control/.ssh/id_ed25519",
				},
			},
		},
		Legacy: nil,
		AllowedActions: []string{
			"install",
			"resume",
			"rollback",
			"suspend",
			"uninstall",
			"verify",
		},
	}
}

func configImmutableImage(name, digit string) string {
	return "example.invalid/portable/" + name + "@sha256:" +
		strings.Repeat(digit, 64)
}
