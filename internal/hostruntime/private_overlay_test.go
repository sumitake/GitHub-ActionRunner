package hostruntime

import (
	"errors"
	"math"
	"strings"
	"testing"
)

const goldenPrivateOverlayRevision = "1e0755006f66749efedb618696dcc589832bb9f2ba3920f14466a7a5fda1bb75"

func TestPrivateOverlayGolden(t *testing.T) {
	t.Parallel()

	overlay := goldenPrivateOverlay()
	encoded, revision, err := MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	if revision != goldenPrivateOverlayRevision {
		t.Fatalf(
			"MarshalPrivateOverlay() revision = %q, want %q; json=%s",
			revision,
			goldenPrivateOverlayRevision,
			encoded,
		)
	}
	decoded, decodedRevision, err := ParsePrivateOverlay(encoded, len(encoded))
	if err != nil {
		t.Fatalf("ParsePrivateOverlay() error = %v", err)
	}
	if decoded.Target.OS != "linux" ||
		decoded.Target.ExpectedEUID != 0 ||
		decoded.Manifest.Digest != strings.Repeat("a", 64) ||
		decoded.ManagementTransport.Mode != "openssh-subsystem-v1" ||
		decoded.Legacy != nil ||
		decodedRevision != revision {
		t.Fatalf("ParsePrivateOverlay() = %#v, revision=%q", decoded, decodedRevision)
	}
}

func TestPrivateOverlayRejectsNoncanonicalAndIncompleteInputs(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*PrivateOverlay){
		"darwin target": func(overlay *PrivateOverlay) {
			overlay.Target.OS = "darwin"
		},
		"arm64 target": func(overlay *PrivateOverlay) {
			overlay.Target.Architecture = "arm64"
		},
		"same control host": func(overlay *PrivateOverlay) {
			overlay.Target.ControlHostIdentityDigest =
				overlay.Target.HostIdentityDigest
		},
		"relative path": func(overlay *PrivateOverlay) {
			overlay.Paths.StateRoot = "state"
		},
		"mutable image": func(overlay *PrivateOverlay) {
			overlay.Docker.RunnerImage = "example.invalid/runner:latest"
		},
		"noncanonical duration": func(overlay *PrivateOverlay) {
			overlay.Controller.AckTimeout = "1000ms"
		},
		"inline secret source": func(overlay *PrivateOverlay) {
			overlay.Secrets[0].Ref.Source = "inline"
		},
		"unsorted repositories": func(overlay *PrivateOverlay) {
			second := overlay.Repositories[0]
			second.Alias = "a-repo"
			overlay.Repositories = append(overlay.Repositories, second)
		},
		"unknown action": func(overlay *PrivateOverlay) {
			overlay.AllowedActions = []string{"shell"}
		},
		"nil resources": func(overlay *PrivateOverlay) {
			overlay.Resources.Storage.Observations = nil
		},
		"missing workflow tool vector": func(overlay *PrivateOverlay) {
			overlay.Resources.SlotResources.WorkflowToolProbe =
				ResourceVectorOverlay{}
		},
		"adapter swap omitted": func(overlay *PrivateOverlay) {
			overlay.Resources.ContainerSwap.Adapter.Configured = false
		},
		"broker swap omitted": func(overlay *PrivateOverlay) {
			overlay.Resources.ContainerSwap.Broker.Configured = false
		},
		"helper swap omitted": func(overlay *PrivateOverlay) {
			overlay.Resources.ContainerSwap.Helper.Configured = false
		},
		"verifier swap omitted": func(overlay *PrivateOverlay) {
			overlay.Resources.ContainerSwap.Verifier.Configured = false
		},
		"workflow tool swap omitted": func(overlay *PrivateOverlay) {
			overlay.Resources.ContainerSwap.WorkflowToolProbe.Configured =
				false
		},
		"adapter swap total overflow": func(overlay *PrivateOverlay) {
			overlay.Resources.ContainerSwap.Adapter.Bytes = math.MaxUint64
		},
		"runner swap total overflow": func(overlay *PrivateOverlay) {
			overlay.Resources.RunnerSizing.SwapLimitBytes = math.MaxUint64
		},
		"missing management transport": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport = ManagementTransportOverlay{}
		},
		"unknown management mode": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.Mode = "ssh-v2"
		},
		"relative OpenSSH binary": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.OpenSSHBinary = "ssh"
		},
		"ambiguous OpenSSH path": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.OpenSSHBinary = "/usr/bin/ssh wrapper"
		},
		"option-like host": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.Host = "-oProxyCommand=id"
		},
		"noncanonical IP host": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.Host = "127.000.000.001"
		},
		"uppercase DNS host": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.Host = "RhoNAS.example"
		},
		"invalid remote user": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.User = "../root"
		},
		"zero port": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.Port = 0
		},
		"relative known hosts": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.KnownHostsFile = "known_hosts"
		},
		"unicode known hosts path": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.KnownHostsFile =
				"/Users/control/.ssh/known_h\u00f6sts"
		},
		"missing management credential": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.CredentialName = "missing"
		},
		"environment management credential": func(overlay *PrivateOverlay) {
			overlay.Secrets[1].Ref.Source = "env"
			overlay.Secrets[1].Ref.Ref = "SSH_AUTH_SOCK"
		},
		"ambiguous management credential path": func(overlay *PrivateOverlay) {
			overlay.Secrets[1].Ref.Ref =
				"/Users/control/.ssh/id ed25519"
		},
		"shared management credential": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.CredentialName = "github"
		},
		"zero control uid": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.ControlUID = 0
		},
		"unknown subsystem": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.Subsystem = "shell"
		},
		"fractional connection timeout": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.ConnectionTimeout = "500ms"
		},
		"operation timeout not greater": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.OperationTimeout =
				overlay.ManagementTransport.ConnectionTimeout
		},
		"reused transport path": func(overlay *PrivateOverlay) {
			overlay.ManagementTransport.KnownHostsFile =
				overlay.ManagementTransport.OpenSSHBinary
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			overlay := goldenPrivateOverlay()
			mutate(&overlay)
			if _, _, err := MarshalPrivateOverlay(overlay); !errors.Is(err, ErrInvalidPrivateOverlay) {
				t.Fatalf("MarshalPrivateOverlay() error = %v", err)
			}
		})
	}
}

func TestParsePrivateOverlayRejectsUnknownWhitespaceAndNullSection(t *testing.T) {
	t.Parallel()

	encoded, _, err := MarshalPrivateOverlay(goldenPrivateOverlay())
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	tests := map[string][]byte{
		"leading whitespace": append([]byte(" "), encoded...),
		"trailing newline":   append(append([]byte(nil), encoded...), '\n'),
		"unknown field": []byte(strings.TrimSuffix(string(encoded), "}") +
			`,"unknown":true}`),
		"unknown swap field": []byte(strings.Replace(
			string(encoded),
			`"adapter":{"configured":true`,
			`"adapter":{"unknown":0,"configured":true`,
			1,
		)),
		"unknown management field": []byte(strings.Replace(
			string(encoded),
			`"management_transport":{"mode":`,
			`"management_transport":{"unknown":0,"mode":`,
			1,
		)),
		"malformed swap configured": []byte(strings.Replace(
			string(encoded),
			`"helper":{"configured":true`,
			`"helper":{"configured":"true"`,
			1,
		)),
		"null target": []byte(strings.Replace(
			string(encoded),
			`"target":{"os":`,
			`"target":null,"removed":{"os":`,
			1,
		)),
	}
	for name, document := range tests {
		name, document := name, document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParsePrivateOverlay(
				document,
				len(document)+1,
			); !errors.Is(err, ErrInvalidPrivateOverlay) {
				t.Fatalf("ParsePrivateOverlay() error = %v", err)
			}
		})
	}
}

func goldenPrivateOverlay() PrivateOverlay {
	vector := ResourceVectorOverlay{
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
	slot := SlotResourcesOverlay{
		Runner:            vector,
		Adapter:           vector,
		Broker:            vector,
		DialAuthority:     vector,
		Helper:            vector,
		Verifier:          vector,
		WorkflowToolProbe: vector,
	}
	observations := make([]StorageObservationOverlay, 0, len(lifecycleFilesystemRoles))
	requirements := make([]StorageRequirementOverlay, 0, len(lifecycleFilesystemRoles))
	for index, role := range lifecycleFilesystemRoles {
		observations = append(observations, StorageObservationOverlay{
			Role:       role,
			Device:     uint64(index + 1),
			Inode:      uint64(index + 11),
			FreeBytes:  1 << 30,
			FreeInodes: 1 << 20,
		})
		requirements = append(requirements, StorageRequirementOverlay{
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
	return PrivateOverlay{
		SchemaVersion: 1,
		Target: TargetIdentityOverlay{
			OS:                        "linux",
			Architecture:              "amd64",
			ExpectedEUID:              0,
			HostIdentityDigest:        strings.Repeat("1", 64),
			ControlHostIdentityDigest: strings.Repeat("2", 64),
			ProfileID:                 "qts-capless-root",
			OwnerID:                   "portable-owner",
			DegradedAcknowledged:      true,
		},
		Manifest: ManifestOverlay{
			Path:   "/opt/portable/manifest.json",
			Digest: strings.Repeat("a", 64),
		},
		Paths: PathOverlay{
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
		Commands: CommandOverlay{
			DockerBinary:      "/usr/local/bin/docker",
			ControllerBinary:  "/opt/portable/bin/portable-ghar-controller",
			WatchdogBinary:    "/opt/portable/bin/portable-ghar-watchdog",
			HostRuntimeBinary: "/opt/portable/bin/portable-ghar",
			LegacyFenceBinary: "/opt/portable/bin/run-legacy-fenced",
		},
		Docker: DockerOverlay{
			BrokerNetworkID:    "restricted-broker-v1",
			RunnerNetworkMode:  "none",
			RunnerImage:        immutableImage("runner", "3"),
			AdapterImage:       immutableImage("adapter", "4"),
			BrokerImage:        immutableImage("broker", "5"),
			HelperImage:        immutableImage("helper", "6"),
			VerifierImage:      immutableImage("verifier", "7"),
			ImmutableBuildMode: "attested-pull",
		},
		Resources: ResourceOverlay{
			AdmissionCeiling: vector,
			SlotResources:    slot,
			ContainerSwap: ContainerSwapOverlay{
				Adapter: SwapLimitOverlay{
					Configured: true,
					Bytes:      64,
				},
				Broker: SwapLimitOverlay{
					Configured: true,
					Bytes:      64,
				},
				Helper: SwapLimitOverlay{
					Configured: true,
					Bytes:      0,
				},
				Verifier: SwapLimitOverlay{
					Configured: true,
					Bytes:      0,
				},
				WorkflowToolProbe: SwapLimitOverlay{
					Configured: true,
					Bytes:      64,
				},
			},
			MaxCapacity:               2,
			MaxLiveReferences:         8,
			MaxOfferLogicalBytes:      1024,
			MaxLiveOfferLogicalBytes:  8192,
			TransientMode:             "serialized",
			PolicyRevision:            1,
			FleetConcurrency:          2,
			NetworkLedgerReserveRows:  8,
			NetworkLedgerReserveBytes: 8192,
			History: HistoryOverlay{
				MinRetention:                 "1h0m0s",
				MaxHistoryRows:               1000,
				MaxHistoryLogicalBytes:       1 << 20,
				MaxNetworkLedgerRows:         1000,
				MaxNetworkLedgerLogicalBytes: 1 << 20,
				InflightReserveRows:          10,
				InflightReserveLogicalBytes:  1024,
				GCBatchRows:                  10,
				NetworkGCBatchRows:           10,
				VacuumBatchPages:             10,
				MaintenanceCadence:           "1m0s",
			},
			RunnerSizing: RunnerSizingOverlay{
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
				MaxActiveConcurrency:            2,
				AuxiliarySlotMemoryBytes:        512,
				IdleControlPlaneBytes:           1024,
				CandidateBuildAndSmokePeakBytes: 1024,
				HostAndGatewayReserveBytes:      4096,
				UsableHostMemoryBytes:           32768,
				MeasuredIdleRunnerBytes:         666,
				ReclamationObservationCadence:   "1m0s",
				EvidenceRevision:                "evidence-v1",
			},
			Conntrack: ConntrackOverlay{
				CurrentEntries:          10,
				MaximumEntries:          10000,
				HostReserveEntries:      100,
				MaximumRunnerCapacity:   2,
				MeasuredJobClassEntries: 10,
				MeasuredDoHClassEntries: 5,
				JobClassBudget:          20,
				DoHClassBudget:          10,
				Timeouts: []ConntrackTimeoutOverlay{
					{Name: "established", Seconds: 60},
				},
				DialTokenStateRevision: "dial-v1",
				ConsumeBeforeDial:      true,
				EvidenceRevision:       "evidence-v1",
				EgressBackend:          "restricted-broker-v1",
			},
			Storage: StorageSizingOverlay{
				MaximumActiveConcurrency: 2,
				Observations:             observations,
				Requirements:             requirements,
				LogBounds: LogBoundsOverlay{
					UsedBytes: 1,
					MaxBytes:  1024,
					UsedFiles: 1,
					MaxFiles:  10,
				},
				EvidenceRevision: "evidence-v1",
			},
		},
		Repositories: []RepositoryOverlay{
			{
				Alias:          "repo-a",
				ConfigURL:      "https://github.com/example/repo-a",
				ScaleSetName:   "portable-repo-a",
				Eligibility:    "active",
				Weight:         1,
				MaxConcurrency: 1,
				AgingThreshold: "1m0s",
				CredentialName: "github",
				SlotResources:  slot,
			},
		},
		Policy: PolicyOverlay{
			ManifestDigest:      strings.Repeat("8", 64),
			CompiledGraphDigest: strings.Repeat("9", 64),
			AcquisitionDefault:  "disabled",
		},
		Controller: ControllerTimingOverlay{
			AckTimeout:            "1s",
			OperationTimeout:      "2s",
			PollCycleTimeout:      "3s",
			ReconciliationTimeout: "4s",
			PollCadence:           "5s",
			ReconciliationCadence: "6s",
			DrainPollCadence:      "7s",
			ShutdownTimeout:       "8s",
			SessionCloseTimeout:   "9s",
			TransitionJoinTimeout: "10s",
			DurableFinishTimeout:  "11s",
			ReplayEvidenceMaxAge:  "12s",
			HostCapacityMaxAge:    "13s",
			PollLeaseTTL:          "14s",
			LedgerTail:            "15s",
		},
		Fence: FenceTimingOverlay{
			LockPollInterval: "10ms",
			RenewalInterval:  "1s",
			RenewalTimeout:   "2s",
		},
		Health: HealthOverlay{
			Sink:              "local-closed-v1",
			MaxDocumentBytes:  4096,
			ObservationMaxAge: "5s",
		},
		Profile: ProfileOverlay{
			ConformanceEvidenceDigest: strings.Repeat("a", 64),
			NetworkEvidenceDigest:     strings.Repeat("b", 64),
			PlatformEvidenceRevision:  "platform-v1",
		},
		Watchdog: WatchdogOverlay{
			Cadence:         "30s",
			RestartDeadline: "1m0s",
			ProcessGrace:    "5s",
			HealthMaxAge:    "10s",
			Logs: LogPolicyOverlay{
				MaxBytes: 1024,
				MaxFiles: 10,
				MaxAge:   "1h0m0s",
			},
		},
		ManagementTransport: ManagementTransportOverlay{
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
		Secrets: []NamedSecretRef{
			{
				Name: "github",
				Ref: SecretRefOverlay{
					Source: "file",
					Ref:    "/run/secrets/github",
				},
			},
			{
				Name: "ssh-control",
				Ref: SecretRefOverlay{
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

func immutableImage(name, digit string) string {
	return "example.invalid/portable/" + name + "@sha256:" + strings.Repeat(digit, 64)
}
