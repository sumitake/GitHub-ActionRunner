package systemd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type sourceStub struct {
	observation hostruntime.ProfileObservation
	network     []byte
	observeCall int
	networkCall int
}

func (s *sourceStub) Observe(context.Context) (hostruntime.ProfileObservation, error) {
	s.observeCall++
	return s.observation, nil
}

func (s *sourceStub) NetworkDocument(context.Context) ([]byte, error) {
	s.networkCall++
	return append([]byte(nil), s.network...), nil
}

func TestProfileAcceptsOnlyStrictLinux(t *testing.T) {
	t.Parallel()

	source := &sourceStub{
		observation: systemdObservation(),
		network:     systemdNetworkDocument(),
	}
	profile := NewProfile(systemdConfig(), source)
	report, err := profile.Probe(context.Background())
	if err != nil {
		t.Fatalf("strict systemd probe: %v", err)
	}
	if report.ProfileID != hostruntime.HostProfileStrictLinux ||
		report.State != hostruntime.ProfileNormal ||
		report.Degraded {
		t.Fatalf("report = %+v", report)
	}
	if _, err := profile.DiscoverNetworks(context.Background()); err != nil {
		t.Fatalf("network discovery: %v", err)
	}

	degraded := systemdConfig()
	degraded.ID = hostruntime.HostProfileQTSCaplessRoot
	degraded.AllowDegradedRoot = true
	if _, err := NewProfile(degraded, source).Probe(context.Background()); err == nil {
		t.Fatal("systemd accepted degraded root")
	}
}

func TestProfileRejectsPlatformBeforeAndAfterSourceBoundary(t *testing.T) {
	t.Parallel()

	source := &sourceStub{observation: systemdObservation()}
	config := systemdConfig()
	config.TargetOS = "darwin"
	if _, err := NewProfile(config, source).Probe(context.Background()); err == nil {
		t.Fatal("darwin accepted")
	}
	if source.observeCall != 0 {
		t.Fatal("darwin reached source")
	}

	config = systemdConfig()
	source.observation.Platform.RuntimeVersion = "different"
	if _, err := NewProfile(config, source).Probe(context.Background()); err == nil {
		t.Fatal("runtime mismatch accepted")
	}
}

func systemdConfig() Config {
	return Config{
		ID:                      hostruntime.HostProfileStrictLinux,
		TargetOS:                "linux",
		Architecture:            "amd64",
		KernelRelease:           "6.8.0",
		RuntimeVersion:          "26.1.0",
		NetworkDocumentMaxBytes: 4096,
	}
}

func systemdObservation() hostruntime.ProfileObservation {
	const mib = uint64(1024 * 1024)
	roles := []hostruntime.StorageRole{
		hostruntime.StorageRoleDockerRoot,
		hostruntime.StorageRoleState,
		hostruntime.StorageRoleStaging,
		hostruntime.StorageRoleRollback,
		hostruntime.StorageRoleScratch,
		hostruntime.StorageRoleLogs,
	}
	observations := make([]hostruntime.StorageObservation, 0, len(roles))
	requirements := make([]hostruntime.StorageRequirement, 0, len(roles))
	for index, role := range roles {
		observations = append(observations, hostruntime.StorageObservation{
			Role: role,
			Filesystem: hostruntime.FilesystemIdentity{
				Device: uint64(index + 10),
				Inode:  uint64(index + 1000),
			},
			FreeBytes:  100_000,
			FreeInodes: 10_000,
		})
		requirements = append(requirements, hostruntime.StorageRequirement{
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
			HostReserveBytes:       100,
			HostReserveInodes:      10,
			StopReserveBytes:       100,
			StopReserveInodes:      10,
			WarningReserveBytes:    200,
			WarningReserveInodes:   20,
		})
	}
	return hostruntime.ProfileObservation{
		Platform: hostruntime.PlatformFacts{
			OS:                   "linux",
			Architecture:         "amd64",
			KernelRelease:        "6.8.0",
			RuntimeVersion:       "26.1.0",
			CgroupMemoryEnforced: true,
			CgroupCPUEnforced:    true,
			CgroupPIDsEnforced:   true,
		},
		UID: 1000,
		Memory: hostruntime.RunnerSizingTuple{
			OperatorApproved:                true,
			RunnerTmpfsBytes:                3 * 1024 * mib,
			RunnerP99Bytes:                  2162 * mib,
			RunnerMarginBytes:               256 * mib,
			TmpTmpfsBytes:                   256 * mib,
			TmpP99Bytes:                     128 * mib,
			TmpMarginBytes:                  64 * mib,
			ScratchTmpfsBytes:               256 * mib,
			ScratchP99Bytes:                 128 * mib,
			ScratchMarginBytes:              64 * mib,
			RunnerCgroupP99Bytes:            3 * 1024 * mib,
			ProcessMarginBytes:              512 * mib,
			RunnerMemoryBytes:               4 * 1024 * mib,
			SwapLimitConfigured:             true,
			MaxActiveConcurrency:            2,
			AuxiliarySlotMemoryBytes:        128 * mib,
			IdleControlPlaneBytes:           512 * mib,
			CandidateBuildAndSmokePeakBytes: 1024 * mib,
			HostAndGatewayReserveBytes:      2 * 1024 * mib,
			UsableHostMemoryBytes:           16 * 1024 * mib,
			MeasuredIdleRunnerBytes:         666 * mib,
			ReclamationObservationCadence:   time.Minute,
			EvidenceRevision:                "runner-r1",
		},
		Conntrack: hostruntime.ConntrackSizing{
			CurrentEntries:          100,
			MaximumEntries:          1000,
			HostReserveEntries:      200,
			MaximumRunnerCapacity:   4,
			MeasuredJobClassEntries: 80,
			MeasuredDoHClassEntries: 20,
			JobClassBudget:          100,
			DoHClassBudget:          25,
			Timeouts: []hostruntime.ConntrackTimeout{
				{Name: "tcp-established", Seconds: 432000},
				{Name: "udp", Seconds: 30},
			},
			DialTokenStateRevision: "dial-r1",
			ConsumeBeforeDial:      true,
			EvidenceRevision:       "conntrack-r1",
			EgressBackend:          hostruntime.EgressBackendRestrictedBrokerV1,
		},
		Storage: hostruntime.StorageSizing{
			MaximumActiveConcurrency: 2,
			Observations:             observations,
			Requirements:             requirements,
			LogBounds: hostruntime.LogBounds{
				UsedBytes: 10,
				MaxBytes:  100,
				UsedFiles: 2,
				MaxFiles:  10,
			},
			EvidenceRevision: "storage-r1",
		},
		Isolation: hostruntime.IsolationEvidence{
			RunnerNetworkNone:          true,
			RunnerTablesEmptyBefore:    true,
			RunnerTablesEmptyAfter:     true,
			RunnerConntrackEmptyBefore: true,
			RunnerConntrackEmptyAfter:  true,
			LoopbackFloodCompleted:     true,
			NamespaceDenied:            true,
			RawSocketDenied:            true,
			BPFDenied:                  true,
			UnshareDenied:              true,
			SetNSDenied:                true,
			Clone3Denied:               true,
			HeldBrokerSocketCountZero:  true,
			LegacyFilterRestored:       true,
			IPv6PostureProven:          true,
			RelayMountIdentityProven:   true,
			DialMountIdentityProven:    true,
			DoHPolicyProven:            true,
			DurableConsumeBeforeDial:   true,
			CPUEnforced:                true,
			MemoryEnforced:             true,
			PIDsEnforced:               true,
			FDsEnforced:                true,
			TmpfsEnforced:              true,
			ReadOnlyRootEnforced:       true,
			SeccompEnforced:            true,
			CapabilitiesEnforced:       true,
			WorkAreaReclamationProven:  true,
			BoundedLogRetention:        true,
			PolicyDigest:               strings.Repeat("f", 64),
			EvidenceRevision:           "isolation-r1",
		},
	}
}

func systemdNetworkDocument() []byte {
	document := hostruntime.NetworkDiscoveryDocument{
		ProfileID:          hostruntime.HostProfileStrictLinux,
		RunnerNetworkMode:  "none",
		BrokerNetworkID:    hostruntime.EgressBackendRestrictedBrokerV1,
		RunnerLoopbackOnly: true,
		RoutesComplete:     true,
		EvidenceRevision:   "network-r1",
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}
