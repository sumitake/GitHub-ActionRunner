package qts

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
	observeErr  error
	network     []byte
	networkErr  error
	observeCall int
	networkCall int
}

func (s *sourceStub) Observe(context.Context) (hostruntime.ProfileObservation, error) {
	s.observeCall++
	return s.observation, s.observeErr
}

func (s *sourceStub) NetworkDocument(context.Context) ([]byte, error) {
	s.networkCall++
	return append([]byte(nil), s.network...), s.networkErr
}

func TestProfileRejectsDarwinBeforeSourceCalls(t *testing.T) {
	t.Parallel()

	source := &sourceStub{}
	profile := NewProfile(Config{
		ID:                      hostruntime.HostProfileStrictLinux,
		TargetOS:                "darwin",
		Architecture:            "amd64",
		KernelRelease:           "5.15.0-qts",
		RuntimeVersion:          "24.0.0",
		NetworkDocumentMaxBytes: 4096,
	}, source)
	if _, err := profile.Probe(context.Background()); err == nil {
		t.Fatal("darwin probe accepted")
	}
	if _, err := profile.DiscoverNetworks(context.Background()); err == nil {
		t.Fatal("darwin discovery accepted")
	}
	if source.observeCall != 0 || source.networkCall != 0 {
		t.Fatalf("source called on darwin: %d/%d", source.observeCall, source.networkCall)
	}
}

func TestStrictAndExplicitCaplessRootProfiles(t *testing.T) {
	t.Parallel()

	strictObservation := qtsObservation()
	strictSource := &sourceStub{
		observation: strictObservation,
		network:     qtsNetworkDocument(hostruntime.HostProfileStrictLinux),
	}
	strict := NewProfile(qtsConfig(hostruntime.HostProfileStrictLinux), strictSource)
	report, err := strict.Probe(context.Background())
	if err != nil {
		t.Fatalf("strict probe: %v", err)
	}
	if report.ProfileID != hostruntime.HostProfileStrictLinux ||
		report.State != hostruntime.ProfileNormal ||
		report.Degraded {
		t.Fatalf("strict report = %+v", report)
	}
	network, err := strict.DiscoverNetworks(context.Background())
	if err != nil {
		t.Fatalf("strict discovery: %v", err)
	}
	if network.ProfileID != hostruntime.HostProfileStrictLinux {
		t.Fatalf("network = %+v", network)
	}

	rootObservation := qtsObservation()
	rootObservation.UID = 0
	rootObservation.Capabilities = hostruntime.CapabilitySets{
		EffectiveEmpty:   true,
		PermittedEmpty:   true,
		InheritableEmpty: true,
		BoundingEmpty:    true,
		AmbientEmpty:     true,
	}
	rootConfig := qtsConfig(hostruntime.HostProfileQTSCaplessRoot)
	rootConfig.AllowDegradedRoot = true
	rootSource := &sourceStub{
		observation: rootObservation,
		network:     qtsNetworkDocument(hostruntime.HostProfileQTSCaplessRoot),
	}
	root := NewProfile(rootConfig, rootSource)
	report, err = root.Probe(context.Background())
	if err != nil {
		t.Fatalf("capless-root probe: %v", err)
	}
	if !report.Degraded || report.State != hostruntime.ProfileDegraded {
		t.Fatalf("root report = %+v", report)
	}

	rootConfig.AllowDegradedRoot = false
	if _, err := NewProfile(rootConfig, rootSource).Probe(context.Background()); err == nil {
		t.Fatal("capless root accepted without explicit private allow")
	}
	rootConfig.AllowDegradedRoot = true
	rootObservation.Capabilities.BoundingEmpty = false
	rootSource.observation = rootObservation
	if _, err := NewProfile(rootConfig, rootSource).Probe(context.Background()); err == nil {
		t.Fatal("capless root accepted with nonempty bounding set")
	}
}

func TestProfileRejectsMissingIsolationAndRecomputesPressure(t *testing.T) {
	t.Parallel()

	observation := qtsObservation()
	observation.Isolation.HeldBrokerSocketCountZero = false
	source := &sourceStub{observation: observation}
	if _, err := NewProfile(
		qtsConfig(hostruntime.HostProfileStrictLinux),
		source,
	).Probe(context.Background()); err == nil {
		t.Fatal("missing broker socket proof accepted")
	}

	observation = qtsObservation()
	source.observation = observation
	normal, err := NewProfile(
		qtsConfig(hostruntime.HostProfileStrictLinux),
		source,
	).Probe(context.Background())
	if err != nil {
		t.Fatalf("normal probe: %v", err)
	}
	observation.Conntrack.CurrentEntries = 650
	source.observation = observation
	warning, err := NewProfile(
		qtsConfig(hostruntime.HostProfileStrictLinux),
		source,
	).Probe(context.Background())
	if err != nil {
		t.Fatalf("warning probe: %v", err)
	}
	if warning.State != hostruntime.ProfileWarning ||
		warning.EffectiveCapacity >= normal.EffectiveCapacity ||
		warning.EvidenceDigest == normal.EvidenceDigest {
		t.Fatalf("normal=%+v warning=%+v", normal, warning)
	}
}

func TestDiscoveryRejectsTruncatedNoncanonicalAndIncompleteDocuments(t *testing.T) {
	t.Parallel()

	config := qtsConfig(hostruntime.HostProfileStrictLinux)
	tests := []struct {
		name     string
		document []byte
		maxBytes int
	}{
		{"truncated", []byte(`{"profile_id":"strict-linux-v1"`), 4096},
		{"trailing", append(qtsNetworkDocument(hostruntime.HostProfileStrictLinux), 'x'), 4096},
		{"oversize", qtsNetworkDocument(hostruntime.HostProfileStrictLinux), 8},
		{
			"incomplete routes",
			networkDocument(hostruntime.NetworkDiscoveryDocument{
				ProfileID:          hostruntime.HostProfileStrictLinux,
				RunnerNetworkMode:  "none",
				BrokerNetworkID:    hostruntime.EgressBackendRestrictedBrokerV1,
				RunnerLoopbackOnly: true,
				RoutesComplete:     false,
				EvidenceRevision:   "network-r1",
			}),
			4096,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			localConfig := config
			localConfig.NetworkDocumentMaxBytes = test.maxBytes
			source := &sourceStub{
				observation: qtsObservation(),
				network:     test.document,
			}
			if _, err := NewProfile(localConfig, source).DiscoverNetworks(
				context.Background(),
			); err == nil {
				t.Fatal("invalid discovery accepted")
			}
		})
	}
}

func qtsConfig(id hostruntime.HostProfile) Config {
	return Config{
		ID:                      id,
		TargetOS:                "linux",
		Architecture:            "amd64",
		KernelRelease:           "5.15.0-qts",
		RuntimeVersion:          "24.0.0",
		NetworkDocumentMaxBytes: 4096,
	}
}

func qtsObservation() hostruntime.ProfileObservation {
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
				Device: uint64(index + 1),
				Inode:  uint64(index + 100),
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
			KernelRelease:        "5.15.0-qts",
			RuntimeVersion:       "24.0.0",
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
			PolicyDigest:               strings.Repeat("a", 64),
			EvidenceRevision:           "isolation-r1",
		},
	}
}

func qtsNetworkDocument(id hostruntime.HostProfile) []byte {
	return networkDocument(hostruntime.NetworkDiscoveryDocument{
		ProfileID:          id,
		RunnerNetworkMode:  "none",
		BrokerNetworkID:    hostruntime.EgressBackendRestrictedBrokerV1,
		BrokerIPv6Enabled:  false,
		RunnerLoopbackOnly: true,
		RoutesComplete:     true,
		EvidenceRevision:   "network-r1",
	})
}

func networkDocument(document hostruntime.NetworkDiscoveryDocument) []byte {
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}
