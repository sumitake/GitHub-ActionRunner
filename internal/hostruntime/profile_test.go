package hostruntime

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

const testMiB = uint64(1024 * 1024)

type profileStub struct {
	id         HostProfile
	report     ConformanceReport
	probeErr   error
	network    NetworkSnapshot
	networkErr error
	probeCalls int
	netCalls   int
}

func (s *profileStub) ID() HostProfile { return s.id }

func (s *profileStub) Probe(context.Context) (ConformanceReport, error) {
	s.probeCalls++
	return s.report, s.probeErr
}

func (s *profileStub) DiscoverNetworks(context.Context) (NetworkSnapshot, error) {
	s.netCalls++
	return s.network, s.networkErr
}

func validConformanceReport(id HostProfile) ConformanceReport {
	return ConformanceReport{
		ProfileID:             id,
		State:                 ProfileNormal,
		EgressBackend:         EgressBackendRestrictedBrokerV1,
		Architecture:          "amd64",
		KernelRelease:         "5.15.0-qts",
		RuntimeVersion:        "24.0.0",
		EffectiveCapacity:     2,
		MemorySizingDigest:    strings.Repeat("a", 64),
		ConntrackSizingDigest: strings.Repeat("b", 64),
		StorageSizingDigest:   strings.Repeat("c", 64),
		EvidenceDigest:        strings.Repeat("d", 64),
	}
}

func validNetworkSnapshot(id HostProfile) NetworkSnapshot {
	return NetworkSnapshot{
		ProfileID:          id,
		RunnerNetworkMode:  "none",
		BrokerNetworkID:    "restricted-broker-v1",
		RunnerLoopbackOnly: true,
		RoutesComplete:     true,
		EvidenceDigest:     strings.Repeat("e", 64),
	}
}

func TestSelectProfileIsClosedAndDoesNotFallbackAfterFailure(t *testing.T) {
	t.Parallel()

	strict := &profileStub{
		id:      HostProfileStrictLinux,
		report:  validConformanceReport(HostProfileStrictLinux),
		network: validNetworkSnapshot(HostProfileStrictLinux),
	}
	selected, err := SelectProfile(
		context.Background(),
		ProfileSelectRequest{},
		[]Profile{strict},
	)
	if err != nil {
		t.Fatalf("automatic strict selection: %v", err)
	}
	if selected.Profile.ID() != HostProfileStrictLinux ||
		selected.Report.ProfileID != HostProfileStrictLinux ||
		selected.Network.ProfileID != HostProfileStrictLinux {
		t.Fatalf("selected = %+v", selected)
	}

	degraded := validConformanceReport(HostProfileQTSCaplessRoot)
	degraded.State = ProfileDegraded
	degraded.Degraded = true
	root := &profileStub{
		id:      HostProfileQTSCaplessRoot,
		report:  degraded,
		network: validNetworkSnapshot(HostProfileQTSCaplessRoot),
	}
	if _, err := SelectProfile(
		context.Background(),
		ProfileSelectRequest{},
		[]Profile{root},
	); err == nil {
		t.Fatal("automatic selection accepted degraded root")
	}
	if root.probeCalls != 0 || root.netCalls != 0 {
		t.Fatalf("automatic degraded candidate was invoked: %d/%d", root.probeCalls, root.netCalls)
	}

	failing := &profileStub{
		id:       HostProfileStrictLinux,
		probeErr: errors.New("probe failed"),
	}
	if _, err := SelectProfile(
		context.Background(),
		ProfileSelectRequest{Explicit: HostProfileStrictLinux},
		[]Profile{failing, root},
	); err == nil {
		t.Fatal("explicit failure fell back")
	}
	if failing.probeCalls != 1 || root.probeCalls != 0 {
		t.Fatalf("unexpected fallback calls: strict=%d root=%d", failing.probeCalls, root.probeCalls)
	}

	if _, err := SelectProfile(
		context.Background(),
		ProfileSelectRequest{},
		[]Profile{strict, strict},
	); err == nil {
		t.Fatal("duplicate candidate ID accepted")
	}
	unknown := &profileStub{id: HostProfile("unknown-v1")}
	if _, err := SelectProfile(
		context.Background(),
		ProfileSelectRequest{},
		[]Profile{unknown},
	); err == nil {
		t.Fatal("unknown candidate ID accepted")
	}
}

func TestSelectProfileRequiresExplicitDegradedRootProof(t *testing.T) {
	t.Parallel()

	report := validConformanceReport(HostProfileQTSCaplessRoot)
	report.State = ProfileDegraded
	report.Degraded = true
	root := &profileStub{
		id:      HostProfileQTSCaplessRoot,
		report:  report,
		network: validNetworkSnapshot(HostProfileQTSCaplessRoot),
	}
	if _, err := SelectProfile(
		context.Background(),
		ProfileSelectRequest{Explicit: HostProfileQTSCaplessRoot},
		[]Profile{root},
	); err == nil {
		t.Fatal("degraded root accepted without private allow")
	}
	selected, err := SelectProfile(
		context.Background(),
		ProfileSelectRequest{
			Explicit:          HostProfileQTSCaplessRoot,
			AllowDegradedRoot: true,
		},
		[]Profile{root},
	)
	if err != nil {
		t.Fatalf("explicit degraded root selection: %v", err)
	}
	if !selected.Report.Degraded || selected.Report.State != ProfileDegraded {
		t.Fatalf("degraded report = %+v", selected.Report)
	}

	caps := CapabilitySets{
		EffectiveEmpty:   true,
		PermittedEmpty:   true,
		InheritableEmpty: true,
		BoundingEmpty:    true,
		AmbientEmpty:     true,
	}
	if err := ValidateDegradedRootProof(
		HostProfileQTSCaplessRoot,
		true,
		0,
		caps,
	); err != nil {
		t.Fatalf("valid degraded-root proof: %v", err)
	}
	caps.BoundingEmpty = false
	if err := ValidateDegradedRootProof(
		HostProfileQTSCaplessRoot,
		true,
		0,
		caps,
	); err == nil {
		t.Fatal("nonempty capability set accepted")
	}
}

func validRunnerSizing() RunnerSizingTuple {
	return RunnerSizingTuple{
		OperatorApproved:                true,
		RunnerTmpfsBytes:                3 * 1024 * testMiB,
		RunnerP99Bytes:                  2162 * testMiB,
		RunnerMarginBytes:               256 * testMiB,
		TmpTmpfsBytes:                   256 * testMiB,
		TmpP99Bytes:                     128 * testMiB,
		TmpMarginBytes:                  64 * testMiB,
		ScratchTmpfsBytes:               256 * testMiB,
		ScratchP99Bytes:                 128 * testMiB,
		ScratchMarginBytes:              64 * testMiB,
		RunnerCgroupP99Bytes:            3 * 1024 * testMiB,
		ProcessMarginBytes:              512 * testMiB,
		RunnerMemoryBytes:               4 * 1024 * testMiB,
		SwapLimitConfigured:             true,
		SwapLimitBytes:                  0,
		MaxActiveConcurrency:            2,
		AuxiliarySlotMemoryBytes:        128 * testMiB,
		IdleControlPlaneBytes:           512 * testMiB,
		CandidateBuildAndSmokePeakBytes: 1024 * testMiB,
		HostAndGatewayReserveBytes:      2 * 1024 * testMiB,
		UsableHostMemoryBytes:           16 * 1024 * testMiB,
		MeasuredIdleRunnerBytes:         666 * testMiB,
		ReclamationObservationCadence:   time.Minute,
		EvidenceRevision:                "runner-sizing-r1",
	}
}

func TestValidateRunnerSizingChecksEveryEnvelope(t *testing.T) {
	t.Parallel()

	valid := validRunnerSizing()
	first, err := ValidateRunnerSizing(valid)
	if err != nil {
		t.Fatalf("valid sizing: %v", err)
	}
	second, err := ValidateRunnerSizing(valid)
	if err != nil || first.Digest != second.Digest || !isLowerHex64(first.Digest) {
		t.Fatalf("unstable sizing digest: first=%+v second=%+v err=%v", first, second, err)
	}

	tests := []struct {
		name   string
		mutate func(*RunnerSizingTuple)
	}{
		{
			name: "unapproved",
			mutate: func(v *RunnerSizingTuple) {
				v.OperatorApproved = false
			},
		},
		{
			name: "idle above p99",
			mutate: func(v *RunnerSizingTuple) {
				v.MeasuredIdleRunnerBytes = v.RunnerP99Bytes + 1
			},
		},
		{
			name: "runner p99 margin above tmpfs",
			mutate: func(v *RunnerSizingTuple) {
				v.RunnerTmpfsBytes = v.RunnerP99Bytes + v.RunnerMarginBytes - 1
			},
		},
		{
			name: "whole cgroup p99 margin above memory",
			mutate: func(v *RunnerSizingTuple) {
				v.RunnerCgroupP99Bytes = 2162 * testMiB
				v.ProcessMarginBytes = 64 * testMiB
				v.RunnerMemoryBytes = 2 * 1024 * testMiB
				v.RunnerTmpfsBytes = 512 * testMiB
				v.RunnerP99Bytes = 256 * testMiB
				v.RunnerMarginBytes = 64 * testMiB
				v.MeasuredIdleRunnerBytes = 128 * testMiB
			},
		},
		{
			name: "tmpfs sum above memory",
			mutate: func(v *RunnerSizingTuple) {
				v.RunnerMemoryBytes = 2 * 1024 * testMiB
				v.RunnerTmpfsBytes = 3 * 1024 * testMiB
			},
		},
		{
			name: "six slots exceed synthetic 32 gib host",
			mutate: func(v *RunnerSizingTuple) {
				v.MaxActiveConcurrency = 6
				v.RunnerMemoryBytes = 5 * 1024 * testMiB
				v.RunnerCgroupP99Bytes = 3 * 1024 * testMiB
				v.UsableHostMemoryBytes = 32 * 1024 * testMiB
			},
		},
		{
			name: "swap omitted",
			mutate: func(v *RunnerSizingTuple) {
				v.SwapLimitConfigured = false
			},
		},
		{
			name: "multiply overflow",
			mutate: func(v *RunnerSizingTuple) {
				v.MaxActiveConcurrency = math.MaxUint64
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := valid
			test.mutate(&value)
			if _, err := ValidateRunnerSizing(value); err == nil {
				t.Fatal("invalid sizing accepted")
			}
		})
	}
}

func TestRunnerSizingNeverCountsSwapAsRAM(t *testing.T) {
	t.Parallel()

	value := validRunnerSizing()
	value.UsableHostMemoryBytes = 8 * 1024 * testMiB
	if _, err := ValidateRunnerSizing(value); err == nil {
		t.Fatal("invalid host equation unexpectedly valid")
	}
	value.SwapLimitBytes = math.MaxUint64
	if _, err := ValidateRunnerSizing(value); err == nil {
		t.Fatal("swap turned invalid RAM equation valid")
	}
}

func validConntrackSizing() ConntrackSizing {
	return ConntrackSizing{
		CurrentEntries:          100,
		MaximumEntries:          1000,
		HostReserveEntries:      200,
		MaximumRunnerCapacity:   4,
		MeasuredJobClassEntries: 80,
		MeasuredDoHClassEntries: 20,
		JobClassBudget:          100,
		DoHClassBudget:          25,
		Timeouts: []ConntrackTimeout{
			{Name: "tcp-established", Seconds: 432000},
			{Name: "udp", Seconds: 30},
		},
		DialTokenStateRevision: "dial-state-r1",
		ConsumeBeforeDial:      true,
		EvidenceRevision:       "conntrack-r1",
		EgressBackend:          EgressBackendRestrictedBrokerV1,
	}
}

func TestValidateConntrackSizingComputesCapacityAndDrift(t *testing.T) {
	t.Parallel()

	value := validConntrackSizing()
	result, err := ValidateConntrackSizing(value)
	if err != nil {
		t.Fatalf("valid conntrack: %v", err)
	}
	if result.State != ProfileNormal || result.EffectiveCapacity != 4 ||
		!isLowerHex64(result.Digest) {
		t.Fatalf("result = %+v", result)
	}

	warning := value
	warning.CurrentEntries = 650
	warningResult, err := ValidateConntrackSizing(warning)
	if err != nil {
		t.Fatalf("warning conntrack: %v", err)
	}
	if warningResult.State != ProfileWarning ||
		warningResult.EffectiveCapacity != 1 ||
		warningResult.Digest == result.Digest {
		t.Fatalf("warning result = %+v", warningResult)
	}

	stop := value
	stop.CurrentEntries = 800
	stopResult, err := ValidateConntrackSizing(stop)
	if err != nil {
		t.Fatalf("stop conntrack: %v", err)
	}
	if stopResult.State != ProfileStop || stopResult.EffectiveCapacity != 0 {
		t.Fatalf("stop result = %+v", stopResult)
	}

	changedTimeout := value
	changedTimeout.Timeouts[0].Seconds--
	changed, err := ValidateConntrackSizing(changedTimeout)
	if err != nil {
		t.Fatalf("changed timeout: %v", err)
	}
	if changed.Digest == result.Digest {
		t.Fatal("timeout drift did not change digest")
	}
}

func TestValidateConntrackSizingRejectsIncompleteAndOverflow(t *testing.T) {
	t.Parallel()

	valid := validConntrackSizing()
	tests := []struct {
		name   string
		mutate func(*ConntrackSizing)
	}{
		{"direct nftables", func(v *ConntrackSizing) { v.EgressBackend = EgressBackendNftablesDirectV1 }},
		{"count above max", func(v *ConntrackSizing) { v.CurrentEntries = v.MaximumEntries + 1 }},
		{"reserve at max", func(v *ConntrackSizing) { v.HostReserveEntries = v.MaximumEntries }},
		{"measurement above budget", func(v *ConntrackSizing) { v.MeasuredJobClassEntries = v.JobClassBudget + 1 }},
		{"consume missing", func(v *ConntrackSizing) { v.ConsumeBeforeDial = false }},
		{"timeout missing", func(v *ConntrackSizing) { v.Timeouts = nil }},
		{"duplicate timeout", func(v *ConntrackSizing) { v.Timeouts = append(v.Timeouts, v.Timeouts[0]) }},
		{"add overflow", func(v *ConntrackSizing) { v.JobClassBudget = math.MaxUint64 }},
		{
			"multiply overflow",
			func(v *ConntrackSizing) {
				v.MaximumRunnerCapacity = math.MaxUint64
				v.MaximumEntries = math.MaxUint64
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := valid
			value.Timeouts = append([]ConntrackTimeout(nil), valid.Timeouts...)
			test.mutate(&value)
			if _, err := ValidateConntrackSizing(value); err == nil {
				t.Fatal("invalid conntrack sizing accepted")
			}
		})
	}
}

func validStorageSizing() StorageSizing {
	roles := []StorageRole{
		StorageRoleDockerRoot,
		StorageRoleState,
		StorageRoleStaging,
		StorageRoleRollback,
		StorageRoleScratch,
		StorageRoleLogs,
	}
	observations := make([]StorageObservation, 0, len(roles))
	requirements := make([]StorageRequirement, 0, len(roles))
	for index, role := range roles {
		identity := FilesystemIdentity{
			Device: uint64(index + 1),
			Inode:  uint64(index + 101),
		}
		observations = append(observations, StorageObservation{
			Role:       role,
			Filesystem: identity,
			FreeBytes:  10_000,
			FreeInodes: 1_000,
		})
		requirements = append(requirements, StorageRequirement{
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
	return StorageSizing{
		MaximumActiveConcurrency: 2,
		Observations:             observations,
		Requirements:             requirements,
		LogBounds: LogBounds{
			UsedBytes: 10,
			MaxBytes:  100,
			UsedFiles: 2,
			MaxFiles:  10,
		},
		EvidenceRevision: "storage-r1",
	}
}

func TestValidateStorageSizingDeduplicatesFilesystemIdentity(t *testing.T) {
	t.Parallel()

	value := validStorageSizing()
	result, err := ValidateStorageSizing(value)
	if err != nil {
		t.Fatalf("valid storage: %v", err)
	}
	if result.State != ProfileNormal || !isLowerHex64(result.Digest) {
		t.Fatalf("result = %+v", result)
	}

	value.Observations[1].Filesystem = value.Observations[0].Filesystem
	value.Observations[1].FreeBytes = value.Observations[0].FreeBytes
	value.Observations[1].FreeInodes = value.Observations[0].FreeInodes
	shared, err := ValidateStorageSizing(value)
	if err != nil {
		t.Fatalf("shared filesystem: %v", err)
	}
	if shared.Digest == result.Digest {
		t.Fatal("filesystem role-to-identity change did not change digest")
	}

	value.Observations[0].FreeBytes = 400
	value.Observations[1].FreeBytes = 400
	pressure, err := ValidateStorageSizing(value)
	if err != nil {
		t.Fatalf("shared pressure: %v", err)
	}
	if pressure.State != ProfileStop {
		t.Fatalf("shared requirements were not summed: %+v", pressure)
	}
}

func TestValidateStorageSizingChecksBytesInodesLogsAndOverflow(t *testing.T) {
	t.Parallel()

	valid := validStorageSizing()
	tests := []struct {
		name   string
		mutate func(*StorageSizing)
	}{
		{"missing role", func(v *StorageSizing) { v.Observations = v.Observations[:5] }},
		{"duplicate role", func(v *StorageSizing) { v.Observations[1].Role = v.Observations[0].Role }},
		{"zero filesystem", func(v *StorageSizing) { v.Observations[0].Filesystem = FilesystemIdentity{} }},
		{"unbounded log bytes", func(v *StorageSizing) { v.LogBounds.MaxBytes = 0 }},
		{"unbounded log files", func(v *StorageSizing) { v.LogBounds.MaxFiles = 0 }},
		{"incomplete simultaneous vector", func(v *StorageSizing) { v.Requirements[0].CurrentReleaseBytes = 0 }},
		{"reserve order", func(v *StorageSizing) { v.Requirements[0].WarningReserveBytes = v.Requirements[0].StopReserveBytes }},
		{
			"slot multiply overflow",
			func(v *StorageSizing) {
				v.MaximumActiveConcurrency = math.MaxUint64
				v.Requirements[0].PerSlotBytes = 2
			},
		},
		{
			"sum overflow",
			func(v *StorageSizing) {
				v.Requirements[0].CurrentReleaseBytes = math.MaxUint64
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := valid
			value.Observations = append([]StorageObservation(nil), valid.Observations...)
			value.Requirements = append([]StorageRequirement(nil), valid.Requirements...)
			test.mutate(&value)
			if _, err := ValidateStorageSizing(value); err == nil {
				t.Fatal("invalid storage sizing accepted")
			}
		})
	}

	inodeStop := validStorageSizing()
	inodeStop.Observations[0].FreeInodes = 20
	result, err := ValidateStorageSizing(inodeStop)
	if err != nil {
		t.Fatalf("inode stop: %v", err)
	}
	if result.State != ProfileStop {
		t.Fatalf("inode stop result = %+v", result)
	}

	logStop := validStorageSizing()
	logStop.LogBounds.UsedBytes = logStop.LogBounds.MaxBytes + 1
	logStop.LogBounds.UsedFiles = logStop.LogBounds.MaxFiles + 1
	result, err = ValidateStorageSizing(logStop)
	if err != nil {
		t.Fatalf("bounded log stop: %v", err)
	}
	if result.State != ProfileStop {
		t.Fatalf("log stop result = %+v", result)
	}
}

func TestConformanceAndNetworkReportsRejectLeakyOrIncompleteScalars(t *testing.T) {
	t.Parallel()

	report := validConformanceReport(HostProfileStrictLinux)
	if err := ValidateConformanceReport(report); err != nil {
		t.Fatalf("valid report: %v", err)
	}
	report.RuntimeVersion = "/private/runner/runtime"
	if err := ValidateConformanceReport(report); err == nil {
		t.Fatal("path-like runtime version accepted")
	}

	network := validNetworkSnapshot(HostProfileStrictLinux)
	if err := ValidateNetworkSnapshot(network); err != nil {
		t.Fatalf("valid network: %v", err)
	}
	network.BrokerNetworkID = "192." + "0.2." + "10"
	if err := ValidateNetworkSnapshot(network); err == nil {
		t.Fatal("network coordinate accepted")
	}
}
