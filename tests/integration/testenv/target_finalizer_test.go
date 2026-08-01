package testenv

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type fakeTargetObservationSource struct {
	observation targetRuntimeObservation
	err         error
	calls       int
}

type fakeTargetEvidenceLedger struct {
	digest string
	err    error
	calls  int
}

func (l *fakeTargetEvidenceLedger) FinalEvidenceDigest() (
	string,
	error,
) {
	l.calls++
	return l.digest, l.err
}

func (s *fakeTargetObservationSource) FinalObservation(
	context.Context,
) (targetRuntimeObservation, error) {
	s.calls++
	return s.observation, s.err
}

func TestDynamicTargetFinalizerRecomputesObservedDigestsAfterExactCases(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, graph, observed :=
		validTargetFinalizerInputs(t)
	source := &fakeTargetObservationSource{observation: observed}
	ledger := &fakeTargetEvidenceLedger{digest: inputDigestD}
	finalizer, err := newDynamicTargetFinalizer(
		input,
		overlay,
		static,
		graph,
		source,
		ledger,
	)
	if err != nil {
		t.Fatalf("newDynamicTargetFinalizer: %v", err)
	}
	completed := conformance.RequiredCases()
	completed = completed[:len(completed)-1]
	result, err := finalizer.Finalize(
		context.Background(),
		completed,
	)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !isLowerHex(result.ProfileEvidenceDigest, 64) ||
		!isLowerHex(result.NetworkEvidenceDigest, 64) ||
		result.ProfileEvidenceDigest ==
			input.Runtime.ExpectedProfileEvidenceDigest ||
		result.NetworkEvidenceDigest ==
			input.Runtime.ExpectedNetworkEvidenceDigest ||
		source.calls != 1 ||
		ledger.calls != 1 {
		t.Fatalf(
			"result = %+v source_calls=%d ledger_calls=%d",
			result,
			source.calls,
			ledger.calls,
		)
	}

	mutated := input
	mutated.Runtime.ExpectedProfileEvidenceDigest =
		strings.Repeat("e", 64)
	mutated.Runtime.ExpectedNetworkEvidenceDigest =
		strings.Repeat("f", 64)
	second, err := newDynamicTargetFinalizer(
		mutated,
		overlay,
		static,
		graph,
		&fakeTargetObservationSource{observation: observed},
		&fakeTargetEvidenceLedger{digest: inputDigestD},
	)
	if err != nil {
		t.Fatalf("new mutated finalizer: %v", err)
	}
	secondResult, err := second.Finalize(
		context.Background(),
		completed,
	)
	if err != nil {
		t.Fatalf("Finalize mutated anchors: %v", err)
	}
	if secondResult != result {
		t.Fatalf(
			"expected anchors changed observations: first=%+v second=%+v",
			result,
			secondResult,
		)
	}
}

func TestDynamicTargetFinalizerRejectsIncompleteOrSubstitutedAuthority(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, graph, observed :=
		validTargetFinalizerInputs(t)
	completed := conformance.RequiredCases()
	completed = completed[:len(completed)-1]
	tests := []struct {
		name      string
		completed []conformance.CaseID
		mutate    func(*targetRuntimeObservation)
		sourceErr error
		ledgerErr error
	}{
		{
			name:      "missing case",
			completed: completed[:len(completed)-1],
		},
		{
			name: "reordered case",
			completed: func() []conformance.CaseID {
				value := append([]conformance.CaseID(nil), completed...)
				value[0], value[1] = value[1], value[0]
				return value
			}(),
		},
		{
			name:      "case fifteen included",
			completed: conformance.RequiredCases(),
		},
		{
			name:      "source failure",
			completed: completed,
			sourceErr: errors.New("closed source unavailable"),
		},
		{
			name:      "policy substitution",
			completed: completed,
			mutate: func(value *targetRuntimeObservation) {
				value.ProbeReport.PolicyDigest = strings.Repeat("9", 64)
			},
		},
		{
			name:      "route proof absent",
			completed: completed,
			mutate: func(value *targetRuntimeObservation) {
				value.RunnerRoutesComplete = false
			},
		},
		{
			name:      "isolation incomplete",
			completed: completed,
			mutate: func(value *targetRuntimeObservation) {
				value.Isolation.WorkAreaReclamationProven = false
			},
		},
		{
			name:      "source evidence revision injection",
			completed: completed,
			mutate: func(value *targetRuntimeObservation) {
				value.Isolation.EvidenceRevision = inputDigestC
			},
		},
		{
			name:      "ledger failure",
			completed: completed,
			ledgerErr: errors.New("evidence ledger unavailable"),
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			candidate := observed
			if testCase.mutate != nil {
				testCase.mutate(&candidate)
			}
			source := &fakeTargetObservationSource{
				observation: candidate,
				err:         testCase.sourceErr,
			}
			ledger := &fakeTargetEvidenceLedger{
				digest: inputDigestD,
				err:    testCase.ledgerErr,
			}
			finalizer, err := newDynamicTargetFinalizer(
				input,
				overlay,
				static,
				graph,
				source,
				ledger,
			)
			if err != nil {
				t.Fatalf("newDynamicTargetFinalizer: %v", err)
			}
			if _, err := finalizer.Finalize(
				context.Background(),
				testCase.completed,
			); !errors.Is(err, conformance.ErrObservation) {
				t.Fatalf("error = %v, want observation rejection", err)
			}
			if len(testCase.completed) != len(completed) ||
				testCase.name == "reordered case" ||
				testCase.name == "case fifteen included" {
				if source.calls != 0 {
					t.Fatalf("invalid case set reached source: %d", source.calls)
				}
			}
		})
	}
}

func TestProfileObservationFromOverlayPreservesEverySizingField(
	t *testing.T,
) {
	t.Parallel()

	_, overlay, static, _, observed := validTargetFinalizerInputs(t)
	observed.Isolation.EvidenceRevision = inputDigestD
	got, err := profileObservationFromTarget(
		"qts-capless-root",
		overlay,
		static,
		static.HostCapabilities,
		observed.Isolation,
	)
	if err != nil {
		t.Fatalf("profileObservationFromTarget: %v", err)
	}
	if got.Memory.RunnerTmpfsBytes !=
		overlay.Resources.RunnerSizing.RunnerTmpfsBytes ||
		got.Memory.SwapLimitBytes !=
			overlay.Resources.RunnerSizing.SwapLimitBytes ||
		got.Memory.ReclamationObservationCadence != time.Minute ||
		len(got.Conntrack.Timeouts) !=
			len(overlay.Resources.Conntrack.Timeouts) ||
		len(got.Storage.Observations) !=
			len(overlay.Resources.Storage.Observations) ||
		len(got.Storage.Requirements) !=
			len(overlay.Resources.Storage.Requirements) {
		t.Fatalf("mapped observation = %+v", got)
	}
	if _, err := hostruntime.EvaluateProfileObservation(
		hostruntime.HostProfileQTSCaplessRoot,
		true,
		got,
	); err != nil {
		t.Fatalf("mapped observation does not validate: %v", err)
	}
}

func TestDynamicTargetFinalizerMapsReportStrictProfileToRuntimeProfile(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, graph, observed :=
		validTargetFinalizerInputs(t)
	input.Target.ProfileID = "strict-linux"
	input.Target.ExpectedEUID = 1000
	overlay.Target.ProfileID = string(
		hostruntime.HostProfileStrictLinux,
	)
	overlay.Target.ExpectedEUID = 1000
	overlay.Target.DegradedAcknowledged = false
	static.HostFacts.EUID = 1000
	static.HostCapabilities = hostruntime.CapabilitySets{}
	finalizer, err := newDynamicTargetFinalizer(
		input,
		overlay,
		static,
		graph,
		&fakeTargetObservationSource{observation: observed},
		&fakeTargetEvidenceLedger{digest: inputDigestD},
	)
	if err != nil {
		t.Fatalf("newDynamicTargetFinalizer: %v", err)
	}
	completed := conformance.RequiredCases()
	if _, err := finalizer.Finalize(
		context.Background(),
		completed[:len(completed)-1],
	); err != nil {
		t.Fatalf("Finalize strict profile: %v", err)
	}
}

func validTargetFinalizerInputs(
	t *testing.T,
) (
	ConformanceInput,
	hostruntime.PrivateOverlay,
	staticPreflightResult,
	networkjail.DecisionGraph,
	targetRuntimeObservation,
) {
	t.Helper()

	const mib = uint64(1024 * 1024)
	input := ConformanceInput{
		Target: TargetBinding{
			OperatingSystem: "linux",
			Architecture:    "amd64",
			ExpectedEUID:    0,
			ProfileID:       "qts-capless-root",
			HostIdentityDigest: strings.Repeat(
				"1",
				64,
			),
		},
		Runtime: RuntimeBinding{
			ExpectedProfileEvidenceDigest: strings.Repeat("2", 64),
			ExpectedNetworkEvidenceDigest: strings.Repeat("3", 64),
		},
	}
	memory := hostruntime.RunnerSizingTuple{
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
		SwapLimitBytes:                  512 * mib,
		MaxActiveConcurrency:            2,
		AuxiliarySlotMemoryBytes:        128 * mib,
		IdleControlPlaneBytes:           512 * mib,
		CandidateBuildAndSmokePeakBytes: 1024 * mib,
		HostAndGatewayReserveBytes:      2 * 1024 * mib,
		UsableHostMemoryBytes:           16 * 1024 * mib,
		MeasuredIdleRunnerBytes:         666 * mib,
		ReclamationObservationCadence:   time.Minute,
		EvidenceRevision:                "runner-sizing-r1",
	}
	conntrack := hostruntime.ConntrackSizing{
		CurrentEntries:          100,
		MaximumEntries:          1000,
		HostReserveEntries:      200,
		MaximumRunnerCapacity:   2,
		MeasuredJobClassEntries: 80,
		MeasuredDoHClassEntries: 20,
		JobClassBudget:          100,
		DoHClassBudget:          25,
		Timeouts: []hostruntime.ConntrackTimeout{
			{Name: "tcp-established", Seconds: 432000},
			{Name: "udp", Seconds: 30},
		},
		DialTokenStateRevision: "dial-state-r1",
		ConsumeBeforeDial:      true,
		EvidenceRevision:       "conntrack-r1",
		EgressBackend: hostruntime.
			EgressBackendRestrictedBrokerV1,
	}
	storage := validTargetStorageSizing()
	overlay := hostruntime.PrivateOverlay{
		Target: hostruntime.TargetIdentityOverlay{
			OS:                   "linux",
			Architecture:         "amd64",
			ExpectedEUID:         0,
			ProfileID:            "qts-capless-root",
			DegradedAcknowledged: true,
		},
		Docker: hostruntime.DockerOverlay{
			BrokerNetworkID:   hostruntime.EgressBackendRestrictedBrokerV1,
			RunnerNetworkMode: "none",
		},
		Profile: hostruntime.ProfileOverlay{
			PlatformEvidenceRevision: "platform-r1",
		},
		Resources: hostruntime.ResourceOverlay{
			MaxCapacity:      2,
			FleetConcurrency: 2,
			RunnerSizing: runnerSizingOverlayFromTarget(
				memory,
			),
			Conntrack: conntrackOverlayFromTarget(
				conntrack,
			),
			Storage: storageOverlayFromTarget(
				storage,
			),
		},
	}
	static := staticPreflightResult{
		HostFacts: FixtureHostFacts{
			OperatingSystem:    "linux",
			Architecture:       "amd64",
			EUID:               0,
			HostIdentityDigest: input.Target.HostIdentityDigest,
		},
		DockerInfo: staticDockerInfoObservation{
			ServerVersion:   "28.0.1",
			OperatingSystem: "Example Linux",
			Architecture:    "x86_64",
			KernelVersion:   "6.12.1",
			CgroupVersion:   "2",
			MemoryLimit:     true,
			CPUCFS:          true,
			PIDsLimit:       true,
		},
		HostCapabilities: hostruntime.CapabilitySets{
			EffectiveEmpty:   true,
			PermittedEmpty:   true,
			InheritableEmpty: true,
			BoundingEmpty:    true,
			AmbientEmpty:     true,
		},
	}
	graph, _, err := networkjail.Compile(
		validCompositionPolicyManifest(),
	)
	if err != nil {
		t.Fatalf("Compile graph: %v", err)
	}
	isolation := validTargetIsolation(graph.Digest().String())
	observed := targetRuntimeObservation{
		Isolation:            isolation,
		RunnerRoutesComplete: true,
		ProbeReport: networkjail.ProbeReport{
			Version:       1,
			PolicyDigest:  graph.Digest().String(),
			EgressBackend: networkjail.RestrictedBrokerV1,
			RunnerNetNSID: networkjail.NamespaceIdentity{
				Device: 1,
				Inode:  2,
			},
			BrokerNetNSID: networkjail.NamespaceIdentity{
				Device: 3,
				Inode:  4,
			},
			RunnerLoopbackOnly:   true,
			RunnerTablesEmpty:    true,
			RunnerConntrackEmpty: true,
			ParserHasNoSocket:    true,
			PositiveOK:           true,
			NegativeOK:           true,
			ConntrackBudgetOK:    true,
		},
	}
	return input, overlay, static, graph, observed
}

func validTargetIsolation(policyDigest string) hostruntime.IsolationEvidence {
	return hostruntime.IsolationEvidence{
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
		PolicyDigest:               policyDigest,
		EvidenceRevision:           "",
	}
}

func validTargetStorageSizing() hostruntime.StorageSizing {
	roles := []hostruntime.StorageRole{
		hostruntime.StorageRoleDockerRoot,
		hostruntime.StorageRoleState,
		hostruntime.StorageRoleStaging,
		hostruntime.StorageRoleRollback,
		hostruntime.StorageRoleScratch,
		hostruntime.StorageRoleLogs,
	}
	result := hostruntime.StorageSizing{
		MaximumActiveConcurrency: 2,
		LogBounds: hostruntime.LogBounds{
			UsedBytes: 10,
			MaxBytes:  100,
			UsedFiles: 2,
			MaxFiles:  10,
		},
		EvidenceRevision: "storage-r1",
	}
	for index, role := range roles {
		result.Observations = append(
			result.Observations,
			hostruntime.StorageObservation{
				Role: role,
				Filesystem: hostruntime.FilesystemIdentity{
					Device: uint64(index + 1),
					Inode:  uint64(index + 101),
				},
				FreeBytes:  10_000,
				FreeInodes: 1_000,
			},
		)
		result.Requirements = append(
			result.Requirements,
			hostruntime.StorageRequirement{
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
			},
		)
	}
	return result
}

func runnerSizingOverlayFromTarget(
	value hostruntime.RunnerSizingTuple,
) hostruntime.RunnerSizingOverlay {
	return hostruntime.RunnerSizingOverlay{
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
		ReclamationObservationCadence: value.
			ReclamationObservationCadence.String(),
		EvidenceRevision: value.EvidenceRevision,
	}
}

func conntrackOverlayFromTarget(
	value hostruntime.ConntrackSizing,
) hostruntime.ConntrackOverlay {
	result := hostruntime.ConntrackOverlay{
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
	for _, timeout := range value.Timeouts {
		result.Timeouts = append(
			result.Timeouts,
			hostruntime.ConntrackTimeoutOverlay(timeout),
		)
	}
	return result
}

func storageOverlayFromTarget(
	value hostruntime.StorageSizing,
) hostruntime.StorageSizingOverlay {
	result := hostruntime.StorageSizingOverlay{
		MaximumActiveConcurrency: value.MaximumActiveConcurrency,
		LogBounds: hostruntime.LogBoundsOverlay{
			UsedBytes: value.LogBounds.UsedBytes,
			MaxBytes:  value.LogBounds.MaxBytes,
			UsedFiles: value.LogBounds.UsedFiles,
			MaxFiles:  value.LogBounds.MaxFiles,
		},
		EvidenceRevision: value.EvidenceRevision,
	}
	for _, observation := range value.Observations {
		result.Observations = append(
			result.Observations,
			hostruntime.StorageObservationOverlay{
				Role:       string(observation.Role),
				Device:     observation.Filesystem.Device,
				Inode:      observation.Filesystem.Inode,
				FreeBytes:  observation.FreeBytes,
				FreeInodes: observation.FreeInodes,
			},
		)
	}
	for _, requirement := range value.Requirements {
		result.Requirements = append(
			result.Requirements,
			hostruntime.StorageRequirementOverlay{
				Role:                   string(requirement.Role),
				CurrentReleaseBytes:    requirement.CurrentReleaseBytes,
				CurrentReleaseInodes:   requirement.CurrentReleaseInodes,
				CandidateReleaseBytes:  requirement.CandidateReleaseBytes,
				CandidateReleaseInodes: requirement.CandidateReleaseInodes,
				ExtractionBytes:        requirement.ExtractionBytes,
				ExtractionInodes:       requirement.ExtractionInodes,
				RollbackBytes:          requirement.RollbackBytes,
				RollbackInodes:         requirement.RollbackInodes,
				PerSlotBytes:           requirement.PerSlotBytes,
				PerSlotInodes:          requirement.PerSlotInodes,
				HelperBytes:            requirement.HelperBytes,
				HelperInodes:           requirement.HelperInodes,
				RelayBytes:             requirement.RelayBytes,
				RelayInodes:            requirement.RelayInodes,
				ControllerBytes:        requirement.ControllerBytes,
				ControllerInodes:       requirement.ControllerInodes,
				LedgerBytes:            requirement.LedgerBytes,
				LedgerInodes:           requirement.LedgerInodes,
				LogBytes:               requirement.LogBytes,
				LogInodes:              requirement.LogInodes,
				HostReserveBytes:       requirement.HostReserveBytes,
				HostReserveInodes:      requirement.HostReserveInodes,
				StopReserveBytes:       requirement.StopReserveBytes,
				StopReserveInodes:      requirement.StopReserveInodes,
				WarningReserveBytes:    requirement.WarningReserveBytes,
				WarningReserveInodes:   requirement.WarningReserveInodes,
			},
		)
	}
	return result
}
