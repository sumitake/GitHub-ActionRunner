package testenv

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type fakeNamespaceEvidenceRuntime struct {
	observation      fixtureRuntimeObservation
	flood            fixtureFloodObservation
	observationCalls int
	floodCalls       int
}

type fakeBrokerCaseRuntime struct {
	observation brokerCaseRuntimeObservation
	calls       int
}

type fakeMountSecretRuntime struct {
	observation mountSecretRuntimeObservation
	calls       int
}

type fakeSandboxRuntime struct {
	observation sandboxRuntimeObservation
	calls       int
}

type fakeRunnerPayloadRuntime struct {
	observation runnerPayloadRuntimeObservation
	calls       int
}

type fakeSyntheticOneJobRuntime struct {
	observation syntheticOneJobRuntimeObservation
	calls       int
}

type fakeCleanupMatrixRuntime struct {
	observation cleanupMatrixRuntimeObservation
	calls       int
}

func (r *fakeCleanupMatrixRuntime) CleanupMatrixObservation(
	context.Context,
	fixtureRuntimeObservation,
) (cleanupMatrixRuntimeObservation, error) {
	r.calls++
	if r.calls != 1 {
		return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func validCleanupMatrixRuntime() *fakeCleanupMatrixRuntime {
	proof := func(digest string) CompleteCleanupProof {
		value := completeCleanupProof()
		value.ObservationDigest = digest
		return value
	}
	return &fakeCleanupMatrixRuntime{
		observation: cleanupMatrixRuntimeObservation{
			Success:             proof(inputDigestA),
			Cancellation:        proof(inputDigestB),
			PreListenerFailure:  proof(inputDigestC),
			ListenerCrash:       proof(inputDigestD),
			ControllerRestart:   proof(inputDigestA),
			UpgradeInterruption: proof(inputDigestB),
		},
	}
}

func (r *fakeSyntheticOneJobRuntime) SyntheticOneJobObservation(
	context.Context,
	fixtureRuntimeObservation,
) (syntheticOneJobRuntimeObservation, error) {
	r.calls++
	if r.calls != 1 {
		return syntheticOneJobRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func validSyntheticOneJobRuntime() *fakeSyntheticOneJobRuntime {
	return &fakeSyntheticOneJobRuntime{
		observation: syntheticOneJobRuntimeObservation{
			JobCompleted:         true,
			JobCompletionDigest:  inputDigestA,
			ProxyRequestComplete: true,
			ProxyRequestDigest:   inputDigestB,
			Deregistered:         true,
			DeregistrationDigest: inputDigestC,
			Reclaimed:            true,
			ReclamationDigest:    inputDigestD,
		},
	}
}

func (r *fakeRunnerPayloadRuntime) RunnerPayloadObservation(
	context.Context,
	fixtureRuntimeObservation,
) (runnerPayloadRuntimeObservation, error) {
	r.calls++
	if r.calls != 1 {
		return runnerPayloadRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func validRunnerPayloadRuntime() *fakeRunnerPayloadRuntime {
	return &fakeRunnerPayloadRuntime{
		observation: runnerPayloadRuntimeObservation{
			SinglePayload:          true,
			SinglePayloadDigest:    inputDigestA,
			ListenerVersionMatches: true,
			ListenerVersionDigest:  inputDigestB,
			NoVersionPair:          true,
			NoVersionPairDigest:    inputDigestC,
			NoFileSweeper:          true,
			NoFileSweeperDigest:    inputDigestD,
			NoBakedJIT:             true,
			NoBakedJITDigest:       inputDigestA,
		},
	}
}

func (r *fakeSandboxRuntime) SandboxObservation(
	context.Context,
	fixtureRuntimeObservation,
) (sandboxRuntimeObservation, error) {
	r.calls++
	if r.calls != 1 {
		return sandboxRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func validSandboxRuntime() *fakeSandboxRuntime {
	return &fakeSandboxRuntime{
		observation: sandboxRuntimeObservation{
			NamespaceDenied:            true,
			RawSocketDenied:            true,
			BPFDenied:                  true,
			UnshareDenied:              true,
			SetNSDenied:                true,
			Clone3Denied:               true,
			SyscallDenialDigest:        inputDigestA,
			ProcMaskProven:             true,
			ProcMaskDigest:             inputDigestB,
			IdentityCapabilitiesValid:  true,
			IdentityCapabilitiesDigest: inputDigestC,
		},
	}
}

func (r *fakeMountSecretRuntime) MountSecretObservation(
	context.Context,
	fixtureRuntimeObservation,
) (mountSecretRuntimeObservation, error) {
	r.calls++
	if r.calls != 1 {
		return mountSecretRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func validMountSecretRuntime() *fakeMountSecretRuntime {
	return &fakeMountSecretRuntime{
		observation: mountSecretRuntimeObservation{
			MountTopologyProven:         true,
			MountTopologyDigest:         inputDigestA,
			OneShotMountAbsenceProven:   true,
			OneShotMountAbsenceDigest:   inputDigestB,
			ControllerSQLiteInvisible:   true,
			ControllerSQLiteDigest:      inputDigestC,
			HostControlInvisible:        true,
			HostControlDigest:           inputDigestD,
			RuntimeSecretScanClean:      true,
			RuntimeSecretScanDigest:     inputDigestA,
			SyntheticTokenAbsent:        true,
			SyntheticTokenAbsenceDigest: inputDigestB,
		},
	}
}

func (r *fakeBrokerCaseRuntime) BrokerCaseObservation(
	context.Context,
	fixtureRuntimeObservation,
) (brokerCaseRuntimeObservation, error) {
	r.calls++
	if r.calls != 1 {
		return brokerCaseRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func validBrokerCaseRuntime() *fakeBrokerCaseRuntime {
	return &fakeBrokerCaseRuntime{
		observation: brokerCaseRuntimeObservation{
			DirectProtocolsDenied:     true,
			DirectProtocolsDigest:     inputDigestA,
			PlaintextHTTPDenied:       true,
			PlaintextHTTPDigest:       inputDigestB,
			ConnectPortDenied:         true,
			ConnectPortDigest:         inputDigestC,
			SOCKSOperationsDenied:     true,
			SOCKSOperationsDigest:     inputDigestD,
			DenialBoundaryDigest:      inputDigestC,
			FloodBoundsProven:         true,
			FloodBoundsDigest:         inputDigestA,
			LossPreventsRelease:       true,
			LossPreventsReleaseDigest: inputDigestB,
		},
	}
}

func (r *fakeNamespaceEvidenceRuntime) RuntimeObservation(
	context.Context,
) (fixtureRuntimeObservation, error) {
	r.observationCalls++
	if r.observationCalls != 1 {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	return r.observation, nil
}

func (r *fakeNamespaceEvidenceRuntime) LoopbackFlood(
	_ context.Context,
	attempts uint32,
) (fixtureFloodObservation, error) {
	r.floodCalls++
	if r.floodCalls != 1 ||
		uint64(attempts) != r.flood.Report.Attempts {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	return r.flood, nil
}

func validNamespaceEvidenceRuntime() *fakeNamespaceEvidenceRuntime {
	probe := networkjail.ProbeReport{
		Version:       1,
		PolicyDigest:  inputDigestA,
		EgressBackend: networkjail.RestrictedBrokerV1,
		RunnerNetNSID: networkjail.NamespaceIdentity{
			Device: 31,
			Inode:  32,
		},
		BrokerNetNSID: networkjail.NamespaceIdentity{
			Device: 41,
			Inode:  42,
		},
		RunnerLoopbackOnly:   true,
		RunnerTablesEmpty:    true,
		RunnerConntrackEmpty: true,
		ParserHasNoSocket:    true,
		PositiveOK:           true,
		NegativeOK:           true,
		ConntrackBudgetOK:    true,
	}
	return &fakeNamespaceEvidenceRuntime{
		observation: fixtureRuntimeObservation{
			Adapter:                 cleanupHandle{kind: CleanupAdapter, id: inputDigestB},
			Broker:                  cleanupHandle{kind: CleanupBroker, id: inputDigestC},
			Runner:                  cleanupHandle{kind: CleanupRunner, id: inputDigestD},
			AdapterSpecDigest:       inputDigestA,
			BrokerSpecDigest:        inputDigestB,
			RunnerSpecDigest:        inputDigestC,
			VerifierSpecDigest:      inputDigestD,
			AdapterEmptinessDigest:  inputDigestA,
			AdapterNamespace:        hostruntime.NetworkNamespaceIdentity{Device: 31, Inode: 32},
			PolicyDigest:            inputDigestA,
			PolicyApplicationDigest: inputDigestB,
			HelperCapabilityDigest:  inputDigestC,
			AuthorityBindingReceipt: inputDigestD,
			BrokerPeerBindingDigest: inputDigestA,
			NetworkEgressDigest:     inputDigestB,
			NetworkEgressReport: hostruntime.NetworkVerifierReport{
				PolicyDigest:         inputDigestA,
				EgressBackend:        string(networkjail.RestrictedBrokerV1),
				RunnerNetNSID:        hostruntime.NetworkNamespaceIdentity{Device: 31, Inode: 32},
				BrokerNetNSID:        hostruntime.NetworkNamespaceIdentity{Device: 41, Inode: 42},
				RunnerLoopbackOnly:   true,
				RunnerTablesEmpty:    true,
				RunnerConntrackEmpty: true,
				ParserHasNoSocket:    true,
				PositiveOK:           true,
				NegativeOK:           true,
			},
			NamespacePreArmReceipt:       inputDigestC,
			NamespaceFinalReceipt:        inputDigestD,
			ReleaseAuthorizationReceipt:  inputDigestA,
			RuntimeCapabilityDigest:      inputDigestB,
			PreparedEvidenceDigest:       inputDigestC,
			BrokerAuditDigest:            inputDigestD,
			RunnerAuditDigest:            inputDigestA,
			HeldSocketZeroDigest:         inputDigestB,
			BrokerReleaseDigest:          inputDigestC,
			PermitUsageDigest:            inputDigestD,
			PermitAuthorityBindingDigest: inputDigestA,
			ProbeMembershipDigest:        inputDigestB,
			PreparedProbeBindingDigest:   inputDigestC,
			ProbeReport:                  probe,
		},
		flood: fixtureFloodObservation{
			EvidenceDigest: inputDigestD,
			Report: hostruntime.LoopbackFloodReport{
				Attempts:       64,
				Completed:      true,
				Namespace:      hostruntime.NetworkNamespaceIdentity{Device: 31, Inode: 32},
				LoopbackOnly:   true,
				TablesEmpty:    true,
				ConntrackEmpty: true,
				RoutesComplete: true,
			},
		},
	}
}

func TestHostProfileMatrixSourceSealsEveryClosedHostObservation(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, _, _ := validTargetFinalizerInputs(t)
	source, err := newHostProfileMatrixSource(
		input,
		overlay,
		static,
	)
	if err != nil {
		t.Fatalf("newHostProfileMatrixSource: %v", err)
	}
	var got []ObservationID
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Source != SourceHostProfile {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		if observation.Requirement != requirement ||
			observation.AssertionCount == 0 ||
			!isLowerHex(observation.Digest, 64) {
			t.Fatalf("observation %s = %+v", requirement.ID, observation)
		}
		got = append(got, requirement.ID)
	}
	want := []ObservationID{
		"host-os-architecture",
		"host-kernel-runtime",
		"host-euid-profile",
		"host-capability-sets",
		"host-cgroup-controls",
		"host-sizing-envelopes",
		"host-effective-capacity",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("host observation IDs = %v, want %v", got, want)
	}
}

func TestHostProfileMatrixSourceRejectsSubstitutionAndExpectedAnchors(
	t *testing.T,
) {
	t.Parallel()

	input, overlay, static, _, _ := validTargetFinalizerInputs(t)
	first, err := newHostProfileMatrixSource(input, overlay, static)
	if err != nil {
		t.Fatalf("newHostProfileMatrixSource: %v", err)
	}
	mutated := input
	mutated.Runtime.ExpectedProfileEvidenceDigest =
		strings.Repeat("e", 64)
	mutated.Runtime.ExpectedNetworkEvidenceDigest =
		strings.Repeat("f", 64)
	second, err := newHostProfileMatrixSource(mutated, overlay, static)
	if err != nil {
		t.Fatalf("new mutated source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Source != SourceHostProfile {
			continue
		}
		one, err := first.Observe(context.Background(), requirement)
		if err != nil {
			t.Fatalf("first Observe(%s): %v", requirement.ID, err)
		}
		two, err := second.Observe(context.Background(), requirement)
		if err != nil {
			t.Fatalf("second Observe(%s): %v", requirement.ID, err)
		}
		if one.Digest != two.Digest {
			t.Fatalf(
				"expected anchors changed %s digest: %s != %s",
				requirement.ID,
				one.Digest,
				two.Digest,
			)
		}
	}

	requirement := RequiredObservationMatrix()[0]
	requirement.Operation = "profile-runtime"
	if _, err := first.Observe(
		context.Background(),
		requirement,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("substitution error = %v", err)
	}
}

func TestSealTypedMatrixObservationRejectsOversizeAndUnknownRows(
	t *testing.T,
) {
	t.Parallel()

	requirement := RequiredObservationMatrix()[0]
	if _, err := sealTypedMatrixObservation(
		requirement,
		1,
		nil,
		struct {
			Value string `json:"value"`
		}{Value: "linux"},
	); err != nil {
		t.Fatalf("sealTypedMatrixObservation: %v", err)
	}
	unknown := requirement
	unknown.ID = "host-substitute"
	if _, err := sealTypedMatrixObservation(
		unknown,
		1,
		nil,
		struct {
			Value string `json:"value"`
		}{Value: "linux"},
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unknown row error = %v", err)
	}
	small := requirement
	small.MaxBytes = 1
	if _, err := sealTypedMatrixObservation(
		small,
		1,
		nil,
		struct {
			Value string `json:"value"`
		}{Value: "linux"},
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestNamespaceBaselineSourceAcquiresOnceAndFreezesExactRows(
	t *testing.T,
) {
	t.Parallel()

	runtime := validNamespaceEvidenceRuntime()
	source, err := newNamespaceBaselineMatrixSource(64, runtime)
	if err != nil {
		t.Fatalf("newNamespaceBaselineMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseNamespaceBaseline {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		if observation.Requirement != requirement ||
			observation.AssertionCount == 0 ||
			!isLowerHex(observation.Digest, 64) {
			t.Fatalf("observation %s = %+v", requirement.ID, observation)
		}
		observations = append(observations, observation)
	}
	if runtime.observationCalls != 1 || runtime.floodCalls != 1 {
		t.Fatalf(
			"runtime/flood calls = %d/%d",
			runtime.observationCalls,
			runtime.floodCalls,
		)
	}
	if len(observations) != 11 {
		t.Fatalf("namespace observations = %d", len(observations))
	}
	if observations[4].Measurements[0] != (conformance.MeasurementInput{
		Name: "loopback_flood_attempts", Value: 64, Unit: "count",
	}) {
		t.Fatalf("flood measurement = %+v", observations[4].Measurements)
	}
	for index := 5; index <= 7; index++ {
		if observations[index].Digest == observations[4].Digest {
			t.Fatalf(
				"post-flood row %s aliased flood digest",
				observations[index].Requirement.ID,
			)
		}
	}
	if _, err := source.Observe(
		context.Background(),
		observations[0].Requirement,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("post-freeze replay error = %v", err)
	}
}

func TestNamespaceBaselineSourceRejectsReorderAndIdentityDrift(
	t *testing.T,
) {
	t.Parallel()

	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseNamespaceBaseline {
			requirements = append(requirements, requirement)
		}
	}
	reorderedRuntime := validNamespaceEvidenceRuntime()
	reordered, err := newNamespaceBaselineMatrixSource(
		64,
		reorderedRuntime,
	)
	if err != nil {
		t.Fatalf("new reordered source: %v", err)
	}
	if _, err := reordered.Observe(
		context.Background(),
		requirements[1],
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("reordered error = %v", err)
	}
	if reorderedRuntime.observationCalls != 0 ||
		reorderedRuntime.floodCalls != 0 {
		t.Fatalf(
			"reordered calls = %d/%d",
			reorderedRuntime.observationCalls,
			reorderedRuntime.floodCalls,
		)
	}

	driftRuntime := validNamespaceEvidenceRuntime()
	driftRuntime.flood.Report.Namespace.Inode++
	drift, err := newNamespaceBaselineMatrixSource(64, driftRuntime)
	if err != nil {
		t.Fatalf("new drift source: %v", err)
	}
	if _, err := drift.Observe(
		context.Background(),
		requirements[0],
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("identity drift error = %v", err)
	}
	if _, err := drift.Observe(
		context.Background(),
		requirements[0],
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("identity drift replay error = %v", err)
	}
	if driftRuntime.observationCalls != 1 ||
		driftRuntime.floodCalls != 1 {
		t.Fatalf(
			"identity drift calls = %d/%d",
			driftRuntime.observationCalls,
			driftRuntime.floodCalls,
		)
	}
}

func TestPreparedRuntimeObservationRejectsCrossObjectSubstitution(
	t *testing.T,
) {
	t.Parallel()

	valid := validNamespaceEvidenceRuntime().observation
	if !validFixtureRuntimeObservation(valid) {
		t.Fatal("valid prepared observation was rejected")
	}
	tests := []struct {
		name   string
		mutate func(*fixtureRuntimeObservation)
	}{
		{
			name: "adapter namespace drift",
			mutate: func(value *fixtureRuntimeObservation) {
				value.AdapterNamespace.Inode++
			},
		},
		{
			name: "egress policy substitution",
			mutate: func(value *fixtureRuntimeObservation) {
				value.NetworkEgressReport.PolicyDigest = inputDigestD
			},
		},
		{
			name: "egress runner namespace substitution",
			mutate: func(value *fixtureRuntimeObservation) {
				value.NetworkEgressReport.RunnerNetNSID.Device++
			},
		},
		{
			name: "missing release receipt",
			mutate: func(value *fixtureRuntimeObservation) {
				value.ReleaseAuthorizationReceipt = ""
			},
		},
		{
			name: "cross-kind handle reuse",
			mutate: func(value *fixtureRuntimeObservation) {
				value.Runner.id = value.Adapter.id
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := valid
			test.mutate(&mutated)
			if validFixtureRuntimeObservation(mutated) {
				t.Fatal("accepted substituted prepared observation")
			}
		})
	}
}

func TestBrokerEgressSourceConsumesFrozenCase2AndClosedRowsOnce(
	t *testing.T,
) {
	t.Parallel()

	namespaceRuntime := validNamespaceEvidenceRuntime()
	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		namespaceRuntime,
	)
	if err != nil {
		t.Fatalf("newPreparedRuntimeEvidenceLedger: %v", err)
	}
	namespace, err := newNamespaceBaselineMatrixSourceFromLedger(ledger)
	if err != nil {
		t.Fatalf("new namespace source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseNamespaceBaseline {
			continue
		}
		if _, err := namespace.Observe(
			context.Background(),
			requirement,
		); err != nil {
			t.Fatalf("namespace Observe(%s): %v", requirement.ID, err)
		}
	}

	runtime := validBrokerCaseRuntime()
	source, err := newBrokerEgressMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newBrokerEgressMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseBrokerEgress {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
	}
	if len(observations) != 12 || runtime.calls != 1 {
		t.Fatalf(
			"broker observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
	for _, observation := range observations {
		if observation.AssertionCount == 0 ||
			!isLowerHex(observation.Digest, 64) {
			t.Fatalf(
				"broker observation %s = %+v",
				observation.Requirement.ID,
				observation,
			)
		}
	}
}

func TestBrokerEgressSourceRejectsUnfrozenOrFalseClosedEvidence(
	t *testing.T,
) {
	t.Parallel()

	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := validBrokerCaseRuntime()
	unfrozen, err := newBrokerEgressMatrixSource(
		unfrozenLedger,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseBrokerEgress {
			first = requirement
			break
		}
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if unfrozenRuntime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", unfrozenRuntime.calls)
	}

	namespaceRuntime := validNamespaceEvidenceRuntime()
	ledger, err := newPreparedRuntimeEvidenceLedger(64, namespaceRuntime)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	namespace, err := newNamespaceBaselineMatrixSourceFromLedger(ledger)
	if err != nil {
		t.Fatalf("new namespace source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseNamespaceBaseline {
			if _, err := namespace.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf("namespace Observe(%s): %v", requirement.ID, err)
			}
		}
	}
	invalidRuntime := validBrokerCaseRuntime()
	invalidRuntime.observation.ConnectPortDenied = false
	invalid, err := newBrokerEgressMatrixSource(ledger, invalidRuntime)
	if err != nil {
		t.Fatalf("new invalid source: %v", err)
	}
	if _, err := invalid.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("false closed evidence error = %v", err)
	}
	if invalidRuntime.calls != 1 {
		t.Fatalf("invalid runtime calls = %d", invalidRuntime.calls)
	}
}

func TestMountSecretSourceConsumesFrozenCase3AndClosedRowsOnce(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughBrokerEgress(t, ledger)

	runtime := validMountSecretRuntime()
	source, err := newMountSecretMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newMountSecretMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case !=
			conformance.CaseMountAndSecretIsolation {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
	}
	if len(observations) != 6 || runtime.calls != 1 {
		t.Fatalf(
			"mount observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
	for _, observation := range observations {
		if observation.AssertionCount == 0 ||
			!isLowerHex(observation.Digest, 64) {
			t.Fatalf(
				"mount observation %s = %+v",
				observation.Requirement.ID,
				observation,
			)
		}
	}
}

func TestMountSecretSourceRejectsUnfrozenOrFalseClosedEvidence(
	t *testing.T,
) {
	t.Parallel()

	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := validMountSecretRuntime()
	unfrozen, err := newMountSecretMatrixSource(
		unfrozenLedger,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case ==
			conformance.CaseMountAndSecretIsolation {
			first = requirement
			break
		}
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if unfrozenRuntime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", unfrozenRuntime.calls)
	}

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughBrokerEgress(t, ledger)
	invalidRuntime := validMountSecretRuntime()
	invalidRuntime.observation.HostControlInvisible = false
	invalid, err := newMountSecretMatrixSource(ledger, invalidRuntime)
	if err != nil {
		t.Fatalf("new invalid source: %v", err)
	}
	if _, err := invalid.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("false closed evidence error = %v", err)
	}
	if invalidRuntime.calls != 1 {
		t.Fatalf("invalid runtime calls = %d", invalidRuntime.calls)
	}
}

func TestSandboxSourceConsumesFrozenCase4AndClosedRowsOnce(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughMountSecrets(t, ledger)

	runtime := validSandboxRuntime()
	source, err := newSandboxMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newSandboxMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseSandbox {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
	}
	if len(observations) != 7 || runtime.calls != 1 {
		t.Fatalf(
			"sandbox observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
	for _, observation := range observations {
		if observation.AssertionCount == 0 ||
			!isLowerHex(observation.Digest, 64) {
			t.Fatalf(
				"sandbox observation %s = %+v",
				observation.Requirement.ID,
				observation,
			)
		}
	}
}

func TestSandboxSourceRejectsUnfrozenOrIncompleteDenials(
	t *testing.T,
) {
	t.Parallel()

	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := validSandboxRuntime()
	unfrozen, err := newSandboxMatrixSource(
		unfrozenLedger,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSandbox {
			first = requirement
			break
		}
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if unfrozenRuntime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", unfrozenRuntime.calls)
	}

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughMountSecrets(t, ledger)
	invalidRuntime := validSandboxRuntime()
	invalidRuntime.observation.Clone3Denied = false
	invalid, err := newSandboxMatrixSource(ledger, invalidRuntime)
	if err != nil {
		t.Fatalf("new invalid source: %v", err)
	}
	if _, err := invalid.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("incomplete denial error = %v", err)
	}
	if invalidRuntime.calls != 1 {
		t.Fatalf("invalid runtime calls = %d", invalidRuntime.calls)
	}
}

func TestRunnerPayloadSourceConsumesFrozenCase5AndClosedRowsOnce(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughSandbox(t, ledger)

	runtime := validRunnerPayloadRuntime()
	source, err := newRunnerPayloadMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newRunnerPayloadMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseRunnerPayload {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
	}
	if len(observations) != 5 || runtime.calls != 1 {
		t.Fatalf(
			"payload observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
}

func TestRunnerPayloadSourceRejectsUnfrozenOrStagedVersionPair(
	t *testing.T,
) {
	t.Parallel()

	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := validRunnerPayloadRuntime()
	unfrozen, err := newRunnerPayloadMatrixSource(
		unfrozenLedger,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseRunnerPayload {
			first = requirement
			break
		}
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if unfrozenRuntime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", unfrozenRuntime.calls)
	}

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughSandbox(t, ledger)
	invalidRuntime := validRunnerPayloadRuntime()
	invalidRuntime.observation.NoVersionPair = false
	invalid, err := newRunnerPayloadMatrixSource(
		ledger,
		invalidRuntime,
	)
	if err != nil {
		t.Fatalf("new invalid source: %v", err)
	}
	if _, err := invalid.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("version pair error = %v", err)
	}
	if invalidRuntime.calls != 1 {
		t.Fatalf("invalid runtime calls = %d", invalidRuntime.calls)
	}
}

func TestSyntheticOneJobSourceConsumesFrozenCase6AndClosedRowsOnce(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughRunnerPayload(t, ledger)

	runtime := validSyntheticOneJobRuntime()
	source, err := newSyntheticOneJobMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newSyntheticOneJobMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseSyntheticOneJob {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
	}
	if len(observations) != 4 || runtime.calls != 1 {
		t.Fatalf(
			"one-job observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
}

func TestSyntheticOneJobSourceRejectsUnfrozenOrIncompleteReclamation(
	t *testing.T,
) {
	t.Parallel()

	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := validSyntheticOneJobRuntime()
	unfrozen, err := newSyntheticOneJobMatrixSource(
		unfrozenLedger,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSyntheticOneJob {
			first = requirement
			break
		}
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if unfrozenRuntime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", unfrozenRuntime.calls)
	}

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughRunnerPayload(t, ledger)
	invalidRuntime := validSyntheticOneJobRuntime()
	invalidRuntime.observation.Reclaimed = false
	invalid, err := newSyntheticOneJobMatrixSource(
		ledger,
		invalidRuntime,
	)
	if err != nil {
		t.Fatalf("new invalid source: %v", err)
	}
	if _, err := invalid.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("reclamation error = %v", err)
	}
	if invalidRuntime.calls != 1 {
		t.Fatalf("invalid runtime calls = %d", invalidRuntime.calls)
	}
}

func TestCleanupMatrixSourceConsumesFrozenCase7AndEveryClosedRow(
	t *testing.T,
) {
	t.Parallel()

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughSyntheticOneJob(t, ledger)
	runtime := validCleanupMatrixRuntime()
	source, err := newCleanupMatrixSource(ledger, runtime)
	if err != nil {
		t.Fatalf("newCleanupMatrixSource: %v", err)
	}
	var observations []matrixObservation
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case != conformance.CaseCleanupMatrix {
			continue
		}
		observation, err := source.Observe(
			context.Background(),
			requirement,
		)
		if err != nil {
			t.Fatalf("Observe(%s): %v", requirement.ID, err)
		}
		observations = append(observations, observation)
	}
	if len(observations) != 6 || runtime.calls != 1 {
		t.Fatalf(
			"cleanup observations/calls = %d/%d",
			len(observations),
			runtime.calls,
		)
	}
}

func TestCleanupMatrixSourceRejectsUnfrozenOrResidualUpdateState(
	t *testing.T,
) {
	t.Parallel()

	unfrozenLedger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new unfrozen ledger: %v", err)
	}
	unfrozenRuntime := validCleanupMatrixRuntime()
	unfrozen, err := newCleanupMatrixSource(
		unfrozenLedger,
		unfrozenRuntime,
	)
	if err != nil {
		t.Fatalf("new unfrozen source: %v", err)
	}
	var first ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseCleanupMatrix {
			first = requirement
			break
		}
	}
	if _, err := unfrozen.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("unfrozen error = %v", err)
	}
	if unfrozenRuntime.calls != 0 {
		t.Fatalf("unfrozen runtime calls = %d", unfrozenRuntime.calls)
	}

	ledger, err := newPreparedRuntimeEvidenceLedger(
		64,
		validNamespaceEvidenceRuntime(),
	)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	freezeThroughSyntheticOneJob(t, ledger)
	invalidRuntime := validCleanupMatrixRuntime()
	invalidRuntime.observation.UpgradeInterruption.WorkUpdateAbsent = false
	invalid, err := newCleanupMatrixSource(ledger, invalidRuntime)
	if err != nil {
		t.Fatalf("new invalid source: %v", err)
	}
	if _, err := invalid.Observe(
		context.Background(),
		first,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("residual update error = %v", err)
	}
	if invalidRuntime.calls != 1 {
		t.Fatalf("invalid runtime calls = %d", invalidRuntime.calls)
	}
}

func freezeThroughBrokerEgress(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	namespace, err := newNamespaceBaselineMatrixSourceFromLedger(ledger)
	if err != nil {
		t.Fatalf("new namespace source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseNamespaceBaseline {
			if _, err := namespace.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"namespace Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
	broker, err := newBrokerEgressMatrixSource(
		ledger,
		validBrokerCaseRuntime(),
	)
	if err != nil {
		t.Fatalf("new broker source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseBrokerEgress {
			if _, err := broker.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"broker Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughMountSecrets(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughBrokerEgress(t, ledger)
	mounts, err := newMountSecretMatrixSource(
		ledger,
		validMountSecretRuntime(),
	)
	if err != nil {
		t.Fatalf("new mount source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case ==
			conformance.CaseMountAndSecretIsolation {
			if _, err := mounts.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"mount Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughSandbox(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughMountSecrets(t, ledger)
	sandbox, err := newSandboxMatrixSource(
		ledger,
		validSandboxRuntime(),
	)
	if err != nil {
		t.Fatalf("new sandbox source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSandbox {
			if _, err := sandbox.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"sandbox Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughRunnerPayload(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughSandbox(t, ledger)
	payload, err := newRunnerPayloadMatrixSource(
		ledger,
		validRunnerPayloadRuntime(),
	)
	if err != nil {
		t.Fatalf("new payload source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseRunnerPayload {
			if _, err := payload.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"payload Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughSyntheticOneJob(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughRunnerPayload(t, ledger)
	oneJob, err := newSyntheticOneJobMatrixSource(
		ledger,
		validSyntheticOneJobRuntime(),
	)
	if err != nil {
		t.Fatalf("new one-job source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSyntheticOneJob {
			if _, err := oneJob.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"one-job Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughCleanupMatrix(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughSyntheticOneJob(t, ledger)
	cleanup, err := newCleanupMatrixSource(
		ledger,
		validCleanupMatrixRuntime(),
	)
	if err != nil {
		t.Fatalf("new cleanup source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseCleanupMatrix {
			if _, err := cleanup.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"cleanup Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughReclamation(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughCleanupMatrix(t, ledger)
	baselines, sampleCount, runtime := validReclamationInputs()
	reclamation, err := newReclamationMatrixSource(
		ledger,
		baselines,
		sampleCount,
		runtime,
	)
	if err != nil {
		t.Fatalf("new reclamation source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseReclamationSeries {
			if _, err := reclamation.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"reclamation Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughWorkflowTools(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughReclamation(t, ledger)
	bindings, users, limits, seccomp := validWorkflowToolSourceInputs(t)
	source, err := newWorkflowToolMatrixSource(
		ledger,
		bindings,
		users,
		limits,
		seccomp,
		newFakeWorkflowToolRuntime(),
	)
	if err != nil {
		t.Fatalf("new workflow-tool source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case ==
			conformance.CaseProxyToolCompatibility {
			if _, err := source.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"workflow-tool Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}

func freezeThroughSeedIsolation(
	t *testing.T,
	ledger *preparedRuntimeEvidenceLedger,
) {
	t.Helper()
	freezeThroughWorkflowTools(t, ledger)
	source, err := newSeedIsolationMatrixSource(
		ledger,
		&fakeSeedIsolationRuntime{
			proof: validSeedIsolationProof(),
		},
	)
	if err != nil {
		t.Fatalf("new seed isolation source: %v", err)
	}
	for _, requirement := range RequiredObservationMatrix() {
		if requirement.Case == conformance.CaseSeedIsolation {
			if _, err := source.Observe(
				context.Background(),
				requirement,
			); err != nil {
				t.Fatalf(
					"seed Observe(%s): %v",
					requirement.ID,
					err,
				)
			}
		}
	}
}
