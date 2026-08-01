package testenv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/buildinfo"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type fakeTask11PreparedRuntime struct {
	prepared      fixtureRuntimeObservation
	flood         fixtureFloodObservation
	slot          networkjail.CapacitySlotID
	generation    networkjail.JobGeneration
	snapshotCalls int
	permitCalls   int
}

func (r *fakeTask11PreparedRuntime) SnapshotPreparedEvidence(
	_ context.Context,
	prepared fixtureRuntimeObservation,
) (fixtureFloodObservation, error) {
	r.snapshotCalls++
	if !sameTask11PreparedObservation(
		prepared,
		r.prepared,
		r.flood,
	) {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	return r.flood, nil
}

func (r *fakeTask11PreparedRuntime) ProvePermitNonconsumption(
	_ context.Context,
	closed closedDenialsSessionObservation,
) (permitNonconsumptionProof, error) {
	r.permitCalls++
	return sealPermitNonconsumption(permitNonconsumptionInput{
		PreparedUsageDigest: r.prepared.PermitUsageDigest,
		RepeatedAuditDigest: r.prepared.PermitUsageDigest,
		PolicyDigest:        r.prepared.PolicyDigest,
		Slot:                r.slot,
		Generation:          r.generation,
		ClosedDenialsDigest: closed.Digest,
	})
}

type fakeTask11ClosedDenialsRuntime struct {
	observation closedDenialsSessionObservation
	calls       int
}

func (r *fakeTask11ClosedDenialsRuntime) ObserveClosedDenials(
	context.Context,
	fixtureRuntimeObservation,
) (closedDenialsSessionObservation, error) {
	r.calls++
	if r.calls != 1 {
		return closedDenialsSessionObservation{}, ErrClosedCommand
	}
	return r.observation, nil
}

type fakeTask11LossPreventionRuntime struct {
	calls         int
	mismatchProof bool
}

func (r *fakeTask11LossPreventionRuntime) ProveLossPreventsRelease(
	_ context.Context,
	_ fixtureRuntimeObservation,
	primarySeal string,
) (task11LossPreventsReleaseProof, error) {
	r.calls++
	if r.calls != 1 {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	if r.mismatchProof {
		primarySeal = inputDigestA
	}
	return newTask11LossPreventsReleaseProof(
		primarySeal,
		inputDigestD,
	)
}

type fakeTask11CaseFourCaptureRuntime struct {
	observation task11CaseFourRuntimeCapture
	calls       int
}

func (r *fakeTask11CaseFourCaptureRuntime) CaptureCaseFour(
	context.Context,
	fixtureRuntimeObservation,
	fixtureFloodObservation,
	closedDenialsSessionObservation,
) (task11CaseFourRuntimeCapture, error) {
	r.calls++
	if r.calls != 1 {
		return task11CaseFourRuntimeCapture{}, ErrFixtureStart
	}
	return r.observation, nil
}

func TestTask11CasesThreeToSixRuntimeAcquiresOnceAndCachesLaterCases(
	t *testing.T,
) {
	t.Parallel()

	runtime, prepared, dependencies :=
		validTask11CasesThreeToSixRuntime(t)
	broker, err := runtime.BrokerCaseObservation(
		context.Background(),
		prepared,
	)
	if err != nil {
		t.Fatalf("BrokerCaseObservation: %v", err)
	}
	if !validBrokerCaseRuntimeObservation(broker) {
		t.Fatalf("broker observation = %+v", broker)
	}
	requireDistinctTask11Digests(t, []string{
		broker.DirectProtocolsDigest,
		broker.PlaintextHTTPDigest,
		broker.ConnectPortDigest,
		broker.SOCKSOperationsDigest,
		broker.DenialBoundaryDigest,
		broker.FloodBoundsDigest,
		broker.LossPreventsReleaseDigest,
	})

	mounts, err := runtime.MountSecretObservation(
		context.Background(),
		prepared,
	)
	if err != nil {
		t.Fatalf("MountSecretObservation: %v", err)
	}
	if !validMountSecretRuntimeObservation(mounts) {
		t.Fatalf("mount observation = %+v", mounts)
	}
	requireDistinctTask11Digests(t, []string{
		mounts.MountTopologyDigest,
		mounts.OneShotMountAbsenceDigest,
		mounts.ControllerSQLiteDigest,
		mounts.HostControlDigest,
		mounts.RuntimeSecretScanDigest,
		mounts.SyntheticTokenAbsenceDigest,
	})

	sandbox, err := runtime.SandboxObservation(
		context.Background(),
		prepared,
	)
	if err != nil {
		t.Fatalf("SandboxObservation: %v", err)
	}
	if !validSandboxRuntimeObservation(sandbox) {
		t.Fatalf("sandbox observation = %+v", sandbox)
	}
	requireDistinctTask11Digests(t, []string{
		sandbox.SyscallDenialDigest,
		sandbox.ProcMaskDigest,
		sandbox.IdentityCapabilitiesDigest,
	})

	payload, err := runtime.RunnerPayloadObservation(
		context.Background(),
		prepared,
	)
	if err != nil {
		t.Fatalf("RunnerPayloadObservation: %v", err)
	}
	if !validRunnerPayloadRuntimeObservation(payload) {
		t.Fatalf("payload observation = %+v", payload)
	}
	requireDistinctTask11Digests(t, []string{
		payload.SinglePayloadDigest,
		payload.ListenerVersionDigest,
		payload.NoVersionPairDigest,
		payload.NoFileSweeperDigest,
		payload.NoBakedJITDigest,
	})

	if dependencies.prepared.snapshotCalls != 2 ||
		dependencies.prepared.permitCalls != 1 ||
		dependencies.closed.calls != 1 ||
		dependencies.loss.calls != 1 ||
		dependencies.capture.calls != 1 {
		t.Fatalf(
			"calls snapshot=%d permit=%d closed=%d loss=%d capture=%d",
			dependencies.prepared.snapshotCalls,
			dependencies.prepared.permitCalls,
			dependencies.closed.calls,
			dependencies.loss.calls,
			dependencies.capture.calls,
		)
	}
}

func TestTask11CasesThreeToSixRuntimeRejectsPhaseCrossingAndSubstitution(
	t *testing.T,
) {
	t.Parallel()

	runtime, prepared, _ := validTask11CasesThreeToSixRuntime(t)
	if _, err := runtime.MountSecretObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("out-of-order mount error = %v", err)
	}

	runtime, prepared, _ = validTask11CasesThreeToSixRuntime(t)
	if _, err := runtime.BrokerCaseObservation(
		context.Background(),
		prepared,
	); err != nil {
		t.Fatalf("BrokerCaseObservation: %v", err)
	}
	substituted := prepared
	substituted.RunnerAuditDigest = inputDigestB
	if _, err := runtime.MountSecretObservation(
		context.Background(),
		substituted,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("substituted mount error = %v", err)
	}
}

func TestTask11CasesThreeToSixRuntimeRejectsUnboundLossOrIncompleteScan(
	t *testing.T,
) {
	t.Parallel()

	runtime, prepared, dependencies :=
		validTask11CasesThreeToSixRuntime(t)
	dependencies.loss.mismatchProof = true
	if _, err := runtime.BrokerCaseObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("mismatched loss proof error = %v", err)
	}

	runtime, prepared, dependencies =
		validTask11CasesThreeToSixRuntime(t)
	if _, err := runtime.BrokerCaseObservation(
		context.Background(),
		prepared,
	); err != nil {
		t.Fatalf("BrokerCaseObservation: %v", err)
	}
	dependencies.capture.observation.Scan.SurfaceCount--
	if _, err := runtime.MountSecretObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("incomplete scan error = %v", err)
	}
}

func TestTask11CaseThreeParserDigestsDoNotAliasDirectClassChanges(
	t *testing.T,
) {
	t.Parallel()

	first, prepared, _ := validTask11CasesThreeToSixRuntime(t)
	firstObservation, err := first.BrokerCaseObservation(
		context.Background(),
		prepared,
	)
	if err != nil {
		t.Fatalf("first BrokerCaseObservation: %v", err)
	}

	second, prepared, dependencies :=
		validTask11CasesThreeToSixRuntime(t)
	dependencies.closed.observation.IPv6TCP =
		closedIPv6TCPFamilyUnavailable
	dependencies.closed.observation.Digest = inputDigestB
	secondObservation, err := second.BrokerCaseObservation(
		context.Background(),
		prepared,
	)
	if err != nil {
		t.Fatalf("second BrokerCaseObservation: %v", err)
	}
	if firstObservation.DirectProtocolsDigest ==
		secondObservation.DirectProtocolsDigest ||
		firstObservation.DenialBoundaryDigest ==
			secondObservation.DenialBoundaryDigest ||
		firstObservation.FloodBoundsDigest ==
			secondObservation.FloodBoundsDigest {
		t.Fatal("direct-class change did not alter bound digests")
	}
	if firstObservation.PlaintextHTTPDigest !=
		secondObservation.PlaintextHTTPDigest ||
		firstObservation.ConnectPortDigest !=
			secondObservation.ConnectPortDigest ||
		firstObservation.SOCKSOperationsDigest !=
			secondObservation.SOCKSOperationsDigest {
		t.Fatal("direct-class change leaked into parser-only digests")
	}
}

func TestOrchestratedFixtureRuntimeSnapshotsPreparedEvidenceReadOnly(
	t *testing.T,
) {
	t.Parallel()

	namespace := validNamespaceEvidenceRuntime()
	runtime := &orchestratedFixtureRuntime{
		observation:      namespace.observation,
		observationReady: true,
		flood:            namespace.flood,
		floodReady:       true,
		heldReady:        true,
		usageReady:       true,
	}
	for attempt := 0; attempt < 2; attempt++ {
		flood, err := runtime.SnapshotPreparedEvidence(
			context.Background(),
			namespace.observation,
		)
		if err != nil || flood != namespace.flood {
			t.Fatalf(
				"SnapshotPreparedEvidence(%d) = %+v, %v",
				attempt,
				flood,
				err,
			)
		}
	}
	substituted := namespace.observation
	substituted.PreparedEvidenceDigest = inputDigestA
	if _, err := runtime.SnapshotPreparedEvidence(
		context.Background(),
		substituted,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("substituted snapshot error = %v", err)
	}
	runtime.destroyAttempted = true
	if _, err := runtime.SnapshotPreparedEvidence(
		context.Background(),
		namespace.observation,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("destroying snapshot error = %v", err)
	}
}

func TestBoundTask11CaseFourRuntimeScannerConsumesCompleteCaptureOnce(
	t *testing.T,
) {
	t.Parallel()

	binding := validClosedNetworkSessionBinding(t)
	namespace := validNamespaceEvidenceRuntime()
	prepared := namespace.observation
	prepared.PolicyDigest = binding.Graph.Digest().String()
	prepared.NetworkEgressReport.PolicyDigest = prepared.PolicyDigest
	prepared.ProbeReport.PolicyDigest = prepared.PolicyDigest
	flood := namespace.flood
	binding.Adapter = prepared.Adapter
	binding.Broker = prepared.Broker
	closed := permitClosedDenialsObservation(t, binding)
	source, commandRunner := validBoundTask11CaseFourRuntimeScanner(
		t,
		prepared,
		flood,
		closed,
		binding,
	)
	capture, err := source.CaptureCaseFour(
		context.Background(),
		prepared,
		flood,
		closed,
	)
	if err != nil {
		t.Fatalf("CaptureCaseFour: %v", err)
	}
	if !validTask11CaseFourRuntimeCapture(capture, "1001:1001") {
		t.Fatalf("capture = %+v", capture)
	}
	if len(commandRunner.results) != 0 ||
		len(commandRunner.argv) != 14 {
		t.Fatalf(
			"remaining results/argv = %d/%d",
			len(commandRunner.results),
			len(commandRunner.argv),
		)
	}
	if _, err := source.CaptureCaseFour(
		context.Background(),
		prepared,
		flood,
		closed,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("second CaptureCaseFour error = %v", err)
	}
}

func TestBoundTask11CaseFourRuntimeScannerRejectsPreparedSubstitution(
	t *testing.T,
) {
	t.Parallel()

	binding := validClosedNetworkSessionBinding(t)
	namespace := validNamespaceEvidenceRuntime()
	prepared := namespace.observation
	prepared.PolicyDigest = binding.Graph.Digest().String()
	prepared.NetworkEgressReport.PolicyDigest = prepared.PolicyDigest
	prepared.ProbeReport.PolicyDigest = prepared.PolicyDigest
	flood := namespace.flood
	binding.Adapter = prepared.Adapter
	binding.Broker = prepared.Broker
	closed := permitClosedDenialsObservation(t, binding)
	source, commandRunner := validBoundTask11CaseFourRuntimeScanner(
		t,
		prepared,
		flood,
		closed,
		binding,
	)
	substituted := prepared
	substituted.BrokerAuditDigest = inputDigestA
	if _, err := source.CaptureCaseFour(
		context.Background(),
		substituted,
		flood,
		closed,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("substituted CaptureCaseFour error = %v", err)
	}
	if len(commandRunner.argv) != 0 {
		t.Fatal("substitution reached the closed command surface")
	}
}

type task11CasesThreeToSixTestDependencies struct {
	prepared *fakeTask11PreparedRuntime
	closed   *fakeTask11ClosedDenialsRuntime
	loss     *fakeTask11LossPreventionRuntime
	capture  *fakeTask11CaseFourCaptureRuntime
}

func validTask11CasesThreeToSixRuntime(
	t *testing.T,
) (
	*task11CasesThreeToSixRuntime,
	fixtureRuntimeObservation,
	task11CasesThreeToSixTestDependencies,
) {
	t.Helper()

	binding := validClosedNetworkSessionBinding(t)
	graphDigest := binding.Graph.Digest().String()
	namespace := validNamespaceEvidenceRuntime()
	prepared := namespace.observation
	prepared.PolicyDigest = graphDigest
	prepared.NetworkEgressReport.PolicyDigest = graphDigest
	prepared.ProbeReport.PolicyDigest = graphDigest
	namespace.flood.Report.Namespace = prepared.AdapterNamespace

	slot := networkjail.CapacitySlotID(17)
	generation := networkjail.JobGeneration(29)
	preparedRuntime := &fakeTask11PreparedRuntime{
		prepared:   prepared,
		flood:      namespace.flood,
		slot:       slot,
		generation: generation,
	}
	closed := &fakeTask11ClosedDenialsRuntime{
		observation: permitClosedDenialsObservation(t, binding),
	}
	loss := &fakeTask11LossPreventionRuntime{}
	capture := &fakeTask11CaseFourCaptureRuntime{
		observation: task11CaseFourRuntimeCapture{
			RunnerUser: "65532:65532",
			Runner: runnerSessionObservation{
				Version: "2.999.0",
				Conformance: runnerConformanceObservation{
					Version:                  1,
					EUID:                     65532,
					EGID:                     65532,
					Capabilities:             emptyLinuxCapabilitiesForTest(),
					RawSocketDenied:          true,
					BPFDenied:                true,
					UnshareDenied:            true,
					SetNSDenied:              true,
					Clone3Denied:             true,
					NamespaceDenied:          true,
					ProcSysReadOnly:          true,
					ProcMasksPresent:         true,
					ControllerDatabaseAbsent: true,
					DockerAuthorityAbsent:    true,
					HostControlAbsent:        true,
					SecretEnvironmentAbsent:  true,
					JITEnvironmentAbsent:     true,
					SyntheticTokenAbsent:     true,
				},
				InventoryDigest:         inputDigestA,
				ConformanceDigest:       inputDigestB,
				VerifyImageDigest:       inputDigestC,
				ListenerVersionDigest:   inputDigestD,
				ScannerEvidencePrepared: true,
			},
			Scan: closedRuntimeSurfaceScanResult{
				Version:        1,
				SurfaceCount:   completeRuntimeSurfaceCount,
				SequenceDigest: inputDigestA,
				Clean:          true,
			},
			OneShotCommandDigest:      inputDigestB,
			OneShotMountAbsenceDigest: inputDigestC,
		},
	}
	runtime, err := newTask11CasesThreeToSixRuntime(
		task11CasesThreeToSixBinding{
			Graph:          binding.Graph,
			CapacitySlotID: slot,
			JobGeneration:  generation,
			RunnerUser:     "65532:65532",
		},
		preparedRuntime,
		closed,
		loss,
		capture,
	)
	if err != nil {
		t.Fatalf("newTask11CasesThreeToSixRuntime: %v", err)
	}
	return runtime, prepared, task11CasesThreeToSixTestDependencies{
		prepared: preparedRuntime,
		closed:   closed,
		loss:     loss,
		capture:  capture,
	}
}

func emptyLinuxCapabilitiesForTest() linuxcap.Wire {
	return linuxcap.Wire{}
}

func validBoundTask11CaseFourRuntimeScanner(
	t *testing.T,
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
	closed closedDenialsSessionObservation,
	networkBinding networkSessionBinding,
) (*boundTask11CaseFourRuntimeScanner, *orderedClosedRunner) {
	t.Helper()

	commandCapture := validRuntimeScannerCaptureForTest()
	version := strings.TrimPrefix(
		buildinfo.Pins().UpstreamRunner.Version,
		"v",
	) + "\n"
	inventory := []byte("101 " + closedHeldGateArgv + "\n")
	copyDocument := func(document []byte) []byte {
		return append([]byte(nil), document...)
	}
	commandRunner := &orderedClosedRunner{
		results: []orderedClosedResult{
			{result: hostruntime.Result{
				Stdout: copyDocument(inventory),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[12].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(inventory),
			}},
			{result: hostruntime.Result{
				Stdout: []byte(version),
			}},
			{result: hostruntime.Result{
				Stdout: []byte(version),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(inventory),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[0].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[1].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[2].Document,
				),
				Stderr: copyDocument(
					commandCapture.Surfaces[3].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[4].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[5].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[6].Document,
				),
				Stderr: copyDocument(
					commandCapture.Surfaces[7].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[8].Document,
				),
			}},
			{result: hostruntime.Result{
				Stdout: copyDocument(
					commandCapture.Surfaces[10].Document,
				),
				Stderr: copyDocument(
					commandCapture.Surfaces[11].Document,
				),
			}},
		},
	}
	surface, err := newClosedCommandSurface(
		closedCommandConfig{
			DockerPath:   "/usr/bin/docker",
			FixtureRoot:  "/private/tmp/portable-ghar-fixture",
			MaximumBytes: 64 << 10,
		},
		commandRunner,
	)
	if err != nil {
		t.Fatalf("newClosedCommandSurface: %v", err)
	}
	networkBinding.Adapter = prepared.Adapter
	networkBinding.Broker = prepared.Broker
	name, cleanup, err := closedDenialsIdentity(networkBinding)
	if err != nil {
		t.Fatalf("closedDenialsIdentity: %v", err)
	}
	network := &networkSession{
		surface:          surface,
		binding:          networkBinding,
		leases:           &fakeClosedLeaseAuthority{},
		name:             name,
		cleanup:          cleanup,
		observationTaken: true,
		scannerDocument: append(
			[]byte(nil),
			closedDenialsDocumentForTest(
				networkBinding.Graph,
			)...,
		),
	}
	runner, err := newRunnerSession(
		surface,
		runnerSessionBinding{
			Runner: prepared.Runner,
			User:   "1001:1001",
		},
	)
	if err != nil {
		t.Fatalf("newRunnerSession: %v", err)
	}
	oneShotCapture := validOneShotTranscriptCaptureForTest()
	oneShotBinding := oneShotTestRecorderBinding()
	oneShotBinding.Helper.BuildID = networkBinding.BuildID
	oneShotBinding.Helper.FleetGeneration =
		networkBinding.FleetGeneration
	oneShotBinding.Helper.SlotIdentity =
		networkBinding.SlotIdentity
	oneShotBinding.Helper.SeccompPath =
		networkBinding.VerifierSeccomp.Path
	oneShotBinding.Verifier = task11OneShotCommandBinding{
		Image:           networkBinding.VerifierImage,
		BuildID:         networkBinding.BuildID,
		FleetGeneration: networkBinding.FleetGeneration,
		SlotIdentity:    networkBinding.SlotIdentity,
		User:            networkBinding.VerifierUser,
		SeccompPath:     networkBinding.VerifierSeccomp.Path,
		Limits:          networkBinding.VerifierLimits,
	}
	oneShots := &task11OneShotRecorder{
		base:                &scriptedClosedRunner{},
		binding:             oneShotBinding,
		step:                len(oneShotRuntimeSurfaceOrder()),
		adapterID:           prepared.Adapter.id,
		brokerID:            prepared.Broker.id,
		runnerID:            prepared.Runner.id,
		adapterVerifierStem: strings.Repeat("1", 32),
		brokerVerifierStem:  strings.Repeat("2", 32),
		repeatedBrokerAudit: true,
		brokerAuditDocument: copyDocument(
			oneShotCapture.surfaces[7].Document,
		),
		surfaces: takeClosedRuntimeSurfaces(
			&oneShotCapture.surfaces,
		),
	}
	matrixBinding := matrixScannerBindingForTest()
	matrixBinding.RunID = networkBinding.RunDigest
	matrixBinding.BuildID = networkBinding.BuildID
	matrixBinding.FleetGeneration = networkBinding.FleetGeneration
	matrixBinding.SlotIdentity = networkBinding.SlotIdentity
	matrixBinding.GraphDigest = prepared.PolicyDigest
	matrix, err := newMatrixScannerCaptureSource(matrixBinding)
	if err != nil {
		t.Fatalf("newMatrixScannerCaptureSource: %v", err)
	}
	scanner, err := newClosedRuntimeSurfaceScanner(64 << 10)
	if err != nil {
		t.Fatalf("newClosedRuntimeSurfaceScanner: %v", err)
	}
	source, err := newBoundTask11CaseFourRuntimeScanner(
		network,
		runner,
		oneShots,
		matrix,
		scanner,
		prepared,
		flood,
		closed,
	)
	if err != nil {
		t.Fatalf("newBoundTask11CaseFourRuntimeScanner: %v", err)
	}
	return source, commandRunner
}

func requireDistinctTask11Digests(t *testing.T, digests []string) {
	t.Helper()
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if !isLowerHex(digest, 64) {
			t.Fatalf("invalid digest %q", digest)
		}
		if _, ok := seen[digest]; ok {
			t.Fatalf("aliased digest %q", digest)
		}
		seen[digest] = struct{}{}
	}
}
