package productionruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestProtocolRejectsEmptyNoncanonicalAndMultipleFrames(t *testing.T) {
	t.Parallel()

	for name, document := range map[string][]byte{
		"empty":             nil,
		"whitespace":        []byte(" {}\n"),
		"missing newline":   []byte("{}"),
		"multiple newlines": []byte("{}\n\n"),
		"multiple frames":   []byte("{}\n{}\n"),
		"unknown object":    []byte("{}\n"),
	} {
		name, document := name, document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseRequest(document); !errors.Is(
				err,
				ErrProtocol,
			) {
				t.Fatalf("ParseRequest(%q) error = %v", document, err)
			}
		})
	}
}

func TestInvokeArgumentsExposeOnlyClosedActionInputs(t *testing.T) {
	t.Parallel()

	got := make(map[string]struct{})
	typ := reflect.TypeOf(InvokeArguments{})
	for index := range typ.NumField() {
		got[typ.Field(index).Name] = struct{}{}
	}
	want := map[string]struct{}{
		"Acquisition":        {},
		"DrainPolicy":        {},
		"ExpectedGeneration": {},
		"HostedConfirmation": {},
		"LegacyCommandFile":  {},
		"RetainState":        {},
		"RequireZero":        {},
		"ManifestDigest":     {},
		"StageProofDigest":   {},
		"TargetProofDigest":  {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("InvokeArguments fields = %v, want %v", got, want)
	}
}

func TestProtocolDoesNotExposeTargetOnlyLifecycleActions(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	target := protocolTestTarget(t, overlay, revision)
	for _, action := range []cli.HostAction{
		cli.ActionRollback,
		cli.ActionUninstall,
	} {
		if _, err := NewInvokeRequest(
			overlay,
			revision,
			target,
			action,
			InvokeArguments{},
		); !errors.Is(err, ErrProtocol) {
			t.Fatalf("NewInvokeRequest(%q) error = %v", action, err)
		}
	}
}

func TestProtocolRoundTripsProveStageAndInvoke(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	target := protocolTestTarget(t, overlay, revision)
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}

	prove, err := NewProveRequest(overlay, revision)
	if err != nil {
		t.Fatalf("NewProveRequest() error = %v", err)
	}
	roundTripRequest(t, prove)
	targetResponse, err := NewTargetResponse(prove, target)
	if err != nil {
		t.Fatalf("NewTargetResponse() error = %v", err)
	}
	roundTripResponse(t, targetResponse, prove)

	stage, err := NewStageRequest(
		overlay,
		revision,
		target,
		manifest,
		manifestDigest,
	)
	if err != nil {
		t.Fatalf("NewStageRequest() error = %v", err)
	}
	roundTripRequest(t, stage)
	stageProof, err := cli.SealStageProof(cli.StageProof{
		SchemaVersion:          1,
		TargetProofDigest:      target.ProofDigest,
		PrivateOverlayRevision: revision,
		ManifestDigest:         manifestDigest,
	})
	if err != nil {
		t.Fatalf("SealStageProof() error = %v", err)
	}
	stageResponse, err := NewStageResponse(stage, stageProof)
	if err != nil {
		t.Fatalf("NewStageResponse() error = %v", err)
	}
	roundTripResponse(t, stageResponse, stage)

	tests := []struct {
		name      string
		action    cli.HostAction
		arguments InvokeArguments
	}{
		{
			name:   "install",
			action: cli.ActionInstall,
			arguments: InvokeArguments{
				Acquisition:       "disabled",
				ManifestDigest:    manifestDigest,
				StageProofDigest:  stageProof.ProofDigest,
				TargetProofDigest: target.ProofDigest,
			},
		},
		{
			name:   "verify",
			action: cli.ActionVerify,
			arguments: InvokeArguments{
				RequireZero:       true,
				ManifestDigest:    manifestDigest,
				TargetProofDigest: target.ProofDigest,
			},
		},
		{
			name:   "suspend",
			action: cli.ActionSuspend,
			arguments: InvokeArguments{
				DrainPolicy:        "wait",
				HostedConfirmation: "/opt/portable/state/hosted-evidence/suspend.json",
				RequireZero:        true,
				ManifestDigest:     manifestDigest,
				TargetProofDigest:  target.ProofDigest,
			},
		},
		{
			name:   "resume",
			action: cli.ActionResume,
			arguments: InvokeArguments{
				Acquisition:       "disabled",
				ManifestDigest:    manifestDigest,
				TargetProofDigest: target.ProofDigest,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, requestErr := NewInvokeRequest(
				overlay,
				revision,
				target,
				test.action,
				test.arguments,
			)
			if requestErr != nil {
				t.Fatalf("NewInvokeRequest() error = %v", requestErr)
			}
			roundTripRequest(t, request)
			proof := strings.Repeat("c", 64)
			result := hostruntime.HostActionResult{
				SchemaVersion:     1,
				Status:            hostruntime.HostActionComplete,
				OperationID:       strings.Repeat("a", 64),
				JournalDigest:     strings.Repeat("b", 64),
				TargetProofDigest: &proof,
				FenceGeneration:   1,
				ActiveFleet:       fleetfence.FleetPortable,
			}
			response, responseErr := NewInvokeResponse(request, result)
			if responseErr != nil {
				t.Fatalf("NewInvokeResponse() error = %v", responseErr)
			}
			roundTripResponse(t, response, request)
			if response.TargetProofDigest != target.ProofDigest ||
				response.Invoke == nil ||
				response.Invoke.TargetProofDigest == nil ||
				*response.Invoke.TargetProofDigest != proof {
				t.Fatalf(
					"invoke response digests = envelope %q result %#v",
					response.TargetProofDigest,
					response.Invoke,
				)
			}
		})
	}
}

func TestProtocolRejectsSubstitutionAndPrivateInvokeFields(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	target := protocolTestTarget(t, overlay, revision)
	request, err := NewInvokeRequest(
		overlay,
		revision,
		target,
		cli.ActionVerify,
		InvokeArguments{
			RequireZero:       true,
			ManifestDigest:    overlay.Manifest.Digest,
			TargetProofDigest: target.ProofDigest,
		},
	)
	if err != nil {
		t.Fatalf("NewInvokeRequest() error = %v", err)
	}
	wire, err := MarshalRequest(request)
	if err != nil {
		t.Fatalf("MarshalRequest() error = %v", err)
	}
	document := string(wire[:len(wire)-1])
	mutations := map[string]string{
		"unknown outer field": strings.TrimSuffix(document, "}") +
			`,"unknown":true}`,
		"private invoke path": strings.Replace(
			document,
			`"arguments":{`,
			`"arguments":{"private_path":"/private/runtime.json",`,
			1,
		),
		"target substitution": strings.Replace(
			document,
			target.ProofDigest,
			strings.Repeat("f", 64),
			1,
		),
		"schema substitution": strings.Replace(
			document,
			`"schema_version":1`,
			`"schema_version":2`,
			1,
		),
	}
	for name, mutated := range mutations {
		name, mutated := name, mutated
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, parseErr := ParseRequest(
				append([]byte(mutated), '\n'),
			); !errors.Is(parseErr, ErrProtocol) {
				t.Fatalf("ParseRequest() error = %v", parseErr)
			}
		})
	}
}

func TestServeRejectsBeforeDispatchAndWritesOneResponse(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	request, err := NewProveRequest(overlay, revision)
	if err != nil {
		t.Fatalf("NewProveRequest() error = %v", err)
	}
	wire, err := MarshalRequest(request)
	if err != nil {
		t.Fatalf("MarshalRequest() error = %v", err)
	}
	handler := &protocolHandlerSpy{
		target: protocolTestTarget(t, overlay, revision),
	}
	var output bytes.Buffer
	if err := Serve(
		context.Background(),
		bytes.NewReader(wire),
		&output,
		false,
		handler,
	); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if handler.calls != 1 {
		t.Fatalf("handler calls = %d, want 1", handler.calls)
	}
	if _, err := ParseResponse(output.Bytes(), request); err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}

	for name, test := range map[string]struct {
		ctx    context.Context
		input  []byte
		tty    bool
		writer io.Writer
	}{
		"canceled": {
			ctx:    canceledContext(),
			input:  wire,
			writer: io.Discard,
		},
		"tty": {
			ctx:    context.Background(),
			input:  wire,
			tty:    true,
			writer: io.Discard,
		},
		"malformed": {
			ctx:    context.Background(),
			input:  []byte("{}\n"),
			writer: io.Discard,
		},
		"multiple frames": {
			ctx:    context.Background(),
			input:  append(append([]byte(nil), wire...), wire...),
			writer: io.Discard,
		},
		"oversized": {
			ctx:    context.Background(),
			input:  bytes.Repeat([]byte{'x'}, MaxWireBytes+1),
			writer: io.Discard,
		},
		"failed write": {
			ctx:    context.Background(),
			input:  wire,
			writer: zeroWriter{},
		},
	} {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			spy := &protocolHandlerSpy{target: handler.target}
			if err := Serve(
				test.ctx,
				bytes.NewReader(test.input),
				test.writer,
				test.tty,
				spy,
			); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Serve() error = %v", err)
			}
			if name != "failed write" && spy.calls != 0 {
				t.Fatalf("handler calls = %d, want 0", spy.calls)
			}
			if name == "failed write" && spy.calls != 1 {
				t.Fatalf("handler calls = %d, want 1", spy.calls)
			}
		})
	}
}

type protocolHandlerSpy struct {
	target cli.TargetProof
	calls  int
}

func (handler *protocolHandlerSpy) ProveTarget(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
) (cli.TargetProof, error) {
	handler.calls++
	return handler.target, nil
}

func (handler *protocolHandlerSpy) StageRelease(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	hostruntime.RuntimeManifest,
	string,
) (cli.StageProof, error) {
	handler.calls++
	return cli.StageProof{}, errors.New("unexpected stage")
}

func (handler *protocolHandlerSpy) Invoke(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	cli.HostAction,
	InvokeArguments,
) (hostruntime.HostActionResult, error) {
	handler.calls++
	return hostruntime.HostActionResult{}, errors.New("unexpected invoke")
}

func (handler *protocolHandlerSpy) ChangeWatchdogMarker(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	hostruntime.TargetHostAction,
	hostruntime.RuntimeManifest,
	string,
) (hostruntime.HostActionResult, error) {
	handler.calls++
	return hostruntime.HostActionResult{}, errors.New(
		"unexpected watchdog marker change",
	)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) {
	return 0, nil
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func roundTripRequest(t *testing.T, request Request) {
	t.Helper()
	wire, err := MarshalRequest(request)
	if err != nil {
		t.Fatalf("MarshalRequest() error = %v", err)
	}
	if len(wire) > MaxWireBytes ||
		len(wire) < 2 ||
		wire[len(wire)-1] != '\n' {
		t.Fatalf("MarshalRequest() emitted invalid frame")
	}
	parsed, err := ParseRequest(wire)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if !reflect.DeepEqual(parsed, request) {
		t.Fatalf("ParseRequest() = %#v, want %#v", parsed, request)
	}
}

func roundTripResponse(
	t *testing.T,
	response Response,
	request Request,
) {
	t.Helper()
	wire, err := MarshalResponse(response, request)
	if err != nil {
		t.Fatalf("MarshalResponse() error = %v", err)
	}
	parsed, err := ParseResponse(wire, request)
	if err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}
	if !reflect.DeepEqual(parsed, response) {
		t.Fatalf("ParseResponse() = %#v, want %#v", parsed, response)
	}
}

func TestMarshalResponseRejectsDifferentOriginatingRequest(t *testing.T) {
	t.Parallel()

	overlay, revision := protocolTestOverlay(t)
	request, err := NewProveRequest(overlay, revision)
	if err != nil {
		t.Fatalf("NewProveRequest() error = %v", err)
	}
	target := protocolTestTarget(t, overlay, revision)
	response, err := NewTargetResponse(request, target)
	if err != nil {
		t.Fatalf("NewTargetResponse() error = %v", err)
	}

	otherOverlay := overlay
	otherOverlay.ManagementTransport.Host = "other.example"
	_, otherRevision, err := hostruntime.MarshalPrivateOverlay(otherOverlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	otherRequest, err := NewProveRequest(otherOverlay, otherRevision)
	if err != nil {
		t.Fatalf("NewProveRequest(other) error = %v", err)
	}
	if _, err := MarshalResponse(response, otherRequest); !errors.Is(
		err,
		ErrProtocol,
	) {
		t.Fatalf("MarshalResponse(other request) error = %v", err)
	}
}

func protocolTestTarget(
	t *testing.T,
	overlay hostruntime.PrivateOverlay,
	revision string,
) cli.TargetProof {
	t.Helper()
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	proof, err := cli.SealTargetProof(cli.TargetProof{
		SchemaVersion:          1,
		PrivateOverlayRevision: revision,
		HostIdentityDigest:     overlay.Target.HostIdentityDigest,
		ControlIdentityDigest:  overlay.Target.ControlHostIdentityDigest,
		OS:                     overlay.Target.OS,
		Architecture:           overlay.Target.Architecture,
		ExpectedEUID:           overlay.Target.ExpectedEUID,
		FenceGeneration:        0,
		ActiveFleet:            fleetfence.FleetNone,
		InstallDisposition:     &disposition,
	})
	if err != nil {
		t.Fatalf("SealTargetProof() error = %v", err)
	}
	return proof
}

func protocolTestOverlay(
	t *testing.T,
) (hostruntime.PrivateOverlay, string) {
	t.Helper()
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
		observations = append(
			observations,
			hostruntime.StorageObservationOverlay{
				Role:       role,
				Device:     uint64(index + 1),
				Inode:      uint64(index + 11),
				FreeBytes:  1 << 30,
				FreeInodes: 1 << 20,
			},
		)
		requirements = append(
			requirements,
			hostruntime.StorageRequirementOverlay{
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
			},
		)
	}
	manifest := protocolTestManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalRuntimeManifest() error = %v", err)
	}
	overlay := hostruntime.PrivateOverlay{
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
			Digest: manifestDigest,
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
			RunnerImage:        testImage("runner", "3"),
			AdapterImage:       testImage("adapter", "4"),
			BrokerImage:        testImage("broker", "5"),
			HelperImage:        testImage("helper", "6"),
			VerifierImage:      testImage("verifier", "7"),
			ImmutableBuildMode: "attested-pull",
		},
		Resources: hostruntime.ResourceOverlay{
			AdmissionCeiling: vector,
			SlotResources:    slot,
			ContainerSwap: hostruntime.ContainerSwapOverlay{
				Adapter: hostruntime.SwapLimitOverlay{
					Configured: true,
					Bytes:      64,
				},
				Broker: hostruntime.SwapLimitOverlay{
					Configured: true,
					Bytes:      64,
				},
				Helper: hostruntime.SwapLimitOverlay{
					Configured: true,
				},
				Verifier: hostruntime.SwapLimitOverlay{
					Configured: true,
				},
				WorkflowToolProbe: hostruntime.SwapLimitOverlay{
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
			History: hostruntime.HistoryOverlay{
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
			Conntrack: hostruntime.ConntrackOverlay{
				CurrentEntries:          10,
				MaximumEntries:          10000,
				HostReserveEntries:      100,
				MaximumRunnerCapacity:   2,
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
				MaximumActiveConcurrency: 2,
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
		Repositories: []hostruntime.RepositoryOverlay{
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
			SessionCloseTimeout:   "9s",
			TransitionJoinTimeout: "10s",
			DurableFinishTimeout:  "11s",
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
			KnownHostsFile:    "/etc/portable-ghar/ssh/known_hosts",
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
					Source: "file",
					Ref:    "/run/secrets/github",
				},
			},
			{
				Name: "ssh-control",
				Ref: hostruntime.SecretRefOverlay{
					Source: "file",
					Ref:    "/run/secrets/ssh-control",
				},
			},
		},
		AllowedActions: []string{
			"install",
			"resume",
			"rollback",
			"suspend",
			"uninstall",
			"verify",
			"watchdog-install",
			"watchdog-uninstall",
		},
	}
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	return overlay, revision
}

func protocolTestManifest() hostruntime.RuntimeManifest {
	return hostruntime.RuntimeManifest{
		SchemaVersion:         1,
		BuildID:               strings.Repeat("1", 64),
		ControllerSHA256:      strings.Repeat("2", 64),
		RunnerImageDigest:     "sha256:" + strings.Repeat("3", 64),
		AdapterImageDigest:    "sha256:" + strings.Repeat("4", 64),
		BrokerImageDigest:     "sha256:" + strings.Repeat("5", 64),
		HelperImageDigest:     "sha256:" + strings.Repeat("6", 64),
		VerifierImageDigest:   "sha256:" + strings.Repeat("7", 64),
		TrustBundleDigest:     strings.Repeat("8", 64),
		SeccompProfileDigest:  strings.Repeat("9", 64),
		EgressMode:            "restricted-broker-v1",
		PolicyManifestDigest:  strings.Repeat("a", 64),
		ConntrackBudgetDigest: strings.Repeat("b", 64),
		StorageBudgetDigest:   strings.Repeat("c", 64),
		LogPolicyDigest:       strings.Repeat("d", 64),
		AcquisitionDefault:    "disabled",
		FleetGeneration:       1,
	}
}

func testImage(name, digit string) string {
	return "example.invalid/portable/" + name +
		"@sha256:" + strings.Repeat(digit, 64)
}

func TestServeOperationDeadlineIsBounded(t *testing.T) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	overlay.ManagementTransport.ConnectionTimeout = "1s"
	overlay.ManagementTransport.OperationTimeout = "2s"
	_, revision, err := hostruntime.MarshalPrivateOverlay(overlay)
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	request, err := NewProveRequest(overlay, revision)
	if err != nil {
		t.Fatalf("NewProveRequest() error = %v", err)
	}
	wire, err := MarshalRequest(request)
	if err != nil {
		t.Fatalf("MarshalRequest() error = %v", err)
	}
	handler := blockingProtocolHandler{}
	started := time.Now()
	if err := Serve(
		context.Background(),
		bytes.NewReader(wire),
		io.Discard,
		false,
		handler,
	); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Serve() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 1800*time.Millisecond ||
		elapsed > 3*time.Second {
		t.Fatalf("Serve() elapsed = %s", elapsed)
	}
}

type blockingProtocolHandler struct{}

func (blockingProtocolHandler) ProveTarget(
	ctx context.Context,
	_ hostruntime.PrivateOverlay,
	_ string,
) (cli.TargetProof, error) {
	<-ctx.Done()
	return cli.TargetProof{}, ctx.Err()
}

func (blockingProtocolHandler) StageRelease(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	hostruntime.RuntimeManifest,
	string,
) (cli.StageProof, error) {
	return cli.StageProof{}, errors.New("unexpected stage")
}

func (blockingProtocolHandler) Invoke(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	cli.HostAction,
	InvokeArguments,
) (hostruntime.HostActionResult, error) {
	return hostruntime.HostActionResult{}, errors.New("unexpected invoke")
}

func (blockingProtocolHandler) ChangeWatchdogMarker(
	context.Context,
	hostruntime.PrivateOverlay,
	string,
	cli.TargetProof,
	hostruntime.TargetHostAction,
	hostruntime.RuntimeManifest,
	string,
) (hostruntime.HostActionResult, error) {
	return hostruntime.HostActionResult{}, errors.New(
		"unexpected watchdog marker change",
	)
}
