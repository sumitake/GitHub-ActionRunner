package testenv

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const (
	task11PreparedObservationDomain = "portable-ghar.task11.cases-3-6.prepared.v1\x00"

	task11DirectProtocolsDomain = "portable-ghar.task11.case3.direct-protocols.v1\x00"
	task11PlaintextHTTPDomain   = "portable-ghar.task11.case3.plaintext-http.v1\x00"
	task11ConnectPortDomain     = "portable-ghar.task11.case3.connect-port.v1\x00"
	task11SOCKSOperationsDomain = "portable-ghar.task11.case3.socks-operations.v1\x00"
	task11DenialBoundaryDomain  = "portable-ghar.task11.case3.denial-boundary.v1\x00"
	task11FloodBoundsDomain     = "portable-ghar.task11.case3.flood-bounds.v1\x00"
	task11LossPreventionDomain  = "portable-ghar.task11.case3.loss-prevents-release.v1\x00"

	task11MountTopologyDomain        = "portable-ghar.task11.case4.mount-topology.v1\x00"
	task11OneShotAbsenceDomain       = "portable-ghar.task11.case4.one-shot-absence.v1\x00"
	task11ControllerSQLiteDomain     = "portable-ghar.task11.case4.controller-sqlite.v1\x00"
	task11HostControlDomain          = "portable-ghar.task11.case4.host-control.v1\x00"
	task11RuntimeSecretScanDomain    = "portable-ghar.task11.case4.runtime-secret-scan.v1\x00"
	task11SyntheticTokenDomain       = "portable-ghar.task11.case4.synthetic-token.v1\x00"
	task11SyscallDenialsDomain       = "portable-ghar.task11.case5.syscall-denials.v1\x00"
	task11ProcMaskDomain             = "portable-ghar.task11.case5.proc-mask.v1\x00"
	task11IdentityCapabilitiesDomain = "portable-ghar.task11.case5.identity-capabilities.v1\x00"
	task11SinglePayloadDomain        = "portable-ghar.task11.case6.single-payload.v1\x00"
	task11ListenerVersionDomain      = "portable-ghar.task11.case6.listener-version.v1\x00"
	task11NoVersionPairDomain        = "portable-ghar.task11.case6.no-version-pair.v1\x00"
	task11NoFileSweeperDomain        = "portable-ghar.task11.case6.no-file-sweeper.v1\x00"
	task11NoBakedJITDomain           = "portable-ghar.task11.case6.no-baked-jit.v1\x00"
)

type task11PreparedRuntimeSource interface {
	SnapshotPreparedEvidence(
		context.Context,
		fixtureRuntimeObservation,
	) (fixtureFloodObservation, error)
	ProvePermitNonconsumption(
		context.Context,
		closedDenialsSessionObservation,
	) (permitNonconsumptionProof, error)
}

type task11ClosedDenialsSource interface {
	ObserveClosedDenials(
		context.Context,
		fixtureRuntimeObservation,
	) (closedDenialsSessionObservation, error)
}

type task11LossPreventionSource interface {
	ProveLossPreventsRelease(
		context.Context,
		fixtureRuntimeObservation,
		string,
	) (task11LossPreventsReleaseProof, error)
}

type task11CaseFourCaptureSource interface {
	CaptureCaseFour(
		context.Context,
		fixtureRuntimeObservation,
		fixtureFloodObservation,
		closedDenialsSessionObservation,
	) (task11CaseFourRuntimeCapture, error)
}

type task11CasesThreeToSixBinding struct {
	Graph          networkjail.DecisionGraph
	CapacitySlotID networkjail.CapacitySlotID
	JobGeneration  networkjail.JobGeneration
	RunnerUser     string
}

type task11LossPreventsReleaseProof struct {
	primarySeal string
	digest      string
	valid       bool
}

func newTask11LossPreventsReleaseProof(
	primarySeal string,
	digest string,
) (task11LossPreventsReleaseProof, error) {
	if !isLowerHex(primarySeal, sha256.Size*2) ||
		!isLowerHex(digest, sha256.Size*2) {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	return task11LossPreventsReleaseProof{
		primarySeal: primarySeal,
		digest:      digest,
		valid:       true,
	}, nil
}

func (p task11LossPreventsReleaseProof) Matches(
	primarySeal string,
) bool {
	return p.valid &&
		p.primarySeal == primarySeal &&
		isLowerHex(p.digest, sha256.Size*2)
}

func (p task11LossPreventsReleaseProof) Digest() string {
	if !p.valid {
		return ""
	}
	return p.digest
}

type task11CaseFourRuntimeCapture struct {
	RunnerUser                string
	Runner                    runnerSessionObservation
	Scan                      closedRuntimeSurfaceScanResult
	OneShotCommandDigest      string
	OneShotMountAbsenceDigest string
}

type task11CasesThreeToSixStage uint8

const (
	task11StageBroker task11CasesThreeToSixStage = iota
	task11StageMountSecret
	task11StageSandbox
	task11StageRunnerPayload
	task11StageComplete
)

type task11CasesThreeToSixRuntime struct {
	binding  task11CasesThreeToSixBinding
	prepared task11PreparedRuntimeSource
	closed   task11ClosedDenialsSource
	loss     task11LossPreventionSource
	capture  task11CaseFourCaptureSource

	mu sync.Mutex

	stage       task11CasesThreeToSixStage
	failed      bool
	primarySeal string
	observation fixtureRuntimeObservation
	flood       fixtureFloodObservation
	denials     closedDenialsSessionObservation
	caseFour    task11CaseFourRuntimeCapture
}

func newTask11CasesThreeToSixRuntime(
	binding task11CasesThreeToSixBinding,
	prepared task11PreparedRuntimeSource,
	closed task11ClosedDenialsSource,
	loss task11LossPreventionSource,
	capture task11CaseFourCaptureSource,
) (*task11CasesThreeToSixRuntime, error) {
	uid, gid, userOK := parseStaticNumericUser(binding.RunnerUser)
	if binding.Graph.Digest() == (networkjail.Digest{}) ||
		binding.CapacitySlotID == 0 ||
		binding.JobGeneration == 0 ||
		!userOK ||
		uid > uint64(^uint32(0)) ||
		gid > uint64(^uint32(0)) ||
		prepared == nil ||
		closed == nil ||
		loss == nil ||
		capture == nil {
		return nil, ErrFixtureStart
	}
	return &task11CasesThreeToSixRuntime{
		binding:  binding,
		prepared: prepared,
		closed:   closed,
		loss:     loss,
		capture:  capture,
		stage:    task11StageBroker,
	}, nil
}

func (r *task11CasesThreeToSixRuntime) BrokerCaseObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (brokerCaseRuntimeObservation, error) {
	if r == nil {
		return brokerCaseRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enter(ctx, task11StageBroker) ||
		!validFixtureRuntimeObservation(prepared) ||
		prepared.PolicyDigest != r.binding.Graph.Digest().String() {
		return brokerCaseRuntimeObservation{}, r.fail()
	}

	flood, err := r.prepared.SnapshotPreparedEvidence(ctx, prepared)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	primarySeal, err := task11PreparedObservationSeal(prepared, flood)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	denials, err := r.closed.ObserveClosedDenials(ctx, prepared)
	if err != nil ||
		!validClosedDenialsSessionObservation(
			denials,
			r.binding.Graph,
		) {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	permit, err := r.prepared.ProvePermitNonconsumption(ctx, denials)
	if err != nil ||
		!permit.Matches(
			prepared.PermitUsageDigest,
			prepared.PolicyDigest,
			r.binding.CapacitySlotID,
			r.binding.JobGeneration,
			denials.Digest,
		) {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	loss, err := r.loss.ProveLossPreventsRelease(
		ctx,
		prepared,
		primarySeal,
	)
	if err != nil || !loss.Matches(primarySeal) {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	reauditedFlood, err := r.prepared.SnapshotPreparedEvidence(
		ctx,
		prepared,
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	reauditedSeal, err := task11PreparedObservationSeal(
		prepared,
		reauditedFlood,
	)
	if err != nil || reauditedSeal != primarySeal {
		return brokerCaseRuntimeObservation{}, r.fail()
	}

	directDigest, err := recordingCanonicalDigest(
		task11DirectProtocolsDomain,
		struct {
			PolicyDigest  string               `json:"policy_digest"`
			IPFamily      networkjail.IPFamily `json:"ip_family"`
			BeforeDigest  string               `json:"before_digest"`
			AfterDigest   string               `json:"after_digest"`
			PermitDigest  string               `json:"permit_digest"`
			DenialClasses [6]closedDenialClass `json:"denial_classes"`
		}{
			PolicyDigest: denials.PolicyDigest,
			IPFamily:     denials.IPFamily,
			BeforeDigest: denials.BeforeDigest,
			AfterDigest:  denials.DirectAfterDigest,
			PermitDigest: permit.Digest(),
			DenialClasses: [6]closedDenialClass{
				denials.IPv4TCP,
				denials.IPv4UDP,
				denials.IPv6TCP,
				denials.IPv6UDP,
				denials.DNSUDP,
				denials.RawICMP,
			},
		},
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	plaintextDigest, err := recordingCanonicalDigest(
		task11PlaintextHTTPDomain,
		struct {
			PolicyDigest      string            `json:"policy_digest"`
			ParserAfterDigest string            `json:"parser_after_digest"`
			Operation         string            `json:"operation"`
			Class             closedDenialClass `json:"class"`
		}{
			PolicyDigest:      denials.PolicyDigest,
			ParserAfterDigest: denials.ParserAfterDigest,
			Operation:         "plaintext-http-fixed-exchange",
			Class:             denials.PlaintextHTTP,
		},
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	connectDigest, err := recordingCanonicalDigest(
		task11ConnectPortDomain,
		struct {
			PolicyDigest      string            `json:"policy_digest"`
			ParserAfterDigest string            `json:"parser_after_digest"`
			Operation         string            `json:"operation"`
			Class             closedDenialClass `json:"class"`
		}{
			PolicyDigest:      denials.PolicyDigest,
			ParserAfterDigest: denials.ParserAfterDigest,
			Operation:         "unsupported-connect-port-fixed-exchange",
			Class:             denials.UnsupportedPort,
		},
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	socksDigest, err := recordingCanonicalDigest(
		task11SOCKSOperationsDomain,
		struct {
			PolicyDigest      string               `json:"policy_digest"`
			ParserAfterDigest string               `json:"parser_after_digest"`
			Operations        [2]string            `json:"operations"`
			Classes           [2]closedDenialClass `json:"classes"`
		}{
			PolicyDigest:      denials.PolicyDigest,
			ParserAfterDigest: denials.ParserAfterDigest,
			Operations: [2]string{
				"socks-bind-fixed-exchange",
				"socks-udp-associate-fixed-exchange",
			},
			Classes: [2]closedDenialClass{
				denials.SOCKSBind,
				denials.SOCKSUDPAssociate,
			},
		},
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	boundaryDigest, err := recordingCanonicalDigest(
		task11DenialBoundaryDomain,
		struct {
			PolicyDigest  string                        `json:"policy_digest"`
			IPFamily      networkjail.IPFamily          `json:"ip_family"`
			IPv6Posture   networkjail.BrokerIPv6Posture `json:"ipv6_posture"`
			BeforeDigest  string                        `json:"before_digest"`
			DirectAfter   string                        `json:"direct_after_digest"`
			ParserAfter   string                        `json:"parser_after_digest"`
			PermitDigest  string                        `json:"permit_digest"`
			DenialClasses [10]closedDenialClass         `json:"denial_classes"`
		}{
			PolicyDigest: denials.PolicyDigest,
			IPFamily:     denials.IPFamily,
			IPv6Posture:  denials.BrokerIPv6Posture,
			BeforeDigest: denials.BeforeDigest,
			DirectAfter:  denials.DirectAfterDigest,
			ParserAfter:  denials.ParserAfterDigest,
			PermitDigest: permit.Digest(),
			DenialClasses: [10]closedDenialClass{
				denials.IPv4TCP,
				denials.IPv4UDP,
				denials.IPv6TCP,
				denials.IPv6UDP,
				denials.DNSUDP,
				denials.RawICMP,
				denials.PlaintextHTTP,
				denials.UnsupportedPort,
				denials.SOCKSBind,
				denials.SOCKSUDPAssociate,
			},
		},
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	floodDigest, err := recordingCanonicalDigest(
		task11FloodBoundsDomain,
		struct {
			PrimarySeal  string                  `json:"primary_seal"`
			ClosedDigest string                  `json:"closed_digest"`
			Flood        fixtureFloodObservation `json:"flood"`
		}{
			PrimarySeal:  primarySeal,
			ClosedDigest: denials.Digest,
			Flood:        flood,
		},
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	lossDigest, err := recordingCanonicalDigest(
		task11LossPreventionDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Proof       string `json:"proof"`
		}{
			PrimarySeal: primarySeal,
			Proof:       loss.Digest(),
		},
	)
	if err != nil {
		return brokerCaseRuntimeObservation{}, r.fail()
	}

	observation := brokerCaseRuntimeObservation{
		DirectProtocolsDenied:     true,
		DirectProtocolsDigest:     directDigest,
		PlaintextHTTPDenied:       true,
		PlaintextHTTPDigest:       plaintextDigest,
		ConnectPortDenied:         true,
		ConnectPortDigest:         connectDigest,
		SOCKSOperationsDenied:     true,
		SOCKSOperationsDigest:     socksDigest,
		DenialBoundaryDigest:      boundaryDigest,
		FloodBoundsProven:         true,
		FloodBoundsDigest:         floodDigest,
		LossPreventsRelease:       true,
		LossPreventsReleaseDigest: lossDigest,
	}
	if !validBrokerCaseRuntimeObservation(observation) {
		return brokerCaseRuntimeObservation{}, r.fail()
	}
	r.primarySeal = primarySeal
	r.observation = prepared
	r.flood = flood
	r.denials = denials
	r.stage = task11StageMountSecret
	return observation, nil
}

func (r *task11CasesThreeToSixRuntime) MountSecretObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (mountSecretRuntimeObservation, error) {
	if r == nil {
		return mountSecretRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enter(ctx, task11StageMountSecret) ||
		!r.matchesPrepared(prepared) {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	capture, err := r.capture.CaptureCaseFour(
		ctx,
		prepared,
		r.flood,
		r.denials,
	)
	if err != nil ||
		!validTask11CaseFourRuntimeCapture(
			capture,
			r.binding.RunnerUser,
		) {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	mountDigest, err := recordingCanonicalDigest(
		task11MountTopologyDomain,
		struct {
			PrimarySeal     string `json:"primary_seal"`
			AdapterSpec     string `json:"adapter_spec_digest"`
			BrokerSpec      string `json:"broker_spec_digest"`
			RunnerSpec      string `json:"runner_spec_digest"`
			VerifierSpec    string `json:"verifier_spec_digest"`
			AdapterAudit    string `json:"adapter_audit_digest"`
			BrokerAudit     string `json:"broker_audit_digest"`
			RunnerAudit     string `json:"runner_audit_digest"`
			OneShotCommands string `json:"one_shot_command_digest"`
		}{
			PrimarySeal:     r.primarySeal,
			AdapterSpec:     prepared.AdapterSpecDigest,
			BrokerSpec:      prepared.BrokerSpecDigest,
			RunnerSpec:      prepared.RunnerSpecDigest,
			VerifierSpec:    prepared.VerifierSpecDigest,
			AdapterAudit:    prepared.AdapterEmptinessDigest,
			BrokerAudit:     prepared.BrokerAuditDigest,
			RunnerAudit:     prepared.RunnerAuditDigest,
			OneShotCommands: capture.OneShotCommandDigest,
		},
	)
	if err != nil {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	oneShotAbsence, err := recordingCanonicalDigest(
		task11OneShotAbsenceDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			CommandSeal string `json:"command_seal"`
			AbsenceSeal string `json:"absence_seal"`
		}{
			PrimarySeal: r.primarySeal,
			CommandSeal: capture.OneShotCommandDigest,
			AbsenceSeal: capture.OneShotMountAbsenceDigest,
		},
	)
	if err != nil {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	scanDigest, err := recordingCanonicalDigest(
		task11RuntimeSecretScanDomain,
		capture.Scan,
	)
	if err != nil {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	controllerDigest, err := recordingCanonicalDigest(
		task11ControllerSQLiteDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Scan        string `json:"scan_digest"`
			Absent      bool   `json:"absent"`
		}{
			PrimarySeal: r.primarySeal,
			Scan:        scanDigest,
			Absent: capture.Runner.Conformance.
				ControllerDatabaseAbsent,
		},
	)
	if err != nil {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	hostDigest, err := recordingCanonicalDigest(
		task11HostControlDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Scan        string `json:"scan_digest"`
			Absent      bool   `json:"absent"`
		}{
			PrimarySeal: r.primarySeal,
			Scan:        scanDigest,
			Absent: capture.Runner.Conformance.
				HostControlAbsent,
		},
	)
	if err != nil {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	syntheticDigest, err := recordingCanonicalDigest(
		task11SyntheticTokenDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Scan        string `json:"scan_digest"`
			Absent      bool   `json:"absent"`
		}{
			PrimarySeal: r.primarySeal,
			Scan:        scanDigest,
			Absent: capture.Runner.Conformance.
				SyntheticTokenAbsent,
		},
	)
	if err != nil {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	observation := mountSecretRuntimeObservation{
		MountTopologyProven:         true,
		MountTopologyDigest:         mountDigest,
		OneShotMountAbsenceProven:   true,
		OneShotMountAbsenceDigest:   oneShotAbsence,
		ControllerSQLiteInvisible:   true,
		ControllerSQLiteDigest:      controllerDigest,
		HostControlInvisible:        true,
		HostControlDigest:           hostDigest,
		RuntimeSecretScanClean:      true,
		RuntimeSecretScanDigest:     scanDigest,
		SyntheticTokenAbsent:        true,
		SyntheticTokenAbsenceDigest: syntheticDigest,
	}
	if !validMountSecretRuntimeObservation(observation) {
		return mountSecretRuntimeObservation{}, r.fail()
	}
	r.caseFour = capture
	r.stage = task11StageSandbox
	return observation, nil
}

func (r *task11CasesThreeToSixRuntime) SandboxObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (sandboxRuntimeObservation, error) {
	if r == nil {
		return sandboxRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enter(ctx, task11StageSandbox) ||
		!r.matchesPrepared(prepared) ||
		!validTask11CaseFourRuntimeCapture(
			r.caseFour,
			r.binding.RunnerUser,
		) {
		return sandboxRuntimeObservation{}, r.fail()
	}
	conformance := r.caseFour.Runner.Conformance
	syscallDigest, err := recordingCanonicalDigest(
		task11SyscallDenialsDomain,
		struct {
			PrimarySeal     string `json:"primary_seal"`
			ConformanceSeal string `json:"conformance_digest"`
			NamespaceDenied bool   `json:"namespace_denied"`
			RawSocketDenied bool   `json:"raw_socket_denied"`
			BPFDenied       bool   `json:"bpf_denied"`
			UnshareDenied   bool   `json:"unshare_denied"`
			SetNSDenied     bool   `json:"setns_denied"`
			Clone3Denied    bool   `json:"clone3_denied"`
		}{
			PrimarySeal:     r.primarySeal,
			ConformanceSeal: r.caseFour.Runner.ConformanceDigest,
			NamespaceDenied: conformance.NamespaceDenied,
			RawSocketDenied: conformance.RawSocketDenied,
			BPFDenied:       conformance.BPFDenied,
			UnshareDenied:   conformance.UnshareDenied,
			SetNSDenied:     conformance.SetNSDenied,
			Clone3Denied:    conformance.Clone3Denied,
		},
	)
	if err != nil {
		return sandboxRuntimeObservation{}, r.fail()
	}
	procDigest, err := recordingCanonicalDigest(
		task11ProcMaskDomain,
		struct {
			PrimarySeal     string `json:"primary_seal"`
			ConformanceSeal string `json:"conformance_digest"`
			ProcSysReadOnly bool   `json:"proc_sys_read_only"`
			ProcMasks       bool   `json:"proc_masks_present"`
		}{
			PrimarySeal:     r.primarySeal,
			ConformanceSeal: r.caseFour.Runner.ConformanceDigest,
			ProcSysReadOnly: conformance.ProcSysReadOnly,
			ProcMasks:       conformance.ProcMasksPresent,
		},
	)
	if err != nil {
		return sandboxRuntimeObservation{}, r.fail()
	}
	identityDigest, err := recordingCanonicalDigest(
		task11IdentityCapabilitiesDomain,
		struct {
			PrimarySeal  string        `json:"primary_seal"`
			RunnerUser   string        `json:"runner_user"`
			RunnerSpec   string        `json:"runner_spec_digest"`
			RunnerAudit  string        `json:"runner_audit_digest"`
			EUID         uint32        `json:"euid"`
			EGID         uint32        `json:"egid"`
			Capabilities linuxcap.Wire `json:"capabilities"`
		}{
			PrimarySeal:  r.primarySeal,
			RunnerUser:   r.binding.RunnerUser,
			RunnerSpec:   prepared.RunnerSpecDigest,
			RunnerAudit:  prepared.RunnerAuditDigest,
			EUID:         conformance.EUID,
			EGID:         conformance.EGID,
			Capabilities: conformance.Capabilities,
		},
	)
	if err != nil {
		return sandboxRuntimeObservation{}, r.fail()
	}
	observation := sandboxRuntimeObservation{
		NamespaceDenied:     conformance.NamespaceDenied,
		RawSocketDenied:     conformance.RawSocketDenied,
		BPFDenied:           conformance.BPFDenied,
		UnshareDenied:       conformance.UnshareDenied,
		SetNSDenied:         conformance.SetNSDenied,
		Clone3Denied:        conformance.Clone3Denied,
		SyscallDenialDigest: syscallDigest,
		ProcMaskProven: conformance.ProcSysReadOnly &&
			conformance.ProcMasksPresent,
		ProcMaskDigest:             procDigest,
		IdentityCapabilitiesValid:  true,
		IdentityCapabilitiesDigest: identityDigest,
	}
	if !validSandboxRuntimeObservation(observation) {
		return sandboxRuntimeObservation{}, r.fail()
	}
	r.stage = task11StageRunnerPayload
	return observation, nil
}

func (r *task11CasesThreeToSixRuntime) RunnerPayloadObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (runnerPayloadRuntimeObservation, error) {
	if r == nil {
		return runnerPayloadRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enter(ctx, task11StageRunnerPayload) ||
		!r.matchesPrepared(prepared) ||
		!validTask11CaseFourRuntimeCapture(
			r.caseFour,
			r.binding.RunnerUser,
		) {
		return runnerPayloadRuntimeObservation{}, r.fail()
	}
	runner := r.caseFour.Runner
	singleDigest, err := recordingCanonicalDigest(
		task11SinglePayloadDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			RunnerSpec  string `json:"runner_spec_digest"`
			RunnerAudit string `json:"runner_audit_digest"`
			Inventory   string `json:"inventory_digest"`
			VerifyImage string `json:"verify_image_digest"`
			Version     string `json:"version"`
		}{
			PrimarySeal: r.primarySeal,
			RunnerSpec:  prepared.RunnerSpecDigest,
			RunnerAudit: prepared.RunnerAuditDigest,
			Inventory:   runner.InventoryDigest,
			VerifyImage: runner.VerifyImageDigest,
			Version:     runner.Version,
		},
	)
	if err != nil {
		return runnerPayloadRuntimeObservation{}, r.fail()
	}
	listenerDigest, err := recordingCanonicalDigest(
		task11ListenerVersionDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Version     string `json:"version"`
			VerifyImage string `json:"verify_image_digest"`
			Listener    string `json:"listener_version_digest"`
		}{
			PrimarySeal: r.primarySeal,
			Version:     runner.Version,
			VerifyImage: runner.VerifyImageDigest,
			Listener:    runner.ListenerVersionDigest,
		},
	)
	if err != nil {
		return runnerPayloadRuntimeObservation{}, r.fail()
	}
	noPairDigest, err := recordingCanonicalDigest(
		task11NoVersionPairDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Version     string `json:"version"`
			Inventory   string `json:"inventory_digest"`
			VerifyImage string `json:"verify_image_digest"`
		}{
			PrimarySeal: r.primarySeal,
			Version:     runner.Version,
			Inventory:   runner.InventoryDigest,
			VerifyImage: runner.VerifyImageDigest,
		},
	)
	if err != nil {
		return runnerPayloadRuntimeObservation{}, r.fail()
	}
	noSweeperDigest, err := recordingCanonicalDigest(
		task11NoFileSweeperDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Inventory   string `json:"inventory_digest"`
			Conformance string `json:"conformance_digest"`
		}{
			PrimarySeal: r.primarySeal,
			Inventory:   runner.InventoryDigest,
			Conformance: runner.ConformanceDigest,
		},
	)
	if err != nil {
		return runnerPayloadRuntimeObservation{}, r.fail()
	}
	noJITDigest, err := recordingCanonicalDigest(
		task11NoBakedJITDomain,
		struct {
			PrimarySeal string `json:"primary_seal"`
			Scan        string `json:"scan_digest"`
			Inventory   string `json:"inventory_digest"`
			JITAbsent   bool   `json:"jit_absent"`
		}{
			PrimarySeal: r.primarySeal,
			Scan:        r.caseFour.Scan.SequenceDigest,
			Inventory:   runner.InventoryDigest,
			JITAbsent:   runner.Conformance.JITEnvironmentAbsent,
		},
	)
	if err != nil {
		return runnerPayloadRuntimeObservation{}, r.fail()
	}
	observation := runnerPayloadRuntimeObservation{
		SinglePayload:          true,
		SinglePayloadDigest:    singleDigest,
		ListenerVersionMatches: true,
		ListenerVersionDigest:  listenerDigest,
		NoVersionPair:          true,
		NoVersionPairDigest:    noPairDigest,
		NoFileSweeper:          true,
		NoFileSweeperDigest:    noSweeperDigest,
		NoBakedJIT:             runner.Conformance.JITEnvironmentAbsent,
		NoBakedJITDigest:       noJITDigest,
	}
	if !validRunnerPayloadRuntimeObservation(observation) {
		return runnerPayloadRuntimeObservation{}, r.fail()
	}
	r.stage = task11StageComplete
	return observation, nil
}

func (r *task11CasesThreeToSixRuntime) enter(
	ctx context.Context,
	expected task11CasesThreeToSixStage,
) bool {
	return ctx != nil &&
		ctx.Err() == nil &&
		!r.failed &&
		r.stage == expected
}

func (r *task11CasesThreeToSixRuntime) matchesPrepared(
	prepared fixtureRuntimeObservation,
) bool {
	if !validFixtureRuntimeObservation(prepared) ||
		!validFixtureFloodObservation(
			r.flood,
			uint32(r.flood.Report.Attempts),
		) {
		return false
	}
	seal, err := task11PreparedObservationSeal(prepared, r.flood)
	return err == nil && seal == r.primarySeal
}

func (r *task11CasesThreeToSixRuntime) fail() error {
	r.failed = true
	return ErrFixtureStart
}

func validTask11CaseFourRuntimeCapture(
	capture task11CaseFourRuntimeCapture,
	expectedRunnerUser string,
) bool {
	return capture.RunnerUser == expectedRunnerUser &&
		validRunnerSessionObservation(
			capture.Runner,
			expectedRunnerUser,
		) &&
		capture.Scan.Version == 1 &&
		capture.Scan.SurfaceCount == completeRuntimeSurfaceCount &&
		isLowerHex(capture.Scan.SequenceDigest, sha256.Size*2) &&
		capture.Scan.Clean &&
		isLowerHex(
			capture.OneShotCommandDigest,
			sha256.Size*2,
		) &&
		isLowerHex(
			capture.OneShotMountAbsenceDigest,
			sha256.Size*2,
		)
}

func sameTask11PreparedObservation(
	left fixtureRuntimeObservation,
	right fixtureRuntimeObservation,
	flood fixtureFloodObservation,
) bool {
	leftSeal, leftErr := task11PreparedObservationSeal(left, flood)
	rightSeal, rightErr := task11PreparedObservationSeal(right, flood)
	return leftErr == nil &&
		rightErr == nil &&
		leftSeal == rightSeal
}

func task11PreparedObservationSeal(
	prepared fixtureRuntimeObservation,
	flood fixtureFloodObservation,
) (string, error) {
	if !validFixtureRuntimeObservation(prepared) ||
		!validFixtureFloodObservation(
			flood,
			uint32(flood.Report.Attempts),
		) ||
		prepared.AdapterNamespace != flood.Report.Namespace {
		return "", ErrFixtureStart
	}
	return recordingCanonicalDigest(
		task11PreparedObservationDomain,
		struct {
			Runtime       matrixRuntimeEvidenceWire         `json:"runtime"`
			NetworkEgress hostruntime.NetworkVerifierReport `json:"network_egress"`
			ProbeReport   networkjail.ProbeReport           `json:"probe_report"`
		}{
			Runtime:       matrixRuntimeEvidenceFrom(prepared, flood),
			NetworkEgress: prepared.NetworkEgressReport,
			ProbeReport:   prepared.ProbeReport,
		},
	)
}

var (
	_ brokerCaseRuntime    = (*task11CasesThreeToSixRuntime)(nil)
	_ mountSecretRuntime   = (*task11CasesThreeToSixRuntime)(nil)
	_ sandboxRuntime       = (*task11CasesThreeToSixRuntime)(nil)
	_ runnerPayloadRuntime = (*task11CasesThreeToSixRuntime)(nil)
)
