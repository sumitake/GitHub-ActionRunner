package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/redaction"
)

type recordedRuntimeHandle struct {
	handle         cleanupHandle
	adapter        hostruntime.AdapterHandle
	broker         hostruntime.BrokerHandle
	runner         hostruntime.RunnerHandle
	specDigest     string
	parentAdapter  string
	verifierDigest string

	emptinessDigest    string
	emptinessNamespace hostruntime.NetworkNamespaceIdentity

	policyDigest            string
	policyApplicationDigest string
	helperCapabilityDigest  string

	authorityProof   hostruntime.AuthorityProof
	authorityReceipt string

	brokerPeerProof   hostruntime.BrokerPeerProof
	brokerPeerReady   bool
	peerBindingDigest string
	boundBrokerID     string

	egressDigest string
	egressReport hostruntime.NetworkVerifierReport

	seedReceipt                 string
	preNamespaceProof           hostruntime.NetworkNamespaceProof
	preNamespaceReceipt         string
	armReceipt                  string
	finalNamespaceProof         hostruntime.NetworkNamespaceProof
	finalNamespaceReceipt       string
	releaseAuthorization        hostruntime.ReleaseAuthorization
	releaseAuthorizationReceipt string

	auditDigest      string
	auditCount       uint8
	heldSocketZero   string
	releaseDigest    string
	flood            fixtureFloodObservation
	floodAttempted   bool
	floodReady       bool
	authorityBound   bool
	releaseAttempted bool
	busy             bool
	removed          bool
}

type loopbackFloodVerifier interface {
	VerifyLoopbackFlood(
		context.Context,
		hostruntime.AdapterHandle,
		hostruntime.VerifierSpec,
		uint64,
	) (hostruntime.LoopbackFloodEvidence, error)
}

type loopbackFloodOperation func(
	context.Context,
	hostruntime.AdapterHandle,
	hostruntime.VerifierSpec,
	uint64,
) (fixtureFloodObservation, error)

type recordingEngine struct {
	base           hostruntime.Engine
	record         func(cleanupHandle) error
	binding        recordingRuntimeBinding
	floodOperation loopbackFloodOperation

	mu               sync.Mutex
	handles          map[string]*recordedRuntimeHandle
	observationTaken bool
}

type recordingRuntimeBinding struct {
	RunID           string
	BuildID         string
	FleetGeneration uint64
	SlotIdentity    string
	CapacitySlotID  uint32
	JobGeneration   uint64
}

func newRecordingEngine(
	base hostruntime.Engine,
	record func(cleanupHandle) error,
	binding recordingRuntimeBinding,
) (*recordingEngine, error) {
	if base == nil || record == nil || !validRecordingRuntimeBinding(binding) {
		return nil, ErrFixtureStart
	}
	engine := &recordingEngine{
		base:    base,
		record:  record,
		binding: binding,
		handles: make(map[string]*recordedRuntimeHandle),
	}
	if verifier, ok := base.(loopbackFloodVerifier); ok {
		engine.floodOperation = func(
			ctx context.Context,
			adapter hostruntime.AdapterHandle,
			spec hostruntime.VerifierSpec,
			attempts uint64,
		) (fixtureFloodObservation, error) {
			evidence, err := verifier.VerifyLoopbackFlood(
				ctx,
				adapter,
				spec,
				attempts,
			)
			if err != nil ||
				evidence.AdapterID() != adapter.ID() ||
				!isLowerHex(evidence.Digest(), sha256.Size*2) {
				return fixtureFloodObservation{}, ErrFixtureStart
			}
			return fixtureFloodObservation{
				EvidenceDigest: evidence.Digest(),
				Report:         evidence.Report(),
			}, nil
		}
	}
	return engine, nil
}

func (e *recordingEngine) CreateNetworkAdapter(
	ctx context.Context,
	spec hostruntime.AdapterSpec,
) (hostruntime.AdapterHandle, error) {
	if e == nil ||
		!recordingAdapterSpecMatches(e.binding, spec) {
		return hostruntime.AdapterHandle{}, ErrFixtureStart
	}
	handle, err := e.base.CreateNetworkAdapter(ctx, spec)
	if err != nil {
		return hostruntime.AdapterHandle{}, err
	}
	specDigest, err := recordingAdapterSpecDigest(
		e.binding,
		spec,
		handle.ID(),
	)
	if err != nil {
		cleanupCtx := context.Background()
		if ctx != nil {
			cleanupCtx = context.WithoutCancel(ctx)
		}
		if removeErr := e.base.RemoveNetworkAdapter(
			cleanupCtx,
			handle,
		); removeErr != nil {
			return hostruntime.AdapterHandle{}, ErrFixtureCleanup
		}
		return hostruntime.AdapterHandle{}, ErrFixtureStart
	}
	entry := &recordedRuntimeHandle{
		handle: cleanupHandle{
			kind: CleanupAdapter,
			id:   handle.ID(),
		},
		adapter:    handle,
		specDigest: specDigest,
	}
	if err := e.registerCreated(ctx, entry); err != nil {
		return hostruntime.AdapterHandle{}, err
	}
	return handle, nil
}

func (e *recordingEngine) CreateNetworkBrokerHeld(
	ctx context.Context,
	spec hostruntime.BrokerSpec,
) (hostruntime.BrokerHandle, error) {
	if e == nil ||
		!recordingBrokerSpecMatches(e.binding, spec) ||
		!e.activeAdapter(spec.Adapter.ID()) {
		return hostruntime.BrokerHandle{}, ErrFixtureStart
	}
	handle, err := e.base.CreateNetworkBrokerHeld(ctx, spec)
	if err != nil {
		return hostruntime.BrokerHandle{}, err
	}
	specDigest, err := recordingBrokerSpecDigest(
		e.binding,
		spec,
		handle.ID(),
	)
	if err != nil {
		cleanupCtx := context.Background()
		if ctx != nil {
			cleanupCtx = context.WithoutCancel(ctx)
		}
		if removeErr := e.base.RemoveNetworkBroker(
			cleanupCtx,
			handle,
		); removeErr != nil {
			return hostruntime.BrokerHandle{}, ErrFixtureCleanup
		}
		return hostruntime.BrokerHandle{}, ErrFixtureStart
	}
	entry := &recordedRuntimeHandle{
		handle: cleanupHandle{
			kind: CleanupBroker,
			id:   handle.ID(),
		},
		broker:        handle,
		specDigest:    specDigest,
		parentAdapter: spec.Adapter.ID(),
	}
	if err := e.registerCreated(ctx, entry); err != nil {
		return hostruntime.BrokerHandle{}, err
	}
	return handle, nil
}

func (e *recordingEngine) CreateRunner(
	ctx context.Context,
	spec hostruntime.RunnerSpec,
) (hostruntime.RunnerHandle, error) {
	if e == nil ||
		!recordingRunnerSpecMatches(e.binding, spec) ||
		!e.activeAdapter(spec.Adapter.ID()) {
		return hostruntime.RunnerHandle{}, ErrFixtureStart
	}
	handle, err := e.base.CreateRunner(ctx, spec)
	if err != nil {
		return hostruntime.RunnerHandle{}, err
	}
	specDigest, err := recordingRunnerSpecDigest(
		e.binding,
		spec,
		handle.ID(),
	)
	if err != nil {
		cleanupCtx := context.Background()
		if ctx != nil {
			cleanupCtx = context.WithoutCancel(ctx)
		}
		if removeErr := e.base.RemoveRunner(
			cleanupCtx,
			handle,
		); removeErr != nil {
			return hostruntime.RunnerHandle{}, ErrFixtureCleanup
		}
		return hostruntime.RunnerHandle{}, ErrFixtureStart
	}
	entry := &recordedRuntimeHandle{
		handle: cleanupHandle{
			kind: CleanupRunner,
			id:   handle.ID(),
		},
		runner:        handle,
		specDigest:    specDigest,
		parentAdapter: spec.Adapter.ID(),
	}
	if err := e.registerCreated(ctx, entry); err != nil {
		return hostruntime.RunnerHandle{}, err
	}
	return handle, nil
}

func (e *recordingEngine) registerCreated(
	ctx context.Context,
	entry *recordedRuntimeHandle,
) error {
	if e == nil || e.base == nil || e.record == nil ||
		entry == nil || !validCleanupKind(entry.handle.kind) ||
		!isLowerHex(entry.handle.id, 64) {
		return ErrFixtureStart
	}
	e.mu.Lock()
	if _, exists := e.handles[entry.handle.id]; exists {
		e.mu.Unlock()
		return ErrFixtureStart
	}
	e.handles[entry.handle.id] = entry
	e.mu.Unlock()
	if err := e.record(entry.handle); err != nil {
		cleanupCtx := context.Background()
		if ctx != nil {
			cleanupCtx = context.WithoutCancel(ctx)
		}
		if removeErr := e.RemoveRecorded(
			cleanupCtx,
			entry.handle,
		); removeErr != nil {
			return ErrFixtureCleanup
		}
		return ErrFixtureStart
	}
	return nil
}

func (e *recordingEngine) activeAdapter(adapterID string) bool {
	if e == nil || !isLowerHex(adapterID, sha256.Size*2) {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.handles[adapterID]
	return entry != nil &&
		entry.handle.kind == CleanupAdapter &&
		entry.adapter.ID() == adapterID &&
		isLowerHex(entry.specDigest, sha256.Size*2) &&
		!entry.busy &&
		!entry.removed
}

func (e *recordingEngine) RemoveRecorded(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if e == nil || ctx == nil || ctx.Err() != nil ||
		!validCleanupKind(handle.kind) ||
		!isLowerHex(handle.id, 64) {
		return ErrFixtureCleanup
	}
	e.mu.Lock()
	entry := e.handles[handle.id]
	e.mu.Unlock()
	if entry == nil || entry.handle != handle {
		return ErrFixtureCleanup
	}
	switch handle.kind {
	case CleanupAdapter:
		return e.RemoveNetworkAdapter(ctx, entry.adapter)
	case CleanupBroker:
		return e.RemoveNetworkBroker(ctx, entry.broker)
	case CleanupRunner:
		return e.RemoveRunner(ctx, entry.runner)
	default:
		return ErrFixtureCleanup
	}
}

func (e *recordingEngine) RecordedRemoved(handle cleanupHandle) bool {
	if e == nil || !validCleanupKind(handle.kind) ||
		!isLowerHex(handle.id, 64) {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.handles[handle.id]
	return entry != nil &&
		entry.handle == handle &&
		entry.removed &&
		!entry.busy
}

func (e *recordingEngine) markRecoveredRemoved(
	identities hostruntime.RecoveredIdentities,
) error {
	if e == nil ||
		!isLowerHex(identities.AdapterID, sha256.Size*2) ||
		(identities.BrokerID != "" &&
			!isLowerHex(identities.BrokerID, sha256.Size*2)) ||
		(identities.RunnerID != "" &&
			!isLowerHex(identities.RunnerID, sha256.Size*2)) ||
		(identities.RunnerID != "" && identities.BrokerID == "") {
		return ErrFixtureCleanup
	}
	expected := map[CleanupKind]string{
		CleanupAdapter: identities.AdapterID,
		CleanupBroker:  identities.BrokerID,
		CleanupRunner:  identities.RunnerID,
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	matched := make(map[CleanupKind]bool, len(expected))
	for _, entry := range e.handles {
		if entry == nil {
			return ErrFixtureCleanup
		}
		switch entry.handle.kind {
		case CleanupAdapter, CleanupBroker, CleanupRunner:
		default:
			continue
		}
		if entry.busy || entry.removed ||
			entry.handle.id == "" ||
			entry.handle.id != expected[entry.handle.kind] ||
			matched[entry.handle.kind] {
			return ErrFixtureCleanup
		}
		matched[entry.handle.kind] = true
	}
	for kind, id := range expected {
		if matched[kind] != (id != "") {
			return ErrFixtureCleanup
		}
	}
	for kind, id := range expected {
		if id == "" {
			continue
		}
		entry := e.handles[id]
		if entry == nil ||
			entry.handle != (cleanupHandle{kind: kind, id: id}) {
			return ErrFixtureCleanup
		}
		clearRecordedRuntimeHandle(entry)
	}
	return nil
}

func (e *recordingEngine) beginRemoval(
	handle cleanupHandle,
) (*recordedRuntimeHandle, bool, error) {
	if e == nil || e.base == nil {
		return nil, false, ErrFixtureCleanup
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.handles[handle.id]
	if entry == nil || entry.handle != handle || entry.busy {
		return nil, false, ErrFixtureCleanup
	}
	if entry.removed {
		return entry, false, nil
	}
	entry.busy = true
	return entry, true, nil
}

func (e *recordingEngine) finishRemoval(
	entry *recordedRuntimeHandle,
	err error,
) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if entry == nil {
		return
	}
	entry.busy = false
	if err == nil {
		clearRecordedRuntimeHandle(entry)
	}
}

func clearRecordedRuntimeHandle(entry *recordedRuntimeHandle) {
	entry.busy = false
	entry.removed = true
	entry.specDigest = ""
	entry.parentAdapter = ""
	entry.verifierDigest = ""
	entry.emptinessDigest = ""
	entry.emptinessNamespace =
		hostruntime.NetworkNamespaceIdentity{}
	entry.policyDigest = ""
	entry.policyApplicationDigest = ""
	entry.helperCapabilityDigest = ""
	entry.authorityProof = hostruntime.AuthorityProof{}
	entry.authorityReceipt = ""
	entry.authorityBound = false
	entry.brokerPeerProof = hostruntime.BrokerPeerProof{}
	entry.brokerPeerReady = false
	entry.peerBindingDigest = ""
	entry.boundBrokerID = ""
	entry.egressDigest = ""
	entry.egressReport = hostruntime.NetworkVerifierReport{}
	entry.seedReceipt = ""
	entry.preNamespaceProof = hostruntime.NetworkNamespaceProof{}
	entry.preNamespaceReceipt = ""
	entry.armReceipt = ""
	entry.finalNamespaceProof = hostruntime.NetworkNamespaceProof{}
	entry.finalNamespaceReceipt = ""
	entry.releaseAuthorization = hostruntime.ReleaseAuthorization{}
	entry.releaseAuthorizationReceipt = ""
	entry.auditDigest = ""
	entry.auditCount = 0
	entry.heldSocketZero = ""
	entry.releaseDigest = ""
	entry.flood = fixtureFloodObservation{}
	entry.floodReady = false
	entry.releaseAttempted = false
}

func validRecordingRuntimeBinding(binding recordingRuntimeBinding) bool {
	return isLowerHex(binding.RunID, sha256.Size*2) &&
		binding.BuildID != "" &&
		binding.FleetGeneration != 0 &&
		binding.SlotIdentity != "" &&
		binding.CapacitySlotID != 0 &&
		binding.JobGeneration != 0
}

func recordingAdapterSpecMatches(
	binding recordingRuntimeBinding,
	spec hostruntime.AdapterSpec,
) bool {
	return validRecordingRuntimeBinding(binding) &&
		spec.BuildID == binding.BuildID &&
		spec.FleetGeneration == binding.FleetGeneration &&
		spec.SlotIdentity == binding.SlotIdentity
}

func recordingAdapterSpecDigest(
	binding recordingRuntimeBinding,
	spec hostruntime.AdapterSpec,
	handleID string,
) (string, error) {
	if !recordingAdapterSpecMatches(binding, spec) ||
		!isLowerHex(handleID, sha256.Size*2) {
		return "", ErrFixtureStart
	}
	return recordingCanonicalDigest(
		"portable-ghar.task11.adapter-create.v1\x00",
		struct {
			SchemaVersion   uint32                      `json:"schema_version"`
			RunID           string                      `json:"run_id"`
			HandleID        string                      `json:"handle_id"`
			CapacitySlotID  uint32                      `json:"capacity_slot_id"`
			JobGeneration   uint64                      `json:"job_generation"`
			Name            string                      `json:"name"`
			Image           string                      `json:"image"`
			BuildID         string                      `json:"build_id"`
			FleetGeneration uint64                      `json:"fleet_generation"`
			SlotIdentity    string                      `json:"slot_identity"`
			BrokerParent    string                      `json:"broker_parent"`
			User            string                      `json:"user"`
			Seccomp         hostruntime.SeccompBinding  `json:"seccomp"`
			Limits          hostruntime.ContainerLimits `json:"limits"`
			Success         bool                        `json:"success"`
		}{
			SchemaVersion:   1,
			RunID:           binding.RunID,
			HandleID:        handleID,
			CapacitySlotID:  binding.CapacitySlotID,
			JobGeneration:   binding.JobGeneration,
			Name:            spec.Name,
			Image:           spec.Image,
			BuildID:         spec.BuildID,
			FleetGeneration: spec.FleetGeneration,
			SlotIdentity:    spec.SlotIdentity,
			BrokerParent:    spec.BrokerParent,
			User:            spec.User,
			Seccomp:         spec.Seccomp,
			Limits:          spec.Limits,
			Success:         true,
		},
	)
}

func recordingBrokerSpecMatches(
	binding recordingRuntimeBinding,
	spec hostruntime.BrokerSpec,
) bool {
	return validRecordingRuntimeBinding(binding) &&
		spec.BuildID == binding.BuildID &&
		spec.FleetGeneration == binding.FleetGeneration &&
		spec.SlotIdentity == binding.SlotIdentity &&
		spec.CapacitySlotID == binding.CapacitySlotID &&
		spec.JobGeneration == binding.JobGeneration &&
		isLowerHex(spec.Adapter.ID(), sha256.Size*2)
}

func recordingBrokerSpecDigest(
	binding recordingRuntimeBinding,
	spec hostruntime.BrokerSpec,
	handleID string,
) (string, error) {
	if !recordingBrokerSpecMatches(binding, spec) ||
		!isLowerHex(handleID, sha256.Size*2) {
		return "", ErrFixtureStart
	}
	return recordingCanonicalDigest(
		"portable-ghar.task11.broker-create.v1\x00",
		struct {
			SchemaVersion   uint32                     `json:"schema_version"`
			RunID           string                     `json:"run_id"`
			HandleID        string                     `json:"handle_id"`
			Name            string                     `json:"name"`
			Image           string                     `json:"image"`
			HelperImage     string                     `json:"helper_image"`
			BuildID         string                     `json:"build_id"`
			FleetGeneration uint64                     `json:"fleet_generation"`
			SlotIdentity    string                     `json:"slot_identity"`
			CapacitySlotID  uint32                     `json:"capacity_slot_id"`
			JobGeneration   uint64                     `json:"job_generation"`
			AdapterID       string                     `json:"adapter_id"`
			RelayParent     string                     `json:"relay_parent"`
			AuthorityParent string                     `json:"authority_parent"`
			User            string                     `json:"user"`
			Seccomp         hostruntime.SeccompBinding `json:"seccomp"`
			Limits          hostruntime.BrokerLimits   `json:"limits"`
			HelperLimits    hostruntime.OneShotLimits  `json:"helper_limits"`
			Success         bool                       `json:"success"`
		}{
			SchemaVersion:   1,
			RunID:           binding.RunID,
			HandleID:        handleID,
			Name:            spec.Name,
			Image:           spec.Image,
			HelperImage:     spec.HelperImage,
			BuildID:         spec.BuildID,
			FleetGeneration: spec.FleetGeneration,
			SlotIdentity:    spec.SlotIdentity,
			CapacitySlotID:  spec.CapacitySlotID,
			JobGeneration:   spec.JobGeneration,
			AdapterID:       spec.Adapter.ID(),
			RelayParent:     spec.RelayParent,
			AuthorityParent: spec.AuthorityParent,
			User:            spec.User,
			Seccomp:         spec.Seccomp,
			Limits:          spec.Limits,
			HelperLimits:    spec.HelperLimits,
			Success:         true,
		},
	)
}

func recordingRunnerSpecMatches(
	binding recordingRuntimeBinding,
	spec hostruntime.RunnerSpec,
) bool {
	return validRecordingRuntimeBinding(binding) &&
		spec.BuildID == binding.BuildID &&
		spec.FleetGeneration == binding.FleetGeneration &&
		spec.SlotIdentity == binding.SlotIdentity &&
		isLowerHex(spec.Adapter.ID(), sha256.Size*2)
}

func recordingRunnerSpecDigest(
	binding recordingRuntimeBinding,
	spec hostruntime.RunnerSpec,
	handleID string,
) (string, error) {
	if !recordingRunnerSpecMatches(binding, spec) ||
		!isLowerHex(handleID, sha256.Size*2) {
		return "", ErrFixtureStart
	}
	return recordingCanonicalDigest(
		"portable-ghar.task11.runner-create.v1\x00",
		struct {
			SchemaVersion   uint32                     `json:"schema_version"`
			RunID           string                     `json:"run_id"`
			HandleID        string                     `json:"handle_id"`
			CapacitySlotID  uint32                     `json:"capacity_slot_id"`
			JobGeneration   uint64                     `json:"job_generation"`
			Name            string                     `json:"name"`
			Image           string                     `json:"image"`
			BuildID         string                     `json:"build_id"`
			FleetGeneration uint64                     `json:"fleet_generation"`
			SlotIdentity    string                     `json:"slot_identity"`
			AdapterID       string                     `json:"adapter_id"`
			Profile         hostruntime.HostProfile    `json:"profile"`
			User            string                     `json:"user"`
			Seccomp         hostruntime.SeccompBinding `json:"seccomp"`
			Limits          hostruntime.RunnerLimits   `json:"limits"`
			Success         bool                       `json:"success"`
		}{
			SchemaVersion:   1,
			RunID:           binding.RunID,
			HandleID:        handleID,
			CapacitySlotID:  binding.CapacitySlotID,
			JobGeneration:   binding.JobGeneration,
			Name:            spec.Name,
			Image:           spec.Image,
			BuildID:         spec.BuildID,
			FleetGeneration: spec.FleetGeneration,
			SlotIdentity:    spec.SlotIdentity,
			AdapterID:       spec.Adapter.ID(),
			Profile:         spec.Profile,
			User:            spec.User,
			Seccomp:         spec.Seccomp,
			Limits:          spec.Limits,
			Success:         true,
		},
	)
}

func recordingCanonicalDigest(domain string, value any) (string, error) {
	if domain == "" || value == nil {
		return "", ErrFixtureStart
	}
	document, err := json.Marshal(value)
	if err != nil || len(document) == 0 {
		return "", ErrFixtureStart
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(document)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func recordingVerifierSpecMatches(
	binding recordingRuntimeBinding,
	spec hostruntime.VerifierSpec,
) bool {
	return validRecordingRuntimeBinding(binding) &&
		spec.BuildID == binding.BuildID &&
		spec.FleetGeneration == binding.FleetGeneration &&
		spec.SlotIdentity == binding.SlotIdentity &&
		isLowerHex(spec.Adapter.ID(), sha256.Size*2)
}

func recordingVerifierSpecDigest(
	binding recordingRuntimeBinding,
	spec hostruntime.VerifierSpec,
) (string, error) {
	if !recordingVerifierSpecMatches(binding, spec) {
		return "", ErrFixtureStart
	}
	return recordingCanonicalDigest(
		"portable-ghar.task11.verifier-spec.v1\x00",
		struct {
			SchemaVersion   uint32                     `json:"schema_version"`
			RunID           string                     `json:"run_id"`
			CapacitySlotID  uint32                     `json:"capacity_slot_id"`
			JobGeneration   uint64                     `json:"job_generation"`
			Image           string                     `json:"image"`
			BuildID         string                     `json:"build_id"`
			FleetGeneration uint64                     `json:"fleet_generation"`
			SlotIdentity    string                     `json:"slot_identity"`
			AdapterID       string                     `json:"adapter_id"`
			User            string                     `json:"user"`
			Seccomp         hostruntime.SeccompBinding `json:"seccomp"`
			Limits          hostruntime.OneShotLimits  `json:"limits"`
		}{
			SchemaVersion:   1,
			RunID:           binding.RunID,
			CapacitySlotID:  binding.CapacitySlotID,
			JobGeneration:   binding.JobGeneration,
			Image:           spec.Image,
			BuildID:         spec.BuildID,
			FleetGeneration: spec.FleetGeneration,
			SlotIdentity:    spec.SlotIdentity,
			AdapterID:       spec.Adapter.ID(),
			User:            spec.User,
			Seccomp:         spec.Seccomp,
			Limits:          spec.Limits,
		},
	)
}

func validRecordingNetworkReport(
	report hostruntime.NetworkVerifierReport,
) bool {
	return isLowerHex(report.PolicyDigest, sha256.Size*2) &&
		report.EgressBackend == string(networkjail.RestrictedBrokerV1) &&
		report.RunnerNetNSID.Device != 0 &&
		report.RunnerNetNSID.Inode != 0 &&
		report.BrokerNetNSID.Device != 0 &&
		report.BrokerNetNSID.Inode != 0 &&
		report.RunnerNetNSID != report.BrokerNetNSID &&
		report.RunnerLoopbackOnly &&
		report.RunnerTablesEmpty &&
		report.RunnerConntrackEmpty &&
		report.ParserHasNoSocket &&
		report.PositiveOK &&
		report.NegativeOK
}

func recordingGateOperation(operation hostruntime.GateOperation) string {
	switch operation {
	case hostruntime.GateNetNSIDPreArm:
		return "namespace-pre-arm"
	case hostruntime.GateNetNSIDFinal:
		return "namespace-final"
	default:
		return ""
	}
}

func (e *recordingEngine) boundReceipt(
	label string,
	values ...string,
) string {
	if e == nil || !validRecordingRuntimeBinding(e.binding) ||
		label == "" {
		return ""
	}
	bound := make([]string, 0, len(values)+6)
	bound = append(
		bound,
		e.binding.RunID,
		e.binding.BuildID,
		strconv.FormatUint(e.binding.FleetGeneration, 10),
		e.binding.SlotIdentity,
		strconv.FormatUint(uint64(e.binding.CapacitySlotID), 10),
		strconv.FormatUint(e.binding.JobGeneration, 10),
	)
	bound = append(bound, values...)
	return recordingReceiptDigest(label, bound...)
}

func (e *recordingEngine) RemoveRunner(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
) error {
	entry, remove, err := e.beginRemoval(cleanupHandle{
		kind: CleanupRunner,
		id:   handle.ID(),
	})
	if err != nil || !remove {
		return err
	}
	if entry.runner.ID() != handle.ID() {
		e.finishRemoval(entry, ErrFixtureCleanup)
		return ErrFixtureCleanup
	}
	err = e.base.RemoveRunner(ctx, handle)
	e.finishRemoval(entry, err)
	return err
}

func (e *recordingEngine) RemoveNetworkBroker(
	ctx context.Context,
	handle hostruntime.BrokerHandle,
) error {
	entry, remove, err := e.beginRemoval(cleanupHandle{
		kind: CleanupBroker,
		id:   handle.ID(),
	})
	if err != nil || !remove {
		return err
	}
	if entry.broker.ID() != handle.ID() {
		e.finishRemoval(entry, ErrFixtureCleanup)
		return ErrFixtureCleanup
	}
	err = e.base.RemoveNetworkBroker(ctx, handle)
	e.finishRemoval(entry, err)
	return err
}

func (e *recordingEngine) RemoveNetworkAdapter(
	ctx context.Context,
	handle hostruntime.AdapterHandle,
) error {
	entry, remove, err := e.beginRemoval(cleanupHandle{
		kind: CleanupAdapter,
		id:   handle.ID(),
	})
	if err != nil || !remove {
		return err
	}
	if entry.adapter.ID() != handle.ID() {
		e.finishRemoval(entry, ErrFixtureCleanup)
		return ErrFixtureCleanup
	}
	err = e.base.RemoveNetworkAdapter(ctx, handle)
	e.finishRemoval(entry, err)
	return err
}

func (e *recordingEngine) ApplyNetworkPolicy(
	ctx context.Context,
	handle hostruntime.BrokerHandle,
	policy hostruntime.PolicyArtifact,
) error {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil ||
		!policy.Valid() ||
		!isLowerHex(policy.Digest(), sha256.Size*2) {
		return ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	if entry == nil ||
		entry.handle.kind != CleanupBroker ||
		entry.broker.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		!isLowerHex(entry.specDigest, sha256.Size*2) ||
		entry.policyApplicationDigest != "" ||
		entry.authorityBound {
		e.mu.Unlock()
		return ErrFixtureStart
	}
	entry.busy = true
	specDigest := entry.specDigest
	e.mu.Unlock()
	if err := e.base.ApplyNetworkPolicy(ctx, handle, policy); err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return err
	}
	applicationDigest := e.boundReceipt(
		"portable-ghar.task11.policy-application.v1\x00",
		handle.ID(),
		specDigest,
		policy.Digest(),
		"success",
	)
	helperDigest := e.boundReceipt(
		"portable-ghar.task11.helper-capability-lifetime.v1\x00",
		handle.ID(),
		specDigest,
		policy.Digest(),
		applicationDigest,
		"net-admin-only",
		"helper-absent",
		"success",
	)
	e.mu.Lock()
	defer e.mu.Unlock()
	if current := e.handles[handle.ID()]; current != entry ||
		!entry.busy ||
		entry.removed ||
		entry.specDigest != specDigest ||
		entry.policyApplicationDigest != "" ||
		!isLowerHex(applicationDigest, sha256.Size*2) ||
		!isLowerHex(helperDigest, sha256.Size*2) {
		entry.busy = false
		return ErrFixtureStart
	}
	entry.policyDigest = policy.Digest()
	entry.policyApplicationDigest = applicationDigest
	entry.helperCapabilityDigest = helperDigest
	entry.busy = false
	return nil
}

func (e *recordingEngine) BindDialAuthority(
	ctx context.Context,
	handle hostruntime.BrokerHandle,
	proof hostruntime.AuthorityProof,
) error {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil ||
		!isLowerHex(handle.ID(), 64) {
		return ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	valid := entry != nil &&
		entry.handle.kind == CleanupBroker &&
		entry.handle.id == handle.ID() &&
		entry.broker.ID() == handle.ID() &&
		!entry.busy &&
		!entry.removed &&
		isLowerHex(entry.specDigest, sha256.Size*2) &&
		isLowerHex(entry.policyApplicationDigest, sha256.Size*2) &&
		!entry.authorityBound
	if valid {
		entry.busy = true
	}
	e.mu.Unlock()
	if !valid {
		return ErrFixtureStart
	}
	if err := e.base.BindDialAuthority(ctx, handle, proof); err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		entry.authorityBound {
		entry.busy = false
		return ErrFixtureStart
	}
	if err := e.setBoundAuthority(entry, handle.ID(), proof); err != nil {
		entry.busy = false
		return err
	}
	entry.busy = false
	return nil
}

func (e *recordingEngine) retainBoundAuthority(
	brokerID string,
	proof hostruntime.AuthorityProof,
) error {
	if e == nil || !isLowerHex(brokerID, 64) {
		return ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.handles[brokerID]
	if entry == nil ||
		entry.handle.kind != CleanupBroker ||
		entry.handle.id != brokerID ||
		entry.busy ||
		entry.removed ||
		!isLowerHex(entry.specDigest, sha256.Size*2) ||
		!isLowerHex(entry.policyApplicationDigest, sha256.Size*2) ||
		entry.authorityBound {
		return ErrFixtureStart
	}
	return e.setBoundAuthority(entry, brokerID, proof)
}

func (e *recordingEngine) setBoundAuthority(
	entry *recordedRuntimeHandle,
	brokerID string,
	proof hostruntime.AuthorityProof,
) error {
	if e == nil || entry == nil ||
		entry.handle.kind != CleanupBroker ||
		entry.handle.id != brokerID ||
		entry.removed ||
		!isLowerHex(entry.specDigest, sha256.Size*2) ||
		!isLowerHex(entry.policyApplicationDigest, sha256.Size*2) ||
		entry.authorityBound {
		return ErrFixtureStart
	}
	entry.authorityProof = proof
	entry.authorityReceipt = e.boundReceipt(
		"portable-ghar.task11.authority-binding.v1\x00",
		brokerID,
		entry.specDigest,
		entry.policyDigest,
		entry.policyApplicationDigest,
		"success",
	)
	if !isLowerHex(entry.authorityReceipt, sha256.Size*2) {
		entry.authorityProof = hostruntime.AuthorityProof{}
		entry.authorityReceipt = ""
		return ErrFixtureStart
	}
	entry.authorityBound = true
	return nil
}

func (e *recordingEngine) ReleaseNetworkBroker(
	ctx context.Context,
	handle hostruntime.BrokerHandle,
) (hostruntime.BrokerPeerProof, error) {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil {
		return hostruntime.BrokerPeerProof{}, ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	if entry == nil ||
		entry.handle.kind != CleanupBroker ||
		entry.broker.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		!entry.authorityBound ||
		!isLowerHex(entry.authorityReceipt, sha256.Size*2) ||
		!isLowerHex(entry.policyApplicationDigest, sha256.Size*2) ||
		entry.heldSocketZero != "" ||
		entry.releaseDigest != "" ||
		entry.brokerPeerReady {
		e.mu.Unlock()
		return hostruntime.BrokerPeerProof{}, ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	proof, err := e.base.ReleaseNetworkBroker(ctx, handle)
	if err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.BrokerPeerProof{}, err
	}
	heldSocketZero := proof.HeldSocketZeroDigest()
	if !isLowerHex(heldSocketZero, sha256.Size*2) {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.BrokerPeerProof{}, ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		!entry.authorityBound ||
		!isLowerHex(entry.authorityReceipt, sha256.Size*2) ||
		!isLowerHex(entry.policyApplicationDigest, sha256.Size*2) ||
		entry.heldSocketZero != "" ||
		entry.releaseDigest != "" ||
		entry.brokerPeerReady {
		entry.busy = false
		return hostruntime.BrokerPeerProof{}, ErrFixtureStart
	}
	releaseDigest := e.boundReceipt(
		"portable-ghar.task11.broker-release.v1\x00",
		handle.ID(),
		entry.specDigest,
		entry.policyDigest,
		entry.policyApplicationDigest,
		entry.authorityReceipt,
		heldSocketZero,
		"success",
	)
	if !isLowerHex(releaseDigest, sha256.Size*2) {
		entry.busy = false
		return hostruntime.BrokerPeerProof{}, ErrFixtureStart
	}
	entry.heldSocketZero = heldSocketZero
	entry.releaseDigest = releaseDigest
	entry.brokerPeerProof = proof
	entry.brokerPeerReady = true
	entry.busy = false
	return proof, nil
}

func (e *recordingEngine) AuditNetworkBroker(
	ctx context.Context,
	handle hostruntime.BrokerHandle,
) (hostruntime.BrokerAudit, error) {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil {
		return hostruntime.BrokerAudit{}, ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	var runnerReady bool
	if entry != nil {
		for _, candidate := range e.handles {
			if candidate.handle.kind == CleanupRunner &&
				candidate.parentAdapter == entry.parentAdapter &&
				candidate.preNamespaceReceipt != "" &&
				!candidate.removed {
				if runnerReady {
					runnerReady = false
					break
				}
				runnerReady = true
			}
		}
	}
	if entry == nil ||
		entry.handle.kind != CleanupBroker ||
		entry.broker.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		entry.egressDigest == "" ||
		entry.auditCount != 0 ||
		!runnerReady {
		e.mu.Unlock()
		return hostruntime.BrokerAudit{}, ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	audit, err := e.base.AuditNetworkBroker(ctx, handle)
	if err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.BrokerAudit{}, err
	}
	if !isLowerHex(audit.Digest(), 64) {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.BrokerAudit{}, ErrFixtureStart
	}
	e.mu.Lock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		entry.auditDigest != "" ||
		entry.auditCount != 0 {
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.BrokerAudit{}, ErrFixtureStart
	}
	entry.auditDigest = audit.Digest()
	entry.auditCount = 1
	entry.busy = false
	e.mu.Unlock()
	return audit, nil
}

func (e *recordingEngine) BindBrokerPeer(
	ctx context.Context,
	handle hostruntime.AdapterHandle,
	proof hostruntime.BrokerPeerProof,
) error {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil ||
		!isLowerHex(handle.ID(), sha256.Size*2) {
		return ErrFixtureStart
	}
	e.mu.Lock()
	adapter := e.handles[handle.ID()]
	var broker *recordedRuntimeHandle
	if adapter != nil &&
		adapter.handle.kind == CleanupAdapter &&
		adapter.adapter.ID() == handle.ID() &&
		!adapter.busy &&
		!adapter.removed &&
		adapter.boundBrokerID == "" &&
		isLowerHex(adapter.specDigest, sha256.Size*2) {
		for _, candidate := range e.handles {
			if candidate.handle.kind != CleanupBroker ||
				candidate.busy ||
				candidate.removed ||
				!candidate.brokerPeerReady ||
				candidate.brokerPeerProof != proof ||
				candidate.parentAdapter != handle.ID() ||
				candidate.peerBindingDigest != "" {
				continue
			}
			if broker != nil {
				broker = nil
				break
			}
			broker = candidate
		}
	}
	if adapter == nil || broker == nil {
		e.mu.Unlock()
		return ErrFixtureStart
	}
	adapter.busy = true
	broker.busy = true
	e.mu.Unlock()
	if err := e.base.BindBrokerPeer(ctx, handle, proof); err != nil {
		e.mu.Lock()
		adapter.busy = false
		broker.busy = false
		e.mu.Unlock()
		return err
	}
	bindingDigest := e.boundReceipt(
		"portable-ghar.task11.broker-peer-binding.v1\x00",
		handle.ID(),
		adapter.specDigest,
		broker.handle.id,
		broker.specDigest,
		broker.releaseDigest,
		broker.heldSocketZero,
		"success",
	)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != adapter ||
		e.handles[broker.handle.id] != broker ||
		!adapter.busy ||
		!broker.busy ||
		adapter.removed ||
		broker.removed ||
		adapter.boundBrokerID != "" ||
		broker.peerBindingDigest != "" ||
		!isLowerHex(bindingDigest, sha256.Size*2) {
		adapter.busy = false
		broker.busy = false
		return ErrFixtureStart
	}
	adapter.boundBrokerID = broker.handle.id
	adapter.peerBindingDigest = bindingDigest
	broker.boundBrokerID = broker.handle.id
	broker.peerBindingDigest = bindingDigest
	adapter.busy = false
	broker.busy = false
	return nil
}

func (e *recordingEngine) VerifyNetworkAdapterEmpty(
	ctx context.Context,
	handle hostruntime.AdapterHandle,
	spec hostruntime.VerifierSpec,
) (hostruntime.AdapterEmptinessEvidence, error) {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil ||
		spec.Adapter.ID() != handle.ID() ||
		!recordingVerifierSpecMatches(e.binding, spec) {
		return hostruntime.AdapterEmptinessEvidence{}, ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	if entry == nil ||
		entry.handle.kind != CleanupAdapter ||
		entry.adapter.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		entry.emptinessDigest != "" ||
		entry.boundBrokerID != "" {
		e.mu.Unlock()
		return hostruntime.AdapterEmptinessEvidence{}, ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	evidence, err := e.base.VerifyNetworkAdapterEmpty(ctx, handle, spec)
	if err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.AdapterEmptinessEvidence{}, err
	}
	verifierDigest, digestErr := recordingVerifierSpecDigest(
		e.binding,
		spec,
	)
	if digestErr != nil ||
		evidence.AdapterID() != handle.ID() ||
		evidence.Namespace().Device == 0 ||
		evidence.Namespace().Inode == 0 ||
		!isLowerHex(evidence.Digest(), sha256.Size*2) {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.AdapterEmptinessEvidence{}, ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		entry.emptinessDigest != "" {
		entry.busy = false
		return hostruntime.AdapterEmptinessEvidence{}, ErrFixtureStart
	}
	entry.verifierDigest = verifierDigest
	entry.emptinessDigest = evidence.Digest()
	entry.emptinessNamespace = evidence.Namespace()
	entry.busy = false
	return evidence, nil
}

func (e *recordingEngine) VerifyNetworkEgress(
	ctx context.Context,
	adapter hostruntime.AdapterHandle,
	broker hostruntime.BrokerHandle,
	policy hostruntime.PolicyArtifact,
	spec hostruntime.VerifierSpec,
) (hostruntime.NetworkEgressEvidence, error) {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil ||
		spec.Adapter.ID() != adapter.ID() ||
		!recordingVerifierSpecMatches(e.binding, spec) ||
		!policy.Valid() {
		return hostruntime.NetworkEgressEvidence{}, ErrFixtureStart
	}
	e.mu.Lock()
	adapterEntry := e.handles[adapter.ID()]
	brokerEntry := e.handles[broker.ID()]
	if adapterEntry == nil ||
		brokerEntry == nil ||
		adapterEntry.handle.kind != CleanupAdapter ||
		brokerEntry.handle.kind != CleanupBroker ||
		adapterEntry.adapter.ID() != adapter.ID() ||
		brokerEntry.broker.ID() != broker.ID() ||
		adapterEntry.busy ||
		brokerEntry.busy ||
		adapterEntry.removed ||
		brokerEntry.removed ||
		adapterEntry.boundBrokerID != broker.ID() ||
		brokerEntry.parentAdapter != adapter.ID() ||
		adapterEntry.peerBindingDigest == "" ||
		adapterEntry.peerBindingDigest != brokerEntry.peerBindingDigest ||
		brokerEntry.policyDigest != policy.Digest() ||
		adapterEntry.egressDigest != "" ||
		brokerEntry.egressDigest != "" {
		e.mu.Unlock()
		return hostruntime.NetworkEgressEvidence{}, ErrFixtureStart
	}
	adapterEntry.busy = true
	brokerEntry.busy = true
	e.mu.Unlock()
	evidence, err := e.base.VerifyNetworkEgress(
		ctx,
		adapter,
		broker,
		policy,
		spec,
	)
	if err != nil {
		e.mu.Lock()
		adapterEntry.busy = false
		brokerEntry.busy = false
		e.mu.Unlock()
		return hostruntime.NetworkEgressEvidence{}, err
	}
	verifierDigest, digestErr := recordingVerifierSpecDigest(
		e.binding,
		spec,
	)
	report := evidence.Report()
	if digestErr != nil ||
		verifierDigest != adapterEntry.verifierDigest ||
		evidence.AdapterID() != adapter.ID() ||
		evidence.BrokerID() != broker.ID() ||
		evidence.PolicyArtifactDigest() != policy.Digest() ||
		!isLowerHex(evidence.Digest(), sha256.Size*2) ||
		!validRecordingNetworkReport(report) {
		e.mu.Lock()
		adapterEntry.busy = false
		brokerEntry.busy = false
		e.mu.Unlock()
		return hostruntime.NetworkEgressEvidence{}, ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[adapter.ID()] != adapterEntry ||
		e.handles[broker.ID()] != brokerEntry ||
		!adapterEntry.busy ||
		!brokerEntry.busy ||
		adapterEntry.removed ||
		brokerEntry.removed ||
		adapterEntry.egressDigest != "" ||
		brokerEntry.egressDigest != "" {
		adapterEntry.busy = false
		brokerEntry.busy = false
		return hostruntime.NetworkEgressEvidence{}, ErrFixtureStart
	}
	adapterEntry.egressDigest = evidence.Digest()
	brokerEntry.egressDigest = evidence.Digest()
	adapterEntry.egressReport = report
	brokerEntry.egressReport = report
	adapterEntry.busy = false
	brokerEntry.busy = false
	return evidence, nil
}

func (e *recordingEngine) HydrateSeeds(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
	ids []string,
) error {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil {
		return ErrFixtureStart
	}
	idsDigest, err := recordingCanonicalDigest(
		"portable-ghar.task11.seed-input.v1\x00",
		ids,
	)
	if err != nil {
		return ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	adapter := (*recordedRuntimeHandle)(nil)
	if entry != nil {
		adapter = e.handles[entry.parentAdapter]
	}
	if entry == nil ||
		adapter == nil ||
		entry.handle.kind != CleanupRunner ||
		entry.runner.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		entry.seedReceipt != "" ||
		adapter.egressDigest == "" {
		e.mu.Unlock()
		return ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	if err := e.base.HydrateSeeds(ctx, handle, ids); err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return err
	}
	receipt := e.boundReceipt(
		"portable-ghar.task11.seed-hydration.v1\x00",
		handle.ID(),
		entry.specDigest,
		idsDigest,
		"success",
	)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		entry.seedReceipt != "" ||
		!isLowerHex(receipt, sha256.Size*2) {
		entry.busy = false
		return ErrFixtureStart
	}
	entry.seedReceipt = receipt
	entry.busy = false
	return nil
}

func (e *recordingEngine) ProbeRunnerNetworkNamespace(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
	operation hostruntime.GateOperation,
) (hostruntime.NetworkNamespaceProof, error) {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil ||
		(operation != hostruntime.GateNetNSIDPreArm &&
			operation != hostruntime.GateNetNSIDFinal) {
		return hostruntime.NetworkNamespaceProof{}, ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	if entry == nil ||
		entry.handle.kind != CleanupRunner ||
		entry.runner.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		entry.seedReceipt == "" ||
		(operation == hostruntime.GateNetNSIDPreArm &&
			(entry.preNamespaceReceipt != "" ||
				entry.armReceipt != "")) ||
		(operation == hostruntime.GateNetNSIDFinal &&
			(entry.armReceipt == "" ||
				entry.finalNamespaceReceipt != "")) {
		e.mu.Unlock()
		return hostruntime.NetworkNamespaceProof{}, ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	proof, err := e.base.ProbeRunnerNetworkNamespace(
		ctx,
		handle,
		operation,
	)
	if err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.NetworkNamespaceProof{}, err
	}
	receipt := e.boundReceipt(
		"portable-ghar.task11.namespace-gate.v1\x00",
		handle.ID(),
		entry.specDigest,
		recordingGateOperation(operation),
		"success",
	)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		!isLowerHex(receipt, sha256.Size*2) {
		entry.busy = false
		return hostruntime.NetworkNamespaceProof{}, ErrFixtureStart
	}
	switch operation {
	case hostruntime.GateNetNSIDPreArm:
		if entry.preNamespaceReceipt != "" ||
			entry.armReceipt != "" {
			entry.busy = false
			return hostruntime.NetworkNamespaceProof{}, ErrFixtureStart
		}
		entry.preNamespaceProof = proof
		entry.preNamespaceReceipt = receipt
	case hostruntime.GateNetNSIDFinal:
		if entry.armReceipt == "" ||
			entry.finalNamespaceReceipt != "" {
			entry.busy = false
			return hostruntime.NetworkNamespaceProof{}, ErrFixtureStart
		}
		entry.finalNamespaceProof = proof
		entry.finalNamespaceReceipt = receipt
	}
	entry.busy = false
	return proof, nil
}

func (e *recordingEngine) ArmRunner(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
) error {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil {
		return ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	if entry == nil ||
		entry.handle.kind != CleanupRunner ||
		entry.runner.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		entry.preNamespaceReceipt == "" ||
		entry.auditCount != 1 ||
		entry.armReceipt != "" {
		e.mu.Unlock()
		return ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	if err := e.base.ArmRunner(ctx, handle); err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return err
	}
	receipt := e.boundReceipt(
		"portable-ghar.task11.runner-arm.v1\x00",
		handle.ID(),
		entry.specDigest,
		entry.preNamespaceReceipt,
		entry.auditDigest,
		"success",
	)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		entry.armReceipt != "" ||
		!isLowerHex(receipt, sha256.Size*2) {
		entry.busy = false
		return ErrFixtureStart
	}
	entry.armReceipt = receipt
	entry.busy = false
	return nil
}

func (e *recordingEngine) AuditHeldRunner(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
) (hostruntime.HeldRunnerAudit, error) {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil {
		return hostruntime.HeldRunnerAudit{}, ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	preparedViewComplete := e.releasePreparedViewCompleteLocked(entry)
	validOrder := entry != nil &&
		entry.handle.kind == CleanupRunner &&
		entry.runner.ID() == handle.ID() &&
		!entry.busy &&
		!entry.removed &&
		preparedViewComplete &&
		((entry.auditCount == 0 &&
			entry.preNamespaceReceipt != "" &&
			entry.armReceipt == "" &&
			entry.finalNamespaceReceipt == "") ||
			(entry.auditCount == 1 &&
				isLowerHex(entry.auditDigest, sha256.Size*2) &&
				entry.armReceipt != "" &&
				entry.finalNamespaceReceipt != ""))
	if !validOrder {
		e.mu.Unlock()
		return hostruntime.HeldRunnerAudit{}, ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	audit, err := e.base.AuditHeldRunner(ctx, handle)
	if err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.HeldRunnerAudit{}, err
	}
	if !isLowerHex(audit.Digest(), 64) {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.HeldRunnerAudit{}, ErrFixtureStart
	}
	e.mu.Lock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		(entry.auditDigest != "" &&
			entry.auditDigest != audit.Digest()) {
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.HeldRunnerAudit{}, ErrFixtureStart
	}
	entry.auditDigest = audit.Digest()
	entry.auditCount++
	entry.busy = false
	e.mu.Unlock()
	return audit, nil
}

// releasePreparedViewCompleteLocked proves that the runner's private
// recording view still contains the component, policy, and evidence facts
// required by the final and release-authorization audits. The caller must
// hold e.mu. Cleanup authority remains in the opaque handles and is
// deliberately independent of this provisional evidence view.
func (e *recordingEngine) releasePreparedViewCompleteLocked(
	runner *recordedRuntimeHandle,
) bool {
	if e == nil || runner == nil ||
		runner.handle.kind != CleanupRunner ||
		!isLowerHex(runner.parentAdapter, sha256.Size*2) {
		return false
	}
	adapter := e.handles[runner.parentAdapter]
	if adapter == nil ||
		adapter.handle.kind != CleanupAdapter ||
		adapter.handle.id != runner.parentAdapter ||
		adapter.busy ||
		adapter.removed ||
		!isLowerHex(adapter.specDigest, sha256.Size*2) ||
		!isLowerHex(adapter.emptinessDigest, sha256.Size*2) ||
		!isLowerHex(adapter.peerBindingDigest, sha256.Size*2) ||
		!isLowerHex(adapter.egressDigest, sha256.Size*2) {
		return false
	}
	var broker *recordedRuntimeHandle
	for _, candidate := range e.handles {
		if candidate.handle.kind != CleanupBroker ||
			candidate.parentAdapter != runner.parentAdapter ||
			candidate.removed {
			continue
		}
		if broker != nil {
			return false
		}
		broker = candidate
	}
	return broker != nil &&
		!broker.busy &&
		isLowerHex(broker.specDigest, sha256.Size*2) &&
		isLowerHex(broker.policyDigest, sha256.Size*2) &&
		isLowerHex(broker.policyApplicationDigest, sha256.Size*2) &&
		isLowerHex(broker.authorityReceipt, sha256.Size*2) &&
		broker.authorityBound &&
		isLowerHex(broker.peerBindingDigest, sha256.Size*2) &&
		broker.peerBindingDigest == adapter.peerBindingDigest &&
		isLowerHex(broker.egressDigest, sha256.Size*2) &&
		broker.egressDigest == adapter.egressDigest &&
		isLowerHex(broker.auditDigest, sha256.Size*2) &&
		broker.auditCount == 1
}

func (e *recordingEngine) releaseAuthorizationViewCompleteLocked(
	runner *recordedRuntimeHandle,
) bool {
	return e.releasePreparedViewCompleteLocked(runner) &&
		runner.auditCount == 1 &&
		isLowerHex(runner.auditDigest, sha256.Size*2) &&
		isLowerHex(runner.armReceipt, sha256.Size*2) &&
		isLowerHex(runner.finalNamespaceReceipt, sha256.Size*2) &&
		runner.releaseAuthorizationReceipt == ""
}

func (e *recordingEngine) AuthorizeRelease(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
	pre hostruntime.NetworkNamespaceProof,
	final hostruntime.NetworkNamespaceProof,
) (hostruntime.ReleaseAuthorization, error) {
	if e == nil || e.base == nil || ctx == nil || ctx.Err() != nil {
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	if entry == nil ||
		entry.handle.kind != CleanupRunner ||
		entry.runner.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		entry.auditCount != 2 ||
		entry.preNamespaceReceipt == "" ||
		entry.finalNamespaceReceipt == "" ||
		entry.armReceipt == "" ||
		entry.releaseAuthorizationReceipt != "" ||
		entry.preNamespaceProof != pre ||
		entry.finalNamespaceProof != final {
		e.mu.Unlock()
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	entry.busy = true
	e.mu.Unlock()
	authorization, err := e.base.AuthorizeRelease(
		ctx,
		handle,
		pre,
		final,
	)
	if err != nil {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return hostruntime.ReleaseAuthorization{}, err
	}
	receipt := e.boundReceipt(
		"portable-ghar.task11.release-authorization.v1\x00",
		handle.ID(),
		entry.specDigest,
		entry.preNamespaceReceipt,
		entry.finalNamespaceReceipt,
		entry.armReceipt,
		entry.auditDigest,
		"success",
	)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[handle.ID()] != entry ||
		!entry.busy ||
		entry.removed ||
		entry.releaseAuthorizationReceipt != "" ||
		!isLowerHex(receipt, sha256.Size*2) {
		entry.busy = false
		return hostruntime.ReleaseAuthorization{}, ErrFixtureStart
	}
	entry.releaseAuthorizationReceipt = receipt
	entry.releaseAuthorization = authorization
	entry.busy = false
	return authorization, nil
}

func (e *recordingEngine) ReleaseRunner(
	ctx context.Context,
	handle hostruntime.RunnerHandle,
	authorization hostruntime.ReleaseAuthorization,
	jit *redaction.Secret,
) error {
	if e == nil || e.base == nil {
		return ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[handle.ID()]
	if entry == nil ||
		entry.handle.kind != CleanupRunner ||
		entry.runner.ID() != handle.ID() ||
		entry.busy ||
		entry.removed ||
		entry.releaseAttempted ||
		entry.releaseAuthorizationReceipt == "" ||
		entry.releaseAuthorization != authorization {
		e.mu.Unlock()
		return ErrFixtureStart
	}
	entry.releaseAttempted = true
	e.mu.Unlock()
	return e.base.ReleaseRunner(ctx, handle, authorization, jit)
}

func (e *recordingEngine) VerifyLoopbackFlood(
	ctx context.Context,
	adapterID string,
	spec hostruntime.VerifierSpec,
	attempts uint64,
) (fixtureFloodObservation, error) {
	if e == nil || e.base == nil || e.floodOperation == nil ||
		ctx == nil || ctx.Err() != nil ||
		!isLowerHex(adapterID, sha256.Size*2) ||
		attempts == 0 ||
		attempts > uint64(^uint32(0)) ||
		(spec.Adapter.ID() != "" &&
			spec.Adapter.ID() != adapterID) {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	e.mu.Lock()
	entry := e.handles[adapterID]
	if entry == nil ||
		entry.handle.kind != CleanupAdapter ||
		entry.handle.id != adapterID ||
		entry.adapter.ID() != adapterID ||
		entry.busy ||
		entry.removed ||
		!e.observationTaken ||
		!isLowerHex(entry.verifierDigest, sha256.Size*2) ||
		entry.floodAttempted ||
		entry.floodReady {
		e.mu.Unlock()
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	spec.Adapter = entry.adapter
	verifierDigest, digestErr := recordingVerifierSpecDigest(
		e.binding,
		spec,
	)
	if digestErr != nil || verifierDigest != entry.verifierDigest {
		e.mu.Unlock()
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	entry.busy = true
	entry.floodAttempted = true
	adapter := entry.adapter
	e.mu.Unlock()

	observation, err := e.floodOperation(
		ctx,
		adapter,
		spec,
		attempts,
	)
	if err != nil ||
		!validFixtureFloodObservation(observation, uint32(attempts)) {
		e.mu.Lock()
		entry.busy = false
		e.mu.Unlock()
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if current := e.handles[adapterID]; current != entry ||
		!entry.busy ||
		entry.removed ||
		entry.floodReady {
		entry.busy = false
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	entry.flood = observation
	entry.floodReady = true
	entry.busy = false
	return observation, nil
}

func (e *recordingEngine) RuntimeObservation(
	held networkjail.HeldJail,
	usage networkjail.PermitUsageProof,
) (fixtureRuntimeObservation, error) {
	if e == nil || e.base == nil ||
		networkjail.ValidateProbeReport(held.ProbeReport()) != nil ||
		!isLowerHex(usage.Digest(), 64) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.observationTaken {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	adapter := e.handles[held.AdapterID()]
	broker := e.handles[held.BrokerID()]
	runner := e.handles[held.RunnerID()]
	if adapter == nil ||
		broker == nil ||
		runner == nil ||
		adapter.handle.kind != CleanupAdapter ||
		broker.handle.kind != CleanupBroker ||
		runner.handle.kind != CleanupRunner ||
		adapter.adapter.ID() != held.AdapterID() ||
		broker.broker.ID() != held.BrokerID() ||
		runner.runner.ID() != held.RunnerID() ||
		broker.parentAdapter != held.AdapterID() ||
		runner.parentAdapter != held.AdapterID() ||
		adapter.busy ||
		broker.busy ||
		runner.busy ||
		adapter.removed ||
		broker.removed ||
		runner.removed ||
		adapter.floodAttempted ||
		adapter.floodReady ||
		runner.releaseAttempted ||
		!isLowerHex(adapter.specDigest, sha256.Size*2) ||
		!isLowerHex(broker.specDigest, sha256.Size*2) ||
		!isLowerHex(runner.specDigest, sha256.Size*2) ||
		!isLowerHex(adapter.verifierDigest, sha256.Size*2) ||
		!isLowerHex(adapter.emptinessDigest, sha256.Size*2) ||
		adapter.emptinessNamespace.Device == 0 ||
		adapter.emptinessNamespace.Inode == 0 ||
		adapter.emptinessNamespace.Device !=
			held.ProbeReport().RunnerNetNSID.Device ||
		adapter.emptinessNamespace.Inode !=
			held.ProbeReport().RunnerNetNSID.Inode ||
		!isLowerHex(broker.policyDigest, sha256.Size*2) ||
		broker.policyDigest != held.ProbeReport().PolicyDigest ||
		!isLowerHex(broker.policyApplicationDigest, sha256.Size*2) ||
		!isLowerHex(broker.helperCapabilityDigest, sha256.Size*2) ||
		!broker.authorityBound ||
		!isLowerHex(broker.authorityReceipt, sha256.Size*2) ||
		!broker.brokerPeerReady ||
		adapter.boundBrokerID != held.BrokerID() ||
		adapter.peerBindingDigest == "" ||
		adapter.peerBindingDigest != broker.peerBindingDigest ||
		adapter.egressDigest == "" ||
		adapter.egressDigest != broker.egressDigest ||
		!networkEgressReportMatchesProbe(
			adapter.egressReport,
			held.ProbeReport(),
		) ||
		broker.auditCount != 1 ||
		runner.auditCount != 2 ||
		runner.seedReceipt == "" ||
		runner.preNamespaceReceipt == "" ||
		runner.armReceipt == "" ||
		runner.finalNamespaceReceipt == "" ||
		runner.releaseAuthorizationReceipt == "" ||
		!isLowerHex(broker.auditDigest, 64) ||
		!isLowerHex(runner.auditDigest, 64) ||
		!isLowerHex(broker.heldSocketZero, 64) ||
		!isLowerHex(broker.releaseDigest, 64) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	authorityBindingDigest, err := usage.BindAuthority(
		broker.authorityProof,
	)
	if err != nil || !isLowerHex(authorityBindingDigest, 64) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	runtimeCapabilityDigest := e.boundReceipt(
		"portable-ghar.task11.runtime-capabilities-empty.v1\x00",
		adapter.specDigest,
		broker.specDigest,
		runner.specDigest,
		adapter.verifierDigest,
		adapter.emptinessDigest,
		adapter.egressDigest,
		broker.auditDigest,
		runner.auditDigest,
		"adapter-broker-runner-verifier-empty",
		"success",
	)
	observation := fixtureRuntimeObservation{
		Adapter:                      adapter.handle,
		Broker:                       broker.handle,
		Runner:                       runner.handle,
		AdapterSpecDigest:            adapter.specDigest,
		BrokerSpecDigest:             broker.specDigest,
		RunnerSpecDigest:             runner.specDigest,
		VerifierSpecDigest:           adapter.verifierDigest,
		AdapterEmptinessDigest:       adapter.emptinessDigest,
		AdapterNamespace:             adapter.emptinessNamespace,
		PolicyDigest:                 broker.policyDigest,
		PolicyApplicationDigest:      broker.policyApplicationDigest,
		HelperCapabilityDigest:       broker.helperCapabilityDigest,
		AuthorityBindingReceipt:      broker.authorityReceipt,
		BrokerPeerBindingDigest:      broker.peerBindingDigest,
		NetworkEgressDigest:          adapter.egressDigest,
		NetworkEgressReport:          adapter.egressReport,
		NamespacePreArmReceipt:       runner.preNamespaceReceipt,
		NamespaceFinalReceipt:        runner.finalNamespaceReceipt,
		ReleaseAuthorizationReceipt:  runner.releaseAuthorizationReceipt,
		RuntimeCapabilityDigest:      runtimeCapabilityDigest,
		BrokerAuditDigest:            broker.auditDigest,
		RunnerAuditDigest:            runner.auditDigest,
		HeldSocketZeroDigest:         broker.heldSocketZero,
		BrokerReleaseDigest:          broker.releaseDigest,
		PermitUsageDigest:            usage.Digest(),
		PermitAuthorityBindingDigest: authorityBindingDigest,
		ProbeReport:                  held.ProbeReport(),
	}
	preparedDigest, err := recordingCanonicalDigest(
		"portable-ghar.task11.prepared-evidence.v1\x00",
		struct {
			SchemaVersion                uint32                               `json:"schema_version"`
			Binding                      recordingRuntimeBinding              `json:"binding"`
			AdapterID                    string                               `json:"adapter_id"`
			BrokerID                     string                               `json:"broker_id"`
			RunnerID                     string                               `json:"runner_id"`
			AdapterSpecDigest            string                               `json:"adapter_spec_digest"`
			BrokerSpecDigest             string                               `json:"broker_spec_digest"`
			RunnerSpecDigest             string                               `json:"runner_spec_digest"`
			VerifierSpecDigest           string                               `json:"verifier_spec_digest"`
			AdapterEmptinessDigest       string                               `json:"adapter_emptiness_digest"`
			AdapterNamespace             hostruntime.NetworkNamespaceIdentity `json:"adapter_namespace"`
			PolicyDigest                 string                               `json:"policy_digest"`
			PolicyApplicationDigest      string                               `json:"policy_application_digest"`
			HelperCapabilityDigest       string                               `json:"helper_capability_digest"`
			AuthorityBindingReceipt      string                               `json:"authority_binding_receipt"`
			BrokerPeerBindingDigest      string                               `json:"broker_peer_binding_digest"`
			NetworkEgressDigest          string                               `json:"network_egress_digest"`
			NetworkEgressReport          hostruntime.NetworkVerifierReport    `json:"network_egress_report"`
			SeedReceipt                  string                               `json:"seed_receipt"`
			NamespacePreArmReceipt       string                               `json:"namespace_pre_arm_receipt"`
			ArmReceipt                   string                               `json:"arm_receipt"`
			NamespaceFinalReceipt        string                               `json:"namespace_final_receipt"`
			ReleaseAuthorizationReceipt  string                               `json:"release_authorization_receipt"`
			RuntimeCapabilityDigest      string                               `json:"runtime_capability_digest"`
			BrokerAuditDigest            string                               `json:"broker_audit_digest"`
			RunnerAuditDigest            string                               `json:"runner_audit_digest"`
			HeldSocketZeroDigest         string                               `json:"held_socket_zero_digest"`
			BrokerReleaseDigest          string                               `json:"broker_release_digest"`
			PermitUsageDigest            string                               `json:"permit_usage_digest"`
			PermitAuthorityBindingDigest string                               `json:"permit_authority_binding_digest"`
			ProbeReport                  networkjail.ProbeReport              `json:"probe_report"`
			Success                      bool                                 `json:"success"`
		}{
			SchemaVersion:                1,
			Binding:                      e.binding,
			AdapterID:                    held.AdapterID(),
			BrokerID:                     held.BrokerID(),
			RunnerID:                     held.RunnerID(),
			AdapterSpecDigest:            observation.AdapterSpecDigest,
			BrokerSpecDigest:             observation.BrokerSpecDigest,
			RunnerSpecDigest:             observation.RunnerSpecDigest,
			VerifierSpecDigest:           observation.VerifierSpecDigest,
			AdapterEmptinessDigest:       observation.AdapterEmptinessDigest,
			AdapterNamespace:             observation.AdapterNamespace,
			PolicyDigest:                 observation.PolicyDigest,
			PolicyApplicationDigest:      observation.PolicyApplicationDigest,
			HelperCapabilityDigest:       observation.HelperCapabilityDigest,
			AuthorityBindingReceipt:      observation.AuthorityBindingReceipt,
			BrokerPeerBindingDigest:      observation.BrokerPeerBindingDigest,
			NetworkEgressDigest:          observation.NetworkEgressDigest,
			NetworkEgressReport:          observation.NetworkEgressReport,
			SeedReceipt:                  runner.seedReceipt,
			NamespacePreArmReceipt:       observation.NamespacePreArmReceipt,
			ArmReceipt:                   runner.armReceipt,
			NamespaceFinalReceipt:        observation.NamespaceFinalReceipt,
			ReleaseAuthorizationReceipt:  observation.ReleaseAuthorizationReceipt,
			RuntimeCapabilityDigest:      observation.RuntimeCapabilityDigest,
			BrokerAuditDigest:            observation.BrokerAuditDigest,
			RunnerAuditDigest:            observation.RunnerAuditDigest,
			HeldSocketZeroDigest:         observation.HeldSocketZeroDigest,
			BrokerReleaseDigest:          observation.BrokerReleaseDigest,
			PermitUsageDigest:            observation.PermitUsageDigest,
			PermitAuthorityBindingDigest: observation.PermitAuthorityBindingDigest,
			ProbeReport:                  observation.ProbeReport,
			Success:                      true,
		},
	)
	if err != nil || !isLowerHex(runtimeCapabilityDigest, sha256.Size*2) ||
		!isLowerHex(preparedDigest, sha256.Size*2) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	observation.PreparedEvidenceDigest = preparedDigest
	if !validFixtureRuntimeObservationCore(observation) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	e.observationTaken = true
	return observation, nil
}

func recordingReceiptDigest(label string, values ...string) string {
	hash := sha256.New()
	writeRecordingReceiptField(hash, label)
	for _, value := range values {
		writeRecordingReceiptField(hash, value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeRecordingReceiptField(writer io.Writer, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}

var _ hostruntime.Engine = (*recordingEngine)(nil)
