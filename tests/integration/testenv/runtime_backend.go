package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

const fixtureCleanupProofDomain = "portable-ghar.task11.cleanup-proof.v1\x00"

type fixtureRootRemover interface {
	RemoveRoot(context.Context, cleanupHandle) error
}

type fixtureRuntimeGraph interface {
	Prepare(context.Context) error
	LoopbackFlood(
		context.Context,
		uint32,
	) (fixtureFloodObservation, error)
	Remove(context.Context, cleanupHandle) error
	RecordedRemoved(cleanupHandle) bool
	RuntimeObservation(
		context.Context,
	) (fixtureRuntimeObservation, error)
}

type fixtureFloodObservation struct {
	EvidenceDigest string
	Report         hostruntime.LoopbackFloodReport
}

type fixtureRuntimeObservation struct {
	Adapter                      cleanupHandle
	Broker                       cleanupHandle
	Runner                       cleanupHandle
	AdapterSpecDigest            string
	BrokerSpecDigest             string
	RunnerSpecDigest             string
	VerifierSpecDigest           string
	AdapterEmptinessDigest       string
	AdapterNamespace             hostruntime.NetworkNamespaceIdentity
	PolicyDigest                 string
	PolicyApplicationDigest      string
	HelperCapabilityDigest       string
	AuthorityBindingReceipt      string
	BrokerPeerBindingDigest      string
	NetworkEgressDigest          string
	NetworkEgressReport          hostruntime.NetworkVerifierReport
	NamespacePreArmReceipt       string
	NamespaceFinalReceipt        string
	ReleaseAuthorizationReceipt  string
	RuntimeCapabilityDigest      string
	PreparedEvidenceDigest       string
	BrokerAuditDigest            string
	RunnerAuditDigest            string
	HeldSocketZeroDigest         string
	BrokerReleaseDigest          string
	PermitUsageDigest            string
	PermitAuthorityBindingDigest string
	ProbeMembershipDigest        string
	PreparedProbeBindingDigest   string
	ProbeReport                  networkjail.ProbeReport
}

type fixtureStateStoreOpener func(
	string,
	state.HistoryLimits,
) (*state.SQLiteStore, error)

type fixtureRuntimeGraphFactory func(
	context.Context,
	*state.SQLiteStore,
	func(cleanupHandle) error,
) (fixtureRuntimeGraph, error)

type fixtureRuntimeBackend struct {
	input          ConformanceInput
	plan           compositionPlan
	brokerUser     string
	workspace      *fixtureWorkspace
	root           fixtureRootRemover
	openStore      fixtureStateStoreOpener
	runtimeFactory fixtureRuntimeGraphFactory
	now            func() time.Time

	mu               sync.Mutex
	startAttempted   bool
	effectHandles    []cleanupHandle
	store            *state.SQLiteStore
	storeCloseTried  bool
	storeClosed      bool
	runtime          fixtureRuntimeGraph
	removed          map[cleanupHandle]bool
	workspaceRemoved bool
	rootRemoved      bool
	floodAttempted   bool
	floodReady       bool
	flood            fixtureFloodObservation
	observationTaken bool
	observation      fixtureRuntimeObservation
}

func newFixtureRuntimeBackend(
	input ConformanceInput,
	plan compositionPlan,
	brokerUser string,
	workspace *fixtureWorkspace,
	root fixtureRootRemover,
	openStore fixtureStateStoreOpener,
	runtimeFactory fixtureRuntimeGraphFactory,
	now func() time.Time,
) (*fixtureRuntimeBackend, error) {
	uid, _, brokerOK := parseStaticNumericUser(brokerUser)
	expectedWorkspace, workspaceErr := compositionCleanupHandle(
		CleanupTestProcess,
		"portable-ghar.task11.workspace.v1\x00",
		input.Authorization.RunID,
	)
	if workspaceErr != nil ||
		workspace == nil ||
		workspace.handle != expectedWorkspace ||
		root == nil ||
		openStore == nil ||
		runtimeFactory == nil ||
		now == nil ||
		!brokerOK ||
		uid == 0 ||
		!validAbsolutePath(input.Fixture.Root) ||
		!isLowerHex(input.Fixture.RequiredEmptyDigest, sha256.Size*2) ||
		plan.AssignmentKey.RepositoryAlias !=
			"portable-ghar-conformance" ||
		plan.AssignmentKey.RunnerRequestID !=
			plan.Identity.RunnerRequestID ||
		plan.Identity.RunnerRequestID <= 0 ||
		plan.Identity.CapacitySlotID == 0 ||
		plan.Identity.SlotIdentity == "" {
		return nil, ErrFixtureStart
	}
	return &fixtureRuntimeBackend{
		input:          input,
		plan:           plan,
		brokerUser:     brokerUser,
		workspace:      workspace,
		root:           root,
		openStore:      openStore,
		runtimeFactory: runtimeFactory,
		now:            now,
		removed:        make(map[cleanupHandle]bool),
	}, nil
}

func (b *fixtureRuntimeBackend) Start(
	ctx context.Context,
	record func(cleanupHandle) error,
) error {
	if b == nil || ctx == nil || ctx.Err() != nil || record == nil {
		return ErrFixtureStart
	}
	b.mu.Lock()
	if b.startAttempted {
		b.mu.Unlock()
		return ErrFixtureStart
	}
	b.startAttempted = true
	b.mu.Unlock()

	trackedRecord := func(handle cleanupHandle) error {
		if !validCleanupKind(handle.kind) ||
			!isLowerHex(handle.id, sha256.Size*2) {
			return ErrFixtureStart
		}
		b.mu.Lock()
		for _, existing := range b.effectHandles {
			if existing.id == handle.id {
				b.mu.Unlock()
				return ErrFixtureStart
			}
		}
		b.mu.Unlock()
		if err := record(handle); err != nil {
			return ErrFixtureStart
		}
		b.mu.Lock()
		b.effectHandles = append(b.effectHandles, handle)
		b.mu.Unlock()
		return nil
	}
	if err := b.workspace.Acquire(
		ctx,
		b.brokerUser,
		trackedRecord,
	); err != nil {
		return ErrFixtureStart
	}
	databasePath, err := b.workspace.StateDatabasePath()
	if err != nil {
		return ErrFixtureStart
	}
	store, err := b.openStore(databasePath, b.plan.HistoryLimits)
	if err != nil || store == nil || store.DB() == nil {
		if store != nil {
			_ = store.Close()
		}
		return ErrFixtureStart
	}
	b.mu.Lock()
	b.store = store
	b.mu.Unlock()
	now := b.now().UTC()
	if now.IsZero() ||
		seedCompositionAssignment(ctx, store, b.plan, now) != nil {
		return ErrFixtureStart
	}
	runtimeGraph, err := b.runtimeFactory(ctx, store, trackedRecord)
	if err != nil || runtimeGraph == nil {
		return ErrFixtureStart
	}
	b.mu.Lock()
	b.runtime = runtimeGraph
	b.mu.Unlock()
	if err := runtimeGraph.Prepare(ctx); err != nil {
		return ErrFixtureStart
	}
	return nil
}

func (b *fixtureRuntimeBackend) CloseUnstarted() error {
	if b == nil || b.workspace == nil {
		return ErrFixtureCleanup
	}
	b.mu.Lock()
	started := b.startAttempted
	b.mu.Unlock()
	if started {
		return nil
	}
	return b.workspace.CloseUnstarted()
}

func (b *fixtureRuntimeBackend) RuntimeObservation(
	ctx context.Context,
) (fixtureRuntimeObservation, error) {
	if b == nil || ctx == nil || ctx.Err() != nil {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	b.mu.Lock()
	runtimeGraph := b.runtime
	started := b.startAttempted
	if !started || runtimeGraph == nil || b.observationTaken {
		b.mu.Unlock()
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	b.observationTaken = true
	b.mu.Unlock()
	observation, err := runtimeGraph.RuntimeObservation(ctx)
	if err != nil || !validFixtureRuntimeObservation(observation) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	b.mu.Lock()
	b.observation = observation
	b.mu.Unlock()
	return observation, nil
}

func (b *fixtureRuntimeBackend) LoopbackFlood(
	ctx context.Context,
	attempts uint32,
) (fixtureFloodObservation, error) {
	if b == nil || ctx == nil || ctx.Err() != nil ||
		attempts == 0 ||
		attempts != b.input.LoopbackFloodAttempts {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	b.mu.Lock()
	if !b.startAttempted ||
		b.runtime == nil ||
		b.floodAttempted ||
		b.floodReady {
		b.mu.Unlock()
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	b.floodAttempted = true
	runtimeGraph := b.runtime
	b.mu.Unlock()

	observation, err := runtimeGraph.LoopbackFlood(ctx, attempts)
	if err != nil || !validFixtureFloodObservation(observation, attempts) {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	b.mu.Lock()
	if b.floodReady {
		b.mu.Unlock()
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	b.flood = observation
	b.floodReady = true
	b.mu.Unlock()
	return observation, nil
}

func (b *fixtureRuntimeBackend) runtimeForCase(
	ctx context.Context,
) (fixtureRuntimeGraph, error) {
	if b == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrFixtureStart
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.startAttempted ||
		b.runtime == nil ||
		b.workspaceRemoved ||
		b.rootRemoved {
		return nil, ErrFixtureStart
	}
	return b.runtime, nil
}

func (b *fixtureRuntimeBackend) BrokerCaseObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (brokerCaseRuntimeObservation, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return brokerCaseRuntimeObservation{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(brokerCaseRuntime)
	if !ok {
		return brokerCaseRuntimeObservation{}, ErrFixtureStart
	}
	return runtime.BrokerCaseObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) MountSecretObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (mountSecretRuntimeObservation, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return mountSecretRuntimeObservation{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(mountSecretRuntime)
	if !ok {
		return mountSecretRuntimeObservation{}, ErrFixtureStart
	}
	return runtime.MountSecretObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) SandboxObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (sandboxRuntimeObservation, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return sandboxRuntimeObservation{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(sandboxRuntime)
	if !ok {
		return sandboxRuntimeObservation{}, ErrFixtureStart
	}
	return runtime.SandboxObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) RunnerPayloadObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (runnerPayloadRuntimeObservation, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return runnerPayloadRuntimeObservation{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(runnerPayloadRuntime)
	if !ok {
		return runnerPayloadRuntimeObservation{}, ErrFixtureStart
	}
	return runtime.RunnerPayloadObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) SyntheticOneJobObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (syntheticOneJobRuntimeObservation, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return syntheticOneJobRuntimeObservation{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(syntheticOneJobRuntime)
	if !ok {
		return syntheticOneJobRuntimeObservation{}, ErrFixtureStart
	}
	return runtime.SyntheticOneJobObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) CleanupMatrixObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (cleanupMatrixRuntimeObservation, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(cleanupMatrixRuntime)
	if !ok {
		return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
	}
	return runtime.CleanupMatrixObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) ReclamationObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (reclamationRuntimeObservation, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return reclamationRuntimeObservation{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(reclamationRuntime)
	if !ok {
		return reclamationRuntimeObservation{}, ErrFixtureStart
	}
	return runtime.ReclamationObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) RegisterWorkflowToolCleanup(
	ctx context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return "", ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(workflowToolProbeRuntime)
	if !ok {
		return "", ErrFixtureStart
	}
	return runtime.RegisterWorkflowToolCleanup(ctx, lease)
}

func (b *fixtureRuntimeBackend) RunWorkflowTool(
	ctx context.Context,
	spec workflowToolProbeSpec,
) (workflowToolExecution, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return workflowToolExecution{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(workflowToolProbeRuntime)
	if !ok {
		return workflowToolExecution{}, ErrFixtureStart
	}
	return runtime.RunWorkflowTool(ctx, spec)
}

func (b *fixtureRuntimeBackend) ProveWorkflowToolAbsent(
	ctx context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return "", ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(workflowToolProbeRuntime)
	if !ok {
		return "", ErrFixtureStart
	}
	return runtime.ProveWorkflowToolAbsent(ctx, lease)
}

func (b *fixtureRuntimeBackend) SeedIsolationObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (SeedIsolationProof, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return SeedIsolationProof{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(seedIsolationRuntime)
	if !ok {
		return SeedIsolationProof{}, ErrFixtureStart
	}
	return runtime.SeedIsolationObservation(ctx, prepared)
}

func (b *fixtureRuntimeBackend) RecoveryObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (SyntheticRecoveryProof, error) {
	runtimeGraph, err := b.runtimeForCase(ctx)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	runtime, ok := runtimeGraph.(recoveryRuntime)
	if !ok {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	return runtime.RecoveryObservation(ctx, prepared)
}

func validFixtureRuntimeObservation(
	observation fixtureRuntimeObservation,
) bool {
	return validFixtureRuntimeObservationCore(observation) &&
		isLowerHex(
			observation.ProbeMembershipDigest,
			sha256.Size*2,
		) &&
		isLowerHex(
			observation.PreparedProbeBindingDigest,
			sha256.Size*2,
		)
}

func validFixtureRuntimeObservationCore(
	observation fixtureRuntimeObservation,
) bool {
	return observation.Adapter.kind == CleanupAdapter &&
		observation.Broker.kind == CleanupBroker &&
		observation.Runner.kind == CleanupRunner &&
		isLowerHex(observation.Adapter.id, sha256.Size*2) &&
		isLowerHex(observation.Broker.id, sha256.Size*2) &&
		isLowerHex(observation.Runner.id, sha256.Size*2) &&
		observation.Adapter.id != observation.Broker.id &&
		observation.Adapter.id != observation.Runner.id &&
		observation.Broker.id != observation.Runner.id &&
		isLowerHex(observation.AdapterSpecDigest, sha256.Size*2) &&
		isLowerHex(observation.BrokerSpecDigest, sha256.Size*2) &&
		isLowerHex(observation.RunnerSpecDigest, sha256.Size*2) &&
		isLowerHex(observation.VerifierSpecDigest, sha256.Size*2) &&
		isLowerHex(observation.AdapterEmptinessDigest, sha256.Size*2) &&
		observation.AdapterNamespace.Device != 0 &&
		observation.AdapterNamespace.Inode != 0 &&
		isLowerHex(observation.PolicyDigest, sha256.Size*2) &&
		isLowerHex(observation.PolicyApplicationDigest, sha256.Size*2) &&
		isLowerHex(observation.HelperCapabilityDigest, sha256.Size*2) &&
		isLowerHex(observation.AuthorityBindingReceipt, sha256.Size*2) &&
		isLowerHex(observation.BrokerPeerBindingDigest, sha256.Size*2) &&
		isLowerHex(observation.NetworkEgressDigest, sha256.Size*2) &&
		isLowerHex(observation.NamespacePreArmReceipt, sha256.Size*2) &&
		isLowerHex(observation.NamespaceFinalReceipt, sha256.Size*2) &&
		isLowerHex(
			observation.ReleaseAuthorizationReceipt,
			sha256.Size*2,
		) &&
		isLowerHex(observation.RuntimeCapabilityDigest, sha256.Size*2) &&
		isLowerHex(observation.PreparedEvidenceDigest, sha256.Size*2) &&
		isLowerHex(observation.BrokerAuditDigest, sha256.Size*2) &&
		isLowerHex(observation.RunnerAuditDigest, sha256.Size*2) &&
		isLowerHex(observation.HeldSocketZeroDigest, sha256.Size*2) &&
		isLowerHex(observation.BrokerReleaseDigest, sha256.Size*2) &&
		isLowerHex(observation.PermitUsageDigest, sha256.Size*2) &&
		isLowerHex(
			observation.PermitAuthorityBindingDigest,
			sha256.Size*2,
		) &&
		networkjail.ValidateProbeReport(observation.ProbeReport) == nil &&
		observation.PolicyDigest == observation.ProbeReport.PolicyDigest &&
		observation.AdapterNamespace.Device ==
			observation.ProbeReport.RunnerNetNSID.Device &&
		observation.AdapterNamespace.Inode ==
			observation.ProbeReport.RunnerNetNSID.Inode &&
		networkEgressReportMatchesProbe(
			observation.NetworkEgressReport,
			observation.ProbeReport,
		)
}

func networkEgressReportMatchesProbe(
	egress hostruntime.NetworkVerifierReport,
	probe networkjail.ProbeReport,
) bool {
	return egress.PolicyDigest == probe.PolicyDigest &&
		egress.EgressBackend == string(probe.EgressBackend) &&
		egress.RunnerNetNSID.Device == probe.RunnerNetNSID.Device &&
		egress.RunnerNetNSID.Inode == probe.RunnerNetNSID.Inode &&
		egress.BrokerNetNSID.Device == probe.BrokerNetNSID.Device &&
		egress.BrokerNetNSID.Inode == probe.BrokerNetNSID.Inode &&
		egress.RunnerLoopbackOnly == probe.RunnerLoopbackOnly &&
		egress.RunnerTablesEmpty == probe.RunnerTablesEmpty &&
		egress.RunnerConntrackEmpty == probe.RunnerConntrackEmpty &&
		egress.ParserHasNoSocket == probe.ParserHasNoSocket &&
		egress.PositiveOK == probe.PositiveOK &&
		egress.NegativeOK == probe.NegativeOK
}

func validFixtureFloodObservation(
	observation fixtureFloodObservation,
	attempts uint32,
) bool {
	report := observation.Report
	return attempts != 0 &&
		uint64(attempts) == report.Attempts &&
		isLowerHex(observation.EvidenceDigest, sha256.Size*2) &&
		report.Completed &&
		report.Namespace.Device != 0 &&
		report.Namespace.Inode != 0 &&
		report.LoopbackOnly &&
		report.TablesEmpty &&
		report.ConntrackEmpty &&
		report.RoutesComplete
}

func (b *fixtureRuntimeBackend) Remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if b == nil || ctx == nil || ctx.Err() != nil ||
		!validCleanupKind(handle.kind) ||
		!isLowerHex(handle.id, sha256.Size*2) {
		return ErrFixtureCleanup
	}
	b.mu.Lock()
	if b.removed[handle] {
		b.mu.Unlock()
		return nil
	}
	runtimeGraph := b.runtime
	b.mu.Unlock()

	var err error
	switch handle.kind {
	case CleanupRunner, CleanupBroker, CleanupAdapter,
		CleanupVerifier, CleanupSyntheticListener:
		if runtimeGraph == nil {
			return ErrFixtureCleanup
		}
		err = runtimeGraph.Remove(ctx, handle)
	case CleanupTestProcess:
		if handle != b.workspace.handle {
			return ErrFixtureCleanup
		}
		if err = b.closeStore(); err == nil {
			err = b.workspace.Remove(ctx, handle)
		}
		if err == nil {
			b.mu.Lock()
			b.workspaceRemoved = true
			b.mu.Unlock()
		}
	case CleanupFixtureRoot:
		expected := cleanupHandle{
			kind: CleanupFixtureRoot,
			id:   b.input.Fixture.RequiredEmptyDigest,
		}
		if handle != expected {
			return ErrFixtureCleanup
		}
		err = b.root.RemoveRoot(ctx, handle)
		if err == nil {
			b.mu.Lock()
			b.rootRemoved = true
			b.mu.Unlock()
		}
	default:
		return ErrFixtureCleanup
	}
	if err != nil {
		if err == ErrFixtureUnexpectedObject {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	b.mu.Lock()
	b.removed[handle] = true
	b.mu.Unlock()
	return nil
}

func (b *fixtureRuntimeBackend) Prove(
	ctx context.Context,
	handles []cleanupHandle,
	binding FixtureBinding,
) (conformance.CleanupObservation, error) {
	if b == nil || ctx == nil || ctx.Err() != nil ||
		binding != b.input.Fixture {
		return conformance.CleanupObservation{}, ErrFixtureCleanup
	}
	b.mu.Lock()
	expected := make([]cleanupHandle, 0, len(b.effectHandles)+1)
	expected = append(expected, cleanupHandle{
		kind: CleanupFixtureRoot,
		id:   b.input.Fixture.RequiredEmptyDigest,
	})
	expected = append(expected, b.effectHandles...)
	runtimeGraph := b.runtime
	storeClosed := b.store == nil || b.storeClosed
	workspaceRemoved := b.workspaceRemoved
	rootRemoved := b.rootRemoved
	removed := make(map[cleanupHandle]bool, len(b.removed))
	for handle, value := range b.removed {
		removed[handle] = value
	}
	b.mu.Unlock()
	if len(handles) != len(expected) || len(handles) == 0 {
		return conformance.CleanupObservation{}, ErrFixtureCleanup
	}
	for index, handle := range handles {
		if handle != expected[index] || !removed[handle] {
			return conformance.CleanupObservation{}, ErrFixtureCleanup
		}
		switch handle.kind {
		case CleanupRunner, CleanupBroker, CleanupAdapter,
			CleanupVerifier, CleanupSyntheticListener:
			if runtimeGraph == nil ||
				!runtimeGraph.RecordedRemoved(handle) {
				return conformance.CleanupObservation{},
					ErrFixtureCleanup
			}
		}
	}
	workspaceExpected := linuxWorkspaceNamePresentCleanup(
		handles,
		CleanupTestProcess,
	)
	if workspaceExpected != workspaceRemoved || !storeClosed ||
		!rootRemoved {
		return conformance.CleanupObservation{}, ErrFixtureCleanup
	}
	wire := fixtureCleanupProofWire{
		SchemaVersion: 1,
		FixtureRoot:   binding.Root,
		RootDigest:    binding.RequiredEmptyDigest,
		Handles:       make([]fixtureCleanupHandleWire, 0, len(handles)),
	}
	for _, handle := range handles {
		wire.Handles = append(wire.Handles, fixtureCleanupHandleWire{
			Kind: uint8(handle.kind),
			ID:   handle.id,
		})
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return conformance.CleanupObservation{}, ErrFixtureCleanup
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(fixtureCleanupProofDomain))
	_, _ = digest.Write(document)
	assertions := len(handles) + 3
	if assertions <= 0 {
		return conformance.CleanupObservation{}, ErrFixtureCleanup
	}
	return conformance.CleanupObservation{
		AssertionCount:    uint64(assertions),
		ObservationDigest: hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func (b *fixtureRuntimeBackend) closeStore() error {
	b.mu.Lock()
	if b.store == nil {
		b.storeClosed = true
		b.mu.Unlock()
		return nil
	}
	if b.storeCloseTried {
		closed := b.storeClosed
		b.mu.Unlock()
		if closed {
			return nil
		}
		return ErrFixtureCleanup
	}
	b.storeCloseTried = true
	store := b.store
	b.mu.Unlock()
	if err := store.Close(); err != nil {
		return ErrFixtureCleanup
	}
	b.mu.Lock()
	b.storeClosed = true
	b.mu.Unlock()
	return nil
}

type fixtureCleanupHandleWire struct {
	Kind uint8  `json:"kind"`
	ID   string `json:"id"`
}

type fixtureCleanupProofWire struct {
	SchemaVersion uint32                     `json:"schema_version"`
	FixtureRoot   string                     `json:"fixture_root"`
	RootDigest    string                     `json:"root_digest"`
	Handles       []fixtureCleanupHandleWire `json:"handles"`
}

func linuxWorkspaceNamePresentCleanup(
	handles []cleanupHandle,
	kind CleanupKind,
) bool {
	for _, handle := range handles {
		if handle.kind == kind {
			return true
		}
	}
	return false
}

type orchestratedFixtureRuntime struct {
	composition fixtureRuntimeComposition

	mu               sync.Mutex
	lossPrevention   *task11LossPreventionRuntime
	lossAttempt      *task11RealLossAttemptSource
	task11Sessions   *task11RuntimeSessionSource
	task11Cases      *task11CasesThreeToSixRuntime
	task11Workflow   *task11WorkflowToolRuntime
	task11Synthetic  *task11SyntheticLifecycleRuntime
	task11Recovery   *task11RecoveryRuntime
	prepareAttempted bool
	held             networkjail.HeldJail
	heldReady        bool
	usage            networkjail.PermitUsageProof
	usageReady       bool
	nonconsumption   *permitNonconsumptionTracker
	floodAttempted   bool
	floodReady       bool
	flood            fixtureFloodObservation
	observationTaken bool
	observationReady bool
	observation      fixtureRuntimeObservation
	destroyAttempted bool
	destroyed        bool
}

func (r *orchestratedFixtureRuntime) bindTask11CasesThreeToSix() error {
	if r == nil {
		return ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prepareAttempted ||
		r.lossPrevention == nil ||
		r.lossAttempt == nil ||
		r.task11Sessions != nil ||
		r.task11Cases != nil {
		return ErrFixtureStart
	}
	sessions, err := newTask11RuntimeSessionSource(
		r.composition,
		r,
	)
	if err != nil {
		return ErrFixtureStart
	}
	cases, err := newTask11CasesThreeToSixRuntime(
		task11CasesThreeToSixBinding{
			Graph: r.composition.Request.Graph,
			CapacitySlotID: networkjail.CapacitySlotID(
				r.composition.Request.Broker.CapacitySlotID,
			),
			JobGeneration: networkjail.JobGeneration(
				r.composition.Request.Broker.JobGeneration,
			),
			RunnerUser: r.composition.RunnerUser,
		},
		r,
		sessions,
		r,
		sessions,
	)
	if err != nil {
		return ErrFixtureStart
	}
	r.task11Sessions = sessions
	r.task11Cases = cases
	return nil
}

func (r *orchestratedFixtureRuntime) bindTask11WorkflowTool(
	workflow *task11WorkflowToolRuntime,
) error {
	if r == nil || workflow == nil || workflow.owner != r {
		return ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prepareAttempted || r.task11Workflow != nil {
		return ErrFixtureStart
	}
	r.task11Workflow = workflow
	return nil
}

func (r *orchestratedFixtureRuntime) bindTask11SyntheticLifecycle(
	synthetic *task11SyntheticLifecycleRuntime,
) error {
	if r == nil ||
		synthetic == nil ||
		synthetic.prepared != r {
		return ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prepareAttempted || r.task11Synthetic != nil {
		return ErrFixtureStart
	}
	r.task11Synthetic = synthetic
	return nil
}

func (r *orchestratedFixtureRuntime) Prepare(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ErrFixtureStart
	}
	r.mu.Lock()
	if r.prepareAttempted {
		r.mu.Unlock()
		return ErrFixtureStart
	}
	r.prepareAttempted = true
	r.mu.Unlock()
	held, err := r.composition.Orchestrator.Prepare(
		ctx,
		r.composition.Request,
	)
	if err != nil {
		return ErrFixtureStart
	}
	r.mu.Lock()
	r.held = held
	r.heldReady = true
	r.mu.Unlock()
	recoverable, err := r.composition.Store.ListRecoverable(ctx)
	if err != nil ||
		len(recoverable) != 1 ||
		recoverable[0].Key != r.composition.Request.Key ||
		recoverable[0].State != controller.StateReleaseArmed ||
		recoverable[0].Slot.AdapterContainerID != held.AdapterID() ||
		recoverable[0].Slot.BrokerContainerID != held.BrokerID() ||
		recoverable[0].Slot.RunnerContainerID != held.RunnerID() {
		return ErrFixtureStart
	}
	authorizeEffect, err := r.composition.Store.LookupAssignmentEffect(
		ctx,
		r.composition.Request.Key,
		networkjail.StageRunnerAuthorize.String(),
	)
	if err != nil ||
		authorizeEffect.State != state.EffectCompleted ||
		authorizeEffect.ResultIdentity != "" ||
		authorizeEffect.ReasonCode != "" {
		return ErrFixtureStart
	}
	slot := networkjail.CapacitySlotID(
		r.composition.Request.Broker.CapacitySlotID,
	)
	generation := networkjail.JobGeneration(
		r.composition.Request.Broker.JobGeneration,
	)
	usage, err := r.composition.Authority.AuditActiveUsage(
		ctx,
		slot,
		generation,
	)
	if err != nil ||
		!usage.Matches(slot, generation) ||
		!isLowerHex(usage.Digest(), sha256.Size*2) {
		return ErrFixtureStart
	}
	r.mu.Lock()
	r.usage = usage
	r.usageReady = true
	r.nonconsumption, err = newPermitNonconsumptionTracker(
		usage.Digest(),
		slot,
		generation,
	)
	r.mu.Unlock()
	if err != nil {
		return ErrFixtureStart
	}
	return nil
}

func (r *orchestratedFixtureRuntime) ProvePermitNonconsumption(
	ctx context.Context,
	closedDenials closedDenialsSessionObservation,
) (permitNonconsumptionProof, error) {
	if r == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		!validClosedDenialsSessionObservation(
			closedDenials,
			r.composition.Request.Graph,
		) {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	r.mu.Lock()
	tracker := r.nonconsumption
	source := r.composition.UsageAudit
	ready := r.heldReady &&
		r.usageReady &&
		tracker != nil &&
		source != nil &&
		!r.destroyAttempted &&
		!r.destroyed
	r.mu.Unlock()
	if !ready ||
		tracker.PreparedUsageDigest() == "" ||
		closedDenials.PolicyDigest !=
			r.composition.Request.Graph.Digest().String() {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	proof, err := tracker.Prove(
		ctx,
		source,
		closedDenials.PolicyDigest,
		closedDenials.Digest,
	)
	if err != nil ||
		!proof.Matches(
			tracker.PreparedUsageDigest(),
			closedDenials.PolicyDigest,
			networkjail.CapacitySlotID(
				r.composition.Request.Broker.CapacitySlotID,
			),
			networkjail.JobGeneration(
				r.composition.Request.Broker.JobGeneration,
			),
			closedDenials.Digest,
		) {
		return permitNonconsumptionProof{}, ErrFixtureStart
	}
	return proof, nil
}

func (r *orchestratedFixtureRuntime) LoopbackFlood(
	ctx context.Context,
	attempts uint32,
) (fixtureFloodObservation, error) {
	if r == nil || ctx == nil || ctx.Err() != nil ||
		r.composition.Engine == nil ||
		attempts == 0 ||
		attempts != r.composition.FloodAttempts {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	if !r.heldReady ||
		!r.usageReady ||
		r.floodAttempted ||
		r.floodReady ||
		r.destroyAttempted ||
		r.destroyed {
		r.mu.Unlock()
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	r.floodAttempted = true
	held := r.held
	r.mu.Unlock()

	observation, err := r.composition.Engine.VerifyLoopbackFlood(
		ctx,
		held.AdapterID(),
		r.composition.Request.Verifier,
		uint64(attempts),
	)
	if err != nil || !validFixtureFloodObservation(observation, attempts) {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	report := observation.Report
	probe := held.ProbeReport()
	if report.Namespace.Device != probe.RunnerNetNSID.Device ||
		report.Namespace.Inode != probe.RunnerNetNSID.Inode {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.floodReady || r.destroyAttempted || r.destroyed {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	r.flood = observation
	r.floodReady = true
	return observation, nil
}

func (r *orchestratedFixtureRuntime) Remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ErrFixtureCleanup
	}
	r.mu.Lock()
	heldReady := r.heldReady
	held := r.held
	lossAttempt := r.lossAttempt
	workflow := r.task11Workflow
	synthetic := r.task11Synthetic
	recovery := r.task11Recovery
	if heldReady &&
		handle.kind == CleanupRunner &&
		handle.id == held.RunnerID() {
		if r.destroyAttempted {
			destroyed := r.destroyed
			r.mu.Unlock()
			if destroyed {
				return nil
			}
			return ErrFixtureCleanup
		}
		r.destroyAttempted = true
		r.mu.Unlock()
		if err := r.composition.Orchestrator.DestroyHeld(
			ctx,
			held,
		); err != nil {
			return ErrFixtureCleanup
		}
		r.mu.Lock()
		r.destroyed = true
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if recovery != nil && recovery.owns(handle) {
		if recovery.remove(ctx, handle) != nil {
			return ErrFixtureCleanup
		}
		return nil
	}
	if synthetic != nil && synthetic.owns(handle) {
		if synthetic.remove(ctx, handle) != nil {
			return ErrFixtureCleanup
		}
		return nil
	}
	if workflow != nil && workflow.owns(handle) {
		if workflow.remove(ctx, handle) != nil {
			return ErrFixtureCleanup
		}
		return nil
	}
	if lossAttempt != nil && lossAttempt.owns(handle) {
		if lossAttempt.remove(ctx, handle) != nil {
			return ErrFixtureCleanup
		}
		return nil
	}
	if handle.kind == CleanupVerifier {
		if r.composition.OneShotLeases == nil ||
			r.composition.OneShotLeases.Remove(
				ctx,
				handle,
			) != nil {
			return ErrFixtureCleanup
		}
		return nil
	}
	if err := r.composition.Engine.RemoveRecorded(ctx, handle); err != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (r *orchestratedFixtureRuntime) RecordedRemoved(
	handle cleanupHandle,
) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	lossAttempt := r.lossAttempt
	workflow := r.task11Workflow
	synthetic := r.task11Synthetic
	recovery := r.task11Recovery
	r.mu.Unlock()
	if recovery != nil && recovery.owns(handle) {
		return recovery.recordedRemoved(handle)
	}
	if synthetic != nil && synthetic.owns(handle) {
		return synthetic.recordedRemoved(handle)
	}
	if workflow != nil && workflow.owns(handle) {
		return workflow.recordedRemoved(handle)
	}
	if lossAttempt != nil && lossAttempt.owns(handle) {
		return lossAttempt.recordedRemoved(handle)
	}
	if handle.kind == CleanupVerifier {
		return r.composition.OneShotLeases != nil &&
			r.composition.OneShotLeases.RecordedRemoved(handle)
	}
	return r.composition.Engine != nil &&
		r.composition.Engine.RecordedRemoved(handle)
}

func (r *orchestratedFixtureRuntime) RuntimeObservation(
	ctx context.Context,
) (fixtureRuntimeObservation, error) {
	if r == nil || ctx == nil || ctx.Err() != nil ||
		r.composition.Engine == nil {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	held := r.held
	usage := r.usage
	ready := r.heldReady &&
		r.usageReady &&
		!r.observationTaken &&
		!r.destroyAttempted &&
		!r.destroyed
	if ready {
		r.observationTaken = true
	}
	r.mu.Unlock()
	if !ready {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	observation, err := r.composition.Engine.RuntimeObservation(held, usage)
	if err != nil ||
		!validFixtureRuntimeObservationCore(observation) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	probeBinding, err := r.composition.ProbeMembership.BindPreparedReport(
		observation.ProbeReport,
		observation.PermitUsageDigest,
		observation.PermitAuthorityBindingDigest,
	)
	if err != nil {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	observation.ProbeMembershipDigest =
		r.composition.ProbeMembership.Digest()
	observation.PreparedProbeBindingDigest = probeBinding
	if !validFixtureRuntimeObservation(observation) {
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	if r.observationReady ||
		r.destroyAttempted ||
		r.destroyed {
		r.mu.Unlock()
		return fixtureRuntimeObservation{}, ErrFixtureStart
	}
	r.observation = observation
	r.observationReady = true
	r.mu.Unlock()
	return observation, nil
}

func (r *orchestratedFixtureRuntime) SnapshotPreparedEvidence(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (fixtureFloodObservation, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	observation := r.observation
	flood := r.flood
	ready := r.heldReady &&
		r.usageReady &&
		r.observationReady &&
		r.floodReady &&
		!r.destroyAttempted &&
		!r.destroyed
	r.mu.Unlock()
	if !ready ||
		!sameTask11PreparedObservation(
			prepared,
			observation,
			flood,
		) {
		return fixtureFloodObservation{}, ErrFixtureStart
	}
	return flood, nil
}

func (r *orchestratedFixtureRuntime) ProveLossPreventsRelease(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
	primarySeal string,
) (task11LossPreventsReleaseProof, error) {
	if r == nil {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	r.mu.Lock()
	prevention := r.lossPrevention
	ready := r.heldReady &&
		r.usageReady &&
		r.observationReady &&
		r.floodReady &&
		!r.destroyAttempted &&
		!r.destroyed
	r.mu.Unlock()
	if !ready || prevention == nil {
		return task11LossPreventsReleaseProof{}, ErrFixtureStart
	}
	return prevention.ProveLossPreventsRelease(
		ctx,
		prepared,
		primarySeal,
	)
}

func (r *orchestratedFixtureRuntime) BrokerCaseObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (brokerCaseRuntimeObservation, error) {
	if r == nil {
		return brokerCaseRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	cases := r.task11Cases
	r.mu.Unlock()
	if cases == nil {
		return brokerCaseRuntimeObservation{}, ErrFixtureStart
	}
	return cases.BrokerCaseObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) MountSecretObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (mountSecretRuntimeObservation, error) {
	if r == nil {
		return mountSecretRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	cases := r.task11Cases
	r.mu.Unlock()
	if cases == nil {
		return mountSecretRuntimeObservation{}, ErrFixtureStart
	}
	return cases.MountSecretObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) SandboxObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (sandboxRuntimeObservation, error) {
	if r == nil {
		return sandboxRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	cases := r.task11Cases
	r.mu.Unlock()
	if cases == nil {
		return sandboxRuntimeObservation{}, ErrFixtureStart
	}
	return cases.SandboxObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) RunnerPayloadObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (runnerPayloadRuntimeObservation, error) {
	if r == nil {
		return runnerPayloadRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	cases := r.task11Cases
	r.mu.Unlock()
	if cases == nil {
		return runnerPayloadRuntimeObservation{}, ErrFixtureStart
	}
	return cases.RunnerPayloadObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) RegisterWorkflowToolCleanup(
	ctx context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	if r == nil {
		return "", ErrFixtureStart
	}
	r.mu.Lock()
	workflow := r.task11Workflow
	r.mu.Unlock()
	if workflow == nil {
		return "", ErrFixtureStart
	}
	return workflow.RegisterWorkflowToolCleanup(ctx, lease)
}

func (r *orchestratedFixtureRuntime) RunWorkflowTool(
	ctx context.Context,
	spec workflowToolProbeSpec,
) (workflowToolExecution, error) {
	if r == nil {
		return workflowToolExecution{}, ErrFixtureStart
	}
	r.mu.Lock()
	workflow := r.task11Workflow
	r.mu.Unlock()
	if workflow == nil {
		return workflowToolExecution{}, ErrFixtureStart
	}
	return workflow.RunWorkflowTool(ctx, spec)
}

func (r *orchestratedFixtureRuntime) ProveWorkflowToolAbsent(
	ctx context.Context,
	lease workflowToolCleanupLease,
) (string, error) {
	if r == nil {
		return "", ErrFixtureStart
	}
	r.mu.Lock()
	workflow := r.task11Workflow
	r.mu.Unlock()
	if workflow == nil {
		return "", ErrFixtureStart
	}
	return workflow.ProveWorkflowToolAbsent(ctx, lease)
}

func (r *orchestratedFixtureRuntime) SyntheticOneJobObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (syntheticOneJobRuntimeObservation, error) {
	if r == nil {
		return syntheticOneJobRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	synthetic := r.task11Synthetic
	r.mu.Unlock()
	if synthetic == nil {
		return syntheticOneJobRuntimeObservation{}, ErrFixtureStart
	}
	return synthetic.SyntheticOneJobObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) CleanupMatrixObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (cleanupMatrixRuntimeObservation, error) {
	if r == nil {
		return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	synthetic := r.task11Synthetic
	r.mu.Unlock()
	if synthetic == nil {
		return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
	}
	return synthetic.CleanupMatrixObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) ReclamationObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (reclamationRuntimeObservation, error) {
	if r == nil {
		return reclamationRuntimeObservation{}, ErrFixtureStart
	}
	r.mu.Lock()
	synthetic := r.task11Synthetic
	r.mu.Unlock()
	if synthetic == nil {
		return reclamationRuntimeObservation{}, ErrFixtureStart
	}
	return synthetic.ReclamationObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) SeedIsolationObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (SeedIsolationProof, error) {
	if r == nil {
		return SeedIsolationProof{}, ErrFixtureStart
	}
	r.mu.Lock()
	synthetic := r.task11Synthetic
	r.mu.Unlock()
	if synthetic == nil {
		return SeedIsolationProof{}, ErrFixtureStart
	}
	return synthetic.SeedIsolationObservation(ctx, prepared)
}

func (r *orchestratedFixtureRuntime) RecoveryObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (SyntheticRecoveryProof, error) {
	if r == nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	r.mu.Lock()
	recovery := r.task11Recovery
	r.mu.Unlock()
	if recovery == nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	return recovery.RecoveryObservation(ctx, prepared)
}

var (
	_ fixtureEffects              = (*fixtureRuntimeBackend)(nil)
	_ fixtureCleanup              = (*fixtureRuntimeBackend)(nil)
	_ namespaceEvidenceRuntime    = (*fixtureRuntimeBackend)(nil)
	_ brokerCaseRuntime           = (*fixtureRuntimeBackend)(nil)
	_ mountSecretRuntime          = (*fixtureRuntimeBackend)(nil)
	_ sandboxRuntime              = (*fixtureRuntimeBackend)(nil)
	_ runnerPayloadRuntime        = (*fixtureRuntimeBackend)(nil)
	_ syntheticOneJobRuntime      = (*fixtureRuntimeBackend)(nil)
	_ cleanupMatrixRuntime        = (*fixtureRuntimeBackend)(nil)
	_ reclamationRuntime          = (*fixtureRuntimeBackend)(nil)
	_ workflowToolProbeRuntime    = (*fixtureRuntimeBackend)(nil)
	_ seedIsolationRuntime        = (*fixtureRuntimeBackend)(nil)
	_ recoveryRuntime             = (*fixtureRuntimeBackend)(nil)
	_ fixtureRuntimeGraph         = (*orchestratedFixtureRuntime)(nil)
	_ task11PreparedRuntimeSource = (*orchestratedFixtureRuntime)(nil)
	_ task11LossPreventionSource  = (*orchestratedFixtureRuntime)(nil)
	_ brokerCaseRuntime           = (*orchestratedFixtureRuntime)(nil)
	_ mountSecretRuntime          = (*orchestratedFixtureRuntime)(nil)
	_ sandboxRuntime              = (*orchestratedFixtureRuntime)(nil)
	_ runnerPayloadRuntime        = (*orchestratedFixtureRuntime)(nil)
	_ workflowToolProbeRuntime    = (*orchestratedFixtureRuntime)(nil)
	_ syntheticOneJobRuntime      = (*orchestratedFixtureRuntime)(nil)
	_ cleanupMatrixRuntime        = (*orchestratedFixtureRuntime)(nil)
	_ reclamationRuntime          = (*orchestratedFixtureRuntime)(nil)
	_ seedIsolationRuntime        = (*orchestratedFixtureRuntime)(nil)
	_ recoveryRuntime             = (*orchestratedFixtureRuntime)(nil)
)
