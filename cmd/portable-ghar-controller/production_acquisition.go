package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/admission"
	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/failoverclient"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/githubscale"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/lifecycle"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/state"
)

// errStartupCleanup marks a composition failure whose cleanup also failed:
// something it opened, such as a GitHub message session, may still be held.
var errStartupCleanup = errors.New("portable-ghar-controller: startup cleanup failed")

// maxProductionPolicyBytes matches the decision graph's own size bound.
const maxProductionPolicyBytes = 128 << 10

// startupStep names the startup step that failed, so the operator sees where
// run-acquisition stopped. A cause is attached only where it is known to
// carry no secret: construction and validation errors, never a credential
// read.
func startupStep(name string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", errCommandUnavailable, name)
	}
	return fmt.Errorf("%w: %s: %w", errCommandUnavailable, name, cause)
}

// openProductionAcquisitionController composes the acquiring controller from
// the verified runtime. It refuses to start unless the portable fleet holds
// the fence at the manifest's generation, and it holds a portable guard for
// the whole run, so no handover can complete while it runs. The service it
// builds starts disabled; only an operator transition enables acquisition,
// and the conformance gate refuses every active mode until a report exists.
func openProductionAcquisitionController(
	ctx context.Context,
	configPath string,
	databasePath string,
	ownership controllerOwnershipLease,
	logs io.Writer,
) (controllerProcess, error) {
	loaded, err := loadProductionRuntime(ctx, configPath, databasePath, ownership)
	if err != nil {
		return nil, startupStep("verify overlay, manifest, and host", nil)
	}
	overlay, manifest, timings := loaded.overlay, loaded.manifest, loaded.timings
	if overlay.Worker == nil || overlay.GitHub == nil || overlay.Jail == nil ||
		overlay.Resources.MaxCapacity > math.MaxUint32 || logs == nil {
		return nil, startupStep("overlay needs worker, github, and jail sections", nil)
	}
	service, err := parseProductionServiceTimings(overlay.Controller)
	if err != nil {
		return nil, startupStep("parse controller timings", nil)
	}
	dialTimeout, err := time.ParseDuration(overlay.Jail.DialAuthorityTimeout)
	if err != nil {
		return nil, startupStep("parse dial authority timeout", nil)
	}
	brokerUID, err := jailUserID(overlay.Jail.AdapterBrokerUser)
	if err != nil {
		return nil, startupStep("parse adapter-broker user", nil)
	}
	graph, policy, err := readProductionPolicy(overlay)
	if err != nil {
		return nil, startupStep("read decision graph", nil)
	}
	enabledTemplate, err := productionEnabledPolicyTemplate(overlay)
	if err != nil {
		return nil, startupStep("build enabled policy template", nil)
	}
	pressure, err := productionHistoryPressure(overlay, loaded.history)
	if err != nil {
		return nil, startupStep("derive history pressure thresholds", nil)
	}
	hmacPath, ok := fileSecretPath(overlay, overlay.Worker.HMACCredentialName)
	if !ok {
		return nil, startupStep("find Worker HMAC file secret", nil)
	}
	hmacKey, err := readCredentialFile(hmacPath)
	if err != nil {
		return nil, startupStep("read Worker HMAC secret", nil)
	}

	resources := &productionControllerResources{}
	fail := func(primary error) (controllerProcess, error) {
		if cleanupErr := resources.Close(); cleanupErr != nil {
			return nil, errors.Join(primary, errStartupCleanup, cleanupErr)
		}
		return nil, primary
	}
	store, err := state.OpenWithHistoryLimits(databasePath, loaded.history)
	if err != nil {
		return fail(startupStep("open state store", nil))
	}
	resources.Add(store)
	stateAdapter, err := state.NewControllerAdapter(store, loaded.history)
	if err != nil {
		return fail(startupStep("open state adapter", nil))
	}

	fenceStore, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             overlay.Paths.FenceRoot,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: timings.fenceLock,
	})
	if err != nil {
		return fail(startupStep("open fence store", nil))
	}
	resources.Add(fenceStore)
	callCtx, callCancel := context.WithTimeout(ctx, timings.operation)
	fenceSnapshot, err := fenceStore.Inspect(callCtx)
	callCancel()
	if err != nil ||
		fenceSnapshot.Header.Generation != manifest.FleetGeneration ||
		fenceSnapshot.Header.ActiveFleet != fleetfence.FleetPortable {
		return fail(startupStep("fence is not held by the portable fleet at the manifest generation", nil))
	}
	fleetGuards, err := fleetfence.NewControllerAdapter(fleetfence.ControllerAdapterConfig{
		Store:           fenceStore,
		Generation:      manifest.FleetGeneration,
		OwnerID:         overlay.Target.OwnerID,
		PID:             os.Getpid(),
		RenewalInterval: timings.fenceRenewal,
		RenewalTimeout:  timings.fenceTimeout,
	})
	if err != nil {
		return fail(startupStep("build fence adapter", nil))
	}
	callCtx, callCancel = context.WithTimeout(ctx, timings.operation)
	guard, err := fleetGuards.AcquirePortable(callCtx)
	callCancel()
	if err != nil || guard == nil {
		return fail(startupStep("acquire portable fence guard", nil))
	}
	resources.Add(guard)
	failureSource, ok := guard.(interface{ Failure() <-chan error })
	if !ok || failureSource.Failure() == nil {
		return fail(startupStep("watch portable fence guard", nil))
	}
	// Every later guard in this process is a view of this one.
	fence := newSharedFenceGuard(failureSource.Failure())
	resources.Add(fence)

	docker, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    overlay.Commands.DockerBinary,
			BrokerRoot:    overlay.Paths.BrokerRoot,
			SeccompRoot:   overlay.Paths.SeccompRoot,
			BrokerNetwork: overlay.Docker.BrokerNetworkID,
		},
		hostruntime.NewExecCommandRunner(),
	)
	if err != nil {
		return fail(startupStep("build Docker client", nil))
	}
	monotonic, err := newPermitClock()
	if err != nil {
		return fail(startupStep("open permit clock", nil))
	}
	peers, err := networkjail.NewProcPermitPeerValidator(brokerUID)
	if err != nil {
		return fail(startupStep("build permit peer validator", nil))
	}
	references, err := networkjail.NewStateLedgerReferenceGuard(store)
	if err != nil {
		return fail(startupStep("build ledger reference guard", nil))
	}
	permitAuthority, err := networkjail.NewSQLitePermitAuthority(
		graph,
		monotonic,
		store,
		peers,
		references,
		networkjail.RejectEmptyConntrackRebase{},
		overlay.Jail.DialReservationBlockSize,
	)
	if err != nil {
		return fail(startupStep("open permit authority", nil))
	}
	callCtx, callCancel = context.WithTimeout(ctx, timings.reconciliation)
	err = clearUnreferencedSlots(
		callCtx,
		store,
		permitAuthority,
		overlay.Paths.BrokerRoot,
		overlay.Resources.MaxCapacity,
		hostruntime.RemoveUnreferencedSlotDirectories,
	)
	callCancel()
	if err != nil {
		return fail(startupStep("clear unreferenced slots", err))
	}

	authorityManager, err := networkjail.NewUnixAuthorityManager(
		permitAuthority,
		uint32(overlay.Jail.DialAuthorityMaxClients),
		dialTimeout,
	)
	if err != nil {
		return fail(startupStep("build dial authority manager", nil))
	}
	journal, err := networkjail.NewStateLifecycleJournal(store)
	if err != nil {
		return fail(startupStep("open lifecycle journal", nil))
	}
	orchestrator, err := networkjail.NewOrchestrator(docker, journal, authorityManager)
	if err != nil {
		return fail(startupStep("build jail orchestrator", nil))
	}
	jails, err := lifecycle.WithSlotDirectories(orchestrator, overlay.Paths.BrokerRoot)
	if err != nil {
		return fail(startupStep("wrap slot directories", nil))
	}
	setupConfig, err := lifecycle.SetupConfigFromOverlay(overlay, manifest, graph, policy)
	if err != nil {
		return fail(startupStep("map overlay to setup config", err))
	}
	builder, err := lifecycle.NewSetupBuilder(setupConfig)
	if err != nil {
		return fail(startupStep("build setup builder", err))
	}

	callCtx, callCancel = context.WithTimeout(ctx, timings.operation)
	policyEpoch, err := durablePolicyEpoch(callCtx, stateAdapter, overlay)
	callCancel()
	if err != nil {
		return fail(startupStep("read durable policy epoch", nil))
	}
	admissionConfig, err := productionAdmissionConfig(overlay, policyEpoch, time.Now)
	if err != nil {
		return fail(startupStep("build admission config", nil))
	}
	broker, err := admission.NewBroker(admissionConfig)
	if err != nil {
		return fail(startupStep("build admission broker", err))
	}
	history, ok := broker.(admission.LiveHistory)
	if !ok {
		return fail(startupStep("admission broker lacks live history", nil))
	}
	brokerAdapter, err := admission.NewControllerAdapter(
		broker,
		history,
		admissionConfig.Repositories,
		admissionConfig.TransientMode,
	)
	if err != nil {
		return fail(startupStep("build admission adapter", err))
	}

	authorityClock, err := failoverclient.NewProductionAuthorityClock()
	if err != nil {
		return fail(startupStep("open Worker authority clock", nil))
	}
	worker, err := newProductionWorkerClients(productionWorkerConfig{
		Overlay:         overlay,
		HMACKeyHex:      hmacKey,
		FleetGuards:     fence,
		BuildID:         manifest.BuildID,
		Fence:           manifest.FleetGeneration,
		AttemptInterval: timings.reconciliationCadence + timings.reconciliation,
		Clock:           authorityClock,
	})
	if err != nil {
		return fail(startupStep("build Worker clients", err))
	}
	resources.Add(worker)

	// The service owns the GitHub sessions once it exists: Service.Run closes
	// them on every return path. Until then a failure closes them here.
	targets, err := openGitHubPollTargets(ctx, overlay, productionGitHubAccess())
	if err != nil {
		return fail(startupStep("open GitHub sessions", err))
	}
	for index := range targets {
		targets[index].Session = &closeOnceSession{Session: targets[index].Session}
	}
	failWithTargets := func(primary error) (controllerProcess, error) {
		if closeErr := closePollTargets(ctx, targets); closeErr != nil {
			primary = errors.Join(primary, errStartupCleanup, closeErr)
		}
		return fail(primary)
	}
	jit := &jitAuthorizerSlot{}
	runtime, err := lifecycle.NewService(
		store,
		newPollTargetSessions(targets),
		jit,
		builder,
		jails,
		docker,
		time.Now,
	)
	if err != nil {
		return failWithTargets(startupStep("build lifecycle runtime", err))
	}
	reconciler, err := controller.NewReconciler(
		stateAdapter,
		runtime,
		time.Now,
		acquisitionCycleID,
	)
	if err != nil {
		return failWithTargets(startupStep("build reconciler", err))
	}

	process := &acquisitionControllerProcess{}
	terminator := &processTerminator{
		stderr: logs,
		cancel: func() { process.stop(errAcquisitionFatal) },
	}
	external := newUnavailableExternalGraph()
	acquiring, err := controller.NewService(controller.ServiceConfig{
		State:                 stateAdapter,
		Broker:                brokerAdapter,
		Transitions:           stateAdapter,
		Revoker:               runtime,
		RunningCanceler:       runtime,
		Terminator:            terminator,
		Events:                runtime,
		Replay:                external,
		Hosted:                external,
		FleetGuards:           fence,
		Permits:               worker.Permits,
		Conformance:           conformance.NewUnavailableAcquisitionGate(),
		HostCapacity:          fixedHostCapacity{capacity: int(overlay.Resources.MaxCapacity), evidence: loaded.overlayDigest, now: time.Now},
		HistoryPressure:       pressure,
		HealthPublisher:       worker.Health,
		EventSink:             &logEventSink{out: logs},
		Reconciler:            reconciler,
		FleetAlias:            overlay.Worker.FleetID,
		HostProfileID:         overlay.Target.ProfileID,
		BuildID:               manifest.BuildID,
		FleetGeneration:       manifest.FleetGeneration,
		EnabledPolicyTemplate: enabledTemplate,
		PollTargets:           targets,
		Now:                   time.Now,
		AckTimeout:            service.ack,
		OperationTimeout:      timings.operation,
		PollCycleTimeout:      service.pollCycle,
		ReconciliationTimeout: timings.reconciliation,
		PollCadence:           service.pollCadence,
		ReconciliationCadence: timings.reconciliationCadence,
		DrainPollCadence:      service.drainPollCadence,
		ShutdownTimeout:       timings.shutdown,
		SessionCloseTimeout:   service.sessionClose,
		TransitionJoinTimeout: service.transitionJoin,
		DurableFinishTimeout:  service.durableFinish,
		ReplayEvidenceMaxAge:  service.replayEvidenceMaxAge,
		HostCapacityMaxAge:    service.hostCapacityMaxAge,
	})
	if err != nil {
		return failWithTargets(startupStep("build controller service", err))
	}
	jit.Set(acquiring)
	if err := process.init(acquisitionProcessConfig{
		Service:   acquiring,
		FenceLost: fence.Lost(),
		CloseSessions: func() error {
			return closePollTargets(context.Background(), targets)
		},
		Resources:        resources,
		Ownership:        ownership,
		AdminSocketPath:  overlay.Paths.AdminSocketPath,
		HealthSocketPath: overlay.Paths.HealthSocketPath,
		ExpectedUID:      uint32(overlay.Target.ExpectedEUID),
		AdmissionLimit:   int(overlay.Resources.MaxCapacity),
		OperationTimeout: timings.operation,
		OwnershipCheck:   timings.reconciliationCadence,
		DrainTimeout:     timings.shutdown,
		ShutdownTimeout:  timings.shutdown,
	}); err != nil {
		return failWithTargets(startupStep("build process", nil))
	}
	if ownership.Validate() != nil {
		return failWithTargets(startupStep("ownership lease lost", nil))
	}
	return process, nil
}

// productionServiceTimings are the service timings the disabled observer
// does not use. The overlay schema already checked each is canonical.
// closeOnceSession sends only the first Close to GitHub. Service.Run closes
// its sessions on the way out, but returns before doing so when its context
// is already canceled, so the process closes them again on every path. GitHub
// allows one message session per scale set, so a leaked one blocks the next
// start until it expires.
type closeOnceSession struct {
	githubscale.Session
	mu     sync.Mutex
	closed bool
}

// Close counts the session as closed only once GitHub accepts the close, so
// a failed close (a timeout, say) is retried by the next caller.
func (session *closeOnceSession) Close(ctx context.Context) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	if err := session.Session.Close(ctx); err != nil {
		return err
	}
	session.closed = true
	return nil
}

type productionServiceTimings struct {
	ack                  time.Duration
	pollCycle            time.Duration
	pollCadence          time.Duration
	drainPollCadence     time.Duration
	sessionClose         time.Duration
	transitionJoin       time.Duration
	durableFinish        time.Duration
	replayEvidenceMaxAge time.Duration
	hostCapacityMaxAge   time.Duration
}

func parseProductionServiceTimings(
	timings hostruntime.ControllerTimingOverlay,
) (productionServiceTimings, error) {
	values := []string{
		timings.AckTimeout, timings.PollCycleTimeout, timings.PollCadence,
		timings.DrainPollCadence, timings.SessionCloseTimeout,
		timings.TransitionJoinTimeout, timings.DurableFinishTimeout,
		timings.ReplayEvidenceMaxAge, timings.HostCapacityMaxAge,
	}
	parsed := make([]time.Duration, len(values))
	for index, value := range values {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return productionServiceTimings{}, errCommandUnavailable
		}
		parsed[index] = duration
	}
	return productionServiceTimings{
		ack:                  parsed[0],
		pollCycle:            parsed[1],
		pollCadence:          parsed[2],
		drainPollCadence:     parsed[3],
		sessionClose:         parsed[4],
		transitionJoin:       parsed[5],
		durableFinish:        parsed[6],
		replayEvidenceMaxAge: parsed[7],
		hostCapacityMaxAge:   parsed[8],
	}, nil
}

// readProductionPolicy reads the pinned decision graph and checks it is the
// graph the overlay names. The setup builder and the permit authority both
// take the graph; the builder also takes its compiled filter programs.
func readProductionPolicy(
	overlay hostruntime.PrivateOverlay,
) (networkjail.DecisionGraph, hostruntime.PolicyArtifact, error) {
	document, err := readPinnedRootFile(overlay.Paths.PolicyPath, 0o600, maxProductionPolicyBytes)
	if err != nil {
		return networkjail.DecisionGraph{}, hostruntime.PolicyArtifact{}, errCommandUnavailable
	}
	graph, err := networkjail.DecodeDecisionGraph(bytes.NewReader(document))
	if err != nil || graph.Digest().String() != overlay.Policy.CompiledGraphDigest {
		return networkjail.DecisionGraph{}, hostruntime.PolicyArtifact{}, errCommandUnavailable
	}
	policy, err := networkjail.CompilePolicyArtifact(graph)
	if err != nil {
		return networkjail.DecisionGraph{}, hostruntime.PolicyArtifact{}, errCommandUnavailable
	}
	return graph, policy, nil
}

// jailUserID returns the UID of a "uid:gid" jail user.
func jailUserID(user string) (uint32, error) {
	uid, _, ok := strings.Cut(user, ":")
	value, err := strconv.ParseUint(uid, 10, 32)
	if !ok || err != nil || value == 0 {
		return 0, errCommandUnavailable
	}
	return uint32(value), nil
}

type recoverableLister interface {
	ListRecoverable(context.Context) ([]state.RecoverableAssignment, error)
}

type unreferencedLedgerReleaser interface {
	DeactivateUnreferenced(context.Context, networkjail.CapacitySlotID) error
}

// clearUnreferencedSlots releases what a crashed controller left behind on
// slots no recoverable assignment references: a dial ledger still active,
// and an empty slot directory. It runs before the service starts, so no
// admission can race it. A referenced slot is left for the service's own
// recovery.
func clearUnreferencedSlots(
	ctx context.Context,
	store recoverableLister,
	ledgers unreferencedLedgerReleaser,
	brokerRoot string,
	maxCapacity uint64,
	removeDirectories func(string, map[string]bool) error,
) error {
	if maxCapacity == 0 || maxCapacity > math.MaxUint32 {
		return errCommandUnavailable
	}
	recoverable, err := store.ListRecoverable(ctx)
	if err != nil {
		return err
	}
	for slot := uint64(1); slot <= maxCapacity; slot++ {
		err := ledgers.DeactivateUnreferenced(ctx, networkjail.CapacitySlotID(slot))
		if err != nil && !errors.Is(err, networkjail.ErrLedgerReferenced) {
			return err
		}
	}
	referenced := make(map[string]bool, len(recoverable))
	for _, assignment := range recoverable {
		referenced[controller.OpaqueSlotName(assignment.Key)] = true
	}
	return removeDirectories(brokerRoot, referenced)
}

type policySnapshotter interface {
	Snapshot(context.Context) (controller.AcquisitionPolicy, error)
	Transition(context.Context, uint64, controller.AcquisitionPolicy) (controller.AcquisitionPolicy, error)
}

// durablePolicyEpoch returns the durable acquisition epoch the admission
// broker starts at. A new database is at epoch 0, which the broker cannot
// start at, so it first records the disabled policy, the same policy the
// service's startup records next.
func durablePolicyEpoch(
	ctx context.Context,
	policies policySnapshotter,
	overlay hostruntime.PrivateOverlay,
) (uint64, error) {
	current, err := policies.Snapshot(ctx)
	if err != nil || current.Epoch == math.MaxUint64 {
		return 0, errCommandUnavailable
	}
	if current.Epoch > 0 {
		return current.Epoch, nil
	}
	disabled, err := productionDisabledPolicy(overlay)
	if err != nil {
		return 0, err
	}
	recorded, err := policies.Transition(ctx, 0, disabled)
	if err != nil || recorded.Epoch == 0 {
		return 0, errCommandUnavailable
	}
	return recorded.Epoch, nil
}

func acquisitionCycleID() string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ""
	}
	return "acquisition-" + hex.EncodeToString(nonce[:])
}
