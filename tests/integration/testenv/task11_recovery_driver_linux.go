//go:build integration && linux

package testenv

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/state"
	"golang.org/x/sys/unix"
)

const (
	task11RecoveryCleanupDomain = "portable-ghar.task11.recovery-cleanup.v1\x00"
	task11RecoveryProofDomain   = "portable-ghar.task11.recovery-proof.v1\x00"
)

type linuxTask11RecoveryProcess struct {
	role     string
	command  *exec.Cmd
	identity ProcessIdentity
	wait     <-chan error

	mu       sync.Mutex
	finished bool
	waitErr  error
}

type linuxTask11RecoveryDriver struct {
	input           ConformanceInput
	overlay         hostruntime.PrivateOverlay
	plan            compositionPlan
	cycle           task11SyntheticCycleIdentity
	handle          cleanupHandle
	lockPoll        time.Duration
	restartDeadline time.Duration
	processGrace    time.Duration
	cleanupTimeout  time.Duration

	mu          sync.Mutex
	registered  bool
	attempted   bool
	removed     bool
	root        *linuxTask11SyntheticCycleRoot
	stateStore  *state.SQLiteStore
	transitions *state.ControllerAdapter
	fence       *fleetfence.Store
	processes   []*linuxTask11RecoveryProcess
}

func newLinuxTask11RecoveryDriver(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	plan compositionPlan,
) (*linuxTask11RecoveryDriver, error) {
	cycle, err := deriveTask11RecoveryCycleIdentity(
		input.Fixture,
		input.Authorization.RunID,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	handle, err := compositionCleanupHandle(
		CleanupHelper,
		task11RecoveryCleanupDomain,
		cycle.RunDigest,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	lockPoll, lockErr := time.ParseDuration(
		overlay.Fence.LockPollInterval,
	)
	restartDeadline, restartErr := time.ParseDuration(
		overlay.Watchdog.RestartDeadline,
	)
	processGrace, graceErr := time.ParseDuration(
		overlay.Watchdog.ProcessGrace,
	)
	cleanupTimeout := durationMilliseconds(
		input.Limits.CleanupTimeoutMilliseconds,
	)
	historyErr := state.ValidateHistoryLimits(plan.HistoryLimits)
	if lockErr != nil ||
		restartErr != nil ||
		graceErr != nil ||
		historyErr != nil ||
		lockPoll <= 0 ||
		restartDeadline <= 0 ||
		processGrace <= 0 ||
		cleanupTimeout <= 0 ||
		plan.Identity.SlotIdentity == "" {
		return nil, ErrFixtureStart
	}
	return &linuxTask11RecoveryDriver{
		input:           input,
		overlay:         overlay,
		plan:            plan,
		cycle:           cycle,
		handle:          handle,
		lockPoll:        lockPoll,
		restartDeadline: restartDeadline,
		processGrace:    processGrace,
		cleanupTimeout:  cleanupTimeout,
	}, nil
}

func (d *linuxTask11RecoveryDriver) register(
	record func(cleanupHandle) error,
) error {
	if d == nil || record == nil {
		return ErrFixtureStart
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.registered || d.attempted || d.removed {
		return ErrFixtureStart
	}
	if err := record(d.handle); err != nil {
		return ErrFixtureStart
	}
	d.registered = true
	return nil
}

func (d *linuxTask11RecoveryDriver) RunRecovery(
	ctx context.Context,
) (SyntheticRecoveryProof, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	d.mu.Lock()
	if !d.registered || d.attempted || d.removed {
		d.mu.Unlock()
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	d.attempted = true
	d.mu.Unlock()

	proof, runErr := d.runRecovery(ctx)
	cleanupCtx, cancel := context.WithTimeout(
		context.Background(),
		d.cleanupTimeout,
	)
	cleanupErr := d.cleanup(cleanupCtx)
	cancel()
	if runErr != nil || cleanupErr != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	return proof, nil
}

func (d *linuxTask11RecoveryDriver) runRecovery(
	ctx context.Context,
) (SyntheticRecoveryProof, error) {
	root, binding, err := createLinuxTask11SyntheticCycleRoot(
		d.input.Fixture,
		d.cycle,
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	d.mu.Lock()
	d.root = root
	d.mu.Unlock()
	if binding.Root != d.cycle.Root {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	databasePath, fencePath, err := root.prepareRecoveryState()
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := d.openStores(databasePath, fencePath); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	current, err := d.transitions.Snapshot(ctx)
	if err != nil ||
		current.Epoch != 0 ||
		current.Mode != controller.AcquisitionDisabled {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	stale := current
	stale.Mode = controller.AcquisitionCanaryOnly
	stale.MaxCapacity = 1
	stale.EligibleScaleSets = []string{d.plan.Identity.SlotIdentity}
	stale.RepositoryPolicyRevision = 1
	stale, err = d.transitions.Transition(ctx, current.Epoch, stale)
	if err != nil ||
		stale.Epoch != current.Epoch+1 ||
		stale.Mode != controller.AcquisitionCanaryOnly {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	stale, err = controller.CanonicalizeAcquisitionPolicy(stale)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	portableHeader, err := d.fence.Handoff(
		ctx,
		fleetfence.HandoffRequest{
			From:               fleetfence.FleetNone,
			To:                 fleetfence.FleetPortable,
			ExpectedGeneration: 0,
			OperationID: fleetfence.HandoffOperationID(
				0,
				fleetfence.FleetNone,
				fleetfence.FleetPortable,
			),
		},
	)
	if err != nil ||
		portableHeader.Generation == 0 ||
		portableHeader.ActiveFleet != fleetfence.FleetPortable {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	controllerProcess, err := d.startProcess(
		ctx,
		task11RecoveryHelperController,
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	controllerGuard, err := d.fence.Acquire(
		ctx,
		fleetfence.AcquireRequest{
			Fleet:      fleetfence.FleetPortable,
			Generation: portableHeader.Generation,
			OwnerID:    d.plan.Identity.SlotIdentity,
			PID:        int(controllerProcess.identity.PID),
		},
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := d.killAndProve(ctx, controllerProcess); err != nil {
		_ = controllerGuard.Close()
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := controllerGuard.Close(); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	watchdogProcess, err := d.startProcess(
		ctx,
		task11RecoveryHelperController,
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	watchdogGuard, err := d.fence.Acquire(
		ctx,
		fleetfence.AcquireRequest{
			Fleet:      fleetfence.FleetPortable,
			Generation: portableHeader.Generation,
			OwnerID:    d.plan.Identity.SlotIdentity,
			PID:        int(watchdogProcess.identity.PID),
		},
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	controllerDeath := ProcessDeathProof{
		Expected:      []ProcessIdentity{controllerProcess.identity},
		ObservedAfter: []ProcessIdentity{watchdogProcess.identity},
	}
	if !validProcessDeath(controllerDeath) {
		_ = watchdogGuard.Close()
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := watchdogGuard.Close(); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := d.killAndProve(ctx, watchdogProcess); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	legacyHeader, err := d.fence.Handoff(
		ctx,
		fleetfence.HandoffRequest{
			From:               fleetfence.FleetPortable,
			To:                 fleetfence.FleetLegacy,
			ExpectedGeneration: portableHeader.Generation,
			OperationID: fleetfence.HandoffOperationID(
				portableHeader.Generation,
				fleetfence.FleetPortable,
				fleetfence.FleetLegacy,
			),
		},
	)
	if err != nil ||
		legacyHeader.Generation != portableHeader.Generation+1 ||
		legacyHeader.ActiveFleet != fleetfence.FleetLegacy {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	pollProcess, err := d.startProcess(
		ctx,
		task11RecoveryHelperPoll,
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	normalization, err := fleetfence.NormalizeLegacyObserver(
		ctx,
		d.fence,
		d.transitions,
	)
	if err != nil ||
		normalization.FleetGeneration != legacyHeader.Generation ||
		normalization.PolicyEpoch != stale.Epoch+1 {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	disabled, err := d.transitions.Snapshot(ctx)
	if err != nil ||
		disabled.Epoch != normalization.PolicyEpoch ||
		disabled.Mode != controller.AcquisitionDisabled ||
		disabled.MaxCapacity != 0 ||
		len(disabled.EligibleScaleSets) != 0 {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := d.proveNoncancellableThenKill(
		ctx,
		pollProcess,
	); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	observerProcess, err := d.startProcess(
		ctx,
		task11RecoveryHelperObserver,
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	snapshot, err := d.fence.Inspect(ctx)
	if err != nil ||
		snapshot.Header.Generation != legacyHeader.Generation ||
		snapshot.Header.ActiveFleet != fleetfence.FleetLegacy ||
		len(snapshot.Holders) != 0 {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := d.killAndProve(ctx, observerProcess); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := d.closeStores(); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	if err := d.openStores(databasePath, fencePath); err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	rebootFence, err := d.fence.Inspect(ctx)
	if err != nil ||
		rebootFence.Header.Generation != legacyHeader.Generation ||
		rebootFence.Header.ActiveFleet != fleetfence.FleetLegacy ||
		len(rebootFence.Holders) != 0 {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	rebootPolicy, err := d.transitions.Snapshot(ctx)
	if err != nil ||
		rebootPolicy.Epoch != disabled.Epoch ||
		rebootPolicy.Mode != controller.AcquisitionDisabled ||
		rebootPolicy.MaxCapacity != 0 ||
		len(rebootPolicy.EligibleScaleSets) != 0 {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	rebootObserver, err := d.startProcess(
		ctx,
		task11RecoveryHelperObserver,
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	noncancellableDeath := ProcessDeathProof{
		Expected:      []ProcessIdentity{pollProcess.identity},
		ObservedAfter: []ProcessIdentity{rebootObserver.identity},
	}
	if !validProcessDeath(noncancellableDeath) {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}

	proof := SyntheticRecoveryProof{
		InitialFenceGeneration:      stale.Epoch,
		DisabledGeneration:          disabled.Epoch,
		PersistedMode:               string(disabled.Mode),
		PersistedCapacity:           uint64(disabled.MaxCapacity),
		ControllerKilled:            true,
		ControllerProcessDeath:      controllerDeath,
		WatchdogRestarted:           true,
		RestartAfterControllerDeath: true,
		LegacyOwnsFence:             true,
		RebootRecoveredDark:         true,
		NoncancellableProcessDeath:  noncancellableDeath,
		ObserverRestarted:           true,
		ObserverRestartAfterDeath:   true,
		OrderedStates: append(
			[]string(nil),
			requiredRecoveryStates[:]...,
		),
		AssertionCount: 19,
	}
	digestInput := cloneSyntheticRecoveryProof(proof)
	digestInput.ObservationDigest = ""
	digest, err := recordingCanonicalDigest(
		task11RecoveryProofDomain,
		digestInput,
	)
	if err != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	proof.ObservationDigest = digest
	if ValidateSyntheticRecovery(proof) != nil {
		return SyntheticRecoveryProof{}, ErrFixtureStart
	}
	return proof, nil
}

func (d *linuxTask11RecoveryDriver) openStores(
	databasePath string,
	fencePath string,
) error {
	if d == nil ||
		!validAbsolutePath(databasePath) ||
		!validAbsolutePath(fencePath) ||
		filepath.Dir(databasePath) != d.cycle.Root ||
		filepath.Dir(fencePath) != d.cycle.Root {
		return ErrFixtureStart
	}
	store, err := state.OpenWithHistoryLimits(
		databasePath,
		d.plan.HistoryLimits,
	)
	if err != nil || store == nil || store.DB() == nil {
		if store != nil {
			_ = store.Close()
		}
		return ErrFixtureStart
	}
	transitions, err := state.NewControllerAdapter(
		store,
		d.plan.HistoryLimits,
	)
	if err != nil {
		_ = store.Close()
		return ErrFixtureStart
	}
	fence, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             fencePath,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: d.lockPoll,
	})
	if err != nil {
		_ = store.Close()
		return ErrFixtureStart
	}
	d.mu.Lock()
	d.stateStore = store
	d.transitions = transitions
	d.fence = fence
	d.mu.Unlock()
	return nil
}

func (d *linuxTask11RecoveryDriver) closeStores() error {
	if d == nil {
		return ErrFixtureCleanup
	}
	d.mu.Lock()
	fence := d.fence
	store := d.stateStore
	d.fence = nil
	d.stateStore = nil
	d.transitions = nil
	d.mu.Unlock()
	var result error
	if fence != nil {
		result = errors.Join(result, fence.Close())
	}
	if store != nil {
		result = errors.Join(result, store.Close())
	}
	if result != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (d *linuxTask11RecoveryDriver) startProcess(
	ctx context.Context,
	role string,
) (*linuxTask11RecoveryProcess, error) {
	if d == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		(role != task11RecoveryHelperController &&
			role != task11RecoveryHelperObserver &&
			role != task11RecoveryHelperPoll) {
		return nil, ErrFixtureStart
	}
	executable, err := os.Executable()
	if err != nil || !validAbsolutePath(executable) {
		return nil, ErrFixtureStart
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, ErrFixtureStart
	}
	defer reader.Close()
	command := exec.Command(executable, "-test.run=^$")
	command.Env = []string{task11RecoveryHelperEnv + "=" + role}
	command.ExtraFiles = []*os.File{writer}
	command.SysProcAttr = &unix.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: unix.SIGKILL,
	}
	if err := command.Start(); err != nil {
		_ = writer.Close()
		return nil, ErrFixtureStart
	}
	_ = writer.Close()
	wait := make(chan error, 1)
	go func() {
		wait <- command.Wait()
		close(wait)
	}()
	process := &linuxTask11RecoveryProcess{
		role:    role,
		command: command,
		wait:    wait,
	}
	failed := true
	defer func() {
		if failed {
			cleanupCtx, cancel := context.WithTimeout(
				context.Background(),
				d.processGrace,
			)
			_ = d.killProcessGroup(cleanupCtx, process)
			cancel()
		}
	}()
	deadline := time.Now().Add(d.restartDeadline)
	if contextDeadline, ok := ctx.Deadline(); ok &&
		contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := reader.SetReadDeadline(deadline); err != nil {
		return nil, ErrFixtureStart
	}
	ready, err := io.ReadAll(io.LimitReader(reader, 2))
	if err != nil || !bytes.Equal(ready, []byte{1}) {
		return nil, ErrFixtureStart
	}
	identity, err := observeLinuxTask11Process(command.Process.Pid)
	if err != nil ||
		identity.PID != int64(command.Process.Pid) ||
		identity.ProcessGroup != identity.PID {
		return nil, ErrFixtureStart
	}
	rechecked, err := observeLinuxTask11Process(command.Process.Pid)
	if err != nil || rechecked != identity {
		return nil, ErrFixtureStart
	}
	process.identity = identity
	d.mu.Lock()
	d.processes = append(d.processes, process)
	d.mu.Unlock()
	failed = false
	return process, nil
}

func (d *linuxTask11RecoveryDriver) proveNoncancellableThenKill(
	ctx context.Context,
	process *linuxTask11RecoveryProcess,
) error {
	if d == nil ||
		process == nil ||
		process.role != task11RecoveryHelperPoll ||
		!validProcessIdentity(process.identity) {
		return ErrFixtureStart
	}
	current, err := observeLinuxTask11Process(int(process.identity.PID))
	if err != nil || current != process.identity {
		return ErrFixtureStart
	}
	if err := unix.Kill(
		-int(process.identity.ProcessGroup),
		unix.SIGTERM,
	); err != nil {
		return ErrFixtureStart
	}
	timer := time.NewTimer(d.processGrace)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ErrFixtureStart
	case waitErr, ok := <-process.wait:
		if !ok {
			waitErr = nil
		}
		process.markFinished(waitErr)
		return ErrFixtureStart
	case <-timer.C:
	}
	current, err = observeLinuxTask11Process(int(process.identity.PID))
	if err != nil || current != process.identity {
		return ErrFixtureStart
	}
	return d.killAndProve(ctx, process)
}

func (d *linuxTask11RecoveryDriver) killAndProve(
	ctx context.Context,
	process *linuxTask11RecoveryProcess,
) error {
	if d == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		process == nil ||
		!validProcessIdentity(process.identity) {
		return ErrFixtureStart
	}
	current, err := observeLinuxTask11Process(int(process.identity.PID))
	if err != nil || current != process.identity {
		return ErrFixtureStart
	}
	if err := unix.Kill(
		-int(process.identity.ProcessGroup),
		unix.SIGKILL,
	); err != nil {
		return ErrFixtureStart
	}
	if err := process.await(ctx); err != nil {
		return ErrFixtureStart
	}
	after, err := observeLinuxTask11Process(int(process.identity.PID))
	if err == nil && after == process.identity {
		return ErrFixtureStart
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrFixtureStart
	}
	return nil
}

func (d *linuxTask11RecoveryDriver) killProcessGroup(
	ctx context.Context,
	process *linuxTask11RecoveryProcess,
) error {
	if ctx == nil || process == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ErrFixtureCleanup
	}
	if process.finishedState() {
		return nil
	}
	if validProcessIdentity(process.identity) {
		current, err := observeLinuxTask11Process(
			int(process.identity.PID),
		)
		if err == nil && current == process.identity {
			_ = unix.Kill(
				-int(process.identity.ProcessGroup),
				unix.SIGKILL,
			)
		} else if err == nil && current != process.identity {
			return ErrFixtureCleanup
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrFixtureCleanup
		}
	} else if process.command != nil && process.command.Process != nil {
		_ = process.command.Process.Kill()
	}
	if err := process.await(ctx); err != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (p *linuxTask11RecoveryProcess) await(ctx context.Context) error {
	if p == nil || ctx == nil {
		return ErrFixtureCleanup
	}
	p.mu.Lock()
	if p.finished {
		err := p.waitErr
		p.mu.Unlock()
		if task11ExpectedProcessExit(err) {
			return nil
		}
		return ErrFixtureCleanup
	}
	wait := p.wait
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return ErrFixtureCleanup
	case err, ok := <-wait:
		if !ok {
			err = nil
		}
		p.markFinished(err)
		if task11ExpectedProcessExit(err) {
			return nil
		}
		return ErrFixtureCleanup
	}
}

func (p *linuxTask11RecoveryProcess) markFinished(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.finished {
		p.finished = true
		p.waitErr = err
	}
}

func (p *linuxTask11RecoveryProcess) finishedState() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.finished
}

func task11ExpectedProcessExit(err error) bool {
	if err == nil {
		return true
	}
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ProcessState != nil
}

func observeLinuxTask11Process(pid int) (ProcessIdentity, error) {
	if pid <= 0 {
		return ProcessIdentity{}, ErrFixtureStart
	}
	procFD, err := unix.Open(
		"/proc",
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return ProcessIdentity{}, ErrFixtureStart
	}
	defer unix.Close(procFD)
	relative := filepath.Join(strconv.Itoa(pid), "stat")
	fd, err := unix.Openat2(procFD, relative, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS,
		),
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return ProcessIdentity{}, os.ErrNotExist
		}
		return ProcessIdentity{}, ErrFixtureStart
	}
	file := os.NewFile(uintptr(fd), "task11-recovery-proc-stat")
	if file == nil {
		_ = unix.Close(fd)
		return ProcessIdentity{}, ErrFixtureStart
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(document) == 0 || len(document) > 4096 {
		return ProcessIdentity{}, ErrFixtureStart
	}
	closeParen := bytes.LastIndexByte(document, ')')
	if closeParen <= 0 || closeParen+2 >= len(document) {
		return ProcessIdentity{}, ErrFixtureStart
	}
	pidSeparator := bytes.IndexByte(document, ' ')
	if pidSeparator <= 0 || pidSeparator >= closeParen {
		return ProcessIdentity{}, ErrFixtureStart
	}
	parsedPID, err := strconv.ParseInt(
		strings.TrimSpace(string(document[:pidSeparator])),
		10,
		64,
	)
	fields := strings.Fields(string(document[closeParen+2:]))
	if err != nil || parsedPID != int64(pid) || len(fields) <= 19 {
		return ProcessIdentity{}, ErrFixtureStart
	}
	processGroup, groupErr := strconv.ParseInt(fields[2], 10, 64)
	startTime, startErr := strconv.ParseUint(fields[19], 10, 64)
	observedGroup, groupLookupErr := unix.Getpgid(pid)
	if groupErr != nil ||
		startErr != nil ||
		groupLookupErr != nil ||
		processGroup <= 0 ||
		startTime == 0 ||
		int64(observedGroup) != processGroup {
		return ProcessIdentity{}, ErrFixtureStart
	}
	return ProcessIdentity{
		PID:          int64(pid),
		StartTime:    startTime,
		ProcessGroup: processGroup,
	}, nil
}

func (d *linuxTask11RecoveryDriver) cleanup(ctx context.Context) error {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return ErrFixtureCleanup
	}
	d.mu.Lock()
	if d.removed {
		d.mu.Unlock()
		return nil
	}
	processes := append(
		[]*linuxTask11RecoveryProcess(nil),
		d.processes...,
	)
	root := d.root
	d.mu.Unlock()
	var result error
	for index := len(processes) - 1; index >= 0; index-- {
		if ctx.Err() != nil {
			return ErrFixtureCleanup
		}
		result = errors.Join(
			result,
			d.killProcessGroup(ctx, processes[index]),
		)
	}
	result = errors.Join(result, d.closeStores())
	if root != nil {
		result = errors.Join(result, root.removeRecoveryState())
	}
	if result != nil {
		return ErrFixtureCleanup
	}
	d.mu.Lock()
	d.removed = true
	d.mu.Unlock()
	return nil
}

func (d *linuxTask11RecoveryDriver) owns(handle cleanupHandle) bool {
	return d != nil && handle == d.handle
}

func (d *linuxTask11RecoveryDriver) remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if !d.owns(handle) {
		return ErrFixtureCleanup
	}
	return d.cleanup(ctx)
}

func (d *linuxTask11RecoveryDriver) recordedRemoved(
	handle cleanupHandle,
) bool {
	if !d.owns(handle) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.removed
}

var _ task11RecoveryDriver = (*linuxTask11RecoveryDriver)(nil)
