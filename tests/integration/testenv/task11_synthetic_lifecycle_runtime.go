package testenv

import (
	"context"
	"crypto/sha256"
	"sync"
)

const task11ReclamationStagingDomain = "portable-ghar.task11.reclamation-staging.v1\x00"

type task11SyntheticCycleKind string

const (
	task11CycleOneJob                     task11SyntheticCycleKind = "one-job"
	task11CycleCleanupSuccess             task11SyntheticCycleKind = "cleanup-success"
	task11CycleCleanupCancellation        task11SyntheticCycleKind = "cleanup-cancellation"
	task11CycleCleanupPreListenerFailure  task11SyntheticCycleKind = "cleanup-pre-listener-failure"
	task11CycleCleanupListenerCrash       task11SyntheticCycleKind = "cleanup-listener-crash"
	task11CycleCleanupControllerRestart   task11SyntheticCycleKind = "cleanup-controller-restart"
	task11CycleCleanupUpgradeInterruption task11SyntheticCycleKind = "cleanup-upgrade-interruption"
	task11CycleReclamation                task11SyntheticCycleKind = "reclamation"
)

var task11CleanupCycles = [...]task11SyntheticCycleKind{
	task11CycleCleanupSuccess,
	task11CycleCleanupCancellation,
	task11CycleCleanupPreListenerFailure,
	task11CycleCleanupListenerCrash,
	task11CycleCleanupControllerRestart,
	task11CycleCleanupUpgradeInterruption,
}

type task11SyntheticCycleRequest struct {
	Kind    task11SyntheticCycleKind
	Ordinal uint64
}

type task11SyntheticResourceObservation struct {
	Resource    ReclamationResource
	HighWater   uint64
	PostCleanup uint64
}

type task11SyntheticCycleResult struct {
	Kind    task11SyntheticCycleKind
	Ordinal uint64

	OneJob  syntheticOneJobRuntimeObservation
	Cleanup CompleteCleanupProof
	Restart *task11SyntheticRestartAggregateEvidence

	Resources                   []task11SyntheticResourceObservation
	VersionStagingAbsent        bool
	VersionStagingAbsenceDigest string
}

type task11SeedIsolationResult struct {
	Proof         SeedIsolationProof
	FirstCleanup  CompleteCleanupProof
	SecondCleanup CompleteCleanupProof
}

type task11SyntheticLifecycleDriver interface {
	RunSyntheticCycle(
		context.Context,
		task11SyntheticCycleRequest,
	) (task11SyntheticCycleResult, error)
	RunSeedIsolation(context.Context) (task11SeedIsolationResult, error)
}

type task11SyntheticCleanupOwner interface {
	owns(cleanupHandle) bool
	remove(context.Context, cleanupHandle) error
	recordedRemoved(cleanupHandle) bool
}

type task11SyntheticLifecycleStage uint8

const (
	task11SyntheticStageOneJob task11SyntheticLifecycleStage = iota
	task11SyntheticStageCleanup
	task11SyntheticStageReclamation
	task11SyntheticStageSeed
	task11SyntheticStageComplete
)

type task11SyntheticLifecycleRuntime struct {
	sampleCount uint64
	prepared    task11PreparedRuntimeSource
	driver      task11SyntheticLifecycleDriver

	mu             sync.Mutex
	stage          task11SyntheticLifecycleStage
	busy           bool
	failed         bool
	cleanupDigests map[string]struct{}
}

func newTask11SyntheticLifecycleRuntime(
	sampleCount uint64,
	prepared task11PreparedRuntimeSource,
	driver task11SyntheticLifecycleDriver,
) (*task11SyntheticLifecycleRuntime, error) {
	if sampleCount < 3 || prepared == nil || driver == nil {
		return nil, ErrFixtureStart
	}
	return &task11SyntheticLifecycleRuntime{
		sampleCount:    sampleCount,
		prepared:       prepared,
		driver:         driver,
		stage:          task11SyntheticStageOneJob,
		cleanupDigests: make(map[string]struct{}),
	}, nil
}

func (r *task11SyntheticLifecycleRuntime) SyntheticOneJobObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (syntheticOneJobRuntimeObservation, error) {
	if !r.begin(ctx, prepared, task11SyntheticStageOneJob) {
		return syntheticOneJobRuntimeObservation{}, ErrFixtureStart
	}
	result, err := r.driver.RunSyntheticCycle(
		ctx,
		task11SyntheticCycleRequest{
			Kind:    task11CycleOneJob,
			Ordinal: 0,
		},
	)
	if err != nil ||
		!validTask11SyntheticCycleIdentity(
			result,
			task11CycleOneJob,
			0,
		) ||
		!validSyntheticOneJobRuntimeObservation(result.OneJob) ||
		!r.acceptCleanup(result.Cleanup) ||
		result.OneJob.ReclamationDigest !=
			result.Cleanup.ObservationDigest ||
		result.Restart != nil ||
		len(result.Resources) != 0 ||
		result.VersionStagingAbsent ||
		result.VersionStagingAbsenceDigest != "" {
		r.finish(false, task11SyntheticStageCleanup)
		return syntheticOneJobRuntimeObservation{}, ErrFixtureStart
	}
	r.finish(true, task11SyntheticStageCleanup)
	return result.OneJob, nil
}

func (r *task11SyntheticLifecycleRuntime) CleanupMatrixObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (cleanupMatrixRuntimeObservation, error) {
	if !r.begin(ctx, prepared, task11SyntheticStageCleanup) {
		return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
	}
	proofs := make([]CompleteCleanupProof, 0, len(task11CleanupCycles))
	for _, kind := range task11CleanupCycles {
		result, err := r.driver.RunSyntheticCycle(
			ctx,
			task11SyntheticCycleRequest{
				Kind:    kind,
				Ordinal: 0,
			},
		)
		restartValid := kind != task11CycleCleanupControllerRestart &&
			result.Restart == nil &&
			result.Cleanup.AssertionCount == 13
		if kind == task11CycleCleanupControllerRestart {
			restartValid = result.Restart != nil &&
				validTask11SyntheticRestartAggregateEvidence(
					*result.Restart,
				) &&
				result.Restart.proof == result.Cleanup
		}
		if err != nil ||
			!validTask11SyntheticCycleIdentity(result, kind, 0) ||
			!restartValid ||
			!r.acceptCleanup(result.Cleanup) ||
			result.OneJob !=
				(syntheticOneJobRuntimeObservation{}) ||
			len(result.Resources) != 0 ||
			result.VersionStagingAbsent ||
			result.VersionStagingAbsenceDigest != "" {
			r.finish(false, task11SyntheticStageReclamation)
			return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
		}
		proofs = append(proofs, result.Cleanup)
	}
	if len(proofs) != len(task11CleanupCycles) {
		r.finish(false, task11SyntheticStageReclamation)
		return cleanupMatrixRuntimeObservation{}, ErrFixtureStart
	}
	r.finish(true, task11SyntheticStageReclamation)
	return cleanupMatrixRuntimeObservation{
		Success:             proofs[0],
		Cancellation:        proofs[1],
		PreListenerFailure:  proofs[2],
		ListenerCrash:       proofs[3],
		ControllerRestart:   proofs[4],
		UpgradeInterruption: proofs[5],
	}, nil
}

func (r *task11SyntheticLifecycleRuntime) ReclamationObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (reclamationRuntimeObservation, error) {
	if !r.begin(ctx, prepared, task11SyntheticStageReclamation) {
		return reclamationRuntimeObservation{}, ErrFixtureStart
	}
	series := make(
		[]ReclamationResourceSeries,
		len(requiredReclamationResources),
	)
	for index, resource := range requiredReclamationResources {
		series[index].Resource = resource
		series[index].HighWater = make(
			[]ReclamationSample,
			0,
			r.sampleCount,
		)
		series[index].PostCleanup = make(
			[]ReclamationSample,
			0,
			r.sampleCount,
		)
	}
	stagingDigests := make([]string, 0, r.sampleCount)
	for ordinal := uint64(0); ordinal < r.sampleCount; ordinal++ {
		result, err := r.driver.RunSyntheticCycle(
			ctx,
			task11SyntheticCycleRequest{
				Kind:    task11CycleReclamation,
				Ordinal: ordinal,
			},
		)
		if err != nil ||
			!validTask11SyntheticCycleIdentity(
				result,
				task11CycleReclamation,
				ordinal,
			) ||
			result.Restart != nil ||
			result.Cleanup.AssertionCount != 13 ||
			!r.acceptCleanup(result.Cleanup) ||
			result.OneJob !=
				(syntheticOneJobRuntimeObservation{}) ||
			len(result.Resources) !=
				len(requiredReclamationResources) ||
			!result.VersionStagingAbsent ||
			!isLowerHex(
				result.VersionStagingAbsenceDigest,
				sha256.Size*2,
			) {
			r.finish(false, task11SyntheticStageSeed)
			return reclamationRuntimeObservation{}, ErrFixtureStart
		}
		for resourceIndex, expected := range requiredReclamationResources {
			resource := result.Resources[resourceIndex]
			if resource.Resource != expected ||
				resource.HighWater < resource.PostCleanup {
				r.finish(false, task11SyntheticStageSeed)
				return reclamationRuntimeObservation{},
					ErrFixtureStart
			}
			series[resourceIndex].HighWater = append(
				series[resourceIndex].HighWater,
				ReclamationSample{
					Index: ordinal,
					Value: resource.HighWater,
				},
			)
			series[resourceIndex].PostCleanup = append(
				series[resourceIndex].PostCleanup,
				ReclamationSample{
					Index: ordinal,
					Value: resource.PostCleanup,
				},
			)
		}
		stagingDigests = append(
			stagingDigests,
			result.VersionStagingAbsenceDigest,
		)
	}
	stagingDigest, err := recordingCanonicalDigest(
		task11ReclamationStagingDomain,
		struct {
			SchemaVersion uint32   `json:"schema_version"`
			SampleCount   uint64   `json:"sample_count"`
			Digests       []string `json:"digests"`
		}{
			SchemaVersion: 1,
			SampleCount:   r.sampleCount,
			Digests:       stagingDigests,
		},
	)
	if err != nil {
		r.finish(false, task11SyntheticStageSeed)
		return reclamationRuntimeObservation{}, ErrFixtureStart
	}
	r.finish(true, task11SyntheticStageSeed)
	return reclamationRuntimeObservation{
		Series:                      series,
		VersionStagingAbsent:        true,
		VersionStagingAbsenceDigest: stagingDigest,
	}, nil
}

func (r *task11SyntheticLifecycleRuntime) SeedIsolationObservation(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
) (SeedIsolationProof, error) {
	if !r.begin(ctx, prepared, task11SyntheticStageSeed) {
		return SeedIsolationProof{}, ErrFixtureStart
	}
	result, err := r.driver.RunSeedIsolation(ctx)
	if err != nil ||
		ValidateSeedIsolation(result.Proof) != nil ||
		!r.acceptCleanup(result.FirstCleanup) ||
		!r.acceptCleanup(result.SecondCleanup) ||
		result.FirstCleanup.ObservationDigest ==
			result.SecondCleanup.ObservationDigest {
		r.finish(false, task11SyntheticStageComplete)
		return SeedIsolationProof{}, ErrFixtureStart
	}
	r.finish(true, task11SyntheticStageComplete)
	return result.Proof, nil
}

func (r *task11SyntheticLifecycleRuntime) begin(
	ctx context.Context,
	prepared fixtureRuntimeObservation,
	expected task11SyntheticLifecycleStage,
) bool {
	if r == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		r.prepared == nil ||
		r.driver == nil ||
		!validFixtureRuntimeObservation(prepared) {
		return false
	}
	if _, err := r.prepared.SnapshotPreparedEvidence(
		ctx,
		prepared,
	); err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed || r.busy || r.stage != expected {
		return false
	}
	r.busy = true
	return true
}

func (r *task11SyntheticLifecycleRuntime) finish(
	success bool,
	next task11SyntheticLifecycleStage,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy = false
	if !success {
		r.failed = true
		return
	}
	r.stage = next
}

func (r *task11SyntheticLifecycleRuntime) acceptCleanup(
	proof CompleteCleanupProof,
) bool {
	if _, err := SealCompleteCleanup(proof); err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.cleanupDigests[proof.ObservationDigest]; exists {
		return false
	}
	r.cleanupDigests[proof.ObservationDigest] = struct{}{}
	return true
}

func (r *task11SyntheticLifecycleRuntime) owns(
	handle cleanupHandle,
) bool {
	if r == nil {
		return false
	}
	owner, ok := r.driver.(task11SyntheticCleanupOwner)
	return ok && owner.owns(handle)
}

func (r *task11SyntheticLifecycleRuntime) remove(
	ctx context.Context,
	handle cleanupHandle,
) error {
	if r == nil {
		return ErrFixtureCleanup
	}
	owner, ok := r.driver.(task11SyntheticCleanupOwner)
	if !ok {
		return ErrFixtureCleanup
	}
	return owner.remove(ctx, handle)
}

func (r *task11SyntheticLifecycleRuntime) recordedRemoved(
	handle cleanupHandle,
) bool {
	if r == nil {
		return false
	}
	owner, ok := r.driver.(task11SyntheticCleanupOwner)
	return ok && owner.recordedRemoved(handle)
}

func validTask11SyntheticCycleIdentity(
	result task11SyntheticCycleResult,
	kind task11SyntheticCycleKind,
	ordinal uint64,
) bool {
	return result.Kind == kind &&
		result.Ordinal == ordinal &&
		validTask11SyntheticCycleKind(kind)
}

func validTask11SyntheticCycleKind(
	kind task11SyntheticCycleKind,
) bool {
	switch kind {
	case task11CycleOneJob,
		task11CycleCleanupSuccess,
		task11CycleCleanupCancellation,
		task11CycleCleanupPreListenerFailure,
		task11CycleCleanupListenerCrash,
		task11CycleCleanupControllerRestart,
		task11CycleCleanupUpgradeInterruption,
		task11CycleReclamation:
		return true
	default:
		return false
	}
}

func task11CleanupCycleKinds() []task11SyntheticCycleKind {
	return append([]task11SyntheticCycleKind(nil), task11CleanupCycles[:]...)
}

var (
	_ syntheticOneJobRuntime = (*task11SyntheticLifecycleRuntime)(nil)
	_ cleanupMatrixRuntime   = (*task11SyntheticLifecycleRuntime)(nil)
	_ reclamationRuntime     = (*task11SyntheticLifecycleRuntime)(nil)
	_ seedIsolationRuntime   = (*task11SyntheticLifecycleRuntime)(nil)
)
