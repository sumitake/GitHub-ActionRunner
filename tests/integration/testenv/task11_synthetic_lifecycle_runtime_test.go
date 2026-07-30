package testenv

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

type fakeTask11SyntheticLifecycleDriver struct {
	cycles     map[task11SyntheticCycleKind][]task11SyntheticCycleResult
	seed       task11SeedIsolationResult
	calls      []task11SyntheticCycleRequest
	seedCalls  int
	cycleError error
	seedError  error
}

func (d *fakeTask11SyntheticLifecycleDriver) RunSyntheticCycle(
	ctx context.Context,
	request task11SyntheticCycleRequest,
) (task11SyntheticCycleResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	d.calls = append(d.calls, request)
	if d.cycleError != nil {
		return task11SyntheticCycleResult{}, d.cycleError
	}
	results := d.cycles[request.Kind]
	if request.Ordinal >= uint64(len(results)) {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	return results[request.Ordinal], nil
}

func (d *fakeTask11SyntheticLifecycleDriver) RunSeedIsolation(
	ctx context.Context,
) (task11SeedIsolationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	d.seedCalls++
	return d.seed, d.seedError
}

func TestTask11SyntheticLifecycleRuntimeRunsClosedCanonicalCyclesOnce(
	t *testing.T,
) {
	t.Parallel()

	sampleCount := uint64(3)
	driver := validTask11SyntheticLifecycleDriver(t, sampleCount)
	preparedSource, prepared := validTask11SyntheticPreparedSource()
	runtime, err := newTask11SyntheticLifecycleRuntime(
		sampleCount,
		preparedSource,
		driver,
	)
	if err != nil {
		t.Fatalf("newTask11SyntheticLifecycleRuntime: %v", err)
	}
	oneJob, err := runtime.SyntheticOneJobObservation(
		context.Background(),
		prepared,
	)
	if err != nil ||
		!validSyntheticOneJobRuntimeObservation(oneJob) {
		t.Fatalf("one job = %+v err=%v", oneJob, err)
	}
	cleanup, err := runtime.CleanupMatrixObservation(
		context.Background(),
		prepared,
	)
	if err != nil {
		t.Fatalf("CleanupMatrixObservation: %v", err)
	}
	for index, proof := range cleanupProofs(cleanup) {
		if _, err := SealCompleteCleanup(proof); err != nil {
			t.Fatalf("cleanup proof %d: %v", index, err)
		}
	}
	reclamation, err := runtime.ReclamationObservation(
		context.Background(),
		prepared,
	)
	if err != nil ||
		!validReclamationRuntimeObservation(
			reclamation,
			validTask11ReclamationBaselines(),
			sampleCount,
		) {
		t.Fatalf("reclamation = %+v err=%v", reclamation, err)
	}
	seed, err := runtime.SeedIsolationObservation(
		context.Background(),
		prepared,
	)
	if err != nil || ValidateSeedIsolation(seed) != nil {
		t.Fatalf("seed = %+v err=%v", seed, err)
	}

	expectedKinds := []task11SyntheticCycleKind{
		task11CycleOneJob,
		task11CycleCleanupSuccess,
		task11CycleCleanupCancellation,
		task11CycleCleanupPreListenerFailure,
		task11CycleCleanupListenerCrash,
		task11CycleCleanupControllerRestart,
		task11CycleCleanupUpgradeInterruption,
		task11CycleReclamation,
		task11CycleReclamation,
		task11CycleReclamation,
	}
	if len(driver.calls) != len(expectedKinds) {
		t.Fatalf("cycle calls = %d", len(driver.calls))
	}
	for index, expected := range expectedKinds {
		if driver.calls[index].Kind != expected {
			t.Fatalf(
				"cycle %d kind = %q, want %q",
				index,
				driver.calls[index].Kind,
				expected,
			)
		}
		if expected == task11CycleReclamation {
			wantOrdinal := uint64(index - (len(expectedKinds) - int(sampleCount)))
			if driver.calls[index].Ordinal != wantOrdinal {
				t.Fatalf(
					"reclamation ordinal = %d, want %d",
					driver.calls[index].Ordinal,
					wantOrdinal,
				)
			}
		} else if driver.calls[index].Ordinal != 0 {
			t.Fatalf("cycle %d ordinal = %d", index, driver.calls[index].Ordinal)
		}
	}
	if driver.seedCalls != 1 {
		t.Fatalf("seed calls = %d", driver.seedCalls)
	}

	if _, err := runtime.SyntheticOneJobObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("repeat one-job error = %v", err)
	}
	if _, err := runtime.CleanupMatrixObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("repeat cleanup error = %v", err)
	}
	if _, err := runtime.ReclamationObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("repeat reclamation error = %v", err)
	}
	if _, err := runtime.SeedIsolationObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("repeat seed error = %v", err)
	}
}

func TestTask11SyntheticLifecycleRuntimeRejectsIncompleteCleanupAndDrift(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(*fakeTask11SyntheticLifecycleDriver){
		"one-job cleanup incomplete": func(
			driver *fakeTask11SyntheticLifecycleDriver,
		) {
			result := driver.cycles[task11CycleOneJob][0]
			result.Cleanup.ContainersAbsent = false
			driver.cycles[task11CycleOneJob][0] = result
		},
		"one-job reclamation unbound": func(
			driver *fakeTask11SyntheticLifecycleDriver,
		) {
			result := driver.cycles[task11CycleOneJob][0]
			result.OneJob.ReclamationDigest = inputDigestA
			driver.cycles[task11CycleOneJob][0] = result
		},
		"cleanup payload pair": func(
			driver *fakeTask11SyntheticLifecycleDriver,
		) {
			result := driver.cycles[task11CycleCleanupUpgradeInterruption][0]
			result.Cleanup.PayloadVersionCount = 2
			driver.cycles[task11CycleCleanupUpgradeInterruption][0] = result
		},
		"reclamation resource reordered": func(
			driver *fakeTask11SyntheticLifecycleDriver,
		) {
			result := driver.cycles[task11CycleReclamation][1]
			result.Resources[0], result.Resources[1] =
				result.Resources[1], result.Resources[0]
			driver.cycles[task11CycleReclamation][1] = result
		},
		"reclamation staging remains": func(
			driver *fakeTask11SyntheticLifecycleDriver,
		) {
			result := driver.cycles[task11CycleReclamation][2]
			result.VersionStagingAbsent = false
			driver.cycles[task11CycleReclamation][2] = result
		},
		"seed first workspace remains": func(
			driver *fakeTask11SyntheticLifecycleDriver,
		) {
			driver.seed.FirstCleanup.WorkAbsent = false
		},
		"seed mutation visible": func(
			driver *fakeTask11SyntheticLifecycleDriver,
		) {
			driver.seed.Proof.SecondCopyDigest =
				driver.seed.Proof.CurrentMutationDigest
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			driver := validTask11SyntheticLifecycleDriver(t, 3)
			mutate(driver)
			preparedSource, prepared :=
				validTask11SyntheticPreparedSource()
			runtime, err := newTask11SyntheticLifecycleRuntime(
				3,
				preparedSource,
				driver,
			)
			if err != nil {
				t.Fatalf("newTask11SyntheticLifecycleRuntime: %v", err)
			}
			var observeErr error
			switch name {
			case "one-job cleanup incomplete", "one-job reclamation unbound":
				_, observeErr = runtime.SyntheticOneJobObservation(
					context.Background(),
					prepared,
				)
			case "cleanup payload pair":
				advanceTask11SyntheticRuntime(
					t,
					runtime,
					prepared,
					task11SyntheticStageCleanup,
				)
				_, observeErr = runtime.CleanupMatrixObservation(
					context.Background(),
					prepared,
				)
			case "reclamation resource reordered",
				"reclamation staging remains":
				advanceTask11SyntheticRuntime(
					t,
					runtime,
					prepared,
					task11SyntheticStageReclamation,
				)
				_, observeErr = runtime.ReclamationObservation(
					context.Background(),
					prepared,
				)
			default:
				advanceTask11SyntheticRuntime(
					t,
					runtime,
					prepared,
					task11SyntheticStageSeed,
				)
				_, observeErr = runtime.SeedIsolationObservation(
					context.Background(),
					prepared,
				)
			}
			if !errors.Is(observeErr, ErrFixtureStart) {
				t.Fatalf("observation error = %v", observeErr)
			}
		})
	}
}

func advanceTask11SyntheticRuntime(
	t *testing.T,
	runtime *task11SyntheticLifecycleRuntime,
	prepared fixtureRuntimeObservation,
	target task11SyntheticLifecycleStage,
) {
	t.Helper()
	if target > task11SyntheticStageOneJob {
		if _, err := runtime.SyntheticOneJobObservation(
			context.Background(),
			prepared,
		); err != nil {
			t.Fatalf("advance one job: %v", err)
		}
	}
	if target > task11SyntheticStageCleanup {
		if _, err := runtime.CleanupMatrixObservation(
			context.Background(),
			prepared,
		); err != nil {
			t.Fatalf("advance cleanup: %v", err)
		}
	}
	if target > task11SyntheticStageReclamation {
		if _, err := runtime.ReclamationObservation(
			context.Background(),
			prepared,
		); err != nil {
			t.Fatalf("advance reclamation: %v", err)
		}
	}
}

func TestTask11SyntheticLifecycleRuntimeRejectsPreparedSubstitution(
	t *testing.T,
) {
	t.Parallel()

	driver := validTask11SyntheticLifecycleDriver(t, 3)
	preparedSource, prepared := validTask11SyntheticPreparedSource()
	runtime, err := newTask11SyntheticLifecycleRuntime(
		3,
		preparedSource,
		driver,
	)
	if err != nil {
		t.Fatalf("newTask11SyntheticLifecycleRuntime: %v", err)
	}
	if prepared.PreparedEvidenceDigest == inputDigestA {
		prepared.PreparedEvidenceDigest = inputDigestB
	} else {
		prepared.PreparedEvidenceDigest = inputDigestA
	}
	if _, err := runtime.SyntheticOneJobObservation(
		context.Background(),
		prepared,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("prepared substitution error = %v", err)
	}
	if len(driver.calls) != 0 {
		t.Fatal("prepared substitution reached lifecycle driver")
	}
}

func TestOrchestratedFixtureRuntimeBindsOwnedSyntheticLifecycleBeforePrepare(
	t *testing.T,
) {
	t.Parallel()

	owner := &orchestratedFixtureRuntime{}
	driver := validTask11SyntheticLifecycleDriver(t, 3)
	runtime, err := newTask11SyntheticLifecycleRuntime(3, owner, driver)
	if err != nil {
		t.Fatalf("newTask11SyntheticLifecycleRuntime: %v", err)
	}
	if err := owner.bindTask11SyntheticLifecycle(runtime); err != nil {
		t.Fatalf("bindTask11SyntheticLifecycle: %v", err)
	}
	if owner.task11Synthetic != runtime {
		t.Fatal("synthetic lifecycle ownership was not exact")
	}
	if err := owner.bindTask11SyntheticLifecycle(runtime); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("duplicate bind error = %v", err)
	}

	late := &orchestratedFixtureRuntime{prepareAttempted: true}
	lateRuntime, err := newTask11SyntheticLifecycleRuntime(3, late, driver)
	if err != nil {
		t.Fatalf("new late runtime: %v", err)
	}
	if err := late.bindTask11SyntheticLifecycle(lateRuntime); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("late bind error = %v", err)
	}

	other := &orchestratedFixtureRuntime{}
	if err := other.bindTask11SyntheticLifecycle(runtime); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("cross-owner bind error = %v", err)
	}
}

func validTask11SyntheticPreparedSource() (
	*fakeTask11PreparedRuntime,
	fixtureRuntimeObservation,
) {
	namespace := validNamespaceEvidenceRuntime()
	return &fakeTask11PreparedRuntime{
		prepared: namespace.observation,
		flood:    namespace.flood,
	}, namespace.observation
}

func validTask11SyntheticLifecycleDriver(
	t *testing.T,
	sampleCount uint64,
) *fakeTask11SyntheticLifecycleDriver {
	t.Helper()

	oneJobCleanup := validCompleteCleanupProofForTask11("one-job")
	oneJob := syntheticOneJobRuntimeObservation{
		JobCompleted:         true,
		JobCompletionDigest:  inputDigestA,
		ProxyRequestComplete: true,
		ProxyRequestDigest:   inputDigestB,
		Deregistered:         true,
		DeregistrationDigest: inputDigestC,
		Reclaimed:            true,
		ReclamationDigest:    oneJobCleanup.ObservationDigest,
	}
	cycles := map[task11SyntheticCycleKind][]task11SyntheticCycleResult{
		task11CycleOneJob: {{
			Kind:    task11CycleOneJob,
			OneJob:  oneJob,
			Cleanup: oneJobCleanup,
		}},
	}
	for _, kind := range task11CleanupCycleKinds() {
		cycles[kind] = []task11SyntheticCycleResult{{
			Kind:    kind,
			Cleanup: validCompleteCleanupProofForTask11(string(kind)),
		}}
	}
	restart := validTask11SyntheticRestartAggregate(t)
	cycles[task11CycleCleanupControllerRestart][0].Cleanup =
		restart.proof
	cycles[task11CycleCleanupControllerRestart][0].Restart =
		&restart
	reclamation := make(
		[]task11SyntheticCycleResult,
		sampleCount,
	)
	for sampleIndex := uint64(0); sampleIndex < sampleCount; sampleIndex++ {
		resources := make(
			[]task11SyntheticResourceObservation,
			len(requiredReclamationResources),
		)
		for resourceIndex, resource := range requiredReclamationResources {
			resources[resourceIndex] = task11SyntheticResourceObservation{
				Resource:    resource,
				HighWater:   uint64(resourceIndex + 2),
				PostCleanup: uint64(resourceIndex % 2),
			}
		}
		reclamation[sampleIndex] = task11SyntheticCycleResult{
			Kind:    task11CycleReclamation,
			Ordinal: sampleIndex,
			Cleanup: validCompleteCleanupProofForTask11(
				string(task11CycleReclamation) +
					strconv.FormatUint(sampleIndex, 10),
			),
			Resources:                   resources,
			VersionStagingAbsent:        true,
			VersionStagingAbsenceDigest: inputDigestD,
		}
	}
	cycles[task11CycleReclamation] = reclamation
	return &fakeTask11SyntheticLifecycleDriver{
		cycles: cycles,
		seed: task11SeedIsolationResult{
			Proof: validSeedIsolationProof(),
			FirstCleanup: validCompleteCleanupProofForTask11(
				"seed-first",
			),
			SecondCleanup: validCompleteCleanupProofForTask11(
				"seed-second",
			),
		},
	}
}

func validCompleteCleanupProofForTask11(
	label string,
) CompleteCleanupProof {
	digest, err := recordingCanonicalDigest(
		"portable-ghar.task11.test-cleanup.v1\x00",
		struct {
			Label string `json:"label"`
		}{Label: label},
	)
	if err != nil {
		panic(err)
	}
	return CompleteCleanupProof{
		ContainersAbsent:        true,
		CgroupsAbsent:           true,
		TmpfsAbsent:             true,
		WorkAbsent:              true,
		WorkUpdateAbsent:        true,
		ProcessesAbsent:         true,
		NamespacesAbsent:        true,
		SocketsAbsent:           true,
		AuthoritiesAbsent:       true,
		TemporaryFilesAbsent:    true,
		HostBackedWorkAbsent:    true,
		UnexpectedObjectsAbsent: true,
		PayloadVersionCount:     1,
		AssertionCount:          13,
		ObservationDigest:       digest,
	}
}

func validTask11ReclamationBaselines() ReclamationBaselines {
	resources := make(
		[]ReclamationBaseline,
		len(requiredReclamationResources),
	)
	for index, resource := range requiredReclamationResources {
		resources[index] = ReclamationBaseline{
			Resource:                resource,
			Baseline:                uint64(index + 2),
			Margin:                  16,
			MaximumSlopeNumerator:   1,
			MaximumSlopeDenominator: 1,
		}
	}
	return ReclamationBaselines{Resources: resources}
}

func cleanupProofs(
	observation cleanupMatrixRuntimeObservation,
) []CompleteCleanupProof {
	return []CompleteCleanupProof{
		observation.Success,
		observation.Cancellation,
		observation.PreListenerFailure,
		observation.ListenerCrash,
		observation.ControllerRestart,
		observation.UpgradeInterruption,
	}
}
