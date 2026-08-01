package productionruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/watchdog"
)

func TestSelectWatchdogReservationRequiresExactTerminalCommittedInstall(
	t *testing.T,
) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(
			*hostruntime.OperationJournal,
			*hostruntime.StorageReservation,
		)
		persistJournal     bool
		persistReservation bool
		wantError          bool
	}{
		{
			name:               "terminal committed",
			persistJournal:     true,
			persistReservation: true,
		},
		{
			name:      "missing",
			wantError: true,
		},
		{
			name:           "one-sided journal",
			persistJournal: true,
			wantError:      true,
		},
		{
			name:               "one-sided reservation",
			persistReservation: true,
			wantError:          true,
		},
		{
			name: "active",
			mutate: func(
				_ *hostruntime.OperationJournal,
				reservation *hostruntime.StorageReservation,
			) {
				reservation.State = hostruntime.ReservationStateActive
				reservation.CommittedTargetProofDigest = nil
			},
			persistJournal:     true,
			persistReservation: true,
			wantError:          true,
		},
		{
			name: "released",
			mutate: func(
				_ *hostruntime.OperationJournal,
				reservation *hostruntime.StorageReservation,
			) {
				proof := strings.Repeat("d", 64)
				reservation.State = hostruntime.ReservationStateReleased
				reservation.CommittedTargetProofDigest = nil
				reservation.ReleasedAbsenceProofDigest = &proof
			},
			persistJournal:     true,
			persistReservation: true,
			wantError:          true,
		},
		{
			name: "compensated",
			mutate: func(
				journal *hostruntime.OperationJournal,
				_ *hostruntime.StorageReservation,
			) {
				path := hostruntime.CompensationInstallGreenfieldPostSelection
				journal.CompensationPath = &path
				journal.Phase = hostruntime.OperationPhaseCompGreenfieldSelected
			},
			persistJournal:     true,
			persistReservation: true,
			wantError:          true,
		},
		{
			name: "overlay revision mismatch",
			mutate: func(
				journal *hostruntime.OperationJournal,
				_ *hostruntime.StorageReservation,
			) {
				journal.BindingDigest = strings.Repeat("f", 64)
			},
			persistJournal:     true,
			persistReservation: true,
			wantError:          true,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := openProductionLifecycleTestStore(t)
			binding, manifest, journal, reservation :=
				greenfieldContinuationFixture(t)
			journal.Phase = hostruntime.OperationPhaseComplete
			proof := strings.Repeat("c", 64)
			reservation.State = hostruntime.ReservationStateCommitted
			reservation.CommittedTargetProofDigest = &proof
			if test.mutate != nil {
				test.mutate(&journal, &reservation)
			}
			persistWatchdogFixture(
				t,
				store,
				journal,
				reservation,
				test.persistJournal,
				test.persistReservation,
			)
			_, manifestDigest, err :=
				hostruntime.MarshalRuntimeManifest(manifest)
			if err != nil {
				t.Fatalf("MarshalRuntimeManifest() error = %v", err)
			}
			got, err := selectWatchdogReservation(
				store,
				binding.PrivateOverlayRevision,
				manifest,
				manifestDigest,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("selectWatchdogReservation() = %#v, %v", got, err)
			}
			if err == nil && got.OperationID != reservation.OperationID {
				t.Fatalf("reservation operation = %q", got.OperationID)
			}
		})
	}
}

func TestSelectWatchdogReservationRejectsSecondCurrentTargetBinding(
	t *testing.T,
) {
	t.Parallel()

	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	journal.Phase = hostruntime.OperationPhaseComplete
	proof := strings.Repeat("c", 64)
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &proof
	persistWatchdogFixture(t, store, journal, reservation, true, true)

	foreign := binding
	foreign.PrivateOverlayRevision = strings.Repeat("f", 64)
	operationID, err := hostruntime.DeriveOperationID(
		foreign.Kind,
		foreign.InstallDisposition,
		foreign.ExpectedGeneration,
		foreign.PriorManifestDigest,
		foreign.TargetManifestDigest,
		foreign.TargetFleet,
		foreign.PrivateOverlayRevision,
	)
	if err != nil {
		t.Fatalf("DeriveOperationID() error = %v", err)
	}
	foreign.OperationID = operationID
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(foreign)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	foreignJournal := journal
	foreignJournal.OperationID = operationID
	foreignJournal.BindingDigest = bindingDigest
	foreignReservation := reservation
	foreignReservation.OperationID = operationID
	foreignReservation.BindingDigest = bindingDigest
	persistWatchdogFixture(
		t,
		store,
		foreignJournal,
		foreignReservation,
		true,
		true,
	)
	_, manifestDigest, _ := hostruntime.MarshalRuntimeManifest(manifest)
	if _, err := selectWatchdogReservation(
		store,
		binding.PrivateOverlayRevision,
		manifest,
		manifestDigest,
	); err == nil {
		t.Fatal("selectWatchdogReservation() accepted second current target")
	}
}

func TestSystemWatchdogStorageEnvelopeRevalidatesSelectedReservation(
	t *testing.T,
) {
	t.Parallel()

	store := openProductionLifecycleTestStore(t)
	binding, manifest, journal, reservation :=
		greenfieldContinuationFixture(t)
	journal.Phase = hostruntime.OperationPhaseComplete
	proof := strings.Repeat("c", 64)
	reservation.State = hostruntime.ReservationStateCommitted
	reservation.CommittedTargetProofDigest = &proof
	persistWatchdogFixture(t, store, journal, reservation, true, true)
	_, manifestDigest, _ := hostruntime.MarshalRuntimeManifest(manifest)
	factoryCalls := 0
	envelope := &systemWatchdogStorageEnvelope{
		store:            store,
		overlayRevision:  binding.PrivateOverlayRevision,
		manifest:         manifest,
		manifestDigest:   manifestDigest,
		operationTimeout: time.Second,
		probe: func(ctx context.Context) (StorageProbe, error) {
			factoryCalls++
			if _, ok := ctx.Deadline(); !ok {
				return nil, errors.New("deadline missing")
			}
			return storageProbeFromReservation(reservation), nil
		},
	}
	if err := envelope.Revalidate(context.Background()); err != nil {
		t.Fatalf("Revalidate() error = %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("probe factory calls = %d", factoryCalls)
	}
	envelope.probe = func(context.Context) (StorageProbe, error) {
		probe := storageProbeFromReservation(reservation)
		probe.err = errors.New("observation failed")
		return probe, nil
	}
	if err := envelope.Revalidate(context.Background()); err == nil {
		t.Fatal("Revalidate() accepted unavailable storage observation")
	}
}

func TestSystemWatchdogLifecycleGateReadsOwnershipUnderLease(t *testing.T) {
	t.Parallel()

	store := openProductionLifecycleTestStore(t)
	gate := &systemWatchdogLifecycleGate{store: store}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := gate.Acquire(ctx, time.Millisecond)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	owned, err := lease.Owned()
	if err != nil || owned {
		t.Fatalf("Owned() = %t, %v", owned, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, _, journal, reservation := greenfieldContinuationFixture(t)
	persistGreenfieldContinuation(t, store, journal, reservation)
	lease, err = gate.Acquire(ctx, time.Millisecond)
	if err != nil {
		t.Fatalf("second Acquire() error = %v", err)
	}
	owned, err = lease.Owned()
	if err != nil || !owned {
		t.Fatalf("Owned(active) = %t, %v", owned, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestSystemWatchdogSupervisorStopsFenceNoneOnlyThroughExactRecord(
	t *testing.T,
) {
	t.Parallel()

	record := validProcessRecordFixture()
	record.PrivateOverlayRevision = strings.Repeat("a", 64)
	record.ManifestDigest = strings.Repeat("b", 64)
	record.ActiveFleet = fleetfence.FleetPortable
	record.FenceGeneration = 7
	store := &fakeProcessRecordStore{record: &record}
	fence := &fakeSystemWatchdogFence{snapshot: fleetfence.Snapshot{
		Header: fleetfence.Header{
			Generation:  8,
			ActiveFleet: fleetfence.FleetNone,
		},
	}}
	authority := &fakeSystemWatchdogProcess{
		inspection: ProcessInspection{State: ProcessRunning},
	}
	var bindings []ProcessBinding
	supervisor, err := newSystemWatchdogSupervisor(
		systemWatchdogSupervisorConfig{
			Fence:              fence,
			Store:              store,
			Authority:          recordingWatchdogAuthority(&bindings, authority),
			Probe:              &fakeSystemWatchdogProbe{},
			Quiescence:         &fakeSystemWatchdogQuiescence{},
			OverlayRevision:    record.PrivateOverlayRevision,
			ManifestDigest:     record.ManifestDigest,
			ManifestGeneration: 7,
			OperationTimeout:   time.Second,
		},
	)
	if err != nil {
		t.Fatalf("newSystemWatchdogSupervisor() error = %v", err)
	}
	observation, err := supervisor.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	_, identity, _ := MarshalProcessRecord(record)
	if observation.ActiveFleet != watchdog.FleetNone ||
		observation.FenceGeneration != 8 ||
		observation.Process != watchdog.ProcessUnhealthy ||
		observation.ProcessIdentity != identity {
		t.Fatalf("Inspect() = %#v", observation)
	}
	if err := supervisor.SafeStop(
		boundedSystemWatchdogContext(t),
		observation,
	); err != nil {
		t.Fatalf("SafeStop() error = %v", err)
	}
	if authority.stoppedIdentity != identity || len(bindings) != 2 {
		t.Fatalf("stop identity=%q bindings=%#v", authority.stoppedIdentity, bindings)
	}
	for _, binding := range bindings {
		if binding.ActiveFleet != record.ActiveFleet ||
			binding.FenceGeneration != record.FenceGeneration {
			t.Fatalf("record binding was not preserved: %#v", binding)
		}
	}
}

func TestSystemWatchdogSafeStopRejectsProcessTupleDriftBeforeSignal(
	t *testing.T,
) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*ProcessObservation)
	}{
		{
			"boot-id",
			func(observation *ProcessObservation) {
				observation.Start.BootID =
					"1" + observation.Start.BootID[1:]
			},
		},
		{
			"pid-namespace",
			func(observation *ProcessObservation) {
				observation.Start.PIDNamespaceInode++
			},
		},
		{
			"process-group",
			func(observation *ProcessObservation) { observation.PGID++ },
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := validProcessRecordFixture()
			store := &fakeProcessRecordStore{record: &record}
			kernel := newFakeProcessKernel(record)
			test.mutate(&kernel.observation)
			fence := &fakeSystemWatchdogFence{snapshot: fleetfence.Snapshot{
				Header: fleetfence.Header{
					Generation:  record.FenceGeneration,
					ActiveFleet: record.ActiveFleet,
				},
			}}
			authorityFactory := func(
				binding ProcessBinding,
			) (systemWatchdogProcess, error) {
				config := validProcessAuthorityConfig(store, kernel)
				config.Binding = binding
				return NewProcessAuthority(config)
			}
			supervisor, err := newSystemWatchdogSupervisor(
				systemWatchdogSupervisorConfig{
					Fence:              fence,
					Store:              store,
					Authority:          authorityFactory,
					Probe:              &fakeSystemWatchdogProbe{},
					Quiescence:         &fakeSystemWatchdogQuiescence{},
					OverlayRevision:    record.PrivateOverlayRevision,
					ManifestDigest:     record.ManifestDigest,
					ManifestGeneration: record.FenceGeneration,
					OperationTimeout:   time.Second,
				},
			)
			if err != nil {
				t.Fatalf("newSystemWatchdogSupervisor() error = %v", err)
			}
			_, identity, err := MarshalProcessRecord(record)
			if err != nil {
				t.Fatalf("MarshalProcessRecord() error = %v", err)
			}
			observation := watchdog.Observation{
				FenceGeneration: record.FenceGeneration,
				ActiveFleet:     watchdog.FleetPortable,
				Process:         watchdog.ProcessUnhealthy,
				ProcessIdentity: identity,
			}

			if err := supervisor.SafeStop(
				boundedSystemWatchdogContext(t),
				observation,
			); err == nil {
				t.Fatal("SafeStop() accepted a drifted process tuple")
			}
			if len(kernel.signals) != 0 || store.removeCalls != 0 {
				t.Fatal("SafeStop() signaled or removed a drifted process tuple")
			}
		})
	}
}

func TestSystemWatchdogSupervisorStartAndProofUseLiveFenceAndPositiveZeros(
	t *testing.T,
) {
	t.Parallel()

	revision := strings.Repeat("a", 64)
	manifestDigest := strings.Repeat("b", 64)
	fence := &fakeSystemWatchdogFence{snapshot: fleetfence.Snapshot{
		Header: fleetfence.Header{
			Generation:  11,
			ActiveFleet: fleetfence.FleetPortable,
		},
	}}
	store := &fakeProcessRecordStore{}
	startedIdentity := strings.Repeat("c", 64)
	authority := &fakeSystemWatchdogProcess{
		inspection: ProcessInspection{
			State:           ProcessRunning,
			ProcessIdentity: startedIdentity,
		},
		started: ProcessInspection{
			State:           ProcessRunning,
			ProcessIdentity: startedIdentity,
		},
	}
	var bindings []ProcessBinding
	probe := &fakeSystemWatchdogProbe{}
	quiescence := &fakeSystemWatchdogQuiescence{}
	supervisor, err := newSystemWatchdogSupervisor(
		systemWatchdogSupervisorConfig{
			Fence:              fence,
			Store:              store,
			Authority:          recordingWatchdogAuthority(&bindings, authority),
			Probe:              probe,
			Quiescence:         quiescence,
			OverlayRevision:    revision,
			ManifestDigest:     manifestDigest,
			ManifestGeneration: 11,
			OperationTimeout:   time.Second,
		},
	)
	if err != nil {
		t.Fatalf("newSystemWatchdogSupervisor() error = %v", err)
	}
	absent := watchdog.Observation{
		FenceGeneration: 11,
		ActiveFleet:     watchdog.FleetPortable,
		Process:         watchdog.ProcessAbsent,
	}
	started, err := supervisor.StartDisabled(
		boundedSystemWatchdogContext(t),
		absent,
	)
	if err != nil {
		t.Fatalf("StartDisabled() error = %v", err)
	}
	if started.Process != watchdog.ProcessRunning ||
		started.ProcessIdentity != startedIdentity ||
		len(bindings) != 1 ||
		bindings[0].ActiveFleet != fleetfence.FleetPortable ||
		bindings[0].FenceGeneration != 11 {
		t.Fatalf("StartDisabled() = %#v bindings=%#v", started, bindings)
	}

	record := validProcessRecordFixture()
	record.PrivateOverlayRevision = revision
	record.ManifestDigest = manifestDigest
	record.ActiveFleet = fleetfence.FleetPortable
	record.FenceGeneration = 11
	_, recordIdentity, _ := MarshalProcessRecord(record)
	recordStore := &fakeProcessRecordStore{record: &record}
	authority.inspection.ProcessIdentity = recordIdentity
	proofSupervisor, err := newSystemWatchdogSupervisor(
		systemWatchdogSupervisorConfig{
			Fence:              fence,
			Store:              recordStore,
			Authority:          recordingWatchdogAuthority(&bindings, authority),
			Probe:              probe,
			Quiescence:         quiescence,
			OverlayRevision:    revision,
			ManifestDigest:     manifestDigest,
			ManifestGeneration: 11,
			OperationTimeout:   time.Second,
		},
	)
	if err != nil {
		t.Fatalf("new proof supervisor error = %v", err)
	}
	proofObservation := watchdog.Observation{
		FenceGeneration: 11,
		ActiveFleet:     watchdog.FleetPortable,
		Process:         watchdog.ProcessRunning,
		ProcessIdentity: recordIdentity,
	}
	proof, err := proofSupervisor.ProveDisabled(
		boundedSystemWatchdogContext(t),
		proofObservation,
	)
	if err != nil {
		t.Fatalf("ProveDisabled() error = %v", err)
	}
	if !proof.PolicyDisabled || proof.ManagedProcesses != 1 ||
		proof.PendingAcquisitions != 0 || proof.ActiveListeners != 0 ||
		proof.AcquisitionProcesses != 0 || probe.calls != 1 ||
		quiescence.calls != 1 {
		t.Fatalf("ProveDisabled() = %#v", proof)
	}

	probe.err = errors.New("health failed")
	if _, err := proofSupervisor.ProveDisabled(
		boundedSystemWatchdogContext(t),
		proofObservation,
	); err == nil {
		t.Fatal("ProveDisabled() accepted failed controller proof")
	}
	if quiescence.calls != 1 {
		t.Fatal("quiescence ran after failed controller proof")
	}
}

func TestSystemWatchdogSupervisorCompositeCallsUseCycleContext(t *testing.T) {
	t.Parallel()

	const operationTimeout = 20 * time.Millisecond
	revision := strings.Repeat("a", 64)
	manifestDigest := strings.Repeat("b", 64)
	record := validProcessRecordFixture()
	record.PrivateOverlayRevision = revision
	record.ManifestDigest = manifestDigest
	record.ActiveFleet = fleetfence.FleetPortable
	record.FenceGeneration = 11
	_, recordIdentity, err := MarshalProcessRecord(record)
	if err != nil {
		t.Fatalf("MarshalProcessRecord() error = %v", err)
	}
	baseSnapshot := fleetfence.Snapshot{Header: fleetfence.Header{
		Generation:  11,
		ActiveFleet: fleetfence.FleetPortable,
	}}
	running := watchdog.Observation{
		FenceGeneration: 11,
		ActiveFleet:     watchdog.FleetPortable,
		Process:         watchdog.ProcessRunning,
		ProcessIdentity: recordIdentity,
	}
	absent := watchdog.Observation{
		FenceGeneration: 11,
		ActiveFleet:     watchdog.FleetPortable,
		Process:         watchdog.ProcessAbsent,
	}

	t.Run("safe stop", func(t *testing.T) {
		process := &fakeSystemWatchdogProcess{}
		deadlineMatched := false
		cancelLinked := false
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		deadline, _ := ctx.Deadline()
		process.stop = func(callCtx context.Context, _ string) error {
			deadlineMatched = sameContextDeadline(callCtx, deadline)
			cancel()
			cancelLinked = contextCancellationObserved(callCtx)
			return callCtx.Err()
		}
		supervisor := newSystemWatchdogSupervisorFixture(
			t,
			baseSnapshot,
			&fakeProcessRecordStore{record: &record},
			process,
			&fakeSystemWatchdogProbe{},
			&fakeSystemWatchdogQuiescence{},
			revision,
			manifestDigest,
			operationTimeout,
		)
		if err := supervisor.SafeStop(ctx, running); err == nil {
			t.Fatal("SafeStop() accepted parent cancellation")
		}
		if !deadlineMatched || !cancelLinked {
			t.Fatalf(
				"SafeStop() parent deadline=%t cancellation=%t",
				deadlineMatched,
				cancelLinked,
			)
		}
	})

	t.Run("start", func(t *testing.T) {
		process := &fakeSystemWatchdogProcess{}
		deadlineMatched := false
		cancelLinked := false
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		deadline, _ := ctx.Deadline()
		process.start = func(callCtx context.Context) (ProcessInspection, error) {
			deadlineMatched = sameContextDeadline(callCtx, deadline)
			cancel()
			cancelLinked = contextCancellationObserved(callCtx)
			return ProcessInspection{}, callCtx.Err()
		}
		supervisor := newSystemWatchdogSupervisorFixture(
			t,
			baseSnapshot,
			&fakeProcessRecordStore{},
			process,
			&fakeSystemWatchdogProbe{},
			&fakeSystemWatchdogQuiescence{},
			revision,
			manifestDigest,
			operationTimeout,
		)
		if _, err := supervisor.StartDisabled(ctx, absent); err == nil {
			t.Fatal("StartDisabled() accepted parent cancellation")
		}
		if !deadlineMatched || !cancelLinked {
			t.Fatalf(
				"StartDisabled() parent deadline=%t cancellation=%t",
				deadlineMatched,
				cancelLinked,
			)
		}
	})

	t.Run("post-start fence cleanup", func(t *testing.T) {
		startedIdentity := strings.Repeat("c", 64)
		process := &fakeSystemWatchdogProcess{}
		startDeadlineMatched := false
		stopDeadlineMatched := false
		cancelLinked := false
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		deadline, _ := ctx.Deadline()
		process.start = func(callCtx context.Context) (ProcessInspection, error) {
			startDeadlineMatched = sameContextDeadline(callCtx, deadline)
			return ProcessInspection{
				State:           ProcessRunning,
				ProcessIdentity: startedIdentity,
			}, nil
		}
		process.stop = func(callCtx context.Context, _ string) error {
			stopDeadlineMatched = sameContextDeadline(callCtx, deadline)
			cancel()
			cancelLinked = contextCancellationObserved(callCtx)
			return callCtx.Err()
		}
		fenceCalls := 0
		fence := &fakeSystemWatchdogFence{inspect: func(
			context.Context,
		) (fleetfence.Snapshot, error) {
			fenceCalls++
			if fenceCalls == 1 {
				return baseSnapshot, nil
			}
			changed := baseSnapshot
			changed.Header.Generation++
			return changed, nil
		}}
		supervisor := newSystemWatchdogSupervisorFixtureWithFence(
			t,
			fence,
			&fakeProcessRecordStore{},
			process,
			&fakeSystemWatchdogProbe{},
			&fakeSystemWatchdogQuiescence{},
			revision,
			manifestDigest,
			operationTimeout,
		)
		if _, err := supervisor.StartDisabled(ctx, absent); err == nil {
			t.Fatal("StartDisabled() accepted changed fence")
		}
		if !startDeadlineMatched || !stopDeadlineMatched || !cancelLinked {
			t.Fatalf(
				"cleanup contexts start=%t stop=%t cancellation=%t",
				startDeadlineMatched,
				stopDeadlineMatched,
				cancelLinked,
			)
		}
	})

	t.Run("controller probe", func(t *testing.T) {
		process := &fakeSystemWatchdogProcess{inspection: ProcessInspection{
			State:           ProcessRunning,
			ProcessIdentity: recordIdentity,
		}}
		probe := &fakeSystemWatchdogProbe{}
		quiescence := &fakeSystemWatchdogQuiescence{}
		deadlineMatched := false
		cancelLinked := false
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		deadline, _ := ctx.Deadline()
		probe.observe = func(callCtx context.Context) (
			DisabledControllerObservation,
			error,
		) {
			deadlineMatched = sameContextDeadline(callCtx, deadline)
			cancel()
			cancelLinked = contextCancellationObserved(callCtx)
			return DisabledControllerObservation{}, callCtx.Err()
		}
		supervisor := newSystemWatchdogSupervisorFixture(
			t,
			baseSnapshot,
			&fakeProcessRecordStore{record: &record},
			process,
			probe,
			quiescence,
			revision,
			manifestDigest,
			operationTimeout,
		)
		if _, err := supervisor.ProveDisabled(ctx, running); err == nil {
			t.Fatal("ProveDisabled() accepted partial cancelled probe")
		}
		if !deadlineMatched || !cancelLinked || quiescence.calls != 0 {
			t.Fatalf(
				"probe parent deadline=%t cancellation=%t quiescence=%d",
				deadlineMatched,
				cancelLinked,
				quiescence.calls,
			)
		}
	})

	t.Run("narrow observations", func(t *testing.T) {
		process := &fakeSystemWatchdogProcess{inspection: ProcessInspection{
			State:           ProcessRunning,
			ProcessIdentity: recordIdentity,
		}}
		probe := &fakeSystemWatchdogProbe{}
		quiescence := &fakeSystemWatchdogQuiescence{}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		parentDeadline, _ := ctx.Deadline()
		probeDeadlineMatched := false
		quiescenceBounded := false
		probe.observe = func(callCtx context.Context) (
			DisabledControllerObservation,
			error,
		) {
			probeDeadlineMatched = sameContextDeadline(callCtx, parentDeadline)
			return DisabledControllerObservation{
				PolicyEpoch:  1,
				PolicyDigest: strings.Repeat("d", 64),
			}, nil
		}
		quiescence.prove = func(callCtx context.Context) error {
			deadline, ok := callCtx.Deadline()
			quiescenceBounded = ok && deadline.Before(parentDeadline) &&
				time.Until(deadline) <= operationTimeout
			return nil
		}
		supervisor := newSystemWatchdogSupervisorFixture(
			t,
			baseSnapshot,
			&fakeProcessRecordStore{record: &record},
			process,
			probe,
			quiescence,
			revision,
			manifestDigest,
			operationTimeout,
		)
		if _, err := supervisor.ProveDisabled(ctx, running); err != nil {
			t.Fatalf("ProveDisabled() error = %v", err)
		}
		if !probeDeadlineMatched || !quiescenceBounded {
			t.Fatalf(
				"probe parent deadline=%t quiescence bounded=%t",
				probeDeadlineMatched,
				quiescenceBounded,
			)
		}
	})
}

func TestSystemWatchdogSupervisorRejectsForeignRecordWithoutAuthority(
	t *testing.T,
) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	fence := &fakeSystemWatchdogFence{snapshot: fleetfence.Snapshot{
		Header: fleetfence.Header{
			Generation:  record.FenceGeneration,
			ActiveFleet: record.ActiveFleet,
		},
	}}
	authorityCalls := 0
	supervisor, err := newSystemWatchdogSupervisor(
		systemWatchdogSupervisorConfig{
			Fence: fence,
			Store: store,
			Authority: func(
				ProcessBinding,
			) (systemWatchdogProcess, error) {
				authorityCalls++
				return &fakeSystemWatchdogProcess{}, nil
			},
			Probe:              &fakeSystemWatchdogProbe{},
			Quiescence:         &fakeSystemWatchdogQuiescence{},
			OverlayRevision:    strings.Repeat("f", 64),
			ManifestDigest:     record.ManifestDigest,
			ManifestGeneration: record.FenceGeneration,
			OperationTimeout:   time.Second,
		},
	)
	if err != nil {
		t.Fatalf("newSystemWatchdogSupervisor() error = %v", err)
	}
	if _, err := supervisor.Inspect(context.Background()); err == nil {
		t.Fatal("Inspect() accepted foreign overlay record")
	}
	if authorityCalls != 0 {
		t.Fatalf("authority calls = %d", authorityCalls)
	}
}

func TestParseSystemWatchdogTimingsUsesOnlyOverlayBounds(t *testing.T) {
	t.Parallel()

	overlay := hostruntime.PrivateOverlay{
		Fence: hostruntime.FenceTimingOverlay{
			LockPollInterval: "5ms",
		},
		Controller: hostruntime.ControllerTimingOverlay{
			OperationTimeout: "2s",
		},
		Watchdog: hostruntime.WatchdogOverlay{
			ProcessGrace:    "3s",
			RestartDeadline: "9s",
		},
	}
	poll, grace, operation, restart, err :=
		parseSystemWatchdogTimings(overlay)
	if err != nil ||
		poll != 5*time.Millisecond ||
		grace != 3*time.Second ||
		operation != 2*time.Second ||
		restart != 9*time.Second {
		t.Fatalf(
			"parseSystemWatchdogTimings() = %v %v %v %v, %v",
			poll,
			grace,
			operation,
			restart,
			err,
		)
	}
	overlay.Fence.LockPollInterval = "2s"
	if _, _, _, _, err := parseSystemWatchdogTimings(overlay); err == nil {
		t.Fatal("parseSystemWatchdogTimings() accepted slow lock poll")
	}
}

func persistWatchdogFixture(
	t *testing.T,
	store *hostruntime.LifecycleStore,
	journal hostruntime.OperationJournal,
	reservation hostruntime.StorageReservation,
	persistJournal bool,
	persistReservation bool,
) {
	t.Helper()
	if persistJournal {
		document, _, err := hostruntime.MarshalOperationJournal(journal)
		if err != nil {
			t.Fatalf("MarshalOperationJournal() error = %v", err)
		}
		if err := store.CreateCanonical(
			hostruntime.LifecycleJournals,
			journal.OperationID+".journal.json",
			document,
			maximumProductionLifecycleJournalBytes,
		); err != nil {
			t.Fatalf("CreateCanonical(journal) error = %v", err)
		}
	}
	if persistReservation {
		document, _, err := hostruntime.MarshalStorageReservation(reservation)
		if err != nil {
			t.Fatalf("MarshalStorageReservation() error = %v", err)
		}
		if err := store.CreateCanonical(
			hostruntime.LifecycleReservations,
			reservation.OperationID+".reservation.json",
			document,
			maximumProductionLifecycleReservationBytes,
		); err != nil {
			t.Fatalf("CreateCanonical(reservation) error = %v", err)
		}
	}
}

type fakeSystemWatchdogFence struct {
	snapshot fleetfence.Snapshot
	err      error
	calls    int
	inspect  func(context.Context) (fleetfence.Snapshot, error)
}

func (fence *fakeSystemWatchdogFence) Inspect(
	ctx context.Context,
) (fleetfence.Snapshot, error) {
	fence.calls++
	if _, ok := ctx.Deadline(); !ok {
		return fleetfence.Snapshot{}, errors.New("deadline missing")
	}
	if fence.inspect != nil {
		return fence.inspect(ctx)
	}
	return fence.snapshot, fence.err
}

type fakeSystemWatchdogProcess struct {
	inspection      ProcessInspection
	inspectErr      error
	started         ProcessInspection
	startErr        error
	stopErr         error
	stoppedIdentity string
	inspect         func(context.Context) (ProcessInspection, error)
	start           func(context.Context) (ProcessInspection, error)
	stop            func(context.Context, string) error
}

func (process *fakeSystemWatchdogProcess) Inspect(
	ctx context.Context,
) (ProcessInspection, error) {
	if process.inspect != nil {
		return process.inspect(ctx)
	}
	return process.inspection, process.inspectErr
}

func (process *fakeSystemWatchdogProcess) StartDisabled(
	ctx context.Context,
) (ProcessInspection, error) {
	if process.start != nil {
		return process.start(ctx)
	}
	return process.started, process.startErr
}

func (process *fakeSystemWatchdogProcess) Stop(
	ctx context.Context,
	identity string,
) error {
	process.stoppedIdentity = identity
	if process.stop != nil {
		return process.stop(ctx, identity)
	}
	return process.stopErr
}

func recordingWatchdogAuthority(
	bindings *[]ProcessBinding,
	process systemWatchdogProcess,
) systemWatchdogAuthorityFactory {
	return func(binding ProcessBinding) (systemWatchdogProcess, error) {
		*bindings = append(*bindings, binding)
		return process, nil
	}
}

type fakeSystemWatchdogProbe struct {
	calls   int
	err     error
	observe func(context.Context) (DisabledControllerObservation, error)
}

func (probe *fakeSystemWatchdogProbe) Observe(
	ctx context.Context,
) (DisabledControllerObservation, error) {
	probe.calls++
	if probe.observe != nil {
		return probe.observe(ctx)
	}
	if probe.err != nil {
		return DisabledControllerObservation{}, probe.err
	}
	return DisabledControllerObservation{
		PolicyEpoch:  1,
		PolicyDigest: strings.Repeat("d", 64),
	}, nil
}

type fakeSystemWatchdogQuiescence struct {
	calls int
	err   error
	prove func(context.Context) error
}

func (quiescence *fakeSystemWatchdogQuiescence) ProveManagedQuiescence(
	ctx context.Context,
) error {
	quiescence.calls++
	if quiescence.prove != nil {
		return quiescence.prove(ctx)
	}
	return quiescence.err
}

func newSystemWatchdogSupervisorFixture(
	t *testing.T,
	snapshot fleetfence.Snapshot,
	store ProcessRecordStore,
	process systemWatchdogProcess,
	probe DisabledControllerProbe,
	quiescence hostruntime.ManagedQuiescence,
	revision string,
	manifestDigest string,
	operationTimeout time.Duration,
) *systemWatchdogSupervisor {
	t.Helper()
	return newSystemWatchdogSupervisorFixtureWithFence(
		t,
		&fakeSystemWatchdogFence{snapshot: snapshot},
		store,
		process,
		probe,
		quiescence,
		revision,
		manifestDigest,
		operationTimeout,
	)
}

func newSystemWatchdogSupervisorFixtureWithFence(
	t *testing.T,
	fence systemWatchdogFence,
	store ProcessRecordStore,
	process systemWatchdogProcess,
	probe DisabledControllerProbe,
	quiescence hostruntime.ManagedQuiescence,
	revision string,
	manifestDigest string,
	operationTimeout time.Duration,
) *systemWatchdogSupervisor {
	t.Helper()
	supervisor, err := newSystemWatchdogSupervisor(
		systemWatchdogSupervisorConfig{
			Fence:              fence,
			Store:              store,
			Authority:          recordingWatchdogAuthority(&[]ProcessBinding{}, process),
			Probe:              probe,
			Quiescence:         quiescence,
			OverlayRevision:    revision,
			ManifestDigest:     manifestDigest,
			ManifestGeneration: 11,
			OperationTimeout:   operationTimeout,
		},
	)
	if err != nil {
		t.Fatalf("newSystemWatchdogSupervisor() error = %v", err)
	}
	return supervisor
}

func sameContextDeadline(ctx context.Context, want time.Time) bool {
	got, ok := ctx.Deadline()
	return ok && got.Equal(want)
}

func contextCancellationObserved(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(100 * time.Millisecond):
		return false
	}
}

func boundedSystemWatchdogContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
