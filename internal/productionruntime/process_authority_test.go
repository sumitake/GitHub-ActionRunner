package productionruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestProcessAuthorityInspectUsesRecordDigestIdentity(t *testing.T) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	kernel := newFakeProcessKernel(record)
	authority := newProcessAuthorityFixture(t, store, kernel)

	inspection, err := authority.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	_, want, err := MarshalProcessRecord(record)
	if err != nil {
		t.Fatalf("MarshalProcessRecord() error = %v", err)
	}
	if inspection.State != ProcessRunning ||
		inspection.ProcessIdentity != want {
		t.Fatalf("Inspect() = %#v, want running %q", inspection, want)
	}
	if store.removeCalls != 0 || len(kernel.signals) != 0 {
		t.Fatal("Inspect() mutated process state")
	}
}

func TestProcessAuthorityInspectAbsentDoesNotObserveKernel(t *testing.T) {
	t.Parallel()

	store := &fakeProcessRecordStore{}
	kernel := newFakeProcessKernel(validProcessRecordFixture())
	authority := newProcessAuthorityFixture(t, store, kernel)

	inspection, err := authority.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if inspection.State != ProcessAbsent ||
		inspection.ProcessIdentity != "" ||
		kernel.observeCalls != 0 {
		t.Fatalf("Inspect() = %#v; observe calls = %d", inspection, kernel.observeCalls)
	}
}

func TestProcessAuthorityInspectRejectsBindingAndObservationDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ProcessRecord, *fakeProcessKernel)
	}{
		{
			"binding",
			func(record *ProcessRecord, _ *fakeProcessKernel) {
				record.FenceGeneration++
			},
		},
		{
			"pid-reuse",
			func(_ *ProcessRecord, kernel *fakeProcessKernel) {
				kernel.observation.Start.StartTimeTicks++
			},
		},
		{
			"unstable",
			func(_ *ProcessRecord, kernel *fakeProcessKernel) {
				kernel.observe = func(call int) (ProcessObservation, error) {
					observation := kernel.observation
					if call == 2 {
						observation.Start.ExecutableInode++
					}
					return observation, nil
				}
			},
		},
		{
			"unavailable",
			func(_ *ProcessRecord, kernel *fakeProcessKernel) {
				kernel.observe = func(int) (ProcessObservation, error) {
					return ProcessObservation{}, errors.New("unavailable")
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := validProcessRecordFixture()
			kernel := newFakeProcessKernel(record)
			test.mutate(&record, kernel)
			store := &fakeProcessRecordStore{record: &record}
			authority := newProcessAuthorityFixture(t, store, kernel)

			inspection, err := authority.Inspect(context.Background())
			if err == nil || inspection.State != ProcessUnhealthy {
				t.Fatalf("Inspect() = %#v, %v", inspection, err)
			}
			if store.removeCalls != 0 || len(kernel.signals) != 0 {
				t.Fatal("drift path mutated process state")
			}
		})
	}
}

func TestProcessAuthorityStartDisabledCreatesAndProvesRecord(t *testing.T) {
	t.Parallel()

	store := &fakeProcessRecordStore{}
	record := validProcessRecordFixture()
	kernel := newFakeProcessKernel(record)
	authority := newProcessAuthorityFixture(t, store, kernel)

	inspection, err := authority.StartDisabled(context.Background())
	if err != nil {
		t.Fatalf("StartDisabled() error = %v", err)
	}
	if inspection.State != ProcessRunning ||
		inspection.ProcessIdentity == "" ||
		store.record == nil ||
		store.createCalls != 1 ||
		kernel.launchCalls != 1 ||
		kernel.cleanupCalls != 0 {
		t.Fatalf(
			"StartDisabled() = %#v; store=%#v kernel=%#v",
			inspection,
			store,
			kernel,
		)
	}
}

func TestProcessAuthorityStartFailureCleansChildAndNeverFalseSucceeds(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name        string
		configure   func(*fakeProcessRecordStore, *fakeProcessKernel)
		wantRecord  bool
		wantCleanup int
	}{
		{
			"exclusive-create",
			func(store *fakeProcessRecordStore, _ *fakeProcessKernel) {
				store.createErr = errors.New("create failed")
			},
			false,
			1,
		},
		{
			"ambiguous-create-exact-record",
			func(store *fakeProcessRecordStore, _ *fakeProcessKernel) {
				store.createErr = errors.New("create failed after publish")
				store.publishOnCreateError = true
			},
			false,
			1,
		},
		{
			"post-create-observation",
			func(_ *fakeProcessRecordStore, kernel *fakeProcessKernel) {
				kernel.observe = func(call int) (ProcessObservation, error) {
					if call >= 3 {
						return ProcessObservation{}, errors.New("observe failed")
					}
					return kernel.observation, nil
				}
			},
			false,
			1,
		},
		{
			"cleanup-incomplete-retains-record",
			func(_ *fakeProcessRecordStore, kernel *fakeProcessKernel) {
				kernel.observe = func(call int) (ProcessObservation, error) {
					if call >= 3 {
						return ProcessObservation{}, errors.New("observe failed")
					}
					return kernel.observation, nil
				}
				kernel.cleanupErr = errors.New("cleanup failed")
			},
			true,
			1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeProcessRecordStore{}
			record := validProcessRecordFixture()
			kernel := newFakeProcessKernel(record)
			test.configure(store, kernel)
			authority := newProcessAuthorityFixture(t, store, kernel)

			inspection, err := authority.StartDisabled(context.Background())
			if !errors.Is(err, ErrProcessStartFailed) ||
				inspection.State != "" ||
				kernel.cleanupCalls != test.wantCleanup ||
				(store.record != nil) != test.wantRecord {
				t.Fatalf(
					"StartDisabled() = %#v, %v; store=%#v kernel=%#v",
					inspection,
					err,
					store,
					kernel,
				)
			}
		})
	}
}

func TestProcessAuthorityStopGracefulExitRemovesExactRecord(t *testing.T) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	kernel := newFakeProcessKernel(record)
	kernel.absentAfterTerm = true
	kernel.groupAbsent = true
	authority := newProcessAuthorityFixture(t, store, kernel)
	_, identity, _ := MarshalProcessRecord(record)

	if err := authority.Stop(context.Background(), identity); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if store.record != nil ||
		store.removeCalls != 1 ||
		len(kernel.signals) != 1 ||
		kernel.signals[0] != ProcessSignalTerminate {
		t.Fatalf("stop state: store=%#v kernel=%#v", store, kernel)
	}
}

func TestProcessAuthorityStopReplacementBeforeTerminateSendsNoSignal(
	t *testing.T,
) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	kernel := newFakeProcessKernel(record)
	store.onRead = func(call int) {
		if call == 2 {
			replacement := record
			replacement.PID++
			store.record = &replacement
		}
	}
	authority := newProcessAuthorityFixture(t, store, kernel)
	_, identity, _ := MarshalProcessRecord(record)

	if err := authority.Stop(
		context.Background(),
		identity,
	); !errors.Is(err, ErrProcessIdentityDrift) {
		t.Fatalf("Stop() error = %v", err)
	}
	if len(kernel.signals) != 0 || store.removeCalls != 0 {
		t.Fatal("replacement before TERM was signaled or removed")
	}
}

func TestProcessAuthorityStopPIDReuseSendsNoSignal(t *testing.T) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	kernel := newFakeProcessKernel(record)
	kernel.observation.Start.StartTimeTicks++
	authority := newProcessAuthorityFixture(t, store, kernel)
	_, identity, _ := MarshalProcessRecord(record)

	if err := authority.Stop(
		context.Background(),
		identity,
	); !errors.Is(err, ErrProcessIdentityDrift) {
		t.Fatalf("Stop() error = %v", err)
	}
	if len(kernel.signals) != 0 || store.removeCalls != 0 {
		t.Fatal("reused PID was signaled or removed")
	}
}

func TestProcessAuthorityStopEscalatesOnlyWhileIdentityRemainsExact(
	t *testing.T,
) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	kernel := newFakeProcessKernel(record)
	kernel.absentAfterKill = true
	kernel.groupAbsent = true
	authority := newProcessAuthorityFixture(t, store, kernel)
	_, identity, _ := MarshalProcessRecord(record)

	if err := authority.Stop(context.Background(), identity); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if len(kernel.signals) != 2 ||
		kernel.signals[0] != ProcessSignalTerminate ||
		kernel.signals[1] != ProcessSignalKill {
		t.Fatalf("signals = %#v", kernel.signals)
	}
}

func TestProcessAuthorityStopReplacementBeforeKillSendsNoKill(
	t *testing.T,
) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	kernel := newFakeProcessKernel(record)
	store.onRead = func(call int) {
		if call == 3 {
			replacement := record
			replacement.PID++
			store.record = &replacement
		}
	}
	authority := newProcessAuthorityFixture(t, store, kernel)
	_, identity, _ := MarshalProcessRecord(record)

	if err := authority.Stop(
		context.Background(),
		identity,
	); !errors.Is(err, ErrProcessIdentityDrift) {
		t.Fatalf("Stop() error = %v", err)
	}
	if len(kernel.signals) != 1 ||
		kernel.signals[0] != ProcessSignalTerminate ||
		store.removeCalls != 0 {
		t.Fatalf("signals=%#v removeCalls=%d", kernel.signals, store.removeCalls)
	}
}

func TestProcessAuthorityStopRetainsRecordUntilGroupAbsence(t *testing.T) {
	t.Parallel()

	record := validProcessRecordFixture()
	store := &fakeProcessRecordStore{record: &record}
	kernel := newFakeProcessKernel(record)
	kernel.absentAfterTerm = true
	kernel.groupAbsent = false
	authority := newProcessAuthorityFixture(t, store, kernel)
	_, identity, _ := MarshalProcessRecord(record)

	if err := authority.Stop(
		context.Background(),
		identity,
	); !errors.Is(err, ErrProcessTimeout) {
		t.Fatalf("Stop() error = %v", err)
	}
	if store.record == nil || store.removeCalls != 0 {
		t.Fatal("record removed before group absence proof")
	}
}

func TestProcessAuthorityRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	validStore := &fakeProcessRecordStore{}
	validKernel := newFakeProcessKernel(validProcessRecordFixture())
	valid := validProcessAuthorityConfig(validStore, validKernel)
	tests := []struct {
		name   string
		mutate func(*ProcessAuthorityConfig)
	}{
		{"store", func(config *ProcessAuthorityConfig) { config.Store = nil }},
		{"kernel", func(config *ProcessAuthorityConfig) { config.Kernel = nil }},
		{"overlay", func(config *ProcessAuthorityConfig) {
			config.Binding.PrivateOverlayRevision = "00"
		}},
		{"manifest", func(config *ProcessAuthorityConfig) {
			config.Binding.ManifestDigest = "00"
		}},
		{"fleet", func(config *ProcessAuthorityConfig) {
			config.Binding.ActiveFleet = fleetfence.FleetNone
		}},
		{"generation", func(config *ProcessAuthorityConfig) {
			config.Binding.FenceGeneration = 0
		}},
		{"binary", func(config *ProcessAuthorityConfig) {
			config.Launch.ControllerBinary = "relative"
		}},
		{"executable-digest", func(config *ProcessAuthorityConfig) {
			config.Launch.ExecutableDigest = "00"
		}},
		{"poll", func(config *ProcessAuthorityConfig) {
			config.Timing.PollInterval = 0
		}},
		{"term", func(config *ProcessAuthorityConfig) {
			config.Timing.TermGrace = 0
		}},
		{"kill", func(config *ProcessAuthorityConfig) {
			config.Timing.KillGrace = 0
		}},
		{"cleanup", func(config *ProcessAuthorityConfig) {
			config.Timing.CleanupGrace = 0
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := valid
			test.mutate(&config)
			if _, err := NewProcessAuthority(
				config,
			); !errors.Is(err, ErrProcessAuthorityInvalid) {
				t.Fatalf("NewProcessAuthority() error = %v", err)
			}
		})
	}
}

type fakeProcessRecordStore struct {
	record               *ProcessRecord
	readErr              error
	createErr            error
	removeErr            error
	publishOnCreateError bool
	readCalls            int
	createCalls          int
	removeCalls          int
	onRead               func(int)
}

func (store *fakeProcessRecordStore) Read(
	context.Context,
) (ProcessRecord, string, bool, error) {
	store.readCalls++
	if store.onRead != nil {
		store.onRead(store.readCalls)
	}
	if store.readErr != nil {
		return ProcessRecord{}, "", false, store.readErr
	}
	if store.record == nil {
		return ProcessRecord{}, "", false, nil
	}
	record := *store.record
	_, digest, err := MarshalProcessRecord(record)
	return record, digest, true, err
}

func (store *fakeProcessRecordStore) Create(
	_ context.Context,
	record ProcessRecord,
) (string, error) {
	store.createCalls++
	if store.record != nil {
		return "", errors.New("create failed")
	}
	_, digest, err := MarshalProcessRecord(record)
	if err != nil {
		return "", err
	}
	if store.createErr != nil {
		if store.publishOnCreateError {
			store.record = &record
		}
		return "", store.createErr
	}
	store.record = &record
	return digest, nil
}

func (store *fakeProcessRecordStore) Remove(
	_ context.Context,
	expected string,
) error {
	store.removeCalls++
	if store.removeErr != nil || store.record == nil {
		return errors.New("remove failed")
	}
	_, digest, err := MarshalProcessRecord(*store.record)
	if err != nil || digest != expected {
		return errors.New("remove conflict")
	}
	store.record = nil
	return nil
}

type fakeProcessKernel struct {
	observation     ProcessObservation
	observe         func(int) (ProcessObservation, error)
	observeCalls    int
	launchCalls     int
	cleanupCalls    int
	signals         []ProcessSignal
	launchErr       error
	cleanupErr      error
	signalErr       error
	groupErr        error
	groupAbsent     bool
	absentAfterTerm bool
	absentAfterKill bool
}

func newFakeProcessKernel(record ProcessRecord) *fakeProcessKernel {
	return &fakeProcessKernel{
		observation: ProcessObservation{
			Present: true,
			Start: hostruntime.ProcessStartObservation{
				BootID:             "01234567-89ab-cdef-0123-456789abcdef",
				PIDNamespaceInode:  100,
				PID:                record.PID,
				StartTimeTicks:     record.StartTimeTicks,
				ExecutableDigest:   record.ExecutableDigest,
				ExecutableDevice:   record.ExecutableDevice,
				ExecutableInode:    record.ExecutableInode,
				ExecutableFileSize: 500,
			},
		},
	}
}

func (kernel *fakeProcessKernel) LaunchDisabled(
	context.Context,
	ControllerLaunch,
) (hostruntime.ProcessStartObservation, uint64, error) {
	kernel.launchCalls++
	if kernel.launchErr != nil {
		return hostruntime.ProcessStartObservation{}, 0, kernel.launchErr
	}
	return kernel.observation.Start, kernel.observation.Start.PID, nil
}

func (kernel *fakeProcessKernel) Observe(
	context.Context,
	uint64,
) (ProcessObservation, error) {
	kernel.observeCalls++
	if kernel.observe != nil {
		return kernel.observe(kernel.observeCalls)
	}
	if kernel.absentAfterKill &&
		len(kernel.signals) > 0 &&
		kernel.signals[len(kernel.signals)-1] == ProcessSignalKill {
		return ProcessObservation{Present: false}, nil
	}
	if kernel.absentAfterTerm && len(kernel.signals) > 0 {
		return ProcessObservation{Present: false}, nil
	}
	return kernel.observation, nil
}

func (kernel *fakeProcessKernel) SignalGroup(
	_ context.Context,
	_ uint64,
	signal ProcessSignal,
) error {
	if kernel.signalErr != nil {
		return kernel.signalErr
	}
	kernel.signals = append(kernel.signals, signal)
	return nil
}

func (kernel *fakeProcessKernel) GroupAbsent(
	context.Context,
	uint64,
) (bool, error) {
	return kernel.groupAbsent, kernel.groupErr
}

func (kernel *fakeProcessKernel) CleanupStarted(
	context.Context,
	uint64,
	uint64,
) error {
	kernel.cleanupCalls++
	return kernel.cleanupErr
}

func newProcessAuthorityFixture(
	t *testing.T,
	store ProcessRecordStore,
	kernel ProcessKernel,
) *ProcessAuthority {
	t.Helper()
	authority, err := NewProcessAuthority(
		validProcessAuthorityConfig(store, kernel),
	)
	if err != nil {
		t.Fatalf("NewProcessAuthority() error = %v", err)
	}
	return authority
}

func validProcessAuthorityConfig(
	store ProcessRecordStore,
	kernel ProcessKernel,
) ProcessAuthorityConfig {
	return ProcessAuthorityConfig{
		Store:  store,
		Kernel: kernel,
		Binding: ProcessBinding{
			PrivateOverlayRevision: strings.Repeat("b", 64),
			ManifestDigest:         strings.Repeat("c", 64),
			ActiveFleet:            fleetfence.FleetPortable,
			FenceGeneration:        505,
		},
		Launch: ControllerLaunch{
			ControllerBinary: "/opt/portable/controller",
			PrivateOverlay:   "/opt/portable/private.json",
			DatabasePath:     "/opt/portable/state.db",
			StdoutLog:        "/opt/portable/logs/controller.stdout",
			StderrLog:        "/opt/portable/logs/controller.stderr",
			ExecutableDigest: strings.Repeat("a", 64),
		},
		Timing: ProcessTiming{
			PollInterval: time.Millisecond,
			TermGrace:    2 * time.Millisecond,
			KillGrace:    2 * time.Millisecond,
			CleanupGrace: 2 * time.Millisecond,
		},
	}
}
