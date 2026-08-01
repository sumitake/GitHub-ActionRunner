package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestUpgradeConstructorAndAuthoritySurface(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		fixture := newUpgradeFixture(t)
		if fixture.upgrade == nil {
			t.Fatal("New() returned nil upgrade")
		}
	})

	t.Run("invalid configuration", func(t *testing.T) {
		t.Parallel()
		tests := map[string]func(*Config){
			"nil admin": func(config *Config) {
				config.Admin = nil
			},
			"nil store": func(config *Config) {
				config.Store = nil
			},
			"nil observer": func(config *Config) {
				config.Observer = nil
			},
			"nil selection": func(config *Config) {
				config.Selection = nil
			},
			"nil candidates": func(config *Config) {
				config.Candidates = nil
			},
			"nil runtime": func(config *Config) {
				config.Runtime = nil
			},
			"nil requests": func(config *Config) {
				config.Requests = nil
			},
			"nil publisher": func(config *Config) {
				config.Publisher = nil
			},
			"zero revision": func(config *Config) {
				config.ConfigurationRevision = 0
			},
			"invalid drain": func(config *Config) {
				config.DrainPolicy = "other"
			},
			"empty canary": func(config *Config) {
				config.CanaryScaleSet = ""
			},
			"zero capacity": func(config *Config) {
				config.EnabledCapacity = 0
			},
			"bad canary digest": func(config *Config) {
				config.CanaryPolicyDigest = "bad"
			},
			"bad enabled digest": func(config *Config) {
				config.EnabledPolicyDigest = "bad"
			},
			"zero operation timeout": func(config *Config) {
				config.OperationTimeout = 0
			},
			"zero directive future": func(config *Config) {
				config.DirectiveMaxFuture = 0
			},
			"nil clock": func(config *Config) {
				config.Now = nil
			},
		}
		for name, mutate := range tests {
			name := name
			mutate := mutate
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				config, _ := validUpgradeConfig(t)
				mutate(&config)
				if _, err := New(config); !errors.Is(
					err,
					ErrInvalidUpgradeConfig,
				) {
					t.Fatalf(
						"New() error = %v, want ErrInvalidUpgradeConfig",
						err,
					)
				}
			})
		}
	})

	t.Run("store probe failure", func(t *testing.T) {
		t.Parallel()
		config, store := validUpgradeConfig(t)
		store.acquireErr = ErrJournalIntegrity
		if _, err := New(config); !errors.Is(
			err,
			ErrInvalidUpgradeConfig,
		) {
			t.Fatalf(
				"New() error = %v, want ErrInvalidUpgradeConfig",
				err,
			)
		}
	})

	t.Run("direct primitives have no authority", func(t *testing.T) {
		t.Parallel()
		fixture := newUpgradeFixture(t)
		candidate, _ := validCandidateAndManifest(t)
		release := validRunnerRelease()
		ctx := context.Background()
		if _, err := fixture.upgrade.StageRunnerCandidate(
			ctx,
			release,
		); !errors.Is(err, ErrUpgradeUnauthorized) {
			t.Fatalf("StageRunnerCandidate() error = %v", err)
		}
		if _, err := fixture.upgrade.QualifyRunnerCandidate(
			ctx,
			candidate,
		); !errors.Is(err, ErrUpgradeUnauthorized) {
			t.Fatalf("QualifyRunnerCandidate() error = %v", err)
		}
		if err := fixture.upgrade.Prepare(
			ctx,
			controller.DrainWait,
		); !errors.Is(err, ErrUpgradeUnauthorized) {
			t.Fatalf("Prepare() error = %v", err)
		}
		if _, err := fixture.upgrade.ProveQuiescent(
			ctx,
		); !errors.Is(err, ErrUpgradeUnauthorized) {
			t.Fatalf("ProveQuiescent() error = %v", err)
		}
		if _, err := fixture.upgrade.ValidateReplacement(
			ctx,
		); !errors.Is(err, ErrUpgradeUnauthorized) {
			t.Fatalf("ValidateReplacement() error = %v", err)
		}
		if fixture.admin.totalCalls() != 0 ||
			fixture.runtime.totalCalls() != 0 {
			t.Fatalf(
				"direct primitive effects admin/runtime = %d/%d",
				fixture.admin.totalCalls(),
				fixture.runtime.totalCalls(),
			)
		}
	})
}

func TestUpgradeObserveCurrentAndUpgradeRequired(t *testing.T) {
	t.Parallel()

	t.Run("current", func(t *testing.T) {
		t.Parallel()
		fixture := newUpgradeFixture(t)
		fixture.observer.release = selectedReleaseForSelection(
			fixture.selection.selection,
			fixture.observer.release,
		)
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("ReconcileRunnerRelease() error = %v", err)
		}
		journal := fixture.store.parsedJournal(t)
		if journal.Phase != JournalCurrent ||
			fixture.publisher.last(t).State != RunnerReleaseCurrent {
			t.Fatalf(
				"journal/status = %s/%s",
				journal.Phase,
				fixture.publisher.last(t).State,
			)
		}
		if fixture.candidates.calls != 0 ||
			fixture.provider.calls != 0 ||
			fixture.admin.totalCalls() != 0 ||
			fixture.runtime.totalCalls() != 0 {
			t.Fatalf(
				"unexpected current effects candidate/provider/admin/runtime = %d/%d/%d/%d",
				fixture.candidates.calls,
				fixture.provider.calls,
				fixture.admin.totalCalls(),
				fixture.runtime.totalCalls(),
			)
		}
		firstSequence := journal.ObservationSequence
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("second current reconcile error = %v", err)
		}
		if second := fixture.store.parsedJournal(t); second.
			ObservationSequence != firstSequence+1 {
			t.Fatalf(
				"current observation sequence = %d, want %d",
				second.ObservationSequence,
				firstSequence+1,
			)
		}
	})

	t.Run("newer release then binds candidate read-only", func(t *testing.T) {
		t.Parallel()
		fixture := newUpgradeFixture(t)
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("ReconcileRunnerRelease() error = %v", err)
		}
		journal := fixture.store.parsedJournal(t)
		if journal.Phase != JournalUpgradeRequired ||
			journal.Candidate != nil {
			t.Fatalf("upgrade journal = %#v", journal)
		}
		status := fixture.publisher.last(t)
		if status.State != RunnerReleaseUpgradeRequired ||
			status.CandidateVersion != nil {
			t.Fatalf("upgrade status = %#v", status)
		}
		if fixture.candidates.calls != 0 ||
			fixture.provider.calls != 0 ||
			fixture.admin.totalCalls() != 0 ||
			fixture.runtime.totalCalls() != 0 {
			t.Fatalf(
				"unexpected upgrade effects candidate/provider/admin/runtime = %d/%d/%d/%d",
				fixture.candidates.calls,
				fixture.provider.calls,
				fixture.admin.totalCalls(),
				fixture.runtime.totalCalls(),
			)
		}
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("candidate bind reconcile error = %v", err)
		}
		bound := fixture.store.parsedJournal(t)
		if bound.Candidate == nil ||
			bound.Candidate.ManifestDigest !=
				fixture.candidates.candidate.ManifestDigest ||
			fixture.candidates.calls != 1 ||
			fixture.provider.calls != 0 {
			t.Fatalf("candidate-bound journal = %#v", bound)
		}
	})

	t.Run("downgrade fails before persistence", func(t *testing.T) {
		t.Parallel()
		fixture := newUpgradeFixture(t)
		fixture.observer.release.Version = "v2.334.0"
		fixture.observer.release.LinuxX64AssetName =
			"actions-runner-linux-x64-2.334.0.tar.gz"
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()
		err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		)
		if !errors.Is(err, ErrUpgradeIntegrity) {
			t.Fatalf(
				"ReconcileRunnerRelease() error = %v, want ErrUpgradeIntegrity",
				err,
			)
		}
		if fixture.store.hasDocument() ||
			fixture.publisher.count() != 0 ||
			fixture.candidates.calls != 0 {
			t.Fatal("downgrade changed durable/public state")
		}
	})
}

func TestUpgradeRejectsConfigurationBindingDriftOnRestart(t *testing.T) {
	t.Parallel()

	config, store := validUpgradeConfig(t)
	upgrade, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := upgrade.ReconcileRunnerRelease(
		ctx,
		&recordingDirectiveProvider{},
	); err != nil {
		t.Fatalf("initial reconcile error = %v", err)
	}
	if !store.hasDocument() {
		t.Fatal("initial reconcile did not persist journal")
	}
	config.CanaryPolicyDigest = testJournalDigest("changed-canary")
	if _, err := New(config); !errors.Is(
		err,
		ErrInvalidUpgradeConfig,
	) {
		t.Fatalf(
			"New(changed binding) error = %v, want ErrInvalidUpgradeConfig",
			err,
		)
	}
}

func TestUpgradeUnavailableDirectiveHoldsWithoutEffects(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("first reconcile error = %v", err)
	}
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("candidate bind error = %v", err)
	}
	before := fixture.store.documentCopy()
	fixture.provider.err = ErrMaintenanceUnavailable
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrMaintenanceUnavailable) {
		t.Fatalf("hold error = %v, want ErrMaintenanceUnavailable", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) {
		t.Fatal("unavailable directive changed journal")
	}
	if fixture.admin.totalCalls() != 0 ||
		fixture.runtime.totalCalls() != 0 {
		t.Fatal("unavailable directive caused an effect")
	}
}

func TestUpgradeWaitHostedDirectiveHoldsWithoutEffects(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceWaitHosted
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for index := 0; index < 2; index++ {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("setup reconcile %d error = %v", index, err)
		}
	}
	before := fixture.store.documentCopy()
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrMaintenanceUnavailable) {
		t.Fatalf("wait-hosted error = %v", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) ||
		fixture.admin.totalCalls() != 0 ||
		fixture.runtime.totalCalls() != 0 {
		t.Fatal("wait-hosted changed journal or caused effect")
	}
}

func TestUpgradeRejectsLiveSelectionDriftBeforeDirective(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceStagePermitted
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for index := 0; index < 2; index++ {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("setup reconcile %d error = %v", index, err)
		}
	}
	before := fixture.store.documentCopy()
	fixture.selection.selection.ManifestDigest =
		testJournalDigest("substituted-selection")
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeIntegrity) {
		t.Fatalf("selection drift error = %v", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) ||
		fixture.provider.calls != 0 ||
		fixture.admin.totalCalls() != 0 {
		t.Fatal("selection drift reached provider or effect")
	}
}

func TestUpgradeControlReplayAndFreshEnrollment(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceStagePermitted
	fixture.provider.candidate = &fixture.candidates.candidate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for index := 0; index < 3; index++ {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("disable setup reconcile %d error = %v", index, err)
		}
	}
	disabled := fixture.store.parsedJournal(t)
	if disabled.Phase != JournalDisabled {
		t.Fatalf("setup phase = %s", disabled.Phase)
	}
	fixture.requests.auto = false
	fixture.requests.request = RunnerMaintenanceStatusRequest{
		Protocol:                runnerMaintenanceStatusProtocol,
		FleetID:                 "portable-example",
		Epoch:                   disabled.Authorization.EnrollmentEpoch,
		SessionID:               "session-example-0001",
		ControlSequence:         disabled.Authorization.ControlSequence,
		SelectedManifestDigest:  disabled.Selected.ManifestDigest,
		CandidateManifestDigest: stringPointer(disabled.Candidate.ManifestDigest),
	}
	before := fixture.store.documentCopy()
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeUnauthorized) {
		t.Fatalf("replayed control error = %v", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) ||
		fixture.runtime.totalCalls() != 0 {
		t.Fatal("replayed control changed state")
	}

	fixture.requests.request.Epoch++
	fixture.requests.request.SessionID = "session-example-0002"
	fixture.requests.request.ControlSequence = 1
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("fresh enrollment stage error = %v", err)
	}
	staged := fixture.store.parsedJournal(t)
	if staged.Phase != JournalStaged ||
		staged.Authorization.EnrollmentEpoch !=
			fixture.requests.request.Epoch {
		t.Fatalf("fresh enrollment journal = %#v", staged)
	}
}

func TestUpgradeFreezesCandidateAcrossNewerCadenceObservation(t *testing.T) {
	t.Parallel()

	fixture := qualifiedUpgradeFixture(t)
	before := fixture.store.parsedJournal(t)
	fixture.observer.release.Version = "v2.337.0"
	fixture.observer.release.LinuxX64AssetName =
		"actions-runner-linux-x64-2.337.0.tar.gz"
	fixture.observer.release.ObservationEvidence =
		testJournalDigest("newer-release")
	fixture.provider.phase = MaintenanceReplacePermitted
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("prepare with newer cadence error = %v", err)
	}
	after := fixture.store.parsedJournal(t)
	if after.Phase != JournalPrepared ||
		after.Observed.Version != before.Observed.Version ||
		after.Candidate.Version != before.Candidate.Version {
		t.Fatalf("newer cadence substituted frozen tuple: %#v", after)
	}
}

func TestUpgradeLeaseCloseFailureTakesPrecedence(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.store.leaseCloseErr = ErrJournalIntegrity
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeIntegrity) {
		t.Fatalf("lease close error = %v, want ErrUpgradeIntegrity", err)
	}
}

func TestUpgradeLeaseCloseFailurePreservesPriorTypedError(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.publisher.err = ErrUpgradeUnavailable
	fixture.store.leaseCloseErr = ErrJournalIntegrity
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeIntegrity) ||
		!errors.Is(err, ErrUpgradeUnavailable) {
		t.Fatalf(
			"combined publish/close error = %v, want integrity and unavailable",
			err,
		)
	}
	if !fixture.store.hasDocument() {
		t.Fatal("publish failure did not retain the created journal")
	}
}

func TestUpgradeRepublishesDurableStatusBeforeNextEffectAfterRestart(
	t *testing.T,
) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceStagePermitted
	fixture.provider.candidate = &fixture.candidates.candidate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for index := 0; index < 2; index++ {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("setup reconcile %d error = %v", index, err)
		}
	}
	bound := fixture.store.parsedJournal(t)
	fixture.publisher.failSequence =
		bound.ObservationSequence + 2
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeUnavailable) {
		t.Fatalf("failed publication error = %v", err)
	}
	disabled := fixture.store.parsedJournal(t)
	if disabled.Phase != JournalDisabled ||
		disabled.ObservationSequence != fixture.publisher.failSequence ||
		fixture.runtime.totalCalls() != 0 {
		t.Fatalf("durable unpublished journal = %#v", disabled)
	}
	if got := fixture.publisher.sequenceCount(
		disabled.ObservationSequence,
	); got != 1 {
		t.Fatalf("initial publication attempts = %d, want 1", got)
	}

	fixture.publisher.failSequence = 0
	restarted, restartErr := New(fixture.config)
	if restartErr != nil {
		t.Fatalf("restart New() error = %v", restartErr)
	}
	fixture.upgrade = restarted
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("restart reconcile error = %v", err)
	}
	if got := fixture.publisher.sequenceCount(
		disabled.ObservationSequence,
	); got != 2 {
		t.Fatalf("durable status publication attempts = %d, want 2", got)
	}
	if staged := fixture.store.parsedJournal(t); staged.Phase != JournalStaged {
		t.Fatalf("restart phase = %s, want %s", staged.Phase, JournalStaged)
	}
	if fixture.runtime.stageCalls != 1 {
		t.Fatalf("Stage() calls = %d, want 1", fixture.runtime.stageCalls)
	}
}

func TestUpgradeStageAndQualifyOnePhasePerCall(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceStagePermitted
	fixture.provider.candidate = &fixture.candidates.candidate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("observe error = %v", err)
	}
	if got := fixture.store.parsedJournal(t).Phase; got !=
		JournalUpgradeRequired {
		t.Fatalf("after observe phase = %s", got)
	}

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("candidate bind error = %v", err)
	}
	if got := fixture.store.parsedJournal(t); got.Candidate == nil ||
		got.Phase != JournalUpgradeRequired {
		t.Fatalf("after candidate bind journal = %#v", got)
	}

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("disable error = %v", err)
	}
	disabled := fixture.store.parsedJournal(t)
	if disabled.Phase != JournalDisabled ||
		disabled.Policy == nil ||
		disabled.Policy.Mode != "disabled" {
		t.Fatalf("disabled journal = %#v", disabled)
	}
	if fixture.admin.probes != 1 ||
		fixture.admin.sets != 1 ||
		fixture.runtime.totalCalls() != 0 {
		t.Fatalf(
			"disable calls probe/set/runtime = %d/%d/%d",
			fixture.admin.probes,
			fixture.admin.sets,
			fixture.runtime.totalCalls(),
		)
	}

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("stage error = %v", err)
	}
	staged := fixture.store.parsedJournal(t)
	if staged.Phase != JournalStaged ||
		staged.Stage == nil ||
		staged.Stage.ManifestDigest !=
			fixture.candidates.candidate.ManifestDigest {
		t.Fatalf("staged journal = %#v", staged)
	}
	if fixture.runtime.stageCalls != 1 ||
		fixture.runtime.inspectStageCalls != 2 ||
		fixture.runtime.qualifyCalls != 0 {
		t.Fatalf(
			"stage calls stage/inspect/qualify = %d/%d/%d",
			fixture.runtime.stageCalls,
			fixture.runtime.inspectStageCalls,
			fixture.runtime.qualifyCalls,
		)
	}

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("qualify error = %v", err)
	}
	qualified := fixture.store.parsedJournal(t)
	if qualified.Phase != JournalCandidateQualified ||
		qualified.Qualified == nil ||
		qualified.Qualified.ManifestDigest !=
			fixture.candidates.candidate.ManifestDigest {
		t.Fatalf("qualified journal = %#v", qualified)
	}
	if fixture.runtime.qualifyCalls != 1 ||
		fixture.provider.calls != 3 ||
		fixture.requests.calls != 3 {
		t.Fatalf(
			"qualify calls runtime/provider/requests = %d/%d/%d",
			fixture.runtime.qualifyCalls,
			fixture.provider.calls,
			fixture.requests.calls,
		)
	}
	if fixture.publisher.last(t).State !=
		RunnerReleaseCandidateQualified {
		t.Fatalf(
			"qualified status = %#v",
			fixture.publisher.last(t),
		)
	}
}

func TestUpgradeDisableApplyingResumesWithFreshDirective(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceStagePermitted
	fixture.provider.candidate = &fixture.candidates.candidate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("observe error = %v", err)
	}
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("candidate bind error = %v", err)
	}
	fixture.admin.setErr = ErrUpgradeUnavailable
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeUnavailable) {
		t.Fatalf("failed disable error = %v", err)
	}
	applying := fixture.store.parsedJournal(t)
	if applying.Phase != JournalDisableApplying ||
		applying.Authorization == nil {
		t.Fatalf("applying journal = %#v", applying)
	}
	firstControl := applying.Authorization.ControlSequence

	fixture.admin.setErr = nil
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("resume disable error = %v", err)
	}
	disabled := fixture.store.parsedJournal(t)
	if disabled.Phase != JournalDisabled ||
		disabled.Authorization.ControlSequence <= firstControl {
		t.Fatalf("resumed disabled journal = %#v", disabled)
	}
	if fixture.admin.sets != 2 {
		t.Fatalf("SetAcquisition() calls = %d, want 2", fixture.admin.sets)
	}
}

func TestUpgradeRejectsWrongDirectiveBeforeEffect(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceCanaryPermitted
	fixture.provider.candidate = &fixture.candidates.candidate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("observe error = %v", err)
	}
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("candidate bind error = %v", err)
	}
	before := fixture.store.documentCopy()
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeUnauthorized) {
		t.Fatalf("wrong directive error = %v", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) ||
		fixture.admin.totalCalls() != 0 ||
		fixture.runtime.totalCalls() != 0 {
		t.Fatal("wrong directive changed journal or caused effect")
	}
}

func TestUpgradePermanentQualificationRejectionIsTerminal(t *testing.T) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceStagePermitted
	fixture.provider.candidate = &fixture.candidates.candidate
	fixture.runtime.qualifyErr = ErrUpgradeRejected
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for index := 0; index < 4; index++ {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("setup reconcile %d error = %v", index, err)
		}
	}
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("rejection reconcile error = %v", err)
	}
	rejected := fixture.store.parsedJournal(t)
	if rejected.Phase != JournalCandidateRejected ||
		rejected.Rejection == nil ||
		rejected.Authorization != nil ||
		rejected.Policy != nil {
		t.Fatalf("rejected journal = %#v", rejected)
	}
	if fixture.publisher.last(t).State !=
		RunnerReleaseCandidateRejected {
		t.Fatalf(
			"rejected status = %#v",
			fixture.publisher.last(t),
		)
	}

	before := fixture.store.documentCopy()
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeRejected) {
		t.Fatalf("identical rejected tuple error = %v", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) {
		t.Fatal("identical rejected tuple changed journal")
	}

	changed := fixture.candidates.candidate
	changed.ManifestDigest = testJournalDigest("changed-candidate")
	fixture.candidates.candidate = changed
	fixture.runtime.candidate = changed
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("different candidate reentry error = %v", err)
	}
	reentered := fixture.store.parsedJournal(t)
	if reentered.Phase != JournalUpgradeRequired ||
		reentered.Candidate == nil ||
		reentered.Candidate.ManifestDigest != changed.ManifestDigest {
		t.Fatalf("reentered journal = %#v", reentered)
	}
}

func TestUpgradeReplacementCanaryEnableAndComplete(t *testing.T) {
	t.Parallel()

	fixture := qualifiedUpgradeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fixture.provider.phase = MaintenanceReplacePermitted

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("prepare error = %v", err)
	}
	prepared := fixture.store.parsedJournal(t)
	if prepared.Phase != JournalPrepared ||
		fixture.admin.drains != 1 ||
		prepared.Policy == nil ||
		prepared.Policy.Mode != "disabled" {
		t.Fatalf(
			"prepared journal/drains = %#v/%d",
			prepared,
			fixture.admin.drains,
		)
	}

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("quiescence error = %v", err)
	}
	quiescent := fixture.store.parsedJournal(t)
	if quiescent.Phase != JournalQuiescent ||
		quiescent.Quiescence == nil ||
		fixture.runtime.quiescenceCalls != 1 {
		t.Fatalf("quiescent journal = %#v", quiescent)
	}

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("replacement validation error = %v", err)
	}
	replacement := fixture.store.parsedJournal(t)
	if replacement.Phase != JournalReplacementValidated ||
		replacement.Replacement == nil ||
		fixture.runtime.replacementCalls != 1 {
		t.Fatalf("replacement journal = %#v", replacement)
	}

	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("select error = %v", err)
	}
	selected := fixture.store.parsedJournal(t)
	if selected.Phase != JournalSelectedDisabled ||
		selected.Selected.Version !=
			fixture.candidates.candidate.Version ||
		selected.Selected.RollbackVersion != "v2.335.1" ||
		fixture.runtime.selectCalls != 1 {
		t.Fatalf("selected journal = %#v", selected)
	}
	selectedStatus := fixture.publisher.last(t)
	if selectedStatus.State != RunnerReleaseCurrent ||
		selectedStatus.CandidateVersion != nil {
		t.Fatalf("selected public status = %#v", selectedStatus)
	}

	fixture.provider.phase = MaintenanceCanaryPermitted
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("canary error = %v", err)
	}
	canary := fixture.store.parsedJournal(t)
	if canary.Phase != JournalCanaryActive ||
		canary.Policy == nil ||
		canary.Policy.Mode != "canary-only" ||
		canary.Policy.Capacity != 1 ||
		fixture.admin.lastSet.EligibleScaleSet !=
			"portable-canary" {
		t.Fatalf("canary journal/change = %#v/%#v", canary, fixture.admin.lastSet)
	}

	fixture.provider.phase = MaintenanceEnablePermitted
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("enable error = %v", err)
	}
	enabled := fixture.store.parsedJournal(t)
	if enabled.Phase != JournalEnabled ||
		enabled.Policy == nil ||
		enabled.Policy.Mode != "enabled" ||
		enabled.Policy.Capacity != 4 {
		t.Fatalf("enabled journal = %#v", enabled)
	}

	effectsBeforeComplete := fixture.admin.totalCalls() +
		fixture.runtime.totalCalls()
	fixture.provider.phase = MaintenanceComplete
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("complete error = %v", err)
	}
	complete := fixture.store.parsedJournal(t)
	if complete.Phase != JournalComplete ||
		fixture.admin.totalCalls()+fixture.runtime.totalCalls() !=
			effectsBeforeComplete {
		t.Fatalf("complete journal/effects = %#v/%d", complete, effectsBeforeComplete)
	}

	providerCalls := fixture.provider.calls
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("terminal reset error = %v", err)
	}
	current := fixture.store.parsedJournal(t)
	if current.Phase != JournalCurrent ||
		current.Candidate != nil ||
		current.Authorization != nil ||
		current.Selected.Version !=
			fixture.candidates.candidate.Version ||
		fixture.provider.calls != providerCalls {
		t.Fatalf("fresh current journal = %#v", current)
	}
}

func TestUpgradeReplacementFailureRemainsApplying(t *testing.T) {
	t.Parallel()

	fixture := qualifiedUpgradeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fixture.provider.phase = MaintenanceReplacePermitted
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("prepare error = %v", err)
	}
	fixture.runtime.quiescenceErr = ErrUpgradeUnavailable
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeUnavailable) {
		t.Fatalf("quiescence failure error = %v", err)
	}
	applying := fixture.store.parsedJournal(t)
	if applying.Phase != JournalQuiescenceProving {
		t.Fatalf("failure phase = %s", applying.Phase)
	}
	firstControl := applying.Authorization.ControlSequence
	fixture.runtime.quiescenceErr = nil
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("quiescence resume error = %v", err)
	}
	quiescent := fixture.store.parsedJournal(t)
	if quiescent.Phase != JournalQuiescent ||
		quiescent.Authorization.ControlSequence <= firstControl {
		t.Fatalf("resumed quiescent journal = %#v", quiescent)
	}
}

func TestUpgradeSelectApplyingClassifiesCompletedEffectAfterRestart(
	t *testing.T,
) {
	t.Parallel()

	fixture := qualifiedUpgradeFixture(t)
	fixture.provider.phase = MaintenanceReplacePermitted
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, want := range []JournalPhase{
		JournalPrepared,
		JournalQuiescent,
		JournalReplacementValidated,
	} {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("setup %s error = %v", want, err)
		}
		if got := fixture.store.parsedJournal(t).Phase; got != want {
			t.Fatalf("setup phase = %s, want %s", got, want)
		}
	}
	fixture.runtime.selectErr = ErrUpgradeUnavailable
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeUnavailable) {
		t.Fatalf("select failure error = %v", err)
	}
	applying := fixture.store.parsedJournal(t)
	if applying.Phase != JournalSelectApplying {
		t.Fatalf("failure phase = %s", applying.Phase)
	}
	firstControl := applying.Authorization.ControlSequence
	if fixture.runtime.selectCalls != 1 {
		t.Fatalf("failed Select() calls = %d, want 1", fixture.runtime.selectCalls)
	}

	fixture.runtime.selectErr = nil
	fixture.runtime.selected = true
	fixture.selection.selection = fixture.runtime.selection
	restarted, restartErr := New(fixture.config)
	if restartErr != nil {
		t.Fatalf("restart New() error = %v", restartErr)
	}
	fixture.upgrade = restarted
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("select resume error = %v", err)
	}
	selected := fixture.store.parsedJournal(t)
	if selected.Phase != JournalSelectedDisabled ||
		selected.Authorization.ControlSequence <= firstControl {
		t.Fatalf("resumed selection journal = %#v", selected)
	}
	if fixture.runtime.selectCalls != 1 {
		t.Fatalf(
			"completed effect repeated Select(): calls = %d",
			fixture.runtime.selectCalls,
		)
	}
}

func TestUpgradePolicyReadbackMismatchRemainsApplyingAndResumes(
	t *testing.T,
) {
	t.Parallel()

	fixture := qualifiedUpgradeFixture(t)
	fixture.provider.phase = MaintenanceReplacePermitted
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, want := range []JournalPhase{
		JournalPrepared,
		JournalQuiescent,
		JournalReplacementValidated,
		JournalSelectedDisabled,
	} {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("setup %s error = %v", want, err)
		}
		if got := fixture.store.parsedJournal(t).Phase; got != want {
			t.Fatalf("setup phase = %s, want %s", got, want)
		}
	}
	fixture.provider.phase = MaintenanceCanaryPermitted
	mismatch := controller.PolicyStatus{
		Mode:     controller.AcquisitionCanaryOnly,
		Epoch:    fixture.admin.status.Epoch + 1,
		Digest:   testJournalDigest("wrong-canary-readback"),
		Capacity: 1,
	}
	fixture.admin.setResult = &mismatch
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeIntegrity) {
		t.Fatalf("readback mismatch error = %v", err)
	}
	applying := fixture.store.parsedJournal(t)
	if applying.Phase != JournalCanaryApplying {
		t.Fatalf("readback mismatch phase = %s", applying.Phase)
	}
	setCalls := fixture.admin.sets

	fixture.admin.setResult = nil
	restarted, restartErr := New(fixture.config)
	if restartErr != nil {
		t.Fatalf("restart New() error = %v", restartErr)
	}
	fixture.upgrade = restarted
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("canary resume error = %v", err)
	}
	if canary := fixture.store.parsedJournal(t); canary.Phase !=
		JournalCanaryActive {
		t.Fatalf("canary resume phase = %s", canary.Phase)
	}
	if fixture.admin.sets != setCalls {
		t.Fatalf(
			"completed canary repeated SetAcquisition(): %d -> %d",
			setCalls,
			fixture.admin.sets,
		)
	}
}

func TestUpgradeRejectsSameVersionReleaseIdentityDrift(t *testing.T) {
	t.Parallel()

	fixture := qualifiedUpgradeFixture(t)
	before := fixture.store.documentCopy()
	effects := fixture.admin.totalCalls() + fixture.runtime.totalCalls()
	fixture.observer.release.ObservationEvidence =
		testJournalDigest("same-version-substitution")
	fixture.provider.phase = MaintenanceReplacePermitted
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeIntegrity) {
		t.Fatalf("identity drift error = %v", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) ||
		fixture.admin.totalCalls()+fixture.runtime.totalCalls() != effects {
		t.Fatal("same-version identity drift changed state or caused effect")
	}
}

func TestUpgradeRejectsSameVersionReleaseIdentityDriftFromCurrent(
	t *testing.T,
) {
	t.Parallel()

	fixture := newUpgradeFixture(t)
	fixture.observer.release = selectedReleaseForSelection(
		fixture.selection.selection,
		fixture.observer.release,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fixture.upgrade.ReconcileRunnerRelease(
		ctx,
		fixture.provider,
	); err != nil {
		t.Fatalf("current setup reconcile error = %v", err)
	}
	before := fixture.store.documentCopy()
	effects := fixture.admin.totalCalls() + fixture.runtime.totalCalls()
	fixture.observer.release.ObservationEvidence =
		testJournalDigest("current-same-version-substitution")
	err := fixture.upgrade.ReconcileRunnerRelease(ctx, fixture.provider)
	if !errors.Is(err, ErrUpgradeIntegrity) {
		t.Fatalf("current identity drift error = %v", err)
	}
	if !bytes.Equal(before, fixture.store.documentCopy()) ||
		fixture.admin.totalCalls()+fixture.runtime.totalCalls() != effects {
		t.Fatal("current same-version identity drift changed state or caused effect")
	}
}

func TestUpgradeEveryApplyingPhaseResumesAfterRestart(t *testing.T) {
	t.Parallel()

	type recoveryCase struct {
		predecessor JournalPhase
		applying    JournalPhase
		proven      JournalPhase
		maintenance RunnerMaintenancePhase
		fail        func(*upgradeFixture)
		complete    func(*upgradeFixture)
		effectCount func(*upgradeFixture) int
		resumeDelta int
	}
	cases := map[string]recoveryCase{
		"disable": {
			predecessor: JournalUpgradeRequired,
			applying:    JournalDisableApplying,
			proven:      JournalDisabled,
			maintenance: MaintenanceStagePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.admin.setErr = ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.admin.setErr = nil
				fixture.admin.status.Epoch++
				fixture.admin.status.Mode =
					controller.AcquisitionDisabled
				fixture.admin.status.Capacity = 0
				fixture.admin.status.Digest =
					testJournalDigest("disabled-after-crash")
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.admin.sets
			},
		},
		"stage": {
			predecessor: JournalDisabled,
			applying:    JournalStageApplying,
			proven:      JournalStaged,
			maintenance: MaintenanceStagePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.runtime.stageErr = ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.runtime.stageErr = nil
				fixture.runtime.staged = true
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.runtime.stageCalls
			},
		},
		"qualify": {
			predecessor: JournalStaged,
			applying:    JournalQualifyApplying,
			proven:      JournalCandidateQualified,
			maintenance: MaintenanceStagePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.runtime.qualifyErr = ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.runtime.qualifyErr = nil
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.runtime.qualifyCalls
			},
			resumeDelta: 1,
		},
		"prepare": {
			predecessor: JournalCandidateQualified,
			applying:    JournalPrepareApplying,
			proven:      JournalPrepared,
			maintenance: MaintenanceReplacePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.admin.drainErr = ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.admin.drainErr = nil
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.admin.drains
			},
			resumeDelta: 1,
		},
		"quiescence": {
			predecessor: JournalPrepared,
			applying:    JournalQuiescenceProving,
			proven:      JournalQuiescent,
			maintenance: MaintenanceReplacePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.runtime.quiescenceErr =
					ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.runtime.quiescenceErr = nil
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.runtime.quiescenceCalls
			},
			resumeDelta: 1,
		},
		"replacement": {
			predecessor: JournalQuiescent,
			applying:    JournalReplacementValidating,
			proven:      JournalReplacementValidated,
			maintenance: MaintenanceReplacePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.runtime.replacementErr =
					ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.runtime.replacementErr = nil
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.runtime.replacementCalls
			},
			resumeDelta: 1,
		},
		"select": {
			predecessor: JournalReplacementValidated,
			applying:    JournalSelectApplying,
			proven:      JournalSelectedDisabled,
			maintenance: MaintenanceReplacePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.runtime.selectErr = ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.runtime.selectErr = nil
				fixture.runtime.selected = true
				fixture.selection.selection =
					fixture.runtime.selection
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.runtime.selectCalls
			},
		},
		"canary": {
			predecessor: JournalSelectedDisabled,
			applying:    JournalCanaryApplying,
			proven:      JournalCanaryActive,
			maintenance: MaintenanceCanaryPermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.admin.setErr = ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.admin.setErr = nil
				fixture.admin.status.Epoch++
				fixture.admin.status.Mode =
					controller.AcquisitionCanaryOnly
				fixture.admin.status.Capacity = 1
				fixture.admin.status.Digest =
					fixture.config.CanaryPolicyDigest
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.admin.sets
			},
		},
		"enable": {
			predecessor: JournalCanaryActive,
			applying:    JournalEnableApplying,
			proven:      JournalEnabled,
			maintenance: MaintenanceEnablePermitted,
			fail: func(fixture *upgradeFixture) {
				fixture.admin.setErr = ErrUpgradeUnavailable
			},
			complete: func(fixture *upgradeFixture) {
				fixture.admin.setErr = nil
				fixture.admin.status.Epoch++
				fixture.admin.status.Mode =
					controller.AcquisitionEnabled
				fixture.admin.status.Capacity =
					int(fixture.config.EnabledCapacity)
				fixture.admin.status.Digest =
					fixture.config.EnabledPolicyDigest
			},
			effectCount: func(fixture *upgradeFixture) int {
				return fixture.admin.sets
			},
		},
	}
	for name, testCase := range cases {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newUpgradeFixture(t)
			advanceUpgradeToPhase(t, fixture, testCase.predecessor)
			fixture.provider.phase = testCase.maintenance
			testCase.fail(fixture)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				10*time.Second,
			)
			defer cancel()
			err := fixture.upgrade.ReconcileRunnerRelease(
				ctx,
				fixture.provider,
			)
			if !errors.Is(err, ErrUpgradeUnavailable) {
				t.Fatalf("effect failure error = %v", err)
			}
			applying := fixture.store.parsedJournal(t)
			if applying.Phase != testCase.applying {
				t.Fatalf(
					"failure phase = %s, want %s",
					applying.Phase,
					testCase.applying,
				)
			}
			firstControl := applying.Authorization.ControlSequence
			testCase.complete(fixture)
			before := testCase.effectCount(fixture)
			restarted, restartErr := New(fixture.config)
			if restartErr != nil {
				t.Fatalf("restart New() error = %v", restartErr)
			}
			fixture.upgrade = restarted
			if err := fixture.upgrade.ReconcileRunnerRelease(
				ctx,
				fixture.provider,
			); err != nil {
				t.Fatalf("resume error = %v", err)
			}
			proven := fixture.store.parsedJournal(t)
			if proven.Phase != testCase.proven ||
				proven.Authorization.ControlSequence <= firstControl {
				t.Fatalf("resumed journal = %#v", proven)
			}
			if after := testCase.effectCount(fixture); after !=
				before+testCase.resumeDelta {
				t.Fatalf(
					"effect count = %d, want %d",
					after,
					before+testCase.resumeDelta,
				)
			}
		})
	}
}

func advanceUpgradeToPhase(
	t *testing.T,
	fixture *upgradeFixture,
	target JournalPhase,
) {
	t.Helper()
	fixture.provider.auto = true
	fixture.provider.candidate = &fixture.candidates.candidate
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for step := 0; step < 24; step++ {
		if fixture.store.hasDocument() {
			journal := fixture.store.parsedJournal(t)
			phase := journal.Phase
			if phase == target &&
				(target != JournalUpgradeRequired ||
					journal.Candidate != nil) {
				return
			}
			switch phase {
			case JournalUpgradeRequired, JournalDisabled, JournalStaged:
				fixture.provider.phase = MaintenanceStagePermitted
			case JournalCandidateQualified, JournalPrepared,
				JournalQuiescent, JournalReplacementValidated:
				fixture.provider.phase = MaintenanceReplacePermitted
			case JournalSelectedDisabled:
				fixture.provider.phase = MaintenanceCanaryPermitted
			case JournalCanaryActive:
				fixture.provider.phase = MaintenanceEnablePermitted
			default:
				t.Fatalf("cannot advance from phase %s", phase)
			}
		} else {
			fixture.provider.phase = MaintenanceStagePermitted
		}
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("advance step %d error = %v", step, err)
		}
	}
	t.Fatalf("did not reach phase %s", target)
}

func qualifiedUpgradeFixture(t *testing.T) *upgradeFixture {
	t.Helper()
	fixture := newUpgradeFixture(t)
	fixture.provider.auto = true
	fixture.provider.phase = MaintenanceStagePermitted
	fixture.provider.candidate = &fixture.candidates.candidate
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for index := 0; index < 5; index++ {
		if err := fixture.upgrade.ReconcileRunnerRelease(
			ctx,
			fixture.provider,
		); err != nil {
			t.Fatalf("qualify setup reconcile %d error = %v", index, err)
		}
	}
	if phase := fixture.store.parsedJournal(t).Phase; phase !=
		JournalCandidateQualified {
		t.Fatalf("qualified setup phase = %s", phase)
	}
	return fixture
}

type upgradeFixture struct {
	upgrade    *Upgrade
	config     Config
	store      *memoryJournalStore
	admin      *recordingUpgradeAdmin
	observer   *recordingReleaseObserver
	selection  *fixedSelectionSource
	candidates *recordingCandidateSource
	runtime    *recordingCandidateRuntime
	requests   *recordingMaintenanceRequestSource
	publisher  *recordingReleasePublisher
	provider   *recordingDirectiveProvider
}

func newUpgradeFixture(t *testing.T) *upgradeFixture {
	t.Helper()
	config, store := validUpgradeConfig(t)
	upgrade, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return &upgradeFixture{
		upgrade:    upgrade,
		config:     config,
		store:      store,
		admin:      config.Admin.(*recordingUpgradeAdmin),
		observer:   config.Observer.(*recordingReleaseObserver),
		selection:  config.Selection.(*fixedSelectionSource),
		candidates: config.Candidates.(*recordingCandidateSource),
		runtime:    config.Runtime.(*recordingCandidateRuntime),
		requests:   config.Requests.(*recordingMaintenanceRequestSource),
		publisher:  config.Publisher.(*recordingReleasePublisher),
		provider: &recordingDirectiveProvider{
			configRevision: config.ConfigurationRevision,
			canaryDigest:   config.CanaryPolicyDigest,
			enabledDigest:  config.EnabledPolicyDigest,
		},
	}
}

func validUpgradeConfig(
	t *testing.T,
) (Config, *memoryJournalStore) {
	t.Helper()
	candidate, _ := validCandidateAndManifest(t)
	selection := Selection{
		Version:                "v2.335.1",
		ManifestDigest:         testJournalDigest("selected-manifest"),
		ImageDigest:            "sha256:" + testJournalDigest("selected-image"),
		RollbackVersion:        "v2.334.0",
		RollbackManifestDigest: testJournalDigest("rollback-manifest"),
		RollbackImageDigest: "sha256:" +
			testJournalDigest("rollback-image"),
		ObservedAt: fixedModelTime(),
	}
	store := &memoryJournalStore{}
	clock := &testUpgradeClock{now: fixedDirectiveTime()}
	admin := &recordingUpgradeAdmin{
		status: controller.PolicyStatus{
			Mode:     controller.AcquisitionEnabled,
			Epoch:    10,
			Digest:   testJournalDigest("enabled-before"),
			Capacity: 4,
		},
		enabledCapacity: 4,
	}
	runtime := &recordingCandidateRuntime{
		candidate: candidate,
		stage: StageObservation{
			Version:               candidate.Version,
			ReleaseEvidenceDigest: candidate.ReleaseEvidenceDigest,
			ManifestDigest:        candidate.ManifestDigest,
			ImageDigest:           candidate.ImageDigest,
			Complete:              true,
			EvidenceDigest:        testJournalDigest("stage"),
			ObservedAt:            fixedModelTime(),
		},
	}
	_, manifest := validCandidateAndManifest(t)
	runtime.report = validCompatibilityReport(t, candidate, manifest)
	runtime.replacement = runtime.report
	runtime.quiescence = Quiescence{
		RetainedLedgers: true,
		EvidenceDigest:  testJournalDigest("quiescence"),
		ObservedAt:      fixedModelTime(),
	}
	selectionSource := &fixedSelectionSource{selection: selection}
	runtime.selection = Selection{
		Version:                candidate.Version,
		ManifestDigest:         candidate.ManifestDigest,
		ImageDigest:            candidate.ImageDigest,
		RollbackVersion:        selection.Version,
		RollbackManifestDigest: selection.ManifestDigest,
		RollbackImageDigest:    selection.ImageDigest,
		ObservedAt:             fixedModelTime(),
	}
	runtime.selectionSink = selectionSource
	return Config{
		Admin:                 admin,
		Store:                 store,
		Observer:              &recordingReleaseObserver{release: validRunnerRelease()},
		Selection:             selectionSource,
		Candidates:            &recordingCandidateSource{candidate: candidate},
		Runtime:               runtime,
		Requests:              &recordingMaintenanceRequestSource{auto: true},
		Publisher:             &recordingReleasePublisher{},
		ConfigurationRevision: 19,
		DrainPolicy:           controller.DrainWait,
		CanaryScaleSet:        "portable-canary",
		EnabledCapacity:       4,
		CanaryPolicyDigest:    testJournalDigest("policy-canary-only"),
		EnabledPolicyDigest:   testJournalDigest("policy-enabled"),
		OperationTimeout:      time.Second,
		DirectiveMaxFuture:    2 * time.Hour,
		Now:                   clock.next,
	}, store
}

type testUpgradeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testUpgradeClock) next() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

type memoryJournalStore struct {
	mu            sync.Mutex
	document      []byte
	acquireErr    error
	leaseCloseErr error
}

func (store *memoryJournalStore) Acquire(
	context.Context,
) (JournalLease, error) {
	if store.acquireErr != nil {
		return nil, store.acquireErr
	}
	store.mu.Lock()
	return &memoryJournalLease{store: store}, nil
}

func (store *memoryJournalStore) Close() error { return nil }

func (store *memoryJournalStore) documentCopy() []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]byte(nil), store.document...)
}

func (store *memoryJournalStore) hasDocument() bool {
	return len(store.documentCopy()) != 0
}

func (store *memoryJournalStore) parsedJournal(t *testing.T) Journal {
	t.Helper()
	document := store.documentCopy()
	journal, _, err := ParseJournal(document, 1<<20)
	if err != nil {
		t.Fatalf("ParseJournal() error = %v", err)
	}
	return journal
}

type memoryJournalLease struct {
	store  *memoryJournalStore
	closed bool
}

func (lease *memoryJournalLease) Read() ([]byte, error) {
	if lease.closed {
		return nil, ErrJournalStoreClosed
	}
	if len(lease.store.document) == 0 {
		return nil, ErrJournalAbsent
	}
	return append([]byte(nil), lease.store.document...), nil
}

func (lease *memoryJournalLease) Create(document []byte) error {
	if lease.closed {
		return ErrJournalStoreClosed
	}
	if len(lease.store.document) != 0 {
		return ErrJournalConflict
	}
	lease.store.document = append([]byte(nil), document...)
	return nil
}

func (lease *memoryJournalLease) Replace(
	expected, replacement []byte,
) error {
	if lease.closed {
		return ErrJournalStoreClosed
	}
	if !bytes.Equal(lease.store.document, expected) {
		return ErrJournalConflict
	}
	lease.store.document = append([]byte(nil), replacement...)
	return nil
}

func (lease *memoryJournalLease) Close() error {
	if lease.closed {
		return nil
	}
	lease.closed = true
	lease.store.mu.Unlock()
	return lease.store.leaseCloseErr
}

type recordingUpgradeAdmin struct {
	mu              sync.Mutex
	probes          int
	sets            int
	drains          int
	status          controller.PolicyStatus
	probeErr        error
	setErr          error
	drainErr        error
	lastSet         controller.AcquisitionChange
	drainPolicy     controller.DrainPolicy
	enabledCapacity int
	setResult       *controller.PolicyStatus
}

func (admin *recordingUpgradeAdmin) Probe(
	context.Context,
) (controller.PolicyStatus, error) {
	admin.mu.Lock()
	defer admin.mu.Unlock()
	admin.probes++
	return admin.status, admin.probeErr
}

func (admin *recordingUpgradeAdmin) ReconcileOnce(
	context.Context,
) (controller.CycleReceipt, error) {
	return controller.CycleReceipt{}, errors.New("not used")
}

func (admin *recordingUpgradeAdmin) Drain(
	_ context.Context,
	policy controller.DrainPolicy,
) error {
	admin.mu.Lock()
	defer admin.mu.Unlock()
	admin.drains++
	admin.drainPolicy = policy
	if admin.drainErr != nil {
		return admin.drainErr
	}
	admin.status.Epoch++
	admin.status.Mode = controller.AcquisitionDisabled
	admin.status.Capacity = 0
	admin.status.Digest = testJournalDigest("policy-disabled-drained")
	return nil
}

func (admin *recordingUpgradeAdmin) SetAcquisition(
	_ context.Context,
	change controller.AcquisitionChange,
) (controller.PolicyStatus, error) {
	admin.mu.Lock()
	defer admin.mu.Unlock()
	admin.sets++
	admin.lastSet = change
	if admin.setErr != nil {
		return controller.PolicyStatus{}, admin.setErr
	}
	admin.status.Epoch++
	admin.status.Mode = change.Set
	admin.status.Digest = testJournalDigest(
		"policy-" + string(change.Set),
	)
	switch change.Set {
	case controller.AcquisitionDisabled:
		admin.status.Capacity = 0
	case controller.AcquisitionCanaryOnly:
		admin.status.Capacity = 1
	case controller.AcquisitionEnabled:
		admin.status.Capacity = admin.enabledCapacity
	}
	if admin.setResult != nil {
		return *admin.setResult, nil
	}
	return admin.status, nil
}

func (admin *recordingUpgradeAdmin) totalCalls() int {
	admin.mu.Lock()
	defer admin.mu.Unlock()
	return admin.probes + admin.sets + admin.drains
}

type recordingReleaseObserver struct {
	release RunnerRelease
	err     error
	calls   int
}

func (observer *recordingReleaseObserver) Observe(
	context.Context,
) (RunnerRelease, error) {
	observer.calls++
	return observer.release, observer.err
}

type fixedSelectionSource struct {
	selection Selection
	err       error
	calls     int
}

func (source *fixedSelectionSource) CurrentSelection(
	context.Context,
) (Selection, error) {
	source.calls++
	return source.selection, source.err
}

type recordingCandidateSource struct {
	candidate Candidate
	err       error
	calls     int
}

func (source *recordingCandidateSource) ObserveCandidate(
	context.Context,
	RunnerRelease,
) (Candidate, error) {
	source.calls++
	return source.candidate, source.err
}

type recordingCandidateRuntime struct {
	mu sync.Mutex

	inspectStageCalls     int
	stageCalls            int
	qualifyCalls          int
	inspectSelectionCalls int
	quiescenceCalls       int
	replacementCalls      int
	selectCalls           int
	candidate             Candidate
	stage                 StageObservation
	report                CompatibilityReport
	staged                bool
	inspectStageErr       error
	stageErr              error
	qualifyErr            error
	quiescence            Quiescence
	quiescenceErr         error
	replacement           CompatibilityReport
	replacementErr        error
	selection             Selection
	selectionErr          error
	selectionSink         *fixedSelectionSource
	selected              bool
	selectErr             error
}

func (runtime *recordingCandidateRuntime) InspectStage(
	context.Context,
	Candidate,
) (StageObservation, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.inspectStageCalls++
	if runtime.inspectStageErr != nil {
		return StageObservation{}, runtime.inspectStageErr
	}
	if !runtime.staged {
		return StageObservation{}, ErrUpgradeAbsent
	}
	return runtime.stage, nil
}

func (runtime *recordingCandidateRuntime) Stage(
	context.Context,
	Candidate,
) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.stageCalls++
	if runtime.stageErr != nil {
		return runtime.stageErr
	}
	runtime.staged = true
	return nil
}

func (runtime *recordingCandidateRuntime) Qualify(
	context.Context,
	Candidate,
) (CompatibilityReport, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.qualifyCalls++
	if runtime.qualifyErr != nil {
		return CompatibilityReport{}, runtime.qualifyErr
	}
	return runtime.report, nil
}

func (runtime *recordingCandidateRuntime) InspectSelection(
	context.Context,
) (Selection, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.inspectSelectionCalls++
	if runtime.selectionErr != nil {
		return Selection{}, runtime.selectionErr
	}
	if !runtime.selected {
		return Selection{}, ErrUpgradeAbsent
	}
	return runtime.selection, nil
}

func (runtime *recordingCandidateRuntime) ProveQuiescent(
	context.Context,
) (Quiescence, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.quiescenceCalls++
	if runtime.quiescenceErr != nil {
		return Quiescence{}, runtime.quiescenceErr
	}
	return runtime.quiescence, nil
}

func (runtime *recordingCandidateRuntime) ValidateReplacement(
	context.Context,
	Candidate,
) (CompatibilityReport, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.replacementCalls++
	if runtime.replacementErr != nil {
		return CompatibilityReport{}, runtime.replacementErr
	}
	return runtime.replacement, nil
}

func (runtime *recordingCandidateRuntime) Select(
	context.Context,
	Candidate,
) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.selectCalls++
	if runtime.selectErr != nil {
		return runtime.selectErr
	}
	runtime.selected = true
	if runtime.selectionSink != nil {
		runtime.selectionSink.selection = runtime.selection
	}
	return nil
}

func (runtime *recordingCandidateRuntime) totalCalls() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.inspectStageCalls +
		runtime.stageCalls +
		runtime.qualifyCalls +
		runtime.inspectSelectionCalls +
		runtime.quiescenceCalls +
		runtime.replacementCalls +
		runtime.selectCalls
}

type recordingMaintenanceRequestSource struct {
	request RunnerMaintenanceStatusRequest
	err     error
	calls   int
	auto    bool
}

func (source *recordingMaintenanceRequestSource) CurrentMaintenanceRequest(
	_ context.Context,
	selected string,
	candidate *string,
) (RunnerMaintenanceStatusRequest, error) {
	source.calls++
	if source.auto || source.request.Protocol == "" {
		source.request = RunnerMaintenanceStatusRequest{
			Protocol:                runnerMaintenanceStatusProtocol,
			FleetID:                 "portable-example",
			Epoch:                   7,
			SessionID:               "session-example-0001",
			ControlSequence:         uint64(source.calls),
			SelectedManifestDigest:  selected,
			CandidateManifestDigest: cloneOptionalString(candidate),
		}
	}
	return source.request, source.err
}

type recordingReleasePublisher struct {
	mu           sync.Mutex
	statuses     []RunnerReleaseStatus
	err          error
	failSequence uint64
}

func (publisher *recordingReleasePublisher) PublishRunnerRelease(
	_ context.Context,
	status RunnerReleaseStatus,
) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	publisher.statuses = append(publisher.statuses, status)
	if publisher.failSequence != 0 &&
		status.ObservationSequence == publisher.failSequence {
		return ErrUpgradeUnavailable
	}
	return publisher.err
}

func (publisher *recordingReleasePublisher) count() int {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	return len(publisher.statuses)
}

func (publisher *recordingReleasePublisher) sequenceCount(
	sequence uint64,
) int {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	count := 0
	for _, status := range publisher.statuses {
		if status.ObservationSequence == sequence {
			count++
		}
	}
	return count
}

func (publisher *recordingReleasePublisher) last(
	t *testing.T,
) RunnerReleaseStatus {
	t.Helper()
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if len(publisher.statuses) == 0 {
		t.Fatal("no published status")
	}
	return publisher.statuses[len(publisher.statuses)-1]
}

type recordingDirectiveProvider struct {
	directive RunnerMaintenanceDirective
	err       error
	calls     int
	auto      bool
	phase     RunnerMaintenancePhase
	candidate *Candidate

	configRevision uint64
	canaryDigest   string
	enabledDigest  string
}

func (provider *recordingDirectiveProvider) Current(
	ctx context.Context,
	request RunnerMaintenanceStatusRequest,
) (RunnerMaintenanceDirective, error) {
	provider.calls++
	if provider.err != nil {
		return RunnerMaintenanceDirective{}, provider.err
	}
	if provider.auto {
		qualifiedCandidate := provider.candidate
		if provider.phase == MaintenanceStagePermitted ||
			provider.phase == MaintenanceWaitHosted {
			qualifiedCandidate = nil
		}
		wire := validMaintenanceWire(
			provider.phase,
			request,
			qualifiedCandidate,
		)
		wire.ConfigRevision = provider.configRevision
		wire.CanaryPolicyDigest = provider.canaryDigest
		wire.EnabledPolicyDigest = provider.enabledDigest
		wire.ExpiresAtServerMS = fixedDirectiveTime().
			Add(time.Hour).
			UnixMilli()
		document, err := json.Marshal(wire)
		if err != nil {
			return RunnerMaintenanceDirective{}, err
		}
		return ParseVerifiedRunnerMaintenanceDirective(
			ctx,
			document,
			16<<10,
			&recordingMaintenanceVerifier{},
		)
	}
	return provider.directive, provider.err
}
