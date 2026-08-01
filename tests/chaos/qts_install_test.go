//go:build chaos

package chaos_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type chaosStorageAuthority struct{}

func (chaosStorageAuthority) Revalidate(
	context.Context,
	hostruntime.StorageReservation,
) error {
	return nil
}

type chaosEffectFailure string

const (
	chaosFailBefore chaosEffectFailure = "before"
	chaosFailAfter  chaosEffectFailure = "after"
)

type chaosLifecycleEffects struct {
	binding hostruntime.OperationBinding

	mu               sync.Mutex
	applied          map[hostruntime.OperationPhase]hostruntime.TargetPostcondition
	applyCalls       map[hostruntime.OperationPhase]int
	commits          map[hostruntime.OperationPhase]int
	order            []hostruntime.OperationPhase
	failPhase        hostruntime.OperationPhase
	failMode         chaosEffectFailure
	failed           bool
	observeFailure   bool
	observationTicks uint64
}

func newChaosLifecycleEffects(
	binding hostruntime.OperationBinding,
) *chaosLifecycleEffects {
	return &chaosLifecycleEffects{
		binding:    binding,
		applied:    make(map[hostruntime.OperationPhase]hostruntime.TargetPostcondition),
		applyCalls: make(map[hostruntime.OperationPhase]int),
		commits:    make(map[hostruntime.OperationPhase]int),
	}
}

func (effects *chaosLifecycleEffects) Observe(
	_ context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) (hostruntime.LifecycleEffectObservation, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	if binding != effects.binding {
		return hostruntime.LifecycleEffectObservation{},
			errors.New("chaos: lifecycle binding drift")
	}
	if effects.observeFailure && phase == effects.failPhase {
		effects.observeFailure = false
		return hostruntime.LifecycleEffectObservation{},
			errors.New("chaos: post-effect readback interrupted")
	}
	postcondition, found := effects.applied[phase]
	if !found {
		return hostruntime.LifecycleEffectObservation{
			State: hostruntime.LifecycleEffectAbsent,
		}, nil
	}
	return hostruntime.LifecycleEffectObservation{
		State:         hostruntime.LifecycleEffectPresent,
		Postcondition: &postcondition,
	}, nil
}

func (effects *chaosLifecycleEffects) Apply(
	_ context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) (hostruntime.TargetPostcondition, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	if binding != effects.binding {
		return hostruntime.TargetPostcondition{},
			errors.New("chaos: lifecycle binding drift")
	}
	effects.applyCalls[phase]++
	if phase == effects.failPhase && !effects.failed {
		effects.failed = true
		if effects.failMode == chaosFailBefore {
			return hostruntime.TargetPostcondition{},
				errors.New("chaos: interrupted before effect")
		}
	}
	postcondition, found := effects.applied[phase]
	if !found {
		effects.observationTicks++
		postcondition = chaosPostcondition(
			binding,
			phase,
			effects.observationTicks,
		)
		effects.applied[phase] = postcondition
		effects.commits[phase]++
		effects.order = append(effects.order, phase)
	}
	if phase == effects.failPhase &&
		effects.failMode == chaosFailAfter &&
		effects.failed &&
		effects.applyCalls[phase] == 1 {
		effects.observeFailure = true
		return hostruntime.TargetPostcondition{},
			errors.New("chaos: interrupted after effect")
	}
	return postcondition, nil
}

func (effects *chaosLifecycleEffects) snapshot() (
	map[hostruntime.OperationPhase]int,
	map[hostruntime.OperationPhase]int,
	[]hostruntime.OperationPhase,
) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	calls := make(map[hostruntime.OperationPhase]int, len(effects.applyCalls))
	for phase, count := range effects.applyCalls {
		calls[phase] = count
	}
	commits := make(map[hostruntime.OperationPhase]int, len(effects.commits))
	for phase, count := range effects.commits {
		commits[phase] = count
	}
	return calls, commits, append([]hostruntime.OperationPhase(nil), effects.order...)
}

func TestQTSLifecycleEveryJournalEffectResumesAfterRestart(t *testing.T) {
	_ = requireChaosHost(t)

	for _, kind := range []hostruntime.OperationKind{
		hostruntime.OperationKindInstall,
		hostruntime.OperationKindSuspend,
		hostruntime.OperationKindResume,
		hostruntime.OperationKindRollback,
		hostruntime.OperationKindUninstall,
	} {
		t.Run(string(kind), func(t *testing.T) {
			request := chaosLifecycleRequest(t, kind)
			baselineRoot := newChaosLifecycleRoot(t)
			baselineStore := openChaosLifecycleStore(t, baselineRoot, true)
			baselineEffects := newChaosLifecycleEffects(request.Binding)
			baselineEngine := chaosLifecycleEngine(
				baselineStore,
				baselineEffects,
			)
			result, err := baselineEngine.Execute(
				context.Background(),
				request,
			)
			if err != nil || result.Status != hostruntime.HostActionComplete {
				t.Fatalf("chaos: baseline %s = %+v, error=%v", kind, result, err)
			}
			_, _, phases := baselineEffects.snapshot()
			if err := baselineStore.Close(); err != nil {
				t.Fatalf("chaos: close baseline store: %v", err)
			}
			if len(phases) == 0 ||
				phases[len(phases)-1] != hostruntime.OperationPhaseComplete {
				t.Fatalf("chaos: %s phase sequence = %v", kind, phases)
			}

			for _, phase := range phases {
				for _, mode := range []chaosEffectFailure{
					chaosFailBefore,
					chaosFailAfter,
				} {
					t.Run(string(phase)+"/"+string(mode), func(t *testing.T) {
						root := newChaosLifecycleRoot(t)
						firstStore := openChaosLifecycleStore(t, root, true)
						effects := newChaosLifecycleEffects(request.Binding)
						effects.failPhase = phase
						effects.failMode = mode
						firstEngine := chaosLifecycleEngine(firstStore, effects)
						first, firstErr := firstEngine.Execute(
							context.Background(),
							request,
						)
						if firstErr == nil ||
							first.Status == hostruntime.HostActionComplete {
							t.Fatalf(
								"chaos: interruption %s/%s unexpectedly completed: %+v",
								phase,
								mode,
								first,
							)
						}
						if err := firstStore.Close(); err != nil {
							t.Fatalf("chaos: close interrupted store: %v", err)
						}

						restartedStore := openChaosLifecycleStore(t, root, false)
						restartedEngine := chaosLifecycleEngine(
							restartedStore,
							effects,
						)
						recovered, recoverErr := restartedEngine.Execute(
							context.Background(),
							request,
						)
						if recoverErr != nil ||
							recovered.Status != hostruntime.HostActionComplete ||
							recovered.OperationID != request.Binding.OperationID {
							t.Fatalf(
								"chaos: restart %s/%s = %+v, error=%v",
								phase,
								mode,
								recovered,
								recoverErr,
							)
						}
						callsBeforeReplay, commitsBeforeReplay, order :=
							effects.snapshot()
						replayed, replayErr := restartedEngine.Execute(
							context.Background(),
							request,
						)
						callsAfterReplay, commitsAfterReplay, _ :=
							effects.snapshot()
						if replayErr != nil ||
							replayed.Status != hostruntime.HostActionComplete ||
							replayed.JournalDigest != recovered.JournalDigest ||
							!reflect.DeepEqual(
								callsBeforeReplay,
								callsAfterReplay,
							) ||
							!reflect.DeepEqual(
								commitsBeforeReplay,
								commitsAfterReplay,
							) {
							t.Fatalf(
								"chaos: terminal replay %s/%s changed effects",
								phase,
								mode,
							)
						}
						if !reflect.DeepEqual(order, phases) {
							t.Fatalf(
								"chaos: recovered phase order = %v, want %v",
								order,
								phases,
							)
						}
						for _, committedPhase := range phases {
							if commitsBeforeReplay[committedPhase] != 1 {
								t.Fatalf(
									"chaos: %s commit count = %d, want 1",
									committedPhase,
									commitsBeforeReplay[committedPhase],
								)
							}
						}
						if mode == chaosFailBefore &&
							callsBeforeReplay[phase] != 2 {
							t.Fatalf(
								"chaos: before-effect apply attempts = %d, want 2",
								callsBeforeReplay[phase],
							)
						}
						if mode == chaosFailAfter &&
							callsBeforeReplay[phase] != 1 {
							t.Fatalf(
								"chaos: after-effect apply attempts = %d, want 1",
								callsBeforeReplay[phase],
							)
						}
						if err := restartedStore.Close(); err != nil {
							t.Fatalf("chaos: close restarted store: %v", err)
						}
					})
				}
			}
		})
	}
}

func TestQTSShellLifecycleFailureRemainsClosed(t *testing.T) {
	_ = requireChaosHost(t)

	sandbox := copyQTSSandbox(t)
	tests := []struct {
		script string
		args   []string
	}{
		{
			script: "install-controller.sh",
			args: []string{
				"--private", "/private/runtime.json",
				"--manifest", "/release/manifest.json",
				"--acquisition", "disabled",
			},
		},
		{
			script: "suspend-controller.sh",
			args: []string{
				"--private", "/private/runtime.json",
				"--drain-policy=wait",
				"--hosted-confirmation", "/private/hosted.json",
			},
		},
		{
			script: "resume-controller.sh",
			args: []string{
				"--private", "/private/runtime.json",
				"--acquisition", "disabled",
			},
		},
		{
			script: "rollback-controller.sh",
			args: []string{
				"--private", "/private/runtime.json",
				"--expected-generation", "42",
				"--hosted-confirmation", "/private/hosted.json",
				"--legacy-command-file", "/private/legacy.json",
			},
		},
		{
			script: "uninstall-controller.sh",
			args: []string{
				"--private", "/private/runtime.json",
				"--retain-state",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.script, func(t *testing.T) {
			argv := append(
				[]string{filepath.Join(sandbox, test.script)},
				test.args...,
			)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			result, err := hostruntime.NewExecCommandRunner().Run(
				ctx,
				argv,
				nil,
				nil,
			)
			cancel()
			if err != nil ||
				result.ExitCode == 0 ||
				len(result.Stdout) != 0 ||
				string(result.Stderr) != "portable-ghar-qts: action failed\n" {
				t.Fatalf(
					"chaos: %s failure exit=%d stdout=%q stderr=%q error=%v",
					test.script,
					result.ExitCode,
					result.Stdout,
					result.Stderr,
					err,
				)
			}
		})
	}
}

func chaosLifecycleRequest(
	t *testing.T,
	kind hostruntime.OperationKind,
) hostruntime.LifecycleRequest {
	t.Helper()
	manifest := chaosRuntimeManifest()
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil {
		t.Fatalf("chaos: marshal runtime manifest: %v", err)
	}
	var (
		disposition    *hostruntime.InstallDisposition
		priorDigest    *string
		targetDigest   *string
		priorManifest  *hostruntime.RuntimeManifest
		targetManifest *hostruntime.RuntimeManifest
		targetFleet    fleetfence.Fleet
	)
	expectedGeneration := uint64(41)
	switch kind {
	case hostruntime.OperationKindInstall:
		value := hostruntime.InstallDispositionUpgradePortable
		disposition = &value
		priorDigest = &manifestDigest
		targetDigest = &manifestDigest
		priorManifest = &manifest
		targetManifest = &manifest
		targetFleet = fleetfence.FleetPortable
	case hostruntime.OperationKindSuspend:
		priorDigest = &manifestDigest
		priorManifest = &manifest
		targetFleet = fleetfence.FleetNone
	case hostruntime.OperationKindResume:
		targetDigest = &manifestDigest
		targetManifest = &manifest
		targetFleet = fleetfence.FleetPortable
	case hostruntime.OperationKindRollback:
		priorDigest = &manifestDigest
		priorManifest = &manifest
		targetFleet = fleetfence.FleetLegacy
	case hostruntime.OperationKindUninstall:
		priorDigest = &manifestDigest
		priorManifest = &manifest
		targetFleet = fleetfence.FleetNone
	default:
		t.Fatalf("chaos: unsupported operation kind %q", kind)
	}
	overlay := strings.Repeat("c", 64)
	operationID, err := hostruntime.DeriveOperationID(
		kind,
		disposition,
		expectedGeneration,
		priorDigest,
		targetDigest,
		targetFleet,
		overlay,
	)
	if err != nil {
		t.Fatalf("chaos: derive operation id: %v", err)
	}
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   kind,
		InstallDisposition:     disposition,
		ExpectedGeneration:     expectedGeneration,
		PriorManifestDigest:    priorDigest,
		TargetManifestDigest:   targetDigest,
		TargetFleet:            targetFleet,
		PrivateOverlayRevision: overlay,
	}
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("chaos: marshal binding: %v", err)
	}
	filesystems := chaosLifecycleFilesystems()
	roles := make([]hostruntime.StorageRoleReservation, len(filesystems))
	for index, identity := range filesystems {
		roles[index] = hostruntime.StorageRoleReservation{
			Role:               identity.Role,
			MountID:            identity.MountID,
			RequiredBytes:      uint64(1000 + index),
			RequiredInodes:     uint64(100 + index),
			CompensationBytes:  uint64(100 + index),
			CompensationInodes: uint64(10 + index),
			ObservedFreeBytes:  uint64(100000 + index),
			ObservedFreeInodes: uint64(10000 + index),
		}
	}
	created := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	return hostruntime.LifecycleRequest{
		Binding:        binding,
		PriorManifest:  priorManifest,
		TargetManifest: targetManifest,
		Reservation: hostruntime.StorageReservation{
			SchemaVersion:        1,
			OperationID:          operationID,
			BindingDigest:        bindingDigest,
			State:                hostruntime.ReservationStateActive,
			StorageBudgetDigest:  manifest.StorageBudgetDigest,
			TargetManifestDigest: targetDigest,
			Filesystems:          filesystems,
			Roles:                roles,
			CrashOrphans:         []hostruntime.CrashOrphanReservation{},
			CreatedAt:            created,
			UpdatedAt:            created,
		},
	}
}

func chaosRuntimeManifest() hostruntime.RuntimeManifest {
	return hostruntime.RuntimeManifest{
		SchemaVersion:         1,
		BuildID:               strings.Repeat("a", 64),
		ControllerSHA256:      strings.Repeat("b", 64),
		RunnerImageDigest:     "sha256:" + strings.Repeat("c", 64),
		AdapterImageDigest:    "sha256:" + strings.Repeat("d", 64),
		BrokerImageDigest:     "sha256:" + strings.Repeat("e", 64),
		HelperImageDigest:     "sha256:" + strings.Repeat("f", 64),
		VerifierImageDigest:   "sha256:" + strings.Repeat("1", 64),
		TrustBundleDigest:     strings.Repeat("2", 64),
		SeccompProfileDigest:  strings.Repeat("3", 64),
		EgressMode:            "restricted-broker-v1",
		PolicyManifestDigest:  strings.Repeat("4", 64),
		ConntrackBudgetDigest: strings.Repeat("5", 64),
		StorageBudgetDigest:   strings.Repeat("6", 64),
		LogPolicyDigest:       strings.Repeat("7", 64),
		AcquisitionDefault:    "disabled",
		FleetGeneration:       7,
	}
}

func chaosLifecycleFilesystems() []hostruntime.LifecycleFilesystemIdentity {
	roles := []string{
		"docker-root",
		"state",
		"staging",
		"rollback",
		"scratch",
		"logs",
	}
	result := make([]hostruntime.LifecycleFilesystemIdentity, len(roles))
	for index, role := range roles {
		result[index] = hostruntime.LifecycleFilesystemIdentity{
			Role:        role,
			MountID:     uint64(index + 1),
			DeviceMajor: 8,
			DeviceMinor: uint32(index + 1),
			RootInode:   uint64(100 + index),
			FSType:      "ext4",
		}
	}
	return result
}

func chaosPostcondition(
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	tick uint64,
) hostruntime.TargetPostcondition {
	_, bindingDigest, _ := hostruntime.MarshalOperationBinding(binding)
	effectKey, _ := hostruntime.DeriveOperationEffectKey(binding, phase)
	manifestDigest := binding.TargetManifestDigest
	if manifestDigest == nil {
		manifestDigest = binding.PriorManifestDigest
	}
	postcondition := hostruntime.TargetPostcondition{
		SchemaVersion:          1,
		OperationID:            binding.OperationID,
		BindingDigest:          bindingDigest,
		EffectKey:              effectKey,
		Phase:                  phase,
		ManifestDigest:         manifestDigest,
		PrivateOverlayRevision: binding.PrivateOverlayRevision,
		FenceGeneration:        binding.ExpectedGeneration,
		ActiveFleet:            binding.TargetFleet,
		Filesystems:            chaosLifecycleFilesystems(),
		Artifacts:              []hostruntime.ArtifactProjection{},
		Processes:              []hostruntime.ProcessProjection{},
		Policy: hostruntime.PolicyProjection{
			PolicyManifestDigest: strings.Repeat("4", 64),
			TransitionEpoch:      9,
		},
		Quiescence: hostruntime.QuiescenceProjection{},
		ObservedAt: time.Date(
			2026,
			7,
			29,
			13,
			0,
			int(tick%60),
			int(tick),
			time.UTC,
		),
	}
	if phase == hostruntime.OperationPhaseCurrentSelected ||
		phase == hostruntime.OperationPhaseVerified {
		postcondition.CurrentSelection =
			&hostruntime.CurrentSelectionProjection{
				ReleaseDirectoryDeviceMajor: 8,
				ReleaseDirectoryDeviceMinor: 1,
				ReleaseDirectoryInode:       200,
				SymlinkDeviceMajor:          8,
				SymlinkDeviceMinor:          1,
				SymlinkInode:                201,
				RelativeLinkText:            "release-a",
				ManifestDeviceMajor:         8,
				ManifestDeviceMinor:         1,
				ManifestInode:               202,
				ManifestDigest:              *binding.TargetManifestDigest,
				FenceGeneration:             binding.ExpectedGeneration,
				ActiveFleet:                 binding.TargetFleet,
			}
	}
	return postcondition
}

func newChaosLifecycleRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "lifecycle")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("chaos: create lifecycle root: %v", err)
	}
	return root
}

func openChaosLifecycleStore(
	t *testing.T,
	root string,
	bootstrap bool,
) *hostruntime.LifecycleStore {
	t.Helper()
	store, err := hostruntime.OpenLifecycleStore(root, bootstrap)
	if err != nil {
		t.Fatalf("chaos: open lifecycle store: %v", err)
	}
	return store
}

func chaosLifecycleEngine(
	store *hostruntime.LifecycleStore,
	effects *chaosLifecycleEffects,
) hostruntime.LifecycleEngine {
	var tick atomic.Uint64
	return hostruntime.LifecycleEngine{
		Store:        store,
		Effects:      effects,
		Storage:      chaosStorageAuthority{},
		PollInterval: time.Millisecond,
		Now: func() time.Time {
			return time.Date(
				2026,
				7,
				29,
				14,
				0,
				0,
				int(tick.Add(1)),
				time.UTC,
			)
		},
	}
}

func copyQTSSandbox(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("chaos: QTS source location unavailable")
	}
	source := filepath.Clean(filepath.Join(filepath.Dir(current), "..", "..", "deploy", "qts"))
	target := filepath.Join(t.TempDir(), "qts")
	if err := filepath.WalkDir(
		source,
		func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			destination := filepath.Join(target, relative)
			if entry.IsDir() {
				return os.MkdirAll(destination, 0o700)
			}
			document, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			document = []byte(strings.ReplaceAll(
				strings.ReplaceAll(
					string(document),
					"/usr/bin/id",
					filepath.Join(target, "fake-id"),
				),
				"/bin/uname",
				filepath.Join(target, "fake-uname"),
			))
			return os.WriteFile(destination, document, 0o700)
		},
	); err != nil {
		t.Fatalf("chaos: copy QTS sandbox: %v", err)
	}
	for name, body := range map[string]string{
		"fake-id":    "#!/bin/sh\nprintf '%s\\n' 0\n",
		"fake-uname": "#!/bin/sh\nprintf '%s\\n' Linux\n",
		"portable-ghar": "#!/bin/sh\n" +
			"exit 1\n",
	} {
		if err := os.WriteFile(
			filepath.Join(target, name),
			[]byte(body),
			0o700,
		); err != nil {
			t.Fatalf("chaos: write QTS sandbox helper: %v", err)
		}
	}
	return target
}
