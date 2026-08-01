package productionruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/state"
)

type productionEffect uint8

const (
	maximumProductionLifecycleJournalBytes       = 1 << 20
	maximumProductionLifecyclePostconditionBytes = 4 << 20
	maximumProductionLifecycleReservationBytes   = 4 << 20
)

const (
	effectPreflight productionEffect = iota + 1
	effectCandidateStaged
	effectCandidateSmoked
	effectCandidatePromoted
	effectGreenfieldProven
	effectUpgradeProven
	effectPriorAcquisitionDisabled
	effectPriorDrained
	effectPriorControllerStopped
	effectPriorQuiescenceProven
	effectFencePortableProven
	effectFencePortable
	effectWatchdogInstalled
	effectPolicyDisabled
	effectObserverStarted
	effectZeroProven
	effectCurrentSelected
	effectVerified
	effectLegacyDispositionProven
	effectLegacyAcquisitionDisabled
	effectLegacyDrained
	effectLegacyControllerStopped
	effectLegacyQuiescenceProven
	effectFenceLegacyProven
	effectLegacyNormalizedProven
	effectHoldProven
	effectWatchdogDisabled
	effectDrained
	effectControllerStopped
	effectQuiescenceProven
	effectFenceNone
	effectStoppedProven
	effectLegacyRestored
	effectFenceLegacy
	effectLegacyStarted
	effectWatchdogRemoved
	effectControllerRemoved
	effectRegistrationRemoved
	effectRetentionProven
	effectCompensationStarted
	effectCandidateStopped
	effectCandidateRemoved
	effectAbsenceProven
	effectObserverStopped
	effectCurrentRemoved
	effectPriorSelectionProven
	effectPriorDisabledProven
	effectPriorRestored
	effectPriorObserverStarted
	effectPriorZeroProven
	effectLegacyZeroProven
	effectLegacyStopped
	effectNoneDisabledProven
	effectCompensated
)

// productionPhaseEffects is the sole phase-to-effect table. All lifecycle
// adapters below dispatch only on the closed effect value from this table.
var productionPhaseEffects = map[hostruntime.OperationPhase]productionEffect{
	hostruntime.OperationPhasePrepared:                    effectPreflight,
	hostruntime.OperationPhasePreflightProven:             effectPreflight,
	hostruntime.OperationPhaseCandidateStaged:             effectCandidateStaged,
	hostruntime.OperationPhaseCandidateSmoked:             effectCandidateSmoked,
	hostruntime.OperationPhasePriorRetained:               effectCandidatePromoted,
	hostruntime.OperationPhaseDispositionGreenfieldProven: effectGreenfieldProven,
	hostruntime.OperationPhasePriorAbsenceProven:          effectGreenfieldProven,
	hostruntime.OperationPhaseDispositionUpgradeProven:    effectUpgradeProven,
	hostruntime.OperationPhasePriorAcquisitionDisabled:    effectPriorAcquisitionDisabled,
	hostruntime.OperationPhasePriorDrained:                effectPriorDrained,
	hostruntime.OperationPhasePriorControllerStopped:      effectPriorControllerStopped,
	hostruntime.OperationPhasePriorQuiescenceProven:       effectPriorQuiescenceProven,
	hostruntime.OperationPhaseFencePortableProven:         effectFencePortableProven,
	hostruntime.OperationPhaseFencePortable:               effectFencePortable,
	hostruntime.OperationPhaseWatchdogInstalled:           effectWatchdogInstalled,
	hostruntime.OperationPhasePolicyDisabled:              effectPolicyDisabled,
	hostruntime.OperationPhaseObserverStarted:             effectObserverStarted,
	hostruntime.OperationPhaseZeroProven:                  effectZeroProven,
	hostruntime.OperationPhaseCurrentSelected:             effectCurrentSelected,
	hostruntime.OperationPhaseVerified:                    effectVerified,
	hostruntime.OperationPhaseComplete:                    effectVerified,
	hostruntime.OperationPhaseDispositionLegacyProven:     effectLegacyDispositionProven,
	hostruntime.OperationPhaseLegacyAcquisitionDisabled:   effectLegacyAcquisitionDisabled,
	hostruntime.OperationPhaseLegacyDrained:               effectLegacyDrained,
	hostruntime.OperationPhaseLegacyControllerStopped:     effectLegacyControllerStopped,
	hostruntime.OperationPhaseLegacyQuiescenceProven:      effectLegacyQuiescenceProven,
	hostruntime.OperationPhaseFenceLegacyProven:           effectFenceLegacyProven,
	hostruntime.OperationPhaseLegacyNormalizedProven:      effectLegacyNormalizedProven,
	hostruntime.OperationPhaseHoldProven:                  effectHoldProven,
	hostruntime.OperationPhaseWatchdogDisabled:            effectWatchdogDisabled,
	hostruntime.OperationPhaseDrained:                     effectDrained,
	hostruntime.OperationPhaseControllerStopped:           effectControllerStopped,
	hostruntime.OperationPhaseQuiescenceProven:            effectQuiescenceProven,
	hostruntime.OperationPhaseFenceNone:                   effectFenceNone,
	hostruntime.OperationPhaseStoppedProven:               effectStoppedProven,
	hostruntime.OperationPhaseLegacyRestored:              effectLegacyRestored,
	hostruntime.OperationPhaseFenceLegacy:                 effectFenceLegacy,
	hostruntime.OperationPhaseLegacyStarted:               effectLegacyStarted,
	hostruntime.OperationPhaseWatchdogRemoved:             effectWatchdogRemoved,
	hostruntime.OperationPhaseControllerRemoved:           effectControllerRemoved,
	hostruntime.OperationPhaseRegistrationRemoved:         effectRegistrationRemoved,
	hostruntime.OperationPhaseRetentionProven:             effectRetentionProven,

	hostruntime.OperationPhaseCGPreStarted:             effectCompensationStarted,
	hostruntime.OperationPhaseCGPreCandidateStopped:    effectCandidateStopped,
	hostruntime.OperationPhaseCGPreCandidateRemoved:    effectCandidateRemoved,
	hostruntime.OperationPhaseCGPreAbsenceProven:       effectAbsenceProven,
	hostruntime.OperationPhaseCompGreenfieldAbsent:     effectCompensated,
	hostruntime.OperationPhaseCGFenceStarted:           effectCompensationStarted,
	hostruntime.OperationPhaseCGFenceObserverStopped:   effectObserverStopped,
	hostruntime.OperationPhaseCGFenceQuiescenceProven:  effectQuiescenceProven,
	hostruntime.OperationPhaseCGFenceNone:              effectFenceNone,
	hostruntime.OperationPhaseCGFenceCandidateRemoved:  effectCandidateRemoved,
	hostruntime.OperationPhaseCompGreenfieldNone:       effectCompensated,
	hostruntime.OperationPhaseCGSelectStarted:          effectCompensationStarted,
	hostruntime.OperationPhaseCGSelectObserverStopped:  effectObserverStopped,
	hostruntime.OperationPhaseCGSelectQuiescenceProven: effectQuiescenceProven,
	hostruntime.OperationPhaseCGSelectCurrentRemoved:   effectCurrentRemoved,
	hostruntime.OperationPhaseCGSelectNone:             effectFenceNone,
	hostruntime.OperationPhaseCGSelectCandidateRemoved: effectCandidateRemoved,
	hostruntime.OperationPhaseCompGreenfieldSelected:   effectCompensated,

	hostruntime.OperationPhaseCUPreStarted:                 effectCompensationStarted,
	hostruntime.OperationPhaseCUPreCandidateStopped:        effectCandidateStopped,
	hostruntime.OperationPhaseCUPreCandidateRemoved:        effectCandidateRemoved,
	hostruntime.OperationPhaseCUPrePriorSelectionProven:    effectPriorSelectionProven,
	hostruntime.OperationPhaseCUPrePriorDisabledProven:     effectPriorDisabledProven,
	hostruntime.OperationPhaseCompUpgradePrior:             effectCompensated,
	hostruntime.OperationPhaseCUSelectStarted:              effectCompensationStarted,
	hostruntime.OperationPhaseCUSelectObserverStopped:      effectObserverStopped,
	hostruntime.OperationPhaseCUSelectQuiescenceProven:     effectQuiescenceProven,
	hostruntime.OperationPhaseCUSelectPriorRestored:        effectPriorRestored,
	hostruntime.OperationPhaseCUSelectPriorObserverStarted: effectPriorObserverStarted,
	hostruntime.OperationPhaseCUSelectPriorZeroProven:      effectPriorZeroProven,
	hostruntime.OperationPhaseCUSelectCandidateRemoved:     effectCandidateRemoved,
	hostruntime.OperationPhaseCompUpgradeRestored:          effectCompensated,

	hostruntime.OperationPhaseCLPreStarted:              effectCompensationStarted,
	hostruntime.OperationPhaseCLPreCandidateStopped:     effectCandidateStopped,
	hostruntime.OperationPhaseCLPreCandidateRemoved:     effectCandidateRemoved,
	hostruntime.OperationPhaseCLPrePriorSelectionProven: effectPriorSelectionProven,
	hostruntime.OperationPhaseCLPreLegacyZeroProven:     effectLegacyZeroProven,
	hostruntime.OperationPhaseCompLegacyPrior:           effectCompensated,
	hostruntime.OperationPhaseCLSelectStarted:           effectCompensationStarted,
	hostruntime.OperationPhaseCLSelectObserverStopped:   effectObserverStopped,
	hostruntime.OperationPhaseCLSelectQuiescenceProven:  effectQuiescenceProven,
	hostruntime.OperationPhaseCLSelectPriorRestored:     effectPriorRestored,
	hostruntime.OperationPhaseCLSelectLegacyStarted:     effectLegacyStarted,
	hostruntime.OperationPhaseCLSelectLegacyZeroProven:  effectLegacyZeroProven,
	hostruntime.OperationPhaseCLSelectCandidateRemoved:  effectCandidateRemoved,
	hostruntime.OperationPhaseCompLegacyRestored:        effectCompensated,

	hostruntime.OperationPhaseCSNoneStarted:           effectCompensationStarted,
	hostruntime.OperationPhaseCSNoneDisabledProven:    effectNoneDisabledProven,
	hostruntime.OperationPhaseCSNoneQuiescenceProven:  effectQuiescenceProven,
	hostruntime.OperationPhaseCompSuspendNone:         effectCompensated,
	hostruntime.OperationPhaseCRPreStarted:            effectCompensationStarted,
	hostruntime.OperationPhaseCRPreObserverAbsent:     effectObserverStopped,
	hostruntime.OperationPhaseCRPreWatchdogAbsent:     effectWatchdogDisabled,
	hostruntime.OperationPhaseCRPreNoneDisabledProven: effectNoneDisabledProven,
	hostruntime.OperationPhaseCompResumeNone:          effectCompensated,
	hostruntime.OperationPhaseCRPostStarted:           effectCompensationStarted,
	hostruntime.OperationPhaseCRPostObserverStopped:   effectObserverStopped,
	hostruntime.OperationPhaseCRPostQuiescenceProven:  effectQuiescenceProven,
	hostruntime.OperationPhaseCRPostNone:              effectFenceNone,
	hostruntime.OperationPhaseCRPostWatchdogAbsent:    effectWatchdogDisabled,
	hostruntime.OperationPhaseCBPreStarted:            effectCompensationStarted,
	hostruntime.OperationPhaseCBPreNoneProven:         effectFenceNone,
	hostruntime.OperationPhaseCompRollbackNone:        effectCompensated,
	hostruntime.OperationPhaseCBPostStarted:           effectCompensationStarted,
	hostruntime.OperationPhaseCBPostLegacyStopped:     effectLegacyStopped,
	hostruntime.OperationPhaseCBPostQuiescenceProven:  effectLegacyQuiescenceProven,
	hostruntime.OperationPhaseCBPostNone:              effectFenceNone,
	hostruntime.OperationPhaseCompRollbackLegacyNone:  effectCompensated,
}

func isProductionCompensationPhase(phase hostruntime.OperationPhase) bool {
	switch phase {
	case hostruntime.OperationPhaseCGPreStarted,
		hostruntime.OperationPhaseCGPreCandidateStopped,
		hostruntime.OperationPhaseCGPreCandidateRemoved,
		hostruntime.OperationPhaseCGPreAbsenceProven,
		hostruntime.OperationPhaseCompGreenfieldAbsent,
		hostruntime.OperationPhaseCGFenceStarted,
		hostruntime.OperationPhaseCGFenceObserverStopped,
		hostruntime.OperationPhaseCGFenceQuiescenceProven,
		hostruntime.OperationPhaseCGFenceNone,
		hostruntime.OperationPhaseCGFenceCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldNone,
		hostruntime.OperationPhaseCGSelectStarted,
		hostruntime.OperationPhaseCGSelectObserverStopped,
		hostruntime.OperationPhaseCGSelectQuiescenceProven,
		hostruntime.OperationPhaseCGSelectCurrentRemoved,
		hostruntime.OperationPhaseCGSelectNone,
		hostruntime.OperationPhaseCGSelectCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldSelected,
		hostruntime.OperationPhaseCUPreStarted,
		hostruntime.OperationPhaseCUPreCandidateStopped,
		hostruntime.OperationPhaseCUPreCandidateRemoved,
		hostruntime.OperationPhaseCUPrePriorSelectionProven,
		hostruntime.OperationPhaseCUPrePriorDisabledProven,
		hostruntime.OperationPhaseCompUpgradePrior,
		hostruntime.OperationPhaseCUSelectStarted,
		hostruntime.OperationPhaseCUSelectObserverStopped,
		hostruntime.OperationPhaseCUSelectQuiescenceProven,
		hostruntime.OperationPhaseCUSelectPriorRestored,
		hostruntime.OperationPhaseCUSelectPriorObserverStarted,
		hostruntime.OperationPhaseCUSelectPriorZeroProven,
		hostruntime.OperationPhaseCUSelectCandidateRemoved,
		hostruntime.OperationPhaseCompUpgradeRestored,
		hostruntime.OperationPhaseCLPreStarted,
		hostruntime.OperationPhaseCLPreCandidateStopped,
		hostruntime.OperationPhaseCLPreCandidateRemoved,
		hostruntime.OperationPhaseCLPrePriorSelectionProven,
		hostruntime.OperationPhaseCLPreLegacyZeroProven,
		hostruntime.OperationPhaseCompLegacyPrior,
		hostruntime.OperationPhaseCLSelectStarted,
		hostruntime.OperationPhaseCLSelectObserverStopped,
		hostruntime.OperationPhaseCLSelectQuiescenceProven,
		hostruntime.OperationPhaseCLSelectPriorRestored,
		hostruntime.OperationPhaseCLSelectLegacyStarted,
		hostruntime.OperationPhaseCLSelectLegacyZeroProven,
		hostruntime.OperationPhaseCLSelectCandidateRemoved,
		hostruntime.OperationPhaseCompLegacyRestored,
		hostruntime.OperationPhaseCSNoneStarted,
		hostruntime.OperationPhaseCSNoneDisabledProven,
		hostruntime.OperationPhaseCSNoneQuiescenceProven,
		hostruntime.OperationPhaseCompSuspendNone,
		hostruntime.OperationPhaseCRPreStarted,
		hostruntime.OperationPhaseCRPreObserverAbsent,
		hostruntime.OperationPhaseCRPreWatchdogAbsent,
		hostruntime.OperationPhaseCRPreNoneDisabledProven,
		hostruntime.OperationPhaseCompResumeNone,
		hostruntime.OperationPhaseCRPostStarted,
		hostruntime.OperationPhaseCRPostObserverStopped,
		hostruntime.OperationPhaseCRPostQuiescenceProven,
		hostruntime.OperationPhaseCRPostNone,
		hostruntime.OperationPhaseCRPostWatchdogAbsent,
		hostruntime.OperationPhaseCBPreStarted,
		hostruntime.OperationPhaseCBPreNoneProven,
		hostruntime.OperationPhaseCompRollbackNone,
		hostruntime.OperationPhaseCBPostStarted,
		hostruntime.OperationPhaseCBPostLegacyStopped,
		hostruntime.OperationPhaseCBPostQuiescenceProven,
		hostruntime.OperationPhaseCBPostNone,
		hostruntime.OperationPhaseCompRollbackLegacyNone:
		return true
	default:
		return false
	}
}

type productionLifecycleBackend struct {
	target *systemLifecycleTarget
}

func (backend *productionLifecycleBackend) ObservePhase(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) (hostruntime.LifecycleEffectObservation, error) {
	effect, ok := productionPhaseEffects[phase]
	if backend == nil ||
		backend.target == nil ||
		!ok {
		return hostruntime.LifecycleEffectObservation{},
			ErrLifecycleEffects
	}
	return backend.target.observe(ctx, binding, phase, effect)
}

func (backend *productionLifecycleBackend) ApplyPhase(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
) error {
	effect, ok := productionPhaseEffects[phase]
	if backend == nil ||
		backend.target == nil ||
		!ok {
		return ErrLifecycleEffects
	}
	return backend.target.apply(ctx, binding, phase, effect)
}

type systemLifecycleTarget struct {
	kind           hostruntime.OperationKind
	disposition    hostruntime.InstallDisposition
	overlay        hostruntime.PrivateOverlay
	revision       string
	manifest       hostruntime.RuntimeManifest
	manifestDigest string
	entryFence     uint64
	terminalFence  uint64
	terminalFleet  fleetfence.Fleet
	retainState    bool
	drainPolicy    string
	pollInterval   time.Duration
	now            func() time.Time

	releases            *releaseBundleStore
	fence               *fleetfence.Store
	storage             *SystemStorageProbe
	docker              hostruntime.ManagedQuiescence
	process             *ProcessAuthority
	priorProcess        *ProcessAuthority
	processStore        *PinnedProcessRecordStore
	watchdog            *watchdogMarkerStore
	probe               DisabledControllerProbe
	admin               lifecycleControllerAdmin
	priorAdmin          lifecycleControllerAdmin
	hosted              HostedHoldAuthority
	hostedExpectation   HostedHoldExpectation
	priorOverlay        *hostruntime.PrivateOverlay
	priorRevision       string
	priorManifestDigest string
	artifacts           releaseArtifactAuthority
}

type systemLifecycleSnapshot struct {
	fencePresent bool
	generation   uint64
	fleet        fleetfence.Fleet

	stagedPresent   bool
	imagesVerified  bool
	runnerSmoked    bool
	releasedPresent bool
	currentPresent  bool
	current         releaseBundleSnapshot

	watchdogPresent bool
	watchdogPrior   bool
	watchdogTarget  bool
	watchdog        hostruntime.ArtifactProjection
	processPresent  bool
	processPrior    bool
	processTarget   bool
	processRecord   ProcessRecord
	processIdentity string
	priorPolicy     controller.PolicyStatus
	priorDrained    bool
	assignedJobs    uint64
	runningJobs     uint64
	activeListeners uint64
	zero            bool
	policyEpoch     uint64
	filesystems     []hostruntime.LifecycleFilesystemIdentity
}

func invokeSystemLifecycle(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	action cli.HostAction,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	switch action {
	case cli.ActionInstall:
		return invokePortableInstall(
			ctx,
			overlay,
			revision,
			target,
			arguments,
		)
	case cli.ActionVerify:
		return verifyInstalledTarget(
			ctx,
			overlay,
			revision,
			target,
			arguments,
		)
	case cli.ActionSuspend,
		cli.ActionResume,
		cli.ActionRollback,
		cli.ActionUninstall:
		return invokePortableTransition(
			ctx,
			overlay,
			revision,
			target,
			action,
			arguments,
		)
	default:
		return hostruntime.HostActionResult{}, ErrProtocol
	}
}

func invokePortableTransition(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	action cli.HostAction,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	if ctx == nil || ctx.Err() != nil ||
		!overlay.Resources.RunnerSizing.OperatorApproved {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	manifest, document, manifestDigest, err := loadPinnedTargetManifest(
		overlay.Manifest.Path,
	)
	if err != nil || len(document) == 0 ||
		manifestDigest != arguments.ManifestDigest ||
		manifestDigest != overlay.Manifest.Digest ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	binding, terminalGeneration, terminalFleet, err := fixedTransitionBinding(
		action,
		target,
		manifestDigest,
		revision,
		arguments.ExpectedGeneration,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	var hosted HostedHoldAuthority
	if action == cli.ActionSuspend || action == cli.ActionRollback {
		hosted, err = NewSystemHostedHoldAuthority(
			func() time.Time { return time.Now().UTC() },
		)
		if err != nil {
			return hostruntime.HostActionResult{}, ErrProtocol
		}
	}
	var legacy LegacyCommandAuthority
	if action == cli.ActionRollback {
		legacy, err = NewUnavailableLegacyCommandAuthority()
		if err != nil {
			return hostruntime.HostActionResult{}, ErrProtocol
		}
	}
	hostedExpectation, err := validateTransitionAuthorities(
		ctx,
		action,
		overlay,
		arguments,
		binding,
		hosted,
		legacy,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	resources, request, err := openTransitionOperation(
		ctx,
		overlay,
		revision,
		manifest,
		manifestDigest,
		binding,
		terminalGeneration,
		terminalFleet,
		action,
		arguments,
		hosted,
		hostedExpectation,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	result, runErr := resources.engine.Execute(ctx, request)
	closeErr := resources.Close()
	if runErr != nil || closeErr != nil {
		return hostruntime.HostActionResult{},
			errors.Join(ErrProtocol, runErr, closeErr)
	}
	return result, nil
}

func validateTransitionAuthorities(
	ctx context.Context,
	action cli.HostAction,
	overlay hostruntime.PrivateOverlay,
	arguments InvokeArguments,
	binding hostruntime.OperationBinding,
	hosted HostedHoldAuthority,
	legacy LegacyCommandAuthority,
) (HostedHoldExpectation, error) {
	var hostedExpectation HostedHoldExpectation
	if ctx == nil || ctx.Err() != nil {
		return hostedExpectation, ErrLifecycleAuthority
	}
	if action == cli.ActionSuspend || action == cli.ActionRollback {
		hostedExpectation = HostedHoldExpectation{
			Path:              arguments.HostedConfirmation,
			RepositoryAliases: lifecycleRepositoryAliases(overlay),
			FenceGeneration:   binding.ExpectedGeneration,
		}
		if hosted == nil || !validHostedHoldExpectation(hostedExpectation) {
			return HostedHoldExpectation{}, ErrLifecycleAuthority
		}
		validation := hosted.Validate(ctx, hostedExpectation)
		if validation.Validity != AuthorityValid ||
			!lowerHexDigest(validation.EvidenceDigest) {
			return HostedHoldExpectation{}, ErrLifecycleAuthority
		}
		hostedExpectation.EvidenceDigest = validation.EvidenceDigest
	}
	if action == cli.ActionRollback {
		if overlay.Legacy == nil || legacy == nil ||
			arguments.LegacyCommandFile != overlay.Legacy.CommandFilePath {
			return HostedHoldExpectation{}, ErrLifecycleAuthority
		}
		legacyExpectation := LegacyCommandExpectation{
			Path:                arguments.LegacyCommandFile,
			CommandDigest:       overlay.Legacy.CommandDigest,
			ConfigurationDigest: overlay.Legacy.ConfigurationDigest,
			ImageDigests: append(
				[]string(nil),
				overlay.Legacy.ImageDigests...,
			),
			WatchdogDigest: overlay.Legacy.WatchdogDigest,
		}
		if !validLegacyCommandExpectation(legacyExpectation) ||
			legacy.Validate(ctx, legacyExpectation).Validity != AuthorityValid {
			return HostedHoldExpectation{}, ErrLifecycleAuthority
		}
	}
	return hostedExpectation, nil
}

func lifecycleRepositoryAliases(
	overlay hostruntime.PrivateOverlay,
) []string {
	aliases := make([]string, len(overlay.Repositories))
	for index, repository := range overlay.Repositories {
		aliases[index] = repository.Alias
	}
	return aliases
}

func invokePortableInstall(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	if ctx == nil ||
		ctx.Err() != nil ||
		target.InstallDisposition == nil ||
		!overlay.Resources.RunnerSizing.OperatorApproved {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	disposition := *target.InstallDisposition
	if disposition != hostruntime.InstallDispositionGreenfieldPortable &&
		disposition != hostruntime.InstallDispositionUpgradePortable {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	if disposition == hostruntime.InstallDispositionGreenfieldPortable &&
		(target.FenceGeneration != 0 ||
			target.ActiveFleet != fleetfence.FleetNone ||
			target.CurrentManifestDigest != nil) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	if disposition == hostruntime.InstallDispositionUpgradePortable &&
		(target.FenceGeneration == 0 ||
			target.ActiveFleet != fleetfence.FleetPortable ||
			target.CurrentManifestDigest == nil) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	manifest, manifestDocument, manifestDigest, err :=
		loadPinnedTargetManifest(overlay.Manifest.Path)
	if err != nil ||
		len(manifestDocument) == 0 ||
		manifestDigest != arguments.ManifestDigest ||
		manifestDigest != overlay.Manifest.Digest ||
		(disposition == hostruntime.InstallDispositionGreenfieldPortable &&
			manifest.FleetGeneration != 1) ||
		(disposition == hostruntime.InstallDispositionUpgradePortable &&
			manifest.FleetGeneration != target.FenceGeneration) ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	binding, terminalGeneration, err := fixedInstallBinding(
		target,
		manifestDigest,
		revision,
	)
	if err != nil || terminalGeneration != manifest.FleetGeneration {
		return hostruntime.HostActionResult{}, ErrProtocol
	}

	resources, request, err := openInstallOperation(
		ctx,
		overlay,
		revision,
		manifest,
		manifestDigest,
		binding,
		true,
		manifest.FleetGeneration,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	result, runErr := resources.engine.Execute(ctx, request)
	closeErr := resources.Close()
	if runErr != nil || closeErr != nil {
		return hostruntime.HostActionResult{},
			errors.Join(ErrProtocol, runErr, closeErr)
	}
	return result, nil
}

func fixedInstallBinding(
	target cli.TargetProof,
	manifestDigest string,
	revision string,
) (hostruntime.OperationBinding, uint64, error) {
	if target.InstallDisposition == nil {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	switch *target.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		return fixedGreenfieldBinding(target, manifestDigest, revision)
	case hostruntime.InstallDispositionUpgradePortable:
		return fixedUpgradeBinding(target, manifestDigest, revision)
	default:
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
}

func fixedGreenfieldBinding(
	target cli.TargetProof,
	manifestDigest string,
	revision string,
) (hostruntime.OperationBinding, uint64, error) {
	operationID, terminalGeneration, terminalFleet, err :=
		cli.ExpectedOperation(
			cli.ActionInstall,
			target,
			manifestDigest,
			revision,
		)
	if err != nil ||
		terminalFleet != fleetfence.FleetPortable ||
		target.InstallDisposition == nil ||
		*target.InstallDisposition !=
			hostruntime.InstallDispositionGreenfieldPortable {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	targetManifest := manifestDigest
	disposition := hostruntime.InstallDispositionGreenfieldPortable
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     0,
		PriorManifestDigest:    nil,
		TargetManifestDigest:   &targetManifest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	if _, _, err := hostruntime.MarshalOperationBinding(binding); err != nil {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	return binding, terminalGeneration, nil
}

func fixedUpgradeBinding(
	target cli.TargetProof,
	manifestDigest string,
	revision string,
) (hostruntime.OperationBinding, uint64, error) {
	operationID, terminalGeneration, terminalFleet, err :=
		cli.ExpectedOperation(
			cli.ActionInstall,
			target,
			manifestDigest,
			revision,
		)
	if err != nil ||
		terminalFleet != fleetfence.FleetPortable ||
		target.InstallDisposition == nil ||
		*target.InstallDisposition !=
			hostruntime.InstallDispositionUpgradePortable ||
		target.CurrentManifestDigest == nil ||
		*target.CurrentManifestDigest == manifestDigest {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	priorManifest := *target.CurrentManifestDigest
	targetManifest := manifestDigest
	disposition := hostruntime.InstallDispositionUpgradePortable
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		Kind:                   hostruntime.OperationKindInstall,
		InstallDisposition:     &disposition,
		ExpectedGeneration:     target.FenceGeneration,
		PriorManifestDigest:    &priorManifest,
		TargetManifestDigest:   &targetManifest,
		TargetFleet:            fleetfence.FleetPortable,
		PrivateOverlayRevision: revision,
	}
	if _, _, err := hostruntime.MarshalOperationBinding(binding); err != nil {
		return hostruntime.OperationBinding{}, 0, ErrLifecycleEffects
	}
	return binding, terminalGeneration, nil
}

func fixedTransitionBinding(
	action cli.HostAction,
	target cli.TargetProof,
	manifestDigest string,
	revision string,
	expectedGeneration uint64,
) (hostruntime.OperationBinding, uint64, fleetfence.Fleet, error) {
	if target.CurrentManifestDigest == nil ||
		*target.CurrentManifestDigest != manifestDigest ||
		!lowerHexDigest(manifestDigest) ||
		!lowerHexDigest(revision) {
		return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
	}
	if action == cli.ActionRollback {
		if expectedGeneration == 0 || expectedGeneration != target.FenceGeneration {
			return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
		}
	} else if expectedGeneration != 0 {
		return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
	}
	operationID, terminalGeneration, terminalFleet, err := cli.ExpectedOperation(
		action,
		target,
		manifestDigest,
		revision,
	)
	if err != nil {
		return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
	}
	priorManifest := manifestDigest
	binding := hostruntime.OperationBinding{
		SchemaVersion:          1,
		OperationID:            operationID,
		ExpectedGeneration:     target.FenceGeneration,
		PriorManifestDigest:    &priorManifest,
		TargetFleet:            terminalFleet,
		PrivateOverlayRevision: revision,
	}
	switch action {
	case cli.ActionSuspend:
		binding.Kind = hostruntime.OperationKindSuspend
		if target.ActiveFleet != fleetfence.FleetPortable ||
			terminalFleet != fleetfence.FleetNone {
			return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
		}
	case cli.ActionResume:
		binding.Kind = hostruntime.OperationKindResume
		targetManifest := manifestDigest
		binding.TargetManifestDigest = &targetManifest
		if target.ActiveFleet != fleetfence.FleetNone ||
			terminalFleet != fleetfence.FleetPortable {
			return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
		}
	case cli.ActionRollback:
		binding.Kind = hostruntime.OperationKindRollback
		if target.ActiveFleet != fleetfence.FleetPortable ||
			terminalFleet != fleetfence.FleetLegacy {
			return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
		}
	case cli.ActionUninstall:
		binding.Kind = hostruntime.OperationKindUninstall
		if (target.ActiveFleet != fleetfence.FleetNone &&
			target.ActiveFleet != fleetfence.FleetLegacy) ||
			terminalFleet != target.ActiveFleet {
			return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
		}
	default:
		return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
	}
	if _, _, err := hostruntime.MarshalOperationBinding(binding); err != nil {
		return hostruntime.OperationBinding{}, 0, "", ErrLifecycleEffects
	}
	return binding, terminalGeneration, terminalFleet, nil
}

func loadPriorReleaseForInstall(
	releases *releaseBundleStore,
	binding hostruntime.OperationBinding,
	targetOverlay hostruntime.PrivateOverlay,
	targetManifest hostruntime.RuntimeManifest,
) (
	*hostruntime.RuntimeManifest,
	*hostruntime.PrivateOverlay,
	string,
	error,
) {
	if releases == nil || binding.InstallDisposition == nil {
		return nil, nil, "", ErrLifecycleEffects
	}
	switch *binding.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		if binding.PriorManifestDigest != nil {
			return nil, nil, "", ErrLifecycleEffects
		}
		return nil, nil, "", nil
	case hostruntime.InstallDispositionUpgradePortable:
		if binding.PriorManifestDigest == nil ||
			binding.TargetManifestDigest == nil ||
			*binding.PriorManifestDigest ==
				*binding.TargetManifestDigest {
			return nil, nil, "", ErrLifecycleEffects
		}
	default:
		return nil, nil, "", ErrLifecycleEffects
	}
	current, present, err := releases.InspectReleasedDigest(
		*binding.PriorManifestDigest,
	)
	if err != nil ||
		!present ||
		current.manifestDigest != *binding.PriorManifestDigest ||
		!lowerHexDigest(current.overlayRevision) {
		return nil, nil, "", ErrLifecycleEffects
	}
	priorManifest, parsedManifestDigest, err :=
		hostruntime.ParseRuntimeManifest(
			current.manifestDocument,
			maximumReleaseManifestBytes,
		)
	if err != nil ||
		parsedManifestDigest != current.manifestDigest ||
		priorManifest.FleetGeneration != binding.ExpectedGeneration ||
		priorManifest.FleetGeneration != targetManifest.FleetGeneration {
		return nil, nil, "", ErrLifecycleEffects
	}
	priorOverlay, parsedRevision, err := hostruntime.ParsePrivateOverlay(
		current.overlayDocument,
		maximumReleaseOverlayBytes,
	)
	if err != nil ||
		parsedRevision != current.overlayRevision ||
		priorOverlay.Manifest.Digest != current.manifestDigest ||
		priorOverlay.Paths != targetOverlay.Paths ||
		priorOverlay.Target != targetOverlay.Target ||
		!priorOverlay.Resources.RunnerSizing.OperatorApproved ||
		!runtimeManifestMatchesOverlay(priorManifest, priorOverlay) {
		return nil, nil, "", ErrLifecycleEffects
	}
	return &priorManifest, &priorOverlay, parsedRevision, nil
}

type systemLifecycleResources struct {
	engine       hostruntime.LifecycleEngine
	lifecycle    *hostruntime.LifecycleStore
	releases     *releaseBundleStore
	fence        *fleetfence.Store
	processStore *PinnedProcessRecordStore
	watchdog     *watchdogMarkerStore
}

func openInstallOperation(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	manifest hostruntime.RuntimeManifest,
	manifestDigest string,
	binding hostruntime.OperationBinding,
	bootstrapLifecycle bool,
	operationalGeneration uint64,
) (*systemLifecycleResources, hostruntime.LifecycleRequest, error) {
	var request hostruntime.LifecycleRequest
	if ctx == nil || ctx.Err() != nil ||
		operationalGeneration < manifest.FleetGeneration {
		return nil, request, ErrProtocol
	}
	releases, err := openReleaseBundleStore(
		overlay.Paths.StagingRoot,
		overlay.Paths.ReleaseRoot,
	)
	if err != nil {
		return nil, request, ErrProtocol
	}
	resources := &systemLifecycleResources{releases: releases}
	fail := func(primary error) (
		*systemLifecycleResources,
		hostruntime.LifecycleRequest,
		error,
	) {
		return nil, hostruntime.LifecycleRequest{},
			errors.Join(primary, resources.Close())
	}
	priorManifest, priorOverlay, priorRevision, err :=
		loadPriorReleaseForInstall(
			releases,
			binding,
			overlay,
			manifest,
		)
	if err != nil {
		return fail(ErrProtocol)
	}
	if _, err := digestPinnedExecutable(
		overlay.Commands.HostRuntimeBinary,
	); err != nil {
		return fail(ErrProtocol)
	}

	commandRunner := hostruntime.NewExecCommandRunner()
	commandRunner.StdoutLimit = maximumDockerRootOutputBytes
	commandRunner.StderrLimit = maximumDockerRootOutputBytes
	artifacts, err := NewReleaseArtifactVerifier(
		overlay.Commands.DockerBinary,
		commandRunner,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	storage, err := NewSystemStorageProbe(ctx, overlay, commandRunner)
	if err != nil {
		return fail(ErrProtocol)
	}
	availability, err := storage.Snapshot(ctx)
	if err != nil {
		return fail(ErrProtocol)
	}
	layout, err :=
		hostruntime.LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		return fail(ErrProtocol)
	}
	lifecycle, err := hostruntime.OpenLifecycleStoreLayout(
		layout,
		bootstrapLifecycle,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.lifecycle = lifecycle
	reservation, err := selectGreenfieldReservation(
		lifecycle,
		binding,
		priorManifest,
		manifest,
		func() (hostruntime.StorageReservation, error) {
			return BuildStorageReservation(
				binding,
				overlay,
				manifest,
				availability,
				time.Now().UTC(),
			)
		},
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	storageAuthority, err := NewReservationStorageAuthority(storage)
	if err != nil ||
		storageAuthority.Revalidate(ctx, reservation.persisted) != nil {
		return fail(ErrProtocol)
	}

	pollInterval, err := time.ParseDuration(
		overlay.Fence.LockPollInterval,
	)
	if err != nil || pollInterval <= 0 || pollInterval > time.Second {
		return fail(ErrProtocol)
	}
	fence, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             overlay.Paths.FenceRoot,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: pollInterval,
	})
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.fence = fence
	fenceSnapshot, fencePresent, err := fence.InspectOptional(ctx)
	if err != nil {
		return fail(ErrProtocol)
	}
	current, currentPresent, err := releases.Current()
	if err != nil {
		return fail(ErrProtocol)
	}
	switch *binding.InstallDisposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		if !reservation.continuationPresent &&
			(fencePresent || currentPresent) {
			return fail(ErrProtocol)
		}
	case hostruntime.InstallDispositionUpgradePortable:
		expectedLiveGeneration := binding.ExpectedGeneration
		if reservation.continuationPresent &&
			reservation.continuation.journal.Phase ==
				hostruntime.OperationPhaseComplete &&
			reservation.continuation.reservation.State ==
				hostruntime.ReservationStateCommitted {
			expectedLiveGeneration = operationalGeneration
		}
		if !fencePresent ||
			fenceSnapshot.Header.Generation != expectedLiveGeneration ||
			fenceSnapshot.Header.ActiveFleet != fleetfence.FleetPortable ||
			!currentPresent ||
			(current.manifestDigest != *binding.PriorManifestDigest &&
				current.manifestDigest != *binding.TargetManifestDigest) ||
			(!reservation.continuationPresent &&
				current.manifestDigest != *binding.PriorManifestDigest) {
			return fail(ErrProtocol)
		}
	default:
		return fail(ErrProtocol)
	}

	processStore, err := OpenProcessRecordStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.processStore = processStore
	_, _, processPresent, err := processStore.Read(ctx)
	if err != nil ||
		(!reservation.continuationPresent &&
			*binding.InstallDisposition ==
				hostruntime.InstallDispositionGreenfieldPortable &&
			processPresent) ||
		(!reservation.continuationPresent &&
			*binding.InstallDisposition ==
				hostruntime.InstallDispositionUpgradePortable &&
			!processPresent) {
		return fail(ErrProtocol)
	}
	kernel, err := NewSystemProcessKernel()
	if err != nil {
		return fail(ErrProtocol)
	}
	processGrace, err := time.ParseDuration(
		overlay.Watchdog.ProcessGrace,
	)
	if err != nil || processGrace <= 0 {
		return fail(ErrProtocol)
	}
	newAuthority := func(
		boundOverlay hostruntime.PrivateOverlay,
		boundRevision string,
		boundManifest hostruntime.RuntimeManifest,
		boundDigest string,
		fenceGeneration uint64,
	) (*ProcessAuthority, string, error) {
		releaseOverlayPath := filepath.Join(
			boundOverlay.Paths.ReleaseRoot,
			boundDigest,
			releaseOverlayName,
		)
		controllerDigest, err := digestPinnedExecutable(
			boundOverlay.Commands.ControllerBinary,
		)
		if err != nil || controllerDigest != boundManifest.ControllerSHA256 {
			return nil, "", ErrProtocol
		}
		authority, err := NewProcessAuthority(ProcessAuthorityConfig{
			Store:  processStore,
			Kernel: kernel,
			Binding: ProcessBinding{
				PrivateOverlayRevision: boundRevision,
				ManifestDigest:         boundDigest,
				ActiveFleet:            fleetfence.FleetPortable,
				FenceGeneration:        fenceGeneration,
			},
			Launch: ControllerLaunch{
				ControllerBinary: boundOverlay.Commands.ControllerBinary,
				PrivateOverlay:   releaseOverlayPath,
				DatabasePath:     boundOverlay.Paths.DatabasePath,
				StdoutLog: filepath.Join(
					boundOverlay.Paths.LogRoot,
					"controller.stdout.log",
				),
				StderrLog: filepath.Join(
					boundOverlay.Paths.LogRoot,
					"controller.stderr.log",
				),
				ExecutableDigest: controllerDigest,
			},
			Timing: ProcessTiming{
				PollInterval: pollInterval,
				TermGrace:    processGrace,
				KillGrace:    processGrace,
				CleanupGrace: processGrace,
			},
		})
		return authority, releaseOverlayPath, err
	}
	process, releaseOverlayPath, err := newAuthority(
		overlay,
		revision,
		manifest,
		manifestDigest,
		operationalGeneration,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	var priorProcess *ProcessAuthority
	var priorAdmin lifecycleControllerAdmin
	if priorManifest != nil && priorOverlay != nil {
		var priorOverlayPath string
		priorProcess, priorOverlayPath, err = newAuthority(
			*priorOverlay,
			priorRevision,
			*priorManifest,
			*binding.PriorManifestDigest,
			priorManifest.FleetGeneration,
		)
		if err != nil {
			return fail(ErrProtocol)
		}
		priorAdmin, err = NewSystemDisabledControllerProbe(
			priorOverlay.Commands.ControllerBinary,
			priorOverlayPath,
		)
		if err != nil {
			return fail(ErrProtocol)
		}
	}

	watchdog, err := openWatchdogMarkerStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.watchdog = watchdog
	targetWatchdogBinding := watchdogMarkerBinding{
		PrivateOverlayRevision: revision,
		ManifestDigest:         manifestDigest,
		WatchdogBinary:         overlay.Commands.WatchdogBinary,
	}
	if priorOverlay == nil {
		if _, present, err := watchdog.Inspect(
			targetWatchdogBinding,
		); err != nil || !installWatchdogAdmissible(
			hostruntime.InstallDispositionGreenfieldPortable,
			reservation.continuationPresent,
			reservation.continuation.journal.Phase,
			0,
			present,
		) {
			return fail(ErrProtocol)
		}
	} else {
		priorWatchdogBinding := watchdogMarkerBinding{
			PrivateOverlayRevision: priorRevision,
			ManifestDigest:         *binding.PriorManifestDigest,
			WatchdogBinary:         priorOverlay.Commands.WatchdogBinary,
		}
		_, matched, present, err := watchdog.InspectOneOf(
			priorWatchdogBinding,
			targetWatchdogBinding,
		)
		if err != nil || !installWatchdogAdmissible(
			hostruntime.InstallDispositionUpgradePortable,
			reservation.continuationPresent,
			reservation.continuation.journal.Phase,
			matched,
			present,
		) {
			return fail(ErrProtocol)
		}
	}

	docker, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    overlay.Commands.DockerBinary,
			BrokerRoot:    overlay.Paths.BrokerRoot,
			SeccompRoot:   overlay.Paths.SeccompRoot,
			BrokerNetwork: overlay.Docker.BrokerNetworkID,
		},
		commandRunner,
	)
	if err != nil ||
		(*binding.InstallDisposition ==
			hostruntime.InstallDispositionGreenfieldPortable &&
			docker.ProveManagedQuiescence(ctx) != nil) {
		return fail(ErrProtocol)
	}
	probe, err := NewSystemDisabledControllerProbe(
		overlay.Commands.ControllerBinary,
		releaseOverlayPath,
	)
	if err != nil {
		return fail(ErrProtocol)
	}

	backend := &productionLifecycleBackend{
		target: &systemLifecycleTarget{
			disposition:    *binding.InstallDisposition,
			overlay:        overlay,
			revision:       revision,
			manifest:       manifest,
			manifestDigest: manifestDigest,
			terminalFence:  operationalGeneration,
			pollInterval:   pollInterval,
			now:            func() time.Time { return time.Now().UTC() },
			releases:       releases,
			fence:          fence,
			storage:        storage,
			docker:         docker,
			process:        process,
			priorProcess:   priorProcess,
			processStore:   processStore,
			watchdog:       watchdog,
			probe:          probe,
			admin:          probe,
			priorAdmin:     priorAdmin,
			artifacts:      artifacts,
			priorOverlay:   priorOverlay,
			priorRevision:  priorRevision,
			priorManifestDigest: func() string {
				if binding.PriorManifestDigest == nil {
					return ""
				}
				return *binding.PriorManifestDigest
			}(),
		},
	}
	effects, err := NewLifecycleEffects(backend)
	if err != nil {
		return fail(ErrProtocol)
	}
	compensation, err :=
		hostruntime.NewLifecycleCompensationAuthority(lifecycle)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.engine = hostruntime.LifecycleEngine{
		Store:        lifecycle,
		Effects:      effects,
		Storage:      storageAuthority,
		Compensation: compensation,
		PollInterval: pollInterval,
		Now:          func() time.Time { return time.Now().UTC() },
	}
	request = hostruntime.LifecycleRequest{
		Binding:        binding,
		PriorManifest:  priorManifest,
		TargetManifest: &manifest,
		Reservation:    reservation.request,
	}
	return resources, request, nil
}

func openTransitionOperation(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	manifest hostruntime.RuntimeManifest,
	manifestDigest string,
	binding hostruntime.OperationBinding,
	terminalGeneration uint64,
	terminalFleet fleetfence.Fleet,
	action cli.HostAction,
	arguments InvokeArguments,
	hosted HostedHoldAuthority,
	hostedExpectation HostedHoldExpectation,
) (*systemLifecycleResources, hostruntime.LifecycleRequest, error) {
	var request hostruntime.LifecycleRequest
	if ctx == nil || ctx.Err() != nil ||
		binding.Kind == hostruntime.OperationKindInstall ||
		binding.ExpectedGeneration == 0 || terminalGeneration == 0 {
		return nil, request, ErrProtocol
	}
	releases, err := openReleaseBundleStore(
		overlay.Paths.StagingRoot,
		overlay.Paths.ReleaseRoot,
	)
	if err != nil {
		return nil, request, ErrProtocol
	}
	resources := &systemLifecycleResources{releases: releases}
	fail := func(primary error) (
		*systemLifecycleResources,
		hostruntime.LifecycleRequest,
		error,
	) {
		return nil, hostruntime.LifecycleRequest{},
			errors.Join(primary, resources.Close())
	}
	released, present, err := releases.InspectReleased(
		manifestDigest,
		revision,
	)
	if err != nil || !present ||
		released.manifestDigest != manifestDigest ||
		released.overlayRevision != revision {
		return fail(ErrProtocol)
	}
	if _, err := digestPinnedExecutable(
		overlay.Commands.HostRuntimeBinary,
	); err != nil {
		return fail(ErrProtocol)
	}
	commandRunner := hostruntime.NewExecCommandRunner()
	commandRunner.StdoutLimit = maximumDockerRootOutputBytes
	commandRunner.StderrLimit = maximumDockerRootOutputBytes
	storage, err := NewSystemStorageProbe(ctx, overlay, commandRunner)
	if err != nil {
		return fail(ErrProtocol)
	}
	availability, err := storage.Snapshot(ctx)
	if err != nil {
		return fail(ErrProtocol)
	}
	layout, err := hostruntime.LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		return fail(ErrProtocol)
	}
	lifecycle, err := hostruntime.OpenLifecycleStoreLayout(layout, false)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.lifecycle = lifecycle
	priorManifest := &manifest
	var targetManifest *hostruntime.RuntimeManifest
	if binding.Kind == hostruntime.OperationKindResume {
		targetManifest = &manifest
	}
	reservation, err := selectLifecycleReservation(
		lifecycle,
		binding,
		priorManifest,
		targetManifest,
		manifest,
		func() (hostruntime.StorageReservation, error) {
			return BuildStorageReservation(
				binding,
				overlay,
				manifest,
				availability,
				time.Now().UTC(),
			)
		},
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	current, currentPresent, err := releases.Current()
	if err != nil || !transitionCurrentSelectionAdmissible(
		binding,
		reservation.continuationPresent,
		reservation.continuation.journal.Phase,
		current,
		currentPresent,
		manifestDigest,
		revision,
	) {
		return fail(ErrProtocol)
	}
	storageAuthority, err := NewReservationStorageAuthority(storage)
	if err != nil ||
		storageAuthority.Revalidate(ctx, reservation.persisted) != nil {
		return fail(ErrProtocol)
	}
	pollInterval, err := time.ParseDuration(overlay.Fence.LockPollInterval)
	if err != nil || pollInterval <= 0 || pollInterval > time.Second {
		return fail(ErrProtocol)
	}
	fence, err := fleetfence.OpenStore(fleetfence.StoreConfig{
		Root:             overlay.Paths.FenceRoot,
		Identity:         fleetfence.NewSystemIdentitySource(),
		Now:              time.Now,
		LockPollInterval: pollInterval,
	})
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.fence = fence
	fenceSnapshot, fencePresent, err := fence.InspectOptional(ctx)
	if err != nil || !fencePresent {
		return fail(ErrProtocol)
	}
	entryFleet := transitionEntryFleet(binding)
	if !reservation.continuationPresent &&
		(fenceSnapshot.Header.Generation != binding.ExpectedGeneration ||
			fenceSnapshot.Header.ActiveFleet != entryFleet) {
		return fail(ErrProtocol)
	}
	processStore, err := OpenProcessRecordStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.processStore = processStore
	kernel, err := NewSystemProcessKernel()
	if err != nil {
		return fail(ErrProtocol)
	}
	processGrace, err := time.ParseDuration(overlay.Watchdog.ProcessGrace)
	if err != nil || processGrace <= 0 {
		return fail(ErrProtocol)
	}
	processGeneration := binding.ExpectedGeneration
	if binding.Kind == hostruntime.OperationKindResume {
		processGeneration = terminalGeneration
	}
	process, releaseOverlayPath, err := newTransitionProcessAuthority(
		processStore,
		kernel,
		overlay,
		revision,
		manifest,
		manifestDigest,
		processGeneration,
		pollInterval,
		processGrace,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	admin, err := NewSystemDisabledControllerProbe(
		overlay.Commands.ControllerBinary,
		releaseOverlayPath,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	watchdog, err := openWatchdogMarkerStore(overlay.Paths.StateRoot)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.watchdog = watchdog
	docker, err := hostruntime.NewDockerCLI(
		hostruntime.DockerCLIConfig{
			DockerPath:    overlay.Commands.DockerBinary,
			BrokerRoot:    overlay.Paths.BrokerRoot,
			SeccompRoot:   overlay.Paths.SeccompRoot,
			BrokerNetwork: overlay.Docker.BrokerNetworkID,
		},
		commandRunner,
	)
	if err != nil {
		return fail(ErrProtocol)
	}
	target := &systemLifecycleTarget{
		kind:              binding.Kind,
		overlay:           overlay,
		revision:          revision,
		manifest:          manifest,
		manifestDigest:    manifestDigest,
		entryFence:        binding.ExpectedGeneration,
		terminalFence:     terminalGeneration,
		terminalFleet:     terminalFleet,
		retainState:       arguments.RetainState,
		drainPolicy:       arguments.DrainPolicy,
		pollInterval:      pollInterval,
		now:               func() time.Time { return time.Now().UTC() },
		releases:          releases,
		fence:             fence,
		storage:           storage,
		docker:            docker,
		process:           process,
		processStore:      processStore,
		watchdog:          watchdog,
		probe:             admin,
		admin:             admin,
		hosted:            hosted,
		hostedExpectation: hostedExpectation,
	}
	continuationPhase := hostruntime.OperationPhase("")
	if reservation.continuationPresent {
		continuationPhase = reservation.continuation.journal.Phase
	}
	if target.preAdmission(
		ctx,
		action,
		continuationPhase,
		reservation.continuationPresent,
	) != nil {
		return fail(ErrProtocol)
	}
	backend := &productionLifecycleBackend{target: target}
	effects, err := NewLifecycleEffects(backend)
	if err != nil {
		return fail(ErrProtocol)
	}
	compensation, err := hostruntime.NewLifecycleCompensationAuthority(lifecycle)
	if err != nil {
		return fail(ErrProtocol)
	}
	resources.engine = hostruntime.LifecycleEngine{
		Store:        lifecycle,
		Effects:      effects,
		Storage:      storageAuthority,
		Compensation: compensation,
		PollInterval: pollInterval,
		Now:          func() time.Time { return time.Now().UTC() },
	}
	request = hostruntime.LifecycleRequest{
		Binding:        binding,
		PriorManifest:  priorManifest,
		TargetManifest: targetManifest,
		Reservation:    reservation.request,
	}
	return resources, request, nil
}

func transitionEntryFleet(
	binding hostruntime.OperationBinding,
) fleetfence.Fleet {
	switch binding.Kind {
	case hostruntime.OperationKindSuspend,
		hostruntime.OperationKindRollback:
		return fleetfence.FleetPortable
	case hostruntime.OperationKindResume:
		return fleetfence.FleetNone
	case hostruntime.OperationKindUninstall:
		return binding.TargetFleet
	default:
		return ""
	}
}

func installWatchdogAdmissible(
	disposition hostruntime.InstallDisposition,
	continuation bool,
	phase hostruntime.OperationPhase,
	matched int,
	present bool,
) bool {
	switch disposition {
	case hostruntime.InstallDispositionGreenfieldPortable:
		return !present || continuation && matched == 0
	case hostruntime.InstallDispositionUpgradePortable:
		if present {
			return matched == 0 || continuation && matched == 1
		}
		if !continuation {
			return false
		}
		switch phase {
		case hostruntime.OperationPhaseCUPreCandidateStopped,
			hostruntime.OperationPhaseCUPreCandidateRemoved,
			hostruntime.OperationPhaseCUPrePriorSelectionProven,
			hostruntime.OperationPhaseCUPrePriorDisabledProven,
			hostruntime.OperationPhaseCompUpgradePrior,
			hostruntime.OperationPhaseCUSelectObserverStopped,
			hostruntime.OperationPhaseCUSelectQuiescenceProven,
			hostruntime.OperationPhaseCUSelectPriorRestored,
			hostruntime.OperationPhaseCUSelectPriorObserverStarted,
			hostruntime.OperationPhaseCUSelectPriorZeroProven,
			hostruntime.OperationPhaseCUSelectCandidateRemoved,
			hostruntime.OperationPhaseCompUpgradeRestored:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func transitionCurrentSelectionAdmissible(
	binding hostruntime.OperationBinding,
	continuation bool,
	phase hostruntime.OperationPhase,
	current releaseBundleSnapshot,
	present bool,
	manifestDigest string,
	revision string,
) bool {
	if present {
		return current.manifestDigest == manifestDigest &&
			current.overlayRevision == revision
	}
	if !continuation || binding.Kind != hostruntime.OperationKindUninstall {
		return false
	}
	switch phase {
	case hostruntime.OperationPhaseRegistrationRemoved,
		hostruntime.OperationPhaseRetentionProven,
		hostruntime.OperationPhaseComplete:
		return true
	default:
		return false
	}
}

func newTransitionProcessAuthority(
	store *PinnedProcessRecordStore,
	kernel ProcessKernel,
	overlay hostruntime.PrivateOverlay,
	revision string,
	manifest hostruntime.RuntimeManifest,
	manifestDigest string,
	fenceGeneration uint64,
	pollInterval time.Duration,
	processGrace time.Duration,
) (*ProcessAuthority, string, error) {
	releaseOverlayPath := filepath.Join(
		overlay.Paths.ReleaseRoot,
		manifestDigest,
		releaseOverlayName,
	)
	controllerDigest, err := digestPinnedExecutable(
		overlay.Commands.ControllerBinary,
	)
	if err != nil || controllerDigest != manifest.ControllerSHA256 {
		return nil, "", ErrProtocol
	}
	authority, err := NewProcessAuthority(ProcessAuthorityConfig{
		Store:  store,
		Kernel: kernel,
		Binding: ProcessBinding{
			PrivateOverlayRevision: revision,
			ManifestDigest:         manifestDigest,
			ActiveFleet:            fleetfence.FleetPortable,
			FenceGeneration:        fenceGeneration,
		},
		Launch: ControllerLaunch{
			ControllerBinary: overlay.Commands.ControllerBinary,
			PrivateOverlay:   releaseOverlayPath,
			DatabasePath:     overlay.Paths.DatabasePath,
			StdoutLog:        filepath.Join(overlay.Paths.LogRoot, "controller.stdout.log"),
			StderrLog:        filepath.Join(overlay.Paths.LogRoot, "controller.stderr.log"),
			ExecutableDigest: controllerDigest,
		},
		Timing: ProcessTiming{
			PollInterval: pollInterval,
			TermGrace:    processGrace,
			KillGrace:    processGrace,
			CleanupGrace: processGrace,
		},
	})
	return authority, releaseOverlayPath, err
}

func (target *systemLifecycleTarget) preAdmission(
	ctx context.Context,
	action cli.HostAction,
	continuationPhase hostruntime.OperationPhase,
	continuation bool,
) error {
	if target == nil || ctx == nil || ctx.Err() != nil {
		return ErrLifecycleEffects
	}
	if target.requiresHostedHoldForPhase(continuationPhase, continuation) &&
		target.revalidateHosted(ctx) != nil {
		return ErrLifecycleEffects
	}
	effect := effectPreflight
	if continuation {
		var ok bool
		effect, ok = productionPhaseEffects[continuationPhase]
		if !ok {
			return ErrLifecycleEffects
		}
	}
	snapshot, err := target.snapshotTransition(ctx, effect)
	if err != nil {
		return ErrLifecycleEffects
	}
	if continuation {
		if target.effectState(effect, snapshot) ==
			hostruntime.LifecycleEffectAmbiguous {
			return ErrLifecycleEffects
		}
		return nil
	}
	if target.effectState(effectPreflight, snapshot) !=
		hostruntime.LifecycleEffectPresent {
		return ErrLifecycleEffects
	}
	_ = action
	return nil
}

func (target *systemLifecycleTarget) requiresHostedHold() bool {
	return target != nil &&
		(target.operationKind() == hostruntime.OperationKindSuspend ||
			target.operationKind() == hostruntime.OperationKindRollback)
}

func (target *systemLifecycleTarget) requiresHostedHoldForPhase(
	phase hostruntime.OperationPhase,
	continuation bool,
) bool {
	return target.requiresHostedHold() &&
		(!continuation || !isProductionCompensationPhase(phase))
}

func (target *systemLifecycleTarget) revalidateHosted(ctx context.Context) error {
	if target == nil || target.hosted == nil ||
		target.hostedExpectation.EvidenceDigest == "" {
		return ErrLifecycleEffects
	}
	validation := target.hosted.Validate(ctx, target.hostedExpectation)
	if validation.Validity != AuthorityValid ||
		validation.EvidenceDigest != target.hostedExpectation.EvidenceDigest {
		return ErrLifecycleEffects
	}
	return nil
}

func (resources *systemLifecycleResources) Close() error {
	if resources == nil {
		return nil
	}
	var result error
	if resources.lifecycle != nil {
		result = errors.Join(result, resources.lifecycle.Close())
		resources.lifecycle = nil
	}
	if resources.watchdog != nil {
		result = errors.Join(result, resources.watchdog.Close())
		resources.watchdog = nil
	}
	if resources.processStore != nil {
		result = errors.Join(result, resources.processStore.Close())
		resources.processStore = nil
	}
	if resources.fence != nil {
		result = errors.Join(result, resources.fence.Close())
		resources.fence = nil
	}
	if resources.releases != nil {
		result = errors.Join(result, resources.releases.Close())
		resources.releases = nil
	}
	return result
}

func (target *systemLifecycleTarget) observe(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	effect productionEffect,
) (hostruntime.LifecycleEffectObservation, error) {
	if target == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		!target.bindingMatches(binding) {
		return hostruntime.LifecycleEffectObservation{},
			ErrLifecycleEffects
	}
	if target.requiresHostedHoldForPhase(phase, true) &&
		target.revalidateHosted(ctx) != nil {
		return hostruntime.LifecycleEffectObservation{}, ErrLifecycleEffects
	}
	snapshot, err := target.snapshot(ctx, phase, effect)
	if err != nil {
		return hostruntime.LifecycleEffectObservation{},
			errors.Join(ErrLifecycleEffects, err)
	}
	state := target.effectStateForPhase(phase, effect, snapshot)
	if state != hostruntime.LifecycleEffectPresent {
		return hostruntime.LifecycleEffectObservation{
			State: state,
		}, nil
	}
	postcondition, err := target.postcondition(
		binding,
		phase,
		snapshot,
	)
	if err != nil {
		return hostruntime.LifecycleEffectObservation{},
			errors.Join(ErrLifecycleEffects, err)
	}
	return hostruntime.LifecycleEffectObservation{
		State:         hostruntime.LifecycleEffectPresent,
		Postcondition: &postcondition,
	}, nil
}

func (target *systemLifecycleTarget) effectState(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) hostruntime.LifecycleEffectState {
	if target.effectPresent(effect, snapshot) {
		return hostruntime.LifecycleEffectPresent
	}
	if target.effectAbsent(effect, snapshot) {
		return hostruntime.LifecycleEffectAbsent
	}
	return hostruntime.LifecycleEffectAmbiguous
}

func (target *systemLifecycleTarget) effectStateForPhase(
	phase hostruntime.OperationPhase,
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) hostruntime.LifecycleEffectState {
	if !isProductionCompensationPhase(phase) {
		return target.effectState(effect, snapshot)
	}
	if target.compensationEffectPresent(phase, snapshot) {
		return hostruntime.LifecycleEffectPresent
	}
	if target.compensationEffectAbsent(phase, snapshot) {
		return hostruntime.LifecycleEffectAbsent
	}
	return hostruntime.LifecycleEffectAmbiguous
}

func (target *systemLifecycleTarget) apply(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	effect productionEffect,
) error {
	if target == nil || ctx == nil || ctx.Err() != nil ||
		!target.bindingMatches(binding) || productionPhaseEffects[phase] != effect {
		return ErrLifecycleEffects
	}
	if target.requiresHostedHoldForPhase(phase, true) &&
		target.revalidateHosted(ctx) != nil {
		return ErrLifecycleEffects
	}
	snapshot, err := target.snapshot(ctx, phase, effect)
	if err != nil {
		return ErrLifecycleEffects
	}
	switch target.effectStateForPhase(phase, effect, snapshot) {
	case hostruntime.LifecycleEffectPresent:
		return nil
	case hostruntime.LifecycleEffectAbsent:
	default:
		return ErrLifecycleEffects
	}
	if target.requiresHostedHoldForPhase(phase, true) &&
		target.revalidateHosted(ctx) != nil {
		return ErrLifecycleEffects
	}
	if isProductionCompensationPhase(phase) {
		return target.applyCompensation(ctx, binding, phase, snapshot)
	}
	switch target.operationKind() {
	case hostruntime.OperationKindInstall:
		return target.applyInstall(ctx, binding, effect)
	case hostruntime.OperationKindResume:
		return target.applyResume(ctx, binding, effect, snapshot)
	case hostruntime.OperationKindSuspend:
		return target.applySuspend(ctx, binding, effect, snapshot)
	case hostruntime.OperationKindUninstall:
		return target.applyUninstall(ctx, binding, effect, snapshot)
	default:
		return ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) bindingMatches(
	binding hostruntime.OperationBinding,
) bool {
	if target == nil || binding.Kind != target.operationKind() ||
		binding.PrivateOverlayRevision != target.revision {
		return false
	}
	if _, _, err := hostruntime.MarshalOperationBinding(binding); err != nil {
		return false
	}
	switch binding.Kind {
	case hostruntime.OperationKindInstall:
		return binding.InstallDisposition != nil &&
			*binding.InstallDisposition == target.disposition &&
			(target.disposition ==
				hostruntime.InstallDispositionGreenfieldPortable ||
				target.disposition ==
					hostruntime.InstallDispositionUpgradePortable) &&
			binding.TargetManifestDigest != nil &&
			*binding.TargetManifestDigest == target.manifestDigest
	case hostruntime.OperationKindResume:
		return binding.InstallDisposition == nil &&
			binding.ExpectedGeneration == target.entryFence &&
			binding.PriorManifestDigest != nil &&
			*binding.PriorManifestDigest == target.manifestDigest &&
			binding.TargetManifestDigest != nil &&
			*binding.TargetManifestDigest == target.manifestDigest &&
			binding.TargetFleet == fleetfence.FleetPortable &&
			target.entryFence != ^uint64(0) &&
			target.terminalFence == target.entryFence+1
	case hostruntime.OperationKindSuspend:
		return binding.InstallDisposition == nil &&
			binding.ExpectedGeneration == target.entryFence &&
			binding.PriorManifestDigest != nil &&
			*binding.PriorManifestDigest == target.manifestDigest &&
			binding.TargetManifestDigest == nil &&
			binding.TargetFleet == fleetfence.FleetNone &&
			target.terminalFleet == fleetfence.FleetNone &&
			target.entryFence != ^uint64(0) &&
			target.terminalFence == target.entryFence+1
	case hostruntime.OperationKindUninstall:
		return binding.InstallDisposition == nil &&
			binding.ExpectedGeneration == target.entryFence &&
			binding.PriorManifestDigest != nil &&
			*binding.PriorManifestDigest == target.manifestDigest &&
			binding.TargetManifestDigest == nil &&
			binding.TargetFleet == target.terminalFleet &&
			target.terminalFence == target.entryFence && target.retainState
	default:
		return false
	}
}

func (target *systemLifecycleTarget) applyInstall(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	effect productionEffect,
) error {
	if target == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		binding.Kind != hostruntime.OperationKindInstall {
		return ErrLifecycleEffects
	}
	switch effect {
	case effectCandidateStaged:
		if target.artifacts == nil || target.releases == nil {
			return ErrLifecycleEffects
		}
		images, err := target.artifacts.VerifyImages(ctx, target.overlay)
		if err != nil {
			return ErrLifecycleEffects
		}
		receipt, err := marshalImageVerificationReceipt(
			target.manifestDigest,
			target.revision,
			images,
		)
		if err != nil || validateImageVerificationReceipt(
			receipt,
			target.manifestDigest,
			target.revision,
			target.overlay.Docker,
		) != nil {
			return ErrLifecycleEffects
		}
		overlayDocument, revision, err :=
			hostruntime.MarshalPrivateOverlay(target.overlay)
		if err != nil || revision != target.revision {
			return ErrLifecycleEffects
		}
		manifestDocument, manifestDigest, err :=
			hostruntime.MarshalRuntimeManifest(target.manifest)
		if err != nil || manifestDigest != target.manifestDigest ||
			ctx.Err() != nil {
			return ErrLifecycleEffects
		}
		if err := target.releases.Stage(
			target.manifestDigest,
			target.revision,
			overlayDocument,
			manifestDocument,
		); err != nil || ctx.Err() != nil {
			return ErrLifecycleEffects
		}
		if err := target.releases.WriteStagedReceipt(
			target.manifestDigest,
			releaseImageVerificationReceiptName,
			receipt,
		); err != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectCandidateSmoked:
		if target.artifacts == nil || target.releases == nil ||
			target.verifyCandidateStage() != nil {
			return ErrLifecycleEffects
		}
		version, err := target.artifacts.SmokeRunner(ctx, target.overlay)
		if err != nil {
			return ErrLifecycleEffects
		}
		receipt, err := marshalRunnerSmokeReceipt(
			target.manifestDigest,
			target.revision,
			target.overlay.Docker.RunnerImage,
			version,
		)
		if err != nil || ctx.Err() != nil {
			return ErrLifecycleEffects
		}
		if err := target.releases.WriteStagedReceipt(
			target.manifestDigest,
			releaseRunnerSmokeReceiptName,
			receipt,
		); err != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectCandidatePromoted:
		return target.releases.Promote(
			target.manifestDigest,
			target.revision,
		)
	case effectFencePortable:
		if target.disposition !=
			hostruntime.InstallDispositionGreenfieldPortable {
			return ErrLifecycleEffects
		}
		request := fleetfence.HandoffRequest{
			From:               fleetfence.FleetNone,
			To:                 fleetfence.FleetPortable,
			ExpectedGeneration: 0,
		}
		request.OperationID = fleetfence.HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		)
		header, err := target.fence.Handoff(ctx, request)
		if err != nil ||
			header.Generation != target.terminalFence ||
			header.ActiveFleet != fleetfence.FleetPortable {
			return ErrLifecycleEffects
		}
		return nil
	case effectPriorAcquisitionDisabled:
		if target.disposition !=
			hostruntime.InstallDispositionUpgradePortable ||
			target.priorAdmin == nil {
			return ErrLifecycleEffects
		}
		status, err := target.priorAdmin.Disable(ctx)
		if err != nil ||
			status.Mode != controller.AcquisitionDisabled ||
			status.Capacity != 0 {
			return ErrLifecycleEffects
		}
		return nil
	case effectPriorDrained:
		if target.disposition !=
			hostruntime.InstallDispositionUpgradePortable ||
			target.priorAdmin == nil ||
			target.priorAdmin.Drain(ctx, "wait") != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectPriorControllerStopped:
		if target.disposition !=
			hostruntime.InstallDispositionUpgradePortable ||
			target.priorProcess == nil {
			return ErrLifecycleEffects
		}
		inspection, err := target.priorProcess.Inspect(ctx)
		if err != nil || inspection.State != ProcessRunning ||
			!lowerHexDigest(inspection.ProcessIdentity) ||
			target.priorProcess.Stop(
				ctx,
				inspection.ProcessIdentity,
			) != nil {
			return ErrLifecycleEffects
		}
		return nil
	case effectWatchdogInstalled:
		if target.disposition ==
			hostruntime.InstallDispositionUpgradePortable {
			if target.priorOverlay == nil {
				return ErrLifecycleEffects
			}
			return target.watchdog.Replace(
				watchdogMarkerBinding{
					PrivateOverlayRevision: target.priorRevision,
					ManifestDigest:         target.priorManifestDigest,
					WatchdogBinary:         target.priorOverlay.Commands.WatchdogBinary,
				},
				watchdogMarkerBinding{
					PrivateOverlayRevision: target.revision,
					ManifestDigest:         target.manifestDigest,
					WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
				},
			)
		}
		return target.watchdog.Install(watchdogMarkerBinding{
			PrivateOverlayRevision: target.revision,
			ManifestDigest:         target.manifestDigest,
			WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
		})
	case effectObserverStarted:
		inspection, err := target.process.StartDisabled(ctx)
		if err != nil ||
			inspection.State != ProcessRunning ||
			!lowerHexDigest(inspection.ProcessIdentity) {
			return ErrLifecycleEffects
		}
		return nil
	case effectZeroProven:
		return target.waitForZero(ctx)
	case effectCurrentSelected:
		return target.releases.Select(
			target.manifestDigest,
			target.revision,
		)
	default:
		return ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) applyResume(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) error {
	switch effect {
	case effectFencePortable:
		request := fleetfence.HandoffRequest{
			From:               fleetfence.FleetNone,
			To:                 fleetfence.FleetPortable,
			ExpectedGeneration: binding.ExpectedGeneration,
		}
		request.OperationID = fleetfence.HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		)
		header, err := target.fence.Handoff(ctx, request)
		if err != nil || header.Generation != target.terminalFence ||
			header.ActiveFleet != fleetfence.FleetPortable {
			return ErrLifecycleEffects
		}
		return nil
	case effectObserverStarted:
		if target.process == nil {
			return ErrLifecycleEffects
		}
		inspection, err := target.process.StartDisabled(ctx)
		if err != nil || inspection.State != ProcessRunning ||
			!lowerHexDigest(inspection.ProcessIdentity) {
			return ErrLifecycleEffects
		}
		return nil
	case effectWatchdogInstalled:
		return target.watchdog.Install(target.watchdogBinding())
	case effectZeroProven:
		return target.waitForZero(ctx)
	default:
		_ = snapshot
		return ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) applyUninstall(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) error {
	_ = binding
	switch effect {
	case effectWatchdogRemoved:
		return target.watchdog.Remove(target.watchdogBinding())
	case effectControllerRemoved:
		if target.process == nil || !snapshot.processPresent ||
			!snapshot.processTarget ||
			!lowerHexDigest(snapshot.processIdentity) {
			return ErrLifecycleEffects
		}
		return target.process.Stop(ctx, snapshot.processIdentity)
	case effectRegistrationRemoved:
		return target.releases.ClearCurrent(
			target.manifestDigest,
			target.revision,
		)
	default:
		return ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) applySuspend(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) error {
	switch effect {
	case effectWatchdogDisabled:
		return target.watchdog.Remove(target.watchdogBinding())
	case effectPolicyDisabled:
		status, err := target.admin.Disable(ctx)
		if err != nil || status.Mode != controller.AcquisitionDisabled ||
			status.Capacity != 0 {
			return ErrLifecycleEffects
		}
		return nil
	case effectDrained:
		if target.drainPolicy != "wait" && target.drainPolicy != "cancel" {
			return ErrLifecycleEffects
		}
		return target.admin.Drain(ctx, target.drainPolicy)
	case effectControllerStopped:
		if !snapshot.processPresent || !snapshot.processTarget ||
			!lowerHexDigest(snapshot.processIdentity) {
			return ErrLifecycleEffects
		}
		return target.process.Stop(ctx, snapshot.processIdentity)
	case effectFenceNone:
		request := fleetfence.HandoffRequest{
			From:               fleetfence.FleetPortable,
			To:                 fleetfence.FleetNone,
			ExpectedGeneration: binding.ExpectedGeneration,
		}
		request.OperationID = fleetfence.HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		)
		header, err := target.fence.Handoff(ctx, request)
		if err != nil || header.Generation != target.terminalFence ||
			header.ActiveFleet != fleetfence.FleetNone {
			return ErrLifecycleEffects
		}
		return nil
	default:
		return ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) watchdogBinding() watchdogMarkerBinding {
	return watchdogMarkerBinding{
		PrivateOverlayRevision: target.revision,
		ManifestDigest:         target.manifestDigest,
		WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
	}
}

func (target *systemLifecycleTarget) verifyCandidateStage() error {
	if target == nil || target.releases == nil {
		return ErrLifecycleEffects
	}
	_, present, err := target.releases.InspectStaged(
		target.manifestDigest,
		target.revision,
	)
	if err != nil || !present {
		return ErrLifecycleEffects
	}
	document, present, err := target.releases.InspectStagedReceipt(
		target.manifestDigest,
		releaseImageVerificationReceiptName,
	)
	if err != nil || !present || validateImageVerificationReceipt(
		document,
		target.manifestDigest,
		target.revision,
		target.overlay.Docker,
	) != nil {
		return ErrLifecycleEffects
	}
	return nil
}

func (target *systemLifecycleTarget) snapshot(
	ctx context.Context,
	phase hostruntime.OperationPhase,
	effect productionEffect,
) (systemLifecycleSnapshot, error) {
	switch target.operationKind() {
	case hostruntime.OperationKindInstall:
		return target.snapshotInstall(ctx, phase, effect)
	case hostruntime.OperationKindSuspend,
		hostruntime.OperationKindResume,
		hostruntime.OperationKindUninstall:
		return target.snapshotTransition(ctx, effect)
	default:
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) snapshotInstall(
	ctx context.Context,
	phase hostruntime.OperationPhase,
	effect productionEffect,
) (systemLifecycleSnapshot, error) {
	var snapshot systemLifecycleSnapshot
	if target == nil || ctx == nil || ctx.Err() != nil {
		return snapshot, ErrLifecycleEffects
	}
	header, fencePresent, err := target.fence.InspectOptional(ctx)
	if err != nil {
		return snapshot, ErrLifecycleEffects
	}
	snapshot.fencePresent = fencePresent
	snapshot.fleet = fleetfence.FleetNone
	if fencePresent {
		snapshot.generation = header.Header.Generation
		snapshot.fleet = header.Header.ActiveFleet
	}
	_, snapshot.stagedPresent, err = target.releases.InspectStaged(
		target.manifestDigest,
		target.revision,
	)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	if snapshot.stagedPresent {
		verification, present, inspectErr :=
			target.releases.InspectStagedReceipt(
				target.manifestDigest,
				releaseImageVerificationReceiptName,
			)
		if inspectErr != nil {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		if present {
			if validateImageVerificationReceipt(
				verification,
				target.manifestDigest,
				target.revision,
				target.overlay.Docker,
			) != nil {
				return systemLifecycleSnapshot{}, ErrLifecycleEffects
			}
			snapshot.imagesVerified = true
		}
		smoke, present, inspectErr :=
			target.releases.InspectStagedReceipt(
				target.manifestDigest,
				releaseRunnerSmokeReceiptName,
			)
		if inspectErr != nil {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		if present {
			if validateRunnerSmokeReceipt(
				smoke,
				target.manifestDigest,
				target.revision,
				target.overlay.Docker.RunnerImage,
			) != nil {
				return systemLifecycleSnapshot{}, ErrLifecycleEffects
			}
			snapshot.runnerSmoked = true
		}
	}
	_, snapshot.releasedPresent, err =
		target.releases.InspectReleased(
			target.manifestDigest,
			target.revision,
		)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.current, snapshot.currentPresent, err =
		target.releases.Current()
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	targetWatchdog := watchdogMarkerBinding{
		PrivateOverlayRevision: target.revision,
		ManifestDigest:         target.manifestDigest,
		WatchdogBinary:         target.overlay.Commands.WatchdogBinary,
	}
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		if target.priorOverlay == nil || target.priorProcess == nil {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		priorWatchdog := watchdogMarkerBinding{
			PrivateOverlayRevision: target.priorRevision,
			ManifestDigest:         target.priorManifestDigest,
			WatchdogBinary:         target.priorOverlay.Commands.WatchdogBinary,
		}
		var matched int
		snapshot.watchdog, matched, snapshot.watchdogPresent, err =
			target.watchdog.InspectOneOf(priorWatchdog, targetWatchdog)
		if err == nil && snapshot.watchdogPresent {
			snapshot.watchdogPrior = matched == 0
			snapshot.watchdogTarget = matched == 1
		}
	} else {
		snapshot.watchdog, snapshot.watchdogPresent, err =
			target.watchdog.Inspect(targetWatchdog)
		snapshot.watchdogTarget = snapshot.watchdogPresent
	}
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	record, identity, recordPresent, err := target.processStore.Read(ctx)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	if recordPresent {
		var authority *ProcessAuthority
		switch {
		case target.priorProcess != nil &&
			processRecordMatchesBinding(record, target.priorProcess.binding):
			authority = target.priorProcess
			snapshot.processPrior = true
		case target.process != nil &&
			processRecordMatchesBinding(record, target.process.binding):
			authority = target.process
			snapshot.processTarget = true
		default:
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		inspection, inspectErr := authority.Inspect(ctx)
		if inspectErr != nil ||
			inspection.State != ProcessRunning ||
			identity != inspection.ProcessIdentity {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		snapshot.processPresent = true
		snapshot.processRecord = record
		snapshot.processIdentity = identity
	}
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		status, summary, inspectErr := target.inspectDurableState(ctx)
		if inspectErr != nil {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		snapshot.priorPolicy = status
		snapshot.policyEpoch = status.Epoch
		snapshot.assignedJobs = summary.AssignedJobs
		snapshot.runningJobs = summary.RunningJobs
		snapshot.activeListeners = summary.UnassignedReleasedListeners
		snapshot.priorDrained = summary.RunningJobs == 0 &&
			summary.UnassignedReleasedListeners == 0
		if snapshot.processPrior {
			live, liveErr := target.priorAdmin.Policy(ctx)
			if liveErr != nil || live != status {
				return systemLifecycleSnapshot{}, ErrLifecycleEffects
			}
		}
	}
	if target.effectRequiresManagedQuiescence(effect) {
		if err := target.docker.ProveManagedQuiescence(ctx); err != nil {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
	}
	availability, err := target.storage.Snapshot(ctx)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.filesystems = make(
		[]hostruntime.LifecycleFilesystemIdentity,
		len(availability),
	)
	for index, observation := range availability {
		snapshot.filesystems[index] = observation.Filesystem
	}
	if snapshot.policyEpoch == 0 {
		snapshot.policyEpoch = target.overlay.Resources.PolicyRevision
	}
	zeroProbe, requireProcess, requireZeroProbe :=
		target.installZeroProbe(phase, effect, snapshot)
	if requireZeroProbe {
		if requireProcess && !snapshot.processPresent {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		observation, observeErr := observeDisabledZero(ctx, zeroProbe)
		if observeErr != nil {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		if target.disposition ==
			hostruntime.InstallDispositionUpgradePortable &&
			(observation.PolicyEpoch != snapshot.priorPolicy.Epoch ||
				observation.PolicyDigest != snapshot.priorPolicy.Digest ||
				snapshot.priorPolicy.Mode != controller.AcquisitionDisabled ||
				snapshot.priorPolicy.Capacity != 0) {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		snapshot.zero = true
		snapshot.policyEpoch = observation.PolicyEpoch
	}
	return snapshot, nil
}

func (target *systemLifecycleTarget) installZeroProbe(
	phase hostruntime.OperationPhase,
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) (DisabledControllerProbe, bool, bool) {
	if !isProductionCompensationPhase(phase) {
		required := effect == effectZeroProven ||
			effect == effectCurrentSelected || effect == effectVerified
		return target.probe, true, required
	}
	switch phase {
	case hostruntime.OperationPhaseCGPreAbsenceProven,
		hostruntime.OperationPhaseCompGreenfieldAbsent,
		hostruntime.OperationPhaseCGFenceQuiescenceProven,
		hostruntime.OperationPhaseCGFenceNone,
		hostruntime.OperationPhaseCGFenceCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldNone,
		hostruntime.OperationPhaseCGSelectQuiescenceProven,
		hostruntime.OperationPhaseCGSelectCurrentRemoved,
		hostruntime.OperationPhaseCGSelectNone,
		hostruntime.OperationPhaseCGSelectCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldSelected,
		hostruntime.OperationPhaseCUSelectQuiescenceProven,
		hostruntime.OperationPhaseCUSelectPriorRestored:
		return target.probe, false, true
	case hostruntime.OperationPhaseCUPrePriorDisabledProven,
		hostruntime.OperationPhaseCompUpgradePrior,
		hostruntime.OperationPhaseCUSelectPriorZeroProven,
		hostruntime.OperationPhaseCUSelectCandidateRemoved,
		hostruntime.OperationPhaseCompUpgradeRestored:
		if target.priorAdmin == nil {
			return nil, false, true
		}
		return target.priorAdmin, snapshot.processPrior, true
	default:
		return nil, false, false
	}
}

func (target *systemLifecycleTarget) snapshotTransition(
	ctx context.Context,
	effect productionEffect,
) (systemLifecycleSnapshot, error) {
	var snapshot systemLifecycleSnapshot
	if target == nil || ctx == nil || ctx.Err() != nil ||
		target.releases == nil || target.fence == nil || target.storage == nil ||
		target.docker == nil || target.processStore == nil ||
		target.watchdog == nil || target.process == nil || target.probe == nil ||
		target.admin == nil {
		return snapshot, ErrLifecycleEffects
	}
	header, present, err := target.fence.InspectOptional(ctx)
	if err != nil || !present {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.fencePresent = true
	snapshot.generation = header.Header.Generation
	snapshot.fleet = header.Header.ActiveFleet
	_, snapshot.releasedPresent, err = target.releases.InspectReleased(
		target.manifestDigest,
		target.revision,
	)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.current, snapshot.currentPresent, err = target.releases.Current()
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.watchdog, snapshot.watchdogPresent, err =
		target.watchdog.Inspect(target.watchdogBinding())
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.watchdogTarget = snapshot.watchdogPresent
	record, identity, recordPresent, err := target.processStore.Read(ctx)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	if recordPresent {
		if !processRecordMatchesBinding(record, target.process.binding) {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		inspection, inspectErr := target.process.Inspect(ctx)
		if inspectErr != nil || inspection.State != ProcessRunning ||
			inspection.ProcessIdentity != identity {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		snapshot.processPresent = true
		snapshot.processTarget = true
		snapshot.processRecord = record
		snapshot.processIdentity = identity
	}
	status, summary, err := target.inspectDurableState(ctx)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.priorPolicy = status
	snapshot.policyEpoch = status.Epoch
	snapshot.assignedJobs = summary.AssignedJobs
	snapshot.runningJobs = summary.RunningJobs
	snapshot.activeListeners = summary.UnassignedReleasedListeners
	snapshot.priorDrained = summary.RunningJobs == 0 &&
		summary.UnassignedReleasedListeners == 0
	if snapshot.processPresent {
		live, liveErr := target.admin.Policy(ctx)
		if liveErr != nil || live != status {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
	}
	if target.effectRequiresManagedQuiescence(effect) &&
		target.docker.ProveManagedQuiescence(ctx) != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	availability, err := target.storage.Snapshot(ctx)
	if err != nil {
		return systemLifecycleSnapshot{}, ErrLifecycleEffects
	}
	snapshot.filesystems = make(
		[]hostruntime.LifecycleFilesystemIdentity,
		len(availability),
	)
	for index, observation := range availability {
		snapshot.filesystems[index] = observation.Filesystem
	}
	requireZero := effect == effectZeroProven || effect == effectVerified
	if requireZero {
		if !snapshot.processTarget {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		observation, observeErr := observeDisabledZero(ctx, target.probe)
		if observeErr != nil || observation.PolicyEpoch != status.Epoch ||
			observation.PolicyDigest != status.Digest ||
			status.Mode != controller.AcquisitionDisabled || status.Capacity != 0 {
			return systemLifecycleSnapshot{}, ErrLifecycleEffects
		}
		snapshot.zero = true
	}
	return snapshot, nil
}

func (target *systemLifecycleTarget) inspectDurableState(
	ctx context.Context,
) (controller.PolicyStatus, state.OperationalSummary, error) {
	var empty state.OperationalSummary
	limits, err := lifecycleHistoryLimits(target.overlay.Resources.History)
	if err != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	store, err := state.OpenReadOnlyWithHistoryLimits(
		target.overlay.Paths.DatabasePath,
		limits,
	)
	if err != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	policy, policyErr := store.AcquisitionPolicy(ctx)
	summary, summaryErr := store.OperationalSummary(ctx, target.now())
	closeErr := store.Close()
	if policyErr != nil || summaryErr != nil || closeErr != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	canonical, err := controller.CanonicalizeAcquisitionPolicy(policy)
	if err != nil || canonical.Epoch == 0 {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	digest, err := controller.AcquisitionPolicyDigest(canonical)
	if err != nil {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	status := controller.PolicyStatus{
		Mode:     canonical.Mode,
		Epoch:    canonical.Epoch,
		Digest:   hex.EncodeToString(digest[:]),
		Capacity: canonical.MaxCapacity,
	}
	if !validControllerPolicyStatus(status) {
		return controller.PolicyStatus{}, empty, ErrLifecycleEffects
	}
	return status, summary, nil
}

func lifecycleHistoryLimits(
	history hostruntime.HistoryOverlay,
) (state.HistoryLimits, error) {
	minRetention, err := time.ParseDuration(history.MinRetention)
	if err != nil {
		return state.HistoryLimits{}, ErrLifecycleEffects
	}
	maintenanceCadence, err := time.ParseDuration(history.MaintenanceCadence)
	if err != nil {
		return state.HistoryLimits{}, ErrLifecycleEffects
	}
	limits := state.HistoryLimits{
		MinRetention:                 minRetention,
		MaxHistoryRows:               history.MaxHistoryRows,
		MaxHistoryLogicalBytes:       history.MaxHistoryLogicalBytes,
		MaxNetworkLedgerRows:         history.MaxNetworkLedgerRows,
		MaxNetworkLedgerLogicalBytes: history.MaxNetworkLedgerLogicalBytes,
		InflightReserveRows:          history.InflightReserveRows,
		InflightReserveLogicalBytes:  history.InflightReserveLogicalBytes,
		GCBatchRows:                  history.GCBatchRows,
		NetworkGCBatchRows:           history.NetworkGCBatchRows,
		VacuumBatchPages:             history.VacuumBatchPages,
		MaintenanceCadence:           maintenanceCadence,
	}
	if state.ValidateHistoryLimits(limits) != nil {
		return state.HistoryLimits{}, ErrLifecycleEffects
	}
	return limits, nil
}

func (target *systemLifecycleTarget) effectRequiresManagedQuiescence(
	effect productionEffect,
) bool {
	switch target.operationKind() {
	case hostruntime.OperationKindSuspend:
		switch effect {
		case effectQuiescenceProven,
			effectFenceNone,
			effectVerified,
			effectNoneDisabledProven,
			effectCompensated:
			return true
		default:
			return false
		}
	case hostruntime.OperationKindResume,
		hostruntime.OperationKindUninstall:
		return true
	case hostruntime.OperationKindInstall:
	default:
		return false
	}
	if target.disposition ==
		hostruntime.InstallDispositionGreenfieldPortable {
		return true
	}
	switch effect {
	case effectPriorQuiescenceProven,
		effectFencePortableProven,
		effectWatchdogInstalled,
		effectPolicyDisabled,
		effectObserverStarted,
		effectZeroProven,
		effectCurrentSelected,
		effectVerified,
		effectQuiescenceProven,
		effectCurrentRemoved,
		effectFenceNone,
		effectCandidateRemoved,
		effectPriorSelectionProven,
		effectPriorDisabledProven,
		effectPriorRestored,
		effectPriorObserverStarted,
		effectPriorZeroProven,
		effectCompensated:
		return true
	default:
		return false
	}
}

func observeDisabledZero(
	ctx context.Context,
	probe DisabledControllerProbe,
) (DisabledControllerObservation, error) {
	if ctx == nil || ctx.Err() != nil || probe == nil {
		return DisabledControllerObservation{}, ErrLifecycleEffects
	}
	return probe.Observe(ctx)
}

func activeReservationView(
	persisted hostruntime.StorageReservation,
) (hostruntime.StorageReservation, error) {
	if _, _, err := hostruntime.MarshalStorageReservation(persisted); err != nil {
		return hostruntime.StorageReservation{}, ErrLifecycleEffects
	}
	view := persisted
	view.State = hostruntime.ReservationStateActive
	view.CommittedTargetProofDigest = nil
	view.ReleasedAbsenceProofDigest = nil
	if _, _, err := hostruntime.MarshalStorageReservation(view); err != nil {
		return hostruntime.StorageReservation{}, ErrLifecycleEffects
	}
	return view, nil
}

type greenfieldContinuation struct {
	journal     hostruntime.OperationJournal
	reservation hostruntime.StorageReservation
}

type greenfieldReservationChoice struct {
	persisted           hostruntime.StorageReservation
	request             hostruntime.StorageReservation
	continuation        greenfieldContinuation
	continuationPresent bool
}

type greenfieldReservationBuilder func() (
	hostruntime.StorageReservation,
	error,
)

func selectGreenfieldReservation(
	store *hostruntime.LifecycleStore,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
	buildFresh greenfieldReservationBuilder,
) (greenfieldReservationChoice, error) {
	if buildFresh == nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	continuation, present, err := readGreenfieldContinuation(
		store,
		binding,
		priorManifest,
		manifest,
	)
	if err != nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	if present {
		request, err := activeReservationView(continuation.reservation)
		if err != nil {
			return greenfieldReservationChoice{}, ErrLifecycleEffects
		}
		return greenfieldReservationChoice{
			persisted:           continuation.reservation,
			request:             request,
			continuation:        continuation,
			continuationPresent: true,
		}, nil
	}
	fresh, err := buildFresh()
	if err != nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	if fresh.State != hostruntime.ReservationStateActive ||
		validateGreenfieldReservation(fresh, binding, manifest) != nil {
		return greenfieldReservationChoice{}, ErrLifecycleEffects
	}
	return greenfieldReservationChoice{
		persisted: fresh,
		request:   fresh,
	}, nil
}

func selectLifecycleReservation(
	store *hostruntime.LifecycleStore,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	targetManifest *hostruntime.RuntimeManifest,
	storageManifest hostruntime.RuntimeManifest,
	buildFresh greenfieldReservationBuilder,
) (greenfieldReservationChoice, error) {
	var empty greenfieldReservationChoice
	if store == nil || buildFresh == nil ||
		!lifecycleManifestMatchesDigest(
			priorManifest,
			binding.PriorManifestDigest,
		) || !lifecycleManifestMatchesDigest(
		targetManifest,
		binding.TargetManifestDigest,
	) {
		return empty, ErrLifecycleEffects
	}
	journalDocument, journalErr := store.ReadCanonical(
		hostruntime.LifecycleJournals,
		binding.OperationID+".journal.json",
		maximumProductionLifecycleJournalBytes,
	)
	reservationDocument, reservationErr := store.ReadCanonical(
		hostruntime.LifecycleReservations,
		binding.OperationID+".reservation.json",
		maximumProductionLifecycleReservationBytes,
	)
	journalAbsent := errors.Is(journalErr, hostruntime.ErrLifecycleStateAbsent)
	reservationAbsent := errors.Is(
		reservationErr,
		hostruntime.ErrLifecycleStateAbsent,
	)
	if journalAbsent && reservationAbsent {
		fresh, err := buildFresh()
		if err != nil || validateLifecycleReservationForBinding(
			fresh,
			binding,
			storageManifest,
		) != nil {
			return empty, ErrLifecycleEffects
		}
		return greenfieldReservationChoice{
			persisted: fresh,
			request:   fresh,
		}, nil
	}
	if journalErr != nil || reservationErr != nil {
		return empty, ErrLifecycleEffects
	}
	journal, _, err := hostruntime.ParseOperationJournal(
		journalDocument,
		maximumProductionLifecycleJournalBytes,
	)
	if err != nil ||
		hostruntime.ValidateOperationJournalAgainstBinding(journal, binding) != nil ||
		!manifestPointersEqualForLifecycle(journal.PriorManifest, priorManifest) ||
		!manifestPointersEqualForLifecycle(journal.TargetManifest, targetManifest) {
		return empty, ErrLifecycleEffects
	}
	reservation, _, err := hostruntime.ParseStorageReservation(
		reservationDocument,
		maximumProductionLifecycleReservationBytes,
	)
	if err != nil || validateLifecycleReservationForBinding(
		reservation,
		binding,
		storageManifest,
	) != nil {
		return empty, ErrLifecycleEffects
	}
	request, err := activeReservationView(reservation)
	if err != nil {
		return empty, ErrLifecycleEffects
	}
	return greenfieldReservationChoice{
		persisted:           reservation,
		request:             request,
		continuation:        greenfieldContinuation{journal: journal, reservation: reservation},
		continuationPresent: true,
	}, nil
}

func lifecycleManifestMatchesDigest(
	manifest *hostruntime.RuntimeManifest,
	digest *string,
) bool {
	if manifest == nil || digest == nil {
		return manifest == nil && digest == nil
	}
	_, actual, err := hostruntime.MarshalRuntimeManifest(*manifest)
	return err == nil && actual == *digest
}

func validateLifecycleReservationForBinding(
	reservation hostruntime.StorageReservation,
	binding hostruntime.OperationBinding,
	manifest hostruntime.RuntimeManifest,
) error {
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil ||
		reservation.OperationID != binding.OperationID ||
		reservation.BindingDigest != bindingDigest ||
		reservation.StorageBudgetDigest != manifest.StorageBudgetDigest ||
		!digestPointersEqual(
			reservation.TargetManifestDigest,
			binding.TargetManifestDigest,
		) {
		return ErrLifecycleEffects
	}
	if _, _, err := hostruntime.MarshalStorageReservation(reservation); err != nil {
		return ErrLifecycleEffects
	}
	return nil
}

func digestPointersEqual(left *string, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func readGreenfieldContinuation(
	store *hostruntime.LifecycleStore,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) (greenfieldContinuation, bool, error) {
	if store == nil ||
		binding.InstallDisposition == nil ||
		binding.TargetManifestDigest == nil ||
		binding.TargetFleet != fleetfence.FleetPortable {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil || manifestDigest != *binding.TargetManifestDigest {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	if priorManifest == nil && binding.PriorManifestDigest != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	if priorManifest != nil {
		_, priorDigest, err := hostruntime.MarshalRuntimeManifest(*priorManifest)
		if err != nil ||
			binding.PriorManifestDigest == nil ||
			priorDigest != *binding.PriorManifestDigest {
			return greenfieldContinuation{}, false, ErrLifecycleEffects
		}
	}
	journalDocument, journalErr := store.ReadCanonical(
		hostruntime.LifecycleJournals,
		binding.OperationID+".journal.json",
		maximumProductionLifecycleJournalBytes,
	)
	reservationDocument, reservationErr := store.ReadCanonical(
		hostruntime.LifecycleReservations,
		binding.OperationID+".reservation.json",
		maximumProductionLifecycleReservationBytes,
	)
	journalAbsent := errors.Is(
		journalErr,
		hostruntime.ErrLifecycleStateAbsent,
	)
	reservationAbsent := errors.Is(
		reservationErr,
		hostruntime.ErrLifecycleStateAbsent,
	)
	if journalAbsent && reservationAbsent {
		return greenfieldContinuation{}, false, nil
	}
	if journalErr != nil || reservationErr != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	journal, _, err := hostruntime.ParseOperationJournal(
		journalDocument,
		maximumProductionLifecycleJournalBytes,
	)
	if err != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	reservation, _, err := hostruntime.ParseStorageReservation(
		reservationDocument,
		maximumProductionLifecycleReservationBytes,
	)
	continuation := greenfieldContinuation{
		journal:     journal,
		reservation: reservation,
	}
	if err != nil || validateGreenfieldContinuation(
		continuation,
		binding,
		priorManifest,
		manifest,
	) != nil {
		return greenfieldContinuation{}, false, ErrLifecycleEffects
	}
	return continuation, true, nil
}

func validateGreenfieldContinuation(
	continuation greenfieldContinuation,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) error {
	if hostruntime.ValidateOperationJournalAgainstBinding(
		continuation.journal,
		binding,
	) != nil || !manifestPointersEqualForLifecycle(
		continuation.journal.PriorManifest,
		priorManifest,
	) || validateGreenfieldReservation(
		continuation.reservation,
		binding,
		manifest,
	) != nil {
		return ErrLifecycleEffects
	}
	if continuation.journal.CompensationPath != nil {
		if compensationTerminalPhase(continuation.journal.Phase) {
			if continuation.reservation.State !=
				hostruntime.ReservationStateActive &&
				continuation.reservation.State !=
					hostruntime.ReservationStateReleased {
				return ErrLifecycleEffects
			}
			return nil
		}
		if continuation.reservation.State !=
			hostruntime.ReservationStateActive {
			return ErrLifecycleEffects
		}
		return nil
	}
	if continuation.journal.Phase == hostruntime.OperationPhaseComplete {
		if continuation.reservation.State !=
			hostruntime.ReservationStateActive &&
			continuation.reservation.State !=
				hostruntime.ReservationStateCommitted {
			return ErrLifecycleEffects
		}
		return nil
	}
	if continuation.reservation.State !=
		hostruntime.ReservationStateActive {
		return ErrLifecycleEffects
	}
	return nil
}

func compensationTerminalPhase(phase hostruntime.OperationPhase) bool {
	switch phase {
	case hostruntime.OperationPhaseCompGreenfieldAbsent,
		hostruntime.OperationPhaseCompGreenfieldNone,
		hostruntime.OperationPhaseCompGreenfieldSelected,
		hostruntime.OperationPhaseCompUpgradePrior,
		hostruntime.OperationPhaseCompUpgradeRestored,
		hostruntime.OperationPhaseCompLegacyPrior,
		hostruntime.OperationPhaseCompLegacyRestored,
		hostruntime.OperationPhaseCompSuspendNone,
		hostruntime.OperationPhaseCompResumeNone,
		hostruntime.OperationPhaseCompRollbackNone,
		hostruntime.OperationPhaseCompRollbackLegacyNone:
		return true
	default:
		return false
	}
}

func manifestPointersEqualForLifecycle(
	left *hostruntime.RuntimeManifest,
	right *hostruntime.RuntimeManifest,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftDocument, leftDigest, leftErr :=
		hostruntime.MarshalRuntimeManifest(*left)
	rightDocument, rightDigest, rightErr :=
		hostruntime.MarshalRuntimeManifest(*right)
	return leftErr == nil &&
		rightErr == nil &&
		leftDigest == rightDigest &&
		string(leftDocument) == string(rightDocument)
}

func validateGreenfieldReservation(
	reservation hostruntime.StorageReservation,
	binding hostruntime.OperationBinding,
	manifest hostruntime.RuntimeManifest,
) error {
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		return ErrLifecycleEffects
	}
	_, manifestDigest, err := hostruntime.MarshalRuntimeManifest(manifest)
	if err != nil ||
		reservation.OperationID != binding.OperationID ||
		reservation.BindingDigest != bindingDigest ||
		reservation.TargetManifestDigest == nil ||
		*reservation.TargetManifestDigest != manifestDigest ||
		reservation.StorageBudgetDigest != manifest.StorageBudgetDigest {
		return ErrLifecycleEffects
	}
	if _, _, err := hostruntime.MarshalStorageReservation(
		reservation,
	); err != nil {
		return ErrLifecycleEffects
	}
	return nil
}

func verifyGreenfieldTerminal(
	ctx context.Context,
	store *hostruntime.LifecycleStore,
	effects hostruntime.LifecycleEffectAuthority,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || store == nil || effects == nil {
		return "", "", ErrLifecycleEffects
	}
	journalDigest, persisted, proofDigest, err :=
		readCommittedInstallProof(
			store,
			binding,
			priorManifest,
			manifest,
		)
	if err != nil {
		return "", "", ErrLifecycleEffects
	}
	observation, err := effects.Observe(
		ctx,
		binding,
		hostruntime.OperationPhaseComplete,
	)
	if err != nil ||
		observation.State != hostruntime.LifecycleEffectPresent ||
		observation.Postcondition == nil ||
		hostruntime.ValidateTargetPostconditionAgainstBinding(
			*observation.Postcondition,
			binding,
			hostruntime.OperationPhaseComplete,
		) != nil {
		return "", "", ErrLifecycleEffects
	}
	live := *observation.Postcondition
	live.ObservedAt = persisted.ObservedAt
	_, liveDigest, err := hostruntime.MarshalTargetPostcondition(live)
	if err != nil || liveDigest != proofDigest {
		return "", "", ErrLifecycleEffects
	}
	return journalDigest, proofDigest, nil
}

func readCommittedInstallProof(
	store *hostruntime.LifecycleStore,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) (string, hostruntime.TargetPostcondition, string, error) {
	var empty hostruntime.TargetPostcondition
	if store == nil {
		return "", empty, "", ErrLifecycleEffects
	}
	continuation, present, err := readGreenfieldContinuation(
		store,
		binding,
		priorManifest,
		manifest,
	)
	if err != nil ||
		!present ||
		continuation.journal.Phase !=
			hostruntime.OperationPhaseComplete ||
		continuation.reservation.State !=
			hostruntime.ReservationStateCommitted ||
		continuation.reservation.CommittedTargetProofDigest == nil {
		return "", empty, "", ErrLifecycleEffects
	}
	_, journalDigest, err := hostruntime.MarshalOperationJournal(
		continuation.journal,
	)
	if err != nil {
		return "", empty, "", ErrLifecycleEffects
	}
	effectKey, err := hostruntime.DeriveOperationEffectKey(
		binding,
		hostruntime.OperationPhaseComplete,
	)
	if err != nil {
		return "", empty, "", ErrLifecycleEffects
	}
	document, err := store.ReadCanonical(
		hostruntime.LifecycleReceipts,
		effectKey+".postcondition.json",
		maximumProductionLifecyclePostconditionBytes,
	)
	if err != nil {
		return "", empty, "", ErrLifecycleEffects
	}
	persisted, proofDigest, err := hostruntime.ParseTargetPostcondition(
		document,
		maximumProductionLifecyclePostconditionBytes,
	)
	if err != nil ||
		hostruntime.ValidateTargetPostconditionAgainstBinding(
			persisted,
			binding,
			hostruntime.OperationPhaseComplete,
		) != nil ||
		*continuation.reservation.CommittedTargetProofDigest != proofDigest {
		return "", empty, "", ErrLifecycleEffects
	}
	return journalDigest, persisted, proofDigest, nil
}

func verifyEvolvedInstallTerminal(
	ctx context.Context,
	store *hostruntime.LifecycleStore,
	effects hostruntime.LifecycleEffectAuthority,
	binding hostruntime.OperationBinding,
	priorManifest *hostruntime.RuntimeManifest,
	manifest hostruntime.RuntimeManifest,
) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || effects == nil {
		return "", "", ErrLifecycleEffects
	}
	journalDigest, _, _, err := readCommittedInstallProof(
		store,
		binding,
		priorManifest,
		manifest,
	)
	if err != nil {
		return "", "", ErrLifecycleEffects
	}
	observation, err := effects.Observe(
		ctx,
		binding,
		hostruntime.OperationPhaseComplete,
	)
	if err != nil ||
		observation.State != hostruntime.LifecycleEffectPresent ||
		observation.Postcondition == nil ||
		hostruntime.ValidateTargetPostconditionAgainstBinding(
			*observation.Postcondition,
			binding,
			hostruntime.OperationPhaseComplete,
		) != nil {
		return "", "", ErrLifecycleEffects
	}
	live := *observation.Postcondition
	if binding.TargetManifestDigest == nil || live.CurrentSelection == nil ||
		live.CurrentSelection.ManifestDigest != *binding.TargetManifestDigest ||
		live.FenceGeneration == 0 ||
		live.ActiveFleet != fleetfence.FleetPortable ||
		live.Policy.AcquisitionEnabled ||
		live.Policy.PendingAcquisitions != 0 ||
		live.Policy.ActiveListeners != 0 ||
		live.Quiescence.RunnerProcesses != 0 ||
		live.Quiescence.PendingAcquisitions != 0 {
		return "", "", ErrLifecycleEffects
	}
	for _, process := range live.Processes {
		if process.AcquisitionCapable {
			return "", "", ErrLifecycleEffects
		}
	}
	_, liveDigest, err := hostruntime.MarshalTargetPostcondition(live)
	if err != nil {
		return "", "", ErrLifecycleEffects
	}
	return journalDigest, liveDigest, nil
}

func (target *systemLifecycleTarget) effectPresent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	switch target.operationKind() {
	case hostruntime.OperationKindSuspend:
		return target.suspendEffectPresent(effect, snapshot)
	case hostruntime.OperationKindResume:
		return target.resumeEffectPresent(effect, snapshot)
	case hostruntime.OperationKindUninstall:
		return target.uninstallEffectPresent(effect, snapshot)
	case hostruntime.OperationKindInstall:
		return target.installEffectPresent(effect, snapshot)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) installEffectPresent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		return target.upgradeEffectPresent(effect, snapshot)
	}
	baseline := !snapshot.fencePresent &&
		snapshot.generation == 0 &&
		snapshot.fleet == fleetfence.FleetNone &&
		!snapshot.currentPresent &&
		!snapshot.watchdogPresent &&
		!snapshot.processPresent
	switch effect {
	case effectPreflight:
		return baseline &&
			target.candidateClean(snapshot)
	case effectCandidateStaged:
		return baseline &&
			target.candidateVerified(snapshot)
	case effectCandidateSmoked:
		return baseline &&
			target.candidateSmoked(snapshot) &&
			!snapshot.releasedPresent
	case effectCandidatePromoted:
		return baseline &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectGreenfieldProven:
		return baseline &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectFencePortable:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			!snapshot.watchdogPresent &&
			!snapshot.processPresent &&
			snapshot.releasedPresent
	case effectWatchdogInstalled, effectPolicyDisabled:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			!snapshot.processPresent &&
			snapshot.releasedPresent &&
			target.overlay.Policy.AcquisitionDefault == "disabled"
	case effectObserverStarted:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent
	case effectZeroProven:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			!snapshot.currentPresent &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent &&
			snapshot.zero
	case effectCurrentSelected, effectVerified:
		return snapshot.fencePresent &&
			snapshot.generation == target.terminalFence &&
			snapshot.fleet == fleetfence.FleetPortable &&
			target.artifactsReady(snapshot) &&
			snapshot.currentPresent &&
			snapshot.current.manifestDigest ==
				target.manifestDigest &&
			snapshot.current.overlayRevision ==
				target.revision &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.releasedPresent &&
			snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) effectAbsent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	switch target.operationKind() {
	case hostruntime.OperationKindSuspend:
		return target.suspendEffectAbsent(effect, snapshot)
	case hostruntime.OperationKindResume:
		return target.resumeEffectAbsent(effect, snapshot)
	case hostruntime.OperationKindUninstall:
		return target.uninstallEffectAbsent(effect, snapshot)
	case hostruntime.OperationKindInstall:
		return target.installEffectAbsent(effect, snapshot)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) installEffectAbsent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	if target.disposition ==
		hostruntime.InstallDispositionUpgradePortable {
		return target.upgradeEffectAbsent(effect, snapshot)
	}
	baseline := !snapshot.fencePresent &&
		snapshot.generation == 0 &&
		snapshot.fleet == fleetfence.FleetNone &&
		!snapshot.currentPresent &&
		!snapshot.watchdogPresent &&
		!snapshot.processPresent
	portable := snapshot.fencePresent &&
		snapshot.generation == target.terminalFence &&
		snapshot.fleet == fleetfence.FleetPortable &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		!snapshot.currentPresent
	switch effect {
	case effectCandidateStaged:
		return baseline && target.candidateStageAbsent(snapshot)
	case effectCandidateSmoked:
		return baseline && target.candidateVerified(snapshot)
	case effectCandidatePromoted:
		return baseline &&
			target.artifactsReady(snapshot) &&
			!snapshot.releasedPresent
	case effectFencePortable:
		return baseline &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectWatchdogInstalled:
		return portable &&
			!snapshot.watchdogPresent &&
			!snapshot.processPresent
	case effectObserverStarted:
		return portable &&
			snapshot.watchdogPresent &&
			!snapshot.processPresent
	case effectCurrentSelected:
		return portable &&
			snapshot.watchdogPresent &&
			snapshot.processPresent &&
			snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) operationKind() hostruntime.OperationKind {
	if target != nil && target.kind != "" {
		return target.kind
	}
	return hostruntime.OperationKindInstall
}

func (target *systemLifecycleTarget) compensationEffectPresent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	switch target.operationKind() {
	case hostruntime.OperationKindInstall:
		return target.installCompensationPresent(phase, snapshot)
	case hostruntime.OperationKindSuspend:
		return target.suspendCompensationPresent(phase, snapshot)
	case hostruntime.OperationKindResume:
		return target.resumeCompensationPresent(phase, snapshot)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) compensationEffectAbsent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	switch target.operationKind() {
	case hostruntime.OperationKindInstall:
		return target.installCompensationAbsent(phase, snapshot)
	case hostruntime.OperationKindResume:
		return target.resumeCompensationAbsent(phase, snapshot)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) installCompensationPresent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	if target.disposition == hostruntime.InstallDispositionGreenfieldPortable {
		return target.greenfieldCompensationPresent(phase, snapshot)
	}
	if target.disposition == hostruntime.InstallDispositionUpgradePortable {
		return target.upgradeCompensationPresent(phase, snapshot)
	}
	return false
}

func (target *systemLifecycleTarget) installCompensationAbsent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	if target.disposition == hostruntime.InstallDispositionGreenfieldPortable {
		return target.greenfieldCompensationAbsent(phase, snapshot)
	}
	if target.disposition == hostruntime.InstallDispositionUpgradePortable {
		return target.upgradeCompensationAbsent(phase, snapshot)
	}
	return false
}

func targetRuntimeOwnedOrAbsent(snapshot systemLifecycleSnapshot) bool {
	return (!snapshot.watchdogPresent || snapshot.watchdogTarget) &&
		(!snapshot.processPresent || snapshot.processTarget)
}

func noTargetRuntime(snapshot systemLifecycleSnapshot) bool {
	return !snapshot.watchdogTarget && !snapshot.processTarget
}

func (target *systemLifecycleTarget) greenfieldCompensationBase(
	snapshot systemLifecycleSnapshot,
	generation uint64,
	fleet fleetfence.Fleet,
	currentPresent bool,
) bool {
	if !targetRuntimeOwnedOrAbsent(snapshot) ||
		snapshot.generation != generation || snapshot.fleet != fleet ||
		snapshot.currentPresent != currentPresent {
		return false
	}
	if generation == 0 {
		return !snapshot.fencePresent
	}
	return snapshot.fencePresent
}

func candidateArtifactsAbsent(snapshot systemLifecycleSnapshot) bool {
	return !snapshot.stagedPresent && !snapshot.imagesVerified &&
		!snapshot.runnerSmoked && !snapshot.releasedPresent
}

func candidateArtifactsPresent(snapshot systemLifecycleSnapshot) bool {
	return snapshot.stagedPresent || snapshot.imagesVerified ||
		snapshot.runnerSmoked || snapshot.releasedPresent
}

func (target *systemLifecycleTarget) greenfieldCompensationPresent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	pre := target.greenfieldCompensationBase(
		snapshot,
		0,
		fleetfence.FleetNone,
		false,
	) && noTargetRuntime(snapshot)
	portableUnselected := target.greenfieldCompensationBase(
		snapshot,
		target.terminalFence,
		fleetfence.FleetPortable,
		false,
	) && snapshot.releasedPresent
	portableSelected := target.greenfieldCompensationBase(
		snapshot,
		target.terminalFence,
		fleetfence.FleetPortable,
		true,
	) && target.currentMatches(snapshot, target.manifestDigest, target.revision) &&
		snapshot.releasedPresent
	portableStopped := portableUnselected && noTargetRuntime(snapshot)
	selectedStopped := portableSelected && noTargetRuntime(snapshot)
	if target.terminalFence == ^uint64(0) {
		return false
	}
	noneUnselected := target.greenfieldCompensationBase(
		snapshot,
		target.terminalFence+1,
		fleetfence.FleetNone,
		false,
	) && noTargetRuntime(snapshot)
	switch phase {
	case hostruntime.OperationPhaseCGPreStarted,
		hostruntime.OperationPhaseCGPreCandidateStopped:
		return pre
	case hostruntime.OperationPhaseCGPreCandidateRemoved:
		return pre && candidateArtifactsAbsent(snapshot)
	case hostruntime.OperationPhaseCGPreAbsenceProven,
		hostruntime.OperationPhaseCompGreenfieldAbsent:
		return pre && candidateArtifactsAbsent(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGFenceStarted:
		return portableUnselected
	case hostruntime.OperationPhaseCGFenceObserverStopped:
		return portableStopped
	case hostruntime.OperationPhaseCGFenceQuiescenceProven:
		return portableStopped && snapshot.zero
	case hostruntime.OperationPhaseCGFenceNone:
		return noneUnselected && candidateArtifactsPresent(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGFenceCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldNone:
		return noneUnselected && candidateArtifactsAbsent(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGSelectStarted:
		return portableSelected
	case hostruntime.OperationPhaseCGSelectObserverStopped:
		return selectedStopped
	case hostruntime.OperationPhaseCGSelectQuiescenceProven:
		return selectedStopped && snapshot.zero
	case hostruntime.OperationPhaseCGSelectCurrentRemoved:
		return portableStopped && snapshot.zero
	case hostruntime.OperationPhaseCGSelectNone:
		return noneUnselected && candidateArtifactsPresent(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGSelectCandidateRemoved,
		hostruntime.OperationPhaseCompGreenfieldSelected:
		return noneUnselected && candidateArtifactsAbsent(snapshot) && snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) greenfieldCompensationAbsent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	if target.terminalFence == ^uint64(0) {
		return false
	}
	pre := target.greenfieldCompensationBase(
		snapshot,
		0,
		fleetfence.FleetNone,
		false,
	) && noTargetRuntime(snapshot)
	portableUnselected := target.greenfieldCompensationBase(
		snapshot,
		target.terminalFence,
		fleetfence.FleetPortable,
		false,
	) && snapshot.releasedPresent
	portableSelected := target.greenfieldCompensationBase(
		snapshot,
		target.terminalFence,
		fleetfence.FleetPortable,
		true,
	) && target.currentMatches(snapshot, target.manifestDigest, target.revision) &&
		snapshot.releasedPresent
	noneUnselected := target.greenfieldCompensationBase(
		snapshot,
		target.terminalFence+1,
		fleetfence.FleetNone,
		false,
	) && noTargetRuntime(snapshot)
	switch phase {
	case hostruntime.OperationPhaseCGPreCandidateRemoved:
		return pre && candidateArtifactsPresent(snapshot)
	case hostruntime.OperationPhaseCGFenceObserverStopped:
		return portableUnselected &&
			(snapshot.processTarget || snapshot.watchdogTarget)
	case hostruntime.OperationPhaseCGFenceNone:
		return portableUnselected && noTargetRuntime(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGFenceCandidateRemoved:
		return noneUnselected && candidateArtifactsPresent(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGSelectObserverStopped:
		return portableSelected &&
			(snapshot.processTarget || snapshot.watchdogTarget)
	case hostruntime.OperationPhaseCGSelectCurrentRemoved:
		return portableSelected && noTargetRuntime(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGSelectNone:
		return portableUnselected && noTargetRuntime(snapshot) && snapshot.zero
	case hostruntime.OperationPhaseCGSelectCandidateRemoved:
		return noneUnselected && candidateArtifactsPresent(snapshot) && snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) upgradeCompensationBase(
	snapshot systemLifecycleSnapshot,
	manifestDigest string,
	revision string,
) bool {
	return snapshot.fencePresent &&
		snapshot.generation == target.terminalFence &&
		snapshot.fleet == fleetfence.FleetPortable &&
		target.currentMatches(snapshot, manifestDigest, revision) &&
		(!snapshot.watchdogPresent || snapshot.watchdogPrior ||
			snapshot.watchdogTarget) &&
		(!snapshot.processPresent || snapshot.processPrior ||
			snapshot.processTarget)
}

func (target *systemLifecycleTarget) upgradeCompensationPresent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	prior := target.upgradeCompensationBase(
		snapshot,
		target.priorManifestDigest,
		target.priorRevision,
	)
	targetSelected := target.upgradeCompensationBase(
		snapshot,
		target.manifestDigest,
		target.revision,
	)
	stoppedPrior := prior && !snapshot.processPresent && !snapshot.watchdogTarget
	stoppedTarget := targetSelected && !snapshot.processPresent &&
		!snapshot.watchdogTarget
	priorRunning := prior && snapshot.processPresent && snapshot.processPrior &&
		!snapshot.processTarget && !snapshot.watchdogTarget
	disabled := snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 && snapshot.priorDrained
	switch phase {
	case hostruntime.OperationPhaseCUPreStarted:
		return prior
	case hostruntime.OperationPhaseCUPreCandidateStopped:
		return stoppedPrior
	case hostruntime.OperationPhaseCUPreCandidateRemoved,
		hostruntime.OperationPhaseCUPrePriorSelectionProven:
		return stoppedPrior && candidateArtifactsAbsent(snapshot)
	case hostruntime.OperationPhaseCUPrePriorDisabledProven,
		hostruntime.OperationPhaseCompUpgradePrior:
		return stoppedPrior && candidateArtifactsAbsent(snapshot) &&
			disabled && snapshot.zero
	case hostruntime.OperationPhaseCUSelectStarted:
		return targetSelected
	case hostruntime.OperationPhaseCUSelectObserverStopped:
		return stoppedTarget
	case hostruntime.OperationPhaseCUSelectQuiescenceProven:
		return stoppedTarget && snapshot.zero
	case hostruntime.OperationPhaseCUSelectPriorRestored:
		return stoppedPrior && snapshot.zero
	case hostruntime.OperationPhaseCUSelectPriorObserverStarted:
		return priorRunning
	case hostruntime.OperationPhaseCUSelectPriorZeroProven:
		return priorRunning && disabled && snapshot.zero
	case hostruntime.OperationPhaseCUSelectCandidateRemoved,
		hostruntime.OperationPhaseCompUpgradeRestored:
		return priorRunning && disabled && snapshot.zero &&
			candidateArtifactsAbsent(snapshot)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) upgradeCompensationAbsent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	prior := target.upgradeCompensationBase(
		snapshot,
		target.priorManifestDigest,
		target.priorRevision,
	)
	targetSelected := target.upgradeCompensationBase(
		snapshot,
		target.manifestDigest,
		target.revision,
	)
	stoppedPrior := prior && !snapshot.processPresent && !snapshot.watchdogTarget
	stoppedTarget := targetSelected && !snapshot.processPresent &&
		!snapshot.watchdogTarget
	switch phase {
	case hostruntime.OperationPhaseCUPreCandidateStopped:
		return prior && (snapshot.processPresent || snapshot.watchdogTarget)
	case hostruntime.OperationPhaseCUPreCandidateRemoved:
		return stoppedPrior && candidateArtifactsPresent(snapshot)
	case hostruntime.OperationPhaseCUSelectObserverStopped:
		return targetSelected &&
			(snapshot.processPresent || snapshot.watchdogTarget)
	case hostruntime.OperationPhaseCUSelectPriorRestored:
		return stoppedTarget && snapshot.zero
	case hostruntime.OperationPhaseCUSelectPriorObserverStarted:
		return stoppedPrior && snapshot.zero
	case hostruntime.OperationPhaseCUSelectCandidateRemoved:
		return prior && snapshot.processPrior && snapshot.zero &&
			candidateArtifactsPresent(snapshot)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) suspendCompensationPresent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	if !target.suspendTerminalState(snapshot) {
		return false
	}
	switch phase {
	case hostruntime.OperationPhaseCSNoneStarted,
		hostruntime.OperationPhaseCSNoneDisabledProven,
		hostruntime.OperationPhaseCSNoneQuiescenceProven,
		hostruntime.OperationPhaseCompSuspendNone:
		return true
	default:
		return false
	}
}

func (target *systemLifecycleTarget) resumeCompensationTerminalState(
	snapshot systemLifecycleSnapshot,
	watchdogPresent bool,
) bool {
	if target.terminalFence == ^uint64(0) {
		return false
	}
	return snapshot.fencePresent &&
		snapshot.generation == target.terminalFence+1 &&
		snapshot.fleet == fleetfence.FleetNone &&
		target.currentMatches(snapshot, target.manifestDigest, target.revision) &&
		snapshot.releasedPresent && !snapshot.processPresent &&
		snapshot.watchdogPresent == watchdogPresent &&
		(!watchdogPresent || snapshot.watchdogTarget) &&
		suspendPolicyDisabled(snapshot) && snapshot.priorDrained
}

func (target *systemLifecycleTarget) resumeCompensationPresent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	pre := target.resumeEntryState(snapshot)
	post := target.resumePortableState(snapshot)
	postStopped := post && !snapshot.processPresent
	postNoneWithWatchdog := target.resumeCompensationTerminalState(snapshot, true)
	postNone := target.resumeCompensationTerminalState(snapshot, false)
	switch phase {
	case hostruntime.OperationPhaseCRPreStarted,
		hostruntime.OperationPhaseCRPreObserverAbsent,
		hostruntime.OperationPhaseCRPreWatchdogAbsent,
		hostruntime.OperationPhaseCRPreNoneDisabledProven:
		return pre
	case hostruntime.OperationPhaseCRPostStarted:
		return post
	case hostruntime.OperationPhaseCRPostObserverStopped,
		hostruntime.OperationPhaseCRPostQuiescenceProven:
		return postStopped
	case hostruntime.OperationPhaseCRPostNone:
		return postNoneWithWatchdog
	case hostruntime.OperationPhaseCRPostWatchdogAbsent:
		return postNone
	case hostruntime.OperationPhaseCompResumeNone:
		return pre || postNone
	default:
		return false
	}
}

func (target *systemLifecycleTarget) resumeCompensationAbsent(
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) bool {
	post := target.resumePortableState(snapshot)
	switch phase {
	case hostruntime.OperationPhaseCRPostObserverStopped:
		return post && snapshot.processPresent && snapshot.processTarget
	case hostruntime.OperationPhaseCRPostNone:
		return post && !snapshot.processPresent
	case hostruntime.OperationPhaseCRPostWatchdogAbsent:
		return target.resumeCompensationTerminalState(snapshot, true)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) applyCompensation(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) error {
	if target.operationKind() == hostruntime.OperationKindInstall {
		return target.applyInstallCompensation(
			ctx,
			binding,
			phase,
			snapshot,
		)
	}
	switch phase {
	case hostruntime.OperationPhaseCRPostObserverStopped:
		if target.operationKind() != hostruntime.OperationKindResume ||
			!snapshot.processPresent || !snapshot.processTarget ||
			!lowerHexDigest(snapshot.processIdentity) {
			return ErrLifecycleEffects
		}
		return target.process.Stop(ctx, snapshot.processIdentity)
	case hostruntime.OperationPhaseCRPostNone:
		if target.operationKind() != hostruntime.OperationKindResume ||
			target.terminalFence == ^uint64(0) {
			return ErrLifecycleEffects
		}
		request := fleetfence.HandoffRequest{
			From:               fleetfence.FleetPortable,
			To:                 fleetfence.FleetNone,
			ExpectedGeneration: target.terminalFence,
		}
		request.OperationID = fleetfence.HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		)
		header, err := target.fence.Handoff(ctx, request)
		if err != nil || header.Generation != target.terminalFence+1 ||
			header.ActiveFleet != fleetfence.FleetNone {
			return ErrLifecycleEffects
		}
		return nil
	case hostruntime.OperationPhaseCRPostWatchdogAbsent:
		if target.operationKind() != hostruntime.OperationKindResume {
			return ErrLifecycleEffects
		}
		return target.watchdog.Remove(target.watchdogBinding())
	default:
		_ = binding
		return ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) applyInstallCompensation(
	ctx context.Context,
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) error {
	if binding.Kind != hostruntime.OperationKindInstall {
		return ErrLifecycleEffects
	}
	switch phase {
	case hostruntime.OperationPhaseCGFenceObserverStopped,
		hostruntime.OperationPhaseCGSelectObserverStopped,
		hostruntime.OperationPhaseCUPreCandidateStopped,
		hostruntime.OperationPhaseCUSelectObserverStopped:
		return target.stopCompensationRuntime(ctx, snapshot)
	case hostruntime.OperationPhaseCGPreCandidateRemoved,
		hostruntime.OperationPhaseCGFenceCandidateRemoved,
		hostruntime.OperationPhaseCGSelectCandidateRemoved,
		hostruntime.OperationPhaseCUPreCandidateRemoved,
		hostruntime.OperationPhaseCUSelectCandidateRemoved:
		return target.releases.RemoveCandidate(
			target.manifestDigest,
			target.revision,
		)
	case hostruntime.OperationPhaseCGSelectCurrentRemoved:
		return target.releases.ClearCurrent(
			target.manifestDigest,
			target.revision,
		)
	case hostruntime.OperationPhaseCGFenceNone,
		hostruntime.OperationPhaseCGSelectNone:
		if target.terminalFence == ^uint64(0) {
			return ErrLifecycleEffects
		}
		request := fleetfence.HandoffRequest{
			From:               fleetfence.FleetPortable,
			To:                 fleetfence.FleetNone,
			ExpectedGeneration: target.terminalFence,
		}
		request.OperationID = fleetfence.HandoffOperationID(
			request.ExpectedGeneration,
			request.From,
			request.To,
		)
		header, err := target.fence.Handoff(ctx, request)
		if err != nil || header.Generation != target.terminalFence+1 ||
			header.ActiveFleet != fleetfence.FleetNone {
			return ErrLifecycleEffects
		}
		return nil
	case hostruntime.OperationPhaseCUSelectPriorRestored:
		return target.releases.SelectReleased(
			target.priorManifestDigest,
			target.priorRevision,
		)
	case hostruntime.OperationPhaseCUSelectPriorObserverStarted:
		if target.priorProcess == nil {
			return ErrLifecycleEffects
		}
		inspection, err := target.priorProcess.StartDisabled(ctx)
		if err != nil || inspection.State != ProcessRunning ||
			!lowerHexDigest(inspection.ProcessIdentity) {
			return ErrLifecycleEffects
		}
		return nil
	case hostruntime.OperationPhaseCUSelectPriorZeroProven:
		return target.waitForPriorZero(ctx)
	default:
		return ErrLifecycleEffects
	}
}

func (target *systemLifecycleTarget) stopCompensationRuntime(
	ctx context.Context,
	snapshot systemLifecycleSnapshot,
) error {
	if snapshot.watchdogTarget {
		if err := target.watchdog.Remove(target.watchdogBinding()); err != nil {
			return ErrLifecycleEffects
		}
	}
	if !snapshot.processPresent {
		return nil
	}
	var process *ProcessAuthority
	var admin lifecycleControllerAdmin
	switch {
	case snapshot.processTarget && !snapshot.processPrior:
		process = target.process
		admin = target.admin
	case snapshot.processPrior && !snapshot.processTarget:
		process = target.priorProcess
		admin = target.priorAdmin
	default:
		return ErrLifecycleEffects
	}
	if process == nil || admin == nil ||
		!lowerHexDigest(snapshot.processIdentity) {
		return ErrLifecycleEffects
	}
	status, err := admin.Disable(ctx)
	if err != nil || status.Mode != controller.AcquisitionDisabled ||
		status.Capacity != 0 || admin.Drain(ctx, "wait") != nil {
		return ErrLifecycleEffects
	}
	if err := process.Stop(ctx, snapshot.processIdentity); err != nil {
		return ErrLifecycleEffects
	}
	return nil
}

func (target *systemLifecycleTarget) suspendBaseState(
	snapshot systemLifecycleSnapshot,
	generation uint64,
	fleet fleetfence.Fleet,
) bool {
	return snapshot.fencePresent &&
		snapshot.generation == generation &&
		snapshot.fleet == fleet &&
		target.currentMatches(snapshot, target.manifestDigest, target.revision) &&
		snapshot.releasedPresent
}

func suspendPolicyDisabled(snapshot systemLifecycleSnapshot) bool {
	return snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0
}

func (target *systemLifecycleTarget) suspendEntryState(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.suspendBaseState(
		snapshot,
		target.entryFence,
		fleetfence.FleetPortable,
	) && snapshot.watchdogPresent && snapshot.watchdogTarget &&
		snapshot.processPresent && snapshot.processTarget
}

func (target *systemLifecycleTarget) suspendWatchdogDisabledState(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.suspendBaseState(
		snapshot,
		target.entryFence,
		fleetfence.FleetPortable,
	) && !snapshot.watchdogPresent &&
		snapshot.processPresent && snapshot.processTarget
}

func (target *systemLifecycleTarget) suspendStoppedState(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.suspendBaseState(
		snapshot,
		target.entryFence,
		fleetfence.FleetPortable,
	) && !snapshot.watchdogPresent && !snapshot.processPresent &&
		suspendPolicyDisabled(snapshot) && snapshot.priorDrained
}

func (target *systemLifecycleTarget) suspendTerminalState(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.suspendBaseState(
		snapshot,
		target.terminalFence,
		fleetfence.FleetNone,
	) && !snapshot.watchdogPresent && !snapshot.processPresent &&
		suspendPolicyDisabled(snapshot) && snapshot.priorDrained
}

func (target *systemLifecycleTarget) suspendEffectPresent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	entry := target.suspendEntryState(snapshot)
	watchdogDisabled := target.suspendWatchdogDisabledState(snapshot)
	disabled := watchdogDisabled && suspendPolicyDisabled(snapshot)
	drained := disabled && snapshot.priorDrained
	stopped := target.suspendStoppedState(snapshot)
	terminal := target.suspendTerminalState(snapshot)
	switch effect {
	case effectPreflight, effectHoldProven:
		return entry
	case effectWatchdogDisabled:
		return watchdogDisabled
	case effectPolicyDisabled:
		return disabled
	case effectDrained:
		return drained
	case effectControllerStopped, effectQuiescenceProven:
		return stopped
	case effectFenceNone, effectVerified:
		return terminal
	default:
		return false
	}
}

func (target *systemLifecycleTarget) suspendEffectAbsent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	entry := target.suspendEntryState(snapshot)
	watchdogDisabled := target.suspendWatchdogDisabledState(snapshot)
	disabled := watchdogDisabled && suspendPolicyDisabled(snapshot)
	drained := disabled && snapshot.priorDrained
	switch effect {
	case effectWatchdogDisabled:
		return entry
	case effectPolicyDisabled:
		return watchdogDisabled && !suspendPolicyDisabled(snapshot)
	case effectDrained:
		return disabled && !snapshot.priorDrained
	case effectControllerStopped:
		return drained && snapshot.processPresent && snapshot.processTarget
	case effectFenceNone:
		return target.suspendStoppedState(snapshot)
	default:
		return false
	}
}

func (target *systemLifecycleTarget) resumeEntryState(
	snapshot systemLifecycleSnapshot,
) bool {
	return snapshot.fencePresent &&
		snapshot.generation == target.entryFence &&
		snapshot.fleet == fleetfence.FleetNone &&
		target.currentMatches(snapshot, target.manifestDigest, target.revision) &&
		snapshot.releasedPresent &&
		!snapshot.watchdogPresent &&
		!snapshot.processPresent &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *systemLifecycleTarget) resumePortableState(
	snapshot systemLifecycleSnapshot,
) bool {
	return snapshot.fencePresent &&
		snapshot.generation == target.terminalFence &&
		snapshot.fleet == fleetfence.FleetPortable &&
		target.currentMatches(snapshot, target.manifestDigest, target.revision) &&
		snapshot.releasedPresent
}

func (target *systemLifecycleTarget) resumeEffectPresent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	entry := target.resumeEntryState(snapshot)
	portable := target.resumePortableState(snapshot)
	switch effect {
	case effectPreflight, effectStoppedProven, effectPolicyDisabled:
		return entry
	case effectFencePortable:
		return portable && !snapshot.processPresent && !snapshot.watchdogPresent
	case effectObserverStarted:
		return portable && snapshot.processPresent && snapshot.processTarget &&
			!snapshot.watchdogPresent
	case effectWatchdogInstalled:
		return portable && snapshot.processPresent && snapshot.processTarget &&
			snapshot.watchdogPresent && snapshot.watchdogTarget
	case effectZeroProven, effectVerified:
		return portable && snapshot.processPresent && snapshot.processTarget &&
			snapshot.watchdogPresent && snapshot.watchdogTarget && snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) resumeEffectAbsent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	entry := target.resumeEntryState(snapshot)
	portable := target.resumePortableState(snapshot)
	switch effect {
	case effectFencePortable:
		return entry
	case effectObserverStarted:
		return portable && !snapshot.processPresent && !snapshot.watchdogPresent
	case effectWatchdogInstalled:
		return portable && snapshot.processPresent && snapshot.processTarget &&
			!snapshot.watchdogPresent
	case effectZeroProven:
		return portable && snapshot.processPresent && snapshot.processTarget &&
			snapshot.watchdogPresent && snapshot.watchdogTarget && !snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) uninstallBaseState(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.retainState &&
		snapshot.fencePresent &&
		snapshot.generation == target.entryFence &&
		snapshot.fleet == target.terminalFleet &&
		snapshot.releasedPresent &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *systemLifecycleTarget) uninstallEffectPresent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	base := target.uninstallBaseState(snapshot)
	selected := target.currentMatches(
		snapshot,
		target.manifestDigest,
		target.revision,
	)
	switch effect {
	case effectPreflight, effectQuiescenceProven:
		return base && selected
	case effectWatchdogRemoved:
		return base && selected && !snapshot.watchdogPresent
	case effectControllerRemoved:
		return base && selected && !snapshot.watchdogPresent &&
			!snapshot.processPresent
	case effectRegistrationRemoved, effectRetentionProven, effectVerified:
		return base && !snapshot.currentPresent && !snapshot.watchdogPresent &&
			!snapshot.processPresent
	default:
		return false
	}
}

func (target *systemLifecycleTarget) uninstallEffectAbsent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	base := target.uninstallBaseState(snapshot)
	selected := target.currentMatches(
		snapshot,
		target.manifestDigest,
		target.revision,
	)
	switch effect {
	case effectWatchdogRemoved:
		return base && selected && snapshot.watchdogPresent &&
			snapshot.watchdogTarget
	case effectControllerRemoved:
		return base && selected && !snapshot.watchdogPresent &&
			snapshot.processPresent && snapshot.processTarget
	case effectRegistrationRemoved:
		return base && selected && !snapshot.watchdogPresent &&
			!snapshot.processPresent
	default:
		return false
	}
}

func (target *systemLifecycleTarget) upgradeEffectPresent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	priorServing := target.upgradePriorServing(snapshot)
	priorStopped := target.upgradePriorStopped(snapshot)
	targetStopped := target.upgradeTargetStopped(snapshot)
	targetRunningPriorSelected := target.upgradeTargetRunning(
		snapshot,
		false,
	)
	targetRunningSelected := target.upgradeTargetRunning(
		snapshot,
		true,
	)
	switch effect {
	case effectPreflight:
		return priorServing && target.candidateClean(snapshot)
	case effectCandidateStaged:
		return priorServing && target.candidateVerified(snapshot)
	case effectCandidateSmoked:
		return priorServing &&
			target.candidateSmoked(snapshot) &&
			!snapshot.releasedPresent
	case effectCandidatePromoted, effectUpgradeProven:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent
	case effectPriorAcquisitionDisabled:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0
	case effectPriorDrained:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0 &&
			snapshot.priorDrained
	case effectPriorControllerStopped,
		effectPriorQuiescenceProven,
		effectFencePortableProven:
		return priorStopped
	case effectWatchdogInstalled, effectPolicyDisabled:
		return targetStopped &&
			target.overlay.Policy.AcquisitionDefault == "disabled"
	case effectObserverStarted:
		return targetRunningPriorSelected
	case effectZeroProven:
		return targetRunningPriorSelected && snapshot.zero
	case effectCurrentSelected, effectVerified:
		return targetRunningSelected && snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) upgradeEffectAbsent(
	effect productionEffect,
	snapshot systemLifecycleSnapshot,
) bool {
	priorServing := target.upgradePriorServing(snapshot)
	priorStopped := target.upgradePriorStopped(snapshot)
	targetStopped := target.upgradeTargetStopped(snapshot)
	targetRunningPriorSelected := target.upgradeTargetRunning(
		snapshot,
		false,
	)
	switch effect {
	case effectCandidateStaged:
		return priorServing && target.candidateStageAbsent(snapshot)
	case effectCandidateSmoked:
		return priorServing && target.candidateVerified(snapshot)
	case effectCandidatePromoted:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			!snapshot.releasedPresent
	case effectPriorAcquisitionDisabled:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			(snapshot.priorPolicy.Mode == controller.AcquisitionEnabled ||
				snapshot.priorPolicy.Mode == controller.AcquisitionCanaryOnly)
	case effectPriorDrained:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0 &&
			!snapshot.priorDrained
	case effectPriorControllerStopped:
		return priorServing &&
			target.artifactsReady(snapshot) &&
			snapshot.releasedPresent &&
			snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
			snapshot.priorPolicy.Capacity == 0 &&
			snapshot.priorDrained
	case effectWatchdogInstalled:
		return priorStopped
	case effectObserverStarted:
		return targetStopped
	case effectCurrentSelected:
		return targetRunningPriorSelected && snapshot.zero
	default:
		return false
	}
}

func (target *systemLifecycleTarget) upgradePriorServing(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.upgradeCommon(snapshot) &&
		target.currentMatches(
			snapshot,
			target.priorManifestDigest,
			target.priorRevision,
		) &&
		snapshot.watchdogPresent &&
		snapshot.watchdogPrior &&
		!snapshot.watchdogTarget &&
		snapshot.processPresent &&
		snapshot.processPrior &&
		!snapshot.processTarget
}

func (target *systemLifecycleTarget) upgradePriorStopped(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.upgradeCommon(snapshot) &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		target.currentMatches(
			snapshot,
			target.priorManifestDigest,
			target.priorRevision,
		) &&
		snapshot.watchdogPresent &&
		snapshot.watchdogPrior &&
		!snapshot.watchdogTarget &&
		!snapshot.processPresent &&
		!snapshot.processPrior &&
		!snapshot.processTarget &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *systemLifecycleTarget) upgradeTargetStopped(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.upgradeCommon(snapshot) &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		target.currentMatches(
			snapshot,
			target.priorManifestDigest,
			target.priorRevision,
		) &&
		snapshot.watchdogPresent &&
		!snapshot.watchdogPrior &&
		snapshot.watchdogTarget &&
		!snapshot.processPresent &&
		!snapshot.processPrior &&
		!snapshot.processTarget &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *systemLifecycleTarget) upgradeTargetRunning(
	snapshot systemLifecycleSnapshot,
	selected bool,
) bool {
	digest := target.priorManifestDigest
	revision := target.priorRevision
	if selected {
		digest = target.manifestDigest
		revision = target.revision
	}
	return target.upgradeCommon(snapshot) &&
		target.artifactsReady(snapshot) &&
		snapshot.releasedPresent &&
		target.currentMatches(snapshot, digest, revision) &&
		snapshot.watchdogPresent &&
		!snapshot.watchdogPrior &&
		snapshot.watchdogTarget &&
		snapshot.processPresent &&
		!snapshot.processPrior &&
		snapshot.processTarget &&
		snapshot.priorPolicy.Mode == controller.AcquisitionDisabled &&
		snapshot.priorPolicy.Capacity == 0 &&
		snapshot.priorDrained
}

func (target *systemLifecycleTarget) upgradeCommon(
	snapshot systemLifecycleSnapshot,
) bool {
	return snapshot.fencePresent &&
		snapshot.generation == target.terminalFence &&
		snapshot.fleet == fleetfence.FleetPortable
}

func (target *systemLifecycleTarget) candidateClean(
	snapshot systemLifecycleSnapshot,
) bool {
	return !snapshot.stagedPresent &&
		!snapshot.imagesVerified &&
		!snapshot.runnerSmoked &&
		!snapshot.releasedPresent
}

func (target *systemLifecycleTarget) candidateVerified(
	snapshot systemLifecycleSnapshot,
) bool {
	return snapshot.stagedPresent &&
		snapshot.imagesVerified &&
		!snapshot.runnerSmoked &&
		!snapshot.releasedPresent
}

func (target *systemLifecycleTarget) candidateStageAbsent(
	snapshot systemLifecycleSnapshot,
) bool {
	return !snapshot.imagesVerified &&
		!snapshot.runnerSmoked &&
		!snapshot.releasedPresent
}

func (target *systemLifecycleTarget) candidateSmoked(
	snapshot systemLifecycleSnapshot,
) bool {
	return target.artifactsReady(snapshot)
}

func (target *systemLifecycleTarget) artifactsReady(
	snapshot systemLifecycleSnapshot,
) bool {
	return snapshot.stagedPresent &&
		snapshot.imagesVerified &&
		snapshot.runnerSmoked
}

func (target *systemLifecycleTarget) currentMatches(
	snapshot systemLifecycleSnapshot,
	manifestDigest string,
	overlayRevision string,
) bool {
	return snapshot.currentPresent &&
		snapshot.current.manifestDigest == manifestDigest &&
		snapshot.current.overlayRevision == overlayRevision
}

func (target *systemLifecycleTarget) postcondition(
	binding hostruntime.OperationBinding,
	phase hostruntime.OperationPhase,
	snapshot systemLifecycleSnapshot,
) (hostruntime.TargetPostcondition, error) {
	_, bindingDigest, err := hostruntime.MarshalOperationBinding(binding)
	if err != nil {
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	}
	effectKey, err :=
		hostruntime.DeriveOperationEffectKey(binding, phase)
	if err != nil {
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	}
	artifacts := []hostruntime.ArtifactProjection{}
	if snapshot.watchdogPresent {
		artifacts = append(artifacts, snapshot.watchdog)
	}
	processes := []hostruntime.ProcessProjection{}
	if snapshot.processPresent {
		role := "disabled-observer"
		acquisitionCapable := false
		if snapshot.processPrior {
			role = "prior-controller"
			acquisitionCapable =
				snapshot.priorPolicy.Mode == controller.AcquisitionEnabled ||
					snapshot.priorPolicy.Mode == controller.AcquisitionCanaryOnly
		}
		processes = append(processes, hostruntime.ProcessProjection{
			Role:               role,
			PID:                snapshot.processRecord.PID,
			StartIdentity:      snapshot.processIdentity,
			ExecutableDigest:   snapshot.processRecord.ExecutableDigest,
			AcquisitionCapable: acquisitionCapable,
		})
	}
	policyManifestDigest := target.overlay.Policy.ManifestDigest
	if snapshot.watchdogPrior && target.priorOverlay != nil {
		policyManifestDigest = target.priorOverlay.Policy.ManifestDigest
	}
	acquisitionEnabled :=
		snapshot.priorPolicy.Mode == controller.AcquisitionEnabled ||
			snapshot.priorPolicy.Mode == controller.AcquisitionCanaryOnly
	controllerProcesses := uint64(0)
	if snapshot.processPresent {
		controllerProcesses = 1
	}
	postcondition := hostruntime.TargetPostcondition{
		SchemaVersion:          1,
		OperationID:            binding.OperationID,
		BindingDigest:          bindingDigest,
		EffectKey:              effectKey,
		Phase:                  phase,
		ManifestDigest:         binding.TargetManifestDigest,
		PrivateOverlayRevision: binding.PrivateOverlayRevision,
		FenceGeneration:        snapshot.generation,
		ActiveFleet:            snapshot.fleet,
		Filesystems:            snapshot.filesystems,
		Artifacts:              artifacts,
		Processes:              processes,
		Policy: hostruntime.PolicyProjection{
			PolicyManifestDigest: policyManifestDigest,
			TransitionEpoch:      snapshot.policyEpoch,
			AcquisitionEnabled:   acquisitionEnabled,
			PendingAcquisitions:  snapshot.activeListeners,
			ActiveListeners:      snapshot.activeListeners,
		},
		Quiescence: hostruntime.QuiescenceProjection{
			ControllerProcesses: controllerProcesses,
			RunnerProcesses:     snapshot.runningJobs,
			PendingAcquisitions: snapshot.activeListeners,
		},
		ObservedAt: target.now(),
	}
	if snapshot.currentPresent {
		selection := snapshot.current.selection
		selection.FenceGeneration = snapshot.generation
		selection.ActiveFleet = snapshot.fleet
		postcondition.CurrentSelection = &selection
	}
	if _, _, err := hostruntime.MarshalTargetPostcondition(
		postcondition,
	); err != nil {
		return hostruntime.TargetPostcondition{}, ErrLifecycleEffects
	}
	return postcondition, nil
}

func (target *systemLifecycleTarget) waitForZero(
	ctx context.Context,
) error {
	return target.waitForZeroProbe(ctx, target.probe)
}

func (target *systemLifecycleTarget) waitForPriorZero(
	ctx context.Context,
) error {
	if target.priorAdmin == nil {
		return ErrLifecycleEffects
	}
	return target.waitForZeroProbe(ctx, target.priorAdmin)
}

func (target *systemLifecycleTarget) waitForZeroProbe(
	ctx context.Context,
	probe DisabledControllerProbe,
) error {
	if probe == nil {
		return ErrLifecycleEffects
	}
	timer := time.NewTicker(target.pollInterval)
	defer timer.Stop()
	for {
		if _, err := probe.Observe(ctx); err == nil {
			if err := target.docker.ProveManagedQuiescence(ctx); err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ErrLifecycleEffects
		case <-timer.C:
		}
	}
}

func verifyInstalledTarget(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	arguments InvokeArguments,
) (hostruntime.HostActionResult, error) {
	sealedTarget, err := cli.SealTargetProof(target)
	if ctx == nil ||
		ctx.Err() != nil ||
		err != nil ||
		sealedTarget != target ||
		target.PrivateOverlayRevision != revision ||
		target.HostIdentityDigest != overlay.Target.HostIdentityDigest ||
		target.ControlIdentityDigest !=
			overlay.Target.ControlHostIdentityDigest ||
		target.FenceGeneration == 0 ||
		target.ActiveFleet != fleetfence.FleetPortable ||
		target.CurrentManifestDigest == nil ||
		*target.CurrentManifestDigest != arguments.ManifestDigest ||
		arguments.ManifestDigest != overlay.Manifest.Digest ||
		arguments.TargetProofDigest != target.ProofDigest ||
		!arguments.RequireZero ||
		!overlay.Resources.RunnerSizing.OperatorApproved {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	manifest, manifestDocument, manifestDigest, err :=
		loadPinnedTargetManifest(overlay.Manifest.Path)
	if err != nil ||
		len(manifestDocument) == 0 ||
		manifestDigest != arguments.ManifestDigest ||
		manifest.FleetGeneration > target.FenceGeneration ||
		!runtimeManifestMatchesOverlay(manifest, overlay) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	layout, err := hostruntime.LifecycleStoreLayoutFromPrivateOverlay(overlay)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	lookup, err := hostruntime.OpenLifecycleStoreLayout(layout, false)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	choice, present, selectErr := selectPortableInstallContinuation(
		lookup,
		revision,
		manifest,
	)
	lookupCloseErr := lookup.Close()
	if selectErr != nil ||
		lookupCloseErr != nil ||
		!present ||
		choice.continuation.journal.Phase !=
			hostruntime.OperationPhaseComplete ||
		choice.continuation.reservation.State !=
			hostruntime.ReservationStateCommitted ||
		!portableContinuationMatchesLiveState(
			choice.binding,
			choice.continuation.journal.Phase,
			target.CurrentManifestDigest,
		) {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	resources, _, err := openInstallOperation(
		ctx,
		overlay,
		revision,
		manifest,
		manifestDigest,
		choice.binding,
		false,
		target.FenceGeneration,
	)
	if err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	journalDigest, proofDigest, verifyErr := verifyEvolvedInstallTerminal(
		ctx,
		resources.lifecycle,
		resources.engine.Effects,
		choice.binding,
		choice.priorManifest,
		manifest,
	)
	closeErr := resources.Close()
	if verifyErr != nil || closeErr != nil {
		return hostruntime.HostActionResult{}, errors.Join(
			ErrProtocol,
			verifyErr,
			closeErr,
		)
	}
	operationID, generation, fleet, err := cli.ExpectedOperation(
		cli.ActionVerify,
		target,
		manifestDigest,
		revision,
	)
	if err != nil ||
		generation != target.FenceGeneration ||
		fleet != fleetfence.FleetPortable {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	result := hostruntime.HostActionResult{
		SchemaVersion:     1,
		Status:            hostruntime.HostActionComplete,
		OperationID:       operationID,
		JournalDigest:     journalDigest,
		TargetProofDigest: &proofDigest,
		FenceGeneration:   generation,
		ActiveFleet:       fleet,
	}
	if _, _, err := hostruntime.MarshalHostActionResult(result); err != nil {
		return hostruntime.HostActionResult{}, ErrProtocol
	}
	return result, nil
}

var _ LifecyclePhaseBackend = (*productionLifecycleBackend)(nil)
