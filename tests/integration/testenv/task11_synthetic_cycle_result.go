package testenv

import (
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

const task11VersionStagingAbsenceDomain = "portable-ghar.task11.version-staging-absence.v1\x00"

func task11SyntheticScenario(
	kind task11synthetic.CycleKind,
) (task11synthetic.Scenario, bool, bool) {
	switch kind {
	case task11synthetic.CycleOneJob:
		return task11synthetic.ScenarioOneJob, true, true
	case task11synthetic.CycleCleanupSuccess:
		return task11synthetic.ScenarioCleanupSuccess, true, true
	case task11synthetic.CycleCleanupCancellation,
		task11synthetic.CycleCleanupPreListenerFailure,
		task11synthetic.CycleCleanupControllerRestart:
		return "", false, true
	case task11synthetic.CycleCleanupListenerCrash:
		return task11synthetic.ScenarioCleanupListenerCrash, true, true
	case task11synthetic.CycleCleanupUpgradeInterruption:
		return task11synthetic.ScenarioCleanupUpgradeInterruption, true, true
	case task11synthetic.CycleReclamation:
		return task11synthetic.ScenarioReclamation, true, true
	case task11synthetic.CycleSeedFirst:
		return task11synthetic.ScenarioSeedFirst, true, true
	case task11synthetic.CycleSeedSecond:
		return task11synthetic.ScenarioSeedSecond, true, true
	default:
		return "", false, false
	}
}

func task11SyntheticListenerInput(
	primary ConformanceInput,
	cycle task11SyntheticCycleIdentity,
	scenario task11synthetic.Scenario,
	nonce string,
	cgroupVersion task11synthetic.CgroupVersion,
	maximumBytes uint64,
) (
	task11synthetic.Input,
	task11synthetic.StreamBinding,
	[]byte,
	error,
) {
	expectedScenario, listener, ok := task11SyntheticScenario(
		cycle.ProtocolKind,
	)
	if !ok || !listener || expectedScenario != scenario ||
		(cgroupVersion != task11synthetic.CgroupV1 &&
			cgroupVersion != task11synthetic.CgroupV2) {
		return task11synthetic.Input{},
			task11synthetic.StreamBinding{},
			nil,
			ErrFixtureStart
	}
	seedID := ""
	if cycle.ProtocolKind == task11synthetic.CycleSeedFirst ||
		cycle.ProtocolKind == task11synthetic.CycleSeedSecond {
		seedID = task11synthetic.SeedID
	}
	input := task11synthetic.Input{
		SchemaVersion:  task11synthetic.SchemaVersion,
		ProtocolID:     task11synthetic.ProtocolID,
		Scenario:       scenario,
		CycleRunDigest: cycle.RunDigest,
		Nonce:          nonce,
		Sentinel: task11synthetic.Sentinel{
			URL:                  primary.Sentinels.Positive.URL,
			Host:                 primary.Sentinels.Positive.Host,
			Port:                 primary.Sentinels.Positive.Port,
			HostIdentityDigest:   primary.Sentinels.Positive.HostIdentityDigest,
			SPKIDigest:           primary.Sentinels.Positive.SPKIDigest,
			CertificateDigest:    primary.Sentinels.Positive.CertificateDigest,
			PolicyEntryDigest:    primary.Sentinels.Positive.PolicyEntryDigest,
			PolicyEvidenceDigest: primary.Sentinels.Positive.PolicyEvidenceDigest,
			ResponseBodyDigest:   primary.Sentinels.Positive.ResponseBodyDigest,
		},
		SeedID: seedID,
	}
	document, err := task11synthetic.MarshalInput(input, maximumBytes)
	if err != nil {
		return task11synthetic.Input{},
			task11synthetic.StreamBinding{},
			nil,
			ErrFixtureStart
	}
	jobMarker, err := task11synthetic.DeriveJobMarkerDigest(
		cycle.RunDigest,
		nonce,
	)
	if err != nil {
		return task11synthetic.Input{},
			task11synthetic.StreamBinding{},
			nil,
			ErrFixtureStart
	}
	binding := task11synthetic.StreamBinding{
		Scenario:        scenario,
		CycleRunDigest:  cycle.RunDigest,
		JobMarkerDigest: jobMarker,
		CgroupVersion:   cgroupVersion,
	}
	return input, binding, document, nil
}

func task11SyntheticCycleResultFromStream(
	cycle task11SyntheticCycleIdentity,
	stream task11synthetic.Stream,
	cleanup CompleteCleanupProof,
) (task11SyntheticCycleResult, error) {
	scenario, listener, ok := task11SyntheticScenario(cycle.ProtocolKind)
	mapped, mappedOK := task11ProtocolCycleKind(cycle.Request.Kind)
	if !ok || !listener || !mappedOK ||
		mapped != cycle.ProtocolKind ||
		stream.Boundary.Scenario != scenario ||
		stream.Boundary.CycleRunDigest != cycle.RunDigest ||
		!validTask11CleanupProofForCycle(cleanup) {
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	result := task11SyntheticCycleResult{
		Kind:    cycle.Request.Kind,
		Ordinal: cycle.Request.Ordinal,
		Cleanup: cleanup,
	}
	switch cycle.ProtocolKind {
	case task11synthetic.CycleOneJob:
		terminal, err := task11SyntheticNormalTerminal(
			cycle,
			scenario,
			stream,
		)
		if err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		canonical, err := task11synthetic.MarshalTerminalFrame(terminal)
		if err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		completion, err := task11synthetic.DeriveJobCompletionDigest(
			cycle.RunDigest,
			terminal.JobMarkerDigest,
			canonical,
		)
		if err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		deregistration, err := task11synthetic.DeriveDeregistrationDigest(
			cycle.RunDigest,
			terminal.JobMarkerDigest,
			canonical,
		)
		if err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		result.OneJob = syntheticOneJobRuntimeObservation{
			JobCompleted:         true,
			JobCompletionDigest:  completion,
			ProxyRequestComplete: true,
			ProxyRequestDigest:   terminal.ProxyRequestDigest,
			Deregistered:         true,
			DeregistrationDigest: deregistration,
			Reclaimed:            true,
			ReclamationDigest:    cleanup.ObservationDigest,
		}
	case task11synthetic.CycleCleanupSuccess:
		if _, err := task11SyntheticNormalTerminal(
			cycle,
			scenario,
			stream,
		); err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
	case task11synthetic.CycleCleanupListenerCrash,
		task11synthetic.CycleCleanupUpgradeInterruption:
		if stream.Terminal != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
	case task11synthetic.CycleReclamation:
		terminal, err := task11SyntheticNormalTerminal(
			cycle,
			scenario,
			stream,
		)
		if err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		resources, err := task11SyntheticResourceResults(
			terminal.Resources,
		)
		if err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		absence, err := recordingCanonicalDigest(
			task11VersionStagingAbsenceDomain,
			struct {
				SchemaVersion    uint32 `json:"schema_version"`
				CycleRunDigest   string `json:"cycle_run_digest"`
				CleanupDigest    string `json:"cleanup_digest"`
				ObservationProof string `json:"observation_proof"`
			}{
				SchemaVersion:    1,
				CycleRunDigest:   cycle.RunDigest,
				CleanupDigest:    cycle.CleanupDigest,
				ObservationProof: cleanup.ObservationDigest,
			},
		)
		if err != nil {
			return task11SyntheticCycleResult{}, ErrFixtureStart
		}
		result.Resources = resources
		result.VersionStagingAbsent = true
		result.VersionStagingAbsenceDigest = absence
	default:
		return task11SyntheticCycleResult{}, ErrFixtureStart
	}
	return result, nil
}

func task11SyntheticSeedIsolationResultFromStreams(
	primaryRoot string,
	primaryRunDigest string,
	firstCycle task11SyntheticCycleIdentity,
	firstStream task11synthetic.Stream,
	firstCleanup CompleteCleanupProof,
	secondCycle task11SyntheticCycleIdentity,
	secondStream task11synthetic.Stream,
	secondCleanup CompleteCleanupProof,
) (task11SeedIsolationResult, error) {
	expectedFirst, firstErr := deriveTask11SyntheticProtocolCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		task11synthetic.CycleSeedFirst,
		0,
	)
	expectedSecond, secondErr := deriveTask11SyntheticProtocolCycleIdentity(
		primaryRoot,
		primaryRunDigest,
		task11synthetic.CycleSeedSecond,
		0,
	)
	if firstErr != nil ||
		secondErr != nil ||
		firstCycle != expectedFirst ||
		secondCycle != expectedSecond ||
		firstCycle.Root == secondCycle.Root ||
		firstCleanup.ObservationDigest ==
			secondCleanup.ObservationDigest ||
		!validTask11CleanupProofForCycle(firstCleanup) ||
		!validTask11CleanupProofForCycle(secondCleanup) {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	firstTerminal, err := task11SyntheticNormalTerminal(
		firstCycle,
		task11synthetic.ScenarioSeedFirst,
		firstStream,
	)
	if err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	secondTerminal, err := task11SyntheticNormalTerminal(
		secondCycle,
		task11synthetic.ScenarioSeedSecond,
		secondStream,
	)
	if err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	if _, err := task11synthetic.MarshalBoundaryFrame(
		firstStream.Boundary,
	); err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	if _, err := task11synthetic.MarshalBoundaryFrame(
		secondStream.Boundary,
	); err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	if _, err := task11synthetic.MarshalTerminalFrame(
		firstTerminal,
	); err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	if _, err := task11synthetic.MarshalTerminalFrame(
		secondTerminal,
	); err != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	if firstTerminal.Seed == nil ||
		secondTerminal.Seed == nil ||
		firstTerminal.Seed.SeedID != task11synthetic.SeedID ||
		secondTerminal.Seed.SeedID != task11synthetic.SeedID ||
		firstTerminal.Seed.MutationAbsent ||
		!secondTerminal.Seed.MutationAbsent {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	firstWorkspaceReclaimed := firstCleanup.WorkAbsent &&
		firstCleanup.TmpfsAbsent &&
		firstCleanup.HostBackedWorkAbsent &&
		firstCleanup.UnexpectedObjectsAbsent
	secondWorkspaceReclaimed := secondCleanup.WorkAbsent &&
		secondCleanup.TmpfsAbsent &&
		secondCleanup.HostBackedWorkAbsent &&
		secondCleanup.UnexpectedObjectsAbsent
	proof := SeedIsolationProof{
		SourceDigest:          firstTerminal.Seed.SourceDigest,
		FirstCopyDigest:       firstTerminal.Seed.CopyDigest,
		CurrentMutationDigest: firstTerminal.Seed.MutationDigest,
		SecondCopyDigest:      secondTerminal.Seed.CopyDigest,
		SourcePostDigest:      secondTerminal.Seed.SourcePostDigest,
		MutationAbsent:        secondTerminal.Seed.MutationAbsent,
		SourceImmutable: firstTerminal.Seed.SourceImmutable &&
			secondTerminal.Seed.SourceImmutable &&
			firstTerminal.Seed.SourcePostDigest ==
				secondTerminal.Seed.SourcePostDigest,
		HostBackedWorkAbsent: firstCleanup.HostBackedWorkAbsent &&
			secondCleanup.HostBackedWorkAbsent,
		SharedSeedPathAbsent: firstCycle.Root != secondCycle.Root &&
			firstCleanup.HostBackedWorkAbsent &&
			secondCleanup.HostBackedWorkAbsent &&
			firstCleanup.UnexpectedObjectsAbsent &&
			secondCleanup.UnexpectedObjectsAbsent,
		FirstWorkspaceReclaimed:  firstWorkspaceReclaimed,
		SecondWorkspaceReclaimed: secondWorkspaceReclaimed,
		WorkspacesReclaimed: firstWorkspaceReclaimed &&
			secondWorkspaceReclaimed,
	}
	if ValidateSeedIsolation(proof) != nil {
		return task11SeedIsolationResult{}, ErrFixtureStart
	}
	return task11SeedIsolationResult{
		Proof:         proof,
		FirstCleanup:  firstCleanup,
		SecondCleanup: secondCleanup,
	}, nil
}

func task11SyntheticNormalTerminal(
	cycle task11SyntheticCycleIdentity,
	scenario task11synthetic.Scenario,
	stream task11synthetic.Stream,
) (task11synthetic.TerminalFrame, error) {
	if stream.Terminal == nil ||
		stream.Terminal.Scenario != scenario ||
		stream.Terminal.CycleRunDigest != cycle.RunDigest ||
		stream.Terminal.JobMarkerDigest !=
			stream.Boundary.JobMarkerDigest ||
		stream.Terminal.CgroupVersion !=
			stream.Boundary.CgroupVersion {
		return task11synthetic.TerminalFrame{}, ErrFixtureStart
	}
	return *stream.Terminal, nil
}

func task11SyntheticResourceResults(
	values []task11synthetic.ResourceHighWater,
) ([]task11SyntheticResourceObservation, error) {
	if len(values) != len(requiredReclamationResources) {
		return nil, ErrFixtureStart
	}
	result := make(
		[]task11SyntheticResourceObservation,
		0,
		len(values),
	)
	for index, value := range values {
		resource, ok := task11ReclamationResource(value.Resource)
		if !ok || resource != requiredReclamationResources[index] {
			return nil, ErrFixtureStart
		}
		result = append(result, task11SyntheticResourceObservation{
			Resource:    resource,
			HighWater:   value.HighWater,
			PostCleanup: 0,
		})
	}
	return result, nil
}

func task11ReclamationResource(
	resource task11synthetic.Resource,
) (ReclamationResource, bool) {
	switch resource {
	case task11synthetic.ResourceMemoryBytes:
		return ResourceMemoryBytes, true
	case task11synthetic.ResourceSwapBytes:
		return ResourceSwapBytes, true
	case task11synthetic.ResourceRunnerTmpfsBytes:
		return ResourceRunnerTmpfs, true
	case task11synthetic.ResourceTmpBytes:
		return ResourceTmp, true
	case task11synthetic.ResourceScratchBytes:
		return ResourceScratch, true
	case task11synthetic.ResourceContainers:
		return ResourceContainers, true
	case task11synthetic.ResourceProcesses:
		return ResourceProcesses, true
	case task11synthetic.ResourceFileDescriptors:
		return ResourceFileDescriptors, true
	case task11synthetic.ResourceNamespaces:
		return ResourceNamespaces, true
	case task11synthetic.ResourceConntrackRows:
		return ResourceConntrackRows, true
	case task11synthetic.ResourceInodes:
		return ResourceInodes, true
	default:
		return "", false
	}
}

func validTask11CleanupProofForCycle(
	proof CompleteCleanupProof,
) bool {
	_, err := SealCompleteCleanup(proof)
	return err == nil && proof.AssertionCount == 13
}
