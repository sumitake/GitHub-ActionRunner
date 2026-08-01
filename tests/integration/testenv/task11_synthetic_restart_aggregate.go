package testenv

import (
	"crypto/sha256"
	"path/filepath"
	"sync"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/state"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

const task11RestartCleanupAggregateDomain = "portable-ghar.task11.restart-cleanup-aggregate.v1\x00"

type task11SyntheticRestartSuccessCompletion struct {
	cycleRunDigest       string
	assignmentKey        controller.AssignmentKey
	assignmentDestroyed  bool
	terminalOfferReplay  bool
	listenerEffectAbsent bool
}

type task11SyntheticCycleRemovalSnapshot struct {
	cycleRunDigest string
	handles        []cleanupHandle
	handlesDigest  string
	allRemoved     bool
}

type task11SyntheticRestartChildEvidence struct {
	stage            task11synthetic.SetupStage
	declarationIndex uint64
	cycle            task11SyntheticCycleIdentity
	cleanup          task11SyntheticProvedCleanup
	completion       task11SyntheticRestartSuccessCompletion
	removal          task11SyntheticCycleRemovalSnapshot
}

type task11SyntheticRestartAggregateEvidence struct {
	parent   task11SyntheticCycleIdentity
	children []task11SyntheticRestartChildEvidence
	proof    CompleteCleanupProof
	failed   bool
}

type task11SyntheticRestartAggregateBuilder struct {
	mu       sync.Mutex
	parent   task11SyntheticCycleIdentity
	children []task11SyntheticRestartChildEvidence
	failed   bool
	sealed   bool
}

type task11SyntheticRestartAggregateHandleWire struct {
	Kind CleanupKind `json:"kind"`
	ID   string      `json:"id"`
}

type task11SyntheticRestartStageWire struct {
	SetupStage              task11synthetic.SetupStage `json:"setup_stage"`
	DeclarationIndex        uint64                     `json:"declaration_index"`
	ChildCycleRunDigest     string                     `json:"child_cycle_run_digest"`
	ChildCleanupDigest      string                     `json:"child_cleanup_digest"`
	ContainersAbsent        bool                       `json:"containers_absent"`
	CgroupsAbsent           bool                       `json:"cgroups_absent"`
	TmpfsAbsent             bool                       `json:"tmpfs_absent"`
	WorkAbsent              bool                       `json:"work_absent"`
	WorkUpdateAbsent        bool                       `json:"work_update_absent"`
	ProcessesAbsent         bool                       `json:"processes_absent"`
	NamespacesAbsent        bool                       `json:"namespaces_absent"`
	SocketsAbsent           bool                       `json:"sockets_absent"`
	AuthoritiesAbsent       bool                       `json:"authorities_absent"`
	TemporaryFilesAbsent    bool                       `json:"temporary_files_absent"`
	HostBackedWorkAbsent    bool                       `json:"host_backed_work_absent"`
	UnexpectedObjectsAbsent bool                       `json:"unexpected_objects_absent"`
	PayloadVersionCount     uint64                     `json:"payload_version_count"`
	AssertionCount          uint64                     `json:"assertion_count"`
	ChildObservationDigest  string                     `json:"child_observation_digest"`
	AssignmentDestroyed     bool                       `json:"assignment_destroyed"`
	TerminalOfferReplay     bool                       `json:"terminal_offer_replay"`
	RegisteredHandlesDigest string                     `json:"registered_handles_digest"`
}

type task11SyntheticRestartAggregateWire struct {
	SchemaVersion           uint32                            `json:"schema_version"`
	ProtocolID              string                            `json:"protocol_id"`
	ParentCycleRunDigest    string                            `json:"parent_cycle_run_digest"`
	ParentCleanupDigest     string                            `json:"parent_cleanup_digest"`
	CgroupVersion           task11synthetic.CgroupVersion     `json:"cgroup_version"`
	StageCount              uint64                            `json:"stage_count"`
	Stages                  []task11SyntheticRestartStageWire `json:"stages"`
	ContainersAbsent        bool                              `json:"containers_absent"`
	CgroupsAbsent           bool                              `json:"cgroups_absent"`
	TmpfsAbsent             bool                              `json:"tmpfs_absent"`
	WorkAbsent              bool                              `json:"work_absent"`
	WorkUpdateAbsent        bool                              `json:"work_update_absent"`
	ProcessesAbsent         bool                              `json:"processes_absent"`
	NamespacesAbsent        bool                              `json:"namespaces_absent"`
	SocketsAbsent           bool                              `json:"sockets_absent"`
	AuthoritiesAbsent       bool                              `json:"authorities_absent"`
	TemporaryFilesAbsent    bool                              `json:"temporary_files_absent"`
	HostBackedWorkAbsent    bool                              `json:"host_backed_work_absent"`
	UnexpectedObjectsAbsent bool                              `json:"unexpected_objects_absent"`
	PayloadVersionCount     uint64                            `json:"payload_version_count"`
	AssertionCount          uint64                            `json:"assertion_count"`
}

func newTask11SyntheticRestartSuccessCompletion(
	cycle task11SyntheticCycleIdentity,
	receipt state.OfferReceipt,
	listenerEffect state.EffectRecord,
) (task11SyntheticRestartSuccessCompletion, error) {
	key := controller.AssignmentKey{
		RepositoryAlias: "portable-ghar-conformance",
		RunnerRequestID: cycle.Composition.RunnerRequestID,
		Attempt:         0,
	}
	if !validTask11SyntheticRestartChildCycle(cycle) ||
		receipt.Key != key ||
		receipt.Disposition != state.OfferTerminalReplay ||
		receipt.State != controller.StateDestroyed ||
		listenerEffect != (state.EffectRecord{
			State: state.EffectAbsent,
		}) {
		return task11SyntheticRestartSuccessCompletion{},
			ErrFixtureStart
	}
	return task11SyntheticRestartSuccessCompletion{
		cycleRunDigest:       cycle.RunDigest,
		assignmentKey:        key,
		assignmentDestroyed:  true,
		terminalOfferReplay:  true,
		listenerEffectAbsent: true,
	}, nil
}

func newTask11SyntheticCycleRemovalSnapshot(
	cycle task11SyntheticCycleIdentity,
	handles []cleanupHandle,
	recordedRemoved func(cleanupHandle) bool,
) (task11SyntheticCycleRemovalSnapshot, error) {
	if !validTask11SyntheticRestartChildCycle(cycle) ||
		len(handles) == 0 ||
		recordedRemoved == nil {
		return task11SyntheticCycleRemovalSnapshot{}, ErrFixtureCleanup
	}
	rootHandle, err := task11CycleRootHandle(cycle)
	if err != nil {
		return task11SyntheticCycleRemovalSnapshot{}, ErrFixtureCleanup
	}
	seen := make(map[cleanupHandle]struct{}, len(handles))
	wires := make(
		[]task11SyntheticRestartAggregateHandleWire,
		0,
		len(handles),
	)
	rootPresent := false
	for _, handle := range handles {
		if !validCleanupKind(handle.kind) ||
			!isLowerHex(handle.id, sha256.Size*2) ||
			!recordedRemoved(handle) {
			return task11SyntheticCycleRemovalSnapshot{},
				ErrFixtureCleanup
		}
		if _, exists := seen[handle]; exists {
			return task11SyntheticCycleRemovalSnapshot{},
				ErrFixtureCleanup
		}
		seen[handle] = struct{}{}
		rootPresent = rootPresent || handle == rootHandle
		wires = append(wires, task11SyntheticRestartAggregateHandleWire{
			Kind: handle.kind,
			ID:   handle.id,
		})
	}
	if !rootPresent {
		return task11SyntheticCycleRemovalSnapshot{}, ErrFixtureCleanup
	}
	digest, err := recordingCanonicalDigest(
		"portable-ghar.task11.synthetic-cycle-removed-handles.v1\x00",
		struct {
			CycleRunDigest string                                      `json:"cycle_run_digest"`
			Handles        []task11SyntheticRestartAggregateHandleWire `json:"handles"`
		}{
			CycleRunDigest: cycle.RunDigest,
			Handles:        wires,
		},
	)
	if err != nil {
		return task11SyntheticCycleRemovalSnapshot{}, ErrFixtureCleanup
	}
	return task11SyntheticCycleRemovalSnapshot{
		cycleRunDigest: cycle.RunDigest,
		handles:        append([]cleanupHandle(nil), handles...),
		handlesDigest:  digest,
		allRemoved:     true,
	}, nil
}

func newTask11SyntheticRestartAggregateBuilder(
	parent task11SyntheticCycleIdentity,
) (*task11SyntheticRestartAggregateBuilder, error) {
	if !validTask11SyntheticRestartParentCycle(parent) {
		return nil, ErrFixtureStart
	}
	return &task11SyntheticRestartAggregateBuilder{
		parent: parent,
		children: make(
			[]task11SyntheticRestartChildEvidence,
			0,
			len(task11synthetic.RestartSetupStages()),
		),
	}, nil
}

func (b *task11SyntheticRestartAggregateBuilder) appendSuccess(
	child task11SyntheticRestartChildEvidence,
) error {
	if b == nil {
		return ErrFixtureStart
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed || b.sealed ||
		len(b.children) >= len(task11synthetic.RestartSetupStages()) ||
		!validTask11SyntheticRestartChildEvidence(
			b.parent,
			uint64(len(b.children)),
			child,
		) {
		b.failed = true
		return ErrFixtureStart
	}
	b.children = append(
		b.children,
		cloneTask11SyntheticRestartChildEvidence(child),
	)
	return nil
}

func (b *task11SyntheticRestartAggregateBuilder) fail() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failed = true
	b.mu.Unlock()
}

func (b *task11SyntheticRestartAggregateBuilder) seal() (
	task11SyntheticRestartAggregateEvidence,
	error,
) {
	if b == nil {
		return task11SyntheticRestartAggregateEvidence{}, ErrFixtureStart
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed || b.sealed ||
		len(b.children) != len(task11synthetic.RestartSetupStages()) {
		b.failed = true
		return task11SyntheticRestartAggregateEvidence{}, ErrFixtureStart
	}
	children := cloneTask11SyntheticRestartChildren(b.children)
	proof, err := task11SyntheticRestartAggregateProof(
		b.parent,
		children,
	)
	if err != nil {
		b.failed = true
		return task11SyntheticRestartAggregateEvidence{}, ErrFixtureStart
	}
	evidence := task11SyntheticRestartAggregateEvidence{
		parent:   b.parent,
		children: children,
		proof:    proof,
	}
	if !validTask11SyntheticRestartAggregateEvidence(evidence) {
		b.failed = true
		return task11SyntheticRestartAggregateEvidence{}, ErrFixtureStart
	}
	b.sealed = true
	return evidence, nil
}

func validTask11SyntheticRestartAggregateEvidence(
	evidence task11SyntheticRestartAggregateEvidence,
) bool {
	if evidence.failed ||
		len(evidence.children) !=
			len(task11synthetic.RestartSetupStages()) {
		return false
	}
	proof, err := task11SyntheticRestartAggregateProof(
		evidence.parent,
		evidence.children,
	)
	return err == nil && proof == evidence.proof
}

func task11SyntheticRestartAggregateProof(
	parent task11SyntheticCycleIdentity,
	children []task11SyntheticRestartChildEvidence,
) (CompleteCleanupProof, error) {
	stages := task11synthetic.RestartSetupStages()
	if !validTask11SyntheticRestartParentCycle(parent) ||
		len(children) != len(stages) {
		return CompleteCleanupProof{}, ErrFixtureStart
	}
	wires := make(
		[]task11SyntheticRestartStageWire,
		0,
		len(stages),
	)
	runDigests := make(map[string]struct{}, len(stages))
	cleanupDigests := make(map[string]struct{}, len(stages))
	observationDigests := make(map[string]struct{}, len(stages))
	var cgroupVersion task11synthetic.CgroupVersion
	for index, child := range children {
		if !validTask11SyntheticRestartChildEvidence(
			parent,
			uint64(index),
			child,
		) {
			return CompleteCleanupProof{}, ErrFixtureStart
		}
		if index == 0 {
			cgroupVersion = child.cleanup.observation.CgroupVersion
		} else if child.cleanup.observation.CgroupVersion != cgroupVersion {
			return CompleteCleanupProof{}, ErrFixtureStart
		}
		for digest, seen := range map[string]map[string]struct{}{
			child.cycle.RunDigest:                 runDigests,
			child.cycle.CleanupDigest:             cleanupDigests,
			child.cleanup.proof.ObservationDigest: observationDigests,
		} {
			if _, exists := seen[digest]; exists {
				return CompleteCleanupProof{}, ErrFixtureStart
			}
			seen[digest] = struct{}{}
		}
		proof := child.cleanup.proof
		wires = append(wires, task11SyntheticRestartStageWire{
			SetupStage:              child.stage,
			DeclarationIndex:        child.declarationIndex,
			ChildCycleRunDigest:     child.cycle.RunDigest,
			ChildCleanupDigest:      child.cycle.CleanupDigest,
			ContainersAbsent:        proof.ContainersAbsent,
			CgroupsAbsent:           proof.CgroupsAbsent,
			TmpfsAbsent:             proof.TmpfsAbsent,
			WorkAbsent:              proof.WorkAbsent,
			WorkUpdateAbsent:        proof.WorkUpdateAbsent,
			ProcessesAbsent:         proof.ProcessesAbsent,
			NamespacesAbsent:        proof.NamespacesAbsent,
			SocketsAbsent:           proof.SocketsAbsent,
			AuthoritiesAbsent:       proof.AuthoritiesAbsent,
			TemporaryFilesAbsent:    proof.TemporaryFilesAbsent,
			HostBackedWorkAbsent:    proof.HostBackedWorkAbsent,
			UnexpectedObjectsAbsent: proof.UnexpectedObjectsAbsent,
			PayloadVersionCount:     proof.PayloadVersionCount,
			AssertionCount:          proof.AssertionCount,
			ChildObservationDigest:  proof.ObservationDigest,
			AssignmentDestroyed:     child.completion.assignmentDestroyed,
			TerminalOfferReplay:     child.completion.terminalOfferReplay,
			RegisteredHandlesDigest: child.removal.handlesDigest,
		})
	}
	assertionCount := uint64(len(stages) * 13)
	wire := task11SyntheticRestartAggregateWire{
		SchemaVersion:           task11synthetic.SchemaVersion,
		ProtocolID:              task11synthetic.ProtocolID,
		ParentCycleRunDigest:    parent.RunDigest,
		ParentCleanupDigest:     parent.CleanupDigest,
		CgroupVersion:           cgroupVersion,
		StageCount:              uint64(len(stages)),
		Stages:                  wires,
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
		AssertionCount:          assertionCount,
	}
	digest, err := recordingCanonicalDigest(
		task11RestartCleanupAggregateDomain,
		wire,
	)
	if err != nil {
		return CompleteCleanupProof{}, ErrFixtureStart
	}
	proof := CompleteCleanupProof{
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
		AssertionCount:          assertionCount,
		ObservationDigest:       digest,
	}
	if _, err := SealCompleteCleanup(proof); err != nil {
		return CompleteCleanupProof{}, ErrFixtureStart
	}
	return proof, nil
}

func validTask11SyntheticRestartChildEvidence(
	parent task11SyntheticCycleIdentity,
	index uint64,
	child task11SyntheticRestartChildEvidence,
) bool {
	stages := task11synthetic.RestartSetupStages()
	if index >= uint64(len(stages)) ||
		child.stage != stages[index] ||
		child.declarationIndex != index ||
		!validTask11SyntheticRestartChildCycle(child.cycle) ||
		child.cycle.Restart != (task11SyntheticRestartStageIdentity{
			ParentRunDigest:  parent.RunDigest,
			Stage:            stages[index],
			DeclarationIndex: index,
		}) {
		return false
	}
	expectedRun, err := task11synthetic.DeriveRestartCycleRunDigest(
		parent.RunDigest,
		stages[index],
		index,
	)
	if err != nil || expectedRun != child.cycle.RunDigest {
		return false
	}
	expectedCleanup, err := task11synthetic.DeriveCleanupDigest(expectedRun)
	if err != nil || expectedCleanup != child.cycle.CleanupDigest {
		return false
	}
	primaryRoot := filepath.Dir(parent.Root)
	expectedParent, err := deriveTask11SyntheticCycleIdentity(
		primaryRoot,
		child.cleanup.binding.PrimaryRunDigest,
		parent.Request,
	)
	if err != nil ||
		expectedParent != parent ||
		child.cleanup.binding.PrimaryRoot != primaryRoot ||
		child.cleanup.binding.Cycle != child.cycle ||
		child.cleanup.outcomeKind != task11CleanupOutcomeNoListener ||
		!validTask11SyntheticProvedCleanup(
			child.cleanup,
			child.cleanup.binding,
		) ||
		!validTask11SyntheticRestartSuccessCompletion(
			child.completion,
			child.cycle,
		) ||
		!validTask11SyntheticCycleRemovalSnapshot(
			child.removal,
			child.cycle,
		) {
		return false
	}
	return true
}

func validTask11SyntheticRestartSuccessCompletion(
	completion task11SyntheticRestartSuccessCompletion,
	cycle task11SyntheticCycleIdentity,
) bool {
	return completion.cycleRunDigest == cycle.RunDigest &&
		completion.assignmentKey == (controller.AssignmentKey{
			RepositoryAlias: "portable-ghar-conformance",
			RunnerRequestID: cycle.Composition.RunnerRequestID,
			Attempt:         0,
		}) &&
		completion.assignmentDestroyed &&
		completion.terminalOfferReplay &&
		completion.listenerEffectAbsent
}

func validTask11SyntheticCycleRemovalSnapshot(
	snapshot task11SyntheticCycleRemovalSnapshot,
	cycle task11SyntheticCycleIdentity,
) bool {
	if snapshot.cycleRunDigest != cycle.RunDigest ||
		!snapshot.allRemoved ||
		!isLowerHex(snapshot.handlesDigest, sha256.Size*2) ||
		len(snapshot.handles) == 0 {
		return false
	}
	recomputed, err := newTask11SyntheticCycleRemovalSnapshot(
		cycle,
		snapshot.handles,
		func(cleanupHandle) bool { return true },
	)
	return err == nil &&
		recomputed.handlesDigest == snapshot.handlesDigest
}

func validTask11SyntheticRestartParentCycle(
	parent task11SyntheticCycleIdentity,
) bool {
	if parent.Request != (task11SyntheticCycleRequest{
		Kind: task11CycleCleanupControllerRestart,
	}) ||
		parent.ProtocolKind !=
			task11synthetic.CycleCleanupControllerRestart ||
		parent.Restart != (task11SyntheticRestartStageIdentity{}) ||
		!isLowerHex(parent.RunDigest, sha256.Size*2) ||
		!isLowerHex(parent.CleanupDigest, sha256.Size*2) ||
		filepath.Dir(parent.Root) == parent.Root ||
		filepath.Base(parent.Root) != parent.Composition.SlotIdentity {
		return false
	}
	cleanup, err := task11synthetic.DeriveCleanupDigest(parent.RunDigest)
	composition, compositionErr := deriveCompositionIdentity(parent.RunDigest)
	return err == nil &&
		compositionErr == nil &&
		cleanup == parent.CleanupDigest &&
		composition == parent.Composition
}

func validTask11SyntheticRestartChildCycle(
	cycle task11SyntheticCycleIdentity,
) bool {
	if cycle.Request != (task11SyntheticCycleRequest{
		Kind: task11CycleCleanupControllerRestart,
	}) ||
		cycle.ProtocolKind !=
			task11synthetic.CycleCleanupControllerRestart ||
		cycle.Restart == (task11SyntheticRestartStageIdentity{}) ||
		filepath.Base(cycle.Root) != cycle.Composition.SlotIdentity {
		return false
	}
	run, err := task11synthetic.DeriveRestartCycleRunDigest(
		cycle.Restart.ParentRunDigest,
		cycle.Restart.Stage,
		cycle.Restart.DeclarationIndex,
	)
	cleanup, cleanupErr := task11synthetic.DeriveCleanupDigest(
		cycle.RunDigest,
	)
	composition, compositionErr := deriveCompositionIdentity(
		cycle.RunDigest,
	)
	return err == nil &&
		cleanupErr == nil &&
		compositionErr == nil &&
		run == cycle.RunDigest &&
		cleanup == cycle.CleanupDigest &&
		composition == cycle.Composition
}

func cloneTask11SyntheticRestartChildEvidence(
	child task11SyntheticRestartChildEvidence,
) task11SyntheticRestartChildEvidence {
	cloned := child
	cloned.removal.handles = append(
		[]cleanupHandle(nil),
		child.removal.handles...,
	)
	return cloned
}

func cloneTask11SyntheticRestartChildren(
	children []task11SyntheticRestartChildEvidence,
) []task11SyntheticRestartChildEvidence {
	cloned := make(
		[]task11SyntheticRestartChildEvidence,
		0,
		len(children),
	)
	for _, child := range children {
		cloned = append(
			cloned,
			cloneTask11SyntheticRestartChildEvidence(child),
		)
	}
	return cloned
}
