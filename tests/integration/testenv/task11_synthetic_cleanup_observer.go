package testenv

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"sync"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

type task11SyntheticCleanupObserverBinding struct {
	PrimaryRoot      string
	PrimaryRunDigest string
	Cycle            task11SyntheticCycleIdentity
	Recovery         hostruntime.RecoverySpec
	Expected         hostruntime.ManagedObservation

	CapacitySlotID         uint32
	JobGeneration          uint64
	CgroupVersion          task11synthetic.CgroupVersion
	MaximumProcesses       uint64
	MaximumFileDescriptors uint64
	Cadence                time.Duration
	Deadline               time.Duration
	PayloadVersionCount    uint64
	AuthorityExpected      bool
	RelaySocketExpected    bool
}

type task11SyntheticCleanupCapture struct {
	bindingDigest string
	seal          [sha256.Size]byte
}

type task11SyntheticListenerOutcome struct {
	RunnerID string
	ExitCode int
	Stream   task11synthetic.Stream
}

type task11SyntheticNoListenerReason string

const (
	task11NoListenerCancellation       task11SyntheticNoListenerReason = "caller-cancellation"
	task11NoListenerPreListenerFailure task11SyntheticNoListenerReason = "pre-listener-failure"
	task11NoListenerControllerRestart  task11SyntheticNoListenerReason = "controller-restart"
)

type task11SyntheticNoListenerOutcome struct {
	Reason                 task11SyntheticNoListenerReason
	AttachStarted          bool
	ReleaseEffectCompleted bool
	ReleaseEffectAmbiguous bool
}

type task11SyntheticCleanupOutcomeKind uint8

const (
	task11CleanupOutcomeListener task11SyntheticCleanupOutcomeKind = iota + 1
	task11CleanupOutcomeNoListener
)

type task11SyntheticCleanupOutcomeSeal struct {
	bindingDigest  string
	structuralSeal [sha256.Size]byte
	kind           task11SyntheticCleanupOutcomeKind
	digest         string
}

type task11SyntheticProvedCleanup struct {
	binding        task11SyntheticCleanupObserverBinding
	observation    task11synthetic.CleanupObservation
	proof          CompleteCleanupProof
	structuralSeal [sha256.Size]byte
	outcomeKind    task11SyntheticCleanupOutcomeKind
	outcomeDigest  string
}

type task11SyntheticCleanupProbe interface {
	ArmStructural(
		context.Context,
		task11SyntheticCleanupObserverBinding,
		hostruntime.ManagedSnapshot,
	) (task11SyntheticCleanupCapture, error)
	Prove(
		context.Context,
		task11SyntheticCleanupObserverBinding,
		task11SyntheticCleanupCapture,
		task11SyntheticCleanupOutcomeSeal,
	) (task11synthetic.CleanupObservation, error)
}

type task11SyntheticCleanupObserverState uint8

const (
	task11CleanupObserverUnarmed task11SyntheticCleanupObserverState = iota + 1
	task11CleanupObserverStructuralArmed
	task11CleanupObserverOutcomeSealed
	task11CleanupObserverProved
	task11CleanupObserverFailed
)

type task11SyntheticCleanupObserver struct {
	binding       task11SyntheticCleanupObserverBinding
	bindingDigest string
	probe         task11SyntheticCleanupProbe

	mu      sync.Mutex
	state   task11SyntheticCleanupObserverState
	capture task11SyntheticCleanupCapture
	outcome task11SyntheticCleanupOutcomeSeal
}

func newTask11SyntheticCleanupObserver(
	binding task11SyntheticCleanupObserverBinding,
	probe task11SyntheticCleanupProbe,
) (*task11SyntheticCleanupObserver, error) {
	if probe == nil || !task11SyntheticCleanupObserverBindingValid(binding) {
		return nil, ErrFixtureStart
	}
	digest, err := task11SyntheticCleanupObserverBindingDigest(binding)
	if err != nil {
		return nil, ErrFixtureStart
	}
	return &task11SyntheticCleanupObserver{
		binding:       binding,
		bindingDigest: digest,
		probe:         probe,
		state:         task11CleanupObserverUnarmed,
	}, nil
}

func (o *task11SyntheticCleanupObserver) ArmStructural(
	ctx context.Context,
	snapshot hostruntime.ManagedSnapshot,
) error {
	if o == nil {
		return ErrFixtureStart
	}
	o.mu.Lock()
	if ctx == nil ||
		ctx.Err() != nil ||
		o.state != task11CleanupObserverUnarmed {
		o.state = task11CleanupObserverFailed
		o.mu.Unlock()
		return ErrFixtureStart
	}
	o.state = task11CleanupObserverFailed
	o.mu.Unlock()

	capture, err := o.probe.ArmStructural(
		ctx,
		o.binding,
		snapshot,
	)
	if err != nil ||
		capture.bindingDigest != o.bindingDigest ||
		capture.seal == ([sha256.Size]byte{}) {
		return ErrFixtureStart
	}
	o.mu.Lock()
	if o.state != task11CleanupObserverFailed {
		o.mu.Unlock()
		return ErrFixtureStart
	}
	o.capture = capture
	o.state = task11CleanupObserverStructuralArmed
	o.mu.Unlock()
	return nil
}

func (o *task11SyntheticCleanupObserver) SealListenerOutcome(
	ctx context.Context,
	listener task11SyntheticListenerOutcome,
) error {
	if o == nil {
		return ErrFixtureStart
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil ||
		ctx.Err() != nil ||
		o.state != task11CleanupObserverStructuralArmed {
		o.state = task11CleanupObserverFailed
		return ErrFixtureStart
	}
	capture := o.capture
	o.state = task11CleanupObserverFailed
	digest, ok := task11SyntheticListenerOutcomeDigest(
		o.binding,
		capture,
		listener,
	)
	if !ok {
		return ErrFixtureStart
	}
	o.outcome = task11SyntheticCleanupOutcomeSeal{
		bindingDigest:  o.bindingDigest,
		structuralSeal: capture.seal,
		kind:           task11CleanupOutcomeListener,
		digest:         digest,
	}
	o.state = task11CleanupObserverOutcomeSealed
	return nil
}

func (o *task11SyntheticCleanupObserver) SealNoListenerOutcome(
	ctx context.Context,
	noListener task11SyntheticNoListenerOutcome,
) error {
	if o == nil {
		return ErrFixtureStart
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil ||
		ctx.Err() != nil ||
		o.state != task11CleanupObserverStructuralArmed {
		o.state = task11CleanupObserverFailed
		return ErrFixtureStart
	}
	capture := o.capture
	o.state = task11CleanupObserverFailed
	digest, ok := task11SyntheticNoListenerOutcomeDigest(
		o.binding,
		capture,
		noListener,
	)
	if !ok {
		return ErrFixtureStart
	}
	o.outcome = task11SyntheticCleanupOutcomeSeal{
		bindingDigest:  o.bindingDigest,
		structuralSeal: capture.seal,
		kind:           task11CleanupOutcomeNoListener,
		digest:         digest,
	}
	o.state = task11CleanupObserverOutcomeSealed
	return nil
}

func (o *task11SyntheticCleanupObserver) Prove(
	ctx context.Context,
) (CompleteCleanupProof, error) {
	evidence, err := o.proveEvidence(ctx)
	if err != nil {
		return CompleteCleanupProof{}, err
	}
	return evidence.proof, nil
}

func (o *task11SyntheticCleanupObserver) proveEvidence(
	ctx context.Context,
) (task11SyntheticProvedCleanup, error) {
	if o == nil {
		return task11SyntheticProvedCleanup{}, ErrFixtureCleanup
	}
	o.mu.Lock()
	if ctx == nil ||
		ctx.Err() != nil ||
		o.state != task11CleanupObserverOutcomeSealed {
		o.state = task11CleanupObserverFailed
		o.mu.Unlock()
		return task11SyntheticProvedCleanup{}, ErrFixtureCleanup
	}
	capture := o.capture
	outcome := o.outcome
	o.state = task11CleanupObserverFailed
	o.mu.Unlock()

	observation, err := o.probe.Prove(
		ctx,
		o.binding,
		capture,
		outcome,
	)
	if err != nil ||
		!task11CleanupObservationMatchesBinding(
			observation,
			o.binding,
		) {
		return task11SyntheticProvedCleanup{}, ErrFixtureCleanup
	}
	digest, err := task11synthetic.DeriveCleanupObservationDigest(
		observation,
	)
	if err != nil {
		return task11SyntheticProvedCleanup{}, ErrFixtureCleanup
	}
	proof := CompleteCleanupProof{
		ContainersAbsent:        observation.ContainersAbsent,
		CgroupsAbsent:           observation.CgroupsAbsent,
		TmpfsAbsent:             observation.TmpfsAbsent,
		WorkAbsent:              observation.WorkAbsent,
		WorkUpdateAbsent:        observation.WorkUpdateAbsent,
		ProcessesAbsent:         observation.ProcessesAbsent,
		NamespacesAbsent:        observation.NamespacesAbsent,
		SocketsAbsent:           observation.SocketsAbsent,
		AuthoritiesAbsent:       observation.AuthoritiesAbsent,
		TemporaryFilesAbsent:    observation.TemporaryFilesAbsent,
		HostBackedWorkAbsent:    observation.HostBackedWorkAbsent,
		UnexpectedObjectsAbsent: observation.UnexpectedObjectsAbsent,
		PayloadVersionCount:     observation.PayloadVersionCount,
		AssertionCount:          observation.AssertionCount,
		ObservationDigest:       digest,
	}
	if _, err := SealCompleteCleanup(proof); err != nil {
		return task11SyntheticProvedCleanup{}, ErrFixtureCleanup
	}
	evidence := task11SyntheticProvedCleanup{
		binding:        o.binding,
		observation:    observation,
		proof:          proof,
		structuralSeal: capture.seal,
		outcomeKind:    outcome.kind,
		outcomeDigest:  outcome.digest,
	}
	if !validTask11SyntheticProvedCleanup(evidence, o.binding) {
		return task11SyntheticProvedCleanup{}, ErrFixtureCleanup
	}
	o.mu.Lock()
	if o.state != task11CleanupObserverFailed {
		o.mu.Unlock()
		return task11SyntheticProvedCleanup{}, ErrFixtureCleanup
	}
	o.capture = task11SyntheticCleanupCapture{}
	o.outcome = task11SyntheticCleanupOutcomeSeal{}
	o.state = task11CleanupObserverProved
	o.mu.Unlock()
	return evidence, nil
}

func validTask11SyntheticProvedCleanup(
	evidence task11SyntheticProvedCleanup,
	binding task11SyntheticCleanupObserverBinding,
) bool {
	if evidence.binding != binding ||
		evidence.structuralSeal == ([sha256.Size]byte{}) ||
		(evidence.outcomeKind != task11CleanupOutcomeListener &&
			evidence.outcomeKind != task11CleanupOutcomeNoListener) ||
		!isLowerHex(evidence.outcomeDigest, sha256.Size*2) ||
		!task11CleanupObservationMatchesBinding(
			evidence.observation,
			binding,
		) {
		return false
	}
	digest, err := task11synthetic.DeriveCleanupObservationDigest(
		evidence.observation,
	)
	if err != nil ||
		digest != evidence.proof.ObservationDigest {
		return false
	}
	expected := CompleteCleanupProof{
		ContainersAbsent:        evidence.observation.ContainersAbsent,
		CgroupsAbsent:           evidence.observation.CgroupsAbsent,
		TmpfsAbsent:             evidence.observation.TmpfsAbsent,
		WorkAbsent:              evidence.observation.WorkAbsent,
		WorkUpdateAbsent:        evidence.observation.WorkUpdateAbsent,
		ProcessesAbsent:         evidence.observation.ProcessesAbsent,
		NamespacesAbsent:        evidence.observation.NamespacesAbsent,
		SocketsAbsent:           evidence.observation.SocketsAbsent,
		AuthoritiesAbsent:       evidence.observation.AuthoritiesAbsent,
		TemporaryFilesAbsent:    evidence.observation.TemporaryFilesAbsent,
		HostBackedWorkAbsent:    evidence.observation.HostBackedWorkAbsent,
		UnexpectedObjectsAbsent: evidence.observation.UnexpectedObjectsAbsent,
		PayloadVersionCount:     evidence.observation.PayloadVersionCount,
		AssertionCount:          evidence.observation.AssertionCount,
		ObservationDigest:       digest,
	}
	if evidence.proof != expected {
		return false
	}
	_, err = SealCompleteCleanup(evidence.proof)
	return err == nil
}

func task11SyntheticListenerOutcomeDigest(
	binding task11SyntheticCleanupObserverBinding,
	capture task11SyntheticCleanupCapture,
	listener task11SyntheticListenerOutcome,
) (string, bool) {
	scenario, hasListener, ok := task11SyntheticScenario(
		binding.Cycle.ProtocolKind,
	)
	expectedExit, exitOK := task11SyntheticExpectedExit(scenario)
	expectedBindingDigest, bindingErr :=
		task11SyntheticCleanupObserverBindingDigest(binding)
	if !ok ||
		!hasListener ||
		!exitOK ||
		bindingErr != nil ||
		capture.bindingDigest != expectedBindingDigest ||
		capture.seal == ([sha256.Size]byte{}) ||
		listener.RunnerID != binding.Recovery.ExpectedRunnerID ||
		!isLowerHex(listener.RunnerID, 64) ||
		listener.ExitCode != expectedExit ||
		listener.Stream.Boundary.Scenario != scenario ||
		listener.Stream.Boundary.CycleRunDigest !=
			binding.Cycle.RunDigest ||
		listener.Stream.Boundary.CgroupVersion !=
			binding.CgroupVersion {
		return "", false
	}
	boundary, err := task11synthetic.MarshalBoundaryFrame(
		listener.Stream.Boundary,
	)
	if err != nil {
		return "", false
	}
	var terminal []byte
	if expectedExit == task11synthetic.NormalExitStatus {
		if listener.Stream.Terminal == nil ||
			listener.Stream.Terminal.Scenario != scenario ||
			listener.Stream.Terminal.CycleRunDigest !=
				binding.Cycle.RunDigest ||
			listener.Stream.Terminal.CgroupVersion !=
				binding.CgroupVersion ||
			listener.Stream.Terminal.JobMarkerDigest !=
				listener.Stream.Boundary.JobMarkerDigest {
			return "", false
		}
		terminal, err = task11synthetic.MarshalTerminalFrame(
			*listener.Stream.Terminal,
		)
		if err != nil {
			return "", false
		}
	} else if listener.Stream.Terminal != nil {
		return "", false
	}
	digest, err := recordingCanonicalDigest(
		"portable-ghar.task11.synthetic-cleanup-listener-outcome.v1\x00",
		struct {
			BindingDigest  string            `json:"binding_digest"`
			StructuralSeal [sha256.Size]byte `json:"structural_seal"`
			RunnerID       string            `json:"runner_id"`
			ExitCode       int               `json:"exit_code"`
			Boundary       []byte            `json:"boundary"`
			Terminal       []byte            `json:"terminal,omitempty"`
		}{
			BindingDigest:  capture.bindingDigest,
			StructuralSeal: capture.seal,
			RunnerID:       listener.RunnerID,
			ExitCode:       listener.ExitCode,
			Boundary:       boundary,
			Terminal:       terminal,
		},
	)
	return digest, err == nil
}

func task11SyntheticNoListenerOutcomeDigest(
	binding task11SyntheticCleanupObserverBinding,
	capture task11SyntheticCleanupCapture,
	noListener task11SyntheticNoListenerOutcome,
) (string, bool) {
	expectedReason, ok := task11SyntheticNoListenerReasonForCycle(
		binding.Cycle.ProtocolKind,
	)
	expectedBindingDigest, bindingErr :=
		task11SyntheticCleanupObserverBindingDigest(binding)
	if !ok ||
		noListener.Reason != expectedReason ||
		noListener.AttachStarted ||
		noListener.ReleaseEffectCompleted ||
		noListener.ReleaseEffectAmbiguous ||
		bindingErr != nil ||
		capture.bindingDigest != expectedBindingDigest ||
		capture.seal == ([sha256.Size]byte{}) {
		return "", false
	}
	digest, err := recordingCanonicalDigest(
		"portable-ghar.task11.synthetic-cleanup-no-listener-outcome.v1\x00",
		struct {
			BindingDigest  string                          `json:"binding_digest"`
			StructuralSeal [sha256.Size]byte               `json:"structural_seal"`
			Reason         task11SyntheticNoListenerReason `json:"reason"`
		}{
			BindingDigest:  capture.bindingDigest,
			StructuralSeal: capture.seal,
			Reason:         noListener.Reason,
		},
	)
	return digest, err == nil
}

func task11SyntheticNoListenerReasonForCycle(
	kind task11synthetic.CycleKind,
) (task11SyntheticNoListenerReason, bool) {
	switch kind {
	case task11synthetic.CycleCleanupCancellation:
		return task11NoListenerCancellation, true
	case task11synthetic.CycleCleanupPreListenerFailure:
		return task11NoListenerPreListenerFailure, true
	case task11synthetic.CycleCleanupControllerRestart:
		return task11NoListenerControllerRestart, true
	default:
		return "", false
	}
}

func task11SyntheticCleanupObserverBindingValid(
	binding task11SyntheticCleanupObserverBinding,
) bool {
	if !validAbsolutePath(binding.PrimaryRoot) ||
		binding.PrimaryRoot == string(filepath.Separator) ||
		binding.Cycle.Root == binding.PrimaryRoot ||
		filepath.Dir(binding.Cycle.Root) != binding.PrimaryRoot ||
		filepath.Base(binding.Cycle.Root) !=
			binding.Cycle.Composition.SlotIdentity ||
		binding.Recovery.SlotIdentity !=
			binding.Cycle.Composition.SlotIdentity ||
		binding.Recovery.AdapterName !=
			binding.Cycle.Composition.AdapterName ||
		binding.Recovery.BrokerName !=
			binding.Cycle.Composition.BrokerName ||
		binding.Recovery.RunnerName !=
			binding.Cycle.Composition.RunnerName ||
		binding.Recovery.RelayParent !=
			filepath.Join(binding.Cycle.Root, "relay") ||
		binding.Recovery.AuthorityParent !=
			filepath.Join(binding.Cycle.Root, "authority") ||
		!isLowerHex(binding.Recovery.BuildID, 64) ||
		binding.Recovery.FleetGeneration == 0 ||
		binding.CapacitySlotID !=
			binding.Cycle.Composition.CapacitySlotID ||
		binding.JobGeneration !=
			binding.Cycle.Composition.JobGeneration ||
		(binding.CgroupVersion != task11synthetic.CgroupV1 &&
			binding.CgroupVersion != task11synthetic.CgroupV2) ||
		binding.MaximumProcesses == 0 ||
		binding.MaximumFileDescriptors == 0 ||
		binding.Cadence <= 0 ||
		binding.Deadline <= 0 ||
		binding.PayloadVersionCount != 1 ||
		!validTask11ManagedExpectation(
			binding.Expected,
			binding.Recovery,
		) ||
		(binding.AuthorityExpected &&
			!binding.Expected.BrokerPresent) ||
		(binding.RelaySocketExpected &&
			!binding.Expected.BrokerPresent) {
		return false
	}
	var expected task11SyntheticCycleIdentity
	var err error
	if binding.Cycle.Restart !=
		(task11SyntheticRestartStageIdentity{}) {
		parent, parentErr := deriveTask11SyntheticCycleIdentity(
			binding.PrimaryRoot,
			binding.PrimaryRunDigest,
			task11SyntheticCycleRequest{
				Kind: task11CycleCleanupControllerRestart,
			},
		)
		if parentErr != nil {
			return false
		}
		expected, err = deriveTask11SyntheticRestartStageIdentity(
			binding.PrimaryRoot,
			binding.PrimaryRunDigest,
			parent,
			binding.Cycle.Restart.Stage,
			binding.Cycle.Restart.DeclarationIndex,
		)
	} else {
		expected, err = deriveTask11SyntheticProtocolCycleIdentity(
			binding.PrimaryRoot,
			binding.PrimaryRunDigest,
			binding.Cycle.ProtocolKind,
			binding.Cycle.Request.Ordinal,
		)
	}
	return err == nil &&
		expected.RunDigest == binding.Cycle.RunDigest &&
		expected.CleanupDigest == binding.Cycle.CleanupDigest &&
		expected.Composition == binding.Cycle.Composition &&
		expected.Root == binding.Cycle.Root &&
		expected.Restart == binding.Cycle.Restart
}

func validTask11ManagedExpectation(
	expected hostruntime.ManagedObservation,
	recovery hostruntime.RecoverySpec,
) bool {
	if !expected.AdapterPresent ||
		(expected.AdapterRunning && !expected.AdapterPresent) ||
		(expected.BrokerRunning && !expected.BrokerPresent) ||
		(expected.RunnerRunning && !expected.RunnerPresent) ||
		(expected.BrokerPresent && !expected.AdapterPresent) ||
		(expected.RunnerPresent && !expected.BrokerPresent) {
		return false
	}
	values := []struct {
		present bool
		id      string
	}{
		{expected.AdapterPresent, recovery.ExpectedAdapterID},
		{expected.BrokerPresent, recovery.ExpectedBrokerID},
		{expected.RunnerPresent, recovery.ExpectedRunnerID},
	}
	for _, value := range values {
		if value.present != (value.id != "") ||
			(value.id != "" && !isLowerHex(value.id, 64)) {
			return false
		}
	}
	return true
}

func task11SyntheticCleanupObserverBindingDigest(
	binding task11SyntheticCleanupObserverBinding,
) (string, error) {
	return recordingCanonicalDigest(
		"portable-ghar.task11.synthetic-cleanup-observer.v1\x00",
		binding,
	)
}

func newTask11SyntheticCleanupCapture(
	binding task11SyntheticCleanupObserverBinding,
	seal [sha256.Size]byte,
) (task11SyntheticCleanupCapture, error) {
	if seal == ([sha256.Size]byte{}) {
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	digest, err := task11SyntheticCleanupObserverBindingDigest(binding)
	if err != nil {
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	return task11SyntheticCleanupCapture{
		bindingDigest: digest,
		seal:          seal,
	}, nil
}

func task11CleanupObservationMatchesBinding(
	observation task11synthetic.CleanupObservation,
	binding task11SyntheticCleanupObserverBinding,
) bool {
	return observation.SchemaVersion == task11synthetic.SchemaVersion &&
		observation.ProtocolID == task11synthetic.ProtocolID &&
		observation.CycleRunDigest == binding.Cycle.RunDigest &&
		observation.CleanupDigest == binding.Cycle.CleanupDigest &&
		observation.CgroupVersion == binding.CgroupVersion &&
		observation.ContainersAbsent &&
		observation.CgroupsAbsent &&
		observation.TmpfsAbsent &&
		observation.WorkAbsent &&
		observation.WorkUpdateAbsent &&
		observation.ProcessesAbsent &&
		observation.NamespacesAbsent &&
		observation.SocketsAbsent &&
		observation.AuthoritiesAbsent &&
		observation.TemporaryFilesAbsent &&
		observation.HostBackedWorkAbsent &&
		observation.UnexpectedObjectsAbsent &&
		observation.PayloadVersionCount ==
			binding.PayloadVersionCount &&
		observation.AssertionCount == 13
}
