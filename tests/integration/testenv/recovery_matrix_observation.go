package testenv

import (
	"context"
	"sync"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type recoveryRuntime interface {
	RecoveryObservation(
		context.Context,
		fixtureRuntimeObservation,
	) (SyntheticRecoveryProof, error)
}

type recoveryMatrixSource struct {
	ledger       *preparedRuntimeEvidenceLedger
	runtime      recoveryRuntime
	requirements []ObservationRequirement

	mu           sync.Mutex
	observations []matrixObservation
	next         int
	ready        bool
	failed       bool
}

type processIdentityWire struct {
	PID          int64  `json:"pid"`
	StartTime    uint64 `json:"start_time"`
	ProcessGroup int64  `json:"process_group"`
}

type processDeathWire struct {
	Expected      []processIdentityWire `json:"expected"`
	ObservedAfter []processIdentityWire `json:"observed_after"`
}

func newRecoveryMatrixSource(
	ledger *preparedRuntimeEvidenceLedger,
	runtime recoveryRuntime,
) (*recoveryMatrixSource, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrFixtureStart
	}
	var requirements []ObservationRequirement
	for _, requirement := range RequiredObservationMatrix() {
		switch requirement.Case {
		case conformance.CaseWatchdogRecovery,
			conformance.CaseLegacyFenceRecovery,
			conformance.CaseNoncancellableShutdown:
			requirements = append(requirements, requirement)
		}
	}
	if len(requirements) != 7 {
		return nil, ErrFixtureStart
	}
	return &recoveryMatrixSource{
		ledger:       ledger,
		runtime:      runtime,
		requirements: requirements,
	}, nil
}

func (s *recoveryMatrixSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed ||
		s.next >= len(s.requirements) ||
		requirement != s.requirements[s.next] {
		return matrixObservation{}, conformance.ErrObservation
	}
	if !s.ready {
		observations, err := s.acquire(ctx)
		if err != nil {
			s.failed = true
			return matrixObservation{}, conformance.ErrObservation
		}
		s.observations = observations
		s.ready = true
	}
	if len(s.observations) != len(s.requirements) ||
		s.observations[s.next].Requirement != requirement {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	observation := s.observations[s.next]
	s.next++
	var frozen bool
	switch requirement.ID {
	case "watchdog-zero-traps":
		frozen = s.ledger.freezeCase12()
	case "legacy-zero-portable-acquisition":
		frozen = s.ledger.freezeCase13()
	case "noncancellable-observer-order":
		frozen = s.ledger.freezeCase14()
	default:
		frozen = true
	}
	if !frozen {
		s.failed = true
		return matrixObservation{}, conformance.ErrObservation
	}
	return observation, nil
}

func (s *recoveryMatrixSource) acquire(
	ctx context.Context,
) ([]matrixObservation, error) {
	prepared, _, frozen := s.ledger.snapshotAfterCase11()
	if !frozen || !validFixtureRuntimeObservation(prepared) {
		return nil, conformance.ErrObservation
	}
	proof, err := s.runtime.RecoveryObservation(ctx, prepared)
	if err != nil || ValidateSyntheticRecovery(proof) != nil {
		return nil, conformance.ErrObservation
	}
	observations := make([]matrixObservation, 0, len(s.requirements))
	for _, requirement := range s.requirements {
		observation, err := recoveryMatrixObservation(
			requirement,
			prepared.PreparedEvidenceDigest,
			proof,
		)
		if err != nil {
			return nil, conformance.ErrObservation
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func recoveryMatrixObservation(
	requirement ObservationRequirement,
	preparedEvidenceDigest string,
	proof SyntheticRecoveryProof,
) (matrixObservation, error) {
	type binding struct {
		PreparedEvidenceDigest string `json:"prepared_evidence_digest"`
		RecoveryDigest         string `json:"recovery_digest"`
	}
	bound := binding{
		PreparedEvidenceDigest: preparedEvidenceDigest,
		RecoveryDigest:         proof.ObservationDigest,
	}
	var (
		assertions uint64
		payload    any
	)
	switch requirement.ID {
	case "watchdog-portable-restart":
		assertions = 5
		payload = struct {
			Binding                     binding          `json:"binding"`
			ControllerKilled            bool             `json:"controller_killed"`
			ControllerProcessDeath      processDeathWire `json:"controller_process_death"`
			WatchdogRestarted           bool             `json:"watchdog_restarted"`
			RestartAfterControllerDeath bool             `json:"restart_after_controller_death"`
		}{
			Binding:                     bound,
			ControllerKilled:            proof.ControllerKilled,
			ControllerProcessDeath:      processDeathWireFrom(proof.ControllerProcessDeath),
			WatchdogRestarted:           proof.WatchdogRestarted,
			RestartAfterControllerDeath: proof.RestartAfterControllerDeath,
		}
	case "watchdog-zero-traps":
		assertions = 5
		payload = struct {
			Binding              binding `json:"binding"`
			RouteWriterCalls     uint64  `json:"route_writer_calls"`
			PollCalls            uint64  `json:"poll_calls"`
			AcquisitionCalls     uint64  `json:"acquisition_calls"`
			JITCalls             uint64  `json:"jit_calls"`
			ListenerReleaseCalls uint64  `json:"listener_release_calls"`
		}{
			Binding:              bound,
			RouteWriterCalls:     proof.RouteWriterCalls,
			PollCalls:            proof.PollCalls,
			AcquisitionCalls:     proof.AcquisitionCalls,
			JITCalls:             proof.JITCalls,
			ListenerReleaseCalls: proof.ListenerReleaseCalls,
		}
	case "legacy-disabled-epoch":
		assertions = 4
		payload = struct {
			Binding            binding `json:"binding"`
			InitialGeneration  uint64  `json:"initial_generation"`
			DisabledGeneration uint64  `json:"disabled_generation"`
			PersistedMode      string  `json:"persisted_mode"`
			PersistedCapacity  uint64  `json:"persisted_capacity"`
		}{
			Binding:            bound,
			InitialGeneration:  proof.InitialFenceGeneration,
			DisabledGeneration: proof.DisabledGeneration,
			PersistedMode:      proof.PersistedMode,
			PersistedCapacity:  proof.PersistedCapacity,
		}
	case "legacy-reboot-recovery":
		assertions = 3
		payload = struct {
			Binding             binding  `json:"binding"`
			LegacyOwnsFence     bool     `json:"legacy_owns_fence"`
			RebootRecoveredDark bool     `json:"reboot_recovered_dark"`
			OrderedStates       []string `json:"ordered_states"`
		}{
			Binding:             bound,
			LegacyOwnsFence:     proof.LegacyOwnsFence,
			RebootRecoveredDark: proof.RebootRecoveredDark,
			OrderedStates: append(
				[]string(nil),
				proof.OrderedStates...,
			),
		}
	case "legacy-zero-portable-acquisition":
		assertions = 5
		payload = struct {
			Binding              binding `json:"binding"`
			RouteWriterCalls     uint64  `json:"route_writer_calls"`
			PollCalls            uint64  `json:"poll_calls"`
			AcquisitionCalls     uint64  `json:"acquisition_calls"`
			JITCalls             uint64  `json:"jit_calls"`
			ListenerReleaseCalls uint64  `json:"listener_release_calls"`
		}{
			Binding:              bound,
			RouteWriterCalls:     proof.RouteWriterCalls,
			PollCalls:            proof.PollCalls,
			AcquisitionCalls:     proof.AcquisitionCalls,
			JITCalls:             proof.JITCalls,
			ListenerReleaseCalls: proof.ListenerReleaseCalls,
		}
	case "noncancellable-process-death":
		assertions = 3
		payload = struct {
			Binding binding          `json:"binding"`
			Death   processDeathWire `json:"death"`
		}{
			Binding: bound,
			Death: processDeathWireFrom(
				proof.NoncancellableProcessDeath,
			),
		}
	case "noncancellable-observer-order":
		assertions = 3
		payload = struct {
			Binding                   binding  `json:"binding"`
			ObserverRestarted         bool     `json:"observer_restarted"`
			ObserverRestartAfterDeath bool     `json:"observer_restart_after_death"`
			OrderedStates             []string `json:"ordered_states"`
		}{
			Binding:                   bound,
			ObserverRestarted:         proof.ObserverRestarted,
			ObserverRestartAfterDeath: proof.ObserverRestartAfterDeath,
			OrderedStates: append(
				[]string(nil),
				proof.OrderedStates...,
			),
		}
	default:
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		requirement,
		assertions,
		nil,
		payload,
	)
}

func processDeathWireFrom(proof ProcessDeathProof) processDeathWire {
	return processDeathWire{
		Expected:      processIdentityWires(proof.Expected),
		ObservedAfter: processIdentityWires(proof.ObservedAfter),
	}
}

func processIdentityWires(
	values []ProcessIdentity,
) []processIdentityWire {
	result := make([]processIdentityWire, len(values))
	for index, identity := range values {
		result[index] = processIdentityWire(identity)
	}
	return result
}

var _ matrixObservationSource = (*recoveryMatrixSource)(nil)
