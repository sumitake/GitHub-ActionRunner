package testenv

import "errors"

var ErrSyntheticRecovery = errors.New(
	"testenv: synthetic recovery proof invalid",
)

var requiredRecoveryStates = [...]string{
	"portable-stopped",
	"disabled-persisted",
	"legacy-owned",
	"observer-started",
}

// ProcessIdentity binds process death to PID, start time, and process group so
// PID reuse cannot satisfy a recovery proof.
type ProcessIdentity struct {
	PID          int64
	StartTime    uint64
	ProcessGroup int64
}

// ProcessDeathProof records the exact identities expected to disappear and
// the complete identities observed after the death boundary.
type ProcessDeathProof struct {
	Expected      []ProcessIdentity
	ObservedAfter []ProcessIdentity
}

// SyntheticRecoveryProof is the closed, secret-free proof surface shared by
// the watchdog, legacy-fence, and noncancellable-shutdown integration cases.
type SyntheticRecoveryProof struct {
	InitialFenceGeneration uint64
	DisabledGeneration     uint64
	PersistedMode          string
	PersistedCapacity      uint64

	ControllerKilled            bool
	ControllerProcessDeath      ProcessDeathProof
	WatchdogRestarted           bool
	RestartAfterControllerDeath bool
	LegacyOwnsFence             bool
	RebootRecoveredDark         bool
	NoncancellableProcessDeath  ProcessDeathProof
	ObserverRestarted           bool
	ObserverRestartAfterDeath   bool

	OrderedStates []string

	RouteWriterCalls     uint64
	PollCalls            uint64
	AcquisitionCalls     uint64
	JITCalls             uint64
	ListenerReleaseCalls uint64

	AssertionCount    uint64
	ObservationDigest string
}

// ValidateSyntheticRecovery rejects stale generations, any non-dark persisted
// state, PID-only death observations, and every acquisition-side effect.
func ValidateSyntheticRecovery(proof SyntheticRecoveryProof) error {
	if proof.InitialFenceGeneration == 0 ||
		proof.DisabledGeneration <= proof.InitialFenceGeneration ||
		proof.PersistedMode != "disabled" ||
		proof.PersistedCapacity != 0 ||
		!proof.ControllerKilled ||
		!proof.WatchdogRestarted ||
		!proof.RestartAfterControllerDeath ||
		!proof.LegacyOwnsFence ||
		!proof.RebootRecoveredDark ||
		!proof.ObserverRestarted ||
		!proof.ObserverRestartAfterDeath ||
		proof.RouteWriterCalls != 0 ||
		proof.PollCalls != 0 ||
		proof.AcquisitionCalls != 0 ||
		proof.JITCalls != 0 ||
		proof.ListenerReleaseCalls != 0 ||
		proof.AssertionCount == 0 ||
		!isLowerHex(proof.ObservationDigest, 64) ||
		!validRecoveryStateOrder(proof.OrderedStates) ||
		!validProcessDeath(proof.ControllerProcessDeath) ||
		!validProcessDeath(proof.NoncancellableProcessDeath) {
		return ErrSyntheticRecovery
	}
	return nil
}

func validRecoveryStateOrder(states []string) bool {
	if len(states) != len(requiredRecoveryStates) {
		return false
	}
	for index, expected := range requiredRecoveryStates {
		if states[index] != expected {
			return false
		}
	}
	return true
}

func validProcessDeath(proof ProcessDeathProof) bool {
	if len(proof.Expected) == 0 {
		return false
	}
	expected := make(map[ProcessIdentity]struct{}, len(proof.Expected))
	for _, identity := range proof.Expected {
		if !validProcessIdentity(identity) {
			return false
		}
		if _, duplicate := expected[identity]; duplicate {
			return false
		}
		expected[identity] = struct{}{}
	}
	observed := make(map[ProcessIdentity]struct{}, len(proof.ObservedAfter))
	for _, identity := range proof.ObservedAfter {
		if !validProcessIdentity(identity) {
			return false
		}
		if _, duplicate := observed[identity]; duplicate {
			return false
		}
		if _, remained := expected[identity]; remained {
			return false
		}
		observed[identity] = struct{}{}
	}
	return true
}

func validProcessIdentity(identity ProcessIdentity) bool {
	return identity.PID > 0 &&
		identity.StartTime > 0 &&
		identity.ProcessGroup > 0
}

func cloneSyntheticRecoveryProof(
	proof SyntheticRecoveryProof,
) SyntheticRecoveryProof {
	proof.ControllerProcessDeath.Expected = append(
		[]ProcessIdentity(nil),
		proof.ControllerProcessDeath.Expected...,
	)
	proof.ControllerProcessDeath.ObservedAfter = append(
		[]ProcessIdentity(nil),
		proof.ControllerProcessDeath.ObservedAfter...,
	)
	proof.NoncancellableProcessDeath.Expected = append(
		[]ProcessIdentity(nil),
		proof.NoncancellableProcessDeath.Expected...,
	)
	proof.NoncancellableProcessDeath.ObservedAfter = append(
		[]ProcessIdentity(nil),
		proof.NoncancellableProcessDeath.ObservedAfter...,
	)
	proof.OrderedStates = append([]string(nil), proof.OrderedStates...)
	return proof
}
