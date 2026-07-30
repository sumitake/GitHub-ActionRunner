package testenv

import "testing"

func TestValidateSyntheticRecoveryRequiresFenceZeroAndExactProcessDeath(
	t *testing.T,
) {
	t.Parallel()

	valid := SyntheticRecoveryProof{
		InitialFenceGeneration: 7,
		DisabledGeneration:     8,
		PersistedMode:          "disabled",
		PersistedCapacity:      0,
		ControllerKilled:       true,
		ControllerProcessDeath: ProcessDeathProof{
			Expected: []ProcessIdentity{{
				PID:          101,
				StartTime:    202,
				ProcessGroup: 101,
			}},
		},
		WatchdogRestarted:           true,
		RestartAfterControllerDeath: true,
		LegacyOwnsFence:             true,
		RebootRecoveredDark:         true,
		NoncancellableProcessDeath: ProcessDeathProof{
			Expected: []ProcessIdentity{{
				PID:          303,
				StartTime:    404,
				ProcessGroup: 303,
			}},
		},
		ObserverRestarted:         true,
		ObserverRestartAfterDeath: true,
		OrderedStates: []string{
			"portable-stopped",
			"disabled-persisted",
			"legacy-owned",
			"observer-started",
		},
		AssertionCount:    9,
		ObservationDigest: inputDigestA,
	}
	if err := ValidateSyntheticRecovery(valid); err != nil {
		t.Fatalf("ValidateSyntheticRecovery: %v", err)
	}
	tests := map[string]func(*SyntheticRecoveryProof){
		"stale generation": func(proof *SyntheticRecoveryProof) {
			proof.DisabledGeneration = proof.InitialFenceGeneration
		},
		"stale enabled state": func(proof *SyntheticRecoveryProof) {
			proof.PersistedMode = "enabled"
		},
		"stale canary state": func(proof *SyntheticRecoveryProof) {
			proof.PersistedMode = "canary-only"
		},
		"route writer trap": func(proof *SyntheticRecoveryProof) {
			proof.RouteWriterCalls = 1
		},
		"poll trap": func(proof *SyntheticRecoveryProof) {
			proof.PollCalls = 1
		},
		"JIT trap": func(proof *SyntheticRecoveryProof) {
			proof.JITCalls = 1
		},
		"listener release trap": func(proof *SyntheticRecoveryProof) {
			proof.ListenerReleaseCalls = 1
		},
		"restart before death": func(proof *SyntheticRecoveryProof) {
			proof.RestartAfterControllerDeath = false
		},
		"controller process remains": func(proof *SyntheticRecoveryProof) {
			proof.ControllerProcessDeath.ObservedAfter = append(
				proof.ControllerProcessDeath.ObservedAfter,
				proof.ControllerProcessDeath.Expected[0],
			)
		},
		"controller PID only": func(proof *SyntheticRecoveryProof) {
			proof.ControllerProcessDeath.Expected[0].StartTime = 0
		},
		"poll process remains": func(proof *SyntheticRecoveryProof) {
			proof.NoncancellableProcessDeath.ObservedAfter = append(
				proof.NoncancellableProcessDeath.ObservedAfter,
				proof.NoncancellableProcessDeath.Expected[0],
			)
		},
		"observer restarted before poll death": func(proof *SyntheticRecoveryProof) {
			proof.ObserverRestartAfterDeath = false
		},
		"state order": func(proof *SyntheticRecoveryProof) {
			proof.OrderedStates[0], proof.OrderedStates[1] =
				proof.OrderedStates[1], proof.OrderedStates[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			proof := cloneSyntheticRecoveryProof(valid)
			mutate(&proof)
			if err := ValidateSyntheticRecovery(proof); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}
