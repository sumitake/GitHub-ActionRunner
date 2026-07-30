package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func permitTestDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

type fakePermitUsageAuditSource struct {
	snapshot permitUsageAuditSnapshot
	err      error
	calls    uint32
	slot     networkjail.CapacitySlotID
	gen      networkjail.JobGeneration
}

func (s *fakePermitUsageAuditSource) AuditActiveUsage(
	_ context.Context,
	slot networkjail.CapacitySlotID,
	generation networkjail.JobGeneration,
) (permitUsageAuditSnapshot, error) {
	s.calls++
	s.slot = slot
	s.gen = generation
	return s.snapshot, s.err
}

func TestPermitNonconsumptionTrackerSealsEqualReadOnlyAudit(t *testing.T) {
	t.Parallel()

	prepared := permitTestDigest("prepared")
	policy := permitTestDigest("policy")
	closedDenials := permitTestDigest("closed-denials")
	slot := networkjail.CapacitySlotID(17)
	generation := networkjail.JobGeneration(29)
	tracker, err := newPermitNonconsumptionTracker(
		prepared,
		slot,
		generation,
	)
	if err != nil {
		t.Fatalf("newPermitNonconsumptionTracker: %v", err)
	}
	source := &fakePermitUsageAuditSource{
		snapshot: permitUsageAuditSnapshot{
			Digest:     prepared,
			Slot:       slot,
			Generation: generation,
		},
	}
	proof, err := tracker.Prove(
		context.Background(),
		source,
		policy,
		closedDenials,
	)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if source.calls != 1 ||
		source.slot != slot ||
		source.gen != generation {
		t.Fatalf(
			"audit calls=%d slot=%d generation=%d",
			source.calls,
			source.slot,
			source.gen,
		)
	}
	if proof.Digest() == "" ||
		!proof.Matches(
			prepared,
			policy,
			slot,
			generation,
			closedDenials,
		) {
		t.Fatalf("proof = %#v", proof)
	}
	if tracker.PreparedUsageDigest() != prepared {
		t.Fatal("negative audit replaced the prepared usage digest")
	}
	if _, err := tracker.Prove(
		context.Background(),
		source,
		policy,
		closedDenials,
	); !errors.Is(err, ErrFixtureStart) {
		t.Fatalf("second Prove error = %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("second Prove crossed audit boundary: calls=%d", source.calls)
	}
}

func TestPermitNonconsumptionTrackerFailsClosedOnAuditDrift(
	t *testing.T,
) {
	t.Parallel()

	prepared := permitTestDigest("prepared")
	policy := permitTestDigest("policy")
	closedDenials := permitTestDigest("closed-denials")
	slot := networkjail.CapacitySlotID(17)
	generation := networkjail.JobGeneration(29)
	auditFailure := errors.New("audit missing required permit class")
	tests := map[string]struct {
		snapshot permitUsageAuditSnapshot
		err      error
	}{
		"changed usage": {
			snapshot: permitUsageAuditSnapshot{
				Digest:     permitTestDigest("changed"),
				Slot:       slot,
				Generation: generation,
			},
		},
		"changed slot": {
			snapshot: permitUsageAuditSnapshot{
				Digest:     prepared,
				Slot:       slot + 1,
				Generation: generation,
			},
		},
		"changed generation": {
			snapshot: permitUsageAuditSnapshot{
				Digest:     prepared,
				Slot:       slot,
				Generation: generation + 1,
			},
		},
		"missing class": {
			err: auditFailure,
		},
		"invalid digest": {
			snapshot: permitUsageAuditSnapshot{
				Digest:     "not-a-digest",
				Slot:       slot,
				Generation: generation,
			},
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tracker, err := newPermitNonconsumptionTracker(
				prepared,
				slot,
				generation,
			)
			if err != nil {
				t.Fatalf(
					"newPermitNonconsumptionTracker: %v",
					err,
				)
			}
			source := &fakePermitUsageAuditSource{
				snapshot: test.snapshot,
				err:      test.err,
			}
			if _, err := tracker.Prove(
				context.Background(),
				source,
				policy,
				closedDenials,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("Prove error = %v", err)
			}
			if source.calls != 1 {
				t.Fatalf("audit calls = %d, want 1", source.calls)
			}
			if tracker.PreparedUsageDigest() != prepared {
				t.Fatal("failed audit replaced prepared usage digest")
			}
		})
	}
}

func TestPermitNonconsumptionDigestBindsEveryClosedField(t *testing.T) {
	t.Parallel()

	base := permitNonconsumptionInput{
		PreparedUsageDigest: permitTestDigest("prepared"),
		RepeatedAuditDigest: permitTestDigest("prepared"),
		PolicyDigest:        permitTestDigest("policy"),
		Slot:                networkjail.CapacitySlotID(17),
		Generation:          networkjail.JobGeneration(29),
		ClosedDenialsDigest: permitTestDigest("closed-denials"),
	}
	proof, err := sealPermitNonconsumption(base)
	if err != nil {
		t.Fatalf("sealPermitNonconsumption: %v", err)
	}
	if proof.Digest() == "" {
		t.Fatal("permit nonconsumption digest is empty")
	}

	mutations := map[string]func(*permitNonconsumptionInput){
		"prepared": func(input *permitNonconsumptionInput) {
			input.PreparedUsageDigest = permitTestDigest("changed")
			input.RepeatedAuditDigest = input.PreparedUsageDigest
		},
		"policy": func(input *permitNonconsumptionInput) {
			input.PolicyDigest = permitTestDigest("changed")
		},
		"slot": func(input *permitNonconsumptionInput) {
			input.Slot++
		},
		"generation": func(input *permitNonconsumptionInput) {
			input.Generation++
		},
		"closed denials": func(input *permitNonconsumptionInput) {
			input.ClosedDenialsDigest = permitTestDigest("changed")
		},
	}
	for name, mutate := range mutations {
		name := name
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			changed := base
			mutate(&changed)
			changedProof, err := sealPermitNonconsumption(changed)
			if err != nil {
				t.Fatalf("sealPermitNonconsumption: %v", err)
			}
			if changedProof.Digest() == proof.Digest() {
				t.Fatal("digest did not bind changed field")
			}
		})
	}

	unequal := base
	unequal.RepeatedAuditDigest = permitTestDigest("changed")
	if _, err := sealPermitNonconsumption(unequal); !errors.Is(
		err,
		ErrFixtureStart,
	) {
		t.Fatalf("unequal audit error = %v", err)
	}
}

func TestOrchestratedRuntimePermitNonconsumptionKeepsPositiveProofSeparate(
	t *testing.T,
) {
	t.Parallel()

	binding := validClosedNetworkSessionBinding(t)
	closedDenials := permitClosedDenialsObservation(t, binding)
	prepared := permitTestDigest("prepared")
	slot := networkjail.CapacitySlotID(17)
	generation := networkjail.JobGeneration(29)
	tracker, err := newPermitNonconsumptionTracker(
		prepared,
		slot,
		generation,
	)
	if err != nil {
		t.Fatalf("newPermitNonconsumptionTracker: %v", err)
	}
	source := &fakePermitUsageAuditSource{
		snapshot: permitUsageAuditSnapshot{
			Digest:     prepared,
			Slot:       slot,
			Generation: generation,
		},
	}
	runtime := &orchestratedFixtureRuntime{
		composition: fixtureRuntimeComposition{
			UsageAudit: source,
			Request: networkjail.PreparedSetupRequest{
				Broker: hostruntime.BrokerSpec{
					CapacitySlotID: uint32(slot),
					JobGeneration:  uint64(generation),
				},
				Graph: binding.Graph,
			},
		},
		heldReady:      true,
		usageReady:     true,
		nonconsumption: tracker,
	}
	proof, err := runtime.ProvePermitNonconsumption(
		context.Background(),
		closedDenials,
	)
	if err != nil {
		t.Fatalf("ProvePermitNonconsumption: %v", err)
	}
	if !proof.Matches(
		prepared,
		binding.Graph.Digest().String(),
		slot,
		generation,
		closedDenials.Digest,
	) {
		t.Fatalf("proof = %#v", proof)
	}
	if tracker.PreparedUsageDigest() != prepared {
		t.Fatal("runtime replaced the prepared positive usage proof")
	}
}

func permitClosedDenialsObservation(
	t *testing.T,
	binding networkSessionBinding,
) closedDenialsSessionObservation {
	t.Helper()
	wire, canonical, err := parseClosedDenialsObservation(
		closedDenialsDocumentForTest(binding.Graph),
		binding.Graph,
	)
	if err != nil {
		t.Fatalf("parseClosedDenialsObservation: %v", err)
	}
	defer zeroClosedBytes(canonical)
	name, cleanup := closedNetworkIdentityForTest(binding)
	beforeDigest, err := closedStructuredDigest(
		"portable-ghar.task11.closed-denials.before.v1\x00",
		wire.Before,
	)
	if err != nil {
		t.Fatalf("closedStructuredDigest(before): %v", err)
	}
	directAfterDigest, err := closedStructuredDigest(
		"portable-ghar.task11.closed-denials.direct-after.v1\x00",
		wire.DirectAfter,
	)
	if err != nil {
		t.Fatalf("closedStructuredDigest(direct): %v", err)
	}
	parserAfterDigest, err := closedStructuredDigest(
		"portable-ghar.task11.closed-denials.parser-after.v1\x00",
		wire.ParserAfter,
	)
	if err != nil {
		t.Fatalf("closedStructuredDigest(parser): %v", err)
	}
	observation := closedDenialsSessionObservation{
		Name:              name,
		Cleanup:           cleanup,
		PolicyDigest:      wire.PolicyDigest,
		IPFamily:          wire.IPFamily,
		BrokerIPv6Posture: wire.BrokerIPv6Posture,
		BeforeDigest:      beforeDigest,
		DirectAfterDigest: directAfterDigest,
		ParserAfterDigest: parserAfterDigest,
		IPv4TCP:           wire.IPv4TCP,
		IPv4UDP:           wire.IPv4UDP,
		IPv6TCP:           wire.IPv6TCP,
		IPv6UDP:           wire.IPv6UDP,
		DNSUDP:            wire.DNSUDP,
		RawICMP:           wire.RawICMP,
		PlaintextHTTP:     wire.PlaintextHTTP,
		UnsupportedPort:   wire.UnsupportedPort,
		SOCKSBind:         wire.SOCKSBind,
		SOCKSUDPAssociate: wire.SOCKSUDPAssociate,
		Digest: closedSessionDigest(
			"portable-ghar.task11.closed-denials.v1\x00",
			canonical,
		),
		Completed: true,
	}
	if !validClosedDenialsSessionObservation(
		observation,
		binding.Graph,
	) {
		t.Fatalf("closed denials observation = %#v", observation)
	}
	return observation
}
