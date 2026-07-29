package hostruntime

import (
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const goldenHostActionResultDigest = "1446ec6ac0e04b22f9abbb4d1563e48cfbc69bfae7f9f52eda26d7ee781b1a7b"

func TestHostActionResultGoldenAndRoundTrip(t *testing.T) {
	t.Parallel()

	proof := strings.Repeat("c", 64)
	result := HostActionResult{
		SchemaVersion:     1,
		Status:            HostActionComplete,
		OperationID:       strings.Repeat("a", 64),
		JournalDigest:     strings.Repeat("b", 64),
		TargetProofDigest: &proof,
		FenceGeneration:   7,
		ActiveFleet:       fleetfence.FleetPortable,
		ErrorClass:        "",
	}
	document, digest, err := MarshalHostActionResult(result)
	if err != nil {
		t.Fatalf("MarshalHostActionResult() error = %v", err)
	}
	if digest != goldenHostActionResultDigest {
		t.Fatalf(
			"MarshalHostActionResult() digest = %q, want %q; json=%s",
			digest,
			goldenHostActionResultDigest,
			document,
		)
	}
	decoded, decodedDigest, err := ParseHostActionResult(
		document,
		len(document),
	)
	if err != nil ||
		decoded.Status != HostActionComplete ||
		decodedDigest != digest {
		t.Fatalf(
			"ParseHostActionResult() = %#v, %q, %v",
			decoded,
			decodedDigest,
			err,
		)
	}
}

func TestHostActionResultRejectsFalseSuccessAndNoncanonicalInput(t *testing.T) {
	t.Parallel()

	proof := strings.Repeat("c", 64)
	base := HostActionResult{
		SchemaVersion:     1,
		Status:            HostActionComplete,
		OperationID:       strings.Repeat("a", 64),
		JournalDigest:     strings.Repeat("b", 64),
		TargetProofDigest: &proof,
		FenceGeneration:   7,
		ActiveFleet:       fleetfence.FleetPortable,
	}
	mutations := []func(*HostActionResult){
		func(result *HostActionResult) { result.SchemaVersion = 0 },
		func(result *HostActionResult) { result.Status = "ok" },
		func(result *HostActionResult) { result.TargetProofDigest = nil },
		func(result *HostActionResult) { result.ErrorClass = "ignored" },
		func(result *HostActionResult) { result.OperationID = strings.Repeat("A", 64) },
		func(result *HostActionResult) { result.ActiveFleet = "unknown" },
	}
	for index, mutate := range mutations {
		result := base
		mutate(&result)
		if _, _, err := MarshalHostActionResult(result); !errors.Is(
			err,
			ErrInvalidHostActionResult,
		) {
			t.Fatalf("mutation %d error = %v", index, err)
		}
	}
	failed := base
	failed.Status = HostActionFailed
	failed.TargetProofDigest = nil
	failed.ErrorClass = "effect_failed"
	if _, _, err := MarshalHostActionResult(failed); err != nil {
		t.Fatalf("MarshalHostActionResult(failed) error = %v", err)
	}
	failed.TargetProofDigest = &proof
	if _, _, err := MarshalHostActionResult(failed); !errors.Is(
		err,
		ErrInvalidHostActionResult,
	) {
		t.Fatalf("failed-with-proof error = %v", err)
	}
}
