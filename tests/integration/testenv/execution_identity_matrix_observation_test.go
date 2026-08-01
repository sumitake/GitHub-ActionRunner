package testenv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

func TestExecutionIdentitySourceSealsOnlyExactSeparatedTarget(
	t *testing.T,
) {
	t.Parallel()

	target := TargetBinding{
		OperatingSystem:            "linux",
		Architecture:               "amd64",
		ExpectedEUID:               1000,
		ProfileID:                  "strict-linux",
		HostIdentityDigest:         inputDigestA,
		ControlHostIdentityDigest:  inputDigestB,
		IdentitySeparationRequired: true,
	}
	source, err := newExecutionIdentityMatrixSource(
		target,
		inputDigestA,
	)
	if err != nil {
		t.Fatalf("newExecutionIdentityMatrixSource: %v", err)
	}
	var requirement ObservationRequirement
	for _, current := range RequiredObservationMatrix() {
		if current.ID == "host-execution-identity" {
			requirement = current
			break
		}
	}
	observation, err := source.Observe(
		context.Background(),
		requirement,
	)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Requirement != requirement ||
		observation.AssertionCount != 3 ||
		len(observation.Measurements) != 0 ||
		!isLowerHex(observation.Digest, 64) {
		t.Fatalf("observation = %+v", observation)
	}
	if _, err := source.Observe(
		context.Background(),
		requirement,
	); !errors.Is(err, conformance.ErrObservation) {
		t.Fatalf("second Observe error = %v", err)
	}
}

func TestExecutionIdentitySourceRejectsEchoSubstitutionOrNoSeparation(
	t *testing.T,
) {
	t.Parallel()

	target := TargetBinding{
		OperatingSystem:            "linux",
		Architecture:               "arm64",
		ExpectedEUID:               0,
		ProfileID:                  "qts-capless-root",
		HostIdentityDigest:         inputDigestA,
		ControlHostIdentityDigest:  inputDigestB,
		IdentitySeparationRequired: true,
	}
	for name, mutate := range map[string]func(*TargetBinding, *string){
		"observed mismatch": func(_ *TargetBinding, observed *string) {
			*observed = inputDigestC
		},
		"same control identity": func(value *TargetBinding, _ *string) {
			value.ControlHostIdentityDigest = value.HostIdentityDigest
		},
		"separation disabled": func(value *TargetBinding, _ *string) {
			value.IdentitySeparationRequired = false
		},
		"invalid digest": func(value *TargetBinding, _ *string) {
			value.HostIdentityDigest = strings.Repeat("z", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := target
			observed := inputDigestA
			mutate(&candidate, &observed)
			if _, err := newExecutionIdentityMatrixSource(
				candidate,
				observed,
			); err != ErrFixtureStart {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
