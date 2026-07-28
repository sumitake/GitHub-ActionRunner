package hostruntime

import "testing"

func TestDeploymentEligibilityRequiresMatchingSourceAndTargetProofs(t *testing.T) {
	binding := EvidenceBinding{
		BuildID:    "build-" + repeatHex("a"),
		Profile:    "strict-linux-v1",
		Generation: 23,
	}
	source, err := recordSourceVerification(binding, repeatHex("b"))
	if err != nil {
		t.Fatalf("recordSourceVerification: %v", err)
	}
	target, err := recordTargetConformance(binding, repeatHex("c"))
	if err != nil {
		t.Fatalf("recordTargetConformance: %v", err)
	}

	eligible, err := NewDeploymentEligibility(source, target)
	if err != nil {
		t.Fatalf("NewDeploymentEligibility: %v", err)
	}
	if eligible.Binding() != binding {
		t.Fatalf("eligible binding = %+v, want %+v", eligible.Binding(), binding)
	}
}

func TestDeploymentEligibilityRejectsMissingOrMismatchedTarget(t *testing.T) {
	binding := EvidenceBinding{BuildID: "build-" + repeatHex("a"), Profile: "strict-linux-v1", Generation: 23}
	source, err := recordSourceVerification(binding, repeatHex("b"))
	if err != nil {
		t.Fatalf("recordSourceVerification: %v", err)
	}

	if _, err := NewDeploymentEligibility(source, TargetConformance{}); err == nil {
		t.Fatal("source-only proof constructed DeploymentEligibility")
	}

	other := binding
	other.Generation++
	target, err := recordTargetConformance(other, repeatHex("c"))
	if err != nil {
		t.Fatalf("recordTargetConformance: %v", err)
	}
	if _, err := NewDeploymentEligibility(source, target); err == nil {
		t.Fatal("mismatched evidence generations constructed DeploymentEligibility")
	}
}

func repeatHex(char string) string {
	result := ""
	for range 64 {
		result += char
	}
	return result
}
