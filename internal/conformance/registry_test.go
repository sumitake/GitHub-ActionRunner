package conformance_test

import (
	"slices"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

func TestRequiredCasesHaveExactOrderAndLayers(t *testing.T) {
	t.Parallel()

	want := []struct {
		id    conformance.CaseID
		layer conformance.ProofLayer
	}{
		{conformance.CaseHostProfile, conformance.LayerActualHostImmutable},
		{conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable},
		{conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable},
		{conformance.CaseMountAndSecretIsolation, conformance.LayerActualHostImmutable},
		{conformance.CaseSandbox, conformance.LayerActualHostImmutable},
		{conformance.CaseRunnerPayload, conformance.LayerActualHostImmutable},
		{conformance.CaseSyntheticOneJob, conformance.LayerSyntheticLifecycle},
		{conformance.CaseCleanupMatrix, conformance.LayerSyntheticLifecycle},
		{conformance.CaseReclamationSeries, conformance.LayerSyntheticLifecycle},
		{conformance.CaseProxyToolCompatibility, conformance.LayerActualHostImmutable},
		{conformance.CaseSeedIsolation, conformance.LayerSyntheticLifecycle},
		{conformance.CaseWatchdogRecovery, conformance.LayerSyntheticLifecycle},
		{conformance.CaseLegacyFenceRecovery, conformance.LayerSyntheticLifecycle},
		{conformance.CaseNoncancellableShutdown, conformance.LayerSyntheticLifecycle},
		{conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport},
	}

	got := conformance.RequiredCases()
	if len(got) != len(want) {
		t.Fatalf("RequiredCases length = %d, want %d", len(got), len(want))
	}
	for index, expected := range want {
		if got[index] != expected.id {
			t.Fatalf("RequiredCases[%d] = %q, want %q", index, got[index], expected.id)
		}
		layer, ok := conformance.RequiredLayer(got[index])
		if !ok || layer != expected.layer {
			t.Fatalf(
				"RequiredLayer(%q) = %q, %t; want %q, true",
				got[index],
				layer,
				ok,
				expected.layer,
			)
		}
	}
	if _, ok := conformance.RequiredLayer(conformance.CaseID("unknown")); ok {
		t.Fatal("RequiredLayer accepted unknown case")
	}
}

func TestRequiredCasesReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	first := conformance.RequiredCases()
	second := conformance.RequiredCases()
	if len(first) == 0 || !slices.Equal(first, second) {
		t.Fatal("RequiredCases did not return equal populated registries")
	}
	first[0] = conformance.CaseID("mutated")
	third := conformance.RequiredCases()
	if slices.Equal(first, third) || !slices.Equal(second, third) {
		t.Fatal("RequiredCases exposed mutable registry storage")
	}
}
