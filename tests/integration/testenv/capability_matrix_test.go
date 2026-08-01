package testenv_test

import (
	"slices"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/tests/integration/testenv"
)

func TestCapabilityMatrixCoversEveryRequiredObservation(t *testing.T) {
	t.Parallel()

	matrix := testenv.RequiredObservationMatrix()
	if err := testenv.ValidateObservationMatrix(matrix); err != nil {
		t.Fatalf("ValidateObservationMatrix: %v", err)
	}
	wantIDs := testenv.RequiredObservationIDs()
	gotIDs := make([]testenv.ObservationID, 0, len(matrix))
	for _, row := range matrix {
		gotIDs = append(gotIDs, row.ID)
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("matrix IDs differ from required registry")
	}

	counts := make(map[conformance.CaseID]int)
	for _, row := range matrix {
		counts[row.Case]++
	}
	for _, caseID := range conformance.RequiredCases() {
		if counts[caseID] == 0 {
			t.Fatalf("case %q has no observation row", caseID)
		}
	}
	var githubDisableUpdate int
	for _, row := range matrix {
		if row.ID == "disable-update" {
			t.Fatal("local disable-update observation remains in the matrix")
		}
		if row.ID == "actual-github-disable-update" {
			githubDisableUpdate++
			if row.Case != conformance.CaseActualGitHubTransport ||
				row.Layer != conformance.LayerActualGitHubTransport ||
				row.Source != testenv.SourceActualGitHubCanary {
				t.Fatalf("actual GitHub DisableUpdate row = %+v", row)
			}
		}
	}
	if githubDisableUpdate != 1 {
		t.Fatalf(
			"actual GitHub DisableUpdate row count = %d, want 1",
			githubDisableUpdate,
		)
	}

	expectedSources := map[testenv.ObservationID]testenv.ObservationSource{
		"adapter-runner-netns-identity":        testenv.SourceBoundEvidenceLedger,
		"runner-loopback-only":                 testenv.SourceNetworkOrchestrator,
		"runner-tables-empty":                  testenv.SourceNetworkOrchestrator,
		"runner-conntrack-before":              testenv.SourceNetworkOrchestrator,
		"runner-tables-after-flood":            testenv.SourceClosedTestCommand,
		"runner-conntrack-after":               testenv.SourceClosedTestCommand,
		"runner-route-absence":                 testenv.SourceClosedTestCommand,
		"namespace-stable-after-attach":        testenv.SourceBoundEvidenceLedger,
		"runtime-capabilities-empty":           testenv.SourceBoundEvidenceLedger,
		"held-broker-sockets-zero":             testenv.SourceHostRuntimeEngine,
		"broker-denied-plaintext-http":         testenv.SourceClosedTestCommand,
		"broker-denied-connect-port":           testenv.SourceClosedTestCommand,
		"broker-denied-socks-operations":       testenv.SourceClosedTestCommand,
		"broker-denial-boundary":               testenv.SourceBoundEvidenceLedger,
		"broker-policy-ledger-authority-match": testenv.SourceBoundEvidenceLedger,
		"relay-mount-visibility":               testenv.SourceBoundEvidenceLedger,
		"authority-mount-visibility":           testenv.SourceBoundEvidenceLedger,
		"host-control-invisible":               testenv.SourceBoundEvidenceLedger,
		"runner-sizing-tuple-match":            testenv.SourceBoundEvidenceLedger,
	}
	seen := make(map[testenv.ObservationID]bool)
	for _, row := range matrix {
		expected, found := expectedSources[row.ID]
		if !found {
			continue
		}
		if row.Source != expected {
			t.Fatalf(
				"observation %q source = %q, want %q",
				row.ID,
				row.Source,
				expected,
			)
		}
		seen[row.ID] = true
	}
	for id := range expectedSources {
		if !seen[id] {
			t.Fatalf("required amended observation %q is absent", id)
		}
	}
}

func TestCapabilityMatrixRejectsLayerAndSourceSubstitution(t *testing.T) {
	t.Parallel()

	base := testenv.RequiredObservationMatrix()
	tests := map[string]func([]testenv.ObservationRequirement){
		"missing": func(rows []testenv.ObservationRequirement) {
			rows = rows[:len(rows)-1]
			if testenv.ValidateObservationMatrix(rows) == nil {
				t.Fatal("accepted missing row")
			}
		},
		"duplicate": func(rows []testenv.ObservationRequirement) {
			rows[len(rows)-1] = rows[0]
			if testenv.ValidateObservationMatrix(rows) == nil {
				t.Fatal("accepted duplicate row")
			}
		},
		"synthetic actual": func(rows []testenv.ObservationRequirement) {
			rows[0].Source = testenv.SourceSyntheticLocal
			if testenv.ValidateObservationMatrix(rows) == nil {
				t.Fatal("accepted synthetic source for actual case")
			}
		},
		"generic command": func(rows []testenv.ObservationRequirement) {
			rows[0].Operation = "exec"
			if testenv.ValidateObservationMatrix(rows) == nil {
				t.Fatal("accepted generic command")
			}
		},
		"github source elsewhere": func(rows []testenv.ObservationRequirement) {
			rows[0].Source = testenv.SourceActualGitHubCanary
			if testenv.ValidateObservationMatrix(rows) == nil {
				t.Fatal("accepted GitHub canary source outside case 15")
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			rows := append([]testenv.ObservationRequirement(nil), base...)
			mutate(rows)
		})
	}
}

func TestCapabilityMatrixReturnsDefensiveCopies(t *testing.T) {
	t.Parallel()

	first := testenv.RequiredObservationMatrix()
	second := testenv.RequiredObservationMatrix()
	if len(first) == 0 {
		t.Fatal("empty matrix")
	}
	first[0].Operation = "mutated"
	third := testenv.RequiredObservationMatrix()
	if slices.Equal(first, third) || !slices.Equal(second, third) {
		t.Fatal("matrix registry storage is mutable")
	}

	ids := testenv.RequiredObservationIDs()
	ids[0] = testenv.ObservationID("mutated")
	if slices.Equal(ids, testenv.RequiredObservationIDs()) {
		t.Fatal("observation ID registry storage is mutable")
	}
}
