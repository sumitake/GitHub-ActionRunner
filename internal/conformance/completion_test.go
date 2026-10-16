package conformance

import (
	"bytes"
	"context"
	"reflect"
	"testing"
)

func TestCompleteActualGitHubTransportPreservesOriginalReport(t *testing.T) {
	pending := Run(context.Background(), validProfile(t, false))
	before, err := MarshalReport(pending)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReport(before, len(before))
	if err != nil {
		t.Fatal(err)
	}
	result, err := SealActualGitHubTransport(ActualGitHubObservation{
		AssertionCount:    7,
		ObservationDigest: testDigestD,
		Measurements:      []MeasurementInput{{Name: "job_count", Value: 1, Unit: "count"}, {Name: "tool_count", Value: 10, Unit: "count"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := CompleteActualGitHubTransport(parsed, result)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireFullPass(completed); err != nil {
		t.Fatalf("completed report does not pass normal gate: %v", err)
	}
	if !reflect.DeepEqual(completed.binding, parsed.binding) ||
		!reflect.DeepEqual(completed.cases[:14], parsed.cases[:14]) ||
		!reflect.DeepEqual(completed.cleanup, parsed.cleanup) ||
		completed.observedProfileEvidenceDigest != parsed.observedProfileEvidenceDigest ||
		completed.observedNetworkEvidenceDigest != parsed.observedNetworkEvidenceDigest {
		t.Fatal("completion changed existing evidence or bindings")
	}
	if completed.reportDigest == parsed.reportDigest || completed.buildSeal == parsed.buildSeal {
		t.Fatal("completion retained old digest or build seal")
	}
	last := completed.cases[14]
	if last.observationDigest != testDigestD || last.assertionCount != 7 || last.status != StatusPassed || len(last.measurements) != 2 {
		t.Fatalf("case 15: %+v", last)
	}
	after, err := MarshalReport(pending)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("completion mutated input report")
	}
	document, err := MarshalReport(completed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReport(document, len(document)); err != nil {
		t.Fatal(err)
	}
	// Completed measurements must not alias caller-owned evidence.
	result.measurements[0].value = 99
	if err := ValidateReport(completed); err != nil {
		t.Fatal("result measurements alias completed report")
	}
}

func TestCompleteActualGitHubTransportRejectsInvalidReportOrResult(t *testing.T) {
	for name, change := range map[string]func(*Report, *ActualGitHubResult){
		"empty report":            func(r *Report, _ *ActualGitHubResult) { *r = Report{} },
		"already completed":       func(r *Report, _ *ActualGitHubResult) { *r = Run(context.Background(), validProfile(t, true)) },
		"corrupt original seal":   func(r *Report, _ *ActualGitHubResult) { r.buildSeal = testDigestC },
		"corrupt original digest": func(r *Report, _ *ActualGitHubResult) { r.reportDigest = testDigestC },
		"failed prerequisite": func(r *Report, _ *ActualGitHubResult) {
			p := validProfile(t, false)
			p.actualErr[ActualHostProfile] = ErrObservation
			*r = Run(context.Background(), p)
		},
		"failed cleanup": func(r *Report, _ *ActualGitHubResult) {
			p := validProfile(t, false)
			p.cleanupErr = ErrObservation
			*r = Run(context.Background(), p)
		},
		"changed binding":              func(r *Report, _ *ActualGitHubResult) { r.binding.wire.FleetGeneration++ },
		"pending result":               func(_ *Report, g *ActualGitHubResult) { *g = PendingActualGitHubTransport() },
		"pending flag with assertions": func(_ *Report, g *ActualGitHubResult) { g.pending = true },
		"empty result":                 func(_ *Report, g *ActualGitHubResult) { *g = ActualGitHubResult{} },
		"zero assertions":              func(_ *Report, g *ActualGitHubResult) { g.assertionCount = 0 },
		"invalid observation":          func(_ *Report, g *ActualGitHubResult) { g.observationDigest = "invalid" },
		"invalid measurement": func(_ *Report, g *ActualGitHubResult) {
			g.measurements = []Measurement{{name: "unknown", value: 1, unit: "count"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			pending := Run(context.Background(), validProfile(t, false))
			result, err := SealActualGitHubTransport(ActualGitHubObservation{AssertionCount: 7, ObservationDigest: testDigestD})
			if err != nil {
				t.Fatal(err)
			}
			change(&pending, &result)
			completed, err := CompleteActualGitHubTransport(pending, result)
			if err == nil {
				t.Fatalf("invalid completion accepted: %+v", completed)
			}
			if !reflect.DeepEqual(completed, Report{}) {
				t.Fatal("failure returned partial report")
			}
		})
	}
}
