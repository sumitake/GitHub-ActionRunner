//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/tests/integration/testenv"
)

func TestPortableGHARConformance(t *testing.T) {
	fixture := testenv.StartDockerFixture(t)
	report := conformance.Run(context.Background(), fixture)
	// Write before judging the report, so a failed run still records which
	// cases passed.
	if err := fixture.WriteReport(report); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := testenv.ValidateConformanceTerminalReport(report); err != nil {
		t.Fatalf("terminal report: %v", err)
	}

	document, err := conformance.MarshalReport(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	parsed, err := conformance.ParseReport(document, len(document))
	if err != nil {
		t.Fatalf("parse canonical report: %v", err)
	}
	roundTrip, err := conformance.MarshalReport(parsed)
	if err != nil {
		t.Fatalf("marshal parsed report: %v", err)
	}
	if !bytes.Equal(roundTrip, document) {
		t.Fatal("canonical report changed across exact round trip")
	}
}
