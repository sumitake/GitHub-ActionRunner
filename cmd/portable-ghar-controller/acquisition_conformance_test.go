package main

import (
	"context"
	"errors"
	"testing"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

type productionReportGate struct {
	calls []conformance.AcquisitionConformanceRequest
	err   error
}

func (gate *productionReportGate) Verify(
	_ context.Context,
	request conformance.AcquisitionConformanceRequest,
) error {
	gate.calls = append(gate.calls, request)
	return gate.err
}

func TestProductionCanaryConformanceRefusesEnabledDespitePassingReport(t *testing.T) {
	report := &productionReportGate{}
	gate := productionCanaryConformance{report: report}
	request := conformance.AcquisitionConformanceRequest{
		BuildID:         "build-a",
		HostProfileID:   "profile-a",
		FleetGeneration: 7,
		Mode:            conformance.AcquisitionEnabled,
	}
	// A passing report would grant enabled authority through the generic gate.
	if err := report.Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	report.calls = nil
	if err := gate.Verify(context.Background(), request); !errors.Is(err, errProductionEnabledUnavailable) {
		t.Fatalf("enabled = %v, want unavailable production adapters", err)
	}
	if len(report.calls) != 0 {
		t.Fatal("enabled delegated to the report gate")
	}
}

func TestProductionCanaryConformancePreservesReportBindingAndFailures(t *testing.T) {
	request := conformance.AcquisitionConformanceRequest{
		BuildID:         "build-a",
		HostProfileID:   "profile-a",
		FleetGeneration: 7,
		Mode:            conformance.AcquisitionCanaryOnly,
	}
	for _, reportErr := range []error{
		nil,
		conformance.ErrAcquisitionConformanceMismatch,
		conformance.ErrAcquisitionConformanceUnavailable,
	} {
		report := &productionReportGate{err: reportErr}
		gate := productionCanaryConformance{report: report}
		if err := gate.Verify(context.Background(), request); !errors.Is(err, reportErr) {
			t.Fatalf("canary = %v, want report result %v", err, reportErr)
		}
		if len(report.calls) != 1 || report.calls[0] != request {
			t.Fatalf("report requests = %+v, want exact binding %+v", report.calls, request)
		}
	}
	if err := (productionCanaryConformance{}).Verify(context.Background(), request); !errors.Is(err, conformance.ErrAcquisitionConformanceUnavailable) {
		t.Fatalf("missing report = %v, want unavailable", err)
	}
}

func TestProductionCanaryConformancePreservesCancellation(t *testing.T) {
	report := &productionReportGate{}
	gate := productionCanaryConformance{report: report}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, mode := range []conformance.AcquisitionMode{
		conformance.AcquisitionCanaryOnly,
		conformance.AcquisitionEnabled,
	} {
		if err := gate.Verify(ctx, conformance.AcquisitionConformanceRequest{Mode: mode}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled %s = %v", mode, err)
		}
	}
	if len(report.calls) != 0 {
		t.Fatal("invalid context reached report gate")
	}
}
