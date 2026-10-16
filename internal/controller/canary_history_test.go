package controller

import (
	"context"
	"testing"
	"time"
)

func TestHistoryPressureIncludesRetainedCanaryEvidence(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	durable := &fakeDurableState{usage: HistoryUsage{CanaryEvidenceRows: 1, CanaryEvidenceLogicalBytes: 8192}}
	service := startPressureService(t, now, durable, &fakeAdmissionBroker{}, testHistoryPressureThresholds(), &fakeHealthPublisher{}, &fakeEventSink{})
	snapshot, err := service.EvaluateHistoryPressure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.HistoryRows != 1 || snapshot.HistoryLogicalBytes != 8192 {
		t.Fatal("retained canary evidence escaped pressure accounting")
	}
}
