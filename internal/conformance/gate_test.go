package conformance

import (
	"context"
	"errors"
	"testing"
)

func TestAcquisitionGateAcceptsOnlyMatchingFullyPassedReport(t *testing.T) {
	t.Parallel()

	report := Run(context.Background(), validProfile(t, true))
	gate, err := NewAcquisitionGate(report)
	if err != nil {
		t.Fatalf("NewAcquisitionGate: %v", err)
	}
	for _, mode := range []AcquisitionMode{
		AcquisitionCanaryOnly,
		AcquisitionEnabled,
	} {
		request := AcquisitionConformanceRequest{
			BuildID:         report.Binding().BuildID(),
			HostProfileID:   report.Binding().ProfileID(),
			FleetGeneration: report.Binding().FleetGeneration(),
			Mode:            mode,
		}
		if err := gate.Verify(context.Background(), request); err != nil {
			t.Fatalf("Verify(%q): %v", mode, err)
		}
	}
}

func TestAcquisitionGateRejectsIncompleteOrTamperedReport(t *testing.T) {
	t.Parallel()

	passed := Run(context.Background(), validProfile(t, true))
	pending := Run(context.Background(), validProfile(t, false))
	failedProfile := validProfile(t, true)
	failedProfile.actualErr[ActualBrokerEgress] = ErrPolicy
	failed := Run(context.Background(), failedProfile)

	missing := passed
	missing.cases = append([]CaseEvidence(nil), passed.cases[:len(passed.cases)-1]...)
	reordered := passed
	reordered.cases = cloneCaseEvidence(passed.cases)
	reordered.cases[0], reordered.cases[1] = reordered.cases[1], reordered.cases[0]
	crossLayer := passed
	crossLayer.cases = cloneCaseEvidence(passed.cases)
	crossLayer.cases[0].layer = LayerSyntheticLifecycle
	tampered := passed
	tampered.reportDigest = testDigestD

	for name, report := range map[string]Report{
		"pending":     pending,
		"failed":      failed,
		"missing":     missing,
		"reordered":   reordered,
		"cross-layer": crossLayer,
		"tampered":    tampered,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewAcquisitionGate(report); !errors.Is(
				err,
				ErrAcquisitionConformanceUnavailable,
			) {
				t.Fatalf(
					"NewAcquisitionGate(%s) = %v, want unavailable",
					name,
					err,
				)
			}
		})
	}
}

func TestAcquisitionGateRejectsMismatchedRequestAndCancellation(t *testing.T) {
	t.Parallel()

	report := Run(context.Background(), validProfile(t, true))
	gate, err := NewAcquisitionGate(report)
	if err != nil {
		t.Fatalf("NewAcquisitionGate: %v", err)
	}
	valid := AcquisitionConformanceRequest{
		BuildID:         report.Binding().BuildID(),
		HostProfileID:   report.Binding().ProfileID(),
		FleetGeneration: report.Binding().FleetGeneration(),
		Mode:            AcquisitionEnabled,
	}

	wrongBuild := valid
	wrongBuild.BuildID = testDigestB
	wrongProfile := valid
	wrongProfile.HostProfileID = "strict-linux"
	wrongGeneration := valid
	wrongGeneration.FleetGeneration++
	wrongMode := valid
	wrongMode.Mode = AcquisitionMode("disabled")

	for name, request := range map[string]AcquisitionConformanceRequest{
		"build":      wrongBuild,
		"profile":    wrongProfile,
		"generation": wrongGeneration,
		"mode":       wrongMode,
	} {
		t.Run(name, func(t *testing.T) {
			if err := gate.Verify(context.Background(), request); !errors.Is(
				err,
				ErrAcquisitionConformanceMismatch,
			) {
				t.Fatalf("Verify(%s) = %v, want mismatch", name, err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.Verify(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify(canceled) = %v, want context.Canceled", err)
	}
}

func TestUnavailableAcquisitionGateAlwaysFailsClosed(t *testing.T) {
	t.Parallel()

	gate := NewUnavailableAcquisitionGate()
	if err := gate.Verify(context.Background(), AcquisitionConformanceRequest{
		BuildID:         testDigestA,
		HostProfileID:   "qts-capless-root",
		FleetGeneration: 7,
		Mode:            AcquisitionCanaryOnly,
	}); !errors.Is(err, ErrAcquisitionConformanceUnavailable) {
		t.Fatalf("Verify = %v, want unavailable", err)
	}
}
