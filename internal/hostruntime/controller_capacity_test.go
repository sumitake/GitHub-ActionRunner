package hostruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
)

func TestControllerCapacityProviderRereadsAndMapsClosedProfileState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC)
	profile := &profileStub{
		id:     HostProfileStrictLinux,
		report: validConformanceReport(HostProfileStrictLinux),
	}
	provider, err := NewControllerCapacityProvider(ControllerCapacityConfig{
		Profile: profile,
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewControllerCapacityProvider: %v", err)
	}

	report, err := provider.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate normal: %v", err)
	}
	if report.State != controller.HostCapacityNormal ||
		report.EffectiveCapacity != 2 ||
		report.EvidenceDigest != strings.Repeat("d", 64) ||
		report.ObservedAt != now ||
		profile.probeCalls != 1 {
		t.Fatalf("normal report = %+v, calls=%d", report, profile.probeCalls)
	}

	profile.report.State = ProfileWarning
	profile.report.EffectiveCapacity = 1
	now = now.Add(time.Minute)
	report, err = provider.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate warning: %v", err)
	}
	if report.State != controller.HostCapacityWarning ||
		report.EffectiveCapacity != 1 ||
		report.ObservedAt != now ||
		profile.probeCalls != 2 {
		t.Fatalf("warning report = %+v, calls=%d", report, profile.probeCalls)
	}

	profile.report.State = ProfileStop
	profile.report.EffectiveCapacity = 0
	now = now.Add(time.Minute)
	report, err = provider.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate stop: %v", err)
	}
	if report.State != controller.HostCapacityStop ||
		report.EffectiveCapacity != 0 ||
		report.ObservedAt != now ||
		profile.probeCalls != 3 {
		t.Fatalf("stop report = %+v, calls=%d", report, profile.probeCalls)
	}
}

func TestControllerCapacityProviderFailsClosedOnInvalidOrMismatchedReport(t *testing.T) {
	t.Parallel()

	valid := validConformanceReport(HostProfileStrictLinux)
	tests := []struct {
		name    string
		profile *profileStub
	}{
		{
			name: "probe error",
			profile: &profileStub{
				id:       HostProfileStrictLinux,
				probeErr: errors.New("observation failed"),
			},
		},
		{
			name: "profile mismatch",
			profile: &profileStub{
				id:     HostProfileStrictLinux,
				report: validConformanceReport(HostProfileQTSCaplessRoot),
			},
		},
		{
			name: "invalid digest",
			profile: &profileStub{
				id: HostProfileStrictLinux,
				report: func() ConformanceReport {
					report := valid
					report.EvidenceDigest = "not-a-digest"
					return report
				}(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provider, err := NewControllerCapacityProvider(ControllerCapacityConfig{
				Profile: test.profile,
				Now: func() time.Time {
					return time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC)
				},
			})
			if err != nil {
				t.Fatalf("NewControllerCapacityProvider: %v", err)
			}
			if _, err := provider.Evaluate(context.Background()); err == nil {
				t.Fatal("invalid profile report was accepted")
			}
		})
	}
}

func TestControllerCapacityProviderMapsExplicitDegradedProfileWithoutInventingPressure(t *testing.T) {
	t.Parallel()

	report := validConformanceReport(HostProfileQTSCaplessRoot)
	report.State = ProfileDegraded
	report.Degraded = true
	profile := &profileStub{
		id:     HostProfileQTSCaplessRoot,
		report: report,
	}
	provider, err := NewControllerCapacityProvider(ControllerCapacityConfig{
		Profile: profile,
		Now:     time.Now,
	})
	if err != nil {
		t.Fatalf("NewControllerCapacityProvider: %v", err)
	}
	projected, err := provider.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if projected.State != controller.HostCapacityNormal ||
		projected.EffectiveCapacity != int(report.EffectiveCapacity) {
		t.Fatalf("degraded projection = %+v", projected)
	}
}

func TestControllerCapacityProviderConstructorRejectsMissingDependencies(t *testing.T) {
	t.Parallel()

	if _, err := NewControllerCapacityProvider(ControllerCapacityConfig{}); err == nil {
		t.Fatal("missing dependencies accepted")
	}
	if _, err := NewControllerCapacityProvider(ControllerCapacityConfig{
		Profile: &profileStub{id: HostProfileStrictLinux},
	}); err == nil {
		t.Fatal("missing clock accepted")
	}
}
