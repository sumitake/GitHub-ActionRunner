package main

import (
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"strings"
	"testing"
)

func TestCanaryPlanUsesThePendingRuntimeAndAuthenticatedSessionCounter(t *testing.T) {
	report := pendingCanaryFixture(t)
	runtime := canaryRuntimeFixture(report)
	overlay := templateOverlay(t)
	overlay.Worker = &hostruntime.WorkerOverlay{FleetID: "example-fleet"}
	runtime.overlay = overlay
	runtime.overlay.Target.ProfileID = report.Binding().ProfileID()
	runtime.overlay.Manifest.Digest = report.Binding().RuntimeManifestDigest()
	status := localPolicyStatus{Mode: controller.AcquisitionDisabled, Epoch: 2, Digest: strings.Repeat("a", 64), Capacity: 0, WorkerLeaseGeneration: 9, CanaryReportDigest: report.Digest()}
	plan, err := buildCanaryPlan(runtime, report, status, overlay.Repositories[0].ScaleSetName)
	if err != nil || plan.LeaseGeneration != 9 || plan.FenceGeneration != report.Binding().FleetGeneration() || plan.ReportDigest != report.Digest() || len(plan.PolicyDigest) != 64 {
		t.Fatal("canary plan did not bind actual inputs", plan, err)
	}
	for _, change := range []func(*localPolicyStatus){func(s *localPolicyStatus) { s.WorkerLeaseGeneration = 0 },
		func(s *localPolicyStatus) { s.Epoch = 0 }, func(s *localPolicyStatus) { s.WorkerLeaseGeneration = 9007199254740992 }, func(s *localPolicyStatus) { s.Mode = controller.AcquisitionCanaryOnly; s.Capacity = 1 }} {
		bad := status
		change(&bad)
		if _, err := buildCanaryPlan(runtime, report, bad, overlay.Repositories[0].ScaleSetName); err == nil {
			t.Fatal("unready session or active mode accepted")
		}
	}
	if _, err := buildCanaryPlan(runtime, report, status, "unknown-scale-set"); err == nil {
		t.Fatal("uninventoried scale set accepted")
	}
}

func TestCanaryPlanRefusesRuntimeDriftNonpendingOrAmbiguousScaleSet(t *testing.T) {
	for _, scenario := range []string{"runtime drift", "missing worker", "duplicate scale set", "completed report"} {
		t.Run(scenario, func(t *testing.T) {
			report := pendingCanaryFixture(t)
			runtime := canaryRuntimeFixture(report)
			overlay := templateOverlay(t)
			overlay.Worker = &hostruntime.WorkerOverlay{FleetID: "example-fleet"}
			overlay.Target.ProfileID = report.Binding().ProfileID()
			overlay.Manifest.Digest = report.Binding().RuntimeManifestDigest()
			runtime.overlay = overlay
			scale := overlay.Repositories[0].ScaleSetName
			status := localPolicyStatus{Mode: controller.AcquisitionDisabled, Epoch: 1, Digest: strings.Repeat("a", 64), WorkerLeaseGeneration: 9, CanaryReportDigest: report.Digest()}
			switch scenario {
			case "runtime drift":
				runtime.manifest.FleetGeneration++
			case "missing worker":
				runtime.overlay.Worker = nil
			case "duplicate scale set":
				repo := runtime.overlay.Repositories[0]
				repo.Alias = "other-repo"
				runtime.overlay.Repositories = append(runtime.overlay.Repositories, repo)
			case "completed report":
				var err error
				report, err = completeCanaryReport(report, readyCanaryFixture(report))
				if err != nil {
					t.Fatal(err)
				}
				status.CanaryReportDigest = report.Digest()
			}
			if _, err := buildCanaryPlan(runtime, report, status, scale); err == nil {
				t.Fatal("unbound or ambiguous plan accepted")
			}
		})
	}
}

func TestCanaryPlanRequiresTheRunningControllersOriginalReport(t *testing.T) {
	report := pendingCanaryFixture(t)
	runtime := canaryRuntimeFixture(report)
	overlay := templateOverlay(t)
	overlay.Worker = &hostruntime.WorkerOverlay{FleetID: "example-fleet"}
	overlay.Target.ProfileID = report.Binding().ProfileID()
	overlay.Manifest.Digest = report.Binding().RuntimeManifestDigest()
	runtime.overlay = overlay
	for _, digest := range []string{"", strings.Repeat("c", 64)} {
		status := localPolicyStatus{Mode: controller.AcquisitionDisabled, Epoch: 2, Digest: strings.Repeat("a", 64), WorkerLeaseGeneration: 9, CanaryReportDigest: digest}
		if _, err := buildCanaryPlan(runtime, report, status, overlay.Repositories[0].ScaleSetName); err == nil {
			t.Fatal("mixed the running session with a different on-disk runtime/report")
		}
	}
}

func TestCanaryPlanRequiresAnActiveWorkerCompatibleRepository(t *testing.T) {
	for _, scenario := range []string{"archived-disabled", "pending-reactivation", "uppercase alias", "unicode alias", "uppercase scale set", "unicode scale set", "long scale set"} {
		t.Run(scenario, func(t *testing.T) {
			report := pendingCanaryFixture(t)
			runtime := canaryRuntimeFixture(report)
			overlay := templateOverlay(t)
			overlay.Worker = &hostruntime.WorkerOverlay{FleetID: "example-fleet"}
			overlay.Target.ProfileID = report.Binding().ProfileID()
			overlay.Manifest.Digest = report.Binding().RuntimeManifestDigest()
			runtime.overlay = overlay
			repo := &runtime.overlay.Repositories[0]
			switch scenario {
			case "archived-disabled", "pending-reactivation":
				repo.Eligibility = scenario
			case "uppercase alias":
				repo.Alias = "Example"
			case "unicode alias":
				repo.Alias = "exämple"
			case "uppercase scale set":
				repo.ScaleSetName = "Example"
			case "unicode scale set":
				repo.ScaleSetName = "exämple"
			case "long scale set":
				repo.ScaleSetName = strings.Repeat("a", 65)
			}
			status := localPolicyStatus{Mode: controller.AcquisitionDisabled, Epoch: 2, Digest: strings.Repeat("a", 64), WorkerLeaseGeneration: 9, CanaryReportDigest: report.Digest()}
			if _, err := buildCanaryPlan(runtime, report, status, repo.ScaleSetName); err == nil {
				t.Fatal("planned work that the controller or Worker cannot admit")
			}
		})
	}
}
