package main

import (
	"context"
	"github.com/sumitake/portable-ghar/internal/controller"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCanaryGenerationFlowsThroughTheExistingRootLocalProbe(t *testing.T) {
	f := newAcquisitionProcessFixture(t)
	f.service.probeStatus = controller.PolicyStatus{Mode: controller.AcquisitionDisabled, Epoch: 2, Digest: strings.Repeat("a", 64)}
	f.process.config.WorkerLeaseGeneration = func() uint64 { return 9 }
	f.process.config.CanaryReportDigest = strings.Repeat("b", 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	admin, health, err := f.process.startServers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()); _ = health.Close(context.Background()) }()
	// The server uses the startup copy, not later mutable configuration.
	f.process.config.CanaryReportDigest = strings.Repeat("c", 64)
	client, err := newLocalAdminClient(f.adminPath, uint32(os.Geteuid()), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.call(context.Background(), localRequest{SchemaVersion: localProtocolSchemaVersion, Method: localMethodProbe})
	if err != nil || response.Policy.WorkerLeaseGeneration != 9 || response.Policy.CanaryReportDigest != strings.Repeat("b", 64) || response.Policy.Mode != controller.AcquisitionDisabled {
		t.Fatal("authenticated counter lost at existing probe boundary", response, err)
	}
	// The ordinary policy API remains the same identity-free shape.
	policy, err := client.Probe(context.Background())
	if err != nil || policy != f.service.probeStatus {
		t.Fatal("ordinary probe changed", policy, err)
	}
}

func TestCanaryGenerationProtocolRefusesUnsafeCounters(t *testing.T) {
	policy := localPolicyStatus{Mode: controller.AcquisitionDisabled, Epoch: 2, Digest: strings.Repeat("a", 64), WorkerLeaseGeneration: 9007199254740992}
	if validLocalPolicyStatus(&policy) {
		t.Fatal("unsafe protocol counter accepted")
	}
}

func TestCanaryProbeRejectsMalformedCapturedReportDigests(t *testing.T) {
	status := localPolicyStatus{Mode: controller.AcquisitionDisabled, Epoch: 1, Digest: strings.Repeat("a", 64), WorkerLeaseGeneration: 9, CanaryReportDigest: "invalid"}
	if validLocalPolicyStatus(&status) {
		t.Fatal("malformed startup report identity accepted")
	}
}
