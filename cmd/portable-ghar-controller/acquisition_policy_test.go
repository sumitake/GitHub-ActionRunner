package main

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/admission"
	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// templateOverlay loads the assembly test's overlay template: a complete,
// synthetic overlay whose manifest-bound fields are irrelevant here.
func templateOverlay(t *testing.T) hostruntime.PrivateOverlay {
	t.Helper()
	document, err := os.ReadFile("../../internal/cli/testdata/private-overlay-template.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var overlay hostruntime.PrivateOverlay
	if err := json.Unmarshal(document, &overlay); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return overlay
}

// admittingOverlay is the template with an admission ceiling that holds one
// complete slot. The template sizes every component vector at the ceiling,
// so a slot's complete charge (four stable components plus the serialized
// helper or verifier) is five ceilings.
func admittingOverlay(t *testing.T) hostruntime.PrivateOverlay {
	t.Helper()
	overlay := templateOverlay(t)
	ceiling := &overlay.Resources.AdmissionCeiling
	for _, value := range []*uint64{
		&ceiling.MilliCPU, &ceiling.MemoryBytes, &ceiling.PIDs,
		&ceiling.FileDescriptors, &ceiling.TmpfsBytes, &ceiling.ScratchBytes,
		&ceiling.SocketStateBytes, &ceiling.DurableStateBytes, &ceiling.Inodes,
	} {
		*value *= 5
	}
	return overlay
}

func TestProductionAdmissionRejectsACeilingNoSlotFits(t *testing.T) {
	config, err := productionAdmissionConfig(templateOverlay(t), 4, time.Now)
	if err != nil {
		t.Fatalf("productionAdmissionConfig: %v", err)
	}
	if _, err := admission.NewBroker(config); !errors.Is(err, admission.ErrInvalidConfig) {
		t.Fatalf("NewBroker = %v, want ErrInvalidConfig for the template ceiling", err)
	}
}

func TestProductionAdmissionAndPolicyComposeIntoAWorkingBroker(t *testing.T) {
	overlay := admittingOverlay(t)
	config, err := productionAdmissionConfig(overlay, 4, time.Now)
	if err != nil {
		t.Fatalf("productionAdmissionConfig: %v", err)
	}
	broker, err := admission.NewBroker(config)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	adapter, err := admission.NewControllerAdapter(
		broker,
		broker.(admission.LiveHistory),
		config.Repositories,
		config.TransientMode,
	)
	if err != nil {
		t.Fatalf("NewControllerAdapter: %v", err)
	}

	template, err := productionEnabledPolicyTemplate(overlay)
	if err != nil {
		t.Fatalf("productionEnabledPolicyTemplate: %v", err)
	}
	if template.Mode != controller.AcquisitionEnabled ||
		template.MaxCapacity != int(overlay.Resources.MaxCapacity) ||
		len(template.EligibleScaleSets) != 1 ||
		template.EligibleScaleSets[0] != overlay.Repositories[0].ScaleSetName ||
		len(template.RepositoryPolicies) != len(overlay.Repositories) {
		t.Fatalf("template = %+v", template)
	}
	// Startup persists the next epoch and applies it to the broker, which
	// starts at the durable epoch.
	template.Epoch = 5
	if err := adapter.ApplyAcquisitionPolicy(template); err != nil {
		t.Fatalf("ApplyAcquisitionPolicy(enabled template): %v", err)
	}
}

func TestProductionAdmissionConfigRejectsUnrepresentableValues(t *testing.T) {
	tests := map[string]func(*hostruntime.PrivateOverlay){
		"ceiling beyond int64": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Resources.AdmissionCeiling.MemoryBytes = 1 << 63
		},
		"profile beyond int64": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Repositories[0].SlotResources.Runner.PIDs = 1 << 63
		},
		"malformed poll lease": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Controller.PollLeaseTTL = "soon"
		},
		"malformed aging threshold": func(overlay *hostruntime.PrivateOverlay) {
			overlay.Repositories[0].AgingThreshold = "later"
		},
	}
	if _, err := productionAdmissionConfig(templateOverlay(t), 0, time.Now); err == nil {
		t.Fatal("productionAdmissionConfig accepted a zero policy epoch")
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			overlay := templateOverlay(t)
			mutate(&overlay)
			if _, err := productionAdmissionConfig(overlay, 4, time.Now); err == nil {
				t.Fatal("productionAdmissionConfig accepted an unrepresentable value")
			}
		})
	}
}

func TestProductionHistoryPressureComesFromExistingLimits(t *testing.T) {
	overlay := templateOverlay(t)
	limits, err := productionHistoryLimits(overlay)
	if err != nil {
		t.Fatalf("productionHistoryLimits: %v", err)
	}
	thresholds, err := productionHistoryPressure(overlay, limits)
	if err != nil {
		t.Fatalf("productionHistoryPressure: %v", err)
	}
	// The template sets 1000 history rows, a reserve of 10 rows per job at a
	// fleet concurrency of 2, and an 8-row network ledger reserve.
	want := controller.HistoryPressureThresholds{
		WarningHistoryRows:        980,
		StopHistoryRows:           1000,
		WarningHistoryBytes:       1048576 - 2048,
		StopHistoryBytes:          1048576,
		WarningNetworkLedgerRows:  992,
		StopNetworkLedgerRows:     1000,
		WarningNetworkLedgerBytes: 1048576 - 8192,
		StopNetworkLedgerBytes:    1048576,
		WarningMaxCapacity:        1,
	}
	if thresholds != want {
		t.Fatalf("thresholds = %+v, want %+v", thresholds, want)
	}

	limits.MaxNetworkLedgerRows = overlay.Resources.NetworkLedgerReserveRows
	if _, err := productionHistoryPressure(overlay, limits); err == nil {
		t.Fatal("productionHistoryPressure accepted a reserve that fills the ledger")
	}
}
