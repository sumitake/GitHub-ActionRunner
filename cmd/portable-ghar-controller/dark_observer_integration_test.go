package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestDarkObserverCompositionKeepsWorkloadGraphClosed(t *testing.T) {
	fixture, config := newDisabledProcessConfigFixture(t, time.Second)
	if config.Admin.Desired.Mode != controller.AcquisitionDisabled ||
		config.Admin.Desired.MaxCapacity != 0 ||
		len(config.Admin.Desired.EligibleScaleSets) != 0 ||
		config.Admin.ExpectedFleet != fleetfence.FleetPortable ||
		config.Admin.ExpectedGeneration != 17 ||
		config.Admin.External == nil ||
		config.Admin.Broker == nil ||
		config.Admin.External.PollTargets() != nil {
		t.Fatalf("dark composition config = %#v", config.Admin)
	}
	process, err := newDisabledControllerProcess(config)
	if err != nil {
		t.Fatalf("newDisabledControllerProcess() error = %v", err)
	}
	if process.adminServer != nil || process.healthServer != nil ||
		process.service.external != config.Admin.External ||
		process.service.broker != config.Admin.Broker ||
		process.service.expectedFleet != config.Admin.ExpectedFleet ||
		process.service.expectedGeneration != config.Admin.ExpectedGeneration {
		t.Fatal("dark composition widened or lost exact fleet identity")
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- process.Run(runCtx) }()
	waitForLocalSocket(t, fixture.adminPath)
	waitForLocalSocket(t, fixture.healthPath)
	admin, err := newLocalAdminClient(
		fixture.adminPath,
		uint32(os.Geteuid()),
		time.Second,
	)
	if err != nil {
		cancelRun()
		t.Fatalf("newLocalAdminClient() error = %v", err)
	}
	waitForAdminReady(t, admin)
	status, err := admin.Probe(context.Background())
	if err != nil || status.Mode != controller.AcquisitionDisabled ||
		status.Capacity != 0 {
		cancelRun()
		t.Fatalf("Probe() = %#v, %v", status, err)
	}
	if err := validateZeroCapacitySummary(
		process.service.broker.CapacitySummary(),
		status.Epoch,
	); err != nil {
		cancelRun()
		t.Fatalf("zero capacity summary error = %v", err)
	}
	observation := fixture.authority.Observation()
	if err := observation.Validate(
		config.Admin.Now(),
		config.Admin.ObservationMaxAge,
	); err != nil || !observation.Zero() ||
		fixture.authority.ColdCalls() != 1 {
		cancelRun()
		t.Fatalf(
			"dark observation = %#v cold_calls=%d error=%v",
			observation,
			fixture.authority.ColdCalls(),
			err,
		)
	}
	if err := admin.Close(); err != nil {
		cancelRun()
		t.Fatalf("admin Close() error = %v", err)
	}
	cancelRun()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not stop")
	}
	if err := process.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestDarkObserverRejectsManifestFenceIdentityMismatchBeforeSockets(
	t *testing.T,
) {
	t.Parallel()

	for name, mutate := range map[string]func(*disabledControllerProcessConfig){
		"generation": func(config *disabledControllerProcessConfig) {
			config.Admin.ExpectedGeneration++
		},
		"fleet": func(config *disabledControllerProcessConfig) {
			config.Admin.ExpectedFleet = fleetfence.FleetLegacy
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture, config := newDisabledProcessConfigFixture(t, time.Second)
			mutate(&config)
			process, err := newDisabledControllerProcess(config)
			if err != nil {
				t.Fatalf("newDisabledControllerProcess() error = %v", err)
			}
			if err := process.Run(context.Background()); !errors.Is(
				err,
				controller.ErrRuntimeUnavailable,
			) {
				t.Fatalf("Run() error = %v", err)
			}
			for _, path := range []string{fixture.adminPath, fixture.healthPath} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("mismatched identity created socket %s: %v", path, err)
				}
			}
		})
	}
}

func TestControllerManifestBindingRejectsEveryMismatchedArtifact(t *testing.T) {
	t.Parallel()

	digest := func(character string) string {
		return "sha256:" + repeatedDigest(character)
	}
	manifest := hostruntime.RuntimeManifest{
		EgressMode:           "restricted-broker-v1",
		PolicyManifestDigest: repeatedDigest("a"),
		RunnerImageDigest:    digest("1"),
		AdapterImageDigest:   digest("2"),
		BrokerImageDigest:    digest("3"),
		HelperImageDigest:    digest("4"),
		VerifierImageDigest:  digest("5"),
	}
	overlay := hostruntime.PrivateOverlay{
		Docker: hostruntime.DockerOverlay{
			BrokerNetworkID: "restricted-broker-v1",
			RunnerImage:     "example.invalid/runner@" + manifest.RunnerImageDigest,
			AdapterImage:    "example.invalid/adapter@" + manifest.AdapterImageDigest,
			BrokerImage:     "example.invalid/broker@" + manifest.BrokerImageDigest,
			HelperImage:     "example.invalid/helper@" + manifest.HelperImageDigest,
			VerifierImage:   "example.invalid/verifier@" + manifest.VerifierImageDigest,
		},
		Policy: hostruntime.PolicyOverlay{
			ManifestDigest: manifest.PolicyManifestDigest,
		},
	}
	if !controllerManifestMatchesOverlay(manifest, overlay) {
		t.Fatal("exact manifest/overlay binding was rejected")
	}
	for name, mutate := range map[string]func(*hostruntime.PrivateOverlay){
		"egress": func(value *hostruntime.PrivateOverlay) {
			value.Docker.BrokerNetworkID = "wrong"
		},
		"policy": func(value *hostruntime.PrivateOverlay) {
			value.Policy.ManifestDigest = repeatedDigest("b")
		},
		"runner": func(value *hostruntime.PrivateOverlay) {
			value.Docker.RunnerImage = "example.invalid/runner@" + digest("9")
		},
		"adapter": func(value *hostruntime.PrivateOverlay) {
			value.Docker.AdapterImage = "example.invalid/adapter@" + digest("9")
		},
		"broker": func(value *hostruntime.PrivateOverlay) {
			value.Docker.BrokerImage = "example.invalid/broker@" + digest("9")
		},
		"helper": func(value *hostruntime.PrivateOverlay) {
			value.Docker.HelperImage = "example.invalid/helper@" + digest("9")
		},
		"verifier": func(value *hostruntime.PrivateOverlay) {
			value.Docker.VerifierImage = "example.invalid/verifier@" + digest("9")
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := overlay
			mutate(&value)
			if controllerManifestMatchesOverlay(manifest, value) {
				t.Fatal("mismatched manifest/overlay artifact was accepted")
			}
		})
	}
}
