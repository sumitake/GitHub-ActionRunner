package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/failoverclient"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type unusedFleetGuards struct{}

func (unusedFleetGuards) AcquirePortable(context.Context) (controller.AcquisitionGuard, error) {
	return nil, errors.New("unused")
}

func testWorkerConfig() productionWorkerConfig {
	return productionWorkerConfig{
		Overlay: hostruntime.PrivateOverlay{
			Worker: &hostruntime.WorkerOverlay{
				BaseURL:            "https://failover.example.invalid",
				HMACCredentialName: "worker-hmac",
				FleetID:            "example-fleet",
				TimestampWindow:    "5m0s",
				LeaseDuration:      "2m0s",
				HeartbeatDeadline:  "10s",
				ShorteningMargin:   "5s",
				LostRenewals:       2,
				TerminationTail:    "30s",
			},
			GitHub: &hostruntime.GitHubOverlay{
				MaxResponseBytes:      1 << 20,
				OperationTimeout:      "30s",
				ResponseHeaderTimeout: "15s",
			},
		},
		HMACKeyHex:      strings.Repeat("0b", 32),
		FleetGuards:     unusedFleetGuards{},
		BuildID:         strings.Repeat("a", 64),
		Fence:           7,
		AttemptInterval: 20 * time.Second,
		Clock:           failoverclient.NewFakeAuthorityClock(time.Unix(1_800_000_000, 0)),
	}
}

func TestProductionWorkerClientsComposeFromTheOverlay(t *testing.T) {
	clients, err := newProductionWorkerClients(testWorkerConfig())
	if err != nil {
		t.Fatalf("newProductionWorkerClients: %v", err)
	}
	if clients.Health == nil || clients.session == nil ||
		clients.Permits.Fence != 7 ||
		clients.Permits.Holder != failoverclient.HolderPortable ||
		clients.Permits.CallDuration != 30*time.Second ||
		clients.Permits.TerminationTail != 30*time.Second {
		t.Fatalf("clients = %+v", clients)
	}
	if err := clients.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestProductionWorkerClientsRejectAnUnsafeConfiguration(t *testing.T) {
	tests := map[string]func(*productionWorkerConfig){
		"no worker section": func(config *productionWorkerConfig) { config.Overlay.Worker = nil },
		"no github section": func(config *productionWorkerConfig) { config.Overlay.GitHub = nil },
		// (2 lost renewals + 1) x 40s + 10s + 5s exceeds the 2m lease.
		"lease shorter than the heartbeat budget": func(config *productionWorkerConfig) {
			config.AttemptInterval = 40 * time.Second
		},
		"no attempt interval": func(config *productionWorkerConfig) { config.AttemptInterval = 0 },
		"uppercase key":       func(config *productionWorkerConfig) { config.HMACKeyHex = strings.Repeat("0B", 32) },
		"short key":           func(config *productionWorkerConfig) { config.HMACKeyHex = strings.Repeat("0b", 31) },
		"non-hex key":         func(config *productionWorkerConfig) { config.HMACKeyHex = strings.Repeat("zz", 32) },
		"no fence":            func(config *productionWorkerConfig) { config.Fence = 0 },
		"short build ID":      func(config *productionWorkerConfig) { config.BuildID = "abc" },
		"incapable clock": func(config *productionWorkerConfig) {
			clock := failoverclient.NewFakeAuthorityClock(time.Unix(1_800_000_000, 0))
			clock.Disable()
			config.Clock = clock
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := testWorkerConfig()
			mutate(&config)
			if clients, err := newProductionWorkerClients(config); err == nil {
				_ = clients.Close()
				t.Fatal("newProductionWorkerClients accepted an unsafe configuration")
			}
		})
	}
}
