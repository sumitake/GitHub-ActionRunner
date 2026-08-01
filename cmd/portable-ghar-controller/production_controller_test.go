package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

type healthBoundTestAdmin struct {
	status controller.PolicyStatus
	err    error
	order  *[]string
}

func (admin *healthBoundTestAdmin) Probe(
	context.Context,
) (controller.PolicyStatus, error) {
	*admin.order = append(*admin.order, "admin-probe")
	return admin.status, admin.err
}

func (*healthBoundTestAdmin) ReconcileOnce(
	context.Context,
) (controller.CycleReceipt, error) {
	return controller.CycleReceipt{}, nil
}

func (*healthBoundTestAdmin) Drain(
	context.Context,
	controller.DrainPolicy,
) error {
	return nil
}

func (*healthBoundTestAdmin) SetAcquisition(
	context.Context,
	controller.AcquisitionChange,
) (controller.PolicyStatus, error) {
	return controller.PolicyStatus{}, nil
}

func (admin *healthBoundTestAdmin) Close() error {
	*admin.order = append(*admin.order, "admin-close")
	return nil
}

type healthBoundTestClient struct {
	err   error
	order *[]string
}

func (client *healthBoundTestClient) Health(context.Context) error {
	*client.order = append(*client.order, "health-probe")
	return client.err
}

func (client *healthBoundTestClient) Close() error {
	*client.order = append(*client.order, "health-close")
	return nil
}

func TestHealthBoundAdminRequiresAdminThenHealthAndClosesInReverse(
	t *testing.T,
) {
	t.Parallel()

	wantStatus := controller.PolicyStatus{
		Mode:     controller.AcquisitionDisabled,
		Epoch:    9,
		Digest:   strings.Repeat("a", 64),
		Capacity: 0,
	}
	for _, test := range []struct {
		name      string
		adminErr  error
		healthErr error
		wantError bool
		wantOrder []string
	}{
		{
			name:      "both positive",
			wantOrder: []string{"admin-probe", "health-probe"},
		},
		{
			name:      "admin failure stops before health",
			adminErr:  errors.New("admin unavailable"),
			wantError: true,
			wantOrder: []string{"admin-probe"},
		},
		{
			name:      "health failure rejects admin success",
			healthErr: errors.New("health unavailable"),
			wantError: true,
			wantOrder: []string{"admin-probe", "health-probe"},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var order []string
			admin := &healthBoundTestAdmin{
				status: wantStatus,
				err:    test.adminErr,
				order:  &order,
			}
			health := &healthBoundTestClient{
				err:   test.healthErr,
				order: &order,
			}
			combined, err := newHealthBoundAdmin(admin, health)
			if err != nil {
				t.Fatalf("newHealthBoundAdmin() error = %v", err)
			}
			status, err := combined.Probe(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("Probe() error = %v", err)
			}
			if err == nil && status != wantStatus {
				t.Fatalf("Probe() = %#v, want %#v", status, wantStatus)
			}
			if !slices.Equal(order, test.wantOrder) {
				t.Fatalf("Probe() order = %v, want %v", order, test.wantOrder)
			}
			if err := combined.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			wantClose := append(
				append([]string(nil), test.wantOrder...),
				"health-close",
				"admin-close",
			)
			if !slices.Equal(order, wantClose) {
				t.Fatalf("Close() order = %v, want %v", order, wantClose)
			}
		})
	}
	var _ controller.LiveAdmin = (*healthBoundAdmin)(nil)
	var _ io.Closer = (*healthBoundAdmin)(nil)
}

func TestProductionHistoryLimitsComeFromPrivateOverlay(t *testing.T) {
	t.Parallel()

	overlay := hostruntime.PrivateOverlay{
		Resources: hostruntime.ResourceOverlay{
			FleetConcurrency:          2,
			NetworkLedgerReserveRows:  3,
			NetworkLedgerReserveBytes: 4,
			History: hostruntime.HistoryOverlay{
				MinRetention:                 "1h",
				MaxHistoryRows:               100,
				MaxHistoryLogicalBytes:       200,
				MaxNetworkLedgerRows:         10,
				MaxNetworkLedgerLogicalBytes: 20,
				InflightReserveRows:          2,
				InflightReserveLogicalBytes:  3,
				GCBatchRows:                  4,
				NetworkGCBatchRows:           5,
				VacuumBatchPages:             6,
				MaintenanceCadence:           "1m",
			},
		},
	}
	limits, err := productionHistoryLimits(overlay)
	if err != nil {
		t.Fatalf("productionHistoryLimits: %v", err)
	}
	if limits.MinRetention != time.Hour ||
		limits.MaxHistoryRows != 100 ||
		limits.MaxHistoryLogicalBytes != 200 ||
		limits.MaxNetworkLedgerRows != 10 ||
		limits.MaxNetworkLedgerLogicalBytes != 20 ||
		limits.InflightReserveRows != 2 ||
		limits.InflightReserveLogicalBytes != 3 ||
		limits.GCBatchRows != 4 ||
		limits.NetworkGCBatchRows != 5 ||
		limits.VacuumBatchPages != 6 ||
		limits.MaintenanceCadence != time.Minute {
		t.Fatalf("productionHistoryLimits() = %#v", limits)
	}

	invalid := overlay
	invalid.Resources.NetworkLedgerReserveRows = 1
	if _, err := productionHistoryLimits(invalid); err == nil {
		t.Fatal("productionHistoryLimits accepted undersized ledger reserve")
	}
	invalid = overlay
	invalid.Resources.History.MaxHistoryRows = 1
	if _, err := productionHistoryLimits(invalid); err == nil {
		t.Fatal("productionHistoryLimits accepted undersized inflight reserve")
	}
}

func TestParseProductionControllerTimingsUsesOnlyExplicitOverlayValues(
	t *testing.T,
) {
	t.Parallel()

	overlay := hostruntime.PrivateOverlay{
		Controller: hostruntime.ControllerTimingOverlay{
			OperationTimeout:      "2s",
			ReconciliationTimeout: "3s",
			ReconciliationCadence: "4s",
			ShutdownTimeout:       "5s",
		},
		Health: hostruntime.HealthOverlay{
			ObservationMaxAge: "6s",
		},
		Fence: hostruntime.FenceTimingOverlay{
			LockPollInterval: "7ms",
			RenewalInterval:  "8s",
			RenewalTimeout:   "9s",
		},
	}
	got, err := parseProductionControllerTimings(overlay)
	if err != nil {
		t.Fatalf("parseProductionControllerTimings: %v", err)
	}
	want := productionControllerTimings{
		operation:             2 * time.Second,
		reconciliation:        3 * time.Second,
		reconciliationCadence: 4 * time.Second,
		shutdown:              5 * time.Second,
		observationMaxAge:     6 * time.Second,
		fenceLock:             7 * time.Millisecond,
		fenceRenewal:          8 * time.Second,
		fenceTimeout:          9 * time.Second,
	}
	if got != want {
		t.Fatalf("timings = %+v, want %+v", got, want)
	}
	overlay.Controller.OperationTimeout = ""
	if _, err := parseProductionControllerTimings(overlay); err == nil {
		t.Fatal("missing explicit timing accepted")
	}
}

func TestProductionDisabledPolicyUsesRepositoryProjectionAndZeroCapacity(
	t *testing.T,
) {
	t.Parallel()

	overlay := hostruntime.PrivateOverlay{
		Resources: hostruntime.ResourceOverlay{PolicyRevision: 11},
		Repositories: []hostruntime.RepositoryOverlay{
			{
				Alias:          "repo-b",
				MaxConcurrency: 2,
				Eligibility:    "pending-reactivation",
			},
			{
				Alias:          "repo-a",
				MaxConcurrency: 1,
				Eligibility:    "active",
			},
		},
	}
	policy, err := productionDisabledPolicy(overlay)
	if err != nil {
		t.Fatalf("productionDisabledPolicy: %v", err)
	}
	if policy.Mode != controller.AcquisitionDisabled ||
		policy.MaxCapacity != 0 ||
		len(policy.EligibleScaleSets) != 0 ||
		policy.RepositoryPolicyRevision != 11 ||
		policy.Epoch != 0 ||
		len(policy.RepositoryPolicies) != 2 ||
		policy.RepositoryPolicies[0].Alias != "repo-a" ||
		policy.RepositoryPolicies[1].Alias != "repo-b" {
		t.Fatalf("policy = %+v", policy)
	}
}

func TestValidateProductionControllerPathsPinsPrivateRootsAndDatabase(
	t *testing.T,
) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	paths := hostruntime.PathOverlay{}
	for name, target := range map[string]*string{
		"state":   &paths.StateRoot,
		"fence":   &paths.FenceRoot,
		"broker":  &paths.BrokerRoot,
		"seccomp": &paths.SeccompRoot,
	} {
		path := filepath.Join(base, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%s): %v", name, err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatalf("Chmod(%s): %v", name, err)
		}
		*target = path
	}
	paths.DatabasePath = filepath.Join(paths.StateRoot, "controller.db")
	paths.AdminSocketPath = filepath.Join(paths.StateRoot, "admin.sock")
	paths.HealthSocketPath = filepath.Join(paths.StateRoot, "health.sock")
	overlay := hostruntime.PrivateOverlay{Paths: paths}
	if err := validateProductionControllerPaths(
		overlay,
		uint32(os.Geteuid()),
	); err != nil {
		t.Fatalf("validate absent database: %v", err)
	}
	if err := os.WriteFile(paths.DatabasePath, []byte("db"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := validateProductionControllerPaths(
		overlay,
		uint32(os.Geteuid()),
	); err != nil {
		t.Fatalf("validate exact database: %v", err)
	}
	if err := os.Chmod(paths.DatabasePath, 0o644); err != nil {
		t.Fatalf("Chmod database: %v", err)
	}
	if err := validateProductionControllerPaths(
		overlay,
		uint32(os.Geteuid()),
	); err == nil {
		t.Fatal("permissive database accepted")
	}
}

type orderedCloser struct {
	name  string
	order *[]string
	err   error
}

func (closer orderedCloser) Close() error {
	*closer.order = append(*closer.order, closer.name)
	return closer.err
}

func TestProductionControllerResourcesCloseReverseOrderAndJoinFailures(
	t *testing.T,
) {
	t.Parallel()

	var order []string
	resources := &productionControllerResources{}
	resources.Add(orderedCloser{name: "database", order: &order})
	resources.Add(orderedCloser{
		name:  "fence",
		order: &order,
		err:   errors.New("fence close"),
	})
	resources.Add(orderedCloser{name: "guard", order: &order})
	err := resources.Close()
	if !slices.Equal(order, []string{"guard", "fence", "database"}) {
		t.Fatalf("close order = %v", order)
	}
	if err == nil || !strings.Contains(err.Error(), "fence close") {
		t.Fatalf("close error = %v, want joined failure", err)
	}
	if err := resources.Close(); err != nil {
		t.Fatalf("second close = %v, want idempotent nil", err)
	}
}
