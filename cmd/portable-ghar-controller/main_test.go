package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/state"
)

func statusTestLimits() state.HistoryLimits {
	return state.HistoryLimits{
		MinRetention:                 time.Hour,
		MaxHistoryRows:               100,
		MaxHistoryLogicalBytes:       100_000,
		MaxNetworkLedgerRows:         20,
		MaxNetworkLedgerLogicalBytes: 20_000,
		InflightReserveRows:          8,
		InflightReserveLogicalBytes:  8_000,
		GCBatchRows:                  8,
		NetworkGCBatchRows:           4,
		VacuumBatchPages:             2,
		MaintenanceCadence:           time.Minute,
	}
}

func TestHistoryStatusClassifiesNormalWarningAndStopWithoutImplicitHeadroom(t *testing.T) {
	now := time.Date(2026, 7, 28, 17, 0, 0, 0, time.UTC)
	limits := statusTestLimits()
	base := state.HistoryUsage{
		LiveRows:         10,
		LiveLogicalBytes: 10_000,
		OldestRetainedAt: now.Add(-time.Hour),
		ActivePageBytes:  32_768,
		FreelistBytes:    4_096,
		WALBytes:         8_192,
		Maintenance: state.HistoryMaintenanceResult{
			ObservedAt:              now,
			CompactedTerminalGraphs: 1,
			DeletedTombstones:       2,
			CheckpointLogPages:      3,
			CheckpointedPages:       3,
			VacuumedPages:           1,
		},
	}

	normal, err := buildHistoryStatus(now, base, limits, 2, 4, 4_000)
	if err != nil {
		t.Fatalf("buildHistoryStatus(normal): %v", err)
	}
	if normal.State != historyStateNormal {
		t.Fatalf("normal state = %q, want %q", normal.State, historyStateNormal)
	}

	warningUsage := base
	warningUsage.TombstoneRows = limits.MaxHistoryRows -
		limits.InflightReserveRows -
		warningUsage.LiveRows +
		1
	warning, err := buildHistoryStatus(now, warningUsage, limits, 2, 4, 4_000)
	if err != nil {
		t.Fatalf("buildHistoryStatus(warning): %v", err)
	}
	if warning.State != historyStateWarning {
		t.Fatalf("warning state = %q, want %q", warning.State, historyStateWarning)
	}

	stopUsage := base
	stopUsage.NetworkLedgerLogicalBytes = limits.MaxNetworkLedgerLogicalBytes
	stop, err := buildHistoryStatus(now, stopUsage, limits, 2, 4, 4_000)
	if err != nil {
		t.Fatalf("buildHistoryStatus(stop): %v", err)
	}
	if stop.State != historyStateStop {
		t.Fatalf("stop state = %q, want %q", stop.State, historyStateStop)
	}
}

func TestHistoryStatusWarningUsesFleetWideInflightReserve(t *testing.T) {
	now := time.Date(2026, 7, 28, 17, 30, 0, 0, time.UTC)
	limits := statusTestLimits()
	usage := state.HistoryUsage{
		LiveRows:         70,
		LiveLogicalBytes: 70_000,
	}

	status, err := buildHistoryStatus(now, usage, limits, 4, 4, 4_000)
	if err != nil {
		t.Fatalf("buildHistoryStatus: %v", err)
	}
	if status.State != historyStateWarning {
		t.Fatalf("status state = %q, want %q", status.State, historyStateWarning)
	}
}

func TestHistoryStatusRejectsFleetReserveOverflow(t *testing.T) {
	limits := statusTestLimits()
	if _, err := buildHistoryStatus(
		time.Date(2026, 7, 28, 17, 45, 0, 0, time.UTC),
		state.HistoryUsage{},
		limits,
		^uint64(0),
		4,
		4_000,
	); err == nil {
		t.Fatal("buildHistoryStatus accepted overflowing fleet reserve")
	}
}

func TestHistoryStatusJSONContainsOnlyApprovedAggregateKeys(t *testing.T) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	status, err := buildHistoryStatus(
		now,
		state.HistoryUsage{
			LiveRows:                  1,
			LiveLogicalBytes:          100,
			ProtectedTerminalRows:     2,
			ProtectedTerminalBytes:    200,
			MessageReceiptRows:        3,
			MessageReceiptBytes:       300,
			TombstoneRows:             4,
			TombstoneLogicalBytes:     400,
			NetworkLedgerRows:         5,
			NetworkLedgerLogicalBytes: 500,
			ReservedRows:              6,
			ReservedLogicalBytes:      600,
			OldestRetainedAt:          now.Add(-2 * time.Hour),
			ActivePageBytes:           4_096,
			FreelistBytes:             8_192,
			WALBytes:                  12_288,
			Maintenance: state.HistoryMaintenanceResult{
				ObservedAt:              now,
				CompactedTerminalGraphs: 1,
				DeletedMessageReceipts:  2,
				DeletedTombstones:       3,
				DeletedNetworkLedgers:   4,
				CheckpointBusy:          true,
				CheckpointLogPages:      5,
				CheckpointedPages:       4,
				VacuumedPages:           2,
			},
		},
		statusTestLimits(),
		2,
		4,
		4_000,
	)
	if err != nil {
		t.Fatalf("buildHistoryStatus: %v", err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, forbidden := range []string{
		"repository", "assignment", "runner", "message_id", "ledger_key",
		"database", "path", "secret", "token",
	} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("status JSON contains forbidden identity key %q: %s", forbidden, encoded)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	gotKeys := make([]string, 0, len(decoded))
	for key := range decoded {
		gotKeys = append(gotKeys, key)
	}
	wantKeys := []string{
		"active_page_bytes",
		"freelist_bytes",
		"history_logical_bytes",
		"history_rows",
		"last_maintenance",
		"network_ledger_logical_bytes",
		"network_ledger_rows",
		"oldest_retained_age_seconds",
		"state",
		"wal_bytes",
	}
	sortStrings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("status keys = %v, want %v", gotKeys, wantKeys)
	}
}

func TestStatusCommandReadsPersistedMaintenanceWithoutMutatingDatabase(t *testing.T) {
	temp := t.TempDir()
	configPath := filepath.Join(temp, "runtime.json")
	databasePath := filepath.Join(temp, "controller.db")
	configDocument := `{
		"egress_backend": "restricted-broker-v1",
		"ip_family": "public_ipv4_only",
		"secret": {"source": "env", "ref": "PORTABLE_GHAR_TEST_SECRET"},
		"fleet_concurrency": 2,
		"network_ledger_reserve_rows": 4,
		"network_ledger_reserve_logical_bytes": 4096,
		"history": {
			"min_retention": "1h",
			"max_history_rows": 100,
			"max_history_logical_bytes": 100000,
			"max_network_ledger_rows": 20,
			"max_network_ledger_logical_bytes": 20000,
			"inflight_reserve_rows": 8,
			"inflight_reserve_logical_bytes": 8000,
			"gc_batch_rows": 8,
			"network_gc_batch_rows": 4,
			"vacuum_batch_pages": 2,
			"maintenance_cadence": "1m"
		}
	}`
	if err := os.WriteFile(configPath, []byte(configDocument), 0o600); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}
	store, err := state.OpenWithHistoryLimits(databasePath, statusTestLimits())
	if err != nil {
		t.Fatalf("OpenWithHistoryLimits: %v", err)
	}
	maintainedAt := time.Date(2026, 7, 28, 18, 30, 0, 0, time.UTC)
	if _, err := store.CollectHistory(
		context.Background(),
		statusTestLimits(),
		maintainedAt,
	); err != nil {
		_ = store.Close()
		t.Fatalf("CollectHistory: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close initialized store: %v", err)
	}
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read database before status: %v", err)
	}

	var stdout, stderr bytes.Buffer
	now := time.Date(2026, 7, 28, 19, 0, 0, 0, time.UTC)
	exitCode := run(
		[]string{"status", "--json", "--config", configPath, "--database", databasePath},
		&stdout,
		&stderr,
		func() time.Time { return now },
	)
	if exitCode != 0 {
		t.Fatalf("run(status) exit = %d stderr=%q", exitCode, stderr.String())
	}
	var status historyStatus
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("status output is not JSON: %v output=%q", err, stdout.String())
	}
	if status.State != historyStateNormal ||
		status.ActivePageBytes == 0 ||
		!status.LastMaintenance.ObservedAt.Equal(maintainedAt) {
		t.Fatalf("status = %+v", status)
	}
	if stderr.Len() != 0 {
		t.Fatalf("status stderr = %q, want empty", stderr.String())
	}
	after, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read database after status: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("status command changed the database")
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
