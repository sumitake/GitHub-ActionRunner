// Command portable-ghar-controller exposes the controller's aggregate,
// read-only history status entrypoint. Production orchestration wiring lands
// in a later task; this command deliberately accepts no implicit sizing and
// never runs maintenance or migration.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/sumitake/portable-ghar/internal/config"
	"github.com/sumitake/portable-ghar/internal/state"
)

type historyState string

const (
	historyStateNormal  historyState = "normal"
	historyStateWarning historyState = "warning"
	historyStateStop    historyState = "stop"
)

type historyMaintenanceStatus struct {
	ObservedAt              time.Time `json:"observed_at"`
	CompactedTerminalGraphs uint64    `json:"compacted_terminal_graphs"`
	DeletedMessageReceipts  uint64    `json:"deleted_message_receipts"`
	DeletedTombstones       uint64    `json:"deleted_tombstones"`
	DeletedNetworkLedgers   uint64    `json:"deleted_network_ledgers"`
	CheckpointBusy          bool      `json:"checkpoint_busy"`
	CheckpointLogPages      uint64    `json:"checkpoint_log_pages"`
	CheckpointedPages       uint64    `json:"checkpointed_pages"`
	VacuumedPages           uint64    `json:"vacuumed_pages"`
}

type historyStatus struct {
	State                     historyState             `json:"state"`
	HistoryRows               uint64                   `json:"history_rows"`
	HistoryLogicalBytes       uint64                   `json:"history_logical_bytes"`
	NetworkLedgerRows         uint64                   `json:"network_ledger_rows"`
	NetworkLedgerLogicalBytes uint64                   `json:"network_ledger_logical_bytes"`
	ActivePageBytes           uint64                   `json:"active_page_bytes"`
	FreelistBytes             uint64                   `json:"freelist_bytes"`
	WALBytes                  uint64                   `json:"wal_bytes"`
	OldestRetainedAgeSeconds  uint64                   `json:"oldest_retained_age_seconds"`
	LastMaintenance           historyMaintenanceStatus `json:"last_maintenance"`
}

func addStatusTotals(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return math.MaxUint64, false
		}
		total += value
	}
	return total, true
}

func reserveFits(used uint64, reserve uint64, cap uint64) bool {
	total, ok := addStatusTotals(used, reserve)
	return ok && total <= cap
}

func multiplyStatusTotal(left uint64, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func buildHistoryStatus(
	now time.Time,
	usage state.HistoryUsage,
	limits state.HistoryLimits,
	fleetConcurrency uint64,
	networkReserveRows uint64,
	networkReserveBytes uint64,
) (historyStatus, error) {
	if now.IsZero() || state.ValidateHistoryLimits(limits) != nil ||
		fleetConcurrency == 0 ||
		networkReserveRows == 0 || networkReserveBytes == 0 {
		return historyStatus{}, errors.New("history status inputs are invalid")
	}
	historyReserveRows, rowsReserveOK := multiplyStatusTotal(
		fleetConcurrency,
		limits.InflightReserveRows,
	)
	historyReserveBytes, bytesReserveOK := multiplyStatusTotal(
		fleetConcurrency,
		limits.InflightReserveLogicalBytes,
	)
	if !rowsReserveOK || !bytesReserveOK {
		return historyStatus{}, errors.New("history status reserve is invalid")
	}
	historyRows, rowsOK := addStatusTotals(
		usage.LiveRows,
		usage.ProtectedTerminalRows,
		usage.MessageReceiptRows,
		usage.TombstoneRows,
		usage.ReservedRows,
	)
	historyBytes, bytesOK := addStatusTotals(
		usage.LiveLogicalBytes,
		usage.ProtectedTerminalBytes,
		usage.MessageReceiptBytes,
		usage.TombstoneLogicalBytes,
		usage.ReservedLogicalBytes,
	)
	level := historyStateNormal
	if !rowsOK || !bytesOK ||
		historyRows >= limits.MaxHistoryRows ||
		historyBytes >= limits.MaxHistoryLogicalBytes ||
		usage.NetworkLedgerRows >= limits.MaxNetworkLedgerRows ||
		usage.NetworkLedgerLogicalBytes >= limits.MaxNetworkLedgerLogicalBytes {
		level = historyStateStop
		// Warning preserves the same complete fleet-wide future headroom proven at
		// configuration load. Current in-flight reservations remain part of usage;
		// this intentionally warns before a fully occupied fleet plus its retained
		// evidence could consume the configured cap.
	} else if !reserveFits(
		historyRows,
		historyReserveRows,
		limits.MaxHistoryRows,
	) || !reserveFits(
		historyBytes,
		historyReserveBytes,
		limits.MaxHistoryLogicalBytes,
	) || !reserveFits(
		usage.NetworkLedgerRows,
		networkReserveRows,
		limits.MaxNetworkLedgerRows,
	) || !reserveFits(
		usage.NetworkLedgerLogicalBytes,
		networkReserveBytes,
		limits.MaxNetworkLedgerLogicalBytes,
	) {
		level = historyStateWarning
	}
	var oldestAge time.Duration
	if !usage.OldestRetainedAt.IsZero() {
		if usage.OldestRetainedAt.After(now) {
			return historyStatus{}, errors.New("history status timestamp is in the future")
		}
		oldestAge = now.Sub(usage.OldestRetainedAt)
	}
	if oldestAge < 0 {
		return historyStatus{}, errors.New("history status age is invalid")
	}
	maintenance := usage.Maintenance
	return historyStatus{
		State:                     level,
		HistoryRows:               historyRows,
		HistoryLogicalBytes:       historyBytes,
		NetworkLedgerRows:         usage.NetworkLedgerRows,
		NetworkLedgerLogicalBytes: usage.NetworkLedgerLogicalBytes,
		ActivePageBytes:           usage.ActivePageBytes,
		FreelistBytes:             usage.FreelistBytes,
		WALBytes:                  usage.WALBytes,
		OldestRetainedAgeSeconds:  uint64(oldestAge / time.Second),
		LastMaintenance: historyMaintenanceStatus{
			ObservedAt:              maintenance.ObservedAt,
			CompactedTerminalGraphs: maintenance.CompactedTerminalGraphs,
			DeletedMessageReceipts:  maintenance.DeletedMessageReceipts,
			DeletedTombstones:       maintenance.DeletedTombstones,
			DeletedNetworkLedgers:   maintenance.DeletedNetworkLedgers,
			CheckpointBusy:          maintenance.CheckpointBusy,
			CheckpointLogPages:      maintenance.CheckpointLogPages,
			CheckpointedPages:       maintenance.CheckpointedPages,
			VacuumedPages:           maintenance.VacuumedPages,
		},
	}, nil
}

func run(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	clock func() time.Time,
) int {
	if len(args) == 0 || args[0] != "status" || clock == nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 2
	}
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit aggregate JSON")
	configPath := flags.String("config", "", "runtime configuration")
	databasePath := flags.String("database", "", "controller database")
	if err := flags.Parse(args[1:]); err != nil ||
		!*jsonOutput ||
		*configPath == "" ||
		*databasePath == "" ||
		flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 2
	}
	configFile, err := os.Open(*configPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 1
	}
	runtime, loadErr := config.LoadControllerRuntime(configFile)
	closeErr := configFile.Close()
	if loadErr != nil || closeErr != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 1
	}
	store, err := state.OpenReadOnlyWithHistoryLimits(
		*databasePath,
		runtime.HistoryLimits(),
	)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 1
	}
	now := clock().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	usage, err := store.HistoryUsage(ctx, runtime.HistoryLimits())
	if err != nil {
		_ = store.Close()
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 1
	}
	if err := store.Close(); err != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 1
	}
	document, err := buildHistoryStatus(
		now,
		usage,
		runtime.HistoryLimits(),
		runtime.FleetConcurrency,
		runtime.NetworkLedgerReserveRows,
		runtime.NetworkLedgerReserveLogicalBytes,
	)
	if err != nil || json.NewEncoder(stdout).Encode(document) != nil {
		_, _ = fmt.Fprintln(stderr, "portable-ghar-controller: status unavailable")
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}
