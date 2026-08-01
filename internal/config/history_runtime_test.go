package config

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func validControllerRuntimeDocument() map[string]any {
	return map[string]any{
		"egress_backend":                       "restricted-broker-v1",
		"ip_family":                            "public_ipv4_only",
		"secret":                               map[string]any{"source": "env", "ref": "PORTABLE_GHAR_TEST_SECRET"},
		"fleet_concurrency":                    uint64(6),
		"network_ledger_reserve_rows":          uint64(12),
		"network_ledger_reserve_logical_bytes": uint64(4096),
		"history": map[string]any{
			"min_retention":                    "24h",
			"max_history_rows":                 uint64(256),
			"max_history_logical_bytes":        uint64(1 << 20),
			"max_network_ledger_rows":          uint64(64),
			"max_network_ledger_logical_bytes": uint64(1 << 18),
			"inflight_reserve_rows":            uint64(8),
			"inflight_reserve_logical_bytes":   uint64(1 << 14),
			"gc_batch_rows":                    uint64(16),
			"network_gc_batch_rows":            uint64(8),
			"vacuum_batch_pages":               uint64(4),
			"maintenance_cadence":              "1m",
		},
		"controller": validControllerPrivateOverlay(),
	}
}

func marshalControllerRuntime(t *testing.T, document map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(encoded)
}

func loadControllerRuntimeDocument(t *testing.T, document map[string]any) (Runtime, error) {
	t.Helper()
	return LoadControllerRuntime(strings.NewReader(marshalControllerRuntime(t, document)))
}

func TestHistoryConfigRequiresEveryExplicitField(t *testing.T) {
	topLevel := []string{
		"fleet_concurrency",
		"network_ledger_reserve_rows",
		"network_ledger_reserve_logical_bytes",
		"history",
	}
	for _, field := range topLevel {
		t.Run("missing "+field, func(t *testing.T) {
			document := validControllerRuntimeDocument()
			delete(document, field)
			if _, err := loadControllerRuntimeDocument(t, document); err == nil {
				t.Fatalf("LoadControllerRuntime accepted missing %q", field)
			}
		})
	}

	historyFields := []string{
		"min_retention",
		"max_history_rows",
		"max_history_logical_bytes",
		"max_network_ledger_rows",
		"max_network_ledger_logical_bytes",
		"inflight_reserve_rows",
		"inflight_reserve_logical_bytes",
		"gc_batch_rows",
		"network_gc_batch_rows",
		"vacuum_batch_pages",
		"maintenance_cadence",
	}
	for _, field := range historyFields {
		t.Run("missing history."+field, func(t *testing.T) {
			document := validControllerRuntimeDocument()
			history := document["history"].(map[string]any)
			delete(history, field)
			if _, err := loadControllerRuntimeDocument(t, document); err == nil {
				t.Fatalf("LoadControllerRuntime accepted missing history.%s", field)
			}
		})
	}
}

func TestHistoryConfigRejectsZeroNegativeOverflowAndInconsistentReserves(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "zero concurrency",
			mutate: func(document map[string]any) {
				document["fleet_concurrency"] = uint64(0)
			},
		},
		{
			name: "zero history scalar",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["gc_batch_rows"] = uint64(0)
			},
		},
		{
			name: "negative history scalar",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["max_history_rows"] = int64(-1)
			},
		},
		{
			name: "overflow history scalar",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["max_history_rows"] =
					json.Number("18446744073709551616")
			},
		},
		{
			name: "zero retention",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["min_retention"] = "0s"
			},
		},
		{
			name: "negative cadence",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["maintenance_cadence"] = "-1s"
			},
		},
		{
			name: "invalid duration",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["min_retention"] = "forever"
			},
		},
		{
			name: "history row reserve exceeds cap",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["max_history_rows"] = uint64(47)
			},
		},
		{
			name: "history byte reserve exceeds cap",
			mutate: func(document map[string]any) {
				document["history"].(map[string]any)["max_history_logical_bytes"] =
					uint64(6*(1<<14) - 1)
			},
		},
		{
			name: "network row reserve smaller than concurrency",
			mutate: func(document map[string]any) {
				document["network_ledger_reserve_rows"] = uint64(5)
			},
		},
		{
			name: "network row reserve exceeds cap",
			mutate: func(document map[string]any) {
				document["network_ledger_reserve_rows"] = uint64(65)
			},
		},
		{
			name: "network byte reserve exceeds cap",
			mutate: func(document map[string]any) {
				document["network_ledger_reserve_logical_bytes"] = uint64(1<<18 + 1)
			},
		},
		{
			name: "concurrency multiplication overflow",
			mutate: func(document map[string]any) {
				document["fleet_concurrency"] = uint64(math.MaxUint64)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			document := validControllerRuntimeDocument()
			tc.mutate(document)
			if _, err := loadControllerRuntimeDocument(t, document); err == nil {
				t.Fatal("LoadControllerRuntime accepted invalid history sizing")
			}
		})
	}
}

func TestHistoryConfigAcceptsExplicitConsistentEnvelope(t *testing.T) {
	rt, err := loadControllerRuntimeDocument(t, validControllerRuntimeDocument())
	if err != nil {
		t.Fatalf("LoadControllerRuntime: %v", err)
	}
	limits := rt.HistoryLimits()
	if rt.FleetConcurrency != 6 ||
		limits.MinRetention != 24*time.Hour ||
		limits.MaintenanceCadence != time.Minute ||
		limits.MaxHistoryRows != 256 ||
		limits.MaxNetworkLedgerRows != 64 {
		t.Fatalf("decoded runtime = %+v limits=%+v", rt, limits)
	}
}

func TestHistoryConfigRejectsTrailingJSONDocument(t *testing.T) {
	document := marshalControllerRuntime(t, validControllerRuntimeDocument()) + "\n{}"
	if _, err := LoadControllerRuntime(strings.NewReader(document)); err == nil {
		t.Fatal("LoadControllerRuntime accepted a trailing JSON document")
	}
}
