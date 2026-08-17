package health

import (
	"strings"
	"testing"
	"time"
)

func TestEncodeExportRejectsOpenSnapshots(t *testing.T) {
	snapshot := Snapshot{
		ObservedAt:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		FleetAlias:               "example-fleet",
		AcquisitionMode:          AcquisitionDisabled,
		PolicyEpoch:              1,
		PolicyDigest:             strings.Repeat("a", 64),
		RepositoryPolicyRevision: 1,
		Capacity:                 CapacitySummary{},
		HostProfileID:            "strict-linux-v1",
		BuildID:                  strings.Repeat("b", 64),
	}
	raw, err := EncodeExport(snapshot)
	if err != nil {
		t.Fatalf("EncodeExport: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version":1`) {
		t.Fatalf("export = %s", raw)
	}
	snapshot.PolicyEpoch = 0
	if _, err := EncodeExport(snapshot); err == nil {
		t.Fatal("invalid snapshot exported")
	}
}
