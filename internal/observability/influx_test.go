package observability

import (
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/health"
)

func TestEncodeHealthLineIsOneWayAndSecretFree(t *testing.T) {
	export := health.Export{
		SchemaVersion: health.SnapshotSchemaVersion,
		Snapshot: health.Snapshot{
			ObservedAt:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			FleetAlias:               "example-fleet",
			AcquisitionMode:          health.AcquisitionEnabled,
			PolicyEpoch:              3,
			PolicyDigest:             strings.Repeat("a", 64),
			RepositoryPolicyRevision: 1,
			Capacity: health.CapacitySummary{
				Configured: 2,
				Effective:  2,
				Occupied:   0,
				Available:  2,
				Queued:     0,
			},
			HostProfileID: "strict-linux-v1",
			BuildID:       strings.Repeat("b", 64),
		},
	}
	line, err := EncodeHealthLine(export)
	if err != nil {
		t.Fatalf("EncodeHealthLine: %v", err)
	}
	if !strings.HasPrefix(line, "portable_ghar_health,") {
		t.Fatalf("line = %s", line)
	}
	for _, forbidden := range []string{"token", "secret", "path", "hmac", "key"} {
		if strings.Contains(strings.ToLower(line), forbidden) {
			t.Fatalf("line leaked %q: %s", forbidden, line)
		}
	}
}
