package failoverclient

import (
	"strings"
	"testing"
	"time"
)

func TestInstallHeartbeatLeasePopulatesCache(t *testing.T) {
	cache := &LeaseCache{}
	body := []byte(`{"lease":{"archivedDisabledAliases":[],"canaryScaleSet":null,"durationMs":8000,"expiry":"2026-01-01T00:00:08.000Z","fleetId":"example-fleet","holder":"portable","leaseGeneration":3,"localPolicyEpoch":9,"maxCapacity":2,"mode":"enabled","policyDigest":"` + strings.Repeat("a", 64) + `","protocolVersion":1,"repositoryPolicyRevision":4,"serverEpoch":2,"sessionId":"` + strings.Repeat("b", 64) + `"},"sequence":4}`)
	send := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := InstallHeartbeatLease(cache, body, 7, send, time.Second); err != nil {
		t.Fatalf("InstallHeartbeatLease: %v", err)
	}
	entry, err := cache.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if entry.Lease.LocalPolicyEpoch != 9 || entry.Fence != 7 || entry.Sequence != 4 {
		t.Fatalf("entry = %+v", entry)
	}
}
