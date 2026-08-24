package failoverclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readProtocolFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureRoot(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return bytesTrimNL(raw)
}

func mutateProtocolFixture(
	t *testing.T,
	name string,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(readProtocolFixture(t, name), &document); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
	mutate(document)
	raw, err := CanonicalJSON(document)
	if err != nil {
		t.Fatalf("canonical %s mutation: %v", name, err)
	}
	return raw
}

func mutateLeaseFixture(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	response := mutateProtocolFixture(t, "heartbeat-response-lease.canonical.txt", func(response map[string]any) {
		mutate(response["lease"].(map[string]any))
	})
	var document map[string]json.RawMessage
	if err := json.Unmarshal(response, &document); err != nil {
		t.Fatalf("unmarshal lease response: %v", err)
	}
	return document["lease"]
}

func TestParseFrozenProtocolMessages(t *testing.T) {
	sessionRequest, err := ParseSessionRequestV1(readProtocolFixture(t, "session-request.canonical.txt"))
	if err != nil {
		t.Fatalf("ParseSessionRequestV1: %v", err)
	}
	if sessionRequest.Nonce != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("session nonce = %q", sessionRequest.Nonce)
	}

	sessionResponse, err := ParseSessionResponseV1(readProtocolFixture(t, "session-response.canonical.txt"))
	if err != nil {
		t.Fatalf("ParseSessionResponseV1: %v", err)
	}
	if sessionResponse.Sequence != 0 || sessionResponse.Epoch != 1 {
		t.Fatalf("session response = %+v", sessionResponse)
	}

	heartbeatRequest, err := ParseHeartbeatRequestV1(readProtocolFixture(t, "heartbeat-request.canonical.txt"))
	if err != nil {
		t.Fatalf("ParseHeartbeatRequestV1: %v", err)
	}
	if heartbeatRequest.Snapshot.Capacity.Available != 1 || heartbeatRequest.Sequence != 1 {
		t.Fatalf("heartbeat request = %+v", heartbeatRequest)
	}

	heartbeatResponse, err := ParseHeartbeatResponseV1(readProtocolFixture(t, "heartbeat-response-lease.canonical.txt"))
	if err != nil {
		t.Fatalf("ParseHeartbeatResponseV1 lease: %v", err)
	}
	if heartbeatResponse.Lease == nil || heartbeatResponse.NoLeaseReason != nil {
		t.Fatalf("heartbeat lease response = %+v", heartbeatResponse)
	}

	noLease, err := ParseHeartbeatResponseV1(readProtocolFixture(t, "heartbeat-response-no-lease.canonical.txt"))
	if err != nil {
		t.Fatalf("ParseHeartbeatResponseV1 no lease: %v", err)
	}
	if noLease.Lease != nil || noLease.NoLeaseReason == nil || *noLease.NoLeaseReason != NoLeaseHostedHold {
		t.Fatalf("heartbeat no-lease response = %+v", noLease)
	}
}

func TestFrozenProtocolDocumentsCanonicalizeIdentically(t *testing.T) {
	for _, name := range []string{
		"session-request",
		"session-response",
		"heartbeat-request",
		"heartbeat-response-lease",
		"heartbeat-response-no-lease",
	} {
		t.Run(name, func(t *testing.T) {
			var document any
			if err := json.Unmarshal(readProtocolFixture(t, name+".json"), &document); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got, err := CanonicalJSON(document)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			want := readProtocolFixture(t, name+".canonical.txt")
			if string(got) != string(want) {
				t.Fatalf("canonical = %s, want %s", got, want)
			}
			if _, err := ParseCanonicalJSON(want); err != nil {
				t.Fatalf("ParseCanonicalJSON: %v", err)
			}
		})
	}
}

func TestProtocolParsersRejectMissingUnknownAndInconsistentFields(t *testing.T) {
	missing := mutateProtocolFixture(t, "heartbeat-request.canonical.txt", func(request map[string]any) {
		snapshot := request["snapshot"].(map[string]any)
		delete(snapshot["capacity"].(map[string]any), "queued")
	})
	if _, err := ParseHeartbeatRequestV1(missing); err == nil {
		t.Fatal("heartbeat request accepted a missing nested field")
	}

	unknown := mutateProtocolFixture(t, "heartbeat-response-lease.canonical.txt", func(response map[string]any) {
		response["maintenance"].(map[string]any)["unknown"] = true
	})
	if _, err := ParseHeartbeatResponseV1(unknown); err == nil {
		t.Fatal("heartbeat response accepted an unknown nested field")
	}

	both := mutateProtocolFixture(t, "heartbeat-response-lease.canonical.txt", func(response map[string]any) {
		response["noLeaseReason"] = "hosted-hold"
	})
	if _, err := ParseHeartbeatResponseV1(both); err == nil {
		t.Fatal("heartbeat response accepted both a lease and a no-lease reason")
	}
}

func TestHeartbeatResponseRequiresCheckedExpiryEquation(t *testing.T) {
	for _, test := range []struct {
		name       string
		durationMs float64
		expiry     string
	}{
		{name: "shorter", durationMs: 20000, expiry: "2026-01-01T00:00:20.999Z"},
		{name: "longer", durationMs: 20000, expiry: "2026-01-01T00:00:21.001Z"},
		{name: "duration overflow", durationMs: 9223372036855, expiry: "2026-01-01T00:00:21.000Z"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := mutateProtocolFixture(t, "heartbeat-response-lease.canonical.txt", func(response map[string]any) {
				lease := response["lease"].(map[string]any)
				lease["durationMs"] = test.durationMs
				lease["expiry"] = test.expiry
			})
			if _, err := ParseHeartbeatResponseV1(raw); err == nil {
				t.Fatal("heartbeat response accepted an invalid expiry equation")
			}
		})
	}
}

func TestHeartbeatResponseRequiresRoutingHolderModeMatrix(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{name: "hosted lease", mutate: func(response, _ map[string]any) { response["routingState"] = "HOSTED" }},
		{name: "draining lease", mutate: func(response, _ map[string]any) { response["routingState"] = "DRAINING_TO_HOSTED" }},
		{name: "full state canary mode", mutate: func(response, lease map[string]any) {
			response["routingState"] = "PORTABLE_CANARY"
			lease["mode"] = "enabled"
		}},
		{name: "wrong holder", mutate: func(_ map[string]any, lease map[string]any) { lease["holder"] = "legacy" }},
		{name: "full state canary set", mutate: func(_ map[string]any, lease map[string]any) { lease["canaryScaleSet"] = "canary-set" }},
		{name: "legacy state portable holder", mutate: func(response, _ map[string]any) { response["routingState"] = "LEGACY" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := mutateProtocolFixture(t, "heartbeat-response-lease.canonical.txt", func(response map[string]any) {
				test.mutate(response, response["lease"].(map[string]any))
			})
			if _, err := ParseHeartbeatResponseV1(raw); err == nil {
				t.Fatal("heartbeat response accepted an inconsistent routing matrix")
			}
		})
	}
}

func TestHeartbeatResponseRequiresPositiveLeaseGeneration(t *testing.T) {
	for _, fixture := range []string{
		"heartbeat-response-lease.canonical.txt",
		"heartbeat-response-no-lease.canonical.txt",
	} {
		t.Run(fixture, func(t *testing.T) {
			raw := mutateProtocolFixture(t, fixture, func(response map[string]any) {
				response["maintenance"].(map[string]any)["leaseGeneration"] = float64(0)
				if lease, ok := response["lease"].(map[string]any); ok {
					lease["leaseGeneration"] = float64(0)
				}
			})
			if _, err := ParseHeartbeatResponseV1(raw); err == nil {
				t.Fatal("heartbeat response accepted lease generation zero")
			}
		})
	}
}

func TestProtocolTimestampFormattingIsExactUTCAndMillisecondBounded(t *testing.T) {
	input := time.Date(2026, 1, 1, 1, 2, 3, 456789000, time.FixedZone("offset", 3600))
	if got := FormatProtocolTimestamp(input); got != "2026-01-01T00:02:03.456Z" {
		t.Fatalf("FormatProtocolTimestamp = %q", got)
	}
}

func TestSessionResponseSafeIntegerBoundary(t *testing.T) {
	atBoundary := mutateProtocolFixture(t, "session-response.canonical.txt", func(response map[string]any) {
		response["epoch"] = float64(9007199254740991)
	})
	if _, err := ParseSessionResponseV1(atBoundary); err != nil {
		t.Fatalf("safe boundary rejected: %v", err)
	}
	beyond := mutateProtocolFixture(t, "session-response.canonical.txt", func(response map[string]any) {
		response["epoch"] = float64(9007199254740992)
	})
	if _, err := ParseSessionResponseV1(beyond); err == nil {
		t.Fatal("unsafe integer accepted")
	}
}

func TestProtocolParsersRejectNullForNonNullableWireFields(t *testing.T) {
	t.Run("session scalar", func(t *testing.T) {
		raw := mutateProtocolFixture(t, "session-response.canonical.txt", func(response map[string]any) {
			response["sequence"] = nil
		})
		if _, err := ParseSessionResponseV1(raw); err == nil {
			t.Fatal("session response accepted sequence:null")
		}
	})

	t.Run("heartbeat boolean and counter", func(t *testing.T) {
		for _, field := range []string{"degraded", "runningJobs"} {
			raw := mutateProtocolFixture(t, "heartbeat-request.canonical.txt", func(request map[string]any) {
				request["snapshot"].(map[string]any)[field] = nil
			})
			if _, err := ParseHeartbeatRequestV1(raw); err == nil {
				t.Fatalf("heartbeat request accepted %s:null", field)
			}
		}
	})

	t.Run("lease alias set", func(t *testing.T) {
		raw := mutateLeaseFixture(t, func(lease map[string]any) {
			lease["archivedDisabledAliases"] = nil
		})
		if _, err := ParseLeaseV1(raw); err == nil {
			t.Fatal("lease accepted archivedDisabledAliases:null")
		}
	})
}
