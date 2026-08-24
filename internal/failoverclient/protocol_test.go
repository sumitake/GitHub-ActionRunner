package failoverclient

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "../../tests/fixtures/protocol/v1")
}

func TestHMACVectorMatchesFrozenFixture(t *testing.T) {
	root := fixtureRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "hmac-vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		KeyHex            string `json:"keyHex"`
		Method            string `json:"method"`
		Path              string `json:"path"`
		Timestamp         string `json:"timestamp"`
		CanonicalBodyFile string `json:"canonicalBodyFile"`
		MACHex            string `json:"macHex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, vector.CanonicalBodyFile))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	key, err := hex.DecodeString(vector.KeyHex)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	mac, err := SignCanonical(key, vector.Method, vector.Path, vector.Timestamp, bytesTrimNL(body))
	if err != nil {
		t.Fatalf("SignCanonical: %v", err)
	}
	if mac != vector.MACHex {
		t.Fatalf("mac = %s, want %s", mac, vector.MACHex)
	}
	if err := VerifyCanonical(key, vector.Method, vector.Path, vector.Timestamp, bytesTrimNL(body), vector.MACHex); err != nil {
		t.Fatalf("VerifyCanonical: %v", err)
	}
}

func TestFullExchangeHMACVectorsMatchFrozenFixtures(t *testing.T) {
	root := fixtureRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "exchange-hmac-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var fixture struct {
		KeyHex  string `json:"keyHex"`
		Vectors []struct {
			Name              string `json:"name"`
			Method            string `json:"method"`
			Path              string `json:"path"`
			Timestamp         string `json:"timestamp"`
			CanonicalBodyFile string `json:"canonicalBodyFile"`
			MACHex            string `json:"macHex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	key, err := hex.DecodeString(fixture.KeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, vector.CanonicalBodyFile))
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			mac, err := SignCanonical(key, vector.Method, vector.Path, vector.Timestamp, bytesTrimNL(body))
			if err != nil {
				t.Fatalf("SignCanonical: %v", err)
			}
			if mac != vector.MACHex {
				t.Fatalf("mac = %s, want %s", mac, vector.MACHex)
			}
		})
	}
}

func TestProtocolTimestampRejectsCalendarInvalidValue(t *testing.T) {
	if _, err := MACInput(
		"POST",
		SessionPath,
		"2026-02-31T00:00:00.000Z",
		[]byte("{}"),
	); err == nil {
		t.Fatal("MACInput accepted a calendar-invalid timestamp")
	}
}

func TestLeaseRejectsValuesOutsideWorkerNumericAndTimeDomain(t *testing.T) {
	unsafeNumber := mutateLeaseFixture(t, func(lease map[string]any) {
		lease["serverEpoch"] = float64(9007199254740992)
	})
	if _, err := ParseLeaseV1(unsafeNumber); err == nil {
		t.Fatal("ParseLeaseV1 accepted an integer above the JavaScript safe range")
	}

	zeroGeneration := mutateLeaseFixture(t, func(lease map[string]any) {
		lease["leaseGeneration"] = float64(0)
	})
	if _, err := ParseLeaseV1(zeroGeneration); err == nil {
		t.Fatal("ParseLeaseV1 accepted lease generation zero")
	}

	invalidTime := mutateLeaseFixture(t, func(lease map[string]any) {
		lease["expiry"] = "2026-02-31T00:00:00.000Z"
	})
	if _, err := ParseLeaseV1(invalidTime); err == nil {
		t.Fatal("ParseLeaseV1 accepted a calendar-invalid expiry")
	}
}

func TestHeartbeatBudgetAndLocalDeadline(t *testing.T) {
	budget := HeartbeatBudget{
		LeaseDuration:      20 * time.Millisecond,
		MaxAttemptInterval: 4 * time.Millisecond,
		Deadline:           3 * time.Millisecond,
		ShorteningMargin:   2 * time.Millisecond,
		LostRenewals:       1,
	}
	if err := budget.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	budget.LostRenewals = 0
	if err := budget.Validate(); err == nil {
		t.Fatal("Validate() accepted N=0")
	}
	budget = HeartbeatBudget{
		LeaseDuration:      20 * time.Millisecond,
		MaxAttemptInterval: time.Millisecond,
		Deadline:           time.Millisecond,
		ShorteningMargin:   time.Millisecond,
		LostRenewals:       ^uint(0),
	}
	if err := budget.Validate(); err == nil {
		t.Fatal("Validate() accepted a renewal-count overflow")
	}
	budget = HeartbeatBudget{
		LeaseDuration:      time.Duration(1<<63 - 1),
		MaxAttemptInterval: time.Duration(1<<63 - 1),
		Deadline:           time.Nanosecond,
		ShorteningMargin:   time.Nanosecond,
		LostRenewals:       1,
	}
	if err := budget.Validate(); err == nil {
		t.Fatal("Validate() accepted duration arithmetic overflow")
	}
	send := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	got, err := LocalLeaseDeadline(send, 8*time.Second, time.Second)
	if err != nil {
		t.Fatalf("LocalLeaseDeadline: %v", err)
	}
	if !got.Equal(send.Add(7 * time.Second)) {
		t.Fatalf("deadline = %s", got)
	}
}

func TestUnsupportedClockDisablesAcquisition(t *testing.T) {
	clock := NewUnsupportedAuthorityClock()
	if clock.Capable() {
		t.Fatal("unsupported clock reported capable")
	}
	if _, err := clock.Now(); err == nil {
		t.Fatal("unsupported Now succeeded")
	}
}

func bytesTrimNL(raw []byte) []byte {
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		return raw[:len(raw)-1]
	}
	return raw
}
