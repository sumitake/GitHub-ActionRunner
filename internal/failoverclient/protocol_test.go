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

func TestCanonicalSessionRequestMatchesFrozenFixture(t *testing.T) {
	root := fixtureRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "session-request.json"))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(root, "session-request.canonical.txt"))
	if err != nil {
		t.Fatalf("read canonical: %v", err)
	}
	want = bytesTrimNL(want)
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := CanonicalJSON(document)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
	if _, err := ParseCanonicalJSON(want); err != nil {
		t.Fatalf("ParseCanonicalJSON: %v", err)
	}
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
