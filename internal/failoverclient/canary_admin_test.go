package failoverclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func canaryCommandFixture(t *testing.T, kind string) []byte {
	t.Helper()
	value := map[string]any{"protocolVersion": 1, "kind": kind, "fleetId": "example-fleet", "timestamp": "2026-01-01T00:00:00.000Z", "nonce": strings.Repeat("a", 64)}
	if kind == "portable-canary-start" {
		for k, v := range map[string]any{"repositoryAlias": "example-repository", "workflow": "canary.yml", "revision": strings.Repeat("b", 40), "scaleSet": "example-canary", "configurationRevision": 1, "policyDigest": strings.Repeat("c", 64), "fenceGeneration": 8, "leaseGeneration": 2, "observeUntil": "2026-01-01T01:00:00.000Z"} {
			value[k] = v
		}
	}
	raw, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCanaryAdminSignsAndBindsStartAndStop(t *testing.T) {
	for _, status := range []string{"portable-canary", "draining", "hosted"} {
		t.Run(status, func(t *testing.T) {
			kind := "portable-canary-stop"
			if status == "portable-canary" {
				kind = "portable-canary-start"
			}
			body := canaryCommandFixture(t, kind)
			calls := 0
			config := protocolClientConfig(nil)
			config.RoundTripper = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(raw) != string(body) || r.Method != "POST" || r.URL.Path != AdminCommandPath {
					t.Fatal("command changed")
				}
				if err := VerifyCanonical(config.HMACKey, "POST", AdminCommandPath, r.Header.Get(TimestampHeader), raw, r.Header.Get(MACHeader)); err != nil {
					t.Fatal(err)
				}
				reply := map[string]any{"protocolVersion": 1, "kind": kind, "fleetId": "example-fleet", "nonce": strings.Repeat("a", 64), "status": status, "receiptTime": "2026-01-01T00:00:00.000Z"}
				if kind == "portable-canary-start" {
					reply["scaleSet"] = "example-canary"
				}
				encoded, err := CanonicalJSON(reply)
				if err != nil {
					t.Fatal(err)
				}
				return signedResponse(t, config.HMACKey, AdminCommandPath, "2026-01-01T00:00:00.000Z", encoded, 200), nil
			})
			client, err := NewProtocolClient(config)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := client.SendCanaryAdmin(context.Background(), "example-fleet", body)
			if err != nil || calls != 1 || receipt.Status != status || receipt.Kind != kind {
				t.Fatalf("receipt=%+v calls=%d error=%v", receipt, calls, err)
			}
		})
	}
}

func TestCanaryAdminRejectsInvalidCommandsBeforeSending(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"version":   func(v map[string]any) { v["protocolVersion"] = 2 },
		"kind":      func(v map[string]any) { v["kind"] = "other" },
		"fleet":     func(v map[string]any) { v["fleetId"] = "bad/fleet" },
		"nonce":     func(v map[string]any) { v["nonce"] = "bad" },
		"timestamp": func(v map[string]any) { v["timestamp"] = "bad" },
		"stale": func(v map[string]any) {
			v["timestamp"] = "2025-12-31T00:00:00.000Z"
			v["observeUntil"] = "2025-12-31T01:00:00.000Z"
		},
		"alias":                func(v map[string]any) { v["repositoryAlias"] = "bad/alias" },
		"workflow":             func(v map[string]any) { v["workflow"] = "../canary.yml" },
		"revision":             func(v map[string]any) { v["revision"] = "main" },
		"scale set":            func(v map[string]any) { v["scaleSet"] = "bad/set" },
		"configuration zero":   func(v map[string]any) { v["configurationRevision"] = 0 },
		"configuration unsafe": func(v map[string]any) { v["configurationRevision"] = maxJavaScriptSafeInteger + 1 },
		"policy":               func(v map[string]any) { v["policyDigest"] = "bad" },
		"fence zero":           func(v map[string]any) { v["fenceGeneration"] = 0 },
		"fence unsafe":         func(v map[string]any) { v["fenceGeneration"] = maxJavaScriptSafeInteger + 1 },
		"lease zero":           func(v map[string]any) { v["leaseGeneration"] = 0 },
		"lease unsafe":         func(v map[string]any) { v["leaseGeneration"] = maxJavaScriptSafeInteger + 1 },
		"window malformed":     func(v map[string]any) { v["observeUntil"] = "bad" },
		"window past":          func(v map[string]any) { v["observeUntil"] = v["timestamp"] },
		"window too long":      func(v map[string]any) { v["observeUntil"] = "2026-01-02T00:00:00.001Z" },
		"unknown field":        func(v map[string]any) { v["other"] = true },
		"missing field":        func(v map[string]any) { delete(v, "revision") },
		"null":                 func(v map[string]any) { v["workflow"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(canaryCommandFixture(t, "portable-canary-start"), &value); err != nil {
				t.Fatal(err)
			}
			change(value)
			body, err := CanonicalJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			if name != "stale" {
				if _, err := parseCanaryAdminCommand(body); err == nil {
					t.Fatal("invalid command shape accepted by parser")
				}
			}
			calls := 0
			client, err := NewProtocolClient(protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; t.Fatal("invalid command sent"); return nil, nil })))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.SendCanaryAdmin(context.Background(), "example-fleet", body); err == nil || calls != 0 {
				t.Fatalf("invalid command accepted: %v", err)
			}
		})
	}
}

func TestCanaryAdminRejectsSignedResponseMismatch(t *testing.T) {
	for field, bad := range map[string]any{"protocolVersion": 2, "kind": "portable-canary-start", "fleetId": "other-fleet", "nonce": strings.Repeat("b", 64), "status": "enabled", "receiptTime": "2026-01-01T00:00:01.000Z", "extra": true} {
		t.Run(field, func(t *testing.T) {
			config := protocolClientConfig(nil)
			config.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
				value := map[string]any{"protocolVersion": 1, "kind": "portable-canary-stop", "fleetId": "example-fleet", "nonce": strings.Repeat("a", 64), "status": "hosted", "receiptTime": "2026-01-01T00:00:00.000Z"}
				value[field] = bad
				body, err := CanonicalJSON(value)
				if err != nil {
					t.Fatal(err)
				}
				return signedResponse(t, config.HMACKey, AdminCommandPath, "2026-01-01T00:00:00.000Z", body, 200), nil
			})
			client, err := NewProtocolClient(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.SendCanaryAdmin(context.Background(), "example-fleet", canaryCommandFixture(t, "portable-canary-stop")); err == nil {
				t.Fatal("mismatched response accepted")
			}
		})
	}
}

func TestCanaryAdminRefusesAnotherConfiguredFleet(t *testing.T) {
	client, err := NewProtocolClient(protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("wrong fleet sent"); return nil, nil })))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendCanaryAdmin(context.Background(), "other-fleet", canaryCommandFixture(t, "portable-canary-stop")); err == nil {
		t.Fatal("wrong configured fleet accepted")
	}
	if _, err := client.SendCanaryAdmin(contextWithNoValue(), "example-fleet", canaryCommandFixture(t, "portable-canary-stop")); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestCanaryAdminRejectsStartResponseScaleSetOrStatus(t *testing.T) {
	for field, bad := range map[string]string{"scaleSet": "other-canary", "status": "hosted"} {
		t.Run(field, func(t *testing.T) {
			config := protocolClientConfig(nil)
			config.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
				value := map[string]any{"protocolVersion": 1, "kind": "portable-canary-start", "fleetId": "example-fleet", "nonce": strings.Repeat("a", 64), "status": "portable-canary", "receiptTime": "2026-01-01T00:00:00.000Z", "scaleSet": "example-canary"}
				value[field] = bad
				body, err := CanonicalJSON(value)
				if err != nil {
					t.Fatal(err)
				}
				return signedResponse(t, config.HMACKey, AdminCommandPath, "2026-01-01T00:00:00.000Z", body, 200), nil
			})
			client, err := NewProtocolClient(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.SendCanaryAdmin(context.Background(), "example-fleet", canaryCommandFixture(t, "portable-canary-start")); err == nil {
				t.Fatal("mismatched start response accepted")
			}
		})
	}
}

// contextWithNoValue supplies an invalid context to exercise the public boundary.
func contextWithNoValue() context.Context { return nil }
