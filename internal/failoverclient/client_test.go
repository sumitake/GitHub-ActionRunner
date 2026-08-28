package failoverclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type trackingBody struct {
	io.Reader
	closed bool
}

type countingAuthorityClock struct {
	now   time.Time
	calls int
}

func (clock *countingAuthorityClock) Capable() bool { return true }

func (clock *countingAuthorityClock) Now() (time.Time, error) {
	clock.calls++
	return clock.now, nil
}

func (*countingAuthorityClock) WaitUntil(context.Context, time.Time) error { return nil }

func (body *trackingBody) Close() error {
	body.closed = true
	return nil
}

func protocolClientConfig(transport http.RoundTripper) ProtocolClientConfig {
	return ProtocolClientConfig{
		BaseURL:        "https://worker.example",
		HMACKey:        []byte(strings.Repeat("k", 32)),
		RoundTripper:   transport,
		AuthorityClock: NewFakeAuthorityClock(time.Unix(100, 0)),
		UTCNow: func() time.Time {
			return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		AttemptTimeout:  100 * time.Millisecond,
		TimestampWindow: 5 * time.Second,
	}
}

func signedResponse(t *testing.T, key []byte, path, timestamp string, body []byte, status int) *http.Response {
	t.Helper()
	mac, err := SignCanonical(key, "POST", path, timestamp, body)
	if err != nil {
		t.Fatalf("SignCanonical response: %v", err)
	}
	header := make(http.Header)
	header.Set(TimestampHeader, timestamp)
	header.Set(MACHeader, mac)
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}

func TestProtocolClientOpensBoundAuthenticatedSessionWithoutRetry(t *testing.T) {
	responseBody := readProtocolFixture(t, "session-response.canonical.txt")
	var calls int
	var config ProtocolClientConfig
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != "POST" || request.URL.String() != "https://worker.example/v1/session" {
			t.Fatalf("request target = %s %s", request.Method, request.URL)
		}
		requestBody, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		timestamp := request.Header.Values(TimestampHeader)
		mac := request.Header.Values(MACHeader)
		if len(timestamp) != 1 || len(mac) != 1 {
			t.Fatalf("request auth headers = %v %v", timestamp, mac)
		}
		if err := VerifyCanonical(config.HMACKey, "POST", SessionPath, timestamp[0], requestBody, mac[0]); err != nil {
			t.Fatalf("request MAC: %v", err)
		}
		return signedResponse(t, config.HMACKey, SessionPath, "2026-01-01T00:00:00.000Z", responseBody, http.StatusOK), nil
	})
	config = protocolClientConfig(transport)
	client, err := NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	result, err := client.OpenSession(context.Background(), SessionDraftV1{
		FleetID: "example-fleet",
		Nonce:   strings.Repeat("a", 64),
		BuildID: strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if calls != 1 || result.Response.SessionID != strings.Repeat("c", 64) ||
		!result.SendAnchor.Equal(time.Unix(100, 0)) {
		t.Fatalf("session result calls=%d result=%+v", calls, result)
	}
}

func TestProtocolClientBindsHeartbeatResponseAndReturnsNoAuthorityOnMismatch(t *testing.T) {
	request, err := ParseHeartbeatRequestV1(readProtocolFixture(t, "heartbeat-request.canonical.txt"))
	if err != nil {
		t.Fatalf("parse request fixture: %v", err)
	}
	responseBody := readProtocolFixture(t, "heartbeat-response-lease.canonical.txt")
	config := protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return signedResponse(t, []byte(strings.Repeat("k", 32)), HeartbeatPath, "2026-01-01T00:00:01.000Z", responseBody, http.StatusOK), nil
	}))
	config.UTCNow = func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	}
	client, err := NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	result, err := client.Heartbeat(context.Background(), HeartbeatDraftV1{
		FleetID:         request.FleetID,
		Epoch:           request.Epoch,
		SessionID:       request.SessionID,
		Sequence:        request.Sequence,
		Holder:          request.Holder,
		FenceGeneration: request.FenceGeneration,
		Snapshot:        request.Snapshot,
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if result.Response.Lease == nil || result.Response.Lease.LeaseGeneration != 1 {
		t.Fatalf("heartbeat result = %+v", result)
	}

	wrongSequence := []byte(strings.Replace(
		string(responseBody),
		`"sequence":1`,
		`"sequence":2`,
		1,
	))
	config.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return signedResponse(t, config.HMACKey, HeartbeatPath, "2026-01-01T00:00:01.000Z", wrongSequence, http.StatusOK), nil
	})
	client, err = NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient mismatch: %v", err)
	}
	if _, err := client.Heartbeat(context.Background(), HeartbeatDraftV1{
		FleetID:         request.FleetID,
		Epoch:           request.Epoch,
		SessionID:       request.SessionID,
		Sequence:        request.Sequence,
		Holder:          request.Holder,
		FenceGeneration: request.FenceGeneration,
		Snapshot:        request.Snapshot,
	}); !errors.Is(err, ErrProtocolBinding) {
		t.Fatalf("mismatched response error = %v", err)
	}
}

func TestProtocolClientAcceptsServerOwnedLeaseGenerationTransitions(t *testing.T) {
	request, err := ParseHeartbeatRequestV1(readProtocolFixture(t, "heartbeat-request.canonical.txt"))
	if err != nil {
		t.Fatalf("parse request fixture: %v", err)
	}
	for _, test := range []struct {
		name       string
		fixture    string
		mutate     func(map[string]any)
		wantReason NoLeaseReason
	}{
		{
			name:    "stale selector drain",
			fixture: "heartbeat-response-no-lease.canonical.txt",
			mutate: func(response map[string]any) {
				response["routingState"] = "DRAINING_TO_HOSTED"
				response["noLeaseReason"] = "stale-selector-evidence"
				maintenance := response["maintenance"].(map[string]any)
				maintenance["kind"] = "none"
				maintenance["leaseGeneration"] = float64(2)
			},
			wantReason: NoLeaseStaleSelector,
		},
		{
			name:    "canary route readiness",
			fixture: "heartbeat-response-lease.canonical.txt",
			mutate: func(response map[string]any) {
				response["routingState"] = "PORTABLE_CANARY"
				maintenance := response["maintenance"].(map[string]any)
				maintenance["leaseGeneration"] = float64(2)
				lease := response["lease"].(map[string]any)
				lease["leaseGeneration"] = float64(2)
				lease["mode"] = "canary-only"
				lease["maxCapacity"] = float64(1)
				lease["canaryScaleSet"] = "repo-a"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var response map[string]any
			if err := json.Unmarshal(readProtocolFixture(t, test.fixture), &response); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			test.mutate(response)
			responseBody, err := CanonicalJSON(response)
			if err != nil {
				t.Fatalf("canonical response: %v", err)
			}
			config := protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return signedResponse(t, []byte(strings.Repeat("k", 32)), HeartbeatPath, "2026-01-01T00:00:01.000Z", responseBody, http.StatusOK), nil
			}))
			config.UTCNow = func() time.Time {
				return time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
			}
			client, err := NewProtocolClient(config)
			if err != nil {
				t.Fatalf("NewProtocolClient: %v", err)
			}
			result, err := client.Heartbeat(context.Background(), HeartbeatDraftV1{
				FleetID:         request.FleetID,
				Epoch:           request.Epoch,
				SessionID:       request.SessionID,
				Sequence:        request.Sequence,
				Holder:          request.Holder,
				FenceGeneration: request.FenceGeneration,
				Snapshot:        request.Snapshot,
			})
			if err != nil {
				t.Fatalf("Heartbeat: %v", err)
			}
			if result.Response.Maintenance.LeaseGeneration != 2 {
				t.Fatalf("lease generation = %d", result.Response.Maintenance.LeaseGeneration)
			}
			if test.wantReason != "" && (result.Response.NoLeaseReason == nil || *result.Response.NoLeaseReason != test.wantReason) {
				t.Fatalf("no lease reason = %v", result.Response.NoLeaseReason)
			}
		})
	}
}

func TestProtocolClientCapturesSendAnchorAfterLocalValidation(t *testing.T) {
	clock := &countingAuthorityClock{now: time.Unix(200, 0)}
	config := protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport must not be called")
		return nil, nil
	}))
	config.AuthorityClock = clock
	client, err := NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	if _, err := client.OpenSession(context.Background(), SessionDraftV1{
		FleetID: "Invalid",
		Nonce:   strings.Repeat("a", 64),
		BuildID: strings.Repeat("b", 64),
	}); err == nil {
		t.Fatal("OpenSession accepted invalid local draft")
	}
	if clock.calls != 0 {
		t.Fatalf("authority clock calls before local validation = %d", clock.calls)
	}
}

func TestProtocolClientAuthenticatesBeforeStatusClassification(t *testing.T) {
	rejected := []byte(`{"error":"rejected"}`)
	for _, test := range []struct {
		name      string
		response  func(ProtocolClientConfig) *http.Response
		wantError error
	}{
		{
			name: "unsigned rejection",
			response: func(ProtocolClientConfig) *http.Response {
				return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(rejected)))}
			},
			wantError: ErrProtocolAuth,
		},
		{
			name: "authenticated rejection",
			response: func(config ProtocolClientConfig) *http.Response {
				return signedResponse(t, config.HMACKey, SessionPath, "2026-01-01T00:00:00.000Z", rejected, http.StatusUnauthorized)
			},
			wantError: ErrProtocolRejected,
		},
		{
			name: "bad response mac",
			response: func(config ProtocolClientConfig) *http.Response {
				response := signedResponse(t, config.HMACKey, SessionPath, "2026-01-01T00:00:00.000Z", readProtocolFixture(t, "session-response.canonical.txt"), http.StatusOK)
				response.Header.Set(MACHeader, strings.Repeat("0", 64))
				return response
			},
			wantError: ErrProtocolAuth,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config ProtocolClientConfig
			config = protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return test.response(config), nil
			}))
			client, err := NewProtocolClient(config)
			if err != nil {
				t.Fatalf("NewProtocolClient: %v", err)
			}
			if _, err := client.OpenSession(context.Background(), SessionDraftV1{
				FleetID: "example-fleet",
				Nonce:   strings.Repeat("a", 64),
				BuildID: strings.Repeat("b", 64),
			}); !errors.Is(err, test.wantError) {
				t.Fatalf("OpenSession error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestProtocolClientBoundsAndClosesResponseBody(t *testing.T) {
	body := &trackingBody{Reader: strings.NewReader(strings.Repeat("x", maxProtocolBytes+1))}
	config := protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
	}))
	client, err := NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	_, err = client.OpenSession(context.Background(), SessionDraftV1{
		FleetID: "example-fleet",
		Nonce:   strings.Repeat("a", 64),
		BuildID: strings.Repeat("b", 64),
	})
	if !errors.Is(err, ErrProtocolResponse) || !body.closed {
		t.Fatalf("oversized response error=%v closed=%v", err, body.closed)
	}
}

func TestProtocolClientRejectsAmbiguousResponseHeaders(t *testing.T) {
	var config ProtocolClientConfig
	config = protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := signedResponse(
			t,
			config.HMACKey,
			SessionPath,
			"2026-01-01T00:00:00.000Z",
			readProtocolFixture(t, "session-response.canonical.txt"),
			http.StatusOK,
		)
		response.Header.Add(TimestampHeader, "2026-01-01T00:00:00.000Z")
		return response, nil
	}))
	client, err := NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	_, err = client.OpenSession(context.Background(), SessionDraftV1{
		FleetID: "example-fleet",
		Nonce:   strings.Repeat("a", 64),
		BuildID: strings.Repeat("b", 64),
	})
	if !errors.Is(err, ErrProtocolAuth) {
		t.Fatalf("duplicate header error = %v", err)
	}
}

func TestProtocolClientBindsReceiptBodyToAuthenticatedHeader(t *testing.T) {
	var config ProtocolClientConfig
	config = protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return signedResponse(
			t,
			config.HMACKey,
			SessionPath,
			"2026-01-01T00:00:01.000Z",
			readProtocolFixture(t, "session-response.canonical.txt"),
			http.StatusOK,
		), nil
	}))
	client, err := NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	_, err = client.OpenSession(context.Background(), SessionDraftV1{
		FleetID: "example-fleet",
		Nonce:   strings.Repeat("a", 64),
		BuildID: strings.Repeat("b", 64),
	})
	if !errors.Is(err, ErrProtocolBinding) {
		t.Fatalf("receipt binding error = %v", err)
	}
}

func TestProtocolClientRequiresCanonicalHTTPSOrigin(t *testing.T) {
	for _, baseURL := range []string{
		"http://worker.example",
		"https://:443",
		strings.Join([]string{"https://user", "worker.example"}, "@"),
		"https://worker.example/base",
		"https://worker.example?query=1",
		"https://worker.example/#fragment",
	} {
		config := protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("transport must not be called")
			return nil, nil
		}))
		config.BaseURL = baseURL
		if _, err := NewProtocolClient(config); !errors.Is(err, ErrProtocolClient) {
			t.Fatalf("base URL %q error = %v", baseURL, err)
		}
	}
}

func TestProtocolClientRejectsZeroUTCClockBeforeTransport(t *testing.T) {
	var calls int
	config := protocolClientConfig(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not run")
	}))
	config.UTCNow = func() time.Time { return time.Time{} }
	client, err := NewProtocolClient(config)
	if err != nil {
		t.Fatalf("NewProtocolClient: %v", err)
	}
	_, err = client.OpenSession(context.Background(), SessionDraftV1{
		FleetID: "example-fleet",
		Nonce:   strings.Repeat("a", 64),
		BuildID: strings.Repeat("b", 64),
	})
	if !errors.Is(err, ErrProtocolClient) || calls != 0 {
		t.Fatalf("zero UTC clock error=%v calls=%d", err, calls)
	}
}

func TestProtocolClientDoesNotRetryTimeoutAmbiguityOrRedirect(t *testing.T) {
	for _, test := range []struct {
		name      string
		transport roundTripFunc
	}{
		{
			name: "timeout",
			transport: func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			},
		},
		{
			name: "ambiguous transport failure",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("ambiguous write")
			},
		},
		{
			name: "redirect",
			transport: func(*http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("Location", "https://other.example/v1/session")
				return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: header, Body: io.NopCloser(strings.NewReader(""))}, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			config := protocolClientConfig(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				return test.transport(request)
			}))
			config.AttemptTimeout = 5 * time.Millisecond
			client, err := NewProtocolClient(config)
			if err != nil {
				t.Fatalf("NewProtocolClient: %v", err)
			}
			if _, err := client.OpenSession(context.Background(), SessionDraftV1{
				FleetID: "example-fleet",
				Nonce:   strings.Repeat("a", 64),
				BuildID: strings.Repeat("b", 64),
			}); !errors.Is(err, ErrProtocolTransport) {
				t.Fatalf("OpenSession error = %v", err)
			}
			if calls != 1 {
				t.Fatalf("transport calls = %d", calls)
			}
		})
	}
}
