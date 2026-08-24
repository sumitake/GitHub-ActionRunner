package failoverclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrProtocolClient    = errors.New("failoverclient: protocol client")
	ErrProtocolTransport = errors.New("failoverclient: protocol transport")
	ErrProtocolResponse  = errors.New("failoverclient: protocol response")
	ErrProtocolBinding   = errors.New("failoverclient: protocol binding")
	ErrProtocolRejected  = errors.New("failoverclient: protocol rejected")
)

type ProtocolClientConfig struct {
	BaseURL         string
	HMACKey         []byte
	RoundTripper    http.RoundTripper
	AuthorityClock  AuthorityClock
	UTCNow          func() time.Time
	AttemptTimeout  time.Duration
	TimestampWindow time.Duration
}

type ProtocolClient struct {
	baseURL         string
	hmacKey         []byte
	httpClient      *http.Client
	authorityClock  AuthorityClock
	utcNow          func() time.Time
	attemptTimeout  time.Duration
	timestampWindow time.Duration
}

type SessionDraftV1 struct {
	FleetID string
	Nonce   string
	BuildID string
}

type VerifiedSessionV1 struct {
	Request    SessionRequestV1
	Response   SessionResponseV1
	SendAnchor time.Time
}

type HeartbeatDraftV1 struct {
	FleetID         string
	Epoch           uint64
	SessionID       string
	Sequence        uint64
	Holder          Holder
	FenceGeneration uint64
	Snapshot        HeartbeatSnapshotV1
}

type VerifiedHeartbeatV1 struct {
	Request    HeartbeatRequestV1
	Response   HeartbeatResponseV1
	SendAnchor time.Time
}

func NewProtocolClient(config ProtocolClientConfig) (*ProtocolClient, error) {
	baseURL, err := canonicalHTTPSOrigin(config.BaseURL)
	if err != nil || len(config.HMACKey) < 32 || config.AuthorityClock == nil ||
		!config.AuthorityClock.Capable() || config.UTCNow == nil ||
		config.AttemptTimeout <= 0 || config.TimestampWindow <= 0 {
		return nil, fmt.Errorf("%w: configuration", ErrProtocolClient)
	}
	transport := config.RoundTripper
	if transport == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("%w: default transport", ErrProtocolClient)
		}
		transport = defaultTransport.Clone()
	}
	key := append([]byte(nil), config.HMACKey...)
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: redirect", ErrProtocolTransport)
		},
	}
	return &ProtocolClient{
		baseURL:         baseURL,
		hmacKey:         key,
		httpClient:      client,
		authorityClock:  config.AuthorityClock,
		utcNow:          config.UTCNow,
		attemptTimeout:  config.AttemptTimeout,
		timestampWindow: config.TimestampWindow,
	}, nil
}

func (client *ProtocolClient) CloseIdleConnections() {
	if client != nil && client.httpClient != nil {
		client.httpClient.CloseIdleConnections()
	}
}

func (client *ProtocolClient) OpenSession(ctx context.Context, draft SessionDraftV1) (VerifiedSessionV1, error) {
	timestamp, err := client.requestTimestamp()
	if err != nil {
		return VerifiedSessionV1{}, err
	}
	request := SessionRequestV1{
		ProtocolVersion: 1,
		FleetID:         draft.FleetID,
		Nonce:           draft.Nonce,
		Timestamp:       timestamp,
		BuildID:         draft.BuildID,
	}
	body, err := validatedSessionRequest(request)
	if err != nil {
		return VerifiedSessionV1{}, err
	}
	responseBody, responseTimestamp, anchor, err := client.exchange(ctx, SessionPath, timestamp, body)
	if err != nil {
		return VerifiedSessionV1{}, err
	}
	response, err := ParseSessionResponseV1(responseBody)
	if err != nil {
		return VerifiedSessionV1{}, fmt.Errorf("%w: session response", ErrProtocolResponse)
	}
	if response.ReceiptTime != responseTimestamp ||
		response.FleetID != request.FleetID || response.Nonce != request.Nonce {
		return VerifiedSessionV1{}, fmt.Errorf("%w: session response", ErrProtocolBinding)
	}
	return VerifiedSessionV1{Request: request, Response: response, SendAnchor: anchor}, nil
}

func (client *ProtocolClient) Heartbeat(
	ctx context.Context,
	draft HeartbeatDraftV1,
) (VerifiedHeartbeatV1, error) {
	timestamp, err := client.requestTimestamp()
	if err != nil {
		return VerifiedHeartbeatV1{}, err
	}
	request := HeartbeatRequestV1{
		ProtocolVersion: 1,
		FleetID:         draft.FleetID,
		Epoch:           draft.Epoch,
		SessionID:       draft.SessionID,
		Sequence:        draft.Sequence,
		Holder:          draft.Holder,
		FenceGeneration: draft.FenceGeneration,
		Snapshot:        draft.Snapshot,
		Timestamp:       timestamp,
	}
	body, err := validatedHeartbeatRequest(request)
	if err != nil {
		return VerifiedHeartbeatV1{}, err
	}
	responseBody, responseTimestamp, anchor, err := client.exchange(ctx, HeartbeatPath, timestamp, body)
	if err != nil {
		return VerifiedHeartbeatV1{}, err
	}
	response, err := ParseHeartbeatResponseV1(responseBody)
	if err != nil {
		return VerifiedHeartbeatV1{}, fmt.Errorf("%w: heartbeat response", ErrProtocolResponse)
	}
	if response.ReceiptTime != responseTimestamp ||
		response.FleetID != request.FleetID ||
		response.SessionID != request.SessionID ||
		response.Sequence != request.Sequence {
		return VerifiedHeartbeatV1{}, fmt.Errorf("%w: heartbeat response", ErrProtocolBinding)
	}
	if response.Lease != nil &&
		(response.Lease.ServerEpoch != request.Epoch ||
			response.Lease.Holder != LeaseHolder(request.Holder) ||
			response.Lease.LocalPolicyEpoch != request.Snapshot.PolicyEpoch ||
			response.Lease.PolicyDigest != request.Snapshot.PolicyDigest ||
			response.Lease.RepositoryPolicyRevision != request.Snapshot.RepositoryPolicyRevision) {
		return VerifiedHeartbeatV1{}, fmt.Errorf("%w: heartbeat lease", ErrProtocolBinding)
	}
	return VerifiedHeartbeatV1{Request: request, Response: response, SendAnchor: anchor}, nil
}

func (client *ProtocolClient) requestTimestamp() (string, error) {
	if client == nil || client.utcNow == nil {
		return "", fmt.Errorf("%w: unavailable", ErrProtocolClient)
	}
	utcNow := client.utcNow()
	if utcNow.IsZero() {
		return "", fmt.Errorf("%w: utc clock", ErrProtocolClient)
	}
	timestamp := FormatProtocolTimestamp(utcNow)
	if _, err := parseProtocolTimestamp(timestamp); err != nil {
		return "", fmt.Errorf("%w: utc clock", ErrProtocolClient)
	}
	return timestamp, nil
}

func (client *ProtocolClient) exchange(
	ctx context.Context,
	path string,
	requestTimestamp string,
	body []byte,
) ([]byte, string, time.Time, error) {
	mac, err := SignCanonical(client.hmacKey, http.MethodPost, path, requestTimestamp, body)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	attemptContext, cancel := context.WithTimeout(ctx, client.attemptTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		attemptContext,
		http.MethodPost,
		client.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("%w: request", ErrProtocolClient)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(TimestampHeader, requestTimestamp)
	request.Header.Set(MACHeader, mac)
	anchor, err := client.authorityClock.Now()
	if err != nil || anchor.IsZero() {
		return nil, "", time.Time{}, fmt.Errorf("%w: send anchor", ErrProtocolClient)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, "", time.Time{}, fmt.Errorf("%w: attempt", ErrProtocolTransport)
	}
	if response.Body == nil {
		return nil, "", time.Time{}, fmt.Errorf("%w: missing body", ErrProtocolResponse)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxProtocolBytes+1))
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("%w: read body", ErrProtocolResponse)
	}
	if len(responseBody) == 0 || len(responseBody) > maxProtocolBytes {
		return nil, "", time.Time{}, fmt.Errorf("%w: body size", ErrProtocolResponse)
	}
	if _, err := ParseCanonicalJSON(responseBody); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("%w: canonical body", ErrProtocolResponse)
	}
	timestamps := response.Header.Values(TimestampHeader)
	macs := response.Header.Values(MACHeader)
	if len(timestamps) != 1 || len(macs) != 1 {
		return nil, "", time.Time{}, fmt.Errorf("%w: response headers", ErrProtocolAuth)
	}
	responseTimestamp := timestamps[0]
	if err := VerifyCanonical(client.hmacKey, http.MethodPost, path, responseTimestamp, responseBody, macs[0]); err != nil {
		return nil, "", time.Time{}, err
	}
	if err := AssertTimestampWindow(responseTimestamp, requestTimestamp, client.timestampWindow); err != nil {
		return nil, "", time.Time{}, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", time.Time{}, fmt.Errorf("%w: status", ErrProtocolRejected)
	}
	return responseBody, responseTimestamp, anchor, nil
}

func validatedSessionRequest(request SessionRequestV1) ([]byte, error) {
	body, err := CanonicalJSON(request)
	if err != nil {
		return nil, err
	}
	if _, err := ParseSessionRequestV1(body); err != nil {
		return nil, err
	}
	return body, nil
}

func validatedHeartbeatRequest(request HeartbeatRequestV1) ([]byte, error) {
	body, err := CanonicalJSON(request)
	if err != nil {
		return nil, err
	}
	if _, err := ParseHeartbeatRequestV1(body); err != nil {
		return nil, err
	}
	return body, nil
}

func canonicalHTTPSOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.ForceQuery ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("%w: base URL", ErrProtocolClient)
	}
	if strings.Contains(parsed.Host, "\\") {
		return "", fmt.Errorf("%w: base URL", ErrProtocolClient)
	}
	return "https://" + parsed.Host, nil
}
