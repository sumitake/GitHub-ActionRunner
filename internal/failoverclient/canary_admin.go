package failoverclient

import (
	"context"
	"regexp"
	"time"
)

var (
	canaryWorkflowPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$`)
	canaryRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type canaryAdminCommand struct {
	ProtocolVersion       int    `json:"protocolVersion"`
	Kind                  string `json:"kind"`
	FleetID               string `json:"fleetId"`
	Timestamp             string `json:"timestamp"`
	Nonce                 string `json:"nonce"`
	RepositoryAlias       string `json:"repositoryAlias,omitempty"`
	Workflow              string `json:"workflow,omitempty"`
	Revision              string `json:"revision,omitempty"`
	ScaleSet              string `json:"scaleSet,omitempty"`
	ConfigurationRevision uint64 `json:"configurationRevision,omitempty"`
	PolicyDigest          string `json:"policyDigest,omitempty"`
	FenceGeneration       uint64 `json:"fenceGeneration,omitempty"`
	LeaseGeneration       uint64 `json:"leaseGeneration,omitempty"`
	ObserveUntil          string `json:"observeUntil,omitempty"`
}

// CanaryAdminReceipt is the authenticated, exactly bound result of one
// portable-canary-start or portable-canary-stop command. Draining requires a
// later stop with a fresh nonce; no admin request is automatically retried.
type CanaryAdminReceipt struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Kind            string `json:"kind"`
	FleetID         string `json:"fleetId"`
	Nonce           string `json:"nonce"`
	Status          string `json:"status"`
	ReceiptTime     string `json:"receiptTime"`
	ScaleSet        string `json:"scaleSet,omitempty"`
}

// SendCanaryAdmin sends exactly one canonical command using the same HMAC,
// response verification, size limits, deadlines, and redirect refusal as the
// session/heartbeat protocol. The caller supplies the timestamp and fresh nonce
// so the exact command can be journaled before its potentially ambiguous effect.
func (client *ProtocolClient) SendCanaryAdmin(ctx context.Context, expectedFleet string, body []byte) (CanaryAdminReceipt, error) {
	if ctx == nil {
		return CanaryAdminReceipt{}, ErrProtocolClient
	}
	command, err := parseCanaryAdminCommand(body)
	if err != nil {
		return CanaryAdminReceipt{}, err
	}
	if command.FleetID != expectedFleet {
		return CanaryAdminReceipt{}, ErrProtocolBinding
	}
	now, err := client.requestTimestamp()
	if err != nil {
		return CanaryAdminReceipt{}, err
	}
	if err := AssertTimestampWindow(now, command.Timestamp, client.timestampWindow); err != nil {
		return CanaryAdminReceipt{}, err
	}
	responseBody, timestamp, _, err := client.exchange(ctx, AdminCommandPath, command.Timestamp, body)
	if err != nil {
		return CanaryAdminReceipt{}, err
	}
	fields := []string{"protocolVersion", "kind", "fleetId", "nonce", "status", "receiptTime"}
	if command.Kind == "portable-canary-start" {
		fields = append(fields, "scaleSet")
	}
	var response CanaryAdminReceipt
	if _, err := decodeExactMessage(responseBody, fields, &response); err != nil {
		return CanaryAdminReceipt{}, err
	}
	if response.ProtocolVersion != 1 || response.Kind != command.Kind || response.FleetID != command.FleetID || response.Nonce != command.Nonce || response.ReceiptTime != timestamp || response.ScaleSet != command.ScaleSet {
		return CanaryAdminReceipt{}, ErrProtocolBinding
	}
	if (command.Kind == "portable-canary-start" && response.Status != "portable-canary") || (command.Kind == "portable-canary-stop" && response.Status != "draining" && response.Status != "hosted") {
		return CanaryAdminReceipt{}, ErrProtocolResponse
	}
	return response, nil
}

func parseCanaryAdminCommand(body []byte) (canaryAdminCommand, error) {
	parsed, err := ParseCanonicalJSON(body)
	if err != nil {
		return canaryAdminCommand{}, err
	}
	record, ok := parsed.(map[string]any)
	if !ok {
		return canaryAdminCommand{}, ErrProtocolMessage
	}
	fields := []string{"protocolVersion", "kind", "fleetId", "timestamp", "nonce"}
	switch record["kind"] {
	case "portable-canary-start":
		fields = append(fields, "repositoryAlias", "workflow", "revision", "scaleSet", "configurationRevision", "policyDigest", "fenceGeneration", "leaseGeneration", "observeUntil")
	case "portable-canary-stop":
	default:
		return canaryAdminCommand{}, ErrProtocolMessage
	}
	var command canaryAdminCommand
	if _, err := decodeExactMessage(body, fields, &command); err != nil {
		return canaryAdminCommand{}, err
	}
	if command.ProtocolVersion != 1 || !fleetIDPattern.MatchString(command.FleetID) || !hex64Pattern.MatchString(command.Nonce) {
		return canaryAdminCommand{}, ErrProtocolMessage
	}
	at, err := parseProtocolTimestamp(command.Timestamp)
	if err != nil {
		return canaryAdminCommand{}, err
	}
	if command.Kind == "portable-canary-stop" {
		return command, nil
	}
	if !aliasPattern.MatchString(command.RepositoryAlias) || !canaryWorkflowPattern.MatchString(command.Workflow) || !canaryRevisionPattern.MatchString(command.Revision) || !aliasPattern.MatchString(command.ScaleSet) || !hex64Pattern.MatchString(command.PolicyDigest) {
		return canaryAdminCommand{}, ErrProtocolMessage
	}
	for _, value := range []uint64{command.ConfigurationRevision, command.FenceGeneration, command.LeaseGeneration} {
		if value == 0 || value > maxJavaScriptSafeInteger {
			return canaryAdminCommand{}, ErrProtocolMessage
		}
	}
	until, err := parseProtocolTimestamp(command.ObserveUntil)
	if err != nil || !until.After(at) || until.Sub(at) > 24*time.Hour {
		return canaryAdminCommand{}, ErrProtocolMessage
	}
	return command, nil
}
