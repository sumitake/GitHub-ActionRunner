package main

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/sumitake/portable-ghar/internal/failoverclient"
)

func executeWorkerCanary(ctx context.Context, args []string, stdout, stderr io.Writer, deps commandDependencies) int {
	flags, err := parseExactFlags(args, map[string]bool{"config": true, "command-file": true})
	if err != nil || flags["config"] == "" || flags["command-file"] == "" || deps.WorkerCanary == nil {
		return commandUsage(stderr)
	}
	if !deps.IsRoot() {
		_, _ = io.WriteString(stderr, "portable-ghar-controller: Worker canary command failed\n")
		return 1
	}
	callCtx, cancel := context.WithTimeout(ctx, deps.AdminTimeout)
	defer cancel()
	receipt, err := deps.WorkerCanary(callCtx, flags["config"], flags["command-file"])
	if err != nil {
		_, _ = io.WriteString(stderr, "portable-ghar-controller: Worker canary command failed\n")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(receipt); err != nil {
		_, _ = io.WriteString(stderr, "portable-ghar-controller: output failed\n")
		return 1
	}
	return 0
}

func productionWorkerCanary(ctx context.Context, configPath, commandPath string) (failoverclient.CanaryAdminReceipt, error) {
	overlay, err := readProductionOverlay(configPath)
	if err != nil || overlay.Worker == nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	body, err := readPinnedRootFile(commandPath, 0o600, 65536)
	if err != nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	secretPath, ok := fileSecretPath(overlay, overlay.Worker.HMACCredentialName)
	if !ok {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	encodedKey, err := readCredentialFile(secretPath)
	if err != nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	key, err := failoverclient.DecodeHex(encodedKey)
	if err != nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	defer clear(key)
	window, err := time.ParseDuration(overlay.Worker.TimestampWindow)
	if err != nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	deadline, err := time.ParseDuration(overlay.Worker.HeartbeatDeadline)
	if err != nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	clock, err := failoverclient.NewProductionAuthorityClock()
	if err != nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	client, err := failoverclient.NewProtocolClient(failoverclient.ProtocolClientConfig{
		BaseURL: overlay.Worker.BaseURL, HMACKey: key, AuthorityClock: clock, UTCNow: time.Now, AttemptTimeout: deadline, TimestampWindow: window,
	})
	if err != nil {
		return failoverclient.CanaryAdminReceipt{}, errCommandUnavailable
	}
	defer client.CloseIdleConnections()
	return client.SendCanaryAdmin(ctx, overlay.Worker.FleetID, body)
}
