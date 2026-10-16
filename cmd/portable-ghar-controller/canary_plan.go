package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/controller"
)

type canaryPlanReceipt struct {
	SchemaVersion         uint32 `json:"schema_version"`
	FleetID               string `json:"fleet_id"`
	RepositoryAlias       string `json:"repository_alias"`
	ScaleSet              string `json:"scale_set"`
	ConfigurationRevision uint64 `json:"configuration_revision"`
	FenceGeneration       uint64 `json:"fence_generation"`
	LeaseGeneration       uint64 `json:"lease_generation"`
	PolicyDigest          string `json:"policy_digest"`
	ReportDigest          string `json:"report_digest"`
}

func executeCanaryPlan(ctx context.Context, args []string, stdout, stderr io.Writer, deps commandDependencies) int {
	flags, err := parseExactFlags(args, map[string]bool{"config": true, "eligible-scale-set": true})
	if err != nil || flags["config"] == "" || flags["eligible-scale-set"] == "" || deps.CanaryPlan == nil {
		return commandUsage(stderr)
	}
	if !deps.IsRoot() {
		return commandFailure(stderr, "canary plan")
	}
	callCtx, cancel := context.WithTimeout(ctx, deps.AdminTimeout)
	defer cancel()
	receipt, err := deps.CanaryPlan(callCtx, flags["config"], flags["eligible-scale-set"])
	if err != nil || json.NewEncoder(stdout).Encode(receipt) != nil {
		return commandFailure(stderr, "canary plan")
	}
	return 0
}

func buildCanaryPlan(runtime productionRuntime, report conformance.Report, status localPolicyStatus, scaleSet string) (canaryPlanReceipt, error) {
	if !validLocalPolicyStatus(&status) || status.Mode != controller.AcquisitionDisabled || status.WorkerLeaseGeneration == 0 || runtime.overlay.Worker == nil || report.Status() != conformance.StatusPending || !reportMatchesCanaryRuntime(report, runtime) {
		return canaryPlanReceipt{}, errCommandUnavailable
	}
	alias := ""
	for _, repo := range runtime.overlay.Repositories {
		if repo.ScaleSetName == scaleSet {
			if alias != "" {
				return canaryPlanReceipt{}, errCommandUnavailable
			}
			alias = repo.Alias
		}
	}
	if alias == "" {
		return canaryPlanReceipt{}, errCommandUnavailable
	}
	template, err := productionEnabledPolicyTemplate(runtime.overlay)
	if err != nil {
		return canaryPlanReceipt{}, errCommandUnavailable
	}
	policy, err := controller.CanaryPolicy(template, scaleSet)
	if err != nil {
		return canaryPlanReceipt{}, errCommandUnavailable
	}
	digest, err := controller.AcquisitionPolicyDigest(policy)
	if err != nil {
		return canaryPlanReceipt{}, errCommandUnavailable
	}
	return canaryPlanReceipt{SchemaVersion: 1, FleetID: runtime.overlay.Worker.FleetID, RepositoryAlias: alias, ScaleSet: scaleSet, ConfigurationRevision: policy.RepositoryPolicyRevision, FenceGeneration: runtime.manifest.FleetGeneration, LeaseGeneration: status.WorkerLeaseGeneration, PolicyDigest: hex.EncodeToString(digest[:]), ReportDigest: report.Digest()}, nil
}

// Read-only planning uses the exact pending runtime and an existing root-local
// probe. It neither opens a Worker session nor changes policy or evidence.
func productionCanaryPlan(ctx context.Context, configPath, scaleSet string) (canaryPlanReceipt, error) {
	readback, err := readCanaryReadback(ctx, configPath, false)
	if err != nil {
		return canaryPlanReceipt{}, err
	}
	runtime := readback.runtime
	client, err := newLocalAdminClient(runtime.overlay.Paths.AdminSocketPath, uint32(runtime.overlay.Target.ExpectedEUID), runtime.timings.operation)
	if err != nil {
		return canaryPlanReceipt{}, errCommandUnavailable
	}
	defer client.Close()
	response, err := client.call(ctx, localRequest{SchemaVersion: localProtocolSchemaVersion, Method: localMethodProbe})
	if err != nil {
		return canaryPlanReceipt{}, errCommandUnavailable
	}
	return buildCanaryPlan(runtime, readback.report, *response.Policy, scaleSet)
}
