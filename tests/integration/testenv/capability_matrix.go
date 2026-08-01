package testenv

import (
	"errors"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

// ObservationID is one closed target or synthetic observation.
type ObservationID string

// ObservationSource is the only authority allowed to produce an observation.
type ObservationSource string

const (
	SourceHostProfile         ObservationSource = "host-profile"
	SourceHostRuntimeEngine   ObservationSource = "hostruntime-engine"
	SourceNetworkOrchestrator ObservationSource = "networkjail-orchestrator"
	SourceClosedTestCommand   ObservationSource = "closed-test-command"
	SourceBoundEvidenceLedger ObservationSource = "bound-evidence-ledger"
	SourceSyntheticLocal      ObservationSource = "synthetic-local"
	SourceActualGitHubCanary  ObservationSource = "actual-github-canary"
)

var errInvalidObservationMatrix = errors.New(
	"testenv: invalid observation capability matrix",
)

// ObservationRequirement binds one observation to one case, layer, closed
// source, operation, output bound, and parser.
type ObservationRequirement struct {
	ID        ObservationID
	Case      conformance.CaseID
	Layer     conformance.ProofLayer
	Source    ObservationSource
	Operation string
	MaxBytes  uint64
	Parser    string
}

const (
	smallObservation = uint64(64 << 10)
	largeObservation = uint64(1 << 20)
)

var requiredObservationMatrix = [...]ObservationRequirement{
	// Case 1: host profile.
	{"host-os-architecture", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceHostProfile, "profile-platform", smallObservation, "platform-v1"},
	{"host-kernel-runtime", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceHostProfile, "profile-runtime", smallObservation, "platform-v1"},
	{"host-euid-profile", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceHostProfile, "profile-identity", smallObservation, "identity-v1"},
	{"host-capability-sets", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceHostProfile, "profile-capabilities", smallObservation, "capabilities-v1"},
	{"host-cgroup-controls", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceHostProfile, "profile-cgroups", smallObservation, "cgroups-v1"},
	{"host-sizing-envelopes", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceHostProfile, "profile-envelopes", largeObservation, "envelopes-v1"},
	{"host-effective-capacity", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceHostProfile, "profile-capacity", smallObservation, "capacity-v1"},
	{"host-execution-identity", conformance.CaseHostProfile, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "execution-host-identity", smallObservation, "identity-v1"},

	// Case 2: namespace baseline.
	{"adapter-runner-netns-identity", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "namespace-identity", smallObservation, "namespace-v1"},
	{"runner-loopback-only", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceNetworkOrchestrator, "namespace-links", smallObservation, "links-v1"},
	{"runner-tables-empty", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceNetworkOrchestrator, "namespace-tables", largeObservation, "tables-v1"},
	{"runner-conntrack-before", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceNetworkOrchestrator, "namespace-conntrack-before", largeObservation, "conntrack-v1"},
	{"loopback-flood", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "loopback-flood", smallObservation, "flood-v1"},
	{"runner-tables-after-flood", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "loopback-flood", smallObservation, "flood-v1"},
	{"runner-conntrack-after", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "loopback-flood", smallObservation, "flood-v1"},
	{"runner-route-absence", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "loopback-flood", smallObservation, "flood-v1"},
	{"namespace-stable-after-attach", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "namespace-final-proof", smallObservation, "namespace-v1"},
	{"helper-capabilities-lifetime", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceHostRuntimeEngine, "helper-lifetime", largeObservation, "process-capabilities-v1"},
	{"runtime-capabilities-empty", conformance.CaseNamespaceBaseline, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "runtime-capabilities", largeObservation, "process-capabilities-v1"},

	// Case 3: broker egress.
	{"held-broker-sockets-zero", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceHostRuntimeEngine, "held-broker-sockets", smallObservation, "socket-counts-v1"},
	{"broker-positive-https", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceNetworkOrchestrator, "broker-positive-https", largeObservation, "broker-probe-v1"},
	{"broker-denied-literal", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceNetworkOrchestrator, "broker-denied-literal", largeObservation, "broker-denial-v1"},
	{"broker-denied-dns", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceNetworkOrchestrator, "broker-denied-dns", largeObservation, "broker-denial-v1"},
	{"broker-denied-direct-protocols", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "runner-direct-protocols", largeObservation, "protocol-denial-v1"},
	{"broker-denied-plaintext-http", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "broker-plaintext-http", smallObservation, "broker-denial-v1"},
	{"broker-denied-connect-port", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "broker-connect-port", smallObservation, "broker-denial-v1"},
	{"broker-denied-socks-operations", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "broker-socks-operations", smallObservation, "broker-denial-v1"},
	{"broker-denial-boundary", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "broker-denial-boundary", largeObservation, "denial-boundary-v1"},
	{"broker-policy-ledger-authority-match", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "broker-final-audit", largeObservation, "broker-audit-v1"},
	{"broker-flood-bounds", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "broker-flood-bounds", largeObservation, "resource-formula-v1"},
	{"broker-loss-prevents-release", conformance.CaseBrokerEgress, conformance.LayerActualHostImmutable, SourceNetworkOrchestrator, "broker-loss-release-trap", smallObservation, "release-trap-v1"},

	// Case 4: mount and secret isolation.
	{"relay-mount-visibility", conformance.CaseMountAndSecretIsolation, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "inspect-relay-mounts", largeObservation, "mounts-v1"},
	{"authority-mount-visibility", conformance.CaseMountAndSecretIsolation, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "inspect-authority-mounts", largeObservation, "mounts-v1"},
	{"controller-sqlite-invisible", conformance.CaseMountAndSecretIsolation, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "probe-controller-database", smallObservation, "absence-v1"},
	{"host-control-invisible", conformance.CaseMountAndSecretIsolation, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "inspect-forbidden-mounts", largeObservation, "mounts-v1"},
	{"runtime-secret-scan", conformance.CaseMountAndSecretIsolation, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "scan-runtime-surfaces", largeObservation, "secret-scan-v1"},
	{"synthetic-token-absence", conformance.CaseMountAndSecretIsolation, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "probe-synthetic-token-absence", largeObservation, "absence-v1"},

	// Case 5: runner sandbox.
	{"runner-read-only-root", conformance.CaseSandbox, conformance.LayerActualHostImmutable, SourceHostRuntimeEngine, "inspect-runner-root", largeObservation, "sandbox-v1"},
	{"runner-resource-limits", conformance.CaseSandbox, conformance.LayerActualHostImmutable, SourceHostRuntimeEngine, "inspect-runner-limits", largeObservation, "limits-v1"},
	{"runner-seccomp-syscall-denials", conformance.CaseSandbox, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "probe-syscall-denials", largeObservation, "syscall-denial-v1"},
	{"runner-proc-mask", conformance.CaseSandbox, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "probe-proc-mask", smallObservation, "mounts-v1"},
	{"runner-forbidden-mounts-devices", conformance.CaseSandbox, conformance.LayerActualHostImmutable, SourceHostRuntimeEngine, "inspect-runner-mounts-devices", largeObservation, "sandbox-v1"},
	{"runner-identity-capabilities", conformance.CaseSandbox, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "probe-runner-identity", smallObservation, "identity-capabilities-v1"},
	{"runner-sizing-tuple-match", conformance.CaseSandbox, conformance.LayerActualHostImmutable, SourceBoundEvidenceLedger, "inspect-runner-sizing", largeObservation, "limits-v1"},

	// Case 6: runner payload.
	{"single-runner-payload", conformance.CaseRunnerPayload, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "inspect-runner-payload", largeObservation, "runner-payload-v1"},
	{"listener-version", conformance.CaseRunnerPayload, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "listener-version", smallObservation, "listener-version-v1"},
	{"no-version-pair", conformance.CaseRunnerPayload, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "inspect-runner-versions", largeObservation, "runner-payload-v1"},
	{"no-file-sweeper", conformance.CaseRunnerPayload, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "inspect-runner-processes", largeObservation, "process-inventory-v1"},
	{"no-baked-jit", conformance.CaseRunnerPayload, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "inspect-runner-secret-absence", largeObservation, "absence-v1"},

	// Cases 7-9: synthetic lifecycle and reclamation.
	{"synthetic-job-completion", conformance.CaseSyntheticOneJob, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "synthetic-job-complete", smallObservation, "synthetic-job-v1"},
	{"synthetic-job-proxy", conformance.CaseSyntheticOneJob, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "synthetic-job-proxy", smallObservation, "synthetic-job-v1"},
	{"synthetic-job-deregistration", conformance.CaseSyntheticOneJob, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "synthetic-job-deregister", smallObservation, "synthetic-job-v1"},
	{"synthetic-job-reclamation", conformance.CaseSyntheticOneJob, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "synthetic-job-reclaim", smallObservation, "synthetic-job-v1"},
	{"cleanup-success", conformance.CaseCleanupMatrix, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "cleanup-success", smallObservation, "cleanup-row-v1"},
	{"cleanup-cancellation", conformance.CaseCleanupMatrix, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "cleanup-cancellation", smallObservation, "cleanup-row-v1"},
	{"cleanup-pre-listener-failure", conformance.CaseCleanupMatrix, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "cleanup-pre-listener-failure", smallObservation, "cleanup-row-v1"},
	{"cleanup-listener-crash", conformance.CaseCleanupMatrix, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "cleanup-listener-crash", smallObservation, "cleanup-row-v1"},
	{"cleanup-controller-restart", conformance.CaseCleanupMatrix, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "cleanup-controller-restart", smallObservation, "cleanup-row-v1"},
	{"cleanup-upgrade-interruption", conformance.CaseCleanupMatrix, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "cleanup-upgrade-interruption", smallObservation, "cleanup-row-v1"},
	{"reclamation-high-water", conformance.CaseReclamationSeries, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "reclamation-high-water", largeObservation, "reclamation-v1"},
	{"reclamation-post-cleanup", conformance.CaseReclamationSeries, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "reclamation-post-cleanup", largeObservation, "reclamation-v1"},
	{"reclamation-version-staging-absence", conformance.CaseReclamationSeries, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "reclamation-version-staging", smallObservation, "absence-v1"},

	// Case 10: actual-host tool compatibility.
	{"workflow-tool-probes", conformance.CaseProxyToolCompatibility, conformance.LayerActualHostImmutable, SourceClosedTestCommand, "workflow-tool-probes", largeObservation, "workflow-tools-v1"},

	// Case 11: synthetic seed isolation.
	{"seed-current-job", conformance.CaseSeedIsolation, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "seed-current-job", smallObservation, "seed-v1"},
	{"seed-next-job", conformance.CaseSeedIsolation, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "seed-next-job", smallObservation, "seed-v1"},
	{"seed-source-immutable", conformance.CaseSeedIsolation, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "seed-source-immutable", smallObservation, "seed-v1"},
	{"seed-workspaces-reclaimed", conformance.CaseSeedIsolation, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "seed-workspaces-reclaimed", smallObservation, "absence-v1"},

	// Cases 12-14: test-local watchdog and fence.
	{"watchdog-portable-restart", conformance.CaseWatchdogRecovery, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "watchdog-portable-restart", largeObservation, "watchdog-v1"},
	{"watchdog-zero-traps", conformance.CaseWatchdogRecovery, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "watchdog-zero-traps", smallObservation, "trap-count-v1"},
	{"legacy-disabled-epoch", conformance.CaseLegacyFenceRecovery, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "legacy-disabled-epoch", largeObservation, "fence-v1"},
	{"legacy-reboot-recovery", conformance.CaseLegacyFenceRecovery, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "legacy-reboot-recovery", largeObservation, "fence-v1"},
	{"legacy-zero-portable-acquisition", conformance.CaseLegacyFenceRecovery, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "legacy-zero-portable-acquisition", smallObservation, "trap-count-v1"},
	{"noncancellable-process-death", conformance.CaseNoncancellableShutdown, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "noncancellable-process-death", smallObservation, "process-identity-v1"},
	{"noncancellable-observer-order", conformance.CaseNoncancellableShutdown, conformance.LayerSyntheticLifecycle, SourceSyntheticLocal, "noncancellable-observer-order", smallObservation, "process-order-v1"},

	// Case 15: actual GitHub canary only.
	{"actual-github-disable-update", conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport, SourceActualGitHubCanary, "actual-disable-update", smallObservation, "actual-github-v1"},
	{"actual-github-jit-absence", conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport, SourceActualGitHubCanary, "actual-jit-absence", largeObservation, "actual-github-v1"},
	{"actual-github-listener", conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport, SourceActualGitHubCanary, "actual-listener-transport", largeObservation, "actual-github-v1"},
	{"actual-github-checkout", conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport, SourceActualGitHubCanary, "actual-checkout", largeObservation, "actual-github-v1"},
	{"actual-github-tools", conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport, SourceActualGitHubCanary, "actual-workflow-tools", largeObservation, "actual-github-v1"},
	{"actual-github-reclamation", conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport, SourceActualGitHubCanary, "actual-reclamation", largeObservation, "actual-github-v1"},
	{"actual-github-binding", conformance.CaseActualGitHubTransport, conformance.LayerActualGitHubTransport, SourceActualGitHubCanary, "actual-binding", smallObservation, "actual-github-v1"},
}

// RequiredObservationMatrix returns a defensive copy of the exact registry.
func RequiredObservationMatrix() []ObservationRequirement {
	return append([]ObservationRequirement(nil), requiredObservationMatrix[:]...)
}

// RequiredObservationIDs returns the exact observation order.
func RequiredObservationIDs() []ObservationID {
	ids := make([]ObservationID, len(requiredObservationMatrix))
	for index, row := range requiredObservationMatrix {
		ids[index] = row.ID
	}
	return ids
}

// ValidateObservationMatrix rejects every missing, reordered, substituted, or
// widened row. The matrix is compiled source authority, not private input.
func ValidateObservationMatrix(rows []ObservationRequirement) error {
	if len(rows) != len(requiredObservationMatrix) {
		return errInvalidObservationMatrix
	}
	for index, expected := range requiredObservationMatrix {
		actual := rows[index]
		if actual != expected ||
			actual.ID == "" ||
			actual.Case == "" ||
			actual.Layer == "" ||
			actual.Source == "" ||
			actual.Operation == "" ||
			actual.Operation == "exec" ||
			actual.MaxBytes == 0 ||
			actual.Parser == "" {
			return errInvalidObservationMatrix
		}
		layer, ok := conformance.RequiredLayer(actual.Case)
		if !ok || layer != actual.Layer {
			return errInvalidObservationMatrix
		}
		switch actual.Layer {
		case conformance.LayerActualHostImmutable:
			if actual.Source == SourceSyntheticLocal ||
				actual.Source == SourceActualGitHubCanary {
				return errInvalidObservationMatrix
			}
		case conformance.LayerSyntheticLifecycle:
			if actual.Source != SourceSyntheticLocal {
				return errInvalidObservationMatrix
			}
		case conformance.LayerActualGitHubTransport:
			if actual.Case != conformance.CaseActualGitHubTransport ||
				actual.Source != SourceActualGitHubCanary {
				return errInvalidObservationMatrix
			}
		default:
			return errInvalidObservationMatrix
		}
	}
	return nil
}
