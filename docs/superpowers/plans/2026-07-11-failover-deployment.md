# Portable GHAR Failover Deployment Implementation Plan

<!-- markdownlint-disable MD013 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and safely deploy Portable GHAR's external failover authority, prove hosted fallback and epoch-bound recovery, and retire the legacy watcher only after a 14-day soak and rehearsed rollback while retaining encrypted rollback artifacts for 30 days.

**Architecture:** A versioned outbound heartbeat protocol terminates at a Cloudflare Worker, which authenticates each request and routes a fleet to exactly one deterministic SQLite-backed Durable Object. The object owns enrollment epochs, anti-replay state, hysteresis, transition locks, GitHub mutation intent, canary identity, notification outboxes, and bounded audit evidence; every external mutation is read back before confirmation. Deployment identities and secrets live only in a mode-restricted private overlay, while the public repository contains strict schemas, synthetic examples, tested ports, and safe-state runbooks.

**Tech Stack:** Go controller client (`crypto/hmac`, `crypto/rand`, `net/http`), TypeScript Cloudflare Worker, SQLite Durable Objects, Workers Vitest integration, one-minute Worker cron, Cloudflare Email Service `send_email` binding, GitHub App installation tokens and REST API, generic HTTPS webhook with HMAC-SHA256, JSON Schema, shell/Bats operational checks, GitHub-hosted CI.

## Global Constraints

- Implement against `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`; any conflict stops execution and returns to design review.
- The Worker and one deterministic SQLite Durable Object per fleet are the sole automatic routing authority. The controller and watchdog never mutate repository routing.
- There is no inbound route to the Docker host. Enrollment and heartbeat traffic is outbound HTTPS only.
- The Durable Object owns and increments the epoch. A controller boot creates a random session ID, begins at sequence `1`, and re-enrolls after local state loss.
- Authenticate method, path, bounded client timestamp, and exact request body with HMAC-SHA256. Challenge and admin requests contain random single-use nonces whose digests are consumed transactionally. Workers use `crypto.subtle.verify`; Go uses `hmac.Equal`. Ordinary string/byte equality is prohibited for MAC verification.
- Worker receipt time, never client time, controls freshness.
- Evaluate every fleet once per minute. The stale default is six minutes; failover requires two consecutive unhealthy evaluations unless an authenticated fatal state makes it immediately eligible.
- Persist transition intent and one claimed outbox row per repository variable before each GitHub mutation. Hosted/bootstrap reconciliation creates exactly one row for each of route, scale-set, and legacy-label; local-route transitions create a route row only after separate companion read-back. Confirm each variable and repository independently; timeout, rate limit, partial success, and ambiguity remain unconfirmed until reconciled.
- GitHub API unavailability preserves desired state and the last confirmed route; it never becomes a successful failover claim.
- `hosted` is always the safe route. A missing, failed, late, or superseded canary cannot fail back.
- Bootstrap must create and read back `PORTABLE_GHAR_ROUTE=hosted` for every repository before recovery observations or any canary; it can never transition directly from `BOOTSTRAP` to healthy self-hosted.
- Every candidate job must use the exact three-state consumer expression from the platform design: missing/empty/unknown route selects `ubuntu-latest`; `self-hosted` resolves to one validated scalar scale-set name; `legacy` resolves to one validated scalar label unique to the captured legacy registrations and is available only through authenticated governed rollback. Deleting the route variable never restores legacy.
- The Worker owns `PORTABLE_GHAR_ROUTE`, `PORTABLE_GHAR_SCALE_SET`, and `PORTABLE_GHAR_LEGACY_LABEL`. Private configuration binds both companion names and their exact expected scalar values. While hosted, bootstrap/reconciliation persists and reads them back; every canary, local transition, and route proof repeats exact read-back, and cron performs a bounded integrity sweep at least every five minutes. Missing, invalid, drifted, inaccessible, or non-unique companion state persists a hosted transition.
- Hosted confirmation binds route read-back to the current default-branch head, configured workflow path/blob/content digest, exact job IDs/required-check names, and a fixed route-attestation step. Before legacy suspension, positively observe a secretless bound candidate at that exact head with `runner.environment=github-hosted` and successful attestation; variable read-back alone is insufficient.
- An authenticated Worker-owned hosted hold is the only supported maintenance, upgrade, and retirement freeze. Enabling it persists hosted transition intent, blocks recovery, and requires per-repository read-back; releasing it starts a new recovery epoch and still requires a current-epoch canary. A direct transition-variable write is limited to initial bootstrap and the one-time all-candidate hosted transition before normal Worker authority; governed recovery and legacy rollback remain Worker-owned and never treat a direct write as a durable hold.
- Repository archival is a per-repository eligibility change, not a fleet failover. The bounded five-minute integrity sweep reads each repository's live `archived` state alongside its routing variables; observing `archived=true` latches that repository's `eligibility_state` to `archived-disabled`, revokes its acquisition permits and any legacy lease through the normal revoke-and-drain sequence, blocks new permit issuance for it, and leaves it routed hosted. This per-repository disable inserts NO fleet-wide queue-risk row and never blocks acquisition for other repositories. An already running job drains normally. The latch is durable: a later live `archived=false` does not clear it. Reactivation is the operator path `archived-disabled` → `pending-reactivation` → `active`, requiring an operator-approved configuration revision, a fresh eligibility audit, hosted bootstrap and read-back, per-repository queue-risk clearance, and a current-epoch canary. A stale private overlay that still lists an archived repository as active never re-enables it. Against an archived repository GitHub accepts variable writes and workflow dispatches but runs nothing — a write succeeds silently and a dispatch stays `queued` with no job ever assigned (empirically confirmed) — so cleanup and disablement must never depend on a write or dispatch being rejected, and must treat a queued-forever dispatch as inert, never as progress. The disable is enforced entirely by the Worker's live-`archived` read and permit-gate refusal, not by any GitHub rejection.
- Per-repository effective-concurrency maxima and declared eligibility are admission-policy inputs, not routing inputs. The Worker holds them in `FleetConfig`/`RepositoryConfig` solely so it can recompute the expected acquisition-policy digest (which covers them) and know the policy the controller must enforce; it never routes on them and they are not part of the three-variable routing contract. The live archive latch (`eligibility_state`) is a separate Durable Object state applied as a permit-gate refusal at issuance, on top of the config-declared eligibility, and does not itself alter the acquisition-policy digest.
- Routing-variable changes affect newly evaluated jobs only. Never claim that a pre-transition local-queue job migrated, and never automatically cancel/rerun it; persist one transition/repository-scoped queue-risk row until an authenticated same-epoch selective GitHub read-back and operator recovery clears it idempotently. Never migrate, cancel, or duplicate an already assigned hosted job merely because a later job routes self-hosted.
- Queue-risk rows are created only by a hosted transition that changes a
  repository's effective route away from `self-hosted` (an actual failover);
  releasing a hold, an already-hosted recovery, and a per-repository archive
  disable create none. Any open queue-risk row from the latest failover is a
  hard zero-acquisition gate: Portable must remain `disabled`—not
  `canary-only`—and legacy runners/listeners remain stopped until every
  `active`-eligibility repository in that failover clears. Archived-disabled
  repositories are not in the clear set and cannot wedge it. A new failover
  transition invalidates earlier clear evidence.
- A status read and local acquisition-mode command are never acquisition
  authority. Every Portable poll/acquire/JIT call requires a fresh persisted
  Worker permit obtained inside the controller's local policy-epoch barrier;
  a legacy compatibility process requires a short renewable Worker lease.
  Before a hosted transition, the Durable Object revokes the permit generation,
  stops issuance/renewal, and waits for every prior permit/lease to close or
  expire plus the forced-termination margin before it creates hosted intent or
  queue-risk rows; for a governed legacy rollback or an administrative
  hold/upgrade drain it additionally waits for a fresh heartbeat reporting zero
  un-assigned released listeners under the current generation, but a staleness-
  or fatal-triggered failover does not wait for one, since the host may be down
  and cannot send it.
- A canary is bound to the active transition epoch and exact expected revision. Failure requires a new operator recovery epoch; no automatic bypass exists.
- A canary workflow uses exactly one scalar GitHub.com scale-set name in `runs-on`; arrays and `[self-hosted, label]` syntax are prohibited.
- Email and webhook are independent persisted outboxes. Notification failure never blocks or reverses routing.
- Use a native Cloudflare Email Service binding restricted to configured sender and destination addresses. The only public secondary adapter is a generic HTTPS webhook signed over timestamp, event ID, and exact body; recipients enforce timestamp skew, replay rejection, and event-ID deduplication.
- Private deployment completion requires observed end-to-end Signal receipt through a webhook bridge on a failure domain separate from the QTS runner host. HTTP `2xx` alone is not delivery proof, and neither the Worker nor bridge may add an inbound endpoint to the runner host.
- The Signal receipt key is distinct from the webhook-delivery key, absent from the Worker and QTS host, and readable only by the separate-domain bridge plus private evidence verifier. Key loss, rotation ambiguity, or compromise invalidates Signal evidence and restarts the soak; it cannot change routing state.
- Keep controller and failover GitHub Apps separate. The failover App has repository-variable read/write, Metadata read, Contents read only for configured workflow-blob binding, Actions read for all route-proof/canary observation, and Actions write only for automatic dispatch. It has no Contents write, Pull requests, Administration, Issues, Deployments, Secrets, or broader access.
- GitHub REST requests use `X-GitHub-Api-Version: 2026-03-10`.
- Pin Worker tooling exactly to TypeScript `6.0.3`, Vitest `4.1.10`, `@cloudflare/vitest-pool-workers` `0.18.4`, `@cloudflare/workers-types` `5.20260708.1` with registry integrity `sha512-FSRyCsxALKmmNnk/2HMkTiX9Iz9yqTiTWX/BJZdffGznMSunXmQgb3mKy9wGBX2BCTLOuRYWL36uh7/3Gm05Eg==`, Wrangler `4.110.0`, ESLint `10.7.0`, `@eslint/js` `10.0.1`, and `typescript-eslint` `8.63.0`; ranges, peer-range violations, and floating versions are prohibited. Lock verification must prove the Workers types date matches pinned workerd `1.20260708.1` and Miniflare `4.20260708.1`.
- Public files use only synthetic values such as `example-fleet`, `owner/repository`, and `operator@example.invalid`. Never include real identifiers, routes, addresses, paths, request bodies, signatures, keys, tokens, or secret-bearing command output.
- The private overlay is outside the repository, broadly ignored, directory mode `0700`, file mode `0600`, strict-schema validated, and contains secret references rather than inline values.
- Never add an active self-hosted workflow under this public repository's `.github/workflows/`. The secretless canary remains a non-active template copied into a private consumer repository.
- Public CI remains GitHub-hosted, secretless, least-privilege, SHA-pinned, timeout-bounded, and uses `pull_request`, never `pull_request_target` with fork code.
- Worker binding types are generated by `wrangler types`; `nodejs_compat` and sanitized observability are explicit; request state is never module-global; every promise is awaited/returned/waitUntil-tracked; no `passThroughOnException`, manual `Env`, `any`, double-cast, or secret-bearing log is allowed.
- Migration starts from a fresh capture of the live legacy deployment. A stale public or local copy is not rollback evidence.
- New and legacy fleets must never acquire work concurrently. One continuously held generation fence is shared by the new controller/watchdog and every restored legacy wrapper, including during watchdog races and rollback.
- Every controller mode/eligibility/effective-capacity transition uses the bounded acquisition-policy epoch barrier. Canary-only is one exact persisted scale set at capacity one; watchdog/probe stops, host-pressure reductions, suspend, and observer startup cannot bypass it. An upstream call that ignores cancellation makes the controller fatal/zero-capacity and process-terminating, which the Worker treats as immediate failover-eligible health.
- Collect evidence for 14 consecutive 24-hour UTC windows; any unexplained safety or evidence gap restarts the soak clock.
- Retain verified encrypted rollback artifacts for 30 full days after retirement; deletion before `retention_until` is a hard failure.
- Do not update README wording from “implementation not started” or equivalent to an operational claim until live deployment and final positive verification succeed. Then record only public, evidence-backed truth without deployment identity.
- Once the design-finalization review gate has passed, the operator's standing authorization covers the implementation, deployment, rollback-drill, and retirement go/no-go for this scope without a redundant per-step approval round-trip. That authorization is procedural: it does not waive the fresh distinct-family design review gate, any executable design probe, or any verification gate in this plan. Stop on target/account mismatch, new scope, architecture ambiguity, or failed gate.
- Every task uses red-green-refactor, runs narrow then affected suites, stages only the exact paths named in that task's Files block (repository-wide staging is prohibited), and ends in a signed scoped commit.

---

## Execution Preconditions and Stop Conditions

1. Begin after repository foundation, controller core, and isolation-runtime phases merge and stable CI check names are recorded.
2. Existing operator authorization covers the in-scope live steps; positively verify target/account from the private overlay immediately before mutation and stop on any mismatch.
3. Stop if the controller cannot produce every allowlisted heartbeat field without job-controlled data.
4. Stop if the pinned scale-set adapter cannot expose a unique canary label while normal acquisition stays disabled.
5. Stop if routing is not an independently readable/writable repository variable, if the email binding cannot restrict sender and destination, or if a legacy writer can mutate the new transition variable.
6. Stop if the live legacy state cannot be captured/restored, the shared generation fence cannot be used by both generations and their watchdogs, or mutual exclusion cannot be continuously proved.
7. Stop and return for authorization if execution discovers new scope beyond this plan.

## Locked Protocol and Interfaces

Public enrollment/health endpoints are `POST /v1/enrollment/challenge`, `POST /v1/enrollment/complete`, and `POST /v1/heartbeat`. Outbound controller authority endpoints are `POST /v1/acquisition/permit`, `POST /v1/acquisition/close`, and `POST /v1/acquisition/legacy-lease`; they use the enrolled fleet key/session and an independent strict control sequence. Disabled-by-default administrative endpoints are `POST /v1/admin/recovery`, `POST /v1/admin/legacy-recovery`, `POST /v1/admin/queue-recovery`, `POST /v1/admin/hosted-hold`, and `POST /v1/admin/status`; they use the separate administrative HMAC key, the same timestamp/nonce anti-replay rules, and generic rejection responses. Requests use `Content-Type: application/json`, `X-Portable-GHAR-Key-Id`, `X-Portable-GHAR-Timestamp: <unix-seconds>`, and `X-Portable-GHAR-Signature: v1=<base64url-mac>`. Permit/lease responses are MACed over a domain-separated response frame that excludes the `responseMac` field itself: the signed bytes are `portable-ghar-response-v1\n`, then `<protocol>\n`, then the response object serialized with its interface-declared field order, no insignificant whitespace, and the `responseMac` field omitted entirely. The verifier reconstructs the identical frame with `responseMac` removed and compares in constant time. Signed request bytes are:

```text
portable-ghar-request-v1\n
<UPPERCASE_METHOD>\n
<PATH_ONLY>\n
<UNIX_SECONDS>\n
<EXACT_UTF8_BODY>
```

Challenge bodies include a random 32-byte base64url `requestNonce`; the Worker accepts timestamps within 300 seconds, verifies HMAC before Durable Object access, stores only the nonce digest, and atomically rejects reuse. Enrollment completion consumes its random server challenge exactly once. All administrative bodies include a random nonce, use a separate HMAC key, enforce the same 300-second skew, and atomically reject nonce reuse. Invalid/replayed requests return `404 {"error":"request_rejected"}`. An authenticated stale heartbeat sequence returns `409 {"error":"re_enrollment_required"}` without epoch/sequence details. `PORTABLE_GHAR_ROUTE` has exactly `hosted`, `self-hosted`, and governed `legacy`; bootstrap creates it as hosted and reads it back before canary work, while missing/unknown workflow values remain hosted.

```typescript
export interface HeartbeatV1 {
  protocol: "portable-ghar.heartbeat.v1";
  fleetId: string; epoch: number; sessionId: string; sequence: number;
  clientObservedAt: string; // diagnostic only
  activeFleet: "portable" | "legacy" | "none"; fleetGeneration: number;
  acquisitionState: "disabled" | "canary-only" | "enabled" | "fatal";
  acquisitionEpoch: number; acquisitionPolicyDigest: string;
  repositoryPolicyRevision: number;
  capacity: { availableUnits: number; totalUnits: number };
  assignedJobs: number; unassignedReleasedListeners: number;
  oldestAssignmentAgeSeconds: number | null;
  lastTerminalJobAt: string | null; hostProfileId: string;
  degradedProfile: boolean; controllerBuildId: string;
  fatalReasonCode?: "compatibility_failed" | "host_profile_failed" |
    "legacy_probe_failed" | "state_ambiguous";
}

export interface ChallengeRequestV1 {
  protocol: "portable-ghar.enrollment.challenge.v1";
  fleetId: string; requestNonce: string;
}

export interface EnrollmentCompleteRequestV1 {
  protocol: "portable-ghar.enrollment.complete.v1";
  fleetId: string; requestNonce: string;
  challenge: string; sessionId: string;
}

export interface AcquisitionPermitRequestV1 {
  protocol: "portable-ghar.acquisition.permit.v1";
  fleetId: string; epoch: number; sessionId: string; controlSequence: number;
  operationId: string; // fresh cryptographically random >=128-bit id per operation
  operationKind: "poll" | "acquire" | "jit";
  repositoryAlias: string; scaleSetName: string;
  policyEpoch: number; policyDigest: string; repositoryPolicyRevision: number;
}

export interface AcquisitionPermitV1 {
  protocol: "portable-ghar.acquisition.permit-response.v1";
  permitId: string; operationId: string; operationKind: "poll" | "acquire" | "jit";
  epoch: number; sessionId: string;
  repositoryAlias: string; scaleSetName: string; policyEpoch: number;
  policyDigest: string; repositoryPolicyRevision: number;
  transitionEpoch: number; permitGeneration: number;
  expiresAtServerMs: number; responseMac: string;
}

export interface AcquisitionPermitCloseRequestV1 {
  protocol: "portable-ghar.acquisition.close.v1";
  fleetId: string; epoch: number; sessionId: string; controlSequence: number;
  permitId: string; operationId: string;
}

export interface LegacyProcessLeaseRequestV1 {
  protocol: "portable-ghar.acquisition.legacy-lease.v1";
  fleetId: string; epoch: number; sessionId: string; controlSequence: number;
  leaseId: string | null; repositoryAlias: string; expectedLegacyLabel: string;
  fenceGeneration: number; configDigest: string;
}

export interface AdminRecoveryRequestV1 {
  protocol: "portable-ghar.admin.recovery.v1";
  fleetId: string; requestNonce: string; reasonCode: string;
}

export interface AdminLegacyRecoveryRequestV1 {
  protocol: "portable-ghar.admin.legacy-recovery.v1";
  fleetId: string; requestNonce: string; reasonCode: string;
  expectedFenceGeneration: number; evidenceDigest: string;
}

export interface AdminQueueRecoveryRequestV1 {
  protocol: "portable-ghar.admin.queue-recovery.v1";
  fleetId: string; requestNonce: string;
  transitionEpoch: number; repositoryAlias: string;
  evidenceDigest: string;
}

export interface AdminHostedHoldRequestV1 {
  protocol: "portable-ghar.admin.hosted-hold.v1";
  fleetId: string; requestNonce: string;
  action: "enable" | "disable"; reasonCode: string;
}

export interface AdminStatusRequestV1 {
  protocol: "portable-ghar.admin.status.v1";
  fleetId: string; requestNonce: string;
}

export interface WorkflowBinding {
  path: string; blobSha: string; contentSha256: string;
  jobId: string; requiredCheckName: string;
  routeAttestationStep: "portable-ghar-route-attestation";
}

export interface RepositoryConfig {
  alias: string; owner: string; repository: string;
  installationIdRef: string; notificationAlias: string;
  scaleSetVariable: "PORTABLE_GHAR_SCALE_SET";
  expectedScaleSetName: string;
  legacyLabelVariable: "PORTABLE_GHAR_LEGACY_LABEL";
  expectedLegacyLabel: string;
  // admission-policy inputs held only to recompute the expected
  // acquisition-policy digest; never used for routing:
  maxConcurrency: number;
  declaredEligibility: "active" | "archived-disabled" | "pending-reactivation";
  workflows: WorkflowBinding[];
}

export interface RoutingVariables {
  route: "hosted" | "self-hosted" | "legacy" | "missing";
  scaleSetName: string | null;
  legacyLabel: string | null;
}

export interface WorkflowBindingResult {
  defaultBranch: string; headSha: string; matched: boolean;
  verifiedWorkflowCount: number; verifiedJobCount: number;
}

export interface RouteProofIdentity {
  repositoryAlias: string; headSha: string; workflow: string;
  jobId: string; expectedRoute: "hosted" | "self-hosted" | "legacy";
}

export interface RouteProofRun extends RouteProofIdentity {
  runId: number; runnerEnvironment: "github-hosted" | "self-hosted";
  attestationConclusion: "success" | "failure" | null;
  conclusion: "success" | "failure" | "cancelled" | null;
}

export interface CanaryIdentity {
  transitionEpoch: number; expectedRevision: string;
  repositoryAlias: string; workflow: string;
}

export interface CanaryPolicy {
  mode: "automatic" | "manual";
  expectedRevision: string; repositoryAlias: string; workflow: string;
}

export interface CanaryDispatch extends CanaryIdentity { ref: string }
export interface CanaryRun extends CanaryIdentity {
  runId: number; headSha: string;
  status: "queued" | "in_progress" | "completed";
  conclusion: "success" | "failure" | "cancelled" | null;
}

export interface LegacyCanaryIdentity {
  transitionEpoch: number; repositoryAlias: string; workflow: string;
  expectedRevision: string; expectedLegacyLabel: string;
  expectedFenceGeneration: number; evidenceDigest: string; headSha: string;
}

export interface LegacyCanaryRun extends LegacyCanaryIdentity {
  runId: number;
  runnerEnvironment: "self-hosted";
  attestationConclusion: "success" | "failure" | null;
  conclusion: "success" | "failure" | "cancelled" | null;
}

export interface FleetConfig {
  fleetId: string; keyId: string;
  configRevision: number; configDigest: string;
  challengeTtlSeconds: number;
  staleAfterSeconds: number; unhealthyEvaluations: number;
  recoveryHealthyEvaluations: number;
  acquisitionPermitTtlSeconds: number;
  acquisitionPermitDrainMarginSeconds: number;
  transitionVariable: "PORTABLE_GHAR_ROUTE";
  expectedEnabledPolicyDigest: string;
  expectedCanaryPolicyDigest: string;
  expectedEnabledCapacityUnits: number;
  repositoryPolicyRevision: number;
  canary: CanaryPolicy;
  legacyRecoveryCanary: CanaryPolicy;
  repositories: RepositoryConfig[];
  notifications: { email: true; webhook: boolean };
}

export interface EvaluationResult {
  state: "BOOTSTRAP" | "HEALTHY_SELF_HOSTED" | "SUSPECT" |
    "FAILOVER_PENDING" | "HOSTED_CONFIRMED" | "QUEUE_RISK_CLEARED" |
    "RECOVERY_OBSERVED" |
    "CANARY_PENDING" | "CANARY_PASSED" |
    "ACQUISITION_ENABLED_CONFIRMED" | "SELF_HOSTED_CONFIRMED" |
    "LEGACY_RECOVERY_PENDING" | "LEGACY_CANARY_PREPARED" | "LEGACY_CONFIRMED";
  route: "hosted" | "self-hosted" | "legacy";
  transitionEpoch: number; workQueued: boolean;
}

export interface AdministrativeStatus {
  state: EvaluationResult["state"];
  route: "hosted" | "self-hosted" | "legacy";
  configRevision: number; configDigest: string;
  transitionEpoch: number; enrollmentEpoch: number; lastSequence: number;
  heartbeatFresh: boolean;
  activeFleet: "portable" | "legacy" | "unobserved";
  fleetGeneration: number | null;
  acquisitionState: HeartbeatV1["acquisitionState"] | "unobserved";
  acquisitionEpoch: number | null;
  acquisitionPolicyDigest: string | null;
  hostedHold: boolean;
  currentEpochCanaryPassed: boolean;
  acquisitionEnabledConfirmed: boolean;
  repositoryCount: number; repositoriesConfirmed: boolean;
  outboxesCurrent: boolean; preTransitionQueueMayRemain: boolean;
  queueRiskCount: number; queueRiskCleared: boolean;
}

export interface FleetCoordinator {
  claimRequestNonce(input: { digest: string; purpose: "challenge" | "admin-recovery" | "admin-legacy-recovery" | "admin-queue-recovery" | "admin-hosted-hold" | "admin-status"; seenAtMs: number; expiresAtMs: number }): Promise<{ accepted: true }>;
  issueChallenge(input: { challengeDigest: string; requestNonceDigest: string; issuedAtMs: number; expiresAtMs: number }): Promise<void>;
  completeEnrollment(input: { challengeDigest: string; requestNonceDigest: string; sessionId: string; nowMs: number }): Promise<{ epoch: number; sessionId: string }>;
  acceptHeartbeat(input: { heartbeat: HeartbeatV1; receivedAtMs: number }): Promise<{ accepted: true }>;
  issueAcquisitionPermit(input: { request: AcquisitionPermitRequestV1; receivedAtMs: number; config: FleetConfig }): Promise<AcquisitionPermitV1>;
  closeAcquisitionPermit(input: { request: AcquisitionPermitCloseRequestV1; receivedAtMs: number }): Promise<{ closed: true }>;
  renewLegacyProcessLease(input: { request: LegacyProcessLeaseRequestV1; receivedAtMs: number; config: FleetConfig }): Promise<{ leaseId: string; transitionEpoch: number; permitGeneration: number; expiresAtServerMs: number; responseMac: string }>;
  reconcileConfiguration(input: { config: FleetConfig; nowMs: number }): Promise<{ configRevision: number; configDigest: string; repositoriesConfirmed: boolean }>;
  evaluate(input: { nowMs: number; config: FleetConfig }): Promise<EvaluationResult>;
  processDueWork(input: { nowMs: number; config: FleetConfig; maxItems: number }): Promise<{ processed: number; nextDueAtMs: number | null }>;
  startRecoveryEpoch(input: { reasonCode: string; nowMs: number }): Promise<{ transitionEpoch: number }>;
  startLegacyRecovery(input: { reasonCode: string; evidenceDigest: string; expectedFenceGeneration: number; nowMs: number }): Promise<{ transitionEpoch: number }>;
  clearQueueRisk(input: { transitionEpoch: number; repositoryAlias: string; evidenceDigest: string; nowMs: number; config: FleetConfig }): Promise<{ cleared: true; remaining: number }>;
  setHostedHold(input: { enabled: boolean; reasonCode: string; nowMs: number }): Promise<{ transitionEpoch: number }>;
  administrativeStatus(input: { nowMs: number; config: FleetConfig }): Promise<AdministrativeStatus>;
}

export interface GitHubPort {
  readRoutingVariables(repository: RepositoryConfig): Promise<RoutingVariables>;
  readRepositoryArchiveState(repository: RepositoryConfig): Promise<{ archived: boolean }>;
  writeRoutingVariable(input: { repository: RepositoryConfig; variableName: "PORTABLE_GHAR_ROUTE" | "PORTABLE_GHAR_SCALE_SET" | "PORTABLE_GHAR_LEGACY_LABEL"; desiredValue: string }): Promise<void>;
  verifyWorkflowBinding(repository: RepositoryConfig): Promise<WorkflowBindingResult>;
  findRouteProof(input: RouteProofIdentity): Promise<RouteProofRun | null>;
  dispatchCanary(input: CanaryDispatch): Promise<void>;
  findCanary(input: CanaryIdentity): Promise<CanaryRun | null>;
  dispatchLegacyCanary(input: LegacyCanaryIdentity): Promise<void>;
  findLegacyCanary(input: LegacyCanaryIdentity): Promise<LegacyCanaryRun | null>;
  verifyQueueRecovery(input: { transitionEpoch: number; repository: RepositoryConfig; evidenceDigest: string }): Promise<{ sourceHeadSha: string; evidenceDigest: string }>;
}
```

`expectedScaleSetName` and `expectedLegacyLabel` must each match
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`; they must differ, and the legacy label must
be unique to the captured fenced registrations. `expectedEnabledPolicyDigest`
and `expectedCanaryPolicyDigest` use the platform design's exact
`portable-ghar-acquisition-policy-v1` UTF-8/LF, byte-sorted-name, base-10
framing (including the repository-policy revision and the per-repository
maxima/eligibility section): the enabled digest over mode `enabled` with
`expectedEnabledCapacityUnits`, the canary digest over mode `canary-only` with
the single canary scale set and capacity one. The Worker recomputes the expected
digest for the issuance mode from its own authoritative configuration and never
echoes the client's. Neither raw selector is returned by administrative status
or written to logs. Heartbeat and configured policy
digests are exactly 64 lowercase hexadecimal SHA-256 characters. `configDigest`
is SHA-256 over a canonical serialization of `FleetConfig` with the
`configDigest` field itself omitted: the domain prefix
`portable-ghar-fleet-config-v1\n` followed by every remaining field in
interface-declared order, nested objects and arrays emitted in that same
declared order, strings as exact UTF-8, numbers as base-10, booleans as
`true`/`false`, and `\n` between top-level fields. Equivalent configurations
therefore hash identically, and any covered change — repository set, workflow
binding, expected companions, per-repository maxima or eligibility, or
thresholds — changes the digest.

`Env` is generated by `wrangler types`, never hand-written. The rendered configuration must generate exact bindings/vars for `FLEETS`, `EMAIL`, `FLEET_CONFIG_JSON`, `HEARTBEAT_HMAC_KEYS_JSON`, `FAILOVER_GITHUB_APP_ID`, `FAILOVER_GITHUB_PRIVATE_KEY`, optional `WEBHOOK_HMAC_KEY`, `ADMIN_RECOVERY_ENABLED`, and optional `ADMIN_SERVICE_HMAC_KEY`. Secret-bearing entries are installed as Worker secrets rather than plain `vars`; tests compare the generated declaration to the rendered schema.

The public webhook contract signs `<unix-seconds>.<eventId>.<exactBody>`. A conforming recipient must verify the MAC in constant time, reject timestamps outside 300 seconds, atomically claim the event ID/replay digest before side effects, retain that claim for at least the sender retry horizon, and return the same success response for a duplicate already accepted event without delivering it twice. After destination acknowledgment, the separate-domain bridge emits a delivery receipt signed with a different private receipt key over `<unix-seconds>.<eventId>.<exactReceiptBody>`; the strict body is `{eventId,channel:"signal",deliveredAt,destinationAckDigest,failureDomainClass,runnerHost:false}`. Public code defines and verifies this generic receipt contract but does not implement Signal transport or contain destination identity.

## Persistent State Contract

`worker/src/fleet/schema.ts` creates these tables in the SQLite-backed object. Schema initialization is idempotent, and all enum values are checked in application code before writes.

```sql
fleet_state(
  singleton PRIMARY KEY, active_epoch, active_session_id,
  last_heartbeat_sequence, last_control_sequence,
  last_heartbeat_received_at_ms, last_heartbeat_json, health_state,
  route_state, hosted_hold, hosted_hold_reason_code,
  consecutive_unhealthy, consecutive_healthy,
  transition_epoch, transition_lock, recovery_blocked,
  permit_generation, permit_mode,
  acquisition_enabled_epoch, acquisition_enabled_sequence,
  config_revision, config_digest, canary_config_json, last_evaluated_at_ms
)
challenges(
  challenge_digest PRIMARY KEY, request_nonce_digest UNIQUE,
  issued_at_ms, expires_at_ms, consumed_at_ms
)
request_nonces(
  nonce_digest PRIMARY KEY, purpose, seen_at_ms, expires_at_ms,
  CHECK(purpose IN ('challenge', 'admin-recovery', 'admin-legacy-recovery',
    'admin-queue-recovery', 'admin-hosted-hold', 'admin-status'))
)
repositories(
  alias PRIMARY KEY, owner, repository, installation_id_ref, variable_name,
  scale_set_variable, expected_scale_set_name, confirmed_scale_set_name,
  legacy_label_variable, expected_legacy_label, confirmed_legacy_label,
  desired_route, confirmed_route, confirmed_at_ms,
  config_revision, onboarding_state,
  eligibility_state, archived_observed, archived_observed_at_ms,
  CHECK(eligibility_state IN ('active','archived-disabled','pending-reactivation')),
  UNIQUE(owner, repository)
)
transitions(
  event_id PRIMARY KEY, transition_epoch UNIQUE, kind, reason_code,
  status, created_at_ms, completed_at_ms
)
github_outbox(
  id PRIMARY KEY, event_id, transition_epoch, repository_alias,
  variable_kind, variable_name, desired_value,
  request_fingerprint, status, claim_id, claim_expires_at_ms,
  attempt_count, next_attempt_at_ms,
  last_http_status, last_error_code, created_at_ms, updated_at_ms,
  CHECK(variable_kind IN ('route', 'scale-set', 'legacy-label')),
  UNIQUE(transition_epoch, repository_alias, variable_name, desired_value)
)
canaries(
  id PRIMARY KEY, transition_epoch, kind, event_id, repository_alias, workflow,
  expected_revision, expected_legacy_label, expected_head_sha,
  expected_fence_generation,
  evidence_digest, github_run_id, runner_environment,
  attestation_conclusion, conclusion, status, claim_id, claim_expires_at_ms,
  next_check_at_ms, dispatched_at_ms, completed_at_ms,
  CHECK(kind IN ('portable', 'legacy-recovery')),
  UNIQUE(transition_epoch, kind)
)
queue_risk(
  transition_epoch, repository_alias, source_head_sha_nullable, status,
  evidence_digest, created_at_ms, cleared_at_ms,
  PRIMARY KEY(transition_epoch, repository_alias),
  CHECK(status IN ('open', 'cleared'))
)
acquisition_permits(
  permit_id PRIMARY KEY, operation_id UNIQUE, kind, repository_alias,
  scale_set_name, policy_epoch, policy_digest, transition_epoch,
  permit_generation, enrollment_epoch, session_id,
  issued_at_ms, expires_at_ms, closed_at_ms, status,
  CHECK(kind IN ('poll', 'acquire', 'jit', 'legacy-process')),
  CHECK(status IN ('live', 'closed', 'expired', 'revoked'))
)
notification_outbox(
  id PRIMARY KEY, event_id, channel, payload_json, status,
  claim_id, claim_expires_at_ms, attempt_count,
  next_attempt_at_ms, last_error_code, created_at_ms, updated_at_ms,
  UNIQUE(event_id, channel)
)
audit_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id, event_type,
             reason_code, occurred_at_ms, details_json)
```

Challenge issuance and every administrative request first use one atomic storage transaction to reject an existing nonce digest and insert the new digest with its bounded expiry. Enrollment rotation uses a separate atomic transaction: require one live unconsumed challenge digest bound to the supplied initiating request-nonce digest, mark it consumed, increment `active_epoch`, replace `active_session_id`, reset both `last_heartbeat_sequence` and `last_control_sequence` to `0`, clear prior heartbeat freshness, revoke the prior session's permits/lease, and append a sanitized audit event. Configuration reconciliation is transactional: require `configRevision == previous+1` and a canonical SHA-256 `configDigest`; the same revision with a different digest fails. Add new repositories only while a hosted hold is active; insert them unconfirmed-hosted, persist exact expected scale-set/legacy-label values, and queue one Worker-owned outbox row for each hosted companion and route mutation/read-back; persist the exact canary repository/workflow/revision; reject identity mutation, removal, revision skip/rollback, or digest mismatch outside explicit retirement.

A hosted transition is deliberately two-phase. Its first atomic transaction
locks the transition, increments `permit_generation`, changes `permit_mode` to
`revoking`, and schedules a drain row; no later permit/legacy-lease issue or
renewal can succeed. Bounded due work waits until every earlier live permit is
closed or server-expired plus `acquisitionPermitDrainMarginSeconds`; Portable
operation deadlines and legacy wrapper termination deadlines must end within
that margin. Only then does one final atomic transaction increment
`transition_epoch`, insert the hosted transition, set desired routes, create
exactly one GitHub outbox row per variable requiring mutation (three per
repository for hosted/bootstrap), and insert independent email/webhook rows. It
inserts one open queue-risk row (using the last verified source head or explicit
unknown) ONLY for a repository whose effective route this transition actually
changes away from `self-hosted` — a real failover. Bootstrap (already hosted), a
hold release, an already-hosted recovery, and a per-repository archive disable
change no route away from `self-hosted` and insert none, so those paths cannot
wedge the fleet acquisition gate. The state cannot claim `HOSTED_CONFIRMED` or
the hard zero-acquisition gate before this drain transaction completes. A
non-hosted transition uses the same final transaction after its state-specific
permit gate. Enabling a hosted hold starts this revoke/drain sequence and blocks
recovery; it inserts queue-risk rows only for repositories it actually moves
from `self-hosted` to hosted, and none for repositories already hosted.
Disabling it clears the hold, increments the recovery epoch, and remains hosted
through canary and acquisition-enabled confirmation. No network/external promise
occurs inside these transactions; only methods bound to the same storage
transaction may be awaited.

Queue-risk clearing is a two-phase fail-closed operation. After nonce claim, the
Worker reads the exact repository/run/job state through `GitHubPort` outside a
storage transaction and produces a bounded evidence digest. A second atomic
transaction clears only the matching open `(transition_epoch,
repository_alias)` row when its source head and evidence digest agree and no
newer open risk exists. Repeating the same clear is an idempotent success;
stale-epoch, ambiguous, inaccessible, or mismatched evidence leaves the row open.
The same final-clear transaction enters `QUEUE_RISK_CLEARED`; creating any
newer hosted transition inserts its rows and revokes that state atomically.

Outbox status values are `pending`, `processing`, `retry_wait`, `confirmed`, and `permanent_failure`. Due-work processing transactionally claims a bounded row batch with a random claim ID and expiry, performs no network I/O inside the claim transaction, then commits an outcome only when the claim ID still matches. Expired claims return to due work. A GitHub row reaches `confirmed` only after GET read-back of its exact `variable_name` equals `desired_value`; an HTTP success alone is insufficient. A routing transition additionally requires both companion rows confirmed at their configured values. Crash after an ambiguous GitHub mutation retries through read-back before any write. Notification delivery may duplicate after a crash; the shared event ID makes webhook recipients idempotent and makes email duplicates recognizable. Notification `permanent_failure` remains visible but cannot change routing state. Expired request nonces and consumed challenges are pruned only after their acceptance/replay windows plus a safety margin; sanitized audit events remain. Audit retention is bounded only after the same rows are present in a verified private evidence bundle; active transitions and outboxes are never pruned.

Each Durable Object owns one alarm. All producers call
`commitDueWithAlarm(mutation: DueMutation)`, which opens exactly one synchronous
`ctx.storage.transactionSync(() => { ... })` closure. `DueMutation` is a closed
discriminated union of bounded insert/reschedule/claim-release data, and every
variant carries the exact `dueAtMs` persisted by its SQL command. The helper
derives the alarm candidate from that same field; callers cannot supply a
second/later deadline, callback, Promise, thenable, raw SQL, or external-I/O
closure. Inside that synchronous closure the helper executes the selected
command with `ctx.storage.sql.exec()` and sets the preserved minimum with
`ctx.storage.setAlarm()`; because SQLite-backend alarm state lives in the
internal `_cf_METADATA` table in the same physical database, both writes commit
or roll back together under one native SQLite transaction, and `setAlarm()`'s
returned `Promise` is never awaited (the closure is synchronous and awaiting adds
nothing to durability, as a pinned re-probe confirmed). The async
`ctx.storage.transaction(txn => ...)` form is prohibited: its
`DurableObjectTransaction` handle has no `.sql` member, so pairing `txn.setAlarm`
with an outer `ctx.storage.sql.exec()` is not a contracted atomicity guarantee.
No external I/O/promise, pre-arm commit, or second transaction is permitted;
static type tests reject async/thenable mutation inputs. The exact pinned
`@cloudflare/workers-types@5.20260708.1` contract exposes `transactionSync`,
`ctx.storage.sql.exec`, and `ctx.storage.setAlarm`; the lock must also contain
its recorded registry integrity and the Workerd/Miniflare date-aligned versions.
The Workers-runtime suite proves alarm and SQL rollback together — and that
alarm durability does not depend on awaiting `setAlarm()` — under pinned workerd
`1.20260708.1`, Miniflare `4.20260708.1`, and the Vitest pool before deployment. There is no non-transactional fallback: a type/runtime mismatch
fails CI and deployment closed. Concurrent cron/request/alarm scheduling can
never overwrite an earlier wake-up with a later one; any mutation-command failure
preserves both prior alarm and prior SQL state, and a committed due row cannot
exist without an equal-or-earlier alarm. Cron reconciles configuration,
evaluates health, and calls bounded `processDueWork`. The alarm performs the
same bounded claim/process/reconcile loop and commits the next retry row and
alarm together; it never depends on a future request or the next cron tick to
finish hosted holds, GitHub mutations, canary dispatch/polling, or notification
retries. Alarm and cron overlap is safe through the transactional minimum,
claim IDs/expiry, and idempotent read-back.

## Failover State Contract

```text
BOOTSTRAP
  -> HOSTED_CONFIRMED
  -> QUEUE_RISK_CLEARED
  -> RECOVERY_OBSERVED
  -> CANARY_PENDING
  -> CANARY_PASSED
  -> ACQUISITION_ENABLED_CONFIRMED
  -> SELF_HOSTED_CONFIRMED
  -> HEALTHY_SELF_HOSTED
HEALTHY_SELF_HOSTED
  -> SUSPECT
  -> FAILOVER_PENDING
  -> HOSTED_CONFIRMED
  -> QUEUE_RISK_CLEARED
  -> RECOVERY_OBSERVED
  -> CANARY_PENDING
  -> CANARY_PASSED
  -> ACQUISITION_ENABLED_CONFIRMED
  -> SELF_HOSTED_CONFIRMED
  -> HEALTHY_SELF_HOSTED
HOSTED_CONFIRMED
  -> QUEUE_RISK_CLEARED
QUEUE_RISK_CLEARED
  -> LEGACY_RECOVERY_PENDING
LEGACY_RECOVERY_PENDING
  -> LEGACY_CANARY_PREPARED
LEGACY_CANARY_PREPARED
  -> LEGACY_CONFIRMED
LEGACY_CONFIRMED
  -> FAILOVER_PENDING
  -> HOSTED_CONFIRMED
```

- `BOOTSTRAP` creates a hosted mutation intent for every repository and cannot advance until each repository reads back hosted; only then does it enter `HOSTED_CONFIRMED`.
- First stale evaluation from healthy records `SUSPECT`; the second creates a hosted transition. An authenticated fatal heartbeat may create that transition immediately.
- `HOSTED_CONFIRMED` requires every repository row confirmed hosted; partial success remains `FAILOVER_PENDING`.
- `QUEUE_RISK_CLEARED` requires zero open rows from the latest hosted
  transition after authenticated per-repository GitHub read-back/selective
  recovery. While any row is open, Portable remains disabled, no canary-only
  acquisition starts, and legacy components that can accept work remain stopped.
  A new hosted transition revokes this state and creates a new risk generation.
- A hosted hold may enter from any state, queues hosted intent once, remains held until every repository reads back hosted, and suppresses recovery observations while enabled.
- Sustained healthy observations move toward `CANARY_PENDING` without changing
  the route, but only after `QUEUE_RISK_CLEARED`.
- Releasing a hosted hold creates a new recovery epoch; it never restores self-hosted directly.
- A failed canary sets `recovery_blocked=1`; only `startRecoveryEpoch` can clear it and create a new epoch.
- `CANARY_PASSED` is valid only for the current epoch, persisted run ID, expected revision, and successful conclusion.
- `CANARY_PASSED` keeps all consumer routes hosted. It advances only after the
  controller enables full acquisition and, while the Worker transition epoch is
  unchanged, the Worker accepts a heartbeat from the same enrollment session
  with sequence newer than the canary observation, reporting `enabled`, the
  exact expected policy digest, and complete configured capacity.
- `ACQUISITION_ENABLED_CONFIRMED` is the only state allowed to create a
  self-hosted GitHub outbox. A later narrowing/fatal heartbeat before route
  confirmation persists hosted intent instead.
- `SELF_HOSTED_CONFIRMED` requires per-repository self-hosted read-back before returning to healthy.
- Governed legacy rollback is staged so its evidence can exist before the state that consumes it. `LEGACY_RECOVERY_PENDING` is an authenticated manual rollback state entered after latest-transition queue risk is cleared and the operator's authenticated request with expected fence generation; it grants only the short renewable fenced legacy process lease while routing stays hosted and writes no `legacy` value.
- `LEGACY_CANARY_PREPARED` dispatches and observes the secretless legacy canary while routing still stays hosted, gathering exact-head `runner.environment=self-hosted` evidence plus a newer legacy heartbeat.
- `LEGACY_CONFIRMED` is entered only after fence-generation, workflow-binding, evidence-digest, and legacy-canary verification all agree; only then does it write the explicit `legacy` value, and it never deletes the variable. A hosted hold blocks only this final commit, not the staged lease or canary.
- Once `LEGACY_CONFIRMED`, every repository must read back `legacy`; thereafter any authenticated fatal/stale legacy health or a manual hosted hold persists a hosted outbox transition, reverting to hosted.

## Planned File Map

- Worker: modify the foundation workspace's `worker/{package.json,tsconfig.json,vitest.config.ts}` and root `package-lock.json`; create `worker/{eslint.config.js,wrangler.jsonc,wrangler.test.jsonc,worker-configuration.d.ts}` with the declaration file generated only by `wrangler types`.
- Protocol/auth: `worker/src/{config.ts,protocol.ts,index.ts}`, `worker/src/security/hmac.ts`, `internal/failoverclient/{protocol.go,client.go}`; no hand-written binding `Env`.
- Fleet state: `worker/src/fleet/{schema.ts,store.ts,coordinator.ts,evaluator.ts,due-work.ts}`, `worker/src/scheduler.ts`.
- Generation fence: extend `internal/fleetfence/{store,store_unix}.go`, `cmd/portable-ghar-fleet-fence/main.go`, `deploy/qts/run-legacy-fenced.sh`, and `tests/shell/qts/fleet-fence.bats` from the controller-runtime phase.
- GitHub/canary: `worker/src/github/{app-auth.ts,client.ts,mutation-outbox.ts,canary.ts}`.
- Notifications: `worker/src/notifications/{event.ts,email.ts,webhook.ts,outbox.ts}`, `docs/security/signed-webhook-contract.md`, `tests/operations/webhook-recipient-contract.test.mjs`.
- Tests: `worker/test/**/*.test.ts`, `internal/failoverclient/*_test.go`, `internal/health/*_test.go`, `tests/fixtures/failover/hmac-v1.json`, `tests/operations/*`.
- Public config/templates: `config/schema/{failover-deployment.schema.json,failover-evidence.schema.json,queue-recovery-manifest.schema.json,secondary-delivery-receipt.schema.json,legacy-retirement-manifest.schema.json}`, `config/examples/{failover-deployment.example.json,queue-recovery-manifest.example.json,secondary-delivery-receipt.example.json,legacy-retirement-manifest.example.json,portable-ghar-canary.workflow.yml,legacy-recovery-canary.workflow.yml,consumer-routing.workflow.yml}`.
- Safety tooling: `scripts/{validate-failover-config.mjs,render-failover-config.mjs,validate-canary-template.mjs,verify-failover.sh}`, `scripts/ops/{assert-private-overlay.sh,capture-legacy.sh,adopt-legacy-fence.mjs,suspend-legacy.mjs,control-plane-admin.mjs,probe-private-deployment.mjs,transition-variable.mjs,verify-consumer-routing.mjs,record-drill.mjs,record-signal-receipt.mjs,retire-legacy.mjs,verify-legacy-retired.mjs,collect-soak-evidence.mjs,verify-retirement-gates.mjs}`, `deploy/qts/{adopt-legacy-fence,suspend-legacy,retire-legacy,verify-legacy-retired}.sh`, `.gitignore`, `.dockerignore`.
- Docs: `docs/security/failover-permissions.md`, `docs/operations/{failover-deployment.md,legacy-capture-and-freeze.md,failover-canary-cutover.md,failover-failure-drills.md,failover-soak-and-retirement.md,failover-final-verification.md}`, and post-verification `README.md`.

### Task 1: Scaffold Worker Tooling and Strict Public Configuration

**Files:** Modify the foundation workspace files named above; create Worker config/generated-type files, `worker/src/{config.ts,index.ts}`, `worker/test/{scaffold.test.ts,config.test.ts}`, both configuration schema/example files, validation/render scripts, and private-artifact patterns in `.gitignore`/`.dockerignore`.

**Interfaces:** `loadFailoverConfig(raw: string): FailoverConfig`; `renderPrivateConfig(config, secretRefs, outputPath): Promise<void>` writes mode `0600` and returns no values; `node scripts/validate-failover-config.mjs --config <json>` prints only `failover configuration: PASS|FAIL`; `node scripts/render-failover-config.mjs --overlay <root> --output <root>/rendered/wrangler.jsonc` prints only `failover render: PASS|FAIL`.

- [ ] Write failing tests `returns_generic_404`, `rejects_unknown_nested_fields`, `rejects_inline_secret_fields`, `rejects_duplicate_fleet_or_repo_alias`, `requires_all_three_repository_variable_names`, `requires_exact_scalar_companion_values`, `requires_expected_enabled_policy_digest_and_capacity`, `requires_bounded_permit_ttl_and_drain_margin`, `pins_worker_dependencies_exactly`, `satisfies_peer_ranges`, `generated_env_matches_config`, `private_path_must_be_outside_git`, and `render_prints_no_values`.
- [ ] Run `npm run --workspace worker test -- scaffold.test.ts config.test.ts`; expect FAIL for missing modules. Run `node --test tests/operations/failover-config.test.mjs`; expect FAIL for missing validator.
- [ ] Install the missing pool and direct Workers type dependencies through the root workspace lock: `npm install --workspace worker --save-dev --save-exact @cloudflare/vitest-pool-workers@0.18.4 @cloudflare/workers-types@5.20260708.1`. Preserve the foundation's exact TypeScript `6.0.3`, Vitest `4.1.10`, Wrangler `4.110.0`, ESLint `10.7.0`, `@eslint/js` `10.0.1`, and `typescript-eslint` `8.63.0`; assert published peer ranges, every exact dependency string, the recorded Workers-types registry integrity, and date parity with locked workerd `1.20260708.1`/Miniflare `4.20260708.1`. Create strict parsers with `additionalProperties: false` at every schema level. Require a bounded permit TTL and drain margin whose sum exceeds the controller's maximum external-operation deadline plus forced-termination bound, and reject any config that cannot prove that inequality. Public Wrangler config contains only a synthetic name, `compatibility_date: "2026-07-10"`, `nodejs_compat`, generated binding types, and sanitized observability; it contains no account, route, address, or secret. Rendered production config exists only below the validated overlay root and restricts both email sender and destination.
- [ ] Run `npm ci --ignore-scripts`, `npm run --workspace worker lint`, `npm run --workspace worker typecheck`, `npm run --workspace worker types:check`, and `npm run --workspace worker test -- scaffold.test.ts config.test.ts`, then `node scripts/validate-failover-config.mjs --config config/examples/failover-deployment.example.json`; expect all PASS and only `failover configuration: PASS` on validator stdout.
- [ ] Commit: `git add package-lock.json worker config scripts .gitignore .dockerignore tests/operations/failover-config.test.mjs && git commit -S -m "worker: scaffold failover configuration"`.

### Task 2: Add Exact-Body HMAC and the Controller Enrollment Client

**Files:** Create `worker/src/{protocol.ts,security/hmac.ts}`, `worker/test/hmac.test.ts`, `tests/fixtures/failover/hmac-v1.json`, and `internal/failoverclient/{protocol.go,protocol_test.go,client.go,client_test.go}`; modify `cmd/portable-ghar-controller/main.go` and its tests to wire the remote provider alongside the independently injected host-fence provider.

**Interfaces:** TypeScript `signatureInput(method, path, unixSeconds, body): Uint8Array`, `responseSignatureInput(path, body): Uint8Array`, `verifyRequestMac(key, header, input): Promise<boolean>`; Go `SignatureInput(method, path string, unixSeconds int64, body []byte) []byte`, `Client.Enroll(ctx)`, `Client.Publish(ctx, Snapshot)`, `Client.AcquirePermit(ctx, controller.AcquisitionPermitRequest) (controller.AcquisitionGuard, error)`, `Client.AcquireOrRenewLegacyLease(ctx, LegacyLeaseRequest) (LegacyLease, error)`, and in-memory `{epoch,sessionID,nextHeartbeatSequence,nextControlSequence}`. The client implements only the remote permit provider; it does not implement the host-local fleet fence.

- [ ] Write failing cross-language tests for the same synthetic request/response vectors, one-byte body/path/timestamp/MAC mutations through the exact signature-input functions, malformed base64url, short keys, challenge request timestamps at `now±300s` accepted and `now±301s` rejected, duplicate request-nonce rejection, challenge/request-nonce mismatch, completion replay, independent strict heartbeat/control sequences, idempotent same-operation permit response after response loss, sequence ambiguity, state loss, and re-enrollment. Permit tests reject wrong operation/repository/scale set/policy epoch/digest/Worker transition or permit generation, server expiry, response MAC, reuse, and close mismatch. Legacy-lease tests require bounded renewal and fail closed on missed/denied renewal. Assert TypeScript calls `crypto.subtle.verify` and Go uses `hmac.Equal` for both directions.
- [ ] Run `npm run --workspace worker test -- hmac.test.ts`; expect missing HMAC symbols. Run `go test ./internal/failoverclient -run 'Test(HMAC|Enrollment|Reenrollment|Permit|LegacyLease)' -count=1`; expect missing client symbols.
- [ ] Implement the locked timestamped request and domain-separated response framing, strict raw base64url decoding, 32-byte keys/MACs, client-generated random 32-byte request nonce, server-generated random 32-byte single-use challenge bound to that nonce digest, `EnrollmentCompleteRequestV1` carrying the same nonce plus challenge and a client-generated random 16-byte session ID, server epoch response, independent heartbeat/control sequences starting at `1`, and one bounded re-enrollment attempt after authenticated `409`. Verify HMAC before claiming the initial request nonce; completion atomically verifies the bound pair and consumes the challenge exactly once. The remote provider requests a fresh operation-bound permit only from inside the controller critical section, validates the exact MAC/bindings/server expiry, retains it only in memory across that one external call, and sends an idempotent close; the legacy wrapper renews its process lease before the fail-closed termination deadline. Never persist a reusable permit/lease bearer or server epoch locally, or log bodies, timestamps, nonces, headers, keys, challenge, session, permit/lease IDs, or MAC.
- [ ] Run both commands again plus `go test -race ./internal/failoverclient`; expect shared-vector PASS, every mutation rejected, and no race.
- [ ] Commit: `git add worker/src/protocol.ts worker/src/security worker/test/hmac.test.ts tests/fixtures/failover internal/failoverclient cmd/portable-ghar-controller && git commit -S -m "failover: add authenticated enrollment and permit client"`.

### Task 3: Persist Epoch, Challenge, Session, Sequence, and Heartbeats in One SQLite Object per Fleet

**Files:** Modify both Wrangler configs, generated `worker/worker-configuration.d.ts`, and `worker/src/index.ts`; create `worker/src/fleet/{schema.ts,store.ts,coordinator.ts}` and tests `worker/test/{fleet-store.test.ts,enrollment.test.ts,heartbeat.test.ts}`.

**Interfaces:** Add the `FleetCoordinator` methods above; the module handler uses generated `Env`, `env.FLEETS.getByName(fleetId)`, and no other fleet-to-object mapping; the Durable Object extends `DurableObject<Env>` and uses `this.env`/`this.ctx`.

- [ ] Write failing tests for deterministic object identity, SQLite persistence across object eviction, challenge/request-nonce association/reuse/expiry, every closed nonce purpose (`challenge`, recovery, legacy recovery, queue recovery, hosted hold, status), rejection of an unknown purpose, migration from the prior nonce `CHECK`, concurrent completion (exactly one winner), server epoch increment, prior-session invalidation, independent sequence `1` for heartbeat/control channels, duplicate/reordered/gapped/old-epoch rejection on each, strict acquisition epoch/policy-digest shape, permit/legacy-lease row persistence and session binding across eviction, receipt-time freshness, unknown-field rejection, generated binding drift, and no manual `Env` declaration.
- [ ] Add schema/migration parity tests proving `LegacyCanaryIdentity.expectedRevision` and `expectedLegacyLabel` each map to a required persisted column and survive eviction/reload atomically with head, fence generation, evidence digest, run ID, environment, attestation, and conclusion.
- [ ] Run `npm run --workspace worker test -- fleet-store.test.ts enrollment.test.ts heartbeat.test.ts`; expect missing coordinator/schema failures.
- [ ] Configure binding `FLEETS`, class `FleetCoordinator`, migration `{"tag":"v1","new_sqlite_classes":["FleetCoordinator"]}`. Create the contracted tables with a `_sql_schema_migrations` table because `PRAGMA user_version` is unsupported. The application migration rebuilds `request_nonces` when adding closed purposes so the SQLite `CHECK` and TypeScript union remain exact; contract tests inspect both. Atomically claim nonce digests by purpose, and separately verify the bound challenge/request-nonce pair, consume challenge, increment epoch, activate session, reset both sequence channels, revoke prior-session permits/lease, and invalidate the prior session. Persist only the closed permit/lease fields above, never request bodies/MACs; store only allowlisted heartbeat JSON and server receipt time. Run `wrangler types`; never hand-write binding types.
- [ ] Run the narrow tests, `npm run --workspace worker typecheck`, and `npm run --workspace worker types:check`; expect all PASS. Inspect SQLite in tests and assert no signature, request body, key, challenge plaintext, or secret column exists.
- [ ] Commit: `git add worker/wrangler* worker/worker-configuration.d.ts worker/src/index.ts worker/src/fleet worker/test && git commit -S -m "worker: persist fleet enrollment and heartbeat state"`.

### Task 4: Implement Cron Evaluation and Hysteresis

**Files:** Create `worker/src/{scheduler.ts,admin.ts}`, `worker/src/fleet/{evaluator.ts,due-work.ts}`, `worker/test/{evaluator.test.ts,scheduler.test.ts,due-work.test.ts,admin.test.ts}`; modify Wrangler configs and `worker/src/index.ts`.

**Interfaces:** `evaluateHealth(snapshot, policy, nowMs): EvaluationDecision`; `issueAcquisitionPermit`/`closeAcquisitionPermit`/`renewLegacyProcessLease` above use server-owned time and persistent permit generation; closed `DueMutation` data variants for bounded insert/reschedule/claim-release commands, each with exact `dueAtMs`; `commitDueWithAlarm(mutation: DueMutation): void` derives the alarm deadline from that same persisted field and commits the minimum alarm plus internally executed SQL mutation in one synchronous `ctx.storage.transactionSync` closure using `ctx.storage.sql.exec()` and `ctx.storage.setAlarm()` (its returned `Promise` unawaited); `DueWorkPorts { github?, canary?, email?, webhook? }` is constructor-injected and an absent port fails closed without external I/O; Worker `scheduled()` calls `reconcileConfiguration`, `evaluate`, and bounded `processDueWork` once per configured fleet on each `* * * * *` event; `FleetCoordinator.alarm()` runs the same due-work loop and reschedules the earliest persisted due row. Authenticated admin handlers expose recovery, governed legacy recovery, queue-risk recovery, hosted-hold enable/disable, and read-only status only when explicitly enabled.

- [ ] Write table-driven failing tests for bootstrap creating hosted intents, bootstrap remaining blocked until every hosted/companion read-back, `HOSTED_CONFIRMED` recovery observation, current canary success remaining hosted, rejection of self-hosted outbox while acquisition is canary-only, full acquisition enable followed—without a Worker epoch change—by a same-enrollment-session heartbeat whose sequence is newer than canary completion and whose policy digest/capacity exactly match config to reach `ACQUISITION_ENABLED_CONFIRMED`, first healthy-state stale observation to `SUSPECT`, second to `FAILOVER_PENDING`, authenticated fatal immediate eligibility, healthy reset before mutation, failed-canary block, new recovery epoch, hosted-hold entry from every state, hosted read-back before hold confirmation, no recovery while held, release creating a new recovery epoch and inserting no queue-risk row, the staged legacy path (`LEGACY_RECOVERY_PENDING` granting only the fenced lease while hosted, `LEGACY_CANARY_PREPARED` running the secretless legacy canary while hosted, `LEGACY_CONFIRMED` creating the `legacy` outbox only after a persisted exact-head legacy canary/fence/evidence record plus a newer legacy heartbeat session), a hosted hold blocking only the `LEGACY_CONFIRMED` commit, rejection of active-fleet/fence-generation mismatch, automatic stale/fatal legacy fallback to hosted, and late epoch rejection. Add queue-risk tests for durable per-repository rows on every failover transition, no queue-risk row on a hold release / already-hosted recovery / per-repository archive disable, an archived-disabled repository excluded from the clear set so it cannot wedge the fleet gate, eviction persistence, authenticated same-epoch GitHub-read-backed clear, stale/mismatched/ambiguous clear rejection, idempotent repeat, and preservation of newer risk. Add configuration tests: a new repository is accepted only under hosted hold, inserted unconfirmed-hosted, reconciled with exact expected companion variables by Worker-owned outbox, bound to the persisted canary config/revision/digest, and rejected on identity mutation/removal, revision skip/rollback, or same-revision digest mismatch. Add pinned Workers-runtime alarm tests that compile and execute `ctx.storage.sql.exec()` beside `ctx.storage.setAlarm()` inside one synchronous `ctx.storage.transactionSync` closure, prove alarm durability is independent of awaiting `setAlarm()`'s `Promise` and that a post-eviction alarm still fires, reject the async `ctx.storage.transaction(txn => ...)`-with-outer-`sql` pattern as non-contracted, and cover concurrent closed mutations carrying their exact persisted `dueAtMs` arriving in both orders, transactional minimum preserving the earliest alarm, injected alarm/SQL failure preserving both prior alarm and prior SQL, compile-time rejection of async/thenable/callback/raw-SQL mutation inputs, rejection of any split-deadline/two-transaction/pre-arm API, already-due mutations, overlap with cron, object eviction, six exhausted native retries followed by self-rescheduling, and crash before/after claim/network/outcome. Admin tests enforce `±300s` timestamp skew, every nonce-purpose schema value including legacy/queue recovery, single-use nonce digest, separate HMAC key with `crypto.subtle.verify`, disabled-by-default routing, generic rejection responses, and a status response containing only `AdministrativeStatus` fields.
- [ ] Add an explicit acquisition-safety matrix: every state with an open latest-transition queue-risk row rejects canary dispatch, self-hosted outbox creation, acquisition-enabled confirmation, and governed legacy recovery; only the last authenticated clear enters `QUEUE_RISK_CLEARED`, and a new hosted transition immediately revokes it.
- [ ] Add permit-state tests proving only exact state/mode bindings issue authority: `RECOVERY_OBSERVED`/`CANARY_PENDING` may issue one-capacity Portable canary permits for the configured scale set; `CANARY_PASSED` may issue exact enabled-policy permits while routing remains hosted; healthy self-hosted states may issue matching Portable permits; `LEGACY_RECOVERY_PENDING` and `LEGACY_CANARY_PREPARED` may renew only the exact fenced legacy process lease, and `LEGACY_CANARY_PREPARED` may dispatch the one legacy canary. Bootstrap, hosted hold, any open latest queue-risk row, stale config/session, companion drift, revoking/draining mode, or any other state rejects. A hosted transition atomically increments the permit generation and rejects issuance/renewal, then remains pre-transition until every prior row is closed or server-expired plus the configured termination margin; only afterward may it create hosted intent/outboxes/queue risk. Test a hosted transition racing after admin status, after local canary-only intent, before/after every poll permit, during a stuck external call, and during legacy renewal. No state claims hosted hard-zero while earlier authority remains live.
- [ ] Run `npm run --workspace worker test -- evaluator.test.ts scheduler.test.ts due-work.test.ts admin.test.ts`; expect missing evaluator/scheduler/due-work behavior.
- [ ] Implement the locked health, permit, and transactional configuration state machines. Apply the six-minute stale default, two-observation failover floor, configured recovery observations, transition lock/epoch, one-minute cron, persisted due times, and server-owned permit expiry. Validate each HMAC/session/control sequence and issue an idempotent operation-bound response only in the allowed state; recompute and require the Worker-owned expected acquisition-policy digest and repository-policy revision for the issuance mode (canary-only or enabled), never the client's echoed digest; refuse any repository whose `eligibility_state` is not `active`; require a cryptographically random `operationId` bound to the current enrollment epoch/session with idempotency keyed on `(epoch, sessionId, operationId, request-fingerprint)`, and reject — never replay — an `operationId` presented under a superseded epoch/session; close affects only its exact live permit; legacy renewal extends only its current exact lease and never crosses a permit-generation change. A failed canary remains hosted with `recovery_blocked=1` until `startRecoveryEpoch` increments the epoch. Hosted-hold enable and every hosted safety transition first persist permit revocation/drain and block recovery; only the alarm-driven drain completion persists hosted transition plus queue-risk intent. Disable clears the hold, increments the recovery epoch, and remains hosted through canary and acquisition-enabled confirmation. After current canary success, accept only a fresh same-enrollment-session/transition-epoch heartbeat whose `enabled` state and full capacity/eligibility match config; only then create the self-hosted outbox. Governed legacy recovery is staged so its evidence can exist before the state that consumes it: `LEGACY_RECOVERY_PENDING` grants only the short renewable fenced legacy process lease while routing stays hosted; `LEGACY_CANARY_PREPARED` dispatches and observes the secretless legacy canary while routing still stays hosted; and only `LEGACY_CONFIRMED` — reached when the authenticated request, expected fence generation, evidence digest, exact legacy workflow binding, persisted GitHub-observed exact-head secretless legacy canary with `runner.environment=self-hosted`/successful attestation, and a newer server-owned heartbeat session reporting matching `activeFleet=legacy`/generation all agree — creates the explicit `legacy` outbox transition. A hosted hold blocks only that final commit, not the staged lease or canary. Legacy session staleness, fatal probe, fleet/generation mismatch, or lease renewal failure starts permit revocation/drain before hosted intent. Queue-risk clearing performs GitHub read-back outside the transaction then atomically clears only the matching open epoch/repository/evidence row. Every due-row create or reschedule uses `commitDueWithAlarm` with closed `DueMutation` data whose exact `dueAtMs` is both persisted and used to derive the alarm; its one synchronous `ctx.storage.transactionSync` closure performs `ctx.storage.sql.exec()` and `ctx.storage.setAlarm()` together (the alarm `Promise` unawaited), with no second deadline, caller callback, or external promise, and rolls both back on failure; never move an existing alarm later. `processDueWork` claims bounded rows, invokes only injected ports outside storage transactions, and reconciles claims through the same combined helper; Task 4 wires fail-closed absent ports so this intermediate commit compiles/tests without making an external call. The alarm catches downstream errors and commits its next retry row/alarm together before returning. Optional admin endpoints are absent when disabled; otherwise each verifies timestamp, separate-key HMAC, and one-time nonce before Durable Object access. Mutating endpoints return only `202 {"status":"accepted"}`; status returns the bounded typed document and is never logged.
- [ ] Enforce `queueRiskCount == 0` for the latest hosted transition before canary dispatch, permit/legacy-lease issuance, acquisition-enabled confirmation, or `startLegacyRecovery`; `clearQueueRisk` advances to `QUEUE_RISK_CLEARED` only on the last matching clear. A hosted transition revokes permit generation first and creates the new queue-risk generation only after drain; no split admin-status/local-command sequence can substitute for live authority.
- [ ] Treat "same transition epoch" above as unchanged Worker state, not a heartbeat field: freshness is proven by the same enrollment session, a sequence newer than canary completion, and exact policy-digest/total-capacity match. Re-run narrow tests, then `npm run --workspace worker test`; expect all PASS, exactly one evaluation call per configured fleet per cron event, no unclaimed due row without an alarm, and bounded at-least-once processing after eviction/crash.
- [ ] Commit: `git add worker/src/fleet/evaluator.ts worker/src/fleet/due-work.ts worker/src/scheduler.ts worker/src/admin.ts worker/src/index.ts worker/wrangler* worker/test && git commit -S -m "worker: add failover scheduler and due-work engine"`.

### Task 5: Add Least-Privilege GitHub Auth and Persisted Per-Repository Mutation Outbox

**Files:** Create `worker/src/github/{app-auth.ts,client.ts,mutation-outbox.ts}`, `worker/test/{github-auth.test.ts,mutation-outbox.test.ts}`, and `docs/security/failover-permissions.md`; modify `worker/src/fleet/due-work.ts`, `worker/src/index.ts`, and affected tests to wire only the variable-specific GitHub port.

**Interfaces:** `GitHubPort` above; `processMutation(row, github, store, nowMs): Promise<MutationOutcome>`; unique idempotency key `(transition_epoch, repository_alias, variable_name, desired_value)`.

- [ ] Write failing tests for installation-token scoping, exact permitted Variables read/write + Metadata read + configured-workflow Contents read + mandatory Actions read + conditional Actions write, prohibited broader permission rejection, intent-before-I/O, exactly one claimed row and one variable-specific port call per mutation, already-correct route/companion selectors, variable GET `404` with repository/variables-collection access both verified before classifying missing, access-loss `404` rejection, route creation only as hosted, companion create/repair only while hosted/held to exact configured scalars, POST timeout followed by GET reconciliation, POST `422` with `errors[].code == "already_exists"` followed by GET, other `422` validation/abuse classification, refusal to create route directly as self-hosted/legacy, refusal to route locally when a companion is missing/invalid/drifted/inaccessible or the legacy label is not unique, PATCH then GET read-back, crash/timeout before and after PATCH, `Retry-After`, `X-RateLimit-Reset`, default-branch/workflow blob/content/job/check/attestation binding mismatch, per-transition companion read-back, five-minute integrity sweep, an `archived=true` read latching eligibility to `archived-disabled`, revoking that repository's permits/leases, blocking new permit issuance, and creating no fleet-wide queue-risk row, a bare live `archived=false` NOT clearing the latch (only the operator reactivation path does), archived-repository behavior (a variable write accepted silently and a dispatch accepted-but-queued-with-no-job) handled without depending on any rejection and with a dispatch against a newly-archived repository timed out rather than awaited, stale-overlay-versus-live-archive disagreement resolving to the live GitHub read, partial repository success, retry after object eviction, stale claim completion rejection, and refusal to confirm mismatched read-back. Reject a coarse multi-variable provider call and any outcome that confirms more than its claimed row.
- [ ] Run `npm run --workspace worker test -- github-auth.test.ts mutation-outbox.test.ts`; expect missing GitHub modules.
- [ ] Implement GitHub App JWT/installation-token flow without logging tokens. Use `X-GitHub-Api-Version: 2026-03-10`; read `PORTABLE_GHAR_ROUTE`, `PORTABLE_GHAR_SCALE_SET`, and `PORTABLE_GHAR_LEGACY_LABEL` through the repository Actions Variables API; create a missing route only as `hosted`; and create/repair companions only to the exact configured scalars while desired/confirmed route is hosted under the hold. Bind the default branch and configured workflow blobs through repository/Contents reads, dispatch `POST /repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches`, and locate runs/jobs/attestation steps through the Actions API. For each repository, transactionally persist transition/configuration intent plus exactly one outbox row per variable before I/O; claim one bounded due row and pass only that row's closed variable name/value to `writeRoutingVariable`; GET, or on variable `404` use the same installation token to verify both repository metadata and the variables collection before classifying the variable missing. Treat repository/collection `404` as installation access loss, not absence. PATCH only when that claimed variable exists and differs; never create a missing route directly as self-hosted/legacy. Classify POST `422` as duplicate only when a bounded parsed `errors[].code` equals `already_exists`; classify other `422` as typed validation/abuse failures. After every success, timeout, ambiguous POST/PATCH, or `422`, GET that same variable again and mark only that row confirmed when exact desired state is read back under the same live claim. Persist retry deadline and sanitized error code. Before every canary/local transition/route proof, and at least every five minutes in cron, read back both companion values and the repository's live `archived` state, validate the scalar grammar and unique legacy registration, and persist hosted intent on any mismatch. On `archived=true`, persist the archive hard-disable transition — hosted intent plus permit/lease revocation and blocked issuance — recording `archived_observed`/`archived_observed_at_ms`, and never make disablement depend on a variable write or dispatch being rejected by the archived repository, since GitHub accepts both but runs nothing (writes succeed silently; dispatches stay `queued` with no job); any dispatch against a repository that has archived must be timed out rather than awaited, never read as progress. Confirm a local transition only when all repositories read back route plus expected companions and their current default-branch workflow binding still matches.
- [ ] Re-run tests and `npm test`; expect all PASS, no steady-state API polling, and chaos fixtures proving partial success is independently recoverable.
- [ ] Commit: stage the Task 5 GitHub modules, due-work/entrypoint wiring, tests, and permissions document only, then `git commit -S -m "worker: reconcile repository routing outbox"`.

### Task 6: Build the Secretless Epoch-Bound Canary

**Files:** Create `worker/src/github/canary.ts`, `worker/test/canary.test.ts`, `config/examples/{portable-ghar-canary.workflow.yml,legacy-recovery-canary.workflow.yml,consumer-routing.workflow.yml}`, and `scripts/validate-canary-template.mjs` with `tests/operations/canary-template.test.mjs`; modify `worker/src/fleet/due-work.ts`, `worker/src/index.ts`, and affected tests to wire both canary paths through the GitHub port.

**Interfaces:** `CanaryIdentity { transitionEpoch, expectedRevision, repositoryAlias, workflow }`; `LegacyCanaryIdentity` and `LegacyCanaryRun` exactly as defined above; `GitHubPort.dispatchCanary`/`findCanary` and `dispatchLegacyCanary`/`findLegacyCanary`; persisted status `pending|locating|running|passed|failed|superseded` for both kinds.

- [ ] Write failing tests for Portable dispatch at exact persisted configuration revision, correlation by run name/epoch/revision, due-row claim/expiry, persisted run ID, crash before/after dispatch and poll, success only on matching `head_sha`, late success ignored, failed conclusion blocks recovery, manual mode making no dispatch, canary success remaining hosted, and self-hosted outbox rejection until a later same-enrollment-session/newer-sequence `enabled` heartbeat arrives while the Worker epoch is unchanged and proves the expected policy digest/full capacity. Add legacy dispatch/find, persistence, claim-expiry, eviction recovery, and negative-correlation tests for exact head, run ID, expected revision/label, fence generation, evidence digest, `runner.environment=self-hosted`, attestation, and conclusion; stale/wrong-head/wrong-label/wrong-environment/wrong-fence/wrong-evidence/failed-attestation results never permit legacy recovery. Static tests reject `secrets`, `pull_request_target`, write permissions, active public workflow paths, checkout, YAML-sequence `runs-on`, or an unexpected label; Portable uses one scalar scale-set name and legacy uses exactly `${{ vars.PORTABLE_GHAR_LEGACY_LABEL }}`.
- [ ] Run `npm run --workspace worker test -- canary.test.ts` and `node --test tests/operations/canary-template.test.mjs`; expect missing canary code/template validator.
- [ ] Implement both non-active `workflow_dispatch` templates with `permissions: {}`, no checkout, no declared secrets, exact inputs/run-name correlation, five-minute timeout, exact `github.sha` checks, and attestation. Portable uses one scalar synthetic `runs-on: portable-ghar-canary-scale-set` value rendered to the private GitHub.com scale-set name and isolation smoke checks; legacy uses exactly `${{ vars.PORTABLE_GHAR_LEGACY_LABEL }}` and attests `runner.environment=self-hosted`. The validator rejects YAML sequences, `self-hosted` arrays, and any selector outside the template's exact contract. Dispatch Portable only after bootstrap hosted/companion read-back and `QUEUE_RISK_CLEARED`, while route remains hosted and heartbeat says `canary-only`. Dispatch the legacy canary only from `LEGACY_CANARY_PREPARED` — entered from `LEGACY_RECOVERY_PENDING` once the fenced legacy lease is granted and the fenced process is up — after exact fence/evidence/workflow identity is persisted, while routing stays hosted. Implement `dispatchLegacyCanary`/`findLegacyCanary` in `worker/src/github/canary.ts`; persist and recover its due work through eviction. Only `LEGACY_CONFIRMED`, not `startLegacyRecovery`, consumes the verified legacy-canary evidence to write the `legacy` outbox; `startLegacyRecovery` only enters `LEGACY_RECOVERY_PENDING` and grants the lease.
- [ ] Re-run tests; expect current-epoch Portable success records `CANARY_PASSED` while routing stays hosted; only a subsequent acquisition-enabled confirmation enables self-hosted outbox creation, while every obsolete/failed result or canary-only heartbeat leaves hosted confirmed. Expect only a fully correlated persisted legacy result to unblock the separately authenticated legacy-recovery transition after eviction/retry.
- [ ] Commit: stage the Task 6 canary module, due-work/entrypoint wiring, tests, examples, and validator only, then `git commit -S -m "failover: add epoch-bound canary contract"`.

### Task 7: Add Independent Email and Signed-Webhook Notification Outboxes

**Files:** Create `worker/src/notifications/{event.ts,email.ts,webhook.ts,outbox.ts}`, `worker/test/notifications.test.ts`, `docs/security/signed-webhook-contract.md`, and `tests/operations/webhook-recipient-contract.test.mjs`; modify `worker/src/fleet/due-work.ts`, `worker/src/index.ts`, affected tests, the private-config renderer, and generated `worker/worker-configuration.d.ts` to wire email/webhook ports.

**Interfaces:** `NotificationEvent { eventId, fleetDisplayName, transitionType, repositoryAliases, lastConfirmedRoute, reasonCode, receivedAt, preTransitionQueueMayRemain, operatorAction }`; `EmailPort.send(event)`; `WebhookPort.send(event)`; unique key `(event_id, channel)`.

- [ ] Write failing tests for allowlisted event fields, text+HTML parity, restricted sender/destination config, signature over `<timestamp>.<eventId>.<exactBody>`, recipient `±300s` skew, replay-digest claim, event-ID dedupe, transactional outbox claim/expiry, crash before/after delivery, independent delivery, transient backoff, permanent stop, email-only failure, webhook-only failure, both failure, webhook-disabled mode creating no secondary row, routing success despite all notification failure, and every hosted transition carrying `preTransitionQueueMayRemain=true` from persisted queue-risk rows until authenticated same-epoch GitHub-read-backed recovery evidence clears every repository row. Exercise eviction, partial clear, stale/mismatched evidence, idempotent repeat, and newer-risk preservation. Contract tests reject a bridge on the QTS runner host and reject HTTP `2xx` as end-to-end Signal evidence; they require the separate-domain bridge to emit a distinct HMAC-signed delivery-receipt envelope only after destination acknowledgment. Receipt tests reject reuse of the webhook key, Worker/QTS access to the receipt key, stale/unknown key IDs, and ambiguous rotation; compromise or unverifiable rotation invalidates the evidence window without changing routing.
- [ ] Run `npm run --workspace worker test -- notifications.test.ts`; expect missing notification modules.
- [ ] Implement `env.EMAIL.send()` with both bodies and no attachment/raw log. Render `allowed_sender_addresses` and `destination_address` only into the private Wrangler config and verify the exact schema against Wrangler 4.110.0. Keep the public secondary Worker code generic: HTTPS-only webhook, separate Worker secret key, bounded exponential retry, sanitized permanent/transient codes, and headers `X-Portable-GHAR-Event-ID`, `X-Portable-GHAR-Timestamp`, `X-Portable-GHAR-Signature`. Due-work claims each channel independently. Document recipient constant-time MAC verification, skew/replay/dedupe enforcement, and a separate delivery-receipt HMAC contract `{eventId,channel,deliveredAt,destinationAckDigest,failureDomainClass,runnerHost:false}` without implementing the private Signal bridge.
- [ ] Run `npm run --workspace worker test -- notifications.test.ts`, then `npm run --workspace worker test` and `node --test tests/operations/webhook-recipient-contract.test.mjs`; expect independent outbox PASS, identical sanitized event ID/content across channels, replay rejection, and no Signal-specific Worker adapter.
- [ ] Commit: stage the Task 7 notification modules, due-work/entrypoint wiring, generated binding, tests, renderer, receipt schema/example, and webhook contract only, then `git commit -S -m "worker: add failover notification outboxes"`.

### Task 8: Extend the Host Fence with Continuous Cross-Generation Proof

**Files:** Modify `internal/fleetfence/{store,store_unix}.go` and tests, `cmd/portable-ghar-fleet-fence/main.go` and tests, `deploy/qts/run-legacy-fenced.sh`, and `tests/shell/qts/fleet-fence.bats` created by the controller-runtime phase.

**Interfaces:** Preserve `portable-ghar-fleet-fence guard --fleet portable|legacy --generation N -- COMMAND`, `inspect`, and `handoff --from portable|legacy|none --to portable|legacy|none --expected-generation N`. A guard holds the stable lock inode shared for the command lifetime, refreshes its own generation/fleet/owner/PID/boot-scoped holder record every five seconds, and terminates its child if that proof cannot be persisted for 30 seconds; handoff holds the stable inode exclusively, waits for all old-fleet guards to close, compares the separate generation header, and returns N+1. A legacy work-accepting wrapper also acquires and renews the separate short Worker process lease from Task 2; local fence success alone cannot start or keep its listener alive.

- [ ] Write failing Go/Bats tests for atomic header read-back, stable lock inode across header replacement, independent process-lifetime shared guards/holder records within one fleet, exclusive handoff, five-second per-holder renewal, one-child termination on its renewal failure, crash lock release, PID/boot-identity reuse, stale generation rejection, new/legacy simultaneous start, both watchdogs racing after crash, allowed same-fleet restart, disabled observer restart while `legacy` is active, and legacy restore only after the generation atomically changes while routing is confirmed hosted. For every work-accepting legacy process, also require a current exact Worker lease, renewal before expiry, immediate stop on denial/generation change, and proof that a hosted revoke/drain waits for termination before hosted intent; a prior status response is insufficient.
- [ ] Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/fleetfence ./cmd/portable-ghar-fleet-fence -run TestGenerationFence -count=1` and `bats tests/shell/qts/fleet-fence.bats`; expect renewal/race cases to fail before the extension.
- [ ] Extend the existing host authority without adding a second local lock: never rename the lock inode; update only the separate generation header under exclusive lock; create one atomic mode-restricted holder record per active guard; and retire old-generation records after handoff. The new controller/watchdog and every restored legacy controller/watchdog command execute through the same binary for nonzero work; a stale wrapper exits before child start, and renewal failure kills only its child. The legacy work-accepting path composes its local guard with the failover client's short Worker lease and terminates before the configured drain margin on renewal denial/loss; it never caches the lease across restart. The documented force-disabled observer path proves zero capacity and needs neither a `portable` host guard nor remote acquisition authority while `legacy` is active.
- [ ] Re-run both commands plus QTS-state-filesystem conformance; expect every race PASS, same-fleet controller/watchdog guards and renewals independently visible, no observation containing holders from both fleets, stable lock inode identity, and the non-current fleet unable to reacquire after a watchdog restart.
- [ ] Commit: `git add internal/fleetfence cmd/portable-ghar-fleet-fence deploy/qts/run-legacy-fenced.sh tests/shell/qts/fleet-fence.bats && git commit -S -m "runtime: extend cross-generation fence proof"`.

### Task 9: Connect Heartbeats to Successful Reconciliation and Complete Chaos Coverage

**Files:** Modify `internal/health/{publisher.go,publisher_test.go}` created by the controller phase and `deploy/qts/run-legacy-fenced.sh`; create `internal/health/{legacy_probe.go,legacy_probe_test.go}`, `cmd/portable-ghar-legacy-heartbeat/{main.go,main_test.go}`, `worker/test/failover-chaos.test.ts`, `tests/integration/failover_contract_test.go`, and `scripts/verify-failover.sh`.

**Interfaces:** Extend the existing `HealthPublisher` with `PublishAfterCycle(ctx, SuccessfulReconciliation) error`, `PublishLegacyAfterProbe(ctx, LegacyProbeReceipt) error`, and `PublishFatal(ctx, FatalReason) error`; failed/incomplete cycles have no ordinary heartbeat path. `LegacyProbeReceipt` contains only the current `legacy` fence generation, fixed captured adapter health booleans, bounded assignment summary, and sanitized reason code; the compatibility publisher has heartbeat authentication but no routing or failover GitHub App credential.

- [ ] Write failing tests proving ordinary portable heartbeat follows complete reconciliation only; the legacy compatibility heartbeat follows only a fixed target-safe probe while a current `legacy` guard and Worker process lease are held; each carries matching `activeFleet` and monotonic fence generation; fleet switch creates a newer server-owned session; stale/mismatched generation, lost legacy lease, and `legacy_probe_failed` begin permit revoke/drain then route hosted. Prove neither publisher has a routing client, and job-controlled fields cannot enter payload/logs; fatal reasons are closed enums; controller death, Docker loss, duplicated/reordered/dropped heartbeat, local state rollback, DO eviction, pre/post-outbox failure, GitHub ambiguity/rate limit/partial success, obsolete canary, and both notification failures preserve the safe state. Prove a passed canary remains hosted until a later fresh same-session/epoch enabled/full-capacity heartbeat and that narrowing before route confirmation returns hosted. Queue a secretless local canary immediately before failover and prove the route change does not migrate it, the persisted queue-risk row/flag survives eviction, authenticated `/v1/admin/queue-recovery` clears it only after exact same-epoch GitHub read-back, selective recovery creates no duplicate-execution claim, and no automatic cancel/rerun occurs. Inject a hosted-transition race after status and during every permit/lease state, plus cancellation-resistant poll/acquire/JIT during canary narrowing, pressure reduction, watchdog stop, and suspend; require permit-generation revocation, bounded controller/legacy termination and drain, a fatal heartbeat or subsequent staleness, hosted read-back only after drain, and no non-current-epoch acquisition.
- [ ] Run `go test ./internal/health ./internal/controller ./cmd/portable-ghar-legacy-heartbeat ./tests/integration -run Failover -count=1` and `npm run --workspace worker test -- failover-chaos.test.ts`; expect failures for missing publisher/integration wiring.
- [ ] Implement the publisher mapping, fixed allowlisted legacy probe, and compatibility command invoked only inside `run-legacy-fenced.sh`. It establishes a new server-owned session after the fence is `legacy`, publishes only while its process-lifetime guard/probe remains current, and sends fatal then exits on mismatch; it never mutates routing or recreates an external watcher. Add a verification script that runs Go race tests including the generation fence/legacy publisher, Worker lint/typecheck/tests, webhook-recipient contract, schema/template validators, forbidden-pattern scans, and `git diff --check`. It prints only stage names and PASS/FAIL.
- [ ] Run `scripts/verify-failover.sh`; expect every stage PASS, zero secret-shaped output, and hosted route after every unresolved failure fixture.
- [ ] Commit: `git add internal/health cmd/portable-ghar-legacy-heartbeat deploy/qts/run-legacy-fenced.sh worker/test/failover-chaos.test.ts tests/integration scripts/verify-failover.sh && git commit -S -m "failover: verify end-to-end safety invariants"`.

### Task 10: Write Private-Overlay, Least-Privilege, and Dark-Deployment Runbooks

**Files:** Create `scripts/ops/{assert-private-overlay.sh,control-plane-admin.mjs,probe-private-deployment.mjs}`, `tests/operations/{private-overlay.bats,control-plane-admin.test.mjs,probe-private-deployment.test.mjs,runbook-content.test.mjs}`, `config/schema/queue-recovery-manifest.schema.json`, `config/examples/queue-recovery-manifest.example.json`, `docs/operations/failover-deployment.md`; finalize `docs/security/failover-permissions.md`.

**Interfaces:** `assert-private-overlay.sh <absolute-root>` exits `0` only outside Git with `0700` root and `0600` files. `node scripts/ops/control-plane-admin.mjs hold-hosted|release-hosted|queue-recovery|status --overlay <root> --evidence-out <private-json>` sends a timestamped, nonce-protected administrative request, validates the typed response/read-back, writes mode `0600`, and prints only `control plane: PASS|FAIL`; `queue-recovery` requires `--recovery-manifest <private-json>` containing exact latest transition/repository/evidence entries, clears them one at a time, and succeeds only when status reads zero. `status` always compares the returned configuration revision/digest to the current overlay and also accepts bounded assertions `--expect-route hosted|self-hosted`, `--expect-hold true|false`, `--expect-acquisition disabled|canary-only|enabled|fatal|unobserved`, `--expect-config-revision <integer>`, `--min-sequence-advance N`, `--require-queue-risk-cleared`, `--require-current-epoch-canary`, `--require-acquisition-enabled-confirmed`, and `--wait-seconds 0..900`, using a fresh nonce per poll. `node scripts/ops/probe-private-deployment.mjs --overlay <root> --phase predeploy|postdeploy --evidence-out <private-json>` performs typed target/account, Docker/kernel/resource, GitHub App/install, Cloudflare binding/DO, Email Service, webhook, and repository-access probes and prints only `private deployment probe: PASS|FAIL`. Private evidence never goes to stdout.

The strict queue-recovery manifest is
`{protocol:"portable-ghar.queue-recovery.v1",fleetId,hostedTransitionEpoch,configDigest,entries:[{repositoryAlias,evidenceDigest}]}` with exactly one entry per configured repository and no duplicates/unknown fields. It records only evidence already produced by the operator's selective GitHub procedure; the public tool never chooses, cancels, or reruns work. Each Worker call independently re-reads GitHub before clearing.

- [ ] Write failing Bats cases for in-repo path, symlink escape, permissive mode, inline secret, unknown field, and sanitized success. Add admin-client tests for disabled endpoint, timestamp skew, nonce reuse, malformed/extra status fields, private evidence modes, hosted-hold/read-back, configuration-revision read-back, release creating a new epoch, queue-recovery exact-epoch/GitHub-read-back/idempotency, bounded waiting with a fresh nonce per poll, sequence advance, current-epoch canary/route assertions, acquisition-enabled confirmation, and secret-free stdout. Probe tests require positive target/account/Docker/kernel/resource/App/install/binding/DO/email/webhook/repository observations, private evidence modes, synthetic stdout, and mismatch stop. Add markdown checks requiring separate App tables, explicit denied permissions, mandatory Actions read, manual-canary omission of Actions write only, API version `2026-03-10`, restricted email binding, DO migration/alarm, generation-fence paths, separate-failure-domain webhook bridge, no inbound runner-host endpoint, and secret-reference installation.
- [ ] Validate the queue-recovery manifest's exact repository coverage, latest hosted transition/config digest, unique aliases, lowercase SHA-256 evidence digests, unknown-field rejection, mode `0600`, and refusal to perform cancel/rerun side effects.
- [ ] Run `bats tests/operations/private-overlay.bats` and `node --test tests/operations/control-plane-admin.test.mjs tests/operations/probe-private-deployment.test.mjs tests/operations/runbook-content.test.mjs`; expect missing script/runbook failures.
- [ ] Under the existing operator authorization, document exact gated order: validate overlay; run the predeploy private probe and stop on mismatch; record App installations/permissions; onboard and verify Email Service privately; render config; `wrangler deploy --dry-run`; install HMAC/GitHub/webhook/admin secrets from references without echo; deploy Worker/SQLite class; read authenticated status; repeat the identical deploy and prove enrollment/config/outbox/hold state persisted; enable and read back the hosted hold; verify its persisted email/webhook outboxes and record the matching private Signal receipt; run the postdeploy probe; install the shared generation wrapper without enabling new acquisition; enroll a force-disabled observer while `legacy` owns the fence; verify advancing accepted heartbeat and zero acquisition through authenticated status; reconcile/read back hosted for every repository; only then permit a new recovery epoch. Store raw output only in encrypted private evidence.
- [ ] Re-run tests and manually inspect the runbook for only synthetic examples; expect PASS and no active external action during source execution.
- [ ] Commit: `git add scripts/ops/assert-private-overlay.sh scripts/ops/control-plane-admin.mjs scripts/ops/probe-private-deployment.mjs tests/operations config/schema/queue-recovery-manifest.schema.json config/examples/queue-recovery-manifest.example.json docs/operations/failover-deployment.md docs/security/failover-permissions.md && git commit -S -m "docs: define private failover deployment gate"`.

### Task 11: Capture and Freeze Live Legacy State, Bind Consumer Routing, and Run the Canary Order

**Files:** Create `scripts/ops/{capture-legacy.sh,adopt-legacy-fence.mjs,suspend-legacy.mjs,transition-variable.mjs,verify-consumer-routing.mjs}`, `deploy/qts/{adopt-legacy-fence,suspend-legacy}.sh`, tests `tests/operations/{legacy-capture.bats,legacy-fence-adoption.test.mjs,legacy-suspend.test.mjs,transition-variable.test.mjs,consumer-routing.test.mjs}`, and runbooks `docs/operations/{legacy-capture-and-freeze.md,failover-canary-cutover.md}`; modify `cmd/portable-ghar` and `internal/cli/host.go`. The legacy template, validator, Worker dispatch/find implementation, and their correlation/eviction tests are already owned and committed by Task 6.

**Interfaces:** `capture-legacy.sh --overlay <root> --manifest <private-json> --output <private-archive>`; `adopt-legacy-fence.mjs --overlay <root> --manifest <private-json> --evidence-out <private-json>` invokes only `portable-ghar adopt legacy-fence`; `suspend-legacy.mjs --overlay <root> --manifest <private-json> --hosted-confirmation <private-json> --consumer-proof <private-json> --evidence-out <private-json>` invokes only `portable-ghar suspend legacy`; both host commands positively match QTS, use the fixed captured action allowlist, and return only after process/watchdog/holder read-back. `transition-variable.mjs create-hosted|read-back --overlay <root> (--repository-alias <alias>|--all-configured)` prints no identifiers or secret values; it has no delete-to-legacy behavior. `verify-consumer-routing.mjs --overlay <root> --expect hosted|self-hosted|legacy [--dispatch-proof] --evidence-out <private-json>` verifies current default-branch head, configured workflow blob/content digests, exact job IDs/check names/routing expression/attestation step, all three routing-variable read-backs, and an exact-head successful route-proof run with the expected `runner.environment`. The dedicated legacy canary uses canonical `LegacyCanaryIdentity`/`LegacyCanaryRun`; dispatch/find persists exact head, run ID, fence generation, evidence digest, scalar expected legacy label, conclusion, runner environment, and attestation before `/v1/admin/legacy-recovery` may succeed. Direct variable writes are allowed only before Worker bootstrap or for the one-time all-candidate hosted bootstrap; routine expansion and governed legacy recovery use Worker authority, and the tool refuses concurrent normal Worker authority.

- [ ] Write failing tests requiring fresh live inputs for controller/supervisor scripts, image digests, config, watchdog/cron, external watcher, credential references, writer state, and routes; encrypted archive plus SHA-256 manifest; QTS-only fence adoption at an idle point; stable `legacy` header plus one holder per launcher/watchdog; target-safe suspension only after hosted confirmation plus exact-head hosted consumer proof; zero legacy processes/listeners and fence `none` on return; hosted route/companion create/read-back with no delete-to-legacy path; missing/empty/unknown route resolving to `ubuntu-latest`; exact scalar self-hosted scale-set and unique legacy label; current default-branch/workflow blob/content/job/check/route-attestation bindings; successful `runner.environment=github-hosted` proof before suspension; stable required-check names; scalar GitHub.com scale-set canary name; a separate permissions-empty/no-checkout/no-secret legacy-recovery template whose `runs-on` is exactly `${{ vars.PORTABLE_GHAR_LEGACY_LABEL }}` and whose attestation requires `runner.environment=self-hosted`; exact-head dispatch/run correlation; persisted run ID/fence generation/evidence digest/expected label/conclusion; rejection of stale/wrong-head/wrong-label/wrong-environment/failed-attestation runs; monotonic private configuration revision; Worker-owned addition of a new repository as unconfirmed-hosted under hold; persisted per-expansion and legacy-recovery canary identities; and rejection when a legacy writer or routine operator tool claims any Worker-owned routing variable.
- [ ] Add gate-order fixtures proving both Portable and legacy acquisition stay zero until every latest-transition queue-risk row clears; a status success followed by a newer hosted transition cannot authorize a local CLI mode, Portable operation, or legacy process; every nonzero Portable effect has one live exact Worker permit and every work-accepting legacy wrapper has one renewable exact Worker lease; hosted intent/queue risk waits for prior authority to drain; persisted legacy-canary identity includes exact expected revision and legacy label; and a newer hosted transition invalidates prior clear/canary evidence.
- [ ] Run `bats tests/operations/legacy-capture.bats` and `node --test tests/operations/legacy-fence-adoption.test.mjs tests/operations/legacy-suspend.test.mjs tests/operations/transition-variable.test.mjs tests/operations/consumer-routing.test.mjs`; expect missing scripts/runbooks.
- [ ] Implement public tooling against typed private manifests, fixed command allowlists, `umask 077`, temporary-file cleanup, encryption-before-retention, and sanitized summaries. Document order: live capture; decrypt/list/hash rehearsal; freeze legacy configuration changes without retiring its watcher; initialize the stable fence with `legacy` active and wrap the live legacy launchers/watchdogs; register Portable GHAR scale sets disabled; deploy the force-disabled observer after normalizing persisted acquisition to a new disabled/empty/zero epoch; merge the exact scalar three-state consumer expression/attestation plus the separately bound legacy-recovery canary without renaming job IDs/checks; enable/read back the Worker hosted hold; increment private `configRevision`, render/redeploy, and wait for `reconcileConfiguration` to add every repository unconfirmed-hosted and read back hosted plus both companions; re-read each current default-branch workflow binding and dispatch/observe the exact-head hosted proof; only then stop legacy acquisition while hosted; atomically hand the fence through `none` to `portable` and start Portable disabled; prove the legacy watchdog cannot reacquire; clear every latest-transition queue-risk row through authenticated GitHub read-back/selective recovery while acquisition remains zero; install the secretless Portable canary with one scalar private scale-set name; transition through the bounded policy barrier to `canary-only` for exactly that scale set and one capacity unit; release the hold into a new recovery epoch; run the canary while routing stays hosted; enable full acquisition and wait for a fresh enabled/full-capacity heartbeat before self-hosted intent; prove lifecycle/isolation/recovery/hosted fallback/email/webhook and matching Signal receipt; expand later by reacquiring the hold, transitioning acquisition to disabled, updating config/workflow/canary revision, redeploying/reconciling hosted, clearing the new queue-risk generation, and repeating the exact-head route proof plus epoch canary plus enabled-heartbeat gate while sensitive jobs stay hosted. Routine expansion never writes a routing variable directly.
- [ ] Re-run the same commands; expect all PASS, target identity/read-back proof, and a fixture proving the transition variable is untouched by legacy writers.
- [ ] Commit: `git add scripts/ops deploy/qts cmd/portable-ghar internal/cli/host.go tests/operations docs/operations && git commit -S -m "ops: define fenced legacy capture and canary cutover"`.

### Task 12: Retire Legacy with Typed Tools and Rehearse Mutually Exclusive Rollback

**Files:** Create `docs/operations/failover-failure-drills.md`, `tests/operations/{failure-drills.test.mjs,signal-receipt.test.mjs,retire-legacy.test.mjs,verify-legacy-retired.test.mjs}`, `tests/shell/qts/legacy-retirement.bats`, `tests/fixtures/failover/drill-pass.json`, `config/schema/{failover-evidence.schema.json,legacy-retirement-manifest.schema.json}`, `config/examples/legacy-retirement-manifest.example.json`, `scripts/ops/{record-drill.mjs,record-signal-receipt.mjs,retire-legacy.mjs,verify-legacy-retired.mjs}`, `deploy/qts/{retire-legacy,verify-legacy-retired}.sh`; modify `cmd/portable-ghar` and `internal/cli/host.go`.

**Interfaces:** Each drill emits `{drillId, transitionEpoch, startedAt, completedAt, expectedSafeRoute, observedSafeRoute, readBackConfirmed, result}`. `node scripts/ops/record-drill.mjs --overlay <root> --drill <allowlisted-id> --evidence-out <private-json>` records live typed evidence and prints only `failure drill: PASS|FAIL`; fixture mode is `--fixture <synthetic-json> --evidence-out <path>`. `node scripts/ops/record-signal-receipt.mjs --overlay <root> --receipt <private-json> --evidence-out <private-json>` verifies the separate delivery-receipt HMAC, event correlation, timestamp, destination-ack digest, and `runnerHost:false`, then prints only `signal receipt: PASS|FAIL`. `node scripts/ops/retire-legacy.mjs --overlay <root> --manifest <private-json> --evidence-out <private-json>` invokes only `portable-ghar retire legacy --private PATH --manifest PATH --hosted-confirmation PATH` through the verified management channel and prints only `legacy retirement: PASS|FAIL`; verification similarly invokes `portable-ghar verify legacy-retired` and prints only `legacy retired: PASS|FAIL`.

- [ ] Write failing content/schema tests requiring stale heartbeat, fatal state, controller death, Docker restart/loss, host outage, uplink loss, GitHub timeout/rate-limit/partial success, email-only/webhook-only/both failures, matching HMAC-verified end-to-end Signal receipt, receipt replay/mismatch/same-host rejection, failed/late canary, DO reschedule, generation-fence renewal failure, simultaneous watchdog race, and complete rollback rehearsal. Retirement tests require positive QTS target identity, refusal on Darwin/non-QTS, soak proof, hosted-safe barrier, typed private manifest, current `none` fence, legacy acquisition denial, legacy watcher/writer/process/container/registration absence, credential revocation evidence, and retained encrypted artifacts.
- [ ] Require rollback fixtures to keep the fence at `none` and both acquisition paths at zero until exact latest-transition queue-risk recovery completes; any open, stale, superseded, or ambiguous row blocks legacy restore/canary.
- [ ] Run `node --test tests/operations/failure-drills.test.mjs tests/operations/signal-receipt.test.mjs tests/operations/retire-legacy.test.mjs tests/operations/verify-legacy-retired.test.mjs` and `bats tests/shell/qts/legacy-retirement.bats`; expect missing drill/receipt schema and target-safe retirement coverage.
- [ ] Implement typed retirement tools without accepting arbitrary shell strings: the Node orchestrators validate overlay/evidence and call only the fixed host CLI subcommands; the CLI positively matches the target; target scripts revalidate Linux/QTS identity and select only enumerated adapter actions/secret references. Require post-action process/container/cron/writer/registration/fence read-back before PASS. Document positive observations for every drill. Rollback order is exact: enable the Worker hosted hold and read back every repository hosted with current workflow bindings and companions; stop new acquisition; journaled suspend to `none`; prove zero new listeners/runner/adapter/held-or-running-broker/helper/verifier containers, per-job relay/dial-authority socket directories, broker dials, and pending acquisition while stable slot ledgers remain retained/non-refilled through `T`; while the fence is `none` and all local acquisition is zero, clear every latest-transition queue-risk row through authenticated GitHub read-back/selective recovery; only then atomically hand `none` to `legacy` and restore captured legacy components through wrappers that compose the local fence with the current short Worker process lease; prove the new watchdog cannot reacquire and a denied/missed renewal terminates legacy before drain; prove legacy egress and advancing health; dispatch and persist a secretless exact-head legacy canary with matching revision/scalar label, run ID, fence generation, evidence digest, `runner.environment=self-hosted`, and successful attestation; then submit the authenticated `/v1/admin/legacy-recovery` request with the same expected fence generation/evidence digest and read back explicit `PORTABLE_GHAR_ROUTE=legacy` plus unchanged expected companions. Never delete the variable or treat absence as legacy. Any dual-fleet holder, missing/expired Worker lease, open latest queue-risk row, lost hosted hold before the governed transition, target mismatch, workflow-binding/companion drift, obsolete canary, or wrapper bypass fails immediately; later unhealthy legacy state revokes/drains acquisition authority before automatically returning hosted.
- [ ] Run all tests above plus `bats tests/shell/qts/fleet-fence.bats tests/operations/legacy-capture.bats`; then run `node scripts/ops/record-drill.mjs --fixture tests/fixtures/failover/drill-pass.json --evidence-out /tmp/portable-ghar-drill.json`; expect PASS, one schema-valid record, fenced mutual exclusion, target-safe adapter proof, and no mutation outside fixtures or `/tmp`.
- [ ] Commit: `git add docs/operations/failover-failure-drills.md tests/operations tests/shell/qts/legacy-retirement.bats config/schema scripts/ops deploy/qts cmd/portable-ghar internal/cli/host.go && git commit -S -m "ops: add failover and target-safe rollback drills"`.

### Task 13: Enforce the 14-Day Soak, Retirement Gates, 30-Day Retention, and Final Positive Verification

**Files:** Create `scripts/ops/{collect-soak-evidence.mjs,verify-retirement-gates.mjs}`, tests `tests/operations/{soak-evidence.test.mjs,retirement-gates.test.mjs}`, runbooks `docs/operations/{failover-soak-and-retirement.md,failover-final-verification.md}`; modify `README.md` only after the live final gate passes.

**Interfaces:** `node scripts/ops/collect-soak-evidence.mjs --overlay <root> --day <UTC-date>` creates one schema-valid private record and prints only `soak evidence: PASS|FAIL`; `node scripts/ops/verify-retirement-gates.mjs --phase soak|pre-retire|final --overlay <root> --as-of <RFC3339>` prints only `retirement gates: PASS|FAIL`.

- [ ] Write failing tests for exactly 14 consecutive complete UTC days; no unexplained evaluation gap over two minutes; continuous per-holder generation-fence renewals with no dual fleet; heartbeat freshness below stale threshold outside annotated drills; zero unconfirmed route claimed successful; zero self-hosted confirmation without both current-epoch canary and a later same-epoch enabled/full-capacity heartbeat; durable queue-risk rows until verified selective recovery and zero Portable/legacy acquisition while any latest row is open; no overdue/unclaimed due work without an alarm; all drills passed; Worker/DO persistence; primary email delivery; signed-webhook recipient skew/replay/dedupe proof; matching HMAC-verified Signal receipt from a separate failure domain; rollback rehearsal; verified legacy retirement; archive decrypt/hash; and `retention_until >= retired_at + 30 days`.
- [ ] Run `node --test tests/operations/soak-evidence.test.mjs tests/operations/retirement-gates.test.mjs`; expect missing collectors/gates.
- [ ] Implement sanitized daily collection and fail-closed gates. Any missing day, unexplained gap, fence lapse/dual-fleet holder, route divergence, obsolete-canary acceptance, overdue/unowned due work, failed drill, HTTP-only webhook evidence, unsigned/mismatched receipt, same-host bridge, or unverifiable archive resets the soak. Existing operator authorization satisfies retirement approval. Enable and verify the hosted hold first; `--phase pre-retire` then requires the complete soak/drill/archive/receipt evidence plus hosted read-back. After it passes, invoke target-safe typed retirement, verify legacy is absent and fenced out, revoke only obsolete credentials not required for the retained recovery procedure, remove legacy containers/images only after backup verification, and retain encrypted rollback material through `retention_until`. Release the hold only into a new recovery epoch and after the Portable GHAR fence/disabled-controller state is read back.
- [ ] Under the existing authorization and after target/account re-verification, force stale and fatal failover with hosted/companion read-back; reconcile an ambiguous mutation; prove durable queue-risk plus exact selective-recovery clearing; prove email plus matching Signal receipt through the separate-domain bridge; recover through a current-epoch expected-revision canary while hosted, enable full acquisition, observe the same-epoch enabled/full-capacity heartbeat, then read back self-hosted; prove DO persistence and continuous fencing. Run `node scripts/ops/verify-retirement-gates.mjs --phase pre-retire --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"`; expect `retirement gates: PASS`. Run `node scripts/ops/retire-legacy.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-retirement.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-retirement.json"`; expect `legacy retirement: PASS`. Run `node scripts/ops/verify-legacy-retired.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-retirement.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-retired-verification.json"`; expect `legacy retired: PASS`. Run `node scripts/ops/verify-retirement-gates.mjs --phase final --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"`; expect `retirement gates: PASS`.
- [ ] Only after that command returns `retirement gates: PASS`, update `README.md` to replace “implementation not started” with the exact publicly verified capabilities, experimental preview status, container-grade isolation boundary, GitHub API residual risk, and link to public runbooks. Run `scripts/verify-failover.sh`, `git diff --check`, and `rg -n 'example-fleet|owner/repository|operator@example.invalid' README.md docs/operations`; expect all tests PASS, clean diff, and no deployment identity.
- [ ] Commit: commit source/runbooks first with `git add scripts/ops tests/operations docs/operations config/schema && git commit -S -m "ops: gate failover retirement on reliability evidence"`. After live PASS, commit README separately with `git add README.md && git commit -S -m "docs: record verified failover deployment status"`.

## Final Positive Verification Checklist

- [ ] `scripts/verify-failover.sh` passes from a clean checkout on GitHub-hosted CI.
- [ ] Challenge/admin timestamp bounds and nonce-digest replay rejection pass; enrollment state survives Worker rescheduling; controller state loss produces a newer server epoch; old session and replay traffic are rejected.
- [ ] Bootstrap creates and reads back hosted for every repository before recovery observation or canary.
- [ ] Authenticated hosted hold enters safely from every state, survives Worker rescheduling/redeploy, blocks recovery until all repositories read back hosted, and releases only into a new recovery epoch.
- [ ] Stale and fatal health create persisted per-repository hosted intents before API calls, then read back every configured repository as hosted.
- [ ] Partial and ambiguous GitHub results reconcile idempotently without duplicate success claims.
- [ ] Cron and Durable Object alarm jointly guarantee every persisted due mutation, canary, and notification row is claimed/retried after eviction or crash; no due row relies on a future request.
- [ ] Email and signed webhook share the same sanitized event ID and fail independently; the recipient enforces skew/replay/dedupe, and matching Signal receipt is HMAC-verified from a separate-domain bridge rather than inferred from HTTP `2xx`.
- [ ] Recovery stays hosted until the current transition epoch and expected revision canary passes; obsolete results are ignored.
- [ ] The canary uses one scalar GitHub.com scale-set name, never a label array.
- [ ] Live legacy capture decrypts and matches its manifest; the continuously renewed generation fence proves zero concurrent new/legacy acquisition under watchdog races.
- [ ] Fourteen consecutive complete UTC days satisfy every reliability gate and include all required failure/rollback drills.
- [ ] Retirement evidence records `retired_at` and `retention_until` at least 30 days later; encrypted rollback artifacts remain present and verified.
- [ ] `verify-legacy-retired.mjs` confirms legacy writers/watchdogs/processes/containers are absent, obsolete credentials are revoked, and the legacy generation cannot acquire the fence.
- [ ] README describes only the post-deployment public truth after all preceding checks pass.
