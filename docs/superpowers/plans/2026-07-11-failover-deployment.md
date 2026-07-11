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
- Persist transition intent and one outbox row per repository before GitHub mutation. Confirm each repository independently with read-back; timeout, rate limit, partial success, and ambiguity remain unconfirmed until reconciled.
- GitHub API unavailability preserves desired state and the last confirmed route; it never becomes a successful failover claim.
- `hosted` is always the safe route. A missing, failed, late, or superseded canary cannot fail back.
- Bootstrap must create and read back `PORTABLE_GHAR_ROUTE=hosted` for every repository before recovery observations or any canary; it can never transition directly from `BOOTSTRAP` to healthy self-hosted.
- An authenticated Worker-owned hosted hold is the only supported maintenance, upgrade, and retirement freeze. Enabling it persists hosted transition intent, blocks recovery, and requires per-repository read-back; releasing it starts a new recovery epoch and still requires a current-epoch canary. A direct transition-variable write is limited to bootstrap, the one-time all-candidate hosted transition, or emergency/legacy recovery and is never treated as a durable hold.
- Routing-variable changes affect newly evaluated jobs only; never migrate, cancel, or duplicate an already assigned hosted job merely because a later job routes self-hosted.
- A canary is bound to the active transition epoch and exact expected revision. Failure requires a new operator recovery epoch; no automatic bypass exists.
- A canary workflow uses exactly one scalar GitHub.com scale-set name in `runs-on`; arrays and `[self-hosted, label]` syntax are prohibited.
- Email and webhook are independent persisted outboxes. Notification failure never blocks or reverses routing.
- Use a native Cloudflare Email Service binding restricted to configured sender and destination addresses. The only public secondary adapter is a generic HTTPS webhook signed over timestamp, event ID, and exact body; recipients enforce timestamp skew, replay rejection, and event-ID deduplication.
- Private deployment completion requires observed end-to-end Signal receipt through a webhook bridge on a failure domain separate from the QTS runner host. HTTP `2xx` alone is not delivery proof, and neither the Worker nor bridge may add an inbound endpoint to the runner host.
- The Signal receipt key is distinct from the webhook-delivery key, absent from the Worker and QTS host, and readable only by the separate-domain bridge plus private evidence verifier. Key loss, rotation ambiguity, or compromise invalidates Signal evidence and restarts the soak; it cannot change routing state.
- Keep controller and failover GitHub Apps separate. The failover App has repository-variable read/write, Metadata read, and Actions read/write only for automatic canaries; it has no Contents, Pull requests, Administration, Issues, Deployments, Secrets, or broader access.
- GitHub REST requests use `X-GitHub-Api-Version: 2026-03-10`.
- Pin Worker tooling exactly to TypeScript `6.0.3`, Vitest `4.1.10`, `@cloudflare/vitest-pool-workers` `0.18.4`, Wrangler `4.110.0`, ESLint `10.7.0`, `@eslint/js` `10.0.1`, and `typescript-eslint` `8.63.0`; ranges, peer-range violations, and floating versions are prohibited.
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
- The operator's current authorization satisfies the implementation, deployment, rollback-drill, and retirement go/no-go for this scope; do not add a redundant approval round-trip. Stop on target/account mismatch, new scope, architecture ambiguity, or failed gate.
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

Public enrollment/health endpoints are `POST /v1/enrollment/challenge`, `POST /v1/enrollment/complete`, and `POST /v1/heartbeat`. Disabled-by-default administrative endpoints are `POST /v1/admin/recovery`, `POST /v1/admin/hosted-hold`, and `POST /v1/admin/status`; they use the separate administrative HMAC key, the same timestamp/nonce anti-replay rules, and generic rejection responses. Requests use `Content-Type: application/json`, `X-Portable-GHAR-Key-Id`, `X-Portable-GHAR-Timestamp: <unix-seconds>`, and `X-Portable-GHAR-Signature: v1=<base64url-mac>`. Signed bytes are:

```text
portable-ghar-request-v1\n
<UPPERCASE_METHOD>\n
<PATH_ONLY>\n
<UNIX_SECONDS>\n
<EXACT_UTF8_BODY>
```

Challenge bodies include a random 32-byte base64url `requestNonce`; the Worker accepts timestamps within 300 seconds, verifies HMAC before Durable Object access, stores only the nonce digest, and atomically rejects reuse. Enrollment completion consumes its random server challenge exactly once. Admin recovery bodies also include a random nonce, use a separate HMAC key, enforce the same 300-second skew, and atomically reject nonce reuse. Invalid/replayed requests return `404 {"error":"request_rejected"}`. An authenticated stale heartbeat sequence returns `409 {"error":"re_enrollment_required"}` without epoch/sequence details. `PORTABLE_GHAR_ROUTE` has only `hosted` and `self-hosted`; bootstrap creates it as hosted and reads it back before canary work.

```typescript
export interface HeartbeatV1 {
  protocol: "portable-ghar.heartbeat.v1";
  fleetId: string; epoch: number; sessionId: string; sequence: number;
  clientObservedAt: string; // diagnostic only
  acquisitionState: "disabled" | "canary-only" | "enabled" | "fatal";
  capacity: { availableUnits: number; totalUnits: number };
  assignedJobs: number; oldestAssignmentAgeSeconds: number | null;
  lastTerminalJobAt: string | null; hostProfileId: string;
  degradedProfile: boolean; controllerBuildId: string;
  fatalReasonCode?: "compatibility_failed" | "host_profile_failed" | "state_ambiguous";
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

export interface AdminRecoveryRequestV1 {
  protocol: "portable-ghar.admin.recovery.v1";
  fleetId: string; requestNonce: string; reasonCode: string;
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

export interface RepositoryConfig {
  alias: string; owner: string; repository: string;
  installationIdRef: string; notificationAlias: string;
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

export interface FleetConfig {
  fleetId: string; keyId: string;
  configRevision: number; configDigest: string;
  challengeTtlSeconds: number;
  staleAfterSeconds: number; unhealthyEvaluations: number;
  recoveryHealthyEvaluations: number;
  transitionVariable: "PORTABLE_GHAR_ROUTE";
  canary: CanaryPolicy;
  repositories: RepositoryConfig[];
  notifications: { email: true; webhook: boolean };
}

export interface EvaluationResult {
  state: "BOOTSTRAP" | "HEALTHY_SELF_HOSTED" | "SUSPECT" |
    "FAILOVER_PENDING" | "HOSTED_CONFIRMED" | "RECOVERY_OBSERVED" |
    "CANARY_PENDING" | "CANARY_PASSED" | "SELF_HOSTED_CONFIRMED";
  route: "hosted" | "self-hosted";
  transitionEpoch: number; workQueued: boolean;
}

export interface AdministrativeStatus {
  state: EvaluationResult["state"]; route: "hosted" | "self-hosted";
  configRevision: number; configDigest: string;
  transitionEpoch: number; enrollmentEpoch: number; lastSequence: number;
  heartbeatFresh: boolean;
  acquisitionState: HeartbeatV1["acquisitionState"] | "unobserved";
  hostedHold: boolean;
  currentEpochCanaryPassed: boolean;
  repositoryCount: number; repositoriesConfirmed: boolean;
  outboxesCurrent: boolean;
}

export interface FleetCoordinator {
  claimRequestNonce(input: { digest: string; purpose: "challenge" | "admin-recovery" | "admin-hosted-hold" | "admin-status"; seenAtMs: number; expiresAtMs: number }): Promise<{ accepted: true }>;
  issueChallenge(input: { challengeDigest: string; requestNonceDigest: string; issuedAtMs: number; expiresAtMs: number }): Promise<void>;
  completeEnrollment(input: { challengeDigest: string; requestNonceDigest: string; sessionId: string; nowMs: number }): Promise<{ epoch: number; sessionId: string }>;
  acceptHeartbeat(input: { heartbeat: HeartbeatV1; receivedAtMs: number }): Promise<{ accepted: true }>;
  reconcileConfiguration(input: { config: FleetConfig; nowMs: number }): Promise<{ configRevision: number; configDigest: string; repositoriesConfirmed: boolean }>;
  evaluate(input: { nowMs: number; config: FleetConfig }): Promise<EvaluationResult>;
  processDueWork(input: { nowMs: number; config: FleetConfig; maxItems: number }): Promise<{ processed: number; nextDueAtMs: number | null }>;
  startRecoveryEpoch(input: { reasonCode: string; nowMs: number }): Promise<{ transitionEpoch: number }>;
  setHostedHold(input: { enabled: boolean; reasonCode: string; nowMs: number }): Promise<{ transitionEpoch: number }>;
  administrativeStatus(input: { nowMs: number; config: FleetConfig }): Promise<AdministrativeStatus>;
}

export interface GitHubPort {
  readRoute(repository: RepositoryConfig): Promise<"hosted" | "self-hosted" | "missing">;
  writeRoute(repository: RepositoryConfig, route: "hosted" | "self-hosted"): Promise<void>;
  dispatchCanary(input: CanaryDispatch): Promise<void>;
  findCanary(input: CanaryIdentity): Promise<CanaryRun | null>;
}
```

`Env` is generated by `wrangler types`, never hand-written. The rendered configuration must generate exact bindings/vars for `FLEETS`, `EMAIL`, `FLEET_CONFIG_JSON`, `HEARTBEAT_HMAC_KEYS_JSON`, `FAILOVER_GITHUB_APP_ID`, `FAILOVER_GITHUB_PRIVATE_KEY`, optional `WEBHOOK_HMAC_KEY`, `ADMIN_RECOVERY_ENABLED`, and optional `ADMIN_SERVICE_HMAC_KEY`. Secret-bearing entries are installed as Worker secrets rather than plain `vars`; tests compare the generated declaration to the rendered schema.

The public webhook contract signs `<unix-seconds>.<eventId>.<exactBody>`. A conforming recipient must verify the MAC in constant time, reject timestamps outside 300 seconds, atomically claim the event ID/replay digest before side effects, retain that claim for at least the sender retry horizon, and return the same success response for a duplicate already accepted event without delivering it twice. After destination acknowledgment, the separate-domain bridge emits a delivery receipt signed with a different private receipt key over `<unix-seconds>.<eventId>.<exactReceiptBody>`; the strict body is `{eventId,channel:"signal",deliveredAt,destinationAckDigest,failureDomainClass,runnerHost:false}`. Public code defines and verifies this generic receipt contract but does not implement Signal transport or contain destination identity.

## Persistent State Contract

`worker/src/fleet/schema.ts` creates these tables in the SQLite-backed object. Schema initialization is idempotent, and all enum values are checked in application code before writes.

```sql
fleet_state(
  singleton PRIMARY KEY, active_epoch, active_session_id, last_sequence,
  last_heartbeat_received_at_ms, last_heartbeat_json, health_state,
  route_state, hosted_hold, hosted_hold_reason_code,
  consecutive_unhealthy, consecutive_healthy,
  transition_epoch, transition_lock, recovery_blocked,
  config_revision, config_digest, canary_config_json, last_evaluated_at_ms
)
challenges(
  challenge_digest PRIMARY KEY, request_nonce_digest UNIQUE,
  issued_at_ms, expires_at_ms, consumed_at_ms
)
request_nonces(
  nonce_digest PRIMARY KEY, purpose, seen_at_ms, expires_at_ms,
  CHECK(purpose IN ('challenge', 'admin-recovery', 'admin-hosted-hold', 'admin-status'))
)
repositories(
  alias PRIMARY KEY, owner, repository, installation_id_ref, variable_name,
  desired_route, confirmed_route, confirmed_at_ms,
  config_revision, onboarding_state, UNIQUE(owner, repository)
)
transitions(
  event_id PRIMARY KEY, transition_epoch UNIQUE, kind, reason_code,
  status, created_at_ms, completed_at_ms
)
github_outbox(
  id PRIMARY KEY, event_id, transition_epoch, repository_alias, desired_route,
  request_fingerprint, status, claim_id, claim_expires_at_ms,
  attempt_count, next_attempt_at_ms,
  last_http_status, last_error_code, created_at_ms, updated_at_ms,
  UNIQUE(transition_epoch, repository_alias, desired_route)
)
canaries(
  transition_epoch PRIMARY KEY, event_id, repository_alias, workflow,
  expected_revision, github_run_id, status, claim_id, claim_expires_at_ms,
  next_check_at_ms, dispatched_at_ms, completed_at_ms
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

Challenge issuance and every administrative request first use one synchronous transaction to reject an existing nonce digest and insert the new digest with its bounded expiry. Enrollment rotation uses a separate synchronous transaction: require one live unconsumed challenge digest bound to the supplied initiating request-nonce digest, mark it consumed, increment `active_epoch`, replace `active_session_id`, reset `last_sequence` to `0`, clear prior heartbeat freshness, and append a sanitized audit event. Configuration reconciliation is transactional: require `configRevision == previous+1` and a canonical SHA-256 `configDigest`; the same revision with a different digest fails. Add new repositories only while a hosted hold is active; insert them unconfirmed-hosted and queue Worker-owned hosted mutation/read-back; persist the exact canary repository/workflow/revision; reject identity mutation, removal, revision skip/rollback, or digest mismatch outside explicit retirement. Transition creation also uses one synchronous transaction: increment/lock `transition_epoch`, insert the transition, set each repository's desired route, insert exactly one GitHub outbox row per repository, and insert independent email/webhook rows. Enabling a hosted hold performs that hosted transition in the same state transaction and blocks recovery; disabling it clears the hold, increments the recovery epoch, and remains hosted until the new epoch's canary passes. No network call or `await` occurs inside these transactions.

Outbox status values are `pending`, `processing`, `retry_wait`, `confirmed`, and `permanent_failure`. Due-work processing transactionally claims a bounded row batch with a random claim ID and expiry, performs no network I/O inside the claim transaction, then commits an outcome only when the claim ID still matches. Expired claims return to due work. A GitHub row reaches `confirmed` only after GET read-back equals `desired_route`; an HTTP success alone is insufficient. Crash after an ambiguous GitHub mutation retries through read-back before any write. Notification delivery may duplicate after a crash; the shared event ID makes webhook recipients idempotent and makes email duplicates recognizable. Notification `permanent_failure` remains visible but cannot change routing state. Expired request nonces and consumed challenges are pruned only after their acceptance/replay windows plus a safety margin; sanitized audit events remain. Audit retention is bounded only after the same rows are present in a verified private evidence bundle; active transitions and outboxes are never pruned.

Each Durable Object owns one alarm. All producers call `ensureAlarmNoLaterThan(candidateMs)` before committing a SQL state change that creates or moves due work. That helper uses `DurableObjectStorage.transaction`, reads `txn.getAlarm()`, and sets only an absent or earlier candidate, so concurrent cron/request/alarm scheduling can never overwrite an earlier wake-up with a later one. A crash after arming but before the SQL commit creates only a harmless spurious alarm; a committed due row cannot exist without an equal-or-earlier alarm. Cron reconciles configuration, evaluates health, calls a bounded `processDueWork`, and applies the same rule. The alarm performs the same bounded claim/process/reconcile loop, catches downstream outages, and arms the next attempt before committing its retry timestamp; it never depends on a future request or the next cron tick to finish hosted holds, GitHub mutations, canary dispatch/polling, or notification retries. Alarm and cron overlap is safe through the transactional minimum, claim IDs/expiry, and idempotent read-back.

## Failover State Contract

```text
BOOTSTRAP
  -> HOSTED_CONFIRMED
  -> RECOVERY_OBSERVED
  -> CANARY_PENDING
  -> CANARY_PASSED
  -> SELF_HOSTED_CONFIRMED
  -> HEALTHY_SELF_HOSTED
HEALTHY_SELF_HOSTED
  -> SUSPECT
  -> FAILOVER_PENDING
  -> HOSTED_CONFIRMED
  -> RECOVERY_OBSERVED
  -> CANARY_PENDING
  -> CANARY_PASSED
  -> SELF_HOSTED_CONFIRMED
  -> HEALTHY_SELF_HOSTED
```

- `BOOTSTRAP` creates a hosted mutation intent for every repository and cannot advance until each repository reads back hosted; only then does it enter `HOSTED_CONFIRMED`.
- First stale evaluation from healthy records `SUSPECT`; the second creates a hosted transition. An authenticated fatal heartbeat may create that transition immediately.
- `HOSTED_CONFIRMED` requires every repository row confirmed hosted; partial success remains `FAILOVER_PENDING`.
- A hosted hold may enter from any state, queues hosted intent once, remains held until every repository reads back hosted, and suppresses recovery observations while enabled.
- Sustained healthy observations move toward `CANARY_PENDING` without changing the route.
- Releasing a hosted hold creates a new recovery epoch; it never restores self-hosted directly.
- A failed canary sets `recovery_blocked=1`; only `startRecoveryEpoch` can clear it and create a new epoch.
- `CANARY_PASSED` is valid only for the current epoch, persisted run ID, expected revision, and successful conclusion.
- `SELF_HOSTED_CONFIRMED` requires per-repository self-hosted read-back before returning to healthy.

## Planned File Map

- Worker: modify the foundation workspace's `worker/{package.json,tsconfig.json,vitest.config.ts}` and root `package-lock.json`; create `worker/{eslint.config.js,wrangler.jsonc,wrangler.test.jsonc,worker-configuration.d.ts}` with the declaration file generated only by `wrangler types`.
- Protocol/auth: `worker/src/{config.ts,protocol.ts,index.ts}`, `worker/src/security/hmac.ts`, `internal/failoverclient/{protocol.go,client.go}`; no hand-written binding `Env`.
- Fleet state: `worker/src/fleet/{schema.ts,store.ts,coordinator.ts,evaluator.ts,due-work.ts}`, `worker/src/scheduler.ts`.
- Generation fence: extend `internal/fleetfence/{store,store_unix}.go`, `cmd/portable-ghar-fleet-fence/main.go`, `deploy/qts/run-legacy-fenced.sh`, and `tests/shell/qts/fleet-fence.bats` from the controller-runtime phase.
- GitHub/canary: `worker/src/github/{app-auth.ts,client.ts,mutation-outbox.ts,canary.ts}`.
- Notifications: `worker/src/notifications/{event.ts,email.ts,webhook.ts,outbox.ts}`, `docs/security/signed-webhook-contract.md`, `tests/operations/webhook-recipient-contract.test.mjs`.
- Tests: `worker/test/**/*.test.ts`, `internal/failoverclient/*_test.go`, `internal/health/*_test.go`, `tests/fixtures/failover/hmac-v1.json`, `tests/operations/*`.
- Public config/templates: `config/schema/{failover-deployment.schema.json,failover-evidence.schema.json,secondary-delivery-receipt.schema.json,legacy-retirement-manifest.schema.json}`, `config/examples/{failover-deployment.example.json,secondary-delivery-receipt.example.json,legacy-retirement-manifest.example.json,portable-ghar-canary.workflow.yml,consumer-routing.workflow.yml}`.
- Safety tooling: `scripts/{validate-failover-config.mjs,render-failover-config.mjs,validate-canary-template.mjs,verify-failover.sh}`, `scripts/ops/{assert-private-overlay.sh,capture-legacy.sh,adopt-legacy-fence.mjs,suspend-legacy.mjs,control-plane-admin.mjs,probe-private-deployment.mjs,transition-variable.mjs,record-drill.mjs,record-signal-receipt.mjs,retire-legacy.mjs,verify-legacy-retired.mjs,collect-soak-evidence.mjs,verify-retirement-gates.mjs}`, `deploy/qts/{adopt-legacy-fence,suspend-legacy,retire-legacy,verify-legacy-retired}.sh`, `.gitignore`, `.dockerignore`.
- Docs: `docs/security/failover-permissions.md`, `docs/operations/{failover-deployment.md,legacy-capture-and-freeze.md,failover-canary-cutover.md,failover-failure-drills.md,failover-soak-and-retirement.md,failover-final-verification.md}`, and post-verification `README.md`.

### Task 1: Scaffold Worker Tooling and Strict Public Configuration

**Files:** Modify the foundation workspace files named above; create Worker config/generated-type files, `worker/src/{config.ts,index.ts}`, `worker/test/{scaffold.test.ts,config.test.ts}`, both configuration schema/example files, validation/render scripts, and private-artifact patterns in `.gitignore`/`.dockerignore`.

**Interfaces:** `loadFailoverConfig(raw: string): FailoverConfig`; `renderPrivateConfig(config, secretRefs, outputPath): Promise<void>` writes mode `0600` and returns no values; `node scripts/validate-failover-config.mjs --config <json>` prints only `failover configuration: PASS|FAIL`; `node scripts/render-failover-config.mjs --overlay <root> --output <root>/rendered/wrangler.jsonc` prints only `failover render: PASS|FAIL`.

- [ ] Write failing tests `returns_generic_404`, `rejects_unknown_nested_fields`, `rejects_inline_secret_fields`, `rejects_duplicate_fleet_or_repo_alias`, `requires_repository_variable_name`, `pins_worker_dependencies_exactly`, `satisfies_peer_ranges`, `generated_env_matches_config`, `private_path_must_be_outside_git`, and `render_prints_no_values`.
- [ ] Run `npm run --workspace worker test -- scaffold.test.ts config.test.ts`; expect FAIL for missing modules. Run `node --test tests/operations/failover-config.test.mjs`; expect FAIL for missing validator.
- [ ] Install only the missing pool dependency through the root workspace lock: `npm install --workspace worker --save-dev --save-exact @cloudflare/vitest-pool-workers@0.18.4`. Preserve the foundation's exact TypeScript `6.0.3`, Vitest `4.1.10`, Wrangler `4.110.0`, ESLint `10.7.0`, `@eslint/js` `10.0.1`, and `typescript-eslint` `8.63.0`; assert published peer ranges and every exact dependency string. Create strict parsers with `additionalProperties: false` at every schema level. Public Wrangler config contains only a synthetic name, `compatibility_date: "2026-07-10"`, `nodejs_compat`, generated binding types, and sanitized observability; it contains no account, route, address, or secret. Rendered production config exists only below the validated overlay root and restricts both email sender and destination.
- [ ] Run `npm ci --ignore-scripts`, `npm run --workspace worker lint`, `npm run --workspace worker typecheck`, `npm run --workspace worker types:check`, and `npm run --workspace worker test -- scaffold.test.ts config.test.ts`, then `node scripts/validate-failover-config.mjs --config config/examples/failover-deployment.example.json`; expect all PASS and only `failover configuration: PASS` on validator stdout.
- [ ] Commit: `git add package-lock.json worker config scripts .gitignore .dockerignore tests/operations/failover-config.test.mjs && git commit -S -m "worker: scaffold failover configuration"`.

### Task 2: Add Exact-Body HMAC and the Controller Enrollment Client

**Files:** Create `worker/src/{protocol.ts,security/hmac.ts}`, `worker/test/hmac.test.ts`, `tests/fixtures/failover/hmac-v1.json`, and `internal/failoverclient/{protocol.go,protocol_test.go,client.go,client_test.go}`.

**Interfaces:** TypeScript `signatureInput(method, path, unixSeconds, body): Uint8Array`, `verifyRequestMac(key, header, input): Promise<boolean>`; Go `SignatureInput(method, path string, unixSeconds int64, body []byte) []byte`, `Client.Enroll(ctx)`, `Client.Publish(ctx, Snapshot)`, and in-memory `{epoch,sessionID,nextSequence}`.

- [ ] Write failing cross-language tests for the same synthetic vector, one-byte body/path/timestamp/MAC mutations through the exact signature-input functions, malformed base64url, short keys, challenge request timestamps at `now±300s` accepted and `now±301s` rejected, duplicate request-nonce rejection, challenge/request-nonce mismatch, completion replay, response-loss sequence ambiguity, state loss, and re-enrollment. Assert TypeScript calls `crypto.subtle.verify` and Go uses `hmac.Equal`.
- [ ] Run `npm run --workspace worker test -- hmac.test.ts`; expect missing HMAC symbols. Run `go test ./internal/failoverclient -run 'Test(HMAC|Enrollment|Reenrollment)' -count=1`; expect missing client symbols.
- [ ] Implement the locked timestamped framing, strict raw base64url decoding, 32-byte keys/MACs, client-generated random 32-byte request nonce, server-generated random 32-byte single-use challenge bound to that nonce digest, `EnrollmentCompleteRequestV1` carrying the same nonce plus challenge and a client-generated random 16-byte session ID, server epoch response, sequence starting at `1`, and one bounded re-enrollment attempt after authenticated `409`. Verify HMAC before claiming the initial request nonce; completion atomically verifies the bound pair and consumes the challenge exactly once. Never persist server epoch locally or log bodies, timestamps, nonces, headers, keys, challenge, session, or MAC.
- [ ] Run both commands again plus `go test -race ./internal/failoverclient`; expect shared-vector PASS, every mutation rejected, and no race.
- [ ] Commit: `git add worker/src/protocol.ts worker/src/security worker/test/hmac.test.ts tests/fixtures/failover internal/failoverclient && git commit -S -m "failover: add authenticated enrollment client"`.

### Task 3: Persist Epoch, Challenge, Session, Sequence, and Heartbeats in One SQLite Object per Fleet

**Files:** Modify both Wrangler configs, generated `worker/worker-configuration.d.ts`, and `worker/src/index.ts`; create `worker/src/fleet/{schema.ts,store.ts,coordinator.ts}` and tests `worker/test/{fleet-store.test.ts,enrollment.test.ts,heartbeat.test.ts}`.

**Interfaces:** Add the `FleetCoordinator` methods above; the module handler uses generated `Env`, `env.FLEETS.getByName(fleetId)`, and no other fleet-to-object mapping; the Durable Object extends `DurableObject<Env>` and uses `this.env`/`this.ctx`.

- [ ] Write failing tests for deterministic object identity, SQLite persistence across object eviction, challenge/request-nonce association/reuse/expiry, concurrent completion (exactly one winner), server epoch increment, prior-session invalidation, sequence `1`, duplicate/reordered/gapped/old-epoch rejection, receipt-time freshness, unknown-field rejection, generated binding drift, and no manual `Env` declaration.
- [ ] Run `npm run --workspace worker test -- fleet-store.test.ts enrollment.test.ts heartbeat.test.ts`; expect missing coordinator/schema failures.
- [ ] Configure binding `FLEETS`, class `FleetCoordinator`, migration `{"tag":"v1","new_sqlite_classes":["FleetCoordinator"]}`. Create the contracted tables with a `_sql_schema_migrations` table because `PRAGMA user_version` is unsupported. Atomically claim nonce digests by purpose, and separately verify the bound challenge/request-nonce pair, consume challenge, increment epoch, activate session, reset sequence, and invalidate the prior session. Store only allowlisted heartbeat JSON and server receipt time. Run `wrangler types`; never hand-write binding types.
- [ ] Run the narrow tests, `npm run --workspace worker typecheck`, and `npm run --workspace worker types:check`; expect all PASS. Inspect SQLite in tests and assert no signature, request body, key, challenge plaintext, or secret column exists.
- [ ] Commit: `git add worker/wrangler* worker/worker-configuration.d.ts worker/src/index.ts worker/src/fleet worker/test && git commit -S -m "worker: persist fleet enrollment and heartbeat state"`.

### Task 4: Implement Cron Evaluation and Hysteresis

**Files:** Create `worker/src/{scheduler.ts,admin.ts}`, `worker/src/fleet/{evaluator.ts,due-work.ts}`, `worker/test/{evaluator.test.ts,scheduler.test.ts,due-work.test.ts,admin.test.ts}`; modify Wrangler configs and `worker/src/index.ts`.

**Interfaces:** `evaluateHealth(snapshot, policy, nowMs): EvaluationDecision`; `ensureAlarmNoLaterThan(candidateMs): Promise<void>` transactionally preserves the earliest alarm; `DueWorkPorts { github?, canary?, email?, webhook? }` is constructor-injected and an absent port fails closed without external I/O; Worker `scheduled()` calls `reconcileConfiguration`, `evaluate`, and bounded `processDueWork` once per configured fleet on each `* * * * *` event; `FleetCoordinator.alarm()` runs the same due-work loop and reschedules the earliest persisted due row. Authenticated admin handlers expose recovery, hosted-hold enable/disable, and read-only status only when explicitly enabled.

- [ ] Write table-driven failing tests for bootstrap creating hosted intents, bootstrap remaining blocked until every hosted read-back, `HOSTED_CONFIRMED` recovery observation, current canary failback, first healthy-state stale observation to `SUSPECT`, second to `FAILOVER_PENDING`, authenticated fatal immediate eligibility, healthy reset before mutation, failed-canary block, new recovery epoch, hosted-hold entry from every state, hosted read-back before hold confirmation, no recovery while held, release creating a new recovery epoch, and late epoch rejection. Add configuration tests: a new repository is accepted only under hosted hold, inserted unconfirmed-hosted, reconciled by Worker-owned outbox, bound to the persisted canary config/revision/digest, and rejected on identity mutation/removal, revision skip/rollback, or same-revision digest mismatch. Add alarm tests for concurrent candidates arriving in both orders, transactional minimum preserving the earliest alarm, spurious alarm after crash between arm and SQL commit, prohibition on SQL due-row commit before arming, overlap with cron, object eviction, six exhausted native retries followed by self-rescheduling, and crash before/after claim/network/outcome. Admin tests enforce `±300s` timestamp skew, single-use nonce digest, separate HMAC key with `crypto.subtle.verify`, disabled-by-default routing, generic rejection responses, and a status response containing only `AdministrativeStatus` fields.
- [ ] Run `npm run --workspace worker test -- evaluator.test.ts scheduler.test.ts due-work.test.ts admin.test.ts`; expect missing evaluator/scheduler/due-work behavior.
- [ ] Implement the locked health state machine and transactional configuration reconciliation. Apply the six-minute stale default, two-observation failover floor, configured recovery observations, transition lock/epoch, one-minute cron, and persisted due times. A failed canary remains hosted with `recovery_blocked=1` until `startRecoveryEpoch` increments the epoch. Hosted-hold enable persists hosted transition intent and blocks recovery; disable clears it, increments the recovery epoch, and remains hosted. Before any SQL transaction makes a due row visible, call the transactional-minimum alarm helper; never move an existing alarm later. `processDueWork` claims bounded rows, invokes only injected ports outside storage transactions, reconciles claims, and arms before committing any retry deadline; Task 4 wires fail-closed absent ports so this intermediate commit compiles/tests without making an external call. The alarm catches downstream errors and self-arms before returning. Optional admin endpoints are absent when disabled; otherwise each verifies timestamp, separate-key HMAC, and one-time nonce before Durable Object access. Mutating endpoints return only `202 {"status":"accepted"}`; status returns the bounded typed document and is never logged.
- [ ] Re-run narrow tests, then `npm run --workspace worker test`; expect all PASS, exactly one evaluation call per configured fleet per cron event, no unclaimed due row without an alarm, and bounded at-least-once processing after eviction/crash.
- [ ] Commit: `git add worker/src/fleet/evaluator.ts worker/src/fleet/due-work.ts worker/src/scheduler.ts worker/src/admin.ts worker/src/index.ts worker/wrangler* worker/test && git commit -S -m "worker: add failover scheduler and due-work engine"`.

### Task 5: Add Least-Privilege GitHub Auth and Persisted Per-Repository Mutation Outbox

**Files:** Create `worker/src/github/{app-auth.ts,client.ts,mutation-outbox.ts}`, `worker/test/{github-auth.test.ts,mutation-outbox.test.ts}`, and `docs/security/failover-permissions.md`; modify `worker/src/fleet/due-work.ts`, `worker/src/index.ts`, and affected tests to wire only the GitHub port.

**Interfaces:** `GitHubPort` above; `processMutation(row, github, store, nowMs): Promise<MutationOutcome>`; unique idempotency key `(transition_epoch, repository_alias, desired_route)`.

- [ ] Write failing tests for installation-token scoping, prohibited permission rejection, intent-before-I/O, already-correct route, transactional due-row claim/expiry, PATCH then GET read-back, crash/timeout before and after PATCH, `Retry-After`, `X-RateLimit-Reset`, partial repository success, retry after object eviction, stale claim completion rejection, and refusal to confirm mismatched read-back.
- [ ] Run `npm run --workspace worker test -- github-auth.test.ts mutation-outbox.test.ts`; expect missing GitHub modules.
- [ ] Implement GitHub App JWT/installation-token flow without logging tokens. Use `X-GitHub-Api-Version: 2026-03-10`; read and update `GET|PATCH /repos/{owner}/{repo}/actions/variables/PORTABLE_GHAR_ROUTE`, dispatch `POST /repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches`, and locate runs through `GET /repos/{owner}/{repo}/actions/workflows/{workflow}/runs`. For each repository, transactionally persist transition plus outbox first; claim a bounded due row; GET, PATCH only when needed, GET again, then mark confirmed only under the same live claim. Persist retry deadline and sanitized error code. Confirm transition only when all repositories read back desired state.
- [ ] Re-run tests and `npm test`; expect all PASS, no steady-state API polling, and chaos fixtures proving partial success is independently recoverable.
- [ ] Commit: stage the Task 5 GitHub modules, due-work/entrypoint wiring, tests, and permissions document only, then `git commit -S -m "worker: reconcile repository routing outbox"`.

### Task 6: Build the Secretless Epoch-Bound Canary

**Files:** Create `worker/src/github/canary.ts`, `worker/test/canary.test.ts`, both workflow examples, and `scripts/validate-canary-template.mjs` with `tests/operations/canary-template.test.mjs`; modify `worker/src/fleet/due-work.ts`, `worker/src/index.ts`, and affected tests to wire the canary port.

**Interfaces:** `CanaryIdentity { transitionEpoch, expectedRevision, repositoryAlias, workflow }`; persisted status `pending|locating|running|passed|failed|superseded`.

- [ ] Write failing tests for dispatch at exact persisted configuration revision, correlation by run name/epoch/revision, due-row claim/expiry, persisted run ID, crash before/after dispatch and poll, success only on matching `head_sha`, late success ignored, failed conclusion blocks recovery, and manual mode making no dispatch. Static tests reject `secrets`, `pull_request_target`, write permissions, active public workflow paths, checkout, YAML-sequence `runs-on`, `self-hosted`, and any value other than one scalar scale-set name.
- [ ] Run `npm run --workspace worker test -- canary.test.ts` and `node --test tests/operations/canary-template.test.mjs`; expect missing canary code/template validator.
- [ ] Implement a non-active `workflow_dispatch` template with `permissions: {}`, no checkout, no declared secrets, inputs `transition_epoch` and `expected_revision`, run-name correlation, one scalar synthetic `runs-on: portable-ghar-canary-scale-set` value rendered to the private GitHub.com scale-set name, five-minute timeout, exact `github.sha` check, and isolation smoke checks. The validator rejects YAML sequences and any `self-hosted` label. Dispatch only after bootstrap hosted read-back, while route remains hosted and heartbeat says `canary-only`.
- [ ] Re-run tests; expect current-epoch success enables self-hosted outbox creation, while every obsolete or failed result leaves hosted confirmed.
- [ ] Commit: stage the Task 6 canary module, due-work/entrypoint wiring, tests, examples, and validator only, then `git commit -S -m "failover: add epoch-bound canary contract"`.

### Task 7: Add Independent Email and Signed-Webhook Notification Outboxes

**Files:** Create `worker/src/notifications/{event.ts,email.ts,webhook.ts,outbox.ts}`, `worker/test/notifications.test.ts`, `docs/security/signed-webhook-contract.md`, and `tests/operations/webhook-recipient-contract.test.mjs`; modify `worker/src/fleet/due-work.ts`, `worker/src/index.ts`, affected tests, the private-config renderer, and generated `worker/worker-configuration.d.ts` to wire email/webhook ports.

**Interfaces:** `NotificationEvent { eventId, fleetDisplayName, transitionType, repositoryAliases, lastConfirmedRoute, reasonCode, receivedAt, operatorAction }`; `EmailPort.send(event)`; `WebhookPort.send(event)`; unique key `(event_id, channel)`.

- [ ] Write failing tests for allowlisted event fields, text+HTML parity, restricted sender/destination config, signature over `<timestamp>.<eventId>.<exactBody>`, recipient `±300s` skew, replay-digest claim, event-ID dedupe, transactional outbox claim/expiry, crash before/after delivery, independent delivery, transient backoff, permanent stop, email-only failure, webhook-only failure, both failure, webhook-disabled mode creating no secondary row, and routing success despite all notification failure. Contract tests reject a bridge on the QTS runner host and reject HTTP `2xx` as end-to-end Signal evidence; they require the separate-domain bridge to emit a distinct HMAC-signed delivery-receipt envelope only after destination acknowledgment. Receipt tests reject reuse of the webhook key, Worker/QTS access to the receipt key, stale/unknown key IDs, and ambiguous rotation; compromise or unverifiable rotation invalidates the evidence window without changing routing.
- [ ] Run `npm run --workspace worker test -- notifications.test.ts`; expect missing notification modules.
- [ ] Implement `env.EMAIL.send()` with both bodies and no attachment/raw log. Render `allowed_sender_addresses` and `destination_address` only into the private Wrangler config and verify the exact schema against Wrangler 4.110.0. Keep the public secondary Worker code generic: HTTPS-only webhook, separate Worker secret key, bounded exponential retry, sanitized permanent/transient codes, and headers `X-Portable-GHAR-Event-ID`, `X-Portable-GHAR-Timestamp`, `X-Portable-GHAR-Signature`. Due-work claims each channel independently. Document recipient constant-time MAC verification, skew/replay/dedupe enforcement, and a separate delivery-receipt HMAC contract `{eventId,channel,deliveredAt,destinationAckDigest,failureDomainClass,runnerHost:false}` without implementing the private Signal bridge.
- [ ] Run `npm run --workspace worker test -- notifications.test.ts`, then `npm run --workspace worker test` and `node --test tests/operations/webhook-recipient-contract.test.mjs`; expect independent outbox PASS, identical sanitized event ID/content across channels, replay rejection, and no Signal-specific Worker adapter.
- [ ] Commit: stage the Task 7 notification modules, due-work/entrypoint wiring, generated binding, tests, renderer, receipt schema/example, and webhook contract only, then `git commit -S -m "worker: add failover notification outboxes"`.

### Task 8: Extend the Host Fence with Continuous Cross-Generation Proof

**Files:** Modify `internal/fleetfence/{store,store_unix}.go` and tests, `cmd/portable-ghar-fleet-fence/main.go` and tests, `deploy/qts/run-legacy-fenced.sh`, and `tests/shell/qts/fleet-fence.bats` created by the controller-runtime phase.

**Interfaces:** Preserve `portable-ghar-fleet-fence guard --fleet portable|legacy --generation N -- COMMAND`, `inspect`, and `handoff --from portable|legacy|none --to portable|legacy|none --expected-generation N`. A guard holds the stable lock inode shared for the command lifetime, refreshes its own generation/fleet/owner/PID/boot-scoped holder record every five seconds, and terminates its child if that proof cannot be persisted for 30 seconds; handoff holds the stable inode exclusively, waits for all old-fleet guards to close, compares the separate generation header, and returns N+1.

- [ ] Write failing Go/Bats tests for atomic header read-back, stable lock inode across header replacement, independent process-lifetime shared guards/holder records within one fleet, exclusive handoff, five-second per-holder renewal, one-child termination on its renewal failure, crash lock release, PID/boot-identity reuse, stale generation rejection, new/legacy simultaneous start, both watchdogs racing after crash, allowed same-fleet restart, disabled observer restart while `legacy` is active, and legacy restore only after the generation atomically changes while routing is confirmed hosted.
- [ ] Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/fleetfence ./cmd/portable-ghar-fleet-fence -run TestGenerationFence -count=1` and `bats tests/shell/qts/fleet-fence.bats`; expect renewal/race cases to fail before the extension.
- [ ] Extend the existing authority without adding a second lock: never rename the lock inode; update only the separate generation header under exclusive lock; create one atomic mode-restricted holder record per active guard; and retire old-generation records after handoff. The new controller/watchdog and every restored legacy controller/watchdog command execute through the same binary for nonzero work; a stale wrapper exits before child start, and renewal failure kills only its child. The documented force-disabled observer path proves zero capacity and never takes a `portable` guard while `legacy` is active.
- [ ] Re-run both commands plus QTS-state-filesystem conformance; expect every race PASS, same-fleet controller/watchdog guards and renewals independently visible, no observation containing holders from both fleets, stable lock inode identity, and the non-current fleet unable to reacquire after a watchdog restart.
- [ ] Commit: `git add internal/fleetfence cmd/portable-ghar-fleet-fence deploy/qts/run-legacy-fenced.sh tests/shell/qts/fleet-fence.bats && git commit -S -m "runtime: extend cross-generation fence proof"`.

### Task 9: Connect Heartbeats to Successful Reconciliation and Complete Chaos Coverage

**Files:** Modify `internal/health/{publisher.go,publisher_test.go}` created by the controller phase; create `worker/test/failover-chaos.test.ts`, `tests/integration/failover_contract_test.go`, and `scripts/verify-failover.sh`.

**Interfaces:** Extend the existing `HealthPublisher` with `PublishAfterCycle(ctx, SuccessfulReconciliation) error` and `PublishFatal(ctx, FatalReason) error`; failed/incomplete cycles have no ordinary heartbeat path.

- [ ] Write failing tests proving ordinary heartbeat follows complete reconciliation only; job-controlled fields cannot enter payload/logs; fatal reasons are closed enums; controller death, Docker loss, duplicated/reordered/dropped heartbeat, local state rollback, DO eviction, pre/post-outbox failure, GitHub ambiguity/rate limit/partial success, obsolete canary, and both notification failures preserve the safe state. Inject cancellation-resistant poll/acquire/JIT during canary narrowing, pressure reduction, watchdog stop, and suspend; require bounded controller termination, a fatal heartbeat or subsequent staleness, hosted read-back, and no non-current-epoch acquisition.
- [ ] Run `go test ./internal/health ./internal/controller ./tests/integration -run Failover -count=1` and `npm run --workspace worker test -- failover-chaos.test.ts`; expect failures for missing publisher/integration wiring.
- [ ] Implement the publisher mapping and a verification script that runs Go race tests including the generation fence, Worker lint/typecheck/tests, webhook-recipient contract, schema/template validators, forbidden-pattern scans, and `git diff --check`. It prints only stage names and PASS/FAIL.
- [ ] Run `scripts/verify-failover.sh`; expect every stage PASS, zero secret-shaped output, and hosted route after every unresolved failure fixture.
- [ ] Commit: `git add internal/health worker/test/failover-chaos.test.ts tests/integration scripts/verify-failover.sh && git commit -S -m "failover: verify end-to-end safety invariants"`.

### Task 10: Write Private-Overlay, Least-Privilege, and Dark-Deployment Runbooks

**Files:** Create `scripts/ops/{assert-private-overlay.sh,control-plane-admin.mjs,probe-private-deployment.mjs}`, `tests/operations/{private-overlay.bats,control-plane-admin.test.mjs,probe-private-deployment.test.mjs,runbook-content.test.mjs}`, `docs/operations/failover-deployment.md`; finalize `docs/security/failover-permissions.md`.

**Interfaces:** `assert-private-overlay.sh <absolute-root>` exits `0` only outside Git with `0700` root and `0600` files. `node scripts/ops/control-plane-admin.mjs hold-hosted|release-hosted|status --overlay <root> --evidence-out <private-json>` sends a timestamped, nonce-protected administrative request, validates the typed response/read-back, writes mode `0600`, and prints only `control plane: PASS|FAIL`; `status` always compares the returned configuration revision/digest to the current overlay and also accepts bounded assertions `--expect-route hosted|self-hosted`, `--expect-hold true|false`, `--expect-acquisition disabled|canary-only|enabled|fatal|unobserved`, `--expect-config-revision <integer>`, `--min-sequence-advance N`, `--require-current-epoch-canary`, and `--wait-seconds 0..900`, using a fresh nonce per poll. `node scripts/ops/probe-private-deployment.mjs --overlay <root> --phase predeploy|postdeploy --evidence-out <private-json>` performs typed target/account, Docker/kernel/resource, GitHub App/install, Cloudflare binding/DO, Email Service, webhook, and repository-access probes and prints only `private deployment probe: PASS|FAIL`. Private evidence never goes to stdout.

- [ ] Write failing Bats cases for in-repo path, symlink escape, permissive mode, inline secret, unknown field, and sanitized success. Add admin-client tests for disabled endpoint, timestamp skew, nonce reuse, malformed/extra status fields, private evidence modes, hosted-hold/read-back, configuration-revision read-back, release creating a new epoch, bounded waiting with a fresh nonce per poll, sequence advance, current-epoch canary/route assertions, and secret-free stdout. Probe tests require positive target/account/Docker/kernel/resource/App/install/binding/DO/email/webhook/repository observations, private evidence modes, synthetic stdout, and mismatch stop. Add markdown checks requiring separate App tables, explicit denied permissions, manual-canary Actions omission, API version `2026-03-10`, restricted email binding, DO migration/alarm, generation-fence paths, separate-failure-domain webhook bridge, no inbound runner-host endpoint, and secret-reference installation.
- [ ] Run `bats tests/operations/private-overlay.bats` and `node --test tests/operations/control-plane-admin.test.mjs tests/operations/probe-private-deployment.test.mjs tests/operations/runbook-content.test.mjs`; expect missing script/runbook failures.
- [ ] Under the existing operator authorization, document exact gated order: validate overlay; run the predeploy private probe and stop on mismatch; record App installations/permissions; onboard and verify Email Service privately; render config; `wrangler deploy --dry-run`; install HMAC/GitHub/webhook/admin secrets from references without echo; deploy Worker/SQLite class; read authenticated status; repeat the identical deploy and prove enrollment/config/outbox/hold state persisted; enable and read back the hosted hold; verify its persisted email/webhook outboxes and record the matching private Signal receipt; run the postdeploy probe; install the shared generation wrapper without enabling new acquisition; enroll a force-disabled observer while `legacy` owns the fence; verify advancing accepted heartbeat and zero acquisition through authenticated status; reconcile/read back hosted for every repository; only then permit a new recovery epoch. Store raw output only in encrypted private evidence.
- [ ] Re-run tests and manually inspect the runbook for only synthetic examples; expect PASS and no active external action during source execution.
- [ ] Commit: `git add scripts/ops/assert-private-overlay.sh scripts/ops/control-plane-admin.mjs scripts/ops/probe-private-deployment.mjs tests/operations docs/operations/failover-deployment.md docs/security/failover-permissions.md && git commit -S -m "docs: define private failover deployment gate"`.

### Task 11: Capture and Freeze Live Legacy State, Add the Transition Variable, and Run the Canary Order

**Files:** Create `scripts/ops/{capture-legacy.sh,adopt-legacy-fence.mjs,suspend-legacy.mjs,transition-variable.mjs}`, `deploy/qts/{adopt-legacy-fence,suspend-legacy}.sh`, tests `tests/operations/{legacy-capture.bats,legacy-fence-adoption.test.mjs,legacy-suspend.test.mjs,transition-variable.test.mjs}`, and runbooks `docs/operations/{legacy-capture-and-freeze.md,failover-canary-cutover.md}`; modify `cmd/portable-ghar` and `internal/cli/host.go`.

**Interfaces:** `capture-legacy.sh --overlay <root> --manifest <private-json> --output <private-archive>`; `adopt-legacy-fence.mjs --overlay <root> --manifest <private-json> --evidence-out <private-json>` invokes only `portable-ghar adopt legacy-fence`; `suspend-legacy.mjs --overlay <root> --manifest <private-json> --hosted-confirmation <private-json> --evidence-out <private-json>` invokes only `portable-ghar suspend legacy`; both host commands positively match QTS, use the fixed captured action allowlist, and return only after process/watchdog/holder read-back. `transition-variable.mjs create-hosted|read-back|remove --overlay <root> (--repository-alias <alias>|--all-configured)` prints no identifiers or secret values. Direct variable writes are allowed only before Worker bootstrap, for the one-time all-candidate hosted transition bootstrap under a confirmed hold, or during documented emergency/legacy recovery; routine expansion uses Worker `reconcileConfiguration`, and the tool refuses concurrent normal Worker authority.

- [ ] Write failing tests requiring fresh live inputs for controller/supervisor scripts, image digests, config, watchdog/cron, external watcher, credential references, writer state, and routes; encrypted archive plus SHA-256 manifest; QTS-only fence adoption at an idle point; stable `legacy` header plus one holder per launcher/watchdog; target-safe suspension only after hosted confirmation; zero legacy processes/listeners and fence `none` on return; read-back after emergency variable create/update/delete; stable required-check names; scalar GitHub.com scale-set canary name; monotonic private configuration revision; Worker-owned addition of a new repository as unconfirmed-hosted under hold; persisted per-expansion canary identity; and rejection when a legacy writer or routine operator tool claims `PORTABLE_GHAR_ROUTE`.
- [ ] Run `bats tests/operations/legacy-capture.bats` and `node --test tests/operations/legacy-fence-adoption.test.mjs tests/operations/legacy-suspend.test.mjs tests/operations/transition-variable.test.mjs`; expect missing scripts/runbooks.
- [ ] Implement public tooling against typed private manifests, fixed command allowlists, `umask 077`, temporary-file cleanup, encryption-before-retention, and sanitized summaries. Document order: live capture; decrypt/list/hash rehearsal; freeze legacy configuration changes without retiring its watcher; initialize the stable fence with `legacy` active and wrap the live legacy launchers/watchdogs; register Portable GHAR scale sets disabled; deploy the force-disabled observer after normalizing persisted acquisition to a new disabled/empty/zero epoch; enable/read back the Worker hosted hold; increment private `configRevision`, render/redeploy, and wait for `reconcileConfiguration` to add every repository unconfirmed-hosted and read it back hosted; stop legacy acquisition while hosted; atomically hand the fence through `none` to `portable`; prove the legacy watchdog cannot reacquire; install the secretless canary with one scalar private scale-set name; transition through the bounded policy barrier to `canary-only` for exactly that scale set and one capacity unit; release the hold into a new recovery epoch; prove lifecycle/isolation/recovery/hosted fallback/email/webhook and matching Signal receipt; expand later by reacquiring hold, updating config/canary revision, redeploying, reconciling hosted, and repeating the epoch canary while sensitive jobs stay hosted. Routine expansion never writes the variable directly.
- [ ] Re-run the same commands; expect all PASS, target identity/read-back proof, and a fixture proving the transition variable is untouched by legacy writers.
- [ ] Commit: `git add scripts/ops deploy/qts cmd/portable-ghar internal/cli/host.go tests/operations docs/operations && git commit -S -m "ops: define fenced legacy capture and canary cutover"`.

### Task 12: Retire Legacy with Typed Tools and Rehearse Mutually Exclusive Rollback

**Files:** Create `docs/operations/failover-failure-drills.md`, `tests/operations/{failure-drills.test.mjs,signal-receipt.test.mjs,retire-legacy.test.mjs,verify-legacy-retired.test.mjs}`, `tests/shell/qts/legacy-retirement.bats`, `tests/fixtures/failover/drill-pass.json`, `config/schema/{failover-evidence.schema.json,legacy-retirement-manifest.schema.json}`, `config/examples/legacy-retirement-manifest.example.json`, `scripts/ops/{record-drill.mjs,record-signal-receipt.mjs,retire-legacy.mjs,verify-legacy-retired.mjs}`, `deploy/qts/{retire-legacy,verify-legacy-retired}.sh`; modify `cmd/portable-ghar` and `internal/cli/host.go`.

**Interfaces:** Each drill emits `{drillId, transitionEpoch, startedAt, completedAt, expectedSafeRoute, observedSafeRoute, readBackConfirmed, result}`. `node scripts/ops/record-drill.mjs --overlay <root> --drill <allowlisted-id> --evidence-out <private-json>` records live typed evidence and prints only `failure drill: PASS|FAIL`; fixture mode is `--fixture <synthetic-json> --evidence-out <path>`. `node scripts/ops/record-signal-receipt.mjs --overlay <root> --receipt <private-json> --evidence-out <private-json>` verifies the separate delivery-receipt HMAC, event correlation, timestamp, destination-ack digest, and `runnerHost:false`, then prints only `signal receipt: PASS|FAIL`. `node scripts/ops/retire-legacy.mjs --overlay <root> --manifest <private-json> --evidence-out <private-json>` invokes only `portable-ghar retire legacy --private PATH --manifest PATH --hosted-confirmation PATH` through the verified management channel and prints only `legacy retirement: PASS|FAIL`; verification similarly invokes `portable-ghar verify legacy-retired` and prints only `legacy retired: PASS|FAIL`.

- [ ] Write failing content/schema tests requiring stale heartbeat, fatal state, controller death, Docker restart/loss, host outage, uplink loss, GitHub timeout/rate-limit/partial success, email-only/webhook-only/both failures, matching HMAC-verified end-to-end Signal receipt, receipt replay/mismatch/same-host rejection, failed/late canary, DO reschedule, generation-fence renewal failure, simultaneous watchdog race, and complete rollback rehearsal. Retirement tests require positive QTS target identity, refusal on Darwin/non-QTS, soak proof, hosted-safe barrier, typed private manifest, current `none` fence, legacy acquisition denial, legacy watcher/writer/process/container/registration absence, credential revocation evidence, and retained encrypted artifacts.
- [ ] Run `node --test tests/operations/failure-drills.test.mjs tests/operations/signal-receipt.test.mjs tests/operations/retire-legacy.test.mjs tests/operations/verify-legacy-retired.test.mjs` and `bats tests/shell/qts/legacy-retirement.bats`; expect missing drill/receipt schema and target-safe retirement coverage.
- [ ] Implement typed retirement tools without accepting arbitrary shell strings: the Node orchestrators validate overlay/evidence and call only the fixed host CLI subcommands; the CLI positively matches the target; target scripts revalidate Linux/QTS identity and select only enumerated adapter actions/secret references. Require post-action process/container/cron/writer/registration/fence read-back before PASS. Document positive observations for every drill. Rollback order is exact: enable the Worker hosted hold and read back every repository hosted; stop new acquisition; journaled suspend to `none`; prove zero new listeners/runner/helper/verifier containers and pending acquisition; atomically hand `none` to `legacy`; restore captured legacy components only through fenced wrappers; prove the new watchdog cannot reacquire; prove legacy egress, advancing health, and secretless canary; only then remove/read back absence of the transition variable. Any dual-fleet holder, lost hosted hold, target mismatch, or wrapper bypass fails immediately.
- [ ] Run all tests above plus `bats tests/shell/qts/fleet-fence.bats tests/operations/legacy-capture.bats`; then run `node scripts/ops/record-drill.mjs --fixture tests/fixtures/failover/drill-pass.json --evidence-out /tmp/portable-ghar-drill.json`; expect PASS, one schema-valid record, fenced mutual exclusion, target-safe adapter proof, and no mutation outside fixtures or `/tmp`.
- [ ] Commit: `git add docs/operations/failover-failure-drills.md tests/operations tests/shell/qts/legacy-retirement.bats config/schema scripts/ops deploy/qts cmd/portable-ghar internal/cli/host.go && git commit -S -m "ops: add failover and target-safe rollback drills"`.

### Task 13: Enforce the 14-Day Soak, Retirement Gates, 30-Day Retention, and Final Positive Verification

**Files:** Create `scripts/ops/{collect-soak-evidence.mjs,verify-retirement-gates.mjs}`, tests `tests/operations/{soak-evidence.test.mjs,retirement-gates.test.mjs}`, runbooks `docs/operations/{failover-soak-and-retirement.md,failover-final-verification.md}`; modify `README.md` only after the live final gate passes.

**Interfaces:** `node scripts/ops/collect-soak-evidence.mjs --overlay <root> --day <UTC-date>` creates one schema-valid private record and prints only `soak evidence: PASS|FAIL`; `node scripts/ops/verify-retirement-gates.mjs --phase soak|pre-retire|final --overlay <root> --as-of <RFC3339>` prints only `retirement gates: PASS|FAIL`.

- [ ] Write failing tests for exactly 14 consecutive complete UTC days; no unexplained evaluation gap over two minutes; continuous per-holder generation-fence renewals with no dual fleet; heartbeat freshness below stale threshold outside annotated drills; zero unconfirmed route claimed successful; zero self-hosted confirmation without current-epoch canary; no overdue/unclaimed due work without an alarm; all drills passed; Worker/DO persistence; primary email delivery; signed-webhook recipient skew/replay/dedupe proof; matching HMAC-verified Signal receipt from a separate failure domain; rollback rehearsal; verified legacy retirement; archive decrypt/hash; and `retention_until >= retired_at + 30 days`.
- [ ] Run `node --test tests/operations/soak-evidence.test.mjs tests/operations/retirement-gates.test.mjs`; expect missing collectors/gates.
- [ ] Implement sanitized daily collection and fail-closed gates. Any missing day, unexplained gap, fence lapse/dual-fleet holder, route divergence, obsolete-canary acceptance, overdue/unowned due work, failed drill, HTTP-only webhook evidence, unsigned/mismatched receipt, same-host bridge, or unverifiable archive resets the soak. Existing operator authorization satisfies retirement approval. Enable and verify the hosted hold first; `--phase pre-retire` then requires the complete soak/drill/archive/receipt evidence plus hosted read-back. After it passes, invoke target-safe typed retirement, verify legacy is absent and fenced out, revoke only obsolete credentials not required for the retained recovery procedure, remove legacy containers/images only after backup verification, and retain encrypted rollback material through `retention_until`. Release the hold only into a new recovery epoch and after the Portable GHAR fence/disabled-controller state is read back.
- [ ] Under the existing authorization and after target/account re-verification, force stale and fatal failover with hosted read-back; reconcile an ambiguous mutation; prove email plus matching Signal receipt through the separate-domain bridge; recover through a current-epoch expected-revision canary; read back self-hosted; prove DO persistence and continuous fencing. Run `node scripts/ops/verify-retirement-gates.mjs --phase pre-retire --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"`; expect `retirement gates: PASS`. Run `node scripts/ops/retire-legacy.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-retirement.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-retirement.json"`; expect `legacy retirement: PASS`. Run `node scripts/ops/verify-legacy-retired.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-retirement.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-retired-verification.json"`; expect `legacy retired: PASS`. Run `node scripts/ops/verify-retirement-gates.mjs --phase final --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"`; expect `retirement gates: PASS`.
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
