# Portable GHAR Failover Deployment Implementation Plan

<!-- markdownlint-disable MD013 -->

> **For implementers:** Execute this plan task by task with test-driven
> development. A task is not complete until its narrow tests, affected suites,
> and exact read-back pass. Deployment tasks require a separately approved
> execution packet with exact targets, values, rollback, and stop conditions.

**Goal:** Build and safely deploy Portable GHAR's external failover authority,
prove hosted fallback and lease-bounded recovery, and retire the legacy watcher
only after a 14-day soak and a rehearsed rollback while retaining verified
encrypted rollback artifacts for 30 days.

**Architecture:** The controller establishes one authenticated outbound session
with a Cloudflare Worker and sends signed heartbeats to one deterministic
SQLite-backed Durable Object per fleet. The accepted heartbeat response carries
the only remote acquisition authority: one short-lived signed lease for the
exclusive `portable` or governed `legacy` holder. The Durable Object is the sole
automatic GitHub routing writer. It persists transition intent and idempotent
due work before external effects; one Cloudflare Cron Trigger is the sole
durable scheduler. A six-state routing machine keeps implementation checkpoints
out of authority state. Email and an optional signed webhook are independent
notifications, never routing evidence.

**Tech stack:** Go controller client; TypeScript Cloudflare Worker; SQLite
Durable Objects; Workers Vitest integration; one Cloudflare Cron Trigger;
GitHub App REST API; native email binding; optional HMAC-signed HTTPS webhook;
JSON Schema; Go, Vitest, Node, Python, and Bats tests; GitHub-hosted CI.

## Engineering baseline

Correctness, security, operational reliability, practical simplicity, and
elegant boundaries are co-equal blocking criteria.

1. Every network call, datastore operation, lock, subprocess, scheduler action,
   and long-lived worker has an enforceable timeout/backpressure bound or an
   explicit lifecycle owner.
2. Timeout, unavailability, partial success, crash/re-entry, stale state,
   concurrency, resource exhaustion, and misconfiguration each have a tested
   safe outcome. Authority and authentication failures fail closed.
3. Persistent and external effects are idempotent or safely re-entrant and are
   successful only after authoritative read-back.
4. Retry count, elapsed retry age, batches, claims, queues, histories, evidence,
   processes, descriptors, memory, tmpfs, and disk are bounded.
5. Use one lifecycle engine, one external routing writer, one due-work
   scheduler, one acquisition-lease protocol, and one authoritative routing
   state definition. Do not add a parallel authority or recovery path.
6. Every component, endpoint, table, state, and abstraction must satisfy a
   present requirement that a materially simpler design cannot safely satisfy.
7. Preserve the Phase 2 security boundaries and SQLite one-writer/full-sync
   store; these remove concrete privilege and race classes and are not
   gratuitous component count.
8. Keep Portable GHAR standalone. No consumer repository, reviewer transport,
   collaboration service, or named deployment is a product dependency.

## Four routing invariants

1. `hosted` is the safe route for cold, unknown, stale, ambiguous, or invalid
   state.
2. Exactly one external authority writes GitHub routing variables.
3. Local acquisition authority expires before hosted confirmation can complete.
4. Every external mutation is persisted first and positively read back before
   success.

## Simplified authority model

### Public endpoints

- `POST /v1/session`: one timestamped, nonce-bearing, HMAC-authenticated
  enrollment request. The response is signed and binds the request nonce,
  server-owned epoch, random session, initial sequence, lease generation, and
  Worker receipt time.
- `POST /v1/heartbeat`: one signed health/status request. The response binds the
  accepted sequence, routing transition, maintenance directive, and either one
  `AcquisitionLeaseV1` or an explicit no-lease result.
- `POST /v1/admin/command`: a closed administrative command union protected by
  an independent credential, timestamp, and single-use nonce.
- `POST /v1/admin/status`: bounded typed status with no mutation authority.

Do not add challenge/complete enrollment, per-operation remote permits, permit
close calls, a separate legacy process-lease endpoint, or one endpoint per
administrative verb. A new endpoint requires an independently authenticated or
lifecycle-owned responsibility the closed interfaces cannot express safely.

### Acquisition lease

`AcquisitionLeaseV1` binds:

- protocol version, fleet, holder, server epoch, and session;
- lease generation and mode (`disabled`, `canary-only`, or `enabled`);
- exact acquisition-policy digest and repository-policy revision;
- maximum capacity and the one eligible canary scale set when canary-only; and
- server-owned validity duration, server expiry for audit, and response MAC.

The controller converts the duration to a strictly shorter monotonic deadline
at receipt. It never extends authority from wall time, status, or an
administrative command. The existing local `AcquisitionPermitProvider`
interface may derive an operation-scoped proof from the cached lease while the
local epoch barrier and host fence remain held; it performs no network call and
creates no remote per-operation state.

### Routing states

Only these authority states are persisted:

```text
HOSTED -> PORTABLE_CANARY -> PORTABLE
HOSTED -> LEGACY_CANARY   -> LEGACY
PORTABLE -> DRAINING_TO_HOSTED -> HOSTED
LEGACY   -> DRAINING_TO_HOSTED -> HOSTED
```

Canary dispatch/result, GitHub mutation/read-back, lease expiry, queue-risk
clearance, notifications, and retries are transition outcomes, not additional
routing states. All Portable-to-legacy movement passes through hosted.

### Durable data

Start with six responsibility-based tables:

1. `fleet_state`
2. `request_nonces`
3. `repositories`
4. `transitions`
5. `due_work`
6. `audit_events`

This count is not a quota. Add a table only for an independently owned
lifecycle/retention contract that cannot be represented safely in these
responsibilities. Do not depend on private Durable Object tables or couple SQL
correctness to runtime-internal alarm storage.

### Durable scheduling

One Cloudflare Cron Trigger scans and claims bounded due-work batches. Request
handlers may opportunistically execute work they just persisted, but recovery
never depends on another request. Durable Object alarms are not a second
scheduler. Expired claims return to the queue; permanent failures stay visible.

If the Worker and Cron path are both unavailable while GitHub still routes
locally, the short lease expires and new local acquisition stops. Jobs may queue
on the last confirmed route until recovery. This availability degradation is
explicit, observable, and never reported as hosted failover.

## External dependency failure contract

| Dependency | Bound | Safe degradation and proof |
| --- | --- | --- |
| Cloudflare Worker/DO | Request deadline; short lease lifetime | Lease expires; new local acquisition stops; no status or cached response extends it. |
| Cron Trigger | Bounded batch/claim/retry age | Due work waits durably; expired claims are reclaimed; no second scheduler masks an outage. |
| GitHub API | Per-call deadline, rate-limit budget | Desired state remains persisted; ambiguity is read back; unconfirmed failover is never success. |
| Email/webhook | Per-attempt deadline and retry ceiling | Routing continues; terminal delivery failure stays visible. |
| Controller heartbeat | Bounded request/response and sequence | No accepted response means no renewed lease. |
| Local epoch barrier | Cancellation and join deadline | Unjoinable upstream work persists fatal/zero capacity and terminates the controller. |
| SQLite/locks | Busy deadline and single writer | Mutation fails before authority changes; recovery resumes from durable applying state. |
| Host/Docker subprocess | Context deadline plus bounded reap | Timeout kills/reaps the whole owned group or reports terminal cleanup failure; no unbounded wait. |
| InfluxDB/Grafana | Bounded adapter/query; no authority credential | Panels become no-data; authoritative receipts, not dashboards, gate cutover. |

## Global constraints

- Implement against the platform design. A conflict stops implementation and
  returns to design review.
- Use server receipt time for heartbeat freshness; client time is diagnostic.
- Authenticate exact method, path, timestamp, and canonical body. Verify MACs
  in constant time. Store only bounded nonce digests/expiries.
- Public values remain synthetic. Secrets and deployment identities stay in a
  mode-restricted private overlay and never enter tests, commits, logs, or
  command transcripts.
- Public CI remains GitHub-hosted, secretless, SHA-pinned, and timeout-bounded.
- The Worker owns `PORTABLE_GHAR_ROUTE`, `PORTABLE_GHAR_SCALE_SET`, and
  `PORTABLE_GHAR_LEGACY_LABEL`. Missing, empty, case-variant, or unknown route
  values select hosted.
- GitHub mutation intent and one variable-specific due row are persisted before
  each call. Timeout, partial success, rate limit, and ambiguity reconcile by
  exact read-back.
- Hosted confirmation binds route read-back to exact default-branch workflow
  blobs, job/check identities, and a successful GitHub-hosted route-attestation
  run.
- Every hosted transition advances the lease generation and stops renewal
  before routing work begins. It waits through the last server-recorded expiry
  plus the approved safety margin before hosted confirmation.
- Open queue-risk evidence from the latest local-to-hosted transition blocks
  Portable and legacy canary/acquisition until authenticated selective recovery
  is read back. Never cancel or rerun user work automatically.
- Repository archive state is a durable per-repository eligibility latch. It
  cannot be cleared by a later unarchive observation without an operator-
  approved configuration revision, hosted reconciliation, and canary.
- A hosted hold is the only maintenance freeze. An operator hold dominates
  runner-upgrade automation and never auto-releases.
- One current lease type authorizes either fenced local holder. Portable and
  legacy never use parallel remote authority protocols and never acquire
  concurrently.
- Notification failure never blocks or reverses routing. The optional webhook
  ends at authenticated acknowledgment; no messaging product or receipt bridge
  is mandatory.
- Numeric timeouts, capacities, tmpfs/memory/swap values, concurrency, retry
  ceilings, cadence, retention, and sample-skew bounds require separate
  operator sign-off. Source may define schemas and inequalities, not hidden
  defaults.
- Every task uses red-green-refactor, runs narrow then affected suites, stages
  exact paths only, and ends at a deliberate signed checkpoint.

---

## Task 0: Close Phase 2 hard bounds before Phase 3

**Files:** Modify `internal/hostruntime/command.go`,
`internal/productionruntime/controller_probe.go`, their tests,
`scripts/test-controller-runtime.sh`, and the affected Bats tests.

- [ ] Add RED tests proving a child that ignores termination cannot leave either
  command path blocked forever after the kill deadline.
- [ ] Implement a bounded post-kill reap/terminal-cleanup contract without
  weakening process-group ownership or false-success behavior.
- [ ] Add RED coverage proving the aggregate gate cannot wait for interactive
  confirmation when run by CI or an agent.
- [ ] Force noninteractive stdin in the aggregate harness and retain one direct
  EOF test for the interactive command itself.
- [ ] Run focused Go/Bats tests, `go test ./... -count=1`, and
  `scripts/test-controller-runtime.sh --unit < /dev/null`.
- [ ] Obtain exact-head distinct-family review with reliability/simplicity as
  blocking lenses before merging this prerequisite.

## Task 1: Implement the session, heartbeat, and lease protocols

**Files:** Create `worker/src/protocol/{auth,session,heartbeat,lease}.ts`,
`worker/test/protocol/` tests, `internal/failoverclient/` Go client and tests;
modify `worker/src/protocol/version.ts` and configuration schemas.

- [ ] Write RED tests for canonical request/response bytes, timestamp bounds,
  nonce replay, constant-time MAC verification, response/request binding,
  server epoch rollover, old-session rejection, sequence ordering, unknown
  fields, size limits, and generic rejection responses.
- [ ] Implement the one-step session exchange and signed heartbeat response.
- [ ] Implement exact `AcquisitionLeaseV1` validation and monotonic local expiry;
  prove stale, future, wrong-holder, wrong-policy, wrong-generation, altered,
  and expired leases cannot authorize acquisition.
- [ ] Prove a lost/ambiguous heartbeat response grants no lease and re-enrollment
  invalidates the old session without permanent lockout.
- [ ] Run Go race tests, Worker lint/typecheck/Vitest, schema validation, and
  protocol differential fixtures.

## Task 2: Implement six-table persistence and one Cron scheduler

**Files:** Create `worker/src/state/{schema,repository}.ts`,
`worker/src/scheduler/cron.ts`, migrations, and focused Worker tests.

- [ ] Write RED tests for first boot, migration replay, transaction rollback,
  bounded nonce/audit retention, unique transition epochs, and closed due-work
  kinds.
- [ ] Implement the six tables and typed repositories. Unknown migrations,
  schema drift, and corrupt identity fail hosted/closed.
- [ ] Write RED tests for bounded batch ordering, expiring claims, crash after
  claim, ambiguous effect, permanent failure, retry ceilings, and Cron outage.
- [ ] Implement one Cron scanner/claimer. Request handlers may claim only work
  they just persisted and cannot become the recovery guarantee.
- [ ] Add a repository test forbidding Durable Object alarms, private metadata
  tables, a second scheduler, and unbounded retry/history fields.

## Task 3: Implement idempotent GitHub routing and the six-state machine

**Files:** Create `worker/src/github/{client,outbox,attestation}.ts`,
`worker/src/routing/machine.ts`, fixtures, and focused Worker tests.

- [ ] Write RED tests for the six allowed states/transitions and reject direct
  Portable-to-legacy movement, inferred local routes, and checkpoint-shaped
  extra authority states.
- [ ] Persist transition plus variable-specific due rows before bounded GitHub
  calls. Classify `404`, `422`, rate-limit, timeout, and partial results from
  structured responses and exact read-back.
- [ ] Bind hosted confirmation to routing companions, default-branch head,
  workflow blob/content digest, job/check identity, and route-attestation.
- [ ] Advance lease generation and stop renewal before any hosted transition;
  require last-lease expiry/safety margin before hosted confirmation.
- [ ] Prove every effect is idempotent across crash/re-entry and an ambiguous
  mutation cannot become success without read-back.

## Task 4: Add canary, queue-risk, archive, and legacy rollback behavior

**Files:** Extend `worker/src/routing/`, add canary/queue-risk/archive tests and
consumer-neutral templates under `config/examples/` or `tests/fixtures/`.

- [ ] Implement Portable canary while routing stays hosted, with exactly one
  canary scale set and one capacity unit in the signed lease.
- [ ] Require the canary result plus a newer same-session enabled heartbeat and
  matching full-capacity lease before self-hosted intent.
- [ ] Persist queue-risk evidence for actual local-to-hosted transitions. Clear
  it only through nonce-protected selective GitHub read-back; never auto-cancel
  or rerun work.
- [ ] Implement the archive-disabled latch and operator reactivation path. A
  queued-forever archived dispatch is inert, never progress.
- [ ] Implement legacy canary and explicit legacy routing with the same lease
  type and one host fence. Prove watchdog races cannot yield dual holders.
- [ ] Add stale/late/wrong-head/wrong-label/wrong-environment canary tests and
  combined Worker/GitHub/host failure tests.

## Task 5: Integrate the controller without a second authority layer

**Files:** Modify the existing acquisition-policy/heartbeat/upgrade integration
and add focused Go tests; keep the current lifecycle engine and phase table.

- [ ] Adapt the existing `AcquisitionPermitProvider` to validate/derive a local
  operation proof from the cached signed lease. It must make no remote call and
  persist no remote per-operation record.
- [ ] Hold local epoch, eligibility, capacity, policy-digest, lease-generation,
  and fleet-fence guards through the acquisition decision.
- [ ] On missing/expired/mismatched lease, transition effective capacity to zero
  through the existing barrier; running jobs drain normally.
- [ ] Integrate maintenance directives as intent only. Status, CLI success, and
  upgrade observation never grant acquisition.
- [ ] Add cancellation-resistant upstream, stale listener, re-enrollment,
  release-update, restart, and combined-failure tests.
- [ ] If operation-family partitioning is needed for safe review, split the
  existing lifecycle implementation behind its current interfaces; do not add
  a parallel engine or duplicate phase table.

## Task 6: Add independent notifications and read-only observability

**Files:** Create Worker email/webhook modules and tests; add a schema-versioned
read-only `health.Snapshot` export, one-way InfluxDB adapter, cutover verifier,
Grafana provisioning assets, and docs/tests.

- [ ] Persist email and webhook as independent due-work kinds with attempt
  timeout, retry count/age ceiling, idempotent event ID, and sanitized content.
- [ ] Prove either/both channel failures do not block routing. Do not add a
  Signal-specific bridge or downstream receipt as a product gate.
- [ ] Preserve the existing liveness method and health socket peer/identity
  checks. Export only the closed health schema; no workload identity, secrets,
  paths, or mutation method.
- [ ] Implement a one-way least-privilege adapter for
  `portable_ghar_health`. The controller receives no InfluxDB or Grafana
  credential.
- [ ] Implement one projection-readiness gate: export, Influx write/query,
  reviewed dashboard revision, zero-idle semantics, and rollback anchors.
- [ ] Implement a small read-only cutover verifier over authoritative GitHub,
  controller-adapter, signed-heartbeat, scope, and configuration receipts.
  Grafana remains a human projection and cannot route or synthesize evidence.

## Task 7: Build the private overlay and target-safe operations tools

**Files:** Add strict private-overlay schemas and fixed-action tools under
`scripts/ops/`, QTS/systemd adapters, runbooks, and synthetic tests.

- [ ] Validate target/account/host identity, secret references, file modes, and
  exact repository/workflow/selector inventory without printing private values.
- [ ] Capture and verify encrypted legacy rollback material from live state;
  stale public/local references are not rollback evidence.
- [ ] Journal every host effect with an idempotent operation ID, applying/proven
  phases, fixed command allowlist, and post-effect read-back.
- [ ] Implement dark observer, hold, fence transfer, queue-risk recovery,
  canary, enable, hosted rollback, and legacy rollback tools. No tool accepts an
  arbitrary shell command or deletes a route to mean legacy.
- [ ] Test crash/re-entry, wrong target, Darwin/non-QTS refusal, dual-watchdog
  race, partial effect, rollback, and cleanup.

## Task 8: Execute dark deployment, migration, and failure drills

**Prerequisite:** Tasks 0-7 merged; reproducible release and Linux/Docker host
gates passed; exact numeric sizing/cadence approved; a separate live execution
packet approved.

- [ ] Capture current live identities and rollback artifacts; verify target and
  account immediately before every mutation phase.
- [ ] Deploy the controller force-disabled under the legacy fence. Prove zero
  acquisition and host conformance without changing consumer routing.
- [ ] Deploy Worker/DO/Cron privately; establish session and heartbeat with an
  explicit no-lease result while hosted hold is active.
- [ ] Reconcile every repository hosted and prove exact workflow/attestation
  bindings. Clear queue risk before canary.
- [ ] Pass projection readiness, dark receipts, queued canary, running canary,
  enabled/full-capacity receipts, and scope reconciliation.
- [ ] Exercise controller death, Docker loss/restart, host/uplink loss, Worker
  and Cron outage, GitHub timeout/rate-limit/partial success, stale/fatal health,
  notification failures, obsolete canary, and mutual-exclusion rollback.
- [ ] Stop immediately on target mismatch, unbounded call, dual holder, false
  success, missing read-back, resource leak, or architecture divergence.

## Task 9: Soak, retire legacy, and merge completion evidence

- [ ] Collect 14 consecutive complete 24-hour UTC windows. Any unexplained
  authority, evidence, cleanup, or resource-bounds gap restarts the soak.
- [ ] Prove no unconfirmed routing success, no local acquisition without a live
  exact lease, no dual holder, no unbounded due work/history/resource trend,
  and successful recovery from every required drill.
- [ ] Rehearse hosted and governed legacy rollback from exact retained artifacts
  while both acquisition paths remain zero through fence transfer.
- [ ] Retire the legacy watcher/writers/runners only through target-matched typed
  tools after the full pre-retirement gate passes.
- [ ] Retain verified encrypted rollback artifacts for 30 full days after
  retirement. Revoke/remove only artifacts the retained recovery procedure no
  longer requires.
- [ ] Create a second signed evidence/completion PR. Keep “source implemented”
  distinct from “fully verified/deployed” until every positive operational gate
  passes.

## Final positive verification

- [ ] Session/heartbeat replay, sequence, epoch, response binding, and lease
  expiry tests pass across Go and Worker implementations.
- [ ] Exactly one routing writer, one scheduler, one lease protocol, six routing
  states, and one local lifecycle engine are present.
- [ ] Every external effect is durably intended, bounded, idempotent, and read
  back before success.
- [ ] Worker/Cron outage expires local authority and is reported as queued/
  availability-degraded, not confirmed hosted failover.
- [ ] Hosted hold, queue-risk clearance, canary, enabled lease, archive latch,
  and legacy rollback all pass current-epoch exact-identity tests.
- [ ] Email/webhook fail independently and cannot affect routing.
- [ ] Health export, Influx adapter/query, Grafana projection, and authoritative
  cutover verifier pass without giving observability routing authority.
- [ ] Linux/Docker isolation, reclamation, reproducibility, forced runner-version
  bump, sizing, dark deployment, migration, drills, soak, and rollback evidence
  are positive.
- [ ] README status changes only after the exact public claims are true and
  independently verified.

## Stop condition

After the declared failover/deployment completion checkpoint is signed, pushed,
reviewed, and merged, pause. Do not begin another phase, deploy additional
features, mutate unrelated hosts, or retire retained rollback artifacts without
new operator direction.
