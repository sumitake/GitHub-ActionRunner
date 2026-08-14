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
durable scheduler and addresses every deterministic fleet object from one
validated, bounded private `fleetIds` inventory. A six-state routing machine
keeps implementation checkpoints out of authority state. Email and an optional
signed webhook are independent notifications, never routing evidence.

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
  the server-owned `leaseNotBefore` restriction plus Worker receipt time.
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
- exact acquisition-policy digest, repository-policy revision, and the local
  acquisition-policy epoch accepted from this heartbeat;
- maximum capacity and the one eligible canary scale set when canary-only;
- a canonical bounded `archivedDisabledAliases` set of Worker-latched
  repository aliases; and
- server-owned validity duration `L`, checked server expiry equal to this
  heartbeat's Worker receipt time plus `L`, and response MAC.

V1 is a closed schema. Its canonical admission-authority key contains every
authority-bearing field above, including protocol version, canonical
present-or-absent canary scale set, canonical archive-disable set, and `L`.
Only the accepted heartbeat sequence, Worker receipt time, absolute expiry,
derived local deadline, and response MAC are renewal-envelope data. Unknown,
duplicate, missing, or noncanonical fields fail validation instead of being
ignored by the key derivation.

The controller uses one injected suspend-aware monotonic authority clock for
heartbeat send anchors, lease/operation comparisons, and absolute deadline
wakeups. Linux/QTS production uses `CLOCK_BOOTTIME` for both `Now` and
`WaitUntil`; a target that cannot prove both keeps acquisition disabled rather
than falling back to suspend-pausing `CLOCK_MONOTONIC`. The controller records
that clock before sending the heartbeat and derives the lease deadline from
that attempt-start observation, the returned duration, and the approved
shortening margin. A response received at or after that
deadline grants no lease, so response latency cannot make local authority
outlive server expiry. Every operation also rejects its repository alias when
it appears in the signed disable set. Lease installation and every later use
require the authenticated local epoch and digest to equal the current persisted
policy; every policy transition atomically advances the epoch and discards the
cache while the existing barrier remains closed through old-operation join.
The controller never extends authority from wall time, status, or an
administrative command.

The signed lease cache and derived deadlines are process-memory-only; controller
restart begins empty, and per-job containers never restart after host reboot.
Each poll/acquire/JIT operation sets one authority-clock deadline to the earlier
of `now + configured call duration` and the local lease deadline minus the
existing positive cancel/join/fatal/termination tail. Checked arithmetic, exact
equality, missing tail bounds, or insufficient slack fails before the call. One
small per-operation mutex serializes the deadline handler with a two-way
`active -> admitted|dropped` token: the handler cancels only while active; the
normal path snapshots the canonical key, original shortened deadline, and exact
host-fleet fence generation. At final commit it atomically loads one immutable
current cache entry and admits only before both the original deadline and that
entry's checked local deadline minus the same termination tail, with uncancelled
context, a fully valid equal key, and unchanged epoch/digest/fence generation,
then disarms the handler. Signature, expiry, key, and deadline come from that
same entry. A newer-sequence routine
renewal may replace only renewal-envelope data, keep the key/fence unchanged,
and move its send-anchored deadline forward; it therefore does not starve a
long operation. Any authority change or regressing renewal drops. A dropped,
late, or ambiguous result may enter only the existing idempotent reconciliation
journal, whose assignment identity excludes renewal-envelope fields, and cannot
Ack or release a runner. The existing local `AcquisitionPermitProvider` derives
its proof from the cached lease, performs no network call, and creates no remote
per-operation state.

Archive restriction is deliberately bounded rather than falsely described as
instantaneous. The Worker persists the last successful archive observation for
each configured repository. Missing, `archived=true`, or older-than-approved
evidence places the alias in the restrictive lease set. A pre-restriction lease
can remain usable until its existing local deadline: a restrictive replacement
response stops new controller operations but cannot rewrite a listener already
released under the prior lease. The normative repository-wide convergence point
is therefore that deadline. The maximum interval from a just-after-observation
GitHub archive change is the approved evidence-age bound plus the maximum
remaining local lease lifetime. Work acquired before that convergence point may
drain and is audited; work beginning at or after it is denied. This closes the
failure case without push delivery, a second protocol, or a remote call per
acquisition.

The operator-approved heartbeat configuration must satisfy
`L > (N + 1) * H + D + S`, where `H` is the maximum interval between attempt
starts, `D` is the enforced end-to-end heartbeat deadline, `S` is the local
shortening margin, `L` is the server-owned lease duration, and `N >= 1` is the
number of wholly lost renewal attempts to tolerate. Source supplies no numeric
default.

### Routing states

Only these authority states are persisted:

```text
UNINITIALIZED (not an authority state) -> HOSTED
HOSTED -> PORTABLE_CANARY -> PORTABLE
PORTABLE_CANARY -> DRAINING_TO_HOSTED -> HOSTED
HOSTED -> LEGACY_CANARY   -> LEGACY
LEGACY_CANARY -> DRAINING_TO_HOSTED -> HOSTED
PORTABLE -> DRAINING_TO_HOSTED -> HOSTED
LEGACY   -> DRAINING_TO_HOSTED -> HOSTED
```

Canary dispatch/result, GitHub mutation/read-back, lease expiry, queue-risk
clearance, notifications, and retries are transition outcomes, not additional
routing states. All Portable-to-legacy movement passes through hosted.
Bootstrap issues no lease and persists `HOSTED` only after exact hosted
read-back. A failed or cancelled canary advances the lease generation, stops
renewal, and uses the existing `DRAINING_TO_HOSTED` state through
`lastIssuedLeaseExpiryMax` plus the approved safety margin. Routing never left
hosted, and every released listener's local deadline is strictly earlier than
that boundary, so no route mutation, queue-risk row, or positive controller
drain report is needed. `HOSTED` is not persisted until the bounded lease
residual ends.

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

`fleet_state` includes fleet-global monotonic `lastIssuedLeaseExpiryMax` and the
current session's `leaseNotBefore`. Issuing a lease and max-advancing the former
are one transaction; enrollment atomically computes the latter as the maximum
of Worker receipt time, any existing restriction, and the issued-lease maximum
plus the existing positive hosted-transition safety margin. It does not add a
handoff endpoint, controller registry, or second lease protocol.

### Durable scheduling

One Cloudflare Cron Trigger validates a canonical, duplicate-free, size-bounded
private `fleetIds` inventory and addresses every listed deterministic Durable
Object directly; Durable Object namespaces are never assumed enumerable.
Per-fleet calls have enforced deadlines and bounded concurrency. Each addressed
object claims a bounded due-work batch. The fleet count/deadline/concurrency/
Cron-period inequality must fit the platform execution budget before
deployment. Request handlers may opportunistically execute work they just
persisted, but recovery never depends on another request. Durable Object alarms
are not a second scheduler. Expired claims return to the queue; permanent
failures stay visible. Enrollment and lease renewal fail closed for a fleet
missing from that same inventory; fleet addition requires positive Cron
addressability, and fleet removal requires hosted/zero-lease/empty-due-work
proof first.

If the Worker and Cron path are both unavailable while GitHub still routes
locally, the short lease expires and new local acquisition stops. Jobs may queue
on the last confirmed route until recovery. This availability degradation is
explicit, observable, and never reported as hosted failover.

## External dependency failure contract

| Dependency | Bound | Safe degradation and proof |
| --- | --- | --- |
| Cloudflare Worker/DO | Request deadline; short lease lifetime | Lease expires; new local acquisition stops; no status or cached response extends it. |
| Cron Trigger/fleet inventory | Bounded fleet count, per-fleet deadline/concurrency, batch/claim/retry age | Every configured object is addressed directly; invalid/absent inventory blocks authority, due work waits durably, and no second scheduler masks an outage. |
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
  before routing work begins. It waits through `lastIssuedLeaseExpiryMax` plus
  the approved safety margin before hosted confirmation. With Cron
  functioning, its completion budget covers the lease window, safety margin,
  one Cron period, bounded delivery jitter, and one bounded due-work
  execution/read-back attempt; an outage never becomes false success.
- Every replacement enrollment rejects old-session traffic immediately but
  issues no new lease before the carried-forward fleet-global issued-lease
  maximum plus that same safety margin. A first enrollment has no predecessor
  delay; an intervening no-lease session and repeated enrollment never shorten
  the restriction, and no predecessor callback is required. Drain heartbeats
  expose `predecessor-lease-draining` as liveness-only status, never acquisition
  readiness, failback evidence, hosted success, or zero-listener quiescence
  evidence. The latter is accepted only from the exact enrollment session and
  lease generation whose listeners are being drained; supersession before that
  proof leaves the governed local transition incomplete under hosted-safe
  routing and alerts.
- Open queue-risk evidence from the latest local-to-hosted transition is one
  bounded current record per repository and blocks
  Portable and legacy canary/acquisition until authenticated selective recovery
  is read back. Never cancel or rerun user work automatically.
- Repository archive state is a durable per-repository eligibility latch. It
  is carried in the lease as a signed restrictive alias set, so one archived
  repository stops without stalling unrelated repositories. Archive evidence
  has an approved maximum age; missing or stale evidence is restrictive. The
  accepted propagation bound is evidence age plus the remaining local lease,
  and no claim may imply instantaneous revocation. The latch cannot be cleared
  by a later unarchive observation without an operator-approved configuration
  revision, hosted reconciliation, and canary.
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
  server epoch rollover, old-session rejection, predecessor-lease drain,
  sequence ordering, unknown fields, size limits, and generic rejection
  responses.
- [ ] Implement the one-step session exchange and signed heartbeat response.
- [ ] Implement exact `AcquisitionLeaseV1` validation, send-anchored
  authority-clock expiry, authenticated local acquisition-policy epoch, and the
  signed archive-disable set. Prove stale, future, wrong-holder, wrong-policy,
  wrong-local-epoch, wrong-generation, altered, late-response,
  unknown/duplicate/unsorted alias, expired, and old-cache-after-restart leases
  cannot authorize acquisition; include enabled-disabled-enabled ABA.
- [ ] Implement one injected authority clock with Linux/QTS `CLOCK_BOOTTIME`
  `Now` and absolute `WaitUntil`; use it for send anchors, local lease deadlines,
  operation cancellation, final admission, and listener job acceptance. Prove
  host suspension counts against every deadline and unsupported clock/waiter
  capability leaves acquisition disabled with no ordinary-monotonic fallback.
  Keep the cache and derived deadlines process-memory-only; restart/reboot begins
  with no acquisition authority.
- [ ] Implement the closed canonical admission-authority key and strict total V1
  field mapping. Prove repeated authority-equivalent renewals during a long poll
  preserve one admission, while one-at-a-time changes to every key field,
  canary absence/presence, archive aliases, `L`, or fence generation drop it.
  Reject unknown/missing fields, bad MAC, stale sequence, regressing deadline,
  and mixed-entry cache reads.
- [ ] Prove missing/stale archive evidence is restrictive, a failed metadata
  read cannot refresh evidence age, and the archive event-to-denial interval
  never exceeds the approved evidence-age plus remaining-local-lease bound. A
  restrictive replacement stops new controller acquisition immediately but
  cannot count as repository-wide convergence while a listener released under
  the preceding lease remains before its original local deadline; prove the
  exact deadline boundary.
- [ ] Write RED tests for the heartbeat/lease inequality, including one wholly
  lost renewal followed by recovery inside the approved budget and rejection
  when any symbolic term makes the inequality false.
- [ ] Prove a lost/ambiguous heartbeat response grants no lease and re-enrollment
  invalidates the old session without permanent lockout. Cover first enrollment
  with no prior lease, a still-live predecessor lease, exact
  `leaseNotBefore` equality, an already-expired predecessor, repeated
  enrollments and an intervening no-lease session that preserve the maximum
  drain, old-session traffic during the drain, and no new recorded lease before
  the boundary. Prove lease issuance atomically max-advances the fleet-global
  expiry, that it never recedes after a shorter later lease, that a pre-commit
  failure grants nothing, and that a lost post-commit response remains covered
  by later enrollment. Race an old-session heartbeat with enrollment and prove
  either the lease commits first and enters the drain maximum, or enrollment
  commits first and the old heartbeat grants no lease. Reject regressing Worker
  receipt time without shortening the drain.
- [ ] Prove zero-listener quiescence accepts only the exact enrollment session
  and lease generation being drained. A replacement drain heartbeat reporting
  zero for its new generation must not complete a governed legacy rollback,
  administrative hold, or upgrade drain; supersession before exact proof stays
  hosted-safe and alerts.
- [ ] Run Go race tests, Worker lint/typecheck/Vitest, schema validation, and
  protocol differential fixtures.

## Task 2: Implement six-table persistence and one Cron scheduler

**Files:** Create `worker/src/state/{schema,repository}.ts`,
`worker/src/scheduler/cron.ts`, migrations, and focused Worker tests.

- [ ] Write RED tests for first boot, migration replay, transaction rollback,
  bounded nonce/audit retention, unique transition epochs, and closed due-work
  kinds.
- [ ] Implement the six tables and typed repositories, including at most one
  bounded `openQueueRisk` record per repository for the latest applicable
  transition. Cleared history moves only to bounded audit events. Unknown
  migrations, schema drift, and corrupt identity fail hosted/closed.
- [ ] Write RED tests for bounded batch ordering, expiring claims, crash after
  claim, ambiguous effect, permanent failure, retry ceilings, and Cron outage.
- [ ] Write RED tests proving a Cron handler cannot enumerate a Durable Object
  namespace, rejects invalid/duplicate/oversized fleet inventories, addresses
  every configured deterministic object once, and does not starve healthy
  fleets when one call times out.
- [ ] Implement one Cron scanner/claimer over the validated private `fleetIds`
  inventory with bounded per-fleet deadlines/concurrency. Session and lease
  paths reject an absent fleet; addition requires Cron-addressability read-back,
  and removal requires hosted, zero-lease, empty-due-work proof. Request handlers
  may claim only work they just persisted and cannot become the recovery
  guarantee.
- [ ] Add a repository test forbidding Durable Object alarms, private metadata
  tables, a second scheduler, and unbounded retry/history fields.

## Task 3: Implement idempotent GitHub routing and the six-state machine

**Files:** Create `worker/src/github/{client,outbox,attestation}.ts`,
`worker/src/routing/machine.ts`, fixtures, and focused Worker tests.

- [ ] Write RED tests for the six persisted authority states, fail-closed
  bootstrap into `HOSTED`, both direct canary-abort edges, and the allowed
  active-route transitions; reject direct Portable-to-legacy movement, inferred
  local routes, and checkpoint-shaped extra authority states.
- [ ] Persist transition plus variable-specific due rows before bounded GitHub
  calls. Classify `404`, `422`, rate-limit, timeout, and partial results from
  structured responses and exact read-back.
- [ ] Bind hosted confirmation to routing companions, default-branch head,
  workflow blob/content digest, job/check identity, and route-attestation.
- [ ] On every heartbeat lease decision, compare Worker time with the persisted
  exact selector-evidence receipt time for every configured repository. Missing,
  invalid, mismatched, or stale evidence must atomically advance lease
  generation, persist the existing hosted transition and due work, and return
  no lease even when Cron delivery is absent. Prove the one Cron scheduler can
  later resume that work; do not add a heartbeat scheduler or watcher.
- [ ] Advance lease generation and stop renewal before any hosted transition;
  require the `lastIssuedLeaseExpiryMax` boundary and safety margin before
  hosted confirmation.
- [ ] Prove every effect is idempotent across crash/re-entry and an ambiguous
  mutation cannot become success without read-back.

## Task 4: Add canary, queue-risk, archive, and legacy rollback behavior

**Files:** Extend `worker/src/routing/`, add canary/queue-risk/archive tests and
consumer-neutral templates under `config/examples/` or `tests/fixtures/`.

- [ ] Implement Portable canary while routing stays hosted, with exactly one
  canary scale set and one capacity unit in the signed lease; a failed or
  cancelled canary advances the generation, stops renewal, and reuses
  `DRAINING_TO_HOSTED` until the fleet-global issued-lease maximum plus margin.
  Prove routing stays hosted without a new mutation/queue-risk row, reaches
  `HOSTED` without a later controller heartbeat, and admits no cached canary
  lease at or after the exact boundary.
- [ ] Require the canary result plus a newer same-session enabled heartbeat as
  full-capacity route-readiness evidence before self-hosted intent, but issue no
  enabled lease while routing remains hosted. After exact self-hosted read-back
  enters `PORTABLE`, require a subsequent matching heartbeat and enabled lease
  before local acquisition.
- [ ] Persist queue-risk evidence for actual local-to-hosted transitions. Clear
  it only through the nonce-protected `queue-recovery` member of the closed
  admin-command union plus selective GitHub read-back; never auto-cancel or
  rerun work.
- [ ] Implement the archive-disabled latch, the signed restrictive alias set in
  each lease, archive-evidence freshness, and the operator reactivation path. A
  dispatch still queued at the bounded archive convergence point is inert,
  while work acquired under a still-current pre-restriction lease may drain and
  is audited; unrelated repositories retain their current lease authority.
- [ ] Implement legacy canary and explicit legacy routing with the same lease
  type and one host fence. Prove watchdog races cannot yield dual holders.
- [ ] Add stale/late/wrong-head/wrong-label/wrong-environment canary tests and
  combined Worker/GitHub/host failure tests. Stop Cron after one valid selector
  observation, advance Worker time through the evidence-age boundary, and prove
  a healthy heartbeat still returns no lease and persists resumable hosted work.

## Task 5: Integrate the controller without a second authority layer

**Files:** Modify the existing acquisition-policy/heartbeat/upgrade integration
and add focused Go tests; keep the current lifecycle engine and phase table.

- [ ] Adapt the existing `AcquisitionPermitProvider` to validate/derive a local
  operation proof from the cached signed lease. It must make no remote call and
  persist no remote per-operation record.
- [ ] Hold local epoch, eligibility, capacity, policy-digest, lease-generation,
  and fleet-fence guards through the acquisition decision.
- [ ] Bound every poll/acquire/JIT call, its validation, and non-authorizing
  durable preparation by one authority-clock deadline: the earlier of
  `now + configured call duration` or local lease deadline minus the proven
  termination tail. Serialize deadline cancellation and admission with one
  per-operation mutex and two-way token. Snapshot the
  original deadline, closed admission-authority key, and exact fence generation;
  final admission atomically validates one whole current cache entry and both
  its safe deadline and the original deadline. A newer-sequence pure renewal
  may change only envelope timing/MAC fields and cannot extend the original
  deadline; any authority or fence change drops. Only a current, uncancelled,
  pre-deadline admission may Ack or release a runner. Route late or ambiguous
  remote effects through the existing idempotent journal/read-back path.
- [ ] On missing/expired/mismatched lease, transition effective capacity to zero
  through the existing barrier; running jobs drain normally.
- [ ] Bind every released listener to the lease enrollment session/generation
  and send-anchored local deadline as well as local epoch/fence. At job accept,
  destroy it when any locally observable binding is superseded or the local
  deadline is reached. Prove a still-live predecessor cannot accept at or after
  that deadline, and separately prove the replacement receives no acquisition
  lease before the later `leaseNotBefore` boundary. Do not claim asynchronous
  revocation merely from replacement enrollment.
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
- [ ] Validate the canonical bounded `fleetIds` inventory, its revision/digest,
  Cron execution-budget inequality, and per-fleet addressability without
  creating a second fleet registry.
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
  explicit no-lease result while hosted hold is active. Prove the deployed Cron
  addresses every configured fleet object from the exact private inventory.
- [ ] Reconcile every repository hosted and prove exact workflow/attestation
  bindings. Clear queue risk before canary.
- [ ] Pass projection readiness, dark receipts, queued canary, running canary,
  pre-route enabled/full-capacity readiness, post-read-back enabled-lease
  receipts, and scope reconciliation.
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
- [ ] The exact bounded fleet inventory addresses every per-fleet Durable Object
  on each Cron tick; invalid addition/removal and execution-budget overflow fail
  closed without a second registry or scheduler.
- [ ] Send-anchored lease expiry, the heartbeat/lease inequality, and the
  signed archive-disable set pass exact cross-language tests without adding a
  second authority protocol; stale archive evidence and the bounded
  event-to-denial window are covered explicitly.
- [ ] Every external effect is durably intended, bounded, idempotent, and read
  back before success.
- [ ] Worker/Cron outage expires local authority and is reported as queued/
  availability-degraded, not confirmed hosted failover.
- [ ] Hosted hold, queue-risk clearance, canary, pre-route readiness evidence,
  post-read-back enabled lease, archive latch, and legacy rollback all pass
  current-epoch exact-identity tests.
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
