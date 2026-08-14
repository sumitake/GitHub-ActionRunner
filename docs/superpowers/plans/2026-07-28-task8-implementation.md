# Task 8 Implementation Plan: Acquisition Barrier, Controller Cycles, Health, and CLI

> Status: source design only. This plan does not authorize or perform any
> Docker, QTS, RhoNAS, selector, routing, release, deployment, or host-
> configuration mutation. Numeric runner sizing remains a separate operator-
> signoff gate.

**Phase 3 authority amendment:** This completed Phase 2 plan remains the history
and contract for the local epoch barrier and acquisition interface. Future
external authority uses one cached, short-lived signed lease renewed by
heartbeat; the local permit interface derives an operation proof without a
remote per-operation call. Platform-design §9 and the failover plan are
normative over any older permit wording below.

**Goal:** Complete the controller's source-level poll, acquire, admit, one-job
JIT, reconciliation, revocation, health, and command surfaces without allowing
local intent, a stale broker lease, or an unavailable authority provider to
create work.

**Architecture:** One persisted acquisition epoch is the only live-policy
barrier. Every nonzero `Poll`, `Acquire`, or `GenerateJIT` enters that epoch,
holds one current host-fleet guard, derives one operation proof locally from one
whole cached signed Worker lease, revalidates its exact local inputs, and leaves
before a policy transition returns. The
admission broker consumes `Statistics.TotalAssignedJobs` as desired runner
count, journals exact upstream acquisition outcomes before message
acknowledgement, and never creates a slot for a rejected or ambiguous request.
Reconciliation is the only path from an admitted slot into the Task 7
lifecycle. Successful reconciliation produces a closed health snapshot;
failures produce no heartbeat. The Task 8 executable exposes the required
commands but ships unavailable host/permit providers, so it cannot perform
nonzero work before later tasks provide those authorities.

**Tech stack:** Go 1.26.0 with toolchain 1.26.5, `modernc.org/sqlite`,
the pinned `github.com/actions/scaleset v0.4.0` adapter, the Task 4 admission
broker, the Task 7 lifecycle/reconciler, and table-driven/race tests.

## Scope Correction Required by the Existing Source

The Task 8 file list names controller, health, observability, and CLI files,
but the already-implemented Tasks 2-4 expose two load-bearing gaps that cannot
be repaired by controller glue alone:

1. `PollLease.Epoch` currently carries repository-policy revision. The
   canonical design requires the current acquisition epoch so every mode,
   capacity, and eligibility transition invalidates old poll capacity.
2. `PollOnce` persists offers but never calls or journals `Session.Acquire`.
   Therefore the current source cannot prove that only upstream-accepted
   requests reach runner creation or that acquisition completed before Ack.
3. The repository has no production `lifecycle.SetupBuilder`, production
   `lifecycle.SessionProvider`, health transport, live-admin transport, or
   controller composition configuration. The current public runtime document
   intentionally carries only transport selection, one secret reference, and
   bounded-history sizing. It does not carry repositories, immutable
   admission templates, host-runtime identities, controller deadlines and
   cadences, or a health endpoint. Consequently a production Task 8 factory
   cannot construct the Task 7 lifecycle or safely recover nonempty state
   without inventing configuration or substituting no-op cleanup.

Task 8 will make narrowly scoped changes in `internal/admission`,
`internal/state`, and `internal/lifecycle` to close those seams. It will not
change resource sizing, network-jail policy, Docker configuration, or host
authority. The command parser, exclusive-writer boundary, and injected
controller/admin ports land in Task 8, but the production `OpenController`
factory remains explicitly unavailable. Task 10, which owns the runtime
manifest and crash-resumable host lifecycle, must add the complete
configuration/composition graph and then prove that `run` restores and runs a
disabled observer. Returning unavailable is safer than a fake observer: it
cannot skip recovery, silently discard heartbeat failures, or report
quiescence without Task 7 cleanup authority.

## Canonical Public Boundaries

Define the canonical interfaces exactly as follows:

```go
package controller

type AcquisitionTransitioner interface {
	Snapshot(context.Context) (AcquisitionPolicy, error)
	Transition(context.Context, uint64, AcquisitionPolicy) (AcquisitionPolicy, error)
}

type AcquisitionGuard interface {
	Close() error
}

type FleetGuardProvider interface {
	AcquirePortable(context.Context) (AcquisitionGuard, error)
}

type AcquisitionPermitRequest struct {
	OperationID     string
	RepositoryAlias string
	ScaleSetName    string
	PolicyDigest    string
	OperationKind   string
	PolicyEpoch     uint64
}

type AcquisitionPermitProvider interface {
	Acquire(context.Context, AcquisitionPermitRequest) (AcquisitionGuard, error)
}

type FatalTerminator interface {
	TerminateAfterPersist(ReasonCode)
}

type HealthPublisher interface {
	Publish(context.Context, health.Snapshot) error
}
```

`AcquisitionGuard` remains opaque. The trusted permit-provider implementation
is responsible for decoding and validating the Worker response, including
exact request equality, Worker transition epoch, permit generation,
single-use state, and server-owned expiry, before it returns a guard. The
controller never receives or persists a bearer token. It retains the guard
through the external call; a failed or ambiguous `Close` is an operation
failure. Tests inject providers that reject reused, expired, wrong-operation,
wrong-policy, wrong-repository, wrong-scale-set, superseded, or unavailable
permits before any external effect.

The `Service` will satisfy:

```go
Run(context.Context) error
ReconcileOnce(context.Context) (CycleReceipt, error)
Snapshot(context.Context) (AcquisitionPolicy, error)
Transition(context.Context, uint64, AcquisitionPolicy) (AcquisitionPolicy, error)
```

The injected raw transitioner is only the durable compare-and-set store. No
watchdog, CLI, pressure callback, suspension path, or test helper may call it
around the live service.

## Threat Model and Failure Classes

The implementation must fail closed against:

1. stale poll capacity surviving a mode, eligibility, repository-policy, or
   capacity transition;
2. a local CLI/status result being mistaken for Worker authority;
3. an authority provider returning success for a mismatched or expired
   request;
4. `Poll`, `Acquire`, or JIT ignoring cancellation after its deadline;
5. an acquisition request succeeding upstream but crashing before its result
   is durable;
6. a partial or reordered acquisition result creating a runner for a rejected
   request;
7. message redelivery repeating a completed acquisition or Ack under different
   bytes;
8. offer count being used as desired runner count instead of
   `TotalAssignedJobs`;
9. one repository consuming another repository's lease, demand, or permit;
10. a policy transition returning while an older external effect or
    acquisition critical section is still live;
11. a released, unassigned listener surviving revocation and accepting work
    after its authority is superseded;
12. a revocation killing a durably `JOB_RUNNING` assignment that should drain;
13. publishing a heartbeat after partial/failed reconciliation;
14. eligible scale-set names, repository/job coordinates, JIT, credentials,
    paths, routes, request bodies, or command output entering health/logs;
15. a command-line process mutating SQLite behind a live controller rather
    than using the same barrier;
16. acquisition-history rows or operational summaries growing without the
    existing bounded-history accounting and retention rules.

## Architecture and TDD Tasks

### Task 1: Canonicalize and digest acquisition policy

**Files:**

- Modify `internal/controller/model.go`.
- Create `internal/controller/acquisition.go`.
- Create `internal/controller/acquisition_test.go`.

- [ ] Add strict policy validation and canonicalization. Modes are closed;
  `disabled` and `fatal` require zero capacity and no eligible scale set;
  `canary-only` requires capacity one and exactly one eligible scale set;
  `enabled` requires positive capacity. Repository aliases and scale-set names
  are nonempty, bounded UTF-8 strings without NUL, tab, CR, or LF. Eligible
  names and repository aliases are unique.
- [ ] Implement the exact V1 digest bytes from the platform design:
  domain line, lowercase mode, decimal capacity, decimal repository-policy
  revision, unsigned-UTF-8-sorted eligible names, `--`, and unsigned-UTF-8-
  sorted repository summaries. Every line ends in LF. Epoch is excluded.
- [ ] Canonicalize before persistence: sorted copies only, no caller slice
  aliasing, no duplicate-equivalent input, and no normalization or
  case-folding of names.
- [ ] Replace the pre-Task-8 `Current` interface method with canonical
  `Snapshot`, and add compile-time assertions for all canonical interfaces.
- [ ] RED/GREEN tests cover exact byte vectors and hashes; empty sections;
  reordered equivalent input; duplicates; invalid modes/eligibility; negative
  or inconsistent capacity; decimal and separator ambiguity; tabs/newlines;
  nil versus empty slices; and mutation after digesting.

### Task 2: Journal acquisition intent/results and revocation state

**Files:**

- Modify `internal/state/migrations.go`, `store.go`, `sqlite.go`,
  `controller_adapter.go`, and their tests.
- Modify `internal/controller/service.go` durable-state projections.

- [ ] Add schema V3 with one bounded `message_acquisitions` row per
  `(repository_alias, message_id)` and acquisition fields on each assignment.
  The batch row stores only canonical request/result SHA-256 digests, closed
  state (`begun`, `not_attempted`, `completed`, or `ambiguous`), timestamps,
  and checked logical bytes. Assignment rows store only closed outcome
  (`offered`, `requested`, `acquired`, `rejected`) plus the source message
  identity. Runner request IDs already belong to the durable assignment key
  and are not duplicated as an open JSON payload.
- [ ] `BeginAcquisition` atomically verifies that the exact sorted requested
  set belongs to offers durably recorded under that message, writes the batch
  intent, and moves those assignments to `requested`. Exact replay is a no-op;
  changed membership/digest fails. It rejects an empty requested set; a poll
  with no eligible offers performs no acquisition operation.
- [ ] `AbortAcquisitionBeforeCall` is legal only while the batch is `begun`
  and the tracked external-call boundary proves `Acquire` has not started. In
  one transaction it moves `requested` assignments back to `offered` and the
  batch to `not_attempted`, retaining the exact request digest. An exact
  redelivery may reopen that same row through `BeginAcquisition`; different
  membership or digest fails. `not_attempted` is never eligible for admission
  or JIT and is never promoted to ambiguous at startup.
- [ ] `CompleteAcquisition` accepts a unique returned subset of the requested
  set, atomically marks that subset `acquired`, marks the remainder `rejected`,
  stores the canonical result digest, and closes the batch before Ack. A
  duplicate, foreign, noncanonical, digest-conflicting, or reordered-
  conflicting result fails with no partial write. The returned subset may be
  empty: that is a completed all-rejected result and queues no broker work.
- [ ] A call error after `BeginAcquisition` marks the batch `ambiguous`; it is
  never blindly retried. The service persists fatal/zero and invokes the
  terminator because upstream may own any subset. No requested/ambiguous row
  is eligible for admission or JIT.
- [ ] Add `MarkPreRunningRevoked(newEpoch)` in one transaction. It marks every
  nonterminal assignment that has not durably reached `JOB_RUNNING`, including
  `offered`, `requested`, `rejected`, acquired-but-not-reserved, and migrated
  queued rows. Revocation must distinguish rows with no listener/runtime
  identity from rows that reached `CAPACITY_RESERVED`: `RECEIVED` rows advance
  directly through the checked pre-release terminal shortcut without building
  or cleaning a nonexistent runtime, while later acquired rows use full
  lifecycle cleanup. A Started observation that later encounters the mark
  must run exact cleanup and terminal resolution rather than bind the stale
  listener.
- [ ] Add an aggregate operational query returning assigned/running count,
  oldest live-assignment age, unassigned `LISTENER_RELEASED` count, and latest
  terminal time without returning identities.
- [ ] Include acquisition rows/bytes in bounded-history usage. Compact their
  row only after the linked receipt and assignment graph meet the existing
  retention rules. Add v2-to-v3 all-or-nothing migration fault injection and
  read-only future/old-schema rejection.
- [ ] RED/GREEN state tests cover begun-to-not-attempted rollback and exact
  reopen, mismatched reopen rejection, empty-result all-rejected completion,
  duplicate/foreign/conflicting results with no partial write, surviving
  `begun` promotion on restart, and exclusion of every non-`acquired` outcome
  from admission and JIT.

### Task 3: Make the admission broker acquisition-epoch and demand aware

**Files:**

- Modify `internal/admission/resources.go`, `broker.go`,
  `controller_adapter.go`, and tests.
- Modify the controller-owned `AdmissionBroker` port in
  `internal/controller/service.go`.

- [ ] Extend the native policy revision operation with an explicit effective
  capacity and use its strictly increasing epoch as the acquisition epoch.
  Applying a newer epoch cancels all leased/reserved nonactive capacity,
  replaces the validated repository policy set, sets the effective capacity
  in either direction up to the immutable configured ceiling, and marks excess
  active slots retire-on-release. The older `SetPressure` API remains
  reduction-only; it cannot be used to restore capacity.
- [ ] Construct `admission.ControllerAdapter` with immutable full repository
  templates. For each acquisition transition it overlays only the exact
  controller-owned alias/max-concurrency/eligibility summary, preserving
  weight, aging threshold, and resource profile. Missing, extra, duplicate, or
  changed aliases fail closed.
- [ ] Add `SetDemand(repositoryAlias, acquisitionEpoch, totalAssignedJobs)`.
  Demand is nonnegative, epoch-bound, and per repository. `Admit` may create
  active slots only until the repository's active/reserved count reaches that
  demand; queue length never substitutes for demand. A new broker or policy
  epoch starts with zero demand until a poll supplies statistics.
- [ ] Split a poll lease's advertised upstream capacity from residual broker
  ownership. `Reserved` is the exact number of new slots committed to that
  poll and the hard maximum number of offers that may enter `Acquire`.
  `PollCapacity` is the capacity passed to GitHub: the repository's owned
  active-plus-reserved capacity after leasing, clamped to the current
  repository concurrency and fleet effective-capacity ceilings. Residual
  active slots above a reduced ceiling remain retire-on-release but are not
  exposed as acquisition authority. When effective capacity is zero,
  `PollCapacity` and `Reserved` are both zero even while preserved running
  jobs remain.
- [ ] Expose a closed capacity snapshot with configured/effective/occupied/
  available/queued counts for health, without repository or assignment
  identities.
- [ ] Prove old leases fail after every epoch change, canary capacity is
  exactly one, disabled is zero, explicit re-enable may restore capacity only
  under a newer persisted epoch, pressure cannot increase capacity, and one
  repository's demand/lease cannot admit another's work.

### Task 4: Implement the bounded live acquisition barrier

**Files:**

- Modify `internal/controller/service.go` and tests.
- Create `internal/controller/acquisition_barrier.go` and
  `internal/controller/acquisition_barrier_test.go`.

- [ ] Replace the global network-call mutex with a transition mutex plus one
  epoch object containing the canonical policy/digest, a cancel cause,
  operation registry, wait group, and `transitioning` gate. Persistence and
  in-memory publication remain serialized, while unrelated assignment/state
  work need not share one unbounded lock.
- [ ] `Service.Transition` validates/canonicalizes the request and, under the
  transition mutex, closes the current epoch's admission gate before comparing
  and persisting the expected-epoch CAS. A failed CAS reopens the unchanged
  epoch without publication. A successful CAS publishes and cancels the prior
  epoch, applies the same epoch/capacity/policies to the broker (invalidating
  leases), joins all older external operations and reconciliation critical
  sections, durably marks pre-running assignments revoked, invokes lifecycle
  revocation, proves zero unassigned released listeners when the requested
  transition requires quiescence, and only then opens the new epoch.
- [ ] Quiescence is closed, not caller-defined. `disabled`, `fatal`,
  `drain wait`, and `drain cancel` require no old-epoch operation/critical
  section and zero unassigned `LISTENER_RELEASED` before the transition or
  command succeeds. `canary-only` and `enabled` transitions still join,
  mark/revoke every pre-running old-epoch assignment, and preserve
  `JOB_RUNNING`, but do not wait for running jobs to finish. A reduction made
  only through legacy `SetPressure` is retire-on-release and does not claim
  full listener quiescence; if pressure enters `disabled` or `fatal`, it must
  use the acquisition transition and its full proof.
- [ ] A crash after the SQLite CAS is recovered by startup's existing
  disabled-zero normalization before broker restore. In-process failure after
  CAS persists a newer `fatal`/zero epoch, safe-stops the broker, emits one
  closed reason, marks service not-ready, and calls
  `TerminateAfterPersist`. If fatal persistence itself fails, do not claim the
  after-persist terminator contract.
- [ ] Each operation receives an injected explicit deadline and a fresh opaque
  operation ID. For nonzero `poll`, `acquire`, or `jit`: register in the
  current epoch, acquire the host guard, derive the exact operation proof from
  one whole current cached signed lease without a remote call or remote state,
  re-read policy/digest/mode/scale-set eligibility/effective capacity/epoch
  and that immutable lease entry, invoke the
  external call, finish any operation-specific durable result, close permit
  then host guard, and unregister. On a registration, guard, permit, or
  post-permit revalidation failure, do not invoke the external call; close
  every acquired resource in reverse order, unregister, and return failure.
  A close failure remains an operation failure even when no external effect
  occurred. Zero-capacity observer polls use no authority and cannot
  acquire/JIT.
- [ ] `Poll`, `Acquire`, and JIT execute in tracked goroutines so a caller that
  ignores context cancellation is observable. If it remains live past the
  explicit join/forced-termination margin, persist fatal/zero and invoke the
  terminator; the API returns failure in tests and never reports quiescence.
  Tests release the injected blocked goroutine after observing termination so
  the test process itself has no leak.
- [ ] A repository poll cycle owns one epoch reconciliation critical section
  from before lease acquisition through `Poll`, all receipt/event/offer and
  acquisition persistence, demand and broker projection, and `Ack`. The
  subordinate external calls remain separately guarded and tracked, but the
  outer critical section prevents a successful transition from overtaking
  message handling whose external effects or acknowledgement still belong to
  the old epoch. It releases that section only after either full success
  through Ack or terminal durable finish for the message attempt, including
  every acquisition-journal write and `not_attempted`, `completed`, or
  `ambiguous` outcome. Once its epoch is cancelled, the cycle retains the
  section only for that bounded finish; it cannot Ack, call `SetDemand`, or
  start another external `Poll`/`Acquire`. A per-repository/message exclusion
  prevents redelivery from entering while the prior attempt owns the section.
  Transition joins that release before revocation or opening the new epoch.
- [ ] RED/GREEN races cover the full mode sequence, concurrent CAS, pressure,
  watchdog/probe/suspend/observer transitions, stale leases, a crash after
  epoch persistence, permit/guard acquisition and close failures, and
  cancellation-ignoring calls. They prove an explicit Acquire result is
  durable before an injected close failure, a cancelled poll retains its
  outer critical section through durable finish, and exact redelivery cannot
  enter that message concurrently. Every successful transition proves zero
  old operations and critical sections.

### Task 5: Poll, acquire, persist, Ack, and admit in the required order

**Files:**

- Modify `internal/controller/service.go` and `service_test.go`.
- Modify controller/state adapter tests for the new acquisition records.

- [ ] For each configured repository session, obtain the repository-scoped
  broker lease before `Poll`. Validate that its epoch equals the current
  acquisition epoch, its alias is exact, it has not expired, and its
  `PollCapacity` is within current mode (`0`, exact canary ceiling `1`, or the
  enabled limit). Validate `0 <= Reserved <= PollCapacity`, but do not compare
  residual owned capacity to the new ceiling: preserved active work may
  temporarily exceed a reduced effective capacity.
- [ ] A zero-capacity observer still polls with `maxCapacity=0` so terminal
  events can reconcile, but it cannot call `Acquire` or JIT even when the
  returned batch contains locally eligible offers. It may persist offers,
  assigned-job demand, and Ack the exact message, leaving those offers
  non-acquired. This remains true when residual `JOB_RUNNING` assignments
  exceed a disabled or reduced policy ceiling. A nonzero poll uses one guarded
  `poll` operation and passes `PollCapacity` unchanged.
- [ ] Persist receipt, assigned/started/completed observations, and every offer
  before any acquisition or Ack. Local eligibility and replay checks remain
  idempotent. No offer can consume more than its repository lease commitment.
- [ ] Build the acquisition request only from locally eligible, preflighted
  offers whose durable state is `offered`, in canonical key order, capped at
  that lease's exact positive `Reserved` count. `PollCapacity > 0` alone never
  authorizes `Acquire`: a reduced-capacity poll may advertise preserved
  ownership while `Reserved == 0`. Offers beyond the reservation remain
  non-acquired. Persist intent, perform exactly one guarded `Acquire`, validate
  the unique returned subset, and persist acquired versus rejected outcomes.
  Queue only `acquired` assignments in the broker. An empty returned subset is
  valid and completes every requested assignment as rejected. Rejected
  requests create no reservation, lifecycle call, or runner.
- [ ] Reserve a separate, cancellation-independent durable-finish deadline
  before starting `Acquire`. Cancellation or failure before the external call
  begins invokes `AbortAcquisitionBeforeCall`; that exact intent is then safe
  to reopen from a redelivery. Once the call begins, every explicit result is
  validated and passed to `CompleteAcquisition` under that finish deadline
  even if the epoch context is cancelled. Only after this durable result step
  does the service close the permit, close the host guard, and unregister. A
  post-completion close failure cannot rewrite `completed` as `ambiguous`; it
  separately fails the cycle, suppresses Ack, and takes fatal/zero for
  uncertain authority teardown. A call error, invalid result, or failure to
  durably store the result leaves `begun`/`ambiguous`, suppresses Ack and
  retry, and triggers fatal/zero because upstream may own any subset. Startup
  treats every surviving `begun` row as ambiguous; it never infers rejection
  from cancellation or process death.
- [ ] Set repository demand from `Batch.Statistics.TotalAssignedJobs`, never
  `len(Offers)`, returned acquisition count, or message length. The field must
  be present, exactly representable as a nonnegative integer, and within the
  adapter's checked integer bound; missing, negative, fractional, or overflow
  encodings fail before Ack. There is deliberately no equality check against
  offer, message, or acquired counts. `SetDemand` occurs only after durable
  acquisition completion, only for the still-current epoch, and is skipped
  after cancellation.
- [ ] Ack only after batch events, offers, acquisition result, demand, and
  broker projections are durable. Preserve the current exact-redelivery
  protocol. A completed acquisition replay reuses its durable result and does
  not call `Acquire` twice; an ambiguous acquisition cannot Ack.
- [ ] `AdmitOnce` accepts only broker decisions whose durable assignment is
  `acquired`, persists `CAPACITY_RESERVED`, and leaves runner creation to
  reconciliation. Duplicate batches and decisions are harmless; repository,
  request, slot, or epoch mismatch is fatal/zero.

### Task 6: Guard JIT and revoke unassigned listeners

**Files:**

- Modify `internal/lifecycle/service.go` and tests.
- Modify `internal/controller/reconciler.go`, `service.go`, and tests.

- [ ] Inject a `JITAuthorizer` into lifecycle. `Release` passes the exact
  assignment key, repository alias, scale-set binding, session, opaque runner
  name, and JIT request to it rather than calling `Session.GenerateJIT`
  directly. The controller implementation performs one guarded `jit`
  operation and revalidates the exact active admission reference immediately
  before the call. Revalidation requires: acquisition outcome `acquired`;
  lifecycle state `CAPACITY_RESERVED`; no pre-running revocation mark; exact
  repository alias, scale-set binding, opaque runner name, assignment,
  admission, slot, and epoch identifiers; current policy epoch/digest/mode and
  eligibility; live reservation; and the fresh host guard plus exact Worker
  permit for `jit`. Any mismatch closes acquired authority without calling
  `GenerateJIT` and follows Task 7 cleanup-only resolution. Cleanup-only
  GitHub reads/removals remain possible without minting acquisition authority.
- [ ] Preserve Task 7's deterministic-name, stale-registration cleanup,
  secret destruction, and ambiguous-release rules. A JIT authority/close
  failure after upstream may have acted marks the assignment ambiguous and is
  reconciled by name; it never repeats JIT blindly or exposes the secret.
- [ ] Add lifecycle revocation over the durable recoverable set. Under the
  existing same-key lock, destroy and positively resolve every marked
  pre-running assignment, including a live unbound released listener. Preserve
  `JOB_RUNNING` under ordinary acquisition revocation. A marked `RECEIVED`
  assignment has no slot, listener, or managed runtime to reconstruct:
  validate its exact revocation epoch and use the checked pre-release terminal
  shortcut regardless of whether its acquisition outcome is offered,
  requested, acquired, or rejected. Any later pre-running lifecycle state
  still requires an `acquired` outcome and full cleanup. Explicit drain-cancel
  may terminate running work through a separately named reason/path.
- [ ] After lifecycle revocation has made every marked row terminal and before
  the new acquisition epoch opens, the controller retires each corresponding
  broker reference in stable key order. Active references are released before
  retirement; queued/reserved references are retired directly. It positively
  proves no live broker reference remains and clears the durable admission
  projection only after retirement succeeds. Any retirement, proof, or clear
  failure keeps the gate closed and takes the existing fatal-after-CAS path.
  This ordering makes schema-v3's deliberate legacy `queued -> offered`
  migration safe without falsely claiming that an old queued projection proves
  a completed upstream `Acquire`.
- [ ] A Started observation for a durably revoked pre-running assignment
  cannot bind or run it: perform exact upstream/runtime cleanup, prove absence,
  resolve `DESTROYED`, and treat exact replay as success so the enclosing
  message may be acknowledged.
- [ ] RED/GREEN JIT tests independently vary every revalidation predicate,
  inject cancellation and close failure before/after the call boundary, and
  prove no mismatched or revoked reference reaches `GenerateJIT`; cleanup-only
  resolution remains available without host or Worker acquisition authority.
- [ ] `Service.ReconcileOnce` invokes the Task 7 reconciler, then terminal
  finalization for newly destroyed assignments in stable order. It publishes
  no health until all reconciliation and finalization work succeeds.

### Task 7: Publish a closed health document and closed observability events

**Files:**

- Replace `internal/health/snapshot.go` with the Task 8 heartbeat contract.
- Create `internal/health/publisher.go` and tests.
- Modify `internal/observability/events.go` and tests.
- Modify controller health construction/tests.

- [ ] Split bounded-history diagnostics from the Worker heartbeat.
  `health.Snapshot` contains only: fleet alias; acquisition mode; policy epoch;
  canonical policy digest; repository-policy revision; closed capacity
  summary; assigned/running count; oldest live-assignment age; unassigned
  released-listener count; optional last terminal time; host-profile ID;
  degraded flag; and build ID. It has no eligible scale-set list or workload
  identity.
- [ ] Keep history rows/bytes/ledger/WAL/maintenance values in a separate
  closed `health.HistorySnapshot` used by local status and pressure events.
  `EvaluateHistoryPressure` may lower policy and emit its closed event but may
  not publish a Worker heartbeat.
- [ ] Validate bounded ASCII/UTF-8 identifiers and exact build/digest formats,
  closed enums, nonnegative ages, consistent capacity arithmetic, and terminal
  timestamps not in the future. Publisher validates before delegating to its
  sink.
- [ ] Construct and publish the heartbeat only after a fully successful
  `ReconcileOnce`. A failed state read, lifecycle action, finalizer, summary,
  validation, or publish returns error and emits no success receipt/heartbeat.
- [ ] Reflection/JSON tests assert the exact allowlisted field/key set and scan
  encoded events for repository/job/request/JIT/token/secret/path/route/
  command-output keys and values. Observability reasons remain closed enums;
  raw errors never become event fields.

### Task 8: Add bounded run loops and the fail-closed CLI

**Files:**

- Create `internal/controller/runtime.go` and tests.
- Modify `cmd/portable-ghar-controller/main.go` and `main_test.go`.

- [ ] `Service.Run` performs one ordered cold-start recovery before any work
  loop: open/migrate the store; promote every surviving `begun` acquisition to
  `ambiguous`; CAS the persisted policy to a newer canonical `disabled`/zero
  epoch; initialize the closed epoch barrier and broker at that exact epoch,
  zero capacity, and zero demand; construct repository sessions without
  starting polls; `MarkPreRunningRevoked(newEpoch)`; lifecycle-revoke/destroy
  every marked pre-running assignment and unassigned released listener; and
  prove the disabled quiescence conditions. Only then may it open the epoch
  gate, run one bounded observer poll loop per configured session, and use one
  central admission/reconciliation loop. This same path recovers a crash after
  a live policy CAS; it never resumes a partially published in-memory
  transition. All cadences, call deadlines, join deadline, and shutdown
  deadline are required injected values; there are no production defaults.
- [ ] Session shutdown cancels/join loops, closes each session with a bounded
  context, transitions through the same disabled barrier, revokes unassigned
  listeners, and returns only after no old operation remains. Any unjoinable
  call takes the fatal path.
- [ ] RED/GREEN startup tests seed enabled/canary policy, surviving `begun`,
  `not_attempted`, every acquisition outcome at `RECEIVED`, migrated queued
  offered rows, acquired `CAPACITY_RESERVED`, released-listener, and
  `JOB_RUNNING` rows;
  crash after each recovery boundary; and prove a newer disabled epoch, begun
  promotion, exact revocation/cleanup, preservation of running work, zero
  demand/listeners, and no poll loop before recovery completes.
- [ ] Implement exact command parsing for:
  `run`, `probe`, `reconcile --once`,
  `drain --policy=wait|cancel`,
  `acquisition --set=... --expected=... [--eligible-scale-set NAME] --json`,
  and `status --json`. Mutating commands require injected root identity.
  Canary requires exactly one eligible scale set; other modes reject the
  flag. Unknown, duplicate, missing, or trailing flags fail.
- [ ] The CLI dispatches through an injected live-controller/admin interface.
  `run` is the sole writer process: it acquires the injected exclusive
  controller-process ownership guard, opens the store read-write, and owns
  `Service.Run`; it never attaches to a second writer. `probe`, `reconcile`,
  `drain`, and `acquisition` require the live admin port and never fall back to
  opening SQLite read-write in their command process. An unavailable live port
  returns a typed generic nonzero failure with no mutation. Task 8's
  production `OpenController` and admin transports remain explicitly
  unavailable, while tests inject them. This is a source-convergence boundary,
  not a deployed-runtime claim: Task 10 must replace `OpenController` only
  after its runtime manifest supplies every required lifecycle, repository,
  deadline, admission, host, and health input. That factory must still inject
  unavailable host and lease-backed acquisition providers until their
  separately planned implementations land, so nonzero work remains impossible.
  `status --json`
  is the sole local non-owner path: it opens the store read-only, accepts only
  the exact current schema, and emits the closed summary without eligible
  names, repository/assignment identities, paths, or secrets. Dual-process
  mutation is prevented by writer ownership plus refusal of local admin write
  paths, not by relying on SQLite locks. Task 9 supplies only host authority;
  the heartbeat-lease-backed provider remains a later failover integration.
- [ ] CLI tests hold the writer ownership guard with a fake live process and
  prove every second `run` or local-write attempt fails without mutation;
  admin commands cannot fall back when the live port is absent; injected live
  admin calls use the same barrier; and `status --json` is read-only,
  current-schema-only, and field-allowlisted.
- [ ] `acquisition` reads the current policy, checks exact expected mode, and
  calls the same CAS barrier. Enabled uses the injected configured policy
  template; disabled zeroes capacity/eligibility; canary uses the one supplied
  scale set at capacity one. The JSON response contains only mode, epoch,
  digest, and capacity—not the raw eligible set.
- [ ] `drain wait` disables/revokes and waits for running jobs plus unassigned
  listeners to reach zero under a deadline. `drain cancel` uses the explicit
  cancellation path, then proves the same zero. Neither command claims hosted
  routing or fleet handoff.

## Verification Sequence

Run focused RED/GREEN slices while implementing:

```bash
GOCACHE=/private/tmp/portable-ghar-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test -race ./internal/controller ./internal/admission ./internal/state \
  ./internal/lifecycle ./internal/observability ./internal/health \
  ./cmd/portable-ghar-controller \
  -run 'TestAcquisition|TestPolicy|TestBarrier|TestDemand|TestPoll|TestAdmit|TestJIT|TestRevok|TestHealth|TestControllerCLI' \
  -count=20
```

Then run:

```bash
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go test -race ./internal/controller ./internal/observability \
  ./internal/health ./cmd/portable-ghar-controller -count=20
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go test -race ./internal/admission ./internal/state ./internal/lifecycle -count=20
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 go test -race ./...
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 go vet ./...
HOME=/private/tmp/portable-ghar-static-home GOPATH="$(go env GOPATH)" \
  GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool staticcheck ./...
HOME=/private/tmp/portable-ghar-static-home GOPATH="$(go env GOPATH)" \
  GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool govulncheck ./...
python3 scripts/sanitize_public.py --tracked
python3 scripts/check_repository_metadata.py
python3 tests/repository/test_workflow_policy.py
```

Use `gofmt -l` as a non-mutating final formatting check and
`git diff --check`. Linux/Docker/QTS conformance remains a later typed target
gate; this task makes no host change and does not convert source tests into
target proof.

## Review and Commit Gate

Before code generation:

1. Seal this exact plan by byte count and SHA-256.
2. Send the exact artifact to a direct distinct-family architecture reviewer
   with correctness and adversarial lenses. The broker is not used.
3. Integrate every material finding. If a load-bearing decision changes,
   reseal and re-run the review. Stop after two substantive cycles and surface
   any unresolved disagreement rather than implementing through it.

After GREEN:

1. Seal the exact base-to-head artifact and obtain a substantive
   distinct-family exact-diff review.
2. Address every material finding and re-review any changed artifact.
3. Re-run all focused/full gates and public leak scans.
4. Stage only the reviewed Task 8 paths.
5. Create one signed commit:

```text
feat: wire controller acquisition and health cycles
```

No push, PR, merge, release, deployment, Docker execution, or host mutation is
authorized by this plan.
