# Task 7 Implementation Plan: One-Job JIT Lifecycle and Reconciliation

> Status: source design only. This plan does not authorize or perform any
> Docker, QTS, RhoNAS, selector, routing, or host-configuration mutation.
> Numeric runner sizing remains a separate operator-signoff gate.

## Objective

Implement the missing lifecycle layer between durable admission, the pinned
GitHub scale-set session, and Task 6's network-jail transaction. Each admitted
offer gets at most one deterministic opaque runner identity, one one-job JIT
registration at a time, one broker release, and one listener release. A crash
at any checkpoint must reconcile forward or compensate without creating a
duplicate runner, accepting a second job, deleting retained network-ledger
state, or persisting secret material.

The implementation must preserve these canonical public package boundaries:

```go
package lifecycle

type Service interface {
	Prepare(context.Context, controller.Assignment) (controller.RunnerSlot, error)
	Release(context.Context, controller.AssignmentKey) error
	Observe(context.Context, githubscale.Event) error
	Destroy(context.Context, controller.AssignmentKey, controller.ReasonCode) error
}

type Reconciler interface {
	Once(context.Context) (controller.CycleReceipt, error)
}
```

`githubscale.JITConfig.Encoded` remains `*redaction.Secret`, the accepted
copy-safe amendment to the original value-shaped pseudocode.

## Existing Boundaries to Reuse

- `controller.State`, `AssignmentKey`, `RunnerSlot`, and
  `controller.Transition` already define and enforce the 15-state ordering.
- `controller.Service.AdmitOnce` and `state.SQLiteStore.ReserveActive`
  atomically persist `CAPACITY_RESERVED`, the stable capacity slot, and the
  deterministic opaque slot name before Task 7 may generate a JIT.
- `githubscale.Session` already bounds and serializes `GenerateJIT`,
  `GetRunnerByName`, `GetRunner`, and `RemoveRunner`; it validates scale-set
  identity and returns JIT bytes only as `*redaction.Secret`.
- `networkjail.Orchestrator.Configure` currently owns all effects from adapter
  creation through listener release. Task 7 will split that transaction at the
  existing durable `RELEASE_ARMED` checkpoint without changing effect order or
  weakening Task 6's proofs.
- `state.Store` already journals each Task 6 external effect before execution
  and records opaque result identities. Its `reconcile_cycles` table exists but
  has no API yet.
- `hostruntime.DockerCLI` already emits managed component/build/generation
  labels, validates exact container configuration, and removes resources in a
  bounded way. It needs a slot-scoped recovery surface because its ordinary
  opaque handles are intentionally process-local and cannot survive restart.

## Threat Model and Failure Classes

The design must fail closed against:

1. **JIT loss after success:** the process dies after GitHub creates the runner
   registration but before the secret reaches the held gate.
2. **Ambiguous JIT response:** the request times out after GitHub may have
   created the deterministic runner.
3. **Container create ambiguity:** Docker creates a component but the caller
   dies before the opaque ID is checkpointed.
4. **Release ambiguity:** the gate may have exec'd the listener even though the
   caller saw an error or failed to persist the completion checkpoint.
5. **Handle loss:** a restarted process cannot trust or synthesize a prior
   process's opaque `hostruntime` handles.
6. **Label/name spoofing:** an unrelated container attempts to look like an
   orphan for another slot.
7. **Reassignment:** one workflow job is reissued under another request ID, or
   two prepared runners bind in an order different from offer order.
8. **Out-of-order events:** completion arrives without a locally observed
   start, or a start proves a listener release whose checkpoint was ambiguous.
9. **Cleanup asymmetry:** GitHub sees a runner while Docker does not, or vice
   versa.
10. **Duplicate terminal work:** redelivery or restart repeats listener
    release, capacity release, upstream runner removal, or component cleanup.
11. **Secret crossing:** JIT bytes enter SQLite, labels, names, argv, logs,
    diagnostics, result identities, or cycle receipts.
12. **Unbounded reconciliation history:** repeated cycles grow
    `reconcile_cycles` indefinitely.
13. **Live-runner destruction:** an obsolete offer or ambiguous read-back
    destroys a runner already bound to a current live request.
14. **Ledger destruction:** per-job relay and authority directories are
    removed, but the separately retained SQLite network ledger is accidentally
    deleted before its retention floor `T`.

## Architecture

### 1. Add the missing lifecycle domain values

Add a controller-owned lifecycle model without importing host/runtime
packages:

- `controller.Assignment{Key, Offer, Slot}`. The caller supplies only the
  already-durable offer/slot projection. Construction rejects any mismatch
  between `Key`, `Offer.RunnerRequestID`, `Slot.OpaqueName`, and
  `Slot.CapacitySlotID`. `AssignmentKey.Attempt == 0` is the canonical initial
  durable offer emitted by the existing admission path and is valid; positive
  attempts remain distinct retry identities.
- `controller.CycleReceipt{CycleID, CompletedAt, AssignmentCount, OldestAge}`.
- closed lifecycle reason codes for cancellation, preparation failure,
  release ambiguity, reassignment retirement, job completion, and
  reconciliation.

Add a closed `githubscale.Event` discriminated union and constructors for the
already-translated Assigned, Started, and Completed values. Do not change the
wire adapter or make arbitrary field combinations representable.

### 2. Split the Task 6 transaction at `RELEASE_ARMED`

Refactor `networkjail.Orchestrator` into:

- `Prepare(ctx, PreparedSetupRequest) (HeldJail, error)`, executing the exact
  existing order from adapter create through the durable
  `StateReleaseArmed` checkpoint. `PreparedSetupRequest` contains no JIT.
- `Release(ctx, HeldJail, *redaction.Secret) (LiveJail, error)`, performing
  exactly the journaled one-use listener release and durable
  `StateListenerReleased` checkpoint.
- `DestroyHeld` and `DestroyLive` consume only orchestrator-issued opaque
  values and run bounded cleanup.
- Existing `Configure(ctx, SetupRequest)` remains as a compatibility wrapper
  that calls `Prepare` then `Release`; existing Task 6 callers/tests remain
  valid while new tests prove identical ordering.

The split must preserve all opaque adapter, broker, authority, runner,
namespace, audit, and release-authorization proofs inside `HeldJail`; no caller
can synthesize or inspect them.

Any error before beginning the listener-release effect compensates as before.
The durable `StageListenerRelease` effect row is the crash-proof boundary:

- absence proves the listener-release call was never authorized or invoked;
- pending proves intent was durable but the external outcome is unknown;
- completed proves the external call returned success even if the following
  state checkpoint did not persist.

Once that effect is begun, **every** call error or missing
completion/advance checkpoint is ambiguous: leave the effect pending when the
call does not return a trustworthy success, best-effort record the closed
ambiguity reason only as supplemental diagnostics, preserve resources, destroy
the controller-owned JIT buffer, and return `ErrListenerAmbiguous`. A hard
crash need not write the reason: recovery classifies any `RELEASE_ARMED` row
with a pending or completed listener-release effect as ambiguous. Never perform
a blind cleanup after the release effect may have exec'd the listener.

### 3. Generate JIT at the narrowest lifetime

The lifecycle service receives:

- a `SessionProvider` keyed by repository alias;
- a `SetupBuilder` that deterministically constructs the Task 6 prepared
  request from the durable assignment and deployment configuration;
- the split network-jail orchestrator;
- durable state and a slot-scoped runtime recovery interface;
- an injected clock and cycle-ID source for deterministic tests.

`Prepare`:

1. Re-read/validate the durable assignment at `CAPACITY_RESERVED`. The full
   secret-free offer projection and full reserved slot must match semantically
   (with nil/empty label slices normalized); matching only request and job IDs
   is insufficient.
2. Require exact deterministic component names derived only from
   `Slot.OpaqueName`, and an exact slot label on every long/short-lived
   component. The cleanup-only recovery paths must equal the prepared broker
   relay and authority paths.
3. Call network-jail `Prepare`; cache the returned opaque `HeldJail` under the
   assignment key; return the persisted slot identities. It performs no JIT or
   upstream runner call.

`Release`:

1. Require the exact cached held jail and re-read `RELEASE_ARMED`.
2. Query `GetRunnerByName(Slot.OpaqueName)` before generating JIT. If a stale
   pre-release registration exists, remove it and positively read back
   absence. A read error, identity mismatch, or failed absence proof stops.
3. Call `GenerateJIT` once with the exact opaque name and fixed work folder.
   Require a positive runner ID and exact returned name.
4. Pass the `*redaction.Secret` directly into network-jail `Release`. Both
   lifecycle and orchestrator guarantee destruction on every terminal path.
5. On a definitely pre-release failure, remove the returned upstream
   registration immediately and read back absence. If cleanup is uncertain,
   mark the assignment ambiguous and leave it to reconciliation.
6. On listener ambiguity, do not remove or repeat anything. Reconciliation
   reads GitHub and Docker state.

All `Prepare`, `Release`, `Observe`, `Destroy`, and per-assignment reconciliation
sequences acquire the same lifecycle-owned keyed exclusion before their first
read and hold it through their final read-back/checkpoint. Per-call
`githubscale.Session` serialization is not treated as transaction isolation.
The keyed exclusion prevents a reconciler from racing the multi-call
get/remove/absence/generate sequence or cleanup against an in-process
operation. Batch observation acquires affected keys in deterministic sorted
order.

The durable `CAPACITY_RESERVED` row is the pre-JIT intent. The deterministic
name plus mandatory read-before-create/read-after-cleanup protocol resolves a
lost JIT without persisting a secret or relying on absence inference. Task 6's
per-effect journal remains the intent/effect/read-back record for every Docker,
broker, socket, and listener effect.

### 4. Add slot-scoped restart recovery without weakening handles

Add `SlotIdentity` to adapter, broker, runner, helper, and verifier specs and
emit `io.portable-ghar.slot=<opaque-slot-name>` in addition to the existing
managed/kind/build/generation labels. All inspect/audit validators require the
exact five-label set. No job-controlled value can supply this label.

Extend the host runtime with an opaque, cleanup-only recovery API:

```go
type RecoverySpec struct {
	SlotIdentity string
	BuildID string
	FleetGeneration uint64
	AdapterName, BrokerName, RunnerName string
	ExpectedAdapterID, ExpectedBrokerID, ExpectedRunnerID string
	RelayParent, AuthorityParent string
}

type ManagedSnapshot struct { /* unexported issuer and records */ }

InspectManaged(context.Context, RecoverySpec) (ManagedSnapshot, error)
RemoveManaged(context.Context, ManagedSnapshot) error
```

`InspectManaged` lists by the exact slot label, then inspects every result. It
requires:

- only the closed component kinds;
- exact deterministic names, build ID, fleet generation, and slot label;
- expected persisted IDs when present;
- no duplicate kind/name, unknown helper, unmanaged object, truncated output,
  or extra label;
- exact relay/authority directory descendants and non-symlink ownership.

It may recover an ID that was created after `BeginEffect` but before
`CompleteEffect` only when every other immutable identity matches. It issues a
new process-local opaque snapshot but never reconstructs a normal operational
handle or release token. `RemoveManaged` can only stop/remove the inspected
resources in runner/verifier/helper/broker/adapter order and remove the two
per-job socket directories. It never touches the SQLite network ledger.
Every recovered container removal is followed by a successful, empty,
non-truncated exact-ID inventory query; a failed `inspect` or inventory command
never counts as absence.

The in-process path uses `DestroyHeld`/`DestroyLive` so the live authority
endpoint is stopped. The restart path uses the cleanup-only snapshot; the old
process and its authority endpoint are already gone.

### 5. Persist observations and bind reassignment correctly

Change `state.Store.BindRunner` to accept the observed
`boundRequestID` separately from the assignment key. It must be an
idempotent compare-and-set:

- empty binding may become the exact observed tuple;
- an exact replay is a no-op;
- any changed runner ID, request ID, or container ID is
  `ErrIdentityConflict`;
- live upstream runner IDs remain unique.

`lifecycle.Service.Observe` matches Started/Completed events by exact opaque
runner name and same workflow-job identity, never by offer order:

- A start at `RELEASE_ARMED` is positive evidence that listener release
  occurred; use one durable observation operation that advances the release
  checkpoint, binds the exact observed request/runner/container tuple, clears
  any supplemental ambiguity reason, and advances to `JOB_RUNNING`.
- A start at `LISTENER_RELEASED` binds and advances normally.
- A completion may idempotently establish a missing start from the same exact
  runner tuple, then advances to `JOB_FINISHED`. Both start and completion
  paths atomically clear a stale release-ambiguity marker when their exact
  upstream evidence resolves it.
- Exact redelivery is a no-op. Conflicting binding or impossible earlier state
  fails closed.
- An Assigned event for a newer request marks only unbound, pre-running
  same-job offers obsolete. It never marks a slot with a nonzero live binding
  or a `JOB_RUNNING` state. Reconciliation performs the external cleanup.

Implement `RecordBatch(ctx, controller.MessageEnvelope)` on the lifecycle
service so the existing controller polling service durably applies all events
before Ack. Partial application is safe because each observation is
idempotent and the message remains unacknowledged on error.

### 6. Add an explicit post-release resolution gate

Keep `Store.Advance`'s no-blind-post-release-destroy invariant unchanged.
Add a separate, narrowly typed durable method:

```go
ResolvePostRelease(
	context.Context,
	controller.AssignmentKey,
	controller.PostReleaseOutcome,
	[sha256.Size]byte,
	time.Time,
) error
```

It is legal only for a post-release-ambiguous assignment: `RELEASE_ARMED` with
a begun listener-release effect, `LISTENER_RELEASED`, or `JOB_RUNNING`. A
separately written ambiguity reason is supplemental and is not required. The
method atomically records a domain-separated reconciliation evidence digest,
clears any ambiguity reason, and sets exactly one closed outcome
(`LISTENER_RELEASED`, `JOB_RUNNING`, `JOB_FINISHED`, or `DESTROYED`).
If later two-sided evidence proves a legal forward outcome for the same
assignment, the same transaction supersedes the stored resolution digest and
advances the state. Exact-state replay must remain digest-identical; backward,
same-state/different-evidence, malformed-prior-digest, and terminal rewrites
fail closed.

There is one consistent terminal-transition rule:

- ordinary `Advance(DESTROYED)` is legal for a pre-release state only when the
  listener-release effect is absent, and for the proven normal adjacent
  `JOB_FINISHED -> DESTROYED` transition;
- `RELEASE_ARMED` with any listener-release effect, `LISTENER_RELEASED`, and
  `JOB_RUNNING` may reach `DESTROYED` only through `ResolvePostRelease` after
  positive two-sided read-back and cleanup evidence.

The existing general `Store.Advance` signature stays unchanged; lifecycle
checks the exact effect record under its keyed exclusion before invoking the
otherwise legal pre-release shortcut. The state adapter also provides a
single-purpose checked helper for this transition so callers cannot omit the
effect-absence predicate.

The evidence digest covers only closed observations: exact slot name,
persisted IDs, GitHub found/runner-ID/name equality, Docker component
presence/running state, and cleanup absence read-backs. It contains no paths,
JIT, token, job display data, or command output.
For one-sided residue, the digest binds the actual pre-cleanup
upstream/runtime observation as well as the positive post-cleanup absence bit.

### 7. Implement reconciliation and bounded cycle receipts

Add `controller.Reconciler.Once` over a controller-owned lifecycle port:

1. Generate and durably begin one opaque cycle.
2. Load the bounded recoverable assignment set and process it in stable key
   order.
3. Compute `OldestAge` from the oldest nonfuture `UpdatedAt`.
4. Complete the durable cycle and return a receipt only when every assignment
   reconciles successfully. A failed cycle cannot publish a success receipt.

Assignment reconciliation:

- `RECEIVED`: leave to the polling/admission restoration layer.
- `CAPACITY_RESERVED` with no Task 6 effect: prepare and release normally;
  stale deterministic JIT registration is removed before replacement.
- Any pre-release record with a pending/completed setup effect after restart,
  or an obsolete/cancel reason, may take the cleanup shortcut only after the
  exact `StageListenerRelease` lookup proves that effect absent. Then inspect
  exact resources and use the checked pre-release terminal transition. States
  before `RELEASE_ARMED` structurally precede JIT generation, so local reclaim
  does not depend on GitHub availability. At `RELEASE_ARMED`, remove any
  deterministic upstream registration and prove absence before the terminal
  transition.
- Every `RELEASE_ARMED` row whose listener-release effect is pending or
  completed takes the post-release read-both-sides branch regardless of
  whether an ambiguity reason was written. If the exact runner and container
  are live, resolve to `LISTENER_RELEASED` (or `JOB_RUNNING` only with exact
  start evidence); if both are absent, resolve to `DESTROYED`; for one-sided
  residue, clean the exact residue, prove both absent, then resolve destroyed.
- A restart-visible `RELEASE_ARMED` row with no listener-release effect may be
  compensated and destroyed; it is never blindly retried because the opaque
  in-memory release authorization was lost.
- `LISTENER_RELEASED`: leave an exact live unbound listener in place; clean and
  resolve only on positive absence/asymmetry evidence.
- `JOB_RUNNING`: leave the exact live bound runner in place. Missing or
  conflicting state remains ambiguous and fails the cycle; never fabricate a
  completion.
- `JOB_FINISHED`: remove the runner/container, registration, adapter, broker,
  relay and authority directories; prove absence; advance to `DESTROYED`.

Add store methods to begin/complete/abort reconcile cycles. Enforce a fixed
bounded representation: at most one incomplete cycle while running and one
latest completed/aborted cycle. Beginning the next cycle closes or replaces a
crash-left incomplete record with a closed reason and deletes older terminal
rows in the same transaction. Cycle IDs, counts, times, ages, and closed reason
codes are the only persisted fields.

### 8. Terminal cleanup ownership

`Destroy` is idempotent and state-aware:

- before listener release, first prove the listener-release effect absent,
  cleanup, then use the checked pre-release `Advance(DESTROYED)`;
- at `JOB_FINISHED`, cleanup then use the ordinary adjacent
  `Advance(DESTROYED)`;
- after release but before finish, only the explicit post-release resolution
  path may destroy;
- repeated calls after proven absence are no-ops.

Task 7 removes the per-job runtime graph and upstream runner registration.
The existing admission broker/controller terminal finalizer remains the sole
owner of active capacity release, broker-reference retirement, terminal
message binding, and eventual bounded compaction; Task 8 wires those two
owners in order. Task 7 must not duplicate admission-capacity release.

## TDD Sequence

### RED 1: split transaction and JIT lifetime

- Prove `Prepare` reaches `RELEASE_ARMED` with no JIT/session call.
- Prove `Release` consumes exactly one secret and one listener effect.
- Inject before/after every Task 6 effect and checkpoint.
- Prove any post-invocation listener-release error is ambiguous and performs no
  blind cleanup.
- Hard-crash after listener invocation but before completion/reason/state
  writes; prove the begun effect alone forces two-sided read-back and protects
  a live runner.
- Preserve all existing Task 6 ordering, secret-destruction, and cleanup tests.

### RED 2: deterministic JIT and cleanup

- JIT cannot run before `CAPACITY_RESERVED` and held-jail readiness.
- The exact opaque name is stable across restart and contains no offer/job
  text.
- Lost/ambiguous JIT is found by name, removed, absence-proven, then replaced.
- Container/pre-release failure removes upstream registration immediately.
- No store method, log field, error, label, result identity, or cycle row can
  accept JIT or `redaction.Secret`.

### RED 3: restart inventory

- Crash after Docker create but before effect completion for each component.
- Recover only exact label/name/build/generation/expected-ID combinations.
- Reject duplicate, unknown, conflicting, symlinked, or truncated evidence.
- Remove all per-job containers/directories while retaining the network
  ledger row through its existing `T`.
- Prove no duplicate create, broker release, or listener release after restart.

### RED 4: reassignment and event ordering

- Same workflow job under successive request IDs.
- Two runners bind in opposite order by observed runner name/request ID.
- Exact replay is harmless; conflicting rebinding fails.
- Obsolete unbound offer retires; already bound/live runner survives.
- Completion without a prior observed start establishes the same exact tuple
  and reaches `JOB_FINISHED` without skipping unproven release.
- A start/completion that resolves a prior listener ambiguity atomically clears
  the stale reason; later reconciliation does not abort the healthy job.

### RED 5: post-release reconciliation

- Both sides live -> released/running.
- An already `LISTENER_RELEASED` both-live pass records no new post-release
  resolution effect; if either side later disappears, the same assignment can
  still resolve monotonically to `DESTROYED`.
- A `RELEASE_ARMED` both-live recovery first resolves to
  `LISTENER_RELEASED`; a later both-absent pass atomically supersedes that
  evidence and resolves to `DESTROYED`, while exact-state conflicting evidence
  remains rejected.
- Both absent -> destroyed with a nonzero exact evidence digest.
- One-sided residue -> exact cleanup, absence proof, destroyed.
- Conflicting identity or unreadable side -> remains ambiguous and returns
  error.
- A `JOB_RUNNING` runner is never destroyed merely because an offer was
  superseded.

### RED 6: cycle durability and bounds

- Success receipt only after all assignments succeed.
- Future timestamps, duplicate cycle IDs, invalid counts/ages, and partial
  completion fail closed.
- Crash-left cycles recover deterministically.
- A long soak leaves no more than the fixed current/latest cycle rows.

### RED 7: same-key exclusion

- Block `Release` between upstream absence proof and JIT generation while
  starting `Reconciler.Once`; prove reconciliation cannot enter that key.
- Block cleanup while delivering Started/Completed; prove no conflicting
  state write or resource removal occurs.
- Race Prepare/Release/Observe/Destroy/Reconcile under `-race -count=50` and
  assert at most one JIT generation, broker release, listener release, and
  cleanup sequence per key.

## Verification

Use a dedicated cache because the normal module-stat cache is not writable in
the sandbox:

```bash
GOCACHE=/private/tmp/portable-ghar-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test -race ./internal/lifecycle ./internal/controller ./internal/state \
  ./internal/networkjail ./internal/hostruntime \
  -run 'TestLifecycle|TestReconcile|TestOrchestrator|TestSQLite|TestDocker' \
  -count=50
```

Then:

```bash
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 go test -race ./...
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 go vet ./...
HOME=/private/tmp/portable-ghar-static-home GOPATH="$(go env GOPATH)" \
  GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool staticcheck ./...
HOME=/private/tmp/portable-ghar-static-home GOPATH="$(go env GOPATH)" \
  GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool govulncheck ./...
python3 scripts/sanitize_public.py --check .
python3 tests/repository/test_repository_metadata.py
```

Also run the repo's shell, schema, docs, and workflow gates if any shared file
changes. Linux/Docker target conformance remains separately pending; no host
mutation is part of this task.

## Review and Commit Gate

Before implementation, send this exact plan to a distinct-family adversarial
reviewer and integrate every material lifecycle/ambiguity finding. If that
changes a load-bearing decision, re-run the plan review.

After GREEN:

1. Seal the exact base-to-head artifact and run a distinct-family exact-diff
   code review.
2. Address every material finding and confirm any changed artifact.
3. Re-run all gates and public leak scans.
4. Stage exact Task 7 paths only.
5. Create one signed commit:

```text
feat: reconcile one-job JIT runner lifecycle
```

No push, PR merge, release, Docker execution, or host change is authorized by
this plan.
