# Portable-GHAR Task 10 disabled-observer admin/readiness design review

> Historical Phase 2 review artifact. Its Worker-permit references name the
> local unavailable interface reviewed for the disabled observer. Phase 3 uses
> that local seam with one cached signed heartbeat lease and adds no remote
> per-operation permit or close path. Platform-design §9 and the failover plan
> are normative.

You are the distinct-family adversarial architecture reviewer. Review this
source-only plan for the Portable-GHAR Task 10 disabled controller observer.
Do not edit files, run commands, browse, invoke subagents, or propose host
changes. Read only the named repository files if needed.

Context and fixed constraints:

- Author/primary: OpenAI Codex.
- This is source implementation only. No QTS/RhoNAS, systemd, Docker, launchd,
  network, selector, deployment, numeric sizing, or host mutation is allowed.
- The approved Task 10 plan is
  `docs/superpowers/plans/2026-07-29-task10-implementation.md`.
- The observer must publish and prove disabled/empty/zero before serving, expose
  only a local closed admin/readiness surface, and possess no GitHub, Worker,
  routing, generic command, image, lifecycle-journal-advance, or fence-handoff
  authority.
- Nonzero acquisition remains unavailable. Incomplete local cleanup authority
  must fail closed; it must never be reported as successful reconciliation,
  drain, or readiness.
- QTS host identity and persisted lifecycle operation-binding work is an
  operator approval gate and is out of scope here.
- Prefer exact, bounded, canonical protocols and positive identity readback.
- Relevant files:
  `cmd/portable-ghar-controller/commands.go`,
  `cmd/portable-ghar-controller/disabled_observer.go`,
  `cmd/portable-ghar-controller/production_controller.go`,
  `internal/controller/runtime.go`,
  `internal/config/runtime.go`,
  `internal/hostruntime/private_overlay.go`, and
  `cmd/portable-ghar-runner-gate/socket.go`.

Proposed implementation:

1. Add a production-only Unix-domain IPC module inside
   `cmd/portable-ghar-controller`. It uses two independently identity-pinned,
   root-owned mode-0600 Unix stream sockets in an already-existing,
   direct/root-owned mode-0700 directory:
   `PrivateOverlay.Paths.AdminSocketPath` and `HealthSocketPath`. It rejects
   symlinked parents, existing paths, path aliasing, non-socket replacements,
   wrong UID/mode/link count, and removes only the exact device/inode socket it
   created. Before every accepted request and immediately before every success
   response, it revalidates the exact listener path identity. On Linux it also
   requires the accepted peer's kernel-reported UID to equal the overlay's
   expected EUID. A mismatch cannot reach a handler.

2. Each connection carries exactly one bounded request frame and one bounded
   response frame with fixed compile-time byte ceilings. The client writes
   canonical JSON bytes, calls `CloseWrite`, and reads to EOF. The server reads
   through `LimitReader`, requires EOF, rejects empty, oversized, noncanonical,
   unknown, or trailing input, and writes a canonical response. Both sides use
   mandatory short per-connection read/write idle deadlines, while method
   execution uses its separate caller/overlay deadline. Immediately after
   accept plus peer/path identity checks, the accept loop must acquire a shared
   fixed admission slot before reading any request byte or spawning a handler.
   Saturation closes/refuses the connection without waiting or invoking a
   method. Every admitted connection is tracked for shutdown cancel/join; no
   unadmitted connection allocates request-body storage. Slowloris,
   partial-write, and half-open connections expire. Shutdown cancels and joins
   all admitted handlers. A recovered handler panic marks the server fatal and
   cancels the process; it never returns success or leaves readiness set. No
   free-form errors, paths, identities, or secret material cross the socket.

3. The closed request union has schema version 1 and exact methods:
   `probe`, `reconcile_once`, `drain`, and `set_acquisition` on the admin
   socket; only `health` on the health socket. Method-inapplicable fields must
   be absent. The closed response union has schema version 1, exact status
   `ok|unavailable|conflict`, one closed reason code, and at most one
   method-specific payload. Reasons are exactly `none`, `not_ready`,
   `policy_drift`, `projection_incomplete`, `method_unavailable`,
   `deadline_exceeded`, `identity_mismatch`, and `internal_failure`.
   `PolicyStatus` is copied into a separate wire struct with explicit JSON
   fields. Reconciliation serializes a receipt only after complete local
   reconciliation authority is constructed. No Go error string is serialized.
   The client maps `ok` to a validated payload and nil error, `unavailable` to
   `controller.ErrRuntimeUnavailable`, and `conflict` to
   `controller.ErrAdminConflict`; a failure status can never become a nil Go
   error or zero-value success.

4. Define one sealed `completeLocalAuthority` dependency rather than a set of
   optional callbacks. It exposes only:
   - `ColdReconcile(context.Context) error`;
   - `ReconcileOnce(context.Context) (controller.CycleReceipt, error)`;
   - `DrainWait(context.Context) error`;
   - `RevokePreRunning(context.Context) error`; and
   - `Observe(context.Context) (localObservation, error)`.
   `localObservation` contains a mandatory nonzero monotonic sample sequence,
   observation time, and the complete workload counts for running jobs, pending
   acquisitions, released listeners, runners, adapters, brokers, helpers,
   verifiers, active dials, and per-job sockets. It validates only when every
   source was positively observed by the exclusive local authority.
   Missing, unsupported, stale, partial, or unreadable sources return an error,
   never an all-zero default. There is no production incomplete or no-op
   implementation; an incomplete composition cannot construct or serve the
   observer. Cancellation is part of this sealed production contract, not an
   advisory convention: every method must check `ctx.Done()` before and after
   each local I/O or mutation step; every wait/retry/subprocess must use a
   context-aware primitive; and `DrainWait` plus `ReconcileOnce` must return
   promptly after cancellation. No detached child, background goroutine, or
   unbounded blocking operation may outlive its method. A concrete authority
   that cannot prove these properties is incomplete and cannot be composed.

5. Construction also requires three other sealed dependencies:
   - a zero-demand admission broker whose capacity summary is bound to the
     current policy epoch and whose effective capacity is zero; and
   - one concrete unavailable-external graph whose Worker permit, hosted route,
     replay verification, Worker health, GitHub session, and poll methods all
     fail with a closed unavailable error and expose no generic network or
     mutation port; and
   - a read-only `fleetAuthority` whose fresh proof distinguishes required
     self-authority from workload quiescence. Portable mode requires exactly the
     expected generation plus the identity of this process's live self guard
     and rejects every foreign, orphan, duplicate, or stale guard. Legacy mode
     requires the exact current `NormalizeLegacyObserver` proof and no portable
     self guard. It never reduces fleet authority to an all-zero counter.
   There are no poll targets. Construction further requires an exact current
   fleet proof: `portable` at the overlay's expected generation, or `legacy`
   at that generation plus a successful exact `NormalizeLegacyObserver` proof.
   Fleet `none`, stale generations, absent guards, incomplete unavailable
   externals, and nonzero broker capacity all fail before either socket exists.
   Readiness, health, probe, disabled-to-disabled, drain success, reconciliation
   success, and shutdown all require a fresh mode-appropriate fleet-authority
   proof alongside the all-zero workload observation.

6. The disabled observer implements only safe local admin semantics:
   - Every method first requires the readiness bit under the observer's
     serialization barrier. Pre-ready requests return `not_ready` and perform
     no transition or cleanup.
   - `Probe`: snapshot, canonicalize, require exact match to the immutable
     disabled/empty/zero desired policy, derive the acquisition-policy digest,
     and bind the response to the sealed broker's capacity summary. Its epoch
     must equal the policy epoch and its effective capacity must equal zero; no
     literal or unbound zero is serialized.
   - `SetAcquisition`: reject canary/enabled, eligible scale-set input, expected
     modes other than disabled, and any drift. Exact disabled-to-disabled first
     obtains a fresh complete zero observation, snapshots the exact current
     epoch internally, uses that epoch in the existing compare-and-swap
     transition, and reads back the newer disabled epoch. The public command
     contract remains the approved expected-mode barrier; no caller-supplied
     epoch or digest is invented.
   - `Drain`: require a caller deadline, accept only `wait`, and return success
     only after `completeLocalAuthority.DrainWait` finishes, the exact immutable
     disabled policy is re-snapshotted under the barrier, and a fresh complete
     observation proves every workload counter zero. `cancel` remains unavailable
     because the observer has no destructive running-job authority.
   - `ReconcileOnce`: delegates to the complete local authority and validates a
     real nonzero receipt; it never returns an empty success receipt.
   - `health`: succeeds only when the process has completed its startup
     disabled publication, both socket identities are still exact, policy is
     exact disabled/empty/zero, a fresh complete workload observation is zero,
     and the separate fleet-authority proof is exact.
     Otherwise it returns unavailable.

7. Strengthen the command-side database ownership handle from `io.Closer` to a
   sealed lease with `Validate() error` and `Close() error`. It identity-pins
   the stable lock file and proves the same descriptor still holds the
   exclusive advisory lock; a plain closer or path-only check is insufficient.
   `executeRun` transfers this exact locked descriptor into `OpenController`;
   successful construction makes the observer the sole owner. `executeRun`
   closes it only when construction fails before transfer and never retains a
   parallel closer. The observer revalidates the same descriptor throughout
   `Run`, joins its close into process shutdown after readiness is cleared, and
   cannot re-open the proof by path.

   Inside that exclusive process boundary, a context-aware effect gate
   serializes every policy transition and `completeLocalAuthority` effect. It
   has mutex semantics for normal methods but supports cancellation/deadline
   while waiting so shutdown cannot wait forever for a long effect. A separate
   state mutex protects readiness generation, sticky fatal/busy/shutdown state,
   proof tuples, observations, broker capacity, and fleet-authority proofs.
   Normal mutation paths that need both acquire effect then state. The sole
   exception is the state-only shutdown trip described below: it never waits
   for effect while holding state and never mutates controller authority.
   Concurrent connections may complete bounded framing outside both.

   Short methods hold the effect gate through ownership validation, policy
   snapshot/CAS, local authority call/observation, fleet/broker proof, and
   success commit. Before a long effect (`DrainWait` or a potentially long
   reconciliation), the handler holds effect+state, advances/clears readiness,
   sets busy with a unique nonzero effect-owner generation token, and releases
   state while retaining effect for the entire mutation. It then reacquires
   state, performs the full proof, and may transition busy-to-ready only by
   compare-and-swap of the exact token it installed, while still holding
   effect, and only when sticky-fatal and shutdown are false. It re-samples the
   full success tuple in that same state critical section. The process owns one
   cancellable `runContext`. Every admitted-handler and method context,
   including every long-effect context, is a child of that context and then
   capped by the applicable overlay/caller deadline; no handler or authority
   call may use a detached `context.Background`-only timeout. Shutdown first
   cancels this process context and trips shutdown under state alone, without
   waiting for effect. That trip clears readiness, advances its generation, and
   invalidates every effect-owner token, so every later proof/commit and
   busy-to-ready CAS observes shutdown and fails closed. Only the current
   effect owner has the narrow exception allowing busy-to-ready after complete
   proof before the shutdown trip.

   Health first reads
   readiness/busy atomically and returns `not_ready` immediately if either is
   adverse; otherwise it uses a nonblocking `TryLock` on effect and returns
   `not_ready` rather than waiting when an effect is active. It rechecks
   readiness/busy after locking before any success proof.

   Framing and method budgets are separate. Short read/write idle deadlines
   defend the socket boundary. Method execution uses a child of the process
   `runContext`, capped by the caller deadline and the exact overlay admin,
   drain, or reconciliation budget; the framing deadline is not stretched
   across or reused to abort a valid long effect. Health is specifically
   capped server-side by the parsed `Controller.OperationTimeout`; its
   observation must also satisfy `Health.ObservationMaxAge`. Ownership
   validation, local observation, fleet/broker proof, and socket checks all run
   inside that health context. A caller deadline returns closed
   `deadline_exceeded`; process cancellation returns closed `not_ready` or
   terminates the connection during shutdown. Both release effect and may
   clear only their own still-current busy token under state. Neither can
   re-arm readiness or commit `ok` after shutdown/sticky-fatal/token
   invalidation. No handler can commit after readiness is cleared, while
   busy/fatal/shutdown is set, or while another handler owns the effect.

   Each successful response is bound to a fresh tuple containing validated
   ownership-lease identity, policy epoch/digest, local workload-observation
   sequence/time, mode-appropriate fleet-authority proof, broker capacity
   epoch/value, controller process-start identity, readiness generation,
   busy=false, sticky-fatal=false, shutdown=false, and both socket device/inode
   identities. The
   tuple is re-read immediately before response commit; any change returns
   conflict or unavailable. This is a process-local proof barrier backed by the
   stable ownership lock, not an assertion that unrelated filesystem reads are
   globally atomic.

8. Startup order:
   - existing manifest/config/executable/store validation and composition;
   - prove the stable single-instance database ownership lock remains held;
   - construct complete local cleanup/reconciliation authority or fail;
   - construct and validate the zero-demand broker;
   - construct the sealed unavailable-external graph and prove there are no
     poll targets or external mutation ports;
   - prove the exact portable self guard or exact legacy-normalized state,
     rejecting `none`;
   - publish/read back a newer disabled epoch;
   - run cold local reconciliation under disabled acquisition;
   - obtain a fresh complete zero workload observation plus the separate exact
     fleet-authority proof;
   - create both sockets and verify exact identities;
   - start bounded accept loops;
   - re-read the full proof tuple; and
   - only then advance the readiness generation and set readiness.
   If either socket cannot be created or any proof fails, close both loops,
   remove only owned sockets, compare-and-swap another disabled epoch during
   shutdown, close state, and return failure.

9. Shutdown order:
   - trip the barrier without waiting for effect: cancel the process
     `runContext`; under state alone set shutdown, clear readiness, advance its
     generation, and invalidate every effect-owner token; release state; then
     close the listeners so no new admission can begin;
   - require every admitted handler and authority effect to inherit that
   cancellation and prohibit detached contexts;
   - every handler releases the effect gate with a defer installed immediately
     after successful acquisition, including cancellation, deadline, panic,
     and authority-error exits; shutdown's acquisition is therefore a bounded
     join of owners already required to be canceling, not the mechanism that
     asks them to cancel;
   - acquire effect through the context-aware gate under the configured
     shutdown deadline, thereby joining every in-flight effect without an
     effect-then-cancel deadlock; after acquisition, take state, confirm
     shutdown/readiness/token state, clear only invalidated busy bookkeeping,
     and release state;
   - close/join both accept loops and admitted handlers under that same
     configured shutdown deadline;
   - remove only identity-matching owned sockets;
   - under the exclusive barrier revalidate ownership and the exact
     disabled/empty/zero policy;
   - call `RevokePreRunning`, obtain a fresh complete workload observation,
     require every workload counter zero, and separately require the exact
     mode-appropriate self fleet-authority proof;
   - compare-and-swap another disabled epoch only from the exact epoch owned by
     this process; if a foreign newer epoch exists, return conflict rather than
     overwrite it; and
   - close the state/store and then the exact transferred ownership/fleet-guard
     leases.
   If the effect gate or any handler cannot join by the shutdown deadline,
   readiness remains false, listeners remain closed, cancellation remains
   tripped, no state/store/lease close races the live effect, and `Run` returns
   a typed `shutdown_effect_stuck` non-nil failure while retaining those
   resources until process exit. A late effect return may release its gate and
   clear only its own invalidated busy token; it can never re-enter proof,
   re-arm, publish, close shared resources, or commit success. Any close, join,
   remove, publication, or close-store failure is joined and returned; no
   false success.

10. Client discovery remains explicit and private. Production live-admin
   commands require environment variable `PORTABLE_GHAR_PRIVATE_OVERLAY`
   containing the absolute path to the root-owned mode-0600 controller runtime
   config. The CLI reuses the existing pinned-file loader and
   `LoadControllerRuntime`, obtains the admin socket path, and dials it. It
   applies the same absolute, canonical, no-symlink, root-owned, mode-0600
   pinned identity checks as production startup before trusting either socket
   path, obtains only `AdminSocketPath` for admin methods, and verifies the
   exact socket path plus peer UID after connect. `probe` remains non-root at
   the CLI grammar layer, but the private config/socket modes and kernel peer
   checks make an ordinary unprivileged production call fail closed. Mutating
   commands retain the existing root check. No compiled default path, PATH
   lookup, health/admin path substitution, shell, or arbitrary socket argument
   is introduced.

   The watchdog/readiness client uses the same pinned private-overlay loader,
   but extracts only `HealthSocketPath`, verifies its exact socket identity and
   peer UID after connect, and accepts only the `health` method. There is no
   arbitrary health socket argument or fallback from one socket role to the
   other.

1. The wire decoder enforces exact cross-field invariants. Status `ok` is
    valid only with reason `none` and exactly the payload shape required by the
    request method; a no-payload success is allowed only for a method whose
    schema explicitly says so. Every non-`ok` status requires a non-`none`
    closed reason, forbids success payloads, and maps to a non-nil error. Every
    other status/reason/payload crossover is a protocol error and can never
    reach CLI `encodeOK` or a zero-value successful object.

2. A recovered handler panic or internal fatal first enters the exclusive
    barrier, advances and clears readiness, sets a sticky fatal bit included in
    every success tuple, and only then cancels accept loops and handlers.
    Concurrent requests must re-read fatal/readiness at commit and cannot
    return `ok` after the fatal transition.

3. `disabled/empty/zero` is acquisition terminology: mode disabled, zero
    capacity, and no eligible scale sets. It does not erase the nonzero
    immutable repository-policy revision or repository summaries, which the
    current observer constructor deliberately requires and the approved Task 10
    plan uses as immutable templates. Production preserves that metadata. This
    rejects the review's contrary factual premise while retaining its valid
    false-readiness findings.

4. TDD and mutation traps:

- RED first for canonical framing, bounds, unknown/trailing fields, partial
  writes, deadlines/cancellation, method-field crossovers, closed errors,
  wrong socket identity/parent/replacement, startup rollback, shutdown join,
  and exact owned-path removal.
- RED first for every nonzero acquisition attempt, cancel drain,
  zero-proof failure, policy drift, pre-readiness behavior, socket
  replacement, unavailable reconciliation, and server panic or connection
  failure.
- RED first for incomplete, missing, or stale observations, zero-valued
  sample sequences, absent cleanup authority, cold-reconcile failure,
  post-proof drift, response-status/error mismatches, peer-credential
  mismatch, handler saturation, slowloris, handler panic, and a foreign
  newer shutdown epoch.
- RED first for ownership validation loss at readiness and response commit,
  concurrent method effects, late success after shutdown/fatal, nonzero or
  epoch-mismatched broker capacity, fence none/stale/unguarded state,
  incomplete unavailable-external graph, nonempty poll targets, missing
  pre-running revocation, nonzero shutdown observation, and health/admin
  discovery crossover.
- RED first for self-guard-versus-workload separation in portable and legacy
  modes, foreign/duplicate/orphan guards, health during a long drain or
  reconciliation, separate framing/method deadlines, effect `TryLock`
  behavior, and exact ownership-lease transfer/close semantics.
- RED first for effect completion racing shutdown, stale effect-owner token
  re-arm, health observation deadline, and admission saturation before the
  first request byte read.
- RED first with in-flight `DrainWait` and long `ReconcileOnce`: process
  shutdown must trip cancellation/readiness promptly without waiting for
  effect, every method must inherit process cancellation, no handler may
  return `ok` or re-arm afterward, the effect/handler join must complete
  within the shutdown deadline, and no effect-then-shutdown deadlock is
  permitted. Also reject any detached `context.Background` authority path.
- RED first with a deliberately cancellation-ignoring authority double:
  readiness still clears promptly, no late return can re-arm or commit, the
  join terminates at its bound with typed `shutdown_effect_stuck`, shared
  store/ownership leases are not closed underneath the live effect, and the
  gate-release defer runs when the double is finally released. Production
  authority tests prove every real wait/retry/subprocess and local
  multi-step I/O observes cancellation before the shutdown bound.
- RED first for every status/reason/payload crossover and prove every
  non-`ok` response becomes a non-nil client and CLI error.
- Prove no IPC request can expose or invoke GitHub, routing, generic
  commands, lifecycle apply, journal advance, image selection, or fence
  handoff.
- Run focused tests, full Task 10 Go tests, race-sensitive socket tests where
  supported, vet, shellcheck/Bats, dependency gates, and then exact changed
  artifact Grok review before signed commit.

Review question:

Does this plan preserve fail-closed disabled-observer semantics and provide a
sound bounded local IPC boundary? Attack discovery, framing, socket identity,
concurrency, startup/shutdown, proof freshness, authority leakage, and false
success. Return PROCEED only if no material design gap remains; otherwise
return REVISE with precise mandatory changes.
