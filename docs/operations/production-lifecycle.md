# Production lifecycle

This runbook describes the intended production lifecycle of a Portable
GHAR deployment: the controller's persisted states, its safe-upgrade
sequence, the host-profile probes a deployment must pass, and the
zero-capacity dark-deployment step every install starts from. It assumes
the components in [Architecture overview](../architecture/overview.md)
and the boundaries in [Trust boundaries](../security/trust-boundaries.md).
All commands shown here are synthetic and illustrative -- they describe
the shape of an operator's positive read-back gate, not a real
deployment's paths, hosts, or credentials.

Phase 1 of this repository ships no runtime controller. This page
describes the intended lifecycle the later runtime phases implement; it is
not a claim that any of the states or gates below are live today.

## Persisted controller states

Each job assignment the controller accepts is tracked through a persisted
state machine, checkpointed at every real external effect:

```text
RECEIVED -> CAPACITY_RESERVED -> ADAPTER_CREATED -> ADAPTER_VERIFIED
  -> BROKER_HELD -> BROKER_POLICY_APPLIED -> DIAL_AUTHORITY_READY
  -> BROKER_RELEASED -> EGRESS_VERIFIED -> RUNNER_HELD -> RELEASE_ARMED
  -> LISTENER_RELEASED -> JOB_RUNNING -> JOB_FINISHED -> DESTROYED
```

Persistence exists so a controller restart -- planned or crash-induced --
can reconcile every in-flight assignment to exactly one terminal outcome
without ever duplicating a runner or double-accepting a job. A transition
that is repeated after a restart is always either a no-op or the
completion of the interrupted step.

Acquisition policy itself (mode, eligible scale sets, capacity, and
per-repository policy) is also persisted, and every change to it passes
through one bounded epoch barrier before taking effect: stale in-flight
operations are cancelled and joined, and an operation the controller
cannot join in time makes the controller fail closed rather than let a
stale operation acquire capacity under superseded policy.

## Safe upgrade sequence

An upgrade never replaces a running controller in place while it might
still be accepting work. The intended sequence is:

1. enable the Worker-owned hosted hold and positively read back every
   configured repository routed to GitHub-hosted runners;
2. stop new acquisition and drain or cancel assigned jobs per policy;
3. prove zero listeners, adapters, brokers, helpers, verifiers, and
   per-job sockets remain -- retained ledger state stays retained, not
   reused, until its retention window expires;
4. replace the pinned controller binary and images, then run compatibility
   and host-profile probes;
5. start the replacement disabled, and clear every open queue-risk row
   through authenticated GitHub read-back before any new acquisition;
6. set canary-only intent, release the hosted hold into a new recovery
   epoch, and run one canary operation that must obtain a fresh Worker
   permit while consumer routing stays hosted; and
7. only after that canary passes, and a fresh heartbeat proves full
   acquisition capacity, does the failover state machine permit
   self-hosted routing to resume.

An illustrative operator gate read for step 1 of this sequence:

```operator-command
portable-ghar status --expect-route hosted --expect-hold true
```

Host lifecycle changes use a durable operation journal keyed by an
idempotent operation ID; a rerun after a crash resumes or compensates
forward rather than repeating an already-applied effect. An upstream
compatibility failure leaves acquisition disabled and hosted routing
unchanged.

Detailed source-ready procedures are separated by lifecycle phase:

- [Controller upgrade](controller-upgrade.md) covers immutable replacement,
  hosted hold, qualification, drain, selection, canary, and enable gates.
- [Controller recovery](controller-recovery.md) covers authoritative
  read-back, ambiguity, dark observer startup, forward recovery, compensation,
  and rollback.
- [Runner release](runner-release.md) covers automatic official-release
  observation, maintenance responses, forced-version-bump continuity, and
  whole-container reclamation.

These procedures do not authorize live-host commands. Each live execution
still requires a separately approved packet with exact identities,
postconditions, rollback, and stop conditions.

## Grafana and InfluxDB activation gate

Portable GHAR controller health and GitHub workflow state are complementary
signals. The existing GitHub API collector remains authoritative for current
workload identity and waiting state: active runners are current
`in_progress` jobs with a non-empty GitHub runner name; queued jobs are
current jobs whose GitHub status is `queued`; current queue wait is measured
from the oldest still-queued job's `created_at`; and a pull-request number is
shown only when GitHub supplies the workflow-run association. Controller
counters and runner-registration counts never replace those definitions.

Operational telemetry is required cutover evidence, but it is not acquisition
or routing authority. Before canary-only intent:

1. change the dashboard's online-registration presentation so zero is neutral
   or healthy when there is no demand. Portable GHAR deliberately keeps zero
   idle runners, so `online self-hosted = 0` cannot be a red fleet-health
   condition. Keep registration count as a diagnostic rather than a readiness
   signal;
2. add an explicit, schema-versioned read-only export of the controller's
   validated `health.Snapshot`. The current local `health` method is a
   liveness response with no snapshot payload; the implementation must not
   assume otherwise. Preserve the health socket's peer-UID and socket-identity
   checks, canonical JSON, size bounds, deadlines, closed field allowlist, and
   unknown-field rejection. Keep the liveness method compatible and do not add
   any mutation to the health socket or any telemetry method to the admin
   socket;
3. deploy a one-way local telemetry adapter that reads only that closed health
   export and writes measurement `portable_ghar_health` to InfluxDB at the
   controller heartbeat cadence. The controller receives no InfluxDB
   credential or Grafana dependency. The adapter uses a least-privilege
   write-only credential from the private deployment overlay and never places
   it in process arguments or logs. Adapter, InfluxDB, and Grafana failures
   cannot grant, retain, revoke, or synthesize acquisition authority; and
4. preserve the snapshot's closed identity boundary. No repository, workflow,
   pull request, job, runner, path, route, command output, token, or credential
   may enter `portable_ghar_health`. The existing GitHub collector remains
   the separate source for workload and PR identity. Synthetic conformance
   protocol IDs, scenario/cycle identifiers, digests, cleanup booleans,
   resource vectors, seed proofs, and restart evidence are likewise test-only
   and may not enter the health export, signed Worker heartbeat, InfluxDB
   measurement, Grafana variables or annotations, GitHub collector, or
   cutover evidence, even after renaming, hashing, aggregation, or projection.

### InfluxDB contract

The adapter receipt time is the InfluxDB point timestamp and freshness anchor,
matching the control plane's receipt-time model. The controller's
`ObservedAt` is retained as a diagnostic field, not trusted as arrival time.
The adapter validates the exact exported schema, rejects observations outside
the configured clock-skew bound or older than the last accepted observation
for that fleet and policy epoch, and emits either one complete point or no
point.

Tag only the bounded `fleet_alias`, `acquisition_mode`, and
`host_profile_id`. Store policy and build digests as fields rather than tags
to bound series cardinality. Each point has fixed field types and contains
`schema_version=1`, `sample_complete=1`, `observed_at_unix_ns`, policy
epoch/digest, repository-policy revision, configured/effective/occupied/
available/queued capacity, assigned/running jobs, oldest live-assignment age
in seconds, unassigned released-listener count, last-terminal Unix time (zero
when absent), degraded state, and build ID. Schema, escaping, integer range,
duration conversion, optional-terminal, replay, and partial-write cases require
deterministic adapter tests before deployment.

### Dashboard behavior

Grafana keeps the GitHub-derived active-runner, queued-job, current-queue-wait,
online/busy-registration, and PR-aware job panels. It adds controller panels
for heartbeat freshness, acquisition mode, configured/effective/occupied/
available capacity, controller-queued capacity, assigned and running jobs,
oldest live-assignment age, unassigned released listeners, degraded/profile
state, build identity, and last-terminal age. Label controller-queued capacity
as controller demand; it is not GitHub's queued-job count.

Controller panels accept only `sample_complete=1` points newer than the
configured control-plane stale threshold. The current design carries a
six-minute threshold, while the existing GitHub collector carries its
five-minute schedule and separate fifteen-minute fail-closed window; this
design slice does not approve or alter any of those numeric values. Schedule,
heartbeat staleness, retention, and cross-source skew remain private
deployment settings requiring separate operator sign-off. Stale or malformed
data becomes no-data, never a last-known-good green state. Cross-system
comparisons use stored receipt timestamps and exact source definitions rather
than treating panel-now counts as atomic.

### Cutover acceptance

Every numbered cutover phase below records its own complete jointly fresh
evidence tuple:
`github_sample_received_at`, `controller_adapter_receipt_at`,
`signed_heartbeat_received_at`, `dashboard_revision`, and
`scope_fingerprint`. The three receipt times must each be within their
independently configured stale windows, and their maximum pairwise skew must
not exceed the separately operator-approved private
`cutover_max_sample_skew`. Dashboard revision and scope fingerprint must equal
the reviewed deployment. Source supplies no default for the skew bound. Until
all five members, all stale windows, and the skew bound pass, that phase is
not accepted and cannot authorize the next phase. The tuple is evidence only:
the signed Worker heartbeat and governed controller policy remain the
automated routing authorities.

1. **Dark observer:** record at least three consecutive complete health points
   from successful reconciliation cycles with acquisition `disabled`,
   effective/occupied/available capacity zero, assigned/running jobs zero,
   unassigned released listeners zero, and the expected policy epoch/digest,
   repository-policy revision, host profile, degraded state, and build ID.
2. **Queued canary while disabled:** dispatch the secretless canary while
   consumer routing and the hosted hold remain hosted and Portable GHAR
   acquisition remains disabled. Keep the canary queued through one scheduled
   GitHub collection point, then reconcile the dashboard's queued count,
   current wait, repository scope, completeness flag, and queued-set
   fingerprint directly against GitHub.
3. **Running canary while hosted:** enter `canary-only` and keep the canary's
   workload step alive through one scheduled GitHub collection point. Verify
   GitHub active/online/busy sets and authoritative identity while the
   controller point reports effective capacity one and the expected assignment
   lifecycle. After completion, wait for the next complete GitHub sample and
   verify assigned/running/occupied/unassigned-listener counts return to zero,
   last-terminal advances, and every fixed-cardinality job slot clears.
4. **Enabled/full-capacity confirmation:** only after the dashboard and InfluxDB
   gates above pass may the operator enable full acquisition. The signed Worker
   heartbeat remains the sole automated health/routing input. After its
   authoritative enabled/full-capacity confirmation, require the enabled
   phase's complete jointly fresh tuple. A missing member, stale member,
   fingerprint/revision mismatch, or excessive skew fails the tuple; no
   last-known-good member may be substituted. If that post-enable observation
   fails, treat cutover acceptance as failed, reacquire the hosted hold, and
   disable acquisition through the governed rollback path. InfluxDB or
   Grafana failure can block or revoke cutover acceptance, but neither can
   grant routing authority or directly change routing.
5. **Scope and natural-sample reconciliation:** verify the private collector
   repository list exactly matches the repositories managed by this
   deployment. Any addition, archive-state change, or removal must update that
   scope explicitly. Record the complete jointly fresh tuple above with the
   GitHub and controller completeness flags and source-specific fingerprints
   used as cutover evidence.

If the health export, adapter, InfluxDB write, dashboard query, or source
reconciliation fails before cutover, retain the hosted hold and keep Portable
GHAR disabled or canary-only. After an accepted cutover, telemetry failure
makes affected panels fail closed and alerts the operator while the signed
Worker heartbeat and failover policy remain authoritative. Portable GHAR and
Grafana/collector rollback remain independent: a fleet rollback must not
overwrite the existing GitHub collector, schedule, repository scope, retention
policy, or dashboard rollback anchor, and the Portable GHAR health series may
age to no-data when its adapter stops.

## Host-profile probes

A host is only eligible to acquire work after it positively proves,
rather than merely declares, every required property: supported
Docker/runtime version and kernel features; CPU, memory, PID, tmpfs,
read-only-root, seccomp, and capability enforcement; non-root execution or
an explicitly acknowledged, visibly flagged degraded-root profile; checked
free-byte and free-inode headroom on every filesystem the controller
writes to; complete egress-policy enforcement observed from an actual
runner namespace; no access to host Docker control or private paths from
inside a job; and reboot-persistent watchdog behavior. An unsupported host
profile fails closed rather than falling back to a weaker default.

## Dark deployment

A new Portable GHAR install is never handed live traffic on day one.
While an existing (legacy, or no) fleet still owns the host-local
fleet-generation fence, the new controller and watchdog start as a
**force-disabled, zero-capacity observer**: they may run, report local
health, and prove their own host-profile conformance, but they cannot
poll for work, acquire a job, or generate a JIT credential. Only an
explicit, fenced hand-off from the prior fleet to `portable` -- itself
gated on the safe-upgrade sequence above -- ever lets the observer begin
acquiring at nonzero capacity.
