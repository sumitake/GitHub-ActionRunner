# Failover and notifications

This runbook describes the external failover control plane -- the
Cloudflare Worker and its per-fleet Durable Object -- and the two
notification channels a routing transition drives. It assumes the
components in [Architecture overview](../architecture/overview.md) and
the boundaries in [Trust boundaries](../security/trust-boundaries.md).

Phase 2 source does not activate a Cloudflare Worker deployment. This page
describes the intended failover and notification contract the later
external-control-plane phase implements; it is not a claim that any
behavior below is live against a deployed Worker today.

## Server-owned enrollment epochs

The Durable Object, not the host, owns a fleet's enrollment epoch. A
controller instance enrolls with a random nonce and a timestamped,
HMAC-authenticated `POST /v1/session`; the Durable Object atomically rejects a
reused nonce digest, increments its own server-owned epoch and lease generation,
invalidates the prior session, carries forward the fleet's lease-drain
restriction, and returns a signed response bound to the request nonce and
`leaseNotBefore`. Local controller-state loss -- a wiped disk, a fresh install
-- causes a new authenticated enrollment, never a permanent lockout, because
the host never has to remember or reconstruct the epoch itself.

Invalidating the old session rejects its later traffic but cannot erase its
cached lease. The enrollment transaction therefore carries one
`leaseNotBefore` restriction in the existing fleet state through the
fleet-global monotonic maximum expiry of every issued lease plus the
hosted-transition safety margin. Issuing a lease and advancing that maximum are
one transaction. The replacement can reconcile and send heartbeats immediately,
but those responses explicitly grant no lease until Worker receipt time reaches
that boundary. They prove controller liveness only: the closed
`predecessor-lease-draining` reason stays visible in status and audit, is not
acquisition-ready health, failback evidence, hosted success, or zero-listener
quiescence evidence, and local-routed work may queue for the bounded remainder.
Quiescence proof is accepted only from the exact enrollment session and lease
generation whose listener set is being drained. A replacement cannot report
zero for its predecessor; if supersession occurs before that exact proof, the
governed local transition stays incomplete under hosted-safe routing and
alerts. A first enrollment has no predecessor delay, and repeated enrollments
cannot shorten an existing drain. No positive response from the old controller
is required merely to expire its cached lease.

## Heartbeat replay and ordering

A heartbeat is only ever generated after a successful controller
reconciliation cycle, and carries a monotonic session sequence number plus
the epoch it was issued under. The Worker treats its own receipt time,
not the client's claimed time, as the freshness signal, and it
**rejects** any heartbeat that is a duplicate, **reordered**, from a
superseded epoch, or a **replay** of an earlier message. A late canary
result from an obsolete epoch is likewise ignored rather than accepted.

The accepted heartbeat response carries the only remote acquisition authority:
one short-lived signed lease binding the fleet holder, session, generation,
policy digest, mode, maximum capacity, and a bounded signed set of
Worker-latched archived-disabled repository aliases. Portable and governed
legacy rollback use the same lease type. The controller derives its shorter
monotonic deadline from heartbeat send time, rejects a late response, and
validates the operator-approved heartbeat/lease inequality. Missing, stale,
mismatched, or expired leases stop new local acquisition while running jobs
drain; a signed repository disable stops only that alias. Archive evidence has
an approved maximum age and missing or stale evidence is restrictive. A cached
pre-restriction lease converges by its next replacement or existing local
deadline, so the documented worst case is evidence age plus remaining lease,
not an instantaneous remote revocation claim. Administrative status and
maintenance commands never grant authority.

## Transition, outbox, and read-back

Every GitHub-facing routing mutation is staged through a durable outbox
before it is attempted: local transition intent and outbox rows are
committed first, each due row is claimed with an expiring claim before the
external call, and the outcome commit requires that same live claim. A
crash or an ambiguous API result triggers claim recovery, a GitHub
read-back, and idempotent reconciliation rather than a blind retry or a
silently dropped mutation. No external routing write is ever attempted
from state that was not first durably persisted.

One Cloudflare Cron Trigger is the sole durable scheduler for this due work.
Because Durable Object namespaces are not enumerable, each tick validates one
canonical bounded private fleet-ID inventory, directly addresses every listed
object with an enforced deadline and bounded concurrency, and asks each object
to claim a bounded batch. An invalid or absent inventory prevents enrollment
and lease renewal; addition requires Cron-addressability read-back, and removal
requires hosted, zero-lease, empty-due-work proof. Expired claims return to the
queue and all retries and retained history are capped. Request handlers may
opportunistically execute newly persisted work, but recovery never depends on
another request. Durable Object alarms and private runtime-storage behavior are
deliberately not a second recovery path or fleet registry.

With Cron functioning, the operator-approved hosted-transition completion
budget covers the last lease window, safety margin, one Cron period, bounded
delivery jitter, and one due-work execution/read-back attempt. If that budget
is exceeded, or Cron is unavailable, the transition remains incomplete and
visible; it is never reported as hosted success.

The routing state machine stays small: hosted, draining-to-hosted, Portable
canary, Portable, legacy canary, and legacy. API calls, canary outcomes,
read-backs, queue-risk clearance, and notifications are transition evidence,
not additional authority states. Bootstrap issues no lease and enters hosted
only after exact read-back. A failed canary revokes its canary lease and returns
directly to hosted because routing never left hosted.

## Canary-gated failback

Routing never fails back to self-hosted runners on health alone. Recovery
requires, in order: every open queue-risk record from the latest hosted
transition cleared by authenticated GitHub read-back; a canary run tied
to the current transition epoch that observes
`runner.environment=self-hosted` at the exact expected workflow revision;
local enabled intent; and, without the Worker's transition epoch changing in
between, a newer-sequence heartbeat from the same enrollment session proving
the expected acquisition-policy digest and full configured capacity. That
heartbeat is route-readiness evidence only and grants no enabled lease while
routing remains hosted. The Worker may then create self-hosted routing intent;
only exact read-back enters `PORTABLE`, after which a subsequent matching
heartbeat may return the enabled lease that starts local acquisition. If the
canary cannot pass, hosted routing is the safe state that
remains in effect -- there is no automatic bypass of a failed canary.

## Independent notification retries

Primary email and the optional secondary signed webhook are separate
outbox items from the routing transition itself, and are retried
**independently** of each other: a transient failure on either channel
uses bounded exponential backoff, a permanent failure stops retrying but
stays visible in recorded state, and duplicate delivery is expected and
made safe by an idempotent event ID on the consumer side.

Critically, **notification failure never blocks routing safety**: a
failed or delayed email, webhook, or downstream relay never delays,
reverses, or otherwise gates a hosted-hold, failover, or failback
transition. Routing correctness and operator notification are
deliberately decoupled failure domains.

If both the Worker and Cron path are unavailable while GitHub still routes a
repository locally, the short lease expires and new local acquisition stops.
Already evaluated jobs may queue until the control plane recovers. This is an
explicit availability degradation, never evidence that hosted failover was
confirmed.
