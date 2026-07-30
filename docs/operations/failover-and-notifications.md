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
HMAC-authenticated challenge/response exchange; the Durable Object
atomically consumes the challenge once, increments its own server-owned
epoch, invalidates the prior session, and returns the new epoch and
session identifiers. Local controller-state loss -- a wiped disk, a fresh
install -- causes a new authenticated enrollment, never a permanent
lockout, because the host never has to remember or reconstruct the epoch
itself.

## Heartbeat replay and ordering

A heartbeat is only ever generated after a successful controller
reconciliation cycle, and carries a monotonic session sequence number plus
the epoch it was issued under. The Worker treats its own receipt time,
not the client's claimed time, as the freshness signal, and it
**rejects** any heartbeat that is a duplicate, **reordered**, from a
superseded epoch, or a **replay** of an earlier message. A late canary
result from an obsolete epoch is likewise ignored rather than accepted.

## Transition, outbox, and read-back

Every GitHub-facing routing mutation is staged through a durable outbox
before it is attempted: local transition intent and outbox rows are
committed first, each due row is claimed with an expiring claim before the
external call, and the outcome commit requires that same live claim. A
crash or an ambiguous API result triggers claim recovery, a GitHub
read-back, and idempotent reconciliation rather than a blind retry or a
silently dropped mutation. No external routing write is ever attempted
from state that was not first durably persisted.

## Canary-gated failback

Routing never fails back to self-hosted runners on health alone. Recovery
requires, in order: every open queue-risk row from the latest hosted
transition cleared by authenticated GitHub read-back; a canary run tied
to the current transition epoch that observes
`runner.environment=self-hosted` at the exact expected workflow revision;
local acquisition then enabled; and, without the Worker's transition epoch
changing in between, a newer-sequence heartbeat from the same enrollment
session proving the expected acquisition-policy digest and full
configured capacity. Only that combination can create self-hosted routing
intent. If the canary cannot pass, hosted routing is the safe state that
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
