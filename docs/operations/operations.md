# Operations

This runbook describes the host watchdog's authority, what incident
evidence a Portable GHAR deployment is expected to preserve, and how long
that evidence and any rollback material is retained. It assumes the
components in [Architecture overview](../architecture/overview.md) and
the boundaries in [Trust boundaries](../security/trust-boundaries.md).

Phase 1 of this repository ships no host watchdog binary. This page
describes the intended operational contract the later host-integration
phase implements; it is not a claim that any watchdog behavior below is
live against a deployed host today.

## Watchdog restart authority

The host watchdog's authority is deliberately narrow, and it is a
**restart** authority, **never** a **routing** authority. The watchdog
may:

- restart a missing or failed controller process;
- reconcile stale controller PID or lock state;
- verify required private files and their file-mode bits;
- report local health; and
- stop acquisition when a host prerequisite fails.

The watchdog may **never**:

- change repository routing;
- mint or store failover GitHub App credentials;
- mark the external failover state healthy independently of the
  controller's own reconciliation; or
- run as a Docker container on a host whose Docker daemon it is expected
  to recover.

When a prior (legacy) fleet owns the host-local fence, the watchdog may
restart Portable GHAR only as a force-disabled, zero-capacity observer;
any nonzero poll, acquisition, or JIT generation still requires a current,
correctly-fenced guard, regardless of what the watchdog itself observes
locally.

## Incident evidence

An incident record is built entirely from sanitized, schema-defined
fields -- never from raw logs, request bodies, or secret-bearing state.
The controller's redacting logger emits only allowlisted fields and
rejects any field shaped like a secret or sourced from job-controlled
input; the Durable Object similarly records only bounded, typed audit
events (transition type, epoch, sanitized reason code, and timestamps),
never credentials, request bodies, repository coordinates beyond a
configured alias, or notification destinations. An operator reconstructing
an incident timeline reads back this sanitized evidence -- controller
state transitions, Worker/Durable Object transition history, and delivery
records for both notification channels -- rather than raw production
logs.

## Retention

Rollback material and incident evidence are kept for a documented
retention period after retirement of any replaced fleet, not deleted
immediately once a migration or upgrade completes. Legacy credentials are
revoked only after retirement is independently verified and the
documented retention window for its rollback material has been
satisfied, so an operator can still recover from a mistaken retirement
during that window. Public documentation intentionally does not fix a
specific retention duration here: the exact window is deployment
configuration, set and enforced by the operator's own private overlay,
not a value this repository hard-codes.
