# Deployment and rollback

This runbook describes how a Portable GHAR deployment is rolled back to a
prior (legacy, or hosted-only) fleet, and the gates that keep a rollback
safe. It assumes the components in
[Architecture overview](../architecture/overview.md) and the boundaries in
[Trust boundaries](../security/trust-boundaries.md). All commands shown
here are synthetic and illustrative -- they describe the shape of an
operator's positive read-back gate, not a real deployment's paths, hosts,
or credentials.

Phase 2 source implements the local controller and host rollback seams,
but no Cloudflare failover authority or live deployment has been
activated. This page describes the complete intended rollback contract;
it is not a claim that any rollback below has been exercised against a
live deployment.

## Mutually exclusive rollback barrier

The new (Portable GHAR) fleet and a prior (legacy) fleet must **never
acquire work concurrently** during a rollback. The rollback sequence is a
strict barrier, not a best-effort handoff:

1. enable the Worker-owned hosted hold and read back every configured
   repository on GitHub-hosted runners;
2. stop new Portable GHAR acquisition;
3. drain or cancel already-assigned jobs according to policy;
4. stop the controller;
5. prove zero listeners, runners, adapters, brokers, helpers, verifiers,
   per-job sockets, and pending dials remain -- retained ledger state
   stays retained, not reused, until its retention window expires;
6. while local acquisition remains zero, clear every open queue-risk row
   through authenticated GitHub read-back and selective recovery;
7. only then flip the host-local fleet-generation fence from the disabled
   state to the captured legacy generation, and only after that flip
   restore and verify the legacy fleet; and
8. through the authenticated Worker rollback transition, explicitly set
   and read back the `legacy` route -- deleting a routing variable is
   never interpreted as selecting legacy work.

Starting the legacy fleet before the new fleet's stop is positively proven
is prohibited. Both generations, and both fleets' watchdogs, honor one
exclusive, stable-inode host-local fence so a race between them cannot
produce concurrent acquisition.

## Hosted hold as the only maintenance freeze

An authenticated, disabled-by-default administrative hosted hold is the
**only** maintenance freeze in the design: it can be enabled from any
failover state, persists hosted transition intent, and blocks recovery
until every configured repository reads back hosted. Releasing it starts
a new recovery epoch; because routing was already hosted throughout the
hold, releasing it does not itself re-block acquisition or insert a new
queue-risk row.

## Positive read-back gates

No step in this runbook advances on an assumption. Every gate is a
**positive read-back**, not a fire-and-forget mutation: a hosted-hold
transition is only confirmed once every repository's routing variable
resolves to hosted, a queue-risk row is only cleared once GitHub state has
actually been re-read for that repository at the same epoch, and a
recovery canary is only accepted if it observed
`runner.environment=self-hosted` at the exact expected workflow revision.

An illustrative operator gate read before a rollback proceeds past its
hosted-hold step:

```operator-command
portable-ghar status --expect-route hosted --expect-hold true --require-queue-risk-cleared
```

## Rollback sequence

Putting the barrier and the read-back gates together, a full rollback
never leaves an ambiguous window: acquisition is proven zero before the
legacy fence is armed, the legacy fleet is proven healthy (including a
successful, secretless canary) before workflows are ever told to route to
it, and the explicit `legacy` route is only written -- and only read back
-- after every earlier gate has passed. Any unhealthy legacy observation
after that point transitions routing back to hosted automatically; a
governed legacy route is never a permanent, unmonitored destination.
