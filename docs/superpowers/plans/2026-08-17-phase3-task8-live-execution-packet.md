# Phase 3 Task 8 live execution packet

**Status:** draft for operator review. **Do not execute.** No Cloudflare,
GitHub routing, overlay, QTS, systemd, Grafana, Influx, or host mutation is
authorized by this document.

**Source head:** `6429b16edfcfa429f294a33b8d1262c11a1dcf98`
(`Phase 3 source: pre-deployment build (Tasks 0-7) (#29)`).

**Goal:** Record the exact gates Task 8 still needs, and the first live
sequence if those gates later pass. This packet is not a deploy order.

## What is already true

- Phase 3 Tasks 0–7 source is on `main`.
- One Worker, one `FLEET` Durable Object, one Cron parser, six route states,
  one signed lease, one local lifecycle engine.
- Production fetch forwards to `FLEET.getByName(fleetId)` or returns 401.
- Snapshot save uses `storage.transactionSync`, not SQL `BEGIN`.
- Production controller remains the disabled observer.
- Cron does not claim due work unless an execute client is injected.

## Prerequisites

| Gate | State |
| --- | --- |
| Tasks 0–7 merged | **met** — `6429b16` |
| Operator review of this packet | **open** — this document |
| Linux/Docker host gates | **deferred** — not run |
| Reproducible rebuild / comparator | **deferred** |
| Forced official runner-version-bump drill | **deferred** |
| Operator numeric tuple (tmpfs, memory, swap, concurrency, cadence) | **unset** — source must fail closed |
| Cloudflare account, Worker name, HMAC, inventory, Cron bounds | **unset** |
| Private overlay with real targets | **not generated** |
| GitHub App / routing mutation rights | **not used** |

Task 8 live steps stay blocked until every row above is met or the operator
explicitly waives a deferred gate in writing.

## Residual source honesty

These are not silent defects to paper over during deploy:

- The production process must stay a disabled observer until a later enrollment
  slice attaches `CachedLeasePermitProvider` to a live Worker session.
- Default Cron stays fail-closed without an injected GitHub execute client.
- Missing HMAC, fleet inventory, or duration bounds stay 401 / no-op.

Do not “complete” those by pointing production at live Cloudflare from this
packet.

## If later approved: first live sequence

Execute only after this packet is approved and the table above is satisfied.
Stop and report rather than improvising.

1. Recapture live identities and rollback artifacts. Verify target and account
   immediately before each mutation phase.
2. Deploy the controller force-disabled under the legacy fence. Prove zero
   acquisition and host conformance without changing consumer routing.
3. Deploy Worker / Durable Object / Cron privately. Establish session and
   heartbeat with an explicit no-lease result while hosted hold is active.
4. Prove Cron addresses every configured fleet object from the exact private
   inventory.
5. Reconcile hosted repositories and clear queue risk before any canary.

Stop immediately on target mismatch, unbounded call, dual holder, false
success, missing read-back, resource leak, or architecture divergence.

## What this packet forbids

- `wrangler deploy` or any Cloudflare write
- GitHub routing variable mutation
- Overlay generation with real hosts or secrets
- QTS, systemd, Grafana, Influx, or runner mutation
- Merging a later deploy PR without a new exact-head review

## Operator decisions needed

1. Approve or reject this packet as the Task 8 execution identity.
2. Supply or refuse the numeric tuple.
3. Name the Cloudflare / GitHub / host targets, or keep deploy deferred.
4. Confirm Linux/Docker and release gates, or keep them deferred.

Until those decisions land, the next honest work is more source or more
deferred-gate evidence, not a live cutover.
