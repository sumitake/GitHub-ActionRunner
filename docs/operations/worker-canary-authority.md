# Worker canary authority

The deployed Worker is address-only: it answers the Cron receipt and the
signed address-status query and rejects session, heartbeat, and admin
requests. This page describes the opt-in lease authority one portable canary
job needs. Turning it on is a redeploy, and a redeploy needs a separate,
explicit operator go. Merging this code changes nothing in production.

## Turning authority on

The Worker serves session, heartbeat, and admin requests only when its
deployment sets `WORKER_AUTHORITY` to exactly `enabled`. The deployment
renderer (`scripts/render-worker-deployment.mjs`) emits that variable, and the
four timing variables the lease path needs, only from an optional `authority`
block in the private descriptor:

```json
"authority": {
  "leaseDurationMs": 120000,
  "archiveEvidenceMaxAgeMs": 600000,
  "selectorEvidenceMaxAgeMs": 600000,
  "hostedTransitionSafetyMarginMs": 30000
}
```

Without the block the rendered configuration is byte-for-byte the
address-only one. `leaseDurationMs` must equal the controller overlay's
`worker.lease_duration`, or every lease is rejected. The controller signs with
the existing `HMAC_KEY`.

Requests for a fleet ID outside `FLEET_IDS` are rejected before any Durable
Object is addressed.

## Choosing the canary fleet

Use one fleet from the existing inventory and record the choice in the canary
runbook. The signed address-status query answers only while a fleet's state is
inert. A successful session makes it non-inert, so the canary fleet's
address-status fails closed and the addressability verifier reports it red.
A request with a bad or missing signature, and a rejected heartbeat or admin
request, writes nothing, so it leaves a fleet inert. A correctly signed
session request that is rejected (wrong binding, stale timestamp, or a
replayed nonce) writes one `session-rejected-*` audit row and nothing else;
that row makes the fleet non-inert, so its address-status reports red. Treat a
red result as expected for the canary fleet and as a reason to read the audit
rows for any other.

## Canary commands

Both are signed admin commands (`POST /v1/admin/command`).

- `portable-canary-start` moves a fleet that has a session and no repository
  records from `UNINITIALIZED` or `HOSTED` into `PORTABLE_CANARY`. It names the
  scale set, the canary workflow and revision, and the controller's fence
  generation, policy digest, and configuration revision. The Worker then
  issues canary-only, capacity-1 leases to the portable holder whose values
  match. It never promotes the fleet past `PORTABLE_CANARY`.
- `portable-canary-stop` moves `PORTABLE_CANARY` to `DRAINING_TO_HOSTED` and
  answers `draining`. Repeat it after the last issued lease has expired plus
  the safety margin; it then answers `hosted`.

For the canary the Worker holds no repository records, so it writes no
repository variables and needs no GitHub credential. The canary workflow
targets the scale set's label directly.
