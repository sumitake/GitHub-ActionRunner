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

## One-shot admin client

The controller binary provides the operator-only command:

```sh
<controller_binary> worker-canary \
  --config=<overlay_path> --command-file=<private_command_path>
```

It reads the overlay's Worker origin, fleet ID, HMAC file secret, and timing
limits. Both files must pass the controller's root-owned, mode `0600`,
single-link regular-file checks. The overlay must describe the invoking
platform and euid. The command does not open controller state, acquire the
fence, establish a session, or change the local acquisition mode. Worker
authority and an established controller session are prerequisites for start.

The command file is the exact canonical JSON accepted by
`worker/src/protocol/admin.ts`, with no trailing newline. It must name the
overlay's fleet. The client accepts only `portable-canary-start` and
`portable-canary-stop`. It sends one signed request without retries and
prints only the authenticated receipt. It refuses stale commands, unknown
fields, malformed bindings, and responses whose identity or outcome differs.
No secret belongs in a command file or receipt.

For start, the operator-approved fields file supplies `kind`, `fleetId`,
`repositoryAlias`, `workflow`, the exact 40-character `revision`, `scaleSet`,
`configurationRevision`, `policyDigest`, `fenceGeneration`, `leaseGeneration`,
and `observeUntil`. The policy and configuration values must match the
intended canary controller snapshot. `fenceGeneration` is the manifest's
post-handover N+1; `leaseGeneration` comes from the established authenticated
Worker session and is independent of the fence. `observeUntil` is a UTC
timestamp with milliseconds, after the command timestamp and at most one day
later. For stop, the approved fields file contains only `kind` and `fleetId`.

On the QTS target, the operator can prepare a fresh private command and send
it in the same step. Replace the placeholders before running:

```sh
python3 - <approved_fields_path> <private_command_path> <<'PY'
import datetime
import json
import os
import secrets
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    command = json.load(source)
command["protocolVersion"] = 1
command["timestamp"] = datetime.datetime.now(
    datetime.timezone.utc
).isoformat(timespec="milliseconds").replace("+00:00", "Z")
command["nonce"] = secrets.token_hex(32)
document = json.dumps(command, sort_keys=True, separators=(",", ":"))
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as destination:
    destination.write(document)
    destination.flush()
    os.fsync(destination.fileno())
PY
<controller_binary> worker-canary \
  --config=<overlay_path> --command-file=<private_command_path>
```

Journal the command identity and verified receipt privately. Keep the HMAC
key out of shell arguments and recorded output. Do not resend the same file.
A verified `draining` stop receipt calls for a later stop with a fresh command
file after lease expiry plus the safety margin. A transport failure is
ambiguous: inspect the private Worker state before deciding another action.
This client is a runbook prerequisite; it does not itself dispatch a canary.
