# Operations

This runbook describes the host watchdog's authority, what incident
evidence a Portable GHAR deployment is expected to preserve, and how long
that evidence and any rollback material is retained. It assumes the
components in [Architecture overview](../architecture/overview.md) and
the boundaries in [Trust boundaries](../security/trust-boundaries.md).

Phase 2 source includes the host watchdog and its host-integration seams.
They remain pre-deployment pending the deferred operational and
live-activation gates, so this page is not a claim that any watchdog
behavior below is live against a deployed host today.

## Assembling the private overlay

First prepare the host runtime manifest for the next handover generation,
using the [D2 preparation steps](live-acquisition-operator-steps.md#bind-the-handover-generation-before-preparing-the-input).
`assemble-runtime-manifest` serializes an approved identity template; release
publication emits a different document and does not choose this generation.

The host overlay (`controller-runtime.json`) must name the exact release it
deploys. Do not type release identities into it by hand. Write a template
with every operator and host value, leave the release-derived fields empty,
and bind it to the release's `runtime-manifest.json`:

```sh
portable-ghar assemble-private-overlay \
  --template "$PORTABLE_GHAR_PRIVATE_OVERLAY/template.json" \
  --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/runtime-manifest.json" \
  --output "$PORTABLE_GHAR_PRIVATE_OVERLAY/controller-runtime.json"
```

The command copies the manifest path and digest, the policy manifest digest,
and the five image IDs (`sha256:` plus each image's config digest) from the
manifest. A template field that is already set must equal the derived value.
The template is read through the same private-tree checks as the overlay, so
it belongs in the private root. The overlay is staged as a mode `0600` file
beside the output and read back through the same loader `deploy` uses. Only
a staged file that passes replaces the output, so a failure leaves any
existing overlay unchanged. The receipt prints only the overlay revision and
the manifest digest. Re-running it with the same inputs produces the same
bytes.

The overlay records the `--manifest` path as given. The control host and the
target both open that path, so the manifest must sit at the same absolute
path on each.

Three sections are optional and only an acquiring controller reads them:
`worker` (the failover Worker's bare `https://` origin with no port, fleet ID, HMAC secret name, and lease
timings, which must match the Worker's deployment settings), `github`
(response-size and timeout bounds for scale-set calls), and `jail` (the
numeric `uid:gid` container users, a seccomp profile under `seccomp_root`,
container log limits, and the dial authority's block size, client limit, and
timeout). When `github` is present, every repository's `credential_name` must
name exactly one file secret. In `jail`, the adapter-broker and verifier users
are never root; the runner is unprivileged on `strict-linux-v1` and `0:0` on
`qts-capless-root`. The adapter, broker, and runner logs of every slot, at the
jail's rotation limits, must fit the remaining `log_bounds` budget at
`max_capacity`. The disabled observer ignores all three.

The command does not observe the target host. Host identity, storage, and
other live observations stay the operator's inputs in the template.

## Running the acquiring controller

`portable-ghar-controller run-acquisition --config <overlay> --database <db>`
runs the acquiring controller. It takes the same flags as `run`, needs root,
and takes the same ownership lock, so `run` and `run-acquisition` never run
against one database at once. The systemd unit still runs `run`.

It refuses to start unless:

- the overlay has the `worker`, `github`, and `jail` sections;
- every repository's `slot_resources` equals `resources.slot_resources`, the
  vector each job's containers are sized from, and one complete slot fits
  the admission ceiling;
- the fence names the portable fleet at the manifest's generation. It does
  not take over a legacy fence; hand the fence over first;
- the decision graph at `policy_path`, a root-owned mode `0600` file, is the
  graph the overlay names in `compiled_graph_digest`;
- the Worker HMAC secret is a root-owned mode `0600` file holding the
  lowercase hex the Worker binds;
- the Worker `termination_tail` exceeds the fixed two-second lease overrun
  slice and stays shorter than `lease_duration` less `shortening_margin`, so
  permits keep usable slack.

When it refuses, the error names the startup step that failed.

A permit stops granting `termination_tail` before its local lease deadline.
If any permit is still open two seconds before that deadline, the process
logs the operation and exits at once with a non-zero status, so no
acquisition effect outlives the Worker lease, whatever path shutdown takes.
To let the controller reach its own fatal state first, set the tail above
five `transition_join_timeout`s plus two `durable_finish_timeout`s plus the
two-second slice.

At startup it takes one portable fence guard and holds it for the whole run. Every later acquisition and heartbeat uses that guard, since the fence records one holder per process. It then
releases any dial ledger and removes any empty slot directory that no
recoverable assignment references, and opens one GitHub message session per
repository. On a new database it first records the disabled policy, so the
admission broker has an epoch to start from.

The service starts disabled. It sends a Worker heartbeat every
reconciliation cycle, starting while still disabled, so the first one is the
Worker check. A failed heartbeat fails the cycle and stops the run, so enable
the Worker's lease authority before starting this command. Enabling takes an operator
transition through the usual `acquisition` command, and the conformance gate
refuses every active mode until a report exists at
`<state_root>/conformance-report.json`: a root-owned mode `0600` file. A report
whose cases 1-14 passed and whose case 15 is pending allows `canary-only`
only; `enabled` needs every case to pass. Without a report the gate refuses;
a report that exists but cannot be read or parsed, or grants nothing, stops
startup. The admin and
health sockets are the same as `run`; health reports ready only after
startup recovery.

A signal stops it cleanly: the service records a disabled epoch and closes
its GitHub sessions on the way out, even when the signal arrives before startup finishes. A persisted fatal state, a lost fence guard, a database ownership lock that no longer validates (checked every reconciliation cadence), a local server failure, or a lease overrun also stops it, with a non-zero exit. If the service cannot shut down cleanly, for example because its loops miss the join deadline, the process exits without releasing its store, fence guard, or ownership lock, and the kernel drops the locks with the process.

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
