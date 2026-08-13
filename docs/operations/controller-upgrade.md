# Controller upgrade

This source-ready runbook defines the evidence and ordering required to replace
a Portable GHAR controller or runtime bundle. It refines the
[production lifecycle](production-lifecycle.md), assumes the component model in
the [architecture overview](../architecture/overview.md), and preserves the
[trust boundaries](../security/trust-boundaries.md).

The repository does not authorize a live host change. Every path, identity,
private setting, command, timeout, size, concurrency value, and target
observation belongs in a separately approved execution packet. Until that
packet is approved, this page is a procedure contract rather than a command
sheet.

## Authority and immutable identities

Record one pre-change evidence bundle before requesting any maintenance
authority:

- selected version, runtime-manifest digest, and image digest;
- candidate version, release-evidence digest, runner-release-manifest digest,
  runtime-manifest digest, image digest, attestation digest, and provenance
  digest, or an explicit candidate-absent observation;
- retained rollback version, manifest digest, and image digest;
- fleet-generation fence header, holder set, controller policy epoch and
  digest, private configuration revision, and Worker enrollment epoch;
- current operation-journal identity and phase, if one exists; and
- GitHub-hosted routing and hold read-back for every repository in scope.

Selected, candidate, and rollback are three immutable identities, not mutable
tags. A candidate may not alias either selected or rollback bytes. The
retained rollback identity remains available until the replacement passes its
governed canary and the separately approved retention gate. Nothing in this
runbook authorizes deleting it.

The release status publisher is at-least-once. A restarted controller
republishes the same observation sequence idempotently before it advances a
journal or performs another effect.

## Hosted hold and directive sequence

Maintenance remains externally governed. A local observation is evidence, not
permission. The expected directive sequence is:

1. `wait-hosted` while routing or hold proof is missing, stale, ambiguous, or
   intentionally held;
2. `stage-permitted` for the exact observed candidate and request identity;
3. `replace-permitted` only after candidate qualification and fresh hosted,
   drain, zero-job, and acquisition-authority quiescence/expiry evidence;
4. `canary-permitted` only after the exact candidate is selected, starts
   disabled, and passes post-selection validation;
5. `enable-permitted` only after a Worker-observed canary succeeds; and
6. `complete` only after an enabled-policy read-back matches the exact
   transition and acquisition-authority generation.

Every directive binds the enrollment epoch, session, request control sequence,
selected and candidate manifest digests, transition epoch,
acquisition-authority generation, configuration revision, policy digests, and
server expiry. Missing,
unavailable, expired, repeated, future, wrong-tuple, or wrong-phase authority
causes zero mutation and returns to `wait-hosted`.

An operator hold has precedence over every upgrade directive. Release
observation and status publication may continue while held, but staging,
qualification, drain, selection, canary, and enable effects may not.

## Candidate build and qualification

Prefer a prebuilt, signed, attested image produced by the governed release
workflow. The target independently verifies every manifest, digest, platform,
license, SBOM, provenance subject, and immutable image identity before it
accepts the candidate.

QNAP Container Station cannot run `docker build` as the non-admin account in
the current host design because its wrapper forces an admin-only home. A QTS
build therefore requires the separately approved admin execution path, or the
approved run-plus-exec-plus-commit recovery path from an already retained
rollback image. That exception applies only to the build step. It does not
authorize controller execution as admin or weaken the image checks. A
governed prebuilt image is the normal path.

Qualification must positively prove:

- the official `actions/runner` tag, source commit, Linux x64 asset name,
  size, and `sha256:` digest;
- the image contains exactly one `bin` and one `externals` runner payload,
  with no old-version siblings and no `_work/_update` staging;
- in-place update is disabled and the scale-set configuration agrees;
- `Runner.Listener --version` exactly equals the qualified release before the
  candidate can become selected;
- runtime, archive, trust-bundle, seccomp, policy, conntrack-budget,
  storage-budget, and log-policy digests all match the candidate manifest;
- the target host profile and whole-container reclamation probes pass; and
- the selected and retained rollback identities remain unchanged during
  staging and qualification.

A failed authenticity, identity, version, platform, smoke, policy, host, or
reclamation check records `candidate-rejected` for that exact tuple. It
neither deletes the selected or rollback image nor selects a partial
candidate.

## Drain and quiescence

After `replace-permitted`, acquisition stays disabled. Apply the
operator-selected wait-or-cancel policy and require a fresh read-back showing
zero listeners, runners, adapters, held or running brokers, helpers,
verifiers, per-job socket directories, active dials, and pending effects.
Retained permit ledgers remain retained through their approved window; they
are not treated as active work or reset to make the proof pass.

During migration from the legacy runner fleet, drain only an idle registered
container. Idle means the container has no `Runner.Worker` process at the
read-back instant. Disable registration before removing that old-image
container so it cannot accept one more job. A running worker is never
reclassified as idle from age, logs, or a missing local wrapper status.

If any effect outcome is ambiguous, retain the hosted hold, keep acquisition
disabled, and resume through the durable journal. Never infer quiescence from
the absence of a run log; the July 2026 incident demonstrated that a failing
job may expose its real error only through check-run annotations.

## Journaled selection and restart recovery

Every local effect has an `applying` phase followed by a proven phase. The
operation journal is keyed by one idempotent operation ID and binds the exact
release, candidate, selected, rollback, configuration, policy, and fence
identities.

On restart:

1. reopen and validate the journal, reservation, receipt chain, and current
   live selection;
2. republish the durable release status before observing or applying anything
   newer;
3. read the target effect back;
4. if absent, apply the exact journal-bound effect;
5. if present and equal, persist the proven phase without applying it again;
6. if ambiguous, changed, or unreadable, make no later effect and remain
   hosted with acquisition disabled; and
7. resume only the next adjacent phase.

Selection is the one permitted crash boundary where an `applying` journal may
read back the exact qualified candidate as current while the journal still
names the prior selected identity. That classification is accepted only for
the exact candidate and exact retained rollback binding. Any other selection
change is an integrity failure.

Neither restart nor compensation restores a raw fence snapshot, decrements a
generation, rewrites the selected tag, or deletes a running container's
files. Compensation advances through a separately journaled, closed path.

## Selection, canary, and enable gates

Selection is an atomic exact-digest change after quiescence and replacement
validation. Preserve rollback bytes first, select the qualified candidate,
and positively read back the selected manifest, image, version, fence
generation, active fleet, disabled policy, and zero-listener state.

Run `Runner.Listener --version` and the complete compatibility probe again
against the selected image. Then require a fresh `canary-permitted` directive
before entering canary-only mode. The canary must obtain fresh acquisition
authority and must be observed running and finishing by the governed control
plane. Its complete post-job evidence must show whole-container, tmpfs,
worktree, update-staging, process, namespace, socket, and temporary-file
reclamation.

Only a fresh `enable-permitted` directive may enter the full-capacity policy.
The jointly fresh GitHub, controller-health, signed-heartbeat, and dashboard
tuple defined in the
[Grafana and InfluxDB activation gate](production-lifecycle.md#grafana-and-influxdb-activation-gate)
is cutover evidence. GitHub remains authoritative for workload identity and
queue state; the one-way InfluxDB adapter remains read-only evidence and has
no routing authority.

## Execution packet boundary

No live-host commands may be derived from this page alone. A separately
approved execution packet must bind the target host, exact binary and image
digests, immutable manifests, private paths, expected current state, rollback
identity, hosted confirmation, directive identities, drain policy, all
numeric resource settings, commands, read-back assertions, and stop
conditions.

The packet must stop before any mutation if its initial read-back differs from
the reviewed tuple. Build, install, selector change, controller or watchdog
restart, fleet handoff, route change, drain, deletion, and rollback each
remain explicit operator gates.
