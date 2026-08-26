# Runner release

This source-ready runbook defines how Portable GHAR observes, qualifies, and
responds to a new official GitHub Actions runner release. It refines the
[production lifecycle](production-lifecycle.md), assumes the component model in
the [architecture overview](../architecture/overview.md), and preserves the
[trust boundaries](../security/trust-boundaries.md).

The goal is uninterrupted hosted availability across forced runner-version
bumps without relying on in-place binary self-update. This page provides no
live target commands, numeric resource defaults, private paths, credentials,
or authority to modify a host.

## Automatic release path

The normal path is an authenticated, scheduled observation of the fixed
official `actions/runner` release source from GitHub-hosted infrastructure.
The observer records the exact `vMAJOR.MINOR.PATCH` version, tag-ref commit,
source commit, Linux x64 asset name and size, asset `sha256:` digest,
publication time, and closed observation-evidence digest.

Version comparison is numeric and overflow-checked. It rejects leading zeroes,
prerelease/build extensions, missing components, permissive semver aliases,
and same-version identity drift. A caller cannot choose a production origin,
asset, platform, version, or digest.

When the official tuple is newer than the selected tuple, the release workflow
builds, signs, attests, qualifies, and publishes one immutable candidate. It
does not alter the live selector, drain a fleet, or change routing. GitHub
hosted routing and the Worker-owned hold remain the continuity path throughout
qualification and replacement.

A break-glass observation is separately approved and uses the same fixed
official source, immutable manifests, qualification gates, and external
maintenance directives. It is not an operator-edited tag, file, URL, digest,
or bypass around verification.

## Immutable candidate qualification

The candidate identity binds the release-evidence digest,
runner-release-manifest digest, runtime-manifest digest, image digest,
attestation digest, and provenance digest. The target independently verifies
that tuple and retains the selected and rollback identities unchanged.

Qualification must prove:

- the exact official source and Linux x64 asset tuple;
- a prebuilt, signed, attested image or a separately approved build whose
  output is independently verified;
- exactly one runner `bin` and one `externals` payload, with no old-version
  siblings and no retained `_work/_update` staging;
- disabled in-place runner update and matching scale-set policy;
- exact `Runner.Listener --version` output before selection and again after
  selection;
- complete runtime, archive, trust, seccomp, egress, conntrack, storage, and
  log-policy manifest equality;
- supported host-profile probes and whole-container reclamation evidence; and
- an immutable rollback identity that remains runnable under the current
  official requirement.

Permanent authenticity, identity, version, platform, smoke, policy, host, or
reclamation failure publishes `candidate-rejected` for that exact candidate.
The candidate remains unselected, the selected fleet is not mutated, and the
retained rollback anchor is not deleted. Transient observation or build
unavailability remains retriable without being relabeled as rejection.

## Maintenance response phases

Release status is evidence and is published at least once. Maintenance
authority is a separate authenticated response from the Worker control plane.
The six ordered response phases are:

1. `wait-hosted`: keep acquisition disabled and make no upgrade effect while
   hosted routing, hold, identity, expiry, request, or phase proof is missing;
2. `stage-permitted`: stage only the exact observed candidate while selection,
   routing, and capacity remain unchanged;
3. `replace-permitted`: after qualification, hosted confirmation, drain, and
   quiescence, journal the bounded replacement and selection sequence;
4. `canary-permitted`: run only the exact selected candidate under
   canary-capacity policy after post-selection compatibility passes;
5. `enable-permitted`: enter full capacity only after the governed canary is
   observed successful and every policy binding is fresh; and
6. `complete`: close the exact transition only after enabled-policy and
   acquisition-authority-generation read-back match the directive.

`candidate-rejected` is a runner-release status, not a seventh maintenance
phase. It cannot authorize staging, replacement, selection, canary, enable, or
cleanup.

Every phase binds the Worker enrollment epoch, session, request control
sequence, observed release, selected and candidate manifests, configuration
revision, transition epoch, policy digests, acquisition-authority generation,
and expiry.
One reconciliation call performs at most one adjacent external phase.

## Retry and operator hold

Every effect has a durable applying intent, an exact read-back, and a proven
phase. A restart republishes the durable release status before a newer
observation and reconciles the current phase rather than replaying the whole
upgrade.

When an effect is absent, the controller may apply only the exact
journal-bound effect. When present and equal, it records the proven phase
without duplicating the effect. Missing, stale, contradictory, partially
written, or wrong-identity evidence is ambiguous: acquisition stays disabled,
hosted routing remains in place, and no later phase executes.

An operator hold has precedence over all maintenance responses. Observation
and bounded status publication may continue during a hold, but build
acceptance, staging, qualification, drain, selection, canary, enable,
completion, and cleanup wait. Clearing a hold does not revive an expired
directive; the controller requires a fresh response.

Retries are idempotent for one exact request and phase. Reusing a request
across a different release, candidate, selection, policy, configuration,
transition, or acquisition-authority generation is rejected rather than
normalized.

## Forced-version-bump continuity

A GitHub-forced runner-version bump must not make the runner path disappear.
Consumer routing remains GitHub-hosted while Portable GHAR automatically
observes, builds, qualifies, drains, selects, canaries, and enables the new
immutable version under fresh authority.

The selected runner image has in-place update disabled. A stale selected image
therefore fails closed for new local acquisition instead of copying a second
runner version into `/runner`. The release workflow prepares the replacement
outside the serving container and proves its exact version before selection.
No daily or periodic binary auto-update window is allowed to remove both the
selected and hosted execution paths.

If qualification, control-plane authority, drain, or canary does not complete,
the system stays hosted and disabled. A new candidate never causes a
best-effort local update or an incompatible rollback. The eventual
forced-version-bump drill must prove the full sequence without manual repair.

## Reclamation and bounded retention

An ephemeral job is reclaimed by destroying its whole container after the
terminal post-job proof. Never delete old `bin`, `externals`, `_work`, or
`_work/_update` directories from a serving runner. The durable design prevents
duplicate payloads by selecting only a prequalified single-version image and
by discarding whole stopped containers.

Keep a bounded immutable set: the selected image, one retained rollback
identity, and at most one qualifying or qualified candidate. Failed build
scratch, stopped job containers, and superseded unselected candidates become
eligible for separately journaled cleanup only after no-use proof and the
approved retention window.

The repository intentionally supplies no tmpfs size, memory-cgroup cap,
concurrency ceiling, disk quota, retention age, or rebuild cadence. Those
values must be sized together against the measured workload, host memory, and
operator-approved headroom. If disk-backed work is ever approved, it must be
bounded and ephemeral and may not grow on persistent NAS storage.

## Unattended-operation dependencies

This source package is not sufficient for unattended release operation.
Before enabling automation:

- Phase 3 must supply the authenticated Worker maintenance client and exact
  external directive state machine;
- Task 14 must supply the official release workflow, signed attestations,
  immutable candidate artifacts, and production publication path;
- a supported Linux/Docker target must execute the opt-in Task 12 chaos suite;
- the operator must approve tmpfs, memory-cgroup, concurrency, retention, and
  rebuild-cadence values;
- the health export and one-way observability path must pass the
  [Grafana and InfluxDB activation gate](production-lifecycle.md#grafana-and-influxdb-activation-gate);
  and
- a forced-version-bump exercise must prove hosted continuity, qualification,
  drain, selection, canary, enable, rollback preservation, and reclamation.

Until every dependency passes, automatic observation may be source-ready, but
selection and local acquisition remain disabled.

## Execution packet boundary

No live-host action is authorized by this document. A separately approved
execution packet must bind the target host, official release tuple, candidate,
selected and rollback identities, manifests and attestations, initial hosted
state, Worker directives, journal, policy, fence, exact build or install
method, read-back commands, resource settings, retention policy, rollback, and
stop conditions.

The packet stops before mutation on any mismatched, missing, stale, ambiguous,
or expired observation. Build, stage, drain, selector change, controller
restart, image cleanup, canary, enable, rollback, and route change remain
separate operator gates.
