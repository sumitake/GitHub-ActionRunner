# Controller recovery

This source-ready runbook defines how an operator classifies and recovers an
interrupted Portable GHAR controller operation. It refines the
[production lifecycle](production-lifecycle.md), assumes the component model in
the [architecture overview](../architecture/overview.md), and preserves the
[trust boundaries](../security/trust-boundaries.md).

This page does not authorize a host mutation. It deliberately omits private
paths, target values, credentials, commands that change state, resource sizes,
and timing values. Those details belong in a separately approved execution
packet after the operator accepts its exact initial state and stop conditions.

## Initial read-back

Begin with read-only evidence. Do not restart a process, remove a file, repair
a tag, or release a hold to make the evidence easier to interpret. Capture:

- the installed controller's canonical `status --json` response, including its
  exact build, policy, capacity, degraded state, and last terminal result;
- selected, candidate, and retained rollback version, manifest, and image
  identities, with candidate absence represented explicitly;
- the operation journal's identifier, phase, generation, immutable request
  bindings, applying intent, receipts, and recorded postconditions;
- the fleet fence header and holders from the canonical file-backed fence;
- controller and watchdog install identity, loaded configuration, process
  identity, executable identity, and separately observed responsiveness;
- controller policy epoch and digest, Worker enrollment epoch, private
  configuration revision, active capacity, and all in-flight component counts;
- GitHub-hosted route and hold read-back for every repository in scope; and
- the check-run annotations API for a failed job when the run log is absent.

Persisted control-plane metadata and current process executability are
different observations. Neither may be substituted for the other. An
installed executable is not responsive merely because a selector or service
definition names it, and an answering process does not prove its persisted
journal or fence state.

Record closed diagnostic classes and byte-presence facts where needed, but do
not copy credentials, tokens, provider output, private paths, or unbounded logs
into the recovery bundle.

## Ambiguity and disabled acquisition

Classify each expected effect as exactly one of:

- **absent:** the authoritative read-back proves the effect did not occur;
- **present and equal:** the read-back proves the exact journal-bound effect
  and immutable identity; or
- **ambiguous:** evidence is missing, stale, contradictory, partially written,
  outside the closed schema, or bound to another identity.

Recovery begins and remains with acquisition disabled. An ambiguous result
never becomes absent through retry, age, log silence, a missing wrapper
process, or operator intuition. Preserve the hosted hold and stop before any
later phase until the ambiguity is resolved by authoritative read-back or an
approved compensation path.

The fleet generation must never decrement. Never restore a raw fence snapshot,
edit the fence header or holders directly, delete a lease to force progress,
or create a second active fleet. A release that may have succeeded cannot be
followed by a blind destroy; first prove the exact generation, holder, policy
epoch, and component identity.

## Transient disabled recovery

When no complete portable authority exists, or a legacy controller state
cannot prove the current Worker maintenance tuple, normalize the local policy
through the canonical admin boundary to `disabled` at a new monotonic epoch,
then read it back. This is a transient fail-closed recovery primitive, not a
resident observer outcome or deployment phase. Do not inherit capacity,
acquisition mode, a signed acquisition lease, or a maintenance directive from
legacy files.

Transient disabled recovery may publish bounded health and runner-release
status, reconcile journals, inspect the fleet fence, and request new external
authority. It may not acquire a job, create or release a listener, select an
image, alter routing, or infer a hosted-hold release. An unavailable Worker
client therefore leaves the system hosted and disabled rather than activating
a local fallback. The bounded RhoNAS canary does not install this recovery
composition as a permanent process.

The observability requirements in the
[Grafana and InfluxDB activation gate](production-lifecycle.md#grafana-and-influxdb-activation-gate)
remain evidence-only. A dashboard point cannot repair or grant authority, and
stale telemetry is no-data rather than last-known-good health.

## Forward recovery and compensation

Reopen the durable journal and validate its canonical encoding, generation,
immutable bindings, phase, receipt chain, and stored release-status
observation. Republish that durable release status at least once before a new
effect.

For the current applying phase:

1. read back the exact target effect;
2. when absent, apply only the journal-bound effect and persist its receipt;
3. when present and equal, persist the adjacent proven phase without applying
   the effect again;
4. when ambiguous, record no later effect and stay disabled under the hosted
   hold; and
5. after a proven phase, allow at most the next adjacent phase on a fresh
   reconciliation request and fresh external directive.

Selection has one narrow crash classification: a selection-applying journal
may observe the exact qualified candidate selected while retaining the exact
journal-bound rollback identity. No other unexpected selection is accepted.

Forward resume is preferred. Compensation is permitted only when the journal
names a closed compensation transition whose preconditions, target identity,
and postcondition can all be read back. Compensation advances its own
monotonic journal phases; it does not rewrite history, restore a raw fence,
decrement a generation, delete evidence, or mutate files inside a serving
runner.

## Hosted confirmation and rollback

Before any recovery mutation, positively confirm that all configured
repositories remain on GitHub-hosted routing and that the Worker-owned
maintenance hold is current for the exact enrollment epoch, session,
configuration revision, and transition. Missing, expired, stale, or
wrong-scope confirmation is a stop condition.

Rollback means restoring the retained prior controller and control-plane
identity in disabled mode through the same journaled, read-back-gated process.
It does not mean downgrading to an incompatible runner binary, reinstalling a
stale self-updating image, or returning consumer routing to a self-hosted fleet
before a new canary.

The retained image must first pass its own manifest, image, version,
configuration, host-profile, and `Runner.Listener --version` compatibility
checks against the current upstream requirement. If it is an incompatible
runner, preserve it as evidence and keep hosted routing; do not run it merely
because it was previously selected.

After rollback selection, prove the exact rollback identity, zero acquisition,
zero listener state, monotonic fence generation, and disabled policy. A later
canary and enable transition still require new external directives and the
complete production lifecycle gates.

## Retained state and evidence

Retain the selected, candidate, rollback, journal, receipt, fence, policy,
hosted-confirmation, and compatibility evidence required by the approved
recovery window. Retention is bounded by count and age in the private
deployment policy, but this source runbook intentionally supplies no numeric
defaults.

Whole stopped containers and immutable images are the units of cleanup.
Never reclaim space by deleting runner payloads, `_work`, update staging, or
logs from a serving container. A failed or ambiguous candidate remains
unselected and cannot displace the known-good rollback identity.

Evidence cleanup is a separate journaled operation after terminal proof and
retention eligibility. It must preserve the active selected identity, the
retained rollback anchor, the latest terminal operation, the current fence
generation, and the closed audit record.

## Execution packet boundary

A separately approved execution packet must bind the target host, exact
selected/candidate/rollback identities, initial `status --json`, journal and
fence observations, hosted confirmation, expected policy and capacity,
permitted recovery or compensation phase, exact read-only and mutation
commands, postconditions, rollback, timeouts, numeric resource settings, and
stop conditions.

The packet stops before mutation if any initial value differs from its reviewed
tuple. Controller or watchdog restart, selector change, policy mutation, fence
handoff, image selection, route change, deletion, rollback, and activation are
independent operator gates. No instruction in this source document grants any
of them.
