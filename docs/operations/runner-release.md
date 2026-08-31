# Runner release

This runbook defines how Portable GHAR produces and qualifies its runner
payload from an exact official `actions/runner` source revision. It refines the
[production lifecycle](production-lifecycle.md), assumes the component model in
the [architecture overview](../architecture/overview.md), and preserves the
[trust boundaries](../security/trust-boundaries.md).

The upstream prebuilt Linux runner archive is not a release input. The prior
daily upstream-release heartbeat is paused and must not be recreated as a
release or deployment dependency. This page supplies no live target commands,
private paths, credentials, or authority to modify a host.

## Exact source release path

One closed release manifest binds an exact official runner tag, peeled source
commit, source tree, and source epoch. It also binds the exact .NET SDK archive
and digest, expected SDK and runtime versions, ordered NuGet lock files, the
runner command-settings source digest, and every standard and Alpine Node
external archive and digest required by the product layout.

Each release-build leg independently:

1. clones only the fixed official `actions/runner` origin at the bound tag;
2. proves the peeled commit, tree, clean checkout, command-settings digest, and
   source epoch before building;
3. verifies every tool and external archive digest before safe extraction;
4. restores the exact ordered lock set with an isolated home, NuGet package
   store, HTTP cache, and plugin cache;
5. builds deterministically with the pinned SDK and latest fixed runtime patch
   selected by that SDK;
6. proves a nonempty, canonical Linux-x64 runtime-pack graph at the
   manifest-bound runtime version, full Node external layouts, listener
   version, single payload, no update residue, normalized modes, and immutable
   runtime lock; and
7. emits a deterministic payload archive and evidence bound to the closed
   source-release manifest.

The two build legs share no writable cache or workspace. Their payload bytes,
normalized trees, runtime locks, OCI graph, SBOMs, checksums, and provenance
must compare equal before publication. A mismatch is a release stop, not a
reason to normalize or patch one leg after the fact.

The source release is deliberately operator-advanced. A newer upstream tag is
not automatically selected, built, or released. Advancing any source or
toolchain pin requires a reviewed manifest and lock update followed by the same
two-leg qualification. Never substitute the upstream prebuilt runner archive,
patch Microsoft's signed archive, fabricate VEX, suppress a fixed HIGH or
CRITICAL finding, or weaken the scan policy.

## Immutable candidate qualification

The repository candidate workflow is an explicit trusted-actor
`workflow_dispatch` against one exact branch commit. It consumes the reviewed
schema-2 source-release object already in `release/manifest.json`; it has no
schedule or repository-dispatch trigger and never invokes the legacy archive
observer. Candidate and product rehearsal both require that complete object to
equal the checked-in baseline exactly; even a semantically newer out-of-band
object is rejected. Advancing the runner therefore requires a reviewed exact-
head manifest change first. Candidate publication proves payload identity and
qualification only and grants no routing or acquisition authority.

The candidate identity binds the source-release evidence digest, runner
payload digest and tree, runtime-manifest digest, image digest, SBOM digest,
attestation digest, and provenance digest. The target independently verifies
that tuple and retains the selected and rollback identities unchanged.

Qualification must prove:

- both isolated source builds and their exact comparison receipt;
- the exact official source tag, commit, tree, epoch, and command-settings
  digest;
- the pinned .NET SDK/runtime and locked NuGet and Node input set;
- exactly one runner `bin` and one `externals` payload, with no old-version
  siblings and no retained `_work/_update` staging;
- disabled in-place runner update and matching scale-set policy;
- exact `Runner.Listener --version` output before selection and again after
  selection;
- complete runtime, trust, seccomp, egress, conntrack, storage, and log-policy
  manifest equality;
- zero unsuppressed HIGH or CRITICAL findings in every blocking filesystem and
  image scan; and
- supported host-profile probes and whole-container reclamation evidence.

Permanent authenticity, identity, compatibility, reproducibility, scan,
platform, smoke, policy, host, or reclamation failure publishes
`candidate-rejected` for that exact candidate. The candidate remains
unselected, the selected fleet is not mutated, and the retained rollback
anchor is not deleted. Missing evidence is a stop and is never approval.

## Maintenance response phases

Source qualification and publication do not themselves grant production
acquisition or routing authority. A later full migration still requires the
authenticated Worker control plane and its six ordered response phases:

1. `wait-hosted`: keep acquisition disabled and make no upgrade effect while
   hosted routing, hold, identity, expiry, request, or phase proof is missing;
2. `stage-permitted`: stage only the exact qualified candidate while selection,
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
cleanup. Every phase binds the Worker enrollment epoch, session, request
control sequence, selected and candidate manifests, configuration revision,
transition epoch, policy digests, acquisition-authority generation, and
expiry. One reconciliation call performs at most one adjacent external phase.

The separate [QTS live canary](qts-live-canary.md) admits only the exact payload
and RhoNAS host profile on a disjoint one-job selector. It does not synthesize
these maintenance responses or qualify production routing.

## Retry and operator hold

Every effect has a durable applying intent, an exact read-back, and a proven
phase. A restart republishes durable release status and reconciles the current
phase rather than replaying the whole upgrade.

When an effect is absent, the controller may apply only the exact journal-bound
effect. When present and equal, it records the proven phase without duplicating
the effect. Missing, stale, contradictory, partially written, or wrong-identity
evidence is ambiguous: acquisition stays disabled, hosted routing remains in
place, and no later phase executes. An operation that may already have taken
effect is read back and never blindly retried.

An operator hold has precedence over all maintenance responses. Clearing a
hold does not revive an expired directive; the controller requires a fresh
response. Retries are idempotent for one exact request and phase. Reusing a
request across a different release, candidate, selection, policy,
configuration, transition, or acquisition-authority generation is rejected.

## Forced-version-bump continuity

A GitHub-forced version bump must not make the hosted path disappear. Consumer
routing stays on the proven hosted or retained production path while a new
source pin is explicitly reviewed, built twice, qualified, and published. The
selected runner image has in-place update disabled; an incompatible selected
image therefore fails closed for new local acquisition instead of copying a
second runner version into `/runner`.

If source construction, qualification, control-plane authority, drain, or
canary does not complete, the system stays hosted and disabled. A new candidate
never causes a best-effort local update or an incompatible rollback. No daily
observer, release heartbeat, or periodic binary update is required for this
safe state.

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

The general release manifest intentionally supplies no deployment tmpfs size,
memory-cgroup cap, concurrency ceiling, disk quota, retention age, or rebuild
cadence. The bounded QTS deployment instead reuses the separately approved,
validator-proven tuple recorded in the [QTS live canary](qts-live-canary.md) and
bound by its private execution packet. Other deployment profiles must size
those values together against measured workload, host memory, and
operator-approved headroom. Persistent NAS storage may not become an unbounded
build cache or workspace.

## Unattended-operation dependencies

Source qualification and the bounded RhoNAS canary do not authorize unattended
production operation. Before full routing migration:

- Phase 3 must supply the authenticated Worker maintenance client and exact
  external directive state machine;
- Task 14 release artifacts, checksums, SBOMs, provenance, and attestations
  must bind the exact merged product SHA and exact source-built payload;
- a supported Linux/Docker target must pass the opt-in integration,
  conformance, and chaos suites against that same identity;
- the operator-approved sizing and retention values must pass live read-back;
  and
- the governed enable and rollback sequence must prove there is no overlapping
  acquisition authority.

Until every dependency passes, the exact candidate may be source-qualified and
tested on the disjoint QTS canary path, but production selection and ordinary
local acquisition remain disabled.

Existing release tags `v0.1.0` and `v0.1.1` are immutable historical anchors.
Never reuse, move, or delete them. A new release tag may be created only on the
exact qualified merged SHA.

## Execution packet boundary

No live-host action is authorized by this document. A separately approved
execution packet must bind the target host, control host, source-release
manifest, candidate, selected and rollback identities, manifests and
attestations, initial routing state, Worker directives when applicable,
journal, policy, fence, exact install method, read-back commands, resource
settings, retention policy, rollback, and stop conditions.

The packet stops before mutation on any mismatched, missing, stale, ambiguous,
or expired evidence. Build, publication, stage, selector change, canary,
enable, rollback, and route change remain separately evidenced gates.
