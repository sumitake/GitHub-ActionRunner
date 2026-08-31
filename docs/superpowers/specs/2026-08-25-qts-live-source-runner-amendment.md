# QTS Live Source-Built Runner Deployment Amendment

**Date:** 2026-08-25

**Status:** Approved architecture; implementation pending

**Distinct-family review:** Antigravity conversation
`25e9d474-b3c3-497d-b8b5-7de87370ad1a`; original design digest
`087b203c3a32d7a95473286b9e59bc0b036bccacf222e3938ec3b02fe20eedd8`
received `PROCEED WITH CHANGES`; focused revised-digest check
`19a1b0f2dc45d22cd1482d008e7db48dcf006f225069128c2799de86fb7e8f6e`
received `PROCEED` with no unresolved blockers. The empirical
`TargetLatestRuntimePatch=true` correction at digest
`91dd936f7b826e98db6e8e7fdba18464e07167fb2c05a2d526b7834be1d06f27`
was separately accepted with no blocker in the same conversation.

**Qualified source baseline:** `28d545e961155901d54b30aafd0f851407caa49d`

**Scope:** replace the active persistent dark-observer closure with the
smallest source-built payload and bounded live-canary path. Preserve the
existing release, authority, fleet-fence, lifecycle, conformance, rollback,
and exact-head gates unless this amendment explicitly narrows the old
deployment outcome.

## 1. Decision and superseded outcome

The active deployment outcome is a live, one-job-at-a-time QTS/RhoNAS
candidate that proves the qualified payload under a disjoint canary selector
before any existing consumer route is expanded. LabMacPro remains active,
untouched, and authoritative for its existing production workload throughout
qualification and canary stability. JOHN-MBP is never a runtime, staging, or
deployment host.

The persistent QTS dark observer is deleted as an active requirement,
completion gate, roadmap phase, release dependency, and deployment outcome.
No permanent zero-capacity observer, observer watchdog, or observer cron is
installed merely for soak or testing. Historical design and implementation
records remain historical. Existing force-disabled startup, zero-authority,
zero-listener, cleanup, and compensation code remains because those are
load-bearing transient fail-closed and rollback primitives.

The upstream Microsoft/GitHub prebuilt runner archive is no longer a release
input. Its unchanged HIGH/CRITICAL vulnerability failure remains valid
evidence about that archive, but it is not the source-built candidate's
admission result. No VEX, vulnerability suppression, binary patching, or tag
reuse is allowed. `v0.1.0` and `v0.1.1` remain immutable and unreleased.

The already-green address-only Worker at signed source
`28d545e961155901d54b30aafd0f851407caa49d` is not redeployed, replayed, or
expanded by this amendment. Its hard ordinary-authority fence remains closed.
Consequently, the bounded payload canary below is not evidence authorizing the
later Worker-owned `PORTABLE_CANARY -> PORTABLE` production-routing transition.
That transition may run only when its existing independently reviewed
production-authority and private execution-packet gates are actually present.
Missing authority is a truthful post-canary stop, never a reason to bypass or
duplicate it.

## 2. Frozen invariants

- one immutable product payload and one runner tree in every candidate;
- two isolated source builds must produce byte-identical deterministic trees;
- the runner source tag, source commit, source tree, SDK, runtime, NuGet graph,
  external Node payloads, listener version, output tree, image, SBOM,
  provenance, checksums, and attestations are digest-bound;
- `DisableUpdate`, single-payload, update-residue, compatibility, Trivy,
  integration, conformance, chaos, exact-head review, signed-tag, and
  exact-merged-SHA gates remain unchanged;
- HIGH or CRITICAL findings fail the candidate; no fixed finding is ignored;
- LabMacPro and RhoNAS never race for the same job or selector;
- every live canary operation has exactly one terminal classification and is
  never blindly replayed when it may have taken effect;
- a failed or ambiguous RhoNAS step disarms and removes only the candidate,
  then positively re-proves LabMacPro's existing health and authority;
- no new service, queue, scheduler, alarm, timer manager, table, retry path,
  authority engine, or persistent permit state is introduced.

## 3. One locked source-build stage

Advance the existing `runtime.runner_release` object from its archive-shaped
schema version 1 to one source-build-shaped schema version 2 and add one
bounded source-build script. Do not retain an adjacent archive object or a
second payload selector. The version-2 object has this closed top-level key
set:

```text
schema_version, version, tag_ref_sha, source_commit_sha, source_tree_sha,
published_at, command_settings_sha256, observation_evidence, build
```

Its closed `build` object contains exactly `dotnet_sdk`, `nuget_locks`,
`externals`, and `expected_listener_version`. Those values pin:

- official repository `actions/runner`, tag `v2.336.0`, commit
  `98aabcd429c4e8402406c56ce2d26387fed3b9ce`, and its exact Git tree;
- official .NET SDK `8.0.424` Linux x64 archive and SHA-512, with required
  SDK-reported runtime `8.0.30`;
- the complete NuGet locked dependency graph and content hashes used by the
  seven upstream runner projects;
- upstream-selected Node `20.20.2` and `24.18.0` Linux x64 and Alpine x64
  external archives with exact URLs and SHA-256 digests; and
- expected listener version `2.336.0`.

The script accepts only the checked manifest, an empty output directory, and
one caller-owned temporary root. It performs this closed sequence:

1. fetch the exact official tag/commit with a bounded transfer and positively
   verify repository URL, tag resolution, commit, tree, and clean checkout;
2. download the exact SDK and external archives, verify their digests before
   extraction, and reject links, special files, traversal, extra roots, or
   changed file identity through the existing closed extraction patterns;
3. prove `dotnet --version` is `8.0.424` and the installed runtime is exactly
   `8.0.30`;
4. set `NUGET_PACKAGES` to a new directory inside the caller-owned isolated
   root, copy only the checked NuGet lock files into their matching upstream
   projects, and restore with `RestorePackagesWithLockFile=true` and locked
   mode. Preserve the upstream `TargetLatestRuntimePatch=true`: with the exact
   SDK `8.0.424` this resolves the self-contained .NET runtime packs to exactly
   `8.0.30`; an empirical control restore with the property forced false
   instead selected core runtime packs `8.0.0` and is prohibited. Require the
   restore assets and published layout to prove only `8.0.30` runtime packs.
   Across all seven asset documents, require a nonempty graph containing only
   canonical ASCII `Microsoft.*.linux-x64` pack names at that manifest-bound
   runtime version. Pack membership and project placement remain outputs of the
   exact source and SDK rather than a second hand-maintained authority.
   Build the official Linux x64 Release layout with
   `ContinuousIntegrationBuild=true`,
   `Deterministic=true`, and a path map from the exact checkout root to the
   fixed logical `/src` root. Set `SOURCE_DATE_EPOCH` to the official source
   commit time and set `DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_NOLOGO=1`,
   `DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1`, and
   `DOTNET_GENERATE_ASPNET_CERTIFICATE=0`. No upstream download helper or
   user-global NuGet cache is allowed;
5. populate `externals/` from the complete four digest-verified upstream Node
   archives using the upstream-selected layout. Preserve the official runner
   runtime contents—including package-manager support files that actions may
   legitimately call—rather than pruning the distribution to `bin/node`.
   Normalize directories to `0555`, executable files to `0555`, and ordinary
   files to `0444`; require every relative symlink to resolve to a regular file
   inside the admitted tree; and admit the complete result through the existing
   runner-tree validator;
6. remove build-only symbols/residue exactly as the official package step does,
   require `Runner.Listener --version` to equal `2.336.0`, require no updater
   payload or second runner tree, and normalize only timestamps/ownership/modes
   already normalized by the product release pipeline; and
7. emit the ordinary verified `build/runner` tree plus one canonical provenance
   record. It emits no credential, package-cache path, or arbitrary command
   output.

The existing release Build A and Build B jobs invoke this same stage in
separate empty temporary roots and otherwise remain independent. The existing
tree comparator, rehearsal, SBOM, Trivy, provenance, attestation, and
publication jobs consume the resulting tree without a second payload path.
The prebuilt-archive download/extract path becomes impossible for a product
release, while archive-validation code and tests remain for historical and
library safety coverage.

This adds one small build boundary rather than a new build system. It reuses
the upstream MSBuild graph and the product's current two-builder comparator.
If locked restore, exact fixed runtime selection, or byte-for-byte A/B equality
cannot be achieved with this boundary, the release stops with the exact failed
invariant. Do not add a package proxy, cache service, third builder, patch
queue, custom .NET distribution, or second release pipeline.

The strict rehearsal and comparator schemas advance in the same change. They
accept only runner-release schema version 2 and the exact closed keys above;
schema version 1 is rejected for a product release. The version-2 validator
recomputes `observation_evidence`, the aggregate canonical NuGet-lock digest,
and every external digest. The source builder and NuGet locks are immutable
exact-head inputs admitted by the clean checkout, manifest digest checks, and
ordinary exact-head gates; they are not candidate-overlay mutation surfaces.
Candidate and product rehearsal both require the supplied version-2 object to
equal the checked-in baseline exactly. The existing registered identity-path
inventory remains a read-only closure check in this narrow amendment: equality
makes every registered substitution a no-op, and either release kind rejects a
dirty post-check clone. Runtime-release evidence and the A/B comparator bind
the full version-2 object, so an archive-shaped or out-of-band manifest cannot
enter either path through a stale validator.

## 4. Bounded live RhoNAS canary

The canary reuses GitHub's existing dedicated canary workflow shape: its
`runs-on` targets one private RhoNAS-only scalar selector directly and never
the consumer `PORTABLE_GHAR_ROUTE` expression. The selector uses the private
execution packet's fixed
`rhonas-canary-ephemeral-<operation-digest-prefix>` shape and must be absent
from every LabMacPro registration and every existing RhoNAS legacy
registration. The canary repository/workflow revision and selector are bound
in the private execution packet and positively read back before registration.

The candidate is an ephemeral, one-job runner using the qualified immutable
image, `DisableUpdate`, and the existing one-job JIT/container lifecycle. It is
started manually for one pre-dispatched, secretless controlled workflow run;
there is no resident controller, observer, watchdog, cron, or automatic retry.
Native GitHub assignment supplies the disjoint routing authority for that one
run. Existing product fence checks still protect any product-controlled local
acquisition, but the canary does not invent a second durable authority source
or write consumer routing.

Each canary attempt is a single state machine:

```text
prepared -> dispatched -> assigned -> completed -> reclaimed
                                \-> failed-or-ambiguous -> disarmed
```

The operation records the GitHub workflow run/job identity before starting the
candidate. Read-only status polling is bounded by one overall deadline. A
definite dispatch rejection that proves no run or job was created may be
corrected only under a new operation ID. Once dispatch is accepted, never
redispatch that operation. The job-three local-startup exception below may
resume only the same recorded operation and queued job after positive
pre-registration proof. A timeout or conflicting readback is
`failed-or-ambiguous`, not permission to submit another run.

Green stability requires three serial controlled jobs, each with a fresh
one-job registration but the same immutable product image and QTS/Docker
identity. After each job, positively prove:

- the exact workflow revision, job ID, RhoNAS-only selector, self-hosted
  environment, runner name, listener version, and successful terminal result;
- exactly one assignment and one effect marker, with no duplicate workflow,
  job, runner, listener, or external effect;
- zero remaining runner container, listener, registration, worktree, tmpfs,
  update staging, socket, namespace, and candidate secret material;
- the exact admitted candidate image remains at its expected immutable digest;
- Docker daemon binary, server, root, configuration, and restart identity plus
  unrelated preexisting container/image identities are unchanged, and QTS
  crond state and unrelated root cron bytes are unchanged;
- CPU, iowait, available memory, storage, inode, PID, and container bounds meet
  the approved QTS sizing tuple; and
- LabMacPro remains healthy on its unchanged production selectors.

For job three on the shared live RhoNAS host, first record and queue its exact
run/job under one operation, then interrupt only the local pre-registration
startup gate. Resume that same operation and already queued job through its
single JIT registration only after authoritative readback proves no
registration, assignment, or job effect and proves the operation has not
consumed that registration. Do not create a new operation or redispatch the
run; ambiguity disarms the canary. A Docker daemon or QTS host restart is
prohibited while any legacy or unrelated production workload may be active.
Whole-daemon/host lifecycle evidence may be reused only from an isolated
staging run, or performed later under a separate drain gate that positively
proves every affected legacy runner idle. The live stability window is bounded
by the three serial jobs plus candidate-scoped interruption and resource
observations; it is not implemented as a persistent soak daemon.

On any failed or ambiguous job, stop dispatch, revoke/delete only its ephemeral
registration or credential when exact identity is known, stop/remove only the
candidate container, prove zero candidate residue, and re-read LabMacPro.
Unknown remote effect is preserved as evidence and is not retried. LabMacPro is
never stopped, restarted, relabeled, drained, or used as the test target.
After an otherwise terminal job, an exact recorded runner ID that remains
visible as offline is deleted once as cleanup and its absence is read back;
an unknown or mismatched registration is preserved for adjudication rather
than broadly deleted.

## 5. Expansion and rollback boundary

Passing the three-job window admits only the exact source-built payload and
RhoNAS host profile. It does not silently activate ordinary Worker authority,
change consumer workflows, or retire LabMacPro.

If every pre-existing production-authority gate is available, continue through
the existing hosted-hold, queue-risk, `canary-permitted`, exact-current-epoch
canary, `enable-permitted`, route-readback, and fleet-fence sequence. Keep
LabMacPro registered as the proven rollback/failback path until the new runner
has passed the separately recorded production stability criteria. Any later
retirement is a separate reported decision.

If those authority inputs are absent—as they are in the currently deployed
address-only Worker—stop after the bounded payload canary. Report source,
release, RhoNAS mutation, LabMacPro health, canary stability, rollback
readiness, and the missing authority gate as separate facts. Do not claim the
full migration completed and do not bridge the gap with direct route writes.

## 6. Failure and degradation matrix

| Dependency or boundary | Failure/ambiguity | Safe degradation |
| --- | --- | --- |
| official runner source | timeout, tag/commit/tree mismatch, dirty checkout | no build; retain exact observation; no fallback archive |
| .NET SDK/runtime | download error, digest/version/runtime mismatch | no restore/build; no alternate SDK or floating patch |
| NuGet | unavailable feed, shared/global cache, unlocked graph, content-hash drift, partial restore | delete isolated root; no candidate; no alternate feed or unlocked restore |
| Node externals | unavailable asset, digest/extraction/symlink/tree mismatch | no layout; no pruning or upstream helper download |
| isolated A/B builds | tree mismatch or residual path/time variance | no compare/attest/publish; one simplicity adjudication before any redesign |
| Trivy/SBOM/provenance | tool error, HIGH/CRITICAL finding, missing subject | no release; unchanged policy; missing evidence is not approval |
| GitHub canary API | definite rejection | no runner start; record rejection |
| GitHub canary API | accepted/timeout/unknown result | no replay; read back existing run/job only, then disarm on ambiguity |
| LabMacPro readback | unavailable or unhealthy | no RhoNAS mutation or next canary; preserve current routing |
| RhoNAS SSH/Docker | identity drift, timeout, partial mutation | stop/remove exact candidate when knowable; no broad cleanup; re-prove LabMacPro |
| canary job | failure, duplicate, timeout, residue, resource breach | fail closed; candidate-only teardown; no routing expansion |
| candidate interruption/recovery | incomplete cleanup or non-deterministic recovery | canary fails; no shared daemon/host restart and no resident watchdog added |
| ordinary Worker authority | address-only fence or missing execution packet | payload canary may be reported; production migration remains blocked |

## 7. Acceptance evidence

The amendment is green only when all applicable evidence is bound to one exact
merged product SHA and immutable source-build input set:

1. exact-head distinct-family architecture/adversarial/reliability review;
2. RED-to-green unit/repository/shell tests for the source lock, archive-path
   exclusion, locked restore, SDK/runtime mismatch, external digest mismatch,
   listener/update residue, A/B tree comparison, and canary no-replay contract;
3. full local and GitHub qualification including integration, conformance,
   chaos, race, static analysis, Worker tests, and unchanged vulnerability gate;
4. two isolated byte-identical runner/product builds and their immutable
   digests, SBOM, provenance, checksums, and attestations;
5. a new signed tag on only the qualified merged SHA and positive release
   readback; and
6. positive LabMacPro/control-host/RhoNAS identities, three serial canary jobs,
   candidate-scoped interruption/recovery, zero residue, resource bounds, and
   candidate-only rollback.

No completed Worker/Cron/token evidence, previous review, prior rehearsal, or
old tag is replayed to satisfy these items.
