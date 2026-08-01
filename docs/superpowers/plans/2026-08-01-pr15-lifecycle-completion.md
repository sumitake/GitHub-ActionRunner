# PR #15 Lifecycle Completion Plan

> Status: source-only completion plan for the final Phase 2 checkpoint. This
> plan changes no host, Docker, launchd, cron, systemd, runner, or GitHub
> configuration. Numeric sizing and every activation decision remain deferred
> for operator sign-off.

## Objective

Close the remaining exact-head review gaps without adding another service,
reconciler, mutable selector, generic command surface, or deployment path.
The result must truthfully support the closed target-local command grammar,
positively verify preloaded immutable release images, smoke the exact runner
listener, and drive every locally satisfiable Task 10 lifecycle phase through
the existing `hostruntime.LifecycleEngine`.

Transitions that require an external hosted-hold or legacy-normalization
authority must be fully parsed and bound but must fail before their first
write when that authority is unavailable. Phase 2 source completeness does
not fabricate those deferred external proofs.

## Non-goals and hard boundaries

- Do not pull, build, retag, delete, or run a serving image on any host.
- Do not choose tmpfs, cgroup, concurrency, storage, log, or cadence numbers.
- Do not enable cron/systemd/watchdog registration on a host.
- Do not create a second lifecycle engine, retry loop, background reconciler,
  generic argv executor, or free-form recovery path.
- Do not turn the disabled observer into an acquisition-capable controller.
- Do not manufacture hosted-hold, Worker, routing, legacy-normalization, or
  retention evidence. Missing external evidence is typed non-success before
  mutation.
- Keep the public control-side CLI limited to deploy, verify, suspend, and
  resume. Rollback, uninstall, and watchdog marker actions remain target-local
  closed commands.
- Preserve the approved Grafana/InfluxDB activation contract as documentation
  only.
- Do not add an unrelated repository, collaboration broker, reviewer plugin,
  or developer workspace as a source, build, test, release, deployment, or
  runtime dependency. Review transport remains replaceable development
  tooling; its availability does not change Portable GHAR's product boundary.

## Threat and failure model

The remaining code must fail closed against:

1. request/overlay manifest-path substitution;
2. mutable or absent image tags masquerading as immutable staged artifacts;
3. a digest reference resolving to the wrong OS, architecture, or RepoDigest;
4. a listener smoke that runs a different entrypoint, gains network access,
   emits extra output, or reports the wrong pinned version;
5. unsupported target actions returning success without an effect;
6. a lifecycle phase being marked present merely because metadata was staged;
7. stale target proof, fence generation, selection, process, watchdog, or
   reservation identity between observation and effect;
8. cancellation immediately before an external process start or lifecycle
   effect;
9. a lost lifecycle lease immediately before recovery applies an effect;
10. unavailable hosted/legacy evidence being treated as absence or success;
11. uninstall deleting retained state, journals, ledgers, manifests, or
    rollback material;
12. architecture drift: current release assets, runner archive, seccomp audit,
    and image pipeline are Linux x86-64 only, so `arm64` must not be accepted.

## One simple authority shape

Retain the current layers:

1. `SystemTargetHostExecutor` parses one closed target-local request and binds
   caller-supplied paths to the private overlay.
2. `SystemTargetHandler` re-proves target identity, performs only read-only
   `StageRelease` admission, and dispatches the exact lifecycle action. Bundle
   stage, verification/smoke receipts, and their phase presence are solely
   `LifecycleEngine`/phase-table effects.
3. `hostruntime.LifecycleEngine` remains the only crash-resumable state driver.
4. One `productionPhaseEffects` table remains the only phase-to-effect map.
5. Narrow authorities perform image inspection/smoke, hosted evidence
   validation, disabled controller operations, process operations, watchdog
   marker changes, release selection, fleet handoff, and retention proof.

No layer receives arbitrary argv. The only external commands introduced here
are fixed Docker argv vectors derived from already-validated overlay fields.

## Work package A: close entry and cancellation bindings

Write RED tests first, then make these minimal changes:

1. For install, verify, and watchdog-install, require
   `request.ManifestPath == overlay.Manifest.Path` before loading the
   manifest. Actions whose grammar intentionally omits `--manifest` load only
   the overlay-bound manifest path.
2. Restrict the target fields in private overlays and target proofs to
   `linux/amd64`. Reject `arm64` at parse/proof boundaries rather than carrying
   an architecture the release pipeline cannot produce. Do not reject the
   development host's `runtime.GOARCH`; macOS/arm64 still runs injected unit
   tests without executing Docker effects.
3. Add `ctx.Err()` immediately before `ExecCommandRunner` calls `cmd.Start()`.
   Preserve its existing cancel-after-start behavior: kill the owned process
   group, wait for reap, and return non-success. Image verification or smoke
   cancellation can never write a success receipt.
4. In `LifecycleEngine.Recover`, validate the held lifecycle lease immediately
   before the first `ensurePhaseApplied` call, matching the normal drive loop.

These changes do not add configuration or new public fields.

## Work package B: positively verify immutable artifacts and smoke the runner

Add one narrow `ReleaseArtifactVerifier` dependency to the production
lifecycle target. Production constructs it from the overlay's exact Docker
binary and `hostruntime.ExecCommandRunner`; tests inject a recorder.

`SystemTargetHandler.StageRelease` becomes a pure, read-only admission step:
it re-proves the target, validates the exact overlay/manifest/controller
binding, and seals the stage proof, but writes no release metadata and runs no
Docker command. Immutable image verification, listener smoke, proof receipt,
and bundle staging are ordinary install effects owned by the existing
`LifecycleEngine`.

### Image verification

During the engine-owned `candidate-staged` effect, before writing the release
bundle, run exactly one bounded command:

```text
<docker> image inspect --format <fixed-json-template>
  <runner-ref> <adapter-ref> <broker-ref> <helper-ref> <verifier-ref>
```

The parser requires:

- exit zero, no signal/truncation/stderr, exactly five newline-terminated
  canonical JSON objects, and no extra bytes;
- the five references are distinct, digest-qualified, and appear in the fixed
  role order from the overlay/manifest;
- each observation has `Os == "linux"`, `Architecture == "amd64"`, one valid
  lower-hex image ID, and a `RepoDigests` set containing the exact requested
  reference exactly once;
- no missing, duplicate, unknown, mutable, wrong-platform, or mismatched
  observation is accepted.

This is a positive preloaded-image gate, not a pull. If an approved external
preload has not made the immutable references available, install fails before
the release bundle is staged. After positive verification, the same effect
idempotently stages the exact bundle and atomically writes one canonical
verification receipt as its final write. A crash before the receipt causes
the effect to rerun; it never makes the phase present.

### Listener smoke

During the engine-owned `candidate-smoked` effect, after a positively observed
`candidate-staged`, run exactly:

```text
<docker> run --rm --network none --read-only --entrypoint
  /opt/actions-runner/bin/Runner.Listener <exact-runner-ref> --version
```

Require exit zero, no signal/truncation/stderr, and stdout equal to the pinned
`buildinfo.Pins().UpstreamRunner.Version` without its leading `v`, followed by
one newline. There are no mounts, environment additions, host namespaces,
capabilities, or fallback entrypoints. The existing phase order is retained:
image verification and inactive bundle stage produce `candidate-staged`, then
listener smoke produces `candidate-smoked`. A failed smoke may leave only the
immutable inactive `candidate-staged` bundle and exact verification receipt;
the install remains non-successful, nothing is selected/started/handed off,
and the existing pre-handoff compensation path removes that candidate or an
exact rerun resumes the smoke phase.

`candidate-staged` is present only after the exact image-verification receipt
and bundle readback agree. Its observation requires the manifest digest,
overlay revision, all five ordered digest-qualified references, target
`linux/amd64`, and exact receipt schema to match. `candidate-smoked` is present
only after a durable smoke receipt bound to the manifest digest, overlay
revision, runner reference, and pinned version is read back. Generic staged
files, a partial/malformed receipt, or a receipt for any other tuple never
makes either phase present. I/O or parse uncertainty is ambiguous; clean
absence is absent.

Use the existing release root and canonical release-file helpers for the two
small receipts; do not create another database. The receipt writes and bundle
stage are effects in the single phase table, not handler-side pre-writes.

## Work package C: complete the closed target-local action routing

Extend the internal action enum and `ExpectedOperation` derivation for
rollback and uninstall while leaving the public parser unchanged. Extend
`InvokeArguments` only with the already-parsed closed fields:

- expected generation;
- descriptor-pinned hosted-confirmation authority;
- descriptor-pinned legacy-command authority; and
- retain-state boolean.

`SystemTargetHostExecutor` must accept all eight `TargetHostAction` values:

- install, verify, suspend, resume, rollback, uninstall use the handler and
  exact operation/result binding;
- watchdog-install and watchdog-uninstall use a dedicated target-handler
  marker method only while holding the same lifecycle lease and after proving
  there is no active journal/reservation. The marker write is the existing
  atomic rename plus exact readback. The method returns one canonical complete
  result bound to the current target proof. It does not create a second lock,
  state store, or unconstrained marker writer.

Every request-shape branch must reject irrelevant nonzero fields. Target-local
rollback/uninstall/watchdog actions are not exposed through SSH/public
`HostAction` parsing.

Every request file is bound before its contents can count as authority:

- a supplied manifest path must equal `overlay.Manifest.Path`;
- a legacy command path must equal `overlay.Legacy.CommandFilePath`;
- hosted evidence is intentionally ephemeral, so its canonical path must be a
  direct regular-file child of the fixed
  `<overlay.Paths.StateRoot>/hosted-evidence` directory. Its descriptor-pinned
  canonical content must additionally bind the full sorted repository set,
  server-owned transition epoch, fence generation, validity interval, and
  proof digest. A different path or tuple is non-success before mutation.

## Work package D: complete the existing lifecycle phase table

Do not create a second target type. Generalize the existing
`greenfieldSystemTarget` to a `systemLifecycleTarget` while retaining its
current release, fence, process, watchdog, storage, Docker-quiescence, and
disabled-probe authorities. Extend the one phase table to enumerate every
normal phase used by install, suspend, resume, rollback, and uninstall.

### Shared narrow effects

- hosted hold: validate the exact descriptor-pinned canonical evidence file
  through an injected `HostedHoldAuthority`; unavailable production
  integration returns typed failure before the journal/reservation or any
  effect write;
- watchdog disable/remove/install: mutate only the exact manifest/revision
  marker and read it back;
- policy disabled/drained: use the exact bound controller admin socket and
  require its positive readback;
- controller stopped/started: use `ProcessAuthority` only;
- quiescence/zero: use the existing Docker managed-quiescence and disabled
  controller probes only;
- fleet handoff: use only exact expected generation/from/to through
  `fleetfence.Store`;
- release selection/absence: use only `releaseBundleStore` exact digest and
  current-link operations;
- legacy restore/start: validate the exact canonical legacy command file and
  injected legacy authority; unavailable production normalization fails before
  the first write;
- uninstall removal: remove only watchdog marker, process record/bound
  controller registration, current selection, and release-scoped binaries;
  retain state, journals, reservations, receipts, manifests, rollback roots,
  and stable ledgers;
- retention proven: positive inventory/readback only.

Production constructors always install concrete hosted-hold and legacy
authorities. A nil authority is a constructor error. Each authority returns a
closed `valid`, `invalid`, or `unavailable` result; missing files and absent
integration are never interpreted as absence of a requirement. Suspend and
rollback cannot open a writable lifecycle operation unless the required
authority returned `valid` for the exact bound tuple.

Every `ApplyPhase` performs one idempotent effect, then `LifecycleEffects`
re-observes it. Observation error is ambiguous failure, never absent.

Immediately before every effect—not only at operation admission—the lifecycle
target runs one shared pre-effect rebind predicate. It requires the same
operation binding as the journal/reservation, current target proof identity,
expected fence generation/fleet, permitted current-selection digest, exact
process/watchdog identities where applicable, and the same external-evidence
descriptor/digest for evidence-dependent phases. The engine already validates
the lifecycle lease and storage envelope; `Recover` adds the missing lease
validation before its first phase and then uses this same target rebind path.
Any drift is ambiguous non-success.

Do not introduce new lifecycle phases or a second compensation graph. All
normal and compensation phases referenced here already exist in
`hostruntime/operation_journal.go`; implementation extends the one production
phase-to-effect table to cover them exactly. Each table entry must name either
its existing graph-specified reverse/compensation phase or its existing
forward-only rule. Tests cover crash after every effect and every existing
compensation pivot; an unmapped graph phase is a construction/test failure.

### Operation entry rules

- Install preserves its current fresh/re-entry matrix and stable operation
  identity.
- Suspend admits only a selected portable release at the exact generation and
  validates hosted evidence before opening a writable operation.
- Resume admits only exact `none` ownership with a selected retained portable
  release and no live controller/watchdog; it always starts disabled and
  proves zero.
- Rollback admits only exact portable ownership, exact expected generation,
  a retained legacy overlay/command binding, and hosted evidence; absent
  external legacy/hosted authority fails before mutation.
- Uninstall admits only exact `none` or `legacy` ownership plus positive
  Portable quiescence and `--retain-state`; false or omitted retain-state is
  unsupported non-success before any effect, and no purge request is accepted.

Operation binding, terminal generation/fleet, journal, reservation, and result
are derived rather than caller-supplied. Re-entry requires the exact existing
journal/reservation pair. The existing compensation graphs remain the only
recovery paths.

After retained-state uninstall, terminal old-operation journals are inert
history. A later install derives a new operation ID from its new target tuple
and may not reuse an old journal/reservation; any active, incomplete,
one-sided, or tuple-colliding retained record blocks admission as ambiguity.

## Work package E: targeted review hardening

Apply only findings that remain true on the exact head and have a small,
closed repair:

1. Put systemd `StartLimitIntervalSec` and `StartLimitBurst` in `[Unit]` and
   replace unsupported `ConditionPathIsRegular` with supported positive
   executable/path conditions plus the program's own exact mode/digest check.
2. On watchdog `StartDisabled` error or malformed result, perform one bounded
   inspect; if an exact bound process appeared, invoke `SafeStop` and require
   positive absence before returning failure.
3. Add the fixed proxy environment to runner creation:
   `HTTPS_PROXY`/`https_proxy=http://127.0.0.1:18080` and
   `NO_PROXY`/`no_proxy=127.0.0.1,::1`. Do not set HTTP proxy variables because
   plaintext absolute-form HTTP is intentionally unsupported. Use one shared
   closed runtime-environment contract for creation, held-runner audit,
   conformance, listener exec, and the post-JIT residual check so the proxy
   cannot disappear at the release boundary.
4. Change rejected-container cleanup to remove only a container whose inspected
   immutable labels/name prove it belongs to the current create attempt. A
   pre-existing foreign same-name object is failure without removal.

Do not expand this checkpoint into root-adversary defenses that the CLI cannot
provide truthfully (for example pretending an fd can be passed through the
Docker daemon or SSH client). Document and adjudicate those findings against
the declared trusted-root boundary rather than adding cosmetic copies.

## TDD and verification order

1. Add focused RED tests for work package A and make them GREEN.
2. Add artifact-verifier parser/argv/receipt RED tests; implement B.
3. Add table-driven target-action grammar/routing/result RED tests; implement C.
4. Add one table per operation covering absent/present/ambiguous observation,
   one effect, crash-after-effect re-entry, stale proof, cancellation, and
   unavailable external authority; implement D in operation order:
   resume, uninstall, suspend, rollback. Keep install regression-green after
   every step.
   Add cross-operation fixtures for a simulated suspend residual followed by
   resume/uninstall admission, failed rollback before its first write, and
   candidate stage/smoke crashes followed by exact install recovery.
5. Add focused RED tests and implement E.
6. Run race tests for changed packages, then `go test -race ./...`, vet,
   staticcheck, govulncheck, QTS Bats, repository metadata, workflow policy,
   Debian snapshot, sanitizer, and controller aggregate checks.
7. Re-run all source/container gates available on macOS. Record Linux/Docker
   skips as deferred, never as passes.
8. Seal the exact base-to-head diff and obtain a direct high-effort
   distinct-family exact-artifact adversarial review through any eligible
   read-only reviewer route. Review provider and transport are replaceable
   development tooling, not product dependencies. Integrate any valid finding,
   rehash, and obtain a matching-digest approval.
9. Create a signed crash-safe commit, push, reply to and resolve exact-head PR
   threads with focused evidence, pass hosted checks, and merge normally.

## Success criteria for this checkpoint

- No target action is silently unsupported or false-successful.
- Install positively verifies all exact preloaded image references, then
  creates only an inactive bundle plus verification receipt as
  `candidate-staged`; the pinned listener smoke and receipt then establish
  `candidate-smoked`. Install remains non-successful until smoked. Smoke
  failure can leave only that inactive staged candidate for exact re-entry or
  pre-handoff compensation—never selection, process start, or fleet handoff.
- All locally satisfiable lifecycle operations use the existing durable engine
  and exact phase table.
- Missing external hosted/legacy authority is a typed pre-write failure.
- The disabled observer remains zero-acquisition.
- No host or deployment state changes during this work.
- PR #15 merges as the Phase 2 source-complete checkpoint only; the separate
  Linux/Docker, reproducibility, forced-version-bump, sizing/cadence,
  immutable-release, and host-activation evidence checkpoint remains open.
