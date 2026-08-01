# PR #15 Final Review Repair Plan

> **Status:** source-only implementation plan for the Phase 2 checkpoint.
> This plan authorizes no deployment, host configuration, RhoNAS/QTS change,
> release, tag, selector, fleet drain, Phase 3 work, or operator-reserved
> numeric sizing/cadence choice.

**Goal:** Close every exact-head PR #15 review finding, replace the four
unconditional production stubs with real fail-closed source compositions, and
merge a truthful **Phase 2 source complete** checkpoint. The later Linux/Docker
rehearsal, two-build reproducibility proof, forced-runner-version-bump drill,
numeric sizing approval, private host values, and activation remain the
separate **Phase 2 fully verified** evidence checkpoint.

**Architecture:** Keep `cmd` packages as composition roots only. Harden the
existing typed state machines first, then add one closed production
composition layer built from the already-validated `PrivateOverlay` and
`RuntimeManifest`. The management path uses one framed, versioned OpenSSH
subsystem protocol rather than a remote shell string; the target path uses one
phase-scoped lifecycle authority rather than arbitrary argv; the watchdog uses
one exact Linux process record rather than PID/argv discovery. Every omitted,
unapproved, unsupported, stale, ambiguous, or identity-drifted input fails
before a write. Tests use temporary roots, fake subprocesses, and synthetic
profiles only.

**Independent architecture decision:** A direct xAI/Grok 4.5 high-effort
adversarial review classified the four unconditional production failures as
blocking under Task 10 and the current source-complete claim. It also required
stronger process identity, cleanup precedence, process-group, symlink, Docker
name, and HTTPS deadline contracts. This plan incorporates those constraints.

## Hard boundaries and success criteria

1. No code path may return success while a lifecycle/watchdog lease release,
   exact-process stop proof, Docker ambiguity cleanup, lifecycle readback, or
   transport binding remains uncertain.
2. No production path may expose a generic command, shell string, arbitrary
   destination, arbitrary environment, arbitrary stdin, mutable image tag, or
   unbounded network/body operation.
3. No private target value, credential value, sizing number, cadence, or host
   identity is invented in source. Source defines validation and execution
   mechanisms; a real private overlay remains an operator gate.
4. A missing OpenSSH subsystem, missing credential reference, incomplete
   process record, unsupported platform, unapproved sizing tuple, or missing
   phase authority returns a typed failure before effects.
5. Phase 2 source completion is mergeable only when all local and hosted gates
   pass at one signed head, every PR review thread is resolved with evidence,
   and an eligible read-only distinct-family exact-diff review reports no
   material defect. Reviewer provider and transport are replaceable development
   tooling, not Portable GHAR dependencies.
6. After the normal PR merge and exact merge-commit readback, stop. Do not
   begin Phase 3, deployment, activation, or the deferred evidence PR.

## Task 1: Watchdog identity, safe-stop, and lease-finalization integrity

**Files:**

- Modify `internal/watchdog/watchdog.go`.
- Modify `internal/watchdog/watchdog_test.go`.

**RED tests:**

1. Reject `FenceGeneration == 0` before `SafeStop`, `StartDisabled`, or proof.
2. A running-controller disabled-proof failure must call `SafeStop`, then
   `Inspect`, and return failure unless the same fence/fleet is process-absent.
3. A storage revalidation failure must still inspect, stop an observed
   process, prove absence, and never start a replacement.
4. A newly started controller whose proof fails must be stopped and proven
   absent before return.
5. `LifecycleLease.Close` failure after an otherwise successful cycle must
   return `StatusFailed`/`ErrSupervisionFailed`; when another error already
   exists, preserve that primary reason and join the close failure.
6. Wrong fence/fleet/process identity after stop, repeated stop failure, proof
   failure, or close failure must never be reported recoverable/healthy.
7. Call-order fixtures prove stop/prove cleanup happens before lease close and
   every acquired lease is closed exactly once.

**GREEN implementation:**

- Make `RunCycle` use named result/error returns and one explicit deferred
  finalizer that joins `Close` failure without replacing an existing specific
  reason.
- Reject zero generations in `validateObservation`.
- Add one `safeStopAndProveAbsent(ctx, observation)` helper. It accepts only
  the already-inspected immutable observation and succeeds only when a fresh
  observation has the same nonzero generation and fleet and is absent with an
  empty process identity.
- Treat a post-stop inspection error, timeout, partial observation, generation
  or fleet mismatch, or any nonempty/mismatched process identity as
  `StatusFailed`/`ErrSupervisionFailed`. None of these cases is recoverable,
  healthy, or evidence of absence.
- Route storage-stop, already-running proof failure, unhealthy process, and
  newly-started proof failure through the same helper. Never start after a
  storage stop.
- Do not add PID parsing to the state machine. The production supervisor in
  Task 8 is responsible for making `ProcessIdentity` a digest of a full pinned
  process record, so PID reuse cannot satisfy equality.

**Focused verification:**

```bash
GOTOOLCHAIN=go1.26.5 go test -race ./internal/watchdog -count=1
```

## Task 2: Host lifecycle lease integrity

**Files:**

- Modify `internal/hostruntime/lifecycle_engine.go`.
- Modify `internal/hostruntime/lifecycle_engine_test.go`.
- Modify lifecycle-store tests only where a concrete stable-inode lease is
  needed to prove the fault.

**RED tests:**

1. `Execute` close failure after `HostActionComplete` becomes a failed result
   with `LifecycleErrorIntegrity`.
2. `Recover` close failure after success does the same.
3. If an operation already failed, close failure is joined and observable but
   cannot clear or replace the operation's specific primary class.
4. `Recover` calls `lease.Validate()` immediately after acquire and before
   `prepareLocked`, `Observe`, or `Apply`.
5. Concrete-FD corruption and stable lock-inode replacement after acquire
   produce zero effect calls.
6. Every acquired lease closes exactly once, including validation and prepare
   failures.

**GREEN implementation:**

- Add one shared finalization helper that takes the binding, partial journal,
  result, primary error, and close error. It upgrades pure success to
  integrity failure and joins cleanup failure to an existing failure without
  returning success.
- Convert `Execute` and `Recover` to named results with the same acquire →
  validate → prepare/drive → explicit finalizer ordering.
- Add the missing recovery validation before any phase observation/effect.
- Keep the current descriptor-relative lifecycle store as the authority; do
  not introduce path re-resolution after validation.

**Focused verification:**

```bash
GOTOOLCHAIN=go1.26.5 go test -race ./internal/hostruntime -run 'Lifecycle|Recovery' -count=1
```

## Task 3: Fleet-fence process-group containment

**Files:**

- Modify `cmd/portable-ghar-fleet-fence/main.go`.
- Modify `cmd/portable-ghar-fleet-fence/main_test.go` and Unix integration
  helpers.
- Add a non-Unix fail-closed file only if the existing build matrix requires
  it.

**RED tests:**

1. The guarded direct child and grandchild are in a dedicated group and both
   disappear after renewal failure and parent SIGTERM.
2. A child that ignores TERM is killed with the whole group after the grace
   bound.
3. Normal completion performs one direct-child wait and never signals the
   group afterward.
4. Start failure, missing/changed PGID, or a child that escapes its group is a
   failure; guard/store close still run.
5. A simulated reused PGID is never signaled after the direct-child wait has
   completed.

**GREEN implementation:**

- Set `SysProcAttr.Setpgid=true` before start.
- After `Start`, require `Getpgid(child.Pid) == child.Pid` and capture that
  value as the immutable PGID.
- TERM/KILL `-pgid` only while the direct child is not yet reaped. The direct
  child remains the sole wait/reap anchor. Once wait completes, invalidate the
  PGID and never signal it again.
- Join termination, renewal, guard-close, and store-close failures without
  releasing authority early.

**Focused verification:**

```bash
GOTOOLCHAIN=go1.26.5 go test -race ./cmd/portable-ghar-fleet-fence -count=1
```

## Task 4: Immutable runner runtime overlay

**Files:**

- Modify `images/runner/Dockerfile`.
- Modify `cmd/portable-ghar-runner-gate/main.go` and tests.
- Modify runner image verification scripts/tests that enforce the tree lock.

**RED tests:**

1. Admit both and exactly `/opt/actions-runner/_diag -> /runner/_diag` and
   `/opt/actions-runner/_work -> /runner/_work` as the post-manifest overlay;
   reject a missing, relative, indirect, wrong-target, parent-symlink, file,
   directory, or extra-entry variant. Verify only each symlink inode under the
   immutable image root; never follow either tmpfs target during image build.
2. The listener smoke may create `_diag`, but after removing only `_diag` a
   second strict image verification must reject `_work` or any other residue
   before the exact two-link overlay is installed.
3. The runtime gate creates `/runner/_diag` only under the already-proven
   ephemeral `/runner` tmpfs and requires directory mode `0700`, UID 65532,
   GID 65532, and unchanged device/inode across the pre-listener check.
   Its existing seed hydration creates the fresh `/runner/_work` root before
   listener release.
4. Wrong owner/mode/type/identity prevents listener start. Image verification
   still rejects every immutable runner binary/tree drift, and the overlay
   remains digest-neutral.

**GREEN implementation:**

- Keep the official archive/tree verification and version smoke first.
- Remove smoke `_diag` only, rerun strict verification, require its version to
  equal the original verified version, then create the exact `_diag` and
  `_work` links and run the runtime-overlay verifier. Never delete `_work` to
  make the build pass; its pre-overlay presence is evidence of unknown smoke
  residue and must fail closed.
- At runtime create/pin `/runner/_diag`, re-stat it immediately before
  listener execution, and never make `/opt/actions-runner` writable.
- Use no persistent volume and choose no new tmpfs size.

**Focused verification:**

```bash
GOTOOLCHAIN=go1.26.5 go test -race ./cmd/portable-ghar-runner-gate -count=1
./scripts/verify-runner-image-contract.sh --source-only
```

## Task 5: Docker create ambiguity reclamation

**Files:**

- Modify `internal/hostruntime/dockercli.go`.
- Modify `internal/hostruntime/dockercli_test.go`.

**RED tests:**

- For adapter and runner creation, cover runner error, nonzero exit, signal,
  stdout/stderr truncation, nonempty stderr, empty/malformed/mismatched ID,
  cancellation, and cleanup failure.
- Every failure after `docker run` invocation calls exactly one independently
  bounded `docker rm -f <validated deterministic name>`.
- Pre-validation, seccomp verification, adapter reinspection, or nonce
  generation failure performs no removal.
- The original create failure remains primary; removal failure is joined and
  cannot produce success.
- Invalid or non-binding-derived names never reach cleanup.
- Concurrent creates for the same deterministic name are serialized by an
  in-process pending-name reservation that is acquired before invocation and
  released only after success registration or bounded cleanup. A duplicate
  waiter fails before its own `docker run`; restart-time ambiguity is still
  resolved by the existing durable reconciliation path, not by assuming name
  ownership.

**GREEN implementation:**

- Add one shared `cleanupRejectedCreate(name, primary)` helper using a fresh
  bounded context independent of the canceled request context.
- Set an `invoked` boundary immediately before `CommandRunner.Run`; all
  rejected outcomes after that boundary use the helper.
- Continue validating names before invocation. Do not infer ownership from
  stdout; the deterministic validated name is the cleanup authority.
- Hold a pending-name reservation across run, parse, handle registration, and
  cleanup so two local callers cannot race one name into removing the other's
  container.

**Focused verification:**

```bash
GOTOOLCHAIN=go1.26.5 go test -race ./internal/hostruntime -run 'DockerCLI|CreateNetworkAdapter|CreateRunner' -count=1
```

## Task 6: Bounded Task 11 HTTPS exchange

**Files:**

- Modify `cmd/portable-ghar-task11-listener/core.go`.
- Modify `cmd/portable-ghar-task11-listener/main.go`.
- Modify `cmd/portable-ghar-task11-listener/proxy.go`.
- Modify `cmd/portable-ghar-task11-listener/main_test.go`.
- Modify `cmd/portable-ghar-task11-listener/proxy_test.go`.

**RED tests:**

1. No enclosing deadline or no positive connection deadline fails before
   network I/O.
2. Stalled CONNECT/dial, TLS handshake, headers, and body each terminate under
   their applicable bound and honor parent cancellation.
3. Exactly `MaximumWireBytes` decoded response bytes may succeed;
   `MaximumWireBytes+1` fails without canonical-success parsing.
4. Redirects, non-HTTP/1.1 final responses, content encoding, declared or
   delivered trailers, content-length mismatch, partial framing, and 1xx
   behavior cannot create an unbounded or accepted exchange.
5. Cancellation or overflow cannot emit the terminal success frame.
6. The exact loopback relay/CONNECT/TLS happy path remains stable under the
   race detector and repeated execution. Relay-side `ECONNRESET`, `EPIPE`, or
   closed-connection errors are benign only after the exact CONNECT request
   was captured and the client exchange already reached its terminal result;
   they never mask a CONNECT-phase failure.

**GREEN implementation:**

- Keep the existing simple one-connection state machine. `main` creates a
  signal-cancelable parent; `run` wraps only the `run` action in one fixed
  30-second source-level protocol timeout; `runListener` passes that exact
  bounded context into `exchangeHTTPS`. No environment, overlay, host, or
  operator sizing field selects or extends this timeout.
- Before any network I/O, require a non-nil caller context with a future
  deadline. After the exact `tcp4` loopback dial, bind the connection to that
  enclosing deadline and close it on caller cancellation. Never clear or
  extend the deadline.
- Preserve the exact manual CONNECT request/response bytes, normal TLS
  verification, exact leaf certificate/SPKI digest binding, and HTTP/1.1-only
  negotiation before sending the GET.
- For only the already-authenticated tunnel, use one fresh, non-reusable HTTP
  transport/client whose only TLS dial callback can return that exact
  connection once. Its ordinary dial path always rejects, proxy discovery is
  absent, redirects/compression/keep-alives/HTTP2 are disabled, response
  headers have a fixed 32-KiB source bound, and the header timeout is clamped
  to the positive enclosing time remaining.
- Use `io.LimitReader(MaximumWireBytes+1)` on the decoded body, reject a copied
  count above `MaximumWireBytes` before digest acceptance, require clean EOF
  and exact nonnegative content length, reject trailers both before and after
  the read, and bind digest/status/TLS only after the complete in-bound
  response is closed successfully.
- Keep every returned error opaque. Do not add a generic transport framework,
  timeout configuration surface, retry, connection pool, alternate proxy
  mode, or direct-network fallback.

**Focused verification:**

```bash
GOTOOLCHAIN=go1.26.5 go test -race ./cmd/portable-ghar-task11-listener -count=1
```

## Task 7: Closed production configuration and management transport

**Files:**

- Modify `internal/hostruntime/private_overlay.go` and tests.
- Add `internal/productionruntime/transport.go`, protocol codec files, and
  tests.
- Modify `internal/cli/host.go` only for strictly necessary typed proof/stage
  bindings.
- Modify `cmd/portable-ghar/main.go` and tests.

**Configuration contract:**

- Extend the private overlay with a mandatory closed `management_transport`
  object for production management use. Its only initial mode is
  `openssh-subsystem-v1`.
- Required fields are mechanism references, never values invented by source:
  absolute local OpenSSH binary, exact host locator, port, remote user,
  absolute known-hosts file, one named credential reference, fixed subsystem
  name `portable-ghar-v1`, and explicit connection/operation durations.
- Port is a typed nonzero `uint16`. Both durations are positive, canonical,
  integral seconds; operation timeout is strictly greater than connection
  timeout. The parent applies operation timeout as a wall-clock context
  deadline whose command runner kills and waits for the entire OpenSSH process
  group on expiry. OpenSSH's connection timeout is additive, not the outer
  liveness bound.
- The credential reference must resolve to one absolute regular-file path.
  Open it with `O_NOFOLLOW`, pin device/inode/owner/mode, require the declared
  control UID and mode `0600`, revalidate after use, and reject relative paths,
  symlinks, directories, sockets/agents, environment-derived resolution, and
  user configuration. Inline key data, agent fallback, host-key prompting,
  password prompting, multiplexed control masters, proxy commands, and
  unknown fields are rejected. Apply the same pinned-file discipline to the
  OpenSSH binary and known-hosts file.
- The host is either a canonical `netip` address without a zone or strict
  lowercase ASCII DNS labels. The remote user is a strict closed local-name
  scalar. Both reject option-like, path-like, whitespace, control, and Unicode
  forms before constructing argv.
- Open the binary, identity, and known-hosts files nonblocking with
  `O_NOFOLLOW`, prove regular files, then clear nonblocking mode. Identity is
  exactly control-UID-owned mode `0600`; known-hosts is root/control-UID-owned
  and not group/other writable. OpenSSH plus every ancestor is root-owned and
  not group/other writable, with no symlink component. Identity and
  known-hosts ancestors are root/control-UID-owned and not group/other
  writable, also with no symlink component. Pin and revalidate all identities
  after every outcome. This excludes `/tmp`, runner workspaces, and any other
  group/other-writable placement without adding a second configured root.
- A positive Darwin probe showed that `/usr/bin/ssh` closes inherited
  descriptors above stderr before resolving `IdentityFile`: a correctly passed
  `/dev/fd/3` produced `Identity file /dev/fd/3 not accessible: Bad file
  descriptor`, while the same inherited descriptor was visible to `/bin/ls`.
  Therefore execute the pinned root-immutable OpenSSH binary and supply the
  pinned identity and known-hosts file by their canonical absolute paths.
  Require management paths to use a narrow no-whitespace ASCII path grammar so
  OpenSSH's `-o` parser has no second interpretation. Canonical means absolute,
  `filepath.Clean(path) == path`, no empty, `.` or `..` segment, no trailing
  slash except root, and only ASCII letters, digits, slash, dot, underscore,
  and hyphen. The control UID and root are trusted configuration authorities;
  compromise of either is outside this transport's threat model because either
  can already replace the overlay or executable. A descriptor shim, copied-key
  cache, helper daemon, shell, custom launcher, agent, or SSH library is
  deliberately excluded.

**Protocol contract:**

- Invoke OpenSSH with fixed argv and `-s`; never construct a remote shell
  command. Disable config discovery and interactive authentication, require
  strict host-key checking and the exact known-hosts file, and clear the child
  environment. Every keyword uses an exact two-element `-o`, `Key=value`
  pair—including `GlobalKnownHostsFile=/dev/null` and
  `UserKnownHostsFile=<validated-path>`—rather than a bare option token. Use a
  literal `--` before the validated host. Pass no extra descriptors. The exact
  suffix is `-i <identity> -p <port> -l <user> -s -- <host>
  portable-ghar-v1`; the only variable argv values are the already validated
  canonical binary, identity and known-hosts paths, host, port, user, and fixed
  timeout values.
- The fixed option vector is exactly:
  `BatchMode=yes`, `IdentityFile=none`, `CertificateFile=none`,
  `IdentitiesOnly=yes`, `IdentityAgent=none`,
  `PubkeyAuthentication=yes`, `HostbasedAuthentication=no`,
  `GSSAPIAuthentication=no`, `PasswordAuthentication=no`,
  `KbdInteractiveAuthentication=no`,
  `PreferredAuthentications=publickey`, `AddKeysToAgent=no`,
  `PKCS11Provider=none`, `SecurityKeyProvider=none`,
  `CanonicalizeHostname=no`, `CheckHostIP=no`,
  `VerifyHostKeyDNS=no`, `StrictHostKeyChecking=yes`,
  `UpdateHostKeys=no`, `HashKnownHosts=no`,
  `KnownHostsCommand=none`, `GlobalKnownHostsFile=/dev/null`,
  `UserKnownHostsFile=<validated-path>`, `ControlMaster=no`,
  `ControlPath=none`, `ProxyCommand=none`, `ProxyJump=none`,
  `RequestTTY=no`, `StdinNull=no`, `ClearAllForwardings=yes`,
  `ExitOnForwardFailure=yes`, `PermitLocalCommand=no`,
  `EnableEscapeCommandline=no`, `ForwardAgent=no`, `ForwardX11=no`,
  `NumberOfPasswordPrompts=0`, `ConnectionAttempts=1`, and
  `ConnectTimeout=<validated-seconds>`. `IdentityFile=none` precedes the sole
  `-i <identity>` argument so compiled default identity paths cannot join the
  candidate set. A non-default port requires the operator's pinned known-hosts
  file to use OpenSSH's exact `[host]:port` key; a mismatch fails closed.
- Over stdin/stdout exchange one bounded canonical JSON request/result frame
  with schema, action enum (`prove-target`, `stage-release`, `invoke`), request
  digest, overlay revision, target proof digest, and action-specific closed
  payload. The document maximum is 3 MiB and the wire maximum is exactly that
  plus one LF; the command runner uses the same stream bound. No frame carries
  a raw credential.
- Each direction is exactly `canonical_json + LF`, with no leading bytes,
  embedded raw LF, second frame, or trailing bytes. The client fully writes and
  closes request stdin; stdout is fully consumed under the same exact bound;
  any stderr byte fails.
- Construct the production transport only after loading and rehashing the
  overlay. The factory returns an immutable transport bound to the exact
  canonical document and revision. It byte-compares the prove argument and
  validates every target/stage binding before any runner call; no mutable
  prove/stage/invoke cache or global registry exists.
- The full private overlay crosses the authenticated channel as the single
  operation configuration identity. It contains references, never credential
  values. The management object is inert in the target handler except for the
  server operation deadline. A second projected overlay/revision is excluded
  because it adds a parallel configuration identity without adding a trust
  boundary.
- `prove-target` revalidates local target OS/arch/EUID, host/control identity,
  manifest/current fence, and disposition. `stage-release` writes only the
  manifest-bound release beneath the declared staging root and returns an
  exact stage proof. `invoke` maps only the four public actions to the closed
  target executor. Its wire arguments contain only public action inputs and
  manifest/stage/target binding digests; control-local paths and expected
  operation/fence/fleet values remain client-side.
- Any extra output, truncation, nonzero/signal, schema drift, digest mismatch,
  target change, or timeout fails. No action is retried after an ambiguous
  transport result.
- Add one exact target entrypoint, `portable-ghar transport-serve`, intended as
  the configured `portable-ghar-v1` sshd subsystem. It accepts no flags or
  trailing argv, rejects a TTY, reads/writes only the same bounded canonical
  frame protocol, clears inherited environment, and dispatches only the three
  closed protocol actions into the target proof/stage/executor adapters. A
  shell invocation cannot supply an alternate command, path, environment, or
  action. Invalid accept mode, partial/extra frame, schema drift, or response
  write failure reaches no lifecycle `Apply` and leaves an ambiguous action
  non-successful.

**RED tests:**

- Strict overlay field/ref validation and no defaults.
- Exact OpenSSH argv/env; no shell; no user config/agent/password fallback.
- Bounded frame parse, target/stage/action proof substitution, changed host
  identity, cancellation, timeout, extra output, and ambiguity.
- Subsystem server rejects any argv, TTY, bare shell-mode request, partial or
  multiple frames, oversized input, schema drift, and extra output; a spy
  target executor proves zero apply calls on every rejection.
- Production command dependency tests prove a valid injected subsystem
  transport can complete while invalid/missing configuration fails before
  invocation.

**Converged review:**

- xAI/Grok 4.5 at high effort returned `PROCEED` after adversarially reviewing
  the root-immutable Darwin path-exec exception and the single-overlay
  identity. It found no material gap and confirmed that a daemon, SSH library,
  retry layer, connection pool, projection, or generic executor is not needed.
- Implementation preflight then disproved the inherited-descriptor premise for
  the OpenSSH client. The revised canonical-path contract above must receive a
  fresh high-effort distinct-family adversarial review before implementation;
  the earlier `PROCEED` does not approve this changed transport detail.
- The fresh xAI/Grok 4.5 high-effort pass agreed that the revised one-process
  path is at the simplicity floor and requested four specification
  tightenings: literal `-o` argv grammar, an explicit canonical-path
  definition, typed port/timeouts, and an explicit parent process-group
  deadline. All four are integrated above; no helper, copy, agent, daemon,
  lock, library, fallback, or second protocol was added. A changed-plan
  confirm-only pass remains required.
- The confirm-only pass closed those four points but surfaced additional
  detail. Accepted: fully enumerate identity/config options, make exact framing
  explicit, call out non-default-port known-host syntax, and state the existing
  new-process-group kill/wait behavior. Existing ancestor checks already
  exclude job-writable paths; existing descriptor `fstat` plus exact-path
  `lstat` is Darwin-compatible. Rejected as outside the declared authority
  boundary or needless duplication: a second configured credential root,
  filesystem-type allowlist, killing a successfully reaped root-immutable
  OpenSSH group, a global transport lock, and defense against control-UID/root
  mutation. The two-cycle cross-check cap is reached with no unresolved
  in-scope mechanism change; implementation proceeds against this integrated
  simple contract.

## Task 8: Concrete target lifecycle, disabled observer, and watchdog

**Files:**

- Add target-local files under `internal/productionruntime` for lifecycle
  composition, phase effects, storage revalidation, process records, and
  watchdog adapters.
- Modify `cmd/portable-ghar/main.go` to use the concrete target executor.
- Modify `cmd/portable-ghar-controller/production_controller.go` and add only
  narrowly required composition adapters in that command package.
- Modify `cmd/portable-ghar-watchdog/main.go` and tests.
- Modify QTS shell/systemd fixtures only where the new fixed subsystem/process
  entrypoint must be declared; do not enable anything.

**Target lifecycle composition:**

1. Load the private overlay and manifest with pinned no-follow bounded reads;
   require target OS/arch/EUID, manifest, binary digest, allowed action, and
   operator-approved resource/storage evidence before opening a lifecycle
   store.
2. Derive `OperationBinding`, prior/target manifests, storage reservation, and
   exact operation ID only from the request plus re-read target state. Never
   accept those values from an open caller field.
3. Compose the existing `LifecycleEngine` with concrete phase-scoped
   authorities. Each `Observe` reads the target state; each `Apply` performs
   exactly one fixed idempotent effect and re-reads it. Switches must enumerate
   every valid normal and compensation phase; the default is a typed failure.
4. Fixed effects cover only manifest-bound staging/retention/selection,
   disabled policy, exact process start/stop, quiescence, watchdog marker,
   fleet-fence action, legacy fixed command file, and retention proof. There is
   no generic command executor exposed to lifecycle callers.
5. `Recover` is used only for the exact operation ID already in the durable
   journal. Ambiguous readback retains journal/reservation and fails.

The high-effort xAI/Grok adversarial cross-check converged on the same minimum
shape with four binding clarifications: there is exactly one phase-to-effect
table; lifecycle code may call the narrow disabled primitives but the watchdog
never calls the lifecycle apply engine; every successful receipt comes from
the post-effect observation rather than the effect return; and phases that
depend on unavailable hosted-hold authority fail before their first write.
No retry layer, background reconciler, generic executor, second configuration
object, or second lifecycle/process authority is permitted.

**Checkpoint-resume refinement (2026-07-31):** The first Task 8 checkpoint
exposed a concrete crash-reentry gap: after the portable-fleet handoff but
before current-release selection, a fresh live-state proof no longer looks
greenfield even though the durable lifecycle journal still owns the exact
greenfield operation. The minimal continuation is split only for sequencing,
not into new authorities:

- **Task 8A — finish the existing greenfield operation path.** Keep the same
  greenfield `OperationBinding` and operation ID across a restart. Fresh entry
  requires absent fence/current/process/watchdog state. Re-entry requires the
  durable journal for that exact binding plus live state consistent with one
  of its completed phases. A post-fence orphan without that exact journal is
  a fail-before-write condition. `LifecycleEngine.Execute` remains the sole
  forward driver; do not add a resume service, second engine, new disposition,
  retry, or reconciler. Observation errors are never converted to an empty
  snapshot or `Absent`. Add the truthful read-only terminal verify path and
  wire the existing handler/executor into the command composition root.
- **Task 8B — complete the already-specified disabled observer and watchdog
  composition.** This remains required for the Phase 2 source-complete claim,
  but it follows the stable install/verify entry contract so it does not hide
  or duplicate crash-reentry authority.

The resumed high-effort xAI/Grok adversarial pass converged Task 8B on four
additional bindings without adding another service or state machine. A
fence-`none` orphan is stopped only through the exact persisted portable or
legacy process binding; no `none` process binding is invented. Storage
revalidation selects exactly one terminal, committed install reservation whose
journal, target manifest, storage budget, binding digest, and current overlay
revision all agree; a missing, duplicate, active, released, compensated, or
one-sided pair fails closed. The existing fixed controller `probe` is extended
compositionally so success proves both the disabled admin policy and the
health socket backed by the controller's durable/Docker zero observer; proof
fields are never synthesized after an observation error. Lifecycle lock polls,
fence reads, process stop/start, controller proof, Docker quiescence, and the
overall cycle use only durations already declared in the overlay. Narrow
observations remain capped by `Controller.OperationTimeout`; composite process
lifecycle calls and the dual-socket controller proof inherit the parent cycle's
`Watchdog.RestartDeadline`, while their existing `ProcessGrace` and per-socket
operation bounds remain linked sub-deadlines. Cancellation or partial progress
always fails closed. Do not add guessed timeout arithmetic: numeric adequacy is
activation evidence for the operator-selected overlay, not a new source
constant.

The exact Task 8A re-entry matrix is:

| Live state | Exact lifecycle journal | Result |
| --- | --- | --- |
| fence/current/process/watchdog absent | absent | admit fresh greenfield install |
| incomplete portable greenfield state | matching operation binding | admit the same greenfield operation and continue with `Execute` |
| incomplete portable greenfield state | absent, foreign, or ambiguous | fail before write |
| terminal portable state | terminal matching operation | read-only verify may succeed; install does not invent an upgrade path |
| any other state | any | fail before write |

The stable greenfield identity is mechanized, not inferred from intermediate
live state. It is always derived from the fixed start-of-operation tuple:
greenfield disposition, expected generation `0`, nil prior/current manifest,
the requested target manifest, portable target fleet, and overlay revision.
Fence/current/process/watchdog observations participate only in the admission
matrix above; they never re-key or rebind the operation and no new disposition
is introduced.

Reservation identity follows the same split. Open the descriptor-pinned
lifecycle store before deciding fresh versus re-entry. A fresh operation may
build and persist one new active reservation. Re-entry must read the exact
operation journal and reservation from that store, validate both against the
fixed binding, preserve the reservation identity fields byte-for-byte
(including `CreatedAt`, filesystem vector, roles, crash-orphans, and budget
digest), and revalidate that persisted envelope. Because the existing engine
requires an active request shape even when the persisted reservation is
committed or released, the request uses an active view of that same identity:
only state/transition-proof fields are normalized for request validation;
identity fields are never regenerated and `time.Now()` is never used. A
missing or one-sided journal/reservation pair, mismatched binding, malformed
state, or failed revalidation is an orphan/ambiguity failure before effects.

Task 8A TDD order is fixed: (1) make probe/inspection failures ambiguous rather
than absent; (2) prove matching-journal re-entry and orphan rejection; (3)
exercise crash points after promote, fence, marker, observer, zero proof, and
selection without duplicate effects; (4) implement byte-stable read-only
verify; (5) replace only the install/verify composition stubs. Pure-observation
phases never acquire a fallback write. Successful phase receipts still come
only from their post-effect observation.

**Exact process authority:**

- Store one root-owned `0600` canonical process record under the declared
  state root. Its exact schema-v2 document binds boot ID, PID namespace inode,
  PID, PGID, `/proc/<pid>/stat` start token, pinned executable digest/inode,
  private-overlay revision, manifest digest, fleet, and nonzero generation;
  its digest is the watchdog `ProcessIdentity`. Older, future, hybrid, or
  unknown-field records are rejected rather than migrated in place.
- Start the controller directly with fixed argv, a minimal environment,
  detached session/process group, bounded root-owned logs, and immediate
  record/readback. Never scan `/proc` by argv.
- Stop only while two fresh complete observations agree and boot ID, PID
  namespace, PID, live PGID, start token, executable, and record digest all
  match. A process is absent only when process-start observation is unavailable
  and an immediately following `getpgid` reports `ESRCH`; every mixed or
  uncertain result is unavailable and never authorizes a signal. Hold the same
  descriptor-pinned state-root/record identity through
  the decision, re-read the full record immediately before each signal, and
  signal the dedicated process group only while the direct process has not
  been reaped. The order is: revalidate → TERM → bounded wait → revalidate if
  still live → KILL → bounded wait → prove kernel/process-group absence while
  retaining the record → unlink/fsync the exact record → final absent
  readback. Any record mutation, inspection failure, still-live process, or
  proof timeout returns typed identity/stop failure and retains the record.
  PID/PGID reuse is never a signal target or evidence of success.

**Disabled observer composition:**

- Open SQLite with exact configured history limits and build the existing
  `state.ControllerAdapter`.
- Normalize a newer disabled/empty/zero policy, build `zeroDemandBroker`, and
  use the sealed unavailable external graph.
- Compose a complete local authority that lists recoverable assignments,
  derives cleanup specs from durable slot/build/generation identity, uses
  `DockerCLI` managed inspection/removal, runs cold reconciliation, revokes
  pre-running work, and emits a complete zero observation. Missing cleanup
  identity fails before socket creation.
- Compose fleet authority from the stable fence store: exact portable guard or
  exact legacy normalization proof; reject `none` for controller startup.
- Construct `disabledControllerProcess`; on partial open, close in reverse
  order and join close failures.

**Watchdog composition:**

- Load and bind the same overlay/manifest, lifecycle gate, storage envelope,
  fence authority, and process authority.
- Implement `Inspect`, `SafeStop`, `StartDisabled`, and `ProveDisabled` only;
  the package still imports no host transport, GitHub scale-set client, or
  lifecycle apply engine.
- `StartDisabled` uses the fixed process authority. `ProveDisabled` reads the
  local admin/health socket plus durable/Docker zero inventory and requires
  the exact process-record digest.

**RED tests:**

- Every target action has a positive synthetic temp-root path and a matrix of
  fail-before-write identity/mode/digest/fence/storage/process faults.
- Every lifecycle phase has observe-present/absent/ambiguous and idempotent
  apply/readback tests; every compensation path has crash-reentry coverage.
- Controller startup/shutdown persist newer disabled epochs, perform cold
  reconciliation, create no listener, and close partial components in reverse
  order.
- Watchdog portable/legacy/none behavior, process-record drift, PID reuse,
  storage stop, active lifecycle, disabled-proof failure, repeated crash, and
  close failure never false-success.
- Process-record replacement/unlink between match and TERM/KILL produces zero
  signal to the new occupant; slow death retains the record until absence is
  proven; post-stop inspect failure/wrong fence/foreign identity is failed,
  never healthy.
- Dependency tests retain the watchdog ban on GitHub/client/transport/apply
  packages.

## Task 9: Documentation, review replies, and full verification

**Files:**

- Update `README.md`, `docs/operations/production-lifecycle.md`, and the Task
  10/14 status language only where needed to describe the completed source
  mechanism and deferred operator/live gates.
- Preserve the approved Grafana/InfluxDB activation contract already present
  in `docs/operations/production-lifecycle.md`; do not implement deployment.

**Verification sequence:**

```bash
gofmt -w <changed Go files>
GOCACHE=/private/tmp/portable-ghar-pr15-go-cache GOTOOLCHAIN=go1.26.5 \
  go test -race ./... -count=1
GOCACHE=/private/tmp/portable-ghar-pr15-go-cache GOTOOLCHAIN=go1.26.5 \
  go vet ./...
GOCACHE=/private/tmp/portable-ghar-pr15-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool staticcheck ./...
GOCACHE=/private/tmp/portable-ghar-pr15-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool govulncheck ./...
bats tests/shell/qts/*.bats
python3 scripts/check_repository_metadata.py --root .
python3 scripts/check_workflow_policy.py .github/workflows
python3 scripts/ci/check_runner_debian_snapshot.py
python3 scripts/sanitize_public.py --tracked
./scripts/test-controller-runtime.sh --unit
```

- Re-run all available container/source-only gates. A macOS skip is not a
  positive Linux/Docker proof and must remain recorded as deferred.
- Reply to every exact-head PR review comment with the focused test/evidence,
  then resolve its thread only after readback.
- Create deliberate signed crash-safe commits, push, and wait for all hosted
  checks at the exact head.
- Seal the final base-to-head artifact (byte count + SHA-256), obtain a direct
  high-effort distinct-family exact-diff review through any eligible read-only
  route, and count only a matching-digest substantive approval. The provider
  and transport remain replaceable development tooling.
- Merge PR #15 normally, never with admin bypass. Read back the PR merge commit,
  signature, `origin/main`, and all required checks.
- Report the merged Phase 2 source checkpoint and the deferred Linux/Docker,
  reproducibility, forced-version-bump, sizing/cadence, immutable-release, and
  host-activation gates. Then pause.
