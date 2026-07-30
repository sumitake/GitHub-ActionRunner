# Portable-GHAR Task 13 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one non-mutating, fail-closed controller-runtime release gate
and one source-aware boundary suite that prevent the Phase 2 containment,
authority, resource, dependency, and public-safety contracts from silently
regressing.

**Architecture:** `tests/boundaries/runtime_boundary_test.go` is the durable
source-policy authority. It parses production Go syntax where structure
matters, inspects exact closed source anchors where a contract is deliberately
centralized, and enumerates tracked artifacts through Git. It never treats
comments, tests, or documentation as proof of a production invariant.
`scripts/test-controller-runtime.sh` is a small Bash orchestrator. It runs
fixed stage functions, captures all subordinate output in a private temporary
directory, emits exactly one closed JSON summary, and verifies that the
tracked worktree and index are byte-identical to their entry state. Unit mode
is portable and source-only. Full mode additionally requires a positively
identified Linux host, Docker, both explicit opt-in environment gates, and
prepared immutable image contexts before it runs any Docker, integration,
conformance, or chaos stage.

**Tech Stack:** Go 1.26.5, Go AST/parser/token packages, Git tracked-file
enumeration, Bash with `set -euo pipefail`, ShellCheck, `go tool shfmt`, Bats,
Python repository/sanitization checks, canonical JSON emitted from fixed
constants, opt-in Linux/Docker integration and chaos suites.

## Global Constraints

- The authoritative requirements are Task 13 in
  `docs/superpowers/plans/2026-07-11-controller-runtime.md`, the locked
  contracts in
  `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`, and
  the Phase 2 completion boundaries in
  `docs/superpowers/plans/2026-07-11-portable-ghar-program.md`.
- This task changes only:
  - `scripts/test-controller-runtime.sh`;
  - `tests/boundaries/runtime_boundary_test.go`;
  - formatting-only shfmt normalization in
    `deploy/qts/run-legacy-fenced.sh`; and
  - this implementation plan.
- No command in unit mode may invoke Docker, reach a live host, install a
  service, change QTS, change routing, change acquisition, publish an
  artifact, fetch an upstream archive, or prepare an ignored image context.
- Full mode may operate only against the local caller-selected Linux/Docker
  test fixture. It is still a test gate, not deployment authority. It has no
  RhoNAS/QTS target or remote-host path.
- Numeric tmpfs, memory, swap, CPU, concurrency, storage, and runner-release
  cadence values remain operator-open. The boundary suite proves that
  production accepts only a complete validated/evidence-bound tuple; it does
  not approve or introduce numeric values.
- An unavailable Linux/Docker prerequisite is `FAIL` for `--full`, never
  `PASS` or `SKIP`. Unit mode reports the full gate as `not_run`.
- Existing integration and chaos suites retain their own exact unsupported
  marker for direct local source-compilation checks. The runtime gate must
  never aggregate an operational skip into successful full evidence.
- The script never rewrites source, formats in place, runs a generator, runs
  an image-preparation script, downloads an archive, or changes the index.
- Subordinate command output is not forwarded on success or failure. The
  script emits one fixed-schema, identity-free JSON object to stdout and at
  most one fixed stage identifier to stderr. Raw paths, test fixtures,
  environment, commands, stderr, response bodies, and credentials never
  cross the summary boundary.
- Subordinate logs live below one `umask 077` temporary directory whose mode
  is positively checked as `0700`. Finalization removes that directory before
  emitting the terminal summary. A cleanup failure after otherwise successful
  stages selects the closed `cleanup` stage; after an earlier failure it
  preserves that first failed stage. Either path is terminal failure and can
  never be reported as success.
- Go test subprocesses alone run in a subshell with deterministic `umask 022`.
  This does not weaken the gate's private log posture: existing negative
  integrity tests deliberately create unsafe-mode fixtures and must not have
  the gate's `umask 077` silently mask those fixtures into safe objects.
- Staticcheck's own cache is rooted below the private gate directory and is
  removed with the subordinate logs. It must not write the caller's user cache
  or create durable repository state.
- Stage and helper functions explicitly propagate every failed predicate and
  command. They do not rely on Bash `errexit`, because functions invoked from
  `if` conditions inherit a context where `set -e` is suppressed.
- The script accepts exactly one argument, `--unit` or `--full`. Unknown,
  duplicate, missing, or extra arguments fail closed before any test stage.
- The script runs from its own canonical repository root rather than trusting
  the caller's current directory.
- The entry tracked-tree and index fingerprints are captured before stages
  and compared after stages. A changed tracked tree or index makes the gate
  fail even when every test command exited zero.
- A failure cannot be overwritten by cleanup or summary generation. The
  first failed stage remains the terminal stage; `cleanup` is selected only
  when cleanup is the first failure.
- The boundary suite scans production source only for production invariants.
  Test fixtures may contain negative examples, but fixture/public-identity
  scans cover every tracked fixture and example file.
- Go source analysis parses the complete production tree, rejects parse
  errors and dot imports, resolves normal/blank/aliased imports by import path,
  and binds protected calls to AST symbols rather than source substrings.
- Upstream `github.com/actions/scaleset` types are allowed only inside
  `internal/githubscale`; the exact blank dependency anchor in
  `internal/buildinfo/pins.go` is the sole exception.
- Kubernetes, ARC, runner-controller, container-hook, and job/service
  container orchestration dependencies are absent.
- Controller and watchdog production code may depend on narrow injected
  interfaces, but cannot import or mention a GitHub-variable, Cloudflare, or
  concrete routing-writer implementation.
- The runner Docker argv has no bind, mount, volume, device, socket, host
  network, privileged, or reusable-workspace surface. It joins only the
  issuer-bound adapter namespace and uses only bounded tmpfs paths.
- Runner and adapter argv proofs inspect only the returned `[]string` AST
  elements and their static literal fragments. Required options cannot be
  supplied by comments or unrelated source text.
- The adapter has exactly one read-only bind of its per-job broker directory.
  The broker's two private directories remain broker-only; no runner mount is
  introduced.
- Runner, adapter, broker, helper, and verifier retain read-only root,
  `CapDrop=ALL`, the closed seccomp profile, bounded CPU/memory/swap/PID/FD/
  tmpfs/log settings, and exact role-specific capabilities.
- The checked-in seccomp profile and its production parser must continue to
  deny namespace creation, namespace switching, raw/BPF operations, and
  prohibited socket classes.
- Only HTTP CONNECT and SOCKS5 CONNECT are accepted. Plaintext HTTP, SOCKS
  BIND, SOCKS UDP, trailing frames, unsupported ports, and non-canonical
  destinations remain rejected.
- DNS resolution yields `netip.Addr` values that are revalidated. Only a
  normalized literal address can enter the kernel dialer; no hostname reaches
  `net.Dialer`.
- Every job and DoH kernel dial is preceded by a durable, exact-slot,
  exact-generation, exact-class permit consumption. The boundary verifies
  AST call ordering and rejects a parallel or fallback dial site; comments
  cannot supply or reorder a permit call.
- Public-network constructors and kernel dial call sites are a closed
  package/function allowlist. Unix-socket clients remain separately
  classified. Production assignments to `http.DefaultClient`,
  `http.DefaultTransport`, or `net.DefaultResolver` are forbidden; explicit
  injected clients, transports, resolvers, and dialers remain required at
  security-sensitive public-network boundaries.
- All network concurrency, handshake, relay, FD, buffer, body, manifest, log,
  tmpfs, memory, storage, and dial budgets are bounded by validators. No zero
  or implicit production default becomes an approved value.
- The pinned module/toolchain, scale-set module, runner release/digest/source,
  base image digest, component image posture, archive locks, and
  `DisableUpdate=true` live compatibility check remain exact.
- No production `Secret.Bytes`, byte getter, escaping reader, or unbounded
  `io.ReadAll` API is permitted. A function-local identifier passed to
  `io.ReadAll` is allowed only when it has one dominating
  `io.LimitReader(...)` assignment and no reassignment.
- No upstream runner archive, upstream runner binary, ELF, Mach-O, PE image,
  package archive, mutable cross-job cache, host work directory, or updater
  staging directory is tracked.
- The mutable-cache prohibition applies to serving-runner state and
  cross-job/runtime caches. A caller-owned Go or Docker build cache on a
  disposable test host is tool state, not an approved runner cache.
- Whole-container removal remains the cleanup unit. Production code may not
  add a serving-runner `_work`, `_update`, `bin`, or `externals` file sweeper.
- All scale-set operations retain explicit context deadlines and the exact
  one-label/name plus `DisableUpdate=true` compatibility gate.
- All acquisition stop, narrowing, and effective-capacity reduction paths
  continue through `controller.AcquisitionTransitioner` and the epoch barrier.
- The shared fleet fence, all QTS lifecycle scripts, root checks, host
  identity checks, journal/resume boundaries, and disabled-default posture
  remain present.
- Private fixture identifiers are rejected by the Go boundary and the
  authoritative Python sanitizer. Public examples remain synthetic.
- The canonical Task 13 checkpoint is one signed commit after a matching exact
  direct xAI/Grok review. No broker lifecycle state is used or changed.

## Threat Model and Regression Classes

The gate is designed to stop source changes that remain individually
test-green but reopen a system boundary:

1. **Dependency expansion:** an ARC/Kubernetes/controller package or upstream
   type escapes the adapter package.
2. **Authority expansion:** controller/watchdog obtains a concrete routing
   writer, a second acquisition mutation path, or a hidden fallback.
3. **Container escape:** Docker socket/device/host networking, a mutable bind,
   a reusable workspace, extra capabilities, or a weaker seccomp profile.
4. **Parser/dial divergence:** plaintext or unsupported SOCKS behavior, a
   hostname reaches the kernel, DNS answers skip normalization, or a dial
   occurs before durable permit consumption.
5. **Resource fail-open:** a zero/default/unbounded budget or inconsistent
   tmpfs-memory-concurrency tuple is accepted.
6. **Upgrade regression:** scale-set self-update is re-enabled, pins become
   mutable, a runner file sweeper appears, or updater residue becomes a
   supported lifecycle.
7. **Secret/read regression:** an escaping secret getter or unbounded reader
   enters production code.
8. **Lifecycle regression:** fleet fencing/QTS scripts disappear or direct
   lifecycle effects bypass journal and read-back.
9. **Artifact/public-safety regression:** an upstream binary/archive, mutable
   cache, private identifier, or secret-shaped result enters the tracked tree
   or gate output.
10. **Evidence laundering:** a source-only skip, missing Docker, wrong host,
    or changed worktree is summarized as a successful full release gate.

## File and Dependency Map

### `tests/boundaries/runtime_boundary_test.go`

The test file owns:

- repository-root discovery;
- tracked-file enumeration through `git ls-files -z`;
- production Go-file enumeration;
- exact file reads with bounded sizes;
- Go AST parsing and import maps;
- string-literal and function-body extraction;
- the `io.ReadAll` boundedness analysis;
- tracked binary/archive/cache detection;
- fixed private-identifier scanning;
- source-anchor assertions for centralized contracts; and
- the top-level boundary test with independently named subtests.

It imports only the Go standard library. It does not shell out to a network
tool, execute production binaries, or mutate the checkout.

### `scripts/test-controller-runtime.sh`

The script owns:

- exact mode parsing;
- canonical repository-root discovery;
- private temporary log storage;
- entry/exit tracked-state fingerprints;
- fixed unit/full stage arrays;
- generic first-failure handling;
- fixed JSON serialization; and
- cleanup of temporary logs.

It does not own the semantics of an individual test. Each stage calls the
existing authoritative test/tool.

## Boundary Suite Design

### Repository and module contract

`TestRuntimeBoundary` first requires:

- module exactly `github.com/sumitake/portable-ghar`;
- `go 1.26.0`;
- `toolchain go1.26.5`;
- the exact pinned module versions already asserted by
  `internal/buildinfo/pins_test.go`;
- no `replace`, `exclude`, or `retract` directive;
- `scripts/test-controller-runtime.sh` present, regular, and executable; and
- every required QTS lifecycle script present, regular, executable, and
  tracked.

### AST import and authority contract

For every production `.go` file under `cmd/` and `internal/`:

- parse with `parser.AllErrors`;
- reject dot imports;
- reject Kubernetes/ARC/runner-controller/container-hook imports;
- reject `github.com/actions/scaleset` outside `internal/githubscale`, except
  the exact blank pin anchor;
- reject concrete GitHub/Cloudflare/routing-writer imports and the three route
  variable names from controller/watchdog production files; and
- require scale-set calls to stay inside `internal/githubscale`.

The scan also requires that `controller.AcquisitionTransitioner` remains the
sole exported transition dependency and that the controller/watchdog command
packages have no second concrete policy store or setter. This proof is
independent from the routing-authority proof: acquisition call sites are
enumerated by interface symbol, while controller/watchdog routing-writer
imports, concrete types, constructors, setters, and route-variable assignments
are rejected separately.

### Docker/container contract

The boundary extracts the AST bodies of:

- `(*DockerCLI).adapterCreateArgv`;
- `(*DockerCLI).runnerCreateArgv`; and
- the broker/helper/verifier constructors and audit validators.

It asserts:

- the runner body contains `--network container:` and no `--mount`,
  `--volume`, `--device`, `--privileged`, host network, Docker socket, or
  reusable-workspace literal;
- the runner has exactly three bounded tmpfs declarations and no host-backed
  work path;
- the adapter has `--network none`, exactly one `--mount`, the fixed broker
  destination, and `readonly`;
- every role drops all capabilities, is read-only, has no-new-privileges,
  exact seccomp, bounded CPU/memory/swap/PID/FD/tmpfs/log values, and no
  restart loop;
- helper capability is exactly `NET_ADMIN`; the other roles add none; and
- audit/read-back code rejects any unexpected bind, mount, device, capability,
  network, tmpfs, or security option.

The test parses `config/seccomp/portable-ghar-capless-v1.json` as JSON and
requires the closed namespace/raw/BPF/socket deny sets as well as the
production duplicate-field/semantic validator anchor.

### Network/parser/permit contract

The boundary builds a symbol-aware inventory of public-network constructors
and kernel dial sites across all production Go files. The closed allowlist
contains only:

- the network-jail literal dialer and permit-gated DoH connector;
- the bounded GitHub scale-set client and official runner-release observer;
- the Task 11 synthetic HTTPS listener; and
- the network verifier's explicit probe/flood/closed-denial functions.

Unix-domain `DialContext` sites are classified by their literal `unix` network
and are never accepted as public-network dial sites. A new public constructor,
`Dial`, `DialContext`, `DialTLSContext`, `http.Client`, or `http.Transport`
site fails until its package, function, authority, deadline, and permit
contract are deliberately reviewed and entered in the closed table.

The boundary then extracts `(*BrokerDialer).DialFrame` and requires:

- one `permits.Request` call site;
- one `literals.DialLiteral` call site;
- permit source position before literal dial source position;
- no `go` statement in the function;
- no direct `net.Dialer`, `net.Dial`, or syscall connect in that function;
- `LiteralDialer.DialLiteral` accepts `netip.Addr`, not a string; and
- `LiteralNetDialer.DialLiteral` uses only `address.String()` after canonical
  validation.

It also requires the existing behavioral authorities to remain present and
pass:

- `TestBrokerDialerRevalidatesThenPermitsEveryLiteralAttempt`;
- `TestBrokerDialerLiteralSkipsResolverAndRequiresPermit`;
- `TestBrokerDialerPermitFailurePreventsKernelDial`; and
- `TestDoHResolverUsesOnePermittedLockedPersistentConnection`.

It requires the HTTP/SOCKS parser's closed method/command checks, port policy,
trailing-data rejection, bounded reads, and fixed client/server concurrency
limits. It rejects source literals or switch arms that introduce HTTP
forwarding, SOCKS BIND, SOCKS UDP, or an additional proxy protocol.

### Secret and bounded-reader contract

The boundary parses the `redaction.Secret` method set and permits only the
closed exported methods `Use`, `Destroy`, `String`, and `MarshalJSON`. It
rejects exported byte slices, readers, strings containing material, or any
method named `Bytes`, `Reader`, `Raw`, `Reveal`, `Value`, or `Get`.

Every production `io.ReadAll` call must:

- directly wrap `io.LimitReader`; or
- consume a function-local identifier assigned once from `io.LimitReader`
  earlier in the same function and never reassigned before use.

The test fails with the exact file and line for any unbounded or ambiguous
read.

### Pins, sizing, upgrade, and lifecycle contract

Exact anchors require:

- the `buildinfo.Pins` runner version/digest/source and base-image digest;
- the live `RunnerSetting.DisableUpdate` check;
- one-label/name compatibility;
- `hostruntime.ValidateRunnerSizing` checked arithmetic across tmpfs, memory,
  swap, concurrency, and host reserve;
- config loading of the complete evidence-bound sizing tuple with no
  production numeric defaults;
- whole-container cleanup and positive absence;
- no live runner path sweeper;
- exact acquisition authority backed by
  `TestPollPermitFailureAbortsBeforeAcquireAndLeavesServiceReady`,
  `TestServiceTransitionCancelsAndJoinsOldOperationBeforeOpen`,
  `TestServiceDisabledTransitionRequiresListenerQuiescence`, and
  `TestServiceTransitionJoinTimeoutPersistsFatalBeforeTermination`;
- exact routing-failure durability backed by
  `TestReplayHostedExplicitRouteFailureIsDurableAndNeverAcknowledged` and
  `TestReplayHostedEmptyOwnershipProofIsDurableFailure`;
- fleet-fence guard/handoff checks in controller, watchdog, install, suspend,
  resume, rollback, and uninstall paths; and
- disabled acquisition as the only default/startup posture.

### Tracked artifact and fixture contract

For every tracked file:

- reject archive/package extensions and upstream runner names;
- reject ELF, Mach-O, fat Mach-O, PE, and ZIP/gzip archive magic where the
  path is not a deliberately registered text fixture;
- reject tracked `_work`, `_update`, runner payload, mutable cache, and image
  build-output paths;
- reject the fixed private-identifier patterns already used by the public
  sanitizer; and
- require all public fixture/exemplar values to remain under the synthetic
  identity vocabulary.

The authoritative Python sanitizer still runs in the unit gate. The Go scan is
an independent narrow fail-fast layer, not a replacement.

### Script source contract

The boundary reads the gate script and requires:

- Bash shebang and SPDX header;
- `set -euo pipefail`;
- exact `--unit|--full` parser;
- canonical repository root;
- `umask 077`, a private `0700` `mktemp` directory, cleanup-before-summary,
  and a terminal cleanup-failure branch;
- fixed stage functions and no `eval`, `source`, network client, package
  install, generator, image preparation, Git mutation, or deployment command;
- tracked-tree and index entry/exit fingerprint comparison;
- explicit Linux, Docker, and both environment gates for full mode;
- all required unit/full stage identifiers; and
- exactly one final JSON-emission call.

## Runtime Gate Contract

### Summary schema

The only stdout record is one line:

```json
{"schema_version":1,"gate":"portable-ghar-controller-runtime","mode":"unit","status":"pass","failed_stage":null,"linux_docker":"not_run","stages":[{"id":"source-integrity","status":"pass"}]}
```

Rules:

- field order is fixed as shown;
- `mode` is `unit` or `full`;
- `status` is `pass` or `fail`;
- `failed_stage` is null on success or one closed stage identifier;
- `linux_docker` is `not_run`, `ready`, or `failed`;
- stage IDs and statuses are fixed constants;
- no elapsed time, hostname, architecture, path, command, output, environment,
  identity, count derived from private input, or raw error is included.

### Unit stages

Unit mode runs, in order:

1. `source-integrity-entry`
   - capture tracked tree and index fingerprints;
2. `gofmt`
   - `gofmt -l` over `cmd`, `internal`, and `tests`; output must be empty;
3. `vet`
   - `GOTOOLCHAIN=go1.26.5 go vet ./...`;
4. `unit`
   - `GOTOOLCHAIN=go1.26.5 go test ./... -count=1`;
5. `race`
   - `GOTOOLCHAIN=go1.26.5 go test -race ./... -count=1`;
6. `network-authority`
   - run the four exact network-jail behavioral tests named above with verbose
     output and require all four exact top-level `PASS` records;
7. `acquisition-authority`
   - run the four exact acquisition transition tests named above with verbose
     output and require all four exact top-level `PASS` records;
8. `routing-authority`
   - run the two exact durable routing-failure tests named above with verbose
     output and require both exact top-level `PASS` records;
9. `boundary`
   - `GOTOOLCHAIN=go1.26.5 go test ./tests/boundaries -count=1`;
10. `staticcheck`
   - `GOTOOLCHAIN=go1.26.5 go tool staticcheck ./...`;
11. `module`
   - `GOTOOLCHAIN=go1.26.5 go mod verify`;
12. `shellcheck`
   - ShellCheck over every tracked `scripts/**/*.sh` and `deploy/**/*.sh`
     through a NUL-delimited array, plus the gate itself before it is tracked;
13. `shfmt`
    - `GOTOOLCHAIN=go1.26.5 go tool shfmt -d scripts deploy`, requiring empty
      diff;
14. `bats`
   - every `tests/shell/*.bats` and `tests/shell/qts/*.bats` through a
     NUL-delimited array;
15. `python-contract`
    - every tracked `tests/**/test_*.py` through `python3 -m unittest`;
16. `workflow-policy`
    - existing workflow policy checker;
17. `repository-metadata`
    - existing repository metadata checker;
18. `public-sanitizer`
    - `python3 scripts/sanitize_public.py --tracked`;
19. `chaos-source`
   - compile/run only `TestChaosSourceOptInBoundary` under `-tags=chaos -v`
     and require its exact top-level `PASS` record;
20. `source-integrity-exit`
    - compare the tracked tree and index with entry fingerprints.

`govulncheck` remains a CI and exact-task verification command, but is not a
unit gate stage: it may require advisory database network access and therefore
cannot be a deterministic offline release gate. It is run separately before
the Task 13 commit.

### Full-only stages

After all unit stages, full mode runs:

1. `linux-docker-preflight`
   - `uname -s` exactly `Linux`;
   - `PGHAR_INTEGRATION_DOCKER=1`;
   - `PGHAR_CHAOS_DOCKER=1`;
   - executable Docker client;
   - positive bounded `docker info`;
   - every registered image context and immutable input already present;
   - capture sorted container, network, and volume inventories;
   - require no pre-existing `portable-ghar-check-images:*` tag;
2. `image-reproducibility`
   - `bash scripts/ci/check-images.sh`;
3. `integration-authority`
   - `go test -tags=integration ./internal/networkjail -count=1`;
4. `conformance`
   - `go test -tags=integration ./tests/integration -count=1`;
5. `chaos`
   - `go test -tags=chaos ./tests/chaos -v -count=10`;
6. `docker-state-exit`
   - require container, network, and volume inventories byte-identical to
     entry and no residual `portable-ghar-check-images:*` tags;
7. `source-integrity-full-exit`
   - compare tracked tree and index again.

The full gate never runs `docker pull`, prune, network creation, or volume
creation. Image building is the only expected Docker inventory mutation, and
the fixed check tags must be absent at exit; the Docker builder cache is
allowed test-tool state, not NAS runner state. Any skip emitted by an
operational tagged test makes the full stage fail. Each tagged-stage log must
be nonempty and must contain a positive Go package result while containing no
exact unsupported-host marker, `SKIP`, or package-level skipped result before
the stage can record `PASS`. Each stage also requires the closed named
top-level `PASS` set expected from its authority packages, including all five
Linux integration-authority tests, one exact conformance test from each
package, and all nine chaos tests across all ten repetitions. Top-level success
is impossible until every full-only stage and both postflight comparisons
pass.

## Implementation Tasks

### Task 1: Add RED boundary tests

**Files:**

- Create `tests/boundaries/runtime_boundary_test.go`.

- [ ] Add repository/module/import/artifact scanners and the top-level
      subtests.
- [ ] Add scanner self-tests using synthetic Go source and tracked-name cases
      for at least:
  - disallowed ARC import;
  - scaleset import outside adapter;
  - unbounded `io.ReadAll`;
  - hidden parallel dial;
  - Docker socket/device/mount;
  - upstream binary/archive;
  - private fixture identity; and
  - missing lifecycle script.
- [ ] Run:

  ```sh
  GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    go test ./tests/boundaries -count=1
  ```

  Expected RED: the gate script is missing.

### Task 2: Add RED script-source and CLI-shape tests

**Files:**

- Continue `tests/boundaries/runtime_boundary_test.go`.

- [ ] Require exact script safety/stage/summary anchors.
- [ ] Test that the script rejects no argument, an unknown mode, and extra
      arguments without entering a stage.
- [ ] Test summary parsing against a small internal fixed-schema decoder; do
      not add a test bypass or alternate stage mode to the production script.
- [ ] From the parent Go test, prepend a failing fake `gofmt` to `PATH`, point
      `TMPDIR` at a controlled private parent, invoke the real unit gate, and
      require exactly one `gofmt` failure summary, no raw fake-tool output, and
      no residual gate directory.
- [ ] Re-run the boundary package.

  Expected RED: script is absent.

### Task 3: Implement the unit gate

**Files:**

- Create `scripts/test-controller-runtime.sh`.

- [ ] Implement exact argument parsing and dependency preflight.
- [ ] Capture private logs and tracked-state fingerprints.
- [ ] Implement fixed stage functions and first-failure handling.
- [ ] Normalize only Go test fixture creation to `umask 022`, contain the
      Staticcheck cache, and explicitly propagate every stage/helper failure.
- [ ] Implement the one-line fixed-schema JSON summary.
- [ ] Make the script executable.
- [ ] Run the narrow script-source/boundary tests.

  Expected GREEN.

### Task 4: Prove the unit gate and non-mutation

- [ ] Record entry `git status --short`.
- [ ] Run:

  ```sh
  GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    ./scripts/test-controller-runtime.sh --unit
  ```

- [ ] Parse stdout as one JSON object, require every listed stage `PASS`, and
      require `linux_docker=not_run`.
- [ ] Require no additional stdout or secret-shaped stderr.
- [ ] In a separate direct harness, prepend an `rm` wrapper that delegates
      every path except the known gate-log prefix and fails only that final
      removal. Rerun the otherwise-real unit gate, require one `cleanup`
      failure summary and nonzero exit, then remove the deliberate residue
      with the trusted parent shell. This is outside the boundary package so
      its nested unit stage does not recurse into itself.
- [ ] Record exit `git status --short`; require only the four planned Task 13
      files.

### Task 5: Implement and test the full-mode hard boundary

- [ ] Add the Linux/Docker/env/context preflight before any full-only effect.
- [ ] Prove with a fake unsupported-host/Docker harness that the first failed
      host predicate returns immediately and never invokes Docker.
- [ ] Add image, integration-authority, conformance, and chaos stages.
- [ ] Add exact skip-log rejection before marking a full stage `PASS`.
- [ ] Capture and compare container/network/volume inventories, reject
      pre-existing or residual fixed check-image tags, and prove the gate has
      no pull/prune/network-create/volume-create path.
- [ ] On this macOS host, run `--full` without opt-ins and require one
      identity-free failure summary at `linux-docker-preflight`; do not invoke
      Docker.
- [ ] Cross-compile the new boundary package and tagged suites for
      Linux/amd64.
- [ ] Keep the real Linux/Docker `--full` gate open for the separately
      approved execution target.

### Task 6: Exact verification and review

- [ ] Run:

  ```sh
  GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    go test -race ./tests/boundaries -count=50
  GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    go test ./... -count=1
  GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    go test -race ./... -count=1
  GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    go vet ./...
  HOME=/private/tmp/portable-ghar-home \
    GOPATH=/Users/josumi/go \
    GOMODCACHE=/Users/josumi/go/pkg/mod \
    GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    go tool staticcheck ./...
  HOME=/private/tmp/portable-ghar-home \
    GOPATH=/Users/josumi/go \
    GOMODCACHE=/Users/josumi/go/pkg/mod \
    GOCACHE=/private/tmp/portable-ghar-gocache \
    GOTOOLCHAIN=go1.26.5 \
    go tool govulncheck ./...
  ```

- [ ] Run the unit gate once more.
- [ ] Stage only the four planned Task 13 files.
- [ ] Seal the exact staged diff and request direct xAI/Grok
      `code-review`/governance review, read-only, against the full digest.
- [ ] Integrate only verified findings through RED-to-GREEN tests, rerun the
      affected and complete gates, and reseal if the tree changes.
- [ ] Require one matching-digest substantive approval with no blocking
      defect.
- [ ] Run `git diff --cached --check`.

### Task 7: Commit

- [ ] Verify the staged tree still matches the approved tree.
- [ ] Create the signed commit:

  ```sh
  git commit -S -m "test: gate portable GHAR controller runtime"
  ```

- [ ] Verify the signature in an isolated keyring if the sandbox blocks the
      local GPG trust database.
- [ ] Verify the commit tree equals the reviewed tree and the worktree is
      clean.

## Completion Evidence

Task 13 source is complete when:

- the boundary suite detects every enumerated regression class;
- `--unit` returns one secret-free JSON `PASS` without changing tracked state;
- `--full` fails closed before Docker on this unsupported local host;
- Linux/amd64 compilation succeeds;
- the exact staged artifact receives matching-digest direct Grok approval;
- the signed commit tree equals the reviewed tree; and
- the real Linux/Docker `--full` gate remains explicitly open rather than
  being represented as passed.

Phase 2 is not fully verified until the separately approved Linux/Docker full
gate passes. Task 13 does not select that target and does not change any host.
