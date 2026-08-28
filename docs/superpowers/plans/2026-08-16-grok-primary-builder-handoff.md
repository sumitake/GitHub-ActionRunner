# Portable GHAR Grok Primary-Builder Handoff

<!-- markdownlint-disable MD013 -->

> **For Grok:** Use `superpowers:subagent-driven-development` or the closest
> available equivalent to execute this plan task by task. You are the primary
> builder and integrator. Bounded subagents are authorized as described below;
> recursive delegation is not.

**Goal:** Continue Portable GHAR from its merged Phase 2 source-complete state,
finish the remaining pre-deployment build and disposable verification work,
and hand one clean exact head to Codex for a full adversarial review before
merge or deployment.

**Architecture:** Preserve the current review-gated platform design and its
single external routing authority, single scheduler, six-state route machine,
single signed acquisition-lease protocol, and single local lifecycle engine.
This document changes execution ownership, not architecture. The build boundary
ends after source-only Phase 3 Tasks 0-7 and available disposable evidence; live
deployment begins at Phase 3 Task 8 and is outside this handoff.

**Tech stack:** Go 1.26.6, Node.js 24.18.0, npm 12.0.1, TypeScript, Cloudflare
Workers and Durable Objects, SQLite, Docker/OCI, POSIX shell and Bats, GitHub
Apps and REST API, Grafana/InfluxDB projection assets, GitHub Actions, CodeQL,
Gitleaks, Trivy, and SBOM/provenance tooling already declared by the program.

## 1. Authority, starting state, and claim boundary

At planning time, the authoritative public base is `origin/main` at
`0d29cff` (`docs: simplify Portable GHAR reliability design (#27)`). The kickoff
prompt supplies the signed plan commit that Grok must use as its actual start
commit. Before editing, fetch `origin/main`, prove the supplied start commit is
present and clean, and stop if a newer non-dependency change overlaps the
planned paths or changes the architecture.

The authority order is:

1. `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`;
2. `docs/superpowers/plans/2026-07-11-failover-deployment.md`;
3. `docs/superpowers/plans/2026-07-11-portable-ghar-program.md`;
4. this execution handoff.

This handoff may narrow execution but never widen product authority. If two
documents conflict, follow the earlier item and record the conflict rather than
inventing a compromise.

The truthful starting claim is **Phase 2 source complete, pre-deployment**.
Linux/Docker operational evidence, two-rebuild reproducibility, the integrated
forced-runner-version-bump drill, numeric host sizing/cadence, external
failover, migration, activation, soak, and retirement are not complete merely
because source exists.

## 2. Grok ownership and bounded subagents

Grok is the primary builder at high effort. Grok owns objective interpretation,
contract preservation, interface decisions within the reviewed design, local
integration, conflict resolution, exact-head assembly, test adjudication,
signed checkpoints, and the final handoff package.

Subagents are enabled when their cost is lower than having the primary read or
implement the same independent material to the same standard. Apply all of
these bounds:

- at most three subagents active at once;
- no subagent may spawn another subagent;
- use isolated worktrees or strictly non-overlapping paths for writes;
- give each subagent a bounded brief, stop condition, and expected evidence;
- use the cheapest capable worker for read-heavy or mechanical work;
- never provide credentials, private overlays, host identities, tokens, keys,
  private logs, or deployment state to a subagent;
- treat every returned patch and conclusion as untrusted until Grok reviews the
  exact diff and runs the relevant tests; and
- subagents never merge, deploy, activate, mutate live services, edit standing
  directives, or make completion claims.

Good phase-local delegation units are:

| Unit | Scope | Safe parallelism | Return contract |
| --- | --- | --- | --- |
| Worker authority | Phase 3 Tasks 1-4 under `worker/src/` and focused Worker tests | After Grok freezes the cross-language protocol fixtures | Patch, tests run, invariants covered, unresolved risks |
| Controller integration | Task 0 and Task 5 Go packages and focused tests | After the same protocol fixtures are frozen | Patch, race-test evidence, deadline/failure-path summary |
| Operations and evidence | Task 6-7 schemas, read-only observability, synthetic tools/tests, and disposable evidence triage | In parallel where it does not change protocol or controller interfaces | Patch or distilled findings, validation commands, deferred gates |

Do not split one tightly coupled state machine across agents. A subagent may
inspect broad source or test output and return distilled findings, but Grok must
personally inspect every load-bearing contract and integrated change.

## 3. Simplicity and reliability rules

Use the existing primitives before adding anything. In particular:

- one Worker/DO authority, not a second coordinator;
- one Cron scheduler over the bounded fleet inventory, not alarms or a second
  registry;
- one signed lease protocol, not per-operation remote authority;
- one local lifecycle engine and phase table, not a parallel deployment engine;
- one schema-versioned read-only health snapshot and one-way telemetry adapter,
  not a second health authority; and
- existing journals, outboxes, receipts, and atomic-file helpers rather than a
  new database or generic workflow framework.

Every external call or wait must have an enforced bound or explicit lifecycle
owner. Persistent/external effects must be idempotent or safely re-entrant and
must be read back before success. Ambiguity, stale authority, identity mismatch,
misconfiguration, partial write, or failed security validation must fail safe;
auth and routing authority fail closed. Cleanup must be deterministic on every
exit path.

For each new dependency edge, add or update tests for timeout, unavailable,
partial success, concurrency/race, cold state, corrupt state, and
misconfiguration. Record the safe degradation path. Reject an abstraction or
component unless a current requirement cannot be met more simply with an
existing primitive.

## 4. Scope and hard prohibitions

### In scope

- Phase 3 Tasks 0-7 in
  `docs/superpowers/plans/2026-07-11-failover-deployment.md`;
- the corresponding Program Tasks 5-6 source and release-rehearsal work;
- source-only schemas, tools, docs, synthetic fixtures, and tests needed for a
  future private overlay and deployment;
- disposable Linux/Docker, reproducibility, and forced-version-bump evidence
  when the environment and separately gated settings already exist; and
- a draft governed source PR and exact review packet.

### Out of scope and prohibited

- Phase 3 Task 8 or later;
- live Cloudflare, GitHub routing, repository-variable, GitHub App, release
  setting, runner, consumer-workflow, QTS/RhoNAS, systemd, Grafana, or InfluxDB
  mutation;
- creating or populating a real private deployment overlay;
- selecting numeric tmpfs, memory, swap, concurrency, reserve, or cadence
  values on the operator's behalf;
- deployment, activation, migration, canary execution, soak, retirement,
  rollback-artifact deletion, tagging, release publication, or host changes;
- product dependencies on a collaboration broker, reviewer plugin, developer
  workspace, or named consumer repository; and
- merging the final build PR before Codex completes the exact-head adversarial
  review and all resulting findings are resolved.

If a disposable verification gate requires an operator-owned setting, secret,
host, or numeric decision, stop that gate and record it as deferred. Do not
substitute synthetic success for missing operational evidence.

## 5. Execution sequence

### Task A: Bind the build to the exact starting state

1. Fetch `origin/main` and verify the kickoff start commit, signature, tree, and
   clean status.
2. Inventory open non-dependency pull requests and local worktrees for overlap.
3. Create one Grok-owned topic worktree and branch from the supplied plan
   commit. Do not reuse an old Phase 2 worktree.
4. Read the four authority documents in section 1 and the Phase 2 completion
   boundary in
   `docs/superpowers/plans/2026-07-29-task14-implementation.md`.
5. Run the existing cheap baseline: repository metadata, sanitizer, Markdown,
   formatting, schemas, focused Go/Worker tests, and any platform-independent
   aggregate supported by the exact local toolchain.
6. Record genuine baseline failures before changing source. Do not repair
   unrelated dependency-update or broker/workspace issues.

**Checkpoint:** A clean isolated worktree, exact start identity, baseline
receipt, overlap inventory, and no product or live-state mutation.

### Task B: Close Phase 2 hard bounds needed by Phase 3

Execute Phase 3 Task 0 exactly. Use TDD for the bounded command, shutdown,
reclamation, release-observer, and lifecycle edges. Keep the operator-owned
numeric tuple unset and fail closed when it is absent.

Do not claim the deferred Phase 2 evidence PR complete. Source may implement
and test the gate, but positive Linux/Docker, immutable-release setting,
GitHub App, forced-version-bump, and operator sizing evidence remain separate
facts.

**Checkpoint:** Focused RED-to-GREEN tests, a signed task commit, a clean
worktree, and a short list of still-deferred operational evidence.

### Task C: Build the external routing authority

Execute Phase 3 Tasks 1-4 in order:

1. session, heartbeat, response binding, and lease protocols;
2. six-table Durable Object persistence and the single Cron scheduler;
3. idempotent GitHub routing outbox and the six-state route machine; and
4. canary, queue-risk, archive restriction, and governed legacy rollback.

Freeze canonical cross-language fixtures before parallel Go integration begins.
Use fake time and fault injection. Tests must cover replay, reordering, stale
evidence, old sessions, exact response binding, lease-generation monotonicity,
GitHub timeout/rate-limit/partial/ambiguous results, Cron interruption, archive
evidence expiry, failed canary, and crash re-entry.

**Checkpoint:** Worker lint, typecheck, Vitest, schema, and failover tests pass;
the route machine has exactly six authority states; one signed task commit is
clean and self-reviewed.

### Task D: Integrate the controller without another authority layer

Execute Phase 3 Task 5 against the frozen fixtures. Adapt the existing
acquisition permit provider and lifecycle engine; do not create a remote
per-operation authority or duplicate phase table.

Prove enforced send-anchored deadlines, policy-epoch and fleet-fence binding,
listener deadline enforcement, stale/superseded lease rejection, bounded
cancellation-resistant upstream behavior, restart with an empty lease cache,
and safe zero-capacity degradation.

**Checkpoint:** Focused and race tests pass, cross-language fixtures match, the
existing lifecycle regression suite remains green, and a signed task commit is
clean.

### Task E: Add notifications, read-only observability, and safe tools

Execute Phase 3 Tasks 6-7 as source-only work:

- independent bounded email and optional-webhook due work;
- the closed `health.Snapshot` export;
- a one-way least-privilege `portable_ghar_health` InfluxDB adapter;
- Grafana provisioning and cutover-evidence projection assets;
- the authoritative read-only cutover verifier; and
- strict private-overlay schemas plus fixed-action, target-safe operations
  tools tested only with synthetic/disposable inputs.

GitHub API receipts remain authoritative for active, queued, current-wait, and
pull-request identity. Grafana is a human projection and never becomes routing
authority or deployment proof. Zero idle means online self-hosted runners may
truthfully be zero.

Do not generate a real private overlay, connect real credentials, or call a
live mutation endpoint.

**Checkpoint:** Notification isolation, health-schema, telemetry, projection,
cutover-verifier, operation-journal, wrong-target, partial-effect, and crash
re-entry tests pass; a signed task commit is clean.

### Task F: Run the complete pre-deployment build matrix

Use the repository-pinned toolchains. At minimum run:

```sh
GOTOOLCHAIN=go1.26.6 go test -race ./...
GOTOOLCHAIN=go1.26.6 go vet ./...
GOTOOLCHAIN=go1.26.6 go tool staticcheck ./...
GOTOOLCHAIN=go1.26.6 go tool govulncheck ./...
npm ci --ignore-scripts
npm run worker:lint
npm run worker:typecheck
npm run worker:test
npm run schema:test
npm run schema:validate
npm run lint:docs
npm run format:check
bats tests/shell
python3 scripts/check_repository_metadata.py
python3 scripts/sanitize_public.py --tracked
scripts/ci/check-images.sh
scripts/verify-failover.sh
```

Also run supported disposable Linux/Docker gates, two independent runtime
rehearsals, the rebuild comparator, image/SBOM/license/scan/provenance checks,
and the integrated forced official runner-version-bump drill when their
separate prerequisites are available. Preserve exact logs, digests, platform,
toolchain, and skip reasons without committing generated artifacts or private
data.

The build is not failed merely because an operator-gated live prerequisite is
absent, but the corresponding verification remains incomplete and must be
reported as such. A deterministic source or disposable-test failure is a build
failure and must be fixed before handoff.

### Task G: Assemble the exact-head review checkpoint

1. Rebase once onto current `origin/main` before final sealing, resolving only
   genuine Portable GHAR conflicts.
2. Repeat the full applicable matrix on the rebased head.
3. Run the tracked-file sanitizer, secret scan, placeholder scan, and
   `git diff --check` last.
4. Verify every task commit is signed and the worktree is clean.
5. Push the exact branch and open or update one draft governed source PR. Do not
   merge it.
6. Create the review packet in the PR body or a public-safe tracked document.
   Do not add a second machine-readable evidence system.

The review packet must include:

- repository, PR URL, exact base SHA, exact head SHA, tree SHA, and ordered
  signed commit list;
- exact base-to-head diff byte count and SHA-256;
- changed-path inventory and architecture/spec mapping;
- complete command/result matrix with toolchain and platform;
- Linux/Docker, reproducibility, forced-bump, sizing, and operator-gated status
  stated separately;
- dependency failure/degradation matrix and any justified new component;
- subagent ledger naming each bounded task, files touched, tests run, returned
  risks, and Grok's integration adjudication;
- all known defects, disputed findings, deferred gates, and residual risks; and
- positive confirmation that no deployment, activation, host, consumer,
  Cloudflare, GitHub routing, or private-overlay mutation occurred.

### Task H: Stop for Codex adversarial review

After the exact-head draft PR and review packet exist, stop. The operator will
bring the immutable review identity to Codex.

Codex will review the complete base-to-head artifact with correctness,
security/bypass, operational reliability, simplicity, architecture fidelity,
failure degradation, concurrency, cleanup, and test-adequacy lenses. Codex may
inspect subagent output only as provenance; the integrated source and tests are
the authority.

Any source change after the review identity is sealed invalidates that review.
Grok must integrate valid findings, rerun affected and aggregate tests, reseal
the head, and return the changed artifact for confirmation. No approval by
Grok or one of its subagents substitutes for the distinct-family Codex gate.

## 6. Primary-builder definition of done

Grok's build assignment is complete only when all are true:

- Phase 3 source Tasks 0-7 are implemented without architecture divergence;
- deterministic source tests and every available disposable gate pass;
- unavailable operator-gated evidence is enumerated precisely, not counted;
- the repository remains standalone and contains no private values;
- task commits are signed, the final worktree is clean, and one exact draft PR
  is ready;
- the public-safe review packet is complete and reproducible; and
- no merge, deployment, activation, migration, host mutation, or live service
  mutation occurred.

This is a **pre-deployment build-complete review checkpoint**, not a claim that
Portable GHAR is deployed, production-ready, fully verified, or released.

## 7. Stop conditions

Stop and report rather than improvising when any of these occurs:

- a material architecture change is required;
- a third post-hoc review round exposes a new material bypass or edge class;
- the reviewed single-authority/single-scheduler/single-engine shape would be
  violated;
- a secret, private identity, live target, or operator-only numeric decision is
  required;
- an unbounded call, false success, dual acquisition authority, cleanup leak,
  non-idempotent persistent effect, or irreconcilable test result remains;
- the start base or final head cannot be proven exactly; or
- unrelated work would need to be repaired.

For a material architecture change, write a revised plan and obtain a
distinct-family adversarial architecture review before further codegen. Do not
continue by adding another patch layer.
