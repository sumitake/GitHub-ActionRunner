# Portable GHAR Public Foundation Implementation Plan

<!-- markdownlint-disable MD013 MD031 MD032 MD033 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (<code>- [ ]</code>) syntax for tracking.

**Goal:** Establish a safe public repository foundation for Portable GHAR with synthetic configuration contracts, enforceable sanitization, stable GitHub-hosted CI, supply-chain controls, operating documentation, and reproducible source releases.

**Architecture:** Phase 1 contains no live runner controller, host integration, Worker deployment, or routing writer. Go and TypeScript create only build/protocol seams; JSON Schema defines portable public inputs and sanitized outputs; repository policy, hosted CI, release gates, and GitHub settings fail closed before later runtime phases add privileged code.

**Tech Stack:** Go 1.26.6; Node.js 24.18.0 and npm 12.0.1; TypeScript 6.0.3; Ajv 8.20.0; Vitest 4.1.10; Python 3 standard library; ShellCheck, shfmt 3.13.1, and Bats; GitHub Actions on <code>ubuntu-24.04</code>; CodeQL; Gitleaks; Trivy; Syft/Anchore SBOM; GitHub artifact attestations.

## Global Constraints

- The review-gated design at <code>docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md</code> is authoritative. Implement phase 1 only.
- Do not add assignment acquisition, runner/adapter/broker/helper/verifier images, network rules, host watchdogs, deployment overlays, Worker endpoints, GitHub routing writes, credentials, or production changes.
- Do not commit deployment-specific operator identities, mailboxes, hosts, domains, addresses/ranges, paths, repository inventories, scale-set names, Cloudflare/GitHub deployment identifiers, schedules, logs, state, or secrets. The canonical public source identity <code>github.com/sumitake/portable-ghar</code> and governance owner <code>@sumitake</code> are approved narrow exceptions, not deployment identifiers.
- Public examples use only <code>example-fleet</code>, <code>owner/repository</code>, <code>operator@example.invalid</code>, and IANA documentation values. Unknown fields and inline secret values are errors.
- Private overlays and deployment-specific denylists stay untracked and never enter CI.
- Every PR job uses GitHub-hosted <code>ubuntu-24.04</code>, least privilege, timeout, concurrency cancellation, and checkout with <code>persist-credentials: false</code>. Never use <code>pull_request_target</code>.
- Stable required contexts are exactly <code>go</code>, <code>worker</code>, <code>shell</code>, <code>repository-metadata</code>, <code>sanitization</code>, <code>container</code>, and <code>dependency-review</code>.
- Pin every remote action to a full SHA with a release comment:

  | Action | SHA / release |
  | --- | --- |
  | actions/checkout | <code>9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0</code> / v7.0.0 |
  | actions/setup-go | <code>924ae3a1cded613372ab5595356fb5720e22ba16</code> / v6.5.0 |
  | actions/setup-node | <code>48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e</code> / v6.4.0 |
  | actions/upload-artifact | <code>043fb46d1a93c77aae656e7c1c64a875d1fc6a0a</code> / v7.0.1 |
  | github/codeql-action | <code>99df26d4f13ea111d4ec1a7dddef6063f76b97e9</code> / v4.37.0 |
  | actions/dependency-review-action | <code>a1d282b36b6f3519aa1f3fc636f609c47dddb294</code> / v5.0.0 |
  | gitleaks/gitleaks-action | <code>e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e</code> / v3.0.0 |
  | aquasecurity/trivy-action | <code>ed142fd0673e97e23eac54620cfb913e5ce36c25</code> / v0.36.0 |
  | actions/attest | <code>a1948c3f048ba23858d222213b7c278aabede763</code> / v4.1.1 |
  | anchore/sbom-action | <code>e22c389904149dbc22b58101806040fa8d37a610</code> / v0.24.0 |
  | bats-core/bats-action | <code>77d6fb60505b4d0d1d73e48bd035b55074bbfb43</code> / 4.0.0 |

- During pin verification, annotated release tags must be dereferenced to commits before this table is updated; workflows use the exact reviewed commit SHAs recorded above.
- The operator has pre-authorized the valid CODEOWNERS entry and source self-merge, scoped to phase-1 governance and scaffolding commits only; this is procedural authorization, not an implementation-readiness determination, and it does not waive the design-review gate. GitHub cannot count the author's self-approval, so sole-maintainer protection requires zero approvals while retaining ownership routing; independent-reviewer mode may later require one.
- A merge is not a deployment. Repository-setting writes occur only after all seven protected contexts have succeeded on one PR head SHA; <code>dependency-review</code> is PR-only and need not run on <code>main</code>.
- Every task stages only paths named in its Files block; repository-wide <code>git add .</code> and <code>git add -A</code> are prohibited.
- The phase-1 README must truthfully say pre-deployment. A later final production-posture update may claim live behavior only after deployment, rollback, failover/notification, workflow-migration, and read-back gates pass.

---

## File Map

- Toolchains/seams: <code>go.mod</code>, <code>go.sum</code>, <code>internal/buildinfo/</code>, <code>package*.json</code>, <code>worker/src/protocol/version.ts</code>.
- Contracts: <code>config/schema/</code>, <code>config/examples/</code>, <code>scripts/validate-config.mjs</code>.
- Policy: <code>scripts/sanitize_public.py</code>, <code>scripts/check_workflow_policy.py</code>, <code>scripts/check_repository_metadata.py</code>, and matching tests.
- Public docs: <code>docs/architecture/</code>, <code>docs/security/</code>, <code>docs/operations/</code>, then final <code>README.md</code>.
- Governance/automation: root community files, <code>.github/</code> templates, workflows, Dependabot, release scripts, and settings bootstrap.

### Task 1: Scaffold pinned toolchains and non-operational seams

**Files:**
- Create: <code>.editorconfig</code>, <code>.gitattributes</code>, <code>.gitignore</code>, <code>.dockerignore</code>, <code>.nvmrc</code>, <code>.markdownlint-cli2.jsonc</code>
- Create: <code>go.mod</code>, <code>go.sum</code>, <code>internal/buildinfo/buildinfo.go</code>, <code>internal/buildinfo/buildinfo_test.go</code>
- Create: <code>package.json</code>, <code>package-lock.json</code>, <code>eslint.config.mjs</code>, <code>tsconfig.base.json</code>
- Create: <code>worker/package.json</code>, <code>worker/tsconfig.json</code>, <code>worker/vitest.config.ts</code>, <code>worker/src/protocol/version.ts</code>, <code>worker/test/protocol/version.test.ts</code>
- Create: <code>images/manifest.json</code> and README-only directories for <code>images/{runner,network-adapter,network-broker-parser,network-broker-dialer,network-helper,network-verifier}</code> and <code>deploy/{qts,systemd}</code>

**Interfaces:** Produces <code>buildinfo.Info() BuildInfo</code>, <code>HEARTBEAT_PROTOCOL_VERSION = 1</code>, and <code>{"version":1,"images":[]}</code>; no executable or deployable runtime.

- [ ] Write failing Go and Vitest assertions:
~~~go
if got := Info(); got.Version != "dev" || got.Commit != "unknown" { t.Fatalf("%#v", got) }
~~~
~~~ts
expect(HEARTBEAT_PROTOCOL_VERSION).toBe(1);
~~~
- [ ] Run <code>go test ./internal/buildinfo</code> and <code>npm test --workspace worker</code>. Expected: both fail because implementations are absent.
- [ ] Set module <code>github.com/sumitake/portable-ghar</code>, <code>go 1.26.0</code>, toolchain <code>go1.26.6</code>; add tools actionlint v1.7.12, govulncheck v1.6.0, staticcheck v0.7.0, shfmt v3.13.1.
- [ ] Implement immutable <code>BuildInfo</code> defaults and the protocol constant. The root package owns the only lockfile and declares exactly one npm workspace, <code>worker</code>; no nested lockfile is allowed. Pin Node/npm and exact dependencies: Ajv 8.20.0, ajv-formats 3.0.1, ESLint 10.7.0, typescript-eslint 8.63.0, TypeScript 6.0.3, Vitest 4.1.10, Prettier 3.9.5, markdownlint-cli2 0.23.0, yaml 2.9.0, Wrangler 4.110.0, Workers types 5.20260708.1. Assert the published peer ranges are satisfied before locking. Configure Markdown lint to allow long plan lines, inline HTML, and Go tabs inside code blocks while retaining structural rules.
- [ ] Ignore environment/key/private-overlay/state/database/dist/cache paths. Image and deploy READMEs must say real paths, identities, schedules, networks, and Dockerfiles are deferred.
- [ ] Run <code>unformatted="$(find internal/buildinfo -type f -name '*.go' -print0 | xargs -0 gofmt -l)"; test -z "$unformatted" && go test ./internal/buildinfo && npm ci --ignore-scripts && npm run worker:lint && npm run worker:typecheck && npm run worker:test</code>. Expected: no unformatted path, Go <code>ok</code>, one Vitest pass, all checks exit 0 without rewriting source.
- [ ] Commit: stage only <code>.editorconfig .gitattributes .gitignore .dockerignore .nvmrc .markdownlint-cli2.jsonc go.mod go.sum internal/buildinfo package.json package-lock.json eslint.config.mjs tsconfig.base.json worker images deploy</code>, inspect the staged diff, then <code>git commit -S -m "build: scaffold public foundation toolchains"</code>.

### Task 2: Define strict synthetic schemas and examples

**Files:**
- Create: <code>config/schema/{fleet,host-profile,public-log-event,notification-event}.schema.json</code>
- Create: <code>config/examples/{fleet,host-profile,public-log-event,notification-event}.example.json</code>
- Create: <code>scripts/validate-config.mjs</code>, <code>tests/config/schema-validation.test.mjs</code>

**Interfaces:** Produces Draft 2020-12 schemas with closed objects and <code>validateFile(schemaPath, dataPath)</code>.

- [ ] First test all four examples plus negatives for unknown fields, inline secrets, non-synthetic repository values, host paths/identities/schedules, missing blocked egress classes, missing per-repository maxima or archive-eligibility state, IPv6 other than <code>deny</code>, raw log fields, and notification free text.
- [ ] Run <code>npm run schema:test</code>. Expected: FAIL because validator/schemas do not exist.
- [ ] Implement Ajv 2020 strict/all-errors validation. Fleet requires capacity units/profiles, weighted repositories plus aging, per-repository effective-concurrency maxima and archive-eligibility state (<code>active</code>/<code>archived-disabled</code>/<code>pending-reactivation</code>), host-profile reference, public-IPv4-only network policy with all eight enumerated blocked classes, 60-second evaluation, 360-second stale default, two unhealthy observations, canary safe-hosted policy, notification flags, and secret-reference names only.
- [ ] Host schema permits adapter <code>qts|systemd</code>, portable kernel/Docker capabilities, non-root/degraded-root declaration, and conformance probe names; it rejects deployment facts.
- [ ] Log schema allowlists identifiers, component/event/severity/reason, aliases, receipt time, and build ID. Notification schema allowlists event/transition ID, synthetic display name, repository aliases, confirmed route, reason code, Worker receipt time, and generic action.
- [ ] Run <code>npm run schema:test && npm run schema:validate</code>. Expected: all tests pass and output <code>validated 4 synthetic examples</code>.
- [ ] Commit: <code>git add config scripts/validate-config.mjs tests/config && git commit -S -m "config: define synthetic public contracts"</code>.

### Task 3: Enforce public-source sanitization

**Files:**
- Create: <code>scripts/sanitize_public.py</code>, <code>.sanitization-allowlist.json</code>, <code>.gitleaks.toml</code>
- Create: <code>tests/sanitization/test_sanitize_public.py</code>, <code>tests/sanitization/fixtures/fixture-lines.txt</code>

**Interfaces:** CLI <code>--tracked</code>, repeatable <code>--generated PATH</code>, optional <code>--private-denylist PATH</code>; diagnostics <code>path:line:rule: message</code>.

- [ ] Write failing tests for private/loopback/link-local/CGNAT/IPv6 literals, PEM blocks, token/JWT/JIT shapes, personal/NAS paths, non-example mail/domains, deployment identifiers, raw artifacts, archive members, symlinks, oversized/unscannable binaries, and optional private patterns. Add positive tests for the exact canonical source/import prefix <code>github.com/sumitake/portable-ghar</code> and exact CODEOWNERS entry <code>* @sumitake</code>; near-miss usernames, repositories, or placements remain findings.
- [ ] Test exact allowlist entries <code>{path,line,rule,sha256,reason}</code>; changed content/line, wildcard paths, global regex exemptions, duplicate entries, and unknown rules must fail.
- [ ] Run <code>python3 -m unittest discover -s tests/sanitization -p 'test_*.py' -v</code>. Expected: FAIL because scanner is absent.
- [ ] Implement <code>tracked_files</code> using <code>git ls-files -z</code>, explicit generated-path walking, safe zip/tar member inspection, 25 MiB/file cap, sorted findings, content-hash allowlists, and private-denylist rules loaded only from the supplied untracked file. When a private denylist is supplied, also scan every reachable branch-introduced blob and Git metadata (commit messages, author/committer identities, tag messages, and deleted-file paths), not only the current tracked tree, so a deployment identifier that was committed and later deleted cannot pass a tree-only scan yet remain recoverable from history. Encode the repository URL/import prefix and CODEOWNERS line as named exact-value/context exceptions, never broad username or GitHub-domain exemptions.
- [ ] Configure Gitleaks defaults only:
~~~toml
title = "Portable GHAR public-source secret policy"
[extend]
useDefault = true
~~~
- [ ] Run unit tests and <code>python3 scripts/sanitize_public.py --tracked</code>. Expected: tests pass; scanner prints <code>sanitization passed</code>.
- [ ] Commit: <code>git add scripts/sanitize_public.py .sanitization-allowlist.json .gitleaks.toml tests/sanitization && git commit -S -m "security: enforce public-source sanitization"</code>.

### Task 4: Add governance, contribution, and security policy

**Files:**
- Verify and retain unchanged: <code>LICENSE</code>
- Create: <code>SECURITY.md</code>, <code>CONTRIBUTING.md</code>, <code>CODE_OF_CONDUCT.md</code>, <code>CHANGELOG.md</code>, <code>THIRD_PARTY_NOTICES.md</code>
- Create: <code>.github/CODEOWNERS</code>, <code>.github/PULL_REQUEST_TEMPLATE.md</code>, <code>.github/ISSUE_TEMPLATE/{bug.yml,feature.yml,config.yml}</code>
- Create: <code>scripts/check_repository_metadata.py</code>, <code>tests/repository/test_governance.py</code>

**Interfaces:** Metadata checker returns nonzero for missing/malformed governance, unsafe issue fields, or missing redaction acknowledgements.

- [ ] Write tests requiring all files, the existing MPL-2.0 license, private-reporting instructions, exact CODEOWNERS content <code>* @sumitake</code>, PR public-safety checklist, structured issue forms, and warnings never to paste logs/config/state.
- [ ] Run <code>python3 -m unittest tests.repository.test_governance -v</code>. Expected: FAIL with missing files.
- [ ] Verify <code>LICENSE</code> contains <code>Mozilla Public License Version 2.0</code> and retains current SHA-256 <code>3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04</code>. Expected: PASS with no file change; on mismatch, stop for reconciliation rather than replacing it.
- [ ] SECURITY routes reports only through GitHub private vulnerability reporting. CONTRIBUTING requires TDD, synthetic fixtures, signed commits, action SHA pins, and hosted CI. CODEOWNERS contains exactly <code>* @sumitake</code>, preserving valid ownership routing even when sole-maintainer approval count is zero.
- [ ] Run metadata tests and <code>python3 scripts/sanitize_public.py --tracked</code>. Expected: PASS.
- [ ] Commit: <code>git add SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md CHANGELOG.md THIRD_PARTY_NOTICES.md .github scripts/check_repository_metadata.py tests/repository/test_governance.py && git diff --exit-code -- LICENSE && git diff --cached --exit-code -- LICENSE && git commit -S -m "community: add public governance baseline"</code>.

### Task 5: Document architecture and trust boundaries

**Files:**
- Create: <code>docs/architecture/overview.md</code>, <code>docs/security/trust-boundaries.md</code>
- Create: <code>scripts/docs/{check-links,check-command-examples}.mjs</code>, <code>tests/repository/{test_docs_contract.py,test_docs_tools.py}</code>

**Interfaces:** Docs define stable links/headings consumed by README; test helper <code>assert_sections(path, headings)</code>.

- [ ] First assert architecture headings for components, data flow, capacity/fairness, persisted lifecycle, external authority, and residual risks; trust headings for trusted/untrusted/bounded credentials, Docker-host-equivalent authority, egress barrier, shared kernel, and non-claims. Tool tests require local links/anchors to resolve, every fenced operator command to map to a planned/existing executable, and external links to be syntax-checked without a flaky network dependency.
- [ ] Run <code>python3 -m unittest tests.repository.test_docs_contract -v</code>. Expected: FAIL with missing docs.
- [ ] Write outcome-first docs: no inbound host route; one fresh runner/job; helper exits before verifier/listener; Worker+one Durable Object/fleet is sole automatic routing writer; JIT is bounded, not claimed invisible; VM-grade isolation is explicitly not claimed. Implement deterministic link/anchor and command-example checkers with synthetic fixtures and no shell evaluation.
- [ ] Run docs tests, markdown lint, and sanitization. Expected: PASS.
- [ ] Commit: <code>git add docs/architecture docs/security scripts/docs tests/repository/test_docs_contract.py tests/repository/test_docs_tools.py && git commit -S -m "docs: explain architecture and trust boundaries"</code>.

### Task 6: Document lifecycle, deployment, failover, migration, and operations

**Files:**
- Create: <code>docs/operations/{production-lifecycle,deployment-and-rollback,failover-and-notifications,workflow-migration,operations}.md</code>

**Interfaces:** Operational runbooks link to architecture/trust docs and contain positive read-back gates, not deployment-specific commands.

- [ ] Extend docs tests to require: persisted controller states and safe upgrade; host-profile probes and dark deployment; mutually exclusive rollback barrier; server-owned enrollment epochs; heartbeat replay/order rules; transition/outbox/read-back; canary-gated failback; independent email/webhook retries; stable workflow checks and hosted rollback; watchdog authority; incident evidence and retention.
- [ ] Run docs tests. Expected: FAIL naming all five missing files/headings.
- [ ] Write all runbooks with synthetic commands only. Explicitly keep secret-bearing, release, deployment-write, and unsupported jobs hosted; legacy and new fleets must never acquire concurrently during rollback; notification failure never blocks routing safety.
- [ ] Run docs tests, markdown lint, and sanitization. Expected: PASS.
- [ ] Commit: <code>git add docs/operations tests/repository/test_docs_contract.py && git commit -S -m "docs: add public production and migration runbooks"</code>.

### Task 7: Write the truthful phase-1 public README

**Files:** Create <code>README.md</code>; modify <code>tests/repository/test_docs_contract.py</code>.

**Interfaces:** README is the truthful pre-deployment public entrypoint and links every phase-1 contract/runbook; the later production gate owns any live-posture update.

- [ ] First require these sections in order: pre-deployment status/experimental upstream warning; purpose; architecture; trust boundaries; intended production lifecycle; deployment/rollback gates; failover/notifications design; workflow migration plan; operations; repository map; development/CI; release/security; docs/license. Reject unqualified claims that the controller, failover, notifications, migration, or rollback is live or verified.
- [ ] Run the README contract test. Expected: FAIL because README is absent.
- [ ] Write the README outcome-first: public-preview <code>actions/scaleset</code>, not official GitHub, container-grade only, no hosted service, and pre-deployment/unverified runtime posture. Use a generic Mermaid diagram and no deployment-specific identifiers. State that the final production-posture section is updated only after live deployment, rollback, failover/notification, workflow-migration, and read-back gates pass. Mirror the reference structure—posture, architecture, authority, lifecycle, deployment/rollback, workflows, map, commands—without copying private content.
- [ ] Run docs tests, link/Markdown checks, and sanitization. Expected: PASS.
- [ ] Commit: <code>git add README.md tests/repository/test_docs_contract.py && git commit -S -m "docs: add public project entrypoint"</code>.

### Task 8: Enforce workflow policy and stable hosted checks

**Files:**
- Create: <code>scripts/check_workflow_policy.py</code>, <code>tests/repository/test_workflow_policy.py</code>
- Create: <code>.github/workflows/ci.yml</code>, <code>scripts/ci/check-images.sh</code>, <code>tests/shell/check-images.bats</code>

**Interfaces:** Policy checker validates reviewed action SHA+release, triggers, hosted runner, permissions, checkout, timeout, concurrency, and unique stable contexts.

- [ ] Tests first: reject tag/branch/39-char refs, unknown full SHA, missing release comment, Docker action without digest, unsafe PR trigger, self-hosted/expression runner, write-default permission, missing timeout/concurrency, checkout credential persistence, and duplicate contexts.
- [ ] Run <code>python3 -m unittest tests.repository.test_workflow_policy -v</code>. Expected: FAIL.
- [ ] Implement a fail-closed parser with the reviewed-pin table in Global Constraints. Local <code>./</code> actions pass; multiline/aliased constructs the checker cannot prove safe fail.
- [ ] Create <code>ci.yml</code> on push/PR/manual with jobs:
  - <code>go</code>: recursively enumerate <code>*.go</code> with NUL-safe <code>find</code>/<code>xargs</code>, run <code>gofmt -l</code>, and fail on any output; then vet, test, race, staticcheck, govulncheck. CI formatting checks report diffs only and never run <code>gofmt -w</code>, <code>shfmt -w</code>, or Prettier write mode;
  - <code>worker</code>: npm ci, ESLint, typecheck, Vitest;
  - <code>shell</code>: ShellCheck, shfmt, Bats;
  - <code>repository-metadata</code>: JSON/YAML, schemas, actionlint, Markdown, formatting, SPDX headers, policy checker;
  - <code>container</code>: Trivy filesystem vulnerability/secret and config/misconfiguration scans plus manifest-driven reproducible build checks. Empty phase-1 image manifest passes explicitly; later Dockerfiles must register and build twice to identical image IDs.
- [ ] Run unit tests, <code>go tool actionlint .github/workflows/*.yml</code>, and <code>python3 scripts/check_workflow_policy.py .github/workflows</code>. Expected: PASS and five unique stable contexts.
- [ ] Commit: <code>git add scripts tests/repository/test_workflow_policy.py tests/shell .github/workflows/ci.yml && git commit -S -m "ci: add stable hosted checks"</code>.

### Task 9: Add sanitization, CodeQL, dependency review, and Dependabot

**Files:**
- Create: <code>.github/workflows/{sanitization,codeql,dependency-review}.yml</code>
- Create: <code>.github/dependabot.yml</code>
- Modify: <code>tests/repository/test_workflow_policy.py</code>, <code>tests/repository/test_governance.py</code>

**Interfaces:** Adds remaining stable contexts <code>sanitization</code> and <code>dependency-review</code>; CodeQL scans Go plus JavaScript/TypeScript.

- [ ] First assert triggers/permissions: sanitization and CodeQL run push, PR, weekly schedule, manual; dependency review runs PR; CodeQL matrix is exactly <code>go</code> and <code>javascript-typescript</code>; Dependabot ecosystems are actions, gomod, npm, and Docker in all six future image directories: <code>runner</code>, <code>network-adapter</code>, <code>network-broker-parser</code>, <code>network-broker-dialer</code>, <code>network-helper</code>, and <code>network-verifier</code>.
- [ ] Run repository tests. Expected: FAIL with missing workflows/config.
- [ ] Sanitization checks out full history, runs Gitleaks over the base-to-head branch-introduced range on PRs and complete reachable history on push/schedule/manual, then runs generic tracked/generated scans; it never receives the private denylist. Dependency review fails on high vulnerabilities and denied licenses. CodeQL uses only GitHub-hosted runners and <code>security-events: write</code>.
- [ ] Dependabot groups safe minor/patch updates weekly, caps open PRs, and never coexists with Renovate.
- [ ] Run actionlint, policy checker, metadata tests, and sanitization. Expected: all seven stable contexts discovered exactly once.
- [ ] Commit: <code>git add .github tests/repository && git commit -S -m "security: add hosted analysis and dependency automation"</code>.

### Task 10: Add reproducible source release, SBOM, scans, and provenance

**Files:**
- Create: <code>release/manifest.json</code>, <code>scripts/release/package-source.sh</code>, <code>tests/shell/package-source.bats</code>
- Create: <code>.github/workflows/release.yml</code>

**Interfaces:** <code>package-source.sh VERSION OUTPUT_DIR</code> creates one deterministic source tarball; manifest lists allowed release subjects and forbids unregistered binaries/images.

- [ ] Bats first: two packages of one commit produce identical SHA-256; dirty tree, invalid version, missing source epoch, symlink escape, or unregistered output fails.
- [ ] Run <code>bats tests/shell/package-source.bats</code>. Expected: FAIL because packager is absent.
- [ ] Implement <code>git archive</code> with prefix <code>portable-ghar-$VERSION/</code>, commit-derived <code>SOURCE_DATE_EPOCH</code>, gzip without timestamp, clean-tree check, and manifest verification. Phase 1 manifest permits only the source archive.
- [ ] Tag workflow: clean checkout; full seven-check command suite; package; Trivy scan source/dist; generic sanitization of archive members; Anchore SPDX JSON SBOM; third-party license inventory; SHA-256 file; provenance attestation for archive/SBOM/checksums with pinned <code>actions/attest</code>; immutable GitHub release upload. Permissions are <code>contents: write</code>, <code>id-token: write</code>, <code>attestations: write</code> only in the release job.
- [ ] Run Bats, actionlint, action-pin policy, and local package twice. Expected: identical checksums and no unregistered artifact.
- [ ] Commit: <code>git add release scripts/release tests/shell/package-source.bats .github/workflows/release.yml && git commit -S -m "release: add SBOM and provenance pipeline"</code>.

### Task 11: Codify repository settings and protected-main bootstrap

**Files:**
- Create: <code>scripts/repository/configure.sh</code>, <code>tests/shell/repository-configure.bats</code>
- Create: <code>docs/operations/repository-bootstrap.md</code>

**Interfaces:** <code>configure.sh --check REPOSITORY</code> is read-only; <code>configure.sh --apply-foundation REPOSITORY</code> and <code>configure.sh --apply-ruleset REPOSITORY PR_NUMBER</code> require explicit confirmation and admin access.

- [ ] Bats first with a stub <code>gh</code>: reject missing repository, non-public repo, absent PR number/head SHA, any of the seven contexts missing or unsuccessful on that PR head, unresolved independent CODEOWNERS mode, wrong API responses, and any unconfirmed apply.
- [ ] Run Bats. Expected: FAIL because script is absent.
- [ ] Use GitHub REST API version <code>2026-03-10</code>. Foundation mode sets default workflow token read-only; Actions cannot approve PRs; selected actions are GitHub-owned plus only Gitleaks, Trivy, Anchore SBOM, and Bats; delete branches after merge; merge commits off; squash/rebase on; alerts/security updates/private reporting on; secret scanning, push protection, validity checks, and non-provider patterns on when supported. Read every value back.
- [ ] Ruleset mode first proves all seven contexts succeeded on one PR head SHA, then creates active <code>main</code> rules for PRs, resolved conversations, linear history, signed commits, no deletion/force-push, and strict required checks. <code>dependency-review</code> is observed on that PR and is not required to run on <code>main</code>. Sole-maintainer mode keeps CODEOWNERS routing but requires zero approvals and disables code-owner enforcement because self-approval cannot count; independent-reviewer mode may later require one approval and code-owner review. No bypass is created by default.
- [ ] Document the two-stage order: run all seven checks on the bootstrap PR head, read back each successful context for that exact SHA, merge under the operator's pre-authorization, apply settings, apply ruleset, read back JSON, and record ruleset ID. Do not execute mutating modes during this source task.
- [ ] Run Bats and <code>shellcheck scripts/repository/configure.sh</code>. Expected: PASS with captured endpoints/payloads exactly matching the runbook.
- [ ] Commit: <code>git add scripts/repository tests/shell/repository-configure.bats docs/operations/repository-bootstrap.md && git commit -S -m "ops: codify secure repository settings"</code>.

### Task 12: Final full-matrix and public-safety gate

**Files:** Modify only files already listed if verification exposes a defect.

**Interfaces:** Produces a clean, signed, phase-1 branch ready for review; no merge, settings write, release, or deployment.

- [ ] Run:
~~~sh
unformatted="$(find . -type f -name '*.go' -not -path './.git/*' -print0 | xargs -0 gofmt -l)"
test -z "$unformatted" || { printf '%s\n' "$unformatted"; exit 1; }
go vet ./... && go test ./... && go test -race ./...
go tool staticcheck ./... && go tool govulncheck ./...
npm ci --ignore-scripts
npm run worker:lint && npm run worker:typecheck && npm run worker:test
npm run schema:test && npm run schema:validate && npm run lint:docs && npm run format:check
python3 -m unittest discover -s tests -p 'test_*.py' -v
shellcheck scripts/**/*.sh && go tool shfmt -d scripts
bats tests/shell
go tool actionlint .github/workflows/*.yml
python3 scripts/check_workflow_policy.py .github/workflows
python3 scripts/check_repository_metadata.py
python3 scripts/sanitize_public.py --tracked
~~~
- [ ] Expected: every command exits 0; seven stable contexts are unique; no unsafe trigger/self-hosted runner/unpinned action exists; schemas/examples validate; source scan passes.
- [ ] Build two source packages and compare SHA-256. Expected: identical.
- [ ] Run Trivy filesystem and config scans at HIGH/CRITICAL with exit code 1. Expected: no blocking result.
- [ ] Run <code>git diff --check</code>, <code>git status --short</code>, and <code>git log --show-signature --format='%h %G? %s' origin/main..HEAD</code>. Expected: no unstaged change and every commit marker <code>G</code>.
- [ ] If verification required a correction, commit only that correction: <code>git commit -S -m "test: close foundation verification gaps"</code>. Otherwise do not create an empty commit.
- [ ] Stop for independent review. Do not merge, publish a release, apply GitHub settings, or deploy from this plan without the corresponding explicit authority.
