# Portable GHAR Implementation Program

<!-- markdownlint-disable MD013 MD036 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to execute each phase plan task-by-task. Do not combine source, deployment, and retirement gates into one unreviewed change.

**Goal:** Build, publish, deploy, validate, and operate Portable GHAR as the generic source-of-truth for ephemeral GitHub Actions runners on a QTS Docker host, then retire the pre-existing runner fleet and external watcher only after a successful reliability soak and rollback rehearsal.

**Architecture:** A Go controller acquires jobs through an exact-pinned `actions/scaleset` adapter, launches one constrained runner per job, and releases the listener only after a one-shot network helper and independent verifier establish public-internet-only egress. A QTS host watchdog may restart or reconcile the controller but cannot change workflow routing; while the legacy fleet owns the stable per-holder generation fence it can run only a zero-capacity observer. A Cloudflare Worker backed by one SQLite Durable Object per fleet is the only automatic routing authority; cron plus a Durable Object alarm reconcile versioned configuration and persisted due work, signed outbound heartbeats drive health, a Worker-owned hosted hold gates maintenance, idempotent GitHub variable mutations are read back, failback requires an epoch-bound secretless canary, and email/signed-webhook notifications retry independently.

**Tech Stack:** Go, SQLite, Docker/OCI, POSIX shell and Bats, TypeScript, Cloudflare Workers, Durable Objects SQLite, Vitest, JSON Schema, GitHub Apps and REST API, GitHub Actions, CodeQL, Gitleaks, Trivy, Syft/CycloneDX or SPDX SBOM tooling.

## Global Constraints

- The approved design in `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md` is authoritative. A material architecture change requires a revised design review before code.
- The public repository must contain only generic source, schemas, synthetic fixtures, documentation, and reproducible build metadata. Actual host, network, repository, account, notification, schedule, credential, and migration values stay in a mode-restricted private overlay outside the repository.
- Never place a GitHub App private key, installation token, Cloudflare token, heartbeat key, JIT configuration, webhook URL, notification destination, raw production log, or private denylist in a command transcript, test fixture, issue, pull request, commit, release, or delegate prompt.
- All public pull-request checks run on GitHub-hosted runners with no deployment secrets, no `pull_request_target`, least-privilege permissions, `persist-credentials: false`, timeouts, concurrency cancellation, and Actions pinned to full commit SHAs.
- Runner jobs never receive a Docker socket, host mount, device, controller credential, Worker credential, or reusable GitHub App credential.
- No Kubernetes, ARC, VM-isolation claim, container-job feature, Docker-in-Docker, or inbound host endpoint is in scope.
- The host watchdog can restart and reconcile local services only. The Cloudflare control plane is the sole automatic writer of routing state; its authenticated hosted hold is the only durable maintenance, upgrade, and retirement freeze.
- The new and legacy fleets must never acquire the same workflow workload concurrently during rollback or retirement.
- The fence uses one stable lock inode, a monotonic generation header, and independent renewal records for every same-fleet controller/watchdog holder; dark deployment while `legacy` is active is observer-only.
- Every local acquisition-policy change—mode, eligible scale sets, or effective capacity—uses one bounded epoch CAS that invalidates and joins old pollers/leases and drains acquisition critical sections. Watchdog/probe stops, host-pressure reductions, canary narrowing, suspend, and observer startup use no weaker path; an unjoinable upstream call persists fatal/zero capacity and terminates the controller process.
- No persisted GitHub mutation, canary check, or notification retry may depend on a future request: cron plus the fleet object's alarm must claim and resume all due work after eviction/crash.
- Every live legacy adoption/suspend/retirement mutation goes through a positively matched QTS target adapter with fixed typed actions and post-action read-back.
- Preserve existing consumer-workflow job and required-check names. Keep secret-bearing, release, deployment-write, and unsupported browser/container jobs GitHub-hosted unless separately reviewed.
- A source merge is not a deployment. Every production transition requires positive read-back from the target host, GitHub, Cloudflare, and the affected workflow.
- The final `README.md` is a release artifact. It must truthfully document the shipped architecture, trust boundaries, production lifecycle, deployment and rollback flow, failover and notification workflows, workflow migration, operational commands, support matrix, residual risks, repository map, and linked runbooks without deployment-specific data.

## Phase Plans and Ownership

| Phase | Detailed plan | Exit artifact |
| --- | --- | --- |
| 1. Public foundation | `docs/superpowers/plans/2026-07-11-public-foundation.md` | Protected, security-scanned repository with stable hosted CI and generic configuration contracts |
| 2. Controller and isolation runtime | `docs/superpowers/plans/2026-07-11-controller-runtime.md` | Tested controller, runner/helper/verifier images, host adapters, and conformance suite |
| 3. External failover and deployment | `docs/superpowers/plans/2026-07-11-failover-deployment.md` | Tested Worker/DO authority, notifications, deployment runbooks, canary/soak/retirement evidence |

The detailed plans are independently executable but not independently deployable. Phase 1 must merge before runtime code. Controller domain and fake-runtime tests must merge before host integration. Worker protocol tests must pass before Cloudflare deployment. Retirement remains the final, separately evidenced gate.

## Program Task 1: Freeze the Approved Contracts

**Files:**

- Verify: `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`
- Verify: `docs/superpowers/plans/2026-07-11-public-foundation.md`
- Verify: `docs/superpowers/plans/2026-07-11-controller-runtime.md`
- Verify: `docs/superpowers/plans/2026-07-11-failover-deployment.md`

**Step 1: Check the plan-only diff**

```sh
git diff --check
npm_config_cache=/tmp/portable-ghar-plan-npm npx --yes markdownlint-cli2@0.23.0 'docs/superpowers/**/*.md'
```

Expected: exit 0 with no whitespace or structural Markdown finding. The exact lint version is temporary plan-validation tooling; Phase 1 moves it into the repository lockfile.

**Step 2: Search for unresolved planning placeholders**

```sh
! rg -n 'T[O]DO|T[B]D|F[I]XME|C[H]ANGEME|R[E]PLACE_ME|Y[O]UR_' docs/superpowers
```

Expected: exit 0 and no unresolved placeholder in an executable command, interface, gate, or expected result. Deliberate examples are excluded narrowly in the checker rather than through a global allowlist.

**Step 3: Run independent adversarial plan review**

Expected: one Google-family and one xAI-family reviewer read the complete specification plus all phase plans, surface no unresolved load-bearing gap, and agree that implementation can begin. After Phase 1 creates the sanitizer, re-run `python3 scripts/sanitize_public.py --tracked` before any runtime source PR.

**Step 4: Commit the program and phase plans**

```sh
git add docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md docs/superpowers/plans
git commit -S -m "docs: plan portable GHAR implementation"
```

Expected: one signed plan-only commit with no runtime or deployment-state changes.

## Program Task 2: Establish the Public Safety Baseline

Execute `2026-07-11-public-foundation.md` through its repository-foundation, configuration-contract, security-workflow, and repository-settings gates.

**Required evidence before Phase 2:**

```sh
GOTOOLCHAIN=go1.26.5 go test -race ./...
npm ci --ignore-scripts
npm run --workspace worker test
bats tests/shell
python3 scripts/check_repository_metadata.py
python3 scripts/sanitize_public.py --tracked
scripts/ci/check-images.sh
```

Expected: all commands exit 0 on a clean checkout; the corresponding GitHub-hosted checks named `go`, `worker`, `shell`, `repository-metadata`, `sanitization`, `container`, and `dependency-review` have completed successfully at least once.

Then apply repository rules only after exact check names are observed from GitHub. Read the ruleset back and prove signed commits, no force pushes/deletion, conversation resolution, required checks, read-only workflow token defaults, disabled workflow PR approval, automatic branch deletion, native secret scanning, push protection, Dependabot, private vulnerability reporting, SHA pinning, and the reviewed Actions allowlist.

## Program Task 3: Build the Controller Core Without Host Authority

Execute the controller-domain portion of `2026-07-11-controller-runtime.md` using fake GitHub, fake scale-set, fake clock, fake state store, and fake host-runtime adapters.

**Required behaviors:**

- Upstream `actions/scaleset` types stop at `internal/githubscale`.
- Contract fixtures and startup probes fail closed on upstream drift.
- Duplicate assignment delivery and restart recovery never create a second runner for one assignment.
- Weighted fair admission, aging, host-pressure reduction, and the global ceiling are deterministic under a fake clock.
- The lifecycle state machine is persisted before side effects and every transition is idempotent.
- A complete successful reconciliation cycle is required before a healthy heartbeat can be emitted.
- The redacting logger accepts only schema-defined fields and the adversarial corpus yields no reusable credential or job-controlled value.
- Every policy transition invalidates prior pollers and leases; a nonzero poll/acquire/JIT call revalidates mode, exact scale-set eligibility, effective capacity, lease, epoch, and fleet guard in one ordered critical section. Canary-only permits one exact scale set and one unit.

**Verification:**

```sh
GOTOOLCHAIN=go1.26.5 go test -race ./internal/admission/... ./internal/controller/... ./internal/githubscale/... ./internal/lifecycle/... ./internal/redaction/... ./internal/state/...
GOTOOLCHAIN=go1.26.5 go vet ./...
GOTOOLCHAIN=go1.26.5 go tool staticcheck ./...
GOTOOLCHAIN=go1.26.5 go tool govulncheck ./...
```

Expected: all commands exit 0; fault-injection tests cover every persisted lifecycle boundary.

## Program Task 4: Build and Prove the QTS Isolation Runtime

Execute the host-runtime, image, adapter, watchdog, integration, and chaos portions of `2026-07-11-controller-runtime.md`.

**Required barrier:**

```text
assignment -> reserve -> create capless per-job network anchor
-> install IPv4 and IPv6 policy in anchor -> apply helper exits
-> capless verifier succeeds -> create held runner joined to exact anchor
-> read-only audit helper proves no attach mutation and exits
-> one-use readiness token appears in runner-private tmpfs -> listener starts
```

Any missing, stale, reordered, ambiguous, or contradictory event destroys the pre-listener runner and leaves acquisition safe-stopped.

**Verification:**

```sh
PGHAR_INTEGRATION_DOCKER=1 PGHAR_CHAOS_DOCKER=1 ./scripts/test-controller-runtime.sh --full
scripts/ci/check-images.sh
```

Expected: all commands exit 0; backend-parity tests prove nftables and iptables-legacy implement the same normalized policy contract; an actual runner namespace on each supported host profile proves public egress succeeds and every prohibited IPv4/IPv6 class fails; inspection proves no socket, host mount, device, extra capability, controller secret, or reusable workspace. The QTS reference host explicitly selects the iptables-legacy backend because its verified kernel lacks `nf_tables`; this is a supported profile, not a runtime fallback.

## Program Task 5: Build and Prove the External Routing Authority

Execute the Worker, Durable Object, GitHub outbox, canary, email, and webhook portions of `2026-07-11-failover-deployment.md`.

**Required behaviors:**

- The server owns enrollment epochs and consumes single-use challenges.
- Fleet, random session, challenge, epoch, and monotonic sequence are authenticated with constant-time comparison.
- Worker receipt time determines freshness; client time is diagnostic only.
- Desired routing mutations are persisted per repository before GitHub calls, transactionally claimed, read back after success or ambiguity, and retried idempotently by cron plus Durable Object alarms after eviction/crash.
- Repository additions reconcile hosted under a monotonic configuration revision and persisted canary identity before the hold may release.
- Recovery remains hosted until a current-epoch secretless canary succeeds; obsolete or late canaries cannot fail back.
- Email and webhook share a sanitized event ID but have independent persisted delivery attempts and retries.
- Notification failure never blocks a safety routing mutation.

**Verification:**

```sh
npm ci --ignore-scripts
npm run --workspace worker lint
npm run --workspace worker typecheck
npm run --workspace worker types:check
npm run --workspace worker test
scripts/verify-failover.sh
```

Expected: exit 0 with deterministic fake-time coverage for replay, sequence, stale-heartbeat, hysteresis, partial mutation, rate-limit, ambiguous response, late-canary, and notification-failure cases.

## Program Task 6: Produce and Verify a Release Candidate

**Step 1: Run the full local release rehearsal from a clean checkout**

```sh
./scripts/release/rehearse-runtime.sh --version 0.1.0-rc.1 --output dist/rehearsal-a
./scripts/release/rehearse-runtime.sh --version 0.1.0-rc.1 --output dist/rehearsal-b
```

Expected: clean rebuild; test suite passes; controller binaries and OCI images are built; SBOM, licenses, checksums, image digests, and provenance subjects are generated; filesystem/image/sanitization scans pass.

**Step 2: Verify reproducibility**

```sh
./scripts/release/compare-runtime-rebuilds.sh dist/rehearsal-a dist/rehearsal-b
```

Expected: byte-identical supported binaries and equivalent immutable image manifests under the documented build environment.

**Step 3: Independently review security-sensitive code**

Review the GitHub authentication boundary, JIT handling, network policy generation, lifecycle idempotency, enrollment/HMAC verification, GitHub mutation outbox, redaction, sanitization, deployment scripts, and watchdog authority. Resolve every actionable finding, rerun focused tests, then rerun the complete matrix.

## Program Task 7: Create the Private Deployment Overlay

This task executes only on operator-owned storage outside the public repository. The overlay root is supplied at runtime through `PORTABLE_GHAR_PRIVATE_OVERLAY`; it is never written into source, CI, logs, or public plan evidence.

**Step 1: Generate a mode-restricted template**

```sh
umask 077
mkdir -p "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence" "$PORTABLE_GHAR_PRIVATE_OVERLAY/rollback" "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered"
chmod 0700 "$PORTABLE_GHAR_PRIVATE_OVERLAY"
scripts/ops/assert-private-overlay.sh "$PORTABLE_GHAR_PRIVATE_OVERLAY"
```

Expected: the overlay exists outside the repository, its root is mode `0700`, every populated file is mode `0600`, and it contains secret references rather than secret values wherever supported.

**Step 2: Validate without rendering secrets**

```sh
node scripts/validate-failover-config.mjs --config "$PORTABLE_GHAR_PRIVATE_OVERLAY/failover.json"
scripts/ops/assert-private-overlay.sh "$PORTABLE_GHAR_PRIVATE_OVERLAY"
```

Expected: strict schema and secret-reference validation passes; output is exactly `failover configuration: PASS`. Live target/account/service checks are performed separately by the typed private probe.

**Step 3: Capture the live legacy rollback source**

```sh
scripts/ops/capture-legacy.sh --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-capture.json" --output "$PORTABLE_GHAR_PRIVATE_OVERLAY/rollback/legacy-capture.enc"
```

Expected: an encrypted, mode-restricted private bundle records live scripts, images/digests, configuration, watchdog schedule/state, routing writers, registrations, and restore checks; no bundle content enters the public checkout.

**Step 4: Adopt the live legacy fleet into the shared fence**

```sh
node scripts/ops/adopt-legacy-fence.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-capture.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-fence-adoption.json"
```

Expected: after an idle check and target re-verification, the target initializes the stable fence as `legacy`, restarts every legacy launcher/watchdog only through the captured fixed-command wrapper, and positively observes current legacy holder records. Existing workload routing is unchanged and no Portable GHAR acquisition path is active.

## Program Task 8: Deploy Dark and Prove No Acquisition

**Step 1: Deploy controller and host support in disabled mode**

```sh
node scripts/ops/probe-private-deployment.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --phase predeploy --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/predeploy-probe.json"
portable-ghar deploy host --private "$PORTABLE_GHAR_PRIVATE_OVERLAY/host.json" --acquisition disabled
portable-ghar verify host --private "$PORTABLE_GHAR_PRIVATE_OVERLAY/host.json" --require-zero-listeners
```

Expected: target identity matches the overlay; signed release digest and staged manifest match; while `legacy` owns the fence, Portable GHAR first normalizes any stale acquisition policy to a new disabled/empty/zero epoch and survives restart only as a force-disabled observer with `maxCapacity=0`; zero listeners, runner containers, helpers, JIT generations, polls, and assignments exist.

**Step 2: Render and deploy Worker/DO under a hosted hold**

```sh
node scripts/render-failover-config.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --output "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
npm exec --workspace worker -- wrangler deploy --dry-run --config "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
npm exec --workspace worker -- wrangler deploy --config "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
node scripts/ops/control-plane-admin.mjs hold-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/hosted-hold.json"
node scripts/ops/transition-variable.mjs read-back --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --all-configured
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold true --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/before-noop-redeploy.json"
npm exec --workspace worker -- wrangler deploy --config "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold true --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/after-noop-redeploy.json"
node scripts/ops/probe-private-deployment.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --phase postdeploy --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/postdeploy-probe.json"
node scripts/ops/record-signal-receipt.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --receipt "$PORTABLE_GHAR_PRIVATE_OVERLAY/signal-delivery-receipt.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/signal-delivery.json"
```

Expected: migrations, generated bindings, and configuration revision match; one fleet object preserves enrollment/config/outbox/hosted-hold state across the explicit no-op redeploy; GitHub reads confirm every managed repository is hosted; the hold transition's email and signed-webhook rows deliver independently. The matching Signal receipt is ingested before this deployment phase is considered complete.

**Step 3: Enroll and heartbeat with acquisition disabled**

Run the controller commands on the verified target through the deployment runbook's private management channel:

```sh
portable-ghar-controller probe
portable-ghar-controller reconcile --once
portable-ghar-controller status --json
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold true --expect-acquisition disabled --min-sequence-advance 3 --wait-seconds 180 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/dark-heartbeat.json"
```

Expected: server-owned epoch is established; three accepted heartbeats are observed across distinct successful reconciliation cycles; the authenticated status evidence confirms acquisition disabled, hosted hold true, hosted route, and zero current-epoch canary; replay/old-session probes fail.

## Program Task 9: Migrate Consumer Workflows Through a Transition Variable

Create separate governed pull requests in consumer repositories. Introduce the private transition-routing variable without removing or renaming existing check/job identifiers. Keep current secret-bearing, release, deployment-write, and unsupported browser/container jobs on `ubuntu-latest`.

Canary order:

1. the smallest read-only, secretless build;
2. plugin read-only validation gates;
3. workspace unit-test chain;
4. workspace governance aggregate last;
5. application core and aggregate tests;
6. any write-capable deployment recorder only after separate review.

Before the first canary, route every workflow that could still target the legacy fleet to hosted, stop that fleet through its captured target-safe adapter, and transfer host authority:

```sh
node scripts/ops/control-plane-admin.mjs hold-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/cutover-hosted-hold.json"
node scripts/ops/transition-variable.mjs read-back --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --all-configured
node scripts/ops/suspend-legacy.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-capture.json" --hosted-confirmation "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/cutover-hosted-hold.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-suspended.json"
portable-ghar resume host --private "$PORTABLE_GHAR_PRIVATE_OVERLAY/host.json" --acquisition disabled
portable-ghar-controller acquisition --set=canary-only --expected=disabled --eligible-scale-set "$PORTABLE_GHAR_CANARY_SCALE_SET" --json
node scripts/ops/control-plane-admin.mjs release-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/recovery-epoch.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route self-hosted --expect-hold false --expect-acquisition canary-only --require-current-epoch-canary --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/current-canary.json"
node scripts/ops/record-drill.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --drill workflow-canary --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/workflow-canary.json"
portable-ghar-controller acquisition --set=enabled --expected=canary-only --json
```

Run the controller commands on the verified target. The legacy suspend command must return with the fence at `none`, zero legacy processes/listeners, and all candidate repositories read back hosted; `resume host` then hands `none` to `portable` and starts disabled.

For each later repository-risk expansion, add exactly one repository plus its workflow/expected revision under a new private `configRevision`, then run:

```sh
node scripts/ops/control-plane-admin.mjs hold-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-hosted-hold.json"
portable-ghar-controller acquisition --set=canary-only --expected=enabled --eligible-scale-set "$PORTABLE_GHAR_CANARY_SCALE_SET" --json
node scripts/render-failover-config.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --output "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
npm exec --workspace worker -- wrangler deploy --config "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold true --expect-acquisition canary-only --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-configured.json"
node scripts/ops/control-plane-admin.mjs release-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-recovery.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route self-hosted --expect-hold false --expect-acquisition canary-only --require-current-epoch-canary --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-canary.json"
portable-ghar-controller acquisition --set=enabled --expected=canary-only --json
```

The private runbook resolves `PORTABLE_GHAR_CANARY_SCALE_SET` from the validated overlay without printing it. The status command validates the response configuration revision against the current overlay. Routine expansion never writes the transition variable directly. Expected: every acquisition command completes the bounded epoch barrier; a current-epoch exact-revision canary precedes self-hosted read-back; one ephemeral runner accepts exactly one job; original required check names pass; runner and helper are destroyed; no credential/workspace residue remains; email and webhook record the same sanitized routing event ID. If any assertion fails, reacquire the hosted hold before diagnosis.

## Program Task 10: Exercise Failure and Rollback Paths

Execute every drill from the failover-deployment plan against secretless canary workflows before broad routing:

- controller process death in every lifecycle state;
- Docker unavailability and restart;
- host watchdog restart and host reboot;
- helper/verifier failure and contradiction;
- delayed, duplicate, reordered, replayed, and dropped heartbeats;
- local state loss followed by server-owned re-enrollment;
- partial/rate-limited/ambiguous GitHub mutations;
- controller fatal state and uplink loss;
- late canary from an obsolete epoch;
- email-only, webhook-only, and dual notification failure;
- generation-proof renewal failure and simultaneous portable/legacy watchdog restart races;
- cancellation-resistant poll/acquire/JIT calls during canary narrowing, pressure reduction, watchdog stop, and suspend;
- hosted-hold persistence across Worker reschedule/redeploy and release into a new epoch;
- full new-to-legacy rollback with the mutual-exclusion barrier.

For each allowlisted drill:

```sh
node scripts/ops/record-drill.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --drill controller-death --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/controller-death.json"
```

The recorder stores only sanitized event IDs, state transitions, GitHub read-back, timestamps, fence observations, and pass/fail assertions in the private evidence store. Expected: hosted hold and hosted routing are confirmed before any unsafe local restoration, recovery never bypasses the current-epoch canary, and no observation contains guards or acquisition from both fleets.

## Program Task 11: Run the Reliability Soak

Run a minimum continuous 14-day soak after all planned read-only workloads are routed to Portable GHAR. A reset-worthy failure restarts the soak clock after remediation and full regression verification.

Daily evidence must show:

- heartbeat sequence and reconciliation timestamp advancing;
- controller, Docker, watchdog, Worker cron, and Durable Object health;
- assignments received/completed/destroyed with no duplicate job execution;
- zero idle runner containers outside active jobs;
- global CPU/memory/PID/scratch ceiling respected;
- queue latency, job startup latency, job duration, and hosted-fallback duration;
- no private-egress success from scheduled probes;
- no JIT/App/Worker/heartbeat secrets in logs or diagnostics;
- outboxes drained or explained;
- primary email, signed webhook, and matching end-to-end Signal receipt through the separate failure domain;
- GitHub routing state confirmed rather than inferred;
- continuous current-generation fence renewals with no dual-fleet holder observation;
- legacy fleet and watcher retained but unable to acquire transition-routed work.

```sh
node scripts/ops/collect-soak-evidence.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --day "$(date -u +%F)"
node scripts/ops/verify-retirement-gates.mjs --phase soak --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Expected: collection writes one schema-valid mode-restricted daily record and prints no deployment identity. The soak gate exits 0 only after 14 continuous qualifying UTC days; its private summary remains unpublished unless independently approved.

## Program Task 12: Retire the Legacy Fleet and Watcher

Retirement is prohibited unless Tasks 8-11 pass, the complete rollback rehearsal succeeds from the live capture, and the 14-day soak command exits 0.

**Step 1: Acquire and confirm the Worker-owned hosted hold**

```sh
node scripts/ops/control-plane-admin.mjs hold-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/retirement-hosted-hold.json"
node scripts/ops/transition-variable.mjs read-back --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --all-configured
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold true --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/retirement-hosted-status.json"
node scripts/ops/verify-retirement-gates.mjs --phase pre-retire --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Expected: the Durable Object reports hosted hold true and every managed repository independently reads back hosted routing. A direct variable write is not accepted as hold evidence.

**Step 2: Stop and prove the new fleet idle**

```sh
portable-ghar suspend host --private "$PORTABLE_GHAR_PRIVATE_OVERLAY/host.json" --drain-policy=wait --hosted-confirmation "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/retirement-hosted-status.json"
portable-ghar verify host --private "$PORTABLE_GHAR_PRIVATE_OVERLAY/host.json" --require-zero-listeners
```

Expected: zero Portable GHAR listeners, runners, helpers, verifiers, pending acquisition effects, and fence guards remain after the controller/watchdog is stopped through the QTS runbook. Handoff then moves the verified fence from `portable` to `none` at the expected generation.

**Step 3: Disable legacy writers and unregister legacy runners**

```sh
node scripts/ops/retire-legacy.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-retirement.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-retirement.json"
node scripts/ops/verify-legacy-retired.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-retirement.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-retired-verification.json"
```

Expected: the typed allowlist disables legacy host watchdog entries, supervisors, heartbeat writers, and external watcher jobs; legacy runner registrations are absent; GitHub routing remains held hosted; retained encrypted rollback artifacts decrypt and match their manifest; `none` remains the only active fence state.

**Step 4: Restore the new fleet through canary-gated failback**

Run `portable-ghar resume host` from the deployment workstation, then run the controller commands on the verified target through the private management channel:

```sh
portable-ghar resume host --private "$PORTABLE_GHAR_PRIVATE_OVERLAY/host.json" --acquisition disabled
portable-ghar-controller probe
portable-ghar-controller reconcile --once
portable-ghar-controller acquisition --set=canary-only --expected=disabled --eligible-scale-set "$PORTABLE_GHAR_CANARY_SCALE_SET" --json
node scripts/ops/control-plane-admin.mjs release-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/post-retirement-recovery.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route self-hosted --expect-hold false --expect-acquisition canary-only --require-current-epoch-canary --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/post-retirement-canary.json"
portable-ghar-controller acquisition --set=enabled --expected=canary-only --json
node scripts/ops/verify-retirement-gates.mjs --phase final --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Expected: the released hold creates a new recovery epoch; the authenticated status evidence proves a matching current-epoch canary and self-hosted read-back before normal acquisition; managed read-only workloads return to Portable GHAR; the final gate confirms the legacy fleet remains absent and fenced out. On any failure, reacquire the hosted hold and stop acquisition.

**Step 5: Preserve rollback material for 30 days**

Do not delete legacy images, scripts, captures, or recovery records until the documented 30-day retention expires and integrity verification still passes. Credential revocation happens after retirement verification, in dependency order, without exposing values in evidence.

## Program Task 13: Complete Public Documentation and Release

Update `README.md` only after production behavior has been positively observed so the public documentation describes shipped facts rather than intent. Use the structural strengths of the operator-provided README reference—current posture, architecture, lifecycle, topology/boundaries, deployment, rollback, operational workflows, repository map, verification commands, and runbook index—without naming or copying unrelated deployment topology.

**Required README sections:**

- current release and support posture;
- Mermaid system architecture and trust boundaries;
- assignment and runner lifecycle;
- network-readiness barrier and residual shared-kernel risk;
- external failover and current-epoch canary lifecycle;
- Worker-owned hosted hold, configuration reconciliation, and cron/alarm due-work lifecycle;
- bounded acquisition-policy epoch barrier, fatal handling for unjoinable upstream calls, dark-observer normalization, and per-holder generation fence;
- email, signed-webhook, and separately signed Signal-receipt workflow;
- generic production topology and authority matrix;
- deployment, upgrade, rollback, soak, and retirement flows;
- consumer-workflow migration and unsupported job classes;
- operator commands and expected safe results;
- configuration and private-overlay boundary;
- repository map, development/release workflow, linked runbooks, and security reporting.

**Verification:**

```sh
node scripts/docs/check-links.mjs
node scripts/docs/check-command-examples.mjs
npm exec -- markdownlint-cli2 README.md docs
python3 scripts/check_repository_metadata.py
python3 scripts/sanitize_public.py --tracked
```

Expected: docs build and link checks pass; every documented command exists; diagrams match versioned architecture sources; examples remain synthetic; no private evidence or identifier appears.

Tag the first stable release only after all required checks, release rehearsal, deployment verification, rollback drill, soak, retirement, and final README review pass. Verify the GitHub release assets, checksums, SBOMs, license inventory, provenance, image digests, and sanitization results from the public release endpoint.

## Final Definition of Done

- The public source, history, generated artifacts, and release payload pass generic and private pre-publication scans.
- Required hosted CI/security checks are green and protected `main` enforces the observed names.
- The QTS host runs only the expected controller/watchdog state and ephemeral per-job containers; no runner has Docker control or private-network egress.
- The Cloudflare Worker/DO is the sole automatic routing writer and all mutations are confirmed through GitHub read-back.
- Email and signed-webhook notifications work independently and retry without affecting safety; matching Signal delivery is proven by a separate-key receipt from a separate failure domain.
- All selected consumer workflows retain their job/check contracts and complete on the new fleet with hosted fallback verified.
- The 14-day qualifying soak and full rollback rehearsal pass.
- Legacy runners, host-side legacy writers, and the external watcher are retired without overlapping acquisition; retained rollback artifacts remain verified for 30 days.
- The final README and runbooks truthfully describe the shipped system while the private overlay and operational evidence remain outside the public repository.
