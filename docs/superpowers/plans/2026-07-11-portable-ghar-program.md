# Portable GHAR Implementation Program

<!-- markdownlint-disable MD013 MD036 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to execute each phase plan task-by-task. Do not combine source, deployment, and retirement gates into one unreviewed change.

**Goal:** Build, publish, deploy, validate, and operate Portable GHAR as the generic source-of-truth for ephemeral GitHub Actions runners on a QTS Docker host, then retire the pre-existing runner fleet and external watcher only after a successful reliability soak and rollback rehearsal.

**Architecture:** A Go controller acquires jobs through an exact-pinned `actions/scaleset` adapter and launches one constrained runner per job. On the QTS reference host, the runner shares only an empty `--network none` namespace with a capless loopback relay; a separately jailed, dial-bounded broker owns all real network sockets through a per-job Unix channel, and the listener is released only after namespace, policy, destination, resource-budget, and conntrack proofs pass. A QTS host watchdog may restart or reconcile the controller but cannot change workflow routing; while the legacy fleet owns the stable per-holder generation fence it can run only a zero-capacity observer. A scheduled official-release observer builds and attests immutable one-version runner candidates outside job containers, scale sets disable in-place updates, and whole-container destruction reclaims every job cgroup/tmpfs/workspace. A Cloudflare Worker backed by one SQLite Durable Object per fleet is the only automatic routing authority; cron plus a Durable Object alarm reconcile versioned configuration and persisted due work, signed outbound heartbeats drive health and runner-upgrade holds, idempotent GitHub variable mutations are read back, failback requires an epoch-bound secretless canary, and email/signed-webhook notifications retry independently.

**Tech Stack:** Go, SQLite, Docker/OCI, POSIX shell and Bats, TypeScript, Cloudflare Workers, Durable Objects SQLite, Vitest, JSON Schema, GitHub Apps and REST API, GitHub Actions, CodeQL, Gitleaks, Trivy, Syft/CycloneDX or SPDX SBOM tooling.

## Global Constraints

- The review-gated design in `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md` is authoritative for planning. Phase 2 implementation is underway; the 2026-07-22 runner-lifecycle amendment remains pre-code review-gated, and any further material architecture change requires a revised design review.
- The public repository must contain only generic source, schemas, synthetic fixtures, documentation, and reproducible build metadata. Actual host, network, repository, account, notification, schedule, credential, and migration values stay in a mode-restricted private overlay outside the repository.
- Never place a GitHub App private key, installation token, Cloudflare token, heartbeat key, JIT configuration, webhook URL, notification destination, raw production log, or private denylist in a command transcript, test fixture, issue, pull request, commit, release, or delegate prompt.
- All public pull-request checks run on GitHub-hosted runners with no deployment secrets, no `pull_request_target`, least-privilege permissions, `persist-credentials: false`, timeouts, concurrency cancellation, and Actions pinned to full commit SHAs.
- Runner jobs never receive a Docker socket, host mount, device, controller credential, Worker credential, or reusable GitHub App credential.
- Scale sets require `RunnerSetting.DisableUpdate=true`; runner updates occur only through an externally observed, immutable, smoke-tested, attested candidate. A forced bump, pending/rejected candidate, or upgrade interruption must retain GitHub-hosted execution and recover without manual intervention.
- Runner work is bounded tmpfs by default and never a persistent reusable NAS volume. Completion requires positive whole-container/cgroup/tmpfs/workspace/process/namespace reclamation. Tmpfs, memory, swap, concurrency, and release cadence form one operator-approved sizing tuple; the emergency legacy high-water accommodation is not the Portable baseline.
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
| 2. Controller and isolation runtime | `docs/superpowers/plans/2026-07-11-controller-runtime.md` | Tested controller, runner/adapter/broker/helper/verifier images, host adapters, and conformance suite |
| 3. External failover and deployment | `docs/superpowers/plans/2026-07-11-failover-deployment.md` | Tested Worker/DO authority, notifications, deployment runbooks, canary/soak/retirement evidence |

The detailed plans are independently executable but not independently deployable. Phase 1 must merge before runtime code. Controller domain and fake-runtime tests must merge before host integration. Worker protocol tests must pass before Cloudflare deployment. Retirement remains the final, separately evidenced gate.

## Program Task 1: Freeze the Reviewed Contracts

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

Expected: at least one independent reviewer from a model family distinct from the authoring agent reads the complete specification plus all phase plans as one artifact, surfaces no unresolved load-bearing gap, and agrees that implementation can begin. This must be a fresh review of the exact current revision; the historical review record in the specification's section 22 does not satisfy this step. After Phase 1 creates the sanitizer, re-run `python3 scripts/sanitize_public.py --tracked` before any runtime source PR.

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
- Every policy transition invalidates prior pollers and leases; a nonzero poll/acquire/JIT call obtains both the current host-fleet guard and one fresh operation-bound Worker permit inside the same ordered epoch critical section, then revalidates mode, exact scale-set eligibility, effective capacity, lease, local epoch/digest, Worker transition/permit generation, and server expiry. Canary-only permits one exact scale set and one unit. Local CLI/status success alone grants no authority.

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
assignment -> reserve -> create capless per-job network adapter with --network none
-> prove runner namespace has loopback only, no tables/conntrack
-> create/start broker held as its namespace owner -> apply broker policy
-> helper exits -> start/verify the per-slot dial authority
-> release that same broker once
-> capless loopback-to-Unix relay and CONNECT verifier succeed
-> create held runner joined to exact relay namespace with no mount
-> read-only audit proves namespace/socket/policy/budget and exits
-> digest-only arm in runner-private tmpfs
-> bounded one-use token/JIT release frame arrives over stdin -> listener starts
```

Any missing, stale, reordered, ambiguous, or contradictory event destroys the pre-listener runner and leaves acquisition safe-stopped.

**Verification:**

```sh
PGHAR_INTEGRATION_DOCKER=1 PGHAR_CHAOS_DOCKER=1 ./scripts/test-controller-runtime.sh --full
scripts/ci/check-images.sh
```

Expected: all commands exit 0. The QTS profile proves the runner namespace has no routable interface, registered iptables table, or conntrack row before/after loopback flood; only the trusted broker performs durably tokened kernel dials; the checked per-dial conntrack formula, FD/memory caps, legacy broker-policy closure, and complete negative destination/protocol probes pass. Inspection proves the runner has no socket mount, host mount, device, extra capability, controller secret, or reusable workspace; its scale set has `DisableUpdate=true`, its image contains one exact smoke-tested runner payload, and every terminal/interrupted path removes the whole container, cgroup, tmpfs, `_work/_update`, processes, and namespaces. Joint tmpfs/memory/swap/concurrency validation rejects the incident's 2,162 MiB `/runner` peak under a 2 GiB memory cap. GitHub transport and every current proxy-sensitive workflow tool pass CONNECT canaries; direct UDP/ICMP/IP, plaintext HTTP proxying, SSH, SOCKS BIND/UDP, and non-proxy-aware tools remain explicitly unsupported. The optional nftables direct profile stays disabled unless a different host proves exact pre-conntrack admission; there is no runtime fallback.

## Program Task 5: Build and Prove the External Routing Authority

Execute the Worker, Durable Object, GitHub outbox, canary, email, and webhook portions of `2026-07-11-failover-deployment.md`.

**Required behaviors:**

- The server owns enrollment epochs and consumes single-use challenges.
- Fleet, random session, challenge, epoch, and monotonic sequence are authenticated with constant-time comparison.
- Worker receipt time determines freshness; client time is diagnostic only.
- Desired routing mutations are persisted per repository before GitHub calls, transactionally claimed, read back after success or ambiguity, and retried idempotently by cron plus Durable Object alarms after eviction/crash. Every due-row create/reschedule uses closed SQL-only mutation data carrying the one exact persisted `dueAtMs`; the helper derives the equal-or-earlier alarm from that field and commits alarm plus row in the same storage transaction, with no caller-supplied second deadline, callback, or Promise surface.
- Repository additions reconcile hosted plus exact expected scale-set/legacy-label companions under a monotonic configuration revision and persisted canary identity before the hold may release.
- Recovery remains hosted until a current-epoch secretless canary succeeds,
  full acquisition is enabled locally, and—without changing the Worker epoch—a
  same-session/newer-sequence heartbeat proves the expected policy digest and
  complete capacity; obsolete/late canaries and canary-only acquisition cannot
  fail back.
- Email and webhook share a sanitized event ID but have independent persisted delivery attempts and retries.
- Notification failure never blocks a safety routing mutation.
- Every hosted transition persists queue risk until an authenticated same-epoch
  GitHub read-back and selective recovery clears it idempotently.
- Portable remains disabled and legacy work-accepting components remain stopped
  until the latest queue-risk generation is completely cleared.
- Every Portable acquisition effect requires a fresh Worker permit; the legacy
  compatibility wrapper requires a short renewable Worker process lease. A
  hosted transition revokes issuance and drains prior authority before it
  creates hosted intent or the next queue-risk generation.
- A signed non-current runner-release heartbeat enters a Worker-owned
  `runner-upgrade` hosted hold. Candidate rejection or interruption remains
  hosted; exact qualified-candidate selection under disabled acquisition and
  zero listeners auto-releases only that machine-created hold into the normal
  recovery-canary path. Operator-created holds remain manual.
- An existing operator hold takes precedence over the runner-upgrade state:
  release evidence and permit drain persist, but the reason cannot change,
  every maintenance request returns `wait-hosted`, and no staging, selection,
  or auto-release occurs. After authenticated operator release, only a fresh
  non-current heartbeat may begin the runner-upgrade sequence.
- The host learns each automatic phase only through a fresh signed read-only
  maintenance directive: `stage-permitted`, `replace-permitted`,
  `canary-permitted`, then `enable-permitted`. Staging waits for hosted
  read-back, permit drain, queue clearance, and zero assigned jobs; selection
  waits for the exact later qualified tuple. A missing, expired, stale-session,
  wrong-request, wrong-generation, wrong-candidate, or wrong-policy directive
  means `wait-hosted` and cannot mutate routing.
- Phase 2 may ship the controller-side release observer, immutable-candidate
  journal, and fail-closed directive-provider interface, but unattended runner
  replacement is not operational until this task supplies the authenticated
  client plus the Worker state machine. The forced-version-bump success
  criterion is proved only by the integrated Phase 2 + Phase 3 system.

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
./scripts/release/observe-runner-release.sh --current-manifest release/manifest.json --output dist/runner-candidate.json
./scripts/release/rehearse-runtime.sh --version 0.1.0-rc.1 --runner-manifest dist/runner-candidate.json --output dist/rehearsal-a
./scripts/release/rehearse-runtime.sh --version 0.1.0-rc.1 --runner-manifest dist/runner-candidate.json --output dist/rehearsal-b
```

Expected: the observer emits one canonical monotonic official-release manifest; clean rebuild; test suite passes; controller binaries and one-version OCI runner image are built; listener version, update-staging absence, SBOM, licenses, checksums, image digests, and provenance subjects are generated; filesystem/image/sanitization scans pass.

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

Expected: strict schema and secret-reference validation passes; output is exactly `failover configuration: PASS`. The host overlay also carries the operator-approved `/runner` and `/tmp` tmpfs, memory/swap cgroup, maximum-concurrency, host-reserve, and runner-release-cadence tuple with its evidence digest; host validation must reject it until p99/margin and 32 GiB host-budget inequalities pass. Live target/account/service checks are performed separately by the typed private probe.

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

Expected: target identity matches the overlay; signed release digest and staged manifest match; while `legacy` owns the fence, Portable GHAR first normalizes any stale acquisition policy to a new disabled/empty/zero epoch and survives restart only as a force-disabled observer with `maxCapacity=0`; zero listeners, runner/adapter/held-or-running-broker/helper/verifier containers, per-job relay/dial-authority socket directories, JIT generations, broker dials, polls, and assignments exist. Stable slot ledgers, if any, remain retained and unavailable until their measured `T` expires.

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

Create separate governed pull requests in consumer repositories. Replace every
candidate job's legacy runner selector with the exact three-state
`PORTABLE_GHAR_ROUTE` contract from the platform design without removing or
renaming existing job IDs/check names. Missing, empty, case-variant, and unknown
values must select `ubuntu-latest`; `self-hosted` must resolve to one validated
scalar scale-set name; `legacy` must resolve to one validated scalar label
unique to the captured legacy registrations and is reserved for authenticated
rollback. Add the fixed
`portable-ghar-route-attestation` step and bind each default-branch head,
workflow blob/content digest, job ID, and required-check name in the private
configuration. Keep current secret-bearing, release, deployment-write, and
unsupported browser/container jobs on `ubuntu-latest`.

Canary order:

1. the smallest public read-only, secretless build;
2. workspace unit-test chain;
3. workspace governance aggregate;
4. application core and aggregate tests;
5. any write-capable deployment recorder only after separate review.

Fresh inventory immediately before migration is authoritative. A repository
with no workflow that can route self-hosted is excluded from the private fleet
configuration, receives no scale set or idle capacity, and is not retained as a
canary merely because a legacy runner profile still exists for it. A repository
whose live GitHub `archived` state is `true` is likewise excluded with effective
capacity zero regardless of what any local or private-overlay inventory says;
unarchiving alone never restores eligibility, and reactivation follows the
archive-state contract in the platform design (operator-approved configuration
revision, fresh eligibility audit, hosted bootstrap and read-back, queue-risk
clearance, and a current-epoch canary).

Before the first canary, route every workflow that could still target the
legacy fleet to hosted, verify the bound workflow digests/job IDs/check names,
and positively observe a secretless candidate at that exact default-branch SHA
with `runner.environment=github-hosted` and its route-attestation step passing.
Only then stop the legacy fleet through its captured target-safe adapter and
transfer host authority:

```sh
node scripts/ops/control-plane-admin.mjs hold-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/cutover-hosted-hold.json"
node scripts/ops/transition-variable.mjs read-back --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --all-configured
node scripts/ops/verify-consumer-routing.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect hosted --dispatch-proof --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/hosted-workflow-proof.json"
node scripts/ops/suspend-legacy.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/legacy-capture.json" --hosted-confirmation "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/cutover-hosted-hold.json" --consumer-proof "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/hosted-workflow-proof.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/legacy-suspended.json"
portable-ghar resume host --private "$PORTABLE_GHAR_PRIVATE_OVERLAY/host.json" --acquisition disabled
node scripts/ops/control-plane-admin.mjs queue-recovery --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --recovery-manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/queue-recovery.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/queue-risk-cleared.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-acquisition disabled --require-queue-risk-cleared --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/queue-risk-status.json"
portable-ghar-controller acquisition --set=canary-only --expected=disabled --eligible-scale-set "$PORTABLE_GHAR_CANARY_SCALE_SET" --json
node scripts/ops/control-plane-admin.mjs release-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/recovery-epoch.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold false --expect-acquisition canary-only --require-current-epoch-canary --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/current-canary.json"
node scripts/ops/record-drill.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --drill workflow-canary --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/workflow-canary.json"
portable-ghar-controller acquisition --set=enabled --expected=canary-only --json
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route self-hosted --expect-hold false --expect-acquisition enabled --require-current-epoch-canary --require-acquisition-enabled-confirmed --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/acquisition-enabled.json"
```

Run the controller commands on the verified target. The legacy suspend command must return with the fence at `none`, zero legacy processes/listeners, and all candidate repositories read back hosted; `resume host` then hands `none` to `portable` and starts disabled.

The mode-restricted private `queue-recovery.json` is produced by the documented
selective-recovery procedure from exact latest-transition GitHub run/job
read-back. It records no claim that a queued job migrated, and it is invalidated
by any newer hosted transition. The admin tool must clear every configured row
before the first nonzero acquisition command. That status result and the local
mode command are evidence/intent only: each later poll/acquire/JIT must obtain a
fresh Worker permit inside the controller's policy-epoch barrier. If a newer
hosted transition starts between commands, permit generation is revoked and the
external call cannot begin; hosted intent waits until all earlier authority is
drained.

For each later repository-risk expansion, add exactly one repository plus its workflow/expected revision under a new private `configRevision`, then run:

```sh
node scripts/ops/control-plane-admin.mjs hold-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-hosted-hold.json"
portable-ghar-controller acquisition --set=disabled --expected=enabled --json
node scripts/render-failover-config.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --output "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
npm exec --workspace worker -- wrangler deploy --config "$PORTABLE_GHAR_PRIVATE_OVERLAY/rendered/wrangler.jsonc"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold true --expect-acquisition disabled --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-configured.json"
node scripts/ops/control-plane-admin.mjs queue-recovery --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --recovery-manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/queue-recovery.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-queue-risk-cleared.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold true --expect-acquisition disabled --require-queue-risk-cleared --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-queue-risk-status.json"
portable-ghar-controller acquisition --set=canary-only --expected=disabled --eligible-scale-set "$PORTABLE_GHAR_CANARY_SCALE_SET" --json
node scripts/ops/control-plane-admin.mjs release-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-recovery.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold false --expect-acquisition canary-only --require-current-epoch-canary --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-canary.json"
portable-ghar-controller acquisition --set=enabled --expected=canary-only --json
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route self-hosted --expect-hold false --expect-acquisition enabled --require-current-epoch-canary --require-acquisition-enabled-confirmed --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/expansion-enabled.json"
```

The private runbook resolves `PORTABLE_GHAR_CANARY_SCALE_SET` from the validated overlay without printing it. The status command validates the response configuration revision against the current overlay but is not an acquisition credential. Routine expansion never writes the transition variable directly. Expected: every acquisition command completes the bounded epoch barrier; every external poll/acquire/JIT also holds a fresh exact Worker permit; a current-epoch exact-revision canary completes while consumer routing remains hosted; without a Worker epoch change, a later same-enrollment-session/newer-sequence `enabled` heartbeat with the exact policy digest and full expected capacity precedes self-hosted outbox creation/read-back; one ephemeral runner accepts exactly one job; original required check names pass; runner, adapter, held/running broker, helper, verifier, and per-job socket directories are destroyed; the stable slot ledger remains through `T`; no credential/workspace residue remains; email and webhook record the same sanitized routing event ID. If any assertion fails, reacquire the hosted hold before diagnosis.

## Program Task 10: Exercise Failure and Rollback Paths

Execute every drill from the failover-deployment plan against secretless canary workflows before broad routing:

- controller process death in every lifecycle state;
- Docker unavailability and restart;
- host watchdog restart and host reboot;
- adapter/broker/helper/verifier failure, socket replacement, token-ledger rollback, and contradiction;
- delayed, duplicate, reordered, replayed, and dropped heartbeats;
- local state loss followed by server-owned re-enrollment;
- governed legacy rollback publisher re-enrollment with matching active-fleet/
  fence generation, plus stale/fatal mismatch back to hosted;
- partial/rate-limited/ambiguous GitHub mutations;
- controller fatal state and uplink loss;
- late canary from an obsolete epoch;
- email-only, webhook-only, and dual notification failure;
- generation-proof renewal failure and simultaneous portable/legacy watchdog restart races;
- cancellation-resistant poll/acquire/JIT calls during canary narrowing, pressure reduction, watchdog stop, and suspend;
- hosted-hold persistence across Worker reschedule/redeploy and release into a new epoch;
- forced runner release while idle, busy, staging, and restarting; automated
  `runner-upgrade` hold, candidate rejection, later qualification, immutable
  switch, fresh phase directives across re-enrollment, whole-container
  reclamation, and canary-gated recovery with no interval in which the hosted
  path is unavailable;
- latest-transition queue-risk persistence/eviction, selective clear, and denial
  of Portable/legacy acquisition before the final clear;
- full new-to-legacy rollback with the mutual-exclusion barrier.

For each allowlisted drill:

```sh
node scripts/ops/record-drill.mjs --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --drill controller-death --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/controller-death.json"
```

The recorder stores only sanitized event IDs, state transitions, GitHub read-back, timestamps, fence observations, and pass/fail assertions in the private evidence store. Expected: hosted hold and hosted routing are confirmed before any unsafe local restoration, recovery never bypasses the current-epoch canary, and no observation contains guards or acquisition from both fleets.

## Program Task 11: Run the Reliability Soak

Run a minimum continuous 14-day soak after all planned read-only workloads are routed to Portable GHAR. A reset-worthy failure restarts the soak clock after remediation and full regression verification.

Before fixing the production sizing tuple, collect at least 15 representative
jobs over seven days, including the largest eligible workload classes. The
subsequent 14-day soak exceeds the five-complete-day stability floor and must
retain the same approved tuple unless a new measured/reviewed revision restarts
the sizing and soak evidence.

Daily evidence must show:

- heartbeat sequence and reconciliation timestamp advancing;
- controller, Docker, watchdog, Worker cron, and Durable Object health;
- assignments received/completed/destroyed with no duplicate job execution;
- zero idle runner, adapter, or released-broker containers outside active jobs;
  held brokers exist only for a persisted pre-release assignment and every
  helper/verifier is transient;
- global CPU/memory/PID/FD/tmpfs/scratch/durable-byte/inode ceiling respected
  for complete slots and transient peaks;
- approved tmpfs/memory/swap/concurrency tuple respected, with tmpfs resident
  pages accounted inside the memory cgroup and swap excluded from RAM capacity;
- per-job cgroup, `/runner`, `/tmp`, `_work`, `_work/_update`, descendant
  process, namespace, and container absence observed within the cleanup SLO;
- memory, swap, tmpfs, storage, process, container, and cgroup use returns to
  the approved baseline without a monotonic trend or periodic restart;
- no orphan per-job relay/dial-authority socket directory; stable slot ledgers
  are retained, non-refilled, and garbage-collected only after measured `T`;
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
node scripts/ops/control-plane-admin.mjs queue-recovery --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --recovery-manifest "$PORTABLE_GHAR_PRIVATE_OVERLAY/queue-recovery.json" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/post-retirement-queue-risk-cleared.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-acquisition disabled --require-queue-risk-cleared --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/post-retirement-queue-risk-status.json"
portable-ghar-controller acquisition --set=canary-only --expected=disabled --eligible-scale-set "$PORTABLE_GHAR_CANARY_SCALE_SET" --json
node scripts/ops/control-plane-admin.mjs release-hosted --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/post-retirement-recovery.json"
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route hosted --expect-hold false --expect-acquisition canary-only --require-current-epoch-canary --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/post-retirement-canary.json"
portable-ghar-controller acquisition --set=enabled --expected=canary-only --json
node scripts/ops/control-plane-admin.mjs status --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --expect-route self-hosted --expect-hold false --expect-acquisition enabled --require-current-epoch-canary --require-acquisition-enabled-confirmed --wait-seconds 600 --evidence-out "$PORTABLE_GHAR_PRIVATE_OVERLAY/evidence/post-retirement-enabled.json"
node scripts/ops/verify-retirement-gates.mjs --phase final --overlay "$PORTABLE_GHAR_PRIVATE_OVERLAY" --as-of "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Expected: the released hold creates a new recovery epoch; the authenticated status evidence proves a matching current-epoch canary while consumer routes remain hosted, then a fresh enabled/full-capacity heartbeat before self-hosted outbox/read-back; managed read-only workloads return to Portable GHAR; the final gate confirms the legacy fleet remains absent and fenced out. On any failure, reacquire the hosted hold and stop acquisition.

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
- The QTS host runs only the expected controller/watchdog state and ephemeral per-job runner/adapter/held-or-running-broker/helper/verifier containers; per-job socket directories are removed, stable ledgers remain non-refilled through measured `T`, runner namespaces remain loopback-only/table-empty, no runner has Docker control, mounts, or direct/private-network egress, and every complete-slot resource plus broker dial/FD/conntrack budget is enforced.
- Scale-set self-update is disabled; scheduled release observation, immutable
  qualification, Worker-owned hosted continuity, safe drain, exact listener
  smoke proof, and canary recovery survive a forced runner bump without manual
  intervention. Every job/interruption reclaims its entire container/cgroup/
  tmpfs/workspace/process/namespace footprint, and no persistent reusable NAS
  work area exists.
- The operator-approved tmpfs/memory/swap/concurrency/cadence tuple has
  representative p99 headroom and stays within the 32 GiB host budget; the
  temporary legacy high-water accommodation is not counted as production proof.
- The Cloudflare Worker/DO is the sole automatic routing writer and all mutations are confirmed through GitHub read-back.
- Every hosted transition's queue-risk generation is durable, and no Portable
  or legacy acquisition resumes before its authenticated selective recovery.
- Every nonzero local acquisition holds current Worker-issued authority, and a
  hosted transition revokes/drains prior permits or the legacy process lease
  before claiming the hard zero-acquisition state.
- Email and signed-webhook notifications work independently and retry without affecting safety; matching Signal delivery is proven by a separate-key receipt from a separate failure domain.
- All selected consumer workflows retain their job/check contracts and complete on the new fleet with hosted fallback verified.
- The 14-day qualifying soak and full rollback rehearsal pass.
- Legacy runners, host-side legacy writers, and the external watcher are retired without overlapping acquisition; retained rollback artifacts remain verified for 30 days.
- The final README and runbooks truthfully describe the shipped system while the private overlay and operational evidence remain outside the public repository.
