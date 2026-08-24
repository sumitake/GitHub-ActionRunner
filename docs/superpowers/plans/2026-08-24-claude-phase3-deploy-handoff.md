<!-- markdownlint-disable MD013 -->
# Phase 3 deploy — Claude → Codex handoff (as-of 2026-08-24)

**Author:** Claude (Opus 4.8), Phase 3 deploy owner across sessions. **Purpose:**
surface design work that lived only in a Claude session so parallel work does not
re-derive it. Companion to `2026-08-16-grok-primary-builder-handoff.md`. Repo is
`GitHub-ActionRunner`; source identifiers remain `portable-ghar-*` (unchanged).

**Governance:** nothing live has been deployed. No Cloudflare/GitHub-routing/QTS/host
mutation. The dark deploy begins only when the operator names the step. The runbooks
below were Gemini distinct-family cross-checked (recorded per item).

## 1. Verified state (read-only, 2026-08-24)

- `main` tip `97fc9c0` (**PR #34** "test: stabilize release verification prerequisites").
- **PR #31 (`fcc8437`, merged):** release-gate fix — `--ignore-unfixed` on the trivy
  **image** scans only + weekly `vuln-watch` workflow. Source `fs` scan still blocks unfixed.
- **PR #34:** made the packager's missing-`SOURCE_DATE_EPOCH` negative test hermetic
  (`env SOURCE_DATE_EPOCH=`), + go.mod/go.sum. (A Claude local branch fixed the identical
  bug with `env -u`; discarded as redundant — we converged.)
- **`v0.1.0` tag is STALE:** annotated tag → `fcc8437`, which **predates #34**. **0 releases
  published**; its two release runs failed. **Must be deleted and re-cut at `97fc9c0`+** or the
  next release run fails again on the (now-fixed-on-main) bats blocker.

## 2. Release blocker analysis (both defects, first-ever tag exercise)

The tag-gated `release.yml` runs `rehearse-runtime.sh`, whose `--full` controller-runtime
gate had two serial blockers, discovered by instrumenting `capture()`/`run()` on a throwaway
branch (the private log is swallowed to a closed "unavailable" surface):

1. **trivy image-scan wall** — pinned (and latest) `debian:bookworm-slim` carries 22
   HIGH/CRITICAL findings, all unfixable (16 affected / 5 fix_deferred / 1 will_not_fix; 0
   FixedVersion). Gate had no achievable green state. **Fixed by PR #31** (`--ignore-unfixed`
   on image scans; `vuln-watch` turns red weekly when any becomes fixable). Gemini review L→H.
2. **bats stage** — `failed_stage:"bats"`: the rehearsal exports `SOURCE_DATE_EPOCH`, which
   leaked into the packager's *missing-epoch* negative test. **Fixed by PR #34.**
3. **UNVERIFIED (recommended next):** the rehearsal's **docker / integration / conformance /
   chaos / image-reproducibility** stages run *after* bats and have **never executed in the
   rehearsal env** (they need Linux+Docker; unrunnable on macOS/local). Before spending a
   full two-leg release, dispatch **one instrumented `--full` gate run on a branch** to flush
   any remaining serial blocker cheaply. Local `go vet -tags=integration,chaos` passes (no
   compile-level blocker); runtime behavior is the open risk.

## 3. Scope & topology (operator-locked)

- **3 PRIVATE fleets:** `agent-collab-workspace`, `keicrew`, `keicrew-public` (3-entry
  `fleetIds`). `agent-collab` is PUBLIC → stays GitHub-hosted (free + no self-hosted fork risk).
  `keicrew-public` is misleadingly named but PRIVATE.
- **Deploy host:** QNAP RhoNAS (`192.168.1.230`), QTS/Linux, Docker 27.1.2-qnap8; replaces the
  live 6-container `supervisor.sh` + root-cron `m3-watchdog.sh` fleet. `claude`=uid1000, NO sudo.
- **External authority:** one Cloudflare Worker `github-actionrunner` (account `673fa21a…`
  Personal) + one `FLEET` DO per fleet + one Cron `* * * * *`. Replaces the LabMac
  `failover-watcher.sh`, which exits at the single-writer handoff (Phase 4), not before.
- **Control host** (overlay `management_transport`, mgmt-time only, nothing installed/backgrounded):
  this Mac. Verified in `transport.go`: transient outbound `ssh` to the QNAP subsystem.

## 4. Phase-1 sizing tuple — VALIDATOR-PROVEN (reuse; do not re-derive)

`ValidateRunnerSizing` (in `internal/hostruntime/profile.go`) enforces tmpfs ⊂ memory-cgroup
and a hard host-memory budget, so the raw legacy 6×(5 GiB tmpfs / 4 GiB mem) is **rejected**.
The closest compliant tuple (PASS; digest `1e675e7d01ab33306e2c8fbcd86c2379aa5475f949363b30d0904c53847d841e`, effective capacity 4):

- per-runner: `/runner` tmpfs **3 GiB** (p99 2,162 MiB + margin), `/tmp` **512 MiB**, scratch
  **512 MiB**, runner memory **5 GiB**, swap **5 GiB** (mem+swap 10 GiB), pids **512**,
  cgroup-p99 3.5 GiB / process-margin 1 GiB, reclamation cadence 1m.
- **max active concurrency 4** (host budget: 4×(5+0.5)+1 idle-CP+2 build-peak+4 host/gw ≤ 30 GiB
  of 32). Per-repo: workspace 2 / keicrew 1 / keicrew-public 1.
- **This is the migration accommodation, not the baseline** — the durable p99 tuple comes from
  the Phase-4a canary sizing window (≥15 jobs / 7 UTC days), signed before enable. NOT the
  14-day soak (that is final pre-retirement validation and does not gate enable).
- Live-verified per-runner limits (read-only `docker inspect`, 2026-08-18): mem 4 GiB /
  mem-swap 10 GiB / `/runner` 5 GiB + `/tmp` 1 GiB / pids 512.

## 5. Phase-1 overlay assembly map

Overlay = `controller-runtime.json`, schema = `hostruntime.PrivateOverlay`
(`internal/hostruntime/private_overlay.go`, **unchanged since PR #15**; strict
`DisallowUnknownFields`; secrets are `SecretRef{source:file|env}` — never inline). Field sources:

- **operator-signed** (see §4 + timings/fence/watchdog/history/conntrack — proposed values in
  the Claude tuple analysis): sizing, cadences, retention bounds.
- **live-captured by the built `portable-ghar host-runtime` binary ON the QNAP** (needs the
  v0.1.0 binary): `host_identity_digest`, `control_host_identity_digest`, storage observations
  (docker-root/state/staging/rollback/scratch/logs device+inode+free), conntrack, policy digests,
  profile evidence digests.
- **release-derived** (needs published v0.1.0): `manifest.path`+`digest`, the five
  `@sha256`-pinned images (runner/adapter/broker/helper/verifier).
- **validator-fixed:** `os=linux`, `arch=amd64`, `expected_euid=0`, profile `qts-capless-root`
  (+`degraded_acknowledged:true`), `acquisition_default="disabled"`, runner net mode `none`,
  egress `restricted-broker-v1`, health sink `local-closed-v1`.
- reference-rule gotcha: refs must contain `-`/`_`/`.`/`:` or be <20 chars, else the
  base64-shaped guard rejects them as possible secret material.

Consequence: the overlay JSON is **assembled mechanically at deploy time** (built binary +
published release), not hand-buildable now.

## 6. Phase-2 `dark-deploy-observer` execution contract (from `deploy/qts/`)

All controller scripts require **Linux + EUID 0** (`claude` has no sudo → operator-run OR the
proven root-cron pattern). Reversible; observer holds `maxCapacity=0` alongside the untouched legacy fleet.

1. **Cloudflare:** mint a Workers token from `cloudflare-johnosumi-parent` (Workers Scripts
   Write group `e086da7e…`), `wrangler deploy` `github-actionrunner` (source `wrangler.jsonc`
   is minimal: FLEET DO + v1 SQLite migration; add name/Cron/env vars/HMAC secret at deploy),
   establish session+heartbeat → **explicit no-lease** under hosted hold, prove Cron addresses
   all 3 DOs; revoke the token. Rollback: `wrangler delete`.
2. **Controller:** `install-controller.sh --private <ov> --manifest <mf> --acquisition disabled`
   then `install-watchdog.sh --private <ov> --manifest <mf>` (root). Verify:
   `verify-controller.sh --private <ov> --manifest <mf> --require-zero-listeners`. Rollback:
   `uninstall-watchdog.sh` + `uninstall-controller.sh --private <ov> --retain-state false`.
3. Other verbs: `suspend-controller.sh --drain-policy=wait|cancel --hosted-confirmation <p>`;
   `resume-controller.sh --acquisition disabled`; `rollback-controller.sh --expected-generation
   <n> --hosted-confirmation <p> --legacy-command-file <p>`.

Phase 2 writes **no routing** (RUNNER_TARGET + LabMac watcher remain live). Hosted reconcile
(Phase 3) and canary/enable/handoff (Phase 4+) are later, separately-packeted named steps.

## 7. Credentials (all set / verified; HMAC is the one new secret)

- **Release App provisioned:** secret `PORTABLE_GHAR_RELEASE_APP_PRIVATE_KEY` + vars
  `PORTABLE_GHAR_RELEASE_APP_CLIENT_ID` (`Iv23liLC3tK5cf7Y2fGg`),
  `PORTABLE_GHAR_RUNNER_OBSERVER_ACTOR=sumitake`, `PORTABLE_GHAR_DEFAULT_BRANCH=main`. Key in
  operator Keychain `github-actionrunner-release-app-key`.
- **Cloudflare:** no standing Workers token — mint-from-parent pattern (parent verified active).
- **GitHub routing:** the routing writer is an **injected** `GitHubClient` (not baked;
  `worker/src/github/outbox.ts`), so the dark deploy needs no routing credential — Phase-4
  concern. The existing `.gh_pat` (QNAP, fine-grained) read-verified to reach all 3 repos'
  `actions/variables` (HTTP 200); a least-privilege routing-only credential is cleaner for Phase 4.
- **HMAC heartbeat key:** NEW to this system — generate fresh at deploy into the Worker
  secret and the overlay `SecretRef{file}`; value never exposed.

## 8. Recommended next sequence (for whoever drives it)

1. Re-cut `v0.1.0` at `97fc9c0`+ (delete stale tag first).
2. One instrumented `--full` gate run on a branch to flush docker-stage blockers (§2.3) BEFORE
   a full two-leg release.
3. Release publishes → A/B reproducibility proven, manifest + attested images exist.
4. Assemble + `ParsePrivateOverlay`-validate the overlay (§4/§5), Gemini-check.
5. Operator names `dark-deploy-observer` → §6.

Optional cost-saver: scope `ci.yml` `on: push` to `main` only (this repo double-runs CI on
push+pull_request). Complementary: dependabot PRs #17–22 bump the debian base digest.
