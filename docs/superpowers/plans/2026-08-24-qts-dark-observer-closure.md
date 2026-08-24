# QTS Dark-Observer Closure Implementation Plan

> **Execution contract:** begin with the empirical OCI identity probe. If QTS Docker cannot produce the immutable `RepoDigests` required by the existing verifier from a release-format archive, stop the QTS implementation/deployment leg without weakening identity admission or adding a registry. The Worker leg remains independent.

**Goal:** mechanically assemble and install a force-disabled, zero-capacity Portable observer beside the active legacy QTS fleet while preserving the exact legacy fence generation, holders, launchers, watchdog, and rollback material.

**Architecture:** fill the existing QTS observation, lifecycle, journal, verifier, watchdog, and SSH transport seams. Correct the legacy dark-install graph so it never drains/stops/restarts legacy. Reuse the existing fence, journal, release store, watchdog runner, lifecycle lease, typed manifest, and typed overlay. Add no service, registry, authority engine, queue, scheduler, or persistent state schema.

**Tech stack:** Go, shell/Bats, QTS Linux/amd64 Docker, SSH/SCP, existing lifecycle journal and release verifier.

---

## Task 0: Empirical QTS OCI identity gate

**Local artifacts:** use a disposable directory under `/private/tmp`; do not add repository files unless the probe reveals a testable bug in existing archive generation.

1. Create a minimal release-format OCI archive with the repository's pinned image tooling and record its archive SHA and manifest digest.
2. Transfer only that disposable archive to an explicit temporary QTS path using the pinned SSH target and bounded commands.
3. Load it with `/share/CACHEDEV1_DATA/.qpkg/container-station/usr/bin/docker`, inspect the loaded image, and positively compare the exact `RepoDigests` value with the expected manifest digest.
4. Remove the exact disposable image and archive and read back their absence, regardless of pass/fail.
5. If `RepoDigests` is absent or cannot satisfy `ReleaseArtifactVerifier`, record the hard stop and do not implement Tasks 1-10, deploy, add a registry, or weaken digest admission. Continue the Worker track only.

### Task 0 acceptance status — hard stop

The privately retained capability probe did not satisfy the existing
digest-qualified `RepoDigests` admission contract. No image or probe artifact
remains on the target. This public plan intentionally records no target
identifier, engine version, archive digest, or raw diagnostic. Per the approved
boundary, Tasks 1-10 and QTS deployment are stopped. A separately reviewed
distribution design is required; this branch will not add a registry or weaken
immutable identity admission.

## Task 1: Correct the legacy install and compensation graphs

**Files:**

- Modify: `internal/hostruntime/operation_journal.go`
- Modify: `internal/hostruntime/operation_binding.go`
- Modify: existing lifecycle/journal tests under `internal/hostruntime/`

1. Add RED table tests for the exact legacy normal sequence and both compensation sequences from the approved design.
2. Prove an initial legacy adoption accepts a nil prior Portable manifest only for the legacy disposition and never fabricates one.
3. Prove no legacy acquisition-disable, drain, stop, start, quiescence, or zero callback appears in install or compensation.
4. Implement `legacy-preserved-proven` as a read-only comparison phase covering fence header/generation, complete holder set, launcher identities, and captured command/config/image/watchdog digests.
5. Re-run every crash-boundary/replay test and prove legacy-effect callback counters remain zero.

## Task 2: Adopted-legacy target classification

**Files:**

- Modify: `internal/hostruntime/target_handler.go`
- Modify or create: the narrow target-classification command under `cmd/`
- Modify: target handler tests

1. Add RED cases for `none@0`, valid `legacy@N` with exact holders, malformed/mixed holders, Portable ownership, identity drift, and stale observation.
2. Implement a closed classification result used by the lifecycle; do not echo an overlay-provided target identity as proof.
3. Run focused tests and malformed-input fuzz/property cases already supported by the package.

## Task 3: Accept exact legacy holders for dark composition

**Files:**

- Modify: `internal/hostruntime/production_fleet.go`
- Modify: production-fleet tests

1. Add RED tests proving dark observer composition accepts only the observation-bound legacy generation and complete exact holder set.
2. Reject missing, extra, malformed, cross-generation, Portable, or mixed holders and any nonzero Portable capacity/listener/guard state.
3. Implement the smallest disposition-specific branch; keep existing non-legacy rejection behavior unchanged.

## Task 4: Wire the production lifecycle and deterministic chaos coverage

**Files:**

- Modify: the existing production lifecycle/controller implementation under `internal/hostruntime/`
- Modify: lifecycle normal, compensation, and chaos tests

1. Add RED end-to-end tests for the exact legacy sequence, one-time policy normalization receipt, observer zero state, current selection, terminal verification, pre-selection compensation, and post-selection compensation.
2. At every journal crash boundary, replay and assert byte-equivalent fence header/holders and no legacy stop/start callbacks.
3. Implement only the existing phase/effect wiring needed to satisfy the graph.
4. Run focused tests repeatedly and under `-race`.

## Task 5: Lifecycle-owned persistent QTS watchdog cron

**Files:**

- Modify: the existing watchdog registration effect in `internal/hostruntime/`
- Create only if needed: a focused fixed-command QTS cron helper in the same package
- Modify: watchdog tests and shell fixtures

1. Add RED tests for marker+line presence, supported cadence mapping, install/readback, one controlled crond reload, replay, removal, marker-only and cron-only convergence, unrelated byte preservation, and foreign/malformed Portable line rejection.
2. Implement bounded regular-file reads/writes under the existing lifecycle lease plus the fixed QTS crond reload command. Do not add a timer manager or daemon.
3. Prove uninstall removes only the owned line/marker and leaves unrelated root cron byte-for-byte unchanged.

## Task 6: Promote the execution-host identity algorithm

**Files:**

- Modify/create production identity code under `internal/hostruntime/`
- Reuse vectors from: `tests/integration/testenv/host_identity.go`
- Add focused production tests

1. Add RED parity vectors for the tested algorithm and drift cases for Docker binary/device/inode, deployment-root parent, daemon/server observation, remount, reinstall, and replacement.
2. Move/promote the minimal algorithm into production and make the integration helper call it, avoiding two implementations.
3. Run focused and integration identity suites.

## Task 7: Canonical read-only QTS observation

**Files:**

- Implement: the existing `internal/hostruntime/qts.Source` seam
- Add/modify: one narrow observation command under `cmd/`
- Add: focused QTS source/command tests

1. Add RED tests for the full canonical observation fields, fixed argv allowlist, bounded output/file sizes, pre/post identity equality, sorted legacy material, exact fence holders, unknown-field rejection, timeout, truncation, symlink/non-regular file, and drift.
2. Implement fixed probes only; no generic remote executor or capture framework.
3. Use explicit contexts/timeouts and deterministically release processes, pipes, files, and waiters on every path.
4. Run focused tests, race tests, and a read-only live QTS capture; compare canonical re-parse bytes and perform no target mutation.

## Task 8: Revalidate local control identity in SSH transport

**Files:**

- Modify: the existing `NewSSHTransport` implementation
- Modify: SSH transport tests

1. Add RED tests for executable drift, key public-fingerprint drift, known-hosts bytes/identity drift, UID drift, control-root drift, and unchanged success.
2. Recompute locally before every remote lifecycle invocation and reject before network mutation on mismatch.
3. Keep private key material and known-host contents out of logs/evidence.

## Task 9: Typed manifest/private-overlay assembler

**Files:**

- Create: one narrow assembler command under `cmd/`
- Add: assembler package/tests under `internal/hostruntime/` or the nearest existing release package

1. Add RED fixtures for exact release source/tag/subjects, all five OCI roles, broker-to-dialer mapping, manifest-digest versus tar-hash confusion, observation/control identity binding, approved sizing tuple, fleet caps 2/1/1, unknown/private fields, secret references, no partial output, and deterministic bytes.
2. Implement using only existing typed `RuntimeManifest`/`PrivateOverlay` constructors and strict canonical marshal/parse functions; do not build JSON maps in shell or add a schema.
3. Atomically write only after both documents round-trip and the complete existing validators pass.
4. Re-run focused tests and assemble a sanitized fixture twice to prove byte identity.

## Task 10: Terminal verification and idempotent uninstall

**Files:**

- Modify: existing terminal verifier and uninstall lifecycle effects/tests

1. Add RED cases for exact target/control/selection identities; unchanged legacy generation/holders/material; force-disabled observer; disabled-empty-zero policy projection; zero listeners/runners/pending/broker/Portable guards; watchdog marker+cron; and each drift case.
2. Add uninstall/replay tests proving only Portable observer, selection, registration, marker, and owned cron line are removed.
3. Preserve legacy fence, holders, launchers, captured rollback material, lifecycle/release evidence, external watcher, hosted routing, and unrelated cron.

## Task 11: Verification and governed deployment

Before any QTS mutation, run:

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go tool staticcheck ./...
git diff --check
```

Then run the repository's Linux/Docker full runtime, integration, conformance, and chaos gates exactly once at the qualified head. Open a governed PR, consume one complete exact-head review inventory, merge normally, and qualify the exact merged SHA.

Create a fresh immutable product tag only after the unchanged runner vulnerability gate is green. Positively verify tag object, source commit/tree, assets, hashes, subjects, attestations, and OCI identities. On QTS: capture/back up legacy, prove hosted routing and bounded idle, adopt `none@0 -> legacy@1`, rewrap exact launchers through `run-legacy-fenced.sh`, read back complete holders, install the observer, and prove terminal zero state. Rollback removes only owned Portable state and positively re-verifies legacy and unrelated cron.
