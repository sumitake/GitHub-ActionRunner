# Portable GHAR Deployment Closure Design

**Date:** 2026-08-24

**Status:** Approved architecture, implementation pending

**Qualified source baseline:** `f41abb21274b6f9fe709d8f32edd21123d037faa`
**Scope:** close only the production seams required for an address-only Worker deployment and a QTS zero-capacity observer deployment. Preserve the existing authority, lifecycle, receipt, fence, and rollback machinery.

## 1. Outcome and truth boundary

The closure has two independently admissible deployment legs:

1. Deploy the Cloudflare Worker in **address-only** mode. Cron may address the three inventoried Durable Objects and persist receipt-only SQLite state. Ordinary session, heartbeat, lease, selector, archive, routing, and admin authority remain hard-disabled.
2. Deploy a **force-disabled, zero-capacity Portable observer** on QTS while the captured legacy fleet remains active and owns the existing stable fence. The observer has no workload listener, no acquisition authority, and no routing authority.

The QTS leg requires a qualified immutable runtime release. The Worker leg does not depend on the QTS OCI archives and may proceed from an exact merged source SHA after its own gates pass.

The first product tag, `v0.1.1`, is immutable and remains bound to `f41abb2`. Its release run failed before publication. A fresh scan of the exact pinned upstream runner archive found 30 HIGH detections representing six unique .NET CVEs; every finding has a published fixed version, while the current pinned official GitHub runner still bundles .NET `8.0.28`. `--ignore-unfixed` therefore cannot and must not admit it. No release asset, container image, attestation, or GitHub Release exists for `v0.1.1`.

This design does not suppress those findings, fabricate VEX, modify the signed tag, or replace upstream runner bytes. A later product tag is created only after an official compatible runner (or a separately reviewed, source-backed remediation) makes the unchanged HIGH/CRITICAL gate safely green.

## 2. Frozen invariants

The closure must preserve all of these:

- one Worker Cron scheduler; `noRetry`; bounded global and per-fleet deadlines; deadline revalidation; partial-success reporting;
- receipt-only Durable Object SQLite compare-and-swap; no lease, alarm, queue, retry, routing, or ordinary authority bootstrap;
- one host-local fleet fence with monotonic generation and per-holder guards;
- the live legacy launchers and watchdog remain captured, wrapped by the existing fixed-command legacy guard, and active throughout dark deployment;
- the Portable observer is forced disabled, has `maxCapacity=0`, has no workload listener, and holds no portable fleet guard while `legacy` owns the fence;
- one existing lifecycle journal, one release bundle store, one watchdog runner, and one lifecycle lease;
- fail-closed target matching, exact release and private-overlay digests, bounded external commands, positive readback, and idempotent rollback;
- exact-head source review and verification before merge, and exact merged-SHA qualification before either deployment leg;
- no new service, registry, queue, table, alarm, scheduler, timer manager, retry path, persistent permit state, authority abstraction, or generic remote executor.

## 3. Release failure observability

The rehearsal currently collapses every internal failure to `rehearse-runtime: unavailable` and deletes its private log. That is safe for public output but too brittle to operate: the failed `v0.1.1` run did not identify whether source admission, image build, vulnerability admission, SBOM generation, or cleanup failed.

Add one closed, non-sensitive **stage code** to the terminal message. The allowed stages are compiled constants covering the existing sequential rehearsal sections, for example `source`, `runner`, `build`, `security`, `sbom`, `authority`, `compare`, and `cleanup`. The message contains only the stage code; command output, paths, URLs, vulnerability detail, and private logs remain suppressed and deleted. The current security gate and all timeouts remain unchanged.

The release decision remains:

- an unsuccessful build is unavailable evidence and publishes nothing;
- no automatic replay follows a failure;
- `v0.1.0` and `v0.1.1` are never deleted, moved, or reused;
- a new tag names the exact later merged SHA and runs one two-leg release;
- release assets, subjects, hashes, attestations, tag object, source commit, and source tree are positively read back before QTS assembly.

## 4. Worker deployment closure

### 4.1 Deterministic private configuration

Add one small renderer that consumes:

- the checked public `worker/wrangler.jsonc` base;
- a mode-`0600` private deployment descriptor; and
- a mode-`0600` secret document containing exactly `HMAC_KEY` and `CRON_HMAC_KEY`.

The renderer validates and emits one mode-`0600` temporary Wrangler config. It preserves the existing entrypoint, `FLEET` Durable Object binding, and sole `v1/new_sqlite_classes` migration. It adds:

- Worker name `github-actionrunner`;
- the Personal account identifier;
- exactly one Cron trigger, `* * * * *`;
- the sorted three-fleet inventory and only these address-only variables:
  `FLEET_IDS`, `TIMESTAMP_WINDOW_MS`, `NONCE_TTL_MS`, `MAX_FLEETS`,
  `PER_FLEET_DEADLINE_MS`, `CRON_BUDGET_OVERHEAD_MS`,
  `CRON_TICK_BUDGET_MS`, `FLEET_INVENTORY_REVISION`, and
  `FLEET_INVENTORY_DIGEST`.

The renderer recomputes the inventory digest, checks all existing count and budget inequalities, requires two distinct keys of at least 32 bytes, rejects unknown fields and inline secrets, and never writes secret values into the Wrangler config, argv, evidence, or logs. Lease/archive/selector/safety-margin variables are deliberately absent, providing a second fail-closed barrier against ordinary authority.

### 4.2 Persistent signed readback in the existing Worker/DO

Ephemeral `wrangler tail` delivery is not deployment authority: a correct Cron receipt could be missed because the subscription connects after the tick or loses a WebSocket frame. Use the already-reserved `POST /v1/admin/status` path for one narrowly authenticated, read-only addressability query inside the existing Worker and Durable Object. This is not a new service or admin command surface.

The status path is routed before the ordinary-authority hard fence, but only after a status-specific parser succeeds. That parser consumes only the fleet inventory, ordinary HMAC key, timestamp window, nonce TTL, inventory revision, and inventory digest. It must not call `parseWorkerBindings` or depend on lease/archive/selector/safety-margin configuration. Session, heartbeat, and every state-changing admin command remain rejected byte-for-byte.

The request and response use distinct status request/response MAC domains, canonical bodies, bounded reads, the existing timestamp window, and a single-use nonce consumed in the existing `request_nonces` table. Within one existing Durable Object SQLite transaction the handler reads, but does not rewrite, the Cron receipt and an inert-authority summary. It does not call `saveFleetStore`, increment persistence generation, add a table, or mutate authority/child state.

The response binds:

- fleet ID, request nonce, request time, and response time;
- inventory revision and digest;
- Cron tick time, receipt time, and persistence generation;
- fleet mode, holder, capacity, transition state, and bounded existing-table counts; and
- the exact closed status `inert-receipt`.

Incomplete/corrupt receipts, non-inert authority, stale receipts, identity mismatch, replay, and extra fields fail closed.

The scheduled entrypoint still receives a signed response only after each Durable Object has committed its Cron receipt. Preserve that mechanism and also emit one bounded structured diagnostic log record when the scheduled call completes or fails.

The record contains only:

- schema version and event name;
- inventory revision and digest;
- scheduled timestamp;
- addressed fleet IDs and failed fleet IDs in inventory order;
- the persistence generation and receipt time returned by each accepted signed response; and
- one closed success/partial/failure status.

No key, MAC, nonce, request body, response body, account identifier, or arbitrary error text is logged. A partial result is logged and then rethrown so the platform run remains failed. Invalid configuration logs only a closed `configuration-rejected` status without reflecting input.

For live proof, a bounded verifier polls only signed status until every fleet reports a receipt time after the deployed version's creation time, or one caller-supplied overall deadline expires. Each poll waits until the configured Cron tick budget plus one timestamp window after the natural minute boundary, so the bounded Cron invocation can finish before the status query. It performs at most one status request per fleet per natural Cron boundary, so existing nonce consumption remains bounded and cannot contend as a busy loop. It preserves per-fleet partial results, never triggers or replays Cron, and writes one sanitized private evidence file. The structured tail record is corroborating diagnostics only. Require the exact inventory digest, three successful fleet responses, inert authority, receipt times after deployment, and positive persistence generations. A missing tick, partial result, stale version, nonce failure, or overall timeout is not approval.

### 4.3 Deploy and rollback

Use one short-lived Cloudflare account token with only Workers Scripts Write. Deploy the exact merged source and private config, provision the two secrets without printing them, then read back:

- deployed version/source identity;
- Worker name;
- `FLEET` binding and sole SQLite migration;
- exact Cron schedule;
- nonsecret variable names and values;
- secret names only; and
- the signed persistent status result above.

Revoke the short-lived token after readback. Rollback deletes only `github-actionrunner`, verifies absence, and revokes the token even if deletion or readback fails.

## 5. QTS observation and private assembly

### 5.1 One canonical observation

Implement the existing `internal/hostruntime/qts.Source` seam with one target-local, read-only QTS observation command. It uses only fixed argv, bounded command execution, bounded regular-file reads, pre/post file identity checks, and canonical JSON. It is not a generic capture framework.

The private observation binds:

- QTS/Linux/amd64/root platform identity;
- the deployment-root parent and Docker binary device/inode identities plus a canonical bounded Docker server observation, using the production form of the already-tested execution-host identity algorithm;
- live storage, inode, conntrack, cgroup, namespace, Docker, and isolation observations required by `ProfileObservation`;
- the exact legacy supervisor command file, configuration digest, sorted image digests, watchdog digest, root-cron record, process/container identities, and external-watcher state;
- the current fence header and every exact legacy holder; and
- observation start/end times and per-probe deadlines.

Target drift between pre/post identities, truncated output, unknown fields, an unsafe file, an unexpected command, a malformed legacy holder, or an unbounded probe rejects the observation and performs no mutation.

Device/inode values are freshness observations, not permanent machine identifiers. A daemon reinstall, firmware update, volume remount, or deployment-root replacement legitimately invalidates the prior observation and requires a fresh capture and overlay; the lifecycle must not attempt to repair or normalize that drift automatically.

The control-host identity is computed locally from the already-pinned OpenSSH executable, private-key public fingerprint, known-hosts content/identity, local UID, and canonical repository/control-root identity. `NewSSHTransport` recomputes it before every remote lifecycle invocation. The target proof may carry the bound digest, but local transport admission—not a target echo—is the authority that it is current.

### 5.2 Mechanical assembly

Add one control-side assembler that consumes exactly:

- the verified product release tree and `runtime-release.json`;
- the canonical QTS observation;
- the recorded approved sizing tuple and overlay field-source map; and
- one typed private operator document for paths, repository bindings, time bounds, secret references, and management transport.

The assembler uses the existing typed `RuntimeManifest` and `PrivateOverlay` constructors and canonical marshal/parse functions. It does not assemble JSON maps in shell and does not add a schema.

It must:

- verify every `provenance-subjects.json` subject hash and exact release source/tag identity;
- map the five runtime roles to runner, adapter, broker-dialer, helper, and verifier OCI manifests; the broker role intentionally uses the dialer image because it contains the parser binary;
- reject tar-file hashes substituted for OCI manifest digests;
- bind the exact live target/control identities and captured legacy material;
- reuse the approved 3 GiB runner tmpfs, 512 MiB `/tmp`, 512 MiB scratch, 5 GiB memory, 5 GiB swap, PID 512, p99/margin/reclamation values, total concurrency four, and per-fleet caps 2/1/1;
- validate the complete host profile and all existing sizing/storage/network/secret rules; and
- write manifest and overlay atomically only after both round-trip through the existing strict parsers.

Before implementing the assembler or QTS installer, run one disposable Linux/Docker probe using a release-format OCI archive. Positively determine whether the deployed QTS Docker engine can load it and populate the exact immutable `RepoDigests` identity required by `ReleaseArtifactVerifier`; remove the probe image afterward. If it cannot, deployment and this implementation branch stop at that boundary. Do not add a registry or weaken digest admission inside this slice. That empirical result determines whether a separately reviewed distribution change is needed.

## 6. Legacy fence adoption and dark-observer lifecycle

### 6.1 Fence adoption

Before installing Portable code:

1. capture and privately back up the exact live legacy scripts, images, configuration, watchdog/cron state, external watcher state, and required credentials;
2. positively read back existing GitHub routing as hosted, keep the existing external watcher live, and observe no active legacy `Runner.Worker` process across the bounded idle window;
3. revalidate the capture against live process/container/cron state;
4. initialize `none@0 -> legacy@1` with the existing idempotent fence handoff;
5. restart each exact captured legacy launcher/watchdog only through `deploy/qts/run-legacy-fenced.sh`; and
6. positively read back `legacy@1` and the complete expected holder set.

This bounded adoption uses fixed commands and existing fence primitives. Hosted routing plus the stable idle observation closes the incoming-job race while the supervisor is rewrapped; the adoption itself does not write routing. A crash before handoff leaves the prior legacy launch unchanged. A crash after handoff is safely down and replayable from the recaptured exact state. If hosted routing, exact launcher control, process absence, or holder readback cannot be proven, stop; do not add a supervisor service, generic executor, or second owner registry.

### 6.2 Correct the legacy install disposition

The authoritative platform design requires dark deployment beside the active legacy fleet. The current intermediate install sequence instead includes `legacy-acquisition-disabled`, `legacy-drained`, `legacy-controller-stopped`, and `legacy-quiescence-proven`; following it would violate the approved dark-deploy invariant.

The production legacy observer sequence is therefore exactly:

```text
prepared
preflight-proven
candidate-staged
candidate-smoked
prior-retained
disposition-legacy-proven
fence-legacy-proven
legacy-normalized-proven
watchdog-installed
policy-disabled
observer-started
zero-proven
current-selected
verified
complete
```

For this disposition:

- a prior Portable manifest is optional; initial adoption must not fabricate one;
- the private overlay revision binds the captured legacy command/config/image/watchdog identity;
- the fence must remain `legacy` at the same nonzero generation throughout;
- the exact legacy holders must remain present and unchanged;
- normalization changes only the Portable acquisition-policy epoch to disabled/empty/zero exactly once;
- the new Portable observer has no self guard token while legacy owns the fence;
- install and compensation never disable, drain, stop, restart, or remove a legacy launcher; and
- a crash after selection compensates by stopping/removing only the Portable observer, current selection, candidate, and Portable watchdog registration.

The legacy compensation graphs must change with the normal path. Both pre-selection and post-selection compensation replace the old `legacy-zero-proven` / `legacy-started` assumptions with one read-only `legacy-preserved-proven` phase. That phase compares the current fence header, generation, complete holder set, launcher identities, and captured command/config/image/watchdog digests to the operation binding. It performs no legacy effect. A mismatch stops compensation for operator investigation rather than attempting to start, stop, or repair legacy.

The old legacy-stop phases remain valid only where a later, explicitly named migration or rollback operation truly retires/stops legacy. They are not part of dark observer install.

### 6.3 Verification and uninstall

Terminal verification for this disposition requires:

- exact target and control identities;
- the selected target manifest and private-overlay revision;
- unchanged `legacy` fence generation and exact legacy holder set;
- exact force-disabled Portable observer process;
- disabled/empty/zero policy with the receipt-bound normalization projection;
- zero listeners, runners, pending acquisition, broker capacity, and portable guards;
- exact watchdog marker and QTS cron registration; and
- unchanged captured legacy command/config/image/watchdog identity.

Uninstall is idempotent and removes only the Portable observer, selection, registration, watchdog marker, and Portable cron line. It preserves the legacy fence, holders, launchers, captured rollback material, lifecycle/release evidence, and unrelated root cron byte-for-byte.

## 7. Lifecycle-owned QTS watchdog cron

Extend the existing watchdog registration effect so presence means **both** the existing marker and one exact QTS root-cron line in QTS's persistent `/etc/config/crontab`. The helper:

- derives the fixed line from the watchdog binary and exact manifest/private paths;
- maps only supported watchdog cadences to QTS cron syntax;
- edits one bounded cron source under the lifecycle lease;
- preserves every unrelated line byte-for-byte;
- installs, invokes the fixed QTS crond reload command, and reads back through fixed, bounded commands;
- converges marker-only and cron-only crash states idempotently; and
- rejects foreign/malformed Portable lines without changing them.

No long-lived timer manager is added. Cron invokes the existing one-cycle `SystemWatchdogRunner`, which retains its current bounded calls, ownership checks, and no-network/no-GitHub/no-Worker boundary. Dark deployment additionally proves the exact line survives one controlled crond reload. A QTS firmware update or any administrative cron regeneration invalidates that evidence and requires the same install/readback verification before the observer is again claimed watched. Loss of the line is safe in this phase because legacy remains active and Portable has zero authority; it is never treated as marker-only success.

## 8. Failure and degradation matrix

| Dependency/effect | Failure | Safe outcome |
| --- | --- | --- |
| GitHub release build | vulnerability, build, compare, attestation, or publication failure | publish nothing; retain typed stage; no replay |
| Cloudflare token mint/deploy | auth, quota, API, or partial deployment | ordinary authority stays hard-disabled; read back exact version or delete; revoke token |
| Natural Cron/status | no tick, partial fleets, stale receipt, timeout, status auth/read failure | no Cron retry; deployment not green; receipts remain inert |
| SSH/control identity | key/known-host/binary/control-root drift | no remote action |
| QTS observation | timeout, truncation, identity drift, malformed state | no mutation and no assembly |
| Legacy adoption | stale capture, non-idle fleet, handoff/readback mismatch | stop before mutation, or remain safely down after handoff; bounded replay only |
| OCI load/readback | archive/hash/reference mismatch | no selection or observer start |
| Lifecycle effect | crash before/after apply or receipt | existing journal/readback resumes exactly once |
| Watchdog registration | marker-only or cron-only partial state | reconcile under lifecycle lease; foreign line untouched |
| Observer start/verify | process, policy, listener, fence, or holder mismatch | stop/remove Portable observer; legacy remains active |
| Uninstall | partial removal | replay removes only owned Portable state; legacy and unrelated cron remain |

Every external call is bounded by an enforceable timeout or explicit lifecycle cancellation. Every background waiter/tail is deterministically joined. No failure starts an unbounded retry or a more privileged fallback.

## 9. Verification strategy

Implementation follows RED-first tests. The minimum matrix is:

- closed release stage reporting while private diagnostics remain suppressed;
- deterministic Worker config bytes, exact binding/migration/trigger/vars, distinct keys, secret non-disclosure, and dry-run bundle;
- scheduled success/partial/failure structured records plus signed status readback, replay rejection, and byte-identical state outside existing nonce consumption, without weakening `noRetry`, deadlines, or the hard ordinary-authority fence;
- canonical QTS observation, bounded fixed probes, stable pre/post identities, and rejection of drift/truncation/unknown input;
- deterministic manifest/overlay assembly, exact subject and OCI-role mapping, round-trip parsing, and no partial output;
- initial legacy operation with nil prior Portable manifest;
- adopted-legacy target classification and continuation;
- dark legacy install and both compensation graphs across every journal crash boundary with byte-equivalent fence header/holders and no legacy stop/start callbacks;
- one-time normalization and receipt replay;
- exact observer zero-listener/no-acquisition composition;
- marker+cron install/readback/replay/removal/partial-state convergence and foreign-line preservation;
- terminal legacy-observer verification drift cases;
- idempotent uninstall preserving legacy ownership and unrelated cron;
- focused race/repetition tests, full Go/Worker/shell/repository gates, Linux/Docker full runtime gate, and exact-head review.

## 10. Deployment gates and rollback

The Worker leg may proceed after its source PR merges and exact merged-SHA CI/review gates pass. Its production green condition is exact settings/secret-name/version readback plus signed current-version status for one natural three-fleet Cron receipt. Rollback is Worker deletion and absence proof.

The QTS leg additionally requires:

1. a successful new immutable product release from a safe runner payload;
2. downloaded asset hash/subject/attestation/source/tag verification;
3. a fresh canonical QTS observation and private backup;
4. exact legacy fence adoption and holder readback;
5. successful immutable OCI load/readback under the existing verifier contract;
6. operator-run root installation on the verified QTS target, never this Mac; and
7. terminal zero-listener/zero-acquisition/fence/holder/watchdog/cron readback.

Any missing evidence is not approval. Rollback removes only Portable watchdog/observer state and proves the legacy fleet, fence holders, external watcher, hosted routing, and unrelated cron are unchanged.

## 11. Explicit non-goals

This slice does not enable Worker session/heartbeat/lease/routing authority, create a hosted hold, add a state-changing admin command, migrate workflows, run a canary, hand the fence to Portable, retire legacy, add a registry, patch the upstream runner, add persistent permit state, or change the approved permit/controller state machine. Those require separately named later phases and their existing gates.
