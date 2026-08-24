# Worker and Release Closure Implementation Plan

> **Execution contract:** implement each task RED-first, keep the ordinary Worker authority fence byte-for-byte effective, and do not create or replay a release tag until every exact-head gate is satisfied.

**Goal:** make release failures operable without disclosing diagnostics, deploy the Worker in address-only mode from an exact merged SHA, and prove one natural three-fleet Cron receipt through a persistent signed read-only status path.

**Architecture:** extend the existing release rehearsal with one closed stage code. Add one status-specific protocol/parser/reader inside the existing Worker and Durable Object, using the existing nonce table and SQLite transaction. Add deterministic private-config rendering and a bounded natural-Cron verifier. No ordinary lease/archive/selector configuration, new table, alarm, queue, retry, service, or authority path is introduced.

**Tech stack:** TypeScript/Vitest/Cloudflare Workers/Durable Objects/SQLite, Node.js scripts, Bash/Bats, Wrangler.

---

## Task 1: Closed release-stage diagnostics

**Files:**

- Modify: `scripts/release/rehearse-runtime.sh`
- Modify: `tests/shell/runtime-release.bats`

1. Add RED tests proving each existing rehearsal section maps to a compiled closed stage, the terminal error exposes only that stage, and private log content/path remains absent.
2. Run `bats tests/shell/runtime-release.bats` and confirm the new cases fail for the missing stage.
3. Track the current stage with a fixed allowlist (`source`, `runner`, `build`, `security`, `sbom`, `authority`, `compare`, `cleanup`) and emit only `rehearse-runtime: unavailable stage=<stage>` on failure.
4. Re-run the focused Bats suite and `git diff --check`. Do not change vulnerability policy, timeouts, cleanup, or publication behavior.

## Task 2: Frozen signed status protocol

**Files:**

- Create: `worker/src/protocol/address-status.ts`
- Create: `worker/test/protocol/address-status.test.ts`
- Modify only if a tiny shared primitive is required: `worker/src/protocol/messages.ts`

1. Add RED vectors for canonical request/response bodies, distinct request/response domains, extra-field rejection, malformed MACs, stale/future timestamps, wrong fleet/inventory identity, and ordinary-vector preservation.
2. Run the focused Vitest file and confirm protocol symbols are absent.
3. Implement a direct deterministic string-to-bytes tagged preimage primitive; do not decode and re-encode an ordinary byte preimage.
4. Re-run focused protocol tests plus all frozen ordinary message vectors.

## Task 3: Minimal address-status bindings

**Files:**

- Create: `worker/src/config/address-status-bindings.ts`
- Create: `worker/test/config/address-status-bindings.test.ts`

1. Add RED tests for the exact required inputs: fleet inventory, timestamp window, nonce TTL, inventory revision/digest, and ordinary HMAC key solely for distinct-key rejection.
2. Prove missing or invalid lease/archive/selector/safety-margin variables cannot disable valid status parsing and unknown status inputs fail closed where applicable.
3. Implement the focused parser without calling `parseWorkerBindings()` or constructing lease-specific configuration.
4. Re-run the focused suite and a regression test that malformed external-authority configuration still blocks external authority.

## Task 4: Read-only Durable Object status transaction

**Files:**

- Create: `worker/src/state/address-status.ts`
- Create: `worker/test/state/address-status.test.ts`
- Modify: the existing Durable Object router/handler files located by `rg -n "v1/admin/status|fetch\(" worker/src`

1. Add RED tests for nonce consume-once, one-transaction reads, corrupt/incomplete receipt rejection, stale receipt rejection, inert-authority enforcement, bounded existing-table counts, and exact signed response fields.
2. Snapshot all persistent state before/after a successful status call and prove the only mutation is the existing request-nonce consumption; persistence generation and authority/child state must not change.
3. Implement the read path using the existing `request_nonces` table. Do not call `saveFleetStore`, add a table, or increment generation.
4. Re-run focused tests and the Durable Object migration/schema suites.

## Task 5: Route only status before the production authority fence

**Files:**

- Modify: the existing Worker gateway/runtime routing files located by `rg -n "ADDRESS_ONLY_AUTHORITY_DISABLED|admin/status" worker/src`
- Modify: relevant runtime/gateway tests under `worker/test/`

1. Add RED tests proving only signed `POST /v1/admin/status` can pass before the fence; session, heartbeat, lease, and all state-changing admin routes remain rejected with their frozen response.
2. Implement the narrow route after status-specific parsing/authentication and before the ordinary hard fence.
3. Run the focused gateway/runtime suites, frozen protocol suites, and grep the production path to prove `parseWorkerBindings()` is not reachable from status.

## Task 6: Preserve Cron receipt metadata and emit closed logs

**Files:**

- Modify: `worker/src/runtime.ts`
- Modify only for scheduled-entry logging delegation if needed: `worker/src/index.ts`
- Modify: the Cron protocol/runtime tests under `worker/test/`

1. Add RED tests for success, partial success, complete failure, and configuration rejection logs; prove inventory order, receipt time, and persistence generation are retained.
2. Prove no key, MAC, nonce, request/response body, account ID, or arbitrary error text appears, and partial failure is logged then rethrown with `noRetry` unchanged.
3. Implement one bounded structured record and retain accepted response metadata.
4. Run focused scheduled/runtime tests, including exact deadline equality, per-fleet deadline revalidation, partial success, and `noRetry` assertions.

## Task 7: Deterministic private Worker configuration renderer

**Files:**

- Create: `scripts/render-worker-deployment.mjs`
- Create: `worker/test/deployment/config.test.ts`
- Update: `package.json` only if a test/command entry is necessary

1. Add RED fixtures for exact output bytes, Worker name, Personal account, `FLEET` binding, sole `v1` SQLite migration, one `* * * * *` Cron, sorted three-fleet inventory, exact address-only variable allowlist, recomputed digest, budget inequalities, mode checks, unknown fields, inline secrets, short/equal keys, and secret non-disclosure.
2. Implement strict descriptor parsing and write one mode-`0600` temporary config atomically. Keep secrets out of the rendered Wrangler file.
3. Run focused tests and `wrangler deploy --dry-run --config <rendered>` against a sanitized fixture.

## Task 8: Bounded natural-Cron verifier

**Files:**

- Create: `scripts/ops/verify-worker-addressability.mjs`
- Create: `worker/test/deployment/addressability-verifier.test.ts`

1. Add RED tests for three-fleet success, partial preservation, stale receipt/version, identity mismatch, nonce rejection, exact-deadline equality, overall timeout, and at-most-one request per fleet per natural Cron boundary.
2. Implement signed status polling with a lifecycle-owned abort/deadline and deterministic waiter cleanup. It must never trigger or replay Cron.
3. Emit one mode-`0600` sanitized evidence file that contains no secret/MAC/request body.
4. Re-run focused tests with fake time and deterministic cancellation/join assertions.

## Task 9: Operator runbook and rollback

**Files:**

- Create: `docs/operations/worker-address-only-deployment.md`

Document exact merged-SHA qualification, private-input creation, token scope, secret provisioning, deploy/readback, natural-Cron proof, token revocation, and rollback-by-deleting-only-`github-actionrunner`. Explicitly state that missing status evidence is not approval and QTS release assets are not a Worker prerequisite.

## Task 10: Exact-head verification

Run from the repository root:

```bash
cd worker && npm run lint && npm run typecheck && npm test -- --run
cd .. && bats tests/shell/runtime-release.bats
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go tool staticcheck ./...
git diff --check
```

Then run the repository's documented exact-head/full gates. Record the commit/tree and do not reuse review evidence after any head change.
