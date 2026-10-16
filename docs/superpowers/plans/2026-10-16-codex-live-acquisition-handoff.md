# Live acquisition: Claude to Codex handoff (as of 2026-10-16)

**From:** Claude, which drove plan phases 1-6 of the live acquisition plan.
**To:** Codex, which takes over from phase 7.
**Base:** `main` at `d1ddad9` (PR #114).

Read this first, then the plan it continues:
`docs/superpowers/plans/2026-10-10-live-acquisition-plan.md`. The plan holds
the decisions (D1-D7) and the phase order. This document records what is
done, what is left, what was learned on the way, and the rules the operator
set. Where this document and the plan disagree, the plan's decision text
wins and this document is the one to fix.

## 1. Ground rules from the operator

These are standing rules. None of them may be relaxed without the operator
saying so.

**Design.** Reliable and non-brittle, as simple as practical, no machinery
that is not needed. The operator rejected designs that add approval steps or
mechanisms that can each fail the whole deploy. Prefer one small rule over a
framework. When in doubt, propose the smaller design and ask.

**Hosts.**

- The operator's personal workstation is never a runtime, staging, control,
  or deployment host.
- The QTS target is controlled only through the verified control host.
- The existing production runner host stays untouched. It is the production
  runner and the fallback.
- No host mutation until the gates pass.

**Releases and the Worker.**

- Never move, reuse, or delete the tags `v0.1.0` or `v0.1.1`.
- Do not redeploy the Worker or replay runs. A Worker redeploy needs its own
  explicit operator go, even after the code is merged.

**Public safety.** This is a public repository.

- No real hostnames, addresses, account or zone identifiers, repository
  coordinates of the deployment, tokens, or real logs. Use placeholders such
  as `<state_root>` and "the QTS target".
- Do not name the target host in repository text. Say "QTS target".
- `python3 scripts/sanitize_public.py --tracked --history` must pass.

**Operator steps.** D2, D5, and D7, the Worker redeploy, and the canary
itself are run by the operator. The repository ships exact commands for them;
an agent never runs them. There is no route from a cloud agent session to the
control host or the QTS target.

**Merging.** The operator authorised Claude to squash-merge PRs in this work
stream once CI is green and the Codex reviews are clean, pinned to the
reviewed head SHA. That authorisation was given to Claude. Codex should
confirm with the operator how merges are approved before merging anything.

## 2. What is done

All of the following is merged on `main`.

| PR | Plan phase | What it did |
| --- | --- | --- |
| #92 | plan | Live acquisition plan with decisions D1-D7. Later PRs updated its phase section as each phase was scoped. |
| #102 | 1 | Optional overlay `worker` and `github` sections. |
| #103, #113 | 2 | Worker lease authority behind `WORKER_AUTHORITY=enabled`, `portable-canary-start` and `portable-canary-stop`, and the forward fix that persists `session-rejected` audit rows. Not deployed. |
| #104 | 3 | GitHub sessions, `external-probe`, and `create-scale-set`. |
| #105, #106 | 4 | Permit sockets bound to their slot with production guards; production setup builder and slot directories. |
| #107 | 5a | Overlay `jail` section and startup cleanup. |
| #108 | 5b | Setup builder configuration built from the overlay. |
| #109, #110 | 5c, 5d | Parts for the acquiring controller, then `portable-ghar-controller run-acquisition`. |
| #111 | CI | Dated `.trivyignore` entry, `CVE-2026-84008 exp:2026-11-14`. Revisit by that date. |
| #112 | ops | `docs/operations/live-acquisition-operator-steps.md`: the exact D5, D7, and D2 commands. |
| #114 | 6a | The D2 harness writes its report to `PGHAR_CONFORMANCE_REPORT`. Corrected D2 command. |
| #115 | 6b | Gate rule: a report with cases 1-14 passed and case 15 pending allows `canary-only` only. `run-acquisition` reads `<state_root>/conformance-report.json`. |

### D1 as built (phase 6)

The plan's D1 text is authoritative. In short:

- `internal/conformance/gate.go`: `reportAuthority` returns `enabled` for a
  full pass and `canary-only` for a report whose cases 1-14 passed, whose
  case 15 is pending with the fixed pending evidence, and whose cleanup
  passed. Anything else is refused. `validateReport` already guarantees case
  15 is the only case that can be pending; the gate relies on that.
- `conformance.RequireFullPass` is what deployment evidence uses
  (`internal/hostruntime/evidence.go`). A pending report never yields target
  evidence.
- `cmd/portable-ghar-controller/production_acquisition.go`,
  `productionConformanceGate`: no file means every active mode is refused. A
  file that is not a root-owned mode `0600` regular file, or does not parse,
  or grants nothing, stops startup at the step `read conformance report`.
- There is no authority table, no single-use consume, and no per-job binding.
  The operator removed them deliberately. Do not reintroduce them. The one-job
  bound is procedural: capacity 1, one dedicated scale set and label, and the
  runbook sets `disabled` after the job.

## 3. What is left

### Phase 7: case 15 evidence

Scope from the plan: record the canary job's result, a `canary-seal` command
that derives the evidence only from durable state, completion of the same
pending report, the canary workflow, and the JIT hand-over fix if the probe
needs it.

Facts established while scoping. Each has a file reference; re-check before
relying on it.

1. **Case 15 requirements** are in
   `docs/superpowers/plans/2026-07-29-task11-implementation.md`, "Case 15:
   actual GitHub transport" (around lines 1297-1316). The canary must: obtain
   one JIT through the governed acquisition path; get an in-run authenticated
   `githubscale.Compatibility()` result proving live `DisableUpdate=true`;
   apply the operator's bounded-credential amendment (PR #120 is a prerequisite:
   own-job `/proc` and tmpfs exposure is recorded without bytes; inherited JIT
   and prohibited Docker, host, log, report, or cross-container leaks still
   fail); complete one real listener transport and HTTPS checkout; run every
   current proxy-sensitive tool; prove deregistration and full reclamation;
   and bind all of it to the same manifest, image, profile, policy, network
   evidence, fleet generation, and report run. Task 11 forbids any alternate
   JIT source or direct GitHub call.
2. **The sealer exists**: `conformance.SealActualGitHubTransport`
   (`internal/conformance/report.go`, around line 410). It takes an assertion
   count, an observation digest, and measurements. Case 15 allows only
   `job_count` and `tool_count` (`allowedMeasurement`, around line 1243).
   Nothing produces its input yet.
3. **Report completion API.** `conformance.CompleteActualGitHubTransport`
   (`internal/conformance/completion.go`) takes the parsed pending report and
   a sealed `ActualGitHubResult`. It requires validated canary-only authority,
   replaces only case 15, recomputes status, report digest, and build seal,
   and validates the result. It preserves the entire original binding,
   cases 1-14, target observations, and cleanup. It rejects already-completed,
   failed, or corrupt reports and pending or invalid results. The collector
   still must derive its result from durable observations tied to that same
   report; this low-level API does not collect evidence or run a canary.
4. **Durable evidence collection and sealing.** The phase 7 collector retains
   one bounded non-authorizing journal row before ordinary assignment
   compaction. Existing acquisition batches, governed permits, listener release
   effects, identity-checked job events, and cleanup/finalization supply the
   lifecycle evidence. The fixed `canary-read` command reads the reviewed final
   workflow step's private Unix socket while the lifecycle lock prevents job
   teardown. It stores only closed observations, never raw logs or credentials.
   `canary-seal` requires disabled, quiescent durable state and completes the
   original pending report. See
   [the evidence mapping](../../operations/live-acquisition-case15.md).
5. **The JIT is bounded, not hidden from its own job.** The operator explicitly
   selected bounded exposure. PR #120 updates the plan, Task 11, and trust
   boundary consistently and adds the three fixed tmpfs configuration links the
   pinned listener needs. Those source/image changes must be reviewed and
   installed before D2. No JIT hand-over redesign is needed for own-job `/proc`
   readability. Do not claim the job cannot observe its one-job credential.
6. **The canary workflow** targets only the scale set's single label created
   in D7. It lives in the dedicated canary repository. This repository ships
   [a reviewed-install template](../../../examples/live-acquisition/README.md),
   not an enabled canary workflow. The operator records and verifies its exact
   revision and dispatched run before sealing.

Phase 7 changes the conformance package, so it needs a security review, as
phase 6 did.

### Phase 8: canary runbook

Scope from the plan: one bash script that journals each step: watchdog
suspend, fence handover, Worker start, `canary-only`, dispatch, wait, seal,
residue check, and the reverse steps. Existing pieces to reuse:
`deploy/qts/suspend-controller.sh`, `resume-controller.sh`,
`rollback-controller.sh`, `uninstall-watchdog.sh`, `install-watchdog.sh`, and
the fence binary's `handoff` command.

Gaps found while preparing this handoff:

- **Worker admin client prerequisite.** PR #119 supplies the one-shot signed
  `worker-canary` client and exact canonical command instructions. It must be
  reviewed and installed before the runbook. The original gap was:
  **No client sends Worker admin commands.** `portable-canary-start` and
  `portable-canary-stop` are signed `POST /v1/admin/command` requests
  (`docs/operations/worker-canary-authority.md`). The Go side has only the
  path constants (`internal/failoverclient/auth.go`, lines 18-19). Nothing
  signs or sends an admin command. The runbook needs a small one-shot
  subcommand, for example in `portable-ghar-controller`, that reads the
  overlay's Worker section and HMAC secret and sends one command. [Verify:
  how the Worker authenticates admin requests, in `worker/src/protocol/admin.ts`,
  before designing the client.]
- **The fence generation moves at the handover.** `handoff` writes
  `ExpectedGeneration + 1` (`internal/fleetfence/store.go`, around line 353).
  `run-acquisition` requires the fence to name the portable fleet at exactly
  the runtime manifest's `fleet_generation`
  (`production_acquisition.go`, around line 140), and the gate requires the
  report's fleet generation to match the controller's. If D5 reads N, the
  approved runtime manifest and D2 input/report must carry N+1. The overlay
  has no generation field: it binds the exact manifest path and digest.
  PR #117 adds the missing explicit runtime-manifest assembly command and
  operator instructions. Worker fenceGeneration must also be N+1; its
  leaseGeneration is independent. Finish all manifest/image/overlay changes
  before D2 consumes its input.
- **D4.** The watchdog safe-stops any controller that is not `disabled`, so
  the runbook suspends it for the canary window and re-arms it after, as a
  journaled step.
- **D6.** Hosted and replay routes are stubs; a stale offer ends the process.
  Accepted for the canary. Real hosted routing comes before `enabled`.
- The runbook must end with `disabled`, whatever happened.

### Smaller follow-ups

- Revisit `.trivyignore` `CVE-2026-84008` by 2026-11-14.
- `cmd/portable-ghar-fleet-fence` and `cmd/portable-ghar-task11-listener`
  tests fail in sandboxed agent containers only. They pass in CI.
- With `-tags integration`, four `testenv` Task 11 root tests
  (`TestTask11SyntheticCycleRoot*`, `TestTask11RecoveryRoot*`) fail on `main`
  as well. CI does not run tagged tests. Not caused by phase 6.

## 4. Operator steps and their order

In plan order. None has been recorded as run in this repository; confirm the
current state with the operator.

1. **D5, fence read (read-only).** `live-acquisition-operator-steps.md`, D5.
   The result table decides the handover. Record N.
2. **D7, scale set and token.** Same document, D7. `create-scale-set` twice
   (the second must print `"created":false`), then `external-probe`.
3. **D2, conformance cases 1-14 on the target.** Same document, D2. The
   report must end up at `<state_root>/conformance-report.json` as a
   root-owned, mode `0600` file. If the input's euid is 0, write it there
   directly. Otherwise write it elsewhere and install a root-owned copy with
   the same bytes. Expect cases 1-14 passed and case 15 pending. Resolve the generation question in
   section 3 first.
4. **Worker redeploy** with the `authority` block. Needs its own explicit go.
5. **The canary**, through the phase 8 runbook.

## 5. How work was done here

**Branches and PRs.** One branch and one PR per change. PRs open as drafts,
then are marked ready, which triggers the Codex code and security reviews.
Commits are signed. PR bodies follow the repository template: Summary, Test
plan, PUBLIC-SAFETY checklist, Additional context.

**Checks to run before pushing.**

```sh
go tool staticcheck ./...
go vet ./...
GOOS=darwin go vet ./...
go vet -tags integration ./...
GOOS=darwin go vet -tags integration ./...
go test -race ./...
npm run -s lint:docs
npm run -s format:check
python3 scripts/sanitize_public.py --tracked --history
python3 scripts/check_repository_metadata.py --root .
```

Also run changed packages as a non-root user: build with `go test -c` and run
the binary from the package directory under
`setpriv --reuid=65534 --regid=65534 --clear-groups`. Several tests check
ownership and modes and behave differently as root.

**Test discipline.** Write the failing test first. For each new guard, run a
mutation check: remove the guard and confirm a test fails. If no test fails,
either the guard is redundant (remove it) or a test is missing (add one).

**Review findings.** Confirm a finding before fixing it. Fix it with a test
that fails without the fix, reply on the thread with the commit, and resolve
it. Several findings of one kind mean the root cause is still open.

**Known traps.**

- `go test -buildvcs=true` stamps `vcs.revision` in a regular clone but
  silently omits it in a git worktree. The D2 preflight needs the stamp.
- `conformance.ParseReport` accepts canonical JSON only, with no trailing
  newline. Write reports with `MarshalReport`.
- Only `amd64` targets pass the overlay schema.

## 6. File map

| Topic | Where |
| --- | --- |
| Plan and decisions | `docs/superpowers/plans/2026-10-10-live-acquisition-plan.md` |
| Task 11 spec (case 15, invariants) | `docs/superpowers/plans/2026-07-29-task11-implementation.md` |
| Operator steps D5, D7, D2 | `docs/operations/live-acquisition-operator-steps.md` |
| Acquiring controller | `docs/operations/operations.md`, `cmd/portable-ghar-controller/production_acquisition.go` |
| Worker authority and canary commands | `docs/operations/worker-canary-authority.md`, `worker/src/engine/admin.ts` |
| Scale set and probe | `docs/operations/github-scale-set.md`, `internal/githubscale/` |
| Conformance report and gate | `internal/conformance/report.go`, `gate.go`, `registry.go` |
| D2 harness and report writer | `tests/integration/conformance_test.go`, `tests/integration/testenv/fixture.go`, `report_output.go` |
| Fence | `internal/fleetfence/store.go`, `cmd/portable-ghar-fleet-fence/` |
| QTS scripts | `deploy/qts/` |
| Earlier handoffs | `2026-08-16-grok-primary-builder-handoff.md`, `2026-08-24-claude-phase3-deploy-handoff.md` (both superseded where this one differs) |
