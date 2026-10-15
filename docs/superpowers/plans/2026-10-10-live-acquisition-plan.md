# Live acquisition: phased plan

**Goal:** run one real GitHub Actions job through the Portable controller on
the QTS target in `canary-only` mode, then stop. Production routing, full
capacity, and retirement of the existing runner remain out of scope.

**Status:** approved by the operator on 2026-10-12. Every decision in
section 2 is taken as recommended. Two limits from the standing rules still
apply:

- The Worker is not redeployed without a separate, explicit operator go at
  that step, even after its code merges (D3).
- Steps that run on the target, read live host state, or change GitHub
  settings are operator actions (D2, D5, D7). Each phase ships the exact
  commands; nothing here runs them.

**Design rule:** reliable and simple first. Reuse the library code that
already exists and is tested. Add no new framework, service, or abstraction
unless a phase cannot work without it. When a phase can be smaller, it is.

## 1. Where the source stands (main @ ecd645c)

The pieces needed for acquisition exist mostly as library code exercised by
unit tests. Nothing joins them in the production process.

| Area | State | Evidence |
| --- | --- | --- |
| Controller process | The binary always starts the disabled observer. `controller.Service` is constructed only in tests. | `cmd/portable-ghar-controller/commands.go:44-61`; `production_controller.go:145-395`; `disabled_admin.go:122,323` rejects every mode except disabled |
| GitHub scale-set client | Complete (PAT only). No production caller. | `internal/githubscale/client.go:98-131,373-431`; `adapter_v040.go` |
| Overlay repository fields | `config_url`, `scale_set_name`, `credential_name` are validated but read by no other code. | `internal/hostruntime/private_overlay.go:271-281,761-769` |
| Worker lease client | The protocol client and heartbeat session are constructed only in their own package's tests; the lease cache and permit provider also appear in the test environment. | `internal/failoverclient/client.go:71`, `heartbeat_session.go:57`, `permit.go:216`; `tests/integration/testenv/task11_synthetic_permit.go:92-103` |
| Overlay Worker settings | No Worker URL, HMAC secret, or fleet ID field exists. | strict schema, `private_overlay.go:371-392` |
| Worker authority | The deployed Worker is compiled address-only. Session, heartbeat, and admin requests are rejected. | `worker/src/protocol/cron.ts:7` (`ADDRESS_ONLY_AUTHORITY_DISABLED = true`); `worker/src/runtime.ts:57-58` |
| Worker canary route | The routing machine allows `HOSTED → PORTABLE_CANARY`, but no admin command enters it. | `worker/src/routing/machine.ts:7`; `worker/src/engine/admin.ts:320` (only `LEGACY_CANARY`); `heartbeat.ts:229-310` |
| Conformance gate | `canary-only` needs a fully passing 15-case report, checked at transition and before every guarded poll, acquire, and JIT call. The report binds BuildID, runtime manifest, private overlay, and fleet generation. No production report producer exists; `SealActualGitHubTransport` is called only by tests. | `internal/conformance/gate.go:62-125`; `registry.go:68-82`; `report.go:72-86,397-420,475-520` |
| Network jail authority | Production has no `PermitPeerValidator`, `LedgerReferenceGuard`, or `EmptyConntrackValidator`. The test environment has the first two and a reject-only stub for the third. | `internal/networkjail/permit_proof.go:28-54`; `tests/integration/testenv/permit_guard.go:163-177` |
| Lifecycle runtime | `lifecycle.Service` is constructed only in its own tests. No `SessionProvider` or `SetupBuilder` exists outside a unit-test fake. | `internal/lifecycle/service.go:131`; `service_test.go:482` |
| Controller service dependencies | `NewService` rejects a nil value for any of 16 dependencies, and no non-test code calls it. `FatalTerminator` and `EventSink` have no implementation outside tests. `ReplayVerifier` and `HostedRouter` have only the fail-closed stub. Real implementations of the broker adapter, permit provider, conformance gate, capacity provider, health publisher, and lifecycle runtime exist, but the controller binary constructs none of them. | `internal/controller/service.go:665-700`; fakes at `service_test.go:1972,2800`; stub at `cmd/portable-ghar-controller/disabled_authority.go:284,300`; the binary wires a zero-demand broker stub at `production_controller.go:356` |
| Case 15 evidence | `SealActualGitHubTransport` accepts a caller-supplied assertion count and digest. No collector produces the evidence the spec lists, and the target profile always returns pending. | `internal/conformance/report.go:410-427` |
| Hosted and replay routes | Stubs only. A stale, oversized, or untimed offer ends the poll loop and so the controller process. | `internal/controller/service.go:2026-2046`; `runtime.go:146-193` |
| Watchdog | Every cycle requires `disabled` mode and capacity 0, and safe-stops the controller otherwise. It only launches the disabled path. | `internal/watchdog/watchdog.go:235-253`; `internal/productionruntime/controller_probe.go:64-72` |
| Fence | Acquisition needs the portable fence guard. The QTS install keeps the legacy fleet active. The live fence state on the target is not recorded here. | `internal/controller/acquisition.go:58-61`; `internal/cli/host.go:627-635` |

The runner image cannot run a job outside this stack. The listener's proxy is
fixed to the adapter's loopback relay (`internal/runtimeenv/environment.go:22,52-55`),
and release requires the gate's arm and namespace handshake
(`cmd/portable-ghar-runner-gate/main.go:74-157`).

The August deployment closure lists Worker authority, a canary, and the
fence handover as separately named later phases with their own gates
(`docs/superpowers/specs/2026-08-24-deployment-closure-design.md:303`).

## 2. Decisions needed before code

**D1. Conformance case 15 (actual GitHub transport).** The Task 11 spec defines
case 15 as one real job: a one-job JIT through the governed acquisition path,
live `DisableUpdate`, JIT absence after parsing, real listener transport and
checkout, every proxy-sensitive tool, and deregistration plus reclamation
(`docs/superpowers/plans/2026-07-29-task11-implementation.md:49-53,1292-1307`).
The gate demands it before acquisition, so the first job cannot happen
without changing the gate. Options:

- (a) Prove case 15 with a probe that mints and deletes a JIT but runs no
  job. This changes what the case means. It is not a lesser form of (b).
- (b) Let `canary-only` run with case 15 pending in general.
- (c) One-shot canary authority: accept a report with cases 1-14 passing and
  case 15 pending only for one operator-approved, capacity-1 canary, and seal
  case 15 from that job.

The Task 11 spec is internally inconsistent here. It says pending reports
"can never enable acquisition" (line 74), yet case 15 can only pass during a
canary that acquires a real job (lines 1292-1305). No option satisfies both
sentences, so every option is a spec change.

Decision (revised 2026-10-15): (b), limited to `canary-only`, adopted as an
explicit amendment to the Task 11 invariant. The gate accepts a report whose
cases 1-14 passed and whose case 15 is pending only for `canary-only`;
`enabled` still requires all 15. Nothing else is added: no authority table,
no per-job binding.

Scoping found that the per-job binding (c) asked for could not be built as
specified: the scale-set protocol carries no head SHA, the run ID is known
only after dispatch, and poll sees no job identity. Each extra mechanism was
another way to fail the deploy, so the operator chose the smallest rule.

What bounds the canary instead: `canary-only` caps capacity at 1 and allows
one eligible scale set; D7 creates that scale set with a single label used
only by the canary workflow; and the runbook sets `canary-only`, dispatches
one job, and sets `disabled` after it. The "one job" bound is procedural: if
several jobs target the canary label while `canary-only` is on, each can run.
After the canary, a report completed with the sealed case 15 evidence must
pass the normal gate before `enabled`.

**D2. Cases 1-14 on the target.** The test harness already implements
`conformance.HostProfile` (`tests/integration/conformance_test.go:14-35`), and
Task 11 defined an operator-gated target run for it. Recommendation: run the
existing harness on the QTS target first, with no new code, to learn which
cases pass. Build a production profile only after that. Decision: as
recommended.

**D3. Worker authority and canary route.** The Worker must leave address-only
mode, accept session and heartbeat, and gain an operator command that moves
one fleet `HOSTED → PORTABLE_CANARY` with a named scale set and back. This is
a Worker code change and redeploy, and its canary route writes repository
variables, which needs a routing credential. Decision: write and test the
Worker change. Redeploy only on a separate operator go.

**D4. Watchdog during the canary.** The watchdog stops any controller that is
not disabled. Options: suspend the watchdog for the canary window and re-arm
it after (no restart supervision during the job), or teach it to supervise
`canary-only`. Decision: suspend for the canary, as a recorded runbook
step.

**D5. Fence and legacy coexistence.** Acquisition needs the portable fence.
The legacy fleet on the target must be suspended and the fence handed to
Portable for the canary window, with a tested rollback. The live fence state
must be read before this is designed. Decision: as described; the read is
an operator step.

**D6. Hosted and replay stubs.** For a single canary job, a stale offer would
end the controller process. Decision: accept fail-stop for the canary.
Implement real hosted routing only before `enabled` mode.

**D7. GitHub prerequisites.** The scale set must already exist in the default
runner group with a single-name label and `DisableUpdate=true`; no code
creates it (`internal/githubscale/client.go:397-413,475-489`). The canary
workflow must target that label. The client supports a personal access token
only; whether a fine-grained PAT can use the scale-set API is not yet
verified. Decision: the operator creates the scale set and the token.

## 3. Phases

Scoped against the source on 2026-10-12. Each code PR merges only when green.
Operator steps ship as exact commands and run only on the operator's go.

### Findings that change the original phase list

- **D3 needs no GitHub credential.** Entering `PORTABLE_CANARY` writes no
  repository variables (`worker/src/github/outbox.ts:263-315`), and the
  Worker's GitHub executor has no production caller. For the canary the Worker
  is a pure lease authority over a fleet with zero repository records.
- **D2 cannot run today.** Its preflight requires `vcs.revision` in the build
  info (`tests/integration/testenv/static_preflight_linux.go:490-515`), and
  `go test` binaries carry none (verified with `go version -m`). The harness
  also never writes its report out.
- **D7 needs a tool.** A runner scale set cannot be created in the GitHub UI or
  REST API, and nothing in the repo creates one.
- **Production rollback is a stub** (`internal/productionruntime/system_lifecycle.go:1856-1866`),
  so the fence handover uses the existing fence `handoff` command, rehearsed
  in a fixture and logged by the runbook.
- **The JIT is likely visible to the job.** It is passed in the listener's exec
  environment (`internal/runtimeenv/environment.go:52-56`), which stays readable
  in `/proc`. The canary workflow probes this; if it is present, the runner
  gate must hand the JIT over another way before case 15 can pass.
- **No production host-capacity source exists.** The canary uses a capacity-1
  provider read from the overlay.

### Order

1. **Overlay settings.** Optional `worker` and `github` sections, plus the jail
   inputs the setup builder needs (image users, dial and authority limits, log
   limits), in one schema change.
2. **Worker lease authority.** `WORKER_AUTHORITY=enabled` replaces the
   compile-time constant (off by default, so merging changes nothing),
   `portable-canary-start` and `portable-canary-stop` admin commands, and a fix
   so unsigned or uninventoried session requests write nothing. Redeploy only
   on a separate operator go.
3. **GitHub sessions and probes.** A session provider per repository, a
   one-shot `external-probe` (opens and closes each GitHub session), and a
   one-shot `create-scale-set` that creates and re-verifies the scale set
   (D7). The Worker check is the enabled controller's first heartbeat, which
   it sends while acquisition is still disabled.
4. **Jail and lifecycle adapters.** Production permit-peer and ledger-reference
   checks, the reject-only conntrack rebase promoted from the test environment,
   and a setup builder that creates the broker directories safely. Security
   review.
5. **Enabled controller process.** A `run-acquisition` subcommand beside `run`
   that composes `controller.Service` from existing parts, with a fatal
   terminator, a log event sink, and the capacity-1 provider. It starts
   disabled and refuses to run unless the portable fleet holds the fence.
   Split into four: 5a adds the overlay `jail` section and two startup
   helpers that clear crash leftovers no recoverable assignment references
   (empty slot directories, a dial ledger left active); 5b maps the overlay
   to the setup builder's configuration; 5c adds the remaining parts built
   from the overlay (Worker client, admission, policy template, pressure
   thresholds, and small runtime adapters); 5d is the composition and the
   command. It never calls `Collect`: each slot keeps one ledger row, which
   `Activate` reuses.
6. **Canary gate (D1).** The Task 11 amendment, and one gate rule: a report
   with cases 1-14 passing and case 15 pending allows `canary-only` only.
   `run-acquisition` reads the report from `<state_root>/conformance-report.json`.
   The D2 harness writes its report out (6a). Security review.
7. **Case 15 evidence.** Record the canary job's result, a
   `canary-seal` command that derives the evidence only from durable state,
   completion of the same pending report, and the canary workflow. Includes the
   JIT hand-over fix if the probe needs it.
8. **Canary runbook.** One bash script that journals each step: watchdog
   suspend, fence handover, Worker start, `canary-only`, dispatch, wait, seal,
   residue check, and the reverse steps.

Operator steps, in order: D5 fence read (read-only), D7 scale set and token,
D2 conformance run, Worker redeploy, then the canary.

## 4. Alternatives

- **Keep the existing runner as primary.** Defer the Portable controller. The
  release, image, and vulnerability work already merged stays useful.
- **Direct canary harness.** Feed a real JIT into the test environment's jail
  composition and skip the controller and Worker. This is about two PRs, but
  it breaks the governed-acquisition rule, the Worker-lease rule, and Task
  11's ban on an alternate JIT source. It proves the image, jail, and proxy,
  not the controller.
