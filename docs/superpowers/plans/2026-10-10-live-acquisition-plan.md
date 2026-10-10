# Live acquisition: phased plan

**Goal:** run one real GitHub Actions job through the Portable controller on
the QTS target in `canary-only` mode, then stop. Production routing, full
capacity, and retirement of the existing runner remain out of scope.

**Status:** proposal for operator review, revised after an adversarial
review. No production code is written until the decisions in section 2 are
made.

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
  case 15 from that job. This is the spec's own stated intent.

Recommendation: (c). It keeps the case's meaning. It still needs a new gate
constructor, which `gate.go` currently says does not exist, so it is an
approved amendment to the gate, not a bypass.

**D2. Cases 1-14 on the target.** The test harness already implements
`conformance.HostProfile` (`tests/integration/conformance_test.go:14-35`), and
Task 11 defined an operator-gated target run for it. Recommendation: run the
existing harness on the QTS target first, with no new code, to learn which
cases pass. Build a production profile only after that.

**D3. Worker authority and canary route.** The Worker must leave address-only
mode, accept session and heartbeat, and gain an operator command that moves
one fleet `HOSTED → PORTABLE_CANARY` with a named scale set and back. This is
a Worker code change and redeploy, and its canary route writes repository
variables, which needs a routing credential. This needs explicit approval.

**D4. Watchdog during the canary.** The watchdog stops any controller that is
not disabled. Options: suspend the watchdog for the canary window and re-arm
it after (no restart supervision during the job), or teach it to supervise
`canary-only`. Recommendation: suspend for the canary, as a recorded runbook
step.

**D5. Fence and legacy coexistence.** Acquisition needs the portable fence.
The legacy fleet on the target must be suspended and the fence handed to
Portable for the canary window, with a tested rollback. The live fence state
must be read before this is designed.

**D6. Hosted and replay stubs.** For a single canary job, a stale offer would
end the controller process. Recommendation: accept fail-stop for the canary.
Implement real hosted routing only before `enabled` mode.

**D7. GitHub prerequisites.** The scale set must already exist in the default
runner group with a single-name label and `DisableUpdate=true`; no code
creates it (`internal/githubscale/client.go:397-413,475-489`). The canary
workflow must target that label. The client supports a personal access token
only; whether a fine-grained PAT can use the scale-set API is not yet
verified.

## 3. Phases

Each phase is one PR, merged only when green, except phases that only run
existing code on the target. Effort per phase is not yet estimated.

1. **Target conformance run (D2).** Run the existing harness on the QTS target
   and record which of cases 1-14 pass. No code.
2. **Overlay Worker and GitHub settings.** Add Worker base URL, HMAC secret
   name, fleet ID, and GitHub response-size limit to the overlay schema, with
   validators, the golden fixture, and assembler support.
3. **GitHub sessions.** Build one scale-set client per repository from the
   overlay and its secret, and expose an alias-to-session provider.
4. **Worker authority (D3).** Enable session and heartbeat in the Worker, add
   the portable canary route, and redeploy after approval.
5. **Worker enrollment, still disabled.** Construct the protocol client,
   heartbeat session, and lease cache in the controller process. Prove a live
   session and heartbeat with acquisition still disabled.
6. **Production jail and lifecycle adapters.** Write production
   permit-peer, ledger-reference, and empty-conntrack validators, a lifecycle
   `SetupBuilder`, and a `SessionProvider`. This is new security-critical code,
   not a port, and needs a security review.
7. **Production conformance profile and canary gate (D1).** Implement the
   profile for the target and the approved one-shot canary gate constructor.
8. **Enabled controller process.** Compose `controller.Service` with the
   lifecycle runtime, the Worker permit provider, and the conformance gate in
   a separate process path. Acquisition stays `disabled` by default.
9. **Fence handover and watchdog (D4, D5).** Suspend legacy and hand the
   fence to Portable for the canary window, with rollback. Suspend and re-arm
   the watchdog around it.
10. **Release and qualify.** Cut a release from the frozen code, assemble the
    overlay, deploy, run conformance cases 1-14 on the target, and install the
    report. The report's binding is invalidated by any later build or overlay
    change, so this comes last.
11. **Canary runbook script.** A thin script that records each step before it
    runs: suspend the watchdog, hand over the fence, set `canary-only` on one
    scale set, dispatch one job, wait for one terminal result, seal case 15,
    verify zero residue, set `disabled`, restore the fence and watchdog.

## 4. Alternatives

- **Keep the existing runner as primary.** Defer the Portable controller. The
  release, image, and vulnerability work already merged stays useful.
- **Direct canary harness.** Feed a real JIT into the test environment's jail
  composition and skip the controller and Worker. This is about two PRs, but
  it breaks the governed-acquisition rule, the Worker-lease rule, and Task
  11's ban on an alternate JIT source. It proves the image, jail, and proxy,
  not the controller.
