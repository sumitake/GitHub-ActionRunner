# Live acquisition: phased plan

**Goal:** run one real GitHub Actions job through the Portable controller on
the QTS target in `canary-only` mode, then stop. Production routing, full
capacity, and retirement of the existing runner remain out of scope.

**Status:** proposal for operator review. No production code is written
until the decisions in section 2 are made.

## 1. Where the source stands (main @ d89ab34)

The pieces needed for acquisition exist mostly as library code exercised by
tests. Nothing joins them in the production process.

| Area | State | Evidence |
| --- | --- | --- |
| Controller process | The binary always starts the disabled observer. `controller.Service` is constructed only in tests. | `cmd/portable-ghar-controller/commands.go:44-61`; `production_controller.go:145-395`; `disabled_admin.go:122,323` rejects every mode except disabled |
| GitHub scale-set client | Complete (PAT only). No production caller. | `internal/githubscale/client.go:98-131,373-431`; `adapter_v040.go` |
| Overlay repository fields | `config_url`, `scale_set_name`, `credential_name` are validated but read by no code. | `internal/hostruntime/private_overlay.go:271-281` |
| Worker lease client | Protocol client, heartbeat session, lease cache, and permit provider exist. Only the test environment constructs them. | `internal/failoverclient/client.go:71`, `heartbeat_session.go:57`, `permit.go:216` |
| Overlay Worker settings | No Worker URL, HMAC secret, or fleet ID field exists. | strict schema, `private_overlay.go:371-392` |
| Conformance gate | `canary-only` needs a fully passing 15-case report, checked at transition and before every guarded poll, acquire, and JIT call. No production report producer exists. Case 15 (actual GitHub transport) only ever reports `pending`. | `internal/conformance/gate.go:94-125`; `registry.go:68-82`; `report.go:397-407`; `tests/integration/testenv/profile.go:56` |
| Network jail authority | `PermitPeerValidator`, `LedgerReferenceGuard`, `EmptyConntrackValidator` and the lifecycle `SetupBuilder` exist only in the test environment. These are security-critical. | `internal/networkjail/permit_proof.go:28-54`; `tests/integration/testenv/permit_guard.go`, `runtime_composition.go:146-226` |
| Hosted and replay routes | Stubs only. A stale, oversized, or untimed offer ends the poll loop and so the controller process. | `internal/controller/service.go:2026-2046`; `runtime.go:191-193` |
| Worker canary route | The routing machine allows `HOSTED → PORTABLE_CANARY`, but no admin command enters it. A portable canary lease cannot be issued today. | `worker/src/routing/machine.ts:7`; `worker/src/engine/admin.ts:320` (only `LEGACY_CANARY`); `heartbeat.ts:229-310` |

The runner image cannot run a job outside this stack. The listener's
proxy is fixed to the adapter's loopback relay
(`internal/runtimeenv/environment.go:22,52-55`), and release requires the
gate's arm and namespace handshake (`cmd/portable-ghar-runner-gate/main.go:74-157`).

## 2. Decisions needed before code

**D1. Conformance case 15 (actual GitHub transport).** Acquisition needs it
to pass, and the obvious way to produce it is a real job, which needs
acquisition. Options:

- (a) **Transport probe, no job.** Case 15 proves that the target can open a
  scale-set session with the configured credential and mint, read back, and
  delete one JIT registration. No job is acquired.
- (b) Let `canary-only` run with case 15 pending. This removes a gate the
  design says has no bypass.
- (c) A separate one-shot authority that produces case 15 from the canary
  job itself.

Recommendation: (a). It needs no acquisition, every effect is reversible,
and it matches the case's name.

**D2. Actual-host and synthetic cases (1-14).** These need a production
`conformance.HostProfile` running on the target. The scope is not yet
measured. Recommendation: a one-PR spike that implements the profile
against the existing test-environment drivers and reports which cases can
pass on QTS.

**D3. Worker canary route.** The Worker needs an operator command that moves
one fleet `HOSTED → PORTABLE_CANARY` with a named scale set, and back. That
requires a Worker redeploy, which the August checkpoint prohibited without
approval. This needs explicit approval.

**D4. Hosted and replay stubs.** For a single canary job, a stale offer would
end the controller process; the watchdog restarts it disabled.
Recommendation: accept fail-stop for the canary, and document it. Implement
real hosted routing only before `enabled` mode.

**D5. Credential.** The client supports a personal access token only. Use one
fine-grained PAT per repository, stored as a `file` secret in the private
overlay root. GitHub App authentication is not implemented.

## 3. Phases

Each phase is one PR, merged only when green. Effort per phase is not yet
estimated. Phases 1-3 are independent of D2 and D3.

1. **Overlay Worker and GitHub settings.** Add Worker base URL, HMAC secret
   name, fleet ID, and GitHub response-size limit to the overlay schema, with
   validators, the golden fixture, and assembler support.
2. **GitHub sessions and transport probe.** Build one scale-set client per
   repository from the overlay and its secret, and expose an alias-to-session
   provider. Add an operator command that runs the D1(a) probe and seals case
   15 evidence.
3. **Worker enrollment, still disabled.** Construct the protocol client,
   heartbeat session, and lease cache in the controller process. Prove a live
   session and heartbeat against the deployed Worker with acquisition still
   disabled.
4. **Production jail adapters.** Port the permit-peer, ledger-reference, and
   empty-conntrack validators and the lifecycle setup builder from the test
   environment into production packages, with security review.
5. **Production conformance profile.** Implement `conformance.HostProfile`
   for the QTS target (the D2 spike, then the remaining cases) and produce a
   passing report.
6. **Enabled controller process.** Add a separate process path that composes
   `controller.Service` with the lifecycle runtime, the Worker permit
   provider, and the conformance gate. Acquisition stays `disabled` by
   default. The disabled observer is unchanged.
7. **Worker canary route (D3).** Add the `PORTABLE_CANARY` admin command and
   redeploy after approval.
8. **Canary runbook script.** A thin script that records each step before it
   runs: set `canary-only` on one scale set, dispatch one job, wait for one
   terminal result, verify zero residue, and set `disabled`.

## 4. Alternative

If eight PRs plus a Worker change is more than the goal justifies, keep the
existing self-hosted runner as primary and defer the Portable controller.
The release, image, and vulnerability work already merged stays useful
either way.
