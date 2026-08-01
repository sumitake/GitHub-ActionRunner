# Portable-GHAR Task 11 Linux Composition Amendment v4

Author: openai/gpt-5.6-sol
Date: 2026-07-29
Scope: source design only; no host mutation and no numeric value selection

## Context

Task 11 has a Grok-converged single-run topology and now has:

- one tagged effect entrypoint, `TestPortableGHARConformance`;
- one `StartDockerFixture` call and one `conformance.Run` call, enforced by an
  untagged AST topology test;
- a retained one-shot private-input lease;
- an exact empty fixture-root digest and retained no-follow root authority;
- static manifest/overlay/policy/CA/seccomp/image/host preflight; and
- a closed terminal report validator accepting only:
  - P: cases 1-14 passed, actual-GitHub case pending, cleanup passed; or
  - A: all 15 cases passed under their exact proof layers, cleanup passed.

The next implementation step composes the existing production
`hostruntime.NewDockerCLI`, `networkjail.NewSQLitePermitAuthority`,
`networkjail.NewUnixAuthorityManager`, and `networkjail.NewOrchestrator` inside
the dedicated test fixture root.

The v1 and v2 Grok architecture reviews returned `REVISE`: explicit operator
inputs were the correct mechanism, but the proposal had to prove that every
numeric, duration, and count consumed by the composition had an exact
authority. This revision makes that inventory a blocking contract and
incorporates every review binding. The later observation-source review found
one remaining quantity gap: Docker swap was bound only for the runner even
though adapter and broker memory enforcement was also claimed. This v4
revision gives every fixture-owned Docker container an explicit swap
authority without selecting any value.

## No-default input extension

Extend `ConformanceLimits` with six mandatory fields:

```go
MaximumCommandInputBytes           uint64 `json:"maximum_command_input_bytes"`
DialReservationBlockSize           uint64 `json:"dial_reservation_block_size"`
DialAuthorityMaximumClients        uint32 `json:"dial_authority_maximum_clients"`
DialAuthorityTimeoutMilliseconds   uint64 `json:"dial_authority_timeout_milliseconds"`
DockerLogMaximumBytes              uint64 `json:"docker_log_maximum_bytes"`
DockerLogMaximumFiles              uint64 `json:"docker_log_maximum_files"`
```

The constructor inventory added `MaximumCommandInputBytes` to the original
five fields. `hostruntime.NewExecCommandRunner` otherwise supplies an implicit
one-MiB stdin default. The conformance composition instead sets:

- `StdoutLimit = MaximumEvidenceBytes`;
- `StderrLimit = MaximumEvidenceBytes`; and
- `StdinLimit = MaximumCommandInputBytes`.

Both values must fit a positive Go `int`. Every exact policy, seed, or
test-local JIT payload is length-checked against the stdin bound before the
first command that could consume it. There is no fallback to the production
default.

All six fields are required private input, not source defaults. Task 11 does
not choose their values. A later operator-authored private input supplies them
only after the separate sizing sign-off.

## No-default container-swap overlay

Extend the private resource overlay with:

```go
type SwapLimitOverlay struct {
	Configured bool   `json:"configured"`
	Bytes      uint64 `json:"bytes"`
}

type ContainerSwapOverlay struct {
	Adapter           SwapLimitOverlay `json:"adapter"`
	Broker            SwapLimitOverlay `json:"broker"`
	Helper            SwapLimitOverlay `json:"helper"`
	Verifier          SwapLimitOverlay `json:"verifier"`
	WorkflowToolProbe SwapLimitOverlay `json:"workflow_tool_probe"`
}
```

and add `ContainerSwap ContainerSwapOverlay` to `ResourceOverlay`. Also add:

```go
WorkflowToolProbe ResourceVectorOverlay `json:"workflow_tool_probe"`
```

to `SlotResourcesOverlay`. The workflow-tool images are distinct one-shot
Docker containers, so their CPU, memory, PID, FD, work-tmpfs, scratch, and swap
limits cannot be borrowed from the verifier or runner.

The runner remains bound to the existing, already-approved
`RunnerSizingOverlay.SwapLimitConfigured` and `SwapLimitBytes` fields. It is
not duplicated in the new overlay. The five new entries are mandatory,
including when their explicit byte value is zero. `Configured` distinguishes
an operator-selected zero-swap limit from an omitted value.

For every container role `c` in the exhaustive closed set

```text
C_fixture = {
  adapter,
  broker,
  runner-role,
  helper,
  verifier,
  workflow-tool-probe
}
```

`runner-role` covers both the actual runner image and the synthetic-listener
image because both are created only through the same production
`CreateRunner`/`RunnerSpec` path. Synthetic listener is an image/payload
variant, not a seventh resource class or a direct Docker invocation.

The Docker total is:

```text
MemorySwapBytes(c) = checkedAdd(MemoryBytes(c), SwapLimitBytes(c))
```

The total must fit Docker's positive `int64` range and must be no smaller than
the memory limit. A zero swap allowance is represented only by an explicit
configured value of zero, producing `MemorySwapBytes == MemoryBytes`. No
source default, Docker default, `-1`, unlimited value, or inferred
adapter/broker/helper/verifier/workflow-tool value is accepted.

## Closed constructor and spec matrix

The matrix below is exhaustive for the Task 11 Linux composition. A new
constructor parameter, spec field, or effect-path quantity not listed here
stops implementation and requires another reviewed amendment.

### Constructor and runner quantities

| Surface | Numeric, count, or duration input | Exact authority |
| --- | --- | --- |
| `NewExecCommandRunner` | stdout/stderr byte limits | private input `MaximumEvidenceBytes`, exact positive `int` conversion |
| `NewExecCommandRunner` | stdin byte limit | new private input `MaximumCommandInputBytes`, exact positive `int` conversion |
| `NewDockerCLI` | none | its configuration contains only validated paths and the fixed broker-network identity |
| `state.OpenWithHistoryLimits` | retention, row, logical-byte, GC, vacuum, and cadence limits | exact fields from `overlay.Resources.History` through `historyLimitsFromOverlay`; no defaulted `state.Open` path |
| `NewStateLifecycleJournal` | none | exact test-local store |
| `NewSystemMonotonicClock` | none | production monotonic clock |
| `NewSQLitePermitAuthority` | reservation block size | new private input `DialReservationBlockSize` |
| `NewUnixAuthorityManager` | maximum clients | new private input `DialAuthorityMaximumClients` |
| `NewUnixAuthorityManager` | request timeout | exact checked conversion from new private input `DialAuthorityTimeoutMilliseconds` |
| `NewUnixAuthorityManager` | production request-timeout ceiling | existing production protocol constant `maxPermitUnixTimeout`; composition neither selects nor overrides it |
| `NewOrchestrator` | none | exact engine, journal, and authority objects above |
| broker-egress effect path | case deadline ceiling | exact timeout for `conformance.CaseBrokerEgress` from the declaration-ordered private `CaseTimeouts`; composition neither selects nor restates it |

The SQLite busy/migration timeouts, the helper's fixed 64-KiB `/run` tmpfs,
closed verifier result limits, broker-record capacity, and cleanup timeouts
remain existing production protocol/safety constants. The same classification
applies to `maxPermitUnixTimeout`, whose production value is the authoritative
upper bound on the explicitly supplied authority timeout. The Task 11
composition does not select or override these constants, and does not
represent them as operator sizing.

### Host-runtime spec quantities

| Spec field | Exact authority and binding |
| --- | --- |
| `AdapterSpec.FleetGeneration` | private input/runtime-manifest fleet generation; exact equality already proven by static preflight |
| adapter milli-CPU, memory, PIDs, file descriptors, state tmpfs, scratch | exact `overlay.Resources.SlotResources.Adapter` fields; state tmpfs is that vector's `TmpfsBytes` |
| adapter total memory-plus-swap | checked sum of adapter memory and `overlay.Resources.ContainerSwap.Adapter.Bytes`; `Configured` is mandatory |
| adapter log bytes/files | new Docker log fields, applied identically to every member of the closed log set below |
| `BrokerSpec.FleetGeneration` | same exact fleet generation as the adapter |
| `BrokerSpec.CapacitySlotID` | identity-only derivation defined below; never interpreted as capacity |
| `BrokerSpec.JobGeneration` | identity-only derivation defined below; never interpreted as a retry count or resource bound |
| broker milli-CPU, memory, PIDs, file descriptors, state tmpfs, scratch | exact `overlay.Resources.SlotResources.Broker` fields; state tmpfs is that vector's `TmpfsBytes` |
| broker total memory-plus-swap | checked sum of broker memory and `overlay.Resources.ContainerSwap.Broker.Bytes`; `Configured` is mandatory |
| broker log bytes/files | new Docker log fields |
| helper milli-CPU, memory, PIDs, file descriptors | exact `overlay.Resources.SlotResources.Helper` fields |
| helper total memory-plus-swap | checked sum of helper memory and `overlay.Resources.ContainerSwap.Helper.Bytes`; `Configured` is mandatory |
| `RunnerSpec.FleetGeneration` | same exact fleet generation as adapter and broker |
| runner milli-CPU, PIDs, file descriptors | exact `overlay.Resources.SlotResources.Runner` fields |
| runner memory, `/runner`, `/tmp`, scratch, process margin | exact `overlay.Resources.RunnerSizing.{RunnerMemoryBytes,RunnerTmpfsBytes,TmpTmpfsBytes,ScratchTmpfsBytes,ProcessMarginBytes}` |
| runner total memory-plus-swap | checked sum of runner memory and existing `overlay.Resources.RunnerSizing.SwapLimitBytes`; existing `SwapLimitConfigured` is mandatory |
| runner log bytes/files | new Docker log fields |
| `VerifierSpec.FleetGeneration` | same exact fleet generation as the adapter |
| verifier milli-CPU, memory, PIDs, file descriptors | exact `overlay.Resources.SlotResources.Verifier` fields |
| verifier total memory-plus-swap | checked sum of verifier memory and `overlay.Resources.ContainerSwap.Verifier.Bytes`; `Configured` is mandatory |

The composition rejects unless slot-runner memory, tmpfs, and scratch equal
the corresponding approved runner-sizing values. Every mapped Docker numeric
is also passed through the production `hostruntime` range and memory-fit
validators before effects.

`MemorySwapBytes` is added to `ContainerLimits`, `BrokerLimits`,
`RunnerLimits`, and `OneShotLimits`. Every Docker invocation represented by
`C_fixture` passes the exact total with `--memory-swap`. Adapter, broker, and
runner-role HostConfig audits parse `MemorySwap` and require exact equality
before their successful evidence boundary. Helper and verifier are `--rm`
one-shots, so their proof is the closed, unit-tested production argv plus
successful bounded self-observation and exact-name absence; workflow-tool
probes use the separately closed harness argv/absence proof below. No one-shot
argv proof is promoted into a long-lived HostConfig-readback claim.

`SocketStateBytes`, `DurableStateBytes`, and `Inodes`, plus unused tmpfs or
scratch dimensions on one-shot and dial-authority vectors, remain explicit
admission/storage accounting dimensions. They are not silently translated
into unrelated Docker flags.

### Closed-harness workflow-tool quantities

Workflow-tool probes are the only Task 11 Docker class outside the five
production host-runtime specs. They use one test-local closed
`workflowToolProbeSpec`; there is no generic Docker or argv API.

| Probe field | Exact authority |
| --- | --- |
| ordered probe ID | declaration-ordered `requiredWorkflowToolProbeIDs` plus exact private binding |
| immutable image and digest | exact `WorkflowToolBinding`, already static-preflight verified |
| fixed action/entrypoint | compiled closed mapping for that probe ID; never private argv |
| numeric user | exact immutable-image inspect readback for that binding |
| network namespace | `container:<exact engine-issued held runner ID>`; no caller container identity |
| milli-CPU, memory, PIDs, file descriptors | exact `overlay.Resources.SlotResources.WorkflowToolProbe` fields |
| `/work` tmpfs and `/tmp` scratch | exact workflow-tool vector `TmpfsBytes` and `ScratchBytes` |
| total memory-plus-swap | checked sum of workflow-tool memory and `overlay.Resources.ContainerSwap.WorkflowToolProbe.Bytes`; `Configured` is mandatory |
| seccomp | exact already-preflighted Task 11 seccomp binding |
| log mode | fixed `--log-driver none` |
| deadline | remaining exact `conformance.CaseProxyToolCompatibility` deadline; no new duration |
| name | pure run/probe identity derivation with exact-name cleanup lease |

The invocation is `--rm`, non-root, `CapDrop=ALL`, read-only,
no-new-privileges, seccomp-bound, mount-free except for its two private tmpfs
paths, and cannot accept environment, volume, device, privilege, port, network,
entrypoint, or command overrides. Its swap/resource proof is closed argv plus
successful bounded result and exact-name absence, not HostConfig readback.
Every probe is serialized under the case deadline, and cancellation leaves
only its already-registered exact cleanup lease.

### Orchestrator request quantities

| Request field | Exact authority |
| --- | --- |
| `AssignmentKey.RunnerRequestID` | identity-only derivation from the run digest |
| `AssignmentKey.Attempt` | structural initial-attempt constant `0`, whose production meaning is fixed by `controller.AssignmentKey` |
| `Budget.NFConntrackMax` / `NFConntrackCount` | exact overlay conntrack maximum/current entries |
| `Budget.TailTimeoutID` | exact overlay conntrack evidence revision; identity only |
| `MaxRunnerCapacity` | exact `overlay.Resources.Conntrack.MaximumRunnerCapacity` |
| `SeedIDs` count | structural empty set for the held pre-release transaction; later synthetic release inputs remain case-owned and bounded |

Every policy-manifest quantity used by `Budget.Compute` comes from the already
parsed, digest-bound policy document. The composition does not restate or
derive those values.

## Exact validation and cross-binding

### Duration and reservation bounds

- `DialReservationBlockSize` is independently operator supplied and must be
  in the production constructor's exact range `[1, math.MaxUint32]`.
  It is deliberately not derived from contract-row, conntrack, burst, or other
  maxima; the production authority already caps each reservation by current
  availability.
- `DialAuthorityMaximumClients` is mandatory and independently nonzero.
  Canonical JSON decoding writes directly into `uint32`; a value outside that
  type is rejected rather than narrowed. Comparison then performs the exact,
  lossless widening
  `clients := uint64(DialAuthorityMaximumClients)` and compares that value
  directly with the existing `uint64` ceilings. There is no ceiling narrowing,
  signed conversion, or truncation. The composition rejects it when it exceeds
  any of:
  - private input `MaximumProcesses`;
  - private input `MaximumFileDescriptors`;
  - overlay dial-authority PIDs; or
  - overlay dial-authority file descriptors.
  Those are consistency ceilings, never sources for the value.
- `DialAuthorityTimeoutMilliseconds` must be in
  `[1, floor(math.MaxInt64 / 1_000_000)]`.
  Conversion is exactly
  `time.Duration(milliseconds) * time.Millisecond`, after the bound check.
  The result must also be no greater than:
  - the existing production protocol ceiling `maxPermitUnixTimeout`; and
  - the exact `conformance.CaseBrokerEgress` timeout from the declaration-
    ordered case-timeout input.

### Closed Docker log set and overflow rules

The closed log-emitting long-lived set is:

```text
L = {adapter, broker, runner-role}
```

The synthetic-listener image is a member of `runner-role`, so it receives the
same explicit local-log rotation and runner resource enforcement through its
`RunnerSpec`; it is not a log-driver-none one-shot.

For every `c` in `L`:

```text
LogBytes = DockerLogMaximumBytes
LogFiles = DockerLogMaximumFiles
```

Every fixture-started container outside `L`—helper, verifier, and
workflow-tool probe—must use the production or closed-harness
`--log-driver none` path and receives no rotation value.

The Docker local-driver upper-bound model is exactly
`max-size * max-file` per container. Arithmetic is pairwise checked:

```text
perContainerBytes = checkedMul(DockerLogMaximumBytes, DockerLogMaximumFiles)
fleetBytes        = checkedMul(perContainerBytes, uint64(len(L)))
fleetFiles        = checkedMul(DockerLogMaximumFiles, uint64(len(L)))
```

Any overflow rejects the input. `len(L)` is a compiled closed-set count, not a
bare magic factor. The composition also rejects unless:

```text
fleetBytes <= MaximumLogBytes
fleetBytes <= overlay.Resources.Storage.LogBounds.MaxBytes
              - overlay.Resources.Storage.LogBounds.UsedBytes
fleetFiles <= overlay.Resources.Storage.LogBounds.MaxFiles
              - overlay.Resources.Storage.LogBounds.UsedFiles
```

Subtractions are checked. `MaximumLogBytes` is therefore the private
conformance run's global Docker-retained-log ceiling. It is not a per-container
rotation default and cannot be substituted for `DockerLogMaximumBytes`.

### Closed Docker swap set and overflow rules

For every `c` in `C_fixture`, validation requires the exact configured swap
source named above and computes the total with checked unsigned addition
before any effect. Each memory value and each checked total must be in
`[1, math.MaxInt64]`; an addition overflow, omitted `Configured` bit, Docker
`-1`, a total below memory, or a total unequal to the exact source mapping is
terminal.

The adapter, broker, and runner-role create argv and HostConfig validators
must agree byte-for-byte on their totals. The helper, verifier, and
workflow-tool-probe fixed argv must agree with their respective totals. Tests
must independently mutate every member of `C_fixture`; no runner-only proof,
shared fallback, or equality among unrelated members can satisfy another
member.

These fields are enforcement inputs, not sizing approval. Numeric sign-off
for all six role allowances remains outside Task 11 and no private input is
authored in this build.

### Command byte bounds

- `MaximumEvidenceBytes` and `MaximumCommandInputBytes` must each be in
  `[1, math.MaxInt]`.
- every closed command session uses the exact configured runner;
- every command output is bounded by `MaximumEvidenceBytes`; and
- every nonempty command input is length-checked against
  `MaximumCommandInputBytes` before process creation.

## Identity-only derivation

Each derived identity uses a distinct domain and the already unique lowercase
run digest:

- positive `int64` runner request ID;
- positive `uint32` capacity-slot ID;
- positive `uint64` job generation;
- slot identity; and
- exact adapter, broker, and runner container names.

Integer extraction is one pure, range-preserving operation with golden and
mutation tests. A zero or invalid result fails composition; there is no retry,
counter increment, or rejection-sampling loop. Container names use a fixed
ASCII prefix plus a fixed lowercase-hex digest slice, and are checked against
the production Docker name/length contract. No identity is interpreted as a
resource bound, timeout, client count, block size, log quantity, retry policy,
or capacity.

## TDD and stop conditions

0. Keep this constructor/spec matrix as the implementation checklist.
1. Add codec RED tests for missing, zero, overflow, unknown, reordered, and
   cross-bound failures for all six fields, plus missing/unknown/malformed
   swap overlay entries and an explicit configured zero.
2. Add RED tests for exact command bounds, duration conversion, reservation
   range, client consistency ceilings, runner cross-binding, checked log
   arithmetic, identical application to `L`, log-driver-none outside `L`,
   checked swap addition for every member of `C_fixture`, exact
   `--memory-swap`, long-lived HostConfig readback, and the workflow-tool
   closed argv/absence contract.
3. Add golden/mutation RED tests for every identity derivation.
4. Implement the smallest codec and composition helpers.
5. Re-run source tests and Linux integration-tag cross-compilation.
6. Only then wire `TestPortableGHARConformance` Linux composition.

Stop and revise again if implementation encounters any numeric, duration, or
count parameter not represented by the matrix. Do not derive policy from an
unrelated maximum, fall back to a constructor default, or select an operator
value in source.

## Confirm-only review request

Confirm whether this v4 amendment closes the prior `REVISE` findings and the
later swap-authority gap:

1. exhaustive constructor/spec/request quantity inventory;
2. exact duration and overflow contracts;
3. closed log-emitter set and residual aggregate budget;
4. explicit `MaximumLogBytes` semantics;
5. reservation range and max-client anti-aliasing;
6. fail-closed identity derivation; and
7. exact equality between `C_fixture` and every fixture-started Docker role,
   including runner-role treatment of the synthetic-listener image and the
   distinct workflow-tool-probe resource/swap vector, with
   lifetime-appropriate proof and no numeric selection.

Return `PROCEED` only if no production composition quantity remains unbound.
