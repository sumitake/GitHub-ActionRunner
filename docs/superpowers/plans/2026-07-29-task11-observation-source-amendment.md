# Portable-GHAR Task 11 Observation-Source Amendment v3

Author: openai/gpt-5.6-sol
Date: 2026-07-29
Scope: source design only; no host mutation and no numeric value selection

## Why this amendment exists

The Task 11 capability registry currently assigns several namespace rows to
`SourceHostRuntimeEngine`. That assignment is too broad. The production
`hostruntime.Engine` deliberately returns opaque release authority plus bounded
audit/evidence digests; it does not expose arbitrary post-setup namespace
links, routes, tables, conntrack contents, or per-probe transcripts.

The first amendment draft also overclaimed three facts:

1. `ApplyNetworkPolicy` constructs fixed `CapDrop=ALL, CapAdd=NET_ADMIN`
   arguments but, because the helper is `--rm`, it does not inspect the
   helper's live capability sets.
2. the verifier is launched with `CapDrop=ALL`, but its HostConfig is not
   inspected before it exits;
3. the broker audit alone cannot prove mount exclusivity across adapter,
   broker, runner, helper, and verifier.

The source audit additionally found two pre-existing contract mismatches:

- the broker must see the relay parent read-write so it can create and own its
  relay socket; only the adapter sees the relay parent read-only. The older
  Task 11 sentence saying the relay is read-only in both containers is
  incorrect and is superseded by this amendment.
- `RunnerSizingTuple.SwapLimitBytes` is validated as operator input but does
  not currently reach Docker `--memory-swap` or HostConfig readback. Task 11
  cannot claim an enforced runner swap limit until that mapping exists.

This amendment gives every actual-host claim a truthful authority, adds the
one ordered post-setup namespace observation that production does not perform,
and publishes a complete `IsolationEvidence` field-to-fact map before codegen.

The v2 Grok architecture review returned `REVISE` on three precise remaining
gaps:

1. swap enforcement was still runner-only while adapter and broker memory
   enforcement was claimed;
2. graph membership plus a positive probe did not prove that an actual
   same-run DoH-class permit was consumed before bootstrap dial; and
3. the identity triangle did not explicitly require successful completion of
   the full production `Orchestrator.Prepare` sequence through
   `StageRunnerAuthorize`.

This revision closes all three without choosing an operating value or turning
test evidence into production authority.

## Non-negotiable boundaries

1. Do not add a generic exec, inspect, namespace, Docker-argv, or raw command
   method to `hostruntime.Engine`.
2. Do not export engine handles, namespace release proofs, or container IDs as
   caller-synthesizable authority.
3. Do not treat operator-supplied expected profile, policy, manifest, image,
   sizing, or report digests as observations.
4. Do not claim a property from an audit digest unless the production path
   checks that property on the same object.
5. Do not select a flood count, swap value, duration, resource ceiling, or
   other operating number in source. All operational values remain separate
   operator input.
6. Do not mutate QTS, Docker, systemd, launchd, a live controller, or host
   configuration while implementing or testing this amendment on macOS.
7. Keep the verifier non-root, read-only, no-new-privileges, seccomp-bound,
   log-driver-none, and attached only to the exact engine-issued namespace.
8. Keep the policy helper root, read-only, no-new-privileges,
   seccomp-bound, log-driver-none, and NET_ADMIN-only for its bounded lifetime.
9. Do not turn a test-only observation into production acquisition authority.
10. A failed or canceled observation may run cleanup-only verification, but
    cleanup output cannot become passing case evidence.

## Closed evidence-source vocabulary

The existing source enum gains one non-observing source:

```text
SourceBoundEvidenceLedger
```

It may only compare or conjoin already-passed typed facts. It cannot execute a
command, inspect a host object, accept expected input as evidence, or turn an
opaque digest into a new property. Its output digest includes every input row
ID, source ID, parser ID, operation ID, typed observation digest, runtime
object binding, and comparison result.

All other source meanings remain unchanged:

- `SourceHostProfile`: static closed profile observation and sizing
  validation;
- `SourceHostRuntimeEngine`: a production engine method whose successful
  return actually validates the named property;
- `SourceNetworkOrchestrator`: the immutable graph, final `ProbeReport`,
  opaque engine audit/evidence, and release-authorization path;
- `SourceClosedTestCommand`: one enumerated, fixed command whose dynamic
  values are pre-bound engine identities and validated private quantities;
- `SourceSyntheticLocal`: a case explicitly classified as synthetic
  lifecycle evidence; and
- `SourceActualGitHubCanary`: case 15 only.

`ValidateObservationMatrix` rejects `SourceBoundEvidenceLedger` unless every
declared dependency precedes the derived row and belongs to the same exact run
binding.

## Production-checked capability truth

Fixed launch arguments alone are insufficient capability evidence. Task 11
therefore adds a bounded self-observation to the immutable helper and verifier
binaries and validates that observation in the production caller.

### Canonical capability wire

Both binaries read the five Linux capability masks from their own
`/proc/self/status` before their operation. The canonical wire contains five
fixed-width lower-hex masks:

```json
{
  "effective": "0000000000000000",
  "permitted": "0000000000000000",
  "inheritable": "0000000000000000",
  "bounding": "0000000000000000",
  "ambient": "0000000000000000"
}
```

The values above show the verifier profile. They are schema examples, not
operator input.

The parser rejects missing, duplicate, unknown, noncanonical, oversized,
mixed-case, wider, shorter, or non-hex values. It rejects a repeated
`/proc/self/status` capability key, an unknown capability key, or a mask that
does not fit the kernel capability domain used by the build.

The verifier requires all five masks to be zero. The helper requires:

- effective, permitted, and bounding contain exactly `CAP_NET_ADMIN`;
- inheritable and ambient are zero; and
- no other bit is set.

The implementation uses the platform capability constant, not a new
operator-supplied number.

### Wire integration

- Bump the policy-helper application proof to a closed new version carrying
  the capability wire. `ApplyNetworkPolicy` parses and independently validates
  the NET_ADMIN-only profile before accepting the policy readback.
- Bump each verifier output to a closed new version carrying the capability
  wire. `runNetworkVerifier` parsers independently validate the empty profile
  for `namespace-id`, `namespace-empty`, `probe`, and the new flood operation.
- Preserve the existing output byte ceilings. Do not add raw status text,
  paths, process IDs, environment, or arbitrary key/value fields.
- A capability mismatch is terminal before a success receipt can be retained.

This is a narrow production result-contract strengthening. It does not widen
`hostruntime.Engine` and does not expose capability text through the engine.

## Exact observation-source matrix changes

### Case 1

All existing `SourceHostProfile` rows remain unchanged. They come from static
host preflight plus production sizing validators. The
`host-execution-identity` row remains a closed preflight command.

### Case 2: namespace baseline

The exact ordered rows become:

| Observation | Source | Exact evidence |
| --- | --- | --- |
| `adapter-runner-netns-identity` | `SourceBoundEvidenceLedger` | `AdapterEmptinessEvidence.Namespace`, `ProbeReport.RunnerNetNSID`, the post-flood namespace identity, the held adapter/runner IDs, and the successful `AuthorizeRelease` receipt form the exact identity triangle described below. |
| `runner-loopback-only` | `SourceNetworkOrchestrator` | `ProbeReport.RunnerLoopbackOnly`, produced by the empty-capability verifier and bound into the final audit. |
| `runner-tables-empty` | `SourceNetworkOrchestrator` | `ProbeReport.RunnerTablesEmpty`, produced before the flood and bound into the final audit. |
| `runner-conntrack-before` | `SourceNetworkOrchestrator` | `ProbeReport.RunnerConntrackEmpty`, produced before the flood and bound into the final audit. |
| `loopback-flood` | `SourceClosedTestCommand` | One fixed verifier mode consumes the validated private flood count and emits one canonical report. |
| `runner-tables-after-flood` | `SourceClosedTestCommand` | The cached flood report's distinct post-flood `tables_empty` fact. This row is mandatory and cannot alias the pre-flood row. |
| `runner-conntrack-after` | `SourceClosedTestCommand` | The same cached report's post-flood `conntrack_empty` fact. |
| `runner-route-absence` | `SourceClosedTestCommand` | The same cached report's post-flood `routes_complete` fact. |
| `namespace-stable-after-attach` | `SourceBoundEvidenceLedger` | Exact equality across `AdapterEmptinessEvidence.Namespace`, `ProbeReport.RunnerNetNSID`, post-flood identity, and the successful release-authorization receipt. |
| `helper-capabilities-lifetime` | `SourceHostRuntimeEngine` | `ApplyNetworkPolicy` validated the helper's self-observed NET_ADMIN-only masks, exact policy readback, exact helper absence, and held-broker reinspection before success. |
| `runtime-capabilities-empty` | `SourceBoundEvidenceLedger` | Actual adapter, broker, and runner HostConfig audits plus every accepted verifier self-observation; no helper fact is reused as an empty-capability fact. |

The matrix rejects the old `SourceHostRuntimeEngine` assignments for raw
links, routes, tables, or conntrack facts.

### Case 3: broker egress

Only probe types representable by `networkjail.Probe` remain
`SourceNetworkOrchestrator` rows:

| Observation | Source | Required binding |
| --- | --- | --- |
| `held-broker-sockets-zero` | `SourceHostRuntimeEngine` | A new internal, input-free, pre-release broker audit counts AF_INET/AF_INET6 TCP, UDP, and raw rows while the broker is held; every count must be zero before release. The result is canonical, checked by `ReleaseNetworkBroker`, and not exposed as raw text. |
| `broker-positive-https` | `SourceNetworkOrchestrator` | Exact graph digest; exactly one positive probe matching the positive sentinel's non-literal DNS host, port, and HTTP CONNECT class; aggregate `PositiveOK`; exact immutable verifier code that iterates the ordered positive list; and a same-run dual-class permit-usage proof obtained only after successful `Orchestrator.Prepare`. |
| `broker-denied-literal` | `SourceNetworkOrchestrator` | Exact ordered membership of every literal-deny sentinel in the negative graph set; no missing, duplicate, or unclassified literal; aggregate `NegativeOK`; exact list-iteration topology. |
| `broker-denied-dns` | `SourceNetworkOrchestrator` | Exact ordered membership of every DNS-deny sentinel in the negative graph set; no missing, duplicate, or unclassified DNS name; aggregate `NegativeOK`; exact list-iteration topology. |
| `broker-denied-direct-protocols` | `SourceClosedTestCommand` | Fixed direct IPv4, IPv6, DNS, TCP, UDP, ICMP, and non-proxy attempts with typed closed denial classes. |
| `broker-denied-plaintext-http` | `SourceClosedTestCommand` | A fixed plaintext request. It cannot be inferred from `networkjail.Probe`, which represents CONNECT classes only. |
| `broker-denied-connect-port` | `SourceClosedTestCommand` | A fixed unsupported CONNECT-port request. Negative graph probes are required to use allowed ports and therefore cannot prove this row. |
| `broker-denied-socks-operations` | `SourceClosedTestCommand` | Fixed SOCKS BIND and UDP operations. `networkjail.Probe` represents SOCKS CONNECT only. |
| `broker-denial-boundary` | `SourceBoundEvidenceLedger` | Conjunction of the three graph-deny classes and the four closed denial rows, with exact typed failure-boundary classes. |
| `broker-policy-ledger-authority-match` | `SourceBoundEvidenceLedger` | Exact graph/policy digest; broker audit; final orchestrator audit; authority directory/socket/peer; ledger revision; permit topology seal; held-jail IDs; and actual positive-probe result. |
| `broker-flood-bounds` | `SourceClosedTestCommand` | Existing checked parser/fallback/crash flood operation and resource formula. |
| `broker-loss-prevents-release` | `SourceNetworkOrchestrator` | Actual orchestrator failure path proves no release authorization after component, policy, state, or evidence loss. |

#### Mechanical graph-membership seal

Before effects, the fixture constructs a private immutable
`probeMembershipSeal` from:

- the graph digest;
- the exact ordered positive and negative probe lists;
- the positive, literal-deny, and DNS-deny sentinel bindings;
- the exact canonical list indexes assigned to each row; and
- the source topology seal for `VerifyProxyEgress`.

Construction fails unless:

- every represented matrix class has at least one exact member;
- the positive sentinel maps exactly once and its host is a canonical
  non-literal public DNS name, not an IPv4 or IPv6 address;
- every literal/DNS sentinel maps at least once and no graph deny is
  unclassified;
- indexes are unique, ordered, complete, and in range;
- the graph digest matches the runtime policy and final `ProbeReport`;
- `PositiveOK`/`NegativeOK` are true; and
- the immutable verifier topology iterates every ordered member exactly once.

Mutation tests delete, duplicate, reorder, reclassify, or mark an index
uniterated and must fail. Aggregate OK alone cannot pass a row.

#### Same-run dual-class permit-usage proof

The positive sentinel must force the broker resolver path. Static input
validation rejects a positive host when `net.ParseIP(host) != nil`, even for a
public address. The exact positive probe therefore performs DoH resolution
before its job-class upstream dial.

Add one narrow read-only production audit boundary on the concrete
`*networkjail.PermitAuthority`:

```go
AuditActiveUsage(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
) (PermitUsageProof, error)
```

`PermitUsageProof` has private fields. It exposes only a canonical digest and
an exact tuple-matching method; it is not a permit, cannot issue a permit, and
cannot authorize release. This is not an `Engine` API widening.

`PermitAuthority` maintains an in-memory, generation-bound usage receipt for
each active slot. `Activate` initializes it with the exact activation
revision; activation of a new generation resets it. `Consume` updates it only
immediately before returning a successfully consumed permit. The receipt
records, separately for `DialClassDoH` and `DialClassJob`, the successfully
issued permit number and sequence. A durable ledger load or reservation burn
on process recovery never creates class-usage entries, so a restarted
authority cannot turn abandoned reservations into same-run consumption
evidence.

While holding the authority mutex, `AuditActiveUsage`:

1. requires a live usage receipt for the exact slot and generation with one
   successful DoH issue and one successful job issue;
2. loads the active in-memory ledger and the durable store row separately;
3. validates both encodings and exact version, slot, boot ID, active
   generation, and current revision equality, and requires that current
   revision not precede the receipt's activation revision;
4. requires the in-memory issued high-water and sequence for each class to
   include the corresponding usage receipt;
5. requires the durable reserved high-water and reserved sequence for each
   class to include that same issued number and sequence;
6. requires the durable reserved fields to equal the in-memory reserved
   fields, and durable issued fields to be no greater than their in-memory
   counterparts; and
7. seals the graph digest, tuple, boot ID, activation revision, current
   revision, both class identifiers, both usage receipts, and both
   durable-reservation bindings into the opaque proof digest.

The broker's `AuthorityProof` legitimately carries the activation revision,
while permit block reservations can advance the durable ledger before the
post-probe audit. The final evidence therefore binds the authority proof to
the usage proof's activation revision and separately binds the usage proof's
current revision to the durable row; it never incorrectly requires the two
revisions to remain equal after traffic.

That binding is closed rather than reflective. `hostruntime.AuthorityProof`
gains one non-revealing predicate that answers whether its private binding
matches an exact slot, generation, and activation revision; it exposes no
directory, socket, peer, or raw binding. After a successful
`BindDialAuthority`, `recordingEngine` retains the opaque proof on the exact
broker record. The prepared-evidence transfer asks `PermitUsageProof` to bind
that opaque proof to its private activation revision and emits one additional
domain-separated binding digest. A proof from another authority, slot,
generation, or revision fails. The opaque proof is cleared on removal and
cannot be replayed after cleanup.

The audit runs exactly once after production `Orchestrator.Prepare` returns.
At that point `StageEgressVerify` has completed every positive and negative
probe while the authority is still active and the runner is held. Missing
either class, literal positive input, usage only from an earlier generation,
recovery-burned reservations, durable/in-memory drift, or a second audit with
changed usage fails closed.

### Case 4: mount and secret isolation

Mount claims use a same-run multi-object proof:

- adapter creation/reinspection: exactly one bind, the relay parent at the
  adapter destination, read-only, with no bind list, device, privilege, port,
  or namespace-mode escape;
- broker audit: exactly two binds, relay read-write and authority read-only,
  with exact source/destination identities and no other bind/device;
- held-runner audit: zero mounts, binds, and devices;
- helper/verifier closed argv: no mount or device option, followed by exact
  name absence;
- workflow-tool-probe closed argv: only its two private tmpfs paths, no host
  bind/device/privilege option, followed by exact name absence; and
- all object IDs, specs, build IDs, fleet generation, slot, run digest, and
  engine receipts agree.

The exact rows are:

- `relay-mount-visibility`: the adapter read-only relay bind, broker
  read-write relay bind, runner absence, and every one-shot bind absence;
- `authority-mount-visibility`: broker read-only authority bind and absence
  from adapter, runner, helper, verifier, and workflow-tool probes;
- `host-control-invisible`: the three long-lived audits reject every extra
  bind/device and every one-shot argv rejects host bind/device authority;
- `controller-sqlite-invisible`, `runtime-secret-scan`, and
  `synthetic-token-absence`: remain closed commands because container audits
  do not open negative paths or scan content.

This section supersedes the older claim that the broker relay mount is
read-only.

### Case 5: runner sandbox and complete container swap

The existing held-runner audit remains authoritative for read-only root,
capability drop/add, seccomp path, zero mounts/devices, network namespace
attachment, CPU, memory, PID, FD, tmpfs, log limits, user, and single-process
inventory.

Task 11 maps explicit swap authority for the exhaustive fixture Docker-role
set defined by composition amendment v4:

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

`runner-role` includes both the actual runner image and the synthetic-listener
image because each is created only through production `CreateRunner` with an
exact `RunnerSpec`; the synthetic payload is not a separate Docker resource
class.

The runner role remains sourced only from the already-approved
`RunnerSizingOverlay.SwapLimitConfigured` and `SwapLimitBytes`. Adapter,
broker, helper, verifier, and workflow-tool-probe receive distinct mandatory
`ResourceOverlay.ContainerSwap` entries. The workflow-tool probe also receives
its own `SlotResourcesOverlay.WorkflowToolProbe` vector; it cannot borrow
runner or verifier resources. Every entry has `Configured` plus an allowance
in bytes, so an omitted value cannot alias an explicit zero.

For every member, add `MemorySwapBytes` to the corresponding production limit
struct or closed test-local workflow-tool spec, derive it only as checked
`MemoryBytes + SwapLimitBytes`, require the configured bit, and pass the exact
total through `--memory-swap`. The checked total must fit Docker's positive
`int64` range. `SwapLimitBytes == 0` remains a valid explicit no-swap choice
only when the resulting total equals memory. No default, unlimited value,
cross-member fallback, or numeric value is introduced.

Adapter, broker, and runner-role inspect parsers add HostConfig `MemorySwap` and
require exact equality in their successful reinspection/audit boundary.
Helper, verifier, and workflow-tool-probe are short-lived `--rm` containers;
their swap binding is proved only by their respective closed argv, successful
bounded result/self-observation, and exact-name absence. It is not used to
claim a long-lived HostConfig readback.

The sandbox row sources remain:

- runner read-only root, resources, forbidden mounts/devices, and sizing:
  held-runner audit;
- syscall denials, `/proc` mask, and runtime identity/capability self-readback:
  closed runner commands;
- swap enforcement: exact adapter, broker, and held-runner-role HostConfig
  readbacks plus the three checked private mappings; helper/verifier mappings
  and the workflow-tool mapping remain bounded one-shot argv facts.

### Cases 6-9 and 11-15

Case 6 remains closed commands. Cases 7-9 and 11-14 retain their
synthetic-lifecycle classification. Case 15 remains the only actual GitHub
canary. No synthetic row may satisfy case 15.

### Case 10: workflow-tool one-shots

Each exact private workflow-tool binding maps to one serialized test-local
`workflowToolProbeSpec`. It uses:

- the declaration-ordered probe ID and immutable image/digest;
- the compiled fixed action for that ID, never caller argv;
- the exact static-preflight image user;
- `--network container:<exact held runner ID>`;
- the dedicated `SlotResourcesOverlay.WorkflowToolProbe` CPU, memory, PID,
  FD, work-tmpfs, and scratch values;
- the dedicated configured workflow-tool swap allowance and checked total;
- the exact Task 11 seccomp binding; and
- fixed read-only, `CapDrop=ALL`, no-new-privileges, two-private-tmpfs,
  mount/device-free, and log-driver-none options.

The exact-name cleanup lease is registered before each invocation. Success
requires bounded typed output and exact-name absence. Cancellation or failure
leaves cleanup authority but cannot pass the row. The one-shot resource facts
are argv/absence evidence only and cannot satisfy long-lived target
HostConfig evidence.

## Exact identity triangle and retained engine facts

`recordingEngine` may retain only nonsecret values already returned by the
production engine and exact success receipts for closed production methods:

- adapter, broker, and runner cleanup handles;
- input specs digested at the successful creation boundary;
- adapter-emptiness evidence plus its namespace and digest;
- network-egress evidence plus its report and digest;
- broker audit digest;
- held-runner audit digest;
- policy-application receipt;
- opaque authority proof retained only for the prepared-evidence bind plus
  its successful authority/usage binding receipt;
- pre-release held-socket-zero receipt;
- broker-release receipt;
- release-authorization receipt; and
- final held-jail IDs and `ProbeReport`.

Each receipt is a domain-separated digest over the operation name, exact
engine-issued object IDs, build/fleet/slot/run binding, relevant spec/policy
digest, and successful return boundary. A receipt is usable only for a
property that the production method checks before returning.

The namespace identity proof requires all of:

```text
AdapterEmptinessEvidence.Namespace
    == ProbeReport.RunnerNetNSID
    == postFloodReport.Namespace.Identity
```

and a successful `AuthorizeRelease` receipt for the same runner handle,
generation, held-jail IDs, pre-arm proof, and final proof. The opaque proofs
remain opaque. A receipt cannot manufacture their device/inode values.

Any changed graph, object ID, audit digest, policy, generation, operation
order, post-removal access, or duplicate-but-different receipt is terminal.
No new getter is added to `hostruntime.Engine`.

### Prepare-first sealing invariant

Every retained engine fact is provisional until the single production
`Orchestrator.Prepare` call returns a valid `HeldJail`. Case execution and the
evidence ledger receive no accessor for provisional facts.

The runtime exposes one test-local, one-shot prepared-evidence transfer only
after all of these are true:

- `Prepare` returned success;
- the exact held adapter, broker, runner, authority, graph, slot, generation,
  and final `ProbeReport` agree with the retained receipts;
- the journal reached `StageRunnerAuthorize` and
  `controller.StateReleaseArmed`;
- the final held-runner audit and successful `AuthorizeRelease` receipt are
  present; and
- the runtime has not begun release, destroy, or cleanup.

This makes the identity triangle a consequence of the complete production
ordering:

```text
adapter emptiness
  -> policy
  -> authority
  -> broker release
  -> egress verification
  -> runner creation
  -> pre-arm namespace
  -> final audit
  -> runner arm
  -> final namespace
  -> StageRunnerAuthorize
  -> HeldJail
```

A caller cannot assemble Case 2 evidence by invoking engine methods manually,
by stopping after a partial orchestrator sequence, or by replaying provisional
receipts after a failed `Prepare`. Any `Prepare` failure performs only
production cleanup and leaves the prepared-evidence transfer permanently
unavailable for that fixture.

## One fixed post-flood verifier operation

### Private input

Add exactly one mandatory field:

```go
LoopbackFloodAttempts uint32 `json:"loopback_flood_attempts"`
```

It must be nonzero. Source supplies no default or operational value. Checked
arithmetic must prove the one-listener serial client count, bytes, process/FD
use, evidence bytes, and case deadline fit the existing private limits before
any effect. The supplied count is recorded as a measurement, never converted
into a sizing choice.

### Verifier mode

Extend the immutable verifier with one closed mode:

```text
loopback-flood
```

It accepts exactly one canonical JSON line:

```json
{"version":1,"attempts":1}
```

The number above is a schema example. Unknown, duplicate, missing, zero,
noncanonical, trailing, or oversized input fails before network activity.
There is no hostname, address, port, protocol, path, environment, duration,
concurrency, executable, or argv field.

The operation:

1. self-validates all five capability sets empty;
2. reads current namespace identity and empty isolation snapshot;
3. opens one listener only on numeric `127.0.0.1` and a kernel-selected
   ephemeral port;
4. performs exactly the supplied number of serial one-byte exchanges under
   the caller's case deadline;
5. closes and joins both sides of every exchange;
6. immediately rereads namespace identity, devices, IPv4/IPv6 routes,
   IPv4/IPv6 registered tables, and namespace conntrack; and
7. emits one canonical report only if identity is unchanged, only loopback is
   present, routes are loopback-only, tables are empty, conntrack is empty,
   and every exchange completed.

The typed report contains:

```json
{
  "version": 2,
  "attempts": 1,
  "completed": true,
  "capabilities": {
    "effective": "0000000000000000",
    "permitted": "0000000000000000",
    "inheritable": "0000000000000000",
    "bounding": "0000000000000000",
    "ambient": "0000000000000000"
  },
  "namespace": {
    "identity": {"device": 1, "inode": 2},
    "loopback_only": true,
    "tables_empty": true,
    "conntrack_empty": true
  },
  "routes_complete": true
}
```

Counts and identity values are schema examples. The parser requires canonical
JSON, exact fields, exact attempt equality, positive identity, bounded bytes,
empty capability sets, and every boolean true. Raw bytes are zeroed after the
typed report is sealed.

### Closed invocation and cleanup

`networkSession` receives only:

- the existing closed command runner;
- exact engine-issued adapter and broker handles;
- the validated verifier spec;
- the run digest;
- the validated flood count; and
- the fixture cleanup recorder/remover.

It constructs one fixed Docker invocation. The only dynamic Docker values are
the engine-issued namespace ID, deterministic run-bound verifier name,
immutable verifier image/spec values already cross-checked by composition,
and canonical stdin. No caller supplies argv.

Before process creation, the session registers one exact verifier cleanup
lease binding a domain-separated cleanup handle to the deterministic name.
Normal completion proves exact-name absence and retires the lease.
Cancellation, command error, malformed output, or absence-proof failure leaves
the lease active so fixture cleanup removes exactly that name and proves it
absent. There is no prefix scan or generic container deletion.

After cancellation during the flood, cleanup additionally runs one fixed,
cleanup-only namespace recovery verifier. It proves:

- the canceled verifier name is absent;
- no listening AF_INET/AF_INET6 socket remains in the shared namespace;
- namespace conntrack is empty; and
- the namespace identity still matches the retained runner identity.

This recovery output can only complete cleanup; it cannot mark a row passed or
populate final target evidence. It has its own pre-registered exact cleanup
lease. A cleanup-proof failure fails the fixture cleanup.

The successful post-flood report is cached exactly once. Later rows read
defensive typed copies. A second success-path flood, second host read,
reordered row, changed count, or changed identity fails closed.

## Complete `IsolationEvidence` field-to-fact map

`FinalizeTarget` may assign a field only from the named conjunction below.
Every named row must be present, passed, ordered, same-run bound, and
unconsumed. There is no all-true literal or expected-anchor fallback.

| `IsolationEvidence` field | Required passed fact(s) |
| --- | --- |
| `RunnerNetworkNone` | adapter HostConfig `NetworkMode=none`; runner HostConfig `NetworkMode=container:<exact adapter>`; identity triangle; `adapter-runner-netns-identity` |
| `RunnerTablesEmptyBefore` | `runner-tables-empty` |
| `RunnerTablesEmptyAfter` | distinct `runner-tables-after-flood` |
| `RunnerConntrackEmptyBefore` | `runner-conntrack-before` |
| `RunnerConntrackEmptyAfter` | `runner-conntrack-after` |
| `LoopbackFloodCompleted` | `loopback-flood`, exact supplied/completed count equality |
| `NamespaceDenied` | named namespace-creation denial subfact from `runner-seccomp-syscall-denials` |
| `RawSocketDenied` | named raw-socket denial subfact from the same typed row |
| `BPFDenied` | named BPF denial subfact |
| `UnshareDenied` | named unshare denial subfact |
| `SetNSDenied` | named setns denial subfact |
| `Clone3Denied` | named clone3 denial subfact |
| `HeldBrokerSocketCountZero` | `held-broker-sockets-zero` pre-release receipt |
| `LegacyFilterRestored` | helper application receipt binds exact IPv4 and selected IPv6 policy readback to the policy artifact |
| `IPv6PostureProven` | helper policy readback plus released broker readiness/audit report the exact graph-selected posture |
| `RelayMountIdentityProven` | adapter RO relay bind + broker RW relay bind + runner zero mounts + helper/verifier/workflow-tool host-bind absence, same-run bound |
| `DialMountIdentityProven` | broker RO authority bind + adapter/runner absence + helper/verifier/workflow-tool authority-bind absence, same-run bound |
| `DoHPolicyProven` | exact graph/policy digest, DoH endpoint graph facts, a non-literal positive DNS member, aggregate graph execution, broker audit/readiness, and the same-run dual-class `PermitUsageProof` |
| `DurableConsumeBeforeDial` | immutable source-topology seal proving `DialPermitClient.Request` dominates every job and DoH literal dial; exact built-image/source binding; active SQLite ledger/authority revision; same-run job and DoH usage receipts bounded by durable reservations; actual positive probe; broker/final audits |
| `CPUEnforced` | host cgroup CPU availability plus exact nonzero adapter/broker/runner HostConfig CPU readback |
| `MemoryEnforced` | host cgroup memory availability; exact adapter/broker/runner memory and `MemorySwap` readback from distinct explicit mappings |
| `PIDsEnforced` | host PIDs controller availability plus exact adapter/broker/runner PIDs readback |
| `FDsEnforced` | exact adapter/broker/runner nofile soft/hard readback plus bounded one-shot argv |
| `TmpfsEnforced` | exact adapter/broker/runner tmpfs maps and modes from audits |
| `ReadOnlyRootEnforced` | adapter/broker/runner read-only root audits plus fixed helper/verifier/workflow-tool read-only argv |
| `SeccompEnforced` | adapter/broker/runner exact seccomp HostConfig readback plus fixed helper/verifier seccomp argv/self-observation and fixed workflow-tool seccomp argv/absence |
| `CapabilitiesEnforced` | adapter/broker/runner HostConfig capability audits; every verifier self-report empty; helper self-report NET_ADMIN-only; exact helper/verifier absence |
| `WorkAreaReclamationProven` | successful synthetic job reclamation, every cleanup-matrix row, reclamation post-cleanup, version-staging absence, seed-workspaces-reclaimed, and exact runtime cleanup ledger absence proofs |
| `BoundedLogRetention` | adapter/broker/runner-role exact local-log rotation readback; helper/verifier/workflow-tool log-driver-none argv/absence; approved storage log bounds; reclamation/log cleanup facts |
| `PolicyDigest` | exact lower-hex graph digest equal across compiled graph, policy artifact, helper readback, broker readiness/audit, egress evidence, final `ProbeReport`, and ledger |
| `EvidenceRevision` | domain-separated final ordered evidence-ledger digest described below |

The source-topology seal for `DurableConsumeBeforeDial` is part of source
verification, never a substitute for the actual runtime probe. It mechanically
requires permit acquisition and validation to dominate `DialLiteral` for both
job and DoH paths, with no alternate direct-dial branch. The immutable image
manifest/build binding connects that source fact to the target binary. The
same-run `PermitUsageProof` is independently mandatory: source dominance
without both runtime class receipts cannot pass, and runtime receipts without
the dominance seal cannot pass.

`RunnerRoutesComplete` for `NetworkDiscoveryDocument` is assigned only from
`runner-route-absence`. Its `EvidenceRevision` is the final evidence-ledger
digest, not merely the policy digest.

## Evidence ledger and finalization

The matrix source maintains a typed append-only ledger. A row is passed only
after its source-specific parser and all cross-bindings succeed. A typed row
may expose multiple named subfacts, but a subfact cannot be silently inferred
from the row's aggregate success.

The exact Case 2 sequence is:

1. require the one successful production `Orchestrator.Prepare` transfer
   through `StageRunnerAuthorize`; partial/manual engine state is unavailable;
2. consume retained orchestrator facts for loopback, tables-before, and
   conntrack-before;
3. run and cache the one flood/post-flood report;
4. seal tables-after, conntrack-after, and routes from distinct fields of that
   same report;
5. seal the exact namespace identity triangle;
6. seal helper/runtime capability rows; and
7. freeze Case 2.

Case 3 then consumes the already-obtained positive probe and the one
post-`Prepare` `PermitUsageProof`. It may not rerun egress or manufacture a
permit solely for evidence.

`FinalizeTarget` may run only after cases 1-14 complete in canonical order and
every required pre-canary row is passed. It rejects missing, duplicate,
reordered, substituted, uniterated, cross-run, cross-graph, stale, or
post-removal facts.

The final evidence revision is SHA-256 over a domain-separated canonical
preimage containing:

- run/build/fleet/profile/slot bindings;
- ordered case and row IDs;
- source, operation, and parser IDs;
- typed observation and subfact digests;
- probe membership indexes and graph digest;
- engine evidence/audit/receipt digests;
- the opaque dual-class permit-usage proof digest;
- exact runtime object IDs;
- capability-profile digests;
- policy digest;
- final namespace identity; and
- cleanup/reclamation fact digests.

Expected profile/network/report digests and expected booleans are excluded.

## TDD sequence

1. RED: capability-matrix tests require the new source remaps,
   `runner-tables-after-flood`, `held-broker-sockets-zero`, and closed-command
   remaps for plaintext/unsupported-port/SOCKS operations.
2. RED: helper capability-wire tests reject every non-NET_ADMIN-only mask,
   malformed `/proc/self/status`, and any accepted old proof.
3. RED: verifier capability-wire tests reject every nonempty mask in all
   modes, including flood and cleanup recovery.
4. RED: `ReleaseNetworkBroker` tests require the pre-release internet-socket
   zero check and reject a row, malformed report, drift, or post-check state
   change.
5. RED: swap-overlay, limit, argv, inspect, and composition tests require
   independent checked memory-plus-swap mapping for every `C_fixture` role;
   exact `--memory-swap`; long-lived HostConfig readback; workflow-tool
   resource/argv/absence proof; explicit zero; overflow rejection; missing
   configuration; no default; and no cross-member substitution. A synthetic
   listener must use the runner-role mapping rather than a direct invocation.
6. RED: permit-usage tests require actual current-process DoH and job issues,
   active tuple equality, exact durable reservations, and a stable opaque
   proof plus exact activation-revision binding to the retained
   `AuthorityProof`; reject one-class use, literal-positive input,
   prior-generation use, recovery-burned reservations, store drift, changed
   sequence, mismatched authority proof, and replay.
7. RED: prepare-first tests reject every manual/partial engine sequence,
   failure before or at `StageRunnerAuthorize`, provisional-fact access,
   post-failure replay, and post-cleanup transfer; only one successful
   `Prepare` may expose prepared evidence.
8. RED: input codec tests require the flood count and reject missing, zero,
   duplicate, unknown, reordered, overflow, and cross-bound inputs.
9. RED: flood verifier tests prove exact serial exchanges, post-flood table and
   conntrack facts, routes, identity, cancellation, partial completion, and
   canonical output.
10. RED: cleanup tests cancel mid-flood and require exact-name removal, no
   listener, empty conntrack, stable identity, and no pass evidence.
11. RED: recording-engine tests require all immutable evidence, audits, and
   receipts; reject changed graph/object/spec/generation, duplicate-different
   receipt, and post-removal reuse.
12. RED: probe-membership tests reject missing, duplicate, reordered,
    reclassified, or uniterated members and prove aggregate OK alone is
    insufficient; a public literal positive host is also rejected.
13. RED: mount tests mutate each adapter/broker/runner object independently and
    prove no broker-only digest can satisfy relay, authority, or host-control
    visibility.
14. RED: finalizer tests enumerate every `IsolationEvidence` field and reject
    any missing named fact, all-true literal, expected-anchor echo, policy-only
    evidence revision, or cross-case substitution.
15. GREEN: implement the minimum closed production result checks and test-local
    composition required by the converged plan.
16. Run all macOS-safe unit/source tests and Linux cross-compilation. Run actual
    Docker integration only on a separately operator-approved Linux target.

## Stop conditions

Stop and revise again if implementation requires:

- another unlisted numeric, duration, count, path, executable, image, or
  Docker option;
- a generic production engine API widening;
- raw Docker/container authority outside the closed session;
- expected input used as observed evidence;
- any fixture-owned Docker container without an explicit swap allowance;
- permit evidence inferred from durable reservation state without both
  current-process class receipts;
- any case evidence exposed before successful production `Prepare` through
  `StageRunnerAuthorize`;
- a success-path second flood or second post-flood host read;
- a capability claim without self-observation or HostConfig readback;
- a mount claim from one object when exclusivity requires multiple objects;
- cleanup by prefix, scan, or caller-supplied identity;
- synthetic evidence satisfying actual GitHub transport; or
- a final isolation field without an exact named ledger fact.

## Distinct-family confirmation request

Adversarially confirm whether this revised source split is truthful and
sufficient before codegen. In particular:

1. Does the helper/verifier self-capability contract close the fixed-argv
   overclaim without widening production authority?
2. Is the new post-flood table row and prepare-first identity triangle
   sufficient, including failure-only cancellation cleanup and rejection of
   every partial/manual engine sequence?
3. Are broker probe rows now correctly divided between graph membership and
   closed operations, with mechanical no-skip/no-reorder binding?
4. Does the multi-object mount proof correctly reflect adapter RO relay,
   broker RW relay, broker RO authority, and absence elsewhere?
5. Does `C_fixture` now exactly cover every fixture-started Docker role,
   including synthetic-listener-as-runner-role and the distinct
   workflow-tool-probe vector, without selecting an operating value or
   overstating one-shot readback?
6. Does every `IsolationEvidence` field have a truthful, non-circular fact
   source, especially `HeldBrokerSocketCountZero`,
   `DurableConsumeBeforeDial`, `CapabilitiesEnforced`,
   `WorkAreaReclamationProven`, and `BoundedLogRetention`?
7. Does the opaque same-run dual-class permit proof truthfully combine actual
   current-process consumption with durable reservation, including recovery
   burn and literal-positive negatives?
8. Are any additional RED cases required before implementation?

Return `PROCEED` only if no material source-authority, lifecycle, or fail-open
gap remains. Otherwise return `REVISE` with exact required changes.
