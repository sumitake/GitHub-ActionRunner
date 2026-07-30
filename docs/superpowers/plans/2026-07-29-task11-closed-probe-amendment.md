# Task 11 Closed In-Container Probe Amendment

> **Status:** revision 3 converged after xAI/Grok architecture reviews
> `portable-ghar-task11-closed-probe-amendment-grok-architecture-20260729-1`
> and `...-2` returned `REVISE`; exact-artifact confirm `...-3` returned
> `PROCEED` over 33,496 bytes / SHA-256
> `7a1b3ad34fcf16f84bf2638dd2d1a9967828ffc464f67d68ebe58c32c5905ebc`.
> Revision 3 seals the last two material gaps: exact live scanner capture
> authority and fail-closed non-Linux verifier behavior. This amendment
> authorizes no Docker execution, image build, host mutation, RhoNAS/QTS
> change, numeric sizing choice, or target conformance claim.

## Discovery

Task 11's prepared-evidence path now truthfully transfers the successful
production `Orchestrator.Prepare` result through `StageRunnerAuthorize`, and
the Case 1-14 evidence ledger and target finalizer are source-complete. The
remaining Linux entrypoint cannot yet be wired without inventing evidence:

- the existing verifier has no stateless operation for the direct-protocol,
  plaintext HTTP, unsupported CONNECT-port, or SOCKS BIND/UDP denial rows;
- the existing runner gate has no stateless operation for the syscall-denial,
  `/proc` mask, runtime identity, or fixed forbidden-path observations; and
- `closedCommandSurface` currently accepts the operation enum but constructs
  argv only for preflight and fixture stat. Its network and runner sessions do
  not consume their engine-issued identities; and
- the Case 4 `runtime-secret-scan` row remains a separate closed observation:
  fixed-path/environment absence cannot substitute for scanning the exact
  bounded runtime surfaces.

Deriving these rows from opaque audit digests alone would be false. Adding a
generic `Engine.Exec`, accepting caller argv/path/environment, or relying on a
shell would violate the converged Task 11 plan. A new executable would also
introduce an unreviewed image/build authority. The narrow repair is therefore
to add two stateless, closed modes to binaries already present in the
qualified images and to bind their invocation through the existing
test-local session types.

## Invariants

1. No production `hostruntime.Engine` method is added or widened.
2. No new executable, image role, image binding, path-valued input, positive
   network endpoint, environment map, caller-selected command fragment,
   duration, count, or sizing value is introduced. The fixed IANA
   documentation-only negative sentinels and fixed protocol/parser constants
   already required by the base Task 11 plan remain non-authoritative source
   constants compiled into the verifier. They never become private input or a
   positive route.
3. Both modes are observation-only. They cannot arm, release, register,
   acquire a permit, mutate a policy, remove a resource, or create durable
   state.
4. The runner mode is input-free. The verifier mode accepts only the already
   canonical decision graph; it cannot accept a hostname, address, port,
   protocol, argv, or environment field.
5. Every invocation is bound to an engine-issued container identity already
   present in the successful prepared-runtime observation. The test-local
   verifier name is domain-separated from production verifier names and is
   derived only from that adapter identity plus the already-bound run/build/
   fleet/verifier tuple.
6. The verifier remains non-root, read-only, capability-empty,
   `CapDrop=ALL`, no-new-privileges, seccomp-bound, mount/device-free,
   log-driver-none, and attached only to
   `container:<prepared adapter ID>`.
7. The runner observation executes inside the held runner through the fixed
   installed runner-gate path. No shell, package tool, interpreter, or
   caller-supplied executable is used.
8. Output is canonical JSON plus one LF, bounded by the existing observation
   ceiling, parsed with unknown fields rejected, rebound to the prepared
   runtime, domain-separated, and zeroed.
9. A partial, canceled, noncanonical, reordered, repeated, or mismatched
   observation cannot produce any passing row.
10. These modes contribute only to Cases 3-6. The separate bounded
    runtime-surface scanner remains mandatory for Case 4. None of these
    observations can satisfy synthetic lifecycle Cases 7-9 or 11-14,
    workflow-tool Case 10, or actual GitHub Case 15.

## Existing-binary additions

### Runner gate: `conformance-observe`

Add one input-free mode to `portable-ghar-runner-gate`. It performs all
observations in the current held runner and emits exactly:

```go
type runnerConformanceWire struct {
    Version uint8 `json:"version"`

    EUID uint32 `json:"euid"`
    EGID uint32 `json:"egid"`
    Capabilities linuxcap.Wire `json:"capabilities"`

    RawSocketDenied bool `json:"raw_socket_denied"`
    BPFDenied bool `json:"bpf_denied"`
    UnshareDenied bool `json:"unshare_denied"`
    SetNSDenied bool `json:"setns_denied"`
    Clone3Denied bool `json:"clone3_denied"`
    NamespaceDenied bool `json:"namespace_denied"`

    ProcSysReadOnly bool `json:"proc_sys_read_only"`
    ProcMasksPresent bool `json:"proc_masks_present"`

    ControllerDatabaseAbsent bool `json:"controller_database_absent"`
    DockerAuthorityAbsent bool `json:"docker_authority_absent"`
    HostControlAbsent bool `json:"host_control_absent"`
    SecretEnvironmentAbsent bool `json:"secret_environment_absent"`
    JITEnvironmentAbsent bool `json:"jit_environment_absent"`
    SyntheticTokenAbsent bool `json:"synthetic_token_absent"`
}
```

The implementation has no caller paths. It uses a compiled fixed forbidden
projection set representing the standard container destinations for the
authorities the runtime design forbids. Those negative path facts are
authoritative only when paired with the successful zero-mount held-runner
audit; they never claim that an arbitrary host path was opened in the
container. The mode validates:

- all five Linux capability masks are empty;
- EUID/EGID are canonical numeric identities and match both the
  already-inspected runner `Config.User` and the exact `docker exec --user`
  binding;
- a raw IPv4 socket, `bpf`, `unshare(CLONE_NEWNET)`, `setns` against the
  already-open current network namespace, and `clone3` are denied with the
  exact closed seccomp/permission errno set;
- no new namespace identity is obtained;
- `/proc/sys` is read-only in the parsed mount table and the fixed Docker
  masked-proc set has the expected non-followed identities;
- fixed Docker, controller, host-control, credential, and reusable-work
  projections are absent; and
- the exact process environment matches the runner image contract and
  contains no JIT or synthetic-token variable.

The mode does not scan arbitrary bytes for secret-shaped strings and does not
return raw environment, paths, errno values, mountinfo, or capability text.
The separate runtime-surface scanner below owns that row. The tests inject
syscall/path/status readers and cover every one-field false result, wrong
errno, nonempty capability mask, unexpected environment name, duplicate
status field, mountinfo ambiguity, and output mutation.

`MountSecretObservation` consumes the fixed-absence/environment facts only for
`controller-sqlite-invisible` and `synthetic-token-absence`, paired with the
already-successful adapter/broker/runner audits and one-shot argv seals. It
cannot use them for `runtime-secret-scan`. `SandboxObservation` consumes only
the identity, capability, syscall, and proc-mask facts plus the held-runner
audit. No aggregate boolean is shared across those row families without the
named subfact.

### Network verifier: `closed-denials`

Add one mode to `portable-ghar-network-verifier`. Its input is the exact
canonical decision-graph document already used by `probe`; no new request
schema or private field is introduced. Before traffic it:

- validates its five capability masks are empty;
- validates the current namespace identity and loopback-only/empty snapshot;
- binds the graph's exact `IPFamily`, `BrokerIPv6Posture`, and policy digest;
  and
- selects exactly one HTTP CONNECT positive-probe host only after requiring a
  canonical nonliteral DNS name and an allowed nonzero port.

The mode is callable only after the same-run primary `Prepare` completed
through `StageRunnerAuthorize`, the adapter relay is bound to the broker
parser, and the prepared audit/identity tuple is frozen. A refused loopback
connection is not a denial success.

The source constants are exact and non-authoritative:

```text
direct IPv4 sentinel       192.0.2.1
direct IPv6 sentinel       2001:db8::1
direct DNS sentinel        192.0.2.53:53
direct TCP/UDP port        443
adapter parser endpoint    127.0.0.1:18080
unsupported CONNECT port   80
```

The first three are IANA documentation-only negative sentinels already
authorized by the base Task 11 plan. Port 80 is the parser's existing
unsupported-port corpus value, not private input. Construction fails before
traffic if port 80 appears in `AllowedConnectPorts`; the verifier never
selects an unsupported port from the graph.

It then performs this declaration-ordered, fixed operation set:

1. direct IPv4 TCP connect;
2. direct IPv4 UDP send;
3. direct IPv6 TCP connect;
4. direct IPv6 UDP send;
5. one fixed direct DNS UDP query;
6. raw ICMP socket creation;
7. plaintext HTTP to the fixed adapter loopback endpoint;
8. HTTP CONNECT for the selected positive host on fixed port 80;
9. SOCKS5 BIND; and
10. SOCKS5 UDP ASSOCIATE.

The committed documentation addresses are negative probes only and never
positive endpoints. All ports and protocol bytes are existing protocol or
adapter constants. There is no success fallback through a proxy-aware
library. The fixed closed result enum is:

```text
ipv4_tcp_no_route
ipv4_udp_no_route
ipv6_tcp_no_route
ipv6_tcp_family_unavailable
ipv6_udp_no_route
ipv6_udp_family_unavailable
dns_udp_no_route
raw_icmp_permission_denied
plaintext_http_parser_rejected
unsupported_connect_port_parser_rejected
socks_bind_parser_rejected
socks_udp_associate_parser_rejected
```

Each report field accepts only the operation-specific member(s) above.
`*_no_route` maps only the fixed immediate no-route/unreachable errno set;
`*_family_unavailable` maps only the fixed unsupported-family errno set.
Timeout, cancellation, connection refusal, success, a generic I/O error, or
any other errno fails. IPv6 accepts either closed observed class for the
runner namespace and records which one occurred. The report also carries the
real graph `IPFamily` and `BrokerIPv6Posture`, but neither field is used as a
proxy for runner-netns routing. In particular,
`deny-via-ip6tables` remains broker-helper/audit evidence and is not proved by
this runner-netns operation.

Parser classes require a successful TCP accept by `127.0.0.1:18080`, the
exact request exchange, zero tunnel-success bytes, and EOF/reset only after
the parser received the request. SOCKS classes additionally require the exact
accepted no-auth greeting before the BIND/UDP command is rejected. Listener
refusal, timeout, partial write/read, or any non-loopback connection fails.

Namespace semantics are split rather than over-claimed:

- before all traffic: valid identity, loopback-only, tables empty, conntrack
  empty;
- after the six direct/raw operations: the same identity, loopback-only,
  tables empty, and conntrack empty;
- after the four loopback parser operations: the same identity,
  loopback-only, and tables empty; conntrack is explicitly unmeasured and no
  Case 2/3 row receives a post-parser conntrack claim.

The canonical output contains version, policy digest, the exact graph
`IPFamily` and `BrokerIPv6Posture`, before/direct-after/parser-after topology,
ten named result classes, and `completed=true`. It contains no address, host,
port, request bytes, response bytes, error text, timing, or aggregate
pass/fail boolean.

Tests cover every allowed and disallowed errno, both IPv6 closed classes,
graph-field/report substitution, port-80 graph admission, success-like proxy
responses, connection to any non-loopback local endpoint, a missing parser
listener, partial execution, changed namespace, nonempty pre/direct tables or
conntrack, nonempty parser tables, timeout, cancellation, reordered/duplicate
operations, and noncanonical graph/output.

The mode has an explicit platform boundary. Its syscall/traffic
implementation is Linux-build-tagged. The `!linux` implementation returns
typed `ErrClosedDenialsUnsupportedPlatform` before graph decoding, namespace
inspection, or socket creation and emits no observation bytes. Existing
verifier modes retain their current platform behavior; this stub applies only
to `closed-denials`.

## Permit nonconsumption seal

The prepared same-run dual-class `PermitUsageProof` remains the single
consumption-establishing Case 3 proof. It is acquired after successful
`Prepare` and stored unchanged in the prepared ledger.

After `closed-denials` completes, the fixture performs one separate read-only
`AuditActiveUsage` call for the same slot/generation. This call is allowed only
to establish nonconsumption:

- its returned digest must equal the stored prepared proof digest exactly;
- it cannot replace, reissue, or rebind the prepared proof;
- it cannot satisfy the positive-probe or authority-match row;
- any changed usage, durable/in-memory drift, generation change, missing
  class, or audit error fails Case 3; and
- the fixture seals a distinct
  `portable-ghar.task11.permit-nonconsumption.v1` digest over the prepared
  proof digest, repeated audit digest, policy digest, slot/generation, and
  exact `closed-denials` report digest.

The observation-source amendment's “one post-Prepare proof” rule therefore
continues to mean one proof used as positive consumption authority. This
second equality audit is a negative subfact only.

## Separate runtime-surface secret scan

`conformance-observe` does not satisfy `runtime-secret-scan`. A test-local
`closedRuntimeSurfaceScanner` performs that row without adding an executable
or accepting a path/argv/environment input. It may consume live Docker bytes
only through the exact `scannerSession` operations below. A Prepare/audit
digest, reconstructed claim, or unbound Docker call cannot substitute for
those bytes.

Its exact source set is constructed from already-bound objects and results:

- strict Docker inspect projections captured once through `scannerSession`
  for the engine-issued adapter, broker, and runner IDs: environment,
  entrypoint, command, labels, mounts, binds, devices, and security options;
- exact process inventories and bounded stdout/stderr from fixed
  `docker logs <exact-id>` operations captured through that same session for
  those three containers before runner release; the runner inventory is the
  already-captured final byte-equal held-gate inventory, not a fourth top
  call;
- byte-equal canonical output reconstructed from each already-validated
  helper/verifier one-shot wire, plus directly captured output for the runner
  observation, image verification, listener version, and exact absence
  checks; every successful contributing command except the three explicit log
  captures must have zero stderr, while each log capture's bounded stderr is
  itself a required scanned surface;
- canonical prepared-runtime, `closed-denials`, runner-conformance, and
  Cases 1-4 matrix documents; and
- the fixed negative-path/environment projection results.

Every source is size-bounded, tagged by a closed surface enum, scanned once in
declaration order, and zeroed after its domain-separated digest is computed.
The capture sequence is fixed: adapter inspect/top/logs, broker
inspect/top/logs, runner inspect/final-held-inventory/logs, then the existing
one-shot and canonical-document surfaces. A command, role, or phase outside
that sequence fails rather than recapturing.
An opaque helper/verifier digest cannot substitute for bytes: the existing
parser must already have proved raw output byte-equal to the reconstructed
canonical wire before that wire enters the scanner.
Structured JSON is decoded with unknown fields rejected and only string
values are scanned, so field names such as `synthetic_token_absent` cannot
cause false positives. Raw log/process text is scanned byte-for-byte. The
scanner shares the existing Task 11 secret-shape table from
`containsSecretShapedValue` (`access_token`, `refresh_token`, GitHub token
prefixes, bearer material, PEM begin markers, `password=`, and `token=`),
case-insensitively; it adds no heuristic entropy detector or returned match.

The scanner returns only version, ordered surface count, a digest of the
closed surface/type/length sequence, `clean=true`, and one LF. Any missing,
duplicate, reordered, truncated, noncanonical, unparsed, nonempty forbidden,
or matched surface fails without returning matching bytes. A finalizer-side
pass over the complete canonical matrix/report uses the same scanner revision
and must also be clean before target finalization; this prevents later Cases
5-14 from bypassing the Case 4 report-surface claim. Actual JIT-after-parse
remains exclusively Case 15 evidence.

## Bound test-local command sessions

`closedCommandSurface` remains the sole argv constructor and gains no public
method. Its sessions become real authority boundaries:

- `preflightSession` retains only pre-effect Docker/image operations;
- `networkSession` binds the prepared adapter and broker IDs, the immutable
  verifier binding, its validated numeric user/seccomp/limits, the exact
  decision graph, the run/build/fleet tuple, and one registered exact-name
  cleanup lease;
- `runnerSession` binds the prepared runner ID, expected numeric user, and the
  fixed runner-gate/listener paths; and
- `scannerSession` binds the exact prepared adapter, broker, and runner IDs,
  the already-validated final runner inventory, and a one-use declaration-
  ordered capture state machine. It accepts only the closed role and capture
  enums; neither an ID nor an argv fragment is an operation input.

The constructors accept typed values from static preflight/composition and
engine-issued prepared evidence only. They reject a changed ID, build,
generation, user, image, seccomp binding, or resource vector.

Exact argv:

- runner observation:
  `docker exec --user <prepared-uid:gid> <runner-id> /usr/local/bin/portable-ghar-runner-gate conformance-observe`
- image verification:
  `docker exec --user <prepared-uid:gid> <runner-id> /usr/local/bin/portable-ghar-runner-gate verify-image`
- listener version:
  `docker exec --user <prepared-uid:gid> <runner-id> /opt/actions-runner/bin/Runner.Listener --version`
- runner process inventory:
  `docker top <runner-id> -eo pid=,args=`
- scanner inspect projection, once for each bound role:
  `docker inspect --type container --format <fixed-projection-template> <exact-id>`.
  The compiled template emits one JSON object containing only `Config.Env`,
  `Config.Entrypoint`, `Config.Cmd`, `Config.Labels`, `Mounts`,
  `HostConfig.Binds`, `HostConfig.Devices`, and
  `HostConfig.SecurityOpt`. The result is decoded with an exact projection
  schema and re-encoded byte-equal before scanning; no full-inspect opaque
  digest is accepted.
- scanner process inventory, once for the bound adapter and broker only:
  `docker top <exact-id> -eo pid=,args=`. The runner source reuses the exact
  already-authorized final held-gate inventory.
- scanner logs, once for each bound role:
  `docker logs <exact-id>`. Both CLI stdout and stderr are independently
  bounded and scanned as raw bytes; nonzero exit, truncation, or output after
  the capture deadline fails. Container stderr is evidence rather than a
  command failure when the Docker CLI return code is zero.
- denial verifier: one fixed `docker run --rm` vector using the immutable
  verifier image, `--network container:<adapter-id>`, the existing verifier
  resource/swap/user/seccomp values, no mounts/devices/logs, fixed
  `closed-denials` mode, and the canonical graph on stdin;
- exact-name absence:
  `docker inspect --type container <derived-one-shot-name>` must return the
  closed not-found class after the `--rm` process exits.

The test-local verifier identity is:

```text
full = SHA-256(
  "portable-ghar.task11.closed-denials-name.v1\0" ||
  adapter-id || run-digest || build-id || fleet-generation ||
  verifier-image-reference || verifier-spec-digest
)
name = "pghar-task11-verifier-" || hex(full[0:16]) || "-denials"
cleanup handle = CleanupVerifier + hex(full)
```

Every preimage field is already validated and rebound to static/prepared
evidence; none is accepted from an operation request. The `pghar-task11-`
prefix and `-denials` suffix make collision with production
`pghar-verifier-...-{empty,probe,identity,flood}` names impossible.

The fixed projection template is a compiled argv constant, not caller data or
a shell program. `scannerSession` is the only authority for the live
inspect/top/log captures. Existing Prepare audits remain property authority
for their named rows, while the scanner obtains raw projection bytes
independently through `scannerSession`; neither an audit digest nor a
reconstruction from audit booleans enters the scanner.

The exact `--format` argument is byte-equal to this single line (the outer
backticks are documentation delimiters, not argv bytes):

```text
{"version":1,"env":{{json .Config.Env}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"labels":{{json .Config.Labels}},"mounts":{{json .Mounts}},"binds":{{json .HostConfig.Binds}},"devices":{{json .HostConfig.Devices}},"security_options":{{json .HostConfig.SecurityOpt}}}
```

It is passed directly as one argv element. No shell quoting, interpolation,
alternate template, full-inspect fallback, or caller-provided format is
accepted.

The exact cleanup handle-to-name mapping is installed in the fixture cleanup
authority and registered before `docker run`. Any ambiguous result retains
removal authority and fails the row. Normal completion requires `--rm`
absence; cleanup uses only `docker rm -f <exact-name>` followed by the same
closed not-found proof. No prefix/label discovery or JSON revalidation is
used.

Runner observation order is fixed:

1. prove the original single held-gate process inventory;
2. execute `conformance-observe` and wait for the exec process to exit;
3. re-prove the single held-gate process inventory;
4. execute `verify-image` and direct listener `--version` serially;
5. re-prove the single held-gate process inventory again; and
6. only then seal `no-file-sweeper` and the inventory-dependent Case 6 rows.

Any extra process, exec-user mismatch, nonzero/stderr/truncation, failed reap,
or inventory change fails the affected cases. Docker's default exec-user
selection is never relied upon.

## Case 3-6 evidence mapping

- Case 3 `broker-denied-direct-protocols` consumes the six direct/raw result
  fields, the before/direct-after topology equality, the exact graph
  `IPFamily`, and the separate permit-nonconsumption digest. IPv6 accepts the
  observed runner-namespace no-route or family-unavailable class but never
  derives the broker's `BrokerIPv6Posture` from it. The graph posture is
  carried only as a rebound policy field.
- Case 3 `broker-denied-plaintext-http`,
  `broker-denied-connect-port`, and `broker-denied-socks-operations` consume
  only their four exact parser result fields, successful loopback listener
  precondition, exact protocol exchanges, and parser-after identity/
  loopback/table facts. They receive no post-parser conntrack fact.
- Case 3 `broker-denial-boundary` seals the declaration-ordered ten-result
  vector, the three phase-topology digests, policy digest, graph family/
  posture fields, and permit-nonconsumption digest. No aggregate result or
  one operation's denial class can satisfy another row.
- Case 3 flood bounds remain the already checked immutable parser/fallback
  formulas and source-topology seal. The runtime row additionally binds the
  successful closed-denials execution and prepared graph/resource tuple; it
  does not invent another traffic count.
- Case 3 loss-prevents-release uses a separate in-run, test-local
  fault-injection orchestration over a distinct real engine-created
  adapter/broker/runner tuple. Before `StageRunnerAuthorize`, the wrapper
  removes exactly one closed required fact from its private recording view
  while leaving the underlying resource tuple available to cleanup. The
  orchestration must return the expected typed authorization failure, record
  zero `ReleaseRunner` calls, and invoke the ordinary production cleanup path
  to exact absence. Its run digest, slot, generation, IDs, cleanup handles,
  and evidence ledger are domain-separated from the primary successful jail;
  the primary tuple is re-audited byte-identical before and after and is never
  supplied to the fault wrapper.
- Case 4 mount topology remains derived from the three successful production
  audits and the fixed helper/verifier/workflow-tool argv seals. The runner
  observation contributes only fixed-path and environment absence subfacts,
  and those subfacts are authoritative only with the zero-mount audit.
  `runtime-secret-scan` is satisfied solely by the independent bounded
  `closedRuntimeSurfaceScanner`; neither fixed absence nor an opaque audit
  digest can pass that row. `controller-sqlite-invisible` and
  `synthetic-token-absence` retain their own named path/environment facts and
  cannot alias the scanner result.
- Case 5 read-only root, resources, mounts/devices, sizing, and long-lived
  swap remain production-audit facts. The runner observation contributes only
  syscall, proc-mask, numeric identity, and self-capability subfacts. Its
  digest is rebound to the inspected `Config.User`, the explicit exec user,
  and the exact pre/post/final held-gate process inventories.
- Case 6 requires both successful `verify-image` and exact equality between
  its version and the direct `Runner.Listener --version` output. Exact image
  tree verification plus the held-runner audit proves one payload, no
  old/new pair, no updater staging, no extra process/sweeper, and no baked JIT
  environment. The direct version output must equal the immutable runner
  release binding as well as `verify-image`; all three process inventories
  must be byte-identical to the original single held-gate inventory. Each
  named row receives a separate domain-separated digest over the exact
  contributing facts.

## TDD and verification sequence

1. RED runner-gate unit tests for the exact wire, every allowed and rejected
   syscall errno, EUID/EGID overflow or mismatch, nonempty capability mask,
   namespace-identity change, ambiguous `/proc` mount/mask record,
   missing/duplicate fixed path or environment fact, unknown mode/input,
   repeated/reordered field, and noncanonical output.
2. GREEN the injected input-free runner observer, with Linux implementation
   and fail-closed non-Linux stub.
3. RED verifier unit tests for all ten exact operations and every permitted
   class/errno mapping. Cover success, timeout, refusal, generic I/O,
   wrong-family class, wrong operation class, missing/reordered/duplicate
   operation, IPv6 no-route and family-unavailable, and substitution of
   graph `IPFamily` or `BrokerIPv6Posture`. Prove the IPv6 result never changes
   or supplies broker-posture authority.
4. RED verifier construction/parser tests for port 80 appearing in
   `AllowedConnectPorts`, changed constants, unavailable loopback listener,
   partial request/response, non-loopback connection, tunnel-success bytes,
   wrong SOCKS greeting, and request rejection before the parser received the
   full fixed exchange.
5. RED topology tests for the exact three phases: pre and direct-after require
   identity/loopback/tables/conntrack; parser-after requires the same identity,
   loopback, and empty tables while representing conntrack as explicitly
   unmeasured. Missing the parser phase or manufacturing a parser conntrack
   value fails.
6. GREEN the injected verifier observer without changing existing
   namespace/probe/flood modes. All `closed-denials` syscall and traffic
   implementation files are Linux-build-tagged. A `!linux` implementation
   returns one typed `ErrClosedDenialsUnsupportedPlatform` before parsing the
   graph or opening a socket and emits no observation bytes. Tests compile and
   invoke that stub on Darwin and prove zero injected network/namespace
   operations; the Linux package remains cross-compiled separately.
7. RED permit-nonconsumption tests require a stored prepared dual-class proof
   and one later read-only audit with an equal digest. Unequal digest, missing
   class, changed tuple/generation, audit error, or an attempt to replace the
   prepared proof fails. The new digest must change if the closed-denials
   report changes and can never satisfy the positive-probe row.
8. RED `closedCommandSurface` tests for bound IDs, exact numeric exec user,
   exact argv/stdin, output parsing, byte limits, phase crossing, and buffer
   zeroing. Cover a deterministic one-shot name collision, cleanup
   registration before create, ambiguous `docker run`, exact-name-only
   removal, closed inspect absence, and rejection of prefix/label discovery.
9. RED runner-session process tests require the ordered
   pre-observe/post-observe/post-version inventories, exact single held-gate
   content, byte equality, and no unreaped exec process. A default-user exec,
   mismatched `Config.User`, extra process, reordered call, stderr byte, or
   listener/verify-image/release-version mismatch fails.
10. RED scanner tests require the complete declaration-ordered surface enum,
    raw byte equality for reconstructed canonical wires, per-surface size
    bounds, and the shared secret-shape matcher. Missing, duplicate,
    reordered, truncated, opaque-only, or matching input fails; fixed-path
    absence alone cannot pass `runtime-secret-scan`. The finalizer rescan must
    catch a later Case 5-14 report mutation.
11. RED scanner-session tests require the exact fixed projection template,
    role-bound IDs, adapter/broker-only top calls, runner final-inventory
    reuse, three bounded log calls, exact capture order, and one-use phase.
    Reject any full-inspect fallback, audit-digest substitution, changed role
    ID, repeated/omitted call, unbound argv, nonzero result, truncation, or
    late capture.
12. GREEN typed network/runner/scanner sessions and the independent runtime-
    surface scanner.
13. RED/green concrete Case 3-6 provider tests for every mapping above.
    Opaque audit digests alone must not pass any newly observed subfact.
14. RED loss-prevents-release tests use a distinct engine-created tuple,
    inject each allowed missing prepared fact before
    `StageRunnerAuthorize`, require the exact typed failure and zero
    `ReleaseRunner`, prove production cleanup, and prove the primary jail
    tuple and evidence ledger are untouched.
15. Wire those providers into the Task 11 runtime suite without yet enabling
   the Linux fixture entrypoint.
16. Run macOS-safe focused/full tests, `go vet`, direct non-Linux stub tests,
    tagged Darwin explicit skip, and Linux cross-compilation only.
17. Continue with the already-converged synthetic/tool/recovery provider plan,
    then wire `StartDockerFixture`.

Actual Docker execution and target evidence remain separately operator-gated.

## Deferred operational decisions

This amendment chooses proof semantics, not live values or deployment state:

- The changed runner-gate and verifier binaries will require new immutable
  runner/verifier image digests and the ordinary qualification flow before a
  future Linux target run. No image is built, tagged, pushed, selected, or
  activated in this source phase.
- Numeric tmpfs, cgroup memory, concurrency, and rebuild-cadence decisions
  remain deferred for separate operator sign-off. This amendment does not
  supply defaults through tests or constants.
- Runner-namespace IPv6 records whichever closed class the target kernel
  produces. That observation needs no new operator policy choice and grants
  no broker-filter claim.
- Post-parser conntrack is deliberately unmeasured because the fixed
  loopback parser exchanges can create namespace-local state. Adding a
  post-parser conntrack claim would require a new design amendment and review;
  no current matrix row depends on it.
- Any future Docker execution, RhoNAS/QTS operation, image qualification, or
  target evidence run remains an explicit operator-gated phase.

## Stop conditions

Stop and return to design review if implementation needs:

- any new input field, executable, image, positive endpoint, operational
  number, path, environment key, or runtime secret;
- a generic exec/inspect method on `hostruntime.Engine`;
- a shell or package-manager command;
- a caller-supplied container ID, argv, path, environment, or protocol;
- a denial inferred only from timeout or absence of output;
- an unbound live Docker inspect/top/log capture or a Prepare-audit digest
  substituted for its raw scanner surface;
- a runner-netns IPv6 result used to infer broker `ip6tables` posture;
- fixed-path absence or an opaque digest used to satisfy
  `runtime-secret-scan`;
- a capability, mount, resource, payload, or secret claim inferred from an
  opaque digest that did not validate that property;
- a second use of the primary prepared jail; or
- synthetic evidence to satisfy an actual-host or actual-GitHub row.
