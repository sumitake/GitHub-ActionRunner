# Portable-GHAR Task 6 implementation plan

Author: Codex / OpenAI family

Scope: source-only implementation and locally executable verification for
`Install and Verify Bounded Broker Egress Before Listener Release`.

## Fixed boundaries

- Implement the converged Task 6 contract in
  `docs/superpowers/plans/2026-07-11-controller-runtime.md` and section 7.2 of
  `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`.
- Preserve the signed Task 5 host-runtime and held-runner interfaces at commit
  `385366bc2478da50858db41f180510397598bb4b`.
- No RhoNAS/QTS mutation, Docker daemon use, live networking, release, or
  production sizing selection. Docker/QTS conformance remains a separately
  typed target gate. Numeric host-memory/tmpfs/concurrency/cadence choices
  remain operator-reserved.
- Implement only `restricted-broker-v1`. Keep `nftables-direct-v1` defined but
  unavailable; never auto-detect or fall back.
- Public fixtures contain synthetic addresses and paths only. Destination,
  payload, credential, JIT, and token values never enter errors or logs.
- Linux-only imports and syscalls stay behind `//go:build linux`; Darwin stubs
  fail closed while the pure policy/parser/budget/ledger code remains fully
  testable on macOS.

## Security invariants

1. The runner/adapter namespace remains loopback-only and has no routable
   interface. The adapter only byte-relays loopback TCP to one exact AF_UNIX
   socket and cannot parse, resolve, or dial.
2. The broker parser consumes untrusted CONNECT/SOCKS bytes but cannot create
   AF_INET/AF_INET6 sockets. It emits one canonical bounded `DialRequest`.
3. The dialer treats that request as hostile: it repeats authority parsing,
   port checks, name/literal normalization, deny-range classification, and
   validates every DNS answer. It dials literal IP text only.
4. Every real `connect()` attempt, including each DoH reconnect and every
   address fallback, follows a durably committed permit. Lost replies and
   crashes waste permits; no path refunds them.
5. The authority owns time and durable state. Request frames contain slot,
   job generation, class, and sequence only—no timestamp, rate, token count,
   refill, or boot hint.
6. No listener exists until adapter emptiness, held broker identity, helper
   exit, policy readback, authority proof, positive/negative probes, namespace
   identities, socket identities, and conntrack arithmetic all bind the same
   build/profile/evidence generation.
7. Any ambiguity is terminal and cleanup-first. Source verification and target
   conformance remain non-interchangeable.

## Package and type design

Create `internal/networkjail` with the planned files plus narrowly named test
helpers. Public values have no maps, `any`, raw argv, raw Docker IDs, or
caller-provided digests.

### Policy

Define closed enums:

- `EgressBackend`: `restricted-broker-v1`, `nftables-direct-v1`
- `IPFamily`: `public_ipv4_only`, `public_dual_stack`
- `BrokerIPv6Posture`: `deny-via-ip6tables`, `kernel-disabled`
- `DialClass`: `job`, `doh`
- `ProxyProtocol`: `http-connect`, `socks5-connect`

Define:

```go
type DoHEndpoint struct {
    ServerName string
    Bootstrap  []netip.Addr
    Path       string
}

type Probe struct {
    Protocol ProxyProtocol
    Host     string
    Port     uint16
}

type PolicyManifest struct {
    EgressBackend                  EgressBackend
    IPFamily                       IPFamily
    BrokerIPv6Posture              BrokerIPv6Posture
    AllowedConnectPorts            []uint16
    EnabledProtocols               []ProxyProtocol
    DoHBootstrap                   []DoHEndpoint
    DynamicDeny                    []netip.Prefix
    DockerHost                     []netip.Addr
    JobOpenCap                     uint64
    JobDialRate                    uint64
    JobDialBurst                   uint64
    DoHOpenCap                     uint64
    DoHDialRate                    uint64
    DoHDialBurst                   uint64
    TailTimeoutSeconds             uint64
    ConntrackEntriesPerActualDial  uint64
    HostReserveEntries             uint64
    PositiveProbes                 []Probe
    NegativeProbes                 []Probe
}
```

`Compile` rejects every zero/incomplete field, duplicate or unsorted
set-like input, unavailable backend, family/posture mismatch, non-public DoH
bootstrap, empty probe set, and any probe outside the compiled port/protocol
set. It normalizes to sorted immutable slices, emits a versioned decision graph
with no defaults, and hashes canonical length-prefixed binary encoding. The
digest is computed internally and covers every field.

### Address and name normalization

Use `net/netip` plus one bounded legacy-IPv4 parser deliberately coupled by
test vectors to `scripts/_sanitize_normalize.py`:

- decimal/octal/hex components and one-, two-, three-, and four-part inet_aton
  forms use checked 32-bit arithmetic;
- ambiguous numeric-looking input that fails the legacy grammar is rejected as
  an invalid literal, never treated as a hostname;
- fold IPv4-mapped and IPv4-compatible IPv6, 6to4 embedded IPv4, and the
  bitwise-inverted Teredo client IPv4 before classification;
- reject zones, percent escapes in literals, non-canonical bracket use, and
  parser disagreement.

Names use `idna.Lookup.ToASCII`, lower-case ASCII, exactly one removed trailing
dot, label length 1..63, total length <=253, no empty/internal trailing labels,
no control/NUL/userinfo/brackets, and reparse after normalization to reject a
name that becomes a literal.

The single classifier is used by compile-time policy, literal validation, DoH
answers, and dialer revalidation. It denies:

- loopback/this-host;
- RFC1918 and IPv6 ULA;
- link-local and metadata;
- CGNAT;
- unspecified, reserved, documentation, and benchmarking;
- multicast and broadcast;
- every normalized dynamic host/bridge/management prefix/address;
- anything not allowed public unicast by exclusion.

For `public_ipv4_only`, any IPv6 literal or AAAA answer fails the entire
request. For dual stack, all returned records must be public; one denied or
malformed member rejects the entire RRset and no sibling address is dialed.

### Parser and fixed request frame

HTTP parsing is an explicit state machine, not `net/http`:

- bounded total bytes, line bytes, header count, and deadline;
- exact `CONNECT authority HTTP/1.1`;
- exactly one `Host` header whose independently normalized authority equals
  the request target;
- no userinfo, URI scheme, path/query/fragment, obs-fold, duplicate or
  conflicting authority, transfer encoding, content length, proxy auth,
  control/NUL, unsupported port, or bytes after the header terminator;
- absolute-form plaintext HTTP and every other method are rejected.

The no-trailing-bytes rule is not weakened for speculative compatibility.
A Linux/Docker canary must capture the real GitHub runner CONNECT handshake and
prove it waits for the broker's `200` response before sending the TLS
ClientHello. A client that pipelines tunnel bytes is recorded as unsupported;
source tests cannot infer compatibility from customary client behavior.

SOCKS5 is accepted only when explicitly enabled: no-auth greeting, CONNECT
only, domain/IPv4/IPv6 address forms only, one request, exact EOF at each
message boundary, no BIND/UDP, and the same normalization/port policy.

The parser emits/accepts only a versioned binary frame:

`magic | version | host-kind | port:u16be | host-len:u16be | host-bytes`

with exact EOF, maximum 253 host bytes, no optional fields, and canonical
literal/name encoding. Decoder re-normalizes and rejects noncanonical bytes.
The AF_UNIX decoder uses `ReadMsgUnix`, requires zero ancillary-data bytes and
no `MSG_CTRUNC`, and rejects any control message, including `SCM_RIGHTS`; no
dialer path consumes a caller-supplied descriptor. Fuzz both wire protocols,
the internal frame, and ancillary-data rejection.

### Dialer and DoH

Inject narrow interfaces:

```go
type Resolver interface {
    Resolve(context.Context, string) ([]netip.Addr, error)
}
type LiteralDialer interface {
    DialLiteral(context.Context, netip.Addr, uint16) (net.Conn, error)
}
type DialPermitClient interface {
    Request(context.Context, DialPermitRequest) (Permit, error)
}
```

The broker dialer decodes and independently validates each frame. Names resolve
only through the fixed DoH resolver. It rejects the whole RRset on any bad,
duplicate, family-disallowed, or denied address, then sorts canonical addresses
and tries them serially. Immediately before every literal kernel dial it obtains
one committed job-class permit. The literal dialer receives `netip.Addr` and
`uint16`, formats `tcp4`/`tcp6` with `net.JoinHostPort`, disables fallback, sets
bounded deadlines, and never accepts a hostname.

The DoH transport:

- POSTs bounded `application/dns-message` requests to one fixed path;
- connects only to a configured literal bootstrap IP;
- sets and verifies the configured TLS ServerName using the locked root pool;
- has bounded response size, response count, idle connections, request time,
  and connection lifetime;
- obtains a DoH-class permit before each new bootstrap connection;
- disables environment proxy, system resolver, redirects, compression
  ambiguity, and automatic Happy Eyeballs;
- validates DNS ID/question/type, response code, record count, TTL bounds, and
  every A/AAAA answer before returning an immutable slice.

Trust-lock validation binds schema version, source URL/revision, SHA-256,
license/SPDX, copied image path, generated-context path, and SBOM path. The
bundle itself is a generated ignored build-context input, fetched/checksummed
by a fail-closed script; it is not silently taken from the host trust store.
Unit TLS tests use generated test CAs for valid, expired, wrong-name, missing,
and untrusted cases without external networking.

### Conntrack arithmetic

`Budget` contains the target-read `nf_conntrack_max`, current count, and
observed timeout identity. `Compute(manifest, maxRunnerCapacity)` performs only
checked uint64 operations:

`factor * (2*openCap + burst + ceil(rate*tailSeconds))`

for job and DoH classes separately, then checked sum per runner, checked
capacity multiplication, and checked host reserve. Reject zero values,
overflow, current count above max, reserve >= max, or total above remaining
capacity. The result records every input and canonical digest. A re-read with
changed max/count/timeout is a new proof and cannot reuse the prior result.

### Durable permits

Define a controller-owned monotonic clock returning `(bootID, monotonicNanos)`;
the boot ID is not accepted from clients. On Linux, the production clock reads
the kernel boot UUID from `/proc/sys/kernel/random/boot_id` and time from
`CLOCK_BOOTTIME`. Both values survive controller-process restart within one
machine boot. Each observation re-reads and validates the same boot UUID;
missing/malformed proc state, an unsupported clock, changed UUID, arithmetic
overflow, or a lower same-boot reading fails closed. Non-Linux production
construction is unavailable; pure tests inject a fake clock.

Define a storage interface with compare-and-swap load/reserve/rebase operations
and a production SQLite implementation over the existing `network_ledgers`
table. Persist one versioned canonical state object in `state_digest`;
`logical_bytes` is exact; `retained_until` is updated from the trusted clock
projection. SQLite uses the already-open canonical `state.SQLiteStore` (`WAL`,
`synchronous=EXTRA`, single-writer) and one immediate transaction per
reservation block.

Ledger state is keyed only by stable capacity-slot ID and holds boot ID,
revision, active job generation, last accepted request sequence per class,
last monotonic observation, class token/debt state, reserved high-water,
issued high-water, retained-tail deadline, and one-use rebase boot identity.
The assignment never resets the bucket.

`Consume`:

1. validates active slot/job generation and authenticated Unix peer through
   controller-owned injected validators;
2. rejects zero/non-monotonic sequence and class mismatch;
3. reads the trusted clock and rejects same-boot regression;
4. applies checked integer token-bucket refill;
5. when the in-memory reserved block is exhausted, atomically persists a
   bounded next high-water block before issuing anything;
6. advances issued state in memory and returns an opaque monotonic permit ID.

Restart sets issued equal to durable reserved high-water, conservatively
wasting the unfinished block. No failure path decrements either value. A new
boot may rebase exactly once only with an opaque proven-empty conntrack proof
issued by the orchestrator; replay, rollback, or an in-boot regression fails.
Garbage collection requires no live slot/job/dialer reference and elapsed
`T`, and remains bounded by the already-approved history limits.

The client frame is fixed canonical binary and contains exactly:
`version, slot ID, job generation, class, sequence`. Tests scan the source and
wire bytes to prove there is no time/refill field.

### Host-runtime and orchestration

Extend `hostruntime.Engine` with opaque `BrokerHandle` and:

- `CreateNetworkBrokerHeld(ctx, BrokerSpec) (BrokerHandle, error)`
- `ApplyNetworkPolicy(ctx, BrokerHandle, PolicyArtifact) error`
- `BindDialAuthority(ctx, BrokerHandle, AuthorityProof) error`
- `ReleaseNetworkBroker(ctx, BrokerHandle) (BrokerPeerProof, error)`
- `AuditNetworkBroker(ctx, BrokerHandle) (BrokerAudit, error)`
- `RemoveNetworkBroker(ctx, BrokerHandle) error`

`BrokerHandle` represents exactly one held broker container and one persisted
container ID. Its initial dialer/supervisor PID is the namespace owner and the
only held process. It opens no listener, resolver, control, or upstream socket
before release.

The one-use release operation targets that same inspected PID and generation.
Only after release does it create fixed AF_UNIX control descriptors and
fork/exec the parser child. The parser's first executable action, before reading
any untrusted byte or opening the relay listener, is:

1. set `PR_SET_NO_NEW_PRIVS`;
2. install a versioned seccomp-BPF filter with `SECCOMP_SET_MODE_FILTER` and
   mandatory `SECCOMP_FILTER_FLAG_TSYNC`, rejecting a kernel that cannot apply
   it to every existing Go runtime thread;
3. prove the filter on the installing thread and on newly scheduled locked OS
   threads by denied `socket(AF_INET, ...)` and `socket(AF_INET6, ...)`
   self-probes;
4. return a fixed readiness record over its one explicitly inherited AF_UNIX
   control descriptor.

The filter allows the exact AF_UNIX operations needed for the relay/control
path but denies AF_INET/AF_INET6 `socket` and `socketpair` creation, raw/packet
sockets, namespace-changing syscalls, BPF, and filter replacement. The parent
creates no routable descriptor before the child filter/readiness proof, and the
child inherits no network descriptor. The parent remains the sole process
allowed to create DoH/upstream sockets.

Descriptor inheritance is exact rather than implicit: the parent creates
AF_UNIX socketpairs with `SOCK_CLOEXEC`; only the one child control endpoint is
passed through `exec.Cmd.ExtraFiles`, which duplicates it to a fixed child fd
with close-on-exec cleared for that exec. The parent closes its child copy
immediately, and every other descriptor remains close-on-exec. The parser
readiness record identifies that fixed fd and proves no unexpected descriptor
is open.

The process-wide denial test runs the parser test mode as a subprocess so the
test runner is not permanently sandboxed. After TSYNC installation it
enumerates the existing Linux task set, starts additional `runtime.LockOSThread`
workers, and requires every worker's AF_INET and AF_INET6 socket attempt to
return the configured seccomp denial. Failure to synchronize any existing
thread, create the fresh-thread proof set, or observe exact denial is terminal.

`ReleaseNetworkBroker` proves the unchanged namespace-owner PID, one release
generation, exact child parentage/cgroup/container membership, parser
PID/start-time, control socket, relay socket, and filter-readiness record. The
returned frozen `BrokerPeerProof` binds the parser child and relay socket for
Task 5's adapter check. A separate opaque `BrokerAudit` binds that proof to the
same container ID, namespace-owner PID, one-use release generation, parser
child, dialer-control socket, authority socket, and process inventory. Final
audit re-inspects both processes and the relationship; the adapter proof is
never treated as the sole broker-release evidence.

This preserves the canonical single held namespace owner, single container ID,
single release event, and existing crash-reconciliation schema while providing
per-process syscall separation. Any partial release, child/filter/readiness
failure, PID replacement, unexpected third process, or socket mismatch removes
the one container and both per-job directories.

All Docker argv are closed constructors: digest-pinned images, exact labels,
no restart, cap-drop ALL except the one-shot helper with NET_ADMIN only,
read-only roots, bounded tmpfs/log/CPU/memory/PID/FD limits, exact mount
visibility, no Docker socket/device/host namespace, and no environment except
the helper's exact `XTABLES_LOCKFILE`. Inspect readback requires byte-for-byte
identity and one-use state; record maps are bounded and removal is ordered.

`networkjail.Orchestrator` is a pure state machine over typed engine actions.
It persists and verifies this exact order:

adapter created -> adapter empty -> logical broker held -> helper applied and
gone -> policy checkpoint -> authority started/verified -> authority checkpoint
-> broker released once -> broker-release checkpoint -> adapter peer bound ->
positive/negative verifier -> egress checkpoint -> held runner attached ->
final audit -> readiness digest armed -> listener released.

It exposes no arm/release authority before the final audit. Every error,
cancellation, timeout, duplicate call, missing checkpoint, identity mismatch,
or ambiguous Docker result invokes cleanup in reverse ownership order and
returns a closed reason.

The implemented verifier boundary is deliberately split. A capability-less,
non-root, one-shot verifier emits only canonical `ProxyProbeReport` bytes from
the adapter namespace. `hostruntime.Engine` then obtains the broker namespace
identity separately, revalidates the parser seccomp-readiness record, and
returns opaque `AdapterEmptinessEvidence` and `NetworkEgressEvidence`.
`Orchestrator` combines those values with a freshly computed checked
`ConntrackBudget`, broker audit, held-runner audit, exact graph/policy bytes,
and build/generation identity to create the full final `ProbeReport`. The
one-shot verifier name carries 128 bits of an engine-issued nonce; success
requires an exact post-run absence proof, and an ambiguous lingering verifier
is removed under a cancellation-independent bounded cleanup context before
the operation returns failure.

The production Unix constructor accepts only the real host engine, lifecycle
journal, and Unix dial-authority manager. Its verifier adapter carries the
closed `VerifierSpec` through both pre-broker emptiness and post-release
positive/negative verification. No public constructor accepts a caller-made
host evidence value, report digest, Docker ID, or raw command fragment.

### Images and Linux/QTS boundary

- Add scratch images for helper, verifier, parser, and dialer, deny-all
  `.dockerignore` files, generated build-context scripts, and register them in
  `images/manifest.json`.
- The runtime dialer image contains the static dialer/supervisor and parser
  binaries plus the locked CA bundle. The separate parser scratch image
  contains only the parser binary and is used for independent filter and
  source/target conformance tests; it is not a second runtime broker container.
  Verifier contains its static binary plus the identical CA bundle.
- The helper uses a digest-pinned Debian build stage and a scratch final stage
  containing exact legacy restore/save binaries, loader/library closure,
  `libxtables`, and complete extension directory. A canonical manifest/SBOM
  fixture enumerates paths/digests/licenses. Missing/extra path tests fail.
- Helper runtime has only NET_ADMIN, exact
  `XTABLES_LOCKFILE=/run/xtables.lock`, and one
  `rw,noexec,nosuid,nodev,size=64k,mode=0700` `/run` tmpfs.
- Linux-tagged tests verify seccomp/socket denial, peer credentials, legacy
  restore/readback grammar, namespace identity, routes/tables/conntrack, and
  Docker isolation. They emit an explicit unsupported-host skip on Darwin and
  never claim target conformance.
- CI and release must prepare both Task 5 and Task 6 ignored contexts before
  the single manifest-driven reproducibility build; registering an image
  without preparing its locked context is a hard workflow failure.

## TDD and verification sequence

1. RED: policy/range/name/parser/internal-frame/budget/trust-lock tests and fuzz
   seed corpus. Implement until pure package tests pass.
2. RED: permit frames, fake clock, fake durable store, block reservation,
   crash waste, slot reuse, clock rollback, boot rebase, GC, concurrent
   sequence, and no-refund tests. Implement authority/client/SQLite adapter.
3. RED: dialer revalidation, mixed RRset, resolve-then-literal-dial,
   permit-before-each-attempt, DoH permit/TLS/size tests, FD/deadline tests.
4. RED: host-runtime exact argv/readback, opaque handle, one-use release,
   partial-effect cleanup, and bounded-record tests. Implement broker methods.
5. RED: orchestration order/fault injection at every edge, no arm-before-audit,
   kill/corrupt/rebind/restart/hidden-fallback tests. Implement orchestrator.
6. RED: image context, lock/SBOM/closure, seccomp, workflow, and Linux-tagged
   conformance harness tests. Implement commands/images/scripts.
7. Run Go unit/race/vet/staticcheck/govulncheck, count-heavy networkjail tests,
   bounded fuzz runs, shell/metadata/sanitization gates, exact-artifact
   distinct-family review, and signed commit
   `feat: gate listeners on bounded broker egress`.

Docker image reproducibility and QTS target conformance remain explicitly
pending until an approved Linux+Docker environment runs them. No source-only
result can create `TargetConformance` or `DeploymentEligibility`.

## Adversarial review questions

1. Does the revised single-container, one-held-PID design plus parser
   self-seccomp satisfy “same held broker released exactly once” and preserve
   genuinely disjoint socket authority without an inherited-descriptor escape?
2. Is the durable block/high-water design conservative across crash, slot
   reuse, capacity reduction, monotonic rollback, and new-boot empty-conntrack
   rebase?
3. Which parser/name/literal/DoH ambiguity or request-smuggling class remains
   unsealed?
4. Can any path reach a kernel dial without an already-committed class-correct
   permit?
5. Can any source-only or mocked proof be confused with Linux/QTS target
   conformance?

Return `PROCEED` only if there is no material design gap. Otherwise return
`REVISE` with specific load-bearing changes.
