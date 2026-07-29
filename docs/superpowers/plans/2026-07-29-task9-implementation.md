# Task 9 Implementation Plan: Host Profiles and Exclusive Fleet Fence

> Status: source design only. This plan authorizes no Docker, QTS, RhoNAS,
> systemd, launchd, routing, deployment, service, selector, or host-
> configuration mutation. All numeric sizing selections remain deferred to a
> separate operator sign-off. Tests use synthetic values, including the
> incident anchors, solely to prove rejection and checked arithmetic.

**Goal:** Add fail-closed host-profile qualification and one host-local
portable/legacy generation authority without allowing unsupported hosts,
unapproved resource envelopes, malformed private state, stale processes, or
two fleet generations to acquire work concurrently.

**Architecture:** The existing `hostruntime.HostProfile` string remains the
closed runner-profile identifier. A new `hostruntime.Profile` behavior
interface is implemented by QTS and standard-Linux profiles and produces
typed, secret-free conformance and network-discovery evidence from injected
fixed-command sources. Shared validators prove the complete memory/tmpfs,
conntrack, storage, log-retention, platform, and isolation contracts with
checked arithmetic and no production defaults. Separately, `fleetfence.Store`
holds shared/exclusive `flock` authority on one stable never-renamed inode,
stores its monotonic header in a distinct canonical atomic file, and stores
one independently renewed canonical holder record per exact process identity.
Only a current `portable` shared guard satisfies
`controller.FleetGuardProvider`. The legacy wrapper and the fence CLI use the
same store. An exclusive handoff waits for every shared guard, increments once,
atomically publishes the new generation, and removes only obsolete holder
records while still holding the exclusive lock.

**Tech stack:** Go 1.26.0 with toolchain 1.26.5,
`golang.org/x/sys/unix`, strict canonical JSON, mode-checked private files,
POSIX advisory locks on Darwin/Linux, table-driven/race tests, and Bats shell
tests. Target QTS conformance remains a later positive Linux gate.

Task 9's planned source boundary includes the named hostruntime/fleetfence/CLI
files plus the narrow `internal/controller` pressure-provider seam required to
make recurring profile observations enforce capacity before another poll and
before each published health cycle.

## Existing-Source Corrections

### Preserve the closed profile ID

`internal/hostruntime/engine.go` already defines:

```go
type HostProfile string
```

and existing container specifications persist that exact type. Replacing it
with a behavior interface would break the Task 5/6 public contract and stored
runner identity. Task 9 therefore adds:

```go
type Profile interface {
	ID() HostProfile
	Probe(context.Context) (ConformanceReport, error)
	DiscoverNetworks(context.Context) (NetworkSnapshot, error)
}
```

`qts.Profile` and `systemd.Profile` implement this interface. This is the only
safe way to realize the plan's conceptual `HostProfile.Probe` surface without
renaming or widening the already-fixed `HostProfile` identifier.

### Do not pretend the complete production controller exists

Task 8 intentionally left `OpenController` unavailable because the public
runtime document does not yet contain the complete lifecycle, session,
admission, health, host-profile, and private-manifest composition graph. Task
9 supplies a real `fleetfence.ControllerAdapter` and a production factory that
can construct that one authority from an explicit fence root/generation. It
does not invent the missing Task 10 manifest or turn `run` into a partial
controller. Task 10 will consume the factory while building the complete
disabled-observer composition. The remote Worker permit provider remains
independently unavailable.

### Separate source qualification from target conformance

Task 9 validates exact typed observations and implements fixed-command
discovery parsers. It does not claim that macOS source tests prove a QTS
kernel, Docker daemon, namespace, seccomp profile, filesystem, or conntrack
table. `Probe` rejects Darwin. Synthetic Linux observations prove the
fail-closed decision logic; Task 11 supplies the actual target evidence.

## Threat Model and Required Invariants

The implementation must resist:

1. symlink, hard-link, type, mode, owner, size, trailing-data, unknown-field,
   noncanonical, partial-write, and rename races in fence state;
2. renaming or replacing the lock inode so old and new processes lock
   different objects;
3. same-PID reuse across process starts or boots;
4. replay of an old header, holder record, operation ID, expected generation,
   or active fleet;
5. a handoff returning before every prior shared guard closes;
6. a crash after lock acquisition, header publication, or holder retirement
   causing a second generation increment;
7. one same-fleet holder failure deleting or invalidating another holder;
8. a failed renewal leaving a child process running with stale authority;
9. a read-only inspect path creating, repairing, cleaning, or otherwise
   mutating state;
10. a legacy-owned host starting any nonzero Portable poll, acquire, JIT,
    listener, or watchdog path, or starting even a dark observer without the
    exact new disabled/empty/zero epoch proof;
11. a host profile accepting Darwin, an unsupported architecture/kernel/
    runtime, absent cgroup/resource enforcement, an unqualified root profile,
    incomplete network discovery, or the unavailable direct-nftables backend;
12. integer overflow or double-counting in memory, conntrack, storage, inode,
    slot, log, and concurrency calculations;
13. counting swap as RAM capacity, counting tmpfs again outside its enclosing
    cgroup, or allowing a tmpfs sub-limit larger than the cgroup that charges
    it;
14. treating the 666 MiB idle or 2,162 MiB measured high-water as a production
    size selection rather than incident evidence requiring an operator margin;
15. aggregating filesystem reserves by path rather than stable filesystem
    identity, or failing to deduplicate shared filesystems before comparison;
16. warning/stop pressure, conntrack timeout/count/max drift, or storage drift
    being observed without reducing capacity or safe-stopping before another
    acquisition;
17. raw command output, private paths, network coordinates, or deployment
    identities entering health or public diagnostics; and
18. conflating the host-local guard with the separately required Worker
    outbound permit.

## Public Host-Profile Contracts

Add to `internal/hostruntime/profile.go`:

```go
type Profile interface {
	ID() HostProfile
	Probe(context.Context) (ConformanceReport, error)
	DiscoverNetworks(context.Context) (NetworkSnapshot, error)
}

type ProfileState string

const (
	ProfileNormal   ProfileState = "normal"
	ProfileDegraded ProfileState = "degraded"
	ProfileWarning  ProfileState = "warning"
	ProfileStop     ProfileState = "stop"
)

type ConformanceReport struct {
	ProfileID             HostProfile
	State                 ProfileState
	Degraded              bool
	EgressBackend         string
	Architecture          string
	KernelRelease         string
	RuntimeVersion        string
	EffectiveCapacity     uint32
	MemorySizingDigest    string
	ConntrackSizingDigest string
	StorageSizingDigest   string
	EvidenceDigest        string
}

type NetworkSnapshot struct {
	ProfileID          HostProfile
	RunnerNetworkMode  string
	BrokerNetworkID    string
	BrokerIPv6Enabled  bool
	RunnerLoopbackOnly bool
	RoutesComplete     bool
	EvidenceDigest     string
}
```

All reports use canonical SHA-256 digests over validated typed inputs.
`ConformanceReport` contains no filesystem path, Docker ID, interface name,
route, repository, scale-set, job, runner, socket, or command output. Full
typed observations remain inside the trusted profile object.

`SelectProfile(ctx, explicit, candidates)` has these rules:

- an explicit profile selects exactly one matching candidate and never falls
  back if its probe fails;
- automatic selection tries the caller-provided deterministic candidate order,
  but every automatic candidate must be non-degraded;
- `qts-capless-root` is never selected automatically. It is eligible only when
  the private profile explicitly names `qts-capless-root`, explicitly allows
  degraded execution, and its probe positively proves every degraded
  requirement;
- unsupported platform, malformed evidence, unsafe private state, backend
  mismatch, and sizing failure stop selection rather than causing fallback;
- candidate IDs are unique and limited to the closed existing identifiers; and
- successful discovery is required before a candidate can be selected.

## Joint Memory/Tmpfs/Concurrency Sizing

Define one no-default `RunnerSizingTuple` with:

- an explicit `OperatorApproved` bit;
- `/runner`, `/tmp`, and `/scratch` tmpfs sub-limits;
- measured p99 and explicit margin for each sub-limit;
- measured whole-runner memory-cgroup p99;
- process margin;
- runner memory limit;
- explicitly configured swap limit, where zero is valid but omission is not;
- maximum active concurrency;
- per-slot auxiliary memory;
- idle control-plane memory;
- candidate-build-and-smoke peak;
- host-and-gateway reserve;
- usable host memory;
- measured idle `/runner` use;
- release/reclamation observation cadence; and
- a stable evidence revision.

Validation is checked and exact:

```text
runnerP99 + runnerMargin <= runnerTmpfs
tmpP99 + tmpMargin <= tmpTmpfs
scratchP99 + scratchMargin <= scratchTmpfs
runnerCgroupP99 + processMargin <= runnerMemory
runnerTmpfs + tmpTmpfs + scratchTmpfs + processMargin <= runnerMemory
maxActive * runnerMemory
  + maxActive * auxiliarySlotMemory
  + idleControlPlane
  + candidateBuildAndSmokePeak
  + hostAndGatewayReserve
  <= usableHostMemory
```

Swap is never added to `usableHostMemory`. Tmpfs is counted only inside
`runnerMemory`, so it is not added again in the host equation. Every add and
multiply uses checked unsigned arithmetic. A nonzero concurrency and cadence
are required. Idle use must not exceed measured p99; each p99/margin pair is
required. No value is defaulted.

Tests include:

- 666 MiB idle and 2,162 MiB `/runner` p99 as incident anchors;
- rejection when 2,162 MiB whole-cgroup p99 plus process margin exceeds the
  runner memory cgroup, independently of all tmpfs sub-limit equations;
- rejection of a 2 GiB cgroup with a 3 GiB `/runner` tmpfs;
- rejection of six large slots whose total exceeds a synthetic 32 GiB host;
- overflow at every add/multiply boundary;
- a valid synthetic tuple with explicit headroom; and
- proof that changing swap alone cannot turn an invalid RAM equation valid.

These fixtures do not choose production tmpfs, cgroup, concurrency, or
cadence values.

## Conntrack and Egress Qualification

`ConntrackSizing` carries no defaults and requires:

- current `nf_conntrack_count` and `nf_conntrack_max`;
- nonzero host reserve strictly below max;
- maximum runner capacity;
- measured entries per actual job-class and DoH-class dial;
- configured per-class budgets at least as large as the measurements;
- the exact timeout vector read from the target;
- the current durable dial-token-state revision and consumption proof;
- an evidence revision; and
- the qualified egress backend.

Validate:

```text
perSlot = jobClassBudget + dohClassBudget
configured = maxRunnerCapacity * perSlot
configured <= nf_conntrack_max - hostReserveEntries
```

The current count must not exceed max. Effective capacity is the minimum of
the approved maximum and the checked residual headroom after current count and
host reserve. Timeout/count/max drift changes the canonical digest and
recomputes capacity. A zero residual yields `ProfileStop`; a smaller residual
yields `ProfileWarning`. Only `restricted-broker-v1` is accepted.
`nftables-direct-v1` fails closed.

## Storage and Log-Pressure Qualification

Define exact closed roles:

```text
docker-root
state
staging
rollback
scratch
logs
```

Each role binds to one stable filesystem identity. Observations provide free
bytes/inodes per identity; requirements provide these named simultaneous
vectors:

- current immutable release;
- candidate immutable release;
- temporary extraction/build;
- verified rollback reserve;
- complete configured slot vector multiplied by maximum active concurrency;
- serialized helper/verifier transient peak;
- relay and dial-authority directories;
- controller state;
- retained ledgers through `T`;
- bounded controller/watchdog/Docker logs; and
- host safety reserve.

Requirements map to roles explicitly. Shared filesystem identities are
deduplicated after checked summation; paths are never used as identity.
Warning and stop reserves are nonzero and ordered. A write is permitted only
when every deduplicated filesystem remains above its stop reserve after the
complete simultaneous requirement. Warning produces reduced capacity;
crossing stop produces zero. Inode and byte checks are independent. Log byte
and file-count caps are both mandatory; an unbounded log vector is invalid.

Task 9 exposes the typed pressure result. Controller/watchdog integration must
call the existing acquisition epoch barrier before later tasks can act on a
reduction. No Task 9 test claims that observing pressure alone changed a live
host.

## Recurring Host-Pressure Enforcement

Add a narrow controller-owned port:

```go
type HostCapacityState uint8

const (
	HostCapacityNormal HostCapacityState = iota + 1
	HostCapacityWarning
	HostCapacityStop
)

type HostCapacityReport struct {
	State             HostCapacityState
	EffectiveCapacity int
	EvidenceDigest    string
	ObservedAt        time.Time
}

type HostCapacityProvider interface {
	Evaluate(context.Context) (HostCapacityReport, error)
}
```

The selected profile is adapted to this port without exposing its raw typed
observations. `ServiceConfig` requires the provider. `EvaluateHostPressure`
validates the closed report, requires a current observation and lowercase
SHA-256 digest, and may only retain or lower the current policy capacity:

- provider error, invalid report, stale evidence, or `HostCapacityStop`
  persists zero through the existing epoch barrier before returning failure;
- warning clamps to the smaller of the report capacity and current capacity;
- normal never raises capacity automatically; recovery requires an explicit
  operator policy transition after a sustained healthy window; and
- any transition/revocation failure is fatal/closed exactly like the existing
  history-pressure path.

Call this evaluation:

1. at the start of every `PollOnce`, before `beginCritical`, broker lease,
   upstream poll, or acquisition;
2. before every externally invoked `AdmitOnce`;
3. before every externally invoked `ReconcileOnce`, before lifecycle effects
   and the resulting heartbeat; and
4. through private `pollOnceAfterHostPressure`,
   `admitOnceAfterHostPressure`, and `reconcileOnceAfterHostPressure` helpers
   so the central loop performs one evaluation before admission and
   reconciliation without duplicating it while retaining every public method's
   guarantee.

Thus count/max/timeouts, durable token state, storage, inode, and log facts are
reread before another poll/acquisition and on every successful health cycle.
The source never raises capacity merely because a later observation improves.
`EvaluateHostPressure` is never called while its caller owns an acquisition
critical section; therefore its use of the epoch barrier cannot self-deadlock.

## QTS Profile

`internal/hostruntime/qts/profile.go` implements `hostruntime.Profile` from an
injected `Source`. The source has closed methods that return typed
observations; it never exposes a generic shell command or arbitrary argv.
`discovery.go` implements fixed-command parsers for the target adapter and is
bounded by context deadlines and maximum output sizes.

The QTS profile accepts only Linux and the configured closed architecture,
kernel, Docker version, cgroup/resource-enforcement facts, and
`restricted-broker-v1`. Its positive evidence must bind:

- runner network mode `none`;
- empty runner iptables-table and conntrack observations before and after a
  bounded loopback flood;
- namespace, raw-socket, BPF, `unshare`, `setns`, and `clone3` denial;
- held broker socket count zero before one-use release;
- exact legacy-filter restore/read-back before release;
- configured IPv6 posture;
- relay and dial-authority mount identities and read/write modes;
- fixed DoH/bootstrap/port/TLS-root policy digest;
- durable consume-before-dial proof;
- measured conntrack entries per actual dial;
- CPU, memory, PID, FD, tmpfs, read-only-root, seccomp, and capability
  enforcement;
- whole-container work-area reclamation capability;
- bounded log retention; and
- the validated memory, conntrack, and storage tuples.

`HostProfileStrictLinux` requires the configured nonroot identity.
`HostProfileQTSCaplessRoot` is accepted only when:

- the private profile explicitly selects that exact named profile;
- the private profile explicitly allows degraded execution;
- UID is zero;
- effective, permitted, inheritable, bounding, and ambient capability sets are
  all positively empty; and
- the report is visibly degraded.

Strict-profile failure never falls back automatically to root.
Any missing fact, stale evidence revision, command truncation, noncanonical
parse, or incomplete network snapshot fails closed.

## Standard-Linux Profile

`internal/hostruntime/systemd/profile.go` uses the same common validators but
accepts only `HostProfileStrictLinux`. It rejects QTS-specific degraded root,
requires standard cgroup/resource enforcement and the configured systemd/
Docker/kernel versions, and requires the same restricted-broker, sizing,
storage, log, and network-isolation evidence. Its discovery source is fixed and
typed. Darwin and unsupported architectures fail before any target command.

## Fleet-Fence State and Filesystem Contract

`internal/fleetfence/store.go` defines:

```go
type Fleet string

const (
	FleetNone     Fleet = "none"
	FleetPortable Fleet = "portable"
	FleetLegacy   Fleet = "legacy"
)

type Header struct {
	Version     uint32
	Generation  uint64
	ActiveFleet Fleet
	BootID      string
	RootDevice  uint64
	RootInode   uint64
	LockDevice  uint64
	LockInode   uint64
	HolderDevice uint64
	HolderInode  uint64
	UpdatedAt   time.Time
	OperationID string
}

type HolderIdentity struct {
	Generation uint64
	Fleet      Fleet
	OwnerID    string
	PID        int
	BootID     string
}

type Guard interface {
	controller.AcquisitionGuard
	Renew(context.Context) error
	Failure() <-chan error
	Header() Header
}

type Store struct { ... }
```

The root is an explicit absolute clean private path supplied by the later
private manifest. It must already exist, be a non-symlink directory owned by
the effective user, and have mode `0700`. Construction opens it once with
`O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, validates it by `fstat`, retains that
directory descriptor for the store lifetime, and performs every later
operation relative to it. The store never repairs or reopens it by path.

State layout:

```text
ROOT/
  fleet.lock           stable regular inode, mode 0600, never renamed
  fleet.json           canonical atomic header, mode 0600
  holders/             mode 0700
    HOLDER_SHA256.json canonical atomic per-holder record, mode 0600
```

All opens reject symlinks; regular files must have one link, expected owner,
exact mode, bounded size, canonical JSON plus one newline, known fields, and
no trailing bytes. Holder filenames are the lowercase SHA-256 of a
domain-separated canonical identity, never a raw owner/PID/boot string.

`store_unix.go` uses `openat`, `fstatat`, `renameat`, and `unlinkat` relative
to the retained root and holder directory descriptors. It never resolves the
root or holder directory path again. It opens the stable lock with
`O_NOFOLLOW|O_CLOEXEC`, verifies it by `fstat`, and uses nonblocking `flock`
with bounded context-aware polling. The holder directory is likewise opened
once relative to the retained root descriptor, verified, and retained. Darwin
and Linux are supported. Other platforms compile a fail-closed stub. Atomic
header/holder writes use a same-directory unique temporary regular file,
`fsync`, `renameat`, and directory-descriptor `fsync`. The lock inode itself is
never replaced or truncated.

The lock has a single bootstrap rule. Only the initial
`{from:none, expectedGeneration:0}` handoff may create `fleet.lock`, using
`openat(O_CREAT|O_EXCL|O_NOFOLLOW)` against the retained root descriptor.
That same bootstrap may `mkdirat` the missing `holders` directory with mode
`0700`, then open/fstat it relative to the retained root; every other operation
requires it already exist. Concurrent bootstraps converge by reopening and
verifying the winner's inode. Acquire and Inspect never create a missing lock
or holder directory. The first header seals the exact root, lock, and holder-
directory `(st_dev,st_ino)` identities. Every later Acquire, Handoff, and
Inspect requires the retained root plus freshly `fstat`ed lock and holder
directory to match those sealed identities. An unlink/recreate, alternate-
root, copied-header, split-lock, or split-holder-directory attempt therefore
fails closed.

## Guard Acquisition, Renewal, and Close

`Acquire(ctx, request)`:

1. validates the exact requested fleet, generation, owner, PID, boot identity,
   and current process identity source;
2. opens and verifies the stable lock;
3. obtains `LOCK_SH` under the caller deadline;
4. reads and validates the header while holding the shared lock;
5. requires exact sealed root/lock/holder identity, generation, and active
   fleet, and validates the new holder against the current boot/process
   identity source;
6. exclusively creates this holder identity without overwriting any record;
7. writes and fsyncs the canonical record; and
8. returns a guard retaining the lock file descriptor.

Same-fleet guards coexist. A duplicate exact holder identity fails rather than
rebinding a record. The current process cannot reset or repair a stale header.
The header's `BootID` records the boot on which the last handoff occurred; it
is not required to equal the current boot, because the active fleet must
survive reboot. New holder records always carry the current boot identity, and
PID/owner reuse is checked against that current identity.

`Renew` retains the same shared lock, rereads the exact holder record and
header, requires unchanged generation/fleet/identity, advances only
`RenewedAt`, and atomically replaces only that holder record. A renewal error is
published once on `Failure()`.

`Close` attempts exact holder deletion plus holder-directory fsync while the
shared lock is still held, then always unlocks and closes the descriptor.
Missing/drifted holder state is an error even though authority is released.
One holder never deletes another.

## Handoff and Crash Idempotency

`Handoff(ctx, request)`:

1. validates closed `from`/`to` values, disallows `from == to`, validates the
   expected generation and deterministic operation ID, and checks increment
   overflow;
2. for the sole initial `{from:none, expectedGeneration:0}` request, creates
   the stable lock exactly once with exclusive-create semantics; every other
   request requires it already exist;
3. opens and verifies that stable lock relative to the retained root
   descriptor and obtains `LOCK_EX` under the caller deadline, thereby waiting
   for every shared guard to close;
4. reads and validates the canonical header plus sealed root/lock/holder
   identity;
5. permits the sole missing-header bootstrap only for
   `{from:none, expectedGeneration:0}`;
6. accepts an exact already-published `{generation:N+1, fleet:to,
   operationID:same}` as idempotent crash recovery;
7. otherwise requires exact `{generation:N, fleet:from}`;
8. publishes `{generation:N+1, fleet:to, currentBootID, sealedRootIdentity,
   sealedLockIdentity, sealedHolderIdentity, now, operationID}` through the
   separate atomic header;
9. removes every old holder record while still holding `LOCK_EX`, validates
   that the holder directory is empty, and fsyncs it; and
10. rereads the header and re-fstats the root/lock/holder descriptors before
    returning `N+1`.

The CLI derives the operation ID deterministically from a domain-separated
canonical `{expectedGeneration,from,to}` tuple, so retrying the exact command
after a crash is idempotent without accepting caller-controlled IDs.
Different operations cannot reuse it.

If a crash occurs after header publication but before holder retirement, the
same request resumes step 9 without incrementing again. An old expected
generation with a different operation ID fails. Generation never decrements.
No stale process may delete or rewrite the header.

`Inspect` takes a shared lock and returns a canonical sorted snapshot. It does
not create a missing lock/header/root/holder directory, clean stale records,
renew a holder, or modify timestamps.

Tests replace the root path, holder path, and lock path after a Store opens;
the open Store must remain bound to its original descriptors and every fresh
Store must fail sealed-identity validation. Tests also unlink and recreate
`fleet.lock` while an old shared guard is held and prove a second process
cannot acquire or hand off on the replacement inode.

## Controller Adapter

`internal/fleetfence/controller_adapter.go` implements only:

```go
var _ controller.FleetGuardProvider = (*ControllerAdapter)(nil)
```

It is configured with the exact expected generation and a trusted current
process identity source. `AcquirePortable` asks the store for a current
`portable` guard and starts bounded renewal for the operation lifetime.
Renewal failure is retained and makes `Close` fail even if the external effect
already returned. The adapter exposes no handoff, legacy, mutation, reset, or
Worker-permit method.

The controller continues to acquire the independent Worker permit after the
host guard and before each outbound effect. Neither authority substitutes for
the other.

## Legacy-Owned Force-Disabled Observer

The sole no-guard exception is explicit and narrow. Add
`NormalizeLegacyObserver(ctx, inspector, transitions)` as a separate function;
do not add handoff or legacy methods to `ControllerAdapter`.

It:

1. read-only inspects and requires one exact current `legacy` header;
2. snapshots the persisted acquisition policy;
3. compare-and-sets a new epoch with mode `disabled`, empty eligibility, and
   `maxCapacity=0`, even when the prior values were already zero;
4. rereads both fence and policy and requires the same legacy generation plus
   the exact new zero epoch; and
5. returns only a typed zero-observer proof for Task 10's launcher.

No loop or listener is started by this function. A Task 10 caller must consume
the proof before launch and prove the same zero state after launch. Under this
exception, `AcquirePortable` continues to fail and no advertisement, poll,
Acquire, JIT, listener release, runner start, or Worker-permit request is
allowed. Any non-cancellable old critical section triggers the existing fatal
termination path instead of returning a proof.

## Fence CLI

`cmd/portable-ghar-fleet-fence` accepts only:

```text
portable-ghar-fleet-fence guard
  --state-dir ABSOLUTE
  --fleet portable|legacy
  --generation N
  -- COMMAND [ARG...]

portable-ghar-fleet-fence inspect
  --state-dir ABSOLUTE
  --json

portable-ghar-fleet-fence handoff
  --state-dir ABSOLUTE
  --from portable|legacy|none
  --to portable|legacy|none
  --expected-generation N
  --json
```

Parsing rejects duplicate, unknown, missing, empty, reordered post-`--`, or
overflowing values. `inspect` is read-only and does not require root in source
tests; mutating/guard commands require the configured privileged execution
context.

`guard` acquires authority before child creation, starts the child without a
shell, passes that exact child a duplicate of the same locked open-file
description, and retains the parent guard until the exact child exits. The
inherited descriptor keeps the shared flock authoritative if the guard parent
is killed before orderly cleanup; only the exact workload's exit releases the
last reference. Forwarded termination and renewal failure both wait a bounded
grace, kill only that child if necessary, reap it, close the guard, and return
failure. Child success cannot hide guard-close or renewal failure.

`handoff` prints only the new generation and active fleet after positive
read-back. It never starts a controller or legacy process.

`deploy/qts/run-legacy-fenced.sh` refuses non-Linux, validates exact arguments,
and `exec`s the fence CLI's `guard --fleet legacy` form around the caller's
already-captured fixed command argv. It performs no `eval`, command-file
parsing, Docker build, retag, service management, or host mutation of its own.

## TDD Sequence

### Phase A: common profile arithmetic and selection

Add failing tests for:

- non-Linux and unsupported architecture/kernel/runtime;
- explicit profile failure without fallback;
- deterministic non-degraded auto selection and rejection of every automatic
  degraded-root candidate;
- explicit named degraded-root selection with private allow plus empty-cap
  proof, and rejection when any one is absent;
- malformed, duplicate, unknown, or incomplete candidates;
- restricted-broker acceptance and direct-nftables rejection;
- all memory inequalities, incident regressions, overflow, and swap exclusion;
- conntrack max/reserve/per-slot arithmetic, drift, warning, and stop;
- storage filesystem deduplication, bytes/inodes, complete simultaneous
  vectors, log bounds, warning/stop, and overflow; and
- secret-free canonical report/digest stability.

Observe RED, then implement `internal/hostruntime/profile.go`.

### Phase B: QTS and systemd profiles

Add fixed-source tests for:

- Darwin rejected before source calls;
- QTS strict success;
- QTS strict nonroot failure stopping without fallback;
- explicitly selected capless-root degraded success;
- rejection when any capability set is nonempty;
- missing runner-none/table/conntrack/loopback/held-broker/filter/mount/DoH/
  durable-consume/IPv6 fact;
- truncated/noncanonical discovery output and incomplete routes;
- systemd strict success and degraded-root rejection; and
- changed count/max/timeout/storage observations recomputing state/capacity.

Observe RED, then implement the two profiles and fixed discovery parsers.

### Phase C: fleet store

Add failing tests for:

- private root, lock/header/holder type, mode, owner, link, symlink, canonical
  encoding, size, unknown-field, and trailing-data rejection;
- missing bootstrap shape and malformed state;
- same-fleet shared guards;
- wrong fleet/generation/boot/process identity;
- duplicate exact holder identity and PID/boot reuse;
- independent renewal and close;
- renewal failure isolation;
- blocked exclusive handoff until all guards close;
- stable lock inode across header replacement and repeated handoffs;
- first-lock exclusive-create races, sealed root/lock device+inode mismatch,
  unlink/recreate split-lock attempts, copied-header attempts, and mid-life
  root/holder directory replacement under retained dirfds;
- stale generation/from/operation rejection;
- exact crash resume after header publication;
- checked generation overflow;
- holder cleanup only under exclusive lock;
- crash-released lock with stale record cleanup;
- read-only inspect causing byte-for-byte no mutation; and
- 1,000 bounded race iterations using a temporary filesystem, including
  holder close versus handoff and killed operations at each injected boundary.

Observe RED, then implement common canonical state plus Darwin/Linux flock.

### Phase D: adapter, CLI, and legacy wrapper

Add failing tests for:

- compile-time `FleetGuardProvider` satisfaction only;
- portable-current success and legacy/stale generation failure;
- independent Worker permit remains required by existing controller tests;
- profile observation failure/stop persisting zero before Poll and before a
  heartbeat, warning only lowering capacity, and normal never auto-raising;
- count/max/timeout/token/storage drift being reread on every poll and
  reconciliation cycle;
- central admission receiving host-pressure enforcement before `AdmitOnce`,
  and no pressure transition being invoked while holding a critical section;
- legacy-owned force-disabled normalization producing a new disabled/empty/
  zero epoch and proof while every nonzero path remains guarded;
- renewal failure propagates through guard close;
- exact CLI grammar and JSON output;
- child never starts without guard;
- guard retained for child lifetime;
- parent crash cannot release the fence while the inherited child remains;
- signal/renewal failure terminates and reaps only the child;
- inspect read-only behavior;
- handoff idempotency; and
- QTS wrapper Linux refusal, no `eval`, exact argument forwarding, and current
  legacy generation enforcement.

Observe RED, then implement the adapter, CLI, production provider factory, and
shell wrapper.

## Verification

During implementation:

```bash
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go test ./internal/hostruntime/... ./internal/fleetfence \
  ./cmd/portable-ghar-fleet-fence -count=1

GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go test -race ./internal/fleetfence -count=100
```

Final local gates:

```bash
GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go test -race ./internal/hostruntime/... ./internal/fleetfence \
  ./cmd/portable-ghar-fleet-fence ./cmd/portable-ghar-controller -count=20

GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go test -race ./... -count=1

GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 go vet ./...

HOME=/private/tmp/portable-ghar-static-home GOPATH=/Users/josumi/go \
  GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool staticcheck ./...

HOME=/private/tmp/portable-ghar-static-home GOPATH=/Users/josumi/go \
  GOCACHE=/private/tmp/portable-ghar-go-cache GOTOOLCHAIN=go1.26.5 \
  go tool govulncheck ./...

bats tests/shell/qts/fleet-fence.bats
python3 scripts/sanitize_public.py --tracked
python3 scripts/check_repository_metadata.py
python3 tests/repository/test_workflow_policy.py
```

Also require `gofmt -l` over changed Go files and `git diff --check`.
The Bats suite uses a temporary local state directory and fake child commands;
it does not run Docker or modify QTS.

### Named target residual: `TASK9-QTS-FS-CONFORMANCE`

Canonical Task 9 is not fully complete until the same 1,000-iteration
shared-guard/exclusive-handoff/crash/rename/fsync suite passes on the selected
QTS state volume and positively proves stable lock identity and no dual-fleet
observation. The source tree will include an opt-in target harness whose root
must be supplied explicitly by the later private manifest. It refuses Darwin,
an unqualified profile, a nonempty production state directory, or a missing
operator test authorization.

This turn may create the reviewed signed source commit and later source tasks
may build against it, but the ledger status remains
`source-implemented / TASK9-QTS-FS-CONFORMANCE pending`. Neither local temp
filesystem races nor a clean commit may be reported as full Task 9 completion.
Task 11/13 owns execution and evidence capture for the residual. Actual QTS
filesystem, namespace, conntrack, and host configuration remain untouched
until separate operator authorization.

## Review and Commit Gate

Before code:

1. Seal this exact plan by byte count and SHA-256.
2. Send it to direct xAI/Grok as the distinct-family correctness and
   adversarial reviewer.
3. Integrate every material finding and reseal/re-review if a load-bearing
   decision changes. Stop after two substantive cycles and surface any
   unresolved disagreement.

After local source GREEN:

1. Seal the exact base-to-head artifact and obtain substantive xAI/Grok
   exact-diff review.
2. Address every material finding and re-review a changed artifact.
3. Re-run all focused/full gates and public leak scans.
4. Stage only the reviewed Task 9 paths.
5. Create one signed commit:

```text
feat: fence portable and legacy fleet generations
```

The commit records source convergence only; it does not clear
`TASK9-QTS-FS-CONFORMANCE`.

No push, PR, merge, release, deployment, Docker execution, QTS access, service
restart, routing mutation, or host configuration change is authorized by this
plan.
