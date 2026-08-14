# Portable GHAR Controller Runtime Implementation Plan

<!-- markdownlint-disable MD010 MD013 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Phase 3 authority amendment:** This completed Phase 2 plan remains the
history and contract for the local epoch barrier, host fence, lifecycle, and
`AcquisitionPermitProvider` interface. For future external authority,
platform-design §9 and `2026-07-11-failover-deployment.md` supersede any remote
per-operation permit or separate legacy-process-lease wording: the local
interface derives its proof from one cached signed heartbeat lease. The same
authority plan also supersedes ordinary monotonic deadline wording: one injected
authority clock drives send anchors, comparisons, and absolute waits; its
Linux/QTS implementation is `CLOCK_BOOTTIME`, and missing target proof keeps
acquisition disabled.

**Goal:** Build the fail-closed Go controller runtime that fairly acquires GitHub Actions scale-set work, launches exactly one isolated runner per acquired slot, proves its per-job egress jail before listener release, reconciles crashes idempotently, and runs safely under QTS or standard Linux supervision.

**Architecture:** A pinned `actions/scaleset` adapter translates preview API types into internal offers, statistics, and runner references; upstream types never cross the adapter. SQLite journals assignment transitions and external-effect intent, a weighted/aging broker leases capacity before it is advertised, and a reconciler drives each assignment through the approved state machine. On the QTS reference profile, a capless adapter sidecar owns an otherwise empty `--network none` namespace shared only with the held runner and relays loopback proxy bytes through a per-job Unix socket to a separately jailed, dial-bounded broker. Only the broker dialer creates real network sockets, and it is a separate process from the socket-less broker parser that reads untrusted CONNECT bytes. A modern Linux direct backend remains optional only after exact pre-conntrack enforcement is positively proven. The listener is released through the digest-armed gate over a runner-private tmpfs socket, and every per-job component is destroyed after one job.

**Tech Stack:** Go language level 1.26.0 with toolchain 1.26.6; `github.com/actions/scaleset v0.4.0`; `modernc.org/sqlite v1.53.0`; `github.com/google/nftables v0.3.0`; Docker Engine CLI; a restricted CONNECT broker/loopback relay profile with a pinned iptables-legacy helper for the trusted broker namespace; an optional exact-qualified nftables direct profile; POSIX shell plus Bats for QTS installation tests; Go unit, contract, fuzz, integration, conformance, race, and chaos tests.

## 2026-07-22 Runner Self-Update Incident Amendment

This amendment incorporates the merged RhoNAS runner-overhaul design as an input to Portable GHAR, not as authority to change a host. The incident was a runner-state failure: an image baked with runner `2.335.1` booted after GitHub required `2.336.0`, self-updated in the RAM-backed `/runner` filesystem, retained both versions plus `_work/_update`, and exhausted a 3 GiB tmpfs before cleanup. The event-asymmetric check result and annotation-only ENOSPC error are regression fixtures; Portable GHAR must not classify that signature as pull-request content failure.

The permanent Portable GHAR contract is:

1. Runner releases are observed outside job containers. A verified exact runner archive is baked into an immutable candidate image, smoke-tested, qualified, and referenced by digest. The scale set must report `RunnerSetting.DisableUpdate=true`; otherwise compatibility fails and acquisition stays disabled.
2. A runner never updates itself in place. GitHub-forced version bumps trigger the external candidate pipeline automatically. Until the candidate qualifies, the external failover authority keeps affected work GitHub-hosted; an upgrade-pending or rejected candidate must never remove the hosted path.
3. Every runner is one-job ephemeral. Normal reclamation removes the entire container, its cgroup, `/runner`, `/tmp`, `_work`, `_work/_update`, processes, and namespaces. A live file sweeper that deletes version directories from a serving runner is prohibited: it can race the listener and would preserve the flawed long-lived-container model.
4. Runner work remains memory-backed by default and receives no persistent host work volume. A disk-backed work area is admissible only as a separately reviewed, size-bounded anonymous ephemeral filesystem that is destroyed with the container; it cannot use an unbounded or reusable NAS path. Immutable images and a bounded rollback image are release artifacts, not job workspaces, and remain covered by the storage-reserve contract.
5. Tmpfs is a sub-limit inside the runner memory cgroup, not additional free memory. Configuration must satisfy both `runner tmpfs used + other tmpfs used + process margin <= runner memory limit` and the host-wide concurrency inequality below. The measured RhoNAS anchors are 666 MiB idle and 2,162 MiB `/runner` used for one real post-fix job on a 32 GiB host with six legacy slots. A 2 GiB memory cap is therefore invalid for that measured workload even if `/runner` is configured as 3 GiB.
6. The existing 5 GiB `/runner`, 4 GiB memory, and 6 GiB swap accommodation is a migration bridge only. It prevents an immediate job-local ENOSPC while the legacy image is repaired, but is neither a Portable GHAR baseline nor evidence that six-way concurrency is safe. Portable limits are selected from representative p99 telemetry plus explicit margin.

Before any host activation, the operator must approve one internally consistent tuple:

- runner `/runner` and `/tmp` tmpfs limits;
- runner memory and swap cgroup limits;
- maximum active concurrency; and
- upstream release-observation/rebuild cadence.

The profile validator rejects an unsigned/unapproved tuple and applies checked sizing:

```text
runner_tmpfs_limit >= p99_runner_tmpfs_used + runner_tmpfs_margin
runner_memory_limit >= p99_runner_cgroup_used + process_margin
runner_tmpfs_limit + runner_other_tmpfs_limits + process_margin <= runner_memory_limit
max_active * runner_memory_limit
  + max_active * auxiliary_slot_memory
  + idle_controller_and_watchdog
  + candidate_build_and_smoke_peak
  + host_and_gateway_reserve
  <= usable_host_memory
```

`usable_host_memory` excludes the operator-approved host reserve; swap is a bounded degradation buffer and is not counted as RAM capacity. Representative sizing requires at least 15 jobs over seven days, including the largest eligible workload classes, followed by five complete stable days with no upward memory, swap, tmpfs, storage, process, container, or cgroup trend. Pressure reduces concurrency or routes work hosted before either the per-runner or host-wide limit is threatened.

## Global Constraints

- Phase 1 is a prerequisite and already creates `go.mod`/`go.sum` with module `github.com/sumitake/portable-ghar`. This phase modifies those files, preserves `go 1.26.0` and `toolchain go1.26.6`, and runs every Go command with `GOTOOLCHAIN=go1.26.6`. The scale-set adapter retains its upstream minimum-compatibility contract with Go 1.25.3 while the project builds on 1.26.6.
- Pin `github.com/actions/scaleset` to `v0.4.0`, tag commit `6ce025902cd964747a078c2aabe7340ebc667eca`, module sum `h1:691GC2AkHb3ZGjfNvatboYoRS7CLr3+4VcZk/6w9IbM=`, and record its MIT license. Never use `@latest`.
- Pin the upstream runner to `v2.336.0` and Linux x64 archive SHA-256 `04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d`. A checksum mismatch is fatal. This is the implementation baseline, not a forever pin: the external release observer advances it only through the immutable candidate/qualification contract in Tasks 12 and 14.
- Pin the Linux x64 runner base to `debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4`; adapter, broker, helper, and verifier final images are `scratch`. Broker and verifier include one release-locked CA bundle whose source revision, SHA-256, license, copied path, and SBOM record live in the dependency lock; missing/expired/wrong-name/untrusted TLS tests and reviewed rotation are release gates. The iptables-legacy helper uses a digest-pinned build stage and copies its declared dynamic loader/library closure plus the complete pinned xtables extension directory into scratch; every image's SBOM and dependency-closure test is a release gate.
- Treat the scale-set dependency as Public Preview. Acquisition stays disabled until compile-time contracts, version fixtures, startup compatibility probes, and host conformance pass.
- Target each GitHub.com repository's scale set by its configured scale-set name, require exactly one label equal to that name, and require `RunnerSetting.DisableUpdate=true`. Reject missing, additional, or mismatched labels or enabled/unknown in-place update behavior before acquisition.
- Use `Statistics.TotalAssignedJobs` for demand and pass only broker-leased capacity as `maxCapacity`. Persist complete handling before acknowledging a scale-set message; tolerate redelivery and GitHub reassignment.
- A JobAvailable `runnerRequestId` is an acquisition offer, not a promise that GitHub will bind that job to a particular JIT runner. Persist offers and runner slots separately; bind them only from JobAssigned/JobStarted observations.
- Keep GitHub App keys, JIT configuration, raw readiness tokens, and secret references out of SQLite, argv, logs, metrics, diagnostics, Docker container/exec metadata, labels, and committed configuration. The readiness-token digest lives only in the held gate's process memory and is never written to a file; JIT exists only in controller-owned memory and the listener bootstrap environment until upstream argument parsing consumes it.
- Zero idle runners is the default. Every runner is fresh, handles at most one job, has no automatic restart, and is forcibly removed after success, cancellation, ambiguity resolution, or error. Destruction is incomplete until the container, its cgroup, tmpfs mounts, `_work`, `_work/_update`, processes, and namespaces are positively absent.
- Runners receive no Docker socket, host bind mount, named volume, device, host namespace, control-plane credential, or Linux capability. They use a read-only root, bounded tmpfs, `no-new-privileges`, seccomp, resource limits, and non-root execution unless the exact named `qts-capless-root` degraded profile is explicitly configured and positively matched.
- The QTS runner has no routable interface and no iptables/conntrack table. Its seccomp profile denies `unshare`, `setns`, `clone3`, `bpf`, raw-packet sockets, and `clone` with any namespace-creation flag; `/proc/sys` is masked/read-only. Only the trusted adapter sidecar receives the per-job broker-directory bind, read-only; the runner receives no mount.
- QTS supports proxy-compatible HTTPS/HTTP-CONNECT and optionally SOCKS5 CONNECT only. Direct UDP/ICMP/IP, plaintext absolute-form HTTP proxying, SOCKS BIND/UDP, SSH, and non-proxy-aware tools are unsupported and must fail explicitly. Current workflows receive no compatibility claim until their canaries pass.
- The helper gets only NET_ADMIN and the held broker network namespace. It never joins the empty runner/adapter namespace. The helper must be gone before the held broker is released and a capability-less verifier starts; helper and verifier must both be gone before the listener is released.
- The QTS default is proxy-compatible public TCP through fixed persistent DoH and explicit CONNECT ports, with direct IPv4/IPv6/DNS/UDP/ICMP denied by the empty runner namespace. An optional direct/dual-stack profile requires separate exact pre-conntrack qualification and complete IPv6 deny-class/route proof.
- Unsupported kernels, Docker builds, cgroup enforcement, selected egress profile, namespace emptiness, route discovery, broker accounting, or non-root behavior fail closed. There is no automatic direct/broker or nftables/iptables fallback. Host pressure may reduce capacity and never increase configured ceilings; every effective reduction traverses the acquisition-policy epoch barrier before it takes effect.
- Admission charges one complete stable-slot resource vector: runner, adapter, held/running broker, per-slot dial-authority/socket/ledger state, and serialized helper/verifier peak across CPU, memory, PIDs, file descriptors, tmpfs, scratch, durable bytes, and inodes. Helpers are serialized or their concurrent peaks are summed. Tmpfs remains a separately enforced sub-ceiling but its resident pages are not double-counted outside the enclosing memory-cgroup charge in the host RAM inequality. Durable ledger retention through `T` is part of storage pressure and garbage-collection accounting.
- The local watchdog may restart the controller, validate private-file modes, report health, and request a local acquisition stop only through the acquisition-policy transition interface. While `legacy` owns the fence it may run Portable GHAR only in force-disabled observer mode (`maxCapacity=0`) without a Portable guard; any nonzero advertisement, poll, JIT generation, or acquisition requires a current `portable` guard. It cannot mutate repository routing, hold failover credentials, mark external health, or flip a weaker side flag.
- A host-local, lock-protected fleet-generation fence names exactly one active fleet (`none`, `portable`, or `legacy`). A stable never-renamed lock inode supplies shared/exclusive authority; the generation header is a separate atomically replaced file; and each same-fleet controller/watchdog holder renews its own generation-scoped record. Handoff takes the exclusive lock, waits for every old-fleet shared guard to close, increments generation monotonically, and retires old holder records, so stale processes fail closed without a check-then-act race.
- Local acquisition policy persists `{mode, eligibleScaleSets, maxCapacity, repositoryPolicyRevision, repositoryPolicies, acquisitionEpoch}`, where `repositoryPolicies` is the per-repository `{alias, maxConcurrency, eligibility}` set. Every mode, eligibility, capacity, or repository-policy change closes the existing acquisition gate, atomically increments its epoch and discards cached Worker authority, cancels and joins old critical sections, and reopens only after zero remain. While closed, the gate rejects new critical sections, heartbeat lease installation, and cached-lease use; a persisted epoch alone is not effective acquisition authority. Every cached signed lease authenticates that local epoch, and every install and use requires exact current epoch/digest equality. Poll, acquire, and JIT calls use one checked authority-clock deadline: the earlier of `now + configured call duration` or the suspend-aware local lease deadline minus the proven positive cancel/join/fatal/termination tail. One per-operation mutex serializes deadline cancellation with a two-way admitted/dropped token. The handler remains armed through one journal-authorized at-most-once Ack or listener-release attempt; short pre/post barriers validate the same authority binding without holding the mutex across I/O, and the held-listener gate enforces its original local lease deadline at the actual release point. Ack grants no acquisition authority. If an old call ignores cancellation beyond the bounded shutdown deadline, the epoch owner persists `fatal` with zero capacity and terminates the controller process; the caller must observe failure/quiescence rather than a successful return. Canary narrowing, watchdog/probe stops, host-pressure reductions, suspend, and observer startup all use this interface.
- Acquisition authority uses one injected clock for both `Now` and absolute
  `WaitUntil`. Linux/QTS binds both to `CLOCK_BOOTTIME`, so suspension consumes
  lease and operation lifetime; no wall time or suspend-pausing monotonic
  fallback may authorize. Startup/host conformance failure for either operation
  leaves capacity zero. The cache and derived deadlines are process-memory-only;
  restart/reboot starts with no authority.
- An optional action/tool archive manifest may seed current or near-term first-party actions/tools only after source URL, immutable revision, SHA-256, and SPDX license verification. Seed content is read-only in the image and copied into per-job tmpfs; no mutable cross-job cache or upstream binary/archive is committed.
- The external Worker/Durable Object remains the sole automatic routing authority. This plan defines only the controller health-publisher interface; it does not implement failover, notification, or routing writes.
- No Kubernetes, ARC, job containers, service containers, Docker-in-Docker, Docker socket in runners, VM-isolation claim, private deployment identifier, production overlay, deployment, secret access, or live-host operation is permitted in this phase.
- QTS install scripts require Linux plus a positively matched QTS host profile and refuse Darwin; this plan never installs controller/watchdog services on the development/control Mac.
- Every planned commit uses `git commit -S` after staging only the exact paths named in that task's Files block; repository-wide staging is prohibited. Formatting checks and CI/release gates are non-mutating: use `gofmt -l`, fail on any listed path, and do not rewrite source.
- Public fixtures use only `owner/repository`, `example-fleet`, `example.invalid`, TEST-NET addresses, and temporary paths. Real host, account, repository, route, UID/GID, schedule, and notification values stay in a mode-restricted external overlay.

## File and Boundary Map

| Boundary | Files | Responsibility |
| --- | --- | --- |
| Pins and secrets | `go.mod`, `go.sum`, `internal/buildinfo/pins.go`, `internal/redaction/*.go`, `internal/config/runtime.go` | Modify the Phase-1 module, add immutable upstream inputs, strict config, scoped secret access, and schema-defined logs. |
| Domain and persistence | `internal/controller/model.go`, `internal/controller/state_machine.go`, `internal/state/{store,sqlite,migrations}.go` | Assignment/runner-slot split, legal transitions, effect journal, crash-safe SQLite. |
| GitHub and admission | `internal/githubscale/*.go`, `internal/admission/*.go`, `tests/fixtures/scaleset/v0.4.0/*.json` | Preview adapter, contract fixtures, max-capacity leases, weighted fairness and aging. |
| Runtime and isolation | `internal/hostruntime/*.go`, `internal/networkjail/*.go`, `internal/lifecycle/*.go` | Docker argv construction, unique netns, jail sequence, JIT lifecycle, reconciliation. |
| Trusted images | `cmd/portable-ghar-{runner-gate,network-adapter,network-broker-parser,network-broker-dialer,network-helper,network-verifier}/*`, `internal/archive/*`, `config/schema/action-tool-archive-manifest.schema.json`, `images/{runner,network-adapter,network-broker-parser,network-broker-dialer,network-helper,network-verifier}/Dockerfile`, `scripts/{fetch-runner,stage-action-tool-archive}.sh` | Held listener and held broker namespace owner, capless relay, bounded broker, optional verified immutable seeds, one-shot policy install, capless probes, pinned runner assembly and CA bundle. |
| Host operations | `cmd/portable-ghar-{controller,watchdog,fleet-fence}/*`, `internal/{hostruntime,fleetfence}/*`, `deploy/{qts,systemd}/*` | Controller wiring, exclusive fleet generation, exact QTS install/verify/rollback/uninstall, root-cron and Linux supervision without routing authority. |
| Verification | `tests/{integration,conformance,chaos}/*`, `scripts/test-controller-runtime.sh`, `docs/operations/controller-{upgrade,recovery}.md` | Live boundary proofs, crash matrices, safe drain/replace/reconcile instructions. |

## Canonical Runtime Contracts

These names and signatures are fixed for this plan. Implementations may add private helpers but must not rename or widen these boundaries.

```go
package controller

type State string

const (
	StateReceived            State = "RECEIVED"
	StateCapacityReserved    State = "CAPACITY_RESERVED"
	StateAdapterCreated      State = "ADAPTER_CREATED"
	StateAdapterVerified     State = "ADAPTER_VERIFIED"
	StateBrokerHeld          State = "BROKER_HELD"
	StateBrokerPolicyApplied State = "BROKER_POLICY_APPLIED"
	StateDialAuthorityReady  State = "DIAL_AUTHORITY_READY"
	StateBrokerReleased      State = "BROKER_RELEASED"
	StateEgressVerified      State = "EGRESS_VERIFIED"
	StateRunnerHeld          State = "RUNNER_HELD"
	StateReleaseArmed        State = "RELEASE_ARMED"
	StateListenerReleased    State = "LISTENER_RELEASED"
	StateJobRunning          State = "JOB_RUNNING"
	StateJobFinished         State = "JOB_FINISHED"
	StateDestroyed           State = "DESTROYED"
)

type AssignmentKey struct {
	RepositoryAlias string
	RunnerRequestID int64
	Attempt         uint32
}

type RunnerSlot struct {
	OpaqueName         string
	UpstreamRunnerID   int64
	RunnerContainerID  string
	AdapterContainerID string
	BrokerContainerID  string
	CapacitySlotID     uint32
	BoundRequestID     int64
}

type CycleReceipt struct {
	CycleID         string
	CompletedAt     time.Time
	AssignmentCount int
	OldestAge       time.Duration
}

type AcquisitionMode string

const (
	AcquisitionDisabled   AcquisitionMode = "disabled"
	AcquisitionCanaryOnly AcquisitionMode = "canary-only"
	AcquisitionEnabled    AcquisitionMode = "enabled"
	AcquisitionFatal      AcquisitionMode = "fatal"
)

type AcquisitionPolicy struct {
	Mode                     AcquisitionMode
	EligibleScaleSets        []string
	MaxCapacity              int
	RepositoryPolicyRevision uint64
	RepositoryPolicies       []RepositoryPolicySummary
	Epoch                    uint64
}

type RepositoryPolicySummary struct {
	Alias          string
	MaxConcurrency uint32
	Eligibility    string // active | archived-disabled | pending-reactivation
}

type AcquisitionTransitioner interface {
	Snapshot(context.Context) (AcquisitionPolicy, error)
	Transition(context.Context, uint64, AcquisitionPolicy) (AcquisitionPolicy, error)
}

type AcquisitionGuard interface {
	Close() error
}

type FleetGuardProvider interface {
	AcquirePortable(context.Context) (AcquisitionGuard, error)
}

type AcquisitionPermitRequest struct {
	OperationID, RepositoryAlias, ScaleSetName, PolicyDigest string
	OperationKind string // poll | acquire | jit
	PolicyEpoch uint64
}

type AcquisitionPermitProvider interface {
	Acquire(context.Context, AcquisitionPermitRequest) (AcquisitionGuard, error)
}
```

```go
package githubscale

type Fleet struct {
	RepositoryAlias string
	GitHubConfigURL  string
	ScaleSetName     string
}

type Client interface {
	Open(context.Context, Fleet) (Session, error)
	Probe(context.Context) (CompatibilityReport, error)
}

type Session interface {
	Compatibility() ScaleSetCompatibilityReport
	Poll(context.Context, int, int) (Batch, error)
	Ack(context.Context, int) error
	Acquire(context.Context, []int64) ([]int64, error)
	GenerateJIT(context.Context, JITRequest) (JITConfig, error)
	GetRunnerByName(context.Context, string) (RunnerRef, bool, error)
	GetRunner(context.Context, int64) (RunnerRef, bool, error)
	RemoveRunner(context.Context, int64) error
	Close(context.Context) error
}

type ScaleSetCompatibilityReport struct {
	SingleNameLabel bool
	DisableUpdate   bool
}

type JITConfig struct {
	Runner  RunnerRef
	Encoded redaction.Secret
}

type Statistics struct {
	TotalAvailableJobs int
	TotalAcquiredJobs  int
	TotalAssignedJobs  int
	TotalRunningJobs   int
}
```

```go
package admission

type Resources struct {
	MilliCPU          int64
	MemoryBytes       int64
	PIDs              int64
	FileDescriptors   int64
	TmpfsBytes        int64
	ScratchBytes      int64
	SocketStateBytes  int64
	DurableStateBytes int64
	Inodes            int64
}

type SlotResources struct {
	Runner        Resources
	Adapter       Resources
	Broker        Resources
	DialAuthority Resources
	Helper        Resources
	Verifier      Resources
}

type CapacityChange struct {
	Previous int
	Current  int
}

type Broker interface {
	Enqueue(githubscale.Offer) error
	LeasePoll(string, time.Time) (CapacityLease, error)
	Admit(time.Time) ([]Decision, error)
	SetPressure(Pressure) (CapacityChange, error)
	Release(controller.AssignmentKey) error
}
```

```go
package hostruntime

type Engine interface {
	CreateNetworkAdapter(context.Context, AdapterSpec) (Container, error)
	CreateNetworkBrokerHeld(context.Context, BrokerSpec) (Container, error)
	ReleaseNetworkBroker(context.Context, string) error
	CreateRunner(context.Context, RunnerSpec) (Container, error)
	Start(context.Context, string) error
	Inspect(context.Context, string) (Container, error)
	Wait(context.Context, string) (Exit, error)
	ExecStdin(context.Context, string, ExecSpec, io.Reader) (Result, error)
	RunOneShot(context.Context, OneShotSpec, io.Reader) (Result, error)
	ListManaged(context.Context, map[string]string) ([]Container, error)
	Remove(context.Context, string, bool) error
}

type CommandRunner interface {
	Run(context.Context, []string, []*os.File, io.Reader) (Result, error)
}

type HostProfile interface {
	Probe(context.Context) (ConformanceReport, error)
	DiscoverNetworks(context.Context) (NetworkSnapshot, error)
}

type RuntimeManifest struct {
	SchemaVersion         uint32
	BuildID               string
	ControllerSHA256      string
	RunnerImageDigest     string
	AdapterImageDigest    string
	BrokerImageDigest     string
	HelperImageDigest     string
	VerifierImageDigest   string
	TrustBundleDigest     string
	SeccompProfileDigest  string
	EgressMode            string
	PolicyManifestDigest  string
	ConntrackBudgetDigest string
	StorageBudgetDigest   string
	LogPolicyDigest       string
	ArchiveManifestDigest *string
	AcquisitionDefault    string
	FleetGeneration       uint64
}
```

```go
package fleetfence

type Fleet string

const (
	FleetNone     Fleet = "none"
	FleetPortable Fleet = "portable"
	FleetLegacy   Fleet = "legacy"
)

type Header struct {
	Generation  uint64
	ActiveFleet Fleet
	BootID      string
	UpdatedAt   time.Time
	OperationID string
}

type Holder struct {
	Generation  uint64
	Fleet       Fleet
	OwnerID     string
	PID         int
	BootID      string
	AcquiredAt  time.Time
	RenewedAt   time.Time
}

type Snapshot struct {
	Header  Header
	Holders []Holder
}

type Guard interface {
	Holder() Holder
	Close() error
}

type Store interface {
	Acquire(context.Context, Header, string) (Guard, error)
	Inspect(context.Context) (Snapshot, error)
	Handoff(context.Context, uint64, Fleet, Fleet, string) (Header, error)
}
```

```go
package networkjail

type IPFamily string

const (
	PublicIPv4Only IPFamily = "public_ipv4_only"
	PublicDualStack IPFamily = "public_dual_stack"
)

type EgressBackend string

const (
	RestrictedBrokerV1 EgressBackend = "restricted-broker-v1"
	NftablesDirectV1   EgressBackend = "nftables-direct-v1"
)

type PolicyManifest struct {
	EgressBackend   EgressBackend
	IPFamily        IPFamily
	PublicDNS       []netip.Addr
	DynamicDeny     []netip.Prefix
	DockerHost      []netip.Addr
	PositiveProbes  []Probe
	NegativeProbes  []Probe
}

type Jail interface {
	Configure(context.Context, hostruntime.Container, PolicyManifest) (Verification, error)
}

type Verification struct {
	PolicyDigest string
	NetNSID      string
	PositiveOK   bool
	NegativeOK   bool
}
```

```go
package lifecycle

type Service interface {
	Prepare(context.Context, controller.Assignment) (controller.RunnerSlot, error)
	Release(context.Context, controller.AssignmentKey) error
	Observe(context.Context, githubscale.Event) error
	Destroy(context.Context, controller.AssignmentKey, controller.ReasonCode) error
}

type Reconciler interface {
	Once(context.Context) (controller.CycleReceipt, error)
}
```

---

### Task 1: Extend the Foundation Module with Runtime Pins, Secrets, and Log Schema

**Files:** Modify `go.mod` and `go.sum` created by Phase 1. Create `internal/buildinfo/pins.go`, `internal/buildinfo/pins_test.go`, `internal/redaction/secret.go`, `internal/redaction/logger.go`, `internal/redaction/redaction_test.go`, `internal/config/runtime.go`, `internal/config/runtime_test.go`.

**Interfaces:** Produce `buildinfo.Pins() Manifest`; `redaction.SecretFromBytes([]byte) *Secret`, `Secret.Use(func(io.Reader) error) error`, `Secret.Destroy()`, and `ErrSecretScopeClosed`; `redaction.Logger.Event(name string, fields map[string]any) error`; `config.LoadRuntime(io.Reader) (Runtime, error)` and `config.ReadSecret(SecretRef) (*redaction.Secret, error)`. No method returns the backing bytes or an unbounded reader.

- [ ] **Step 1: Write failing boundary tests.** Table-test that unknown JSON fields and inline secret values fail, secret `String`/`MarshalJSON` never reveal bytes, non-allowlisted log keys and job-controlled fields fail, and the pins equal the exact values in Global Constraints.
- [ ] **Step 2: Verify the tests fail.** Run `GOTOOLCHAIN=go1.26.6 go test ./internal/buildinfo ./internal/redaction ./internal/config`. Expected: FAIL because runtime additions do not exist.
- [ ] **Step 3: Modify the foundation module and add minimal implementations.** Preserve module `github.com/sumitake/portable-ghar`, `go 1.26.0`, and `toolchain go1.26.6`; add scaleset `v0.4.0`, sqlite `v1.53.0`, and nftables `v0.3.0`. Define the profile-aware blocked-address/policy decision graph here; `restricted-broker-v1` is the QTS default, iptables-legacy remains a generated broker-helper protocol rather than a host userspace dependency, and `nftables-direct-v1` is unavailable until exact pre-conntrack qualification. `Secret.Use` supplies a scope-invalidated reader only during the callback; `Destroy` best-effort zeroes owned buffers. Immediately convert the upstream immutable JIT string into owned bytes and clear the upstream field, while documenting that Go cannot guarantee erasure of prior immutable string storage.
- [ ] **Step 4: Lock and verify dependency content.** Run `GOTOOLCHAIN=go1.26.6 go mod tidy && GOTOOLCHAIN=go1.26.6 go mod verify && grep -F 'github.com/actions/scaleset v0.4.0 h1:691GC2' go.sum`. Expected: all modules verified and grep prints exactly one module-sum line.
- [ ] **Step 5: Re-run tests and commit.** Retaining a reader after `Use` must return `ErrSecretScopeClosed`; formatting, JSON, and repeated destroy tests pass. Commit: `git commit -S -m "build: pin controller runtime dependencies"`.

### Task 1A: Advance the Bootstrap Runner Pin After the Self-Update Incident

**Files:** Modify `internal/buildinfo/pins.go` and `internal/buildinfo/pins_test.go`.

**Interfaces:** Preserve `buildinfo.Pins() Manifest`; change only `UpstreamRunner` to version `v2.336.0` and Linux x64 archive SHA-256 `04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d`.

This corrective task exists because Task 1 was implemented before the 2026-07-22 incident amendment. It must land before the amended Task 3 compatibility proof or any Task 5 runner-image build. It advances the bootstrap pin only; the automatic monotonic release-observer and qualified-candidate lifecycle remain Tasks 12 and 14. Execute this task only after the incident amendment receives the required distinct-family design cross-check.

- [ ] **Step 1: Change the exact pin tests first.** Update only the expected runner version and digest in `internal/buildinfo/pins_test.go`; do not change the implementation yet.
- [ ] **Step 2: Prove the intended red state.** Run `GOTOOLCHAIN=go1.26.6 go test ./internal/buildinfo -run 'TestPins(ExactValues|FieldTable)$' -count=1`. Expected: FAIL only because `Pins().UpstreamRunner` still returns `v2.335.1` and its prior Linux x64 digest.
- [ ] **Step 3: Advance the implementation pin.** Update only `Pins().UpstreamRunner` in `internal/buildinfo/pins.go`. Do not add a mutable tag lookup, downloader, updater, or second source of truth.
- [ ] **Step 4: Verify the focused and repository suites.** Re-run the focused command, then `GOTOOLCHAIN=go1.26.6 go test ./...` and `git diff --check`. Expected: PASS; the exact new version/digest have one implementation source, and no task has enabled in-place runner update.
- [ ] **Step 5: Commit.** Stage only the two buildinfo files and commit `git commit -S -m "build: advance runner bootstrap pin"`.

### Task 2: Implement the Assignment State Machine and Crash-Safe SQLite Store

**Files:** Create `internal/controller/model.go`, `internal/controller/state_machine.go`, `internal/controller/state_machine_test.go`, `internal/state/store.go`, `internal/state/migrations.go`, `internal/state/sqlite.go`, `internal/state/sqlite_test.go`.

**Interfaces:** Define the exact ordered `State` constants `RECEIVED`, `CAPACITY_RESERVED`, `ADAPTER_CREATED`, `ADAPTER_VERIFIED`, `BROKER_HELD`, `BROKER_POLICY_APPLIED`, `DIAL_AUTHORITY_READY`, `BROKER_RELEASED`, `EGRESS_VERIFIED`, `RUNNER_HELD`, `RELEASE_ARMED`, `LISTENER_RELEASED`, `JOB_RUNNING`, `JOB_FINISHED`, and `DESTROYED`; `AssignmentKey{RepositoryAlias string; RunnerRequestID int64; Attempt uint32}`; the canonical `RunnerSlot` with runner/adapter/broker container IDs and stable capacity-slot ID; `Transition(current, next State, released bool) error`; and `Store` methods `UpsertOffer`, `Reserve`, `BeginEffect`, `CompleteEffect`, `Advance`, `MarkAmbiguous`, `BindRunner`, `ListRecoverable`, `AcquisitionPolicy`, and `CompareAndSetAcquisition(expectedEpoch, nextPolicy)`.

- [ ] **Step 1: Write failing state/store tests.** Cover every adjacent legal transition in the exact external-effect order, idempotent replay, pre-release failure-to-DESTROYED, rejection of skipped/reversed states, post-release ambiguity without duplicate release, unique offer and runner-slot keys, persisted adapter/broker/runner/capacity-slot identities, orphan held-broker reconciliation, restart from every checkpoint, and transaction rollback after injected failure.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.6 go test ./internal/controller ./internal/state -run 'Test(State|SQLite)' -v`. Expected: FAIL with undefined domain/store symbols.
- [ ] **Step 3: Implement the model and schema.** Use WAL, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=FULL`, `BEGIN IMMEDIATE` for reservations, and tables `assignments`, `runner_slots`, `reservations`, `effects`, `acquisition_state`, `network_ledgers`, and `reconcile_cycles`. Persist each real lifecycle checkpoint and its adapter, held-broker, runner, policy/socket digest, release generation, and stable capacity-slot identity before the next effect. `network_ledgers` is the controller's single-writer token/clock state and outlives assignment rows for at least measured `T`. `acquisition_state` persists mode, exact eligible scale-set list, effective maximum capacity, and monotonic `acquisition_epoch`; compare-and-set requires the expected epoch and every broker poll lease stores the resulting epoch. Store only opaque names/IDs, digests, reason codes, and timestamps; reject secret-bearing columns at the repository API.
- [ ] **Step 4: Prove idempotency and durability.** Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/controller ./internal/state -count=20`. Expected: PASS with one row/effect per idempotency key and no race.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: persist idempotent assignment transitions"`.

### Task 3: Wrap `actions/scaleset` Behind a Pinned Contract Adapter

**Files:** Create `internal/githubscale/types.go`, `internal/githubscale/client.go`, `internal/githubscale/adapter_v040.go`, `internal/githubscale/probe.go`, `internal/githubscale/adapter_contract_test.go`, and versioned synthetic fixtures under `tests/fixtures/scaleset/v0.4.0/`.

**Interfaces:** `Fleet{RepositoryAlias, GitHubConfigURL, ScaleSetName string}`; `Client.Open(ctx, Fleet) (Session, error)`; `Session.Compatibility() ScaleSetCompatibilityReport` returns only the immutable result captured during successful Open; `Session.Poll(ctx, lastMessageID, maxCapacity int) (Batch, error)`; `Ack(ctx, messageID int) error`; `Acquire(ctx, []int64) ([]int64, error)`; `GenerateJIT(ctx, JITRequest) (JITConfig, error)`; `GetRunnerByName`, `GetRunner`, `RemoveRunner`, `Close`; package/module `Probe(ctx) CompatibilityReport`. Internal `Batch` carries statistics, offers, assigned/started/completed events, and no upstream type.

- [ ] **Step 1: Write failing compile and wire-contract tests.** Assert `*scaleset.Client` and `*scaleset.MessageSessionClient` satisfy private exact-signature interfaces; translate all four job message types; preserve `TotalAssignedJobs`; pass `maxCapacity` unchanged; model nil polls, redelivery, duplicate batch IDs, and the same workflow job reappearing with a new runner request ID. For GitHub.com, reject a scale set unless lookup by `ScaleSetName` returns exactly one label equal to that same name and `RunnerSetting.DisableUpdate` is explicitly true; false, omitted/unknown, malformed, or drifted update settings keep acquisition disabled. A successful Session returns an immutable private `ScaleSetCompatibilityReport{SingleNameLabel:true, DisableUpdate:true}` captured from that Open; the package-level module probe does not falsely claim live scale-set evidence. Against a server that never completes a response, prove each poll/acquire/JIT call obeys its explicit context/transport deadline and returns after cancellation.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.6 go test ./internal/githubscale -run 'TestContract|TestTranslate|TestRedelivery|TestSingleNameLabel' -v`. Expected: FAIL because the adapter is absent.
- [ ] **Step 3: Implement translation and probes.** Call the v0.4.0 API directly rather than its opinionated listener, target the configured GitHub.com scale set by its single scale-set-name label, require the returned scale set's `RunnerSetting.DisableUpdate` to be explicitly true, never expose upstream structs, retain the immutable live label/update proof on the returned Session, persist the tag commit/license only in the separate module `CompatibilityReport`, reject a build whose module version is not `v0.4.0`, require explicit per-operation context deadlines plus HTTP transport/header timeouts, and keep acquisition disabled on fixture, session, cancellation, label, scale-set identity, update-setting, or JIT shape mismatch.
- [ ] **Step 4: Prove acknowledgement discipline at the boundary.** A fake session must record `Poll -> persist callback -> Ack`; when persistence fails, assert zero `Ack` calls and successful redelivery. Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/githubscale -count=20`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: isolate pinned scale-set preview adapter"`.

### Task 4: Add Resource Ceilings, Weighted Fairness, Aging, and Capacity Leases

**Files:** Create `internal/admission/resources.go`, `internal/admission/broker.go`, `internal/admission/broker_test.go`.

**Interfaces:** Canonical `Resources` covers CPU, memory, PIDs, file descriptors, tmpfs, scratch, socket state, durable state, and inodes; `SlotResources{Runner, Adapter, Broker, DialAuthority, Helper, Verifier Resources}`; `RepositoryPolicy{Alias string; Weight uint32; MaxConcurrency uint32; Eligibility Eligibility; AgingThreshold time.Duration; Profile SlotResources}` where `Eligibility` is `active`, `archived-disabled`, or `pending-reactivation`, `MaxConcurrency` is a hard per-repository admission cap independent of `Weight` (the sum of configured maxima may exceed the fleet-wide ceiling, which still bounds total concurrency), and any `Eligibility` other than `active` forces effective capacity zero for that repository through the acquisition-policy epoch barrier regardless of `MaxConcurrency`; `CapacitySlotID` is a stable bounded integer whose egress ledger outlives assignments; `Broker.Enqueue(githubscale.Offer) error`; `Broker.LeasePoll(repo string, now time.Time) (CapacityLease, error)`; `Broker.Admit(now time.Time) ([]Decision, error)` returns one stable slot per admitted assignment; `Broker.SetPressure(Pressure) (CapacityChange, error)`; `Broker.Release(controller.AssignmentKey) error` frees scheduling use but retains the slot egress ledger for at least `T`. Add compile-time interface assertions against the canonical contract.

- [ ] **Step 1: Write failing deterministic-clock tests.** Prove no resource dimension exceeds the global ceiling after charging runner + adapter + held/running broker + explicit `DialAuthority` resources (including socket/ledger state) + `max(helper, verifier)` when transient work is serialized; prove concurrent transient work is rejected unless both peaks were charged. Cover every CPU/memory/PID/FD/tmpfs/scratch/durable-byte/inode dimension, weighted sequence `repo-a, repo-a, repo-b` for weights 2:1, FIFO within a repository, aging override of an old low-volume offer, no head-of-line starvation across repositories, pressure returns the exact previous/current effective capacity and only lowers availability, and concurrent poll leases cannot over-advertise. Prove a repository at its `MaxConcurrency` (live plus reserved slots) is skipped even when fleet-wide capacity is free and its weight would otherwise select it, that a lower-weight repository below its cap is admitted instead, and that the cap releases as that repository's slots are released. Prove an `Eligibility` other than `active` (`archived-disabled`, `pending-reactivation`) admits nothing and grants no lease at any weight or cap, that already-admitted slots for a newly disabled repository drain normally without forced cancellation, and that the latch does not clear on its own — only a new configuration revision arriving through the epoch barrier (never a bare live `archived=false`) moves a repository back toward `active`.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.6 go test ./internal/admission -run TestBroker -v`. Expected: FAIL with undefined broker.
- [ ] **Step 3: Implement weighted deficit round robin.** Charge one deficit per admitted complete slot profile, skip queues whose head does not fit or whose repository is archived or at its per-repository `MaxConcurrency`, select the oldest aged fitting offer first with stable alias/request-ID ties, persist reservations before admission, and allocate one stable capacity-slot ID whose dial ledger is never reset by assignment/release. Serialize helper and verifier operations per slot or charge both peaks. Calculate each `maxCapacity` as active complete slots plus broker-owned poll leases; capacity reduction retires scheduling slots but retains their ledgers and durable-storage charge until the network-jail tail window expires and guarded garbage collection succeeds.
- [ ] **Step 4: Stress invariants.** Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/admission -run TestBroker -count=100`. Expected: PASS with no oversubscription or race.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: broker fair fleet-wide capacity"`.

### Task 5: Build the Docker Engine Adapter and Held Runner Gate

**Files:** Create `internal/hostruntime/{engine,handles,evidence,command,dockercli}.go` and tests, `internal/archive/{manifest,verify,directory}.go` plus platform-specific identity helpers and tests, `config/seccomp/portable-ghar-capless-v1.json`, `config/schema/action-tool-archive-manifest.schema.json`, `cmd/portable-ghar-runtime-lock/main.go` and tests, `cmd/portable-ghar-runner-gate/main.go` and tests, `cmd/portable-ghar-network-adapter/main.go` and tests, `scripts/{fetch-runner,stage-action-tool-archive}.sh`, `tests/shell/{fetch-runner,action-tool-archive}.bats`, `images/{runner,network-adapter}/Dockerfile`, and Docker build-context ignore files that exclude downloaded archives and mutable staging trees.

**Interfaces:** `Engine.CreateNetworkAdapter(ctx, AdapterSpec) (AdapterHandle, error)` creates the capless `--network none` namespace owner with only a read-only per-job broker-directory bind; `AdapterHandle` has unexported identity/generation proof and cannot be synthesized from a string. Task 6 adds `CreateNetworkBrokerHeld`/`ReleaseNetworkBroker`; before the adapter opens loopback, `BindBrokerPeer(ctx, AdapterHandle, BrokerPeerProof)` runs exactly once and binds the controller-recorded broker container generation plus exact socket mount/device/inode/owner/mode and available peer PID/start-time proof. `Engine.CreateRunner(ctx, RunnerSpec{Adapter AdapterHandle}) (RunnerHandle, error)` re-inspects that exact managed adapter before using `container:<adapter-id>`, receives no mount, and carries no JIT/readiness secret in Docker configuration. Secret-bearing exec accepts only `RunnerHandle` plus the closed ordered `GateOperation` values `HydrateSeeds`, `NetNSIDPreArm`, `Arm`, `NetNSIDFinal`, `Release`; both namespace probes and `InspectNetworkNamespace(AdapterHandle)` return one generation-bound `NetworkNamespaceProof`, and release requires exact equality of all three. `AuditHeldRunner` returns a closed process/config proof. `Start`, `Inspect`, `Wait`, `RunOneShot`, `ListManaged`, and `Remove` likewise use controller-produced handles rather than caller-controlled Docker identifiers. `archive.Load(io.Reader) (Manifest, error)` and logical `archive.Verify(fs.FS, Manifest) (Digest, error)` never claim OS identity; production staging additionally requires `archive.VerifyDirectory(root, Manifest) (VerifiedDirectory, error)` with descriptor-relative no-follow traversal, stable pre/post metadata, unique device/inode, `nlink=1`, and no mount crossing. `VerifiedDirectory` has unexported construction and binds root identity, manifest digest, deterministic tree-lock digest, and evidence generation; seed publish, tree-lock emission, build-context preparation, and image bake accept only this type, never logical `Digest`. `CommandRunner.Run(ctx, argv []string, extraFiles []*os.File, stdin io.Reader) (Result, error)`; gate subcommands `hold`, `arm`, `release`, `hydrate-seeds`, and `netns-id`. `SourceVerification` and `TargetConformance` are distinct non-interchangeable proof types; `DeploymentEligibility` requires both for the same build/profile/evidence generation and there is no aggregate source-only success. The token is exactly 32 random bytes. `arm` accepts only `PGHARARM | version:u8=1 | algorithm:u8=1 | digestLength:u16be=32 | sha256(token):32`; `release` accepts only `PGHARREL | version:u8=1 | tokenLength:u16be=32 | jitLength:u32be | token | jit`, with nonzero `jitLength <= 65536` and exact EOF, after network verification. Add compile-time interface assertions against the canonical contract.

- [ ] **Step 1: Write failing argv, handle, proof-type, and gate tests.** Assert adapter creation has `--network none`, cap-drop ALL, read-only root, `no-new-privileges`, strict seccomp identity, no published port, no runner/JIT/job data, no volume/device/socket except the exact per-job broker parent directory bind mounted read-only, no restart, opaque labels, bounded FD/memory settings, and one unique namespace. Source tests prove only the configured seccomp path+digest+schema identity; actual denial of `unshare`, `setns`, `clone3`, `bpf`, raw-packet sockets, namespace-flagged `clone`, and writable `/proc/sys` remains `TargetConformance` evidence on Linux. Reject a caller-synthesized adapter/container name, stale generation, changed label/image/state, unknown or out-of-order gate operation, extra held process, and any source-only proof used to construct deployment eligibility. Parameterize runner creation by host profile: strict Linux requires a non-root user, while only exact configured `qts-capless-root` may use UID 0 with every capability set empty and never report strict/conforming; both require read-only root, bounded executable work/tmp tmpfs, CPU/memory/PID/FD/scratch limits, cap-drop ALL, no-new-privileges, the same namespace-denying seccomp identity, no mounts/volumes/devices/socket, no restart, and exact controller-handle-bound `container:<adapter-id>` mode with no independent endpoint mutation. Reject any runner profile whose measured/configured `/runner` plus `/tmp` tmpfs sub-limits and process margin do not fit inside its memory cgroup, including the incident-regression case `2162 MiB /runner peak > 2 GiB memory`. Require the image's `Runner.Listener --version` to equal the runtime-manifest pin, an authenticated deterministic extracted-tree lock plus exact listener digest, exactly one runner `bin`/`externals` payload, no wrapper/configuration that enables in-place update, and no baked `_work/_update`. Require JIT and raw token-corpus absence from create/exec argv, `Config.Env`, labels, inspect output, isolated-daemon `config.v2.json`, normal logs, and diagnostics; register rather than erase the bounded Docker-stdin, final `execve` environment, transient `/proc/<pid>/environ`, daemon-debug, and upstream-immutable-string residuals. Require absence from tmpfs after release, the listener environment after upstream parsing, and every job/descendant environment. Explicitly permit the JIT only in the listener bootstrap environment before that observation point. Reject bad magic/version/algorithm, zero/short/long/duplicate fields, truncation, premature EOF, trailing bytes, `jitLength > 65536`, wrong/absent/duplicate/reused tokens, re-arm, second release, and any frame that would exec the listener after a parse failure.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.6 go test ./internal/hostruntime ./internal/archive ./cmd/portable-ghar-runner-gate ./cmd/portable-ghar-network-adapter -v`. Expected: FAIL.
- [ ] **Step 3: Implement one-use release over a single held gate without a shell.** Keep JIT bytes in the controller's owned secret buffer; Docker create receives no JIT or readiness value. Generate a fresh 32-byte token per runner. The runner's one long-lived held gate process owns a mode-`0600` `AF_UNIX` socket in runner-private tmpfs and holds all arm state (the armed digest) only in its own process memory — no digest or token is ever written to a file. Every Docker exec is one controller-leased, reaped, ordered operation: `HydrateSeeds` (mandatory even for empty selection; accepts bounded manifest IDs, never a path), `NetNSIDPreArm` (input-free), `Arm`, `NetNSIDFinal` (input-free), then `Release`. The minimal forwarder copies only bounded stdin into the socket and exits with no secret state; only the fixed operation name enters Docker exec metadata. Unknown, missing, duplicate, concurrent, or out-of-order operations and any extra process destroy the runner. Both namespace operations produce generation-bound `NetworkNamespaceProof`; after final probe the controller re-inspects the `AdapterHandle` and requires `preArm == final == adapter` before the release transition can be constructed. Missing, unequal, stale, or unrepresentable proof destroys; probes merely running are not success. `arm` is accepted once and its SHA-256 digest kept in memory. Only after the final closed input-free network/namespace/socket/process/config/policy/budget audit passes does the controller deliver `release`; the gate parses with bounded reads and a read deadline, rejects any premature EOF or trailing byte, constant-time verifies the released token against the in-memory digest, atomically consumes arm state, removes the socket, closes inherited descriptors, opens the fixed listener from the read-only image root with no-follow semantics, rechecks type/owner/mode/size/SHA-256 against the baked runner-tree lock, constructs a fresh closed listener environment containing the fixed nonsecret image entries, the exact TLS-only loopback proxy quartet, and the bounded JIT entry (never ambient `os.Environ`), and `exec`s it. The listener is never copied to tmpfs/scratch. Duplicate/re-arm/release attempts, any parse or identity failure, and any gate-process restart destroy the runner and owned secret buffer; consumed authority is never restored. Pin and source-test the upstream behavior that removes the JIT environment variable during argument parsing before any job process while retaining the exact seven-entry image-plus-proxy runtime environment; explicitly retain the one-job-process-memory residual because immutable .NET strings cannot be proven erased. Poisoned-ambient tests require the exact eight-entry bootstrap environment, reject `HTTP_PROXY`/`http_proxy`, and prove no other container/controller variable crosses the exec boundary.
- [ ] **Step 4: Implement the capless loopback relay sidecar.** Start held with no loopback listener. Task 6 creates the held broker socket, then the controller performs one `BindBrokerPeer` under the adapter lease using its exact broker container generation plus controller-observed socket mount/device/inode/owner/mode and representable peer PID/start-time. Bare UID is never sufficient; if the required instance proof is unavailable, target conformance rejects. Only after binding may the adapter listen on the closed compile-time loopback-port-to-Unix-target table. Accept a bounded number of TCP clients, open exactly one AF_UNIX stream under the mounted per-job directory for each, and perform no job protocol parsing, DNS, or network dial. Require directory mode `0700`, socket mode `0600`, exact read-only mount identity, and the same dedicated non-runner UID in adapter/broker; broker state is a separate mount invisible to the adapter. On every connect require the bound socket identity plus before/after path identity and `SO_PEERCRED`; broker restart/replacement or mismatch is terminal. Use fixed maximum buffers, deadlines, half-close propagation, close-on-exec FDs, and fail-closed cancellation. Reject path escape, aliases when detectable, unexpected inode/owner/mode, unknown ports, and any mount other than the exact read-only parent. Fuzz relay state transitions and prove same-UID replacement, slowloris, and client floods remain fail-closed and inside FD/memory limits.
- [ ] **Step 5: Pin and verify runner plus optional first-party seed archives.** `fetch-runner.sh` downloads `v2.336.0` to an untracked build directory and verifies Linux x64 SHA-256 `04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d` before extraction. It derives version and digest from `buildinfo.Pins().UpstreamRunner`/the generated runtime lock rather than repeating an independent mutable value, rejects downgrade, redirects outside the exact canonical origin, and asset-name/platform ambiguity, preflights every archive entry type/path/link/collision, and extracts into a controller-private snapshot. Production verification must call `VerifyDirectory`; only its opaque `VerifiedDirectory` result may authorize tree-lock emission, seed publication, Docker build-context preparation, or image bake. Logical `Verify` output cannot be converted into that authority. `VerifyDirectory` hashes held descriptors with stable pre/post identity, `nlink=1`, unique device/inode, and no mount crossing, then binds the deterministic full runner-tree lock and exact listener digest. It smoke-tests `Runner.Listener --version` as compatibility evidence, never as authenticity by itself. The optional manifest accepts only exact canonical `action`/`tool` sources under the first decoded path segment `actions` on `https://github.com` (no user info, port, query, fragment, trailing-dot/IDN/escape ambiguity), with a full 40-hex action commit or immutable tool release asset, SHA-256, approved SPDX ID, manifest-bound license-file path/size/SHA-256, and deterministic target; `stage-action-tool-archive.sh` requires `VerifiedDirectory`, rejects namespace/revision/checksum/license/path/identity failure, records the manifest digest, and commits no archive or upstream binary.

  **Pinned-archive implementation finding (2026-07-28):** the exact `v2.336.0` Linux x64 archive contains eight legitimate zero-length regular files and six relative symlinks used by the bundled Node runtimes. Runner identity therefore uses a closed `RunnerTreeManifest` and opaque `VerifiedRunnerDirectory`, distinct at the type level from the provenance-bearing action/tool seed `Manifest` and `VerifiedDirectory`; separate marker interfaces plus projection tests prove that neither authority nor a logical digest can be converted into the other. The runner manifest binds every normalized directory, regular file, and symlink, accepts a zero-length regular file only with the SHA-256 of empty content, normalizes read-only modes while preserving executable intent, and binds each symlink target string plus digest. Symlinks must be relative, lexically canonical, root-confined, and resolve directly to a manifest-bound regular file; absolute targets and symlink chains fail. Hardlinks, devices, FIFOs, sockets, continuation/unknown types, sparse/PAX metadata ambiguity, absolute or traversal paths, backslashes, duplicate/case-fold-colliding paths, missing parents or targets, any top-level directory other than the single `bin` and `externals` trees, a missing/duplicated `bin/Runner.Listener`, and mutable runner state (`_work`, `_diag`, `_update`, `.runner`, `.credentials*`) fail closed.

  Acquisition is a bounded two-pass operation over one no-follow archive descriptor positively proven regular, single-link, seekable, and stable in device/inode/size/mode/mtime before, between, and after both passes. Pass one verifies the exact compressed digest before parsing, disables gzip multistream, rejects any second member or raw trailing byte, accepts only bounded zero tar-record padding after the end markers, and applies fixed release-locked ceilings to compressed bytes, entry count, resolved path/link bytes, individual file bytes, and cumulative expanded bytes. The initial ceilings are 256 MiB compressed, 16,384 entries, 512 bytes per path/link, 256 MiB per file, and 1 GiB expanded—each above the measured pinned archive anchor (226,035,903 compressed bytes; 11,433 entries; 129-byte maximum path; 131,464,856-byte maximum file; 675,809,636 expanded regular bytes) but deliberately bounded; a future upstream archive that exceeds them stays hosted and requires a reviewed candidate-constant change. Both passes consume only `archive/tar.Reader`'s resolved `Name` and `Linkname`, reject nonempty PAX metadata, apply the same positive `{directory, regular, symlink}` type allowlist and canonical-entry validator, and compare the same sealed entry sequence, so PAX/GNU extension handling cannot diverge. Pass one completes all type/path/link/collision/content-hash/shape checks before an output path exists. Pass two rewinds that same held descriptor, revalidates every resolved header and content hash against the sealed manifest, and writes a new private snapshot through descriptor-relative no-follow operations; any pass-two or final-verification failure removes the entire snapshot.

  Only `VerifyRunnerDirectory` over the completed snapshot may emit its manifest/tree lock/runtime lock and final `READY`; extraction or a logical manifest digest alone grants no build or deployment authority. Evidence generation is caller-owned authority metadata: identical content retains the same manifest/tree digest, while the runtime lock and `READY` bind the nonzero generation and therefore change across generations. `VerifyDirectory` remains the independent OS-identity gate for optional seed publication.

  **Installed-image implementation finding (2026-07-28):** the private verified runner and seed staging roots are intentionally mode `0700`, but copying that root mode unchanged would make the strict image unreadable by numeric UID/GID `65532`. Image assembly therefore performs one explicit root-only mode transition after copying an already-authorized tree: installed `/opt/actions-runner` and `/opt/portable-ghar/seed-cache` are root-owned mode `0555`, while every manifest-bound child object, byte, mode, and symlink target remains unchanged. A distinct non-authorizing `RunnerImageVerification` re-walks the installed runner root with descriptor-relative no-follow semantics, requires UID/GID `0`, root mode `0555`, the exact manifest/tree/runtime-lock/`READY` generation tuple, exactly one listener, and no extra object. It is type-separated from `VerifiedRunnerDirectory` and cannot publish or extract. The seed gate already requires the analogous installed root shape and re-verifies its canonical manifest/tree/`READY`.

  Image config keeps the closed three-entry nonsecret environment (`HOME`, `LANG`, `PATH` above). Held-runner creation adds the exact TLS-only loopback proxy quartet, and listener exec carries that same seven-entry runtime set plus the one-use JIT entry. Host-runtime readback normalizes ordering for the held set but requires exactly those names and values, rejects duplicate/unknown/secret-bearing entries, rejects `HTTP_PROXY`/`http_proxy`, and continues to require an empty environment for the scratch adapter; the listener exec boundary additionally requires canonical ordering. Per-image `.dockerignore` files use a deny-all/positive-allowlist form so only the Dockerfile, final verified runtime/seed trees, and static target binary enter each context; the downloaded archive, transfer metadata, native verifier, source tree, and mutable staging paths do not. CI tests the effective context exclusions, not only the pattern text. Back-to-back image-ID equality remains a true-fail Task-5 gate; if the pinned Debian dependency installation is not reproducible without the later hermetic-release normalization, Task 5 stays typed source/target-conformance pending rather than weakening the comparison or claiming Task-14 evidence early.
- [ ] **Step 6: Build immutable seeds and verify.** Copy verified seeds mode 0555 into `/opt/portable-ghar/seed-cache` on the read-only image; `hydrate-seeds` copies selected content into that runner's private tmpfs before listener release. Absence of a manifest builds an empty seed cache. Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/hostruntime ./internal/archive ./cmd/portable-ghar-runner-gate ./cmd/portable-ghar-network-adapter && bats tests/shell/fetch-runner.bats tests/shell/action-tool-archive.bats`. Expected: `SourceVerification` PASS, including corrupt digest/license, skipped OS-identity verification, mid-hash mutation, hardlink/mount crossing, tracked archive, immutable seed, relay same-UID replacement/flood/path/mount tests, cross-job mutation tests, version-smoke/tree-lock failure, duplicate-version/update-staging rejection, closed operation ordering, and a compile-time/projection test proving source-only evidence cannot construct deployment eligibility. Linux-only seccomp enforcement, cgroup/tmpfs, namespace, peer-instance, image/tree, process-inventory, listener, whole-container reclamation, and forced-version-bump proofs remain typed `TargetConformance` pending; neither unit tests nor macOS Dockerfile inspection may aggregate them into green. No live runner file sweeper is added. After exact-diff distinct-family review and all locally executable gates pass, commit: `git commit -S -m "feat: create held runner with verified immutable seeds"`.

### Task 6: Install and Verify Bounded Broker Egress Before Listener Release

**Files:** Create `internal/networkjail/{policy,ranges,orchestrator,budget,token_ledger,dial_authority,dial_client,connect_parser,doh,broker_parser,broker_dialer}.go` and tests/fuzz targets; modify `internal/hostruntime/{engine,dockercli}.go` and tests; create `cmd/portable-ghar-network-{helper,verifier,broker-parser,broker-dialer}/main.go` and tests; scratch-based Dockerfiles under `images/network-{helper,verifier,broker-parser,broker-dialer}/`; release-locked `images/trust/ca-bundle.lock.json`; and the legacy helper dependency manifest/SBOM fixture under `images/network-helper/legacy/`.

**Interfaces:** `PolicyManifest{EgressBackend, IPFamily, BrokerIPv6Posture, EnabledProtocols, AllowedConnectPorts, DoHBootstrap, DynamicDeny, DockerHost, JobOpenCap, JobDialRate, JobDialBurst, DoHOpenCap, DoHDialRate, DoHDialBurst, TailTimeoutSeconds, ConntrackEntriesPerActualDial, HostReserveEntries, PositiveProbes, NegativeProbes}`; `Compile(PolicyManifest) (DecisionGraph, Digest, error)`; `Budget.Compute(manifest, maxRunnerCapacity) (ConntrackBudget, error)`; controller-owned `DialAuthority.Consume(ctx, DialPermitRequest{CapacitySlotID, JobGeneration, Class, Sequence}) (Permit, error)` obtains time only from its injected trusted monotonic clock, durably persists before returning, and retains each slot across job/restart/reduction for at least `T`; dialer-side `DialPermitClient.Request(ctx, ...)` has no time field; `BrokerParser.Serve(ctx, JobSocket, DialerControl, PolicyManifest) error` reads untrusted CONNECT/SOCKS bytes, opens no `AF_INET`/`AF_INET6` socket (seccomp-enforced), and emits only a fixed bounded `DialRequest{Host, Port}` struct to `DialerControl`; `BrokerDialer.Serve(ctx, DialerControl, DialPermitClient, PolicyManifest) error` owns all DoH and upstream sockets, re-applies the deny classes and port allowlist to every `DialRequest` and resolved answer, and consumes a `DialPermitClient` permit before each `connect()`; `Engine.CreateNetworkBrokerHeld`, `Engine.ReleaseNetworkBroker`; `Jail.Configure(ctx, Adapter, PolicyManifest) (Verification, error)`; verifier returns `ProbeReport{PolicyDigest, EgressBackend, RunnerNetNSID, BrokerNetNSID, RunnerTablesEmpty, RunnerConntrackEmpty, ParserHasNoSocket, PositiveOK, NegativeOK, ConntrackBudgetOK}`; audit returns the same identities plus exact adapter/held-broker release/socket/authority/policy/budget assertions. `EgressBackend` is exact `restricted-broker-v1` or qualified `nftables-direct-v1`, `IPFamily` is `public_ipv4_only` or `public_dual_stack`, `BrokerIPv6Posture` is exact `deny-via-ip6tables` or `kernel-disabled`, and `EnabledProtocols` contains only the closed CONNECT protocol set; no auto-detection or fallback exists on any axis.

- [ ] **Step 1: Write failing range, parser, trust-root, and budget tests.** Cover every prohibited IPv4/IPv6 class, dynamic host/bridge/management routes, literal/parser disagreement, DNS answers containing any denied address, and resolve-then-dial rebinding. Fuzz HTTP CONNECT request lines/headers and optional SOCKS5 CONNECT; reject NUL/control/obs-fold, multiple/conflicting authorities, userinfo, invalid/overlong IDNA, malformed bracketed IPv6, unsupported port, plaintext absolute-form HTTP, SOCKS BIND/UDP, trailing request smuggling, slowloris, and oversized input. Require fixed public DoH bootstrap IPs plus TLS server name, bounded persistent control sockets, validation of every A/AAAA answer, literal-IP dial after validation, and no hostname dial. Verify the CA lock's source revision/SHA-256/license/SBOM path and reject missing, expired, wrong-name, or untrusted TLS chains. Test checked `classBudget = factor * (2*openCap + burst + ceil(rate*tailTimeout))`, separate job/DoH classes, summed capacity plus `hostReserveEntries <= nf_conntrack_max`, overflow rejection, runtime timeout above configured `T`, max/count drift, and clock rollback. Prove the parser process cannot create an `AF_INET`/`AF_INET6` socket (seccomp), that it emits only a fixed bounded `DialRequest{Host,Port}`, and that the dialer independently re-applies the enumerated deny classes and port allowlist to that struct and to every resolved answer so a compromised parser reaches nothing denied; test the enumerated classes including `::ffff:169.254.169.254`, alternate-numeric IPv4 literals, and a mixed RRset in which one denied record fails the whole CONNECT. Prove the dial authority reserves in durable blocks (one fsync per block, not per `connect()`), never refunds a reserved block on crash, and reclaims over-count only after `T`; prove a new boot identity with a proven-empty conntrack table rebases consumption to zero exactly once while in-boot clock regression still fails closed.
- [ ] Add compile/runtime tests proving the broker permit frame has no time/refill field; arbitrary broker bytes cannot influence the authority clock; and only the injected monotonic fake advances/refills deterministic test buckets.
- [ ] **Step 2: Write failing orchestration and emptiness tests.** Require exact persisted order `adapter created -> adapter emptiness verified -> broker created/started held as namespace owner -> NET_ADMIN-only broker-policy helper -> helper exit/gone -> policy checkpoint -> controller-owned per-slot dial authority started/verified -> authority checkpoint -> same broker released once -> broker-release checkpoint -> adapter-to-per-job Unix socket identity -> CONNECT verifier positive/negative -> egress checkpoint -> held runner joins exact adapter netns without mount/endpoint mutation -> final audit of both namespaces/sockets/policy/budget -> readiness digest armed -> readiness release`. Prove no arm state exists before the final audit checkpoint. Prove the held broker opens no listener/resolver/upstream socket, no separate anchor exists, and restart reconciles or removes every orphan by persisted container ID. Prove runner direct IP/DNS/TCP/UDP/ICMP and private CONNECT fail. Kill/timeout/corrupt every component; replace/rebind/symlink either socket directory; mutate a namespace/table/route; crash the broker repeatedly; roll the clock/ledger state back; exhaust Unix/client/upstream FDs; and simulate hidden parallel fallback. Every ambiguity destroys the environment and no untrusted listener exists during setup/audit.
- [ ] **Step 3: Implement the restricted QTS broker profile and durable dial authority.** The adapter from Task 5 byte-relays one loopback TCP stream to one AF_UNIX stream and never parses/dials. Create/start the broker once in held mode as its namespace owner; apply policy while it is held; start and verify the controller-owned per-slot authority; only then release that same broker PID exactly once through a fixed host-runtime action. The per-job broker identifies the job solely by its dedicated relay socket path, parses CONNECT with bounded reads, uses fixed DoH bootstrap IPs, validates every result, disables automatic Happy Eyeballs, and calls a literal-IP dial function only after its client obtains a committed permit from that authority. The authority is the only writer to canonical controller SQLite, validates Unix peer plus active slot/job generation/monotonic sequence, reads time only from its injected trusted monotonic clock, fsyncs token and clock state before reply, and never refunds a lost permit. Broker requests contain no wall/monotonic timestamp or refill hint. Broker receives the authority directory read-only; adapter/runner see neither it nor the database. Each slot ledger survives broker restart, job teardown/reassignment, and capacity reduction for at least `T`; assignment never resets/refills it, rollback/clock regression fails closed, and guarded garbage collection requires no live reference plus elapsed `T`. Every FD is close-on-exec. Apply separate hard caps to loopback clients, AF_UNIX streams, authority clients, upstream job sockets, DoH sockets, buffers, and memory. The runner sets upper/lower-case `HTTPS_PROXY`/`https_proxy` to `http://127.0.0.1:<fixed-port>` and upper/lower-case `NO_PROXY`/`no_proxy` to `127.0.0.1,::1`; `HTTP_PROXY`/`http_proxy` are set only when the workflow has no plaintext-HTTP dependency because absolute-form HTTP is rejected. Optional SOCKS5 is separately configured. Direct/non-proxy traffic has no route.
- [ ] **Step 4: Build the broker jail, TLS roots, and optional direct profile.** The QTS broker namespace uses the scratch iptables-legacy closure with exact restore/save binaries, loader/libraries, `libxtables`, complete extension directory, canonical path/digest manifest, SBOM, and missing-extension tests. Its run manifest sets `XTABLES_LOCKFILE=/run/xtables.lock` with only `/run` writable as `rw,noexec,nosuid,nodev,size=64k,mode=0700`. Apply/read back exact default-drop/private-deny rules before broker release; the broker has no capability, Docker access, runner data, shell, or package manager. Copy the checksum-verified release-locked CA bundle into broker and verifier scratch images, record source/license/SBOM, and make trust-root rotation a reviewed dependency-lock/image-digest change that must repeat target TLS conformance. `nftables-direct-v1` remains disabled unless a different host profile proves an exact pre-conntrack allocation ceiling; no filter-only approximation is implemented.
  **Source implementation finding (2026-07-28):** verifier execution is split
  into a capability-less one-shot observation and a controller-completed final
  proof. `ProxyProbeReport` is the exact canonical JSON emitted from the runner
  namespace and contains only policy/backend identity, runner namespace
  identity, loopback/table/conntrack emptiness, and positive/negative results.
  The host runtime separately enters the released broker namespace to obtain
  its identity, revalidates the broker parser's AF_INET/AF_INET6 seccomp
  readiness, and emits opaque `AdapterEmptinessEvidence` and
  `NetworkEgressEvidence`. A closed `VerifierSpec` binds the digest-pinned
  image, build ID, fleet generation, adapter handle, non-root user, seccomp
  profile, and one-shot resource limits. Every verifier uses a fresh
  nonce-derived 128-bit container name, `--rm`, no mounts/environment/logs,
  and an exact absence query; an ambiguous lingering verifier is removed by
  that exact name under a cancellation-independent bounded cleanup context and
  absence is re-proven before control returns.

  `networkjail.Orchestrator` accepts the same canonical `DecisionGraph` bytes
  as the runtime policy, a target-read `Budget`, explicit maximum runner
  capacity, and the closed verifier specification. It computes the conntrack
  budget with checked arithmetic, carries only the opaque host-runtime
  evidence across stages, and performs the held-runner plus broker audit before
  arming. The final controller `ProbeReport` then adds the broker namespace,
  parser sandbox, and `ConntrackBudgetOK` proof and binds the policy, graph,
  budget, adapter, broker, runner, build, and generation identities. The
  production Unix constructor requires the real host engine, state journal,
  and Unix dial-authority manager; source tests cannot manufacture either
  opaque evidence type or target conformance.

  The trust input is release-locked to curl's Mozilla-derived
  `cacert-2026-07-16.pem` (SHA-256
  `3ff344e30b9b1ed2971044eabb438a08f2e2245ddb5f8ab1a3ad8b63ab4eaf91`,
  MPL-2.0). The legacy helper closure is pinned to the Debian bookworm
  `20250101T000000Z` snapshot and enumerates `iptables` plus the exact seven
  loader/library dependencies, every extracted path/mode/digest, the complete
  107-file xtables extension directory, and SPDX metadata. Context preparation
  verifies every archive and installed path before emitting the four static
  scratch-image contexts. These are source locks only: Docker reproducibility,
  Linux seccomp/namespace behavior, QTS policy application, live conntrack
  measurements, workflow canaries, and all numeric sizing selections remain
  typed target gates.

- [ ] **Step 5: Prove conntrack and workflow-compatible behavior on the target.** Measure the conservative per-actual-dial factor across success/refusal/timeout/normal close/SIGKILL/container removal including broker plus host NAT. Runtime-probe `T` and prove every broker FD teardown moves every tracked flow out of `ESTABLISHED`; if any entry remains established, use the full established timeout in the formula or reject the profile. Flood loopback clients, unique destinations, retry/fallback, and repeated broker crashes. Persist token consumption before each actual connect and across stable slot reuse; prove global count delta never exceeds the checked formula, established-stream throughput remains unthrottled, and job/restart generations cannot refill tokens. Prove namespace-creation/raw-socket/BPF attempts fail under runner seccomp. Run GitHub runner transport plus current workflow tool canaries through CONNECT; record unsupported tools rather than widening the profile silently.
- [ ] **Step 6: Verify and commit.** Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/networkjail ./cmd/portable-ghar-network-helper ./cmd/portable-ghar-network-verifier ./cmd/portable-ghar-network-broker-parser ./cmd/portable-ghar-network-broker-dialer -count=20`, parser fuzz targets, and tagged QTS Docker conformance. Expected: PASS with runner namespace/table/conntrack emptiness, exact broker policy, bounded dials/FDs/memory, complete negative probes, final/periodic audit match, and no setup helper overlapping the untrusted listener. Commit: `git commit -S -m "feat: gate listeners on bounded broker egress"`.

### Task 7: Implement One-Job JIT Lifecycle and Secret-Bound Reconciliation

**Files:** Create `internal/lifecycle/service.go`, `internal/lifecycle/names.go`, `internal/lifecycle/service_test.go`, `internal/controller/reconciler.go`, `internal/controller/reconciler_test.go`.

**Interfaces:** `Lifecycle.Prepare(ctx, Assignment) (RunnerSlot, error)`; `Release`, `Observe`, `Destroy`; `Reconciler.Once(ctx) (CycleReceipt, error)`; `CycleReceipt{CycleID string; CompletedAt time.Time; AssignmentCount int; OldestAge time.Duration}`.

- [ ] **Step 1: Write failing fault-injection tests.** Fail before and after every external effect and persisted checkpoint from adapter creation through release arm. Assert one deterministic opaque runner name per offer, JIT generation only after capacity reservation, immediate upstream-registration cleanup on container failure, no JIT persistence/logging, no duplicate adapter/held-broker/runner after restart, exactly one broker release and listener release, orphan container/socket reconciliation by persisted identity, per-job relay/dial-authority directory cleanup with stable ledger retention through `T`, completion/cancellation cleanup, and one terminal DESTROYED row.
- [ ] **Step 2: Add reassignment tests.** Feed one workflow job under successive request IDs and two runners that bind in opposite order; bind from observed runner name/request ID, never duplicate a slot, and retire canceled obsolete offers without killing a runner already bound to a live request.
- [ ] **Step 3: Implement persist-intent/effect/read-back.** Before retrying an ambiguous JIT create, query the deterministic runner name; before retrying Docker create, list opaque managed labels; after release ambiguity, stop acquisition, read GitHub runner and Docker state, then reconcile to running, finished, or destroyed.
- [ ] **Step 4: Exercise every state.** Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/lifecycle ./internal/controller -run 'TestLifecycle|TestReconcile' -count=50`. Expected: PASS with zero duplicate create/release calls.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: reconcile one-job JIT runner lifecycle"`.

### Task 8: Wire Polling, Admission, Acquisition, Health, and the Controller CLI

**Files:** Create `internal/controller/service.go`, `internal/controller/service_test.go`, `internal/observability/events.go`, `internal/observability/events_test.go`, `internal/health/{snapshot,publisher}.go`, `internal/health/*_test.go`, `cmd/portable-ghar-controller/main.go`, `cmd/portable-ghar-controller/main_test.go`.

**Interfaces:** `Service.Run(ctx) error`, `Service.ReconcileOnce(ctx) (CycleReceipt, error)`; canonical `AcquisitionPolicy`, `AcquisitionTransitioner`, injected host-local `FleetGuardProvider`, and injected lease-backed `AcquisitionPermitProvider`; injected `FatalTerminator.TerminateAfterPersist(reason)` for the unjoinable-call path; `HealthPublisher.Publish(ctx, Snapshot) error`; CLI commands `run`, `probe`, `reconcile --once`, `drain --policy=wait|cancel`, `acquisition --set=disabled|canary-only|enabled --expected=disabled|canary-only|enabled --eligible-scale-set NAME --json`, and `status --json`. `--eligible-scale-set` is required exactly once for `canary-only` and rejected for other modes. The CLI changes local intent only and can never mint, cache, or bypass the signed Worker lease; the provider derives its operation proof locally.

- [ ] **Step 1: Write failing service tests.** Prove broker lease precedes `Poll(maxCapacity)`; demand comes from `TotalAssignedJobs`, not message length; offers/acquisition results/terminal events persist before Ack; duplicate batches are harmless; rejected acquisitions create no runner; one repository cannot consume another's lease. Exercise `disabled -> canary-only -> enabled -> canary-only -> disabled`, host-pressure reduction, watchdog stop, failed probe, suspend, and observer startup; every transition closes the gate, increments the epoch, discards cached Worker authority, joins prior pollers/critical sections, and opens no new section or lease install before join. Delay a poll across each narrowing, crash after epoch increment, replay a stale capacity lease, delay an old-epoch heartbeat response, restart with an old cache, exercise enabled-disabled-enabled ABA, race the deadline handler against admission, and inject a poll/acquire/JIT call that ignores cancellation. Cover exact deadline equality, overflow, every reserved-tail slice, insufficient slack, late success, same-epoch and transition-owned fatal paths, and ambiguous remote completion. Suspend or deschedule after durable effect intent, after the last pre-effect check, and while Ack/release is in flight; prove the deadline handler stays armed, the held-listener gate rejects at the point of an expired release, and a handler or post-effect-check loss cannot release a runner or cause a second invocation. Ack itself grants no acquisition authority. Canary-only accepts exactly its persisted scale set at capacity one and rejects every other repository/scale set. For every nonzero poll/acquire/JIT, atomically snapshot one whole current cached signed lease and derive one local operation proof bound to operation ID/kind, repository, scale set, local policy epoch/digest, Worker transition/lease generation, and checked local deadline. Reject an expired, wrong-operation, wrong-policy, wrong-repository, wrong-scale-set, superseded, mismatched, or unavailable lease/proof. Prove derivation makes no remote call, creates no remote per-operation state, and final admission revalidates one whole current cache entry. Prove a successful admin-status read or local CLI transition grants no authority. On any acquisition revocation (mode change, pressure, watchdog stop, hold, archive latch, or failover-driven drain), prove the controller terminates every runner past `RUNNER_HELD` that has not reached `JOB_RUNNING`, that a `JOB_RUNNING` runner drains uninterrupted, and that a released listener observing a superseded acquisition epoch or fence generation at job-accept destroys itself; the health snapshot's un-assigned released-listener count must reach zero before the drain reports quiescence.
- [ ] **Step 2: Write failing health/log tests.** Publish only after a completely successful reconciliation; expose only approved fleet alias, acquisition state, local acquisition-policy epoch, canonical SHA-256 policy digest over mode/exact eligible set/max capacity/repository-policy revision/per-repository maxima and eligibility, capacity summary, assigned count/age, un-assigned released-listener count, terminal time, profile/degraded flag, and build ID. Assert raw eligible scale-set names, job names, repository coordinates, request bodies, JIT, tokens, paths, routes, and command output are rejected from logs/diagnostics; only the digest enters the heartbeat.
- [ ] **Step 3: Implement one bounded acquisition-policy barrier and ordered external-effect guard.** One session loop per configured repository feeds the central broker. Every mode, eligibility, or effective-capacity change closes the existing gate, compare-and-sets the persisted policy and atomically discards cached Worker authority, cancels and joins older critical sections, and reopens only after zero remain; new critical sections, heartbeat lease installation, and cache use are denied while closed. The root-only CLI, watchdog/probe stop, broker pressure change, shutdown, suspend, and observer normalization all call that same interface. Every cached signed lease authenticates the local acquisition epoch, and install/use requires exact current epoch/digest equality. Each poll/acquire/JIT operation registers under one epoch, holds the current `portable` host guard, and computes one checked authority-clock deadline as the earlier of `now + configured call duration` or local lease deadline minus the proven positive cancellation/termination tail. One per-operation mutex serializes its deadline handler with a two-way completion token. The handler and token remain active through one journal-authorized at-most-once Ack or listener-release attempt, and neither journal nor external I/O holds the mutex. Immediately before the effect, one short barrier requires active/uncancelled/pre-deadline state and one whole current cache entry with the same authority key, epoch/digest, and fence; listener release also carries an original local lease deadline enforced again inside the held-listener gate at the release point. Immediately after a trustworthy success, a second short barrier repeats the checks and only then admits and disarms. Ack is non-authorizing. Late/dropped/ambiguous results zeroize and use existing read-back/idempotent reconciliation without retry or runner release. A same-epoch unjoinable call invokes the existing fatal/zero-capacity terminator; after a transition closes the gate, the transition owner waiting on that critical section owns the fatal path. Task 8 lands the executable command boundary but leaves its production controller/admin factories fail-closed unavailable because the existing public config has no production lifecycle/session/admission/health composition inputs and no production `SetupBuilder`; it must not invent defaults or substitute no-op cleanup. Task 10 replaces the controller factory from its complete runtime manifest and still injects unavailable host and remote providers initially, so `run` cannot perform nonzero work; Task 9 supplies only host authority and the failover client plan later supplies the remote provider. Tests inject fakes independently. `disabled=0`; `canary-only=1` for exactly one persisted canary scale set; `enabled=broker limit`. No local code imports a routing writer.
- [ ] **Step 4: Verify.** Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/controller ./internal/observability ./internal/health ./cmd/portable-ghar-controller -count=20`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: wire controller acquisition and health cycles"`.

### Task 9: Add Host Profiles and the Exclusive Fleet-Generation Fence

**Files:** Create `internal/hostruntime/profile.go`, `internal/hostruntime/qts/{profile,discovery}.go`, `internal/hostruntime/systemd/profile.go` and tests; `internal/fleetfence/{store,store_unix,controller_adapter}.go` and tests; `cmd/portable-ghar-fleet-fence/main.go` and tests; modify `cmd/portable-ghar-controller/main.go` and its tests to replace the unavailable provider; create `deploy/qts/run-legacy-fenced.sh`; create `tests/shell/qts/fleet-fence.bats`.

**Interfaces:** `HostProfile.Probe(ctx) (ConformanceReport, error)`; `HostProfile.DiscoverNetworks(ctx) (NetworkSnapshot, error)`; `fleetfence.ControllerAdapter` satisfies only `controller.FleetGuardProvider`; `portable-ghar-fleet-fence guard --fleet portable|legacy --generation N -- COMMAND` holds a shared guard for the command lifetime; `inspect` is read-only; `handoff --from portable|legacy|none --to portable|legacy|none --expected-generation N` holds the exclusive lock and returns N+1. Add compile-time interface assertions against the canonical contracts. Host fencing never substitutes for the separate Worker permit provider.

- [ ] **Step 1: Write failing profile and fence tests.** Reject non-Linux, unsupported architecture/runtime/kernel, missing resource enforcement, selected-profile failure, profile auto-fallback, incomplete route discovery, unsafe private-file mode, automatic degraded-root selection, malformed state, stale generation, wrong active fleet, reused owner/PID/boot identity, and unlocked mutation. The QTS reference profile must select `restricted-broker-v1`, reject `nftables-direct-v1`, positively prove runner `--network none`, empty runner iptables-table and conntrack views before/after loopback flood, namespace/raw/BPF seccomp denial, held broker opening no socket before one-use release, broker legacy-filter restore/read-back before release, exact IPv6 posture, relay plus dial-authority socket-directory mount identities/modes, fixed DoH/bootstrap/port/TLS-root policy, controller-mediated durable consume-before-dial state, and measured conntrack entries per actual dial. Capture `nf_conntrack_count/max` and every budgeted timeout; reject arithmetic overflow, `hostReserveEntries >= nf_conntrack_max`, or `maxRunnerCapacity * (jobClassBudget + dohClassBudget)` above `nf_conntrack_max - hostReserveEntries`. Re-read count/max/timeouts/token state on every health cycle; any drift recomputes the checked budget and reduces capacity or safe-stops through the epoch barrier before another acquisition. Require an operator-approved sizing tuple covering `/runner` and `/tmp` tmpfs, runner memory/swap, maximum active concurrency, and release-observation cadence. Reject the tuple unless measured p99 plus margins fits each tmpfs, the sum of runner tmpfs sub-limits plus process margin fits the memory cgroup, and checked `maxActive * runnerMemory + maxActive * auxiliarySlotMemory + idleControlPlane + candidateBuildAndSmokePeak + hostAndGatewayReserve <= usableHostMemory`; never count swap as RAM capacity or count tmpfs pages twice outside their memory cgroup. Seed the incident regressions with 666 MiB idle, 2,162 MiB `/runner` peak, 32 GiB host RAM, six legacy slots, and the invalid 2 GiB-memory/3 GiB-tmpfs pair, but make no numeric production selection in public source. Require checked nonzero free-byte/free-inode thresholds for each distinct Docker-root/state/staging/rollback/scratch/log filesystem, exact simultaneous old/new/temp/rollback/complete-slot/retained-ledger/log growth accounting, and bounded controller/watchdog/Docker log retention; reject staging before a write and safe-stop recurring acquisition when warning/stop thresholds cross. Run a target soak with synthetic adapter/broker/runner and repeated audits to prove ordinary Docker/QTS daemons do not mutate either namespace or socket path. Accept degraded root only with exact configured profile `qts-capless-root`, empty capability sets, and a visible health flag. Test multiple same-fleet holder records, stable-lock inode identity across header replacement, blocked exclusive acquisition, crash release, per-holder renewal, stale holder cleanup, and force-disabled observer restart while `legacy` owns the fence.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.6 go test ./internal/hostruntime/... ./internal/fleetfence ./cmd/portable-ghar-fleet-fence -v`. Expected: FAIL because the fence and profiles are absent.
- [ ] **Step 3: Implement one atomic host-local authority.** Hold `flock` shared/exclusive on a stable, never-renamed lock inode. Store `{generation,activeFleet,bootID,updatedAt,operationID}` in a separate same-filesystem fsync/rename header, and one mode-restricted atomic renewal record per `{generation,fleet,ownerID,pid,bootID}`. Every handoff compares the expected generation under the exclusive lock, waits for all shared guards to close, increments exactly once, and retires old holder records without changing the lock inode. Controller advertisement/acquisition holds a current guard across the effect; the watchdog holds one across any non-disabled restart; `run-legacy-fenced.sh` holds one for the restored legacy process lifetime. Force-disabled observer restart is the sole no-guard exception: before any loop opens it compare-and-sets the persisted acquisition policy to disabled/empty eligibility/zero capacity through a new epoch, then proves zero before/after launch. A stale process cannot repair or reset the fence.
- [ ] **Step 4: Prove race exclusion on the target filesystem contract.** Race new-controller and new-watchdog restarts against restored legacy launcher/watchdog processes for 1,000 iterations, kill holders between lock and header rename, replay prior manifests, reuse PIDs across boot IDs, and fail each holder's renewal independently. Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/fleetfence -count=100 && bats tests/shell/qts/fleet-fence.bats`; then run the same filesystem conformance against the QTS state volume. Expected: same-fleet guards coexist, exclusive handoff waits for all of them, no observation contains both fleets, the stable lock inode never changes, and every stale/non-current process fails before acquisition.
- [ ] **Step 5: Commit.** Stage only the Task 9 files, including the controller entrypoint/provider wiring, then `git commit -S -m "feat: fence portable and legacy fleet generations"`.

### Task 10: Add Crash-Resumable QTS Installation, Suspend, Resume, Rollback, Uninstall, and Watchdog

**Files:** Create `internal/hostruntime/{runtime_manifest,operation_journal}.go` and tests; complete the production controller-composition schema/factory in `internal/config/runtime.go`, `cmd/portable-ghar-controller/main.go`, and their tests; create `cmd/portable-ghar-watchdog/main.go` and tests; `cmd/portable-ghar/main.go` plus `internal/cli/host.go` and tests; `deploy/qts/{install-controller,verify-controller,suspend-controller,resume-controller,rollback-controller,uninstall-controller,install-watchdog,uninstall-watchdog}.sh`, `deploy/qts/watchdog.cron.example`, `deploy/qts/lib/{runtime-manifest,operation-journal}.sh`; `deploy/systemd/*.service` and `*.timer`; `tests/shell/qts/{controller-install,controller-verify,controller-suspend,controller-resume,controller-rollback,controller-uninstall,watchdog}.bats`.

**Interfaces:** `RuntimeManifest` has the canonical typed fields above, `AcquisitionDefault == "disabled"`, and a nil `ArchiveManifestDigest` only when the optional archive input is absent. Every lifecycle operation persists `OperationJournal{OperationID, Kind, Phase, ExpectedGeneration, PriorManifest, TargetManifest, TargetFleet, StartedAt, UpdatedAt}` before effects and resumes/compensates forward by operation ID. `portable-ghar deploy host --private PATH --acquisition disabled` stages to the verified remote QTS target then invokes `install-controller.sh --private PATH --manifest PATH --acquisition disabled` there; `portable-ghar verify host --private PATH --require-zero-listeners` invokes `verify-controller.sh --private PATH --manifest PATH --require-zero-listeners`. `portable-ghar suspend host --private PATH --drain-policy=wait|cancel --hosted-confirmation PATH` invokes `suspend-controller.sh`, which validates fresh typed hosted-hold evidence, reads the current generation, disables the watchdog, transitions acquisition through the bounded policy barrier, drains, stops, proves quiescence, and atomically hands `portable` to `none`. `portable-ghar resume host --private PATH --acquisition disabled` invokes `resume-controller.sh`, which while stopped compare-and-sets any persisted stale policy to a new disabled/empty/zero epoch, reads the current generation, hands `none` to `portable`, starts controller/watchdog disabled, and proves zero listeners. Exact target-side rollback/uninstall commands are `rollback-controller.sh --private PATH --expected-generation N --hosted-confirmation PATH --legacy-command-file PATH` and `uninstall-controller.sh --private PATH --retain-state`.

- [ ] **Step 1: Write failing Bats/CLI and crash-boundary tests.** Require EUID 0, Linux, positive QTS profile/target identity, mode-safe overlay, exact staged manifest and file/image/CA-lock digests, current fence generation, acquisition disabled, zero listeners, and the complete free-byte/free-inode budget on every distinct Docker-root/state/staging/rollback/scratch/log filesystem before staging. Account for simultaneous old/new/temp release bytes, retained rollback, complete configured slot vectors, retained stable ledgers through `T`, state reserve, and bounded logs with checked arithmetic; refuse unbounded logging or a threshold crossing before any install write. QTS tests must reject a non-admin `docker build` invocation, prefer pulling a release-attested immutable candidate, and permit a local build only as administrator or through the separately tested run/exec/commit recovery path rooted in the retained rollback image. Preserve the prior immutable image before candidate staging, require `Runner.Listener --version` and image-digest read-back before any manifest switch, and never retag a mutable live image. Suspend tests require fresh typed hosted-hold evidence, ordered watchdog disable/acquisition-policy barrier/drain/process stop/quiescence, and `portable -> none`; resume and legacy-owned observer tests seed stale `enabled`/`canary-only` SQLite state, require a new disabled/empty/zero epoch before any loop opens, then require `none -> portable` only for resume and zero listeners. Inject an unjoinable upstream call and require fatal persistence plus process death/quiescence rather than a hung lifecycle command or false success. SIGKILL every boundary of install, suspend, resume, rollback, and uninstall, then rerun the same operation ID and require one forward-resumed outcome. Refuse Darwin, digest drift, inline secrets, a non-QTS host, default-enabled acquisition, stale generation, stale/unconfirmed hold evidence, journal mismatch, or any unspecified destination path.
- [ ] **Step 2: Implement journaled install with forward compensation.** The local CLI verifies the overlay target and transfers only the staged manifest/artifacts; before the first target write, the target-side script re-verifies QTS identity, all digests/licenses/attestations, the runner version smoke proof, the retained rollback digest, distinct filesystem identities, free bytes/inodes, projected simultaneous staging/rollback/scratch/state/log use, and exact bounded log-retention settings. It journals each phase, stages immutable images by digest without mutating the selected manifest, fsyncs files/directories, atomically switches `current` only after quiescence, installs an idempotent root-cron watchdog, normalizes persisted acquisition to a new disabled/empty/zero epoch while stopped, starts the controller force-disabled observer when `legacy` owns the fence (or normally disabled when `portable` owns it), and runs `verify-controller.sh --require-zero-listeners`. Portable GHAR has no registered idle runners; a legacy migration must identify idle containers by absence of `Runner.Worker`, drain/remove those first, and prevent any old-image registration from accepting one more job before the candidate switch. The watchdog repeats the storage budget each cycle and invokes the same pressure/epoch safe-stop before a threshold breach. On failure, restore binary/symlink/cron state from the journal and prove acquisition disabled. Never restore a raw fence snapshot or decrement generation; if a handoff already occurred, compensate with another expected-generation transition to `none`. Never install a service on the invoking development/control Mac.
- [ ] **Step 3: Implement exact verify, suspend, resume, rollback, and uninstall semantics.** `verify-controller.sh` reads back manifest/digests, process, observer/acquisition mode, fence, journal, advancing health, storage/conntrack/token budgets, and zero listener/runner/adapter/held-or-running-broker/helper/verifier/dial/per-job-socket requirements; stable slot ledgers are instead verified retained/non-refilled until `T`. Suspend and resume use the same journaled primitives and fail closed without repairing stale state. `rollback-controller.sh` validates but cannot create external hosted-routing confirmation, reuses journaled suspend, atomically hands `none` to `legacy` at the next generation, then launches the captured legacy command only through `run-legacy-fenced.sh`. `uninstall-controller.sh` requires `none` or `legacy` active, removes controller/watchdog registration and binaries atomically, and retains state/backups unless `--purge-state-after-retention` is explicitly supplied.
- [ ] **Step 4: Preserve watchdog authority and dark-observer safety.** The watchdog checks the exact runtime manifest. With `portable` active it holds a current guard across restart; with `legacy` active it first normalizes the persisted acquisition policy and may restart only a force-disabled observer, proving disabled/empty eligibility/`maxCapacity=0` before and after launch. Its local stop calls the same bounded transition interface; an unjoinable call causes fatal process termination and a disabled restart, not a side-flag write or infinite wait. It has no GitHub/Worker/routing dependency. Run `GOTOOLCHAIN=go1.26.6 go list -deps ./cmd/portable-ghar-watchdog | grep -E 'actions/scaleset|internal/githubscale'`; expected no output/exit 1.
- [ ] **Step 5: Verify and commit.** Run `GOTOOLCHAIN=go1.26.6 go test -race ./internal/hostruntime/... ./internal/cli ./cmd/portable-ghar ./cmd/portable-ghar-watchdog && bats tests/shell/qts/controller-install.bats tests/shell/qts/controller-verify.bats tests/shell/qts/controller-suspend.bats tests/shell/qts/controller-resume.bats tests/shell/qts/controller-rollback.bats tests/shell/qts/controller-uninstall.bats tests/shell/qts/watchdog.bats`. Expected: PASS, including journaled crash recovery, forward-only fence compensation, exact master-command dispatch, hosted-hold-gated suspend, disabled resume, legacy-owned dark-observer restart, retention-safe uninstall, and watchdog/legacy race fixtures. Commit: `git commit -S -m "feat: add crash-resumable QTS controller lifecycle"`.

### Task 11: Prove Host, Namespace, Secret, and One-Job Conformance

**Files:** Create `tests/conformance/host_profile_test.go`, `tests/integration/network_jail_test.go`, `tests/integration/one_job_test.go`, `tests/integration/watchdog_test.go`, and `tests/integration/testenv/*.go`.

**Interfaces:** `testenv.StartDockerFixture(t)` returns isolated synthetic networks and public/blocked sentinels; `conformance.Run(ctx, HostProfile) Report` returns a signed-by-build, secret-free evidence document.

- [ ] **Step 1: Write integration tests before harness implementation.** From the actual QTS runner netns prove unique adapter namespace per job, loopback only, no registered iptables table, zero namespace conntrack rows before/after loopback flood, no direct route, and no change after runner attach. Prove proxy-compatible public HTTPS succeeds; every literal and DNS-resolved deny class, direct IPv4/IPv6/DNS/TCP/UDP/ICMP, plaintext HTTP, unsupported CONNECT port, SOCKS BIND/UDP, and non-proxy traffic fail. Prove helper NET_ADMIN-only and gone before held-broker release; adapter/broker/verifier capless; exact relay-directory bind visible only to adapter/broker; exact dial-authority bind visible only to broker; controller SQLite invisible to every container; broker policy/budget/permit ledger match; pinned CA/TLS negative tests pass; parser/fallback/crash floods stay within the measured global conntrack formula; and any component/policy/state loss prevents release.
- [ ] **Step 2: Add sandbox, compatibility, reclamation, and seed proofs.** Inspect the actual runner to prove read-only root, enforced CPU/memory/PID/FD/tmpfs/seccomp/capability limits, namespace/raw/BPF syscall denial, masked `/proc/sys`, no socket mount/device/control secret, strict non-root identity or exact named `qts-capless-root` with UID 0 and every capability set empty, exact smoke-tested runner version, scale-set `DisableUpdate=true`, JIT absence from the listener environment after parsing and from every job/exported diagnostic/log, one fake job completion, deregistration, container destruction, and no reusable workspace. After success, cancellation, pre-listener failure, listener crash, controller restart, and forced-upgrade interruption, positively prove the runner container, cgroup, `/runner`, `/tmp`, `_work`, `_work/_update`, descendant processes, and namespaces are absent within the cleanup SLO. Repeat representative jobs and assert memory/swap/tmpfs/container/process high-water returns to the approved baseline without a monotonic trend; the test must fail if an old/new runner version pair or updater staging survives. Run GitHub listener transport, HTTPS checkout, and each current workflow's proxy-sensitive toolchain through the broker; record any unsupported non-proxy-aware tool as a migration blocker. Verify an immutable action/tool seed hydrates only the current job tmpfs and that mutation is absent from the next runner.
- [ ] **Step 3: Add watchdog/fence proof.** Kill the controller, assert the watchdog restarts it with a current `portable` guard, then hand off to `legacy` with stale canary/enabled policy persisted and prove it first writes a new disabled/empty/zero epoch and restarts only the force-disabled observer, without poll/JIT/acquisition calls. Provide a fake route-writer trap and assert zero calls. Simulate reboot while `legacy` owns the fence by recreating cron, controller state, per-holder records, and the persisted header; prove dark observer recovery and no portable acquisition. Inject a non-cancellable poll and prove the old process terminates before the disabled observer restarts.
- [ ] **Step 4: Run on Linux Docker.** `PGHAR_INTEGRATION_DOCKER=1 GOTOOLCHAIN=go1.26.6 go test -tags=integration ./tests/integration ./tests/conformance -v -count=1`. Expected: PASS on a supported profile; explicit `SKIP unsupported host profile` on other hosts, never a structural-only pass.
- [ ] **Step 5: Commit.** `git commit -S -m "test: prove runner host and network isolation"`.

### Task 12: Add Chaos Recovery, Safe Upgrade Gates, and Operator Evidence

**Files:** Create `tests/chaos/controller_states_test.go`, `tests/chaos/docker_failure_test.go`, `tests/chaos/jail_failure_test.go`, `tests/chaos/fleet_fence_test.go`, `tests/chaos/qts_install_test.go`, `internal/upgrade/{service,runner_release}.go`, `internal/upgrade/{service,runner_release}_test.go`, `docs/operations/controller-upgrade.md`, `docs/operations/controller-recovery.md`, `docs/operations/runner-release.md`.

**Interfaces:** `RunnerReleaseObserver.Observe(ctx) (RunnerRelease, error)` returns exact official tag, immutable release identity, Linux x64 asset name/size/SHA-256, publication time, and observation evidence; `MaintenanceDirectiveProvider.Current(ctx, RunnerMaintenanceStatusRequest) (RunnerMaintenanceDirective, error)` is a read-only, signed, short-lived Worker response; `Upgrade.StageRunnerCandidate(ctx, RunnerRelease) (Candidate, error)`; `Upgrade.QualifyRunnerCandidate(ctx, Candidate) (CompatibilityReport, error)`; `Upgrade.Prepare(ctx, DrainPolicy) error`; `Upgrade.ProveQuiescent(ctx) (Quiescence, error)`; `Upgrade.ValidateReplacement(ctx) (CompatibilityReport, error)`; `Upgrade.ReconcileRunnerRelease(ctx, MaintenanceDirectiveProvider) error` resumes the journal through only its currently authorized phase. The observer and upgrader can observe, stage, disable, drain, probe, and change local acquisition through the standard epoch barrier, but have no route mutation method. They publish typed `runner_upgrade_required`, `candidate_qualified`, or `candidate_rejected` health so the external failover authority can keep routing hosted throughout automatic maintenance.

Phase 2 defines this interface, journal, release observer, candidate builder, and a fail-closed fake/unavailable directive provider for unit and chaos tests. It must not claim an operational unattended upgrade until Phase 3 implements the authenticated Worker client and directive state machine from failover Tasks 2, 3, 4, and 9. The forced-version-bump definition of done is therefore a cross-phase integration proof, not a controller-only unit result.

- [ ] **Step 1: Write table-driven chaos tests.** SIGKILL the controller in every persisted lifecycle state; stop/restart Docker; kill/delay adapter, held/released broker, helper, and verifier; replace/rebind either Unix socket; corrupt/roll back token ledger, clock, conntrack factor/timeout/max, runtime/archive/CA/runner-release manifest, and namespace emptiness; flood proxy/AF_UNIX/host FDs; fail install/suspend/resume/rollback/uninstall before and after every journaled boundary; redeliver/reorder scale messages; ignore cancellation in poll/acquire/JIT; and reboot the watchdog sandbox with stale enabled/canary policy while `legacy` is active. Race every policy narrowing and host-pressure stop against dials/external effects, and race old/new watchdogs and controller/legacy launchers across fence handoff; assert bounded fatal termination for unjoinable calls, no dial without a durable permit, repeated crash never refills tokens, checked conntrack/FD bounds, acquisition stops on ambiguity, generations never decrement, observer mode normalizes to zero-capacity, only one fleet can act, and no duplicate runner/listener/broker appears. Simulate a GitHub-forced runner bump and reject stale, downgraded, unsigned, wrong-platform, ambiguous-asset, digest-missing, digest-mismatched, non-monotonic, or version-smoke-failing observations; prove every rejection leaves the old immutable image and hosted route available, creates no partial live selector, and cannot invoke a file sweeper in a serving runner.
- [ ] **Step 2: Write upgrade tests.** Require one fresh signed `stage-permitted` directive as machine-verifiable hosted/read-back/queue-clear/permit-drain/zero-job evidence before disabling local acquisition and staging or qualifying the exact request-bound candidate. After a `candidate_qualified` heartbeat persists that tuple, require a new `replace-permitted` directive, apply the explicit wait/cancel policy, and prove zero listeners/runners/adapters/held-or-running-brokers/helpers/verifiers/per-job socket directories, broker dials, and pending effects while retained ledgers remain safe through `T`; validate the staged runtime manifest and exact file/image/archive/CA/policy/budget/runner-release digests, signed provenance, `Runner.Listener --version`, scale-set disable-update proof, and host probes; preserve the prior immutable image and selector; atomically select the candidate digest; and emit canary-ready evidence. After exact current-selection/compatibility/zero-listener heartbeat proof, require fresh `canary-permitted` before the standard epoch barrier enters canary-only and fresh `enable-permitted` after the Worker-observed canary before it enters enabled; `complete` is evidence only. Reject cached/expired/wrong-session/wrong-request/wrong-transition/wrong-generation/wrong-config/wrong-tuple/wrong-policy directives and fall back to `wait-hosted` with acquisition disabled. Exercise automatic release observation at the configured cadence, including a bump immediately after a successful job, during a job, during candidate staging, and after controller restart/re-enrollment. Prove an operator hold blocks every runner-upgrade directive, staging, selection, and automatic release while still allowing the release observation/qualified tuple to be journaled; after authenticated operator release, require a fresh non-current heartbeat before re-entering the runner-upgrade sequence. A pending, rejected, interrupted, or directive-unavailable candidate keeps acquisition disabled/hosted and resumes forward without operator intervention. Never restore acquisition or claim failback locally, and never downgrade to a preserved runner image that the compatibility probe says GitHub no longer accepts.
- [ ] **Step 3: Implement exact runbooks.** Document `status --json`, runner-release observation/candidate/directive state, operation-journal, fence-header/holder, and `verify-controller.sh` read-back before/after each step; backup private state outside the public repo; describe journaled install compensation without fence rollback, observer-mode dark startup, compatibility/host probes, secretless canary handoff, rollback via journaled suspend plus fenced legacy handoff, and retention-safe uninstall while hosted routing remains confirmed. The runner-release runbook must distinguish the automatic normal path from break-glass recovery, show all six directive phases and fail-closed retry behavior, prohibit non-admin `docker build` on QTS, prefer a release-attested immutable image, preserve rollback by digest, smoke-test the listener before selection, and drain any legacy idle container identified by absence of `Runner.Worker` before it can take another job.
- [ ] **Step 4: Run chaos repeatedly.** `PGHAR_CHAOS_DOCKER=1 GOTOOLCHAIN=go1.26.6 go test -tags=chaos ./tests/chaos -v -count=10` and `GOTOOLCHAIN=go1.26.6 go test -race ./internal/upgrade ./internal/fleetfence -count=50`. Expected: PASS; Docker/install/fence failures end disabled and recover through read-back without dual acquisition.
- [ ] **Step 5: Commit.** `git commit -S -m "test: harden reconciliation and upgrade recovery"`.

### Task 13: Run the Runtime Release Gate

**Files:** Create `scripts/test-controller-runtime.sh` and `tests/boundaries/runtime_boundary_test.go`; update only runtime files named by this plan when fixing failures.

**Interfaces:** The script runs formatting, vet, unit/race/contract, shell, boundary, image build/checksum, integration, conformance, and opt-in chaos stages and emits one secret-free JSON summary.

- [ ] **Step 1: Write a failing boundary test.** Reject the wrong module/toolchain, Kubernetes/ARC packages, job/service-container orchestration, runner Docker socket/mount/device flags, any adapter bind other than one read-only per-job broker directory, direct QTS runner networking, missing namespace/raw/BPF seccomp denial, plaintext HTTP/SOCKS BIND/UDP support, hostname dial after validation, kernel connect without durable token consumption, hidden parallel fallback, unbounded dial/FD/buffer/memory settings, unpinned scale-set/runner/base/archive inputs, a scale set without explicit `DisableUpdate=true`, any live runner file sweeper, a host-backed reusable work volume, an unapproved/internally inconsistent tmpfs-memory-concurrency-cadence tuple, `Secret.Bytes` or unbounded reader APIs, upstream types outside `internal/githubscale`, scale-set calls without explicit deadlines, multiple/mismatched scale-set labels, any acquisition stop/capacity reduction outside `AcquisitionTransitioner`, routing-writer imports in controller/watchdog, missing fleet-fence checks, missing QTS lifecycle scripts, helper capabilities beyond NET_ADMIN, adapter/broker/verifier capabilities, committed upstream archives/binaries, mutable cross-job caches, and private-identifier fixture patterns.
- [ ] **Step 2: Implement the non-mutating gate script with `set -euo pipefail`.** Run `unformatted="$(find cmd internal tests -type f -name '*.go' -print0 | xargs -0 gofmt -l)"; test -z "$unformatted"`, `GOTOOLCHAIN=go1.26.6 go vet ./...`, `GOTOOLCHAIN=go1.26.6 go test ./...`, `GOTOOLCHAIN=go1.26.6 go test -race ./...`, ShellCheck/Bats, `GOTOOLCHAIN=go1.26.6 go mod verify`, runner/archive checksum corruption tests, QTS install/rollback/uninstall tests, fleet-fence race tests, and tagged suites when their explicit environment gates are set. The gate never rewrites source or generated metadata.
- [ ] **Step 3: Run the non-Docker gate.** `./scripts/test-controller-runtime.sh --unit`. Expected: exit 0 with every unit/contract/boundary stage `PASS` and no secret-shaped output.
- [ ] **Step 4: Run the full Linux Docker gate.** `PGHAR_INTEGRATION_DOCKER=1 PGHAR_CHAOS_DOCKER=1 ./scripts/test-controller-runtime.sh --full`. Expected: exit 0; isolation, QTS sandbox, conformance, and chaos stages `PASS`.
- [ ] **Step 5: Inspect and commit.** Run `git diff --check && git status --short`. Expected: only planned runtime files. Commit: `git commit -S -m "test: gate portable GHAR controller runtime"`.

### Task 14: Rehearse Reproducible Runtime Release Artifacts

**Files:** Create `scripts/release/{observe-runner-release,rehearse-runtime,compare-runtime-rebuilds}.sh`, `tests/shell/{runner-release,runtime-release}.bats`; modify `release/manifest.json`, `.github/workflows/release.yml`, and create `.github/workflows/runner-release-candidate.yml` from the foundation phase.

**Interfaces:** `observe-runner-release.sh --current-manifest <path> --output <path>` emits a canonical candidate manifest for the newest official Linux x64 runner only when its tag/ref, asset name, size, SHA-256 digest, publication time, and monotonic version policy validate; `rehearse-runtime.sh --version <semver> --runner-manifest <path> --output <directory>` performs a clean runtime gate and produces registered controller binaries, the exact runner image, immutable image manifests, SPDX SBOMs, third-party notices, checksums, and provenance subjects; `compare-runtime-rebuilds.sh <first> <second>` compares supported binaries byte-for-byte and normalized image manifests by digest without rewriting either tree.

- [ ] **Step 1: Write failing release tests.** Two isolated clean rebuilds of one commit and one canonical runner manifest must match; reject dirty source, unregistered artifact, mutable image tag without digest, missing license/SBOM/checksum/provenance subject, wrong target platform, embedded build path/time, secret/private-identifier finding, stale/downgraded/noncanonical runner versions, missing or non-`sha256:` official asset digest, asset/tag/ref mismatch, duplicate Linux x64 assets, listener-version mismatch, update-staging residue, or an image with more than one runner payload.
- [ ] **Step 2: Run `bats tests/shell/runner-release.bats tests/shell/runtime-release.bats`.** Expected: FAIL because the observer, candidate workflow, runtime rehearsal scripts, and manifest entries are absent.
- [ ] **Step 3: Implement the scheduled observer and hermetic runtime rehearsal.** On the operator-approved cadence, the GitHub-hosted default-branch workflow observes the official `actions/runner` release API with bounded retries, validates the immutable tag/ref and release-asset `sha256:` digest, builds one exact-version image without executing untrusted pull-request code, runs the full runner/version/reclamation compatibility suite, and publishes only a signed, attested immutable candidate manifest/image. Failure publishes no candidate and leaves the prior candidate/current image available. Rehearsal uses pinned Go/tool/image inputs, `SOURCE_DATE_EPOCH` from the commit, stripped deterministic binaries, BuildKit provenance disabled only for the comparison build while the release workflow produces GitHub artifact attestations, normalized OCI manifests, Syft SPDX JSON, license inventory, SHA-256 sums, Trivy source/filesystem/image scans, and `scripts/sanitize_public.py --generated` over every output. Neither local script publishes.
- [ ] **Step 4: Run two rehearsals and compare.** Generate one canonical synthetic runner manifest, run `./scripts/release/rehearse-runtime.sh --version 0.1.0-rc.1 --runner-manifest <path> --output dist/rehearsal-a`, repeat for `dist/rehearsal-b`, then `./scripts/release/compare-runtime-rebuilds.sh dist/rehearsal-a dist/rehearsal-b`. Expected: PASS with registered subjects only and no diff.
- [ ] **Step 5: Integrate and commit.** Update the tag workflow to run the full gate, rehearse once, attest exact archive/SBOM/checksum/image/runner-manifest subjects, and upload immutable assets only after scans pass. The scheduled candidate workflow and runtime upgrader together must survive a forced upstream bump without manual intervention: rejected or unavailable candidates preserve GitHub-hosted execution, qualified candidates enter the external hosted-hold/drain/canary sequence, and no state makes both self-hosted and hosted paths unavailable. Stage only the files named above and commit `git commit -S -m "release: automate qualified runner candidates"`.

## Execution Boundaries and Completion Evidence

- Implementation is complete only when Tasks 1-14 pass in order, the exact dependency/runner/archive/runtime-manifest pins read back from generated artifacts, the fleet-generation race suite proves exclusivity, a supported Linux Docker host produces positive conformance evidence, two runtime release rehearsals compare cleanly, and a forced-runner-version-bump drill proves unattended observation, immutable qualification, hosted continuity, safe drain, canary, rollback preservation, and whole-container reclamation.
- A passing unit suite on macOS, a Docker inspect dump, or a clean command exit alone is not host conformance.
- Acquisition must remain disabled after implementation until an operator separately approves a private overlay, external failover integration, secretless canary, and deployment plan.
- This phase plan covers source/test changes and its scoped signed commits. Push/merge, host access, secrets, service restart, routing mutation, and deployment occur only through the master program's positive gates and the operator's existing authorization; runtime-phase completion alone never triggers them.
