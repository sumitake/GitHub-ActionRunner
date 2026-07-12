# Portable GHAR Controller Runtime Implementation Plan

<!-- markdownlint-disable MD010 MD013 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the fail-closed Go controller runtime that fairly acquires GitHub Actions scale-set work, launches exactly one isolated runner per acquired slot, proves its per-job egress jail before listener release, reconciles crashes idempotently, and runs safely under QTS or standard Linux supervision.

**Architecture:** A pinned `actions/scaleset` adapter translates preview API types into internal offers, statistics, and runner references; upstream types never cross the adapter. SQLite journals assignment transitions and external-effect intent, a weighted/aging broker leases capacity before it is advertised, and a reconciler drives each assignment through the approved state machine. A Docker CLI adapter creates a held runner, joins one NET_ADMIN-only installer and then one capability-less verifier to that runner's unique network namespace, writes a one-use readiness token only after verification, and always destroys the one-job environment.

**Tech Stack:** Go language level 1.26.0 with toolchain 1.26.5; `github.com/actions/scaleset v0.4.0`; `modernc.org/sqlite v1.53.0`; `github.com/google/nftables v0.3.0`; Docker Engine CLI; an explicit nftables or pinned helper-image iptables-legacy policy backend; POSIX shell plus Bats for QTS installation tests; Go unit, contract, integration, conformance, race, and chaos tests.

## Global Constraints

- Phase 1 is a prerequisite and already creates `go.mod`/`go.sum` with module `github.com/sumitake/portable-ghar`. This phase modifies those files, preserves `go 1.26.0` and `toolchain go1.26.5`, and runs every Go command with `GOTOOLCHAIN=go1.26.5`. The scale-set adapter retains its upstream minimum-compatibility contract with Go 1.25.3 while the project builds on 1.26.5.
- Pin `github.com/actions/scaleset` to `v0.4.0`, tag commit `6ce025902cd964747a078c2aabe7340ebc667eca`, module sum `h1:691GC2AkHb3ZGjfNvatboYoRS7CLr3+4VcZk/6w9IbM=`, and record its MIT license. Never use `@latest`.
- Pin the upstream runner to `v2.335.1` and Linux x64 archive SHA-256 `4ef2f25285f0ae4477f1fe1e346db76d2f3ebf03824e2ddd1973a2819bf6c8cf`. A checksum mismatch is fatal.
- Pin the Linux x64 runner base to `debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4`; helper and verifier final images are `scratch`.
- Treat the scale-set dependency as Public Preview. Acquisition stays disabled until compile-time contracts, version fixtures, startup compatibility probes, and host conformance pass.
- Target each GitHub.com repository's scale set by its configured scale-set name and require exactly one label equal to that name. Reject missing, additional, or mismatched labels before acquisition.
- Use `Statistics.TotalAssignedJobs` for demand and pass only broker-leased capacity as `maxCapacity`. Persist complete handling before acknowledging a scale-set message; tolerate redelivery and GitHub reassignment.
- A JobAvailable `runnerRequestId` is an acquisition offer, not a promise that GitHub will bind that job to a particular JIT runner. Persist offers and runner slots separately; bind them only from JobAssigned/JobStarted observations.
- Keep GitHub App keys, JIT configuration, readiness tokens, and secret references out of SQLite, argv, logs, metrics, diagnostics, container labels, and committed configuration. JIT exists only in controller memory and ephemeral container metadata until destruction.
- Zero idle runners is the default. Every runner is fresh, handles at most one job, has no automatic restart, and is forcibly removed after success, cancellation, ambiguity resolution, or error.
- Runners receive no Docker socket, host bind mount, named volume, device, host namespace, control-plane credential, or Linux capability. They use a read-only root, bounded tmpfs, `no-new-privileges`, seccomp, resource limits, and non-root execution unless a named degraded profile is explicitly selected.
- The helper gets only NET_ADMIN and the runner network namespace. The helper must be gone before a capability-less verifier starts; both must be gone before the listener is released.
- Default egress is public IPv4 only with explicit public DNS and all IPv6 denied. An opt-in dual-stack profile may allow public IPv6 only after denying IPv6 local/private/reserved classes and dynamically discovered local routes.
- Unsupported kernels, Docker builds, cgroup enforcement, selected network-policy backend, route discovery, or non-root behavior fail closed. There is no automatic nftables/iptables fallback. Host pressure may reduce capacity and never increase configured ceilings; every effective reduction traverses the acquisition-policy epoch barrier before it takes effect.
- The local watchdog may restart the controller, validate private-file modes, report health, and request a local acquisition stop only through the acquisition-policy transition interface. While `legacy` owns the fence it may run Portable GHAR only in force-disabled observer mode (`maxCapacity=0`) without a Portable guard; any nonzero advertisement, poll, JIT generation, or acquisition requires a current `portable` guard. It cannot mutate repository routing, hold failover credentials, mark external health, or flip a weaker side flag.
- A host-local, lock-protected fleet-generation fence names exactly one active fleet (`none`, `portable`, or `legacy`). A stable never-renamed lock inode supplies shared/exclusive authority; the generation header is a separate atomically replaced file; and each same-fleet controller/watchdog holder renews its own generation-scoped record. Handoff takes the exclusive lock, waits for every old-fleet shared guard to close, increments generation monotonically, and retires old holder records, so stale processes fail closed without a check-then-act race.
- Local acquisition policy persists `{mode, eligibleScaleSets, maxCapacity, acquisitionEpoch}`. Every mode, eligibility, or effective-capacity change compare-and-sets that policy, increments its epoch, cancels and joins old pollers, invalidates their broker leases, and waits for zero acquisition critical sections. Poll, acquire, and JIT calls have explicit deadlines. If an old call ignores cancellation beyond the bounded shutdown deadline, persist `fatal` with zero capacity and terminate the controller process; the caller must observe failure/quiescence rather than a successful return. Canary narrowing, watchdog/probe stops, host-pressure reductions, suspend, and observer startup all use this interface.
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
| Trusted images | `cmd/portable-ghar-{runner-gate,network-helper,network-verifier}/*`, `internal/archive/*`, `config/schema/action-tool-archive-manifest.schema.json`, `images/{runner,network-helper,network-verifier}/Dockerfile`, `scripts/{fetch-runner,stage-action-tool-archive}.sh` | Held listener, optional verified immutable seeds, one-shot policy install, capless probes, pinned runner assembly. |
| Host operations | `cmd/portable-ghar-{controller,watchdog,fleet-fence}/*`, `internal/{hostruntime,fleetfence}/*`, `deploy/{qts,systemd}/*` | Controller wiring, exclusive fleet generation, exact QTS install/verify/rollback/uninstall, root-cron and Linux supervision without routing authority. |
| Verification | `tests/{integration,conformance,chaos}/*`, `scripts/test-controller-runtime.sh`, `docs/operations/controller-{upgrade,recovery}.md` | Live boundary proofs, crash matrices, safe drain/replace/reconcile instructions. |

## Canonical Runtime Contracts

These names and signatures are fixed for this plan. Implementations may add private helpers but must not rename or widen these boundaries.

```go
package controller

type State string

const (
	StateReceived          State = "RECEIVED"
	StateCapacityReserved  State = "CAPACITY_RESERVED"
	StateRunnerHeld        State = "RUNNER_HELD"
	StateNetworkConfigured State = "NETWORK_CONFIGURED"
	StateNetworkVerified   State = "NETWORK_VERIFIED"
	StateListenerReleased  State = "LISTENER_RELEASED"
	StateJobRunning        State = "JOB_RUNNING"
	StateJobFinished       State = "JOB_FINISHED"
	StateDestroyed         State = "DESTROYED"
)

type AssignmentKey struct {
	RepositoryAlias string
	RunnerRequestID int64
	Attempt         uint32
}

type RunnerSlot struct {
	OpaqueName       string
	UpstreamRunnerID int64
	ContainerID      string
	BoundRequestID   int64
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
	Mode              AcquisitionMode
	EligibleScaleSets []string
	MaxCapacity       int
	Epoch             uint64
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
	Poll(context.Context, int, int) (Batch, error)
	Ack(context.Context, int) error
	Acquire(context.Context, []int64) ([]int64, error)
	GenerateJIT(context.Context, JITRequest) (JITConfig, error)
	GetRunnerByName(context.Context, string) (RunnerRef, bool, error)
	GetRunner(context.Context, int64) (RunnerRef, bool, error)
	RemoveRunner(context.Context, int64) error
	Close(context.Context) error
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
	MilliCPU     int64
	MemoryBytes  int64
	PIDs         int64
	ScratchBytes int64
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
	CreateRunner(context.Context, RunnerSpec, SecretEnvFD) (Container, error)
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
	HelperImageDigest     string
	VerifierImageDigest   string
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

type Mode string

const (
	PublicIPv4Only Mode = "public_ipv4_only"
	PublicDualStack Mode = "public_dual_stack"
)

type PolicyManifest struct {
	Mode            Mode
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
- [ ] **Step 2: Verify the tests fail.** Run `GOTOOLCHAIN=go1.26.5 go test ./internal/buildinfo ./internal/redaction ./internal/config`. Expected: FAIL because runtime additions do not exist.
- [ ] **Step 3: Modify the foundation module and add minimal implementations.** Preserve module `github.com/sumitake/portable-ghar`, `go 1.26.0`, and `toolchain go1.26.5`; add scaleset `v0.4.0`, sqlite `v1.53.0`, and nftables `v0.3.0`. Define the backend-neutral network decision graph here; iptables-legacy remains a generated helper protocol rather than a host userspace dependency. `Secret.Use` supplies a scope-invalidated reader only during the callback; `Destroy` best-effort zeroes owned buffers. Immediately convert the upstream immutable JIT string into owned bytes and clear the upstream field, while documenting that Go cannot guarantee erasure of prior immutable string storage.
- [ ] **Step 4: Lock and verify dependency content.** Run `GOTOOLCHAIN=go1.26.5 go mod tidy && GOTOOLCHAIN=go1.26.5 go mod verify && grep -F 'github.com/actions/scaleset v0.4.0 h1:691GC2' go.sum`. Expected: all modules verified and grep prints exactly one module-sum line.
- [ ] **Step 5: Re-run tests and commit.** Retaining a reader after `Use` must return `ErrSecretScopeClosed`; formatting, JSON, and repeated destroy tests pass. Commit: `git commit -S -m "build: pin controller runtime dependencies"`.

### Task 2: Implement the Assignment State Machine and Crash-Safe SQLite Store

**Files:** Create `internal/controller/model.go`, `internal/controller/state_machine.go`, `internal/controller/state_machine_test.go`, `internal/state/store.go`, `internal/state/migrations.go`, `internal/state/sqlite.go`, `internal/state/sqlite_test.go`.

**Interfaces:** Define `State` constants `RECEIVED` through `DESTROYED` exactly as approved; `AssignmentKey{RepositoryAlias string; RunnerRequestID int64; Attempt uint32}`; `RunnerSlot{OpaqueName string; UpstreamRunnerID int64; ContainerID string; BoundRequestID int64}`; `Transition(current, next State, released bool) error`; and `Store` methods `UpsertOffer`, `Reserve`, `BeginEffect`, `CompleteEffect`, `Advance`, `MarkAmbiguous`, `BindRunner`, `ListRecoverable`, `AcquisitionPolicy`, and `CompareAndSetAcquisition(expectedEpoch, nextPolicy)`.

- [ ] **Step 1: Write failing state/store tests.** Cover every adjacent legal transition, idempotent replay, pre-release failure-to-DESTROYED, rejection of skipped/reversed states, post-release ambiguity without duplicate release, unique offer and runner-slot keys, restart recovery, and transaction rollback after injected failure.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.5 go test ./internal/controller ./internal/state -run 'Test(State|SQLite)' -v`. Expected: FAIL with undefined domain/store symbols.
- [ ] **Step 3: Implement the model and schema.** Use WAL, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=FULL`, `BEGIN IMMEDIATE` for reservations, and tables `assignments`, `runner_slots`, `reservations`, `effects`, `acquisition_state`, and `reconcile_cycles`. `acquisition_state` persists mode, exact eligible scale-set list, effective maximum capacity, and monotonic `acquisition_epoch`; compare-and-set requires the expected epoch and every broker poll lease stores the resulting epoch. Store only opaque names/IDs, digests, reason codes, and timestamps; reject secret-bearing columns at the repository API.
- [ ] **Step 4: Prove idempotency and durability.** Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/controller ./internal/state -count=20`. Expected: PASS with one row/effect per idempotency key and no race.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: persist idempotent assignment transitions"`.

### Task 3: Wrap `actions/scaleset` Behind a Pinned Contract Adapter

**Files:** Create `internal/githubscale/types.go`, `internal/githubscale/client.go`, `internal/githubscale/adapter_v040.go`, `internal/githubscale/probe.go`, `internal/githubscale/adapter_contract_test.go`, and versioned synthetic fixtures under `tests/fixtures/scaleset/v0.4.0/`.

**Interfaces:** `Fleet{RepositoryAlias, GitHubConfigURL, ScaleSetName string}`; `Client.Open(ctx, Fleet) (Session, error)`; `Session.Poll(ctx, lastMessageID, maxCapacity int) (Batch, error)`; `Ack(ctx, messageID int) error`; `Acquire(ctx, []int64) ([]int64, error)`; `GenerateJIT(ctx, JITRequest) (JITConfig, error)`; `GetRunnerByName`, `GetRunner`, `RemoveRunner`, `Close`; `Probe(ctx) CompatibilityReport`. Internal `Batch` carries statistics, offers, assigned/started/completed events, and no upstream type.

- [ ] **Step 1: Write failing compile and wire-contract tests.** Assert `*scaleset.Client` and `*scaleset.MessageSessionClient` satisfy private exact-signature interfaces; translate all four job message types; preserve `TotalAssignedJobs`; pass `maxCapacity` unchanged; model nil polls, redelivery, duplicate batch IDs, and the same workflow job reappearing with a new runner request ID. For GitHub.com, reject a scale set unless lookup by `ScaleSetName` returns exactly one label equal to that same name. Against a server that never completes a response, prove each poll/acquire/JIT call obeys its explicit context/transport deadline and returns after cancellation.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.5 go test ./internal/githubscale -run 'TestContract|TestTranslate|TestRedelivery|TestSingleNameLabel' -v`. Expected: FAIL because the adapter is absent.
- [ ] **Step 3: Implement translation and probes.** Call the v0.4.0 API directly rather than its opinionated listener, target the configured GitHub.com scale set by its single scale-set-name label, never expose upstream structs, persist the tag commit/license in `CompatibilityReport`, reject a build whose module version is not `v0.4.0`, require explicit per-operation context deadlines plus HTTP transport/header timeouts, and keep acquisition disabled on fixture, session, cancellation, label, scale-set identity, or JIT shape mismatch.
- [ ] **Step 4: Prove acknowledgement discipline at the boundary.** A fake session must record `Poll -> persist callback -> Ack`; when persistence fails, assert zero `Ack` calls and successful redelivery. Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/githubscale -count=20`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: isolate pinned scale-set preview adapter"`.

### Task 4: Add Resource Ceilings, Weighted Fairness, Aging, and Capacity Leases

**Files:** Create `internal/admission/resources.go`, `internal/admission/broker.go`, `internal/admission/broker_test.go`.

**Interfaces:** `Resources{MilliCPU, MemoryBytes, PIDs, ScratchBytes int64}`; `RepositoryPolicy{Alias string; Weight uint32; AgingThreshold time.Duration; Profile Resources}`; `Broker.Enqueue(githubscale.Offer) error`; `Broker.LeasePoll(repo string, now time.Time) (CapacityLease, error)`; `Broker.Admit(now time.Time) ([]Decision, error)`; `Broker.SetPressure(Pressure) (CapacityChange, error)`; `Broker.Release(controller.AssignmentKey) error`. Add compile-time interface assertions against the canonical contract.

- [ ] **Step 1: Write failing deterministic-clock tests.** Prove no resource dimension exceeds the global ceiling, weighted sequence `repo-a, repo-a, repo-b` for weights 2:1, FIFO within a repository, aging override of an old low-volume offer, no head-of-line starvation across repositories, pressure returns the exact previous/current effective capacity and only lowers availability, and concurrent poll leases cannot over-advertise.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.5 go test ./internal/admission -run TestBroker -v`. Expected: FAIL with undefined broker.
- [ ] **Step 3: Implement weighted deficit round robin.** Charge one deficit per admitted fixed-profile job, skip queues whose head does not fit, select the oldest aged fitting offer first with stable alias/request-ID ties, persist reservations before admission, and calculate each `maxCapacity` as active repository runners plus broker-owned poll leases.
- [ ] **Step 4: Stress invariants.** Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/admission -run TestBroker -count=100`. Expected: PASS with no oversubscription or race.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: broker fair fleet-wide capacity"`.

### Task 5: Build the Docker Engine Adapter and Held Runner Gate

**Files:** Create `internal/hostruntime/engine.go`, `internal/hostruntime/command.go`, `internal/hostruntime/dockercli.go`, `internal/hostruntime/dockercli_test.go`, `internal/archive/{manifest,verify}.go` and tests, `config/schema/action-tool-archive-manifest.schema.json`, `cmd/portable-ghar-runner-gate/main.go` and tests, `cmd/portable-ghar-network-anchor/main.go` and tests, `scripts/{fetch-runner,stage-action-tool-archive}.sh`, `tests/shell/action-tool-archive.bats`, `images/{runner,network-anchor}/Dockerfile`.

**Interfaces:** `Engine.CreateNetworkAnchor(ctx, AnchorSpec) (Container, error)`; `Engine.CreateRunner(ctx, RunnerSpec, SecretEnvFD) (Container, error)` with exact anchor network mode; `Start`, `Inspect`, `Wait`, `ExecStdin`, `RunOneShot`, `ListManaged`, `Remove`; `archive.Load(io.Reader) (Manifest, error)` and `archive.Verify(fs.FS, Manifest) (Digest, error)`; `CommandRunner.Run(ctx, argv []string, extraFiles []*os.File, stdin io.Reader) (Result, error)`; gate subcommands `hold`, `release`, `hydrate-seeds`, and `netns-id`. Add compile-time interface assertions against the canonical contract.

- [ ] **Step 1: Write failing argv and gate tests.** Assert anchor creation has cap-drop ALL, read-only root, strict no-network pause seccomp, no runner/JIT/job data, no mounts/volumes/devices/socket, no restart, opaque labels, and one Docker-default unique netns. Assert runner creation has read-only root, bounded executable work/tmp tmpfs, CPU/memory/PID/scratch limits, cap-drop ALL, no-new-privileges, seccomp, non-root user, no mounts/volumes/devices/socket, no restart, and exact `container:<anchor-id>` network mode with no independent endpoint mutation. Assert wrong, absent, duplicate, and reused readiness tokens never exec the listener.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.5 go test ./internal/hostruntime ./internal/archive ./cmd/portable-ghar-runner-gate -v`. Expected: FAIL.
- [ ] **Step 3: Implement without a shell or secret argv.** Pass JIT and the expected readiness token through an anonymous inherited `--env-file /proc/self/fd/3`, never command arguments; `release` reads the token from stdin, atomically writes mode 0400 in runner-private tmpfs, and `hold` constant-time compares, consumes, unsets it, then `exec`s the runner listener.
- [ ] **Step 4: Pin and verify runner plus optional first-party seed archives.** `fetch-runner.sh` downloads v2.335.1 to an untracked build directory and verifies SHA-256 before extraction. The optional manifest accepts only `action`/`tool` sources under `https://github.com/actions/`, with a full 40-hex action commit or immutable tool release asset, SHA-256, SPDX license, and deterministic target; `stage-action-tool-archive.sh` rejects namespace/revision/checksum/license/path failure, records the manifest digest, and commits no archive or upstream binary.
- [ ] **Step 5: Build immutable seeds and verify.** Copy verified seeds mode 0555 into `/opt/portable-ghar/seed-cache` on the read-only image; `hydrate-seeds` copies selected content into that runner's private tmpfs before listener release. Absence of a manifest builds an empty seed cache. Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/hostruntime ./internal/archive ./cmd/portable-ghar-runner-gate && bats tests/shell/fetch-runner.bats tests/shell/action-tool-archive.bats`. Expected: PASS, including corrupt digest/license, tracked archive, immutable seed, and cross-job mutation tests. Commit: `git commit -S -m "feat: create held runner with verified immutable seeds"`.

### Task 6: Install and Verify Public-Only Egress Before Listener Release

**Files:** Create `internal/networkjail/policy.go`, `internal/networkjail/ranges.go`, `internal/networkjail/orchestrator.go`, `internal/networkjail/*_test.go`, `cmd/portable-ghar-network-helper/main.go`, `cmd/portable-ghar-network-verifier/main.go`, their tests, and scratch-based Dockerfiles under `images/network-helper/` and `images/network-verifier/`.

**Interfaces:** `PolicyManifest{Mode, Backend, PublicDNS, DynamicDeny, DockerHost, MaxTrackedFlows, NewConnectionsPerSecond, NewConnectionBurst, PositiveProbes, NegativeProbes}`; `Compile(PolicyManifest) (DecisionGraph, Digest, error)`; `Backend.Compile(DecisionGraph) (BackendRuleset, error)`; `Jail.Configure(ctx, Anchor, PolicyManifest) (Verification, error)`; apply helper reads canonical JSON on stdin; verifier returns `ProbeReport{PolicyDigest, Backend, NetNSID, PositiveOK, NegativeOK}`; audit helper returns only `AuditReport{PolicyDigest, Backend, NetNSID, BasePolicyOK, DelegationOK}`. `Backend` and its tracked-flow ceiling mechanism are exact enums selected by the validated host profile, never auto-detected fallbacks.

- [ ] **Step 1: Write failing range/compiler and backend-parity tests.** Cover IPv4 unspecified, RFC1918, loopback-off-interface, link-local/metadata, CGNAT, protocol/reserved, documentation/benchmark, multicast, and reserved ranges; IPv6 unspecified, loopback-off-interface, mapped/NAT64, discard, documentation/ORCHID/6to4, ULA, link-local/metadata, multicast, and dynamic host/bridge/management routes. Default mode must deny `::/0`; dual-stack may allow only the remainder. Compile the same manifests through nftables and iptables-legacy and require an identical normalized decision graph and policy digest; reject unknown, mismatched, or auto-selected backends. Require one explicit IPv6 posture: exact ip6tables deny/read-back or positively proven kernel-disabled; reject partial/ambiguous state. Require `OUTPUT` default drop, exact first delegation, no earlier bypass, established-public plus capped/rate-limited NEW-public semantics, and mathematically valid tracked-flow/rate/burst ceilings against host conntrack reserve.
- [ ] **Step 2: Write failing orchestration tests.** Require exact order `anchor capless/no-data -> apply helper NET_ADMIN-only -> IPv4 plus declared IPv6 posture complete -> apply helper exit/gone -> capless TCP/DNS/UDP verifier -> create held runner with exact anchor network mode/no namespace mutation -> audit helper NET_ADMIN-only/read-only -> audit exit/gone -> matching anchor/runner netns/base policy/delegation/policy digest -> readiness release`. Kill, timeout, one-family restore failure, default-policy accept, missing/late delegation, earlier bypass, contradictory report, unexpected route, policy corruption, helper network attempt, helper mutation during audit, helper residue, verifier capability, anchor mismatch, or token failure must remove runner and anchor and never release. Prove no untrusted listener exists during restore/audit, simulate Docker-side namespace mutation at runner attach, and prove a periodic active-job audit mismatch destroys the job and safe-stops acquisition.
- [ ] **Step 3: Implement both explicit policy backends.** The nftables backend uses v0.3.0 in a one-shot static helper. The QTS backend uses a digest-pinned helper image with reviewed `iptables-legacy`/`ip6tables-legacy` userspace, asserts `(legacy)`, and applies complete `*-restore` inputs inside the anchor namespace; it never shells through the QTS host's iptables binary and has no module-loading capability. Both set OUTPUT default drop, place the exact dedicated-chain jump first, reject every denied class, allow established public flows, enforce the profile-proven maximum tracked-flow ceiling, rate-limit remaining NEW public flows, and fall through to drop. Read-back validates base policy/order/linkage plus the generated dedicated-chain grammar into the normalized graph. Apply/audit helpers emit only backend/digest/netns/status and accept trusted controller input only; audit code has no mutation operation or prompt/job input. The capless verifier uses ordinary DNS/TCP and unprivileged UDP-echo probes.
- [ ] **Step 4: Verify unit and host contracts.** Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/networkjail ./cmd/portable-ghar-network-helper ./cmd/portable-ghar-network-verifier -count=20`. Then run the tagged nftables Docker conformance and QTS iptables-legacy sandbox suites. Expected: PASS; backend decision graphs/digests match, base OUTPUT drop/delegation/order are proven before release, exact legacy userspace/kernel compatibility and module preconditions are proven, each IPv6 posture has positive evidence, TCP/DNS/UDP negative probes fail, concurrent and rate NEW-flow floods remain bounded, runner attach does not mutate the anchor namespace, final and periodic audits match, and no apply/audit helper overlaps the untrusted listener at startup.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: gate listeners on verified egress jail"`.

### Task 7: Implement One-Job JIT Lifecycle and Secret-Bound Reconciliation

**Files:** Create `internal/lifecycle/service.go`, `internal/lifecycle/names.go`, `internal/lifecycle/service_test.go`, `internal/controller/reconciler.go`, `internal/controller/reconciler_test.go`.

**Interfaces:** `Lifecycle.Prepare(ctx, Assignment) (RunnerSlot, error)`; `Release`, `Observe`, `Destroy`; `Reconciler.Once(ctx) (CycleReceipt, error)`; `CycleReceipt{CycleID string; CompletedAt time.Time; AssignmentCount int; OldestAge time.Duration}`.

- [ ] **Step 1: Write failing fault-injection tests.** Fail before and after every external effect. Assert one deterministic opaque runner name per offer, JIT generation only after capacity reservation, immediate upstream-registration cleanup on container failure, no JIT persistence/logging, no duplicate runner after restart, exactly one listener release, completion/cancellation cleanup, and one terminal DESTROYED row.
- [ ] **Step 2: Add reassignment tests.** Feed one workflow job under successive request IDs and two runners that bind in opposite order; bind from observed runner name/request ID, never duplicate a slot, and retire canceled obsolete offers without killing a runner already bound to a live request.
- [ ] **Step 3: Implement persist-intent/effect/read-back.** Before retrying an ambiguous JIT create, query the deterministic runner name; before retrying Docker create, list opaque managed labels; after release ambiguity, stop acquisition, read GitHub runner and Docker state, then reconcile to running, finished, or destroyed.
- [ ] **Step 4: Exercise every state.** Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/lifecycle ./internal/controller -run 'TestLifecycle|TestReconcile' -count=50`. Expected: PASS with zero duplicate create/release calls.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: reconcile one-job JIT runner lifecycle"`.

### Task 8: Wire Polling, Admission, Acquisition, Health, and the Controller CLI

**Files:** Create `internal/controller/service.go`, `internal/controller/service_test.go`, `internal/observability/events.go`, `internal/observability/events_test.go`, `internal/health/{snapshot,publisher}.go`, `internal/health/*_test.go`, `cmd/portable-ghar-controller/main.go`, `cmd/portable-ghar-controller/main_test.go`.

**Interfaces:** `Service.Run(ctx) error`, `Service.ReconcileOnce(ctx) (CycleReceipt, error)`; canonical `AcquisitionPolicy`, `AcquisitionTransitioner`, and injected `FleetGuardProvider`; injected `FatalTerminator.TerminateAfterPersist(reason)` for the unjoinable-call path; `HealthPublisher.Publish(ctx, Snapshot) error`; CLI commands `run`, `probe`, `reconcile --once`, `drain --policy=wait|cancel`, `acquisition --set=disabled|canary-only|enabled --expected=disabled|canary-only|enabled --eligible-scale-set NAME --json`, and `status --json`. `--eligible-scale-set` is required exactly once for `canary-only` and rejected for other modes.

- [ ] **Step 1: Write failing service tests.** Prove broker lease precedes `Poll(maxCapacity)`; demand comes from `TotalAssignedJobs`, not message length; offers/acquisition results/terminal events persist before Ack; duplicate batches are harmless; rejected acquisitions create no runner; one repository cannot consume another's lease. Exercise `disabled -> canary-only -> enabled -> canary-only -> disabled`, host-pressure reduction, watchdog stop, failed probe, suspend, and observer startup; every transition increments the epoch and joins prior pollers/critical sections. Delay a poll across each narrowing, crash after epoch increment, replay a stale capacity lease, race concurrent CAS calls, and inject a poll/acquire/JIT call that ignores cancellation: the bounded deadline must persist fatal/zero capacity and invoke the injected process terminator, never hang or return success. Canary-only accepts exactly its persisted scale set at capacity one and rejects every other repository/scale set.
- [ ] **Step 2: Write failing health/log tests.** Publish only after a completely successful reconciliation; expose only approved fleet alias, acquisition state, capacity summary, assigned count/age, terminal time, profile/degraded flag, and build ID. Assert job names, repository coordinates, request bodies, JIT, tokens, paths, routes, and command output are rejected.
- [ ] **Step 3: Implement one bounded acquisition-policy barrier and ordered external-effect guard.** One session loop per configured repository feeds the central broker. Every mode, eligibility, or effective-capacity change compare-and-sets the persisted policy, increments its epoch, cancels and joins older pollers, invalidates their leases, and waits for zero acquisition critical sections. The root-only CLI, watchdog/probe stop, broker pressure change, shutdown, suspend, and observer normalization all call that same interface. Each poll/acquire/JIT operation has an explicit deadline and uses this order: acquire the injected current `portable` guard; enter a critical section bound to the lease epoch; re-read and compare mode, exact eligible scale set, effective capacity, lease ownership, and epoch; then perform the external call while retaining the guard/section. Task 8 ships only a fail-closed unavailable provider in the executable, so `run` cannot perform nonzero work before Task 9 supplies host authority; tests inject a fake provider. If cancellation cannot join by the shutdown deadline, atomically persist fatal/zero capacity, emit a bounded reason code, invoke the injected process terminator, and let target lifecycle verification prove quiescence before restart/handoff. `disabled=0`; `canary-only=1` for exactly one persisted canary scale set; `enabled=broker limit`. No local code imports a routing writer.
- [ ] **Step 4: Verify.** Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/controller ./internal/observability ./internal/health ./cmd/portable-ghar-controller -count=20`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -S -m "feat: wire controller acquisition and health cycles"`.

### Task 9: Add Host Profiles and the Exclusive Fleet-Generation Fence

**Files:** Create `internal/hostruntime/profile.go`, `internal/hostruntime/qts/{profile,discovery}.go`, `internal/hostruntime/systemd/profile.go` and tests; `internal/fleetfence/{store,store_unix,controller_adapter}.go` and tests; `cmd/portable-ghar-fleet-fence/main.go` and tests; modify `cmd/portable-ghar-controller/main.go` and its tests to replace the unavailable provider; create `deploy/qts/run-legacy-fenced.sh`; create `tests/shell/qts/fleet-fence.bats`.

**Interfaces:** `HostProfile.Probe(ctx) (ConformanceReport, error)`; `HostProfile.DiscoverNetworks(ctx) (NetworkSnapshot, error)`; `fleetfence.ControllerAdapter` satisfies `controller.FleetGuardProvider`; `portable-ghar-fleet-fence guard --fleet portable|legacy --generation N -- COMMAND` holds a shared guard for the command lifetime; `inspect` is read-only; `handoff --from portable|legacy|none --to portable|legacy|none --expected-generation N` holds the exclusive lock and returns N+1. Add compile-time interface assertions against the canonical contracts.

- [ ] **Step 1: Write failing profile and fence tests.** Reject non-Linux, unsupported architecture/runtime/kernel, missing resource enforcement, selected-backend failure, backend auto-fallback, incomplete route discovery, unsafe private-file mode, automatic degraded-root selection, malformed state, stale generation, wrong active fleet, reused owner/PID/boot identity, and unlocked mutation. The QTS reference profile must positively prove `(legacy)` userspace, preloaded conntrack/limit/ceiling/filter modules or exact namespace-scoped ceiling control, restore/read-back in an isolated anchor namespace, exact IPv6 posture, and helper/kernel compatibility; it must reject absent `nf_tables` as an nftables profile without rejecting the explicitly selected legacy profile. Capture `nf_conntrack_count/max` and timeouts; reject `maxTrackedFlows * maxRunnerCapacity` or rate/burst combinations that consume the host reserve; lower capacity through the epoch barrier at the warning threshold and safe-stop before exhaustion. Run a target soak with an active synthetic anchor/runner and repeated audits to prove ordinary Docker/QTS daemons do not mutate the namespace. Accept degraded root only with an exact configured profile name and surface it in health. Test multiple same-fleet holder records, stable-lock inode identity across header replacement, blocked exclusive acquisition, crash release, per-holder renewal, stale holder cleanup, and force-disabled observer restart while `legacy` owns the fence.
- [ ] **Step 2: Verify failure.** Run `GOTOOLCHAIN=go1.26.5 go test ./internal/hostruntime/... ./internal/fleetfence ./cmd/portable-ghar-fleet-fence -v`. Expected: FAIL because the fence and profiles are absent.
- [ ] **Step 3: Implement one atomic host-local authority.** Hold `flock` shared/exclusive on a stable, never-renamed lock inode. Store `{generation,activeFleet,bootID,updatedAt,operationID}` in a separate same-filesystem fsync/rename header, and one mode-restricted atomic renewal record per `{generation,fleet,ownerID,pid,bootID}`. Every handoff compares the expected generation under the exclusive lock, waits for all shared guards to close, increments exactly once, and retires old holder records without changing the lock inode. Controller advertisement/acquisition holds a current guard across the effect; the watchdog holds one across any non-disabled restart; `run-legacy-fenced.sh` holds one for the restored legacy process lifetime. Force-disabled observer restart is the sole no-guard exception: before any loop opens it compare-and-sets the persisted acquisition policy to disabled/empty eligibility/zero capacity through a new epoch, then proves zero before/after launch. A stale process cannot repair or reset the fence.
- [ ] **Step 4: Prove race exclusion on the target filesystem contract.** Race new-controller and new-watchdog restarts against restored legacy launcher/watchdog processes for 1,000 iterations, kill holders between lock and header rename, replay prior manifests, reuse PIDs across boot IDs, and fail each holder's renewal independently. Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/fleetfence -count=100 && bats tests/shell/qts/fleet-fence.bats`; then run the same filesystem conformance against the QTS state volume. Expected: same-fleet guards coexist, exclusive handoff waits for all of them, no observation contains both fleets, the stable lock inode never changes, and every stale/non-current process fails before acquisition.
- [ ] **Step 5: Commit.** Stage only the Task 9 files, including the controller entrypoint/provider wiring, then `git commit -S -m "feat: fence portable and legacy fleet generations"`.

### Task 10: Add Crash-Resumable QTS Installation, Suspend, Resume, Rollback, Uninstall, and Watchdog

**Files:** Create `internal/hostruntime/{runtime_manifest,operation_journal}.go` and tests; `cmd/portable-ghar-watchdog/main.go` and tests; `cmd/portable-ghar/main.go` plus `internal/cli/host.go` and tests; `deploy/qts/{install-controller,verify-controller,suspend-controller,resume-controller,rollback-controller,uninstall-controller,install-watchdog,uninstall-watchdog}.sh`, `deploy/qts/watchdog.cron.example`, `deploy/qts/lib/{runtime-manifest,operation-journal}.sh`; `deploy/systemd/*.service` and `*.timer`; `tests/shell/qts/{controller-install,controller-verify,controller-suspend,controller-resume,controller-rollback,controller-uninstall,watchdog}.bats`.

**Interfaces:** `RuntimeManifest` has the canonical typed fields above, `AcquisitionDefault == "disabled"`, and a nil `ArchiveManifestDigest` only when the optional archive input is absent. Every lifecycle operation persists `OperationJournal{OperationID, Kind, Phase, ExpectedGeneration, PriorManifest, TargetManifest, TargetFleet, StartedAt, UpdatedAt}` before effects and resumes/compensates forward by operation ID. `portable-ghar deploy host --private PATH --acquisition disabled` stages to the verified remote QTS target then invokes `install-controller.sh --private PATH --manifest PATH --acquisition disabled` there; `portable-ghar verify host --private PATH --require-zero-listeners` invokes `verify-controller.sh --private PATH --manifest PATH --require-zero-listeners`. `portable-ghar suspend host --private PATH --drain-policy=wait|cancel --hosted-confirmation PATH` invokes `suspend-controller.sh`, which validates fresh typed hosted-hold evidence, reads the current generation, disables the watchdog, transitions acquisition through the bounded policy barrier, drains, stops, proves quiescence, and atomically hands `portable` to `none`. `portable-ghar resume host --private PATH --acquisition disabled` invokes `resume-controller.sh`, which while stopped compare-and-sets any persisted stale policy to a new disabled/empty/zero epoch, reads the current generation, hands `none` to `portable`, starts controller/watchdog disabled, and proves zero listeners. Exact target-side rollback/uninstall commands are `rollback-controller.sh --private PATH --expected-generation N --hosted-confirmation PATH --legacy-command-file PATH` and `uninstall-controller.sh --private PATH --retain-state`.

- [ ] **Step 1: Write failing Bats/CLI and crash-boundary tests.** Require EUID 0, Linux, positive QTS profile/target identity, mode-safe overlay, exact staged manifest and file/image digests, current fence generation, acquisition disabled, and zero listeners. Suspend tests require fresh typed hosted-hold evidence, ordered watchdog disable/acquisition-policy barrier/drain/process stop/quiescence, and `portable -> none`; resume and legacy-owned observer tests seed stale `enabled`/`canary-only` SQLite state, require a new disabled/empty/zero epoch before any loop opens, then require `none -> portable` only for resume and zero listeners. Inject an unjoinable upstream call and require fatal persistence plus process death/quiescence rather than a hung lifecycle command or false success. SIGKILL every boundary of install, suspend, resume, rollback, and uninstall, then rerun the same operation ID and require one forward-resumed outcome. Refuse Darwin, digest drift, inline secrets, a non-QTS host, default-enabled acquisition, stale generation, stale/unconfirmed hold evidence, journal mismatch, or any unspecified destination path.
- [ ] **Step 2: Implement journaled install with forward compensation.** The local CLI verifies the overlay target and transfers only the staged manifest/artifacts; the target-side script re-verifies QTS identity and all digests/licenses, journals each phase, stages on the target filesystem, fsyncs files/directories, atomically switches `current`, installs an idempotent root-cron watchdog, normalizes persisted acquisition to a new disabled/empty/zero epoch while stopped, starts the controller force-disabled observer when `legacy` owns the fence (or normally disabled when `portable` owns it), and runs `verify-controller.sh --require-zero-listeners`. On failure, restore binary/symlink/cron state from the journal and prove acquisition disabled. Never restore a raw fence snapshot or decrement generation; if a handoff already occurred, compensate with another expected-generation transition to `none`. Never install a service on the invoking development/control Mac.
- [ ] **Step 3: Implement exact verify, suspend, resume, rollback, and uninstall semantics.** `verify-controller.sh` reads back manifest/digests, process, observer/acquisition mode, fence, journal, advancing health, and zero-listener/helper requirements. Suspend and resume use the same journaled primitives and fail closed without repairing stale state. `rollback-controller.sh` validates but cannot create external hosted-routing confirmation, reuses journaled suspend, atomically hands `none` to `legacy` at the next generation, then launches the captured legacy command only through `run-legacy-fenced.sh`. `uninstall-controller.sh` requires `none` or `legacy` active, removes controller/watchdog registration and binaries atomically, and retains state/backups unless `--purge-state-after-retention` is explicitly supplied.
- [ ] **Step 4: Preserve watchdog authority and dark-observer safety.** The watchdog checks the exact runtime manifest. With `portable` active it holds a current guard across restart; with `legacy` active it first normalizes the persisted acquisition policy and may restart only a force-disabled observer, proving disabled/empty eligibility/`maxCapacity=0` before and after launch. Its local stop calls the same bounded transition interface; an unjoinable call causes fatal process termination and a disabled restart, not a side-flag write or infinite wait. It has no GitHub/Worker/routing dependency. Run `GOTOOLCHAIN=go1.26.5 go list -deps ./cmd/portable-ghar-watchdog | grep -E 'actions/scaleset|internal/githubscale'`; expected no output/exit 1.
- [ ] **Step 5: Verify and commit.** Run `GOTOOLCHAIN=go1.26.5 go test -race ./internal/hostruntime/... ./internal/cli ./cmd/portable-ghar ./cmd/portable-ghar-watchdog && bats tests/shell/qts/controller-install.bats tests/shell/qts/controller-verify.bats tests/shell/qts/controller-suspend.bats tests/shell/qts/controller-resume.bats tests/shell/qts/controller-rollback.bats tests/shell/qts/controller-uninstall.bats tests/shell/qts/watchdog.bats`. Expected: PASS, including journaled crash recovery, forward-only fence compensation, exact master-command dispatch, hosted-hold-gated suspend, disabled resume, legacy-owned dark-observer restart, retention-safe uninstall, and watchdog/legacy race fixtures. Commit: `git commit -S -m "feat: add crash-resumable QTS controller lifecycle"`.

### Task 11: Prove Host, Namespace, Secret, and One-Job Conformance

**Files:** Create `tests/conformance/host_profile_test.go`, `tests/integration/network_jail_test.go`, `tests/integration/one_job_test.go`, `tests/integration/watchdog_test.go`, and `tests/integration/testenv/*.go`.

**Interfaces:** `testenv.StartDockerFixture(t)` returns isolated synthetic networks and public/blocked sentinels; `conformance.Run(ctx, HostProfile) Report` returns a signed-by-build, secret-free evidence document.

- [ ] **Step 1: Write integration tests before harness implementation.** From the actual runner netns prove unique netns per job, public IPv4 success, every IPv4 deny class failure, all IPv6 failure in default mode, public IPv6 plus deny-class failure in dual-stack mode, helper NET_ADMIN-only, verifier capless, helper gone before release, and policy loss/corruption prevents release.
- [ ] **Step 2: Add sandbox and seed proofs.** Inspect the actual runner to prove read-only root, enforced CPU/memory/PID/tmpfs/seccomp/capability limits, no socket/mount/device/control secret, non-root identity or named degraded result, JIT absence from job env/exported diagnostics/logs, one fake job completion, deregistration, container destruction, and no reusable workspace. Verify an immutable action/tool seed hydrates only the current job tmpfs and that mutation is absent from the next runner.
- [ ] **Step 3: Add watchdog/fence proof.** Kill the controller, assert the watchdog restarts it with a current `portable` guard, then hand off to `legacy` with stale canary/enabled policy persisted and prove it first writes a new disabled/empty/zero epoch and restarts only the force-disabled observer, without poll/JIT/acquisition calls. Provide a fake route-writer trap and assert zero calls. Simulate reboot while `legacy` owns the fence by recreating cron, controller state, per-holder records, and the persisted header; prove dark observer recovery and no portable acquisition. Inject a non-cancellable poll and prove the old process terminates before the disabled observer restarts.
- [ ] **Step 4: Run on Linux Docker.** `PGHAR_INTEGRATION_DOCKER=1 GOTOOLCHAIN=go1.26.5 go test -tags=integration ./tests/integration ./tests/conformance -v -count=1`. Expected: PASS on a supported profile; explicit `SKIP unsupported host profile` on other hosts, never a structural-only pass.
- [ ] **Step 5: Commit.** `git commit -S -m "test: prove runner host and network isolation"`.

### Task 12: Add Chaos Recovery, Safe Upgrade Gates, and Operator Evidence

**Files:** Create `tests/chaos/controller_states_test.go`, `tests/chaos/docker_failure_test.go`, `tests/chaos/jail_failure_test.go`, `tests/chaos/fleet_fence_test.go`, `tests/chaos/qts_install_test.go`, `internal/upgrade/service.go`, `internal/upgrade/service_test.go`, `docs/operations/controller-upgrade.md`, `docs/operations/controller-recovery.md`.

**Interfaces:** `Upgrade.Prepare(ctx, DrainPolicy) error`, `Upgrade.ProveQuiescent(ctx) (Quiescence, error)`, `Upgrade.ValidateReplacement(ctx) (CompatibilityReport, error)`. It can disable/drain/probe locally but has no route mutation method.

- [ ] **Step 1: Write table-driven chaos tests.** SIGKILL the controller in all nine lifecycle states; stop/restart Docker; kill/delay helper and verifier; corrupt the runtime/archive manifest; fail install/suspend/resume/rollback/uninstall before and after every journaled boundary; delete/roll back local state; redeliver/reorder scale messages; ignore cancellation in poll/acquire/JIT; and reboot the watchdog sandbox with stale enabled/canary policy while `legacy` is active. Race every policy narrowing and host-pressure stop against external effects, and race old/new watchdogs and controller/legacy launchers across fence handoff; assert bounded fatal termination for unjoinable calls, acquisition stops on ambiguity, generations never decrement, observer mode normalizes to zero-capacity, only one fleet can act, and no duplicate runner/listener appears.
- [ ] **Step 2: Write upgrade tests.** Require externally observed hosted routing as an operator precondition documented outside the controller, then disable acquisition, apply explicit wait/cancel policy, prove zero listeners/runners/helpers/verifiers and pending effects, validate the staged runtime manifest and exact file/image/archive digests plus host probes, atomically replace, and emit canary-ready evidence. Never restore acquisition or claim failback locally.
- [ ] **Step 3: Implement exact runbooks.** Document `status --json`, operation-journal, fence-header/holder, and `verify-controller.sh` read-back before/after each step; backup private state outside the public repo; describe journaled install compensation without fence rollback, observer-mode dark startup, compatibility/host probes, secretless canary handoff, rollback via journaled suspend plus fenced legacy handoff, and retention-safe uninstall while hosted routing remains confirmed.
- [ ] **Step 4: Run chaos repeatedly.** `PGHAR_CHAOS_DOCKER=1 GOTOOLCHAIN=go1.26.5 go test -tags=chaos ./tests/chaos -v -count=10` and `GOTOOLCHAIN=go1.26.5 go test -race ./internal/upgrade ./internal/fleetfence -count=50`. Expected: PASS; Docker/install/fence failures end disabled and recover through read-back without dual acquisition.
- [ ] **Step 5: Commit.** `git commit -S -m "test: harden reconciliation and upgrade recovery"`.

### Task 13: Run the Runtime Release Gate

**Files:** Create `scripts/test-controller-runtime.sh` and `tests/boundaries/runtime_boundary_test.go`; update only runtime files named by this plan when fixing failures.

**Interfaces:** The script runs formatting, vet, unit/race/contract, shell, boundary, image build/checksum, integration, conformance, and opt-in chaos stages and emits one secret-free JSON summary.

- [ ] **Step 1: Write a failing boundary test.** Reject the wrong module/toolchain, Kubernetes/ARC packages, job/service-container orchestration, runner Docker socket/mount/device flags, unpinned scale-set/runner/base/archive inputs, `Secret.Bytes` or unbounded reader APIs, upstream types outside `internal/githubscale`, scale-set calls without explicit deadlines, multiple/mismatched scale-set labels, any acquisition stop/capacity reduction outside `AcquisitionTransitioner`, routing-writer imports in controller/watchdog, missing fleet-fence checks, missing QTS lifecycle scripts, helper capabilities beyond NET_ADMIN, verifier capabilities, committed upstream archives/binaries, mutable cross-job caches, and private-identifier fixture patterns.
- [ ] **Step 2: Implement the non-mutating gate script with `set -euo pipefail`.** Run `unformatted="$(find cmd internal tests -type f -name '*.go' -print0 | xargs -0 gofmt -l)"; test -z "$unformatted"`, `GOTOOLCHAIN=go1.26.5 go vet ./...`, `GOTOOLCHAIN=go1.26.5 go test ./...`, `GOTOOLCHAIN=go1.26.5 go test -race ./...`, ShellCheck/Bats, `GOTOOLCHAIN=go1.26.5 go mod verify`, runner/archive checksum corruption tests, QTS install/rollback/uninstall tests, fleet-fence race tests, and tagged suites when their explicit environment gates are set. The gate never rewrites source or generated metadata.
- [ ] **Step 3: Run the non-Docker gate.** `./scripts/test-controller-runtime.sh --unit`. Expected: exit 0 with every unit/contract/boundary stage `PASS` and no secret-shaped output.
- [ ] **Step 4: Run the full Linux Docker gate.** `PGHAR_INTEGRATION_DOCKER=1 PGHAR_CHAOS_DOCKER=1 ./scripts/test-controller-runtime.sh --full`. Expected: exit 0; isolation, QTS sandbox, conformance, and chaos stages `PASS`.
- [ ] **Step 5: Inspect and commit.** Run `git diff --check && git status --short`. Expected: only planned runtime files. Commit: `git commit -S -m "test: gate portable GHAR controller runtime"`.

### Task 14: Rehearse Reproducible Runtime Release Artifacts

**Files:** Create `scripts/release/{rehearse-runtime,compare-runtime-rebuilds}.sh`, `tests/shell/runtime-release.bats`; modify `release/manifest.json` and `.github/workflows/release.yml` created by the foundation phase.

**Interfaces:** `rehearse-runtime.sh --version <semver> --output <directory>` performs a clean runtime gate and produces registered controller binaries, immutable image manifests, SPDX SBOMs, third-party notices, checksums, and provenance subjects; `compare-runtime-rebuilds.sh <first> <second>` compares supported binaries byte-for-byte and normalized image manifests by digest without rewriting either tree.

- [ ] **Step 1: Write failing release tests.** Two isolated clean rebuilds of one commit must match; reject dirty source, unregistered artifact, mutable image tag without digest, missing license/SBOM/checksum/provenance subject, wrong target platform, embedded build path/time, or secret/private-identifier finding.
- [ ] **Step 2: Run `bats tests/shell/runtime-release.bats`.** Expected: FAIL because runtime rehearsal scripts and manifest entries are absent.
- [ ] **Step 3: Implement hermetic runtime rehearsal.** Use pinned Go/tool/image inputs, `SOURCE_DATE_EPOCH` from the commit, stripped deterministic binaries, BuildKit provenance disabled only for the comparison build while the release workflow produces GitHub artifact attestations, normalized OCI manifests, Syft SPDX JSON, license inventory, SHA-256 sums, Trivy source/filesystem/image scans, and `scripts/sanitize_public.py --generated` over every output. Never publish from this script.
- [ ] **Step 4: Run two rehearsals and compare.** `./scripts/release/rehearse-runtime.sh --version 0.1.0-rc.1 --output dist/rehearsal-a`, repeat for `dist/rehearsal-b`, then `./scripts/release/compare-runtime-rebuilds.sh dist/rehearsal-a dist/rehearsal-b`. Expected: PASS with registered subjects only and no diff.
- [ ] **Step 5: Integrate and commit.** Update the tag workflow to run the full gate, rehearse once, attest exact archive/SBOM/checksum/image subjects, and upload immutable assets only after scans pass. Stage only the files named above and commit `git commit -S -m "release: rehearse reproducible runtime artifacts"`.

## Execution Boundaries and Completion Evidence

- Implementation is complete only when Tasks 1-14 pass in order, the exact dependency/runner/archive/runtime-manifest pins read back from generated artifacts, the fleet-generation race suite proves exclusivity, a supported Linux Docker host produces positive conformance evidence, and two runtime release rehearsals compare cleanly.
- A passing unit suite on macOS, a Docker inspect dump, or a clean command exit alone is not host conformance.
- Acquisition must remain disabled after implementation until an operator separately approves a private overlay, external failover integration, secretless canary, and deployment plan.
- This phase plan covers source/test changes and its scoped signed commits. Push/merge, host access, secrets, service restart, routing mutation, and deployment occur only through the master program's positive gates and the operator's existing authorization; runtime-phase completion alone never triggers them.
