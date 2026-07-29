# Task 10 Implementation Plan: Crash-Resumable Host Lifecycle and Watchdog

> Status: source design only. This plan authorizes no Docker, QTS, RhoNAS,
> systemd, routing, release, deployment, service, selector, or host-
> configuration mutation. It does not select any memory, tmpfs, swap, storage,
> log, concurrency, or rebuild-cadence value. Those numeric choices and every
> target-host action remain separate operator-signoff gates.

**Goal:** Add a strictly typed, crash-resumable host lifecycle for installing,
verifying, suspending, resuming, rolling back, uninstalling, and supervising a
Portable GHAR controller while keeping acquisition disabled, preserving the
monotonic fleet fence, retaining rollback material, and proving that every
replayed operation moves forward to one safe terminal state.

**Architecture:** A public, identity-free `RuntimeManifest` binds one immutable
release tuple. A private deployment overlay supplies only references, absolute
target paths, target identity, explicit resource evidence, and fixed command
locations; it never embeds secret values or open argv. One root-owned
stable-inode lifecycle lock serializes every mutating host operation. One
`OperationJournal` plus domain-separated per-phase effect receipts is persisted
and read back before and after every external effect. The journal is the sole
operation-resume authority. It records closed kind-specific phases and permits
only the exact next phase or an exact replay of the current phase. Reentry
first inspects the deterministic effect key and target postcondition; it never
blindly repeats an ambiguous effect. Install, suspend, resume, rollback,
uninstall, and watchdog recovery call the same Go lifecycle engine through
fixed target-side scripts. Fence compensation is always a newer expected-
generation handoff through Task 9's sole stable-inode fence store; no code
restores a fence snapshot, writes a second generation counter, or decrements a
generation.

The Task 10 production controller is a real disabled-observer composition:
it opens the bounded SQLite store, restores and reconciles local durable state,
normalizes acquisition through a new disabled/empty/zero epoch before any
loop, and serves the closed local admin/readiness surface. It deliberately
injects unavailable Worker-permit and hosted-routing providers and opens no
GitHub sessions. Therefore it cannot poll, acquire, generate JIT, release a
listener, or route a repository. Later failover integration must replace
those unavailable providers and add configured sessions before a nonzero
policy can be accepted.

The host watchdog imports neither `internal/githubscale` nor
`github.com/actions/scaleset`. It validates the exact manifest, journal,
fence, storage envelope, process identity, and disabled policy, then invokes
only fixed local controller/lifecycle actions. It may restart; it never routes.

**Tech stack:** Go 1.26.0/toolchain 1.26.5, strict bounded canonical JSON,
descriptor-relative no-follow filesystem operations, `fsync` plus same-
filesystem atomic rename, SQLite `synchronous=FULL`, stable-inode `flock`,
fixed-argv subprocesses, POSIX shell wrappers, systemd unit templates, and
table-driven/race/Bats tests.

## Existing-Source Corrections

### 1. Do not turn Task 10 into a premature active controller

Task 8 intentionally left `OpenController` unavailable because the source
lacked a complete production composition. Task 9 supplied only the independent
host-fence and host-capacity authorities. The external Worker permit, hosted
router, heartbeat transport, and live GitHub sessions remain later integration
work.

Task 10 replaces the unconditional `OpenController` failure with one real
disabled-observer factory. The factory must:

1. require `LoadControllerRuntime`, a matching `RuntimeManifest`, and a current
   private overlay;
2. open the bounded state store and its controller adapter;
3. build the immutable admission templates and a zero-demand broker;
4. build cleanup/reconciliation authority only from complete closed runtime
   specifications;
5. build the current fence adapter only when `portable` owns the exact
   generation;
6. when `legacy` owns the fence, call `NormalizeLegacyObserver` and consume its
   exact proof before launch;
7. normalize any persisted enabled/canary/fatal policy to a newer
   disabled/empty/zero epoch before starting the observer;
8. inject no GitHub poll target and no usable Worker permit, hosted-routing, or
   health-transport authority; and
9. fail before serving admin/readiness if any durable cleanup authority is
   incomplete.

The disabled observer is not a no-op. It must perform cold local recovery,
bounded reconciliation, history/host-pressure readback, and closed health
generation. It cannot claim Worker heartbeat delivery or external hosted
routing. A later task must replace every unavailable external authority and
prove a fresh nonzero epoch before acquisition.

### 2. Keep the runtime manifest separate from private deployment data

`RuntimeManifest` is public and contains only immutable digests, one closed
egress mode, one closed acquisition default, and the fleet generation. It has
no host path, user, repository, scale set, route, socket, credential reference,
resource quantity, command, schedule, or target identity.

The private overlay is mode-restricted and names:

- the exact expected target identity and QTS profile;
- absolute canonical roots for state, release, staging, rollback, scratch,
  logs, fence, controller database, sockets, and captured legacy material;
- absolute fixed command paths;
- `SecretRef` objects only;
- exact manifest path and digest;
- the complete operator-approved host-profile observation and storage sizing;
- bounded controller/watchdog log policy;
- closed controller deadlines/cadences and immutable repository templates; and
- the target-side action allowlist.

No public fixture uses a real host, repository, account, route, schedule,
device, UID/GID, filesystem, or private path.

### 3. Make Go the state-machine authority; keep shell as a fixed boundary

The QTS scripts perform only:

1. `set -eu`, `umask 077`, exact argument parsing, EUID/Linux checks, and
   canonical absolute-path checks;
2. a fixed invocation of the installed `portable-ghar host-runtime` action;
3. exact typed-result readback; and
4. one generic failure line without paths, command output, or identifiers.

They do not parse JSON with regex, synthesize Docker argv, use `eval`, source a
private command file, mutate routing, retag an image, restore a fence file, or
invent recovery. `deploy/qts/lib/runtime-manifest.sh` and
`operation-journal.sh` expose fixed functions that delegate validation and
journal transitions to the Go binary.

### 4. Keep install proof separate from target conformance

Source tests prove parser, state-machine, crash-replay, command-dispatch, and
filesystem safety. They do not claim QTS kernel, Docker, seccomp, cgroup,
namespace, image, listener, filesystem, process, or storage conformance.
Task 11 remains the first positive target proof. Task 10 leaves every target-
only proof typed pending and performs no host change.

## Threat Model and Failure Classes

The implementation must fail closed against:

1. unknown, missing, duplicated, trailing, noncanonical, oversized, or
   differently normalized manifest/journal JSON;
2. path traversal, relative paths, symlinks, hardlinks, wrong owner/mode/type,
   mount crossing, parent replacement, or same-name inode substitution;
3. inline secrets or a secret source outside the existing exact allowlist;
4. digest confusion between raw SHA-256 values, `sha256:` image digests, full
   image references, manifests, binaries, policies, CA locks, and profiles;
5. current/candidate/rollback image identity aliasing or mutable tag retarget;
6. a non-admin QNAP Docker build or a build running under the non-admin
   Container Station `HOME` wrapper;
7. installing before all six storage roles have a complete, operator-approved,
   overflow-checked byte/inode envelope and a non-stop result;
8. summing by path rather than filesystem identity, or inconsistent free-space
   readings for two roles on the same filesystem;
9. unbounded controller, watchdog, or Docker logging;
10. a crash before or after every external effect, including an effect that
    committed before returning an error;
11. replay under a different operation ID, kind, expected generation,
    prior/target manifest, target fleet, or private overlay;
12. skipping a journal phase, moving backward, changing an already persisted
    phase payload, or accepting an unrecognized terminal phase;
13. a failed operation deleting evidence needed to distinguish committed from
    uncommitted effects;
14. restoring or decrementing the fence, handing off from stale generation,
    or allowing portable and legacy authority at once;
15. a watchdog/controller/legacy race during disable, quiescence, handoff,
    restart, or rollback;
16. opening an observer before a new disabled/empty/zero acquisition epoch is
    durable and read back;
17. a local command bypassing the live controller barrier by writing SQLite;
18. a cancellation-resistant external call returning false success or leaving
    an old process able to acquire work;
19. identifying an idle legacy container without a live proof that it has no
    `Runner.Worker`, or letting that registration accept one more job;
20. treating a prior status response as current quiescence;
21. accepting stale, wrong-scope, wrong-generation, unauthenticated, expired,
    or locally fabricated hosted-hold evidence;
22. rollback or uninstall creating hosted confirmation instead of validating
    externally produced evidence;
23. an uninstall deleting stable ledgers before `T`, rollback images before
    retention, or private state without an explicit purge-after-retention
    action;
24. the watchdog importing GitHub/scale-set/routing code or gaining mutation
    authority beyond restart and safe-stop;
25. Darwin or the invoking development/control Mac reaching any target-side
    write action; and
26. a source test or synthetic fixture being reported as target-ready.
27. two lifecycle operations, or one watchdog and one lifecycle operation,
    mutating the same release while holding different locks;
28. a phase journal advancing without an exact effect receipt and target
    postcondition bound to the same operation, manifest, fence, and filesystem
    identities;
29. an expired hosted hold at a routing-sensitive handoff or terminal
    readback; and
30. a shell zero exit, truncated result, cleanup hook, or best-effort
    compensation being mistaken for Go's typed terminal success.

## Canonical Runtime Manifest

Create `internal/hostruntime/runtime_manifest.go`:

```go
type RuntimeManifest struct {
    SchemaVersion         uint32  `json:"schema_version"`
    BuildID               string  `json:"build_id"`
    ControllerSHA256      string  `json:"controller_sha256"`
    RunnerImageDigest     string  `json:"runner_image_digest"`
    AdapterImageDigest    string  `json:"adapter_image_digest"`
    BrokerImageDigest     string  `json:"broker_image_digest"`
    HelperImageDigest     string  `json:"helper_image_digest"`
    VerifierImageDigest   string  `json:"verifier_image_digest"`
    TrustBundleDigest     string  `json:"trust_bundle_digest"`
    SeccompProfileDigest  string  `json:"seccomp_profile_digest"`
    EgressMode            string  `json:"egress_mode"`
    PolicyManifestDigest  string  `json:"policy_manifest_digest"`
    ConntrackBudgetDigest string  `json:"conntrack_budget_digest"`
    StorageBudgetDigest   string  `json:"storage_budget_digest"`
    LogPolicyDigest       string  `json:"log_policy_digest"`
    ArchiveManifestDigest *string `json:"archive_manifest_digest"`
    AcquisitionDefault    string  `json:"acquisition_default"`
    FleetGeneration       uint64  `json:"fleet_generation"`
}
```

Validation is exact:

- schema version is `1`;
- `BuildID`, controller/trust/seccomp/policy/conntrack/storage/log digests, and
  a present archive digest are lowercase 64-hex raw SHA-256 values;
- every image digest is exactly `sha256:` plus 64 lowercase hex digits;
- image digests are independently named and cannot be empty;
- `EgressMode` is exactly `restricted-broker-v1`;
- `AcquisitionDefault` is exactly `disabled`;
- `FleetGeneration` is nonzero; and
- `ArchiveManifestDigest == nil` means only that the optional archive input is
  absent. An empty pointer value is invalid.

The V1 canonical codec is frozen: Go struct field order above; UTF-8 only; no
insignificant whitespace; no trailing LF; lowercase decimal integers; `null`
only for the absent archive pointer; and no map-valued field. Its digest is
`SHA256("portable-ghar-runtime-manifest-v1\x00" || canonicalJSON)`, never the
bare JSON hash used by another artifact class.

`ParseRuntimeManifest` uses a byte limit, `DisallowUnknownFields`, one JSON
value, and exact canonical remarshal equality. `ReadRuntimeManifest` opens one
regular, root-owned, non-group/world-writable, no-follow file beneath a
pre-opened private root, rejects link count other than one, rechecks identity
after read, and returns both the manifest and domain-separated canonical
digest. `WriteRuntimeManifestAtomic` is available only to the operation
engine, writes mode `0600`, fsyncs the temporary file, proves the temporary and
parent directory share one local qualified filesystem, renames without
following a replaced parent, fsyncs the parent, reopens no-follow, and requires
byte and final-path identity equality. A missing final directory entry after a
crash is never treated as applied.

## Canonical Operation Journal

Create `internal/hostruntime/operation_journal.go`:

```go
type OperationKind string
type OperationPhase string

type OperationJournal struct {
    SchemaVersion      uint32           `json:"schema_version"`
    OperationID        string           `json:"operation_id"`
    BindingDigest      string           `json:"binding_digest"`
    Kind               OperationKind    `json:"kind"`
    Phase              OperationPhase   `json:"phase"`
    CompensationPath   *CompensationPath `json:"compensation_path"`
    ExpectedGeneration uint64          `json:"expected_generation"`
    PriorManifest      *RuntimeManifest `json:"prior_manifest"`
    TargetManifest     *RuntimeManifest `json:"target_manifest"`
    TargetFleet        fleetfence.Fleet `json:"target_fleet"`
    StartedAt          time.Time        `json:"started_at"`
    UpdatedAt          time.Time        `json:"updated_at"`
}
```

The canonical kinds are `install`, `suspend`, `resume`, `rollback`, and
`uninstall`. Each kind has its own ordered phase graph:

| Kind | Ordered phases |
| --- | --- |
| install | exact common prefix, one disposition-specific stop/quiescence/fence path, and exact common tail defined below |
| suspend | `prepared`, `hold-proven`, `watchdog-disabled`, `policy-disabled`, `drained`, `controller-stopped`, `quiescence-proven`, `fence-none`, `complete` |
| resume | `prepared`, `stopped-proven`, `policy-disabled`, `fence-portable`, `observer-started`, `watchdog-installed`, `zero-proven`, `complete` |
| rollback | `prepared`, `hold-proven`, `watchdog-disabled`, `policy-disabled`, `drained`, `controller-stopped`, `quiescence-proven`, `fence-none`, `legacy-restored`, `fence-legacy`, `legacy-started`, `complete` |
| uninstall | `prepared`, `quiescence-proven`, `watchdog-removed`, `controller-removed`, `registration-removed`, `retention-proven`, `complete` |

Install has one closed `InstallDisposition` persisted in its operation binding.
Its common prefix is exactly:

```text
prepared
preflight-proven
candidate-staged
candidate-smoked
prior-retained
```

It then takes exactly one of these mutually exclusive paths:

| Disposition | Required precondition | Exact disposition path |
| --- | --- | --- |
| `greenfield-portable` | no prior manifest; no current selection; no prior controller/watchdog registration; fence is exact bootstrap `none` at expected generation `0` | `disposition-greenfield-proven`, `prior-absence-proven`, Task 9 `none -> portable`, `fence-portable` at generation `1` |
| `upgrade-portable` | prior manifest and current selection both match the binding; fence is `portable` at exact nonzero expected generation | `disposition-upgrade-proven`, `prior-acquisition-disabled`, `prior-drained`, `prior-controller-stopped`, `prior-quiescence-proven`, read-only `fence-portable-proven`; no handoff and no generation change |
| `legacy-disabled-observer` | captured legacy material and current legacy selection match the binding; fence is `legacy` at exact nonzero expected generation | `disposition-legacy-proven`, `legacy-acquisition-disabled`, `legacy-drained`, `legacy-controller-stopped`, `legacy-quiescence-proven`, read-only `fence-legacy-proven`, `legacy-normalized-proven`; no handoff |

`prior-acquisition-disabled` and `legacy-acquisition-disabled` are
receipt-backed barriers that prove a newer disabled/empty/zero epoch before
drain begins. `prior-drained` and `legacy-drained` prove that all admitted work
has reached the binding's declared wait-or-cancel terminal policy.
`prior-controller-stopped` and `legacy-controller-stopped` prove process death,
not merely a stop request. Their following quiescence phases freshly prove no
listener, runner, adapter, broker, helper, verifier, dial, per-job socket,
pending acquisition, or fleet guard. A crash after any one of these boundaries
replays from that exact applied receipt; it cannot skip directly to observer
start. The legacy path may replace the stopped legacy authority only with the
exact force-disabled observer admitted by `NormalizeLegacyObserver`.
`legacy-normalized-proven` is the sole normalization phase. Before invoking
the fixed normalizer, it writes an applying receipt bound to the captured
command/config/image/watchdog digests. It then records the exact
`LegacyNormalizationProjection`, requires force-disabled true and both counts
zero, writes the applied receipt, and rereads it before entering the common
tail. An applying replay may rerun only this deterministic read-only
normalizer against the same stopped legacy identities; it cannot start a
process or synthesize a new command.

Every disposition then uses this common tail:

```text
watchdog-installed
policy-disabled
observer-started
zero-proven
current-selected
verified
complete
```

The candidate observer is launched by immutable release path, not through the
old `current` link. `current-selected` is the sole current-manifest mutation.
It runs only after `zero-proven`, uses its own applying/applied effect receipt,
and atomically replaces the `current` symlink. Its target postcondition proves
the identity-pinned release-directory inode, the new symlink inode and exact
relative link text, the selected manifest inode and domain-separated digest,
and the exact fence generation/fleet from the binding. The directory is
fsynced before readback. `verified` may advance only from that exact applied
receipt and a fresh matching postcondition. A crash at `verified` is
forward-only replay to `complete`; it never selects compensation.

No install path accepts `none` at a nonzero generation, portable ownership
under the legacy disposition, legacy ownership under an upgrade disposition,
or an omitted/inferred disposition. Every disposition/fence receipt binds the
live Task 9 header generation, fleet, operation ID, stable lock identity, and
target manifest. Only resume and governed cutover later move a legacy-disabled
observer to portable; install itself never silently cuts over legacy.

Canonical hash preimages use only these primitives:

```text
U32(v)       = exactly four unsigned big-endian bytes
U64(v)       = exactly eight unsigned big-endian bytes
LP(s)        = U32(len(UTF8(s))) || UTF8(s)
Digest32(s)  = the 32 bytes decoded from one exact lowercase 64-hex digest
MaybeLP(nil) = 0x00
MaybeLP(&s)  = 0x01 || LP(s)
MaybeDigest(nil) = 0x00
MaybeDigest(&s)  = 0x01 || Digest32(s)
```

Lengths are byte lengths, not rune counts. There is no decimal generation
encoding, empty-string substitute for nil, platform byte order, or implicit
normalization. `OperationID` is lower-hex:

```text
SHA256(
  "portable-ghar-operation-id-v1\0" ||
  LP(kind) || U64(expectedGeneration) ||
  MaybeLP(installDisposition) ||
  MaybeDigest(priorManifestDigest) ||
  MaybeDigest(targetManifestDigest) ||
  LP(targetFleet) || Digest32(privateOverlayRevision)
)
```

`installDisposition` is mandatory and one of the three exact closed values for
kind `install`; it is null for every other kind. Callers may provide the ID,
but it must equal that derivation. The effect key need not repeat the
disposition because it contains `Digest32(operationID)`, which already commits
to it.

Journal rules:

- `StartedAt` and `UpdatedAt` are UTC; `UpdatedAt >= StartedAt`;
- timestamps are informational and never recovery authority;
- `PriorManifest` is nil only when no prior release exists;
- `TargetManifest` is required for install/resume and forbidden only where the
  closed kind does not consume one;
- target fleet and expected generation must match the phase graph;
- an exact same journal replay is idempotent;
- a same-operation next-phase write is allowed only after injected positive
  readback of the immediately preceding effect;
- a different operation while a nonterminal journal exists fails;
- an exact terminal replay returns the already proven outcome;
- a terminal journal is retained and rotated only under explicit bounded
  retention; and
- no failure handler rewrites a prior phase. Compensation itself advances to a
  closed later phase and is journaled.

`CompensationPath` is `null` throughout the normal graph. At a permitted
compensation pivot the engine atomically advances to the path's first
path-specific phase and sets the exact closed `CompensationPath` value. It is
then immutable. A nonnull path at any normal phase, a null path at any
compensation phase, or a phase not belonging to that path is invalid. Generic
`compensating` phases shared by multiple paths are forbidden.

The operation engine injects a crash hook after journal persistence and after
effect readback for every phase. Table tests terminate at each hook, reopen the
same files, rerun the same operation ID, and require one complete terminal
outcome without duplicate effects.

### Frozen operation-binding, journal, and receipt codecs

The validated private overlay has one closed V1 wire struct. It contains
secret references but never secret values. All nested sections are structs or
ordered slices, never maps. Its canonical bytes use the same exact JSON rules
as `RuntimeManifest`: Go declaration order, UTF-8, no insignificant
whitespace/trailing LF, decimal integers, explicit `null` only where the
schema permits it, and exact remarshal equality.

The complete declaration order is:

```go
type PrivateOverlay struct {
    SchemaVersion  uint32                    `json:"schema_version"`
    Target         TargetIdentityOverlay     `json:"target"`
    Manifest       ManifestOverlay           `json:"manifest"`
    Paths          PathOverlay               `json:"paths"`
    Commands       CommandOverlay            `json:"commands"`
    Docker         DockerOverlay             `json:"docker"`
    Resources      ResourceOverlay           `json:"resources"`
    Repositories   []RepositoryOverlay       `json:"repositories"`
    Policy         PolicyOverlay             `json:"policy"`
    Controller     ControllerTimingOverlay   `json:"controller"`
    Fence          FenceTimingOverlay        `json:"fence"`
    Health         HealthOverlay             `json:"health"`
    Profile        ProfileOverlay            `json:"profile"`
    Watchdog       WatchdogOverlay           `json:"watchdog"`
    Secrets        []NamedSecretRef          `json:"secrets"`
    Legacy         *LegacyOverlay            `json:"legacy"`
    AllowedActions []string                  `json:"allowed_actions"`
}

type TargetIdentityOverlay struct {
    OS                        string `json:"os"`
    Architecture              string `json:"architecture"`
    ExpectedEUID              uint64 `json:"expected_euid"`
    HostIdentityDigest        string `json:"host_identity_digest"`
    ControlHostIdentityDigest string `json:"control_host_identity_digest"`
    ProfileID                 string `json:"profile_id"`
    OwnerID                   string `json:"owner_id"`
    DegradedAcknowledged      bool   `json:"degraded_acknowledged"`
}

type ManifestOverlay struct {
    Path   string `json:"path"`
    Digest string `json:"digest"`
}

type PathOverlay struct {
    StateRoot        string `json:"state_root"`
    ReleaseRoot      string `json:"release_root"`
    StagingRoot      string `json:"staging_root"`
    RollbackRoot     string `json:"rollback_root"`
    ScratchRoot      string `json:"scratch_root"`
    LogRoot          string `json:"log_root"`
    FenceRoot        string `json:"fence_root"`
    JournalRoot      string `json:"journal_root"`
    ReceiptRoot      string `json:"receipt_root"`
    ReservationRoot  string `json:"reservation_root"`
    DatabasePath     string `json:"database_path"`
    AdminSocketPath  string `json:"admin_socket_path"`
    HealthSocketPath string `json:"health_socket_path"`
    BrokerRoot       string `json:"broker_root"`
    SeccompRoot      string `json:"seccomp_root"`
    PolicyPath       string `json:"policy_path"`
    TrustLockPath    string `json:"trust_lock_path"`
    LegacyRoot       string `json:"legacy_root"`
}

type CommandOverlay struct {
    DockerBinary       string `json:"docker_binary"`
    ControllerBinary   string `json:"controller_binary"`
    WatchdogBinary     string `json:"watchdog_binary"`
    HostRuntimeBinary  string `json:"host_runtime_binary"`
    LegacyFenceBinary  string `json:"legacy_fence_binary"`
}

type DockerOverlay struct {
    BrokerNetworkID    string `json:"broker_network_id"`
    RunnerNetworkMode  string `json:"runner_network_mode"`
    RunnerImage        string `json:"runner_image"`
    AdapterImage       string `json:"adapter_image"`
    BrokerImage        string `json:"broker_image"`
    HelperImage        string `json:"helper_image"`
    VerifierImage      string `json:"verifier_image"`
    ImmutableBuildMode string `json:"immutable_build_mode"`
}

type ResourceVectorOverlay struct {
    MilliCPU          uint64 `json:"milli_cpu"`
    MemoryBytes       uint64 `json:"memory_bytes"`
    PIDs              uint64 `json:"pids"`
    FileDescriptors   uint64 `json:"file_descriptors"`
    TmpfsBytes        uint64 `json:"tmpfs_bytes"`
    ScratchBytes      uint64 `json:"scratch_bytes"`
    SocketStateBytes  uint64 `json:"socket_state_bytes"`
    DurableStateBytes uint64 `json:"durable_state_bytes"`
    Inodes            uint64 `json:"inodes"`
}

type SlotResourcesOverlay struct {
    Runner        ResourceVectorOverlay `json:"runner"`
    Adapter       ResourceVectorOverlay `json:"adapter"`
    Broker        ResourceVectorOverlay `json:"broker"`
    DialAuthority ResourceVectorOverlay `json:"dial_authority"`
    Helper        ResourceVectorOverlay `json:"helper"`
    Verifier      ResourceVectorOverlay `json:"verifier"`
}

type HistoryOverlay struct {
    MinRetention                 string `json:"min_retention"`
    MaxHistoryRows               uint64 `json:"max_history_rows"`
    MaxHistoryLogicalBytes       uint64 `json:"max_history_logical_bytes"`
    MaxNetworkLedgerRows         uint64 `json:"max_network_ledger_rows"`
    MaxNetworkLedgerLogicalBytes uint64 `json:"max_network_ledger_logical_bytes"`
    InflightReserveRows          uint64 `json:"inflight_reserve_rows"`
    InflightReserveLogicalBytes  uint64 `json:"inflight_reserve_logical_bytes"`
    GCBatchRows                  uint64 `json:"gc_batch_rows"`
    NetworkGCBatchRows           uint64 `json:"network_gc_batch_rows"`
    VacuumBatchPages             uint64 `json:"vacuum_batch_pages"`
    MaintenanceCadence           string `json:"maintenance_cadence"`
}

type RunnerSizingOverlay struct {
    OperatorApproved                bool   `json:"operator_approved"`
    RunnerTmpfsBytes                uint64 `json:"runner_tmpfs_bytes"`
    RunnerP99Bytes                  uint64 `json:"runner_p99_bytes"`
    RunnerMarginBytes               uint64 `json:"runner_margin_bytes"`
    TmpTmpfsBytes                   uint64 `json:"tmp_tmpfs_bytes"`
    TmpP99Bytes                     uint64 `json:"tmp_p99_bytes"`
    TmpMarginBytes                  uint64 `json:"tmp_margin_bytes"`
    ScratchTmpfsBytes               uint64 `json:"scratch_tmpfs_bytes"`
    ScratchP99Bytes                 uint64 `json:"scratch_p99_bytes"`
    ScratchMarginBytes              uint64 `json:"scratch_margin_bytes"`
    RunnerCgroupP99Bytes            uint64 `json:"runner_cgroup_p99_bytes"`
    ProcessMarginBytes              uint64 `json:"process_margin_bytes"`
    RunnerMemoryBytes               uint64 `json:"runner_memory_bytes"`
    SwapLimitConfigured             bool   `json:"swap_limit_configured"`
    SwapLimitBytes                  uint64 `json:"swap_limit_bytes"`
    MaxActiveConcurrency            uint64 `json:"max_active_concurrency"`
    AuxiliarySlotMemoryBytes        uint64 `json:"auxiliary_slot_memory_bytes"`
    IdleControlPlaneBytes           uint64 `json:"idle_control_plane_bytes"`
    CandidateBuildAndSmokePeakBytes uint64 `json:"candidate_build_and_smoke_peak_bytes"`
    HostAndGatewayReserveBytes      uint64 `json:"host_and_gateway_reserve_bytes"`
    UsableHostMemoryBytes           uint64 `json:"usable_host_memory_bytes"`
    MeasuredIdleRunnerBytes         uint64 `json:"measured_idle_runner_bytes"`
    ReclamationObservationCadence   string `json:"reclamation_observation_cadence"`
    EvidenceRevision                string `json:"evidence_revision"`
}

type ConntrackTimeoutOverlay struct {
    Name    string `json:"name"`
    Seconds uint64 `json:"seconds"`
}

type ConntrackOverlay struct {
    CurrentEntries          uint64                    `json:"current_entries"`
    MaximumEntries          uint64                    `json:"maximum_entries"`
    HostReserveEntries      uint64                    `json:"host_reserve_entries"`
    MaximumRunnerCapacity   uint64                    `json:"maximum_runner_capacity"`
    MeasuredJobClassEntries uint64                    `json:"measured_job_class_entries"`
    MeasuredDoHClassEntries uint64                    `json:"measured_doh_class_entries"`
    JobClassBudget          uint64                    `json:"job_class_budget"`
    DoHClassBudget          uint64                    `json:"doh_class_budget"`
    Timeouts                []ConntrackTimeoutOverlay `json:"timeouts"`
    DialTokenStateRevision  string                    `json:"dial_token_state_revision"`
    ConsumeBeforeDial       bool                      `json:"consume_before_dial"`
    EvidenceRevision        string                    `json:"evidence_revision"`
    EgressBackend           string                    `json:"egress_backend"`
}

type StorageObservationOverlay struct {
    Role       string `json:"role"`
    Device     uint64 `json:"device"`
    Inode      uint64 `json:"inode"`
    FreeBytes  uint64 `json:"free_bytes"`
    FreeInodes uint64 `json:"free_inodes"`
}

type StorageRequirementOverlay struct {
    Role                    string `json:"role"`
    CurrentReleaseBytes     uint64 `json:"current_release_bytes"`
    CurrentReleaseInodes    uint64 `json:"current_release_inodes"`
    CandidateReleaseBytes   uint64 `json:"candidate_release_bytes"`
    CandidateReleaseInodes  uint64 `json:"candidate_release_inodes"`
    ExtractionBytes         uint64 `json:"extraction_bytes"`
    ExtractionInodes        uint64 `json:"extraction_inodes"`
    RollbackBytes           uint64 `json:"rollback_bytes"`
    RollbackInodes          uint64 `json:"rollback_inodes"`
    PerSlotBytes            uint64 `json:"per_slot_bytes"`
    PerSlotInodes           uint64 `json:"per_slot_inodes"`
    HelperBytes             uint64 `json:"helper_bytes"`
    HelperInodes            uint64 `json:"helper_inodes"`
    RelayBytes              uint64 `json:"relay_bytes"`
    RelayInodes             uint64 `json:"relay_inodes"`
    ControllerBytes         uint64 `json:"controller_bytes"`
    ControllerInodes        uint64 `json:"controller_inodes"`
    LedgerBytes             uint64 `json:"ledger_bytes"`
    LedgerInodes            uint64 `json:"ledger_inodes"`
    LogBytes                uint64 `json:"log_bytes"`
    LogInodes               uint64 `json:"log_inodes"`
    HostReserveBytes        uint64 `json:"host_reserve_bytes"`
    HostReserveInodes       uint64 `json:"host_reserve_inodes"`
    StopReserveBytes        uint64 `json:"stop_reserve_bytes"`
    StopReserveInodes       uint64 `json:"stop_reserve_inodes"`
    WarningReserveBytes     uint64 `json:"warning_reserve_bytes"`
    WarningReserveInodes    uint64 `json:"warning_reserve_inodes"`
}

type LogBoundsOverlay struct {
    UsedBytes uint64 `json:"used_bytes"`
    MaxBytes  uint64 `json:"max_bytes"`
    UsedFiles uint64 `json:"used_files"`
    MaxFiles  uint64 `json:"max_files"`
}

type StorageSizingOverlay struct {
    MaximumActiveConcurrency uint64                      `json:"maximum_active_concurrency"`
    Observations             []StorageObservationOverlay `json:"observations"`
    Requirements             []StorageRequirementOverlay `json:"requirements"`
    LogBounds                LogBoundsOverlay             `json:"log_bounds"`
    EvidenceRevision         string                       `json:"evidence_revision"`
}

type ResourceOverlay struct {
    AdmissionCeiling            ResourceVectorOverlay `json:"admission_ceiling"`
    SlotResources               SlotResourcesOverlay  `json:"slot_resources"`
    MaxCapacity                 uint64                `json:"max_capacity"`
    MaxLiveReferences           uint64                `json:"max_live_references"`
    MaxOfferLogicalBytes        uint64                `json:"max_offer_logical_bytes"`
    MaxLiveOfferLogicalBytes    uint64                `json:"max_live_offer_logical_bytes"`
    TransientMode               string                `json:"transient_mode"`
    PolicyRevision              uint64                `json:"policy_revision"`
    FleetConcurrency            uint64                `json:"fleet_concurrency"`
    NetworkLedgerReserveRows    uint64                `json:"network_ledger_reserve_rows"`
    NetworkLedgerReserveBytes   uint64                `json:"network_ledger_reserve_bytes"`
    History                     HistoryOverlay        `json:"history"`
    RunnerSizing                RunnerSizingOverlay   `json:"runner_sizing"`
    Conntrack                   ConntrackOverlay      `json:"conntrack"`
    Storage                     StorageSizingOverlay  `json:"storage"`
}

type RepositoryOverlay struct {
    Alias            string               `json:"alias"`
    ConfigURL        string               `json:"config_url"`
    ScaleSetName     string               `json:"scale_set_name"`
    Eligibility      string               `json:"eligibility"`
    Weight           uint32               `json:"weight"`
    MaxConcurrency   uint32               `json:"max_concurrency"`
    AgingThreshold   string               `json:"aging_threshold"`
    CredentialName   string               `json:"credential_name"`
    SlotResources    SlotResourcesOverlay `json:"slot_resources"`
}

type PolicyOverlay struct {
    ManifestDigest     string `json:"manifest_digest"`
    CompiledGraphDigest string `json:"compiled_graph_digest"`
    AcquisitionDefault string `json:"acquisition_default"`
}

type ControllerTimingOverlay struct {
    AckTimeout            string `json:"ack_timeout"`
    OperationTimeout      string `json:"operation_timeout"`
    PollCycleTimeout      string `json:"poll_cycle_timeout"`
    ReconciliationTimeout string `json:"reconciliation_timeout"`
    PollCadence           string `json:"poll_cadence"`
    ReconciliationCadence string `json:"reconciliation_cadence"`
    DrainPollCadence      string `json:"drain_poll_cadence"`
    ShutdownTimeout       string `json:"shutdown_timeout"`
    SessionCloseTimeout   string `json:"session_close_timeout"`
    TransitionJoinTimeout string `json:"transition_join_timeout"`
    DurableFinishTimeout  string `json:"durable_finish_timeout"`
    ReplayEvidenceMaxAge  string `json:"replay_evidence_max_age"`
    HostCapacityMaxAge    string `json:"host_capacity_max_age"`
    PollLeaseTTL          string `json:"poll_lease_ttl"`
    LedgerTail            string `json:"ledger_tail"`
}

type FenceTimingOverlay struct {
    LockPollInterval string `json:"lock_poll_interval"`
    RenewalInterval  string `json:"renewal_interval"`
    RenewalTimeout   string `json:"renewal_timeout"`
}

type HealthOverlay struct {
    Sink                  string `json:"sink"`
    MaxDocumentBytes      uint64 `json:"max_document_bytes"`
    ObservationMaxAge    string `json:"observation_max_age"`
}

type ProfileOverlay struct {
    ConformanceEvidenceDigest string `json:"conformance_evidence_digest"`
    NetworkEvidenceDigest     string `json:"network_evidence_digest"`
    PlatformEvidenceRevision  string `json:"platform_evidence_revision"`
}

type LogPolicyOverlay struct {
    MaxBytes uint64 `json:"max_bytes"`
    MaxFiles uint64 `json:"max_files"`
    MaxAge   string `json:"max_age"`
}

type WatchdogOverlay struct {
    Cadence         string           `json:"cadence"`
    RestartDeadline string           `json:"restart_deadline"`
    ProcessGrace    string           `json:"process_grace"`
    HealthMaxAge    string           `json:"health_max_age"`
    Logs            LogPolicyOverlay `json:"logs"`
}

type NamedSecretRef struct {
    Name string `json:"name"`
    Ref  SecretRefOverlay `json:"ref"`
}

type SecretRefOverlay struct {
    Source string `json:"source"`
    Ref    string `json:"ref"`
}

type LegacyOverlay struct {
    CommandFilePath      string   `json:"command_file_path"`
    CommandDigest        string   `json:"command_digest"`
    ConfigurationDigest  string   `json:"configuration_digest"`
    ImageDigests         []string `json:"image_digests"`
    WatchdogDigest       string   `json:"watchdog_digest"`
}
```

Schema version is exactly `1`; no nested pointer or `null` is permitted except
`Legacy`. `Legacy` is nonnull exactly for `legacy-disabled-observer` install
or rollback and null otherwise. All duration strings must parse and equal
`time.Duration.String()`; all paths are canonical absolute target paths; all
raw digests are lowercase 64-hex; all images are immutable full
`name@sha256:<64hex>` references. Repository aliases, secret names, conntrack
timeouts, storage observations/requirements, legacy image digests, and
allowed actions are supplied in the plan-declared canonical order with no
duplicates. Storage roles are exactly `docker-root`, `state`, `staging`,
`rollback`, `scratch`, `logs`. Named secret sources use the single config
allowlist and credential names must resolve exactly once. `AllowedActions` is
the exact closed action list for the operation kind, never an authorization
wildcard.

`PrivateOverlayRevision` is:

```text
SHA256("portable-ghar-private-overlay-v1\0" || canonicalPrivateOverlayJSON)
```

Before the `prepared` journal, persist and read back:

```go
type OperationBinding struct {
    SchemaVersion          uint32               `json:"schema_version"`
    OperationID            string               `json:"operation_id"`
    Kind                   OperationKind        `json:"kind"`
    InstallDisposition     *InstallDisposition  `json:"install_disposition"`
    ExpectedGeneration     uint64               `json:"expected_generation"`
    PriorManifestDigest    *string              `json:"prior_manifest_digest"`
    TargetManifestDigest   *string              `json:"target_manifest_digest"`
    TargetFleet            fleetfence.Fleet     `json:"target_fleet"`
    PrivateOverlayRevision string               `json:"private_overlay_revision"`
}
```

The operation ID must rederive from these exact fields. Every reentry
recanonicalizes the supplied overlay and requires the same revision before
opening an effect receipt. The binding is immutable for the operation
lifetime. `InstallDisposition` is nonnull with exactly
`greenfield-portable`, `upgrade-portable`, or `legacy-disabled-observer` for
kind `install`; its JSON member is literal `null` for every other kind.

The other V1 wire schemas are closed as follows:

```go
type ReceiptState string
type ReservationState string

type FilesystemIdentity struct {
    Role        string `json:"role"`
    MountID     uint64 `json:"mount_id"`
    DeviceMajor uint32 `json:"device_major"`
    DeviceMinor uint32 `json:"device_minor"`
    RootInode   uint64 `json:"root_inode"`
    FSType      string `json:"fs_type"`
}

type ArtifactProjection struct {
    ObjectID       string  `json:"object_id"`
    Kind           string  `json:"kind"`
    Present        bool    `json:"present"`
    ContentDigest  *string `json:"content_digest"`
    IdentityDigest *string `json:"identity_digest"`
    DeviceMajor    uint32  `json:"device_major"`
    DeviceMinor    uint32  `json:"device_minor"`
    Inode          uint64  `json:"inode"`
    Mode           uint32  `json:"mode"`
    Size           uint64  `json:"size"`
    LinkText       *string `json:"link_text"`
    RuntimeIdentity *string `json:"runtime_identity"`
}

type ProcessProjection struct {
    Role               string  `json:"role"`
    PID                uint64  `json:"pid"`
    StartIdentity      string  `json:"start_identity"`
    ExecutableDigest   string  `json:"executable_digest"`
    AcquisitionCapable bool    `json:"acquisition_capable"`
}

type PolicyProjection struct {
    PolicyManifestDigest string `json:"policy_manifest_digest"`
    TransitionEpoch      uint64 `json:"transition_epoch"`
    AcquisitionEnabled   bool   `json:"acquisition_enabled"`
    PendingAcquisitions  uint64 `json:"pending_acquisitions"`
    ActiveListeners      uint64 `json:"active_listeners"`
}

type QuiescenceProjection struct {
    ControllerProcesses uint64 `json:"controller_processes"`
    LegacyProcesses     uint64 `json:"legacy_processes"`
    RunnerProcesses     uint64 `json:"runner_processes"`
    AdapterProcesses    uint64 `json:"adapter_processes"`
    BrokerProcesses     uint64 `json:"broker_processes"`
    HelperProcesses     uint64 `json:"helper_processes"`
    VerifierProcesses   uint64 `json:"verifier_processes"`
    ActiveDials         uint64 `json:"active_dials"`
    PerJobSockets       uint64 `json:"per_job_sockets"`
    PendingAcquisitions uint64 `json:"pending_acquisitions"`
    FleetGuards         uint64 `json:"fleet_guards"`
}

type CurrentSelectionProjection struct {
    ReleaseDirectoryDeviceMajor uint32 `json:"release_directory_device_major"`
    ReleaseDirectoryDeviceMinor uint32 `json:"release_directory_device_minor"`
    ReleaseDirectoryInode       uint64 `json:"release_directory_inode"`
    SymlinkDeviceMajor          uint32 `json:"symlink_device_major"`
    SymlinkDeviceMinor          uint32 `json:"symlink_device_minor"`
    SymlinkInode                uint64 `json:"symlink_inode"`
    RelativeLinkText            string `json:"relative_link_text"`
    ManifestDeviceMajor         uint32 `json:"manifest_device_major"`
    ManifestDeviceMinor         uint32 `json:"manifest_device_minor"`
    ManifestInode               uint64 `json:"manifest_inode"`
    ManifestDigest              string `json:"manifest_digest"`
    FenceGeneration             uint64 `json:"fence_generation"`
    ActiveFleet                 fleetfence.Fleet `json:"active_fleet"`
}

type LegacyNormalizationProjection struct {
    CommandDigest              string   `json:"command_digest"`
    ConfigurationDigest        string   `json:"configuration_digest"`
    ImageDigests               []string `json:"image_digests"`
    WatchdogDigest             string   `json:"watchdog_digest"`
    ForceDisabled              bool     `json:"force_disabled"`
    RunnerWorkerCount          uint64   `json:"runner_worker_count"`
    AcquisitionCapableProcesses uint64  `json:"acquisition_capable_processes"`
}

type TargetPostcondition struct {
    SchemaVersion          uint32                      `json:"schema_version"`
    OperationID            string                      `json:"operation_id"`
    BindingDigest          string                      `json:"binding_digest"`
    EffectKey              string                      `json:"effect_key"`
    Phase                  OperationPhase              `json:"phase"`
    ManifestDigest         *string                     `json:"manifest_digest"`
    PrivateOverlayRevision string                      `json:"private_overlay_revision"`
    FenceGeneration        uint64                      `json:"fence_generation"`
    ActiveFleet            fleetfence.Fleet            `json:"active_fleet"`
    Filesystems            []FilesystemIdentity        `json:"filesystems"`
    Artifacts              []ArtifactProjection        `json:"artifacts"`
    Processes              []ProcessProjection         `json:"processes"`
    Policy                 PolicyProjection            `json:"policy"`
    Quiescence             QuiescenceProjection        `json:"quiescence"`
    CurrentSelection       *CurrentSelectionProjection `json:"current_selection"`
    LegacyNormalization    *LegacyNormalizationProjection `json:"legacy_normalization"`
    ObservedAt             time.Time                   `json:"observed_at"`
}

type OperationReceipt struct {
    SchemaVersion             uint32          `json:"schema_version"`
    OperationID               string          `json:"operation_id"`
    BindingDigest             string          `json:"binding_digest"`
    EffectKey                 string          `json:"effect_key"`
    Phase                     OperationPhase  `json:"phase"`
    State                     ReceiptState    `json:"state"`
    PriorReceiptDigest        string          `json:"prior_receipt_digest"`
    TargetPostconditionDigest *string         `json:"target_postcondition_digest"`
    CreatedAt                 time.Time       `json:"created_at"`
    UpdatedAt                 time.Time       `json:"updated_at"`
}

type StorageRoleReservation struct {
    Role               string `json:"role"`
    MountID            uint64 `json:"mount_id"`
    RequiredBytes      uint64 `json:"required_bytes"`
    RequiredInodes     uint64 `json:"required_inodes"`
    CompensationBytes  uint64 `json:"compensation_bytes"`
    CompensationInodes uint64 `json:"compensation_inodes"`
    ObservedFreeBytes  uint64 `json:"observed_free_bytes"`
    ObservedFreeInodes uint64 `json:"observed_free_inodes"`
}

type CrashOrphanReservation struct {
    ObjectID       string `json:"object_id"`
    FilesystemRole string `json:"filesystem_role"`
    Bytes          uint64 `json:"bytes"`
    Inodes         uint64 `json:"inodes"`
}

type StorageReservation struct {
    SchemaVersion              uint32                     `json:"schema_version"`
    OperationID                string                     `json:"operation_id"`
    BindingDigest              string                     `json:"binding_digest"`
    State                      ReservationState           `json:"state"`
    StorageBudgetDigest        string                     `json:"storage_budget_digest"`
    TargetManifestDigest       *string                    `json:"target_manifest_digest"`
    Filesystems                []FilesystemIdentity       `json:"filesystems"`
    Roles                      []StorageRoleReservation   `json:"roles"`
    CrashOrphans               []CrashOrphanReservation  `json:"crash_orphans"`
    CommittedTargetProofDigest *string                    `json:"committed_target_proof_digest"`
    ReleasedAbsenceProofDigest *string                    `json:"released_absence_proof_digest"`
    CreatedAt                  time.Time                  `json:"created_at"`
    UpdatedAt                  time.Time                  `json:"updated_at"`
}
```

All schema versions are exactly `1`. Receipt state is exactly `applying` or
`applied`; reservation state is exactly `active`, `committed`, or `released`.
An applying receipt has a literal JSON `null`
`target_postcondition_digest`; an applied receipt requires one exact lowercase
64-hex digest and preserves `CreatedAt`. The first receipt has exactly 64
lowercase zeroes as `PriorReceiptDigest`; later receipts require the digest of
the immediately preceding applied receipt. No receipt may chain to an applying
receipt.

`Filesystems` and reservation `Roles` contain exactly these six entries, in
this declaration order and with no duplicate mount/role contradiction:
`docker-root`, `state`, `staging`, `rollback`, `scratch`, `logs`. Equal mount
IDs must carry byte-identical device and filesystem identity. `Artifacts` is
ordered by `object_id`; `Processes` by `(role, pid)`; `CrashOrphans` by
`(filesystem_role, object_id)`. Parsers reject unsorted, duplicate, unknown,
or over-bound entries rather than sorting caller input.

Artifact kind is exactly `regular-file`, `symlink`, `docker-image`, or
`registration`. For an absent artifact, all four nullable identity members are
`null` and all device, inode, mode, and size integers are zero. A present
regular file requires content/identity digests, nonzero device/inode, exact
type/permission mode, authoritative size (including zero), and null link/
runtime identity. A present symlink requires identity digest, nonzero
device/inode, symlink mode, exact `link_text`, null content/runtime identity,
and size equal to the UTF-8 link-text byte length. A present Docker image or
registration requires identity digest plus exact `runtime_identity`, zero
device/inode/mode/size, null link text, and a content digest only where the
runtime exposes an immutable content digest. Empty strings never represent
absence.

`identity_digest` is lower-hex:

```text
SHA256(
  "portable-ghar-artifact-identity-v1\0" ||
  LP(objectID) || LP(kind) || MaybeDigest(contentDigest) ||
  U32(deviceMajor) || U32(deviceMinor) || U64(inode) ||
  U32(mode) || U64(size) || MaybeLP(linkText) || MaybeLP(runtimeIdentity)
)
```

`ProcessProjection.StartIdentity` is exactly one lowercase 64-hex digest:

```text
SHA256(
  "portable-ghar-process-start-v1\0" ||
  LP(lowercase canonical Linux boot_id UUID) ||
  U64(pidNamespaceInode) || U64(pid) ||
  U64(/proc/<pid>/stat field 22 starttime ticks) ||
  Digest32(executableDigest)
)
```

The `/proc/<pid>/stat` parser uses the final `)` delimiter for `comm`, validates
the decimal fields without signs/overflow, and reopens/rechecks boot ID,
namespace inode, executable identity, and stat starttime after observation.
Darwin, a missing/changed field, or process disappearance yields no positive
identity.

`ManifestDigest`, `TargetManifestDigest`, `CurrentSelection`,
`LegacyNormalization`, `CommittedTargetProofDigest`, and
`ReleasedAbsenceProofDigest` are always present JSON members whose absence is
literal `null`. Current selection is nonnull only for a phase that inspects or
mutates it; it is mandatory for `current-selected`, `verified`, and terminal
install proof. Legacy normalization is nonnull only for
`legacy-normalized-proven` and subsequent legacy-disposition install phases;
its image digests are exact immutable `sha256:` values in binding order, and
both counts must be zero with `force_disabled=true`.

An active reservation has both terminal proof members null. A committed
reservation has only `committed_target_proof_digest` nonnull. A released
reservation has only `released_absence_proof_digest` nonnull. The six role
requirements include the complete simultaneous current, candidate, extraction,
rollback, per-slot, helper, relay, controller, ledger, log, and path-specific
compensation envelope. Integer addition uses checked `uint64`; overflow,
counter wrap, or a free-space sample below requirement is a stop result.

Journal timestamps are canonical UTC RFC3339Nano strings with a literal `Z`;
offsets, lower-case `z`, redundant fractional zeroes, absent timestamps, and
non-UTC values are rejected. Nested runtime manifests use their already frozen
field order and `null` rules. `fleetfence.Fleet` encodes only exact lowercase
`none`, `portable`, or `legacy`. Every nullable field is present as an
explicit JSON member whose value is either the canonical object/string or
`null`; omission differs from `null` and is rejected.

Domains are distinct:

```text
portable-ghar-operation-binding-v1
portable-ghar-operation-journal-v1
portable-ghar-operation-receipt-v1
portable-ghar-storage-reservation-v1
portable-ghar-target-postcondition-v1
portable-ghar-host-action-result-v1
```

For each canonical-JSON artifact above, with its exact domain string `D`, the
only artifact digest is:

```text
ArtifactDigest(D, value) = lowerhex(
  SHA256(UTF8(D) || 0x00 || CanonicalJSON(value))
)
```

Therefore `BindingDigest` is the operation-binding artifact digest;
`JournalDigest` is the operation-journal artifact digest;
`PriorReceiptDigest` is the immediately prior operation-receipt artifact
digest; `TargetPostconditionDigest` and public `TargetProofDigest` are the
target-postcondition artifact digest; reservation readback uses the
storage-reservation artifact digest; and any sealed action result uses the
host-action-result artifact digest. No field uses bare JSON SHA-256, another
artifact's domain, the file's newline-bearing bytes, or an identity preimage.
Private-overlay, runtime-manifest, artifact-identity, process-start,
OperationID, and effect-key digests retain their separately declared exact
preimages.

Journal, binding, receipt, reservation, target-postcondition, and action-result
parsers all enforce byte limits, strict fields, one value, exact canonical
remarshal equality, and exhaustive golden vectors for nil/empty/nested/time/
fleet behavior. The vectors include generation `0`, generation
`math.MaxUint64`, nil and present digests, empty and maximum bounded slices,
genesis and non-genesis receipt links, all receipt/reservation states, every
fleet, current-selection absent/present, and one-byte changes to every field.
These codec/vector tests must be GREEN before lifecycle-engine implementation
begins.

### Lifecycle lock, effect receipts, and target proof

One stable, never-renamed `lifecycle.lock` inode lives beside the journal. All
mutating host actions hold it exclusively for their process lifetime. The
watchdog opens the same inode and either obtains a bounded exclusive lock or
returns without mutation. The operation engine identity-pins the root, lock,
journal directory, receipt directory, and reservation directory. Unlinking or
recreating the lock is an integrity failure, not recovery.

Each phase has one deterministic effect key:

```text
SHA256(
  "portable-ghar-operation-effect-v1\0" ||
  Digest32(operationID) || LP(phase) ||
  U64(expectedGeneration) ||
  MaybeDigest(priorManifestDigest) ||
  MaybeDigest(targetManifestDigest) ||
  LP(targetFleet) || Digest32(privateOverlayRevision)
)
```

The result is lowercase hex. It uses the exact `U64`, `LP`, `Digest32`, and
`MaybeDigest` primitives defined for `OperationID`; string concatenation,
decimal formatting, omitted nils, and an empty-digest sentinel are forbidden.

Before an effect, write a canonical `applying` receipt for that exact key.
After the effect, obtain a typed target postcondition and atomically replace
the receipt with `applied`. A replay seeing `applying` inspects the target
first: exact postcondition advances to `applied`; proven absence safely retries
the same idempotent effect; ambiguity returns non-success and leaves the
operation recoverable. It never creates a second effect key.

Receipts are hash chained by the prior applied receipt digest. The canonical
receipt codec fixes field order, null handling, domain separator, and version
exactly as the manifest codec does. The journal phase may advance only when
the matching `applied` receipt and chain read back exactly.

`TargetPostcondition` is a closed, non-authorizing proof containing the
operation/effect key, manifest digest, fence generation/fleet, pinned
filesystem identities, exact artifact/process/policy/quiescence projections,
observation time, and its domain-separated digest. Terminal success is the
conjunction of:

1. exact planned manifest and private-overlay preimage;
2. a complete applied-receipt chain;
3. a fresh target postcondition under the same fence generation/fleet;
4. a current non-stop storage result and committed reservation;
5. any required hosted hold revalidated after the last mutating effect; and
6. the exact terminal journal bytes read back from the target.

No source-side stage hash, local journal state, subprocess exit, or shell
result can substitute for that conjunction.

### Closed compensation DAGs

Compensation is not a generic callback. `OperationBinding` determines one
closed compensation DAG, and every compensation phase uses an effect key
derived from the original operation ID plus the compensation phase. No new
overlay, target, manifest, command, fence snapshot, or storage vector may
enter after `prepared`.

The selector uses these typed predicates only:

```text
R(p)       matching applied receipt chain exists through phase p
F(f,g)     a fresh Task 9 header proves fleet f at generation g
CUR(x)     current-selection postcondition is exact prior, exact target, or absent
Q0         every QuiescenceProjection field is zero
P0         PolicyProjection is disabled with zero pending acquisitions/listeners
OBJ(x)     the complete operation-created object set equals x by identity
H(valid)   the bound hosted-hold tuple freshly revalidates, or does not
NLEG       the exact bound LegacyNormalizationProjection is force-disabled
           with zero Worker/acquisition-capable process counts
```

Every predicate is evaluated from one fresh `TargetPostcondition` while
holding the lifecycle lock. None accepts cached status, source-side state,
process exit alone, partial object inventory, or an unknown value.

The allowable normal source-phase sets are closed:

```text
I-G-PRE = {
  prepared, preflight-proven, candidate-staged, candidate-smoked,
  prior-retained, disposition-greenfield-proven, prior-absence-proven
}
I-G-POST-FENCE = {
  fence-portable, watchdog-installed, policy-disabled,
  observer-started, zero-proven
}
I-G-POST-SELECT = {current-selected}

I-U-PRE-SELECT = {
  prepared, preflight-proven, candidate-staged, candidate-smoked,
  prior-retained, disposition-upgrade-proven, prior-acquisition-disabled,
  prior-drained, prior-controller-stopped, prior-quiescence-proven,
  fence-portable-proven, watchdog-installed, policy-disabled,
  observer-started, zero-proven
}
I-U-POST-SELECT = {current-selected}

I-L-PRE-SELECT = {
  prepared, preflight-proven, candidate-staged, candidate-smoked,
  prior-retained, disposition-legacy-proven, legacy-acquisition-disabled,
  legacy-drained, legacy-controller-stopped, legacy-quiescence-proven,
  fence-legacy-proven, legacy-normalized-proven, watchdog-installed, policy-disabled,
  observer-started, zero-proven
}
I-L-POST-SELECT = {current-selected}

S-FORWARD = {
  prepared, hold-proven, watchdog-disabled, policy-disabled,
  drained, controller-stopped
}
S-NONE = {fence-none}

RE-PRE = {prepared, stopped-proven, policy-disabled}
RE-POST = {fence-portable, observer-started, watchdog-installed}

RB-PRE = {
  prepared, hold-proven, watchdog-disabled, policy-disabled, drained,
  controller-stopped, quiescence-proven, fence-none, legacy-restored
}
RB-POST = {fence-legacy, legacy-started}

U-FORWARD = {
  prepared, quiescence-proven, watchdog-removed, controller-removed,
  registration-removed, retention-proven
}
```

`verified` for install and the phase immediately before `complete` for every
other kind are not compensation sources: exact proof can only replay forward
to `complete`. `complete` and every `compensated-*` phase are terminal.

The only path values and transitions are:

| `CompensationPath` | Exact normal source set and required predicate | Exact path-specific phases | Only permitted object/fence mutations | Required terminal proof/result |
| --- | --- | --- | --- | --- |
| `install-greenfield-pre-handoff` | source in `I-G-PRE`; `R(source) && F(none,0) && CUR(absent)` | `cg-pre-started`, `cg-pre-candidate-stopped`, `cg-pre-candidate-removed`, `cg-pre-absence-proven`, `compensated-greenfield-absent` | stop only an operation-created candidate process; remove only `OBJ(operation-created candidate)`; no current-selection or fence mutation | `F(none,0) && CUR(absent) && Q0 && P0 && OBJ(empty)`; `HostActionCompensated` |
| `install-greenfield-post-handoff` | source in `I-G-POST-FENCE`; `R(source) && F(portable,1) && CUR(absent)` | `cg-fence-started`, `cg-fence-observer-stopped`, `cg-fence-quiescence-proven`, `cg-fence-none`, `cg-fence-candidate-removed`, `compensated-greenfield-none` | stop only candidate/watchdog; Task 9 `portable@1 -> none@2`; remove only operation-created candidate; current remains absent | `F(none,2) && CUR(absent) && Q0 && P0 && OBJ(empty)`; `HostActionCompensated` |
| `install-greenfield-post-selection` | source in `I-G-POST-SELECT`; `R(current-selected) && F(portable,1) && CUR(target)` | `cg-select-started`, `cg-select-observer-stopped`, `cg-select-quiescence-proven`, `cg-select-current-removed`, `cg-select-none`, `cg-select-candidate-removed`, `compensated-greenfield-selected-none` | stop candidate/watchdog; remove `current` only after exact symlink-inode/target proof; Task 9 `portable@1 -> none@2`; remove only operation-created candidate | `F(none,2) && CUR(absent) && Q0 && P0 && OBJ(empty)`; `HostActionCompensated` |
| `install-upgrade-pre-selection` | source in `I-U-PRE-SELECT`; `R(source) && F(portable,expectedGeneration) && CUR(prior)` | `cu-pre-started`, `cu-pre-candidate-stopped`, `cu-pre-candidate-removed`, `cu-pre-prior-selection-proven`, `cu-pre-prior-disabled-proven`, `compensated-upgrade-prior` | stop/remove only operation-created candidate/watchdog; no fence/current mutation; prior release is immutable | same portable generation, `CUR(prior) && Q0 && P0 && OBJ(no operation-created candidate)`; `HostActionCompensated` |
| `install-upgrade-post-selection` | source in `I-U-POST-SELECT`; `R(current-selected) && F(portable,expectedGeneration) && CUR(target)` | `cu-select-started`, `cu-select-observer-stopped`, `cu-select-quiescence-proven`, `cu-select-prior-restored`, `cu-select-prior-observer-started-disabled`, `cu-select-prior-zero-proven`, `cu-select-candidate-removed`, `compensated-upgrade-restored` | stop target observer/watchdog; atomically restore only the binding's retained prior symlink; start only the retained prior immutable observer disabled; remove only target candidate after selection restoration | same portable generation, `CUR(prior) && P0`, exact prior process identity and zero proof, no target-selected object; `HostActionCompensated` |
| `install-legacy-pre-selection` | source in `I-L-PRE-SELECT`; `R(source) && F(legacy,expectedGeneration) && CUR(prior)` and, when source is at/after `legacy-normalized-proven`, `NLEG` | `cl-pre-started`, `cl-pre-candidate-stopped`, `cl-pre-candidate-removed`, `cl-pre-prior-selection-proven`, `cl-pre-legacy-zero-proven`, `compensated-legacy-prior` | stop/remove only operation-created candidate/watchdog; no fence/current mutation; never start Portable acquisition | same legacy generation, `CUR(prior) && P0 && NLEG`, no operation candidate; `HostActionCompensated` |
| `install-legacy-post-selection` | source in `I-L-POST-SELECT`; `R(current-selected) && F(legacy,expectedGeneration) && CUR(target) && NLEG` | `cl-select-started`, `cl-select-observer-stopped`, `cl-select-quiescence-proven`, `cl-select-prior-restored`, `cl-select-legacy-started-disabled`, `cl-select-legacy-zero-proven`, `cl-select-candidate-removed`, `compensated-legacy-restored` | stop target observer/watchdog; restore only the captured prior selection; start only exact normalized legacy argv force-disabled; remove only target candidate after restoration; no fence mutation | same legacy generation, `CUR(prior) && P0 && NLEG`, exact legacy process/zero proof, no target-selected object; `HostActionCompensated` |
| — (`CompensationPath` remains null; forward-only recovery) | source in `S-FORWARD`; `R(source) && F(portable,expectedGeneration) && !Q0` | no compensation pivot; replay the remaining normal disable/drain/stop/quiescence phases only | normal forward safe-stop effects only; no enable, selection, or reverse fence mutation | until Q0 is proven, journal/reservation retained and `HostActionRecoverable`; after Q0, normal graph may continue |
| `suspend-expired-at-none` | source in `S-NONE`; `R(fence-none) && F(none,expectedGeneration+1) && !H(valid)` | `cs-none-started`, `cs-none-disabled-proven`, `cs-none-quiescence-proven`, `compensated-suspend-none` | no fence/current mutation and no process start; disable/stop only | same none generation, `Q0 && P0`; `HostActionCompensated` |
| `resume-pre-handoff` | source in `RE-PRE`; `R(source) && F(none,expectedGeneration) && CUR(target-or-prior)` | `cr-pre-started`, `cr-pre-observer-absent`, `cr-pre-watchdog-absent`, `cr-pre-none-disabled-proven`, `compensated-resume-none` | remove only operation-created observer/watchdog registration; no fence/current mutation | same none generation, `Q0 && P0`; `HostActionCompensated` |
| `resume-post-handoff` | source in `RE-POST`; `R(source) && F(portable,expectedGeneration+1)` | `cr-post-started`, `cr-post-observer-stopped`, `cr-post-quiescence-proven`, `cr-post-none`, `cr-post-watchdog-absent`, `compensated-resume-none` | stop only operation observer/watchdog; Task 9 `portable@(g+1) -> none@(g+2)`; no release deletion | `F(none,expectedGeneration+2) && Q0 && P0`; `HostActionCompensated` |
| `rollback-pre-legacy-handoff` | source in `RB-PRE`; either `F(portable,expectedGeneration)` before normal `fence-none`, or `F(none,expectedGeneration+1)` at/after it; `CUR(prior-or-target)` remains binding-known | `cb-pre-started`, remaining normal safe-stop phases if required, `cb-pre-none-proven`, `compensated-rollback-none` | forward disable/drain/stop and Task 9 `portable -> none` only if not already applied; retained legacy artifacts may remain but may not start | exact `F(none,expectedGeneration+1) && Q0 && P0`; `HostActionCompensated` |
| `rollback-post-legacy-handoff` | source in `RB-POST`; `R(source) && F(legacy,expectedGeneration+2)` | `cb-post-started`, `cb-post-legacy-stopped`, `cb-post-legacy-quiescence-proven`, `cb-post-none`, `compensated-rollback-legacy-none` | stop only restored legacy process; Task 9 `legacy@(g+2) -> none@(g+3)`; no release/ledger deletion | `F(none,expectedGeneration+3) && Q0 && P0`; `HostActionCompensated` |
| — (`CompensationPath` remains null; forward-only recovery) | source in `U-FORWARD`; `R(source)` plus exact identity inventory for every remaining Portable object | no compensation pivot; replay only the next normal removal phase from target readback | remove only the binding-listed watchdog, controller, registration, current link, and binaries; never remove retained state/ledger/journal/manifest/rollback objects | ambiguity is `HostActionRecoverable`; exact absence plus retention proof advances through normal `complete` and returns `HostActionComplete` |

Rows marked forward-only do not set `CompensationPath`. For every other row,
at the first path-specific phase the journal persists the selected path before
performing another mutation. Reentry at a path-specific phase requires that
same path and resumes only the next phase in that row. The normal source phase
and selecting postcondition digest remain in the first compensation receipt,
so a crash cannot cause reselection.

For paths that use `expectedGeneration+n`, checked addition must succeed and
the live Task 9 header must match the preceding applied handoff exactly. A
fence-changing compensation uses only Task 9's next-generation handoff. Any
unlisted source phase, predicate combination, object identity, path/phase
pair, ambiguous readback, failed receipt write, or failed target proof retains
the journal/reservation and returns recoverable/failed; it cannot enter or
report a compensated terminal.

### Durable storage reservation

The exclusive lifecycle lock prevents concurrent Portable GHAR lifecycle
writes, but unrelated Docker/QTS activity can still consume space. Before the
first release write, persist one `StorageReservation` keyed by operation ID.
It binds the storage-budget digest, all six pinned filesystem identities, the
complete simultaneous required byte/inode vector (including planned
compensation), observed crash-orphan inventory, and target manifest.

At every phase boundary the engine re-observes free bytes/inodes and orphan
inventory, recomputes `ValidateStorageSizing`, and rejects a stop result before
another write. The reservation becomes `committed` only with the terminal
target proof. It is released only after a terminal compensated failure proves
all operation-created objects absent, or after later retention policy
authorizes deletion. An fsync/readback failure leaves the reservation live and
the operation non-successful. The watchdog treats any active reservation or
nonterminal journal as lifecycle-owned and performs no competing repair.

## Private Runtime and Controller Composition

Extend `internal/config/runtime.go` with a nested `ControllerRuntime` pointer.
`LoadRuntime` remains compatible with the narrow transport/offline document:
the nested object may be absent and its production-only values are not
validated there. `LoadControllerRuntime` requires it and validates every
field. The nested object uses custom strict unmarshalling so unknown fields are
rejected despite the compatibility split.

The production configuration contains closed typed sections:

- `manifest`: absolute path plus expected manifest digest;
- `identity`: fleet alias, build ID, host profile, degraded acknowledgement,
  expected fence generation, and owner ID;
- `paths`: database, fence root, broker root, seccomp root, policy, trust lock,
  admin socket, health socket, and operation-journal root;
- `docker`: absolute binary, broker network, and immutable image references;
- `resources`: complete admission ceiling, controller history limits,
  history-pressure thresholds, and complete runner/adapter/broker/helper/
  verifier resource vectors;
- `repositories`: immutable public aliases, exact config URLs, exact scale-set
  names, eligibility, weights, concurrency, queue ages, and `SecretRef`s;
- `policy`: exact policy-manifest and compiled graph digests;
- `controller`: all operation, poll, reconciliation, shutdown, session-close,
  transition-join, durable-finish, drain, replay-age, host-capacity-age, lease,
  and ledger-tail durations;
- `fence`: lock poll, renewal interval, and renewal timeout;
- `health`: local closed sink only for Task 10; no Worker transport;
- `profile`: typed QTS source configuration and explicit operator-approved
  sizing evidence; and
- `watchdog`: cadence, restart deadline, process grace, health max age, and
  bounded log policy.

There are no production defaults. Durations are explicit strings and resource
quantities are explicit unsigned integers. All related values are checked for
overflow and cross-field consistency.

Build the disabled observer in this order:

1. parse and rehash the runtime manifest;
2. require config build/generation/profile/digests to match the manifest;
3. open the SQLite store with explicit history limits;
4. create the state adapter and normalize a newer disabled policy;
5. inspect the fence;
6. if portable-owned, open the exact generation guard provider; if legacy-
   owned, call `NormalizeLegacyObserver`; reject `none`;
7. construct the zero-demand admission broker from immutable templates;
8. construct Docker cleanup authority, network-jail lifecycle, and reconciler
   only from complete specifications;
9. inject unavailable external permit, hosted router, replay verifier, and
   Worker health sink implementations whose every method returns a closed
   unavailable error;
10. supply no poll targets and reject every attempt to set `canary-only` or
    `enabled` while those authorities are unavailable;
11. perform cold local reconciliation under disabled acquisition;
12. serve only the closed local admin socket; and
13. on shutdown, persist another disabled epoch, revoke pre-running work,
    close local sessions/resources, and prove quiescence.

The factory returns a composite closer. Every partially constructed component
is closed in reverse order. A close failure is joined into the result and
never converted to success.

The unavailable external graph is one sealed concrete type, not a set of
optional callbacks. Its permit, hosted-route, replay, and Worker-health methods
all return closed unavailable errors. The disabled observer receives no
interface exposing a generic network dial, GitHub session, routing mutation,
listener release, image apply, lifecycle journal advance, or fence handoff.
Compile-time package-boundary tests and runtime mutation traps prove that
observer construction cannot acquire any such port. Local observation output
is one-way: its return values cannot alter controller policy, retry, backoff,
recovery, or operation success.

## Host Lifecycle Engine and Master CLI

Create `internal/cli/host.go` and `cmd/portable-ghar/main.go`.

Public parsing is exact:

```text
portable-ghar deploy host
  --private PATH --acquisition disabled

portable-ghar verify host
  --private PATH --require-zero-listeners

portable-ghar suspend host
  --private PATH --drain-policy=wait|cancel
  --hosted-confirmation PATH

portable-ghar resume host
  --private PATH --acquisition disabled
```

Unknown, duplicate, reordered, empty, trailing, abbreviated, or conflicting
arguments return usage without an effect. Mutating actions require root on the
target but the local deploy dispatcher itself never treats local root as
target identity.

`internal/cli` receives a closed `HostTransport`:

```go
type HostAction uint8

const (
    ActionInstall HostAction = iota + 1
    ActionVerify
    ActionSuspend
    ActionResume
)

type HostTransport interface {
    ProveTarget(context.Context, PrivateOverlay) (TargetProof, error)
    Stage(context.Context, TargetProof, StagedRelease) (StageProof, error)
    Invoke(context.Context, TargetProof, HostAction, FixedArguments) (ActionResult, error)
}
```

There is no generic command, shell, destination, environment, or stdin
method. `FixedArguments` is constructed only after validating the private
overlay and public command. `deploy` stages only manifest-bound files under
one overlay-declared staging root, rehashes them remotely, then invokes the
fixed install script. `verify`, `suspend`, and `resume` invoke only their fixed
scripts. Public output is one closed status document and contains no private
path, target identifier, command output, repository, image reference, or
credential reference.

The target-side internal surface additionally supports the exact fixed actions
used by QTS scripts, including rollback and uninstall. It is not reachable
through arbitrary public action names.

Every Go target action emits exactly one bounded canonical result:

```go
type HostActionStatus string

const (
    HostActionComplete HostActionStatus = "complete"
    HostActionRecoverable HostActionStatus = "recoverable"
    HostActionCompensated HostActionStatus = "compensated"
    HostActionFailed HostActionStatus = "failed"
)

type HostActionResult struct {
    Status          HostActionStatus `json:"status"`
    OperationID     string           `json:"operation_id"`
    JournalDigest   string           `json:"journal_digest"`
    TargetProofDigest *string        `json:"target_proof_digest"`
    FenceGeneration uint64           `json:"fence_generation"`
    ActiveFleet     fleetfence.Fleet `json:"active_fleet"`
    ErrorClass      string           `json:"error_class"`
}
```

Only `complete` with a nonnil matching target proof is success. Shell requires
exit zero, one canonical result, exact operation ID/fence binding, and
`complete`; any parse failure, truncation, extra output, signal, nonzero exit,
or other status is failure. Cleanup and compensation cannot change a failed
primary result to success.

## QTS Lifecycle State Machines

### Install

Before the first install write:

1. prove EUID 0, Linux, exact QTS profile/target identity, and not the invoking
   development/control Mac;
2. open and identity-pin every private root;
3. parse/re-hash the manifest and private overlay;
4. prove all staged file, image, trust, seccomp, policy, conntrack, storage,
   log, and optional archive digests;
5. evaluate all six storage roles through `ValidateStorageSizing`, including
   simultaneous current/candidate/extraction/rollback/per-slot/helper/relay/
   controller/retained-ledger/log/host reserves;
6. require exact bounded log settings;
7. inspect the current fence generation/fleet and current manifest;
8. reject any build request unless the private action is an attested immutable
   pull, an administrator build, or the separately declared rollback-image
   run/exec/commit recovery method;
9. acquire and identity-pin the sole lifecycle lock;
10. create/read back the `prepared` journal and storage reservation; and
11. only then create a staging object.

Install stages immutable image digests without a live mutable retag, runs the
exact listener version smoke test, reads back all image digests, preserves the
prior immutable release and manifest, then follows the exact persisted
disposition graph. An upgrade barriers acquisition, drains, stops, and proves
the prior Portable controller quiescent. A legacy install performs the same
closed sequence against the captured authority and obtains a fresh
`NormalizeLegacyObserver` proof. Greenfield proves complete prior absence.
Only then may the engine install the root watchdog idempotently, persist a
disabled policy, start the candidate through its immutable path, and prove
zero listeners and full quiescence. It finally applies the receipt-backed
`current-selected` symlink mutation and rereads the exact selection/fence
postcondition. No old controller/legacy process and candidate observer are
allowed to overlap, and no observer starts from the mutable `current` link.

Legacy migration additionally lists exact legacy runner containers, inspects
their process inventories, and removes only containers with no
`Runner.Worker`. A registered idle old-image runner is disabled/drained before
candidate selection so it cannot take one more job.

### Suspend

Suspend requires fresh typed external hosted-hold evidence bound to every
configured repository, the current Worker transition epoch, fence generation,
and an unexpired receipt interval. It cannot create or refresh that evidence.

Order is fixed:

1. journal `prepared` and prove hold;
2. disable watchdog registration and read it back absent;
3. call the live controller acquisition barrier to a newer disabled epoch;
4. drain with exact `wait` or `cancel` policy;
5. stop controller and wait boundedly;
6. prove no listener, runner, adapter, broker, helper, verifier, dial, per-job
   socket, pending acquisition, or portable guard remains;
7. retain stable ledgers through `T`; and
8. hand `portable -> none` at the exact expected generation.

Any unjoinable controller call must first persist fatal/zero state and then
terminate the process. Suspend returns failure until process death and
quiescence are positively observed.

Hosted evidence is revalidated immediately before the acquisition barrier,
immediately before `portable -> none`, and after the terminal target readback.
The exact hold ID, server-owned transition epoch, repository set, not-before,
not-after, fence generation, and proof digest must still match. If it expires
after reaching `none`, suspend remains safely at `none` and returns recoverable
non-success; it never compensates by restoring portable acquisition.

### Resume

Resume requires the stopped state, exact manifest, `none` ownership, and the
current generation. While stopped it opens the state store, compare-and-sets a
new disabled/empty/zero epoch, rereads it, hands `none -> portable`, starts the
observer under the new portable generation, installs the watchdog disabled,
and proves the same zero policy plus zero listeners before returning.

It does not restore a previous enabled/canary policy. Operator and external
failover authority must later create any nonzero transition.

### Rollback

`rollback-controller.sh` accepts only:

```text
--private PATH
--expected-generation N
--hosted-confirmation PATH
--legacy-command-file PATH
```

The command file is a root-owned mode-0600 canonical JSON argv array captured
from the live legacy deployment. It is never sourced or evaluated. Rollback
validates hosted evidence, reuses the suspend state machine, reaches and proves
`none`, verifies the captured legacy binary/scripts/images/config/watchdog
digests, hands `none -> legacy` at the next generation, and starts the exact
argv only through `run-legacy-fenced.sh`.

If a post-handoff effect fails, compensation is a new expected-generation
`legacy -> none` transition. It never restores a prior header or decrements a
generation.

Every possible compensation is enumerated in the kind/phase graph before
execution. Its effect key and storage reservation are pure functions of the
original operation record. No free-form repair command or newly invented
object is allowed. A failed compensation leaves the original operation
recoverable and cannot report terminal success.

### Uninstall

`uninstall-controller.sh --private PATH --retain-state` requires exact `none`
or `legacy` ownership and complete Portable quiescence. It atomically removes
watchdog registration, controller registration, current symlink, and binaries,
then proves absence. It retains state, stable ledgers, operation journals,
manifests, and rollback artifacts.

`--purge-state-after-retention` is a distinct future/operator action. Task 10
parses but refuses it without a private, fresh, typed retention proof. It is
never implied by `--retain-state` omission.

## Watchdog

Create `cmd/portable-ghar-watchdog/main.go` with exact command:

```text
portable-ghar-watchdog run --private PATH --manifest PATH
```

The watchdog:

1. requires root/Linux/QTS identity and exact private modes;
2. rehashes the manifest and every controller/watchdog binary;
3. reads the operation journal and refuses to cross or repair an active
   lifecycle operation;
4. reevaluates the full storage envelope and log bounds on every cycle;
5. invokes the same acquisition safe-stop action before a stop threshold;
6. inspects fence generation/fleet and process identity;
7. when `portable` owns the fence, acquires a current guard across any
   controller restart and proves disabled policy/zero listeners afterward;
8. when `legacy` owns the fence, calls the same legacy observer normalization
   and may restart only the force-disabled observer, proving zero before and
   after;
9. when `none` owns the fence, leaves the controller stopped;
10. uses a bounded restart window and exact process absence/presence readback;
11. reports only a closed status/reason; and
12. never contacts GitHub, a Worker, a routing API, or a repository.

An unjoinable safe-stop call is a fatal controller failure. The watchdog waits
for process death, then may perform one disabled restart. It never writes a
side flag as a substitute for the acquisition barrier.

The watchdog is built against a narrow `Supervisor` interface with only
`Inspect`, `SafeStop`, `StartDisabled`, and `ProveDisabled` operations. It does
not import the lifecycle apply engine, host transport, journal transition
writer, image stager, manifest switcher, fence handoff, or action-result
writer. It may read a journal/receipt/reservation but cannot advance one. If a
nonterminal lifecycle operation exists, only an explicit invocation of that
same operation ID may resume it; the watchdog reports recoverable state and
does not improvise repair.

The dependency gate must return no matches:

```bash
GOTOOLCHAIN=go1.26.5 go list -deps ./cmd/portable-ghar-watchdog |
  grep -E '(^|/)github.com/actions/scaleset$|(^|/)internal/githubscale$'
```

A second dependency/symbol test rejects imports of `internal/cli`, any
deployment apply package, and references to install/resume/rollback/uninstall
actions from the watchdog package.

## QTS and systemd Packaging

Create the exact QTS scripts named by Task 10 plus:

- `deploy/qts/watchdog.cron.example`, containing placeholders only and no
  schedule selected for a real host;
- shell libraries that expose only fixed Go helper calls; and
- Bats fixtures that use synthetic temporary roots and injected fixed-action
  fakes.

Create systemd templates:

- `portable-ghar-controller.service`;
- `portable-ghar-watchdog.service`;
- `portable-ghar-watchdog.timer`; and
- environment/overlay placeholders only.

Units use absolute placeholder paths, `NoNewPrivileges`, private temporary
space, bounded restart behavior, explicit file modes, and no Docker socket or
network dependency in the watchdog. They are templates, not enabled units.

The target preflight also proves the minimum durability feature matrix: local
filesystem identity is stable; regular-file and directory `fsync` succeed;
same-filesystem rename persists across a bounded crash probe; no-follow and
descriptor-relative operations are supported; and the installed binary's Go
runtime/architecture match the declared support matrix. Missing or ambiguous
primitives force read-only verification only. Source CI builds the minimum
declared Linux target, while Task 11 runs the positive QTS crash probe.

## TDD Tasks

### Task 1: Manifest and journal RED/GREEN

**Files:**

- Create `internal/hostruntime/runtime_manifest.go` and tests.
- Create `internal/hostruntime/operation_journal.go` and tests.

- [ ] RED: exact canonical vectors; unknown/missing/duplicate/trailing fields;
  digest kind confusion; invalid acquisition/egress/generation/archive shape;
  byte limit; wrong type/mode/owner; symlink/hardlink/parent replacement;
  partial write; fsync/rename/readback failure.
- [ ] RED: byte-exact golden vectors for `OperationBinding`,
  `OperationJournal`, `OperationReceipt`, `TargetPostcondition`, and
  `StorageReservation`, including every nullable field/state, all three
  fleets, generation 0/max/overflow, absent-vs-empty digest, ordering,
  one-field mutations, genesis chaining, `U32`/`U64`/`LP` preimages, and
  domain separation.
- [ ] RED: the complete `PrivateOverlay` and every nested wire section,
  declaration-order remarshal, only-legacy nullability, canonical duration/
  path/image/secret/action ordering, disposition-present/null OperationID
  vectors, universal artifact-digest domains, every artifact kind identity,
  and Linux process-start identity race/substitution vectors.
- [ ] RED: every kind/phase edge, skipped/backward/changed transition,
  different-operation collision, exact replay, terminal replay, timestamp
  misuse, stale generation, changed manifest/overlay, and overflow.
- [ ] RED: crash/reentry after each greenfield, upgrade, and legacy
  acquisition-barrier/drain/stop/quiescence boundary; no prior/candidate
  process overlap; applying/applied `legacy-normalized-proven`; wrong/nonzero
  normalization projection; immutable-path candidate start; applying/applied
  `current-selected` replay; symlink identity substitution; directory-fsync
  failure; install `verified` and resume `zero-proven` forward-only completion.
- [ ] RED: stable lifecycle lock unlink/recreate; applying-with-committed
  effect; applying-with-absent effect; ambiguous postcondition; broken receipt
  chain; source-only proof; final path lost after file fsync; parent fsync
  failure; active/committed storage reservation and crash-orphan accounting.
- [ ] RED: every normal-source/target-predicate compensation matrix row,
  every crash point in every path-specific phase, wrong/non-null path,
  cross-path phase injection, unlisted source/predicate/object identity,
  overflowed compensation generation, and forward-only suspend/uninstall
  recovery with a null compensation path.
- [ ] GREEN: strict parse/validate/digest plus atomic descriptor-relative
  persistence, one transition function, effect receipts, target proof, and
  reservation state.

### Task 2: Private runtime and disabled controller composition

**Files:**

- Modify `internal/config/runtime.go` and tests.
- Modify `cmd/portable-ghar-controller/main.go`, `commands.go`, and tests.
- Add only narrowly required source files under existing packages.

- [ ] RED: every production field required by `LoadControllerRuntime`; nested
  unknown fields; inline secrets; inconsistent manifest/config; missing
  cleanup authority; stale fence; legacy observer without new zero epoch;
  unavailable external authority; nonzero policy/admin attempt; partial-open
  close order; crash-seeded SQLite states.
- [ ] RED mutation traps for every unavailable external/apply authority and
  observer-output influence on policy, retry, recovery, or success.
- [ ] GREEN: construct and run a real local disabled observer, preserve narrow
  `LoadRuntime`, and keep all external/nonzero authorities unavailable.
- [ ] Prove controller startup and shutdown both publish a newer disabled
  epoch, reconcile local state, release no listener, and leave zero managed
  per-job runtime.

### Task 3: Host engine and exact CLI

**Files:**

- Create `internal/cli/host.go` and tests.
- Create `cmd/portable-ghar/main.go` and tests.

- [ ] RED every command/flag permutation, local-vs-target identity confusion,
  arbitrary destination/command/environment injection, changed target proof,
  stage digest drift, remote result mismatch, timeout, cancellation, and
  sanitized output.
- [ ] GREEN the closed action transport and exact public dispatch.

### Task 4: Crash-resumable QTS operations

**Files:**

- Create every Task 10 QTS script and shell library.
- Create every Task 10 QTS Bats file.
- Add Go lifecycle implementation under `internal/hostruntime`.

- [ ] RED EUID/OS/QTS/mode/path/digest/fence/policy/listener/storage/log/
  hosted-evidence/build-method failures before first write.
- [ ] RED kill after persistence and after effect readback for every phase of
  all five operations; exact rerun must complete once.
- [ ] RED effect-committed/error-return ambiguity, stale process, watchdog
  race, old-image idle registration, unjoinable call, compensation after
  fence handoff, expired hold at each sensitive boundary, storage reservation
  replay, crash orphans, shell-result truncation, and retention refusal.
- [ ] GREEN install/suspend/resume/rollback/uninstall with the ordered state
  machines above.

### Task 5: Watchdog and service templates

**Files:**

- Create `cmd/portable-ghar-watchdog/main.go` and tests.
- Create QTS cron and systemd templates.

- [ ] RED manifest/journal/storage/process/fence drift; portable/legacy/none
  behavior; old watchdog race; repeated crash; unjoinable stop; missing
  quiescence; route-writer trap; dependency import trap.
- [ ] GREEN fixed restart/safe-stop authority and disabled observer behavior.

### Task 6: Source verification and exact review

Run:

```bash
GOCACHE=/private/tmp/portable-ghar-task10-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test -race \
  ./internal/hostruntime/... \
  ./internal/config \
  ./internal/cli \
  ./cmd/portable-ghar-controller \
  ./cmd/portable-ghar \
  ./cmd/portable-ghar-watchdog \
  -count=1

GOCACHE=/private/tmp/portable-ghar-task10-go-cache \
GOTOOLCHAIN=go1.26.5 \
go vet ./...

GOCACHE=/private/tmp/portable-ghar-task10-go-cache \
GOTOOLCHAIN=go1.26.5 \
go tool staticcheck ./...

GOCACHE=/private/tmp/portable-ghar-task10-go-cache \
GOTOOLCHAIN=go1.26.5 \
go tool govulncheck ./...

bats \
  tests/shell/qts/controller-install.bats \
  tests/shell/qts/controller-verify.bats \
  tests/shell/qts/controller-suspend.bats \
  tests/shell/qts/controller-resume.bats \
  tests/shell/qts/controller-rollback.bats \
  tests/shell/qts/controller-uninstall.bats \
  tests/shell/qts/watchdog.bats

test -z "$(
  GOCACHE=/private/tmp/portable-ghar-task10-go-cache \
  GOTOOLCHAIN=go1.26.5 \
  go list -deps ./cmd/portable-ghar-watchdog |
  grep -E '(^|/)github.com/actions/scaleset$|(^|/)internal/githubscale$' || true
)"
```

Then run repository metadata, workflow-policy, generated-artifact,
sanitization, and secret scans. Seal the exact base-to-head diff, obtain a
distinct-family xAI/Grok review over the matching digest, adjudicate every
finding, rerun affected gates, and commit only the reviewed bytes:

```text
feat: add crash-resumable QTS controller lifecycle
```

## Explicit Deferred Gates

Task 10 remains source-complete but not deployable until the operator
separately approves:

1. `/runner`, `/tmp`, and scratch tmpfs sizes;
2. runner/controller cgroup memory and swap limits;
3. maximum concurrency and build/smoke reserve;
4. every storage byte/inode reserve and bounded-log quantity;
5. watchdog and rebuild cadence;
6. the private target overlay and QTS paths/identity;
7. administrator build versus attested immutable pull/recovery method;
8. external hosted-hold/Worker permit/health/routing integration;
9. a secretless canary plan; and
10. any host, Docker, cron, systemd, routing, or deployment mutation.

The implementation must refuse zero, omitted, synthetic, or unapproved
production values. Synthetic test values prove rejection and arithmetic only;
they are never promoted into a private overlay or deployment recommendation.
