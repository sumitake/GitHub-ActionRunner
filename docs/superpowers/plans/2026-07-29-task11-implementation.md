# Task 11 Implementation Plan: Host, Namespace, Secret, and One-Job Conformance

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task by task and
> `superpowers:test-driven-development` for every behavior change.
>
> **Status:** source implementation plan only. This plan authorizes no RhoNAS,
> QTS, Docker, systemd, GitHub, routing, selector, release, service, or host
> configuration mutation. It selects no tmpfs, cgroup, swap, CPU, concurrency,
> conntrack, storage, retention, cadence, or reclamation threshold. Supplying
> the private conformance input and running the tagged suite on a target remain
> separate operator-signoff gates.

**Goal:** Add a fail-closed, Linux-targeted conformance harness that proves the
actual Portable GHAR host profile, network jail, runner sandbox, one-job
reclamation, seed isolation, controller recovery, and fleet-fence behavior,
then emits one canonical, secret-free, build-bound evidence report. Keep
synthetic lifecycle evidence, actual immutable-image evidence, and later
GitHub canary evidence separate so no source test or fake listener can be
misreported as target conformance.

**Architecture:** `internal/conformance` owns a closed, proof-layer-tagged case
registry, a small `HostProfile` execution interface, the canonical report
codec, and the full-pass acquisition gate. `tests/conformance` contains only
black-box contract tests. The report contains only immutable build bindings,
closed proof layers, status and failure classes, counts, bounded numeric
measurements, and domain-separated evidence digests. It contains no hostnames,
addresses, paths, container IDs, repository identities, commands, environment,
logs, secrets, or raw errors.

`tests/integration/testenv` is an opt-in target harness. On Linux, and only
after both `PGHAR_INTEGRATION_DOCKER=1` and an operator-created canonical
private input are present, it validates the exact target and immutable inputs,
creates one collision-resistant dedicated fixture, runs only closed Docker
and host observations, and positively removes every fixture effect. On Darwin
or any host without the explicit authorization, it reports exactly
`SKIP unsupported host profile`; it does not create a structural pass.
Malformed supplied authorization is a test failure, never a skip.

The target harness has three disjoint proof layers:

1. **Actual host and immutable runtime proof** inspects the qualified runner,
   adapter, broker, helper, verifier, seccomp, policy, CA, cgroup, namespace,
   Docker, and QTS observations named by the private input.
2. **Synthetic one-job proof** uses a deterministic test listener image to
   exercise the real held-runner gate, cleanup, crash, cancellation, restart,
   upgrade-interruption, and seed-isolation machinery without contacting
   GitHub or receiving a JIT token.
3. **Actual GitHub transport/canary proof** remains pending until a later
   operator-approved secretless canary supplies a real one-job JIT through the
   governed acquisition path. Synthetic completion can never satisfy this
   case, and an actual runner version inspection can never satisfy synthetic
   cleanup cases.

`conformance.Run` calls every required case in canonical order, always invokes
the fixture's one idempotent cleanup authority on a fresh context, and produces
a passing report only when every actual case and cleanup proof passes. A build
seal binds the report to the runtime manifest and source plan. It is a
domain-separated digest, not a cryptographic identity signature or deployment
attestation; later release provenance supplies those authorities.

`internal/controller` imports the lower-level `internal/conformance` package
and accepts a canary/enabled policy only through its
`conformance.AcquisitionConformance` port.
`internal/conformance.AcquisitionGate` implements that port from a fully
passing, currently matching report. `internal/conformance` imports neither
`internal/controller` nor `tests/integration/testenv`; `internal/hostruntime`
may import `internal/conformance` only to construct the existing opaque target
proof. The gate
revalidates the exact case registry, proof layers, cleanup, build seal, build,
profile, and fleet generation before every canary/enabled transition and
before each acquisition batch. Pending/source-only reports and stale bindings
can therefore never enable acquisition. The Task 10 disabled-observer
composition is a separate zero-capacity type with no active acquisition
service and remains dark.

**Tech stack:** Go 1.26.0/toolchain 1.26.5, strict canonical JSON, SHA-256
domain separation, Linux build tags, the existing closed `hostruntime.Engine`
and `networkjail.Orchestrator`, fixed-argv Docker/host probes, test-only
immutable images, table-driven tests, and the standard `testing` package.

## Implementation-discovered observation-source amendment

The source audit during Task 7 found that the original preflight wording
required the final `hostruntime.ProfileObservation.IsolationEvidence` digest
before cases 2-11 could create the resources that produce that evidence. It
also found no executable reference for the synthetic/tool images and placed
live scale-set `DisableUpdate` under a local closed command. The changed plan
was adversarially reviewed by xAI/Grok 4.5 and converged at `PROCEED` over
exact artifact SHA-256
`d235dfebdf6af1103a82c1d25bbbecdf0eda5b28d04d902155f0f1a1d33aaaf6`.

The implementation therefore has these two explicit phases:

1. `StaticPreflight` performs only canonical parse/hash/readback, immutable
   cross-document checks, a fixed execution-host identity observation, empty
   fixture-parent/root validation, and static platform/capability/cgroup/limit
   checks. It cannot construct `ProfileObservation`, set
   `IsolationEvidence`, compare final profile/network anchors, or mutate the
   host.
2. `DynamicConformance` registers cleanup, acquires the dedicated root,
   creates engine-issued resources, executes cases 1-14, and then calls
   `HostProfile.FinalizeTarget`. Finalization requires the exact completed-case
   bitset, constructs current isolation evidence only from those observations,
   and returns opaque observed profile/network digests. Case 15 may be pending
   or passed at this point. A pending or passing report is valid only when both
   observed digests are nonzero and match the separately named expected
   anchors.

Expected profile/network digests in `Binding` are comparison anchors, never
observed authority. The report carries expected and observed values
separately. `NewAcquisitionGate` rechecks equality.

The execution-host identity uses the compact canonical JSON encoding of this
fixed struct:

```go
type executionHostIdentityWire struct {
    SchemaVersion                 uint32 `json:"schema_version"`
    OperatingSystem               string `json:"operating_system"`
    Architecture                  string `json:"architecture"`
    EUID                          uint32 `json:"euid"`
    FixtureParentDevice           uint64 `json:"fixture_parent_device"`
    FixtureParentInode            uint64 `json:"fixture_parent_inode"`
    DockerBinaryDevice            uint64 `json:"docker_binary_device"`
    DockerBinaryInode             uint64 `json:"docker_binary_inode"`
    DockerServerObservationDigest string `json:"docker_server_observation_digest"`
}
```

Its exact preimage is
`"portable-ghar-execution-host-identity-v1\0" || canonical-json`.
Every field is independently observed through typed no-follow reads or the
fixed `ClosedDockerServerVersion` operation. No path or raw Docker output
enters the wire. The control-host digest is explicitly an
operator-authorization anchor: it must match the private overlay and differ
from the recomputed target digest, but is never described as locally observed.

Every `ImmutableImageBinding` and `WorkflowToolBinding` carries a complete
canonical lowercase `name@sha256:<digest>` reference plus its separate digest.
The suffix must match; tags, aliases, duplicates, production/synthetic/tool
substitution, and overlay/manifest disagreement fail.

Live `DisableUpdate=true` is exclusively case-15 evidence from the in-run
authenticated `githubscale` session `Compatibility()` result. It is not
accepted from input, file, compiled configuration, local command, prior
session, or detached proof. Case 6 proves only immutable image payload,
version, staging, updater-wrapper, sweeper, and baked-JIT properties.

Closed observations use three non-interchangeable session types:
`preflightSession`, engine-handle-bound `networkSession`, and
engine-handle-bound `runnerSession`. Each operation has one matrix-owned
parser/byte cap and fixed argv. No session accepts a caller container ID,
path, image, argv, or environment, and cross-phase operations fail closed.

The later
`docs/superpowers/plans/2026-07-29-task11-observation-source-amendment.md`
(v3, 42,991 UTF-8 bytes, SHA-256
`a6ffa14a721cb19a6e2810193db98a66471e22a4e0aafac65d2107a38df7098a`)
is also binding. It supersedes any broader row-source assignment in this
implementation plan and requires complete fixture-Docker swap authority,
same-run dual-class permit usage, and successful production `Prepare` through
`StageRunnerAuthorize` before evidence transfer.

## Implementation-discovered one-shot authorization amendment

The Linux-entrypoint audit found that the parser's injected
`AuthorizationUsage` query had no durable target authority. An in-process set
does not survive another invocation, an in-fixture marker disappears during
mandatory cleanup, and a persistent marker directory would add the unbounded
NAS state or sizing/retention decision this task forbids. The revised design
was adversarially reviewed by xAI/Grok 4.5 over exact artifact SHA-256
`bd0cc8979fead15d8f42809465b3dbf980d27dce550281a79f13811c2ae2cca8`.
Grok returned `REVISE`: it accepted the private-input-as-one-shot-capability
architecture, subject to the following state and failure seals.

The Linux integration entrypoint exclusively acquires a retained
`ConformanceInputLease`; the ordinary read-only parser remains a test/helper
surface and is never an execution authority. The lease opens the input through
an `O_NOFOLLOW` parent descriptor and basename, obtains a nonblocking
exclusive `flock` before reading, validates the complete file and input, and
retains the descriptor, raw bytes, digest, and immutable identity through the
run. Its closed states are:

1. `held`: locked, parsed, path still present;
2. `consumed`: the exact directory entry was successfully unlinked, whether
   or not the following durability/absence proof succeeds; and
3. `closed`: descriptors closed and retained raw bytes zeroed.

Static preflight runs while the lease is `held` and changes nothing. At the
first-effect boundary it repeats descriptor/path identity and authorization
window validation, unlinks the exact basename relative to the retained parent
descriptor, immediately transitions to `consumed`, fsyncs the parent, and
proves the basename absent. Only full consume proof permits `Root.Acquire` or
any Docker, fixture, journal, network, process, or controller effect.

Pre-unlink validation, expiry, identity, or lock failure leaves the input
intact and is a reusable pre-effect failure. Failure after successful unlink
is the distinct closed `authorization_consumed_run_aborted` class: no run
effect starts, the old capability is spent, and the operator must create a new
input. A second `Consume` never calls unlink. If a new inode appears at the
basename after the authorized unlink, absence proof fails, the new inode is
left untouched, and no cleanup path may delete it.

This prevents reuse of the same lease-bound path/inode capability. It does not
claim cryptographic `RunID` uniqueness after an operator deliberately creates
a new byte-identical input; that stronger property requires a separately
approved durable ledger. Correctness requires a local POSIX filesystem model
where `flock`, `unlinkat`, and parent `fsync` provide the stated exclusion and
name-removal semantics. No marker, history table, retention value, or
persistent runner job state is added. The report retains only the digest
captured at parse time, never the consumed path or raw bytes.

The amended full plan was then re-sealed at 80,900 UTF-8 bytes, SHA-256
`164fdc913e9b05b6ad7a138b4c18883030b43ac371fdb2cba7833d43480b2a37`,
and received a confirm-only xAI/Grok 4.5 `PROCEED`. The confirmation found no
remaining material race, crash, authority, persistence, cleanup, or
first-effect design gap and bound implementation to the exact state, ordering,
replacement-preservation, digest-lifetime, and non-promotion tests below.

## Implementation-discovered single-run topology amendment

The tagged-test audit found that the three originally listed effect-capable
test functions each created a fresh fixture but invoked only one slice of the
canonical case registry. That is incompatible with both the retained one-shot
authorization and `Fixture.beginCase`, which correctly rejects a later case
unless every preceding case in the same run has passed. Relaxing either guard
would permit case substitution and split one report across unrelated target
lifetimes.

The Linux effect-capable entrypoint is therefore exactly one
`TestPortableGHARConformance` invocation:

1. `StartDockerFixture` acquires one retained private-input lease, completes
   static preflight, registers cleanup, consumes the capability, locks the
   exact empty fixture root, and constructs one target profile.
2. The test calls `conformance.Run` exactly once. The registry, not test-file
   order, invokes cases 1-15 in canonical order, finalizes target evidence only
   after cases 1-14, and invokes the one cached cleanup authority.
3. The tagged test accepts exactly two canonical terminal shapes:
   - **source/pending:** top-level pending; cases 1-14 passed with no failure;
     case 15 pending with `actual_proof_pending` under the actual-GitHub proof
     layer; cleanup passed; observed profile/network digests nonzero and equal
     to their expected anchors; and no other pending, failed, or not-run case;
   - **operator canary/pass:** top-level passed with no failure; all 15 cases
     passed under their registry-owned layers; cleanup passed; the same
     observed/expected digest equality; and case 15 produced only by the
     separately approved authenticated actual-GitHub canary authority.
   Every other shape fails. In particular, synthetic evidence cannot mint the
   case-15 result or an all-pass report.
4. The report is marshaled and parsed back through the canonical codec before
   the test returns. No report path, environment-selected output, or durable
   target evidence is added.
5. A source-level AST topology test mechanically requires exactly one tagged
   effect entrypoint named `TestPortableGHARConformance`, exactly one reference
   to `StartDockerFixture`, and exactly one `conformance.Run` call across the
   package. The case-group files may provide non-effectful helper assertions,
   but they do not define separately runnable target tests, acquire additional
   private inputs, or call `Run`. Adversarial case-level behavior remains
   covered by untagged injected tests in `testenv`.
6. On Darwin or without opt-in, this one entrypoint reports the exact
   unsupported-host skip. A skip remains no target evidence.

The same profile rejects a second `conformance.Run`: its case state is already
complete and cleanup returns only its cached result. `go test -count=N` cannot
reuse the consumed input path/inode capability. Case 8's matrix rows are
multiple in-run synthetic job/runner cycles under this one authorized profile
and root; they cannot call `StartDockerFixture`, consume another lease, or
start another `Run`.

This amendment changes only test orchestration. It does not weaken canonical
case ordering, authorize input reuse, select target values, create a second
cleanup path, or authorize target execution.

## Non-Negotiable Boundaries

1. No committed target hostname, account, repository, route, address, device,
   container name, filesystem path, UID/GID, schedule, runner token, JIT,
   credential reference, or resource/sizing value.
2. No Docker build, pull, load, import, tag, push, or image deletion in the
   harness. Every image must already be immutable, qualified, and supplied by
   exact digest in the private input.
3. No arbitrary argv, shell, command fragment, environment map, bind, device,
   volume, network, capability, or Docker option in the private input.
4. No direct runner internet route. Positive public HTTPS must traverse the
   broker and an operator-controlled public sentinel whose host, port,
   certificate/SPKI binding, and policy evidence are supplied privately.
5. Documentation/test-net addresses are negative sentinels only. They are
   never treated as reachable positive endpoints.
6. No local DNS container may stand in for pinned public DoH. DNS-resolved
   deny cases use operator-controlled names whose expected denied address
   classes and evidence are privately bound.
7. No source-only, mocked, Darwin, or unsupported-host result may be promoted
   to `passed` target conformance.
8. No synthetic listener result may satisfy actual runner-version,
   `DisableUpdate`, GitHub listener transport, checkout, or workflow-tool
   compatibility. Live `DisableUpdate` is case-15 authenticated-session
   evidence only.
9. No actual immutable-image inspection may satisfy one-job completion,
   crash, cancellation, controller-restart, upgrade-interruption, or seed
   isolation.
10. No report embeds raw observation bytes or computes authority from a bare
    file hash. Every evidence digest has a distinct domain.
11. No cleanup calls `context.Background()` without a private hard deadline.
    Cancellation of the case context cannot cancel mandatory cleanup.
12. No fixture cleanup discovers by prefix, label scan, or JSON revalidation.
    It removes only engine-issued opaque handles and exact identities recorded
    before effects.
13. No failed cleanup is downgraded to a case failure. Cleanup failure makes
    the complete report fail with the closed `cleanup_failed` class.
14. No report claims target conformance while the actual GitHub transport
    case is pending. Source implementation may be committed as a source-only
    checkpoint, but Task 11's operational gate remains open.
15. No target execution occurs until the operator separately signs off the
    private conformance input, its numeric values, the dedicated fixture root,
    the immutable images, and the execution window.
16. Every case has one registry-owned proof layer. A caller cannot choose,
    convert, or override it, and no generic passed-evidence constructor accepts
    a free `CaseID`.
17. Every input digest is an expected binding only. Static artifacts are
    recomputed before mutation. Final profile/network digests are recomputed
    only after their exact dynamic cases complete, remain distinct from their
    expected anchors in the report, and must match before a pending/passing
    report or acquisition gate is valid.
18. One idempotent fixture cleanup state machine is the sole destructive
    cleanup authority. `conformance.Run` invokes it normally; the pre-registered
    `t.Cleanup` safety net invokes that same object only if `Run` never did and
    otherwise returns the cached result without another effect.
19. No canary/enabled transition or acquisition batch proceeds unless the
    production `AcquisitionConformance` port verifies a fully passing report
    against the current build, profile, and fleet generation.
20. `CaseEvidence`, `CleanupEvidence`, and `Report` have package-private state.
    Other packages receive getters and canonical bytes only; they cannot use a
    composite literal to mint a passed case or report.
21. The package graph is one-way: controller and hostruntime may import
    conformance; conformance imports neither. Testenv may import conformance,
    hostruntime, and networkjail; production packages never import testenv.
22. Task 11 adds no production report path, environment variable, auto-loader,
    or refresh authority. A later operator-governed lifecycle task must load
    and install the exact private report before any active service composition
    can receive a passing gate.

## Threat Model and Failure Classes

The harness and report must fail closed against:

1. unknown, missing, duplicated, reordered, trailing, whitespace-variant,
   oversized, non-UTF-8, or noncanonical private-input/report JSON;
2. wrong OS, architecture, EUID, host identity, control-host identity,
   profile, runtime-manifest digest, private-overlay digest, plan digest,
   source commit, build ID, fleet generation, or immutable image digest;
3. running on the development/control Mac or confusing it with the target;
4. absent opt-in, stale authorization, expired execution window, reuse of the
   same lease-bound authorization capability, or an input file with wrong
   type, owner, mode, link count, or identity;
5. a nonempty or preexisting fixture root, a replaced parent, symlink,
   hardlink, mount crossing, or cleanup outside the exact fixture root;
6. mutable image tags, multiple runner payloads, stale/current version
   ambiguity, an updater staging directory, or listener smoke mismatch;
7. arbitrary command, bind, environment, capability, port, protocol, or
   network injection through test configuration;
8. a runner namespace with a direct route, non-loopback interface, registered
   iptables/nftables state, host conntrack rows, or changed identity after
   broker attachment;
9. a positive probe that bypasses the broker, accepts plaintext, skips pinned
   TLS validation, resolves after policy validation, or reaches a denied
   address/port/protocol;
10. a negative probe whose transport failed for the wrong reason and is
    nevertheless counted as policy denial;
11. missing helper lifetime proof, excess helper capability, any capability
    on adapter/broker/verifier/runner, or a mount visible to the wrong
    container;
12. controller SQLite, Docker socket, device, host control secret, JIT,
    credential, authority socket, relay socket, or runner environment leaking
    into another component or report;
13. incomplete policy, budget, permit-ledger, CA, TLS, namespace, parser,
    process-inventory, or conntrack evidence;
14. parser/fallback/crash floods exceeding the operator-approved checked
    conntrack formula, FD ceiling, process ceiling, or log ceiling;
15. component, policy, journal, authority, peer, state, or evidence loss that
    still releases a runner;
16. read-only root, cgroup, tmpfs, seccomp, masked procfs, namespace/raw/BPF,
    non-root/capless-root, PID, FD, CPU, memory, swap, or scratch proof that
    relies only on requested Docker configuration instead of readback;
17. a JIT value surviving listener parsing or appearing in a job environment,
    export, diagnostic, log, test error, report, or cleanup artifact;
18. cleanup that observes a stop request instead of absence of the runner,
    cgroup, tmpfs mounts, work/update directories, descendants, namespaces,
    sockets, and temporary files;
19. an old/new runner pair or `_work/_update` surviving any job or
    forced-upgrade interruption;
20. repeated-job measurements exceeding approved baseline/margin, exceeding
    approved slope, or showing an all-sample monotonic increase;
21. a reusable host-backed workspace, persistent NAS job data, or seed
    mutation visible in the next runner;
22. watchdog recovery that routes, polls, acquires, creates JIT, releases a
    listener, restores/decrements a fence, or starts before the old process is
    proven dead;
23. legacy observer recovery that preserves enabled/canary capacity instead
    of first writing a newer disabled/empty/zero epoch;
24. a route-writer trap call, dual fleet ownership, stale fence header,
    mismatched holder record, or reboot recovery that enables portable while
    legacy owns the fence;
25. a non-cancellable fake poll whose old process survives observer restart;
26. skipped, duplicated, missing, reordered, unknown, or synthetically
    substituted conformance cases;
27. raw errors, command output, paths, addresses, identifiers, secrets, or
    unbounded strings escaping into test output or the canonical report;
28. a cleanup error being hidden by a primary case error, or a report being
    sealed before cleanup succeeds; and
29. treating the build seal as a signer identity, code-signing proof,
    attestation, approval, deployment authorization, or live-host freshness;
30. a synthetic observation being digested under an actual-host or
    actual-GitHub case domain, or any cross-layer passed-evidence constructor;
31. trusting an expected input digest without recomputing the observed object;
32. two independent cleanup mechanisms racing or hiding each other's failure;
33. a stale/pending/partial report enabling canary, enabled, poll, acquire, or
    listener release;
34. PID reuse causing watchdog restart before the prior PID plus starttime
    identity is absent;
35. too few reclamation samples, checked-arithmetic overflow, or an undefined
    noisy measurement being treated as pass; and
36. CI presenting an unsupported/source-only skip as target conformance.

## Canonical Conformance Contract

Create `internal/conformance/report.go` with these public types and exercise it
from `tests/conformance/host_profile_test.go`:

```go
package conformance

type CaseID string
type ProofLayer string
type CaseStatus string
type FailureClass string

const (
    LayerActualHostImmutable  ProofLayer = "actual-host-immutable"
    LayerSyntheticLifecycle   ProofLayer = "synthetic-lifecycle"
    LayerActualGitHubTransport ProofLayer = "actual-github-transport"
)

const (
    CaseHostProfile             CaseID = "host-profile"
    CaseNamespaceBaseline       CaseID = "namespace-baseline"
    CaseBrokerEgress            CaseID = "broker-egress"
    CaseMountAndSecretIsolation CaseID = "mount-and-secret-isolation"
    CaseSandbox                 CaseID = "runner-sandbox"
    CaseRunnerPayload           CaseID = "runner-payload"
    CaseSyntheticOneJob         CaseID = "synthetic-one-job"
    CaseCleanupMatrix           CaseID = "cleanup-matrix"
    CaseReclamationSeries       CaseID = "reclamation-series"
    CaseProxyToolCompatibility  CaseID = "proxy-tool-compatibility"
    CaseSeedIsolation           CaseID = "seed-isolation"
    CaseWatchdogRecovery        CaseID = "watchdog-recovery"
    CaseLegacyFenceRecovery     CaseID = "legacy-fence-recovery"
    CaseNoncancellableShutdown  CaseID = "noncancellable-shutdown"
    CaseActualGitHubTransport   CaseID = "actual-github-transport"
)

const (
    StatusPassed  CaseStatus = "passed"
    StatusFailed  CaseStatus = "failed"
    StatusPending CaseStatus = "pending"
    StatusNotRun  CaseStatus = "not-run"
)

const (
    FailureNone                 FailureClass = "none"
    FailureInput                FailureClass = "input_invalid"
    FailureUnsupported          FailureClass = "unsupported_profile"
    FailureDeadline             FailureClass = "deadline_expired"
    FailureObservation          FailureClass = "observation_failed"
    FailureInvariant            FailureClass = "invariant_failed"
    FailurePolicy               FailureClass = "policy_failed"
    FailureArithmetic           FailureClass = "arithmetic_failed"
    FailureCleanup              FailureClass = "cleanup_failed"
    FailureActualProofPending   FailureClass = "actual_proof_pending"
    FailurePrerequisite         FailureClass = "prerequisite_failed"
)

type Binding struct { /* package-private canonical state */ }
type Measurement struct { /* package-private canonical state */ }
type CaseEvidence struct { /* package-private canonical state */ }
type CleanupEvidence struct { /* package-private canonical state */ }
type Report struct { /* package-private canonical state */ }

type ActualHostCaseID uint8
type SyntheticCaseID uint8
type ActualHostResult struct { /* package-private sealed state */ }
type SyntheticResult struct { /* package-private sealed state */ }
type ActualGitHubResult struct { /* package-private sealed state */ }
type TargetObservation struct { /* package-private sealed state */ }

type HostProfile interface {
    Binding() (Binding, error)
    RunActualHost(context.Context, ActualHostCaseID) (ActualHostResult, error)
    RunSynthetic(context.Context, SyntheticCaseID) (SyntheticResult, error)
    RunActualGitHub(context.Context) (ActualGitHubResult, error)
    FinalizeTarget(context.Context) (TargetObservation, error)
    Cleanup(context.Context) (CleanupEvidence, error)
    ActualHostTimeout(ActualHostCaseID) time.Duration
    SyntheticTimeout(SyntheticCaseID) time.Duration
    ActualGitHubTimeout() time.Duration
    CleanupTimeout() time.Duration
}

func Run(context.Context, HostProfile) Report
func MarshalReport(Report) ([]byte, error)
func ParseReport([]byte, int) (Report, error)
func RequiredCases() []CaseID
func RequiredLayer(CaseID) (ProofLayer, bool)
func NewBinding(BindingInput) (Binding, error)
func SealHostProfile(HostProfileObservation) (ActualHostResult, error)
func SealNamespaceBaseline(NamespaceObservation) (ActualHostResult, error)
func SealBrokerEgress(BrokerEgressObservation) (ActualHostResult, error)
func SealMountAndSecretIsolation(MountSecretObservation) (ActualHostResult, error)
func SealRunnerSandbox(RunnerSandboxObservation) (ActualHostResult, error)
func SealRunnerPayload(RunnerPayloadObservation) (ActualHostResult, error)
func SealProxyToolCompatibility(ProxyToolObservation) (ActualHostResult, error)
func SealSyntheticOneJob(SyntheticJobObservation) (SyntheticResult, error)
func SealCleanupMatrix(CleanupMatrixObservation) (SyntheticResult, error)
func SealReclamationSeries(ReclamationObservation) (SyntheticResult, error)
func SealSeedIsolation(SeedObservation) (SyntheticResult, error)
func SealWatchdogRecovery(WatchdogObservation) (SyntheticResult, error)
func SealLegacyFenceRecovery(LegacyFenceObservation) (SyntheticResult, error)
func SealNoncancellableShutdown(ShutdownObservation) (SyntheticResult, error)
func SealCleanup(CleanupObservation) (CleanupEvidence, error)
func SealTargetObservation(TargetObservationInput) (TargetObservation, error)
func PendingActualGitHubTransport() ActualGitHubResult
func SealActualGitHubTransport(ActualGitHubObservation) (ActualGitHubResult, error)
```

The unexported V1 wire types have this exact field order:

```go
type bindingWire struct {
    SchemaVersion          uint32 `json:"schema_version"`
    BuildID                string `json:"build_id"`
    SourceCommit           string `json:"source_commit"`
    RuntimeManifestDigest  string `json:"runtime_manifest_digest"`
    PrivateOverlayDigest   string `json:"private_overlay_digest"`
    ConformanceInputDigest string `json:"conformance_input_digest"`
    AuthorizationDigest    string `json:"authorization_digest"`
    RunID                  string `json:"run_id"`
    ProfileID              string `json:"profile_id"`
    FleetGeneration        uint64 `json:"fleet_generation"`
    ExpectedProfileEvidenceDigest string `json:"expected_profile_evidence_digest"`
    ExpectedNetworkEvidenceDigest string `json:"expected_network_evidence_digest"`
    PlanDigest                    string `json:"plan_digest"`
    BindingDigest                 string `json:"binding_digest"`
}

type measurementWire struct {
    Name  string `json:"name"`
    Value uint64 `json:"value"`
    Unit  string `json:"unit"`
}

type caseEvidenceWire struct {
    ID                CaseID            `json:"id"`
    Layer             ProofLayer        `json:"layer"`
    Status            CaseStatus        `json:"status"`
    Failure           FailureClass      `json:"failure"`
    AssertionCount    uint64            `json:"assertion_count"`
    Measurements      []measurementWire `json:"measurements"`
    ObservationDigest string            `json:"observation_digest"`
    EvidenceDigest    string            `json:"evidence_digest"`
}

type cleanupEvidenceWire struct {
    Status            CaseStatus   `json:"status"`
    Failure           FailureClass `json:"failure"`
    AssertionCount    uint64       `json:"assertion_count"`
    ObservationDigest string       `json:"observation_digest"`
    EvidenceDigest    string       `json:"evidence_digest"`
}

type reportWire struct {
    SchemaVersion                 uint32              `json:"schema_version"`
    Binding                       bindingWire         `json:"binding"`
    ObservedProfileEvidenceDigest string              `json:"observed_profile_evidence_digest"`
    ObservedNetworkEvidenceDigest string              `json:"observed_network_evidence_digest"`
    Cases                         []caseEvidenceWire  `json:"cases"`
    Cleanup                       cleanupEvidenceWire `json:"cleanup"`
    Status                        CaseStatus          `json:"status"`
    Failure                       FailureClass        `json:"failure"`
    ReportDigest                  string              `json:"report_digest"`
    BuildSeal                     string              `json:"build_seal"`
}
```

The observation input types are case-specific closed structs. Their fields are
the minimum typed counts/measurements plus one recomputed private observation
digest; none contains a free `CaseID`, `ProofLayer`, status, failure, command,
path, or raw observation. Every evidence/report/binding field is unexported.
Read-only getters return scalars or defensive copies. Custom marshal/parse uses
unexported V1 wire structs, so another package cannot mint a passing composite
literal. There is no generic result constructor, generic command, or raw-
observation escape hatch. `TargetObservationInput` contains only the two
independently recomputed final target digests. `TargetObservation` is opaque,
and the target fixture may seal it only after its finalizer has verified the
exact completed-case bitset.

### Exact registry and status rules

`RequiredCases` returns a fresh copy of the exact order shown above. The list
is not caller-configurable. `RequiredLayer` returns the registry-owned layer:

- cases 1-6 and `CaseProxyToolCompatibility` are
  `LayerActualHostImmutable`;
- `CaseSyntheticOneJob`, `CaseCleanupMatrix`, `CaseReclamationSeries`,
  `CaseSeedIsolation`, and cases 12-14 are `LayerSyntheticLifecycle`; and
- case 15 is `LayerActualGitHubTransport`.

A case:

- is `passed` only with `FailureNone`, a positive assertion count, a valid
  domain-separated evidence digest, its exact registry-owned proof layer,
  canonical sorted measurements, and no raw error;
- is `pending` only for `CaseActualGitHubTransport` with
  `FailureActualProofPending`;
- is `not-run` only after an earlier canonical case failed, with
  `FailurePrerequisite`, zero assertions, no measurements, and its exact
  domain-separated not-run evidence digest;
- is otherwise `failed` with one non-`none` closed failure class;
- cannot be omitted, duplicated, reordered, or substituted; and
- cannot claim a skipped/unsupported profile inside a target report.

Only the named case-specific sealers may create passing evidence. Their
returned state is opaque. There is no constructor that accepts a
caller-selected `CaseID`/layer/status plus arbitrary observation bytes. Each
observation type is accepted only by its exact sealer, so synthetic bytes
cannot compile as actual-host or actual-GitHub evidence.

A complete target report is `passed` only if every required case, including
`CaseActualGitHubTransport`, and cleanup are `passed`. A source checkpoint may
produce a valid `pending` report for the actual GitHub case, but its top-level
status is `pending`, never `passed`.

After cases 1-14 pass and case 15 is either canonical pending or passed,
`Run` invokes `FinalizeTarget` with a context bounded by the case-1 timeout.
It never finalizes after a failed/not-run case. The opaque observation must
contain valid nonzero final profile/network digests and both must match the
separately named expected binding anchors. A finalization error, malformed
observation, or mismatch makes the report top-level `failed` with
`FailureInvariant`; it cannot be converted into case evidence.

The first non-passing case in registry order determines the top-level failure,
then target-finalization failure, except any cleanup failure has precedence
and forces `FailureCleanup`.
`Run` stops launching later effects after the first failed case, records
canonical `not-run` evidence for the unexecuted suffix, and still calls
cleanup once.

### Canonical encoding and evidence domains

The V1 report codec is frozen:

- Go declaration order above;
- UTF-8 only;
- no insignificant whitespace or trailing LF;
- decimal integers;
- no maps, floats, timestamps, nullable fields, or arbitrary strings;
- exact lowercase 64-hex raw digests;
- closed measurement names and units per case;
- measurement names strictly increasing;
- exact remarshal equality; and
- `ParseReport` uses a byte limit, `DisallowUnknownFields`, one JSON value, and
  full validation.

Each case digest is:

```text
SHA256(
  "portable-ghar-conformance-case-v1\0" ||
  LP(case_id) ||
  LP(proof_layer) ||
  LP(case_status) ||
  LP(failure_class) ||
  U64(assertion_count) ||
  U32(measurement_count) ||
  each(LP(name) || U64(value) || LP(unit)) ||
  Digest32(binding_digest) ||
  Digest32(private_case_observation_digest)
)
```

The private observation digest is produced inside the target harness from a
case-specific canonical typed observation. The lowercase domain-separated
digest enters the report so `ParseReport` and the acquisition gate can
recompute `EvidenceDigest`; raw observations are destroyed after digesting and
never enter `Report`.

Cleanup evidence uses
`"portable-ghar-conformance-cleanup-v1\0"`. `ReportDigest` uses
`"portable-ghar-conformance-report-v1\0"` over the canonical report with both
digest fields set to 64 zeroes. `BindingDigest` uses
`"portable-ghar-conformance-binding-v1\0"` over the canonical binding with
`BindingDigest` set to 64 zeroes. `BuildSeal` uses
`"portable-ghar-conformance-build-seal-v1\0" || Digest32(BuildID) ||
Digest32(BindingDigest) || Digest32(ReportDigest)`. Every field named
`*Digest`, `RunID`, or `BuildID` above is an exact lowercase 64-hex digest.
The expected and observed profile/network digests are all committed through
`ReportDigest`; only the expected anchors are committed through
`BindingDigest`. `ProfileID` is exactly one existing closed host profile
(`strict-linux` or `qts-capless-root`). `SourceCommit` is the repository's
exact lowercase 40-hex Git object ID and is committed through
`BindingDigest`; no prose build name is accepted.

`BuildSeal` proves only byte binding. Documentation and tests must reject the
terms signed, signature, signer, attested, approved, authorized, deployed, or
fresh as semantics for it.

## Production Acquisition Consumer

Create:

- `internal/controller/conformance.go`
- `internal/controller/conformance_test.go`
- `internal/conformance/gate.go`
- `internal/conformance/gate_test.go`

Add this closed neutral port in `internal/conformance`:

```go
type AcquisitionMode string

const (
    AcquisitionCanaryOnly AcquisitionMode = "canary-only"
    AcquisitionEnabled    AcquisitionMode = "enabled"
)

type AcquisitionConformanceRequest struct {
    BuildID         string
    HostProfileID   string
    FleetGeneration uint64
    Mode            AcquisitionMode
}

type AcquisitionConformance interface {
    Verify(context.Context, AcquisitionConformanceRequest) error
}
```

`internal/conformance` imports only the standard library.
`internal/controller` imports `internal/conformance`, explicitly converts its
own acquisition mode through one closed switch, and gives `ServiceConfig` a
required non-nil `conformance.AcquisitionConformance` plus exact nonzero
`FleetGeneration`. The service calls `Verify`:

1. before any transition from disabled to canary-only or enabled;
2. before opening a canary/enabled epoch after restart;
3. before every canary/enabled acquisition batch; and
4. again before a prepared listener can consume JIT/release authority.

Failure before a transition leaves acquisition disabled. Failure while an
enabled/canary epoch exists enters the existing cleanup-first fatal/zero path,
revokes pre-running work, and publishes no new listener. Disabled/fatal
operation does not require a passing report.

`conformance.NewAcquisitionGate(report)` accepts only an exact canonical report
whose:

- top-level status is `passed` and failure is `none`;
- case IDs, layers, statuses, failures, measurements, and evidence digests
  exactly match `RequiredCases`;
- cleanup is passed;
- binding/report/build-seal digests recompute;
- build/profile/generation are complete; and
- actual GitHub transport is passed under its exact layer.

`Verify` repeats immutable report validation and matches the request's build,
profile, and fleet generation. It accepts only canary-only or enabled modes.
There is no source-only, pending, warning, bypass, force, or development
constructor. Test or future source compositions that need a dark active
service inject `conformance.NewUnavailableAcquisitionGate()`, whose `Verify`
always returns the closed unavailable error. The existing Task 10
disabled-observer type does not construct the active service at all.

Extend `internal/hostruntime/evidence.go` so
`NewTargetConformanceFromReport(report)` can create the existing opaque
`TargetConformance` only from the same fully passing report. This retains
`NewDeploymentEligibility`'s existing requirement for matching source and
target bindings; no report file presence or bare digest can create
eligibility.

Task 11 deliberately adds no production report loader. Neither controller nor
hostruntime accepts a report path or environment variable. A later
operator-governed lifecycle task must read the mode-restricted private report,
recompute its current binding, construct the gate, and inject it into the
active service composition. A fleet-generation change invalidates the old
gate and requires a newly approved matching report; there is no ambient
refresh or inherited authorization.

## Canonical Private Conformance Input

Create `tests/integration/testenv/config.go` and
`tests/integration/testenv/config_test.go`. The private input is a strict
canonical V1 JSON document with no defaults:

```go
type ConformanceInput struct {
    SchemaVersion         uint32                 `json:"schema_version"`
    Authorization         Authorization          `json:"authorization"`
    Target                TargetBinding          `json:"target"`
    Runtime               RuntimeBinding         `json:"runtime"`
    Images                ImageBindings          `json:"images"`
    Sentinels             SentinelBindings       `json:"sentinels"`
    WorkflowTools         []WorkflowToolBinding  `json:"workflow_tools"`
    Limits                ConformanceLimits      `json:"limits"`
    Baselines             ReclamationBaselines   `json:"baselines"`
    Fixture               FixtureBinding         `json:"fixture"`
}
```

The nested declarations are fixed structs or ordered slices, never maps.
They contain:

- an exact authorization schema, operator-authorization digest, unique run
  digest, UTC not-before/not-after window, and explicit
  `target_conformance` action;
- Linux/architecture/EUID/profile/host/control-host identity digests and an
  exact assertion that target and control identities differ;
- source commit, build ID, runtime-manifest path/digest, private-overlay
  path/digest, policy path/digest, CA path/digest, seccomp path/digest,
  conformance-plan digest, separately named expected profile/network evidence
  digests, and fleet generation;
- complete immutable lowercase `name@sha256:<digest>` references plus separate
  matching digests for actual runner, adapter, broker, helper, verifier, and
  synthetic listener images;
- one positive public HTTPS sentinel with exact host identity digest, port,
  SPKI/certificate digest, policy-entry digest, and expected response-body
  digest;
- ordered literal-deny and DNS-deny sentinel entries with only closed address
  classes and evidence digests;
- a closed ordered list of current workflow-tool probe IDs, immutable
  lowercase image references, and matching probe-image digests, never argv;
- per-case timeouts, cleanup timeout, observation cadence, reclamation sample
  count, maximum evidence bytes, and every bounded resource/conntrack/log
  quantity, all explicit and nonzero. Linux composition additionally requires
  exact nonzero command-input bytes, dial reservation block size, dial
  authority maximum clients and timeout milliseconds, and per-container
  Docker log bytes/files; none has a source default;
- per-resource cleanup baseline, margin, and maximum signed slope numerator
  and denominator using checked integer arithmetic; and
- one absolute dedicated fixture root, parent device/inode binding,
  required-empty digest, and exact execution-owner identity.

Paths remain private and are permitted only for closed reads or the exact
dedicated fixture root. The parser rejects arbitrary extra roots. It rejects
inline secret-shaped names/values, URL userinfo/query/fragment, environment,
commands, tags without digests, duplicate tools/sentinels, private positive
sentinels, public endpoints absent from the policy evidence, and any numeric
zero/default.

Sentinel bindings expire with the authorization window. A certificate, SPKI,
body, DNS answer-class, or policy-entry mismatch fails the run; the harness
does not update pins, follow redirects, weaken TLS, or retry against a
different endpoint. The operator may issue a new reviewed input for a later
window.

`ReadConformanceInput` is the read-only test/helper parser. It opens no-follow,
requires one regular file, exact owner/mode/link count, snapshots
device/inode/size, reads within the explicit maximum, rechecks identity,
validates the time window using an injected clock, and returns the canonical
document plus its domain-separated digest. Tests cover replacement
before/after read, wrong mode/owner/type/link count, oversize, noncanonical
JSON, expired/future authorization, injected reused authorization, and every
cross-binding mismatch.

The Linux entrypoint instead uses `ConformanceInputLease`, which shares these
parse/identity rules but retains the locked descriptors and owns the exact
one-shot consume state machine above. Lock contention is a closed
`authorization_in_use` failure. A successful consume removes only the
operator-supplied input directory entry; it creates no used-run marker.

Every digest in the document is an expected value, never observation
authority. Before the first effect, the harness independently recomputes and
matches:

- the canonical input and authorization digests;
- source plan and current Git commit;
- runtime manifest and private overlay through their production parsers;
- policy, CA, seccomp, and immutable image identities through closed readback;
- the fixed execution-host identity preimage; and
- target/control-host separation.

Preflight does not construct `hostruntime.ProfileObservation`, set
`IsolationEvidence`, or compare final profile/network evidence. Those two
observed values are recomputed after cases 1-14 by `FinalizeTarget`. The report
binds expected and observed values separately. Echoing an input field into an
observed report field is invalid even when the field is well formed.

## Target Harness

Create:

- `tests/integration/testenv/profile.go`
- `tests/integration/testenv/capability_matrix.go`
- `tests/integration/testenv/capability_matrix_test.go`
- `tests/integration/testenv/fixture.go`
- `tests/integration/testenv/fixture_linux.go`
- `tests/integration/testenv/fixture_unsupported.go`
- `tests/integration/testenv/observations.go`
- `tests/integration/testenv/reclamation.go`
- `tests/integration/testenv/closed_command.go`
- `tests/integration/testenv/closed_command_test.go`

### Closed QTS observation-capability matrix

Before implementing any case, define one compiled registry that maps every
required observation for cases 1-15 to exactly one existing closed authority:

- `hostruntime.Profile`;
- `hostruntime.Engine`;
- `networkjail.Orchestrator`;
- a named read-only closed test command; or
- `actual-github-canary` pending.

Each row declares proof layer, source, closed operation ID, maximum bytes,
parser, and the case that consumes it. Validation rejects duplicate/missing
observations, a synthetic source for an actual case, a generic command, or an
actual case routed to `pending`. Unit tests enumerate cgroup v1/v2, Docker/QTS
capability and user readback, seccomp, mounts, namespace links/routes/tables,
host and namespace conntrack, processes/starttime, image payload/version,
work/update absence, proxy/TLS/DNS denial, seed, and cleanup. The sole
`DisableUpdate` row is
`actual-github-disable-update / CaseActualGitHubTransport /
LayerActualGitHubTransport / SourceActualGitHubCanary /
actual-disable-update / actual-github-v1`.
Synthetic one-job/cleanup/reclamation/watchdog/fence rows name test-local
sources only. Case 15 names only `actual-github-canary`.

If a required observation is not available through this matrix, implementation
stops at the plan gate. It may add one narrowly typed test-only probe after a
revised Grok cross-check; it may not widen production command authority during
TDD.

### Opt-in and unsupported-host behavior

`StartDockerFixture(t *testing.T) *Fixture` is the only integration entrypoint.

On non-Linux:

```go
t.Skip("SKIP unsupported host profile")
```

On Linux with `PGHAR_INTEGRATION_DOCKER` absent or not exactly `1`, or with
`PGHAR_CONFORMANCE_INPUT` absent, it uses the same explicit skip. If either
variable is present but malformed, or both are present and any input/host
proof fails, the test fails with one closed error class. It does not skip.

The harness:

1. validates directive, OS, architecture, EUID, the fixed execution-host
   identity preimage, target/control identity separation, input freshness,
   source/build/manifest/overlay/plan bindings, exact immutable image
   references, and static platform/capability/cgroup/limit facts before its
   first effect;
2. consumes the retained one-shot input capability with exact identity,
   current-window, parent-fsync, and path-absence proof;
3. opens and locks the preapproved empty fixture root without following links,
   proves parent/root identity and emptiness, acquires a nonblocking
   stable-inode lock on the open directory descriptor for the complete run,
   then records the run digest;
4. constructs `hostruntime.NewDockerCLI` with the existing
   `NewExecCommandRunner` and the exact private overlay;
5. constructs the existing `networkjail.NewOrchestrator` with a test-local
   lifecycle journal and Unix authority manager inside the fixture root;
6. records each engine-issued opaque handle immediately after creation;
7. admits only methods in a closed test operation enum;
8. registers the fixture's `sync.Once`-guarded cleanup state machine with
   `t.Cleanup` before the first external effect;
9. exposes itself as `conformance.HostProfile`;
10. after cases 1-14, stages the exact completed-case bitset and constructs the
   final QTS profile/network observation only through `FinalizeTarget`; and
11. destroys raw observation buffers after case digest production.

The harness never copies the controller SQLite database. Its test-local
journal/permit stores live only inside the dedicated fixture root. Actual
controller-database invisibility is proven by container mount inspection and
negative open/stat probes, not by sharing the database.

### Linux composition quantity authority

The Grok-converged
`docs/superpowers/plans/2026-07-29-task11-composition-amendment.md`
(v4, 21,287 UTF-8 bytes, SHA-256
`d84c0a33a058e47e06b760c8f646049b443a356fdd09e51b289ddc1c1115b446`)
is incorporated as a binding part of this plan.

Before Linux composition, source must prove a zero-gap matrix for every
numeric, duration, and count consumed by `NewExecCommandRunner`,
`NewDockerCLI`, `state.OpenWithHistoryLimits`,
`NewSQLitePermitAuthority`, `NewUnixAuthorityManager`, `NewOrchestrator`, all
five host-runtime specs, the closed workflow-tool-probe spec, and the prepared
orchestrator request. Exact
authorities are limited to the private input, the digest-bound overlay,
existing production protocol constants, structural constants with fixed
production meaning, and pure identity-only derivations. A newly encountered
quantity stops implementation and requires another distinct-family-reviewed
plan amendment.

The exhaustive Docker-role set is exactly adapter, broker, runner-role,
helper, verifier, and workflow-tool-probe. `runner-role` covers both the
actual runner image and the synthetic-listener image because both are created
only through production `CreateRunner` with the same exact `RunnerSpec`
resource authority. Adapter, broker, and runner-role receive identical
explicit log rotation; helper, verifier, and workflow-tool-probe use
log-driver none. Every role receives an explicit configured swap allowance
and checked Docker memory-plus-swap total. The workflow-tool probe also has a
dedicated overlay resource vector and cannot borrow verifier or runner
limits. All duration, integer-conversion, runner-envelope, log-product,
residual-log-budget, swap-addition, and client-ceiling arithmetic is checked
before effects. Task 11 chooses no operator sizing value.

### Closed command surface

`closed_command.go` wraps the existing bounded `CommandRunner` in three
non-interchangeable internal session types. `preflightSession` binds the fixed
Docker binary, authorized artifact paths, fixture parent/root, and immutable
image references. `networkSession` binds only engine-issued adapter/broker
handles. `runnerSession` binds only an engine-issued runner handle. No session
accepts caller argv, environment, arbitrary paths, image references, or
container IDs, and a cross-phase operation fails closed.

Allowed operations are exactly:

- Docker/server version and info readback;
- immutable image inspect and one fixed listener version smoke;
- container inspect, top/process list, stats, cgroup, mounts, user,
  capabilities, seccomp, masked paths, namespace identity, and exact absence;
- exact namespace routes/links/tables/conntrack and loopback flood;
- exact broker HTTPS/deny/protocol probes;
- exact path absence or immutable seed digest inside an opaque container;
- exact fixture-root stat/empty/remove/fsync operations; and
- exact controller/watchdog/fence test actions against test-local state.

No caller supplies an executable, subcommand, option, environment, mount,
network, container name, path outside the validated fixture bindings, or
unbounded stdin. Dynamic values are engine-issued opaque identities or
validated enum members. Output is bounded per operation, parsed immediately
into typed observations, then cleared. Errors exposed to tests are closed
classes only.

### Fixture cleanup

The fixture owns one `sync.Once`-guarded cleanup state machine. The normal
authority is `conformance.Run`, which calls `HostProfile.Cleanup` exactly once
under a fresh timeout from `ConformanceInput.Limits.CleanupTimeout`. The
pre-registered `t.Cleanup` safety net calls the same method only if `Run`
panicked or returned before cleanup; after a normal call it returns the cached
typed evidence and performs no second observation or deletion.

The single cleanup execution removes, in reverse authority order:

1. synthetic listener and actual held runner if present;
2. broker verifier/helper/broker;
3. adapter;
4. dial authority and per-job socket directories;
5. test-local controller/watchdog processes;
6. test-local networks; and
7. the exact fixture run directory.

It then positively proves:

- all recorded containers absent;
- all recorded cgroups/namespaces/process groups absent;
- all tmpfs/work/update/scratch/socket paths absent;
- no file descriptor holds the exact fixture directory;
- the root is empty and its device/inode binding unchanged; and
- no persistent NAS job/work/cache data exists.

Cleanup does not scan by prefix or delete unknown objects. An unexpected object
inside the exact fixture root fails cleanup and is preserved for operator
inspection; it is not recursively swept. Concurrent or repeated callers wait
for the one cleanup result; they cannot start a second destructive pass.

## Case Implementations

### Case 1: host profile

Seal only static host facts independently observed during preflight. Prove:

- exact Linux/architecture/kernel/Docker runtime;
- the fixed execution-host identity preimage and target/control separation;
- expected EUID and either strict non-root or the exact named
  `qts-capless-root` degraded profile;
- all capability sets empty for the degraded root profile;
- static cgroup-controller availability;
- validated operator-approved memory, conntrack, storage, and log comparison
  facts; and
- exact requested limits without selecting or changing any numeric value.

Case 1 does not construct the composite QTS profile, claim
`IsolationEvidence`, or populate observed final profile/network digests. Those
are produced only by `FinalizeTarget` after cases 1-14.

### Case 2: namespace baseline

Through the actual adapter/held-runner path, prove:

- unique adapter and runner namespace device/inode identities per job;
- runner has only loopback before release;
- no registered iptables/nftables table;
- zero namespace conntrack rows before and after bounded loopback flood;
- no direct IPv4/IPv6 route;
- namespace identity and emptiness unchanged after runner attachment;
- helper is NET_ADMIN-only while applying policy and absent before broker
  release; and
- adapter, broker, verifier, and runner are capability-empty.

### Case 3: broker egress

Use only the operator-controlled sentinel bindings:

- positive public HTTPS through the proxy with pinned CA/SPKI and exact
  response digest;
- literal and DNS-resolved deny classes;
- direct IPv4, IPv6, DNS, TCP, UDP, ICMP, plaintext HTTP, unsupported CONNECT
  port, SOCKS BIND/UDP, and non-proxy attempts;
- exact failure-class evidence proving denial occurred at the intended policy
  boundary;
- policy graph, conntrack budget, durable permit consumption, token ledger,
  resolver, parser, peer, and authority identities match;
- parser/fallback/crash floods remain inside the approved checked global
  conntrack/FD/process/log formulas; and
- loss of any component/policy/state/evidence prevents release.

### Case 4: mount and secret isolation

Inspect every actual component:

- the exact relay directory is read-only and visible only to adapter/broker;
- the exact dial-authority directory is read-only and visible only to broker;
- controller SQLite is invisible to every container;
- Docker socket, host device/control mount, private overlay, manifest source,
  policy source, CA source, JIT, and credential stores are invisible;
- no secret-shaped value appears in environment, command, inspect, logs, or
  report;
- the synthetic listener environment after its synthetic parser and the
  synthetic job environment contain no synthetic token; and
- actual JIT-after-parse absence remains exclusively case 15 evidence.

### Case 5: runner sandbox

On the actual immutable runner image and held runner, prove by readback:

- read-only root;
- enforced CPU, memory, swap, PID, FD, `/runner`, `/tmp`, scratch, and log
  limits;
- exact seccomp digest and namespace/raw/BPF/unshare/setns/clone3 denial;
- masked/read-only `/proc/sys`;
- no capability, socket mount, device, control secret, or reusable host work
  volume;
- strict non-root identity or exact `qts-capless-root` with every capability
  set empty; and
- all requested limits equal the private operator-approved tuple.

### Case 6: runner payload

Without registering to GitHub:

- inspect the actual immutable image for exactly one runner payload;
- smoke `Runner.Listener --version` and match the immutable runner-release
  binding;
- prove no old/new runner pair and no updater staging;
- prove no live file sweeper or update-on-start path;
- prove no JIT is baked in the image, configured environment, or filesystem;
  and
- prove actual GitHub listener transport remains a distinct pending case.

### Case 7: synthetic one job

Use the synthetic listener image through the same held-runner/orchestrator
gate. The fake listener:

- accepts only one in-memory nonsecret test token generated inside the fixture;
- writes one bounded job marker to current-job tmpfs;
- exercises one broker HTTPS request;
- exits through the normal listener completion path; and
- permits proof of deregistration, container destruction, and absent reusable
  workspace.

The fake token is not shaped like GitHub JIT material and cannot be supplied
to the actual runner image.

### Case 8: cleanup matrix

Run separate in-run synthetic job/runner cycles under the one authorized
fixture profile and root for:

- success;
- cancellation before listener release;
- pre-listener failure;
- listener crash;
- controller restart after each durable stage; and
- forced-upgrade interruption with old and candidate payloads staged only in
  the test fixture.

These rows do not create nested conformance fixtures, consume another private
input, or call `conformance.Run` again.

For every row, prove within the approved cleanup SLO that the runner,
container, cgroup, `/runner`, `/tmp`, `_work`, `_work/_update`, descendants,
namespaces, relays, authorities, and temporary files are absent. An interrupted
old/new pair or update staging residue fails.

### Case 9: reclamation series

Run the private input's explicit representative sample count. After each job:

- capture bounded high-water and post-cleanup memory, swap, tmpfs, scratch,
  container, process, FD, namespace, and filesystem counts;
- wait only until the explicit reclamation deadline and cadence;
- require every post-cleanup value at or below its approved baseline plus
  margin;
- reject a strictly increasing complete sample series;
- require at least three samples, then compare an exact integer
  least-squares slope numerator/denominator to the explicit approved maximum
  using checked `math/big` intermediates without float conversion; and
- prove no old/new runner pair, updater staging, container, process, namespace,
  or host-backed work area survives.

The harness never derives a new sizing value from this run. It reports bounded
measurements for later operator sizing review. Missing samples, arithmetic
conversion outside the report's bounded integer range, or a missing
post-cleanup observation returns `FailureArithmetic` or
`FailureObservation`; there is no automatic retry, baseline retuning, or
noisy-neighbor exception inside a run.

### Case 10: proxy-tool compatibility

Run the exact closed workflow-tool probe IDs supplied by the private input.
Each probe image and action is immutable and prequalified. Record:

- supported through broker;
- unsupported because the tool cannot use the approved proxy path; or
- failed for another closed reason.

Any unsupported or failed current tool makes the case and target report fail
and is a migration blocker. The harness does not add a direct-route exception.

Each probe is one serialized `--rm` container attached to the exact held
runner namespace. A test-local closed spec maps its dedicated overlay CPU,
memory, PID, FD, `/work` tmpfs, `/tmp` scratch, and configured swap values;
its checked total is passed through `--memory-swap`. The invocation is
non-root, read-only, `CapDrop=ALL`, no-new-privileges, seccomp-bound,
log-driver-none, and accepts no caller argv/environment/mount/device/network
override. Its exact cleanup lease is registered before execution. Success
requires bounded typed output plus exact-name absence; no one-shot fact is
promoted into long-lived HostConfig evidence.

### Case 11: seed isolation

Hydrate one immutable seed into current-job tmpfs, verify its exact digest,
mutate the current-job copy, destroy the runner, create a new runner, and prove:

- the next runner receives a fresh seed with the immutable source digest;
- current-job mutation is absent;
- no seed directory is host-backed or shared;
- no write reaches the immutable seed source; and
- both job work areas are reclaimed.

### Cases 12-14: watchdog and fence

Inside test-local roots only:

1. kill the portable disabled-observer controller and prove watchdog restart
   under the current portable guard;
2. hand off to legacy with stale enabled/canary state and prove a newer
   disabled/empty/zero epoch is durable before the force-disabled observer
   starts;
3. inject route-writer, poll, acquisition, JIT, and listener-release traps and
   require zero calls;
4. recreate cron/controller state/holder records/header as a reboot while
   legacy owns the fence and prove dark observer recovery with no portable
   acquisition; and
5. inject a non-cancellable poll process and prove process-group death before
   disabled observer restart.

Every death proof binds PID plus immutable process starttime (and process-group
identity where applicable), then proves that exact identity absent. PID-only
absence or presence is never enough because reuse could authorize an early
restart.

No test calls a live service manager, system cron, or host fence path.

### Case 15: actual GitHub transport

Source implementation returns canonical `pending` evidence. This case becomes
passing only during a separately approved secretless canary that:

- obtains one real one-job JIT through the governed acquisition path;
- obtains an in-run authenticated `githubscale.Compatibility()` result and
  proves live `DisableUpdate=true`;
- proves the JIT absent after listener parsing and from all job-visible
  surfaces;
- completes one real listener transport and HTTPS checkout;
- runs every current proxy-sensitive workflow tool;
- proves deregistration and complete reclamation; and
- binds the result to the same runtime manifest, runner image, profile,
  policy, network evidence, fleet generation, and report run.

Task 11 source work must not implement an alternate JIT source or direct
GitHub call.

## TDD Execution Tasks

### Task 0: Freeze proof layers and the QTS observation matrix

**Files:**

- Create `internal/conformance/registry.go`
- Create `internal/conformance/registry_test.go`
- Create `internal/conformance/dependency_test.go`
- Create `tests/integration/testenv/capability_matrix.go`
- Create `tests/integration/testenv/capability_matrix_test.go`

#### Step 1: Write failing registry and matrix tests

Prove:

- every required case has exactly one proof layer;
- no unknown/duplicate/missing case or observation;
- actual cases reject synthetic/pending sources;
- no generic command/argv source;
- every cases 1-15 observation named in this plan has one closed source;
- no local or actual-host `DisableUpdate` row exists;
- `actual-github-disable-update` belongs only to case 15's authenticated
  canary source;
- case 15 alone uses `actual-github-canary`; and
- defensive copies prevent registry mutation; and
- `internal/conformance` imports neither controller nor testenv.

Run:

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test ./internal/conformance ./tests/integration/testenv \
  -run 'Test.*Registry|Test.*CapabilityMatrix' -count=1
```

Expected RED: the registry and matrix are absent.

#### Step 2: Implement only the closed registries

Do not add an observation method yet. If the matrix exposes a missing closed
capability, stop and revise this plan rather than widening production
authority.

#### Step 3: Re-run report suites

Expected GREEN.

### Task 1: Add the canonical report contract

**Files:**

- Create `internal/conformance/report.go`
- Create `internal/conformance/report_test.go`
- Create `tests/conformance/host_profile_test.go`

#### Step 1: Write failing tests

Add table tests for:

- exact required case order and defensive copy;
- exact proof-layer registry and cross-layer substitution rejection;
- package-private evidence/report fields and custom wire-codec round trip;
- black-box code cannot use composite literals to mint passing state;
- one all-pass report;
- actual transport pending forcing top-level pending;
- binding expected profile/network anchors remain distinct from report
  observed profile/network digests;
- target finalization occurs only after cases 1-14 pass and case 15 is pending
  or passed;
- missing, malformed, or mismatched final target observation forces
  `FailureInvariant` while cleanup still runs;
- an expected anchor echoed without independent finalization cannot create a
  pending/passing report;
- case failure plus cleanup success;
- cleanup failure precedence;
- deadline/cancel/error normalization;
- cleanup always called exactly once with an independent bounded context;
- missing/duplicate/reordered/unknown cases;
- invalid status/failure combinations;
- zero assertions, unordered/duplicate/unknown measurements;
- invalid binding/digest/generation;
- report/build-seal domain separation;
- canonical round trip;
- unknown/trailing/whitespace/oversize/non-UTF-8 rejection;
- tampered report digest or build seal; and
- absence of forbidden identity/secret vocabulary in report fields and
  encoded output.

Run:

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test ./internal/conformance ./tests/conformance -count=1
```

Expected RED: package or contract symbols are absent.

#### Step 2: Implement the minimum report contract

Implement the exact registry, expected/observed target finalization,
validation, domains, `Run`, marshal, and parse rules above. Use no maps,
reflection-generated schema, timestamps, or raw errors.

#### Step 3: Re-run acquisition-consumer suites

Expected GREEN.

### Task 2: Add the production full-pass acquisition consumer

**Files:**

- Create `internal/controller/conformance.go`
- Create `internal/controller/conformance_test.go`
- Create `internal/conformance/gate.go`
- Create `internal/conformance/gate_test.go`
- Modify `internal/controller/service.go`
- Modify `internal/controller/runtime.go`
- Modify `internal/controller/*_test.go` only where the new required dependency
  needs an explicit real passing or unavailable conformance gate
- Modify `internal/hostruntime/evidence.go`
- Modify `internal/hostruntime/evidence_test.go`

#### Step 1: Write failing consumer tests

Cover:

- pending/failed/missing/reordered/cross-layer/tampered report rejection;
- wrong build/profile/fleet-generation request rejection;
- canary/enabled transition blocked before persistence;
- restart under persisted canary/enabled enters cleanup-first zero/fatal state;
- acquisition batch and listener release recheck the gate;
- gate loss revokes pre-running work and creates no listener;
- disabled/fatal behavior remains available with the unavailable gate;
- fully passing report permits only matching canary/enabled requests;
- source-only or bare report digest cannot create `TargetConformance`; and
- matching full target plus source evidence is still required for
  `DeploymentEligibility`.

Run:

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test ./internal/conformance ./internal/controller ./internal/hostruntime \
  -run 'Test.*Conformance|Test.*TargetConformance|Test.*AcquisitionGate' \
  -count=1
```

Expected RED: the port/gate and service dependency are absent.

#### Step 2: Implement the minimum fail-closed consumer

Use the existing acquisition transition and cleanup-first fatal paths. Add no
report path, bypass bool, admin force, or implicit development proof.

#### Step 3: Re-run private-input suites

Expected GREEN.

### Task 3: Add and harden the private input codec

**Files:**

- Create `tests/integration/testenv/config.go`
- Create `tests/integration/testenv/config_test.go`

#### Step 1: Write failing parser tests

Cover every canonical field and rejection class in the private-input section,
including immutable image/tool reference grammar and cross-document
substitution rejection, and explicit numeric values without choosing
production values.
Fixtures use synthetic digests, documentation paths under a test temp
directory, and public example domains only.

Run:

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test ./tests/integration/testenv -run 'Test.*ConformanceInput' -count=1
```

Expected RED: input types/parser are absent.

#### Step 2: Implement the minimum strict codec

Implement declaration-order canonical JSON, closed enums, byte/time limits,
cross-binding checks, no-follow file readback, and secret/URL/command rejection.

#### Step 3: Re-run fixture-boundary suites

Expected GREEN.

### Task 4: Add the opt-in fixture boundary

**Files:**

- Create `tests/integration/testenv/profile.go`
- Create `tests/integration/testenv/fixture.go`
- Create `tests/integration/testenv/fixture_linux.go`
- Create `tests/integration/testenv/fixture_unsupported.go`
- Create `tests/integration/testenv/closed_command.go`
- Create `tests/integration/testenv/closed_command_test.go`
- Create `tests/integration/testenv/observations.go`
- Create `tests/integration/testenv/reclamation.go`
- Create `tests/integration/testenv/fixture_test.go`

#### Step 1: Write failing source tests

Use injected host facts and a scripted bounded runner to prove:

- Darwin/unsupported exact skip;
- absent opt-in exact skip;
- malformed present opt-in failure;
- the Linux entrypoint cannot bypass the retained one-shot input lease;
- lock contention returns `authorization_in_use` without retry;
- pre-unlink identity/expiry failure leaves the input intact;
- successful consume proves path absence before root/effects;
- post-unlink fsync/absence failure returns
  `authorization_consumed_run_aborted`, starts no run effect, and cannot
  unlink again;
- a recreated basename is preserved after absence-proof failure;
- a pre-opened losing invocation cannot pass the post-lock path check;
- lease close zeros retained input bytes without losing the previously
  captured report-binding digest;
- target/control identity mismatch required;
- fixed execution-host identity golden bytes and one-field mutations;
- no-follow fixture-parent and Docker-binary identity rejection for symlink,
  replacement, writable, or multilink objects;
- no first effect before every binding validates;
- exact operation enum and argv;
- phase-bound session operation rejection;
- bounded output and closed errors;
- cleanup registration before first effect;
- exact startup order is cleanup registration, authorization consume,
  root acquire, then effects;
- one idempotent cleanup authority, independent deadline, cached second call,
  and cleanup precedence;
- exact reverse-order handle cleanup;
- no prefix scan/recursive sweep;
- unexpected root object preserved and fails cleanup; and
- raw observation buffers cleared after digesting.

Expected RED: fixture boundary is absent.

#### Step 2: Implement the minimum boundary

Keep Linux effect code behind `integration && linux`. The untagged source tests
exercise only injected fakes and perform no Docker or host action.

#### Step 3: Re-run

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test ./tests/integration/testenv -count=1
```

Expected GREEN.

### Task 5: Add network and isolation integration cases

**Files:**

- Create `tests/integration/conformance_test.go`
- Create `tests/integration/topology_test.go`
- Create `tests/integration/network_jail_test.go`
- Extend `tests/integration/testenv/observations.go`
- Extend `tests/integration/testenv/fixture_linux.go`

#### Step 1: Write tagged failing cases 7-11 tests

Add cases 1-6 with exact assertions from this plan through the sole
`TestPortableGHARConformance` entrypoint. Case-level adversarial assertions use
non-effectful injected source tests; no separate tagged test acquires a fixture.

`tests/integration/conformance_test.go` exclusively owns the one tagged
effect-capable `func TestPortableGHARConformance`. Rewrite the pre-amendment
`TestHostAndNetworkIsolationCases`,
`TestOneJobCleanupReclamationToolAndSeedCases`, and
`TestWatchdogFenceAndNoncancellableShutdownCases` functions as helper-only
assertions or delete them. The case-group files must not define another tagged
`func Test*` that references `StartDockerFixture`, consumes a lease, or calls
`conformance.Run`.

Add an untagged AST topology test in `tests/integration/topology_test.go`. It
must first fail RED while the three old effect entrypoints exist, then pass
GREEN only when the package contains exactly one effect entrypoint named
`TestPortableGHARConformance`, exactly one `StartDockerFixture` reference, and
exactly one `conformance.Run` call. It rejects indirect helper call sites and a
second tagged effect `Test*`.

On the development Mac run:

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test -tags=integration ./tests/integration \
  -run '^TestPortableGHARConformance$' -v -count=1

go test ./tests/integration -run '^TestSingleEffectEntrypointTopology$' -v -count=1
```

Expected RED before implementation, then exact
`SKIP unsupported host profile` after the unsupported boundary exists. A skip
is not target evidence.

#### Step 2: Implement Linux observations

Use existing `hostruntime`/`networkjail` production surfaces first. Add no
generic production method solely for tests. Build the final
`hostruntime.ProfileObservation` only after the exact cases 1-14 bitset is
complete, and return its profile/network digests through `FinalizeTarget`.
If one required target observation cannot be made through a closed test-only
command, stop and revise this plan before widening production authority.

#### Step 3: Run cases 7-11 source and tagged suites

Expected: untagged source tests GREEN; Darwin tagged suite explicit SKIP.

### Task 6: Add one-job, cleanup, reclamation, tool, and seed cases

**Files:**

- Extend `tests/integration/conformance_test.go`
- Create `tests/integration/one_job_test.go`
- Extend `tests/integration/testenv/fixture_linux.go`
- Extend `tests/integration/testenv/reclamation.go`

#### Step 1: Write tagged failing cases 12-14 tests

Add cases 7-11 to the same canonical run, with in-run matrix rows and source
tests per cleanup condition and resource dimension. No subtest starts another
fixture or calls `conformance.Run`. Include adversarial regressions for:

- fake success without container/cgroup absence;
- old/new payload pair;
- `_work/_update` residue;
- increasing but individually under-baseline measurements;
- slope overflow;
- unsupported workflow tool counted as pass;
- shared host work volume;
- mutated seed visible in next job; and
- synthetic listener satisfying actual transport.

#### Step 2: Implement the minimum harness

Keep actual and synthetic images separate by type and case registry. No type
conversion or shared `passed` evidence constructor may cross that boundary.

#### Step 3: Run source and tagged suites

Use the exact `^TestPortableGHARConformance$` and
`^TestSingleEffectEntrypointTopology$` commands from Task 5. Expected on
Darwin: explicit SKIP, never target pass.

### Task 7: Add watchdog and fence cases

**Files:**

- Extend `tests/integration/conformance_test.go`
- Create `tests/integration/watchdog_test.go`
- Extend `tests/integration/testenv/fixture.go`
- Extend `tests/integration/testenv/fixture_linux.go`

#### Step 1: Write tagged failing tests

Add cases 12-14 to the same canonical run and assert exact ordered state, zero
trap calls, monotonic fence generation, process death, and cleanup. Include
old-process ignores-cancel and stale enabled/canary policy regressions. No
separate effect-capable tagged test is added.

`watchdog_test.go` is helper/source-test only. The AST topology test remains a
required gate and must still observe exactly one fixture reference and one
`conformance.Run` call in `TestPortableGHARConformance`.

#### Step 2: Implement test-local composition

Reuse Task 9/10 stores and lifecycle engine with test-local roots. Do not call
QTS scripts, launchd, cron, systemd, a live controller, or a live fence.

#### Step 3: Re-run watchdog and fence suites

Expected source GREEN and Darwin explicit SKIP.

### Task 8: Complete report integration and source verification

**Files:**

- Extend `tests/conformance/host_profile_test.go`
- Extend the integration tests only as required

#### Step 1: Add full-report tests

Prove:

- actual transport pending yields a canonical pending report;
- all source/synthetic cases cannot override that pending result;
- expected anchors cannot manufacture observed target evidence;
- pending/pass requires exact expected/observed profile and network equality;
- a later injected actual transport proof can produce all-pass report;
- any component/policy/state loss fails before release;
- any cleanup failure overrides case results; and
- report bytes remain identity-free and secret-free.

#### Step 2: Run formatting and focused suites

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
gofmt -w \
  internal/conformance/*.go \
  internal/controller/conformance*.go \
  internal/controller/service.go \
  internal/controller/runtime.go \
  internal/hostruntime/evidence*.go
find tests/conformance tests/integration -type f -name '*.go' -print0 |
  xargs -0 gofmt -w

HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test ./internal/conformance ./internal/controller ./internal/hostruntime \
  ./tests/conformance ./tests/integration/testenv -count=1

HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test -tags=integration ./tests/integration ./tests/conformance -v -count=1
```

Expected: source suites PASS; tagged Darwin suite reports explicit unsupported
skip and no target-pass report.

#### Step 3: Run repository verification

```bash
HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go test ./... -count=1

HOME=/private/tmp/portable-ghar-task11-home \
GOPATH="$(go env GOPATH)" GOPROXY=off GOSUMDB=off \
GOCACHE=/private/tmp/portable-ghar-task11-go-cache \
GOTOOLCHAIN=go1.26.5 \
go vet ./...

git diff --check
git status --short
```

Expected: all source tests/vet pass; only Task 11 planned files differ.

### Task 9: Obtain exact xAI/Grok review and create a signed source checkpoint

#### Step 1: Seal the exact review artifact

Include:

- this converged plan and its SHA-256;
- base and proposed head;
- complete staged diff;
- focused/full test commands and results;
- explicit unsupported-host output;
- exact list of pending target proofs; and
- statement that no host action or numeric choice occurred.

Run a synchronous read-only xAI/Grok exact-artifact governance review. Accept
only a substantive matching-digest result. If findings materially change the
plan, return to the plan cross-check before implementation changes.

#### Step 2: Verify after review

Rehash the unchanged artifact/head and rerun affected tests. Do not count a
review of a stale digest.

#### Step 3: Commit the source checkpoint

```bash
git add \
  docs/superpowers/plans/2026-07-29-task11-implementation.md \
  internal/conformance \
  internal/controller \
  internal/hostruntime/evidence.go \
  internal/hostruntime/evidence_test.go \
  tests/conformance \
  tests/integration
git diff --cached --check
git status --short
git commit -S -m "test: prove runner host and network isolation"
```

This commit records source implementation only. It does not close Task 11's
operational gate.

## Resolved Design Decisions and Operator-Open Inputs

Resolved in source:

- proof layers are registry-owned and type-separated;
- evidence/report state is package-opaque and uses case-specific sealers plus a
  custom canonical wire codec;
- static expected digests are recomputed before mutation, while final
  profile/network observations are recomputed only after their exact dynamic
  cases and remain distinct from expected anchors in the report;
- execution-host identity has one frozen canonical preimage;
- every image/tool executable identity is a complete immutable reference plus
  a matching separate digest;
- live `DisableUpdate` belongs only to the authenticated actual-GitHub case;
- closed observations are phase-bound to preflight, network, or runner
  sessions;
- the operator-created private input is the one-shot authorization capability;
  its locked exact-identity consume boundary adds no persistent marker or
  runner state and distinguishes reusable pre-unlink failures from spent
  post-unlink aborts;
- one idempotent fixture state machine owns cleanup;
- pending/partial reports cannot enable acquisition;
- the package graph is `controller -> conformance` and
  `hostruntime -> conformance`, never the reverse;
- no production report loader is introduced before the later
  operator-governed lifecycle gate;
- process death binds PID plus starttime;
- reclamation uses at least three samples, exact integer math, and no hidden
  retry/retuning;
- unsupported current workflow tooling is a migration blocker, as required by
  the canonical Task 11 contract; and
- CI/source success remains labeled source-only until Task 13 adds the full
  release gate.

Still operator-gated and intentionally absent from source:

- all tmpfs, cgroup, swap, CPU, concurrency, conntrack, storage, log,
  retention, cadence, baseline, margin, slope, and sample-count values above
  the source minimum;
- exact target identity, private paths, execution owner, fixture root, and
  execution window;
- immutable prequalified image references and digests;
- public positive and DNS-deny sentinel identities/pins;
- the exact current workflow-tool probe set;
- QTS execution timing and acceptable operational impact; and
- the later actual GitHub one-job canary authorization; and
- the later lifecycle authority that installs and refreshes the private
  passing report for an active service generation.

## Operator-Gated Target Execution

Only after separate operator sign-off:

1. review the private conformance input without exposing its values in public
   logs or commits;
2. confirm immutable qualified images already exist and no build/pull/retag is
   required;
3. confirm the dedicated fixture root is empty, bounded, and not persistent
   job storage;
4. confirm the execution window, target identity, numeric envelopes, public
   sentinel, DNS deny sentinels, workflow-tool probes, and cleanup SLO;
5. drain no live workload and change no host config merely to make the test
   pass;
6. run:

```bash
test -n "${PGHAR_OPERATOR_APPROVED_INPUT:?set after operator sign-off}"
PGHAR_INTEGRATION_DOCKER=1 \
PGHAR_CONFORMANCE_INPUT="$PGHAR_OPERATOR_APPROVED_INPUT" \
GOTOOLCHAIN=go1.26.5 \
go test -tags=integration ./tests/integration ./tests/conformance -v -count=1
```

After the command completes:

1. require PASS on the supported target profile, positive cleanup, and one
   canonical private evidence file;
2. separately run the governed actual GitHub transport/canary case; and
3. re-run the full report only when all bindings still match.

Any unsupported profile prints `SKIP unsupported host profile`; any supplied
but invalid target input fails. Neither outcome is a structural pass.

## Definition of Done

The Task 11 source checkpoint is complete when:

- the report and input codecs are canonical and adversarially tested;
- macOS source suites pass without Docker/host effects;
- tagged Darwin execution explicitly skips unsupported target work;
- all Linux effect code is opt-in and closed;
- synthetic and actual evidence cannot substitute for each other;
- cleanup is mandatory, bounded, positively verified, and precedence-safe;
- the exact source artifact receives matching-digest substantive xAI/Grok
  review; and
- the signed commit contains only planned source/test/plan files.

Task 11's operational gate is complete only when a separately approved
supported Linux/QTS run and actual GitHub transport canary both pass against
the same immutable bindings, the canonical report is top-level `passed`, and
positive cleanup proves no persistent job state or monotonic resource trend.

Until then:

- acquisition remains disabled;
- no RhoNAS configuration changes;
- no numeric sizing decisions;
- no Docker build/pull/retag/delete;
- no live service or routing mutation;
- no source-only target-conformance claim; and
- later source tasks may proceed only if they preserve this open target gate.
