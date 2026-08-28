# Portable-GHAR Task 12 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Phase 3 authority amendment:** This completed Phase 2 release plan keeps its
journal, immutable-candidate, hosted-continuity, and read-back guarantees.
Future directives bind the shared acquisition-lease generation; they do not
revive remote per-operation permits or a separate legacy process lease.
Platform-design §9 and the failover plan are normative.

**Goal:** Add a crash-resumable, fail-closed controller-side runner release
observer and externally authorized immutable-candidate replacement state
machine, plus source-ready chaos coverage and operator recovery runbooks,
without enabling routing or touching a live host.

**Architecture:** A new `internal/upgrade` package owns the exact runner
release, maintenance-directive, candidate, compatibility, quiescence, health,
and journal contracts. `Upgrade.ReconcileRunnerRelease` observes and journals
release state freely, but advances at most one externally meaningful phase per
call and re-fetches a fresh, exact-bound, authenticated read-only maintenance
directive immediately before that phase. Every mutation first persists an
`*-applying` intent, then calls an identity-bound idempotent port, then reads
back and persists the proven result; a crash never permits a later phase and a
cached directive is never reusable authority.

**Tech Stack:** Go 1.26.5, canonical JSON, SHA-256 domain-separated evidence,
`net/http`, descriptor-relative Unix file operations and `flock`,
controller `LiveAdmin`, existing host-runtime/fleet-fence contracts, Go unit
and race tests, opt-in Linux/Docker chaos tests, Markdown runbooks.

## Global Constraints

- The authoritative requirements are Task 12 in
  `docs/superpowers/plans/2026-07-11-controller-runtime.md`, the runner release
  lifecycle in
  `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`, and the
  locked maintenance request/directive interfaces in
  `docs/superpowers/plans/2026-07-11-failover-deployment.md`.
- This task is source, tests, and documentation only. It does not modify a
  deployment host, QTS, Docker, launchd, systemd, GitHub routing, a fleet
  selector, a broker lane, a secret, or any live service.
- Numeric runner sizing, tmpfs, memory, swap, CPU, concurrency, storage, build
  reserve, and observer cadence values remain operator-open. No production
  default or inferred value is introduced.
- The selected, candidate, and rollback artifacts are immutable digests. A
  preserved rollback artifact is evidence and storage, not automatic
  downgrade authority.
- A runner version is exactly `vMAJOR.MINOR.PATCH`, with unsigned decimal
  components, no sign, no leading zero, and numeric rather than lexical
  comparison.
- A runner manifest or image identity is exactly `sha256:` plus 64 lowercase
  hexadecimal characters. An evidence digest is exactly 64 lowercase
  hexadecimal characters.
- The official release observer accepts one non-draft, non-prerelease
  `actions/runner` release, one immutable tag/ref identity, and exactly one
  Linux x64 asset named
  `actions-runner-linux-x64-<MAJOR.MINOR.PATCH>.tar.gz`.
- The asset must carry an official `sha256:` digest, nonzero bounded size, and
  a UTC publication time. Missing, duplicate, ambiguous, downgraded, wrong-tag,
  wrong-platform, wrong-name, missing-digest, or malformed observations fail
  closed and create no candidate.
- The observer has bounded bodies, no implicit redirect, an explicit context
  deadline, and no caller-supplied production origin.
- Phase 2 defines the controller-side verified maintenance response parser and
  provider interface, but does not implement the enrolled Worker client or
  claim operational unattended replacement. The default provider is
  unavailable and returns no directive.
- A maintenance response is usable only after cryptographic verification over
  the exact domain-separated response frame, strict canonical parsing, exact
  request/response equality, phase-shape validation, and server-expiry
  validation.
- `wait-hosted` is not mutation authority. Any missing, unavailable, expired,
  malformed, stale-session, wrong-request, wrong-control-sequence,
  wrong-transition, wrong-permit-generation, wrong-config, wrong-candidate,
  wrong-qualified-tuple, or wrong-policy response produces no local effect.
- `stage-permitted` authorizes only acquisition disable, exact-candidate local
  staging, and exact-candidate qualification. It never authorizes selection.
- `replace-permitted` authorizes only bounded drain, exact quiescence proof,
  replacement validation, and atomic selection of the already-qualified exact
  tuple.
- `canary-permitted` and `enable-permitted` authorize only their matching
  policy transitions through `controller.LiveAdmin`; returned epoch, mode,
  capacity, and policy digest must match the directive and configured policy.
- `complete` is evidence only. It never changes policy, routing, a selector,
  or retained artifacts.
- The upgrade package has no routing writer, GitHub-variable writer,
  fleet-fence handoff, arbitrary command, shell, argv, environment, path, or
  secret phase surface. The journal-store constructor accepts one validated
  absolute private root from trusted local configuration; no directive,
  release, candidate, or runtime method can supply or alter it.
- The controller can observe, journal, stage, disable, drain, probe, select,
  and change local acquisition only through the closed injected ports. It
  cannot make both hosted and self-hosted paths unavailable.
- One reconciliation call performs no more than one externally meaningful
  phase. Every later phase requires a new call, a new status request/control
  sequence, and a fresh directive.
- Every effect attempt obtains a strictly newer control sequence in the
  current enrollment session, or a positive newer-enrollment epoch/session
  with a fresh sequence after re-enrollment. The exact request and directive
  digest is single-phase authority and cannot be reused for another effect.
- The selected manifest in every maintenance request is the live immutable
  selection. The candidate manifest is nil only before an exact candidate is
  observed; it remains the journal-bound candidate from disable through
  completion, including after that candidate becomes the selected manifest.
- Before an effect, persist an exact `*-applying` phase. After the effect,
  inspect the target by exact identity and persist the proven phase. An
  applying phase on restart can only be resumed or classified; it cannot be
  skipped.
- Exported canonical Task 12 methods are not alternate authority paths. They
  require an unexported, single-call phase capability created only by
  `ReconcileRunnerRelease` after exact directive authorization, plus the held
  journal lease, exact current phase, and journal-bound tuple. Direct or
  out-of-phase calls perform no effect.
- Errors are typed as unavailable/retryable, rejected/permanent, ambiguous, or
  integrity-fatal. Raw provider, GitHub, Docker, job, repository, path, command,
  response body, or credential content never crosses the public health or
  journal boundary.
- `runner_upgrade_required`, `candidate_qualified`, and
  `candidate_rejected` health follows the exact Phase 3
  `RunnerReleaseStatusV1` tuple and carries no arbitrary error string.
- A non-current status may be journaled during an operator hold, but the
  provider must continue to return `wait-hosted`; the local controller cannot
  replace the hold reason, stage, select, or auto-release it.
- A nonterminal operation freezes the public observed release and candidate
  tuple. Cadence observation may still detect a newer upstream release, but it
  cannot alter the active journal or published `RunnerReleaseStatus`; the next
  cycle re-observes the latest release after the current generation reaches a
  terminal state.
- Job-scoped cleanup removes whole containers and positively proves absence.
  This task adds no serving-runner file sweeper and never deletes an old
  runner payload from a live container.
- The approved Grafana/InfluxDB lifecycle requirements remain documentation
  only. GitHub API workload state remains authoritative; the local health
  export is read-only, schema-versioned, and one-way.
- All public fixtures use project-safe example identities. The sanitizer and
  private-identifier scan must remain clean.
- The canonical Task 12 checkpoint is one signed commit after exact
  distinct-family review. Intermediate RED/GREEN slices are verified but not
  separately committed.

## File and Dependency Map

### New production files

- `internal/upgrade/model.go`
  - closed enums and exact runner release, candidate, compatibility,
    quiescence, selection, and health projections
  - canonical validators, numeric version comparison, and domain-separated
    digests
- `internal/upgrade/runner_release.go`
  - official `actions/runner` release/ref/asset observation
  - fixed production origins, bounded HTTP, immutable tag peeling, and
    evidence construction
- `internal/upgrade/directive.go`
  - exact maintenance request/directive wire contracts
  - canonical response-frame construction and authenticated parser
  - fail-closed unavailable provider
- `internal/upgrade/journal.go`
  - canonical crash-resume journal, closed phases, phase-specific validation,
    transition validation, and store/lease interfaces
- `internal/upgrade/store.go`
  - store constants, configuration, identity-free errors, and platform-neutral
    interfaces
- `internal/upgrade/store_unix.go`
  - Darwin/Linux descriptor-relative journal lock/read/CAS write/read-back
- `internal/upgrade/store_rename_darwin.go`
- `internal/upgrade/store_rename_linux.go`
  - platform-native atomic no-replace rename for the initial durable journal
- `internal/upgrade/store_other.go`
  - fail-closed unsupported-platform implementation
- `internal/upgrade/service.go`
  - `Upgrade` construction, canonical Task 12 methods, one-phase reconciler,
    effect-intent/resume logic, and health publication

### New test files

- `internal/upgrade/model_test.go`
- `internal/upgrade/runner_release_test.go`
- `internal/upgrade/directive_test.go`
- `internal/upgrade/journal_test.go`
- `internal/upgrade/store_test.go`
- `internal/upgrade/service_test.go`
- `tests/chaos/controller_states_test.go`
- `tests/chaos/docker_failure_test.go`
- `tests/chaos/jail_failure_test.go`
- `tests/chaos/fleet_fence_test.go`
- `tests/chaos/qts_install_test.go`

### New runbooks

- `docs/operations/controller-upgrade.md`
- `docs/operations/controller-recovery.md`
- `docs/operations/runner-release.md`

### Existing files modified only when required by tests

- `docs/operations/production-lifecycle.md`
  - add links to the three Task 12 runbooks without changing the approved
    Grafana/InfluxDB authority model
- `internal/hostruntime/recovery.go` or another existing exact read-back helper
  - only if the new chaos tests expose a missing closed read-back needed by the
    Task 12 quiescence port
- `internal/controller/runtime.go`
  - only if an existing `LiveAdmin` response is insufficient to prove the
    exact policy transition; no second acquisition mutation path is allowed

The dependency direction is:

```text
buildinfo ─┐
controller ├──> upgrade
health? ───┘       │
                   ├──> injected status sink
hostruntime <──────┘ through narrow interfaces only
```

`controller`, `hostruntime`, `fleetfence`, and `health` do not import
`upgrade`. The new package may import their stable value types and interfaces.

## Canonical Interfaces

`internal/upgrade/model.go` defines:

```go
type RunnerReleaseObserver interface {
	Observe(context.Context) (RunnerRelease, error)
}

type RunnerRelease struct {
	Version              string
	TagRefSHA            string
	SourceCommitSHA      string
	LinuxX64AssetName    string
	LinuxX64AssetSize    uint64
	LinuxX64AssetDigest  string
	PublishedAt          time.Time
	ObservationEvidence string
}

type Candidate struct {
	Version                     string
	ReleaseEvidenceDigest       string
	RunnerReleaseManifestDigest string
	ManifestDigest              string
	ImageDigest                 string
	AttestationDigest           string
	ProvenanceDigest            string
}

type Selection struct {
	Version                string
	ManifestDigest         string
	ImageDigest            string
	RollbackVersion         string
	RollbackManifestDigest  string
	RollbackImageDigest     string
	ObservedAt             time.Time
}

type StageObservation struct {
	Version               string
	ReleaseEvidenceDigest string
	ManifestDigest        string
	ImageDigest           string
	Complete              bool
	Selected              bool
	EvidenceDigest        string
	ObservedAt            time.Time
}

type CompatibilityReport struct {
	Version                     string
	ManifestDigest              string
	ImageDigest                 string
	ReleaseEvidenceDigest       string
	RunnerReleaseManifestDigest string
	RuntimeManifest             hostruntime.RuntimeManifest
	RuntimeManifestDigest       string
	AttestationDigest           string
	ProvenanceDigest            string
	ListenerVersionEvidence     string
	DisableUpdateEvidence       string
	HostProbeEvidence           string
	ReclamationEvidence         string
	ListenerVersionOK           bool
	DisableUpdateOK             bool
	SingleRunnerPayload         bool
	UpdateStagingAbsent         bool
	RuntimeManifestOK           bool
	HostProfileOK               bool
	ReclamationOK               bool
	EvidenceDigest              string
	ObservedAt                  time.Time
}

type Quiescence struct {
	Listeners        uint64
	Runners          uint64
	Adapters         uint64
	HeldBrokers      uint64
	RunningBrokers   uint64
	Helpers          uint64
	Verifiers        uint64
	PerJobSocketDirs uint64
	ActiveDials      uint64
	PendingEffects   uint64
	RetainedLedgers  bool
	EvidenceDigest   string
	ObservedAt       time.Time
}

type RunnerReleaseState string

const (
	RunnerReleaseCurrent            RunnerReleaseState = "current"
	RunnerReleaseUpgradeRequired    RunnerReleaseState = "upgrade-required"
	RunnerReleaseCandidateQualified RunnerReleaseState = "candidate-qualified"
	RunnerReleaseCandidateRejected  RunnerReleaseState = "candidate-rejected"
)

type RunnerReleaseStatus struct {
	State                   RunnerReleaseState `json:"state"`
	ObservationSequence     uint64             `json:"observationSequence"`
	ObservedVersion         string             `json:"observedVersion"`
	SelectedVersion         string             `json:"selectedVersion"`
	SelectedManifestDigest  string             `json:"selectedManifestDigest"`
	SelectedImageDigest     string             `json:"selectedImageDigest"`
	CandidateVersion        *string            `json:"candidateVersion"`
	CandidateManifestDigest *string            `json:"candidateManifestDigest"`
	CandidateImageDigest    *string            `json:"candidateImageDigest"`
}
```

`RunnerReleaseStatus.Validate` applies the exact Phase 3 tuple rules:

- `current`: observed equals selected; every candidate field is nil
- `upgrade-required`: observed is numerically newer; every candidate field is
  nil
- `candidate-qualified`: all candidate fields are non-nil and equal the
  observed version plus the exact qualified manifest/image tuple
- `candidate-rejected`: candidate version is non-nil and newer; manifest/image
  may be nil but can never authorize selection

`CompatibilityReport.EvidenceDigest` is a domain-separated binding over the
exact candidate and release evidence plus the complete
`hostruntime.RuntimeManifest`: controller and component image/file digests,
archive manifest, trust bundle/CA, seccomp, policy, conntrack/storage/log
budget digests, fleet generation, runner-release manifest, attestation,
provenance, listener-version proof, disable-update proof, host probes, and
reclamation proof. The post-quiescence validation must reproduce that binding;
any field drift is integrity-fatal and leaves selection unchanged.

`internal/upgrade/directive.go` defines:

```go
type RunnerMaintenanceStatusRequest struct {
	Protocol                string  `json:"protocol"`
	FleetID                 string  `json:"fleetId"`
	Epoch                   uint64  `json:"epoch"`
	SessionID               string  `json:"sessionId"`
	ControlSequence         uint64  `json:"controlSequence"`
	SelectedManifestDigest  string  `json:"selectedManifestDigest"`
	CandidateManifestDigest *string `json:"candidateManifestDigest"`
}

type RunnerMaintenancePhase string

const (
	MaintenanceWaitHosted       RunnerMaintenancePhase = "wait-hosted"
	MaintenanceStagePermitted   RunnerMaintenancePhase = "stage-permitted"
	MaintenanceReplacePermitted RunnerMaintenancePhase = "replace-permitted"
	MaintenanceCanaryPermitted  RunnerMaintenancePhase = "canary-permitted"
	MaintenanceEnablePermitted  RunnerMaintenancePhase = "enable-permitted"
	MaintenanceComplete         RunnerMaintenancePhase = "complete"
)

type MaintenanceDirectiveProvider interface {
	Current(
		context.Context,
		RunnerMaintenanceStatusRequest,
	) (RunnerMaintenanceDirective, error)
}

type MaintenanceResponseVerifier interface {
	VerifyRunnerMaintenanceResponse(
		context.Context,
		[]byte,
		string,
	) error
}

type runnerMaintenanceDirectiveWire struct {
	Protocol                         string                 `json:"protocol"`
	Epoch                            uint64                 `json:"epoch"`
	SessionID                        string                 `json:"sessionId"`
	RequestControlSequence           uint64                 `json:"requestControlSequence"`
	RequestedSelectedManifestDigest  string                 `json:"requestedSelectedManifestDigest"`
	RequestedCandidateManifestDigest *string                `json:"requestedCandidateManifestDigest"`
	TransitionEpoch                  uint64                 `json:"transitionEpoch"`
	PermitGeneration                 uint64                 `json:"permitGeneration"`
	Phase                            RunnerMaintenancePhase `json:"phase"`
	QualifiedVersion                 *string                `json:"qualifiedVersion"`
	QualifiedManifestDigest          *string                `json:"qualifiedManifestDigest"`
	QualifiedImageDigest             *string                `json:"qualifiedImageDigest"`
	ConfigRevision                   uint64                 `json:"configRevision"`
	CanaryPolicyDigest               string                 `json:"canaryPolicyDigest"`
	EnabledPolicyDigest              string                 `json:"enabledPolicyDigest"`
	ExpiresAtServerMS                int64                  `json:"expiresAtServerMs"`
	ResponseMAC                      string                 `json:"responseMac"`
}
```

`ParseVerifiedRunnerMaintenanceDirective` is the only exported constructor of
a usable directive. The wire struct carries the exact JSON tags and field order
from `RunnerMaintenanceDirectiveV1`; the public directive stores those values
privately with an unforgeable verified marker. The parser removes
`responseMac`, reconstructs the exact frame:

```text
portable-ghar-response-v1\n
portable-ghar.runner-maintenance.directive.v1\n
<canonical response object without responseMac>
```

and calls the verifier before returning a value carrying private verified
authority. Direct struct literals remain unusable outside package tests.

For each phase attempt, `MaintenanceRequestSource` must return a request with
the live selected manifest and journal candidate rules above. In one
enrollment epoch/session, `controlSequence` must be strictly greater than the
last persisted attempt; a newer enrollment epoch may introduce a new
validated session and fresh positive sequence, while session drift in the same
epoch is rejected. The authorized phase, request, response, enrollment
binding, control sequence, configuration revision, policy digests, and
qualified tuple are hashed into one single-use directive binding. Crash
recovery re-fetches and verifies a new directive; it never reuses the
persisted binding as authority.

`internal/upgrade/service.go` defines:

```go
type Upgrade struct { /* private, validated dependencies */ }

func New(Config) (*Upgrade, error)

func (u *Upgrade) StageRunnerCandidate(
	context.Context,
	RunnerRelease,
) (Candidate, error)

func (u *Upgrade) QualifyRunnerCandidate(
	context.Context,
	Candidate,
) (CompatibilityReport, error)

func (u *Upgrade) Prepare(
	context.Context,
	controller.DrainPolicy,
) error

func (u *Upgrade) ProveQuiescent(
	context.Context,
) (Quiescence, error)

func (u *Upgrade) ValidateReplacement(
	context.Context,
) (CompatibilityReport, error)

func (u *Upgrade) ReconcileRunnerRelease(
	context.Context,
	MaintenanceDirectiveProvider,
) error
```

The service consumes narrow ports:

```go
type SelectionSource interface {
	CurrentSelection(context.Context) (Selection, error)
}

type CandidateSource interface {
	ObserveCandidate(context.Context, RunnerRelease) (Candidate, error)
}

type CandidateRuntime interface {
	InspectStage(context.Context, Candidate) (StageObservation, error)
	Stage(context.Context, Candidate) error
	Qualify(context.Context, Candidate) (CompatibilityReport, error)
	InspectSelection(context.Context) (Selection, error)
	ProveQuiescent(context.Context) (Quiescence, error)
	ValidateReplacement(context.Context, Candidate) (CompatibilityReport, error)
	Select(context.Context, Candidate) error
}

type MaintenanceRequestSource interface {
	CurrentMaintenanceRequest(
		context.Context,
		string,
		*string,
	) (RunnerMaintenanceStatusRequest, error)
}

type ReleaseStatusPublisher interface {
	PublishRunnerRelease(context.Context, RunnerReleaseStatus) error
}
```

`CandidateRuntime` has no delete-current, delete-rollback, downgrade, route,
shell, argv, or arbitrary-image method. `controller.LiveAdmin` is the only
policy/drain authority in `Config`. `Config` also freezes
`ConfigurationRevision`, `DrainPolicy`, `CanaryScaleSet`, `EnabledCapacity`,
`CanaryPolicyDigest`, `EnabledPolicyDigest`, operation/directive deadlines,
and all narrow dependencies. A reconstructed `Upgrade` whose configuration
revision or policy binding differs from the active journal fails closed before
any effect.

`CandidateSource.ObserveCandidate` is strictly read-only discovery of the
Task 14 attested immutable tuple; it has no staging or selection method and may
bind a candidate to `upgrade-required` before a directive exists.
`StageRunnerCandidate` is the separately authorized local stage primitive: the
supplied release must equal the journal release, and the only candidate it may
stage/return is the already journal-bound candidate.

The exported canonical methods are capability-checked primitives, not manual
bypass APIs. `ReconcileRunnerRelease` alone validates a fresh directive,
creates an unexported single-call `phaseCapability`, attaches it to an internal
context, holds the journal lease, and invokes the matching primitive. Each
primitive verifies the capability phase, request/directive digest,
control/enrollment sequence, journal generation, and candidate/selection
binding before acting. `Prepare` additionally requires its caller argument to
equal `Config.DrainPolicy`; `ValidateReplacement` reads the exact candidate
from the journal rather than accepting a caller tuple. Calls without that
capability, with a copied capability, or outside the exact applying phase
return a typed authorization error and make zero admin/runtime calls.

Runtime ports return closed errors: unavailable/retryable remains on the
applying phase; permanent identity or compatibility rejection records
`candidate-rejected` while selection remains unchanged; ambiguous or partial
effect remains applying for exact read-back; integrity-fatal stops the
controller. No raw runtime/provider text is persisted or published.

## Journal State Machine

The journal stores one exact operation at a time. Its immutable binding is:

```text
selected version + selected manifest + selected image
observed release version + release evidence
candidate version + candidate manifest + candidate image
configuration revision
```

The ordered phases are:

```text
current
upgrade-required
disable-applying
disabled
stage-applying
staged
qualify-applying
candidate-qualified
prepare-applying
prepared
quiescence-proving
quiescent
replacement-validating
replacement-validated
select-applying
selected-disabled
canary-applying
canary-active
enable-applying
enabled
complete
candidate-rejected
```

Rules:

- `current` may advance only after observing a strictly newer release.
- A different candidate or observed release cannot replace a nonterminal
  journal. A cadence observation during a nonterminal phase is read-only and
  cannot alter the active journal or public status; the latest official
  release is re-observed after the generation terminates.
- Every `*-applying` phase records the exact candidate and the digest of the
  request/directive binding, enrollment binding, and control sequence, but
  never the response MAC. The same request/directive digest cannot appear on
  two effect phases.
- On restart, an applying phase first calls the matching inspection or probe.
  Proven complete advances; proven absent retries only under a new matching
  directive; ambiguous remains applying and returns a typed recoverable error.
- `candidate-rejected` is terminal for that exact candidate tuple and never
  carries selection authority. A new operation generation may start only
  after read-only observation proves either a strictly newer official release
  or a different attested candidate tuple for the same still-newer release;
  the selected tuple must be unchanged and no directive/effect authority is
  inherited. Reoffering the identical rejected tuple performs no effect.
- `selected-disabled` requires read-back of the exact qualified tuple while
  acquisition remains disabled. Its public status is already `current` with
  observed/selected equal to the qualified tuple and all candidate fields nil;
  rollback identities remain only in the private journal/selection proof.
- `canary-active` requires mode `canary-only`, capacity one, and the exact
  directive policy digest.
- `enabled` requires mode `enabled`, the configured capacity, and the exact
  directive policy digest.
- `complete` requires a fresh `complete` directive but performs no effect.
- `complete` returns to a fresh `current` journal generation only after exact
  selection/current-status read-back. That generation has no candidate or
  prior directive authority and can begin the next forced-bump cycle.
- Journal generation and observation sequence increase without wraparound.
- Canonical validation rejects missing, extra, forbidden-for-phase, stale, or
  cross-phase fields before any store write.

The public status projection is closed:

| Journal phase | `RunnerReleaseStatus.state` | Candidate fields |
| --- | --- | --- |
| `current` | `current` | all nil |
| `upgrade-required` through `qualify-applying` | `upgrade-required` | all nil |
| `candidate-qualified` through `select-applying` | `candidate-qualified` | exact qualified tuple |
| `selected-disabled` through `complete` | `current` | all nil |
| `candidate-rejected` | `candidate-rejected` | exact rejected tuple where known |

Every published projection increments and persists `observationSequence`.
Publication uses only journal/selection-derived fields. Phase 3 heartbeat
integration consumes this validated DTO later; Phase 2 does not add
job-controlled release fields to `health.Snapshot`.

## Task 0: Freeze Closed Models and Tuple Validation

**Files:**

- Create: `internal/upgrade/model.go`
- Create: `internal/upgrade/model_test.go`

**Interfaces:**

- Produces every closed value type in the Canonical Interfaces section.
- Produces `CompareRunnerVersions(left, right string) (int, error)`.
- Produces canonical evidence digest helpers private to `internal/upgrade`.

- [ ] **Step 1: Write RED version tests**

  Table-test valid equality/order across component-width boundaries such as
  `v2.9.0 < v2.10.0`, and reject bare, signed, leading-zero, partial,
  prerelease, metadata, whitespace, overflow, or newline forms.

- [ ] **Step 2: Run the version RED test**

  Run:

  ```bash
  GOTOOLCHAIN=go1.26.5 go test ./internal/upgrade \
    -run 'TestCompareRunnerVersions' -count=1
  ```

  Expected: compile failure because `internal/upgrade` and
  `CompareRunnerVersions` do not exist.

- [ ] **Step 3: Implement only numeric parsing and comparison**

  Parse three unsigned components manually with checked multiply/add. Do not
  use lexical comparison or a permissive semantic-version library.

- [ ] **Step 4: Write RED model-shape tests**

  Exercise every valid `RunnerReleaseStatus` state and mutate each field to
  prove cross-state candidate fields, uppercase digests, equal/older
  candidates, zero sequence, zero time, false compatibility bit, nonzero
  quiescence count, or unsafe retained-ledger state is rejected. Freeze the
  exact camelCase `RunnerReleaseStatusV1` JSON vector. Mutate every
  runtime-manifest, release-manifest, attestation, provenance, listener,
  disable-update, host-probe, and reclamation digest and prove the
  compatibility evidence binding changes or validation fails.

- [ ] **Step 5: Implement closed validation and digesting**

  Use domain-separated SHA-256 encodings with fixed field order and length
  prefixes. Do not hash `fmt` output, maps, raw provider documents, or local
  paths.

- [ ] **Step 6: Run model tests**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test ./internal/upgrade \
    -run 'Test(CompareRunnerVersions|RunnerRelease|Candidate|Compatibility|Quiescence|RunnerReleaseStatus)' \
    -count=1
  ```

  Expected: PASS.

## Task 1: Observe the Exact Official Runner Release

**Files:**

- Create: `internal/upgrade/runner_release.go`
- Create: `internal/upgrade/runner_release_test.go`

**Interfaces:**

- Consumes fixed `https://api.github.com/repos/actions/runner` endpoints.
- Produces `RunnerReleaseObserver` and `RunnerRelease`.

- [ ] **Step 1: Write a RED happy-path HTTP contract test**

  Use a real `httptest.Server` behind an injected test-only transport. Require
  the observer to request:

  1. `/repos/actions/runner/releases/latest`
  2. `/repos/actions/runner/git/ref/tags/<escaped exact tag>`
  3. `/repos/actions/runner/git/tags/<tag-object-sha>` only for an annotated
     tag

  The fixture has one Linux x64 asset with an official digest. Assert the
  returned tag ref, peeled source commit, asset name/size/digest, publication
  time, and evidence digest.

- [ ] **Step 2: Verify RED**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test ./internal/upgrade \
    -run 'TestOfficialRunnerReleaseObserverHappyPath' -count=1
  ```

  Expected: failure because the observer is absent.

- [ ] **Step 3: Implement bounded observation**

  Require a caller deadline. Add a tighter internal per-request deadline,
  fixed Accept/API-version/User-Agent headers, bounded response bodies,
  canonical path escaping, no redirect, duplicate-known-field/trailing-token
  rejection, exactly one tag object peel, and exact status codes. Ignore
  bounded additive unknown GitHub API fields so a harmless upstream schema
  addition cannot wedge automatic release observation; unknown fields never
  enter evidence or authority.

- [ ] **Step 4: Write RED rejection tables**

  Cover draft, prerelease, malformed/older/equal tag when a newer observation
  is required, changed tag name, non-tag ref, nested annotated tag, uppercase
  object SHA, zero/negative/overflow asset size, missing/uppercase/wrong-length
  digest, duplicate Linux x64 asset, wrong architecture, wrong asset version,
  duplicate known release fields, redirect, oversized body, cancellation,
  timeout, and response after context cancellation. Add one positive fixture
  with bounded unknown GitHub fields to freeze additive compatibility.

- [ ] **Step 5: Implement fail-closed rejection**

  Return only typed identity-free errors. Do not include a response body, URL,
  path, tag supplied by an untrusted server, or raw HTTP error in public text.

- [ ] **Step 6: Run observer tests and race**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test -race ./internal/upgrade \
    -run 'TestOfficialRunnerReleaseObserver' -count=10
  ```

  Expected: PASS with no leaked goroutine or request after cancellation.

## Task 2: Seal the Maintenance Directive Contract

**Files:**

- Create: `internal/upgrade/directive.go`
- Create: `internal/upgrade/directive_test.go`

**Interfaces:**

- Produces the exact Phase 3 status request and directive field set.
- Produces `ParseVerifiedRunnerMaintenanceDirective`.
- Produces `UnavailableMaintenanceDirectiveProvider`.

- [ ] **Step 1: Write RED canonical-vector tests**

  Freeze byte-exact JSON vectors for the request and every directive phase.
  Freeze the response frame with `responseMac` omitted. The verifier test
  double must receive those exact bytes once.

- [ ] **Step 2: Verify RED**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test ./internal/upgrade \
    -run 'TestMaintenanceDirectiveCanonical' -count=1
  ```

  Expected: compile failure because the parser and vectors are absent.

- [ ] **Step 3: Implement strict parse and verification**

  Enforce exact field order by canonical re-marshal equality, reject duplicate
  and unknown fields, require exact protocol strings, and verify the response
  frame before setting private directive authority.

- [ ] **Step 4: Write RED cross-binding and phase tests**

  Mutate epoch, session, control sequence, requested selected/candidate
  digest, transition epoch, permit generation, qualified tuple, config
  revision, policy digests, expiry, phase, and MAC. Test nil/non-nil qualified
  fields for every phase and prove a direct struct literal is unusable. Freeze
  candidate-digest construction before and after select, same-session
  sequence monotonicity, newer-enrollment reset, replay rejection, and
  single-use directive binding across adjacent phases.

- [ ] **Step 5: Add service-facing validation**

  Add a private `authorize(request, now, expectedPhase, expectedTuple)` method
  that requires exact request equality, private verified authority,
  `now < expiresAt`, and a bounded future expiry. It returns an opaque
  authorization usable only inside `internal/upgrade`.

- [ ] **Step 6: Add the unavailable provider**

  `UnavailableMaintenanceDirectiveProvider.Current` always returns
  `ErrMaintenanceUnavailable` and a zero directive. It performs no I/O.

- [ ] **Step 7: Run directive tests**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test -race ./internal/upgrade \
    -run 'Test(Maintenance|UnavailableMaintenance)' -count=20
  ```

  Expected: PASS.

## Task 3: Add the Canonical Crash-Resume Journal and Secure Store

**Files:**

- Create: `internal/upgrade/journal.go`
- Create: `internal/upgrade/journal_test.go`
- Create: `internal/upgrade/store.go`
- Create: `internal/upgrade/store_unix.go`
- Create: `internal/upgrade/store_other.go`
- Create: `internal/upgrade/store_test.go`

**Interfaces:**

- Produces `Journal`, `JournalPhase`, strict marshal/parse/transition helpers.
- Produces `JournalStore`, `JournalLease`, and
  `OpenFileJournalStore(StoreConfig)`.

- [ ] **Step 1: Write RED phase-vector tests**

  Build one valid journal for every phase in the Journal State Machine.
  Freeze its canonical JSON and domain-separated digest. Reject skipped,
  reversed, repeated-with-different-data, candidate-substitution, sequence
  rollback, generation wrap, selection-before-qualification, policy-before-
  selection, and complete-before-enabled transitions. Add full transition
  vectors for rejected exact tuple -> different same-release candidate,
  rejected -> strictly newer release, complete -> fresh current, and then a
  second forced bump. Reject identical rejected-tuple reentry, nonterminal
  observed-release substitution, enrollment/session drift, reused control
  sequence, and one directive digest on two effect phases.

  Table-test the public status projection for every journal phase. In
  particular, prove `selected-disabled` immediately projects `current` with
  the new selected tuple and nil candidate fields while rollback remains
  private.

- [ ] **Step 2: Verify RED**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test ./internal/upgrade \
    -run 'TestJournal' -count=1
  ```

  Expected: failure because the journal is absent.

- [ ] **Step 3: Implement the journal codec**

  Use strict canonical JSON with no maps. Phase validation requires exactly the
  fields permitted in that phase and forbids later evidence. Store no response
  MAC, raw directive, provider error, release JSON, command, path, or secret.

- [ ] **Step 4: Write RED Unix store tests**

  In `t.TempDir`, pre-create a mode-0700 private root. Test:

  - stable mode-0600 lock creation only when `Bootstrap` is true
  - no implicit private-root creation
  - deadline-aware 10 ms nonblocking `flock` polling
  - single-writer lease exclusion
  - absent/read/create/CAS-replace/read-back
  - wrong expected bytes and concurrent writer conflict
  - root/lock/journal symlink, hard link, mode, owner, type, inode, and
    directory-replacement rejection
  - temp-file cleanup after every injected write/fsync/rename failure
  - file and directory fsync before success
  - journal read after a new store instance simulates controller restart

- [ ] **Step 5: Implement the Unix store**

  Open the caller-provided absolute root with
  `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`; require current EUID ownership and mode
  0700. Open all children descriptor-relative. Write one private temp, fsync,
  compare the exact expected document under the exclusive lease, rename,
  fsync the root, and read back. Never follow, create, or remove an unexpected
  object.

- [ ] **Step 6: Implement unsupported-platform failure**

  Non-Darwin/non-Linux constructors and methods return `ErrJournalStore`
  without creating anything.

- [ ] **Step 7: Run journal/store tests and race**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test -race ./internal/upgrade \
    -run 'Test(Journal|FileJournalStore)' -count=20
  ```

  Expected: PASS.

## Task 4: Implement Observation, Disable, Stage, and Qualification

**Files:**

- Create: `internal/upgrade/service.go`
- Create: `internal/upgrade/service_test.go`

**Interfaces:**

- Produces `New`, all canonical `Upgrade` methods, and
  `ReconcileRunnerRelease`.
- Consumes `controller.LiveAdmin`, `JournalStore`, `RunnerReleaseObserver`,
  `SelectionSource`, `CandidateSource`, `CandidateRuntime`,
  `MaintenanceRequestSource`, and `ReleaseStatusPublisher`.

- [ ] **Step 1: Write RED constructor and authority-surface tests**

  Reject nil dependencies, missing deadlines, invalid configured canary scale
  set, zero configuration revision, invalid operation timeout, invalid drain
  policy, mismatched canary/enabled policy digest, and a store that cannot
  acquire/read. Reflect over production interfaces and fail if they expose a
  route writer, shell, argv, environment, arbitrary image name, delete-current,
  delete-rollback, fence handoff, or secret field. Call every exported
  primitive directly without an internal phase capability and prove zero
  LiveAdmin/CandidateRuntime effects.

- [ ] **Step 2: Verify RED**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test ./internal/upgrade \
    -run 'TestUpgrade(Constructor|AuthoritySurface)' -count=1
  ```

  Expected: failure because `Upgrade` is absent.

- [ ] **Step 3: Implement read-only observation and status**

  With the journal lease held:

  1. read current immutable selection
  2. observe the official release
  3. compare numerically
  4. persist `current` or `upgrade-required`
  5. publish an exact `RunnerReleaseStatus`

  An equal release publishes `current`; a newer release journals
  `upgrade-required`. An older, rolled-back, or invalid release returns a
  typed observation/integrity error, leaves the prior journal and published
  status unchanged, and performs no candidate or acquisition effect.
  `candidate-rejected` is reserved for a strictly newer observed release whose
  exact candidate later fails permanent qualification.

  If the journal is already nonterminal, still run the bounded release
  observation on cadence, but keep the journal-bound observed release and
  status projection unchanged. Re-observe the latest release only after the
  generation reaches `candidate-rejected` or `complete`. Test bumps during
  staging, replacement, canary, enable, and after restart from every applying
  phase.

- [ ] **Step 4: Write RED stage-authority tests**

  Prove:

  - candidate observation is read-only and may be journaled without a
    directive
  - unavailable or `wait-hosted` provider makes zero admin/runtime calls
  - `stage-permitted` with any mismatch makes zero calls
  - one reconciliation call performs only `disable-applying` plus the exact
    disabled transition
  - the next call requires a new control sequence/directive before
    `stage-applying`
  - the next call requires another new directive before `qualify-applying`
  - intent is persisted before each effect
  - a crash after intent resumes by exact read-back and never skips ahead
  - a changed candidate, selection, config revision, or policy digest is
    rejected
  - repeated control sequence, stale candidate digest, or the same directive
    binding on two phases makes zero calls
  - direct exported primitive calls without the unexported phase capability
    make zero calls

- [ ] **Step 5: Implement disable and stage**

  For disable, call `LiveAdmin.Probe`, persist intent, then call
  `SetAcquisition(Set=disabled, Expected=<exact current mode>)`. Read back and
  require disabled, capacity zero, a newer epoch, and a structurally valid
  read-back policy digest. The maintenance wire contract does not carry a
  disabled-policy digest, so the service must not invent or infer one from the
  canary/enabled digest fields.

  For stage, call only `CandidateRuntime.Stage(exactCandidate)`, then
  `InspectStage(exactCandidate)`. Require the exact manifest/image/release
  tuple and no partial live selection. Permanent candidate identity rejection
  records `candidate-rejected`; transient unavailability remains
  `stage-applying`; ambiguous or partial effects remain applying for exact
  read-back.

- [ ] **Step 6: Implement qualification**

  Call `QualifyRunnerCandidate` only from `qualify-applying`. Require every
  compatibility bit, tuple field, evidence digest, and time. Permanent
  incompatibility records terminal `candidate-rejected`; transient
  unavailability leaves the applying phase recoverable. Publish
  `candidate_qualified` only after the journal stores the exact report. Bind
  and compare the full runtime/release/provenance/probe digest set rather than
  trusting booleans alone.

- [ ] **Step 7: Run stage/qualification tests**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test -race ./internal/upgrade \
    -run 'TestUpgrade(Observe|Stage|Qualify|ResumeStage)' -count=30
  ```

  Expected: PASS with one effect per exact phase.

## Task 5: Implement Replacement, Canary, Enable, and Completion

**Files:**

- Modify: `internal/upgrade/service.go`
- Modify: `internal/upgrade/service_test.go`

**Interfaces:**

- Completes the remaining `Upgrade` methods and journal phases.

- [ ] **Step 1: Write RED replace-permitted tests**

  Require a fresh matching `replace-permitted` directive separately before:

  1. `Prepare` and exact drain
  2. `ProveQuiescent`
  3. `ValidateReplacement`
  4. atomic `Select`

  Each reconciliation call performs exactly one item. Test both `DrainWait`
  and `DrainCancel` from explicit config; a caller-supplied mismatch is
  rejected. Require zero listeners, runners, adapters, both broker classes,
  helpers, verifiers, per-job socket directories, dials, and pending effects,
  with retained ledgers safe. Add same-session control-sequence replay and
  fresh-enrollment tests for every replace phase.

- [ ] **Step 2: Verify RED**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test ./internal/upgrade \
    -run 'TestUpgradeReplace' -count=1
  ```

  Expected: failure because replacement phases are absent.

- [ ] **Step 3: Implement prepare/quiescence/validation**

  `Prepare` delegates only to `LiveAdmin.Drain` with the config-bound policy.
  `Drain` is the idempotent drain-to-zero primitive even though acquisition
  was already disabled: its internal disabled-to-disabled transition may
  advance the epoch and is not compared to canary/enabled policy digests.
  `prepare-applying` restart obtains a fresh directive and calls `Drain`
  again; successful return is the proof of zero running jobs and zero
  unassigned released listeners. Fatal/ambiguous policy remains applying and
  advances nothing.

  `ProveQuiescent` is a separate, broader runtime proof and cannot be inferred
  from `Drain` success. It validates all component, dial, socket, pending-
  effect, and retained-ledger evidence. `ValidateReplacement` re-runs and
  re-binds the full exact runtime/release/provenance/probe digest set after
  quiescence. Any changed tuple or digest returns integrity-fatal and leaves
  selection unchanged.

- [ ] **Step 4: Implement atomic selection and read-back**

  Persist `select-applying`, call `CandidateRuntime.Select(exactCandidate)`,
  then `InspectSelection`. Require selected version/manifest/image equal the
  qualified tuple, the previous immutable selection retained as rollback, and
  acquisition still disabled. A partial, changed, or ambiguous selection
  remains applying and cannot reach canary; a proven permanent candidate
  identity rejection records `candidate-rejected` without deleting either
  immutable identity.

  After exact selection read-back, persist `selected-disabled` and publish
  `RunnerReleaseStatus{state=current}` with observed/selected equal to the
  qualified tuple and all candidate fields nil. The private journal retains
  rollback and compatibility evidence, but public `candidate-qualified`
  authority ends at selection.

- [ ] **Step 5: Write RED canary/enable tests**

  Require fresh `canary-permitted` and `enable-permitted` directives. For
  canary, call:

  ```go
  SetAcquisition(AcquisitionChange{
      Set:              AcquisitionCanaryOnly,
      Expected:         AcquisitionDisabled,
      EligibleScaleSet: configuredCanaryScaleSet,
  })
  ```

  Require mode canary-only, capacity one, newer epoch, and exact directive
  policy digest. For enable, require expected canary-only, configured enabled
  policy, newer epoch, configured capacity, and exact enabled digest.

- [ ] **Step 6: Implement canary/enable/complete**

  Persist applying intent before each policy call and read back after it.
  `complete` validates a fresh complete directive and publishes status only.
  It does not call admin, runtime, selection, route, or store cleanup. On the
  next reconciliation, exact current selection/status read-back creates a
  fresh `current` generation with no candidate or directive authority.

- [ ] **Step 7: Add interruption and precedence tests**

  For every applying and proven phase, create a new `Upgrade` with the same
  store and re-run. Inject context cancellation before intent, after intent,
  during effect, and before read-back. Assert:

  - no later effect
  - no candidate substitution
  - no rollback digest deletion
  - no old-image selection
  - no acquisition restore after error
  - cleanup/read-back error takes precedence over provider text
  - a subsequent `wait-hosted` directive performs zero effects
  - fatal acquisition remains applying and performs no later effect
  - `prepare-applying` safely re-runs the config-bound drain after restart
  - selected/current status and rollback-private identity remain exact
  - `candidate-rejected` and `complete` re-enter only under the terminal-exit
    rules, including a second forced bump

- [ ] **Step 8: Run the full upgrade package repeatedly**

  ```bash
  GOTOOLCHAIN=go1.26.5 go test -race ./internal/upgrade -count=50
  ```

  Expected: PASS.

## Task 6: Add Opt-In Chaos Recovery Coverage

**Files:**

- Create: `tests/chaos/controller_states_test.go`
- Create: `tests/chaos/docker_failure_test.go`
- Create: `tests/chaos/jail_failure_test.go`
- Create: `tests/chaos/fleet_fence_test.go`
- Create: `tests/chaos/qts_install_test.go`

**Interfaces:**

- Uses only public production interfaces and test-local fake targets.
- Does not add a production chaos or arbitrary fault-injection API.

- [ ] **Step 1: Write the opt-in boundary first**

  Every file has `//go:build chaos`. A shared test helper requires Linux,
  Docker availability, and `PGHAR_CHAOS_DOCKER=1`; otherwise it emits the exact
  skip reason `SKIP unsupported host profile`. Structural source tests verify
  that the opt-in gate cannot be mistaken for a pass.

- [ ] **Step 2: Add controller-state restart tables**

  Recreate the service and store after every journal phase. Inject termination
  before/after persistence and effect read-back. Assert no duplicate
  stage/select/policy effect, no phase skip, monotonic journal generation, and
  disabled acquisition on ambiguity.

- [ ] **Step 3: Add Docker/component failure tables**

  Stop/restart the test Docker service; kill/delay the adapter, held/released
  broker, helper, verifier, and listener around existing closed lifecycle
  ports. Prove no second runner/listener/broker, exact whole-container cleanup,
  and no `_work/_update` or dual runner payload.

- [ ] **Step 4: Add jail/permit failure tables**

  Corrupt or roll back only test-local permit, clock, token-ledger, conntrack,
  FD, socket, and namespace evidence. Race policy narrowing and host-pressure
  stop against dials. Prove no dial without durable consumption, no token
  refill after restart, and zero release on missing policy/socket/namespace
  proof.

- [ ] **Step 5: Add fleet-fence race tables**

  Race portable/legacy acquisition, old/new watchdog cycles, and handoff
  boundaries with the real file-backed fence in a private temporary root.
  Assert one active fleet, never-decrementing generation, and disabled observer
  recovery.

- [ ] **Step 6: Add QTS lifecycle compensation tables**

  Use the existing host-runtime lifecycle engine against a test-local QTS
  sandbox. Fail install/suspend/resume/rollback/uninstall before and after
  every journaled effect and read-back. Assert forward resume or one closed
  compensation path without raw fence rollback.

- [ ] **Step 7: Cross-compile before target execution**

  ```bash
  GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.5 \
    go test -c -tags=chaos ./tests/chaos \
    -o /private/tmp/portable-ghar-chaos.test
  ```

  Expected: compile succeeds. This is source readiness, not chaos execution.

- [ ] **Step 8: Reserve the actual Linux Docker command**

  On a separately approved supported target:

  ```bash
  PGHAR_CHAOS_DOCKER=1 GOTOOLCHAIN=go1.26.5 \
    go test -tags=chaos ./tests/chaos -v -count=10
  ```

  Until that operator-gated execution occurs, report this gate as pending and
  do not claim Task 12 operational completion.

## Task 7: Write Exact Upgrade, Recovery, and Release Runbooks

**Files:**

- Create: `docs/operations/controller-upgrade.md`
- Create: `docs/operations/controller-recovery.md`
- Create: `docs/operations/runner-release.md`
- Modify: `docs/operations/production-lifecycle.md`

- [ ] **Step 1: Add documentation contract tests first**

  Extend the existing repository documentation tests to require all three
  files and the headings below. Run the focused test and observe failure before
  creating the runbooks.

- [ ] **Step 2: Write `controller-upgrade.md`**

  Required sections:

  - immutable selected/candidate/rollback identities
  - hosted hold and exact directive sequence
  - non-admin QTS build prohibition
  - prebuilt attested-image preference
  - listener version smoke proof before selection
  - idle legacy runner drain by absence of `Runner.Worker`
  - operation journal and applying-phase recovery
  - no live-host commands without a separately approved execution packet

- [ ] **Step 3: Write `controller-recovery.md`**

  Required sections:

  - `status --json`, journal, fence header/holders, and controller/watchdog
    read-back
  - ambiguity classification and acquisition-disabled invariant
  - observer-mode dark startup
  - journaled compensation without fence rollback
  - hosted confirmation before recovery
  - rollback as control-plane restoration, never incompatible runner
    downgrade
  - retained state and evidence handling

- [ ] **Step 4: Write `runner-release.md`**

  Required sections:

  - automatic normal path versus break-glass
  - official observation and immutable candidate qualification
  - all six maintenance response phases
  - fail-closed retry behavior
  - operator-hold precedence
  - forced-version-bump continuity
  - whole-container reclamation rather than serving-runner file deletion
  - bounded immutable candidate/rollback storage
  - Phase 3 and Task 14 dependencies before unattended operation

- [ ] **Step 5: Preserve the approved observability contract**

  Add only links and phase references to
  `docs/operations/production-lifecycle.md`. Keep GitHub API workload state
  authoritative, preserve zero-idle semantics, and keep the InfluxDB path
  one-way/read-only.

- [ ] **Step 6: Run documentation verification**

  ```bash
  python3 -m unittest tests.repository.test_docs_contract -v
  npm run lint:docs
  npx prettier --check \
    docs/operations/controller-upgrade.md \
    docs/operations/controller-recovery.md \
    docs/operations/runner-release.md \
    docs/operations/production-lifecycle.md
  node scripts/docs/check-links.mjs
  ```

  Expected: PASS.

## Task 8: Verify, Review, and Create the Signed Task 12 Checkpoint

**Files:**

- All Task 12 files above, and only test-driven corrections to named existing
  boundaries.

- [ ] **Step 1: Run focused package verification**

  ```bash
  GOTOOLCHAIN=go1.26.5 gofmt -w internal/upgrade tests/chaos
  GOTOOLCHAIN=go1.26.5 go test -race ./internal/upgrade -count=50
  GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.5 \
    go test -c -tags=chaos ./tests/chaos \
    -o /private/tmp/portable-ghar-chaos.test
  ```

- [ ] **Step 2: Run repository verification**

  ```bash
  git diff --check
  GOTOOLCHAIN=go1.26.5 go vet ./...
  GOTOOLCHAIN=go1.26.5 go test ./... -count=1
  GOTOOLCHAIN=go1.26.5 go test -race ./... -count=1
  GOTOOLCHAIN=go1.26.5 go tool staticcheck ./...
  GOTOOLCHAIN=go1.26.5 go tool govulncheck ./...
  python3 scripts/check_workflow_policy.py .github/workflows
  python3 scripts/check_repository_metadata.py --root .
  python3 scripts/sanitize_public.py --tracked
  npm run lint:docs
  npm run format:check
  ```

- [ ] **Step 3: Run the public-safety scan**

  Scan the exact base-to-head diff for private identifiers and run the
  repository sanitizer. The result must be empty/green before review.

- [ ] **Step 4: Seal an exact review artifact**

  Record base commit, staged tree, full-index staged diff bytes and SHA-256,
  plan SHA-256, file count, validation record, and the open Linux/Docker and
  operator sizing/activation gates. The artifact must contain the exact staged
  diff and no private handoff content.

- [ ] **Step 5: Obtain direct distinct-family review**

  Use xAI/Grok before Anthropic/Claude, under the operator-authorized broker
  bypass. Require a substantive matching-digest verdict over:

  - release source and version arithmetic
  - directive authentication and exact binding
  - journal transition and store safety
  - applying-phase crash recovery
  - acquisition barrier and drain behavior
  - quiescence and atomic selection
  - rollback preservation and downgrade prohibition
  - operator-hold and route-authority separation
  - chaos opt-in truthfulness
  - runbook and observability boundaries

  A pre-inference, malformed, mismatched-digest, or non-substantive response
  does not count.

- [ ] **Step 6: Rehash and verify after review**

  Recompute the staged tree, full-index diff digest, artifact digest, worktree
  status, and focused/full tests. Any code or documentation change invalidates
  the prior review and requires a new artifact.

- [ ] **Step 7: Create the signed checkpoint**

  Stage exact paths only and run:

  ```bash
  git commit -S -m "test: harden reconciliation and upgrade recovery"
  ```

  Verify the cryptographic signature, no-reply author, commit tree equals the
  reviewed staged tree, and clean worktree.

## Self-Review Checklist

- [ ] Every canonical Task 12 interface has one producing file and test.
- [ ] Official release observation has no caller-controlled production origin.
- [ ] Version comparison is numeric and overflow checked.
- [ ] Directive parsing authenticates before authority and binds every request
      and response field.
- [ ] The default directive provider is unavailable.
- [ ] No route mutation interface exists.
- [ ] Every effect has a preceding applying intent and an exact read-back.
- [ ] One reconciliation call advances at most one external phase.
- [ ] Every phase requires a fresh request and directive.
- [ ] Candidate substitution, downgrade, and rollback deletion are impossible.
- [ ] Canary and enable use only `controller.LiveAdmin`.
- [ ] Quiescence covers every component, dial, per-job socket directory, and
      pending effect while retaining safe ledgers.
- [ ] Health states match the Phase 3 tuple.
- [ ] Journal and store are canonical, bounded, descriptor-relative, and
      crash-resumable.
- [ ] Chaos tests are opt-in and cannot turn an unsupported host into a pass.
- [ ] Runbooks preserve hosted continuity, operator-hold precedence, and the
      live-host hard stop.
- [ ] Numeric sizing and host activation remain open operator gates.
- [ ] No placeholder, live-host value, secret, or private identifier appears.

## Completion Boundary

The Task 12 source checkpoint is complete when the package, journal/store,
source-ready chaos suite, runbooks, exact distinct-family review, repository
verification, sanitizer, and signed commit are complete.

Task 12 is not operationally complete until a separately approved supported
Linux/Docker target runs the chaos suite, Phase 3 supplies the authenticated
Worker maintenance client/state machine, Task 14 supplies the attested
candidate workflow and artifacts, the operator approves numeric sizing, and a
forced-version-bump drill proves hosted continuity, qualification, drain,
selection, canary, enable, rollback preservation, and whole-container
reclamation.
