# Portable-GHAR Task 14 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a fail-closed, reproducible Linux/amd64 runtime-release
pipeline that observes one exact official GitHub Actions runner release,
rehearses all registered Portable-GHAR binaries and production images without
publishing them locally, compares two independent rebuilds, and lets trusted
GitHub workflows attest and publish only a complete immutable release.

**Architecture:** Four Bash entry points own distinct authority. The observer
converts fixed-origin GitHub API evidence into one canonical candidate
manifest and emits nothing when the official release is not strictly newer
than the checked-in baseline. The rehearsal script copies the exact source
commit into a private isolated checkout, applies a closed and count-checked
candidate-pin overlay there, runs the full runtime gate, builds deterministic
Linux binaries and production OCI archives with a pinned BuildKit toolchain,
normalizes SPDX metadata, scans every source/output/image, and atomically
commits one closed artifact tree. The comparator validates both artifact trees
against their manifests, compares all non-image subjects byte-for-byte, and
compares OCI subjects by their canonical manifest/config/layer digest graph
without rewriting either input. The publication helper runs only in a final
trusted hosted job, proves repository release immutability through a separate
administration-read credential, crash-rebinds drafts through a bounded
authenticated release-list scan, and applies only a closed resumable-draft
mutation protocol.

**Tech Stack:** Bash with `set -euo pipefail`, jq, Python 3 standard library
for duplicate-key-safe JSON and domain-separated hashing, Go 1.26.5,
Docker/buildx with an immutable BuildKit image, OCI image archives, Syft SPDX
JSON, Trivy, Bats, actionlint, GitHub artifact attestations, and the existing
Portable-GHAR runtime, sanitization, image-context, and repository-policy
gates.

## Global Constraints

- Authoritative requirements are Task 14 in
  `docs/superpowers/plans/2026-07-11-controller-runtime.md`, Program Task 6 in
  `docs/superpowers/plans/2026-07-11-portable-ghar-program.md`, and the locked
  release/upgrade contracts in
  `docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`.
- This task changes:
  - `scripts/release/observe-runner-release.sh`;
  - `scripts/release/rehearse-runtime.sh`;
  - `scripts/release/compare-runtime-rebuilds.sh`;
  - `scripts/release/publish-runtime-release.sh`;
  - `tests/shell/runner-release.bats`;
  - `tests/shell/runtime-release.bats`;
  - `tests/shell/publish-runtime-release.bats`;
  - `release/manifest.json`;
  - `images/runner/Dockerfile`;
  - `.github/workflows/release.yml`;
  - `.github/workflows/runner-release-candidate.yml`;
  - `scripts/check_workflow_policy.py`;
  - `tests/repository/test_workflow_policy.py`; and
  - `tests/shell/prepare-task6-images.bats`;
  - `tests/shell/prepare-task11-images.bats`; and
  - this implementation plan.
- The runner Dockerfile is an intentional addition to the original Task 14
  file list. Its current `apt-get update` uses moving Debian repositories, so
  no release wrapper or OCI metadata rewrite can make its filesystem content
  reproducible. The Dockerfile must use the same immutable Debian snapshot
  already locked for Portable-GHAR dependency acquisition, remove transient
  package-manager state, and accept the commit-derived
  `SOURCE_DATE_EPOCH`.
- The workflow-policy test is an intentional addition because it currently
  asserts the complete job-id set. A new trusted candidate workflow must be
  registered there instead of weakening or deleting the assertion.
- The workflow-policy checker is an intentional addition because the final
  publication jobs mint one separate `administration:read` installation token
  through the pinned `actions/create-github-app-token` action. The reviewed
  exact action SHA and release comment enter the existing closed pin table;
  no dynamic action reference or general allowlist is introduced.
- The existing Task-6/Task-11 workflow integration tests are updated to prove
  the release workflow reaches those preparations through the isolated
  rehearsal entry point before the full image gate. Candidate substitution
  makes duplicating those preparations in the caller checkout both redundant
  and incorrect.
- No script or workflow changes RhoNAS, QTS, a Docker daemon configuration,
  a launch service, routing, acquisition state, repository runner labels,
  selector state, or broker lifecycle.
- The local scripts never publish. Only the two reviewed GitHub workflows may
  attest or publish, after every build, test, scan, comparison, manifest, and
  sanitizer gate succeeds.
- Release publication has two separate credentials in the final hosted job.
  The job-scoped `GITHUB_TOKEN` retains only `contents:write` release/ref
  authority. A repository-scoped GitHub App installation token carries only
  `administration:read` and is used only to prove the immutable-release
  setting through the fixed GitHub REST endpoint. The app client ID variable,
  private-key secret, app installation, and repository immutable-release
  setting are separate operator configuration gates. This task does not
  create an app, store credentials, or enable/disable the repository setting.
  The live repository check on 2026-07-30 UTC returned `enabled:false`, so the
  checked-in workflow must fail before every release/ref mutation until the
  operator completes those gates.
- The release scripts target Linux/amd64 only. Wrong host architecture, absent
  Docker/buildx support, wrong tool version/digest, or unavailable
  Linux/Docker prerequisites is terminal failure, never a skip or a source-only
  pass.
- This macOS worktree may prove observer behavior, manifest contracts,
  comparison behavior, shell/repository policy, and two deterministic
  cross-compiled Linux binary sets. It cannot produce positive full rehearsal
  or image reproducibility evidence. Those remain explicit deferred
  Linux/Docker gates.
- The checked-in source implementation after Task 14 may be called
  **Phase 2 source complete** only after its signed exact-scope commit, governed
  exact-head review/checks, and merge. It is not **Phase 2 fully verified**.
  Full Linux/Docker rehearsal, two independent full runtime rebuilds, and a
  forced upstream runner-version bump require a later signed evidence PR.
- Runner-release observation cadence is an operator-open numeric decision.
  This task creates `workflow_dispatch` and repository-authorized
  `repository_dispatch`
  entry points but does not invent a cron expression. Automatic scheduling is
  not claimed until the operator approves and configures a cadence.
- Numeric tmpfs, cgroup memory, swap, CPU, concurrency, storage, rebuild
  cadence, and host-memory values remain operator-open. No value is inferred
  from the historical 2,162 MiB high-water observation.
- The release workflow operates only on a signed `v*` tag. The candidate
  workflow operates only on the repository default branch and never checks
  out or executes pull-request code.
- Candidate releases use exactly
  `runner-candidate-vMAJOR.MINOR.PATCH-<64-lowercase-hex-observation-evidence>-<40-lowercase-hex-workspace-source-commit>`.
  This namespace cannot match the product release workflow's `v*` trigger.
  A candidate workflow may not create a `v*`, `latest`, floating, shortened,
  or alternate tag, and the product release workflow rejects candidate-tag
  grammar even if invoked indirectly.
- Candidate failure or rejection publishes nothing and cannot delete, retag,
  mutate, or make unavailable the current or rollback runtime.
- Every remote URL is fixed in source/manifest. Redirects are disabled for the
  GitHub JSON API and tag/object reads. The runner asset transfer may follow
  only the already release-locked GitHub asset redirect validator.
- JSON input is UTF-8, bounded, object-shaped, and duplicate-key rejected.
  Known security fields use exact case-sensitive strings. Unknown fields are
  rejected in Portable-GHAR-authored manifests; additive upstream GitHub API
  fields are ignored only after all required fields are unambiguous.
- Every digest is lowercase hexadecimal; image and upstream asset digests use
  the exact `sha256:<64 hex>` form. No implicit digest algorithm is accepted.
- Output paths must be absolute or resolved canonically under an existing
  non-symlink parent. Targets must not exist. Scripts stage in a sibling
  private directory and atomically rename only after all gates pass.
- Source must be clean before rehearsal. The rehearsal copies the exact `HEAD`
  with local clone semantics that do not hardlink mutable worktree files,
  performs any candidate-pin substitutions only in that private copy, and
  positively removes the copy, downloaded tools, temporary Docker tags,
  builder, and ignored image contexts on every terminal path.
- One workflow rebuild is one fresh hosted job. Rebuild A and rebuild B use
  separate runner VMs, source checkouts, private output roots, private
  `GOCACHE`, private `GOMODCACHE`, private `DOCKER_CONFIG`, distinct BuildKit
  builders, `--no-cache`, and no imported/exported Docker build cache. Neither
  job downloads or restores a cache produced by the other. A third read-only
  job downloads both immutable workflow artifacts and compares them. A
  same-job or shared-cache comparison cannot mint full reproducibility
  evidence.
- Candidate pin substitution is not a general patch engine. The release
  manifest lists an exact path/token/count table. The script first proves all
  old values at all listed sites, proves no protected occurrence exists outside
  the closed allowlist, performs literal replacements, and proves the exact new
  counts. A missing, duplicate, extra, or structurally changed occurrence is a
  hard failure requiring source review.
- The protected identity set is structurally closed by two independent gates:
  Task 13 continues to prove by Go AST that
  `internal/buildinfo.Pins().UpstreamRunner` is the sole production runner pin,
  while the Task 14 substitution table enumerates every baseline-dependent
  assertion/fixture that must change for candidate qualification. Before
  substitution, all tracked source/test files are scanned for each complete
  old and candidate token; occurrences outside the exact table fail. Every
  listed file is also scanned for any runner-version, Linux-x64 asset digest,
  source-commit, or CommandSettings digest value other than its declared old
  value. After substitution, the same sites must contain only the declared new
  values/counts. The full Task 13 gate then rejects any alternate production
  pin source. Generic upgrade-state fixtures that do not assert the baseline
  are explicitly not substitution sites.
- The production fixed pins remain fixed. Candidate substitution exists only
  in the isolated rehearsal checkout and never writes the caller checkout,
  index, branch, or release manifest.
- The upstream observer emits only a strictly newer numeric
  `vMAJOR.MINOR.PATCH` release. Equal exact identity is typed no-candidate.
  Equal version with identity drift, older version, leading zero, suffix,
  overflow, draft, prerelease, missing/duplicate Linux x64 asset, wrong asset
  name, non-UTC publication time, ref mismatch, nested tag, missing digest,
  or oversized asset is terminal failure.
- The canonical candidate runner manifest carries exactly:
  `schema_version`, `version`, `tag_ref_sha`, `source_commit_sha`,
  `linux_x64_asset_name`, `linux_x64_asset_size`,
  `linux_x64_asset_digest`, `published_at`,
  `command_settings_sha256`, and `observation_evidence`.
- `observation_evidence` is byte-compatible with
  `internal/upgrade.runnerReleaseEvidenceDigest`: SHA-256 over the domain
  `portable-ghar-runner-release-observation-v1` and each of the seven
  Task-12 release fields, each framed by an unsigned 64-bit big-endian byte
  length. `command_settings_sha256` is separately bound by the canonical
  candidate-manifest digest.
- The exact source commit is obtained by peeling either one lightweight tag or
  one annotated tag. Nested tags and every other object type are rejected.
  `src/Runner.Listener/CommandSettings.cs` is fetched only from
  `raw.githubusercontent.com/actions/runner/<exact commit>/...`, bounded, and
  hashed before candidate emission.
- Rehearsal transfers the candidate runner archive into a private file before
  applying the source overlay. It independently requires the downloaded byte
  length and SHA-256 to equal the manifest's exact asset size/digest. Only
  those verified bytes may be passed to the patched runtime lock for archive
  validation/extraction. Redirect, size, or digest failure occurs before
  overlay, extraction, build, or subject generation.
- A successful observer writes one canonical newline-terminated JSON object.
  Exact current identity exits with code `3`, writes no output, and leaves a
  pre-existing target impossible because targets must not exist. Every other
  nonzero exit is failure.
- The runtime release manifest retains top-level schema `version: 1` for the
  existing source packager and adds one closed `runtime` object. It registers:
  - platform `linux/amd64`;
  - the baseline runner-release tuple;
  - the Debian snapshot timestamp;
  - exact buildx binary, BuildKit image/index/platform digests, Syft binary,
    and Trivy binary identities;
  - all production command packages;
  - all production images; and
  - the exact candidate-pin substitution path/token/count table; and
  - a closed exact license-exception array.
- Production commands are every shipped `cmd/portable-ghar*` entry point except
  the Task-11 synthetic listener. The rehearsal rejects a missing command, an
  unregistered extra production command, duplicate output name, or package
  path outside `./cmd`.
- Production images are
  `runner`, `network-adapter`, `network-broker-dialer`,
  `network-broker-parser`, `network-helper`, and `network-verifier`.
  `synthetic-listener` is test-only and cannot enter a release artifact.
- Every registered production Dockerfile is enumerated by a hermeticity gate.
  Every `FROM` is either `scratch` or digest pinned; no moving distribution
  index or mutable image reference is allowed; every build receives the same
  commit epoch. The five scratch-final network images already satisfy this
  contract and are tested as explicit invariants. The runner is the sole
  production Dockerfile allowed to perform package acquisition, and only from
  the locked snapshot.
- The runner image uses the immutable Debian snapshot
  `20250101T000000Z`, exact base digest already in `buildinfo.Pins`, HTTPS
  snapshot sources, disabled expiry only for that immutable historical
  snapshot, and a closed package-name list. Moving `deb.debian.org` or
  `security.debian.org` sources are forbidden in the build stage.
- Go binaries use `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`,
  `GOTOOLCHAIN=go1.26.5`, `-trimpath`, `-buildvcs=false`, an empty build ID,
  stripped symbols, and exact `internal/buildinfo` version/commit ldflags.
  `SOURCE_DATE_EPOCH` comes from the exact source commit; wall clock is never a
  fallback.
- Buildx is installed in a private `DOCKER_CONFIG`. It creates one
  transaction-named builder backed by the immutable BuildKit Linux/amd64
  digest. OCI exports use `provenance=false`, `sbom=false`, and
  `rewrite-timestamp=true` only for the reproducibility build; GitHub's
  trusted workflow later produces artifact attestations for the exact files.
- Every production image build receives the same `SOURCE_DATE_EPOCH`, target
  platform, and deterministic reference. Mutable base or builder tags without
  digest are forbidden.
- Rehearsal runs `scripts/test-controller-runtime.sh --full` with both explicit
  Docker opt-ins, prepares Task-5/6/11 test contexts, and rejects any
  operational skip. The Task-11 image may exist only during the gate and is
  never copied into release output.
- Before image publication, the runner context and built image prove:
  `Runner.Listener --version` equals the candidate version; exactly one runner
  payload exists; `bin`, `externals`, `_work`, and `_update` have no
  old-version/update-staging siblings; and the runtime/tree locks match.
- Each image is exported as one OCI archive and scanned by the exact pinned
  Trivy binary. The source checkout and completed output tree are also scanned
  for vulnerabilities and secrets. A scan error is failure, not absence of
  findings. Trivy's live vulnerability/secret databases are explicitly a
  non-hermetic, fail-closed admission gate, not a reproducibility subject or
  proof: each rehearsal uses one fresh private cache, records no DB bytes in
  release output, never soft-fails or skips an update error, and never labels
  a scan pass as byte-reproducibility evidence.
- Each binary and image receives one normalized SPDX 2.3 JSON SBOM. Only the
  document creation time/namespace and unordered arrays are normalized from
  Syft output; package/file/license/evidence content is never deleted or
  rewritten. Normalization uses the commit epoch and artifact digest, rejects
  unknown top-level schema drift, and produces canonical sorted JSON.
- Third-party notices are derived deterministically from the normalized SBOMs
  and the checked-in dependency locks. Missing, unknown, or `NOASSERTION`
  licensing for a shipped package is terminal unless the checked-in manifest
  carries a reviewed exact exception. An exception has exactly
  `subject`, `purl`, `version`, `license_expression`, and nonempty `reason`;
  wildcards, empty versions, package-name-only matching, unknown keys, and
  subject/package/version/license drift are rejected.
- Release authority is an acyclic four-layer graph. First, the primary subjects
  are the registered binaries, OCI archives, normalized SBOMs, notices, and
  `runner-release.json`. A `product` rehearsal additionally includes the
  deterministic source archive and its normalized SBOM in this same primary
  layer; a `candidate` rehearsal must omit both. The explicit `release_kind`
  and its exact primary-subject registry are closed fields in
  `runtime-release.json`, so the product source+runtime union is one authority
  DAG rather than two loosely joined release sets. Second,
  `runtime-release.json` binds source
  commit/tree, version, runner-manifest digest, platform, tool identities, and
  every primary subject's name/type/size/SHA-256; for OCI images it also binds
  the canonical index/manifest/config/layer digest graph. Third,
  `checksums.txt` binds every primary subject plus `runtime-release.json`, in
  bytewise filename order. Fourth, `provenance-subjects.json` binds that same
  checksums subject set plus `checksums.txt`, but never itself. The workflow
  attests exactly the paths listed in `provenance-subjects.json` plus
  `provenance-subjects.json`. This ordering has no self-reference or
  checksum/manifest fixed-point; omission, reordering, or a backward edge is
  failure.
- `checksums.txt` has one and only one UTF-8 line per checksums subject:
  `<64 lowercase hex><two ASCII spaces><safe relative path><LF>`. Paths use
  `/`, have no whitespace/control/backslash/traversal component, are unique,
  bytewise sorted, and the file has exactly one final newline.
  `provenance-subjects.json` is canonical compact sorted-key JSON plus one
  newline with exactly `schema_version` and `subjects`; each bytewise
  path-sorted subject has exactly `path`, `sha256`, and integer `size`.
  Unknown fields, duplicate paths/keys, noncanonical bytes, or membership that
  is not exactly the checksums set plus `checksums.txt` are failure.
- The existing public sanitizer scans every text authority, normalized SBOM,
  and notice after manifest/checksum generation. The set is enumerated and
  exact: `runner-release.json`, `runtime-release.json`, `checksums.txt`,
  `provenance-subjects.json`, `notices/THIRD-PARTY-NOTICES.txt`, and every
  registered `sbom/*.spdx.json`; no other text path is permitted. It is not
  used as an implicit dynamic allowlist for opaque binaries, the product
  source archive, or OCI archives: those are scanned in full by the exact
  pinned Trivy binary, and the release validator separately enforces their
  registered identity, byte digest, ELF/OCI/archive shape, embedded-path/time
  constraints, and closed archive graph. A secret-shaped token, local path,
  private identifier, unsupported or unenumerated text authority, Trivy error,
  or Trivy finding is failure.
- The comparator opens both trees read-only, rejects symlinks, devices,
  sockets, hard links, unexpected paths, mutable permissions, manifest drift,
  missing subjects, size/digest mismatch, and differing source/runner/tool
  identity. It never invokes a formatter, scanner, Docker, or writer.
- Non-OCI subjects compare byte-for-byte. OCI archives are read without path
  extraction; `index.json` and digest-addressed blobs must form one closed,
  acyclic, all-sha256 graph. Comparison is by canonical index, manifest,
  config, and ordered layer digests. Unreferenced blobs, duplicate descriptors,
  unsafe tar entries, multiple platforms, or foreign URLs are rejected.
- For each tree independently, the comparator first proves that every parsed
  OCI index/manifest/config/layer graph equals that tree's
  `runtime-release.json` graph claim. Only after both trees are internally
  self-consistent may it compare their graphs to each other.
- The candidate workflow uses bounded retries only around fixed-origin
  observation/asset acquisition. It never retries a validation, test, scan,
  digest, compatibility, or publication failure.
- Candidate release tag/name is a pure function of runner version, the full
  observation-evidence digest, and the admitted full workspace source commit;
  it must match only the disjoint `runner-candidate-*` grammar above. Product
  title/body bytes are exactly `portable-ghar <bare-version>` and the fixed
  release sentence in the workflow. Candidate title/body bytes are exactly
  `portable-ghar runner candidate <v-version>` and the fixed sentence binding
  that version and observation evidence. No run ID, time, locale, environment,
  iteration order, or other mutable input enters release metadata. Both release
  create and publish requests set the exact API string `make_latest:"false"`;
  neither product nor candidate publication may mutate the repository's
  implicit latest-release pointer.
- Publication is interruption-safe and compatible with GitHub immutable
  releases. A fresh publication creates an exact **draft** release through the
  REST API, uploads subjects to that exact numeric draft release ID, verifies
  the complete draft by freshly read asset IDs and bytes, then performs the one
  permitted metadata transition on that same release ID with the exact body
  `{"draft":false,"make_latest":"false"}`. The create body likewise contains
  `draft:true`, `prerelease:false`, and `make_latest:"false"` plus only the
  exact bound tag/title/body/target fields. GitHub release immutability applies
  only after publication, so an interrupted create/upload remains a resumable
  draft rather than a poisoned partial immutable release.
- Repository immutability is a mandatory pre-mutation authority, not an
  assumption inferred from the release response. The helper receives the
  job-scoped contents-write token only through `PGHAR_RELEASE_TOKEN` and a
  separate GitHub App installation token only through
  `PGHAR_RELEASE_SETTINGS_TOKEN`; neither is accepted on argv. Before any
  remote call, both variables must exist, contain at least one non-whitespace
  byte, and differ byte-for-byte. Missing, blank, equal, or cross-wired tokens
  are terminal with no request. Credential-specific request functions are
  structurally separate: the settings token can issue only the one fixed
  immutable-settings GET, while the release token can never call that endpoint
  and is the sole credential for release, ref, and asset reads or mutations.
  Before candidate-ref creation,
  draft creation, starter deletion, every one-asset upload, and the publish
  edit, the helper sends one redirect-disabled, duplicate-key-safe
  `GET https://api.github.com/repos/<owner>/<repo>/immutable-releases` with
  exact API version `2026-03-10` and requires status 200 plus JSON boolean
  `enabled:true`. A 200 `enabled:false` response, 404, permission error,
  malformed/ambiguous response, non-boolean value, redirect, or transport
  failure is terminal before that mutation. `enforced_by_owner` must be a
  boolean when present but either value is accepted; it is observed only as
  configuration provenance and never weakens the enabled requirement. The
  helper never calls the enable/disable endpoints. The same check is repeated
  immediately before `draft:false`; the unavoidable administrator-setting
  race remains an explicitly frozen operator configuration boundary for a
  release run rather than hidden as atomic API behavior.
- GitHub documents the tag-name endpoint as returning a **published** release,
  so it cannot rebind an interrupted draft and is not used as an absence or
  draft authority. Every release-level observation instead performs a fresh,
  authenticated, exhaustive list scan at the source-constant endpoint
  `https://api.github.com/repos/<owner>/<repo>/releases` using the
  contents-write release token. Draft visibility is mandatory. Pages are
  requested sequentially with exact `per_page=100`, redirects disabled, and a
  source-constant ceiling of 100 pages. The first page shorter than 100 closes
  the scan; a full page 100 is terminal rather than silently truncating a
  repository with 10,000 or more releases. Each page must be one
  duplicate-key-safe JSON array of at most 100 objects with a positive unique
  numeric release ID and string tag name. Duplicate IDs across pages,
  duplicate exact target tags, a byte-different ASCII-case-fold collision with
  the target tag, nonsequential/oversized/malformed pages, or any bound
  exhaustion is terminal. The scan always continues to its closing short page
  after a first target match so a later duplicate or case collision cannot
  hide. It sends no conditional cache header and requires status 200 for every
  page; 304 and every other status are terminal. Unrelated releases are never
  mutated.
- The exhaustive scan branches before every other release operation. If it
  returns one published release for the exact tag, the run is verify-only: no
  draft create, upload, asset delete, or release edit is permitted. It succeeds
  only when the uniform published-success predicate below already holds,
  including JSON boolean `immutable:true`; every published mismatch or
  incomplete set is terminal. If it returns one draft, its pure title/body,
  `prerelease:false`, JSON boolean `immutable:false`, positive release ID, and
  exact tag name must already match before starter handling or any upload;
  the separately re-proven ref supplies commit identity. The release object's
  `target_commitish` must remain a string but is non-authorizing: GitHub
  documents that field as unused when the tag already exists, and live
  immutable releases may report the default branch there. Metadata is never
  repaired. Only an exhaustive zero-match scan permits one fresh draft create.
- Product publication has no tag-creation path: before draft creation and
  immediately before every release/asset mutation, the remote ref must already
  point to the exact admission-bound annotated tag-object SHA, whose exact tag
  text, `verification.verified:true`, and peeled commit are re-proven. The same
  proof is repeated immediately after every successful mutation and in the
  final uniform success predicate. Missing, lightweight, unsigned, moved, or
  wrong-commit product tags are terminal before another mutation; a move
  observed after a successful remote write leaves only a resumable/terminal
  remote partial state and can never be reported as success. `target_commitish`
  is never treated as tag proof.
  Candidate refs have a closed state machine. A fresh fixed-origin ref read may
  return 404, or exactly one ref object whose object type is `commit` and whose
  40-hex SHA is the exact admitted source commit; the latter is safely reused.
  Wrong commit, annotated-tag object, malformed/ambiguous response, redirect,
  or any other status is terminal. Only the initial 404 plus a positive
  immutability read permits one candidate lightweight-ref create attempt per
  run. After the settings read, one final ref read either safely reuses an
  exact concurrently created identity or must still observe 404 before the
  create request. A success response is non-authorizing until a fresh ref read
  proves the exact lightweight identity. A create conflict likewise permits
  only one fresh ref read: exact identity may continue, while 404 or any
  mismatch is terminal. Before and immediately after every subsequent
  release/asset mutation, and for final success, the lightweight ref is
  freshly re-proven as the same exact source commit. No branch retries create,
  moves, or replaces a ref.
- Release/ref identity is one closed state matrix evaluated before mutation:
  absent release plus exact ref may attempt one draft create; an exact
  identity-matched draft may resume; an exact identity-matched, complete,
  immutable published release may return verify-only success. An absent
  release after any create attempt, any identity mismatch, an incomplete or
  mutable published release, and every other state are terminal. Title or body
  similarity, an already-exists response, the advisory `target_commitish`, and
  a prior numeric release ID cannot select another cell or authorize success.
  Crash rebind always performs the exhaustive exact-tag scan and then the
  appropriate fresh product/candidate ref proof before it accepts or mutates
  that draft.
- Draft creation is at most once per run. A success response must itself be a
  positive release ID with `draft:true`, exact pure metadata,
  `prerelease:false`, `immutable:false`, and the exact bound tag name before
  any upload; a fresh ref proof separately binds that tag to the commit. The
  response ID is non-authorizing until one fresh
  exhaustive release-list scan returns the same exact tag and positive ID. The
  first create request irreversibly flips a local `create_attempted` state
  before transport; no path can clear it. A 409/422/already-exists response or
  create race permits one fresh exhaustive scan. After any create attempt,
  only one matching published release (verify-only) or one exact
  resume-eligible draft may continue. A zero-match, ambiguous, truncated, or
  conflicting scan is terminal and can never return to the zero-match create
  branch. Any other status, malformed response, missing post-create rebind, or
  identity mismatch is terminal and cannot authorize an upload.
- An existing draft is resume-eligible only when its exact tag, pure
  title/body, `draft:true`, `prerelease:false`, separately proven ref target,
  and every present asset are valid, and its asset names are an exact subset
  of the expected set. The advisory release `target_commitish` string is not
  tag identity and may not override or weaken that ref proof.
  The exhaustive authenticated release-list scan is the sole crash-rebinding
  authority: it returns either zero matches or one release object; a positive
  numeric ID from that fresh object is bound for every operation in the run.
  Later scans must return the same ID. No create response, persisted/local ID,
  release object's embedded asset array, or tag-name endpoint can override it.
  Any ambiguous, truncated, or contradictory release observation is terminal.
  Each `uploaded` asset is downloaded by its positive numeric release-asset API
  ID and compared byte-for-byte before any write. A missing/null API digest is
  permitted for compatibility only when exact size and mandatory downloaded
  bytes match; a present digest must be the exact expected `sha256:` value.
  The only repairable partial-upload residue is state exactly `starter`, name
  exactly one expected missing basename, on that exact validated draft ID.
  This is the only failed-upload residue GitHub's upload contract identifies as
  safe to delete after its documented 502 path; `open` and every other state
  remain terminal rather than broadening destructive authority from an
  undocumented assumption. Such a row is deleted by its positive numeric asset
  ID, the draft is freshly rebound through the exhaustive release-list scan,
  and the name is then treated as missing. Unknown states, an uploaded
  mismatch, an extra starter, or any other residue are terminal.
  Such a terminal draft can wedge that exact product/candidate identity by
  design. Recovery is a separate operator-governed action: positively re-prove
  that the exact release ID is still a draft for the exact tag, then manually
  delete that whole stuck draft before a later fresh run. The helper never
  performs or suggests an automatic draft delete, and recovery never deletes a
  published release, independently published asset, or tag. Tests keep
  `open`, unknown, extra, and mismatched residues terminal so future
  convenience changes cannot silently broaden delete authority.
  The helper uploads only missing expected basenames to the same numeric draft
  ID, never overwrites an uploaded name, and never bulk/parallel uploads. After
  each one-asset upload it freshly rebinds the exact tag through the exhaustive
  release-list scan and proves the same positive draft ID, exact
  metadata/identity, and updated exact partial asset set before another
  mutation. It then re-reads and verifies the exact complete draft before
  publication. An existing published release can
  succeed only when the same uniform predicate proves exact metadata, exact
  complete names, and byte-for-byte equality for every freshly read asset ID;
  published subsets are never modified.
- Every asset-set observation is a fresh exhaustive list against the bound
  positive release ID, never the release object's embedded `assets` array.
  The helper requests sequential numeric pages from the fixed API endpoint
  with exact `per_page=100`, redirects disabled, and duplicate-key-safe JSON
  array parsing. It continues after every full page and stops only on the first
  page shorter than 100. The cumulative hard limit is derived from the closed
  expected set: observing `expected_count + 1` rows is immediately terminal,
  while a full page ending at exactly `expected_count` still requires one
  final empty/short page to prove no later row. Duplicate positive asset IDs,
  duplicate or case-fold-colliding names, a page larger than 100, non-array or
  ambiguous JSON, nonsequential response, or any over-bound result is terminal
  before another mutation or successful exit. Draft resume may use only an
  exhaustively proven subset; prepublish and published success require exact
  equality. This same enumerator is mandatory before starter repair, after
  starter deletion, after every one-asset upload, immediately before publish,
  and for postpublish verification.
- Immediately before the draft-to-published edit, the helper performs a fresh
  exhaustive release-list scan and immutability-setting read, then proves the
  same positive release ID, `draft:true`, `immutable:false`, exact metadata/tag
  identity, and the exact complete safe `uploaded` asset set, including sizes,
  digest rules, and fresh ID-downloaded byte equality. Only those observations
  authorize `draft:false`; the uniform post-edit verification requires the
  same release ID with `draft:false` and `immutable:true` and remains the sole
  success authority. Any pre-publish drift is terminal and is not published.
- Every successful exit applies one uniform predicate: the repository
  immutability read is enabled, the exhaustive release-list scan returns the
  same sole positive release ID, the release has `immutable:true`, exact tag
  name, separately proven ref object/target, exact deterministic metadata and
  published state, exact complete asset-name set, and byte equality for every
  asset fetched by its freshly read numeric ID. The release object's advisory
  `target_commitish` string is never accepted as tag proof. Unexpected,
  duplicate, unsafe, renamed,
  non-uploaded, mutable, or byte-different assets and any metadata, release-ID,
  or tag conflict are terminal. No path deletes, replaces, recreates, clobbers,
  or generally edits an existing release/asset. The only narrow destructive
  operation is deletion of an exact expected-name `starter` residue from the
  exact validated draft release ID; the sole release edit is the verified
  complete draft-to-published transition. Terminal conflicts recover only
  through a newly admitted product version or candidate tag, never in-place
  repair.
- API asset digest handling is closed: absent or explicit JSON null means
  unavailable and therefore falls back to mandatory exact size plus
  ID-downloaded byte equality. A present value must be a lowercase
  `sha256:<64-lowercase-hex>` string exactly equal to the expected digest.
  Empty, malformed, uppercase, non-hex, or other-algorithm values are terminal;
  digest equality never replaces size and byte verification.
- Every publication request uses a source-constant endpoint and exact method.
  JSON immutability/release/tag/ref/asset reads and mutations are fixed to
  `https://api.github.com`; binary uploads are fixed to the exact release-ID
  endpoint under `https://uploads.github.com`. Neither accepts a
  response-supplied host, userinfo, fragment, alternate origin, or redirect.
  Binary asset verification starts at the exact numeric-ID endpoint on
  `https://api.github.com` with `Accept: application/octet-stream`: a direct
  200 is accepted, or exactly one 302 is followed without forwarding
  authorization only when its parsed target is HTTPS on the closed
  `release-assets.githubusercontent.com` host with no userinfo or fragment.
  The second transfer must be a direct 200 at that exact validated URL. Every
  other status, hop, scheme, host, or effective URL is terminal before another
  mutation.
- The complete remote-mutation allowlist is exclusive: one draft create only
  after an exhaustive zero-match release scan and positive immutability read;
  one exact candidate lightweight-ref create only after ref 404 and a positive
  immutability read; upload only one freshly proven missing expected basename
  to the exact validated draft ID after a positive immutability read; delete
  only an exact expected-name `starter` asset by its positive ID on that draft
  after a positive immutability read; and send one exact
  `{"draft":false,"make_latest":"false"}` edit to that verified complete draft.
  No other remote create, edit, delete, tag move, replacement, or clobber
  exists. Failure cleanup removes only bounded local temporary state; it never
  deletes a draft, published release, uploaded asset, or tag.
- If `draft:false` succeeds but the mandatory published re-read fails any part
  of the uniform predicate, the release is in an irreversible terminal state.
  The helper reports the exact closed mismatch class, performs local cleanup
  only, and never re-enters draft/starter recovery or performs another remote
  mutation for that release.
- Provenance relative paths are ASCII, at most 512 bytes, non-absolute, and
  consist only of slash-separated nonempty segments matching
  `[A-Za-z0-9][A-Za-z0-9._-]{0,126}` with neither `.` nor `..`. Asset basenames
  use the same single-segment grammar, may not end in dot/space, and are unique
  both byte-exactly and under ASCII case-folding. The helper uploads through
  the REST asset endpoint with an explicitly URL-encoded exact basename, so
  create, resume, listing, and verification share one name function even for
  nested source paths.
- Product admission passes the exact verified annotated tag-object SHA to
  publication. The helper rechecks that exact ref-object identity, GitHub
  signature verification, tag text, and peeled admitted commit immediately
  before draft creation/publication and after publication. Candidate refs must
  be lightweight exact admitted commits; the helper creates one only if
  absent, then rechecks it around every write. Final post-write verification is
  the only success authority; workflow concurrency is a liveness aid, not an
  integrity assumption.
- `repository_dispatch` accepts exactly event type
  `observe-runner-release` with `client_payload` exactly `{}`. The first step
  before checkout parses `GITHUB_EVENT_PATH`, rejects an unexpected action,
  non-object/unknown/nonempty payload, duplicate JSON ambiguity, or other
  trigger shape, and emits no user-controlled shell fragment. Both dispatch
  paths require `github.actor` to equal the exact nonempty repository variable
  `PORTABLE_GHAR_RUNNER_OBSERVER_ACTOR`; an unset variable is failure. Manual
  `workflow_dispatch` has no inputs. Selecting that actor is a separate
  operator configuration gate. Dispatch authorization never substitutes for
  default-branch checkout, exact action pins, or job permissions.
- The admission job resolves and outputs one exact 40-hex source commit and
  tree from the workflow-fixed `github.sha`. Every later build/compare/publish
  checkout uses that exact commit, then proves both `git rev-parse HEAD` and
  `git rev-parse HEAD^{tree}` against the admission outputs before executing
  source. No job resolves a floating default branch or tag independently.
- Candidate concurrency is non-destructive: observation runs serialize by
  workflow/default branch with `cancel-in-progress: false`; build/publish
  identities are keyed by the full candidate evidence after observation.
  One run never cancels a run that may already be attesting or publishing the
  same immutable candidate. Product tag runs likewise serialize under the
  exact workflow/tag ref with `cancel-in-progress:false`, covering every
  publish mutation for that product identity. Exhaustive release-list
  rebinding and final verification remain integrity authorities; concurrency
  supplies liveness, not trust.
- Publication is a final step. GitHub release creation uses verified tag or an
  immutable candidate tag created from the trusted default-branch commit.
  Upload failure cannot mutate an existing current/rollback release.
- Workflow authority is split structurally:
  - admission/observation jobs have read-only contents;
  - two independent build jobs have read-only contents and upload immutable
    short-retention workflow artifacts;
  - the compare/attest job downloads both, validates them, holds only
    `id-token: write` and `attestations: write`, attests the exact closed
    provenance set, then creates one deterministic uncompressed
    `publication-bundle.tar` from comparator-validated tree A without
    regenerating, filtering, or repacking any subject; it exports the bundle
    SHA-256 as a job output and uploads only those exact tar bytes; and
  - the final publish job alone holds `contents: write`, downloads only that
    tar, verifies the expected bundle SHA-256, safely extracts it into a
    private directory, reruns complete read-only single-tree validation using
    the comparator against itself, rechecks exact release-kind membership, and
    only then mints a current-repository GitHub App installation token through
    pinned `actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1`
    using `vars.PORTABLE_GHAR_RELEASE_APP_CLIENT_ID` and
    `secrets.PORTABLE_GHAR_RELEASE_APP_PRIVATE_KEY`, explicitly narrowed to
    `permission-administration: read`. The job-scoped `GITHUB_TOKEN` remains
    the distinct `contents:write` release/ref credential. Only the helper step
    maps `${{ github.token }}` to `PGHAR_RELEASE_TOKEN` and the app action
    output to `PGHAR_RELEASE_SETTINGS_TOKEN`; it never reassigns `GITHUB_TOKEN`
    or `GH_TOKEN`, and no other step receives the app token. The helper
    publishes precisely the extracted provenance set and never exchanges the
    two credentials. It performs no build, generation, normalization, or
    subject selection.
  No job simultaneously has build authority and release-write authority.
- The observer's exact-current exit code `3` produces no candidate manifest
  and sets the admission output to exact `candidate=false`. Every build,
  compare, attest, and publish job is gated on exact `candidate=true` from that
  same admission job and downloads only the uniquely named manifest artifact
  uploaded by its positive observation path. Empty/missing output, exit `3`,
  any other nonzero observer result, or a stale artifact from another run
  cannot create a ref, rehearse, attest, or publish.
- No generated artifact, downloaded tool, upstream archive, OCI archive,
  local path, or build output is committed.
- Every implementation change is TDD: observe a targeted RED failure, make the
  smallest implementation change, rerun focused tests, then run the full local
  source gate.
- Direct distinct-family review uses xAI/Grok before Anthropic/Claude. The
  broker is bypassed only for this session as explicitly authorized; no broker
  lifecycle state is read or changed.

## Threat Model and Adversarial Classes

1. **Upstream identity substitution:** a release asset, digest, tag, peeled
   commit, source file, platform, or publication record belongs to a different
   runner release.
2. **Version-policy bypass:** lexical comparison, leading zeros, suffixes,
   overflow, downgrade, equal-version drift, prerelease, or stale API response
   becomes a candidate.
3. **Parser ambiguity:** duplicate JSON keys, case folding, numeric coercion,
   unknown local manifest keys, Unicode confusables, or trailing documents
   produce divergent identities.
4. **Transfer confusion:** redirect following, alternate host, userinfo, query,
   fragment, or content-length/body mismatch escapes the fixed source.
5. **Candidate patch expansion:** a generic replacement edits an unintended
   source/test/document path, misses a new pin source, or writes the caller
   checkout.
6. **Non-hermetic build:** moving package indexes, mutable tool/image tags,
   wall-clock metadata, build paths, VCS dirtiness, random SBOM namespaces,
   shared Go/module/BuildKit/Docker cache state, or same-host graph residue
   changes or falsely equalizes output bytes.
7. **Artifact smuggling:** an unregistered binary/image, synthetic listener,
   second runner payload, update staging, unexpected OCI blob, symlink,
   device, hard link, or unsafe tar path enters output.
8. **Evidence laundering:** missing Docker, skipped full tests, failed scan,
   absent SBOM/license/checksum/provenance, or partial publication is labeled
   complete.
9. **Comparison weakening:** the comparator normalizes away content changes,
   compares mutable tags instead of digests, rewrites evidence, ignores
   unreferenced blobs, or accepts different artifact registries.
10. **Workflow authority expansion:** pull-request code, broad permissions,
    unpinned actions, persistence of checkout credentials, open dispatch
    payloads, candidate tags entering `v*`, build-plus-publish authority,
    mutable release replacement, or destructive concurrent publishers reach
    the release path.
11. **Continuity failure:** observation/rehearsal failure deletes or makes
    unavailable the current or rollback release, or forces manual recovery
    during an upstream version bump.
12. **Sensitive-output leakage:** a token, host/user path, private repository
    ID, workflow secret, raw API body, or scan diagnostics enter a public
    artifact or terminal summary.
13. **Draft-rebind ambiguity:** the published-only tag endpoint, a truncated
    release listing, duplicate/case-colliding tag, moving pagination window,
    stale create response, or locally persisted numeric ID binds a mutation to
    the wrong draft.
14. **Immutability misconfiguration:** the repository setting is disabled,
    unreadable, or changes around publication; a mutable published response is
    mistaken for completion; or the administration-read token gains release
    mutation authority.

## Canonical Data Contracts

### Candidate runner manifest

Canonical JSON is UTF-8, sorted-key, compact, and newline terminated:

```json
{
  "command_settings_sha256": "<64 lowercase hex>",
  "linux_x64_asset_digest": "sha256:<64 lowercase hex>",
  "linux_x64_asset_name": "actions-runner-linux-x64-<version>.tar.gz",
  "linux_x64_asset_size": 1,
  "observation_evidence": "<64 lowercase hex>",
  "published_at": "YYYY-MM-DDTHH:MM:SSZ",
  "schema_version": 1,
  "source_commit_sha": "<40 lowercase hex>",
  "tag_ref_sha": "<40 lowercase hex>",
  "version": "vMAJOR.MINOR.PATCH"
}
```

The checked-in baseline under `release/manifest.json.runtime.runner_release`
uses the same object.

### Runtime release artifact tree

Each successful output has exactly:

```text
bin/<registered binaries>
images/<registered image>.oci.tar
sbom/<subject>.spdx.json
notices/THIRD-PARTY-NOTICES.txt
runner-release.json
checksums.txt
provenance-subjects.json
runtime-release.json
```

For `release_kind=product` only, the closed tree additionally contains
`source/portable-ghar-<VERSION>.tar.gz` and its registered normalized SBOM
under `sbom/`; `release_kind=candidate` forbids both. No debug log, downloaded
tool, runner archive, source clone, Docker metadata, scan cache, private path,
or unregistered file may remain.

## Task 14.1: Freeze the Release Manifest and Hermetic Runner Build

**Files:**

- Modify: `release/manifest.json`
- Modify: `images/runner/Dockerfile`
- Test: `tests/shell/runtime-release.bats`

- [ ] Add Bats assertions that the manifest has the exact closed runtime
  schema, unique binary/image names, production-only entries, exact tool/image
  digests, a baseline candidate manifest, a complete substitution table, and
  an exact non-wildcard license-exception schema.
- [ ] Add a RED test proving the current runner Dockerfile is rejected because
  it references moving Debian repositories and does not bind the immutable
  snapshot/epoch.
- [ ] Add a RED test enumerating all registered production Dockerfiles and
  rejecting any mutable `FROM`, moving package index, unbound epoch, or
  unregistered acquisition site. Prove the five network images are
  scratch-final/digest-pinned and the runner is the sole snapshot acquisition
  site.
- [ ] Run:

  ```sh
  bats tests/shell/runtime-release.bats
  ```

  Expected: FAIL on the absent runtime manifest and non-hermetic Dockerfile.

- [ ] Extend `release/manifest.json` without changing top-level `version: 1`.
  Register the exact platform, baseline runner release, production
  commands/images, candidate substitution table, Debian snapshot, buildx,
  BuildKit, Syft, and Trivy identities.
- [ ] Change only the runner Dockerfile's dependency acquisition:
  install from the immutable Debian snapshot, remove package-manager/log state,
  accept the required epoch, and preserve the existing final image/security
  contract.
- [ ] Rerun the focused tests. Expected: PASS.

## Task 14.2: Implement the Official Runner Observer

**Files:**

- Create: `scripts/release/observe-runner-release.sh`
- Create/extend: `tests/shell/runner-release.bats`

- [ ] Write fake-`curl` fixtures that validate the exact URL/header sequence
  and cover lightweight/annotated tag success, exact-current no-candidate,
  strictly newer success, downgrade, equal identity drift, duplicate asset,
  wrong platform/name/digest/size, draft/prerelease, malformed/duplicate JSON,
  tag/ref/object mismatch, nested tag, oversized body, redirect, timeout,
  noncanonical time/version, CommandSettings source mismatch, output
  preexistence, and interrupted atomic output.
- [ ] Assert the exact canonical output bytes and an independently calculated
  Task-12 observation-evidence digest.
- [ ] Run:

  ```sh
  bats tests/shell/runner-release.bats
  ```

  Expected: FAIL because the observer does not exist.

- [ ] Implement strict argument/path handling, private temporary files, fixed
  API/raw origins, bounded curl calls, duplicate-key-safe parsing, numeric
  version comparison, tag peeling, exact asset selection, CommandSettings
  hashing, evidence framing, baseline comparison, canonical JSON, atomic
  output, and cleanup.
- [ ] Rerun the focused suite. Expected: PASS.

## Task 14.3: Implement Runtime Rehearsal and Artifact Validation

**Files:**

- Create: `scripts/release/rehearse-runtime.sh`
- Extend: `tests/shell/runtime-release.bats`

- [ ] Add RED tests for arguments, exact `product|candidate` release-kind
  admission, path/symlink/hard-link handling, dirty
  source, malformed runner manifest, current/new candidate patch counts,
  protected-token occurrence outside the substitution table, pre-substituted
  or third-value token at a protected site, unregistered command/image, wrong
  platform/tool identity, mutable BuildKit identity, non-private/shared Go or
  BuildKit cache, missing Docker/full-gate evidence, downloaded runner
  size/digest mismatch before overlay, failed scan, listener mismatch, multiple
  runner payloads, update staging, broad/mismatched license exception,
  incomplete SBOM/license/checksum/provenance, omitted authority file,
  unexpected output, sensitive output, cleanup, and atomic commit.
- [ ] Use fixture tool shims only to exercise orchestration contracts. They
  must validate the exact argv/environment and produce closed synthetic
  artifacts; fixture success is unit evidence only and can never set a
  full-Linux evidence marker.
- [ ] Run:

  ```sh
  bats tests/shell/runtime-release.bats
  ```

  Expected: FAIL because the rehearsal script does not exist.

- [ ] Implement closed manifest parsing and private tool acquisition.
- [ ] Implement isolated exact-HEAD clone, count-checked candidate pin
  substitution with structured production-pin closure, full runtime-gate
  invocation, and cleanup.
- [ ] Transfer and independently size/hash the exact runner archive before any
  overlay or archive use.
- [ ] Implement deterministic Linux binary compilation and ELF/platform/
  embedded-path/time checks.
- [ ] Implement production image preparation, pinned BuildKit OCI builds,
  private per-run Go/module/BuildKit caches, runner payload/listener/
  update-staging checks, and deterministic Docker cleanup.
- [ ] Implement pinned Trivy scans, normalized Syft SPDX generation, notices,
  the acyclic primary-subject → runtime-manifest → checksums → provenance
  authority graph, text-authority sanitizer, final self-validation, and atomic
  output commit.
- [ ] Rerun focused tests. Expected: PASS.

## Task 14.4: Implement the Read-Only Rebuild Comparator

**Files:**

- Create: `scripts/release/compare-runtime-rebuilds.sh`
- Extend: `tests/shell/runtime-release.bats`

- [ ] Build synthetic valid artifact trees and mutations for binary bytes,
  source/runner/tool identities, registry changes, subject size/digest,
  symlink/hard-link/mode, missing/extra artifact, OCI index/manifest/config/
  layer digest, descriptor order, second platform, foreign URL, unreferenced
  blob, unsafe tar member, runtime-manifest-to-archive graph disagreement, and
  input-mtime preservation.
- [ ] Run the focused comparator tests. Expected: FAIL because the comparator
  does not exist.
- [ ] Implement duplicate-key-safe manifest validation, no-follow tree
  inventory, byte comparison, and read-only bounded OCI graph parsing.
- [ ] Before/after hash, mode, and mtime every input file in tests to prove the
  comparator never rewrites either tree.
- [ ] Rerun the focused suite. Expected: PASS.

## Task 14.5: Integrate Trusted Release Workflows

**Files:**

- Modify: `.github/workflows/release.yml`
- Create: `.github/workflows/runner-release-candidate.yml`
- Create: `scripts/release/publish-runtime-release.sh`
- Modify: `tests/repository/test_workflow_policy.py`
- Extend: `tests/shell/runner-release.bats`
- Extend: `tests/shell/runtime-release.bats`
- Create: `tests/shell/publish-runtime-release.bats`

- [ ] Add RED repository tests for exact triggers, default-branch source,
  minimal permissions, unique job ID, hosted Linux, timeouts/concurrency,
  pinned actions, no PR code, no hard-coded cadence, exact empty
  `repository_dispatch` payload admission, exact configured-actor admission,
  bounded observation retries,
  candidate tag disjoint from `v*`, immutable candidate identity, no-replace
  and interruption-resumable subset-only publication, rejection of conflicting
  release metadata/target/assets, two fresh-host rehearsals with no shared
  caches, comparator
  self-consistency, full gate, scans, exact authority-file attestation
  membership, exact source-commit/tree checkout in every job, a deterministic
  comparator-validated tree-A publication tar with an independently checked
  digest, closed product source+runtime membership, split
  read/build/attest/publish permissions, and publish-last ordering.
  Prove the final job mints a current-repository GitHub App token through the
  exact pinned action and exact client-ID/private-key configuration with only
  `administration:read`, while release/ref writes continue to use only the
  separate job-scoped `contents:write` token.
- [ ] Run:

  ```sh
  python3 -m unittest tests.repository.test_workflow_policy -v
  bats tests/shell/runner-release.bats tests/shell/runtime-release.bats
  ```

  Expected: FAIL because the candidate workflow and release integration are
  absent.

- [ ] Update the complete job-set assertion with the unique observer, two
  build, compare/attest, and publish jobs for product and candidate releases;
  do not add any of them as required PR contexts.
- [ ] Add the candidate workflow with only `workflow_dispatch` and trusted
  `repository_dispatch` event type `observe-runner-release`, no manual inputs,
  exact configured-actor admission, and exact empty-payload validation before
  checkout. Treat observer exit `3` as no-op; every other nonzero is failure.
  Run two full rehearsals on separate fresh hosted jobs with isolated
  caches/builders, compare/attest in a third job, and publish one deterministic
  immutable `runner-candidate-*` release from a final write-only job.
- [ ] Update the tag workflow to run two full rehearsals on separate fresh
  hosted jobs, compare/attest exact source/runtime authority subjects in a
  third job, and publish source plus runtime artifacts from a final
  contents-write-only job. Publication remains the final operation.
- [ ] Implement one shared final-publication helper for both workflows. Test
  fresh draft creation, exact-complete published idempotence, exact-partial
  draft resumption, interruption followed by successful retry, immutable
  asset-ID downloads, exact `starter` residue deletion, one-way
  draft-to-published transition, and fail-closed
  metadata/tag/release-ID/extra/duplicate/state/digest/size/byte-drift cases.
  Test product annotated-tag-object identity and signature binding, candidate
  ref create-after-404 without move/replace, at-most-once draft creation with
  one conflict re-observation, one-asset-at-a-time upload with full revalidation
  between mutations, mandatory prepublish and postpublish byte verification,
  closed ASCII/case-folded asset names, exact fixed-origin/no-redirect API and
  upload calls, the sole validated one-hop unauthenticated asset-download
  redirect, exact `make_latest:"false"` create/publish bodies, non-canceling
  per-tag product concurrency, exhaustive fixed-100 asset pagination with an
  `expected_count + 1` hard stop, second-page expected/extra assets,
  duplicate/case-fold-colliding IDs/names, truncated/ambiguous/over-bound asset
  listings, and irreversible postpublish mismatch. Separately test the
  authenticated release-list rebind over sequential fixed-100 pages, exact
  draft visibility, zero/one-match branching, post-create same-ID binding,
  terminal zero-match after any create attempt with no second create,
  second-page target discovery, continued enumeration after the first target,
  duplicate IDs/tags, target case-fold collisions, malformed/oversized/304
  pages, and the source-constant 100-page fail-closed ceiling. Prove the
  published-only tag endpoint is never used as draft or absence authority.
  Test candidate existing/reused exact lightweight identity, wrong commit,
  annotated-object rejection, create success/conflict re-proof, and terminal
  post-create 404 without retry. For both product and candidate identities,
  prove the exact ref/object is the final API observation immediately before
  every mutation and the first API observation immediately after every
  successful mutation; inject a moved ref at each boundary and require
  terminal failure before another mutation or successful exit. Test the
  separate settings credential, fixed
  versioned immutable-release endpoint, missing/empty/whitespace/equal token
  failures before any remote call, disabled/404/permission/malformed failures
  before every mutation, exact `enabled:true`, draft `immutable:false`,
  published `immutable:true`, credential-specific header non-interchange, and
  no enable/disable method. Policy tests prove the app output is mapped only to
  `PGHAR_RELEASE_SETTINGS_TOKEN`, `${{ github.token }}` only to
  `PGHAR_RELEASE_TOKEN`, and neither `GITHUB_TOKEN` nor `GH_TOKEN` is
  reassigned.
  The helper may perform only the exclusive remote-mutation allowlist defined
  above; it must never generally delete, edit, replace, move, or clobber a tag,
  release, or uploaded asset.
- [ ] Rerun focused tests, actionlint, workflow policy, and JSON/YAML parsing.
  Expected: PASS.

## Task 14.6: Local Source and Binary Reproducibility Verification

- [ ] Run all Task 14 shell tests:

  ```sh
  bats tests/shell/runner-release.bats tests/shell/runtime-release.bats \
    tests/shell/publish-runtime-release.bats
  ```

- [ ] Run repository/workflow checks:

  ```sh
  python3 -m unittest tests.repository.test_workflow_policy -v
  python3 scripts/check_workflow_policy.py .github/workflows
  go tool actionlint .github/workflows/*.yml
  node -e 'const {parseAllDocuments}=require("yaml"); const fs=require("fs"); for (const p of process.argv.slice(1)) { for (const d of parseAllDocuments(fs.readFileSync(p,"utf8"),{strict:true})) { if (d.errors.length) throw d.errors[0]; } }' .github/workflows/*.yml
  ```

- [ ] Run shell/static formatting:

  ```sh
  shellcheck scripts/release/*.sh
  go tool shfmt -d scripts/release
  npm run format:check
  ```

- [ ] Run the portable full unit release gate:

  ```sh
  ./scripts/test-controller-runtime.sh --unit
  ```

- [ ] Cross-compile every registered Linux binary twice into separate private
  directories using the exact manifest flags and compare them byte-for-byte.
  Validate ELF Linux/amd64 identity and absence of the repository path.
- [ ] Run the observer against the official API only as a read-only
  point-in-time check. If the newest version equals the checked-in baseline,
  require exit `3`; if it is newer, validate the canonical candidate but do
  not publish or change pins.
- [ ] Run:

  ```sh
  PGHAR_INTEGRATION_DOCKER=1 PGHAR_CHAOS_DOCKER=1 \
    ./scripts/test-controller-runtime.sh --full
  ```

  Expected on this macOS host: nonzero typed prerequisite failure. Record this
  as the still-open Linux/Docker gate, not a skip/pass.

## Task 14.7: Exact Direct xAI/Grok Review and Signed Checkpoint

- [ ] Seal the complete Task 14 diff plus this plan into one exact UTF-8
  artifact and record byte length/SHA-256.
- [ ] Use the directly authenticated xAI/Grok CLI in read-only mode for an
  exact-artifact code review. Require a substantive matching-digest verdict.
  Do not use or mutate the managed broker.
- [ ] Adjudicate every finding against exact source/tests. Material changes
  require a changed-artifact confirmation review. No matching approval means
  no checkpoint commit.
- [ ] Stage only the planned Task 14 paths. Confirm no generated output,
  downloaded tool, upstream archive, image, secret, or unrelated file is
  staged.
- [ ] Create the signed checkpoint:

  ```sh
  git commit -S -m "release: automate qualified runner candidates"
  ```

- [ ] Read back the signed commit, exact tree, subject, staged path list, and
  clean worktree.

## Task 14.8: Governed Phase 2 Source-Completion PR

- [ ] Push the exact signed Task 14 head and open the governed Phase 2 source
  PR. The PR must clearly state:
  - Phase 2 source implementation is complete;
  - Linux/Docker full rehearsal is not yet complete;
  - full two-rebuild reproducibility is not yet complete;
  - the forced-version-bump drill is not yet complete;
  - numeric sizing/cadence and host changes remain operator gates;
  - repository immutable releases are still disabled and the narrowly scoped
    release-settings GitHub App variable/secret/installation are still
    operator configuration gates; and
  - no deployment or host mutation occurred.
- [ ] Obtain exact-head distinct-family review with xAI/Grok before
  Anthropic/Claude, satisfy required checks/compliance, resolve every review
  thread, and merge without admin bypass.
- [ ] Read back the merge commit and `origin/main`.
- [ ] Do not label the merge as **Phase 2 fully verified**.

## Deferred Evidence/Completion PR

After operator approval of the open numeric decisions and access to a
supported disposable Linux/Docker environment:

- [ ] Enable repository immutable releases under a separately approved
  operator configuration change, provision/install the current-repository
  GitHub App with exactly `administration:read`, store the named variable and
  secret, and positively prove the read-only setting endpoint without
  publishing a release.
- [ ] Run two independent full runtime rehearsals and the read-only comparator.
- [ ] Run the complete full runtime gate and all image/SBOM/license/scan/
  provenance validations.
- [ ] Execute a forced official runner-version-bump drill proving unattended
  observation, immutable qualification, hosted continuity, safe drain,
  canary, rollback preservation, and whole-container reclamation.
- [ ] Record exact artifacts/digests and positive cleanup evidence.
- [ ] Create a second signed evidence/completion commit and governed PR.
- [ ] Only after that PR's exact-head review/checks and merge may Phase 2 be
  described as **fully verified**.
