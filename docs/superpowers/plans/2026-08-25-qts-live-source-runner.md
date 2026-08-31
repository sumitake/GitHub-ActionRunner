# QTS Live Source-Built Runner Implementation Plan

> **Execution mode:** primary-session TDD. The primary owns every design,
> integration, release, mutation, and verification decision; read-only sidecar
> findings are advisory only.

**Goal:** replace the active persistent dark-observer closure with one
source-built, reproducible runner payload and one disjoint, bounded live
RhoNAS canary while LabMacPro remains untouched and authoritative.

**Architecture:** keep the existing release pipeline and host/runtime safety
machinery. Change only the runner acquisition seam: a strict
`runner_release` schema-v2 document drives a single source builder, which
publishes the ordinary verified runner runtime consumed by the existing image
preparation, release, SBOM, Trivy, provenance, attestation, comparator, and
conformance gates. Deployment uses a private one-shot JIT execution packet;
it installs no observer, watchdog, cron, controller, or durable canary state.

**Implementation:** POSIX shell, Python 3 standard library, Go 1.26.6, .NET
SDK 8.0.424/runtime 8.0.30, Bats, GitHub Actions, existing Docker/BuildKit
release jobs.

**Frozen design:**
[`2026-08-25-qts-live-source-runner-amendment.md`](../specs/2026-08-25-qts-live-source-runner-amendment.md)

## Task 1: Freeze schema-v2 and source inputs with RED contract tests

**Files:**

- Modify: `tests/shell/runtime-release.bats`
- Create: `tests/repository/test_runner_source_contract.py`
- Modify later: `release/manifest.json`
- Create later: `release/runner-source-locks/*/packages.lock.json`

1. Add literal schema-v2 fixtures and tests that reject every missing, extra,
   malformed, floating, duplicate, or archive-shaped key. Assert the exact
   official source commit/tree, .NET SDK/runtime URL and SHA-512, seven
   canonical NuGet lock paths/digests, four Node external URLs/SHA-256 values,
   and listener version.
2. Add behavior tests proving an archive-shaped `runner_release` cannot enter
   a product release and that the full version-2 object is bound into
   `runtime-release.json`, checksums, provenance, and A/B comparison.
3. Run the focused tests and record the expected failures caused by the
   current schema-v1 manifest/validators.

## Task 2: Implement and test the closed source builder

**Files:**

- Create: `scripts/release/build-runner-from-source.py`
- Create: `tests/repository/test_runner_source_build.py`
- Modify: `cmd/portable-ghar-runtime-lock/main.go`
- Modify: `cmd/portable-ghar-runtime-lock/main_test.go`
- Modify: `scripts/prepare-task5-images.sh`
- Modify: `tests/shell/prepare-task5-images.bats`

1. Write tests first for manifest admission, exact source identity, bounded
   downloads, SHA-512/SHA-256 rejection, safe tar extraction, isolated NuGet
   cache, locked-mode restore, deterministic MSBuild flags/path mapping,
   exact `TargetLatestRuntimePatch=true` selection of runtime `8.0.30` (and
   rejection of the empirically older `8.0.0` false-property result), official
   Node layout preservation, internal-only symlinks, mode
   normalization, listener-version mismatch, update/build residue rejection,
   deterministic internal tar transport, and canonical provenance.
2. Add one runtime-lock command used only for a locally source-built archive.
   It accepts an exact expected SHA-256 for TOCTOU/structure admission, reuses
   the mature runner archive extractor and runtime/manifest/tree-lock/READY
   publisher, and does not download or select a payload.
3. Implement the Python source builder with one caller-owned transaction root,
   explicit subprocess deadlines, exact official clone/commit/tree proof,
   digest-first extraction, copied locked graphs, isolated `NUGET_PACKAGES`,
   fixed deterministic build environment, full upstream external layout,
   and deterministic cleanup on every path.
4. Extend image preparation with exactly one mutually exclusive
   `--runner-runtime` input. Positively verify the source builder's READY,
   manifest, tree lock, runtime lock, and provenance before copying the same
   ordinary runner tree into the existing image context. Keep the historical
   archive mode for tests/library use, but the product rehearsal must not call
   it.
5. Run the focused Python, Go, and Bats tests to green.

## Task 3: Generate and freeze the NuGet locks

**Files:**

- Create: seven `release/runner-source-locks/<project>/packages.lock.json`
- Modify: `release/manifest.json`

1. Use official .NET SDK 8.0.424 in a disposable environment to restore the
   exact upstream source for `linux-x64` with
   `RestorePackagesWithLockFile=true`; make no upstream source edit other than
   the seven generated lock files.
2. Copy the canonical lock files into the product lock directory, record each
   SHA-256, and compute one aggregate canonical digest.
3. Repeat restore from an empty `NUGET_PACKAGES` root in locked mode and prove
   the lock files remain byte-identical.
4. Populate `runner_release` schema v2 and run Task 1/2 tests again.

## Task 4: Replace the product rehearsal's archive acquisition seam

**Files:**

- Modify: `scripts/release/rehearse-runtime.sh`
- Modify: `scripts/release/compare-runtime-rebuilds.sh`
- Modify: `.github/workflows/release.yml`
- Modify: `tests/shell/runtime-release.bats`
- Modify: `tests/repository/test_workflow_policy.py`

1. Add RED tests proving the product rehearsal invokes the source builder
   before any overlay/image build, supplies a fresh isolated source/NuGet root,
   consumes only the verified runtime output, never constructs the official
   prebuilt release-asset URL, and emits no second runner payload.
2. Advance both strict validators to runner-release schema v2; bind the full
   v2 object to runtime evidence and comparison. Require candidate and product
   input to equal the checked-in object exactly; the registered identity
   inventory becomes a no-op closure check and both paths require a clean clone.
   Retire only archive-specific substitution tokens from this product path.
3. Replace the prebuilt archive download block with one bounded source-builder
   invocation. Pass the result to `prepare-task5-images.sh --runner-runtime`;
   leave all later full-gate, image, Trivy, SBOM, provenance, comparison,
   publication, and cleanup steps intact.
4. In each release builder create separate source, SDK, NuGet, and external
   roots. Preserve the existing independent A/B jobs and exact-tree comparator.
5. Run shell/repository workflow tests and the full non-Docker gate.

## Task 5: Amend only the active closure and operations documents

**Files:**

- Modify: `docs/superpowers/specs/2026-08-24-deployment-closure-design.md`
- Modify: `docs/superpowers/plans/2026-08-24-qts-dark-observer-closure.md`
- Modify: `docs/operations/runner-release.md`
- Modify: `docs/operations/production-lifecycle.md`
- Modify: `docs/operations/operations.md`
- Create: `docs/operations/qts-live-canary.md`
- Modify: `tests/repository/test_docs_contract.py`

1. Mark only the active persistent-observer outcome/phase as superseded by the
   approved amendment. Preserve historical rationale and all transient
   force-disabled/zero-authority safety semantics.
2. Replace the release runbook's product archive path with schema-v2 source
   build/A-B qualification. Keep the unchanged HIGH/CRITICAL gate and old-tag
   prohibitions.
3. Add one live-canary runbook and private execution-packet schema: positive
   LabMacPro/control-host/RhoNAS identities; exact release/image; fixed
   disjoint selector; one pre-dispatched secretless workflow; one JIT runner;
   single operation state; bounded readback; exact-ID cleanup; candidate-only
   pre-registration startup interruption on job three's same queued operation;
   three serial jobs; resource and residue proof; LabMac readback after every
   outcome; no redispatch and no shared daemon/host restart.
4. Remove obsolete repository assertions that require a persistent observer.
   Do not replace them with prose-grep tests; source builder, workflow, and
   execution-packet validators carry the executable contracts.

## Task 6: Exact-head local qualification and review

1. Run Worker lint/typecheck/tests serially; all Go tests; race; vet;
   staticcheck; Bats; repository tests; shellcheck; `git diff --check`.
2. Run the actual source build twice in isolated Linux x64 environments. If
   either build or byte comparison fails, stop and record the exact invariant;
   make one explicit simplicity adjudication before considering any design
   expansion.
3. Run the full Docker/integration/conformance/chaos rehearsal once on the
   exact head. Do not replay an ambiguous or potentially effectful run.
4. Inventory every review surface once after review checks reach successful
   terminal state. Apply at most one consolidated remediation batch, rerun the
   complete exact-head inventory, and obtain distinct-family exact-head review
   and verification receipts.

## Task 7: Merge, release, and publish one new exact tag

1. Open a governed PR from the signed exact head with the required compliance
   trace and architecture-review receipt. Let required checks finish; do not
   use admin bypass.
2. Merge only when all gates and review surfaces are complete. Check out the
   exact merged `main`, verify commit/tree/signature, and run the smallest
   qualified full rehearsal still required for that exact head.
3. Create a new signed tag only on the qualified merged SHA. Never move or
   reuse `v0.1.0` or `v0.1.1`.
4. Positively read back Build A/B identity, identical digest, full gate,
   vulnerability result, release assets, checksums, SBOM, provenance,
   attestations, tag object, source commit, and source tree.

## Task 8: Deploy the bounded RhoNAS canary and prove rollback

1. Positively verify LabMacPro control-host identity and health, then the exact
   RhoNAS/QTS target, Docker binary/server, storage, resource, crond, current
   runner/selector, and unrelated cron state. Any mismatch is a stop.
2. Verify the private canary repository/workflow revision and prove the new
   selector absent from LabMacPro and all existing RhoNAS registrations.
3. Load/stage only the qualified immutable image on RhoNAS. Dispatch and record
   one secretless job under a single operation ID, then create its one exact
   JIT registration. Never stage or run on JOHN-MBP.
4. Prove the terminal job and full reclamation, then repeat serially for three
   jobs. On job 3, interrupt only the local pre-registration startup gate for
   its already queued run, prove no registration/assignment/job effect, then
   resume that same operation with its single JIT registration and no
   redispatch. Re-prove LabMacPro after every job and any failure.
5. On failure or ambiguity, disarm/remove only exact candidate identities,
   preserve unknown effects, prove zero candidate residue, and stop. Do not
   retry an operation that may have taken effect.
6. If all three jobs pass, report payload/host stability separately. Continue
   into the pre-existing production migration only if its ordinary Worker
   authority and signed execution-packet gates are actually present; otherwise
   stop truthfully at that explicit blocker with LabMacPro still authoritative.
