# Retained SDK qualification consumer

## Status

This is a source-only implementation increment, not an executable qualification
admission packet. No qualification, publication, deployment, SDK rebuild, or
spending is authorized by these modules. Existing qualification/reconstruction
host rejection and workflow selectors remain unchanged.

The accepted contract is identified by SHA-256
`c88d9e0195b9d22d2af08d61a1540ba252723416fd19705e34b84bbb1624d609`.
Product source C remains commit
`df760529f7635b7fc2d4982f72a50b53d0363de3`, tree
`ea097a04a995899a0b586b70c14a310c54a55a0f`. A separate reviewed, signed tooling
commit/tree T is required before use. These changes do not assign T, candidate
execution B, or qualification execution Q.

## Implemented boundaries

- The explicit internal `retained_sdk_qualification=True` build/scan mode uses
  retained SDK bytes and pinned Go 1.26.10. It retains fresh A/B generations of
  all 11 binaries and six images. It never selects the candidate five-image
  filter or B-deletion branch and does not rebuild the SDK.
- Both image generations use the exact original exporter reference
  `portable-ghar/<image>:candidate-df760529f763-go1.26.10`. Original OCI bytes,
  index metadata, graph, embedded binary hashes and build stamps remain bound.
  BuildKit 0.32.0 records the tag in `org.opencontainers.image.ref.name` and
  the normalized `docker.io/portable-ghar/<image>:<version>` name in
  `io.containerd.image.name`; both original annotations are checked.
- `_retained_qualification.py` verifies exact candidate overlap, complete
  downloaded transport membership, modes, separate C/T/B/Q identities, and the
  one-way evidence hash chain. The exact 13 build reports and 27 scan reports
  include the 17 raw SBOMs. The 17 normalized SBOMs are additional files; these
  evidence counts are separate from publication asset counts.
- `_qualification_packaging.py` independently assembles A/B candidate trees from
  their respective raw payloads and shared qualified metadata, using unchanged
  source release normalization, notices, sanitizer and comparator functions.
  The tree contains 38 runtime subjects and 41 files, with 39 checksum entries
  and 40 provenance rows. There is no additional standalone SDK asset.
- Image OCI archive hashes and manifest hashes are separate. Original raw and
  qualification-normalized SBOMs remain untouched. The assembler records the
  derived release-normalization mapping and preserves the different namespace
  and notices-root digest semantics.

The worker code is not a new public CLI mode. A source edit cannot substitute
for actual observed workers, provider-authenticated execution identities, or an
owner's decision. In particular, supplied JSON, a matching count, a pass flag,
and an ordinary green CI run do not establish qualification.

## Evidence chain

The original `qualification-subjects.json` bytes bind C/T/B/Q and each exact
subject's raw A/B paths, hashes, graph, candidate overlap, scan/SBOM references
and eventual release path. They also bind the source manifests and committed
legal texts.

`worker-evidence-inventory.json` binds the earlier complete worker evidence,
excluding itself and the later subjects, result and final inventory. The
`qualification-result.json` binds both the original subjects-file SHA-256 and
the original worker-inventory SHA-256. It does not hash itself.

`qualification-bundle-inventory.json` binds every qualification-bundle file
except itself, including the subjects, result and worker inventory. An external
publication handoff then binds the original subjects, result and final inventory
hashes, the complete downloaded qualification artifact, and the independently
prepared publication assets/bundle.

B is already complete, so its artifact ID, size and digest are included in the
shared identity tuple. Q's sidecars bind its execution and planned artifact
name. Q's final transport ID, size and digest can only be supplied in the
external handoff after upload/download. Putting the complete bundle's own hash
inside its subjects would create a circular hash dependency. No artifact ID is
invented and no existing B result is rewritten.

Archive verification streams complete bytes without extraction. It accepts
closed uncompressed USTAR and ordinary 32-bit stored/deflated ZIP transport with
native regular-file modes, optional streaming descriptors, and no comments or
extension fields. Unsupported framing, hidden leading/trailing content,
duplicates, links, traversal, unexpected directories and mode changes fail
closed. ZIP declared membership and expansion budgets are checked before
inflation. Publication bundles additionally require exact sorted USTAR headers,
zero ownership/time and empty owner names, matching deterministic assembly. A future transport with different metadata needs review, not silent
normalization of its original bytes.

## Local verification

`verify-retained-qualification.py` is a read-only consistency consumer. Supply
clean, separate source/tooling checkouts, the complete qualification directory,
the complete candidate directory/archive and independently obtained expected
identities. Tracked worktree bytes are checked directly against admitted Git
blob identities, independently of index optimization flags. Its output deliberately reports
`external_execution_verified=false` and `publication_authorized=false`, even
when content is consistent. It is not an upload admission switch.

The assembler requires authenticated Debian and Go module caches as explicit
inputs. It reauthenticates the supplied dependency metadata and passes those
same caches to the unchanged sanitizer. There is no default-cache or network
fallback in this packaging route. Its in-process prepared-assets handle cannot
be reconstructed by supplying a JSON receipt; the handoff consumer revalidates
its exact qualification and A/B inventories before using it.

The focused tests use synthetic payloads and mocked worker commands. The
BuildKit index fixture is derived from pinned upstream 0.32.0 source semantics,
not captured from an actual build or qualification run. Packaging
tests execute the unchanged comparator on synthetic trees; some license and
sanitizer paths are mocked and are not qualification evidence. They do not
claim independent metadata production, a second image scan, an SDK rebuild, or
a real hosted qualification attempt.

## Still required before execution

1. Resolve the retained runner version's eligibility using current official release,
   security and target minimum/offered-version evidence. If ineligible, stop
   and replan. Neither a version upgrade nor an SDK rebuild is implied.
2. Establish the signed T/PR packet, exact workflow blob and dependency hashes,
   exact-head CI and independent review. Keep source C separate from T.
3. Establish the authenticated owner dispatcher and existing credential custody,
   read-only billing/capacity checks and the exact execution/spending decision.
4. Review a closed host/workflow integration that observes build/scan workers,
   seals producer staging, joins them, performs final-image smoke and cleanup,
   sanitizes the complete export before upload, and then creates the sidecars.
   No standalone verifier can grant producer-aware sanitization recognition.
5. Demonstrate finite work/job/cleanup and transfer/storage bounds for all raw
   A/B evidence, cache carry-in and publication packaging. Existing four-CPU,
   memory, swap, PID, storage, reserve and one-attempt safeguards remain intact.
   Existing legacy timings are not feasibility evidence for this new mode.
6. After an actually approved successful Q, require independent grading and
   exact publication approval. The designated operations publisher remains the
   only publisher; publication remains separate from target qualification and
   deployment.

Until those prerequisites close, the source-only functions remain unexecuted
against real retained/candidate payloads. There is no default-workflow fallback,
no automatic retry and no authority expansion.
