# Retained SDK input for the runner version repair

The descriptor selects the prior independently reproduced archive
`8c6ad1f743c97ab650b5c149bda95386a2b6d290b90fa8e0ea732ae89b67eee9`,
220723614 bytes. The original source-pinned provenance binds both SDK outputs,
payload manifests, source/compiler inputs, startup/help results and cleanup.
Its reference SDK image was not executed. Consuming the archive performs no
new SDK build, Restore or current-run SDK startup test.

## Public receipt and private originals

`retained-sdk-verification.json` is the exact canonical public projection. It
retains archive/source/compiler bindings, prior identical A/B and app-local
startup/help/cleanup claims, and hashes of the preserved original evidence.
Its role is `unqualified-sdk-input`; qualification, release admission, target
conformance and live-operation flags are false. It is a reviewed assertion
about prior evidence, not a replacement execution of that evidence.

The private33-file proof stays unchanged and private. Offline, the derivation
entrypoint verifies every original hash, exact membership and cleanup before
emitting the already reviewed receipt. It never executes an input. Boot/daemon
identifiers, raw traces and the producer worker source are not distributed.
The original proof manifest hash remains bound in the public projection.

The unchanged sanitizer reported5172 findings across12 raw proof files:2
operational-ID findings,28 path findings,5133 IP-pattern findings and9 hostname
findings. Sampled path/version patterns include vendor documentation paths and
assembly versions; these observations are not blanket suppressions. No raw
record, sanitizer rule, allowlist or fixture policy is changed by projection.
The exact public receipt passes the same scanner. The producer reported no
content-based blocker in its bounded assessment of the exact archive's
redistributable runtime scope. All5776 member files matched the retained
manifest. Upstream binaries retain producer profile/build strings and debug
paths, so the archive is not path-free. The assessment is not arbitrary-secret
proof or full release qualification. Its public-safe summary is2177bytes,
SHA256 `59aa25dacc85d15fd4f2633e814c34b00f5e54b0d20b1ea29b562f333e5a2c4d`.
That result was relayed to the source owner; its exact summary bytes were not
transferred here. Receipt derivation alone makes no public-distribution claim.

## Digest-bound public release input

`_retained_runner.py` accepts only two files in `.retained-sdk-input`: the exact
archive basename and `sdk-verification.json`. It checks source authority,
receipt bytes, archive size/hash, canonical regular single-link files and stable
identity. Staging reuses the existing checked archive copier. Missing/changed
input fails with no acquisition or SDK fallback. Candidate export/upload binds
this prior evidence separately from fresh Go/image A/B and sealed-image smoke.

The public reader requires an exact repository/release/tag/signed-commit binding,
a published immutable prerelease and exactly those two asset names. Server
sizes/digests and downloaded bytes must agree with source pins. Only public GETs
are used. No workflow token, Library reader, short-lived Actions artifact, new
account or hosted bootstrap job is needed. Redirect authority is checked before
following a single official asset-host redirect. Transport and output are bounded;
partial failures stay visible and cannot trigger a retry or fallback.

`retained-runner-input.json` deliberately has null release bindings. It fails
before network or output until a real approved publication has been read back.
No asset ID, publication, permission, pricing or archive-publication approval is
implied by these source changes. The prior403 immutability-settings read remains
unresolved; this reader does not call that endpoint or bypass that denial.

## Publication sequencing: two separate releases

For this public-input route, staging and publishing an immutable SDK input before
CI and subsequently publishing the completed candidate require two distinct
immutable releases. Assets cannot be added to the first after publication.
The additional SDK-input publication and signed consumer-binding revision were
approved on2026-10-24. That extension grants no new credentials, access, SDK
build, hosted attempt or budget.

Keeping one draft open until the final candidate exists would avoid a second
immutable publication, but public ordinary CI cannot consume that unpublished
input. A private draft-consumer route would be a different access/authority
contract and is not implemented. The existing candidate publisher expects
completed downstream artifacts and describes a qualified runtime bundle; it
must not be repurposed unchanged to label an SDK-only input qualified.

## SDK-only publisher role

`publish-runtime-release.sh --release-kind sdk-input` reuses the existing
publisher's separate settings-read and release-write credentials, repeated live
immutable-setting checks, resumable draft, fixed tag/ref proofs, asset byte
readback and terminal immutable-release verification. It accepts the exact
two-file directory already validated by `_retained_runner.verify_inputs`:
the pinned archive and canonical `sdk-verification.json`. Raw proofs and
`provenance-subjects.json` are not release assets for this role.

The repository is fixed to `sumitake/GitHub-ActionRunner`. The tag must be
`runner-sdk-input-<full archive SHA256>-<full target commit SHA>`. The target
commit must be signature-verified by GitHub before any mutation and whenever
the tag is proved. The release is an unqualified prerelease, never latest;
every uploaded asset requires a matching server SHA256 digest and downloaded
bytes. The canonical six-field consumer locator is emitted on stdout only
after successful terminal readback and local credential-file cleanup. A
failure emits no locator and makes no automatic new attempt.

The existing `runner-release-candidate.yml` manual workflow now has one isolated
`sdk-input-publication` job. Select only `sdk_input_publication:true`, with the
exact reviewed signed `expected_commit` and `expected_tree`. Its job and first
step require the existing observer actor, the fixed runner-version-refresh
branch, first run attempt, fixed repository and exact source identity. The
ordinary observer/build/attestation/publisher path is skipped for that mode;
its default manual and repository-dispatch behavior remains separate.

The job verifies the source and metadata before minting the existing
repository-scoped Release App's `administration:read` token. The separate job
`GITHUB_TOKEN` has `contents:write`. No token is exported to the producer, and
no owner settings-file bypass is supported. The pinned App action normally
revokes its installation token at job end; its server expiry is one hour.
The entire publication-only job has a 45 minute ceiling and creates no Actions
artifact or cache. It performs no SDK build or qualification.

In `--producer-upload true` mode the publisher loads only source-bound expected
asset metadata, verifies the signed target, proves the live immutable setting,
and creates/reconciles one draft with its exact tag. It announces the draft ID
and URL, then polls for up to 30 minutes at 15 second intervals. The producer uses
its separately existing native `gh release upload` credential to attach only
the pinned archive and receipt to that existing draft tag, without `--clobber`.
That producer credential's effective write permission is not assumed from its
read-only identity/admin projection. The actual approved upload may fail; no
write probe, token export, identity switch or new credential is required.

The job never uploads, deletes or replaces producer assets. It refuses extra,
malformed or mismatched assets, leaves partial/starter state on timeout, and
uses the original publisher's byte readback and immutable finalization only
after both exact assets are uploaded. Only terminal success emits the consumer
locator. An uncertain write is reconciled before any new attempt.

This job is prepared source, not authority to execute it. Independent review,
current configuration availability, admission of the distinct producer upload,
exact source/ref/run, and the total storage/trigger ledger remain required
before dispatch or action-time token issuance. Publishing the SDK-job source
before the later signed consumer binding can add an ordinary CI cycle; count
it explicitly. Job-token ref writes suppress recursive push runs; producer
asset uploads change no Git refs and no configured workflow listens to release
events. Do not reuse the build-first final jobs or add a bootstrap artifact.

Ordinary container CI and candidate-refresh share this input contract. Legacy
qualification/reconstruction and direct selected-SDK rebuild paths stop before
expensive work. Existing archive/compiler authorities, allfalse admission flags,
10GiB early/11.5GiB hard storage bounds and kernel/reserve/deadline guards remain.
The public download preserves the earlier conservative storage reservation even
though it no longer stages ZIPs. The hosted job still has its120minute ceiling;
no new retry, build or spend allowance is granted.

Generate tree/runtime locks and READY only through the existing authenticated
extractor and published-tree readback. Never edit old READY or locks manually.
D2/D5/D7 and all target/legacy transition gates remain separate.
