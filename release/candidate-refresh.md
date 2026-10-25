# Bounded runner version refresh build

This manual development mode builds a new candidate. It never claims to recover
original qualified bytes, execute qualification, admit a release or pass target
conformance. Historical reconstruction identities remain separate. The adopted
retained-SDK payload is not admitted through legacy qualification/reconstruction
hosts; those hosts stop before acquisition or compilation.

The independently reproduced SDK A/B output is now bound by the canonical
`runner-rebuild.patch`, descriptor, notices and retained provenance together.
Before publication, establish the authenticated hosted input and its approved
availability lifecycle described in [retained-runner.md](retained-runner.md).
No placeholder digest
or disabled archive guard is accepted. The new mode rejects the old SDK digest,
changed compiler/runtime/upstream inputs, source patch or reviewed smoke code.
The earlier source-only SDK checker remains historical source-boundary evidence;
its immutable standalone bundle is retained with that evidence, not product-image
acceptance. Do not rerun it merely to regenerate historical proof after adoption.

After a signed source revision and normal CI, use the existing CI workflow on
`codex/rr7-runner-version-refresh` with exactly these dispatch inputs:

- `candidate_refresh`: `true`
- `payload_reconstruction`, `bounded_qualification`, `metadata_probe`: `false`
- `expected_commit`, `expected_tree`: the actual reviewed signed source identities
- `carry_in_bytes`: freshly measured retained allocation plus the existing reserve

This mode requires a public owner dispatch on standard hosted Linux x64,
first attempt, exact clean checkout and Git file modes. It accounts the pinned
Go1.26.10 archive/extracted compiler and consumes the exact prior SDK archive
with its exact public verification receipt; originals stay private. No SDK build or Restore executes. Prior app-local
CLR startup and unconfigured Listener help results remain prior producer evidence,
separate from this run's final-image smoke. It builds eleven stamped binaries and five consumed OCI
layouts in fresh A/B phases, compares them, checks embedded identities and keeps
unaffected immutable layers bound to original evidence.

The actual retained runner OCI export is loaded into the disposable builder.
Its inspected Linux/amd64 image ID must be a verified index, manifest or config
digest from that exact export, covering Docker storage backends. Loaded config
and RootFS diff IDs must match the authenticated OCI config; aliases must resolve
to one local image. All graph digests and the observed local ID enter the receipt.
A private compiled test calls production `ReleaseArtifactVerifier.SmokeRunner`;
the rehearsal helper performs the same direct version probe. Both use UID/GID
65532, network-none, read-only root and private `/tmp`, no `/runner` or credentials.
Tracked names, cgroup/label and pull-never are added by a closed Docker wrapper;
no host libraries/account files are injected. Ordinary tests skip the real-image
probe unless the builder explicitly opts in. The temporary image and containers
must be removed before a smoke receipt can pass.

The existing aggregate CPU/memory/swap/process/storage/reserve observers remain
active, including retained inputs and final-image Docker children. This mode has110minutes
work within a120minute hosted job, leaving10minutes for cleanup. No cancellation
or failure grants a retry. Only tracked disposable work may be cleaned up; the
host daemon and unrelated jobs are never stopped. Every other mode retains its
existing deadlines. An explicit false selector is stripped before legacy closed
input validation; true/mixed selectors cannot enter a legacy mode. Ordinary
container CI uses the same retained archive without an acquisition fallback.

The complete transfer is rehashed in a separate bounded scope before upload.
Only eleven binaries, five OCI layouts, the actual SDK archive and closed
provenance/inventory/resource/image-smoke receipts are admitted. Content is capped
at1GiB (2GiB billing reservation), one-day retention, no overwrite. No target
credentials, host records or live runner jobs are inputs or outputs. Full SDK
A/B, ordinary CI, final artifact review and later target/cutover safeguards remain
separate evidence; the generated receipts keep all admission/live-operation flags
false. The new build mode alone is not a permission to dispatch it.
