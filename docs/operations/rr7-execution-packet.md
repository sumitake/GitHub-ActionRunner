# RR7 replacement-runner execution packet

Status: engineering preparation only; no build, Actions dispatch, target boot, job, credential or service change performed. This packet supersedes the proposal to prepare a build-only entry point: that entry point is now implemented in this patch. Product inputs remain the already qualified source, not current main.

## Phase A — reconstruct exact missing payloads

Builder: the existing **GitHub-hosted `ubuntu-24.04` x64 pool** for public `sumitake/GitHub-ActionRunner`. Authorized metadata confirms actual successful repository Go/container jobs on this label (run 39681587311), and official current runner-image metadata `ubuntu24/20261012.334` lists Go **1.26.9**, Docker **28.0.4** and systemd **255.4**. This identifies a real supported pool; no VM is reserved or runtime preflight claimed. The job must still positively admit its actual toolchain, Docker/cgroup/overlayfs, memory, disk and inode state before any build. It must fail rather than install tools, use `ubuntu-latest`, select self-hosted legacy capacity or change settings.

Publish the independently reviewed tooling patch through the project's normal signed-source process to **`codex/rr7-payload-reconstruction`**, pin its actual commit and tree, and dispatch **the already registered `.github/workflows/ci.yml` (CI)** once as the repository owner. Publication, any automatically triggered CI, and dispatch are pending execution actions; none is authorized by this preparation alone. The existing CI workflow is already registered (workflow ID313566742) and has a manual trigger; the proposed branch definition adds a closed reconstruction selector. No new workflow registration or default-branch merge is proposed. Confirm that registered workflow and the exact reviewed branch still match before dispatch.

Closed dispatch inputs:

```yaml
bounded_qualification: false
metadata_probe: false
payload_reconstruction: true
expected_commit: <actual reviewed/signed tooling commit>
expected_tree: <actual reviewed tooling tree>
carry_in_bytes: <fresh retained allocation, including fixed reserve>
```

The workflow checks out tooling and product separately. Product is fixed to commit **874fcc9557166d94a97026ae7c966c99fa598fa9**, tree **8fbc190401b664d434bb405303efd714e0fce1aa**. A clean Git checkout and exact modes are required; the recovered group-writable source tar is immutable evidence, not an executable checkout. The host command is:

```sh
sudo --preserve-env=<the fixed workflow whitelist> /usr/bin/python3 \
  tooling/scripts/release/qualify-runtime.py \
  --reconstruction-host "$RUNNER_TEMP/payload-reconstruction" \
  --source "$GITHUB_WORKSPACE/product" \
  --event "$GITHUB_EVENT_PATH" \
  --go-root "$RUNNER_TOOL_CACHE/go/1.26.9/x64"
```

Exactly one generation of eleven Linux/amd64 binaries and five consumed OCI layouts is built. The original supervised SDK recipe supplies the digest-pinned serviced runner archive and its existing benign three-entrypoint/CLR checks. The original Go flags, source epoch 1792478220, linked identity, signed Debian snapshot, BuildKit/frontend, CA and image recipes remain. The standalone parser image is not rebuilt because the consumed broker already contains the parser binary. The exact **63 files / 455,533,293 content bytes**, complete graphs and embedded stamps must equal `release/reconstruction-identities.json` (SHA256 **cf457df91c94f6afdd0edf88b2be7b202d97dd7af4906446fe05aa52e028b8a6**). All original six-image/A/B qualification evidence remains retained.

The same four-CPU/6,174,015,488-byte/zero-swap/1,024-PID aggregate guard covers SDK, BuildKit, copying, hashing and export. Both input checkouts are charged, alongside Docker allocation and task output. Keep 10GiB early/11.5GiB hard ceilings, reserve and RAM/disk/inode floors, observer freshness, 85-minute worker/90-minute job limits and task-owned cleanup. No scan/qualification worker runs in reconstruction mode. Qualification's default A/B/scanner/privacy path remains intact. A separate fixed comparison receipt explicitly says qualification, release admission and target conformance were not executed.

Only matching previously qualified payload bytes and fixed comparison/inventory/result records may be uploaded; new native logs and host metadata remain private. Host final resource/join proof must pass, private diagnostics must be locked down, and a second complete file/hash/membership check must pass in a read-only two-minute scope with the same CPU/memory/swap/PID limits before the upload check returns ready. Keep one-day retention, and save the accepted payload artifact plus original control and new provenance through a supported durable Library route immediately. A new transport archive has its own hash; do not claim recovery of the old raw ZIP. Establish supported transfer capacity before running, without splitting around a denied transport or changing retention/access policy.

Fresh owner/billing admission is required for this new run and artifact lifetime. Historical $0.10 reserve accounting is not a new spending allowance. Use no paid runner, quota increase, new account, permission or credential. Stop on any mismatch, resource/observer failure, missing tool/input, failed cleanup, unsupported transfer or new terms; retain diagnostics locally, return failure and do not rerun qualification automatically. Cleanup affects only the run-labelled containers/cgroup and task-owned temporary state; no target or legacy rollback is needed for an offline failure.

## Phase B — one bounded candidate preparation session

Re-use the verified cold recovery and accepted RR7 underlay. Bind only LabMacPro owner **agent UID502**, home **/Users/agent/.lima-candidate2-20261020**, VM **ccg-runner-candidate2-20261020**, pinned `/Users/agent/.local/lib/lima/rr7-candidate-e96e78a32f5a/bin/limactl` SHA256 **e96e78a32f5a59439918a3b55d4f502572c28b007114b1a88379a2291d9f5971**. Recheck stopped state and false YAML SHA256 **08d1002d85ed6567d12bd8f571499ad224b0511ed1910210bbb63b607b6b3333**, backup integrity and fresh physical-host reserves before mutation. Existing management SSH key/fingerprint proof is sufficient; create no additional key or access route.

A later approval must cover boot, installing the reconstructed Linux tools/images inside this candidate, and its concrete guest configuration. First verify the actual guest Docker/systemd/jail prerequisites without downloads. Their presence is not established by RR7; if absent or incompatible, stop and prepare exact official dependency versions/pins and installation scope rather than run a convenience installer or silently expand access. Import only validated payloads; inspect actual Linux/amd64 image IDs against the recovered OCI config digests, separately retaining manifest/index/layer evidence. Pin a fresh named guest-local install directory and rollback selection before copying; do not overwrite another runtime, the existing Lima installation or recovery copy. Run the source's image-verification and benign runner-version checks, not an untrusted job.

Before installing/initializing a fence, read the selected actual Linux profile/overlay, fence root and any store/holders. Only a valid inspector can establish an existing generation. Clean uninitialized state may support an explicitly approved bootstrap; absence is not observed generation zero. Partial/conflicting state, unknown holders, shared paths or a changed profile stops mutation. Preserve all seven shared legacy containers, four respawn loops and native runner; do not stop shared Colima/Docker or infer idle from a process snapshot.

The remaining concrete private bindings must be produced from actual receipts in this session: authenticated BuildID; trust/seccomp/policy/resource/log digests; selected private paths/profile; observed fence domain/generation; candidate-only concurrency/resource ceilings; persistent pinned launcher and outside-guest network/resource/shutdown lifecycle. The temporary RR7 fence/guard were removed after acceptance and do not grant an unattended launch. Keep hostLoopback false and independent outer isolation active for every job-bearing boot. Do not insert the repository's test overlay values or silently enable general egress. Phase B must end stopped/disabled if these bindings are incomplete; do not request broad cutover authority to compensate.

## Phase C — D7, one D2 report and one governed canary

Use the existing supported controller/Worker/canary code rather than another framework. Freeze a single owner-controlled repository/workflow and a unique one-name scale-set label, default runner group, DisableUpdate true and both-direction eligibility excluding generic/legacy work. No actual canary repository/label/credential/Worker binding is recovered yet, so no API call or dispatch is ready until those exact selectors are recorded and reviewed. Do not retry the historical runner API 403, read legacy `.runner`/token files, or widen credentials after refusal.

**Potential new persistent access/effects to approve together, if required:** a repository-scoped GitHub PAT stored only as a root-owned0600 guest secret; the corresponding repository scale set and dedicated workflow change; the exact pilot Worker deployment/service bindings and credential relationships if no compatible existing deployment is verified; and the candidate's persistent launcher/outer isolation lifecycle. No new host SSH key, sudo/socket grant, general egress, target account, production registration or legacy permission change is included. Private credential values are never printed or put in this packet. Resolve live compatibility via the existing `create-scale-set`/`external-probe` path only after that scope is approved; those calls create resources/message sessions and are not read-only inventory.

Freeze source/runtime/overlay/input/authorization/profile/network/plan digests and intended generation before running the existing `TestPortableGHARConformance` harness once on the actual candidate (clean regular clone, integration Docker environment, `-buildvcs=true`, no `-trimpath`). Require cases1–14 and cleanup passed, case15 pending; preserve canonical root0600 report and private consumed-input copy. Reuse source reviews, offline qualification and RR7. Keep the same manifest/generation binding into the planned transition; stale-generation reports do not survive a return transition.

Then run one explicitly approved governed JIT canary through the existing canary-plan/bind/status/seal, Worker lease and one-job route. Retain actual GitHub transport, current Compatibility/DisableUpdate, tools, deregistration and reclamation evidence; no alternate JIT shortcut or extra replacement job. The controller watchdog's bounded source procedure does not suspend VM/network/resource safeguards. On failure/timeout/uncertainty stop acquisition, preserve the journal and perform only the recorded candidate-scoped stop/reversal. Finish candidate stopped, hostLoopback false and acquisition disabled at the actual recorded return generation. Remove tracked temporary exceptions/listeners and verify cleanup. Restore the known candidate configuration/runtime selection or use the verified cold recovery only through the precise approved rollback; never roll legacy services or cancel their work back.

**Production jobs, routing cutover and legacy retirement remain excluded.** No phase may infer the unresolved private bindings or proceed through its stopping conditions. This is one consolidated path with hard gates, not approval of unknown access or a promise that source preparation alone proves target acceptance.
