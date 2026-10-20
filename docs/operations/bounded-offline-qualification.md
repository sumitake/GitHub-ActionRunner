# Bounded offline candidate qualification

The existing CI workflow has an owner-only manual mode for the reviewed
`codex/runner-dotnet-servicing` branch. It qualifies build artifacts on a
standard disposable Ubuntu hosted runner. It never contacts a target host,
changes a fleet fence, enrolls an observer, touches production runners, or
creates release/deployment authority. The candidate-test plan ends
stopped/disabled at N+2 with operator-led recovery; that is a planning
constraint, not a live transition performed by this workflow.

After source reviews and ordinary CI pass, dispatch the existing CI workflow
on that branch with `bounded_qualification=true`, its exact 40-character
`expected_commit` and `expected_tree`, and conservative `carry_in_bytes`.
Carry-in includes every retained earlier task artifact and the unchanged
3,758,096,384-byte outside-task reserve. Measure it immediately before
submission; moving execution to another VM does not reset the inventory.
Only the repository owner can run this mode, and the checkout must be clean
and match both supplied identities and the dispatch SHA.

Before dispatch, verify the connected caller's Actions write permission and
the actual billing exposure. Standard hosted public-repository compute is
free; do not infer account-wide artifact allowance from repository artifact
counts. Raw evidence is limited to 1 GiB with one-day retention. Account-wide
usage may require the owner's billing access. Do not raise a quota, select a
paid runner, add access, or assume an unapproved charge. The ordinary push,
pull-request and default manual CI behavior remains unchanged.

The preinstalled Go 1.26.9 toolchain must already exist in the hosted image;
no unaccounted toolchain download is allowed. All build descendants share a
transient aggregate cgroup limited to four CPUs, 6,174,015,488 memory bytes,
zero swap and 1,024 PIDs. SDK and BuildKit containers also retain their own
limits. The host supervisor verifies actual descendants, kernel limits, OOM
events, observer heartbeat, Docker writable roots, and physical allocated
storage. Before any task pull, create or import, the supervisor freezes only
preinstalled immutable image-layer payload paths verified through Docker
metadata. It excludes those payloads from traversal and charges every remaining
allocated Docker block, including pending downloads, new layers, container roots,
logs, volumes and metadata. No Docker baseline is subtracted. Reclaimed task
files return their actual allocation; unrelated baseline deletion cannot hide
new task bytes. Owned writable roots are measured in allocated blocks, including
small-file block slack. One traversal covers all allocation roots within a shared
20-second observer deadline. Interrupted, incomplete or late results fail closed
without refreshing the 30-second worker heartbeat. Initial admission allows
that existing 30-second window before any build starts. Ordinary container CI
runs the same read-only accounting preflight against its hosted Docker store;
that probe starts no qualification, container, pull or import. Filesystem free space and
inodes are checked per physical device, and positive filesystem growth supplies
an additional conservative allocation floor. No net-growth estimate substitutes
for the task allocation measurement. The full retained carry-in, new source
copies, caches, outputs and a 64 MiB control reserve count toward an 11.5 GiB
hard ceiling with a 10 GiB early stop, retaining a 1.5 GiB reserve between
the two limits. Writable roots stop at 2 GiB, free
disk at 13 GiB, available RAM at 4 GiB, and free inodes at 500,000; admission
requires 11 GiB available RAM and 700,000 free inodes. Caps cannot be
changed through dispatch inputs. Work ends after 85 minutes, within the
90-minute workflow timeout. An exhausted guard fails qualification.

The selected SDK rebuild uses the existing descriptor and public recipe,
including all three app-local entrypoint checks and exact archive digest.
BuildKit v0.32.0 and the Dockerfile frontend are pinned by digest. The worker
must prove overlayfs support; native fallback is prohibited. All eleven
binaries are rebuilt A/B with fresh compiler caches. All six images are
built A/B serially with fresh BuildKit state for every export. Raw OCI
image-layout directories retain every independent blob and JSON byte from
both exports, and the unchanged release graph verifier checks each layout.
Full layouts, graphs, file inventories, embedded binary hashes and build
stamps must match. Directory export avoids a second temporary archive
extraction during scanning; it does not discard either raw build.

The disposable source clone is acquired from the reviewed local checkout and
detached at the admitted commit/tree. Before full qualification scans, its origin
is set to the exact admitted public repository URL. The acquisition receipt
records the local method and checked-out identity; it claims no remote fetch.

APT verifies the pinned snapshot signatures offline. Only the exact signed
package closure is acquired. Caches are reclaimed only after their users
have joined. After compilation, complete legal documents and the module
ZIPs required by the producer verifier remain available. Source/binary
vulnerability and secret gates remain unchanged; image gates retain only
the existing fixable HIGH/CRITICAL rule. A separate all-severity runner
report must show the seven reported CVEs absent. Fresh Trivy database
identity is checked before and after scanning. Syft is acquired afterward
to reduce peak storage. Scanning runs in a separate nonprivileged container
with the same aggregate limits and task-only mount. Evidence export remains
under the aggregate observer and preflights the full transfer cap before
copying any text. Seventeen fresh SBOMs, complete notices and the
producer-authenticated public sanitizer must pass.

The release-output check scans the seventeen normalized SBOMs used by the
notices generator and the resulting notices. Raw Syft reports remain retained
evidence. The separate evidence publication gate scans those raw reports too;
any withheld text still prevents full qualification.

Producer-aware publication checks run where the pinned producers actually run.
They preserve raw Syft namespaces while recognizing only the fresh random UUID
suffix; the namespace prefix and subject name remain scanned. Known Go legal
citations bind exact module/version/archive/member bytes. BuildKit recognition
is limited to its exact default enum atom in a parsed GC-filter position, with
executable identity checked before and after capture. Trivy Git authors bind
the admitted public commit headers. Debian maintainers and package identifiers
bind signed index stanzas, and installed-file names bind the authenticated
package archive. Advisory values bind exact records in the unchanged public
scanner database before its normal reclamation. Finding fingerprints are
recomputed from the pinned producer's artifact/target/package/vulnerability
formula; an opaque hash pattern alone grants no recognition.
One exact signed-index `adduser` archive, bounded to 1 MiB and charged until
cleanup, supplies the public installed-file-name evidence when absent from the
existing cache.

These checks construct private scan views, then stage unchanged original report
bytes only after the entire view passes. Recognized scalars also retain secret,
encoding and all other checks outside their finite metadata rule classes, on
their original tokens and decoded values. Unknown fields and neighboring text
remain blocking. After both actual workers join successfully, the controller
requires the complete forty-report membership, exact sizes and hashes before
using those staged checks. Other evidence, including late logs and terminal
receipts, still passes the strict publication gate. Missing, changed, extra or
withheld evidence prevents admission. Staging manifests transport those actual
worker checks; a supplied report or standalone receipt grants no authority.

A successful offline qualification still does not supply target D2/D5
facts or authorize a canary. An incomplete, stopped, mismatching or
security-failing attempt produces no release admission. Raw A/B exports
and sanitized verification evidence are retained even for failures. Text
that fails public sanitization is withheld and recorded by digest; its
omission makes the evidence gate fail rather than silently waiving it.

After a guard stops the workers, bounded failure retention may only rename
completed raw exports and write at most 1 MiB of control metadata. It runs
with the same CPU, memory, swap and PID limits for at most two minutes;
it performs no build, scan, download or raw payload copy. Evidence exceeding
the fixed transfer cap remains unadmitted.

The complete raw bundle is retained alongside a separate control artifact of
at most 1 MiB, both for one day. The control artifact copies the original
inventory and selected small public receipts with exact hashes and source
identity; it contains no raw payloads and grants no release admission.
Duplicated receipts count toward the same aggregate 1 GiB transfer cap.
Optional resource samples may be omitted for size, with the omission recorded.
This copy supports checking the result through a size-limited artifact client;
it does not establish a local download and hash check of the complete raw ZIP.

## Failure diagnostics

An explicitly selected `metadata_probe` dispatch runs a prospective producer
diagnostic instead of qualification. Its job has only `contents: read`, a
15-minute timeout and the existing aggregate resource/storage safeguards;
the worker deadline is 10 minutes. It reproduces the local clone and `/work`
mount context, inspects one fresh BuildKit worker without builds, scans tiny
synthetic file/OCI subjects with pinned Syft, and runs pinned Trivy with only
the secret scanner. It downloads no vulnerability database or historical
artifact and performs no runtime rebuild, live operation or qualification.
Ordinary CI jobs and full qualification are skipped for that dispatch.

Native reports and logs stay in the task workspace until cleanup. The only
upload is at most 1 MiB of sanitizer-checked structural diagnostics and its
inventory, retained for at most one day. Matched values and unknown field
names are represented by hashes and lengths; source provenance is compared
in memory. The final observer must pass and all workers must join before
upload admission. Any remaining private text prevents upload. This evidence
cannot recover previously withheld report bytes, clear the earlier failed
qualification or waive the raw Syft publication requirement above. Before a
probe dispatch, fresh capacity and aggregate lifetime storage accounting must
admit its reserved cost within the existing task allowance.

The composed worker sets `SSL_CERT_FILE` to its copied
`/etc/ssl/certs/ca-certificates.crt` bundle. Python HTTPS acquisition therefore
does not depend on the host OpenSSL build's default path aliases being present
inside the worker. Certificate and hostname verification remain required.

An incomplete producer cache grants no metadata or licensing projection. The
exporter validates the original producer registry, dependency cache and runner
license authority before using those projections. If authority is unavailable,
diagnostics use the unchanged strict raw scanner and full qualification remains
unadmitted. Existing source allowlist checks still apply; no fixture exemption
or broad content-rule exception is added.

The three full CoreHost startup traces contain public producer assembly/native
version fields that resemble addresses and one runtime identifier that resembles
a hostname. Their reviewed exceptions use the existing exact path, line, rule
and canonical-line SHA-256 allowlist. The read-only
`scripts/release/audit-startup-trace-allowlist.py` audit binds every exception to
the three dependency manifests inside the descriptor's digest-pinned runner
archive. It requires complete coverage without unrelated findings or stale
exceptions. Other content, contexts and rules remain blocking. Canonical hashing
retains its existing Unicode, line-ending and trailing-whitespace normalization;
the inventory separately hashes every complete original trace byte. Trace
verbosity and the app-local CoreCLR startup proof remain unchanged.

Text is scanned and copied byte-for-byte under its retained logical evidence
name. Fresh Trivy reports have one explicit producer-rendering step before that
gate: the unique root `ReportID` value token is replaced with a domain-separated
SHA-256 identity of every byte before and after that token. All other native
bytes, including findings, provenance, unknown fields, escapes and number
representations, remain unchanged. Each capture uses the joined pinned producer,
pre/post executable and subject identities, and a fresh private working directory.
Native bytes remain intact and charged until ordinary task cleanup. Public
receipts bind native/output sizes and hashes, the original ID hash and method.
The entire rendered report still passes the unchanged privacy gate; no field
recognition, scanner rule or allowlist exception follows from rendering.

The hosted supervisor's ambient `/home` location is not a published file
label. Private paths or sensitive data within the original contents remain
blocking and are withheld. Files that fail policy are inventoried by digest and
size and blocking rule identifiers; their contents are not published. Initial
allocation counters use logical root names while retaining the exact measured
values. Worker containers use a fixed placeholder hostname, and source Git
operations run quietly to avoid collecting ambient paths in successful output.
Diagnostic preservation does not turn a failed build, incomplete resource proof
or withheld text into a successful run.

Build, scan and scope failure receipts contain fixed stage, exception type and
validated HTTP status classifications only. Messages, URLs, headers and
tracebacks are excluded from those receipts. The Debian-input acquisition stage
is recorded before its first request. Raw completed exports remain independent
of diagnostic retention. An additional full attempt requires separate approval.
