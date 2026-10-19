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
storage including Docker data growth. The full retained carry-in, new source
copies, caches, outputs and a 64 MiB control reserve count toward a 10 GiB
hard ceiling with an 8.5 GiB early stop. Writable roots stop at 2 GiB, free
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
