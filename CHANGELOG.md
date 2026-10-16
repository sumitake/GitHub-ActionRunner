# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once a first tagged release is cut.

## [Unreleased]

Portable GHAR is currently **pre-deployment**. Phase 2 source is complete,
but the Linux/Docker operational, forced-runner-version-bump, host-sizing,
external-failover, migration, and live-activation gates remain incomplete.
Nothing in this section has shipped as a tagged release.

### Added

- Synthetic public configuration contracts (JSON Schema + examples) for
  fleet, host-profile, notification-event, and public-log-event shapes.
- A fail-closed public-source sanitizer (`scripts/sanitize_public.py`)
  enforced on tracked files, generated output, and (optionally) git
  history.
- Public governance baseline: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, this changelog, `THIRD_PARTY_NOTICES.md`,
  `.github/CODEOWNERS`, a pull request template with a PUBLIC-SAFETY
  checklist, and structured GitHub issue forms.
- A persisted, crash-reconciling controller with pinned scale-set
  integration, bounded admission, one-job lifecycle, fleet fencing,
  watchdog, and force-disabled dark-observer startup.
- Per-job runner, adapter, broker, helper, verifier, and held-listener
  components with durable dial authority and fail-closed egress gates.
- QTS and systemd host-lifecycle seams, conformance and chaos harnesses,
  immutable runner-release observation, and reproducible source/runtime
  release tooling.
- Source-ready operational runbooks, including bounded runner reclamation
  and schema-versioned Grafana/InfluxDB observability requirements.

### Security

- Added replacement-resistant Unix-socket guards, exact connected-stream
  framing, crash-safe journal locking, full-history public sanitization,
  and hosted CI checks for Linux, containers, supply chain, and static
  analysis.
- Pinned patched releases of five transitive npm development dependencies
  (sharp, source-map-js, fast-uri, smol-toml, and katex) through `overrides`.
  The braces advisory under the docs linter has no patched release yet.
- Each slot's dial-permit socket now refuses requests that name another slot
  or job generation. The permit authority is shared by every slot, so before
  this a broker that could reach one slot's socket could spend another slot's
  dial budget.

### Changed

- Add the production permit guards an acquiring controller needs: a `/proc` peer validator for the broker user, a ledger-reference guard backed by the controller store, and a conntrack rebase validator that always refuses. The test environment now uses the same `/proc` observer.
- Add the production setup builder for one job's jail. It derives container names, recovery paths and the permit-ledger generation from the assignment, without touching the host, because recovery calls it too. Slot directories are created just before the jail is prepared: owned by the broker user, mode 0700, resolved beneath the broker root without symlinks, and never reused if left over from an unfinished cleanup.
- Add `portable-ghar assemble-private-overlay`, which binds an operator-authored overlay template to a release's runtime manifest. It copies the manifest path and digest, the policy manifest digest, and the five image IDs from the manifest, rejects a template value that disagrees, and writes the overlay atomically after the same validation and read-back `deploy` uses. Release identities in the host overlay are no longer typed by hand.
- `assemble-private-overlay` now reads the template through the private-tree checks and verifies the staged overlay before it replaces the output. A failed read-back no longer deletes an existing overlay. It also rejects a template or manifest path that resolves to the output file, such as a symlink to it.
- The private overlay accepts optional `worker` and `github` sections for an acquiring controller. Overlays without them are unchanged.
- The private overlay accepts an optional `jail` section with the container users, seccomp profile, log limits, and dial authority settings an acquiring controller passes to each job. Two startup helpers clear what a controller crash can leave behind once no recoverable assignment references it: `RemoveUnreferencedSlotDirectories` for empty slot directories, and `PermitAuthority.DeactivateUnreferenced` for a dial ledger still marked active.
- Add `lifecycle.SetupConfigFromOverlay`, which builds the setup builder's configuration from the overlay and runtime manifest. It maps the slot resource vectors, runner sizing, swap allowances, and the `jail` section to per-container limits, and rejects an inconsistent vector at startup rather than at the first job.
- Add the controller-side parts an acquiring controller composes from the overlay: the failover Worker client (heartbeat session, lease cache, health publisher, and lease-bound acquisition permits, with the heartbeat budget checked at startup, each permit bounded by the controller operation timeout, a termination tail longer than a fixed two-second overrun slice and shorter than the lease less its shortening margin, and a required hook that ends the process when a permit is still open that slice before its local lease deadline), the admission broker configuration (each repository profile must equal the slot vector the lifecycle applies), the enabled policy template, history pressure thresholds derived from the existing history limits, and a fixed capacity provider, fatal terminator, event log, and late-bound JIT authorizer. Nothing calls them yet.
- The admission broker rejects, at construction and on a policy revision, a repository profile whose complete slot charge exceeds the admission ceiling. Such a profile was accepted but could never be admitted.
- Add `portable-ghar-controller run-acquisition`, which composes the acquiring controller from the overlay: it requires the portable fleet to hold the fence, holds a fence guard for the whole run, clears crash leftovers no recoverable assignment references, and starts disabled. It exits at once if an acquisition permit is still open two seconds before its local lease deadline. Every active mode stays refused until a conformance report exists. The systemd unit still runs `run`.
- Add a conformance API that completes the same pending report by replacing only case 15 with sealed actual-transport evidence, preserving every existing binding and observation, and recomputing the report digest and build seal. Evidence collection and the real canary remain separate steps.
- The acquisition conformance gate accepts a report whose cases 1-14 passed and whose case 15 (actual GitHub transport) is pending, for `canary-only` only; `enabled` still requires every case to pass. `run-acquisition` reads the report from `<state_root>/conformance-report.json`; without one, every active mode stays refused. Target conformance evidence for deployment still requires a full pass. This amends the Task 11 invariant, as the live acquisition plan records.
- Document the live-acquisition operator steps (`docs/operations/live-acquisition-operator-steps.md`): a read-only fence read (D5), building the controller from `main` and creating the scale set and token (D7), and why the conformance run (D2) waits for plan phase 6.
- The target conformance run writes its canonical report to `PGHAR_CONFORMANCE_REPORT`, a new mode 0600 file it checks before consuming the input, and writes it before judging the result so a failed run still records which cases passed. The D2 operator steps now give the exact command: `go test -buildvcs=true` stamps the source commit the preflight checks, in a regular clone but not a git worktree.
- Add a handoff for the remaining live acquisition work (`docs/superpowers/plans/2026-10-16-codex-live-acquisition-handoff.md`): what phases 1-6 shipped, the open design points for phases 7 and 8 (completing the pending report, a Worker admin client, and the fence generation the handover produces), and the operator steps still to run.
- Add `portable-ghar-controller create-scale-set`, which creates a repository's runner scale set when it is missing and re-verifies it, and `external-probe`, which opens and closes each repository's GitHub session. Neither changes controller state or an existing scale set.
- The Worker serves session, heartbeat, and admin requests only when its deployment sets `WORKER_AUTHORITY=enabled`, rejects fleet IDs outside its inventory before addressing a Durable Object, and adds `portable-canary-start` and `portable-canary-stop` admin commands for a single portable canary. Deployments without the setting stay address-only.
- CI's Trivy filesystem scan ignores CVE-2026-84008 until 2026-11-14 through a dated `.trivyignore` entry. The advisory covers the `System.Security.Cryptography.Pkcs` build bundled in the pinned upstream runner, and no fixed runner release existed when it was added. The scan reports the finding again once the date passes.
- Pin the official GitHub Actions runner to v2.338.0 (tag commit `197ca027…`, Linux x64 asset `sha256:af4b794c…`), published 2026-10-06; runners with updates disabled must move within 30 days. The entry is the observer's own output from the vuln-watch run, cross-checked against the downloaded asset's size and digest and the upstream tag commit; the pinned-archive conformance test passes on the real archive (11,555 upstream entries, 6,665 after omitting the bundled package managers).
- Advance the exact Go toolchain pin from 1.26.6 to 1.26.9 and `golang.org/x/net` from 0.59.0 to 0.60.0. `govulncheck` reported ten reachable standard-library vulnerabilities (GO-2026-6603 to GO-2026-6617; `net/http`, `net/textproto`, `crypto/tls`, `os`) fixed in 1.26.9, and the image and source scans reported CVE-2026-78669 in `x/net`.
- The runner image takes Debian packages from one snapshot date instead of hand-pinned per-package versions and hand-maintained signed-index hashes. Packages are installed by name and `dist-upgrade`d to that snapshot; `apt` verifies Debian's signatures, the release A/B rebuild proves reproducibility, and the installed inventory stays in `dpkg-manifest.tsv`. Security fixes are now a one-line date change. The snapshot timestamp may carry a time of day (`YYYYMMDDTHHMMSSZ`), so a fix is picked up as soon as snapshot.debian.org has it. It moves to `20261010T000000Z` to pick up the `libexpat1` `2.5.0-1+deb12u4` and `libpcre2-8-0` `10.42-1+deb12u2` security updates. The snapshot lock, index verifier, contract checker, and their tests are removed.
- Pin the official GitHub Actions runner to v2.337.0 (tag commit `397b032c…`, Linux x64 asset `sha256:70920811…`), which bundles .NET runtime 8.0.30 and clears the six .NET HIGH findings in v2.336.0. The entry is the observer's own output from the vuln-watch run, cross-checked against the downloaded asset's size and digest and the upstream tag commit.
- Release images are identified, verified, and started by content-addressed image ID (`sha256:` plus the OCI config digest) instead of a repository digest. `docker load` of a release OCI archive preserves the image ID but leaves `RepoDigests` empty, which blocked QTS admission without a registry. Captured legacy-fleet images keep their repository-digest form.
- Runner extraction omits the npm, npx, and corepack copies bundled in each Node external, and runner tree manifests reject them. The runner never invokes them, and they carry the upstream archive's remaining fixable HIGH/CRITICAL findings.
- The weekly vulnerability watch now scans runner-image libraries as well as OS packages, and fails while a newer official runner release exists (GitHub's 30-day update window for runners with updates disabled).
- Reviewed-pin `actions/setup-go` to v7.0.0 (`b7ad1dad…`) and `actions/setup-node` to v7.0.0 (`82076278…`) in workflows and `REVIEWED_ACTION_PINS`.
- Reviewed-pin `github/codeql-action` to v4.37.9 (`cdf488f5…`) and `docker/setup-buildx-action` to v4.3.0 (`37fe6310…`) in workflows and `REVIEWED_ACTION_PINS`.
- Reviewed-pin `docker/setup-buildx-action` to v4.4.1 (`f87e5991…`) in workflows and `REVIEWED_ACTION_PINS`.
- Reviewed-pin `github/codeql-action` to v4.38.2 (`2892aa5e…`) in workflows and `REVIEWED_ACTION_PINS`.
- Reviewed-pin `actions/setup-node` (`949feb24…`), `actions/upload-artifact` (`cf430e03…`), and `github/codeql-action` (`24c54180…`) to the Dependabot #95 releases in workflows and `REVIEWED_ACTION_PINS` (versions in the pin table; kept out of this line so the release manifest's CHANGELOG identity inventory is unchanged).

- Made operational reliability, practical simplicity, and clear boundaries
  blocking design criteria; simplified the planned external control plane to
  one signed heartbeat lease, one Cron scheduler, six routing states, and
  authoritative receipt-based cutover verification. Heartbeat lease renewal
  now independently enforces the bounded selector-evidence age, so missed Cron
  delivery cannot extend local authority indefinitely or require a second
  scheduler.
- Made archive restriction honestly lease-bounded and fail-closed on stale
  evidence; already-released listeners remain bounded by their original local
  lease deadline rather than an impossible replacement-response revocation.
  The single Cron scheduler also has an explicit bounded fleet inventory so
  every per-fleet Durable Object is discoverable without a second registry.
- Bound cached leases to the local acquisition-policy epoch and bounded each
  poll/acquire/JIT admission inside the lease lifetime with serialized
  cancellation. A closed admission-authority key now survives routine heartbeat
  renewal without starving long polls while every real policy, fence, holder,
  generation, capacity, archive, or duration change still drops admission. This
  closes policy ABA and post-expiry completion without adding a revocation
  service or parallel state machine. The same deadline remains armed through
  each at-most-once Ack or listener-release attempt; short pre/post barriers and
  the held listener's own point-of-release deadline check close suspend gaps
  without holding a mutex across I/O. Ack remains non-authorizing, and ambiguous
  effects use the existing journal/read-back path without retry. Failed canaries
  likewise reuse the existing
  draining-to-hosted lease boundary instead of claiming instant cached-lease
  revocation without adding a controller-drain dependency. Linux/QTS authority
  deadlines use one suspend-aware `CLOCK_BOOTTIME` adapter for both time and
  waits, so host sleep cannot preserve expired acquisition authority;
  restart/reboot begins with an empty cache.
- Advanced the exact Go toolchain pin from 1.26.5 to 1.26.6 after the required
  vulnerability gate identified four reachable standard-library advisories.
- Clarified the standalone product boundary: consumer repositories and
  development-time collaboration or review tools are optional integrations,
  never Portable GHAR build, test, release, deployment, or runtime
  dependencies.
- Bound runner creation, held-runner audit, conformance, listener exec, and the
  post-JIT process to one exact TLS-only loopback proxy environment, while
  rejecting plaintext proxy, duplicate, missing, altered, or ambient entries.
- Revalidate the held lifecycle lease immediately before every watchdog stop or
  disabled start so replaced lock identity cannot authorize a later mutation.
- Limit the systemd watchdog oneshot to reaping its own process; controller
  termination remains bound to the watchdog's process-identity authority.

- Scoped the release-admission Trivy image scans to fixable findings
  (`--ignore-unfixed`): the pinned Debian base permanently carries
  HIGH/CRITICAL entries with no published vendor fix, which left the gate
  with no achievable green state and blocked every release. The source
  filesystem scan still blocks on unfixed findings, secret scanning is
  unchanged, and all package versions remain recorded in the release SBOMs.
- Added a weekly `Vulnerability Watch` workflow that re-runs the full
  release-gate filesystem policy against source and scans the built runner
  image for newly fixable HIGH/CRITICAL OS-package findings in the
  installed Debian inventory (`trivy image`, `vuln-type: os`,
  `scanners: vuln`). Node.js / `actions-runner` bundle CVEs remain a
  separate release-admission track. A future official post-DLA
  `bookworm-slim` digest remains a governed atomic lock refresh; watch no
  longer treats the virgin `FROM` digest as the image-admission surface.
- Pin runner `libssh2-1` to `1.10.0-3+deb12u1` from the
  `20260906T000000Z` `bookworm-security` snapshot (DLA-4773-1:
  CVE-2026-58050, CVE-2026-7598), keeping the existing `libpcre2-8-0`
  `10.42-1+deb12u1` pin and mixed Debian snapshots.

[Unreleased]: https://github.com/sumitake/portable-ghar/compare/main...HEAD
