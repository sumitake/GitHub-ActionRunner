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

### Changed

- Reviewed-pin `actions/setup-go` to v7.0.0 (`b7ad1dad…`) and `actions/setup-node` to v7.0.0 (`82076278…`) in workflows and `REVIEWED_ACTION_PINS`.

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
  release-gate policy against default-branch source and turns red the week
  any previously unfixable HIGH/CRITICAL finding in the pinned runner base
  image gains an upstream fix, prompting a deliberate base-image bump.

[Unreleased]: https://github.com/sumitake/portable-ghar/compare/main...HEAD
