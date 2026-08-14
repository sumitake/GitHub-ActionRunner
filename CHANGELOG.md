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

- Made operational reliability, practical simplicity, and clear boundaries
  blocking design criteria; simplified the planned external control plane to
  one signed heartbeat lease, one Cron scheduler, six routing states, and
  authoritative receipt-based cutover verification.
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
  service or parallel state machine. Failed canaries likewise reuse the existing
  draining-to-hosted lease boundary instead of claiming instant cached-lease
  revocation.
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

[Unreleased]: https://github.com/sumitake/portable-ghar/compare/main...HEAD
