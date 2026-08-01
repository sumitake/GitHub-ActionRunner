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

- Clarified the standalone product boundary: consumer repositories and
  development-time collaboration or review tools are optional integrations,
  never Portable GHAR build, test, release, deployment, or runtime
  dependencies.

[Unreleased]: https://github.com/sumitake/portable-ghar/compare/main...HEAD
