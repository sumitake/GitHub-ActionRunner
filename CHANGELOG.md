# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once a first tagged release is cut.

## [Unreleased]

Portable GHAR is currently in the **pre-deployment foundation** phase
(Phase 1): synthetic configuration contracts, enforceable public-source
sanitization, and repository governance, with no runner controller, host
integration, or production deployment target yet. Nothing in this section
has shipped as a tagged release.

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

[Unreleased]: https://github.com/sumitake/portable-ghar/compare/main...HEAD
