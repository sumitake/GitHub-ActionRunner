# Security Policy

## Project status

Portable GHAR is **pre-deployment / experimental**. The repository
contains the Phase 2 source implementation of the local controller,
isolation runtime, host adapters, and release/conformance tooling, but
positive Linux/Docker operational evidence, host sizing, external
failover, migration, and live activation remain separate gates. There is
currently no project-operated, network-reachable instance of this
software; the public security surface is the source tree, its CI pipeline,
its supply chain, and any independently built experimental artifact.

That said, we still want to hear about anything that looks like a
vulnerability -- in the code, in the CI/release pipeline, or in the
sanitization tooling that keeps deployment-specific data out of the public
repository.

## Reporting a vulnerability

**Report vulnerabilities only through GitHub private vulnerability
reporting.** Do not use any other channel.

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability** to open a new private security
   advisory.
3. Describe the issue using synthetic, sanitized examples only (see
   [CONTRIBUTING.md](CONTRIBUTING.md) for what "synthetic" means here).
   Do not attach real logs, real configuration, real runtime state, or any
   other deployment-specific material to the report.

GitHub private vulnerability reporting creates a private discussion thread
scoped to the maintainer and the reporter, so this is the only channel that
keeps a not-yet-fixed report out of the public issue tracker. We do not
provide an email address, a chat channel, or any other reporting path for
vulnerabilities, and reports submitted through public issues, discussions,
or pull requests will be redirected to private reporting instead of
triaged in place.

## What to expect

Because this is a pre-deployment project maintained by a single owner,
response times are best-effort rather than SLA-backed. We will acknowledge
a new private report, ask any clarifying questions we need, and coordinate
a disclosure timeline with the reporter once a fix is available.

## Scope

In scope: this repository's source code, build/test tooling, sanitization
and CI/CD configuration, and any release artifacts it produces.

Out of scope: any personal infrastructure, network, or deployment the
maintainer may run privately. Nothing about a private deployment is ever
appropriate content for a report against this public repository --
findings should be described using the synthetic placeholders defined in
CONTRIBUTING.md.
