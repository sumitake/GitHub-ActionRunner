# Contributing to Portable GHAR

Thanks for considering a contribution. This is a public source tree with a
strict public-safety posture: every contribution is scanned before it can
be merged, and a few practices are non-negotiable because they are what
makes that scan trustworthy.

## The non-negotiables

### 1. Test-driven development (TDD)

Write the failing test first, watch it fail for the expected reason, then
implement until it passes. Do not submit implementation code that was
never proven to fail without it. Pull requests that add behavior without a
preceding failing test will be sent back for rework.

### 2. Synthetic fixtures only -- never real logs, config, or state

**Never paste real logs, real configuration, real runtime state, or any
other deployment-specific material into an issue, a pull request, a commit
message, or a code comment in this repository.** That includes real
hostnames, IP addresses, tunnel/account/zone identifiers, tokens, private
keys, and anything else that could identify or compromise a real
deployment -- yours or anyone else's.

Use synthetic placeholders instead, for example:

- Repository references: `owner/repository`, `example-fleet`
- Hosts/addresses: `example.com`, an address from a documentation-reserved
  range (see `config/examples/fleet.example.json` for the full deny-class
  table this project already treats as non-routable/non-real)
- Identities: `operator@example.invalid`
- Secrets: a clearly fake, obviously non-functional shape (never a real
  token, key, or credential -- not even an expired one)

All fixtures, examples, and test data must be synthetic. If you are unsure
whether a value is safe to include, treat it as unsafe and replace it with
one of the placeholders above before you open the pull request.

### 3. Signed commits

Every commit must be cryptographically signed (`git commit -S`) and verify
against a key associated with your GitHub account. Unsigned commits will
not be merged.

### 4. Action SHA pins

Every GitHub Actions step that references a third-party or reusable action
must pin the full 40-character commit SHA of the action, not a mutable tag
or branch name. This is a supply-chain control: a tag can be moved after
review, a commit SHA cannot. Add a trailing comment noting the
human-readable version next to the pin so reviewers can sanity-check it,
for example `uses: some-org/some-action@<full-commit-sha> # v1.2.3`.

### 5. Hosted CI only

All checks run on GitHub-hosted runners. Do not propose workflow changes
that add or require self-hosted runners, and do not depend on any
credential, network path, or environment that exists only on a
maintainer's private infrastructure. A contribution's checks must be
reproducible by anyone from a clean checkout on hosted CI.

## Before you open a pull request

1. Write the failing test(s) first (TDD).
2. Implement until the tests pass, using synthetic fixtures only.
3. Run the full local check suite, including:
   - `python3 -m unittest discover -s tests -p 'test_*.py'`
   - `python3 scripts/sanitize_public.py --tracked`
   - `python3 scripts/check_repository_metadata.py`
4. Sign your commits (`git commit -S`).
5. Fill out the PUBLIC-SAFETY checklist in the pull request template
   honestly -- it exists because a reviewer cannot always tell from a diff
   alone whether a value is real or synthetic.

## Code of conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a vulnerability

Security issues are handled separately from ordinary contributions. See
[SECURITY.md](SECURITY.md) -- vulnerabilities are reported only through
GitHub private vulnerability reporting, never through a public issue or
pull request.
