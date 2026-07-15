# Repository bootstrap

This runbook describes how a **public** Portable GHAR mirror is brought up to
its foundation security posture and its protected-`main` ruleset, using the
tested-but-not-executed helper [`scripts/repository/configure.sh`](../../scripts/repository/configure.sh).

The helper codifies every setting as a reproducible `gh api` call against the
GitHub REST API (pinned to version `2026-03-10`), and reads every mutated value
back before the next step proceeds. It is **fail closed**: a missing or
non-public repository, an absent PR / head SHA, any required CI context that is
missing or unsuccessful, an unresolved maintainer mode, a malformed API
response, or any apply without explicit confirmation is a hard, non-zero-exit
failure that makes no further change.

This page and its helper are **not executed during the source phase** of this
repository. They are unit-tested against a stub `gh` (see
`tests/shell/repository-configure.bats`) and documented here so an operator can
run the two-stage bootstrap by hand on a real mirror later. All examples below
are synthetic: `owner/repository`, `<head-sha>`, and `<ruleset-id>` are
placeholders, never real names, tokens, or identifiers.

The posture below assumes the trust model in
[Trust boundaries](../security/trust-boundaries.md) and the component layout in
[Architecture overview](../architecture/overview.md).

## Prerequisites

- The GitHub CLI (`gh`) authenticated as a principal with **admin** on the
  target repository. The helper positively verifies admin before any apply and
  refuses otherwise.
- The repository is **public**. The helper refuses to touch a non-public
  repository.
- A merged-ready bootstrap pull request whose head commit has run the full CI
  suite. Its number is the `PR_NUMBER` argument in stage one.

## The seven CI contexts

Tasks 8 and 9 define seven stable CI contexts:

```text
go
worker
shell
repository-metadata
container
sanitization
dependency-review
```

All seven must have **succeeded on the bootstrap PR's exact head SHA** before a
ruleset is created. Only the first **six** become required status checks on
`main`. `dependency-review` is observed on the pull request but is deliberately
**not** required on `main`, so a routine dependency-review signal never blocks
an otherwise-clean merge to the protected branch.

## Two-stage bootstrap order

Run the stages in order. Do not create the ruleset before the contexts are
proven, and do not merge the bootstrap PR before the contexts are proven on the
exact head SHA you are about to protect.

1. **Run all seven checks on the bootstrap PR head.** Push the bootstrap PR and
   let CI run every one of the seven contexts to completion on its head commit.
2. **Read back each successful context for that exact SHA.** Confirm all seven
   report `success` against the PR's head SHA — not merely against the branch,
   and not against a superseded commit. The helper does this precheck and fails
   closed if any context is missing or not `success`:

   ```sh
   # Read-only: report the current foundation + ruleset status first.
   scripts/repository/configure.sh --check owner/repository
   ```

3. **Merge under the operator's pre-authorization.** With all seven green on the
   proven head SHA, merge the bootstrap PR. This is the operator's decision; the
   helper never merges.
4. **Apply the foundation settings.** Requires explicit confirmation (`--yes` or
   an interactive prompt) and admin:

   ```sh
   scripts/repository/configure.sh --apply-foundation owner/repository --yes
   ```

   This sets the default workflow token to read-only; blocks Actions from
   approving pull requests; restricts Actions to a GitHub-owned +
   Gitleaks + Trivy + Anchore SBOM + Bats allowlist; turns delete-branch-on-merge
   on; disables merge commits while keeping squash and rebase; and enables
   vulnerability alerts, automated security updates, private vulnerability
   reporting, and secret scanning with push protection, validity checks, and
   non-provider patterns. Every value is read back after it is set.
5. **Apply the ruleset.** Requires confirmation, admin, the bootstrap PR number,
   and an explicit maintainer mode. The helper first re-proves all seven
   contexts on the PR's head SHA, then creates the ACTIVE `main` ruleset:

   ```sh
   scripts/repository/configure.sh --apply-ruleset owner/repository <PR_NUMBER> \
     --maintainer-mode sole --yes
   ```

   The ruleset requires pull requests, requires resolved conversations, requires
   linear history, requires signed commits, blocks branch deletion and
   force-push, and enforces strict required status checks for the six
   required-on-main contexts (not `dependency-review`). It declares **no bypass
   actors**.
6. **Read back the ruleset JSON and record the id.** The helper reads the ruleset
   back, confirms its enforcement is `active`, and prints the new
   `<ruleset-id>`. Record that id in the deployment log.

## Maintainer mode and CODEOWNERS

The maintainer mode is mandatory and resolves an otherwise-ambiguous choice; the
helper fails closed if it is not supplied.

- `sole` — sole-maintainer mode. CODEOWNERS routing is kept, but the ruleset
  requires **zero** approvals and **disables** code-owner review enforcement,
  because a sole maintainer cannot self-approve and a code-owner gate that can
  never be satisfied would wedge every merge.
- `independent` — an independent reviewer exists. The ruleset requires one
  approval and enforces code-owner review.

Either way, the ruleset declares no bypass actors by default: the protection
applies uniformly, including to administrators, until an operator deliberately
amends it.

## Failure modes (all fail closed)

The helper exits non-zero, changing nothing further, on any of:

- a missing repository argument, or a non-public repository;
- an absent PR number, or a PR whose head SHA cannot be determined;
- any of the seven contexts missing or not `success` on that head SHA;
- an unresolved maintainer/CODEOWNERS mode;
- a malformed or unreadable API response, including a failed read-back after a
  mutation; and
- any apply invoked without confirmation.
